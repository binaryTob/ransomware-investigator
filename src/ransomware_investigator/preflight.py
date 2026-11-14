"""Snapshot-only acquisition planning. No device or destination IO, ever."""
from __future__ import annotations

import re
from pathlib import PurePosixPath

from .inventory import integer, physical_ancestors, select_original
from .safety import RIError, destination_path, parse_time, utcnow


MAX_AGE_SECONDS = 900


def assess(inventory: dict, key: str, destination: dict, *, original: dict | None = None,
           latest_inventory_id: str | None = None, now: str | None = None) -> dict:
    """Evaluate declarations and saved observations, NOT live acquisition readiness."""
    if not isinstance(destination, dict) or destination.get("schema_version") != 1:
        raise RIError("Plan de destino inválido; schema_version=1 requerido.")
    moment = parse_time(now or utcnow())
    checks, reviews = [], []

    def check(code, passed, details):
        checks.append({"code": code, "passed": bool(passed), "details": details})

    def fresh(timestamp):
        age = (moment - parse_time(timestamp)).total_seconds()
        return -5 <= age <= MAX_AGE_SECONDS

    check("SOURCE_FRESH", fresh(inventory["observed_at"]), "El inventario debe tener hasta 900 s y no estar fechado en el futuro.")
    check("LATEST_SNAPSHOT", latest_inventory_id == inventory["id"], "Debe usarse el último inventario del caso y modo.")
    check("SAME_MODE", destination.get("mode") == inventory["mode"], "No mezclar simulaciones con metadatos reales.")
    check("DESTINATION_FRESH", fresh(destination.get("observed_at")), "La declaración de destino también vence a los 900 s.")
    try:
        source = select_original(inventory, key)
    except RIError as exc:
        source = None
        check("SOURCE_ELIGIBLE", False, str(exc))
    else:
        check("SOURCE_ELIGIBLE", True, "Identidad única observada y fuente no protegida según el inventario.")
    registered = original is not None and original.get("identity_key") == key and original.get("mode") == inventory["mode"]
    check("ORIGINAL_REGISTERED", registered, "Se requiere registro del original en el mismo caso y modo.")
    required_bytes = None
    if source:
        nodes = [d for d in inventory["devices"] if source["path"] in physical_ancestors(inventory["devices"], d["path"])]
        check("SOURCE_READ_ONLY", all(d["read_only"] is True for d in nodes), "Disco y todos sus nodos deben informar RO; no equivale a bloqueo físico.")
        check("SOURCE_UNMOUNTED", all(not d["mounts"] for d in nodes), "No se desmonta automáticamente, tampoco montajes RO.")
        check("NO_ACTIVE_VOLUMES", all(d["type"] in ("disk", "part") for d in nodes), "No se permite adquirir sobre dependencias activas de RAID/LVM/crypt.")
        check("SOURCE_GEOMETRY", bool(source["size_bytes"] and source["logical_sector_bytes"] and source["size_bytes"] % source["logical_sector_bytes"] == 0), "Capacidad y sector lógico conocidos y compatibles.")
        if registered:
            previous = original["device_snapshot"]
            matches = all(previous[field] == source[field] for field in ("model", "serial", "wwn", "size_bytes", "logical_sector_bytes"))
            check("IDENTITY_UNCHANGED", matches, "Los atributos deben coincidir con el registro del original.")
        health = source.get("health", {})
        check("NO_KNOWN_PHYSICAL_ALERT", health.get("status") not in ("alert", "failed"), "Una alerta física exige cambiar el procedimiento, no reintentar intensivamente.")
        if health.get("status") != "observed_no_alerts":
            reviews.append("Salud física no verificada: SMART no consultado en este MVP; requiere decisión humana.")

    path = destination_path(destination.get("path"))
    target = destination_path(destination.get("mount_target")) if destination.get("mount_target") != "/" else "/"
    check("DESTINATION_UNDER_MOUNT", PurePosixPath(path).is_relative_to(PurePosixPath(target)) and path != target, "Destino absoluto dentro del punto de montaje declarado; nunca /dev, /proc, /sys o /run.")
    candidates = [m for m in inventory["mounts"] if PurePosixPath(path).is_relative_to(PurePosixPath(m["target"]))]
    mount = max(candidates, key=lambda m: len(m["target"])) if candidates else None
    mount_matches = mount is not None and mount["target"] == target and mount["maj_min"] == destination.get("device_maj_min") and mount["fstype"] == destination.get("filesystem")
    check("DESTINATION_MOUNT_MATCHES", mount_matches, "La ruta, dispositivo y sistema de archivos deben coincidir con findmnt del inventario.")
    backing = physical_ancestors(inventory["devices"], mount["device_path"]) if mount and mount.get("device_path") else set()
    check("DESTINATION_DISTINCT", source is not None and bool(backing) and source["path"] not in backing, "Se deben resolver los discos físicos de destino y excluir la fuente.")
    writable = destination.get("writable") is True and mount is not None and "rw" in (mount.get("options") or "").split(",")
    check("DESTINATION_WRITABLE_DECLARED", writable, "Declaración del operador y opciones de montaje, sin prueba de escritura.")
    check("DESTINATION_NOT_EXISTING", destination.get("target_exists") is False, "No sobrescribir destinos existentes.")
    check("DESTINATION_SYMLINK_CHECK_DECLARED", destination.get("symlinks_checked") is True, "Declaración externa, no comprobación independiente de enlaces.")
    free = integer(destination.get("available_bytes"), "espacio disponible")
    reserve = integer(destination.get("reserve_bytes"), "reserva", minimum=1)
    max_file = integer(destination.get("max_file_size_bytes"), "máximo por archivo", minimum=1)
    if destination.get("filesystem") in ("vfat", "msdos", "fat") and max_file is not None:
        max_file = min(max_file, 2**32 - 1)
    size = source["size_bytes"] if source else None
    if size and reserve is not None:
        required_bytes = size + reserve
    check("SUFFICIENT_SPACE", required_bytes is not None and free is not None and free >= required_bytes,
          {"image_bytes": size, "reserve_bytes": reserve, "required_bytes": required_bytes, "available_bytes": free,
           "policy": "Imagen completa sin asumir compresión, sparse ni descarte de sectores."})
    check("FILE_SIZE_SUPPORTED", size is not None and max_file is not None and size <= max_file,
          {"image_bytes": size, "declared_max_file_bytes": max_file})
    existing = destination.get("existing_copy")
    copy_report = None
    if existing is not None:
        if not isinstance(existing, dict):
            raise RIError("Metadatos de copia existente inválidos.")
        matches = (existing.get("source_identity_key") == key
                   and existing.get("source_inventory_id") == inventory["id"]
                   and existing.get("size_bytes") == size
                   and isinstance(existing.get("expected_sha256"), str)
                   and re.fullmatch(r"[0-9a-f]{64}", existing["expected_sha256"]) is not None
                   and existing.get("sha256") == existing.get("expected_sha256"))
        copy_report = {"metadata_matches": matches, "reusable": False,
                       "reason": "No se verificó contenido, procedencia ni versión de una adquisición; verificar antes de reutilizar."}
        check("EXISTING_COPY_METADATA", matches, copy_report)
        check("EXISTING_COPY_VERIFIED", False, "El MVP no abre imágenes ni acepta un hash declarado como verificación calculada.")
    reviews.append("El destino se evalúa desde una declaración; espacio, enlaces y permisos no se midieron en vivo.")
    return {"scope": "snapshot_preflight", "inventory_id": inventory["id"], "identity_key": key,
            "mode": inventory["mode"], "assessed_at": moment.isoformat(), "destination": destination,
            "checks": checks, "planning_passed": all(c["passed"] for c in checks),
            "blockers": [c["code"] for c in checks if not c["passed"]], "review_required": reviews,
            "existing_copy": copy_report, "required_bytes": required_bytes,
            "acquisition_allowed": False,
            "execution_blockers": ["ACQUISITION_NOT_IMPLEMENTED", "ACQUISITION_NOT_AUTHORIZED", "LIVE_REVALIDATION_REQUIRED"],
            "limit": "Solo planificación sobre metadatos y declaraciones. No confirma aptitud real, integridad ni preservación."}


def record_preflight(store, case_id, inventory_id, key, destination, actor):
    inventory = store.get("inventories", inventory_id)
    if inventory["case_id"] != case_id:
        raise RIError("Inventario de otro caso.")
    snapshots = [inv for inv in store.list("inventories", case_id) if inv["mode"] == inventory["mode"]]
    originals = [e for e in store.list("evidence", case_id) if e["identity_key"] == key and e["mode"] == inventory["mode"]]
    report = assess(inventory, key, destination, original=originals[0] if originals else None,
                    latest_inventory_id=snapshots[-1]["id"] if snapshots else None)
    return store.record("preflights", case_id, report, actor)
