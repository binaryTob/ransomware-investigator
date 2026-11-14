"""Authorized metadata collector. All tests inject a synthetic executor."""
from __future__ import annotations

import json
import re

from .audit import canonical
from .executor import RestrictedExecutor, TOOLS
from .inventory import flatten, kernel_path, save_inventory
from .safety import MAX_INPUT, Policy, RIError, PublicationPending, utcnow


def parse_swaps(raw: str) -> list[str]:
    lines = raw.splitlines()
    if not lines or not lines[0].startswith("Filename"):
        raise RIError("Metadatos de swap malformados.")
    result = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) != 5:
            raise RIError("Entrada de swap inválida.")
        result.append(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), parts[0]))
    return result


def scan_metadata(store, case_id: str, actor: str, reason: str, *, authorized: bool, executor_factory=RestrictedExecutor) -> dict:
    store.get("cases", case_id)
    if not authorized:
        store.record("operations", case_id, {"scope": "metadata_discovery", "status": "denied", "reason": "Falta --authorize-metadata."}, actor)
        raise RIError("Reconocimiento real bloqueado: falta autorización explícita --authorize-metadata.")
    grant = Policy.grant(case_id, actor, reason)
    authorization = store.record("authorizations", case_id, grant, actor)
    operation = store.record("operations", case_id, {"scope": "metadata_discovery", "status": "started", "authorization_id": authorization["id"]}, actor)
    started = utcnow()
    results = []
    try:
        executor = executor_factory(grant)
        output_bytes = 0
        def run(name, **kwargs):
            nonlocal output_bytes
            result = executor.execute(name, **kwargs)
            output_bytes += len(result["stdout"].encode()) + len(result["stderr"].encode())
            if output_bytes > 2 * 1024 * 1024:
                results.append({"operation": name, "status": "collection_limit", "reason": "Límite agregado de salidas: 2 MiB; salida adicional no retenida."})
                raise RIError("Se excedió el límite agregado de colección; no se reintentará.")
            results.append(result)
            if result["status"] == "termination_unconfirmed":
                raise RIError("Terminación del proceso no confirmada; no se lanzarán más consultas.")
            return result
        versions = {tool: run("version", tool=tool) for tool in sorted(TOOLS)}
        tools = list(versions.values())
        if versions["lsblk"]["status"] != "ok":
            raise RIError("Versión de lsblk no disponible; no se intentará la consulta ni un sustituto.")
        ls = run("lsblk_metadata")
        if ls["status"] != "ok":
            raise RIError("lsblk no disponible o falló; no se aplicará un fallback.")
        lsblk = json.loads(ls["stdout"])
        if not isinstance(lsblk, dict) or "blockdevices" not in lsblk:
            raise RIError("lsblk no devolvió la topología requerida.")
        paths = sorted({kernel_path(row.get("kname")) for row, _ in flatten(lsblk["blockdevices"])})
        if len(paths) > 256:
            raise RIError("Demasiados nodos para un reconocimiento acotado (máximo 256).")
        fm = run("findmnt_metadata") if versions["findmnt"]["status"] == "ok" else versions["findmnt"]
        swap = run("swap_metadata")
        bundle = {"schema_version": 1, "lsblk": lsblk, "udev": {}, "tools": tools, "collection_errors": []}
        if fm["status"] == "ok":
            bundle["findmnt"] = json.loads(fm["stdout"])
        else:
            bundle["collection_errors"].append("findmnt:" + fm["status"])
        if swap["status"] == "ok":
            bundle["swaps"] = parse_swaps(swap["stdout"])
        else:
            bundle["collection_errors"].append("swap:" + swap["status"])
        for path in paths:
            if versions["udevadm"]["status"] != "ok":
                bundle["collection_errors"].append("udev:" + path + ":version_unavailable")
                continue
            result = run("udev_properties", device=path)
            if result["status"] == "ok":
                bundle["udev"][path] = result["stdout"]
            else:
                bundle["collection_errors"].append("udev:" + path + ":" + result["status"])
        # Exact tool outputs, including errors, remain in the content-addressed raw bundle.
        bundle["results"] = results
        raw = canonical(bundle).encode()
        if len(raw) > MAX_INPUT:
            raise RIError("Bundle de metadatos mayor a 8 MiB; se conserva el error, no se crea inventario.")
        inventory = save_inventory(store, case_id, bundle, raw, actor, mode="metadata", observed_at=started)
        status = "completed" if inventory["topology_complete"] else "partial"
        store.update_operation(operation["id"], status, results, actor)
        return inventory
    except PublicationPending:
        raise
    except (RIError, OSError, ValueError, TypeError, KeyError) as exc:
        results.append({"status": "collector_failed", "error": str(exc)})
        store.update_operation(operation["id"], "failed", results, actor)
        raise RIError(f"Reconocimiento detenido; error registrado: {exc}") from exc
