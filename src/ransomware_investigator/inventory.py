"""Pure parsing and identity reconciliation; never opens a device."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import PurePosixPath

from .audit import bytes_digest, digest
from .safety import PROJECT, RIError, device_path, parse_time, text, utcnow


def integer(value, name, *, minimum=0):
    if value is None or value == "":
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise RIError(f"{name}: entero inválido.")
    try:
        result = int(value)
    except ValueError as exc:
        raise RIError(f"{name}: entero inválido.") from exc
    if result < minimum:
        raise RIError(f"{name}: fuera de rango.")
    return result


def boolean(value):
    if value is None or value == "":
        return None
    if value is True or type(value) is int and value == 1 or value == "1":
        return True
    if value is False or type(value) is int and value == 0 or value == "0":
        return False
    raise RIError("Estado booleano inválido.")


def optional(value, name):
    return None if value is None or value == "" else text(value, name)


def properties(raw: str) -> dict:
    if not isinstance(raw, str):
        raise RIError("Salida udev inválida.")
    result = {}
    for line in raw.splitlines():
        if not line:
            continue
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z0-9_]+", key) or key in result:
            raise RIError("Propiedades udev malformadas o duplicadas.")
        result[key] = optional(value, key)
    return result


def flatten(rows):
    if not isinstance(rows, list):
        raise RIError("Se esperaba una lista de nodos.")
    pending = [(row, None, 0) for row in reversed(rows)]
    count = 0
    while pending:
        row, parent, depth = pending.pop()
        count += 1
        if count > 4096 or depth > 32 or not isinstance(row, dict):
            raise RIError("Topología inválida o demasiado grande.")
        yield row, parent
        children = row.get("children", [])
        if not isinstance(children, list):
            raise RIError("Hijos inválidos.")
        parent_name = row.get("kname", row.get("target"))
        pending.extend((child, parent_name, depth + 1) for child in reversed(children))


def kernel_path(value) -> str:
    name = text(value, "kname", 100)
    return device_path(name if name.startswith("/dev/") else "/dev/" + name)


def physical_ancestors(devices: list[dict], path: str) -> set[str]:
    by_path = {d["path"]: d for d in devices}
    pending, visited, disks = [path], set(), set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        node = by_path.get(current)
        if node is None:
            continue
        if node["type"] == "disk":
            disks.add(current)
        pending.extend(node["parents"])
    return disks


def _mounts(raw: dict) -> list[dict]:
    if not isinstance(raw, dict):
        raise RIError("findmnt inválido.")
    result = []
    for row, _ in flatten(raw.get("filesystems", [])):
        target = text(row.get("target"), "mount target")
        if not target.startswith("/"):
            raise RIError("Punto de montaje no absoluto.")
        result.append({"target": target, "source": optional(row.get("source"), "mount source"),
                       "fstype": optional(row.get("fstype"), "mount fstype"),
                       "options": optional(row.get("options"), "mount options"),
                       "maj_min": optional(row.get("maj:min"), "mount maj:min")})
    return result


def _known_binfmt_stack(rows, known_block_numbers, protected_paths):
    """Only the standard systemd autofs + binfmt pseudo-stack is nonblocking.

    Do not generalize to all major-0 filesystems or discard overmounted rows:
    hidden block mounts and ambiguous protected-path backing remain unsafe.
    This metadata classification never authorizes a physical read.
    """
    target = "/proc/sys/fs/binfmt_misc"
    return (len(rows) == 2
            and all(row["target"] == target for row in rows)
            and {(row["source"], row["fstype"]) for row in rows}
                == {("systemd-1", "autofs"), ("binfmt_misc", "binfmt_misc")}
            and all(isinstance(row["maj_min"], str) and re.fullmatch(r"0:[1-9][0-9]{0,6}", row["maj_min"])
                    and row["maj_min"] not in known_block_numbers for row in rows)
            and len({row["maj_min"] for row in rows}) == 2
            and not any(PurePosixPath(path).is_relative_to(PurePosixPath(target)) for path in protected_paths))


def build_inventory(bundle: dict, *, mode: str, workspace: str, observed_at: str | None = None) -> dict:
    """Caller sets mode; a fixture cannot impersonate live collection."""
    if mode not in ("simulated", "metadata") or not isinstance(bundle, dict) or bundle.get("schema_version") != 1:
        raise RIError("Formato o modo de inventario no soportado.")
    lsblk = bundle.get("lsblk")
    if not isinstance(lsblk, dict) or not isinstance(lsblk.get("blockdevices"), list):
        raise RIError("lsblk JSON inválido o ausente.")
    moment = observed_at or bundle.get("observed_at") or utcnow()
    parse_time(moment)
    udev = bundle.get("udev", {})
    if not isinstance(udev, dict):
        raise RIError("Base de propiedades inválida.")
    devices, by_path, topology_errors = [], {}, []
    for row, parent in flatten(lsblk["blockdevices"]):
        path = kernel_path(row.get("kname"))
        parents = set()
        for name in (parent, row.get("pkname")):
            if name:
                parents.add(kernel_path(name))
        if path in parents:
            raise RIError("Dependencia circular de dispositivo.")
        props = properties(udev.get(path, ""))
        model = optional(row.get("model"), "modelo") or props.get("ID_MODEL")
        serial = optional(row.get("serial"), "serie") or props.get("ID_SERIAL_SHORT")
        wwn = optional(row.get("wwn"), "wwn") or props.get("ID_WWN")
        conflicts = []
        for key, first, other in (("serial", serial, props.get("ID_SERIAL_SHORT")), ("wwn", wwn, props.get("ID_WWN"))):
            if first and other and first.casefold() != other.casefold():
                conflicts.append(key)
        if props.get("DEVNAME") and props["DEVNAME"] not in (path, row.get("path")):
            conflicts.append("udev_devname")
        if wwn:
            wwn = wwn.lower().removeprefix("0x")
            if not re.fullmatch(r"[0-9a-f]{16,64}", wwn) or not wwn.strip("0"):
                wwn = None
        if serial and (serial.casefold() in {"unknown", "none", "n/a", "default", "not specified"} or not serial.strip("0 -_")):
            serial = None
        kind = text(row.get("type"), "tipo", 40)
        key = None
        if kind == "disk":
            if wwn:
                key = "wwn:" + wwn
            elif model and serial:
                key = "serial:" + digest([model, serial])
        fs = props.get("ID_FS_TYPE")
        hints = []
        if fs:
            if "raid" in fs.lower():
                hints.append("possible_raid")
            if "lvm" in fs.lower():
                hints.append("possible_lvm")
            if any(word in fs.lower() for word in ("bitlocker", "luks", "crypto")):
                hints.append("possible_encryption")
        if kind in ("lvm", "crypt", "mpath") or kind.startswith("raid"):
            hints.append("active_volume")
        links = [item for item in (props.get("DEVLINKS") or "").split() if item.startswith("/dev/disk/by-id/") and ".." not in PurePosixPath(item).parts]
        node = {"path": path, "observed_path": optional(row.get("path"), "path") or path,
                "type": kind, "maj_min": optional(row.get("maj:min"), "maj:min"),
                "parents": sorted(parents), "model": model, "serial": serial, "wwn": wwn,
                "size_bytes": integer(row.get("size"), "capacidad"),
                "logical_sector_bytes": integer(row.get("log-sec"), "sector lógico", minimum=1),
                "physical_sector_bytes": integer(row.get("phy-sec"), "sector físico", minimum=1),
                "transport": optional(row.get("tran"), "transporte") or props.get("ID_BUS"),
                "read_only": boolean(row.get("ro")), "removable": boolean(row.get("rm")),
                "fstype": fs, "fs_uuid": props.get("ID_FS_UUID"), "part_uuid": props.get("ID_PART_ENTRY_UUID"),
                "partition_table": props.get("ID_PART_TABLE_TYPE"), "by_id": sorted(links),
                "identity_key": key, "identity_status": "candidate" if key else "missing",
                "identity_conflicts": conflicts, "hints": hints, "mounts": [], "protection_reasons": [],
                "udev_status": "observed_cached" if path in udev else "unavailable",
                "health": {"status": "not_queried", "reason": "SMART y pruebas físicas no autorizadas en este perfil."}}
        if path in by_path:
            existing = by_path[path]
            if any(existing[k] != node[k] for k in node if k != "parents"):
                raise RIError("Un dispositivo aparece con atributos contradictorios.")
            existing["parents"] = sorted(set(existing["parents"]) | parents)
        else:
            devices.append(node)
            by_path[path] = node
    for d in devices:
        if d["maj_min"] and not re.fullmatch(r"\d{1,7}:\d{1,7}", d["maj_min"]):
            raise RIError("Identificador major:minor inválido.")
        if any(p not in by_path for p in d["parents"]):
            topology_errors.append("missing_parent:" + d["path"])
    # Iterative topological ordering avoids recursion and exponential DAG walks.
    pending = {d["path"]: set(d["parents"]) & by_path.keys() for d in devices}
    children = {path: set() for path in by_path}
    for path, parents in pending.items():
        for parent in parents:
            children[parent].add(path)
    ready = [path for path, parents in pending.items() if not parents]
    visited = set()
    while ready:
        path = ready.pop()
        if path in visited:
            continue
        visited.add(path)
        for child in children[path]:
            pending[child].discard(path)
            if not pending[child]:
                ready.append(child)
    if len(visited) != len(devices):
        raise RIError("Ciclo en la topología de almacenamiento.")
    counts = Counter(d["identity_key"] for d in devices if d["identity_key"])
    majors = Counter(d["maj_min"] for d in devices if d["maj_min"])
    for d in devices:
        if d["identity_key"]:
            d["identity_status"] = "unique_observed" if counts[d["identity_key"]] == 1 and not d["identity_conflicts"] else "ambiguous"
        if not d["maj_min"] or majors[d["maj_min"]] > 1:
            topology_errors.append("invalid_major_minor:" + d["path"])
    mounts = _mounts(bundle.get("findmnt", {}))
    major_paths = {d["maj_min"]: d["path"] for d in devices if d["maj_min"]}
    protected = {"/dev/nvme0n1": {"explicit_internal_exclusion"}}
    topology_complete = "findmnt" in bundle and isinstance(bundle.get("swaps"), list)
    protected_targets = ["/", "/boot", "/boot/efi", str(PROJECT), workspace]
    swaps = bundle.get("swaps", [])
    if not isinstance(swaps, list):
        raise RIError("Swap inválido.")
    validated_swaps = [text(swap, "swap") for swap in swaps]
    protected_paths = protected_targets + [swap for swap in validated_swaps if swap.startswith("/")]
    groups, topology_warnings = {}, []
    for mount in mounts:
        groups.setdefault(mount["target"], []).append(mount)
    for target, rows in groups.items():
        if len(rows) < 2:
            continue
        if _known_binfmt_stack(rows, major_paths, protected_paths):
            topology_warnings.append({"code": "known_binfmt_pseudo_mount_stack", "target": target,
                "sources": [row["source"] for row in rows], "maj_min": [row["maj_min"] for row in rows],
                "reason": "Known non-block pseudo-stack outside protected paths; all rows retained. Not a physical preflight."})
        elif "ambiguous_overlapping_mount_targets" not in topology_errors:
            topology_errors.append("ambiguous_overlapping_mount_targets")
    for target in protected_targets:
        candidates = [m for m in mounts if PurePosixPath(target).is_relative_to(PurePosixPath(m["target"]))]
        if not candidates:
            topology_complete = False
            continue
        match = max(candidates, key=lambda m: len(m["target"]))
        path = major_paths.get(match["maj_min"])
        disks = physical_ancestors(devices, path) if path else set()
        if not disks:
            topology_complete = False
        for disk in disks:
            protected.setdefault(disk, set()).add("backs:" + target)
    for mount in mounts:
        path = major_paths.get(mount["maj_min"])
        mount["device_path"] = path
        if path:
            by_path[path]["mounts"].append(mount)
        elif (mount["source"] or "").startswith("/dev/"):
            topology_errors.append("unresolved_block_mount:" + mount["target"])
    for swap in swaps:
        swap = text(swap, "swap")
        if swap in by_path:
            disks = physical_ancestors(devices, swap)
        elif swap.startswith("/") and not swap.startswith("/dev/"):
            matches = [m for m in mounts if PurePosixPath(swap).is_relative_to(PurePosixPath(m["target"]))]
            disk_path = max(matches, key=lambda m: len(m["target"]))["device_path"] if matches else None
            disks = physical_ancestors(devices, disk_path) if disk_path else set()
        else:
            disks = set()
        if not disks:
            topology_complete = False
        for disk in disks:
            protected.setdefault(disk, set()).add("backs:swap")
    for d in devices:
        for disk in physical_ancestors(devices, d["path"]):
            d["protection_reasons"].extend(sorted(protected.get(disk, set())))
    errors = bundle.get("collection_errors", [])
    if not isinstance(errors, list):
        raise RIError("Errores de colección inválidos.")
    return {"schema_version": 1, "mode": mode, "observed_at": moment,
            "devices": sorted(devices, key=lambda d: d["path"]), "mounts": mounts, "swaps": swaps,
            "topology_complete": topology_complete and not topology_errors and not errors,
             "collection_errors": errors + topology_errors, "tools": bundle.get("tools", []),
             "topology_warnings": topology_warnings,
            "raw_sha256": [], "warning": "Metadatos observados, no prueba de integridad ni de bloqueo físico."}


def select_original(inventory: dict, key: str) -> dict:
    matches = [d for d in inventory["devices"] if d["identity_key"] == key and d["type"] == "disk"]
    if len(matches) != 1 or matches[0]["identity_status"] != "unique_observed":
        raise RIError("Identidad ausente o ambigua; no se puede seleccionar el original.")
    device = matches[0]
    if device["protection_reasons"] or not inventory["topology_complete"]:
        raise RIError("Fuente protegida o topología incompleta; selección bloqueada.")
    if not device["model"] or not device["size_bytes"]:
        raise RIError("Características insuficientes para registrar el original.")
    return device


def save_inventory(store, case_id: str, bundle: dict, raw: bytes, actor: str, *, mode: str, observed_at=None) -> dict:
    inventory = build_inventory(bundle, mode=mode, workspace=str(store.workspace), observed_at=observed_at)
    # Pin observed protection to persistent attributes, not just a /dev name.
    protected_keys, protected_serials = set(), set()
    for previous in store.list("inventories"):
        if previous["mode"] != mode:
            continue
        for node in previous["devices"]:
            if node["type"] == "disk" and node["protection_reasons"]:
                if node["identity_key"]:
                    protected_keys.add(node["identity_key"])
                if node["model"] and node["serial"]:
                    protected_serials.add((node["model"], node["serial"]))
    pinned_paths = {node["path"] for node in inventory["devices"] if node["type"] == "disk" and
                    (node["identity_key"] in protected_keys or (node["model"], node["serial"]) in protected_serials)}
    for node in inventory["devices"]:
        if physical_ancestors(inventory["devices"], node["path"]) & pinned_paths:
            node["protection_reasons"].append("persistent_workspace_exclusion")
    inventory["raw_sha256"] = [bytes_digest(raw)]
    return store.record("inventories", case_id, inventory, actor, blobs=[raw])


def compare(before: dict, after: dict) -> dict:
    if before["case_id"] != after["case_id"] or before["mode"] != after["mode"]:
        raise RIError("No se comparan casos o modos diferentes como si fueran la misma fuente.")
    def index(inv):
        return {d["identity_key"]: d for d in inv["devices"] if d["type"] == "disk" and d["identity_status"] == "unique_observed"}
    old, new = index(before), index(after)
    changed = []
    for key in sorted(old.keys() & new.keys()):
        left = [d for d in before["devices"] if old[key]["path"] in physical_ancestors(before["devices"], d["path"])]
        right = [d for d in after["devices"] if new[key]["path"] in physical_ancestors(after["devices"], d["path"])]
        # Relative paths make partition comparisons stable across /dev renaming.
        def layout(nodes, disk):
            return sorted([[n["part_uuid"], n["type"], n["size_bytes"], n["fstype"], n["read_only"], n["mounts"] != []]
                           for n in nodes if n["path"] != disk], key=lambda x: str(x))
        fields = {field: {"before": old[key][field], "after": new[key][field]} for field in
                  ("path", "model", "serial", "size_bytes", "logical_sector_bytes", "transport", "read_only", "by_id", "protection_reasons")
                  if old[key][field] != new[key][field]}
        left_layout, right_layout = layout(left, old[key]["path"]), layout(right, new[key]["path"])
        if left_layout != right_layout:
            fields["partition_layout"] = {"before": left_layout, "after": right_layout}
        if fields:
            changed.append({"identity_key": key, "changes": fields,
                            "identity_conflict": any(f in fields for f in ("model", "serial", "size_bytes", "logical_sector_bytes"))})
    return {"before": before["id"], "after": after["id"], "added": sorted(new.keys() - old.keys()),
            "removed": sorted(old.keys() - new.keys()), "changed": changed,
            "unresolved": [{"inventory": inv["id"], "path": d["path"], "status": d["identity_status"]}
                           for inv in (before, after) for d in inv["devices"] if d["type"] == "disk" and d["identity_status"] != "unique_observed"],
            "limit": "Comparación de metadatos, no de contenido ni integridad."}


def register_original(store, case_id, inventory_id, key, actor, notes):
    inventory = store.get("inventories", inventory_id)
    if inventory["case_id"] != case_id:
        raise RIError("El inventario no pertenece al caso.")
    device = select_original(inventory, key)
    if any(e["identity_key"] == key and e["mode"] == inventory["mode"] for e in store.list("evidence", case_id)):
        raise RIError("Original ya registrado; no se duplicó el registro.")
    return store.record("evidence", case_id, {"inventory_id": inventory_id, "identity_key": key,
                        "device_snapshot": device, "mode": inventory["mode"], "status": "original_registered",
                        "content_sha256": None, "responsible": text(actor, "responsable", 200),
                        "notes": text(notes, "notas"), "preserved_image": False}, actor)
