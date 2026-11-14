"""Paged metadata inventory. Never directly opens physical sources or file DATA."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
import uuid
from pathlib import Path

from .audit import canonical, digest, bytes_digest
from .exchange import _atomic, _read
from .ntfs import core
from . import ntfs_triage as triage
from .safety import RIError, PublicationPending, utcnow, sha256_value

BACKUP_SUFFIXES = (".bak", ".bak.sealed", ".tib", ".tibx", ".zip", ".7z", ".rar", ".vhd", ".vhdx", ".vmdk")
CLASSIFIER_VERSION = "ntfs-metadata-v2"
SCAN_LIMITATIONS = [
    "Metadata inventory only; no file DATA/header/hash acquisition.",
    "MFT/provider blocks may contain resident DATA bytes; these bytes are not exported as file contents.",
    "MFT slots are the address range reported by TSK, not a count of recoverable files.",
    "Run references are capped at 64 per attribute; truncation is explicit, not a full runlist.",
    "NTFS timestamps are not proven backup creation dates or trusted host time.",
    "Names/extensions identify candidates, never restorability, malware family or causation.",
    "Deleted names/data runs do not establish that bytes remain original or recoverable.",
    "Directory paths use parent/sequence references; unknown/cyclic paths remain unknown.",
]


def _job(store, case_id, scan_id):
    job = store.get("operations", scan_id)
    if job["case_id"] != case_id or job.get("scope") != "ntfs.scan":
        raise RIError("Escaneo fuera del caso.")
    source = triage._source(store, case_id, job["source_id"])
    if digest(source) != job["plan"]["source_record_sha256"]:
        raise RIError("Fuente cambió desde el inicio; lectura bloqueada.")
    return job, source


def _producer_sha256():
    return bytes_digest(Path(__file__).read_bytes())


def _check_producer(job):
    if job["plan"].get("producer_module_sha256")!=_producer_sha256():
        raise RIError("Código del productor cambió; no reanudar automáticamente un escaneo con otras reglas.")


def _physical_validation_gate(store, case_id, identifier, requested_source=None):
    if identifier is None: raise RIError("Antes del escaneo físico integral se requiere --validation-operation de una comparación física inicial aprobada.")
    validation=store.get("operations",identifier)
    if validation["case_id"]!=case_id or validation.get("scope")!="ntfs.reference-validation" or validation["status"]!="completed":
        raise RIError("Validación inicial ausente, fallida o de otro caso.")
    ref=validation["results"][0]["metadata_report"]; data=_read(store.path(store.workspace/ref["path"]))
    if bytes_digest(data)!=ref["sha256"]: raise RIError("Informe de validación alterado.")
    report=json.loads(data)
    validated_source=triage._source(store,case_id,report["source_id"])
    if requested_source is not None:
        from .ntfs.physical import disk_binding
        if disk_binding(validated_source.get("pin",{}))!=disk_binding(requested_source.get("pin",{})):
            raise RIError("Validación de otro disco no habilita esta fuente; requiere validación propia.")
    if (report.get("validation_passed") is not True or report.get("eligible_for_physical_gate") is not True or validated_source["kind"]!="physical"
            or report.get("case_id")!=case_id or report.get("operation_id")!=identifier
            or report.get("device_source_record_sha256")!=digest(validated_source) or report.get("worker_sha256")!=bytes_digest(triage.WORKER.read_bytes())):
        raise RIError("Una comparación sintética/no verificada o de otro build no habilita el escaneo físico.")
    return {"operation_id":identifier,"report_sha256":ref["sha256"],"validated_source_id":validated_source["id"],"worker_sha256":report["worker_sha256"]}


def start_scan(store, case_id, source_id, *, actor, page_size=64, read_budget=64*1024*1024, timeout_ms=10000,
               max_records=20000000, max_directories=1000000, validation_operation=None,
               directory_read_budget=None, directory_timeout_ms=None):
    source = triage._source(store, case_id, source_id)
    if source["kind"]=="physical" and not {"partition_table_type","partition_table_id"} <= set(source["pin"]):
        raise RIError("El escaneo físico nuevo requiere pin con tipo/ID de tabla, además de identidad persistente; no se inferirá de /dev/sdX.")
    for value, low, high in ((page_size,1,256),(max_records,1,1000000000),(max_directories,1,1000000)):
        if type(value) is not int or not low <= value <= high:
            raise RIError("Límite del plan inválido.")
    core.parameters("ntfs.records", {"read_budget": read_budget, "timeout_ms": timeout_ms})
    directory_read_budget=read_budget if directory_read_budget is None else directory_read_budget
    directory_timeout_ms=timeout_ms if directory_timeout_ms is None else directory_timeout_ms
    core.parameters("ntfs.directory", {"read_budget":directory_read_budget,"timeout_ms":directory_timeout_ms})
    plan = {"version": 1, "metadata_only": True, "source_record_sha256": digest(source), "page_size": page_size,
            "classifier_version":CLASSIFIER_VERSION,"producer_module_sha256":_producer_sha256(),
            "read_budget": read_budget, "timeout_ms": timeout_ms, "max_records": max_records, "max_directories": max_directories,
             "physical_approval": False, "limitations": SCAN_LIMITATIONS}
    plan.update(directory_read_budget=directory_read_budget,directory_timeout_ms=directory_timeout_ms)
    if source["kind"]=="physical": plan["initial_physical_validation"]=_physical_validation_gate(store,case_id,validation_operation,source)
    return store.start_ntfs_scan(case_id, source_id, plan, actor)


@contextmanager
def _scan_lock(store, scan_id):
    directory = store.path(store.workspace / "scans")
    directory.mkdir(mode=0o700, exist_ok=True); store._private(directory, directory=True)
    directory = store.path(directory / store._id(scan_id))
    directory.mkdir(mode=0o700, exist_ok=True); store._private(directory, directory=True)
    fd = os.open(directory / ".scan.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        store._private(directory / ".scan.lock")
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc: raise RIError("Otro controlador está ejecutando este escaneo.") from exc
        yield directory
    finally:
        os.close(fd)


def next_page(store, job, state):
    plan = job["plan"]
    params = {"max_entries": plan["page_size"], "read_budget": plan["read_budget"], "timeout_ms": plan["timeout_ms"]}
    if state["phase"] == "volume": return "ntfs.volume", core.parameters("ntfs.volume", params)
    if state["phase"] == "records":
        params["inode"] = state["next_inode"]
        params["max_entries"] = min(plan["page_size"], state["volume_identity"]["last_inode"] - state["next_inode"] + 1)
        return "ntfs.records", core.parameters("ntfs.records", params)
    directory = store.ntfs_scan_directory(job["id"], after=state["after_directory"])
    if directory is None: return None
    params.update(read_budget=plan.get("directory_read_budget",plan["read_budget"]),
                  timeout_ms=plan.get("directory_timeout_ms",plan["timeout_ms"]))
    params.update(inode=directory["inode"], cursor=state["directory_cursor"])
    return "ntfs.directory", core.parameters("ntfs.directory", params)


def _directory_path(store, scan_id, inode, root_inode):
    parts, seen = [], set()
    while inode != root_inode:
        if inode in seen or len(seen) >= 1024: return None
        seen.add(inode)
        directory = store.ntfs_scan_directory(scan_id, inode=inode)
        if directory is None: return None
        names = sorted(directory["names"], key=lambda n: (n["parent_inode"], n["name"]))
        selected = None
        for name in names:
            if name["name"] in (".", "..") or "/" in name["name"] or "\\" in name["name"]: continue
            parent = store.ntfs_scan_directory(scan_id, inode=name["parent_inode"])
            if parent is not None and parent["sequence"] == name["parent_sequence"]:
                selected = name; break
        if selected is None: return None
        parts.append(selected["name"]); inode = selected["parent_inode"]
        if sum(len(p) for p in parts) > 32768: return None
    return "/" + "/".join(reversed(parts)) + ("/" if parts else "")


def classify_metadata(names, timestamps, deleted=False, path=None, *, reference_year=None):
    if reference_year is not None and (type(reference_year) is not int or not 1 <= reference_year <= 9999):
        raise RIError("Reference year must be an explicit calendar year, not an inferred incident date.")
    labels, observed_years = set(), set()
    lower_names = [n.casefold() for n in names]
    for name in lower_names:
        if name.endswith(".sealed"):
            labels.add("encrypted_suffix")
            name=name.removesuffix(".sealed")  # Candidate matching only, never evidence of original format.
        if name.endswith(BACKUP_SUFFIXES): labels.add("backup_candidate")
        if name.endswith((".mdf", ".ldf")): labels.add("sql_database_candidate")
        if name in ("contact.txt", "readme_recover.txt") or any(s in name for s in ("decrypt", "ransom", "how_to_recover")): labels.add("ransom_note_candidate")
        if name.endswith(".evtx"): labels.add("windows_event_log_candidate")
        if name.endswith(".pf"): labels.add("prefetch_candidate")
        if name in ("system", "software", "sam", "security", "ntuser.dat", "usrclass.dat", "amcache.hve"): labels.add("registry_hive_candidate")
        if name in ("$usnjrnl", "$logfile"): labels.add("ntfs_journal_candidate")
        if any(s in name for s in ("anydesk", "teamviewer", "screenconnect", "rustdesk")): labels.add("remote_tool_name_candidate")
    if path:
        normalized = path.casefold().replace("\\", "/")
        if "/windows/system32/tasks/" in normalized: labels.add("scheduled_task_path_candidate")
        if "system volume information" in normalized: labels.add("vss_path_candidate")
    priority_years=set()
    for key,value in timestamps.items():
        if type(value) is int and value > 0:
            try:
                year=datetime.fromtimestamp(value, timezone.utc).year; observed_years.add(year)
                if key in ("modified","created"): priority_years.add(year)
            except (ValueError, OverflowError, OSError): pass
    if deleted: labels.add("deleted_candidate")
    return {"labels": sorted(labels), "observed_timestamp_years": sorted(observed_years),
            "recovery_state": "pending_content_verification", "restorable": None,
            "priority": "reference_year_metadata_candidate" if reference_year in priority_years else "historical_metadata_candidate" if reference_year is not None and priority_years and max(priority_years) < reference_year else "unranked",
            "priority_basis":"modified/created NTFS timestamps, not last access or a verified backup catalog date",
            "potential_encryption_basis": "filename_suffix_only" if "encrypted_suffix" in labels else "not_established",
            "header_status": "not_read_in_metadata_scope", "hypotheses": [], "causal_attribution": "not_established"}


def inspect_authorized_header(data):
    """Pure function for a separately authorized LOCAL prefix/copy, never IO."""
    if not isinstance(data, bytes) or len(data) > 65536: raise RIError("Prefijo local de hasta 64 KiB requerido.")
    signatures = ((b"SYN\0", "synthetic_test_marker"), (b"PK\x03\x04", "ZIP_candidate"), (b"7z\xbc\xaf\x27\x1c", "7z_candidate"),
                  (b"Rar!\x1a\x07", "RAR_candidate"), (b"TAPE", "Microsoft_tape_or_SQL_backup_candidate"))
    return {"bytes_examined": len(data), "prefix_sha256": bytes_digest(data),
            "signature_observations": [label for magic,label in signatures if data.startswith(magic)],
            "algorithm": None, "ransomware_family": None, "restorable": None,
            "limit": "Prefix signatures do not verify full format, complete encryption, integrity or restorability."}


def _page_handler(store, job, state, actor, directory):
    def accept_validated(operation, response):
        expected = next_page(store, job, state)
        request = operation["request"]
        if expected is None or (request["scope"], request["parameters"]) != expected or request["source_id"] != job["source_id"]:
            raise RIError("Página no corresponde al checkpoint; no se avanzará.")
        payload = response.get("result")
        new = json.loads(canonical(state))
        directories, findings, terms = [], [], []
        if response["receipt"]["status"] == "ok":
            if not isinstance(payload, dict): raise RIError("Página sin resultado.")
            volume = payload.get("volume_identity", payload.get("summary", {}).get("volume_identity"))
            if not isinstance(volume, dict) or volume.get("filesystem") != "NTFS": raise RIError("Volumen NTFS no confirmado.")
            if state["volume_identity"] is not None and volume != state["volume_identity"]: raise RIError("Identidad/layout NTFS cambió entre páginas.")
            if state["worker_sha256"] is not None and state["worker_sha256"] != response["receipt"]["worker_sha256"]: raise RIError("Build del worker cambió; reanudación bloqueada.")
            validation_build=job["plan"].get("initial_physical_validation",{}).get("worker_sha256")
            if validation_build is not None and validation_build!=response["receipt"]["worker_sha256"]: raise RIError("Worker físico distinto del validado; resultados no aceptados.")
            new.update(volume_identity=volume, worker_sha256=response["receipt"]["worker_sha256"])
            if state["phase"] == "volume":
                if volume["last_inode"] - volume["first_inode"] + 1 > job["plan"]["max_records"]: raise RIError("Rango MFT supera el plan; no se truncará silenciosamente.")
                new.update(phase="records", next_inode=volume["first_inode"])
            elif state["phase"] == "records":
                entries = payload["entries"]; summary = payload["summary"]
                start = state["next_inode"]; count = request["parameters"]["max_entries"]
                if [row["inode"] for row in entries] != list(range(start, start+count)) or summary["visited"] != count or summary["next_cursor"] != start+count or summary["partial"]:
                    raise RIError("Rango MFT incompleto/discontinuo; checkpoint no avanza.")
                for row in entries:
                    names = [n["name"] for n in row["names"]]
                    finding_id = "RI-F-" + digest([job["case_id"],job["source_id"],row["inode"],row["sequence"],"metadata_record"])
                    assessment = classify_metadata(names, row["times_unix"], row["unallocated"] and row["used"])
                    findings.append({"finding_id": finding_id, "finding_kind":"metadata_record", "inode": row["inode"], "sequence": row["sequence"], "assessment": assessment,
                                     "attribute_references":[{"type":a["type"],"id":a["id"],"name":a["name"],
                                         "finding_id":"RI-F-"+digest([job["case_id"],job["source_id"],row["inode"],row["sequence"],a["type"],a["id"],a["name"],"attribute"])} for a in row["attributes"]]})
                    for label in assessment["labels"]: new["category_counts"][label] = new["category_counts"].get(label,0)+1
                    for name in names:
                        terms.append((finding_id,"name",name.casefold()))
                        if "." in name and not name.startswith("$"): terms.append((finding_id,"extension","."+name.casefold().rsplit(".",1)[-1]))
                    for key in ("modified", "created"):
                        value = row["times_unix"].get(key)
                        if type(value) is int and value > 0: terms.append((finding_id,"timestamp_"+key,str(value)))
                    if row["directory"] and row["allocated"]:
                        directories.append({"inode": row["inode"], "sequence": row["sequence"], "meta_type":row["meta_type"], "names": row["names"]})
                        if row["meta_type"]==11: new["virtual_directories_indexed"]+=1
                    if not row["directory"] and row["allocated"]: new["allocated_files"] += 1
                    if row["unallocated"] and row["used"]: new["deleted_candidates"] += 1
                new["slots_examined"] += count; new["records_decoded"] += len(entries)
                new["directories_indexed"] += len(directories)
                if new["directories_indexed"] > job["plan"]["max_directories"]: raise RIError("Cantidad de directorios supera el plan.")
                new["next_inode"] = start+count
                if new["next_inode"] > volume["last_inode"]: new["phase"] = "directories"
            else:
                summary = payload["summary"]; cursor = request["parameters"]["cursor"]; entries = payload["entries"]
                if summary["partial"] or [row["index"] for row in entries] != list(range(cursor,cursor+len(entries))) or summary["next_cursor"] != cursor+len(entries):
                    raise RIError("Página de directorio incompleta/discontinua.")
                parent = request["parameters"]["inode"]
                indexed=store.ntfs_scan_directory(job["id"],inode=parent)
                if (indexed is None or summary["directory_sequence"]!=indexed["sequence"] or len(entries)>request["parameters"]["max_entries"]
                        or summary["visited"]!=len(entries) or summary["reported_total"]<summary["next_cursor"]
                        or summary["eof"]!=(summary["next_cursor"]==summary["reported_total"])
                        or any(row["parent_inode"]!=parent for row in entries)
                        or state["directory_total"] is not None and state["directory_total"]!=summary["reported_total"]):
                    raise RIError("Secuencia, tamaño o pertenencia de directorio cambió/no es consistente.")
                new["directory_total"]=summary["reported_total"]
                path = _directory_path(store, job["id"], parent, volume["root_inode"])
                if path is None:
                    if indexed.get("meta_type")==11: new["virtual_path_pages"]+=1
                    else: new["path_warnings"] += 1
                for row in entries:
                    if row["name"] in (".", ".."): continue
                    finding_id = "RI-F-" + digest([job["case_id"],job["source_id"],parent,row["inode"],row["name_sequence"],row["name"],"directory_reference"])
                    full_path = path+row["name"] if path is not None and "/" not in row["name"] and "\\" not in row["name"] else None
                    assessment = classify_metadata([row["name"]], {}, row["name_unallocated"], full_path)
                    findings.append({"finding_id": finding_id, "finding_kind":"directory_reference", "inode": row["inode"], "name_sequence": row["name_sequence"], "ntfs_path": full_path,
                                     "parent_inode": parent, "path_basis":"tsk_virtual_namespace" if indexed.get("meta_type")==11 else "directory_index_reference",
                                     "assessment": assessment})
                    if full_path is not None: terms.append((finding_id,"path",full_path.casefold()))
                new["directory_entries"] += len(entries)
                new["directory_cursor"] = summary["next_cursor"]
                if summary["eof"]:
                    if summary["next_cursor"] != summary["reported_total"]: raise RIError("Fin de directorio inconsistente.")
                    new["directories_completed"] += 1; new.update(after_directory=parent, directory_cursor=0, directory_total=None)
                elif not entries: raise RIError("Página sin progreso.")
        envelope = {"schema_version": 1, "case_id": job["case_id"], "scan_id": job["id"], "operation_id": operation["id"],
                    "source_id": job["source_id"], "page_index": state["page_index"], "request": request,
                    "previous_page_sha256": state["previous_page_sha256"], "response": response, "findings": findings, "limitations": SCAN_LIMITATIONS}
        data = canonical(envelope).encode(); sha = bytes_digest(data)
        path = store.path(directory / ("page-" + str(state["page_index"]) + "-" + operation["id"] + "-" + sha + ".json"))
        _atomic(path, data)
        if response["receipt"]["status"] != "ok":
            return store.update_operation(operation["id"], "failed", [{"failed_scan_page": {"path": path.relative_to(store.workspace).as_posix(), "sha256": sha, "size_bytes": len(data)}}], actor)
        new["page_index"] += 1; new["previous_page_sha256"] = sha
        source = store.get("evidence", job["source_id"])
        evidence = {"identity_key": "ntfs-scan-page:"+job["id"]+":"+str(state["page_index"]), "mode": source["mode"], "status": "ntfs_scan_page",
                    "source_evidence_id": source["id"], "relative_path": path.relative_to(store.workspace).as_posix(),
                    "content_sha256": sha, "size_bytes": len(data), "page_index": state["page_index"], "findings_count": len(findings), "file_data_acquisition": False}
        return store.commit_ntfs_scan_page(job["id"], operation["id"], state, new, evidence, directories, terms, actor)
    def accept(operation,response):
        try:
            return accept_validated(operation,response)
        except PublicationPending:
            raise
        except (RIError,OSError,ValueError,KeyError,TypeError) as exc:
            if store.get("operations",operation["id"])["status"]!="started": raise
            envelope={"schema_version":1,"scan_id":job["id"],"case_id":job["case_id"],"operation_id":operation["id"],
                      "request":operation["request"],"response":response,"validation_error":str(exc),"checkpoint_advanced":False}
            data=canonical(envelope).encode(); sha=bytes_digest(data)
            path=directory/("failed-"+operation["id"]+"-"+sha+".json"); _atomic(path,data)
            return store.update_operation(operation["id"],"failed",[{"failed_scan_page":{"path":path.relative_to(store.workspace).as_posix(),"sha256":sha,"size_bytes":len(data)},"error_type":type(exc).__name__}],actor)
    return accept


def status(store, case_id, scan_id):
    job, source = _job(store, case_id, scan_id); state = store.ntfs_scan_state(scan_id)
    volume = state["volume_identity"]
    denominator = volume["last_inode"]-volume["first_inode"]+1 if volume else None
    failures=[]; failure_count=0; attempts=0; unresolved=[]; current_failure=False
    for operation in store.ntfs_scan_attempts(scan_id):
        attempts+=1
        if operation["status"]=="started": unresolved.append(operation["id"])
        if operation["status"]=="failed":
            failure_count+=1
            if operation["scan_context"]["page_index"]==state["page_index"]: current_failure=True
            if len(failures)<100: failures.append(operation["id"])
    return {"scan_id": scan_id, "case_id": case_id, "source_id": source["id"], "status": job["status"], "checkpoint": state,
            "execution_state":"finished" if job["status"]!="started" else "paused_after_failure" if current_failure else "checkpoint_ready_or_waiting_approval",
            "attempt_count":attempts,"failed_operation_count":failure_count,"failed_operation_ids":failures,"failure_list_truncated":failure_count>len(failures),
            "unresolved_operation_ids":unresolved,
            "coverage": {"mft_slots_examined": state["slots_examined"], "tsk_reported_mft_slots": denominator,
                         "mft_slot_percent": 100*state["slots_examined"]/denominator if denominator else None,
                         "allocated_directories_indexed": state["directories_indexed"], "directories_completed": state["directories_completed"],
                         "tsk_virtual_directories_indexed":state["virtual_directories_indexed"],
                         "ntfs_directories_indexed":state["directories_indexed"]-state["virtual_directories_indexed"],
                         "whole_device_percent": None, "file_content_coverage": "not_in_scope"},
            "pending_physical_requests": store.ntfs_scan_pending(scan_id), "limitations": SCAN_LIMITATIONS}


def _finish_if_done(store, job, state, actor):
    if next_page(store, job, state) is not None: return False
    if state["phase"] != "directories" or state["directories_completed"] != state["directories_indexed"]:
        raise RIError("Cobertura inconsistente; no se finalizará.")
    report = status(store, job["case_id"], job["id"])
    report["summary_status"] = "partial" if state["path_warnings"] or report["unresolved_operation_ids"] else "completed"
    directory=store.path(store.workspace/"scans"/job["id"])
    markdown=("# Resumen técnico de inventario NTFS\n\n"
        f"- Caso: `{job['case_id']}`\n- Escaneo: `{job['id']}`\n- Fuente/volumen: `{job['source_id']}`\n"
        f"- Estado del alcance: **{report['summary_status']}**\n- Volúmenes de este escaneo: 1 (otras particiones no examinadas por este job).\n"
        f"- Slots MFT examinados: {state['slots_examined']} / {report['coverage']['tsk_reported_mft_slots']} reportados por TSK.\n"
        f"- Registros decodificados: {state['records_decoded']}; archivos asignados: {state['allocated_files']}.\n"
        f"- Directorios enumerados: {state['directories_completed']} / {state['directories_indexed']} asignados indexados.\n"
        f"- Incluidos en ese total: {state['virtual_directories_indexed']} directorios virtuales de TSK, no directorios físicos adicionales.\n"
        f"- Entradas de directorio leídas (incluye referencias especiales): {state['directory_entries']}.\n"
        f"- Candidatos eliminados usados: {state['deleted_candidates']}.\n- Advertencias de ruta: {state['path_warnings']}.\n"
        f"- Páginas de namespace virtual sin ruta NTFS absoluta: {state['virtual_path_pages']} (límite esperado, no ruta inventada).\n"
        f"- Operaciones fallidas previas: {report['failed_operation_count']}; operaciones sin resolver: {len(report['unresolved_operation_ids'])}.\n\n"
        "## Candidatos por metadatos (no verificación de contenido)\n\n"+
        "".join(f"- {label}: {count}\n" for label,count in sorted(state["category_counts"].items()))+
        "\n## Límites\n\n"+"".join("- "+limit+"\n" for limit in SCAN_LIMITATIONS)+
        "\nNo se confirmó recuperabilidad ni se generó un informe ejecutivo. Consultar las páginas inmutables y sus IDs RI-F para el fundamento técnico.\n")
    data=markdown.encode(); sha=bytes_digest(data); path=directory/("summary-"+sha+".md"); _atomic(path,data)
    reference={"path":path.relative_to(store.workspace).as_posix(),"sha256":sha,"size_bytes":len(data)}
    store.update_operation(job["id"], report["summary_status"], [{"scan_summary": report,"technical_summary":reference}], actor)
    return True


def verify_saved_scan(store,case_id,scan_id):
    job,source=_job(store,case_id,scan_id); state=store.ntfs_scan_state(scan_id)
    pages=sorted((e for e in store.list("evidence",case_id) if e.get("scan_id")==scan_id and e.get("status")=="ntfs_scan_page"),key=lambda e:e["page_index"])
    if [p["page_index"] for p in pages]!=list(range(state["page_index"])): raise RIError("Páginas duplicadas o ausentes en el checkpoint.")
    previous="0"*64; previous_state=job["initial_state"]
    for evidence in pages:
        path=store.path(store.workspace/evidence["relative_path"],exists=True); data=_read(path)
        if len(data)!=evidence["size_bytes"] or bytes_digest(data)!=evidence["content_sha256"]: raise RIError("Página NTFS alterada.")
        page=json.loads(data); operation=store.get("operations",evidence["operation_id"])
        if (page["case_id"]!=case_id or page["scan_id"]!=scan_id or page["source_id"]!=source["id"] or page["operation_id"]!=operation["id"]
                or operation["status"]!="completed" or page["request"]!=operation["request"] or page["previous_page_sha256"]!=previous
                or evidence["prior_state_sha256"]!=digest(previous_state) or page["response"]["receipt"]["status"]!="ok"):
            raise RIError("Página, operación o cadena de checkpoint inconsistente.")
        previous=evidence["content_sha256"]; previous_state=evidence["next_state"]
    if previous!=state["previous_page_sha256"] or previous_state!=state: raise RIError("La cadena no termina en el checkpoint actual.")
    failed_fragments=0
    for attempt in store.ntfs_scan_attempts(scan_id):
        if attempt["status"]!="failed": continue
        for result in attempt.get("results",[]):
            if "failed_scan_page" not in result: continue
            ref=result["failed_scan_page"]; data=_read(store.path(store.workspace/ref["path"]))
            if bytes_digest(data)!=ref["sha256"] or len(data)!=ref["size_bytes"]: raise RIError("Fragmento de fallo alterado.")
            fragment=json.loads(data)
            if fragment["scan_id"]!=scan_id or fragment["case_id"]!=case_id or fragment["operation_id"]!=attempt["id"]: raise RIError("Procedencia de fragmento de fallo inconsistente.")
            failed_fragments+=1
    if job["status"]!="started":
        summary=job["results"][0]["technical_summary"]; data=_read(store.path(store.workspace/summary["path"]))
        if bytes_digest(data)!=summary["sha256"] or len(data)!=summary["size_bytes"]: raise RIError("Resumen técnico alterado.")
    return {"valid":True,"scan_id":scan_id,"pages_verified":len(pages),"failed_fragments_verified":failed_fragments,"status":job["status"],"physical_sources_opened":False,
            "file_contents_opened":False,"scope":"saved metadata pages, checkpoint chain and technical summary only"}


def run_image_batch(store, case_id, scan_id, *, actor, reason, authorized, scope, max_pages=8):
    if authorized is not True or scope != "ntfs.scan-metadata": raise RIError("Lote requiere --authorize-read y --scope ntfs.scan-metadata.")
    if type(max_pages) is not int or not 1 <= max_pages <= 256: raise RIError("Lote de 1 a 256 páginas requerido.")
    job, source = _job(store, case_id, scan_id)
    _check_producer(job)
    if source["kind"] != "image": raise RIError("Dispositivo físico solo mediante solicitudes exactas y broker; no ejecución directa.")
    with _scan_lock(store, scan_id) as directory:
        for _ in range(max_pages):
            job, source = _job(store, case_id, scan_id)
            if job["status"] != "started": break
            state = store.ntfs_scan_state(scan_id)
            if _finish_if_done(store, job, state, actor): break
            page_scope, params = next_page(store, job, state)
            operation = triage.run_image(store, case_id, source["id"], page_scope, params, actor=actor, reason=reason,
                                        authorized=True, provided_scope=page_scope, _page_handler=_page_handler(store, job, state, actor, directory),
                                        _scan_context={"scan_id":scan_id,"page_index":state["page_index"]})
            if operation["status"] != "completed": break
        job = store.get("operations", scan_id)
        if job["status"] == "started": _finish_if_done(store, job, store.ntfs_scan_state(scan_id), actor)
    return status(store, case_id, scan_id)


def prepare_physical_batch(store, case_id, scan_id, *, actor, reason, authorized, scope, max_pages=8, retry_failed=False):
    if authorized is not True or scope != "ntfs.scan-metadata": raise RIError("Preparación requiere alcance explícito de metadatos.")
    if type(max_pages) is not int or not 1 <= max_pages <= 8: raise RIError("Lote físico de hasta 8 páginas exactas.")
    job, source = _job(store, case_id, scan_id)
    _check_producer(job)
    if source["kind"] != "physical" or job["status"] != "started": raise RIError("Escaneo físico pendiente requerido.")
    with _scan_lock(store, scan_id) as directory:
        pending = store.ntfs_scan_pending(scan_id)
        if pending:
            if not retry_failed: raise RIError("Hay solicitudes pendientes/fallidas: revisar ledger; no crear lecturas duplicadas.")
            store.clear_failed_ntfs_scan_pending(scan_id)
        state = store.ntfs_scan_state(scan_id)
        if _finish_if_done(store, job, state, actor): return status(store, case_id, scan_id)
        work = json.loads(canonical(state)); requests = []
        for index in range(max_pages if state["phase"] == "records" else 1):
            page_scope, params = next_page(store, job, work)
            prepared = triage.prepare_device(store, case_id, source["id"], page_scope, params, actor=actor,
                        reason=reason+" [scan "+scan_id+" page "+str(state["page_index"]+index)+"]", authorized=True, provided_scope=page_scope,
                        _scan_context={"scan_id":scan_id,"page_index":state["page_index"]+index})
            operation = store.get("operations", prepared["operation_id"])
            store.add_ntfs_scan_pending(scan_id, state["page_index"]+index, operation["id"])
            requests.append(operation["request"])
            if state["phase"] != "records": break
            work["next_inode"] += params["max_entries"]
            if work["next_inode"] > state["volume_identity"]["last_inode"]: break
        bundle = {"schema_version": 1, "requests": requests}; data = canonical(bundle).encode()
        path = directory / ("batch-"+uuid.uuid4().hex+".json"); _atomic(path,data)
        return {"scan_id": scan_id, "batch_file": str(path), "batch_sha256": bytes_digest(data), "request_count": len(requests),
                "physical_read_performed": False, "status": "awaiting_exact_administrator_batch_approval"}


def execute_physical_batch(store, case_id, scan_id, *, actor, authorized, max_pages=8):
    if authorized is not True or type(max_pages) is not int or not 1 <= max_pages <= 8: raise RIError("Confirmación de lote de hasta 8 solicitudes requerida.")
    job, source = _job(store, case_id, scan_id)
    _check_producer(job)
    if source["kind"] != "physical": raise RIError("Escaneo físico requerido.")
    with _scan_lock(store, scan_id) as directory:
        for pending in store.ntfs_scan_pending(scan_id)[:max_pages]:
            state = store.ntfs_scan_state(scan_id)
            if pending["page_index"] != state["page_index"]: raise RIError("Solicitud fuera de secuencia; no ejecutar.")
            operation = triage.execute_device(store, case_id, pending["operation_id"], actor,
                         _page_handler=_page_handler(store, job, state, actor, directory))
            if operation["status"] != "completed": break
        if store.get("operations", scan_id)["status"] == "started": _finish_if_done(store, job, store.ntfs_scan_state(scan_id), actor)
    return status(store, case_id, scan_id)


def prepare_initial_validation(store,case_id,source_id,*,directory_inode,directory_name,expected_count,actor,reason,authorized):
    """Four exact metadata operations; no full-scan gate bypass or content scope."""
    if authorized is not True or type(directory_inode) is not int or not 16<=directory_inode<2**63 or type(expected_count) is not int or not 1<=expected_count<=126:
        raise RIError("Confirmación y directorio/conteo acotados requeridos.")
    source=triage._source(store,case_id,source_id)
    if source["kind"]!="physical" or not {"partition_table_type","partition_table_id"} <= set(source["pin"]): raise RIError("Pin físico completo con tabla de particiones requerido.")
    from .safety import text
    directory_name=text(directory_name,"nombre de directorio esperado",255); reason=text(reason,"motivo")
    operation=store.record("operations",case_id,{"scope":"ntfs.validation-prepare","status":"started","source_id":source_id,
            "parameters":{"directory_inode":directory_inode,"directory_name_expected":directory_name,"expected_file_count":expected_count,
                          "read_budget_per_request":64*1024*1024,"timeout_ms_per_request":10000,"metadata_only":True}},actor)
    requests=[]; operation_ids=[]
    specifications=[("ntfs.volume",{}),("ntfs.records",{"inode":5,"max_entries":1}),
                    ("ntfs.records",{"inode":directory_inode,"max_entries":1}),
                    ("ntfs.directory",{"inode":directory_inode,"max_entries":128,"cursor":0})]
    try:
        for scope,params in specifications:
            prepared=triage.prepare_device(store,case_id,source_id,scope,params,actor=actor,reason=reason,authorized=True,provided_scope=scope)
            child=store.get("operations",prepared["operation_id"]); operation_ids.append(child["id"]); requests.append(child["request"])
        directory=store.path(store.workspace/"ntfs-requests"); bundle={"schema_version":1,"requests":requests}; data=canonical(bundle).encode()
        path=directory/("validation-batch-"+operation["id"]+".json"); _atomic(path,data)
        result={"batch_file":str(path),"batch_sha256":bytes_digest(data),"operation_ids":operation_ids,"request_count":len(requests),
                "listing_operation_id":operation_ids[3],"metadata_operation_id":operation_ids[2],"physical_read_performed":False}
        store.update_operation(operation["id"],"completed",[result],actor)
        return {**result,"plan_operation_id":operation["id"],"status":"awaiting_exact_administrator_batch_approval"}
    except PublicationPending: raise
    except (RIError,OSError,ValueError) as exc:
        store.update_operation(operation["id"],"failed",[{"error_type":type(exc).__name__,"prepared_operation_ids":operation_ids}],actor); raise


def execute_initial_validation(store,case_id,plan_operation_id,*,actor,authorized):
    if authorized is not True: raise RIError("--authorize-batch requerido; no sustituye aprobación del broker.")
    plan=store.get("operations",plan_operation_id)
    if plan["case_id"]!=case_id or plan.get("scope")!="ntfs.validation-prepare" or plan["status"]!="completed": raise RIError("Plan inicial preparado de este caso requerido.")
    reference=plan["results"][0]; data=_read(store.path(reference["batch_file"],exists=True))
    if bytes_digest(data)!=reference["batch_sha256"]: raise RIError("Lote inicial alterado.")
    bundle=json.loads(data)
    if len(bundle["requests"])!=4 or len(reference["operation_ids"])!=4: raise RIError("El lote inicial debe contener exactamente cuatro solicitudes.")
    children=[store.get("operations",identifier) for identifier in reference["operation_ids"]]
    source=triage._source(store,case_id,plan["source_id"])
    for child,request in zip(children,bundle["requests"]):
        if child["case_id"]!=case_id or child["source_id"]!=source["id"] or child["request"]!=request or request["scope"] not in core.SCAN_SCOPES or request["source"]!={"kind":"physical","pin":source["pin"]}:
            raise RIError("Solicitudes iniciales no corresponden a la fuente/aprobación.")
    execution=store.record("operations",case_id,{"scope":"ntfs.validation-execution","status":"started","source_id":source["id"],"plan_operation_id":plan_operation_id},actor)
    outcomes=[]
    try:
        for child in children:
            if child["status"]=="failed": raise RIError("Solicitud previa fallida; revisar ledger y renovar lote, no reintentar automáticamente.")
            if child["status"]=="completed":
                outcomes.append({"operation_id":child["id"],"status":"completed","reused_saved_result":True}); continue
            result=triage.execute_device(store,case_id,child["id"],actor)
            outcomes.append({"operation_id":child["id"],"status":result["status"],"reused_saved_result":False})
            if result["status"]!="completed":
                store.update_operation(execution["id"],"partial",[{"outcomes":outcomes,"stopped":True}],actor)
                return {"operation_id":execution["id"],"status":"partial","operations_completed":sum(o["status"]=="completed" for o in outcomes),"validation_passed":False}
        store.update_operation(execution["id"],"completed",[{"outcomes":outcomes,"comparison_still_required":True}],actor)
        return {"operation_id":execution["id"],"status":"completed","operations_completed":len(outcomes),"validation_passed":False,
                "next_step":"compare-reference against approved prior TSK evidence; execution alone is not validation",
                "listing_operation_id":reference["listing_operation_id"],"metadata_operation_id":reference["metadata_operation_id"],"root_metadata_operation_id":reference["operation_ids"][1]}
    except PublicationPending: raise
    except (RIError,OSError,ValueError) as exc:
        store.update_operation(execution["id"],"failed",[{"error_type":type(exc).__name__,"outcomes":outcomes,"stopped":True}],actor); raise


def _save_derived(store, case_id, operation, document, actor, *, status_name="completed"):
    directory = store.path(store.workspace / "scans"); directory.mkdir(mode=0o700, exist_ok=True); store._private(directory,directory=True)
    data=canonical(document).encode(); sha=bytes_digest(data)
    path=directory/("report-"+operation["id"]+"-"+sha+".json"); _atomic(path,data)
    reference={"path":path.relative_to(store.workspace).as_posix(),"sha256":sha,"size_bytes":len(data)}
    evidence=store.record("evidence",case_id,{"identity_key":"ntfs-derived:"+operation["id"],"mode":"derived","status":"ntfs_metadata_report",
              "operation_id":operation["id"],"relative_path":reference["path"],"content_sha256":sha,"size_bytes":len(data),"physical_reads_performed":False},actor)
    store.update_operation(operation["id"],status_name,[{"metadata_report":{**reference,"evidence_id":evidence["id"]}}],actor)
    return {"operation_id":operation["id"],"evidence_id":evidence["id"],"status":status_name,"report":reference}


def correlate_saved(store, case_id, actor, *, max_groups=1000):
    if type(max_groups) is not int or not 1<=max_groups<=10000: raise RIError("Límite de correlaciones inválido.")
    operation=store.record("operations",case_id,{"scope":"ntfs.metadata-correlation","status":"started","parameters":{"max_groups":max_groups},"physical_reads_performed":False},actor)
    try:
        report=store.ntfs_scan_correlations(case_id,max_groups=max_groups)
        # Verify every cited member against its immutable original page, not just the derived SQL index.
        for group in report["groups"]:
            for member in group["members"]:
                evidence=store.get("evidence",member["page_evidence_id"])
                data=_read(store.path(store.workspace/evidence["relative_path"]))
                if bytes_digest(data)!=evidence["content_sha256"]: raise RIError("Página citada por correlación alterada.")
                page=json.loads(data)
                if page["source_id"]!=member["source_id"] or page["scan_id"]!=member["scan_id"]: raise RIError("Procedencia de correlación discrepante.")
                findings={item["finding_id"]:item for item in page["findings"]}
                finding=findings.get(member["finding_id"])
                if finding is None: raise RIError("Hallazgo citado inexistente.")
                rows=page["response"]["result"].get("entries",[])
                if group["kind"]=="path": values=[finding.get("ntfs_path","").casefold()]
                else:
                    row=next((r for r in rows if r.get("kind")=="record" and r["inode"]==finding["inode"] and r["sequence"]==finding.get("sequence")),None)
                    if row is None: raise RIError("Registro citado inexistente.")
                    if group["kind"]=="name": values=[n["name"].casefold() for n in row["names"]]
                    elif group["kind"]=="extension": values=["."+n["name"].casefold().rsplit(".",1)[-1] for n in row["names"] if "." in n["name"] and not n["name"].startswith("$")]
                    else: values=[str(row["times_unix"].get(group["kind"].removeprefix("timestamp_"))) ]
                if group["value"] not in values: raise RIError("Índice de correlación no coincide con la evidencia.")
        # Whole-copy hashes already measured by the existing extraction/analyzer workflows.
        by_hash={}
        registered_complete={result["artifact_id"] for op in store.list("operations",case_id) if op.get("scope")=="artifact_register" and op["status"]=="completed" for result in op.get("results",[]) if "artifact_id" in result}
        for artifact in store.list("evidence",case_id):
            if artifact.get("status") not in ("triage_extracted_copy","extracted_copy_registered"): continue
            if artifact["status"]=="triage_extracted_copy" and store.get("operations",artifact["operation_id"])["status"]!="completed": continue
            if artifact["status"]=="extracted_copy_registered" and artifact["id"] not in registered_complete: continue
            by_hash.setdefault(artifact["content_sha256"],[]).append({"evidence_id":artifact["id"],"source_id":artifact["source_evidence_id"],"size_bytes":artifact["size_bytes"]})
        report["saved_whole_copy_hash_matches"]=[{"sha256":sha,"members":members,"basis":"previous complete-copy measurement; not a fresh read or causal attribution"}
                for sha,members in sorted(by_hash.items()) if len({m["source_id"] for m in members})>1]
        prefix_hashes={}; prefix_signatures={}
        for prefix in store.list("evidence",case_id):
            if prefix.get("status")!="ntfs_prefix_copy": continue
            extraction=store.get("operations",prefix["operation_id"])
            if extraction["status"]!="completed": continue
            member={"evidence_id":prefix["id"],"source_id":prefix["source_evidence_id"],"prefix_size_bytes":prefix["size_bytes"]}
            key=(prefix["size_bytes"],prefix["content_sha256"])
            prefix_hashes.setdefault(key,[]).append(member)
            for signature in prefix["header_assessment"]["signature_observations"]: prefix_signatures.setdefault(signature,[]).append(member)
        report["saved_prefix_hash_matches"]=[{"prefix_size_bytes":key[0],"prefix_sha256":key[1],"members":members,"whole_file_equal":None}
                for key,members in sorted(prefix_hashes.items()) if len({m["source_id"] for m in members})>1]
        report["saved_prefix_signature_matches"]=[{"signature":signature,"members":members,"algorithm":None,"ransomware_family":None,"causal_attribution":"not_established"}
                for signature,members in sorted(prefix_signatures.items()) if len({m["source_id"] for m in members})>1]
        report.update(case_id=case_id,operation_id=operation["id"],generated_at=utcnow(),limitations=SCAN_LIMITATIONS,
                      source_count_meaning="registered sources/partitions, not independently authenticated distinct physical disks")
        partial=report["groups_truncated"] or any(g["members_truncated"] for g in report["groups"])
        result=_save_derived(store,case_id,operation,report,actor,status_name="partial" if partial else "completed")
        return {**result,"groups":len(report["groups"]),"hash_match_groups":len(report["saved_whole_copy_hash_matches"])}
    except PublicationPending: raise
    except (RIError,OSError,ValueError) as exc:
        store.update_operation(operation["id"],"failed",[{"error_type":type(exc).__name__,"reason":str(exc)}],actor); raise


def _saved_payload(store, case_id, identifier):
    operation=store.get("operations",identifier)
    if operation["case_id"]!=case_id or operation["status"]!="completed": raise RIError("Resultado completado del mismo caso requerido.")
    result=operation["results"][0]
    if "scan_page" in result:
        ref=result["scan_page"]; data=_read(store.path(store.workspace/ref["path"]))
        if bytes_digest(data)!=ref["sha256"]: raise RIError("Página guardada alterada.")
        response=json.loads(data)["response"]
    else: response=result
    if response.get("receipt",{}).get("status")!="ok" or not isinstance(response.get("result"),dict): raise RIError("Resultado TSK no válido para comparación.")
    payload={**response["result"],"_measurement":{"receipt":response["receipt"],"physical_validation":response.get("physical_validation")}}
    return operation,payload


def compare_saved_reference(store, case_id, listing_id, metadata_id, baseline_path, expected_sha256, actor, *, root_metadata_id=None):
    operation=store.record("operations",case_id,{"scope":"ntfs.reference-validation","status":"started",
                 "parameters":{"listing_operation":listing_id,"metadata_operation":metadata_id,"root_metadata_operation":root_metadata_id,"baseline_sha256":sha256_value(expected_sha256)},"physical_reads_performed":False},actor)
    try:
        data=_read(store.path(baseline_path,exists=True))
        if bytes_digest(data)!=expected_sha256: raise RIError("Hash de referencia no coincide; no se reparará.")
        baseline=json.loads(data)
        listed,listing=_saved_payload(store,case_id,listing_id); metadata_op,metadata=_saved_payload(store,case_id,metadata_id)
        if listed.get("source_id")!=metadata_op.get("source_id"): raise RIError("Resultados de fuentes distintas.")
        required={"schema_version","source_id","directory_inode","directory_name","directory_path","expected_count","entries","reference_tool"}
        missing=sorted(required-set(baseline))
        failures=[]; sequence_compared=False
        if missing: failures.append({"missing_reference_fields":missing})
        if not missing:
            sha256_value(baseline["reference_tool"]["original_output_sha256"])
            if type(baseline["schema_version"]) is not int or baseline["schema_version"]!=1 or baseline["source_id"]!=listed["source_id"]: failures.append({"reference_source_or_schema_mismatch":True})
            if listed["request"]["parameters"]["inode"]!=baseline["directory_inode"]: failures.append({"directory_inode_mismatch":True})
            rows=metadata.get("entries",[metadata] if metadata.get("kind")=="record" else [])
            record=next((row for row in rows if row.get("inode")==baseline["directory_inode"]),None)
            if record is None or not record.get("allocated") or not record.get("directory") or not any(n["name"]==baseline["directory_name"] for n in record.get("names",[])):
                failures.append({"directory_metadata_not_confirmed":True})
            direct_path="/"+baseline["directory_name"]+"/"
            if baseline["directory_path"]!=direct_path or record is None or not any(n["parent_inode"]==5 and n["name"]==baseline["directory_name"] for n in record.get("names",[])):
                failures.append({"root_relative_directory_path_not_confirmed":True})
            summary=listing.get("summary",{})
            if summary.get("partial") or summary.get("eof") is not True or listed["request"]["parameters"].get("cursor",0)!=0: failures.append({"listing_not_a_complete_direct_directory":True})
            entries=[row for row in listing.get("entries",[]) if row.get("name") not in (".","..")]
            observed=[{"name":row["name"],"inode":row["inode"],"name_unallocated":row["name_unallocated"],"name_sequence":row["name_sequence"],"ntfs_path":direct_path+row["name"]} for row in entries]
            if not isinstance(baseline["entries"],list) or len(baseline["entries"])>126: raise RIError("Referencia debe ser una lista acotada de hasta 126 entradas.")
            if type(baseline["expected_count"]) is not int or len(baseline["entries"])!=baseline["expected_count"] or len(observed)!=baseline["expected_count"]:
                failures.append({"entry_count_or_reference_incomplete":True})
            remaining=list(observed); core_fields={"name","inode","name_unallocated","ntfs_path"}; sequence_compared=bool(baseline["entries"]) and all(row.get("name_sequence") is not None for row in baseline["entries"])
            for expected in baseline["entries"]:
                if (not core_fields <= set(expected) or set(expected)-core_fields-{"name_sequence"} or type(expected["inode"]) is not int
                        or type(expected["name_unallocated"]) is not bool or not isinstance(expected["name"],str) or not isinstance(expected["ntfs_path"],str)
                        or expected.get("name_sequence") is not None and type(expected["name_sequence"]) is not int):
                    raise RIError("Entrada de referencia no tipada o incompleta.")
                match=next((i for i,row in enumerate(remaining) if all(row[key]==expected[key] for key in core_fields)
                            and (expected.get("name_sequence") is None or row["name_sequence"]==expected["name_sequence"])),None)
                if match is None: failures.append({"names_mft_name_allocation_sequence_or_paths_differ":True}); break
                remaining.pop(match)
            if remaining: failures.append({"extra_or_unmatched_observed_entries":len(remaining)})
            listing_volume=listing.get("summary",{}).get("volume_identity"); metadata_volume=metadata.get("summary",{}).get("volume_identity")
            if not isinstance(listing_volume,dict) or listing_volume!=metadata_volume or listing_volume.get("filesystem")!="NTFS": failures.append({"ntfs_volume_identity_not_consistent":True})
        source=triage._source(store,case_id,listed["source_id"])
        root_verified=False
        if root_metadata_id is not None:
            root_op,root_payload=_saved_payload(store,case_id,root_metadata_id)
            root_record=next((r for r in root_payload.get("entries",[]) if r.get("inode")==5 and r.get("allocated") and r.get("directory")),None)
            root_verified=(root_op.get("source_id")==source["id"] and root_record is not None
                           and root_payload.get("summary",{}).get("volume_identity")==listing.get("summary",{}).get("volume_identity")
                           and not missing and record is not None and any(n["parent_inode"]==5 and n.get("parent_sequence")==root_record["sequence"]
                                   and n["name"]==baseline["directory_name"] for n in record.get("names",[])))
        if source["kind"]=="physical" and not root_verified: failures.append({"fresh_root_parent_sequence_not_verified":True})
        measured=[listing.get("_measurement",{}),metadata.get("_measurement",{})]
        workers=[m.get("receipt",{}).get("worker_sha256") for m in measured]
        physical_checks=all(isinstance(m.get("physical_validation"),dict) and m["physical_validation"].get("before")==m["physical_validation"].get("after")
                            and m["physical_validation"].get("broker_audit_sha256") for m in measured)
        if workers[0] and workers[1] and workers[0]!=workers[1]: failures.append({"worker_builds_differ":True})
        report={"schema_version":1,"case_id":case_id,"operation_id":operation["id"],"listing_operation_id":listing_id,"metadata_operation_id":metadata_id,
                "baseline_sha256":expected_sha256,"reference_tool":baseline.get("reference_tool"),"validation_passed":not failures,
                "comparison_status":"matches_supplied_reference" if not failures else "inconclusive_or_mismatch","differences":failures,
                "source_id":source["id"],"device_source_record_sha256":digest(source),"worker_sha256":workers[0],
                "root_parent_sequence_verified":root_verified,
                "child_name_sequences_compared":sequence_compared,
                "eligible_for_physical_gate":not failures and source["kind"]=="physical" and physical_checks and isinstance(workers[0],str) and workers[0]==workers[1],
                "validation_scope":{key:baseline.get(key) for key in ("directory_inode","directory_name","directory_path","expected_count")},
                "limitations":["Matches only the operator-supplied normalized TSK reference; original output hash is declared, not reread here.",
                    "Allocation comparison uses directory-name flags, not proof of DATA integrity or fresh allocation flags of every child.",
                    "No full scan is authorized by passing this comparison."]}
        saved=_save_derived(store,case_id,operation,report,actor,status_name="completed" if not failures else "partial")
        return {**saved,"validation_passed":not failures,"comparison_status":report["comparison_status"]}
    except PublicationPending: raise
    except (RIError,OSError,ValueError,KeyError,TypeError) as exc:
        store.update_operation(operation["id"],"failed",[{"error_type":type(exc).__name__}],actor); raise RIError("Referencia inválida o resultados no comparables; revisar registro local.") from exc
