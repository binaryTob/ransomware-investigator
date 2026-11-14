"""Standalone stdlib-only core, also deployed beside the privileged broker.

No case DB imports, shell, source-path arguments to TSK, or write-capable source
descriptors. The root broker uses this same code with a child UID > 0.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

SCAN_SCOPES = frozenset({"ntfs.volume", "ntfs.records", "ntfs.directory"})
SCOPES = frozenset({"ntfs.list", "ntfs.search", "ntfs.mft", "ntfs.deleted", "ntfs.extract", "ntfs.prefix", "ntfs.diagnose"}) | SCAN_SCOPES
PARAMETERS = {"inode": 5, "attribute_id": 0, "max_entries": 1000, "max_depth": 0,
              "max_bytes": 1024 * 1024, "expected_sequence": 0, "expected_size": 0,
              "allow_deleted": False, "read_budget": 64 * 1024 * 1024, "timeout_ms": 10000, "extensions": []}
BOUNDS = {"inode": (0, 2**63-1), "attribute_id": (0,65535), "max_entries": (1,10000), "max_depth": (0,8),
          "max_bytes": (1,16*1024*1024), "expected_sequence": (0,2**32-1), "expected_size": (0,16*1024*1024),
          "read_budget": (4096,256*1024*1024), "timeout_ms": (1,15000)}

class TriageError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()

def sha(value):
    return hashlib.sha256(value).hexdigest()

def parameters(scope: str, supplied: dict) -> dict:
    defaults = {**PARAMETERS, **({"cursor": 0} if scope == "ntfs.directory" else {})}
    if scope == "ntfs.diagnose": defaults.update(inode=16, max_entries=1, max_bytes=65536)
    if scope not in SCOPES or not isinstance(supplied, dict) or supplied.keys() - defaults.keys():
        raise TriageError("Operación o argumentos de triage no admitidos.")
    result = {**defaults, **supplied}
    if "cursor" in result and (type(result["cursor"]) is not int or not 0 <= result["cursor"] < 2**63):
        raise TriageError("Cursor de directorio inválido.")
    if scope in SCAN_SCOPES and result["max_depth"] != 0:
        raise TriageError("Las páginas de escaneo no son recorridos recursivos.")
    for key, (low, high) in BOUNDS.items():
        if scope == "ntfs.prefix" and key == "expected_size": high = 2**63-1
        # Explicit directory-open budgets only: libtsk can build a whole-MFT
        # parent/orphan map before applying the output cursor. Defaults and
        # every other operation keep the previous 256 MiB ceiling.
        if scope == "ntfs.directory" and key == "read_budget": high = 512*1024*1024
        if type(result[key]) is not int or not low <= result[key] <= high:
            raise TriageError("Argumento numérico fuera del alcance: " + key)
    if type(result["allow_deleted"]) is not bool:
        raise TriageError("allow_deleted debe ser booleano.")
    extensions = result["extensions"]
    if not isinstance(extensions,list) or len(extensions)>32 or any(not isinstance(s,str) or not re.fullmatch(r"\.[A-Za-z0-9_-]{1,32}",s) for s in extensions):
        raise TriageError("Extensiones inválidas (máximo 32, sin patrones ni comandos).")
    result["extensions"] = sorted(set(s.casefold() for s in extensions))
    if scope == "ntfs.search" and not extensions:
        raise TriageError("La búsqueda requiere extensiones explícitas; no se atribuye una familia.")
    if scope != "ntfs.search" and extensions:
        raise TriageError("Extensiones solo permitidas en ntfs.search.")
    if scope in ("ntfs.mft","ntfs.extract","ntfs.deleted") and result["max_depth"]!=0:
        raise TriageError("Profundidad solo aplicable a exploración/búsqueda de directorios.")
    if scope == "ntfs.extract" and (result["inode"] < 16 or result["expected_sequence"] < 1 or result["expected_size"] > result["max_bytes"]):
        raise TriageError("Extracción requiere inode no sistémico, secuencia y tamaño dentro del límite.")
    if scope == "ntfs.prefix" and (result["inode"]<16 or result["expected_sequence"]<1 or result["expected_size"]<1 or result["max_bytes"]>65536 or result["max_depth"]!=0):
        raise TriageError("Prefijo requiere MFT/secuencia/tamaño del stream y un límite explícito de hasta 64 KiB.")
    if scope == "ntfs.diagnose" and (result["inode"]<16 or result["read_budget"]>64*1024*1024 or result["timeout_ms"]>10000 or
            any(result[k]!=v for k,v in defaults.items() if k not in ("inode","read_budget","timeout_ms"))):
        raise TriageError("Diagnóstico: un slot no sistémico, solo metadatos, hasta 64 MiB/10 s; sin extracción ni cursor.")
    return result

def diagnostic_row(row, inode):
    """Closed metadata protocol, not an inventory record or independent map validation."""
    keys = {"kind","inode","assessment","reason","inventory_eligible","locator","checker",
            "sector_size","cluster_size","record_size","mft_start_bytes","bitmap","record"}
    assessments = {"inconclusive","structural_rejection","unallocated_corroborated","valid_header_fixups"}
    structures = {"signature_rejected","usa_count_rejected","usa_bounds_rejected","fixup_mismatch","header_bounds_rejected","valid_header_fixups"}
    reasons = structures | {"unsupported_geometry","inode_out_of_range","mft_mapping_unavailable","bitmap_unavailable","zero_and_bitmap_free","allocation_conflict","header_and_bitmap_agree"}
    if (not isinstance(row,dict) or set(row)!=keys or row["kind"]!="diagnostic" or type(row["inode"]) is not int or row["inode"]!=inode or
            row["inventory_eligible"] is not False or row["locator"]!="libtsk_mft_map" or row["checker"]!="bounded_header_fixups_v1" or
            row["assessment"] not in assessments or row["reason"] not in reasons or row["bitmap"] not in ("unknown","free","allocated")):
        raise ValueError("diagnostic protocol")
    for key, high in (("sector_size",65535),("cluster_size",2**32-1),("record_size",2**32-1),("mft_start_bytes",2**63-1)):
        if type(row[key]) is not int or not 0<=row[key]<=high: raise ValueError("diagnostic geometry")
    record=row["record"]
    if record is not None:
        limits={"usa_offset":65535,"usa_count":65535,"attribute_offset":65535,"flags":65535,
                "bytes_used":2**32-1,"bytes_allocated":2**32-1,"fixup_mismatches":128}
        if (not isinstance(record,dict) or set(record)!=set(limits)|{"signature","structure"} or
                record["signature"] not in ("file","zero","other") or record["structure"] not in structures):
            raise ValueError("diagnostic header")
        for key,high in limits.items():
            if type(record[key]) is not int or not 0<=record[key]<=high: raise ValueError("diagnostic header number")
        size=row["record_size"]
        if row["sector_size"]!=512 or not 512<=size<=65536 or size%512:
            raise ValueError("diagnostic unsupported record geometry")
        if record["structure"]=="valid_header_fixups" and not (
                record["signature"]=="file" and record["usa_count"]==size//512+1 and
                48<=record["usa_offset"] and not record["usa_offset"]%2 and
                record["usa_offset"]+record["usa_count"]*2<=min(510,record["attribute_offset"]) and
                not record["fixup_mismatches"] and not record["attribute_offset"]%8 and
                48<=record["attribute_offset"]<=size-4 and record["attribute_offset"]+4<=record["bytes_used"]<=size and
                record["bytes_allocated"]==size and not record["flags"]&~3):
            raise ValueError("diagnostic header contradiction")
    if row["assessment"]=="valid_header_fixups" and (row["bitmap"]!="allocated" or not record or record["structure"]!="valid_header_fixups" or not record["flags"]&1):
        raise ValueError("diagnostic validity conflict")
    if row["assessment"]=="unallocated_corroborated" and (row["bitmap"]!="free" or not record or not
            (record["signature"]=="zero" or record["structure"]=="valid_header_fixups" and not record["flags"]&1)):
        raise ValueError("diagnostic allocation conflict")
    if row["assessment"] in ("valid_header_fixups","unallocated_corroborated") and row["reason"] not in ("header_and_bitmap_agree","zero_and_bitmap_free"):
        raise ValueError("diagnostic validity reason")
    if row["assessment"]=="structural_rejection" and (not record or row["bitmap"]=="unknown" or
            row["reason"]!=record["structure"] or record["structure"]=="valid_header_fixups"):
        raise ValueError("diagnostic rejection contradiction")
    if row["assessment"]=="inconclusive" and row["reason"] not in ("unsupported_geometry","inode_out_of_range","mft_mapping_unavailable","bitmap_unavailable","allocation_conflict"):
        raise ValueError("diagnostic inconclusive reason")
    return row

def validate_request(request: dict) -> dict:
    keys = {"schema_version","request_id","case_id","source_id","uid","scope","parameters","source","reason"}
    if not isinstance(request,dict) or set(request) != keys or type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise TriageError("Formato de solicitud no admitido.")
    for key in ("request_id","case_id","source_id"):
        if not isinstance(request[key],str) or not re.fullmatch(r"[0-9a-f]{32}",request[key]):
            raise TriageError("ID de solicitud/caso/fuente inválido.")
    if type(request["uid"]) is not int or not 0 < request["uid"] < 2**31:
        raise TriageError("UID solicitante inválido; nunca root.")
    if not isinstance(request["reason"],str) or not request["reason"].strip() or len(request["reason"])>4096 or any(ord(c)<32 for c in request["reason"]):
        raise TriageError("Motivo de autorización requerido.")
    clean = parameters(request["scope"],request["parameters"])
    if clean != request["parameters"]:
        raise TriageError("La solicitud debe contener parámetros canónicos completos.")
    if not isinstance(request["source"],dict) or request["source"].get("kind") not in ("image","physical"):
        raise TriageError("Tipo de fuente inválido.")
    return request

def trusted_file(path: Path, *, privileged=False, executable=False):
    target = Path(path)
    if not target.is_absolute() or target.is_symlink():
        raise TriageError("Archivo de ejecución no confiable.")
    info = target.stat()
    expected = 0 if privileged else os.getuid()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != expected or info.st_nlink != 1 or info.st_mode & 0o6022:
        raise TriageError("Código/binario debe ser propio (root en broker), sin permisos de escritura ajenos ni setid.")
    if executable and not info.st_mode & 0o100:
        raise TriageError("Worker no ejecutable; compilar antes de usar.")
    if privileged:
        for parent in target.parents:
            pi = parent.stat()
            if parent.is_symlink() or pi.st_uid != 0 or pi.st_mode & 0o022:
                raise TriageError("El broker no puede importar/ejecutar código de un checkout modificable.")
    try:
        if os.getxattr(target,"security.capability"):
            raise TriageError("Capabilities de archivo prohibidas.")
    except OSError as exc:
        import errno
        if exc.errno not in (errno.ENODATA,errno.ENOTSUP):
            raise TriageError("No se pudieron verificar capabilities.") from exc
    return target

def run_worker(worker: Path, fd: int, request: dict, *, base: int, length: int, gid: int | None = None, parser_uid: int | None = None, not_after: float | None = None) -> dict:
    validate_request(request)
    privileged = os.geteuid() == 0
    worker = trusted_file(worker, privileged=privileged, executable=True)
    if (os.getuid()==0) != privileged:
        raise TriageError("No se admite ejecución setuid.")
    if privileged and (gid is None or type(gid) is not int or gid <= 0 or type(parser_uid) is not int or parser_uid<=0 or parser_uid==request["uid"]):
        raise TriageError("El parser requiere UID/GID dedicado distinto de root y del agente; sin grupos suplementarios.")
    import fcntl
    if fcntl.fcntl(fd,fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        raise TriageError("Descriptor de fuente no es solo lectura.")
    source_info=os.fstat(fd)
    if request["source"]["kind"]=="physical":
        if not privileged or not stat.S_ISBLK(source_info.st_mode):
            raise TriageError("Una fuente física solo puede entrar por el broker y un descriptor de bloques verificado.")
    elif privileged or not stat.S_ISREG(source_info.st_mode):
        raise TriageError("Imágenes regulares solo como usuario normal.")
    if type(base) is not int or type(length) is not int or base<0 or length<=0 or base+length>2**63-1:
        raise TriageError("Extensión de volumen inválida.")
    p = request["parameters"]
    duration_ms=p["timeout_ms"] if not_after is None else min(p["timeout_ms"],int((not_after-time.time())*1000))
    if duration_ms<=0: raise TriageError("Autorización vencida antes de iniciar lecturas.")
    argv = [str(worker),str(fd),request["scope"].split(".")[1],str(base),str(length)] + [str(int(p[k])) for k in
            ("inode","attribute_id","max_entries","max_depth","max_bytes","expected_sequence","expected_size","allow_deleted","read_budget","timeout_ms")]
    argv[-1]=str(duration_ms)
    if request["scope"] == "ntfs.directory": argv.append(str(p["cursor"]))
    actual_parser_uid=parser_uid if privileged else os.getuid()
    kwargs = {"user":actual_parser_uid,"group":gid,"extra_groups":[]} if privileged else {}
    env={"PATH":"/usr/bin:/bin","LC_ALL":"C","LANG":"C","HOME":"/nonexistent"}
    started_at = datetime.now(timezone.utc).isoformat()
    proc = subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                            pass_fds=(fd,),close_fds=True,shell=False,start_new_session=True,env=env,umask=0o077,**kwargs)
    proc.stdin.close()
    out, err = bytearray(), bytearray()
    status, start = "ok", time.monotonic()
    cap = p["max_bytes"] if request["scope"] in ("ntfs.extract","ntfs.prefix","ntfs.diagnose") else 8*1024*1024
    try:
        with selectors.DefaultSelector() as selector:
            for stream, destination in ((proc.stdout,out),(proc.stderr,err)):
                os.set_blocking(stream.fileno(),False)
                selector.register(stream,selectors.EVENT_READ,destination)
            while selector.get_map():
                remaining = p["timeout_ms"]/1000+1 - (time.monotonic()-start)
                if remaining<=0:
                    status="timeout"; break
                for key,_ in selector.select(min(remaining,0.1)):
                    data = os.read(key.fd,65536)
                    if not data:
                        selector.unregister(key.fileobj); continue
                    destination=key.data
                    limit=cap if destination is out else 1024*1024
                    if len(destination)+len(data)>limit:
                        status="output_limit"; break
                    destination.extend(data)
                if status!="ok": break
        if status=="ok":
            try: proc.wait(timeout=max(0.001,p["timeout_ms"]/1000+1-(time.monotonic()-start)))
            except subprocess.TimeoutExpired: status="timeout"
    finally:
        if proc.poll() is None:
            try: os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError: pass
        try: proc.wait(timeout=1)
        except subprocess.TimeoutExpired: status="termination_unconfirmed"
        proc.stdout.close(); proc.stderr.close()
    if status=="ok" and proc.returncode!=0: status="worker_failed"
    identities=[line.split()[1:] for line in err.decode("utf-8","backslashreplace").splitlines() if line.startswith("RI_ID ")]
    expected_identity=[str(actual_parser_uid),str(actual_parser_uid),str(gid if privileged else os.getgid())]
    if status=="ok" and identities!=[expected_identity]: status="worker_identity_mismatch"
    receipt = {"status":status,"returncode":proc.returncode,"request_sha256":sha(canonical(request)),
               "stdout_sha256":sha(out),"stderr_sha256":sha(err),"stderr":err.decode("utf-8","backslashreplace"),
               "worker_sha256":sha(worker.read_bytes()),"parser_uid":actual_parser_uid,"requesting_uid":request["uid"],"duration_seconds":time.monotonic()-start}
    receipt["read_offset_basis"]="partition_device_bytes" if request["source"]["kind"]=="physical" else "image_file_bytes"
    receipt["started_at"] = started_at
    receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
    versions = [line.split()[-1] for line in receipt["stderr"].splitlines() if re.fullmatch(r"RI_SUMMARY \d+ \d+ [0-9.]+", line)]
    receipt["tool_version"] = versions[-1] if versions else None
    if status=="ok" and request["scope"]=="ntfs.diagnose":
        # Exit 0 with any warning is NOT a structurally validated diagnostic.
        lines=receipt["stderr"].splitlines()
        allowed=r"(?:RI_ID \d+ \d+ \d+|RI_SANDBOX seccomp_no_open_exec_network_writefiles|RI_READ_INTENT \d+ \d+|RI_READ \d+ \d+ \d+|RI_SUMMARY \d+ \d+ [0-9.]+)"
        if (any(not re.fullmatch(allowed,line) for line in lines) or len(versions)!=1 or
                lines.count("RI_SANDBOX seccomp_no_open_exec_network_writefiles")!=1):
            status="diagnostic_warning"
        else:
            intents=[tuple(map(int,line.split()[1:])) for line in lines if line.startswith("RI_READ_INTENT ")]
            reads=[tuple(map(int,line.split()[1:])) for line in lines if line.startswith("RI_READ ")]
            summary=[tuple(map(int,line.split()[1:3])) for line in lines if line.startswith("RI_SUMMARY ")]
            if (not intents or len(intents)>4096 or [(a,n) for a,n,g in reads if n==g]!=intents or
                    len(reads)!=len(intents) or summary!=[(len(intents),sum(n for _,n in intents))] or
                    summary[0][1]>p["read_budget"] or any(n<=0 or a<base or a+n>base+length for a,n in intents)):
                status="invalid_diagnostic_receipts"
        receipt["status"]=status
    if status!="ok":
        receipt["partial_stdout_base64"] = base64.b64encode(out).decode()
        receipt["partial_stdout_bytes"] = len(out)
        receipt["partial_output_policy"] = "unvalidated diagnostic fragment; not a verified extraction or complete inventory"
        return {"receipt":receipt,"result":None}
    if request["scope"] in ("ntfs.extract","ntfs.prefix"):
        prefix = request["scope"] == "ntfs.prefix"
        if len(out)!=(min(p["expected_size"],p["max_bytes"]) if prefix else p["expected_size"]):
            receipt["status"]="size_mismatch"; return {"receipt":receipt,"result":None}
        result={"data_base64":base64.b64encode(out).decode(),"sha256":sha(out),"size_bytes":len(out),
                "acquisition_type":"selective_ntfs_triage_not_full_image", "deleted_recovery_verified":False}
        if prefix:
            result.update(acquisition_type="selective_prefix_not_complete_file",hash_scope="prefix_only",source_expected_size=p["expected_size"],prefix_offset=0)
    else:
        try:
            rows=[json.loads(line) for line in out.decode("utf-8").splitlines()]
            if request["scope"]=="ntfs.diagnose":
                if len(rows)!=1: raise ValueError("diagnostic row count")
                return {"receipt":receipt,"result":diagnostic_row(rows[0],p["inode"])}
            for row in rows:
                for key in ("name","path"):
                    if key+"_hex" in row: row[key]=bytes.fromhex(row[key+"_hex"]).decode("utf-8","backslashreplace")
                for stream in row.get("streams",[]):
                    stream["name"]=bytes.fromhex(stream["name_hex"]).decode("utf-8","backslashreplace")
                for item in row.get("attributes", []) + row.get("names", []):
                    item["name"] = bytes.fromhex(item["name_hex"]).decode("utf-8", "backslashreplace")
                if row.get("kind")=="entry":
                    row["deleted_candidate"]=True if row["name_unallocated"] or row["metadata_unallocated"] else False if row["metadata_available"] else None
                    row["sequence_matches"]=(row["name_sequence"]==row.get("sequence")) if row["metadata_available"] and row["name_sequence"] is not None else None
            if request["scope"] == "ntfs.volume":
                if len(rows) != 1 or rows[0].get("kind") != "volume": raise ValueError("volume response")
                result = rows[0]
            elif request["scope"] in ("ntfs.records", "ntfs.directory"):
                expected_kind = "record" if request["scope"] == "ntfs.records" else "directory_entry"
                if not rows or rows[-1].get("kind") != "summary" or any(r.get("kind") != expected_kind for r in rows[:-1]): raise ValueError("scan page response")
                result = {"entries": rows[:-1], "summary": rows[-1], "scope": request["scope"]}
            elif request["scope"]=="ntfs.mft":
                if len(rows)!=1 or rows[0].get("kind")!="mft": raise ValueError("MFT response")
                result=rows[0]
            else:
                if not rows or rows[-1].get("kind")!="summary": raise ValueError("missing summary")
                entries=rows[:-1]
                if request["scope"]=="ntfs.search":
                    entries=[r for r in entries if any(r["name"].casefold().endswith(e) for e in p["extensions"])]
                result={"entries":entries,"summary":rows[-1],"scope":request["scope"],"attribution":"not_established",
                        "deleted_scope":"bounded_unallocated_MFT_records; names need not have a reconstructible path"}
        except (ValueError,TypeError,KeyError,AttributeError,IndexError) as exc:
            receipt.update(status="invalid_worker_protocol",protocol_error_type=type(exc).__name__,partial_stdout_base64=base64.b64encode(out).decode(),partial_stdout_bytes=len(out))
            return {"receipt":receipt,"result":None}
    return {"receipt":receipt,"result":result}
