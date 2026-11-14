"""Case-integrated NTFS triage. Physical reads exist only behind the root broker."""
from __future__ import annotations

import base64
import os
import time
import uuid

from .audit import bytes_digest, digest
from .copy_io import file_identity, read_copy
from .ntfs import core
from .ntfs.physical import validate_pin, validate_state
from .safety import PROJECT, Policy, RIError, PublicationPending, copy_path, sha256_value, text

WORKER=PROJECT/".build/ntfs_worker"

def _destination(store,size_bytes):
    directory=store.path(store.workspace/"extracted")
    directory.mkdir(mode=0o700,exist_ok=True); store._private(directory,directory=True)
    space=os.statvfs(directory)
    if space.f_bavail*space.f_frsize<size_bytes+1024*1024:
        raise RIError("Espacio insuficiente para extracción selectiva y reserva de 1 MiB; sin lectura adicional.")
    return directory

def _consent(store,case_id,scope,provided_scope,authorized,actor,reason,**binding):
    store.get("cases",case_id)
    if authorized is not True or provided_scope!=scope:
        store.record("operations",case_id,{"scope":scope,"status":"denied","reason_code":"explicit_scope_required"},actor)
        raise RIError("Lectura bloqueada: --authorize-read y --scope exacto requeridos para esta operación.")
    return store.record("authorizations",case_id,{"scope":scope,"uid":os.getuid(),"actor":text(actor,"responsable",200),
                        "reason":text(reason,"motivo"),"expires_at_unix":time.time()+300,
                        "physical_approval":False,"remote_disclosure_authorized":False,**binding},actor)

def _image_check(store,case_id,source,authorization):
    if time.time()>=authorization["expires_at_unix"]: raise RIError("Autorización de lectura vencida.")
    path=copy_path(store.workspace,store.workspace/source["relative_path"])
    if path.stat().st_mode & 0o222: raise RIError("Imagen no protegida contra escritura por permisos; no se cambiarán automáticamente.")
    grant=Policy.copy_grant(case_id,source["source_evidence_id"],source["relative_path"],source["expected_sha256"],
                            authorization["actor"],"Verificación de imagen incluida en alcance "+authorization["scope"],authorized=True)
    facts,_=read_copy(store.workspace,path,grant,case_id,source["expected_sha256"],expected_identity=source.get("file_identity"))
    if time.time()>=authorization["expires_at_unix"]: raise RIError("Autorización vencida durante la validación.")
    return path,facts

def register_image(store,case_id,*,source_id,path,expected_sha256,offset_bytes,volume_length,actor,reason,authorized,scope):
    source=store.get("evidence",source_id)
    if source["case_id"]!=case_id or source["status"] not in ("source_declared","original_registered"):
        raise RIError("La fuente de procedencia no es un original/declaración de este caso.")
    authorization=_consent(store,case_id,"ntfs.register-image",scope,authorized,actor,reason,source_evidence_id=source_id,
                            requested_path=text(str(path),"ruta solicitada"),expected_sha256=sha256_value(expected_sha256),
                            offset_bytes=offset_bytes,volume_length=volume_length)
    operation=store.record("operations",case_id,{"scope":"ntfs.register-image","status":"started","authorization_id":authorization["id"]},actor)
    try:
        path=copy_path(store.workspace,path)
        payload={"source_evidence_id":source_id,"relative_path":path.relative_to(store.workspace).as_posix(),
                 "expected_sha256":sha256_value(expected_sha256)}
        _,facts=_image_check(store,case_id,payload,authorization)
        if type(offset_bytes) is not int or offset_bytes<0 or offset_bytes%512:
            raise RIError("Offset debe ser un número de bytes no negativo, múltiplo de 512.")
        length=facts["size_bytes"]-offset_bytes if volume_length is None else volume_length
        if type(length) is not int or length<=0 or length%512 or offset_bytes+length>facts["size_bytes"]:
            raise RIError("Extensión NTFS fuera de los límites de la imagen.")
        key="ntfs-image:"+digest([source_id,expected_sha256,offset_bytes,length])
        if any(d["identity_key"]==key for d in store.list("evidence",case_id)):
            raise RIError("Imagen/volumen ya registrado; usar su ID (no se copió contenido).")
        image=store.record("evidence",case_id,{**payload,"identity_key":key,"mode":source["mode"],"status":"ntfs_image_registered",
                           "kind":"image","content_sha256":facts["sha256"],"size_bytes":facts["size_bytes"],"file_identity":facts["identity"],
                           "offset_bytes":offset_bytes,"volume_length":length,"authorization_id":authorization["id"],
                           "format_claim":"NTFS; verified by libtsk on each operation, not by registration", "preserved_image":False},actor)
        store.update_operation(operation["id"],"completed",[{"source_id":image["id"],"sha256":facts["sha256"],"size_bytes":facts["size_bytes"]}],actor)
        return image
    except PublicationPending:
        raise
    except (RIError,ValueError,OSError) as exc:
        store.update_operation(operation["id"],"failed",[{"error_type":type(exc).__name__,"reason":str(exc)}],actor); raise

def register_device(store,case_id,*,source_id,pin,actor,reason):
    source=store.get("evidence",source_id)
    if source["case_id"]!=case_id or source["status"] not in ("source_declared","original_registered") or source["mode"] not in ("declared","metadata"):
        raise RIError("El dispositivo requiere procedencia física real declarada/registrada, no un fixture.")
    if source["status"]=="source_declared" and source.get("source_kind")!="physical-device":
        raise RIError("La declaración debe ser de dispositivo físico.")
    validate_pin(pin)
    text(reason,"motivo de registro")
    if source["status"]=="original_registered":
        original=source["device_snapshot"]
        def normalize_wwid(value):
            value=(value or "").casefold()
            for prefix in ("0x","naa.","eui."):
                if value.startswith(prefix): return value[len(prefix):]
            return value
        if (original["serial"]!=pin["serial"] or original["size_bytes"]!=pin["disk_size_bytes"] or original["protection_reasons"]
                or original["logical_sector_bytes"]!=pin["sector_size"]
                or (original.get("model") or "").replace("_"," ").strip()!=pin["model"].replace("_"," ").strip()
                or original.get("wwn") and normalize_wwid(original["wwn"])!=normalize_wwid(pin.get("wwid"))):
            raise RIError("El pin discrepa del original o la fuente está protegida.")
    key="ntfs-device:"+digest(pin)
    if any(d["identity_key"]==key for d in store.list("evidence",case_id)): raise RIError("Pin físico ya registrado.")
    return store.record("evidence",case_id,{"identity_key":key,"mode":"physical","status":"ntfs_physical_registered","kind":"physical",
                        "source_evidence_id":source_id,"pin":pin,"content_sha256":None,"preserved_image":False,
                        "validation_status":"declared pin only; broker must independently validate before every read",
                        "reason":reason},actor)

def _source(store,case_id,identifier):
    source=store.get("evidence",identifier)
    if source["case_id"]!=case_id or source["status"] not in ("ntfs_image_registered","ntfs_physical_registered"):
        raise RIError("Fuente NTFS no registrada en este caso.")
    return source

def _request(case_id,source,scope,parameters,reason,identifier):
    p=core.parameters(scope,parameters)
    binding={"kind":"physical","pin":source["pin"]} if source["kind"]=="physical" else {
        "kind":"image","sha256":source["content_sha256"],"offset_bytes":source["offset_bytes"],"volume_length":source["volume_length"]}
    return core.validate_request({"schema_version":1,"request_id":identifier,"case_id":case_id,"source_id":source["id"],
                                 "uid":os.getuid(),"scope":scope,"parameters":p,"source":binding,"reason":text(reason,"motivo")})

def _extract_output(store,case_id,source,request,response,actor,operation_id):
    result=response["result"]
    data=base64.b64decode(result.pop("data_base64"),validate=True)
    if bytes_digest(data)!=result["sha256"] or len(data)!=result["size_bytes"] or len(data)>request["parameters"]["max_bytes"]:
        raise RIError("Salida extraída no corresponde a tamaño/hash autorizado.")
    version=source.get("content_sha256") or digest(request["source"])
    for existing in store.list("evidence",case_id):
        if (existing.get("status")=="triage_extracted_copy" and existing["source_evidence_id"]==source["id"]
                and existing["source_version"]==version
                and all(existing["mft_binding"][key]==request["parameters"][key] for key in ("inode","attribute_id","expected_sequence"))
                and (existing["content_sha256"]!=result["sha256"] or existing["size_bytes"]!=result["size_bytes"])):
            raise RIError("Contenido cambió para la misma fuente/MFT/secuencia; salida nueva bloqueada, requiere revisión de versión.")
    key="ntfs-triage-copy:"+digest([source["id"],version,request["parameters"]["inode"],request["parameters"]["attribute_id"],
                                   request["parameters"]["expected_sequence"],result["sha256"]])
    previous=next((e for e in store.list("evidence",case_id) if e["identity_key"]==key),None)
    if previous:
        grant=Policy.copy_grant(case_id,source["id"],previous["relative_path"],previous["content_sha256"],actor,
                               "Verificación de copia existente incluida en ntfs.extract",authorized=True)
        read_copy(store.workspace,store.workspace/previous["relative_path"],grant,case_id,previous["content_sha256"],expected_identity=previous["file_identity"])
        result.update(evidence_id=previous["id"],relative_path=previous["relative_path"],reused=True)
        return
    directory=_destination(store,len(data))
    path=store.path(directory/("triage-"+operation_id+".bin"))
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream: stream.write(data); stream.flush(); os.fsync(fd)
        info=os.fstat(fd)
    finally: os.close(fd)
    store.sync_directory(directory)
    relative=path.relative_to(store.workspace).as_posix()
    grant=Policy.copy_grant(case_id,source["id"],relative,result["sha256"],actor,
                           "Verificación de salida incluida en alcance ntfs.extract",authorized=True)
    verified,_=read_copy(store.workspace,path,grant,case_id,result["sha256"],expected_identity=file_identity(info))
    result["output_verification"]={"sha256":verified["sha256"],"size_bytes":verified["size_bytes"],"hash_scope":"entire_output_file"}
    evidence=store.record("evidence",case_id,{"identity_key":key,"mode":source["mode"],"status":"triage_extracted_copy",
                         "source_evidence_id":source["id"],"source_version":version,"operation_id":operation_id,
                         "relative_path":relative,"file_identity":verified["identity"],
                          "content_sha256":result["sha256"],"size_bytes":len(data),"mft_binding":request["parameters"],
                          "output_verification":result["output_verification"],
                         "acquisition_type":"selective_triage_not_full_forensic_image","deleted_recovery_verified":False,
                         "preserved_image":False},actor)
    result.update(evidence_id=evidence["id"],relative_path=evidence["relative_path"],reused=False)

def _prefix_output(store,case_id,source,request,response,actor,operation_id):
    from .ntfs_scan import inspect_authorized_header
    result=response["result"]; data=base64.b64decode(result.pop("data_base64"),validate=True); p=request["parameters"]
    if len(data)!=min(p["expected_size"],p["max_bytes"]) or len(data)>65536 or bytes_digest(data)!=result["sha256"]:
        raise RIError("Prefijo fuera de tamaño/hash autorizado.")
    binding={key:p[key] for key in ("inode","attribute_id","expected_sequence","expected_size")}
    binding["prefix_length"]=len(data)
    previous=None
    for evidence in store.list("evidence",case_id):
        if evidence.get("status")=="ntfs_prefix_copy" and evidence["source_evidence_id"]==source["id"] and evidence["prefix_binding"]==binding:
            if evidence["content_sha256"]!=result["sha256"]: raise RIError("Prefijo cambió bajo el mismo binding; requiere revisión de versión.")
            previous=evidence; break
    if previous:
        path=store.workspace/previous["relative_path"]
        grant=Policy.copy_grant(case_id,source["id"],previous["relative_path"],result["sha256"],actor,"Verificar prefijo autorizado existente",authorized=True)
        verified,_=read_copy(store.workspace,path,grant,case_id,result["sha256"],expected_identity=previous["file_identity"])
        result.update(evidence_id=previous["id"],relative_path=previous["relative_path"],reused=True,header_assessment=previous["header_assessment"],output_verification={"sha256":verified["sha256"],"size_bytes":verified["size_bytes"],"hash_scope":"entire_prefix_copy_only"})
        return
    directory=_destination(store,len(data)); path=store.path(directory/("prefix-"+operation_id+".bin"))
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream: stream.write(data); stream.flush(); os.fsync(fd)
        identity=file_identity(os.fstat(fd))
    finally: os.close(fd)
    store.sync_directory(directory); relative=path.relative_to(store.workspace).as_posix()
    grant=Policy.copy_grant(case_id,source["id"],relative,result["sha256"],actor,"Verificar salida del prefijo autorizado",authorized=True)
    verified,_=read_copy(store.workspace,path,grant,case_id,result["sha256"],expected_identity=identity)
    assessment=inspect_authorized_header(data)
    verification={"sha256":verified["sha256"],"size_bytes":verified["size_bytes"],"hash_scope":"entire_prefix_copy_only"}
    evidence=store.record("evidence",case_id,{"identity_key":"ntfs-prefix:"+digest([source["id"],binding,result["sha256"]]),"mode":source["mode"],"status":"ntfs_prefix_copy",
             "source_evidence_id":source["id"],"operation_id":operation_id,"prefix_binding":binding,"source_expected_size":p["expected_size"],
             "relative_path":relative,"file_identity":verified["identity"],"content_sha256":result["sha256"],"size_bytes":len(data),"hash_scope":"prefix_only",
             "header_assessment":assessment,"output_verification":verification,"acquisition_type":"selective_prefix_not_complete_file","deleted_recovery_verified":False},actor)
    result.update(evidence_id=evidence["id"],relative_path=relative,reused=False,header_assessment=assessment,output_verification=verification)


def _finish(store,case_id,source,request,operation,response,actor):
    if response["receipt"]["status"]!="ok":
        return store.update_operation(operation["id"],"failed",[response],actor)
    if request["scope"]=="ntfs.extract": _extract_output(store,case_id,source,request,response,actor,operation["id"])
    if request["scope"]=="ntfs.prefix": _prefix_output(store,case_id,source,request,response,actor,operation["id"])
    partial=response["result"].get("summary",{}).get("partial",False)
    return store.update_operation(operation["id"],"partial" if partial else "completed",[response],actor)

def run_image(store,case_id,source_id,scope,parameters,*,actor,reason,authorized,provided_scope,_page_handler=None,_scan_context=None):
    if _page_handler is not None and scope not in core.SCAN_SCOPES:
        raise RIError("El receptor de páginas solo acepta metadatos de escaneo.")
    source=_source(store,case_id,source_id)
    if source["kind"]!="image": raise RIError("Para dispositivos físicos usar prepare-device y execute-device; la CLI nunca eleva privilegios.")
    request=_request(case_id,source,scope,parameters,reason,uuid.uuid4().hex)
    authorization=_consent(store,case_id,scope,provided_scope,authorized,actor,reason,source_evidence_id=source_id,request_sha256=digest(request))
    operation=store.record("operations",case_id,{"scope":scope,"status":"started","source_id":source_id,"authorization_id":authorization["id"],"request":request,
                           **({"scan_context":_scan_context} if _scan_context is not None else {})},actor)
    fd=None
    try:
        if scope in ("ntfs.extract","ntfs.prefix"): _destination(store,min(request["parameters"]["expected_size"],request["parameters"]["max_bytes"]))
        path,facts=_image_check(store,case_id,source,authorization)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME|os.O_CLOEXEC)
        if file_identity(os.fstat(fd))!=facts["identity"]: raise RIError("La imagen cambió al abrir su descriptor.")
        before=os.fstat(fd)
        response=core.run_worker(WORKER,fd,request,base=source["offset_bytes"],length=source["volume_length"],not_after=authorization["expires_at_unix"])
        after=os.fstat(fd)
        if file_identity(before)!=file_identity(after) or before.st_atime_ns!=after.st_atime_ns or file_identity(path.stat())!=facts["identity"]:
            raise RIError("La imagen cambió durante el triage; salida descartada.")
        response["source_validation"]={"image_sha256":facts["sha256"],"identity":facts["identity"],"physical_checks":"not_applicable_regular_image"}
        if _page_handler is not None:
            return _page_handler(operation, response)
        return _finish(store,case_id,source,request,operation,response,actor)
    except PublicationPending:
        raise
    except (RIError,ValueError,OSError) as exc:
        store.update_operation(operation["id"],"failed",[{"error_type":type(exc).__name__,"reason":str(exc)}],actor); raise
    finally:
        if fd is not None: os.close(fd)

def prepare_device(store,case_id,source_id,scope,parameters,*,actor,reason,authorized,provided_scope,_scan_context=None):
    source=_source(store,case_id,source_id)
    if source["kind"]!="physical": raise RIError("Se requiere pin físico registrado.")
    request=_request(case_id,source,scope,parameters,reason,uuid.uuid4().hex)
    authorization=_consent(store,case_id,scope,provided_scope,authorized,actor,reason,source_evidence_id=source_id,request_sha256=digest(request))
    operation=store.record("operations",case_id,{"scope":scope,"status":"started","source_id":source_id,"authorization_id":authorization["id"],
                           "request":request,"physical_state":"awaiting_independent_root_approval_no_device_read",
                           **({"scan_context":_scan_context} if _scan_context is not None else {})},actor)
    directory=store.path(store.workspace/"ntfs-requests"); directory.mkdir(mode=0o700,exist_ok=True); store._private(directory,directory=True)
    path=store.path(directory/(request["request_id"]+".json"))
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream: stream.write(core.canonical(request)); stream.flush(); os.fsync(fd)
    finally: os.close(fd)
    return {"operation_id":operation["id"],"request_id":request["request_id"],"request_sha256":digest(request),
            "request_file":str(path),"scope":scope,"physical_read_performed":False,"status":"awaiting_independent_root_approval"}

def execute_device(store,case_id,operation_id,actor,*,_page_handler=None):
    from .ntfs.client import execute_physical
    operation=store.get("operations",operation_id)
    if operation["case_id"]!=case_id or operation["status"]!="started" or operation.get("physical_state")!="awaiting_independent_root_approval_no_device_read":
        raise RIError("No es una solicitud física pendiente de este caso.")
    request=core.validate_request(operation["request"])
    if _page_handler is not None and request["scope"] not in core.SCAN_SCOPES:
        raise RIError("El receptor de páginas solo acepta metadatos de escaneo.")
    source=_source(store,case_id,operation["source_id"])
    if source["kind"]!="physical" or request["source"]!={"kind":"physical","pin":source["pin"]} or request["uid"]!=os.getuid():
        raise RIError("Fuente/usuario cambió desde la solicitud; sin lectura.")
    try:
        if request["scope"] in ("ntfs.extract","ntfs.prefix"): _destination(store,min(request["parameters"]["expected_size"],request["parameters"]["max_bytes"]))
        response=execute_physical(request)
        if response.get("request_id")!=request["request_id"] or response.get("request_sha256")!=digest(request):
            raise RIError("Recibo físico no corresponde a la solicitud autorizada.")
        validate_state(source["pin"],response["before"]); validate_state(source["pin"],response["after"])
        if response["before"]!=response["after"]: raise RIError("Discrepancia en la revalidación física; salida descartada.")
        worker=response.pop("worker")
        if worker["receipt"].get("request_sha256")!=digest(request):
            raise RIError("El recibo del parser no coincide con la autorización.")
        if type(worker["receipt"].get("parser_uid")) is not int or worker["receipt"]["parser_uid"] in (0,request["uid"]):
            raise RIError("El parser físico no está aislado del agente en un UID separado.")
        worker["physical_validation"]={key:value for key,value in response.items() if key!="status"}
        if _page_handler is not None:
            return _page_handler(operation, worker)
        return _finish(store,case_id,source,request,operation,worker,actor)
    except PublicationPending:
        raise
    except (RIError,ValueError,OSError) as exc:
        store.update_operation(operation_id,"failed",[{"error_type":type(exc).__name__,"reason":str(exc)}],actor); raise
