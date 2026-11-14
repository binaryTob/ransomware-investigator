"""Physical gate used ONLY by the separately deployed, approved root broker.

Tests inject probe results. Importing this module never queries /dev, /sys or
/proc. No operation here changes block flags, mounts or device permissions.
"""
from __future__ import annotations

import array
import fcntl
import os
import errno
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

from .core import TriageError, trusted_file

PIN_FIELDS={"target_by_id","disk_by_id","wwid","serial","model","disk_size_bytes","partition_size_bytes",
            "sector_size","partition_start_sectors","partition_number","partition_uuid"}
TABLE_FIELDS={"partition_table_type","partition_table_id"}
NUMERIC={"disk_size_bytes","partition_size_bytes","sector_size","partition_start_sectors","partition_number"}
SESSION_SCHEME="station_composite_v1"
SESSION_FIELDS={"boot_id","diskseq","disk_by_path","target_by_path","usb_sysfs_path","usb_vendor_id",
                "usb_product_id","usb_busnum","usb_devnum","usb_devpath","layout_sha256","volume_uuid"}

def session_pin(pin):
    return isinstance(pin,dict) and pin.get("identity_scheme")==SESSION_SCHEME

def disk_binding(pin):
    """Same physical/session disk, allowing a separately pinned sibling partition."""
    keys={"disk_by_id","wwid","serial","model","disk_size_bytes","sector_size","partition_table_type","partition_table_id","identity_scheme"}
    result={k:pin[k] for k in sorted(keys) if k in pin}
    if session_pin(pin):
        result["station_binding"]={k:v for k,v in pin["station_binding"].items() if k not in {"target_by_path","volume_uuid"}}
    return result

def validate_pin(pin):
    alternate=(PIN_FIELDS-{"wwid"})|TABLE_FIELDS|{"identity_scheme","station_binding"}
    is_session=session_pin(pin)
    if not isinstance(pin,dict) or (set(pin)!=alternate if is_session else set(pin) not in (PIN_FIELDS,PIN_FIELDS|TABLE_FIELDS)):
        raise TriageError("Pin físico incompleto o con argumentos extra.")
    if is_session:
        binding=pin["station_binding"]
        if not isinstance(binding,dict) or set(binding)!=SESSION_FIELDS:
            raise TriageError("Binding de estación/sesión incompleto.")
        for key in ("diskseq","usb_busnum","usb_devnum"):
            if type(binding[key]) is not int or not 0<binding[key]<2**63: raise TriageError("Binding numérico inválido.")
        for key,pattern in (("boot_id",r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"),
                            ("layout_sha256",r"[0-9a-f]{64}"),("volume_uuid",r"[0-9a-f]{16}"),
                            ("usb_vendor_id",r"[0-9a-f]{4}"),("usb_product_id",r"[0-9a-f]{4}"),
                            ("usb_devpath",r"[0-9]+(?:\.[0-9]+)*")):
            if not isinstance(binding[key],str) or not re.fullmatch(pattern,binding[key]): raise TriageError("Binding textual inválido: "+key)
        for key in ("disk_by_path","target_by_path"):
            if not isinstance(binding[key],str) or not re.fullmatch(r"/dev/disk/by-path/[A-Za-z0-9_.:+-]{1,240}",binding[key]): raise TriageError("Selector by-path cerrado requerido.")
        if binding["disk_by_path"]==binding["target_by_path"]: raise TriageError("Disco y partición by-path distintos requeridos.")
        path=binding["usb_sysfs_path"]
        if not isinstance(path,str) or not re.fullmatch(r"/sys/devices/[A-Za-z0-9_./:+-]{1,480}",path) or ".." in Path(path).parts:
            raise TriageError("Ruta USB sysfs inválida.")
    if TABLE_FIELDS <= set(pin):
        pattern=r"[0-9a-f]{8}" if pin["partition_table_type"]=="dos" else r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
        if pin["partition_table_type"] not in ("dos","gpt") or not isinstance(pin["partition_table_id"],str) or not re.fullmatch(pattern,pin["partition_table_id"]):
            raise TriageError("Tipo/ID de tabla de particiones inválido o no normalizado.")
    for key in NUMERIC:
        if type(pin[key]) is not int or not 0<=pin[key]<2**63 or (key!="partition_start_sectors" and pin[key]==0):
            raise TriageError("Geometría física inválida: "+key)
    if pin["sector_size"] not in (512,4096) or pin["partition_number"]>128:
        raise TriageError("Geometría/partición fuera del alcance.")
    if (pin["partition_start_sectors"]*512+pin["partition_size_bytes"]>pin["disk_size_bytes"]
            or pin["partition_size_bytes"]%pin["sector_size"] or pin["disk_size_bytes"]%pin["sector_size"]
            or pin["partition_start_sectors"]*512%pin["sector_size"]):
        raise TriageError("Extensión de partición fuera del disco o no alineada.")
    for key in PIN_FIELDS-NUMERIC-({"wwid"} if is_session else set()):
        value=pin[key]
        if not isinstance(value,str) or not value or len(value)>512 or any(ord(c)<32 for c in value):
            raise TriageError("Atributo persistente inválido: "+key)
    for key in ("target_by_id","disk_by_id"):
        if not re.fullmatch(r"/dev/disk/by-id/[A-Za-z0-9_.:+-]{1,240}",pin[key]):
            raise TriageError("Se requieren enlaces by-id cerrados, nunca /dev/sda solamente.")
    if pin["target_by_id"]==pin["disk_by_id"]:
        raise TriageError("Solo particiones NTFS; no se aceptan discos completos como volumen.")
    return pin

def validate_state(pin, state):
    validate_pin(pin)
    if not isinstance(state,dict) or any(type(state.get(key)) is not type(pin[key]) or state.get(key)!=pin[key] for key in pin):
        raise TriageError("Identidad persistente o geometría cambió; lectura bloqueada.")
    if any(state.get(key) is not expected for key,expected in
           (("disk_read_only",True),("partition_read_only",True),("all_children_read_only",True),
            ("mounted",False),("holders",False),("swap_active",False),("protected",False),("identity_unique",True))):
        raise TriageError("Montaje, solo lectura, protección o topología no cumplen la autorización.")
    if type(state.get("rdev")) is not int or type(state.get("disk_rdev")) is not int:
        raise TriageError("Identidad de kernel no verificable.")
    return state

def _text(path, cap=16384):
    with open(path,"r",encoding="utf-8") as stream:
        value=stream.read(cap+1)
    if len(value)>cap: raise TriageError("Metadata del kernel demasiado grande.")
    return value.strip()

def _selector(value):
    path=Path(value)
    for parent in path.parents:
        info=parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise TriageError("Directorio de selectores no confiable.")
    if not path.is_symlink() or path.lstat().st_uid!=0:
        raise TriageError("Selector persistente no es un enlace administrado por root.")
    target=path.resolve(strict=True)
    if not re.fullmatch(r"/dev/(?:sd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|vd[a-z]+\d*)",str(target)):
        raise TriageError("Destino físico del selector fuera del catálogo.")
    info=target.stat()
    if not stat.S_ISBLK(info.st_mode): raise TriageError("Fuente física no es dispositivo de bloques.")
    return target,info

def _ioctl(fd, request, typecode):
    value=array.array(typecode,[0]); fcntl.ioctl(fd,request,value,True); return int(value[0])

def _wwid(node):
    """Known absent VPD is not an IO error of NTFS; all other errors propagate."""
    for candidate in (node/"device/wwid",node/"wwid"):
        try: value=_text(candidate)
        except OSError as exc:
            if exc.errno in (errno.ENOENT,errno.ENXIO): continue
            raise
        if value: return value
    return None

def _layout(disk):
    result=[]
    parts=[p for p in disk.iterdir() if p.is_dir() and (p/"partition").exists()]
    if not 1<=len(parts)<=128: raise TriageError("Layout de particiones ausente/excesivo.")
    for part in parts:
        props=_udev(part.name)
        start=int(_text(part/"start")); size=int(_text(part/"size"))
        if not props.get("ID_PART_ENTRY_UUID"): raise TriageError("UUID de partición no verificable en layout.")
        for key,expected in (("ID_PART_ENTRY_OFFSET",start),("ID_PART_ENTRY_SIZE",size)):
            if key in props and int(props[key])!=expected: raise TriageError("Layout udev/sysfs discrepante.")
        result.append({"number":int(_text(part/"partition")),"start_sectors_512":start,"size_bytes":size*512,
                       "partition_uuid":props["ID_PART_ENTRY_UUID"].lower(),"filesystem_type":props.get("ID_FS_TYPE"),
                       "filesystem_uuid":(props.get("ID_FS_UUID") or "").lower() or None})
    return sorted(result,key=lambda p:p["number"])

def layout_digest(layout):
    return hashlib.sha256(json.dumps(layout,sort_keys=True,ensure_ascii=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()

def validate_fd_diskseq(binding, disk_fd, partition_fd):
    if (_ioctl(disk_fd,0x80081280,"Q")!=binding["diskseq"]
            or _ioctl(partition_fd,0x80081280,"Q")!=binding["diskseq"]):
        raise TriageError("BLKGETDISKSEQ del descriptor no coincide; lectura bloqueada.")

def _usb(disk):
    for parent in disk.parents:
        if (parent/"idVendor").exists() and (parent/"idProduct").exists():
            return {"usb_sysfs_path":str(parent),"usb_vendor_id":_text(parent/"idVendor"),
                    "usb_product_id":_text(parent/"idProduct"),"usb_busnum":int(_text(parent/"busnum")),
                    "usb_devnum":int(_text(parent/"devnum")),"usb_devpath":_text(parent/"devpath")}
    raise TriageError("Topología USB verificable requerida para identidad de sesión.")

def observe_station(disk, partition, binding, *, class_root=Path('/sys/class/block')):
    """Metadata only. Must still be followed by FD diskseq + ALL physical gates."""
    if _wwid(disk) is not None: raise TriageError("WWID disponible: usar identidad de hardware, no alternativa de sesión.")
    disk_props=_udev(disk.name)
    if disk_props.get("ID_WWN"): raise TriageError("WWN cacheado contradice ausencia de WWID; revisar, no degradar.")
    layout=_layout(disk)
    part=next((p for p in layout if p["number"]==int(_text(partition/"partition"))),None)
    if part is None or part["filesystem_type"]!="ntfs" or not part["filesystem_uuid"]:
        raise TriageError("Volumen NTFS/UUID cacheados requeridos; contenido no verificado todavía.")
    table_id=(disk_props.get("ID_PART_TABLE_UUID") or "").lower().removeprefix("0x")
    nodes=list(class_root.iterdir())
    if len(nodes)>256: raise TriageError("Demasiados nodos para descartar duplicados de identidad lógica.")
    for other in nodes:
        if other.resolve()==disk or (other/"partition").exists() or not re.fullmatch(r"(?:sd[a-z]+|nvme\d+n\d+|vd[a-z]+)",other.name): continue
        props=_udev(other.name)
        if (props.get("ID_PART_TABLE_UUID") or "").lower().removeprefix("0x")==table_id:
            raise TriageError("ID de tabla duplicado en estación; identidad alternativa ambigua.")
        for p in _layout(other.resolve()):
            if p["filesystem_type"]=="ntfs" and not p["filesystem_uuid"]:
                raise TriageError("Otro NTFS sin UUID verificable; no presumir unicidad.")
            if p["filesystem_uuid"]==part["filesystem_uuid"]:
                raise TriageError("UUID de volumen duplicado; posible clon, revisión de custodia requerida.")
    return {"boot_id":_text(Path('/proc/sys/kernel/random/boot_id')),"diskseq":int(_text(disk/"diskseq")),
            "disk_by_path":binding["disk_by_path"],"target_by_path":binding["target_by_path"],
            **_usb(disk),"layout_sha256":layout_digest(layout),"volume_uuid":part["filesystem_uuid"]}

def _udev(name):
    binary=trusted_file(Path("/usr/bin/udevadm"),privileged=True,executable=True)
    result=subprocess.run([str(binary),"info","--query=property","--path=/sys/class/block/"+name],
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.DEVNULL,
                          timeout=3,check=True,env={"PATH":"/usr/bin:/bin","LC_ALL":"C"})
    if len(result.stdout)>65536: raise TriageError("udev excedió límite.")
    values={}
    for line in result.stdout.decode("utf-8").splitlines():
        key,separator,value=line.partition("=")
        if not separator or key in values: raise TriageError("Metadata udev inconsistente.")
        values[key]=value
    return values

def _mounted_any(major_minor):
    if os.readlink("/proc/self/ns/mnt")!=os.readlink("/proc/1/ns/mnt"):
        raise TriageError("Broker fuera del namespace de montaje de init; sin visión suficiente del host.")
    if _text(Path("/proc/self/uid_map")).split()!=["0","0","4294967295"]:
        raise TriageError("Broker dentro de un user namespace; no se presume visibilidad global.")
    init_mounts=_text(Path("/proc/1/mountinfo"),2*1024*1024)
    for line in init_mounts.splitlines():
        fields=line.split()
        if len(fields)>=10 and fields[4]=="/" and "-" in fields and fields[fields.index("-")+1] in ("overlay","aufs"):
            raise TriageError("El broker requiere host nativo, no un root filesystem de contenedor.")
    namespaces=set()
    processes=[p for p in Path("/proc").iterdir() if p.name.isdecimal()]
    if len(processes)>65536: raise TriageError("Demasiados procesos para verificar montajes.")
    seen_init=False
    for proc in processes:
        try:
            namespace=os.readlink(proc/"ns/mnt")
            if proc.name=="1": seen_init=True
            if namespace in namespaces: continue
            namespaces.add(namespace)
            if len(namespaces)>256: raise TriageError("Demasiados namespaces para verificar montajes.")
            mounts=_text(proc/"mountinfo",2*1024*1024)
        except (FileNotFoundError,ProcessLookupError):
            continue  # Process exited; any still-live namespace is visited through another process.
        for line in mounts.splitlines():
            fields=line.split()
            if len(fields)<10 or "-" not in fields: raise TriageError("mountinfo inválido.")
            if fields[2] in major_minor: return True
    if not seen_init or not namespaces: raise TriageError("No se pudo verificar el namespace del host.")
    return False

def probe_physical(pin):
    """Caller must already have consumed a root-owned, exact single-use grant."""
    validate_pin(pin)
    if os.getuid()!=0 or os.geteuid()!=0:
        raise TriageError("Solo el broker aislado puede abrir fuentes físicas.")
    target,ti=_selector(pin["target_by_id"])
    disk,di=_selector(pin["disk_by_id"])
    tsys=(Path("/sys/class/block")/target.name).resolve(strict=True)
    dsys=(Path("/sys/class/block")/disk.name).resolve(strict=True)
    if not (tsys/"partition").exists() or tsys.parent!=dsys or (dsys/"partition").exists():
        raise TriageError("Partición y disco no corresponden al selector aprobado.")
    if disk.name=="nvme0n1": raise TriageError("Disco interno expresamente excluido.")
    nodes=[dsys]+[p for p in dsys.iterdir() if p.is_dir() and (p/"partition").exists()]
    major_minor={_text(node/"dev") for node in nodes}
    children_ro=all(_text(node/"ro")=="1" for node in nodes)
    holders=any(any((node/"holders").iterdir()) for node in nodes)
    mounted=_mounted_any(major_minor)
    swap_active=False
    swaps=_text(Path("/proc/swaps"))
    if not swaps.startswith("Filename"): raise TriageError("No se pudo verificar swap.")
    for line in swaps.splitlines()[1:]:
        fields=line.split()
        if len(fields)!=5: raise TriageError("Entrada swap inválida.")
        if fields[0].startswith("/dev/"):
            si=Path(fields[0]).stat()
            if f"{os.major(si.st_rdev)}:{os.minor(si.st_rdev)}" in major_minor: swap_active=True
    binding=None
    if session_pin(pin):
        expected=pin["station_binding"]
        bp_disk,bp_di=_selector(expected["disk_by_path"])
        bp_part,bp_ti=_selector(expected["target_by_path"])
        if bp_disk!=disk or bp_part!=target or bp_di.st_rdev!=di.st_rdev or bp_ti.st_rdev!=ti.st_rdev:
            raise TriageError("by-id/by-path no corresponden al mismo disco/partición.")
        binding=observe_station(dsys,tsys,expected)
        if binding!=expected: raise TriageError("Binding de estación, USB, boot, diskseq o layout cambió.")
        wwid=None; identities=[disk.name]
    else:
        wwid=_wwid(dsys)
        if wwid is None: raise TriageError("WWID no disponible; alternativa de sesión requiere pin y custodia explícitos.")
        identities=[node.name for node in Path('/sys/class/block').iterdir() if _wwid(node)==wwid]
    disk_udev,partition_udev=_udev(disk.name),_udev(target.name)
    model=_text(dsys/"device/model") if (dsys/"device/model").exists() else _text(dsys/"device/../model")
    serial=disk_udev.get("ID_SERIAL_SHORT")
    if not serial: raise TriageError("Serie persistente no verificable; sin fallback SMART.")
    if (dsys/"device/serial").exists() and _text(dsys/"device/serial")!=serial:
        raise TriageError("Serie sysfs/udev discrepante.")
    flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
    disk_fd=os.open(disk,flags)
    target_fd=None
    try:
        target_fd=os.open(target,flags)
        if os.fstat(target_fd).st_rdev!=ti.st_rdev or os.fstat(disk_fd).st_rdev!=di.st_rdev:
            raise TriageError("El dispositivo cambió durante la apertura.")
        if binding is not None: validate_fd_diskseq(binding,disk_fd,target_fd)
        state={"target_by_id":pin["target_by_id"],"disk_by_id":pin["disk_by_id"],"serial":serial,"model":model,
               "disk_size_bytes":_ioctl(disk_fd,0x80081272,"Q"),"partition_size_bytes":_ioctl(target_fd,0x80081272,"Q"),
               "sector_size":_ioctl(target_fd,0x1268,"i"),"partition_start_sectors":int(_text(tsys/"start")),
               "partition_number":int(_text(tsys/"partition")),"partition_uuid":partition_udev.get("ID_PART_ENTRY_UUID"),
               "disk_read_only":_ioctl(disk_fd,0x125e,"i")==1,"partition_read_only":_ioctl(target_fd,0x125e,"i")==1,
               "all_children_read_only":children_ro,"mounted":mounted,"holders":holders,"swap_active":swap_active,
               "protected":disk.name=="nvme0n1","identity_unique":identities==[disk.name],
               "rdev":ti.st_rdev,"disk_rdev":di.st_rdev,"kernel_path_observed":str(target),
                "physical_write_blocker_verified":False,"identity_basis":"fresh sysfs + udev cache; not hardware authentication"}
        if binding is None: state["wwid"]=wwid
        else:
            state.update(identity_scheme=SESSION_SCHEME,station_binding=binding,
                         identity_basis="station session instance + USB/by-path + cloneable logical fingerprint; human custody attestation required, not hardware authentication")
        if TABLE_FIELDS <= set(pin):
            state.update(partition_table_type=disk_udev.get("ID_PART_TABLE_TYPE"),partition_table_id=disk_udev.get("ID_PART_TABLE_UUID"," ").lower().removeprefix("0x"))
            state["partition_table_identity_basis"]="udev properties; not a new raw partition-table read"
        validate_state(pin,state)
        result=target_fd; target_fd=None
        return result,state
    finally:
        if target_fd is not None: os.close(target_fd)
        os.close(disk_fd)

def recheck_physical(pin, original_fd, previous, *, probe=probe_physical):
    fresh_fd,current=probe(pin)
    try:
        validate_state(pin,current)
        if current!=previous or os.fstat(original_fd).st_rdev!=current["rdev"]:
            raise TriageError("Fuente/montaje/RO cambiaron: resultado descartado.")
    finally:
        os.close(fresh_fd)
    return current
