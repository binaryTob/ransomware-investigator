#!/usr/bin/env python3
"""Create a NEW regular synthetic NTFS volume, without mounts or block devices.

The one MFT allocation-flag patch is a fixture construction step, never a
repair/extraction function. It is not a model of every real deletion state.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT / "src"))
from ransomware_investigator.safety import ensure_user, project_path, RIError

FILES = {"README_RECOVER.txt": b"SYNTHETIC NTFS TEST. Your files have been encrypted. Pay bitcoin; demo@triage.invalid\n",
         "invoice.docx.locked": b"SYNTHETIC-ENCRYPTED-LOOKING-DATA\x00\xff\n",
         "ordinary.docx": b"SYNTHETIC ordinary document; extension alone is not attribution.\n",
         "deleted.locked": b"SYNTHETIC DELETED RESIDENT DATA\n", "oversize.bin": b"S"*131072}

def create_fixture(directory: Path, *, extra_files=None, alternate_streams=None) -> dict:
    ensure_user()
    files={**FILES,**(extra_files or {})}
    if len(files)>256 or any(not isinstance(name,str) or "/" in name or "\\" in name or not name or len(name)>200 or not isinstance(data,bytes) or len(data)>1024*1024 for name,data in files.items()):
        raise RIError("Solo archivos sintéticos acotados, con nombres simples.")
    directory=project_path(directory)
    directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    image=project_path(directory / ("synthetic-"+uuid.uuid4().hex+".ntfs"))
    with image.open("xb") as stream:
        for _ in range(16): stream.write(b"\0"*(1024*1024))
    image.chmod(0o600)
    identity=image.stat()
    def command(args):
        current=image.lstat()
        if (not stat.S_ISREG(current.st_mode) or current.st_uid!=os.getuid() or current.st_nlink!=1
                or (current.st_dev,current.st_ino)!=(identity.st_dev,identity.st_ino)):
            raise RIError("Fixture dejó de ser el archivo sintético nuevo; escritura bloqueada.")
        return subprocess.run(args,capture_output=True,check=True,timeout=30,
                              env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C"})
    command(["/usr/sbin/mkntfs","-F","-Q","-T","-s","512","-p","0","-H","1","-S","1","-L","RI_SYNTHETIC",str(image)])
    for name,data in files.items():
        staging=project_path(directory / ("input-"+uuid.uuid4().hex))
        with staging.open("xb") as stream: stream.write(data)
        command(["/usr/sbin/ntfscp",str(image),str(staging),"/"+name])
        staging.unlink()  # Only the just-created synthetic staging file.
    for (name,stream_name),data in (alternate_streams or {}).items():
        if name not in files or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}",stream_name) or not isinstance(data,bytes) or len(data)>65536:
            raise RIError("ADS de fixture inválido.")
        staging=project_path(directory / ("input-"+uuid.uuid4().hex))
        with staging.open("xb") as stream: stream.write(data)
        command(["/usr/sbin/ntfscp","-N",stream_name,str(image),str(staging),"/"+name])
        staging.unlink()
    listing=command(["/usr/local/bin/fls","-f","ntfs",str(image)]).stdout.decode()
    entries={}
    for line in listing.splitlines():
        match=re.search(r"\s(\d+)-128-(\d+):\s+(.+)$",line)
        if match and match[3] in files: entries[match[3]]={"inode":int(match[1]),"attribute_id":int(match[2])}
    if set(entries)!=set(files):
        raise RIError("No se pudieron identificar los archivos sintéticos por TSK.")
    with image.open("r+b") as stream:
        boot=stream.read(512)
        cluster=int.from_bytes(boot[11:13],"little")*boot[13]
        record_code=int.from_bytes(boot[64:65],"little",signed=True)
        record_size=2**(-record_code) if record_code<0 else record_code*cluster
        mft=int.from_bytes(boot[48:56],"little")*cluster
        offset=mft+entries["deleted.locked"]["inode"]*record_size
        stream.seek(offset); record=stream.read(record_size)
        if record[:4]!=b"FILE" or "deleted.locked".encode("utf-16le") not in record:
            raise RIError("Fixture MFT no contigua o distinta; no se parcheará por heurística.")
        flags=int.from_bytes(record[22:24],"little")
        stream.seek(offset+22); stream.write((flags & ~1).to_bytes(2,"little")); stream.flush(); os.fsync(stream.fileno())
    image.chmod(0o400)  # Seal before registration, never alter registered inputs.
    return {"path":str(image),"sha256":hashlib.sha256(image.read_bytes()).hexdigest(),"size_bytes":image.stat().st_size,
            "entries":entries,"files":{name:{"sha256":hashlib.sha256(data).hexdigest(),"size_bytes":len(data)} for name,data in files.items()},
            "deleted_fixture_method":"unallocated MFT flag with stale directory reference; not a guarantee of deleted-file recovery"}

if __name__=="__main__":
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory",required=True)
    args=parser.parse_args()
    print(json.dumps(create_fixture(Path(args.directory)),indent=2))
