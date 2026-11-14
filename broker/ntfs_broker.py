#!/usr/bin/python3
"""Separately deployed root broker. NEVER run the development checkout as root.

Deploy this file, core.py, physical.py and ntfs_worker into a root-owned,
non-writable directory. Start with /usr/bin/python3 -I. No installer is run by RI.
Each request requires a root-approved, hash-bound, UID-bound, single-use manifest.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import struct
import sys
import time
import types

STATE=Path("/var/lib/ransomware-investigator-ntfs")
RUNTIME=Path("/run/ransomware-investigator-ntfs")
MAX_FRAME=32*1024*1024

def parser_identity():
    user=pwd.getpwnam("ri-ntfs-parser")
    if user.pw_uid<=0 or user.pw_gid<=0 or not user.pw_shell.endswith(("/nologin","/false")):
        raise ValueError("A dedicated, non-root, non-login ri-ntfs-parser account is required; no account is created automatically.")
    return user

def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=True,separators=(",",":"),allow_nan=False).encode()

def digest(value): return hashlib.sha256(canonical(value)).hexdigest()

def root_file(path, *, directory=False):
    path=Path(path)
    for candidate in (path,*path.parents):
        info=candidate.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise ValueError("Broker/code/state must be root-owned and not writable by others.")
    info=path.stat()
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink==1):
        raise ValueError("Invalid broker file type.")
    return path

def load_core():
    if os.getuid()!=0 or os.geteuid()!=0 or not sys.flags.isolated:
        raise ValueError("Root broker requires an isolated interpreter and a separately installed root-owned deployment. Never sudo the checkout.")
    root_file(Path(__file__))
    directory=Path(__file__).resolve().parent
    for name in ("core.py","physical.py","ntfs_worker"): root_file(directory/name)
    parser_identity()
    sys.dont_write_bytecode=True
    package=types.ModuleType("ri_ntfs"); package.__path__=[str(directory)]
    sys.modules["ri_ntfs"]=package
    modules={}
    for name in ("core","physical"):
        spec=importlib.util.spec_from_file_location("ri_ntfs."+name,directory/(name+".py"))
        module=importlib.util.module_from_spec(spec); sys.modules[spec.name]=module; spec.loader.exec_module(module)
        modules[name]=module
    return modules["core"],modules["physical"],directory/"ntfs_worker"

def setup_state():
    STATE.mkdir(mode=0o700,exist_ok=True)
    root_file(STATE,directory=True)
    if STATE.stat().st_mode & 0o077 or STATE.stat().st_dev!=Path("/").stat().st_dev:
        raise ValueError("Persistent broker state must be private and on the host root filesystem, not evidence storage.")
    RUNTIME.mkdir(mode=0o711,exist_ok=True)
    root_file(RUNTIME,directory=True)
    for name in ("approved","used"):
        path=STATE/name; path.mkdir(mode=0o700,exist_ok=True); root_file(path,directory=True)
        if path.stat().st_mode & 0o077: raise ValueError("Approval directories must be private.")

def ledger(action, **data):
    path=STATE/"audit.jsonl"
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_APPEND|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        info=os.fstat(fd)
        if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode & 0o077 or info.st_size>64*1024*1024:
            raise ValueError("Broker audit unavailable/untrusted/full; reading is blocked.")
        os.lseek(fd,max(0,info.st_size-65536),os.SEEK_SET)
        lines=os.read(fd,65536).splitlines()
        previous=json.loads(lines[-1])["sha256"] if lines else "0"*64
        event={"at_unix":time.time(),"action":action,"previous_sha256":previous,**data}
        envelope={"event":event,"sha256":digest(event)}
        encoded=canonical(envelope)+b"\n"
        if len(encoded)>32768: raise ValueError("Audit event too large.")
        view=memoryview(encoded)
        while view:
            written=os.write(fd,view)
            if written<=0: raise ValueError("Incomplete audit write.")
            view=view[written:]
        os.fsync(fd)
        return envelope["sha256"]
    finally: os.close(fd)

def read_json_file(path, *, require_root=False, maximum=65536):
    if require_root: root_file(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>maximum:
            raise ValueError("Invalid manifest file.")
        with os.fdopen(fd,"rb",closefd=False) as stream: data=stream.read(maximum+1)
        if len(data)>maximum: raise ValueError("Manifest too large.")
        return json.loads(data)
    finally: os.close(fd)

def audit_capacity():
    path=STATE/"audit.jsonl"
    size=0
    if path.exists():
        root_file(path); size=path.stat().st_size
    space=os.statvfs(STATE)
    reserve=8*1024*1024
    if size+reserve>64*1024*1024 or space.f_bavail*space.f_frsize<reserve:
        raise ValueError("Insufficient audit capacity for read receipts; source will not be opened.")

def approve(core, physical, request_path, expected_digest, approved_uid, reason, *, custody_attestation=None):
    request=core.validate_request(read_json_file(request_path))
    return approve_request(core, physical, request, expected_digest, approved_uid, reason,custody_attestation=custody_attestation)

def approve_request(core, physical, request, expected_digest, approved_uid, reason, *, custody_attestation=None):
    core.validate_request(request)
    if request["source"].get("kind")!="physical" or set(request["source"])!={"kind","pin"}:
        raise ValueError("Only exact physical pins can be approved.")
    physical.validate_pin(request["source"]["pin"])
    if physical.session_pin(request["source"]["pin"]):
        if (not isinstance(custody_attestation,str) or not 8<=len(custody_attestation.strip())<=4096
                or any(ord(c)<32 for c in custody_attestation)):
            raise ValueError("Session identity requires an explicit human custody attestation before approving reads.")
    if digest(request)!=expected_digest or request["uid"]!=approved_uid or not reason.strip() or approved_uid<=0:
        raise ValueError("Explicit hash/UID/reason confirmation does not match.")
    user=pwd.getpwuid(approved_uid)
    if user.pw_gid<=0: raise ValueError("Worker cannot run with root group.")
    if parser_identity().pw_uid==approved_uid: raise ValueError("The parser account cannot be the requesting agent.")
    grant={"request":request,"request_sha256":expected_digest,"approved_uid":approved_uid,
            "approved_at":time.time(),"expires_at":time.time()+300,"reason":reason,"administrator_uid":0}
    if physical.session_pin(request["source"]["pin"]): grant["custody_attestation"]=custody_attestation.strip()
    nonce=request["request_id"]
    if (STATE/"used"/(nonce+".json")).exists(): raise ValueError("Request was already consumed.")
    path=STATE/"approved"/(nonce+".json")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream: stream.write(canonical(grant)); stream.flush(); os.fsync(fd)
    finally: os.close(fd)
    ledger("approved",request_id=nonce,request_sha256=expected_digest,uid=approved_uid,scope=request["scope"])
    return {"request_id":nonce,"expires_at":grant["expires_at"],"scope":request["scope"],"uid":approved_uid}

def approve_batch(core, physical, path, expected_digest, approved_uid, reason, *, custody_attestation=None):
    bundle = read_json_file(path)
    if (not isinstance(bundle,dict) or set(bundle)!={"schema_version","requests"} or type(bundle["schema_version"]) is not int
            or bundle["schema_version"]!=1 or not isinstance(bundle["requests"],list) or not 1<=len(bundle["requests"])<=8
            or digest(bundle)!=expected_digest):
        raise ValueError("Exact metadata batch of up to eight requests required.")
    identities=set(); binding=None
    for request in bundle["requests"]:
        core.validate_request(request)
        if request["scope"] not in core.SCAN_SCOPES or request["uid"]!=approved_uid or request["request_id"] in identities:
            raise ValueError("Batch contains content reads, UID mismatch or duplicate nonce.")
        if set(request["source"])!={"kind","pin"} or request["source"]["kind"]!="physical": raise ValueError("Physical pin required.")
        physical.validate_pin(request["source"]["pin"])
        current=(request["case_id"],request["source_id"],digest(request["source"]))
        if binding is not None and current!=binding: raise ValueError("Batch mixes cases or sources.")
        binding=current; identities.add(request["request_id"])
    grants=[]
    for request in bundle["requests"]:
        grants.append(approve_request(core,physical,request,digest(request),approved_uid,reason+" [batch "+expected_digest+"]",custody_attestation=custody_attestation))
    return {"batch_sha256":expected_digest,"grants":grants,"partial_approval_possible_on_error":True}

def consume(core, physical, request, peer_uid):
    core.validate_request(request)
    if request["uid"]!=peer_uid or peer_uid<=0: raise ValueError("Peer UID mismatch.")
    if set(request["source"])!={"kind","pin"} or request["source"]["kind"]!="physical": raise ValueError("Physical source required.")
    physical.validate_pin(request["source"]["pin"])
    nonce=request["request_id"]
    approved=STATE/"approved"/(nonce+".json")
    grant=read_json_file(approved,require_root=True)
    if physical.session_pin(request["source"]["pin"]) and (not isinstance(grant.get("custody_attestation"),str) or len(grant["custody_attestation"].strip())<8):
        raise ValueError("Session identity grant lacks explicit custody attestation.")
    if (grant.get("request_sha256")!=digest(request) or grant.get("request")!=request
            or grant.get("approved_uid")!=peer_uid or grant.get("administrator_uid")!=0
            or not 0<grant.get("expires_at",0)-grant.get("approved_at",0)<=301
            or time.time()<grant["approved_at"]-5 or time.time()>=grant["expires_at"]):
        raise ValueError("Missing, expired or mismatched administrator authorization.")
    used=STATE/"used"/(nonce+".json")
    if used.exists(): raise ValueError("Authorization already consumed.")
    os.rename(approved,used)
    directory_fd=os.open(STATE/"used",os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(directory_fd)
    finally: os.close(directory_fd)
    ledger("authorization_consumed",request_id=nonce,request_sha256=digest(request),uid=peer_uid,scope=request["scope"])
    return grant

def execute(core, physical, worker, request, uid):
    grant=consume(core,physical,request,uid)
    nonce=request["request_id"]; fd=None
    try:
        audit_capacity()
        parser=parser_identity()
        if parser.pw_uid==uid: raise ValueError("Parser UID must differ from agent UID.")
        ledger("physical_precheck_started",request_id=nonce,scope=request["scope"])
        fd,before=physical.probe_physical(request["source"]["pin"])
        physical.validate_state(request["source"]["pin"],before)
        ledger("physical_precheck_passed",request_id=nonce,state_sha256=digest(before))
        if time.time()>=grant["expires_at"]: raise ValueError("Authorization expired before source data read.")
        response=core.run_worker(worker,fd,request,base=0,length=before["partition_size_bytes"],gid=parser.pw_gid,parser_uid=parser.pw_uid,not_after=grant["expires_at"])
        ledger("worker_finished",request_id=nonce,receipt_sha256=digest(response["receipt"]),worker_status=response["receipt"]["status"])
        for line in response["receipt"]["stderr"].splitlines():
            if re.fullmatch(r"RI_READ_INTENT \d+ \d+",line):
                _,offset,requested=line.split()
                ledger("source_read_intent",request_id=nonce,offset_bytes_relative_to_partition=int(offset),requested_bytes=int(requested))
            if re.fullmatch(r"RI_READ \d+ \d+ -?\d+",line):
                _,offset,requested,returned=line.split()
                ledger("source_read",request_id=nonce,offset_bytes_relative_to_partition=int(offset),requested_bytes=int(requested),returned_bytes=int(returned))
        after=physical.recheck_physical(request["source"]["pin"],fd,before)
        physical.validate_state(request["source"]["pin"],after)
        if after!=before: raise ValueError("Physical state changed; output discarded.")
        # Byte-level read receipts are retained in the case; their digest is independently anchored here.
        head=ledger("physical_read_finished",request_id=nonce,state_sha256=digest(after),receipt_sha256=digest(response["receipt"]))
        # completed describes transport/validated handling, NOT a successful worker.
        # Return diagnostics only after successful physical postchecks. The client
        # records a failed operation from receipt.status; no partial copy is promoted.
        return {"status":"completed","request_id":nonce,"request_sha256":digest(request),"before":before,"after":after,
                "worker":response,"operation_status":"completed" if response["receipt"]["status"]=="ok" else "failed",
                "broker_audit_sha256":head,"administrator_authorization_expires":grant["expires_at"],
                "custody_attestation_sha256":hashlib.sha256(grant["custody_attestation"].encode()).hexdigest() if "custody_attestation" in grant else None}
    except Exception as exc:
        ledger("physical_read_failed",request_id=nonce,error_type=type(exc).__name__)
        raise
    finally:
        if fd is not None: os.close(fd)

def recv(connection, maximum=65536):
    def exact(n):
        result=bytearray()
        while len(result)<n:
            piece=connection.recv(n-len(result))
            if not piece: raise ValueError("Incomplete request.")
            result.extend(piece)
        return bytes(result)
    size=struct.unpack("!I",exact(4))[0]
    if not 2<=size<=maximum: raise ValueError("Invalid request length.")
    return json.loads(exact(size))

def serve(core, physical, worker, *, socket_gid=None):
    if socket_gid is not None and (type(socket_gid) is not int or socket_gid <= 0):
        raise ValueError("Socket requires a non-root operator group.")
    path=RUNTIME/"broker.sock"
    if path.exists() or path.is_symlink(): raise ValueError("Socket already exists; administrator must review, not blindly overwrite.")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
        server.bind(str(path))
        if socket_gid is not None: os.chown(path,0,socket_gid)
        os.chmod(path,0o660 if socket_gid is not None else 0o600)
        server.listen(8)
        while True:
            connection,_=server.accept()
            with connection:
                connection.settimeout(5)
                _,uid,_=struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                request={}
                try:
                    request=recv(connection)
                    if not isinstance(request,dict):
                        request={}; raise ValueError("Request must be an object.")
                    result=execute(core,physical,worker,request,uid)
                except Exception as exc:
                    ledger("request_denied_or_failed",peer_uid=uid,error_type=type(exc).__name__)
                    result={"status":"failed","request_id":request.get("request_id"),"request_sha256":digest(request),"error":str(exc)}
                payload=canonical(result)
                if len(payload)>MAX_FRAME:
                    ledger("response_limit",request_id=request.get("request_id"),uid=uid)
                    payload=canonical({"status":"failed","request_id":request.get("request_id"),"request_sha256":digest(request),"error":"Response exceeds transport limit."})
                try: connection.sendall(struct.pack("!I",len(payload))+payload)
                except (BrokenPipeError,ConnectionResetError,socket.timeout):
                    ledger("response_delivery_failed",request_id=request.get("request_id"),uid=uid)

def main():
    core,physical,worker=load_core()
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--serve",action="store_true")
    group.add_argument("--approve-request")
    group.add_argument("--approve-batch")
    parser.add_argument("--confirm-sha256")
    parser.add_argument("--uid",type=int)
    parser.add_argument("--reason")
    parser.add_argument("--custody-attestation",help="Human custody/connection statement, mandatory for station-session pins; not an authorization to install.")
    parser.add_argument("--socket-gid",type=int,help="Restrict socket to this non-root operator group (otherwise root-only).")
    args=parser.parse_args()
    setup_state()
    if args.serve: serve(core,physical,worker,socket_gid=args.socket_gid)
    else:
        if args.uid is None or not args.reason or not re.fullmatch(r"[0-9a-f]{64}",args.confirm_sha256 or ""):
            parser.error("Approval requires exact --confirm-sha256, --uid and --reason.")
        action=approve_batch if args.approve_batch else approve
        print(json.dumps(action(core,physical,args.approve_batch or args.approve_request,args.confirm_sha256,args.uid,args.reason,custody_attestation=args.custody_attestation)))

if __name__=="__main__":
    try: main()
    except (ValueError,OSError) as exc:
        print(json.dumps({"error":str(exc)}),file=sys.stderr); raise SystemExit(2)
