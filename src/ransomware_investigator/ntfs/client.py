"""AF_UNIX-only transport. Never launches or elevates a broker."""
import json
import os
from pathlib import Path
import socket
import stat
import struct

from .core import TriageError, canonical, sha, validate_request

SOCKET = Path("/run/ransomware-investigator-ntfs/broker.sock")
MAX_RESPONSE = 32*1024*1024

def receive(connection, maximum):
    def exact(size):
        data=bytearray()
        while len(data)<size:
            chunk=connection.recv(size-len(data))
            if not chunk: raise TriageError("Respuesta de broker truncada.")
            data.extend(chunk)
        return bytes(data)
    size=struct.unpack("!I",exact(4))[0]
    if size<2 or size>maximum: raise TriageError("Frame del broker fuera de límites.")
    return json.loads(exact(size))

def send(connection, value):
    payload=canonical(value)
    if len(payload)>MAX_RESPONSE: raise TriageError("Frame demasiado grande.")
    connection.sendall(struct.pack("!I",len(payload))+payload)

def execute_physical(request):
    validate_request(request)
    if request["source"].get("kind")!="physical": raise TriageError("El broker físico no acepta imágenes.")
    for path in (SOCKET,SOCKET.parent):
        info=path.lstat()
        if path.is_symlink() or info.st_uid!=0 or (path==SOCKET.parent and info.st_mode & 0o022):
            raise TriageError("Endpoint del broker no confiable.")
    if not stat.S_ISSOCK(SOCKET.stat().st_mode): raise TriageError("Endpoint no es un socket UNIX.")
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(25)
        connection.connect(str(SOCKET))
        _,uid,_=struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        if uid!=0: raise TriageError("El broker no tiene identidad de root; sin fallback.")
        send(connection,request)
        response=receive(connection,MAX_RESPONSE)
    if (response.get("request_id")!=request["request_id"] or response.get("request_sha256")!=sha(canonical(request))):
        raise TriageError("Recibo del broker no corresponde a la solicitud.")
    if response.get("status")!="completed":
        raise TriageError("Broker bloqueó la lectura: "+str(response.get("error","unknown")))
    return response
