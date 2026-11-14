"""Bounded read-only IO for explicitly authorized, already extracted copies."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from .safety import Policy, RIError, copy_path


MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
SAMPLE_BYTES = 256 * 1024
CHUNK_BYTES = 1024 * 1024


def file_identity(info) -> dict:
    return {"device": info.st_dev, "inode": info.st_ino, "size_bytes": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns, "links": info.st_nlink}


def _validate(info, device: int, *, directory=False, private_directory=False):
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if not valid or info.st_dev != device or info.st_uid != os.getuid():
        raise RIError("Solo archivos regulares propios, sin hardlinks, del sistema de archivos del proyecto.")
    if directory and private_directory and info.st_mode & 0o077:
        raise RIError("Directorio de copias modificable por terceros; lectura bloqueada.")
    if not directory and info.st_size > MAX_ARTIFACT_BYTES:
        raise RIError("Copia mayor al límite de 64 MiB; no se realizará lectura parcial de integridad.")


def read_copy(workspace: Path, path: str | Path, grant: dict, case_id: str, expected_sha256: str,
              *, expected_identity: dict | None = None) -> tuple[dict, bytes]:
    path = copy_path(workspace, path)
    relative = path.relative_to(workspace).as_posix()
    Policy.check_copy(grant, case_id, relative, expected_sha256)
    if not hasattr(os, "O_NOATIME"):
        raise RIError("O_NOATIME no disponible; no se usará un fallback que cambie atime.")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME
    descriptors = []
    try:
        current = os.open(workspace, flags | os.O_DIRECTORY)
        descriptors.append(current)
        device = os.fstat(current).st_dev
        _validate(os.fstat(current), device, directory=True, private_directory=True)
        parts = path.relative_to(workspace).parts
        for depth, part in enumerate(parts[:-1], 1):
            current = os.open(part, flags | os.O_DIRECTORY, dir_fd=current)
            descriptors.append(current)
            _validate(os.fstat(current), device, directory=True, private_directory=True)
        before_open = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        _validate(before_open, device)
        fd = os.open(parts[-1], flags, dir_fd=current)
        descriptors.append(fd)
        before = os.fstat(fd)
        _validate(before, device)
        identity = file_identity(before)
        if identity != file_identity(before_open) or (expected_identity is not None and identity != expected_identity):
            raise RIError("La identidad o metadata de la copia cambió; requiere revisión y autorización de versión.")
        total, sample, hasher = 0, bytearray(), hashlib.sha256()
        while True:
            chunk = os.read(fd, CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ARTIFACT_BYTES or total > before.st_size:
                raise RIError("La copia creció durante la lectura; no se registrará un resultado parcial.")
            hasher.update(chunk)
            if len(sample) < SAMPLE_BYTES:
                sample.extend(chunk[:SAMPLE_BYTES - len(sample)])
        after = os.fstat(fd)
        current_path = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        if (identity != file_identity(after) or identity != file_identity(current_path)
                or total != before.st_size or before.st_atime_ns != after.st_atime_ns):
            raise RIError("Copia o timestamps cambiaron durante la lectura; operación detenida.")
        actual = hasher.hexdigest()
        if actual != expected_sha256:
            raise RIError("SHA-256 calculado no coincide con el esperado; integridad rechazada.")
        return {"sha256": actual, "size_bytes": total, "identity": identity,
                "hash_scope": "entire_file", "sample_bytes": len(sample),
                "sample_sha256": hashlib.sha256(sample).hexdigest(), "sample_truncated": total > len(sample),
                "read_policy": "O_RDONLY|O_NOFOLLOW|O_NOATIME; no content or timestamp writes"}, bytes(sample)
    except OSError as exc:
        raise RIError(f"No se pudo leer la copia autorizada (errno={exc.errno}); sin fallback.") from exc
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
