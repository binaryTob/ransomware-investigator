"""Independent deny-by-default policy and filesystem boundaries."""
from __future__ import annotations

import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[2]
MAX_INPUT = 8 * 1024 * 1024
DEVICE = re.compile(r"/dev/(?:sd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?|vd[a-z]+\d*|xvd[a-z]+\d*|dm-\d+|md\d+|loop\d+|sr\d+|mmcblk\d+(?:p\d+)?|zram\d+)")
CASE_ID = re.compile(r"[0-9a-f]{32}")
SHA256 = re.compile(r"[0-9a-f]{64}")
CASE_NAMESPACE = "ransomware-investigator"


class RIError(Exception):
    """An expected failure that must never trigger a privileged fallback."""


class PublicationPending(RIError):
    """A durable DB commit exists; publication recovery must not rerun analysis."""


def ensure_user() -> None:
    if os.getuid() == 0 or os.geteuid() == 0:
        raise RIError("Ejecución como root prohibida; usar un usuario normal, sin sudo.")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value)
        if result.tzinfo is None:
            raise ValueError("zona horaria ausente")
        return result.astimezone(timezone.utc)
    except (TypeError, ValueError) as exc:
        raise RIError("Fecha inválida; se requiere ISO 8601 con zona horaria.") from exc


def text(value: object, name: str, limit: int = 4096) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise RIError(f"{name}: texto requerido (máximo {limit} caracteres).")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise RIError(f"{name}: caracteres de control prohibidos.")
    return value.strip()


def project_path(value: str | Path, *, exists: bool = False) -> Path:
    """Only ordinary project paths, with no symbolic-link components."""
    path = Path(os.path.abspath(value))
    if not path.is_relative_to(PROJECT) or path == PROJECT:
        raise RIError("La ruta debe estar dentro del proyecto y no ser su raíz.")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise RIError("No se permiten enlaces simbólicos en rutas del proyecto.")
        if part.exists() and part.stat().st_dev != PROJECT.stat().st_dev:
            raise RIError("Se rechazan montajes de otro sistema de archivos dentro del proyecto.")
        if part == PROJECT:
            break
    if exists and not path.exists():
        raise RIError("La ruta no existe.")
    return path


def read_project_file(value: str | Path) -> bytes:
    path = project_path(value, exists=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_INPUT:
            raise RIError("Se requiere un archivo regular, sin hardlinks, de hasta 8 MiB.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read(MAX_INPUT + 1)
        if len(content) > MAX_INPUT:
            raise RIError("Archivo demasiado grande.")
        return content
    finally:
        os.close(fd)


def existing_case_root(value: str | Path) -> Path:
    """Explicit authority for an EXISTING dossier, never a creation fallback."""
    text(str(value), "directorio del expediente")
    path = Path(value).expanduser()
    if not path.is_absolute() or ".." in path.parts:
        raise RIError("RI_CASE_ROOT requiere una ruta absoluta existente, sin traversal.")
    destination_path(str(path))
    local = path.is_relative_to(PROJECT) and path != PROJECT
    for part in (*reversed(path.parents), path):
        info = part.lstat()  # A missing root is an error, never mkdir(parents=True).
        # Synthetic/local workspaces retain the preexisting project trust boundary.
        # External dossiers additionally require non-writable ancestor directories.
        project_ancestor = local and part.is_relative_to(PROJECT) and part != path
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_mode & 0o022 and not project_ancestor):
            raise RIError("Expediente y padres deben ser directorios sin enlaces ni escritura ajena.")
    if path.stat().st_uid != os.getuid():
        raise RIError("El expediente debe pertenecer al operador; no se cambiarán permisos.")
    return path


def workspace_path(workspace: Path, value: str | Path, *, exists: bool = False) -> Path:
    """Constrain data paths to a local workspace or the explicit dossier namespace."""
    workspace = Path(os.path.abspath(workspace))
    path = Path(os.path.abspath(value))
    if ".." in Path(value).parts or not path.is_relative_to(workspace):
        raise RIError("Ruta fuera del workspace autorizado.")
    if workspace.is_relative_to(PROJECT):
        return project_path(path, exists=exists)
    if workspace.name != CASE_NAMESPACE:
        raise RIError("Workspace externo fuera del namespace del expediente.")
    root = existing_case_root(workspace.parent)
    for part in (path, *path.parents):
        if part.is_symlink() or (part.exists() and part.stat().st_dev != root.stat().st_dev):
            raise RIError("Enlace o montaje anidado dentro del expediente; acceso bloqueado.")
        if part == root:
            break
    if exists and not path.exists():
        raise RIError("La ruta no existe.")
    return path


def device_path(value: object) -> str:
    if not isinstance(value, str) or not DEVICE.fullmatch(value):
        raise RIError("Ruta de dispositivo no admitida; no se resuelven aliases arbitrarios.")
    return value


def sha256_value(value: object) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise RIError("SHA-256 esperado inválido; se requieren 64 caracteres hexadecimales minúsculos.")
    return value


def copy_path(workspace: Path, value: str | Path) -> Path:
    text(str(value), "ruta de copia")
    if ".." in Path(value).parts:
        raise RIError("Traversal prohibido en rutas de copias.")
    path = workspace_path(workspace, value, exists=True)
    base = workspace_path(workspace, workspace / "extracted", exists=True)
    if path == base or not path.is_relative_to(base):
        raise RIError("Solo se permiten copias bajo <workspace>/extracted/.")
    return path


def destination_path(value: str) -> str:
    """Lexical plan validation only: do NOT stat/open an acquisition destination."""
    text(value, "destino")
    path = Path(value)
    if not path.is_absolute() or value.startswith("//") or ".." in path.parts or str(path) != value.rstrip("/"):
        raise RIError("Destino: ruta absoluta y normalizada requerida.")
    if path == Path("/") or any(path.is_relative_to(Path(p)) for p in ("/dev", "/proc", "/sys", "/run")):
        raise RIError("Destino especial o de dispositivo prohibido.")
    return str(path)


class Policy:
    """No user-supplied command, operation name or privileged capability."""

    OPERATIONS = frozenset({"lsblk_metadata", "findmnt_metadata", "udev_properties", "version", "swap_metadata"})

    @staticmethod
    def copy_grant(case_id: str, source_id: str, relative_path: str, expected_sha256: str,
                   actor: str, reason: str, *, authorized: bool) -> dict:
        ensure_user()
        if authorized is not True:
            raise RIError("Lectura de copia no autorizada; se requiere --authorize-copy.")
        if not all(isinstance(i, str) and CASE_ID.fullmatch(i) for i in (case_id, source_id)):
            raise RIError("Caso o fuente inválidos.")
        relative = Path(text(relative_path, "ruta relativa"))
        if relative.is_absolute() or ".." in relative.parts or len(relative.parts) < 2 or relative.parts[0] != "extracted":
            raise RIError("Ruta fuera del área de copias autorizadas.")
        return {"scope": "artifact_copy_read", "case_id": case_id, "source_evidence_id": source_id,
                "relative_path": relative.as_posix(), "expected_sha256": sha256_value(expected_sha256),
                "actor": text(actor, "responsable", 200), "reason": text(reason, "motivo"),
                "uid": os.getuid(), "issued_at": utcnow(), "remote_disclosure_authorized": False,
                "allowed_uses": ["register", "verify", "static_artifact_analysis"]}

    @staticmethod
    def check_copy(grant: dict, case_id: str, relative_path: str, expected_sha256: str) -> None:
        ensure_user()
        if (not isinstance(grant, dict) or grant.get("scope") != "artifact_copy_read"
                or grant.get("uid") != os.getuid() or grant.get("case_id") != case_id
                or grant.get("relative_path") != relative_path
                or grant.get("expected_sha256") != sha256_value(expected_sha256)
                or grant.get("remote_disclosure_authorized") is not False):
            raise RIError("Autorización de copia ausente o no corresponde a caso, ruta, usuario y hash.")

    @staticmethod
    def grant(case_id: str, actor: str, reason: str) -> dict:
        ensure_user()
        if not CASE_ID.fullmatch(case_id):
            raise RIError("Caso inválido.")
        return {
            "case_id": case_id,
            "actor": text(actor, "responsable", 200),
            "reason": text(reason, "motivo"),
            "scope": "metadata_discovery",
            "created_at": utcnow(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
            "uid": os.getuid(),
        }

    @classmethod
    def check(cls, operation: str, grant: dict | None) -> None:
        ensure_user()
        if operation not in cls.OPERATIONS:
            raise RIError("Operación no permitida por la política.")
        if not isinstance(grant, dict) or grant.get("scope") != "metadata_discovery" or grant.get("uid") != os.getuid():
            raise RIError("Reconocimiento real no autorizado.")
        if not isinstance(grant.get("case_id"), str) or not CASE_ID.fullmatch(grant["case_id"]):
            raise RIError("Autorización sin caso válido.")
        text(grant.get("actor"), "responsable", 200)
        text(grant.get("reason"), "motivo")
        now = datetime.now(timezone.utc)
        start, end = parse_time(grant.get("created_at")), parse_time(grant.get("expires_at"))
        if not 0 < (end - start).total_seconds() <= 301 or start > now + timedelta(seconds=5):
            raise RIError("Vigencia de autorización inválida.")
        if end <= now:
            raise RIError("Autorización vencida.")
