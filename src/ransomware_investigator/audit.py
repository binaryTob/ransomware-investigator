"""Canonical serialization and tamper-evident (not immutable) event chains."""
import hashlib
import json

from .safety import RIError


def canonical(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RIError("Documento no serializable como JSON canónico.") from exc


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
