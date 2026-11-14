"""Unprivileged, closed command catalog. No shell, sudo or device-content IO."""
from __future__ import annotations

import base64
import errno
import os
import selectors
import signal
import stat
import subprocess
import time
from pathlib import Path

from .audit import bytes_digest
from .safety import MAX_INPUT, Policy, RIError, device_path, utcnow


LSBLK_COLUMNS = "KNAME,PATH,TYPE,SIZE,RO,RM,MODEL,SERIAL,WWN,TRAN,PKNAME,MAJ:MIN,LOG-SEC,PHY-SEC"
TOOLS = frozenset({"lsblk", "findmnt", "udevadm"})


def trusted_binary(name: str) -> str:
    if name not in TOOLS:
        raise RIError("Herramienta no permitida.")
    for directory in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
        candidate = Path(directory) / name
        if not candidate.exists():
            continue
        target = candidate.resolve(strict=True)
        if not any(target.is_relative_to(Path(p)) for p in ("/usr/bin", "/usr/sbin")):
            raise RIError("Ejecutable fuera de las ubicaciones confiables.")
        for part in (target, *target.parents):
            info = part.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise RIError("Ejecutable o directorio no confiable.")
        info = target.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & (stat.S_ISUID | stat.S_ISGID) or not os.access(target, os.X_OK):
            raise RIError("Ejecutable inválido.")
        try:
            capabilities = os.getxattr(target, "security.capability")
        except OSError as exc:
            if exc.errno not in (errno.ENODATA, errno.ENOTSUP):
                raise RIError("No se pudieron verificar capabilities del ejecutable.") from exc
        else:
            if capabilities:
                raise RIError("Ejecutable con capabilities prohibido.")
        return str(target)
    raise FileNotFoundError(f"{name}: herramienta no instalada; no se instalará ni sustituirá.")


def command(operation: str, *, device: str | None = None, tool: str | None = None) -> list[str]:
    if operation == "udev_properties":
        if tool is not None:
            raise RIError("Argumento adicional prohibido.")
        path = device_path(device)
        return [trusted_binary("udevadm"), "info", "--query=property", "--path=/sys/class/block/" + path.removeprefix("/dev/")]
    if device is not None:
        raise RIError("Esta operación no acepta dispositivos.")
    if operation == "version":
        return [trusted_binary(tool), "--version"]
    if tool is not None:
        raise RIError("Esta operación no acepta herramientas adicionales.")
    if operation == "lsblk_metadata":
        # No FSTYPE, LABEL, UUID, --fs, --discard or --properties-by probing.
        return [trusted_binary("lsblk"), "--json", "--bytes", "--paths", "--tree", "--output", LSBLK_COLUMNS]
    if operation == "findmnt_metadata":
        return [trusted_binary("findmnt"), "--kernel", "--json", "--list", "--output", "SOURCE,TARGET,FSTYPE,OPTIONS,MAJ:MIN"]
    raise RIError("Operación no permitida por el ejecutor.")


class RestrictedExecutor:
    def __init__(self, grant: dict, *, timeout: float = 10.0, max_output: int = MAX_INPUT):
        if not 0 < timeout <= 30 or not 64 <= max_output <= MAX_INPUT:
            raise RIError("Límites de ejecución inválidos.")
        self.grant, self.timeout, self.max_output = grant, timeout, max_output

    def execute(self, operation: str, *, device: str | None = None, tool: str | None = None) -> dict:
        Policy.check(operation, self.grant)
        if operation == "swap_metadata":
            if device is not None or tool is not None:
                raise RIError("Swap no acepta argumentos.")
            return self._swaps()
        try:
            argv = command(operation, device=device, tool=tool)
        except FileNotFoundError as exc:
            return self._result(operation, [], "unavailable", b"", str(exc).encode(), None, 0)
        return self._capture(operation, argv)

    @staticmethod
    def _result(operation, argv, status, out, err, code, duration):
        return {"operation": operation, "argv": argv, "status": status, "returncode": code,
                "stdout": out.decode("utf-8", errors="backslashreplace"),
                "stderr": err.decode("utf-8", errors="backslashreplace"),
                "stdout_base64": base64.b64encode(out).decode("ascii"),
                "stderr_base64": base64.b64encode(err).decode("ascii"),
                "stdout_sha256": bytes_digest(out), "stderr_sha256": bytes_digest(err),
                "duration_seconds": round(duration, 6), "collected_at": utcnow()}

    def _swaps(self):
        try:
            # Kernel metadata only; this never opens a swap device or swap file.
            with open("/proc/swaps", "rb") as stream:
                out = stream.read(self.max_output + 1)
            status = "ok" if len(out) <= self.max_output else "output_limit"
            return self._result("swap_metadata", ["read-kernel-metadata:/proc/swaps"], status, out[:self.max_output], b"", 0, 0)
        except OSError as exc:
            return self._result("swap_metadata", [], "unavailable", b"", str(exc).encode(), None, 0)

    def _capture(self, operation: str, argv: list[str]) -> dict:
        start = time.monotonic()
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    shell=False, close_fds=True, start_new_session=True,
                                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/nonexistent"})
        except PermissionError as exc:
            return self._result(operation, argv, "permission_denied", b"", str(exc).encode(), None, time.monotonic() - start)
        except OSError as exc:
            return self._result(operation, argv, "unavailable", b"", str(exc).encode(), None, time.monotonic() - start)
        proc.stdin.close()
        outputs = {"stdout": bytearray(), "stderr": bytearray()}
        status = "ok"
        try:
            with selectors.DefaultSelector() as selector:
                for name in outputs:
                    pipe = getattr(proc, name)
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = self.timeout - (time.monotonic() - start)
                    if remaining <= 0:
                        status = "timeout"
                        break
                    for key, _ in selector.select(min(remaining, 0.1)):
                        content = os.read(key.fileobj.fileno(), 65536)
                        if not content:
                            selector.unregister(key.fileobj)
                            continue
                        available = self.max_output - sum(len(v) for v in outputs.values())
                        outputs[key.data].extend(content[:available])
                        if len(content) > available:
                            status = "output_limit"
                            break
                    if status != "ok":
                        break
            remaining = self.timeout - (time.monotonic() - start)
            if status == "ok":
                try:
                    proc.wait(timeout=max(0.001, remaining))
                except subprocess.TimeoutExpired:
                    status = "timeout"
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                status = "termination_unconfirmed"
            proc.stdout.close()
            proc.stderr.close()
        if status == "ok" and proc.returncode != 0:
            status = "error"
        return self._result(operation, argv, status, bytes(outputs["stdout"]), bytes(outputs["stderr"]), proc.returncode, time.monotonic() - start)
