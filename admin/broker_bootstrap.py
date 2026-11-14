"""Reviewed literal for system Python -c AFTER approval; never run checkout as root.

Capture hash-approved bytes into a new root-owned directory, then exec ONLY there.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time


def fail(message):
    raise SystemExit(message)


if os.getuid() != 0 or os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site:
    fail('Isolated administrative interpreter required')
bundle, plan_hash, installer_hash = sys.argv[1:]
if any(len(v) != 64 or any(c not in '0123456789abcdef' for c in v) for v in (plan_hash, installer_hash)):
    fail('Exact approved digests required')
flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
source = os.open(bundle, flags | os.O_DIRECTORY)


def capture(name, cap):
    fd = os.open(name, flags | os.O_NONBLOCK, dir_fd=source)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > cap:
            fail('Unexpected source file type/link/size')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(cap + 1)
        after = os.fstat(fd)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        if len(data) != info.st_size or len(data) > cap or signature(info) != signature(after):
            fail('Source changed during capture')
        return data
    finally:
        os.close(fd)


try:
    plan_data = capture('plan.json', 8 * 1024 * 1024)
    if hashlib.sha256(plan_data).hexdigest() != plan_hash:
        fail('Deployment plan changed; no administrative writes')
    plan = json.loads(plan_data)
    names = ('ntfs_broker.py', 'core.py', 'physical.py', 'ntfs_worker', 'broker_installer.py')
    if set(plan.get('payloads', {})) != set(names) or plan.get('physical_read_authorized') is not False:
        fail('Unexpected scope/payload list')
    if plan['payloads']['broker_installer.py'] != installer_hash:
        fail('Installer not approved')
    payloads = {}
    for name in names:
        data = capture(name, 16 * 1024 * 1024 if name == 'ntfs_worker' else 2 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != plan['payloads'][name]:
            fail('Approved payload changed; no administrative writes')
        payloads[name] = data
finally:
    os.close(source)

base = Path('/var/lib/ransomware-investigator-deployments')
for parent in (base.parent, *base.parent.parents):
    info = parent.lstat()
    if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        fail('Untrusted administrative parent')
if base.parent.stat().st_dev != Path('/').stat().st_dev:
    fail('Administrative capture must be on root filesystem')
if not os.path.lexists(base):
    base.mkdir(mode=0o700)
info = base.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
    fail('Existing administrative directory not trusted; no correction')
review = base / plan_hash
review.mkdir(mode=0o700)  # existing/partial capture is NEVER overwritten or resumed


def write(name, data):
    fd = os.open(review / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data); stream.flush(); os.fsync(fd)
    finally:
        os.close(fd)


write('bootstrap.json', json.dumps({'at_unix': time.time(), 'action': 'approved_capture_started',
      'plan_sha256': plan_hash, 'physical_device_reads': False}, sort_keys=True).encode())
for name, data in payloads.items():
    write(name, data)
write('plan.json', plan_data)
fd = os.open(review, flags | os.O_DIRECTORY)
try: os.fsync(fd)
finally: os.close(fd)
os.execv('/usr/bin/python3', ['/usr/bin/python3', '-I', '-S', '-B', str(review / 'broker_installer.py'),
                             '--apply', str(review / 'plan.json'), '--approved-plan-sha256', plan_hash])
