"""Local ZIP handoff: bounded, no-follow/noatime source reads and hash checks.

Never scans devices, executes content, extracts archives or follows metadata source
paths. Callers must supply an explicit allowlist and authorize evidence-copy IO.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid
import zipfile


CHUNK = 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_SQLITE_BACKUP = 768 * 1024 * 1024
MAX_TOTAL = 2 * 1024**3
MAX_ENTRIES = 20000


def relative(value):
    if not isinstance(value, str) or not value or '\\' in value or ':' in value or '\x00' in value:
        raise ValueError('Invalid portable relative path')
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(p in ('', '.', '..') for p in value.split('/')):
        raise ValueError('Unsafe or noncanonical relative path')
    return path.parts


@dataclass(frozen=True)
class Source:
    root: Path
    relative_path: str
    archive_path: str
    sha256: str
    size_bytes: int
    scope: str
    max_file_bytes: int = MAX_FILE


def registered_files(documents):
    """Resolve only explicit evidence output references, never pin/source paths."""
    result = {}
    for doc in documents:
        path = doc.get('relative_path')
        if path is None:
            continue
        parts = relative(path)
        if parts[0] not in ('scans', 'extracted') or len(parts) < 2:
            raise ValueError('Registered output is outside the explicit output areas')
        sha = doc.get('content_sha256')
        size = doc.get('size_bytes')
        if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
            raise ValueError('Registered output hash required')
        if size is not None and (type(size) is not int or not 0 <= size <= MAX_FILE):
            raise ValueError('Registered output size invalid')
        if path in result:
            old = result[path]
            if old['sha256'] != sha or (size is not None and old['size_bytes'] is not None and size != old['size_bytes']):
                raise ValueError('Conflicting registrations cannot be deduplicated')
            old['evidence_ids'].append(doc['id'])
            if old['size_bytes'] is None:
                old['size_bytes'] = size
        else:
            result[path] = {'path': path, 'sha256': sha, 'size_bytes': size, 'evidence_ids': [doc['id']]}
    return result


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _valid_file(info, device):
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_dev != device:
        raise ValueError('Only owned, regular, single-link same-filesystem files are permitted')


def _write_source(archive, source):
    if not hasattr(os, 'O_NOATIME'):
        raise ValueError('O_NOATIME required; no fallback')
    parts = relative(source.relative_path)
    relative(source.archive_path)
    if not source.root.is_absolute() or source.root.resolve() != source.root:
        raise ValueError('Source root must be explicit, absolute and without symlinks')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    directory = os.open(source.root, flags | os.O_DIRECTORY)
    fd = None
    try:
        root_info = os.fstat(directory)
        if root_info.st_uid != os.getuid():
            raise ValueError('Source root must be owned by the operator')
        for component in parts[:-1]:
            child = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode) or info.st_dev != root_info.st_dev or info.st_uid != os.getuid():
                os.close(child)
                raise ValueError('Source directory boundary changed')
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], flags | os.O_NOATIME, dir_fd=directory)
        before = os.fstat(fd)
        _valid_file(before, root_info.st_dev)
        if before.st_size != source.size_bytes:
            raise ValueError('Source size differs from explicit allowlist')
        stamp = datetime.fromtimestamp(before.st_mtime, timezone.utc)
        year = max(1980, min(stamp.year, 2107))
        entry = zipfile.ZipInfo(source.archive_path, (year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second))
        entry.compress_type = zipfile.ZIP_DEFLATED
        entry.external_attr = (stat.S_IFREG | 0o600) << 16
        hasher, total = hashlib.sha256(), 0
        with archive.open(entry, 'w') as destination:
            while data := os.read(fd, CHUNK):
                total += len(data)
                if total > source.size_bytes:
                    raise ValueError('Source grew while reading')
                hasher.update(data)
                destination.write(data)
        after = os.fstat(fd)
        current = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if (_identity(before) != _identity(after) or _identity(before) != _identity(current)
                or before.st_atime_ns != after.st_atime_ns or before.st_atime_ns != current.st_atime_ns
                or total != source.size_bytes or hasher.hexdigest() != source.sha256):
            raise ValueError('Source identity, timestamps or expected hash changed; partial preserved')
        return {'path': source.archive_path, 'sha256': source.sha256, 'size_bytes': total,
                'source_scope': source.scope, 'source_relative_path': source.relative_path,
                'source_mtime_ns': before.st_mtime_ns, 'source_atime_unchanged': True}
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def write_bundle(output, sources, buffers, *, context):
    """Write one new archive. Buffers are generated docs or explicitly verified copies.

    Each buffer: (archive path, bytes, metadata). Partial files survive failures;
    an existing final target is never replaced. No automatic retries.
    """
    if os.geteuid() == 0:
        raise ValueError('Never run as root')
    if len(sources) + len(buffers) > MAX_ENTRIES:
        raise ValueError('Entry budget exceeded')
    total, names = 0, {'manifest.json'}
    for source in sources:
        relative(source.archive_path); relative(source.relative_path)
        if not re.fullmatch('[0-9a-f]{64}', source.sha256):
            raise ValueError('Expected SHA-256 required')
        large_backup = (source.max_file_bytes == MAX_SQLITE_BACKUP and source.scope == 'logical_sqlite_backup'
                        and source.archive_path == 'datos/auditoria.sqlite3')
        if type(source.max_file_bytes) is not int or (source.max_file_bytes != MAX_FILE and not large_backup):
            raise ValueError('Larger file budget is only explicit for the logical SQLite backup')
        if type(source.size_bytes) is not int or not 0 <= source.size_bytes <= source.max_file_bytes:
            raise ValueError('Explicit bounded source size required')
        name = source.archive_path.casefold()
        if name in names:
            raise ValueError('Duplicate or reserved archive path')
        names.add(name); total += source.size_bytes
    for name, data, metadata in buffers:
        relative(name)
        if name.casefold() in names or not isinstance(data, bytes) or len(data) > MAX_FILE:
            raise ValueError('Invalid or duplicate buffered archive entry')
        names.add(name.casefold()); total += len(data)
    if total > MAX_TOTAL:
        raise ValueError('Total source byte budget exceeded')
    output = Path(output)
    if not output.is_absolute() or output.parent.resolve() != output.parent or output.exists() or output.is_symlink():
        raise ValueError('Output must be a new path under a real explicit directory')
    partial = output.with_name(output.name + '.partial-' + uuid.uuid4().hex)
    fd = os.open(partial, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    manifest = {'format': 'ri-handoff-zip-v1', 'context': context, 'files': [],
        'limits': ['Query export, not an image or a live case root.',
            'Original registered bytes and timestamps are not rewritten.',
            'ZIP filesystem mtime uses UTC with ZIP precision; source timestamps remain in original data.',
            'The manifest does not hash itself; preserve the external ZIP SHA-256 independently.',
            'Sensitive local evidence; do not execute content or reuse historical approvals.']}
    with os.fdopen(fd, 'w+b') as stream:
        with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
            for source in sources:
                manifest['files'].append(_write_source(archive, source))
            for name, data, metadata in buffers:
                entry = zipfile.ZipInfo(name, datetime.now(timezone.utc).timetuple()[:6])
                entry.compress_type = zipfile.ZIP_DEFLATED
                entry.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(entry, data)
                manifest['files'].append({**metadata, 'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data)})
            raw = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode()
            if len(raw) > 16 * 1024**2:
                raise ValueError('Manifest budget exceeded')
            entry = zipfile.ZipInfo('MANIFEST.json', datetime.now(timezone.utc).timetuple()[:6])
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(entry, raw)
        stream.flush(); os.fsync(stream.fileno())
    verified = verify_bundle(partial)
    os.link(partial, output, follow_symlinks=False)
    partial.unlink()  # Only this successful invocation's staging link.
    directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {**verified, 'path': str(output), 'sha256': _file_hash(output)}


def _file_hash(path):
    hasher = hashlib.sha256()
    with open(path, 'rb') as stream:
        while data := stream.read(CHUNK):
            hasher.update(data)
    return hasher.hexdigest()


def verify_bundle(path):
    """Hash every ZIP entry without extracting or interpreting evidence content."""
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES + 1:
            raise ValueError('Archive entry budget exceeded')
        names = []
        for info in infos:
            relative(info.filename)
            mode = info.external_attr >> 16
            if info.is_dir() or stat.S_ISLNK(mode) or info.flag_bits & 1:
                raise ValueError('Directories, symlinks and encrypted entries are not supported')
            file_budget = MAX_SQLITE_BACKUP if info.filename == 'datos/auditoria.sqlite3' else MAX_FILE
            if not 0 <= info.file_size <= file_budget:
                raise ValueError('Archive file budget exceeded')
            names.append(info.filename.casefold())
        if len(names) != len(set(names)) or sum(i.file_size for i in infos) > MAX_TOTAL + 16 * 1024**2:
            raise ValueError('Duplicate archive path or total byte budget exceeded')
        manifest_info = archive.getinfo('MANIFEST.json')
        if manifest_info.file_size > 16 * 1024**2:
            raise ValueError('Manifest budget exceeded')
        manifest = json.loads(archive.read(manifest_info))
        if manifest.get('format') != 'ri-handoff-zip-v1' or not isinstance(manifest.get('files'), list):
            raise ValueError('Unsupported handoff manifest')
        expected = {}
        for entry in manifest['files']:
            relative(entry['path'])
            file_budget = (MAX_SQLITE_BACKUP if entry['path'] == 'datos/auditoria.sqlite3'
                           and entry.get('source_scope') == 'logical_sqlite_backup' else MAX_FILE)
            if (entry['path'] in expected or entry['path'].casefold() == 'manifest.json'
                    or type(entry['size_bytes']) is not int or not 0 <= entry['size_bytes'] <= file_budget
                    or not isinstance(entry['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])):
                raise ValueError('Invalid manifest entry')
            expected[entry['path']] = entry
        if set(archive.namelist()) != set(expected) | {'MANIFEST.json'}:
            raise ValueError('Archive entries differ from manifest')
        total = 0
        for name, entry in expected.items():
            info = archive.getinfo(name)
            if info.file_size != entry['size_bytes']:
                raise ValueError('Entry size mismatch')
            hasher, size = hashlib.sha256(), 0
            with archive.open(info) as stream:
                while data := stream.read(CHUNK):
                    size += len(data)
                    if size > entry['size_bytes']:
                        raise ValueError('Entry grew past size budget')
                    hasher.update(data)
            if size != entry['size_bytes'] or hasher.hexdigest() != entry['sha256']:
                raise ValueError('Entry SHA-256 mismatch')
            total += size
    return {'valid': True, 'files_verified': len(expected), 'uncompressed_bytes': total,
            'source_revision': manifest['context'].get('source_revision'), 'extracted_or_executed_content': False}
