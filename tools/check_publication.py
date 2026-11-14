#!/usr/bin/env python3
"""Offline, fail-closed checks of an explicit public file list and Git objects.

No content or suspect paths are printed. Pattern checks cannot prove anonymity;
manual review of the approved files remains mandatory.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

MAX_FILE = 2 * 1024 * 1024
MANIFEST = 'PUBLICATION_FILES.txt'
EMAIL = re.compile(r'\b[A-Za-z0-9_.+%-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')
HOME = re.compile(r'/home/([A-Za-z0-9_.-]+)')
IPV4 = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
SECRET = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|'
                    r'\bgh[pousr]_[A-Za-z0-9_]{20,}\b|'
                    r'\bgithub_pat_[A-Za-z0-9_]{20,}\b|'
                    r'\bAKIA[A-Z0-9]{16}\b|\bsk-[A-Za-z0-9_-]{24,}\b')
LONG_HEX = re.compile(r'\b[0-9a-fA-F]{32,128}\b')
FIXTURE_DATA = frozenset({
    'examples/artifacts/synthetic-note.txt', 'examples/artifacts/benign-readme.txt',
    'examples/artifacts/educational-example.txt', 'examples/simulated/windows-usb.json',
    'examples/simulated/destination.json', 'examples/ntfs/physical-pin.example.json',
})
ROOT_FILES = frozenset({'.gitignore', MANIFEST, 'README.md', 'AGENTS.md', 'SECURITY.md',
                        'CONTRIBUTING.md', 'pyproject.toml', 'ri.py'})


def valid_public_path(value):
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or str(path) != value or '\\' in value
            or any(p in ('', '.', '..') or p.startswith('.') for p in path.parts)
            and value != '.gitignore'):
        return False
    if value in ROOT_FILES or value in FIXTURE_DATA:
        return True
    if path.parts[0] in {'src', 'tests', 'tools', 'examples', 'admin', 'broker'}:
        return path.suffix in {'.py', '.md'}
    if path.parts[0] == 'native':
        return path.suffix in {'.c', '.h'}
    return path.parts[0] == 'docs' and path.suffix == '.md'


def scan_text(data, denylist=()):
    issues = set()
    if len(data) > MAX_FILE:
        return {'oversized_file'}
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return {'binary_or_non_utf8'}
    if '\x00' in text:
        issues.add('binary_or_nul')
    if SECRET.search(text):
        issues.add('credential_pattern')
    if any(match[1] != 'SYNTHETIC' for match in HOME.finditer(text)):
        issues.add('personal_home_path')
    for match in EMAIL.finditer(text):
        host = match[1].lower()
        full = match[0].lower()
        if (host not in {'example.com', 'example.org', 'example.net'}
                and not host.endswith(('.invalid', '.example', '.test'))
                and full != 'contributors@users.noreply.github.com'):
            issues.add('non_example_email')
    for match in IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match[0])
        except ValueError:
            continue
        if (not address.is_loopback and not any(address in ipaddress.ip_network(net)
                for net in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'))):
            issues.add('non_documentation_ip')
    if any(len(set(match[0].lower())) > 1 for match in LONG_HEX.finditer(text)):
        issues.add('opaque_identifier_requires_review')
    for token in denylist:
        if re.search(r'(?<!\w)' + re.escape(token) + r'(?!\w)', text, re.IGNORECASE):
            issues.add('private_denylist_match')
    return issues


def regular_bytes(root, relative):
    path = root / relative
    for component in (path, *path.parents):
        if component == root:
            break
        if component.is_symlink():
            raise ValueError('unsafe_file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
            raise ValueError('unsafe_or_oversized_file')
        return os.read(fd, MAX_FILE + 1)
    finally:
        os.close(fd)


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, check=False)
    if result.returncode:
        raise ValueError('git_command_failed')
    return result.stdout


def read_manifest(data):
    text = data.decode('utf-8')
    entries = text.splitlines()
    if (not entries or len(entries) != len(set(entries)) or MANIFEST not in entries
            or entries != sorted(entries) or not all(valid_public_path(v) for v in entries)):
        raise ValueError('invalid_public_file_manifest')
    return set(entries)


def assess(root, *, staged=False, history=False, denylist=()):
    findings = Counter()
    checked = 0
    if staged:
        index = {}
        for entry in git(root, 'ls-files', '--stage', '-z').split(b'\0'):
            if not entry:
                continue
            meta, name = entry.split(b'\t', 1)
            mode, oid, stage = meta.decode('ascii').split()
            name = name.decode('utf-8')
            if stage != '0' or mode not in {'100644', '100755'} or name in index:
                raise ValueError('unsafe_git_index')
            index[name] = oid
        if MANIFEST not in index:
            raise ValueError('missing_staged_manifest')
        manifest = read_manifest(git(root, 'cat-file', 'blob', index[MANIFEST]))
        if set(index) != manifest:
            findings['index_differs_from_manifest'] += 1
        for name, oid in index.items():
            if not valid_public_path(name):
                findings['unapproved_path'] += 1
            findings.update(scan_text(name.encode(), denylist))
            size = int(git(root, 'cat-file', '-s', oid))
            findings.update(scan_text(git(root, 'cat-file', 'blob', oid), denylist)
                            if size <= MAX_FILE else {'oversized_file'})
            checked += 1
    else:
        manifest = read_manifest(regular_bytes(root, MANIFEST))
        found = set()
        for base, dirs, files in os.walk(root, followlinks=False):
            if Path(base) == root:
                dirs[:] = [d for d in dirs if d != '.git']
            for name in dirs:
                if (Path(base) / name).is_symlink():
                    findings['unexpected_symlink'] += 1
            for name in files:
                found.add(str((Path(base) / name).relative_to(root)))
        if found != manifest:
            findings['worktree_differs_from_manifest'] += 1
        for relative in sorted(manifest):
            findings.update(scan_text(relative.encode(), denylist))
            try:
                findings.update(scan_text(regular_bytes(root, relative), denylist))
            except (OSError, ValueError):
                findings['unreadable_or_unsafe_file'] += 1
            checked += 1
    objects_checked = 0
    if history:
        objects = git(root, 'cat-file', '--batch-all-objects',
                      '--batch-check=%(objectname) %(objecttype) %(objectsize)').splitlines()
        if len(objects) > 10000:
            raise ValueError('git_object_budget_exceeded')
        for row in objects:
            oid, kind, size = row.decode('ascii').split()
            if kind in {'blob', 'commit', 'tag'}:
                if int(size) > MAX_FILE:
                    findings['oversized_git_object'] += 1
                else:
                    data = git(root, 'cat-file', kind, oid)
                    if kind in {'commit', 'tag'}:
                        header, separator, body = data.partition(b'\n\n')
                        header = re.sub(rb'(?m)^(?:tree|parent|object) [0-9a-f]{40,64}$',
                                        b'[structural object reference]', header)
                        data = header + separator + body
                    findings.update(scan_text(data, denylist))
                if kind == 'commit':
                    metadata = git(root, 'cat-file', 'commit', oid).decode('utf-8')
                    identity = r'(?:author|committer) Project Contributors <contributors@users\.noreply\.github\.com> \d+ [+-]\d{4}'
                    for line in metadata.split('\n\n', 1)[0].splitlines():
                        if line.startswith(('author ', 'committer ')) and not re.fullmatch(identity, line):
                            findings['non_anonymous_git_identity'] += 1
                    historical_paths = set()
                    for item in git(root, 'ls-tree', '-r', '-z', '--full-tree', oid).split(b'\0'):
                        if item:
                            _, name = item.split(b'\t', 1)
                            relative = name.decode('utf-8')
                            historical_paths.add(relative)
                            findings.update(scan_text(name, denylist))
                    if not historical_paths <= manifest:
                        findings['unapproved_historical_path'] += 1
            elif kind == 'tree':
                for item in git(root, 'ls-tree', '-z', oid).split(b'\0'):
                    if item:
                        header, name = item.split(b'\t', 1)
                        findings.update(scan_text(name, denylist))
                        if header.split()[0] in {b'120000', b'160000'}:
                            findings['unsafe_historical_mode'] += 1
            objects_checked += 1
    return {'status': 'PASS' if not findings else 'BLOCKED', 'files_checked': checked,
            'git_objects_checked': objects_checked, 'checks': dict(sorted(findings.items())),
            'manual_review_required': True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--staged', action='store_true')
    parser.add_argument('--history', action='store_true', help='Scan all stored Git objects, including unreachable objects')
    parser.add_argument('--denylist-file', type=Path, help='Private local JSON string list; never committed or printed')
    args = parser.parse_args(argv)
    try:
        if os.getuid() == 0 or os.geteuid() == 0:
            raise ValueError('normal_user_required')
        denylist = ()
        if args.denylist_file:
            fd = os.open(args.denylist_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME)
            with os.fdopen(fd) as stream:
                denylist = json.load(stream)
            if not isinstance(denylist, list) or not all(isinstance(t, str) and len(t) >= 3 for t in denylist):
                raise ValueError('invalid_private_denylist')
        result = assess(args.root.resolve(), staged=args.staged, history=args.history, denylist=denylist)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        result = {'status': 'BLOCKED', 'reason': 'Input or tooling validation failed; no sensitive details emitted'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
