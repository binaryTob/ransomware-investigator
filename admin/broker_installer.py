#!/usr/bin/python3
"""Offline first-install transaction. Prepare as user; apply ONLY captured root copy.

No imports from the project, source devices, downloads, shell, repair or rollback.
The hash-approved plan fixes every payload, dependency and administrative action.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import grp
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import sysconfig
import time
import uuid
from datetime import datetime, timezone

CODE = Path('/opt/ri-ntfs')
STATE = Path('/var/lib/ransomware-investigator-ntfs')
RUNTIME = Path('/run/ransomware-investigator-ntfs')
REVIEWS = Path('/var/lib/ransomware-investigator-deployments')
UNIT_PATH = Path('/etc/systemd/system/ri-ntfs-broker.service')
UNIT = 'ri-ntfs-broker.service'
PARSER = 'ri-ntfs-parser'
FILES = ('ntfs_broker.py', 'core.py', 'physical.py', 'ntfs_worker', 'broker_installer.py')
TOOLS = ('/usr/bin/python3', '/usr/bin/readelf', '/usr/sbin/ldconfig',
         '/usr/bin/systemctl', '/usr/sbin/useradd', '/usr/bin/udevadm', '/usr/bin/pkexec')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'HOME': '/nonexistent'}
MAX_FILE = 64 * 1024 * 1024


class InstallError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def read_regular(path, *, cap=MAX_FILE, directory_fd=None, noatime=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                 | (os.O_NOATIME if noatime else 0), dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > cap:
            raise InstallError('Not a bounded, single-link regular file: ' + str(path))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(cap + 1)
        if len(data) != before.st_size or len(data) > cap or identity(before) != identity(os.fstat(fd)):
            raise InstallError('File changed while reading: ' + str(path))
        return data
    finally:
        os.close(fd)


def no_capabilities(path):
    try:
        if os.getxattr(path, 'security.capability'):
            raise InstallError('File capabilities forbidden: ' + str(path))
    except OSError as exc:
        if exc.errno not in (errno.ENODATA, errno.ENOTSUP):
            raise


def trusted(path, *, executable=False):
    """Resolve distribution symlinks, checking every link and physical parent."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise InstallError('Absolute dependency path required')
    for name in (path, *path.parents):
        info = name.lstat()
        if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
            raise InstallError('Dependency or parent not root-controlled: ' + str(name))
    resolved = path.resolve(strict=True)
    for name in (resolved, *resolved.parents):
        info = name.lstat()
        if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
            raise InstallError('Physical dependency path unsafe: ' + str(name))
    info = resolved.stat()
    allowed_setid = 0o4000 if str(path) == '/usr/bin/pkexec' else 0
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o6000 != allowed_setid:
        raise InstallError('Dependency not plain, single-link, non-setid code: ' + str(resolved))
    if executable and not info.st_mode & 0o111:
        raise InstallError('Dependency not executable: ' + str(resolved))
    no_capabilities(resolved)
    return resolved


def run(argv, *, user=None, group=None, timeout=20, expected=0):
    kwargs = {'user': user, 'group': group, 'extra_groups': []} if user is not None else {}
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=ENV, cwd='/', shell=False, close_fds=True, timeout=timeout, **kwargs)
    if len(result.stdout) + len(result.stderr) > 4 * 1024 * 1024:
        raise InstallError('Administrative command output limit')
    if result.returncode != expected:
        raise InstallError('Command failed (no retry): ' + str(argv[0]) + ' rc=' + str(result.returncode))
    return result.stdout.decode('utf-8', 'strict')


def dependency_facts(path):
    resolved = trusted(path)
    info = resolved.stat()
    return {'path': str(Path(path)), 'resolved': str(resolved), 'sha256': sha(read_regular(resolved)),
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid, 'size_bytes': info.st_size,
            'identity': list(identity(info))}


def elf_arch(data):
    if not data.startswith(b'\x7fELF'):
        return None
    if len(data) < 20 or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise InstallError('Invalid ELF architecture header')
    return data[4], int.from_bytes(data[18:20], 'little' if data[5] == 1 else 'big')


def elf_edges(path, readelf, cache):
    """Inspect ELF metadata only, never ldd/execute an untrusted dependency."""
    data = read_regular(path)
    arch = elf_arch(data)
    if arch is None:
        return []
    result = run([str(readelf), '--wide', '--program-headers', '--dynamic', str(path)])
    needed = re.findall(r'\(NEEDED\).*?\[([^\]]+)\]', result)
    paths = re.findall(r'\((?:RPATH|RUNPATH)\).*?\[([^\]]*)\]', result)
    search = []
    for entry in paths:
        for directory in entry.split(':'):
            # No cwd, $ORIGIN, environment-dependent or arbitrary search fallback.
            if not directory.startswith('/') or '$' in directory or '..' in Path(directory).parts:
                raise InstallError('Unsupported ELF search path: ' + directory)
            base = Path(directory)
            for parent in (base, *base.parents):
                info = parent.lstat()
                if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
                    raise InstallError('Writable ELF search directory: ' + directory)
            search.append(base)
    edges = re.findall(r'Requesting program interpreter:\s*([^\]]+)\]', result)
    for name in needed:
        if '/' in name:
            raise InstallError('ELF dependency with embedded path')
        local = next((str(base / name) for base in search if (base / name).exists()), None)
        candidates = [local] if local else cache.get(name, [])
        candidates = list(dict.fromkeys(str(trusted(p)) for p in candidates
                                       if elf_arch(read_regular(trusted(p))) == arch))
        if len(candidates) != 1:
            raise InstallError('Missing or ambiguous offline ELF dependency: ' + name)
        edges.append(candidates[0])
    return edges


def dependencies(worker):
    readelf = trusted('/usr/bin/readelf', executable=True)
    ldconfig = trusted('/usr/sbin/ldconfig', executable=True)
    listing = run([str(ldconfig), '-p'])  # print existing cache ONLY; never update it
    cache = {}
    for line in listing.splitlines():
        match = re.match(r'\s*(\S+) \([^)]*\) => (/\S+)\s*$', line)
        if match:
            cache.setdefault(match[1], []).append(match[2])
    queue = [str(trusted(tool, executable=True)) for tool in TOOLS]
    # -I -S -B excludes site/.pth and prevents new root bytecode. Pin stdlib too.
    stdlib = Path(sysconfig.get_path('stdlib'))
    for parent, dirs, names in os.walk(stdlib, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in ('site-packages', 'dist-packages'))
        for directory in dirs:
            info = (Path(parent) / directory).lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise InstallError('Unsafe Python stdlib directory')
        for name in sorted(names):
            queue.append(str(Path(parent) / name))
    facts = {str(Path(tool)): dependency_facts(tool) for tool in TOOLS}
    facts['/etc/ld.so.cache'] = dependency_facts('/etc/ld.so.cache')
    inspected = set()
    # Worker is a hash-bound payload, NOT required to be root-owned while preparing.
    queue.extend(elf_edges(worker, readelf, cache))
    while queue:
        path = queue.pop()
        if path in inspected:
            continue
        if len(inspected) >= 8192:
            raise InstallError('Dependency graph limit')
        inspected.add(path)
        facts[path] = dependency_facts(path)
        queue.extend(elf_edges(facts[path]['resolved'], readelf, cache))
    return [facts[key] for key in sorted(facts)]


def unit_bytes(gid):
    if type(gid) is not int or gid <= 0:
        raise InstallError('Non-root operator group required')
    return ("[Unit]\nDescription=RI typed read-only NTFS broker\nAfter=local-fs.target\n"
        "[Service]\nType=simple\nUser=root\nGroup=root\nWorkingDirectory=/\nUMask=0077\n"
        "ExecStart=/usr/bin/python3 -I -S -B /opt/ri-ntfs/ntfs_broker.py --serve --socket-gid " + str(gid) + "\n"
        "Restart=no\nKillMode=control-group\nTimeoutStopSec=20\nLimitCORE=0\nNoNewPrivileges=yes\n"
        "UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PYTHONHOME\n"
        "RuntimeDirectory=ransomware-investigator-ntfs\nRuntimeDirectoryMode=0711\n"
        "StandardOutput=journal\nStandardError=journal\n").encode()


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data); stream.flush(); os.fsync(fd)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try: os.fsync(directory_fd)
    finally: os.close(directory_fd)


def validate_plan(plan):
    keys = {'schema_version', 'operation', 'operator_uid', 'operator_gid', 'operator_name', 'payloads',
            'dependencies', 'unit_sha256', 'bootstrap_sha256', 'actions', 'physical_read_authorized'}
    session=isinstance(plan,dict) and plan.get('operation')=='sequence_approval_session_only'
    updating=isinstance(plan,dict) and plan.get('operation') in ('update_broker_code_only','sequence_approval_session_only')
    preserving=isinstance(plan,dict) and plan.get('operation')=='update_broker_code_only' and 'preserved_expired_approvals' in plan
    if updating: keys |= {'installed_before','unit_before_sha256','parser_uid','parser_gid'}
    if session: keys.add('sequence_authorization')
    if preserving: keys.add('preserved_expired_approvals')
    if (not isinstance(plan, dict) or set(plan) != keys or type(plan['schema_version']) is not int or plan['schema_version'] != 1
            or plan['operation'] not in ('first_install_only','update_broker_code_only','sequence_approval_session_only') or plan['physical_read_authorized'] is not False
            or set(plan['payloads']) != set(FILES) or plan['actions'] != (SESSION_ACTIONS if session else PRESERVING_UPDATE_ACTIONS if preserving else UPDATE_ACTIONS if updating else ACTIONS)):
        raise InstallError('Unexpected deployment plan or expanded scope')
    for key in ('operator_uid', 'operator_gid'):
        if type(plan[key]) is not int or not 0 < plan[key] < 2**31:
            raise InstallError('Invalid operator identity')
    account = pwd.getpwuid(plan['operator_uid'])
    if account.pw_name != plan['operator_name'] or account.pw_gid != plan['operator_gid']:
        raise InstallError('Operator identity changed')
    for value in list(plan['payloads'].values()) + [plan['unit_sha256'], plan['bootstrap_sha256']]:
        if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
            raise InstallError('Invalid approved SHA-256')
    if plan['unit_sha256'] != sha(unit_bytes(plan['operator_gid'])):
        raise InstallError('Unit differs from fixed reviewed procedure')
    if updating:
        if (not isinstance(plan['installed_before'],dict) or set(plan['installed_before'])!=set(FILES[:-1])
                or plan['unit_before_sha256']!=plan['unit_sha256']):
            raise InstallError('Update only reviewed code, not unit/account/state configuration')
        for value in plan['installed_before'].values():
            if not isinstance(value,str) or not re.fullmatch('[0-9a-f]{64}',value): raise InstallError('Invalid installed baseline hash')
        if any(type(plan[k]) is not int or plan[k]<=0 for k in ('parser_uid','parser_gid')) or plan['parser_uid']==plan['operator_uid']:
            raise InstallError('Invalid existing parser identity')
    if session:
        validate_sequence_authorization(plan['sequence_authorization'],plan['operator_uid'])
        if any(plan['payloads'][name]!=plan['installed_before'][name] for name in FILES[:-1]):
            raise InstallError('Approval session cannot change any installed broker code')
    if preserving:
        validate_update_preservation(plan['preserved_expired_approvals'],plan['operator_uid'])
    if not isinstance(plan['dependencies'], list) or not 1 <= len(plan['dependencies']) <= 8192:
        raise InstallError('Missing dependency inventory')
    allowed = ('/usr/', '/lib/', '/lib64/', '/bin/', '/sbin/')
    system_config = {'/etc/ld.so.cache', '/etc/python' + str(sys.version_info.major) + '.' + str(sys.version_info.minor) + '/sitecustomize.py'}
    seen = set()
    for item in plan['dependencies']:
        if not isinstance(item, dict) or set(item) != {'path','resolved','sha256','mode','uid','gid','size_bytes','identity'}:
            raise InstallError('Malformed dependency facts')
        for key in ('path', 'resolved'):
            value = item[key]
            if (not isinstance(value, str) or '..' in Path(value).parts
                    or not (value.startswith(allowed) or value in system_config)):
                raise InstallError('Dependency outside fixed system-code/cache locations')
        if item['path'] in seen or item['uid'] != 0 or not re.fullmatch('[0-9a-f]{64}', item['sha256']):
            raise InstallError('Duplicate or untrusted dependency facts')
        seen.add(item['path'])
    if not set(TOOLS) <= seen or '/etc/ld.so.cache' not in seen:
        raise InstallError('Required dependencies omitted')


ACTIONS = ['verify_payloads_and_dependencies', 'create_locked_parser_account', 'install_four_broker_files',
           'create_private_broker_state', 'install_unit_without_boot_enablement', 'start_service',
           'test_parser_loader_as_unprivileged_uid', 'test_socket_denial_without_grant', 'write_admin_receipt']
UPDATE_ACTIONS=['verify_installed_baseline_and_dependencies','require_idle_no_approved_grants',
                'stop_existing_service','backup_reviewed_code','replace_changed_code_only','start_service',
                'test_parser_loader_as_unprivileged_uid','test_socket_denial_without_grant',
                 'verify_preserved_nonce_state_and_ledger','write_admin_receipt']
PRESERVING_UPDATE_ACTIONS=[UPDATE_ACTIONS[0],'require_idle_preserve_exact_expired_grants',
                          *UPDATE_ACTIONS[2:-1],'verify_preserved_expired_grants_unchanged',UPDATE_ACTIONS[-1]]
SESSION_ACTIONS=['verify_installed_baseline_and_dependencies','verify_exact_sequence_and_completed_prefix',
                 'serve_bounded_typed_approval_session','write_admin_receipt']


def validate_update_preservation(items, uid):
    """History to preserve, never requests to approve/execute. Update-only opt-in.

    A hash of the entire old grant binds even non-authorizing fields. Runtime
    checks still require actual expiry, no consumption, and the exact ledger.
    No imports of mutable project code or interpretation of device selectors.
    """
    if type(uid) is not int or not 0<uid<2**31 or not isinstance(items,list) or not 1<=len(items)<=8:
        raise InstallError('Update preservation requires one to eight exact expired grants')
    seen=set()
    for item in items:
        if (not isinstance(item,dict) or set(item)!={'request','expires_at','failed_execution_id','grant_sha256'} or
                type(item['expires_at']) not in (int,float) or not 0<item['expires_at']<2**63):
            raise InstallError('Exact expired-grant hash, request, expiry and failure reference required')
        for field,width in (('grant_sha256',64),('failed_execution_id',32)):
            if not isinstance(item[field],str) or not re.fullmatch('[0-9a-f]{'+str(width)+'}',item[field]):
                raise InstallError('Invalid expired-grant hash or failure reference')
        request=item['request']
        fields={'schema_version','request_id','case_id','source_id','uid','scope','parameters','source','reason'}
        if (not isinstance(request,dict) or set(request)!=fields or type(request['schema_version']) is not int or
                request['schema_version']!=1 or type(request['uid']) is not int or request['uid']!=uid or uid<=0 or
                request['scope'] not in ('ntfs.volume','ntfs.records','ntfs.directory','ntfs.list','ntfs.search',
                                         'ntfs.mft','ntfs.deleted','ntfs.extract','ntfs.prefix','ntfs.diagnose') or
                not isinstance(request['parameters'],dict) or not isinstance(request['source'],dict) or
                set(request['source'])!={'kind','pin'} or request['source']['kind']!='physical' or
                not isinstance(request['source']['pin'],dict) or not request['source']['pin'] or
                not isinstance(request['reason'],str) or not 1<=len(request['reason'])<=4096 or
                any(ord(c)<32 for c in request['reason'])):
            raise InstallError('Preservation is limited to exact historical physical requests for this UID')
        for field in ('request_id','case_id','source_id'):
            if not isinstance(request[field],str) or not re.fullmatch('[0-9a-f]{32}',request[field]):
                raise InstallError('Invalid historical request identity')
        if request['request_id'] in seen: raise InstallError('Duplicate preserved expired nonce')
        seen.add(request['request_id'])
        try: raw=canonical(request)
        except (ValueError,TypeError) as exc: raise InstallError('Invalid historical request JSON') from exc
        if len(raw)>65536: raise InstallError('Historical request exceeds grant read limit')


def _selective_content_output_size(request):
    """A separate opt-in profile, never a metadata-scope exception.

    The installed core and physical gate independently validate the complete
    request/pin before approval and execution. This courier adds tighter caps.
    """
    p=request.get('parameters')
    fields={'inode','attribute_id','max_entries','max_depth','max_bytes','expected_sequence',
            'expected_size','allow_deleted','read_budget','timeout_ms','extensions'}
    if not isinstance(p,dict) or set(p)!=fields:
        raise InstallError('Selective content requires every canonical stream parameter, without extras')
    bounds={'inode':(16,2**63-1),'attribute_id':(0,65535),'max_entries':(1,1),'max_depth':(0,0),
            'max_bytes':(1,1024*1024),'expected_sequence':(1,2**32-1),'expected_size':(1,2**63-1),
            'read_budget':(4096,64*1024*1024),'timeout_ms':(1,10000)}
    if (any(type(p[key]) is not int or not low<=p[key]<=high for key,(low,high) in bounds.items())
            or p['allow_deleted'] is not False or type(p['extensions']) is not list or p['extensions']):
        raise InstallError('Selective content must be an allocated, exact, nonrecursive bounded stream')
    if request['scope']=='ntfs.extract':
        if p['max_bytes']!=p['expected_size']:
            raise InstallError('Selective extraction requires the exact complete stream, not fragments')
        return p['expected_size']
    if request['scope']!='ntfs.prefix' or p['max_bytes']>65536 or p['max_bytes']>p['expected_size']:
        raise InstallError('Selective prefixes are at most 64 KiB, never beyond the declared stream size')
    return p['max_bytes']


def validate_sequence_authorization(auth, uid):
    keys={'sequence','sequence_sha256','first_batch_ordinal','custody_attestation','reason','max_session_seconds'}
    allowed_keys=[keys|preserved|profile
        for preserved in (set(),{'preserved_expired_approval'},{'preserved_expired_approvals'})
        for profile in (set(),{'approval_profile'})]
    if not isinstance(auth,dict) or set(auth) not in allowed_keys:
        raise InstallError('Exact finite sequence authorization required')
    selective='approval_profile' in auth
    if selective and auth['approval_profile']!='selective_content_v1':
        raise InstallError('Unknown approval profile; no default content permission')
    allowed_scopes=('ntfs.extract','ntfs.prefix') if selective else ('ntfs.volume','ntfs.records','ntfs.directory')
    sequence=auth['sequence']
    if (not isinstance(sequence,dict) or type(sequence.get('schema_version')) is not int or sequence['schema_version']!=1
            or type(sequence.get('requesting_uid')) is not int or sequence['requesting_uid']!=uid
            or not isinstance(sequence.get('case_id'),str) or not re.fullmatch('[0-9a-f]{32}',sequence['case_id'])
            or not isinstance(sequence.get('batches'),list) or not 1<=len(sequence['batches'])<=512
            or type(sequence.get('batch_count')) is not int or sequence['batch_count']!=len(sequence['batches'])
            or not isinstance(auth['sequence_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',auth['sequence_sha256'])
            or sha(canonical(sequence))!=auth['sequence_sha256']):
        raise InstallError('Sequence hash/schema/UID mismatch')
    if (type(auth['first_batch_ordinal']) is not int or not 1<=auth['first_batch_ordinal']<=len(sequence['batches'])
            or type(auth['max_session_seconds']) is not int or not 600<=auth['max_session_seconds']<=14400):
        raise InstallError('Approval session must have a finite batch boundary and 10-minute to 4-hour cap')
    for key in ('custody_attestation','reason'):
        value=auth[key]
        if not isinstance(value,str) or not 8<=len(value.strip())<=2048 or any(ord(c)<32 for c in value):
            raise InstallError('Explicit bounded reason/custody statement required')
    nonces=set(); count=0; output_bytes=0
    for ordinal,batch in enumerate(sequence['batches'],1):
        if (not isinstance(batch,dict) or type(batch.get('ordinal')) is not int or batch['ordinal']!=ordinal
                or not isinstance(batch.get('requests'),list) or not 1<=len(batch['requests'])<=8
                or type(batch.get('request_count')) is not int or batch['request_count']!=len(batch['requests'])
                or batch.get('batch_sha256')!=sha(canonical({'schema_version':1,'requests':batch['requests']}))):
            raise InstallError('Exact ordered batches of at most eight requests required')
        binding=None
        for request in batch['requests']:
            if (not isinstance(request,dict) or request.get('case_id')!=sequence['case_id']
                    or type(request.get('uid')) is not int or request['uid']!=uid
                    or request.get('scope') not in allowed_scopes
                    or not isinstance(request.get('request_id'),str) or not re.fullmatch('[0-9a-f]{32}',request['request_id'])
                    or request['request_id'] in nonces or not isinstance(request.get('source'),dict)
                    or set(request['source'])!={'kind','pin'} or request['source']['kind']!='physical'):
                raise InstallError('Sequence contains duplicate/nonphysical/unsupported-scope/mismatched requests')
            if selective: output_bytes+=_selective_content_output_size(request)
            current=(request.get('source_id'),sha(canonical(request['source'])))
            if binding is not None and current!=binding: raise InstallError('A batch cannot mix sources')
            binding=current; nonces.add(request['request_id']); count+=1
    if type(sequence.get('request_count')) is not int or sequence['request_count']!=count or count>4096:
        raise InstallError('Finite sequence request count mismatch or exceeded')
    if selective and (count>8 or output_bytes>1024*1024):
        raise InstallError('Selective content is capped at eight requests and 1 MiB total output across all batches')
    preserved=_preserved_approvals(auth)
    if not isinstance(preserved,list) or len(preserved)>8 or ('preserved_expired_approvals' in auth and not preserved):
        raise InstallError('At most eight explicitly listed expired approvals may be preserved')
    old_nonces=set()
    for item in preserved:
        if (not isinstance(item,dict) or set(item)!={'request','expires_at','failed_execution_id'}
                or type(item.get('expires_at')) not in (int,float) or not 0<item['expires_at']<2**63
                or not isinstance(item.get('failed_execution_id'),str)
                or not re.fullmatch('[0-9a-f]{32}',item['failed_execution_id'])):
            raise InstallError('One exact previously failed, expired approval declaration required')
        old=item['request']
        if (not isinstance(old,dict) or old.get('case_id')!=sequence['case_id']
                or type(old.get('uid')) is not int or old['uid']!=uid
                or old.get('scope') not in ('ntfs.volume','ntfs.records','ntfs.directory')
                or not isinstance(old.get('request_id'),str) or not re.fullmatch('[0-9a-f]{32}',old['request_id'])
                or old['request_id'] in nonces or old['request_id'] in old_nonces or not isinstance(old.get('source'),dict)
                or set(old['source'])!={'kind','pin'} or old['source']['kind']!='physical'):
            raise InstallError('Preserved expired nonce must be unrelated to this exact new sequence')
        old_nonces.add(old['request_id'])
    return sequence['batches']


def _preserved_approvals(auth):
    if 'preserved_expired_approvals' in auth: return auth['preserved_expired_approvals']
    if 'preserved_expired_approval' in auth: return [auth['preserved_expired_approval']]
    return []


def _session_receive(fd, deadline, *, maximum=65536):
    def exact(count):
        data=bytearray()
        while len(data)<count:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([fd],[],[],remaining)[0]:
                raise InstallError('Approval session/frame expired')
            piece=os.read(fd,count-len(data))
            if not piece: raise EOFError('Approval client disconnected')
            data.extend(piece)
        return bytes(data)
    size=struct.unpack('!I',exact(4))[0]
    if not 2<=size<=maximum: raise InstallError('Invalid typed session frame size')
    value=json.loads(exact(size))
    if not isinstance(value,dict): raise InstallError('Typed session object required')
    return value


def _session_send(fd, value):
    data=canonical(value)
    if not 2<=len(data)<=65536: raise InstallError('Session response exceeds fixed frame limit')
    view=memoryview(struct.pack('!I',len(data))+data)
    while view:
        count=os.write(fd,view)
        if count<=0: raise InstallError('Incomplete session frame write')
        view=view[count:]


class SequenceApprovalSession:
    """Normal-user pipe client. One polkit process; no password handling or shell."""
    def __init__(self, plan_path, approved_sha256):
        self.plan_path=Path(plan_path).absolute(); self.approved_sha256=approved_sha256
        self.process=None; self.plan=None; self.next_ordinal=None; self.closed=False

    def start(self):
        if os.getuid()==0 or os.geteuid()==0 or self.process is not None:
            raise InstallError('Session launcher must be normal-user and single-use')
        raw=read_regular(self.plan_path,cap=8*1024*1024)
        if sha(raw)!=self.approved_sha256: raise InstallError('Approval session plan hash mismatch')
        plan=json.loads(raw); validate_plan(plan)
        if plan['operation']!='sequence_approval_session_only' or plan['operator_uid']!=os.getuid():
            raise InstallError('Wrong approval-session plan/operator')
        if sha(read_regular(Path(__file__)))!=plan['payloads']['broker_installer.py']:
            raise InstallError('Session launcher changed')
        for name,expected in plan['payloads'].items():
            if sha(read_regular(self.plan_path.parent/name))!=expected: raise InstallError('Captured session payload changed')
        bootstrap=read_regular(self.plan_path.parent/'bootstrap.py',cap=2*1024*1024)
        if sha(bootstrap)!=plan['bootstrap_sha256']: raise InstallError('Captured bootstrap changed')
        verify_dependencies(plan,worker=self.plan_path.parent/'ntfs_worker')
        write_new(self.plan_path.parent/'session-launch-intent.json',canonical({'plan_sha256':self.approved_sha256,
            'sequence_sha256':plan['sequence_authorization']['sequence_sha256'],'automatic_retry':False}))
        argv=['/usr/bin/pkexec','--disable-internal-agent','/usr/bin/python3','-I','-S','-B','-c',
              bootstrap.decode(),str(self.plan_path.parent),self.approved_sha256,plan['payloads']['broker_installer.py']]
        self.plan=plan
        ready=None
        try:
            self.process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    env=ENV,cwd='/',shell=False,close_fds=True)
            ready=_session_receive(self.process.stdout.fileno(),time.monotonic()+300)
            auth=plan['sequence_authorization']
            if (ready.get('status')!='approval_session_ready' or ready.get('plan_sha256')!=self.approved_sha256
                    or ready.get('sequence_sha256')!=auth['sequence_sha256']
                    or ready.get('next_batch_ordinal')!=auth['first_batch_ordinal']
                    or ready.get('operator_uid')!=plan['operator_uid']):
                raise InstallError('Approval helper did not confirm the exact session')
            self.next_ordinal=auth['first_batch_ordinal']
            write_new(self.plan_path.parent/'session-start-receipt.json',canonical(ready))
            return ready
        except Exception:
            self.close(ready); raise

    def approve_next(self, ordinal):
        if self.closed or self.process is None or type(ordinal) is not int or ordinal!=self.next_ordinal:
            raise InstallError('Out-of-order or inactive approval session')
        _session_send(self.process.stdin.fileno(),{'action':'approve-next','ordinal':ordinal})
        result=_session_receive(self.process.stdout.fileno(),time.monotonic()+120)
        batch=self.plan['sequence_authorization']['sequence']['batches'][ordinal-1]
        if (result.get('status')!='batch_approved' or result.get('ordinal')!=ordinal
                or result.get('batch_sha256')!=batch['batch_sha256']
                or not isinstance(result.get('grants'),list) or len(result['grants'])!=batch['request_count']
                or [(g.get('request_id'),g.get('uid'),g.get('scope')) for g in result['grants']]
                   !=[(r['request_id'],r['uid'],r['scope']) for r in batch['requests']]):
            raise InstallError('Exact batch approval failed; stop without a new authentication')
        self.next_ordinal+=1
        return result

    def finish(self):
        if self.closed or self.process is None or self.next_ordinal!=len(self.plan['sequence_authorization']['sequence']['batches'])+1:
            raise InstallError('Cannot finish an incomplete approval sequence')
        _session_send(self.process.stdin.fileno(),{'action':'finish'})
        result=_session_receive(self.process.stdout.fileno(),time.monotonic()+120)
        if result.get('status')!='sequence_session_completed': raise InstallError('Session completion not confirmed')
        self.close(result)
        return result

    def close(self, receipt=None):
        if self.closed: return
        self.closed=True
        if self.process is None: return
        if self.process.stdin is not None: self.process.stdin.close()
        confirmed=True
        try: self.process.wait(timeout=5)
        except subprocess.TimeoutExpired: confirmed=False
        stderr=b''
        if confirmed and self.process.stderr is not None: stderr=self.process.stderr.read(65537)
        for stream in (self.process.stdout,self.process.stderr):
            if stream is not None: stream.close()
        write_new(self.plan_path.parent/'session-end-receipt.json',canonical({'receipt':receipt,
            'helper_exit_confirmed':confirmed,'returncode':self.process.returncode if confirmed else None,
            'stderr_sha256':sha(stderr),'stderr_local':stderr.decode('utf-8','backslashreplace'),
            'automatic_retry':False,'broker_or_worker_signalled':False}))


def prepare(project, *, update=False, sequence_authorization=None, preserved_expired_approvals=None):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise InstallError('Preparation/tests never run as root')
    if preserved_expired_approvals is not None:
        if not update or sequence_authorization is not None:
            raise InstallError('Expired-grant update opt-in is not an install or approval session')
        validate_update_preservation(preserved_expired_approvals,os.getuid())
    project = Path(project).resolve(strict=True)
    if Path(__file__).resolve() != project / 'admin/broker_installer.py':
        raise InstallError('Fixed project preparation entrypoint required')
    user = pwd.getpwuid(os.getuid())
    source = {'ntfs_broker.py': project / 'broker/ntfs_broker.py',
              'core.py': project / 'src/ransomware_investigator/ntfs/core.py',
              'physical.py': project / 'src/ransomware_investigator/ntfs/physical.py',
              'ntfs_worker': project / '.build/ntfs_worker', 'broker_installer.py': Path(__file__)}
    captured = {name: read_regular(path) for name, path in source.items()}
    bootstrap = read_regular(project / 'admin/broker_bootstrap.py')
    plan = {'schema_version': 1, 'operation': 'first_install_only', 'operator_uid': user.pw_uid,
            'operator_gid': user.pw_gid, 'operator_name': user.pw_name,
            'payloads': {name: sha(data) for name, data in captured.items()},
            'dependencies': dependencies(source['ntfs_worker']), 'unit_sha256': sha(unit_bytes(user.pw_gid)),
            'bootstrap_sha256': sha(bootstrap),
            'actions': ACTIONS, 'physical_read_authorized': False}
    if update or sequence_authorization is not None:
        parser=pwd.getpwnam(PARSER)
        plan.update(operation='update_broker_code_only',actions=UPDATE_ACTIONS,
                    installed_before={name:sha(read_regular(trusted(CODE/name))) for name in FILES[:-1]},
                    unit_before_sha256=sha(read_regular(trusted(UNIT_PATH))),parser_uid=parser.pw_uid,parser_gid=parser.pw_gid)
    if sequence_authorization is not None:
        plan.update(operation='sequence_approval_session_only',actions=SESSION_ACTIONS,
                     sequence_authorization=sequence_authorization)
    if preserved_expired_approvals is not None:
        plan.update(preserved_expired_approvals=json.loads(canonical(preserved_expired_approvals)),actions=PRESERVING_UPDATE_ACTIONS)
    validate_plan(plan)
    directory = project / '.build' / ('broker-deployment-' + uuid.uuid4().hex)
    directory.mkdir(mode=0o700)
    for name, data in captured.items(): write_new(directory / name, data)
    write_new(directory / 'bootstrap.py', bootstrap)
    write_new(directory / 'plan.json', canonical(plan))
    return {'bundle': str(directory), 'plan_sha256': sha(canonical(plan)),
            'installer_sha256': plan['payloads']['broker_installer.py'],
            'bootstrap_sha256': plan['bootstrap_sha256'],
            'dependency_count': len(plan['dependencies']), 'privileged_operations_executed': False}


def launch(plan_path, approved_sha256):
    """Exactly ONE pkexec attempt after explicit approval; no sudo/su fallbacks."""
    if os.getuid() == 0 or os.geteuid() == 0:
        raise InstallError('The checkout launcher must remain unprivileged')
    plan_path = Path(plan_path).absolute()
    data = read_regular(plan_path, cap=8 * 1024 * 1024)
    if sha(data) != approved_sha256:
        raise InstallError('Approval does not match bundle plan')
    plan = json.loads(data); validate_plan(plan)
    if plan['operation']=='sequence_approval_session_only':
        raise InstallError('Use the normal-user SequenceApprovalSession client, not the installer launcher')
    if plan['operator_uid'] != os.getuid() or sha(read_regular(Path(__file__))) != plan['payloads']['broker_installer.py']:
        raise InstallError('Launcher/installer or requesting UID changed')
    for name, expected in plan['payloads'].items():
        if sha(read_regular(plan_path.parent / name)) != expected:
            raise InstallError('Payload changed before privilege request')
    bootstrap = read_regular(plan_path.parent / 'bootstrap.py', cap=2 * 1024 * 1024)
    if sha(bootstrap) != plan['bootstrap_sha256']:
        raise InstallError('Administrative bootstrap changed')
    verify_dependencies(plan, worker=plan_path.parent / 'ntfs_worker')
    # Authentication uses the existing OS agent, never collects a password here.
    argv = ['/usr/bin/pkexec', '--disable-internal-agent', '/usr/bin/python3', '-I', '-S', '-B',
            '-c', bootstrap.decode('utf-8'), str(plan_path.parent), approved_sha256,
            plan['payloads']['broker_installer.py']]
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=ENV, cwd='/', shell=False, close_fds=True, timeout=300)
    except (subprocess.TimeoutExpired, OSError) as exc:
        write_new(plan_path.parent / 'launch-receipt.json', canonical({'status':'execution_unconfirmed',
            'plan_sha256':approved_sha256, 'automatic_retry':False,
            'error_type':type(exc).__name__,
            'partial_stdout_sha256':sha(getattr(exc,'stdout',None) or b''),
            'partial_stderr_sha256':sha(getattr(exc,'stderr',None) or b'')}))
        raise InstallError('Administrative execution unconfirmed; review root audit; do not retry') from exc
    receipt = {'at': datetime.now(timezone.utc).isoformat(), 'plan_sha256': approved_sha256,
               'returncode': result.returncode, 'stdout_sha256': sha(result.stdout),
               'stderr_sha256': sha(result.stderr), 'stdout': result.stdout.decode('utf-8', 'backslashreplace'),
               'stderr': result.stderr.decode('utf-8', 'backslashreplace'), 'automatic_retry': False}
    write_new(plan_path.parent / 'launch-receipt.json', canonical(receipt))
    if result.returncode != 0:
        raise InstallError('Administrative launch/install failed; receipt saved locally; no retry/fallback')
    installed = json.loads(result.stdout)
    expected_status='updated_and_smoke_checked' if plan['operation']=='update_broker_code_only' else 'installed_and_smoke_checked'
    if installed.get('status') != expected_status or installed.get('plan_sha256') != approved_sha256:
        raise InstallError('Unconfirmed installation; review administrative audit')
    return installed


class Audit:
    def __init__(self, directory):
        self.path = Path(directory) / 'administration.jsonl'
        self.previous = '0' * 64
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

    def event(self, action, **details):
        event = {'at': datetime.now(timezone.utc).isoformat(), 'action': action,
                 'previous_sha256': self.previous, **details}
        self.previous = sha(canonical(event))
        data = canonical({'event': event, 'sha256': self.previous}) + b'\n'
        view = memoryview(data)
        while view:
            count = os.write(self.fd, view)
            if count <= 0: raise InstallError('Administrative audit write failed')
            view = view[count:]
        os.fsync(self.fd)

    def command(self, argv):
        self.event('command_intent', argv=argv)
        output = run(argv)
        self.event('command_completed', argv=argv, stdout_sha256=sha(output.encode()))


def verify_dependencies(plan, *, worker=None):
    for saved in plan['dependencies']:
        if dependency_facts(saved['path']) != saved:
            raise InstallError('Approved dependency changed: ' + saved['path'])
    if worker is not None and dependencies(worker) != plan['dependencies']:
        raise InstallError('Loader resolution, stdlib files or dependency graph changed')


def check_absent():
    for path in (CODE, STATE, RUNTIME, UNIT_PATH):
        if os.path.lexists(path):
            raise InstallError('Existing target; no automatic repair/update: ' + str(path))
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try: lookup(PARSER)
        except KeyError: pass
        else: raise InstallError('Parser account/group already exists; no takeover')


def host_prechecks():
    # Kernel metadata only. No physical module import or source descriptor here.
    if os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'):
        raise InstallError('Installer is not in host init mount namespace')
    with open('/proc/self/uid_map', 'rb') as kernel:
        uid_map = kernel.read(16385)
    if len(uid_map) > 16384 or uid_map.split() != [b'0', b'0', b'4294967295']:
        raise InstallError('Initial user namespace required')
    with open('/proc/1/mountinfo', 'r', encoding='utf-8') as kernel:
        mounts = kernel.read(2 * 1024 * 1024 + 1)
    if len(mounts) > 2 * 1024 * 1024:
        raise InstallError('Host mount metadata limit')
    for line in mounts.splitlines():
        fields = line.split()
        if len(fields) >= 10 and fields[4] == '/' and '-' in fields and fields[fields.index('-')+1] in ('overlay','aufs'):
            raise InstallError('Native host required, not container root')
    if not Path('/run/systemd/system').is_dir():
        raise InstallError('Running host systemd required; no fallback supervisor')
    root_dev = Path('/').stat().st_dev
    for parent in (CODE.parent, STATE.parent, UNIT_PATH.parent):
        for item in (parent, *parent.parents):
            info = item.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                    or info.st_dev != root_dev):
                raise InstallError('Administrative target not root-controlled/on root filesystem')


def root_directory(path, mode):
    path.mkdir(mode=0o700)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(fd, mode)  # initial configuration of a NEW directory only
        os.fsync(fd)
        info = os.fstat(fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
            raise InstallError('Created directory permissions differ')
    finally:
        os.close(fd)


def smoke(plan, parser):
    # Wrong argc exits 2 before opening any source; loader still runs as parser UID.
    run([str(CODE / 'ntfs_worker')], user=parser.pw_uid, group=parser.pw_gid, expected=2)
    probe = """import json,os,socket,stat,struct
p='/run/ransomware-investigator-ntfs/broker.sock'
assert stat.S_ISSOCK(os.lstat(p).st_mode) and os.lstat(p).st_uid==0
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
 s.settimeout(5); s.connect(p)
 assert struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]==0
 s.sendall(struct.pack('!I',2)+b'{}')
 def exact(n):
  b=b''
  while len(b)<n:
   p=s.recv(n-len(b))
   if not p: raise ValueError('truncated')
   b+=p
  return b
 n=struct.unpack('!I',exact(4))[0]; assert 2<=n<=65536
 r=json.loads(exact(n)); assert r['status']=='failed'
 print('denied_without_grant_no_source_requested')
"""
    output = run(['/usr/bin/python3', '-I', '-S', '-B', '-c', probe],
                 user=plan['operator_uid'], group=plan['operator_gid'])
    if output.strip() != 'denied_without_grant_no_source_requested':
        raise InstallError('Unexpected no-grant smoke result')


def existing_update_baseline(plan):
    for name,expected in plan['installed_before'].items():
        path=trusted(CODE/name); info=path.stat()
        if (sha(read_regular(path))!=expected or info.st_gid!=0
                or stat.S_IMODE(info.st_mode)!=(0o755 if name=='ntfs_worker' else 0o644)):
            raise InstallError('Installed baseline/hash/permissions changed; no update')
    path=trusted(UNIT_PATH)
    if sha(read_regular(path))!=plan['unit_before_sha256'] or stat.S_IMODE(path.stat().st_mode)!=0o644:
        raise InstallError('Existing unit changed; no update')
    parser=pwd.getpwnam(PARSER)
    if (parser.pw_uid!=plan['parser_uid'] or parser.pw_gid!=plan['parser_gid']
            or parser.pw_shell!='/usr/sbin/nologin' or parser.pw_dir!='/nonexistent'
            or set(os.getgrouplist(PARSER,parser.pw_gid))!={parser.pw_gid}):
        raise InstallError('Existing parser account changed; no correction')
    return parser


def idle_state(*, preserved_expired_approval=None, preserved_expired_approvals=None):
    """Root-owned administrative state only; never inspect a source device."""
    for directory in (STATE,STATE/'approved',STATE/'used'):
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
            raise InstallError('Existing broker state not private/root-owned')
    outstanding=list((STATE/'approved').iterdir())
    if preserved_expired_approval is not None and preserved_expired_approvals is not None:
        raise InstallError('Ambiguous expired-approval declaration')
    preserved=([preserved_expired_approval] if preserved_expired_approval is not None else preserved_expired_approvals)
    declared={}
    if preserved is None:
        if outstanding: raise InstallError('Outstanding approvals; update blocked, not revoked automatically')
    else:
        if not isinstance(preserved,list) or not 1<=len(preserved)<=8:
            raise InstallError('Finite nonempty expired-approval list required')
        declared={item['request']['request_id']:item for item in preserved}
        if len(declared)!=len(preserved) or {path.name for path in outstanding}!={nonce+'.json' for nonce in declared}:
            raise InstallError('Preserved expired approval baseline changed or unexpected grants present')
    for old_nonce,item in declared.items():
        expected=item['request']; name=old_nonce+'.json'; path=STATE/'approved'/name
        info=path.lstat(); used=STATE/'used'/name
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o077
                or info.st_nlink!=1 or used.exists() or used.is_symlink()):
            raise InstallError('Preserved expired grant must be private, regular and never consumed')
        grant=json.loads(read_regular(path,cap=65536,noatime=True))
        approved_at=grant.get('approved_at'); expires_at=grant.get('expires_at')
        if (grant.get('request')!=expected or grant.get('request_sha256')!=sha(canonical(expected))
                or type(grant.get('approved_uid')) is not int or grant['approved_uid']!=expected['uid']
                or type(grant.get('administrator_uid')) is not int or grant['administrator_uid']!=0
                or type(approved_at) not in (int,float) or type(expires_at) not in (int,float)
                or not 0<expires_at-approved_at<=301 or expires_at!=item['expires_at']
                or time.time()<expires_at):
            raise InstallError('Preserved approval is not the exact already-expired unused grant')
        # Preserve bytes/path/expiry/nonce. The broker still rejects this grant
        # before consume or source IO; it is never a completed-prefix member.
    ledger_path=STATE/'audit.jsonl'; info=ledger_path.lstat()
    if info.st_uid!=0 or info.st_mode & 0o077: raise InstallError('Ledger not private/root-owned')
    ledger=read_regular(ledger_path)
    previous='0'*64; active=set(); old_events={nonce:[] for nonce in declared}
    for line in ledger.splitlines():
        row=json.loads(line); event=row['event']
        if row['sha256']!=sha(canonical(event)) or event['previous_sha256']!=previous:
            raise InstallError('Broker ledger invalid; no repair')
        previous=row['sha256']
        if event.get('request_id') in old_events: old_events[event['request_id']].append(event)
        if event['action']=='authorization_consumed': active.add(event['request_id'])
        if event['action'] in ('physical_read_finished','physical_read_failed'): active.discard(event['request_id'])
    if active: raise InstallError('In-flight or unresolved physical request; update blocked')
    for old_nonce,item in declared.items():
        approved=[event for event in old_events[old_nonce] if event['action']=='approved']
        if (len(approved)!=1 or approved[0].get('request_sha256')!=sha(canonical(item['request']))
                or approved[0].get('uid')!=item['request']['uid']
                or any(event['action']!='approved' for event in old_events[old_nonce])):
            raise InstallError('Root ledger must prove the preserved grant was approved once and never consumed')
    used={}
    for path in (STATE/'used').iterdir():
        if not re.fullmatch('[0-9a-f]{32}\\.json',path.name): raise InstallError('Unexpected nonce state file')
        info=path.lstat()
        if info.st_uid!=0 or info.st_mode & 0o077: raise InstallError('Used nonce not private/root-owned')
        used[path.name]=sha(read_regular(path,cap=65536))
    return ledger,used


def _approval_session_idle(auth, audit):
    preserved=_preserved_approvals(auth)
    if not preserved: return idle_state()
    ledger,used=idle_state(preserved_expired_approvals=preserved)
    for item in preserved:
        path=STATE/'approved'/(item['request']['request_id']+'.json')
        audit.event('exact_expired_approval_preserved_without_renewal',request_id=item['request']['request_id'],
                    request_sha256=sha(canonical(item['request'])),grant_sha256=sha(read_regular(path,cap=65536,noatime=True)),
                    failed_execution_id=item['failed_execution_id'],expiry=item['expires_at'],
                    grant_changed=False,nonce_consumed=False,source_opened=False)
    return ledger,used


def _update_idle(plan):
    """Default remains strict. Opt-in additionally snapshots immutable grants.

    idle_state validates the COMPLETE outstanding set, expiry and ledger first.
    All grant reads use O_NOATIME without fallback. Identity/time snapshots are
    compared across stop/start; same bytes in a replaced inode are not enough.
    """
    if 'preserved_expired_approvals' not in plan:
        ledger,used=idle_state()
        return ledger,used,{}
    items=plan['preserved_expired_approvals']
    validate_update_preservation(items,plan['operator_uid'])
    ledger,used=idle_state(preserved_expired_approvals=items)
    snapshot={}
    def facts(info):
        return {'identity':list(identity(info)),'atime_ns':info.st_atime_ns,
                'mode':info.st_mode,'uid':info.st_uid,'gid':info.st_gid}
    for item in items:
        nonce=item['request']['request_id']; path=STATE/'approved'/(nonce+'.json')
        before=path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_gid!=0 or
                before.st_mode & 0o6077 or before.st_nlink!=1):
            raise InstallError('Preserved update grant is not private plain root-owned data')
        raw=read_regular(path,cap=65536,noatime=True)
        after=path.lstat()
        if sha(raw)!=item['grant_sha256'] or facts(before)!=facts(after):
            raise InstallError('Preserved grant bytes, identity or timestamps changed; no update')
        snapshot[nonce]={**facts(after),'sha256':sha(raw)}
    return ledger,used,snapshot


def require_completed_sequence_requests(requests, ledger, used):
    """Root audit + used nonces, never a client assertion that a read completed."""
    worker_status={}; finished=set(); previous='0'*64
    for line in ledger.splitlines():
        row=json.loads(line); event=row['event']
        if row['sha256']!=sha(canonical(event)) or event['previous_sha256']!=previous:
            raise InstallError('Root read ledger chain changed')
        previous=row['sha256']; nonce=event.get('request_id')
        if event['action']=='worker_finished': worker_status[nonce]=event.get('worker_status')
        if event['action']=='physical_read_finished' and worker_status.get(nonce)=='ok': finished.add(nonce)
        if event['action']=='physical_read_failed': finished.discard(nonce)
    for request in requests:
        name=request['request_id']+'.json'
        if request['request_id'] not in finished or name not in used:
            raise InstallError('Previous sequence request is not successfully closed in root audit')
        data=read_regular(trusted(STATE/'used'/name),cap=65536)
        if sha(data)!=used[name]: raise InstallError('Used nonce changed during approval')
        grant=json.loads(data)
        if grant.get('request')!=request or grant.get('request_sha256')!=sha(canonical(request)) or grant.get('approved_uid')!=request['uid']:
            raise InstallError('Previous used nonce is not the exact approved request')


def serve_approval_session(plan, review, approved_sha256, audit, *, input_fd=0, output_fd=1):
    """Captured root-owned approval courier; no source IO or installed-code edits."""
    auth=plan['sequence_authorization']; batches=validate_sequence_authorization(auth,plan['operator_uid'])
    approved=[]; next_ordinal=auth['first_batch_ordinal']; deadline=time.monotonic()+auth['max_session_seconds']
    try:
        verify_dependencies(plan,worker=review/'ntfs_worker'); host_prechecks(); existing_update_baseline(plan)
        broker_path=trusted(CODE/'ntfs_broker.py')
        spec=importlib.util.spec_from_file_location('ri_approval_courier_broker',broker_path)
        broker=importlib.util.module_from_spec(spec); spec.loader.exec_module(broker)
        core,physical,_=broker.load_core()
        # Validate the entire embedded immutable scope before creating any grant.
        for batch in batches:
            for request in batch['requests']:
                core.validate_request(request); physical.validate_pin(request['source']['pin'])
        for item in _preserved_approvals(auth):
            old=item['request']
            core.validate_request(old); physical.validate_pin(old['source']['pin'])
        prefix=[r for b in batches[:next_ordinal-1] for r in b['requests']]
        ledger,used=_approval_session_idle(auth,audit); require_completed_sequence_requests(prefix,ledger,used)
        for batch in batches[next_ordinal-1:]:
            for request in batch['requests']:
                name=request['request_id']+'.json'
                if name in used or (STATE/'approved'/name).exists():
                    raise InstallError('Remaining request already consumed or approved; no renewal/replay')
        audit.event('approval_session_ready',plan_sha256=approved_sha256,sequence_sha256=auth['sequence_sha256'],
                    first_batch_ordinal=next_ordinal,max_session_seconds=auth['max_session_seconds'],
                    approval_profile=auth.get('approval_profile','metadata_v1'),
                    physical_device_reads=False,installed_code_changed=False)
        _session_send(output_fd,{'status':'approval_session_ready','plan_sha256':approved_sha256,
            'sequence_sha256':auth['sequence_sha256'],'next_batch_ordinal':next_ordinal,
            'max_session_seconds':auth['max_session_seconds'],'operator_uid':plan['operator_uid']})
        while True:
            command=_session_receive(input_fd,deadline,maximum=1024)
            if command=={'action':'finish'}:
                if next_ordinal!=len(batches)+1: raise InstallError('Cannot finish before all exact batches')
                ledger,used=_approval_session_idle(auth,audit)
                require_completed_sequence_requests([r for b in batches for r in b['requests']],ledger,used)
                receipt={'status':'sequence_session_completed','plan_sha256':approved_sha256,
                    'sequence_sha256':auth['sequence_sha256'],'approved_batch_ordinals':approved,
                    'physical_device_reads':False,'installed_code_changed':False,
                    'audit_head_before_receipt':audit.previous}
                write_new(review/'receipt.json',canonical(receipt)); audit.event('approval_session_completed',receipt_sha256=sha(canonical(receipt)))
                _session_send(output_fd,receipt)
                return None
            if (set(command)!={'action','ordinal'} or command['action']!='approve-next'
                    or type(command['ordinal']) is not int or command['ordinal']!=next_ordinal
                    or next_ordinal>len(batches)):
                raise InstallError('Only the next exact batch or final finish is permitted')
            # A normal five-minute grant must expire inside the four-hour session.
            if time.monotonic()+301>=deadline: raise InstallError('Insufficient session lifetime for a fresh five-minute batch')
            verify_dependencies(plan,worker=review/'ntfs_worker'); existing_update_baseline(plan)
            ledger,used=_approval_session_idle(auth,audit)
            require_completed_sequence_requests([r for b in batches[:next_ordinal-1] for r in b['requests']],ledger,used)
            if time.monotonic()+301>=deadline: raise InstallError('Session lifetime exhausted during verification')
            batch=batches[next_ordinal-1]
            # Prevalidate every nonce before invoking legacy per-request approvals.
            for request in batch['requests']:
                name=request['request_id']+'.json'
                if name in used or (STATE/'approved'/name).exists(): raise InstallError('No expired grant renewal or consumed-nonce replay')
            audit.event('exact_batch_approval_intent',ordinal=next_ordinal,batch_sha256=batch['batch_sha256'])
            grants=[broker.approve_request(core,physical,request,sha(canonical(request)),plan['operator_uid'],
                auth['reason']+' [sequence '+auth['sequence_sha256']+' batch '+str(next_ordinal)+']',
                custody_attestation=auth['custody_attestation']) for request in batch['requests']]
            approved.append(next_ordinal)
            audit.event('exact_batch_approved',ordinal=next_ordinal,batch_sha256=batch['batch_sha256'],grant_count=len(grants))
            _session_send(output_fd,{'status':'batch_approved','ordinal':next_ordinal,
                'batch_sha256':batch['batch_sha256'],'grants':grants})
            next_ordinal+=1
    except Exception as exc:
        audit.event('approval_session_stopped_no_retry',error_type=type(exc).__name__,reason=str(exc),
                    approved_batch_ordinals=approved,unused_grants_not_revoked_or_renewed=True)
        receipt={'status':'sequence_session_stopped','plan_sha256':approved_sha256,
                 'sequence_sha256':auth['sequence_sha256'],'approved_batch_ordinals':approved,
                 'error_type':type(exc).__name__,'reason':str(exc),'physical_device_reads':False,
                 'installed_code_changed':False,'automatic_retry':False}
        write_new(review/'receipt.json',canonical(receipt))
        try: _session_send(output_fd,receipt)
        except (OSError,InstallError): pass
        return None


def apply_update(plan,payloads,review,approved_sha256,audit):
    started=False
    try:
        audit.event('code_update_started',plan_sha256=approved_sha256,physical_read_authorized=False)
        verify_dependencies(plan,worker=review/'ntfs_worker'); host_prechecks()
        parser=existing_update_baseline(plan)
        ledger_before,used_before,expired_before=_update_idle(plan)
        audit.event('idle_baseline_verified',ledger_sha256=sha(ledger_before),used_snapshot_sha256=sha(canonical(used_before)))
        if expired_before:
            audit.event('update_exact_expired_grants_verified',snapshot_sha256=sha(canonical(expired_before)),
                        count=len(expired_before),grant_changed=False,nonce_consumed=False,source_opened=False)
        audit.command(['/usr/bin/systemctl','is-active','--quiet',UNIT])
        audit.command(['/usr/bin/systemctl','stop',UNIT])
        # Stop is synchronous and KillMode=control-group; no code replacement while serving.
        existing_update_baseline(plan)
        ledger_stopped,used_stopped,expired_stopped=_update_idle(plan)
        if ledger_stopped!=ledger_before or used_stopped!=used_before or expired_stopped!=expired_before:
            raise InstallError('Broker state changed during stop; no replacement')
        backup=review/'previous'; root_directory(backup,0o700)
        for name in FILES[:-1]:
            write_new(backup/name,read_regular(trusted(CODE/name)),0o600)
        write_new(backup/'unit.service',read_regular(trusted(UNIT_PATH)),0o600)
        for name in FILES[:-1]:
            if plan['payloads'][name]==plan['installed_before'][name]: continue
            temporary=CODE/(name+'.update-'+approved_sha256[:16])
            audit.event('code_replace_intent',path=str(CODE/name),before=plan['installed_before'][name],after=plan['payloads'][name])
            write_new(temporary,payloads[name],0o755 if name=='ntfs_worker' else 0o644)
            if sha(read_regular(trusted(CODE/name)))!=plan['installed_before'][name]: raise InstallError('Baseline changed before replacement')
            os.replace(temporary,CODE/name)
            fd=os.open(CODE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: os.fsync(fd)
            finally: os.close(fd)
        for name in FILES[:-1]:
            if sha(read_regular(trusted(CODE/name)))!=plan['payloads'][name]: raise InstallError('Updated code hash mismatch')
        verify_dependencies(plan,worker=review/'ntfs_worker')
        if expired_before:
            if _update_idle(plan)!=(ledger_stopped,used_stopped,expired_stopped):
                raise InstallError('Broker state changed before restart; service remains stopped')
        audit.command(['/usr/bin/systemctl','start',UNIT]); started=True
        audit.command(['/usr/bin/systemctl','is-active','--quiet',UNIT])
        for _ in range(50):
            if (RUNTIME/'broker.sock').exists(): break
            time.sleep(0.1)
        info=(RUNTIME/'broker.sock').lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_gid!=plan['operator_gid'] or stat.S_IMODE(info.st_mode)!=0o660:
            raise InstallError('Updated socket permissions mismatch')
        smoke(plan,parser)
        ledger_after,used_after,expired_after=_update_idle(plan)
        if not ledger_after.startswith(ledger_before) or used_after!=used_before or expired_after!=expired_before:
            raise InstallError('Nonce/ledger history not preserved')
        verify_dependencies(plan,worker=review/'ntfs_worker')
        receipt={'status':'updated_and_smoke_checked','plan_sha256':approved_sha256,'parser_uid':parser.pw_uid,
                 'operator_uid':plan['operator_uid'],'physical_device_reads':False,'read_grants_created':0,
                 'service':UNIT,'nonce_history_preserved':True,'ledger_preserved_append_only':True,
                  'audit_head_before_receipt':audit.previous}
        if expired_before:
            receipt.update(expired_approvals_preserved=len(expired_before),
                           expired_approval_snapshot_sha256=sha(canonical(expired_before)))
        write_new(review/'receipt.json',canonical(receipt)); audit.event('code_update_completed',receipt_sha256=sha(canonical(receipt)))
        return receipt
    except Exception as exc:
        audit.event('code_update_failed_no_repair_or_rollback',error_type=type(exc).__name__,reason=str(exc))
        if started:
            try:
                verify_dependencies(plan,worker=review/'ntfs_worker'); audit.command(['/usr/bin/systemctl','stop',UNIT])
            except Exception as stop_error: audit.event('containment_unconfirmed',error_type=type(stop_error).__name__)
        raise


def apply(plan_path, approved_sha256):
    # No root execution of a path in the mutable checkout, even with an apply flag.
    if os.getuid() != 0 or os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site:
        raise InstallError('Apply requires isolated root-owned captured deployment')
    self_path = trusted(Path(__file__).absolute())
    review = self_path.parent
    if review.parent != REVIEWS or review.name != approved_sha256:
        raise InstallError('Installer must execute from the fixed root-owned review directory')
    if Path(plan_path) != review / 'plan.json':
        raise InstallError('Captured plan only')
    data = read_regular(plan_path)
    if sha(data) != approved_sha256:
        raise InstallError('Plan differs from explicit approval')
    plan = json.loads(data); validate_plan(plan)
    payloads = {}
    for name, expected in plan['payloads'].items():
        path = trusted(review / name)
        payloads[name] = read_regular(path)
        if sha(payloads[name]) != expected:
            raise InstallError('Approved payload changed: ' + name)
    audit = Audit(review)
    if plan['operation']=='sequence_approval_session_only':
        try: return serve_approval_session(plan,review,approved_sha256,audit)
        finally: os.close(audit.fd)
    if plan['operation']=='update_broker_code_only':
        try: return apply_update(plan,payloads,review,approved_sha256,audit)
        finally: os.close(audit.fd)
    started = False
    try:
        audit.event('installation_started', plan_sha256=approved_sha256, physical_read_authorized=False)
        verify_dependencies(plan, worker=review / 'ntfs_worker')
        check_absent()
        host_prechecks()
        audit.event('all_readonly_prechecks_passed')
        audit.command(['/usr/sbin/useradd', '--system', '--user-group', '--no-create-home',
                       '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', '--password', '!', PARSER])
        parser = pwd.getpwnam(PARSER)
        groups = os.getgrouplist(PARSER, parser.pw_gid)
        if (parser.pw_uid <= 0 or parser.pw_uid == plan['operator_uid'] or parser.pw_gid <= 0
                or parser.pw_shell != '/usr/sbin/nologin' or parser.pw_dir != '/nonexistent'
                or set(groups) != {parser.pw_gid}):
            raise InstallError('Created parser account is not restricted as approved')
        root_directory(CODE, 0o755)
        for name in FILES[:-1]:
            audit.event('file_install_intent', path=str(CODE / name), sha256=plan['payloads'][name])
            write_new(CODE / name, payloads[name], 0o755 if name == 'ntfs_worker' else 0o644)
        audit.event('four_broker_files_installed')
        root_directory(STATE, 0o700)
        root_directory(STATE / 'approved', 0o700)
        root_directory(STATE / 'used', 0o700)
        write_new(UNIT_PATH, unit_bytes(plan['operator_gid']), 0o644)
        audit.event('unit_installed_without_boot_enablement', unit_sha256=plan['unit_sha256'])
        verify_dependencies(plan, worker=review / 'ntfs_worker')
        for name in FILES[:-1]:
            if sha(read_regular(trusted(CODE / name))) != plan['payloads'][name]:
                raise InstallError('Installed file differs from approved payload')
        audit.command(['/usr/bin/systemctl', 'daemon-reload'])
        audit.command(['/usr/bin/systemctl', 'start', UNIT])
        started = True
        audit.command(['/usr/bin/systemctl', 'is-active', '--quiet', UNIT])
        # systemctl Type=simple doesn't imply socket readiness; bounded readiness check.
        for _ in range(50):
            if (RUNTIME / 'broker.sock').exists(): break
            time.sleep(0.1)
        info = (RUNTIME / 'broker.sock').lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != plan['operator_gid']
                or stat.S_IMODE(info.st_mode) != 0o660):
            raise InstallError('Socket not root-owned/operator-group 0660')
        smoke(plan, parser)
        if list((STATE / 'approved').iterdir()) or list((STATE / 'used').iterdir()):
            raise InstallError('Unexpected read grants during installation')
        verify_dependencies(plan, worker=review / 'ntfs_worker')
        receipt = {'status': 'installed_and_smoke_checked', 'plan_sha256': approved_sha256,
                   'operator_uid': plan['operator_uid'], 'parser_uid': parser.pw_uid,
                   'physical_device_reads': False, 'read_grants_created': 0, 'service': UNIT,
                   'audit_head_before_receipt': audit.previous}
        write_new(review / 'receipt.json', canonical(receipt))
        audit.event('installation_completed', receipt_sha256=sha(canonical(receipt)))
        return receipt
    except Exception as exc:
        audit.event('installation_failed_no_repair', error_type=type(exc).__name__, reason=str(exc))
        if started:
            # Containment only: stop THIS newly started unit, never repair/retry/install.
            try:
                verify_dependencies(plan, worker=review / 'ntfs_worker')
                audit.command(['/usr/bin/systemctl', 'stop', UNIT])
            except Exception as stop_error:
                audit.event('containment_unconfirmed', error_type=type(stop_error).__name__)
        raise
    finally:
        os.close(audit.fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--prepare', metavar='PROJECT')
    action.add_argument('--prepare-update',metavar='PROJECT')
    action.add_argument('--prepare-approval-session',metavar='PROJECT')
    action.add_argument('--apply', metavar='CAPTURED_PLAN')
    action.add_argument('--launch', metavar='APPROVED_PLAN')
    parser.add_argument('--approved-plan-sha256')
    parser.add_argument('--sequence-json')
    parser.add_argument('--sequence-sha256')
    parser.add_argument('--first-batch',type=int)
    parser.add_argument('--custody-attestation')
    parser.add_argument('--reason')
    parser.add_argument('--session-seconds',type=int,default=14400)
    parser.add_argument('--preserve-expired-approvals-json')
    parser.add_argument('--preserve-expired-approvals-sha256')
    args = parser.parse_args()
    preserved=None
    if args.preserve_expired_approvals_json is not None or args.preserve_expired_approvals_sha256 is not None:
        if (not args.prepare_update or not args.preserve_expired_approvals_json or
                not re.fullmatch('[0-9a-f]{64}',args.preserve_expired_approvals_sha256 or '')):
            raise InstallError('Update-only preservation requires an explicit JSON path and exact byte hash')
        raw=read_regular(args.preserve_expired_approvals_json,cap=512*1024,noatime=True)
        if sha(raw)!=args.preserve_expired_approvals_sha256: raise InstallError('Expired-grant declaration hash mismatch')
        try: preserved=json.loads(raw)
        except (ValueError,UnicodeError) as exc: raise InstallError('Invalid expired-grant declaration JSON') from exc
        validate_update_preservation(preserved,os.getuid())
    if args.prepare_approval_session:
        if not args.sequence_json or not args.sequence_sha256 or args.first_batch is None:
            raise InstallError('Exact sequence path/hash and first unexecuted batch required')
        fd=os.open(args.sequence_json,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            before=os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>6*1024*1024:
                raise InstallError('Bounded regular sequence JSON required')
            with os.fdopen(fd,'rb',closefd=False) as stream: raw=stream.read(6*1024*1024+1)
            if len(raw)!=before.st_size or identity(before)!=identity(os.fstat(fd)):
                raise InstallError('Sequence changed during preparation')
        finally: os.close(fd)
        if sha(raw)!=args.sequence_sha256: raise InstallError('Exact sequence byte hash mismatch')
        auth={'sequence':json.loads(raw),'sequence_sha256':args.sequence_sha256,'first_batch_ordinal':args.first_batch,
              'custody_attestation':args.custody_attestation,'reason':args.reason,'max_session_seconds':args.session_seconds}
        result=prepare(args.prepare_approval_session,sequence_authorization=auth)
    elif args.prepare or args.prepare_update:
        result = prepare(args.prepare or args.prepare_update,update=bool(args.prepare_update),preserved_expired_approvals=preserved)
    else:
        if not re.fullmatch('[0-9a-f]{64}', args.approved_plan_sha256 or ''):
            raise InstallError('Exact explicit approval hash required')
        result = launch(args.launch, args.approved_plan_sha256) if args.launch else apply(args.apply, args.approved_plan_sha256)
    if result is not None: print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (InstallError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'blocked_no_retry', 'reason': str(exc)}), file=sys.stderr)
        raise SystemExit(2)
