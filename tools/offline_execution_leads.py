"""Pure metadata correlations, never executable attribution or evidence IO."""
from __future__ import annotations

import re

BINARY_SUFFIXES = ('.exe', '.dll', '.sys', '.scr', '.com')
SCRIPT_SUFFIXES = ('.ps1', '.psm1', '.vbs', '.vbe', '.bat', '.cmd', '.jse', '.hta', '.wsf')
PREFETCH_NAME = re.compile(r'^(.+\.(?:exe|com|scr))-[0-9a-f]{8,16}\.pf$')
REMOTE_NAMES = ('anydesk', 'teamviewer', 'screenconnect', 'rustdesk')
DUAL_USE_NAMES = frozenset(('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'wmic.exe', 'vssadmin.exe', 'bcdedit.exe', 'wbadmin.exe',
    'rundll32.exe', 'regsvr32.exe', 'schtasks.exe', 'certutil.exe'))


def normalized_names(names):
    if not isinstance(names, list):
        raise ValueError('Metadata names must be a list')
    result = set()
    for value in names:
        if not isinstance(value, str) or not 1 <= len(value) <= 4096:
            raise ValueError('Malformed bounded metadata name')
        value = value.casefold()
        result.add(value.removesuffix('.sealed'))
    return result


def prefetch_executable_names(names):
    return {match[1] for name in normalized_names(names) if (match := PREFETCH_NAME.fullmatch(name))}


def classify_lead(record, paths, prefetch_names, start, end):
    """Return flags only; filenames and paths never become commands or paths to open."""
    if type(start) is not int or type(end) is not int or end < start:
        raise ValueError('Explicit finite metadata time window required')
    if not isinstance(paths, list) or any(not isinstance(p, str) or len(p) > 32768 for p in paths):
        raise ValueError('Malformed bounded metadata path')
    names = normalized_names([n['name'] for n in record['names']])
    kind = 'binary_name_candidate' if any(n.endswith(BINARY_SUFFIXES) for n in names) else (
        'script_name_candidate' if any(n.endswith(SCRIPT_SUFFIXES) for n in names) else None)
    if record.get('allocated') is not True or record.get('directory') is not False or kind is None:
        return None
    times = record.get('times_unix', {})
    in_window = {key: type(times.get(key)) is int and start <= times[key] <= end
                 for key in ('created', 'modified', 'changed')}
    writable_name = any(any(token in p.casefold().replace('\\', '/') for token in
        ('/temp/', '/downloads/', '/desktop/', '/appdata/', '/startup/')) for p in paths)
    pf_match = bool(names & prefetch_names)
    remote = any(any(token in n for token in REMOTE_NAMES) for n in names)
    temporal = in_window['created'] or in_window['modified']
    reasons = []
    if writable_name and temporal:
        reasons.append('potentially_writable_path_and_metadata_time_window')
    if pf_match and temporal:
        reasons.append('prefetch_basename_match_and_metadata_time_window')
    if remote and pf_match:
        reasons.append('remote_tool_name_and_prefetch_basename_match')
    return {'candidate_kind': kind, 'prioritize_for_review': bool(reasons), 'priority_reasons': reasons,
        'created_in_metadata_window': in_window['created'], 'modified_in_metadata_window': in_window['modified'],
        'changed_in_metadata_window': in_window['changed'], 'potentially_writable_path_name': writable_name,
        'path_available_from_saved_MFT': bool(paths), 'prefetch_basename_match': pf_match,
        'remote_tool_name_candidate': remote, 'dual_use_Windows_utility_name': bool(names & DUAL_USE_NAMES),
        'execution_established': False, 'malware_established': False, 'incident_trigger_established': False}
