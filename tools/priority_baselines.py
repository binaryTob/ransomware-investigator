"""Pure baseline checks for operational coordinators, never device access.

The caller verifies saved page hashes/provenance before passing raw records.
A filtered candidate report is not an exhaustive record baseline.
"""
import copy

from ransomware_investigator.safety import RIError


def index_record_baselines(required_inodes, raw_records):
    required = set()
    for inode in required_inodes:
        if type(inode) is not int or not 0 <= inode < 2**63:
            raise RIError('Invalid required MFT baseline inode.')
        required.add(inode)
    baselines = {}
    fields = {'inode', 'kind', 'sequence', 'allocated', 'directory', 'size_bytes', 'names', 'times_unix'}
    for record in raw_records:
        if not isinstance(record, dict) or type(record.get('inode')) is not int:
            raise RIError('Baseline requires raw MFT records, not a candidate subset.')
        inode = record['inode']
        if inode not in required:
            continue
        if not fields <= record.keys() or record['kind'] != 'record':
            raise RIError('Incomplete raw MFT baseline record.')
        if inode in baselines:
            raise RIError('Ambiguous duplicate raw MFT baseline.')
        baselines[inode] = copy.deepcopy(record)
    if set(baselines) != required:
        raise RIError('Requested MFT baseline is incomplete; stop before authentication.')
    return baselines


def require_matching_record(record, baselines):
    if not isinstance(record, dict) or type(record.get('inode')) is not int:
        raise RIError('Invalid observed MFT record.')
    previous = baselines.get(record['inode'])
    if previous is None:
        raise RIError('Observed MFT record has no verified baseline; stop without replay.')
    if record != previous:
        raise RIError('Observed MFT record differs from the complete saved baseline.')
