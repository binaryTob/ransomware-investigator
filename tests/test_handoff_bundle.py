import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from tools.handoff_bundle import MAX_SQLITE_BACKUP, Source, registered_files, relative, verify_bundle, write_bundle


class HandoffBundleTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[1] / '.test-tmp'
        base.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=base)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'synthetic.dat'
        self.source.write_bytes(b'<script>synthetic, never executed</script>')
        self.expected = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def entry(self, **changes):
        args = {'root': self.root, 'relative_path': self.source.name, 'archive_path': 'datos/synthetic.dat',
                'sha256': self.expected, 'size_bytes': self.source.stat().st_size, 'scope': 'synthetic_fixture'}
        return Source(**{**args, **changes})

    def test_exact_source_hash_all_entries_and_timestamps_preserved(self):
        before = self.source.stat()
        result = write_bundle(self.root / 'handoff.zip', [self.entry()], [('LEEME.txt', b'SYNTHETIC', {})], context={'source_revision': 7})
        after = self.source.stat()
        self.assertTrue(result['valid'])
        self.assertEqual(result['files_verified'], 2)
        for key in ('st_ino', 'st_mode', 'st_mtime_ns', 'st_ctime_ns', 'st_atime_ns'):
            self.assertEqual(getattr(before, key), getattr(after, key))
        self.assertTrue(verify_bundle(self.root / 'handoff.zip')['valid'])

    def test_mismatch_preserves_partial_without_final_or_retry(self):
        with self.assertRaises(ValueError):
            write_bundle(self.root / 'bad.zip', [self.entry(sha256='0'*64)], [], context={})
        self.assertFalse((self.root / 'bad.zip').exists())
        self.assertEqual(len(list(self.root.glob('bad.zip.partial-*'))), 1)

    def test_existing_output_never_overwritten(self):
        out = self.root / 'existing.zip'; out.write_bytes(b'USER WORK')
        with self.assertRaises(ValueError):
            write_bundle(out, [self.entry()], [], context={})
        self.assertEqual(out.read_bytes(), b'USER WORK')

    def test_traversals_absolute_windows_and_duplicate_paths_rejected(self):
        for path in ('../outside', '/dev/never-opened', 'a/../b', 'a//b', 'C:/file', 'a\\b', './file', ''):
            with self.assertRaises(ValueError):
                relative(path)
        with self.assertRaises(ValueError):
            write_bundle(self.root / 'duplicate.zip', [self.entry(), self.entry(archive_path='DATOS/SYNTHETIC.DAT')], [], context={})
        with self.assertRaises(ValueError):
            write_bundle(self.root / 'reserved.zip', [], [('MANIFEST.json', b'{}', {})], context={})

    def test_symlinks_and_hardlinks_are_rejected(self):
        link = self.root / 'link'; link.symlink_to(self.source)
        with self.assertRaises(OSError):
            write_bundle(self.root / 'link.zip', [self.entry(relative_path='link')], [], context={})
        link.unlink(); os.link(self.source, link)
        with self.assertRaises(ValueError):
            write_bundle(self.root / 'hardlink.zip', [self.entry()], [], context={})

    def test_directory_symlinks_and_source_size_mismatch_rejected(self):
        (self.root / 'linked').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            write_bundle(self.root / 'dirlink.zip', [self.entry(relative_path='linked/synthetic.dat')], [], context={})
        with self.assertRaises(ValueError):
            write_bundle(self.root / 'size.zip', [self.entry(size_bytes=1)], [], context={})

    def test_noatime_failure_has_no_weaker_open(self):
        original = os.open
        evidence_opens = []
        def opened(path, flags, *args, **kwargs):
            if str(path) == 'synthetic.dat':
                evidence_opens.append(flags)
                if flags & os.O_NOATIME:
                    raise PermissionError('synthetic denial')
            return original(path, flags, *args, **kwargs)
        with mock.patch('tools.handoff_bundle.os.open', side_effect=opened):
            with self.assertRaises(PermissionError):
                write_bundle(self.root / 'noatime.zip', [self.entry()], [], context={})
        self.assertEqual(len(evidence_opens), 1)
        self.assertTrue(evidence_opens[0] & os.O_NOATIME)

    def test_manifest_and_entry_tampering_detected_without_extraction(self):
        good = self.root / 'good.zip'
        write_bundle(good, [self.entry()], [], context={})
        with zipfile.ZipFile(good) as original:
            manifest = original.read('MANIFEST.json')
        bad = self.root / 'changed.zip'
        with zipfile.ZipFile(bad, 'w') as archive:
            archive.writestr('datos/synthetic.dat', b'X' * self.source.stat().st_size)
            archive.writestr('MANIFEST.json', manifest)
        with self.assertRaises(ValueError):
            verify_bundle(bad)

    def test_unexpected_entries_and_zip_traversals_are_rejected(self):
        for name in ('../escape', 'unexpected.dat'):
            bad = self.root / ('traversal.zip' if name.startswith('..') else 'extra.zip')
            with zipfile.ZipFile(bad, 'w') as archive:
                archive.writestr(name, b'SYNTHETIC')
                archive.writestr('MANIFEST.json', json.dumps({'format': 'ri-handoff-zip-v1', 'context': {}, 'files': []}))
            with self.assertRaises(ValueError):
                verify_bundle(bad)

    def test_root_and_unbounded_sources_fail_before_read(self):
        with mock.patch('tools.handoff_bundle.os.geteuid', return_value=0):
            with self.assertRaises(ValueError):
                write_bundle(self.root / 'root.zip', [], [], context={})
        for size in (True, -1, 129 * 1024**2):
            with self.assertRaises(ValueError):
                write_bundle(self.root / 'size-budget.zip', [self.entry(size_bytes=size)], [], context={})

    def test_metadata_source_pin_paths_are_never_export_candidates(self):
        docs = [{'id': 'synthetic', 'pin': {'path': '/dev/never-opened'}, 'path': '/dev/never-opened'}]
        self.assertEqual(registered_files(docs), {})

    def test_large_backup_budget_requires_explicit_role_and_destination(self):
        with self.assertRaises(ValueError):
            write_bundle(self.root / 'bad-role.zip', [self.entry(max_file_bytes=MAX_SQLITE_BACKUP)], [], context={})
        entry = self.entry(archive_path='datos/auditoria.sqlite3', scope='logical_sqlite_backup', max_file_bytes=MAX_SQLITE_BACKUP)
        result = write_bundle(self.root / 'explicit-backup.zip', [entry], [], context={})
        self.assertTrue(result['valid'])

    def test_registered_aliases_deduplicate_but_conflicting_hashes_fail(self):
        one = {'id': 'one', 'relative_path': 'extracted/synthetic', 'content_sha256': '1'*64, 'size_bytes': 4}
        two = {**one, 'id': 'two'}
        result = registered_files([one, two])
        self.assertEqual(result['extracted/synthetic']['evidence_ids'], ['one', 'two'])
        with self.assertRaises(ValueError):
            registered_files([one, {**two, 'content_sha256': '2'*64}])

    def test_unhashed_or_outside_registered_outputs_fail_closed(self):
        for doc in ({'id': 'x', 'relative_path': '/dev/never-opened', 'content_sha256': '1'*64},
                {'id': 'x', 'relative_path': 'other/synthetic', 'content_sha256': '1'*64},
                {'id': 'x', 'relative_path': 'scans/synthetic'},
                {'id': 'x', 'relative_path': 'scans/synthetic', 'content_sha256': '1'*64, 'size_bytes': True}):
            with self.assertRaises(ValueError):
                registered_files([doc])
