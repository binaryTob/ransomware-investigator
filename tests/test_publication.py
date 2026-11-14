import contextlib
import io
import json
import os
from pathlib import Path
import subprocess

from tests.common import ProjectTest
from tools.check_publication import assess, main, read_manifest, scan_text, valid_public_path


class PublicationTests(ProjectTest):
    def repository(self):
        root = self.work / 'publication'
        root.mkdir(mode=0o700)
        (root / 'README.md').write_text('Entirely synthetic project.\n')
        (root / 'PUBLICATION_FILES.txt').write_text('PUBLICATION_FILES.txt\nREADME.md\n')
        return root

    def git(self, root, *args):
        return subprocess.run(['git', '-C', str(root), *args], check=True,
                              capture_output=True, timeout=30)

    def test_reserved_fixtures_are_allowed_not_arbitrary_contacts(self):
        self.assertFalse(scan_text(b'help@example.invalid and 192.0.2.1'))
        self.assertIn('non_example_email', scan_text(('person@' + 'unapproved.tld').encode()))
        self.assertIn('personal_home_path', scan_text(('/home/' + 'fictional-operator').encode()))
        self.assertFalse(scan_text(b'/home/SYNTHETIC/input'))
        self.assertIn('non_documentation_ip', scan_text(('10.1.' + '2.3').encode()))

    def test_secrets_and_binary_content_fail_closed(self):
        self.assertIn('credential_pattern', scan_text(('ghp_' + 'A' * 36).encode()))
        self.assertIn('credential_pattern', scan_text(('-----BEGIN ' + 'PRIVATE KEY-----').encode()))
        self.assertIn('binary_or_nul', scan_text(b'hello\x00'))
        self.assertIn('binary_or_non_utf8', scan_text(b'\xff'))
        self.assertIn('opaque_identifier_requires_review', scan_text(('ab' * 32).encode()))

    def test_private_denylist_is_not_printed(self):
        root = self.repository()
        marker = 'fictional-private-marker'
        (root / 'README.md').write_text(marker)
        private = self.work / 'denylist.json'
        private.write_text(json.dumps([marker]))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(['--root', str(root), '--denylist-file', str(private)]), 1)
        self.assertNotIn(marker, output.getvalue())
        self.assertIn('private_denylist_match', output.getvalue())

    def test_unapproved_paths_traversal_and_unsorted_manifest_are_rejected(self):
        for path in ('../README.md', '/README.md', 'src/../README.md', '.env',
                     'tests/evidence.bin', 'examples/private.json', 'src/.hidden.py'):
            self.assertFalse(valid_public_path(path))
        for data in (b'README.md\nPUBLICATION_FILES.txt\n',
                     b'PUBLICATION_FILES.txt\nPUBLICATION_FILES.txt\n', b'../README.md\n'):
            with self.assertRaises(ValueError):
                read_manifest(data)

    def test_worktree_rejects_unlisted_data_and_symlinks(self):
        root = self.repository()
        self.assertEqual(assess(root)['status'], 'PASS')
        extra = root / 'private.json'; extra.write_text('{}')
        self.assertEqual(assess(root)['status'], 'BLOCKED')
        extra.unlink()
        readme = root / 'README.md'; readme.unlink(); readme.symlink_to(self.work / 'outside')
        self.assertEqual(assess(root)['status'], 'BLOCKED')

    def test_staged_scan_reads_index_not_a_clean_worktree_replacement(self):
        root = self.repository()
        self.git(root, 'init', '--initial-branch=main')
        (root / 'README.md').write_text('ghp_' + 'A' * 36)
        self.git(root, 'add', '--', 'README.md', 'PUBLICATION_FILES.txt')
        (root / 'README.md').write_text('Entirely synthetic project.\n')
        self.assertIn('credential_pattern', assess(root, staged=True)['checks'])

    def test_unreachable_git_objects_are_also_checked(self):
        root = self.repository()
        self.git(root, 'init', '--initial-branch=main')
        self.git(root, 'add', '--', 'README.md', 'PUBLICATION_FILES.txt')
        private = self.work / 'synthetic-secret.txt'
        private.write_text('ghp_' + 'A' * 36)
        self.git(root, 'hash-object', '-w', '--', str(private))
        self.assertIn('credential_pattern', assess(root, staged=True, history=True)['checks'])

    def test_git_author_identity_is_checked(self):
        root = self.repository()
        self.git(root, 'init', '--initial-branch=main')
        self.git(root, 'add', '--', 'README.md', 'PUBLICATION_FILES.txt')
        self.git(root, '-c', 'user.name=Synthetic Test Author', '-c',
                 'user.email=test@example.invalid', '-c', 'commit.gpgsign=false',
                 'commit', '-m', 'Synthetic test commit')
        self.assertIn('non_anonymous_git_identity', assess(root, staged=True, history=True)['checks'])
