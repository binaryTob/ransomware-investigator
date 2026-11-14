import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.common import ProjectTest
from ransomware_investigator.exchange import _read
from ransomware_investigator.safety import RIError


class ExchangeReadRaceTests(ProjectTest):
    def pointer(self):
        directory = self.work / 'exchange'
        directory.mkdir(mode=0o700)
        path = directory / 'manifest.json'
        path.write_bytes(b'{"synthetic":true}')
        path.chmod(0o600)
        return path

    def test_stale_unlinked_path_stat_is_not_used_instead_of_descriptor(self):
        path = self.pointer()
        info = path.stat()
        stale = SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid, st_nlink=0)
        with patch.object(Path, 'lstat', return_value=stale):
            self.assertEqual(_read(path, replaceable_pointer=True), b'{"synthetic":true}')

    def test_unlinked_open_pointer_remains_readable(self):
        path = self.pointer()
        replacement = path.with_name('next.json')
        replacement.write_bytes(b'{"synthetic":"next"}')
        replacement.chmod(0o600)
        original_open = os.open

        def replace_after_open(value, flags, *args, **kwargs):
            fd = original_open(value, flags, *args, **kwargs)
            if Path(value) == path:
                os.replace(replacement, path)
            return fd

        with patch('ransomware_investigator.exchange.os.open', side_effect=replace_after_open):
            self.assertEqual(_read(path, replaceable_pointer=True), b'{"synthetic":true}')

    def test_permissions_are_checked_on_open_descriptor_not_prior_path(self):
        path = self.pointer()
        original_open = os.open

        def change_before_open(value, flags, *args, **kwargs):
            if Path(value) == path:
                path.chmod(0o644)
            return original_open(value, flags, *args, **kwargs)

        with patch('ransomware_investigator.exchange.os.open', side_effect=change_before_open):
            with self.assertRaises(RIError):
                _read(path, replaceable_pointer=True)

    def test_immutable_files_and_hardlinked_pointers_remain_rejected(self):
        path = self.pointer()
        alias = path.with_name('alias.json')
        os.link(path, alias)
        for replaceable in (False, True):
            with self.assertRaises(RIError):
                _read(path, replaceable_pointer=replaceable)
        with self.assertRaises(RIError):
            _read(alias, replaceable_pointer=True)
