import hashlib
from pathlib import Path
from unittest.mock import patch

from tests.common import ProjectTest
from ransomware_investigator.copy_io import read_copy
from ransomware_investigator.safety import Policy, RIError


class CopyIOSecurityTests(ProjectTest):
    def setUp(self):
        super().setUp()
        self.workspace = self.work / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.inputs = self.workspace / "extracted"
        self.inputs.mkdir(mode=0o700)
        self.path = self.inputs / "file.txt"
        self.path.write_bytes(b"synthetic")
        self.sha = hashlib.sha256(b"synthetic").hexdigest()
        self.grant = Policy.copy_grant("a" * 32, "b" * 32, "extracted/file.txt", self.sha, "Synthetic Operator", "test", authorized=True)

    def read(self):
        return read_copy(self.workspace, self.path, self.grant, "a" * 32, self.sha)

    def test_private_inputs_and_workspace_are_required(self):
        for directory in (self.inputs, self.workspace):
            directory.chmod(0o755)
            with self.subTest(directory=directory), self.assertRaises(RIError):
                self.read()
            directory.chmod(0o700)

    def test_missing_noatime_is_a_hard_failure(self):
        import os
        value = os.O_NOATIME
        try:
            del os.O_NOATIME
            with self.assertRaises(RIError):
                self.read()
        finally:
            os.O_NOATIME = value

    def test_changed_owner_and_filesystem_fail_without_read(self):
        import os
        from types import SimpleNamespace
        original = os.fstat
        for field, value in (("st_uid", -1), ("st_dev", -1)):
            def changed(fd):
                info = original(fd)
                if info.st_ino == self.path.stat().st_ino:
                    values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                    values[field] = value
                    return SimpleNamespace(**values)
                return info
            with self.subTest(field=field), patch("os.fstat", changed), patch("os.read", side_effect=AssertionError("No leer")):
                with self.assertRaises(RIError):
                    self.read()
