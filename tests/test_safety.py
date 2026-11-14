from unittest.mock import patch

from tests.common import ProjectTest
from ransomware_investigator.safety import (
    RIError, Policy, destination_path, device_path, ensure_user,
    project_path, read_project_file,
)


class SafetyTests(ProjectTest):
    def test_root_rejected(self):
        for method in ("getuid", "geteuid"):
            with patch("os." + method, return_value=0), self.assertRaises(RIError):
                ensure_user()

    def test_deny_by_default_and_authorization_expiry(self):
        grant = Policy.grant("a" * 32, "operador", "metadatos solamente")
        Policy.check("lsblk_metadata", grant)
        for op in ("mount", "acquire", "sudo", "smartctl", "shell", "lsblk;id"):
            with self.subTest(op=op), self.assertRaises(RIError):
                Policy.check(op, grant)
        with self.assertRaises(RIError):
            Policy.check("lsblk_metadata", None)
        grant["expires_at"] = "2000-01-01T00:00:00+00:00"
        with self.assertRaises(RIError):
            Policy.check("lsblk_metadata", grant)

    def test_device_paths_never_accept_shell_aliases_or_traversal(self):
        for path in ("/dev/sda", "/dev/nvme0n1p1", "/dev/dm-0"):
            self.assertEqual(device_path(path), path)
        for path in ("/dev/sda;id", "/dev/../etc/passwd", "-a", "/dev/disk/by-id/x", "/etc/passwd"):
            with self.subTest(path=path), self.assertRaises(RIError):
                device_path(path)

    def test_project_files_only_no_links_or_special_files(self):
        source = self.work / "fixture.json"
        source.write_text("{}")
        self.assertEqual(read_project_file(source), b"{}")
        link = self.work / "link"
        link.symlink_to(source)
        with self.assertRaises(RIError):
            read_project_file(link)
        import os
        hard = self.work / "hard"
        os.link(source, hard)
        with self.assertRaises(RIError):
            read_project_file(hard)
        for path in ("/dev/sda", "/proc/swaps", "/tmp/outside", self.work / "../../../../escape"):
            with self.subTest(path=path), self.assertRaises(RIError):
                project_path(path)

    def test_destination_validation_is_lexical(self):
        self.assertEqual(destination_path("/evidence/case/image.raw"), "/evidence/case/image.raw")
        for path in ("/dev/sda", "/proc/out", "/sys/out", "/run/out", "/", "relative", "/a/../b", "/a//b", "//host/path"):
            with self.subTest(path=path), self.assertRaises(RIError):
                destination_path(path)

    def test_malformed_and_overlong_grants_fail_closed(self):
        from datetime import datetime, timedelta, timezone
        valid = Policy.grant("a" * 32, "Synthetic Operator", "Test")
        for change in ({"case_id": "../x"}, {"actor": ""}, {"expires_at": None},
                       {"expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}):
            with self.subTest(change=change), self.assertRaises(RIError):
                Policy.check("lsblk_metadata", {**valid, **change})
        for grant in ("forged", {}, None):
            with self.subTest(grant=grant), self.assertRaises(RIError):
                Policy.check("lsblk_metadata", grant)
