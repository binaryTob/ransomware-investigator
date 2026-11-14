import errno
import io
import os
import stat
import subprocess
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests.common import ProjectTest
from ransomware_investigator.executor import RestrictedExecutor, command, trusted_binary
from ransomware_investigator.safety import Policy, RIError


class BaselineGapTests(ProjectTest):
    def test_actual_expired_grant_branch_with_otherwise_valid_duration(self):
        grant = Policy.grant("a" * 32, "Synthetic Operator", "test")
        grant["created_at"] = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
        grant["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        with self.assertRaisesRegex(RIError, "vencida"):
            Policy.check("lsblk_metadata", grant)

    def test_swap_reader_is_bounded_and_permission_failure_has_no_fallback(self):
        executor = RestrictedExecutor(Policy.grant("a" * 32, "Synthetic Operator", "test"), max_output=64)
        with patch("builtins.open", return_value=io.BytesIO(b"Filename Type Size Used Priority\n")) as opened:
            self.assertEqual(executor.execute("swap_metadata")["status"], "ok")
            opened.assert_called_once_with("/proc/swaps", "rb")
        with patch("builtins.open", return_value=io.BytesIO(b"x" * 65)):
            result = executor.execute("swap_metadata")
            self.assertEqual(result["status"], "output_limit")
            self.assertEqual(len(result["stdout"]), 64)
        with patch("builtins.open", side_effect=PermissionError("synthetic")), patch("subprocess.Popen", side_effect=AssertionError("No fallback")):
            self.assertEqual(executor.execute("swap_metadata")["status"], "unavailable")

    def test_read_timeout_and_unconfirmed_termination_using_simulated_process(self):
        for final_status in ("timeout", "termination_unconfirmed"):
            pipes, writers = [], []
            for _ in range(2):
                read_fd, write_fd = os.pipe()
                pipes.append(os.fdopen(read_fd, "rb"))
                writers.append(write_fd)
            proc = Mock(stdin=Mock(), stdout=pipes[0], stderr=pipes[1], returncode=-9, pid=999999)
            proc.poll.return_value = None
            if final_status == "termination_unconfirmed":
                proc.wait.side_effect = subprocess.TimeoutExpired("synthetic", 1)
            try:
                with patch("ransomware_investigator.executor.trusted_binary", return_value="/usr/bin/lsblk"), patch("subprocess.Popen", return_value=proc), patch("os.killpg", side_effect=ProcessLookupError), patch("time.monotonic", side_effect=[0, 20, 20, 20]):
                    result = RestrictedExecutor(Policy.grant("a" * 32, "Synthetic Operator", "test")).execute("lsblk_metadata")
                self.assertEqual(result["status"], final_status)
            finally:
                for writer in writers:
                    os.close(writer)

    def test_trusted_binary_success_and_capability_verification_errors_are_mocked(self):
        for error, expected_success in ((errno.ENODATA, True), (errno.EACCES, False)):
            with patch("ransomware_investigator.executor.Path") as path, patch("os.access", return_value=True), patch("os.getxattr", side_effect=OSError(error, "synthetic")):
                candidate = path.return_value.__truediv__.return_value
                candidate.exists.return_value = True
                target = candidate.resolve.return_value
                target.is_relative_to.return_value = True
                target.parents = ()
                target.stat.return_value = SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
                if expected_success:
                    self.assertEqual(trusted_binary("lsblk"), str(target))
                else:
                    with self.assertRaises(RIError):
                        trusted_binary("lsblk")
        with patch("ransomware_investigator.executor.trusted_binary", side_effect=lambda name: "/usr/bin/" + name):
            self.assertEqual(command("version", tool="udevadm"), ["/usr/bin/udevadm", "--version"])
            self.assertIn("--kernel", command("findmnt_metadata"))
