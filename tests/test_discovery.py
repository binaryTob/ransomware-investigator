import json
import os
import subprocess
from unittest.mock import Mock, patch

from tests.common import ProjectTest
from tests.test_inventory import bundle
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.discovery import parse_swaps, scan_metadata
from ransomware_investigator.executor import RestrictedExecutor, command, trusted_binary
from ransomware_investigator.safety import Policy, RIError


class FakeExecutor:
    def __init__(self, grant):
        self.raw = bundle()

    def execute(self, operation, **kwargs):
        if operation == "version":
            out = "synthetic version 1"
        elif operation == "lsblk_metadata":
            out = json.dumps(self.raw["lsblk"])
        elif operation == "findmnt_metadata":
            out = json.dumps(self.raw["findmnt"])
        elif operation == "swap_metadata":
            out = "Filename Type Size Used Priority\n/swapfile file 100 0 -2\n"
        else:
            out = self.raw["udev"][kwargs["device"]]
        return {"operation": operation, "status": "ok", "stdout": out, "stderr": "", "returncode": 0, "argv": ["SYNTHETIC"]}


class DiscoveryTests(ProjectTest):
    def test_no_authorization_means_no_executor_or_probe(self):
        with CaseStore(self.work / "store") as store:
            case = store.create_case("Caso", "Synthetic Operator", "Synthetic Operator")
            factory = Mock(side_effect=AssertionError("No ejecutar"))
            with self.assertRaises(RIError):
                scan_metadata(store, case["id"], "Synthetic Operator", "Test", authorized=False, executor_factory=factory)
            factory.assert_not_called()
            self.assertEqual(store.list("operations", case["id"])[0]["status"], "denied")

    def test_authorized_flow_with_synthetic_executor_only(self):
        with CaseStore(self.work / "store") as store:
            case = store.create_case("Caso", "Synthetic Operator", "Synthetic Operator")
            with patch("subprocess.Popen", side_effect=AssertionError("No procesos reales")):
                inv = scan_metadata(store, case["id"], "Synthetic Operator", "Metadatos simulados", authorized=True, executor_factory=FakeExecutor)
            self.assertEqual(inv["mode"], "metadata")  # Transport tested; this is not a live-hardware check.
            self.assertTrue(inv["topology_complete"])
            self.assertEqual(len(store.list("authorizations", case["id"])), 1)
            self.assertEqual(store.list("operations", case["id"])[0]["status"], "completed")
            self.assertTrue(store.verify()["valid"])

    def test_missing_tool_timeout_disconnect_and_malformed_are_audited(self):
        for failed_operation, status in (("lsblk_metadata", "unavailable"), ("lsblk_metadata", "timeout"), ("udev_properties", "error"), ("findmnt_metadata", "permission_denied")):
            class Failing(FakeExecutor):
                def execute(self, op, **kwargs):
                    result = super().execute(op, **kwargs)
                    if op == failed_operation:
                        result.update(status=status, stdout="", returncode=1)
                    return result
            with self.subTest(op=failed_operation, status=status), CaseStore(self.work / (failed_operation + status)) as store:
                case = store.create_case("Caso", "Synthetic Operator", "Synthetic Operator")
                if failed_operation == "lsblk_metadata":
                    with self.assertRaises(RIError):
                        scan_metadata(store, case["id"], "Synthetic Operator", "Test", authorized=True, executor_factory=Failing)
                    expected = "failed"
                else:
                    inv = scan_metadata(store, case["id"], "Synthetic Operator", "Test", authorized=True, executor_factory=Failing)
                    self.assertFalse(inv["topology_complete"])
                    expected = "partial"
                self.assertEqual(store.list("operations", case["id"])[0]["status"], expected)
                self.assertTrue(store.verify()["valid"])
        class Malformed(FakeExecutor):
            def execute(self, op, **kwargs):
                result = super().execute(op, **kwargs)
                if op == "lsblk_metadata":
                    result["stdout"] = "not json"
                return result
        with CaseStore(self.work / "malformed") as store:
            case = store.create_case("Caso", "Synthetic Operator", "Synthetic Operator")
            with self.assertRaises(RIError):
                scan_metadata(store, case["id"], "Synthetic Operator", "Test", authorized=True, executor_factory=Malformed)
            self.assertEqual(store.list("operations", case["id"])[0]["status"], "failed")

    def test_catalog_fixed_no_probing_or_extra_arguments(self):
        with patch("ransomware_investigator.executor.trusted_binary", side_effect=lambda n: "/usr/bin/" + n):
            ls = command("lsblk_metadata")
            self.assertNotIn("FSTYPE", ls[-1])
            self.assertEqual(command("udev_properties", device="/dev/sda")[-1], "--path=/sys/class/block/sda")
            for op, kwargs in (("shell", {}), ("lsblk_metadata", {"tool": "sudo"}), ("findmnt_metadata", {"device": "/dev/sda"}), ("udev_properties", {"device": "/dev/sda;id"})):
                with self.subTest(op=op), self.assertRaises(RIError):
                    command(op, **kwargs)
        with self.assertRaises(RIError):
            trusted_binary("smartctl")
        with self.assertRaises(RIError):
            trusted_binary("/home/SYNTHETIC")

    def test_executor_requires_grant_and_never_falls_back(self):
        with patch("subprocess.Popen") as popen:
            with self.assertRaises(RIError):
                RestrictedExecutor(None).execute("lsblk_metadata")
            popen.assert_not_called()
        grant = Policy.grant("a" * 32, "Synthetic Operator", "Test")
        executor = RestrictedExecutor(grant)
        with patch("ransomware_investigator.executor.trusted_binary", side_effect=FileNotFoundError("missing")), patch("subprocess.Popen") as popen:
            self.assertEqual(executor.execute("lsblk_metadata")["status"], "unavailable")
            popen.assert_not_called()
        with patch("ransomware_investigator.executor.trusted_binary", return_value="/usr/bin/lsblk"), patch("subprocess.Popen", side_effect=PermissionError("denied")):
            self.assertEqual(executor.execute("lsblk_metadata")["status"], "permission_denied")

    def test_capture_bounds_and_exit_status_using_pipes_not_commands(self):
        grant = Policy.grant("a" * 32, "Synthetic Operator", "Test")
        for content, code, expected in ((b'{"ok":1}', 0, "ok"), (b"x" * 200, 0, "output_limit"), (b"error", 1, "error")):
            pipes = []
            for payload in (content, b""):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, payload)
                os.close(write_fd)
                pipes.append(os.fdopen(read_fd, "rb"))
            proc = Mock(stdin=Mock(), stdout=pipes[0], stderr=pipes[1], returncode=code)
            proc.poll.return_value = code
            with patch("ransomware_investigator.executor.trusted_binary", return_value="/usr/bin/lsblk"), patch("subprocess.Popen", return_value=proc) as popen:
                result = RestrictedExecutor(grant, max_output=64).execute("lsblk_metadata")
                self.assertEqual(result["status"], expected)
                self.assertLessEqual(len(result["stdout"]), 64)
                self.assertFalse(popen.call_args.kwargs["shell"])
                self.assertNotIn("LD_PRELOAD", popen.call_args.kwargs["env"])

    def test_process_wait_timeout_is_reported_and_killed(self):
        pipes = []
        for _ in range(2):
            read_fd, write_fd = os.pipe()
            os.close(write_fd)
            pipes.append(os.fdopen(read_fd, "rb"))
        proc = Mock(stdin=Mock(), stdout=pipes[0], stderr=pipes[1], returncode=-9, pid=999999)
        proc.poll.return_value = None
        proc.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 1), -9]
        with patch("ransomware_investigator.executor.trusted_binary", return_value="/usr/bin/lsblk"), patch("subprocess.Popen", return_value=proc), patch("os.killpg") as kill:
            result = RestrictedExecutor(Policy.grant("a" * 32, "Synthetic Operator", "Test")).execute("lsblk_metadata")
        self.assertEqual(result["status"], "timeout")
        kill.assert_called_once()

    def test_swap_parser(self):
        self.assertEqual(parse_swaps("Filename Type Size Used Priority\n/a\\040b file 1 0 -2\n"), ["/a b"])
        with self.assertRaises(RIError):
            parse_swaps("broken")
