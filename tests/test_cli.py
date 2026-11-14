import contextlib
import importlib.util
import io
import json
import subprocess
import sys
from unittest.mock import patch

from tests.common import ROOT, ProjectTest
from tests.test_inventory import FIXTURE, USB_KEY
from tests.test_preflight import destination
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.cli import main


class CLITests(ProjectTest):
    def call(self, *argv, expected=0):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()) as error:
            status = main(["--workspace", str(self.work / "cases"), "--operator", "Synthetic Operator", *argv])
        self.assertEqual(status, expected, error.getvalue())
        return json.loads(output.getvalue() or error.getvalue())

    def test_full_synthetic_cli_case_inventory_evidence_preflight_export(self):
        with patch("subprocess.Popen", side_effect=AssertionError("No ejecutar herramientas del host")):
            case = self.call("case", "create", "--title", "Sintético", "--responsible", "Synthetic Operator")
            inv = self.call("discovery", "simulate", "--case", case["id"], "--fixture", str(FIXTURE))
            self.assertEqual(self.call("inventory", "list", "--case", case["id"])[0]["id"], inv["id"])
            self.assertEqual(self.call("inventory", "show", "--inventory", inv["id"])["id"], inv["id"])
            self.assertEqual(self.call("inventory", "raw", "--inventory", inv["id"])[0]["sha256"], inv["raw_sha256"][0])
            self.call("evidence", "register-original", "--case", case["id"], "--inventory", inv["id"], "--device", USB_KEY, "--notes", "Fixture")
            self.assertEqual(len(self.call("evidence", "list", "--case", case["id"])), 1)
            self.call("evidence", "register-original", "--case", case["id"], "--inventory", inv["id"], "--device", USB_KEY, "--notes", "Duplicado", expected=2)
            plan = self.work / "destination.json"
            plan.write_text(json.dumps(destination()))
            report = self.call("acquisition", "preflight", "--case", case["id"], "--inventory", inv["id"], "--device", USB_KEY, "--destination-plan", str(plan), expected=2)
            self.assertIn("SUFFICIENT_SPACE", report["blockers"])
            self.assertFalse(report["acquisition_allowed"])
            exported = self.call("case", "export", "--case", case["id"])
            self.assertEqual(exported["case"]["id"], case["id"])
            self.assertEqual(len(exported["raw_outputs"]), 1)
            self.assertTrue(self.call("audit", "verify")["valid"])

    def test_real_scan_denied_via_cli_without_authorization(self):
        case = self.call("case", "create", "--title", "Test", "--responsible", "Synthetic Operator")
        with patch("subprocess.Popen", side_effect=AssertionError("No dispositivos")), patch("ransomware_investigator.discovery.RestrictedExecutor", side_effect=AssertionError("No executor")):
            result = self.call("discovery", "scan", "--case", case["id"], "--profile", "metadata", "--reason", "Sin autorización", expected=2)
        self.assertIn("bloqueado", result["error"])

    def test_real_launcher_executes_help_and_synthetic_inventory_only(self):
        # The only real subprocess in the suite is our Python CLI, never storage tools.
        prefix = [sys.executable, str(ROOT / "ri.py"), "--workspace", str(self.work / "launcher")]
        help_result = subprocess.run(prefix + ["--help"], capture_output=True, text=True, timeout=10, check=True)
        self.assertIn("discovery", help_result.stdout)
        case = json.loads(subprocess.run(prefix + ["case", "create", "--title", "Launcher", "--responsible", "Synthetic Operator"], capture_output=True, text=True, timeout=10, check=True).stdout)
        inv = json.loads(subprocess.run(prefix + ["discovery", "simulate", "--case", case["id"], "--fixture", str(FIXTURE)], capture_output=True, text=True, timeout=10, check=True).stdout)
        self.assertEqual(inv["mode"], "simulated")

    def test_malformed_fixture_outside_path_and_tampered_reads_fail(self):
        case = self.call("case", "create", "--title", "Test", "--responsible", "Synthetic Operator")
        malformed = self.work / "broken.json"
        malformed.write_text("broken")
        self.call("discovery", "simulate", "--case", case["id"], "--fixture", str(malformed), expected=2)
        self.call("discovery", "simulate", "--case", case["id"], "--fixture", "/dev/sda", expected=2)
        with CaseStore(self.work / "cases") as store:
            with store.db:
                store.db.execute("UPDATE events SET document='[]'")
        self.assertFalse(self.call("audit", "verify", expected=2)["valid"])
        self.call("case", "show", "--case", case["id"], expected=2)

    def test_runnable_demo_never_instantiates_executor(self):
        path = ROOT / "examples/simulated/run_demo.py"
        spec = importlib.util.spec_from_file_location("synthetic_demo", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch("subprocess.Popen", side_effect=AssertionError("No procesos del host")):
            report = module.demo(self.work / "demo")
        self.assertFalse(report["physical_devices_accessed"])
        self.assertFalse(report["acquisition_allowed"])
        self.assertIn("SUFFICIENT_SPACE", report["preflight_blockers"])
        self.assertTrue(report["audit"]["valid"])

    def test_no_arbitrary_shell_acquire_mount_or_smart_subcommands(self):
        for args in (("acquisition", "run"), ("discovery", "smartctl"), ("shell",), ("mount",)):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                main(["--workspace", str(self.work / "blocked"), *args])
            self.assertEqual(caught.exception.code, 2)
