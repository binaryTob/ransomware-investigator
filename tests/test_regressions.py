import ast
import base64
import copy
import json
import os
import sqlite3
import stat
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from tests.common import ROOT, ProjectTest
from tests.test_discovery import FakeExecutor
from tests.test_inventory import FIXTURE, USB_KEY, bundle
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.discovery import scan_metadata
from ransomware_investigator.executor import RestrictedExecutor, trusted_binary
from ransomware_investigator.inventory import build_inventory, compare, register_original, save_inventory, select_original
from ransomware_investigator.safety import Policy, RIError, read_project_file


class RegressionTests(ProjectTest):
    def test_protected_identity_remains_excluded_after_rename_and_root_move(self):
        with CaseStore(self.work / "store") as store:
            case = store.create_case("Prueba", "Synthetic Operator", "Synthetic Operator")
            save_inventory(store, case["id"], bundle(), FIXTURE.read_bytes(), "Synthetic Operator", mode="simulated")
            raw = json.loads(json.dumps(bundle()).replace("nvme0n1", "sdb"))
            new_system = json.loads(json.dumps(bundle()["lsblk"]["blockdevices"][0]).replace("nvme0n1", "nvme1n1").replace("259:", "260:").replace("5000000000000001", "5000000000000002").replace("TEST-INTERNAL-001", "TEST-INTERNAL-002"))
            raw["lsblk"]["blockdevices"].append(new_system)
            raw["findmnt"] = json.loads(json.dumps(bundle()["findmnt"]).replace("nvme0n1", "nvme1n1").replace("259:", "260:"))
            pure = build_inventory(raw, mode="simulated", workspace=str(self.work))
            formerly_internal = next(d for d in pure["devices"] if d["path"] == "/dev/sdb")
            self.assertFalse(formerly_internal["protection_reasons"])
            saved = save_inventory(store, case["id"], raw, json.dumps(raw).encode(), "Synthetic Operator", mode="simulated")
            pinned = next(d for d in saved["devices"] if d["path"] == "/dev/sdb")
            self.assertIn("persistent_workspace_exclusion", pinned["protection_reasons"])
            with self.assertRaises(RIError):
                select_original(saved, pinned["identity_key"])

    def test_mapped_root_protects_physical_backing_and_unknown_mount_blocks(self):
        raw = bundle()
        raw["lsblk"]["blockdevices"][1]["children"][2]["children"] = [
            {"kname": "dm-0", "path": "/dev/mapper/test-vg-root", "type": "lvm", "size": 100000000,
             "ro": True, "maj:min": "253:0", "pkname": "sda3"}]
        raw["findmnt"]["filesystems"][0].update(source="/dev/mapper/test-vg-root", **{"maj:min": "253:0"})
        inv = build_inventory(raw, mode="simulated", workspace=str(self.work))
        self.assertTrue(inv["topology_complete"])
        with self.assertRaises(RIError):
            select_original(inv, USB_KEY)
        raw = bundle()
        raw["findmnt"]["filesystems"].append({"source": "/dev/sdz1", "target": "/media/unknown", "fstype": "ntfs", "options": "rw", "maj:min": "65:241"})
        self.assertFalse(build_inventory(raw, mode="simulated", workspace=str(self.work))["topology_complete"])

    def test_unknown_ro_serial_fallback_placeholder_and_duplicate_mount(self):
        raw = bundle()
        disk = raw["lsblk"]["blockdevices"][1]
        disk["wwn"] = None
        raw["udev"]["/dev/sda"] = "ID_SERIAL_SHORT=TEST-USB-001\n"
        inv = build_inventory(raw, mode="simulated", workspace=str(self.work))
        device = next(d for d in inv["devices"] if d["path"] == "/dev/sda")
        self.assertTrue(device["identity_key"].startswith("serial:"))
        disk["serial"] = "0000"
        raw["udev"]["/dev/sda"] = ""
        inv = build_inventory(raw, mode="simulated", workspace=str(self.work))
        self.assertEqual(next(d for d in inv["devices"] if d["path"] == "/dev/sda")["identity_status"], "missing")
        raw = bundle()
        raw["findmnt"]["filesystems"].append(copy.deepcopy(raw["findmnt"]["filesystems"][0]))
        self.assertFalse(build_inventory(raw, mode="simulated", workspace=str(self.work))["topology_complete"])

    def test_multidisk_raid_dependency_is_merged_not_discarded(self):
        raw = bundle()
        other = {"kname": "sdb", "path": "/dev/sdb", "type": "disk", "size": 480103981056,
                 "model": "SYNTHETIC RAID MEMBER", "serial": "RAID-002", "wwn": "0x5000000000000088", "ro": True,
                 "maj:min": "8:16", "log-sec": 512}
        md = {"kname": "md0", "path": "/dev/md0", "type": "raid1", "size": 100000000, "ro": True, "maj:min": "9:0"}
        raw["lsblk"]["blockdevices"][1]["children"][2]["children"] = [copy.deepcopy(md)]
        other["children"] = [copy.deepcopy(md)]
        raw["lsblk"]["blockdevices"].append(other)
        inv = build_inventory(raw, mode="simulated", workspace=str(self.work))
        mapped = next(d for d in inv["devices"] if d["path"] == "/dev/md0")
        self.assertEqual(mapped["parents"], ["/dev/sda3", "/dev/sdb"])

    def test_conflicting_capacity_same_wwn_is_not_silently_reused(self):
        first = build_inventory(bundle(), mode="simulated", workspace=str(self.work))
        raw = bundle()
        raw["lsblk"]["blockdevices"][1]["size"] += 512
        second = build_inventory(raw, mode="simulated", workspace=str(self.work))
        first.update(id="a" * 32, case_id="c" * 32)
        second.update(id="b" * 32, case_id="c" * 32)
        self.assertTrue(compare(first, second)["changed"][0]["identity_conflict"])
        second["mode"] = "metadata"
        with self.assertRaises(RIError):
            compare(first, second)
        second.update(mode="simulated", case_id="d" * 32)
        with self.assertRaises(RIError):
            compare(first, second)

    def test_sqlite_constraint_prevents_duplicate_original_even_bypassing_cli(self):
        with CaseStore(self.work / "store") as store:
            case = store.create_case("Caso", "Synthetic Operator", "Synthetic Operator")
            inv = save_inventory(store, case["id"], bundle(), FIXTURE.read_bytes(), "Synthetic Operator", mode="simulated")
            first = register_original(store, case["id"], inv["id"], USB_KEY, "Synthetic Operator", "Fixture")
            with self.assertRaises(sqlite3.IntegrityError):
                store.record("evidence", case["id"], first, "Synthetic Operator")
            self.assertTrue(store.verify()["valid"])
            self.assertEqual(len(store.list("evidence", case["id"])), 1)

    def test_tampered_blob_and_fk_columns_detected(self):
        with CaseStore(self.work / "store") as store:
            case = store.create_case("Caso", "Synthetic Operator", "Synthetic Operator")
            other = store.create_case("Otro", "Synthetic Operator", "Synthetic Operator")
            inv = save_inventory(store, case["id"], bundle(), FIXTURE.read_bytes(), "Synthetic Operator", mode="simulated")
            with store.db:
                store.db.execute("UPDATE inventories SET case_id=? WHERE id=?", (other["id"], inv["id"]))
                store.db.execute("UPDATE blobs SET content=?", (b"tampered",))
            self.assertFalse(store.verify()["valid"])
            with self.assertRaises(RIError):
                store.blob(inv["raw_sha256"][0])
            with self.assertRaises(RIError):
                store.export_case(case["id"])

    def test_file_safety_fifo_hardlink_db_and_external_mount(self):
        fifo = self.work / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(RIError):
            read_project_file(fifo)
        with CaseStore(self.work / "store"):
            pass
        db = self.work / "store/cases.sqlite3"
        os.link(db, self.work / "db-hardlink")
        with self.assertRaises(RIError):
            CaseStore(self.work / "store")
        source = self.work / "external.json"
        source.write_text("{}")
        original_stat = Path.stat
        def external_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == source:
                return SimpleNamespace(st_dev=info.st_dev + 1, st_mode=info.st_mode)
            return info
        with patch("pathlib.Path.stat", external_stat), self.assertRaises(RIError):
            read_project_file(source)

    def test_unsafe_executable_ownership_bits_capabilities_fail_closed(self):
        for owner, mode, cap in ((1000, stat.S_IFREG | 0o755, b""), (0, stat.S_IFREG | 0o777, b""),
                                 (0, stat.S_IFREG | 0o4755, b""), (0, stat.S_IFREG | 0o2755, b""),
                                 (0, stat.S_IFREG | 0o755, b"capabilities")):
            with self.subTest(owner=owner, mode=mode, cap=cap), patch("ransomware_investigator.executor.Path") as path, patch("os.access", return_value=True), patch("os.getxattr", return_value=cap):
                candidate = path.return_value.__truediv__.return_value
                candidate.exists.return_value = True
                target = candidate.resolve.return_value
                target.is_relative_to.return_value = True
                target.parents = ()
                target.stat.return_value = SimpleNamespace(st_uid=owner, st_mode=mode)
                with self.assertRaises(RIError):
                    trusted_binary("lsblk")

    def test_output_bytes_are_preserved_even_if_utf8_is_invalid(self):
        out, err = b"invalid\xff", b"warning\xfe"
        result = RestrictedExecutor._result("version", ["SYNTHETIC"], "error", out, err, 1, 0.1)
        self.assertEqual(base64.b64decode(result["stdout_base64"]), out)
        self.assertEqual(base64.b64decode(result["stderr_base64"]), err)

    def test_collection_limit_and_unconfirmed_termination_stop_further_queries(self):
        for failed_status in ("too_big", "termination_unconfirmed"):
            calls = []
            class Bounded(FakeExecutor):
                def execute(self, op, **kwargs):
                    calls.append(op)
                    result = super().execute(op, **kwargs)
                    if failed_status == "too_big":
                        result["stdout"] = "x" * (2 * 1024 * 1024 + 1)
                    else:
                        result["status"] = failed_status
                    return result
            with CaseStore(self.work / failed_status) as store:
                case = store.create_case("Caso", "Synthetic Operator", "Synthetic Operator")
                with self.assertRaises(RIError):
                    scan_metadata(store, case["id"], "Synthetic Operator", "Sintético", authorized=True, executor_factory=Bounded)
                self.assertEqual(calls, ["version"])
                self.assertEqual(store.list("operations", case["id"])[0]["status"], "failed")

    def test_unavailable_versions_are_not_retried_as_real_queries(self):
        for missing in ("lsblk", "findmnt", "udevadm"):
            calls = []
            class MissingVersion(FakeExecutor):
                def execute(self, op, **kwargs):
                    calls.append(op)
                    result = super().execute(op, **kwargs)
                    if op == "version" and kwargs["tool"] == missing:
                        result["status"] = "unavailable"
                    return result
            with CaseStore(self.work / ("version-" + missing)) as store:
                case = store.create_case("Caso", "Synthetic Operator", "Synthetic Operator")
                if missing == "lsblk":
                    with self.assertRaises(RIError):
                        scan_metadata(store, case["id"], "Synthetic Operator", "Sintético", authorized=True, executor_factory=MissingVersion)
                    self.assertNotIn("lsblk_metadata", calls)
                else:
                    inv = scan_metadata(store, case["id"], "Synthetic Operator", "Sintético", authorized=True, executor_factory=MissingVersion)
                    self.assertFalse(inv["topology_complete"])
                    self.assertNotIn("findmnt_metadata" if missing == "findmnt" else "udev_properties", calls)

    def test_process_and_network_boundaries_in_production_modules(self):
        source = ROOT / "src/ransomware_investigator"
        for path in source.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [node.module or ""] if isinstance(node, ast.ImportFrom) else [n.name for n in node.names]
                    self.assertFalse(set(names) & {"socket", "requests", "urllib", "http", "ftplib"}, path.name)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    self.assertNotIn(node.func.attr, {"system", "popen", "execv", "execve", "execl", "spawnv", "enable_load_extension"}, path.name)
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                        self.assertEqual(path.name, "executor.py")
                        self.assertEqual(node.func.attr, "Popen")
