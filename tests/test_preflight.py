import copy
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from tests.common import ROOT, ProjectTest
from tests.test_inventory import USB_KEY, bundle
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.inventory import build_inventory, register_original, save_inventory
from ransomware_investigator.preflight import assess, record_preflight
from ransomware_investigator.safety import RIError, utcnow


def destination():
    result = json.loads((ROOT / "examples/simulated/destination.json").read_bytes())
    result["observed_at"] = utcnow()
    return result


class PreflightTests(ProjectTest):
    def setUp(self):
        super().setUp()
        self.inv = build_inventory(bundle(), mode="simulated", workspace=str(self.work))
        self.inv.update(id="1" * 32, case_id="a" * 32)
        self.disk = next(d for d in self.inv["devices"] if d["identity_key"] == USB_KEY)
        self.original = {"identity_key": USB_KEY, "mode": "simulated", "device_snapshot": copy.deepcopy(self.disk)}

    def assess(self, plan=None, inv=None, **kwargs):
        return assess(inv or self.inv, USB_KEY, plan or destination(), original=self.original,
                      latest_inventory_id=kwargs.pop("latest_inventory_id", self.inv["id"]), **kwargs)

    def test_insufficient_space_stops_without_opening_destination(self):
        with patch("builtins.open", side_effect=AssertionError("No abrir destinos")), patch("os.statvfs", side_effect=AssertionError("No medir hardware")):
            plan = {"schema_version": 1, "mode": "simulated", "observed_at": utcnow(), "path": "/evidence/image.raw", "mount_target": "/",
                    "device_maj_min": "259:2", "filesystem": "ext4", "available_bytes": 233 * 2**30,
                    "reserve_bytes": 2**30, "max_file_size_bytes": 2**44, "writable": True,
                    "target_exists": False, "symlinks_checked": True}
            report = self.assess(plan)
        self.assertIn("SUFFICIENT_SPACE", report["blockers"])
        self.assertFalse(report["acquisition_allowed"])
        self.assertGreater(report["required_bytes"], plan["available_bytes"])

    def test_planning_can_pass_but_never_authorizes_execution(self):
        plan = destination()
        plan["available_bytes"] = 2**40
        report = self.assess(plan)
        self.assertTrue(report["planning_passed"], report["checks"])
        self.assertFalse(report["acquisition_allowed"])
        self.assertIn("ACQUISITION_NOT_AUTHORIZED", report["execution_blockers"])
        self.assertTrue(report["review_required"])

    def test_every_partition_ro_checked_and_mounts_blocked(self):
        for ro in (False, None):
            inv = copy.deepcopy(self.inv)
            part = next(d for d in inv["devices"] if d["path"] == "/dev/sda3")
            part["read_only"] = ro
            part["mounts"] = [{"target": "/media/evidence", "options": "ro"}]
            report = self.assess(inv=inv)
            self.assertIn("SOURCE_READ_ONLY", report["blockers"])
            self.assertIn("SOURCE_UNMOUNTED", report["blockers"])

    def test_stale_newer_and_changed_identity_blocked(self):
        inv = copy.deepcopy(self.inv)
        inv["observed_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        next(d for d in inv["devices"] if d["identity_key"] == USB_KEY)["size_bytes"] += 512
        report = self.assess(inv=inv, latest_inventory_id="2" * 32)
        for code in ("SOURCE_FRESH", "LATEST_SNAPSHOT", "IDENTITY_UNCHANGED"):
            self.assertIn(code, report["blockers"])

    def test_destination_on_source_mismatch_links_existing_and_fat_limit(self):
        inv = copy.deepcopy(self.inv)
        inv["mounts"].append({"target": "/evidence", "source": "/dev/sda1", "device_path": "/dev/sda1", "maj_min": "8:1", "fstype": "vfat", "options": "rw"})
        plan = destination()
        plan.update(path="/evidence/image.raw", mount_target="/evidence", device_maj_min="8:1", filesystem="vfat", symlinks_checked=False, target_exists=True)
        report = self.assess(plan, inv=inv)
        for code in ("DESTINATION_DISTINCT", "DESTINATION_SYMLINK_CHECK_DECLARED", "DESTINATION_NOT_EXISTING", "FILE_SIZE_SUPPORTED"):
            self.assertIn(code, report["blockers"])
        plan["device_maj_min"] = "wrong"
        self.assertIn("DESTINATION_MOUNT_MATCHES", self.assess(plan, inv=inv)["blockers"])

    def test_active_lvm_raid_encryption_unknown_health_and_alert(self):
        for kind in ("lvm", "raid1", "crypt"):
            inv = copy.deepcopy(self.inv)
            part = next(d for d in inv["devices"] if d["path"] == "/dev/sda3")
            part["type"] = kind
            next(d for d in inv["devices"] if d["identity_key"] == USB_KEY)["health"] = {"status": "alert"}
            report = self.assess(inv=inv)
            self.assertIn("NO_ACTIVE_VOLUMES", report["blockers"])
            self.assertIn("NO_KNOWN_PHYSICAL_ALERT", report["blockers"])

    def test_existing_copy_never_reused_by_filename_or_declared_hash(self):
        plan = destination()
        plan["existing_copy"] = {"source_identity_key": USB_KEY, "source_inventory_id": self.inv["id"],
                                 "size_bytes": self.disk["size_bytes"], "sha256": "a" * 64, "expected_sha256": "a" * 64}
        report = self.assess(plan)
        self.assertTrue(report["existing_copy"]["metadata_matches"])
        self.assertFalse(report["existing_copy"]["reusable"])
        self.assertIn("EXISTING_COPY_VERIFIED", report["blockers"])
        for field, bad in (("source_inventory_id", "wrong"), ("sha256", "b" * 64), ("source_identity_key", "wrong")):
            altered = copy.deepcopy(plan)
            altered["existing_copy"][field] = bad
            self.assertIn("EXISTING_COPY_METADATA", self.assess(altered)["blockers"])

    def test_unsafe_paths_missing_quantities_and_modes_fail_closed(self):
        for path in ("/dev/sda", "relative.raw", "/a/../b", "/proc/x"):
            plan = destination()
            plan["path"] = path
            with self.subTest(path=path), self.assertRaises(RIError):
                self.assess(plan)
        plan = destination()
        plan.update(mode="metadata", reserve_bytes=None, available_bytes=None, max_file_size_bytes=None)
        report = self.assess(plan)
        for code in ("SAME_MODE", "SUFFICIENT_SPACE", "FILE_SIZE_SUPPORTED"):
            self.assertIn(code, report["blockers"])

    def test_recorded_preflight_and_cross_case_rejection(self):
        with CaseStore(self.work / "store") as store:
            case = store.create_case("Caso", "Synthetic Operator", "Synthetic Operator")
            other = store.create_case("Otro", "Bob", "Bob")
            raw = json.dumps(bundle()).encode()
            inv = save_inventory(store, case["id"], bundle(), raw, "Synthetic Operator", mode="simulated")
            register_original(store, case["id"], inv["id"], USB_KEY, "Synthetic Operator", "Fixture")
            report = record_preflight(store, case["id"], inv["id"], USB_KEY, destination(), "Synthetic Operator")
            self.assertFalse(report["acquisition_allowed"])
            self.assertTrue(store.verify()["valid"])
            self.assertEqual(len(store.list("preflights", case["id"])), 1)
            with self.assertRaises(RIError):
                record_preflight(store, other["id"], inv["id"], USB_KEY, destination(), "Bob")
