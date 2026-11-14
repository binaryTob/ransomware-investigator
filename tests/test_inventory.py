import copy
import json

from tests.common import ROOT, ProjectTest
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.inventory import build_inventory, compare, register_original, save_inventory, select_original
from ransomware_investigator.safety import RIError

FIXTURE = ROOT / "examples/simulated/windows-usb.json"
USB_KEY = "wwn:5000000000000099"


def bundle():
    return json.loads(FIXTURE.read_bytes())


class InventoryTests(ProjectTest):
    def build(self, raw=None):
        return build_inventory(bundle() if raw is None else raw, mode="simulated", workspace=str(self.work))

    def test_internal_and_four_partition_windows_ssd(self):
        inv = self.build()
        self.assertTrue(inv["topology_complete"])
        disk = select_original(inv, USB_KEY)
        self.assertTrue(disk["read_only"])
        self.assertEqual(disk["health"]["status"], "not_queried")
        self.assertEqual(len([d for d in inv["devices"] if "/dev/sda" in d["parents"]]), 4)
        self.assertIn("possible_encryption", next(d for d in inv["devices"] if d["path"] == "/dev/sda3")["hints"])
        with self.assertRaises(RIError):
            select_original(inv, "wwn:5000000000000001")
        with self.assertRaises(RIError):
            select_original(inv, "/dev/sda")

    def test_internal_only_is_valid_inventory_not_evidence(self):
        raw = bundle()
        raw["lsblk"]["blockdevices"].pop()
        inv = self.build(raw)
        self.assertTrue(inv["topology_complete"])
        self.assertEqual(len(inv["devices"]), 3)
        self.assertTrue(all(d["protection_reasons"] for d in inv["devices"]))

    def test_missing_duplicate_and_conflicting_identifiers_fail_closed(self):
        raw = bundle()
        disk = raw["lsblk"]["blockdevices"][1]
        disk["wwn"] = disk["serial"] = None
        raw["udev"]["/dev/sda"] = ""
        self.assertEqual(next(d for d in self.build(raw)["devices"] if d["path"] == "/dev/sda")["identity_status"], "missing")
        raw = bundle()
        raw["udev"]["/dev/sda"] = "ID_SERIAL_SHORT=CONFLICT\n"
        with self.assertRaises(RIError):
            select_original(self.build(raw), USB_KEY)
        raw = bundle()
        other = copy.deepcopy(raw["lsblk"]["blockdevices"][1])
        other.update(kname="sdb", path="/dev/sdb", children=[], **{"maj:min": "8:16"})
        raw["lsblk"]["blockdevices"].append(other)
        with self.assertRaises(RIError):
            select_original(self.build(raw), USB_KEY)

    def test_renaming_keeps_identity_and_detects_layout_changes(self):
        first = self.build()
        renamed = json.loads(json.dumps(bundle()).replace("sda", "sdc"))
        second = self.build(renamed)
        first.update(id="1" * 32, case_id="a" * 32)
        second.update(id="2" * 32, case_id="a" * 32)
        report = compare(first, second)
        self.assertEqual(report["added"], [])
        self.assertEqual(report["removed"], [])
        self.assertIn("path", report["changed"][0]["changes"])
        self.assertNotIn("partition_layout", report["changed"][0]["changes"])
        renamed["lsblk"]["blockdevices"][1]["children"][0]["ro"] = False
        third = self.build(renamed)
        third.update(id="3" * 32, case_id="a" * 32)
        self.assertIn("partition_layout", compare(second, third)["changed"][0]["changes"])

    def test_topology_swap_protection_and_missing_collection(self):
        raw = bundle()
        raw["swaps"] = ["/dev/sda2"]
        with self.assertRaises(RIError):
            select_original(self.build(raw), USB_KEY)
        raw = bundle()
        del raw["findmnt"]
        self.assertFalse(self.build(raw)["topology_complete"])
        raw = bundle()
        raw["findmnt"]["filesystems"][0]["maj:min"] = "0:1"
        self.assertFalse(self.build(raw)["topology_complete"])

    def test_malformed_data_controls_cycles_and_boolean_unknown(self):
        for field, value in (("size", -1), ("ro", "false"), ("model", "evil\x1b[2J")):
            raw = bundle()
            raw["lsblk"]["blockdevices"][1][field] = value
            with self.subTest(field=field), self.assertRaises(RIError):
                self.build(raw)
        raw = bundle()
        raw["lsblk"]["blockdevices"][1]["pkname"] = "sda1"
        with self.assertRaises(RIError):
            self.build(raw)
        raw = bundle()
        raw["lsblk"]["blockdevices"][1]["ro"] = None
        self.assertIsNone(select_original(self.build(raw), USB_KEY)["read_only"])

    def test_record_raw_dedup_original_and_case_isolation(self):
        with CaseStore(self.work / "store") as store:
            case = store.create_case("Sintético", "Synthetic Operator", "Synthetic Operator")
            other = store.create_case("Otro", "Bob", "Bob")
            raw = FIXTURE.read_bytes()
            first = save_inventory(store, case["id"], bundle(), raw, "Synthetic Operator", mode="simulated")
            second = save_inventory(store, case["id"], bundle(), raw, "Synthetic Operator", mode="simulated")
            self.assertEqual(store.db.execute("SELECT COUNT(*) FROM blobs").fetchone()[0], 1)
            evidence = register_original(store, case["id"], first["id"], USB_KEY, "Synthetic Operator", "Solo fixture")
            self.assertIsNone(evidence["content_sha256"])
            self.assertFalse(evidence["preserved_image"])
            with self.assertRaises(RIError):
                register_original(store, case["id"], second["id"], USB_KEY, "Synthetic Operator", "Duplicado")
            with self.assertRaises(RIError):
                register_original(store, other["id"], first["id"], USB_KEY, "Bob", "Ajeno")
            self.assertTrue(store.verify()["valid"])
