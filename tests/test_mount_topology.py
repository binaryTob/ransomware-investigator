"""Synthetic regressions for overlapping mount classification; no host probes."""
import copy
from unittest.mock import patch

from tests.common import ProjectTest
from tests.test_inventory import USB_KEY, bundle
from tests.test_preflight import destination
from ransomware_investigator.inventory import build_inventory, select_original
from ransomware_investigator.preflight import assess
from ransomware_investigator.safety import RIError


TARGET = "/proc/sys/fs/binfmt_misc"


def pseudo_stack():
    # Synthetic mount metadata, not a copy of the operator's inventory.
    return [
        {"source": "systemd-1", "target": TARGET, "fstype": "autofs",
         "options": "rw,relatime,direct", "maj:min": "0:701"},
        {"source": "binfmt_misc", "target": TARGET, "fstype": "binfmt_misc",
         "options": "rw,nosuid,nodev,noexec", "maj:min": "0:702"},
    ]


class MountTopologyTests(ProjectTest):
    def build(self, raw, workspace=None):
        return build_inventory(raw, mode="simulated", workspace=workspace or str(self.work))

    def stacked_bundle(self):
        raw = bundle()
        raw["findmnt"]["filesystems"].extend(pseudo_stack())
        return raw

    def test_known_binfmt_stack_is_retained_without_blocking_unrelated_disks(self):
        raw = self.stacked_bundle()
        original = copy.deepcopy(raw)
        with patch("builtins.open", side_effect=AssertionError("Pure metadata parsing only")):
            inv = self.build(raw)
        self.assertTrue(inv["topology_complete"])
        self.assertEqual(raw, original)
        self.assertEqual(len([m for m in inv["mounts"] if m["target"] == TARGET]), 2)
        warning = inv["topology_warnings"][0]
        self.assertEqual(warning["code"], "known_binfmt_pseudo_mount_stack")
        self.assertEqual(warning["maj_min"], ["0:701", "0:702"])
        self.assertFalse(select_original(inv, USB_KEY)["mounts"])
        internal = next(d for d in inv["devices"] if d["path"] == "/dev/nvme0n1")
        self.assertTrue(internal["protection_reasons"])
        self.assertEqual([m["device_path"] for m in inv["mounts"] if m["target"] == TARGET], [None, None])

    def test_unknown_or_block_backed_overlaps_remain_blocked(self):
        for target in ("/", "/boot/efi", "/media/SYNTHETIC", TARGET):
            for majors in (("8:1", "8:3"), ("0:701", "0:702")):
                raw = bundle()
                rows = pseudo_stack()
                for row, major in zip(rows, majors):
                    row.update(target=target, source="unknown", fstype="tmpfs", **{"maj:min": major})
                raw["findmnt"]["filesystems"].extend(rows)
                with self.subTest(target=target, majors=majors):
                    inv = self.build(raw)
                    self.assertFalse(inv["topology_complete"])
                    self.assertIn("ambiguous_overlapping_mount_targets", inv["collection_errors"])
                    with self.assertRaises(RIError): select_original(inv, USB_KEY)

    def test_matching_type_labels_never_hide_block_sources_or_unknown_major_minor(self):
        modifications = [
            {"source": "/dev/sda3"}, {"fstype": "ntfs"}, {"maj:min": "8:3"},
            {"maj:min": None}, {"maj:min": "0:0"}, {"maj:min": "0:garbage"},
        ]
        for index in (0, 1):
            for change in modifications:
                raw = self.stacked_bundle()
                raw["findmnt"]["filesystems"][-2 + index].update(change)
                with self.subTest(index=index, change=change):
                    self.assertFalse(self.build(raw)["topology_complete"])
        raw = self.stacked_bundle()
        raw["lsblk"]["blockdevices"][1]["children"][2]["maj:min"] = "0:702"
        self.assertFalse(self.build(raw)["topology_complete"])

    def test_duplicate_same_row_extra_layer_and_same_superblock_remain_ambiguous(self):
        for variant in ("duplicate", "third_layer", "same_major"):
            raw = self.stacked_bundle()
            rows = raw["findmnt"]["filesystems"]
            if variant == "duplicate": rows[-1] = copy.deepcopy(rows[-2])
            elif variant == "third_layer": rows.append(copy.deepcopy(rows[-1]))
            else: rows[-1]["maj:min"] = rows[-2]["maj:min"]
            with self.subTest(variant=variant):
                self.assertFalse(self.build(raw)["topology_complete"])

    def test_stack_at_other_path_or_over_protected_location_is_not_exempt(self):
        raw = self.stacked_bundle()
        for row in raw["findmnt"]["filesystems"][-2:]: row["target"] = "/media/SYNTHETIC"
        self.assertFalse(self.build(raw)["topology_complete"])
        raw = self.stacked_bundle()
        self.assertFalse(self.build(raw, workspace=TARGET + "/case")["topology_complete"])
        raw["swaps"] = [TARGET + "/swapfile"]
        self.assertFalse(self.build(raw)["topology_complete"])

    def test_warning_does_not_mask_other_collection_errors_or_mounted_evidence(self):
        raw = self.stacked_bundle()
        raw["collection_errors"] = ["synthetic_missing_metadata"]
        self.assertFalse(self.build(raw)["topology_complete"])
        raw = self.stacked_bundle()
        raw["findmnt"]["filesystems"].append({"source": "/dev/sda3", "target": "/media/SYNTHETIC",
            "fstype": "ntfs", "options": "ro", "maj:min": "8:3"})
        inv = self.build(raw)
        inv.update(id="a" * 32, case_id="b" * 32)
        report = assess(inv, USB_KEY, destination(), latest_inventory_id=inv["id"])
        self.assertIn("SOURCE_UNMOUNTED", report["blockers"])
        self.assertFalse(report["acquisition_allowed"])

    def test_all_device_exclusions_ro_and_mounts_are_unchanged_by_known_stack(self):
        before = self.build(bundle())
        after = self.build(self.stacked_bundle())
        self.assertEqual(before["devices"], after["devices"])
        self.assertEqual(before["swaps"], after["swaps"])
        self.assertEqual(after["collection_errors"], [])
        with self.assertRaises(RIError): select_original(after, "wwn:5000000000000001")
