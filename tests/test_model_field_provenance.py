"""Model-field provenance reproductions using synthetic metadata only."""
import copy

from tests.common import ProjectTest
from tests.ntfs_support import PIN, state
from tests.test_inventory import bundle, USB_KEY
from ransomware_investigator.inventory import build_inventory, select_original
from ransomware_investigator.ntfs.physical import TriageError, validate_state


class ModelFieldProvenanceTests(ProjectTest):
    def inventory(self, raw):
        return build_inventory(raw, mode='simulated', workspace=str(self.work))

    def test_inventory_prefers_lsblk_model_and_preserves_distinct_cached_value(self):
        raw = bundle()
        raw['lsblk']['blockdevices'][1]['model'] = 'SYNTHETIC INVENTORY MODEL'
        raw['udev']['/dev/sda'] += '\nID_MODEL=SYNTHETIC_CACHED_MODEL\n'
        before = copy.deepcopy(raw)
        disk = select_original(self.inventory(raw), USB_KEY)
        self.assertEqual(disk['model'], 'SYNTHETIC INVENTORY MODEL')
        # Current identity_status does not compare these two model fields.
        self.assertEqual(disk['identity_status'], 'unique_observed')
        self.assertEqual(raw, before)

    def test_inventory_only_falls_back_to_cached_model_when_lsblk_model_is_missing(self):
        for missing in (None, ''):
            raw = bundle()
            raw['lsblk']['blockdevices'][1]['model'] = missing
            raw['udev']['/dev/sda'] += '\nID_MODEL=SYNTHETIC_CACHED_MODEL\n'
            with self.subTest(missing=missing):
                disk = select_original(self.inventory(raw), USB_KEY)
                self.assertEqual(disk['model'], 'SYNTHETIC_CACHED_MODEL')

    def test_equal_wwid_serial_and_geometry_do_not_override_a_model_mismatch(self):
        observed = {**state(), 'model': 'SYNTHETIC TRANSPORT MODEL'}
        before = copy.deepcopy(observed)
        for field in ('wwid', 'serial', 'disk_size_bytes', 'sector_size',
                      'partition_size_bytes', 'partition_uuid'):
            self.assertEqual(observed[field], PIN[field])
        with self.assertRaisesRegex(TriageError, 'Identidad persistente o geometría'):
            validate_state(PIN, observed)
        self.assertEqual(observed, before)
