"""Two observed model views retain strict pin matching and immutable provenance."""
from tests.common import ProjectTest
from tests.ntfs_support import PIN, state
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.ntfs import physical
from ransomware_investigator.ntfs_triage import register_device
from ransomware_investigator.safety import RIError


class TransportIdentityViewTests(ProjectTest):
    def test_registered_original_model_mismatch_still_rejects_without_overwriting(self):
        with CaseStore(self.work / 'workspace') as store:
            case = store.create_case('synthetic', 'Synthetic Operator', 'Synthetic Operator')
            original = store.record('evidence', case['id'], {
                'identity_key': 'synthetic-original', 'mode': 'metadata', 'status': 'original_registered',
                'device_snapshot': {'model': PIN['model'], 'serial': PIN['serial'],
                    'size_bytes': PIN['disk_size_bytes'], 'logical_sector_bytes': PIN['sector_size'],
                    'protection_reasons': [], 'wwn': None}}, 'Synthetic Operator')
            pin = {**PIN, 'model': 'SYNTHETIC TRANSPORT VIEW'}
            with self.assertRaises(RIError):
                register_device(store, case['id'], source_id=original['id'], pin=pin,
                                actor='Synthetic Operator', reason='Synthetic mismatch must fail')
            self.assertEqual(store.get('evidence', original['id']), original)

    def test_separate_declared_view_links_original_but_never_weakens_kernel_comparison(self):
        with CaseStore(self.work / 'workspace') as store:
            case = store.create_case('synthetic', 'Synthetic Operator', 'Synthetic Operator')
            original = store.record('evidence', case['id'], {
                'identity_key': 'synthetic-original', 'mode': 'metadata', 'status': 'original_registered',
                'device_snapshot': {'model': PIN['model'], 'serial': PIN['serial'],
                    'size_bytes': PIN['disk_size_bytes'], 'logical_sector_bytes': PIN['sector_size'],
                    'protection_reasons': [], 'wwn': None}}, 'Synthetic Operator')
            view = store.record('evidence', case['id'], {
                'identity_key': 'synthetic-declared-transport-view', 'mode': 'declared',
                'status': 'source_declared', 'source_kind': 'physical-device',
                'source_evidence_id': original['id'], 'reference': 'SYNTHETIC identity observation only',
                'provenance_status': 'declared association, not physical-original authentication'}, 'Synthetic Operator')
            pin = {**PIN, 'model': 'SYNTHETIC TRANSPORT VIEW'}
            source = register_device(store, case['id'], source_id=view['id'], pin=pin,
                                     actor='Synthetic Operator', reason='Synthetic independently observed model view')
            self.assertEqual(source['source_evidence_id'], view['id'])
            self.assertEqual(store.get('evidence', view['id'])['source_evidence_id'], original['id'])
            self.assertEqual(store.get('evidence', original['id']), original)
            with self.assertRaises(physical.TriageError):
                physical.validate_state(pin, state())
            physical.validate_state(pin, {**state(), 'model': pin['model']})
