import copy

from tests.common import ProjectTest
from ransomware_investigator.safety import RIError
from tools.priority_baselines import index_record_baselines, require_matching_record


def record(inode):
    return {'inode': inode, 'kind': 'record', 'sequence': 3, 'allocated': True,
            'directory': False, 'size_bytes': 119,
            'names': [{'name': 'SYNTHETIC.txt', 'parent_inode': 5}],
            'times_unix': {'created': 1000}, 'attributes': [], 'meta_type': 1}


class PriorityBaselineTests(ProjectTest):
    def test_record_omitted_from_selected_candidates_uses_complete_raw_baseline(self):
        raw = [record(inode) for inode in (5, 96, 99, 113)]
        selected = {row['inode']: row for row in raw if row['inode'] != 113}
        # Deterministic reproduction of the previous coordinator failure.
        with self.assertRaises(KeyError):
            selected[113]
        baselines = index_record_baselines((5, 96, 99, 113), raw)
        require_matching_record(record(113), baselines)
        self.assertEqual(set(baselines), {5, 96, 99, 113})

    def test_missing_baseline_is_rejected_during_preparation_not_on_a_later_read(self):
        with self.assertRaisesRegex(RIError, 'before authentication'):
            index_record_baselines((96, 113), [record(96)])

    def test_duplicate_raw_baseline_is_ambiguous_even_if_bytes_match(self):
        with self.assertRaisesRegex(RIError, 'duplicate'):
            index_record_baselines((113,), [record(113), record(113)])

    def test_filtered_report_shape_is_not_accepted_as_raw_records(self):
        with self.assertRaises(RIError):
            index_record_baselines((113,), [{'mft': 113, 'names_local_only': []}])

    def test_invalid_inode_and_incomplete_raw_record_fail_closed(self):
        for inode in (True, -1, '113', 2**63):
            with self.subTest(inode=inode), self.assertRaises(RIError):
                index_record_baselines((inode,), [])
        incomplete = record(113)
        del incomplete['times_unix']
        with self.assertRaises(RIError):
            index_record_baselines((113,), [incomplete])

    def test_every_changed_raw_field_is_rejected_not_only_priority_report_fields(self):
        original = record(113)
        baselines = index_record_baselines((113,), [original])
        for field, value in (('sequence', 4), ('allocated', False), ('directory', True),
                             ('size_bytes', 120), ('names', []), ('times_unix', {}),
                             ('attributes', [{'type': 128}]), ('meta_type', 2)):
            changed = {**original, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(RIError, 'differs'):
                require_matching_record(changed, baselines)

    def test_unknown_observed_record_is_not_silently_accepted(self):
        baselines = index_record_baselines((96,), [record(96)])
        with self.assertRaisesRegex(RIError, 'no verified baseline'):
            require_matching_record(record(113), baselines)

    def test_index_is_detached_and_does_not_modify_raw_records(self):
        raw = [record(113)]
        before = copy.deepcopy(raw)
        baselines = index_record_baselines((113,), raw)
        require_matching_record(raw[0], baselines)
        self.assertEqual(raw, before)
        baselines[113]['names'][0]['name'] = 'SYNTHETIC changed baseline'
        self.assertEqual(raw, before)
