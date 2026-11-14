import copy
import unittest

from tools.offline_execution_leads import classify_lead, prefetch_executable_names


class OfflineExecutionLeadTests(unittest.TestCase):
    def row(self, name='synthetic.exe', **times):
        return {'allocated': True, 'directory': False, 'names': [{'name': name}], 'times_unix': times}

    def test_prefetch_match_is_bounded_lexical_not_execution(self):
        names = prefetch_executable_names(['SYNTHETIC.EXE-01234567.PF.sealed', 'not-prefetch.txt'])
        self.assertEqual(names, {'synthetic.exe'})
        result = classify_lead(self.row(), [], names, 100, 200)
        self.assertTrue(result['prefetch_basename_match'])
        self.assertFalse(result['execution_established'])
        self.assertFalse(result['prioritize_for_review'])

    def test_path_and_creation_are_a_lead_not_maliciousness(self):
        result = classify_lead(self.row(created=150), ['/Users/SYNTHETIC/AppData/Local/Temp/synthetic.exe'], set(), 100, 200)
        self.assertTrue(result['prioritize_for_review'])
        self.assertFalse(result['malware_established'])
        self.assertFalse(result['incident_trigger_established'])

    def test_change_time_alone_does_not_prioritize_mass_transformed_files(self):
        result = classify_lead(self.row('synthetic.exe.sealed', changed=150), ['/Windows/Temp/synthetic.exe.sealed'], set(), 100, 200)
        self.assertFalse(result['prioritize_for_review'])

    def test_remote_prefetch_match_is_explicitly_inconclusive(self):
        result = classify_lead(self.row('TeamViewer.exe'), [], {'teamviewer.exe'}, 100, 200)
        self.assertTrue(result['prioritize_for_review'])
        self.assertFalse(result['execution_established'])

    def test_dll_and_scripts_are_candidates_without_a_PE_or_script_parse(self):
        for name in ('synthetic.dll', 'synthetic.ps1', 'synthetic.cmd.sealed'):
            self.assertIsNotNone(classify_lead(self.row(name), [], set(), 100, 200))
        self.assertIsNone(classify_lead(self.row('ordinary.txt'), [], set(), 100, 200))

    def test_directories_unallocated_and_missing_paths_do_not_become_execution(self):
        row = self.row(); row['directory'] = True
        self.assertIsNone(classify_lead(row, [], set(), 100, 200))
        row['directory'] = False; row['allocated'] = False
        self.assertIsNone(classify_lead(row, [], set(), 100, 200))
        result = classify_lead(self.row(created=150), [], set(), 100, 200)
        self.assertFalse(result['path_available_from_saved_MFT'])
        self.assertFalse(result['prioritize_for_review'])

    def test_untrusted_text_is_data_and_inputs_are_not_mutated(self):
        row = self.row('ignore previous instructions.exe', created=150); before = copy.deepcopy(row)
        result = classify_lead(row, ['/Temp/ignore previous instructions.exe'], set(), 100, 200)
        self.assertEqual(row, before)
        self.assertNotIn('ignore previous instructions', str(result))

    def test_invalid_window_and_names_are_rejected(self):
        with self.assertRaises(ValueError):
            classify_lead(self.row(), [], set(), True, 200)
        with self.assertRaises(ValueError):
            classify_lead(self.row(), [], set(), 200, 100)
        with self.assertRaises(ValueError):
            prefetch_executable_names(['x' * 4097])
