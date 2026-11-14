"""Explicit small-content approval profile; synthetic state, never real IO."""
import copy
import json
from unittest.mock import patch

from tests.common import ProjectTest
from tests import test_sequence_approval as sequence_tests
from tests.test_sequence_approval import installer, authorization, rehash, session_plan
from ransomware_investigator.ntfs import core, physical


def content_authorization(scopes=('ntfs.extract', 'ntfs.prefix')):
    auth = authorization(len(scopes))
    auth['approval_profile'] = 'selective_content_v1'
    for index, (batch, scope) in enumerate(zip(auth['sequence']['batches'], scopes)):
        request = batch['requests'][0]
        request['scope'] = scope
        request['parameters'] = core.parameters(scope, {
            'inode': 100 + index, 'attribute_id': 3, 'max_entries': 1,
            'expected_sequence': 1, 'expected_size': 119 if scope == 'ntfs.extract' else 406763,
            'max_bytes': 119 if scope == 'ntfs.extract' else 65536,
            'read_budget': 64 * 1024**2, 'timeout_ms': 10000})
    return rehash(auth)


class SelectiveContentPolicyTests(ProjectTest):
    def check(self, auth):
        return installer.validate_sequence_authorization(rehash(auth), auth['sequence']['requesting_uid'])

    def test_explicit_profile_accepts_only_small_exact_extractions_and_prefixes(self):
        auth = content_authorization()
        self.assertEqual(len(self.check(auth)), 2)
        plan, _ = session_plan(auth)
        installer.validate_plan(plan)

    def test_default_metadata_profile_still_rejects_both_content_scopes(self):
        for scope in ('ntfs.extract', 'ntfs.prefix'):
            auth = content_authorization((scope,))
            del auth['approval_profile']
            with self.subTest(scope=scope), self.assertRaises(installer.InstallError):
                self.check(auth)

    def test_content_profile_does_not_accept_metadata_or_other_operations(self):
        for scope in ('ntfs.volume', 'ntfs.records', 'ntfs.directory', 'ntfs.list', 'ntfs.mft'):
            auth = content_authorization(('ntfs.extract',))
            auth['sequence']['batches'][0]['requests'][0]['scope'] = scope
            with self.subTest(scope=scope), self.assertRaises(installer.InstallError):
                self.check(auth)

    def test_profile_does_not_relax_case_uid_nonce_or_batch_source_binding(self):
        for mutation in ('case', 'uid', 'duplicate', 'image', 'mixed_source'):
            auth = content_authorization()
            request = auth['sequence']['batches'][1]['requests'][0]
            if mutation == 'case':
                request['case_id'] = 'd' * 32
            elif mutation == 'uid':
                request['uid'] = 0
            elif mutation == 'duplicate':
                request['request_id'] = auth['sequence']['batches'][0]['requests'][0]['request_id']
            elif mutation == 'image':
                request['source'] = {'kind': 'image', 'path': '/SYNTHETIC'}
            else:
                batch = auth['sequence']['batches'][0]
                other = copy.deepcopy(batch['requests'][0])
                other['request_id'], other['source_id'] = 'd' * 32, 'e' * 32
                batch['requests'].append(other)
                batch['request_count'] += 1
                auth['sequence']['request_count'] += 1
            with self.subTest(mutation=mutation), self.assertRaises(installer.InstallError):
                self.check(auth)

    def test_unknown_profile_and_additional_permission_keys_are_rejected(self):
        for value in (None, '', True, 'selective_content_v2', {'allow_all': True}):
            auth = content_authorization()
            auth['approval_profile'] = value
            with self.subTest(value=value), self.assertRaises(installer.InstallError):
                self.check(auth)
        auth = content_authorization()
        auth['allow_full_acquisition'] = True
        with self.assertRaises(installer.InstallError):
            self.check(auth)

    def test_all_parameters_are_explicit_and_no_extra_command_is_accepted(self):
        for mutation in ('missing', 'extra'):
            auth = content_authorization(('ntfs.extract',))
            params = auth['sequence']['batches'][0]['requests'][0]['parameters']
            if mutation == 'missing':
                del params['attribute_id']
            else:
                params['command'] = 'SYNTHETIC never executed'
            with self.subTest(mutation=mutation), self.assertRaises(installer.InstallError):
                self.check(auth)

    def test_deleted_recursive_unbounded_and_boolean_numeric_requests_fail_closed(self):
        mutations = (('inode', 15), ('inode', True), ('attribute_id', -1), ('attribute_id', 65536),
            ('expected_sequence', 0), ('expected_sequence', True), ('expected_size', 0),
            ('expected_size', 2**63), ('allow_deleted', True), ('allow_deleted', 0),
            ('max_depth', 1), ('max_depth', False), ('max_entries', 1000),
            ('read_budget', 64 * 1024**2 + 1), ('read_budget', True),
            ('timeout_ms', 10001), ('extensions', ['.exe']))
        for key, value in mutations:
            auth = content_authorization(('ntfs.extract',))
            auth['sequence']['batches'][0]['requests'][0]['parameters'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(installer.InstallError):
                self.check(auth)

    def test_extraction_requires_exact_full_stream_size_not_partial_fragmentation(self):
        for maximum in (118, 120, 1024**2 + 1):
            auth = content_authorization(('ntfs.extract',))
            auth['sequence']['batches'][0]['requests'][0]['parameters']['max_bytes'] = maximum
            with self.subTest(maximum=maximum), self.assertRaises(installer.InstallError):
                self.check(auth)

    def test_large_source_can_only_supply_at_most_64kib_prefix(self):
        auth = content_authorization(('ntfs.prefix',))
        params = auth['sequence']['batches'][0]['requests'][0]['parameters']
        params['expected_size'] = 3 * 1024**3
        self.check(auth)
        params['max_bytes'] = 65537
        with self.assertRaises(installer.InstallError):
            self.check(auth)
        params['max_bytes'], params['expected_size'] = 1024, 100
        with self.assertRaises(installer.InstallError):
            self.check(auth)

    def test_total_output_is_capped_at_one_mib_across_all_batches(self):
        auth = content_authorization(('ntfs.extract', 'ntfs.extract'))
        for batch in auth['sequence']['batches']:
            p = batch['requests'][0]['parameters']
            p['expected_size'] = p['max_bytes'] = 512 * 1024
        self.check(auth)
        params = auth['sequence']['batches'][1]['requests'][0]['parameters']
        params['expected_size'] += 1
        params['max_bytes'] += 1
        with self.assertRaises(installer.InstallError):
            self.check(auth)

    def test_at_most_eight_content_requests_in_the_whole_sequence(self):
        self.check(content_authorization(('ntfs.extract',) * 8))
        with self.assertRaises(installer.InstallError):
            self.check(content_authorization(('ntfs.extract',) * 9))

    def test_prior_expired_metadata_grants_can_be_explicitly_preserved(self):
        auth = content_authorization()
        old = copy.deepcopy(authorization(1)['sequence']['batches'][0]['requests'][0])
        old['request_id'] = 'e' * 32
        auth['preserved_expired_approvals'] = [{'request': old, 'expires_at': 1000.0,
                                               'failed_execution_id': 'f' * 32}]
        self.check(auth)
        # The new profile does not silently broaden expired-grant exceptions.
        old['scope'] = 'ntfs.extract'
        with self.assertRaises(installer.InstallError):
            self.check(auth)


class SelectiveContentSessionTests(ProjectTest):
    def test_one_courier_approves_exact_typed_content_without_source_io(self):
        auth = content_authorization()
        with patch.object(physical, 'probe_physical', side_effect=AssertionError('No device IO')):
            broker, sent, prefix, receipt = sequence_tests.SessionServerTests.serve(self,
                [{'action': 'approve-next', 'ordinal': 1}, {'action': 'approve-next', 'ordinal': 2},
                 {'action': 'finish'}], auth)
        self.assertEqual(broker.approve_request.call_count, 2)
        self.assertEqual([call.args[2]['scope'] for call in broker.approve_request.call_args_list],
                         ['ntfs.extract', 'ntfs.prefix'])
        self.assertEqual(receipt['status'], 'sequence_session_completed')
        self.assertFalse(receipt['physical_device_reads'])
        self.assertFalse(receipt['installed_code_changed'])
        self.assertEqual([len(call.args[0]) for call in prefix.call_args_list], [0, 0, 1, 2])
        self.assertEqual(sent[0]['status'], 'approval_session_ready')

    def test_content_profile_uses_unchanged_exact_five_minute_legacy_grant(self):
        auth = content_authorization(('ntfs.extract',))
        _, _, _, receipt = sequence_tests.SessionServerTests.serve(self,
            [{'action': 'approve-next', 'ordinal': 1}, EOFError('SYNTHETIC disconnect')], auth, actual_grants=True)
        grants = list((self.work / 'state' / 'approved').iterdir())
        self.assertEqual(len(grants), 1)
        grant = json.loads(grants[0].read_bytes())
        self.assertEqual(grant['request'], auth['sequence']['batches'][0]['requests'][0])
        self.assertAlmostEqual(grant['expires_at'] - grant['approved_at'], 300, delta=0.01)
        self.assertFalse(receipt['physical_device_reads'])
