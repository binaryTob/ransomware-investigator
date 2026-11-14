"""Exact expired-grant preservation; synthetic state only, never real root IO."""
import copy
import json
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tests.common import ProjectTest
from tests.test_sequence_approval import installer, authorization, rehash, session_plan
from tests.test_ntfs_broker import broker as legacy_broker
from ransomware_investigator.ntfs import core, physical


def preserved(auth):
    old = copy.deepcopy(auth['sequence']['batches'][0]['requests'][0])
    old['request_id'] = 'e' * 32
    return {'request': old, 'expires_at': 1000.0, 'failed_execution_id': 'f' * 32}


class PreservedApprovalPolicyTests(ProjectTest):
    def test_explicit_bounded_list_rejects_duplicate_empty_and_ambiguous_declarations(self):
        auth = authorization()
        first = preserved(auth)
        second = copy.deepcopy(first)
        second['request']['request_id'] = 'd' * 32
        auth['preserved_expired_approvals'] = [first, second]
        installer.validate_sequence_authorization(auth, auth['sequence']['requesting_uid'])
        for invalid in ([], [first, first], [first] * 9):
            changed = copy.deepcopy(auth)
            changed['preserved_expired_approvals'] = invalid
            with self.subTest(invalid_count=len(invalid)), self.assertRaises(installer.InstallError):
                installer.validate_sequence_authorization(changed, changed['sequence']['requesting_uid'])
        auth['preserved_expired_approval'] = first
        with self.assertRaises(installer.InstallError):
            installer.validate_sequence_authorization(auth, auth['sequence']['requesting_uid'])

    def test_explicit_feature_is_valid_but_cannot_reuse_the_old_nonce(self):
        auth = authorization()
        auth['preserved_expired_approval'] = preserved(auth)
        installer.validate_sequence_authorization(auth, auth['sequence']['requesting_uid'])
        auth['preserved_expired_approval']['request']['request_id'] = auth['sequence']['batches'][0]['requests'][0]['request_id']
        with self.assertRaises(installer.InstallError):
            installer.validate_sequence_authorization(auth, auth['sequence']['requesting_uid'])

    def test_malformed_or_cross_case_or_content_exception_is_rejected(self):
        for change in ('uid', 'case', 'content', 'expiry', 'extra', 'failure'):
            auth = authorization()
            item = preserved(auth)
            auth['preserved_expired_approval'] = item
            if change == 'uid': item['request']['uid'] = 0
            elif change == 'case': item['request']['case_id'] = 'd' * 32
            elif change == 'content': item['request']['scope'] = 'ntfs.extract'
            elif change == 'expiry': item['expires_at'] = True
            elif change == 'extra': item['allow_any_expired'] = True
            else: item['failed_execution_id'] = 'arbitrary-path'
            with self.subTest(change=change), self.assertRaises(installer.InstallError):
                installer.validate_sequence_authorization(auth, auth['sequence']['requesting_uid'])


class PreservedApprovalStateTests(ProjectTest):
    def second_grant(self, *, active=False):
        item = copy.deepcopy(self.item)
        item['request']['request_id'] = 'd' * 32
        request = item['request']
        grant = {**self.grant, 'request': request, 'request_sha256': installer.sha(installer.canonical(request))}
        if active:
            item['expires_at'] = grant['expires_at'] = 1100.0
            grant['approved_at'] = 800.0
        path = self.state / 'approved' / (request['request_id'] + '.json')
        installer.write_new(path, installer.canonical(grant))
        self.events.append({'action': 'approved', 'request_id': request['request_id'],
                            'request_sha256': grant['request_sha256'], 'uid': request['uid']})
        self.write_ledger()
        return item, path

    def setUp(self):
        super().setUp()
        self.state = self.work / 'state'
        self.state.mkdir(mode=0o700)
        (self.state / 'approved').mkdir(mode=0o700)
        (self.state / 'used').mkdir(mode=0o700)
        self.item = preserved(authorization())
        self.request = self.item['request']
        self.path = self.state / 'approved' / (self.request['request_id'] + '.json')
        self.grant = {'request': self.request, 'request_sha256': installer.sha(installer.canonical(self.request)),
                      'approved_uid': self.request['uid'], 'administrator_uid': 0,
                      'approved_at': 700.0, 'expires_at': 1000.0}
        self.save(self.grant)
        self.events = [{'action': 'approved', 'request_id': self.request['request_id'],
                        'request_sha256': self.grant['request_sha256'], 'uid': self.request['uid']}]
        self.write_ledger()

    def save(self, value):
        if self.path.exists(): self.path.unlink()  # Exact synthetic test fixture only.
        installer.write_new(self.path, installer.canonical(value))

    def write_ledger(self):
        target = self.state / 'audit.jsonl'
        if target.exists(): target.unlink()  # Exact synthetic test fixture only.
        previous = '0' * 64
        rows = []
        for item in self.events:
            event = {**item, 'previous_sha256': previous}
            previous = installer.sha(installer.canonical(event))
            rows.append(installer.canonical({'event': event, 'sha256': previous}))
        installer.write_new(target, b'\n'.join(rows) + (b'\n' if rows else b''))

    @contextmanager
    def root_metadata(self):
        real_lstat = installer.Path.lstat
        def metadata(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            return SimpleNamespace(st_uid=0, st_mode=info.st_mode, st_nlink=info.st_nlink)
        with patch.object(installer, 'STATE', self.state), \
                patch.object(installer.Path, 'lstat', autospec=True, side_effect=metadata), \
                patch.object(installer.time, 'time', return_value=1001.0):
            yield

    def test_default_remains_strict_even_for_an_expired_grant(self):
        with self.root_metadata(), self.assertRaises(installer.InstallError):
            installer.idle_state()

    def test_two_explicit_expired_grants_remain_unchanged_and_not_completed_prefix(self):
        second, path = self.second_grant()
        before = [target.stat() for target in (self.path, path)]
        with self.root_metadata():
            ledger, used = installer.idle_state(preserved_expired_approvals=[second, self.item])
            with self.assertRaises(installer.InstallError):
                installer.require_completed_sequence_requests([self.request], ledger, used)
            with self.assertRaises(installer.InstallError):
                installer.idle_state()
        after = [target.stat() for target in (self.path, path)]
        for left, right in zip(before, after):
            self.assertEqual((left.st_ino, left.st_size, left.st_mtime_ns, left.st_ctime_ns, left.st_atime_ns),
                             (right.st_ino, right.st_size, right.st_mtime_ns, right.st_ctime_ns, right.st_atime_ns))

    def test_one_active_grant_in_explicit_list_blocks_the_entire_session(self):
        second, _ = self.second_grant(active=True)
        with self.root_metadata(), self.assertRaises(installer.InstallError):
            installer.idle_state(preserved_expired_approvals=[self.item, second])

    def test_session_audits_each_exact_preserved_grant_without_mutation(self):
        second, path = self.second_grant()
        auth = authorization()
        auth['preserved_expired_approvals'] = [self.item, second]
        installer.validate_sequence_authorization(auth, auth['sequence']['requesting_uid'])
        audit = Mock()
        before = [target.stat() for target in (self.path, path)]
        with self.root_metadata():
            ledger, used = installer._approval_session_idle(auth, audit)
        self.assertTrue(ledger)
        self.assertEqual(used, {})
        self.assertEqual(audit.event.call_count, 2)
        for call, item in zip(audit.event.call_args_list, (self.item, second)):
            self.assertEqual(call.args, ('exact_expired_approval_preserved_without_renewal',))
            self.assertEqual(call.kwargs['request_id'], item['request']['request_id'])
            self.assertEqual(call.kwargs['request_sha256'], installer.sha(installer.canonical(item['request'])))
            self.assertEqual(call.kwargs['failed_execution_id'], item['failed_execution_id'])
            self.assertEqual(call.kwargs['expiry'], item['expires_at'])
            for field in ('grant_changed', 'nonce_consumed', 'source_opened'):
                self.assertIs(call.kwargs[field], False)
        for left, target in zip(before, (self.path, path)):
            right = target.stat()
            self.assertEqual((left.st_ino, left.st_size, left.st_mtime_ns, left.st_ctime_ns, left.st_atime_ns),
                             (right.st_ino, right.st_size, right.st_mtime_ns, right.st_ctime_ns, right.st_atime_ns))

    def test_session_does_not_audit_preservation_until_entire_list_is_valid(self):
        second, _ = self.second_grant(active=True)
        auth = authorization()
        auth['preserved_expired_approvals'] = [self.item, second]
        audit = Mock()
        with self.root_metadata(), self.assertRaises(installer.InstallError):
            installer._approval_session_idle(auth, audit)
        audit.event.assert_not_called()

    def test_extra_unlisted_grant_is_rejected_even_when_two_explicit_grants_are_expired(self):
        second, _ = self.second_grant()
        installer.write_new(self.state / 'approved' / ('c' * 32 + '.json'), b'{}')
        with self.root_metadata(), self.assertRaises(installer.InstallError):
            installer.idle_state(preserved_expired_approvals=[self.item, second])

    def test_exact_unused_expired_grant_is_preserved_without_metadata_changes(self):
        before = self.path.stat()
        with self.root_metadata():
            ledger, used = installer.idle_state(preserved_expired_approval=self.item)
        after = self.path.stat()
        self.assertTrue(ledger)
        self.assertEqual(used, {})
        self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_atime_ns),
                         (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_atime_ns))
        self.assertEqual(json.loads(self.path.read_bytes()), self.grant)

    def test_active_grant_unknown_grant_missing_grant_or_used_nonce_is_rejected(self):
        for change in ('active', 'unknown', 'missing', 'used'):
            with self.subTest(change=change):
                extra = self.state / 'approved' / ('d' * 32 + '.json')
                used = self.state / 'used' / self.path.name
                if change == 'active': self.item['expires_at'] = 1100.0; self.save({**self.grant, 'expires_at': 1100.0, 'approved_at': 800.0})
                elif change == 'unknown': installer.write_new(extra, b'{}')
                elif change == 'missing': self.path.unlink()
                else: installer.write_new(used, b'{}')
                with self.root_metadata(), self.assertRaises(installer.InstallError):
                    installer.idle_state(preserved_expired_approval=self.item)
                for path in (extra, used):
                    if path.exists(): path.unlink()
                self.item['expires_at'] = 1000.0
                self.save(self.grant)

    def test_mismatched_grant_fields_fail_closed(self):
        for change in ({'request_sha256': '0' * 64}, {'administrator_uid': False}, {'approved_uid': 0},
                       {'approved_at': 0.0}, {'expires_at': 999.0}, {'request': {}}):
            self.save({**self.grant, **change})
            with self.subTest(change=change), self.root_metadata(), self.assertRaises(installer.InstallError):
                installer.idle_state(preserved_expired_approval=self.item)

    def test_root_ledger_must_prove_exactly_one_approval_and_no_consumption(self):
        original = list(self.events)
        for change in ('missing', 'duplicate', 'consumed', 'different_hash'):
            self.events = copy.deepcopy(original)
            if change == 'missing': self.events = []
            elif change == 'duplicate': self.events += copy.deepcopy(original)
            elif change == 'consumed': self.events.append({'action': 'authorization_consumed', 'request_id': self.request['request_id']})
            else: self.events[0]['request_sha256'] = '0' * 64
            self.write_ledger()
            with self.subTest(change=change), self.root_metadata(), self.assertRaises(installer.InstallError):
                installer.idle_state(preserved_expired_approval=self.item)

    def test_expired_grant_remains_unusable_by_the_unchanged_broker(self):
        with patch.object(legacy_broker, 'STATE', self.state), \
                patch.object(legacy_broker, 'read_json_file', return_value=self.grant), \
                patch.object(legacy_broker.time, 'time', return_value=1001.0), \
                patch.object(legacy_broker.os, 'rename') as rename:
            with self.assertRaisesRegex(ValueError, 'expired'):
                legacy_broker.consume(core, physical, self.request, self.request['uid'])
        rename.assert_not_called()

    def test_noatime_denial_does_not_fallback(self):
        real_open = installer.os.open
        calls = []
        def denied(path, flags, *args, **kwargs):
            if installer.Path(path) == self.path:
                calls.append(flags)
                raise PermissionError('Synthetic O_NOATIME denied')
            return real_open(path, flags, *args, **kwargs)
        with self.root_metadata(), patch.object(installer.os, 'open', side_effect=denied), \
                self.assertRaises(PermissionError):
            installer.idle_state(preserved_expired_approval=self.item)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0] & installer.os.O_NOATIME)

    def test_session_validates_expired_baseline_without_approving_or_opening_sources(self):
        from contextlib import ExitStack
        auth = authorization(1)
        auth['preserved_expired_approval'] = self.item
        plan, _ = session_plan(auth)
        review = self.work / 'review'
        review.mkdir()
        audit = installer.Audit(review)
        broker = SimpleNamespace(load_core=lambda: (core, physical, None), approve_request=Mock())
        loader = SimpleNamespace(exec_module=lambda module: None)
        sent = []
        before = self.path.stat()
        with self.root_metadata(), ExitStack() as stack:
            for name in ('verify_dependencies', 'host_prechecks', 'existing_update_baseline'):
                stack.enter_context(patch.object(installer, name))
            stack.enter_context(patch.object(installer, 'trusted', side_effect=lambda path: path))
            stack.enter_context(patch.object(installer.importlib.util, 'spec_from_file_location',
                                            return_value=SimpleNamespace(loader=loader)))
            stack.enter_context(patch.object(installer.importlib.util, 'module_from_spec', return_value=broker))
            stack.enter_context(patch.object(installer, '_session_receive', side_effect=EOFError('Synthetic disconnect')))
            stack.enter_context(patch.object(installer, '_session_send', side_effect=lambda fd, value: sent.append(value)))
            try:
                installer.serve_approval_session(plan, review, 'a' * 64, audit)
            finally:
                installer.os.close(audit.fd)
        after = self.path.stat()
        self.assertEqual(sent[0]['status'], 'approval_session_ready')
        self.assertEqual(sent[-1]['status'], 'sequence_session_stopped')
        broker.approve_request.assert_not_called()
        self.assertEqual((before.st_ino, before.st_size, before.st_mtime_ns, before.st_atime_ns),
                         (after.st_ino, after.st_size, after.st_mtime_ns, after.st_atime_ns))
