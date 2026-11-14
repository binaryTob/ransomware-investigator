"""Code-update preservation opt-in: synthetic private state and mocked admin IO."""
import copy
import io
import json
import os
import stat
from contextlib import ExitStack, contextmanager, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.common import ROOT, ProjectTest
from tests.test_broker_installer import installer, plan
from tests.test_broker_update import update_plan
from tests.test_ntfs_broker import request, broker
from ransomware_investigator.ntfs import core, physical
from tests.test_sequence_approval import session_plan


class UpdatePreservationTests(ProjectTest):
    def setUp(self):
        super().setUp()
        self.state=self.work/'state'; self.state.mkdir(mode=0o700)
        for name in ('approved','used'): (self.state/name).mkdir(mode=0o700)
        self.events=[]
        self.items=[]
        for index,scope in enumerate(('ntfs.records','ntfs.extract')):
            params={'inode':66,'max_entries':1}
            if scope=='ntfs.extract': params.update(expected_sequence=1,expected_size=8,max_bytes=8)
            req=request(scope,params); req['request_id']=str(index+1)*32
            grant={'request':req,'request_sha256':installer.sha(installer.canonical(req)),
                   'approved_uid':os.getuid(),'administrator_uid':0,'approved_at':700.0,'expires_at':1000.0,
                   'reason':'SYNTHETIC old grant, never executed'}
            raw=installer.canonical(grant)
            path=self.state/'approved'/(req['request_id']+'.json')
            installer.write_new(path,raw)
            self.items.append({'request':req,'expires_at':1000.0,'failed_execution_id':'f'*32,
                               'grant_sha256':installer.sha(raw)})
            self.events.append({'action':'approved','request_id':req['request_id'],
                                'request_sha256':grant['request_sha256'],'uid':os.getuid()})
        self.ledger()
        self.doc,self.payloads=update_plan()
        self.doc['preserved_expired_approvals']=copy.deepcopy(self.items)
        # New explicit actions cannot be confused with the strict legacy plan.
        self.doc['actions']=[
            'verify_installed_baseline_and_dependencies','require_idle_preserve_exact_expired_grants',
            'stop_existing_service','backup_reviewed_code','replace_changed_code_only','start_service',
            'test_parser_loader_as_unprivileged_uid','test_socket_denial_without_grant',
            'verify_preserved_nonce_state_and_ledger','verify_preserved_expired_grants_unchanged','write_admin_receipt']

    def ledger(self):
        previous='0'*64; rows=[]
        for event in self.events:
            value={**event,'previous_sha256':previous}; previous=installer.sha(installer.canonical(value))
            rows.append(installer.canonical({'event':value,'sha256':previous}))
        path=self.state/'audit.jsonl'
        path.write_bytes(b'\n'.join(rows)+b'\n'); path.chmod(0o600)

    @contextmanager
    def state_context(self):
        original=Path.lstat
        def metadata(path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            return SimpleNamespace(**{**{k:getattr(info,k) for k in dir(info) if k.startswith('st_')},
                                      'st_uid':0,'st_gid':0})
        with patch.object(installer,'STATE',self.state), patch.object(Path,'lstat',metadata), \
                patch.object(installer.time,'time',return_value=1001.0):
            yield

    def path(self,index=0):
        return self.state/'approved'/(self.items[index]['request']['request_id']+'.json')

    def change(self,index,**fields):
        path=self.path(index); grant=json.loads(installer.read_regular(path,noatime=True))
        grant.update(fields); path.write_bytes(installer.canonical(grant))

    def facts(self):
        result={}
        for path in sorted((self.state/'approved').iterdir()):
            info=path.stat(); raw=installer.read_regular(path,noatime=True)
            result[path.name]=(installer.sha(raw),installer.identity(info),info.st_atime_ns,info.st_mode)
        return result

    def test_exact_opt_in_including_old_content_is_valid_update_only(self):
        installer.validate_plan(self.doc)
        legacy,_=update_plan(); installer.validate_plan(legacy)
        for doc in (plan()[0],session_plan()[0]):
            doc['preserved_expired_approvals']=self.items
            with self.assertRaises(installer.InstallError): installer.validate_plan(doc)
        bad=copy.deepcopy(self.doc); bad['actions']=list(installer.UPDATE_ACTIONS)
        with self.assertRaises(installer.InstallError): installer.validate_plan(bad)

    def test_policy_rejects_empty_duplicate_unbounded_unknown_and_boolean_fields(self):
        for items in ([],self.items*5,[self.items[0]]*2,True,{'allow_any_expired':True}):
            bad=copy.deepcopy(self.doc); bad['preserved_expired_approvals']=items
            with self.subTest(items=type(items).__name__),self.assertRaises(installer.InstallError): installer.validate_plan(bad)
        for field,value in (('grant_sha256','bad'),('grant_sha256',True),('expires_at',True),
                            ('expires_at',float('nan')),('expires_at',float('inf')),('failed_execution_id','../x'),
                            ('allow_any_expired',True)):
            bad=copy.deepcopy(self.doc); bad['preserved_expired_approvals'][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(installer.InstallError): installer.validate_plan(bad)
        for field,value in (('uid',0),('uid',True),('uid',os.getuid()+1),('scope','shell'),
                            ('request_id','../x'),('case_id','bad'),('schema_version',True),
                            ('source',{'kind':'image'})):
            bad=copy.deepcopy(self.doc); bad['preserved_expired_approvals'][0]['request'][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(installer.InstallError): installer.validate_plan(bad)

    def test_snapshot_preserves_exact_hash_identity_mode_timestamps_and_default_denial(self):
        before=self.facts()
        with self.state_context():
            with self.assertRaises(installer.InstallError): installer.idle_state()
            ledger,used,snapshot=installer._update_idle(self.doc)
            self.assertTrue(ledger); self.assertEqual(used,{})
            self.assertEqual(len(snapshot),2)
            self.assertEqual(installer._update_idle(self.doc),(ledger,used,snapshot))
            with self.assertRaises(installer.InstallError): installer.idle_state()
        self.assertEqual(before,self.facts())

    def test_active_unknown_missing_changed_expiry_or_raw_bytes_are_blocked(self):
        cases=('active','unknown','missing','expiry','bytes','consumed','inflight','corrupt_ledger')
        for case in cases:
            # Separate fixtures for each adversarial change; no real grants.
            with self.subTest(case=case):
                original=self.path().read_bytes(); ledger=(self.state/'audit.jsonl').read_bytes()
                extra=self.state/'approved'/('e'*32+'.json')
                if case=='active': self.change(0,approved_at=800.0,expires_at=1100.0)
                elif case=='unknown': installer.write_new(extra,original)
                elif case=='missing': self.path().unlink()
                elif case=='expiry': self.change(0,expires_at=999.0)
                elif case=='bytes': self.change(0,reason='SYNTHETIC changed commentary; same request/expiry')
                elif case=='consumed': installer.write_new(self.state/'used'/self.path().name,original)
                elif case=='inflight':
                    self.events.append({'action':'authorization_consumed','request_id':'e'*32}); self.ledger()
                else: (self.state/'audit.jsonl').write_bytes(b'{}\n')
                with self.state_context(),self.assertRaises((installer.InstallError,KeyError)):
                    installer._update_idle(self.doc)
                # Restore only this test's newly-created synthetic fixtures.
                if extra.exists(): extra.unlink()
                used=self.state/'used'/self.path().name
                if used.exists(): used.unlink()
                self.path().write_bytes(original); self.path().chmod(0o600)
                (self.state/'audit.jsonl').write_bytes(ledger)
                if case=='inflight': self.events.pop()

    def test_noatime_failure_has_no_fallback_and_replaced_or_linked_grants_fail(self):
        real=installer.os.open
        def denied(path,flags,*args,**kwargs):
            if Path(path)==self.path():
                self.assertTrue(flags&os.O_NOATIME)
                raise PermissionError('SYNTHETIC noatime denied')
            return real(path,flags,*args,**kwargs)
        with self.state_context(),patch.object(installer.os,'open',side_effect=denied),self.assertRaises(PermissionError):
            installer._update_idle(self.doc)
        before=None
        with self.state_context(): before=installer._update_idle(self.doc)[2]
        replacement=self.work/'replacement'; installer.write_new(replacement,installer.read_regular(self.path(),noatime=True))
        os.replace(replacement,self.path())
        with self.state_context(): self.assertNotEqual(before,installer._update_idle(self.doc)[2])
        hard=self.work/'hard'; os.link(self.path(),hard)
        with self.state_context(),self.assertRaises(installer.InstallError): installer._update_idle(self.doc)

    def test_symlink_and_duplicate_approval_history_are_rejected(self):
        self.events.append(copy.deepcopy(self.events[0])); self.ledger()
        with self.state_context(),self.assertRaises(installer.InstallError): installer._update_idle(self.doc)
        self.events.pop(); self.ledger()
        target=self.work/'grant-backup'; self.path().rename(target); self.path().symlink_to(target)
        with self.state_context(),self.assertRaises(installer.InstallError): installer._update_idle(self.doc)

    @contextmanager
    def simulation(self,*,during=None):
        code=self.work/'code'; code.mkdir(); review=self.work/'review'; review.mkdir()
        unit=self.work/'unit.service'; installer.write_new(unit,b'SYNTHETIC unit')
        for name in installer.FILES[:-1]:
            data=('SYNTHETIC OLD '+name).encode(); installer.write_new(code/name,data)
            self.doc['installed_before'][name]=installer.sha(data)
        commands=[]; before={p.name:p.read_bytes() for p in code.iterdir()}
        runtime=self.work/'runtime'; runtime.mkdir()
        socket_path=runtime/'broker.sock'; socket_path.write_bytes(b'SYNTHETIC socket metadata, never connect')
        original=Path.lstat
        def metadata(path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            values={k:getattr(info,k) for k in dir(info) if k.startswith('st_')}
            values.update(st_uid=0,st_gid=0)
            if path==socket_path: values.update(st_mode=stat.S_IFSOCK|0o660,st_gid=self.doc['operator_gid'])
            return SimpleNamespace(**values)
        def run(argv,**kwargs):
            commands.append(argv)
            if during: during(argv)
            return ''
        audit=installer.Audit(review)
        with ExitStack() as stack:
            for name,value in (('CODE',code),('STATE',self.state),('UNIT_PATH',unit),('RUNTIME',runtime)):
                stack.enter_context(patch.object(installer,name,value))
            stack.enter_context(patch.object(Path,'lstat',metadata))
            stack.enter_context(patch.object(installer.time,'time',return_value=1001.0))
            stack.enter_context(patch.object(installer,'trusted',side_effect=lambda p,**kw:Path(p)))
            for name in ('verify_dependencies','host_prechecks','smoke'):
                stack.enter_context(patch.object(installer,name))
            stack.enter_context(patch.object(installer,'existing_update_baseline',return_value=SimpleNamespace(pw_uid=555,pw_gid=555)))
            stack.enter_context(patch.object(installer,'root_directory',side_effect=lambda p,m:p.mkdir(mode=m)))
            stack.enter_context(patch.object(installer,'run',side_effect=run))
            try: yield code,review,commands,before,audit
            finally: os.close(audit.fd)

    def test_simulated_update_preserves_metadata_content_grants_and_closed_history(self):
        expired_before=self.facts(); ledger_before=installer.read_regular(self.state/'audit.jsonl')
        installer.write_new(self.state/'used'/('d'*32+'.json'),b'SYNTHETIC historical used nonce')
        with self.simulation() as (code,review,commands,old,audit):
            result=installer.apply_update(self.doc,self.payloads,review,'a'*64,audit)
            self.assertEqual(result['expired_approvals_preserved'],2)
            self.assertEqual(result['read_grants_created'],0)
            self.assertFalse(result['physical_device_reads'])
            for name in installer.FILES[:-1]:
                self.assertEqual((code/name).read_bytes(),self.payloads[name])
                self.assertEqual((review/'previous'/name).read_bytes(),old[name])
            self.assertEqual(sum(a[:2]==['/usr/bin/systemctl','stop'] for a in commands),1)
            self.assertEqual(sum(a[:2]==['/usr/bin/systemctl','start'] for a in commands),1)
        self.assertEqual(expired_before,self.facts())
        self.assertEqual(installer.read_regular(self.state/'audit.jsonl'),ledger_before)
        self.assertEqual(installer.read_regular(self.state/'used'/('d'*32+'.json')),b'SYNTHETIC historical used nonce')

    def test_active_or_changed_grant_blocks_before_any_administrative_command(self):
        self.change(0,reason='SYNTHETIC changed')
        with self.simulation() as (code,review,commands,old,audit):
            with self.assertRaises(installer.InstallError): installer.apply_update(self.doc,self.payloads,review,'a'*64,audit)
            self.assertEqual(commands,[])
            self.assertFalse((review/'previous').exists())
            self.assertEqual({p.name:p.read_bytes() for p in code.iterdir()},old)

    def test_active_grant_also_blocks_before_stop_even_if_its_new_hash_is_declared(self):
        self.change(0,approved_at=800.0,expires_at=1100.0)
        self.doc['preserved_expired_approvals'][0].update(
            expires_at=1100.0,grant_sha256=installer.sha(installer.read_regular(self.path(),noatime=True)))
        with self.simulation() as (code,review,commands,old,audit):
            with self.assertRaises(installer.InstallError): installer.apply_update(self.doc,self.payloads,review,'a'*64,audit)
            self.assertEqual(commands,[])
            self.assertFalse((review/'previous').exists())
            self.assertEqual({p.name:p.read_bytes() for p in code.iterdir()},old)

    def test_change_during_stop_prevents_code_replacement(self):
        def change(argv):
            if argv[:2]==['/usr/bin/systemctl','stop']:
                raw=installer.read_regular(self.path(),noatime=True)
                replacement=self.work/'new-grant'; installer.write_new(replacement,raw)
                os.replace(replacement,self.path())
        with self.simulation(during=change) as (code,review,commands,old,audit):
            with self.assertRaises(installer.InstallError): installer.apply_update(self.doc,self.payloads,review,'a'*64,audit)
            self.assertFalse((review/'previous').exists())
            self.assertEqual({p.name:p.read_bytes() for p in code.iterdir()},old)
            self.assertFalse(any(a[:2]==['/usr/bin/systemctl','start'] for a in commands))

    def test_post_start_change_prevents_success_receipt_and_stops_started_service(self):
        def change(argv):
            if argv[:2]==['/usr/bin/systemctl','start']: self.change(0,reason='SYNTHETIC post-start change')
        with self.simulation(during=change) as (_,review,commands,_,audit):
            with self.assertRaises(installer.InstallError): installer.apply_update(self.doc,self.payloads,review,'a'*64,audit)
            self.assertFalse((review/'receipt.json').exists())
            self.assertEqual(sum(a[:2]==['/usr/bin/systemctl','stop'] for a in commands),2)

    def test_change_before_restart_leaves_service_stopped_without_success_receipt(self):
        count=0
        def dependencies(*args,**kwargs):
            nonlocal count
            count+=1
            if count==2: self.change(0,reason='SYNTHETIC changed after replacement')
        with self.simulation() as (_,review,commands,_,audit), \
                patch.object(installer,'verify_dependencies',side_effect=dependencies):
            with self.assertRaises(installer.InstallError): installer.apply_update(self.doc,self.payloads,review,'a'*64,audit)
            self.assertFalse((review/'receipt.json').exists())
            self.assertFalse(any(a[:2]==['/usr/bin/systemctl','start'] for a in commands))

    def test_preserved_old_grants_remain_unusable_by_unchanged_broker(self):
        before={p.name:installer.sha(installer.read_regular(p,noatime=True)) for p in (self.state/'approved').iterdir()}
        with self.state_context(),patch.object(broker,'STATE',self.state), \
                patch.object(broker,'root_file',side_effect=lambda p,**kw:Path(p)), \
                patch.object(broker,'ledger',side_effect=AssertionError('Never consume an expired nonce')), \
                patch.object(physical,'probe_physical',side_effect=AssertionError('Never open a source')):
            installer._update_idle(self.doc)
            for item in self.items:
                with self.assertRaisesRegex(ValueError,'expired'):
                    broker.consume(core,physical,item['request'],os.getuid())
        after={p.name:installer.sha(installer.read_regular(p,noatime=True)) for p in (self.state/'approved').iterdir()}
        self.assertEqual(before,after)
        self.assertEqual(list((self.state/'used').iterdir()),[])

    def test_cli_declaration_is_update_only_noatime_and_byte_hash_bound(self):
        declaration=self.work/'declaration.json'; installer.write_new(declaration,installer.canonical(self.items))
        digest=installer.sha(installer.read_regular(declaration,noatime=True))
        argv=['installer','--prepare-update',str(ROOT),'--preserve-expired-approvals-json',str(declaration),
              '--preserve-expired-approvals-sha256',digest]
        with patch.object(installer.sys,'argv',argv),patch.object(installer,'prepare',return_value={'synthetic_only':True}) as prepare,redirect_stdout(io.StringIO()):
            installer.main()
        self.assertEqual(prepare.call_args.kwargs['preserved_expired_approvals'],self.items)
        self.assertTrue(prepare.call_args.kwargs['update'])
        for invalid in ([*argv[:-1],'0'*64],argv[:-2],[argv[0],'--prepare',*argv[2:]],
                        [argv[0],'--launch',*argv[2:]]):
            with self.subTest(argv=invalid),patch.object(installer.sys,'argv',invalid), \
                    patch.object(installer,'prepare',side_effect=AssertionError('No plan from an invalid declaration')), \
                    patch.object(installer,'launch',side_effect=AssertionError('No elevation')):
                with self.assertRaises(installer.InstallError): installer.main()

    def test_preparation_requires_explicit_update_and_preservation_enters_plan_hash(self):
        # All installed-code/dependency reads are mocked. Source payloads are
        # project code; no deployment or real private state is inspected.
        with patch.object(installer,'dependencies',return_value=plan()[0]['dependencies']), \
                patch.object(installer,'trusted',side_effect=AssertionError('No host baseline for invalid opt-in')):
            with self.assertRaises(installer.InstallError): installer.prepare(ROOT,preserved_expired_approvals=self.items)
        original=installer.read_regular
        def read(path,**kwargs):
            if Path(path).is_relative_to(installer.CODE) or Path(path)==installer.UNIT_PATH:
                return installer.unit_bytes(os.getgid()) if Path(path)==installer.UNIT_PATH else b'SYNTHETIC installed'
            return original(path,**kwargs)
        with patch.object(installer,'dependencies',return_value=plan()[0]['dependencies']), \
                patch.object(installer,'read_regular',side_effect=read), \
                patch.object(installer,'trusted',side_effect=lambda p,**kw:Path(p)), \
                patch.object(installer.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=555,pw_gid=555)):
            capture=installer.prepare(ROOT,update=True,preserved_expired_approvals=self.items)
        bundle=Path(capture['bundle'])
        # Relocate only this newly generated synthetic administrative bundle to
        # the test's disposable directory; never delete existing bundles.
        moved=self.work/'prepared'; bundle.rename(moved)
        doc=json.loads((moved/'plan.json').read_bytes())
        self.assertEqual(doc['preserved_expired_approvals'],self.items)
        self.assertFalse(doc['physical_read_authorized'])
        self.assertEqual(installer.sha(installer.canonical(doc)),capture['plan_sha256'])
        doc['preserved_expired_approvals'][0]['grant_sha256']='0'*64
        self.assertNotEqual(installer.sha(installer.canonical(doc)),capture['plan_sha256'])
