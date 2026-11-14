"""Single-auth finite approval sessions; synthetic files/mocks, never root."""
import copy
import json
import os
import struct
import time
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock,patch

from tests.common import ProjectTest
from tests.test_broker_installer import installer,plan as installation_plan
from tests.test_ntfs_broker import request,broker as legacy_broker
from ransomware_investigator.ntfs import core,physical


def authorization(count=3,first=1):
    batches=[]
    for ordinal in range(1,count+1):
        req=request('ntfs.records',{'inode':ordinal+4,'max_entries':1})
        req['request_id']=f'{ordinal:032x}'
        bundle={'schema_version':1,'requests':[req]}
        batches.append({'ordinal':ordinal,'request_count':1,'requests':[req],
                        'batch_sha256':installer.sha(installer.canonical(bundle))})
    seq={'schema_version':1,'case_id':'b'*32,'requesting_uid':os.getuid(),
         'batch_count':count,'request_count':count,'batches':batches}
    return {'sequence':seq,'sequence_sha256':installer.sha(installer.canonical(seq)),
            'first_batch_ordinal':first,'custody_attestation':'SYNTHETIC custody only, no real device',
            'reason':'SYNTHETIC exact finite metadata sequence','max_session_seconds':14400}


def rehash(auth):
    for batch in auth['sequence']['batches']:
        batch['batch_sha256']=installer.sha(installer.canonical({'schema_version':1,'requests':batch['requests']}))
    auth['sequence_sha256']=installer.sha(installer.canonical(auth['sequence']))
    return auth


def session_plan(auth=None):
    doc,payloads=installation_plan()
    doc.update(operation='sequence_approval_session_only',actions=list(installer.SESSION_ACTIONS),
        installed_before={n:doc['payloads'][n] for n in installer.FILES[:-1]},
        unit_before_sha256=doc['unit_sha256'],parser_uid=555,parser_gid=555,
        sequence_authorization=auth or authorization())
    return doc,payloads


class SequencePolicyTests(ProjectTest):
    def test_exact_metadata_sequence_and_resume_boundary(self):
        auth=authorization(first=2)
        self.assertEqual(len(installer.validate_sequence_authorization(auth,os.getuid())),3)
        doc,_=session_plan(auth); installer.validate_plan(doc)

    def test_rejects_uid_case_content_duplicate_scope_and_batch_mix(self):
        base=authorization()
        for mutation in ('uid','case','data','duplicate','image','mixed'):
            auth=copy.deepcopy(base); req=auth['sequence']['batches'][1]['requests'][0]
            if mutation=='uid': req['uid']=0
            elif mutation=='case': req['case_id']='c'*32
            elif mutation=='data': req['scope']='ntfs.extract'
            elif mutation=='duplicate': req['request_id']=auth['sequence']['batches'][0]['requests'][0]['request_id']
            elif mutation=='image': req['source']={'kind':'image','path':'/SYNTHETIC'}
            else:
                other=copy.deepcopy(req); other['request_id']='d'*32; other['source_id']='e'*32
                auth['sequence']['batches'][1]['requests'].append(other)
                auth['sequence']['batches'][1]['request_count']=2; auth['sequence']['request_count']=4
            with self.subTest(mutation=mutation),self.assertRaises(installer.InstallError):
                installer.validate_sequence_authorization(rehash(auth),os.getuid())

    def test_no_unbounded_lifetime_bool_boundary_or_missing_custody(self):
        for key,value in (('max_session_seconds',14401),('max_session_seconds',599),
                          ('first_batch_ordinal',True),('first_batch_ordinal',4),
                          ('custody_attestation',''),('reason','x\ny'),('sequence_sha256','0'*64)):
            auth=authorization(); auth[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(installer.InstallError):
                installer.validate_sequence_authorization(auth,os.getuid())

    def test_session_cannot_change_installed_code_or_administrative_actions(self):
        doc,_=session_plan()
        for change in ('code','actions','read_flag'):
            bad=copy.deepcopy(doc)
            if change=='code': bad['payloads']['ntfs_broker.py']='c'*64
            elif change=='actions': bad['actions']=list(installer.UPDATE_ACTIONS)
            else: bad['physical_read_authorized']=True
            with self.subTest(change=change),self.assertRaises(installer.InstallError): installer.validate_plan(bad)

    def test_frames_are_bounded_typed_and_expiring(self):
        read,write=os.pipe()
        try:
            installer._session_send(write,{'action':'approve-next','ordinal':1})
            self.assertEqual(installer._session_receive(read,time.monotonic()+1),{'action':'approve-next','ordinal':1})
            os.write(write,struct.pack('!I',2048))
            with self.assertRaises(installer.InstallError): installer._session_receive(read,time.monotonic()+1,maximum=1024)
            with self.assertRaises(installer.InstallError): installer._session_receive(read,time.monotonic()-1)
        finally: os.close(read); os.close(write)


class CompletedPrefixTests(ProjectTest):
    def fixture(self,worker_status='ok',finished=True,wrong_request=False):
        req=authorization(1)['sequence']['batches'][0]['requests'][0]
        state=self.work/'state'; (state/'used').mkdir(parents=True)
        grant_req=copy.deepcopy(req)
        if wrong_request: grant_req['parameters']['inode']+=1
        grant={'request':grant_req,'request_sha256':installer.sha(installer.canonical(grant_req)),'approved_uid':os.getuid()}
        data=installer.canonical(grant); path=state/'used'/(req['request_id']+'.json'); installer.write_new(path,data)
        previous='0'*64; lines=[]
        events=[{'action':'worker_finished','request_id':req['request_id'],'worker_status':worker_status}]
        if finished: events.append({'action':'physical_read_finished','request_id':req['request_id']})
        for item in events:
            event={**item,'previous_sha256':previous}; previous=installer.sha(installer.canonical(event))
            lines.append(installer.canonical({'event':event,'sha256':previous}))
        return req,state,b'\n'.join(lines)+b'\n',{path.name:installer.sha(data)}

    def test_prefix_requires_successful_root_worker_and_postcheck_and_exact_used_nonce(self):
        req,state,ledger,used=self.fixture()
        with patch.object(installer,'STATE',state),patch.object(installer,'trusted',side_effect=lambda p:p):
            installer.require_completed_sequence_requests([req],ledger,used)

    def test_failed_worker_missing_postcheck_or_changed_used_nonce_block_resume(self):
        for options in ({'worker_status':'worker_failed'},{'finished':False},{'wrong_request':True}):
            # Isolate each synthetic root-state fixture.
            with self.subTest(options=options):
                old=self.work; self.work=old/str(len(list(old.iterdir()))); self.work.mkdir()
                req,state,ledger,used=self.fixture(**options)
                with patch.object(installer,'STATE',state),patch.object(installer,'trusted',side_effect=lambda p:p):
                    with self.assertRaises(installer.InstallError): installer.require_completed_sequence_requests([req],ledger,used)
                self.work=old

    def test_corrupted_root_chain_blocks_sequence(self):
        req,state,ledger,used=self.fixture()
        with self.assertRaises(installer.InstallError):
            installer.require_completed_sequence_requests([req],ledger.replace(b'"sha256":"',b'"sha256":"0',1),used)


class SessionServerTests(ProjectTest):
    def serve(self,commands,auth=None,clock=None,actual_grants=False):
        doc,_=session_plan(auth); review=self.work/'review'; review.mkdir(); audit=installer.Audit(review)
        state=self.work/'state'; (state/'approved').mkdir(parents=True); (state/'used').mkdir()
        broker=SimpleNamespace(load_core=lambda:(core,physical,None),approve_request=Mock(side_effect=lambda c,p,r,h,u,why,**kw:{'request_id':r['request_id'],'uid':u,'scope':r['scope'],'expires_at':time.time()+300}))
        loader=SimpleNamespace(exec_module=lambda module:None)
        sent=[]
        with ExitStack() as stack:
            stack.enter_context(patch.object(installer,'STATE',state))
            if actual_grants:
                broker.approve_request=legacy_broker.approve_request
                stack.enter_context(patch.object(legacy_broker,'STATE',state))
                stack.enter_context(patch.object(legacy_broker,'root_file',side_effect=lambda p,**kw:p))
                stack.enter_context(patch.object(legacy_broker,'ledger',return_value='c'*64))
                stack.enter_context(patch.object(legacy_broker,'parser_identity',return_value=SimpleNamespace(pw_uid=555,pw_gid=555)))
            for name in ('verify_dependencies','host_prechecks','existing_update_baseline'):
                stack.enter_context(patch.object(installer,name))
            stack.enter_context(patch.object(installer,'trusted',side_effect=lambda p:p))
            stack.enter_context(patch.object(installer,'idle_state',return_value=(b'',{})))
            prefix=stack.enter_context(patch.object(installer,'require_completed_sequence_requests'))
            stack.enter_context(patch.object(installer.importlib.util,'spec_from_file_location',return_value=SimpleNamespace(loader=loader)))
            stack.enter_context(patch.object(installer.importlib.util,'module_from_spec',return_value=broker))
            stack.enter_context(patch.object(installer,'_session_receive',side_effect=commands))
            stack.enter_context(patch.object(installer,'_session_send',side_effect=lambda fd,value:sent.append(value)))
            if clock is not None: stack.enter_context(patch.object(installer.time,'monotonic',side_effect=clock))
            try: installer.serve_approval_session(doc,review,'a'*64,audit,input_fd=70,output_fd=71)
            finally: os.close(audit.fd)
        return broker,sent,prefix,json.loads((review/'receipt.json').read_bytes())

    def test_all_batches_share_one_server_and_prefix_is_checked_before_next(self):
        broker,sent,prefix,receipt=self.serve([{'action':'approve-next','ordinal':i} for i in (1,2,3)]+[{'action':'finish'}])
        self.assertEqual(broker.approve_request.call_count,3)
        self.assertEqual([v['status'] for v in sent],['approval_session_ready','batch_approved','batch_approved','batch_approved','sequence_session_completed'])
        self.assertEqual(receipt['status'],'sequence_session_completed')
        self.assertEqual([len(call.args[0]) for call in prefix.call_args_list],[0,0,1,2,3])
        self.assertFalse(receipt['installed_code_changed'])

    def test_resume_validates_closed_prefix_and_does_not_reapprove_it(self):
        broker,sent,prefix,receipt=self.serve([{'action':'approve-next','ordinal':2},{'action':'approve-next','ordinal':3},{'action':'finish'}],authorization(first=2))
        self.assertEqual(broker.approve_request.call_count,2)
        self.assertEqual(receipt['approved_batch_ordinals'],[2,3])
        self.assertEqual(len(prefix.call_args_list[0].args[0]),1)

    def test_arbitrary_command_wrong_order_and_early_finish_create_no_grants(self):
        for command in ({'action':'shell','command':'SYNTHETIC'}, {'action':'approve-next','ordinal':2}, {'action':'finish'}):
            with self.subTest(command=command):
                old=self.work; self.work=old/str(len(list(old.iterdir()))); self.work.mkdir()
                broker,sent,_,receipt=self.serve([command])
                self.assertEqual(broker.approve_request.call_count,0)
                self.assertEqual(receipt['status'],'sequence_session_stopped')
                self.work=old

    def test_disconnect_and_expiry_stop_without_new_grants(self):
        broker,_,_,receipt=self.serve([EOFError('SYNTHETIC disconnected')])
        self.assertEqual(broker.approve_request.call_count,0)
        self.assertFalse(receipt['automatic_retry'])
        self.work=self.work/'expired'; self.work.mkdir()
        auth=authorization(); auth['max_session_seconds']=600
        broker,_,_,receipt=self.serve([{'action':'approve-next','ordinal':1}],auth,clock=[0,350])
        self.assertEqual(broker.approve_request.call_count,0)
        self.assertEqual(receipt['status'],'sequence_session_stopped')

    def test_courier_uses_unchanged_five_minute_exact_legacy_grants(self):
        from tests.test_station_identity import session_pin
        auth=authorization(1)
        auth['sequence']['batches'][0]['requests'][0]['source']['pin']=session_pin()
        _,sent,_,receipt=self.serve([{'action':'approve-next','ordinal':1},EOFError('SYNTHETIC stop')],rehash(auth),actual_grants=True)
        grants=list((self.work/'state/approved').iterdir())
        self.assertEqual(len(grants),1)
        grant=json.loads(grants[0].read_bytes())
        self.assertAlmostEqual(grant['expires_at']-grant['approved_at'],300,delta=0.01)
        self.assertEqual(grant['approved_uid'],os.getuid())
        self.assertEqual(grant['request_sha256'],installer.sha(installer.canonical(grant['request'])))
        self.assertEqual(sent[1]['status'],'batch_approved')
        self.assertIn('custody_attestation',grant)
        self.assertFalse(receipt['physical_device_reads'])


class SingleAuthenticationClientTests(ProjectTest):
    def bundle(self):
        doc,payloads=session_plan(authorization(30)); bundle=self.work/'bundle'; bundle.mkdir()
        data=installer.Path(installer.__file__).read_bytes(); payloads['broker_installer.py']=data
        doc['payloads']['broker_installer.py']=installer.sha(data)
        for name,data in payloads.items(): installer.write_new(bundle/name,data)
        bootstrap=b'# SYNTHETIC only; never execute\n'; doc['bootstrap_sha256']=installer.sha(bootstrap)
        installer.write_new(bundle/'bootstrap.py',bootstrap); raw=installer.canonical(doc); installer.write_new(bundle/'plan.json',raw)
        return doc,bundle,installer.sha(raw)

    def test_thirty_batches_invoke_polkit_once_not_thirty_times(self):
        doc,bundle,sha=self.bundle()
        class Stream:
            def fileno(self): return 50
            def close(self): pass
            def read(self,n): return b''
        process=SimpleNamespace(stdin=Stream(),stdout=Stream(),stderr=Stream(),returncode=0,wait=Mock(return_value=0))
        auth=doc['sequence_authorization']; replies=[{'status':'approval_session_ready','plan_sha256':sha,'sequence_sha256':auth['sequence_sha256'],'next_batch_ordinal':1,'operator_uid':os.getuid()}]
        for batch in auth['sequence']['batches']:
            r=batch['requests'][0]
            replies.append({'status':'batch_approved','ordinal':batch['ordinal'],'batch_sha256':batch['batch_sha256'],
                'grants':[{'request_id':r['request_id'],'uid':r['uid'],'scope':r['scope']}]})
        replies.append({'status':'sequence_session_completed'})
        with patch.object(installer,'verify_dependencies'),patch.object(installer.subprocess,'Popen',return_value=process) as popen,patch.object(installer,'_session_receive',side_effect=replies),patch.object(installer,'_session_send') as send:
            session=installer.SequenceApprovalSession(bundle/'plan.json',sha); session.start()
            for ordinal in range(1,31): session.approve_next(ordinal)
            session.finish()
        self.assertEqual(popen.call_count,1)
        self.assertEqual(popen.call_args.args[0][:7],['/usr/bin/pkexec','--disable-internal-agent','/usr/bin/python3','-I','-S','-B','-c'])
        self.assertFalse(popen.call_args.kwargs['shell'])
        self.assertEqual(send.call_count,31)
        self.assertTrue((bundle/'session-end-receipt.json').is_file())

    def test_hash_mismatch_blocks_before_authentication(self):
        _,bundle,_=self.bundle()
        with patch.object(installer.subprocess,'Popen',side_effect=AssertionError('No authentication')):
            with self.assertRaises(installer.InstallError): installer.SequenceApprovalSession(bundle/'plan.json','0'*64).start()
