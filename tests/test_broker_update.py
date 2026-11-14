import copy
import importlib.util
import json
import os
import socket
import stat
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.common import ROOT, ProjectTest
from tests.test_broker_installer import installer, plan


def update_plan():
    doc,payloads=plan()
    doc.update(operation='update_broker_code_only',actions=list(installer.UPDATE_ACTIONS),
               installed_before={name:'b'*64 for name in installer.FILES[:-1]},
               unit_before_sha256=doc['unit_sha256'],parser_uid=555,parser_gid=555)
    return doc,payloads


class BrokerUpdateTests(ProjectTest):
    def test_update_plan_cannot_change_unit_or_recreate_accounts(self):
        doc,_=update_plan(); installer.validate_plan(doc)
        for key,value in (('unit_before_sha256','c'*64),('actions',list(installer.ACTIONS)),('parser_uid',0),('installed_before',{})):
            bad=copy.deepcopy(doc); bad[key]=value
            with self.subTest(key=key),self.assertRaises(installer.InstallError): installer.validate_plan(bad)

    def state(self, events=()):
        directory=self.work/'state'; directory.mkdir(mode=0o700)
        for name in ('approved','used'): (directory/name).mkdir(mode=0o700)
        previous='0'*64; data=b''
        for event in events:
            event={**event,'previous_sha256':previous}; previous=installer.sha(installer.canonical(event))
            data+=installer.canonical({'event':event,'sha256':previous})+b'\n'
        installer.write_new(directory/'audit.jsonl',data)
        return directory

    def root_metadata(self):
        original=Path.lstat
        def lstat(path,*args,**kwargs):
            info=original(path,*args,**kwargs)
            return SimpleNamespace(st_uid=0,st_gid=0,st_mode=info.st_mode)
        return patch.object(Path,'lstat',lstat)

    def test_pending_grant_or_unfinished_request_blocks_update(self):
        directory=self.state([{'action':'authorization_consumed','request_id':'a'*32}])
        with patch.object(installer,'STATE',directory),self.root_metadata():
            with self.assertRaises(installer.InstallError): installer.idle_state()
            installer.write_new(directory/'approved'/('b'*32+'.json'),b'SYNTHETIC approved')
            with self.assertRaises(installer.InstallError): installer.idle_state()

    def test_closed_ledger_and_used_nonces_are_preserved_and_corruption_blocks(self):
        directory=self.state([{'action':'authorization_consumed','request_id':'a'*32},{'action':'physical_read_failed','request_id':'a'*32}])
        used=directory/'used'/('a'*32+'.json'); installer.write_new(used,b'SYNTHETIC used nonce')
        with patch.object(installer,'STATE',directory),self.root_metadata():
            data,nonces=installer.idle_state()
            self.assertEqual(nonces[used.name],installer.sha(b'SYNTHETIC used nonce'))
            (directory/'audit.jsonl').write_bytes(data+b'{}\n')
            with self.assertRaises((installer.InstallError,KeyError)): installer.idle_state()

    def test_idle_failure_performs_no_service_command_or_replacement(self):
        doc,payloads=update_plan(); audit=installer.Audit(self.work)
        try:
            with patch.object(installer,'verify_dependencies'),patch.object(installer,'host_prechecks'),patch.object(installer,'existing_update_baseline'),patch.object(installer,'idle_state',side_effect=installer.InstallError('SYNTHETIC busy')),patch.object(installer,'run',side_effect=AssertionError('No administrative command')):
                with self.assertRaises(installer.InstallError): installer.apply_update(doc,payloads,self.work,'a'*64,audit)
        finally: os.close(audit.fd)

    def test_simulated_update_only_changes_reviewed_code_and_keeps_history(self):
        doc,payloads=update_plan(); code=self.work/'code'; code.mkdir(); review=self.work/'review'; review.mkdir()
        unit=self.work/'unit.service'; installer.write_new(unit,b'SYNTHETIC existing unit')
        state=self.state(); runtime=self.work/'runtime'
        before={}
        for name in installer.FILES[:-1]:
            old=('SYNTHETIC OLD '+name).encode(); before[name]=old
            installer.write_new(code/name,old)
            doc['installed_before'][name]=installer.sha(old)
            if name in ('core.py','ntfs_worker'):
                payloads[name]=old; doc['payloads'][name]=installer.sha(old)
        nonce=state/'used'/('a'*32+'.json'); installer.write_new(nonce,b'SYNTHETIC historical nonce')
        audit=installer.Audit(review); commands=[]
        def command(argv,**kwargs):
            commands.append(argv)
            if argv[:2]==['/usr/bin/systemctl','start']:
                runtime.mkdir(); server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                server.bind(str(runtime/'broker.sock')); self.addCleanup(server.close)
            return ''
        original=Path.lstat
        def lstat(path,*args,**kwargs):
            if path==runtime/'broker.sock': return SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=doc['operator_gid'])
            info=original(path,*args,**kwargs)
            return SimpleNamespace(st_mode=info.st_mode,st_uid=0,st_gid=0)
        with ExitStack() as stack:
            for name,value in (('CODE',code),('STATE',state),('UNIT_PATH',unit),('RUNTIME',runtime)):
                stack.enter_context(patch.object(installer,name,value))
            stack.enter_context(patch.object(installer,'trusted',side_effect=lambda p,**kw:Path(p)))
            stack.enter_context(patch.object(installer,'verify_dependencies'))
            stack.enter_context(patch.object(installer,'host_prechecks'))
            stack.enter_context(patch.object(installer,'existing_update_baseline',return_value=SimpleNamespace(pw_uid=555,pw_gid=555)))
            stack.enter_context(patch.object(installer,'root_directory',side_effect=lambda p,m:p.mkdir(mode=m)))
            stack.enter_context(patch.object(installer,'run',side_effect=command))
            stack.enter_context(patch.object(installer,'smoke'))
            stack.enter_context(patch.object(Path,'lstat',lstat))
            try: result=installer.apply_update(doc,payloads,review,'a'*64,audit)
            finally: os.close(audit.fd)
        self.assertTrue(result['nonce_history_preserved'])
        self.assertEqual(nonce.read_bytes(),b'SYNTHETIC historical nonce')
        self.assertEqual(unit.read_bytes(),b'SYNTHETIC existing unit')
        for name in installer.FILES[:-1]:
            self.assertEqual((review/'previous'/name).read_bytes(),before[name])
            self.assertEqual((code/name).read_bytes(),payloads[name])
        self.assertEqual(sum('stop' in argv for argv in commands),1)
        self.assertEqual(sum('start' in argv for argv in commands),1)
        self.assertFalse(any(argv[0]=='/usr/sbin/useradd' or 'daemon-reload' in argv for argv in commands))


class PerDiskValidationTests(ProjectTest):
    def test_a_reference_validation_of_another_disk_never_unlocks_this_disk(self):
        from ransomware_investigator.ntfs import physical
        from ransomware_investigator import ntfs_scan as scan
        from ransomware_investigator.safety import RIError
        other={'kind':'physical','pin':{'disk_by_id':'/dev/disk/by-id/OTHER','wwid':'naa.OTHER'}}
        validated={'kind':'physical','pin':{'disk_by_id':'/dev/disk/by-id/SYNTHETIC','wwid':'naa.SYNTHETIC'}}
        validation={'case_id':'a'*32,'scope':'ntfs.reference-validation','status':'completed','results':[{'metadata_report':{'path':'SYNTHETIC.json','sha256':scan.bytes_digest(b'{}')}}]}
        class Store:
            workspace=Path('/SYNTHETIC')
            def get(self,kind,identifier): return validation
            def path(self,path): return path
        with patch.object(scan,'_read',return_value=b'{}'),patch.object(scan.json,'loads',return_value={'source_id':'b'*32}),patch.object(scan.triage,'_source',return_value=validated):
            with self.assertRaisesRegex(RIError,'otro disco'): scan._physical_validation_gate(Store(),'a'*32,'c'*32,other)
        self.assertNotEqual(physical.disk_binding(other['pin']),physical.disk_binding(validated['pin']))
