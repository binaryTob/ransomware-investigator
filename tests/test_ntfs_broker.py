import copy
import io
import json
import os
from pathlib import Path
import struct
import time
from types import SimpleNamespace
from unittest.mock import Mock,patch

from tests.common import ROOT,ProjectTest
from tests.ntfs_support import PIN,state,load_module
from ransomware_investigator.artifacts import register_source
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.ntfs import core,physical,client
from ransomware_investigator.ntfs_triage import register_device,prepare_device,execute_device
from ransomware_investigator.safety import RIError

broker=load_module("ntfs_broker_tests",ROOT/"broker/ntfs_broker.py")

def request(scope="ntfs.list",params=None):
    return {"schema_version":1,"request_id":"a"*32,"case_id":"b"*32,"source_id":"c"*32,"uid":os.getuid(),
            "scope":scope,"parameters":core.parameters(scope,params or {}),"source":{"kind":"physical","pin":dict(PIN)},
            "reason":"Explicit synthetic test; no real device access"}


class PhysicalGateTests(ProjectTest):
    def test_all_identity_geometry_mount_and_ro_discrepancies_fail_closed(self):
        baseline=state()
        self.assertIs(physical.validate_state(PIN,baseline),baseline)
        self.assertFalse(baseline["physical_write_blocker_verified"])
        for key in physical.PIN_FIELDS:
            changed=copy.deepcopy(baseline)
            changed[key]=changed[key]+1 if type(changed[key]) is int else "changed"
            with self.subTest(key=key),self.assertRaises(core.TriageError):
                physical.validate_state(PIN,changed)
        for key in ("disk_read_only","partition_read_only","all_children_read_only","identity_unique"):
            for value in (False,None,1):
                with self.subTest(key=key,value=value),self.assertRaises(core.TriageError):
                    physical.validate_state(PIN,{**baseline,key:value})
        for key in ("mounted","holders","swap_active","protected"):
            with self.subTest(key=key),self.assertRaises(core.TriageError):
                physical.validate_state(PIN,{**baseline,key:True})

    def test_pin_never_accepts_transient_device_name_or_unknown_arguments(self):
        for changed in ({"target_by_id":"/dev/sda1"},{"disk_by_id":"/dev/sda"},{"target_by_id":"/dev/disk/by-id/../../sda"},
                        {"command":"sudo mount"},{"partition_number":True},{"sector_size":123},{"serial":""}):
            with self.subTest(changed=changed),self.assertRaises(core.TriageError):
                physical.validate_pin({**PIN,**changed})

    def test_physical_probe_cannot_run_in_agent_and_does_not_touch_dev(self):
        with patch("ransomware_investigator.ntfs.physical._selector",side_effect=AssertionError("No /dev lookup")):
            with self.assertRaises(core.TriageError): physical.probe_physical(PIN)
        with self.assertRaises(ValueError): broker.load_core()
        with self.assertRaises(ValueError): broker.root_file(ROOT/"broker/ntfs_broker.py")

    def test_parser_account_must_be_non_root_and_non_login(self):
        for uid,gid,shell in ((0,1000,"/usr/sbin/nologin"),(1000,0,"/usr/sbin/nologin"),(1000,1000,"/bin/bash")):
            with patch.object(broker.pwd,"getpwnam",return_value=SimpleNamespace(pw_uid=uid,pw_gid=gid,pw_shell=shell)),self.assertRaises(ValueError):
                broker.parser_identity()

    def test_recheck_discards_changed_fd_or_state(self):
        file=self.work/"fd"; file.write_bytes(b"synthetic")
        fd=os.open(file,os.O_RDONLY)
        self.addCleanup(os.close,fd)
        current={**state(),"rdev":os.fstat(fd).st_rdev}
        def probe(pin): return os.open(file,os.O_RDONLY),copy.deepcopy(current)
        self.assertEqual(physical.recheck_physical(PIN,fd,current,probe=probe),current)
        with self.assertRaises(core.TriageError):
            physical.recheck_physical(PIN,fd,{**current,"kernel_path_observed":"different"},probe=probe)


class BrokerApprovalTests(ProjectTest):
    def setUp(self):
        super().setUp()
        self.state=self.work/"broker-state"; self.state.mkdir(mode=0o711)
        for name in ("approved","used"): (self.state/name).mkdir(mode=0o700)
        self.patch_state=patch.object(broker,"STATE",self.state); self.patch_state.start(); self.addCleanup(self.patch_state.stop)
        # Simulated administrator storage only. Production root ownership checks remain mandatory.
        self.patch_root=patch.object(broker,"root_file",side_effect=lambda path,**kwargs:Path(path)); self.patch_root.start(); self.addCleanup(self.patch_root.stop)
        self.events=[]
        self.patch_audit=patch.object(broker,"ledger",side_effect=lambda action,**data:self.events.append((action,data)) or "d"*64)
        self.patch_audit.start(); self.addCleanup(self.patch_audit.stop)
        self.patch_parser=patch.object(broker,"parser_identity",return_value=SimpleNamespace(pw_uid=65534,pw_gid=65534,pw_shell="/usr/sbin/nologin"))
        self.patch_parser.start(); self.addCleanup(self.patch_parser.stop)
        self.req=request()
        self.path=self.work/"request.json"; self.path.write_text(json.dumps(self.req))

    def approve(self):
        return broker.approve(core,physical,self.path,broker.digest(self.req),os.getuid(),"Simulated human authorization")

    def test_approval_is_exact_uid_hash_scoped_expiring_and_one_use(self):
        with self.assertRaises(ValueError): broker.approve(core,physical,self.path,"0"*64,os.getuid(),"Test")
        with self.assertRaises(ValueError): broker.approve(core,physical,self.path,broker.digest(self.req),os.getuid()+1,"Test")
        self.approve()
        modified=copy.deepcopy(self.req); modified["parameters"]["max_entries"]+=1
        with self.assertRaises(ValueError): broker.consume(core,physical,modified,os.getuid())
        with self.assertRaises(ValueError): broker.consume(core,physical,self.req,os.getuid()+1)
        grant=broker.consume(core,physical,self.req,os.getuid())
        self.assertEqual(grant["request_sha256"],broker.digest(self.req))
        self.assertTrue((self.state/"used"/(self.req["request_id"]+".json")).exists())
        with self.assertRaises(OSError): broker.consume(core,physical,self.req,os.getuid())
        self.assertEqual([event[0] for event in self.events].count("authorization_consumed"),1)

    def test_expired_approval_never_opens_a_source(self):
        self.approve()
        path=self.state/"approved"/(self.req["request_id"]+".json")
        grant=json.loads(path.read_text()); grant.update(approved_at=time.time()-600,expires_at=time.time()-300)
        path.write_text(json.dumps(grant))
        with patch.object(physical,"probe_physical",side_effect=AssertionError("No physical source")):
            with self.assertRaises(ValueError): broker.execute(core,physical,Path("unused"),self.req,os.getuid())

    def test_no_audit_space_blocks_before_device_access(self):
        self.approve()
        with patch.object(broker,"audit_capacity",side_effect=ValueError("Audit full")),patch.object(physical,"probe_physical",side_effect=AssertionError("No source")):
            with self.assertRaises(ValueError): broker.execute(core,physical,Path("unused"),self.req,os.getuid())

    def execute_fake(self,before,after=None):
        self.approve()
        file=self.work/"source-fixture"; file.write_bytes(b"synthetic descriptor; not a block device")
        worker={"receipt":{"status":"ok","request_sha256":broker.digest(self.req),"stderr":"RI_READ_INTENT 0 512\nRI_READ 0 512 512\n","stdout_sha256":"e"*64},
                "result":{"entries":[],"summary":{"partial":False}}}
        def open_fake(pin): return os.open(file,os.O_RDONLY),before
        patches=(patch.object(physical,"probe_physical",side_effect=open_fake),
                 patch.object(physical,"recheck_physical",return_value=after or before),
                 patch.object(core,"run_worker",return_value=worker))
        return patches

    def test_before_read_discrepancy_blocks_parser(self):
        patches=self.execute_fake({**state(),"partition_read_only":False})
        with patches[0],patches[1],patches[2] as run:
            with self.assertRaises(ValueError): broker.execute(core,physical,Path("unused"),self.req,os.getuid())
            run.assert_not_called()

    def test_after_read_discrepancy_discards_result_but_preserves_read_audit(self):
        patches=self.execute_fake(state(),{**state(),"mounted":True})
        with patches[0],patches[1],patches[2] as run:
            with self.assertRaises(ValueError): broker.execute(core,physical,Path("unused"),self.req,os.getuid())
            run.assert_called_once()
        actions=[event[0] for event in self.events]
        self.assertIn("source_read",actions)
        self.assertIn("source_read_intent",actions)
        self.assertIn("physical_read_failed",actions)
        self.assertNotIn("physical_read_finished",actions)

    def test_success_keeps_root_receipt_and_passes_drop_privilege_deadline(self):
        patches=self.execute_fake(state())
        with patches[0],patches[1],patches[2] as run:
            result=broker.execute(core,physical,Path("unused"),self.req,os.getuid())
        self.assertEqual(result["status"],"completed")
        self.assertEqual(result["before"],result["after"])
        self.assertIn("gid",run.call_args.kwargs)
        self.assertNotEqual(run.call_args.kwargs["parser_uid"],self.req["uid"])
        self.assertGreater(run.call_args.kwargs["not_after"],time.time())
        self.assertEqual(result["broker_audit_sha256"],"d"*64)


class PhysicalCaseTests(ProjectTest):
    def setUp(self):
        super().setUp()
        self.store=CaseStore(self.work/"cases"); self.addCleanup(self.store.db.close)
        self.case=self.store.create_case("Physical workflow SIMULATED","Synthetic Operator","Synthetic Operator")["id"]
        original=register_source(self.store,self.case,reference="SYNTHETIC-DECLARED-DEVICE",source_kind="physical-device",
                                 description="Simulated pin, never connected",source_sha256=None,actor="Synthetic Operator")
        self.device=register_device(self.store,self.case,source_id=original["id"],pin=PIN,actor="Synthetic Operator",reason="Metadata only")

    def prepare(self):
        return prepare_device(self.store,self.case,self.device["id"],"ntfs.list",{},actor="Synthetic Operator",reason="Explicit simulated physical request",
                              authorized=True,provided_scope="ntfs.list")

    def test_prepare_is_not_device_access_or_root_approval(self):
        with patch.object(physical,"probe_physical",side_effect=AssertionError("No device access")),patch("subprocess.Popen",side_effect=AssertionError("No auto elevation")):
            prepared=self.prepare()
        self.assertFalse(prepared["physical_read_performed"])
        operation=self.store.get("operations",prepared["operation_id"])
        self.assertIn("awaiting_independent_root",operation["physical_state"])
        self.assertEqual(broker.digest(json.loads(Path(prepared["request_file"]).read_text())),prepared["request_sha256"])

    def test_no_broker_no_fallback_and_failure_audited(self):
        prepared=self.prepare()
        with patch.object(client,"execute_physical",side_effect=PermissionError("No deployed broker")),patch("subprocess.Popen",side_effect=AssertionError("No sudo")):
            with self.assertRaises(OSError): execute_device(self.store,self.case,prepared["operation_id"],"Synthetic Operator")
        self.assertEqual(self.store.get("operations",prepared["operation_id"])["status"],"failed")
        self.assertTrue(self.store.verify()["valid"])

    def test_correlated_broker_response_and_single_case_replay_control(self):
        prepared=self.prepare(); op=self.store.get("operations",prepared["operation_id"]); req=op["request"]
        response={"status":"completed","request_id":req["request_id"],"request_sha256":core.sha(core.canonical(req)),
                  "before":state(),"after":state(),"broker_audit_sha256":"d"*64,
                  "worker":{"receipt":{"status":"ok","request_sha256":core.sha(core.canonical(req)),"parser_uid":65534,"stdout_sha256":"e"*64,"stderr":"RI_READ 0 512 512\n"},
                            "result":{"entries":[],"summary":{"partial":False}}}}
        with patch.object(client,"execute_physical",return_value=response):
            result=execute_device(self.store,self.case,prepared["operation_id"],"Synthetic Operator")
        self.assertEqual(result["status"],"completed")
        with self.assertRaises(RIError): execute_device(self.store,self.case,prepared["operation_id"],"Synthetic Operator")
        other=self.store.create_case("Other","Bob","Bob")["id"]
        with self.assertRaises(RIError): execute_device(self.store,other,prepared["operation_id"],"Bob")

    def test_mismatched_receipt_cannot_be_imported_as_success(self):
        prepared=self.prepare()
        with patch.object(client,"execute_physical",return_value={"request_id":"0"*32,"request_sha256":"0"*64}):
            with self.assertRaises(RIError): execute_device(self.store,self.case,prepared["operation_id"],"Synthetic Operator")
        self.assertEqual(self.store.get("operations",prepared["operation_id"])["status"],"failed")


class ProtocolTests(ProjectTest):
    def test_bounded_frames_and_truncated_frames(self):
        class Connection:
            def __init__(self,data): self.stream=io.BytesIO(data)
            def recv(self,size): return self.stream.read(min(size,3))
        payload=core.canonical({"safe":"synthetic"})
        self.assertEqual(client.receive(Connection(struct.pack("!I",len(payload))+payload),1024),{"safe":"synthetic"})
        for frame in (struct.pack("!I",2**31),b"\0\0",struct.pack("!I",100)+b"{}"):
            with self.assertRaises(ValueError): client.receive(Connection(frame),1024)

    def test_non_root_peer_is_rejected_before_sending_sensitive_pin(self):
        socket_path=Mock()
        socket_path.parent=Mock()
        for p in (socket_path,socket_path.parent):
            p.lstat.return_value=SimpleNamespace(st_uid=0,st_mode=0o140666 if p is socket_path else 0o040711)
            p.is_symlink.return_value=False
        socket_path.stat.return_value=SimpleNamespace(st_mode=0o140666)
        connection=Mock(); connection.getsockopt.return_value=struct.pack("3i",1234,os.getuid(),os.getgid())
        context=Mock(); context.__enter__=Mock(return_value=connection); context.__exit__=Mock(return_value=False)
        with patch.object(client,"SOCKET",socket_path),patch.object(client.socket,"socket",return_value=context):
            with self.assertRaises(ValueError): client.execute_physical(request())
        connection.sendall.assert_not_called()
