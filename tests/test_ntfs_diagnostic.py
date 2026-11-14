"""New regular synthetic images only; no broker service or physical devices."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from unittest import mock
from types import SimpleNamespace

from tests.common import ROOT, ProjectTest
from tests.ntfs_support import builder, build_worker
from admin.broker_installer import read_regular
from ransomware_investigator.ntfs import core
from ransomware_investigator import ntfs_triage
from ransomware_investigator.cases import public_artifact_record
from ransomware_investigator.safety import RIError
from tests.ntfs_support import NTFSTest, PIN, load_module
from ransomware_investigator.ntfs import physical


class NTFSDiagnosticTests(ProjectTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        build_worker()

    def setUp(self):
        super().setUp()
        self.manifest=builder.create_fixture(self.work/"control")
        self.path=Path(self.manifest["path"])
        self.data=read_regular(self.path,noatime=True)
        self.inode=self.manifest["entries"]["ordinary.docx"]["inode"]
        self.cluster=int.from_bytes(self.data[11:13],"little")*self.data[13]
        code=int.from_bytes(self.data[64:65],"little",signed=True)
        self.size=2**-code if code<0 else code*self.cluster
        self.mft=int.from_bytes(self.data[48:56],"little")*self.cluster
        self.offset=self.mft+self.inode*self.size
        self.assertEqual(self.data[self.offset:self.offset+4],b"FILE")
        self.assertIn("ordinary.docx".encode("utf-16le"),self.data[self.offset:self.offset+self.size])

    def request(self, scope="ntfs.diagnose", **parameters):
        return {"schema_version":1,"request_id":"c"*32,"case_id":"a"*32,"source_id":"b"*32,
                "uid":os.getuid(),"scope":scope,"parameters":core.parameters(scope,{"inode":self.inode,**parameters}),
                "source":{"kind":"image","sha256":hashlib.sha256(self.data).hexdigest(),
                          "offset_bytes":0,"volume_length":len(self.data)},"reason":"Explicit synthetic diagnostic only"}

    def measure(self, data=None, *, scope="ntfs.diagnose", length=None, **parameters):
        path=self.path
        if data is not None:
            path=self.work/("copy-"+str(len(list(self.work.iterdir())))+".ntfs")
            with path.open("xb") as f: f.write(data)
            path.chmod(0o400)  # New, unregistered fixture only.
        before=path.stat()
        request=self.request(scope,**parameters)
        request["source"]["sha256"]=hashlib.sha256(self.data if data is None else data).hexdigest()
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME|os.O_CLOEXEC)
        try:
            response=core.run_worker(ROOT/".build/ntfs_worker",fd,request,base=0,
                                     length=len(self.data) if length is None else length)
        finally: os.close(fd)
        after=path.stat()
        self.assertEqual((before.st_atime_ns,before.st_mtime_ns,before.st_ctime_ns,before.st_mode),
                         (after.st_atime_ns,after.st_mtime_ns,after.st_ctime_ns,after.st_mode))
        self.assertEqual(hashlib.sha256(read_regular(path,noatime=True)).hexdigest(),request["source"]["sha256"])
        return response

    def mft_attribute(self, kind):
        # Fixture construction only: assert attribute bounds in synthetic MFT0.
        pos=self.mft+int.from_bytes(self.data[self.mft+20:self.mft+22],"little")
        while pos<self.mft+self.size-16:
            value=int.from_bytes(self.data[pos:pos+4],"little")
            if value==0xffffffff: break
            length=int.from_bytes(self.data[pos+4:pos+8],"little")
            self.assertGreaterEqual(length,24)
            self.assertLessEqual(pos+length,self.mft+self.size)
            if value==kind:
                self.assertEqual(self.data[pos+9],0)  # Unnamed.
                return pos
            pos+=length
        self.fail("Missing synthetic MFT attribute")

    def bitmap_bit(self, data, allocated):
        pos=self.mft_attribute(0xb0)
        if self.data[pos+8]==0:
            start=pos+int.from_bytes(self.data[pos+20:pos+22],"little")
        else:
            run=pos+int.from_bytes(self.data[pos+32:pos+34],"little")
            sizes=self.data[run]; n=sizes&15; width=sizes>>4
            self.assertGreater(width,0)
            lcn=int.from_bytes(self.data[run+1+n:run+1+n+width],"little",signed=True)
            self.assertGreater(lcn,0)
            start=lcn*self.cluster
        index=start+self.inode//8
        if allocated: data[index]|=1<<(self.inode%8)
        else: data[index]&=255^(1<<(self.inode%8))

    def result(self, response):
        self.assertEqual(response["receipt"]["status"],"ok",response["receipt"])
        result=response["result"]
        self.assertFalse(result["inventory_eligible"])
        self.assertNotIn("entries",result)
        for name in ("ordinary.docx","SYNTHETIC ordinary document", "name_hex", "data_base64"):
            self.assertNotIn(name,json.dumps(response))
        self.assertLess(len(core.canonical(result)),65536)
        return result

    def test_valid_header_fixups_allocation_and_audited_provider(self):
        response=self.measure()
        row=self.result(response)
        self.assertEqual(row["assessment"],"valid_header_fixups")
        self.assertEqual(row["bitmap"],"allocated")
        self.assertEqual(row["record"]["usa_count"],self.size//512+1)
        self.assertEqual(row["locator"],"libtsk_mft_map")
        reads=[tuple(map(int,m)) for m in re.findall(r"^RI_READ (\d+) (\d+) (\d+)$",response["receipt"]["stderr"],re.M)]
        self.assertIn((self.offset,self.size,self.size),reads)
        self.assertTrue(all(0<=offset and offset+length<=len(self.data) and got==length for offset,length,got in reads))
        self.assertLessEqual(sum(n for _,n,_ in reads),64*1024**2)
        self.assertIn("RI_SANDBOX seccomp_no_open_exec_network_writefiles",response["receipt"]["stderr"])

    def test_usa_counts_bounds_trailers_and_header_are_not_valid_inventory(self):
        mutations=[(6,b"\0\0","usa_count_rejected"),(6,b"\xff\xff","usa_count_rejected"),
                   (6,(1).to_bytes(2,"little"),"usa_count_rejected"),
                   (4,(49).to_bytes(2,"little"),"usa_bounds_rejected"),
                   (4,(self.size-2).to_bytes(2,"little"),"usa_bounds_rejected"),
                   (510,b"\xfe\xfe","fixup_mismatch"),
                   (24,(self.size+8).to_bytes(4,"little"),"header_bounds_rejected"),
                   (28,(self.size-1).to_bytes(4,"little"),"header_bounds_rejected"),
                   (20,(self.size-2).to_bytes(2,"little"),"header_bounds_rejected")]
        for offset,value,expected in mutations:
            with self.subTest(offset=offset,value=value):
                data=bytearray(self.data); data[self.offset+offset:self.offset+offset+len(value)]=value
                row=self.result(self.measure(data))
                self.assertEqual(row["record"]["structure"],expected)
                self.assertEqual(row["assessment"],"structural_rejection")

    def test_zero_free_used_and_allocation_conflict_are_distinct(self):
        data=bytearray(self.data); data[self.offset:self.offset+self.size]=bytes(self.size)
        row=self.result(self.measure(data))
        self.assertEqual(row["assessment"],"structural_rejection")
        self.bitmap_bit(data,False)
        row=self.result(self.measure(data))
        self.assertEqual(row["assessment"],"unallocated_corroborated")
        self.assertEqual(row["record"]["signature"],"zero")
        data=bytearray(self.data); self.bitmap_bit(data,False)
        row=self.result(self.measure(data))
        self.assertEqual((row["assessment"],row["reason"]),("inconclusive","allocation_conflict"))
        data[self.offset+22]&=254
        row=self.result(self.measure(data))
        self.assertEqual(row["assessment"],"unallocated_corroborated")
        data[self.offset+6:self.offset+8]=b"\0\0"
        row=self.result(self.measure(data))
        self.assertEqual(row["assessment"],"structural_rejection")  # Free bit is not an exemption.

    def test_unknown_bitmap_and_uninitialized_mft_are_inconclusive(self):
        data=bytearray(self.data); pos=self.mft_attribute(0xb0)
        if self.data[pos+8]: data[pos+56:pos+64]=bytes(8)
        else: data[pos:pos+4]=(0x100).to_bytes(4,"little")
        row=self.result(self.measure(data))
        self.assertEqual((row["assessment"],row["bitmap"]),("inconclusive","unknown"))
        self.assertEqual(row["record"]["structure"],"valid_header_fixups")
        data=bytearray(self.data); pos=self.mft_attribute(0x80)
        self.assertEqual(data[pos+8],1)
        data[pos+56:pos+64]=(self.inode*self.size).to_bytes(8,"little")
        row=self.result(self.measure(data))
        self.assertEqual(row["assessment"],"inconclusive")
        self.assertIsNone(row["record"])

    def test_fragmented_mft_uses_runs_not_a_contiguous_offset_guess(self):
        data=bytearray(self.data); pos=self.mft_attribute(0x80)
        run=pos+int.from_bytes(data[pos+32:pos+34],"little")
        # This generator has exactly one small extent. Split its last three
        # clusters into a NEW synthetic location, leaving the old target bad.
        self.assertEqual(data[run],0x11)
        blocks=data[run+1]; lcn=data[run+2]; split=self.inode*self.size//self.cluster
        self.assertLess(split,blocks); self.assertLess(blocks,128)
        destination=80
        source=(lcn+split)*self.cluster; length=(blocks-split)*self.cluster
        data[destination*self.cluster:destination*self.cluster+length]=data[source:source+length]
        data[self.offset:self.offset+self.size]=bytes(self.size)
        data[run:run+8]=bytes([0x11,split,lcn,0x11,blocks-split,destination-lcn,0,0])
        response=self.measure(data); row=self.result(response)
        self.assertEqual(row["assessment"],"valid_header_fixups")
        expected=destination*self.cluster+self.inode*self.size-split*self.cluster
        self.assertIn(f"RI_READ {expected} {self.size} {self.size}",response["receipt"]["stderr"])
        # A physically overlapping run is not a validated map.
        data[run+5]=0
        response=self.measure(data)
        if response["receipt"]["status"]=="ok":
            row=self.result(response)
            self.assertEqual(row["assessment"],"inconclusive")
            self.assertIsNone(row["record"])
        else:
            self.assertIsNone(response["result"])

    def test_strict_records_still_reject_same_invalid_usa_fixture(self):
        data=bytearray(self.data); data[self.offset+6:self.offset+8]=b"\0\0"
        row=self.result(self.measure(data))
        self.assertEqual(row["record"]["usa_count"],0)
        failed=self.measure(data,scope="ntfs.records",max_entries=1)
        self.assertEqual(failed["receipt"]["status"],"worker_failed")
        self.assertIsNone(failed["result"])
        self.assertIn("Invalid update count value out of bounds",failed["receipt"]["stderr"])

    def test_budget_truncated_geometry_and_out_of_range_never_succeed(self):
        failed=self.measure(read_budget=4096)
        self.assertEqual(failed["receipt"]["status"],"worker_failed")
        self.assertIsNone(failed["result"])
        self.assertIn("RI_DENIED",failed["receipt"]["stderr"])
        truncated=self.measure(self.data[:100],length=len(self.data))
        self.assertEqual(truncated["receipt"]["status"],"worker_failed")
        self.assertIn("RI_READ 0 512 100",truncated["receipt"]["stderr"])
        data=bytearray(self.data); data[64]=0xe0  # Unbounded record size rejected before libtsk.
        self.assertEqual(self.measure(data)["receipt"]["status"],"worker_failed")
        out=self.result(self.measure(inode=2**63-1))
        self.assertEqual(out["assessment"],"inconclusive")
        self.assertIsNone(out["record"])

    def test_typed_parameters_no_raw_offsets_content_or_batch(self):
        self.assertNotIn("ntfs.diagnose",core.SCAN_SCOPES)
        for values in ({"offset":0},{"inode":True},{"inode":15},{"cursor":0},{"max_entries":2},
                       {"max_bytes":65537},{"attribute_id":1},{"expected_sequence":1},{"expected_size":1},
                       {"allow_deleted":True},{"extensions":[".bak"]},{"read_budget":64*1024**2+1},
                       {"timeout_ms":10001}):
            with self.subTest(values=values), self.assertRaises(core.TriageError):
                core.parameters("ntfs.diagnose",values)

    def test_native_argument_limits_cannot_bypass_python(self):
        p=self.request()["parameters"]
        argv=[str(ROOT/".build/ntfs_worker"),"0","diagnose","0",str(len(self.data))]+[
            str(int(p[k])) for k in ("inode","attribute_id","max_entries","max_depth","max_bytes",
                                     "expected_sequence","expected_size","allow_deleted","read_budget","timeout_ms")]
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME|os.O_CLOEXEC)
        try:
            argv[1]=str(fd)
            for index,value in ((7,"2"),(9,"65537"),(13,str(64*1024**2+1)),(14,"10001")):
                bad=list(argv); bad[index]=value
                with self.subTest(index=index):
                    result=subprocess.run(bad,pass_fds=(fd,),capture_output=True,timeout=10)
                    self.assertEqual(result.returncode,2)
                    self.assertNotIn(b"RI_READ",result.stderr)
        finally: os.close(fd)

    def test_exit_zero_with_warning_or_malformed_rows_never_promoted(self):
        # Run the real sandboxed worker; inject only its captured pipe stream to
        # test wrapper handling, not a claim about an independent interpreter.
        real_read=core.os.read
        added=False
        def warning(fd,size):
            nonlocal added
            data=real_read(fd,size)
            if b"RI_ID " in data and not added:
                added=True
                return data+b"ntfs_mst_post_read_fixup_warn: synthetic warning\n"
            return data
        with mock.patch.object(core.os,"read",side_effect=warning): response=self.measure()
        self.assertTrue(added)
        self.assertEqual(response["receipt"]["returncode"],0)
        self.assertEqual(response["receipt"]["status"],"diagnostic_warning")
        self.assertIsNone(response["result"])
        self.assertIn("partial_stdout_base64",response["receipt"])
        changed=False
        def short_receipt(fd,size):
            nonlocal changed
            data=real_read(fd,size)
            if not changed and re.search(rb"RI_READ \d+ \d+ \d+\n",data):
                changed=True
                return re.sub(rb"(RI_READ \d+ \d+) \d+\n",rb"\1 0\n",data,count=1)
            return data
        with mock.patch.object(core.os,"read",side_effect=short_receipt): response=self.measure()
        self.assertTrue(changed)
        self.assertEqual(response["receipt"]["returncode"],0)
        self.assertEqual(response["receipt"]["status"],"invalid_diagnostic_receipts")
        self.assertIsNone(response["result"])
        row=self.result(self.measure())
        for change in ({"entries":[]},{"inode":True},{"bitmap":"free"},{"record":{"name_hex":"00"}},
                       {"inventory_eligible":True},{"reason":"arbitrary untrusted string"}):
            with self.subTest(change=change), self.assertRaises((ValueError,TypeError)):
                core.diagnostic_row({**copy.deepcopy(row),**change},self.inode)
        for key,value in (("fixup_mismatches",1),("usa_count",0),("attribute_offset",65535)):
            invalid=copy.deepcopy(row); invalid["record"][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError): core.diagnostic_row(invalid,self.inode)

    def test_independent_ntfsinfo_exit_zero_is_not_proof_of_fixups(self):
        data=bytearray(self.data); data[self.offset+6:self.offset+8]=b"\0\0"
        path=self.work/"independent-negative.ntfs"
        with path.open("xb") as f: f.write(data)
        path.chmod(0o400)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NOATIME|os.O_CLOEXEC)
        try:
            result=subprocess.run(["/usr/bin/ntfsinfo","--inode",str(self.inode),"/proc/self/fd/"+str(fd)],
                                  pass_fds=(fd,),capture_output=True,timeout=10,
                                  env={"PATH":"/usr/bin:/bin","LC_ALL":"C"})
        finally: os.close(fd)
        self.assertEqual(result.returncode,0)
        self.assertIn(b"ntfs_mst_post_read_fixup_warn",result.stderr)
        self.assertEqual(hashlib.sha256(read_regular(path,noatime=True)).digest(),hashlib.sha256(data).digest())


class NTFSDiagnosticCaseTests(NTFSTest):
    def test_explicit_consent_case_audit_and_redaction_without_content_output(self):
        params={"inode":self.manifest["entries"]["ordinary.docx"]["inode"]}
        with mock.patch.object(core,"run_worker",side_effect=AssertionError("No authorized read")):
            with self.assertRaises(RIError):
                ntfs_triage.run_image(self.store,self.case,self.image["id"],"ntfs.diagnose",params,
                    actor="Synthetic Operator",reason="Synthetic only",authorized=False,provided_scope="ntfs.diagnose")
        before=len(self.store.list("evidence",self.case))
        operation=ntfs_triage.run_image(self.store,self.case,self.image["id"],"ntfs.diagnose",params,
            actor="Synthetic Operator",reason="Explicit synthetic metadata-only diagnosis",authorized=True,provided_scope="ntfs.diagnose")
        self.assertEqual(operation["status"],"completed")  # Diagnostic delivered, NOT inventory validated.
        result=operation["results"][0]["result"]
        self.assertEqual(result["assessment"],"valid_header_fixups")
        self.assertFalse(result["inventory_eligible"])
        self.assertEqual(len(self.store.list("evidence",self.case)),before)
        self.assertNotIn("record",json.dumps(public_artifact_record(operation)))
        self.assertEqual(public_artifact_record(operation)["result_summary"]["worker_status"],"ok")
        with self.assertRaises(RIError):
            ntfs_triage.run_image(self.store,self.case,self.image["id"],"ntfs.diagnose",params,
                actor="Synthetic Operator",reason="Must not become scan pages",authorized=True,provided_scope="ntfs.diagnose",_page_handler=lambda *a:None)


class NTFSDiagnosticApprovalTests(ProjectTest):
    def test_simulated_exact_single_use_approval_not_metadata_batch_or_device_access(self):
        broker=load_module("diagnostic_broker_contract",ROOT/"broker/ntfs_broker.py")
        directory=self.work/"mock-broker-state"; directory.mkdir()
        for name in ("approved","used"): (directory/name).mkdir()
        request={"schema_version":1,"request_id":"c"*32,"case_id":"a"*32,"source_id":"b"*32,
                 "uid":os.getuid(),"scope":"ntfs.diagnose","parameters":core.parameters("ntfs.diagnose",{}),
                 "source":{"kind":"physical","pin":dict(PIN)},"reason":"Synthetic approval simulation, no device IO"}
        with (mock.patch.object(broker,"STATE",directory),
              mock.patch.object(broker,"root_file",side_effect=lambda p,**kw:Path(p)),
              mock.patch.object(broker,"ledger"),
              mock.patch.object(broker,"parser_identity",return_value=SimpleNamespace(pw_uid=65534,pw_gid=65534)),
              mock.patch.object(physical,"probe_physical",side_effect=AssertionError("No physical access"))):
            with self.assertRaises(ValueError):
                broker.approve_request(core,physical,request,"0"*64,os.getuid(),"Synthetic approval only")
            broker.approve_request(core,physical,request,core.sha(core.canonical(request)),os.getuid(),"Synthetic approval only")
            modified=copy.deepcopy(request); modified["parameters"]["inode"]+=1
            with self.assertRaises(ValueError): broker.consume(core,physical,modified,os.getuid())
            grant=broker.consume(core,physical,request,os.getuid())
            self.assertEqual(grant["request"],request)
            with self.assertRaises(OSError): broker.consume(core,physical,request,os.getuid())
            bundle={"schema_version":1,"requests":[request]}
            path=self.work/"batch.json"; path.write_bytes(core.canonical(bundle))
            with self.assertRaises(ValueError):
                broker.approve_batch(core,physical,path,core.sha(core.canonical(bundle)),os.getuid(),"Not a scan batch")
