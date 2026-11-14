import json
import os
import copy
import hashlib
import re
import subprocess
import multiprocessing
import base64
import time
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from tests.ntfs_support import NTFSTest, builder, PIN, state, load_module
from tests.common import ROOT, ProjectTest
from ransomware_investigator import ntfs_scan as scan
from ransomware_investigator.ntfs_triage import run_image, register_image, register_device
from ransomware_investigator.exchange import _read, read_manifest, verify_exchange, _atomic
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.artifacts import register_source
from ransomware_investigator.ntfs import core
from ransomware_investigator.safety import RIError, PublicationPending
from ransomware_investigator.audit import canonical, digest, bytes_digest
from tests.test_ntfs_broker import broker, request
from types import SimpleNamespace


def synthetic_validation_fixture(store,case_id,source_id):
    """Simulate a gate record ONLY in a labelled synthetic case, not hardware proof."""
    operation=store.record("operations",case_id,{"scope":"ntfs.reference-validation","status":"started"},"Synthetic fixture")
    report={"case_id":case_id,"operation_id":operation["id"],"source_id":source_id,"validation_passed":True,"eligible_for_physical_gate":True,
            "worker_sha256":bytes_digest((ROOT/".build/ntfs_worker").read_bytes()),"device_source_record_sha256":digest(store.get("evidence",source_id)),
            "fixture_notice":"SYNTHETIC MOCK RECORD, NEVER A REAL HARDWARE VALIDATION"}
    return scan._save_derived(store,case_id,operation,report,"Synthetic fixture")["operation_id"]


def second_controller(workspace,case_id,scan_id,queue):
    try:
        with CaseStore(workspace) as store:
            scan.run_image_batch(store,case_id,scan_id,actor="Synthetic child",reason="Synthetic",authorized=True,scope="ntfs.scan-metadata",max_pages=1)
        queue.put("unexpected success")
    except RIError:
        queue.put("blocked")


class NTFSScanImageTests(NTFSTest):
    def start(self, **kwargs):
        return scan.start_scan(self.store,self.case,self.image["id"],actor="Synthetic Operator",**kwargs)["id"]

    def run_batch(self, identifier, count=256):
        return scan.run_image_batch(self.store,self.case,identifier,actor="Synthetic Operator",reason="Synthetic metadata batch",authorized=True,scope="ntfs.scan-metadata",max_pages=count)

    def test_real_ntfs_complete_scan_pages_and_directory_inventory(self):
        identifier=self.start(page_size=8)
        result=self.run_batch(identifier)
        self.assertIn(result["status"],("completed","partial"), result)
        self.assertEqual(result["coverage"]["mft_slots_examined"],result["coverage"]["tsk_reported_mft_slots"])
        self.assertEqual(result["checkpoint"]["directories_completed"],result["checkpoint"]["directories_indexed"])
        self.assertEqual(result["checkpoint"]["category_counts"]["deleted_candidate"],result["checkpoint"]["deleted_candidates"])
        self.assertEqual(result["coverage"]["ntfs_directories_indexed"]+result["coverage"]["tsk_virtual_directories_indexed"],result["checkpoint"]["directories_indexed"])
        self.assertGreater(result["checkpoint"]["directories_completed"],1)
        self.assertIsNone(result["coverage"]["whole_device_percent"])
        self.assertTrue(self.store.verify()["valid"])
        pages=[e for e in self.store.list("evidence",self.case) if e.get("scan_id")==identifier]
        self.assertTrue(pages)
        seen=[]
        for page in pages:
            doc=json.loads(_read(self.store.workspace/page["relative_path"]))
            seen.extend(row["inode"] for row in doc["response"]["result"].get("entries",[]) if row.get("kind")=="record")
        self.assertEqual(len(seen),len(set(seen)))
        self.assertTrue(scan.verify_saved_scan(self.store,self.case,identifier)["valid"])
        summary=self.store.get("operations",identifier)["results"][0]["technical_summary"]
        self.assertTrue((self.store.workspace/summary["path"]).is_file())

    def test_checkpoint_resume_does_not_repeat_completed_ranges(self):
        identifier=self.start(page_size=16)
        initial=self.run_batch(identifier,2)
        self.assertEqual(initial["status"],"started")
        checkpoint=initial["checkpoint"]["page_index"]
        result=self.run_batch(identifier)
        self.assertIn(result["status"],("completed","partial"),result)
        self.assertGreater(result["checkpoint"]["page_index"],checkpoint)
        count=len(self.store.list("operations",self.case))
        self.run_batch(identifier)
        self.assertEqual(len(self.store.list("operations",self.case)),count)

    def test_large_and_boolean_limits_or_missing_consent_never_read(self):
        for kwargs in ({"page_size":True},{"page_size":257},{"max_records":0},{"max_directories":1000001}):
            with self.assertRaises(RIError): self.start(**kwargs)
        identifier=self.start()
        with patch("ransomware_investigator.ntfs_scan.triage.run_image",side_effect=AssertionError("No source read")):
            with self.assertRaises(RIError): scan.run_image_batch(self.store,self.case,identifier,actor="Synthetic Operator",reason="Test",authorized=False,scope="ntfs.scan-metadata")

    def test_read_budget_failure_retains_partial_receipt_without_advancing(self):
        identifier=self.start(read_budget=4096)
        result=self.run_batch(identifier)
        self.assertEqual(result["checkpoint"]["page_index"],0)
        self.assertEqual(result["failed_operation_count"],1)
        self.assertEqual(result["execution_state"],"paused_after_failure")
        operation=list(self.store.ntfs_scan_attempts(identifier))[-1]
        ref=operation["results"][0]["failed_scan_page"]
        data=_read(self.store.workspace/ref["path"])
        self.assertEqual(bytes_digest(data),ref["sha256"])
        response=json.loads(data)["response"]
        self.assertNotEqual(response["receipt"]["status"],"ok")
        self.assertIsNone(response["result"])

    def test_discontinuous_mft_page_does_not_advance_and_can_be_retried_explicitly(self):
        identifier=self.start(page_size=16); self.run_batch(identifier,1)
        before=self.store.ntfs_scan_state(identifier)
        original=core.run_worker
        def bad_page(*args,**kwargs):
            response=original(*args,**kwargs)
            response["result"]["entries"][0]["inode"]+=1
            return response
        with patch("ransomware_investigator.ntfs_triage.core.run_worker",side_effect=bad_page): result=self.run_batch(identifier)
        self.assertEqual(self.store.ntfs_scan_state(identifier),before)
        self.assertEqual(result["failed_operation_count"],1)
        result=self.run_batch(identifier)
        self.assertEqual(result["coverage"]["mft_slot_percent"],100)
        self.assertEqual(result["failed_operation_count"],1)

    def test_interruption_before_checkpoint_keeps_original_page_and_previous_progress(self):
        identifier=self.start(page_size=16); self.run_batch(identifier,1)
        before=self.store.ntfs_scan_state(identifier)
        with patch.object(self.store,"commit_ntfs_scan_page",side_effect=RuntimeError("Synthetic process interruption")):
            with self.assertRaises(RuntimeError): self.run_batch(identifier,1)
        files={path:_read(path) for path in (self.store.workspace/"scans"/identifier).glob("page-*.json")}
        self.assertEqual(self.store.ntfs_scan_state(identifier),before)
        result=self.run_batch(identifier)
        self.assertEqual(result["coverage"]["mft_slot_percent"],100)
        self.assertEqual(result["status"],"partial")
        self.assertTrue(result["unresolved_operation_ids"])
        for path,data in files.items(): self.assertEqual(_read(path),data)

    def test_tampered_checkpoint_and_second_controller_are_blocked(self):
        identifier=self.start()
        with scan._scan_lock(self.store,identifier):
            with self.assertRaises(RIError): self.run_batch(identifier,1)
        self.store.db.execute("UPDATE ntfs_scan_state SET document='{}' WHERE scan_id=?",(identifier,)); self.store.db.commit()
        with self.assertRaises(RIError): self.run_batch(identifier,1)

    def test_ads_backups_notes_and_windows_metadata_without_exporting_contents(self):
        extras={f"synthetic-{i}.bak.sealed":b"SYN\0SYNTHETIC_SECRET_CONTENT_DO_NOT_EXPORT" for i in range(8)}
        extras.update({"Contact.txt":b"SYNTHETIC only", "Security.evtx":b"ElfFile\0synthetic", "historical.tib":b"synthetic", "database.mdf":b"synthetic"})
        fixture=builder.create_fixture(self.inputs,extra_files=extras,alternate_streams={("Contact.txt","ri_trace"):b"SYNTHETIC ADS secret"})
        image=register_image(self.store,self.case,source_id=self.original["id"],path=fixture["path"],expected_sha256=fixture["sha256"],offset_bytes=0,volume_length=None,actor="Synthetic Operator",reason="Synthetic extended fixture",authorized=True,scope="ntfs.register-image")
        identifier=scan.start_scan(self.store,self.case,image["id"],actor="Synthetic Operator",page_size=16)["id"]
        result=self.run_batch(identifier)
        self.assertIn(result["status"],("completed","partial"),result)
        self.assertEqual(result["checkpoint"]["category_counts"]["encrypted_suffix"],8)
        self.assertGreaterEqual(result["checkpoint"]["category_counts"]["backup_candidate"],9)
        self.assertEqual(result["checkpoint"]["category_counts"]["windows_event_log_candidate"],1)
        attributes=[]
        for evidence in self.store.list("evidence",self.case):
            if evidence.get("scan_id")!=identifier: continue
            data=_read(self.store.workspace/evidence["relative_path"])
            self.assertNotIn(b"SYNTHETIC_SECRET_CONTENT_DO_NOT_EXPORT",data)
            self.assertNotIn(b"SYNTHETIC ADS secret",data)
            page=json.loads(data)
            for row in page["response"]["result"].get("entries",[]): attributes.extend(row.get("attributes",[]))
        self.assertTrue(any(a["type"]==128 and a["name"]=="ri_trace" for a in attributes))
        self.assertTrue(any(a["runs"] for a in attributes))

    def test_generated_build_or_volume_change_is_preserved_as_failure(self):
        identifier=self.start(); self.run_batch(identifier,1)
        original=core.run_worker
        def changed(*args,**kwargs):
            response=original(*args,**kwargs); response["receipt"]["worker_sha256"]="f"*64; return response
        with patch("ransomware_investigator.ntfs_triage.core.run_worker",side_effect=changed): result=self.run_batch(identifier,1)
        self.assertEqual(result["checkpoint"]["page_index"],1)
        self.assertEqual(result["failed_operation_count"],1)
        ref=list(self.store.ntfs_scan_attempts(identifier))[-1]["results"][0]["failed_scan_page"]
        self.assertIn("validation_error",json.loads(_read(self.store.workspace/ref["path"])))

    def test_changed_python_producer_blocks_resume_before_source_access(self):
        identifier=self.start()
        with patch("ransomware_investigator.ntfs_scan._producer_sha256",return_value="f"*64),patch("ransomware_investigator.ntfs_scan.triage.run_image",side_effect=AssertionError("No source")):
            with self.assertRaises(RIError): self.run_batch(identifier,1)
        self.assertEqual(self.store.ntfs_scan_state(identifier)["page_index"],0)

    def test_two_processes_cannot_control_the_same_scan(self):
        identifier=self.start(); context=multiprocessing.get_context("spawn"); queue=context.Queue()
        process=context.Process(target=second_controller,args=(str(self.store.workspace),self.case,identifier,queue))
        with scan._scan_lock(self.store,identifier):
            process.start(); process.join(30)
            if process.is_alive(): process.terminate(); process.join(5); self.fail("Synthetic controller did not stop")
            self.assertEqual(process.exitcode,0)
            self.assertEqual(queue.get(timeout=2),"blocked")
        self.assertEqual(self.store.ntfs_scan_state(identifier)["page_index"],0)

    def test_partial_directory_page_continues_by_index_not_name_or_depth(self):
        identifier=self.start(page_size=2)
        result=self.run_batch(identifier)
        self.assertEqual(result["checkpoint"]["directories_completed"],result["checkpoint"]["directories_indexed"])
        root_pages=[]
        for evidence in self.store.list("evidence",self.case):
            if evidence.get("scan_id")!=identifier: continue
            page=json.loads(_read(self.store.workspace/evidence["relative_path"]))
            if page["request"]["scope"]=="ntfs.directory" and page["request"]["parameters"]["inode"]==5: root_pages.append(page)
        self.assertGreater(len(root_pages),1)
        seen=[row["index"] for page in root_pages for row in page["response"]["result"]["entries"]]
        self.assertEqual(seen,list(range(len(seen))))

    def test_saved_comparison_matches_independent_tsk_on_an_unregistered_synthetic_fixture(self):
        fixture=builder.create_fixture(self.inputs)
        # Independent TSK reads only this NEW fixture, before registration/sealing
        # of its evidence identity. No registered copy is opened without O_NOATIME.
        fls=subprocess.run(["/usr/local/bin/fls","-f","ntfs",fixture["path"],"11"],check=True,capture_output=True,timeout=15).stdout
        references={}
        for line in fls.decode().splitlines():
            match=re.match(r"\S+\s+(\*\s+)?(\d+)(?:-\d+-\d+)?:\s+(.+)",line)
            if match:
                name=match[3].split(":",1)[0]
                inode=int(match[2])
                istat=subprocess.run(["/usr/local/bin/istat","-f","ntfs",fixture["path"],str(inode)],check=True,capture_output=True,timeout=15).stdout
                sequence=int(re.search(rb"Sequence:\s*(\d+)",istat)[1])
                references[(inode,name)]={"name":name,"inode":inode,"name_unallocated":bool(match[1]),"name_sequence":sequence,"ntfs_path":"/$Extend/"+name}
        image=register_image(self.store,self.case,source_id=self.original["id"],path=fixture["path"],expected_sha256=fixture["sha256"],offset_bytes=0,volume_length=None,actor="Synthetic Operator",reason="Synthetic TSK reference",authorized=True,scope="ntfs.register-image")
        def read(scope,params): return run_image(self.store,self.case,image["id"],scope,params,actor="Synthetic Operator",reason="Synthetic",authorized=True,provided_scope=scope)
        listing=read("ntfs.directory",{"inode":11,"max_entries":128})
        metadata=read("ntfs.records",{"inode":11,"max_entries":1})
        baseline={"schema_version":1,"source_id":image["id"],"directory_inode":11,"directory_name":"$Extend","directory_path":"/$Extend/",
                  "expected_count":len(references),"entries":list(references.values()),"reference_tool":{"name":"TSK fls + istat (synthetic only)","version":"4.15.0","original_output_sha256":bytes_digest(fls)}}
        path=self.store.workspace/"baseline.json"; path.write_text(canonical(baseline)); path.chmod(0o600)
        result=scan.compare_saved_reference(self.store,self.case,listing["id"],metadata["id"],path,bytes_digest(_read(path)),"Synthetic Operator")
        self.assertTrue(result["validation_passed"],result)
        baseline["expected_count"]=8; baseline["entries"]=[]
        path2=self.store.workspace/"missing-baseline.json"; path2.write_text(canonical(baseline)); path2.chmod(0o600)
        missing=scan.compare_saved_reference(self.store,self.case,listing["id"],metadata["id"],path2,bytes_digest(_read(path2)),"Synthetic Operator")
        self.assertFalse(missing["validation_passed"])

    def test_selective_prefix_is_separate_from_metadata_and_never_a_whole_file_hash(self):
        content=b"SYN\0"+b"SYNTHETIC_PREFIX_ONLY"*100
        fixture=builder.create_fixture(self.inputs,extra_files={"small.sealed":content})
        image=register_image(self.store,self.case,source_id=self.original["id"],path=fixture["path"],expected_sha256=fixture["sha256"],offset_bytes=0,volume_length=None,actor="Synthetic Operator",reason="Synthetic prefix source",authorized=True,scope="ntfs.register-image")
        metadata=run_image(self.store,self.case,image["id"],"ntfs.mft",{"inode":fixture["entries"]["small.sealed"]["inode"]},actor="Synthetic Operator",reason="Synthetic MFT",authorized=True,provided_scope="ntfs.mft")["results"][0]["result"]
        params={"inode":metadata["inode"],"attribute_id":metadata["streams"][0]["id"],"expected_sequence":metadata["sequence"],"expected_size":len(content),"max_bytes":64}
        first=run_image(self.store,self.case,image["id"],"ntfs.prefix",params,actor="Synthetic Operator",reason="Only first 64 bytes authorized",authorized=True,provided_scope="ntfs.prefix")["results"][0]["result"]
        self.assertEqual(first["size_bytes"],64)
        self.assertEqual(first["hash_scope"],"prefix_only")
        self.assertNotEqual(first["sha256"],hashlib.sha256(content).hexdigest())
        self.assertEqual(first["header_assessment"]["signature_observations"],["synthetic_test_marker"])
        self.assertIsNone(first["header_assessment"]["ransomware_family"])
        evidence=self.store.get("evidence",first["evidence_id"]); path=self.store.workspace/evidence["relative_path"]
        before=path.stat()
        second=run_image(self.store,self.case,image["id"],"ntfs.prefix",params,actor="Synthetic Operator",reason="Repeat explicitly authorized",authorized=True,provided_scope="ntfs.prefix")["results"][0]["result"]
        self.assertTrue(second["reused"])
        self.assertEqual(second["evidence_id"],first["evidence_id"])
        after=path.stat()
        self.assertEqual((before.st_atime_ns,before.st_mtime_ns,before.st_ctime_ns),(after.st_atime_ns,after.st_mtime_ns,after.st_ctime_ns))
        self.assertEqual(_read(path),content[:64])
        with self.assertRaises(ValueError): core.parameters("ntfs.prefix",{**params,"max_bytes":65537})
        self.assertEqual(core.parameters("ntfs.prefix",{**params,"expected_size":2**40})["expected_size"],2**40)
        with self.assertRaises(ValueError): core.parameters("ntfs.extract",{**params,"expected_size":2**40})
        self.assertTrue(self.store.verify()["valid"])

    def test_eight_file_reference_comparator_with_mocked_observations_is_not_physical_validation(self):
        # Deliberately invented entries. This tests comparison, NOT SYNTHETIC_VOLUME_A contents.
        entries=[{"name":str(i)+".bak.sealed","inode":100+i,"name_sequence":1,"name_unallocated":False} for i in range(8)]
        baseline={"schema_version":1,"source_id":self.image["id"],"directory_inode":120,"directory_name":"SYNTHETIC_BACKUPS","directory_path":"/SYNTHETIC_BACKUPS/",
                  "expected_count":8,"entries":[{**row,"ntfs_path":"/SYNTHETIC_BACKUPS/"+row["name"]} for row in entries],
                  "reference_tool":{"name":"SYNTHETIC MOCK, NOT SYNTHETIC_VOLUME_A","original_output_sha256":"a"*64}}
        volume={"filesystem":"NTFS","fs_id_hex":"SYNTHETIC"}
        metadata={"entries":[{"inode":120,"allocated":True,"directory":True,"names":[{"name":"SYNTHETIC_BACKUPS","parent_inode":5}]}],"summary":{"volume_identity":volume}}
        op={"source_id":self.image["id"],"request":{"parameters":{"inode":120,"cursor":0}}}
        listing={"entries":entries,"summary":{"partial":False,"eof":True,"volume_identity":volume}}
        path=self.store.workspace/"synthetic-reference.json"; path.write_text(canonical(baseline)); path.chmod(0o600)
        with patch("ransomware_investigator.ntfs_scan._saved_payload",side_effect=[(op,listing),(op,metadata)]):
            result=scan.compare_saved_reference(self.store,self.case,"a"*32,"b"*32,path,bytes_digest(_read(path)),"Synthetic Operator")
        self.assertTrue(result["validation_passed"])
        listing["entries"][0]["name_unallocated"]=True
        with patch("ransomware_investigator.ntfs_scan._saved_payload",side_effect=[(op,listing),(op,metadata)]):
            result=scan.compare_saved_reference(self.store,self.case,"a"*32,"b"*32,path,bytes_digest(_read(path)),"Synthetic Operator")
        self.assertFalse(result["validation_passed"])

    def test_physical_batch_adapter_consumes_mock_transport_pages_without_device_io(self):
        from ransomware_investigator.ntfs import physical
        pin={**PIN,"partition_table_type":"dos","partition_table_id":"11112222"}
        declared=register_source(self.store,self.case,reference="SYNTHETIC MOCK TRANSPORT",source_kind="physical-device",description="Not hardware",source_sha256=None,actor="Synthetic Operator")
        device=register_device(self.store,self.case,source_id=declared["id"],pin=pin,actor="Synthetic Operator",reason="Synthetic mock only")
        validation=synthetic_validation_fixture(self.store,self.case,device["id"])
        identifier=scan.start_scan(self.store,self.case,device["id"],actor="Synthetic Operator",page_size=16,validation_operation=validation)["id"]
        observed_state={**state(),"partition_table_type":"dos","partition_table_id":"11112222"}
        def transport(req):
            surrogate=run_image(self.store,self.case,self.image["id"],req["scope"],req["parameters"],actor="Synthetic Operator",reason="Synthetic surrogate regular image",authorized=True,provided_scope=req["scope"])["results"][0]
            surrogate.pop("source_validation",None)
            surrogate["receipt"].update(request_sha256=digest(req),parser_uid=65534,read_offset_basis="partition_device_bytes")
            return {"status":"completed","request_id":req["request_id"],"request_sha256":digest(req),"before":observed_state,"after":dict(observed_state),"worker":surrogate,"broker_audit_sha256":"a"*64}
        with patch("ransomware_investigator.ntfs.client.execute_physical",side_effect=transport),patch.object(physical,"probe_physical",side_effect=AssertionError("No hardware")):
            for _ in range(20):
                current=scan.status(self.store,self.case,identifier)
                if current["status"]!="started": break
                scan.prepare_physical_batch(self.store,self.case,identifier,actor="Synthetic Operator",reason="Synthetic metadata batch",authorized=True,scope="ntfs.scan-metadata",max_pages=2)
                current=scan.execute_physical_batch(self.store,self.case,identifier,actor="Synthetic Operator",authorized=True,max_pages=2)
            else: self.fail("Synthetic mock batches did not finish")
        self.assertIn(current["status"],("completed","partial"))
        self.assertEqual(current["coverage"]["mft_slot_percent"],100)
        self.assertEqual(current["failed_operation_count"],0)
        self.assertFalse(current["pending_physical_requests"])
        self.assertTrue(self.store.verify()["valid"])


class ScanSharedCaseTests(ProjectTest):
    @classmethod
    def setUpClass(cls):
        from tests.ntfs_support import build_worker
        build_worker()

    def test_shared_case_page_descriptors_hashes_and_deterministic_correlations(self):
        root=self.work/"synthetic-case"; root.mkdir(mode=0o700)
        with CaseStore(case_root=root) as store:
            case=store.attach_case("SYNTHETIC NOT ALQUIMIX","Synthetic Operator","Synthetic Operator")["id"]
            inputs=store.workspace/"extracted"; inputs.mkdir(mode=0o700)
            scans=[]
            for label in ("one","two"):
                source=register_source(store,case,reference="SYNTHETIC "+label,source_kind="synthetic",description="Not physical",source_sha256=None,actor="Synthetic Operator")
                fixture=builder.create_fixture(inputs)
                image=register_image(store,case,source_id=source["id"],path=fixture["path"],expected_sha256=fixture["sha256"],offset_bytes=0,volume_length=None,actor="Synthetic Operator",reason="Synthetic",authorized=True,scope="ntfs.register-image")
                identifier=scan.start_scan(store,case,image["id"],actor="Synthetic Operator",page_size=128)["id"]; scans.append(identifier)
                scan.run_image_batch(store,case,identifier,actor="Synthetic Operator",reason="Synthetic metadata only",authorized=True,scope="ntfs.scan-metadata",max_pages=256)
            snapshot=read_manifest(root)
            pages=[e for e in store.list("evidence",case) if e.get("status")=="ntfs_scan_page"]
            self.assertTrue(pages)
            self.assertTrue(all(e["id"] in snapshot["records"]["evidence"] for e in pages))
            for e in pages: self.assertEqual(bytes_digest(_read(store.workspace/e["relative_path"])),e["content_sha256"])
            result=scan.correlate_saved(store,case,"Synthetic Operator")
            report=json.loads(_read(store.workspace/result["report"]["path"]))
            self.assertTrue(report["groups"])
            self.assertTrue(all(g["causal_attribution"]=="not_established" for g in report["groups"]))
            before_ids=sorted(f["finding_id"] for e in pages for f in json.loads(_read(store.workspace/e["relative_path"]))["findings"])
            scan.correlate_saved(store,case,"Synthetic Operator")
            after_ids=sorted(f["finding_id"] for e in pages for f in json.loads(_read(store.workspace/e["relative_path"]))["findings"])
            self.assertEqual(before_ids,after_ids)
            self.assertTrue(verify_exchange(root)["valid"])
            self.assertTrue(store.verify()["valid"])


class ScanPhysicalPreparationTests(ProjectTest):
    @classmethod
    def setUpClass(cls):
        from tests.ntfs_support import build_worker
        build_worker()

    def setUp(self):
        super().setUp(); self.store=CaseStore(self.work/"case"); self.addCleanup(self.store.db.close)
        self.case=self.store.create_case("Synthetic physical plan","Synthetic Operator","Synthetic Operator")["id"]
        source=register_source(self.store,self.case,reference="SYNTHETIC PIN",source_kind="physical-device",description="Never connected",source_sha256=None,actor="Synthetic Operator")
        pin={**PIN,"partition_table_type":"dos","partition_table_id":"11112222"}
        self.source=register_device(self.store,self.case,source_id=source["id"],pin=pin,actor="Synthetic Operator",reason="Synthetic declaration")
        self.validation=synthetic_validation_fixture(self.store,self.case,self.source["id"])
        self.identifier=scan.start_scan(self.store,self.case,self.source["id"],actor="Synthetic Operator",validation_operation=self.validation)["id"]

    def test_full_physical_scan_requires_initial_validation_even_before_preparing_requests(self):
        with self.assertRaises(RIError): scan.start_scan(self.store,self.case,self.source["id"],actor="Synthetic Operator")
        with patch("ransomware_investigator.ntfs_scan.triage.WORKER") as worker:
            worker.read_bytes.return_value=b"changed synthetic build"
            with self.assertRaises(RIError): scan.start_scan(self.store,self.case,self.source["id"],actor="Synthetic Operator",validation_operation=self.validation)

    def test_preparing_batch_is_not_preflight_or_physical_access_and_has_no_fallback(self):
        with patch("ransomware_investigator.ntfs.physical.probe_physical",side_effect=AssertionError("No devices")),patch("subprocess.Popen",side_effect=AssertionError("No escalation")):
            prepared=scan.prepare_physical_batch(self.store,self.case,self.identifier,actor="Synthetic Operator",reason="Synthetic request",authorized=True,scope="ntfs.scan-metadata")
            self.assertFalse(prepared["physical_read_performed"])
            self.assertEqual(prepared["request_count"],1)
            with self.assertRaises(RIError): scan.run_image_batch(self.store,self.case,self.identifier,actor="Synthetic Operator",reason="No",authorized=True,scope="ntfs.scan-metadata")
        with patch("ransomware_investigator.ntfs.client.execute_physical",side_effect=OSError("No broker deployed")):
            with self.assertRaises(OSError): scan.execute_physical_batch(self.store,self.case,self.identifier,actor="Synthetic Operator",authorized=True)
        result=scan.status(self.store,self.case,self.identifier)
        self.assertEqual(result["checkpoint"]["page_index"],0)
        self.assertEqual(result["failed_operation_count"],1)

    def test_initial_validation_batch_stops_at_first_failed_transport(self):
        prepared=scan.prepare_initial_validation(self.store,self.case,self.source["id"],directory_inode=120,directory_name="SYNTHETIC_BACKUPS",expected_count=8,actor="Synthetic Operator",reason="Synthetic initial batch",authorized=True)
        self.assertEqual(prepared["request_count"],4)
        self.assertFalse(prepared["physical_read_performed"])
        with patch("ransomware_investigator.ntfs.client.execute_physical",side_effect=OSError("Synthetic missing broker")) as client:
            with self.assertRaises(OSError): scan.execute_initial_validation(self.store,self.case,prepared["plan_operation_id"],actor="Synthetic Operator",authorized=True)
        self.assertEqual(client.call_count,1)
        statuses=[self.store.get("operations",identifier)["status"] for identifier in prepared["operation_ids"]]
        self.assertEqual(statuses,["failed","started","started","started"])

    def test_initial_execution_alone_is_not_validation_and_fresh_root_is_required(self):
        prepared=scan.prepare_initial_validation(self.store,self.case,self.source["id"],directory_inode=120,directory_name="SYNTHETIC_BACKUPS",expected_count=8,actor="Synthetic Operator",reason="Synthetic initial batch",authorized=True)
        volume={"filesystem":"NTFS","first_inode":0,"last_inode":200000,"root_inode":5,"block_size":4096,"block_count":4096,"fs_id_hex":"0011223344556677"}
        observed_state={**state(),"partition_table_type":"dos","partition_table_id":"11112222"}
        children=[{"kind":"directory_entry","index":i,"parent_inode":120,"inode":100+i,"name_sequence":1,"name_unallocated":False,"name_type":5,"name":str(i)+".bak.sealed"} for i in range(8)]
        def transport(req):
            p=req["parameters"]
            if req["scope"]=="ntfs.volume": payload={"kind":"volume","volume_identity":volume,"tsk_version":"4.15.0"}
            elif req["scope"]=="ntfs.records":
                row={"kind":"record","inode":p["inode"],"sequence":5 if p["inode"]==5 else 7,"allocated":True,"directory":True,"names":[]}
                if p["inode"]==120: row["names"]=[{"name":"SYNTHETIC_BACKUPS","parent_inode":5,"parent_sequence":5}]
                payload={"entries":[row],"summary":{"volume_identity":volume,"partial":False}}
            else: payload={"entries":children,"summary":{"volume_identity":volume,"eof":True,"partial":False}}
            receipt={"status":"ok","request_sha256":digest(req),"parser_uid":65534,"stdout_sha256":digest(payload),"stderr":"RI_READ 0 512 512\n","worker_sha256":bytes_digest((ROOT/".build/ntfs_worker").read_bytes())}
            return {"status":"completed","request_id":req["request_id"],"request_sha256":digest(req),"before":observed_state,"after":dict(observed_state),"broker_audit_sha256":"a"*64,"worker":{"receipt":receipt,"result":payload}}
        with patch("ransomware_investigator.ntfs.client.execute_physical",side_effect=transport):
            executed=scan.execute_initial_validation(self.store,self.case,prepared["plan_operation_id"],actor="Synthetic Operator",authorized=True)
        self.assertFalse(executed["validation_passed"])
        baseline={"schema_version":1,"source_id":self.source["id"],"directory_inode":120,"directory_name":"SYNTHETIC_BACKUPS","directory_path":"/SYNTHETIC_BACKUPS/",
                "expected_count":8,"entries":[{key:row[key] for key in ("name","inode","name_unallocated")} | {"ntfs_path":"/SYNTHETIC_BACKUPS/"+row["name"]} for row in children],
                "reference_tool":{"name":"SYNTHETIC MOCK, NOT REAL SYNTHETIC_VOLUME_A/TSK","original_output_sha256":"b"*64}}
        path=self.store.workspace/"baseline.json"; path.write_text(canonical(baseline)); path.chmod(0o600)
        without_root=scan.compare_saved_reference(self.store,self.case,executed["listing_operation_id"],executed["metadata_operation_id"],path,bytes_digest(_read(path)),"Synthetic Operator")
        self.assertFalse(without_root["validation_passed"])
        matched=scan.compare_saved_reference(self.store,self.case,executed["listing_operation_id"],executed["metadata_operation_id"],path,bytes_digest(_read(path)),"Synthetic Operator",root_metadata_id=executed["root_metadata_operation_id"])
        self.assertTrue(matched["validation_passed"])
        report=json.loads(_read(self.store.workspace/matched["report"]["path"]))
        self.assertFalse(report["child_name_sequences_compared"])
        self.assertTrue(report["root_parent_sequence_verified"])
        job=scan.start_scan(self.store,self.case,self.source["id"],actor="Synthetic Operator",validation_operation=matched["operation_id"])
        self.assertEqual(job["status"],"started")
        self.assertTrue(self.store.verify()["valid"])

    def test_administrator_batch_is_exact_metadata_only_and_single_use(self):
        state_root=self.work/"root-state"; state_root.mkdir(mode=0o700)
        for name in ("approved","used"): (state_root/name).mkdir(mode=0o700)
        first=request("ntfs.records",{"inode":0,"max_entries":8}); second=request("ntfs.records",{"inode":8,"max_entries":8}); second["request_id"]="d"*32
        bundle={"schema_version":1,"requests":[first,second]}; path=self.work/"batch.json"; path.write_text(canonical(bundle))
        with patch.object(broker,"STATE",state_root),patch.object(broker,"root_file",side_effect=lambda p,**kw:Path(p)),patch.object(broker,"ledger",return_value="a"*64),patch.object(broker,"parser_identity",return_value=SimpleNamespace(pw_uid=65534,pw_gid=65534)):
            result=broker.approve_batch(core,__import__('ransomware_investigator.ntfs.physical',fromlist=['validate_pin']),path,digest(bundle),os.getuid(),"Synthetic administrator approval")
            self.assertEqual(len(result["grants"]),2)
            from ransomware_investigator.ntfs import physical
            broker.consume(core,physical,first,os.getuid())
            with self.assertRaises(OSError): broker.consume(core,physical,first,os.getuid())
            bad={"schema_version":1,"requests":[request("ntfs.extract",{"inode":64,"expected_sequence":1})]}; path2=self.work/"bad.json"; path2.write_text(canonical(bad))
            with self.assertRaises(ValueError): broker.approve_batch(core,physical,path2,digest(bad),os.getuid(),"Not authorized")

    def test_broker_returns_failed_diagnostics_only_after_successful_postchecks(self):
        from ransomware_investigator.ntfs import physical
        req=request("ntfs.records",{"max_entries":8})
        file=self.work/"synthetic-fd"; file.write_bytes(b"synthetic descriptor, never /dev")
        fd=os.open(file,os.O_RDONLY)
        worker={"receipt":{"status":"worker_failed","request_sha256":digest(req),"stderr":"RI_READ 0 512 -1\n","partial_stdout_base64":base64.b64encode(b"SYNTHETIC incomplete JSON").decode()},"result":None}
        with patch.object(broker,"consume",return_value={"expires_at":time.time()+300}),patch.object(broker,"audit_capacity"),patch.object(broker,"ledger",return_value="a"*64),patch.object(broker,"parser_identity",return_value=SimpleNamespace(pw_uid=65534,pw_gid=65534)),patch.object(physical,"probe_physical",return_value=(fd,state())),patch.object(physical,"recheck_physical",return_value=state()) as recheck,patch.object(core,"run_worker",return_value=worker):
            response=broker.execute(core,physical,Path("unused"),req,os.getuid())
        recheck.assert_called_once()
        self.assertEqual(response["operation_status"],"failed")
        self.assertEqual(response["worker"]["receipt"]["partial_stdout_base64"],worker["receipt"]["partial_stdout_base64"])
        self.assertIsNone(response["worker"]["result"])


class ScanPureTests(ProjectTest):
    def test_atomic_pointer_unlink_does_not_weaken_immutable_file_checks(self):
        directory=self.work/"exchange"; directory.mkdir(mode=0o700)
        pointer=directory/"manifest.json"; pointer.write_bytes(b'{"version":1}'); pointer.chmod(0o600)
        staged=directory/"new-pointer.json"; staged.write_bytes(b'{"version":2}'); staged.chmod(0o600)
        original=os.fdopen
        @contextmanager
        def reader(fd,*args,**kwargs):
            with original(fd,*args,**kwargs) as stream:
                class View:
                    def read(self,size):
                        data=stream.read(size); os.replace(staged,pointer); return data
                yield View()
        with patch("ransomware_investigator.exchange.os.fdopen",side_effect=reader):
            self.assertEqual(_read(pointer,replaceable_pointer=True),b'{"version":1}')
        immutable=directory/"record.json"; immutable.write_bytes(b"immutable"); immutable.chmod(0o600)
        staged.write_bytes(b"replacement"); staged.chmod(0o600)
        @contextmanager
        def immutable_reader(fd,*args,**kwargs):
            with original(fd,*args,**kwargs) as stream:
                class View:
                    def read(self,size):
                        data=stream.read(size); os.replace(staged,immutable); return data
                yield View()
        with patch("ransomware_investigator.exchange.os.fdopen",side_effect=immutable_reader):
            with self.assertRaises(RIError): _read(immutable)
        with self.assertRaises(RIError): _read(immutable,replaceable_pointer=True)

    def test_header_signatures_do_not_identify_family_algorithm_or_restorability(self):
        result=scan.inspect_authorized_header(b"SYN\0SYNTHETIC")
        self.assertEqual(result["signature_observations"],["synthetic_test_marker"])
        self.assertIsNone(result["algorithm"]); self.assertIsNone(result["ransomware_family"]); self.assertIsNone(result["restorable"])
        self.assertEqual(scan.inspect_authorized_header(b"TAPEsynthetic")["signature_observations"],["Microsoft_tape_or_SQL_backup_candidate"])
        with self.assertRaises(RIError): scan.inspect_authorized_header(b"x"*65537)

    def test_metadata_years_and_extensions_are_not_restore_tests(self):
        historical=scan.classify_metadata(["backup.tib"],{"modified":915148800},reference_year=2000)
        self.assertEqual(historical["priority"],"historical_metadata_candidate")
        self.assertIsNone(historical["restorable"])
        recent=scan.classify_metadata(["backup.bak.sealed"],{"modified":946684800},reference_year=2000)
        self.assertEqual(recent["priority"],"reference_year_metadata_candidate")
        self.assertEqual(recent["potential_encryption_basis"],"filename_suffix_only")
        self.assertEqual(recent["header_status"],"not_read_in_metadata_scope")
        last_access_only=scan.classify_metadata(["old.bak"],{"modified":915148800,"created":915148800,"accessed":946684800},reference_year=2000)
        self.assertEqual(last_access_only["priority"],"historical_metadata_candidate")

        unconfigured=scan.classify_metadata(["backup.bak"],{"modified":946684800})
        self.assertEqual(unconfigured["priority"],"unranked")
        for invalid_year in (True, 0, 10000, "2000"):
            with self.assertRaises(RIError):
                scan.classify_metadata(["backup.bak"],{},reference_year=invalid_year)
        encrypted_archive=scan.classify_metadata(["archive.zip.sealed"],{})
        self.assertIn("backup_candidate",encrypted_archive["labels"])
        encrypted_log=scan.classify_metadata(["Security.evtx.sealed"],{})
        self.assertIn("windows_event_log_candidate",encrypted_log["labels"])

    def test_cyclic_directory_parents_do_not_loop_and_deep_paths_are_explicitly_unknown(self):
        class Store:
            def ntfs_scan_directory(self,scan_id,*,inode=None):
                return {"inode":inode,"sequence":1,"names":[{"name":"synthetic","parent_inode":2 if inode==1 else 1,"parent_sequence":1}]}
        self.assertIsNone(scan._directory_path(Store(),"a"*32,1,5))
        class Deep:
            def ntfs_scan_directory(self,scan_id,*,inode=None):
                return {"inode":inode,"sequence":1,"names":[{"name":"deep","parent_inode":inode+1,"parent_sequence":1}]}
        self.assertIsNone(scan._directory_path(Deep(),"a"*32,1,0))

    def test_paged_cursor_is_typed_and_not_allowed_on_legacy_operations(self):
        self.assertEqual(core.parameters("ntfs.directory",{"cursor":70000})["cursor"],70000)
        for scope,params in (("ntfs.list",{"cursor":1}),("ntfs.directory",{"cursor":True}),("ntfs.records",{"max_depth":1})):
            with self.assertRaises(ValueError): core.parameters(scope,params)

    def test_partition_table_discrepancy_is_a_block_not_a_serial_fallback(self):
        from ransomware_investigator.ntfs.physical import validate_pin,validate_state
        pin={**PIN,"partition_table_type":"dos","partition_table_id":"11112222"}
        current={**state(),"partition_table_type":"dos","partition_table_id":"11112222"}
        self.assertEqual(validate_state(pin,current),current)
        with self.assertRaises(ValueError): validate_state(pin,{**current,"partition_table_id":"33334444"})
        with self.assertRaises(ValueError): validate_pin({**pin,"partition_table_type":"gpt"})
