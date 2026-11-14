import contextlib
import base64
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.common import ROOT
from tests.ntfs_support import NTFSTest,builder
from ransomware_investigator.artifacts import analyze_artifact,register_artifact
from ransomware_investigator.cli import main
from ransomware_investigator.ntfs import core
from ransomware_investigator.ntfs_triage import run_image,register_image
from ransomware_investigator.ntfs_triage import _extract_output
from ransomware_investigator.safety import RIError


class NTFSImageTests(NTFSTest):
    def run_op(self,name,params=None,**kwargs):
        arguments=dict(actor="Synthetic Operator",reason="Explicit synthetic NTFS operation",authorized=True,provided_scope="ntfs."+name)
        arguments.update(kwargs)
        return run_image(self.store,self.case,self.image["id"],"ntfs."+name,params or {},**arguments)

    def mft(self,name):
        result=self.run_op("mft",{"inode":self.manifest["entries"][name]["inode"]})
        self.assertEqual(result["status"],"completed")
        return result["results"][0]["result"]

    def extraction_params(self,name,**kwargs):
        metadata=self.mft(name)
        stream=metadata["streams"][0]
        return {"inode":metadata["inode"],"attribute_id":stream["id"],"expected_sequence":metadata["sequence"],
                "expected_size":stream["size_bytes"],**kwargs}

    def test_real_libtsk_lists_root_and_subdirectory_without_mounts(self):
        before=Path(self.manifest["path"]).stat()
        result=self.run_op("list")["results"][0]
        names={row["name"] for row in result["result"]["entries"]}
        self.assertTrue(set(builder.FILES)<=names)
        self.assertIn("$Extend",names)
        sub=self.run_op("list",{"inode":11})["results"][0]["result"]
        self.assertTrue(sub["entries"])
        self.assertIn("RI_SANDBOX seccomp_no_open_exec_network_writefiles",result["receipt"]["stderr"])
        self.assertGreater(sum(line.startswith("RI_READ ") for line in result["receipt"]["stderr"].splitlines()),0)
        after=Path(self.manifest["path"]).stat()
        self.assertEqual((before.st_atime_ns,before.st_mtime_ns,before.st_ctime_ns),(after.st_atime_ns,after.st_mtime_ns,after.st_ctime_ns))
        self.assertTrue(self.store.verify()["valid"])

    def test_extension_search_has_false_positive_controls_and_no_attribution(self):
        result=self.run_op("search",{"extensions":[".LOCKED"]})["results"][0]["result"]
        self.assertEqual({e["name"] for e in result["entries"]},{"invoice.docx.locked","deleted.locked"})
        self.assertEqual(result["attribution"],"not_established")
        benign=self.run_op("search",{"extensions":[".docx"]})["results"][0]["result"]
        self.assertEqual([e["name"] for e in benign["entries"]],["ordinary.docx"])

    def test_mft_attributes_and_unallocated_mft_scan(self):
        metadata=self.mft("README_RECOVER.txt")
        self.assertTrue(metadata["allocated"])
        self.assertEqual(metadata["streams"][0]["size_bytes"],len(builder.FILES["README_RECOVER.txt"]))
        deleted=self.run_op("deleted")["results"][0]["result"]
        item=next(e for e in deleted["entries"] if e["inode"]==self.manifest["entries"]["deleted.locked"]["inode"])
        self.assertTrue(item["metadata_unallocated"])
        self.assertTrue(item["deleted_candidate"])
        self.assertFalse(item["path_reconstructed"])
        self.assertFalse(self.mft("deleted.locked")["allocated"])

    def test_selective_extraction_hash_provenance_and_no_duplicate_bytes(self):
        params=self.extraction_params("README_RECOVER.txt")
        first=self.run_op("extract",params)
        self.assertEqual(first["status"],"completed")
        result=first["results"][0]["result"]
        data=builder.FILES["README_RECOVER.txt"]
        self.assertEqual(result["sha256"],hashlib.sha256(data).hexdigest())
        self.assertEqual(result["output_verification"]["sha256"],result["sha256"])
        copy=self.store.get("evidence",result["evidence_id"])
        self.assertEqual(copy["source_evidence_id"],self.image["id"])
        self.assertEqual(copy["acquisition_type"],"selective_triage_not_full_forensic_image")
        self.assertEqual((self.store.workspace/copy["relative_path"]).read_bytes(),data)
        files=set(self.inputs.iterdir())
        second=self.run_op("extract",params)["results"][0]["result"]
        self.assertTrue(second["reused"])
        self.assertEqual(second["evidence_id"],copy["id"])
        self.assertEqual(set(self.inputs.iterdir()),files)
        self.assertNotIn("data_base64",json.dumps(self.store.export_case(self.case,include_sensitive=True)))
        self.assertTrue(self.store.verify()["valid"])

    def test_changed_content_under_same_mft_binding_is_not_a_new_silent_version(self):
        params=self.extraction_params("README_RECOVER.txt")
        operation=self.run_op("extract",params)
        original=operation["request"]
        changed=b"?"*params["expected_size"]
        response={"result":{"data_base64":base64.b64encode(changed).decode(),"sha256":hashlib.sha256(changed).hexdigest(),"size_bytes":len(changed)}}
        before=set(self.inputs.iterdir())
        with self.assertRaises(RIError):
            _extract_output(self.store,self.case,self.image,original,response,"Synthetic Operator","f"*32)
        self.assertEqual(set(self.inputs.iterdir()),before)

    def test_deleted_recovery_requires_explicit_permission_and_is_not_verified_original_content(self):
        params=self.extraction_params("deleted.locked")
        denied=self.run_op("extract",params)
        self.assertEqual(denied["status"],"failed")
        result=self.run_op("extract",{**params,"allow_deleted":True})["results"][0]["result"]
        self.assertEqual(result["sha256"],self.manifest["files"]["deleted.locked"]["sha256"])
        self.assertFalse(result["deleted_recovery_verified"])

    def test_nonresident_stream_extraction_matches_all_known_bytes(self):
        params=self.extraction_params("oversize.bin")
        operation=self.run_op("extract",params)
        self.assertEqual(operation["status"],"completed")
        result=operation["results"][0]["result"]
        evidence=self.store.get("evidence",result["evidence_id"])
        self.assertEqual(result["size_bytes"],131072)
        self.assertEqual(result["sha256"],self.manifest["files"]["oversize.bin"]["sha256"])
        self.assertEqual((self.store.workspace/evidence["relative_path"]).read_bytes(),builder.FILES["oversize.bin"])
        self.assertEqual(result["output_verification"]["sha256"],result["sha256"])

    def test_size_sequence_stream_and_read_budget_block_without_partial_copy(self):
        params=self.extraction_params("README_RECOVER.txt")
        before=set(self.inputs.iterdir())
        for change in ({"expected_sequence":params["expected_sequence"]+1},{"expected_size":params["expected_size"]+1},{"attribute_id":60000},{"read_budget":4096}):
            with self.subTest(change=change):
                result=self.run_op("extract",{**params,**change})
                self.assertEqual(result["status"],"failed")
                self.assertIsNone(result["results"][0]["result"])
                self.assertEqual(set(self.inputs.iterdir()),before)
        with self.assertRaises(ValueError): self.run_op("extract",{**params,"max_bytes":1})
        large=self.extraction_params("oversize.bin",max_bytes=1024)
        with self.assertRaises(ValueError): self.run_op("extract",large)

    def test_bounds_are_reported_as_partial_not_complete_volume_results(self):
        result=self.run_op("list",{"max_entries":1})
        self.assertEqual(result["status"],"partial")
        self.assertTrue(result["results"][0]["result"]["summary"]["partial"])
        result=self.run_op("deleted",{"max_entries":1})
        self.assertEqual(result["status"],"partial")
        self.assertEqual(result["results"][0]["result"]["summary"]["scanned_end_inode"],5)

    def test_no_scope_no_authorization_no_read_and_injection_rejected(self):
        for change in ({"authorized":False},{"provided_scope":"ntfs.extract"}):
            with patch("ransomware_investigator.ntfs_triage._image_check",side_effect=AssertionError("No read")):
                with self.assertRaises(RIError): self.run_op("list",**change)
        for params in ({"command":"icat"},{"inode":"5;id"},{"max_entries":True},{"max_depth":9},{"extensions":[".locked;id"]}):
            with self.subTest(params=params),patch("ransomware_investigator.ntfs.core.run_worker",side_effect=AssertionError("No worker")):
                with self.assertRaises(ValueError): self.run_op("search",params)

    def test_modified_or_writable_image_is_never_used_by_parser(self):
        path=Path(self.manifest["path"])
        path.chmod(0o600)
        with patch("ransomware_investigator.ntfs.core.run_worker",side_effect=AssertionError("No worker")):
            with self.assertRaises(RIError): self.run_op("list")
        with path.open("r+b") as stream: stream.seek(0); stream.write(b"BAD")
        path.chmod(0o400)
        with patch("ransomware_investigator.ntfs.core.run_worker",side_effect=AssertionError("No worker")):
            with self.assertRaises(RIError): self.run_op("list")
        self.assertEqual(self.store.list("operations",self.case)[-1]["status"],"failed")

    def test_no_output_space_blocks_before_source_validation_or_parser(self):
        params=self.extraction_params("README_RECOVER.txt")
        with patch("os.statvfs",return_value=SimpleNamespace(f_bavail=0,f_frsize=4096)),patch("ransomware_investigator.ntfs_triage._image_check",side_effect=AssertionError("No source read")):
            with self.assertRaises(RIError): self.run_op("extract",params)
        self.assertEqual(self.store.list("operations",self.case)[-1]["status"],"failed")

    def test_invalid_ntfs_image_and_invalid_volume_extent_fail_closed(self):
        path=self.inputs/"not-ntfs.img"; data=b"\0"*65536; path.write_bytes(data); path.chmod(0o400)
        image=register_image(self.store,self.case,source_id=self.original["id"],path=str(path),expected_sha256=hashlib.sha256(data).hexdigest(),
                              offset_bytes=0,volume_length=None,actor="Synthetic Operator",reason="Synthetic invalid filesystem",authorized=True,scope="ntfs.register-image")
        result=run_image(self.store,self.case,image["id"],"ntfs.list",{},actor="Synthetic Operator",reason="Test",authorized=True,provided_scope="ntfs.list")
        self.assertEqual(result["status"],"failed")
        with self.assertRaises(RIError):
            register_image(self.store,self.case,source_id=self.original["id"],path=str(path),expected_sha256=hashlib.sha256(data).hexdigest(),
                           offset_bytes=1,volume_length=None,actor="Synthetic Operator",reason="Test",authorized=True,scope="ntfs.register-image")

    def test_extracted_copy_can_be_explicitly_authorized_for_artifact_analyzer(self):
        result=self.run_op("extract",self.extraction_params("README_RECOVER.txt"))["results"][0]["result"]
        copy=self.store.get("evidence",result["evidence_id"])
        artifact=register_artifact(self.store,self.case,source_id=self.image["id"],path=str(self.store.workspace/copy["relative_path"]),
                                   source_item="NTFS MFT record 64",extraction_reference=copy["operation_id"],expected_sha256=copy["content_sha256"],
                                   actor="Synthetic Operator",reason="Explicit post-extraction artifact analysis",authorized=True)
        analysis=analyze_artifact(self.store,self.case,artifact["id"],"Synthetic Operator")
        self.assertTrue(analysis["results"][0]["ransom_note_assessment"]["candidate"])

    def test_cli_local_output_redaction_and_same_case_enforcement(self):
        prefix=["--workspace",str(self.store.workspace),"--operator","Synthetic Operator"]
        args=["triage","search","--case",self.case,"--source",self.image["id"],"--extension",".locked","--scope","ntfs.search","--authorize-read","--reason","Synthetic"]
        output=io.StringIO()
        with contextlib.redirect_stdout(output): self.assertEqual(main(prefix+args),0)
        self.assertNotIn("invoice.docx",output.getvalue())
        record=json.loads(output.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as sensitive:
            self.assertEqual(main(prefix+["triage","show","--case",self.case,"--operation-id",record["id"],"--include-sensitive"]),0)
        self.assertIn("invoice.docx.locked",sensitive.getvalue())
        other=self.store.create_case("Other","Bob","Bob")["id"]
        with self.assertRaises(RIError):
            run_image(self.store,other,self.image["id"],"ntfs.list",{},actor="Bob",reason="Test",authorized=True,provided_scope="ntfs.list")
