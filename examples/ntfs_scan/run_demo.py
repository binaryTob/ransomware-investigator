#!/usr/bin/env python3
"""Three NEW synthetic NTFS sources, never the official dossier or /dev."""
import importlib.util
import json
from pathlib import Path
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"src"))
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.artifacts import register_source
from ransomware_investigator import ntfs_scan as scan, ntfs_triage as triage
from ransomware_investigator.exchange import verify_exchange, _read
from ransomware_investigator.safety import ensure_user,project_path


def demo(directory):
    ensure_user(); directory=project_path(directory)
    directory.mkdir(mode=0o700,parents=True,exist_ok=False)
    root=directory/"existing-synthetic-dossier"; root.mkdir(mode=0o700)
    (root/"SYNTHETIC-NOT-REAL-CASE.txt").write_text("Synthetic test fixture. Not Alquimix and not a physical inventory.\n")
    spec=importlib.util.spec_from_file_location("scan_demo_fixture",ROOT/"examples/ntfs/make_fixture.py")
    builder=importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    scans=[]; start=time.monotonic()
    with CaseStore(case_root=root) as store:
        case_id=store.attach_case("SYNTHETIC THREE SOURCES","Synthetic operator","Synthetic operator")["id"]
        inputs=store.workspace/"extracted"; inputs.mkdir(mode=0o700)
        sources=[]
        for label in ("ONE","TWO","THREE"):
            source=register_source(store,case_id,reference="SYNTHETIC "+label,source_kind="synthetic",description="Generated image, never hardware",source_sha256=None,actor="Synthetic operator")
            extras={"backup-"+str(i)+".bak.sealed":b"SYN\0"+b"SYNTHETIC-ONLY-NOT-CLIENT-DATA"*20 for i in range(8)}
            extras.update({"Contact.txt":b"SYNTHETIC ransom-note-shaped fixture; contact@triage.invalid\n","Security.evtx":b"SYNTHETIC NOT AN EVENT LOG","historical.tib":b"SYNTHETIC NOT AN ACRONIS BACKUP"})
            fixture=builder.create_fixture(inputs,extra_files=extras,alternate_streams={("Contact.txt","synthetic_ads"):b"SYNTHETIC ADS"})
            image=triage.register_image(store,case_id,source_id=source["id"],path=fixture["path"],expected_sha256=fixture["sha256"],offset_bytes=0,volume_length=None,
                    actor="Synthetic operator",reason="Explicit synthetic image verification",authorized=True,scope="ntfs.register-image")
            job=scan.start_scan(store,case_id,image["id"],actor="Synthetic operator",page_size=32)
            checkpoint=scan.run_image_batch(store,case_id,job["id"],actor="Synthetic operator",reason="First bounded synthetic metadata batch",authorized=True,scope="ntfs.scan-metadata",max_pages=2)
            sources.append((image,fixture,job["id"],checkpoint["checkpoint"]["page_index"]))
    # Reopen the same case and resume persisted cursors, without rescanning completed pages.
    with CaseStore(case_root=root) as store:
        for image,fixture,identifier,saved_page in sources:
            report=scan.run_image_batch(store,case_id,identifier,actor="Synthetic operator",reason="Explicit synthetic resume",authorized=True,scope="ntfs.scan-metadata",max_pages=256)
            if report["coverage"]["mft_slot_percent"]!=100 or report["failed_operation_count"]:
                raise RuntimeError("Synthetic metadata coverage failed")
            verification=scan.verify_saved_scan(store,case_id,identifier)
            summary=store.get("operations",identifier)["results"][0]["technical_summary"]
            scans.append({"scan_id":identifier,"source_id":image["id"],"resumed_after_page":saved_page,"status":report["status"],
                          "coverage":report["coverage"],"category_counts":report["checkpoint"]["category_counts"],"path_warnings":report["checkpoint"]["path_warnings"],
                          "errors":report["failed_operation_count"],"verification":verification,"technical_summary":summary})
            # Separate, explicitly authorized prefix operation, NOT part of metadata scan.
            metadata=triage.run_image(store,case_id,image["id"],"ntfs.mft",{"inode":fixture["entries"]["backup-0.bak.sealed"]["inode"]},
                    actor="Synthetic operator",reason="Synthetic selected stream metadata",authorized=True,provided_scope="ntfs.mft")["results"][0]["result"]
            stream=next(a for a in metadata["streams"] if a["name"]=="")
            params={"inode":metadata["inode"],"attribute_id":stream["id"],"expected_sequence":metadata["sequence"],"expected_size":stream["size_bytes"],"max_bytes":64}
            prefix=triage.run_image(store,case_id,image["id"],"ntfs.prefix",params,actor="Synthetic operator",reason="Separate synthetic prefix authorization, first 64 bytes only",authorized=True,provided_scope="ntfs.prefix")["results"][0]["result"]
            if prefix["hash_scope"]!="prefix_only" or prefix["header_assessment"]["signature_observations"]!=["synthetic_test_marker"]: raise RuntimeError("Synthetic prefix check failed")
        correlation=scan.correlate_saved(store,case_id,"Synthetic operator")
        correlation_data=json.loads(_read(store.workspace/correlation["report"]["path"]))
        verified=verify_exchange(root); audit=store.verify()
    return {"mode":"synthetic_three_images_real_libtsk","case_root":str(root),"case_id":case_id,"scans":scans,"correlation":correlation,
            "prefix_signature_match_groups":len(correlation_data["saved_prefix_signature_matches"]),"exchange_verification":verified,"audit":audit,
            "manifest":str(root/"ransomware-investigator/exchange/manifest.json"),"duration_seconds":time.monotonic()-start,
            "official_case_touched":False,"physical_devices_accessed":False,"broker_started":False,"wd_physical_validation_passed":False}


if __name__=="__main__":
    print(json.dumps(demo(ROOT/".test-tmp"/("ntfs-scan-demo-"+uuid.uuid4().hex)),indent=2,ensure_ascii=True))
