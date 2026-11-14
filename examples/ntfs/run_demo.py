#!/usr/bin/env python3
"""Real libtsk end-to-end demo on a NEW synthetic NTFS image, never /dev."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"src"))
from ransomware_investigator.cli import main
from ransomware_investigator.safety import ensure_user,project_path

def demo(workspace):
    ensure_user(); workspace=project_path(workspace)
    prefix=["--workspace",str(workspace),"--operator","Synthetic NTFS operator"]
    def call(*args,expected=0):
        out,err=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err): status=main(prefix+list(args))
        if status!=expected: raise RuntimeError(f"Synthetic CLI step {args[:2]} failed ({status}): {err.getvalue()}")
        return json.loads(out.getvalue() or err.getvalue())
    case=call("case","create","--title","NTFS TRIAGE SYNTHETIC","--responsible","Synthetic NTFS operator")["id"]
    original=call("evidence","register-source","--case",case,"--kind","synthetic","--reference","SYNTHETIC-NTFS-JOB-001",
                  "--description","Generated regular test volume; not a client device")["id"]
    directory=Path(call("artifact","prepare-inputs","--case",case)["input_directory"])
    spec=importlib.util.spec_from_file_location("ntfs_demo_builder",ROOT/"examples/ntfs/make_fixture.py")
    builder=importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    manifest=builder.create_fixture(directory)
    source=call("triage","register-image","--case",case,"--source-evidence",original,"--file",manifest["path"],
                "--expected-sha256",manifest["sha256"],"--scope","ntfs.register-image","--authorize-read","--reason","Register synthetic image")["id"]
    def read(action,*args,expected=0):
        return call("triage",action,"--case",case,"--source",source,"--scope","ntfs."+action,"--authorize-read",
                    "--reason","Explicit synthetic "+action,*args,expected=expected)
    root=read("list")
    subdir=read("list","--inode","11")
    search=read("search","--extension",".locked")
    deleted=read("deleted")
    limited=read("list","--max-entries","1",expected=2)
    extracted={}
    for name in ("README_RECOVER.txt","deleted.locked"):
        metadata=read("mft","--inode",str(manifest["entries"][name]["inode"]))["result_summary"]
        stream=metadata["streams"][0]
        args=["--inode",str(metadata["inode"]),"--attribute-id",str(stream["id"]),"--expected-sequence",str(metadata["sequence"]),
              "--expected-size",str(stream["size_bytes"]),"--max-bytes","1048576"]
        if name=="deleted.locked": args.append("--allow-deleted")
        result=read("extract",*args)["result_summary"]
        if result["sha256"]!=manifest["files"][name]["sha256"]: raise RuntimeError("Synthetic known-file hash mismatch")
        extracted[name]=result
    # Repeated authorized read reuses a verified copy; no extra duplicate content.
    reused=read("extract",*args)["result_summary"]
    audit=call("audit","verify")
    call("case","export","--case",case)
    return {"mode":"synthetic_ntfs_real_libtsk","workspace":str(workspace),"case_id":case,"ntfs_source_id":source,
            "image_sha256":manifest["sha256"],"root":root["result_summary"],"subdirectory":subdir["result_summary"],
            "extension_search":search["result_summary"],"deleted_mft_records":deleted["result_summary"],
            "bounded_listing_status":limited["status"],"extracted":extracted,"repeat_reused":reused["reused"],"audit":audit,
            "physical_devices_accessed":False,"broker_started":False,"samples_executed":False,
            "acquisition_type":"selective_triage_only","note":"Synthetic integration, not physical preservation certification."}

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace",default=str(ROOT/".ri-cases"/("ntfs-demo-"+uuid.uuid4().hex)))
    args=parser.parse_args()
    print(json.dumps(demo(Path(args.workspace)),indent=2,ensure_ascii=True))
