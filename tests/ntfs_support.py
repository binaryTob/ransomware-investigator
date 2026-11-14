import importlib.util
import subprocess
import sys
from pathlib import Path

from tests.common import ROOT, ProjectTest
from ransomware_investigator.artifacts import register_source
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.ntfs_triage import register_image

def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

builder=load_module("ntfs_fixture_builder",ROOT/"examples/ntfs/make_fixture.py")

def build_worker():
    subprocess.run([sys.executable,str(ROOT/"tools/build_ntfs_worker.py")],cwd=ROOT,check=True,capture_output=True,timeout=60)

PIN={"target_by_id":"/dev/disk/by-id/wwn-SYNTHETIC-part1","disk_by_id":"/dev/disk/by-id/wwn-SYNTHETIC",
     "wwid":"naa.SYNTHETIC-001","serial":"SYNTHETIC-001","model":"SYNTHETIC NTFS DEVICE",
     "disk_size_bytes":32*1024*1024,"partition_size_bytes":16*1024*1024,"sector_size":512,
     "partition_start_sectors":2048,"partition_number":1,"partition_uuid":"SYNTHETIC-PARTITION-001"}

def state():
    return {**PIN,"disk_read_only":True,"partition_read_only":True,"all_children_read_only":True,
            "mounted":False,"holders":False,"swap_active":False,"protected":False,"identity_unique":True,
            "rdev":2049,"disk_rdev":2048,"physical_write_blocker_verified":False}

class NTFSTest(ProjectTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        build_worker()

    def setUp(self):
        super().setUp()
        self.store=CaseStore(self.work/"case-data"); self.addCleanup(self.store.db.close)
        self.case=self.store.create_case("NTFS synthetic", "Synthetic Operator","Synthetic Operator")["id"]
        self.original=register_source(self.store,self.case,reference="SYNTHETIC NTFS",source_kind="synthetic",description="Never a real device",source_sha256=None,actor="Synthetic Operator")
        self.inputs=self.store.workspace/"extracted"; self.inputs.mkdir(mode=0o700)
        self.manifest=builder.create_fixture(self.inputs)
        self.image=register_image(self.store,self.case,source_id=self.original["id"],path=self.manifest["path"],
                                  expected_sha256=self.manifest["sha256"],offset_bytes=0,volume_length=None,actor="Synthetic Operator",reason="Synthetic image only",
                                  authorized=True,scope="ntfs.register-image")
