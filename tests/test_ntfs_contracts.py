import ast
import copy
import os
from pathlib import Path
from unittest.mock import patch

from tests.common import ROOT,ProjectTest
from tests.test_ntfs_broker import request
from tests.ntfs_support import build_worker
from ransomware_investigator.ntfs import core


class NTFSContractTests(ProjectTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass(); build_worker()

    def test_request_schema_rejects_extra_fields_scope_uid_and_missing_values(self):
        good=request()
        self.assertEqual(core.validate_request(good),good)
        for key,value in (("scope","sudo"),("uid",0),("uid",True),("schema_version",True),("reason",""),("case_id","../x")):
            with self.subTest(key=key),self.assertRaises(ValueError): core.validate_request({**good,key:value})
        with self.assertRaises(ValueError): core.validate_request({**good,"command":"fls"})
        with self.assertRaises(ValueError): core.validate_request({k:v for k,v in good.items() if k!="source"})

    def test_per_operation_limits_and_canonical_parameter_rules(self):
        for scope,params in (("ntfs.extract",{"inode":0}), ("ntfs.extract",{"inode":64,"expected_sequence":0}),
                             ("ntfs.search",{"extensions":[]}), ("ntfs.list",{"extensions":[".locked"]}),
                             ("ntfs.mft",{"max_depth":1}), ("ntfs.list",{"read_budget":2**40}),
                             ("ntfs.list",{"timeout_ms":0}), ("ntfs.list",{"allow_deleted":"yes"})):
            with self.subTest(scope=scope,params=params),self.assertRaises(ValueError): core.parameters(scope,params)
        bad=request(); bad["parameters"]["extensions"]=[".LOCKED"]
        with self.assertRaises(ValueError): core.validate_request(bad)

    def test_worker_never_receives_a_writable_fd_or_unprivileged_physical_fd(self):
        path=self.work/"input"; path.write_bytes(b"synthetic")
        worker=ROOT/".build/ntfs_worker"
        fd=os.open(path,os.O_RDWR)
        try:
            req=request(); req["source"]={"kind":"image"}
            with patch("subprocess.Popen",side_effect=AssertionError("No worker")),self.assertRaises(ValueError):
                core.run_worker(worker,fd,req,base=0,length=9)
        finally: os.close(fd)
        fd=os.open(path,os.O_RDONLY)
        try:
            with patch("subprocess.Popen",side_effect=AssertionError("No physical shortcut")),self.assertRaises(ValueError):
                core.run_worker(worker,fd,request(),base=0,length=9)
            req=request(); req["source"]={"kind":"image"}
            with patch("subprocess.Popen",side_effect=AssertionError("Expired")),self.assertRaises(ValueError):
                core.run_worker(worker,fd,req,base=0,length=9,not_after=1)
        finally: os.close(fd)

    def test_no_external_network_and_process_boundaries_are_recursive(self):
        root=ROOT/"src/ransomware_investigator"
        for path in root.rglob("*.py"):
            relative=path.relative_to(root).as_posix(); tree=ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node,(ast.Import,ast.ImportFrom)):
                    names=[node.module or ""] if isinstance(node,ast.ImportFrom) else [n.name for n in node.names]
                    for name in names:
                        self.assertNotIn(name.split(".")[0],{"requests","urllib","http","ftplib"},relative)
                        if name=="socket": self.assertEqual(relative,"ntfs/client.py")
                if isinstance(node,ast.Attribute):
                    self.assertNotIn(node.attr,{"AF_INET","AF_INET6","create_connection","system","execv","execve","popen"},relative)
                    if isinstance(node.value,ast.Name) and node.value.id=="subprocess":
                        self.assertIn(relative,{"executor.py","ntfs/core.py","ntfs/physical.py"})
        for path in (ROOT/"broker/ntfs_broker.py",root/"ntfs/client.py"):
            self.assertIn("socket.AF_UNIX",path.read_text())
            self.assertNotIn("socket.AF_INET",path.read_text())

    def test_native_worker_has_no_source_paths_and_allows_only_selected_data(self):
        source=(ROOT/"native/ntfs_worker.c").read_text()
        self.assertIn("tsk_img_open_external",source)
        self.assertNotIn("tsk_img_open_utf8",source)
        self.assertNotIn("tsk_img_open_sing",source)
        self.assertIn("tsk_fs_file_attr_get_type(file,TSK_FS_ATTR_TYPE_NTFS_DATA,attr_id,1)",source)
        self.assertIn("a->id != attr_id",source)
        self.assertIn("file->meta->seq != sequence",source)
        self.assertIn("SECCOMP_MODE_FILTER",source)
        for denied in ("ALLOW(open)","ALLOW(openat)","ALLOW(execve)","ALLOW(socket)","ALLOW(ioctl)"):
            self.assertNotIn(denied,source)

    def test_regular_image_registration_still_rejects_root_cli(self):
        from ransomware_investigator.cli import main
        import contextlib,io
        with patch("os.geteuid",return_value=0),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["triage","list","--case","a"*32,"--source","b"*32,"--scope","ntfs.list","--authorize-read","--reason","test"]),2)
