"""Synthetic reproduction of a TSK metadata rejection, never physical evidence."""
import base64
import json
import os
from pathlib import Path

from tests.common import ROOT, ProjectTest
from tests.ntfs_support import builder, build_worker
from admin.broker_installer import read_regular
from ransomware_investigator.audit import bytes_digest
from ransomware_investigator.ntfs import core


class NTFSInvalidUpdateCountTests(ProjectTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        build_worker()

    def test_invalid_update_count_is_failed_metadata_not_a_timeout_or_inventory(self):
        manifest = builder.create_fixture(self.work / "unregistered-synthetic")
        original = Path(manifest["path"])
        before = original.stat()
        data = read_regular(original, noatime=True)
        self.assertEqual(bytes_digest(data), manifest["sha256"])
        boot = data[:512]
        cluster_size = int.from_bytes(boot[11:13], "little") * boot[13]
        code = int.from_bytes(boot[64:65], "little", signed=True)
        record_size = 2 ** -code if code < 0 else code * cluster_size
        mft_offset = int.from_bytes(boot[48:56], "little") * cluster_size
        inode = manifest["entries"]["ordinary.docx"]["inode"]
        offset = mft_offset + inode * record_size
        # Mutate only the initial bytes of a NEW, unregistered synthetic copy.
        # No generic evidence-patching helper or original-device path exists.
        self.assertEqual(data[offset:offset + 4], b"FILE")
        self.assertIn("ordinary.docx".encode("utf-16le"), data[offset:offset + record_size])
        damaged = bytearray(data)
        damaged[offset + 6:offset + 8] = (0).to_bytes(2, "little")
        target = self.work / "synthetic-invalid-update-count.ntfs"
        with target.open("xb") as stream:
            stream.write(damaged)
        target.chmod(0o400)  # Before registration; never change registered inputs.

        def measure(path, request_id, expected_sha256):
            raw = read_regular(path, noatime=True)
            self.assertEqual(bytes_digest(raw), expected_sha256)
            request = core.validate_request({"schema_version": 1, "request_id": request_id,
                "case_id": "a" * 32, "source_id": "b" * 32, "uid": os.getuid(),
                "scope": "ntfs.records", "parameters": core.parameters("ntfs.records", {
                    "inode": inode, "max_entries": 1, "read_budget": 64 * 1024**2, "timeout_ms": 10000}),
                "source": {"kind": "image", "sha256": expected_sha256,
                    "offset_bytes": 0, "volume_length": len(raw)},
                "reason": "Explicit synthetic unregistered regular-image parser reproduction only."})
            fd = os.open(path, os.O_RDONLY | os.O_NOATIME | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                return core.run_worker(ROOT / ".build/ntfs_worker", fd, request, base=0, length=len(raw))
            finally:
                os.close(fd)

        control = measure(original, "c" * 32, manifest["sha256"])
        self.assertEqual(control["receipt"]["status"], "ok")
        self.assertEqual(control["result"]["entries"][0]["inode"], inode)
        failed = measure(target, "d" * 32, bytes_digest(damaged))
        receipt = failed["receipt"]
        self.assertEqual(receipt["status"], "worker_failed")
        self.assertEqual(receipt["returncode"], 3)
        self.assertIsNone(failed["result"])
        self.assertIn("dinode_lookup: Invalid update count value out of bounds", receipt["stderr"])
        self.assertNotIn("RI_DENIED", receipt["stderr"])
        fragment = [json.loads(line) for line in base64.b64decode(receipt["partial_stdout_base64"]).splitlines()]
        self.assertEqual(len(fragment), 1)
        self.assertTrue(fragment[0]["partial"])
        self.assertEqual(fragment[0]["visited"], 0)
        self.assertEqual(fragment[0]["next_cursor"], inode)
        after = original.stat()
        self.assertEqual((before.st_atime_ns, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_atime_ns, after.st_mtime_ns, after.st_ctime_ns))
