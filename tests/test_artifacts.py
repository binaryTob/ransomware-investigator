import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
from unittest.mock import patch

from tests.common import ROOT, ProjectTest
from tests.test_artifact_analysis import NOTE
from ransomware_investigator.artifacts import (analyze_artifact, compare_artifacts, prepare_inputs,
                                              register_artifact, register_source, verify_artifact)
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.cli import main
from ransomware_investigator.copy_io import SAMPLE_BYTES, read_copy
from ransomware_investigator.safety import Policy, RIError


class ArtifactTests(ProjectTest):
    def setUp(self):
        super().setUp()
        self.store = CaseStore(self.work / "cases")
        self.addCleanup(self.store.db.close)
        self.case = self.store.create_case("Caso sintético", "Synthetic Operator", "Synthetic Operator")["id"]
        prepared = prepare_inputs(self.store, self.case, "Synthetic Operator")
        self.inputs = Path(prepared["input_directory"])
        self.source = register_source(self.store, self.case, reference="SYNTHETIC-EXTRACTION-001",
                                      source_kind="synthetic", description="No es un disco real",
                                      source_sha256=None, actor="Synthetic Operator")

    def write(self, name="note.txt", data=NOTE):
        path = self.inputs / name
        path.write_bytes(data)
        return path, hashlib.sha256(data).hexdigest()

    def register(self, path, sha, **kwargs):
        arguments = dict(source_id=self.source["id"], path=str(path), source_item="C:/Users/Public/" + path.name,
                         extraction_reference="synthetic-job-001/version-1", expected_sha256=sha,
                         actor="Synthetic Operator", reason="Autorizar copia sintética para verificación y análisis estático", authorized=True)
        arguments.update(kwargs)
        return register_artifact(self.store, self.case, **arguments)

    def test_register_verify_analyze_without_processes_or_content_duplication(self):
        path, sha = self.write()
        with patch("subprocess.Popen", side_effect=AssertionError("No ejecutar muestras ni herramientas")), patch("ransomware_investigator.executor.RestrictedExecutor.execute", side_effect=AssertionError("No discos")):
            artifact = self.register(path, sha)
            verified = verify_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")
            analysis = analyze_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")
        self.assertEqual(artifact["content_sha256"], sha)
        self.assertEqual(artifact["source_evidence_id"], self.source["id"])
        self.assertEqual(artifact["size_bytes"], len(NOTE))
        self.assertEqual(verified["results"][0]["hash_scope"], "entire_file")
        self.assertEqual(analysis["scope"], "artifact_analysis")
        self.assertTrue(analysis["results"][0]["ransom_note_assessment"]["candidate"])
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM blobs").fetchone()[0], 0)
        self.assertTrue(self.store.verify()["valid"])
        self.assertEqual(sorted(p.name for p in self.inputs.iterdir()), ["note.txt"])

    def test_dedup_verifies_before_reusing_and_rejects_alternate_path(self):
        path, sha = self.write()
        first = self.register(path, sha)
        second = self.register(path, sha)
        self.assertEqual(first["id"], second["id"])
        copies = [d for d in self.store.list("evidence", self.case) if d["status"] == "extracted_copy_registered"]
        self.assertEqual(len(copies), 1)
        self.assertTrue(self.store.list("operations", self.case)[-1]["results"][0]["reused"])
        other_path, _ = self.write("duplicate.txt")
        with self.assertRaises(RIError):
            self.register(other_path, sha, source_item=first["source_item"])
        self.assertEqual(len([d for d in self.store.list("evidence", self.case) if d["status"] == "extracted_copy_registered"]), 1)

    def test_no_authorization_no_file_read(self):
        path, sha = self.write()
        with patch("ransomware_investigator.artifacts.read_copy", side_effect=AssertionError("No leer")):
            with self.assertRaises(RIError):
                self.register(path, sha, authorized=False)
        self.assertEqual(self.store.list("operations", self.case)[-1]["status"], "denied")
        self.assertEqual(self.store.list("authorizations", self.case), [])

    def test_wrong_and_missing_hash_fail_and_are_not_accepted_as_integrity(self):
        path, _ = self.write()
        for value in ("x", None, "G" * 64):
            with self.subTest(value=value), self.assertRaises(RIError):
                self.register(path, value)
        with self.assertRaises(RIError):
            self.register(path, "a" * 64)
        self.assertEqual(self.store.list("operations", self.case)[-1]["status"], "failed")
        self.assertEqual(len(self.store.list("evidence", self.case)), 1)
        self.assertTrue(self.store.verify()["valid"])

    def test_registered_file_content_mode_and_timestamps_are_unchanged(self):
        path, sha = self.write()
        past = 1_600_000_000_000_000_000
        os.utime(path, ns=(past, past))
        path.chmod(0o400)
        before = path.stat()
        artifact = self.register(path, sha)
        analyze_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")
        verify_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")
        after = path.stat()
        self.assertEqual((before.st_size, before.st_mode, before.st_atime_ns, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_size, after.st_mode, after.st_atime_ns, after.st_mtime_ns, after.st_ctime_ns))

    def test_modified_copy_analysis_fails_and_failed_result_is_audited(self):
        path, sha = self.write()
        artifact = self.register(path, sha)
        path.write_bytes(b"tampered")  # Synthetic fixture only; the application never writes evidence.
        with self.assertRaises(RIError):
            analyze_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")
        operation = self.store.list("operations", self.case)[-1]
        self.assertEqual(operation["status"], "failed")
        self.assertNotIn("observations", operation["results"][0])
        self.assertTrue(self.store.verify()["valid"])  # DB integrity is not file integrity.

    def test_symlink_hardlink_fifo_outside_and_device_paths_are_rejected(self):
        path, sha = self.write()
        linked = self.inputs / "symlink.txt"
        linked.symlink_to(path)
        outside = self.work / "outside.txt"
        outside.write_bytes(NOTE)
        fifo = self.inputs / "fifo"
        os.mkfifo(fifo)
        for candidate in (linked, outside, fifo, Path("/dev/sda"), Path("/proc/self/mem"), self.inputs / "../escape"):
            with self.subTest(candidate=candidate), self.assertRaises(RIError):
                self.register(candidate, sha)
        hard = self.inputs / "hard.txt"
        os.link(path, hard)
        with self.assertRaises(RIError):
            self.register(hard, sha)

    def test_authorization_is_bound_to_uid_case_path_hash_and_no_disclosure(self):
        path, sha = self.write()
        artifact = self.register(path, sha)
        grant = self.store.get("authorizations", artifact["authorization_id"])
        for change in ({"uid": -1}, {"scope": "metadata_discovery"}, {"relative_path": "extracted/other.txt"},
                       {"case_id": "a" * 32}, {"expected_sha256": "a" * 64}, {"remote_disclosure_authorized": True}):
            with self.subTest(change=change), patch("os.open", side_effect=AssertionError("No abrir sin grant válido")):
                with self.assertRaises(RIError):
                    read_copy(self.store.workspace, path, {**grant, **change}, self.case, sha)

    def test_noatime_failure_never_retries_with_weaker_flags(self):
        path, sha = self.write()
        with patch("ransomware_investigator.copy_io.os.open", side_effect=PermissionError(1, "synthetic")) as opened:
            with self.assertRaises(RIError):
                self.register(path, sha)
        self.assertEqual(opened.call_count, 1)
        self.assertTrue(opened.call_args.args[1] & os.O_NOATIME)
        self.assertEqual(self.store.list("operations", self.case)[-1]["status"], "failed")

    def test_full_hash_but_prefix_only_analysis_is_explicit(self):
        data = b"a" * (SAMPLE_BYTES + 10) + b"\nYour files have been encrypted. Pay bitcoin to help@late.invalid."
        path, sha = self.write("large.txt", data)
        artifact = self.register(path, sha)
        result = analyze_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")["results"][0]
        self.assertEqual(result["integrity_check"]["hash_scope"], "entire_file")
        self.assertEqual(result["sha256"], sha)
        self.assertTrue(result["coverage"]["sample_truncated"])
        self.assertEqual(result["coverage"]["sample_bytes"], SAMPLE_BYTES)
        self.assertFalse(result["ransom_note_assessment"]["candidate"])

    def test_size_limit_is_checked_before_reading_file_content(self):
        path, sha = self.write()
        with patch("ransomware_investigator.copy_io.MAX_ARTIFACT_BYTES", 16), patch("os.read", side_effect=AssertionError("No contenido sobre límite")):
            with self.assertRaises(RIError):
                self.register(path, sha)

    def test_change_during_read_and_replacement_with_same_bytes_are_rejected(self):
        path, sha = self.write()
        original_read = os.read
        modified = False
        def racing_read(fd, size):
            nonlocal modified
            content = original_read(fd, size)
            if not modified:
                modified = True
                path.write_bytes(NOTE + b"mutation")
            return content
        with patch("ransomware_investigator.copy_io.os.read", racing_read), self.assertRaises(RIError):
            self.register(path, sha)
        path, sha = self.write("stable.txt")
        artifact = self.register(path, sha)
        alternate, _ = self.write("alternate.txt")
        alternate.replace(path)
        with self.assertRaises(RIError):
            verify_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")

    def test_source_reference_never_opened_and_existing_source_not_forged_as_verified(self):
        with patch("os.open", side_effect=AssertionError("No abrir referencia a fuente")):
            source = register_source(self.store, self.case, reference="/dev/sda", source_kind="physical-device",
                                     description="Declaración del operador, sin consulta", source_sha256="a" * 64, actor="Synthetic Operator")
        self.assertEqual(source["source_integrity"], "not_verified_by_application")
        self.assertIsNone(source["content_sha256"])
        self.assertFalse(source["preserved_image"])

    def test_cross_case_source_read_and_comparison_are_rejected(self):
        path, sha = self.write()
        artifact = self.register(path, sha)
        analysis = analyze_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")
        other = self.store.create_case("Otro", "Bob", "Bob")["id"]
        with patch("ransomware_investigator.artifacts.read_copy", side_effect=AssertionError("No lectura cruzada")):
            with self.assertRaises(RIError):
                verify_artifact(self.store, other, artifact["id"], "Bob")
            with self.assertRaises(RIError):
                compare_artifacts(self.store, other, analysis["id"], analysis["id"], "Bob")
            with self.assertRaises(RIError):
                register_artifact(self.store, other, source_id=self.source["id"], path=str(path), source_item="x",
                                  extraction_reference="v1", expected_sha256=sha, actor="Bob", reason="test", authorized=True)

    def test_comparisons_of_saved_results_do_not_reread_files(self):
        path, sha = self.write()
        left = analyze_artifact(self.store, self.case, self.register(path, sha)["id"], "Synthetic Operator")
        path2, sha2 = self.write("second.txt", NOTE.replace(b"SYNTHETIC-001", b"SYNTHETIC-002"))
        right = analyze_artifact(self.store, self.case, self.register(path2, sha2)["id"], "Synthetic Operator")
        with patch("ransomware_investigator.artifacts.read_copy", side_effect=AssertionError("Solo snapshots")):
            comparison = compare_artifacts(self.store, self.case, left["id"], right["id"], "Synthetic Operator")
        self.assertFalse(comparison["results"][0]["files_reread"])
        self.assertTrue(any(f["kind"] == "email" for f in comparison["results"][0]["common"]))
        self.assertTrue(self.store.verify()["valid"])

    def test_registered_python_file_is_never_imported_or_executed(self):
        marker = self.work / "EXECUTION_WOULD_CREATE_THIS"
        script = f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n".encode()
        path, sha = self.write("suspicious.py", script)
        artifact = self.register(path, sha)
        with patch("subprocess.Popen", side_effect=AssertionError("No ejecutar")):
            analyze_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")
        self.assertFalse(marker.exists())

    def call(self, *args, expected=0):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = main(["--workspace", str(self.store.workspace), "--operator", "Synthetic Operator", *args])
        self.assertEqual(status, expected, error.getvalue())
        return json.loads(output.getvalue() or error.getvalue())

    def test_cli_default_redaction_explicit_local_output_and_export(self):
        path, sha = self.write()
        artifact = self.call("artifact", "register", "--case", self.case, "--source-evidence", self.source["id"],
                             "--file", str(path), "--source-item", "C:/README.txt", "--extraction-reference", "v1",
                             "--expected-sha256", sha, "--authorize-copy", "--reason", "test")
        analysis = self.call("artifact", "analyze", "--case", self.case, "--artifact", artifact["id"])
        self.assertNotIn("help@locker.invalid", json.dumps(analysis))
        sensitive = self.call("artifact", "show", "--case", self.case, "--operation", analysis["id"], "--include-sensitive")
        self.assertIn("help@locker.invalid", json.dumps(sensitive))
        default_export = self.call("case", "export", "--case", self.case)
        self.assertNotIn("help@locker.invalid", json.dumps(default_export))
        sensitive_export = self.call("case", "export", "--case", self.case, "--include-sensitive")
        self.assertIn("help@locker.invalid", json.dumps(sensitive_export))
        self.assertEqual(self.call("artifact", "list", "--case", self.case)[0]["id"], artifact["id"])
        self.assertTrue(self.call("audit", "verify")["valid"])

    def test_legacy_workspace_version_unchanged_and_root_blocked(self):
        self.assertEqual(self.store.db.execute("PRAGMA user_version").fetchone()[0], 1)
        path, sha = self.write()
        artifact = self.register(path, sha)
        with patch("os.geteuid", return_value=0), self.assertRaises(RIError):
            verify_artifact(self.store, self.case, artifact["id"], "Synthetic Operator")
        self.assertEqual(self.store.db.execute("PRAGMA user_version").fetchone()[0], 1)
