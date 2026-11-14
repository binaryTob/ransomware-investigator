"""Integration uses only existing synthetic dossiers beneath the project."""
import contextlib
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import threading
from unittest.mock import patch

from tests.common import ROOT, ProjectTest
from tests.ntfs_support import builder, build_worker, PIN, state
from ransomware_investigator.artifacts import register_source, prepare_inputs, register_artifact, analyze_artifact
from ransomware_investigator.audit import canonical, bytes_digest
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.cli import main
from ransomware_investigator.exchange import Exchange, read_manifest, verify_exchange, _read
from ransomware_investigator.ntfs_triage import register_image, run_image, register_device, prepare_device, execute_device
from ransomware_investigator.safety import RIError, PublicationPending, CASE_NAMESPACE


def concurrent_operations(root, case_id, label):
    with CaseStore(case_root=root) as store:
        for index in range(3):
            op = store.record("operations", case_id, {"scope": "synthetic_analysis", "status": "started", "label": label, "index": index}, label)
            store.update_operation(op["id"], "completed", [{"synthetic": True, "value": index}], label)


class _ExchangeFixture(ProjectTest):
    def setUp(self):
        super().setUp()
        self.root = self.work / "existing-dossier"
        self.root.mkdir(mode=0o700)
        self.prior = self.root / "preexisting-synthetic-note.txt"
        self.prior.write_bytes(b"PREEXISTING SYNTHETIC CASE MATERIAL\n")

    def open_store(self):
        store = CaseStore(case_root=self.root)
        self.addCleanup(store.db.close)
        case = store.attach_case("SYNTHETIC EXISTING CASE", "Synthetic Operator", "Synthetic Operator")
        return store, case["id"]


class CaseExchangeTests(_ExchangeFixture):
    def test_existing_root_explicit_binding_and_no_parallel_case(self):
        before = self.prior.stat()
        store, case_id = self.open_store()
        self.assertEqual(store.workspace, self.root / CASE_NAMESPACE)
        self.assertEqual(store.attach_case("SYNTHETIC EXISTING CASE", "Synthetic Operator", "Synthetic Operator")["id"], case_id)
        with self.assertRaises(RIError): store.create_case("Another", "Synthetic Operator", "Synthetic Operator")
        with self.assertRaises(RIError): store.attach_case("Another", "Synthetic Operator", "Synthetic Operator")
        self.assertEqual(len(store.list("cases")), 1)
        after = self.prior.stat()
        self.assertEqual((before.st_mtime_ns, before.st_ctime_ns, before.st_atime_ns), (after.st_mtime_ns, after.st_ctime_ns, after.st_atime_ns))
        self.assertEqual(read_manifest(self.root)["cases"][0]["id"], case_id)

    def test_invalid_roots_never_create_or_fallback(self):
        missing = self.work / "not-an-existing-case"
        for value in (str(missing), "relative-case", "/dev", ""):
            with self.subTest(value=value), patch.dict(os.environ, {"RI_CASE_ROOT": value}):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["case", "list"]), 2)
            self.assertFalse(missing.exists())
        alias = self.work / "alias"; alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(RIError): CaseStore(case_root=alias)
        with self.assertRaises(RIError): CaseStore(self.work / "local", case_root=self.root)
        with patch.dict(os.environ, {"RI_CASE_ROOT": str(missing)}), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--workspace", str(self.work / "local"), "case", "list"]), 2)
        self.assertFalse((self.work / "local").exists())

    def test_unknown_namespace_and_symlink_output_are_not_overwritten(self):
        namespace = self.root / CASE_NAMESPACE; namespace.mkdir(mode=0o700)
        previous = namespace / "unknown.txt"; previous.write_bytes(b"keep")
        with self.assertRaises(RIError): CaseStore(case_root=self.root)
        self.assertEqual(previous.read_bytes(), b"keep")
        self.assertFalse((namespace / "cases.sqlite3").exists())

    def test_cli_environment_and_absolute_override_are_cwd_independent(self):
        # No real dossier or shell environment is modified.
        cwd = Path.cwd()
        try:
            os.chdir(self.work)
            with patch.dict(os.environ, {"RI_CASE_ROOT": str(self.root)}), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(["case", "attach", "--reference", "SYNTHETIC", "--responsible", "Synthetic Operator"]), 0)
            case_id = json.loads(output.getvalue())["id"]
            with patch.dict(os.environ, {"RI_CASE_ROOT": str(self.work / "missing")}), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--case-root", str(self.root), "exchange", "verify"]), 0)
        finally:
            os.chdir(cwd)
        self.assertEqual(read_manifest(self.root)["cases"][0]["id"], case_id)

    def test_history_keeps_started_and_terminal_versions_and_no_overwrite(self):
        store, case_id = self.open_store()
        op = store.record("operations", case_id, {"scope": "synthetic", "status": "started"}, "Synthetic Operator")
        old = read_manifest(self.root)
        original = {item["path"]: _read(store.workspace / item["path"]) for item in old["history"]}
        store.update_operation(op["id"], "completed", [{"synthetic": True}], "Synthetic Operator")
        with self.assertRaises(RIError): store.update_operation(op["id"], "failed", [], "Synthetic Operator")
        snapshot = read_manifest(self.root)
        versions = [json.loads(_read(store.workspace / item["path"]))["record"]["status"] for item in snapshot["history"] if item["id"] == op["id"]]
        self.assertEqual(versions, ["started", "completed"])
        for path, data in original.items(): self.assertEqual(_read(store.workspace / path), data)
        self.assertEqual(snapshot["operations"][op["id"]]["status"], "completed")
        self.assertTrue(verify_exchange(self.root)["valid"])

    def test_publication_failure_is_pending_and_recoverable_without_reanalysis(self):
        store, case_id = self.open_store()
        revision = read_manifest(self.root)["revision_seq"]
        with patch.object(Exchange, "publish", side_effect=OSError("synthetic write failure")):
            with self.assertRaises(PublicationPending):
                store.record("operations", case_id, {"scope": "synthetic", "status": "started"}, "Synthetic Operator")
        self.assertEqual(read_manifest(self.root)["revision_seq"], revision)
        with CaseStore(case_root=self.root) as recovered:
            snapshot = read_manifest(self.root)
            self.assertEqual(snapshot["revision_seq"], recovered.verify()["events"])
            self.assertEqual(list(snapshot["operations"].values())[0]["status"], "started")
            self.assertFalse(list(snapshot["operations"].values())[0]["usable_as_completed_result"])
        self.assertTrue(verify_exchange(self.root)["valid"])

    def test_tampered_immutable_record_blocks_sync_instead_of_overwrite(self):
        store, case_id = self.open_store()
        snapshot = read_manifest(self.root)
        path = store.workspace / snapshot["history"][0]["path"]
        path.write_bytes(b"SYNTHETIC TAMPER")
        with self.assertRaises((RIError, ValueError)): verify_exchange(self.root)
        with self.assertRaises(RIError): CaseStore(case_root=self.root)
        self.assertEqual(path.read_bytes(), b"SYNTHETIC TAMPER")

    def test_manifest_relations_cannot_disagree_with_history(self):
        store, case_id = self.open_store()
        pointer_path = store.workspace / "exchange/manifest.json"
        pointer = json.loads(_read(pointer_path))
        snapshot_path = store.workspace / pointer["snapshot"]["path"]
        snapshot = json.loads(_read(snapshot_path)); snapshot["links"] = [{"invented": True}]
        data = canonical(snapshot).encode(); snapshot_path.write_bytes(data)
        pointer["snapshot"]["sha256"] = bytes_digest(data); pointer_path.write_text(canonical(pointer))
        with self.assertRaises(RIError): verify_exchange(self.root)

    def test_interrupted_atomic_pointer_leaves_previous_snapshot_valid(self):
        store, case_id = self.open_store()
        previous = read_manifest(self.root)
        with patch("ransomware_investigator.exchange.os.replace", side_effect=OSError("synthetic interruption before atomic swap")):
            with self.assertRaises(PublicationPending):
                store.record("operations", case_id, {"scope": "synthetic", "status": "completed", "results": []}, "Synthetic Operator")
        self.assertEqual(read_manifest(self.root), previous)
        self.assertTrue(verify_exchange(self.root)["valid"])
        with CaseStore(case_root=self.root):
            self.assertGreater(read_manifest(self.root)["revision_seq"], previous["revision_seq"])
        self.assertTrue(verify_exchange(self.root)["valid"])

    def test_published_reader_does_not_open_db_extracted_files_or_devices(self):
        store, case_id = self.open_store()
        with patch("sqlite3.connect", side_effect=AssertionError("No DB")), patch("ransomware_investigator.copy_io.read_copy", side_effect=AssertionError("No copies")):
            report = verify_exchange(self.root)
        self.assertTrue(report["valid"])
        self.assertFalse(report["extracted_files_rehashed"])
        self.assertFalse(report["physical_sources_opened"])
        with patch.dict(os.environ, {"RI_CASE_ROOT": str(self.root)}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["exchange", "status"]), 0)

    def test_inventory_comparison_and_deduplicated_raw_outputs_are_published(self):
        store, case_id = self.open_store()
        from ransomware_investigator.inventory import save_inventory
        raw = (ROOT / "examples/simulated/windows-usb.json").read_bytes()
        first = save_inventory(store, case_id, json.loads(raw), raw, "Synthetic Operator", mode="simulated")
        second = save_inventory(store, case_id, json.loads(raw), raw, "Synthetic Operator", mode="simulated")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--case-root", str(self.root), "inventory", "compare", "--before", first["id"], "--after", second["id"]]), 0)
        result = json.loads(output.getvalue())
        snapshot = read_manifest(self.root)
        self.assertEqual(snapshot["operations"][result["operation_id"]]["scope"], "inventory_comparison")
        self.assertEqual(snapshot["operations"][result["operation_id"]]["parameters"], {"before": first["id"], "after": second["id"]})
        self.assertEqual(len(snapshot["raw_outputs"]), 1)
        self.assertTrue(verify_exchange(self.root)["valid"])

    def test_two_processes_and_snapshot_reader_have_consistent_history(self):
        store, case_id = self.open_store()
        context = multiprocessing.get_context("spawn")
        processes = [context.Process(target=concurrent_operations, args=(str(self.root), case_id, label)) for label in ("one", "two")]
        errors = []
        stop = threading.Event()
        def reader():
            while not stop.is_set():
                try: verify_exchange(self.root)
                except Exception as exc: errors.append(repr(exc)); break
        thread = threading.Thread(target=reader); thread.start()
        try:
            for process in processes: process.start()
            for process in processes:
                process.join(30)
                self.assertFalse(process.is_alive())
                self.assertEqual(process.exitcode, 0)
        finally:
            stop.set(); thread.join(5)
            for process in processes:
                if process.is_alive(): process.terminate(); process.join(5)
        self.assertFalse(errors, errors)
        snapshot = read_manifest(self.root)
        self.assertEqual(len(snapshot["operations"]), 6)
        self.assertEqual(snapshot["revision_seq"], 13)
        self.assertTrue(all(op["status"] == "completed" for op in snapshot["operations"].values()))
        self.assertTrue(store.verify()["valid"])
        self.assertTrue(verify_exchange(self.root)["valid"])


class NTFSCaseExchangeTests(_ExchangeFixture):
    @classmethod
    def setUpClass(cls):
        super().setUpClass(); build_worker()

    def fixture(self):
        store, case_id = self.open_store()
        source = register_source(store, case_id, reference="SYNTHETIC DEVICE", source_kind="synthetic", description="Never hardware", source_sha256=None, actor="Synthetic Operator")
        directory = Path(prepare_inputs(store, case_id, "Synthetic Operator")["input_directory"])
        manifest = builder.create_fixture(directory)
        image = register_image(store, case_id, source_id=source["id"], path=manifest["path"], expected_sha256=manifest["sha256"],
                               offset_bytes=0, volume_length=None, actor="Synthetic Operator", reason="Synthetic test", authorized=True, scope="ntfs.register-image")
        return store, case_id, source, manifest, image

    def run_op(self, store, case_id, image, name, params=None):
        return run_image(store, case_id, image["id"], "ntfs." + name, params or {}, actor="Synthetic Operator", reason="Explicit synthetic read",
                         authorized=True, provided_scope="ntfs." + name)

    def extraction(self, store, case_id, manifest, image):
        metadata = self.run_op(store, case_id, image, "mft", {"inode": manifest["entries"]["README_RECOVER.txt"]["inode"]})["results"][0]["result"]
        return {"inode": metadata["inode"], "attribute_id": metadata["streams"][0]["id"], "expected_sequence": metadata["sequence"], "expected_size": metadata["streams"][0]["size_bytes"]}

    def test_real_libtsk_json_has_device_partition_files_mft_times_and_hashes(self):
        store, case_id, original, manifest, image = self.fixture()
        search = self.run_op(store, case_id, image, "search", {"extensions": [".locked"]})
        params = self.extraction(store, case_id, manifest, image)
        extracted = self.run_op(store, case_id, image, "extract", params)
        snapshot = read_manifest(self.root)
        operation = snapshot["operations"][search["id"]]
        self.assertEqual(operation["case_id"], case_id)
        self.assertEqual(operation["sources"][0]["device"]["evidence_id"], original["id"])
        self.assertEqual(operation["sources"][0]["partition"]["evidence_id"], image["id"])
        self.assertEqual(len(operation["files_identified"]), 2)
        self.assertTrue(all(row["ntfs_path"].endswith(".locked") for row in operation["files_identified"]))
        subdirectory = self.run_op(store, case_id, image, "list", {"inode": 11})
        subfiles = read_manifest(self.root)["operations"][subdirectory["id"]]["files_identified"]
        self.assertTrue(subfiles)
        self.assertTrue(all(row["ntfs_path"] is None and row["path_base_directory_mft"] == 11 for row in subfiles))
        self.assertTrue(all(row["relative_ntfs_path"] for row in subfiles))
        self.assertEqual(operation["tool_receipts"][0]["tool_version"], "4.15.0")
        self.assertIsNotNone(operation["tool_receipts"][0]["started_at"])
        mft = next(op for op in snapshot["operations"].values() if op["scope"] == "ntfs.mft")
        self.assertIn("times_unix", mft["files_identified"][0]["timestamps_ntfs"])
        artifact = next(iter(snapshot["artifacts"].values()))
        self.assertTrue(artifact["usable"])
        self.assertEqual(artifact["mft_reference"], params["inode"])
        self.assertEqual(artifact["attribute_id"], params["attribute_id"])
        self.assertEqual(artifact["expected_size_bytes"], artifact["actual_size_bytes"])
        data = _read(store.workspace / artifact["path"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), artifact["sha256"])
        self.assertEqual(artifact["verification"]["sha256"], artifact["sha256"])
        self.assertIn({"case_id": case_id, "device_id": original["id"], "partition_id": image["id"], "operation_id": extracted["id"], "artifact_id": artifact["evidence_id"]}, snapshot["links"])
        self.assertTrue(verify_exchange(self.root)["valid"])

    def test_failed_and_partial_analyses_are_not_completed_evidence(self):
        store, case_id, source, manifest, image = self.fixture()
        failed = self.run_op(store, case_id, image, "list", {"read_budget": 4096})
        partial = self.run_op(store, case_id, image, "list", {"max_entries": 1})
        snapshot = read_manifest(self.root)
        self.assertEqual(snapshot["operations"][failed["id"]]["status"], "failed")
        self.assertTrue(snapshot["operations"][failed["id"]]["errors"])
        self.assertFalse(snapshot["operations"][failed["id"]]["usable_as_completed_result"])
        self.assertFalse(snapshot["operations"][partial["id"]]["usable_as_completed_result"])
        self.assertFalse(snapshot["artifacts"])
        self.assertTrue(verify_exchange(self.root)["valid"])

    def test_interrupted_extraction_is_unusable_even_if_bytes_were_written(self):
        store, case_id, source, manifest, image = self.fixture()
        params = self.extraction(store, case_id, manifest, image)
        update = store.update_operation
        def fail_final(identifier, status, results, actor):
            if status == "completed": raise OSError("Synthetic failure after bytes and evidence registration")
            return update(identifier, status, results, actor)
        with patch.object(store, "update_operation", side_effect=fail_final):
            with self.assertRaises(OSError): self.run_op(store, case_id, image, "extract", params)
        snapshot = read_manifest(self.root)
        artifact = next(iter(snapshot["artifacts"].values()))
        self.assertFalse(artifact["usable"])
        self.assertEqual(snapshot["operations"][artifact["operation_id"]]["status"], "failed")
        self.assertTrue((store.workspace / artifact["path"]).exists())

    def test_repeated_extraction_and_analyzer_do_not_modify_or_duplicate_copies(self):
        store, case_id, source, manifest, image = self.fixture()
        params = self.extraction(store, case_id, manifest, image)
        first = self.run_op(store, case_id, image, "extract", params)["results"][0]["result"]
        path = store.workspace / first["relative_path"]
        before, data = path.stat(), _read(path)
        second = self.run_op(store, case_id, image, "extract", params)
        self.assertTrue(second["results"][0]["result"]["reused"])
        self.assertEqual(len(read_manifest(self.root)["artifacts"]), 1)
        artifact = register_artifact(store, case_id, source_id=image["id"], path=str(path), source_item="SYNTHETIC MFT",
                                     extraction_reference=first["evidence_id"], expected_sha256=first["sha256"], actor="Synthetic Operator", reason="Explicit copy read", authorized=True)
        analysis = analyze_artifact(store, case_id, artifact["id"], "Synthetic Operator")
        snapshot = read_manifest(self.root)
        self.assertTrue(snapshot["operations"][analysis["id"]]["observations"])
        self.assertTrue(snapshot["operations"][analysis["id"]]["hypotheses"])
        self.assertEqual(len(snapshot["links"]), len({canonical(link) for link in snapshot["links"]}))
        self.assertTrue(any(link["operation_id"] == analysis["id"] and link["artifact_id"] == artifact["id"] for link in snapshot["links"]))
        after = path.stat()
        self.assertEqual((before.st_atime_ns, before.st_mtime_ns, before.st_ctime_ns, before.st_mode), (after.st_atime_ns, after.st_mtime_ns, after.st_ctime_ns, after.st_mode))
        self.assertEqual(_read(path), data)
        self.assertTrue(verify_exchange(self.root)["valid"])

    def test_external_workspace_boundary_and_copy_reader_without_relaxing_project_files(self):
        code = self.work / "code-only"; code.mkdir(mode=0o700)
        from ransomware_investigator.safety import existing_case_root
        def validate_synthetic_root(value):
            # Keep actual project fixture authorization while exercising external
            # workspace/copy branches with a separate simulated code directory.
            with patch("ransomware_investigator.safety.PROJECT", ROOT):
                return existing_case_root(value)
        with patch("ransomware_investigator.safety.PROJECT", code), patch("ransomware_investigator.safety.existing_case_root", side_effect=validate_synthetic_root), patch("ransomware_investigator.cases.existing_case_root", side_effect=validate_synthetic_root), patch("ransomware_investigator.exchange.existing_case_root", side_effect=validate_synthetic_root):
            store, case_id = self.open_store()
            path = Path(prepare_inputs(store, case_id, "Synthetic Operator")["input_directory"]) / "synthetic.txt"
            path.write_bytes(b"SYNTHETIC safe copy\n")
            source = register_source(store, case_id, reference="SYNTHETIC", source_kind="synthetic", description="Synthetic", source_sha256=None, actor="Synthetic Operator")
            artifact = register_artifact(store, case_id, source_id=source["id"], path=str(path), source_item="SYNTHETIC", extraction_reference="manual-synthetic",
                                         expected_sha256=hashlib.sha256(b"SYNTHETIC safe copy\n").hexdigest(), actor="Synthetic Operator", reason="Test", authorized=True)
            self.assertEqual(analyze_artifact(store, case_id, artifact["id"], "Synthetic Operator")["status"], "completed")
            from ransomware_investigator.safety import read_project_file
            with self.assertRaises(RIError): read_project_file(path)
            self.assertTrue(verify_exchange(self.root)["valid"])

    def test_physical_workflow_metadata_uses_synthetic_broker_response_only(self):
        store, case_id = self.open_store()
        source = register_source(store, case_id, reference="SYNTHETIC PHYSICAL DECLARATION", source_kind="physical-device", description="Not connected", source_sha256=None, actor="Synthetic Operator")
        device = register_device(store, case_id, source_id=source["id"], pin=PIN, actor="Synthetic Operator", reason="Synthetic metadata only")
        prepared = prepare_device(store, case_id, device["id"], "ntfs.list", {}, actor="Synthetic Operator", reason="Synthetic", authorized=True, provided_scope="ntfs.list")
        self.assertFalse(prepared["physical_read_performed"])
        op = store.get("operations", prepared["operation_id"])
        from ransomware_investigator.audit import digest
        response = {"status": "completed", "request_id": op["request"]["request_id"], "request_sha256": digest(op["request"]),
                    "before": state(), "after": state(), "broker_audit_sha256": "d" * 64,
                    "worker": {"receipt": {"status": "ok", "request_sha256": digest(op["request"]), "parser_uid": 65534, "stdout_sha256": "a" * 64, "stderr": "RI_READ 0 512 512\n"},
                               "result": {"entries": [], "summary": {"partial": False}}}}
        with patch("ransomware_investigator.ntfs.client.execute_physical", return_value=response), patch("ransomware_investigator.ntfs.physical.probe_physical", side_effect=AssertionError("No hardware")):
            execute_device(store, case_id, op["id"], "Synthetic Operator")
        snapshot = read_manifest(self.root)
        normalized = snapshot["operations"][op["id"]]
        self.assertEqual(normalized["sources"][0]["device"]["persistent_identifiers"]["serial"], PIN["serial"])
        self.assertEqual(normalized["sources"][0]["partition"]["pin"], PIN)
        self.assertTrue(verify_exchange(self.root)["valid"])
