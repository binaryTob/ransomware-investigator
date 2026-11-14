import contextlib
import io
import json
import sqlite3
from unittest.mock import patch

from tests.common import ProjectTest
from ransomware_investigator.cases import CaseStore
from ransomware_investigator.cli import main
from ransomware_investigator.safety import RIError


class CaseTests(ProjectTest):
    def test_independent_cases_persist_and_verify(self):
        with CaseStore(self.work / "cases") as store:
            one = store.create_case("Uno", "Synthetic Operator", "Synthetic Operator")
            two = store.create_case("Dos", "Bob", "Bob")
            self.assertNotEqual(one["id"], two["id"])
            self.assertEqual(store.verify()["events"], 2)
        with CaseStore(self.work / "cases") as store:
            self.assertEqual(store.get("cases", one["id"]), one)
            self.assertEqual(len(store.list("cases")), 2)
            self.assertTrue(store.verify()["valid"])

    def test_failed_audit_rolls_back_case(self):
        with CaseStore(self.work / "cases") as store:
            with patch.object(store, "_event", side_effect=RIError("fallo sintético")):
                with self.assertRaises(RIError):
                    store.create_case("Uno", "Synthetic Operator", "Synthetic Operator")
            self.assertEqual(store.list("cases"), [])
            self.assertEqual(store.events(), [])

    def test_tamper_detected_and_writes_blocked(self):
        with CaseStore(self.work / "cases") as store:
            one = store.create_case("Uno", "Synthetic Operator", "Synthetic Operator")
            with store.db:
                store.db.execute("UPDATE cases SET document=? WHERE id=?", ('{}', one["id"]))
            self.assertFalse(store.verify()["valid"])
            with self.assertRaises(RIError):
                store.create_case("Dos", "Bob", "Bob")

    def test_deleted_record_and_changed_event_detected(self):
        with CaseStore(self.work / "cases") as store:
            store.create_case("Uno", "Synthetic Operator", "Synthetic Operator")
            with store.db:
                store.db.execute("DELETE FROM cases")
            self.assertFalse(store.verify()["valid"])
        with CaseStore(self.work / "more") as store:
            store.create_case("Uno", "Synthetic Operator", "Synthetic Operator")
            with store.db:
                store.db.execute("UPDATE events SET sha256='altered'")
            self.assertFalse(store.verify()["valid"])

    def test_rejects_invalid_ids_unknown_kind_and_nonprivate_store(self):
        with CaseStore(self.work / "cases") as store:
            for kind, identifier in (("cases", "../x"), ("cases;DROP TABLE cases", "a" * 32), ("cases", "a" * 32)):
                with self.subTest(kind=kind), self.assertRaises(RIError):
                    store.get(kind, identifier)
        public = self.work / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        with self.assertRaises(RIError):
            CaseStore(public)

    def test_cli_case_flow_and_root_rejection(self):
        prefix = ["--workspace", str(self.work / "cli"), "--operator", "Synthetic Operator"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(prefix + ["case", "create", "--title", "Caso", "--responsible", "Synthetic Operator"]), 0)
        case = json.loads(out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()) as shown:
            self.assertEqual(main(prefix + ["case", "show", "--case", case["id"]]), 0)
        self.assertEqual(json.loads(shown.getvalue())["id"], case["id"])
        with patch("os.geteuid", return_value=0), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(prefix + ["case", "list"]), 2)

    def test_existing_unknown_or_incomplete_db_is_not_initialized_or_repaired(self):
        unknown = self.work / "unknown"
        unknown.mkdir(mode=0o700)
        path = unknown / "cases.sqlite3"
        path.touch(mode=0o600)
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE unrelated (id INTEGER)")
        before = path.read_bytes()
        with self.assertRaises(RIError):
            CaseStore(unknown)
        self.assertEqual(path.read_bytes(), before)
        with CaseStore(self.work / "incomplete") as store:
            store.db.execute("DROP TABLE blobs")
            store.db.commit()
        path = self.work / "incomplete/cases.sqlite3"
        before = path.read_bytes()
        with self.assertRaises(RIError):
            CaseStore(self.work / "incomplete")
        self.assertEqual(path.read_bytes(), before)
