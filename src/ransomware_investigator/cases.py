"""One owner for case state, content-addressed outputs and transactional audit."""
from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import contextmanager, nullcontext
from pathlib import Path

from .audit import bytes_digest, canonical, digest
from .safety import (PROJECT, CASE_ID, CASE_NAMESPACE, RIError, PublicationPending, ensure_user, project_path,
                     existing_case_root, workspace_path, text, utcnow)


KINDS = frozenset({"cases", "inventories", "evidence", "authorizations", "operations", "preflights"})


def public_artifact_record(doc: dict) -> dict:
    """Local output projection; not permission to send anything to a provider."""
    is_artifact = (doc.get("status") in ("extracted_copy_registered", "source_declared")
                   or doc.get("scope", "").startswith(("artifact_","ntfs."))
                   or doc.get("status", "").startswith("ntfs_") or doc.get("status")=="triage_extracted_copy")
    if not is_artifact:
        return doc
    fields = ("id", "case_id", "created_at", "schema_version", "status", "mode", "scope",
              "source_evidence_id", "content_sha256", "size_bytes", "artifact_id", "left_analysis_id", "right_analysis_id")
    output = {key: doc[key] for key in fields if key in doc}
    results = doc.get("results", [])
    if results:
        result = results[0]
        output["result_summary"] = {key: result[key] for key in
                                    ("artifact_id", "sha256", "size_bytes", "integrity", "reused", "error_code") if key in result}
        if "observations" in result:
            output["result_summary"].update(observation_count=len(result["observations"]),
                                             hypothesis_count=len(result["hypotheses"]),
                                             ransom_note_assessment=result["ransom_note_assessment"],
                                             coverage=result["coverage"], format=result["format"])
        for field in ("common", "left_only", "right_only"):
            if field in result:
                output["result_summary"][field] = [{"kind": item["kind"], "value_sha256": bytes_digest(item["normalized"].encode("utf-8"))} for item in result[field]]
        if "receipt" in result:
            receipt=result["receipt"]
            payload=result.get("result") or {}
            output["result_summary"].update(worker_status=receipt["status"],parser_uid=receipt["parser_uid"],
                                             response_sha256=receipt["stdout_sha256"],
                                             read_receipts=sum(line.startswith("RI_READ ") for line in receipt["stderr"].splitlines()))
            if "entries" in payload:
                output["result_summary"].update(entries=len(payload["entries"]),summary=payload["summary"])
            if payload.get("kind")=="mft":
                output["result_summary"].update({k:payload[k] for k in ("inode","sequence","allocated","directory","size_bytes")})
                output["result_summary"]["streams"]=[{k:s[k] for k in ("type","id","size_bytes","flags")} for s in payload["streams"]]
            for key in ("evidence_id","size_bytes","sha256","acquisition_type","reused","deleted_recovery_verified"):
                if key in payload: output["result_summary"][key]=payload[key]
    output["output_policy"] = "artifact_sensitive_fields_redacted; local_use_only"
    return output


class CaseStore:
    def __init__(self, workspace: str | Path | None = None, *, case_root: str | Path | None = None):
        ensure_user()
        if workspace is not None and case_root is not None:
            raise RIError("No combinar workspace local y expediente compartido; no hay fallback.")
        self.case_root = existing_case_root(case_root) if case_root is not None else None
        self.workspace = self.case_root / CASE_NAMESPACE if self.case_root else project_path(PROJECT / ".ri-cases" if workspace is None else workspace)
        self.workspace.mkdir(mode=0o700, parents=self.case_root is None, exist_ok=True)
        self.path(self.workspace)
        self._private(self.workspace, directory=True)
        self.exchange = None
        if self.case_root:
            from .exchange import Exchange
            self.exchange = Exchange(self.workspace, self.case_root)
        with self._lock():
            if self.exchange:
                self.exchange.initialize()
            self._open_database()
            try:
                if self.exchange:
                    self.exchange.publish(self)
            except Exception:
                self.db.close()
                raise

    def path(self, value, *, exists=False):
        return workspace_path(self.workspace, value, exists=exists)

    def sync_directory(self, value):
        path = self.path(value, exists=True)
        self._private(path, directory=True)
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _lock(self):
        return self.exchange.lock() if self.exchange else nullcontext()

    def _open_database(self):
        path = self.path(self.workspace / "cases.sqlite3")
        is_new = False
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
            is_new = True
        self._private(path)
        # SQLite's rollback sidecars must not be attacker-controlled links either.
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = self.path(str(path) + suffix)
            if sidecar.exists():
                self._private(sidecar)
        self.db = sqlite3.connect(path, timeout=5)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA synchronous=FULL")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if (is_new and version != 0) or (not is_new and version != 1):
                raise RIError("Versión de base de datos no soportada; no se migrará automáticamente.")
            if not is_new:
                required = KINDS | {"blobs", "events"}
                if self.exchange:
                    required = required | {"exchange_versions"}
                tables = {row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not required <= tables:
                    raise RIError("Esquema incompleto; no se reparará automáticamente.")
                return
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, document TEXT NOT NULL, sha256 TEXT NOT NULL)")
                for kind in sorted(KINDS - {"cases"}):
                    extra = "identity_key TEXT NOT NULL, mode TEXT NOT NULL," if kind == "evidence" else ""
                    self.db.execute(f"CREATE TABLE IF NOT EXISTS {kind} (id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id), {extra} document TEXT NOT NULL, sha256 TEXT NOT NULL)")
                    self.db.execute(f"CREATE INDEX IF NOT EXISTS {kind}_case ON {kind}(case_id)")
                self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS evidence_identity ON evidence(case_id,identity_key,mode)")
                self.db.execute("CREATE TABLE IF NOT EXISTS blobs (sha256 TEXT PRIMARY KEY, content BLOB NOT NULL)")
                self.db.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, document TEXT NOT NULL, sha256 TEXT NOT NULL)")
                if self.exchange:
                    self.db.execute("CREATE TABLE exchange_versions (seq INTEGER PRIMARY KEY REFERENCES events(seq), document TEXT NOT NULL)")
                self.db.execute("PRAGMA user_version=1")
        except Exception:
            self.db.close()
            raise

    @staticmethod
    def _private(path: Path, directory: bool = False) -> None:
        info = path.lstat()
        valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        if not valid or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RIError("Workspace y DB deben ser propios, privados y sin enlaces (700/600).")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.db.close()

    @staticmethod
    def _kind(kind: str) -> str:
        if kind not in KINDS:
            raise RIError("Tipo de registro no admitido.")
        return kind

    @staticmethod
    def _id(identifier: str) -> str:
        if not isinstance(identifier, str) or not CASE_ID.fullmatch(identifier):
            raise RIError("Identificador inválido; se requieren 32 caracteres hexadecimales.")
        return identifier

    def get(self, kind: str, identifier: str) -> dict:
        kind, identifier = self._kind(kind), self._id(identifier)
        row = self.db.execute(f"SELECT document, sha256 FROM {kind} WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise RIError(f"Registro {kind} inexistente.")
        doc = json.loads(row["document"])
        if digest(doc) != row["sha256"]:
            raise RIError("Integridad del registro inválida.")
        return doc

    def list(self, kind: str, case_id: str | None = None) -> list[dict]:
        kind = self._kind(kind)
        if case_id is not None:
            self.get("cases", case_id)
        if kind != "cases" and case_id is not None:
            rows = self.db.execute(f"SELECT id FROM {kind} WHERE case_id=? ORDER BY rowid", (case_id,))
        else:
            rows = self.db.execute(f"SELECT id FROM {kind} ORDER BY rowid")
        return [self.get(kind, row["id"]) for row in rows.fetchall()]

    @contextmanager
    def transaction(self):
        ensure_user()
        with self._lock():
            self.db.execute("BEGIN IMMEDIATE")
            try:
                report = self.verify()
                if not report["valid"]:
                    raise RIError("Auditoría o persistencia alteradas; escritura bloqueada.")
                yield
                self.db.commit()
            except Exception:
                self.db.rollback()
                raise
            if self.exchange:
                try:
                    self.exchange.publish(self)
                except (RIError, OSError, ValueError) as exc:
                    raise PublicationPending("SQLite confirmó la escritura pero la publicación JSON quedó pendiente; no repetir lecturas. Reabrir/sincronizar el expediente. " + str(exc)) from exc

    def _event(self, kind: str, doc: dict, actor: str, action: str) -> None:
        last = self.db.execute("SELECT seq,sha256 FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        event = {
            "seq": 1 if last is None else last["seq"] + 1,
            "previous_sha256": "0" * 64 if last is None else last["sha256"],
            "at": utcnow(), "actor": text(actor, "operador", 200), "uid": os.getuid(),
            "action": action, "entity": kind, "id": doc["id"], "record_sha256": digest(doc),
        }
        self.db.execute("INSERT INTO events VALUES (?,?,?)", (event["seq"], canonical(event), digest(event)))
        if self.exchange:
            self.db.execute("INSERT INTO exchange_versions VALUES (?,?)", (event["seq"], canonical(doc)))

    def _insert(self, kind: str, doc: dict, actor: str, action: str = "created") -> dict:
        self._kind(kind)
        if kind == "cases":
            self.db.execute("INSERT INTO cases VALUES (?,?,?)", (doc["id"], canonical(doc), digest(doc)))
        elif kind == "evidence":
            self.db.execute("INSERT INTO evidence VALUES (?,?,?,?,?,?)", (doc["id"], doc["case_id"], doc["identity_key"], doc["mode"], canonical(doc), digest(doc)))
        else:
            self.db.execute(f"INSERT INTO {kind} VALUES (?,?,?,?)", (doc["id"], doc["case_id"], canonical(doc), digest(doc)))
        self._event(kind, doc, actor, action)
        return doc

    def create_case(self, title: str, responsible: str, actor: str) -> dict:
        if self.case_root:
            raise RIError("El expediente compartido ya existe: usar case attach, no crear otro caso.")
        doc = {"id": uuid.uuid4().hex, "title": text(title, "título", 300),
               "responsible": text(responsible, "responsable", 200), "created_at": utcnow(), "schema_version": 1}
        with self.transaction():
            return self._insert("cases", doc, actor)

    def attach_case(self, reference: str, responsible: str, actor: str) -> dict:
        """Bind one RI identifier to this existing dossier, never create a dossier."""
        if not self.case_root:
            raise RIError("case attach requiere RI_CASE_ROOT o --case-root explícito.")
        reference = text(reference, "referencia del expediente", 300)
        with self.transaction():
            cases = self.list("cases")
            if cases:
                if len(cases) != 1 or cases[0]["title"] != reference:
                    raise RIError("El expediente ya está vinculado a otra referencia; no se creará un caso paralelo.")
                return cases[0]
            doc = {"id": uuid.uuid4().hex, "title": reference, "responsible": text(responsible, "responsable", 200),
                   "created_at": utcnow(), "schema_version": 1, "existing_dossier": str(self.case_root)}
            return self._insert("cases", doc, actor)

    def record(self, kind: str, case_id: str, payload: dict, actor: str, blobs: list[bytes] = ()) -> dict:
        if kind == "cases":
            raise RIError("Usar create_case para registrar casos.")
        self._kind(kind)
        self.get("cases", case_id)
        doc = {**payload, "id": uuid.uuid4().hex, "case_id": case_id, "created_at": utcnow(), "schema_version": 1}
        with self.transaction():
            for content in blobs:
                self.db.execute("INSERT OR IGNORE INTO blobs VALUES (?,?)", (bytes_digest(content), content))
            context = doc.get("scan_context")
            if context is not None:
                if kind != "operations" or set(context) != {"scan_id", "page_index"} or type(context["page_index"]) is not int or context["page_index"]<0:
                    raise RIError("Contexto de escaneo inválido.")
                job=self.get("operations",context["scan_id"])
                if job.get("scope")!="ntfs.scan" or job["case_id"]!=case_id or job["source_id"]!=doc.get("source_id"):
                    raise RIError("Operación de página fuera del escaneo.")
            self._insert(kind, doc, actor)
            if context is not None:
                self.db.execute("INSERT INTO ntfs_scan_attempts VALUES (?,?,?)",(context["scan_id"],context["page_index"],doc["id"]))
            return doc

    def update_operation(self, identifier: str, status: str, results: list[dict], actor: str) -> dict:
        if status not in ("completed", "partial", "failed"):
            raise RIError("Estado de operación inválido.")
        with self.transaction():
            doc = self.get("operations", identifier)
            if doc["status"] != "started":
                raise RIError("La operación ya tiene un resultado final.")
            doc.update(status=status, results=results, finished_at=utcnow())
            self.db.execute("UPDATE operations SET document=?,sha256=? WHERE id=?", (canonical(doc), digest(doc), identifier))
            self._event("operations", doc, actor, status)
        return doc

    def start_ntfs_scan(self, case_id, source_id, plan, actor):
        """Optional, additive index in the SAME case DB; immutable pages remain evidence."""
        source = self.get("evidence", source_id)
        if source["case_id"] != case_id:
            raise RIError("Fuente fuera del caso.")
        identifier = uuid.uuid4().hex
        state = {"phase": "volume", "page_index": 0, "next_inode": None, "after_directory": -1,
                 "directory_cursor": 0, "directory_total": None, "volume_identity": None, "worker_sha256": None,
                 "slots_examined": 0, "records_decoded": 0, "allocated_files": 0, "deleted_candidates": 0,
                 "directories_indexed": 0, "directories_completed": 0, "directory_entries": 0,
                 "path_warnings": 0, "virtual_directories_indexed": 0, "virtual_path_pages": 0,
                 "category_counts": {}, "previous_page_sha256": "0" * 64}
        doc = {"id": identifier, "case_id": case_id, "schema_version": 1, "created_at": utcnow(),
               "scope": "ntfs.scan", "status": "started", "source_id": source_id, "plan": plan, "initial_state": state}
        with self.transaction():
            self.db.execute("CREATE TABLE IF NOT EXISTS ntfs_scan_state (scan_id TEXT PRIMARY KEY REFERENCES operations(id), document TEXT NOT NULL, sha256 TEXT NOT NULL, checkpoint_id TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS ntfs_scan_dirs (scan_id TEXT NOT NULL REFERENCES operations(id), inode INTEGER NOT NULL, document TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(scan_id,inode))")
            self.db.execute("CREATE TABLE IF NOT EXISTS ntfs_scan_pending (scan_id TEXT NOT NULL REFERENCES operations(id), page_index INTEGER NOT NULL, operation_id TEXT UNIQUE NOT NULL REFERENCES operations(id), PRIMARY KEY(scan_id,page_index))")
            self.db.execute("CREATE TABLE IF NOT EXISTS ntfs_scan_attempts (scan_id TEXT NOT NULL REFERENCES operations(id), page_index INTEGER NOT NULL, operation_id TEXT PRIMARY KEY REFERENCES operations(id))")
            self.db.execute("CREATE TABLE IF NOT EXISTS ntfs_scan_terms (case_id TEXT NOT NULL, scan_id TEXT NOT NULL, source_id TEXT NOT NULL, finding_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, page_evidence_id TEXT NOT NULL, PRIMARY KEY(scan_id,finding_id,kind,value))")
            self.db.execute("CREATE INDEX IF NOT EXISTS ntfs_scan_terms_lookup ON ntfs_scan_terms(case_id,kind,value)")
            self._insert("operations", doc, actor)
            self.db.execute("INSERT INTO ntfs_scan_state VALUES (?,?,?,NULL)", (identifier, canonical(state), digest(state)))
        return doc

    def ntfs_scan_state(self, scan_id):
        job = self.get("operations", scan_id)
        if job.get("scope") != "ntfs.scan":
            raise RIError("No es un escaneo NTFS.")
        row = self.db.execute("SELECT * FROM ntfs_scan_state WHERE scan_id=?", (scan_id,)).fetchone()
        if row is None:
            raise RIError("Checkpoint de escaneo ausente.")
        state = json.loads(row["document"])
        expected = self.get("evidence", row["checkpoint_id"])["next_state"] if row["checkpoint_id"] else job["initial_state"]
        if digest(state) != row["sha256"] or state != expected:
            raise RIError("Checkpoint de escaneo alterado; no se reanudará.")
        return state

    def ntfs_scan_directory(self, scan_id, *, after=None, inode=None):
        if inode is None:
            row = self.db.execute("SELECT document,sha256 FROM ntfs_scan_dirs WHERE scan_id=? AND inode>? ORDER BY inode LIMIT 1", (scan_id, after)).fetchone()
        else:
            row = self.db.execute("SELECT document,sha256 FROM ntfs_scan_dirs WHERE scan_id=? AND inode=?", (scan_id, inode)).fetchone()
        if row is None:
            return None
        doc = json.loads(row["document"])
        if digest(doc) != row["sha256"]:
            raise RIError("Índice derivado de directorios alterado.")
        return doc

    def ntfs_scan_pending(self, scan_id):
        return [{"page_index": row[0], "operation_id": row[1]} for row in self.db.execute("SELECT page_index,operation_id FROM ntfs_scan_pending WHERE scan_id=? ORDER BY page_index", (scan_id,))]

    def ntfs_scan_attempts(self, scan_id):
        for row in self.db.execute("SELECT page_index,operation_id FROM ntfs_scan_attempts WHERE scan_id=? ORDER BY rowid",(scan_id,)):
            doc=self.get("operations",row["operation_id"])
            if doc.get("scan_context")!={"scan_id":scan_id,"page_index":row["page_index"]}: raise RIError("Índice de intentos alterado.")
            yield doc

    def add_ntfs_scan_pending(self, scan_id, page_index, operation_id):
        job, operation = self.get("operations", scan_id), self.get("operations", operation_id)
        if operation["case_id"] != job["case_id"] or operation.get("source_id") != job["source_id"]:
            raise RIError("Solicitud física no corresponde al escaneo.")
        with self.transaction():
            self.db.execute("INSERT INTO ntfs_scan_pending VALUES (?,?,?)", (scan_id, page_index, operation_id))

    def clear_failed_ntfs_scan_pending(self, scan_id):
        with self.transaction():
            for pending in self.ntfs_scan_pending(scan_id):
                if self.get("operations", pending["operation_id"])["status"] == "started":
                    raise RIError("Solicitud aún pendiente; revisar aprobación/ledger antes de descartarla.")
            self.db.execute("DELETE FROM ntfs_scan_pending WHERE scan_id=?", (scan_id,))

    def commit_ntfs_scan_page(self, scan_id, operation_id, prior_state, next_state, evidence, directories, terms, actor):
        job = self.get("operations", scan_id)
        with self.transaction():
            if self.ntfs_scan_state(scan_id) != prior_state or job["status"] != "started":
                raise RIError("Checkpoint obsoleto o escaneo finalizado.")
            operation = self.get("operations", operation_id)
            if operation["status"] != "started" or operation["case_id"] != job["case_id"] or operation["source_id"] != job["source_id"]:
                raise RIError("Operación de página no corresponde al escaneo.")
            for directory in directories:
                self.db.execute("INSERT INTO ntfs_scan_dirs VALUES (?,?,?,?)", (scan_id, directory["inode"], canonical(directory), digest(directory)))
            doc = {**evidence, "id": uuid.uuid4().hex, "case_id": job["case_id"], "schema_version": 1, "created_at": utcnow(),
                   "scan_id": scan_id, "operation_id": operation_id, "next_state": next_state, "prior_state_sha256": digest(prior_state)}
            self._insert("evidence", doc, actor)
            for finding_id, kind, value in terms:
                self.db.execute("INSERT OR IGNORE INTO ntfs_scan_terms VALUES (?,?,?,?,?,?,?)", (job["case_id"], scan_id, job["source_id"], finding_id, kind, value, doc["id"]))
            operation.update(status="completed", finished_at=utcnow(), results=[{"scan_page": {"evidence_id": doc["id"], "path": doc["relative_path"],
                             "sha256": doc["content_sha256"], "size_bytes": doc["size_bytes"], "page_index": prior_state["page_index"]}}])
            self.db.execute("UPDATE operations SET document=?,sha256=? WHERE id=?", (canonical(operation), digest(operation), operation_id))
            self._event("operations", operation, actor, "completed")
            self.db.execute("UPDATE ntfs_scan_state SET document=?,sha256=?,checkpoint_id=? WHERE scan_id=?", (canonical(next_state), digest(next_state), doc["id"], scan_id))
            self.db.execute("DELETE FROM ntfs_scan_pending WHERE scan_id=? AND page_index=?", (scan_id, prior_state["page_index"]))
        return operation

    def ntfs_scan_correlations(self, case_id, *, max_groups=1000, members_per_group=100):
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ntfs_scan_terms'").fetchone() is None:
            return {"groups":[],"groups_truncated":False,"scope":"no metadata scan index exists; no scan terms compared"}
        rows = self.db.execute("SELECT kind,value,COUNT(DISTINCT source_id) AS sources,COUNT(*) AS members FROM ntfs_scan_terms WHERE case_id=? GROUP BY kind,value HAVING COUNT(DISTINCT source_id)>1 ORDER BY kind,value LIMIT ?", (case_id, max_groups + 1)).fetchall()
        groups = []
        for row in rows[:max_groups]:
            members = [dict(item) for item in self.db.execute("SELECT scan_id,source_id,finding_id,page_evidence_id FROM ntfs_scan_terms WHERE case_id=? AND kind=? AND value=? ORDER BY source_id,finding_id LIMIT ?", (case_id, row["kind"], row["value"], members_per_group))]
            groups.append({"kind": row["kind"], "value": row["value"], "source_count": row["sources"], "member_count": row["members"],
                           "members": members, "members_truncated": row["members"] > len(members), "causal_attribution": "not_established"})
        return {"groups": groups, "groups_truncated": len(rows) > max_groups, "scope": "indexed metadata terms; not whole-file content comparison"}

    def record_evidence_once(self, case_id: str, payload: dict, actor: str) -> tuple[dict, bool]:
        """Atomic deduplication of an extracted copy, not of physical sources."""
        self.get("cases", case_id)
        if payload.get("status") != "extracted_copy_registered":
            raise RIError("Solo registro de copias extraídas en esta operación.")
        with self.transaction():
            row = self.db.execute("SELECT id FROM evidence WHERE case_id=? AND identity_key=? AND mode=?",
                                  (case_id, payload["identity_key"], payload["mode"])).fetchone()
            if row:
                previous = self.get("evidence", row["id"])
                if any(previous[field] != payload[field] for field in ("relative_path", "file_identity", "source_evidence_id", "source_item", "extraction_reference", "content_sha256", "size_bytes")):
                    raise RIError("Copia ya registrada con otra ruta o metadata; no se reutilizará ni duplicará silenciosamente.")
                return previous, False
            doc = {**payload, "id": uuid.uuid4().hex, "case_id": case_id, "created_at": utcnow(), "schema_version": 1}
            return self._insert("evidence", doc, actor), True

    def events(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.db.execute("SELECT document FROM events ORDER BY seq")]

    def blob(self, sha256: str) -> bytes:
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise RIError("Hash de salida inválido.")
        row = self.db.execute("SELECT content FROM blobs WHERE sha256=?", (sha256,)).fetchone()
        if row is None or bytes_digest(row[0]) != sha256:
            raise RIError("Salida ausente o alterada.")
        return row[0]

    def export_case(self, case_id: str, *, include_sensitive: bool = False) -> dict:
        report = self.verify()
        if not report["valid"]:
            raise RIError("Integridad inválida; exportación bloqueada.")
        case = self.get("cases", case_id)
        records = {kind: self.list(kind, case_id) for kind in sorted(KINDS - {"cases"})}
        ids = {case_id} | {doc["id"] for docs in records.values() for doc in docs}
        exported_records = records if include_sensitive else {kind: [public_artifact_record(doc) for doc in docs] for kind, docs in records.items()}
        return {"schema_version": 1, "case": case, "records": exported_records,
                "events": [e for e in self.events() if e["id"] in ids],
                "audit_workspace": report,
                "raw_outputs": [{"sha256": sha, "content": json.loads(self.blob(sha))}
                                for sha in sorted({s for inv in records["inventories"] for s in inv["raw_sha256"]})],
                "artifact_output_policy": "local_sensitive" if include_sensitive else "redacted_projection_not_original_documents",
                "limit": "Exportación local; no autoriza envío externo. Campos previos del MVP pueden ser sensibles. No es imagen forense. Eventos filtrados no forman una cadena independiente."}

    def verify(self) -> dict:
        problems, expected = [], {}
        previous = "0" * 64
        event_count = 0
        for seq, row in enumerate(self.db.execute("SELECT seq,document,sha256 FROM events ORDER BY seq"), 1):
            event_count += 1
            try:
                event = json.loads(row["document"])
                if row["seq"] != seq or event["seq"] != seq or event["previous_sha256"] != previous or digest(event) != row["sha256"]:
                    problems.append(f"event:{seq}")
                expected[(event["entity"], event["id"])] = event["record_sha256"]
            except (ValueError, KeyError, TypeError):
                problems.append(f"event:{seq}:malformed")
            previous = row["sha256"]
        seen = set()
        for kind in sorted(KINDS):
            for row in self.db.execute(f"SELECT * FROM {kind}"):
                key = (kind, row["id"])
                seen.add(key)
                try:
                    doc = json.loads(row["document"])
                    if digest(doc) != row["sha256"] or expected.get(key) != row["sha256"] or doc["id"] != row["id"]:
                        problems.append(f"{kind}:{row['id']}")
                    if kind != "cases" and doc["case_id"] != row["case_id"]:
                        problems.append(f"{kind}:{row['id']}:case_mismatch")
                    if kind == "operations" and doc.get("scan_context"):
                        context=doc["scan_context"]
                        attempt=self.db.execute("SELECT scan_id,page_index FROM ntfs_scan_attempts WHERE operation_id=?",(doc["id"],)).fetchone()
                        if attempt is None or tuple(attempt)!=(context["scan_id"],context["page_index"]): problems.append("scan_attempt:"+doc["id"])
                    if kind == "evidence" and any(doc[field] != row[field] for field in ("identity_key", "mode")):
                        problems.append(f"{kind}:{row['id']}:identity_mismatch")
                    if kind == "evidence" and doc.get("status") in ("extracted_copy_registered","ntfs_image_registered","ntfs_physical_registered","triage_extracted_copy","ntfs_scan_page","ntfs_prefix_copy"):
                        relationships=[("evidence","source_evidence_id")]
                        if doc["status"] in ("extracted_copy_registered","ntfs_image_registered") or "authorization_id" in doc:
                            relationships.append(("authorizations","authorization_id"))
                        if doc["status"] in ("triage_extracted_copy", "ntfs_scan_page", "ntfs_prefix_copy"): relationships.append(("operations","operation_id"))
                        if doc["status"] == "ntfs_scan_page": relationships.append(("operations", "scan_id"))
                        for table, field in relationships:
                            related = self.db.execute(f"SELECT case_id FROM {table} WHERE id=?", (doc[field],)).fetchone()
                            if related is None or related[0] != row["case_id"] or doc[field] == doc["id"]:
                                problems.append(f"{kind}:{row['id']}:invalid_{field}")
                    if kind == "inventories":
                        for sha in doc.get("raw_sha256", []):
                            if not self.db.execute("SELECT 1 FROM blobs WHERE sha256=?", (sha,)).fetchone():
                                problems.append(f"missing_blob:{sha}")
                except (ValueError, KeyError, TypeError):
                    problems.append(f"{kind}:{row['id']}:malformed")
        for key in expected.keys() - seen:
            problems.append("missing_record:" + ":".join(key))
        for row in self.db.execute("SELECT sha256,content FROM blobs"):
            if bytes_digest(row["content"]) != row["sha256"]:
                problems.append("blob:" + row["sha256"])
        if self.exchange:
            versions = self.db.execute("SELECT seq,document FROM exchange_versions ORDER BY seq").fetchall()
            if len(versions) != event_count:
                problems.append("exchange:missing_versions")
            for row in versions:
                try:
                    event_row = self.db.execute("SELECT document FROM events WHERE seq=?", (row["seq"],)).fetchone()
                    event, doc = json.loads(event_row[0]), json.loads(row["document"])
                    if digest(doc) != event["record_sha256"] or doc["id"] != event["id"]:
                        problems.append("exchange:version:" + str(row["seq"]))
                except (ValueError, KeyError, TypeError):
                    problems.append("exchange:malformed_version:" + str(row["seq"]))
        if self.db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            problems.append("foreign_key_violation")
        return {"valid": not problems, "problems": problems, "events": event_count,
                "head_sha256": previous, "limit": "No es inmutable: una reescritura completa o rollback requiere ancla externa para detectarse."}
