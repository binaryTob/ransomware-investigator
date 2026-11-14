"""Case-integrated lifecycle for authorized, pre-extracted artifact copies."""
from __future__ import annotations

from contextlib import contextmanager
from .artifact_analysis import ANALYZER_VERSION, analyze_sample, compare_results
from .audit import digest
from .copy_io import read_copy
from .safety import Policy, RIError, PublicationPending, copy_path, sha256_value, text


def prepare_inputs(store, case_id, actor):
    store.get("cases", case_id)
    path = store.path(store.workspace / "extracted")
    path.mkdir(mode=0o700, exist_ok=True)
    store._private(path, directory=True)
    operation = store.record("operations", case_id, {"scope": "artifact_prepare", "status": "completed",
                             "results": [{"input_directory": str(path), "files_read": False}]}, actor)
    return {"operation_id": operation["id"], "input_directory": str(path), "files_read": False}


def register_source(store, case_id: str, *, reference: str, source_kind: str, description: str,
                    source_sha256: str | None, actor: str) -> dict:
    """Metadata only: the reference is never interpreted as an IO path."""
    store.get("cases", case_id)
    if source_kind not in ("physical-device", "forensic-image", "synthetic"):
        raise RIError("Tipo de fuente no soportado.")
    reference, description = text(reference, "referencia de fuente"), text(description, "procedencia")
    declared_hash = sha256_value(source_sha256) if source_sha256 is not None else None
    key = "declared:" + digest([source_kind, reference])
    mode = "simulated" if source_kind == "synthetic" else "declared"
    if any(doc["identity_key"] == key and doc["mode"] == mode for doc in store.list("evidence", case_id)):
        raise RIError("Fuente ya declarada; usar su ID existente.")
    return store.record("evidence", case_id, {"identity_key": key, "mode": mode, "status": "source_declared",
                        "source_kind": source_kind, "reference": reference, "description": description,
                        "responsible": text(actor, "responsable", 200), "content_sha256": None,
                        "declared_source_sha256": declared_hash, "source_integrity": "not_verified_by_application",
                        "preserved_image": False, "provenance_status": "operator_declared"}, actor)


@contextmanager
def _operation(store, case_id, actor, scope, **references):
    operation = store.record("operations", case_id, {"scope": scope, "status": "started", **references}, actor)
    try:
        yield operation
    except PublicationPending:
        raise
    except (RIError, OSError, ValueError) as exc:
        store.update_operation(operation["id"], "failed", [{"error_code": type(exc).__name__, "reason": str(exc)}], actor)
        raise


def register_artifact(store, case_id: str, *, source_id: str, path: str, source_item: str,
                      extraction_reference: str, expected_sha256: str, actor: str, reason: str,
                      authorized: bool) -> dict:
    store.get("cases", case_id)
    source = store.get("evidence", source_id)
    if source["case_id"] != case_id or source["status"] not in ("original_registered", "source_declared", "ntfs_image_registered", "ntfs_physical_registered"):
        raise RIError("Fuente no válida para este caso; usar original registrado o fuente declarada.")
    if authorized is not True:
        store.record("operations", case_id, {"scope": "artifact_register", "status": "denied", "source_evidence_id": source_id}, actor)
        raise RIError("Registro de copia bloqueado: falta --authorize-copy.")
    source_item, extraction_reference = text(source_item, "ubicación original declarada"), text(extraction_reference, "referencia y versión de extracción")
    expected_sha256 = sha256_value(expected_sha256)
    path = copy_path(store.workspace, path)
    relative = path.relative_to(store.workspace).as_posix()
    grant = Policy.copy_grant(case_id, source_id, relative, expected_sha256, actor, reason, authorized=authorized)
    authorization = store.record("authorizations", case_id, grant, actor)
    with _operation(store, case_id, actor, "artifact_register", authorization_id=authorization["id"], source_evidence_id=source_id) as operation:
        facts, _ = read_copy(store.workspace, path, grant, case_id, expected_sha256)
        payload = {"identity_key": "artifact:" + digest([source_id, source_item, extraction_reference, expected_sha256]),
                   "mode": source["mode"], "status": "extracted_copy_registered", "artifact_kind": "extracted_file_copy",
                   "source_evidence_id": source_id, "source_item": source_item, "extraction_reference": extraction_reference,
                   "provenance_status": "operator_declared_extraction; source_not_opened",
                   "relative_path": relative, "copy_name": path.name, "authorization_id": authorization["id"],
                   "expected_sha256": expected_sha256, "content_sha256": facts["sha256"], "size_bytes": facts["size_bytes"],
                   "file_identity": facts["identity"], "integrity_scope": "entire_authorized_copy_not_physical_source",
                   "responsible": text(actor, "responsable", 200), "preserved_image": False}
        artifact, created = store.record_evidence_once(case_id, payload, actor)
        store.update_operation(operation["id"], "completed", [{"artifact_id": artifact["id"], "sha256": facts["sha256"],
                               "size_bytes": facts["size_bytes"], "integrity": "matched", "reused": not created}], actor)
        return artifact


def get_artifact(store, case_id, artifact_id):
    artifact = store.get("evidence", artifact_id)
    if artifact["case_id"] != case_id or artifact["status"] != "extracted_copy_registered":
        raise RIError("El registro no es una copia extraída de este caso.")
    return artifact


def _read_registered(store, case_id, artifact):
    grant = store.get("authorizations", artifact["authorization_id"])
    if grant["case_id"] != case_id or grant.get("source_evidence_id") != artifact["source_evidence_id"]:
        raise RIError("La autorización no corresponde a la procedencia registrada.")
    return read_copy(store.workspace, store.workspace / artifact["relative_path"], grant, case_id,
                     artifact["expected_sha256"], expected_identity=artifact["file_identity"])


def verify_artifact(store, case_id, artifact_id, actor):
    artifact = get_artifact(store, case_id, artifact_id)
    with _operation(store, case_id, actor, "artifact_verify", artifact_id=artifact_id) as operation:
        facts, _ = _read_registered(store, case_id, artifact)
        return store.update_operation(operation["id"], "completed", [{"artifact_id": artifact_id, "integrity": "matched", **facts}], actor)


def analyze_artifact(store, case_id, artifact_id, actor):
    artifact = get_artifact(store, case_id, artifact_id)
    with _operation(store, case_id, actor, "artifact_analysis", artifact_id=artifact_id, analyzer_version=ANALYZER_VERSION) as operation:
        facts, sample = _read_registered(store, case_id, artifact)
        result = analyze_sample(sample, source_item=artifact["source_item"], copy_name=artifact["copy_name"], truncated=facts["sample_truncated"])
        result.update(artifact_id=artifact_id, sha256=facts["sha256"], size_bytes=facts["size_bytes"],
                      integrity="matched", integrity_check=facts, source_evidence_id=artifact["source_evidence_id"])
        return store.update_operation(operation["id"], "completed", [result], actor)


def get_analysis(store, case_id, identifier):
    analysis = store.get("operations", identifier)
    if analysis["case_id"] != case_id or analysis.get("scope") != "artifact_analysis" or analysis.get("status") != "completed":
        raise RIError("Se requiere un análisis de artefacto completado del mismo caso.")
    return analysis


def compare_artifacts(store, case_id, left_id, right_id, actor):
    left, right = get_analysis(store, case_id, left_id), get_analysis(store, case_id, right_id)
    if left["results"][0]["analyzer"] != right["results"][0]["analyzer"]:
        raise RIError("Versiones de analizador diferentes; no se compararán silenciosamente.")
    left_artifact = get_artifact(store, case_id, left["artifact_id"])
    right_artifact = get_artifact(store, case_id, right["artifact_id"])
    if left_artifact["mode"] != right_artifact["mode"]:
        raise RIError("No se comparan modos de procedencia diferentes.")
    with _operation(store, case_id, actor, "artifact_comparison", left_analysis_id=left_id, right_analysis_id=right_id) as operation:
        result = compare_results(left["results"][0], right["results"][0])
        result.update(left_analysis_id=left_id, right_analysis_id=right_id, files_reread=False)
        return store.update_operation(operation["id"], "completed", [result], actor)
