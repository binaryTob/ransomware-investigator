"""Local JSON CLI. Device access is opt-in, never a fallback."""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sqlite3
import sys

from . import __version__
from .cases import CaseStore, public_artifact_record
from .artifacts import (analyze_artifact, compare_artifacts, get_artifact, prepare_inputs,
                        register_artifact, register_source, verify_artifact)
from .discovery import scan_metadata
from .inventory import compare, register_original, save_inventory
from .preflight import record_preflight
from . import ntfs_triage
from . import ntfs_scan
from .safety import PROJECT, RIError, PublicationPending, ensure_user, read_project_file


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="ri", description="Inventario forense local; no monta ni adquiere dispositivos.")
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument("--workspace", help="Workspace local privado dentro del proyecto; incompatible con RI_CASE_ROOT/--case-root.")
    root.add_argument("--case-root", help="Expediente EXISTENTE absoluto; predeterminado RI_CASE_ROOT. Nunca se crea ni hay fallback.")
    root.add_argument("--operator", default=getpass.getuser(), help="Responsable declarado; se registra también el UID real.")
    groups = root.add_subparsers(dest="group", required=True)
    case = groups.add_parser("case").add_subparsers(dest="command", required=True)
    create = case.add_parser("create")
    create.add_argument("--title", required=True)
    create.add_argument("--responsible", required=True)
    attach = case.add_parser("attach", help="Vincular un identificador RI al expediente compartido existente; no crea otro expediente.")
    attach.add_argument("--reference", required=True)
    attach.add_argument("--responsible", required=True)
    case.add_parser("list")
    show = case.add_parser("show")
    show.add_argument("--case", required=True)
    export = case.add_parser("export", help="Exportación JSON local con registros, salidas originales y hashes.")
    export.add_argument("--case", required=True)
    export.add_argument("--include-sensitive", action="store_true", help="Solo exportación local de indicadores; NO autoriza envío a modelos remotos.")
    audit = groups.add_parser("audit").add_subparsers(dest="command", required=True)
    audit.add_parser("verify")
    audit.add_parser("list")
    exchange = groups.add_parser("exchange", help="Intercambio JSON local para el agente investigador.").add_subparsers(dest="command", required=True)
    exchange.add_parser("status")
    exchange.add_parser("verify", help="Solo lectura de JSON/salidas; no abre SQLite, extraídos ni dispositivos.")
    exchange.add_parser("sync", help="Publicar commits pendientes de SQLite, sin repetir análisis ni lecturas de evidencia.")
    manifest = exchange.add_parser("manifest")
    manifest.add_argument("--include-sensitive", action="store_true", help="Contenido local del manifiesto; no autoriza un proveedor remoto.")
    scans = groups.add_parser("scan", help="Inventario NTFS de metadatos paginado/reanudable; contenido separado.").add_subparsers(dest="command",required=True)
    start_scan = scans.add_parser("start",help="Crear plan/checkpoint, sin leer fuente.")
    start_scan.add_argument("--case",required=True); start_scan.add_argument("--source",required=True)
    start_scan.add_argument("--page-size",type=int,default=64); start_scan.add_argument("--read-budget",type=int,default=64*1024*1024)
    start_scan.add_argument("--timeout-ms",type=int,default=10000); start_scan.add_argument("--max-records",type=int,default=20000000)
    start_scan.add_argument("--max-directories",type=int,default=1000000)
    start_scan.add_argument("--validation-operation",help="Comparación física inicial completada del mismo caso y build; obligatoria para escaneos físicos.")
    for name in ("status","run-images","prepare-batch","execute-batch"):
        action=scans.add_parser(name); action.add_argument("--case",required=True); action.add_argument("--scan-id",required=True)
        if name!="status": action.add_argument("--max-pages",type=int,default=8)
        if name in ("run-images","prepare-batch"):
            action.add_argument("--authorize-read",action="store_true"); action.add_argument("--scope",required=True); action.add_argument("--reason",required=True)
        if name=="prepare-batch": action.add_argument("--retry-failed",action="store_true")
        if name=="execute-batch": action.add_argument("--authorize-batch",action="store_true")
    correlate=scans.add_parser("correlate",help="Correlación local de metadatos ya guardados; sin acceso físico.")
    correlate.add_argument("--case",required=True); correlate.add_argument("--max-groups",type=int,default=1000)
    validate=scans.add_parser("compare-reference",help="Comparar resultados guardados con referencia TSK tipada, sin releer dispositivo.")
    validate.add_argument("--case",required=True); validate.add_argument("--listing-operation",required=True); validate.add_argument("--metadata-operation",required=True)
    validate.add_argument("--baseline-json",required=True); validate.add_argument("--expected-baseline-sha256",required=True)
    validate.add_argument("--root-metadata-operation",help="Registro MFT raíz observado en el mismo lote; requerido para validar físicamente la ruta/sequence padre.")
    verify_scan=scans.add_parser("verify",help="Verificar páginas y checkpoints guardados sin fuente física.")
    verify_scan.add_argument("--case",required=True); verify_scan.add_argument("--scan-id",required=True)
    initial=scans.add_parser("prepare-validation",help="Preparar cuatro consultas exactas antes del primer escaneo físico integral.")
    initial.add_argument("--case",required=True); initial.add_argument("--source",required=True); initial.add_argument("--directory-inode",required=True,type=int)
    initial.add_argument("--directory-name",required=True); initial.add_argument("--expected-count",required=True,type=int)
    initial.add_argument("--reason",required=True); initial.add_argument("--authorize-read",action="store_true")
    execute_initial=scans.add_parser("execute-validation",help="Ejecutar lote inicial aprobado por broker; parar ante el primer fallo.")
    execute_initial.add_argument("--case",required=True); execute_initial.add_argument("--plan-operation",required=True); execute_initial.add_argument("--authorize-batch",action="store_true")
    discovery = groups.add_parser("discovery").add_subparsers(dest="command", required=True)
    simulate = discovery.add_parser("simulate")
    simulate.add_argument("--case", required=True)
    simulate.add_argument("--fixture", required=True, help="JSON sintético dentro del proyecto, sin acceso a dispositivos.")
    scan = discovery.add_parser("scan", help="Consulta real de metadatos, solo con autorización expresa.")
    scan.add_argument("--case", required=True)
    scan.add_argument("--profile", choices=["metadata"], required=True)
    scan.add_argument("--authorize-metadata", action="store_true", help="Declaración expresa para esta ejecución; no autoriza adquisición.")
    scan.add_argument("--reason", required=True)
    inventory = groups.add_parser("inventory").add_subparsers(dest="command", required=True)
    inv_list = inventory.add_parser("list")
    inv_list.add_argument("--case", required=True)
    inv_show = inventory.add_parser("show")
    inv_show.add_argument("--inventory", required=True)
    inv_raw = inventory.add_parser("raw")
    inv_raw.add_argument("--inventory", required=True)
    inv_compare = inventory.add_parser("compare")
    inv_compare.add_argument("--before", required=True)
    inv_compare.add_argument("--after", required=True)
    evidence = groups.add_parser("evidence").add_subparsers(dest="command", required=True)
    original = evidence.add_parser("register-original")
    original.add_argument("--case", required=True)
    original.add_argument("--inventory", required=True)
    original.add_argument("--device", required=True, help="identity_key persistente del inventario, nunca /dev/sda.")
    original.add_argument("--notes", required=True)
    evidence_list = evidence.add_parser("list")
    evidence_list.add_argument("--case", required=True)
    evidence_list.add_argument("--include-sensitive", action="store_true")
    source = evidence.add_parser("register-source", help="Declarar procedencia de una extracción previa, sin abrir la fuente.")
    source.add_argument("--case", required=True)
    source.add_argument("--reference", required=True)
    source.add_argument("--kind", choices=["physical-device", "forensic-image", "synthetic"], required=True)
    source.add_argument("--description", required=True)
    source.add_argument("--source-sha256", help="Hash declarado de la fuente; no se verifica ni se abre la fuente.")
    source.add_argument("--include-sensitive", action="store_true")
    artifact = groups.add_parser("artifact", help="Ransomware Artifact Analyzer: solo copias extraídas autorizadas.").add_subparsers(dest="command", required=True)
    prepare = artifact.add_parser("prepare-inputs", help="Crear área vacía de entrada; no copia evidencia.")
    prepare.add_argument("--case", required=True)
    register = artifact.add_parser("register")
    register.add_argument("--case", required=True)
    register.add_argument("--source-evidence", required=True)
    register.add_argument("--file", required=True)
    register.add_argument("--source-item", required=True, help="Ubicación original declarada; nunca se abre.")
    register.add_argument("--extraction-reference", required=True, help="Referencia y versión del proceso de extracción previo.")
    register.add_argument("--expected-sha256", required=True)
    register.add_argument("--authorize-copy", action="store_true")
    register.add_argument("--reason", required=True)
    for name in ("verify", "analyze"):
        action = artifact.add_parser(name)
        action.add_argument("--case", required=True)
        action.add_argument("--artifact", required=True)
        action.add_argument("--include-sensitive", action="store_true", help="Solo visualización local; NO autoriza proveedor remoto.")
    register.add_argument("--include-sensitive", action="store_true")
    artifact_list = artifact.add_parser("list")
    artifact_list.add_argument("--case", required=True)
    artifact_list.add_argument("--include-sensitive", action="store_true")
    show = artifact.add_parser("show")
    show.add_argument("--case", required=True)
    choice = show.add_mutually_exclusive_group(required=True)
    choice.add_argument("--artifact")
    choice.add_argument("--operation")
    show.add_argument("--include-sensitive", action="store_true")
    comparison = artifact.add_parser("compare")
    comparison.add_argument("--case", required=True)
    comparison.add_argument("--left", required=True, help="ID de análisis completado.")
    comparison.add_argument("--right", required=True, help="ID de análisis completado.")
    comparison.add_argument("--include-sensitive", action="store_true")
    acquisition = groups.add_parser("acquisition").add_subparsers(dest="command", required=True)
    preflight = acquisition.add_parser("preflight", help="Solo planificación sobre inventario guardado y declaración de destino.")
    preflight.add_argument("--case", required=True)
    preflight.add_argument("--inventory", required=True)
    preflight.add_argument("--device", required=True, help="identity_key persistente.")
    preflight.add_argument("--destination-plan", required=True, help="JSON de metadatos declarados dentro del proyecto; no inspecciona el destino.")
    triage=groups.add_parser("triage",help="Triage NTFS selectivo; no adquisición completa.").add_subparsers(dest="command",required=True)
    image=triage.add_parser("register-image",help="Registrar imagen/copia regular ya disponible y protegida por permisos.")
    image.add_argument("--case",required=True); image.add_argument("--source-evidence",required=True)
    image.add_argument("--file",required=True); image.add_argument("--expected-sha256",required=True)
    image.add_argument("--offset-bytes",type=int,default=0); image.add_argument("--volume-length",type=int)
    image.add_argument("--scope",required=True); image.add_argument("--authorize-read",action="store_true"); image.add_argument("--reason",required=True)
    image.add_argument("--include-sensitive",action="store_true")
    device=triage.add_parser("register-device",help="Registrar pin DECLARADO sin consultar el dispositivo.")
    device.add_argument("--case",required=True); device.add_argument("--source-evidence",required=True)
    device.add_argument("--pin-json",required=True); device.add_argument("--reason",required=True)
    device.add_argument("--include-sensitive",action="store_true")
    def read_arguments(action):
        action.add_argument("--case",required=True); action.add_argument("--source",required=True)
        action.add_argument("--inode",type=int,default=5); action.add_argument("--attribute-id",type=int,default=0)
        action.add_argument("--max-entries",type=int,default=1000); action.add_argument("--max-depth",type=int,default=0)
        action.add_argument("--max-bytes",type=int,default=1024*1024)
        action.add_argument("--expected-sequence",type=int,default=0); action.add_argument("--expected-size",type=int,default=0)
        action.add_argument("--allow-deleted",action="store_true"); action.add_argument("--extension",action="append",default=[])
        action.add_argument("--read-budget",type=int,default=64*1024*1024); action.add_argument("--timeout-ms",type=int,default=10000)
        action.add_argument("--cursor",type=int,default=0)
        action.add_argument("--scope",required=True); action.add_argument("--authorize-read",action="store_true")
        action.add_argument("--reason",required=True); action.add_argument("--include-sensitive",action="store_true")
    for name in ("list","search","mft","deleted","extract","prefix","volume","records","directory"):
        read_arguments(triage.add_parser(name,help="Operación sobre IMAGEN regular; las fuentes físicas requieren broker."))
    prepare_device=triage.add_parser("prepare-device",help="Preparar petición exacta para aprobación root independiente; no lee dispositivos.")
    prepare_device.add_argument("--operation",choices=["list","search","mft","deleted","extract","prefix","volume","records","directory"],required=True)
    read_arguments(prepare_device)
    execute=triage.add_parser("execute-device",help="Solicitar una lectura ya aprobada al broker root independiente.")
    execute.add_argument("--case",required=True); execute.add_argument("--operation-id",required=True)
    execute.add_argument("--include-sensitive",action="store_true")
    show_triage=triage.add_parser("show")
    show_triage.add_argument("--case",required=True)
    choice=show_triage.add_mutually_exclusive_group(required=True)
    choice.add_argument("--source"); choice.add_argument("--operation-id")
    show_triage.add_argument("--include-sensitive",action="store_true")
    return root


def dispatch(args, store: CaseStore) -> tuple[object, int]:
    if args.group == "scan":
        if args.command == "verify": return ntfs_scan.verify_saved_scan(store,args.case,args.scan_id),0
        if args.command == "prepare-validation":
            return ntfs_scan.prepare_initial_validation(store,args.case,args.source,directory_inode=args.directory_inode,directory_name=args.directory_name,
                        expected_count=args.expected_count,actor=args.operator,reason=args.reason,authorized=args.authorize_read),0
        if args.command == "execute-validation":
            result=ntfs_scan.execute_initial_validation(store,args.case,args.plan_operation,actor=args.operator,authorized=args.authorize_batch)
            return result,0 if result["status"]=="completed" else 2
        if args.command == "start":
            result=ntfs_scan.start_scan(store,args.case,args.source,actor=args.operator,page_size=args.page_size,read_budget=args.read_budget,
                        timeout_ms=args.timeout_ms,max_records=args.max_records,max_directories=args.max_directories,validation_operation=args.validation_operation)
            return {"scan_id":result["id"],"case_id":args.case,"source_id":args.source,"status":"planned_no_source_read"},0
        if args.command == "correlate":
            result=ntfs_scan.correlate_saved(store,args.case,args.operator,max_groups=args.max_groups)
            return result,0 if result["status"]=="completed" else 2
        if args.command == "compare-reference":
            result=ntfs_scan.compare_saved_reference(store,args.case,args.listing_operation,args.metadata_operation,args.baseline_json,args.expected_baseline_sha256,args.operator,root_metadata_id=args.root_metadata_operation)
            return result,0 if result["validation_passed"] else 2
        if args.command == "status": return ntfs_scan.status(store,args.case,args.scan_id),0
        if args.command == "execute-batch": result=ntfs_scan.execute_physical_batch(store,args.case,args.scan_id,actor=args.operator,authorized=args.authorize_batch,max_pages=args.max_pages)
        else:
            action=ntfs_scan.run_image_batch if args.command=="run-images" else ntfs_scan.prepare_physical_batch
            extra={"retry_failed":args.retry_failed} if args.command=="prepare-batch" else {}
            result=action(store,args.case,args.scan_id,actor=args.operator,reason=args.reason,authorized=args.authorize_read,scope=args.scope,max_pages=args.max_pages,**extra)
        return result,0 if result["status"] in ("completed","awaiting_exact_administrator_batch_approval") else 2
    if args.group == "case":
        if args.command == "attach":
            return store.attach_case(args.reference, args.responsible, args.operator), 0
        if args.command == "create":
            return store.create_case(args.title, args.responsible, args.operator), 0
        if args.command == "list":
            return store.list("cases"), 0
        if args.command == "export":
            return store.export_case(args.case, include_sensitive=args.include_sensitive), 0
        return store.get("cases", args.case), 0
    if args.group == "audit":
        if args.command == "list":
            return store.events(), 0
        result = store.verify()
        return result, 0 if result["valid"] else 2
    if args.group == "exchange" and args.command == "sync":
        if not store.exchange:
            raise RIError("Se requiere un expediente compartido explícito.")
        with store._lock():
            return store.exchange.publish(store), 0
    if args.group == "discovery" and args.command == "simulate":
        raw = read_project_file(args.fixture)
        return save_inventory(store, args.case, json.loads(raw), raw, args.operator, mode="simulated"), 0
    if args.group == "discovery" and args.command == "scan":
        result = scan_metadata(store, args.case, args.operator, args.reason, authorized=args.authorize_metadata)
        return result, 0 if result["topology_complete"] else 2
    if args.group == "inventory":
        if args.command == "list":
            return store.list("inventories", args.case), 0
        if args.command == "show":
            return store.get("inventories", args.inventory), 0
        if args.command == "raw":
            inv = store.get("inventories", args.inventory)
            return [{"sha256": sha, "content": json.loads(store.blob(sha))} for sha in inv["raw_sha256"]], 0
        before, after = store.get("inventories", args.before), store.get("inventories", args.after)
        if not store.exchange:
            return compare(before, after), 0
        operation = store.record("operations", before["case_id"], {"scope": "inventory_comparison", "status": "started",
                                 "tool": "ransomware_investigator.inventory.compare", "parameters": {"before": args.before, "after": args.after}}, args.operator)
        try:
            result = compare(before, after)
            store.update_operation(operation["id"], "completed", [result], args.operator)
        except PublicationPending:
            raise
        except RIError as exc:
            store.update_operation(operation["id"], "failed", [{"error": str(exc)}], args.operator)
            raise
        return {**result, "operation_id": operation["id"]}, 0
    if args.group == "evidence":
        if args.command == "list":
            records = store.list("evidence", args.case)
            return records if args.include_sensitive else [public_artifact_record(d) for d in records], 0
        if args.command == "register-source":
            record = register_source(store, args.case, reference=args.reference, source_kind=args.kind,
                                     description=args.description, source_sha256=args.source_sha256, actor=args.operator)
            return record if args.include_sensitive else public_artifact_record(record), 0
        return register_original(store, args.case, args.inventory, args.device, args.operator, args.notes), 0
    if args.group == "artifact":
        if args.command == "prepare-inputs":
            return prepare_inputs(store, args.case, args.operator), 0
        if args.command == "register":
            record = register_artifact(store, args.case, source_id=args.source_evidence, path=args.file,
                                       source_item=args.source_item, extraction_reference=args.extraction_reference,
                                       expected_sha256=args.expected_sha256, actor=args.operator, reason=args.reason,
                                       authorized=args.authorize_copy)
        elif args.command == "verify":
            record = verify_artifact(store, args.case, args.artifact, args.operator)
        elif args.command == "analyze":
            record = analyze_artifact(store, args.case, args.artifact, args.operator)
        elif args.command == "compare":
            record = compare_artifacts(store, args.case, args.left, args.right, args.operator)
        elif args.command == "list":
            records = [doc for doc in store.list("evidence", args.case) if doc["status"] == "extracted_copy_registered"]
            return records if args.include_sensitive else [public_artifact_record(d) for d in records], 0
        elif args.command == "show":
            if args.artifact:
                record = get_artifact(store, args.case, args.artifact)
            else:
                record = store.get("operations", args.operation)
                if record["case_id"] != args.case or not record.get("scope", "").startswith("artifact_"):
                    raise RIError("Operación de artefactos no pertenece a este caso.")
        else:
            raise RIError("Operación de artefacto no implementada.")
        return record if args.include_sensitive else public_artifact_record(record), 0
    if args.group == "acquisition":
        destination = json.loads(read_project_file(args.destination_plan))
        report = record_preflight(store, args.case, args.inventory, args.device, destination, args.operator)
        return report, 0 if report["planning_passed"] else 2
    if args.group == "triage":
        if args.command=="register-image":
            record=ntfs_triage.register_image(store,args.case,source_id=args.source_evidence,path=args.file,expected_sha256=args.expected_sha256,
                     offset_bytes=args.offset_bytes,volume_length=args.volume_length,actor=args.operator,reason=args.reason,
                     authorized=args.authorize_read,scope=args.scope)
        elif args.command=="register-device":
            record=ntfs_triage.register_device(store,args.case,source_id=args.source_evidence,pin=json.loads(read_project_file(args.pin_json)),actor=args.operator,reason=args.reason)
        elif args.command=="execute-device":
            record=ntfs_triage.execute_device(store,args.case,args.operation_id,args.operator)
        elif args.command=="show":
            record=store.get("evidence" if args.source else "operations",args.source or args.operation_id)
            if record["case_id"]!=args.case or not (record.get("status","").startswith("ntfs_") or record.get("status")=="triage_extracted_copy" or record.get("scope","").startswith("ntfs.")):
                raise RIError("Registro de triage no pertenece a este caso.")
        else:
            operation=args.operation if args.command=="prepare-device" else args.command
            parameters={key:getattr(args,key) for key in ("inode","attribute_id","max_entries","max_depth","max_bytes","expected_sequence","expected_size","allow_deleted","read_budget","timeout_ms")}
            parameters["extensions"]=args.extension
            if operation=="directory": parameters["cursor"]=args.cursor
            elif args.cursor: raise RIError("Cursor solo permitido para páginas de directorio.")
            if args.command=="prepare-device":
                return ntfs_triage.prepare_device(store,args.case,args.source,"ntfs."+operation,parameters,
                              actor=args.operator,reason=args.reason,authorized=args.authorize_read,provided_scope=args.scope),0
            record=ntfs_triage.run_image(store,args.case,args.source,"ntfs."+operation,parameters,
                              actor=args.operator,reason=args.reason,authorized=args.authorize_read,provided_scope=args.scope)
        return record if args.include_sensitive else public_artifact_record(record), 2 if record.get("status") in ("failed","partial") else 0
    raise RIError("Operación no implementada.")


def main(argv: list[str] | None = None) -> int:
    try:
        ensure_user()
        args = parser().parse_args(argv)
        case_root = args.case_root if args.case_root is not None else os.environ.get("RI_CASE_ROOT")
        if case_root is not None and not case_root.strip():
            raise RIError("RI_CASE_ROOT vacío: no se usará un workspace alternativo.")
        if case_root is not None and args.workspace is not None:
            raise RIError("RI_CASE_ROOT/--case-root y --workspace son incompatibles; no hay fallback.")
        if args.group == "exchange" and args.command != "sync":
            from .exchange import read_manifest, verify_exchange
            if case_root is None:
                raise RIError("Se requiere RI_CASE_ROOT/--case-root explícito.")
            if args.command == "verify":
                output = verify_exchange(case_root)
            else:
                snapshot = read_manifest(case_root)
                output = snapshot if args.command == "manifest" and args.include_sensitive else {
                    "case_root": snapshot["case_root"], "revision_seq": snapshot["revision_seq"],
                    "audit_head_sha256": snapshot["audit_head_sha256"],
                    "operation_count": len(snapshot["operations"]), "artifact_count": len(snapshot["artifacts"]),
                    "freshness": "published_snapshot_only; use exchange sync to publish pending DB commits"}
            print(json.dumps(output, indent=2, ensure_ascii=True, allow_nan=False))
            return 0
        with CaseStore(args.workspace, case_root=case_root) as store:
            if args.group != "audit" and not store.verify()["valid"]:
                raise RIError("Integridad de la persistencia inválida; usar audit verify y preservar la DB.")
            output, status = dispatch(args, store)
        print(json.dumps(output, indent=2, ensure_ascii=True, allow_nan=False))
        return status
    except (RIError, OSError, sqlite3.Error, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
