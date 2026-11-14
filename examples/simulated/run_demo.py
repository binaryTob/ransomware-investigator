#!/usr/bin/env python3
"""Runnable synthetic CLI workflow. Never invokes discovery scan."""
import argparse
import contextlib
import io
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ransomware_investigator.cli import main
from ransomware_investigator.safety import ensure_user, project_path, read_project_file, utcnow


def demo(workspace: Path) -> dict:
    ensure_user()
    workspace = project_path(workspace)
    prefix = ["--workspace", str(workspace), "--operator", "Operador sintético"]

    def call(*argv, expected=0):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            status = main(prefix + list(argv))
        if status != expected:
            raise RuntimeError(f"CLI sintética devolvió {status}, esperado {expected}: {argv}")
        return json.loads(stream.getvalue())

    case = call("case", "create", "--title", "Demostración SINTÉTICA", "--responsible", "Operador sintético")
    fixture = ROOT / "examples/simulated/windows-usb.json"
    first = call("discovery", "simulate", "--case", case["id"], "--fixture", str(fixture))
    key = "wwn:5000000000000099"
    evidence = call("evidence", "register-original", "--case", case["id"], "--inventory", first["id"], "--device", key, "--notes", "Fixture; no es el SSD real.")

    def write_fixture(label, value):
        path = project_path(workspace / (label + "-" + uuid.uuid4().hex + ".json"))
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream)
        return path

    renamed = json.loads(read_project_file(fixture).decode().replace("sda", "sdc"))
    second_path = write_fixture("renamed", renamed)
    second = call("discovery", "simulate", "--case", case["id"], "--fixture", str(second_path))
    comparison = call("inventory", "compare", "--before", first["id"], "--after", second["id"])
    plan = json.loads(read_project_file(ROOT / "examples/simulated/destination.json"))
    plan["observed_at"] = utcnow()
    destination = write_fixture("destination", plan)
    preflight = call("acquisition", "preflight", "--case", case["id"], "--inventory", second["id"], "--device", key, "--destination-plan", str(destination), expected=2)
    audit = call("audit", "verify")
    export = call("case", "export", "--case", case["id"])
    return {"mode": "simulated", "workspace": str(workspace), "case_id": case["id"],
            "inventory_ids": [first["id"], second["id"]], "evidence_id": evidence["id"],
            "comparison": comparison, "preflight_blockers": preflight["blockers"],
            "acquisition_allowed": preflight["acquisition_allowed"], "audit": audit,
            "exported_raw_outputs": len(export["raw_outputs"]), "physical_devices_accessed": False}


if __name__ == "__main__":
    ensure_user()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=str(ROOT / ".ri-cases" / ("demo-" + uuid.uuid4().hex)))
    args = parser.parse_args()
    print(json.dumps(demo(Path(args.workspace)), indent=2, ensure_ascii=True))
