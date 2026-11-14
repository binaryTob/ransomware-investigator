#!/usr/bin/env python3
"""Offline synthetic demo; never reads a physical source or real artifacts."""
import argparse
import contextlib
import hashlib
import io
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ransomware_investigator.cli import main
from ransomware_investigator.safety import ensure_user, project_path, read_project_file


def demo(workspace: Path) -> dict:
    ensure_user()
    workspace = project_path(workspace)
    prefix = ["--workspace", str(workspace), "--operator", "Demo sintética"]

    def call(*args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = main(prefix + list(args))
        if status != 0:
            raise RuntimeError(f"Falló paso sintético con código {status}: {args[0:2]}")
        return json.loads(out.getvalue())

    case = call("case", "create", "--title", "Artifact Analyzer: SINTÉTICO", "--responsible", "Demo sintética")
    case_id = case["id"]
    source = call("evidence", "register-source", "--case", case_id, "--reference", "SYNTHETIC-PHYSICAL-SOURCE-001",
                  "--kind", "synthetic", "--description", "Fuente y extracción ficticias; no hay acceso físico")
    prepared = call("artifact", "prepare-inputs", "--case", case_id)
    inputs = Path(prepared["input_directory"])
    analyses, artifacts = {}, {}
    for filename in ("synthetic-note.txt", "benign-readme.txt", "educational-example.txt"):
        data = read_project_file(ROOT / "examples/artifacts" / filename)
        path = project_path(inputs / (uuid.uuid4().hex + "-" + filename))
        with path.open("xb") as stream:
            stream.write(data)  # Synthetic setup only. The analyzer itself never copies/writes artifact content.
        artifact = call("artifact", "register", "--case", case_id, "--source-evidence", source["id"],
                        "--file", str(path), "--source-item", "SYNTHETIC-WINDOWS/" + filename,
                        "--extraction-reference", "synthetic-extraction/version-1", "--expected-sha256", hashlib.sha256(data).hexdigest(),
                        "--authorize-copy", "--reason", "Copia sintética para demostración offline")
        call("artifact", "verify", "--case", case_id, "--artifact", artifact["id"])
        artifacts[filename] = artifact["id"]
        analyses[filename] = call("artifact", "analyze", "--case", case_id, "--artifact", artifact["id"])
        call("artifact", "show", "--case", case_id, "--operation", analyses[filename]["id"])
    comparison = call("artifact", "compare", "--case", case_id, "--left", analyses["synthetic-note.txt"]["id"],
                      "--right", analyses["educational-example.txt"]["id"])
    listed = call("artifact", "list", "--case", case_id)
    audit = call("audit", "verify")
    call("case", "export", "--case", case_id)
    return {"mode": "simulated", "workspace": str(workspace), "case_id": case_id, "source_evidence_id": source["id"],
            "artifact_ids": artifacts, "analysis_ids": {key: value["id"] for key, value in analyses.items()},
            "assessments": {key: value["result_summary"]["ransom_note_assessment"] for key, value in analyses.items()},
            "comparison": comparison, "registered_copies": len(listed), "audit": audit,
            "physical_devices_accessed": False, "network_used": False,
            "sensitive_indicators_in_output": False, "note": "Las conclusiones se limitan a fixtures sintéticos, no a evidencia real."}


if __name__ == "__main__":
    ensure_user()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", default=str(ROOT / ".ri-cases" / ("artifact-demo-" + uuid.uuid4().hex)))
    args = parser.parse_args()
    print(json.dumps(demo(Path(args.workspace)), ensure_ascii=True, indent=2))
