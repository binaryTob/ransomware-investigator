#!/usr/bin/env python3
"""Synthetic-only shared dossier demo. Never uses the configured real dossier."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from ransomware_investigator.cli import main
from ransomware_investigator.exchange import read_manifest, verify_exchange
from ransomware_investigator.safety import ensure_user, project_path


def demo(directory):
    ensure_user()
    directory = project_path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = directory / "existing-synthetic-dossier"
    root.mkdir(mode=0o700)  # Fixture construction, not the application's root resolver.
    (root / "SYNTHETIC-NOT-ALQUIMIX.txt").write_text("Previously existing synthetic dossier for integration demo.\n")
    prefix = ["--case-root", str(root), "--operator", "Synthetic operator"]
    def call(*args, expected=0):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(prefix + list(args))
        if code != expected:
            raise RuntimeError(f"Synthetic step {args[:2]} failed ({code}): {err.getvalue()}")
        return json.loads(out.getvalue() or err.getvalue())
    case_id = call("case", "attach", "--reference", "SYNTHETIC EXISTING DOSSIER", "--responsible", "Synthetic operator")["id"]
    source = call("evidence", "register-source", "--case", case_id, "--kind", "synthetic", "--reference", "SYNTHETIC NTFS SOURCE", "--description", "Generated fixture, no physical device")["id"]
    inputs = call("artifact", "prepare-inputs", "--case", case_id)["input_directory"]
    spec = importlib.util.spec_from_file_location("shared_demo_builder", ROOT / "examples/ntfs/make_fixture.py")
    builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    fixture = builder.create_fixture(Path(inputs))
    image = call("triage", "register-image", "--case", case_id, "--source-evidence", source, "--file", fixture["path"],
                 "--expected-sha256", fixture["sha256"], "--scope", "ntfs.register-image", "--authorize-read", "--reason", "Synthetic image registration")["id"]
    def read(name, *params, expected=0):
        return call("triage", name, "--case", case_id, "--source", image, "--scope", "ntfs." + name,
                    "--authorize-read", "--reason", "Explicit synthetic scope", *params, expected=expected)
    read("list")
    read("search", "--extension", ".locked")
    read("deleted")
    metadata = read("mft", "--inode", str(fixture["entries"]["README_RECOVER.txt"]["inode"]))["result_summary"]
    stream = metadata["streams"][0]
    params = ["--inode", str(metadata["inode"]), "--attribute-id", str(stream["id"]),
              "--expected-sequence", str(metadata["sequence"]), "--expected-size", str(stream["size_bytes"])]
    first = read("extract", *params)
    second = read("extract", *params)
    failed = read("list", "--read-budget", "4096", expected=2)
    report = call("exchange", "verify")
    snapshot = read_manifest(root)
    artifact = next(iter(snapshot["artifacts"].values()))
    if artifact["sha256"] != fixture["files"]["README_RECOVER.txt"]["sha256"] or not artifact["usable"]:
        raise RuntimeError("Known synthetic extraction verification failed")
    return {"mode": "synthetic_shared_case_real_libtsk", "case_root": str(root), "case_id": case_id,
            "manifest": str(root / "ransomware-investigator/exchange/manifest.json"),
            "revision_seq": snapshot["revision_seq"], "operation_count": len(snapshot["operations"]),
            "artifact": artifact, "first_extraction": first["id"], "second_extraction": second["id"],
            "reused": second["result_summary"]["reused"], "failed_operation": failed["id"],
            "failed_operation_status": snapshot["operations"][failed["id"]]["status"],
            "exchange_verification": report, "audit": call("audit", "verify"),
            "real_case_touched": False, "physical_devices_accessed": False, "broker_started": False}


if __name__ == "__main__":
    print(json.dumps(demo(ROOT / ".test-tmp" / ("shared-demo-" + uuid.uuid4().hex)), indent=2, ensure_ascii=True))
