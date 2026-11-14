# Ransomware Investigator

A local-first command-line toolkit for recording forensic metadata, managing investigation records, and examining explicitly authorized copies of extracted files.

**This is an investigation aid, not a recovery guarantee, malware attribution service, disk imager, or forensic write blocker.** Results are observations and bounded hypotheses. Missing data does not establish health, integrity, or the absence of encryption.

The public source tree contains code and fictional fixtures only. Do not contribute evidence, customer information, investigation reports, device identities, credentials, or operational authorizations.

## What it does

- **Metadata inventory:** normalize saved or simulated device metadata, track persistent identities, compare observations, and identify protected system dependencies.
- **Local record keeping:** store records in private SQLite workspaces with content hashes, provenance, authorization records, and a verifiable audit chain.
- **Artifact analysis:** verify the expected SHA-256 of an already extracted copy, inspect a bounded sample, recognize basic formats, and identify lexical ransom-note indicators without executing content or making network requests.
- **NTFS triage:** perform bounded metadata queries and selective extraction from regular image files using a native worker backed by The Sleuth Kit (TSK).
- **Resumable metadata scans:** save pages and checkpoints, enforce read/time budgets, and correlate previously saved metadata without reopening the source.
- **Local exchange and reporting:** publish versioned JSON snapshots to an explicitly selected existing dossier, verify saved outputs, and render escaped, script-free HTML reports from caller-supplied text.

CLI help and many validation messages are currently in Spanish. This README is in English.

## Requirements

The Python CLI requires **Python 3.11 or later** and uses the standard library at runtime. It is designed for Linux; filesystem and permission checks rely on Linux/POSIX behavior, including `O_NOATIME` for registered copies.

Optional NTFS functionality additionally requires:

- A C11 compiler available as `/usr/bin/cc`.
- TSK headers and libraries under `/usr/local/include` and `/usr/local/lib`.
- For synthetic NTFS fixtures: `/usr/sbin/mkntfs`, `/usr/sbin/ntfscp`, `/usr/local/bin/fls`, and `/usr/local/bin/istat`. Some diagnostic comparisons also use `/usr/bin/ntfsinfo`.

Build and fixture scripts use fixed tool locations. They do not download dependencies, install packages, configure the host, mount filesystems, or use loop devices. Provision optional dependencies separately if needed.

## Quick start: no installation or devices

From the project root, as a normal user:

```bash
python3 ri.py --help
python3 ri.py --version
```

Run an entirely fictional inventory workflow:

```bash
python3 examples/simulated/run_demo.py
```

Run offline artifact analysis against inert synthetic text:

```bash
python3 examples/artifacts/run_demo.py
```

These demos create new private workspaces under `.ri-cases/` and do not inspect real devices. Their JSON output describes synthetic records, audit verification, and the limits of the observations. Do not reuse demo approvals for operational work.

To exercise the optional NTFS pipeline after its dependencies are already available:

```bash
python3 tools/build_ntfs_worker.py
python3 examples/ntfs/run_demo.py
python3 examples/ntfs_scan/run_demo.py
```

The fixture generator creates **new regular synthetic image files inside the project**. Its construction-only modifications are not a repair feature and must never be applied to evidence.

## CLI overview

```text
python3 ri.py [--workspace PATH | --case-root PATH] [--operator LABEL] GROUP COMMAND ...
```

Use `python3 ri.py GROUP --help` and the individual command's `--help` for exact parameters.

| Group | Purpose |
|---|---|
| `case` | Create local synthetic/workspace records, attach to an existing dossier, list, show, or export |
| `audit` | List audit events or verify persisted records and their chain |
| `exchange` | Inspect, verify, or synchronize the explicit dossier's saved JSON exchange |
| `discovery` | Import synthetic metadata; real metadata discovery requires a separate explicit authorization |
| `inventory` | Inspect and compare saved inventories |
| `evidence` | Register declared provenance or an original's persistent inventory identity |
| `artifact` | Prepare an input area; register, verify, analyze, and compare authorized extracted copies |
| `triage` | Register image metadata, query images, and prepare typed requests for a separately deployed broker |
| `scan` | Plan, page, resume, correlate, and verify bounded NTFS metadata scans |
| `acquisition preflight` | Evaluate saved metadata and a declared destination plan; does not acquire a disk |

### Workspace boundaries

- The default `.ri-cases/` workspace and custom `--workspace` paths stay inside the project. Generated workspaces are private operational data, not public source.
- `--case-root` or `RI_CASE_ROOT` must explicitly identify an **existing** dossier. The application uses its own `ransomware-investigator` namespace inside that dossier.
- A dossier root and a local workspace cannot be combined. Invalid, empty, unsafe, or missing dossier configuration fails closed, without creating a replacement investigation.
- Workspace directories and database files must be owned by the operator and private. The application rejects unsafe permissions rather than silently fixing them.
- Exported JSON, audit records, provenance, filenames, hashes, and reports may all contain sensitive information. A reduced output projection is **not** an anonymization guarantee.

### Artifact handling

The artifact analyzer only reads copies under `<workspace>/extracted/`. Registration requires explicit read authorization, declared extraction provenance, and an expected SHA-256. Metadata source paths are never followed to acquire the original.

Registered copies are read with `O_NOATIME`, without a fallback if that is unavailable or denied. Identity, hash, size, and timestamps are checked. The analyzer does not rewrite copy contents, permissions, or timestamps.

`--include-sensitive` permits local sensitive output only. It does not authorize sending anything to a remote model, telemetry collector, or third-party service.

### Physical access is a separate trust boundary

The CLI does not elevate itself and does not turn a failed image operation into direct physical access. Broker and deployment components live in `broker/` and `admin/`; their presence in the source tree is not permission to deploy or execute them.

Physical operations require a separately installed, root-owned broker, human approval for the exact typed operation, and fresh checks of identity, mounts, protected dependencies, and read-only state. **Do not run the CLI, tests, editor, or this checkout as root.** No broker installation or real-device operation is part of the quick start or test workflow.

Kernel read-only flags are not equivalent to a physical forensic write blocker. No claim of forensic preservation follows solely from software checks.

## Architecture

```text
CLI -> policy and path validation -> fixed execution catalog / image worker
                  |                                |
                  +-------- private CaseStore -----+
                                    |
                         audit, exchange, reports

Physical requests -> separately deployed broker -> exact approved read
```

| Path | Responsibility |
|---|---|
| `src/ransomware_investigator/safety.py` | Deny-by-default policy, authorization and path boundaries |
| `src/ransomware_investigator/executor.py` | Fixed unprivileged command catalog, no shell fallback |
| `src/ransomware_investigator/inventory.py` | Metadata normalization and persistent identity handling |
| `src/ransomware_investigator/cases.py` | Persistence, transactional records and audit ownership |
| `src/ransomware_investigator/preflight.py` | Planning against saved metadata, not acquisition |
| `src/ransomware_investigator/copy_io.py` | Bounded, no-follow, no-atime copy reads |
| `src/ransomware_investigator/artifact_analysis.py` | Deterministic offline sample heuristics |
| `src/ransomware_investigator/ntfs/` | Typed worker and physical-request contracts |
| `native/` | Bounded native NTFS parser and diagnostic code |
| `tools/` | Local build, reporting, bundle verification and publication checks |
| `examples/`, `tests/` | Fictional fixtures and synthetic regression tests |

Report functions take explicit source hashes, expected actions, statuses, and cutoff dates; they contain no embedded investigation chronology. Metadata classification has no built-in incident year. The `.sealed` suffix and `SYN` marker used in fixtures are generic demonstration values, not indicators from an investigation.

## Verification

Run as a normal user from the project root:

```bash
python3 -m unittest discover -s tests -v
python3 ri.py --help
```

The full suite includes native builds and synthetic NTFS integration tests, so optional NTFS dependencies are required for that suite. Missing dependencies are a verification gap, not evidence that the corresponding feature works. Test results on fixtures do not validate behavior against actual evidence or devices.

Before committing or publishing, follow [the publication checklist](docs/publication.md). The privacy checker is an additional guard, not proof that arbitrary text is anonymous.

## Limitations

- No full disk acquisition, mounting, repair, unlocking, or volume activation.
- No sample execution, dynamic malware analysis, decryption, network enrichment, or automatic remote AI access.
- Extension, timestamp, header, and lexical matches do not establish malware family, initial access, execution, cryptographic implementation, integrity, or recoverability.
- Metadata scan scope is distinct from file-content authorization. Prefix hashes do not describe an entire file.
- Audit hashes help detect inconsistencies; they are not an external timestamp authority or a substitute for independently preserved records.
- Historical authorizations do not authorize a new read, replay, retry, or publication.

See [SECURITY.md](SECURITY.md) for security boundaries and [CONTRIBUTING.md](CONTRIBUTING.md) for development rules.

## License

No license has been selected. Public repository visibility alone does not grant a license to reuse or redistribute the code.
