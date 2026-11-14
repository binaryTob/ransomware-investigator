# Contributing

Use Python 3.11+ and keep runtime dependencies in the standard library. Preserve the policy/executor/persistence boundaries and the fail-closed behavior documented in [AGENTS.md](AGENTS.md).

1. Work as a normal user, without sudo, broker deployment, host changes, or real-device access.
2. Reproduce behavior with newly generated synthetic inputs inside the project.
3. Keep assertions and authorization contracts intact. Add regression tests for behavior changes.
4. Run `python3 -m unittest discover -s tests -v` and `python3 ri.py --help`.
5. Follow [the publication checklist](docs/publication.md) before sharing any change.

Tests may compile local code and construct regular synthetic NTFS images when the documented optional tools already exist. They must not use actual device discovery, loop devices, mounting, or evidence.

Never contribute real case data, personal details, private paths, credentials, investigation identifiers, original samples, generated workspaces, exports, or incident reports. Public bug reports must use fictional reproductions.

Changes to the approved public file list require a fresh manual privacy review. Do not add broad ignore exceptions to publish operational output.
