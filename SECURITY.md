# Security and privacy

Do not post evidence, incident details, personal data, device identities, credentials, copies, or operational reports in public issues or pull requests. Demonstrate problems with newly generated synthetic inputs only.

## Boundaries

- The normal CLI refuses root execution. It has no shell or privileged fallback.
- Real metadata discovery requires explicit authorization for that execution.
- Image operations and artifact-copy operations have different authorization scopes.
- Registered copy reads require expected hashes and no-atime, no-follow access.
- Physical operations require a separate deployed broker and exact human approval. Neither deployment nor physical access is authorized by developing or testing this source.
- Sensitive local output is not authorization for remote disclosure. Hashes and reduced projections can still be sensitive.
- Filesystem checks, audit hashes, and read budgets are useful safeguards, not guarantees against all compromise or evidence alteration.

## Reporting a defect

For a non-sensitive defect, provide the affected function or command, a minimal synthetic reproduction, expected behavior, and observed behavior. Never attach an actual investigation archive or database.

No private vulnerability-reporting channel is configured in this source tree. If a report cannot be made safely with synthetic data, do not publish its sensitive details. Arrange a private channel with the repository owner first.

Automated tests and publication scans do not constitute a full independent security audit. Optional native and privileged components require separate review before operational deployment.
