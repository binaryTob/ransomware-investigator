# Public-source publication checklist

Publishing an investigation tool must not publish an investigation. Do not rely on ignore rules, redacted console output, or the absence of a scanner alert as proof of anonymity.

## Approved material

`PUBLICATION_FILES.txt` is the exact approved public file list. It includes code, generic documentation, and explicitly fictional fixtures only. Review new paths manually before changing it.

Keep all operational material outside the Git repository: dossiers, extracted copies, SQLite databases, audit records, approvals, reports, archives, device metadata, notes, private denylist files, logs, and preservation backups. Never stash that material or put it on a private branch of a repository intended to become public.

## Before staging

1. Review every approved file, including comments, literals, filenames, examples, report templates, configuration, and documentation.
2. Replace case-specific defaults with explicit parameters. Replace any retained examples with new fictional data, not lightly edited incident narratives.
3. Move private data and original versions to an operator-approved location outside the repository. Preserve originals rather than editing evidence.
4. Run the synthetic suite and CLI help as a normal user. Record gaps honestly.
5. Move generated workspaces and build/test artifacts outside the publication directory after verification.
6. Run the offline worktree check:

   ```bash
   python3 tools/check_publication.py
   ```

An optional `--denylist-file PATH` accepts a private local JSON list of known sensitive strings. Keep it outside Git. Neither its contents nor matching excerpts are printed.

## Before committing and pushing

Stage only the explicitly reviewed manifest paths. Do not use a broad `git add .` or force-add ignored output.

```bash
python3 tools/check_publication.py --staged
```

Use a non-personal Git identity for both author and committer, such as `Project Contributors <contributors@users.noreply.github.com>`. Do not copy local global Git configuration, email addresses, signing identities, or previous private history into the publication repository.

After committing, check **all stored Git objects**, including unreachable objects, not just the current checkout:

```bash
python3 tools/check_publication.py --staged --history
```

The history check inspects text blobs, commit/tag contents, tree entry names, object sizes, modes, and author/committer identities. For an initial release, start a new Git history only after sanitization. A later cleanup commit does not remove earlier private blobs.

Finally, manually verify the exact GitHub owner, repository name, visibility, branch, committed tree, and intended public metadata. Do not push if any private match, unexplained file, test failure, tooling error, or unresolved privacy concern remains. Public visibility exposes the owner's GitHub account even when commits use an anonymous identity.

## Limits of the checker

The checker enforces a file manifest and detects selected credential, contact, path, IP, opaque-identifier, binary-content, and Git-metadata patterns. A `PASS` is not a complete privacy assessment or security audit. Names, narratives, encoded secrets, and indirect identifiers require human judgment. A newly introduced format or legitimate identifier may need a deliberate policy update and fresh review; do not suppress a warning merely to get a passing result.

No script in this project automatically uploads evidence or creates a public repository.
