# SB-TS-RW-122: Git node Clone/Push source and target repository paths bypass N8N_RESTRICT_FILE_ACCESS_TO sandbox

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-5xp3-2w67-427v`
- CVE: `CVE-2026-49465`
- Vulnerable commit: `1c9511104e32ac492c1dfc3de6e44ce0aab4d5b2` (release n8n@2.22.3)
- Fix commit: `d4f9223842f0584579639647e047a0f4e78a2259` (release n8n@2.22.4)

## Vulnerability
Only the working-directory repositoryPath is checked against the file-access sandbox; the attacker-controlled sourceRepository (clone source) and targetRepository (push target) are passed to git.clone()/git.push() without any isFilePathBlocked validation, so a local path escapes N8N_RESTRICT_FILE_ACCESS_TO.

## Source / Carrier / Sink
- Source: User-supplied sourceRepository (Clone) / targetRepository (Push) parameters of the Git node workflow.
- Carrier: sourceRepository is read via getNodeParameter and passed through prepareRepository directly into git.clone(); the push target flows into git.push().
- Sink: git.clone(sourceRepository, '.') (and git.push(targetRepository)) which reads/writes the local git repository at the attacker-supplied path.
- Missing guard: No this.helpers.isFilePathBlocked / resolvePath sandbox validation of the clone source or push target repository reference (only repositoryPath is checked).

## Fix
The fix adds assertRepositoryReferenceAllowed(), which detects local-path / file:// repository references for both the clone source and the push target (including remote.origin.url/pushurl), resolves them, and throws a NodeOperationError when isFilePathBlocked returns true; it also clones with an explicit '--' separator and rejects hyphen-prefixed references.

## Scanner Expectation
Flag that a user-controlled repository path reaches a git clone/push filesystem sink without being validated against the N8N_RESTRICT_FILE_ACCESS_TO file-access sandbox.
