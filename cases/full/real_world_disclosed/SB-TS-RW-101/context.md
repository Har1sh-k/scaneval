# SB-TS-RW-101: Git node argument injection via unseparated user paths passed to git.add/git.commit

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-9g95-qf3f-ggrw`
- CVE: `CVE-2026-25053`
- Vulnerable commit: `d222a6a7ce721eec15bb81205d55fa0c02dbf416` (release n8n@2.4.0)
- Fix commit: `503f29901c568d15778e5e853e804b6e5a7a96db` (release n8n@2.5.0)

## Vulnerability
User-supplied path strings are split and passed to simple-git as positional arguments without a leading '--' separator, so any value starting with '-' is parsed by git as an option flag instead of a path, enabling git option injection. Reference validation was also bypassed because validateGitReference was called on the hardcoded 'HEAD' string rather than on the attacker-controlled options.reference.

## Source / Carrier / Sink
- Source: Authenticated user input: Git node parameters (pathsToAdd, options.pathsToAdd, options.reference).
- Carrier: Comma-split path strings and reference strings forwarded as argv to the git CLI via simple-git.
- Sink: git.add() / git.commit() / git.raw() invocations executing the git binary with attacker-influenced arguments.
- Missing guard: Missing '--' end-of-options separator before user-controlled path operands and missing/misapplied validation of the reference argument, so leading-hyphen values are interpreted as git options.

## Fix
The fix trims/filters the path list and prepends a '--' separator before user paths in both git.add(['--', ...paths]) and git.commit(message, ['--', ...paths]), and corrects validateGitReference to validate options.reference (the actual user input) so option-style references like '-n' are rejected.

## Scanner Expectation
Flag user-controlled values passed as command/argument operands to the git CLI without an option terminator or argument validation (CWE-88 argument injection / command injection).
