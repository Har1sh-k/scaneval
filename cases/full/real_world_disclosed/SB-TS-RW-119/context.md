# SB-TS-RW-119: n8n Git node argument injection via pathsToAdd enables arbitrary file read

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-57g9-58c2-xjg3`
- CVE: `CVE-2026-44790`
- Vulnerable commit: `6d67db4449db7ab8a5f8d413461ffc46f57d50bb` (release n8n@1.123.0)
- Fix commit: `503f29901c568d15778e5e853e804b6e5a7a96db` (release n8n@1.123.43)

## Vulnerability
User-controlled strings from the pathsToAdd parameter are split and spread directly into the git CLI argument vector, so leading-dash tokens are interpreted as git options rather than literal paths. With no '--' separator and no validation, attacker-supplied flags change git's behavior and allow reading files outside the intended repository scope.

## Source / Carrier / Sink
- Source: Authenticated workflow author's 'pathsToAdd' node parameter (getNodeParameter('pathsToAdd', ...)).
- Carrier: pathsToAdd.split(',') array passed as argv to simple-git.
- Sink: git.add(pathsToAdd.split(',')) which invokes the git CLI with attacker-controlled arguments.
- Missing guard: No '--' end-of-options separator and no validation/trimming, so dash-prefixed tokens are interpreted as git flags (argument injection).

## Fix
The fix trims and filters the split paths and prepends a '--' end-of-options separator before passing them to git.add (and git.commit), so all subsequent tokens are treated strictly as pathspecs and cannot be interpreted as command-line flags. It also corrects a reflog reference validation bug that validated the wrong variable.

## Scanner Expectation
Flag the user-controlled pathsToAdd flowing into git.add() argv as command/argument injection (CWE-88) on the OS command (git) invocation.
