# SB-TS-RW-057: Workspace .env STATE_DIRECTORY not blocked, influencing bundled runtime dependency roots

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-wc84-j36w-pw4x`
- CVE: `CVE-2026-53858`
- Vulnerable commit: `a448042c2edd94a4e8ee86d5ed90a5ed9fe8e4cd` (release v2026.4.29)
- Fix commit: `42dfc36da50ad81c3fb2fef64e7849e6bbda8283` (release v2026.5.2)

## Vulnerability
The workspace-.env key blocklist is an incomplete denylist (CWE-184): STATE_DIRECTORY is a value that participates in runtime state/dependency-root resolution but was omitted from BLOCKED_WORKSPACE_DOTENV_KEYS, so shouldBlockWorkspaceDotEnvKey() returns false for it and the untrusted workspace value is applied to the process environment. Because dependency roots are then resolved relative to that state path, an attacker-influenced .env can point the runtime at an unintended local path.

## Source / Carrier / Sink
- Source: STATE_DIRECTORY assignment in an untrusted workspace .env file
- Carrier: dotenv parsing flows the key through shouldBlockWorkspaceDotEnvKey(), which consults the incomplete BLOCKED_WORKSPACE_DOTENV_KEYS denylist and allows STATE_DIRECTORY through into process.env
- Sink: bundled runtime dependency root resolution that reads STATE_DIRECTORY to choose the local state/dependency path
- Missing guard: STATE_DIRECTORY missing from the workspace-.env blocklist; the guard should treat it as a reserved runtime key and reject it from untrusted workspace .env

## Fix
The fix adds the string "STATE_DIRECTORY" to the BLOCKED_WORKSPACE_DOTENV_KEYS set so the same guard now rejects it from untrusted workspace .env files. The key is reserved for the trusted global/shell config surface, keeping runtime dependency-root resolution fail-closed against workspace input.

## Scanner Expectation
Flag the workspace-.env key gate at lines 111-119 (and its incomplete BLOCKED_WORKSPACE_DOTENV_KEYS denylist) as failing to block STATE_DIRECTORY, allowing untrusted env input to influence runtime dependency-root resolution.
