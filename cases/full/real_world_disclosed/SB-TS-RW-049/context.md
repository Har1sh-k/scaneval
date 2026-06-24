# SB-TS-RW-049: OpenClaw bundled runtime dependency installer trusted npm_execpath from workspace .env

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-24vr-rprv-67rf`
- CVE: `CVE-2026-53846`
- Vulnerable commit: `cbc2ba0931468259f26a7c547131a06e03ca6c6c` (release v2026.4.27)
- Fix commit: `ccb3af556fcb1618f30e94bdd55f77cec07c45a0` (release v2026.4.29)

## Vulnerability
The installer treats env.npm_execpath as a trusted source of the npm CLI path even though that environment variable can be populated from a workspace .env file, which is lower-trust input that crosses into the install execution path. The dotenv blocklist (BLOCKED_WORKSPACE_DOTENV_KEYS in src/infra/dotenv.ts) did not include NPM_EXECPATH, so a workspace .env value flowed into env.npm_execpath and then into the spawned command.

## Source / Carrier / Sink
- Source: Workspace .env file (lower-trust repository content) supplying npm_execpath into the process environment.
- Carrier: env.npm_execpath is read in resolveBundledRuntimeDepsNpmRunner and, after a permissive isNpmCliPath shape check, placed first in npmCliCandidates.
- Sink: The chosen npmCliPath is spawned via the node execPath to run `npm install` for bundled runtime dependencies (command execution).
- Missing guard: No allowlist/blocklist preventing npm_execpath from a workspace .env reaching the installer; NPM_EXECPATH absent from the dotenv blocklist and no rejection of attacker-controlled execpath.

## Fix
The fix stops trusting env.npm_execpath entirely: resolveBundledRuntimeDepsNpmRunner no longer reads npm_execpath or includes it in npmCliCandidates and instead resolves npm only from the node install directory (throwing if no safe npm executable is found), and createBundledRuntimeDepsInstallEnv strips any npm_execpath key from the install env. NPM_EXECPATH was also added to BLOCKED_WORKSPACE_DOTENV_KEYS so a workspace .env can no longer set it.

## Scanner Expectation
A scanner should flag the use of an environment-variable-derived executable path (env.npm_execpath) as the spawned package-manager binary, where the env value can originate from workspace .env input, as untrusted-input-to-command-execution.
