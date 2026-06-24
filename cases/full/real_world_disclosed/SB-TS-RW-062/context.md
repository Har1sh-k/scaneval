# SB-TS-RW-062: OpenClaw movePathToTrash resolved 'trash' executable via workspace-influenced service PATH

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-rx78-29qr-5hq8`
- CVE: `CVE-2026-53865`
- Vulnerable commit: `cbc2ba0931468259f26a7c547131a06e03ca6c6c` (release v2026.4.27)
- Fix commit: `230f7122dd5cd8a37a55e671254bd9be8278f6e8` (release v2026.5.2)

## Vulnerability
The command was launched by name and resolved through a PATH that could include workspace-derived directories, so the executable selected for "trash" was attacker-influenceable. Combined with service PATH entries built from workspace env vars, this let a lower-trust workspace control which binary ran during a privileged maintenance flow.

## Source / Carrier / Sink
- Source: Workspace-derived environment values feeding the service PATH (e.g. PNPM_HOME, NPM_CONFIG_PREFIX, BUN_INSTALL, VOLTA_HOME, NVM_DIR, FNM_DIR, NIX_PROFILES resolved in src/daemon/service-env.ts).
- Carrier: The process PATH used when spawning the child; the bare command name "trash" passed to runExec without an absolute path.
- Sink: runExec("trash", [targetPath], { timeoutMs: 10_000 }) executing whichever 'trash' executable PATH resolves to.
- Missing guard: No use of a fixed/absolute trusted path for the trash executable and no exclusion of workspace-derived directories from the service PATH; the command was resolved by name from an attacker-influenceable PATH.

## Fix
The fix removes the external trash helper entirely from movePathToTrash: it no longer calls runExec("trash", ...) and instead performs the trash operation with internal filesystem primitives (validated allowed roots under home/tmp, a contained ~/.Trash destination, realpath checks and atomic rename/copy), eliminating any PATH-based command resolution. Separately, service-env.ts was hardened to drop workspace-derived directories from the service PATH.

## Scanner Expectation
Flag execution of an external command by bare name resolved through an attacker-influenceable PATH (untrusted search path, CWE-426): the 'trash' binary selection can be controlled by workspace-derived PATH entries, enabling arbitrary local command execution during maintenance.
