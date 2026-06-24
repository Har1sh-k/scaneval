# SB-TS-RW-043: Plugin setup resolver falls back to process.cwd(), loading attacker-controlled setup-api.js (RCE)

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-r39h-4c2p-3jxp`
- CVE: `CVE-2026-45004`
- Vulnerable commit: `00bd2cf7a376f1fba26291c6c4766f1f15cbdfa5` (release v2026.4.22)
- Fix commit: `993781e6e6eaf50f033cfc3e3bf4f47059740707` (release v2026.4.23)

## Vulnerability
process.cwd() is an untrusted location when OpenClaw is run inside an arbitrary repository, yet it was treated as a trusted search root for bundled plugin setup fallbacks. Because the resolved path is passed straight into the jiti module loader (getJiti(setupSource)(setupSource)), a workspace-local setup-api.js is required/executed during ordinary provider/model status resolution.

## Source / Carrier / Sink
- Source: An attacker-controlled directory (repository/workspace) containing extensions/<plugin>/setup-api.js, with the victim running an OpenClaw command from that directory.
- Carrier: resolveSetupApiPath returning a process.cwd()-relative setup-api path, which becomes setupSource in resolveSetupRegistration.
- Sink: getJiti(setupSource)(setupSource) in resolveSetupRegistration (src/plugins/setup-registry.ts line 285), which loads and executes the resolved JavaScript module.
- Missing guard: No restriction of the setup-api fallback search to a trusted root; process.cwd() is included as a trusted candidate so untrusted code is loaded.

## Fix
The fix removes process.cwd() from repoRootCandidates, leaving only the canonical package/repository root (path.resolve(path.dirname(CURRENT_MODULE_PATH), "..", "..")). A regression test verifies that a workspace-local extensions/<plugin>/setup-api.js is no longer loaded through provider setup resolution.

## Scanner Expectation
Flag that a code/module path derived from process.cwd() (untrusted current directory) flows into a dynamic module loader/require/eval-equivalent, enabling code injection / arbitrary code execution.
