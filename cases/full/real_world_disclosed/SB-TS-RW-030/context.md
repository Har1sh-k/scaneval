# SB-TS-RW-030: OpenClaw exec allowlist skipped argPattern on Linux/macOS

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-v2ww-5rh7-2h5v`
- CVE: `CVE-2026-53853` (CWE-693 Protection Mechanism Failure, CWE-863 Incorrect Authorization)
- Vulnerable commit: `eeef4864494f859838fec1586bedbab1f8fa5702` (release v2026.5.7)
- Fix commit: `d583013b8f961f5cb609c72264d3c680f08a1d2f` (release v2026.5.12, "fix(exec): enforce allowlist argument patterns")

## Scenario

OpenClaw is an agentic assistant that can execute external commands on behalf of a model. When `tools.exec.security` is set to `allowlist`, each allowlist entry may carry an optional `argPattern` that constrains which arguments are permitted for an otherwise-allowlisted executable, so an operator can (for example) permit `git status` but not arbitrary `git` invocations.

## Vulnerability

In `matchAllowlist()` (lines 362-384 of `src/infra/exec-command-resolution.ts`), `argPattern` enforcement is gated on the platform:

```ts
const effectivePlatform = platform ?? process.platform;
const useArgPattern = normalizeLowercaseStringOrEmpty(effectivePlatform).startsWith("win");
...
for (const entry of entries) {
  ...
  if (!patternMatches) { continue; }
  if (!useArgPattern) {
    // Non-Windows: first path match wins (legacy behaviour).
    return entry;
  }
```

On Linux and macOS, `useArgPattern` is `false`, so the loop returns the first allowlist entry whose executable **path** matches and never evaluates the configured `argPattern`. The argv restriction the operator believes is in effect is silently skipped, allowing disallowed arguments for an allowlisted executable to run without an approval prompt.

## Source / Carrier / Sink
- Source: model-/caller-controlled argv for an allowlisted executable
- Carrier: `matchAllowlist()` returns a path-only match on non-Windows because `useArgPattern` is gated to Windows, bypassing the `argPattern` check
- Sink: the exec allowlist authorizes the command and it is spawned without an approval prompt
- Missing guard: `argPattern` argv matching must run on all platforms (the fix removes the Windows-only `useArgPattern` gate and the non-Windows early `return entry`)

## Scanner Expectation
A scanner should flag the platform-gated allowlist enforcement at lines 362-384 as an authorization/exec-control bypass: a protection mechanism (`argPattern`) that is conditionally skipped on Linux/macOS, allowing argv outside the configured pattern to reach command execution.
