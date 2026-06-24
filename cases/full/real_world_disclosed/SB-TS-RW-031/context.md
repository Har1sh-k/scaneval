# SB-TS-RW-031: OpenClaw shell inline-command fallback skipped exec allowlist for single commands

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-f397-5vjw-v2c2`
- CVE: `CVE-2026-53866` (CWE-184 Incomplete List of Disallowed Inputs)
- Vulnerable commit: `9c7e67b0f8247dbd81b6610bc1bd9a1a4d4a1256` (release v2026.5.10-beta.1)
- Fix commit: `50f4440c96637f5d2c244f9a7b1119be378b15f3` ("Enforce inline shell wrapper payload matching", #80978)

## Scenario

OpenClaw lets an agent run commands through shell wrappers (e.g. `bash -c "<inline>"`). To keep the exec allowlist meaningful, the wrapper's inline payload must itself be evaluated against the allowlist rather than only the wrapper binary. `resolveInlineChainFallback` / `evaluateShellWrapperInlineChain` in `src/infra/exec-approvals-allowlist.ts` are responsible for that inline evaluation.

## Vulnerability

In the vulnerable snapshot (lines 524-560), both inline-evaluation helpers only proceed when the inline command parses as a **multi-part chain**:

```ts
const inlineChainParts = splitCommandChain(params.inlineCommand);
if (!inlineChainParts || inlineChainParts.length <= 1) {
  return null;
}
```

When `splitCommandChain` returns a single part (a single inline command, not a `&&`/`|` chain) the helper returns `null`, so the inline payload is never analyzed and never receives an allowlist decision. The caller treats the absence of a negative decision as "satisfied", so a single shell inline-command form bypasses the exec allowlist. The duplicate `<= 1` guard inside `evaluateShellWrapperInlineChain` has the same effect.

## Source / Carrier / Sink
- Source: model-/caller-controlled inline command supplied to a shell wrapper (`sh -c "<cmd>"`)
- Carrier: `resolveInlineChainFallback` / `evaluateShellWrapperInlineChain` return `null` for single inline commands, skipping allowlist evaluation
- Sink: the wrapper command is authorized and executed without the inline payload being checked against the allowlist
- Missing guard: the fix (`resolveInlineCommandFallback` + `evaluateShellWrapperInlineCommand`) evaluates single inline commands, not just multi-part chains, against the allowlist

## Scanner Expectation
A scanner should flag the inline-command fallback at lines 524-560 as an allowlist-bypass: an exec-control check whose `length <= 1` early-return omits the single-command case, allowing an unchecked inline command to reach execution.
