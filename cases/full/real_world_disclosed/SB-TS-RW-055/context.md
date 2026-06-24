# SB-TS-RW-055: OpenClaw strict inline-eval approval gate sequenced after the allowlist allow decision, letting shell positional carriers reach exec

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-5cj2-3jr2-5h77`
- CVE: `CVE-2026-53855`
- Vulnerable commit: `da64a978e5814567f7797cc34fbe29b61b7eae7a` (release v2026.4.1)
- Fix commit: `3e452f267139ae26c91766d23f619a1a89e18fcc` (release v2026.4.2)

## Vulnerability
The strict inline-eval approval requirement was coupled to and ordered behind the allowlist allow decision instead of being an independent fail-closed boundary. When the allowlist marked a positional-carrier command as allowed, the strict inline-eval gate could be bypassed, so shell positional parameters weakened the strict inline-eval check.

## Source / Carrier / Sink
- Source: Agent/tool-issued system_run command request combining allowlisted tools with shell positional arguments that carry inline-eval content (e.g. interpreter -c via positional/shell carrier).
- Carrier: parsed.execution segments / shellPayload feeding evaluateSystemRunPolicyPhase; inlineEvalHit (detectInterpreterInlineEvalArgv over segment argv) and policy.allowed from the allowlist evaluator.
- Sink: The approved-execution path after evaluateSystemRunPolicyPhase returns non-null (system run dispatch) when the strict inline-eval approval boundary did not fire.
- Missing guard: An independent, ordering-correct strict inline-eval approval requirement that triggers whenever an inline-eval hit is present and not approved-by-ask, even when the allowlist marks the command as allowed.

## Fix
Fix commit 3e452f26 reorders and decouples the gate: it computes strictInlineEvalRequiresApproval = inlineEvalHit !== null && !policy.approvedByAsk && (policy.allowed ? true : policy.eventReason !== 'security=deny') and denies with 'approval-required' before the generic !policy.allowed branch, so any inline-eval hit requires explicit approval regardless of the allowlist allow result (except hard security denies). It also stops persisting interpreter executables without an argv binding in allow-always collection.

## Scanner Expectation
Flag the policy-phase block where the inline-eval approval check is sequenced behind the allowlist allow decision, allowing a positional/shell-carrier inline-eval to run under strictInlineEval mode without explicit approval (CWE-184 incomplete check / command execution).
