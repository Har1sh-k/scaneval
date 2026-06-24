# SB-TS-RW-051: OpenClaw exec wrapper trust plan treated side-effecting script/time wrappers as transparent

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-cwpp-5962-q4f6`
- CVE: `CVE-2026-53848`
- Vulnerable commit: `a374c3a5bfd5225ce319bce3865aab6216309c4f` (release v2026.5.22)
- Fix commit: `8e41c118fa80c186ac40676e87bfecf988101ecb` (release v2026.5.27)

## Vulnerability
The trust plan classifies `script` and `time` as fully transparent, so the allowlist decision is made solely on the unwrapped inner command and ignores side-effecting wrapper options (e.g. `script out.txt`, `time -o out.txt`). The wrapper still runs, so an allowed inner command can be used to carry an unreviewed file-writing wrapper invocation.

## Source / Carrier / Sink
- Source: Model-/caller-controlled command argv that prefixes an allowlisted inner command with a side-effecting wrapper such as `script` or `time -o`.
- Carrier: DISPATCH_WRAPPER_SPECS marks `script`/`time` transparentUsage: true, so resolveExecWrapperTrustPlan unwraps them and evaluates only the inner command against the allowlist.
- Sink: The wrapper command is authorized based on the inner command and spawned, executing the wrapper's file-writing side effects.
- Missing guard: No check that the transparent wrapper invocation lacks side-effecting options before treating it as transparent; side-effecting wrappers were not excluded from transparency.

## Fix
The fix removes the blanket transparency for these wrappers: `script` is changed to transparentUsage: false (no longer treated as transparent), and `time` becomes conditionally transparent via `(argv) => !timeInvocationWritesOutputFile(argv)`, where the new timeInvocationWritesOutputFile() detects `-o`/`--output` (and value-taking options), so a time invocation that writes an output file is no longer treated as a transparent wrapper and must be evaluated/approved on its own.

## Scanner Expectation
A scanner should flag the transparentUsage: true classification of side-effecting wrappers (script, time) as an exec-control bypass: a protection mechanism that unwraps a wrapper to the inner command while permitting unreviewed wrapper side effects to reach execution.
