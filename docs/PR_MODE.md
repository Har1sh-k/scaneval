# PR Mode

SASTbench supports a second execution mode for benchmarked pull request simulation:

```bash
python scripts/run.py --scanner semgrep --mode pr --track core
```

PR mode compares a clean base tree with a vulnerable head tree and asks a different question than normal benchmark mode:

- normal benchmark mode: can the scanner find the vulnerable region in a known vulnerable snapshot?
- PR mode: would the scanner have reported the vulnerability as part of reviewing the change that introduced it?

This mode is meant to approximate a security review workflow, not just a whole-repo scan.

## What PR Mode Does

For each PR-capable case, SASTbench:

1. Materializes a clean base tree and a vulnerable head tree.
2. Computes the changed files and a unified diff.
3. Runs the scanner against both trees.
4. Produces review findings that represent what is new in head compared with base.
5. Scores whether those review findings hit the introduced vulnerable region.

The output is review-oriented:

- `INTRODUCED VULN DETECTED`
- `INTRODUCED VULN MISSED`
- `PARTIAL DETECTION`
- `SKIP`

## Current Scope

Current PR mode is benchmark PR simulation only.

It works on SASTbench cases that satisfy both conditions:

- the case has `prSimulation` metadata
- the case has non-empty `expectedOutcome.mustDetectRegionIds`

This means:

- `synthetic_vulnerable`, `mixed_intent`, and selected `real_world_disclosed` cases can participate
- `capability_safe` cases are excluded from PR mode because they do not model a vulnerability-introducing change

If a case has `prSimulation` but no `mustDetectRegionIds`, the runner skips it before scanning.

## How Base And Head Are Built

PR mode currently supports two case-level strategies.

### `vendored_base`

Used mostly for Core Track cases.

- `case.json` includes:

```json
"prSimulation": {
  "mode": "vendored_base",
  "baseRoot": "pr/base"
}
```

- the clean baseline lives in `pr/base/`
- the vulnerable head lives in the normal `files.root` tree, usually `project/`

At runtime, SASTbench copies both trees into a temporary directory and scans those temp copies symmetrically.

### `git_commit_pair`

Used for selected Full Track real-world cases.

- `case.json` includes:

```json
"prSimulation": {
  "mode": "git_commit_pair",
  "baseCommit": "<clean commit sha>",
  "headCommit": "<optional vulnerable commit sha>"
}
```

- `baseCommit` is required
- `headCommit` is optional and defaults to `realWorld.vulnerableCommit`

SASTbench uses `git archive` against the pinned repo snapshot to materialize both commits into temporary directories before scanning.

## Adapter Behavior

PR mode prefers native PR-aware adapters when available.

### Native PR scan

If an adapter implements `scan_pr_with_metadata(...)`, SASTbench passes:

- `base_root`
- `head_root`
- `changed_files`
- `diff_text`
- `language`
- `case`

This gives agent-style scanners the same inputs a human PR reviewer would inspect.

### Fallback dual-scan mode

If an adapter does not implement native PR support, or native PR mode fails, SASTbench falls back to:

1. scan base tree
2. scan head tree
3. synthesize review findings as findings that are new in head

The fallback matcher is conservative:

- same normalized path
- same `mappedKind`
- same `ruleId` when available, preferred
- overlapping lines, or near-overlap within a small threshold

## Metrics

PR mode does not use the normal benchmark summary as the main story.

Instead it reports:

- **Introduced Target Hit Rate**
  - aggregate rate at which review findings hit the required introduced region(s)
- **Review Noise**
  - review findings that did not match an introduced target
- **Capability Noise**
  - review findings that hit a capability-safe region
- **Cases Evaluated**
  - PR-capable cases that actually ran
- **Cases Skipped**
  - PR-capable cases that could not be evaluated, for example because the scanner does not support the language

The top-level `summary` block still exists in the JSON for compatibility, but PR mode treats the dedicated `prSummary` block as authoritative.

## CLI Examples

Run PR mode on all PR-capable Core cases:

```bash
python scripts/run.py --scanner semgrep --mode pr --track core
```

Run a single PR-capable case:

```bash
python scripts/run.py --scanner bandit --mode pr --track core --case-id SB-PY-SV-001
```

Run with the deep audit trail:

```bash
python scripts/run.py --scanner semgrep --mode pr --track core --verbose
```

Generate an HTML report from a PR-mode results file:

```bash
python scripts/report.py results/<pr-results>.json
python scripts/report.py results/<pr-results>.json --verbose
```

## Result JSON Shape

PR mode writes `mode: "pr"` in the results file and adds PR-specific fields.

At the case level:

- `prContext.changedFiles`
- `prContext.baselineFindings`
- `prContext.headFindings`
- `prContext.reviewFindings`
- `prScoring.introducedTargetsDetected`
- `prScoring.introducedTargetsTotal`
- `prScoring.introducedTargetHitRate`
- `prScoring.reviewNoise`
- `prScoring.capabilityNoise`

At the run level:

- `prSummary.introducedTargetHitRate`
- `prSummary.totalReviewNoise`
- `prSummary.totalCapabilityNoise`
- `prSummary.casesEvaluated`
- `prSummary.casesSkipped`

See [schema/results.schema.json](../schema/results.schema.json) for the full schema.

## Making A Case PR-Capable

To participate in PR mode, a case must:

1. already be a valid SASTbench case
2. include `prSimulation`
3. have at least one region in `expectedOutcome.mustDetectRegionIds`

For Core cases:

- add a clean baseline under `pr/base/`
- keep the vulnerable tree under the normal `files.root`

For Full Track real-world cases:

- add `prSimulation.mode = "git_commit_pair"`
- choose an explicit clean `baseCommit`
- rely on the vulnerable snapshot as head, or set `headCommit` explicitly

## Mixed-Intent Cases In PR Mode

Mixed-intent cases are especially useful in PR mode.

They let SASTbench ask both questions at once:

- did the scanner report the newly introduced vulnerable region?
- did it avoid flagging nearby capability-safe code that already existed or remained properly guarded?

That is why `Capability Noise` remains a first-class PR metric.

## PR Pair Verification vs Remediation Verification

PR simulation runtime and remediation verification are separate concerns.

### PR runtime

PR mode uses only `baseCommit` and `headCommit`. It does not read `fixCommit` or `fixValidation` at scan time. The runtime question is: *would the scanner have flagged the vulnerability in a PR introducing it?*

### Remediation verification

`fixCommit` is advisory metadata recording which commit addressed the vulnerability. It is used for dataset integrity checks, not PR-mode scoring.

`fixValidation` controls how `scripts/verify_pr_strict.py` verifies that `fixCommit` actually addresses the vulnerability:

- `slice_absent` (default): the exact annotated vulnerable slice must not appear in the file at `fixCommit`. This covers the common case where the fix rewrites the vulnerable code.
- `mitigation_anchor_present`: the fix applies defense at a different code location than the annotated sink (e.g. CORS restriction, config hardening, caller-side validation). The verifier checks that declared anchor strings are present at `fixCommit` but absent at `vulnerableCommit`, and that the fix diff touches the anchor files.

Example `fixValidation` for an indirect mitigation:

```json
"fixValidation": {
  "mode": "mitigation_anchor_present",
  "anchors": [
    {
      "path": "src/server.ts",
      "mustContainAll": ["cors({", "origin(input)", "localhost"]
    }
  ]
}
```

### Verifier

Run the strict verifier to check all real-world PR simulation metadata:

```bash
python scripts/verify_pr_strict.py
```

Output reports two numbers:

- **Fix removes detection slice**: direct slice-removal pass count
- **Remediation verified**: overall count including indirect mitigations

## Current Limitations

- PR mode currently operates on benchmark cases, not arbitrary external repos.
- Cases without `mustDetectRegionIds` are intentionally excluded.
- Unsupported-language scanners still produce skipped PR cases.
- Full Track PR mode depends on the required `.repos/` snapshots being present locally.
- The top-level compatibility `summary` fields are retained, but PR consumers should read `prSummary` first.

## Related Files

- [scripts/run.py](../scripts/run.py)
- [scripts/pr_runner.py](../scripts/pr_runner.py)
- [scripts/pr_scoring.py](../scripts/pr_scoring.py)
- [scripts/report.py](../scripts/report.py)
- [schema/case.schema.json](../schema/case.schema.json)
- [schema/results.schema.json](../schema/results.schema.json)
- [scripts/verify_pr_strict.py](../scripts/verify_pr_strict.py)
