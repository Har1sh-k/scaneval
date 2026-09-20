# Initial evaluation core

This alpha implements the first step in [the design's build order](DESIGN_DECISIONS.md#10-packaging-deliverables-and-build-order). It is not the completed benchmark and does not replace the legacy `scripts/` runner yet.

## What works

- Validate versioned scan requests, results, evaluation plans, and review decisions.
- Score one saved output against all assigned targets and controls for that input.
- Report full-output recall, first-hit ranks, native review-budget recall, exact duplicates, unresolved findings, and conditional control bounds.
- Replay the same saved records without models or network access.
- Generate a standalone HTML report.
- Emit opt-in TypeScript observer events at harness-owned boundaries. Actual scanner integration is the next step.

The core does not determine whether an arbitrary natural-language allegation establishes a root cause. That decision comes from a frozen evaluator-side review record. Replaying that record is deterministic; producing the underlying security label or a live model response is not made deterministic by this package.

## Try it

Requires Python 3.11 or later. Run from the repository:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
sastbench --version
sastbench demo results/diagnostic-demo
```

Open `results/diagnostic-demo/report.html`. The demo is the design's worked example, with fabricated source, findings, and review decisions. It makes no scanner or model calls and supplies no evidence about real-world detection performance.

Expected results:

| Observation | Result |
|---|---|
| Assigned targets | 2 on one input |
| First-hit ranks | T1 at 1, T2 at 5 |
| Recall at 3 claims | 50% |
| Recall at 5 claims and full output | 100% |
| Delivered claims | 5, including 1 exact duplicate |
| Unreviewed distinct claim | 1, not automatically a false positive |
| Capability-safe control | 1 false allegation, even though it ranks below 3 |
| Fixed-target control rate | N/A, none assigned |

All commands refuse to overwrite existing output files. `demo` requires a new directory.

## Bundle and replay

```text
diagnostic-demo/
  scan-input/app.py          source only
  request.json              sanitized invocation contract
  result.json               saved normalized output
  evaluator/plan.json        assigned targets, controls, budgets
  evaluator/decisions.json   frozen matching and control reviews
  evaluation.json           computed result and input-record hashes
  report.html               local report
  README.txt                fixture limitations
```

```sh
sastbench validate scan-request results/diagnostic-demo/request.json
sastbench validate scan-result results/diagnostic-demo/result.json
sastbench replay results/diagnostic-demo --output results/diagnostic-replay.json
sastbench report results/diagnostic-demo --output results/diagnostic-report.html

# The same evaluator also accepts separately stored records.
sastbench score \
  --plan results/diagnostic-demo/evaluator/plan.json \
  --result results/diagnostic-demo/result.json \
  --decisions results/diagnostic-demo/evaluator/decisions.json
```

The original `evaluation.json` and replay JSON are byte-identical for the same package version and saved inputs. Replay verifies IDs, input-hash agreement, and the review's canonical result hash. It records plan and decision hashes in its output. These hashes identify records; they do not authenticate their author or independently verify the source snapshot. The demo hashes a path/content map, not a production git export.

Replay reads `result.json` and `evaluator/` records. It does not execute `request.json`, inspect source, or replay tools. The directory layout illustrates the evaluator boundary but does not enforce access isolation. A real runner must expose only the prepared source and sanitized request to the scanner.

The library entry point is:

```python
from sastbench import evaluate

record = evaluate(plan, saved_result, frozen_decisions)
```

This is saved-record evaluation, not the future configuration-driven live runner.

## Contract rules enforced now

Schemas ship inside [`src/sastbench/schemas`](../src/sastbench/schemas). Strict parsing rejects duplicate JSON keys, nonfinite numbers, escaping file paths, missing IDs, and malformed references. Unknown extra fields are rejected so extensions need a contract change.

- **Scanner boundary:** `ScanRequest` cannot contain evaluator target IDs, regions, fixes, or matching decisions. This is a shape check, not automatic source sanitization.
- **Locations:** file-only reports stay file-only. A line range is optional; if supplied it must be positive and ordered. Location overlap alone never earns credit.
- **Claims:** one allegation and its evidence per normalized claim. Separately structured bundles must be split by an importer or reviewer before claiming an atomic count. This alpha does not implement native/SARIF import.
- **Duplicates:** canonicalize allegation, kind, native rule ID, primary/related locations, and evidence text. Normalize path separators and line endings. Ignore delivery IDs and ranks. Different evidence stays distinct; semantic duplicate review is not implemented yet.
- **Credit:** one claim or exact-duplicate group can hit at most one canonical target. Duplicate copies keep their review positions. Contradictory frozen decisions are rejected.
- **Ranking:** native ranks must be contiguous and follow the submitted array. Unranked output has no native budget score. Its optional random-order expectation is a separate diagnostic and can be affected by duplicate spam.
- **Bundles:** unresolved bundles leave atomic-claim burden and finite-budget metrics pending. Confirmed full-output hits can still count.
- **Execution:** `success`, `partial`, `unsupported`, `error`, and `timeout` remain distinct. Confirmed partial-output hits can count. Failed assignments remain in the denominator. Only successful, resolved, in-scope output can establish a quiet control.
- **Controls:** all claims are eligible for control review, including those below the review budget. Missing assessments remain unresolved. The completed-observation upper bound counts unresolved assessments as false allegations; it is not a confidence interval. `false_allegations` is its completed-only numerator. `observed_false_allegations` also retains explicit reviewed failures from incomplete output, without using incomplete scans in that rate.
- **Unknowns:** unmatched claims are not automatically false positives. This build does not estimate overall precision.
- **Labels:** `diagnostic` plans allow only fixture labels; `reviewed` plans require declared L3/L4 labels. Checking the field does not verify independent review. Evidence records and admission approval still need implementation.

Scores use equal target/control weights within one input. Do not average them as a release score: corpus weighting, repeated-run aggregation, repository clustering, and promotion gates are not implemented. Zero denominators are `null` in JSON and N/A in HTML.

## Observer SDK

See [the SDK guide](OBSERVER_SDK.md) and [event schema](../schema/v2/trace-event.schema.json).

The TypeScript emitter records supplied model/tool events, selected context, and finding lifecycle events: candidate, validation, filtering, and submission. It does not intercept a harness automatically, change its prompts, enforce networking, or inspect hidden reasoning. Recording is off by default. The harness owns its sink and retention policy.

Sink or other instrumentation errors create capture gaps without replacing the operation's result or exception. Missing events are not evidence that an operation did not happen. The HTML report currently shows scores, not a trace timeline.

```sh
cd sdk/typescript
npm ci
npm test
```

## Next implementation slice

1. Prepare a small reviewed case pack from the candidate shortlist, including exact vulnerable states and eligible controls. Add evidence records and an explicit admission decision; do not promote the shortlist automatically.
2. Build grouped-input materialization and isolation, then integrate the own-harness adapter and a pinned conventional scanner. Verify resolved model/tool/ruleset provenance and preserve raw output.
3. Connect SDK events at real model and tool boundaries, link finding lifecycle IDs to the final report, and test tracing-on/off parity.
4. Add multi-system/repetition planning, native output import, the private-pack intake path, corpus aggregation, and baseline/candidate comparison.

The Python core supports request language tags for Python, TypeScript/JavaScript, Go, and Rust. This does not imply equal corpus coverage or live support for every scanner. Inspect/Harbor selection, Jev corpus assistance, and the separate engineering improvement agent remain outside this initial slice.

Run the Python regression suite with `python -m pytest -q`. Legacy tests remain alongside the new contract, scoring, and CLI conformance tests. No real CVEs are silently imported and no paid model evaluations run during these tests.
