# Promotion gate decisions

`scaneval gate` holds one saved comparison of a candidate against a baseline to a gate policy and writes a decision. It follows [design section 8](DESIGN_DECISIONS.md#8-repetitions-uncertainty-and-feedback-for-harness-improvement): ScanEval returns a decision and its evidence, and the workflow that owns the harness owns any promotion. The requirements are the constraints of [evaluation math](EVALUATION_MATH.md) sections 1 to 4, kept separate: detection, precision, control false alarms, completion, review burden, and cost. There is no composite score, so recall cannot compensate for noise. The command reads three kinds of document, runs no scan, and calls no model or judge.

```sh
scaneval compare results/run-a --baseline semgrep-pinned --candidate semgrep-new --output results/compare.json
scaneval gate --policy my-policy.json --comparison results/compare.json \
    --precision-candidate results/precision-candidate.json --output results/gate.json
```

Exit `0` is a pass, `1` is a fail or an inconclusive decision, and `2` means the command could not evaluate: a document that is not what it is named, a refused policy, or an unwritable output. The decision is written for a fail or inconclusive outcome too. Stdout names every failed and every unresolved requirement with its reason, then notes the blocks the policy left out and any estimate it was given and did not read. The output is create-only and refused inside a trial or a run directory.

## The policy

A `gate-policy` states every threshold and is frozen before any result is read. [`examples/gate-policy.json`](../examples/gate-policy.json) holds example values only, never recommended tolerances. Nothing in the schema or the code supplies a default threshold. A policy always declares:

- its `view`, one (mode, profile) pair of the comparison, because views are never pooled;
- the `primary` metric, full-output recall or recall@B in one weighting and slice, and the `min_improvement` it must make. A random-order expectation or any other diagnostic is refused when the policy is loaded;
- `configuration.allowed_differences`, the dotted keys the comparison is meant to measure.

Every other block (`regressions`, `precision`, `controls`, `completion`, `target_coverage`, `burden`, `cost`) is a requirement the policy makes only by writing it, and a block that is written must carry all of its tolerances. The decision lists which blocks were declared and which were not, and evaluates only the declared ones. `required_scope` is `reviewed` unless the policy says `draft`; the decision records the completed policy.

## How outcomes combine

A requirement reports `{id, status, observed, threshold, explanation}` and is `pass`, `fail`, or `inconclusive`. The outcome is `fail` if any requirement fails, else `inconclusive` if any is inconclusive, else `pass`. No requirement is weighed against another.

A requirement **fails** when the recorded figures show it is not met. It is **inconclusive** when what it needs is missing or cannot be trusted: an unavailable or unmeasurable metric, no eligible control, no precision estimate, an unknown cost, an interval that is not `ok`, an unfinished run, or evidence below the required scope. An absent figure is never a perfect one.

## Requirements

Each id below is one requirement in the decision.

| Id | What it checks | Not met |
|---|---|---|
| `contract.shared` | The comparison's own records again: both systems were assigned the same frozen work (assignments, inputs, canonical targets and controls, clusters, target observations, and pairs agree in every view), the runs it names exist and froze one pack, and its aggregation policy matches its digest. `compare` refuses systems that differ, so this catches a document edited afterward. | fail |
| `contract.runs_completed` | Every compared run finished; an unfinished run's missing assignments stand as failures. | inconclusive |
| `configuration.allowed_differences` | Every configuration difference is an allowed key or beneath one; anything else means the comparison does not isolate the intended change. | inconclusive |
| `evidence.scope` | Both systems' evidence in the view is at least the required scope. Draft or diagnostic evidence supports no reviewed recommendation. A policy that itself declares `draft` accepts draft or reviewed evidence and yields a `development` decision. Diagnostic fixtures meet neither. | inconclusive |
| `primary.improvement` | Candidate minus baseline of the metric is at least `min_improvement`. recall@B needs a native position: unranked output or unresolved bundles make it unmeasurable, and a random-order expectation is never substituted. | fail; inconclusive if unavailable |
| `primary.uncertainty` | The paired interval's lower bound is above `lower_bound_above` at the comparison's confidence, and optionally `min_confidence` and `min_clusters` hold. Optional. | fail if the interval lies at or below the bound; inconclusive if it straddles it, is not `ok`, or is too weak |
| `regression.<id>` | The metric does not fall by more than `max_decrease` in the whole view, a named project or workload, or each project or workload. With `check_interval` the interval's lower bound must also stay within it. | fail; inconclusive if unavailable |
| `precision.binding` | The candidate's estimate covers only the candidate, the policy's view and declared population, and runs of this comparison, with the same manifest and schedule digests, including every run the candidate was scheduled in. A first-B estimate must also leave no invocation out: an unranked or bundle-unresolved invocation has no measured position, falls outside that population, and would hide its noise from the estimate. | inconclusive |
| `precision.min_value` | Resolved precision, or the sensitivity lower bound that counts every unresolved claim as false, is at least `min_value`. | fail |
| `precision.max_unresolved_share`, `min_evidence_grade`, `min_coverage` | The unresolved share is at most the maximum, the review grade at least the minimum (an incomplete review never meets one), and the sampled strata hold at least `min_coverage` of the population. | inconclusive |
| `precision.interval` | For resolved precision, the estimate's approximate interval has its lower bound at least `min_interval_lower_bound`. | fail if wholly below; inconclusive otherwise |
| `precision.max_decrease` | The basis figure fell from the baseline's own estimate by at most the limit. Needs a bound baseline estimate. | fail; inconclusive if either is missing |
| `controls.<class>.false_alarm_upper` | The class's F+ (unresolved assessments counted as false allegations) is at most `max_false_alarm_upper`. | fail; inconclusive with no eligible or completed control |
| `controls.<class>.completed_mass`, `assessable_mass` | The completed and the resolved control mass reach their minimums. Failed and unresolved controls are not quiet ones. | inconclusive |
| `completion.min`, `max_decrease` | The share of assigned inputs the candidate completes, with every failure in the denominator, is at least the minimum and fell from the baseline's by at most the limit. | fail |
| `target_coverage.min_assessable_mass` | The assessable target mass of **both** systems reaches the minimum, because a baseline whose matches were never resolved earns no credit and would flatter any candidate. | inconclusive |
| `burden.claims_per_assignment`, `duplicate_share`, `increase_ratio` | Claim records per assignment over every assignment of the view, the share of records that are exact duplicates of another record of the same scan, and the ratio of the candidate's volume to the baseline's are within their maximums. A baseline of zero has no ratio: any increase from nothing fails. | fail; inconclusive with no result bundle |
| `cost.coverage` | The share of executed scans whose cost is known is at least `min_coverage` (every cost, when the policy states none), for the candidate and, with a ratio, the baseline. | inconclusive |
| `cost.per_assignment`, `increase_ratio` | The mean recorded cost per executed scan, over scans whose cost is known, is within the cap and within the ratio of the baseline's. | fail |

Comparisons are between the figures the comparison and estimates recorded and the policy's thresholds as written, with no tolerance of their own: a figure that equals its threshold meets it. A figure the gate derives itself (a share, a ratio, a mean cost, or the difference of two recorded precisions) is computed exactly from the decimals recorded, so binary floating point never moves it across a threshold it equals on paper.

## What the decision binds

The decision embeds its policy and records, by canonical digest, the policy, the comparison, each precision estimate that was supplied, the evaluator version, and the manifest, schedule, and evidence digests of every run the comparison read. The same inputs give the same document byte for byte: nothing here reads a clock, the network, a path, or an unseeded random source. A `gate-decision` refuses one whose outcome does not follow from its requirements, that drops a requirement its policy declares, or whose policy no longer matches its digest.

`recommendation_scope` says what the decision can support: `reviewed` when the policy requires reviewed evidence and the evidence was reviewed, `development` when the policy declares `draft` and the evidence met it, and `none` when the evidence did not meet the policy's scope, whatever the outcome says.

## What it does not do

- It promotes nothing, edits no harness, and deploys nothing. A `pass` says every declared requirement held on this comparison, not that the requirements were well chosen.
- It recomputes nothing from run directories. It is exactly as trustworthy as the comparison and estimates it names, and hashes identify documents without authenticating an author or showing that a reviewer read anything.
- It does not read pair correctness, mixed-intent correctness, or freshness, and it never reads a diagnostic as a metric.
- An interval describes resampling of the projects or families observed. It does not show the corpus represents other software.
