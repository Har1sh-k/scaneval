# Corpus aggregation and comparison

`scaneval aggregate` turns saved run directories into corpus metrics. `scaneval compare` sets a candidate system against a baseline that was assigned exactly the same frozen work. Both read the records a run already wrote. They run no scanner, call no model or judge, and write one new JSON report each. The formulas are sections 1, 2, 4, and 5 of [the evaluation math](EVALUATION_MATH.md); this page states what the implementation computes.

```sh
scaneval aggregate results/run-a results/run-b --output results/aggregate.json
scaneval compare results/run-a --baseline semgrep-pinned --candidate semgrep-new --output results/compare.json
```

Both accept `--policy FILE`, an `aggregation-policy` document. Without it they use the built-in default. The report records the complete policy and its hash either way. [`examples/aggregation-policy.json`](../examples/aggregation-policy.json) holds example values only. Exit code `0` means the report was computed, whatever it says. `2` means the command refused. Failed assignments and draft evidence are recorded in the report, not turned into an exit code.

## What is read

A run directory is read through its 2.1 run manifest, the `evaluator/schedule.json` it names, and `run-config.json`. They must bind to each other by run id and configuration hash. Aggregation refuses:

- a run with a 2.0 manifest, which predates frozen schedules;
- a schedule or configuration that does not bind to its manifest, or a manifest that records an invocation its schedule never assigned;
- one run given twice, or runs whose schedules froze different packs;
- one system id configured two ways across runs, or recorded there with two adapters or adapter versions (see **Systems** below);
- a canonical target or control planned under two projects, workloads, or families;
- a view mixing diagnostic fixtures with any other evidence.

Every assignment in a schedule is one observation. A bundle is read through `scoring.observe`, which checks the plan, result, and decisions bindings, and `review status`. An assignment with no usable bundle is a failure with a reason: `failed_preparation`, `skipped_system`, `skipped`, `missing_row`, `missing_bundle`, or `unusable_bundle`. A failure detects nothing, completes nothing, and stays in every denominator. A failure whose manifest row names a bundle (`missing_bundle` or `unusable_bundle`) ran: its claim volume, wall time, and cost are unknown, not zero, so it counts as an executed scan in the `claims` and `usage` blocks and adds to no sum there.

An input is scored on the targets and controls its schedule froze before the run. An item frozen there but absent from the bundle's plan is scored as a miss and counted as `unscored`: a target is not detected, and a control on a scan that completed is a completed observation with no resolved assessment, so it stays in `C` and counts as unresolved in the false-alarm bound. An item the bundle's plan adds is ignored and counted as `unregistered`. An input whose schedule froze no plan is listed under `inputs_without_frozen_plan`. It takes no part in target or control metrics; its assignments still count toward completion, claims, and usage.

**Alias records.** An input may freeze several records of one canonical target or control, such as a CVE record and a GHSA record of one root cause. They are one item, and it is `unscored` when any of its records is absent from the bundle's plan, not only when all are. The records that are present still count for what they establish: a hit on any of them detects the target, and a confirmed false allegation on any of them is a false allegation on the control, whatever an absent record would have said. Nothing stands in for a record that was never assessed:

- A control is resolved quiet only when every one of its records is in the plan and assessed quiet. Quiet assessments of the others leave it unresolved, so on a completed scan it is in `C`, not in `A`, and counted as unresolved in the false-alarm bound.
- A target with a record absent, every record of it included, is treated as under a pending match: its accepted claims are only a lower bound, so it takes no random-order expectation and, on valid unranked output, counts in `pending_mass`. When no present record detected it, the miss is not assessable, so it stays out of the assessable mass and out of a resolved pair, and is still a miss in recall.
- A pair reads whole items too, not the one record it names. Its fixed state is the pair control's canonical control on the fixed input: every `fixed_target` or `both` record of it that the input froze, as the `fixed_target` block reads it. A record absent from the fixed bundle's plan, or left unresolved, leaves the pair unresolved however quiet the others were, so a pair earns no credit for a control that block counts as unresolved. A confirmed false allegation on any record flags the fixed state, whatever the pair's own record says.

**Omitted paths.** A result may list `omitted_paths`, the paths of its input the adapter observed the scanner did not examine, and may say `examined_nothing` when the adapter can show no part of the input to have been examined (in a PR review, every path the change touches is a listed one). A plan control may carry `paths`, where the pack places it. A record whose control is on a listed path, or whose plan gives it no paths while the result lists any, earns no quiet credit, and when the result says `examined_nothing` no record does, wherever it is placed: `scoring.observe` reports it completed and unresolved, so on a completed scan it is in `C`, not in `A`, and counted as unresolved in the false-alarm bound, as a record the plan lacks is, and a confirmed false allegation about it still resolves it. Aggregation reads the same rows and has no rule of its own for this. Only PR results report omissions so far, and a scan that examined some of the change still credits a control on an unchanged `context` file, which the list never names.

**Evidence scope.** An observation is `reviewed` when its bundle's plan is reviewed and its review record is `human_approved`. It is `diagnostic` when the plan is diagnostic, and `draft` otherwise. A failure takes the scope of its schedule's frozen plan. A system or view is `reviewed` only when every planned observation is. Reviewed mixed with draft reports `draft`.

**Systems.** A system is what its runs configured (adapter, adapter configuration, model, network policy, execution backend, and deadline) and the adapter version their manifests record for it. Two runs that record two versions, or two adapter names, for one system id are refused like two configurations, because a version can change what one configuration does: DeepSec 1.1.0 ignores `config.process_manifest_by_tree` and 1.2.0 honors it. Every manifest that loads carries the field, so a run records no version only for a system it ran nothing for: `null` when the system's adapter could not be resolved and it was skipped, and no row when the run failed before preparing it. Such a run pools with runs of any version and adds none, so its failures stay in every denominator, and each view names the runs that recorded no version.

Every system row reports that `adapter_version`, `null` when no run recorded one, and `processing`, the system's selection marker. It is `curated` when the configuration chose before the run which paths are assigned AI batches, which today is DeepSec's `config.process_manifest_by_tree`, and `full` otherwise. A recorded DeepSec version before 1.2.0 ignored the key and ran unscoped, so that system is `full`, and its view says the key was ignored; an unknown version is taken as configured. Both are read from what each run already recorded, so saved runs show them without being rewritten. Neither changes a figure: a curated system is scored like any other partial run, and every view it is in says its figures describe the chosen paths and are not a detection rate. Reports written before these fields existed omit them.

## Views, slices, and weights

Each (mode, profile) pair is a separate view: `standard`, `metadata_blinded`, and `identity_reduced` are never pooled. `profile_coverage` lists, per mode, the canonical targets each profile carries and those it lacks. Within a view, every system has one block per slice: `all`, each project, and each workload. Weights are renormalized within each slice.

`condition_coverage` records each system's evaluation condition, policy digest, status, assignment
count, and reasons. Claim-bearing observations with different condition names, policies, or
statuses cannot share one system's mode/profile metric view: ordinary weighted aggregation and
comparison refuse that mixture before computing metrics. Systems are checked separately, and
comparison checks only its baseline/candidate. Empty unsupported/error/timeout observations
occupy denominators without blocking other evidence. Missing/skipped assignments remain in the operational denominator and are
reported as unavailable. Legacy bundles without condition evidence remain readable and classify
conservatively. Use `scaneval condition bundle-a bundle-b` to inspect mixed collections and their
separate coverage without pooling results; see [closed-book standard](CLOSED_BOOK.md).

For mixed-status runs, `scaneval aggregate <run> --by-condition --output strata.json` produces
`report_mode: condition_strata` with separate system/profile/condition/status/policy metrics.
Every stratum shows its own assignment and target-observation denominator beside the whole
scheduled view's denominator. Missing repetitions and entire absent bundles remain explicit;
unknown outcomes are null, rather than silent misses. Recall is null with lower/upper bounds
when incomplete, unreviewed, or unresolved, and an unavailable frozen population has no invented
target denominator. Claims and known/unknown usage include failures that delivered claims.
These are unweighted descriptive target-observation metrics, with no pooled weighted headline
or confidence interval; the recorded aggregation policy is provenance, not a claim that these
descriptive counts apply its weightings. `condition_metrics(rows)` also accepts synthetic missing
assignments from a frozen experiment and exposes per-target outcomes for its declared weighting.
Strata also separate the original evidence scope. Diagnostic fixtures are never pooled with
draft or reviewed corpus evidence, and a human-approved finding review never upgrades the
corpus labels. The shared metrics API takes each row's original `scope`, preserves it on target
outcomes, and refuses a flat diagnostic/non-diagnostic mixture. Missing scope stays unavailable.

Condition-aware writers include optional-for-compatibility `condition_coverage` and
`condition_digest_format: condition-structural-v1` fields in 2.1 reports. The structural identity
hash includes every condition-record field and saved artifact hash, with human-readable reason
messages replaced by reason codes, wrapped with that format identifier. It is named
`record_identity_sha256`, rather than a byte hash of the complete record. Run `evidence_sha256`
now includes `condition_identity_sha256`, and paired `structure_sha256` includes the resolved
condition declaration. Regenerated reports therefore have different digest compositions from
reports written before condition support; old reports still validate but their gate bindings
do not apply to regenerated reports.

Observations are keyed by run and input, so one input scanned by two runs is two positive inputs. Each is averaged over its own repetition count `k`.

| Weight | Rule |
|---|---|
| Target `w_i` | `equal_target`: `1/N` over canonical targets. `equal_project` or `equal_family`: `1/(G n_g)`. `explicit`: the policy's `target_weights`, which must cover the view's targets and sum to 1 there, or that weighting is `unavailable`. |
| Input `rho_im` | Equal over the canonical target's positive inputs. More snapshots of one root cause add observations, not weight. |
| Control `u_j`, `lambda_jo` | Equal over canonical controls, then `(1/|inputs_j|)(1/k_m)`. |
| Pair `v_i` | Target weights renormalized over targets with a frozen pair. Frozen pairs weigh equally within a target, and repetition pairs within a pair. |
| Workload | A slice spanning two or more workloads needs the policy's `workload_weights`, renormalized over the workloads present. Without them it reports no pooled number (`unavailable`). The workload slices still report theirs. |

Weights, means, and ratios are exact rationals, rounded once to a float when written. A hand-calculated `2/3` is reported as the float nearest 2/3. Cost is read the same way: the decimals the scanners wrote are summed exactly and rounded once, so costs of `0.1` and `0.2` sum to `0.3` and not to `0.30000000000000004`. Seconds are summed as floats.

## Metrics

Each value is `null` when its denominator is empty, never `0`.

| Field | Meaning | Denominator |
|---|---|---|
| `full_output_recall` | Weighted share of target observations with a confirmed hit from valid output, ranked or not. | All assigned target observations, failures included. |
| `recall_at_budget[B].value` | Share with a measured first-hit rank `<= B`. `null` when any weighted observation is valid output whose position cannot be measured: unranked output, or unresolved bundles. A failure is a measured miss. | Same. |
| `recall_at_budget[B].lower_bound`, `unmeasured_mass` | The value with unmeasurable observations counted as misses, and the weight of those observations. | Same. |
| `random_order_diagnostic` | Expected recall under a uniform random order of delivered claims (duplicates included), over unranked outputs with resolved bundles, no pending match on the target, and no record of it absent from the bundle's plan. While a match is unresolved, or a record is absent (all of them, for a target the plan holds none of), the accepted claims are only a lower bound, so that observation is unmeasured: like one with unresolved bundles, it is left out of `observation_mass` and counted in `pending_mass`. Every unranked valid output is in one of the two. Diagnostic only, never native recall or a promotion metric. | `observation_mass`, the weight of the measured observations. |
| `coverage` | Completed, assessable, and unscored target masses, with raw counts. Assessable means completed with a resolved outcome: a confirmed hit, or a miss with resolved bundles, no pending match, and every record of the target in the bundle's plan. | All assigned target observations. |
| `pairs.value` (Q) | Confirmed pair success only: both observations completed and resolved, target detected, no false allegation in the fixed state. Each side reads every record of its canonical item: a fixed-state control with a record absent from the plan or unresolved leaves the pair unresolved, unless a confirmed false allegation on another record flags the fixed state and so resolves it. | Pairable targets (`v_i`). |
| `pairs.outcomes`, `assessable_mass`, `availability` | The four resolved outcomes (correct, both flagged, both silent, reversed), the resolved share, and the target weight with a pair at all. | Pairable targets; availability over all targets. |
| `controls.<class>.resolved_rate` | `E/A`: confirmed false allegations over resolved mass. `capability_safe` and `fixed_target` are separate; a `both` control is in each. | `A`, resolved mass. |
| `controls.<class>.completed_lower`, `completed_upper` | `[E/C, (E+C-A)/C]`: unresolved completed assessments counted as quiet or as false. A control with a record absent from the bundle's plan, or one the scan did not examine (see omitted paths above), is one of them, unless a false allegation on a record present resolves it. This is a missing-assessment bound, not a confidence interval. | `C`, completed mass. |
| `controls.<class>` counts | Observations, completed, resolved, unresolved, false allegations, and `unscored` (observations with a record absent from the bundle's plan). `observed_false_allegations` also counts confirmed allegations from incomplete output, which stay out of the rates. | Raw counts. |
| `completion` | `sum_m eta_m (1/k_m) sum_r a`: only `success` completes. Counts by status and failure reason. | Assigned inputs, equal `eta`. |
| `claims` | Records, unique, duplicate copies, delivered (resolved bundles only), unmatched, and pending, summed per bundle. `executed` counts the scans the manifest records as run: when it exceeds `bundles`, the sums are short by the executed scans whose bundle is missing or unusable, whose volume is unknown. | Bundles read. |
| `usage` | Wall, setup, tokens, and cost, summed once per executed scan however many targets it covers. An executed scan whose bundle is missing or unusable has unknown wall time and cost. Unknown values are counted, never summed as 0. Cost carries `coverage`, the share of executed scans whose cost is known. | Executed scans (`executed`); `bundles` counts those whose bundle was read. |
| `runs[].timing` | Elapsed wall time from the earliest start to the latest finish in the execution records, beside the records' summed wall time. | Execution records. |
| `first_hit_ranks`, `targets_per_input` | Unweighted rank distribution (a detection without a native rank is counted apart) and the planned canonical target count per input, where the alias records of one root cause are one target. | Raw counts. |
| `leave_one_project_out` | Full-output recall with each project's targets removed in turn, shown while a slice has 2 to 9 projects. | Remaining targets, renormalized. |

## Uncertainty

Intervals come from a cluster bootstrap. Clusters are projects or variant families, per the policy. Each replicate draws clusters with replacement and recomputes every metric exactly, with the frozen weights and cluster multiplicities. Each metric resamples the clusters that carry its frozen items:

- recall and recall@B resample the clusters with targets;
- pair correctness resamples the clusters with a target that has a frozen pair;
- control metrics resample the clusters with controls.

The schedules fix these sets before any outcome, so a project with controls and no target never takes a draw from recall. The slice's `clusters` field counts all three.

- **Seeding.** Draws come from `resampling.Stream(seed, label="bootstrap/<mode>/<profile>/<slice>/<family>")`, where the family is `targets`, `pairs`, or `controls`. Every metric of a family, and both systems of a comparison, read the same replicates.
- **Bounds.** The bounds are the sorted replicate values at ranks `max(1, ceil((alpha/2)R))` and `ceil((1 - alpha/2)R)`. The confidence is read as the decimal it is written as: 25 and 975 of 1000 at 0.95.
- **States.** An interval is `ok`, `degenerate`, `insufficient_clusters`, `unstable`, or `unavailable`:
  - `degenerate`: the two bounding replicate values are equal, a zero-width interval, which is not certainty.
  - `insufficient_clusters`: fewer than `min_clusters` clusters carry the metric.
  - `unstable`: some replicate drew no cluster carrying it.
  - `unavailable`: the metric itself is undefined.

  Only `ok` carries bounds, so no zero-width interval is ever reported.
- **Run variability.** Reported separately: `sum_i w_i^2 sum_m rho_im^2 v_im / k_m`, with `v = p(1-p)k/(k-1)`. It is conditional run noise under an independent-target approximation, not corpus uncertainty. It is `unavailable` when every input ran once and `partial` when some did; `uncovered_mass` holds their weight.

## Comparison

`compare` first checks that baseline and candidate share one frozen evaluation contract: the same inputs with the same mode, profile, snapshot or change set, blinding map, declared tree hash, frozen plan items, levels, scope and budgets, repetitions, pairs, and pack. Run ids may differ. Anything else is refused with the first difference, for example `input p5 is scheduled for baseline but not for candidate`. A system cannot improve by being assigned less.

That check compares the two systems' schedules, so it cannot see a narrowing that applies to both, such as a run started with `--only-input` after its configuration was written: the configuration keeps every input, both systems are assigned the same shorter schedule, and inputs could be dropped after their results were seen. Each run row therefore records the manifest's `selection` and `configured_inputs` beside `inputs`, the inputs its schedule covers, in `aggregate` and `compare` alike. `compare` does not refuse such a run, and [the gate](GATE.md) leaves its shared-contract requirement unresolved.

Differences are candidate minus baseline for each view, slice, and weighting. They cover recall, recall@B and its lower bound, pair correctness and availability, the control rates and masses, and completion. Recall, recall@B, pair correctness, and the control rates carry paired intervals. `configuration_differences` lists every differing value as a dotted key over `adapter`, `adapter_version`, `config`, `model_id`, `model_revision`, `network_policy`, `execution`, `processing`, and `timeout_seconds`. Two systems of different adapter versions, or a curated system and a full one, are compared, not refused: the difference is listed there, where [a gate policy](GATE.md) must name it to measure it, and a curated system's caveat is in every view.

## What is not claimed

- No reviewed precision or review time ([math section 3](EVALUATION_MATH.md#3-reviewed-precision-and-review-burden)), mixed-intent correctness, freshness, or promotion decision.
- An interval describes resampling of the observed projects or families. It does not show that the corpus represents other software, and a `degenerate` or `insufficient_clusters` state is not a narrow interval.
- `reviewed` means a human-approved review record over a reviewed plan exists; the record is not verified here. Draft evidence is pipeline diagnostics, not benchmark evidence.
- Usage figures are what scanners reported; an unknown cost is unknown, not free.

The effective global `timeout_seconds` is part of system configuration identity. A system id
 cannot aggregate different deadlines; comparisons expose deadline changes to the configuration
 allowlist. There is no per-system deadline override. Adapter config, model identity, effective
 network policy, execution backend, the recorded adapter version, and processing also participate. Repetitions, profiles and frozen workload
 follow the shared comparison contract; run timestamps, paths and observed execution timings may vary.
