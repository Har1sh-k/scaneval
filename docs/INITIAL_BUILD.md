# Initial evaluation core

This alpha implements step 1 of [the design's build order](DESIGN_DECISIONS.md#10-packaging-deliverables-and-build-order) and the first vertical slice of step 2. It is not the completed benchmark and does not replace the legacy `scripts/` runner yet. Package version is `2.0.0a1`.

No detection result exists anywhere in this repository. Every case in the pilot pack carries mechanical checks only, so every plan built from it has draft scope; no matching decision has been approved, and confirmed detection is zero. The first real scanner invocations, with their execution facts and their limits, are recorded in [the pilot report](PILOT.md); read that rather than this document for what was actually run.

## What works

- Validate nine versioned JSON contracts: scan requests and results, evaluation plans, review decisions, execution records, case packs, review records, run configurations, and run manifests.
- Build an evaluator-side case pack: pin snapshots, draft cases from supplied artifacts, run mechanical (L1) checks against an exported tree, record explicit human reviews, admissions, and dispositions.
- Fetch a pinned commit into an immutable source cache and export it to an isolated trial directory with a recorded tree hash and preparation provenance.
- Execute a frozen run configuration: prepare every input, freeze the pack, invoke each system once per input per repetition, and write one bundle per invocation plus a run manifest.
- Run two real adapters: pinned Semgrep OSS against a local rules checkout, and the own harness through its own engine entry point with the observer wrapped around its default model runner.
- Draft review decisions by routing claims to planned targets, then record and approve them through explicit human steps.
- Score one saved output against all assigned targets and controls for that input, reporting full-output recall, first-hit ranks, native review-budget recall, exact duplicates, unresolved findings, and conditional control bounds.
- Replay the same saved records without models or network access, and generate a standalone HTML report.

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

## Contracts

Schemas ship inside [`src/sastbench/schemas`](../src/sastbench/schemas) and are the values `sastbench validate` accepts.

| Kind | What it holds |
|---|---|
| `scan-request` | The sanitized invocation handed to a scanner. Cannot carry target IDs, regions, fixes, or decisions. |
| `scan-result` | Normalized claims with an explicit execution status and ranking mode. |
| `execution-record` | Exit status, timing, tool and model versions, declared policy, per-category capture, and provenance for one invocation. |
| `evaluation-plan` | Assigned targets and controls for one materialized input, its scope, review budgets, and pack provenance. |
| `review-decisions` | Per-claim matching decisions and per-control assessments, bound to a saved result by hash. |
| `review-record` | Who produced a decisions file, its state, and the hashes it binds to. |
| `case-pack` | Snapshots, cases, evidence, controls, check results, reviews, and admissions. |
| `run-config` | A frozen run: pack, inputs, systems, repetitions, timeout, trace mode, network policy. |
| `run-manifest` | What ran, what was skipped, and where every artifact landed. |

The preparation record written beside an exported tree (`provenance.json`) is versioned but has no JSON Schema of its own and is not one of the nine kinds.

## Materialization and the immutable cache

`sastbench.materialize` fetches exactly one 40-hex commit into a cache directory (default `.repos`) keyed by repository and short SHA. A cache entry that already exists is verified rather than refetched: its HEAD must be the requested commit and it must have no local modifications. A branch, tag, or short id is refused.

Export copies the tracked regular files of that commit into `<trial>/source`. `.git`, `.securevibes`, `.sastbench`, and `.repos` are stripped; submodule gitlinks and symbolic links are not exported and are recorded as skipped with a reason. Files a scanner may read as project instructions (`CLAUDE.md`, `AGENTS.md`, `.claude/`, `.cursor/`, and similar) stay in the export under the `standard` profile and are recorded as retained identity cues.

The tree hash is the canonical SHA-256 of the `{relative path: file content hash}` map. Only the `standard` profile is implemented. `metadata_blinded` is refused outright, with and without a supplied replacement map, rather than silently downgraded to `standard`.

An adapter that requires git gets a single synthetic commit with a neutral identity created in the workspace copy. Original history is never exported.

This is preparation and provenance, not a sandbox. Filesystem and network policy must be enforced outside this package.

## The invocation runner and the bundle layout

`sastbench run <config> --output <new dir>` executes a frozen run configuration and writes:

```text
<out>/
  run-config.json          canonical copy of the configuration that was executed
  run-manifest.json        what ran, what was skipped, and where every artifact landed
  evaluator/pack.json      the pack copy this run froze, with its mechanical check results
  inputs/<snapshot>/       exported source tree plus preparation provenance beside it
  invocations/<id>/        one bundle per input, system, and repetition
```

Each invocation bundle holds:

```text
<invocation_id>/
  request.json             sanitized scan request, no labels
  result.json              normalized claims with explicit status
  execution.json           exit status, timing, versions, policy, capture, provenance
  raw/                     stdout, stderr, native artifacts, captured harness state
  trace/                   observer events when the adapter captured any
  evaluator/plan.json      targets and controls planned for this input
  evaluator/decisions.json machine-drafted decisions, every one unresolved
  evaluator/review-record.json  state and binding hashes for those decisions
  evaluation.json          computed result and input-record hashes
  report.html              local report
```

A scanner only ever sees a private workspace copy of one export. `raw/` and `trace/` are staged inside that workspace and moved into the bundle once the scan returns or raises, so no path handed to an adapter resolves inside the run directory. The source is hashed before and after the scan and `source_modified` records the comparison. An invocation that fails, times out, or hits an unsupported language keeps that status; it is never rewritten as an empty successful scan. Once the output directory exists, any later failure writes a manifest with status `failed` before the exception leaves the runner.

The declared network policy is recorded, never enforced. The runner computes single-invocation numbers only: no corpus weighting, repeated-run uncertainty, cross-system comparison, or promotion gate is computed anywhere.

## Adapters

Two adapters are registered, `semgrep` and `llm-harness`. An adapter runs the real product once, preserves its raw output, and translates native findings into normalized claims. It never receives labels and never decides whether a claim is true.

**`semgrep`** runs Semgrep OSS against a local git checkout of a rules repository pinned to one commit, with `--metrics=off` and no registry download. A `p/...` or `r/...` registry config is refused because it is not a pin. Preparation records the ruleset commit, the number of rule files Semgrep's own `--config <directory>` walk would select, and one aggregate hash over those files; a symlink anywhere under a configured ruleset directory is refused rather than followed. Native rule identity is recorded relative to the pinned checkout so the cache path does not leak into the rule id. A run that scanned no paths and reported nothing is an error, not a quiet negative result.

**`llm-harness`** runs the `securevibes-agent` and `fieldglass` engine family through its own engine entry point inside its own `tsx`. Presets exist for both; only `securevibes-agent` has been exercised against a live model. SASTbench injects only the harness's default model runner wrapped by the observer and a progress reporter. Findings are imported from the harness's own `findings/*.md` records; they are file-level, and this importer keeps them file-level and never invents line ranges. The harness plan, threat model, scan log, profile, and specialist records are copied into the staging directory so they survive as hashed raw artifacts, and the whole state directory is captured separately. Only `bootstrap` mode on a full scan is supported; native PR mode is not wired.

## Observer connection: what is captured and what is not

The TypeScript observer is connected to the own harness through [`llm_harness_driver.mts`](../src/sastbench/adapters/llm_harness_driver.mts). Importing the SDK still captures nothing on its own; this driver is what emits.

It emits `model.request` and `model.response` around each logical model call, `context.selection` from the harness's own progress notes, and `finding.submitted` for each finding the engine finally wrote. It does not emit tool events or finding candidate, validation, and filtering events.

| Category | Status on a real route | Why |
|---|---|---|
| Model requests and responses | `partial` | One event is one logical call. The harness retries inside its own runner, below the observed boundary, and the CLI path exposes no token usage. |
| Tool calls | `unavailable` | Dispatch happens inside the model CLI subprocess this driver spawns but cannot see into. No tool event is emitted, and that establishes nothing about whether a tool ran. |
| Context selection | `partial` | Only the harness's own progress notes become context events. The complete outgoing prompt is captured separately as model-request content. |
| Finding submitted | `complete` when the engine returned a summary | Read from the engine's own returned findings. |
| Finding candidate, validation, filtered | `unavailable` | Those stages happen inside the harness and are not exposed at the boundaries this driver instruments. |

Each route's declared tool policy is recorded as the harness's own declaration, never as an observation. Model identity is recorded as `unverified` when the CLI path does not report the served model. Cost is recorded as unknown; a harness self-estimate is preserved as a self-report, never as a measurement.

`unavailable` is not `not_applicable`. The mock runner, which spawns no process at all, is the only case where tool dispatch is genuinely inapplicable.

## Case packs, mechanical checks, and explicit human approval

A pack is evaluator-side data and is never copied into a scanner workspace. Code can create drafts and run mechanical (L1) checks; only a recorded human review can raise a case beyond that.

Six checks run against one exported tree, per snapshot: `locations_exist_in_snapshot`, `line_ranges_within_files`, `aliases_well_formed`, `represents_statement`, `evidence_recorded`, and `snapshot_hash_recorded`. They compare declared paths against an exact listing of the export and read file bytes only to count lines. Nothing here parses source, establishes a root cause, or approves anything, so no check raises a case past L1.

Review states are `draft`, `mechanically_checked` (the L1 state), and `human_approved`, which carries whatever level the recorded review named. L3 and L4 additionally require an `independent_reviewer` decision and a `validate` disposition. A case becomes `mechanically_checked` only once every snapshot it references has a recorded passing check set. A referenced snapshot that fails, or that was never checked, demotes a mechanically checked case back to draft. For an approved case the same situation records `validation.checks_failed` and leaves the review state and level untouched, because code never withdraws a human review; plan generation then keeps that case out with a note.

`corpus approve` records the reviewer name the caller supplies and nothing else. Nothing infers approval from a passing check, a matching hash, or the absence of an objection. A license is never recorded as verified by the CLI. An imported artifact becomes a draft case with a `needs_evidence` disposition, never a label.

Plan generation degrades to the lowest state present: a plan is `reviewed` only when every included case is `human_approved` at L3 or L4, and `draft` otherwise. Planned items keep their real validation level; the scope, not a rewritten level, says whether the labels are reviewed.

## Review workflow

`sastbench review init` routes saved claims to planned targets. A candidate means only that the claim's primary location path is an accepted location path of that target. Routing does not read claim prose, compare line ranges, weigh severities, or establish a root cause. Every decision it writes is `unresolved`, so a draft can never earn detection credit, a rejection, or a quiet control, and an empty draft is not evidence of absence.

A human edits `evaluator/decisions.json`. `review record` then re-drafts the review record for the edited decisions and keeps the recorded review history. `review approve` records one explicit human approval, refusing decisions that no longer bind to the saved result.

`review status` reports `missing`, `stale`, `draft`, or `human_approved`. `stale` means the decisions file or the plan changed after the record was written, or that the record and the decisions name different runs. That is the only tampering it can see: it does not check the result, the source tree, or the pack the plan came from. A `human_approved` state is the record's own assertion, not a verified one, and it is not a signature or proof that the named reviewer read anything.

`replay` prints a warning on stderr for any bundle whose review state is not `human_approved`, and `report` prints one for a draft, stale, or missing record. The HTML report carries the same statement in its own notice.

## Run configuration

A run configuration is a frozen document naming the pack, the inputs, the systems, the repetition count, the timeout, the trace mode, and the network policy. The two pilot configurations are [`corpus/pilot/run-semgrep.json`](../corpus/pilot/run-semgrep.json) and [`corpus/pilot/run-harness.json`](../corpus/pilot/run-harness.json).

`--only-input` and `--only-system` narrow a run. Naming something the configuration does not contain is an error rather than a silently empty run, and what was narrowed away is recorded in the manifest. `--workspace-root` chooses where the scanner's private workspace is created; a workspace inside the run output, the source cache, or an exported input is refused.

## CLI surface

| Command | What it does | Network or model calls |
|---|---|---|
| `validate <kind> <path>` | Validate one of the nine contract kinds. | none |
| `score --plan --result --decisions` | Score separately stored records. | none |
| `replay <bundle>` | Recompute a saved bundle offline. | none |
| `report <bundle> --output` | Score a bundle and render standalone HTML. | none |
| `demo <new dir>` | Create the fabricated conformance bundle. | none |
| `corpus init` | Create a new draft pack file. | none |
| `corpus add-snapshot` | Pin one repository commit; license stays unverified. | none |
| `corpus import` | Draft one case from a legacy record, fix commit, finding, or document. | none |
| `corpus validate <pack>` | Print a pack summary. | none |
| `corpus validate <pack> --snapshot-id` | Fetch and export that snapshot, run the L1 checks, record them. | fetches the pinned commit |
| `corpus approve` | Record one explicit human review of a case. | none |
| `corpus admit` | Record an admission decision. | none |
| `corpus disposition` | Record a screening disposition and its stated reason. | none |
| `plan --pack --snapshot-id --tree-hash --output` | Build one evaluation plan for a materialized input. | none |
| `review init <bundle> --pack` | Route claims to targets as unresolved candidates. | none |
| `review record <bundle>` | Re-draft the review record after a human edited the decisions. | none |
| `review approve <bundle> --reviewer --note` | Record one explicit human approval. | none |
| `review status <bundle>` | Report missing, stale, draft, or human_approved. | none |
| `run <config> --output <new dir>` | Execute one frozen run configuration. | depends on the configured systems |

Exit codes: `2` means the command could not be carried out (a usage or contract error, a refused overwrite, a failed fetch or export). `1` means it ran and reports a negative result (a mechanical check set failed, or a run produced no usable scan from some system). `0` means it ran and reports nothing wrong, which is not a statement that any label or decision is correct.

No command writes inside a materialized trial directory, and every output path except a pack file and a review record is create-only.

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

Replay reads `result.json` and `evaluator/` records. It does not execute `request.json`, inspect source, or replay tools. The directory layout illustrates the evaluator boundary but does not enforce access isolation.

The library entry point is:

```python
from sastbench import evaluate

record = evaluate(plan, saved_result, frozen_decisions)
```

This is saved-record evaluation of documents that already exist. The live path is `sastbench run`, which produces those documents from a frozen configuration.

## Contract rules enforced now

Strict parsing rejects duplicate JSON keys, nonfinite numbers, escaping file paths, missing IDs, and malformed references. Unknown extra fields are rejected so extensions need a contract change.

- **Scanner boundary:** `ScanRequest` cannot contain evaluator target IDs, regions, fixes, or matching decisions. This is a shape check, not automatic source sanitization.
- **Locations:** file-only reports stay file-only. A line range is optional; if supplied it must be positive and ordered. Location overlap alone never earns credit.
- **Claims:** one allegation and its evidence per normalized claim. Separately structured bundles must be split by an importer or reviewer before claiming an atomic count. Adapters normalize the output of the system they just ran; there is no importer for a saved vendor file, SARIF or native, produced outside a SASTbench invocation.
- **Duplicates:** canonicalize allegation, kind, native rule ID, primary/related locations, and evidence text. Normalize path separators and line endings. Ignore delivery IDs and ranks. Different evidence stays distinct; semantic duplicate review is not implemented yet.
- **Credit:** one claim or exact-duplicate group can hit at most one canonical target. Duplicate copies keep their review positions. Contradictory frozen decisions are rejected.
- **Ranking:** native ranks must be contiguous and follow the submitted array. Unranked output has no native budget score. Its optional random-order expectation is a separate diagnostic and can be affected by duplicate spam.
- **Bundles:** unresolved bundles leave atomic-claim burden and finite-budget metrics pending. Confirmed full-output hits can still count.
- **Execution:** `success`, `partial`, `unsupported`, `error`, and `timeout` remain distinct. Confirmed partial-output hits can count. Failed assignments remain in the denominator. Only successful, resolved, in-scope output can establish a quiet control.
- **Controls:** all claims are eligible for control review, including those below the review budget. Missing assessments remain unresolved. The completed-observation upper bound counts unresolved assessments as false allegations; it is not a confidence interval. `false_allegations` is its completed-only numerator. `observed_false_allegations` also retains explicit reviewed failures from incomplete output, without using incomplete scans in that rate.
- **Unknowns:** unmatched claims are not automatically false positives. This build does not estimate overall precision.
- **Labels:** `diagnostic` plans allow only fixture labels; `reviewed` plans require declared L3/L4 labels; `draft` plans keep each item's real level and say in their scope that the plan as a whole is not reviewed evidence. Checking the field does not verify independent review.
- **Packs:** a pack's self-consistency is checked, never its correctness. A pack that validates is consistent with itself: no check here reads source, a reviewer, or a scanner.

Scores use equal target/control weights within one input. Do not average them as a release score: corpus weighting, repeated-run aggregation, repository clustering, and promotion gates are not implemented. Zero denominators are `null` in JSON and N/A in HTML.

## Observer SDK

See [the SDK guide](OBSERVER_SDK.md) and [event schema](../schema/v2/trace-event.schema.json).

The TypeScript emitter records supplied model/tool events, selected context, and finding lifecycle events: candidate, validation, filtering, and submission. It does not intercept a harness automatically, change its prompts, enforce networking, or inspect hidden reasoning. Recording is off by default. The harness owns its sink and retention policy. The own-harness driver described above is the one integration that exists; the emitter still captures nothing when imported on its own.

Sink or other instrumentation errors create capture gaps without replacing the operation's result or exception. Missing events are not evidence that an operation did not happen. The HTML report currently shows scores, not a trace timeline.

```sh
cd sdk/typescript
npm ci
npm test
```

## Limits

- **No detection result exists.** Every case carries mechanical checks only, every plan is draft scope, no matching decision has been approved, and confirmed detection is zero. Any recall figure printed today comes from decisions with no recorded human approval.
- **No controls.** The pilot pack defines no negative controls, so control rates are N/A rather than zero, and no fixed-state snapshot has been prepared.
- **Directory separation is not isolation.** The declared network policy is recorded, not enforced. Path checks refuse the obvious mistake and do not follow bind mounts or hard links.
- **Hashes identify documents.** They do not authenticate an author, verify a source snapshot, or prove that a reviewer read anything.
- **Capture gaps are not absence.** An `unavailable` category establishes nothing about whether the underlying activity happened.
- **Single-invocation numbers only.** No corpus aggregation, pair aggregation, repeated-run uncertainty, precision sampling, promotion gate, trace viewer, exporter, or multi-model planner is implemented.
- **Not implemented at all:** native PR mode through an adapter, metadata blinding, SARIF or native output import, and semantic duplicate review.
- **The legacy `scripts/` runner and adapters are unchanged** and continue using old semantics. Their output does not conform to these contracts.

## Next implementation slice

1. Human review of the routed candidates from [the pilot](PILOT.md), recorded through `sastbench review record` and `sastbench review approve`, which is the only path to a non-zero recall.
2. Independent review of the pilot case labels to L3, which is the only path out of draft scope.
3. Fixed-state snapshots so the cases have property-specific negative controls.
4. The own harness on the remaining inputs, plus repetitions, before any comparison between systems.
5. Native PR integration, output import, corpus and pair aggregation, and the buyer report.

The Python core supports request language tags for Python, TypeScript/JavaScript, Go, and Rust. This does not imply equal corpus coverage or live support for every scanner. Inspect/Harbor selection, Jev corpus assistance, and the separate engineering improvement agent remain outside this slice.

The organization-owned pack path is documented separately in [bring your own corpus](BRING_YOUR_OWN_CORPUS.md).

Run the Python regression suite with `python -m pytest -q`. Legacy tests remain alongside the new contract, materialization, execution, runner, corpus, review, scoring, and CLI conformance tests. No real CVEs are silently imported and no paid model evaluations run during these tests.
