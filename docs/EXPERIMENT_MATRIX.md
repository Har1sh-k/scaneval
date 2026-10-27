# Paired evaluation conditions

`scaneval matrix` freezes and executes three conditions over the same source property,
canonical targets, case pack, scanner and version, model request/revision/reasoning settings,
scope, resource and time budgets, repetitions, and finding-adjudication policy. Each cell has
separate condition coverage and metrics. The matrix report retains the complete planned
population when a cell, repetition, condition attestation, or finding review is unavailable.

| Condition | Identity | Git context | Retrieval |
| --- | --- | --- | --- |
| `open_context` | Ordinary repository identity | Exact original ancestor closure, excluding later and unrelated objects | Controlled recorded public research |
| `closed_book_standard` | Ordinary repository identity | Original history absent | Disabled; inference-only network route when needed |
| `identity_reduced` | Strict reviewed transformation | Original history absent | Same controls as closed-book standard |

Open minus closed measures the combined history and public-retrieval context effect. It cannot
separate Git from web effects. Closed minus identity-reduced measures sensitivity to removed
identity context. Neither a difference nor its absence establishes memorization or its absence.
Open-context is assisted investigation: public known-vulnerability information may contribute to
a hit. Identity-reduced retains source and other residual cues and does not create a memory-free
or anonymous input. Optional `git_only`/`web_only` extension definitions are reserved declarations;
matrix v1 does not execute them.

## Complete diagnostic Semgrep example

This example exercises plumbing and paired reporting with a fabricated local repository and
one pinned local Semgrep rule. It does not execute the target application or call a model.
Its allegations are not reviewed CVE benchmark labels. The example generator creates an
**unapproved** identity map; you inspect it and record your own review. No program supplies
a human approval. The declaration explicitly downgrades the report to `diagnostic`, and finding
review cannot promote that corpus evidence scope.

Install ScanEval, start Docker, and pull these pinned images. With Colima, put both configuration
and workspace under a shared home directory. Other OCI engines must be able to mount those paths.

```bash
docker pull python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9
docker pull semgrep/semgrep:1.177.0@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198
fixture_root="$HOME/.cache/scaneval-matrix-fixture-$(date +%s)"
python examples/experiment_matrix_fixture.py "$fixture_root"
scaneval validate experiment-matrix "$fixture_root/matrix-declaration.json"
```

Inspect `map.json`, the original `probe/source/README.md`, and the unchanged scoring file
`probe/source/app.py`. The map removes identity-only documentation, pins its original bytes,
declares the strict identity policy, and leaves executable source intact. After your inspection:

```bash
scaneval blinding review "$fixture_root/map.json" --reviewer "Your name" \
  --role independent_reviewer --decision approve --note "Describe your inspection of this fabricated fixture."
scaneval blinding check "$fixture_root/map.json" --pack "$fixture_root/pack.json" \
  --cache-root "$fixture_root/cache" --profile identity_reduced
scaneval matrix freeze "$fixture_root/matrix-declaration.json" --output "$fixture_root/frozen-matrix.json"
scaneval matrix run "$fixture_root/frozen-matrix.json" --output "$fixture_root/experiment" \
  --workspace-root "$fixture_root/work"
scaneval matrix report "$fixture_root/experiment" --output "$fixture_root/before-review.json"
```

The expected successful execution has one saved Semgrep invocation in each cell, with all three
conditions attested. Semgrep does not use web research: the open cell reports zero retrieval API
events, bounded original history, and explicit provider visibility gaps. This does not demonstrate
a web-using model. The separate real-container retrieval tests exercise a benign public fetch and
private-network denial. The strict cell records one removed README and verified transformation
coverage, including any residual categories. Each cell still needs finding review; a successful
scan and an attested condition alone do not resolve detection outcomes.

The runner has already initialized draft reviews for each bundle. Their decisions live here:

```bash
for condition in open_context closed_book_standard identity_reduced; do
  bundle="$fixture_root/experiment/runs/$condition/invocations/fixture__semgrep__r1"
  echo "$bundle/evaluator/decisions.json"
done
```

Inspect each `result.json`, evaluator plan, and the original source. Edit its
`evaluator/decisions.json` to accept, reject, or leave unresolved each structured allegation.
Apply the same frozen adjudication policy to all cells: identical allegations against the same
source/canonical target cannot be accepted in one and rejected in another. After **your** inspection
and edits, run `scaneval review record <bundle>` and `scaneval review approve <bundle> --reviewer
"Your name" --note "Describe your diagnostic finding review."` for each bundle, then write a new report:

```bash
scaneval matrix report "$fixture_root/experiment" --output "$fixture_root/after-review.json"
```

When all three identical fixture allegations are accepted after inspection, each cell's diagnostic
target detection is one and both paired differences are zero. Before finding review, exact
full-population detection and effects are null with missingness bounds. One target is insufficient
for a bootstrap interval. These fixture numbers establish neither a real vulnerability label nor
scanner quality, and the report remains `diagnostic` after review. CI uses explicitly fictional
diagnostic adjudication only to verify this software path; it creates no real corpus approval.

## Frozen contract and execution evidence

The declaration names the exact source population and exclusions, common systems, context-only
differences, condition policy versions, required capture capabilities, timeout/resources,
repetitions, fixed or seeded run order, adjudication policy, aggregation policy, uncertainty method,
and missingness handling. Remote systems require a requested model revision. Actual runtime adapter,
scanner `tool_versions`, image, request settings, and served-model verification also enter pairing:
an opaque or moving provider alias does not become a verified revision by declaration.

Freeze embeds the complete pack and reviewed maps, checks exact snapshot/map variants, static
strict-policy answer coverage, accepted scoring paths, and scanner-visible identity cues. It derives
eligibility through the existing schedule planner and materializes the full condition/system/input/
repetition cross-product. Semantic validation recomputes the population and configs, so changing
a digest alone cannot waive the frozen declaration. Runtime preflight also checks actual staged
configuration, cache, workspace, and default temporary paths before any cell consumes a budget.

Execution writes the complete matrix, all assignments, every cell config, pack, and map before the
first scanner starts. It checks staged files immediately before each cell, then reconciles each
actual schedule and result with the frozen assignments. Immutable scanner/evidence files receive
matrix and assignment bindings. Later finding review stays separate. `matrix-execution.json`
records every cell and assignment as bound, skipped, missing, invalid, interrupted, or never started
with the available failure reasons; the report validates and preserves these states independently
of scoring missingness. A missing execution manifest leaves execution state explicitly unknown.

Within each cell, every input is prepared and mechanically checked, and the runtime pack saved,
before any system is prepared. The cell then fails, with no adapter work, unless the runtime pack's
label contract equals the frozen pack and a schedule rebuilt from it has the frozen inputs,
assignments, and target/control eligibility. The label contract is the whole pack with only check
timestamps and their derived digests normalized, so it covers excluded and currently unplanned
cases, newly eligible drafts, and stale check sets. A refusal leaves the runtime pack, frozen
schedule, and failed run manifest for diagnosis; run the case checks, review the resulting pack,
and freeze a new matrix. An input whose preparation fails without changing the pack is still a
skipped input. The report repeats the label-contract check after execution.

Each cell has an independent source/rules cache. This can clone the same pinned repository three
times and costs setup time/storage, but avoids cross-cell writable cache state. It is not a model
cache or assurance that remote providers share no hidden state. Source, labels, maps, transformation
manifests, and histories stay in the existing evaluator/scanner isolation boundaries; target
applications, tests, and exploits are never executed by this workflow.

## Metrics, coverage, and precision

Matrix v1 supports the versioned `scaneval.matrix.equal-canonical-target` policy only. It averages
inputs/repetitions within each canonical target, then weights canonical targets equally in every
cell and contrast. Custom/workload weights and other views are refused at freeze time. A paired
cluster bootstrap is available only when the supported method, seed, confidence, replicates,
clustering unit, and minimum cluster count were frozen and the complete planned pairs resolve.

The report exposes separate condition/status/policy/runtime/evidence-scope strata, support,
completion, partial/error/timeout outcomes, claim volume, unresolved matching, finding review
states, usage, actual-model verification, history/retrieval capture, transformation counts, and
residual categories. Corpus scope stays separate from finding approval. Diagnostic and real
draft/reviewed populations cannot be pooled. Unknown work stays in the planned denominators;
full-population exact effects are null whenever any planned contribution is unresolved. Bounds
use known per-cell contributions, and resolved-subset estimates have explicit coverage and are
not represented as full-population effects. Contradictory source/model/adjudication evidence
refuses pairing instead of silently intersecting convenient observations.

Reviewed precision is separate from target matching. Matrix v1 reports `reviewed_precision.status:
"unavailable"`, null estimate/coverage, and zero imported precision artifacts. It imports no estimates
and creates no new estimator. For an available profile, run the existing [precision workflow](PRECISION.md)
on **one cell's run directory at a time**, with a frozen sampling policy and actual human review:

```bash
scaneval precision sample "$fixture_root/experiment/runs/closed_book_standard" \
  --population full --size 1 --seed 42 --profile standard --output "$fixture_root/closed-sample.json"
scaneval precision queue "$fixture_root/closed-sample.json" --output "$fixture_root/closed-queue.json"
# Inspect the queue, then use precision record with your reviewer, outcome, and note.
# Use precision estimate with that sample and its reviews; retain the separate estimate artifact.
```

Claim and unresolved-matching coverage remain available in the matrix even without precision
review. Use `--profile identity_reduced` for the strict cell's separate frame. Profile support and
freshness/binding rules are those of the existing precision command. Do not pool open and closed
precision frames because their shared `standard` profile does not mean they share a condition.
Live web changes, opaque provider retrieval/tunnels, unverified served revisions, and absent model
request capture remain reproducibility limits. Recognition diagnostics never earn detection credit.
