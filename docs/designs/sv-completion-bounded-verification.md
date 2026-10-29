# SV completion bounded verification

ScanEval issue: https://github.com/Har1sh-k/scaneval/issues/104

Method reference: [Anthropic, *Formal verification for AI-generated code*](https://www.anthropic.com/research/formal-verification).

## Claim

This work checks the real ScanEval completion consumers, `read_review_workflow` and
`read_completion` in `src/scaneval/adapters/llm_harness.py`, against an independently stated
finite acceptance oracle. It is **bounded generated verification and concrete conformance**, not
a Rocq/Lean proof, not a proof about all Python executions, and not a claim that model-generated
proofs establish what the shipped implementation does. The Anthropic work motivates separating a
mathematical specification and proof attempt from testing the actual implementation. Here the
executable oracle and generated cases exercise the actual Python entrypoints; no full formal proof
artifact is produced.

The property is:

> If the consumer accepts a declared review workflow, its nonempty immutable inventory contains
> only supported, fully assigned sources, or it is the separately valid all-excluded
> `not-required` case. Every original invocation/model/hypothesis/shard/source/request obligation
> has exactly one matching receipt; file identity and required procedures match exactly; every
> required file/procedure pair has exactly one completed terminal; and no unsupported, unassigned,
> missing, stale, duplicate, partial, inconclusive, budget-omitted, failed-stage, or failed/pending
> model-call evidence is present. Legacy source assessment remains `unassessed`.

Acceptance here means both production readers return no error code. Adapter execution, import,
runtime-identity, timeout, and outer native-outcome gates remain separate and are not claimed by
this checker.

The property must not be satisfied vacuously. Valid complete workflows with zero findings or
findings are both reachable because findings are outside this decision, two independently
reviewed supported files are reachable, and a valid nonempty all-excluded `not-required` workflow
is reachable. A checker or implementation that rejects every case is nonconforming.

## Independent oracle

The oracle is expressed over abstract inventory entries, obligation/receipt multisets, immutable
file/procedure identities, terminal states, and native health flags. It does not call or copy the
production shape or reconciliation helpers. A deterministic materializer turns each abstract case
into the native JSON shape, using `tests/fixtures/sv-review-workflow-summary.json` only as the
healthy outer-summary template. Every generated case is then passed to both production consumer
entrypoints.

The trusted computing base for this bounded check is the abstract oracle, materializer, Python
runtime, fixture, and checker harness. Source SHA-256 values and the Git revision are emitted at
run time; generated output is written outside the repository and is not committed.

## Finite domain

The checker enumerates exactly 708 cases in eight semantic families plus malformed boundaries:

1. **Inventory/assignment product — 144 cases.** File count is 1 or 2; required-procedure count is
   1 or 2; each inventory disposition is `supported`, `unassigned`, or `unsupported`; and every
   ordered obligation plan of length 0, 1, or 2 over nonempty subsets of source-capable files is
   generated. This is the full cross-product within those bounds. Receipts are exact and terminals
   are completed.
2. **Receipt pairing/binding product — 288 cases.** Obligation count is 1 or 2; receipt multiplicity
   for every obligation is independently 0, 1, or 2; every receipt uses one of eight binding modes
   (`exact`, or a swapped invocation, model, hypothesis, shard, source ref, request digest, or file
   identity); and terminal mode is completed, inconclusive, or missing. This is the full stated
   cross-product, not one-at-a-time mutation.
3. **Terminal product — 102 cases.** File count and procedure count are each 1 or 2, and every
   required pair independently has status completed, inconclusive, or missing. All
   `3^(files*procedures)` assignments are generated.
4. **Declared workflow-stage product — 32 cases.** All healthy/failing combinations of model-call,
   structural, lint, marker, and specialist report stages are generated (`2^5`).
5. **Original native-health product — 32 cases.** All healthy/failing combinations of bootstrap
   model health, source delivery, repository lint, marker assessment, and specialist completion
   are generated (`2^5`).
6. **Legacy-completion compatibility product — 90 cases.** Logical-call health has three states;
   the legacy unknown-reason set has five states; source delivery has two states; and structural
   coverage has three states. The full `3*5*2*3` product is generated.
7. **All-excluded reachability — 1 case.** A nonempty immutable all-excluded inventory with no
   obligations or receipts.
8. **Finding/review reachability — 2 cases.** The same valid two-file, two-obligation,
   two-procedure workflow with zero and one declared finding.
9. **Malformed shape/type/numeric boundaries — 17 cases.** Wrong report/container types, Boolean
   and out-of-range integer boundaries, malformed procedure/file/terminal containers, and invalid
   completion counters are explicit rejecting cases.

Families 1–6 are exhaustive only over the dimensions and finite values stated above. The checker
does not claim their Cartesian product with each other, arbitrary strings, arbitrary list sizes,
or arbitrary Python object graphs.

## Checker conformance

The checker must first pass against production and prove non-vacuity with concrete accepted and
rejected witnesses for every critical predicate family. It must then reject five intentionally
faulty **abstract acceptance functions**: always accept, always reject, ignore a missing receipt,
collapse duplicate receipts, and ignore native failure. These are checker self-tests, not claims
that five source-level mutants of `llm_harness.py` were compiled and killed. Each self-test records
a concrete generated witness.

## Exclusions

This check does not prove Git inventory completeness or classification, producer truthfulness,
network or container behavior, cryptographic security of hashes, actual source delivery, semantic
model understanding, provider/model identity, or behavior outside the finite domain. It does not
verify arbitrary Python or TypeScript executions and does not replace the live smoke or independent
review required before changing the pinned producer.
