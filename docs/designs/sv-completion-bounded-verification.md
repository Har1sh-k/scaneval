# SV completion bounded verification

ScanEval issue: https://github.com/Har1sh-k/scaneval/issues/104

Method reference: [Anthropic, *Formal verification for AI-generated code*](https://www.anthropic.com/research/formal-verification).

## Claim

This checker calls the real `read_review_workflow` and `read_completion` entrypoints in
`src/scaneval/adapters/llm_harness.py` for every generated case and compares their joint decision
with an independently stated finite oracle. It is **bounded generated verification and concrete
conformance**, not a Rocq/Lean proof and not a proof over arbitrary Python executions.

The checked property is:

> An accepted corrected review workflow has a nonempty immutable inventory containing only fully
> assigned supported source plus explicit exclusions, or it is the separately valid all-excluded
> `not-required` case. Its public inventory digest, policy, original classifications, native input
> observations, original call identities, obligations, receipts, terminals, and concrete stage
> evidence agree exactly. Unsupported, unassigned, untracked, drifted, stale, duplicate, omitted,
> partial, inconclusive, failed-stage, or failed/pending-call evidence cannot acquire success.
> Legacy source assessment remains unassessed.

Acceptance means both production readers return no error code. Adapter timeout, runtime identity,
import loss, and outer execution gates remain separate.

## Independent oracle and materializer

The oracle is expressed over abstract inventory entries, obligation/receipt multisets, terminal
pairs, stage bits, native health flags, and legacy-completion states. It does not call production
shape or reconciliation helpers. A deterministic materializer emits the corrected wire, including
canonical digest, original dispatched-call identity, matched primary inputs, planner/anchor/
structural/lint evidence, and legacy completion. The healthy outer template is
`tests/fixtures/sv-review-workflow-summary.json`, regenerated from a deterministic upstream engine
run whose imports were bound to producer head `73ae7aa9ba14425abb066306cfabfea4fd83d3eb`, with no
model/network call. Its legitimate `README.md` metadata exclusion remains part of a complete
workflow.

The trusted computing base is the oracle, materializer, fixture, Python runtime, and checker. The
checker emits source SHA-256 values and the current Git revision; generated JSON stays outside the
repository.

## Finite domain: 834 cases

1. **Inventory/assignment product — 144.** One or two files; one or two procedures; each file is
   supported, unassigned, or unsupported; every ordered obligation plan of length zero, one, or two
   over nonempty source subsets.
2. **Receipt pairing/binding product — 288.** One or two obligations; independent receipt
   multiplicity zero/one/two; exact or swapped invocation, model, hypothesis, shard, source ref,
   request digest, or file identity; completed, inconclusive, or missing terminals.
3. **Terminal product — 102.** One or two files and procedures, with every required pair independently
   completed, inconclusive, or missing.
4. **Declared stage product — 128.** Full `2^7` healthy/failing product for planner,
   execution-anchor, model-call, structural, lint, marker, and specialist stages.
5. **Original native-health product — 32.** Full `2^5` product for bootstrap model health, source
   delivery, repository lint, marker assessment, and specialist completion.
6. **Legacy-completion compatibility — 90.** Three call-health states, five reason sets, two source
   delivery states, and three structural states.
7. **All-excluded reachability — 1.** Nonempty exclusion-only inventory with exact `not-required`
   stages and no review work.
8. **Finding reachability — 2.** Valid independent two-file workflows with zero and one finding.
9. **Malformed boundaries — 20.** Container/type/integer, duplicate, procedure, file, terminal, and
   completion-counter boundaries.
10. **Corrected-contract guards — 27.** Digest/preimage, policy, metadata-named code, a positive
    documented `README.md` exclusion, self-consistent forged metadata reasons on unknown,
    executable, and arbitrary extensionless names, additional source extensions, inputs,
    planner/anchor/structural evidence, disabled lint, original invocation/request/response
    identity, obligation bytes, head/mode/model cardinality, positive reasons, out-of-inventory
    calls, `not-required` stage failure, and unknown field/enum cases.

Families are exhaustive only over their documented dimensions, not their Cartesian product or
arbitrary object graphs.

## Non-vacuity and faulty-function checks

The checker requires accepted witnesses for complete workflows, all-excluded `not-required`,
explicitly disabled lint, zero findings, nonzero findings, and independent multi-file review. It
also requires rejecting witnesses for every critical family.

Five intentionally faulty **abstract acceptance functions** remain honestly labelled as checker
self-tests: always accept, always reject, ignore missing receipt, collapse duplicate receipts, and
ignore native failure. They are not source mutants or formal proofs.

Five additional checks temporarily remove actual production guards at runtime and require a
concrete counterexample:

- canonical inventory digest mismatch;
- mismatched input binding;
- planner stage-evidence mismatch;
- original native-call to obligation/receipt binding;
- forged recognized-repository-metadata policy on an unsupported suffix.

Each guard-removal witness is first rejected by unmodified production and then accepted only by the
faulty patched decision. This verifies that digest, input, stage, original-call, and metadata-policy
negatives are meaningful rather than tag-only oracle cases.

## Reproduction

```bash
PYTHONPATH=$PWD/src .venv/bin/python \
  scripts/check_sv_completion_properties.py \
  --output /private/tmp/scaneval-sv-completion-properties.json

PYTHONPATH=$PWD/src .venv/bin/python -m pytest -q \
  tests/test_sv_completion_properties.py

PYTHONPATH=$PWD/src .venv/bin/python -m pytest -q \
  tests/test_v2_llm_harness.py \
  -k 'review_workflow or completed_declared_review_workflow or legacy_completion_without_review_workflow'
```

A conforming run reports `checked: 834`, `expected_accepted: 35`,
`expected_rejected: 799`, no production mismatch, all required witnesses, and all ten faulty
functions detected. Plain `pytest` collection is supported because the test loads the checker by
absolute file path rather than relying on the repository root being on `sys.path`.

## Exclusions

This checker does not prove producer truthfulness, Git inventory capture, actual source delivery,
cryptographic security, semantic model understanding, provider identity, network/container
behavior, or behavior outside the finite domain. It does not replace fresh review, Anshuman's pending review
of upstream PR 206, the coordinated upstream pin, or bounded live smoke; it makes no readiness
claim.
