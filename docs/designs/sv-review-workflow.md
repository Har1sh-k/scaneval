# SV-Agent review-workflow completion consumer

Upstream issue: https://github.com/anshumanbh/securevibes-agent/issues/205

ScanEval acceptance: issue 95 integration acceptance, pending live smoke and a reviewed upstream pin.

## Problem

The pinned SV-Agent revision reports `summary.completion` version 1, but delivered bootstrap source remains `sourceAssessment: unassessed`. Its aggregate coverage therefore remains `unknown` even when the producer can prove that a declared source-review workflow ran. Treating delivery, an empty findings array, process exit, or `completion.coverage.status` alone as completed analysis would be untruthful.

SV-Agent adds `summary.reviewWorkflow` version 1 as a separate native report. It describes producer-declared workflow execution and binds obligations and receipts to immutable source identities. It does not assess source as safe, prove semantic understanding, attest a provider or served model revision, or replace `summary.completion`. ScanEval must preserve both accounts.

## Accepted wire contract

The consumer accepts only the additive `summary.reviewWorkflow` contract with:

- `schemaVersion: 1`, `workflow: "bootstrap-source-review"`, and `sourceAssessment: "unassessed"`;
- status in `complete`, `incomplete`, `unknown`, or `not-required`;
- scope policy `bootstrap-source-review/v1`, an explicit mode, and bootstrap source identity when evidence is present;
- an immutable inventory whose paths, Git object ids, SHA-256 values, byte counts, dispositions, reasons, and required procedures are explicit;
- frozen obligations binding invocation, model, hypothesis, shard, source ref, request digest, files, source digests, byte counts, and required procedures;
- receipts binding the same identity and files plus response digest and exactly one terminal for every required file/procedure pair;
- explicit model-call, structural, lint, marker, and specialist stage states; and
- a list of native reasons.

`complete` is accepted only for bootstrap. `not-required` is accepted only for a nonempty all-excluded inventory with no obligations or receipts. PR, batch, absent evidence, and unknown versions remain non-success.

## Fail-closed reconciliation

The parser validates required fields, closed enums, safe integer bounds, SHA formats, nonempty identifiers and reasons, normalized relative paths, and uniqueness before interpreting status. Unknown or missing fields never earn credit. Duplicate inventory paths, obligation identities, receipt identities, files, required procedures, or terminals invalidate the report.

The consumer independently reconciles the report:

1. `summary.mode`, `summary.headRef`, workflow scope mode, scope source ref, every inventory source ref, and every obligation/receipt source ref agree.
2. Every supported inventory file has immutable digest and byte evidence and is assigned; excluded files carry no source bytes or procedures; unsupported or unassigned inventory blocks completion.
3. Inventory paths are neither omitted from nor invented by obligations. Every obligation file exactly matches its inventory identity and procedures. A file may be reviewed by more than one obligation, but each obligation is internally unique.
4. Every obligation has exactly one receipt and no receipt is unexpected. Model, hypothesis, revision, shard, invocation, request digest, file set, file digest, byte count, and required procedures match exactly.
5. Every receipt has exactly one terminal for every required pair and no extra terminal. Only `completed` can support positive completion; `inconclusive` blocks it.
6. Model calls and all required workflow stages are complete. Structural `not-applicable` is accepted only for this bootstrap-v1 policy. Failed or unevaluated hypotheses, relationship/source gaps, parser failures, lint gaps, pending markers, incomplete specialists, unsupported code, inventory gaps, and model-call failures remain blocking through the original completion and scan records.
7. A positive native status is checked against the reconciled contents. A contradiction is malformed evidence, not a legacy fallback.

The consumer also validates `summary.completion` version 1. For a reconciled complete workflow only, the legacy aggregate may remain `unknown` solely for `source_analysis_completion_not_established` and `structural_coverage_not_recorded`: the new report explicitly supplies workflow evidence while leaving source assessment unassessed and declaring bootstrap structural traversal not applicable. Any other completion reason remains blocking. Legacy reports without `reviewWorkflow` retain their current behavior exactly.

The inventory is the only place exclusions receive credit. Known non-code files such as `README.md` are accepted only when represented by an exact excluded inventory entry with no fabricated source-review procedures; no path-prefix or extension-wide suppression is added in ScanEval.

## Outcome semantics

A valid and reconciled `status: complete` permits the adapter's native outcome to be `success` only after all existing execution, model-call, native scan-status, import-loss, and runtime-identity checks also pass. The execution notes label this narrowly as a **completed declared review workflow**. They do not call the source safe or assessed.

`incomplete`, `unknown`, malformed, unsupported-mode, contradictory, or missing required workflow evidence produces `partial` on a run whose findings are still usable. Imported findings are retained. No partial outcome receives zero-detection or quiet-scan credit. Existing higher-priority timeout, runtime mismatch, driver, model-call, inconclusive-scan, and import-loss outcomes remain truthful; workflow notes survive beside them.

The new contract is optional for legacy local harnesses. Once present, it is authoritative enough to fail closed: malformed new evidence cannot fall back to legacy success. The image route continues to require native completion reporting.

## Pinning and rollout

The Dockerfile and default image harness commit remain at `f959cbcf010c7e41f780c718b65b1724d3aecb43` until the upstream implementation receives fresh review and is committed. Before that coordinated pin update, smoke configurations opt in by supplying the exact reviewed commit through the existing `expected_harness_commit` override and an image built from that same commit.

Acceptance requires focused parser, reconciliation, native-outcome, legacy-compatibility, and JSON round-trip tests, followed by the bounded live smoke. The consumer decision boundary also has a [711-case bounded generated conformance check](sv-completion-bounded-verification.md), which exercises the actual Python readers but is not a full formal proof. This design does not claim issue 95 resolved or the broader corpus ready before that live acceptance passes.
