# SV-Agent review-workflow completion consumer

Upstream issue: https://github.com/anshumanbh/securevibes-agent/issues/205

ScanEval acceptance: issue 95 integration acceptance, pending reviewed upstream pin and live smoke.

## Contract reviewed

This consumer was reconciled against upstream branch `fix/review-workflow-completion` at
`8b8aff6d9a868ba2d1bbda23cee882b5f836cc3f` and the normative
`docs/review-workflow-completion.md` at that revision. The corrected wire is pre-merge protocol
development: no released `reviewWorkflow` version exists to grandfather. Legacy summaries without
the additive field retain their existing completion behavior exactly. The Dockerfile and
`DEFAULT_IMAGE_HARNESS_COMMIT` remain pinned to
`f959cbcf010c7e41f780c718b65b1724d3aecb43`.

## Accepted wire

`summary.reviewWorkflow` is a closed version-1 report beside, not instead of,
`summary.completion`. It requires:

- workflow `bootstrap-source-review`, source assessment `unassessed`, and a supported status;
- portable scope containing mode, source ref, inventory digest, digest-preimage name, and policy
  `{version, additionalCodeExtensions}`; no repository path is hashed or accepted in scope;
- inventory entries preserving Git mode, original `classification` and policy `reason`, plus the
  reconciliation-only `disposition`;
- obligations and receipts bound to invocation, model, hypothesis, shard, source ref, request
  digest, response digest, ordered file identities, and exact terminal coverage;
- actual `inputs` with documented roles, byte observations, immutable source identity, and an
  explicit matched/mismatched/untracked/drifted binding;
- planner, execution-anchor, model-call, structural, lint, marker, and specialist stages plus
  concrete planner, anchor, structural-inspection, and effective lint evidence.

Unknown fields, enums, unsafe integers, malformed hashes, non-normalized paths, surrogate-bearing
preimage strings, duplicate identities, and unbounded repeated evidence fail closed.

## Independent reconciliation

The consumer recomputes `scope.inventoryDigest` as SHA-256 of UTF-8 `JSON.stringify`-compatible
serialization over every public preimage field and policy. It preserves JavaScript UTF-16
code-unit ordering for inventory paths and additional extensions. The preimage excludes absolute
repository paths and includes `schemaVersion`, workflow, source ref, policy, and every inventory
field except `disposition`.

Positive credit additionally requires:

1. scope mode and source ref agree with `summary.mode` and `summary.headRef`; the policy agrees with
   the original summary, and the sorted inventory agrees with the original bootstrap file surface;
2. built-in source extensions and declared additional source extensions cannot receive a metadata
   bypass. `README.py`, `LICENSE.js`, and `NOTICE.php` remain source unless the exact supported
   path-exclusion policy applies. Original classification, reason, and derived disposition remain
   distinct and consistent;
3. every supported source is assigned, every obligation file matches inventory bytes/procedures,
   and every obligation has exactly one matching receipt with completed terminals;
4. every native dispatched call has unique invocation/request/response identity and exact ordered
   agreement with its obligation and receipt. Requested or delivered paths outside inventory are
   blocking;
5. every observed primary, related, or configuration/native input is inventory-backed and
   `matched`. Supported primary observations must exactly equal inventory SHA-256 and byte count,
   and every original primary call has corresponding input evidence;
6. the LLM planner is non-heuristic and non-degraded; actual execution-anchor surfaces cover
   supported prefixes; scanner relationship inspections have no failures; effective default or
   custom lint rules match successful native rule results; explicitly disabled lint is honestly
   `not-applicable`; markers and activated specialists are complete;
7. failed, missing, unsupported, stale, drifted, omitted, partial, inconclusive, duplicated, or
   cross-bound evidence remains blocking.

`not-required` is limited to a nonempty all-excluded inventory with no obligations, receipts,
inputs, or native source-review work. Planner, execution-anchor, model-call, and structural stages
must be `not-applicable`; lint, markers, and specialists must still reflect their actual configured
states. A failed or missing stage is never erased merely because the inventory is excluded.

## Legacy completion interaction

`summary.completion` remains required on the image route. A reconciled complete workflow may
coexist with legacy source assessment `unassessed` and structural coverage `not-recorded`.
Corrected version-1 evidence may also explain a legacy `execution_anchor:<prefix>:unsupported`
reason only when the original anchor surface is uniquely recorded and every inventory path in that
exact prefix is an explicit exclusion. Failed anchors, unsupported source, unmatched prefixes, and
all other legacy gaps remain blocking. Findings are preserved on partial outcomes.

The accepted outcome is labelled only a **completed declared bootstrap review workflow**. It does
not attest a provider/model revision, prove semantic understanding, assess source as safe, or make
a whole-repository safety claim. Excluded metadata/configuration is an explicit workflow scope
limitation, not evidence that the file is harmless.

## Fixture, verification, and rollout

`tests/fixtures/sv-review-workflow-summary.json` was captured from an actual deterministic upstream
engine run at `8b8aff6` using an in-process test runner and no model/network call. The bounded
consumer checker exercises 830 finite cases, including all seven stage bits and concrete runtime
simulations that remove digest, input, stage-evidence, and original-call guards. See
[SV completion bounded verification](sv-completion-bounded-verification.md).

Consumer support alone is not scan readiness. A coordinated reviewed upstream pin, image build,
and bounded live smoke remain required before issue 95 or broad-corpus readiness can be claimed.
