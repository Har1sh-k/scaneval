# Scanner adapter failure patterns

Use these lessons when the relevant boundary exists. Each check asks for observable evidence rather than a prose assertion.

## Completion without positive source evidence

**Symptom:** Model calls succeed, findings are delivered, and the scanner exits normally, but the adapter cannot establish that the intended source population was completely reviewed. An empty finding set is then at risk of being reported as a completed zero-detection scan.

**Cause:** The completion contract reports transport or delivery but has no positive, per-source assessment. For SV-Agent, the pinned `f959cbcf010c7e41f780c718b65b1724d3aecb43` and observed upstream `82a0db6` completion schema v1 do not provide a positive source-assessment state; bootstrap evidence also lacks sufficient structural provenance and ref-bound receipts. Successful calls, delivery, and findings therefore do not establish complete review. A legacy build with no usable completion report is unknown, not successful silence.

ScanEval's current local legacy `llm-harness` route calls `read_completion(..., required=False)` and historically tolerates an absent report. The distinct `oci_image` route, which runs only through the OCI backend, calls it with `required=True` and rejects absence as unreadable evidence. This skill's stricter policy is intended guidance for sound adapters, not a claim that every current ScanEval path already enforces it.

**Corrective action:** Define a versioned evidence contract and immutable source inventory. Bind evidence to each obligation: source/ref, required inspection, model-call health, native stage, omitted scope, and import conservation. Seek a real-source successful fixture that satisfies every obligation, plus meaningful fixtures that fail each obligation, before any long run. If no such positive fixture is attainable, record the capability gap, keep runs partial, and stop broad execution rather than fabricating a witness or weakening the obligations. Preserve findings from partial runs, but do not award quiet or zero-detection credit. Keep omissions visible.

The upstream proposal is tracked by [securevibes-agent issue #205](https://github.com/anshumanbh/securevibes-agent/issues/205) and the consumer work by [ScanEval issue #95](https://github.com/Har1sh-k/scaneval/issues/95). Treat the fix as **unmerged and unresolved** until immutable upstream code and consumer verification show otherwise.

**Regression/acceptance check:** A fixture over real source reaches `success` only with positive evidence for every required source obligation. Missing, malformed, contradictory, incomplete, or unknown completion yields `partial` or `error` as specified, retains findings, and cannot become a zero detection score.

## Treating a canonical digest as classification proof

**Symptom:** A self-consistent inventory digest is accepted even though an excluded file could not legitimately receive its claimed native classification or reason.

**Cause:** A digest binds bytes; it does not validate their meaning. Every exclusion must satisfy the exact versioned producer policy in both directions. Unknown or executable content must not forge known-non-code, configuration, metadata, or code-scope exclusions. Cross-language details can also disagree: JavaScript trimming can remove leading U+FEFF where Python stripping does not, and UTF-16 ordering can differ from code-point ordering. Normalizing such a bound path after hashing changes the asserted identity.

**Corrective action:** Validate classification and reason against the pinned producer policy while preserving the original hashed identity; reject ambiguous bound paths rather than normalizing them into agreement. Use producer conformance probes, positive examples for each legitimate exclusion family, and self-consistent forgery counterexamples. If a native summary is malformed, preserve usable findings and return the specified incomplete outcome instead of crashing.

**Regression/acceptance check:** Each exclusion is accepted only for its exact classification/reason pair. A forged policy remains rejected after recomputing its digest; ordering or U+FEFF ambiguity is refused; malformed summaries retain findings.

## A diagnostic instruction that never reached the model

**Symptom:** A live diagnostic appears to ask the model to use web research or Git history, tools are registered, and network preflight succeeds, yet no model-issued research/history call exists.

**Cause:** The instruction was placed in a fixture README that the scanner never delivered in its actual prompts. Tool availability and operator-side preflight prove capability or transport only. They do not prove that the model was asked to use a tool, chose it, received its result, or used it in a finding. Prompt defaults and explicit prompts may travel through different paths.

**Corrective action:** When the scanner has a model/tool boundary, put the probe in the exact input channel the real scanner/model invocation consumes. Preserve whether text came from a native prompt, a default, stdin, a system layer, or source documentation. Require recorded model-issued tool calls and matching Git/retrieval receipts; never fabricate or infer tool use from availability. A production scan may legitimately require no research, so label a forced-tool probe as a capability smoke rather than evidence about ordinary scanner behavior. For a rule-based scanner, use its native positive criterion—such as a known rule match joined to stage and artifact receipts—instead of inventing a model-call requirement.

**Regression/acceptance check:** For model/tool workflows, capture the actual delivered prompt/request, show the intended instruction in that request, then join each model-issued call to its tool execution and retrieval/Git receipt. A preflight-only run passes transport checks but fails the model-use probe. For rule-based workflows, require the declared native positive witness and receipts without any model call.

## Conflating DeepSec stages and candidate populations

**Symptom:** `scan` found regex candidates, `process` timed out or lost batches, or `export` failed, but the invocation is described as a successful AI scan. Conversely, no regex candidate is described as a failed AI detection. A zero-finding toy run is used as an accuracy claim.

**Cause:** DeepSec has distinct native stages and populations: regex triage, model investigation/selection, and exported findings. Exit codes alone do not encode every outcome, and findings from completed batches can coexist with failed or unfinished batches. A model cannot miss a candidate it was never invoked to examine.

**Corrective action:** Require native `scan -> process -> export` completion for a successful full run, or the scanner's documented native PR path followed by export. Preserve findings when a batch fails, but mark the run partial/error according to observed coverage. Record regex candidates separately from model-selected or curated intersections. Treat “no candidate, therefore no AI batch” as a triage outcome, not a failed AI call.

**Regression/acceptance check:** Fixtures cover each stage failing or timing out, mixed successful/failed batches, unreadable exports, no-candidate runs, and findings plus failure. The fake must exit exactly as the pinned binary does in each of those cases: 2.3.10's standard-mode `process` exits 1 for an errored batch or an exhausted quota after writing every record, and a fake that exited 0 there hid a full-run path that discarded every finished batch's claims. Assert stage receipts, population counts, conservation, preserved findings, and truthful status. A zero-finding toy file establishes only that invocation's output; it does not measure accuracy, prove a false negative, or validate an open-context condition.

## Reconstructing identity from a lossy native export

**Symptom:** Exported claims receive the wrong native IDs through path/title or FIFO pairing, or expected exclusions, unreadable entries, and missing exports are counted as independent losses even though the export still contains usable claims.

**Cause:** DeepSec 2.3.10's default JSON export omits finding IDs and sorts its rows. Its eligible population excludes resolved findings and findings in schema-valid records with no latest analysis; malformed records or findings are native load failures, not legitimate exclusions. Repeated rows can share path and title, and an unreadable or unjoinable export entry may be the same occurrence as an unmatched record, so order and additive subtraction invent certainty.

**Corrective action:** Reproduce the pinned native load and default-export eligibility before reconciliation. Join only on fields copied unchanged into the export, use the native optional-ID algorithm when the version supports it, preserve raw record/export bytes, and compare multisets rather than sets. If export-visible fields cannot distinguish distinct native IDs, retain every usable claim without an ID and mark the run partial. Report honest lower and upper omission bounds without counting one unidentified export twice, and preserve established fatal, stage, and partial-failure priorities.

**Regression/acceptance check:** Cover valid resolved and no-latest exclusions, malformed lookalikes that fail closed, native sort reordering, repeated identities, duplicate-ID multiplicity, distinct indistinguishable IDs, and damaged export entries. Claims remain available, exclusions are not import loss, ambiguous IDs are never guessed, and loss bounds/status precedence remain stable.

## Letting the host parser define the native record contract

**Symptom:** An adapter accepts a record the native scanner rejects, rejects an explicit null the native schema requires, or discards every finding because one finding is malformed. A synthetic test is then described as proof of a real scan or provider integration.

**Cause:** Host JSON and schema behavior is not automatically native behavior. Python parsing can accept non-standard numeric constants that JavaScript `JSON.parse` rejects; nullable keys can still be required; and DeepSec 2.3.10 validates the record envelope before salvaging findings per record. Loose structural equivalence misses those distinctions.

**Corrective action:** Mirror strict JSON parsing across all fields, including unknown ones, and the pinned required/nullable and envelope-versus-finding salvage rules needed for the claim. Preserve usable claims and raw bytes when another record or finding fails. A bounded native export-only fixture made from fabricated records may verify exporter loading, filtering, sorting, and output shape without launching an LLM security scan; report it as exporter integration only, not end-to-end scanner, model, authentication, or provider validation.

**Regression/acceptance check:** Exercise non-standard constants in records and exports, missing versus explicit-null required keys, malformed envelopes, and per-finding salvage. The fabricated native fixture invokes only export, demonstrates the expected lossy format and eligibility behavior, and is never promoted into a live-scan or detection claim.

## Mistaking host configuration for the scanner's effective runtime

**Symptom:** The report names a model or SDK because it was requested or because a host CLI reports that version, while the scanner actually uses an embedded SDK/client or a differently resolved native model string.

**Cause:** Scanner model strings can be interpreted by the scanner's own configuration and bundled dependency graph. The host Pi/Claude/Codex CLI version is not evidence of DeepSec's embedded Agent SDK version. A scanner/client self-report is also not provider attestation of the served model revision.

**Corrective action:** Record the immutable scanner version, generated/native effective configuration, exact argv, bundled lockfile/package versions, embedded model SDK/client version, requested route, scanner-reported effective model, and any provider-attested identity as separate fields. Refuse route/model drift instead of silently switching. Mark requested and client-reported identity at their actual assurance level.

**Regression/acceptance check:** A fixture with a requested/effective mismatch cannot report verified identity. Runtime receipts bind to the scanner installation or image actually executed, and tests fail if a host tool version is substituted for an embedded dependency.

## Inventing certainty while mapping native finding kinds

**Symptom:** A real scanner payload contains a native kind outside the adapter's vocabulary. Fuzzy normalization maps it to a plausible canonical kind, hiding that the mapping was never established.

**Cause:** Native vocabularies differ by producer and version. Titles, prefixes, broad labels such as `rce`, and near matches are insufficient evidence for an exact canonical category.

**Corrective action:** Preserve native rule/class/kind identity and use an exact producer-specific, versioned mapping supported by scanner source or real payloads. Unknown and near-match values remain explicitly `unmapped`. Never infer a kind from finding prose merely to avoid an unknown.

ScanEval's merged [PR #101](https://github.com/Har1sh-k/scaneval/pull/101) added exact DeepSec 2.3.10 mappings for `missing-auth`, `acl-check`, and `go-command-injection`; it deliberately left unknown values unmapped. The supporting contract is tracked in [issue #100](https://github.com/Har1sh-k/scaneval/issues/100).

**Regression/acceptance check:** Test real-shaped scanner payloads, exact known codes, near matches, broad/unknown values, native identity preservation, and the recorded mapping version. Classification remains separate from finding truth or target matching.

## Declaring open context without the condition

**Symptom:** A run is called open-context because a local config says network is allowed, Git exists, or a scanner can theoretically browse. A runtime that cannot enforce or observe the condition is run anyway. A native PR request quietly becomes a full-head scan.

**Cause:** Local network declarations are often unenforced. A normal exported snapshot may carry synthetic or truncated Git state rather than authentic scoped ancestry. Capability is not use, and unsupported modes do not become supported through fallback.

**Corrective action:** Require authentic scoped ancestor history with an immutable object/ref inventory, admitted public egress with externally observed allow/deny evidence, and captured retrieval/tool receipts at the integration boundary. Record provider-side visibility gaps. Return `unsupported` for an incompatible runtime or mode. Never substitute a full-head scan for native PR diff review. Keep future commits, repairs, labels, and other ground truth outside scanner-visible history and source.

**Regression/acceptance check:** Demonstrate that the scanner can see the admitted ancestor and cannot see a later commit; show public retrieval and private/denied retrieval behavior; verify read-only source/history and observer receipts. Unsupported runtime/mode fixtures launch nothing and remain in evaluation accounting.

## Treating process exit as cleanup and stage proof

**Symptom:** The adapter sees a direct child or container exit and assumes all descendants stopped and all stages completed. A timeout leaves agents running. A retry reuses a terminal guard or output directory, mixing evidence from attempts.

**Cause:** Child processes can outlive their parent or container-facing command. Cancellation may not propagate through SDKs. Exit status says nothing about artifacts that were never written or descendants still mutating them. Reusing identifiers destroys attempt immutability.

**Corrective action:** Use bounded shared deadlines, explicit cancellation, process-group or container cleanup, bounded reap checks, and per-stage receipts. Capture the exact runtime receipt before trusting output. Treat terminal guard/run identifiers as immutable; use a fresh directory and identifiers for every attempt. Never commit credentials, raw source, prompts, findings, or unsanitized traces in design notes or result samples.

**Regression/acceptance check:** Timeout and interruption fixtures prove descendants are gone or report cleanup failure, retain partial stdout/stderr, and cannot become success. A retry cannot open an existing create-only output or mutate a terminal record.

## Trusting host state instead of the execution seam

**Symptom:** A guard or wrapper works interactively but not through the adapter: restricted subprocess setup strips its configuration, a non-executable wrapper falls back to another CLI, or prepared/pending verification state is treated as permission to launch.

**Cause:** The caller's environment and PATH are not the scanner's effective environment. Readiness was published before exact pins and checks completed, and attempt ownership or cleanup was inferred rather than observed.

**Corrective action:** Make the launcher supply its own exact configuration, then verify the wrapper is executable and the resolved CLI is the intended binary before execution. Pending state never authorizes execution; publish ready state only after all checks pass. Bind resources to the exact attempt, retain the failed command and partial artifacts, and clean up owned process groups, containers, and networks before reporting completion.

**Regression/acceptance check:** Exercise the real environment-filtering seam, missing execute bits and CLI fallback, pending pins, cross-attempt ownership, failed commands with partial artifacts, and cleanup failures. Cleanup failure blocks completion. Report the covered regressions; do not claim all future failures are prevented.

## Promoting deterministic tests into integration or benchmark evidence

**Symptom:** Unit tests and fake providers pass, then the adapter is described as validated against the real scanner/provider. Partial and unsupported runs disappear from reported denominators, or numbers are published before schemas and replay are checked.

**Cause:** Synthetic providers establish deterministic adapter behavior, not authentication, provider routing, scanner packaging, live network behavior, model quality, or corpus-label validity. Filtering failed assignments changes the population after observation.

**Corrective action:** Report four layers separately:

1. deterministic contract/unit tests;
2. one bounded authorized live integration smoke;
3. detection results over a frozen assignment set;
4. label, control, and publication readiness.

Validate normalized schemas and exact offline replay before reporting results. Preserve unsupported, partial, error, and timeout assignments in the denominator required by the evaluator; do not quietly drop them or turn unresolved completion into success. Obtain independent review before expanding beyond the smoke.

**Regression/acceptance check:** The saved bundle validates and replays without scanner/network access. Reports enumerate every scheduled assignment and status, identify the evidence level of each claim, and make no detection or readiness statement from fake-provider tests alone.

## Repository evidence to inspect

When working in ScanEval, these are search guidance rather than dependencies of this copied skill:

- `src/scaneval/adapters/base.py`: adapter boundary, statuses, execution seam, timeout cleanup.
- `src/scaneval/adapters/deepsec.py`: native stages, batch failures, model identity, exact kind mapping, omitted scope.
- `src/scaneval/adapters/llm_harness.py`: completion evidence, image/runtime receipts, unsupported and partial handling.
- `src/scaneval/mappings/kinds.json`: versioned native-to-canonical vocabulary.
- `docs/INITIAL_BUILD.md`, `docs/OPEN_CONTEXT.md`, and `docs/designs/sv-agent-open-context.md`: current execution, replay, and condition contracts.
- `tests/test_v2_deepsec.py`, `tests/test_v2_sv_open_context.py`, and `tests/test_v2_sv_open_context_docker.py`: deterministic and real-boundary fixture expectations.

In another repository, locate the equivalent protocol, runner, schemas, native payload fixtures, and condition/evidence documentation rather than assuming these paths exist.
