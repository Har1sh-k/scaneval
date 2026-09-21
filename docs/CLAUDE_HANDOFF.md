# Claude continuation prompt

Continue implementing ScanEval in this repository. An offline evaluator, a case-pack workflow, a live invocation runner, two real adapters, an observer connection to the own harness, and a review workflow already exist. Audit and extend them; do not restart from an empty project or treat the complete design as implemented.

## Start here

Repository: the `scaneval` checkout this document sits in.

Working branch: `feat/evaluation-core`, created from `docs/design-decisions`. Inspect the current branch, status, and recent commits before editing. Do not reset, overwrite unrelated changes, or move back to `main`. Leave the untracked `docs/archive/` directory alone unless the user explicitly asks otherwise.

Existing implementation commits:

- `0e04a84`: deterministic saved-output evaluator, versioned contracts, CLI, report, and conformance tests.
- `82c88ca`: opt-in TypeScript observer SDK, event contract, capture safeguards, and tests.
- `53be6af`: repository inventory and CVE candidate research. These are research leads, not admitted labels.
- `e5ad383`: immutable source cache and pinned snapshot export.
- `2c8b735`: invocation runner, adapter protocol, and the pinned Semgrep adapter.
- `5ca9935`: own-harness adapter with the observer wrapped around the model boundary.
- `48494c9`: case-pack contracts, mechanical checks, and plan generation.
- `8a1453e`: draft review decisions, review records, and explicit approval.
- `fbdad50`, `59e25d1`: frozen run-configuration execution and the `corpus`, `plan`, `review`, `run` commands.
- `d36d4a8`, `c47a434`, `c2830d3`, `ca53346`, `16726ec`: the draft pilot pack with its fix-hunk evidence, the two preserved pilot runs, and the pilot report.
- `f9fb52a`, `fa3b3f1`: private-pack case identifiers and the bring-your-own-corpus guide.

Run `git log --oneline` before relying on this list; work was landing while it was written.

Read these files before planning implementation:

1. `docs/DESIGN_DECISIONS.md`: intended product behavior and agreed boundaries.
2. `docs/EVALUATION_MATH.md`: scoring definitions, missing-data treatment, and reporting rules.
3. `docs/INITIAL_BUILD.md`: what this branch actually implements and what is missing.
4. `docs/PILOT.md`: the first real runs, their execution facts, and what they do not establish.
5. `docs/OBSERVER_SDK.md`: event integration, passivity, flushing, and capture limitations.
6. `docs/BRING_YOUR_OWN_CORPUS.md`: the organization-owned pack path as the code implements it.
7. `docs/REPOSITORY_INVENTORY.md` and `docs/CVE_CORPUS_SHORTLIST.md`: source leads and candidate dossiers.
8. `src/scaneval/`, `sdk/typescript/`, `schema/v2/`, `corpus/pilot/`, and `tests/test_v2*`: current code, preserved runs, and executable invariants.

The design and math describe the destination. The initial-build guide and inspected code describe current capabilities. Do not silently change a design decision to accommodate a shortcut in the alpha implementation.

## What we are building

ScanEval supplies a versioned real-world vulnerability corpus, evaluation tools, and a thin SDK for visibility into security scanner harnesses. Users should be able to compare scanners or harness configurations, understand recorded failure points, and evaluate against their own organization's security fixes and findings.

The benchmark is not the separate engineering agent that modifies a scanner. A future project may consume evaluation results and traces, propose harness changes, and rerun comparisons. Keep that optimization agent outside this repository. Do not add automatic model training, prompt optimization, or self-modifying evaluators.

The first release evaluates public workloads. Do not claim that public-case results prove zero-day capability, lack of memorization, or resistance to benchmark-specific tuning. Prior knowledge can earn detection credit when the allegation is correct for the evaluated snapshot.

## Current implementation

- Python package `scaneval`, alpha version `2.0.0a1`.
- `scaneval validate`, `score`, `replay`, `report`, `demo`, `corpus`, `plan`, `review`, and `run` commands. `corpus` has `init`, `add-snapshot`, `import`, `validate`, `approve`, `admit`, `disposition`; `review` has `init`, `record`, `approve`, `status`.
- `evaluate(plan, saved_result, frozen_decisions)` library entry point. This does not run an agent.
- Nine strict JSON contracts: `scan-request`, `scan-result`, `execution-record`, `evaluation-plan`, `review-decisions`, `review-record`, `case-pack`, `run-config`, `run-manifest`.
- Case packs with pinned snapshots, drafted cases, six mechanical (L1) checks per snapshot, recorded human approvals, admissions, and dispositions. Plan generation degrades to the lowest label state present.
- Immutable source cache and pinned snapshot export with a recorded tree hash, stripped controller state, recorded instruction files, and preparation provenance. Only the `standard` profile is implemented; `metadata_blinded` is refused rather than downgraded.
- An invocation runner that executes a frozen run configuration, freezes the pack copy, prepares each input, invokes each system per input per repetition into its own bundle, and writes a run manifest. A failure after the output directory exists writes a `failed` manifest rather than losing what finished.
- Two real adapters: `semgrep` against a pinned local rules checkout with no registry download, and `llm-harness` running the securevibes-agent/Fieldglass engine through its own entry point. Only the securevibes-agent preset has been exercised against a live model, in `bootstrap` mode.
- The TypeScript observer is connected to the own harness through `src/scaneval/adapters/llm_harness_driver.mts`, which wraps the harness's default model runner and emits model request/response, context selection from the harness's own progress notes, and finding submission.
- A review workflow: machine-drafted decisions routed by accepted location path, all unresolved; `review record` re-drafts after a human edits the decisions; `review approve` records one explicit human approval bound to the saved result.
- One-input scoring against all assigned targets and controls, with exact-duplicate handling, first-hit ranks, budgeted/full-output recall, unranked diagnostics, and completed-control bounds.
- A fabricated conformance demo and standalone HTML score report. No real scanner runs in the demo.
- A TypeScript observer emitter with explicit model/tool/context/finding events, recording modes, redaction of supplied copies, failure isolation, capture-gap state, and `flush()`.
- Three real runs, described in `docs/PILOT.md`. The records are not committed; the frozen run configurations in `corpus/pilot/` reproduce them. They are pipeline demonstrations, not results.
- Legacy `scripts/` and adapters remain unchanged and continue using old semantics. Do not assume their output or behavior conforms to the new contracts.

Last verified on this checkout: 663 Python tests passed, 2 legacy snapshot tests skipped because their checkouts were unavailable; 13 TypeScript tests passed. The Python count moved during the session that recorded it, so treat it as a floor and recheck on the current checkout rather than as a permanent guarantee.

**The corpus remains draft.** The pilot pack `corpus/pilot/pack.json` holds three cases, all `mechanically_checked` at L1 with disposition `needs_evidence` and no admission record. Every plan built from it therefore has `draft` scope, every matching decision in the preserved runs is `unresolved`, and confirmed detection is zero. Do not present any number from this repository as a detection result.

Important limitations:

- Matching is supplied through frozen evaluator decisions. The code does not establish root-cause correctness from arbitrary scanner prose. Routing proposes candidates by accepted location path only; path equality is not an allegation.
- A declared L3/L4 field is not proof of independent review. Case evidence records and admission decisions exist as contracts and commands, but no case has been reviewed or admitted.
- Mechanical checks establish artifacts, paths, and ranges. They do not parse source, establish a root cause, or approve anything, so no check raises a case past L1.
- Saved-result hashing is not source-tree verification, a digital signature, or sandbox enforcement. The demo's input hash uses a path/content map. A `human_approved` review record is the record's own assertion, not a verified one.
- Directory separation and the path checks that keep evaluator material out of a trial directory are documented boundaries, not isolation. The declared network policy is recorded and never enforced by this package.
- The observer connection captures the model boundary of the own harness only. Tool dispatch is `unavailable` on every real route because it happens inside the model CLI subprocess; an unavailable category establishes nothing about whether that activity happened. Candidate creation, validation, and filtering are unavailable, and token usage and in-runner retries are not observable at that boundary.
- No native/SARIF importer for saved vendor output, exporter, enforced isolation policy, multi-model planner, trace viewer, corpus aggregation, pair aggregation, precision sampling, promotion gate, native PR mode through an adapter, metadata blinding, or semantic duplicate review is implemented.
- Control rates use completed observations. `observed_false_allegations` separately retains explicit reviewed allegations from incomplete output; do not erase those observations or include incomplete scans in a completed-only denominator.
- The pilot pack defines no controls, so control rates are N/A rather than zero and no fixed-state snapshot has been prepared.

## Immediate objective

The end-to-end slice is built and exercised: three prepared inputs, four real scanner invocations across two systems, preserved native output, machine-drafted decisions, observed harness model events, and offline replay. `docs/PILOT.md` records it. The organization-owned pack path runs through the same interface and is documented in `docs/BRING_YOUR_OWN_CORPUS.md`.

What is missing is the human half. The next objective is to turn the preserved runs into reviewed evidence: human review of the routed candidates through `scaneval review record` and `scaneval review approve`, and independent review of the three case labels to L3 through `scaneval corpus approve` and `scaneval corpus admit`. That is the only path to a non-zero recall and the only path out of draft scope. After that, prepare fixed-state snapshots so the cases have property-specific negative controls, then run the own harness on the remaining inputs with repetitions before any comparison between systems.

Start with a short plan grounded in the existing code. Use the milestones below, but complete and test one vertical slice before expanding the platform.

### 1. Select and prepare a small real-case pilot

**Status: a first pilot pack exists and is draft.** `corpus/pilot/pack.json` holds three cases on three pinned snapshots: Go, Python, and JavaScript; conventional application, agentic application, conventional application. Every commit was verified against its repository. All three are `mechanically_checked` at L1 with disposition `needs_evidence`, none is admitted, and there is no Rust case, no conventional-automation case, no AI-assisted-application case, and no control of any kind. Next step: independent review of these three labels to L3, then coverage of the missing language and workload cells. The guidance below still governs every case added.

- Initial language scope is Python, TypeScript/JavaScript, Go, and Rust. Count the language of the vulnerable implementation, not the repository's frontend or wrappers. Do not add more languages just to enlarge the corpus.
- The inventory contains 103 source leads and the shortlist contains 30 candidates. Verify exact versions, source, fixes, and assumptions before using any candidate. Neither a CVE identifier nor a maintainer patch automatically validates our snapshot-specific scoring label.
- Start with a few high-evidence, distinct mechanisms. Prefer a small runnable pilot over cloning every repository. Cover more than one workflow and repository as evidence allows; do not pretend this first slice represents all four languages equally.
- Workload categories are conventional applications, conventional automation, AI-assisted applications, and agentic workflows. Classify the evaluated mechanism. Application/library/infrastructure and production-use evidence are separate attributes.
- Do not force Gaussian severity counts, arbitrary equal CVE totals, or a fixed repeat count. Severity is not detection difficulty. Select useful mechanisms and justified independent replication, disclose gaps, and avoid domination by one repository.
- Record the issue's source/actor, trust or authorization boundary, guard failure, analysis span, applicable assumptions, and accepted reporting evidence. Endpoint and parameter fields are optional when relevant, not universal substitutes for the root cause.
- Every candidate needs: "This case tests [mechanism] under [assumptions], and adds [coverage gap or justified replication]."
- Preserve dispositions: validate, needs evidence, extended regression, or exclude. Keep draft, mechanically checked, and human-approved states separate. Do not assign independent-review approval yourself.
- Use CVE Program records, maintainer advisories, and exact source/fixes together. Deduplicate CVE/GHSA aliases. Dependency-version alerts alone are not SAST targets unless the vulnerable implementation is in scope.
- Prefer validated previous fixes as property-specific negative-control candidates. A fixed repository is not globally vulnerability-free. Intentional command/file/network capabilities are safe only under explicit reviewed authorization and deployment assumptions.
- Draft the evidence for human review. If required approval is missing, continue testing the pipeline with clearly marked draft/diagnostic records rather than inventing approval or publishing reviewed scores.

### 2. Materialize and invoke once per applicable input

**Status: built for full scans.** `scaneval.materialize` keeps the cache immutable and exports a pinned snapshot with a recorded tree hash and provenance; `scaneval.runner` groups execution by prepared input, system, and repetition, and scores every planned target and control from one output. Raw output, exit status, timeout and partial behavior, tool and ruleset versions, model identity, configuration, timing, usage, and per-category capture are all preserved in the execution record. Still missing: enforced network and filesystem policy (the declared policy is recorded only), the `metadata_blinded` profile, native PR mode, and repetitions greater than one in practice. The guidance below still governs.

- Keep the source cache immutable. Export a pinned snapshot to an isolated trial directory and record exact hashes and preparation provenance.
- Group execution by actual prepared input, scan scope, configuration, and repetition. Score every applicable target/control from that output rather than rescanning separately for each CVE.
- Shared versions can cover multiple vulnerable targets. Later planned snapshots can supply repaired controls for earlier targets, but only when the repair and scope are validated. A CVE range alone does not establish that control.
- Use only `standard` and `metadata_blinded` profiles. Both remove original git history and evaluator artifacts. Standard preserves ordinary source identity; metadata blinding permits reviewed non-runtime metadata edits only. Do not rename imports, packages, or source symbols, invent 20 historical commits, or prompt the model to announce CVEs.
- For native PR mode, invoke the harness once with its real diff-review interface and necessary repository context. Do not replace it with two independent full scans. If git history is operationally required, construct only the minimum validated base/head representation and record it. Controls outside the review scope cannot earn silence credit.
- Provision needed dependencies in a separately recorded preparation phase, then enforce the declared execution network policy. Never expose evaluator labels, fix explanations, or decision files to the scanner. Directory names alone are not an isolation boundary.
- Preserve raw output, exit status, timeout/partial behavior, tool/ruleset versions, resolved model identity, configuration, timing, usage, and capture availability. Do not turn execution errors into empty successful scans.

### 3. Add the first real adapter and observer integration

**Status: both adapters exist and the observer is connected.** The own harness is `~/Documents/GitHub/securevibes-agent`, run unchanged through its own engine entry point inside its own `tsx`; the driver injects only the harness's default model runner wrapped by the observer plus a progress reporter, and no patch to that repository was needed. The pinned conventional scanner path is Semgrep OSS against a local rules checkout, independent of Inspect and Harbor. Finding submission is linked by the harness's own finding ids. Still missing: tool-dispatch visibility (it happens inside the model CLI subprocess), the candidate, validation, and filtering stages, token usage, tracing-on/off parity tests against a live route, and native PR mode. The guidance below still governs, in particular the rule that an unobserved category is never reported as an absence.

- Inspect the available own-harness repository first. A likely local starting point is `~/Documents/GitHub/securevibes-agent`; verify its existence, actual invocation, and output structure. Do not invent a RunSortie command or assume its API matches SecureVibes. If the preferred first harness is ambiguous after inspection, ask one concise question.
- Keep the harness's agent loop intact. Prefer shared model-client/tool-dispatch boundaries or existing callbacks. Request authorization before editing another repository and keep any integration patch separate.
- Instrument the actual outgoing model-visible context separately from system file/tool access. A search tool touching a file does not prove its contents reached the model.
- Link finding candidate creation, validation, filtering, and final submission through stable IDs. Record only explanations the harness exposes. Never claim access to hidden reasoning or a definitive memory-versus-analysis verdict.
- Tracing stays opt-in, with off/metadata/content modes. Preserve prompts, model settings, exceptions, streaming, retry behavior, and findings. Compare tracing-on/off behavior using controlled tests; live-model stochasticity is not removed by the SDK.
- Call `flush()` after the scan and record capture state. The sink owns persistence/backpressure; a never-settling sink can stall flush. Document that limit and unavailable capture categories.
- Preserve native allegations and evidence. File-only results stay file-only. Normalize separately structured claims; send ambiguous bundles or semantic matches to recorded review. Do not invent source ranges or ground truth from title keywords.
- Add one pinned conventional scanner path next. Keep direct execution/import independent of Inspect or Harbor. Select an agent backend only after a representative integration demonstrates useful orchestration savings.

### 4. Preserve scoring boundaries

**Status: enforced in the current scorer and contracts. These are standing constraints, not a milestone to close.** Do not relax any of them to make a later feature simpler.

- One atomic claim can hit at most one canonical target. Exact duplicates add review burden but no target credit.
- Location plus category alone does not establish the right security allegation. Distinguish the affected input/authority and deployment assumptions when necessary. Safely bound `search` is not a hit for vulnerable `sort` at the same endpoint.
- Unknown findings remain unknown, not automatic false positives. Correct additional issues require review and a later versioned label decision, not a tool-specific recall denominator change.
- Keep full-output recall and first-hit ranks. Native finite-budget results and random-order expectations for unranked tools must remain separate. Unresolved bundles leave atomic ranks/budgets pending.
- Failed assignments remain visible. Positive partial output can count where the declared policy permits; incomplete output cannot establish a quiet negative control.
- Check controls against the entire delivered output, not only the first B claims. Keep unresolved assessments, completion, and sensitivity bounds visible. Zero denominator is N/A, not zero.
- Do not introduce a composite score or promotion rule that rewards unlimited finding spam. Add corpus weighting, repeated-run uncertainty, and precision/review constraints only according to the math specification.
- Freeze evaluator decisions and artifacts for comparisons. Never let an engineering agent edit the scorer or held-out labels to manufacture improvement.

### 5. Bring-your-own-case path

**Status: the local library/CLI workflow exists and is documented.** `scaneval corpus init`, `add-snapshot`, `import`, `validate`, `approve`, `admit`, and `disposition` carry a supplied artifact (a legacy case record, a fix commit, a finding, or an internal document) into a namespaced draft pack with the same admission, invocation, scoring, and visibility contracts as public cases. No hosted service is involved. `docs/BRING_YOUR_OWN_CORPUS.md` documents the path as the code implements it and collects the gaps. Jev intake assistance is not implemented. The guidance below still governs.

- Organizations should be able to supply existing security fixes, GitHub commits/issues, prior findings, or internal documents through a local library/CLI workflow. Do not require a hosted service.
- Use a namespaced, versioned private pack with the same admission, invocation, scoring, and visibility contracts as public cases.
- Jev is optional intake/review assistance. It can suggest classifications, evidence gaps, duplicates, and security-fix candidates. It does not approve labels, sanitize secrets automatically, or score scanner correctness.
- Start with existing fixes and findings, not automatic discovery followed by self-labeling. Explicit human approval is required before draft cases become reviewed ground truth.
- Keep private material local unless the organization explicitly approves an external provider and data-egress policy. Public benchmark execution never contacts maintainers; disclosure and publication require separate authorization.
- Capture the authoring procedure for the later case-authoring skill: supplied artifact -> candidate/evidence draft -> human approval -> versioned pack -> evaluation. Corrections should propose a reviewable PR rather than silently changing released labels.

## Verification and working rules

Use the repository's standard environment if already available. Otherwise:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q
scaneval demo results/claude-pilot-demo
scaneval replay results/claude-pilot-demo --output results/claude-pilot-replay.json
cmp results/claude-pilot-demo/evaluation.json results/claude-pilot-replay.json

# Offline, no network and no model: replay a run bundle you produced.
scaneval replay <your run directory>/invocations/<invocation id>
scaneval review status <your run directory>/invocations/<invocation id>
```

The replay prints `review state draft` on stderr and `review status` prints `draft`. Both are correct and must stay correct until a human approval is actually recorded. Reproducing the runs themselves needs the network, and the harness run needs live model calls; the commands are in `docs/PILOT.md`.

Output paths must be new. Run `npm ci` then `npm test` from `sdk/typescript`. Validate both enabled/disabled observer behavior and failure paths. Do not reclassify a failing test as legacy merely to make the suite pass.

The earlier temporary Python environment is `/private/tmp/scaneval-build.5DpOoK/venv`. It may be removed or contain an older installed wheel, so reinstall the current checkout if using it. Do not treat ephemeral paths as package requirements.

The mounted external drive holds research data at `/Volumes/Untitled/sastbench-research/2026-09-19/` (that directory keeps its original name on disk; it is an external path, not a project identifier). Verify it is mounted before writing.

Do not put the source cache on that drive. It is formatted exFAT, which carries no POSIX permission bits, so git reports every checked-out tree as modified and `verify_cached_snapshot` refuses the entry: the immutable-cache guarantee cannot hold there. Measured on 2026-09-20 by copying one cache entry onto it: the entry was refused with "has local modifications", and the copy generated 462 AppleDouble `._` files, which is the same interference that earlier confused setuptools. Reformatting that volume to APFS would remove both problems; until then keep `.repos` and any git checkout on the internal disk and use the drive only for archives that need no file modes.

The cache location is configuration, not a hard-coded path: pass `--cache-root` to the CLI or set `cache_root` in a run configuration. Prefer that over editing a path into the code. Disk pressure has not been an issue so far; measured 2026-09-20, the whole working footprint was about 170 MB with 16 GB free. Do not download all snapshots or large model weights as a side effect of testing.

Run untrusted snapshot code only in an appropriate disposable environment with no live credentials. Ask before paid model sweeps, external submission of private material, destructive operations, or material changes outside this repository. Check license terms for the exact source snapshot and paths before redistribution; recipe-first preparation does not itself grant rights.

Use smaller subagents for bounded inventory, test, or adapter tasks where useful. Give each a separate ownership area. Do not ask several agents to rewrite the same contracts concurrently.

Make small commits by coherent change. **No `Co-authored-by` trailers.** Do not push, publish, open PRs, or contact maintainers unless asked. Update implementation status as features become real, not merely when their schema is drafted.

## Finish the next slice with

1. Implemented changes and commit IDs.
2. Exact tests run, failures/skips, and any paid/external calls.
3. One command to run the prepared pilot and one to replay it offline.
4. A real example report with provenance and capture limits, clearly separated from diagnostic fixtures.
5. Remaining approval or evidence gaps and the next bounded milestone.

Begin by inspecting the branch and required files, then state the smallest achievable next slice. Continue implementation after that inspection; ask only about choices that would materially change scope or require new authority.
