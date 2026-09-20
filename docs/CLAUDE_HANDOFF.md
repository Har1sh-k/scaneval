# Claude continuation prompt

Continue implementing SASTbench in this repository. An initial offline evaluator and experimental observer SDK already exist. Audit and extend them; do not restart from an empty project or treat the complete design as implemented.

## Start here

Repository: `/Users/hk/Documents/GitHub/sast-bench`.

Working branch: `feat/evaluation-core`, created from `docs/design-decisions`. Inspect the current branch, status, and recent commits before editing. Do not reset, overwrite unrelated changes, or move back to `main`. Leave the untracked `docs/archive/` directory alone unless the user explicitly asks otherwise.

Existing implementation commits:

- `0e04a84`: deterministic saved-output evaluator, versioned contracts, CLI, report, and conformance tests.
- `82c88ca`: opt-in TypeScript observer SDK, event contract, capture safeguards, and tests.
- `53be6af`: repository inventory and CVE candidate research. These are research leads, not admitted labels.

Read these files before planning implementation:

1. `docs/DESIGN_DECISIONS.md`: intended product behavior and agreed boundaries.
2. `docs/EVALUATION_MATH.md`: scoring definitions, missing-data treatment, and reporting rules.
3. `docs/INITIAL_BUILD.md`: what this branch actually implements and what is missing.
4. `docs/OBSERVER_SDK.md`: event integration, passivity, flushing, and capture limitations.
5. `docs/REPOSITORY_INVENTORY.md` and `docs/CVE_CORPUS_SHORTLIST.md`: source leads and candidate dossiers.
6. `src/sastbench/`, `sdk/typescript/`, `schema/v2/`, and `tests/test_v2*`: current code and executable invariants.

The design and math describe the destination. The initial-build guide and inspected code describe current capabilities. Do not silently change a design decision to accommodate a shortcut in the alpha implementation.

## What we are building

SASTbench supplies a versioned real-world vulnerability corpus, evaluation tools, and a thin SDK for visibility into security scanner harnesses. Users should be able to compare scanners or harness configurations, understand recorded failure points, and evaluate against their own organization's security fixes and findings.

The benchmark is not the separate engineering agent that modifies a scanner. A future project may consume evaluation results and traces, propose harness changes, and rerun comparisons. Keep that optimization agent outside this repository. Do not add automatic model training, prompt optimization, or self-modifying evaluators.

The first release evaluates public workloads. Do not claim that public-case results prove zero-day capability, lack of memorization, or resistance to benchmark-specific tuning. Prior knowledge can earn detection credit when the allegation is correct for the evaluated snapshot.

## Current implementation

- Python package `sastbench`, alpha version `2.0.0a1`.
- `sastbench validate`, `score`, `replay`, `report`, and `demo` commands.
- `evaluate(plan, saved_result, frozen_decisions)` library entry point. This does not run an agent.
- Strict JSON contracts for scanner requests/results and evaluator plans/review decisions.
- One-input scoring against all assigned targets and controls, with exact-duplicate handling, first-hit ranks, budgeted/full-output recall, unranked diagnostics, and completed-control bounds.
- A fabricated conformance demo and standalone HTML score report. No real scanner runs in the demo.
- A TypeScript observer emitter with explicit model/tool/context/finding events, recording modes, redaction of supplied copies, failure isolation, capture-gap state, and `flush()`.
- Legacy `scripts/` and adapters remain unchanged and continue using old semantics. Do not assume their output or behavior conforms to the new contracts.

Last verified: 234 Python tests passed, 2 legacy snapshot tests skipped because their checkouts were unavailable; 13 TypeScript tests passed. Package installation and wheel/resource loading were smoke-tested. Recheck these counts on the current checkout rather than treating them as permanent guarantees.

Important limitations:

- Matching is supplied through frozen evaluator decisions. The code does not establish root-cause correctness from arbitrary scanner prose.
- A declared L3/L4 field is not proof of independent review. Case evidence and admission records still need implementation.
- Saved-result hashing is not source-tree verification, a digital signature, or sandbox enforcement. The demo's input hash uses a path/content map.
- No live own-harness adapter, native/SARIF importer, exporter, isolation policy, multi-model planner, trace viewer, corpus aggregation, pair aggregation, precision sampling, or promotion gate is implemented in the new core.
- The TypeScript emitter is not connected to SecureVibes or RunSortie. Importing it alone observes nothing.
- Control rates use completed observations. `observed_false_allegations` separately retains explicit reviewed allegations from incomplete output; do not erase those observations or include incomplete scans in a completed-only denominator.

## Immediate objective

Deliver the next small end-to-end slice: one real prepared input, an actual scanner invocation, preserved native findings, reviewer-backed scoring, observable harness events where available, and offline replay. Exercise an organization-owned case pack through the same interface. Grow the case set after that path works.

Start with a short plan grounded in the existing code. Use the milestones below, but complete and test one vertical slice before expanding the platform.

### 1. Select and prepare a small real-case pilot

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

- Keep the source cache immutable. Export a pinned snapshot to an isolated trial directory and record exact hashes and preparation provenance.
- Group execution by actual prepared input, scan scope, configuration, and repetition. Score every applicable target/control from that output rather than rescanning separately for each CVE.
- Shared versions can cover multiple vulnerable targets. Later planned snapshots can supply repaired controls for earlier targets, but only when the repair and scope are validated. A CVE range alone does not establish that control.
- Use only `standard` and `metadata_blinded` profiles. Both remove original git history and evaluator artifacts. Standard preserves ordinary source identity; metadata blinding permits reviewed non-runtime metadata edits only. Do not rename imports, packages, or source symbols, invent 20 historical commits, or prompt the model to announce CVEs.
- For native PR mode, invoke the harness once with its real diff-review interface and necessary repository context. Do not replace it with two independent full scans. If git history is operationally required, construct only the minimum validated base/head representation and record it. Controls outside the review scope cannot earn silence credit.
- Provision needed dependencies in a separately recorded preparation phase, then enforce the declared execution network policy. Never expose evaluator labels, fix explanations, or decision files to the scanner. Directory names alone are not an isolation boundary.
- Preserve raw output, exit status, timeout/partial behavior, tool/ruleset versions, resolved model identity, configuration, timing, usage, and capture availability. Do not turn execution errors into empty successful scans.

### 3. Add the first real adapter and observer integration

- Inspect the available own-harness repository first. A likely local starting point is `/Users/hk/Documents/GitHub/securevibes-agent`; verify its existence, actual invocation, and output structure. Do not invent a RunSortie command or assume its API matches SecureVibes. If the preferred first harness is ambiguous after inspection, ask one concise question.
- Keep the harness's agent loop intact. Prefer shared model-client/tool-dispatch boundaries or existing callbacks. Request authorization before editing another repository and keep any integration patch separate.
- Instrument the actual outgoing model-visible context separately from system file/tool access. A search tool touching a file does not prove its contents reached the model.
- Link finding candidate creation, validation, filtering, and final submission through stable IDs. Record only explanations the harness exposes. Never claim access to hidden reasoning or a definitive memory-versus-analysis verdict.
- Tracing stays opt-in, with off/metadata/content modes. Preserve prompts, model settings, exceptions, streaming, retry behavior, and findings. Compare tracing-on/off behavior using controlled tests; live-model stochasticity is not removed by the SDK.
- Call `flush()` after the scan and record capture state. The sink owns persistence/backpressure; a never-settling sink can stall flush. Document that limit and unavailable capture categories.
- Preserve native allegations and evidence. File-only results stay file-only. Normalize separately structured claims; send ambiguous bundles or semantic matches to recorded review. Do not invent source ranges or ground truth from title keywords.
- Add one pinned conventional scanner path next. Keep direct execution/import independent of Inspect or Harbor. Select an agent backend only after a representative integration demonstrates useful orchestration savings.

### 4. Preserve scoring boundaries

- One atomic claim can hit at most one canonical target. Exact duplicates add review burden but no target credit.
- Location plus category alone does not establish the right security allegation. Distinguish the affected input/authority and deployment assumptions when necessary. Safely bound `search` is not a hit for vulnerable `sort` at the same endpoint.
- Unknown findings remain unknown, not automatic false positives. Correct additional issues require review and a later versioned label decision, not a tool-specific recall denominator change.
- Keep full-output recall and first-hit ranks. Native finite-budget results and random-order expectations for unranked tools must remain separate. Unresolved bundles leave atomic ranks/budgets pending.
- Failed assignments remain visible. Positive partial output can count where the declared policy permits; incomplete output cannot establish a quiet negative control.
- Check controls against the entire delivered output, not only the first B claims. Keep unresolved assessments, completion, and sensitivity bounds visible. Zero denominator is N/A, not zero.
- Do not introduce a composite score or promotion rule that rewards unlimited finding spam. Add corpus weighting, repeated-run uncertainty, and precision/review constraints only according to the math specification.
- Freeze evaluator decisions and artifacts for comparisons. Never let an engineering agent edit the scorer or held-out labels to manufacture improvement.

### 5. Bring-your-own-case path

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
sastbench demo results/claude-pilot-demo
sastbench replay results/claude-pilot-demo --output results/claude-pilot-replay.json
cmp results/claude-pilot-demo/evaluation.json results/claude-pilot-replay.json
```

Output paths must be new. Run `npm ci` then `npm test` from `sdk/typescript`. Validate both enabled/disabled observer behavior and failure paths. Do not reclassify a failing test as legacy merely to make the suite pass.

The earlier temporary Python environment is `/private/tmp/sastbench-build.5DpOoK/venv`. It may be removed or contain an older installed wheel, so reinstall the current checkout if using it. Do not treat ephemeral paths as package requirements.

Use the mounted external drive for large research data, source caches, and build artifacts where compatible. Verify `/Volumes/Untitled` is mounted before writing. Existing research cache: `/Volumes/Untitled/sastbench-research/2026-09-19/`. Small Python packaging builds needed an internal temporary cache because the external filesystem generated AppleDouble `._` files that confused setuptools. Do not download all snapshots or large model weights as a side effect of testing.

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
