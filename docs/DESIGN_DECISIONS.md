# SASTbench design decisions

SASTbench evaluates whether a SAST product or harness finds relevant security problems at an acceptable review cost. It provides reviewed cases, a fixed evaluator, and observer traces that help explain harness behavior. A separate engineering-agent project can consume that feedback and propose harness changes; this repository does not implement that improvement agent.

Bring your own test cases is a core use case: organizations can turn existing security fixes, findings, and internal documents into a private benchmark. Teams or a separate engineering agent can use its scores and observer traces to improve a harness for that codebase. The same evaluation contracts support public comparisons and organization-owned workloads.

[Evaluation math](EVALUATION_MATH.md) defines the scores, denominators, assumptions, and optional research contrasts.

## 1. Scope and comparison contract

The scope is repository-scale SAST across conventional, AI-assisted, and agentic workflows. The initial vulnerability families are command injection, SQL injection, path traversal, SSRF, authentication bypass, and authorization bypass. Synthetic evaluator fixtures remain separate from real-world results. A frozen workload does not support a universal vendor ranking.

### Workload classification

Select coverage by application/workflow type and security mechanism, not repository branding or the volume of published GHSAs.

| Workload | What it represents |
|---|---|
| Conventional applications | Web/API authorization, database access, file handling, and network operations without model-directed behavior. |
| Conventional automation | Intentional command execution and privileged operations controlled by configured workflows. |
| AI-assisted applications | Model-generated content or data handled by application code. |
| Agentic applications | Model output selects actions, tools, or their arguments. |

Use "conventional," not "deterministic": non-agentic software is not necessarily deterministic. Record component role separately as application, library/SDK, or infrastructure. Classify the evaluated workflow and the target's mechanism, including whether model output or selection participates in that mechanism. An ordinary authentication bug in an agent product is not automatically an agent-specific failure. A repository may supply several workloads; preserve canonical-target identity across their reporting views.

### Comparison contract

Two comparisons use the same evaluation contracts:

- **Products and harnesses:** evaluate the complete configuration, including edition, engine, rules, models, context selection, and reporting. Preserve native workflows under a common workload and declared resource limits.
- **Models:** keep the harness, prompts, tools, context policy, inputs, and budget policy fixed. Changing those creates a different system comparison.

Report each workload separately, with full-repository scans and native PR review also separate. Scanners receive ordinary task inputs, not a selected CVE, expected location, or hint that a vulnerability must exist. Any combined workload result needs predeclared membership and weights; do not let available CVE counts determine them implicitly. Use a workload-specific scorecard, not one composite leaderboard score.

The first release compares systems on public workloads only. Repositories and snapshots are not selected yet: assess candidates against the admission rules, then freeze the release manifest before comparison. The inventory below is not that manifest. Results describe performance on the frozen workload, not resistance to benchmark-specific tuning. A sealed or private slice is not a first-release requirement; organization-owned packs remain supported by the design.

SecureVibes may appear in the first comparison; inclusion and independent reviewer assignment remain publication decisions. If included, disclose the authors' relationship to it and apply the same workload, scoring, and review rules. Disputed findings involving it should be adjudicated by a reviewer not involved in the tool. Record who reviewed them and do not claim independent adjudication where it was unavailable. No special adapter or scoring path is needed.

### Current starting point

Metadata recounted on 2026-09-17, with disclosed-subset repository/language counts checked on 2026-09-18. These counts do not independently validate labels. The existing agentic/generic inventory groups are legacy selections, not assignments to the workflow classes above.

| Corpus | Cases | Repositories | Repo/commit snapshots | Snapshot/root/language groups |
|---|---:|---:|---:|---:|
| Legacy disclosed agentic subset | 156 | 10 | 103 | 104 |
| All real-world | 189 | 16 | 128 | 129 |

Of the 156 disclosed cases, 128 (82%) come from OpenClaw, n8n, and Flowise, and 127 (81%) are annotated as TypeScript. Twenty-three snapshots are shared, with up to 12 cases on one snapshot. Only 49 real-world cases have PR-pair metadata. There are zero real-world capability-safe annotations. Retain useful cases, but expand conventional-workflow coverage and independent applications deliberately; a higher CVE count alone does not fix the imbalance.

The candidate inventory is TypeScript-heavy. Across the 189 real-world records, language counts are TypeScript 138, Python 16, Rust 11, Clojure 8, Go 7, Java 6, and Swift 3. Within the separate 156-case disclosed subset, kind counts are command injection 41, authorization bypass 34, authentication bypass 29, SSRF 23, path traversal 20, and SQL injection 9. All nine SQL-injection records are TypeScript cases from two repositories. These are inventory counts, not validated release coverage.

Each release reports workload and component-role coverage alongside a kind-by-language-by-repository matrix for admitted targets and controls. Show counts, denominators, and uncertainty; mark sparse slices and avoid generalizing from them. No universal minimum such as ten targets from three repositories is assumed. The release's workload and language claims must follow its admitted corpus.

The existing [case schema](../schema/case.schema.json) already has `capability_safe`, `capability`, and `requiredGuards`. The [current scorer](../scripts/scoring.py) still classifies these findings by location overlap and capability-kind agreement, not by the validated security property. The richer annotation workflow, scorer changes, SDK, and invocation interfaces below are planned work, not existing guarantees. This document and the math companion define the current design.

## 2. Corpus admission and ground truth

A case represents a specific root cause in real code, not an entire repository's security status. Several CVE/GHSA identifiers may describe one target. Other vulnerabilities can remain unknown.

Each accepted case records:

- `represents`: the distinct analysis challenge or justified independent replication it contributes.
- Evaluated workflow, component role, and the model's involvement, if any, in the target mechanism.
- A coverage signature: language/framework idiom, input source or trust boundary, security operation, guard-failure mechanism, and interprocedural span.
- Canonical target and variant family, pinned snapshots and scope, deployment/authorization assumptions, and accepted reporting locations.
- Evidence origin, reviewer decisions, validation level, disclosure artifacts, and release/split membership.

Same CWE, repository, or file is a duplicate-review signal, not proof of the same mechanism. Group genuine variants, reject duplicate target records, and require justification for repeated coverage signatures. Freeze family weights and a coverage matrix per release. Annotate model-output and other input sources where relevant; do not force every issue into a taint-flow model.

Field states are distinct: `not_applicable` means the concept does not fit and needs a reason; `unknown` means applicable but unresolved; `not_reviewed` means assessment is pending. None bypasses required root-cause evidence or admission review.

### Candidate intake and evidence sources

Define coverage needs first, then search across disclosure sources for cases that fill a gap or provide justified independent replication. Use the CVE Program's official [CVE List V5](https://github.com/CVEProject/cvelistV5) JSON records for broad intake rather than scraping individual cve.org pages or relying only on repository GHSAs.

- **CVE records:** discovery, identifiers, reported affected products/versions, and references.
- **GHSA and vendor advisories:** supplementary descriptions, aliases, and remediation evidence.
- **Source, fixes, and independent review:** establish the actual target/control label on the exact snapshot under stated assumptions.

Retain source provenance and the record revision used. Resolve product/package references to the code in scan scope, merge CVE/GHSA aliases, and group genuine root-cause variants. A CVE is neither required nor sufficient; reviewed findings without one remain eligible. A dependency-version alert alone is SCA evidence, not a SAST target. A dependency vulnerability qualifies only if the vulnerable implementation is in scope and receives the same source-level validation.

The following are candidates to assess, not selected repositories or validated cases:

| Candidate | Coverage to assess |
|---|---|
| [Gitea](https://docs.gitea.com/) | Go application workflows involving repository permissions, file handling, package hosting, and CI. |
| [Apache Airflow](https://airflow.apache.org/docs/apache-airflow/stable/security/index.html) | Conventional automation, authorized execution, user roles, and deployment assumptions. |
| [Open WebUI](https://github.com/open-webui/open-webui/security/advisories/GHSA-p4fx-23fq-jfg6) | The distinction between intentional Python tool execution and unauthorized access to that capability. |
| [FastMCP](https://github.com/PrefectHQ/fastmcp/security/advisories/GHSA-rww4-4w9c-7733) | MCP authorization and OAuth consent boundaries. |

Where valid cases exist, cover the same operation in conventional automation and agentic workflows, such as command execution under different authority and guard assumptions. Score the specific security properties; the comparison is not proof of a scanner's internal understanding.

### Candidate screening and disposition

Screen candidates before spending effort on full validation. Passing these checks makes a case worth validating, not an established ground-truth label.

| Criterion | What must be established |
|---|---|
| SAST relevance | The claimed root cause concerns an in-scope source-code mechanism, not just an outdated dependency or an out-of-scope deployment setting. |
| Available source | The affected repository, component, and candidate snapshot can be identified and pinned. |
| Credible evidence | An advisory, maintainer discussion, patch, or reviewed analysis supports investigating the claimed root cause. A severity number alone is insufficient. |
| Clear security boundary | The input or actor, intended restriction, claimed failure, and necessary trust/deployment assumptions can be described. Intentional functionality alone is not a vulnerability. |
| Useful contribution | The case adds a distinct mechanism, framework/language pattern, trust boundary, analysis challenge, or justified independent replication. |
| Assessable finding | There is enough evidence to propose what a correct security allegation must establish and its acceptable reporting locations, subject to validation. |

Source-level insecure defaults or failed configuration enforcement can qualify under stated assumptions. Do not require an existing scanner to detect a candidate before admitting it. Severity is coverage metadata, not a substitute for these checks; severity proportions remain a separate release-selection decision.

For each candidate, draft its `represents` statement:

> This case tests [specific security mechanism] under [trust/deployment assumptions], and adds [coverage gap or justified replication].

Record one disposition and its reason:

- **Validate:** credible evidence and a useful contribution justify proceeding to the label-validation process below. This is not release admission yet.
- **Needs evidence:** plausible, but source, assumptions, or root-cause evidence is incomplete. Record what is missing; missing evidence alone is not grounds for exclusion.
- **Extended regression:** a validated case whose contribution is redundant for the main release. Keep it separately with the same label-validation requirements; merge duplicate records of the same target rather than counting them again.
- **Exclude:** outside the declared scope or contradicted by the evidence. Record the reason; exclusion from this benchmark is not necessarily a finding that the issue is harmless.

The artifact and localization requirements have direct precedents. [NIST SATE 2010, Section 2.3](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication500-283.pdf#page=10) selected available vulnerable source with identifiable CVE locations and supporting records. [OpenSSF's contribution guide](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark/blob/main/CONTRIBUTING.md#contributing-to-benchmark-data) requires vulnerable/patched commits and an expected reporting location. [CWE-Bench-Java](https://github.com/iris-sast/cwe-bench-java#packaged-data) records affected/fix commits and manually vetted fix locations. These precedents support the evidence requirements, not a universal admission checklist. Our contribution rule and dispositions are coverage policy. Unlike pair-only designs, a validated positive target does not require a fixed counterpart; without one, fixed/pair results remain unavailable.

### Validation

Record evidence origin separately from validation: public advisory and maintainer fix, fix without advisory, independently reviewed internal finding, or diagnostic fixture.

| Annotation validation level | Cumulative requirement |
|---|---|
| L1 | Artifacts, hashes, paths, and applicable patch/remapping records checked. |
| L2 | Affected code parses; relevant structural changes reviewed. |
| L3 | Independent review establishes the target label. Fixed/safe labels also need a targeted regression check or independently checked security invariant. |
| L4 | L3 plus the relevant build and broader tests. |

Headline detection and negative-control results use L3/L4 labels. Retain lower-tier candidates and failed/unavailable validation outside those denominators. Ordinary test success does not establish security correctness. Exploit reproduction and an LLM judge are not required.

### Label corrections

Suspected errors in labels, categories, regions, assumptions, or fixed-state annotations go through a corpus-correction PR, not an in-place change during a scored run. Include the affected IDs and snapshot hashes, old and proposed annotations, supporting evidence, validation results, and expected scoring impact. Human review approves or rejects the correction; unresolved labels remain disputed rather than silently rewritten. Accepted corrections create a new corpus/evaluation version, retain earlier records, and rescore comparable saved outputs for all systems. Keep protected evidence out of public PRs.

A future corpus-maintenance `SKILL.md` will document candidate assessment, annotation validation, Jev's optional role, correction-PR preparation, checks, and release/rescoring steps. It must distinguish a benchmark-label correction from a newly discovered upstream issue, which follows the disclosure boundary in Section 4. This skill is a deliverable, not a dependency on a selected repository set.

### Safe-capability and fixed controls

Prioritize human-reviewed safe-capability regions, initially aiming for ten real repositories selected through admission review, with explicit deployment, authority, and guard assumptions. No particular repositories are committed yet. Powerful operations are neither automatically vulnerable nor automatically safe because they are intentional. Do not add a separate educational-repository-awareness score.

Previously disclosed CVE fixes are the preferred starting point for negative controls. Validate the repaired root cause on the exact snapshot and map its semantic target through moved/deleted symbols, guards, paths, and ranges. An alert overlapping patched code is not automatically false.

A repair is a fixed-target control. It is also a capability-safe control only if the powerful operation remains and is properly constrained. Deleting the operation does not test safe-capability reasoning. Use the real fixed snapshot when suitable; backport the security patch only when a tightly matched experiment needs it. A backport improves experimental control, not proof against memorization.

### Authoring and maintaining a safe control

1. **Select candidates.** Cover distinct operations, trust boundaries, guard mechanisms, and language/framework patterns across the ten-repository pilot. Prioritize documented repairs and ordinary intentional capabilities. Tool alerts can suggest candidates, but do not select the entire control set from one evaluated tool's mistakes. Record selection provenance and freeze the released set before comparison.
2. **State the property.** Assign a stable control ID and pin the exact snapshot/tree, scan scope, operation symbol/range, related evidence locations, and control type: capability-safe, fixed-target, or both. State the allowed actors/inputs, deployment assumptions, and the specific allegation the evidence rules out. A region is an evidence anchor, not a blanket safe zone.
3. **Establish evidence.** Follow relevant callers, data handling, authorization decisions, and guard placement, including across files. Record the invariant and supporting code/test artifacts. Guard names, comments, scanner agreement, or a closed ticket are not sufficient. If the property cannot be established, retain a draft rather than a safe label. An optional [Jev audit](#11-optional-jev-annotation-audit) can check the draft evidence before human approval.
4. **Review independently.** A curator prepares the record; a second reviewer checks the property, assumptions, and L3/L4 evidence. Adjudicate disagreements or leave them unresolved. Record reviewers, decisions, and accepted claim/location matching rules. Revalidate affected controls when code, dependencies, or assumptions change; do not copy a label automatically to a later snapshot.
5. **Separate context from answers.** Store labels, control IDs, and review evidence outside the scanner workspace, not in source markers or suppression comments. Supply any necessary ordinary deployment/authorization context consistently as versioned runtime input, without revealing expected findings. An undisclosed assumption cannot justify marking a scanner's claim false.
6. **Score the property.** Review all submitted claims against eligible controls, including claims below the first-$B$ cutoff. A matching false allegation flags that control once per observation; duplicates add burden, not extra control failures. Different issues in the same region remain eligible for ordinary review. Silence counts only after a valid completed in-scope scan with a resolved assessment; otherwise report unavailable or unresolved control evidence.

Keep these records with release/split membership and snapshot-specific remapping. They establish a scoped control, not safety of the whole function or repository. These are benchmark-specific admission rules, not exhaustive security verification.

## 3. Execution: shared snapshots and native PR review

Separate the execution unit from the scoring unit. Run once per exact input, root/language scope, system/model configuration, environment, condition, tool/network contract, budget, and repetition. Score every applicable known target and validated control against that output. Charge execution cost once; shared outcomes are not independent runs.

Version ranges identify candidate shared inputs, not validated labels. If CVE1 affects 1.0 through 1.7 and CVE2 affects 1.4 through 2.8, a validated 1.7 snapshot can test both. Disjoint affected ranges need different positive snapshots; a later planned snapshot may also supply an earlier target's fixed control.

For a separate hypothetical release sequence in one repository, the plan could be:

| Planned version | CVE1 | CVE2 | CVE3 |
|---|---|---|---|
| v1.7.0 | Vulnerable | Not assessed | Not assessed |
| v2.8.0 | Fixed control | Vulnerable | Not assessed |
| v3.2.0 | Fixed control | Fixed control | Vulnerable |

These version numbers are illustrative, not selected real releases. Resolve each version to a recorded commit SHA and input-tree hash. Each row requires one scan per system/configuration/repetition. Validate every assessed cell, including whether a repair remains effective in later snapshots. "Not assessed" means no label is assigned, not that the target is absent or safe. Freeze target/control selection and weights so repeated old fixes do not dominate.

Prefer later already-planned scans for fixed observations. Do not automatically add a fixed-only scan for every CVE. A final target without a fixed observation keeps its detection result; pair/control coverage is unavailable, not passed. Rolling controls measure practical discrimination, not the isolated effect of a patch. Dedicated matched pairs remain opt-in research inputs.

### Native PR mode

Use one native PR invocation per change set, configuration, and repetition, with base/head references, diff access, and necessary repository context. Internal model calls are part of that invocation. A vulnerability-introducing PR boundary must be validated separately from the repair boundary.

Preserve each declared workflow: DeepSec uses the diff to select changed files for analysis; sv-agent starts from the diff and can examine related unchanged files. Pin adapter versions and test that the integration preserves those scopes.

Declare changed-file or change-affected-flow scoring scope before execution. A validated fixed behavior inside that scope may qualify even if its repair lines are unchanged. Unrelated old fixes do not qualify merely because the repository is accessible. Traces must not shrink the denominator to what the tool chose to read.

Record bootstrap/indexing as setup, include it in total cost, and distinguish fresh from prepared-state runs. Reuse only compatible state prepared without evaluator labels. A synthesized two-full-scan comparison is a separate opt-in workflow, never a silent PR fallback.

### Trial isolation and provenance

- Treat `.repos` as an immutable controller-only cache. Export fresh trial inputs, hash the tree, and record preparation and transformations. Workers cannot browse original checkouts, sibling trials, or evaluator artifacts. Clear conversations, indexes, caches, and scanner state unless the profile explicitly declares reusable prepared state. Isolate harness configuration and instruction discovery from host/parent directories; record approved project instructions and settings.
- Remove benchmark metadata, answer-bearing hints, original Git history, and identifying parent-directory names. Full scans omit `.git`; Git-dependent PR tools receive minimal synthetic base/head history with neutral messages, not fabricated filler commits. Source identity handling follows the selected profile below.
- Pin dependencies before sealing the environment. Prefer read-only source plus writable build/output areas; document compatibility exceptions. Enforce filesystem and network policy externally, not through logging hooks, and record denied requests where observable. Exporting a tree is not a sandbox.
- Keep a controlled no-retrieval profile, allowing only declared inference access where necessary. Disable configurable provider-hosted retrieval tools as well as local web access. Report connected/native-service products separately. Local isolation cannot certify a provider's internal retrieval or training history.
- Pin actual tool edition/version, ruleset hash/date, model identity/revision where available, configuration, environment, and sampling settings. Reject known requested/observed model mismatches; mark unverifiable identity explicitly. Moving aliases and live rule downloads are not reproducible pins.

### Configurable identity profiles

Support only these two values for `input_profile`, with `standard` as the default. Both inherit the isolation controls above; neither exposes original Git history or benchmark answers.

| Profile | Allowed changes | Use |
|---|---|---|
| `standard` | Preserve ordinary project identity and code. | Default buyer evaluation. |
| `metadata_blinded` | Reviewed changes to non-runtime branding, documentation identifiers, and display metadata. | Lower-risk, partial blinding. |

Neither profile renames packages/modules, imports, source identifiers, or source paths, or changes dependencies, executable logic, or security configuration. A manifest field is not automatically non-runtime metadata. If its role is uncertain, leave it unchanged and record the remaining identity cue. Preserve architectural context, deployment assumptions, and security guidance in documentation.

For `metadata_blinded`, use a reviewed per-repository allowlist and deterministic replacement map. Record changed fields, input hashes, validation evidence, and retained identity cues. Apply the same map to related base/head or vulnerable/fixed inputs and freeze it across compared systems. Reject unvalidated edits; if no valid transformation is available, mark blinding unavailable rather than silently substituting `standard`. Report profile results and coverage separately.

This reduces selected identity cues; package names and recognizable code may still reveal the original repository. Do not describe it as full anonymization or proof against memorization. Source/package renaming is outside the current design.

## 4. Scoring without exhaustive repository labels

Report full-output known-target recall and a recall-versus-review-budget curve. For each assigned target observation with native ordering, store the first accepted claim's rank, or `null` if there is no accepted hit, plus output length and execution status. Unranked output retains hit flags but has no measured native rank. Never replace a missing hit with the last output position. Declare budgets before comparison, for example 5, 10, 20, and 50 claims, with separate full-scan and PR settings. Show the distribution of assigned targets per input beside budgeted results. Shared targets compete for the same per-scan budget; positions are not divided into per-target allowances.

### Claim acceptance

A claim is one distinct security allegation about one root cause, with one primary reporting location and optional related locations/evidence. One claim can establish at most one canonical target hit; CVE aliases do not create additional targets. A related location contributes to matching only if it is an accepted reporting location and supports that allegation. Location and type agreement alone, a broad file range, or a CVE mention is insufficient.

Evaluate the full allegation and supporting evidence against the validated target:

| Check | What must match |
|---|---|
| Security issue | The finding identifies the annotated root cause, not merely a dangerous operation. |
| Vulnerability type | The category is compatible with the actual issue under the versioned kind/rule mapping. |
| Affected input or authority | The relevant parameter, data flow, actor, or missing permission check is identified where needed to distinguish the issue. |
| Code location | An accepted location supports the allegation, such as the entry point, missing guard, or sink. An identical line number is not required. |
| Assumptions | The allegation holds under the snapshot's declared deployment and authorization assumptions. |

These are correctness conditions, not five mandatory output fields. Defer dedicated endpoint/parameter fields; preserve full native finding text and code references instead. A clear description or code reference can establish the affected input without naming it in a separate field. This applies to HTTP parameters, agent tool arguments, and other relevant inputs or authority boundaries. Missing output detail does not mean the concept is not applicable. The finding need not restate every supplied assumption or establish a complete evidence chain to earn detection credit.

For example, suppose a database handler safely binds `search` but unsafely incorporates `sort` into query structure:

- A finding saying only "SQL injection somewhere in this function" is insufficient.
- Correctly identifying the unsafe handling of `sort`, with an accepted code reference, can earn credit.
- Claiming that the safely bound `search` parameter is injectable does not detect that target, even if the location and vulnerability type match.

Automate clear matches with validated, versioned matching rules. Arbitrary prose or ambiguous root-cause/input attribution needs recorded human review; until resolved, it earns no confirmed hit and is not automatically a false positive. Replay reuses frozen decisions. This provides deterministic scoring, not guaranteed automatic semantic interpretation of every report; no LLM judge is required.

Importers split native results only where separate allegations are explicitly structured, using frozen label-blind splitting/order rules. Bundles requiring interpretation go to recorded human review; replay reuses those decisions. Budgeted scoring remains pending for an unresolved bundle, rather than treating it as one cheap claim or dropping it. Do not split one issue merely because it has several evidence locations or paths.

For the pilot, detect exact structured duplicates using a versioned canonical payload: allegation, canonical kind, native rule identity, primary/related locations, and supplied flow/evidence details. Normalize path separators and text line endings; exclude delivery IDs, ranks, and timestamps. The same allegation/kind/primary-location tuple is only a duplicate-review hint because distinct flows can share it. Record review decisions for ambiguous semantic duplicates. Keep all delivered copies: duplicates consume review positions and burden but earn no additional target credit.

Preserve a product's declared native review order and tie-breaking, frozen before label matching. If no meaningful native order is supplied, mark output unranked. Report full-output recall plus an optional expected recall over uniform random orderings of the delivered claims, including duplicates, as a diagnostic. This is not a measured prioritization score or a promotion metric; repetition of a claim can change that expectation. Keep native-order and random-order results separate. The [math specification](EVALUATION_MATH.md#unranked-output-diagnostic) defines the diagnostic without rerunning the scanner.

### Scorecard and review

| Scorecard item | What it answers |
|---|---|
| Known-target recall versus B and full-output recall | Which assigned, validated root causes were detected, and how early in ranked output? |
| Capability-safe false-alarm rate | Were validated intentional capabilities incorrectly alleged to be vulnerable? |
| Fixed-target false alarms and pair correctness | Does the tool distinguish a target from its validated repaired state? |
| Mixed-intent correctness | Can it detect an issue without falsely flagging required safe capabilities in the same input? |
| Reviewed alert precision | What fraction of reviewed unique claims are real, with unresolved claims and uncertainty shown? |
| Review burden | Delivered claim count, duplicates, and measured/estimated triage time. |
| Operational fit | Completion, unsupported work, full/PR latency, resources, and cost including setup and retries. |
| Complementary value | Confirmed targets beyond a named baseline, with added review effort and cost. |

Within each declared workload, count each target once, average its planned observations, and use equal-target weights by default, with a separately reported equal-project view. Freeze any alternative or cross-workload weights. Retain assigned failures in operational detection denominators. Valid positive findings from partial output may count; incomplete or failed scans cannot establish a successful negative control. Report control availability, completion, and unresolved matching alongside false-alarm rates. Zero resolved controls means a resolved rate of N/A, not 0%; zero completed controls also leaves the completed-observation bound unavailable.

Alongside the resolved control false-alarm rate, report a worst-case upper bound among completed eligible observations, treating every unresolved assessment as a false allegation. This is a sensitivity bound, not a confidence interval or a bound covering failed scans. Promotion uses that upper bound with predeclared minimum completion and assessable-control coverage, plus uncertainty requirements. Pair and mixed-intent success instead require confirmed success; incomplete or unresolved observations earn no success credit.

Unmatched findings remain unreviewed. Review can establish an additional true finding, false allegation, unresolved claim, or out-of-scope item. Never label everything outside the annotations an FP. Accepted new issues enter a versioned label release; rescore comparable outputs for all systems, not only the discoverer.

Benchmark execution never contacts maintainers or publishes discoveries. Route suspected previously unknown issues to private human review and a separately authorized disclosure process. Public labels, PRs, reports, and traces must not expose the issue until that process approves release. A fix or an embargo expiry is not automatic publication approval.

Review the bounded first-$B$ list for immediate usefulness. Separately take a probability sample across full outputs to estimate broader alert precision. Use two independent reviewers plus adjudication for published estimates, blind tool identity where feasible, and retain selection probabilities and reviewer agreement. Include ordinary snapshots/PRs as well as CVE-selected inputs; ordinary does not mean safe. [NIST SATE](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.500-326.pdf) provides a precedent for sampled production-warning review with unresolved outcomes.

Detection, required-region coverage, complete-chain grounding, and citation precision are separate measurements. Complete grounding requires reviewed evidence nodes and relationships, including authorization decisions where relevant. Opening every annotated file is not required for detection credit, and reported evidence is not proof of internal reasoning.

Where grounding is assessed, annotations need evaluator-only `flowId`, evidence-node IDs, roles, and required relationships. Roles may describe sources, propagation, guards/missing guards, sinks, or authorization decisions. Reports return code citations and claimed relationships, not secret benchmark region IDs. Map clear evidence deterministically and review ambiguous support. Existing required-region coverage alone cannot establish a complete chain.

Conformance tests include flag-everything, duplicate-spam, and always-silent outputs. Promotion requires acceptable precision, control false alarms, completion, review burden, and cost as well as detection. Unknown findings consume review effort; insufficient review evidence leaves a constraint unresolved.

Harmless-edit alert churn is an optional follow-on diagnostic on validated real snapshots, not a buyer score or release gate. The math companion retains its definition alongside unchanged-input repeat variability.

### Worked example: one scan, two targets, one control

This is an illustrative record, not a new synthetic benchmark case. One validated snapshot contains targets T1 and T2 plus control C1. C1 covers only SQL injection through a particular search value: reviewers verified fixed query structure and value binding across the relevant call path. It says nothing about that endpoint's authorization. T1, T2, and C1 are evaluator IDs, never scanner inputs.

The importer preserves native finding IDs, rank, allegation, rule/type, locations, and source-artifact references. Normalization does not assign truth labels. Suppose a completed scan returns these claims and the evaluator resolves the clear matches:

| Rank | Submitted claim | Evaluation record |
|---|---|---|
| 1 | Specific report establishing T1's root cause | One target hit. |
| 2 | The same allegation as rank 1 | Duplicate; consumes a review position, no extra target credit. |
| 3 | A different authorization concern at C1's endpoint | Unreviewed additional finding, not an automatic FP. |
| 4 | Search value is concatenated into C1's SQL structure | Confirmed false allegation about C1's validated property. |
| 5 | Specific report establishing T2's root cause | One additional target hit. |

First-hit ranks are T1 = 1 and T2 = 5. At $B=3$, recall@B is 1/2; at $B=5$ and over full output it is 2/2. C1 is flagged even though its allegation ranks below $B=3$. The output has five delivered claims, one duplicate, and one unreviewed distinct claim. This does not yield an exhaustive repository precision or FP rate. A timeout would prevent successful-negative credit from silence. Store the matching/review decisions so replay reproduces these results without rerunning the scanner.

## 5. Library, adapters, and execution backends

Keep the corpus, scorer, and result format independent of any agent framework. The core owns release planning, materialization, execution contracts, normalization, scoring, and reporting. Pure scoring needs no model API.

| Versioned contract | Contents and boundary |
|---|---|
| Scan request | Input/scope, PR references where applicable, system/model settings, limits, and opaque run ID. No ground truth. |
| Scan result | Explicit success/partial/unsupported/error/timeout status, claims with native order or an unranked declaration, locations, evidence, usage, and native-artifact references. |
| Trace event | Typed observations with declared capture capabilities and status. Required for diagnostic claims that depend on them, not for product scoring. |
| Evaluation record | Labels, matches, review decisions, metrics, and provenance. Evaluator-only. |

Keep schemas language-neutral. [JSON Schema](https://json-schema.org/understanding-json-schema/reference/object), [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html), and [OpenTelemetry trace relationships](https://opentelemetry.io/docs/concepts/signals/traces/) offer reusable conventions, not correctness or access-control guarantees.

Integrate our own harness first with a thin `scan(request, observer=None) -> ScanResult` adapter. Preserve its agent loop. Execution adapters invoke functions/CLIs/containers/services; result importers translate native output; the observer SDK and connectors capture diagnostic events. The pure scorer evaluates saved outputs independently of instrumentation or backend choice.

Canonical claims retain a stable claim ID, native finding ID, full original allegation and evidence text, primary/related locations, native rule/CWE/type/severity, rank, and raw-output references. Do not reduce the allegation to its title. Centralize versioned kind/rule mappings. Do not invent precise locations, discard unmapped claims, or turn parse errors into empty successful scans. A small structured exporter is preferable to free-text extraction; ambiguous extraction still needs review. Adapters do not receive labels or decide TP/FP status.

### Invocation and multi-model support

The interfaces below are proposed, not implemented:

```yaml
harness: my_harness.benchmark:scan
input_profile: standard           # standard | metadata_blinded
corpora:
  - manifest: releases/pilot/manifest.yaml
models: [model_a, model_b, model_c]  # aliases for pinned configurations
selection:
  mode: stratified_sample          # all | fixed_manifest | stratified_sample
  split: development
  stratify_by: canonicalKind
  cases_per_class: 5               # example budget, not a sufficiency claim
  diversity_by: [repository, variant_family]
  seed: 42
execution:
  shuffle_order: true
  order_seed: 43
repetitions: 3                     # example pilot setting
review_budgets:                    # example reporting cutoffs, not scan limits
  full: [5, 10, 20, 50]
  pr: [5, 10, 20]
trace: content                    # off | metadata | content
```

Invoke through `sastbench run bench.yaml` or `sastbench.evaluate("bench.yaml")`; inspect results with `sastbench report runs/<run-id>`. Planning freezes the workload, workers run sanitized requests, and evaluation happens outside the worker. Library use must preserve that boundary.

Support multiple models regardless of backend. Bound provider concurrency, rate limits, and spending; record usage, incompatible combinations, failures, and retry history. Retries are not independent repetitions. Give every compared system the same frozen sample and controls, sampled without replacement with diversity constraints and reported shortfalls. Record selected IDs, weights, hashes, and actual execution order. Selection, order, and model-sampling seeds are separate.

Use fixed development samples for regression checks and configurable rotating samples for broader development coverage. Release comparisons use a frozen shared manifest. Rotation does not create a clean holdout, remove memorization, or add missing repository diversity. A previously saved output can support rescoring, not a new independent repetition.

### Inspect, Harbor, or the direct runner

Keep direct product execution and SARIF/native-JSON import. Compare [Inspect](https://inspect.aisi.org.uk/tasks.html) and [Harbor](https://docs.harborframework.com/core-concepts) on the same small workload and our own harness with at least two models, using the direct runner as a reference. Neither is selected yet.

Judge behavior preservation, identical scoring, failure/retry accounting, observability, integration effort, and maintenance. An orchestration framework manages evaluation; it does not provide our SAST ground truth or make model reruns deterministic. Multi-model support alone does not justify a dependency. Keeping the direct runner is a valid result; maintaining both integrations is not required.

If Inspect is selected, reuse its [agent bridge](https://inspect.aisi.org.uk/agent-bridge.html) for supported model calls and its [log viewer](https://inspect.aisi.org.uk/log-viewer.html). Use SDK connectors for harness-specific events rather than duplicating backend capture and viewing. Preserve canonical run bundles outside the backend. Explicitly check [generation-configuration forwarding](https://inspect.aisi.org.uk/agent-bridge.html#generation-config); a bridge must not silently change the evaluated configuration.

The proposed mapping uses [Inspect's task components](https://inspect.aisi.org.uk/tasks.html):

| Inspect component | SASTbench responsibility |
|---|---|
| Task | Frozen corpus selection, workflow, and comparison contract. |
| Sample and epoch | One unique scan input/scope/condition; independent repetitions, not one rescan per CVE. |
| Solver | Invoke the existing harness through its adapter without replacing its agent loop. |
| Scorer | Call our evaluator with protected labels; aggregate by target/control weights, not an unweighted average of scan samples. |

Neither backend may put evaluator labels in the worker's accessible state. Inspect logs can contain targets and scores; check/redact exports and keep protected logs separate. A transcript is not necessarily the complete raw API payload: configure [raw-call capture](https://inspect.aisi.org.uk/eval-logs.html#model-api-logging) explicitly when that evidence is required. For Harbor, evaluate a [custom verifier](https://docs.harborframework.com/core-concepts/jobs/custom-verifiers) that calls the same evaluator outside the agent workspace. Backend integration does not replace the isolation policy.

## 6. Observer SDK, debug visibility, and deterministic replay

Ship a thin, framework-neutral observer SDK as a language-neutral event protocol with emitters in harness languages. The first emitter is TypeScript for securevibes-agent, with tracing included in our own-harness integration from the start. Instrument shared model-client and tool-dispatch boundaries, with explicit events for context selection and finding filtering. Prefer existing callbacks and native trace imports through connectors; add wrappers or spans only for missing events. Importing the SDK alone does not capture every operation. Open-source access enables integration but does not guarantee complete visibility.

An external CLI does not automatically make model requests unobservable: a supported native log or model proxy/bridge may capture them. Declare capture status per integration and event category; a transcript is not necessarily a complete API request. Mark model-request capture unavailable only when that integration cannot supply it. Any connector must preserve the evaluated configuration and behavior. [Inspect's sandbox bridge](https://inspect.aisi.org.uk/agent-bridge.html#sandbox-bridge) is one possible integration, not a backend commitment.

| Evaluation use | Tracing requirement |
|---|---|
| Product comparison | Optional, including for black-box products. Missing internal visibility does not reduce detection credit or change noise scoring. |
| Harness debugging and improvement | Capture is required for the diagnostic claims being measured. Partial or missing evidence makes the affected conclusion unknown; outcome scoring still works. |

Support `off`, `metadata`, and `content` recording. Normal scans work without the SDK; turning tracing off does not disable required run provenance or finding submission. Keep instrumentation passive: preserve prompts, tools/results, generation settings, streaming, retries, and exceptions. Record SDK/connector versions and any integration patches.

Capture relevant model requests/responses, exposed reasoning, tool calls/results, context inclusion/truncation, handoffs, candidate/filter/submission events, and errors. In content-mode debug runs these may be stored locally, with credential redaction, declared omissions, and separate approval for uploads. Do not elicit extra reasoning during a scored run or claim access to hidden thoughts. Exposed explanations can be unfaithful to what affected an answer. [Turpin et al.](https://arxiv.org/abs/2305.04388).

Distinguish system-access traces from the actual outgoing model request captured after context selection, summarization, and truncation. A search touching 1,000 files may deliver only three snippets. Recorded input establishes availability, not use. Record schema version, event/run/producer IDs, sequence, call/attempt IDs, parent links, timestamps/durations, and artifact hashes; concurrent events have a partial order. Use stable candidate IDs to link findings across filtering and submission, and link selected context to tool results or derived summaries. Separate observer facts, harness self-reports, and model statements. Mark capture complete, partial, redacted, or unavailable for each event category. Hashes detect changed artifacts, not a dishonest producer.

The own-harness connector wraps the shared model client and tool dispatcher, then adds context-selection and finding-filter events. Record tool arguments, result/status, errors, and duration; model events include resolved model/settings and available token usage. For web tools, distinguish attempted/denied requests, returned content, and content actually included in a model request. A tool call alone does not establish that a page was read. Redact stored copies, not the inputs delivered to the harness.

Deterministic queries can establish recorded tool calls, content included in a request, and documented candidate-to-report changes. Absence of an event establishes absence of an action only when capture is complete for that action. Security interpretation still needs validated matching rules or frozen human review.

Run an optional recognition check under both `standard` and `metadata_blinded`. For a verified repository name or CVE/GHSA association, record where it first appears in captured input, tool results, or model output, and whether it was already available in captured context. Keep association maps evaluator-side and exclude evaluator artifacts from the search. No prompt asks the model to announce identifiers. This observation has no score effect: no prior recorded source is not proof of recall, and no mention is not proof of no recognition. Only submitted findings earn detection credit; filtered hypotheses remain debugging evidence.

For example, a tool event records returned span A; a linked context event excludes A; the complete outgoing request confirms that exact span is absent. The supported conclusion is that A was not delivered in that request, not that the model never knew equivalent information or would have detected the issue if A were included. Separately, a candidate ID followed by a filter event and no submitted claim establishes that the harness discarded that candidate. Missing events leave these diagnoses unknown. These queries require no LLM judge.

Replay reads frozen native outputs, adapter/mapping versions, execution records, available traces, labels, human decisions, scoring/diagnostic rules, and statistical settings. It makes no model or web calls. Corrections create a new evaluation record while retaining the old one. Identical saved inputs and rules must reproduce scores and recorded-fact conclusions; identical live agent reruns or certainty about internal reasoning are not promised.

Ship parser/schema fixtures, scoring fixtures, trace-gap checks, and recording on/off parity tests using deterministic or stubbed clients, including streaming/async behavior. Measure tracing overhead. A logging failure is a visible capture gap, not a changed scan result.

## 7. Freshness and memorization audit

A correct finding earns detection credit regardless of whether prior knowledge helped, provided the claim meets the normal matching rules and the vulnerability is present in the evaluated snapshot. Knowing a repaired CVE does not make an allegation against its fixed state correct. Recognition checks do not add or subtract credit; freshness labels select reporting slices, not per-finding penalties.

Keep inexpensive leakage controls and model/ruleset provenance in the main benchmark. Report current-product performance and a common freshness-restricted slice where evidence permits. Apply freshness labels at reporting time; preserve all results. Missing dates are unknown, not eligible. Ruleset dates are provenance, not model training cutoffs.

Use the earliest known credible public answer-bearing artifact, not just CVE publication or a Git timestamp. Compare it with the bound model's documented cutoff. This reduces a specific exposure risk; it cannot prove cleanliness. New advisories, private packs, or an offline workspace do not rule out prior exposure or provider enrichment. Temporal performance signals also depend on benchmark construction. [Test of Time](https://aclanthology.org/2026.acl-long.1693/).

| Audit | Method and limit |
|---|---|
| Identity-only knowledge | Fresh separate session with repo/version, optionally a targeted path, but no code, diagnosis, or candidate CVE. Bound answers and allow `UNKNOWN`; verify associations. Another valid advisory is not hallucination merely because it is not the selected target. |
| Vulnerable/fixed discrimination | Reuse eligible planned observations. Compare the same root-cause allegation across validated states. This measures discrimination, not whether memory caused the original hit. |
| Metadata sensitivity | Optional paired comparison of `standard` and `metadata_blinded` on the same inputs and budgets. Record exactly which metadata changed. Remaining identity cues and changes to useful context limit interpretation; no source renaming is included. |
| Retrieval visibility | Record relevant content entering model context. A request alone is not evidence that a page was read. Matched retrieval-enabled/offline trials can estimate a behavioral effect, not inspect memory. |

Start with fixed-state observations and inexpensive probes where the actual product supports them. Do not substitute its presumed base model or feed probe answers into scored sessions. Freeze the probe wording/output contract: at most one CVE and one GHSA, or `UNKNOWN`, with blind and path-targeted results separate. Use verified pre-cutoff associations as positive controls and unaffected-version controls; decoy paths are negative controls only for explicitly path-scoped questions. Repeat surprising associations in fresh sessions.

A credible post-cutoff association flags a temporal inconsistency for investigation; it does not uniquely falsify a vendor cutoff. Keep documentary cutoff-source verification separate from behavioral statuses: inconsistency detected, none detected, or inconclusive. None detected is not proof of no exposure.

Report available knowledge, discrimination, identity effects, and retrieval limitations separately. Do not produce a memorization percentage, force a memory-versus-reasoning verdict, or embed CVE-printing instructions in source. Formal identity/temporal contrasts and popularity regressions remain future research in the math appendix, outside release and promotion gates.

## 8. Repetitions, uncertainty, and feedback for harness improvement

Pilot nondeterministic systems on a diverse small set, for example 8 to 10 cases at three repetitions. Measure variance, failures, review effort, and cost, then simulate the case/repetition counts needed for a declared effect or interval width. Neither five cases per class nor five repetitions is a statistical rule. One accuracy run is enough only for a demonstrably deterministic pinned configuration; timing may need repeats.

Compare systems on common inputs and policies. Preserve repository, family, shared-scan, and repeat dependencies in uncertainty estimates. Show per-project results and leave-one-project-out sensitivity when repositories are few. More repeats do not create more independent applications. Report mean per-run detection first; optional best-of/all-runs views have different meanings. [Planning formulas](EVALUATION_MATH.md#5-repetitions-and-uncertainty) state the assumptions.

SASTbench owns the evaluations, observations, comparison reports, and gate decisions below. Humans or an engineering agent in a separate repository own the proposed changes. SASTbench does not edit the harness, open improvement PRs, or deploy a candidate automatically. This is evaluation support for an automated engineering loop, not recursive self-modification by the benchmark.

The surrounding development loop is:

1. Freeze development labels, evaluator, workload, and improvement/regression constraints.
2. Evaluate baseline and candidate on the same contract; provide development failure and review feedback.
3. Have the separate engineering workflow change the harness, rules, or configuration, keeping labels, scorer, and protected inputs fixed.
4. Return a gate decision and evidence from detection and precision/control/completion/burden/cost constraints. The external workflow owns any promotion after those constraints pass.
5. Evaluate releases on declared repository-held-out or later-case sets with limited feedback. First-release splits use public cases; restricted evaluation access does not make those cases unpublished.

The cycle returns from re-test to the next harness run with the selected candidate configuration. Approved development cases and scoring rules stay fixed during that cycle; case intake and label changes follow a separate reviewed release.

Keep related targets, fixes, variants, and overlapping snapshot families together. A chronological split must exclude related leakage; repository holdout supports a different claim from within-repository tuning. Repeatedly tuning against leave-one-repository-out scores turns them into validation, not untouched holdout. Rolling ingestion still needs human admission and frozen releases; the newest 90 days are not automatically unseen.

Give the engineering agent development results and permitted traces only. Keep holdout labels, per-case matching decisions, and diagnostic artifacts with the independent evaluator; release only predeclared aggregate feedback. Limit repeated holdout queries. A public repository-held-out case tests tuning separation, not guaranteed absence from foundation-model training. New reviewed development findings enter a new corpus version, never an agent-authored change to frozen answers.

## 9. Bring your own test cases

An organization can build a private benchmark around its own code and use its feedback to refine its harness. Support namespaced, versioned packs through the same schemas, adapters, observer SDK, and scorer. This workflow belongs in the first end-to-end pilot; building the separate improvement agent does not.

This helps teams:

- **Catch recurring failures:** preserve reviewed internal bugs as regression cases when prompts, models, rules, or filtering change.
- **Test local security rules:** represent the organization's frameworks, permissions, trust boundaries, and intentional capabilities with validated targets and controls.
- **Measure changes on relevant code:** compare detection, false allegations, completion, review effort, and cost on their own workload, with traces to investigate what changed.

### Skill-guided intake and case preparation

Provide a case-authoring skill as the primary onboarding path. It uses the shared library/CLI operations to prepare an organization-owned pack. Users can supply existing cases, internal documents, GitHub commit links, or a repository URL/local path. The skill gathers the selected documents, commit metadata, diffs, and relevant source as evidence for Jev; a repository URL is an intake instruction, not evidence that the classifier has inspected its code. A hosted service is not required.

Start with existing security fixes and findings through these inputs:

- **Import cases:** internal security reviews, incident records, fixes, and findings supplied through JSON/SARIF or mapped ticket/CSV exports. A CVE is not required.
- **Point to a repository:** accept a local path or authorized repository reference with a declared component/history scope and available fix commits or issue references. Extract candidate changes and assemble evidence from that security history. A repository reference alone cannot establish target labels.
- **Provide documents:** accept internal review reports, incident write-ups, tickets, and remediation notes. Preserve document/page/section references and resolve each proposed case to its affected source and snapshot. If those artifacts or root-cause evidence are missing, record the gap and retain a draft.

The proposed `corpus init`, `corpus import`, and `corpus validate` operations create and check drafts. They retain source references, pinned snapshots, candidate affected locations, assumptions, and the evidence behind each proposed label. Importing a scanner allegation does not validate it; closed tickets, suppressions, and accepted risks are not automatic negative labels.

The skill can use Jev to identify candidate security fixes or findings in the supplied material, classify their evidence, suggest possible duplicates, and flag inconsistencies or missing context under Section 11. Record suggestions alongside their evidence. Jev remains an optional dependency; the same workflow accepts manually prepared drafts. This step does not certify correctness, remove secrets, or approve a case. Curators and independent reviewers apply Section 2 before a draft becomes eligible for scoring.

The skill produces draft case records, an evidence/missing-context review queue, and a proposed private-pack manifest. Approval records and validated labels belong to the evaluator. The skill must never infer an approved label from a document's wording, a classifier confidence score, or a successful import.

### From private cases to a harness improvement

1. Use the skill to import existing cases or prepare candidates from selected repository history and supplied documents.
2. Validate target labels and any fixed/safe controls, recording the human decisions and evidence.
3. Publish an approved version into the organization's private case registry. Freeze development and evaluation membership, grouping related fixes and variants together.
4. Run the baseline harness on that version. Use development scores and available observer traces to identify missed targets, false allegations, lost context, and filtering mistakes.
5. Return that feedback to humans or the separate engineering agent. Evaluate the candidate harness they supply against the frozen evaluator and acceptance constraints in Section 8, then repeat harness runs on the same approved cases. Keep protected evaluation feedback outside the tuning loop.
6. Admit additional cases or label corrections through review into a new version, retaining earlier run records.

Allow organization-specific categories with declared matching rules. Organizations may supply architecture and security-policy context as versioned runtime input, while expected answers stay with the evaluator. Tune harness configuration on development cases; importing a pack does not fine-tune a model. Within-repository evaluation supports claims about that codebase; cross-repository claims need separate coverage. Report private and public scores separately; any combined score needs explicit weights.

Keep source, labels, results, and traces in organization-controlled storage by default. Remote inference requires an approved data-egress and retention policy; local logs alone do not make it private. Credentials stay outside manifests. Retain draft/reviewed/released states so new cases cannot silently change an earlier denominator.

Documentation deliverable: `docs/BRING_YOUR_OWN_CORPUS.md` and the case-authoring `SKILL.md`, written when interfaces exist, covering these inputs, mappings, human validation, splits, provider/privacy settings, execution, and one complete example from an internal fix or document to a measured harness change. Reuse the corpus-maintenance review and correction rules from Section 2.

## 10. Packaging, deliverables, and build order

Ship a core Python package with CLI/library entry points, separate versioned corpus packs, pinned scanner images where useful, and downloadable HTML/CSV/JSON reports. Default to hash-checked preparation recipes that fetch pinned sources. Check use and redistribution permissions against each exact snapshot and relevant paths, not just today's repository-wide license. Source archives may be distributed separately where permitted; they are not permanently prohibited. Keep large source archives, proprietary tools, credentials, and protected labels out of the core package. A static documentation site and local trace viewer are sufficient initially. A hosted service and public leaderboard are not required.

### What SASTbench delivers

- **Versioned CVE corpus:** real vulnerable repository snapshots, fixes, target mechanisms, accepted evidence locations, and validated fixed/safe controls where available. Published advisories and maintainer records supply the vulnerability evidence; benchmark review checks the exact source mapping and scoring label used by the evaluator. Organization-owned packs use the same format.
- **SDK for harness visibility:** records model/tool calls, context delivered to the model, candidate findings, filtering decisions, errors, and timing. A shared trace format links those observations to scan results and marks incomplete capture. It shows recorded harness behavior, with the reasoning limits described in Section 6.

The evaluator turns those assets into detection, control, review-burden, completion, cost, and observability reports. It does not claim that every repository vulnerability is labeled.

Version the engine, schemas, SDK/connectors, adapters, mappings, scorer, corpus, and system configuration independently; record applicable versions in every run bundle and provide explicit migrations.

| Deliverable | Acceptance check |
|---|---|
| D1. Core protocol and evaluator | Versioned schemas; validate/plan/run/import/score/report interfaces; offline score replay without an agent framework or LLM judge. |
| D2. Versioned CVE corpus release | Admitted repositories/snapshots frozen in a release manifest; workflow/role annotations, source provenance, targets, families, coverage, splits, validation records, hashes, and preparation recipes; safe-capability pilot aiming for ten repositories with independent property/evidence review; visible control gaps and private-pack starter template. |
| D3. Integrations and backend decision | Own-harness adapter with observer SDK integration, callback/native-trace connectors, pinned CLI scanner, SARIF/native import, multi-model execution, parity/conformance tests, and an Inspect/Harbor/direct-runner comparison. |
| D4. Reproducible run and observability bundle | Raw/canonical predictions, status, setup/usage/cost, policy and version provenance, model/tool calls, model-visible context and filtering events with per-category capture status, and evaluator-side decisions. Equivalent inputs score identically across paths; diagnostic claims require their supporting capture. |
| D5. Detection report and review pack | Workload-separated scorecards: known-target detection rate (full recall) and budget curves with first-hit ranks, target density, conditional control bounds/coverage, sampled review, uncertainty, cost, local trace timeline, and baseline/candidate comparison. Native ranking and unranked diagnostics labeled separately; imported vendor runs marked independently verified or unverified. |
| D6. Development gate | Frozen acceptance constraints and protected evaluation separated from development feedback; one complete organization-owned case import, review, baseline/candidate comparison, and decision using the same scorer. |
| D7. Guides and examples | Install, native scanner, own harness/multi-model, SDK/connector integration and capture limits, PR mode, output import, private corpus, safe-control/adapter/case authoring, and offline replay; case-authoring SKILL.md for repository/document intake and corpus-maintenance SKILL.md with the correction-PR workflow. Turn the worked scoring and trace examples into conformance fixtures. |

Build in this order:

1. Contracts and scorer fixtures: unique targets, claim budgets, unknowns, duplicates, shared snapshots, partial/error states, and unavailable controls.
2. A small end-to-end real-case slice with our own harness and one pinned scanner: grouped inputs, isolation, controls, canonical outputs, and replay. Include the observer SDK at shared boundaries, context selection, and finding filtering without replacing the harness. Exercise the case-authoring skill with imported findings, repository fixes, and a supporting document on an approved sample pack, then carry it through a baseline/candidate comparison.
3. Native PR integration, review workflow, repeated-run pilot, backend comparison, and buyer report. Expand validated coverage, including the ten-repository safe-control pilot.
4. Broader protected splits, release gates, and selected follow-on experiments.

Migrate reviewed cases, raw results, and ingestion utilities rather than discarding them. Replace per-case execution and unmatched-as-FP scoring, remove ground truth from adapter requests, bind actual models, and replace live Semgrep rule selection. Fix finding-count TP versus region-count FN inflation, represent zero assessable controls as N/A, and retire the composite `agenticScore` requirement from the result schema. Adapter errors must have explicit status, not empty successful output; update the adapter guide accordingly. Make sv-agent setup explicit and the PR runner's dual-scan fallback opt-in. Keep README and mapping documentation synchronized and legacy results clearly labeled. These are pending implementation changes, not fixes made by this design. New scoring is not directly comparable to old headline scores.

Reuse prior art with clear boundaries: [Delta-Bench](https://doi.org/10.1109/ESEM.2017.24) for differential vulnerable/fixed SAST evaluation, [OpenSSF CVE Benchmark](https://github.com/ossf-cve-benchmark/ossf-cve-benchmark) for affected/patched product evaluation, [IRIS](https://arxiv.org/abs/2405.17238) for whole-project LLM-assisted static analysis behind [CWE-Bench-Java](https://github.com/iris-sast/cwe-bench-java), and [PrimeVul](https://arxiv.org/abs/2403.18624) for pair evaluation. The separately published [SastBench](https://arxiv.org/abs/2601.02941) is triage prior art whose approximate negative labels are not equivalent to our reviewed safe controls. SWE-bench release/prediction separation and CyberGym/ExploitGym packaging/isolation are further review leads, not a commitment to adopt exploitation tasks or their oracles.

## 11. Optional Jev annotation audit

Use Jev optionally to check draft annotations before human approval, after mechanical checks and evidence assembly. It is a corpus-quality assistant, not a scorer or required dependency. For target annotations, also test category support, patch/mechanism consistency, missing evidence, and possible duplicate root causes.

For candidate capability-safe and fixed-target controls:

1. Supply the pinned code, relevant callers/guards/configuration, proposed security property, documented deployment/authorization assumptions, and supporting test, advisory, or patch evidence where available. Assign evidence IDs. Do not ask Jev to confirm that a region is simply "safe."
2. Ask separately whether the supplied evidence supports each proposition: the code implements the stated restriction; the restriction applies before the operation on the shown path; the actor/input assumptions have supporting evidence; and the callers/configuration named in the rationale are covered. Return `supported`, `contradicted`, or `insufficient_context` for each. Reference only supplied evidence IDs; a reference is not automatically valid support. These questions do not establish the absence of other paths or bypasses.
3. Queue the judgments for human review. Keep the record in draft until the normal curator and independent-review process establishes the label, whether Jev flags a problem or not. Confidence never approves a label, replaces missing evidence, or raises its validation level. Never automatically merge/delete cases, overwrite validated labels, or declare a repair safe.

Pilot on independently reviewed safe, unsafe, and incomplete-context examples, plus known annotation errors and possible duplicates. Compare human-only and Jev-assisted review against those frozen labels. Track incorrect safety-supporting suggestions, missed problems, false warnings, reviewer time, and API cost; inspect unflagged records too. Adopt only if the assistance saves review effort without weakening label quality. Private-code submission follows the provider/data-egress approval rules in Section 9.

Deliver a review queue and adopt/skip report with input hashes, question/model versions, raw suggestions, and human outcomes. No Jev calls during scoring or replay. Jev inside an evaluated harness is a different experiment. [TypeSafe's question interface](https://docs.typesafe.ai/primitives) and [commit-miner's evidence protocol](https://github.com/devanshbatham/commit-miner/blob/main/docs/JEV_PROTOCOL.md) motivate this pilot, not claims of established annotation accuracy.

TypeSafe's [Security Incidents evaluation](https://evals.typesafe.ai/security_incidents) illustrates bounded judgments combined by code into workflow decisions; it does not validate CVE annotation or SAST accuracy. Its [documented Jev limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13) reinforce keeping counting, date comparisons, and exact checks in code. Stable confidence values alone do not establish correctness or calibration on our cases.

## 12. Configuration and release decisions

- Select repositories and snapshots through admission review, then freeze the workload, product editions/model snapshots, network profiles, scan limits, and full/PR review-budget grids.
- Approve coverage priorities, evidence requirements, and protected project/snapshot groups before seeing comparative scores.
- Sampling proportions, severity mix, repository caps, and cross-workload weights remain open decisions. The workload classes and candidate list do not fix that distribution.
- Set pilot uncertainty goals and promotion tolerances; leave backend selection to D3's comparison.
- Verify corpus redistribution and named-result publication permissions under the actual licenses. Anonymization is not an assumed workaround.
- A project rename is planned; the current name and example CLI/library names are placeholders. Avoid unsupported first/only, zero-day, and contamination-free claims.
