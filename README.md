# ScanEval

> The replacement core is an alpha (`2.0.0a1`) that now runs end to end: versioned contracts, case packs with mechanical checks and explicit human approval, an immutable source cache and pinned snapshot export, an invocation runner, two real adapters (pinned Semgrep OSS and the own LLM harness), an observer connection at the harness model boundary, a review workflow, saved-output scoring and offline replay, and an HTML report. See [initial build](docs/INITIAL_BUILD.md) for what it does and does not do, and [the pilot report](docs/PILOT.md) for the first real runs.
>
> **No benchmark result exists.** Every case in the repository is a draft, no matching decision has been approved, and confirmed detection is zero. The preserved pilot runs are pipeline demonstrations, not measurements of any scanner.
>
> The existing `scripts/` runner and historical scores still use legacy scoring and are labeled legacy throughout this file. The broader [design](docs/DESIGN_DECISIONS.md) is not fully implemented; repositories for the first public-workload release remain under selection.

> Can your scanner find real vulnerabilities without flagging authorized capabilities?

ScanEval evaluates whether static analyzers find real vulnerabilities at an acceptable review cost. The proposed [workload scope](docs/DESIGN_DECISIONS.md#workload-classification) covers conventional applications, conventional automation, AI-assisted applications, and agentic applications, with separate scorecards. The legacy `cases/` corpus is agentic-heavy, and its `agentic`/`generic` CLI profiles are legacy selections, not the proposed workflow classifications. The new core's corpus is the draft pilot pack under `corpus/pilot/`, which covers three cases and no controls.

## Try the new evaluation core

```bash
python -m pip install -e ".[dev]"
scaneval demo results/diagnostic-demo
scaneval replay results/diagnostic-demo --output results/diagnostic-replay.json
# Open results/diagnostic-demo/report.html locally.
```

This uses fabricated evaluator fixtures, not a live scanner or admitted CVEs. It tests scoring rules without model calls. Output paths must be new. The [SDK guide](docs/OBSERVER_SDK.md) covers opt-in harness visibility and capture limits.

Replay one of the preserved pilot bundles offline, with no network and no model call:

```bash
scaneval replay corpus/pilot/runs/2026-09-20-semgrep/invocations/oauth2-proxy-f4b33b64__semgrep-oss-1.177.0-rules-40b8c63f__r1
# scaneval: review state draft: these numbers come from decisions with no recorded human approval
```

That warning is the accurate state of every bundle in this repository.

### Evaluation core commands

| Command | What it does |
|---|---|
| `scaneval validate <kind> <path>` | Validate one of nine versioned contracts: `scan-request`, `scan-result`, `execution-record`, `evaluation-plan`, `review-decisions`, `review-record`, `case-pack`, `run-config`, `run-manifest`. |
| `scaneval demo <new dir>` | Create the fabricated conformance bundle. No scanner or model runs. |
| `scaneval score --plan --result --decisions` | Score separately stored records. |
| `scaneval replay <bundle>` | Recompute a saved bundle offline. |
| `scaneval report <bundle> --output` | Render a standalone HTML report for a saved bundle. |
| `scaneval corpus init\|add-snapshot\|import\|validate\|approve\|admit\|disposition` | Build and mechanically check an evaluator-side case pack, and record explicit human reviews, admissions, and dispositions. |
| `scaneval plan --pack --snapshot-id --tree-hash --output` | Build one evaluation plan for a materialized input. |
| `scaneval run <config> --output <new dir>` | Execute one frozen run configuration into a new run directory. |
| `scaneval review init\|record\|approve\|status` | Draft, re-draft, approve, and inspect the review of one invocation bundle. |

Only `corpus validate --snapshot-id` and `run` reach the network; what `run` contacts depends on the configured systems. Everything else is offline. Exit code `2` means the command could not be carried out, `1` means it ran and reports a negative result, `0` means it ran and reports nothing wrong, which is not a statement that any label or decision is correct.

Guides: [initial build](docs/INITIAL_BUILD.md) for the current build and its limits, [pilot report](docs/PILOT.md) for the first real runs, [bring your own corpus](docs/BRING_YOUR_OWN_CORPUS.md) for the organization-owned pack path, [design decisions](docs/DESIGN_DECISIONS.md) and [evaluation math](docs/EVALUATION_MATH.md) for the destination.

### Evaluation core status

| Area | State |
|---|---|
| Contracts, scoring, replay, report | Implemented |
| Case packs, mechanical (L1) checks, plan generation | Implemented |
| Source cache, pinned export, provenance | Implemented; `standard` profile only, `metadata_blinded` refused |
| Invocation runner, bundles, run manifest | Implemented for full scans |
| Adapters | `semgrep` (pinned local rules) and `llm-harness` (own harness) |
| Observer connection | Model boundary of the own harness only; tool dispatch and the finding lifecycle before submission are unavailable |
| Review workflow | Machine drafts route candidates; approval requires an explicit reviewer name |
| Reviewed labels, admitted cases, controls | **None.** Every case is draft, no control is defined |
| Corpus aggregation, precision sampling, promotion gates, trace viewer, SARIF import, native PR mode, enforced isolation | Not implemented |

## Legacy runner: what gets scored

**What gets scored:**
ScanEval measures whether a static analyzer can detect annotated vulnerable code regions (true positives) without flooding the user with false positives on nearby code.
Scoring uses six canonical vulnerability kinds (`command_injection`, `path_traversal`, `ssrf`, `auth_bypass`, `authz_bypass`, `sql_injection`) and region-level overlap matching.

**Why capability-safe regions matter:**
Conventional automation and agentic code often call dangerous APIs on purpose: `subprocess.run()`, `fs.writeFile()`, `requests.get()`.
A good scanner should flag those calls only when the guard is missing, not every time they appear.
Capability-safe cases contain properly guarded dangerous code.
The legacy Capability FP Rate currently covers six synthetic safe regions, not a real-world safe-control corpus. The design requires reviewed, property-specific controls for buyer-facing results.

**What ScanEval does not measure:**
- Prompt injection as a runtime attack (it measures whether tainted prompt data reaches code sinks)
- Secret scanning quality
- Severity calibration across vendors
- End-to-end agent runtime exploits
- General non-security code quality

## Legacy runner quick start

```bash
# Install the harness plus pytest
python -m pip install -e ".[dev]"

# Optional: install the official baseline scanners
python -m pip install -e ".[official-adapters]"

# Run benchmark against a scanner
python scripts/run.py --scanner semgrep --track core

# Run with per-finding audit trail
python scripts/run.py --scanner semgrep --track core --verbose

# Filter by profile (agentic only, generic only, or both)
python scripts/run.py --scanner semgrep --track full --profile agentic
python scripts/run.py --scanner semgrep --track full --profile generic
python scripts/run.py --scanner semgrep --track full --profile all

# Model-specific run: only score vulns disclosed AFTER a model's knowledge cutoff
python scripts/run.py --scanner semgrep --track full --model opus-4.8
# Or gate on an explicit date
python scripts/run.py --scanner semgrep --track full --since 2026-01-31

# Validate case definitions (Core Track by default)
python scripts/validate.py

# Generate summary report
python scripts/report.py results/<results-file>.json

# Generate deep report with per-finding detail
python scripts/report.py results/<results-file>.json --verbose
```

PR simulation mode is documented in [docs/PR_MODE.md](docs/PR_MODE.md).

## Setup

### Requirements

- Python 3.11+
- Git (required by `scripts/setup_repos.py`, and by the new core's source cache and pinned export)
- Node.js, only for the observer SDK and the own-harness adapter

The new core uses `jsonschema` for contract validation. The legacy runner uses the Python standard library. Scanner CLIs are optional and can be installed separately or via the `official-adapters` extra. The `llm-harness` adapter additionally needs a local checkout of the harness and a built observer SDK (`npm ci && npm run build` in `sdk/typescript`).

### Legacy Full Track snapshots

Full Track cases reference pinned snapshots under `.repos/`. Populate them with:

```bash
python scripts/setup_repos.py
```

If a previous clone was interrupted and left behind a `.git` directory without checked-out files, rerunning `python scripts/setup_repos.py` repairs that snapshot.

After setup, validate the full benchmark surface with:

```bash
python scripts/validate.py --track full
```

### Legacy PR simulation mode

ScanEval also supports benchmarked PR simulation with:

```bash
python scripts/run.py --scanner semgrep --mode pr --track core
```

PR mode compares a clean base tree with a vulnerable head tree and measures whether the scanner reports the introduced vulnerability as a review finding. See [docs/PR_MODE.md](docs/PR_MODE.md) for the execution model, metrics, case requirements, and adapter behavior.

Verify PR simulation metadata integrity for real-world cases with:

```bash
python scripts/verify_pr_strict.py
```

PR simulation (`baseCommit`/`headCommit`) and remediation verification (`fixCommit`/`fixValidation`) are separate concerns. PR mode runtime does not use `fixCommit`. See [docs/PR_MODE.md](docs/PR_MODE.md#pr-pair-verification-vs-remediation-verification) for details.

### Legacy LLM model tracking

Adapters for LLM-backed scanners can expose an `LLM_MODEL` constant. When present, results JSON includes `scanner.llmModel` and the model is printed at run start. Set via environment variable (e.g. `SECUREVIBES_LLM_MODEL`).

### Legacy model-specific benchmarks (knowledge-cutoff gating)

Prior exposure to advisories or fixes can affect LLM-backed scanner performance. The legacy runner's knowledge-cutoff gate aims to reduce one exposure route; it does not establish absence of memorization. The design retains credit for correct findings regardless of prior knowledge and uses freshness as a reporting slice.

Every real-world case records public-knowledge dates under `realWorld.disclosure`:

```json
"disclosure": {
  "ghsaPublished": "2026-06-18",
  "fixCommitDate": "2026-05-06"
}
```

The **legacy implementation's horizon** is `min(ghsaPublished, fixCommitDate, cvePublished)` over available metadata. Its gate retains dated cases only when that value is strictly after the selected cutoff. A commit timestamp alone does not establish first public availability. The proposed [freshness policy](docs/DESIGN_DECISIONS.md#7-freshness-and-memorization-audit) requires evidenced public artifacts, explicit unknown states, and reporting-time slices rather than this pre-scan filter.

Run a model-specific benchmark with `--model <id>` (resolved against [`taxonomy/models.json`](taxonomy/models.json), aliases supported) or an explicit `--since YYYY-MM-DD`:

```bash
python scripts/run.py --scanner securevibes-agent --track full --model opus-4.8
```

The runner prints how many dated cases were excluded as pre-cutoff, and the results JSON carries a `cutoff` block (`model`, `date`, `excludedCount`, `excludedCaseIds`). The legacy gate also retains records with missing disclosure dates; retention does not establish freshness. In the new design, applicable but missing dates remain unknown, while model-cutoff gating is not applicable to diagnostic fixtures.

Predefined models in `taxonomy/models.json`: `opus-4.8`, `opus-4.7`, `opus-4.6`, `sonnet-4.6`, `sonnet-4.5`, `gpt-5.5`, `gpt-5.4` (aliases accepted, e.g. `claude-sonnet-4-5`). `opus-4.8` is confirmed against the model card. The other Claude cutoffs are self-reported via `claude -p` and the GPT cutoffs via `codex exec` (3/3 consistent each); all are marked `"verified": false`, the runner prints a warning when they are used, and they should be confirmed against the official vendor model card before use in published results.

Backfill or refresh disclosure dates from the GitHub API (GHSA publish date + fix-commit date) with:

```bash
python scripts/backfill_disclosure_dates.py        # incremental; --overwrite to re-fetch
```

Add a model by appending an entry to `taxonomy/models.json` with its `knowledgeCutoff` from the official model card.

### Tests

Run benchmark self-tests from the repo root with:

```bash
python -m pytest -q
```

One suite covers both the evaluation core (`tests/test_v2*`) and the legacy runner. Two legacy snapshot tests skip when their checkouts are unavailable. No real CVE is silently imported and no paid model evaluation runs during these tests.

### Legacy smoke tests for official adapters

Verify your scanner installation works before running the full benchmark:

```bash
# Semgrep on one Python case
python scripts/run.py --scanner semgrep --track core --case-id SB-PY-SV-001

# Bandit on one Python case
python scripts/run.py --scanner bandit --track core --case-id SB-PY-SV-001
```

Both should show `TARGET HIT` for SB-PY-SV-001 (SSRF in reference fetcher).

## Legacy tracks

- **Core Track**: Self-contained, vendored cases. 5-minute quickstart, deterministic runs.
- **Full Track**: Core Track plus pinned snapshots from real public repositories.

## Legacy profiles

Cases carry an `agentic` boolean. The `--profile` flag filters runs by profile:

- `agentic`: only agentic cases (the default agentic-code thesis).
- `generic`: only non-agentic real-world cases (`caseType: real_world_generic`).
- `all`: both, with separate per-profile breakdown in the report.

Legacy cases without an `agentic` field are treated as agentic.

## Legacy corpus status

These counts describe the legacy `cases/` tree scored by `scripts/run.py`. They are not the new core's corpus, which is the draft pilot pack under `corpus/pilot/`.

- **17 Core Track** cases (synthetic vulnerable, capability safe, mixed intent)
- **189 Full Track** cases: 156 real-world disclosed (agentic) + 33 real-world generic (non-agentic)
- **206 total cases** across Python, TypeScript, Rust, Swift, Go, Java, and Clojure

## Legacy official adapters

- `semgrep`
- `bandit`

The new core's adapters are separate: `semgrep` against a pinned local rules checkout, and `llm-harness` for the own harness.

## Legacy baseline reference results

Historical legacy results measured on March 24, 2026 against the synthetic Core Track. They are not results under the proposed scoring design. Capability FP Rate uses six annotated synthetic safe regions; the composite Agentic Score is retained here only as a historical field.

| Adapter | Version | Rule Set Used | Recall | Precision | Cap FP Rate | Agentic Score | Notes |
|---------|---------|---------------|--------|-----------|-------------|---------------|-------|
| `semgrep` | `1.136.0` | `semgrep scan --config auto --lang <language>` | `14.3%` | `50.0%` | `0.0%` | `0.0%` | 2 target hits, 2 additional findings, 0 mixed-intent hits |
| `bandit` | `1.8.6` | `bandit -r -f json` (default built-in Bandit rules; no custom config) | `14.3%` | `33.3%` | `16.7%` | `0.0%` | Python-only; TS/Rust cases are unsupported and still score as misses across the entire Core Track |

Semgrep `auto` fetches the active Semgrep registry bundle and may change over time.
Bandit results above use the default built-in rule set because the official adapter does not pass `-c`, `-t`, or `-s`.

## Repo-Local Agent Skills

If you want another agent to work on this repo, use these repo-local skills:

- [skills/scaneval-results-validation/SKILL.md](skills/scaneval-results-validation/SKILL.md): verify claimed benchmark or PR-mode results, rerun scanners, confirm the exact rule set used, and distinguish valid runs from environment or scanner failures.
- [skills/scaneval-adapter-authoring/SKILL.md](skills/scaneval-adapter-authoring/SKILL.md): build or update a ScanEval scanner adapter, including rule mapping, metadata capture, PR-mode support, tests, and harness validation.

## Legacy V1 canonical vulnerability kinds

| Kind | Capability Surface |
|------|--------------------|
| `command_injection` | Executing commands |
| `path_traversal` | Reading and writing files |
| `ssrf` | Making outbound network requests |
| `auth_bypass` | Authenticating callers and connections |
| `authz_bypass` | Enforcing per-identity permission scopes |
| `sql_injection` | Querying and mutating data stores |

## Legacy scoring labels

This section describes legacy report labels. The replacement [scoring contract](docs/DESIGN_DECISIONS.md#4-scoring-without-exhaustive-repository-labels) separates known-target detection, reviewed precision, controls, and operational outcomes without a composite score.

Legacy reporting uses security-readable labels:

- **Target Hit Rate**: did the scanner detect the disclosed/annotated vulnerability?
- **Intent Accuracy**: in mixed-intent cases (safe + unsafe code together), did the scanner correctly hit the target without flagging the guarded code?
- **Capability Noise**: how often did the scanner flag properly guarded capability code?
- **Additional Findings**: findings beyond the annotated target (on Full Track real-world cases these may be legitimate, not necessarily wrong)

Verbose mode (`--verbose`) also shows legacy Recall, Precision, Capability FP Rate, Mixed-Intent Accuracy, and Benchmark Index (geometric mean of Recall, 1 - Capability FP Rate, Intent Accuracy). Benchmark Index and Agentic Score are not part of the proposed buyer scorecard.

### Core Track vs Full Track scoring language

**Core Track** cases are closed-world synthetic benchmarks. Every finding outside the annotated region is a known false positive. Strict scoring labels apply.

**Full Track** records identify targets in real-world snapshots, sometimes shared by several cases. Additional findings may be legitimate. The proposed scorer preserves unreviewed outcomes and evaluates all assigned targets per scan. The legacy scorer still treats unmatched findings as false positives and counts TP findings rather than unique targets, so its precision and recall must not be read as implementing that design.

### PR mode scoring language

PR mode uses a different top-level summary:

- **Introduced Target Hit Rate**: did the scanner report the vulnerability introduced by the simulated PR?
- **Review Noise**: new-in-head review findings that did not match the introduced target
- **Capability Noise**: review findings that hit capability-safe regions

See [docs/PR_MODE.md](docs/PR_MODE.md) for the full PR-mode model and output schema.

## Legacy OWASP Agentic Top 10 alignment

ScanEval cases are mapped to the [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) as a reporting crosswalk. Each case carries a `standards.owaspAgenticTop10` field with primary and optional secondary ASI category labels. This mapping enables filtering and aggregating results by OWASP category without changing how the benchmark scores findings.

ScanEval currently has strong coverage for ASI02 (Tool Misuse & Exploitation), ASI03 (Identity & Privilege Abuse), and ASI05 (Unexpected Code Execution), plus targeted coverage for ASI01, ASI04, ASI06, and ASI07.

ASI08 (Cascading Failures), ASI09 (Human-Agent Trust Exploitation), and ASI10 (Rogue Agents) remain out of scope for the benchmark's current scoring model because they depend on system-level runtime behavior, human-in-the-loop evaluation, or long-horizon agent behavior rather than stable region-level SAST findings.

See [docs/OWASP_AGENTIC_TOP10_MAPPING.md](docs/OWASP_AGENTIC_TOP10_MAPPING.md) for the full mapping table and per-category case lists.

## Generated Directories

These directories are created at runtime and excluded from git via `.gitignore`:

| Directory | Created by | Contents |
|-----------|-----------|----------|
| `results/` | `scripts/run.py`, `scaneval demo` | Results JSON, HTML reports, raw scanner artifacts |
| `.repos/` | `scripts/setup_repos.py`, `scaneval corpus validate`, `scaneval run` | Legacy Full Track snapshots and the new core's immutable source cache |
| `.securevibes/` | securevibes-agent scanner | Scanner knowledge-base state (cleaned up by adapter) |
| `.claude/` | Some LLM-backed scanners | Scanner config/skills state (cleaned up by adapter) |
| `__pycache__/` | Python | Bytecode cache |
| `node_modules/` | npm | Node.js dependencies (in case project dirs) |

Do not commit these directories. If you see them in `git status`, check `.gitignore`.

## Repository Layout

```text
scaneval/
|- manifest.json
|- LICENSE
|- pyproject.toml
|- src/scaneval/     # Evaluation core: contracts, cases, materialize, runner,
|  |                  # execution, review, scoring, report, CLI
|  |- schemas/        # The nine versioned JSON contracts
|  `- adapters/       # semgrep, llm-harness, and the harness driver
|- sdk/typescript/    # Opt-in observer emitter
|- corpus/pilot/      # Draft pilot pack, frozen run configs, preserved runs
|- docs/              # Design, math, initial build, pilot, guides
|- schema/            # Legacy JSON schemas for cases and results, plus schema/v2 trace events
|- taxonomy/          # Legacy canonical kinds, capabilities, languages
|- cases/
|  |- core/           # Legacy synthetic vendored cases
|  `- full/           # Legacy real-world disclosed cases
|- adapters/          # Legacy scanner adapters (semgrep, bandit, etc.)
|- scripts/           # Legacy run, validate, report
`- tests/             # Benchmark self-tests (new core and legacy)
```

## License

MIT
