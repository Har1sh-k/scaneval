# SASTbench

> Can your scanner find real vulnerabilities in agentic repos without flagging the code the agent is supposed to run?

SASTbench evaluates whether static analyzers can detect real vulnerabilities in agentic codebases without treating intentional agent capabilities as vulnerabilities.

## What SASTbench Is and Is Not

**What gets scored:**
SASTbench measures whether a static analyzer can detect annotated vulnerable code regions (true positives) without flooding the user with false positives on nearby code.
Scoring uses six canonical vulnerability kinds (`command_injection`, `path_traversal`, `ssrf`, `auth_bypass`, `authz_bypass`, `sql_injection`) and region-level overlap matching.

**Why capability-safe regions matter:**
Agentic code often calls dangerous APIs on purpose — `subprocess.run()`, `fs.writeFile()`, `requests.get()`.
A good scanner should flag those calls only when the guard is missing, not every time they appear.
Capability-safe cases contain properly guarded dangerous code.
The Capability FP Rate metric measures how often a scanner flags guarded code that it should leave alone.

**What SASTbench does not measure:**
- Prompt injection as a runtime attack (it measures whether tainted prompt data reaches code sinks)
- Secret scanning quality
- Severity calibration across vendors
- End-to-end agent runtime exploits
- General non-security code quality

## Quick Start

```bash
# Install the harness plus pytest
python -m pip install -e ".[dev]"

# Optional: install the official baseline scanners
python -m pip install -e ".[official-adapters]"

# Run benchmark against a scanner
python scripts/run.py --scanner semgrep --track core

# Run with per-finding audit trail
python scripts/run.py --scanner semgrep --track core --verbose

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
- Git (required for `scripts/setup_repos.py`)

The benchmark harness itself only uses the Python standard library. Scanner CLIs are optional and can be installed separately or via the `official-adapters` extra.

### Full Track Snapshots

Full Track cases reference pinned snapshots under `.repos/`. Populate them with:

```bash
python scripts/setup_repos.py
```

If a previous clone was interrupted and left behind a `.git` directory without checked-out files, rerunning `python scripts/setup_repos.py` repairs that snapshot.

After setup, validate the full benchmark surface with:

```bash
python scripts/validate.py --track full
```

### PR Simulation Mode

SASTbench also supports benchmarked PR simulation with:

```bash
python scripts/run.py --scanner semgrep --mode pr --track core
```

PR mode compares a clean base tree with a vulnerable head tree and measures whether the scanner reports the introduced vulnerability as a review finding. See [docs/PR_MODE.md](docs/PR_MODE.md) for the execution model, metrics, case requirements, and adapter behavior.

Verify PR simulation metadata integrity for real-world cases with:

```bash
python scripts/verify_pr_strict.py
```

PR simulation (`baseCommit`/`headCommit`) and remediation verification (`fixCommit`/`fixValidation`) are separate concerns. PR mode runtime does not use `fixCommit`. See [docs/PR_MODE.md](docs/PR_MODE.md#pr-pair-verification-vs-remediation-verification) for details.

### LLM Model Tracking

Adapters for LLM-backed scanners can expose an `LLM_MODEL` constant. When present, results JSON includes `scanner.llmModel` and the model is printed at run start. Set via environment variable (e.g. `SECUREVIBES_LLM_MODEL`).

### Tests

Run benchmark self-tests from the repo root with:

```bash
python -m pytest -q
```

### Smoke Tests for Official Adapters

Verify your scanner installation works before running the full benchmark:

```bash
# Semgrep on one Python case
python scripts/run.py --scanner semgrep --track core --case-id SB-PY-SV-001

# Bandit on one Python case
python scripts/run.py --scanner bandit --track core --case-id SB-PY-SV-001
```

Both should show `TARGET HIT` for SB-PY-SV-001 (SSRF in reference fetcher).

## Tracks

- **Core Track**: Self-contained, vendored cases. 5-minute quickstart, deterministic runs.
- **Full Track**: Core Track plus pinned snapshots from real public repositories.

## Status

- **17 Core Track** cases (synthetic vulnerable, capability safe, mixed intent)
- **40 Full Track** cases (real-world disclosed from public repositories)
- **57 total cases** across Python, TypeScript, and Rust

## Official Adapters

- `semgrep`
- `bandit`

## Baseline Reference Results

These were measured on March 24, 2026 against the Core Track using the current official adapters in this repository:

| Adapter | Version | Rule Set Used | Recall | Precision | Cap FP Rate | Agentic Score | Notes |
|---------|---------|---------------|--------|-----------|-------------|---------------|-------|
| `semgrep` | `1.136.0` | `semgrep scan --config auto --lang <language>` | `14.3%` | `50.0%` | `0.0%` | `0.0%` | 2 target hits, 2 additional findings, 0 mixed-intent hits |
| `bandit` | `1.8.6` | `bandit -r -f json` (default built-in Bandit rules; no custom config) | `14.3%` | `33.3%` | `16.7%` | `0.0%` | Python-only; TS/Rust cases are unsupported and still score as misses across the entire Core Track |

Semgrep `auto` fetches the active Semgrep registry bundle and may change over time.
Bandit results above use the default built-in rule set because the official adapter does not pass `-c`, `-t`, or `-s`.

## Repo-Local Agent Skills

If you want another agent to work on this repo, use these repo-local skills:

- [skills/sastbench-results-validation/SKILL.md](skills/sastbench-results-validation/SKILL.md): verify claimed benchmark or PR-mode results, rerun scanners, confirm the exact rule set used, and distinguish valid runs from environment or scanner failures.
- [skills/sastbench-adapter-authoring/SKILL.md](skills/sastbench-adapter-authoring/SKILL.md): build or update a SASTbench scanner adapter, including rule mapping, metadata capture, PR-mode support, tests, and harness validation.

## V1 Canonical Vulnerability Kinds

| Kind | Capability Surface |
|------|--------------------|
| `command_injection` | Executing commands |
| `path_traversal` | Reading and writing files |
| `ssrf` | Making outbound network requests |
| `auth_bypass` | Authenticating callers and connections |
| `authz_bypass` | Enforcing per-identity permission scopes |
| `sql_injection` | Querying and mutating data stores |

## Scoring

Default reporting uses security-readable labels:

- **Target Hit Rate**: did the scanner detect the disclosed/annotated vulnerability?
- **Intent Accuracy**: in mixed-intent cases (safe + unsafe code together), did the scanner correctly hit the target without flagging the guarded code?
- **Capability Noise**: how often did the scanner flag properly guarded capability code?
- **Additional Findings**: findings beyond the annotated target (on Full Track real-world cases these may be legitimate, not necessarily wrong)

Verbose mode (`--verbose`) also shows the underlying benchmark internals: Recall, Precision, Capability FP Rate, Mixed-Intent Accuracy, and Benchmark Index (geometric mean of Recall, 1 - Capability FP Rate, Intent Accuracy).

### Core Track vs Full Track scoring language

**Core Track** cases are closed-world synthetic benchmarks. Every finding outside the annotated region is a known false positive. Strict scoring labels apply.

**Full Track** cases are real-world repo snapshots with one disclosed vulnerability. Additional findings may be legitimate issues in the repo. The benchmark only scores whether the disclosed target was detected - it does not claim that every other finding is wrong.

### PR mode scoring language

PR mode uses a different top-level summary:

- **Introduced Target Hit Rate**: did the scanner report the vulnerability introduced by the simulated PR?
- **Review Noise**: new-in-head review findings that did not match the introduced target
- **Capability Noise**: review findings that hit capability-safe regions

See [docs/PR_MODE.md](docs/PR_MODE.md) for the full PR-mode model and output schema.

## OWASP Agentic Top 10 Alignment

SASTbench cases are mapped to the [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) as a reporting crosswalk. Each case carries a `standards.owaspAgenticTop10` field with primary and optional secondary ASI category labels. This mapping enables filtering and aggregating results by OWASP category without changing how the benchmark scores findings.

SASTbench currently has strong coverage for ASI02 (Tool Misuse & Exploitation), ASI03 (Identity & Privilege Abuse), and ASI05 (Unexpected Code Execution), plus targeted coverage for ASI01, ASI04, ASI06, and ASI07.

ASI08 (Cascading Failures), ASI09 (Human-Agent Trust Exploitation), and ASI10 (Rogue Agents) remain out of scope for the benchmark's current scoring model because they depend on system-level runtime behavior, human-in-the-loop evaluation, or long-horizon agent behavior rather than stable region-level SAST findings.

See [docs/OWASP_AGENTIC_TOP10_MAPPING.md](docs/OWASP_AGENTIC_TOP10_MAPPING.md) for the full mapping table and per-category case lists.

## Generated Directories

These directories are created at runtime and excluded from git via `.gitignore`:

| Directory | Created by | Contents |
|-----------|-----------|----------|
| `results/` | `scripts/run.py` | Results JSON, HTML reports, raw scanner artifacts |
| `.repos/` | `scripts/setup_repos.py` | Cloned real-world repo snapshots for Full Track |
| `.securevibes/` | securevibes-agent scanner | Scanner knowledge-base state (cleaned up by adapter) |
| `.claude/` | Some LLM-backed scanners | Scanner config/skills state (cleaned up by adapter) |
| `__pycache__/` | Python | Bytecode cache |
| `node_modules/` | npm | Node.js dependencies (in case project dirs) |

Do not commit these directories. If you see them in `git status`, check `.gitignore`.

## Repository Layout

```text
sastbench/
|- manifest.json
|- LICENSE
|- pyproject.toml
|- schema/            # JSON schemas for cases and results
|- taxonomy/          # Canonical kinds, capabilities, languages
|- cases/
|  |- core/           # Synthetic vendored cases
|  `- full/           # Real-world disclosed cases
|- adapters/          # Scanner adapters (semgrep, bandit, etc.)
|- scripts/           # run, validate, report
`- tests/             # Benchmark self-tests
```

## License

MIT
