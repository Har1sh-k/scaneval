---
name: scaneval-results-validation
description: Verify claimed ScanEval benchmark or PR-mode results. Use when an agent needs to rerun a scanner, confirm the exact scanner version and rule set, inspect results JSON and raw artifacts, distinguish valid runs from scanner or environment failures, and update docs or PR text with reproducible metrics.
---

# ScanEval Results Validation

Validate claimed ScanEval numbers before repeating them in docs, PRs, or comments.

Use this skill for:

- verifying README baseline tables
- checking whether a `results/*.json` file is valid and reproducible
- rerunning an official adapter and confirming the exact rule set used
- distinguishing real benchmark misses from invalid runs caused by scanner setup, sandboxing, or network failures
- summarizing the exact metrics, findings, and caveats for another agent or reviewer

For non-Codex agents, use this `SKILL.md` as the task instructions and then open the referenced repo files.

## Read these files first

Always inspect:

- `scripts/run.py`
- `scripts/scoring.py`
- `schema/results.schema.json`
- `scripts/report.py`
- `adapters/<scanner>/adapter.py`

If you are validating a documentation claim, also inspect:

- `README.md`

If you are validating PR-mode results, also inspect:

- `docs/PR_MODE.md`
- `scripts/pr_scoring.py`
- `scripts/pr_runner.py`

For exact commands, triage rules, and writeup guidance, read `references/validation.md`.

## Required output

A finished validation pass must state:

1. whether the result is valid, invalid, or only partially validated
2. the exact scanner version and adapter version
3. the exact command or rule set used
4. the results JSON path used as evidence
5. the aggregate metrics from `summary` or `prSummary`
6. the notable true positives, additional findings, and capability noise cases
7. any caveats that materially affect interpretation

## Workflow

### 1. Identify the exact claim

Before running anything, capture:

- scanner name
- track (`core` or `full`)
- mode (`benchmark` or `pr`)
- expected metrics or table row being claimed
- whether you are validating an existing artifact, a fresh rerun, or both

Do not compare numbers from different modes or tracks.

### 2. Confirm the real rule set from the adapter

Do not infer the rule set from memory. Read the adapter and write down the actual invocation pattern.

Current official adapter behavior:

- `adapters/semgrep/adapter.py` runs `semgrep scan --json --config auto --lang <language> <scan_root>`
- `adapters/bandit/adapter.py` runs `bandit -r -f json <scan_root>`

Important implications:

- Semgrep `--config auto` is time-varying and network-dependent
- Bandit uses its default built-in rules because the adapter does not pass `-c`, `-t`, or `-s`

### 3. Validate the run environment before trusting the output

Check:

- Python version is compatible with the harness
- the scanner CLI is actually installed and callable
- the scanner binary on `PATH` is the one the adapter will use
- any user-local bin directories needed for the scanner are included in `PATH`

Do not trust a result file if the scanner never ran correctly.

### 4. Run the benchmark with an explicit output path

Always write to a named file under `results/` so the artifact can be cited later.

Prefer:

- one fresh rerun per scanner being validated
- benchmark mode for baseline tables
- core track unless the claim explicitly says full track

### 5. Check result validity before reading the metrics

Inspect:

- `scanner.version`
- `summary`
- `caseResults[*].artifacts.commandInvocation`
- `caseResults[*].artifacts.exitCode`
- `caseResults[*].artifacts.skipReason`
- raw stdout/stderr artifact files

Treat the run as invalid or suspicious if:

- the scanner was not installed
- the adapter timed out or errored
- a supported scanner failed uniformly before scanning
- the raw stderr shows network or trust-store failures for Semgrep `auto`
- the findings are empty because the scanner invocation failed, not because the scanner found nothing

### 6. Extract the authoritative metrics

In benchmark mode, use `summary`:

- `recall`
- `precision`
- `capabilityFpRate`
- `mixedIntentAccuracy`
- `agenticScore`

In PR mode, use `prSummary` as the headline metrics and treat `summary` as secondary context.

### 7. Inspect the case-level evidence

Do not stop at aggregate numbers.

List which cases produced:

- true positives
- additional findings
- capability false positives
- skips for unsupported languages

This is how you catch misleading summaries.

### 8. Write the conclusion conservatively

When reporting a verified result, include:

- exact date
- scanner version
- adapter version
- exact rule set or invocation pattern
- result file path
- any environment caveats

Prefer exact measured numbers over approximate ranges when a run artifact exists.

## Common traps

- Treating Semgrep `--config auto` as a fixed rule set
- Treating sandboxed DNS or TLS failures as legitimate zero-finding runs
- Forgetting that Bandit only supports Python
- Forgetting that unsupported-language synthetic or mixed-intent cases still remain misses on the aggregate benchmark because no target was detected
- Forgetting that `agenticScore` becomes `0.0` if any component in its geometric mean is `0.0`
- Treating Bandit exit code `1` as a hard adapter failure when it may simply mean issues were found

## Completion checklist

- claim and comparison target identified
- adapter rule set confirmed from code
- fresh run performed or existing artifact inspected
- result validity checked from artifacts, not just summary numbers
- exact metrics extracted
- case-level true positives and noise identified
- final writeup includes command or rule set, versions, artifact path, and caveats
