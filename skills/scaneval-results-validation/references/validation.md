# SASTbench Result Validation Reference

## Table of Contents

- Benchmark-mode checklist
- PR-mode checklist
- Official adapter rule-set notes
- Command recipes
- Invalid-run diagnostics
- Writeup template

## Benchmark-mode checklist

Use this when validating baseline or README-style numbers.

1. Read the adapter for the scanner you are validating.
2. Record the exact invocation pattern the adapter uses.
3. Confirm the scanner CLI is installed and callable.
4. Run `scripts/run.py` with an explicit `-o results/<name>.json`.
5. Inspect the result JSON `summary`.
6. Inspect `caseResults[*].artifacts` for exit codes, skips, and raw output files.
7. List the cases with true positives, additional findings, and capability false positives.
8. Only then compare the measured numbers to the claimed ones.

## PR-mode checklist

Use this when validating review or introduced-vulnerability claims.

1. Read `docs/PR_MODE.md`, `scripts/pr_runner.py`, and `scripts/pr_scoring.py`.
2. Run `scripts/run.py --mode pr ...` with an explicit output path.
3. Use `prSummary` as the authoritative metric block.
4. Inspect `prContext.baselineFindings`, `prContext.headFindings`, and `prContext.reviewFindings`.
5. Confirm whether the introduced target was actually detected as a review finding.

## Official adapter rule-set notes

### Semgrep

The official adapter currently invokes:

```bash
semgrep scan --json --config auto --lang <language> <scan_root>
```

Validation implications:

- `--config auto` is not a pinned static rule set
- it fetches the active Semgrep registry bundle
- it may require network access
- results may drift over time as the registry changes

If you publish a Semgrep number, say that it used `--config auto`.

### Bandit

The official adapter currently invokes:

```bash
bandit -r -f json <scan_root>
```

Validation implications:

- no custom config file is provided
- no include or exclude test list is provided
- the effective rule set is Bandit's default built-in rules
- unsupported TypeScript and Rust cases return `language_not_supported`

If you publish a Bandit number, say that it used default Bandit rules via `bandit -r -f json`.

## Command recipes

### Verify scanner installation

```bash
python3.12 --version
PATH="$HOME/Library/Python/3.9/bin:$PATH" semgrep --version
PATH="$HOME/Library/Python/3.9/bin:$PATH" bandit --version
```

If the scanner is installed in another location, adjust `PATH` before running the harness.

### Run benchmark mode

```bash
PATH="$HOME/Library/Python/3.9/bin:$PATH" python3.12 scripts/run.py --scanner semgrep --track core -o results/semgrep_core_verify.json
PATH="$HOME/Library/Python/3.9/bin:$PATH" python3.12 scripts/run.py --scanner bandit --track core -o results/bandit_core_verify.json
```

### Run PR mode

```bash
PATH="$HOME/Library/Python/3.9/bin:$PATH" python3.12 scripts/run.py --scanner semgrep --mode pr --track core -o results/semgrep_pr_verify.json
```

### Print summary metrics from a result file

```bash
python3.12 - <<'PY'
import json
from pathlib import Path
path = Path("results/semgrep_core_verify.json")
data = json.loads(path.read_text())
print("scanner:", data["scanner"])
print("track:", data["track"])
print("mode:", data["mode"])
print("summary:", data.get("summary"))
print("prSummary:", data.get("prSummary"))
PY
```

### List the cases that actually drove the score

```bash
python3.12 - <<'PY'
import json
from pathlib import Path
data = json.loads(Path("results/semgrep_core_verify.json").read_text())
for case in data["caseResults"]:
    findings = case["findings"]
    tp = [f for f in findings if f.get("classification") == "true_positive"]
    fp = [f for f in findings if f.get("classification") == "false_positive"]
    cfp = [f for f in findings if f.get("classification") == "capability_false_positive"]
    if tp or fp or cfp:
        print(case["caseId"], "TP", len(tp), "FP", len(fp), "CapFP", len(cfp))
PY
```

### Inspect raw artifacts for one suspicious case

```bash
python3.12 - <<'PY'
import json
from pathlib import Path
data = json.loads(Path("results/semgrep_core_verify.json").read_text())
case = next(c for c in data["caseResults"] if c["caseId"] == "SB-PY-SV-001")
print(case["artifacts"])
PY
sed -n '1,120p' results/semgrep_core_verify_artifacts/SB-PY-SV-001/scanner.stderr.txt
```

## Invalid-run diagnostics

Do not trust the metric block until you rule these out.

### Uniform scanner failure

Symptoms:

- every supported case has empty findings
- the same non-zero exit code repeats
- raw stderr shows the same fatal error on every case

This is not a legitimate benchmark result.

### Semgrep `auto` failed before scanning

Common symptoms:

- DNS failure reaching `semgrep.dev`
- TLS or trust-store failure
- exit code `2` across supported cases
- empty findings with repeated raw stderr

Treat this as an invalid run and document the failure mode.

### Scanner not installed

Look for:

- `skipReason: "scanner_not_installed"`
- missing version data
- adapter stderr telling you how to install the scanner

### Unsupported language is not the same as a clean pass

Bandit only supports Python. In aggregate benchmark scoring:

- unsupported capability-safe cases may stay clean
- unsupported synthetic-vulnerable and mixed-intent cases still leave required targets undetected
- that means they still depress recall and mixed-intent accuracy

Explain this explicitly when summarizing Bandit numbers.

### Non-zero exit code can still be usable

Bandit often exits non-zero when it finds issues.
Do not discard the run just because `exitCode != 0`.
Check whether findings were parsed and whether raw stderr indicates an actual execution failure.

## Writeup template

Use wording like:

```text
Validated on <date> with <scanner> <version> using the official adapter command pattern <rule set>.
Evidence: results/<file>.json.
Measured metrics: recall X, precision Y, capability FP rate Z, mixed-intent accuracy A, agentic score B.
Notable cases: <TPs/noise/skips>.
Caveats: <network dependence, unsupported languages, time-varying rules, sandbox limits>.
```

If the run is invalid, say so directly and name the exact failure mode from raw artifacts.
