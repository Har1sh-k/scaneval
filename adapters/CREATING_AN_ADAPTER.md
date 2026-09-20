# Creating a SASTbench Adapter

This guide covers everything needed to build an adapter that connects a security scanner to the SASTbench benchmark harness. Use it as a reference or as a prompt to generate a new adapter.

If you want another agent to implement the adapter for you, use the repo-local skill at [../skills/scaneval-adapter-authoring/SKILL.md](../skills/scaneval-adapter-authoring/SKILL.md).

---

## What an adapter does

An adapter is a Python module that:

1. Invokes a scanner on a directory of source code
2. Parses the scanner's native output
3. Maps scanner-specific rule IDs to SASTbench canonical vulnerability kinds
4. Normalizes findings into a standard dict format with file path and line range
5. Returns the normalized findings to the benchmark runner

The runner (`scripts/run.py`) handles case discovery, scoring, and reporting. The adapter only handles scanner invocation and output normalization.

---

## File structure

```
adapters/
  <scanner-name>/
    adapter.py        # required — implements get_version() and scan()
```

The directory name is the value passed to `--scanner` on the command line:

```bash
python scripts/run.py --scanner <scanner-name> --track core
```

---

## Required interface

Every adapter must implement these two functions:

```python
from pathlib import Path

def get_version() -> str:
    """Return the scanner's version string.

    Called once at the start of a benchmark run. Used in results metadata.
    Return "unknown" if the scanner is not installed or version cannot be
    determined.
    """
    ...

def scan(scan_root: Path, language: str) -> list[dict]:
    """Run the scanner on scan_root and return normalized findings.

    Parameters:
        scan_root: Absolute path to the directory to scan. This is the
                   case's files.root resolved to an absolute path.
        language:  One of "python", "typescript", "rust", or "swift".

    Returns a list of finding dicts. Each dict MUST have:

        ruleId:     str  — original scanner rule ID or identifier
        mappedKind: str  — one of: "command_injection", "path_traversal",
                           "ssrf", "auth_bypass", "authz_bypass",
                           "sql_injection", "unmapped"
        path:       str  — file path RELATIVE to scan_root (forward slashes)
        startLine:  int  — first line of the finding (1-indexed)
        endLine:    int  — last line of the finding (1-indexed)

    Each dict MAY have:

        severity:   str  — one of: "low", "medium", "high", "critical"
        message:    str  — scanner-reported description

    Return an empty list if the scanner is not installed, times out,
    produces no findings, or the language is not supported.
    """
    ...
```

Current repo note: valid `mappedKind` values also include `auth_bypass`, `authz_bypass`, and `sql_injection`. Adapters must use the full six-kind set, plus `unmapped`.

### Optional: scan_with_metadata

For official adapters that want raw output preserved for auditing:

```python
def scan_with_metadata(scan_root: Path, language: str) -> dict:
    """Return findings plus raw scanner output and command metadata.

    Returns a dict with:
        findings:           list[dict]   — same format as scan() return
        commandInvocation:  list[str]    — the exact command that was run
        exitCode:           int | None   — scanner process exit code
        rawStdout:          str          — full stdout capture
        rawStderr:          str          — full stderr capture
        skipReason:         str | None   — why the scan was skipped, if applicable
    """
    ...
```

If `scan_with_metadata` exists, the runner calls it instead of `scan()`. The raw output is saved to disk and linked from the results JSON.

### Optional: ADAPTER_VERSION

```python
ADAPTER_VERSION = "1.0.0"
```

Stored in the results JSON for reproducibility. Defaults to "1.0.0" if not set.

---

## Canonical kinds

SASTbench currently uses six canonical vulnerability kinds for scoring. Every finding must be mapped to one of these or to `"unmapped"`:

| Canonical kind       | What it covers                           | Capability family |
|----------------------|------------------------------------------|-------------------|
| `command_injection`  | Shell injection, arbitrary code execution | `code_execution`  |
| `path_traversal`     | Directory traversal, sandbox escape       | `filesystem`      |
| `ssrf`               | Server-side request forgery, URL abuse    | `network`         |
| `auth_bypass`        | Missing or broken caller authentication   | `authentication`  |
| `authz_bypass`       | Missing or broken scope and role checks   | `authorization`   |
| `sql_injection`      | Unsafe query construction and execution   | `data_store`      |

Findings that don't map to any of these six should use `"unmapped"`. Unmapped findings are counted as false positives in scoring but don't affect the agentic-specific metrics.

---

## How to build the rule mapping

### Step 1: Identify scanner rule IDs

Run the scanner manually on one of the benchmark cases and inspect the output:

```bash
# Example for a JSON-output scanner
my-scanner scan --json cases/core/synthetic_vulnerable/PY-SV-001/project/
```

Note the rule IDs, categories, or labels the scanner uses for security findings.

### Step 2: Create a direct rule map

Map specific rule IDs to canonical kinds:

```python
RULE_KIND_MAP = {
    "scanner-rule-for-subprocess": "command_injection",
    "scanner-rule-for-shell-exec": "command_injection",
    "scanner-rule-for-ssrf": "ssrf",
    "scanner-rule-for-open-redirect": "ssrf",
    "scanner-rule-for-path-traversal": "path_traversal",
    "scanner-rule-for-file-write": "path_traversal",
    "scanner-rule-for-missing-auth": "auth_bypass",
    "scanner-rule-for-missing-role-check": "authz_bypass",
    "scanner-rule-for-sql-concat": "sql_injection",
}
```

### Step 3: Add pattern-based fallback

For rules not in the direct map, match on substrings in the rule ID or message:

```python
RULE_PATTERN_MAP = {
    "subprocess": "command_injection",
    "exec": "command_injection",
    "command": "command_injection",
    "shell": "command_injection",
    "ssrf": "ssrf",
    "request-forgery": "ssrf",
    "path-traversal": "path_traversal",
    "directory-traversal": "path_traversal",
    "missing-auth": "auth_bypass",
    "missing-authentication": "auth_bypass",
    "missing-authorization": "authz_bypass",
    "missing-role-check": "authz_bypass",
    "sql": "sql_injection",
    "query-concat": "sql_injection",
}
```

### Step 4: Write the mapping function

```python
def map_rule_to_kind(rule_id: str) -> str:
    if rule_id in RULE_KIND_MAP:
        return RULE_KIND_MAP[rule_id]

    rule_lower = rule_id.lower()
    for pattern, kind in RULE_PATTERN_MAP.items():
        if pattern in rule_lower:
            return kind

    return "unmapped"
```

---

## Path normalization

Paths in findings MUST be relative to `scan_root` with forward slashes. The scoring engine compares finding paths against region paths from `case.json`, so they must match.

```python
def normalize_path(abs_path: str, scan_root: Path) -> str:
    scan_root_str = str(scan_root.resolve()).replace("\\", "/")
    rel_path = abs_path.replace("\\", "/")
    if rel_path.startswith(scan_root_str):
        rel_path = rel_path[len(scan_root_str):].lstrip("/")
    return rel_path
```

---

## Scanner categories

### Category A: CLI scanners with JSON output (e.g., Semgrep, Bandit)

These are the simplest. The pattern is:

1. Run the scanner via `subprocess.run` with JSON output flag
2. Parse the JSON
3. Map rules to canonical kinds
4. Normalize paths and extract line numbers

```python
def scan(scan_root: Path, language: str) -> list[dict]:
    result = subprocess.run(
        ["my-scanner", "--json", str(scan_root)],
        capture_output=True, text=True, timeout=120,
    )
    output = json.loads(result.stdout)

    findings = []
    for item in output.get("results", []):
        findings.append({
            "ruleId": item["rule_id"],
            "mappedKind": map_rule_to_kind(item["rule_id"]),
            "path": normalize_path(item["file"], scan_root),
            "startLine": item["line"],
            "endLine": item.get("end_line", item["line"]),
            "severity": item.get("severity", "medium").lower(),
            "message": item.get("message", ""),
        })
    return findings
```

Key points:
- Use `capture_output=True` to capture JSON
- Handle `FileNotFoundError` (scanner not installed) and `TimeoutExpired`
- Handle `json.JSONDecodeError` (malformed output)

### Category B: LLM-backed scanners (e.g., securevibes-agent)

These scanners use AI models and may:
- Take longer (minutes per case)
- Produce file-level findings without line numbers
- Write results to disk instead of stdout
- Modify the scanned repository (clean up after)

Pattern:

```python
def scan(scan_root: Path, language: str) -> list[dict]:
    scan_root = scan_root.resolve()

    # Clean stale state before scan
    state_dir = scan_root / ".scanner-state"
    if state_dir.exists():
        shutil.rmtree(state_dir, ignore_errors=True)

    # Run scanner — let output stream to terminal
    subprocess.run(
        ["scanner-cli", "scan", "--repo", str(scan_root)],
        cwd=str(SCANNER_DIR),
    )

    # Read findings from disk
    findings = _read_findings_from_disk(state_dir / "findings")

    # Clean up scanner state
    if state_dir.exists():
        shutil.rmtree(state_dir, ignore_errors=True)

    # Restore any source files the scanner modified
    # (some LLM scanners patch code — this is a known issue)

    return _normalize_findings(findings, scan_root)
```

Key points:
- Don't capture stdout — let it stream so the user sees progress
- Read findings from whatever files the scanner writes
- Clean up scanner artifacts after reading
- If the scanner has no line numbers, use whole-file range:
  ```python
  "startLine": 1,
  "endLine": count_lines(scan_root / rel_path),
  ```
- Check `git status` after scanning — some scanners modify source code

### Category C: API-based scanners

For scanners accessed via HTTP API:

```python
def scan(scan_root: Path, language: str) -> list[dict]:
    # Upload or reference the scan target
    # Call the API
    # Poll for results
    # Parse and normalize
    ...
```

Same finding format applies. Handle API timeouts and auth errors gracefully.

---

## Severity mapping

Map the scanner's severity values to SASTbench's four levels:

```python
def severity_map(scanner_severity: str) -> str:
    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "WARNING": "medium",
        "ERROR": "high",
        "INFO": "low",
    }.get(scanner_severity.upper(), "medium")
```

Severity is stored for display only — it does not affect scoring.

---

## How scoring works (what the adapter needs to get right)

The runner classifies each finding the adapter returns:

1. **True positive**: finding path + line range overlaps a `vulnerable` region AND `mappedKind` is in the region's `acceptedKinds`
2. **Capability false positive**: finding overlaps a `capability_safe` region AND `mappedKind` matches the region's capability family
3. **False positive**: finding overlaps no annotated region, or kind doesn't match

So the adapter must get three things right for scoring to work:
- **path** — must exactly match the region path in `case.json` (relative to scan_root, forward slashes)
- **startLine / endLine** — must overlap the region's line range
- **mappedKind** — must match the region's `acceptedKinds`

If any of these are wrong, a correct detection will score as a false positive or miss.

---

## Testing

### Unit tests (no scanner needed)

Write tests that mock `subprocess.run` and verify:
- Rule-to-kind mapping covers the scanner's common rules
- Path normalization handles backslashes and absolute paths
- Empty/error output returns `[]`
- Scanner-not-found returns `[]`

See `tests/test_securevibes_agent_adapter.py` for an example.

### Integration test

```bash
python scripts/run.py --scanner <name> --track core --case-id SB-PY-SV-001
```

A working adapter on PY-SV-001 should produce at least one finding with:
- `path`: `tools/reference_fetcher.py`
- `mappedKind`: `ssrf`
- `startLine`/`endLine` overlapping the annotated vulnerable region

If the runner shows a target hit on the case, the adapter is working correctly.

### PR mode smoke test

If the adapter implements `scan_pr_with_metadata`, or if you want to verify fallback PR behavior:

```bash
python scripts/run.py --scanner <name> --mode pr --track core --case-id SB-PY-SV-001
```

### Full benchmark

```bash
python scripts/run.py --scanner <name> --track core
```

---

## Common pitfalls

| Pitfall | Fix |
|---------|-----|
| Paths use backslashes on Windows | Replace `\\` with `/` in all paths |
| Path is absolute instead of relative to scan_root | Strip the scan_root prefix |
| Scanner not on PATH in subprocess | Use full path or add to env PATH |
| On Windows, `npx`/`npm` need `.cmd` suffix | Check `sys.platform == "win32"` |
| Line numbers are 0-indexed | Add 1 — SASTbench uses 1-indexed lines |
| Scanner modifies scanned code | Clean up with `git checkout` or `shutil.rmtree` |
| Scanner writes state files in scan_root | Clean up `.scanner-state/` dirs after reading findings |
| Scanner only supports one language | Return `[]` for unsupported languages |
| JSON output mixed with log lines on stdout | Try parsing each line, or capture stderr separately |

---

## Checklist

Before submitting an adapter:

- [ ] `get_version()` returns a version string or `"unknown"`
- [ ] `scan()` returns `list[dict]` with all required fields
- [ ] `mappedKind` is one of: `command_injection`, `path_traversal`, `ssrf`, `auth_bypass`, `authz_bypass`, `sql_injection`, `unmapped`
- [ ] `path` is relative to scan_root with forward slashes
- [ ] `startLine` and `endLine` are 1-indexed integers
- [ ] Scanner-not-found returns `[]` (no crash)
- [ ] Scanner timeout returns `[]` (no hang)
- [ ] Invalid output returns `[]` (no crash)
- [ ] No scanner artifacts left in scan_root after scan
- [ ] No source files modified in scan_root after scan
- [ ] Unit tests pass without the scanner installed
- [ ] `python scripts/run.py --scanner <name> --track core --case-id SB-PY-SV-001` shows a target hit
- [ ] PR mode works via fallback or native support if the scanner claims PR awareness

---

## PR mode support (optional)

SASTbench supports a PR simulation mode that compares base (clean) and head (vulnerable) trees. Adapters can optionally implement native PR review support.

### Optional: scan_pr_with_metadata

If your scanner supports diff-aware or PR-style review (e.g., it can compare two trees and focus on changed files), implement this method:

```python
def scan_pr_with_metadata(
    base_root: Path,
    head_root: Path,
    changed_files: list[str],
    diff_text: str,
    language: str | None = None,
    case: dict | None = None,
) -> dict:
    """Run a PR-aware scan comparing base and head trees.

    Parameters:
        base_root:      Absolute path to the clean baseline tree
        head_root:      Absolute path to the vulnerable head tree
        changed_files:  List of file paths that changed (relative, forward slashes)
        diff_text:      Unified diff text between base and head
        language:       Primary language of the case (optional)
        case:           Full case definition dict (optional, for advanced adapters)

    Returns a dict with:
        reviewFindings:     list[dict]   — findings from the PR review (new/relevant findings)
        baselineFindings:   list[dict]   — findings from scanning the base tree
        headFindings:       list[dict]   — findings from scanning the head tree
        commandInvocation:  list[str]    — the exact command(s) run
        exitCode:           int | None   — scanner exit code
        rawStdout:          str          — full stdout capture
        rawStderr:          str          — full stderr capture
        skipReason:         str | None   — why the scan was skipped, if applicable
    """
    ...
```

If `scan_pr_with_metadata` is not implemented, the runner uses a **fallback** approach:
1. Runs `scan()` or `scan_with_metadata()` on the base tree
2. Runs `scan()` or `scan_with_metadata()` on the head tree
3. Computes "new-in-head" review findings by diffing the two result sets

The fallback is conservative: it matches findings by normalized path, mapped kind, rule ID, and overlapping/nearby line ranges (within 10 lines). This works well for most scanners.

### When to implement native PR support

Implement `scan_pr_with_metadata` when your scanner:
- Has built-in diff/PR review capabilities
- Can focus analysis on changed files for better signal
- Produces different output when given diff context vs scanning a full tree
- Benefits from seeing both base and head simultaneously

For traditional SAST tools (Semgrep, Bandit), the fallback approach is usually sufficient. Do not add a fake `scan_pr_with_metadata` implementation just to satisfy the interface.

---

## Reference adapters

| Adapter | Type | Study it for |
|---------|------|-------------|
| `semgrep/adapter.py` | CLI + JSON | Standard pattern, rule mapping, `scan_with_metadata` |
| `bandit/adapter.py` | CLI + JSON | Language filtering, line range extraction |
| `securevibes-agent/adapter.py` | LLM-backed | Streaming output, KB file reading, path env setup, cleanup |
