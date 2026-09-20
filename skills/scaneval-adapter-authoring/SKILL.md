---
name: scaneval-adapter-authoring
description: Build or update a SASTbench scanner adapter under adapters/. Use when an agent needs to create, repair, or extend an adapter for a scanner, including rule mapping, path normalization, raw-output capture, optional PR-mode support, adapter tests, and harness validation against core benchmark cases.
---

# SASTbench Adapter Authoring

Build adapters that actually work with this repo's scoring and reporting model.

Use this skill for:

- creating a new adapter under `adapters/<scanner-name>/adapter.py`
- repairing a broken adapter
- extending an adapter with `scan_with_metadata()`
- adding real PR-aware support via `scan_pr_with_metadata()`
- tightening rule mapping, path normalization, or line handling

For non-Codex agents, use this `SKILL.md` as the task instructions and then open the referenced repo files.

## Read these files first

Before writing adapter code, inspect:

- `adapters/CREATING_AN_ADAPTER.md`
- `adapters/README.md`
- `tests/test_adapters.py`
- `tests/test_securevibes_agent_adapter.py`

Then inspect one reference adapter that matches the scanner type:

- `adapters/semgrep/adapter.py` for CLI JSON scanners
- `adapters/bandit/adapter.py` for simple language-filtered scanners
- `adapters/securevibes-agent/adapter.py` for LLM-backed scanners
- `adapters/code-review-agent/adapter.py` for agent-style finding normalization and filtering

If PR-mode support is relevant, also inspect:

- `docs/PR_MODE.md`
- `scripts/pr_runner.py`
- `tests/test_pr_runner.py`

For exact validation commands, read `references/validation.md`.

## Required outcome

A finished adapter must:

1. implement `get_version()`
2. implement `scan()`
3. return normalized findings with correct path, line, and `mappedKind`
4. handle unsupported languages and scanner failures without crashing the harness
5. include tests
6. pass at least one real SASTbench smoke run

If raw stdout/stderr matters, also implement `scan_with_metadata()`.

If the scanner has real diff-aware review capabilities, implement `scan_pr_with_metadata()`.
If it does not, do not fake PR support. Let the harness fallback handle it.

## Workflow

### 1. Classify the scanner

Decide which category the scanner fits:

- CLI scanner with JSON output
- CLI scanner with text output
- LLM-backed local scanner
- API-backed scanner
- PR-aware scanner with native diff/review support

This determines how much metadata, cleanup, and defensive parsing the adapter needs.

### 2. Build rule mapping first

Create a direct `RULE_KIND_MAP` and then a conservative fallback map.

Valid `mappedKind` values are only:

- `command_injection`
- `path_traversal`
- `ssrf`
- `auth_bypass`
- `authz_bypass`
- `sql_injection`
- `unmapped`

Do not invent a new kind.
Do not map loosely when the scanner signal is ambiguous.
Prefer `unmapped` over a wrong canonical kind.

### 3. Normalize paths and lines carefully

The harness scores by:

- path overlap
- line-range overlap
- kind match

So the adapter must:

- return paths relative to `scan_root`
- use forward slashes
- return 1-indexed inclusive lines

If the scanner only gives file-level findings, use a whole-file range and document that tradeoff in tests or comments.

### 4. Implement scanner invocation defensively

Handle:

- scanner not installed
- unsupported language
- invalid or partial output
- timeout
- non-zero exit code that still returns usable findings

Do not crash the harness for these cases.

Prefer:

- `[]` from `scan()`
- `skipReason` in metadata-returning paths

### 5. Decide on metadata support

Implement `scan_with_metadata()` when any of these are true:

- raw stdout/stderr matters for debugging
- the scanner is hard to inspect from normalized findings alone
- the adapter is likely to be used in baseline comparisons

Use stable metadata keys:

- `findings`
- `commandInvocation`
- `exitCode`
- `rawStdout`
- `rawStderr`
- `skipReason`

### 6. Decide on PR support honestly

Implement `scan_pr_with_metadata()` only if the scanner truly uses:

- base tree
- head tree
- changed files
- diff text

Good candidates:

- PR review agents
- diff-aware LLM scanners
- scanners with built-in patch or pull-request review mode

Bad candidates:

- whole-tree scanners with no diff semantics

If the scanner is not genuinely PR-aware, skip the method and rely on SASTbench fallback PR synthesis.

### 7. Add tests before claiming success

Create or update a dedicated test file such as:

- `tests/test_<scanner>_adapter.py`

Cover at least:

- rule-to-kind mapping
- path normalization
- unsupported-language behavior
- malformed output
- scanner-not-found behavior
- metadata shape if `scan_with_metadata()` exists
- PR metadata shape if `scan_pr_with_metadata()` exists

Reuse the existing test style in:

- `tests/test_adapters.py`
- `tests/test_securevibes_agent_adapter.py`

## Quality bar

Do not stop at "the file exists."

A SASTbench adapter is only good if it:

- hits the right file
- hits the right line range
- maps to the right kind
- returns stable paths
- preserves raw output when needed
- does not leave junk in the scanned tree

## Completion checklist

- adapter code added or updated under `adapters/<scanner-name>/adapter.py`
- tests added or updated
- targeted pytest commands pass
- at least one real harness command runs successfully
- no generated `results/`, `.claude/`, `.securevibes/`, or cache junk is accidentally committed
