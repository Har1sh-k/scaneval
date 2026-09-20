# SASTbench Adapters

Each adapter lives in `adapters/<scanner-name>/adapter.py` and normalizes scanner output into the SASTbench finding format.

Use [CREATING_AN_ADAPTER.md](./CREATING_AN_ADAPTER.md) for the full adapter contract.

If you want another agent to implement the adapter, use the repo-local skill at [../skills/scaneval-adapter-authoring/SKILL.md](../skills/scaneval-adapter-authoring/SKILL.md).

## Required interface

Every adapter must implement:

```python
def get_version() -> str:
    ...


def scan(scan_root: Path, language: str) -> list[dict]:
    ...
```

Each finding must include:

- `ruleId`
- `mappedKind`
- `path`
- `startLine`
- `endLine`

Optional fields:

- `severity`
- `message`

## Supported canonical kinds

Adapters must map findings to one of:

- `command_injection`
- `path_traversal`
- `ssrf`
- `auth_bypass`
- `authz_bypass`
- `sql_injection`
- `unmapped`

## Optional metadata interfaces

Raw-output preservation:

```python
def scan_with_metadata(scan_root: Path, language: str) -> dict:
    ...
```

PR-aware scanning:

```python
def scan_pr_with_metadata(
    base_root: Path,
    head_root: Path,
    changed_files: list[str],
    diff_text: str,
    language: str | None = None,
    case: dict | None = None,
) -> dict:
    ...
```

If `scan_pr_with_metadata` is absent, SASTbench falls back to base-tree plus head-tree synthesis in PR mode.

## Official adapters

| Adapter | Scanner | Languages |
|---------|---------|-----------|
| `semgrep/` | Semgrep | Python, TypeScript, Rust |
| `bandit/` | Bandit | Python only |

These are the baseline adapters intended for official comparison runs today.

## Experimental adapters

- `securevibes-agent/`
- `code-review-agent/`

These are useful for local comparison and development, but they are not baseline leaderboard adapters today.
