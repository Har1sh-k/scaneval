"""SASTbench adapter for securevibes-agent.

Runs securevibes-agent in bootstrap mode on a case directory and normalizes
output to the benchmark's canonical finding format.  For PR mode, creates a
temporary git repository from the vendored base/head trees and invokes
securevibes-agent's native ``pr`` command with diff-aware analysis.

securevibes-agent is an LLM-backed security scanner that produces file-level
findings (no line numbers). The adapter maps vulnerability classes to canonical
kinds and uses whole-file line ranges for scoring overlap.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ADAPTER_VERSION = "1.3.0"
LLM_MODEL = os.environ.get("SECUREVIBES_LLM_MODEL", "anthropic/claude-sonnet-4-5")

_sv_env = os.environ.get("SECUREVIBES_AGENT_DIR", "").strip()
if _sv_env:
    SECUREVIBES_AGENT_DIR = Path(_sv_env)
else:
    # Try to find it as a sibling of the sast-bench repo
    _repo_root = Path(__file__).resolve().parent.parent.parent
    SECUREVIBES_AGENT_DIR = _repo_root.parent / "securevibes-agent"

# fnm-managed Node.js isn't always on the Windows system PATH that Python
# inherits.  Resolve a stable node directory once at import time.
_FNM_NODE_DIR = os.environ.get("FNM_NODE_DIR", "")
if not _FNM_NODE_DIR:
    _candidate = Path.home() / "AppData" / "Roaming" / "fnm" / "node-versions"
    if _candidate.exists():
        versions = sorted(_candidate.iterdir(), reverse=True)
        if versions:
            _FNM_NODE_DIR = str(versions[0] / "installation")

# Map securevibes-agent vulnerability classes to canonical kinds.
# Classes that don't map to the V1 taxonomy get "unmapped".
VULN_CLASS_MAP = {
    "commandinjection": "command_injection",
    "codeexec": "command_injection",
    "sandboxescape": "path_traversal",
    "pathtraversal": "path_traversal",
    "ssrf": "ssrf",
    "requestforgery": "ssrf",
    "authbypass": "auth_bypass",
    "brokenauthz": "authz_bypass",
    "sqlinjection": "sql_injection",
    # Others don't map to the benchmark taxonomy
    "xss": "unmapped",
    "abuse": "unmapped",
    "inputvalidation": "unmapped",
    "secretdisclosure": "unmapped",
    "newattacksurface": "unmapped",
}

# Pattern-based fallback for vulnerability classes or titles
VULN_PATTERN_MAP = {
    "command": "command_injection",
    "exec": "command_injection",
    "injection": "command_injection",
    "shell": "command_injection",
    "subprocess": "command_injection",
    "sandbox": "path_traversal",
    "path": "path_traversal",
    "traversal": "path_traversal",
    "directory": "path_traversal",
    "workspace": "path_traversal",
    "ssrf": "ssrf",
    "request-forgery": "ssrf",
    "url": "ssrf",
    "fetch": "ssrf",
    "auth bypass": "auth_bypass",
    "authentication": "auth_bypass",
    "unauthenticated": "auth_bypass",
    "authorization": "authz_bypass",
    "privilege": "authz_bypass",
    "sql injection": "sql_injection",
    "sql": "sql_injection",
}


def get_version() -> str:
    """Get the securevibes-agent version string."""
    pkg_json = SECUREVIBES_AGENT_DIR / "package.json"
    try:
        with open(pkg_json) as f:
            pkg = json.load(f)
        return pkg.get("version", "unknown")
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


def map_vuln_class(vuln_class: str, title: str = "") -> str:
    """Map a securevibes-agent vulnerability class to a canonical kind."""
    normalized = vuln_class.lower().strip()
    if normalized in VULN_CLASS_MAP:
        kind = VULN_CLASS_MAP[normalized]
        if kind != "unmapped":
            return kind

    # Try pattern matching on the class + title
    combined = f"{normalized} {title.lower()}"
    for pattern, kind in VULN_PATTERN_MAP.items():
        if pattern in combined:
            return kind

    return "unmapped"


def severity_map(sv_severity: str) -> str:
    """Map securevibes-agent severity to benchmark severity."""
    return {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }.get(sv_severity.lower(), "medium")


def _count_lines(file_path: Path) -> int:
    """Count lines in a file for whole-file region."""
    try:
        return len(file_path.read_text(encoding="utf-8", errors="replace").splitlines())
    except Exception:
        return 1


def _extract_json(text: str) -> dict | None:
    """Extract JSON object from potentially mixed output."""
    # Try parsing the whole thing first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try each line (the --json flag prints one JSON object)
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def _build_env() -> dict[str, str]:
    """Build a subprocess environment with Node.js on PATH."""
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    if _FNM_NODE_DIR:
        sep = ";" if sys.platform == "win32" else ":"
        env["PATH"] = _FNM_NODE_DIR + sep + env.get("PATH", "")
    return env


def _read_finding_files(findings_dir: Path) -> list[dict]:
    """Read finding records from .securevibes/findings/ markdown files.

    This gives richer data than the JSON summary because the knowledge
    base files always have the latest file_path and vulnerability_class.
    """
    records = []
    if not findings_dir.exists():
        return records
    for md in sorted(findings_dir.glob("*.md")):
        text = md.read_text(encoding="utf-8", errors="replace")
        # Parse YAML-ish frontmatter between --- fences
        if not text.startswith("---"):
            continue
        end = text.index("---", 3)
        fm_text = text[3:end]
        record: dict = {}
        for line in fm_text.splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            val = val.strip().strip('"').strip("'")
            record[key.strip()] = val
        if record.get("id"):
            records.append(record)
    return records


def _normalize_findings(kb_records: list[dict], scan_root: Path) -> list[dict]:
    """Convert KB finding records into SASTbench-normalized finding dicts."""
    findings = []
    scan_root_str = str(scan_root).replace("\\", "/")

    for record in kb_records:
        file_path = record.get("file_path", "")
        if not file_path:
            continue

        # Normalize path relative to scan_root
        rel_path = file_path.replace("\\", "/")
        if rel_path.startswith(scan_root_str):
            rel_path = rel_path[len(scan_root_str):].lstrip("/")
        rel_path = rel_path.lstrip("./")

        vuln_class = record.get("vulnerability_class", "")
        title = record.get("title", "")
        mapped_kind = map_vuln_class(vuln_class, title)

        abs_file = scan_root / rel_path
        end_line = _count_lines(abs_file) if abs_file.exists() else 9999

        findings.append({
            "ruleId": f"sv-agent:{vuln_class}:{record.get('id', 'unknown')}",
            "mappedKind": mapped_kind,
            "path": rel_path,
            "startLine": 1,
            "endLine": end_line,
            "severity": severity_map(record.get("severity", "medium")),
            "message": title,
        })

    return findings


def _run_scan(scan_root: Path, language: str) -> tuple[list[dict], list[str], str, str, str | None]:
    """Run securevibes-agent and return (findings, command, stdout, stderr, skipReason)."""
    scan_root = scan_root.resolve()

    if not SECUREVIBES_AGENT_DIR or not SECUREVIBES_AGENT_DIR.exists():
        return [], [], "", "", "securevibes-agent not found (set SECUREVIBES_AGENT_DIR)"

    # Remove any stale .securevibes state so findings are fresh.
    sv_dir = scan_root / ".securevibes"
    if sv_dir.exists():
        shutil.rmtree(sv_dir, ignore_errors=True)

    llm_model = os.environ.get("SECUREVIBES_LLM_MODEL", "anthropic/claude-sonnet-4-5")
    env = _build_env()

    # On Windows subprocess needs the .cmd extension for npm/npx shims.
    npx_cmd = "npx.cmd" if sys.platform == "win32" else "npx"

    cmd = [
        npx_cmd, "tsx",
        str(SECUREVIBES_AGENT_DIR / "src" / "runtime" / "cli.ts"),
        "bootstrap",
        "--repo", str(scan_root),
        "--analysis-mode", "llm",
        "--llm-model", llm_model,
    ]

    print("\n", flush=True)
    try:
        subprocess.run(
            cmd,
            cwd=str(SECUREVIBES_AGENT_DIR),
            env=env,
        )
    except FileNotFoundError:
        print("    npx/tsx not found — install Node.js and tsx")
        return [], cmd, "", "", "npx_not_found"

    # Read findings from the knowledge-base files written by the scan.
    kb_records = _read_finding_files(sv_dir / "findings") if sv_dir.exists() else []

    # Clean up .securevibes after reading
    if sv_dir.exists():
        shutil.rmtree(sv_dir, ignore_errors=True)

    findings = _normalize_findings(kb_records, scan_root)
    return findings, cmd, "", "", None


def scan(scan_root: Path, language: str) -> list[dict]:
    """Run securevibes-agent on the scan root and return normalized findings."""
    findings, _, _, _, _ = _run_scan(scan_root, language)
    return findings


def scan_with_metadata(scan_root: Path, language: str) -> dict:
    """Return findings plus raw scanner output and command metadata."""
    findings, cmd, stdout, stderr, skip_reason = _run_scan(scan_root, language)
    return {
        "findings": findings,
        "commandInvocation": cmd,
        "exitCode": 0 if not skip_reason else None,
        "rawStdout": stdout,
        "rawStderr": stderr,
        "skipReason": skip_reason,
    }


# ---------------------------------------------------------------------------
# PR mode — native diff-aware scanning
# ---------------------------------------------------------------------------

def _create_pr_repo(base_root: Path, head_root: Path) -> tuple[Path, str, str]:
    """Create a temp git repo with base and head as separate commits.

    Returns (repo_path, base_sha, head_sha).  The caller is responsible for
    cleaning up the temporary directory.
    """
    tmp = Path(tempfile.mkdtemp(prefix="sv-pr-"))

    def _git(*args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=str(tmp),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    _git("init")
    _git("config", "user.email", "bench@sastbench.dev")
    _git("config", "user.name", "SASTbench")
    # Disable git-lfs filters so operations work without lfs installed
    _git("config", "filter.lfs.clean", "cat")
    _git("config", "filter.lfs.smudge", "cat")
    _git("config", "filter.lfs.process", "")
    _git("config", "filter.lfs.required", "false")

    # Commit 1: base tree (skip .git dirs that pr_runner may have created)
    for src in base_root.rglob("*"):
        if src.is_file() and ".git" not in src.relative_to(base_root).parts:
            rel = src.relative_to(base_root)
            dst = tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    _git("add", "-A")
    _git("commit", "-m", "base", "--allow-empty")
    base_sha = _git("rev-parse", "HEAD")

    # Commit 2: head tree — replace all files
    for item in tmp.iterdir():
        if item.name == ".git":
            continue
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()

    for src in head_root.rglob("*"):
        if src.is_file() and ".git" not in src.relative_to(head_root).parts:
            rel = src.relative_to(head_root)
            dst = tmp / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    _git("add", "-A")
    _git("commit", "-m", "head", "--allow-empty")
    head_sha = _git("rev-parse", "HEAD")

    return tmp, base_sha, head_sha


def scan_pr_with_metadata(
    base_root: Path,
    head_root: Path,
    changed_files: list[str],
    diff_text: str,
    language: str | None = None,
    case: dict | None = None,
) -> dict:
    """Run securevibes-agent in native PR mode on a temp git repo.

    Creates a temporary repository with two commits (base → head), then
    invokes ``securevibes-agent pr --base <base_sha> --head <head_sha>``
    so the scanner performs diff-aware analysis.
    """
    if not SECUREVIBES_AGENT_DIR or not SECUREVIBES_AGENT_DIR.exists():
        return {
            "reviewFindings": [],
            "baselineFindings": [],
            "headFindings": [],
            "commandInvocation": [],
            "exitCode": None,
            "rawStdout": "",
            "rawStderr": "",
            "skipReason": "securevibes-agent not found (set SECUREVIBES_AGENT_DIR)",
        }

    repo_path = None
    try:
        repo_path, base_sha, head_sha = _create_pr_repo(base_root, head_root)

        llm_model = os.environ.get("SECUREVIBES_LLM_MODEL", "anthropic/claude-sonnet-4-5")
        env = _build_env()
        npx_cmd = "npx.cmd" if sys.platform == "win32" else "npx"

        # First run bootstrap to establish the baseline threat model on the
        # base commit so that the PR scan has a knowledge-base to diff against.
        bootstrap_cmd = [
            npx_cmd, "tsx",
            str(SECUREVIBES_AGENT_DIR / "src" / "runtime" / "cli.ts"),
            "bootstrap",
            "--repo", str(repo_path),
            "--analysis-mode", "llm",
            "--llm-model", llm_model,
        ]

        # Checkout base, run bootstrap
        subprocess.run(
            ["git", "checkout", base_sha],
            cwd=str(repo_path), capture_output=True, check=True,
        )
        print("\n  [sv-agent PR] bootstrapping base...", flush=True)
        subprocess.run(bootstrap_cmd, cwd=str(SECUREVIBES_AGENT_DIR), env=env)

        # Read baseline findings
        sv_dir = repo_path / ".securevibes"
        base_kb = _read_finding_files(sv_dir / "findings") if sv_dir.exists() else []
        baseline_findings = _normalize_findings(base_kb, repo_path)

        # Checkout head for PR scan
        subprocess.run(
            ["git", "checkout", head_sha],
            cwd=str(repo_path), capture_output=True, check=True,
        )

        # Run PR mode
        pr_cmd = [
            npx_cmd, "tsx",
            str(SECUREVIBES_AGENT_DIR / "src" / "runtime" / "cli.ts"),
            "pr",
            "--repo", str(repo_path),
            "--base", base_sha,
            "--head", head_sha,
            "--analysis-mode", "llm",
            "--llm-model", llm_model,
        ]

        print("  [sv-agent PR] running PR scan...", flush=True)
        subprocess.run(pr_cmd, cwd=str(SECUREVIBES_AGENT_DIR), env=env)

        # Read findings after PR scan
        pr_kb = _read_finding_files(sv_dir / "findings") if sv_dir.exists() else []
        head_findings = _normalize_findings(pr_kb, repo_path)

        # Review findings = new in head that weren't in baseline
        base_ids = {r.get("id") for r in base_kb}
        review_records = [r for r in pr_kb if r.get("id") not in base_ids]
        review_findings = _normalize_findings(review_records, repo_path)

        return {
            "reviewFindings": review_findings,
            "baselineFindings": baseline_findings,
            "headFindings": head_findings,
            "commandInvocation": pr_cmd,
            "exitCode": 0,
            "rawStdout": "",
            "rawStderr": "",
            "skipReason": None,
        }

    except FileNotFoundError:
        return {
            "reviewFindings": [],
            "baselineFindings": [],
            "headFindings": [],
            "commandInvocation": [],
            "exitCode": None,
            "rawStdout": "",
            "rawStderr": "",
            "skipReason": "npx_not_found",
        }
    finally:
        if repo_path and repo_path.exists():
            shutil.rmtree(repo_path, ignore_errors=True)
