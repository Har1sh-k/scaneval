"""ScanEval adapter for Semgrep.

Runs Semgrep on a case directory and returns normalized findings plus
scanner invocation metadata for auditability.
"""

import json
import subprocess
from pathlib import Path

ADAPTER_VERSION = "1.1.0"

# Rule ID to canonical kind mapping
RULE_KIND_MAP = {
    # Python
    "python.lang.security.audit.dangerous-subprocess-use": "command_injection",
    "python.lang.security.audit.subprocess-shell-true": "command_injection",
    "python.lang.security.injection.os-system": "command_injection",
    "python.lang.security.audit.exec-used": "command_injection",
    "python.lang.security.audit.dangerous-system-call": "command_injection",
    "python.lang.security.ssrf.python-ssrf": "ssrf",
    "python.lang.security.audit.dynamic-urllib-use-detected": "ssrf",
    "python.lang.security.audit.path-traversal": "path_traversal",
    "python.lang.security.audit.dangerous-file-write": "path_traversal",
    # TypeScript / JavaScript
    "javascript.lang.security.audit.dangerous-exec": "command_injection",
    "javascript.lang.security.child-process-exec": "command_injection",
    "typescript.lang.security.audit.dangerous-exec": "command_injection",
    "javascript.lang.security.audit.non-literal-fs-filename": "path_traversal",
    "javascript.lang.security.audit.path-traversal": "path_traversal",
    "javascript.lang.security.audit.non-literal-require": "path_traversal",
    "javascript.lang.security.ssrf": "ssrf",
    # Rust
    "rust.lang.security.command-injection": "command_injection",
    "rust.lang.security.dangerous-command": "command_injection",
    "rust.lang.security.path-traversal": "path_traversal",
}

# Broader pattern matching for rules not in the exact map
RULE_PATTERN_MAP = {
    "subprocess": "command_injection",
    "exec": "command_injection",
    "command": "command_injection",
    "shell": "command_injection",
    "ssrf": "ssrf",
    "request-forgery": "ssrf",
    "path-traversal": "path_traversal",
    "directory-traversal": "path_traversal",
    "file-write": "path_traversal",
}


def get_version() -> str:
    """Get the Semgrep version string."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"


def map_rule_to_kind(rule_id: str) -> str:
    """Map a Semgrep rule ID to a canonical benchmark kind."""
    if rule_id in RULE_KIND_MAP:
        return RULE_KIND_MAP[rule_id]

    rule_lower = rule_id.lower()
    for pattern, kind in RULE_PATTERN_MAP.items():
        if pattern in rule_lower:
            return kind

    return "unmapped"


def severity_map(semgrep_severity: str) -> str:
    """Map Semgrep severity to benchmark severity."""
    return {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
    }.get(semgrep_severity, "medium")


def _parse_findings(output: dict, scan_root: Path) -> list[dict]:
    """Normalize Semgrep JSON output into benchmark findings."""
    findings = []
    scan_root_str = str(scan_root.resolve()).replace("\\", "/")

    for match in output.get("results", []):
        abs_path = match.get("path", "")
        rel_path = abs_path.replace("\\", "/")
        if rel_path.startswith(scan_root_str):
            rel_path = rel_path[len(scan_root_str):].lstrip("/")

        rule_id = match.get("check_id", "")
        mapped_kind = map_rule_to_kind(rule_id)

        findings.append({
            "ruleId": rule_id,
            "mappedKind": mapped_kind,
            "path": rel_path,
            "startLine": match.get("start", {}).get("line", 1),
            "endLine": match.get("end", {}).get("line", 1),
            "severity": severity_map(match.get("extra", {}).get("severity", "")),
            "message": match.get("extra", {}).get("message", ""),
        })

    return findings


def scan_with_metadata(scan_root: Path, language: str) -> dict:
    """Run Semgrep and return findings plus raw output metadata."""
    lang_flag = {
        "python": "python",
        "typescript": "typescript",
        "rust": "rust",
    }.get(language, language)
    command = [
        "semgrep", "scan",
        "--json",
        "--config", "auto",
        "--lang", lang_flag,
        str(scan_root),
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        message = "semgrep not found - install with: pip install semgrep"
        print(f"    {message}")
        return {
            "findings": [],
            "commandInvocation": command,
            "exitCode": None,
            "rawStdout": "",
            "rawStderr": message,
            "skipReason": "scanner_not_installed",
        }
    except subprocess.TimeoutExpired:
        print("    semgrep timed out")
        return {
            "findings": [],
            "commandInvocation": command,
            "exitCode": None,
            "rawStdout": "",
            "rawStderr": "semgrep timed out",
            "skipReason": "timeout",
        }

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        output = {}

    return {
        "findings": _parse_findings(output, scan_root),
        "commandInvocation": command,
        "exitCode": result.returncode,
        "rawStdout": result.stdout,
        "rawStderr": result.stderr,
        "skipReason": None,
    }


def scan(scan_root: Path, language: str) -> list[dict]:
    """Backward-compatible findings-only wrapper."""
    return scan_with_metadata(scan_root, language)["findings"]
