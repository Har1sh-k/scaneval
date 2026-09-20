"""ScanEval adapter for Bandit.

Runs Bandit on a case directory and returns normalized findings plus
scanner invocation metadata. Bandit only supports Python.
"""

import json
import subprocess
from pathlib import Path

ADAPTER_VERSION = "1.1.0"

# Bandit test ID to canonical kind mapping
TEST_KIND_MAP = {
    # Subprocess / command injection
    "B602": "command_injection",
    "B603": "command_injection",
    "B604": "command_injection",
    "B605": "command_injection",
    "B606": "command_injection",
    "B607": "command_injection",
    # os.system / exec
    "B102": "command_injection",
    # Network / SSRF
    "B310": "ssrf",
    "B309": "ssrf",
    # File / path
    "B108": "path_traversal",
}

# Broader pattern matching
TEST_NAME_MAP = {
    "subprocess": "command_injection",
    "exec": "command_injection",
    "system": "command_injection",
    "popen": "command_injection",
    "urlopen": "ssrf",
    "request": "ssrf",
}


def get_version() -> str:
    """Get the Bandit version string."""
    try:
        result = subprocess.run(
            ["bandit", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        first_line = result.stdout.strip().split("\n")[0]
        return first_line.replace("bandit ", "").strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "unknown"


def map_test_to_kind(test_id: str, test_name: str) -> str:
    """Map a Bandit test to a canonical benchmark kind."""
    if test_id in TEST_KIND_MAP:
        return TEST_KIND_MAP[test_id]

    name_lower = test_name.lower()
    for pattern, kind in TEST_NAME_MAP.items():
        if pattern in name_lower:
            return kind

    return "unmapped"


def severity_map(bandit_severity: str) -> str:
    """Map Bandit severity to benchmark severity."""
    return {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }.get(bandit_severity, "medium")


def _parse_findings(output: dict, scan_root: Path) -> list[dict]:
    """Normalize Bandit JSON output into benchmark findings."""
    findings = []
    scan_root_str = str(scan_root.resolve()).replace("\\", "/")

    for issue in output.get("results", []):
        abs_path = issue.get("filename", "")
        rel_path = abs_path.replace("\\", "/")
        if rel_path.startswith(scan_root_str):
            rel_path = rel_path[len(scan_root_str):].lstrip("/")

        test_id = issue.get("test_id", "")
        test_name = issue.get("test_name", "")
        mapped_kind = map_test_to_kind(test_id, test_name)

        findings.append({
            "ruleId": f"{test_id}:{test_name}",
            "mappedKind": mapped_kind,
            "path": rel_path,
            "startLine": issue.get("line_number", 1),
            "endLine": issue.get("line_range", [issue.get("line_number", 1)])[-1],
            "severity": severity_map(issue.get("issue_severity", "")),
            "message": issue.get("issue_text", ""),
        })

    return findings


def scan_with_metadata(scan_root: Path, language: str) -> dict:
    """Run Bandit and return findings plus raw output metadata."""
    if language != "python":
        return {
            "findings": [],
            "commandInvocation": None,
            "exitCode": None,
            "rawStdout": "",
            "rawStderr": "",
            "skipReason": "language_not_supported",
        }

    command = [
        "bandit",
        "-r",
        "-f", "json",
        str(scan_root),
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        message = "bandit not found - install with: pip install bandit"
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
        print("    bandit timed out")
        return {
            "findings": [],
            "commandInvocation": command,
            "exitCode": None,
            "rawStdout": "",
            "rawStderr": "bandit timed out",
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
