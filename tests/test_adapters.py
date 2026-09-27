"""Tests for official ScanEval adapters."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_adapter(name: str):
    """Load an adapter module by directory name."""
    path = REPO_ROOT / "adapters" / name / "adapter.py"
    spec = importlib.util.spec_from_file_location(f"test_{name}_adapter", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_semgrep_rule_mapping():
    semgrep = load_adapter("semgrep")

    assert semgrep.map_rule_to_kind("python.lang.security.ssrf.python-ssrf") == "ssrf"
    assert semgrep.map_rule_to_kind("custom.exec.rule") == "command_injection"
    assert semgrep.map_rule_to_kind("custom.unknown.rule") == "unmapped"


def test_semgrep_scan_with_metadata(monkeypatch, tmp_path):
    semgrep = load_adapter("semgrep")
    scan_root = tmp_path
    app_path = scan_root / "app.py"
    app_path.write_text("print('hello')\n", encoding="utf-8")

    def fake_run(command, capture_output, text, timeout):
        assert capture_output is True
        assert text is True
        assert timeout == 120
        payload = {
            "results": [
                {
                    "check_id": "python.lang.security.ssrf.python-ssrf",
                    "path": str(app_path),
                    "start": {"line": 2},
                    "end": {"line": 4},
                    "extra": {"severity": "ERROR", "message": "SSRF candidate"},
                }
            ]
        }
        return SimpleNamespace(
            stdout=json.dumps(payload),
            stderr="scanner stderr",
            returncode=1,
        )

    monkeypatch.setattr(semgrep.subprocess, "run", fake_run)
    result = semgrep.scan_with_metadata(scan_root, "python")

    assert result["commandInvocation"][:3] == ["semgrep", "scan", "--json"]
    assert result["exitCode"] == 1
    assert result["rawStderr"] == "scanner stderr"
    assert result["skipReason"] is None
    assert result["findings"] == [
        {
            "ruleId": "python.lang.security.ssrf.python-ssrf",
            "mappedKind": "ssrf",
            "path": "app.py",
            "startLine": 2,
            "endLine": 4,
            "severity": "high",
            "message": "SSRF candidate",
        }
    ]


def test_bandit_skip_reason_for_unsupported_language(tmp_path):
    bandit = load_adapter("bandit")
    result = bandit.scan_with_metadata(tmp_path, "rust")

    assert result["findings"] == []
    assert result["commandInvocation"] is None
    assert result["exitCode"] is None
    assert result["skipReason"] == "language_not_supported"


def test_bandit_scan_with_metadata(monkeypatch, tmp_path):
    bandit = load_adapter("bandit")
    scan_root = tmp_path
    app_path = scan_root / "pkg" / "main.py"
    app_path.parent.mkdir(parents=True, exist_ok=True)
    app_path.write_text("import urllib.request\n", encoding="utf-8")

    def fake_run(command, capture_output, text, timeout):
        assert command[:3] == ["bandit", "-r", "-f"]
        payload = {
            "results": [
                {
                    "filename": str(app_path),
                    "test_id": "B310",
                    "test_name": "urllib_urlopen",
                    "line_number": 7,
                    "line_range": [7, 8],
                    "issue_severity": "MEDIUM",
                    "issue_text": "Audit url open for permitted schemes",
                }
            ]
        }
        return SimpleNamespace(
            stdout=json.dumps(payload),
            stderr="",
            returncode=1,
        )

    monkeypatch.setattr(bandit.subprocess, "run", fake_run)
    result = bandit.scan_with_metadata(scan_root, "python")

    assert result["commandInvocation"] == ["bandit", "-r", "-f", "json", str(scan_root)]
    assert result["exitCode"] == 1
    assert result["skipReason"] is None
    assert result["findings"] == [
        {
            "ruleId": "B310:urllib_urlopen",
            "mappedKind": "ssrf",
            "path": "pkg/main.py",
            "startLine": 7,
            "endLine": 8,
            "severity": "medium",
            "message": "Audit url open for permitted schemes",
        }
    ]
