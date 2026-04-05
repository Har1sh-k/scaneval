"""Tests for the securevibes-agent adapter (no live scanner needed)."""

import json
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "adapters" / "securevibes-agent"))

import adapter


# ---------------------------------------------------------------------------
# map_vuln_class
# ---------------------------------------------------------------------------

def test_map_commandinjection():
    assert adapter.map_vuln_class("commandinjection") == "command_injection"


def test_map_codeexec():
    assert adapter.map_vuln_class("codeexec") == "command_injection"


def test_map_sandboxescape():
    assert adapter.map_vuln_class("sandboxescape") == "path_traversal"


def test_map_auth_classes():
    assert adapter.map_vuln_class("authbypass") == "auth_bypass"
    assert adapter.map_vuln_class("brokenauthz") == "authz_bypass"
    assert adapter.map_vuln_class("sqlinjection") == "sql_injection"


def test_map_unmapped_class():
    assert adapter.map_vuln_class("xss") == "unmapped"
    assert adapter.map_vuln_class("abuse") == "unmapped"


def test_map_pattern_fallback_title_ssrf():
    """Unknown class but title contains 'ssrf' -> ssrf."""
    assert adapter.map_vuln_class("unknown", "SSRF via image fetcher") == "ssrf"


def test_map_pattern_fallback_title_traversal():
    assert adapter.map_vuln_class("unknown", "Path traversal in writer") == "path_traversal"


def test_map_pattern_fallback_title_command():
    assert adapter.map_vuln_class("unknown", "Shell command injection") == "command_injection"


def test_map_totally_unknown():
    assert adapter.map_vuln_class("foobar", "nothing relevant") == "unmapped"


# ---------------------------------------------------------------------------
# severity_map
# ---------------------------------------------------------------------------

def test_severity_map():
    assert adapter.severity_map("critical") == "critical"
    assert adapter.severity_map("HIGH") == "high"
    assert adapter.severity_map("Medium") == "medium"
    assert adapter.severity_map("low") == "low"
    assert adapter.severity_map("weird") == "medium"


# ---------------------------------------------------------------------------
# _extract_json
# ---------------------------------------------------------------------------

def test_extract_json_clean():
    data = {"newFindings": [], "updatedFindings": []}
    assert adapter._extract_json(json.dumps(data)) == data


def test_extract_json_with_noise():
    payload = json.dumps({"newFindings": [{"id": "F1"}]})
    text = f"some log line\nanother line\n{payload}\n"
    result = adapter._extract_json(text)
    assert result is not None
    assert result["newFindings"][0]["id"] == "F1"


def test_extract_json_garbage():
    assert adapter._extract_json("not json at all") is None


def test_extract_json_empty():
    assert adapter._extract_json("") is None


# ---------------------------------------------------------------------------
# _read_finding_files
# ---------------------------------------------------------------------------

def test_read_finding_files(tmp_path):
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()

    md = findings_dir / "find-001.md"
    md.write_text(textwrap.dedent("""\
        ---
        id: FIND-001
        title: SSRF in fetcher
        vulnerability_class: secretdisclosure
        severity: high
        file_path: tools/fetcher.py
        confidence: 0.9
        ---
        # FIND-001
        Some reasoning.
    """), encoding="utf-8")

    records = adapter._read_finding_files(findings_dir)
    assert len(records) == 1
    assert records[0]["id"] == "FIND-001"
    assert records[0]["file_path"] == "tools/fetcher.py"
    assert records[0]["vulnerability_class"] == "secretdisclosure"


def test_read_finding_files_empty_dir(tmp_path):
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir()
    assert adapter._read_finding_files(findings_dir) == []


def test_read_finding_files_missing_dir(tmp_path):
    assert adapter._read_finding_files(tmp_path / "nope") == []


# ---------------------------------------------------------------------------
# scan — mocked subprocess, reads from .securevibes/findings/ KB files
# ---------------------------------------------------------------------------

def _make_scan_root(tmp_path):
    """Create a minimal scan root with one Python file."""
    root = tmp_path / "project"
    root.mkdir()
    tools = root / "tools"
    tools.mkdir()
    fetcher = tools / "fetcher.py"
    fetcher.write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")
    return root


def _write_kb_finding(scan_root, finding_id, title, vuln_class, severity, file_path):
    """Write a finding markdown file into .securevibes/findings/."""
    sv_dir = scan_root / ".securevibes" / "findings"
    sv_dir.mkdir(parents=True, exist_ok=True)
    slug = finding_id.lower().replace(" ", "-")
    (sv_dir / f"{slug}.md").write_text(textwrap.dedent(f"""\
        ---
        id: {finding_id}
        title: {title}
        vulnerability_class: {vuln_class}
        severity: {severity}
        file_path: {file_path}
        ---
        # {title}
    """), encoding="utf-8")


def _fake_run_that_writes_kb(scan_root, findings):
    """Return a side_effect that writes KB files then returns successfully."""
    def fake_run(*args, **kwargs):
        for f in findings:
            _write_kb_finding(scan_root, **f)
        return MagicMock(returncode=0)
    return fake_run


def test_scan_produces_findings(tmp_path):
    scan_root = _make_scan_root(tmp_path)

    side_effect = _fake_run_that_writes_kb(scan_root, [{
        "finding_id": "FIND-001",
        "title": "SSRF via fetcher",
        "vuln_class": "secretdisclosure",
        "severity": "high",
        "file_path": "tools/fetcher.py",
    }])

    with patch("adapter.subprocess.run", side_effect=side_effect):
        with patch("adapter.shutil.rmtree"):  # keep KB files for reading
            findings = adapter.scan(scan_root, "python")

    assert len(findings) == 1
    f = findings[0]
    assert f["path"] == "tools/fetcher.py"
    assert f["startLine"] == 1
    assert f["endLine"] == 5
    assert f["severity"] == "high"
    assert f["message"] == "SSRF via fetcher"
    # secretdisclosure is unmapped, but title "SSRF via fetcher" matches "ssrf" pattern
    assert f["mappedKind"] == "ssrf"


def test_scan_maps_commandinjection(tmp_path):
    scan_root = _make_scan_root(tmp_path)
    runner = scan_root / "tools" / "runner.py"
    runner.write_text("x\n" * 10, encoding="utf-8")

    side_effect = _fake_run_that_writes_kb(scan_root, [{
        "finding_id": "FIND-002",
        "title": "Arbitrary command execution",
        "vuln_class": "commandinjection",
        "severity": "critical",
        "file_path": "tools/runner.py",
    }])

    with patch("adapter.subprocess.run", side_effect=side_effect):
        with patch("adapter.shutil.rmtree"):
            findings = adapter.scan(scan_root, "python")

    assert len(findings) == 1
    assert findings[0]["mappedKind"] == "command_injection"
    assert findings[0]["endLine"] == 10


def test_scan_skips_empty_filepath(tmp_path):
    scan_root = _make_scan_root(tmp_path)

    side_effect = _fake_run_that_writes_kb(scan_root, [{
        "finding_id": "FIND-X",
        "title": "No path",
        "vuln_class": "xss",
        "severity": "medium",
        "file_path": "",
    }])

    with patch("adapter.subprocess.run", side_effect=side_effect):
        with patch("adapter.shutil.rmtree"):
            findings = adapter.scan(scan_root, "python")

    assert len(findings) == 0


def test_scan_reads_kb_findings(tmp_path):
    """Scan reads findings from .securevibes/findings/ KB files."""
    scan_root = _make_scan_root(tmp_path)

    side_effect = _fake_run_that_writes_kb(scan_root, [{
        "finding_id": "FIND-001",
        "title": "SSRF in fetcher",
        "vuln_class": "secretdisclosure",
        "severity": "critical",
        "file_path": "tools/fetcher.py",
    }])

    with patch("adapter.subprocess.run", side_effect=side_effect):
        with patch("adapter.shutil.rmtree"):
            findings = adapter.scan(scan_root, "python")

    assert len(findings) == 1
    assert findings[0]["path"] == "tools/fetcher.py"


def test_scan_returns_empty_on_not_found(tmp_path):
    scan_root = _make_scan_root(tmp_path)

    with patch("adapter.subprocess.run", side_effect=FileNotFoundError):
        findings = adapter.scan(scan_root, "python")

    assert findings == []



def test_scan_returns_empty_when_no_findings(tmp_path):
    scan_root = _make_scan_root(tmp_path)

    # Scanner runs but writes no findings
    with patch("adapter.subprocess.run", return_value=MagicMock(returncode=0)):
        findings = adapter.scan(scan_root, "python")

    assert findings == []


def test_create_pr_repo_disables_lfs(tmp_path):
    """_create_pr_repo must disable git-lfs filters so it works without lfs installed."""
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "a.txt").write_text("base\n")
    (head / "a.txt").write_text("head\n")

    repo_path, base_sha, head_sha = adapter._create_pr_repo(base, head)
    try:
        import subprocess as sp
        for key in ("filter.lfs.clean", "filter.lfs.smudge", "filter.lfs.process"):
            val = sp.run(
                ["git", "-C", str(repo_path), "config", "--local", key],
                capture_output=True, text=True,
            ).stdout.strip()
            # Must be overridden to a passthrough (empty or cat)
            assert val in ("", "cat"), f"{key} was not disabled: {val!r}"
        req = sp.run(
            ["git", "-C", str(repo_path), "config", "--local", "filter.lfs.required"],
            capture_output=True, text=True,
        ).stdout.strip()
        assert req == "false", f"filter.lfs.required not disabled: {req!r}"
        assert base_sha != head_sha
    finally:
        import shutil
        shutil.rmtree(repo_path, ignore_errors=True)


def test_create_pr_repo_skips_dotgit_in_sources(tmp_path):
    """_create_pr_repo must ignore .git dirs that pr_runner injects into source trees."""
    import subprocess as sp
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    (base / "a.txt").write_text("base\n")
    (head / "a.txt").write_text("head\n")

    # Simulate pr_runner's _git_init: create a .git in the source trees
    for d in (base, head):
        sp.run(["git", "init"], cwd=str(d), capture_output=True, check=True)
        sp.run(["git", "config", "user.email", "t@t"], cwd=str(d), capture_output=True)
        sp.run(["git", "config", "user.name", "T"], cwd=str(d), capture_output=True)
        sp.run(["git", "add", "-A"], cwd=str(d), capture_output=True, check=True)
        sp.run(["git", "commit", "-m", "init", "--allow-empty"], cwd=str(d), capture_output=True)

    # This must not raise PermissionError from copying .git/objects
    repo_path, base_sha, head_sha = adapter._create_pr_repo(base, head)
    try:
        assert base_sha != head_sha
    finally:
        import shutil
        shutil.rmtree(repo_path, ignore_errors=True)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
