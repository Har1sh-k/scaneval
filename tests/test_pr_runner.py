"""Tests for the ScanEval PR runner (tree materialization, diff, integration)."""

import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from scoring import Finding
from pr_runner import (
    _compute_changed_files,
    _compute_diff_text,
    _has_pr_simulation,
    _is_ignored_path,
    _materialize_vendored,
    _scan_tree,
    _finding_to_dict,
    _try_native_pr_scan,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# --- _has_pr_simulation ---


def test_has_pr_simulation_true():
    assert _has_pr_simulation({"prSimulation": {"mode": "vendored_base"}})


def test_has_pr_simulation_false():
    assert not _has_pr_simulation({"id": "test"})


def test_capability_safe_cases_excluded_from_pr_filtering():
    """The PR runner filtering logic must exclude cases with empty mustDetectRegionIds."""
    from run import find_cases

    all_cases = find_cases("core")

    # Apply the same filtering logic as run_pr_benchmark()
    pr_cases = []
    no_targets_skipped = 0
    for d, c in all_cases:
        if not _has_pr_simulation(c):
            continue
        if not c["expectedOutcome"].get("mustDetectRegionIds"):
            no_targets_skipped += 1
            continue
        pr_cases.append((d, c))

    # capability_safe cases have prSimulation but should be filtered out
    pr_case_types = {c["caseType"] for _, c in pr_cases}
    assert "capability_safe" not in pr_case_types, (
        "capability_safe cases should not pass PR mode filtering"
    )
    assert no_targets_skipped >= 3, (
        f"Expected at least 3 no-target skips (capability_safe), got {no_targets_skipped}"
    )
    # All remaining PR cases should have targets
    for _, c in pr_cases:
        assert len(c["expectedOutcome"]["mustDetectRegionIds"]) > 0, (
            f"{c['id']} passed PR filtering but has no mustDetectRegionIds"
        )


# --- _compute_changed_files ---


def test_compute_changed_files_new_file():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        head = Path(tmp) / "head"
        base.mkdir()
        head.mkdir()

        (base / "a.py").write_text("same")
        (head / "a.py").write_text("same")
        (head / "b.py").write_text("new file")

        changed = _compute_changed_files(base, head)
        assert "b.py" in changed
        assert "a.py" not in changed


def test_compute_changed_files_deleted_file():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        head = Path(tmp) / "head"
        base.mkdir()
        head.mkdir()

        (base / "a.py").write_text("content")
        # a.py not in head

        changed = _compute_changed_files(base, head)
        assert "a.py" in changed


def test_compute_changed_files_modified_file():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        head = Path(tmp) / "head"
        base.mkdir()
        head.mkdir()

        (base / "a.py").write_text("old content")
        (head / "a.py").write_text("new content")

        changed = _compute_changed_files(base, head)
        assert "a.py" in changed


def test_compute_changed_files_ignores_pycache():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        head = Path(tmp) / "head"
        base.mkdir()
        head.mkdir()

        (base / "a.py").write_text("same")
        (head / "a.py").write_text("same")

        # Add __pycache__ only in head
        pycache = head / "__pycache__"
        pycache.mkdir()
        (pycache / "a.cpython-312.pyc").write_bytes(b"\x00")

        changed = _compute_changed_files(base, head)
        assert not any("__pycache__" in f for f in changed)


def test_compute_changed_files_ignores_venv():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        head = Path(tmp) / "head"
        base.mkdir()
        head.mkdir()

        # venv in head only
        venv = head / "venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "site.py").write_text("stuff")

        changed = _compute_changed_files(base, head)
        assert not any("venv" in f for f in changed)


def test_is_ignored_path():
    assert _is_ignored_path("__pycache__/foo.pyc")
    assert _is_ignored_path("agent/__pycache__/planner.cpython-312.pyc")
    assert _is_ignored_path("venv/lib/site.py")
    assert _is_ignored_path(".git/HEAD")
    assert not _is_ignored_path("tools/fetcher.py")
    assert not _is_ignored_path("agent/router.py")


def test_compute_changed_files_identical():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        head = Path(tmp) / "head"
        base.mkdir()
        head.mkdir()

        (base / "a.py").write_text("same")
        (head / "a.py").write_text("same")

        changed = _compute_changed_files(base, head)
        assert changed == []


# --- _compute_diff_text ---


def test_compute_diff_text_produces_unified_diff():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        head = Path(tmp) / "head"
        base.mkdir()
        head.mkdir()

        (base / "a.py").write_text("line1\n")
        (head / "a.py").write_text("line1\nline2\n")

        diff = _compute_diff_text(base, head, ["a.py"])
        assert "--- a/a.py" in diff
        assert "+++ b/a.py" in diff
        assert "+line2" in diff


def test_compute_diff_text_new_file():
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "base"
        head = Path(tmp) / "head"
        base.mkdir()
        head.mkdir()

        (head / "new.py").write_text("content\n")

        diff = _compute_diff_text(base, head, ["new.py"])
        assert "+content" in diff


# --- _materialize_vendored ---


def test_materialize_vendored():
    case_dir = REPO_ROOT / "cases" / "core" / "synthetic_vulnerable" / "PY-SV-001"
    case_json = case_dir / "case.json"
    if not case_json.exists():
        pytest.skip("PY-SV-001 case not available")

    with open(case_json) as f:
        case = json.load(f)

    if "prSimulation" not in case:
        pytest.skip("PY-SV-001 has no prSimulation")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        base_root, head_root = _materialize_vendored(case_dir, case, tmp_root)

        assert base_root.exists()
        assert head_root.exists()

        # Head should have the vulnerable file
        assert (head_root / "tools" / "reference_fetcher.py").exists()
        # Base should NOT have the vulnerable file
        assert not (base_root / "tools" / "reference_fetcher.py").exists()


# --- _scan_tree ---


def test_scan_tree_with_scan():
    adapter = MagicMock()
    adapter.scan.return_value = [
        {
            "ruleId": "test-rule",
            "mappedKind": "ssrf",
            "path": "f.py",
            "startLine": 1,
            "endLine": 5,
        }
    ]
    del adapter.scan_with_metadata  # ensure fallback to scan()

    findings, meta = _scan_tree(adapter, Path("/tmp/test"), "python")
    assert len(findings) == 1
    assert findings[0].rule_id == "test-rule"
    assert meta["skipReason"] is None


def test_scan_tree_with_scan_with_metadata():
    adapter = MagicMock()
    adapter.scan_with_metadata.return_value = {
        "findings": [
            {
                "ruleId": "meta-rule",
                "mappedKind": "ssrf",
                "path": "f.py",
                "startLine": 1,
                "endLine": 5,
            }
        ],
        "commandInvocation": ["scanner", "--json"],
        "exitCode": 0,
        "rawStdout": "output",
        "rawStderr": "",
        "skipReason": None,
    }

    findings, meta = _scan_tree(adapter, Path("/tmp/test"), "python")
    assert len(findings) == 1
    assert findings[0].rule_id == "meta-rule"
    assert meta["commandInvocation"] == ["scanner", "--json"]


def test_scan_tree_error_handling():
    adapter = MagicMock()
    adapter.scan_with_metadata.side_effect = RuntimeError("scanner crashed")

    findings, meta = _scan_tree(adapter, Path("/tmp/test"), "python")
    assert len(findings) == 0
    assert meta["skipReason"] == "adapter_error"


# --- _try_native_pr_scan ---


def test_try_native_pr_scan_no_method():
    adapter = MagicMock(spec=[])  # no scan_pr_with_metadata
    result = _try_native_pr_scan(
        adapter, Path("/base"), Path("/head"), [], "", "python", {}
    )
    assert result is None


def test_try_native_pr_scan_success():
    adapter = MagicMock()
    adapter.scan_pr_with_metadata.return_value = {
        "baselineFindings": [],
        "headFindings": [
            {"ruleId": "r1", "mappedKind": "ssrf", "path": "f.py",
             "startLine": 1, "endLine": 5}
        ],
        "reviewFindings": [
            {"ruleId": "r1", "mappedKind": "ssrf", "path": "f.py",
             "startLine": 1, "endLine": 5}
        ],
        "commandInvocation": ["scanner", "pr"],
        "exitCode": 0,
        "rawStdout": "",
        "rawStderr": "",
        "skipReason": None,
    }

    result = _try_native_pr_scan(
        adapter, Path("/base"), Path("/head"), ["f.py"], "diff", "python", {}
    )
    assert result is not None
    base_f, head_f, review_f, meta = result
    assert len(base_f) == 0
    assert len(head_f) == 1
    assert len(review_f) == 1


def test_try_native_pr_scan_error_falls_back(capsys):
    adapter = MagicMock()
    adapter.scan_pr_with_metadata.side_effect = RuntimeError("broken")

    result = _try_native_pr_scan(
        adapter, Path("/base"), Path("/head"), [], "", "python", {}
    )
    assert result is None

    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "broken" in captured.err
    assert "falling back" in captured.err


# --- _finding_to_dict ---


def test_finding_to_dict():
    f = Finding("r1", "ssrf", "f.py", 10, 20, severity="high", message="bad")
    d = _finding_to_dict(f)
    assert d["ruleId"] == "r1"
    assert d["mappedKind"] == "ssrf"
    assert d["path"] == "f.py"
    assert d["startLine"] == 10
    assert d["endLine"] == 20
    assert d["severity"] == "high"
    assert d["message"] == "bad"


def test_finding_to_dict_no_optional():
    f = Finding("r1", "ssrf", "f.py", 10, 20)
    d = _finding_to_dict(f)
    assert "severity" not in d
    assert "message" not in d
