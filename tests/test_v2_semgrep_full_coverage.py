"""Full-scan coverage survives native skip suppression and gates quiet controls."""
import json
from pathlib import Path
import sys

import pytest

from scaneval.adapters.base import SystemSpec
from scaneval.adapters.semgrep import SemgrepAdapter
from scaneval.contracts import canonical_sha256
from scaneval.scoring import score
from test_v2_semgrep import PLACEABLE, fake_preparation, fake_semgrep, semgrep_required


def run_scan(tmp_path, paths, *, claims=(), exit_code=0):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("value = 1\n")
    (source / "control.py").write_text("value = 2\n")
    raw = tmp_path / "raw"
    raw.mkdir()
    payload = {"version": "1.177.0", "results": list(claims), "errors": []}
    if paths is not None:
        payload["paths"] = paths
    binary = fake_semgrep(tmp_path, json.dumps(payload), exit_code)
    return SemgrepAdapter().scan(
        request={}, source_dir=source, raw_dir=raw,
        spec=SystemSpec("semgrep", "semgrep", {"binary": str(binary)}),
        preparation=fake_preparation(tmp_path), timeout_seconds=20,
        trace_mode="off", trace_dir=None)


def control_metrics(outcome, path):
    bound = "sha256:" + "a" * 64
    result = {"schema_version": "2.1", "run_id": "run", "system_id": "semgrep",
              "input_hash": bound, "status": outcome.status, "ranking": outcome.ranking,
              "claims": outcome.claims, "bundles_resolved": outcome.bundles_resolved,
              "omitted_paths": outcome.omitted_paths, "examined_nothing": outcome.examined_nothing,
              "usage": {"wall_seconds": 1}}
    plan = {"schema_version": "2.1", "input_hash": bound, "scope": "diagnostic",
            "targets": [], "controls": [{"control_id": "C", "type": "capability_safe",
              "description": "synthetic control", "validation_level": "fixture", "paths": [path]}],
            "review_budgets": [1]}
    decisions = {"schema_version": "2.0", "run_id": "run", "input_hash": bound,
                 "result_sha256": canonical_sha256(result), "claim_matches": [],
                 "control_assessments": [{"control_id": "C", "decision": "quiet", "claim_ids": [],
                   "reason": "Synthetic supplied quiet review exercises coverage accounting."}]}
    return score(plan, result, decisions)["metrics"]["controls"]["capability_safe"]


@pytest.mark.parametrize("skipped", [None, ["./control.py"],
    [{"path": "control.py", "reason": "semgrepignore_patterns_match"}]])
def test_ignored_control_cannot_earn_quiet_credit_even_when_skips_are_suppressed(tmp_path, skipped):
    paths = {"scanned": ["./app.py"]}
    if skipped is not None:
        paths["skipped"] = skipped
    outcome = run_scan(tmp_path, paths)
    assert outcome.status == "success"
    assert outcome.omitted_paths == ["control.py"]
    assert outcome.examined_nothing is False
    assert control_metrics(outcome, "control.py")["resolved"] == 0
    assert control_metrics(outcome, "control.py")["sensitivity_upper"] == 1
    assert control_metrics(outcome, "app.py")["resolved"] == 1


@pytest.mark.parametrize("paths", [None, {}, {"scanned": None}, {"scanned": [7, {}, "../app.py"]}])
def test_unknown_or_unusable_coverage_preserves_uncertainty(tmp_path, paths):
    outcome = run_scan(tmp_path, paths)
    assert outcome.omitted_paths == ["app.py", "control.py"]
    assert outcome.examined_nothing is True
    assert control_metrics(outcome, "app.py")["resolved"] == 0


def test_full_coverage_control_retains_quiet_credit(tmp_path):
    outcome = run_scan(tmp_path, {"scanned": ["app.py", "control.py"]})
    assert outcome.omitted_paths == []
    assert outcome.examined_nothing is False
    assert control_metrics(outcome, "control.py")["resolved"] == 1


def test_explicit_skip_wins_over_conflicting_scan_evidence(tmp_path):
    outcome = run_scan(tmp_path, {"scanned": ["app.py", "control.py"],
                                 "skipped": [{"path": "./control.py", "reason": "timeout"}]})
    assert outcome.omitted_paths == ["control.py"]
    assert control_metrics(outcome, "control.py")["resolved"] == 0


def test_partial_scan_keeps_usable_findings_and_omissions(tmp_path):
    outcome = run_scan(tmp_path, {"scanned": ["app.py"]}, claims=[PLACEABLE], exit_code=2)
    assert outcome.status == "partial"
    assert len(outcome.claims) == 1
    assert outcome.omitted_paths == ["control.py"]


@semgrep_required
def test_native_quiet_scan_preserves_ignored_control_coverage(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("value = 1\n")
    (source / "control.py").write_text("value = 2\n")
    (source / ".semgrepignore").write_text("control.py\n")
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule.yml").write_text(
        "rules:\n  - id: harmless\n    languages: [python]\n    severity: INFO\n"
        "    message: synthetic coverage test\n    pattern: __ABSENT_SENTINEL__\n")
    raw = tmp_path / "raw"
    raw.mkdir()
    binary = Path(sys.executable).with_name("semgrep")
    spec = SystemSpec("semgrep", "semgrep", {"binary": str(binary) if binary.exists() else "semgrep"})
    preparation = fake_preparation(tmp_path)
    preparation["config_dirs"] = [str(rules)]
    outcome = SemgrepAdapter().scan(
        request={}, source_dir=source, raw_dir=raw, spec=spec, preparation=preparation,
        timeout_seconds=60, trace_mode="off", trace_dir=None)
    assert outcome.status == "success", outcome.error
    native = json.loads((raw / "semgrep.json").read_text())
    assert "app.py" in native["paths"]["scanned"]
    assert "control.py" not in native["paths"]["scanned"]
    assert "control.py" in outcome.omitted_paths
    assert control_metrics(outcome, "control.py")["resolved"] == 0
    assert control_metrics(outcome, "app.py")["resolved"] == 1
