"""Full-scan coverage survives native skip suppression and gates quiet controls."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import pytest

from scaneval import cases, review
from scaneval.adapters.base import SystemSpec
from scaneval.adapters.semgrep import SemgrepAdapter
from scaneval.cli import main
from scaneval.contracts import canonical_json, canonical_sha256, load_document
from scaneval.runner import run_from_config
from scaneval.scoring import observe, score
from test_v2_semgrep import (PLACEABLE, _git, fake_preparation, fake_semgrep, pinned_rules_repo,
                             semgrep_required)


CLOCK = lambda: datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)  # noqa: E731


def run_scan(tmp_path, paths, *, claims=(), exit_code=0, files=("app.py", "control.py")):
    source = tmp_path / "source"
    source.mkdir()
    for path in files:
        target = source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("value = 1\n")
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


@pytest.mark.parametrize("path", ["control.py/", "./control.py", ".//control.py"])
def test_skipped_path_spelling_is_normalized_for_saved_result_contract(tmp_path, path):
    outcome = run_scan(tmp_path, {"scanned": ["app.py", "control.py"], "skipped": [path]})
    assert outcome.omitted_paths == ["control.py"]
    assert control_metrics(outcome, "control.py")["resolved"] == 0


def test_directory_skips_cover_descendants_without_prefix_collisions(tmp_path):
    files = ["vendor/control.py", "vendor-other/control.py"]
    outcome = run_scan(tmp_path, {"scanned": files, "skipped": [{"path": "./vendor/"}]}, files=files)
    assert outcome.omitted_paths == ["vendor", "vendor/control.py"]
    assert outcome.examined_nothing is False
    assert control_metrics(outcome, "vendor/control.py")["resolved"] == 0
    assert control_metrics(outcome, "vendor-other/control.py")["resolved"] == 1


@pytest.mark.parametrize("spelling", ["pkg//control.py", "pkg/./control.py", "pkg/control.py/"])
def test_internal_path_segments_normalize_without_changing_claim_locations(tmp_path, spelling):
    outcome = run_scan(tmp_path, {"scanned": ["pkg/control.py"], "skipped": [spelling]},
                       files=["pkg/control.py"])
    assert outcome.omitted_paths == ["pkg/control.py"]
    assert outcome.examined_nothing is True
    assert control_metrics(outcome, "pkg/control.py")["resolved"] == 0


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


# --- a standard full input through the runner --------------------------------------------------------------------------
#
# A standard input is one named as its own snapshot: every input of a 2.0 configuration, and a 2.1 input with no
# input_id of its own. Its plan was the 2.0 plan, which cannot say where a control is, and the scorer withholds quiet
# credit from a control the plan does not place whenever the result lists any omitted path, which a Semgrep full scan
# nearly always does: it lists every file it did not scan, a README included. The scanner here is a stand-in that prints
# a fixed payload; the adapter, the runner, the plan cases.build_plan writes, the review records, the scorer, and replay
# are the real ones.

STANDARD_FILES = {"app.py": "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n",
                  "vendor/helper.py": "import subprocess\ndef run():\n    return subprocess.run(['ls'])\n",
                  "README.md": "# widget\n"}
STANDARD_REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
                       "assumption, and adds a single-file Python sink for the coverage tests.")


def standard_input_through_the_runner(root: Path, schema_version: str, entry: dict) -> tuple[Path, dict]:
    """One full scan of one standard input by a stand-in Semgrep that reports only ``app.py`` as scanned.

    The repository holds ``app.py``, ``vendor/helper.py``, and ``README.md``. The pack places the safe control
    ``C-scanned`` on ``app.py`` and ``C-omitted`` on ``vendor/helper.py``, a file Semgrep's own ignore rules could
    drop, and the run mechanically checks the case before it plans it. A fictional reviewer then records a quiet
    assessment of both controls. Returns the run directory and its manifest.
    """
    repo = root / "upstream"
    for relative, text in STANDARD_FILES.items():
        (repo / relative).parent.mkdir(parents=True, exist_ok=True)
        (repo / relative).write_text(text, encoding="utf-8")
    _git("init", "-q", "-b", "main", cwd=repo)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    _git("add", "-A", cwd=repo)
    _git("commit", "-q", "-m", "widget", cwd=repo)
    pack = cases.new_pack("test", "standard-coverage", "Local fixture pack for the standard full-scan coverage tests.")
    cases.add_snapshot(pack, {
        "snapshot_id": "widget-main", "repository": {"url": str(repo), "name": "widget"},
        "commit": _git("rev-parse", "HEAD", cwd=repo),
        "reference": "Commit chosen by the test fixture; no advisory is claimed.", "languages": ["python"],
        "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}})
    case = cases.draft_case(
        "case-widget", snapshot_id="widget-main", kind="command_injection",
        description="cmd reaches subprocess with shell=True", represents=STANDARD_REPRESENTS,
        workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection", reference="app.py",
                                 note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "app.py", "start_line": 3, "end_line": 3, "role": "sink", "note": ""}])
    for control_id, path in (("C-scanned", "app.py"), ("C-omitted", "vendor/helper.py")):
        case["controls"].append({
            "control_id": control_id, "snapshot_id": "widget-main", "type": "capability_safe",
            "description": f"The control {control_id} is a safe capability.",
            "property": "No caller-supplied string reaches a shell at this call site.",
            "allowed_actors_inputs": "Operators on the host.", "assumptions": ["Default deployment."],
            "ruled_out_allegation": "Caller-controlled shell interpolation.",
            "locations": [{"path": path, "start_line": 1, "end_line": 1, "role": "operation"}],
            "evidence_ids": ["source"]})
    cases.add_case(pack, case)
    cases.save_pack(root / "pack.json", pack)
    rules, commit = pinned_rules_repo(root)
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})
    settings = {"binary": str(fake_semgrep(root, payload, 0)),
                "ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}, "jobs": 1}
    config = {"schema_version": schema_version, "run_id": "run-standard", "pack": "pack.json", "cache_root": "cache",
              "inputs": [entry], "systems": [{"system_id": "semgrep", "adapter": "semgrep", "config": settings}],
              "repetitions": 1, "timeout_seconds": 120, "trace_mode": "off", "network_policy": "none"}
    (root / "run.json").write_text(canonical_json(config) + "\n", encoding="utf-8")
    out = root / "out"
    manifest = run_from_config(root / "run.json", out, clock=CLOCK)
    for row in manifest["invocations"]:
        bundle = out / row["bundle_path"]
        decisions = load_document(bundle / "evaluator" / "decisions.json", "review-decisions")
        for assessment in decisions["control_assessments"]:
            assessment.update(decision="quiet", claim_ids=[],
                              reason="fixture: the fictional reviewer saw no allegation about the control")
        (bundle / "evaluator" / "decisions.json").write_text(canonical_json(decisions) + "\n", encoding="utf-8")
        review.record_decisions(bundle, clock=CLOCK)
    return out, manifest


@pytest.mark.parametrize("schema_version, entry", [
    ("2.0", {"snapshot_id": "widget-main"}),
    ("2.1", {"snapshot_id": "widget-main", "mode": "full", "profile": "standard"}),
], ids=["2.0-configuration", "2.1-input-with-no-input-id"])
def test_a_standard_input_credits_a_quiet_control_on_a_scanned_file_and_not_one_on_an_omitted_file(
        tmp_path, capsys, schema_version, entry):
    """The plan the runner has cases.build_plan write for a standard input places each control by its pack paths.

    Semgrep scanned app.py and not vendor/helper.py or README.md, so the result lists those two as omitted. Both controls
    are completed and assessed quiet: C-scanned, on the scanned file, is resolved, and C-omitted, on an omitted file,
    is not. With a pathless plan neither was resolved, because a control the plan does not place cannot be shown to lie
    outside an omission.
    """
    out, manifest = standard_input_through_the_runner(tmp_path, schema_version, entry)
    [row] = manifest["invocations"]
    assert row["input_id"] == "widget-main" and row["status"] == "success", "a standard input is its own snapshot"
    bundle = out / row["bundle_path"]
    result = load_document(bundle / "result.json", "scan-result")
    assert result["claims"] == [] and result["bundles_resolved"] is True
    assert result["omitted_paths"] == ["README.md", "vendor/helper.py"] and result["examined_nothing"] is False
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    frozen = load_document(out / "evaluator" / "pack.json", "case-pack")
    assert plan == cases.build_plan(frozen, "widget-main", manifest["inputs"][0]["tree_hash"])[0], \
        "the bundle holds the plan cases.build_plan writes for a standard input"
    decisions = load_document(bundle / "evaluator" / "decisions.json", "review-decisions")

    assert [(r["control_id"], r["decision"], r["completed"], r["resolved"])
            for r in observe(plan, result, decisions)["controls"]] == [
        ("C-scanned", "quiet", True, True), ("C-omitted", "quiet", True, False)]
    record = score(plan, result, decisions)
    safe = record["metrics"]["controls"]["capability_safe"]
    assert (safe["assigned"], safe["completed"], safe["resolved"]) == (2, 2, 1)
    assert [warning for warning in record["warnings"] if "earn no credit" in warning] == [
        "1 quiet control assessment(s) earn no credit: the scan lists paths it did not examine, and each of these "
        "controls is on one of them or is placed by no path, so its silence says nothing about it."]
    assert main(["replay", str(bundle)]) == 0
    assert json.loads(capsys.readouterr().out) == record, "replay reads the saved plan and agrees"

    assert plan["schema_version"] == "2.1" and plan["input_hash"] == result["input_hash"]
    assert [(c["control_id"], c["paths"]) for c in plan["controls"]] == [
        ("C-scanned", ["app.py"]), ("C-omitted", ["vendor/helper.py"])]
    assert "input_id" not in plan["provenance"] and all("canonical_id" not in c for c in plan["controls"]), \
        "a standard input's plan is 2.1 for its paths alone"
