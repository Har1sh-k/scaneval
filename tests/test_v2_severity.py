"""Calibration math and saved-evidence replay, using fictional reviewed fixtures only."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from scaneval import cases, review, severity
from scaneval.cli import main
from scaneval.contracts import ContractError, canonical_sha256, load_document, validate_document
from test_v2_aggregate import planned, target, scan, write_run, CLOCK, REVIEWER
from test_v2_cases import SNAPSHOT
from test_v2_runner import pilot, upstream, run as run_pilot

VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
REFERENCE = {"level": "critical", "score": 9.1, "cvss_version": "3.1", "vector": VECTOR,
             "source": "https://example.invalid/advisory", "source_kind": "cna_cvss",
             "retrieved": "2026-10-27", "note": "CNA selected; vendor rates this High."}


def refs(reference=REFERENCE):
    return [{"case_id": "example", "severity": deepcopy(reference), "case_sha256": canonical_sha256(reference)}]


@pytest.mark.parametrize("label,error,outcome", [("critical", 0, "exact"), (" HIGH ", -1, "underestimated"), ("low", -3, "underestimated")])
def test_qualitative_comparisons_preserve_label_and_never_invent_score(label, error, outcome):
    result = severity.compare_severity({"native_severity": label}, refs())
    assert result["status"] == "assessed"
    assert result["native_severity"] == label
    assert result["band_error"] == error
    assert result["outcome"] == outcome
    assert result["numeric_delta"] is None
    assert result["numeric_reason"] == "qualitative_only"
    assert result["reference"]["note"] == REFERENCE["note"]


def test_numeric_comparison_is_version_specific_and_provenance_preserved():
    claim = {"claimed_cvss": {"score": 8.2, "version": "3.1", "provenance": "self_reported"}}
    result = severity.compare_severity(claim, refs())
    assert result["numeric_delta"] == -0.9
    assert result["band_error"] == -1
    assert result["claimed_provenance"] == "self_reported"
    claim["claimed_cvss"]["version"] = "4.0"
    result = severity.compare_severity(claim, refs())
    assert result["reason"] == "cvss_version_mismatch"
    assert result["cross_version"] is True
    assert result["numeric_delta"] is result["band_error"] is None


def test_overestimate_and_conflicting_claims():
    reference = {**REFERENCE, "score": 7.0, "level": "high"}
    assert severity.compare_severity({"native_severity": "critical"}, refs(reference))["band_error"] == 1
    result = severity.compare_severity({"native_severity": "low", "claimed_cvss": {"score": 9.1, "version": "3.1", "provenance": "native"}}, refs())
    assert result["reason"] == "conflicting_claimed_severity"
    assert result["numeric_delta"] is None


@pytest.mark.parametrize("claim,reason", [({}, "claimed_severity_missing"), ({"native_severity": "bug"}, "unmapped_severity_label"), ({"native_severity": "ERROR; security-severity 9.1"}, "unmapped_severity_label")])
def test_missing_unknown_and_rule_priority_are_unavailable(claim, reason):
    result = severity.compare_severity(claim, refs())
    assert result["status"] == "unavailable"
    assert result["reason"] == reason
    assert result["band_error"] is result["numeric_delta"] is None


def test_missing_or_conflicting_alias_references_are_unavailable():
    claim = {"native_severity": "high"}
    assert severity.compare_severity(claim, refs(None))["reason"] == "reference_unavailable"
    assert severity.compare_severity(claim, refs() + refs({**REFERENCE, "score": 8.0, "level": "high"}))["reason"] == "conflicting_references"


@pytest.mark.parametrize("score,expected", [(0, "none"), (.1, "low"), (3.9, "low"), (4, "medium"), (6.9, "medium"), (7, "high"), (8.9, "high"), (9, "critical"), (10, "critical")])
def test_band_boundaries(score, expected):
    assert severity.band(score) == expected


@pytest.mark.parametrize("patch", [{"score": True}, {"score": float("nan")}, {"score": 10.1}, {"score": 1.23}, {"version": "2.0"}, {"provenance": "confidence"}, {"vector": "CVSS:3.1/AV:N"}, {"vector": VECTOR + "/AV:N"}, {"vector": VECTOR.replace("AV:N", "AV:Z")}, {"vector": VECTOR.replace("3.1", "4.0")}])
def test_malformed_numeric_evidence_is_rejected(patch):
    with pytest.raises(ContractError):
        severity.validate_claimed_cvss({"score": 9.1, "version": "3.1", "provenance": "native", **patch})


def fixture_run(tmp_path, *, states=None, labels=None, numeric=None, count=1, repetitions=1, aliases=False):
    pack = cases.new_pack("org.example", "severity-fixture", "Fictional calibration fixtures")
    cases.add_snapshot(pack, SNAPSHOT)
    targets = []
    for index in range(count):
        case = cases.draft_case(f"example{index}", snapshot_id=SNAPSHOT["snapshot_id"], kind="command_injection", description="Fictional source bug", represents="A fictional severity test", workload="conventional_application", component_role="application", aliases=[], evidence=[])
        case["severity"] = deepcopy(REFERENCE)
        cases.add_case(pack, case)
        if aliases:
            cases.set_canonical_id(pack, case["case_id"], "canonical-example")
        targets.append({**target(case["target"]["target_id"], canonical="canonical-example" if aliases else None), "case_id": case["case_id"]})
    identity = {"namespace": pack["namespace"], "pack_id": pack["pack_id"], "version": pack["version"], "sha256": cases.pack_sha256(pack)}
    outcomes = {}
    for repetition in range(1, repetitions + 1):
        options = (states or {}).get(repetition, {})
        outcomes[("input", "sys-a", repetition)] = scan(hits={t["target_id"]: index + 1 for index, t in enumerate(targets)}, **options)
    run = write_run(tmp_path, "run-severity", [planned("input", targets=targets)], repetitions=repetitions, outcomes=outcomes, pack=identity)
    (run / "evaluator/pack.json").write_text(json.dumps(pack))
    for bundle in (run / "invocations").iterdir():
        result = load_document(bundle / "result.json", "scan-result")
        result["schema_version"] = "2.1"
        for index, claim in enumerate(result["claims"]):
            label = (labels or {}).get(index, "High")
            if label is not None:
                claim["native_severity"] = label
            if numeric and index in numeric:
                claim["claimed_cvss"] = numeric[index]
        plan, decisions, record = review.load_evaluator(bundle)
        plan["schema_version"] = "2.1"
        for t, frozen in zip(plan["targets"], targets):
            t["canonical_id"] = frozen["canonical_id"]
        plan["provenance"] = {"namespace": pack["namespace"], "pack_id": pack["pack_id"], "pack_version": pack["version"], "pack_sha256": cases.pack_sha256(pack), "snapshot_id": SNAPSHOT["snapshot_id"], "mode": "full", "case_ids": [c["case_id"] for c in pack["cases"]]}
        decisions["result_sha256"] = canonical_sha256(result)
        refreshed = review.review_record(plan, decisions, clock=CLOCK)
        if record["state"] == "human_approved":
            refreshed = review.approve_review(refreshed, decisions, plan, reviewer=REVIEWER, note="Fictional approval", clock=CLOCK)
        for filename, data in (("result.json", result), ("evaluator/plan.json", plan), ("evaluator/decisions.json", decisions), ("evaluator/review-record.json", refreshed)):
            (bundle / filename).write_text(json.dumps(data))
    return run, pack


def test_complete_saved_run_cli_and_replay(tmp_path):
    run, pack = fixture_run(tmp_path, numeric={0: {"score": 8.2, "version": "3.1", "provenance": "native"}})
    report = severity.calibrate([run], pack)
    assert report["counts"]["assessed"] == 1
    metrics = report["views"][0]["weightings"][0]["metrics"]
    assert metrics["numeric_bias"]["value"] == -0.9
    assert metrics["underestimation"]["value"] == 1
    severity.verify(report, [run], pack)
    pack_path = tmp_path / "pack.json"
    pack_path.write_text(json.dumps(pack))
    output, html = tmp_path / "severity.json", tmp_path / "severity.html"
    assert main(["severity", str(run), "--pack", str(pack_path), "--output", str(output), "--html", str(html)]) == 0
    assert main(["severity", str(run), "--pack", str(pack_path), "--verify", str(output)]) == 0
    assert "Target comparisons" in html.read_text()
    assert main(["severity", str(run), "--pack", str(pack_path), "--output", str(output)]) == 2


@pytest.mark.parametrize("options,reason", [({"status": "partial"}, "scan_partial"), ({"status": "timeout"}, "scan_timeout"), ({"status": "error"}, "scan_error"), ({"status": "unsupported"}, "scan_unsupported"), ({"resolved": False}, "unresolved_bundles"), ({"review_state": "draft"}, "review_draft")])
def test_ineligible_observations_do_not_enter_severity_denominator(tmp_path, options, reason):
    run, pack = fixture_run(tmp_path, states={1: options})
    report = severity.calibrate([run], pack)
    assert report["counts"]["excluded"] == 1
    assert report["counts"]["eligible_matched"] == 0
    assert report["records"][0]["reason"] == reason
    assert report["views"][0]["weightings"][0]["metrics"]["assessment_coverage"]["value"] is None


def test_missing_severity_stays_in_coverage_and_html_is_escaped(tmp_path):
    run, pack = fixture_run(tmp_path, count=2, labels={0: None, 1: "<script>alert(1)</script>"})
    report = severity.calibrate([run], pack)
    assert report["counts"]["unavailable"] == 2
    assert report["views"][0]["weightings"][0]["metrics"]["assessment_coverage"]["value"] == 0
    html = severity.render_html(report)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_changed_result_decisions_pack_or_report_invalidates_replay(tmp_path):
    run, pack = fixture_run(tmp_path)
    report = severity.calibrate([run], pack)
    edited = deepcopy(report)
    edited["records"][0]["comparison"]["numeric_delta"] = 0
    with pytest.raises(ContractError):
        severity.verify(edited, [run], pack)
    new_pack = deepcopy(pack)
    new_pack["cases"][0]["severity"]["note"] += " changed source evidence"
    with pytest.raises(ContractError):
        severity.verify(report, [run], new_pack)
    result_path = next((run / "invocations").glob("*/result.json"))
    changed = json.loads(result_path.read_text())
    changed["claims"][0]["native_severity"] = "Critical"
    result_path.write_text(json.dumps(changed))
    with pytest.raises(ContractError, match="stale"):
        severity.verify(report, [run], pack)


def test_repetitions_and_qualitative_denominators(tmp_path):
    run, pack = fixture_run(tmp_path, count=2, repetitions=3, labels={0: "Critical", 1: None})
    report = severity.calibrate([run], pack)
    assert report["counts"]["canonical_targets"] == 2
    assert report["counts"]["target_observations"] == 6
    metrics = report["views"][0]["weightings"][0]["metrics"]
    assert metrics["assessment_coverage"]["value"] == .5
    assert metrics["exact_band_agreement"]["value"] == 1
    assert metrics["numeric_bias"]["value"] is None
    assert metrics["exact_band_agreement"]["denominator_targets"] == 1


def test_aliases_count_once_and_selection_does_not_cherry_pick_severity(tmp_path):
    run, pack = fixture_run(tmp_path, count=2, aliases=True, labels={0: None, 1: "Critical"})
    report = severity.calibrate([run], pack)
    assert report["counts"]["target_observations"] == 1
    assert report["records"][0]["selected_claim"]["claim_id"] == "c1"
    assert report["records"][0]["reason"] == "claimed_severity_missing"


def revise_decisions(run, change, *, approve=True):
    bundle = next((run / "invocations").iterdir())
    plan, decisions, record = review.load_evaluator(bundle)
    change(decisions)
    record = review.review_record(plan, decisions, clock=CLOCK)
    if approve:
        record = review.approve_review(record, decisions, plan, reviewer=REVIEWER, note="Fictional revised decision", clock=CLOCK)
    (bundle / "evaluator/decisions.json").write_text(json.dumps(decisions))
    (bundle / "evaluator/review-record.json").write_text(json.dumps(record))


@pytest.mark.parametrize("state,reason", [("rejected", "unmatched"), ("unresolved", "unresolved_match")])
def test_unaccepted_claims_are_never_compared(tmp_path, state, reason):
    run, pack = fixture_run(tmp_path)
    revise_decisions(run, lambda d: d["claim_matches"][0].update(decision=state))
    report = severity.calibrate([run], pack)
    assert report["records"][0]["comparison"] is None
    assert report["records"][0]["reason"] == reason
    assert report["counts"]["matched"] == 0


def test_stale_review_is_counted_as_excluded(tmp_path):
    run, pack = fixture_run(tmp_path)
    path = next((run / "invocations").glob("*/evaluator/decisions.json"))
    decisions = json.loads(path.read_text())
    decisions["claim_matches"][0]["reason"] = "Changed rationale without renewed review"
    path.write_text(json.dumps(decisions))
    report = severity.calibrate([run], pack)
    assert report["counts"]["matched"] == 1
    assert report["records"][0]["reason"] == "review_stale"


def test_more_repetitions_in_one_run_do_not_change_its_weight():
    def row(run, repetition, label):
        return {"run_id": run, "input_id": "input", "repetition": repetition, "canonical_id": "t", "matched": True,
                "status": "assessed", "reason": None, "comparison": severity.compare_severity({"native_severity": label}, refs())}
    rows = [row("a", 1, "Critical"), *[row("b", r, "High") for r in range(1, 4)]]
    attrs = {"t": {"project": "p", "family": "f", "workload": "conventional_application"}}
    result = severity._metrics(rows, attrs, "equal_target", severity.aggregate.DEFAULT_POLICY, whole_view=True)
    assert result["metrics"]["exact_band_agreement"]["value"] == .5
    assert result["metrics"]["underestimation"]["value"] == .5


def test_weighted_project_view_has_declared_denominator():
    rows = [{"run_id": "run", "input_id": t, "canonical_id": t, "matched": True, "status": "assessed", "reason": None,
             "comparison": severity.compare_severity({"native_severity": label}, refs())}
            for t, label in [("a", "High"), ("b", "High"), ("c", "Critical")]]
    attrs = {t: {"project": "alpha" if t != "c" else "beta", "family": t, "workload": "conventional_application"} for t in "abc"}
    target_view = severity._metrics(rows, attrs, "equal_target", severity.aggregate.DEFAULT_POLICY, whole_view=True)
    project_view = severity._metrics(rows, attrs, "equal_project", severity.aggregate.DEFAULT_POLICY, whole_view=True)
    assert target_view["metrics"]["exact_band_agreement"]["value"] == pytest.approx(1/3)
    assert project_view["metrics"]["exact_band_agreement"]["value"] == .5
    assert project_view["metrics"]["exact_band_agreement"]["weighted_denominator"] == 1


def test_claimed_cvss_field_is_optional_in_21_and_rejected_in_20(tmp_path):
    run, _ = fixture_run(tmp_path, numeric={0: {"score": 8.2, "version": "3.1", "provenance": "imported", "vector": VECTOR}})
    path = next((run / "invocations").glob("*/result.json"))
    result = load_document(path, "scan-result")
    result["schema_version"] = "2.0"
    with pytest.raises(ContractError):
        validate_document("scan-result", result)
    result["claims"][0].pop("claimed_cvss")
    validate_document("scan-result", result)


def test_real_runner_distinguishes_configured_and_mechanically_updated_packs(tmp_path, pilot):
    from scaneval.contracts import pack_anchor_digest
    from scaneval.runner import run_from_config
    first = tmp_path / "preparation"
    run_pilot(pilot, first)
    configured = load_document(first / "evaluator/pack.json", "case-pack")
    configured["cases"][0]["severity"] = deepcopy(REFERENCE)
    configured["anchor_sha256"] = pack_anchor_digest(configured)
    cases.save_pack(pilot["pack_path"], configured)
    out = tmp_path / "actual-run"
    run_from_config(pilot["config_path"], out, workspace_root=pilot["workspace"], adapters={"fake": pilot["adapter"]},
                    clock=lambda: datetime(2026, 10, 27, tzinfo=timezone.utc))
    frozen = load_document(out / "evaluator/pack.json", "case-pack")
    assert canonical_sha256(frozen) != canonical_sha256(configured)
    revise_decisions(out, lambda d: d["claim_matches"][0].update(decision="accepted"))
    report = severity.calibrate([out], configured)
    assert report["records"][0]["reason"] == "scope_draft"
    assert report["records"][0]["matched"]
    assert report["runs"][0]["frozen_pack_sha256"] == canonical_sha256(frozen)
    severity.verify(report, [out], configured)


def test_unavailable_frozen_plan_is_an_explicit_assignment(tmp_path, pilot):
    out = tmp_path / "actual-run"
    configured = load_document(pilot["pack_path"], "case-pack")
    run_pilot(pilot, out)
    report = severity.calibrate([out], configured)
    assert report["counts"]["target_observations"] == 0
    assert report["assignment_counts"] == {"scheduled": 1, "unplanned": 1}
    assert report["unplanned_assignments"][0]["reason"] == "frozen_plan_unavailable"
    assert len(report["views"][0]["unplanned_assignments"]) == 1


def test_mutated_runtime_reference_is_rejected_even_with_new_anchor(tmp_path):
    from scaneval.contracts import pack_anchor_digest
    run, pack = fixture_run(tmp_path)
    changed = deepcopy(pack)
    changed["cases"][0]["severity"]["note"] += " tampered rating selection"
    changed["anchor_sha256"] = pack_anchor_digest(changed)
    (run / "evaluator/pack.json").write_text(json.dumps(changed))
    with pytest.raises(ContractError, match="reference severity"):
        severity.calibrate([run], pack)


def test_approved_diagnostic_plan_does_not_enter_official_metrics(tmp_path):
    run, pack = fixture_run(tmp_path)
    path = next((run / "invocations").glob("*/evaluator/plan.json"))
    plan = json.loads(path.read_text())
    plan["scope"] = "diagnostic"
    plan["targets"][0]["validation_level"] = "fixture"
    path.write_text(json.dumps(plan))
    revise_decisions(run, lambda d: None)
    report = severity.calibrate([run], pack)
    assert report["records"][0]["reason"] == "scope_diagnostic"
    assert report["views"][0]["evidence_scope"] == "diagnostic"
