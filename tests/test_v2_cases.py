"""Case packs: drafts stay drafts, mechanical checks stop at L1, approval is explicit, plans degrade."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from sastbench.cases import (
    accepted_paths_for_targets,
    add_case,
    add_snapshot,
    admit_case,
    approve_case,
    build_plan,
    case_by_id,
    draft_case,
    draft_case_from_legacy,
    dump_json,
    evidence,
    latest_admission,
    load_pack,
    mechanical_checks,
    new_pack,
    pack_summary,
    save_pack,
    set_disposition,
)
from sastbench.contracts import ContractError, validate_document


CLOCK = lambda: datetime(2026, 9, 20, 17, 0, tzinfo=timezone.utc)  # noqa: E731
HASH = "sha256:" + "b" * 64
SNAPSHOT = {
    "snapshot_id": "widget-abc", "repository": {"url": "https://example.invalid/acme/widget.git", "name": "acme/widget"},
    "commit": "a" * 40, "reference": "parent of fix commit", "languages": ["python"],
    "workload": "conventional_application", "component_role": "application",
    "license": {"spdx": "MIT", "verified": False, "note": "not checked"},
}
REPRESENTS = "This case tests shell interpolation of a request parameter under a default deployment, and adds a Python command-injection target."
FIXED_SNAPSHOT = {**SNAPSHOT, "snapshot_id": "widget-fixed", "commit": "e" * 40, "role": "fixed",
                  "reference": "maintainer fix commit"}
LATER_SNAPSHOT = {**SNAPSHOT, "snapshot_id": "widget-later", "commit": "f" * 40, "role": "fixed",
                  "reference": "a later maintainer release"}
FIXED_HASH = "sha256:" + "d" * 64


def fixed_control(case_id: str = "widget-shell") -> dict:
    """A fixed-target control on the repaired snapshot, drafted rather than reviewed."""
    return {
        "control_id": f"C-{case_id}-fixed", "snapshot_id": "widget-fixed", "type": "fixed_target",
        "target_id": f"T-{case_id}", "description": "The repaired call no longer builds a shell string.",
        "property": "The command is passed as an argument list under the same deployment assumptions.",
        "allowed_actors_inputs": "The same callers as the vulnerable snapshot.",
        "assumptions": ["Default deployment."],
        "ruled_out_allegation": "Caller-controlled shell interpolation at this call site.",
        "locations": [{"path": "src/app.py", "start_line": 3, "end_line": 3, "role": "operation"}],
        "evidence_ids": ["fix"],
    }


def make_pack() -> dict:
    pack = new_pack("org.example", "pilot", "test pack")
    add_snapshot(pack, SNAPSHOT)
    add_case(pack, draft_case(
        "widget-shell", snapshot_id="widget-abc", kind="command_injection", description="cmd reaches subprocess with shell=True",
        represents=REPRESENTS, workload="conventional_application", component_role="application",
        aliases=["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"],
        evidence=[evidence("fix", origin="fix_without_advisory", kind="fix_commit", reference="acme/widget@" + "c" * 40)],
        accepted_locations=[{"path": "src/app.py", "start_line": 3, "end_line": 3, "role": "sink"}],
    ))
    return pack


def export(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text("import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    return source


def test_new_pack_and_draft_case_are_valid_and_explicitly_unreviewed(tmp_path):
    pack = make_pack()
    case = pack["cases"][0]
    assert case["validation"] == {"level": None, "review_state": "draft", "checks": [], "reviews": []}
    assert case["disposition"]["value"] == "needs_evidence"
    assert case["coverage_signature"]["guard_failure"] == {"state": "not_reviewed"}
    assert case["target"]["target_id"] == "T-widget-shell"
    path = tmp_path / "pack.json"
    save_pack(path, pack)
    assert load_pack(path) == pack
    assert pack_summary(pack)["review_states"] == {"draft": 1, "mechanically_checked": 0, "human_approved": 0}
    with pytest.raises(ContractError, match="already exists"):
        add_snapshot(pack, SNAPSHOT)
    with pytest.raises(ContractError, match="already exists"):
        add_case(pack, pack["cases"][0])


def test_contract_rejects_inconsistent_review_states_and_dangling_references():
    pack = make_pack()
    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["level"] = "L3"
    with pytest.raises(ContractError, match="requires human_approved"):
        validate_document("case-pack", broken)
    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"].update({"review_state": "human_approved", "level": "L3"})
    with pytest.raises(ContractError, match="approving review"):
        validate_document("case-pack", broken)
    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["target"]["snapshot_id"] = "nope"
    with pytest.raises(ContractError, match="not declared"):
        validate_document("case-pack", broken)
    broken = json.loads(json.dumps(pack))
    broken["admissions"].append({"case_id": "ghost", "decision": "admitted", "by": "x", "at": "t", "reason": "r"})
    with pytest.raises(ContractError, match="unknown case"):
        validate_document("case-pack", broken)


def test_mechanical_checks_reach_l1_only_and_record_failures(tmp_path):
    pack = make_pack()
    source = export(tmp_path)
    outcomes = mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    # Results are swapped into the pack as a validated copy, so every assertion re-reads it.
    validation = lambda: case_by_id(pack, "widget-shell")["validation"]  # noqa: E731
    assert outcomes[0]["passed"] is True
    assert validation()["review_state"] == "mechanically_checked" and validation()["level"] == "L1"
    assert {c["check"]: c["result"] for c in validation()["checks"]}["locations_exist_in_snapshot"] == "pass"
    assert pack["snapshots"][0]["tree_hash"] == HASH
    outcomes = mechanical_checks(pack, "widget-abc", source, "sha256:" + "c" * 64, clock=CLOCK)
    assert outcomes[0]["passed"] is False
    assert pack["snapshots"][0]["tree_hash"] == HASH, "a recorded tree hash is never rewritten"
    assert validation()["review_state"] == "draft" and validation()["level"] is None
    assert [c["result"] for c in validation()["checks"] if c["check"] == "snapshot_hash_recorded"] == ["fail"]
    assert mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)[0]["passed"] is True
    assert validation()["review_state"] == "mechanically_checked"

    case_by_id(pack, "widget-shell")["target"]["accepted_locations"][0]["end_line"] = 99
    outcomes = mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    assert outcomes[0]["passed"] is False
    assert validation()["review_state"] == "draft" and validation()["level"] is None
    assert any(c["check"] == "line_ranges_within_files" and c["result"] == "fail" for c in validation()["checks"])


def test_plan_degrades_to_draft_and_needs_explicit_approval_for_reviewed(tmp_path):
    pack = make_pack()
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["targets"] == [] and any("not planned" in note for note in notes)
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"][0]["validation_level"] == "L1"
    assert plan["review_budgets"] == [5, 10, 20, 50] and plan["provenance"]["case_ids"] == ["widget-shell"]
    assert plan["input_hash"] == HASH
    assert accepted_paths_for_targets(pack, {"T-widget-shell"}) == {"T-widget-shell": {"src/app.py"}}

    with pytest.raises(ContractError, match="independent_reviewer"):
        approve_case(pack, "widget-shell", reviewer="curator", role="curator", level="L3", note="", clock=CLOCK)
    approve_case(pack, "widget-shell", reviewer="curator", role="curator", level="L2", note="structure reviewed", clock=CLOCK)
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"][0]["validation_level"] == "L2"
    with pytest.raises(ContractError, match="L3/L4 require disposition validate"):
        approve_case(pack, "widget-shell", reviewer="second", role="independent_reviewer", level="L3",
                     note="label established", clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed, worth validating")
    approve_case(pack, "widget-shell", reviewer="second", role="independent_reviewer", level="L3", note="label established", clock=CLOCK)
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and plan["targets"][0]["validation_level"] == "L3"
    assert pack["cases"][0]["validation"]["reviews"][-1]["reviewer"] == "second"
    admit_case(pack, "widget-shell", decision="admitted", by="second", reason="pilot", clock=CLOCK)
    assert pack["admissions"][0]["decision"] == "admitted"

    with pytest.raises(ContractError, match="requires disposition validate"):
        set_disposition(pack, "widget-shell", "exclude", "duplicate target")
    assert case_by_id(pack, "widget-shell")["disposition"]["value"] == "validate", \
        "a refused disposition change leaves the screening decision the approval rests on"


def test_approval_requires_prior_mechanical_checks():
    pack = make_pack()
    with pytest.raises(ContractError, match="mechanical checks"):
        approve_case(pack, "widget-shell", reviewer="r", role="independent_reviewer", level="L3", note="", clock=CLOCK)


def test_legacy_migration_keeps_regions_as_draft_evidence(tmp_path):
    legacy = {
        "id": "SB-GO-RG-001", "caseType": "real_world_generic", "canonicalKind": "auth_bypass", "title": "skip regex on full URI",
        "description": "regex matched path plus query", "regions": [{"id": "R1", "path": "oauthproxy.go", "startLine": 582, "endLine": 590,
                                                                     "label": "vulnerable", "capability": "authentication"}],
        "realWorld": {"repo": "oauth2-proxy/oauth2-proxy", "vulnerableCommit": "f" * 40, "fixCommit": "9" * 40,
                      "ghsa": "GHSA-7rh7-c77v-6434", "cve": "CVE-2025-54576",
                      "disclosure": {"ghsaPublished": "2025-07-30", "fixCommitDate": "2025-07-29"}},
    }
    case = draft_case_from_legacy(legacy, case_id="oauth2-proxy-cve-2025-54576", snapshot_id="widget-abc",
                                  legacy_path="cases/full/real_world_generic/SB-GO-RG-001/case.json",
                                  workload="conventional_application", component_role="infrastructure", represents=REPRESENTS)
    pack = new_pack("sastbench.public", "pilot", "x")
    add_snapshot(pack, SNAPSHOT)
    add_case(pack, case)
    assert case["validation"]["review_state"] == "draft" and case["validation"]["level"] is None
    assert case["target"]["accepted_locations"] == [{"path": "oauthproxy.go", "start_line": 582, "end_line": 590, "role": "other",
                                                     "note": "legacy region R1 label=vulnerable capability=authentication"}]
    assert case["canonical_target"]["aliases"] == ["CVE-2025-54576", "GHSA-7rh7-c77v-6434"]
    assert {e["kind"] for e in case["evidence"]} == {"other", "fix_commit", "ghsa_advisory", "cve_record"}
    assert case["evidence"][0]["origin"] == "legacy_case_record"
    assert case["disclosure"]["ghsa_published"] == "2025-07-30" and case["disclosure"]["earliest_public_artifact"] is None


def test_blank_reviewer_and_admission_names_are_refused(tmp_path):
    """A name that is empty after stripping is not a name, so it cannot record a human decision."""
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    for reviewer in ("", "   ", "\t\n", "\u200b", "\ufeff\u200e", "\u00a0", "\u2028", "\u2029",
                     "\u2028\u200b\u00a0"):
        with pytest.raises(ContractError, match="explicit reviewer name"):
            approve_case(pack, "widget-shell", reviewer=reviewer, role="curator", level="L1",
                         note="n", clock=CLOCK)
    assert pack["cases"][0]["validation"]["reviews"] == []

    for by in ("", "  ", "\u200b", "\u00a0\u200e", "\u2028", "\u2029"):
        with pytest.raises(ContractError, match="explicit name"):
            admit_case(pack, "widget-shell", decision="admitted", by=by, reason="pilot", clock=CLOCK)
    with pytest.raises(ContractError, match="non-blank reason"):
        admit_case(pack, "widget-shell", decision="admitted", by="J. Curator", reason="   ", clock=CLOCK)
    assert pack["admissions"] == []
    for reason in (" ", "\u200b", "\u2028", "\u2029"):
        with pytest.raises(ContractError, match="non-blank reason"):
            set_disposition(pack, "widget-shell", "validate", reason)
    assert pack["cases"][0]["disposition"]["value"] == "needs_evidence"


def two_snapshot_pack() -> dict:
    """One case whose target is on the vulnerable snapshot and whose control is on the fixed one."""
    pack = make_pack()
    add_snapshot(pack, FIXED_SNAPSHOT)
    case_by_id(pack, "widget-shell")["controls"].append(fixed_control())
    return pack


def test_a_two_snapshot_case_reaches_l1_only_after_both_snapshots_pass_in_either_order(tmp_path):
    source = export(tmp_path)
    first = two_snapshot_pack()
    assert mechanical_checks(first, "widget-abc", source, HASH, clock=CLOCK)[0]["passed"] is True
    assert case_by_id(first, "widget-shell")["validation"]["review_state"] == "draft", \
        "the fixed snapshot has not been checked yet"
    assert mechanical_checks(first, "widget-fixed", source, FIXED_HASH, clock=CLOCK)[0]["passed"] is True
    validation = case_by_id(first, "widget-shell")["validation"]
    assert validation["review_state"] == "mechanically_checked" and validation["level"] == "L1"

    second = two_snapshot_pack()
    assert mechanical_checks(second, "widget-fixed", source, FIXED_HASH, clock=CLOCK)[0]["passed"] is True
    assert case_by_id(second, "widget-shell")["validation"]["review_state"] == "draft"
    assert mechanical_checks(second, "widget-abc", source, HASH, clock=CLOCK)[0]["passed"] is True

    def state(pack: dict) -> dict:
        """Review state, level, and every recorded check keyed by snapshot; list order is not state."""
        checked = case_by_id(pack, "widget-shell")["validation"]
        return {"review_state": checked["review_state"], "level": checked["level"],
                "checks": {(check["snapshot_id"], check["check"]): check["result"]
                           for check in checked["checks"]}}

    assert state(first) == state(second)
    assert {snapshot for snapshot, _ in state(first)["checks"]} == {"widget-abc", "widget-fixed"}
    assert set(state(first)["checks"].values()) == {"pass"}
    plan, _ = build_plan(first, "widget-fixed", FIXED_HASH)
    assert [(c["control_id"], c["validation_level"]) for c in plan["controls"]] == [
        ("C-widget-shell-fixed", "L1")]


def test_a_failing_check_after_approval_keeps_the_review_and_leaves_the_case_out_of_the_plan(tmp_path):
    pack = make_pack()
    source = export(tmp_path)
    mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L3",
                 note="label established", clock=CLOCK)
    assert "checks_failed" not in case_by_id(pack, "widget-shell")["validation"]

    case_by_id(pack, "widget-shell")["target"]["accepted_locations"][0]["path"] = "src/moved.py"
    outcomes = mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    validation = case_by_id(pack, "widget-shell")["validation"]
    assert outcomes[0]["passed"] is False
    assert validation["review_state"] == "human_approved" and validation["level"] == "L3"
    assert validation["checks_failed"] is True
    assert validation["reviews"][-1]["reviewer"] == "R. Eviewer"

    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["targets"] == [] and plan["scope"] == "draft"
    assert any("a mechanical check set failed after approval" in note for note in notes)

    case_by_id(pack, "widget-shell")["target"]["accepted_locations"][0]["path"] = "src/app.py"
    mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    assert "checks_failed" not in case_by_id(pack, "widget-shell")["validation"]
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert [target["target_id"] for target in plan["targets"]] == ["T-widget-shell"]


def test_a_rejected_admission_excludes_a_case_from_the_plan(tmp_path):
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    admit_case(pack, "widget-shell", decision="rejected", by="J. Curator",
               reason="duplicate of an admitted target", clock=CLOCK)

    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["targets"] == []
    assert any("latest admission decision (rejected by J. Curator" in note for note in notes)

    admit_case(pack, "widget-shell", decision="admitted", by="J. Curator",
               reason="mechanism is distinct after review", clock=CLOCK)
    assert latest_admission(pack, "widget-shell")["decision"] == "admitted"
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert [target["target_id"] for target in plan["targets"]] == ["T-widget-shell"]


def test_set_disposition_records_the_previous_value_and_refuses_unknown_ones(tmp_path):
    pack = make_pack()
    recorded = set_disposition(pack, "widget-shell", "validate", "advisory and fix both read")
    assert recorded == {"value": "validate", "reason": "advisory and fix both read"}
    assert case_by_id(pack, "widget-shell")["notes"][-1] == (
        "disposition changed from needs_evidence to validate: advisory and fix both read")
    with pytest.raises(ContractError, match="disposition must be one of"):
        set_disposition(pack, "widget-shell", "approved", "not a disposition")
    assert case_by_id(pack, "widget-shell")["disposition"]["value"] == "validate"


def test_a_draft_plan_keeps_a_reviewed_level_instead_of_rewriting_it(tmp_path):
    """Scope carries draft status; an approved case keeps L3 beside an unreviewed L1 case."""
    pack = make_pack()
    add_case(pack, draft_case(
        "widget-path", snapshot_id="widget-abc", kind="path_traversal", description="join of a user path",
        represents=REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[evidence("note", origin="research_note", kind="source_inspection", reference="src/app.py")],
        accepted_locations=[{"path": "src/app.py", "start_line": 1, "end_line": 1, "role": "sink"}],
    ))
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L4",
                 note="build and tests reviewed", clock=CLOCK)

    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft"
    assert {target["target_id"]: target["validation_level"] for target in plan["targets"]} == {
        "T-widget-shell": "L4", "T-widget-path": "L1"}
    validate_document("evaluation-plan", plan)


def later_control(case_id: str = "widget-shell") -> dict:
    """A second fixed-target control, on a snapshot no mechanical check has covered."""
    return {**fixed_control(case_id), "control_id": f"C-{case_id}-later", "snapshot_id": "widget-later",
            "description": "The later release still passes the command as an argument list."}


def test_an_excluded_disposition_keeps_a_checked_case_out_of_the_plan(tmp_path):
    """Screening the case out is a stated decision, and the plan says which decision it was."""
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "exclude", "duplicate of an admitted target")

    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["targets"] == [] and plan["scope"] == "draft"
    assert any("excluded by disposition (duplicate of an admitted target)" in note for note in notes)


def test_a_case_is_not_planned_while_any_referenced_snapshot_is_unchecked(tmp_path):
    """L1 covers the case, not one snapshot of it, so an unchecked snapshot withdraws planning."""
    pack = two_snapshot_pack()
    source = export(tmp_path)
    mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    mechanical_checks(pack, "widget-fixed", source, FIXED_HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L3",
                 note="label established", clock=CLOCK)
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert [target["target_id"] for target in plan["targets"]] == ["T-widget-shell"]

    # A control is added on a snapshot no check has ever covered: the approval stands and says
    # nothing about that snapshot, so the case is unplanned until it is checked.
    add_snapshot(pack, LATER_SNAPSHOT)
    case_by_id(pack, "widget-shell")["controls"].append(later_control())

    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["targets"] == [] and plan["controls"] == []
    assert any("no recorded passing mechanical check set for snapshot(s) widget-later" in note
               for note in notes)

    outcomes = mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    validation = case_by_id(pack, "widget-shell")["validation"]
    assert outcomes[0]["passed"] is True, "this snapshot's own check set still passes"
    assert validation["review_state"] == "human_approved" and validation["level"] == "L3"
    assert validation["checks_failed"] is True


def test_a_mechanically_checked_case_returns_to_draft_when_a_new_snapshot_is_unchecked(tmp_path):
    pack = make_pack()
    source = export(tmp_path)
    mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    assert case_by_id(pack, "widget-shell")["validation"]["review_state"] == "mechanically_checked"

    add_snapshot(pack, FIXED_SNAPSHOT)
    case_by_id(pack, "widget-shell")["controls"].append(fixed_control())
    mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)

    validation = case_by_id(pack, "widget-shell")["validation"]
    assert validation["review_state"] == "draft" and validation["level"] is None
    assert "checks_failed" not in validation, "code demotes its own state instead of flagging one"
    mechanical_checks(pack, "widget-fixed", source, FIXED_HASH, clock=CLOCK)
    assert case_by_id(pack, "widget-shell")["validation"]["review_state"] == "mechanically_checked"


def test_a_declared_path_whose_case_differs_from_the_export_is_missing(tmp_path):
    """Paths are compared against an exact listing, so this fails on any filesystem."""
    pack = make_pack()
    source = export(tmp_path)
    case_by_id(pack, "widget-shell")["target"]["accepted_locations"][0]["path"] = "src/App.py"

    outcomes = mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)

    assert outcomes[0]["passed"] is False
    details = {check["check"]: check["detail"] for check in outcomes[0]["checks"]}
    results = {check["check"]: check["result"] for check in outcomes[0]["checks"]}
    assert results["locations_exist_in_snapshot"] == "fail"
    assert details["locations_exist_in_snapshot"] == "missing: src/App.py"
    assert results["line_ranges_within_files"] == "pass", "a missing file has no range to exceed"
    assert case_by_id(pack, "widget-shell")["validation"]["review_state"] == "draft"


def test_the_contract_rejects_label_states_that_contradict_the_recorded_checks(tmp_path):
    pack = two_snapshot_pack()
    source = export(tmp_path)
    mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    mechanical_checks(pack, "widget-fixed", source, FIXED_HASH, clock=CLOCK)
    assert validate_document("case-pack", pack) is pack

    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["checks"] = [
        check for check in broken["cases"][0]["validation"]["checks"]
        if check["snapshot_id"] != "widget-fixed"]
    with pytest.raises(ContractError, match="missing or failed for: widget-fixed"):
        validate_document("case-pack", broken)

    broken = json.loads(json.dumps(pack))
    for check in broken["cases"][0]["validation"]["checks"]:
        if check["snapshot_id"] == "widget-fixed":
            check["result"] = "fail"
    with pytest.raises(ContractError, match="missing or failed for: widget-fixed"):
        validate_document("case-pack", broken)

    broken = json.loads(json.dumps(pack))
    for check in broken["cases"][0]["validation"]["checks"]:
        check.pop("snapshot_id")
    with pytest.raises(ContractError, match="missing or failed for: widget-abc, widget-fixed"):
        validate_document("case-pack", broken)

    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["level"] = "L2"
    with pytest.raises(ContractError, match="mechanically_checked is the L1 state"):
        validate_document("case-pack", broken)

    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["checks_failed"] = True
    with pytest.raises(ContractError, match="belongs only to a human_approved case"):
        validate_document("case-pack", broken)


def test_the_contract_rejects_a_reviewed_level_on_a_case_screened_out(tmp_path):
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L4",
                 note="build and tests reviewed", clock=CLOCK)

    for value in ("needs_evidence", "extended_regression", "exclude"):
        broken = json.loads(json.dumps(pack))
        broken["cases"][0]["disposition"] = {"value": value, "reason": "screened out after approval"}
        with pytest.raises(ContractError, match=f"L4 requires disposition validate, not {value}"):
            validate_document("case-pack", broken)


def test_a_refused_change_leaves_the_pack_exactly_as_it_was(tmp_path):
    """Every pack change is applied to a copy first, so a refusal writes nothing at all."""
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    before = dump_json(pack)

    with pytest.raises(ContractError):
        add_snapshot(pack, {**SNAPSHOT, "snapshot_id": "widget-two", "commit": "not-a-sha"})
    assert dump_json(pack) == before

    with pytest.raises(ContractError):
        add_case(pack, draft_case(
            "widget-range", snapshot_id="widget-abc", kind="path_traversal", description="d",
            represents=REPRESENTS, workload="conventional_application", component_role="application",
            aliases=[], evidence=[evidence("n", origin="research_note", kind="source_inspection",
                                           reference="src/app.py")],
            accepted_locations=[{"path": "src/app.py", "start_line": 9, "end_line": 2, "role": "sink"}]))
    assert dump_json(pack) == before

    # The role is refused by the contract rather than by an argument check, so the review has
    # already been appended to the copy when validation fails.
    with pytest.raises(ContractError):
        approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="peer", level="L1", note="",
                     clock=CLOCK)
    assert dump_json(pack) == before
    assert case_by_id(pack, "widget-shell")["validation"]["reviews"] == []

    with pytest.raises(ContractError, match="explicit name"):
        admit_case(pack, "widget-shell", decision="admitted", by="\u200b", reason="pilot", clock=CLOCK)
    assert dump_json(pack) == before


LEGACY = {
    "id": "SB-GO-RG-001", "caseType": "real_world_generic", "canonicalKind": "auth_bypass",
    "title": "skip regex on full URI", "description": "regex matched path plus query",
    "regions": [{"id": "R1", "path": "oauthproxy.go", "startLine": 582, "endLine": 590,
                 "label": "vulnerable", "capability": "authentication"}],
    "realWorld": {"repo": "oauth2-proxy/oauth2-proxy", "fixCommit": "9" * 40,
                  "disclosure": {"ghsaPublished": "2025-07-30", "fixCommitDate": "2025-07-29"}},
}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("regions", {"R1": {"path": "a.go"}}, "must be a list of region objects"),
        ("regions", [["oauthproxy.go", 1, 2]], "must be a JSON object"),
        ("regions", [{"id": "R1"}], "must name its path as a non-empty string"),
        ("regions", [{"id": "R1", "path": ""}], "must name its path as a non-empty string"),
        ("regions", [{"id": "R1", "path": 7}], "must name its path as a non-empty string"),
        ("regions", [{"path": "a.go", "startLine": 5}], "supplied together; got only startLine"),
        ("regions", [{"path": "a.go", "endLine": 5}], "supplied together; got only endLine"),
        ("regions", [{"path": "a.go", "startLine": True, "endLine": 5}], "integer line number"),
        ("regions", [{"path": "a.go", "startLine": "5", "endLine": 9}], "integer line number"),
        ("regions", [{"path": "a.go", "startLine": 0, "endLine": 9}], "integer line number"),
        ("regions", [{"path": "a.go", "startLine": 1, "endLine": 2.5}], "integer line number"),
        ("realWorld", "CVE-2025-54576", "realWorld must be a JSON object"),
        ("realWorld", {"disclosure": []}, "realWorld.disclosure must be a JSON object"),
    ],
)
def test_a_legacy_record_this_cannot_read_faithfully_is_refused(field, value, message):
    """A malformed legacy shape is refused, never guessed at or silently dropped."""
    legacy = {**LEGACY, field: value}
    with pytest.raises(ContractError, match=message):
        draft_case_from_legacy(legacy, case_id="legacy-case", snapshot_id="widget-abc",
                               legacy_path="cases/full/x/case.json", workload="conventional_application",
                               component_role="infrastructure", represents=REPRESENTS)


def test_a_legacy_record_without_regions_or_a_real_world_block_still_migrates():
    case = draft_case_from_legacy({"id": "SB-1", "title": "t", "description": "d"},
                                  case_id="legacy-bare", snapshot_id="widget-abc",
                                  legacy_path="cases/full/x/case.json",
                                  workload="conventional_application", component_role="application",
                                  represents=REPRESENTS)
    assert case["target"]["accepted_locations"] == []
    assert case["canonical_target"]["aliases"] == []
    assert case["disclosure"] == {"earliest_public_artifact": None, "cve_published": None,
                                  "ghsa_published": None, "fix_commit_date": None,
                                  "note": "Dates copied from the legacy record; earliest public artifact not yet established."}


def test_a_line_or_paragraph_separator_is_not_a_stated_name_or_reason(tmp_path):
    """U+2028 and U+2029 separate lines; a value made only of them states nothing."""
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    before = dump_json(pack)

    with pytest.raises(ContractError, match="explicit reviewer name"):
        approve_case(pack, "widget-shell", reviewer="\u2029\u2028", role="curator", level="L1", note="n",
                     clock=CLOCK)
    with pytest.raises(ContractError, match="non-blank reason"):
        set_disposition(pack, "widget-shell", "validate", "\u2028")
    with pytest.raises(ContractError, match="non-blank reason"):
        admit_case(pack, "widget-shell", decision="admitted", by="J. Curator", reason="\u2029",
                   clock=CLOCK)
    assert dump_json(pack) == before
    # A name carrying a separator alongside real characters is still a name.
    approve_case(pack, "widget-shell", reviewer="J.\u2028Curator", role="curator", level="L1", note="n",
                 clock=CLOCK)
    assert case_by_id(pack, "widget-shell")["validation"]["reviews"][-1]["reviewer"] == "J.\u2028Curator"


@pytest.mark.parametrize("tree_hash", ["", "sha256:" + "z" * 64, "sha256:" + "a" * 63, "a" * 64, None, 7],
                         ids=["empty", "not-hex", "too-short", "no-prefix", "none", "int"])
def test_mechanical_checks_refuse_a_tree_hash_that_is_not_a_sha256_digest(tmp_path, tree_hash):
    """The digest is recorded on the snapshot and every check set, so it is checked before any work."""
    pack = make_pack()
    before = dump_json(pack)

    with pytest.raises(ContractError, match="sha256:"):
        mechanical_checks(pack, "widget-abc", export(tmp_path), tree_hash, clock=CLOCK)

    assert dump_json(pack) == before
    assert case_by_id(pack, "widget-shell")["validation"]["checks"] == []


def test_a_check_set_the_contract_refuses_leaves_the_pack_exactly_as_it_was(tmp_path):
    """Checks are applied to a validated copy, so a refused pack is never half rewritten."""
    pack = make_pack()
    source = export(tmp_path)
    mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L3",
                 note="label established", clock=CLOCK)
    # Hand-edited into a state the contract refuses: the latest review rejected the case.
    case_by_id(pack, "widget-shell")["validation"]["reviews"].append(
        {"reviewer": "A. Djudicator", "role": "adjudicator", "decision": "reject", "level": "L3",
         "at": "2026-09-20T17:00:00+00:00", "note": "evidence withdrawn"})
    before = dump_json(pack)

    with pytest.raises(ContractError, match="latest recorded review rejected"):
        mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)

    assert dump_json(pack) == before


def test_the_contract_refuses_an_approval_whose_checks_are_missing_or_rejected(tmp_path):
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L3",
                 note="label established", clock=CLOCK)
    assert validate_document("case-pack", pack) is pack

    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["checks"] = []
    with pytest.raises(ContractError, match="human_approved requires a recorded passing check set"):
        validate_document("case-pack", broken)
    # The flag is what an approved case records when a check set failed; it is then consistent.
    broken["cases"][0]["validation"]["checks_failed"] = True
    assert validate_document("case-pack", broken) is broken

    broken = json.loads(json.dumps(pack))
    for check in broken["cases"][0]["validation"]["checks"]:
        check["result"] = "fail"
    with pytest.raises(ContractError, match="missing or failed for: widget-abc"):
        validate_document("case-pack", broken)

    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["reviews"].append(
        {"reviewer": "A. Djudicator", "role": "adjudicator", "decision": "reject", "level": "L3",
         "at": "2026-09-20T17:00:00+00:00", "note": "evidence withdrawn"})
    with pytest.raises(ContractError, match="latest recorded review rejected"):
        validate_document("case-pack", broken)
    # A later approving decision reinstates it, because only the latest review decides.
    broken["cases"][0]["validation"]["reviews"].append(
        {"reviewer": "A. Djudicator", "role": "adjudicator", "decision": "approve", "level": "L3",
         "at": "2026-09-20T18:00:00+00:00", "note": "evidence restored"})
    assert validate_document("case-pack", broken) is broken


def test_a_confirmed_snapshot_hash_check_requires_the_snapshot_to_carry_that_hash(tmp_path):
    """The check says the export matched; without the recorded hash nothing says which export."""
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    assert pack["snapshots"][0]["tree_hash"] == HASH

    broken = json.loads(json.dumps(pack))
    broken["snapshots"][0]["tree_hash"] = None
    with pytest.raises(ContractError, match="records a passing snapshot_hash_recorded check"):
        validate_document("case-pack", broken)

    # build_plan refuses the same pack rather than planning against an unbound check set.
    with pytest.raises(ContractError, match="records mechanical checks but carries no tree hash"):
        build_plan(broken, "widget-abc", HASH)


def test_a_snapshot_whose_hash_disagrees_keeps_its_recorded_hash_and_plans_nothing(tmp_path):
    """A failing hash check leaves the declared hash in place, so the pack stays consistent."""
    pack = make_pack()
    source = export(tmp_path)
    mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    other = "sha256:" + "c" * 64

    outcomes = mechanical_checks(pack, "widget-abc", source, other, clock=CLOCK)

    assert outcomes[0]["passed"] is False
    assert pack["snapshots"][0]["tree_hash"] == HASH
    assert validate_document("case-pack", pack) is pack
    with pytest.raises(ContractError, match="tree hash does not match the materialized input"):
        build_plan(pack, "widget-abc", other)
