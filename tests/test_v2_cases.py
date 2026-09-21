"""Case packs: drafts stay drafts, mechanical checks stop at L1, approval is explicit and covers
the labels it named, and plans degrade."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from scaneval.cases import (
    _approval_gap,
    accepted_paths_for_targets,
    add_case,
    add_snapshot,
    admit_case,
    approval_is_current,
    approve_case,
    build_plan,
    case_by_id,
    checked_tree_hash,
    draft_case,
    draft_case_from_legacy,
    dump_json,
    evidence,
    label_digest,
    latest_admission,
    latest_approving_review,
    latest_review,
    load_pack,
    mechanical_checks,
    new_pack,
    pack_sha256,
    pack_summary,
    record_review,
    save_pack,
    set_disposition,
)
from scaneval.contracts import (
    ContractError,
    admission_chain_digest,
    check_set_digest,
    effective_level,
    pack_anchor_digest,
    recorded_check_state,
    review_chain_digest,
    validate_document,
)


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


def safe_control(control_id: str = "C-widget-shell-safe") -> dict:
    """A capability-safe control on the vulnerable snapshot, the one already checked and approved."""
    return {
        "control_id": control_id, "snapshot_id": "widget-abc", "type": "capability_safe",
        "description": "The admin helper runs a fixed argument list.",
        "property": "No caller-supplied string reaches a shell at this call site.",
        "allowed_actors_inputs": "Operators on the host.",
        "assumptions": ["Default deployment."],
        "ruled_out_allegation": "Caller-controlled shell interpolation in the admin helper.",
        "locations": [{"path": "src/app.py", "start_line": 1, "end_line": 1, "role": "operation"}],
        "evidence_ids": ["fix"],
    }


def rebuild_check_set(validation: dict, snapshot_id: str) -> dict:
    """Restate the check set record over the checks as they now stand, as a forger must.

    The record says what the set decided and hashes itself together with its own checks, so a
    hand-edited set has to be rebuilt deliberately: editing or deleting a check alone leaves the
    record hashing to something that is no longer there.
    """
    checks = [check for check in validation["checks"] if check.get("snapshot_id") == snapshot_id]
    record = dict(validation["check_sets"][snapshot_id])
    record["result"] = "pass" if checks and all(c["result"] == "pass" for c in checks) else "fail"
    record["checks_sha256"] = check_set_digest(snapshot_id, record, checks)
    validation["check_sets"][snapshot_id] = record
    return record


def rechain_admissions(pack: dict) -> list[dict]:
    """Rebuild the admission chain and the pack anchor after a hand edit, as a forger must."""
    previous = None
    for admission in pack["admissions"]:
        admission.pop("chain_sha256", None)
        admission["chain_sha256"] = admission_chain_digest(previous, admission)
        previous = admission["chain_sha256"]
    reanchor(pack)
    return pack["admissions"]


def reanchor(pack: dict) -> dict:
    """Rebuild the pack anchor over the cases, histories, and admissions as they now stand.

    Hand-editing a record a planning decision reads costs this: the anchor names the case roster,
    where each review history ends, and where the admission history ends, so an edit that leaves
    one of them somewhere else has to be anchored again deliberately. That is what the anchor is
    for, and a test reproducing a forgery pays the same price a forger does.
    """
    pack["anchor_sha256"] = pack_anchor_digest(pack)
    return pack


def chain_review(pack: dict, validation: dict, entry: dict) -> dict:
    """Append one hand-written review to *validation*, chained as the write path chains it.

    A test that hand-edits a history has to rebuild the chain, the recorded end of it, and the pack
    anchor that names that end, which is the point of all three: an unchained entry is refused
    before anything reads its decision.
    """
    recorded = dict(entry)
    reviews = validation["reviews"]
    recorded["chain_sha256"] = review_chain_digest(
        reviews[-1]["chain_sha256"] if reviews else None, recorded)
    reviews.append(recorded)
    validation["reviews_sha256"] = recorded["chain_sha256"]
    reanchor(pack)
    return recorded


def rechain(pack: dict, validation: dict) -> list[dict]:
    """Rebuild the chain over a hand-edited history, which is what a forger would have to do."""
    previous = None
    for review in validation["reviews"]:
        review.pop("chain_sha256", None)
        review["chain_sha256"] = review_chain_digest(previous, review)
        previous = review["chain_sha256"]
    if previous is None:
        validation.pop("reviews_sha256", None)
    else:
        validation["reviews_sha256"] = previous
    reanchor(pack)
    return validation["reviews"]


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
    broken["admissions"].append({"case_id": "ghost", "target_id": "T-ghost", "decision": "admitted",
                                 "by": "x", "at": "t", "reason": "r"})
    with pytest.raises(ContractError, match="unknown case"):
        validate_document("case-pack", broken)
    # An admission is bound to the target it decided, so it cannot be recorded without one.
    broken = json.loads(json.dumps(pack))
    broken["admissions"].append({"case_id": "widget-shell", "decision": "admitted", "by": "x",
                                 "at": "t", "reason": "r"})
    with pytest.raises(ContractError, match="'target_id' is a required property"):
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
    # Changed deliberately: an approval alone used to reach a reviewed-scope plan. The pack says a
    # label becomes evidence through recorded review and admission, and only an explicit admitted
    # decision admits, so an approved case nobody has decided on is planned at the level its review
    # earned, in the draft-scope plan that says nobody has admitted it yet.
    assert plan["scope"] == "draft" and plan["targets"][0]["validation_level"] == "L3"
    assert pack["cases"][0]["validation"]["reviews"][-1]["reviewer"] == "second"
    admit_case(pack, "widget-shell", decision="admitted", by="second", reason="pilot", clock=CLOCK)
    assert pack["admissions"][0]["decision"] == "admitted"
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and plan["targets"][0]["validation_level"] == "L3"

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
    pack = new_pack("scaneval.public", "pilot", "x")
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

    # Changed deliberately: deleting the checks of a set used to read as a set that was never
    # recorded, so this asked for the missing-set message. The set is one record now, and the
    # record is still there naming checks that are not, which is the more specific complaint.
    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["checks"] = [
        check for check in broken["cases"][0]["validation"]["checks"]
        if check["snapshot_id"] != "widget-fixed"]
    with pytest.raises(ContractError, match="no recorded check carries that snapshot"):
        validate_document("case-pack", broken)

    # Dropping the record with them is the missing set, and that is what the state rule says.
    broken["cases"][0]["validation"]["check_sets"].pop("widget-fixed")
    with pytest.raises(ContractError, match="missing or failed for: widget-fixed"):
        validate_document("case-pack", broken)

    # Changed deliberately: flipping a recorded check used to be enough to restate the set. The
    # set record hashes itself together with its own checks, so an edited check no longer matches.
    broken = json.loads(json.dumps(pack))
    for check in broken["cases"][0]["validation"]["checks"]:
        if check["snapshot_id"] == "widget-fixed":
            check["result"] = "fail"
    with pytest.raises(ContractError, match="a check was deleted, unattributed, reordered, or edited"):
        validate_document("case-pack", broken)

    # Restating the set over the edited checks is what that costs, and then the set reads failed.
    rebuild_check_set(broken["cases"][0]["validation"], "widget-fixed")
    with pytest.raises(ContractError, match="missing or failed for: widget-fixed"):
        validate_document("case-pack", broken)

    # Changed deliberately: a check used to be able to leave its set by dropping the attribution,
    # which turned a failing set into a passing one. Every check names the set it belongs to.
    broken = json.loads(json.dumps(pack))
    for check in broken["cases"][0]["validation"]["checks"]:
        check.pop("snapshot_id")
    with pytest.raises(ContractError, match="'snapshot_id' is a required property"):
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
    chain_review(pack, case_by_id(pack, "widget-shell")["validation"],
                 {"reviewer": "A. Djudicator", "role": "adjudicator", "decision": "reject",
                  "level": "L3", "at": "2026-09-20T17:00:00+00:00", "note": "evidence withdrawn"})
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
    # The checks and the record that states what the set decided are one set, so both go here.
    broken["cases"][0]["validation"]["checks"] = []
    broken["cases"][0]["validation"].pop("check_sets")
    with pytest.raises(ContractError, match="human_approved requires a recorded passing check set"):
        validate_document("case-pack", broken)
    # The flag is what an approved case records when a check set failed; it is then consistent.
    broken["cases"][0]["validation"]["checks_failed"] = True
    assert validate_document("case-pack", broken) is broken
    # Keeping the record while dropping the checks it hashes claims a check set that is not in the
    # pack, so the record is refused rather than read as evidence that anything ran.
    orphaned = json.loads(json.dumps(broken))
    orphaned["cases"][0]["validation"]["check_sets"] = {
        "widget-abc": pack["cases"][0]["validation"]["check_sets"]["widget-abc"]}
    with pytest.raises(ContractError, match="no recorded check carries that snapshot"):
        validate_document("case-pack", orphaned)

    broken = json.loads(json.dumps(pack))
    for check in broken["cases"][0]["validation"]["checks"]:
        check["result"] = "fail"
    rebuild_check_set(broken["cases"][0]["validation"], "widget-abc")
    with pytest.raises(ContractError, match="missing or failed for: widget-abc"):
        validate_document("case-pack", broken)

    broken = json.loads(json.dumps(pack))
    chain_review(broken, broken["cases"][0]["validation"],
                 {"reviewer": "A. Djudicator", "role": "adjudicator", "decision": "reject",
                  "level": "L3", "at": "2026-09-20T17:00:00+00:00", "note": "evidence withdrawn"})
    with pytest.raises(ContractError, match="latest recorded review rejected"):
        validate_document("case-pack", broken)
    # A later approving decision reinstates it, because only the latest review decides. It carries
    # no digest of these labels, so the weaker rule applies and the case plans nothing.
    chain_review(broken, broken["cases"][0]["validation"],
                 {"reviewer": "A. Djudicator", "role": "adjudicator", "decision": "approve",
                  "level": "L3", "at": "2026-09-20T18:00:00+00:00", "note": "evidence restored"})
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


@pytest.mark.parametrize("alias", ["INTERNAL-1234", "SEC-REVIEW-2026-07", "incident/2026-04-11", "JIRA SEC 88"])
def test_a_private_pack_may_name_its_cases_by_internal_identifier(tmp_path, alias):
    """A CVE is neither required nor sufficient, so an internal id must not block L1."""
    pack = make_pack()
    case_by_id(pack, "widget-shell")["canonical_target"]["aliases"] = [alias]

    outcome = mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)[0]

    assert outcome["passed"] is True, outcome["checks"]
    assert outcome["review_state"] == "mechanically_checked" and outcome["level"] == "L1"


@pytest.mark.parametrize("alias,problem", [
    ("CVE-2026-1", "not a well formed"),
    ("GHSA-abc-def-ghi", "not a well formed"),
    ("cve_2026_0001", "not a well formed"),
    ("   ", "cannot be blank"),
])
def test_a_malformed_public_identifier_still_fails_the_check(tmp_path, alias, problem):
    pack = make_pack()
    case_by_id(pack, "widget-shell")["canonical_target"]["aliases"] = [alias]

    outcome = mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)[0]

    assert outcome["passed"] is False
    failed = [c for c in outcome["checks"] if c["check"] == "aliases_well_formed"]
    assert failed and failed[0]["result"] == "fail" and problem in failed[0]["detail"]


def test_a_legacy_fix_commit_without_an_advisory_is_not_a_public_disclosure():
    legacy = {"id": "SB-INT-001", "caseType": "internal", "canonicalKind": "auth_bypass", "title": "internal fix",
              "description": "found in review", "regions": [],
              "realWorld": {"repo": "acme/widget", "fixCommit": "d" * 40}}

    case = draft_case_from_legacy(legacy, case_id="internal-1", snapshot_id="widget-abc",
                                  legacy_path="cases/internal.json", workload="conventional_application",
                                  component_role="application", represents=REPRESENTS)

    fix = [e for e in case["evidence"] if e["evidence_id"] == "fix-commit"][0]
    assert fix["origin"] == "fix_without_advisory"
    assert "names no advisory" in fix["note"]
    assert case["canonical_target"]["aliases"] == []

    advised = draft_case_from_legacy({**legacy, "realWorld": {**legacy["realWorld"], "cve": "CVE-2025-54576"}},
                                     case_id="public-1", snapshot_id="widget-abc", legacy_path="cases/public.json",
                                     workload="conventional_application", component_role="application",
                                     represents=REPRESENTS)
    assert [e for e in advised["evidence"] if e["evidence_id"] == "fix-commit"][0]["origin"] == "public_advisory_and_maintainer_fix"


def approved_pack(tmp_path: Path) -> dict:
    """One checked case, screened as worth validating, approved at L3, and admitted.

    The admission is part of the fixture because a reviewed-scope plan needs all four: the case is
    evidence only once a named person has decided to admit it, and only an explicit ``admitted``
    decision says that.
    """
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L3",
                 note="label established", clock=CLOCK)
    admit_case(pack, "widget-shell", decision="admitted", by="J. Curator",
               reason="reviewed label, admitted to the evaluation slice", clock=CLOCK)
    return pack


def test_an_approval_records_the_digest_of_the_labels_it_covers(tmp_path):
    """The review names the content it read, so what it covers can be checked rather than assumed."""
    pack = approved_pack(tmp_path)
    case = case_by_id(pack, "widget-shell")

    review = latest_approving_review(case)
    assert review["labels_sha256"] == label_digest(pack, case)
    assert approval_is_current(pack, case) is True
    assert label_digest(pack, case).startswith("sha256:")
    # The digest covers the labels, not the record around them: evidence, disposition, notes, and
    # the recorded reviews and checks say where a label came from, not what it alleges.
    before = label_digest(pack, case)
    case["notes"].append("a curator's note")
    case["evidence"].append(evidence("second", origin="research_note", kind="source_inspection",
                                     reference="src/app.py"))
    assert label_digest(pack, case) == before
    assert approval_is_current(pack, case) is True
    # Writing a label field back with the value it already holds is not a change either.
    case["target"]["description"] = "cmd reaches subprocess with shell=True"
    assert label_digest(pack, case) == before and approval_is_current(pack, case) is True


def test_a_control_added_after_approval_cannot_ride_on_that_approval(tmp_path):
    """Reproduces the inherited approval: a new control is outside every review recorded so far."""
    pack = approved_pack(tmp_path)
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and [t["target_id"] for t in plan["targets"]] == ["T-widget-shell"]

    case_by_id(pack, "widget-shell")["controls"].append(safe_control())
    assert validate_document("case-pack", pack) is pack, "the pack is still a consistent record"

    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
    assert any("widget-shell: excluded because the labels changed after the review" in note
               for note in notes)
    validation = case_by_id(pack, "widget-shell")["validation"]
    assert validation["review_state"] == "human_approved" and validation["level"] == "L3", \
        "code never withdraws a human review"
    assert [review["reviewer"] for review in validation["reviews"]] == ["R. Eviewer"], \
        "a review is a historical fact and is not erased"
    assert approval_is_current(pack, case_by_id(pack, "widget-shell")) is False

    # A second review, of the labels as they now stand, is what plans the new control.
    approve_case(pack, "widget-shell", reviewer="S. Econd", role="independent_reviewer", level="L3",
                 note="the control was read too", clock=CLOCK)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []
    assert [(c["control_id"], c["validation_level"]) for c in plan["controls"]] == [
        ("C-widget-shell-safe", "L3")]


def test_removing_or_renaming_a_control_also_leaves_the_approval_behind(tmp_path):
    """Adding is not the only edit: dropping or renaming a control changes what was reviewed."""
    pack = approved_pack(tmp_path)
    case_by_id(pack, "widget-shell")["controls"].append(safe_control())
    approve_case(pack, "widget-shell", reviewer="S. Econd", role="independent_reviewer", level="L3",
                 note="the control was read too", clock=CLOCK)
    assert build_plan(pack, "widget-abc", HASH)[0]["scope"] == "reviewed"

    renamed = copy.deepcopy(pack)
    case_by_id(renamed, "widget-shell")["controls"][0]["control_id"] = "C-widget-shell-other"
    plan, notes = build_plan(renamed, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["controls"] == []
    assert any("the labels changed after the review" in note for note in notes)

    dropped = copy.deepcopy(pack)
    case_by_id(dropped, "widget-shell")["controls"] = []
    plan, notes = build_plan(dropped, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == []
    assert any("the labels changed after the review" in note for note in notes)


def test_reordering_controls_is_not_a_change_to_the_labels(tmp_path):
    """The digest reads the controls as a set keyed by id, so list order alone is not content."""
    pack = approved_pack(tmp_path)
    case_by_id(pack, "widget-shell")["controls"].extend(
        [safe_control(), safe_control("C-widget-shell-safe-2")])
    approve_case(pack, "widget-shell", reviewer="S. Econd", role="independent_reviewer", level="L3",
                 note="both controls were read", clock=CLOCK)
    before = label_digest(pack, case_by_id(pack, "widget-shell"))

    case_by_id(pack, "widget-shell")["controls"].reverse()

    assert label_digest(pack, case_by_id(pack, "widget-shell")) == before
    assert approval_is_current(pack, case_by_id(pack, "widget-shell")) is True
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []
    assert {c["control_id"] for c in plan["controls"]} == {"C-widget-shell-safe", "C-widget-shell-safe-2"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "path_traversal"),
        ("description", "a mechanism nobody reviewed"),
        ("affected_input_or_authority", "the cmd parameter of POST /run"),
        ("accepted_locations", [{"path": "src/app.py", "start_line": 2, "end_line": 2, "role": "sink"}]),
        ("assumptions", ["The admin console is exposed to the internet."]),
        ("matching_rules", ["Accept any claim naming src/app.py."]),
    ],
    ids=["kind", "description", "affected-input", "accepted-locations", "assumptions",
         "matching-rules"],
)
def test_editing_an_approved_target_leaves_it_outside_the_recorded_review(tmp_path, field, value):
    """Reproduces the edited target: every label field the reviewer read is bound to the approval."""
    pack = approved_pack(tmp_path)

    case_by_id(pack, "widget-shell")["target"][field] = value

    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == []
    assert any("the labels changed after the review" in note for note in notes)
    assert approval_is_current(pack, case_by_id(pack, "widget-shell")) is False


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("represents",), "This case tests a path join under a default deployment, and adds a traversal target."),
        (("workload",), "agentic_application"),
        (("component_role",), "library_sdk"),
        (("canonical_target", "kind"), "path_traversal"),
        (("canonical_target", "variant_family"), "widget-other-family"),
        (("canonical_target", "aliases"), ["CVE-2026-0001", "CVE-2026-0002"]),
        (("coverage_signature", "guard_failure"), "no quoting anywhere on this path"),
    ],
    ids=["represents", "workload", "component-role", "canonical-kind", "variant-family",
         "aliases", "coverage-signature"],
)
def test_editing_an_approved_case_label_field_leaves_it_outside_the_recorded_review(tmp_path, path, value):
    """A reviewer approves what the case claims to be, so the case-level label fields bind too."""
    pack = approved_pack(tmp_path)
    field = case_by_id(pack, "widget-shell")
    for key in path[:-1]:
        field = field[key]
    field[path[-1]] = value

    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == []
    assert any("the labels changed after the review" in note for note in notes)
    assert approval_is_current(pack, case_by_id(pack, "widget-shell")) is False


def test_reordering_aliases_is_not_a_change_to_the_labels(tmp_path):
    """Aliases name the same case in any order, so the digest reads them as a set, as it does controls."""
    pack = approved_pack(tmp_path)
    before = label_digest(pack, case_by_id(pack, "widget-shell"))

    case_by_id(pack, "widget-shell")["canonical_target"]["aliases"].reverse()

    assert label_digest(pack, case_by_id(pack, "widget-shell")) == before
    assert approval_is_current(pack, case_by_id(pack, "widget-shell")) is True
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []


def test_a_pack_whose_labels_changed_after_approval_is_refused_a_reviewed_scope_plan(tmp_path):
    """The edited pack still loads, because the review is a record; it just plans nothing reviewed."""
    pack = approved_pack(tmp_path)
    case_by_id(pack, "widget-shell")["target"]["description"] = "a mechanism nobody reviewed"
    path = tmp_path / "pack.json"
    save_pack(path, pack)
    loaded = load_pack(path)

    plan, notes = build_plan(loaded, "widget-abc", HASH)

    assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
    assert any("the labels changed after the review" in note for note in notes)
    assert case_by_id(loaded, "widget-shell")["validation"]["reviews"][-1]["level"] == "L3"
    # Restoring exactly what was reviewed brings the approval back: the digest reads content,
    # not a sequence of edits.
    case_by_id(loaded, "widget-shell")["target"]["description"] = "cmd reaches subprocess with shell=True"
    plan, notes = build_plan(loaded, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []


def test_an_approval_recorded_before_digests_covers_no_current_labels(tmp_path):
    """A review that never named the content it read cannot be shown to cover these labels."""
    pack = approved_pack(tmp_path)
    document = json.loads(json.dumps(pack))
    for review in document["cases"][0]["validation"]["reviews"]:
        del review["labels_sha256"]
    rechain(document, document["cases"][0]["validation"])

    assert validate_document("case-pack", document) is document, \
        "a pack whose reviews never named their content still loads once its chain is consistent"

    plan, notes = build_plan(document, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == []
    assert any("does not say which label content it covered" in note for note in notes)
    assert approval_is_current(document, document["cases"][0]) is False


PILOT_PACK = Path(__file__).resolve().parents[1] / "corpus" / "pilot" / "pack.json"


@pytest.mark.skipif(not PILOT_PACK.is_file(), reason="no pilot pack in this checkout")
def test_the_shipped_pilot_pack_predates_the_check_set_record_and_is_refused_until_rechecked():
    """Changed deliberately: this used to assert that the shipped pilot pack still loads and plans.

    It recorded its mechanical checks as an array of attributed results, before a check set was one
    record, and that array is exactly the shape the blocker this round closes was written against:
    a set reconstituted by membership, where deleting or unattributing a failing check turns a
    failed set into a passing one. Reading such a pack as checked is the tolerance that leaves the
    hole open, so it is refused, naming the record that is missing. Re-running ``corpus validate``
    against the same exports rewrites the pack with one anchored record per set and an anchor over
    its roster, and the checks it records are the checks that ran; nothing here rewrites it,
    because a recorded check is evidence of what ran and every plan names its pack by content hash.
    When the pilot pack is re-recorded against its exports, this is the test to update: it should
    then assert that the pack loads and plans again, which is what it asserted before this round.
    """
    with pytest.raises(ContractError, match="validation.check_sets records no check set for it"):
        load_pack(PILOT_PACK)

    document = json.loads(PILOT_PACK.read_text(encoding="utf-8"))
    assert all(case["validation"]["review_state"] != "human_approved" for case in document["cases"]), \
        "the pilot pack is draft evidence, so no recorded approval is lost by re-running its checks"
    assert "anchor_sha256" not in document


def test_the_contract_refuses_a_level_no_recorded_approval_carries(tmp_path):
    """Loading an edited pack must enforce the level the CLI enforces at approval time."""
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="C. Urator", role="curator", level="L2",
                 note="structure reviewed", clock=CLOCK)
    assert validate_document("case-pack", pack) is pack

    for claimed in ("L3", "L4"):
        broken = json.loads(json.dumps(pack))
        broken["cases"][0]["validation"]["level"] = claimed
        with pytest.raises(ContractError,
                           match=f"requires an approving review recorded at {claimed} or higher"):
            validate_document("case-pack", broken)

    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L3",
                 note="label established", clock=CLOCK)
    raised = json.loads(json.dumps(pack))
    raised["cases"][0]["validation"]["level"] = "L4"
    with pytest.raises(ContractError, match="requires an approving review recorded at L4 or higher"):
        validate_document("case-pack", raised)

    # Changed deliberately: this assertion used to read that levels are ordered, so an L3 approval
    # carries a claimed L2 and the pack loads. It no longer does. The covering review is the only
    # source of the level, so every gate reads L3 from that review whatever the cached field says,
    # and a field claiming L2 is a second record of one fact that contradicts the first. Ordering
    # still holds where it means something, in level_gap, which asks what a review can earn.
    lowered = json.loads(json.dumps(pack))
    lowered["cases"][0]["validation"]["level"] = "L2"
    with pytest.raises(ContractError, match="validation.level records L2, but the review covering "
                                            "these labels is recorded at L3"):
        validate_document("case-pack", lowered)
    plan, notes = build_plan(lowered, "widget-abc", HASH)
    assert plan["targets"] == [] and plan["scope"] == "draft"
    assert any("the recorded level is a cached copy" in note for note in notes)


@pytest.mark.parametrize("role", ["curator", "adjudicator"])
def test_the_contract_refuses_a_reviewed_level_no_independent_reviewer_approved(tmp_path, role):
    """L3 and L4 rest on an independent review, so a hand-edited role cannot supply one."""
    pack = approved_pack(tmp_path)

    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["reviews"][0]["role"] = role
    rechain(broken, broken["cases"][0]["validation"])

    with pytest.raises(ContractError, match="requires an approving review at L3 or higher by an "
                                            "independent_reviewer"):
        validate_document("case-pack", broken)


def test_a_rejecting_review_does_not_carry_a_level(tmp_path):
    """Only an approving review carries a level; a rejection records the opposite decision."""
    pack = approved_pack(tmp_path)

    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["reviews"][0]["decision"] = "unresolved"
    rechain(broken, broken["cases"][0]["validation"])

    with pytest.raises(ContractError, match="requires at least one recorded approving review"):
        validate_document("case-pack", broken)


def test_editing_a_snapshot_tree_hash_cannot_retarget_a_standing_approval(tmp_path):
    """Reproduces the retargeted approval: the checks ran against one tree, the snapshot names another."""
    pack = approved_pack(tmp_path)
    other = "sha256:" + "c" * 64
    assert checked_tree_hash(case_by_id(pack, "widget-shell"), "widget-abc") == HASH

    pack["snapshots"][0]["tree_hash"] = other
    # Changed deliberately: this assertion used to read that the edited pack was still a
    # consistent record. It is not. The passing check says the export digest agreed with the
    # declared hash, and the snapshot now declares another, so the pack contradicts itself and is
    # refused at load. Planning below runs on the pack in memory, which never went through a load.
    with pytest.raises(ContractError, match="the checks ran against an export the snapshot no "
                                            "longer names"):
        validate_document("case-pack", pack)

    plan, notes = build_plan(pack, "widget-abc", other)
    assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
    assert any("widget-shell: excluded because the recorded checks for snapshot(s) widget-abc ran "
               "against a different tree" in note for note in notes)
    validation = case_by_id(pack, "widget-shell")["validation"]
    assert validation["review_state"] == "human_approved" and validation["level"] == "L3", \
        "code never withdraws a human review"

    # Re-running the checks against the tree the snapshot now names is what plans it again.
    pack["snapshots"][0]["tree_hash"] = HASH
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []


def test_a_check_set_is_one_record_so_its_export_cannot_be_dropped_out_from_under_it(tmp_path):
    """Changed deliberately: a check set could once be recorded bound to no export at all.

    The record of which tree a set ran against used to be a separate mapping beside the checks,
    so deleting it, and the passing hash check with it, left five passing checks that named no
    export; the plan excluded the case on that. The export is now part of the one record that is
    the check set, and the record requires it, so there is no set to speak of without one: what
    remains after dropping it is a case with no recorded check set for the snapshot, which is what
    the pack and the plan both say.
    """
    pack = approved_pack(tmp_path)
    document = json.loads(json.dumps(pack))
    validation = document["cases"][0]["validation"]
    del validation["check_sets"]["widget-abc"]
    validation["checks"] = [check for check in validation["checks"]
                            if check["snapshot_id"] != "widget-abc"]
    with pytest.raises(ContractError, match="human_approved requires a recorded passing check set"):
        validate_document("case-pack", document)
    validation["checks_failed"] = True
    assert validate_document("case-pack", document) is document

    plan, notes = build_plan(document, "widget-abc", HASH)

    assert plan["scope"] == "draft" and plan["targets"] == []
    assert any("a mechanical check set failed after approval" in note for note in notes)
    assert checked_tree_hash(document["cases"][0], "widget-abc") is None


def test_a_check_set_recorded_before_the_anchor_is_not_a_recorded_check_set(tmp_path):
    """Changed deliberately: a set recorded before the anchor used to be read from its detail.

    An older pack kept the export in the detail of its passing hash check and nowhere else, and
    this module read it there rather than rewriting it. That tolerance is the hole the blocker this
    round closes: a set read out of the checks that carry a snapshot id is a set a deletion can
    restate. A set with no record is no set, the case is unchecked for that snapshot, and the
    remedy is re-running the checks, which is what writes the record.
    """
    pack = approved_pack(tmp_path)
    document = json.loads(json.dumps(pack))
    del document["cases"][0]["validation"]["check_sets"]
    with pytest.raises(ContractError, match="validation.check_sets records no check set for it"):
        validate_document("case-pack", document)

    assert checked_tree_hash(document["cases"][0], "widget-abc") == HASH, \
        "the detail still says which export ran; what it cannot say is that a set was recorded"
    plan, notes = build_plan(document, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == []
    assert any("no recorded passing mechanical check set" in note for note in notes)


def test_a_trailing_unresolved_review_is_the_operative_one_and_stops_planning(tmp_path):
    """Reopening the question withdraws the case from planning; the approval stays recorded."""
    pack = approved_pack(tmp_path)
    assert build_plan(pack, "widget-abc", HASH)[0]["scope"] == "reviewed"

    chain_review(pack, case_by_id(pack, "widget-shell")["validation"],
                 {"reviewer": "A. Djudicator", "role": "adjudicator", "decision": "unresolved",
                  "level": "L3", "at": "2026-09-20T18:00:00+00:00",
                  "note": "reopened: the deployment assumption is unclear"})
    assert validate_document("case-pack", pack) is pack, "the reopening is a record, not a contradiction"

    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
    assert any("the latest recorded review reopened the question" in note for note in notes)
    validation = case_by_id(pack, "widget-shell")["validation"]
    assert validation["review_state"] == "human_approved" and validation["level"] == "L3"
    assert [review["decision"] for review in validation["reviews"]] == ["approve", "unresolved"]
    assert latest_review(case_by_id(pack, "widget-shell"))["decision"] == "unresolved"
    assert latest_approving_review(case_by_id(pack, "widget-shell"))["reviewer"] == "R. Eviewer", \
        "the approval stays findable in the history it belongs to"
    assert approval_is_current(pack, case_by_id(pack, "widget-shell")) is False

    # A review of the labels as they stand is what settles the question and plans the case again.
    approve_case(pack, "widget-shell", reviewer="S. Econd", role="independent_reviewer", level="L3",
                 note="assumption settled", clock=CLOCK)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []


def test_a_trailing_rejecting_review_is_also_the_operative_one(tmp_path):
    """The contract refuses this pack at load; planning refuses it too, on the pack in memory."""
    pack = approved_pack(tmp_path)
    chain_review(pack, case_by_id(pack, "widget-shell")["validation"],
                 {"reviewer": "A. Djudicator", "role": "adjudicator", "decision": "reject",
                  "level": "L3", "at": "2026-09-20T18:00:00+00:00", "note": "evidence withdrawn"})

    with pytest.raises(ContractError, match="latest recorded review rejected"):
        validate_document("case-pack", pack)

    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == []
    assert any("the latest recorded review rejected this case" in note for note in notes)
    assert approval_is_current(pack, case_by_id(pack, "widget-shell")) is False


def test_a_lesser_approval_of_an_edit_cannot_launder_an_older_independent_level(tmp_path):
    """Reproduces approval laundering: the review covering the edit is the one that must earn L3.

    An independent reviewer approves the case at L3, a control is added afterwards, and a curator
    approves the labels as they now stand at L2. The L3 approval covers what the case used to say,
    so nothing that read the control was recorded at L3 and no L3 plan may carry it.
    """
    pack = approved_pack(tmp_path)
    case_by_id(pack, "widget-shell")["controls"].append(safe_control())
    approve_case(pack, "widget-shell", reviewer="C. Urator", role="curator", level="L2",
                 note="structure re-read; the mechanism was not", clock=CLOCK)
    validation = case_by_id(pack, "widget-shell")["validation"]
    assert validation["level"] == "L2"
    assert [(r["role"], r["level"]) for r in validation["reviews"]] == [
        ("independent_reviewer", "L3"), ("curator", "L2")]

    validation["level"] = "L3"

    with pytest.raises(ContractError, match="the review covering these labels is recorded at L2; "
                                            "L3 requires an approving review recorded at L3 or higher"):
        validate_document("case-pack", pack)
    assert approval_is_current(pack, case_by_id(pack, "widget-shell")) is False
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
    assert any("L3 requires an approving review recorded at L3 or higher" in note for note in notes)

    # The honest record of the same history loads and plans the edit at the level that read it.
    case_by_id(pack, "widget-shell")["validation"]["level"] = "L2"
    assert validate_document("case-pack", pack) is pack
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and notes == []
    assert [target["validation_level"] for target in plan["targets"]] == ["L2"]
    assert [control["validation_level"] for control in plan["controls"]] == ["L2"]

    # An independent reviewer reading the labels as they stand is what reaches a reviewed plan.
    approve_case(pack, "widget-shell", reviewer="S. Econd", role="independent_reviewer", level="L3",
                 note="the control was read too", clock=CLOCK)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []
    assert [control["validation_level"] for control in plan["controls"]] == ["L3"]


def test_a_plan_reads_its_level_from_the_review_that_covers_the_labels(tmp_path):
    """The level a plan claims comes from the covering review, and the stored field only repeats it.

    Changed deliberately: this test used to raise the covering review to L4, leave
    ``validation.level`` at L3, and assert that the pack loaded and the plan claimed L4. That
    disagreement is the defect this round closes, because a gate measuring the review against the
    stored claim asks a question no decision depends on. The plan still reads the review; the
    stored field is now a cached copy of it that the contract refuses when it says anything else.
    """
    pack = approved_pack(tmp_path)
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer",
                 level="L4", note="build and tests read", clock=CLOCK)
    case = case_by_id(pack, "widget-shell")
    assert effective_level(pack, case) == "L4" and case["validation"]["level"] == "L4"

    plan, notes = build_plan(pack, "widget-abc", HASH)

    assert notes == [] and plan["scope"] == "reviewed"
    assert [target["validation_level"] for target in plan["targets"]] == ["L4"]

    stale = copy.deepcopy(pack)
    case_by_id(stale, "widget-shell")["validation"]["level"] = "L3"
    with pytest.raises(ContractError, match="the recorded level is a cached copy of that review"):
        validate_document("case-pack", stale)
    plan, notes = build_plan(stale, "widget-abc", HASH)
    assert plan["targets"] == [] and plan["scope"] == "draft"
    assert effective_level(stale, case_by_id(stale, "widget-shell")) is None


def test_a_two_field_tree_edit_contradicts_the_third_record_of_the_export(tmp_path):
    """Reproduces the retargeted export: three records name the tree the checks read, and they agree.

    Editing the snapshot's declared hash and the check set's recorded export together used to point
    a standing approval at an export the checks never ran against, because nothing compared either
    with the digest the passing ``snapshot_hash_recorded`` check already carried. The set record
    hashes its own fields now, so restating its export is the deliberate rebuild a forger has to
    make; the third record still contradicts it.
    """
    pack = approved_pack(tmp_path)
    other = "sha256:" + "c" * 64
    case = case_by_id(pack, "widget-shell")
    assert case["validation"]["check_sets"]["widget-abc"]["tree_hash"] == HASH
    assert [check["detail"] for check in case["validation"]["checks"]
            if check["check"] == "snapshot_hash_recorded"] == [HASH]

    pack["snapshots"][0]["tree_hash"] = other
    case["validation"]["check_sets"]["widget-abc"]["tree_hash"] = other
    rebuild_check_set(case["validation"], "widget-abc")

    with pytest.raises(ContractError, match="the checks ran against an export the snapshot no "
                                            "longer names"):
        validate_document("case-pack", pack)
    assert checked_tree_hash(case_by_id(pack, "widget-shell"), "widget-abc") is None
    plan, notes = build_plan(pack, "widget-abc", other)
    assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
    assert any("the records of which tree the checks for snapshot(s) widget-abc ran against "
               "disagree with each other" in note for note in notes)

    # Editing the entry alone is the same contradiction seen from the other side.
    pack["snapshots"][0]["tree_hash"] = HASH
    with pytest.raises(ContractError, match="but that check set's passing snapshot_hash_recorded "
                                            "check records"):
        validate_document("case-pack", pack)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["targets"] == []
    assert any("disagree with each other" in note for note in notes)

    # The records agreeing again is what plans the case, and they agree on one export only.
    validation = case_by_id(pack, "widget-shell")["validation"]
    validation["check_sets"]["widget-abc"]["tree_hash"] = HASH
    rebuild_check_set(validation, "widget-abc")
    assert validate_document("case-pack", pack) is pack
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []


def two_case_pack(tmp_path: Path) -> dict:
    """Two mechanically checked cases on one snapshot, each with its own target."""
    pack = make_pack()
    add_case(pack, draft_case(
        "widget-path", snapshot_id="widget-abc", kind="path_traversal", description="join of a user path",
        represents=REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[evidence("note", origin="research_note", kind="source_inspection", reference="src/app.py")],
        accepted_locations=[{"path": "src/app.py", "start_line": 1, "end_line": 1, "role": "sink"}],
    ))
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    return pack


def test_renaming_two_cases_cannot_swap_a_rejected_admission_onto_another(tmp_path):
    """Reproduces the swapped admission: a decision is bound to the target it named, not to a name.

    Case identity stays outside :func:`label_digest`, because an identifier says where a label came
    from rather than what it alleges. The admission is bound to content instead: it records the
    ``target_id`` it decided, which the digest covers, planning routes decisions by that binding,
    and a pack whose admission no longer names the target of the case it names is refused. What
    this protects is the named human decision: a rejection cannot be moved onto content nobody
    rejected, and the content that was rejected cannot be admitted, by renaming two cases.
    """
    pack = two_case_pack(tmp_path)
    admit_case(pack, "widget-shell", decision="rejected", by="J. Curator",
               reason="the mechanism duplicates an admitted target", clock=CLOCK)
    assert pack["admissions"][0]["target_id"] == "T-widget-shell"
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert [target["target_id"] for target in plan["targets"]] == ["T-widget-path"]

    case_by_id(pack, "widget-shell")["case_id"] = "widget-held"
    case_by_id(pack, "widget-path")["case_id"] = "widget-shell"
    case_by_id(pack, "widget-held")["case_id"] = "widget-path"
    # The anchor names the case roster, so a rename is anchored again before anything reads it:
    # what this test is about is what the swap does to a decision, not what it costs to attempt.
    reanchor(pack)

    with pytest.raises(ContractError, match="the decision no longer resolves to the content it named"):
        validate_document("case-pack", pack)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert [target["target_id"] for target in plan["targets"]] == ["T-widget-path"], \
        "the rejection stays on the content it named, whatever that case is now called"
    assert any("widget-path: excluded by the latest admission decision (rejected by J. Curator" in note
               for note in notes)
    assert latest_admission(pack, "widget-path")["decision"] == "rejected"
    assert latest_admission(pack, "widget-shell") is None


def test_renaming_one_case_keeps_its_decision_and_names_what_the_pack_must_say(tmp_path):
    """A rename is not a swap: the decision follows the target, and the record has to be tidied."""
    pack = two_case_pack(tmp_path)
    admit_case(pack, "widget-shell", decision="rejected", by="J. Curator",
               reason="the mechanism duplicates an admitted target", clock=CLOCK)

    case_by_id(pack, "widget-shell")["case_id"] = "widget-shell-renamed"
    reanchor(pack)

    with pytest.raises(ContractError, match="unknown case widget-shell"):
        validate_document("case-pack", pack)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert [target["target_id"] for target in plan["targets"]] == ["T-widget-path"]
    assert any("widget-shell-renamed: excluded by the latest admission decision" in note
               for note in notes)

    # Tidying the record is a deliberate edit of a recorded decision, so it costs rebuilding the
    # chain that binds the decisions to each other and the anchor that says where they end.
    pack["admissions"][0]["case_id"] = "widget-shell-renamed"
    rechain_admissions(pack)
    assert validate_document("case-pack", pack) is pack


def test_a_curator_review_cannot_reach_a_reviewed_plan_by_recording_a_lower_level(tmp_path):
    """Reproduces the unmeasured review: the level a plan reads is the one every gate must measure.

    The covering review is recorded at L4 by a curator, and the case records L2 beside it. Every
    gate used to measure that review against the L2 claim, which an L4 review clears on rank and
    which never asks about the role, while the plan read the level from the review itself: the case
    reached a reviewed-scope plan at L4 with no independent reviewer anywhere in its history, and
    with a screening decision that never said it was worth validating.
    """
    pack = approved_pack(tmp_path)
    case = case_by_id(pack, "widget-shell")
    case["validation"]["reviews"][-1].update({"level": "L4", "role": "curator"})
    rechain(pack, case["validation"])
    case["validation"]["level"] = "L2"
    case["disposition"] = {"value": "needs_evidence", "reason": "screened back after approval"}

    with pytest.raises(ContractError, match="carries the role curator; L4 requires an approving "
                                            "review at L4 or higher by an independent_reviewer"):
        validate_document("case-pack", pack)

    assert approval_is_current(pack, case_by_id(pack, "widget-shell")) is False
    assert effective_level(pack, case_by_id(pack, "widget-shell")) is None
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
    assert any("carries the role curator" in note for note in notes)

    # The same hole with a role the level does support: the claim still may not disagree with the
    # review, because the review is what the plan reads.
    honest = copy.deepcopy(pack)
    case_by_id(honest, "widget-shell")["validation"]["reviews"][-1]["role"] = "independent_reviewer"
    rechain(honest, case_by_id(honest, "widget-shell")["validation"])
    with pytest.raises(ContractError, match="the recorded level is a cached copy of that review"):
        validate_document("case-pack", honest)
    assert effective_level(honest, case_by_id(honest, "widget-shell")) is None

    # Recording what actually happened loads and plans at the level the review carries, and the
    # screening decision is measured against that level rather than against the cached claim.
    case_by_id(honest, "widget-shell")["validation"]["level"] = "L4"
    with pytest.raises(ContractError, match="L4 requires disposition validate, not needs_evidence"):
        validate_document("case-pack", honest)
    set_disposition(honest, "widget-shell", "validate", "evidence reviewed after all")
    assert validate_document("case-pack", honest) is honest
    plan, notes = build_plan(honest, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []
    assert [target["validation_level"] for target in plan["targets"]] == ["L4"]


def test_repinning_a_snapshot_costs_the_approval_that_was_recorded_against_it(tmp_path):
    """Reproduces the retargeted approval: a review covers the bytes it read, not a snapshot name.

    The digest projected the snapshot's name and nothing else, so repinning that snapshot to
    another commit, or re-running the checks against another export and recording it everywhere the
    three tree records live, left a standing L3 approval pointing at bytes nobody reviewed. The
    checks passed, the three records agreed, and the case planned at L3.
    """
    pack = approved_pack(tmp_path)
    source = tmp_path / "source"
    assert build_plan(pack, "widget-abc", HASH)[0]["scope"] == "reviewed"

    pack["snapshots"][0]["commit"] = "b" * 40
    assert validate_document("case-pack", pack) is pack, "the pack is still a truthful record"
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
    assert any("widget-shell: excluded because the labels changed after the review" in note
               for note in notes)

    # Restoring the pin restores the approval: the digest reads content, not a sequence of edits.
    pack["snapshots"][0]["commit"] = "a" * 40
    assert build_plan(pack, "widget-abc", HASH)[0]["scope"] == "reviewed"

    # The same case from the export side. All three records of which tree the checks read are
    # brought into agreement on a new one, so nothing in the check records complains, and the
    # approval is gone all the same.
    other = "sha256:" + "c" * 64
    pack["snapshots"][0]["tree_hash"] = other
    mechanical_checks(pack, "widget-abc", source, other, clock=CLOCK)
    validation = case_by_id(pack, "widget-shell")["validation"]
    assert "checks_failed" not in validation, "the checks themselves passed against that export"
    assert checked_tree_hash(case_by_id(pack, "widget-shell"), "widget-abc") == other
    assert validate_document("case-pack", pack) is pack

    plan, notes = build_plan(pack, "widget-abc", other)
    assert plan["scope"] == "draft" and plan["targets"] == []
    assert any("widget-shell: excluded because the labels changed after the review" in note
               for note in notes)
    assert validation["review_state"] == "human_approved" and validation["level"] == "L3", \
        "code never withdraws a human review"

    # Reviewing the labels as they now stand, against that export, is what plans it again.
    approve_case(pack, "widget-shell", reviewer="S. Econd", role="independent_reviewer", level="L3",
                 note="re-read against the new export", clock=CLOCK)
    plan, notes = build_plan(pack, "widget-abc", other)
    assert plan["scope"] == "reviewed" and notes == []


def test_deleting_the_review_that_withdrew_an_approval_cannot_pass_unnoticed(tmp_path):
    """Reproduces the restored approval: an unchained array loses its last entry without a trace.

    An adjudicator reopens the question, which withdraws the case from planning while leaving the
    approval recorded. Deleting that one entry used to restore a reviewed-scope plan, because
    nothing bound the reviews to each other or said where the history ended.
    """
    pack = approved_pack(tmp_path)
    validation = case_by_id(pack, "widget-shell")["validation"]
    chain_review(pack, validation, {"reviewer": "A. Djudicator", "role": "adjudicator",
                                    "decision": "unresolved", "level": "L3",
                                    "at": "2026-09-20T18:00:00+00:00", "note": "reopened"})
    assert validate_document("case-pack", pack) is pack
    assert build_plan(pack, "widget-abc", HASH)[0]["scope"] == "draft"

    withdrawn = copy.deepcopy(pack)
    del case_by_id(withdrawn, "widget-shell")["validation"]["reviews"][-1]

    with pytest.raises(ContractError, match="a review was deleted from the end of it"):
        validate_document("case-pack", withdrawn)

    # Deleting from the middle is what the chain itself catches.
    reopened = copy.deepcopy(pack)
    approve_case(reopened, "widget-shell", reviewer="S. Econd", role="independent_reviewer",
                 level="L3", note="assumption settled", clock=CLOCK)
    assert build_plan(reopened, "widget-abc", HASH)[0]["scope"] == "reviewed"
    middle = copy.deepcopy(reopened)
    del case_by_id(middle, "widget-shell")["validation"]["reviews"][1]
    with pytest.raises(ContractError, match="does not chain to the review before it"):
        validate_document("case-pack", middle)

    # Editing a recorded review is the same refusal, and so is dropping the chain from one.
    edited = copy.deepcopy(reopened)
    case_by_id(edited, "widget-shell")["validation"]["reviews"][1]["decision"] = "approve"
    with pytest.raises(ContractError, match="does not chain to the review before it"):
        validate_document("case-pack", edited)
    unchained = copy.deepcopy(reopened)
    del case_by_id(unchained, "widget-shell")["validation"]["reviews"][1]["chain_sha256"]
    with pytest.raises(ContractError, match="records no chain_sha256"):
        validate_document("case-pack", unchained)

    # Rebuilding the chain and the head is what a deletion costs, and it is a deliberate act: the
    # pack loads again, and the history it now states is one the person who edited it wrote.
    rebuilt = copy.deepcopy(withdrawn)
    rechain(rebuilt, case_by_id(rebuilt, "widget-shell")["validation"])
    assert validate_document("case-pack", rebuilt) is rebuilt
    assert build_plan(rebuilt, "widget-abc", HASH)[0]["scope"] == "reviewed"


def test_the_three_reproductions_are_refused_end_to_end(tmp_path):
    """Walks the reviewer's three routes on one saved pack, from disk and through planning.

    Each route ends at a pack that loads and plans an L3 or L4 case nobody reviewed as it stands.
    All three are refused at load and left out of the plan, and the honest record of each still
    loads: what is refused is the disagreement, not the history.
    """
    pack = approved_pack(tmp_path)
    path = tmp_path / "pack.json"
    save_pack(path, pack)
    assert build_plan(load_pack(path), "widget-abc", HASH)[0]["scope"] == "reviewed"

    def refuse(mutate, message: str, planned_hash: str = HASH) -> tuple[dict, list[str]]:
        """Apply *mutate* to the saved pack, and require both the load and the plan to refuse.

        The edited document is written as bytes and read back, so the refusal is the one a pack
        arriving from disk meets. Planning then runs on the document in memory, which never went
        through a load, because a gate that only fires at load is a gate a caller can walk past.
        """
        document = load_pack(path)
        mutate(document)
        edited = tmp_path / "edited.json"
        edited.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        with pytest.raises(ContractError, match=message):
            load_pack(edited)
        plan, notes = build_plan(document, "widget-abc", planned_hash)
        assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
        assert approval_is_current(document, case_by_id(document, "widget-shell")) is False
        assert effective_level(document, case_by_id(document, "widget-shell")) is None
        return document, notes

    def lower_the_claim(document: dict) -> None:
        """A review recorded above the claim, measured against the claim and never against itself."""
        validation = case_by_id(document, "widget-shell")["validation"]
        validation["reviews"][-1].update({"level": "L4", "role": "curator"})
        rechain(document, validation)
        validation["level"] = "L2"

    def repin_the_snapshot(document: dict) -> None:
        """The same labels, pointing at bytes the reviewer never saw."""
        document["snapshots"][0]["commit"] = "b" * 40
        document["snapshots"][0]["tree_hash"] = "sha256:" + "c" * 64

    def delete_the_withdrawal(document: dict) -> None:
        """A withdrawal recorded, then deleted, leaving the approval under it standing."""
        validation = case_by_id(document, "widget-shell")["validation"]
        chain_review(document, validation, {"reviewer": "A. Djudicator", "role": "adjudicator",
                                            "decision": "unresolved", "level": "L3",
                                            "at": "2026-09-20T18:00:00+00:00", "note": "reopened"})
        del validation["reviews"][-1]

    _, notes = refuse(lower_the_claim, "carries the role curator")
    assert any("carries the role curator" in note for note in notes)
    # The repin is caught by the first gate it reaches, which is the one comparing the three
    # records of the export. The approval is gone either way, which is what refuse() asserts.
    repinned, notes = refuse(repin_the_snapshot, "the checks ran against an export the snapshot no "
                             "longer names", planned_hash="sha256:" + "c" * 64)
    assert any("ran against a different tree than the pack now declares" in note for note in notes)
    assert _approval_gap(repinned, case_by_id(repinned, "widget-shell")) == (
        "the labels changed after the review, which covers different label content")
    withdrawn, notes = refuse(delete_the_withdrawal, "a review was deleted from the end of it")
    assert any("the recorded review history does not verify" in note for note in notes)
    assert any("a review was deleted from the end of it" in note for note in notes)
    assert [entry["decision"] for entry in
            case_by_id(withdrawn, "widget-shell")["validation"]["reviews"]] == ["approve"], \
        "the deletion succeeded; what it cannot do is pass for the history it came from"

def test_deleting_a_failing_check_cannot_turn_a_failed_set_into_a_passing_one(tmp_path):
    """Reproduces the reconstituted check set: a set read by membership loses its failing check.

    A check set used to be whichever recorded checks carried the snapshot id, so deleting the one
    that failed, or dropping its attribution so it left the set, left five passing checks that read
    as a passing set. The set is one record now: it states what the set decided and hashes that
    together with its own checks, so both routes leave the record hashing to something that is no
    longer there, and every gate reads the record.
    """
    pack = make_pack()
    case_by_id(pack, "widget-shell")["target"]["accepted_locations"][0]["path"] = "src/moved.py"
    outcomes = mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    validation = case_by_id(pack, "widget-shell")["validation"]
    assert outcomes[0]["passed"] is False
    assert validation["check_sets"]["widget-abc"]["result"] == "fail"
    assert validation["review_state"] == "draft" and validation["level"] is None

    deleted = json.loads(json.dumps(pack))
    edited = deleted["cases"][0]["validation"]
    edited["checks"] = [check for check in edited["checks"] if check["result"] == "pass"]
    edited["review_state"] = "mechanically_checked"
    edited["level"] = "L1"
    with pytest.raises(ContractError, match="a check was deleted, unattributed, reordered, or edited"):
        validate_document("case-pack", deleted)
    assert recorded_check_state(edited, "widget-abc") is None
    plan, notes = build_plan(deleted, "widget-abc", HASH)
    assert plan["targets"] == [] and plan["scope"] == "draft"
    assert any("no recorded passing mechanical check set" in note for note in notes)

    unattributed = json.loads(json.dumps(pack))
    edited = unattributed["cases"][0]["validation"]
    for check in edited["checks"]:
        if check["result"] == "fail":
            del check["snapshot_id"]
    edited["review_state"] = "mechanically_checked"
    edited["level"] = "L1"
    with pytest.raises(ContractError, match="'snapshot_id' is a required property"):
        validate_document("case-pack", unattributed)

    moved = json.loads(json.dumps(pack))
    edited = moved["cases"][0]["validation"]
    for check in edited["checks"]:
        if check["result"] == "fail":
            check["snapshot_id"] = "widget-elsewhere"
    with pytest.raises(ContractError, match="a check was deleted, unattributed, reordered, or edited"):
        validate_document("case-pack", moved)
    assert recorded_check_state(edited, "widget-abc") is None

    # Restating the set over the checks that remain is what the deletion costs, and it is a
    # deliberate act: what the pack then records is a set the person who edited it wrote.
    rebuild_check_set(deleted["cases"][0]["validation"], "widget-abc")
    assert validate_document("case-pack", deleted) is deleted
    assert recorded_check_state(deleted["cases"][0]["validation"], "widget-abc") == "pass"


def test_deleting_a_recorded_rejection_cannot_restore_the_case_it_kept_out(tmp_path):
    """Reproduces the restored admission: an unchained array loses a decision without a trace.

    Admissions used to be an append-only array anchored by nothing, so deleting the rejection that
    kept a case out of a plan left a pack that had never rejected anything. They are a chain now,
    and the pack anchor records where the chain ends, so a deletion from the middle leaves the
    decisions after it chaining to nothing and a deletion off the end leaves the pack anchoring to
    a decision it no longer holds.
    """
    pack = approved_pack(tmp_path)
    admit_case(pack, "widget-shell", decision="rejected", by="J. Curator",
               reason="the mechanism duplicates an admitted target", clock=CLOCK)
    assert [entry["decision"] for entry in pack["admissions"]] == ["admitted", "rejected"]
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["targets"] == []
    assert any("latest admission decision (rejected by J. Curator" in note for note in notes)

    truncated = json.loads(json.dumps(pack))
    del truncated["admissions"][-1]
    with pytest.raises(ContractError, match="a case, a review history, or an admission was deleted"):
        validate_document("case-pack", truncated)
    with pytest.raises(ContractError, match="anchored records do not verify"):
        build_plan(truncated, "widget-abc", HASH)
    with pytest.raises(ContractError, match="anchored records do not verify"):
        admit_case(truncated, "widget-shell", decision="admitted", by="J. Curator",
                   reason="a write cannot re-anchor what was deleted", clock=CLOCK)

    middle = json.loads(json.dumps(pack))
    del middle["admissions"][0]
    with pytest.raises(ContractError, match="does not chain to the admission before it"):
        validate_document("case-pack", middle)

    edited = json.loads(json.dumps(pack))
    edited["admissions"][-1]["decision"] = "admitted"
    with pytest.raises(ContractError, match="does not chain to the admission before it"):
        validate_document("case-pack", edited)

    unchained = json.loads(json.dumps(pack))
    del unchained["admissions"][-1]["chain_sha256"]
    with pytest.raises(ContractError, match="records no chain_sha256"):
        validate_document("case-pack", unchained)

    # Rebuilding the chain and the anchor is what a deletion costs, and the pack that results is
    # one the person who edited it wrote: the plan is reviewed again, under no recorded rejection.
    rechain_admissions(truncated)
    assert validate_document("case-pack", truncated) is truncated
    assert build_plan(truncated, "widget-abc", HASH)[0]["scope"] == "reviewed"
    assert pack_sha256(truncated) != pack_sha256(pack)


def test_wiping_a_review_history_whole_is_not_a_case_that_never_had_one(tmp_path):
    """Reproduces the erased withdrawal: an empty history used to verify like a deleted one.

    The chain binds the entries to each other and ``reviews_sha256`` says where they end, but both
    live inside the history, so wiping it took the record that would have complained. The pack
    anchor records where each case's review history ends, and a case that never had one anchors a
    null, which is how the two stay distinguishable.
    """
    pack = approved_pack(tmp_path)
    record_review(pack, "widget-shell", reviewer="A. Djudicator", role="adjudicator",
                  decision="reject", note="the label names the wrong mechanism", clock=CLOCK)
    validation = case_by_id(pack, "widget-shell")["validation"]
    assert [entry["decision"] for entry in validation["reviews"]] == ["approve", "reject"]

    wiped = json.loads(json.dumps(pack))
    edited = wiped["cases"][0]["validation"]
    edited["reviews"] = []
    del edited["reviews_sha256"]
    with pytest.raises(ContractError, match="a case, a review history, or an admission was deleted"):
        validate_document("case-pack", wiped)
    with pytest.raises(ContractError, match="anchored records do not verify"):
        build_plan(wiped, "widget-abc", HASH)

    # Keeping the head while dropping the entries is the older refusal, unchanged.
    named = json.loads(json.dumps(pack))
    named["cases"][0]["validation"]["reviews"] = []
    with pytest.raises(ContractError, match="the history it names was deleted whole"):
        validate_document("case-pack", named)

    # A case that has never been reviewed records no history and anchors none, and loads.
    never = make_pack()
    mechanical_checks(never, "widget-abc", tmp_path / "source", HASH, clock=CLOCK)
    unreviewed = case_by_id(never, "widget-shell")["validation"]
    assert unreviewed["reviews"] == [] and "reviews_sha256" not in unreviewed
    assert validate_document("case-pack", never) is never
    assert build_plan(never, "widget-abc", HASH)[0]["scope"] == "draft"


def test_deleting_a_whole_case_cannot_turn_a_draft_plan_into_a_reviewed_one(tmp_path):
    """Reproduces the deleted case: scope is all or nothing, and the case list was anchored by nothing.

    A plan is reviewed only when every case in it is, so a pack holding one unreviewed case plans
    draft. Deleting that case, its chained review history and all, used to leave a pack that was
    consistent in every other respect and a plan that claimed reviewed scope. The anchor records
    the roster, so the case that is gone is visible as gone.
    """
    pack = approved_pack(tmp_path)
    add_case(pack, draft_case(
        "widget-path", snapshot_id="widget-abc", kind="path_traversal", description="join of a user path",
        represents=REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[evidence("note", origin="research_note", kind="source_inspection", reference="src/app.py")],
        accepted_locations=[{"path": "src/app.py", "start_line": 1, "end_line": 1, "role": "sink"}],
    ))
    mechanical_checks(pack, "widget-abc", tmp_path / "source", HASH, clock=CLOCK)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and notes == []
    assert {target["target_id"] for target in plan["targets"]} == {"T-widget-shell", "T-widget-path"}

    document = json.loads(json.dumps(pack))
    document["cases"] = [case for case in document["cases"] if case["case_id"] != "widget-path"]
    with pytest.raises(ContractError, match="a case, a review history, or an admission was deleted"):
        validate_document("case-pack", document)
    with pytest.raises(ContractError, match="anchored records do not verify"):
        build_plan(document, "widget-abc", HASH)

    # Reordering the roster is the same refusal: the anchor names the list as it was recorded.
    reordered = json.loads(json.dumps(pack))
    reordered["cases"].reverse()
    with pytest.raises(ContractError, match="a case, a review history, or an admission was deleted"):
        validate_document("case-pack", reordered)

    # Re-anchoring is what the deletion costs, and the pack that results no longer hashes to the
    # pack the earlier plans named, so a plan built from it cannot pass for one built from this.
    reanchor(document)
    assert validate_document("case-pack", document) is document
    plan, _ = build_plan(document, "widget-abc", HASH)
    assert plan["scope"] == "reviewed"
    assert plan["provenance"]["pack_sha256"] != pack_sha256(pack)


def test_only_an_explicit_admitted_decision_reaches_a_reviewed_scope_plan(tmp_path):
    """Changed deliberately: an approved case with no admission used to reach a reviewed plan.

    The pack says a label becomes evidence through recorded human review and admission, and the
    admission decisions are ``admitted``, ``rejected``, and ``deferred``. Only ``rejected`` did
    anything, so a deferred decision and no decision at all were both read as admission. A case is
    admitted when a named person recorded that it is.
    """
    pack = make_pack()
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L3",
                 note="label established", clock=CLOCK)

    assert latest_admission(pack, "widget-shell") is None
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and notes == []
    assert [target["validation_level"] for target in plan["targets"]] == ["L3"]

    admit_case(pack, "widget-shell", decision="deferred", by="J. Curator",
               reason="held for the second reviewer", clock=CLOCK)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and notes == []
    assert [target["target_id"] for target in plan["targets"]] == ["T-widget-shell"], \
        "a deferred decision holds the case back from evidence, it does not remove it"

    admit_case(pack, "widget-shell", decision="admitted", by="J. Curator",
               reason="the second reviewer read it", clock=CLOCK)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and notes == []

    admit_case(pack, "widget-shell", decision="deferred", by="J. Curator",
               reason="reopened while the fix commit is re-read", clock=CLOCK)
    assert build_plan(pack, "widget-abc", HASH)[0]["scope"] == "draft"


def test_swapping_the_evidence_under_an_approved_control_leaves_the_approval_behind(tmp_path):
    """Reproduces the swapped evidence: the one control field the label digest did not cover.

    A control rests on the evidence records it names, so what a reviewer approved includes which
    of them it names. The ids used to sit outside the digest, so a control could be pointed at
    other evidence after approval without the approval lapsing.
    """
    pack = make_pack()
    case = case_by_id(pack, "widget-shell")
    case["evidence"].append(evidence("inspection", origin="research_note", kind="source_inspection",
                                     reference="src/app.py", note="a second read of the call site"))
    case["controls"].append(safe_control())
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    set_disposition(pack, "widget-shell", "validate", "evidence reviewed")
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L3",
                 note="the control and the evidence under it were read", clock=CLOCK)
    admit_case(pack, "widget-shell", decision="admitted", by="J. Curator", reason="pilot slice",
               clock=CLOCK)
    assert build_plan(pack, "widget-abc", HASH)[0]["scope"] == "reviewed"

    case = case_by_id(pack, "widget-shell")
    before = label_digest(pack, case)
    case["controls"][0]["evidence_ids"] = ["inspection"]

    assert label_digest(pack, case) != before
    assert approval_is_current(pack, case) is False
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"] == [] and plan["controls"] == []
    assert any("the labels changed after the review" in note for note in notes)

    # Reordering the ids is not a change to the labels, as reordering aliases is not.
    case["controls"][0]["evidence_ids"] = ["fix", "inspection"]
    approve_case(pack, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer", level="L3",
                 note="both records read", clock=CLOCK)
    case = case_by_id(pack, "widget-shell")  # the write validated a copy and swapped it in
    reordered = label_digest(pack, case)
    case["controls"][0]["evidence_ids"] = ["inspection", "fix"]
    assert label_digest(pack, case) == reordered
    assert approval_is_current(pack, case) is True


def test_a_reviewer_can_record_a_withdrawal_or_a_reopening_through_the_library(tmp_path):
    """The withdrawal the design rests on is a supported write, not a hand edit of a pack.

    Every gate reads the latest recorded review, and a rejection or an unresolved reopening is how
    a reviewer withdraws an approval. Until now the only writer was :func:`approve_case`, so the
    only way to record one was to edit the file and rebuild the chain by hand.
    """
    pack = approved_pack(tmp_path)
    assert build_plan(pack, "widget-abc", HASH)[0]["scope"] == "reviewed"

    reopened = copy.deepcopy(pack)
    entry = record_review(reopened, "widget-shell", reviewer="A. Djudicator", role="adjudicator",
                          decision="unresolved", note="the deployment assumption needs a second read",
                          clock=CLOCK)
    validation = case_by_id(reopened, "widget-shell")["validation"]
    assert entry["decision"] == "unresolved" and entry["level"] == "L3"
    assert validation["reviews_sha256"] == entry["chain_sha256"]
    assert validation["review_state"] == "human_approved" and validation["level"] == "L3", \
        "reopening a question says nothing about the mechanical checks, so it moves no state"
    assert validate_document("case-pack", reopened) is reopened
    plan, notes = build_plan(reopened, "widget-abc", HASH)
    assert plan["targets"] == [] and plan["scope"] == "draft"
    assert any("reopened the question and left it unresolved" in note for note in notes)

    rejected = copy.deepcopy(pack)
    record_review(rejected, "widget-shell", reviewer="A. Djudicator", role="adjudicator",
                  decision="reject", note="the label names the wrong mechanism", clock=CLOCK)
    validation = case_by_id(rejected, "widget-shell")["validation"]
    assert [review["decision"] for review in validation["reviews"]] == ["approve", "reject"]
    assert validation["review_state"] == "mechanically_checked" and validation["level"] == "L1", \
        "a rejected case falls back to what its own mechanical checks earn"
    assert validate_document("case-pack", rejected) is rejected
    plan, notes = build_plan(rejected, "widget-abc", HASH)
    assert plan["targets"] == [] and plan["scope"] == "draft"
    assert any("the latest recorded review rejected this case" in note for note in notes), \
        "withdrawing an approval is not a way of handing the case back to its mechanical L1"

    before = dump_json(rejected)
    with pytest.raises(ContractError, match="requires an explicit reviewer name"):
        record_review(rejected, "widget-shell", reviewer="​", role="adjudicator",
                      decision="reject", note="", clock=CLOCK)
    with pytest.raises(ContractError, match="decision must be one of"):
        record_review(rejected, "widget-shell", reviewer="A. Djudicator", role="adjudicator",
                      decision="withdrawn", note="", clock=CLOCK)
    assert dump_json(rejected) == before

    approve_case(rejected, "widget-shell", reviewer="R. Eviewer", role="independent_reviewer",
                 level="L3", note="the mechanism was re-read and the label holds", clock=CLOCK)
    assert build_plan(rejected, "widget-abc", HASH)[0]["scope"] == "reviewed"
    assert [review["decision"] for review in
            case_by_id(rejected, "widget-shell")["validation"]["reviews"]] == [
        "approve", "reject", "approve"]

