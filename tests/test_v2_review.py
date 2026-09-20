"""Review workflow: routing proposes candidates only, and approval stays explicit.

These tests build the small v2 records inline and exercise the public review API.
Packs are built through :mod:`sastbench.cases` so the fixtures are real contract
documents. No scanner, model, network call, or sleep is involved.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from sastbench import cases, review
from sastbench.cli import main
from sastbench.contracts import ContractError, canonical_json, canonical_sha256, validate_document
from sastbench.review import (
    CANDIDATE_REASON,
    PENDING_REASON,
    _assert_draft_only,
    approve_review,
    draft_decisions,
    load_evaluator,
    record_decisions,
    review_record,
    review_status,
    write_evaluator_records,
)
from sastbench.scoring import score


HASH = "sha256:" + "a" * 64
OTHER_HASH = "sha256:" + "b" * 64
CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
LATER = lambda: datetime(2026, 9, 21, 9, 30, tzinfo=timezone.utc)  # noqa: E731


def make_plan(*, input_hash: str = HASH, description: str = "first fixture target") -> dict:
    return {
        "schema_version": "2.0",
        "input_hash": input_hash,
        "scope": "diagnostic",
        "targets": [
            {"target_id": "T-case-a", "description": description, "validation_level": "fixture"},
            {"target_id": "T-case-b", "description": "second fixture target", "validation_level": "fixture"},
        ],
        "controls": [
            {"control_id": "C1", "description": "safe capability", "type": "capability_safe",
             "validation_level": "fixture"},
            {"control_id": "C2", "description": "repaired target", "type": "fixed_target",
             "target_id": "T-case-a", "validation_level": "fixture"},
        ],
        "review_budgets": [3, 5],
    }


def make_pack(*locations: tuple[str, str]) -> dict:
    """A valid pack whose cases carry the given ``(case_id, accepted path)`` locations."""
    pack = cases.new_pack("fixture", "review-pack", "Inline fixture pack; no repository is fetched.")
    cases.add_snapshot(pack, {
        "snapshot_id": "snap-1",
        "repository": {"url": "https://example.invalid/fixture", "name": "fixture"},
        "commit": "0" * 40,
        "reference": "inline fixture, not a real commit",
        "languages": ["python"],
        "workload": "conventional_application",
        "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "fixture"},
    })
    grouped: dict[str, list[str]] = {}
    for case_id, path in locations:
        grouped.setdefault(case_id, []).append(path)
    for case_id, paths in grouped.items():
        cases.add_case(pack, cases.draft_case(
            case_id, snapshot_id="snap-1", kind="command_injection",
            description=f"fixture target for {case_id}",
            represents="This case tests a fixture mechanism under fixture assumptions, and adds nothing real.",
            workload="conventional_application", component_role="application", aliases=[],
            evidence=[cases.evidence("e1", origin="diagnostic_fixture", kind="source_inspection",
                                     reference="inline fixture")],
            accepted_locations=[{"path": path, "role": "sink"} for path in paths],
        ))
    return pack


def default_pack() -> dict:
    return make_pack(("case-a", "src/app.py"), ("case-b", "src/other.py"))


def claim(claim_id: str, path: str, *, rank: int, allegation: str | None = None) -> dict:
    return {
        "claim_id": claim_id,
        "allegation": allegation or f"fixture allegation for {claim_id}",
        "kind": "command_injection",
        "primary_location": {"path": path, "start_line": 10, "end_line": 12},
        "rank": rank,
    }


def make_result(claims: list[dict], *, input_hash: str = HASH, run_id: str = "run-1") -> dict:
    return {
        "schema_version": "2.0",
        "run_id": run_id,
        "system_id": "fixture-system",
        "input_hash": input_hash,
        "status": "success",
        "ranking": "native",
        "claims": claims,
        "bundles_resolved": True,
        "usage": {"wall_seconds": 1},
    }


def default_claims() -> list[dict]:
    return [
        claim("c1", "./src/app.py", rank=1),
        claim("c2", "src\\other.py", rank=2),
        claim("c3", "src/untouched.py", rank=3),
    ]


def pairs(decisions: dict) -> list[tuple[str, str]]:
    return [(match["claim_id"], match["target_id"]) for match in decisions["claim_matches"]]


def written_bundle(tmp_path: Path, *, decisions: dict | None = None) -> tuple[Path, dict, dict, dict]:
    plan = make_plan()
    result = make_result(default_claims())
    decisions = decisions if decisions is not None else draft_decisions(plan, result, default_pack())
    record = review_record(plan, decisions, clock=CLOCK, notes=["drafted by tooling"])
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    write_evaluator_records(bundle, plan, decisions, record)
    return bundle, plan, result, decisions


def test_routing_matches_accepted_location_paths_only_and_normalizes_claim_paths():
    plan = make_plan()
    result = make_result(default_claims())

    decisions = draft_decisions(plan, result, default_pack())

    assert pairs(decisions) == [("c1", "T-case-a"), ("c2", "T-case-b")]
    assert [match["reason"] for match in decisions["claim_matches"]] == [CANDIDATE_REASON] * 2
    assert decisions["run_id"] == "run-1"
    assert decisions["input_hash"] == HASH
    assert decisions["result_sha256"] == canonical_sha256(result)


def test_a_path_shared_by_two_targets_routes_one_claim_to_both_in_sorted_order():
    pack = make_pack(("case-b", "src/app.py"), ("case-a", "src/app.py"))

    decisions = draft_decisions(make_plan(), make_result([claim("c1", "src/app.py", rank=1)]), pack)

    assert pairs(decisions) == [("c1", "T-case-a"), ("c1", "T-case-b")]


def test_without_a_pack_there_are_no_candidate_matches():
    decisions = draft_decisions(make_plan(), make_result(default_claims()))

    assert decisions["claim_matches"] == []
    assert [item["control_id"] for item in decisions["control_assessments"]] == ["C1", "C2"]


def test_every_drafted_decision_is_unresolved_and_controls_cite_no_claims():
    decisions = draft_decisions(make_plan(), make_result(default_claims()), default_pack())

    assert {match["decision"] for match in decisions["claim_matches"]} == {"unresolved"}
    assert [assessment["decision"] for assessment in decisions["control_assessments"]] == \
        ["unresolved", "unresolved"]
    assert all(assessment["claim_ids"] == [] for assessment in decisions["control_assessments"])
    assert all(assessment["reason"] == PENDING_REASON for assessment in decisions["control_assessments"])


def test_draft_refuses_a_plan_and_result_bound_to_different_inputs():
    plan = make_plan(input_hash=OTHER_HASH)

    with pytest.raises(ContractError, match="same input hash"):
        draft_decisions(plan, make_result(default_claims()), default_pack())


def test_record_binds_to_the_plan_and_decisions_hashes_as_a_draft():
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())

    record = review_record(plan, decisions, clock=CLOCK, notes=["drafted by tooling"])

    validate_document("review-record", record)
    assert record["state"] == "draft"
    assert record["reviews"] == []
    assert record["run_id"] == "run-1"
    assert record["created_at"] == "2026-09-20T15:00:00+00:00"
    assert record["decisions_sha256"] == canonical_sha256(decisions)
    assert record["plan_sha256"] == canonical_sha256(plan)
    assert record["notes"] == ["drafted by tooling"]


def test_approval_records_a_named_reviewer_and_leaves_the_draft_record_untouched():
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)

    approved = approve_review(record, decisions, plan, reviewer="A. Reviewer",
                              note="checked both candidates against the snapshot", clock=LATER)

    assert approved["state"] == "human_approved"
    assert approved["reviews"] == [{
        "reviewer": "A. Reviewer",
        "at": "2026-09-21T09:30:00+00:00",
        "decisions_sha256": canonical_sha256(decisions),
        "note": "checked both candidates against the snapshot",
    }]
    assert record["state"] == "draft" and record["reviews"] == []


@pytest.mark.parametrize("reviewer", ["", "   "])
def test_approval_refuses_an_empty_reviewer_name(reviewer):
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)

    with pytest.raises(ContractError, match="explicit reviewer"):
        approve_review(record, decisions, plan, reviewer=reviewer, note="", clock=LATER)

    assert record["state"] == "draft"


def test_approval_refuses_decisions_edited_after_the_record_was_made():
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)
    edited = json.loads(canonical_json(decisions))
    edited["claim_matches"][0]["decision"] = "accepted"
    edited["claim_matches"][0]["reason"] = "hand edited after the record was written"

    with pytest.raises(ContractError, match="decisions changed"):
        approve_review(record, edited, plan, reviewer="A. Reviewer", note="", clock=LATER)


def test_written_bundle_loads_back_and_reports_its_own_review_state(tmp_path):
    assert review_status(tmp_path / "bundle") == "missing"

    bundle, plan, _result, decisions = written_bundle(tmp_path)
    assert review_status(bundle) == "draft"

    loaded_plan, loaded_decisions, loaded_record = load_evaluator(bundle)
    assert loaded_plan == plan
    assert loaded_decisions == decisions
    assert loaded_record["state"] == "draft"
    assert (bundle / "evaluator" / "decisions.json").read_bytes() == \
        (canonical_json(decisions) + "\n").encode("utf-8")


def test_an_approved_record_reports_human_approved_and_a_missing_record_loads_as_none(tmp_path):
    plan = make_plan()
    result = make_result(default_claims())
    decisions = draft_decisions(plan, result, default_pack())
    approved = approve_review(review_record(plan, decisions, clock=CLOCK), decisions, plan,
                              reviewer="A. Reviewer", note="approved", clock=LATER)
    bundle = tmp_path / "approved"
    evaluator = bundle / "evaluator"
    evaluator.mkdir(parents=True)
    for name, document in (("plan.json", plan), ("decisions.json", decisions)):
        (evaluator / name).write_text(canonical_json(document) + "\n", encoding="utf-8")

    assert review_status(bundle) == "missing"
    assert load_evaluator(bundle)[2] is None

    (evaluator / "review-record.json").write_text(canonical_json(approved) + "\n", encoding="utf-8")
    assert review_status(bundle) == "human_approved"


def test_status_is_stale_when_the_decisions_file_changes_after_the_record(tmp_path):
    bundle, _plan, _result, decisions = written_bundle(tmp_path)
    edited = json.loads(canonical_json(decisions))
    edited["control_assessments"][0]["reason"] = "reviewed by hand outside the tool"
    (bundle / "evaluator" / "decisions.json").write_text(
        canonical_json(edited) + "\n", encoding="utf-8")

    assert review_status(bundle) == "stale"


def test_write_refuses_to_overwrite_existing_evaluator_files(tmp_path):
    bundle, plan, _result, decisions = written_bundle(tmp_path)
    record = review_record(plan, decisions, clock=LATER)
    before = (bundle / "evaluator" / "review-record.json").read_bytes()

    with pytest.raises(FileExistsError):
        write_evaluator_records(bundle, plan, decisions, record)

    assert (bundle / "evaluator" / "review-record.json").read_bytes() == before


def test_write_keeps_a_byte_identical_plan_and_refuses_a_different_one(tmp_path):
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)
    bundle = tmp_path / "bundle"
    evaluator = bundle / "evaluator"
    evaluator.mkdir(parents=True)
    (evaluator / "plan.json").write_text(canonical_json(plan) + "\n", encoding="utf-8")

    # Mode 'x' would refuse a rewrite, so a successful call proves the file was kept.
    paths = write_evaluator_records(bundle, plan, decisions, record)
    assert paths["plan"] == evaluator / "plan.json"
    assert (evaluator / "plan.json").read_bytes() == (canonical_json(plan) + "\n").encode("utf-8")

    other = tmp_path / "other"
    (other / "evaluator").mkdir(parents=True)
    (other / "evaluator" / "plan.json").write_text(
        canonical_json(make_plan(description="a different planned target")) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match="different plan"):
        write_evaluator_records(other, plan, decisions, record)

    assert not (other / "evaluator" / "decisions.json").exists()


def test_write_refuses_a_record_that_does_not_bind_to_the_decisions(tmp_path):
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    other_decisions = draft_decisions(plan, make_result(default_claims()), make_pack(("case-a", "src/app.py")))
    record = review_record(plan, other_decisions, clock=CLOCK)
    bundle = tmp_path / "bundle"

    with pytest.raises(ContractError, match="does not bind"):
        write_evaluator_records(bundle, plan, decisions, record)

    assert not (bundle / "evaluator" / "decisions.json").exists()


def test_drafted_candidates_score_as_pending_and_earn_no_detection_credit():
    plan = make_plan()
    result = make_result(default_claims())
    decisions = draft_decisions(plan, result, default_pack())

    record = score(plan, result, decisions)

    assert record["metrics"]["pending_matching_count"] == len(decisions["claim_matches"]) == 2
    assert record["metrics"]["targets_detected"] == 0
    assert record["metrics"]["known_target_recall"] == 0.0
    assert record["metrics"]["controls"]["capability_safe"]["resolved"] == 0
    assert "Unresolved target matches earn no confirmed detection credit." in record["warnings"]


def test_a_written_bundle_replays_offline_through_the_cli(tmp_path, capsys):
    bundle, _plan, result, decisions = written_bundle(tmp_path)
    (bundle / "result.json").write_text(canonical_json(result) + "\n", encoding="utf-8")

    assert main(["replay", str(bundle)]) == 0

    replayed = json.loads(capsys.readouterr().out)
    assert replayed["metrics"]["pending_matching_count"] == 2
    assert replayed["decisions_sha256"] == canonical_sha256(decisions)


def planned_from(pack: dict, *, input_hash: str = HASH) -> dict:
    """A plan that records the pack it was built from, the way :func:`cases.build_plan` does."""
    plan = make_plan(input_hash=input_hash)
    plan["provenance"] = {
        "namespace": pack["namespace"], "pack_id": pack["pack_id"], "pack_version": pack["version"],
        "pack_sha256": cases.pack_sha256(pack), "snapshot_id": "snap-1", "mode": "full",
    }
    return plan


def test_draft_refuses_a_routing_pack_that_is_not_the_pack_the_plan_was_built_from():
    pack = default_pack()
    plan = planned_from(pack)
    result = make_result(default_claims())

    assert pairs(draft_decisions(plan, result, pack)) == [("c1", "T-case-a"), ("c2", "T-case-b")]

    with pytest.raises(ContractError, match="not the pack the plan was built from"):
        draft_decisions(plan, result, make_pack(("case-a", "src/app.py")))

    # No pack means no routing at all, so there is nothing to bind to the plan's provenance.
    assert draft_decisions(plan, result)["claim_matches"] == []


def test_record_refuses_decisions_filed_against_a_different_input_than_the_plan():
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())

    with pytest.raises(ContractError, match="different input hashes"):
        review_record(make_plan(input_hash=OTHER_HASH), decisions, clock=CLOCK)


def test_approval_refuses_a_plan_swapped_after_the_record_was_made():
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)

    with pytest.raises(ContractError, match="plan changed"):
        approve_review(record, decisions, make_plan(description="a different planned target"),
                       reviewer="A. Reviewer", note="", clock=LATER)

    assert record["state"] == "draft" and record["reviews"] == []


def test_approval_refuses_a_record_and_decisions_that_name_different_runs():
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = {**review_record(plan, decisions, clock=CLOCK), "run_id": "run-2"}

    with pytest.raises(ContractError, match="different runs"):
        approve_review(record, decisions, plan, reviewer="A. Reviewer", note="", clock=LATER)


def test_status_is_stale_when_the_plan_file_changes_after_the_record(tmp_path):
    bundle, _plan, _result, _decisions = written_bundle(tmp_path)
    (bundle / "evaluator" / "plan.json").write_text(
        canonical_json(make_plan(description="a different planned target")) + "\n", encoding="utf-8")

    assert review_status(bundle) == "stale"


def test_write_refuses_decisions_and_a_plan_bound_to_different_inputs(tmp_path):
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)
    bundle = tmp_path / "bundle"

    with pytest.raises(ContractError, match="different input hashes"):
        write_evaluator_records(bundle, make_plan(input_hash=OTHER_HASH), decisions, record)

    assert not (bundle / "evaluator").exists()


def test_write_refuses_a_record_and_decisions_that_name_different_runs(tmp_path):
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = {**review_record(plan, decisions, clock=CLOCK), "run_id": "run-2"}
    bundle = tmp_path / "bundle"

    with pytest.raises(ContractError, match="different runs"):
        write_evaluator_records(bundle, plan, decisions, record)

    assert not (bundle / "evaluator").exists()


def test_write_refuses_a_symlinked_bundle_or_evaluator_directory(tmp_path):
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)
    real = tmp_path / "real"
    (real / "evaluator").mkdir(parents=True)
    linked_bundle = tmp_path / "linked-bundle"
    linked_bundle.symlink_to(real, target_is_directory=True)

    with pytest.raises(ContractError, match="symlinked directory"):
        write_evaluator_records(linked_bundle, plan, decisions, record)

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "evaluator").symlink_to(real / "evaluator", target_is_directory=True)

    with pytest.raises(ContractError, match="symlinked directory"):
        write_evaluator_records(bundle, plan, decisions, record)

    assert list((real / "evaluator").iterdir()) == []


def test_a_failed_write_removes_the_files_that_call_created(tmp_path, monkeypatch):
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)
    bundle = tmp_path / "bundle"
    written: list[Path] = []
    real_write = review._write_new

    def failing(path: Path, content: str) -> None:
        written.append(path)
        if len(written) == 3:
            raise OSError("no space left on device")
        real_write(path, content)

    monkeypatch.setattr(review, "_write_new", failing)

    with pytest.raises(OSError, match="no space left"):
        write_evaluator_records(bundle, plan, decisions, record)

    assert [path.name for path in written] == ["plan.json", "decisions.json", "review-record.json"]
    assert [path for path in bundle.rglob("*") if path.is_file()] == []


def test_record_decisions_redrafts_after_a_human_edits_the_decisions_file(tmp_path):
    bundle, plan, result, decisions = written_bundle(tmp_path)
    (bundle / "result.json").write_text(canonical_json(result) + "\n", encoding="utf-8")
    edited = json.loads(canonical_json(decisions))
    edited["claim_matches"][0]["decision"] = "accepted"
    edited["claim_matches"][0]["reason"] = "read the sink by hand and accepted the match"
    (bundle / "evaluator" / "decisions.json").write_text(
        canonical_json(edited) + "\n", encoding="utf-8")
    assert review_status(bundle) == "stale"

    record = record_decisions(bundle, clock=LATER, notes=["re-drafted after a hand edit"])

    assert record["state"] == "draft" and record["reviews"] == []
    assert record["decisions_sha256"] == canonical_sha256(edited)
    assert record["plan_sha256"] == canonical_sha256(plan)
    assert record["run_id"] == "run-1"
    assert record["created_at"] == "2026-09-21T09:30:00+00:00"
    assert record["notes"] == ["re-drafted after a hand edit"]
    assert (bundle / "evaluator" / "review-record.json").read_bytes() == \
        (canonical_json(record) + "\n").encode("utf-8")
    assert review_status(bundle) == "draft"
    assert not list((bundle / "evaluator").glob("*.tmp"))

    with pytest.raises(ContractError, match="already binds"):
        record_decisions(bundle, clock=LATER)

    approved = approve_review(record, edited, plan, reviewer="A. Reviewer",
                              note="read the hand edit", clock=LATER)
    assert approved["state"] == "human_approved"
    assert [review_entry["reviewer"] for review_entry in approved["reviews"]] == ["A. Reviewer"]


def test_record_decisions_refuses_decisions_that_do_not_bind_to_the_saved_result(tmp_path):
    bundle, _plan, result, _decisions = written_bundle(tmp_path)
    before = (bundle / "evaluator" / "review-record.json").read_bytes()
    altered = json.loads(canonical_json(result))
    altered["claims"][0]["allegation"] = "rewritten after the decisions were filed"
    (bundle / "result.json").write_text(canonical_json(altered) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match="filed against a different result"):
        record_decisions(bundle, clock=LATER)

    assert (bundle / "evaluator" / "review-record.json").read_bytes() == before


def test_record_decisions_refuses_decisions_and_a_result_that_name_different_runs(tmp_path):
    plan = make_plan()
    result = make_result(default_claims(), run_id="run-2")
    renamed = json.loads(canonical_json(draft_decisions(plan, result, default_pack())))
    renamed["run_id"] = "run-1"
    bundle = tmp_path / "bundle"
    (bundle / "evaluator").mkdir(parents=True)
    (bundle / "result.json").write_text(canonical_json(result) + "\n", encoding="utf-8")
    (bundle / "evaluator" / "plan.json").write_text(canonical_json(plan) + "\n", encoding="utf-8")
    (bundle / "evaluator" / "decisions.json").write_text(canonical_json(renamed) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match="different runs"):
        record_decisions(bundle, clock=LATER)

    assert not (bundle / "evaluator" / "review-record.json").exists()


def test_record_decisions_refuses_decisions_that_do_not_bind_to_the_plan(tmp_path):
    bundle, _plan, _result, _decisions = written_bundle(tmp_path)
    before = (bundle / "evaluator" / "review-record.json").read_bytes()
    (bundle / "evaluator" / "plan.json").write_text(
        canonical_json(make_plan(input_hash=OTHER_HASH)) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match="different input hashes"):
        record_decisions(bundle, clock=LATER)

    assert (bundle / "evaluator" / "review-record.json").read_bytes() == before


def test_assert_draft_only_refuses_a_hand_built_human_verdict():
    drafted = {
        "claim_matches": [{"claim_id": "c1", "target_id": "T-case-a",
                           "decision": "unresolved", "reason": CANDIDATE_REASON}],
        "control_assessments": [{"control_id": "C1", "decision": "unresolved",
                                 "claim_ids": [], "reason": PENDING_REASON}],
    }

    assert _assert_draft_only(drafted) is drafted

    accepted = json.loads(json.dumps(drafted))
    accepted["claim_matches"][0]["decision"] = "accepted"
    with pytest.raises(ContractError, match="claim decisions must stay"):
        _assert_draft_only(accepted)

    quiet = json.loads(json.dumps(drafted))
    quiet["control_assessments"][0]["decision"] = "quiet"
    with pytest.raises(ContractError, match="control decisions must stay"):
        _assert_draft_only(quiet)


def approved_bundle(tmp_path: Path) -> tuple[Path, dict, dict, dict]:
    """A bundle whose record on disk carries one recorded approval of the decisions beside it."""
    bundle, plan, result, decisions = written_bundle(tmp_path)
    (bundle / "result.json").write_text(canonical_json(result) + "\n", encoding="utf-8")
    approved = approve_review(load_evaluator(bundle)[2], decisions, plan, reviewer="A. Reviewer",
                              note="read both routed candidates", clock=CLOCK)
    (bundle / "evaluator" / "review-record.json").write_text(
        canonical_json(approved) + "\n", encoding="utf-8")
    assert review_status(bundle) == "human_approved"
    return bundle, plan, decisions, approved


def hand_edit_decisions(bundle: Path, decisions: dict) -> dict:
    """Accept one routed candidate in the decisions file, the way a reviewer would in an editor."""
    edited = json.loads(canonical_json(decisions))
    edited["claim_matches"][0]["decision"] = "accepted"
    edited["claim_matches"][0]["reason"] = "read the sink by hand and accepted the match"
    (bundle / "evaluator" / "decisions.json").write_text(
        canonical_json(edited) + "\n", encoding="utf-8")
    return edited


def test_record_decisions_keeps_earlier_reviews_in_the_new_draft_record(tmp_path):
    bundle, plan, decisions, approved = approved_bundle(tmp_path)
    edited = hand_edit_decisions(bundle, decisions)

    redrafted = record_decisions(bundle, clock=LATER, notes=["re-drafted after a hand edit"])

    assert redrafted["state"] == "draft"
    assert redrafted["reviews"] == approved["reviews"]
    assert [entry["reviewer"] for entry in redrafted["reviews"]] == ["A. Reviewer"]
    # The carried entry still names the decisions it was recorded against, not the edited ones.
    assert redrafted["reviews"][0]["decisions_sha256"] == canonical_sha256(decisions)
    assert redrafted["decisions_sha256"] == canonical_sha256(edited)
    assert redrafted["plan_sha256"] == canonical_sha256(plan)
    assert redrafted["notes"] == ["re-drafted after a hand edit"]
    assert review_status(bundle) == "draft"
    assert (bundle / "evaluator" / "review-record.json").read_bytes() == \
        (canonical_json(redrafted) + "\n").encode("utf-8")


def test_record_decisions_refuses_a_bundle_reached_through_a_symlink(tmp_path):
    bundle, _plan, _result, decisions = written_bundle(tmp_path)
    hand_edit_decisions(bundle, decisions)
    record_path = bundle / "evaluator" / "review-record.json"
    before = record_path.read_bytes()
    linked_bundle = tmp_path / "linked-bundle"
    linked_bundle.symlink_to(bundle, target_is_directory=True)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)

    with pytest.raises(ContractError, match="symlinked directory"):
        record_decisions(linked_bundle, clock=LATER)

    with pytest.raises(ContractError, match="does not resolve to itself"):
        record_decisions(linked_parent / "bundle", clock=LATER)

    assert record_path.read_bytes() == before
    assert not list((bundle / "evaluator").glob("*.tmp"))


def test_record_decisions_keeps_the_permissions_of_the_record_it_replaces(tmp_path):
    bundle, _plan, _result, decisions = written_bundle(tmp_path)
    record_path = bundle / "evaluator" / "review-record.json"
    record_path.chmod(0o644)
    hand_edit_decisions(bundle, decisions)

    record_decisions(bundle, clock=LATER)

    assert record_path.stat().st_mode & 0o777 == 0o644


def mismatched_record(plan: dict, decisions: dict) -> dict:
    """A hand-built record binding *plan* and *decisions*, which name different input hashes."""
    record = {**review_record(make_plan(input_hash=decisions["input_hash"]), decisions, clock=CLOCK),
              "plan_sha256": canonical_sha256(plan)}
    assert record["decisions_sha256"] == canonical_sha256(decisions)
    return validate_document("review-record", record)


def decisions_at(input_hash: str) -> dict:
    return draft_decisions(make_plan(input_hash=input_hash),
                           make_result(default_claims(), input_hash=input_hash), default_pack())


def test_approval_refuses_decisions_and_a_plan_bound_to_different_inputs():
    plan = make_plan()
    decisions = decisions_at(OTHER_HASH)
    record = mismatched_record(plan, decisions)

    with pytest.raises(ContractError, match="different input hashes"):
        approve_review(record, decisions, plan, reviewer="A. Reviewer", note="", clock=LATER)

    assert record["state"] == "draft" and record["reviews"] == []


@pytest.mark.parametrize("reviewer", [None, 7, ["A. Reviewer"]])
def test_approval_refuses_a_reviewer_name_that_is_not_a_string(reviewer):
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)

    with pytest.raises(ContractError, match="explicit reviewer"):
        approve_review(record, decisions, plan, reviewer=reviewer, note="", clock=LATER)

    assert record["state"] == "draft"


def test_status_is_stale_when_the_decisions_and_the_plan_name_different_inputs(tmp_path):
    plan = make_plan()
    decisions = decisions_at(OTHER_HASH)
    record = mismatched_record(plan, decisions)
    evaluator = tmp_path / "bundle" / "evaluator"
    evaluator.mkdir(parents=True)
    for name, document in (("plan.json", plan), ("decisions.json", decisions),
                           ("review-record.json", record)):
        (evaluator / name).write_text(canonical_json(document) + "\n", encoding="utf-8")

    assert review_status(tmp_path / "bundle") == "stale"


def test_status_and_load_evaluator_refuse_a_bundle_reached_through_a_symlink(tmp_path):
    bundle, _plan, _result, _decisions = written_bundle(tmp_path)
    linked_bundle = tmp_path / "linked-bundle"
    linked_bundle.symlink_to(bundle, target_is_directory=True)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)

    for reached in (review_status, load_evaluator):
        with pytest.raises(ContractError, match="symlinked directory"):
            reached(linked_bundle)
        with pytest.raises(ContractError, match="does not resolve to itself"):
            reached(linked_parent / "bundle")

    assert review_status(bundle) == "draft"


def test_write_keeps_a_plan_whose_bytes_differ_but_whose_document_is_the_same(tmp_path):
    plan = make_plan()
    decisions = draft_decisions(plan, make_result(default_claims()), default_pack())
    record = review_record(plan, decisions, clock=CLOCK)
    evaluator = tmp_path / "bundle" / "evaluator"
    evaluator.mkdir(parents=True)
    spaced = json.dumps(plan, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    assert spaced != canonical_json(plan) + "\n"
    (evaluator / "plan.json").write_text(spaced, encoding="utf-8")

    write_evaluator_records(tmp_path / "bundle", plan, decisions, record)

    # The file is kept as it stands, not rewritten into canonical form.
    assert (evaluator / "plan.json").read_text(encoding="utf-8") == spaced
    assert review_status(tmp_path / "bundle") == "draft"


def test_status_is_stale_when_the_record_and_the_decisions_name_different_runs(tmp_path):
    bundle, _plan, _result, decisions = written_bundle(tmp_path)
    record_path = bundle / "evaluator" / "review-record.json"
    renamed = json.loads(record_path.read_text(encoding="utf-8"))
    renamed["run_id"] = "run-2"
    record_path.write_text(canonical_json(renamed) + "\n", encoding="utf-8")

    # Both hashes still bind, so the run id is the only thing left that can say these
    # documents describe different scans.
    assert renamed["decisions_sha256"] == canonical_sha256(decisions)
    assert review_status(bundle) == "stale"


def test_status_and_load_evaluator_read_a_symlinked_parent_when_the_guard_is_off(tmp_path):
    bundle, plan, _result, decisions = written_bundle(tmp_path)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    reached = linked_parent / "bundle"

    assert review_status(reached, guard_symlinks=False) == "draft"
    loaded_plan, loaded_decisions, loaded_record = load_evaluator(reached, guard_symlinks=False)
    assert loaded_plan == plan and loaded_decisions == decisions
    assert loaded_record["state"] == "draft"

    # The guard is opt-out, not gone: the default still refuses the same spelling.
    with pytest.raises(ContractError, match="does not resolve to itself"):
        review_status(reached)
