"""Conformance tests for the initial pure v2 scorer.

These tests intentionally construct the small v2 records inline.  They are
black-box tests: matching and duplicate identity are exercised through the
public ``score`` function, while hashes use the contract's canonical helper.
"""

from __future__ import annotations

from copy import deepcopy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scaneval.contracts import ContractError, canonical_sha256
from scaneval.scoring import score


HASH = "sha256:" + "a" * 64


def make_plan(*, controls: list[dict] | None = None) -> dict:
    return {
        "schema_version": "2.0",
        "input_hash": HASH,
        "scope": "diagnostic",
        "targets": [
            {"target_id": "T1", "description": "first root cause", "validation_level": "fixture"},
            {"target_id": "T2", "description": "second root cause", "validation_level": "fixture"},
        ],
        "controls": controls if controls is not None else [
            {"control_id": "C1", "description": "safe capability", "type": "capability_safe", "validation_level": "fixture"},
        ],
        "review_budgets": [3, 5],
    }


def claim(claim_id: str, allegation: str, *, rank: int | None = None,
          kind: str = "auth_bypass", path: str = "src/app.py", line: int = 10,
          native_rule_id: str | None = "rule-1", related_locations=None,
          evidence_text: str | None = None) -> dict:
    value = {
        "claim_id": claim_id,
        "allegation": allegation,
        "kind": kind,
        "primary_location": {"path": path, "start_line": line, "end_line": line},
    }
    if rank is not None:
        value["rank"] = rank
    if native_rule_id is not None:
        value["native_rule_id"] = native_rule_id
    if related_locations is not None:
        value["related_locations"] = related_locations
    if evidence_text is not None:
        value["evidence_text"] = evidence_text
    return value


def make_result(claims: list[dict], *, status="success", ranking="native",
                bundles_resolved=True, run_id="run-1") -> dict:
    return {
        "schema_version": "2.0",
        "run_id": run_id,
        "system_id": "fixture-system",
        "input_hash": HASH,
        "status": status,
        "ranking": ranking,
        "claims": claims,
        "bundles_resolved": bundles_resolved,
        "usage": {"wall_seconds": 1},
    }


def make_decisions(result: dict, *, matches=(), controls=(), run_id="run-1") -> dict:
    return {
        "schema_version": "2.0",
        "run_id": run_id,
        "input_hash": HASH,
        "result_sha256": canonical_sha256(result),
        "claim_matches": [
            {"claim_id": cid, "target_id": tid, "decision": decision, "reason": reason}
            for cid, tid, decision, reason in matches
        ],
        "control_assessments": [
            {"control_id": cid, "decision": decision, "claim_ids": list(claim_ids), "reason": reason}
            for cid, decision, claim_ids, reason in controls
        ],
    }


def score_fixture(claims, *, matches=(), controls=(), status="success", ranking="native",
                  bundles_resolved=True, plan=None):
    result = make_result(claims, status=status, ranking=ranking, bundles_resolved=bundles_resolved)
    return score(plan or make_plan(), result, make_decisions(result, matches=matches, controls=controls))


def test_worked_example_recall_budgets_duplicates_and_first_hit_ranks():
    claims = [
        claim("c1", "T1 specific root cause", rank=1),
        claim("c2", "T1 specific root cause", rank=2),
        claim("c3", "different authorization concern", rank=3, kind="authz_bypass"),
        claim("c4", "search value is concatenated into SQL", rank=4, kind="sql_injection", path="src/search.py", line=20),
        claim("c5", "T2 specific root cause", rank=5, line=30),
    ]
    out = score_fixture(
        claims,
        matches=[("c1", "T1", "accepted", "specific root cause"),
                 ("c5", "T2", "accepted", "specific root cause")],
        controls=[("C1", "false_allegation", ["c4"], "unsafe query structure")],
    )
    m = out["metrics"]
    assert m["known_target_recall"] == 1.0
    assert m["recall_at_budget"] == {"3": 0.5, "5": 1.0}
    assert m["targets_assigned"] == 2 and m["targets_detected"] == 2
    assert m["claims_delivered"] == 5
    assert m["claim_records"] == 5
    assert m["unique_claims"] == 4 and m["duplicate_copies"] == 1
    assert m["unmatched_unique_claims"] == 1
    assert out["targets"] == [
        {"target_id": "T1", "detected": True, "first_hit_rank": 1},
        {"target_id": "T2", "detected": True, "first_hit_rank": 5},
    ]
    assert out["duplicate_groups"][0]["claim_ids"] == ["c1", "c2"]
    assert m["controls"]["capability_safe"]["false_allegations"] == 1


def test_exact_duplicate_identity_excludes_delivery_id_rank_and_normalizes_paths_text():
    a = claim("a", "same\r\nallegation", rank=1, path="src\\x.py", evidence_text="line 1\r\nline 2")
    b = claim("b", "same\nallegation", rank=2, path="src/x.py", evidence_text="line 1\nline 2")
    out = score_fixture([a, b], matches=[("a", "T1", "accepted", "review")])
    assert out["metrics"]["unique_claims"] == 1
    assert out["metrics"]["duplicate_copies"] == 1
    assert out["targets"][0]["detected"] is True


def test_same_location_wrong_parameter_or_kind_without_accepted_decision_is_not_a_hit():
    wrong = claim("wrong", "the safely bound search parameter is injectable", rank=1, kind="sql_injection")
    out = score_fixture([wrong])
    assert out["metrics"]["known_target_recall"] == 0.0
    assert out["metrics"]["targets_detected"] == 0


def test_duplicate_acceptance_propagates_but_conflicting_duplicate_decisions_are_rejected():
    claims = [claim("a", "same allegation", rank=1), claim("b", "same allegation", rank=2)]
    out = score_fixture([*claims], matches=[("a", "T1", "accepted", "review")])
    assert out["targets"][0]["first_hit_rank"] == 1
    with pytest.raises(ContractError):
        score_fixture([*claims], matches=[("a", "T1", "accepted", "x"), ("b", "T1", "rejected", "y")])
    with pytest.raises(ContractError):
        score_fixture([*claims], matches=[("a", "T1", "accepted", "x"), ("b", "T2", "accepted", "y")])


def test_missing_targets_have_null_rank_not_last_position():
    out = score_fixture([claim("c", "unmatched", rank=1)])
    assert out["targets"][0] == {"target_id": "T1", "detected": False, "first_hit_rank": None}
    assert out["targets"][1] == {"target_id": "T2", "detected": False, "first_hit_rank": None}


def test_unranked_uses_full_recall_and_random_order_diagnostic_includes_duplicates():
    claims = [claim("a", "T1", rank=None), claim("b", "T1", rank=None), claim("c", "noise", rank=None)]
    diagnostic_plan = make_plan()
    diagnostic_plan["review_budgets"] = [1, 3]
    out = score_fixture(claims, ranking="unranked", plan=diagnostic_plan,
                        matches=[("a", "T1", "accepted", "review")])
    assert out["metrics"]["known_target_recall"] == 0.5
    assert out["metrics"]["recall_at_budget"] == {"1": None, "3": None}
    # Both exact duplicate copies count as accepted draws for T1: at B=1,
    # P(hit T1)=2/3, averaged over two assigned targets gives 1/3.
    assert out["metrics"]["random_order_expected_recall"]["1"] == pytest.approx(1 / 3)
    assert out["metrics"]["random_order_expected_recall"]["3"] == 0.5


@pytest.mark.parametrize("status", ["error", "timeout", "unsupported"])
def test_failed_assignments_remain_denominator_and_cannot_establish_hit(status):
    c = claim("a", "T1", rank=1)
    out = score_fixture([c], status=status, matches=[("a", "T1", "accepted", "review")])
    assert out["metrics"]["known_target_recall"] == 0.0
    assert out["metrics"]["targets_assigned"] == 2
    assert out["metrics"]["completed"] is False


def test_partial_can_count_confirmed_hit_but_never_completed_control_credit():
    c = claim("a", "T1", rank=1)
    out = score_fixture([c], status="partial", matches=[("a", "T1", "accepted", "review")],
                        controls=[("C1", "quiet", [], "review")])
    assert out["metrics"]["known_target_recall"] == 0.5
    assert out["metrics"]["completed"] is False
    assert out["metrics"]["controls"]["capability_safe"]["completed"] == 0


def test_unresolved_bundles_suspend_budget_metrics_but_retain_observed_claim_counts():
    c = claim("a", "T1", rank=1)
    out = score_fixture([c], bundles_resolved=False, matches=[("a", "T1", "accepted", "review")])
    assert out["metrics"]["known_target_recall"] == 0.5
    assert out["metrics"]["recall_at_budget"] == {"3": None, "5": None}
    assert out["metrics"]["claims_delivered"] is None
    assert out["metrics"]["claim_records"] == 1
    assert out["targets"][0]["first_hit_rank"] is None


def test_controls_are_whole_output_and_zero_denominator_is_na():
    p = make_plan(controls=[
        {"control_id": "safe", "description": "safe", "type": "capability_safe", "validation_level": "fixture"},
        {"control_id": "fixed", "description": "fixed", "type": "fixed_target", "validation_level": "fixture"},
    ])
    out = score_fixture([claim("a", "quiet", rank=1)], controls=[("safe", "quiet", [], "review")], plan=p)
    safe = out["metrics"]["controls"]["capability_safe"]
    fixed = out["metrics"]["controls"]["fixed_target"]
    assert safe["assigned"] == 1 and safe["completed"] == 1 and safe["resolved"] == 1
    assert safe["resolved_false_alarm_rate"] == 0.0
    assert fixed["assigned"] == 1 and fixed["completed"] == 1
    assert fixed["resolved_false_alarm_rate"] is None
    assert fixed["sensitivity_lower"] == 0.0 and fixed["sensitivity_upper"] == 1.0


def test_unresolved_completed_controls_raise_sensitivity_upper_bound():
    controls = [("C1", "quiet", [], "review")]
    p = make_plan(controls=[
        {"control_id": "C1", "description": "safe", "type": "capability_safe", "validation_level": "fixture"},
        {"control_id": "C2", "description": "safe", "type": "capability_safe", "validation_level": "fixture"},
    ])
    out = score_fixture([], controls=controls, plan=p)
    c = out["metrics"]["controls"]["capability_safe"]
    assert c["assigned"] == 2 and c["completed"] == 2
    assert c["resolved"] == 1 and c["false_allegations"] == 0
    assert c["resolved_false_alarm_rate"] == 0.0
    assert c["sensitivity_lower"] == 0.0 and c["sensitivity_upper"] == 0.5


def test_type_both_is_reported_in_each_class_without_combined_pool():
    p = make_plan(controls=[
        {"control_id": "both", "description": "both", "type": "both", "validation_level": "fixture"},
    ])
    out = score_fixture([], controls=[("both", "quiet", [], "review")], plan=p)
    assert out["metrics"]["controls"]["capability_safe"]["assigned"] == 1
    assert out["metrics"]["controls"]["fixed_target"]["assigned"] == 1


def test_validation_rejects_decision_hash_mismatch_unknown_ids_and_conflicting_target_assignment():
    result = make_result([claim("a", "T1", rank=1)])
    decisions = make_decisions(result, matches=[("a", "T1", "accepted", "x")])
    decisions["result_sha256"] = HASH
    with pytest.raises(ContractError):
        score(make_plan(), result, decisions)
    decisions = make_decisions(result, matches=[("unknown", "T1", "accepted", "x")])
    with pytest.raises(ContractError):
        score(make_plan(), result, decisions)
    decisions = make_decisions(result, matches=[("a", "T1", "accepted", "x"), ("a", "T2", "accepted", "y")])
    with pytest.raises(ContractError):
        score(make_plan(), result, decisions)


def test_inputs_are_not_mutated_and_native_ranks_must_be_contiguous():
    plan = make_plan()
    result = make_result([claim("a", "T1", rank=1)])
    decisions = make_decisions(result, matches=[("a", "T1", "accepted", "x")])
    before = deepcopy((plan, result, decisions))
    score(plan, result, decisions)
    assert (plan, result, decisions) == before
    bad = make_result([claim("a", "T1", rank=2)])
    with pytest.raises(ContractError):
        score(make_plan(), bad, make_decisions(bad, matches=[("a", "T1", "accepted", "x")]))


def test_claim_records_and_usage_are_retained_for_always_silent_output():
    out = score_fixture([])
    m = out["metrics"]
    assert m["claims_delivered"] == 0 and m["claim_records"] == 0
    assert m["known_target_recall"] == 0.0
    assert m["usage"]["wall_seconds"] == 1


def test_duplicate_spam_consumes_claim_records_without_increasing_target_credit():
    claims = [claim(f"spam-{i}", "one repeated allegation", rank=i) for i in range(1, 6)]
    out = score_fixture(claims, matches=[("spam-1", "T1", "accepted", "review")])
    m = out["metrics"]
    assert m["claims_delivered"] == 5
    assert m["claim_records"] == 5 and m["unique_claims"] == 1
    assert m["duplicate_copies"] == 4
    assert m["targets_detected"] == 1
    assert m["recall_at_budget"] == {"3": 0.5, "5": 0.5}


def test_confirmed_false_control_is_not_an_unmatched_unknown_but_cannot_also_hit_target():
    c = claim("safe", "unsafe SQL allegation", rank=1, kind="sql_injection")
    out = score_fixture([c], controls=[("C1", "false_allegation", ["safe"], "review")])
    assert out["metrics"]["unmatched_unique_claims"] == 0
    assert out["metrics"]["controls"]["capability_safe"]["false_allegations"] == 1
    with pytest.raises(ContractError):
        score_fixture(
            [c],
            matches=[("safe", "T1", "accepted", "also a target")],
            controls=[("C1", "false_allegation", ["safe"], "contradiction")],
        )


def test_unresolved_match_is_pending_not_a_hit_or_false_alarm():
    c = claim("pending", "ambiguous allegation", rank=1)
    out = score_fixture([c], matches=[("pending", "T1", "unresolved", "needs adjudication")])
    assert out["metrics"]["known_target_recall"] == 0.0
    assert out["metrics"]["targets_detected"] == 0
    assert out["metrics"]["pending_matching_count"] == 1
    assert out["metrics"]["unmatched_unique_claims"] == 1
    assert any("Unresolved target matches" in warning for warning in out["warnings"])


def test_partial_output_keeps_claim_burden_and_target_hit_but_not_success_completion():
    c = claim("partial-hit", "partial root cause", rank=1)
    out = score_fixture(
        [c], status="partial",
        matches=[("partial-hit", "T1", "accepted", "confirmed before cutoff")],
    )
    m = out["metrics"]
    assert m["known_target_recall"] == 0.5
    assert m["claims_delivered"] == 1 and m["claim_records"] == 1
    assert m["completed"] is False
    assert m["controls"]["capability_safe"]["completed"] == 0


def test_partial_false_control_remains_visible_outside_completed_only_rate():
    c = claim("false", "false allegation against safe value", rank=1)
    out = score_fixture([c], status="partial",
                        controls=[("C1", "false_allegation", ["false"], "confirmed")])
    control = out["metrics"]["controls"]["capability_safe"]
    assert control["observed_false_allegations"] == 1
    assert control["completed"] == 0
    assert control["false_allegations"] == 0
    assert control["resolved_false_alarm_rate"] is None
    assert control["sensitivity_upper"] is None


def test_unranked_output_never_fabricates_native_ranks():
    c = claim("u", "unranked hit", rank=None)
    out = score_fixture(
        [c], ranking="unranked",
        matches=[("u", "T1", "accepted", "review")],
    )
    assert out["targets"][0]["detected"] is True
    assert out["targets"][0]["first_hit_rank"] is None
    assert out["metrics"]["recall_at_budget"] == {"3": None, "5": None}
    assert out["metrics"]["random_order_expected_recall"] is not None


def test_observe_is_the_per_observation_layer_score_summarizes():
    """observe() keeps one record per planned target and control, and score() is built on it."""
    from scaneval.scoring import observe

    claims = [
        claim("c1", "T1 specific root cause", rank=1),
        claim("c2", "T1 specific root cause", rank=2),
        claim("c3", "unrelated concern", rank=3, kind="authz_bypass"),
    ]
    result = make_result(claims)
    decisions = make_decisions(
        result,
        matches=[("c1", "T1", "accepted", "specific root cause"),
                 ("c3", "T2", "unresolved", "pending review")],
        controls=[("C1", "quiet", [], "reviewed full output")],
    )
    observed = observe(make_plan(), result, decisions)
    assert observed["budget_measurable"] is True and observed["completed"] is True
    assert observed["targets"] == [
        {"target_id": "T1", "detected": True, "first_hit_rank": 1, "hit_claims": 2,
         "unresolved_match": False},
        {"target_id": "T2", "detected": False, "first_hit_rank": None, "hit_claims": 0,
         "unresolved_match": True},
    ]
    assert observed["controls"] == [
        {"control_id": "C1", "type": "capability_safe", "decision": "quiet", "completed": True,
         "resolved": True, "false_allegation": False, "observed_false_allegation": False},
    ]
    assert observed["claims"] == {"records": 3, "unique": 2, "duplicate_copies": 1, "delivered": 3,
                                  "unmatched_unique": 1, "pending_matching": 1}
    scored = score(make_plan(), result, decisions)
    assert [t["detected"] for t in scored["targets"]] == [t["detected"] for t in observed["targets"]]
    assert scored["metrics"]["pending_matching_count"] == 1


def test_observe_marks_a_budget_unmeasurable_rather_than_missed():
    """Unranked output and unresolved bundles cannot answer a finite budget; that is not a miss."""
    from scaneval.scoring import observe

    unranked = make_result([claim("c1", "T1 specific root cause")], ranking="unranked")
    observed = observe(make_plan(), unranked, make_decisions(
        unranked, matches=[("c1", "T1", "accepted", "specific root cause")]))
    assert observed["budget_measurable"] is False
    assert observed["targets"][0]["detected"] is True and observed["targets"][0]["first_hit_rank"] is None
    assert observed["random_order"]["3"]["T1"] == 1.0 and observed["random_order"]["3"]["T2"] == 0.0
    bundled = make_result([claim("c1", "T1 specific root cause", rank=1)], bundles_resolved=False)
    observed = observe(make_plan(), bundled, make_decisions(
        bundled, matches=[("c1", "T1", "accepted", "specific root cause")]))
    assert observed["budget_measurable"] is False and observed["random_order"] is None
    assert observed["claims"]["delivered"] is None
