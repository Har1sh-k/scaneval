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


# --- a control on a path the scan did not examine ----------------------------------------------------------
#
# A change that touches only tests/server.test.js is a success when the scanner's own filter drops that file,
# though nothing was inspected, and a quiet assessment of the control planned there used to resolve it. A result
# may now list the paths its scanner did not examine and a plan control may say where it is.

SERVER_TEST = "tests/server.test.js"
QUIET = [("C1", "quiet", [], "the scanner said nothing about the control")]


def placed(control_id: str, paths: list[str] | None = None, *, kind: str = "capability_safe") -> dict:
    """A plan control; with *paths* the plan says where it is, and without them it places it nowhere."""
    control = {"control_id": control_id, "description": f"control {control_id}", "type": kind,
               "validation_level": "fixture"}
    if paths is not None:
        control["paths"] = paths
    return control


def omission_fixture(controls: list[dict], omitted: list[str] | None, assessments, *, claims=(),
                     examined_nothing: bool | None = None, **result_fields):
    """``(plan, result, decisions)``: a 2.1 plan of *controls* and a 2.1 result that lists *omitted*, if it lists any.

    The result says it ``examined_nothing`` only when that is given, as an adapter that does not report it does not.
    """
    plan = {**make_plan(controls=controls), "schema_version": "2.1"}
    result = {**make_result(list(claims), **result_fields), "schema_version": "2.1"}
    if omitted is not None:
        result["omitted_paths"] = omitted
    if examined_nothing is not None:
        result["examined_nothing"] = examined_nothing
    return plan, result, make_decisions(result, controls=assessments)


def withheld_warnings(record: dict) -> list[str]:
    return [warning for warning in record["warnings"] if "quiet control assessment(s) earn no credit" in warning]


def test_a_quiet_assessment_of_a_control_on_a_path_the_scan_did_not_examine_resolves_nothing():
    """The case the review found: the scan completed, and the control it never read was resolved quiet.

    The control stays a completed observation, as it was, and is no longer resolved. So the false-alarm bound counts
    it as unresolved, which is what the aggregate does for a control the plan lacks, and it is never dropped.
    """
    from scaneval.scoring import observe

    plan, result, decisions = omission_fixture([placed("C1", [SERVER_TEST])], [SERVER_TEST], QUIET)

    assert observe(plan, result, decisions)["controls"] == [
        {"control_id": "C1", "type": "capability_safe", "decision": "quiet", "completed": True,
         "resolved": False, "false_allegation": False, "observed_false_allegation": False}]
    record = score(plan, result, decisions)
    safe = record["metrics"]["controls"]["capability_safe"]
    assert (safe["assigned"], safe["completed"], safe["resolved"], safe["false_allegations"]) == (1, 1, 0, 0)
    assert safe["completion_mass"] == 1.0 and safe["assessable_mass"] == 0.0
    assert safe["resolved_false_alarm_rate"] is None
    assert safe["sensitivity_lower"] == 0.0 and safe["sensitivity_upper"] == 1.0
    [warning] = withheld_warnings(record)
    assert warning.startswith("1 quiet control assessment(s) earn no credit: the scan lists paths it did not examine")
    assert record["warnings"][-1] == warning


def test_a_control_on_an_examined_path_in_the_same_result_keeps_its_quiet_credit():
    from scaneval.scoring import observe

    plan, result, decisions = omission_fixture(
        [placed("C1", [SERVER_TEST]), placed("C2", ["src/app.py"])], [SERVER_TEST],
        [("C1", "quiet", [], "no claim"), ("C2", "quiet", [], "no claim")])

    rows = {row["control_id"]: row for row in observe(plan, result, decisions)["controls"]}
    assert (rows["C1"]["completed"], rows["C1"]["resolved"]) == (True, False)
    assert (rows["C2"]["completed"], rows["C2"]["resolved"]) == (True, True)
    record = score(plan, result, decisions)
    safe = record["metrics"]["controls"]["capability_safe"]
    assert (safe["assigned"], safe["completed"], safe["resolved"]) == (2, 2, 1)
    assert safe["resolved_false_alarm_rate"] == 0.0 and safe["sensitivity_upper"] == 0.5
    assert len(withheld_warnings(record)) == 1 and withheld_warnings(record)[0].startswith("1 quiet control")


def test_a_confirmed_false_allegation_on_an_omitted_path_still_counts():
    """A control is still failed by an allegation a reviewer confirmed: only silence is withheld."""
    from scaneval.scoring import observe

    alleged = claim("c1", "the handler runs the request body as a command", rank=1, path=SERVER_TEST)
    plan, result, decisions = omission_fixture(
        [placed("C1", [SERVER_TEST])], [SERVER_TEST], [("C1", "false_allegation", ["c1"], "confirmed")],
        claims=[alleged])

    row = observe(plan, result, decisions)["controls"][0]
    assert (row["completed"], row["resolved"], row["false_allegation"], row["observed_false_allegation"]) == (
        True, True, True, True)
    record = score(plan, result, decisions)
    safe = record["metrics"]["controls"]["capability_safe"]
    assert (safe["resolved"], safe["false_allegations"], safe["resolved_false_alarm_rate"]) == (1, 1, 1.0)
    assert withheld_warnings(record) == [], "nothing was withheld: the control was resolved by the allegation"


@pytest.mark.parametrize("omitted, resolved", [(["README.md"], False), ([], True), (None, True)],
                         ids=["lists-one", "lists-none", "no-listing"])
def test_a_control_the_plan_places_nowhere_earns_no_quiet_credit_when_the_result_lists_any_omission(omitted, resolved):
    """It cannot be shown to lie outside an omission, so it is counted as inside; with no omission it is not."""
    from scaneval.scoring import observe

    plan, result, decisions = omission_fixture([placed("C1")], omitted, QUIET)

    row = observe(plan, result, decisions)["controls"][0]
    assert (row["completed"], row["resolved"]) == (True, resolved)
    assert bool(withheld_warnings(score(plan, result, decisions))) is (not resolved)


@pytest.mark.parametrize("omitted, resolved", [
    (["lib/b.py"], False), (["lib/a.py", "lib/b.py"], False), (["lib/a.py", "lib/z.py"], False),
    (["lib/c.py"], True), (["lib"], True), (["Lib/a.py"], True), ([], True),
], ids=["second", "both", "first", "other-file", "its-directory", "another-case", "none"])
def test_a_control_is_unexamined_when_any_one_of_its_paths_is_omitted_and_paths_match_exactly(omitted, resolved):
    from scaneval.scoring import observe

    plan, result, decisions = omission_fixture([placed("C1", ["lib/a.py", "lib/b.py"])], omitted, QUIET)

    assert observe(plan, result, decisions)["controls"][0]["resolved"] is resolved


def test_a_control_of_both_classes_is_withheld_once_and_stays_completed_in_each():
    plan, result, decisions = omission_fixture([placed("C1", [SERVER_TEST], kind="both")], [SERVER_TEST], QUIET)

    record = score(plan, result, decisions)

    for name in ("capability_safe", "fixed_target"):
        control = record["metrics"]["controls"][name]
        assert (control["assigned"], control["completed"], control["resolved"]) == (1, 1, 0)
    assert withheld_warnings(record)[0].startswith("1 quiet control assessment(s)")


@pytest.mark.parametrize("fields", [{"status": "partial"}, {"status": "error"}, {"bundles_resolved": False}],
                         ids=["partial", "error", "unresolved-bundles"])
def test_the_warning_is_only_for_a_quiet_assessment_the_omission_alone_left_unresolved(fields):
    """A scan that did not complete, or whose bundles are unresolved, earned the control nothing for that reason."""
    from scaneval.scoring import observe

    plan, result, decisions = omission_fixture([placed("C1", [SERVER_TEST])], [SERVER_TEST], QUIET, **fields)

    assert observe(plan, result, decisions)["controls"][0]["resolved"] is False
    assert withheld_warnings(score(plan, result, decisions)) == []


def test_a_result_that_lists_no_omission_scores_exactly_as_it_did_and_the_new_fields_add_no_key():
    """The plan's paths and an empty list are inert, and nothing new reaches the record or the observation rows."""
    from scaneval.scoring import observe

    old_plan = make_plan(controls=[placed("C1")])
    old_result = make_result([claim("c1", "T1 specific root cause", rank=1)])
    old_decisions = make_decisions(old_result, matches=[("c1", "T1", "accepted", "specific root cause")],
                                   controls=QUIET)
    new_plan, new_result, new_decisions = omission_fixture(
        [placed("C1", ["src/app.py"])], [], QUIET, claims=[claim("c1", "T1 specific root cause", rank=1)])
    new_decisions["claim_matches"] = old_decisions["claim_matches"]

    old, new = score(old_plan, old_result, old_decisions), score(new_plan, new_result, new_decisions)

    digests = ("result_sha256", "plan_sha256", "decisions_sha256")
    assert {key: value for key, value in new.items() if key not in digests} == {
        key: value for key, value in old.items() if key not in digests}
    assert withheld_warnings(old) == [] and withheld_warnings(new) == []
    assert set(old["metrics"]["controls"]["capability_safe"]) == {
        "assigned", "completed", "resolved", "false_allegations", "observed_false_allegations",
        "resolved_false_alarm_rate", "sensitivity_lower", "sensitivity_upper", "completion_mass", "assessable_mass"}
    assert set(observe(new_plan, new_result, new_decisions)) == set(observe(old_plan, old_result, old_decisions)) == {
        "result_sha256", "plan_sha256", "decisions_sha256", "status", "ranking", "bundles_resolved", "completed",
        "valid_positive_output", "budget_measurable", "review_budgets", "targets", "controls", "random_order",
        "claims", "duplicate_groups", "usage"}


# --- a scan that examined none of what it was given -------------------------------------------------------
#
# The list of omitted paths covers the paths a change touches, so a control on a file the change leaves alone is
# not on it. A scan that examined none of the change reached that control no more than it reached the one on the
# test file, and a quiet assessment of it used to resolve it all the same.

UNCHANGED = "src/server.js"


def test_a_quiet_assessment_of_a_control_on_an_unchanged_file_resolves_nothing_when_the_scan_examined_nothing():
    """The case left open: the change touches only tests/server.test.js, the scan reads none of it, and succeeds.

    The control is the context kind, a safe capability in src/server.js that the change does not touch, so no list of
    the change's paths names it. The scan completed, nothing was examined, and the control stays a completed
    observation that is unresolved, counted in the false-alarm bound as it is for a control on the omitted path.
    """
    from scaneval.scoring import observe

    plan, result, decisions = omission_fixture(
        [placed("C1", [UNCHANGED])], [SERVER_TEST], QUIET, examined_nothing=True)

    assert observe(plan, result, decisions)["controls"] == [
        {"control_id": "C1", "type": "capability_safe", "decision": "quiet", "completed": True,
         "resolved": False, "false_allegation": False, "observed_false_allegation": False}]
    record = score(plan, result, decisions)
    safe = record["metrics"]["controls"]["capability_safe"]
    assert (safe["assigned"], safe["completed"], safe["resolved"], safe["false_allegations"]) == (1, 1, 0, 0)
    assert safe["completion_mass"] == 1.0 and safe["assessable_mass"] == 0.0
    assert safe["resolved_false_alarm_rate"] is None
    assert safe["sensitivity_lower"] == 0.0 and safe["sensitivity_upper"] == 1.0
    [warning] = withheld_warnings(record)
    assert warning == ("1 quiet control assessment(s) earn no credit: the scan examined none of the input it was given, "
                       "so its silence says nothing about any control.")
    assert record["warnings"][-1] == warning


def test_the_same_control_keeps_its_quiet_credit_when_the_scan_examined_some_of_the_change():
    """Examining part of the change is not examining nothing: the unchanged file is as it was, one the list never names."""
    from scaneval.scoring import observe

    for fields in ({"examined_nothing": False}, {}):
        plan, result, decisions = omission_fixture([placed("C1", [UNCHANGED])], [SERVER_TEST], QUIET, **fields)

        assert observe(plan, result, decisions)["controls"][0]["resolved"] is True
        assert withheld_warnings(score(plan, result, decisions)) == []


@pytest.mark.parametrize("controls, omitted", [
    ([placed("C1")], None), ([placed("C1")], []), ([placed("C1")], [SERVER_TEST]),
    ([placed("C1", [UNCHANGED])], None), ([placed("C1", [UNCHANGED])], []),
    ([placed("C1", [SERVER_TEST])], [SERVER_TEST]),
], ids=["unplaced-no-list", "unplaced-empty-list", "unplaced-listed", "placed-no-list", "placed-empty-list",
        "placed-on-an-omitted-path"])
def test_every_control_of_a_scan_that_examined_nothing_is_unexamined_wherever_the_plan_places_it(controls, omitted):
    """With or without the list beside it, and whether the plan places the control or not."""
    from scaneval.scoring import observe

    plan, result, decisions = omission_fixture(controls, omitted, QUIET, examined_nothing=True)

    row = observe(plan, result, decisions)["controls"][0]
    assert (row["completed"], row["resolved"]) == (True, False)
    assert len(withheld_warnings(score(plan, result, decisions))) == 1


def test_a_scan_that_examined_nothing_withholds_from_each_quiet_control_and_counts_only_those():
    """Three controls: two assessed quiet and one never assessed. The warning counts the two, each once."""
    from scaneval.scoring import observe

    plan, result, decisions = omission_fixture(
        [placed("C1", [UNCHANGED]), placed("C2"), placed("C3", ["src/other.js"])], [SERVER_TEST],
        [("C1", "quiet", [], "no claim"), ("C2", "quiet", [], "no claim")], examined_nothing=True)

    rows = {row["control_id"]: row for row in observe(plan, result, decisions)["controls"]}
    assert [(rows[name]["decision"], rows[name]["resolved"]) for name in ("C1", "C2", "C3")] == [
        ("quiet", False), ("quiet", False), ("unresolved", False)]
    [warning] = withheld_warnings(score(plan, result, decisions))
    assert warning.startswith("2 quiet control assessment(s) earn no credit: the scan examined none of the input")


def test_a_confirmed_false_allegation_still_counts_when_the_scan_examined_nothing():
    """Only silence is withheld: an allegation a reviewer confirmed fails the control, and resolves it."""
    from scaneval.scoring import observe

    alleged = claim("c1", "the handler runs the request body as a command", rank=1, path=UNCHANGED)
    plan, result, decisions = omission_fixture(
        [placed("C1", [UNCHANGED])], [SERVER_TEST], [("C1", "false_allegation", ["c1"], "confirmed")],
        claims=[alleged], examined_nothing=True)

    row = observe(plan, result, decisions)["controls"][0]
    assert (row["completed"], row["resolved"], row["false_allegation"]) == (True, True, True)
    record = score(plan, result, decisions)
    safe = record["metrics"]["controls"]["capability_safe"]
    assert (safe["resolved"], safe["false_allegations"], safe["resolved_false_alarm_rate"]) == (1, 1, 1.0)
    assert withheld_warnings(record) == []


@pytest.mark.parametrize("fields", [{"status": "partial"}, {"status": "error"}, {"bundles_resolved": False}],
                         ids=["partial", "error", "unresolved-bundles"])
def test_the_warning_for_a_scan_that_examined_nothing_is_only_for_what_that_alone_left_unresolved(fields):
    from scaneval.scoring import observe

    plan, result, decisions = omission_fixture(
        [placed("C1", [UNCHANGED])], [SERVER_TEST], QUIET, examined_nothing=True, **fields)

    assert observe(plan, result, decisions)["controls"][0]["resolved"] is False
    assert withheld_warnings(score(plan, result, decisions)) == []


def test_a_result_that_says_it_examined_some_scores_exactly_as_one_that_says_nothing():
    """``examined_nothing: false`` is inert, as the plan's paths and an empty list are, and adds no key anywhere."""
    from scaneval.scoring import observe

    plain = omission_fixture([placed("C1", [UNCHANGED])], [SERVER_TEST], QUIET)
    said = omission_fixture([placed("C1", [UNCHANGED])], [SERVER_TEST], QUIET, examined_nothing=False)

    old, new = score(*plain), score(*said)

    digests = ("result_sha256", "plan_sha256", "decisions_sha256")
    assert {key: value for key, value in new.items() if key not in digests} == {
        key: value for key, value in old.items() if key not in digests}
    assert set(observe(*said)) == set(observe(*plain))
    assert observe(*said)["controls"] == observe(*plain)["controls"]
