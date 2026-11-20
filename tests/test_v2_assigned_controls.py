"""Descriptive assigned-control bounds over harmless saved records; no scanner runs."""

from copy import deepcopy
import json

import pytest

from scaneval import aggregate, gate, review
from scaneval.cli import main
from scaneval.contracts import ContractError, canonical_json, load_document, validate_document
from test_v2_aggregate import (
    WORKLOAD, alias_control_run, control, planned, policy, scan, slice_of, system, view, write_run,
)
from test_v2_gate import minimal_policy


def controls(report, name="capability_safe", dimension="all", value=None):
    return slice_of(system(view(report)), dimension, value)["controls"][name]


def bounds(positive=0.0, negative=0.0):
    return {"state": "ok", "reason": None, "positive_mass": positive, "negative_mass": negative,
            "unknown_mass": 1 - positive - negative, "lower": positive, "upper": 1 - negative}


def one_run(tmp_path, spec, *, scope="reviewed"):
    return write_run(tmp_path, "synthetic", [planned("safe", scope=scope, controls=[control("C", level="fixture" if scope == "diagnostic" else "L3")])],
                     outcomes={("safe", "sys-a", 1): spec})


def test_partial_reviewed_positive_and_completed_reviewed_quiet_have_exact_half_bounds(tmp_path):
    run = write_run(tmp_path, "synthetic", [planned("safe", controls=[control("C", kind="both")])],
                    repetitions=2, outcomes={
                        ("safe", "sys-a", 2): scan(status="partial", resolved=False,
                                                       controls={"C": ("false_allegation", 1)})})
    report = aggregate.aggregate([run], policy=policy())
    for name in ("capability_safe", "fixed_target"):
        block = controls(report, name)
        assert block["assigned_population"] == bounds(0.5, 0.5)
        # Preserve the distinct existing estimand and its explicit incomplete-output count.
        assert block["completed_mass"] == 0.5
        assert block["resolved_rate"]["value"] == 0
        assert block["completed_lower"] == block["completed_upper"]["value"] == 0
        assert block["observed_false_allegations"] == 1
    assert any("assigned false-allegation bounds=[0.500, 0.500]" in line
               for line in aggregate.summary(report))


@pytest.mark.parametrize("status", ["success", "partial", "timeout", "error", "unsupported"])
@pytest.mark.parametrize("allegation", [False, True])
def test_status_eligibility_never_treats_incomplete_silence_as_reviewed_quiet(tmp_path, status, allegation):
    spec = scan(status=status, controls={"C": ("false_allegation", 1)} if allegation else {})
    run = one_run(tmp_path, spec)
    assigned = controls(aggregate.aggregate([run], policy=policy()))["assigned_population"]
    positive = float(allegation)
    negative = float(not allegation and status == "success")
    assert assigned == bounds(positive, negative)


@pytest.mark.parametrize("spec", ["missing_row", "missing_bundle", scan(controls={"C": "unresolved"}),
                                  scan(drop=("C",)), scan(resolved=False), scan(examined_nothing=True)])
def test_known_assigned_population_with_unknown_outcomes_has_zero_to_one_bounds(tmp_path, spec):
    run = one_run(tmp_path, spec)
    assert controls(aggregate.aggregate([run], policy=policy()))["assigned_population"] == bounds()


@pytest.mark.parametrize("allegation", [False, True])
@pytest.mark.parametrize("marking", ["draft", "missing", "stale", "draft_scope", "diagnostic"])
def test_approval_and_original_scope_are_required_without_upgrading_reference_labels(tmp_path, allegation, marking):
    spec = scan(controls={"C": ("false_allegation", 1)} if allegation else {},
                review_state="draft" if marking == "draft" else "approved")
    scope = "draft" if marking == "draft_scope" else "diagnostic" if marking == "diagnostic" else "reviewed"
    run = one_run(tmp_path, spec, scope=scope)
    evaluator = run / "invocations/safe__sys-a__r1/evaluator"
    if marking == "missing":
        (evaluator / review.RECORD_FILE).unlink()
    elif marking == "stale":
        # Keep schema-valid current decisions but invalidate the approval's digest binding.
        path = evaluator / review.DECISIONS_FILE
        document = json.loads(path.read_text())
        document["control_assessments"][0]["reason"] += " amended after approval"
        path.write_text(canonical_json(document) + "\n")
    report = aggregate.aggregate([run], policy=policy())
    assert controls(report)["assigned_population"] == bounds()
    assert view(report)["evidence_scope"] == ("diagnostic" if marking == "diagnostic" else "draft")


def test_canonical_alias_requires_every_reviewed_quiet_record_but_one_partial_positive_suffices(tmp_path):
    quiet_missing = alias_control_run(tmp_path / "quiet", "quiet", drop=("C-2",))
    partial_positive = alias_control_run(tmp_path / "positive", "positive", drop=("C-2",),
                                        controls={"C-1": ("false_allegation", 1)}, status="partial")
    assert controls(aggregate.aggregate([quiet_missing], policy=policy()))["assigned_population"] == bounds()
    assert controls(aggregate.aggregate([partial_positive], policy=policy()))["assigned_population"] == bounds(1)


def test_unequal_workload_input_and_repetition_weights_are_not_raw_observation_counts(tmp_path):
    # Workload A has weight 1/4, two canonical controls. C1 is on two inputs, C2 on one.
    # C1: positive 1/4, quiet 1/2, unknown 1/4; C2: quiet 1. Workload B (3/4): positive 1.
    # P = 1/4 * (1/2 * 1/4) + 3/4 = 25/32; N = 1/4 * (1/2 * 1/2 + 1/2) = 3/16.
    agentic = "agentic_application"
    inputs = [planned("a1", controls=[control("C1"), control("C2")]),
              planned("a2", controls=[control("C1")]),
              planned("b", workload=agentic, project="synthetic/b", controls=[control("C3")])]
    outcomes = {("a1", "sys-a", 1): scan(controls={"C1": ("false_allegation", 1)}),
                ("a1", "sys-a", 2): scan(controls={"C1": "unresolved"}),
                **{("b", "sys-a", trial): scan(status="partial", controls={"C3": ("false_allegation", 1)})
                   for trial in (1, 2)}}
    run = write_run(tmp_path, "weighted", inputs, repetitions=2, outcomes=outcomes)
    weighted_policy = {**policy(), "workload_weights": {WORKLOAD: 0.25, agentic: 0.75}}
    assigned = controls(aggregate.aggregate([run], policy=weighted_policy))["assigned_population"]
    assert assigned == bounds(25 / 32, 3 / 16)
    plain = aggregate.aggregate([run], policy=policy())
    assert controls(plain)["assigned_population"]["state"] == "unavailable"
    assert "workload weights" in controls(plain)["assigned_population"]["reason"]
    assert controls(plain, dimension="workload", value=agentic)["assigned_population"] == bounds(1)


@pytest.mark.parametrize("unplanned", [False, True])
def test_no_controls_or_unknown_frozen_population_is_unavailable_not_all_quiet(tmp_path, unplanned):
    inputs = [planned("empty")]
    if unplanned:
        inputs = [planned("safe", controls=[control("C")]), planned("unknown", project="synthetic/unknown", frozen=False)]
    run = write_run(tmp_path, "population", inputs)
    assigned = controls(aggregate.aggregate([run], policy=policy()))["assigned_population"]
    assert assigned["state"] == "unavailable" and assigned["reason"]
    assert all(assigned[key] is None for key in ("positive_mass", "negative_mass", "unknown_mass", "lower", "upper"))
    if unplanned:
        # A slice whose plans are known can still describe its assigned controls.
        assert "no frozen plan" in assigned["reason"]
        report = aggregate.aggregate([run], policy=policy())
        assert controls(report, dimension="project", value="acme/alpha")["assigned_population"] == bounds(0, 1)


def without_assigned(report):
    historical = deepcopy(report)
    for row in historical["views"]:
        systems = row["systems"].values() if isinstance(row["systems"], dict) else row["systems"]
        for item in systems:
            for block in item["slices"]:
                for control_block in block["controls"].values():
                    control_block.pop("assigned_population", None)
    return historical


def test_cli_aggregate_compare_roundtrip_and_historical_optional_fields_leave_gate_semantics(tmp_path, capsys):
    run = write_run(tmp_path, "roundtrip", [planned("safe", controls=[control("C")])],
                    systems=("base", "candidate"), repetitions=2,
                    outcomes={("safe", "candidate", 2): scan(status="partial", controls={"C": ("false_allegation", 1)})})
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(canonical_json(policy()))
    reports = {}
    for kind, extra in (("aggregate", []), ("compare", ["--baseline", "base", "--candidate", "candidate"])):
        path = tmp_path / (kind + ".json")
        assert main([kind, str(run), "--policy", str(policy_path), *extra, "--output", str(path)]) == 0
        schema = "comparison-report" if kind == "compare" else "aggregate-report"
        report = load_document(path, schema)
        assert canonical_json(load_document(path, schema)) == canonical_json(report)
        historical = without_assigned(report)
        validate_document(schema, historical)
        historical_path = tmp_path / (kind + "-historical.json")
        historical_path.write_text(canonical_json(historical))
        assert load_document(historical_path, schema) == historical
        reports[kind] = report, historical
    assert "assigned false-allegation bounds=[0.500, 0.500]" in capsys.readouterr().out
    current, historical = reports["compare"]
    gate_policy = {**minimal_policy(), "controls": {"capability_safe": {
        "max_false_alarm_upper": 0.1, "min_completed_mass": 0.5, "min_assessable_mass": 0.5}}}
    current_decision = gate.evaluate_gate(gate_policy, current)
    assert current_decision["requirements"] == gate.evaluate_gate(gate_policy, historical)["requirements"]
    assert next(item for item in current_decision["requirements"]
                if item["id"] == "controls.capability_safe.false_alarm_upper")["status"] == "pass"
    assert aggregate.comparison_summary(historical)
    assert aggregate.summary(reports["aggregate"][1])
    # Descriptive fields never enter existing paired differences.
    assert "assigned_population" not in current["views"][0]["differences"][0]["controls"]["capability_safe"]


@pytest.mark.parametrize("change", [{"unknown_mass": 0.4}, {"lower": 0.3}, {"upper": 0.2},
                                   {"state": "unavailable"}, {"positive_mass": -1}])
def test_added_report_fields_reject_inconsistent_or_unavailable_numbers(tmp_path, change):
    run = one_run(tmp_path, scan())
    report = aggregate.aggregate([run], policy=policy())
    controls(report)["assigned_population"].update(change)
    with pytest.raises(ContractError):
        validate_document("aggregate-report", report)


def test_unexecuted_assignments_remain_unknown_not_unsupported_negative_labels(tmp_path):
    for label, kwargs in (("preparation", {"failed_inputs": ("safe",)}),
                          ("system", {"skipped_systems": ("sys-a",)})):
        run = write_run(tmp_path / label, label, [planned("safe", controls=[control("C")])], **kwargs)
        assert controls(aggregate.aggregate([run], policy=policy()))["assigned_population"] == bounds()


def test_reviewed_timeout_positive_is_known_but_unreviewed_or_empty_timeout_is_unknown(tmp_path):
    inputs = [planned(name, controls=[control("C-" + name)])
              for name in ("positive", "empty", "missing-review")]
    outcomes = {("positive", "sys-a", 1): scan(status="timeout", controls={"C-positive": ("false_allegation", 1)}),
                ("empty", "sys-a", 1): scan(status="timeout"),
                ("missing-review", "sys-a", 1): scan(status="timeout",
                    controls={"C-missing-review": ("false_allegation", 1)})}
    run = write_run(tmp_path, "timeout", inputs, outcomes=outcomes)
    (run / "invocations/missing-review__sys-a__r1/evaluator" / review.RECORD_FILE).unlink()
    block = controls(aggregate.aggregate([run], policy=policy()))
    assert block["assigned_population"] == {**bounds(1 / 3), "unknown_mass": 2 / 3}
    assert block["completed_mass"] == 0
    assert block["completed_lower"] is None and block["completed_upper"]["value"] is None


def test_assigned_bounds_are_byte_deterministic_across_input_run_order(tmp_path):
    rows = [planned("safe", controls=[control("C")])]
    first = write_run(tmp_path, "first", rows, outcomes={("safe", "sys-a", 1):
        scan(status="partial", controls={"C": ("false_allegation", 1)})})
    second = write_run(tmp_path, "second", rows)
    forward = aggregate.aggregate([first, second], policy=policy())
    backward = aggregate.aggregate([second, first], policy=policy())
    assert canonical_json(forward) == canonical_json(backward)
    assert controls(forward)["assigned_population"] == bounds(0.5, 0.5)


def test_unusable_digest_binding_cannot_create_an_assigned_positive(tmp_path):
    run = one_run(tmp_path, scan(status="timeout", controls={"C": ("false_allegation", 1)}))
    result = run / "invocations/safe__sys-a__r1/result.json"
    document = json.loads(result.read_text())
    document["claims"][0]["allegation"] = "Amended harmless synthetic allegation after review"
    result.write_text(canonical_json(document) + "\n")
    report = aggregate.aggregate([run], policy=policy())
    assert controls(report)["assigned_population"] == bounds()
    assert system(view(report))["observations"]["failures"]["unusable_bundle"] == 1
