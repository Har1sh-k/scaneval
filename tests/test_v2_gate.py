"""Promotion gate decisions: the two contract kinds, then the gate over comparisons built from saved runs.

The contract tests use hand-written policies and decisions. The gate tests build run directories in
``tmp_path`` (a frozen schedule, a 2.1 manifest, and one invocation bundle per assignment whose plan,
result, decisions, and review record bind to one another the way ``scaneval run`` and the review
commands write them), then read them with the real :func:`scaneval.aggregate.compare` and the real
precision sampling and estimate. Reviewed evidence is approved through :mod:`scaneval.review` by a
reviewer, and precision claims are reviewed by reviewers, who are explicitly fictional. No scanner
runs, no network is used, and no model or judge is consulted.
"""

from __future__ import annotations

from copy import deepcopy
import json

import pytest

from scaneval.contracts import (
    CONTRACT_KINDS,
    SCHEMA_VERSIONS,
    ContractError,
    canonical_json,
    canonical_sha256,
    gate_declared_blocks,
    gate_requirement_ids,
    schema_file,
    validate_document,
)


ALL_BLOCKS = ("primary", "configuration", "regressions", "precision", "controls", "completion",
              "target_coverage", "burden", "cost")


# --- hand-written policies and decisions --------------------------------------------------------


def full_policy() -> dict:
    """A policy declaring every block, with fixture values chosen for these tests only."""
    return {
        "schema_version": "2.1", "policy_id": "fixture-gate", "policy_version": "1",
        "required_scope": "reviewed",
        "view": {"mode": "full", "profile": "standard"},
        "primary": {"metric": {"kind": "recall_at_budget", "budget": 5}, "weighting": "equal_target",
                    "slice": {"dimension": "all"}, "min_improvement": 0.1,
                    "uncertainty": {"lower_bound_above": 0.0, "min_confidence": 0.9, "min_clusters": 5}},
        "regressions": [
            {"id": "whole-view", "metric": {"kind": "full_recall"}, "weighting": "equal_target",
             "slice": {"dimension": "all"}, "max_decrease": 0.02, "check_interval": True},
            {"id": "each-project", "metric": {"kind": "full_recall"}, "weighting": "equal_target",
             "slice": {"dimension": "project"}, "max_decrease": 0.2}],
        "precision": {"basis": "resolved", "population": {"name": "first_b", "budget": 5},
                      "min_value": 0.5, "max_unresolved_share": 0.2,
                      "min_evidence_grade": "double_review_or_adjudicated", "min_coverage": 0.9,
                      "min_interval_lower_bound": 0.4, "max_decrease_vs_baseline": 0.05},
        "controls": {name: {"max_false_alarm_upper": 0.1, "min_completed_mass": 0.9, "min_assessable_mass": 0.9}
                     for name in ("capability_safe", "fixed_target")},
        "completion": {"min": 0.9, "max_decrease": 0.02},
        "target_coverage": {"min_assessable_mass": 0.9},
        "burden": {"max_claims_per_assignment": 10, "max_duplicate_share": 0.2, "max_increase_ratio": 2.0},
        "cost": {"min_coverage": 0.9, "max_per_assignment_usd": 1.0, "max_increase_ratio": 2.0},
        "configuration": {"allowed_differences": ["config.knob"]},
        "notes": ["Fixture values for these tests only."],
    }


def minimal_policy() -> dict:
    """The least a policy declares: a view, the primary metric and its change, and the configuration."""
    return {
        "schema_version": "2.1", "policy_id": "fixture-minimal", "policy_version": "1",
        "view": {"mode": "full", "profile": "standard"},
        "primary": {"metric": {"kind": "full_recall"}, "weighting": "equal_target", "min_improvement": 0.05},
        "configuration": {"allowed_differences": []},
    }


def system_record(system_id: str) -> dict:
    return {"system_id": system_id, "config_sha256": canonical_sha256({"fixture": system_id})}


def hand_decision(policy: dict, statuses: dict[str, str] | None = None) -> dict:
    """A decision that is derived from its own requirements: every one passes unless *statuses* says not."""
    statuses = statuses or {}
    requirements = [{"id": requirement_id, "status": statuses.get(requirement_id, "pass"), "observed": None,
                     "threshold": None, "explanation": f"fixture explanation of {requirement_id}"}
                    for requirement_id in gate_requirement_ids(policy)]
    found = [requirement["status"] for requirement in requirements]
    declared = gate_declared_blocks(policy)
    evidence = next(item for item in requirements if item["id"] == "evidence.scope")
    scope = ("none" if evidence["status"] != "pass" else
             "reviewed" if policy.get("required_scope", "reviewed") == "reviewed" else "development")
    return {
        "schema_version": "2.1", "evaluator_version": "2.0.0a1",
        "outcome": "fail" if "fail" in found else "inconclusive" if "inconclusive" in found else "pass",
        "recommendation_scope": scope,
        "policy": policy, "policy_sha256": canonical_sha256(policy),
        "blocks": {"declared": declared, "not_declared": [name for name in ALL_BLOCKS if name not in declared]},
        "view": policy["view"],
        "comparison": {"sha256": canonical_sha256({"fixture": "comparison"}), "evaluator_version": "2.0.0a1",
                       "policy_sha256": canonical_sha256({"fixture": "aggregation policy"}),
                       "contract_sha256": canonical_sha256({"fixture": "contract"}),
                       "baseline": system_record("baseline"), "candidate": system_record("candidate"),
                       "runs": [{"run_id": "run-a", "status": "completed",
                                 "manifest_sha256": canonical_sha256({"fixture": "manifest"}),
                                 "schedule_sha256": canonical_sha256({"fixture": "schedule"}),
                                 "config_sha256": canonical_sha256({"fixture": "config"}),
                                 "evidence_sha256": canonical_sha256({"fixture": "evidence"})}]},
        "precision": {"baseline": None, "candidate": None},
        "requirements": requirements,
        "summary": {"requirements": len(requirements), "passed": found.count("pass"),
                    "failed": found.count("fail"), "inconclusive": found.count("inconclusive")},
        "failed": [item["id"] for item in requirements if item["status"] == "fail"],
        "unresolved": [item["id"] for item in requirements if item["status"] == "inconclusive"],
        "notes": [],
    }


# --- the contract kinds ---------------------------------------------------------------------------


def test_the_gate_kinds_are_published_at_2_1_and_keep_their_plain_file_names():
    for kind in ("gate-policy", "gate-decision"):
        assert kind in CONTRACT_KINDS and SCHEMA_VERSIONS[kind] == ("2.1",)
        assert schema_file(kind, "2.1") == f"{kind}.schema.json"
    for kind, document in (("gate-policy", full_policy()), ("gate-decision", hand_decision(full_policy()))):
        assert validate_document(kind, document) is document
        with pytest.raises(ContractError, match="schema_version"):
            validate_document(kind, {**document, "schema_version": "2.0"})


def test_a_policy_declares_only_the_blocks_it_writes_and_the_decision_lists_them():
    """The primary metric and the configuration are always declared; every other block is chosen."""
    minimal = minimal_policy()
    assert validate_document("gate-policy", minimal) is minimal
    assert gate_declared_blocks(minimal) == ["primary", "configuration"]
    assert gate_requirement_ids(minimal) == [
        "contract.shared", "contract.runs_completed", "configuration.allowed_differences", "evidence.scope",
        "primary.improvement"]
    assert gate_declared_blocks(full_policy()) == list(ALL_BLOCKS)
    assert gate_requirement_ids(full_policy()) == [
        "contract.shared", "contract.runs_completed", "configuration.allowed_differences", "evidence.scope",
        "primary.improvement", "primary.uncertainty", "regression.whole-view", "regression.each-project",
        "precision.binding", "precision.min_value", "precision.max_unresolved_share",
        "precision.min_evidence_grade", "precision.min_coverage", "precision.interval",
        "precision.max_decrease",
        "controls.capability_safe.false_alarm_upper", "controls.capability_safe.completed_mass",
        "controls.capability_safe.assessable_mass", "controls.fixed_target.false_alarm_upper",
        "controls.fixed_target.completed_mass", "controls.fixed_target.assessable_mass",
        "completion.min", "completion.max_decrease", "target_coverage.min_assessable_mass",
        "burden.claims_per_assignment", "burden.duplicate_share", "burden.increase_ratio",
        "cost.coverage", "cost.per_assignment", "cost.increase_ratio"]
    decision = hand_decision(minimal)
    assert decision["blocks"] == {"declared": ["primary", "configuration"],
                                  "not_declared": list(ALL_BLOCKS[2:])}


def walk(node):
    """Every mapping in a parsed schema, at any depth."""
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def test_the_policy_schema_supplies_no_default_tolerance():
    """Nothing here is a recommended threshold: every tolerance is written by the policy's owner."""
    from importlib.resources import files
    for kind in ("gate-policy", "gate-decision"):
        schema = json.loads(files("scaneval").joinpath("schemas", f"{kind}.schema.json").read_text(encoding="utf-8"))
        assert not [node for node in walk(schema) if "default" in node], f"{kind} schema supplies a default"


@pytest.mark.parametrize("change, message", [
    (lambda d: d["primary"].pop("min_improvement"), "primary: 'min_improvement' is a required property"),
    (lambda d: d["primary"].update(metric={}), "primary.metric: 'kind' is a required property"),
    (lambda d: d["primary"].update(uncertainty={"min_confidence": 0.9}),
     "primary.uncertainty: 'lower_bound_above' is a required property"),
    (lambda d: d["precision"].pop("max_unresolved_share"),
     "precision: 'max_unresolved_share' is a required property"),
    (lambda d: d["precision"].pop("min_evidence_grade"), "precision: 'min_evidence_grade' is a required property"),
    (lambda d: d["precision"].update(population={"budget": 5}),
     "precision.population: 'name' is a required property"),
    (lambda d: d["controls"]["capability_safe"].pop("min_assessable_mass"),
     "controls.capability_safe: 'min_assessable_mass' is a required property"),
    (lambda d: d["controls"]["fixed_target"].pop("max_false_alarm_upper"),
     "controls.fixed_target: 'max_false_alarm_upper' is a required property"),
    (lambda d: d.update(target_coverage={}), "target_coverage: 'min_assessable_mass' is a required property"),
])
def test_a_threshold_the_policy_does_not_write_is_refused_not_supplied(change, message):
    """Omit any tolerance a declared block needs and the policy is refused: no value fills the gap."""
    document = full_policy()
    change(document)
    with pytest.raises(ContractError, match=message):
        validate_document("gate-policy", document)


@pytest.mark.parametrize("field", ["configuration", "view", "primary", "policy_id", "policy_version"])
def test_a_policy_must_state_its_view_primary_metric_and_configuration(field):
    document = minimal_policy()
    del document[field]
    with pytest.raises(ContractError, match=f"'{field}' is a required property"):
        validate_document("gate-policy", document)


@pytest.mark.parametrize("kind, message", [
    ("random_order_expected_recall", "random-order expectation, a diagnostic"),
    ("random_order_diagnostic", "random-order expectation, a diagnostic"),
    ("Random_Order", "random-order expectation, a diagnostic"),
    ("run_variability", "is a diagnostic, not a promotion metric"),
    ("leave_one_project_out", "is a diagnostic, not a promotion metric"),
    ("first_hit_ranks", "is a diagnostic, not a promotion metric"),
    ("pair_correctness", "is not a metric a gate reads"),
    ("f1", "is not a metric a gate reads"),
])
def test_a_policy_whose_primary_metric_is_a_random_order_expectation_or_any_diagnostic_is_refused(kind, message):
    """A promotion decision never rests on an expectation over an order the system did not choose."""
    primary = minimal_policy()
    primary["primary"]["metric"] = {"kind": kind}
    with pytest.raises(ContractError, match=f"primary.metric: '{kind}'.*{message}"):
        validate_document("gate-policy", primary)
    regression = full_policy()
    regression["regressions"][0]["metric"] = {"kind": kind}
    with pytest.raises(ContractError, match=f"regressions\\[whole-view\\].metric: '{kind}'.*{message}"):
        validate_document("gate-policy", regression)
    for allowed in ({"kind": "full_recall"}, {"kind": "recall_at_budget", "budget": 10}):
        accepted = minimal_policy()
        accepted["primary"]["metric"] = allowed
        assert validate_document("gate-policy", accepted) is accepted


@pytest.mark.parametrize("change, message", [
    (lambda d: d["primary"].update(metric={"kind": "recall_at_budget"}), "names the budget B it reads"),
    (lambda d: d["primary"].update(metric={"kind": "full_recall", "budget": 3}), "full_recall takes no budget"),
    (lambda d: d["primary"].update(slice={"dimension": "project"}), "a project slice names which project it is"),
    (lambda d: d["primary"].update(slice={"dimension": "all", "value": "acme/alpha"}),
     "the whole-view slice has no value"),
    (lambda d: d["regressions"][1].update(slice={"dimension": "all", "value": "acme/alpha"}),
     "the whole-view slice has no value"),
    (lambda d: d["regressions"].append(deepcopy(d["regressions"][0])), "regressions.id values must be unique"),
    (lambda d: d["precision"].update(population={"name": "first_b"}),
     "a budget is named exactly for the first_b population"),
    (lambda d: d["precision"].update(population={"name": "full", "budget": 5}),
     "a budget is named exactly for the first_b population"),
    (lambda d: d["precision"].update(basis="sensitivity_lower"), "only resolved precision has an interval"),
    (lambda d: d["primary"].update(min_improvement=0), "0 is less than or equal to the minimum of 0"),
    (lambda d: d["primary"].update(min_improvement=1.5), "1.5 is greater than the maximum of 1"),
    (lambda d: d["controls"]["capability_safe"].update(min_completed_mass=0),
     "0 is less than or equal to the minimum of 0"),
    (lambda d: d["burden"].update(max_duplicate_share=1.5), "1.5 is greater than the maximum of 1"),
    (lambda d: d.update(required_scope="diagnostic"), "'diagnostic' is not one of"),
    (lambda d: d.update(colour="blue"), "Additional properties are not allowed"),
    (lambda d: d.update(regressions=[]), "should be non-empty"),
    (lambda d: d.update(cost={}), "should be non-empty"),
])
def test_a_policy_that_cannot_be_read_is_refused_with_a_precise_reason(change, message):
    document = full_policy()
    change(document)
    with pytest.raises(ContractError, match=message):
        validate_document("gate-policy", document)


def test_a_policy_may_cover_every_project_but_the_primary_metric_names_one_slice():
    document = full_policy()
    assert document["regressions"][1]["slice"] == {"dimension": "project"}
    assert validate_document("gate-policy", document) is document
    document["regressions"][1]["slice"] = {"dimension": "workload", "value": "agentic_application"}
    assert validate_document("gate-policy", document) is document


def test_a_decision_is_derived_from_the_requirements_it_records():
    """The outcome, the failed and unresolved lists, and the counts follow from the requirement statuses."""
    policy = full_policy()
    for statuses, outcome in (({}, "pass"), ({"cost.coverage": "inconclusive"}, "inconclusive"),
                              ({"cost.coverage": "inconclusive", "completion.min": "fail"}, "fail")):
        decision = hand_decision(policy, statuses)
        assert decision["outcome"] == outcome
        assert validate_document("gate-decision", decision) is decision

    decision = hand_decision(policy, {"completion.min": "fail", "cost.coverage": "inconclusive"})
    assert decision["failed"] == ["completion.min"] and decision["unresolved"] == ["cost.coverage"]
    assert decision["summary"] == {"requirements": 30, "passed": 28, "failed": 1, "inconclusive": 1}

    for change, message in (
            (lambda d: d.update(outcome="pass"), "outcome is pass, but the requirement statuses give fail"),
            (lambda d: d.update(failed=[]), "failed must list the fail requirements"),
            (lambda d: d.update(unresolved=[]), "unresolved must list the inconclusive requirements"),
            (lambda d: d["summary"].update(passed=29), "summary must count the requirements"),
            (lambda d: d["requirements"].pop(0), "the requirements must be exactly the ones the embedded policy"),
            (lambda d: d["requirements"].reverse(), "the requirements must be exactly the ones the embedded policy"),
            (lambda d: d["blocks"].update(declared=["primary"]), "blocks must list the policy's declared"),
            (lambda d: d.update(view={"mode": "full", "profile": "metadata_blinded"}), "view must be the policy's view"),
            (lambda d: d["comparison"]["candidate"].update(system_id="baseline"), "two different systems"),
            (lambda d: d.update(recommendation_scope="development"), "recommendation_scope is development")):
        broken = hand_decision(policy, {"completion.min": "fail", "cost.coverage": "inconclusive"})
        change(broken)
        with pytest.raises(ContractError, match=message):
            validate_document("gate-decision", broken)


def test_a_decision_cannot_drop_a_failed_requirement_or_edit_its_own_policy():
    """Removing what failed, or loosening the policy it embeds, no longer matches what the decision carries."""
    policy = full_policy()
    failed = hand_decision(policy, {"precision.min_value": "fail"})
    dropped = deepcopy(failed)
    dropped["requirements"] = [item for item in dropped["requirements"] if item["id"] != "precision.min_value"]
    with pytest.raises(ContractError, match="exactly the ones the embedded policy declares"):
        validate_document("gate-decision", dropped)
    loosened = deepcopy(failed)
    loosened["policy"]["precision"]["min_value"] = 0.1
    with pytest.raises(ContractError, match="policy_sha256 does not hash the policy this decision carries"):
        validate_document("gate-decision", loosened)


def test_the_recommendation_scope_follows_the_policys_required_scope_and_the_evidence_requirement():
    """'reviewed' needs a reviewed policy and reviewed evidence; a draft policy is development; unmet is none."""
    reviewed = minimal_policy()
    assert hand_decision(reviewed)["recommendation_scope"] == "reviewed"
    assert hand_decision(reviewed, {"evidence.scope": "inconclusive"})["recommendation_scope"] == "none"
    draft = {**minimal_policy(), "required_scope": "draft"}
    assert validate_document("gate-decision", hand_decision(draft))["recommendation_scope"] == "development"
    assert hand_decision(draft, {"evidence.scope": "inconclusive"})["recommendation_scope"] == "none"
    for policy, scope in ((reviewed, "development"), (draft, "reviewed")):
        broken = hand_decision(policy)
        broken["recommendation_scope"] = scope
        with pytest.raises(ContractError, match="recommendation_scope is"):
            validate_document("gate-decision", broken)
    # A decision is never 'none' while it passes: an evidence requirement that did not pass makes it inconclusive.
    assert hand_decision(reviewed, {"evidence.scope": "inconclusive"})["outcome"] == "inconclusive"
    assert canonical_json(hand_decision(reviewed)) == canonical_json(hand_decision(reviewed))
