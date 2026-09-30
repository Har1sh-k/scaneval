"""Promotion gate decisions: the two contract kinds, then the gate over comparisons built from saved runs.

The contract tests use hand-written policies and decisions. Most gate tests build run directories in
``tmp_path`` (a frozen schedule, a 2.1 manifest, and one invocation bundle per assignment whose plan,
result, decisions, and review record bind to one another the way ``scaneval run`` and the review
commands write them), then read them with the real :func:`scaneval.aggregate.compare` and the real
precision sampling and estimate. The end-to-end tests run the real runner with scripted adapters over a
local ``git init`` fixture instead, and file their decisions through the real review commands. Every
reviewer, of a label, a bundle, or a claim, is explicitly fictional. No scanner runs, no network is
used, and no model or judge is consulted.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

import pytest

from scaneval import aggregate, cases, gate, precision, review, schedule
from scaneval.adapters.base import Adapter, NativeOutcome
from scaneval.cli import main
from scaneval.contracts import (
    CONTRACT_KINDS,
    SCHEMA_VERSIONS,
    ContractError,
    canonical_json,
    canonical_sha256,
    gate_declared_blocks,
    gate_requirement_ids,
    load_document,
    schema_file,
    validate_document,
)
from scaneval.runner import run_from_config


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
CREATED_AT = "2026-09-20T15:00:00+00:00"
REVIEWER = "Fixture Reviewer (fictional)"
REVIEWER_A = "Fixture Reviewer A (fictional)"
REVIEWER_B = "Fixture Reviewer B (fictional)"
WORKLOAD = "conventional_application"
PACK = {"namespace": "org.example", "pack_id": "gate-fixture", "version": "1.0.0",
        "sha256": "sha256:" + "a" * 64}
NO_SELECTION = {"only_inputs": None, "only_systems": None, "excluded_inputs": [], "excluded_systems": []}
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
            (lambda d: d.update(view={"mode": "full", "profile": "metadata_blinded"}),
             "view must be the policy's view"),
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


# --- fixture run directories ------------------------------------------------------------------------


def digest(label: str) -> str:
    return canonical_sha256({"fixture": label})


def input_hash(input_id: str) -> str:
    return digest(f"tree/{input_id}")


def target(target_id: str, *, project: str, family: str, canonical: str | None = None,
           workload: str = WORKLOAD, level: str = "L3") -> dict:
    """One planned target as a schedule freezes it."""
    return {"target_id": target_id, "case_id": f"case-{target_id}", "canonical_id": canonical or target_id,
            "kind": "command_injection", "variant_family": family, "workload": workload,
            "component_role": "application", "project": project, "validation_level": level}


def control(control_id: str, *, kind: str = "capability_safe", target_id: str | None = None,
            level: str = "L3") -> dict:
    """One planned control as a schedule freezes it."""
    return {"control_id": control_id, "case_id": f"case-{target_id or control_id}", "canonical_id": control_id,
            "type": kind, "target_id": target_id, "validation_level": level}


def planned(input_id: str, *, targets=(), controls=(), project: str, workload: str = WORKLOAD,
            scope: str = "reviewed", budgets=(1, 5)) -> dict:
    """One schedule input row with a frozen plan."""
    return {"input_id": input_id, "mode": "full", "profile": "standard", "snapshot_id": input_id,
            "change_set_id": None, "change_set": None, "blinding": None, "project": project,
            "workload": workload, "component_role": "application", "declared_tree_hash": input_hash(input_id),
            "plan": {"state": "frozen", "scope": scope, "review_budgets": list(budgets),
                     "targets": list(targets), "controls": list(controls), "notes": []}}


def scan(*, hits=None, claims: int | None = None, ranking: str = "native", status: str = "success",
         resolved: bool = True, controls=None, pending=None, usage=None, review_state: str = "approved",
         duplicate: bool = False, scope: str | None = None) -> dict:
    """What one bundle holds.

    ``hits`` maps a target id to the 1-based position of the claim a reviewer accepted for it, and
    ``pending`` does the same for a match the reviewer left unresolved; ``controls`` maps a control id
    to ``"quiet"``, ``"unresolved"``, or ``("false_allegation", position)``. ``duplicate`` makes every
    delivered claim an exact copy of the first, which is how a system spams the reviewer without adding
    an allegation.
    """
    return {"hits": hits or {}, "claims": claims, "ranking": ranking, "status": status, "resolved": resolved,
            "controls": controls or {}, "pending": pending or {},
            "usage": usage if usage is not None else {"wall_seconds": 1.0},
            "review_state": review_state, "duplicate": duplicate, "scope": scope}


def _plan_item(item: dict, kind: str) -> dict:
    if kind == "targets":
        return {"target_id": item["target_id"], "description": f"fixture target {item['target_id']}",
                "validation_level": item["validation_level"], "kind": "command_injection"}
    return {"control_id": item["control_id"], "description": f"fixture control {item['control_id']}",
            "type": item["type"], "validation_level": item["validation_level"],
            **({"target_id": item["target_id"]} if item["target_id"] else {})}


def write_bundle(bundle: Path, run_id: str, assignment: dict, row: dict, spec: dict) -> tuple[dict, dict, dict]:
    """Write one invocation bundle: result, execution record, plan, decisions, and review record."""
    frozen = row["plan"]
    bound = input_hash(row["input_id"])
    plan = {"schema_version": "2.0", "input_hash": bound, "scope": spec["scope"] or frozen["scope"],
            "targets": [_plan_item(item, "targets") for item in frozen["targets"]],
            "controls": [_plan_item(item, "controls") for item in frozen["controls"]],
            "review_budgets": frozen["review_budgets"]}
    positions = list(spec["hits"].values()) + list(spec["pending"].values())
    positions += [value[1] for value in spec["controls"].values() if isinstance(value, tuple)]
    count = spec["claims"] if spec["claims"] is not None else max(positions, default=0)
    native = spec["ranking"] == "native"
    same = 1 if spec["duplicate"] else None
    claims = [{"claim_id": f"c{index}", "allegation": f"fixture allegation {same or index}",
               "kind": "command_injection",
               "primary_location": {"path": f"src/file{same or index}.py", "start_line": same or index,
                                    "end_line": same or index},
               **({"rank": index} if native else {})} for index in range(1, count + 1)]
    result = {"schema_version": "2.0", "run_id": run_id, "system_id": assignment["system_id"],
              "input_hash": bound, "status": spec["status"], "ranking": spec["ranking"], "claims": claims,
              "bundles_resolved": spec["resolved"], "usage": dict(spec["usage"])}
    matches = [{"claim_id": f"c{position}", "target_id": target_id, "decision": "accepted",
                "reason": "fixture: accepted by a fictional reviewer"}
               for target_id, position in spec["hits"].items()]
    matches += [{"claim_id": f"c{position}", "target_id": target_id, "decision": "unresolved",
                 "reason": "fixture: pending"} for target_id, position in spec["pending"].items()]
    assessments = []
    for item in plan["controls"]:
        decision = spec["controls"].get(item["control_id"], "quiet")
        if isinstance(decision, tuple):
            assessments.append({"control_id": item["control_id"], "decision": decision[0],
                                "claim_ids": [f"c{decision[1]}"], "reason": "fixture: false allegation"})
        else:
            assessments.append({"control_id": item["control_id"], "decision": decision, "claim_ids": [],
                                "reason": f"fixture: {decision}"})
    decisions = {"schema_version": "2.0", "run_id": run_id, "input_hash": bound,
                 "result_sha256": canonical_sha256(result), "claim_matches": matches,
                 "control_assessments": assessments}
    record = review.review_record(plan, decisions, clock=CLOCK)
    if spec["review_state"] == "approved":
        record = review.approve_review(record, decisions, plan, reviewer=REVIEWER,
                                       note="fixture approval by a fictional reviewer", clock=CLOCK)
    bundle.mkdir(parents=True)
    (bundle / "result.json").write_text(canonical_json(result) + "\n", encoding="utf-8")
    execution = {
        "schema_version": "2.0", "run_id": run_id, "invocation_id": assignment["assignment_id"],
        "input_id": assignment["input_id"], "system_id": assignment["system_id"],
        "repetition": assignment["repetition"], "adapter": {"name": "fake", "version": "1.0.0"},
        "versions": {}, "status": spec["status"], "exit_code": 0, "timed_out": spec["status"] == "timeout",
        "command": [], "started_at": CREATED_AT, "finished_at": "2026-09-20T15:00:01+00:00",
        "wall_seconds": 1.0, "timeout_seconds": 60, "tool_versions": {}, "model_identity": None,
        "system_config": {}, "network_policy": {"declared": "none", "enforced": False, "note": "fixture"},
        "environment": {"passthrough": []}, "capture": {}, "trace": None,
        "provenance": {"tree_hash": bound, "provenance_sha256": digest("provenance"), "profile": row["profile"],
                       "synthetic_history": None, "source_modified": False, "modified_paths": [],
                       "captured_state_dirs": []},
        "preparation": {}, "unsupported_languages": [], "error": None, "import_error": None, "notes": [],
        "raw_artifacts": []}
    validate_document("execution-record", execution)
    (bundle / "execution.json").write_text(canonical_json(execution) + "\n", encoding="utf-8")
    review.write_evaluator_records(bundle, plan, decisions, record)
    return result, plan, record


def write_run(root: Path, run_id: str, inputs: list[dict], *, systems, repetitions: int = 1, outcomes=None,
              configs=None, failed_inputs=(), skipped_systems=(), run_status: str = "completed") -> Path:
    """Write one run directory the way ``scaneval run`` lays it out, with hand-chosen outcomes.

    *outcomes* maps ``(input_id, system_id, repetition)`` to a :func:`scan` spec; unlisted
    assignments are successful scans that detect nothing. An input in *failed_inputs* was never
    prepared, and a system in *skipped_systems* was never invoked.
    """
    outcomes = outcomes or {}
    configs = configs or {}
    directory = root / run_id
    (directory / "evaluator").mkdir(parents=True)
    entries = [{"system_id": system_id, "adapter": "fake", "config": {"knob": 1}, **configs.get(system_id, {})}
               for system_id in systems]
    config = {"schema_version": "2.1", "run_id": run_id, "pack": "pack.json",
              "inputs": [{"input_id": row["input_id"], "snapshot_id": row["snapshot_id"]} for row in inputs],
              "systems": entries, "repetitions": repetitions, "timeout_seconds": 60, "trace_mode": "off",
              "network_policy": "none"}
    validate_document("run-config", config)
    assignments = sorted(({"assignment_id": f"{row['input_id']}__{system_id}__r{repetition}",
                           "input_id": row["input_id"], "system_id": system_id, "repetition": repetition}
                          for row in inputs for system_id in systems for repetition in range(1, repetitions + 1)),
                         key=lambda item: (item["input_id"], item["system_id"], item["repetition"]))
    frozen_schedule = {
        "schema_version": "2.1", "run_id": run_id, "created_at": CREATED_AT,
        "config_sha256": canonical_sha256(config), "pack": PACK, "repetitions": repetitions, "inputs": inputs,
        "systems": [{"system_id": entry["system_id"], "adapter": entry["adapter"],
                     "model_id": entry.get("model_id"), "model_revision": entry.get("model_revision"),
                     "config_sha256": canonical_sha256(entry["config"]), "network_policy": "none",
                     "execution": {"backend": "local", "enforced_expected": False, "image": None}}
                    for entry in entries],
        "assignments": assignments, "pairs": schedule._pairs(inputs, repetitions),
        "notes": ["Hand-built fixture schedule."]}
    validate_document("evaluation-schedule", frozen_schedule)
    rows = {row["input_id"]: row for row in inputs}
    invocations = []
    for assignment in assignments:
        row = {"invocation_id": assignment["assignment_id"], **{key: assignment[key] for key in (
            "input_id", "system_id", "repetition")}}
        skipped = {"status": "skipped", "claim_records": None, "plan_scope": None, "targets_assigned": None,
                   "targets_detected": None, "pending_matching_count": None, "bundle_path": None,
                   "review_state": None}
        if assignment["input_id"] in failed_inputs:
            invocations.append({**row, **skipped, "skipped_reason": (
                f"input {assignment['input_id']} could not be prepared: MaterializationError: fixture "
                "export refused")})
            continue
        if assignment["system_id"] in skipped_systems:
            invocations.append({**row, **skipped, "skipped_reason": "AdapterError: fixture system not installed"})
            continue
        spec = outcomes.get((assignment["input_id"], assignment["system_id"], assignment["repetition"]), scan())
        path = f"invocations/{assignment['assignment_id']}"
        result, plan, record = write_bundle(directory / path, run_id, assignment, rows[assignment["input_id"]], spec)
        invocations.append({**row, "status": result["status"], "claim_records": len(result["claims"]),
                            "plan_scope": plan["scope"], "targets_assigned": len(plan["targets"]),
                            "targets_detected": 0, "pending_matching_count": 0, "bundle_path": path,
                            "review_state": record["state"], "skipped_reason": None})
    manifest = {
        "schema_version": "2.1", "run_id": run_id, "status": run_status, "created_at": CREATED_AT,
        "config_sha256": canonical_sha256(config),
        "pack": {"namespace": PACK["namespace"], "pack_id": PACK["pack_id"], "version": PACK["version"],
                 "status": "draft", "snapshots": len(inputs), "cases": 0,
                 "review_states": {"draft": 0, "mechanically_checked": 0, "human_approved": 0},
                 "dispositions": {"validate": 0, "needs_evidence": 0, "extended_regression": 0, "exclude": 0},
                 "sha256": digest("frozen pack")},
        "selection": NO_SELECTION,
        "inputs": [{"input_id": row["input_id"], "mode": "full", "profile": row["profile"],
                    "snapshot_id": row["snapshot_id"],
                    "tree_hash": None if row["input_id"] in failed_inputs else input_hash(row["input_id"]),
                    "input_hash": None if row["input_id"] in failed_inputs else input_hash(row["input_id"]),
                    "provenance_path": None, "mechanical_checks": [],
                    "preparation_failure": ({"type": "MaterializationError", "message": "fixture export refused"}
                                            if row["input_id"] in failed_inputs else None)} for row in inputs],
        "systems": [{"system_id": system_id, "adapter": "fake", "adapter_version": "1.0.0", "preparation": {},
                     "skipped_reason": ("AdapterError: fixture system not installed"
                                        if system_id in skipped_systems else None)} for system_id in systems],
        "invocations": invocations, "warnings": [], "schedule_path": "evaluator/schedule.json"}
    validate_document("run-manifest", manifest)
    for relative, document in (("run-config.json", config), ("evaluator/schedule.json", frozen_schedule),
                               ("run-manifest.json", manifest)):
        (directory / relative).write_text(canonical_json(document) + "\n", encoding="utf-8")
    return directory


def aggregation_policy(**uncertainty) -> dict:
    """The default aggregation policy with a smaller replicate count, or other settings, for speed."""
    document = json.loads(canonical_json(aggregate.DEFAULT_POLICY))
    document["uncertainty"].update({"replicates": 200, "seed": 7, **uncertainty})
    return document


# --- the scenario corpus ----------------------------------------------------------------------------

PROJECTS = 10
SYSTEMS = ("baseline", "improved", "silent", "flagging", "duplicating", "malformed", "regressing", "late",
           "unranked", "flaky")
CANDIDATES = tuple(name for name in SYSTEMS if name != "baseline")


def corpus_inputs() -> list[dict]:
    """Ten projects, one input, one target, and one capability-safe control each; every target in its own family."""
    return [planned(f"p{index}", project=f"acme/p{index}",
                    targets=[target(f"T-p{index}", project=f"acme/p{index}", family=f"family-{index}")],
                    controls=[control(f"C-p{index}")])
            for index in range(1, PROJECTS + 1)]


# What each priced system reports a successful scan cost, in USD; every other system reports no cost at all.
COST = {"baseline": 0.10, "improved": 0.15, "flaky": 0.15}


def behave(system: str, index: int) -> dict:
    """What one system does on project *index*, with the cost its successful scans report."""
    spec = behavior(system, index)
    if system in COST and spec["status"] == "success":
        spec["usage"] = {"wall_seconds": 1.0, "cost_usd": COST[system]}
    return spec


def behavior(system: str, index: int) -> dict:
    """What one system does on project *index*; every scan delivers native-ranked claims.

    - baseline detects T-p1 and T-p2 with one claim per scan (recall 2/10).
    - improved detects T-p1 to T-p8 with one claim per scan (recall 8/10), quiet on every control.
    - silent delivers nothing at all.
    - flagging detects every target among 12 claims per scan and falsely alleges every control.
    - duplicating detects what the baseline does, delivering the same claim 20 times per scan.
    - malformed returns an error on every scan.
    - regressing detects T-p2 to T-p8: better overall, but it loses the baseline's T-p1.
    - late detects T-p1 to T-p8, but only at position 3 of three claims.
    - unranked detects T-p1 to T-p8 in output that has no native order.
    - flaky detects T-p1 to T-p8 like improved, but its scans of the last two projects end in an error.
    """
    goal, guard = f"T-p{index}", f"C-p{index}"
    if system == "baseline":
        return scan(hits={goal: 1} if index <= 2 else {}, claims=1)
    if system == "improved":
        return scan(hits={goal: 1} if index <= 8 else {}, claims=1)
    if system == "silent":
        return scan(claims=0)
    if system == "flagging":
        return scan(hits={goal: 1}, claims=12, controls={guard: ("false_allegation", 2)})
    if system == "duplicating":
        return scan(hits={goal: 1} if index <= 2 else {}, claims=20, duplicate=True)
    if system == "malformed":
        return scan(status="error", claims=0)
    if system == "regressing":
        return scan(hits={goal: 1} if 2 <= index <= 8 else {}, claims=1)
    if system == "late":
        return scan(hits={goal: 3} if index <= 8 else {}, claims=3)
    if system == "unranked":
        return scan(hits={goal: 1} if index <= 8 else {}, claims=1, ranking="unranked")
    if system == "flaky":
        return scan(hits={goal: 1}, claims=1) if index <= 8 else scan(status="error", claims=0)
    raise AssertionError(system)


@pytest.fixture(scope="module")
def corpus(tmp_path_factory) -> dict:
    """One run of every system over the ten-project corpus, and each candidate's comparison with the baseline.

    Built once and shared: no test modifies it, and a test that changes a comparison copies it first.
    """
    root = tmp_path_factory.mktemp("gate-corpus")
    outcomes = {(f"p{index}", system, 1): behave(system, index)
                for index in range(1, PROJECTS + 1) for system in SYSTEMS}
    run = write_run(root, "run-gate", corpus_inputs(), systems=SYSTEMS, outcomes=outcomes,
                    configs={name: {"config": {"knob": 2}} for name in CANDIDATES})
    comparisons = {name: aggregate.compare([run], baseline="baseline", candidate=name,
                                           policy=aggregation_policy()) for name in CANDIDATES}
    return {"root": root, "run": run, "comparisons": comparisons}


def gate_policy(**blocks) -> dict:
    """A policy over the corpus: the improvement a change must make and the one configuration key it changes."""
    document = {
        "schema_version": "2.1", "policy_id": "fixture-gate", "policy_version": "1",
        "view": {"mode": "full", "profile": "standard"},
        "primary": {"metric": {"kind": "full_recall"}, "weighting": "equal_target", "min_improvement": 0.05},
        "configuration": {"allowed_differences": ["config.knob"]},
    }
    document.update(blocks)
    return document


def decide(corpus: dict, policy: dict, system: str = "improved", **estimates) -> dict:
    return gate.evaluate_gate(policy, corpus["comparisons"][system], **estimates)


def requirement(decision: dict, requirement_id: str) -> dict:
    return next(item for item in decision["requirements"] if item["id"] == requirement_id)


def statuses(decision: dict) -> dict[str, str]:
    return {item["id"]: item["status"] for item in decision["requirements"]}


def primary(kind: str = "full_recall", budget: int | None = None, weighting: str = "equal_target",
            minimum: float = 0.05, **extra) -> dict:
    metric = {"kind": kind} if budget is None else {"kind": kind, "budget": budget}
    return {"metric": metric, "weighting": weighting, "min_improvement": minimum, **extra}


def difference_of(comparison: dict, weighting: str = "equal_target") -> dict:
    """The whole-view detection difference block of a comparison's only view."""
    whole = next(item for item in comparison["views"][0]["differences"] if item["slice"]["dimension"] == "all")
    return next(item for item in whole["detection"] if item["weighting"] == weighting)


# --- the outcome, and what every requirement reports ----------------------------------------------


def test_a_genuine_improvement_passes_when_every_declared_requirement_holds(corpus):
    """The improved system detects 8 of 10 targets against the baseline's 2: recall 0.2 to 0.8, +0.6.

    One target per project makes equal_target and equal_project alike. Nothing regresses: T-p1 and
    T-p2 stay detected, T-p3 to T-p8 are gained, and T-p9 and T-p10 are missed by both.
    """
    policy = gate_policy(regressions=[
        {"id": "whole-view", "metric": {"kind": "full_recall"}, "weighting": "equal_target", "max_decrease": 0.0},
        {"id": "each-project", "metric": {"kind": "full_recall"}, "weighting": "equal_project",
         "slice": {"dimension": "project"}, "max_decrease": 0.0}])

    decision = decide(corpus, policy)

    assert decision["outcome"] == "pass" and decision["recommendation_scope"] == "reviewed"
    assert statuses(decision) == {
        "contract.shared": "pass", "contract.runs_completed": "pass", "configuration.allowed_differences": "pass",
        "evidence.scope": "pass", "primary.improvement": "pass", "regression.whole-view": "pass",
        "regression.each-project": "pass"}
    assert decision["failed"] == [] and decision["unresolved"] == []
    improvement = requirement(decision, "primary.improvement")
    assert improvement["observed"] == {"baseline": 0.2, "candidate": 0.8, "difference": 0.6}
    assert improvement["explanation"] == ("full-output recall (equal_target, the whole view) went from 0.2 to 0.8, "
                                          "+0.6, at least the required +0.05")
    assert validate_document("gate-decision", decision) is decision


def test_the_outcome_is_fail_if_any_requirement_fails_else_inconclusive_else_pass(corpus):
    """Three policies over one comparison: everything holds, one requirement is unresolved, one also fails."""
    assert decide(corpus, gate_policy())["outcome"] == "pass"

    unresolved = decide(corpus, gate_policy(configuration={"allowed_differences": []}))
    assert unresolved["outcome"] == "inconclusive"
    assert unresolved["failed"] == [] and unresolved["unresolved"] == ["configuration.allowed_differences"]

    failing = decide(corpus, gate_policy(configuration={"allowed_differences": []},
                                         primary=primary(minimum=0.9)))
    assert statuses(failing)["configuration.allowed_differences"] == "inconclusive"
    assert statuses(failing)["primary.improvement"] == "fail"
    assert failing["outcome"] == "fail", "a failure outranks an unresolved requirement"
    assert failing["failed"] == ["primary.improvement"]
    assert failing["unresolved"] == ["configuration.allowed_differences"]
    assert failing["summary"] == {"requirements": 5, "passed": 3, "failed": 1, "inconclusive": 1}


def test_every_requirement_reports_the_five_fields_and_every_failure_is_explained(corpus):
    decision = decide(corpus, gate_policy(configuration={"allowed_differences": []},
                                          primary=primary(minimum=0.9)))

    for item in decision["requirements"]:
        assert set(item) == {"id", "status", "observed", "threshold", "explanation"}
        assert item["status"] in ("pass", "fail", "inconclusive")
        assert isinstance(item["explanation"], str) and len(item["explanation"]) > 20
    assert requirement(decision, "primary.improvement")["explanation"] == (
        "full-output recall (equal_target, the whole view) went from 0.2 to 0.8, +0.6, below the required +0.9")
    assert requirement(decision, "primary.improvement")["threshold"] == {
        "metric": {"kind": "full_recall"}, "weighting": "equal_target", "slice": {"dimension": "all"},
        "min_improvement": 0.9}
    unresolved = requirement(decision, "configuration.allowed_differences")
    assert unresolved["observed"] == {"differences": ["config.knob"], "not_allowed": ["config.knob"]}
    assert unresolved["explanation"] == ("the systems also differ in config.knob, which the policy does not intend "
                                         "to measure, so the comparison does not isolate the intended change")


def test_an_always_silent_candidate_fails_the_primary_improvement(corpus):
    """The silent system quietly delivers nothing: recall 0 against the baseline's 0.2, a change of -0.2."""
    decision = decide(corpus, gate_policy(), "silent")

    assert decision["outcome"] == "fail" and decision["failed"] == ["primary.improvement"]
    assert requirement(decision, "primary.improvement")["explanation"] == (
        "full-output recall (equal_target, the whole view) went from 0.2 to 0, -0.2, below the required +0.05")


def test_a_candidate_that_only_matches_the_baseline_fails_the_primary_improvement(corpus):
    """The duplicating system detects T-p1 and T-p2 like the baseline: 0.2 to 0.2, however many copies it sends."""
    decision = decide(corpus, gate_policy(), "duplicating")

    assert decision["outcome"] == "fail" and decision["failed"] == ["primary.improvement"]
    assert requirement(decision, "primary.improvement")["observed"]["difference"] == 0.0


def test_a_malformed_output_candidate_loses_the_detection_it_never_delivered(corpus):
    """An error on every scan detects nothing: recall 0 against 0.2, so the primary requirement fails."""
    decision = decide(corpus, gate_policy(), "malformed")

    assert decision["outcome"] == "fail"
    assert requirement(decision, "primary.improvement")["observed"] == {
        "baseline": 0.2, "candidate": 0.0, "difference": -0.2}


def test_the_primary_metric_may_be_recall_at_a_budget(corpus):
    """The late system finds T-p1 to T-p8, but at position 3: recall@5 0.8 against 0.2, recall@1 0 against 0.2."""
    at_five = decide(corpus, gate_policy(primary=primary("recall_at_budget", 5, minimum=0.5)), "late")
    assert at_five["outcome"] == "pass"
    assert requirement(at_five, "primary.improvement")["observed"] == {
        "baseline": 0.2, "candidate": 0.8, "difference": 0.6}
    assert requirement(at_five, "primary.improvement")["explanation"].startswith("recall@5 (equal_target, ")

    at_one = decide(corpus, gate_policy(primary=primary("recall_at_budget", 1, minimum=0.05)), "late")
    assert at_one["outcome"] == "fail"
    assert requirement(at_one, "primary.improvement")["observed"] == {
        "baseline": 0.2, "candidate": 0.0, "difference": -0.2}


def test_recall_at_a_budget_is_inconclusive_for_unranked_output_and_no_random_order_expectation_replaces_it(corpus):
    """Unranked output has no native position, so recall@5 is null and the gate does not pass.

    The comparison does hold the random-order diagnostic for the unranked system, but a position nobody
    measured is not replaced by an expectation over positions nobody chose; full-output recall, which
    needs no rank, still passes on the same output.
    """
    comparison = corpus["comparisons"]["unranked"]
    block = next(item for item in comparison["views"][0]["systems"]["candidate"]["slices"][0]["detection"]
                 if item["weighting"] == "equal_target")
    assert block["recall_at_budget"][1]["value"] is None and block["random_order_diagnostic"]["observation_mass"] > 0

    decision = decide(corpus, gate_policy(primary=primary("recall_at_budget", 5)), "unranked")

    assert decision["outcome"] == "inconclusive"
    item = requirement(decision, "primary.improvement")
    assert item["status"] == "inconclusive" and item["observed"] is None
    assert item["explanation"] == (
        "recall@5 cannot be measured for unranked: its output is unranked or its bundles are unresolved, so no "
        "native position is known, and a random-order expectation is never substituted for one")
    assert decide(corpus, gate_policy(), "unranked")["outcome"] == "pass"


@pytest.mark.parametrize("changes, reason", [
    ({"primary": primary("recall_at_budget", 7)},
     "the comparison reports no recall@7 for the whole view of full/standard (its budgets are 1, 5)"),
    ({"primary": primary(weighting="explicit")},
     "the comparison's aggregation policy reports no explicit weighting (it reports equal_target, "
     "equal_project, equal_family)"),
    ({"primary": primary(slice={"dimension": "project", "value": "acme/none"})},
     "the comparison has no project acme/none of full/standard"),
    ({"primary": primary(slice={"dimension": "workload", "value": "agentic_application"})},
     "the comparison has no workload agentic_application of full/standard"),
    ({"view": {"mode": "pr", "profile": "standard"}}, "the comparison has no pr/standard view"),
])
def test_a_metric_the_comparison_cannot_supply_is_inconclusive_never_a_pass(corpus, changes, reason):
    decision = decide(corpus, gate_policy(**changes))

    assert decision["outcome"] == "inconclusive" and decision["failed"] == []
    item = requirement(decision, "primary.improvement")
    assert item["status"] == "inconclusive" and item["observed"] is None
    assert item["explanation"] == reason


def test_a_detection_block_the_comparison_marks_unavailable_is_inconclusive(corpus):
    """A slice whose weights the aggregation policy could not form reports detection unavailable, not zero."""
    comparison = deepcopy(corpus["comparisons"]["improved"])
    for side in ("baseline", "candidate"):
        for block in comparison["views"][0]["systems"][side]["slices"][0]["detection"]:
            if block["weighting"] == "equal_target":
                block.update(state="unavailable", reason="the policy declares no weight for canonical target T-p1",
                             full_output_recall=None, recall_at_budget=[], random_order_diagnostic=None,
                             coverage=None, pairs=None, run_variability=None, leave_one_project_out=None)
    for block in comparison["views"][0]["differences"][0]["detection"]:
        if block["weighting"] == "equal_target":
            block.update(state="unavailable", reason="the policy declares no weight for canonical target T-p1",
                         full_output_recall=None, recall_at_budget=[], pair_correctness=None,
                         pair_availability=None, completed_mass=None, assessable_mass=None)

    decision = gate.evaluate_gate(gate_policy(), comparison)

    assert decision["outcome"] == "inconclusive"
    assert requirement(decision, "primary.improvement")["explanation"] == (
        "equal_target detection is unavailable for the whole view of full/standard: the policy declares no weight "
        "for canonical target T-p1")


# --- the uncertainty rule of the primary metric ---------------------------------------------------


def test_the_paired_interval_must_have_its_lower_bound_above_the_declared_threshold(corpus):
    """The improved system's +0.6 rests on the six projects it gained; its interval comes from the comparison.

    The lower bound L is above 0, so a rule asking for more than 0 passes. A rule asking for exactly L
    is not met (above is strict) and the interval still reaches higher, so the improvement is not
    established: inconclusive. A rule asking for the upper bound U is wholly above the interval, so the
    change is shown not to improve that much: fail.
    """
    interval = difference_of(corpus["comparisons"]["improved"])["full_output_recall"]["interval"]
    lower, upper = interval["lower"], interval["upper"]
    assert interval["state"] == "ok" and 0 < lower < 0.6 < upper <= 1

    def outcome(bound: float) -> tuple[str, str]:
        decision = decide(corpus, gate_policy(primary=primary(uncertainty={"lower_bound_above": bound})))
        item = requirement(decision, "primary.uncertainty")
        return item["status"], item["explanation"]

    assert outcome(0.0)[0] == "pass"
    assert outcome(lower - 0.001)[0] == "pass"
    status, explanation = outcome(lower)
    assert status == "inconclusive" and "includes values at or below" in explanation
    assert "so the improvement is not established at the comparison's confidence" in explanation
    status, explanation = outcome(upper)
    assert status == "fail" and "lies wholly at or below" in explanation
    decision = decide(corpus, gate_policy(primary=primary(uncertainty={"lower_bound_above": 0.0})))
    assert requirement(decision, "primary.uncertainty")["observed"]["confidence"] == 0.95
    assert requirement(decision, "primary.uncertainty")["explanation"].startswith(
        f"the paired interval [{lower:.6g}, {upper:.6g}] at 0.95 confidence has its lower bound above 0")


def test_an_interval_that_ends_exactly_at_the_bound_shows_no_improvement_beyond_it(corpus):
    """The bound must be exceeded: an interval whose upper end is the bound lies at or below it, so it fails."""
    policy = gate_policy(primary=primary(uncertainty={"lower_bound_above": 0.0}))

    def status(lower: float, upper: float) -> str:
        doctored = deepcopy(corpus["comparisons"]["improved"])
        difference_of(doctored)["full_output_recall"]["interval"] = {
            "state": "ok", "lower": lower, "upper": upper, "clusters": 10}
        return requirement(gate.evaluate_gate(policy, doctored), "primary.uncertainty")["status"]

    assert status(-0.2, 0.0) == "fail"
    assert status(-0.2, 0.01) == "inconclusive"
    assert status(0.0, 0.3) == "inconclusive", "a lower bound equal to the bound does not exceed it"
    assert status(0.01, 0.3) == "pass"


def test_an_interval_that_is_not_ok_leaves_the_improvement_inconclusive(corpus):
    """Insufficient clusters, a degenerate interval, and an unavailable one carry no bounds and prove nothing."""
    rule = primary(uncertainty={"lower_bound_above": 0.0})
    policy = gate_policy(primary=rule)
    few = aggregate.compare([corpus["run"]], baseline="baseline", candidate="improved",
                            policy=aggregation_policy(min_clusters=11))
    decision = gate.evaluate_gate(policy, few)
    assert difference_of(few)["full_output_recall"]["interval"]["state"] == "insufficient_clusters"
    assert decision["outcome"] == "inconclusive"
    assert requirement(decision, "primary.uncertainty")["explanation"] == (
        "the paired interval is insufficient_clusters (too few clusters carry the metric to resample it), so it "
        "cannot show that the improvement is real")
    assert requirement(decision, "primary.improvement")["status"] == "pass", "the point estimate is still read"

    for state, reason in (("degenerate", "every replicate agreed, which is not certainty"),
                          ("unstable", "some replicate drew no cluster carrying the metric")):
        doctored = deepcopy(corpus["comparisons"]["improved"])
        difference_of(doctored)["full_output_recall"]["interval"] = {
            "state": state, "lower": None, "upper": None, "clusters": 10}
        item = requirement(gate.evaluate_gate(policy, doctored), "primary.uncertainty")
        assert item["status"] == "inconclusive" and reason in item["explanation"]


def test_the_rule_may_also_require_a_confidence_and_a_cluster_count(corpus):
    """The comparison was computed at 0.95 confidence over 10 clusters; a stronger demand is unmet, not failed."""
    def status(**more) -> str:
        rule = {"lower_bound_above": 0.0, **more}
        return requirement(decide(corpus, gate_policy(primary=primary(uncertainty=rule))),
                           "primary.uncertainty")["status"]

    assert status(min_confidence=0.95, min_clusters=10) == "pass"
    assert status(min_confidence=0.99) == "inconclusive"
    assert status(min_clusters=11) == "inconclusive"
    weak = aggregate.compare([corpus["run"]], baseline="baseline", candidate="improved",
                             policy=aggregation_policy(confidence=0.8))
    item = requirement(gate.evaluate_gate(gate_policy(primary=primary(uncertainty={
        "lower_bound_above": 0.0, "min_confidence": 0.9})), weak), "primary.uncertainty")
    assert item["status"] == "inconclusive"
    assert item["explanation"] == "the comparison's interval is at 0.8 confidence and the policy requires at least 0.9"


def test_without_an_uncertainty_rule_the_point_estimate_alone_decides_and_the_policy_says_so(corpus):
    decision = decide(corpus, gate_policy())

    assert "primary.uncertainty" not in statuses(decision)
    assert decision["policy"]["primary"].get("uncertainty") is None
    assert decision["outcome"] == "pass"


# --- regressions ------------------------------------------------------------------------------------


def regression(entry_id: str = "protected", *, kind: str = "full_recall", budget: int | None = None,
               weighting: str = "equal_target", limit: float = 0.0, **more) -> dict:
    metric = {"kind": kind} if budget is None else {"kind": kind, "budget": budget}
    return {"id": entry_id, "metric": metric, "weighting": weighting, "max_decrease": limit, **more}


def test_a_candidate_may_not_lose_a_project_it_detected_even_when_recall_rises_overall(corpus):
    """The regressing system detects T-p2 to T-p8 (7 of 10): +0.5 overall, but T-p1, a baseline detection, is lost.

    The whole view rose, so a whole-view regression passes. Project acme/p1 fell from 1 to 0, so a
    protected slice on it fails, and so does the per-project maximum decrease over every project;
    acme/p2 is protected too and held.
    """
    policy = gate_policy(regressions=[
        regression("whole-view", limit=0.0),
        regression("acme-p1", slice={"dimension": "project", "value": "acme/p1"}),
        regression("acme-p2", slice={"dimension": "project", "value": "acme/p2"}),
        regression("each-project", slice={"dimension": "project"}, limit=0.2)])

    decision = decide(corpus, policy, "regressing")

    assert requirement(decision, "primary.improvement")["observed"]["difference"] == 0.5
    assert statuses(decision)["regression.whole-view"] == "pass"
    assert statuses(decision)["regression.acme-p2"] == "pass"
    assert statuses(decision)["regression.acme-p1"] == "fail"
    assert statuses(decision)["regression.each-project"] == "fail"
    assert decision["outcome"] == "fail" and decision["failed"] == ["regression.acme-p1", "regression.each-project"]
    assert requirement(decision, "regression.acme-p1")["explanation"] == (
        "full-output recall (equal_target) in project acme/p1 may not fall by more than 0, but project acme/p1 "
        "fell from 1 to 0, -1")
    each = requirement(decision, "regression.each-project")
    assert len(each["observed"]["slices"]) == 10
    assert next(row for row in each["observed"]["slices"] if row["slice"] == "acme/p1") == {
        "slice": "acme/p1", "baseline": 1.0, "candidate": 0.0, "difference": -1.0}


def test_a_regression_at_exactly_the_allowed_decrease_passes_and_one_step_more_fails(corpus):
    """The late system's recall@1 is 0 against the baseline's 0.2: a decrease of exactly 0.2."""
    def status(limit: float) -> str:
        policy = gate_policy(regressions=[regression("first-position", kind="recall_at_budget", budget=1,
                                                     limit=limit)])
        return requirement(decide(corpus, policy, "late"), "regression.first-position")["status"]

    assert status(0.2) == "pass"
    assert status(0.19) == "fail"
    decision = decide(corpus, gate_policy(regressions=[regression("first-position", kind="recall_at_budget",
                                                                  budget=1, limit=0.05)]), "late")
    assert requirement(decision, "primary.improvement")["status"] == "pass", "full recall still rose by 0.6"
    assert decision["outcome"] == "fail"


def test_a_regression_the_comparison_cannot_supply_is_inconclusive(corpus):
    """An unmeasurable budget, an absent slice, and a project slice with no target are unresolved, not held."""
    unranked = decide(corpus, gate_policy(regressions=[regression("at-five", kind="recall_at_budget", budget=5)]),
                      "unranked")
    assert requirement(unranked, "regression.at-five")["status"] == "inconclusive"
    assert "recall@5 cannot be measured for unranked" in requirement(unranked, "regression.at-five")["explanation"]

    missing = decide(corpus, gate_policy(regressions=[
        regression("absent", slice={"dimension": "project", "value": "acme/none"})]))
    assert requirement(missing, "regression.absent")["explanation"] == (
        "full-output recall (equal_target) in project acme/none could not be settled: project acme/none: the "
        "comparison has no project acme/none of full/standard")

    carrying = decide(corpus, gate_policy(regressions=[regression("workloads", slice={"dimension": "workload"})]))
    assert requirement(carrying, "regression.workloads")["status"] == "pass"
    assert requirement(carrying, "regression.workloads")["observed"]["slices"] == [
        {"slice": WORKLOAD, "baseline": 0.2, "candidate": 0.8, "difference": 0.6}]


def test_a_project_that_carries_only_controls_takes_no_part_in_a_per_project_regression(tmp_path):
    """Project acme/p3 has a control and no target, so it has no recall to lose.

    Covering each project reads acme/p1 and acme/p2 and passes; naming acme/p3 outright asks for a figure the
    comparison reports as unavailable, and that is unresolved rather than a pass.
    """
    inputs = [planned(f"p{index}", project=f"acme/p{index}",
                      targets=[target(f"T-p{index}", project=f"acme/p{index}", family=f"family-{index}")])
              for index in (1, 2)]
    inputs.append(planned("p3", project="acme/p3", controls=[control("C-p3")]))
    outcomes = {("p1", "baseline", 1): scan(hits={"T-p1": 1}, claims=1),
                ("p1", "candidate", 1): scan(hits={"T-p1": 1}, claims=1),
                ("p2", "candidate", 1): scan(hits={"T-p2": 1}, claims=1)}
    run = write_run(tmp_path, "run-controls-only", inputs, systems=("baseline", "candidate"), outcomes=outcomes,
                    configs={"candidate": {"config": {"knob": 2}}})
    comparison = aggregate.compare([run], baseline="baseline", candidate="candidate",
                                   policy=aggregation_policy(min_clusters=2))

    decision = gate.evaluate_gate(gate_policy(regressions=[
        regression("each-project", slice={"dimension": "project"}),
        regression("controls-only", slice={"dimension": "project", "value": "acme/p3"})]), comparison)

    each = requirement(decision, "regression.each-project")
    assert each["status"] == "pass" and [row["slice"] for row in each["observed"]["slices"]] == [
        "acme/p1", "acme/p2"]
    named = requirement(decision, "regression.controls-only")
    assert named["status"] == "inconclusive"
    assert named["explanation"] == (
        "full-output recall (equal_target) in project acme/p3 could not be settled: project acme/p3: equal_target "
        "detection is unavailable for project acme/p3 of full/standard: this slice has no target planned before "
        "execution")


def test_a_regression_can_also_hold_the_paired_interval_within_the_allowed_decrease(corpus):
    """With check_interval the interval's lower bound must stay within max_decrease: below fails, straddling waits."""
    policy = gate_policy(regressions=[regression("guard", limit=0.05, check_interval=True)])

    def verdict(lower, upper, state="ok") -> tuple[str, str]:
        doctored = deepcopy(corpus["comparisons"]["improved"])
        difference_of(doctored)["full_output_recall"]["interval"] = {
            "state": state, "lower": lower, "upper": upper, "clusters": 10}
        item = requirement(gate.evaluate_gate(policy, doctored), "regression.guard")
        return item["status"], item["explanation"]

    assert verdict(-0.04, 0.9)[0] == "pass"
    assert verdict(-0.05, 0.9)[0] == "pass"
    status, explanation = verdict(-0.3, 0.9)
    assert status == "inconclusive" and "allows a decrease larger than 0.05" in explanation
    status, explanation = verdict(-0.4, -0.06)
    assert status == "fail" and "lies below -0.05" in explanation
    status, explanation = verdict(-0.3, -0.05)
    assert status == "inconclusive", "an interval that reaches the limit is not wholly below it"
    assert "allows a decrease larger than 0.05" in explanation
    status, explanation = verdict(None, None, "degenerate")
    assert status == "inconclusive" and "the paired interval is degenerate" in explanation
    real = requirement(decide(corpus, policy), "regression.guard")
    assert real["status"] == "pass", "the real interval sits above -0.05"


# --- configuration differences and evidence scope ---------------------------------------------------


@pytest.mark.parametrize("allowed, status", [
    (["config.knob"], "pass"),
    (["config"], "pass"),
    (["config.knob", "model_id"], "pass"),
    ([], "inconclusive"),
    (["model_id"], "inconclusive"),
    (["config.kno"], "inconclusive"),
    (["config.knobs"], "inconclusive"),
])
def test_only_the_declared_configuration_differences_may_differ(corpus, allowed, status):
    """The candidate differs from the baseline in config.knob alone; an entry also allows every key beneath it.

    A key is matched whole: ``config.kno`` is not ``config.knob``, and an entry that names something the
    systems do not differ in allows nothing more.
    """
    decision = decide(corpus, gate_policy(configuration={"allowed_differences": allowed}))

    assert requirement(decision, "configuration.allowed_differences")["status"] == status
    assert decision["outcome"] == ("pass" if status == "pass" else "inconclusive")


def test_a_difference_the_policy_did_not_declare_means_the_comparison_does_not_isolate_the_change(corpus):
    """A changed model beside the knob is a second change: inconclusive, and the explanation names it."""
    comparison = deepcopy(corpus["comparisons"]["improved"])
    comparison["configuration_differences"].append(
        {"key": "model_id", "baseline": None, "candidate": "vendor/model-y", "absent_in": None})
    comparison["configuration_differences"].append(
        {"key": "network_policy", "baseline": "none", "candidate": "unrestricted", "absent_in": None})

    decision = gate.evaluate_gate(gate_policy(), comparison)

    item = requirement(decision, "configuration.allowed_differences")
    assert item["status"] == "inconclusive"
    assert item["observed"]["not_allowed"] == ["model_id", "network_policy"]
    assert item["explanation"] == ("the systems also differ in model_id, network_policy, which the policy does not "
                                   "intend to measure, so the comparison does not isolate the intended change")
    assert decision["outcome"] == "inconclusive" and decision["failed"] == []
    allowed = gate.evaluate_gate(gate_policy(configuration={
        "allowed_differences": ["config.knob", "model_id", "network_policy"]}), comparison)
    assert allowed["outcome"] == "pass"


def test_identically_configured_systems_are_reported_as_such(corpus):
    comparison = deepcopy(corpus["comparisons"]["improved"])
    comparison["configuration_differences"] = []

    item = requirement(gate.evaluate_gate(gate_policy(configuration={"allowed_differences": []}), comparison),
                       "configuration.allowed_differences")

    assert item["status"] == "pass" and item["explanation"] == "the two systems are configured identically"


def small_run(root: Path, run_id: str, *, scope: str = "reviewed", candidate_review: str = "approved",
              level: str = "L3") -> Path:
    """Five projects, one target each; the baseline detects two, the candidate four. Evidence scope is chosen."""
    inputs = [planned(f"p{index}", project=f"acme/p{index}", scope=scope,
                      targets=[target(f"T-p{index}", project=f"acme/p{index}", family=f"family-{index}",
                                      level=level)]) for index in range(1, 6)]
    outcomes = {}
    for index in range(1, 6):
        outcomes[(f"p{index}", "baseline", 1)] = scan(hits={f"T-p{index}": 1} if index <= 2 else {}, claims=1)
        outcomes[(f"p{index}", "candidate", 1)] = scan(hits={f"T-p{index}": 1} if index <= 4 else {}, claims=1,
                                                       review_state=candidate_review)
    return write_run(root, run_id, inputs, systems=("baseline", "candidate"), outcomes=outcomes,
                     configs={"candidate": {"config": {"knob": 2}}})


def small_comparison(root: Path, run_id: str, **choices) -> dict:
    return aggregate.compare([small_run(root, run_id, **choices)], baseline="baseline", candidate="candidate",
                             policy=aggregation_policy())


def test_draft_evidence_cannot_produce_a_reviewed_recommendation(tmp_path):
    """The candidate's review records are drafts, so its evidence is draft: inconclusive, with the reason.

    Nothing else is wrong: the improvement is 0.2 to 0.8, +0.6, and it passes. The policy asks for
    reviewed evidence, so the decision supports no recommendation at all.
    """
    comparison = small_comparison(tmp_path, "run-draft", candidate_review="draft")
    assert comparison["views"][0]["evidence_scope"] == {"baseline": "reviewed", "candidate": "draft"}

    decision = gate.evaluate_gate(gate_policy(), comparison)

    assert decision["outcome"] == "inconclusive" and decision["recommendation_scope"] == "none"
    assert statuses(decision)["primary.improvement"] == "pass"
    item = requirement(decision, "evidence.scope")
    assert item["status"] == "inconclusive"
    assert item["observed"] == {"baseline": "reviewed", "candidate": "draft"}
    assert item["explanation"] == ("the candidate evidence is draft, not reviewed: labels or matches without a "
                                   "recorded human approval are pipeline diagnostics, so no reviewed "
                                   "recommendation can rest on them")


def test_a_policy_that_itself_declares_draft_scope_yields_a_development_decision(tmp_path):
    """Draft evidence meets a draft policy, and the decision says it is for development only."""
    comparison = small_comparison(tmp_path, "run-draft", candidate_review="draft")

    decision = gate.evaluate_gate(gate_policy(required_scope="draft"), comparison)

    assert decision["outcome"] == "pass" and decision["recommendation_scope"] == "development"
    assert requirement(decision, "evidence.scope")["explanation"] == (
        "the evidence is reviewed for the baseline and draft for the candidate, which meets the policy's draft "
        "scope; this is a development decision, not a reviewed recommendation")
    reviewed = small_comparison(tmp_path, "run-reviewed")
    assert gate.evaluate_gate(gate_policy(required_scope="draft"), reviewed)["recommendation_scope"] == "development"
    assert gate.evaluate_gate(gate_policy(), reviewed)["recommendation_scope"] == "reviewed"


def test_diagnostic_fixture_evidence_supports_no_recommendation_even_from_a_draft_policy(tmp_path):
    """A plan whose scope is diagnostic holds fixture labels only: neither policy scope accepts it."""
    comparison = small_comparison(tmp_path, "run-diagnostic", scope="diagnostic", level="fixture")
    assert comparison["views"][0]["evidence_scope"] == {"baseline": "diagnostic", "candidate": "diagnostic"}

    for required in ("reviewed", "draft"):
        decision = gate.evaluate_gate(gate_policy(required_scope=required), comparison)
        assert decision["outcome"] == "inconclusive" and decision["recommendation_scope"] == "none"
        assert requirement(decision, "evidence.scope")["explanation"] == (
            "the baseline evidence is diagnostic fixture evidence, which supports no recommendation; the candidate "
            "evidence is diagnostic fixture evidence, which supports no recommendation")


# --- the frozen contract and its bindings -----------------------------------------------------------


def test_the_comparison_contract_and_bindings_are_rechecked(corpus):
    """A comparison the aggregation module wrote holds no contradiction, so a genuine one passes."""
    decision = decide(corpus, gate_policy())

    item = requirement(decision, "contract.shared")
    assert item["status"] == "pass"
    assert item["observed"] == {"contract_sha256": corpus["comparisons"]["improved"]["contract"]["structure_sha256"],
                                "inputs": 10, "pairs": 0, "views": 1}
    assert item["explanation"] == ("baseline and improved share one frozen contract of 10 input(s) and 0 pair(s), and "
                                   "every count the comparison records for them agrees in each of its 1 view(s)")
    for name in CANDIDATES:
        assert requirement(decide(corpus, gate_policy(), name), "contract.shared")["status"] == "pass"


def edited(corpus: dict, change) -> dict:
    """A copy of the improved comparison with *change* applied: a document that may have been edited."""
    comparison = deepcopy(corpus["comparisons"]["improved"])
    change(comparison)
    return comparison


@pytest.mark.parametrize("change, violation", [
    (lambda c: c["views"][0]["systems"]["candidate"]["observations"].update(assignments=8),
     "view full/standard: the systems were assigned 10 and 8 scans"),
    (lambda c: c["views"][0]["systems"]["candidate"]["slices"][0].update(inputs=8),
     "view full/standard, the whole view: inputs differ (10 and 8)"),
    (lambda c: c["views"][0]["systems"]["candidate"]["slices"][0].update(canonical_targets=8),
     "canonical_targets differ (10 and 8)"),
    (lambda c: c["views"][0]["systems"]["candidate"]["slices"][0]["completion"].update(assignments=8),
     "completion assignments differ (10 and 8)"),
    (lambda c: c["views"][0]["systems"]["candidate"]["slices"][0]["claims"].update(assignments=8),
     "the claim volumes cover 10 and 8 assignments"),
    (lambda c: c["views"][0]["systems"]["candidate"]["slices"][0]["detection"][0]["coverage"].update(
        target_observations=8), "equal_target target observations differ (10 and 8)"),
    (lambda c: c["views"][0]["systems"]["candidate"]["slices"][0]["controls"]["capability_safe"].update(
        observations=8), "capability_safe observations differ"),
    (lambda c: c["candidate"].update(runs=[]), "the candidate improved names no run"),
    (lambda c: c["candidate"].update(runs=["run-elsewhere"]),
     "the candidate names run run-elsewhere, which the comparison does not list"),
    (lambda c: c["runs"][0].update(systems=["baseline"]), "run run-gate does not schedule the candidate improved"),
    (lambda c: c["contract"].update(inputs=0), "the contract covers no input"),
    (lambda c: c.update(policy_sha256=digest("another policy")),
     "policy_sha256 does not hash the aggregation policy the comparison carries"),
    (lambda c: c["views"][0]["systems"]["candidate"].update(system_id="baseline"),
     "view full/standard records baseline as the candidate, not improved"),
])
def test_a_comparison_whose_records_contradict_a_shared_contract_fails_whatever_else_holds(corpus, change, violation):
    """Every other requirement passes; a candidate that was assigned less than the baseline still fails."""
    decision = gate.evaluate_gate(gate_policy(), edited(corpus, change))

    item = requirement(decision, "contract.shared")
    assert item["status"] == "fail"
    assert any(violation in found for found in item["observed"]["violations"]), item["observed"]["violations"]
    assert decision["outcome"] == "fail" and decision["failed"] == ["contract.shared"]
    assert item["explanation"].startswith("the comparison's own records show the two systems were not assigned "
                                          "the same frozen work, or do not bind to the runs they name: ")


def test_runs_that_froze_different_packs_fail_the_shared_contract(corpus):
    def second_pack(comparison: dict) -> None:
        other = deepcopy(comparison["runs"][0])
        other.update(run_id="run-other", pack={**other["pack"], "version": "2.0.0"})
        comparison["runs"].append(other)

    item = requirement(gate.evaluate_gate(gate_policy(), edited(corpus, second_pack)), "contract.shared")

    assert item["status"] == "fail" and "the compared runs froze different packs" in item["observed"]["violations"]


def test_a_candidate_cannot_improve_by_dropping_failed_inputs_from_the_denominator(tmp_path):
    """The candidate's schedule leaves out the two inputs it would have failed: the comparison is refused.

    Recall over the eight remaining projects would be 4/8 against the baseline's 2/10, a flattering
    change of +0.3. The comparison never computes it, so the gate is never handed a comparison to pass.
    """
    inputs = corpus_inputs()
    baseline_run = write_run(tmp_path / "a", "run-base", inputs, systems=("baseline",),
                             outcomes={(f"p{index}", "baseline", 1): behave("baseline", index) for index in (1, 2)})
    dropped = write_run(tmp_path / "b", "run-cand", inputs[:8], systems=("candidate",),
                        outcomes={(f"p{index}", "candidate", 1): scan(hits={f"T-p{index}": 1}, claims=1)
                                  for index in range(1, 5)},
                        configs={"candidate": {"config": {"knob": 2}}})

    with pytest.raises(ContractError, match="the systems do not share the frozen evaluation contract: input p10 "
                                            "is scheduled for baseline but not for candidate"):
        aggregate.compare([baseline_run, dropped], baseline="baseline", candidate="candidate")


def test_a_comparison_edited_to_hide_dropped_inputs_still_fails_the_gate(corpus):
    """Doctoring the counts of a genuine comparison to look as if the candidate had two fewer inputs is caught."""
    def drop_two(comparison: dict) -> None:
        side = comparison["views"][0]["systems"]["candidate"]
        side["observations"]["assignments"] = 8
        for block in side["slices"]:
            if block["slice"]["dimension"] == "all":
                block["inputs"] = 8
                block["completion"].update(inputs=8, assignments=8)
                block["claims"]["assignments"] = 8

    decision = gate.evaluate_gate(gate_policy(), edited(corpus, drop_two))

    assert decision["outcome"] == "fail" and decision["failed"] == ["contract.shared"]
    assert statuses(decision)["primary.improvement"] == "pass", "the flattering figure is still in the document"


def test_a_compared_run_that_did_not_finish_leaves_the_decision_inconclusive(corpus):
    """A run that stopped early leaves assignments unrecorded; the comparison rests on part of the schedule."""
    comparison = edited(corpus, lambda c: c["runs"][0].update(status="failed"))

    decision = gate.evaluate_gate(gate_policy(), comparison)

    item = requirement(decision, "contract.runs_completed")
    assert item["status"] == "inconclusive" and item["observed"] == {"run-gate": "failed"}
    assert item["explanation"] == ("run run-gate did not finish, so assignments it never recorded stand as failures "
                                   "for whichever system they belonged to and the comparison rests on part of what "
                                   "was scheduled")
    assert decision["outcome"] == "inconclusive"


# --- binding, replay, and what a policy is refused for ----------------------------------------------


def test_the_decision_is_bound_to_its_policy_comparison_runs_and_evaluator_version(corpus):
    """Each digest is the canonical hash of the document it names, and a changed input changes the decision."""
    policy = gate_policy()
    comparison = corpus["comparisons"]["improved"]

    decision = gate.evaluate_gate(policy, comparison)

    completed = gate.resolve_policy(policy)
    assert decision["policy"] == completed and decision["policy_sha256"] == canonical_sha256(completed)
    binding = decision["comparison"]
    assert binding["sha256"] == canonical_sha256(comparison)
    assert binding["policy_sha256"] == comparison["policy_sha256"]
    assert binding["contract_sha256"] == comparison["contract"]["structure_sha256"]
    assert binding["evaluator_version"] == comparison["evaluator_version"] == decision["evaluator_version"]
    assert binding["baseline"] == {"system_id": "baseline", "config_sha256": comparison["baseline"]["config_sha256"]}
    assert binding["runs"] == [{key: run[key] for key in ("run_id", "status", "manifest_sha256", "schedule_sha256",
                                                          "config_sha256", "evidence_sha256")}
                               for run in comparison["runs"]]
    assert decision["precision"] == {"baseline": None, "candidate": None}
    looser = gate.evaluate_gate(gate_policy(primary=primary(minimum=0.5)), comparison)
    other = gate.evaluate_gate(policy, corpus["comparisons"]["late"])
    assert len({decision["policy_sha256"], looser["policy_sha256"]}) == 2
    assert len({binding["sha256"], other["comparison"]["sha256"]}) == 2
    assert len({canonical_json(item) for item in (decision, looser, other)}) == 3


def test_replaying_the_same_inputs_gives_the_same_decision_bytes_and_leaves_them_untouched(corpus):
    """No clock, path, or randomness: two evaluations, and one from a round-tripped copy, agree byte for byte."""
    policy = gate_policy(regressions=[regression("whole-view")],
                         primary=primary(uncertainty={"lower_bound_above": 0.0}))
    comparison = corpus["comparisons"]["improved"]
    policy_before, comparison_before = deepcopy(policy), deepcopy(comparison)

    first = gate.evaluate_gate(policy, comparison)
    second = gate.evaluate_gate(policy, comparison)
    third = gate.evaluate_gate(json.loads(json.dumps(policy)), json.loads(json.dumps(comparison)))

    assert canonical_json(first) == canonical_json(second) == canonical_json(third)
    assert policy == policy_before and comparison == comparison_before, "the inputs are not modified"


def test_resolving_a_policy_fills_the_required_scope_and_the_notes_and_no_threshold(corpus):
    raw = gate_policy(regressions=[regression("whole-view", limit=0.03)])
    before = deepcopy(raw)

    completed = gate.resolve_policy(raw)

    assert set(completed) - set(raw) == {"required_scope", "notes"}
    assert completed["required_scope"] == "reviewed" and completed["notes"] == []
    assert {key: value for key, value in completed.items() if key in raw} == raw
    assert raw == before
    assert gate.resolve_policy(completed) == completed


@pytest.mark.parametrize("kind", ["random_order_expected_recall", "random_order_diagnostic", "run_variability"])
def test_a_diagnostic_primary_metric_is_refused_when_loaded_and_when_evaluated(corpus, tmp_path, kind):
    """Refused at load, by name: the decision cannot be handed a policy that rests on an expectation."""
    document = gate_policy(primary=primary(kind))
    path = tmp_path / f"{kind}.json"
    path.write_text(canonical_json(document) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match=f"primary.metric: '{kind}'"):
        gate.load_policy(path)
    with pytest.raises(ContractError, match=f"primary.metric: '{kind}'"):
        gate.resolve_policy(document)
    with pytest.raises(ContractError, match=f"primary.metric: '{kind}'"):
        gate.evaluate_gate(document, corpus["comparisons"]["improved"])


def test_a_policy_file_loads_completed(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(canonical_json(gate_policy()) + "\n", encoding="utf-8")

    loaded = gate.load_policy(path)

    assert loaded == gate.resolve_policy(gate_policy()) and loaded["required_scope"] == "reviewed"
    with pytest.raises(ContractError, match="could not load"):
        gate.load_policy(tmp_path / "absent.json")


def test_a_document_that_is_not_a_comparison_is_refused_before_anything_is_decided(corpus):
    with pytest.raises(ContractError, match="schema_version"):
        gate.evaluate_gate(gate_policy(), {"schema_version": "2.0"})
    broken = deepcopy(corpus["comparisons"]["improved"])
    del broken["contract"]
    with pytest.raises(ContractError, match="'contract' is a required property"):
        gate.evaluate_gate(gate_policy(), broken)
    with pytest.raises(ContractError, match="a comparison names two different systems"):
        gate.evaluate_gate(gate_policy(), edited(corpus, lambda c: c["candidate"].update(system_id="baseline")))


def test_the_decision_states_what_it_is_and_which_blocks_the_policy_left_out(corpus):
    decision = decide(corpus, gate_policy())

    assert decision["blocks"] == {"declared": ["primary", "configuration"],
                                  "not_declared": ["regressions", "precision", "controls", "completion",
                                                   "target_coverage", "burden", "cost"]}
    assert any("approves, promotes, and deploys nothing" in note for note in decision["notes"])
    assert any("No requirement is weighed against another" in note for note in decision["notes"])
    assert ("The policy declares no regressions, precision, controls, completion, target_coverage, burden, cost "
            "block, so those requirements are not part of it and were not evaluated.") in decision["notes"]
    full = decide(corpus, gate_policy(regressions=[regression("whole-view")]))
    assert "regressions" in full["blocks"]["declared"] and "regressions" not in full["blocks"]["not_declared"]
    assert not any("The comparison also holds view" in note for note in decision["notes"])


# --- reviewed precision -----------------------------------------------------------------------------


def verdict_for(system: str, hit_inputs: int | None = None):
    """What a fictional reviewer finds: a claim is true only when it is the one that hit a target.

    The baseline and the duplicating system hit T-p1 and T-p2, the improved system T-p1 to T-p8, and the
    flagging system every target, always with their first claim; every other claim they deliver is false.
    """
    hit_inputs = hit_inputs or {"baseline": 2, "duplicating": 2, "improved": 8, "flagging": 10}[system]

    def verdict(unit_id: str) -> str:
        _run, invocation, claim = unit_id.split("/")
        return "true" if claim == "c1" and int(invocation.split("__")[0][1:]) <= hit_inputs else "false"

    return verdict


def review_units(sample: dict, verdict, *, reviewers=(REVIEWER_A, REVIEWER_B), only=None) -> dict | None:
    """Independent reviews of the sampled units (every unit, or those *only* names), by each reviewer."""
    reviews = None
    for entry in sample["selected"]:
        if only is not None and entry["unit_id"] not in only:
            continue
        for reviewer in reviewers:
            reviews = precision.record_review(sample, reviews, unit_id=entry["unit_id"], reviewer=reviewer,
                                              role="independent", outcome=verdict(entry["unit_id"]),
                                              note="fixture review by a fictional reviewer", clock=CLOCK)
    return reviews


def estimate_for(run: Path, system: str, verdict=None, *, budget: int = 5, population: str = "first_b",
                 size: int | None = None, seed: int = 11, only=None, reviewers=(REVIEWER_A, REVIEWER_B),
                 stratify_by: str | None = None) -> dict:
    """The real frame, seeded sample, recorded reviews, and estimate of one system's claims in a run."""
    frame = precision.build_frame([run], population=population, budget=budget if population == "first_b" else None,
                                  systems=[system])
    sample = precision.draw_sample(frame, size=len(frame["units"]) if size is None else size, seed=seed,
                                   stratify_by=stratify_by)
    reviews = review_units(sample, verdict or verdict_for(system), reviewers=reviewers, only=only)
    return precision.estimate(sample, reviews)


@pytest.fixture(scope="module")
def estimates(corpus) -> dict:
    """Census estimates of the first-5 population of each system whose precision the tests read."""
    return {name: estimate_for(corpus["run"], name) for name in ("baseline", "improved", "flagging", "duplicating")}


def precision_block(**changes) -> dict:
    block = {"basis": "resolved", "population": {"name": "first_b", "budget": 5}, "min_value": 0.5,
             "max_unresolved_share": 0.2, "min_evidence_grade": "double_review_or_adjudicated"}
    block.update(changes)
    return block


def test_the_fixture_estimates_are_the_hand_computed_figures(estimates):
    """Each scan delivers one claim (the flagging system 12, of which the first five are in the first-5 list).

    improved: 10 units, 8 true, 2 false: 0.8. baseline: 2 true of 10: 0.2. flagging: 5 units per scan, 50 in
    all, of which each scan's first is true: 10 of 50, 0.2. duplicating: one unit per scan (its 20 copies are
    one allegation), 2 true of 10: 0.2, at 5 copies inside the first-5 list per unit.
    """
    assert (estimates["improved"]["precision_resolved"], estimates["improved"]["totals"]["true"]) == (0.8, 8.0)
    assert estimates["baseline"]["precision_resolved"] == 0.2
    flagging = estimates["flagging"]
    assert (flagging["precision_resolved"], flagging["coverage"]["population_units"]) == (0.2, 50)
    assert estimates["duplicating"]["precision_resolved"] == 0.2
    assert estimates["duplicating"]["duplicate_burden"]["copies_per_unit"] == 5.0
    for estimate in estimates.values():
        assert estimate["evidence_grade"] == "double_review_or_adjudicated" and estimate["unresolved_share"] == 0.0


def test_a_genuine_improvement_passes_every_precision_requirement(corpus, estimates):
    policy = gate_policy(precision=precision_block(min_coverage=0.9, min_interval_lower_bound=0.7,
                                                   max_decrease_vs_baseline=0.05))

    decision = decide(corpus, policy, precision_baseline=estimates["baseline"],
                      precision_candidate=estimates["improved"])

    assert decision["outcome"] == "pass", decision["unresolved"] + decision["failed"]
    assert [item["id"] for item in decision["requirements"] if item["id"].startswith("precision.")] == [
        "precision.binding", "precision.min_value", "precision.max_unresolved_share",
        "precision.min_evidence_grade", "precision.min_coverage", "precision.interval", "precision.max_decrease"]
    assert requirement(decision, "precision.min_value")["explanation"] == (
        "resolved precision is 0.8, at least the required 0.5")
    assert requirement(decision, "precision.max_unresolved_share")["explanation"] == (
        "the unresolved share is 0, within the allowed 0.2")
    assert requirement(decision, "precision.min_evidence_grade")["explanation"] == (
        "the review's evidence grade is double_review_or_adjudicated, which meets double_review_or_adjudicated")
    assert requirement(decision, "precision.min_coverage")["explanation"] == (
        "the sampled strata hold 10 of the population's 10 unit(s), a share of 1, at least the required 0.9")
    assert requirement(decision, "precision.max_decrease")["explanation"] == (
        "resolved precision went from 0.2 to 0.8, a decrease of at most the allowed 0.05")
    assert requirement(decision, "precision.binding")["explanation"] == (
        "the estimate covers only the candidate improved, over the first-5 population of full/standard inputs, "
        "and rests on run(s) run-gate of this comparison")
    assert decision["precision"]["candidate"]["sha256"] == canonical_sha256(estimates["improved"])
    assert decision["precision"]["baseline"]["sha256"] == canonical_sha256(estimates["baseline"])
    assert decision["precision"]["candidate"]["reviews_sha256"] == estimates["improved"]["reviews_sha256"]


def test_a_flag_everything_candidate_fails_precision_whatever_its_recall(corpus, estimates):
    """The flagging system detects every target (recall 1.0, +0.8) but only 10 of its 50 first-5 claims are true."""
    decision = decide(corpus, gate_policy(precision=precision_block()), "flagging",
                      precision_candidate=estimates["flagging"])

    assert requirement(decision, "primary.improvement")["status"] == "pass"
    assert requirement(decision, "primary.improvement")["observed"]["candidate"] == 1.0
    assert decision["outcome"] == "fail" and decision["failed"] == ["precision.min_value"]
    assert requirement(decision, "precision.min_value")["explanation"] == (
        "resolved precision is 0.2, below the required 0.5")


def test_a_missing_precision_estimate_is_inconclusive_and_never_a_perfect_score(corpus):
    decision = decide(corpus, gate_policy(precision=precision_block(min_coverage=0.5)))

    assert decision["outcome"] == "inconclusive" and decision["failed"] == []
    assert decision["unresolved"] == ["precision.binding", "precision.min_value", "precision.max_unresolved_share",
                                      "precision.min_evidence_grade", "precision.min_coverage"]
    assert requirement(decision, "precision.binding")["explanation"] == (
        "the candidate's precision estimate is missing or not bound to this comparison: no precision estimate was "
        "supplied for the candidate improved")
    assert requirement(decision, "precision.min_value")["explanation"].startswith(
        "the candidate's precision is not established: no precision estimate was supplied")
    assert requirement(decision, "precision.min_value")["observed"] is None


def test_an_estimate_of_another_system_or_workload_or_population_does_not_bind(corpus, estimates, tmp_path):
    """Each mismatch is named, and the precision requirements wait rather than pass."""
    policy = gate_policy(precision=precision_block())
    both = estimate_for(corpus["run"], "improved")
    both["population"]["systems"] = ["baseline", "improved"]
    another_view = deepcopy(estimates["improved"])
    another_view["population"].update(mode="pr", profile="metadata_blinded")
    full = estimate_for(corpus["run"], "improved", population="full")
    wider = estimate_for(corpus["run"], "improved", budget=10)
    other_run = write_run(tmp_path, "run-other", corpus_inputs(), systems=("baseline", "improved"),
                          outcomes={(f"p{index}", "improved", 1): behave("improved", index) for index in range(1, 11)})
    elsewhere = estimate_for(other_run, "improved")
    edited_run = deepcopy(estimates["improved"])
    edited_run["runs"][0]["schedule_sha256"] = digest("another schedule")

    for estimate, reason in (
            (estimates["baseline"], "the estimate covers baseline, not only the candidate improved"),
            (both, "the estimate covers baseline, improved, not only the candidate improved"),
            (another_view, "the estimate is over pr/metadata_blinded inputs, not full/standard"),
            (full, "the estimate is over the full population, but the policy declares the first-5 population"),
            (wider, "the estimate is over the first-10 population, but the policy declares the first-5 population"),
            (elsewhere, "the estimate rests on run run-other, which the comparison does not include; the "
                        "candidate's run run-gate is not among the estimate's runs"),
            (edited_run, "the estimate's record of run run-gate is not the comparison's (its manifest or "
                         "schedule digest differs)")):
        decision = decide(corpus, policy, precision_candidate=estimate)
        assert decision["outcome"] == "inconclusive" and decision["failed"] == [], reason
        item = requirement(decision, "precision.binding")
        assert item["status"] == "inconclusive"
        assert item["explanation"] == ("the candidate's precision estimate is missing or not bound to this "
                                       f"comparison: {reason}")
        assert requirement(decision, "precision.min_value")["status"] == "inconclusive"


def test_a_first_b_estimate_that_leaves_invocations_out_does_not_describe_the_whole_output(tmp_path):
    """The mixed system ranks its output on six inputs and leaves it unranked on four.

    An unranked invocation has no measured native position, so the first-5 population leaves it out whole and
    its claims are invisible to that estimate. The estimate says how many it left out, and the gate does not
    treat it as the candidate's precision; the full population leaves nothing out and binds.
    """
    outcomes = {(f"p{index}", "baseline", 1): behave("baseline", index) for index in range(1, 11)}
    outcomes.update({(f"p{index}", "mixed", 1): scan(hits={f"T-p{index}": 1} if index <= 8 else {}, claims=1,
                                                     ranking="native" if index <= 6 else "unranked")
                     for index in range(1, 11)})
    run = write_run(tmp_path, "run-mixed", corpus_inputs(), systems=("baseline", "mixed"), outcomes=outcomes,
                    configs={"mixed": {"config": {"knob": 2}}})
    comparison = aggregate.compare([run], baseline="baseline", candidate="mixed", policy=aggregation_policy())
    first_b = estimate_for(run, "mixed", verdict_for("mixed", 8))
    assert first_b["exclusions"]["unranked"]["invocations"] == 4 and first_b["coverage"]["population_units"] == 6

    decision = gate.evaluate_gate(gate_policy(precision=precision_block()), comparison, precision_candidate=first_b)

    assert decision["outcome"] == "inconclusive" and decision["failed"] == []
    assert requirement(decision, "precision.binding")["explanation"] == (
        "the candidate's precision estimate is missing or not bound to this comparison: the estimate leaves out 4 "
        "unranked invocation(s), whose claims have no measured native position, so it does not describe all of "
        "the candidate's output")
    everything = estimate_for(run, "mixed", verdict_for("mixed", 8), population="full")
    covered = gate.evaluate_gate(gate_policy(precision=precision_block(population={"name": "full"})), comparison,
                                 precision_candidate=everything)
    assert requirement(covered, "precision.binding")["status"] == "pass"
    assert requirement(covered, "precision.min_value")["observed"]["value"] == 0.8


def test_a_run_of_the_compared_system_that_the_estimate_leaves_out_does_not_bind(corpus, estimates):
    """The candidate was scheduled by two runs; an estimate resting on one describes only part of its output."""
    comparison = deepcopy(corpus["comparisons"]["improved"])
    second = deepcopy(comparison["runs"][0])
    second["run_id"] = "run-second"
    comparison["runs"].append(second)
    comparison["candidate"]["runs"] = ["run-gate", "run-second"]

    decision = gate.evaluate_gate(gate_policy(precision=precision_block()), comparison,
                                  precision_candidate=estimates["improved"])

    assert requirement(decision, "precision.binding")["explanation"] == (
        "the candidate's precision estimate is missing or not bound to this comparison: the candidate's run "
        "run-second is not among the estimate's runs")


def partially_reviewed(corpus: dict) -> dict:
    """The improved system's ten first-5 claims, sampled whole, of which six are reviewed by two reviewers each.

    By unit id the first six are p10, p1, p2, p3, p4, and p5: five true and one false. The other four have no
    review, so the unresolved share is 4/10, resolved precision 5/6, and the sensitivity lower bound 5/10.
    """
    frame = precision.build_frame([corpus["run"]], population="first_b", budget=5, systems=["improved"])
    sample = precision.draw_sample(frame, size=10, seed=11)
    reviewed = {entry["unit_id"] for entry in sample["selected"][:6]}
    return precision.estimate(sample, review_units(sample, verdict_for("improved"), only=reviewed))


def test_unresolved_or_unreviewed_claims_leave_the_requirements_inconclusive_not_failed(corpus):
    """Six of ten sampled claims are reviewed, by two reviewers each; the other four have no review at all.

    By unit id the first six are p10, p1, p2, p3, p4, and p5: five true and one false. All four others count
    as unresolved: the unresolved share is 4/10, the grade is incomplete, and resolved precision is 5/6 over
    the reviewed claims. The share and the grade are unmet, which is unresolved evidence and not a finding
    that the claims are false; the sensitivity lower bound, which counts them false, is 5/10 and falls below 0.6.
    """
    partial = partially_reviewed(corpus)
    assert partial["unresolved_share"] == 0.4 and partial["evidence_grade"] == "incomplete"
    assert partial["precision_resolved"] == 5 / 6 and partial["sensitivity"]["lower"] == 0.5

    decision = decide(corpus, gate_policy(precision=precision_block(min_value=0.5, max_unresolved_share=0.2)),
                      precision_candidate=partial)

    assert decision["failed"] == [] and decision["outcome"] == "inconclusive"
    assert requirement(decision, "precision.max_unresolved_share")["explanation"] == (
        "the unresolved share is 0.4, above the allowed 0.2: too much of the review is unresolved for the figures "
        "to be trusted, so it is not a finding that the claims are false")
    assert requirement(decision, "precision.min_evidence_grade")["explanation"] == (
        "the review's evidence grade is incomplete, below the required double_review_or_adjudicated: 4 sampled "
        "claim(s) have no review and 0 have disagreeing reviews with no adjudication")

    lower = gate.evaluate_gate(gate_policy(precision=precision_block(basis="sensitivity_lower", min_value=0.6,
                                                                     max_unresolved_share=1.0,
                                                                     min_evidence_grade="single_review")),
                               corpus["comparisons"]["improved"], precision_candidate=partial)
    item = requirement(lower, "precision.min_value")
    assert item["status"] == "fail" and item["observed"]["value"] == 0.5
    assert item["explanation"] == "the sensitivity lower bound of precision is 0.5, below the required 0.6"
    resolved = requirement(gate.evaluate_gate(gate_policy(precision=precision_block(min_value=0.6)),
                                              corpus["comparisons"]["improved"], precision_candidate=partial),
                           "precision.min_value")
    assert resolved["status"] == "pass", "resolved precision 5/6 ignores the unreviewed claims"


def test_a_review_by_one_person_meets_a_single_review_grade_and_not_a_double_one(corpus):
    solo = estimate_for(corpus["run"], "improved", reviewers=(REVIEWER_A,))
    assert solo["evidence_grade"] == "single_review"

    strict = decide(corpus, gate_policy(precision=precision_block()), precision_candidate=solo)
    relaxed = decide(corpus, gate_policy(precision=precision_block(min_evidence_grade="single_review")),
                     precision_candidate=solo)

    assert requirement(strict, "precision.min_evidence_grade")["explanation"] == (
        "the review's evidence grade is single_review, below the required double_review_or_adjudicated: 10 "
        "sampled claim(s) rest on a single reviewer")
    assert strict["outcome"] == "inconclusive" and relaxed["outcome"] == "pass"


def test_an_estimate_whose_sample_leaves_strata_unsampled_does_not_meet_a_coverage_requirement(corpus):
    """Ten one-claim inputs stratified by input with a sample of 5: five strata draw a unit, five draw none.

    Half the population is not estimated at all, so the share is 0.5 and the coverage requirement, which asks
    for 0.9, is unresolved.
    """
    half = estimate_for(corpus["run"], "improved", size=5, stratify_by="input")
    assert half["coverage"]["share"] == 0.5 and len(half["coverage"]["uncovered_strata"]) == 5

    decision = decide(corpus, gate_policy(precision=precision_block(min_coverage=0.9)), precision_candidate=half)

    item = requirement(decision, "precision.min_coverage")
    assert item["status"] == "inconclusive" and item["observed"]["share"] == 0.5
    assert item["explanation"] == (
        "the sampled strata hold 5 of the population's 10 unit(s), a share of 0.5, below the required 0.9; a "
        "stratum that drew no unit is not estimated at all")


def test_the_precision_interval_bound_passes_fails_or_waits_on_what_the_interval_shows(corpus, estimates):
    """A census has no sampling variance; a doctored interval stands in for the other states."""
    policy = gate_policy(precision=precision_block(min_interval_lower_bound=0.6))

    def verdict(**interval) -> tuple[str, str]:
        estimate = deepcopy(estimates["improved"])
        estimate["interval"].update(interval)
        item = requirement(decide(corpus, policy, precision_candidate=estimate), "precision.interval")
        return item["status"], item["explanation"]

    assert verdict()[0] == "pass", "the census interval is [0.8, 0.8]"
    assert verdict(state="ok", lower=0.6, upper=0.95)[0] == "pass"
    status, explanation = verdict(state="ok", lower=0.5, upper=0.95)
    assert status == "inconclusive"
    assert "reaches below 0.6, so precision at that level is not established" in explanation
    status, explanation = verdict(state="ok", lower=0.2, upper=0.5)
    assert status == "fail" and "lies wholly below 0.6" in explanation
    reaching = verdict(state="ok", lower=0.2, upper=0.6)
    assert reaching[0] == "inconclusive", "an interval reaching the bound is not wholly below it"
    status, explanation = verdict(state="degenerate", lower=None, upper=None)
    assert status == "inconclusive" and explanation == (
        "the estimate's interval is degenerate, so it carries no bounds")


def test_a_fall_in_precision_from_the_baseline_fails_and_needs_a_baseline_estimate(corpus, estimates):
    """The flagging system's claims are all judged false: precision 0 against the baseline's 0.2, a fall of 0.2."""
    worse = estimate_for(corpus["run"], "flagging", lambda unit_id: "false")
    assert worse["precision_resolved"] == 0.0
    policy = gate_policy(precision=precision_block(min_value=0.01, max_decrease_vs_baseline=0.05))

    decision = decide(corpus, policy, "flagging", precision_baseline=estimates["baseline"],
                      precision_candidate=worse)
    assert requirement(decision, "precision.max_decrease")["status"] == "fail"
    assert requirement(decision, "precision.max_decrease")["explanation"] == (
        "resolved precision went from 0.2 to 0, a decrease of 0.2, more than the allowed 0.05")
    same = decide(corpus, gate_policy(precision=precision_block(min_value=0.1, max_decrease_vs_baseline=0.0)),
                  "flagging", precision_baseline=estimates["baseline"], precision_candidate=estimates["flagging"])
    assert requirement(same, "precision.max_decrease")["status"] == "pass", "0.2 to 0.2 is no decrease"

    missing = decide(corpus, policy, "flagging", precision_candidate=estimates["flagging"])
    assert requirement(missing, "precision.max_decrease")["status"] == "inconclusive"
    assert requirement(missing, "precision.max_decrease")["explanation"] == (
        "the change in precision is not established: baseline: no precision estimate was supplied for the "
        "baseline baseline")
    wrong = decide(corpus, policy, "flagging", precision_baseline=estimates["improved"],
                   precision_candidate=estimates["flagging"])
    assert "baseline: the estimate covers improved, not only the baseline baseline" in requirement(
        wrong, "precision.max_decrease")["explanation"]


def test_a_supplied_estimate_the_policy_does_not_read_is_recorded_by_digest_and_noted(corpus, estimates):
    decision = decide(corpus, gate_policy(), precision_candidate=estimates["improved"])

    assert decision["precision"]["candidate"]["sha256"] == canonical_sha256(estimates["improved"])
    assert decision["precision"]["baseline"] is None
    assert ("A precision estimate was supplied for the candidate but the policy declares no precision block, so "
            "it is recorded by digest and was not read.") in decision["notes"]
    assert canonical_json(decision) != canonical_json(decide(corpus, gate_policy()))
    unread = decide(corpus, gate_policy(precision=precision_block()), precision_baseline=estimates["baseline"],
                    precision_candidate=estimates["improved"])
    assert ("A baseline precision estimate was supplied, but the policy declares no maximum decrease from the "
            "baseline, so it is recorded by digest and was not read.") in unread["notes"]


# --- controls, completion, and target coverage ------------------------------------------------------


def bounds(**changes) -> dict:
    block = {"max_false_alarm_upper": 0.1, "min_completed_mass": 0.9, "min_assessable_mass": 0.9}
    block.update(changes)
    return block


def control_run(root: Path, run_id: str, *, kind: str | None = "capability_safe", candidate_controls=None,
                baseline_pending=()) -> Path:
    """Five projects, one target and (unless *kind* is None) one control each.

    The baseline detects T-p1 and T-p2, the second only as an unresolved match when *baseline_pending* names
    it; the candidate detects T-p1 to T-p4 with one claim per scan. *candidate_controls* maps a project number
    to the candidate's assessment of its control.
    """
    inputs = [planned(f"p{index}", project=f"acme/p{index}",
                      targets=[target(f"T-p{index}", project=f"acme/p{index}", family=f"family-{index}")],
                      controls=[] if kind is None else [control(f"C-p{index}", kind=kind, target_id=f"T-p{index}"
                                                                if kind != "capability_safe" else None)])
              for index in range(1, 6)]
    outcomes = {}
    for index in range(1, 6):
        pending = {f"T-p{index}": 1} if index in baseline_pending else {}
        outcomes[(f"p{index}", "baseline", 1)] = scan(hits={f"T-p{index}": 1} if index == 1 else {}, pending=pending,
                                                      claims=1)
        outcomes[(f"p{index}", "candidate", 1)] = scan(
            hits={f"T-p{index}": 1} if index <= 4 else {}, claims=1,
            controls={f"C-p{index}": (candidate_controls or {}).get(index, "quiet")} if kind else {})
    return write_run(root, run_id, inputs, systems=("baseline", "candidate"), outcomes=outcomes,
                     configs={"candidate": {"config": {"knob": 2}}})


def control_comparison(root: Path, run_id: str, **choices) -> dict:
    return aggregate.compare([control_run(root, run_id, **choices)], baseline="baseline", candidate="candidate",
                             policy=aggregation_policy())


def test_a_genuine_improvement_passes_every_control_requirement(corpus):
    """The improved system is quiet on all ten controls: E = 0, and every control completed and resolved.

    C = 1 and A = 1, so the completed bounds are [0/1, (0 + 1 - 1)/1] = [0, 0], and F+ is 0.
    """
    decision = decide(corpus, gate_policy(controls={"capability_safe": bounds()}))

    assert decision["outcome"] == "pass"
    assert [item["id"] for item in decision["requirements"] if item["id"].startswith("controls.")] == [
        "controls.capability_safe.false_alarm_upper", "controls.capability_safe.completed_mass",
        "controls.capability_safe.assessable_mass"]
    upper = requirement(decision, "controls.capability_safe.false_alarm_upper")
    assert upper["explanation"] == (
        "the capability_safe false-alarm upper bound F+ is 0 (confirmed rate 0 on resolved controls; 0 unresolved "
        "assessment(s) counted as false allegations), within the allowed 0.1")
    assert upper["observed"]["false_alarm_upper"] == 0.0 and upper["observed"]["completed"] == 10
    assert upper["threshold"] == {"class": "capability_safe", "max_false_alarm_upper": 0.1}
    assert requirement(decision, "controls.capability_safe.completed_mass")["explanation"] == (
        "the completed capability_safe control mass is 1 (10 of 10 observations completed, 10 resolved), at least "
        "the required 0.9")


def test_a_flag_everything_candidate_fails_the_control_false_alarm_bound_whatever_its_recall(corpus):
    """The flagging system alleges every control falsely: E = 1, C = A = 1, so F+ = (1 + 1 - 1)/1 = 1."""
    decision = decide(corpus, gate_policy(controls={"capability_safe": bounds()}), "flagging")

    assert requirement(decision, "primary.improvement")["observed"]["candidate"] == 1.0
    assert decision["outcome"] == "fail" and decision["failed"] == ["controls.capability_safe.false_alarm_upper"]
    assert requirement(decision, "controls.capability_safe.false_alarm_upper")["explanation"] == (
        "the capability_safe false-alarm upper bound F+ is 1 (confirmed rate 1 on resolved controls; 0 unresolved "
        "assessment(s) counted as false allegations), above the allowed 0.1")


def test_a_silent_candidate_is_quiet_on_controls_and_only_its_detection_fails(corpus):
    decision = decide(corpus, gate_policy(controls={"capability_safe": bounds()}), "silent")

    assert statuses(decision)["controls.capability_safe.false_alarm_upper"] == "pass"
    assert decision["failed"] == ["primary.improvement"]


def test_missing_required_controls_are_inconclusive_and_never_a_perfect_score(corpus, tmp_path):
    """No fixed-target control is planned anywhere, and a pack with no controls at all has none to read."""
    decision = decide(corpus, gate_policy(controls={"capability_safe": bounds(), "fixed_target": bounds()}))

    assert decision["outcome"] == "inconclusive" and decision["failed"] == []
    assert statuses(decision)["controls.capability_safe.false_alarm_upper"] == "pass"
    for check in ("false_alarm_upper", "completed_mass", "assessable_mass"):
        item = requirement(decision, f"controls.fixed_target.{check}")
        assert item["status"] == "inconclusive" and item["observed"] is None
        assert item["explanation"] == ("the comparison plans no fixed_target control in full/standard, so there is "
                                       "no false-alarm bound to read, and none is assumed to be zero")

    bare = control_comparison(tmp_path, "run-bare", kind=None)
    assert bare["views"][0]["systems"]["candidate"]["slices"][0]["controls"]["capability_safe"][
        "resolved_rate"]["value"] is None
    unresolved = gate.evaluate_gate(gate_policy(controls={"capability_safe": bounds()}), bare)
    assert unresolved["outcome"] == "inconclusive" and len(unresolved["unresolved"]) == 3


def test_unresolved_control_assessments_count_as_false_alarms_in_the_bound_and_leave_the_mass_short(tmp_path):
    """Two of five controls are left unresolved by the reviewer, the other three quiet.

    Every control completed, so C = 1; three are resolved, so A = 3/5; none was confirmed false, so E = 0. The
    confirmed rate E/A is 0, but F+ = (0 + 1 - 3/5)/1 = 0.4 counts the two unresolved as false allegations, so the
    bound fails at 0.1 while the assessable mass 0.6 is short of 0.9 and unresolved.
    """
    comparison = control_comparison(tmp_path, "run-hesitant", candidate_controls={1: "unresolved", 2: "unresolved"})

    decision = gate.evaluate_gate(gate_policy(controls={"capability_safe": bounds()}), comparison)

    assert decision["outcome"] == "fail" and decision["failed"] == ["controls.capability_safe.false_alarm_upper"]
    assert decision["unresolved"] == ["controls.capability_safe.assessable_mass"]
    upper = requirement(decision, "controls.capability_safe.false_alarm_upper")
    assert upper["observed"]["false_alarm_upper"] == pytest.approx(0.4) and upper["observed"]["resolved_rate"] == 0.0
    assert upper["explanation"] == (
        "the capability_safe false-alarm upper bound F+ is 0.4 (confirmed rate 0 on resolved controls; 2 unresolved "
        "assessment(s) counted as false allegations), above the allowed 0.1")
    assert requirement(decision, "controls.capability_safe.assessable_mass")["explanation"] == (
        "the resolved (assessable) capability_safe control mass is 0.6 (5 of 5 observations completed, 3 resolved), "
        "below the required 0.9: failed and unresolved controls are not quiet ones, so the false-alarm bound rests "
        "on too little of the frozen weight")
    lenient = gate.evaluate_gate(gate_policy(controls={"capability_safe": bounds(
        max_false_alarm_upper=0.4, min_assessable_mass=0.6)}), comparison)
    assert lenient["outcome"] == "pass", "F+ = 0.4 and A = 0.6 sit exactly on the tolerances"


def test_a_failed_scan_is_not_a_quiet_control(corpus):
    """The flaky system errors on two projects: its controls there are neither completed nor resolved.

    C = A = 8/10, E = 0, so F+ = (0 + 0.8 - 0.8)/0.8 = 0 on what completed, but only 0.8 of the frozen control
    weight completed, which is below 0.9: unresolved. The malformed system completed nothing, so its bound is
    undefined rather than zero.
    """
    policy = gate_policy(controls={"capability_safe": bounds()})

    flaky = decide(corpus, policy, "flaky")
    assert statuses(flaky)["controls.capability_safe.false_alarm_upper"] == "pass"
    assert requirement(flaky, "controls.capability_safe.completed_mass")["status"] == "inconclusive"
    assert requirement(flaky, "controls.capability_safe.completed_mass")["explanation"].startswith(
        "the completed capability_safe control mass is 0.8 (8 of 10 observations completed, 8 resolved), below "
        "the required 0.9")

    malformed = decide(corpus, policy, "malformed")
    upper = requirement(malformed, "controls.capability_safe.false_alarm_upper")
    assert upper["status"] == "inconclusive"
    assert upper["explanation"] == ("no capability_safe control observation completed, so the completed false-alarm "
                                    "bound is undefined; a failed scan is not a quiet one")
    assert requirement(malformed, "controls.capability_safe.assessable_mass")["status"] == "inconclusive"


def test_a_control_of_both_types_is_read_in_each_class(tmp_path):
    """A 'both' control appears in the capability-safe and the fixed-target view, with the same figures."""
    comparison = control_comparison(tmp_path, "run-both", kind="both", candidate_controls={5: ("false_allegation", 1)})

    decision = gate.evaluate_gate(gate_policy(controls={"capability_safe": bounds(max_false_alarm_upper=0.2),
                                                        "fixed_target": bounds(max_false_alarm_upper=0.2)}),
                                  comparison)

    for name in ("capability_safe", "fixed_target"):
        item = requirement(decision, f"controls.{name}.false_alarm_upper")
        assert item["status"] == "pass" and item["observed"]["false_allegations"] == 1
        assert item["observed"]["false_alarm_upper"] == pytest.approx(0.2)


def test_completion_is_read_from_the_assigned_work_with_every_failure_counted(corpus):
    """The flaky system succeeds on 8 of 10 scans and errors on 2: completion 0.8 against the baseline's 1."""
    policy = gate_policy(completion={"min": 0.9, "max_decrease": 0.02})

    good = decide(corpus, policy)
    assert good["outcome"] == "pass"
    assert requirement(good, "completion.min")["explanation"] == (
        "the candidate completed 1 of the assigned work (success 10 scan(s) by status), at least the required 0.9")
    assert requirement(good, "completion.max_decrease")["explanation"] == (
        "completion went from 1 to 1, +0, a decrease of at most the allowed 0.02")

    flaky = decide(corpus, policy, "flaky")
    assert flaky["failed"] == ["completion.min", "completion.max_decrease"]
    assert requirement(flaky, "completion.min")["explanation"] == (
        "the candidate completed 0.8 of the assigned work (success 8, error 2 scan(s) by status), below the "
        "required 0.9")
    assert requirement(flaky, "completion.max_decrease")["explanation"] == (
        "completion went from 1 to 0.8, -0.2, a decrease of more than the allowed 0.02")
    assert requirement(flaky, "completion.min")["observed"]["baseline"] == 1.0
    lenient = decide(corpus, gate_policy(completion={"min": 0.8, "max_decrease": 0.2}), "flaky")
    assert statuses(lenient)["completion.min"] == statuses(lenient)["completion.max_decrease"] == "pass"


def test_a_malformed_output_candidate_fails_completion(corpus):
    """An error on every scan completes 0 of the assigned work, so both completion requirements fail."""
    decision = decide(corpus, gate_policy(completion={"min": 0.9, "max_decrease": 0.02}), "malformed")

    assert decision["outcome"] == "fail"
    assert decision["failed"] == ["primary.improvement", "completion.min", "completion.max_decrease"]
    assert requirement(decision, "completion.min")["explanation"] == (
        "the candidate completed 0 of the assigned work (error 10 scan(s) by status), below the required 0.9")


def test_inputs_that_could_not_be_prepared_stay_in_the_completion_denominator(tmp_path):
    """Two of five inputs fail preparation for both systems; both complete 3 of 5 = 0.6, and neither drops them."""
    inputs = [planned(f"p{index}", project=f"acme/p{index}",
                      targets=[target(f"T-p{index}", project=f"acme/p{index}", family=f"family-{index}")])
              for index in range(1, 6)]
    run = write_run(tmp_path, "run-failed", inputs, systems=("baseline", "candidate"), failed_inputs=("p4", "p5"),
                    outcomes={("p1", "baseline", 1): scan(hits={"T-p1": 1}, claims=1),
                              ("p1", "candidate", 1): scan(hits={"T-p1": 1}, claims=1),
                              ("p2", "candidate", 1): scan(hits={"T-p2": 1}, claims=1)},
                    configs={"candidate": {"config": {"knob": 2}}})
    comparison = aggregate.compare([run], baseline="baseline", candidate="candidate", policy=aggregation_policy())

    decision = gate.evaluate_gate(gate_policy(completion={"min": 0.9, "max_decrease": 0.0}), comparison)

    assert requirement(decision, "completion.min")["observed"]["candidate"] == 0.6
    assert requirement(decision, "completion.min")["observed"]["failures"]["failed_preparation"] == 2
    assert statuses(decision)["completion.min"] == "fail" and statuses(decision)["completion.max_decrease"] == "pass"


def test_an_unresolved_baseline_cannot_make_a_candidate_look_better(tmp_path):
    """The baseline's T-p2 match is left unresolved: it earns no credit and is not assessable.

    The baseline detects T-p1 only (recall 0.2) and has 4 of 5 target observations assessable (the pending one
    is not), a mass of 0.8; the candidate detects four targets (0.8) and all five are assessable. Recall rose by
    +0.6, but part of that is a baseline nobody finished reviewing, so a coverage requirement of 0.9 on BOTH
    systems leaves the improvement unestablished.
    """
    comparison = control_comparison(tmp_path, "run-pending", kind=None, baseline_pending=(2,))
    assert difference_of(comparison)["assessable_mass"] == pytest.approx(0.2)

    decision = gate.evaluate_gate(gate_policy(target_coverage={"min_assessable_mass": 0.9}), comparison)

    assert requirement(decision, "primary.improvement")["status"] == "pass"
    item = requirement(decision, "target_coverage.min_assessable_mass")
    assert item["status"] == "inconclusive" and decision["outcome"] == "inconclusive"
    assert item["observed"]["baseline"]["assessable_mass"] == 0.8
    assert item["observed"]["candidate"]["assessable_mass"] == 1.0
    assert item["explanation"] == (
        "the baseline has 4 of 5 target observations assessable, a mass of 0.8, below the required 0.9: unresolved "
        "or failed observations count as misses, so recall over them is a lower bound and the improvement is not "
        "established")
    assert statuses(gate.evaluate_gate(gate_policy(target_coverage={"min_assessable_mass": 0.8}), comparison))[
        "target_coverage.min_assessable_mass"] == "pass"


def test_target_coverage_holds_both_systems_and_passes_when_both_are_assessable(corpus):
    decision = decide(corpus, gate_policy(target_coverage={"min_assessable_mass": 0.9}))

    item = requirement(decision, "target_coverage.min_assessable_mass")
    assert item["status"] == "pass" and item["threshold"] == {"weighting": "equal_target", "min_assessable_mass": 0.9}
    assert item["explanation"] == ("the assessable target mass is 1 for the baseline and 1 for the candidate, at "
                                   "least the required 0.9")
    flaky = decide(corpus, gate_policy(target_coverage={"min_assessable_mass": 0.9}), "flaky")
    assert requirement(flaky, "target_coverage.min_assessable_mass")["explanation"].startswith(
        "the candidate has 8 of 10 target observations assessable, a mass of 0.8, below the required 0.9")


# --- review burden and cost -------------------------------------------------------------------------


def test_a_genuine_improvement_passes_every_burden_requirement(corpus):
    """Both systems deliver one claim per scan: 1 per assignment each, no duplicate, a ratio of 1."""
    policy = gate_policy(burden={"max_claims_per_assignment": 5, "max_duplicate_share": 0.2,
                                 "max_increase_ratio": 3.0})

    decision = decide(corpus, policy)

    assert decision["outcome"] == "pass"
    assert requirement(decision, "burden.claims_per_assignment")["explanation"] == (
        "the candidate delivered 10 claim record(s) over 10 assignment(s), 1 per assignment, within the allowed 5")
    assert requirement(decision, "burden.duplicate_share")["explanation"] == (
        "0 of the candidate's 10 delivered claim record(s) are exact duplicates of another record of the same "
        "scan, a share of 0, within the allowed 0.2")
    assert requirement(decision, "burden.increase_ratio")["explanation"] == (
        "the candidate's claim volume per assignment is 1 against the baseline's 1, a ratio of 1, within the "
        "allowed 3")
    assert requirement(decision, "burden.increase_ratio")["observed"] == {
        "baseline": 1.0, "candidate": 1.0, "ratio": 1.0}


def test_a_flag_everything_candidate_fails_the_burden_requirements_whatever_its_recall(corpus):
    """The flagging system delivers 12 claims per scan against the baseline's 1: 120 records over 10 assignments."""
    policy = gate_policy(burden={"max_claims_per_assignment": 5, "max_duplicate_share": 0.2,
                                 "max_increase_ratio": 3.0})

    decision = decide(corpus, policy, "flagging")

    assert requirement(decision, "primary.improvement")["observed"]["candidate"] == 1.0
    assert decision["outcome"] == "fail"
    assert decision["failed"] == ["burden.claims_per_assignment", "burden.increase_ratio"]
    assert requirement(decision, "burden.claims_per_assignment")["explanation"] == (
        "the candidate delivered 120 claim record(s) over 10 assignment(s), 12 per assignment, above the allowed 5")
    assert requirement(decision, "burden.increase_ratio")["explanation"] == (
        "the candidate's claim volume per assignment is 12 against the baseline's 1, a ratio of 12, above the "
        "allowed 3")


def test_a_duplicate_spamming_candidate_fails_the_burden_requirements_without_gaining_detection(corpus):
    """The duplicating system sends one claim 20 times per scan: 200 records, 10 unique, 190 duplicate copies.

    It detects exactly what the baseline does, so the primary improvement fails too. Its duplicate share is
    190/200 = 0.95 and its volume 20 claims per assignment against 1: a ratio of 20.
    """
    policy = gate_policy(burden={"max_claims_per_assignment": 5, "max_duplicate_share": 0.2,
                                 "max_increase_ratio": 3.0})

    decision = decide(corpus, policy, "duplicating")

    assert decision["failed"] == ["primary.improvement", "burden.claims_per_assignment", "burden.duplicate_share",
                                  "burden.increase_ratio"]
    assert requirement(decision, "primary.improvement")["observed"]["difference"] == 0.0
    share = requirement(decision, "burden.duplicate_share")
    assert share["observed"]["duplicate_copies"] == 190 and share["observed"]["unique"] == 10
    assert share["explanation"] == (
        "190 of the candidate's 200 delivered claim record(s) are exact duplicates of another record of the same "
        "scan, a share of 0.95, above the allowed 0.2")


def test_silent_and_malformed_candidates_add_no_burden_and_are_failed_elsewhere(corpus):
    """Delivering nothing is no burden; the silent system fails on detection, the malformed one on completion."""
    policy = gate_policy(burden={"max_claims_per_assignment": 5, "max_duplicate_share": 0.2,
                                 "max_increase_ratio": 3.0}, completion={"min": 0.9})

    silent = decide(corpus, policy, "silent")
    assert [statuses(silent)[f"burden.{name}"] for name in ("claims_per_assignment", "duplicate_share",
                                                            "increase_ratio")] == ["pass"] * 3
    assert requirement(silent, "burden.duplicate_share")["explanation"] == (
        "the candidate delivered no claim record, so it delivered no duplicate copy")
    assert silent["failed"] == ["primary.improvement"]
    assert decide(corpus, policy, "malformed")["failed"] == ["primary.improvement", "completion.min"]


def test_a_burden_the_comparison_cannot_supply_is_inconclusive_and_an_increase_from_nothing_fails(corpus):
    """No bundle read means an unknown volume, not zero; a baseline that delivered nothing has no finite ratio."""
    policy = gate_policy(burden={"max_claims_per_assignment": 5, "max_duplicate_share": 0.2,
                                 "max_increase_ratio": 3.0})

    def with_volumes(candidate: dict, baseline: dict) -> dict:
        comparison = deepcopy(corpus["comparisons"]["improved"])
        comparison["views"][0]["systems"]["candidate"]["slices"][0]["claims"].update(candidate)
        comparison["views"][0]["systems"]["baseline"]["slices"][0]["claims"].update(baseline)
        return comparison

    unread = gate.evaluate_gate(policy, with_volumes({"bundles": 0, "records": 0, "unique": 0,
                                                      "duplicate_copies": 0, "delivered": 0}, {}))
    assert statuses(unread)["burden.claims_per_assignment"] == "inconclusive"
    assert requirement(unread, "burden.claims_per_assignment")["explanation"] == (
        "no result bundle was read for the candidate, so its delivered claim volume is unknown, not zero")
    assert unread["outcome"] == "inconclusive"

    nothing_before = gate.evaluate_gate(policy, with_volumes({}, {"records": 0, "unique": 0, "duplicate_copies": 0,
                                                                  "delivered": 0}))
    assert requirement(nothing_before, "burden.increase_ratio")["status"] == "fail"
    assert requirement(nothing_before, "burden.increase_ratio")["explanation"] == (
        "the baseline's claim volume per assignment is zero, so any amount is an unbounded increase over it, above "
        "the allowed 3")
    silence = {"records": 0, "unique": 0, "duplicate_copies": 0, "delivered": 0}
    neither = gate.evaluate_gate(policy, with_volumes(silence, silence))
    assert requirement(neither, "burden.increase_ratio")["status"] == "pass"


def cost_policy(**changes) -> dict:
    block = {"min_coverage": 1.0, "max_per_assignment_usd": 0.2, "max_increase_ratio": 2.0}
    block.update(changes)
    return gate_policy(cost=block)


def test_a_genuine_improvement_passes_every_cost_requirement(corpus):
    """Every scan of both systems reports its cost: the baseline 0.10 and the improved system 0.15, a ratio of 1.5."""
    decision = decide(corpus, cost_policy())

    assert decision["outcome"] == "pass"
    assert [item["id"] for item in decision["requirements"] if item["id"].startswith("cost.")] == [
        "cost.coverage", "cost.per_assignment", "cost.increase_ratio"]
    assert requirement(decision, "cost.coverage")["explanation"] == (
        "the baseline's cost is known for 10 of 10 executed scan(s); the candidate's cost is known for 10 of 10 "
        "executed scan(s), at least the required coverage of 1")
    assert requirement(decision, "cost.per_assignment")["explanation"] == (
        "the candidate's recorded cost is 0.15 USD per executed scan, over 10 scan(s), within the allowed 0.2")
    assert requirement(decision, "cost.increase_ratio")["explanation"] == (
        "the candidate's recorded cost per executed scan is 0.15 against the baseline's 0.1, a ratio of 1.5, "
        "within the allowed 2")


def test_a_candidate_that_costs_more_than_allowed_fails(corpus):
    decision = decide(corpus, cost_policy(max_per_assignment_usd=0.12, max_increase_ratio=1.2))

    assert decision["failed"] == ["cost.per_assignment", "cost.increase_ratio"]
    assert requirement(decision, "cost.per_assignment")["explanation"].endswith("above the allowed 0.12")
    assert requirement(decision, "cost.increase_ratio")["explanation"] == (
        "the candidate's recorded cost per executed scan is 0.15 against the baseline's 0.1, a ratio of 1.5, "
        "above the allowed 1.2")


def test_an_unknown_cost_under_a_cost_constraint_is_inconclusive_never_free(corpus):
    """The late system reports no cost at all: not zero, unknown, so every cost requirement waits."""
    decision = decide(corpus, cost_policy(), "late")

    assert decision["outcome"] == "inconclusive" and decision["failed"] == []
    assert decision["unresolved"] == ["cost.coverage", "cost.per_assignment", "cost.increase_ratio"]
    assert requirement(decision, "cost.coverage")["explanation"] == (
        "the candidate's cost is known for 0 of 10 executed scan(s), a coverage of 0, below the required 1")
    assert requirement(decision, "cost.per_assignment")["explanation"] == (
        "the candidate's cost per scan is not established: the candidate's cost is known for 0 of 10 executed "
        "scan(s), a coverage of 0, below the required 1")
    assert requirement(decision, "cost.per_assignment")["observed"]["mean"] is None
    quiet = decide(corpus, gate_policy(cost={"max_per_assignment_usd": 1000.0}), "late")
    assert requirement(quiet, "cost.per_assignment")["status"] == "inconclusive", "a generous cap does not make it free"
    assert requirement(quiet, "cost.coverage")["explanation"].endswith(
        "(the policy states no lower minimum, so every cost must be known)")


def test_a_cost_coverage_the_policy_accepts_lets_the_known_scans_stand_for_the_rest(corpus):
    """The flaky system reports the cost of 8 of its 10 scans (the two errors report none): coverage 0.8.

    With the default every cost must be known, so it is unresolved; a policy that accepts 0.8 reads the mean of
    the eight known scans, 0.15, against its cap.
    """
    strict = decide(corpus, cost_policy(min_coverage=0.9), "flaky")
    assert strict["unresolved"] == ["cost.coverage", "cost.per_assignment", "cost.increase_ratio"]
    assert requirement(strict, "cost.coverage")["explanation"] == (
        "the candidate's cost is known for 8 of 10 executed scan(s), a coverage of 0.8, below the required 0.9")

    accepting = decide(corpus, cost_policy(min_coverage=0.8), "flaky")
    assert statuses(accepting)["cost.coverage"] == statuses(accepting)["cost.per_assignment"] == "pass"
    assert requirement(accepting, "cost.per_assignment")["observed"]["known"] == 8
    only_coverage = decide(corpus, gate_policy(cost={"min_coverage": 0.8}), "flaky")
    assert [item["id"] for item in only_coverage["requirements"] if item["id"].startswith("cost.")] == ["cost.coverage"]


def test_a_system_that_recorded_no_result_has_an_unknown_cost_not_a_zero_one(corpus):
    """With no bundle read there is no cost to average and no coverage to speak of: unknown, so unresolved."""
    comparison = deepcopy(corpus["comparisons"]["improved"])
    usage = comparison["views"][0]["systems"]["candidate"]["slices"][0]["usage"]
    usage.update(bundles=0, cost_usd={"known_sum": None, "known": 0, "unknown": 0, "coverage": None})

    decision = gate.evaluate_gate(cost_policy(), comparison)

    assert decision["unresolved"] == ["cost.coverage", "cost.per_assignment", "cost.increase_ratio"]
    assert requirement(decision, "cost.coverage")["explanation"] == (
        "no scan of the candidate recorded a result, so its cost is unknown, not zero")
    assert requirement(decision, "cost.per_assignment")["observed"]["mean"] is None


def test_a_cost_increase_from_a_free_baseline_is_unbounded(corpus):
    comparison = deepcopy(corpus["comparisons"]["improved"])
    comparison["views"][0]["systems"]["baseline"]["slices"][0]["usage"]["cost_usd"] = {
        "known_sum": 0.0, "known": 10, "unknown": 0, "coverage": 1.0}

    decision = gate.evaluate_gate(cost_policy(), comparison)

    assert requirement(decision, "cost.increase_ratio")["status"] == "fail"
    assert requirement(decision, "cost.increase_ratio")["explanation"] == (
        "the baseline's recorded cost per executed scan is zero, so any amount is an unbounded increase over it, "
        "above the allowed 2")


# --- acceptance: the scenario fixtures under one complete policy ------------------------------------


def complete_policy(**changes) -> dict:
    """Every block declared, with fixture tolerances chosen so the improved system meets each of them."""
    blocks = dict(
        primary=primary(minimum=0.1, uncertainty={"lower_bound_above": 0.0, "min_confidence": 0.9, "min_clusters": 5}),
        regressions=[regression("whole-view"), regression("each-project", slice={"dimension": "project"}),
                     regression("first-position", kind="recall_at_budget", budget=1)],
        precision=precision_block(min_coverage=0.9, min_interval_lower_bound=0.7, max_decrease_vs_baseline=0.05),
        controls={"capability_safe": bounds()},
        completion={"min": 0.9, "max_decrease": 0.02},
        target_coverage={"min_assessable_mass": 0.9},
        burden={"max_claims_per_assignment": 5, "max_duplicate_share": 0.2, "max_increase_ratio": 3.0},
        cost={"min_coverage": 1.0, "max_per_assignment_usd": 0.2, "max_increase_ratio": 2.0})
    blocks.update(changes)
    return gate_policy(**blocks)


def complete_decision(corpus, estimates, system: str, policy: dict | None = None) -> dict:
    return decide(corpus, policy or complete_policy(), system, precision_baseline=estimates["baseline"],
                  precision_candidate=estimates.get(system))


def test_a_genuine_improvement_passes_only_when_every_configured_constraint_holds(corpus, estimates):
    """All 28 requirements of the complete policy hold for the improved system, and none is vacuous."""
    decision = complete_decision(corpus, estimates, "improved")

    assert decision["outcome"] == "pass" and decision["recommendation_scope"] == "reviewed"
    assert decision["summary"] == {"requirements": 28, "passed": 28, "failed": 0, "inconclusive": 0}
    assert decision["blocks"]["not_declared"] == []
    assert all(item["explanation"] for item in decision["requirements"])


@pytest.mark.parametrize("change, requirement_id, status", [
    (lambda p: p["primary"].update(min_improvement=0.7), "primary.improvement", "fail"),
    (lambda p: p["primary"]["uncertainty"].update(lower_bound_above=0.55), "primary.uncertainty", "inconclusive"),
    (lambda p: p["primary"]["uncertainty"].update(min_clusters=11), "primary.uncertainty", "inconclusive"),
    (lambda p: p["precision"].update(min_value=0.9), "precision.min_value", "fail"),
    (lambda p: p["precision"].update(min_interval_lower_bound=0.9), "precision.interval", "fail"),
    (lambda p: p["burden"].update(max_claims_per_assignment=0.5), "burden.claims_per_assignment", "fail"),
    (lambda p: p["burden"].update(max_increase_ratio=0.5), "burden.increase_ratio", "fail"),
    (lambda p: p["cost"].update(max_per_assignment_usd=0.1), "cost.per_assignment", "fail"),
    (lambda p: p["cost"].update(max_increase_ratio=1.2), "cost.increase_ratio", "fail"),
    (lambda p: p.update(configuration={"allowed_differences": []}), "configuration.allowed_differences",
     "inconclusive"),
])
def test_tightening_any_one_threshold_of_a_passing_policy_flips_the_decision(corpus, estimates, change,
                                                                             requirement_id, status):
    """The improved system passes; each tightened tolerance makes exactly its own requirement fail or wait."""
    policy = complete_policy()
    change(policy)

    decision = complete_decision(corpus, estimates, "improved", policy)

    assert requirement(decision, requirement_id)["status"] == status
    assert decision["outcome"] == ("fail" if status == "fail" else "inconclusive")
    assert (decision["failed"] if status == "fail" else decision["unresolved"]) == [requirement_id]


def test_the_always_silent_candidate_fails_on_detection_and_leaves_precision_unestablished(corpus, estimates):
    """Delivering nothing is quiet and cheap of review, but it detects nothing; no claim exists to estimate."""
    decision = complete_decision(corpus, estimates, "silent")

    assert decision["outcome"] == "fail"
    assert decision["failed"] == ["primary.improvement", "primary.uncertainty", "regression.whole-view",
                                  "regression.each-project", "regression.first-position"]
    assert statuses(decision)["controls.capability_safe.false_alarm_upper"] == "pass"
    assert requirement(decision, "precision.binding")["status"] == "inconclusive"


def test_the_flag_everything_candidate_fails_precision_controls_and_burden_despite_perfect_recall(corpus, estimates):
    decision = complete_decision(corpus, estimates, "flagging")

    assert requirement(decision, "primary.improvement")["observed"]["candidate"] == 1.0
    assert decision["outcome"] == "fail"
    assert decision["failed"] == ["precision.min_value", "precision.interval",
                                  "controls.capability_safe.false_alarm_upper", "burden.claims_per_assignment",
                                  "burden.increase_ratio"]
    assert decision["unresolved"] == ["cost.coverage", "cost.per_assignment", "cost.increase_ratio"]
    assert decision["recommendation_scope"] == "reviewed"


def test_the_duplicate_spam_candidate_fails_burden_and_gains_no_detection(corpus, estimates):
    decision = complete_decision(corpus, estimates, "duplicating")

    assert decision["failed"] == ["primary.improvement", "precision.min_value", "precision.interval",
                                  "burden.claims_per_assignment", "burden.duplicate_share", "burden.increase_ratio"]
    assert decision["unresolved"] == ["primary.uncertainty", "cost.coverage", "cost.per_assignment",
                                      "cost.increase_ratio"]
    assert requirement(decision, "primary.uncertainty")["explanation"].startswith(
        "the paired interval is degenerate (every replicate agreed, which is not certainty)")


def test_the_malformed_output_candidate_fails_completion_and_its_controls_stay_unresolved(corpus, estimates):
    decision = complete_decision(corpus, estimates, "malformed")

    assert decision["outcome"] == "fail"
    assert decision["failed"] == ["primary.improvement", "primary.uncertainty", "regression.whole-view",
                                  "regression.each-project", "regression.first-position", "completion.min",
                                  "completion.max_decrease"]
    for check in ("false_alarm_upper", "completed_mass", "assessable_mass"):
        assert statuses(decision)[f"controls.capability_safe.{check}"] == "inconclusive"
    assert statuses(decision)["target_coverage.min_assessable_mass"] == "inconclusive"


def test_a_flaky_candidate_fails_completion_and_its_failed_scans_are_not_counted_as_quiet(corpus, estimates):
    decision = complete_decision(corpus, estimates, "flaky")

    assert decision["failed"] == ["completion.min", "completion.max_decrease"]
    assert "controls.capability_safe.completed_mass" in decision["unresolved"]
    assert "target_coverage.min_assessable_mass" in decision["unresolved"]
    assert requirement(decision, "primary.improvement")["status"] == "pass", "detection alone would have passed it"


def test_high_recall_cannot_compensate_for_noise_and_no_recall_can_rescue_a_failed_requirement(corpus, estimates):
    """The flagging system's recall is perfect, and each noise requirement fails on its own.

    Declare only one noise block at a time: precision, control false alarms, or burden each fail the decision
    although the primary improvement passes by +0.8 in every case.
    """
    for block, expected in (
            ({"precision": precision_block()}, ["precision.min_value"]),
            ({"controls": {"capability_safe": bounds()}}, ["controls.capability_safe.false_alarm_upper"]),
            ({"burden": {"max_claims_per_assignment": 5}}, ["burden.claims_per_assignment"])):
        decision = decide(corpus, gate_policy(**block), "flagging", precision_candidate=estimates["flagging"])
        assert requirement(decision, "primary.improvement")["observed"]["difference"] == 0.8
        assert decision["outcome"] == "fail" and decision["failed"] == expected


# --- the command line -------------------------------------------------------------------------------


def cli(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def write_json(path: Path, document: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(document) + "\n", encoding="utf-8")
    return path


def gate_command(tmp_path: Path, corpus: dict, policy: dict, system: str = "improved", *, output: str = "decision.json",
                 baseline: dict | None = None, candidate: dict | None = None) -> list[str]:
    """The argv of one ``scaneval gate`` over documents written into *tmp_path*."""
    argv = ["gate", "--policy", str(write_json(tmp_path / "policy.json", policy)),
            "--comparison", str(write_json(tmp_path / f"comparison-{system}.json", corpus["comparisons"][system])),
            "--output", str(tmp_path / output)]
    if baseline is not None:
        argv += ["--precision-baseline", str(write_json(tmp_path / "estimate-baseline.json", baseline))]
    if candidate is not None:
        argv += ["--precision-candidate", str(write_json(tmp_path / f"estimate-{system}.json", candidate))]
    return argv


def test_cli_gate_writes_a_decision_and_exits_0_for_a_pass(corpus, tmp_path, capsys):
    argv = gate_command(tmp_path, corpus, gate_policy())

    code, out, err = cli(capsys, *argv)

    assert code == 0 and err == ""
    output = tmp_path / "decision.json"
    decision = load_document(output, "gate-decision")
    assert output.read_text(encoding="utf-8") == canonical_json(decision) + "\n"
    expected = gate.evaluate_gate(gate_policy(), corpus["comparisons"]["improved"])
    assert canonical_json(decision) == canonical_json(expected)
    lines = out.splitlines()
    assert lines[0] == ("Gate pass: baseline=baseline candidate=improved view=full/standard "
                        "recommendation_scope=reviewed")
    assert lines[1] == f"Policy fixture-gate 1 ({decision['policy_sha256']})"
    assert lines[2] == "Requirements: 5 evaluated, 5 passed, 0 failed, 0 inconclusive"
    assert lines[3] == ("Note: The policy declares no regressions, precision, controls, completion, "
                        "target_coverage, burden, cost block, so those requirements are not part of it and were "
                        "not evaluated.")
    assert lines[-1] == f"Decision: {output}"
    code, out, _err = cli(capsys, "validate", "gate-decision", str(output))
    assert code == 0 and f"Valid gate-decision: {output}" in out
    code, out, _err = cli(capsys, "validate", "gate-policy", str(tmp_path / "policy.json"))
    assert code == 0 and "Valid gate-policy" in out


def test_cli_gate_exits_1_and_names_every_failed_and_unresolved_requirement(corpus, estimates, tmp_path, capsys):
    """The flagging system fails five requirements and leaves three unresolved: all eight are named."""
    policy = complete_policy()
    argv = gate_command(tmp_path, corpus, policy, "flagging", baseline=estimates["baseline"],
                        candidate=estimates["flagging"])

    code, out, err = cli(capsys, *argv)

    assert code == 1 and err == ""
    decision = load_document(tmp_path / "decision.json", "gate-decision")
    assert decision["outcome"] == "fail" and len(decision["failed"]) == 5 and len(decision["unresolved"]) == 3
    lines = out.splitlines()
    assert lines[0].startswith("Gate fail: baseline=baseline candidate=flagging")
    assert lines[2] == "Requirements: 28 evaluated, 20 passed, 5 failed, 3 inconclusive"
    for requirement_id in decision["failed"]:
        assert f"FAIL {requirement_id}: {requirement(decision, requirement_id)['explanation']}" in lines
    for requirement_id in decision["unresolved"]:
        assert f"INCONCLUSIVE {requirement_id}: {requirement(decision, requirement_id)['explanation']}" in lines
    assert "FAIL precision.min_value: resolved precision is 0.2, below the required 0.5" in lines
    assert not any(line.startswith("Note: The policy declares no") for line in lines), "every block is declared"


def test_cli_gate_exits_1_for_an_inconclusive_decision(corpus, tmp_path, capsys):
    argv = gate_command(tmp_path, corpus, gate_policy(configuration={"allowed_differences": []}))

    code, out, err = cli(capsys, *argv)

    assert code == 1 and err == ""
    assert out.splitlines()[0].startswith("Gate inconclusive:")
    assert ("INCONCLUSIVE configuration.allowed_differences: the systems also differ in config.knob, which the policy "
            "does not intend to measure, so the comparison does not isolate the intended change") in out.splitlines()
    assert load_document(tmp_path / "decision.json", "gate-decision")["outcome"] == "inconclusive"


def test_cli_gate_needs_the_estimates_a_policy_reads_and_names_the_ones_it_lacks(corpus, estimates, tmp_path, capsys):
    argv = gate_command(tmp_path, corpus, gate_policy(precision=precision_block(max_decrease_vs_baseline=0.05)))

    code, out, _err = cli(capsys, *argv)

    assert code == 1
    assert "INCONCLUSIVE precision.binding: the candidate's precision estimate is missing or not bound to this " \
           "comparison: no precision estimate was supplied for the candidate improved" in out.splitlines()
    supplied = gate_command(tmp_path, corpus, gate_policy(precision=precision_block(max_decrease_vs_baseline=0.05)),
                            output="second.json", baseline=estimates["baseline"], candidate=estimates["improved"])
    code, out, _err = cli(capsys, *supplied)
    assert code == 0, out
    decision = load_document(tmp_path / "second.json", "gate-decision")
    assert decision["precision"]["candidate"]["sha256"] == canonical_sha256(estimates["improved"])


def test_cli_gate_says_when_it_was_given_an_estimate_the_policy_does_not_read(corpus, estimates, tmp_path, capsys):
    argv = gate_command(tmp_path, corpus, gate_policy(), candidate=estimates["improved"])

    code, out, err = cli(capsys, *argv)

    assert code == 0 and err == ""
    assert ("Note: A precision estimate was supplied for the candidate but the policy declares no precision block, "
            "so it is recorded by digest and was not read.") in out.splitlines()
    assert not any(line.startswith("Note: This decision holds") for line in out.splitlines()), (
        "the standing statements stay in the decision and are not repeated on every run")


def test_cli_gate_exits_2_and_writes_nothing_when_it_cannot_evaluate(corpus, estimates, tmp_path, capsys):
    random_order = write_json(tmp_path / "random.json", gate_policy(primary=primary("random_order_expected_recall")))
    comparison = write_json(tmp_path / "comparison.json", corpus["comparisons"]["improved"])
    policy = write_json(tmp_path / "policy.json", gate_policy())
    not_a_comparison = write_json(tmp_path / "not-a-comparison.json", {"schema_version": "2.0"})

    for argv, message in (
            (["--policy", str(random_order), "--comparison", str(comparison)],
             "primary.metric: 'random_order_expected_recall'"),
            (["--policy", str(tmp_path / "absent.json"), "--comparison", str(comparison)], "could not load"),
            (["--policy", str(policy), "--comparison", str(tmp_path / "absent.json")], "could not load"),
            (["--policy", str(policy), "--comparison", str(not_a_comparison)], "schema_version"),
            (["--policy", str(policy), "--comparison", str(comparison), "--precision-candidate", str(comparison)],
             "Additional properties are not allowed")):
        output = tmp_path / "refused.json"
        code, out, err = cli(capsys, "gate", *argv, "--output", str(output))
        assert code == 2 and out == "" and err.startswith("scaneval: ") and message in err, err
        assert not output.exists()


def test_cli_gate_output_is_create_only_and_refused_inside_a_trial_or_a_run_directory(corpus, tmp_path, capsys):
    argv = gate_command(tmp_path, corpus, gate_policy())
    assert cli(capsys, *argv)[0] == 0
    output = tmp_path / "decision.json"
    written = output.read_bytes()

    code, out, err = cli(capsys, *argv)
    assert code == 2 and out == "" and "scaneval:" in err
    assert output.read_bytes() == written, "an existing decision is never overwritten"

    trial = tmp_path / "trial"
    (trial / "source").mkdir(parents=True)
    (trial / "provenance.json").write_text("{}", encoding="utf-8")
    inside_trial = trial / "decision.json"
    argv_trial = gate_command(tmp_path, corpus, gate_policy(), output="trial/decision.json")
    code, out, err = cli(capsys, *argv_trial)
    assert code == 2 and out == "" and "inside the trial directory" in err
    assert not inside_trial.exists()

    inside_run = corpus["run"] / "decision.json"
    argv_run = [*gate_command(tmp_path, corpus, gate_policy())[:-1], str(inside_run)]
    code, out, err = cli(capsys, *argv_run)
    assert code == 2 and out == "" and "inside the run directory" in err
    assert "a gate decision binds to the runs its comparison read and stays outside them" in err
    assert not inside_run.exists()


def test_cli_gate_decisions_replay_to_the_same_bytes(corpus, estimates, tmp_path, capsys):
    """The same policy, comparison, and estimates in two directories give identical files and identical stdout."""
    written, printed = [], []
    for name in ("first", "second"):
        directory = tmp_path / name
        argv = gate_command(directory, corpus, complete_policy(), "flagging", baseline=estimates["baseline"],
                            candidate=estimates["flagging"])
        code, out, _err = cli(capsys, *argv)
        assert code == 1
        written.append((directory / "decision.json").read_bytes())
        printed.append(out.replace(str(directory), "<dir>"))

    assert written[0] == written[1] and printed[0] == printed[1]
    assert printed[0].splitlines()[-1] == "Decision: <dir>/decision.json"


def test_cli_help_describes_the_gate_command(capsys):
    with pytest.raises(SystemExit) as raised:
        main(["gate", "--help"])
    assert raised.value.code == 0
    text = " ".join(capsys.readouterr().out.split())

    assert "pass only when every requirement the policy declares holds, fail when any fails, inconclusive when " \
           "none fails and any could not be settled" in text
    assert "Exit 0 for a pass, 1 for a fail or an inconclusive decision, 2 when it could not evaluate." in text
    assert "--policy POLICY" in text and "--comparison COMPARISON" in text and "--output OUTPUT" in text
    assert "--precision-baseline PRECISION_BASELINE" in text and "--precision-candidate PRECISION_CANDIDATE" in text
    assert "nothing is approved or promoted" in text


# --- the example policy -----------------------------------------------------------------------------

EXAMPLE_POLICY = Path(__file__).resolve().parents[1] / "examples" / "gate-policy.json"


def test_the_example_policy_is_valid_declares_every_block_and_is_labelled_as_example_values():
    document = json.loads(EXAMPLE_POLICY.read_text(encoding="utf-8"))

    assert validate_document("gate-policy", document) is document
    assert gate_declared_blocks(document) == list(ALL_BLOCKS)
    assert "example" in document["policy_id"] and document["policy_version"].endswith("-example")
    notes = " ".join(document["notes"])
    assert "Example values for a fixture or a first try only" in notes
    assert "not recommended, reviewed, or validated tolerances" in notes
    assert "Freeze your own thresholds before any result is read" in notes
    assert gate.load_policy(EXAMPLE_POLICY)["required_scope"] == "reviewed"


def test_the_example_policy_evaluates_a_real_comparison_and_promises_nothing(corpus):
    """It is a template with its own example tolerances, not tuned to any run: it does not pass the fixture."""
    decision = gate.evaluate_gate(gate.load_policy(EXAMPLE_POLICY), corpus["comparisons"]["improved"])

    assert validate_document("gate-decision", decision) is decision
    assert decision["outcome"] != "pass" and decision["blocks"]["not_declared"] == []
    assert requirement(decision, "configuration.allowed_differences")["status"] == "inconclusive"
    assert requirement(decision, "precision.binding")["status"] == "inconclusive"


# --- the real pipeline: scripted adapters run by the runner, reviewed through the review commands -----

REAL_SOURCE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
REAL_REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
                   "assumption, and adds a single-file Python sink for the gate tests.")


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


class ScriptedAdapter(Adapter):
    """Delivers as many claims on the accepted location as its system's configuration says, or fails. No network."""

    name = "fake"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})

    def prepare(self, spec, cache_root):
        return {"system": spec.system_id}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        native = raw_dir / "native.json"
        native.write_text('{"findings": []}\n', encoding="utf-8")
        if spec.config.get("status") == "error":
            return NativeOutcome(status="error", exit_code=1, command=["fake", "scan"],
                                 artifacts=[{"id": "native", "path": native}], tool_versions={"fake": "1.0.0"},
                                 error={"code": "malformed_output", "message": "the scripted output cannot be parsed"},
                                 capture={"model_requests": "not_applicable"}, notes=["scripted failure"])
        claims = [{"claim_id": f"c{index}", "allegation": f"shell=True with a caller-controlled command ({index})",
                   "kind": "command_injection", "native_rule_id": "fake.shell", "raw_artifact_id": "native",
                   "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5}}
                  for index in range(1, spec.config.get("claims", 0) + 1)]
        return NativeOutcome(status="success", exit_code=0, command=["fake", "scan"], claims=claims,
                             artifacts=[{"id": "native", "path": native}], tool_versions={"fake": "1.0.0"},
                             capture={"model_requests": "not_applicable"}, notes=["scripted run"])


def real_runs(root: Path) -> dict:
    """A real local repository and pack, and two runs of two scripted systems through ``run_from_config``.

    The first run has no declared tree hash, so it freezes no plan, but it exports the snapshot and records
    its mechanical checks in the pack it freezes. A fictional reviewer then approves that case at L3 and a
    fictional curator admits it, and the second run, from that pack, freezes a plan whose scope is reviewed.
    The 'silent' system delivers nothing, the 'finder' one claim on the labeled sink, the 'flagger' twelve
    claims there, and the 'broken' one fails every scan. Every bundle the second run wrote is still a machine
    draft.
    """
    repo = root / "upstream"
    (repo / "src").mkdir(parents=True)
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "src" / "app.py").write_text(REAL_SOURCE, encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    pack = cases.new_pack("test", "gate-runner", "Local fixture pack for the gate tests.")
    cases.add_snapshot(pack, {
        "snapshot_id": "snap-a", "repository": {"url": str(repo), "name": "widget"},
        "commit": git("rev-parse", "HEAD", cwd=repo),
        "reference": "Commit chosen by the test fixture; no advisory is claimed.", "languages": ["python"],
        "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}})
    case = cases.draft_case(
        "case-a", snapshot_id="snap-a", kind="command_injection",
        description="Caller-controlled command string reaches subprocess with shell=True.",
        represents=REAL_REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                 reference="src/app.py", note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "sink", "note": ""}])
    case["controls"].append({
        "control_id": "C-case-a-safe", "snapshot_id": "snap-a", "type": "capability_safe",
        "description": "The import line is not an allegation.",
        "property": "No caller-supplied string reaches a shell at the import line.",
        "allowed_actors_inputs": "Operators on the host.", "assumptions": ["Default deployment."],
        "ruled_out_allegation": "Command injection through the import line.",
        "locations": [{"path": "src/app.py", "start_line": 1, "end_line": 1, "role": "operation"}],
        "evidence_ids": ["source"]})
    cases.add_case(pack, case)
    cases.save_pack(root / "pack.json", pack)
    config = {"schema_version": "2.1", "run_id": "run-first", "pack": "pack.json", "cache_root": "cache",
              "inputs": [{"snapshot_id": "snap-a"}],
              "systems": [{"system_id": "silent", "adapter": "fake", "config": {"claims": 0}},
                          {"system_id": "finder", "adapter": "fake", "config": {"claims": 1}},
                          {"system_id": "flagger", "adapter": "fake", "config": {"claims": 12}},
                          {"system_id": "broken", "adapter": "fake", "config": {"status": "error"}}],
              "repetitions": 1, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none"}
    (root / "run.json").write_text(canonical_json(config) + "\n", encoding="utf-8")
    first = root / "first"
    run_from_config(root / "run.json", first, clock=CLOCK, adapters={"fake": ScriptedAdapter()})
    frozen = cases.load_pack(first / "evaluator" / "pack.json")
    cases.set_disposition(frozen, "case-a", "validate", "evidence reviewed by a fictional reviewer")
    cases.approve_case(frozen, "case-a", reviewer=REVIEWER, role="independent_reviewer", level="L3",
                       note="fixture label established by a fictional reviewer", clock=CLOCK)
    cases.admit_case(frozen, "case-a", decision="admitted", by="Fixture Curator (fictional)",
                     reason="fixture admission by a fictional curator", clock=CLOCK)
    cases.save_pack(root / "pack.json", frozen)
    (root / "run.json").write_text(canonical_json({**config, "run_id": "run-second"}) + "\n", encoding="utf-8")
    second = root / "second"
    run_from_config(root / "run.json", second, clock=CLOCK, adapters={"fake": ScriptedAdapter()})
    return {"first": first, "second": second}


def approve_like_a_reviewer(bundle: Path, capsys, false_control_claims=()) -> None:
    """A fictional reviewer's decisions for one bundle, filed through the real ``review`` commands.

    The first claim is accepted as the labeled sink and any other routed claim is rejected. The control is
    assessed quiet, or a false allegation citing *false_control_claims* when those are named. The decisions
    file is edited by hand, re-drafted with ``review record`` when it changed, and approved with ``review
    approve``.
    """
    path = bundle / "evaluator" / "decisions.json"
    before = path.read_text(encoding="utf-8")
    decisions = json.loads(before)
    for match in decisions["claim_matches"]:
        if match["claim_id"] == "c1":
            match.update(decision="accepted", reason="fixture: the labeled sink, accepted by a fictional reviewer")
        else:
            match.update(decision="rejected", reason="fixture: not the labeled sink, rejected by a fictional reviewer")
    for assessment in decisions["control_assessments"]:
        if false_control_claims:
            assessment.update(decision="false_allegation", claim_ids=list(false_control_claims),
                              reason="fixture: alleges what the control rules out")
        else:
            assessment.update(decision="quiet", reason="fixture: no allegation about the control's property")
    after = canonical_json(decisions) + "\n"
    if after != before:
        path.write_text(after, encoding="utf-8")
        assert cli(capsys, "review", "record", str(bundle))[0] == 0
    code, _out, err = cli(capsys, "review", "approve", str(bundle), "--reviewer", REVIEWER, "--note",
                          "fixture approval by a fictional reviewer")
    assert code == 0, err


def test_evidence_from_a_real_run_is_draft_until_a_reviewer_approves_it_and_only_then_passes(tmp_path, capsys):
    """Scripted adapters run by the runner, a pack a fictional reviewer approved, then the real review commands.

    Before any bundle is approved the plan is reviewed but every review record is a machine draft, so the
    evidence is draft: the evidence requirement is inconclusive and the decision supports no recommendation.
    A draft match earns no detection credit and a draft control assessment is unresolved, which F+ counts as a
    false allegation, so the decision fails too; a draft policy yields a development decision. After the
    reviewer approves both bundles the same policy passes as a reviewed recommendation: the finder detects the
    one labeled target (recall 1 against 0), is quiet on the control, completes every scan, delivers one claim
    per assignment, and its one delivered claim is reviewed true by two fictional reviewers.
    """
    runs = real_runs(tmp_path)
    second = runs["second"]
    schedule_row = load_document(runs["first"] / "evaluator" / "schedule.json", "evaluation-schedule")["inputs"][0]
    assert schedule_row["plan"]["state"] == "unavailable", "the first run declared no tree hash, so it froze no plan"
    frozen = load_document(second / "evaluator" / "schedule.json", "evaluation-schedule")["inputs"][0]["plan"]
    assert frozen["state"] == "frozen" and frozen["scope"] == "reviewed"
    policy = gate_policy(
        configuration={"allowed_differences": ["config.claims"]}, primary=primary(minimum=0.5),
        controls={"capability_safe": bounds()}, completion={"min": 1.0}, target_coverage={"min_assessable_mass": 1.0},
        burden={"max_claims_per_assignment": 5, "max_duplicate_share": 0.0})
    settings = aggregation_policy(min_clusters=2)

    draft = aggregate.compare([second], baseline="silent", candidate="finder", policy=settings)
    assert draft["views"][0]["evidence_scope"] == {"baseline": "draft", "candidate": "draft"}
    unapproved = gate.evaluate_gate(policy, draft)
    assert unapproved["recommendation_scope"] == "none" and unapproved["outcome"] == "fail"
    assert unapproved["failed"] == ["primary.improvement", "controls.capability_safe.false_alarm_upper"], (
        "a draft match earns no credit, and an unresolved draft control assessment counts as false in F+")
    assert requirement(unapproved, "evidence.scope")["status"] == "inconclusive"
    assert requirement(unapproved, "evidence.scope")["explanation"].startswith(
        "the baseline evidence is draft, not reviewed")
    development = gate.evaluate_gate({**policy, "required_scope": "draft"}, draft)
    assert development["recommendation_scope"] == "development"
    earned = requirement(development, "primary.improvement")["observed"]["candidate"]
    assert earned == 0.0, "a draft match earns no credit"

    for name in ("silent", "finder"):
        approve_like_a_reviewer(second / "invocations" / f"snap-a__{name}__r1", capsys)
    approved = aggregate.compare([second], baseline="silent", candidate="finder", policy=settings)
    assert approved["views"][0]["evidence_scope"] == {"baseline": "reviewed", "candidate": "reviewed"}
    frame = precision.build_frame([second], population="full", systems=["finder"])
    sample = precision.draw_sample(frame, size=1, seed=5)
    estimate = precision.estimate(sample, review_units(sample, lambda unit_id: "true"))
    assert estimate["precision_resolved"] == 1.0 and estimate["evidence_grade"] == "double_review_or_adjudicated"
    reviewed_policy = {**policy, "precision": precision_block(population={"name": "full"}, min_value=0.5)}

    decision = gate.evaluate_gate(reviewed_policy, approved, precision_candidate=estimate)

    assert decision["outcome"] == "pass" and decision["recommendation_scope"] == "reviewed", (
        decision["failed"], decision["unresolved"])
    assert requirement(decision, "primary.improvement")["observed"] == {
        "baseline": 0.0, "candidate": 1.0, "difference": 1.0}
    assert requirement(decision, "controls.capability_safe.false_alarm_upper")["observed"]["false_alarm_upper"] == 0.0
    assert requirement(decision, "precision.binding")["status"] == "pass"
    replay = gate.evaluate_gate(reviewed_policy, approved, precision_candidate=estimate)
    assert canonical_json(replay) == canonical_json(decision)


def test_the_real_runner_scenarios_fail_where_the_fixtures_do(tmp_path, capsys):
    """Four scripted systems, all approved by a fictional reviewer, each compared with the silent baseline.

    The finder detects the labeled target with one true claim and passes. The flagger detects it too, among 12
    claims of which 1 is true and one is a false allegation about the control, so its recall (+1) cannot save
    it: the control bound, precision (1/12), and burden fail. The broken system fails every scan: it detects
    nothing and completes nothing, and it delivered no claim, so no precision estimate can exist.
    """
    second = real_runs(tmp_path)["second"]
    for name, false_claims in (("silent", ()), ("finder", ()), ("flagger", ("c2",)), ("broken", ())):
        approve_like_a_reviewer(second / "invocations" / f"snap-a__{name}__r1", capsys, false_claims)
    policy = gate_policy(
        configuration={"allowed_differences": ["config"]}, primary=primary(minimum=0.5),
        precision=precision_block(population={"name": "full"}), controls={"capability_safe": bounds()},
        completion={"min": 1.0}, burden={"max_claims_per_assignment": 5, "max_duplicate_share": 0.0})

    def decide_real(name: str) -> dict:
        comparison = aggregate.compare([second], baseline="silent", candidate=name,
                                       policy=aggregation_policy(min_clusters=2))
        frame = precision.build_frame([second], population="full", systems=[name])
        estimate = None
        if frame["units"]:
            sample = precision.draw_sample(frame, size=len(frame["units"]), seed=5)
            estimate = precision.estimate(
                sample, review_units(sample, lambda unit_id: "true" if unit_id.endswith("/c1") else "false"))
        return gate.evaluate_gate(policy, comparison, precision_candidate=estimate)

    finder, flagger, broken = decide_real("finder"), decide_real("flagger"), decide_real("broken")

    assert finder["outcome"] == "pass" and finder["recommendation_scope"] == "reviewed", (
        finder["failed"], finder["unresolved"])
    assert requirement(flagger, "primary.improvement")["observed"]["difference"] == 1.0
    assert flagger["outcome"] == "fail"
    assert flagger["failed"] == ["precision.min_value", "controls.capability_safe.false_alarm_upper",
                                 "burden.claims_per_assignment"]
    assert requirement(flagger, "precision.min_value")["observed"]["value"] == pytest.approx(1 / 12)
    assert broken["outcome"] == "fail" and broken["failed"] == ["primary.improvement", "completion.min"]
    assert requirement(broken, "precision.binding")["status"] == "inconclusive"
    assert statuses(broken)["controls.capability_safe.false_alarm_upper"] == "inconclusive"
    assert requirement(broken, "completion.min")["explanation"] == (
        "the candidate completed 0 of the assigned work (error 1 scan(s) by status), below the required 1")


def test_a_policy_reads_only_its_own_view_and_the_decision_says_which_others_it_left_alone(corpus):
    """Views are never pooled: the standard and metadata-blinded views of one comparison are read separately."""
    comparison = deepcopy(corpus["comparisons"]["improved"])
    blinded = deepcopy(comparison["views"][0])
    blinded["profile"] = "metadata_blinded"
    for block in blinded["systems"]["candidate"]["slices"][0]["detection"]:
        if block["weighting"] == "equal_target":
            block["full_output_recall"]["value"] = 0.5
    for block in blinded["differences"][0]["detection"]:
        if block["weighting"] == "equal_target":
            block["full_output_recall"]["value"] = 0.3
    comparison["views"].append(blinded)

    standard = gate.evaluate_gate(gate_policy(), comparison)
    other = gate.evaluate_gate(gate_policy(view={"mode": "full", "profile": "metadata_blinded"}), comparison)

    assert requirement(standard, "primary.improvement")["observed"]["difference"] == 0.6
    assert requirement(other, "primary.improvement")["observed"]["difference"] == 0.3
    assert ("The comparison also holds view(s) full/metadata_blinded; this policy reads only full/standard."
            in standard["notes"])
    assert ("The comparison also holds view(s) full/standard; this policy reads only full/metadata_blinded."
            in other["notes"])
    assert other["view"] == {"mode": "full", "profile": "metadata_blinded"}


# --- thresholds are met at equality, and derived figures are exact -----------------------------------

NEAR = 1e-9


@pytest.mark.parametrize("system, requirement_id, build, value, past", [
    ("improved", "primary.improvement", lambda x: {"primary": primary(minimum=x)}, 0.6, "above"),
    ("improved", "burden.claims_per_assignment", lambda x: {"burden": {"max_claims_per_assignment": x}}, 1.0, "below"),
    ("improved", "burden.increase_ratio", lambda x: {"burden": {"max_increase_ratio": x}}, 1.0, "below"),
    ("duplicating", "burden.duplicate_share", lambda x: {"burden": {"max_duplicate_share": x}}, 0.95, "below"),
    ("improved", "cost.per_assignment", lambda x: {"cost": {"max_per_assignment_usd": x}}, 0.15, "below"),
    ("improved", "cost.increase_ratio", lambda x: {"cost": {"max_increase_ratio": x}}, 1.5, "below"),
    ("flaky", "completion.min", lambda x: {"completion": {"min": x}}, 0.8, "above"),
    ("flaky", "completion.max_decrease", lambda x: {"completion": {"max_decrease": x}}, 0.2, "below"),
    ("flaky", "target_coverage.min_assessable_mass", lambda x: {"target_coverage": {"min_assessable_mass": x}}, 0.8,
     "above"),
    ("late", "regression.guard", lambda x: {"regressions": [regression("guard", kind="recall_at_budget", budget=1,
                                                                        limit=x)]}, 0.2, "below"),
])
def test_a_figure_equal_to_its_threshold_meets_it_and_a_step_past_does_not(corpus, system, requirement_id, build,
                                                                           value, past):
    """Every requirement is met when its figure equals the tolerance and is not met one step past it.

    The late system's recall@1 fell by exactly 0.2, the flaky system's completion fell by exactly 0.2 to 0.8, the
    improved system's claims per assignment and claim ratio are exactly 1, its recall rose by exactly 0.6, its
    cost is 0.15 against 0.1, and the duplicating system's duplicate share is 190/200.
    """

    def status(threshold: float) -> str:
        decision = decide(corpus, gate_policy(**build(threshold)), system)
        return requirement(decision, requirement_id)["status"]

    stepped = value + NEAR if past == "above" else value - NEAR
    assert status(value) == "pass", f"{requirement_id} at its threshold {value}"
    assert status(stepped) != "pass", f"{requirement_id} one step past its threshold {stepped}"


def test_precision_and_control_figures_are_met_at_equality_and_not_one_step_past(corpus, estimates, tmp_path):
    """Resolved precision 0.8, F+ 0.4, and the assessable control mass 0.6 each sit exactly on their tolerance."""
    def precision_status(**changes) -> str:
        decision = decide(corpus, gate_policy(precision=precision_block(**changes)),
                          precision_candidate=estimates["improved"])
        return requirement(decision, "precision.min_value")["status"]

    assert precision_status(min_value=0.8) == "pass" and precision_status(min_value=0.8 + NEAR) == "fail"
    comparison = control_comparison(tmp_path, "run-edge", candidate_controls={1: "unresolved", 2: "unresolved"})

    def control_statuses(**changes) -> dict[str, str]:
        decision = gate.evaluate_gate(gate_policy(controls={"capability_safe": bounds(**changes)}), comparison)
        return statuses(decision)

    assert control_statuses(max_false_alarm_upper=0.4)["controls.capability_safe.false_alarm_upper"] == "pass"
    assert control_statuses(max_false_alarm_upper=0.4 - NEAR)["controls.capability_safe.false_alarm_upper"] == "fail"
    assert control_statuses(min_assessable_mass=0.6)["controls.capability_safe.assessable_mass"] == "pass"
    assert control_statuses(min_assessable_mass=0.6 + NEAR)[
        "controls.capability_safe.assessable_mass"] == "inconclusive"

    def estimate_status(requirement_id: str, estimate: dict, **changes) -> str:
        decision = decide(corpus, gate_policy(precision=precision_block(**changes)), precision_candidate=estimate)
        return requirement(decision, requirement_id)["status"]

    partial = partially_reviewed(corpus)
    for share, expected in ((0.4, "pass"), (0.4 - NEAR, "inconclusive")):
        assert estimate_status("precision.max_unresolved_share", partial, max_unresolved_share=share) == expected
    half = estimate_for(corpus["run"], "improved", size=5, stratify_by="input")
    for share, expected in ((0.5, "pass"), (0.5 + NEAR, "inconclusive")):
        assert estimate_status("precision.min_coverage", half, min_coverage=share) == expected
    for bound, expected in ((0.8, "pass"), (0.8 + NEAR, "fail")):
        assert estimate_status("precision.interval", estimates["improved"],
                               min_interval_lower_bound=bound) == expected


def test_a_figure_the_gate_derives_is_exact_so_binary_floats_never_move_it_across_its_threshold(corpus, estimates):
    """0.9 - 0.7 is 0.20000000000000007 as floats and 0.07 / 0.05 is 1.4000000000000001; on paper both are exact.

    A precision that fell from 0.9 to 0.7 fell by exactly 0.2, and a cost of 0.07 against 0.05 is exactly 1.4
    times it, so each meets a tolerance of exactly that and fails one step short of it.
    """
    assert 0.9 - 0.7 > 0.2 and 0.07 / 0.05 > 1.4, "the float arithmetic this guards against"
    baseline, candidate = deepcopy(estimates["baseline"]), deepcopy(estimates["improved"])
    baseline["precision_resolved"], candidate["precision_resolved"] = 0.9, 0.7

    def decrease(limit: float) -> str:
        decision = decide(corpus, gate_policy(precision=precision_block(max_decrease_vs_baseline=limit)),
                          precision_baseline=baseline, precision_candidate=candidate)
        return requirement(decision, "precision.max_decrease")["status"]

    assert decrease(0.2) == "pass" and decrease(0.2 - NEAR) == "fail"
    assert requirement(decide(corpus, gate_policy(precision=precision_block(max_decrease_vs_baseline=0.2)),
                              precision_baseline=baseline, precision_candidate=candidate),
                       "precision.max_decrease")["observed"] == {"baseline": 0.9, "candidate": 0.7, "decrease": 0.2}

    comparison = deepcopy(corpus["comparisons"]["improved"])
    for side, spent in (("baseline", 0.05), ("candidate", 0.07)):
        comparison["views"][0]["systems"][side]["slices"][0]["usage"]["cost_usd"] = {
            "known_sum": spent, "known": 1, "unknown": 0, "coverage": 1.0}

    def ratio(limit: float) -> str:
        decision = gate.evaluate_gate(gate_policy(cost={"max_increase_ratio": limit}), comparison)
        return requirement(decision, "cost.increase_ratio")["status"]

    assert ratio(1.4) == "pass" and ratio(1.4 - NEAR) == "fail"
    item = requirement(gate.evaluate_gate(gate_policy(cost={"max_increase_ratio": 1.4}), comparison),
                       "cost.increase_ratio")
    assert item["observed"] == {"baseline": 0.05, "candidate": 0.07, "ratio": 1.4}
    assert item["explanation"] == ("the candidate's recorded cost per executed scan is 0.07 against the baseline's "
                                   "0.05, a ratio of 1.4, within the allowed 1.4")


# --- a view that spans workloads --------------------------------------------------------------------


def two_workload_comparison(root: Path, run_id: str, **uncertainty) -> dict:
    """Four projects across two workloads; the baseline detects one target per workload, the candidate all four.

    Each input carries one target and one capability-safe control, and every scan is quiet on its control.
    """
    workloads = {1: "conventional_application", 2: "conventional_application", 3: "agentic_application",
                 4: "agentic_application"}
    inputs = [planned(f"p{index}", project=f"acme/p{index}", workload=workloads[index],
                      targets=[target(f"T-p{index}", project=f"acme/p{index}", family=f"family-{index}",
                                      workload=workloads[index])],
                      controls=[control(f"C-p{index}")])
              for index in range(1, 5)]
    outcomes = {}
    for index in range(1, 5):
        outcomes[(f"p{index}", "baseline", 1)] = scan(hits={f"T-p{index}": 1} if index in (1, 3) else {}, claims=1)
        outcomes[(f"p{index}", "candidate", 1)] = scan(hits={f"T-p{index}": 1}, claims=1)
    run = write_run(root, run_id, inputs, systems=("baseline", "candidate"), outcomes=outcomes,
                    configs={"candidate": {"config": {"knob": 2}}})
    settings = aggregation_policy(min_clusters=2)
    settings.update(uncertainty)
    return aggregate.compare([run], baseline="baseline", candidate="candidate", policy=settings)


def test_a_view_spanning_workloads_without_declared_weights_is_inconclusive_but_a_workload_slice_can_be_gated(tmp_path):
    """No summary crosses workloads without predeclared weights, so the whole view reports none.

    Recall is 2/4 to 4/4 in the pooled view the aggregation could not weight, but each workload has its own
    numbers: conventional 1/2 to 2/2 and agentic 1/2 to 2/2, +0.5 each. A policy on a workload slice is decided;
    one on the whole view, or on its controls, is unresolved with the reason the comparison gave.
    """
    comparison = two_workload_comparison(tmp_path, "run-workloads")
    whole = gate.evaluate_gate(gate_policy(controls={"capability_safe": bounds()}), comparison)

    assert whole["outcome"] == "inconclusive" and whole["failed"] == []
    reason = ("this slice spans 2 workloads (agentic_application, conventional_application) and the policy declares "
              "no workload weights; no summary crosses workloads without them")
    assert requirement(whole, "primary.improvement")["explanation"] == (
        f"equal_target detection is unavailable for the whole view of full/standard: {reason}")
    for check in ("false_alarm_upper", "completed_mass", "assessable_mass"):
        assert requirement(whole, f"controls.capability_safe.{check}")["explanation"] == (
            f"the capability_safe controls are unavailable: {reason}")

    sliced = gate.evaluate_gate(gate_policy(primary=primary(
        slice={"dimension": "workload", "value": "agentic_application"}, minimum=0.5)), comparison)
    assert requirement(sliced, "primary.improvement")["observed"] == {
        "baseline": 0.5, "candidate": 1.0, "difference": 0.5}
    assert sliced["outcome"] == "pass"

    weighted = two_workload_comparison(tmp_path, "run-weighted", workload_weights={
        "conventional_application": 0.5, "agentic_application": 0.5})
    declared = gate.evaluate_gate(gate_policy(controls={"capability_safe": bounds()}), weighted)
    assert declared["outcome"] == "pass", "declared workload weights let the whole view be summarized"
