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
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from scaneval import aggregate, gate, precision, review, schedule
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
         resolved: bool = True, controls=None, usage=None, review_state: str = "approved",
         duplicate: bool = False, scope: str | None = None) -> dict:
    """What one bundle holds.

    ``hits`` maps a target id to the 1-based position of the claim a reviewer accepted for it;
    ``controls`` maps a control id to ``"quiet"``, ``"unresolved"``, or ``("false_allegation",
    position)``. ``duplicate`` makes every delivered claim an exact copy of the first, which is how a
    system spams the reviewer without adding an allegation.
    """
    return {"hits": hits or {}, "claims": claims, "ranking": ranking, "status": status, "resolved": resolved,
            "controls": controls or {}, "usage": usage if usage is not None else {"wall_seconds": 1.0},
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
    positions = list(spec["hits"].values())
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
           "unranked")
CANDIDATES = tuple(name for name in SYSTEMS if name != "baseline")


def corpus_inputs() -> list[dict]:
    """Ten projects, one input, one target, and one capability-safe control each; every target in its own family."""
    return [planned(f"p{index}", project=f"acme/p{index}",
                    targets=[target(f"T-p{index}", project=f"acme/p{index}", family=f"family-{index}")],
                    controls=[control(f"C-p{index}")])
            for index in range(1, PROJECTS + 1)]


def behave(system: str, index: int) -> dict:
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
    """A policy over the corpus: the improvement the change is meant to make and the one configuration key it changes."""
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


def test_recall_at_a_budget_is_inconclusive_for_unranked_output_and_a_random_order_expectation_never_replaces_it(corpus):
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
    status, explanation = verdict(None, None, "degenerate")
    assert status == "inconclusive" and "the paired interval is degenerate" in explanation
    assert requirement(decide(corpus, policy), "regression.guard")["status"] == "pass", "the real interval sits above -0.05"


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
    policy = gate_policy(regressions=[regression("whole-view")], primary=primary(uncertainty={"lower_bound_above": 0.0}))
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
def test_a_policy_whose_primary_metric_is_a_diagnostic_is_refused_when_loaded_and_when_evaluated(corpus, tmp_path, kind):
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
