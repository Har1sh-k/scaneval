from copy import deepcopy
import json

import pytest

from scaneval.contracts import ContractError
from scaneval.experiment_report import (check_adjudication_consistency, evidence_scope, label_contract,
                                       paired_effect, weighted_bounds, _runtime, _load_rows)
from scaneval.experiment_execution import load_execution, EXECUTION_FILE, _assignment_states
from test_v2_experiment_execution import frozen_shell


def saved_execution(matrix):
    states = ("failed", "interrupted", "not_started")
    cells = [{"condition": cell["name"], "run_path": "runs/" + cell["name"],
              "assignments": len(cell["assignments"]), "status": status,
              "error": {"type": "FixtureFailure", "message": "preflight refused"} if status == "failed" else None,
              "recorded_bindings": [], "assignment_states": _assignment_states(cell, "missing" if status != "not_started" else "not_started")}
             for cell, status in zip(matrix["cells"], states, strict=True)]
    return {"schema_version": "2.1", "experiment_id": matrix["experiment_id"],
            "experiment_version": matrix["experiment_version"], "matrix_sha256": matrix["matrix_sha256"],
            "assignments": len(matrix["assignments"]), "finished_at": "2000-01-01T00:00:00Z",
            "status": "interrupted", "interruption": {"type": "KeyboardInterrupt", "message": "fixture"}, "cells": cells}


def test_report_preserves_failed_interrupted_and_never_attempted_states(tmp_path):
    matrix = frozen_shell()
    matrix["declaration"] = {"evidence_scope": "diagnostic"}
    matrix["population"] = [{"snapshot_id": "source", "project": "fixture", "source_property": "fixture sink",
                             "plan": {"scope": "draft"}, "schedule_plan": {"targets": [], "controls": []}}]
    saved = saved_execution(matrix)
    (tmp_path / EXECUTION_FILE).write_text(json.dumps(saved))
    rows = _load_rows(matrix, tmp_path)
    assert len(rows) == 6
    assert [row["execution_state"] for row in rows[::2]] == ["failed", "interrupted", "not_started"]
    assert rows[0]["execution_error"]["message"] == "preflight refused"
    assert rows[-1]["assignment_execution_state"] == "not_started"
    assert all(row["status"] == "missing" and row["observed"] is None for row in rows)
    assert all(row["scope"] == "diagnostic" and row["corpus_scope"] == "draft" for row in rows)


def test_absent_execution_manifest_explicitly_leaves_state_unknown(tmp_path):
    value = load_execution(tmp_path, frozen_shell())
    assert value["state"] == "unavailable" and value["manifest"] is None


@pytest.mark.parametrize("mutation", ["matrix", "cell", "assignment", "count", "completion", "bindings"])
def test_execution_manifest_cannot_change_frozen_states_or_claim_completion(tmp_path, mutation):
    matrix = frozen_shell()
    value = saved_execution(matrix)
    if mutation == "matrix": value["matrix_sha256"] = "sha256:" + "0" * 64
    elif mutation == "cell": value["cells"].pop()
    elif mutation == "assignment": value["cells"][0]["assignment_states"][0]["assignment_id"] = "different"
    elif mutation == "count": value["assignments"] -= 1
    elif mutation == "completion": value["cells"][0]["status"] = "completed"
    else: value["cells"][0]["recorded_bindings"] = [{}]
    (tmp_path / EXECUTION_FILE).write_text(json.dumps(value))
    with pytest.raises(ContractError, match="execution"):
        load_execution(tmp_path, matrix)


def outcome(target, value, *, snapshot=None, repetition=1, resolved=True, eligible=True, runtime="same"):
    return {"canonical_id": target, "detected": value, "snapshot_id": snapshot or target,
            "system_id": "scan", "repetition": repetition, "project": "project-" + target,
            "resolved": resolved, "eligible": eligible, "runtime_sha256": runtime, "reasons": []}


def test_canonical_weighting_does_not_overweight_targets_with_more_inputs_or_repetitions():
    rows = [{"canonical_id": "A", "lower": value, "upper": value, "resolved": True} for value in (1, 1, 0)]
    rows.append({"canonical_id": "B", "lower": 0, "upper": 0, "resolved": True})
    assert weighted_bounds(rows)["value"] == 1 / 3


def test_known_contributions_tighten_missing_pair_bounds_without_discarding_it():
    left = [outcome("A", True), outcome("B", None, resolved=False)]
    right = [outcome("A", False), outcome("B", False)]
    result = paired_effect(left, right, uncertainty={"method": "none"}, label="fixture")
    assert result["planned_pairs"] == 2 and result["resolved_pairs"] == 1
    assert result["full_population_effect"]["value"] is None
    assert result["full_population_effect"]["lower_bound"] == 0.5
    assert result["full_population_effect"]["upper_bound"] == 1.0
    assert result["resolved_subset_effect"]["value"] == 1.0


def test_known_right_hand_hit_keeps_unknown_left_difference_nonpositive():
    result = paired_effect([outcome("A", None, resolved=False), outcome("B", True)],
        [outcome("A", True), outcome("B", True)], uncertainty={"method": "none"}, label="fixture")
    assert result["full_population_effect"]["lower_bound"] == -0.5
    assert result["full_population_effect"]["upper_bound"] == 0.0


def test_actual_runtime_drift_refuses_pair_comparability():
    result = paired_effect([outcome("A", True, runtime="scanner-1")], [outcome("A", False, runtime="scanner-2")],
                           uncertainty={"method": "none"}, label="fixture")
    assert result["comparable_pairs"] == 0 and result["full_population_effect"]["value"] is None
    assert result["pairs"][0]["reasons"] == ["actual_scanner_model_scope_or_budget_drift"]
    assert result["full_population_effect"]["lower_bound"] == -1.0
    assert result["full_population_effect"]["upper_bound"] == 1.0


def test_partial_accepted_hit_is_a_known_bound_but_not_complete_work():
    result = paired_effect([outcome("A", True, resolved=False)], [outcome("A", False)],
                           uncertainty={"method": "none"}, label="fixture")
    assert result["full_population_effect"]["value"] is None
    assert result["full_population_effect"]["lower_bound"] == result["full_population_effect"]["upper_bound"] == 1.0
    assert result["resolved_pairs"] == 0


def test_missing_repetition_or_duplicate_pairs_cannot_be_silently_intersected():
    left = [outcome("A", True), outcome("A", False, repetition=2)]
    with pytest.raises(ContractError, match="complete frozen"):
        paired_effect(left, left[:1], uncertainty={"method": "none"}, label="fixture")
    with pytest.raises(ContractError, match="duplicate"):
        paired_effect(left + left[:1], left, uncertainty={"method": "none"}, label="fixture")


def test_bootstrap_is_reproducible_only_for_complete_supported_cluster_population():
    policy = {"method": "paired_cluster_bootstrap", "cluster_by": "canonical_target", "seed": 7,
              "min_clusters": 2, "replicates": 20, "confidence": 0.9}
    left, right = [outcome("A", True), outcome("B", True)], [outcome("A", False), outcome("B", False)]
    result = paired_effect(left, right, uncertainty=policy, label="fixture")
    interval = result["confidence_interval"]
    assert interval["status"] == "available" and interval["lower"] == interval["upper"] == 1.0
    assert paired_effect(left, right, uncertainty=policy, label="fixture") == result
    left[0]["resolved"] = False
    assert paired_effect(left, right, uncertainty=policy, label="fixture")["confidence_interval"]["status"] == "unavailable"


def test_too_few_clusters_never_get_a_confidence_interval():
    policy = {"method": "paired_cluster_bootstrap", "seed": 0, "min_clusters": 2, "replicates": 20, "confidence": 0.95}
    result = paired_effect([outcome("A", True)], [outcome("A", False)], uncertainty=policy, label="fixture")
    assert result["confidence_interval"]["status"] == "unavailable"


def adjudication(decision, *, claim_id="claim"):
    return {"snapshot_id": "source", "target_canonical": {"target": "root"},
        "result": {"claims": [{"claim_id": claim_id, "kind": "command_injection", "allegation": "Same allegation",
                                "primary_location": {"path": "app.py", "start_line": 1, "end_line": 1}}]},
        "decisions": {"claim_matches": [{"claim_id": claim_id, "target_id": "target", "decision": decision}],
                      "control_assessments": []}}


def test_delivery_ids_do_not_hide_conflicting_cross_condition_review():
    with pytest.raises(ContractError, match="conflicting cross-condition"):
        check_adjudication_consistency([adjudication("accepted"), adjudication("rejected", claim_id="different-id")])
    check_adjudication_consistency([adjudication("accepted"), adjudication("unresolved", claim_id="different-id")])


def test_false_allegation_and_accepted_hit_cannot_contradict_between_cells():
    false = adjudication("unresolved", claim_id="other")
    false["decisions"]["control_assessments"] = [{"control_id": "control", "decision": "false_allegation", "claim_ids": ["other"]}]
    with pytest.raises(ContractError, match="both accepted and judged false"):
        check_adjudication_consistency([adjudication("accepted"), false])


def test_evidence_scope_is_independent_of_approved_finding_reviews():
    assert evidence_scope(["draft", "reviewed"]) == "draft"
    assert evidence_scope(["diagnostic", "diagnostic"]) == "diagnostic"
    left, right = outcome("A", True), outcome("A", False)
    left["scope"], right["scope"] = "diagnostic", "reviewed"
    with pytest.raises(ContractError, match="diagnostic fixtures cannot be pooled"):
        paired_effect([left], [right], uncertainty={"method": "none"}, label="fixture")


def test_refreshed_mechanical_timestamps_do_not_allow_label_or_review_drift():
    pack = {"anchor_sha256": "old", "snapshots": [{"snapshot_id": "source", "commit": "original"}],
        "cases": [{"target": {"description": "same security property"}, "validation": {
            "level": "L1", "review_state": "mechanically_checked", "reviews": [],
            "checks": [{"check": "exists", "at": "old", "result": "pass"}],
            "check_sets": {"source": {"tree_hash": "same", "result": "pass", "checks_sha256": "old"}}}}]}
    refreshed = deepcopy(pack)
    refreshed["anchor_sha256"] = "new"
    refreshed["cases"][0]["validation"]["checks"][0]["at"] = "new"
    refreshed["cases"][0]["validation"]["check_sets"]["source"]["checks_sha256"] = "new"
    assert label_contract(pack) == label_contract(refreshed)
    refreshed["cases"][0]["target"]["description"] = "different property"
    assert label_contract(pack) != label_contract(refreshed)
    refreshed = deepcopy(pack)
    refreshed["cases"][0]["validation"]["review_state"] = "human_approved"
    assert label_contract(pack) != label_contract(refreshed)


def test_reporting_and_execution_share_one_label_contract():
    from scaneval import experiment
    assert label_contract is experiment.label_contract


def test_requested_provider_namespace_is_not_a_model_drift_but_unverified_resolution_is_visible():
    image = "fixture@sha256:" + "a" * 64
    system = {"adapter_identity": {"name": "fixture", "version": "1"}, "config": {"model": "provider/model"},
        "execution": {"backend": "oci", "image": image}, "inference": "remote", "model_id": "friendly-model-label",
        "model_revision": "exact-served-snapshot"}
    execution = {"adapter": system["adapter_identity"], "system_config": system["config"], "timeout_seconds": 60,
        "tool_versions": {"scanner": "1"}, "model_identity": {"requested": "provider/model", "resolved": "exact-served-snapshot", "verification": "verified"},
        "isolation": {"image": {"reference": image}, "settings": {"user": "65534:65534", "memory_mb": 2048,
            "memory_swap_mb": 2048, "cpus": 2.0, "pids_limit": 256,
            "tmpfs": [{"target": "/tmp", "size_mb": 256}], "environment": {"credentials": []}}}}
    matrix = {"declaration": {"timeout_seconds": 60}}
    _binding, reasons = _runtime(execution, system, matrix, {"inference": "remote"})
    assert reasons == []
    execution["model_identity"]["verification"] = "self_reported"
    _binding, reasons = _runtime(execution, system, matrix, {"inference": "remote"})
    assert reasons == ["served_model_revision_unverified"]
