from copy import deepcopy

import pytest

from scaneval import experiment
from scaneval.contracts import ContractError


IMAGE = "scanner@sha256:" + "a" * 64
OPEN_POLICY = {"history": "ancestor_history_v1", "retrieval": "recorded_public_v1", "web_mode": "live",
               "capture": "content", "retention": "bundle"}


def declaration():
    contexts = {"scan": {"network_policy": "public_research", "execution": {"proxy_image": IMAGE,
        "egress": [{"host": "example.com", "port": 443}], "retrieval": {"policy": "recorded_public_v1",
        "allowed_origins": ["https://example.com"], "capture": "content", "retention": "bundle"}}}}
    return {"schema_version": "2.1", "stage": "declared", "experiment_id": "fixture", "experiment_version": "1",
        "pack": "pack.json", "population": {"snapshot_ids": ["source"], "canonical_target_ids": ["target"],
        "canonical_control_ids": [], "source_property": "caller-controlled shell invocation"},
        "systems": [{"system_id": "scan", "adapter": "semgrep", "config": {}, "inference": "offline",
                     "execution": {"backend": "oci", "image": IMAGE}}],
        "conditions": [
            {"name": "open_context", "profile": "standard", "history": "bounded_ancestor", "retrieval": "recorded_public",
             "identity": "preserved", "policy": deepcopy(OPEN_POLICY), "system_context": contexts},
            {"name": "closed_book_standard", "profile": "standard", "history": "none", "retrieval": "disabled",
             "identity": "preserved", "policy": {}, "system_context": {"scan": {"network_policy": "none"}}},
            {"name": "identity_reduced", "profile": "identity_reduced", "history": "none", "retrieval": "disabled",
             "identity": "reduced", "policy": {}, "system_context": {"scan": {"network_policy": "none"}},
             "transformation_maps": {"source": "map.json"}}],
        "repetitions": 2, "timeout_seconds": 60, "trace_mode": "metadata",
        "run_order": {"method": "seeded_cell_order", "seed": 0},
        "required_capture": {"open_context": ["external_isolation", "history", "retrieval_events"],
            "closed_book_standard": ["external_isolation", "history", "tool_controls"],
            "identity_reduced": ["external_isolation", "history", "tool_controls", "identity_manifest"]},
        "allowed_differences": sorted(experiment.CONTEXT_DIFFERENCES), "exclusions": [], "missingness": "report_unavailable",
        "adjudication": {"policy_id": "same-structured-review", "version": "1", "matching": "exact_structured_v2"},
        "aggregation_policy": deepcopy(experiment.AGGREGATION_POLICY), "uncertainty": {"method": "none"}}


def test_three_condition_declaration_has_one_common_system_and_reproducible_order():
    value = declaration()
    assert experiment.validate_matrix(value) is value
    assert experiment._cell_order(value) == experiment._cell_order(deepcopy(value))
    assert set(experiment._cell_order(value)) == set(experiment.NAMES)


@pytest.mark.parametrize("field,value", [("profile", "identity_reduced"), ("history", "none"),
                                          ("retrieval", "disabled"), ("identity", "reduced")])
def test_named_open_condition_cannot_change_its_context_definition(field, value):
    matrix = declaration()
    matrix["conditions"][0][field] = value
    with pytest.raises(ContractError, match="incompatible"):
        experiment.validate_matrix(matrix)


@pytest.mark.parametrize("mutation,reason", [
    ("stale", "stale"), ("capture", "capture policies differ"), ("scope", "experiment matrix"),
    ("system", "exactly the common systems"), ("weights", "equal-canonical-target"),
    ("views", "equal-canonical-target"), ("reasoning", "experiment matrix"),
    ("remote", "model_id and model_revision"), ("local", "external OCI"),
    ("map", "every snapshot"), ("capability", "required capture"), ("inference", "network route"),
])
def test_pairing_drift_or_incompatible_condition_settings_are_refused(mutation, reason):
    matrix = declaration()
    opened, closed, reduced = matrix["conditions"]
    if mutation == "stale": opened["policy"] = {**OPEN_POLICY, "history": "old"}
    elif mutation == "capture": opened["system_context"]["scan"]["execution"]["retrieval"]["capture"] = "hashes"
    elif mutation == "scope": closed["system_context"]["scan"]["config"] = {"paths": ["different"]}
    elif mutation == "system": del closed["system_context"]["scan"]
    elif mutation == "weights": matrix["aggregation_policy"]["target_weights"] = {"target": 1}
    elif mutation == "views": matrix["aggregation_policy"]["views"] = ["equal_project"]
    elif mutation == "reasoning": closed["system_context"]["scan"]["reasoning"] = "low"
    elif mutation == "remote": matrix["systems"][0]["inference"] = "remote"
    elif mutation == "local": matrix["systems"][0]["execution"] = {"backend": "local"}
    elif mutation == "map": reduced["transformation_maps"] = {}
    elif mutation == "capability": matrix["required_capture"]["identity_reduced"].remove("identity_manifest")
    else: closed["system_context"]["scan"]["network_policy"] = "model_provider_only"
    with pytest.raises(ContractError, match=reason):
        experiment.validate_matrix(matrix)


def test_seeded_run_order_rejects_unfrozen_seed_and_fixed_order_rejects_unused_seed():
    matrix = declaration()
    del matrix["run_order"]["seed"]
    with pytest.raises(ContractError, match="requires a frozen seed"):
        experiment.validate_matrix(matrix)


def test_identity_contrast_cannot_change_inference_endpoints_or_proxy_image():
    matrix = declaration()
    matrix["systems"][0].update(inference="remote", model_id="model", model_revision="model-revision")
    controls = {"scan": {"network_policy": "model_provider_only", "execution": {
        "proxy_image": IMAGE, "egress": [{"host": "api-a.example", "port": 443}]}}}
    matrix["conditions"][1]["system_context"] = deepcopy(controls)
    matrix["conditions"][2]["system_context"] = deepcopy(controls)
    experiment.validate_matrix(matrix)
    matrix["conditions"][2]["system_context"]["scan"]["execution"]["egress"][0]["host"] = "api-b.example"
    with pytest.raises(ContractError, match="identical inference/network/proxy"):
        experiment.validate_matrix(matrix)


@pytest.mark.parametrize("path", ["/absolute/map.json", "../outside.json", "C:\\outside.json"])
def test_unportable_pack_and_map_paths_are_refused(path):
    matrix = declaration()
    matrix["pack"] = path
    with pytest.raises(ContractError, match="relative path"):
        experiment.validate_matrix(matrix)
    matrix = declaration()
    matrix["conditions"][2]["transformation_maps"]["source"] = path
    with pytest.raises(ContractError, match="relative path"):
        experiment.validate_matrix(matrix)


def test_duplicate_exclusions_and_identity_cues_fail_before_scanning():
    matrix = declaration()
    matrix["exclusions"] = [{"snapshot_id": "excluded", "reason": "predeclared"}] * 2
    with pytest.raises(ContractError, match="duplicate predeclared"):
        experiment.validate_matrix(matrix)
    matrix = declaration()
    matrix["experiment_id"] = "AcmeCorp-study"
    frozen = {"declaration": matrix, "maps": {"map": {"pseudonyms": [{"original": "AcmeCorp", "replacement": "Neutral"}]}}}
    with pytest.raises(ContractError, match="retain reviewed original cues"):
        experiment.check_identity_cues(frozen)
    matrix["run_order"] = {"method": "fixed", "seed": 1}
    with pytest.raises(ContractError, match="does not use a random seed"):
        experiment.validate_matrix(matrix)
