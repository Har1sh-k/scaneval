from __future__ import annotations

import copy
import json

import pytest

from sastbench.contracts import (
    ContractError,
    canonical_json,
    canonical_sha256,
    load_document,
    validate_document,
)


HASH = "sha256:" + "a" * 64


def scan_request() -> dict:
    return {
        "schema_version": "2.0",
        "run_id": "run-1",
        "input": {
            "tree_hash": HASH,
            "root": ".",
            "languages": ["python"],
            "mode": "full",
            "profile": "standard",
        },
        "system": {"id": "scanner"},
        "limits": {"timeout_seconds": 60, "max_turns": 2},
        "trace_mode": "off",
    }


def scan_result() -> dict:
    return {
        "schema_version": "2.0",
        "run_id": "run-1",
        "system_id": "scanner",
        "input_hash": HASH,
        "status": "success",
        "ranking": "native",
        "claims": [
            {
                "claim_id": "claim-1",
                "allegation": "Untrusted input reaches a shell.",
                "kind": "command_injection",
                "primary_location": {"path": "src/run.py"},
                "rank": 1,
            },
            {
                "claim_id": "claim-2",
                "allegation": "A second issue.",
                "kind": "path_traversal",
                "primary_location": {
                    "path": "src/files.py",
                    "start_line": 7,
                    "end_line": 9,
                },
                "rank": 2,
            },
        ],
        "bundles_resolved": True,
        "usage": {"wall_seconds": 1.5, "cost_usd": None},
    }


def evaluation_plan(scope: str = "reviewed") -> dict:
    level = "L3" if scope == "reviewed" else "fixture"
    return {
        "schema_version": "2.0",
        "input_hash": HASH,
        "scope": scope,
        "targets": [
            {
                "target_id": "target-1",
                "description": "A reviewed root cause",
                "validation_level": level,
            }
        ],
        "controls": [
            {
                "control_id": "control-1",
                "description": "A reviewed safe operation",
                "type": "capability_safe",
                "validation_level": level,
            }
        ],
        "review_budgets": [5, 10],
    }


def review_decisions() -> dict:
    return {
        "schema_version": "2.0",
        "run_id": "run-1",
        "input_hash": HASH,
        "result_sha256": HASH,
        "claim_matches": [
            {
                "claim_id": "claim-1",
                "target_id": "target-1",
                "decision": "accepted",
                "reason": "The allegation identifies the reviewed root cause.",
            }
        ],
        "control_assessments": [
            {
                "control_id": "control-1",
                "decision": "quiet",
                "claim_ids": [],
                "reason": "No claim alleged the ruled-out issue.",
            }
        ],
    }


@pytest.mark.parametrize(
    ("kind", "factory"),
    [
        ("scan-request", scan_request),
        ("scan-result", scan_result),
        ("evaluation-plan", evaluation_plan),
        ("review-decisions", review_decisions),
    ],
)
def test_valid_documents_return_same_object(kind, factory):
    document = factory()
    assert validate_document(kind, document) is document


@pytest.mark.parametrize(
    ("kind", "factory"),
    [
        ("scan-request", scan_request),
        ("scan-result", scan_result),
        ("evaluation-plan", evaluation_plan),
        ("review-decisions", review_decisions),
    ],
)
def test_versions_are_strict(kind, factory):
    document = factory()
    document["schema_version"] = "2"
    with pytest.raises(ContractError):
        validate_document(kind, document)


@pytest.mark.parametrize(
    "path",
    ["../secret", "src/../../secret", "/etc/passwd", r"C:\secret", r"\\server\share"],
)
def test_paths_reject_traversal_and_absolute_aliases(path):
    document = scan_result()
    document["claims"][0]["primary_location"]["path"] = path
    with pytest.raises(ContractError):
        validate_document("scan-result", document)


def test_windows_relative_paths_and_file_only_locations_are_allowed():
    document = scan_result()
    document["claims"][0]["primary_location"] = {"path": r"src\run.py"}
    assert validate_document("scan-result", document) is document


def test_line_bounds_are_paired_and_inclusive():
    document = scan_result()
    document["claims"][0]["primary_location"]["start_line"] = 3
    with pytest.raises(ContractError):
        validate_document("scan-result", document)
    document["claims"][0]["primary_location"]["end_line"] = 2
    with pytest.raises(ContractError):
        validate_document("scan-result", document)
    document["claims"][0]["primary_location"]["end_line"] = 3
    validate_document("scan-result", document)


@pytest.mark.parametrize("nested", [False, True])
def test_unknown_fields_are_rejected_at_every_level(nested):
    document = scan_request()
    target = document["input"] if nested else document
    target["evaluator_target"] = "secret"
    with pytest.raises(ContractError):
        validate_document("scan-request", document)


def test_pr_payload_is_present_exactly_for_pr_mode():
    document = scan_request()
    document["input"]["pr"] = {"base": "main", "head": "feature"}
    with pytest.raises(ContractError):
        validate_document("scan-request", document)
    document["input"]["mode"] = "pr"
    validate_document("scan-request", document)
    del document["input"]["pr"]
    with pytest.raises(ContractError):
        validate_document("scan-request", document)


def test_claim_ids_and_native_ranks_are_strict():
    document = scan_result()
    document["claims"][1]["claim_id"] = "claim-1"
    with pytest.raises(ContractError):
        validate_document("scan-result", document)
    document = scan_result()
    document["claims"][1]["rank"] = 3
    with pytest.raises(ContractError):
        validate_document("scan-result", document)
    document["ranking"] = "unranked"
    for claim in document["claims"]:
        claim.pop("rank")
    validate_document("scan-result", document)
    document["claims"][0]["rank"] = 1
    with pytest.raises(ContractError):
        validate_document("scan-result", document)


@pytest.mark.parametrize("field", ["timeout_seconds", "max_turns"])
def test_booleans_are_not_numbers(field):
    document = scan_request()
    document["limits"][field] = True
    with pytest.raises(ContractError):
        validate_document("scan-request", document)


def test_review_budget_rejects_bool_zero_and_duplicates():
    for budgets in ([True], [0], [5, 5]):
        document = evaluation_plan()
        document["review_budgets"] = budgets
        with pytest.raises(ContractError):
            validate_document("evaluation-plan", document)


def test_validation_levels_follow_plan_scope():
    reviewed = evaluation_plan()
    reviewed["targets"][0]["validation_level"] = "L2"
    with pytest.raises(ContractError):
        validate_document("evaluation-plan", reviewed)
    diagnostic = evaluation_plan("diagnostic")
    diagnostic["controls"][0]["validation_level"] = "L4"
    with pytest.raises(ContractError):
        validate_document("evaluation-plan", diagnostic)


def test_decision_uniqueness_and_control_reference_rules():
    document = review_decisions()
    document["claim_matches"].append(copy.deepcopy(document["claim_matches"][0]))
    with pytest.raises(ContractError):
        validate_document("review-decisions", document)
    document = review_decisions()
    document["control_assessments"][0].update(
        {"decision": "false_allegation", "claim_ids": []}
    )
    with pytest.raises(ContractError):
        validate_document("review-decisions", document)
    document["control_assessments"][0].update(
        {"decision": "quiet", "claim_ids": ["claim-1"]}
    )
    with pytest.raises(ContractError):
        validate_document("review-decisions", document)


def test_canonical_json_and_hash_are_deterministic_unicode():
    left = {"z": "café", "a": [2, 1]}
    right = {"a": [2, 1], "z": "café"}
    assert canonical_json(left) == '{"a":[2,1],"z":"café"}'
    assert canonical_sha256(left) == canonical_sha256(right)
    assert canonical_sha256(left).startswith("sha256:")
    with pytest.raises(ContractError):
        canonical_json({"bad": float("nan")})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_in_memory_documents_reject_nonfinite_numbers(value):
    document = scan_result()
    document["usage"]["wall_seconds"] = value
    with pytest.raises(ContractError, match="non-finite"):
        validate_document("scan-result", document)


def test_canonical_serialization_wraps_non_json_values():
    with pytest.raises(ContractError, match="not canonical JSON"):
        canonical_json({"not-json": object()})
    with pytest.raises(ContractError, match="canonical UTF-8 JSON"):
        canonical_sha256({"bad-unicode": "\ud800"})


def test_nul_is_rejected_in_relative_paths():
    document = scan_result()
    document["claims"][0]["primary_location"]["path"] = "src/run.py\x00ignored"
    with pytest.raises(ContractError):
        validate_document("scan-result", document)


def test_load_document_validates_without_adding_defaults(tmp_path):
    path = tmp_path / "request.json"
    document = scan_request()
    path.write_text(json.dumps(document), encoding="utf-8")
    assert load_document(path, "scan-request") == document
    assert "pr" not in document["input"]


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_load_document_rejects_nonstandard_numeric_constants(tmp_path, constant):
    path = tmp_path / "request.json"
    payload = json.dumps(scan_request()).replace("60", constant, 1)
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ContractError, match="non-finite"):
        load_document(path, "scan-request")


def test_load_document_rejects_duplicate_object_keys(tmp_path):
    path = tmp_path / "request.json"
    payload = json.dumps(scan_request())
    payload = payload.replace('"run_id": "run-1"', '"run_id": "first", "run_id": "run-1"')
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ContractError, match="duplicate JSON object key"):
        load_document(path, "scan-request")


def test_unknown_contract_kind_is_a_contract_error():
    with pytest.raises(ContractError):
        validate_document("labels", {})
