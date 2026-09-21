from __future__ import annotations

import copy
import json
import sys

import pytest

from scaneval.contracts import (
    ContractError,
    canonical_json,
    canonical_sha256,
    covering_review,
    is_stated,
    label_digest,
    level_gap,
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


def run_manifest(status: str = "completed") -> dict:
    """One completed run of one input by one system. A failed manifest adds its failure."""
    manifest = {
        "schema_version": "2.0",
        "run_id": "run-1",
        "status": status,
        "created_at": "2026-09-20T15:00:00+00:00",
        "config_sha256": HASH,
        "pack": {
            "namespace": "test", "pack_id": "pilot", "version": "0.1.0-draft", "status": "draft",
            "snapshots": 1, "cases": 1,
            "review_states": {"draft": 0, "mechanically_checked": 1, "human_approved": 0},
            "dispositions": {"validate": 0, "needs_evidence": 1, "extended_regression": 0, "exclude": 0},
            "sha256": HASH,
        },
        "selection": {"only_inputs": None, "only_systems": None,
                      "excluded_inputs": [], "excluded_systems": []},
        "inputs": [
            {
                "snapshot_id": "snap-a", "tree_hash": HASH,
                "provenance_path": "inputs/snap-a/provenance.json",
                "mechanical_checks": [
                    {
                        "case_id": "case-a", "passed": True, "review_state": "mechanically_checked",
                        "level": "L1",
                        "checks": [{"check": "snapshot_hash_recorded", "result": "pass",
                                    "at": "2026-09-20T15:00:00+00:00", "detail": HASH,
                                    "snapshot_id": "snap-a"}],
                    }
                ],
            }
        ],
        "systems": [{"system_id": "fake-a", "adapter": "fake", "adapter_version": "1.0.0",
                     "preparation": {"ruleset": "none"}, "skipped_reason": None}],
        "invocations": [
            {
                "invocation_id": "snap-a__fake-a__r1", "input_id": "snap-a", "system_id": "fake-a",
                "repetition": 1, "status": "success", "claim_records": 1, "plan_scope": "draft",
                "targets_assigned": 1, "targets_detected": 0, "pending_matching_count": 1,
                "bundle_path": "invocations/snap-a__fake-a__r1", "review_state": "draft",
                "skipped_reason": None,
            }
        ],
        "warnings": [],
    }
    if status == "failed":
        manifest["failure"] = {"type": "RuntimeError", "message": "the adapter crashed"}
    return manifest


def skipped_invocation() -> dict:
    return {"invocation_id": "snap-a__broken-b__r1", "input_id": "snap-a", "system_id": "broken-b",
            "repetition": 1, "status": "skipped", "claim_records": None, "plan_scope": None,
            "targets_assigned": None, "targets_detected": None, "pending_matching_count": None,
            "bundle_path": None, "review_state": None, "skipped_reason": "ruleset checkout is missing"}


@pytest.mark.parametrize(
    ("kind", "factory"),
    [
        ("scan-request", scan_request),
        ("scan-result", scan_result),
        ("evaluation-plan", evaluation_plan),
        ("review-decisions", review_decisions),
        ("run-manifest", run_manifest),
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
        ("run-manifest", run_manifest),
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


@pytest.mark.parametrize("level", ["L1", "L2", "L3", "L4"])
def test_a_draft_plan_keeps_every_real_validation_level(level):
    """Scope carries draft status, so a draft plan may report a reviewed item at its own level."""
    draft = evaluation_plan("draft")
    draft["targets"][0]["validation_level"] = level
    draft["controls"][0]["validation_level"] = level
    assert validate_document("evaluation-plan", draft) is draft
    draft["controls"][0]["validation_level"] = "fixture"
    with pytest.raises(ContractError, match="draft plans may only use L1, L2, L3, or L4"):
        validate_document("evaluation-plan", draft)


def test_run_manifest_failure_and_skip_records_must_agree_with_the_status():
    completed = run_manifest()
    completed["failure"] = {"type": "RuntimeError", "message": "x"}
    with pytest.raises(ContractError, match="only a failed run manifest"):
        validate_document("run-manifest", completed)
    failed = run_manifest("failed")
    del failed["failure"]
    with pytest.raises(ContractError, match="must record its failure"):
        validate_document("run-manifest", failed)

    document = run_manifest()
    document["invocations"].append(skipped_invocation())
    assert validate_document("run-manifest", document) is document
    document["invocations"][1]["bundle_path"] = "invocations/snap-a__broken-b__r1"
    with pytest.raises(ContractError, match="a skipped invocation has no bundle"):
        validate_document("run-manifest", document)

    document = run_manifest()
    document["invocations"].append({**skipped_invocation(), "skipped_reason": None})
    with pytest.raises(ContractError, match="must record why it was skipped"):
        validate_document("run-manifest", document)


def test_run_manifest_invocations_are_unique_and_carry_portable_paths():
    document = run_manifest()
    document["invocations"].append(copy.deepcopy(document["invocations"][0]))
    with pytest.raises(ContractError, match="invocation_id values must be unique"):
        validate_document("run-manifest", document)

    document = run_manifest()
    document["invocations"][0]["bundle_path"] = "/tmp/invocations/snap-a__fake-a__r1"
    with pytest.raises(ContractError, match="bundle_path must be a relative path"):
        validate_document("run-manifest", document)

    document = run_manifest()
    document["inputs"][0]["provenance_path"] = "../provenance.json"
    with pytest.raises(ContractError, match="provenance_path must be a relative path"):
        validate_document("run-manifest", document)

    document = run_manifest()
    document["invocations"][0]["skipped_reason"] = "skipped after all"
    with pytest.raises(ContractError, match="is not skipped"):
        validate_document("run-manifest", document)

    document = run_manifest()
    document["invocations"][0]["bundle_path"] = None
    with pytest.raises(ContractError, match="must record its bundle path"):
        validate_document("run-manifest", document)


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


def test_load_document_refuses_a_file_whose_bytes_are_not_utf_8_naming_it(tmp_path):
    """A non-UTF-8 file raises UnicodeDecodeError, which is a ValueError and not a JSON error."""
    path = tmp_path / "request.json"
    path.write_bytes(json.dumps(scan_request()).encode("utf-8").replace(b"run-1", b"run-\xff"))

    with pytest.raises(ContractError) as refusal:
        load_document(path, "scan-request")

    assert str(path) in str(refusal.value) and "utf-8" in str(refusal.value)
    assert isinstance(refusal.value.__cause__, UnicodeDecodeError)


def test_load_document_refuses_a_utf_8_byte_order_mark_naming_the_file(tmp_path):
    """A BOM decodes but is not JSON, so the refusal still names the file rather than escaping."""
    path = tmp_path / "request.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(scan_request()).encode("utf-8"))

    with pytest.raises(ContractError, match="could not load"):
        load_document(path, "scan-request")



def review_record(state: str = "human_approved") -> dict:
    """One recorded human approval of a decisions file, bound to it by hash."""
    return {
        "schema_version": "2.0",
        "run_id": "run-1",
        "decisions_sha256": HASH,
        "plan_sha256": HASH,
        "state": state,
        "created_at": "2026-09-20T15:00:00+00:00",
        "reviews": [{"reviewer": "R. Eviewer", "at": "2026-09-20T15:00:00+00:00",
                     "decisions_sha256": HASH, "note": "read every routed claim"}],
        "notes": [],
    }


def test_load_document_refuses_an_integer_literal_the_parser_will_not_read_naming_the_file(tmp_path):
    """An over-long integer literal raises a bare ValueError, which is not a JSON decode error."""
    path = tmp_path / "request.json"
    digits = "1" * (sys.get_int_max_str_digits() + 1)
    payload = json.dumps(scan_request()).replace('"timeout_seconds": 60', f'"timeout_seconds": {digits}')
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(ContractError) as refusal:
        load_document(path, "scan-request")

    assert str(path) in str(refusal.value) and "could not load" in str(refusal.value)
    assert isinstance(refusal.value.__cause__, ValueError)
    assert not isinstance(refusal.value.__cause__, json.JSONDecodeError)


def test_load_document_refuses_a_document_nested_past_the_recursion_limit_naming_the_file(tmp_path):
    """Deep nesting raises RecursionError, a RuntimeError the CLI would otherwise report unnamed."""
    path = tmp_path / "request.json"
    depth = 200_000
    path.write_text("[" * depth + "]" * depth, encoding="utf-8")

    with pytest.raises(ContractError) as refusal:
        load_document(path, "scan-request")

    assert str(path) in str(refusal.value) and "could not load" in str(refusal.value)
    assert isinstance(refusal.value.__cause__, RecursionError)


def test_the_blank_value_rule_is_the_one_the_write_paths_apply():
    """contracts.is_stated and cases._is_stated must answer alike; neither may drift alone."""
    from scaneval.cases import _is_stated

    values = ["", " ", "\t", "\u200b", "\u200b\ufeff", "\xad", "\u2028", "\x00",
              "R. Eviewer", " R. Eviewer ", "\u200bR", "0", 5, None, ["R. Eviewer"]]
    assert [is_stated(value) for value in values] == [_is_stated(value) for value in values]
    assert is_stated("R. Eviewer") and is_stated("\u200bR")
    assert not is_stated("\u200b") and not is_stated("\u2028") and not is_stated(5)


@pytest.mark.parametrize("reviewer", ["\u200b", "\u200b\ufeff", "\xad", "   "])
@pytest.mark.parametrize("state", ["draft", "human_approved"])
def test_a_review_record_cannot_report_a_review_by_an_unnamed_person(state, reviewer):
    """A hand-edited record whose reviewer is only zero-width characters names nobody."""
    document = review_record(state)
    assert validate_document("review-record", document) is document

    document["reviews"][0]["reviewer"] = reviewer
    with pytest.raises(ContractError, match="must name its reviewer"):
        validate_document("review-record", document)


def test_a_claim_cannot_cite_a_raw_artifact_the_result_does_not_declare():
    """Referential integrity for evidence: a cited artifact id must be one this result registers.

    Without it a claim could name an artifact nobody can open while the result still read
    success with resolved bundles, so an allegation could rest on evidence that does not exist.
    """
    document = scan_result()
    document["claims"][0]["raw_artifact_id"] = "native-json"
    with pytest.raises(ContractError, match="does not declare in raw_artifacts"):
        validate_document("scan-result", document)

    document["raw_artifacts"] = [{"id": "native-json", "path": "raw/native.json",
                                  "sha256": "sha256:" + "c" * 64}]
    assert validate_document("scan-result", document) is document

    # The reference stays checked when the artifact list is non-empty but names something else.
    document["claims"][1]["raw_artifact_id"] = "stderr"
    with pytest.raises(ContractError, match="claim-2"):
        validate_document("scan-result", document)


def test_a_claim_that_cites_no_raw_artifact_is_still_accepted():
    """Citing an artifact is optional; citing one that is not declared is not.

    An adapter with no per-claim raw record to point at, or none at all, still produces a valid
    result: the contract constrains the reference it makes, not whether it makes one.
    """
    document = scan_result()
    assert "raw_artifacts" not in document
    assert validate_document("scan-result", document) is document
    document["raw_artifacts"] = [{"id": "only", "path": "raw/only.json", "sha256": "sha256:" + "d" * 64}]
    assert validate_document("scan-result", document) is document


def review(level: str = "L3", role: str = "independent_reviewer", decision: str = "approve") -> dict:
    """One recorded review, with only the fields the level rule reads filled in."""
    return {"reviewer": "R. Eviewer", "role": role, "decision": decision, "level": level,
            "at": "2026-09-20T15:00:00+00:00", "note": ""}


@pytest.mark.parametrize(
    ("recorded", "claimed", "gap"),
    [
        (review("L3"), "L3", None),
        (review("L4"), "L3", None),
        (review("L3"), "L2", None),
        (review("L2", role="curator"), "L2", None),
        (review("L2", role="curator"), "L1", None),
        (review("L3"), None, None),
        (review("L2", role="curator"), "L3", "recorded at L2"),
        (review("L1", role="curator"), "L2", "recorded at L1"),
        (review("L3"), "L4", "recorded at L3"),
        (review("L4", role="curator"), "L3", "carries the role curator"),
        (review("L4", role="adjudicator"), "L4", "carries the role adjudicator"),
        (review("L3", decision="unresolved"), "L3", "decided unresolved, not approve"),
    ],
    ids=["exact", "higher", "lower-claim", "curator-l2", "curator-carries-l1", "no-claim",
         "curator-under-l3", "below-claim", "above-every-approval", "role-under-l3",
         "role-under-l4", "not-an-approval"],
)
def test_one_review_earns_a_level_on_its_own_record(recorded, claimed, gap):
    """level_gap reads the review it is given: no other review in a history can help it.

    Levels are ordered, so an approval recorded higher earns a lower claim, and L3 and L4 need the
    role on this same review rather than on an approval of content it never covered.
    """
    measured = level_gap(recorded, claimed)

    if gap is None:
        assert measured is None
    else:
        assert measured is not None and gap in measured


def test_the_covering_review_is_the_latest_one_that_names_these_labels():
    """Every gate asks one review, so which review that is cannot depend on who is asking."""
    case = {
        "case_id": "widget-shell", "represents": "r", "workload": "conventional_application",
        "component_role": "application", "model_involvement": {"state": "not_reviewed"},
        "coverage_signature": {"idiom": {"state": "not_reviewed"}},
        "canonical_target": {"kind": "command_injection", "variant_family": "f", "aliases": ["b", "a"]},
        "target": {"target_id": "T-widget-shell", "snapshot_id": "snap-a", "kind": "command_injection",
                   "description": "d", "accepted_locations": [], "assumptions": [], "matching_rules": []},
        "controls": [],
        "validation": {"level": "L3", "review_state": "human_approved", "checks": [], "reviews": []},
    }
    digest = label_digest(case)
    assert covering_review(case) is None, "no review is recorded"

    case["validation"]["reviews"].append({**review(), "labels_sha256": digest})
    assert covering_review(case) is case["validation"]["reviews"][-1]

    # Sorting the aliases is not a content change, so the same review still covers the labels.
    case["canonical_target"]["aliases"] = ["a", "b"]
    assert label_digest(case) == digest and covering_review(case) is not None

    # A later review of any other decision is the operative one, and it covers nothing.
    for decision in ("unresolved", "reject"):
        case["validation"]["reviews"].append({**review(decision=decision), "labels_sha256": digest})
        assert covering_review(case) is None
        case["validation"]["reviews"].pop()

    # An approval that names other content, or names none at all, covers nothing either.
    case["validation"]["reviews"].append({**review(), "labels_sha256": "sha256:" + "f" * 64})
    assert covering_review(case) is None
    case["validation"]["reviews"][-1].pop("labels_sha256")
    assert covering_review(case) is None
