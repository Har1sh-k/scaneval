from __future__ import annotations

import copy
from importlib.resources import files
import json
import sys

from jsonschema import Draft202012Validator
import pytest

from scaneval.contracts import (
    CASE_UNREAD_FIELDS,
    ContractError,
    SNAPSHOT_IDENTITY_FIELDS,
    SNAPSHOT_UNREAD_FIELDS,
    admission_chain_digest,
    canonical_json,
    canonical_sha256,
    case_anchor_projection,
    case_label_projection,
    chain_digest,
    check_set_digest,
    check_set_gap,
    claimed_level_gap,
    covering_review,
    effective_level,
    every_case_binds_its_labels,
    is_stated,
    label_digest,
    labels_are_bound,
    level_gap,
    load_document,
    operative_review_gap,
    pack_anchor_digest,
    pack_anchor_gap,
    pack_anchor_projection,
    pack_shape_gap,
    recorded_check_state,
    review_chain_digest,
    review_chain_gap,
    snapshot_anchor_projection,
    snapshot_identity_projection,
    snapshots_bound_by_labels,
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


def record_history(case: dict, entries: list[dict]) -> list[dict]:
    """Record *entries* on *case* as a verified chain, with the digest the history ends at.

    A review is read as the last entry of a history, so a history that does not verify names no
    operative review at all; a test recording one by hand has to chain it as the write path does.
    """
    reviews, head = chained([dict(entry) for entry in entries])
    case["validation"]["reviews"] = reviews
    if head is None:
        case["validation"].pop("reviews_sha256", None)
    else:
        case["validation"]["reviews_sha256"] = head
    return reviews


def case_pack_fragment(commit: str = "a" * 40, tree_hash: str = HASH) -> tuple[dict, dict]:
    """One pack holding one approved case, with only the fields these helpers read filled in."""
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
    pack = {"snapshots": [{"snapshot_id": "snap-a", "commit": commit, "tree_hash": tree_hash}],
            "cases": [case]}
    return pack, case


def test_the_covering_review_is_the_latest_one_that_names_these_labels():
    """Every gate asks one review, so which review that is cannot depend on who is asking."""
    pack, case = case_pack_fragment()
    digest = label_digest(pack, case)
    assert covering_review(pack, case) is None, "no review is recorded"

    approval = {**review(), "labels_sha256": digest}
    record_history(case, [approval])
    assert covering_review(pack, case) is case["validation"]["reviews"][-1]

    # Sorting the aliases is not a content change, so the same review still covers the labels.
    case["canonical_target"]["aliases"] = ["a", "b"]
    assert label_digest(pack, case) == digest and covering_review(pack, case) is not None

    # A later review of any other decision is the operative one, and it covers nothing.
    for decision in ("unresolved", "reject"):
        record_history(case, [approval, {**review(decision=decision), "labels_sha256": digest}])
        assert covering_review(pack, case) is None

    # An approval that names other content, or names none at all, covers nothing either.
    record_history(case, [{**review(), "labels_sha256": "sha256:" + "f" * 64}])
    assert covering_review(pack, case) is None
    stripped = {key: value for key, value in review().items() if key != "labels_sha256"}
    record_history(case, [stripped])
    assert covering_review(pack, case) is None

    # A history that does not verify names no operative review, whatever its entries say.
    record_history(case, [approval])
    case["validation"]["reviews_sha256"] = "sha256:" + "e" * 64
    assert covering_review(pack, case) is None


@pytest.mark.parametrize(
    ("commit", "tree_hash"),
    [("b" * 40, HASH), ("a" * 40, "sha256:" + "c" * 64), ("b" * 40, None)],
    ids=["repinned-commit", "different-export", "unpinned-export"],
)
def test_the_digest_covers_the_bytes_a_snapshot_stood_for(commit, tree_hash):
    """An approval covers the exact bytes reviewed, so snapshot identity is inside the digest."""
    pack, case = case_pack_fragment()
    digest = label_digest(pack, case)
    record_history(case, [{**review(), "labels_sha256": digest}])
    assert covering_review(pack, case) is not None

    repinned, moved = case_pack_fragment(commit=commit, tree_hash=tree_hash)
    record_history(moved, [{**review(), "labels_sha256": digest}])

    assert label_digest(repinned, moved) != digest
    assert covering_review(repinned, moved) is None
    assert effective_level(repinned, moved) is None


def test_a_level_a_covering_review_does_not_establish_is_refused_in_either_direction():
    """The covering review is the only source of the level, so a cached claim may only repeat it."""
    pack, case = case_pack_fragment()
    record_history(case, [{**review("L3"), "labels_sha256": label_digest(pack, case)}])
    assert claimed_level_gap(case["validation"]["reviews"][-1], "L3") is None
    assert effective_level(pack, case) == "L3"

    # Below the review: the plan would read L3 from the review while the record claims L2, so the
    # claim is measured against nothing any decision uses.
    assert "cached copy" in claimed_level_gap(case["validation"]["reviews"][-1], "L2")
    # Above it, and outside the role it needs: the older messages, unchanged.
    assert "recorded at L3" in claimed_level_gap(case["validation"]["reviews"][-1], "L4")
    curator = {**review("L4", role="curator"), "labels_sha256": label_digest(pack, case)}
    assert "carries the role curator" in claimed_level_gap(curator, "L2"), \
        "a review is measured against the level it records, not against a lower claim beside it"


def chained(entries: list[dict]) -> tuple[list[dict], str | None]:
    """The reviews as a verified chain, with the digest the history ends at."""
    head = None
    for entry in entries:
        entry["chain_sha256"] = review_chain_digest(head, entry)
        head = entry["chain_sha256"]
    return entries, head


def test_a_review_history_verifies_as_a_chain_with_a_recorded_end():
    """Each entry commits to the one before it, and the head commits to where the history stops.

    The chain catches an edit, a reordering, and a deletion from the middle; none of those leaves
    the later entries chaining to anything that is still there. The recorded head catches the
    deletion off the end, which the chain alone cannot see and which is the one that would restore
    an approval by dropping the review that withdrew it.
    """
    reviews, head = chained([review("L3"), review("L3", decision="unresolved"),
                             review("L4", role="curator")])
    assert review_chain_gap(reviews, head) is None
    assert review_chain_gap([], None) is None

    assert "no chain_sha256" in review_chain_gap(
        [{key: value for key, value in reviews[0].items() if key != "chain_sha256"}], head)

    edited = copy.deepcopy(reviews)
    edited[0]["note"] = "a note the reviewer did not write"
    assert "does not chain to the review before it" in review_chain_gap(edited, head)

    reordered = [copy.deepcopy(reviews[1]), copy.deepcopy(reviews[0]), copy.deepcopy(reviews[2])]
    assert "does not chain to the review before it" in review_chain_gap(reordered, head)

    middle = [copy.deepcopy(reviews[0]), copy.deepcopy(reviews[2])]
    assert "does not chain to the review before it" in review_chain_gap(middle, head)

    truncated = copy.deepcopy(reviews[:-1])
    gap = review_chain_gap(truncated, head)
    assert "a review was deleted from the end of it" in gap
    assert review_chain_gap(truncated, truncated[-1]["chain_sha256"]) is None, \
        "rebuilding the head is what it costs to delete one, and that is a deliberate act"

    assert "nothing says where the recorded review history ends" in review_chain_gap(reviews, None)
    assert "the history it names was deleted whole" in review_chain_gap([], head)

def check_set(snapshot_id: str = "snap-a", results: tuple[str, ...] = ("pass", "pass"),
              tree_hash: str = HASH) -> dict:
    """One case validation block holding one anchored check set, as the write path records it."""
    checks = [{"check": f"check-{index}", "result": result, "at": "2026-09-20T15:00:00+00:00",
               "detail": "", "snapshot_id": snapshot_id} for index, result in enumerate(results)]
    record = {"result": "pass" if all(r == "pass" for r in results) else "fail",
              "tree_hash": tree_hash}
    record["checks_sha256"] = check_set_digest(snapshot_id, record, checks)
    return {"checks": checks, "check_sets": {snapshot_id: record}}


def test_a_check_set_is_one_anchored_record_and_not_a_view_over_the_checks():
    """The set states its own result and hashes its own checks, so membership cannot be edited.

    Deleting the failing check, moving it to another set by rewriting its snapshot id, and editing
    the record to say the set passed are all deletions of the same kind: each leaves the record
    hashing to something that is no longer there. Restating the record is the deliberate act, and
    then the pack says what the person who restated it wrote.
    """
    validation = check_set(results=("pass", "fail"))
    assert recorded_check_state(validation, "snap-a") == "fail"
    assert check_set_gap(validation, "snap-a") is None
    assert recorded_check_state(validation, "snap-b") is None, "no set is recorded for it"

    deleted = copy.deepcopy(validation)
    deleted["checks"] = [check for check in deleted["checks"] if check["result"] == "pass"]
    assert "a check was deleted, unattributed, reordered, or edited" in check_set_gap(deleted, "snap-a")
    assert recorded_check_state(deleted, "snap-a") is None

    moved = copy.deepcopy(validation)
    moved["checks"][1]["snapshot_id"] = "snap-b"
    assert "a check was deleted, unattributed, reordered, or edited" in check_set_gap(moved, "snap-a")
    assert "records no check set for it" in check_set_gap(moved, "snap-b")

    reordered = copy.deepcopy(validation)
    reordered["checks"].reverse()
    assert "a check was deleted, unattributed, reordered, or edited" in check_set_gap(reordered, "snap-a")

    claimed = copy.deepcopy(validation)
    claimed["check_sets"]["snap-a"]["result"] = "pass"
    assert "a check was deleted, unattributed, reordered, or edited" in check_set_gap(claimed, "snap-a"), \
        "the record hashes its own result too, so restating it is not a quiet edit"

    # Restated over the checks it still holds, the record contradicts them instead.
    restated = copy.deepcopy(claimed)
    record = restated["check_sets"]["snap-a"]
    record["checks_sha256"] = check_set_digest("snap-a", record, restated["checks"])
    assert "records pass, but the checks it holds are fail" in check_set_gap(restated, "snap-a")

    emptied = copy.deepcopy(validation)
    emptied["checks"] = []
    assert "no recorded check carries that snapshot" in check_set_gap(emptied, "snap-a")

    unrecorded = copy.deepcopy(validation)
    unrecorded.pop("check_sets")
    assert "records no check set for it" in check_set_gap(unrecorded, "snap-a")
    assert recorded_check_state(unrecorded, "snap-a") is None


def admission(case_id: str = "widget-shell", decision: str = "admitted") -> dict:
    """One admission decision, with only the fields the chain and the anchor read filled in."""
    return {"case_id": case_id, "target_id": f"T-{case_id}", "decision": decision,
            "by": "J. Curator", "at": "2026-09-20T15:00:00+00:00", "reason": "pilot slice"}


def anchored(pack: dict) -> dict:
    """Chain the pack's admissions and anchor the pack over them, as the write path does."""
    previous = None
    for entry in pack["admissions"]:
        entry.pop("chain_sha256", None)
        entry["chain_sha256"] = admission_chain_digest(previous, entry)
        previous = entry["chain_sha256"]
    pack["anchor_sha256"] = pack_anchor_digest(pack)
    return pack


@pytest.mark.parametrize(
    ("pack", "gap"),
    [
        ("not a pack", "a case pack is a JSON object, not str"),
        ({}, "this pack records nothing as its snapshots"),
        ({"snapshots": []}, "this pack records nothing as its cases"),
        ({"snapshots": [], "cases": []}, "this pack records nothing as its admissions"),
        ({"snapshots": {}, "cases": [], "admissions": []},
         "this pack records a dict as its snapshots"),
        ({"snapshots": [], "cases": ["widget-shell"], "admissions": []},
         "every entry of cases must be a JSON object"),
    ],
    ids=["not-an-object", "nothing-at-all", "no-cases", "no-admissions", "wrong-type",
         "entry-is-not-an-object"],
)
def test_the_anchor_gate_refuses_a_shape_it_cannot_read_instead_of_raising(pack, gap):
    """The first gate a write asks is asked of whatever it was handed, so it establishes the shape.

    Changed deliberately this round: pack_anchor_gap read pack["admissions"] before anything had
    said there was one, so a hand-built, truncated, or half-written pack came back as
    KeyError: 'admissions' from inside a gate whose whole job is to say what is wrong with a pack.
    A crash is not a refusal, and the caller that has to report it cannot tell the two apart.
    """
    assert gap in pack_shape_gap(pack)
    assert gap in pack_anchor_gap(pack)


def test_the_shape_gate_passes_a_pack_the_contract_would_still_refuse():
    """It says there is something to read, and nothing more; the contract is validate_document."""
    readable = {"snapshots": [], "cases": [], "admissions": []}
    assert pack_shape_gap(readable) is None
    assert "anchor_sha256 is missing" in pack_anchor_gap(readable)
    with pytest.raises(ContractError):
        validate_document("case-pack", readable)


def test_an_admission_history_verifies_as_a_chain_the_pack_anchor_ends():
    """Admissions are a history, so lifting a decision out of it is visible.

    The chain catches an edit, a reordering, and a deletion from the middle. The anchor catches the
    deletion off the end, which the chain alone cannot see and which is the one that would restore
    a case by dropping the rejection that kept it out.
    """
    pack, case = case_pack_fragment()
    pack["admissions"] = [admission(), admission(decision="rejected")]
    anchored(pack)
    assert pack_anchor_gap(pack) is None

    truncated = copy.deepcopy(pack)
    del truncated["admissions"][-1]
    assert "a record a planning decision reads was deleted" in pack_anchor_gap(truncated)

    middle = copy.deepcopy(pack)
    middle["admissions"] = [copy.deepcopy(pack["admissions"][1])]
    assert "does not chain to the admission before it" in pack_anchor_gap(middle)

    edited = copy.deepcopy(pack)
    edited["admissions"][1]["decision"] = "admitted"
    assert "does not chain to the admission before it" in pack_anchor_gap(edited)

    unchained = copy.deepcopy(pack)
    del unchained["admissions"][0]["chain_sha256"]
    assert "records no chain_sha256" in pack_anchor_gap(unchained)

    # A review cannot be replayed as an admission: the chain digest names which kind it covers.
    assert admission_chain_digest(None, admission()) != chain_digest(None, admission(), "review")

    # Rebuilding both is what the deletion costs, and it is a deliberate act.
    assert pack_anchor_gap(anchored(truncated)) is None


def test_the_pack_anchor_records_the_case_roster_and_where_each_history_ends():
    """What a case cannot anchor for itself: that it is there, and that it had a history.

    Deleting a case takes its chained history with it, and wiping a history takes the head that
    would have said where it ended, so both are anchored one level up. Changed deliberately: the
    projection used to be a roster of three fields per case, which is a list someone has to
    remember to extend. It is the whole case minus a stated allowlist now, and minus the labels only
    for a case whose review holds them by digest, so the review head is in it because the validation
    block is, and so is every other field nothing else covers.
    """
    pack, case = case_pack_fragment()
    second = copy.deepcopy(case)
    second["case_id"] = "widget-path"
    second["target"] = {**case["target"], "target_id": "T-widget-path"}
    second["validation"] = {"level": None, "review_state": "draft", "checks": [], "reviews": []}
    pack["cases"].append(second)
    pack["admissions"] = []
    record_history(case, [{**review(), "labels_sha256": label_digest(pack, case)}])
    anchored(pack)
    assert pack_anchor_gap(pack) is None
    projected = pack_anchor_projection(pack)["cases"]
    assert [entry["case_id"] for entry in projected] == ["widget-shell", "widget-path"]
    assert projected[0]["validation"]["reviews_sha256"] == case["validation"]["reviews_sha256"]
    assert "reviews_sha256" not in projected[1]["validation"], \
        "a case that never had a history anchors one that is not there"
    # Changed deliberately this round. This used to assert that no case anchors its labels, which
    # was the escape the anchor claim was refuted by: the second case records no review, so no
    # digest held its target, its controls, or what it says it represents, and editing any of them
    # was invisible to every record. The rule is per case now, and it is the recorded digest that
    # decides, so the reviewed case still keeps its labels out and the unreviewed one does not.
    assert "target" not in projected[0] and "controls" not in projected[0], \
        "a review holds these labels by digest, so anchoring them too would cost a rebuild"
    assert projected[1]["target"] == second["target"], \
        "no review holds this case's labels, so nothing but the anchor can hold them"
    assert {"controls", "represents", "canonical_target"} <= set(projected[1])

    deleted = copy.deepcopy(pack)
    del deleted["cases"][1]
    assert "a record a planning decision reads was deleted" in pack_anchor_gap(deleted)

    reordered = copy.deepcopy(pack)
    reordered["cases"].reverse()
    assert "a record a planning decision reads was deleted" in pack_anchor_gap(reordered)

    renamed = copy.deepcopy(pack)
    renamed["cases"][1]["case_id"] = "widget-other"
    assert "a record a planning decision reads was deleted" in pack_anchor_gap(renamed)

    wiped = copy.deepcopy(pack)
    wiped["cases"][0]["validation"]["reviews"] = []
    wiped["cases"][0]["validation"].pop("reviews_sha256")
    assert review_chain_gap([], None) is None, \
        "nothing inside a wiped history can complain; the anchor is what is left"
    assert "a record a planning decision reads was deleted" in pack_anchor_gap(wiped)

    missing = copy.deepcopy(pack)
    missing.pop("anchor_sha256")
    assert "anchor_sha256 is missing" in pack_anchor_gap(missing)


def control(evidence_ids: list[str]) -> dict:
    """One control, with only the fields the label projection reads filled in."""
    return {"control_id": "C-widget-shell-safe", "snapshot_id": "snap-a", "type": "capability_safe",
            "description": "d", "property": "p", "allowed_actors_inputs": "a", "assumptions": [],
            "ruled_out_allegation": "r", "locations": [], "evidence_ids": evidence_ids}


def test_the_label_digest_covers_the_evidence_a_control_rests_on():
    """A control asserted from other evidence is a different control, so the approval lapses."""
    pack, case = case_pack_fragment()
    case["controls"] = [control(["fix"])]
    digest = label_digest(pack, case)
    record_history(case, [{**review(), "labels_sha256": digest}])
    assert covering_review(pack, case) is not None

    case["controls"] = [control(["inspection"])]
    assert label_digest(pack, case) != digest
    assert covering_review(pack, case) is None

    case["controls"] = [control(["inspection", "fix"])]
    swapped = label_digest(pack, case)
    case["controls"] = [control(["fix", "inspection"])]
    assert label_digest(pack, case) == swapped, "the order of the ids carries no content"



# The one place in this file that knows a case record can hold a free-keyed map: check_sets is
# keyed by snapshot id, so a path through it is collapsed to {} to be comparable with the schema,
# which declares it as additionalProperties. Matching is on the end of the path, so the same map
# collapses whether it is reached from a case or from the pack. A second such map added later has
# no entry here, so the completeness test below fails rather than quietly passing over it.
FREE_KEYED_PATHS = ("validation.check_sets",)


def is_free_keyed(prefix: str) -> bool:
    return any(prefix == path or prefix.endswith(f".{path}") for path in FREE_KEYED_PATHS)


def field_paths(value: object, prefix: str = "") -> set[str]:
    """Every field path inside *value*, list positions merged and free-keyed maps collapsed.

    A list contributes one ``[]`` segment rather than an index, so sorting a list is not a
    different set of paths, and a map keyed by data contributes ``{}`` rather than the key. What is
    compared is therefore which fields are there, not how many or in what order.
    """
    if isinstance(value, dict):
        paths: set[str] = set()
        for key, item in value.items():
            segment = "{}" if is_free_keyed(prefix) else key
            here = f"{prefix}.{segment}" if prefix else segment
            paths.add(here)
            paths |= field_paths(item, here)
        return paths
    if isinstance(value, list):
        paths = set()
        for item in value:
            paths |= field_paths(item, f"{prefix}[]")
        return paths
    return set()


def case_pack_schema() -> dict:
    return json.loads(files("scaneval").joinpath("schemas", "case-pack.schema.json")
                      .read_text(encoding="utf-8"))


# Every JSON Schema keyword this file knows how to read, in two tables. The first holds the
# constructs that can declare a field, each of them walked below; the second holds the ones that
# constrain a value without declaring one. A keyword in neither is refused rather than walked past,
# because a field declared under a construct declared_paths does not walk is a field the
# completeness tests below never ask about, which is the failure they exist to prevent. That is a
# live risk and not a hypothetical one: allOf, prefixItems, patternProperties, if/then/else and
# dependentSchemas all declare fields and none of them is walked here, so adding one to the schema
# now fails this file instead of quietly shrinking what the tests cover.
FIELD_DECLARING_KEYWORDS = frozenset({
    "$ref", "properties", "items", "oneOf", "anyOf", "additionalProperties",
})
# $defs holds subschemas reached only through $ref, so walking it would invent paths for a
# definition nothing references; each one is walked where it is used. propertyNames constrains the
# keys of a free-keyed map rather than declaring a field under it.
VALUE_ONLY_KEYWORDS = frozenset({
    "$schema", "$id", "$defs", "$comment", "title", "description", "default", "examples",
    "type", "required", "enum", "const", "format", "pattern", "propertyNames",
    "minLength", "maxLength", "minItems", "maxItems", "uniqueItems", "minimum", "maximum",
})


def refuse_unknown_keywords(node: dict, prefix: str) -> None:
    """Fail unless every keyword *node* carries is one :func:`declared_paths` accounts for."""
    unknown = sorted(set(node) - FIELD_DECLARING_KEYWORDS - VALUE_ONLY_KEYWORDS)
    assert not unknown, (
        f"{prefix or '<root>'}: declared_paths does not read {unknown}, so a field declared under "
        "it would be invisible to the completeness tests; walk it or state why it declares no field")


def declared_paths(schema: dict, node: dict, prefix: str = "") -> set[str]:
    """Every field path the schema declares under *node*, in the shape :func:`field_paths` writes.

    References are resolved, ``oneOf`` and ``anyOf`` branches contribute all of their fields, array
    items contribute under ``[]``, and an object whose values are a schema, which is how a
    free-keyed map is declared, contributes under ``{}``.

    Every keyword of every node is accounted for on the way: a construct that can declare a field
    is walked, one that only constrains a value is listed, and anything else fails here rather than
    being skipped. Changed deliberately this round, because skipping was the quiet failure: a field
    declared under a construct this does not walk never reaches the completeness tests, so they
    would keep passing while covering less.
    """
    refuse_unknown_keywords(node, prefix)
    while "$ref" in node:
        siblings = sorted((set(node) & FIELD_DECLARING_KEYWORDS) - {"$ref"})
        assert not siblings, f"{prefix or '<root>'}: a $ref beside {siblings} is not read here"
        target = schema
        for part in node["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        node = target
        refuse_unknown_keywords(node, prefix)
    paths: set[str] = set()
    for key, child in node.get("properties", {}).items():
        here = f"{prefix}.{key}" if prefix else key
        paths.add(here)
        paths |= declared_paths(schema, child, here)
    items = node.get("items")
    if items is not None:
        assert isinstance(items, dict), f"{prefix}[]: items must be a schema object to be walked"
        paths |= declared_paths(schema, items, f"{prefix}[]")
    for branch in list(node.get("oneOf", [])) + list(node.get("anyOf", [])):
        paths |= declared_paths(schema, branch, prefix)
    extra = node.get("additionalProperties")
    if isinstance(extra, dict):
        paths |= declared_paths(schema, extra, f"{prefix}.{{}}" if prefix else "{}")
    else:
        assert extra is None or isinstance(extra, bool), (
            f"{prefix}: additionalProperties must be a schema object or a boolean")
    return paths


def test_declared_paths_refuses_a_schema_construct_it_does_not_walk():
    """A construct this cannot read fails loudly, because skipping one hollows out the tests below.

    Each of these declares a field somewhere the walk never reaches, so under the previous version
    the completeness tests kept passing while asking about less than the whole contract.
    """
    schema = case_pack_schema()
    assert declared_paths(schema, schema), "the contract as it stands is fully walked"

    for construct in ("allOf", "prefixItems", "patternProperties", "dependentSchemas", "not"):
        node = {"type": "object", construct: [{"properties": {"escaped": {"type": "string"}}}]}
        with pytest.raises(AssertionError, match=f"does not read \\['{construct}'\\]"):
            declared_paths(schema, node, "case")

    with pytest.raises(AssertionError, match=r"a \$ref beside \['properties'\]"):
        declared_paths(schema, {"$ref": "#/$defs/case", "properties": {"escaped": {}}}, "case")

    with pytest.raises(AssertionError, match="items must be a schema object"):
        declared_paths(schema, {"type": "array", "items": True}, "case.controls")


def maximal_pack() -> dict:
    """One pack carrying every field the contract declares, optional ones included.

    It is shaped for the completeness tests rather than for consistency: the digests in it are not
    computed, because nothing here validates a digest. What matters is that every declared field is
    present, which the tests assert against the schema rather than trusting this to stay complete.
    """
    stated = {"state": "not_reviewed", "reason": "nobody has read this yet"}
    location = {"path": "src/app.py", "start_line": 1, "end_line": 2, "role": "sink",
                "note": "the call site"}
    return {
        "schema_version": "2.0", "namespace": "org.example", "pack_id": "pilot",
        "version": "0.1.0-draft", "status": "draft", "description": "every field, once",
        "review_budgets": {"full": [5, 10], "pr": [5]},
        "notes": ["a pack note"],
        "anchor_sha256": "sha256:" + "a" * 64,
        "snapshots": [{
            "snapshot_id": "snap-a",
            "repository": {"url": "https://example.invalid/acme/widget.git", "name": "acme/widget",
                           "historical_url": "https://example.invalid/old/widget.git"},
            "commit": "a" * 40, "reference": "parent of fix commit", "languages": ["python", "go"],
            "workload": "conventional_application", "component_role": "application",
            "production_use_evidence": "named in the vendor advisory",
            "license": {"spdx": "MIT", "verified": False, "note": "not checked"},
            "tree_hash": HASH, "git_tree": "b" * 40, "role": "vulnerable",
        }],
        "cases": [{
            "case_id": "widget-shell", "represents": "This case tests x under y, and adds z.",
            "workload": "conventional_application", "component_role": "application",
            "model_involvement": dict(stated),
            "coverage_signature": {key: dict(stated) for key in
                                   ("idiom", "input_source", "trust_boundary",
                                    "security_operation", "guard_failure", "analysis_span")},
            "canonical_target": {"kind": "command_injection", "variant_family": "widget-shell",
                                 "aliases": ["CVE-2026-0001"]},
            "target": {"target_id": "T-widget-shell", "snapshot_id": "snap-a",
                       "kind": "command_injection", "description": "cmd reaches a shell",
                       "affected_input_or_authority": dict(stated),
                       "accepted_locations": [dict(location)], "assumptions": ["default deployment"],
                       "matching_rules": ["any claim naming src/app.py"]},
            "controls": [{"control_id": "C-widget-shell-safe", "snapshot_id": "snap-a",
                          "type": "fixed_target", "target_id": "T-widget-shell",
                          "description": "the repaired call", "property": "argument list only",
                          "allowed_actors_inputs": "operators on the host",
                          "assumptions": ["default deployment"],
                          "ruled_out_allegation": "shell interpolation here",
                          "locations": [dict(location)], "evidence_ids": ["fix"]}],
            "evidence": [{"evidence_id": "fix", "origin": "fix_without_advisory",
                          "kind": "fix_commit", "reference": "acme/widget@" + "c" * 40,
                          "revision": "c" * 40, "retrieved": "2026-09-20", "note": "the fix"}],
            "disclosure": {"earliest_public_artifact": "2026-01-01", "cve_published": "2026-01-02",
                           "ghsa_published": "2026-01-03", "fix_commit_date": "2026-01-04",
                           "note": "dates read from the advisory"},
            "disposition": {"value": "validate", "reason": "worth validating"},
            "validation": {
                "level": "L3", "review_state": "human_approved",
                "checks": [{"check": "locations_exist_in_snapshot", "result": "pass",
                            "at": "2026-09-20T15:00:00+00:00", "detail": "1 location found",
                            "snapshot_id": "snap-a"}],
                "check_sets": {"snap-a": {"result": "pass", "tree_hash": HASH,
                                          "checks_sha256": "sha256:" + "d" * 64}},
                "checks_failed": False,
                "reviews": [{"reviewer": "R. Eviewer", "role": "independent_reviewer",
                             "decision": "approve", "level": "L3",
                             "at": "2026-09-20T15:00:00+00:00", "note": "read",
                             "labels_sha256": "sha256:" + "e" * 64,
                             "chain_sha256": "sha256:" + "f" * 64}],
                "reviews_sha256": "sha256:" + "f" * 64,
            },
            "split": "evaluation", "notes": ["a case note"],
        }],
        "admissions": [{"case_id": "widget-shell", "target_id": "T-widget-shell",
                        "decision": "admitted", "by": "J. Curator",
                        "at": "2026-09-20T16:00:00+00:00", "reason": "pilot slice",
                        "chain_sha256": "sha256:" + "0" * 64}],
    }


def test_the_maximal_pack_carries_every_field_the_contract_declares():
    """The fixture the completeness tests measure is itself measured, against the schema.

    A field added to the contract and not to this fixture would otherwise make those tests pass by
    never asking about it. Shape is checked too, so the fixture cannot drift into something the
    contract would not accept.
    """
    schema = case_pack_schema()
    pack = maximal_pack()
    Draft202012Validator(schema).validate(pack)

    missing = declared_paths(schema, schema) - field_paths(pack)
    assert missing == set(), f"the fixture omits declared fields: {sorted(missing)}"


# Why each field of a case sits outside the anchor, written here rather than read out of the
# constants the code projects by. These two tables are what let the completeness tests below fail.
# The previous version of those tests derived the split from CASE_LABEL_FIELDS and then asserted
# that the split was CASE_LABEL_FIELDS, so a field added to that constant escaped the anchor and
# nothing failed: the test compared the split against itself and was cited as evidence that it
# could not. Everything here is written down by hand, and a field that leaves the anchor without
# being named here with a reason is reported as having escaped both records.
CASE_FIELDS_A_DIGEST_HOLDS = {
    "represents": "what the case claims to test: the approving review read this sentence",
    "workload": "the deployment the allegation is made under, which a reviewer judged",
    "component_role": "what the component is, which a reviewer judged",
    "model_involvement": "whether a model is in the path, which a reviewer judged",
    "coverage_signature": "how the case is classified for coverage, which a reviewer judged",
    "canonical_target": "the kind, the variant family, and the public aliases of the allegation",
    "target": "the allegation itself, down to its accepted locations and matching rules",
    "controls": "what the case says is not an allegation, which an approval covers too",
    "evidence": "the records the allegation rests on: an approval covers these with it",
}
CASE_FIELDS_NOTHING_READS = {
    "notes": "free text no planning decision reads, so no record needs to hold it",
}
SNAPSHOT_FIELDS_A_DIGEST_HOLDS = {
    "commit": "the bytes a label points at, which an approval covers",
    "tree_hash": "the exported tree those bytes were read as, which an approval covers",
    "languages": "which adapters ever see those bytes, which an approval covers",
}
SNAPSHOT_FIELDS_NOTHING_READS: dict[str, str] = {}
PACK_FIELDS_OUTSIDE_THE_ANCHOR = {
    "anchor_sha256": "the anchor itself, which cannot cover its own value",
    "description": "free text no planning decision reads",
    "notes": "free text no planning decision reads",
    "schema_version": "pack identity, which every plan binds by hashing the whole file",
    "namespace": "pack identity, which every plan binds by hashing the whole file",
    "pack_id": "pack identity, which every plan binds by hashing the whole file",
    "version": "pack identity, which every plan binds by hashing the whole file",
    "status": "the release workflow rewrites it; every plan binds the file it was built from",
}


def paths_under(names: dict[str, str], paths: set[str]) -> set[str]:
    """Every path in *paths* whose first segment is one of the fields *names* allowlists."""
    return {path for path in paths if path.split(".")[0].split("[")[0] in names}


def check_allowlist(names: dict[str, str], declared: set[str], outside: set[str], label: str) -> None:
    """Hold an allowlist to its job: it explains fields that are really outside, and no others.

    Three things, and each of them is a way the table could stop meaning anything. Every entry
    states a reason, so an entry is a decision rather than a name. Every entry names a field the
    contract actually declares, so a field deleted from the schema does not leave a standing excuse
    behind for the next field to be given that name. And every entry names a field that is really
    outside the anchor, so an excuse cannot be written for a field the anchor covers and then be
    read later as if it had always been the reason that field was exempt.
    """
    top = {path.split(".")[0].split("[")[0] for path in declared}
    for name, reason in names.items():
        assert is_stated(reason), f"{label}: the allowlist entry {name!r} states no reason"
        assert name in top, f"{label}: the allowlist names {name!r}, which the contract does not declare"
        assert name in {path.split(".")[0].split("[")[0] for path in outside}, \
            f"{label}: the allowlist excuses {name!r}, which the anchor covers anyway"


def test_every_declared_case_field_is_anchored_or_allowlisted_with_a_reason():
    """Every field the contract declares for a case is anchored, or allowlisted here with a reason.

    The set of fields comes from the schema, not from the constants the code projects by, and the
    reasons are written by hand in this file. That is the whole point of the rewrite: a field added
    to CASE_LABEL_FIELDS used to leave the anchor and satisfy the assertion that the split was
    CASE_LABEL_FIELDS, so the test could not fail on the thing it was cited for. Now a field can
    leave the anchor only by being named in one of the two tables above, and a table entry has to
    name a field the schema declares and say why.

    Two cases are measured, because whether a field is anchored depends on whether a digest already
    holds it. A case no review has bound is anchored whole, ``notes`` aside. A case whose review
    carries a labels_sha256 is anchored except the label fields that review reads.
    """
    schema = case_pack_schema()
    approved = maximal_pack()["cases"][0]
    assert labels_are_bound(approved), "the maximal case records a review carrying a digest"
    # The same case with a history whose latest review carries no digest, which is how a pack
    # written before approvals were bound to content reads. Every declared field is still present,
    # so what is measured is the projection rather than a fixture with fields missing; a case with
    # no review at all is the other unbound shape, and
    # test_the_anchor_holds_the_labels_no_recorded_digest_holds measures that one.
    unreviewed = copy.deepcopy(approved)
    unreviewed["validation"]["reviews"].append(
        {key: value for key, value in approved["validation"]["reviews"][0].items()
         if key != "labels_sha256"})
    assert not labels_are_bound(unreviewed)

    declared = declared_paths(schema, schema["$defs"]["case"])
    assert declared - field_paths(approved) == set(), "the fixture must carry every declared field"

    # A case no digest speaks for: the anchor is the only record there is, so it holds everything
    # but the fields nothing reads. This is the claim that was false before this round.
    outside_unreviewed = declared - field_paths(case_anchor_projection(unreviewed))
    escaped = outside_unreviewed - paths_under(CASE_FIELDS_NOTHING_READS, declared)
    assert escaped == set(), (
        f"no review binds this case, so nothing but the anchor can hold {sorted(escaped)}")
    check_allowlist(CASE_FIELDS_NOTHING_READS, declared, outside_unreviewed, "case, unreviewed")

    # A case whose review holds its labels by digest: those labels, and only those, may be outside.
    outside_approved = declared - field_paths(case_anchor_projection(approved))
    escaped = (outside_approved - paths_under(CASE_FIELDS_NOTHING_READS, declared)
               - paths_under(CASE_FIELDS_A_DIGEST_HOLDS, declared))
    assert escaped == set(), f"{sorted(escaped)} is in neither record and in no allowlist"
    check_allowlist(CASE_FIELDS_A_DIGEST_HOLDS, declared, outside_approved, "case, approved")
    check_allowlist(CASE_FIELDS_NOTHING_READS, declared, outside_approved, "case, approved")

    # The allowlisted labels are the ones the digest really reads, so a reason cannot be given here
    # for a field no review ever covers. This is what ties the hand-written table to the code: a
    # field added to CASE_LABEL_FIELDS and not to the table fails both this and the assertion above.
    digested = {path.split(".")[0].split("[")[0]
                for path in field_paths(case_label_projection(approved))}
    assert digested == set(CASE_FIELDS_A_DIGEST_HOLDS)
    assert set(CASE_FIELDS_NOTHING_READS) == set(CASE_UNREAD_FIELDS) == {"notes"}
    # And nothing the digest holds is anchored under it as well, for an approved case: two records
    # of one fact would mean an edited label could not be re-approved without an anchor rebuilt.
    assert paths_under(CASE_FIELDS_A_DIGEST_HOLDS, field_paths(case_anchor_projection(approved))) == set()


def test_the_anchor_holds_the_labels_no_recorded_digest_holds():
    """A case nobody has reviewed keeps its labels in the anchor, so editing one is still visible.

    Closed deliberately this round, and it refuted the claim the projections were built on. The
    label fields were subtracted from the anchor unconditionally on the grounds that the covering
    review holds them, which is no ground at all for a draft or mechanically checked case: there is
    no review, so no digest holds the target, the controls, the evidence, or what the case says it
    represents, and editing any of them was visible to nothing. A mechanically checked case is
    planned at L1, so this was an edit to a planned allegation that no record disagreed with.
    """
    pack = maximal_pack()
    pack["cases"][0]["validation"]["reviews"] = []
    pack["cases"][0]["validation"].pop("reviews_sha256")
    anchored(pack)
    assert not labels_are_bound(pack["cases"][0]) and pack_anchor_gap(pack) is None

    def retarget(case: dict) -> None:
        case["target"]["description"] = "something else entirely"

    def drop_a_control(case: dict) -> None:
        case["controls"].clear()

    def add_evidence(case: dict) -> None:
        case["evidence"].append(dict(case["evidence"][0], evidence_id="extra"))

    def restate(case: dict) -> None:
        case["represents"] = "This case tests something else under x, and adds y."

    for edit in (retarget, drop_a_control, add_evidence, restate):
        candidate = copy.deepcopy(pack)
        edit(candidate["cases"][0])
        assert "a record a planning decision reads was deleted" in pack_anchor_gap(candidate), \
            f"{edit.__name__} on an unreviewed case is visible to no other record"

    # Recording a review is what moves the labels out, because it is what records them elsewhere.
    case = pack["cases"][0]
    record_history(case, [{**review(), "labels_sha256": label_digest(pack, case)}])
    anchored(pack)
    assert labels_are_bound(case) and pack_anchor_gap(pack) is None
    retarget(case)
    assert pack_anchor_gap(pack) is None, \
        "the review holds these labels, so an edit costs the approval, not a rebuilt anchor"
    assert covering_review(pack, case) is None, "and it does cost the approval"


def orphan_snapshot_pack() -> dict:
    """A pack of fully bound cases that also declares a snapshot no case names.

    The ordinary shape of one: a snapshot is declared before the case that will point at it, which
    is what ``add_snapshot`` does on its own.
    """
    pack = maximal_pack()
    pack["snapshots"].append({**copy.deepcopy(pack["snapshots"][0]), "snapshot_id": "snap-b"})
    return pack


def test_every_declared_snapshot_field_is_anchored_or_allowlisted_with_a_reason():
    """The same rule for a snapshot, and now measured through the pack that decides it.

    A snapshot's identity is what a label points at, so a recorded review carrying a digest of
    those labels holds it. That is true only of the snapshots such a review names, and only where
    one was recorded, so both conditions are measured here against a real pack instead of being
    passed in as an answer.

    Changed deliberately this round: this test read ``snapshot_anchor_projection`` directly, with
    ``identity_bound`` hardcoded true for one measurement and false for the other. That measured
    the subtraction and never the rule that decides it, so no assertion in this file could fail
    when a pack subtracted the identity of a snapshot no case names, which no label digest can hold
    and the anchor had therefore stopped holding too.
    """
    schema = case_pack_schema()
    declared = declared_paths(schema, schema["$defs"]["snapshot"])
    assert declared - field_paths(maximal_pack()["snapshots"][0]) == set(), \
        "the fixture must carry every declared field"

    def anchored_fields(pack: dict, index: int) -> set[str]:
        """Which of that snapshot's fields the pack anchor holds, as the anchor itself projects."""
        return field_paths(pack_anchor_projection(pack)["snapshots"][index])

    # A snapshot a case names, in a pack where every case binds its labels: the identity, and only
    # the identity, may be outside the anchor.
    outside_bound = declared - anchored_fields(maximal_pack(), 0)
    escaped = outside_bound - paths_under(SNAPSHOT_FIELDS_A_DIGEST_HOLDS, declared)
    assert escaped == set(), f"{sorted(escaped)} is in neither record and in no allowlist"
    check_allowlist(SNAPSHOT_FIELDS_A_DIGEST_HOLDS, declared, outside_bound, "snapshot, bound")

    # The two packs where no digest holds this snapshot's identity: one whose only case records no
    # review at all, and one where the snapshot is declared and no case names it. The anchor is the
    # only record either of them has, so it holds every field the contract declares.
    unreviewed = maximal_pack()
    unreviewed["cases"][0]["validation"]["reviews"] = []
    unreviewed["cases"][0]["validation"].pop("reviews_sha256")

    for reason, pack, index in (("no case binds its labels", unreviewed, 0),
                                ("no case names this snapshot", orphan_snapshot_pack(), 1)):
        outside = declared - anchored_fields(pack, index)
        escaped = outside - paths_under(SNAPSHOT_FIELDS_NOTHING_READS, declared)
        assert escaped == set(), (
            f"{reason}, so no digest holds this snapshot's {sorted(escaped)} and the anchor has to")
    assert SNAPSHOT_FIELDS_NOTHING_READS == {} and SNAPSHOT_UNREAD_FIELDS == frozenset(), \
        "nothing about a snapshot goes unread"

    identity = {path.split(".")[0].split("[")[0]
                for path in field_paths(snapshot_identity_projection(maximal_pack()["snapshots"][0]))}
    assert identity == set(SNAPSHOT_FIELDS_A_DIGEST_HOLDS) == set(SNAPSHOT_IDENTITY_FIELDS)


def repins(pack: dict, index: int) -> list[tuple[str, dict]]:
    """The pack repinned three ways at ``snapshots[index]``: another commit, export, and language."""
    return [(field, {**copy.deepcopy(pack),
                     "snapshots": [{**snapshot, field: value} if position == index else snapshot
                                   for position, snapshot in enumerate(pack["snapshots"])]})
            for field, value in (("commit", "c" * 40), ("tree_hash", "sha256:" + "9" * 64),
                                 ("languages", ["go"]))]


def test_the_anchor_holds_a_snapshot_identity_no_recorded_digest_holds():
    """Two ways a snapshot identity is held by no digest, and the anchor has to hold both.

    A label digest carries the identity of the snapshots that label names, so an identity may leave
    the anchor only where such a digest was recorded and only for a snapshot it names. One
    unreviewed case anywhere in the pack fails the first condition for every snapshot; a snapshot
    the pack declares that no case points at fails the second on its own, however thoroughly the
    rest of the pack is reviewed.

    The first condition is asked of the pack rather than of each snapshot, and deliberately: which
    snapshots a case names is label content, so asking it per snapshot would move a snapshot in and
    out of the anchor whenever a control was pointed elsewhere, and a label edit on an approved
    case would then cost an anchor rebuild. Coarse there anchors an identity some digest does hold.
    Neither condition ever leaves out one no digest holds, which is what the second one fixes: the
    orphan snapshot below had its commit, its export, and its languages inside no record at all.
    """
    pack = maximal_pack()
    assert every_case_binds_its_labels(pack)
    assert snapshots_bound_by_labels(pack) == {"snap-a"}
    anchored(pack)
    pack["snapshots"][0]["commit"] = "b" * 40
    assert pack_anchor_gap(pack) is None, \
        "every case here holds its labels by digest, so a repin costs the approvals, not the anchor"

    # A snapshot the pack declares and no case names, which is what add_snapshot leaves behind
    # until a case is pointed at it. No label digest names it, so no approval lapses when it is
    # repinned, and build_plan and the runner still read its export and its declared languages.
    orphan = anchored(orphan_snapshot_pack())
    assert every_case_binds_its_labels(orphan)
    assert snapshots_bound_by_labels(orphan) == {"snap-a"}, "no case names snap-b"
    for field, candidate in repins(orphan, 1):
        assert "a record a planning decision reads was deleted" in pack_anchor_gap(candidate), \
            f"no digest names snap-b, so its {field} has to be anchored"
    # And snap-a, which a bound case does name, is still subtracted in that same pack.
    assert all(pack_anchor_gap(candidate) is None for _, candidate in repins(orphan, 0))

    draft = copy.deepcopy(pack["cases"][0])
    draft["case_id"] = "widget-path"
    draft["target"] = {**draft["target"], "target_id": "T-widget-path"}
    draft["validation"] = {"level": None, "review_state": "draft", "checks": [], "reviews": []}
    pack["cases"].append(draft)
    assert not every_case_binds_its_labels(pack)
    assert snapshots_bound_by_labels(pack) == frozenset()
    anchored(pack)

    # The second case reads snap-a with no digest behind it, so nothing else records those bytes.
    for field, candidate in repins(pack, 0):
        assert "a record a planning decision reads was deleted" in pack_anchor_gap(candidate), \
            f"an unreviewed case reads these bytes, so {field} has to be anchored"

    # An empty pack is not a pack where every case is bound; it is a pack with nothing to bind.
    assert every_case_binds_its_labels({"cases": []}) is False
    assert snapshots_bound_by_labels({"cases": []}) == frozenset()


def test_every_declared_pack_field_is_anchored_or_allowlisted_with_a_reason():
    """The pack's own fields, by the same rule and against the same kind of hand-written table.

    The three record arrays are projected in their own way and measured by their own tests; every
    other field the contract declares for a pack is anchored whole, down to its leaves, or named in
    the table with a reason.
    """
    schema = case_pack_schema()
    pack = maximal_pack()
    projected = field_paths(pack_anchor_projection(pack))
    record_arrays = {"snapshots", "cases", "admissions"}

    for name, child in schema["properties"].items():
        if name in record_arrays:
            continue
        subtree = {name} | declared_paths(schema, child, name)
        if name in PACK_FIELDS_OUTSIDE_THE_ANCHOR:
            assert is_stated(PACK_FIELDS_OUTSIDE_THE_ANCHOR[name])
            assert subtree & projected == set(), f"{name} is allowlisted and anchored both"
        else:
            assert subtree <= projected, (
                f"pack field {name} is in neither the anchor nor the stated allowlist")
    assert set(PACK_FIELDS_OUTSIDE_THE_ANCHOR) <= set(schema["properties"]), \
        "an allowlist entry for a field the contract no longer declares is a standing excuse"
    assert "review_budgets" in projected, "recall at k is computed at these cut-offs"

    # The record arrays, each by the projection whose own test measures it.
    assert projected >= {"snapshots", "cases"}
    assert (pack_anchor_projection(pack)["cases"]
            == [case_anchor_projection(case) for case in pack["cases"]])
    assert (pack_anchor_projection(pack)["snapshots"]
            == [snapshot_anchor_projection(snapshot, identity_bound=True)
                for snapshot in pack["snapshots"]]), \
        "the one snapshot here is named by a case that binds its labels, so its identity is held"
    assert (pack_anchor_projection(orphan_snapshot_pack())["snapshots"][1]
            == snapshot_anchor_projection(orphan_snapshot_pack()["snapshots"][1])), \
        "and a snapshot no case names is projected whole, because no digest holds its identity"
    assert "admissions" not in projected and "admissions_sha256" in projected, \
        "the admissions are anchored as the chain value their history ends at"


def test_the_snapshot_identity_covers_the_languages_that_decide_which_adapters_run():
    """Re-declaring the languages is a different scan of the same bytes, so the approval lapses."""
    pack, case = case_pack_fragment()
    pack["snapshots"][0]["languages"] = ["python", "go"]
    digest = label_digest(pack, case)
    record_history(case, [{**review(), "labels_sha256": digest}])
    assert covering_review(pack, case) is not None

    # Reordering is not a change: the adapters read the list as a set.
    pack["snapshots"][0]["languages"] = ["go", "python"]
    assert label_digest(pack, case) == digest and covering_review(pack, case) is not None

    for languages in (["python"], ["python", "go", "rust"], []):
        pack["snapshots"][0]["languages"] = languages
        assert label_digest(pack, case) != digest
        assert covering_review(pack, case) is None
        assert effective_level(pack, case) is None


def test_the_label_digest_covers_the_evidence_a_label_rests_on():
    """An allegation at a reviewed level is the allegation together with the evidence under it."""
    pack, case = case_pack_fragment()
    case["evidence"] = [
        {"evidence_id": "ghsa", "origin": "public_advisory_and_maintainer_fix",
         "kind": "ghsa_advisory", "reference": "https://example.invalid/GHSA", "note": "the advisory"},
        {"evidence_id": "fix", "origin": "fix_without_advisory", "kind": "fix_commit",
         "reference": "acme/widget@" + "c" * 40, "note": "the fix"},
    ]
    digest = label_digest(pack, case)
    record_history(case, [{**review(), "labels_sha256": digest}])
    assert covering_review(pack, case) is not None

    # Reordering the records is not a change; the contract keeps their ids unique.
    case["evidence"].reverse()
    assert label_digest(pack, case) == digest and covering_review(pack, case) is not None

    rewritten = copy.deepcopy(case)
    rewritten["evidence"][0]["reference"] = "https://example.invalid/another"
    assert label_digest(pack, rewritten) != digest

    deleted = copy.deepcopy(case)
    del deleted["evidence"][0]
    assert label_digest(pack, deleted) != digest
    assert covering_review(pack, deleted) is None


def test_the_operative_review_rule_is_one_rule_every_gate_reads():
    """A rejection and a reopening are the same answer, and no review at all is an answer too."""
    pack, case = case_pack_fragment()
    assert operative_review_gap(case) == "no review is recorded for this case"

    approval = {**review(), "labels_sha256": label_digest(pack, case)}
    record_history(case, [approval])
    assert operative_review_gap(case) is None

    for decision, reason in (("reject", "rejected this case"),
                             ("unresolved", "reopened the question")):
        record_history(case, [approval, {**review(decision=decision), "labels_sha256": approval["labels_sha256"]}])
        assert reason in operative_review_gap(case)
        assert covering_review(pack, case) is None, "the gate every plan reads asks this one rule"
