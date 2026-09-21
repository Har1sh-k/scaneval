from __future__ import annotations

import copy
from importlib.resources import files
import json
import sys

from jsonschema import Draft202012Validator
import pytest

from scaneval.contracts import (
    CASE_LABEL_FIELDS,
    CASE_UNREAD_FIELDS,
    ContractError,
    PACK_UNANCHORED_FIELDS,
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
    is_stated,
    label_digest,
    level_gap,
    load_document,
    operative_review_gap,
    pack_anchor_digest,
    pack_anchor_gap,
    pack_anchor_projection,
    recorded_check_state,
    review_chain_digest,
    review_chain_gap,
    snapshot_anchor_projection,
    snapshot_identity_projection,
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
    remember to extend. It is the whole case minus its labels and minus a stated allowlist now, so
    the review head is in it because the validation block is, and so is every other field nothing
    else covers.
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
    assert all("target" not in entry and "controls" not in entry for entry in projected), \
        "the labels are bound to the review that covered them, not to the anchor"

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


def declared_paths(schema: dict, node: dict, prefix: str = "") -> set[str]:
    """Every field path the schema declares under *node*, in the shape :func:`field_paths` writes.

    References are resolved, ``oneOf`` and ``anyOf`` branches contribute all of their fields, array
    items contribute under ``[]``, and an object whose values are a schema, which is how a
    free-keyed map is declared, contributes under ``{}``.
    """
    while "$ref" in node:
        target = schema
        for part in node["$ref"].removeprefix("#/").split("/"):
            target = target[part]
        node = target
    paths: set[str] = set()
    for key, child in node.get("properties", {}).items():
        here = f"{prefix}.{key}" if prefix else key
        paths.add(here)
        paths |= declared_paths(schema, child, here)
    if isinstance(node.get("items"), dict):
        paths |= declared_paths(schema, node["items"], f"{prefix}[]")
    for branch in list(node.get("oneOf", [])) + list(node.get("anyOf", [])):
        paths |= declared_paths(schema, branch, prefix)
    extra = node.get("additionalProperties")
    if isinstance(extra, dict):
        paths |= declared_paths(schema, extra, f"{prefix}.{{}}" if prefix else "{}")
    return paths


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


def test_every_case_field_is_projected_or_allowlisted():
    """Every field of a case is in the label digest, in the anchor, or in the stated allowlist.

    This is the rule, rather than a list of fields anyone has to remember to extend: a field that
    affects a planning decision must be inside something a decision is bound to. The two
    projections are defined by subtraction, so a field added to the contract lands in the anchor by
    default, and this holds that true from the other side: the union of the two projections and the
    allowlist is the whole case record, down to the leaves, and nothing is in two of them.

    A field added later and quietly left out of both would fail here, which is the point: the last
    two rounds each closed one escaped field, the mechanical check record and the screening
    disposition, by naming it.
    """
    schema = case_pack_schema()
    case = maximal_pack()["cases"][0]
    declared = declared_paths(schema, schema["$defs"]["case"])
    assert declared - field_paths(case) == set()

    labelled = field_paths(case_label_projection(case))
    anchored_paths = field_paths(case_anchor_projection(case))
    allowlisted = {path for path in field_paths(case)
                   if path.split(".")[0].split("[")[0] in CASE_UNREAD_FIELDS}

    assert field_paths(case) == labelled | anchored_paths | allowlisted
    assert labelled & anchored_paths == set(), "a field in both records is two records of one fact"
    assert allowlisted & (labelled | anchored_paths) == set()
    # The allowlist is small enough to state, and stating it is what makes adding to it a decision.
    assert CASE_UNREAD_FIELDS == {"notes"}
    assert allowlisted == {"notes"}
    # The split itself, so a projection that covered everything by covering the whole record would
    # not pass: the labels are bound to the review that read them, the rest to the anchor. Moving a
    # field from one to the other changes what an approval covers, so it is stated here too.
    assert {path for path in labelled if "." not in path and "[" not in path} == CASE_LABEL_FIELDS
    assert {"target", "controls", "evidence", "represents"} <= CASE_LABEL_FIELDS
    assert {"disposition", "validation", "disclosure", "split", "case_id"} <= anchored_paths
    assert "validation.check_sets.{}.result" in anchored_paths
    assert "validation.checks_failed" in anchored_paths
    assert "validation.reviews_sha256" in anchored_paths


def test_every_snapshot_and_pack_field_is_projected_or_allowlisted():
    """The same rule one level up, for a snapshot and for the pack's own fields.

    A snapshot is split the same way: the identity a label points at travels in the label digest,
    and everything else is anchored. The pack's own fields are anchored except the ones every plan
    already binds by hashing the whole file it was built from.
    """
    schema = case_pack_schema()
    pack = maximal_pack()
    snapshot = pack["snapshots"][0]

    declared = declared_paths(schema, schema["$defs"]["snapshot"])
    assert declared - field_paths(snapshot) == set()
    identity = field_paths(snapshot_identity_projection(snapshot))
    anchored_paths = field_paths(snapshot_anchor_projection(snapshot))
    assert field_paths(snapshot) == identity | anchored_paths
    assert identity & anchored_paths == set()
    assert SNAPSHOT_UNREAD_FIELDS == frozenset(), "nothing about a snapshot goes unread"
    assert identity == set(SNAPSHOT_IDENTITY_FIELDS) == {"commit", "tree_hash", "languages"}

    projection = pack_anchor_projection(pack)
    for name in schema["properties"]:
        covered = (name in PACK_UNANCHORED_FIELDS or name in projection
                   or (name == "admissions" and "admissions_sha256" in projection))
        assert covered, f"pack field {name} is in neither the anchor nor the stated allowlist"
    assert "review_budgets" in projection, "recall at k is computed at these cut-offs"
    assert PACK_UNANCHORED_FIELDS == {"anchor_sha256", "description", "notes", "schema_version",
                                      "namespace", "pack_id", "version", "status"}


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
