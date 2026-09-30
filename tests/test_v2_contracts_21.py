"""Protocol 2.1: the optional fields later phases write, and the rules that keep them honest.

Every 2.0 document still validates against its 2.0 schema exactly as before; these tests hold the
2.1 variants to the shape rules the runner, the PR planner, the SARIF importer, and the isolation
backend all depend on.
"""

from __future__ import annotations

from copy import deepcopy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scaneval import cases, contracts
from scaneval.contracts import (
    ContractError,
    canonical_sha256,
    input_identity,
    label_digest,
    pr_diff_sha256,
    pr_input_hash,
    validate_document,
)


HASH = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
DIGEST = "sha256:" + "e" * 64
DIGEST_IMAGE = "ghcr.io/example/scanner@sha256:" + "c" * 64
PROXY_IMAGE = "python@sha256:" + "d" * 64


def run_config(**changes) -> dict:
    document = {
        "schema_version": "2.1", "run_id": "run-21", "pack": "pack.json",
        "inputs": [{"snapshot_id": "snap-a"}],
        "systems": [{"system_id": "sys-a", "adapter": "fake", "config": {}}],
        "repetitions": 1, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none",
    }
    document.update(changes)
    return document


def test_a_standard_and_a_blinded_input_of_one_snapshot_have_distinct_default_ids():
    inputs = [{"snapshot_id": "snap-a"},
              {"snapshot_id": "snap-a", "profile": "metadata_blinded", "blinding_map": "map.json"},
              {"mode": "pr", "change_set_id": "cs-1"}]
    validate_document("run-config", run_config(inputs=inputs))
    assert [input_identity(item) for item in inputs] == ["snap-a", "snap-a.blinded", "cs-1"]
    with pytest.raises(ContractError, match="input id values must be unique"):
        validate_document("run-config", run_config(inputs=[{"snapshot_id": "snap-a"},
                                                           {"snapshot_id": "snap-b", "input_id": "snap-a"}]))


@pytest.mark.parametrize("entry,message", [
    ({"mode": "pr", "snapshot_id": "snap-a"}, "a pr input names a change_set_id"),
    ({"snapshot_id": "snap-a", "change_set_id": "cs-1"}, "a full input names a snapshot_id and no change_set_id"),
    ({"snapshot_id": "snap-a", "profile": "metadata_blinded"}, "blinding_map is required"),
    ({"snapshot_id": "snap-a", "blinding_map": "map.json"}, "blinding_map is required"),
])
def test_an_input_says_exactly_one_thing(entry, message):
    with pytest.raises(ContractError, match=message):
        validate_document("run-config", run_config(inputs=[entry]))


def test_an_oci_backend_needs_pinned_images_and_declared_egress_for_a_provider_policy():
    def system(execution, policy="none"):
        return run_config(systems=[{"system_id": "sys-a", "adapter": "fake", "config": {},
                                    "network_policy": policy, "execution": execution}])

    validate_document("run-config", system({"backend": "oci", "image": DIGEST_IMAGE}))
    validate_document("run-config", system({"backend": "oci", "image": DIGEST_IMAGE, "proxy_image": PROXY_IMAGE,
                                            "egress": [{"host": "api.example.test", "port": 443}]},
                                           policy="model_provider_only"))
    with pytest.raises(ContractError, match="pinned by digest"):
        validate_document("run-config", system({"backend": "oci", "image": "python:3.13-slim"}))
    with pytest.raises(ContractError, match="egress it allows"):
        validate_document("run-config", system({"backend": "oci", "image": DIGEST_IMAGE},
                                               policy="model_provider_only"))
    with pytest.raises(ContractError, match="only to model_provider_only"):
        validate_document("run-config", system({"backend": "oci", "image": DIGEST_IMAGE,
                                                "egress": [{"host": "x", "port": 1}]}))
    with pytest.raises(ContractError, match="local backend enforces nothing"):
        validate_document("run-config", system({"backend": "local", "image": DIGEST_IMAGE}))


def test_a_2_0_run_config_is_read_exactly_as_before():
    document = run_config(schema_version="2.0")
    validate_document("run-config", document)
    with pytest.raises(ContractError):
        validate_document("run-config", run_config(schema_version="2.0",
                                                   inputs=[{"snapshot_id": "a", "mode": "full"}]))


def scan_result(version: str, **usage) -> dict:
    return {"schema_version": version, "run_id": "r", "system_id": "s", "input_hash": HASH,
            "status": "success", "ranking": "unranked", "claims": [], "bundles_resolved": True,
            "usage": {"wall_seconds": 1, **usage}}


def test_unknown_wall_time_is_null_in_2_1_and_still_refused_in_2_0():
    validate_document("scan-result", {**scan_result("2.1", wall_seconds=None), "location_basis": "pr_head"})
    with pytest.raises(ContractError):
        validate_document("scan-result", scan_result("2.0", wall_seconds=None))
    with pytest.raises(ContractError):
        validate_document("scan-result", {**scan_result("2.0"), "location_basis": "pr_head"})


def plan(mode: str = "full", **provenance) -> dict:
    return {"schema_version": "2.1", "input_hash": HASH, "scope": "draft",
            "targets": [{"target_id": "T1", "description": "d", "validation_level": "L1"}],
            "controls": [], "review_budgets": [5],
            "provenance": {"namespace": "n", "pack_id": "p", "pack_version": "1", "pack_sha256": HASH,
                           "snapshot_id": "snap-a", "mode": mode, **provenance}}


PR = {"change_set_id": "cs-1", "base_snapshot_id": "base", "head_snapshot_id": "snap-a",
      "base_tree_hash": HASH, "head_tree_hash": OTHER, "diff_sha256": HASH, "boundary": "introducing",
      "review_scope": "changed_files", "location_basis": "pr_head"}


def test_a_pr_plan_states_its_boundary_and_the_scope_of_every_item():
    document = plan("pr", pr=PR)
    document["targets"][0]["pr_scope"] = {"relation": "introduced", "code_scope": "changed"}
    validate_document("evaluation-plan", document)
    missing = deepcopy(document)
    del missing["targets"][0]["pr_scope"]
    with pytest.raises(ContractError, match="every item of a pr plan states its pr_scope"):
        validate_document("evaluation-plan", missing)
    with pytest.raises(ContractError, match="provenance.pr is required exactly"):
        validate_document("evaluation-plan", plan("pr"))
    scoped_full = plan()
    scoped_full["targets"][0]["pr_scope"] = {"relation": "introduced", "code_scope": "changed"}
    with pytest.raises(ContractError, match="only a pr plan carries pr_scope"):
        validate_document("evaluation-plan", scoped_full)
    with pytest.raises(ContractError, match="blinding is required exactly"):
        validate_document("evaluation-plan", plan(profile="metadata_blinded"))


def execution_record(**changes) -> dict:
    document = {
        "schema_version": "2.1", "run_id": "r", "invocation_id": "i", "input_id": "snap-a", "system_id": "s",
        "repetition": 1, "adapter": {"name": "fake", "version": "1"}, "versions": {}, "status": "success",
        "exit_code": 0, "timed_out": False, "command": [], "started_at": "t", "finished_at": "t",
        "wall_seconds": 1, "timeout_seconds": 60, "tool_versions": {}, "model_identity": None,
        "system_config": {}, "network_policy": {"declared": "none", "enforced": False, "note": ""},
        "environment": {"passthrough": []}, "capture": {}, "trace": None,
        "provenance": {"tree_hash": HASH, "provenance_sha256": HASH, "profile": "standard",
                       "synthetic_history": None, "source_modified": False, "modified_paths": [],
                       "captured_state_dirs": [], "input_hash": HASH, "mode": "full", "pr": None,
                       "blinding": None},
        "preparation": {}, "unsupported_languages": [], "error": None, "import_error": None, "notes": [],
        "raw_artifacts": [],
        "isolation": {"backend": "local", "enforced": False, "note": "not enforced"},
    }
    document.update(changes)
    return document


def test_enforcement_is_recorded_only_behind_an_enforcing_backend():
    validate_document("execution-record", execution_record())
    with pytest.raises(ContractError, match="local backend enforces nothing"):
        validate_document("execution-record", execution_record(
            isolation={"backend": "local", "enforced": True, "note": ""}))
    with pytest.raises(ContractError, match="only inside an enforced isolation backend"):
        validate_document("execution-record", execution_record(
            network_policy={"declared": "none", "enforced": True, "note": ""}))
    validate_document("execution-record", execution_record(
        isolation={"backend": "oci", "enforced": True, "note": "container"},
        network_policy={"declared": "none", "enforced": True, "note": "network none"}))
    record = execution_record()
    record["provenance"]["mode"] = "pr"
    with pytest.raises(ContractError, match="provenance.pr is recorded exactly"):
        validate_document("execution-record", record)


def manifest(**changes) -> dict:
    document = {
        "schema_version": "2.1", "run_id": "r", "status": "completed", "created_at": "t",
        "config_sha256": HASH, "schedule_path": "evaluator/schedule.json",
        "pack": {"namespace": "n", "pack_id": "p", "version": "1", "status": "draft", "snapshots": 1,
                 "cases": 0, "review_states": {"draft": 0, "mechanically_checked": 0, "human_approved": 0},
                 "dispositions": {"validate": 0, "needs_evidence": 0, "extended_regression": 0, "exclude": 0},
                 "sha256": HASH},
        "selection": {"only_inputs": None, "only_systems": None, "excluded_inputs": [], "excluded_systems": []},
        "inputs": [{"input_id": "snap-a", "mode": "full", "profile": "standard", "snapshot_id": "snap-a",
                    "tree_hash": None, "input_hash": None, "provenance_path": None, "mechanical_checks": [],
                    "preparation_failure": {"type": "MaterializationError", "message": "fetch failed"}}],
        "systems": [], "invocations": [], "warnings": [],
    }
    document.update(changes)
    return document


def test_an_input_that_was_never_prepared_has_only_skipped_invocations():
    row = {"invocation_id": "snap-a__s__r1", "input_id": "snap-a", "system_id": "s", "repetition": 1,
           "status": "skipped", "claim_records": None, "plan_scope": None, "targets_assigned": None,
           "targets_detected": None, "pending_matching_count": None, "bundle_path": None,
           "review_state": None, "skipped_reason": "input snap-a could not be prepared"}
    validate_document("run-manifest", manifest(invocations=[row]))
    ran = {**row, "status": "success", "bundle_path": "invocations/x", "skipped_reason": None}
    with pytest.raises(ContractError, match="was never prepared"):
        validate_document("run-manifest", manifest(invocations=[ran]))


def pr_pack() -> dict:
    """A 2.1 pack with a base and a head snapshot of one repository and one draft case on the head."""
    pack = cases.new_pack("org.example", "pr-pack", "fixture")
    for snapshot_id, commit in (("base", "1" * 40), ("head", "2" * 40)):
        cases.add_snapshot(pack, {
            "snapshot_id": snapshot_id, "repository": {"url": "https://example.test/repo.git", "name": "repo"},
            "commit": commit, "languages": ["python"], "workload": "conventional_application",
            "component_role": "application", "reference": "fixture",
            "license": {"spdx": None, "verified": False, "note": "fixture"}})
    cases.add_case(pack, cases.draft_case(
        "case-a", snapshot_id="head", kind="command_injection", description="shell built from input",
        represents="This case tests a shell sink under fixture assumptions, and adds a fixture.",
        workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("e", origin="diagnostic_fixture", kind="other", reference="fixture")],
        accepted_locations=[{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "sink"}]))
    pack["schema_version"] = "2.1"
    pack["change_sets"] = [{"change_set_id": "cs-1", "base_snapshot_id": "base", "head_snapshot_id": "head",
                            "boundary": "introducing", "review_scope": "changed_files",
                            "description": "introduces the shell sink"}]
    pack["anchor_sha256"] = contracts.pack_anchor_digest(pack)
    return validate_document("case-pack", pack)


def reanchor(pack: dict) -> dict:
    pack["anchor_sha256"] = contracts.pack_anchor_digest(pack)
    return pack


def test_a_change_set_runs_between_two_declared_snapshots_of_one_repository():
    pack = pr_pack()
    broken = deepcopy(pack)
    broken["change_sets"][0]["base_snapshot_id"] = "head"
    with pytest.raises(ContractError, match="base and head must be different"):
        validate_document("case-pack", reanchor(broken))
    broken = deepcopy(pack)
    broken["snapshots"][0]["repository"]["url"] = "https://example.test/other.git"
    with pytest.raises(ContractError, match="different repositories"):
        validate_document("case-pack", reanchor(broken))
    broken = deepcopy(pack)
    broken["change_sets"][0]["head_snapshot_id"] = "missing"
    with pytest.raises(ContractError, match="is not declared"):
        validate_document("case-pack", reanchor(broken))


def test_pr_eligibility_is_a_label_on_the_head_snapshot_that_a_change_set_digest_covers():
    pack = pr_pack()
    case = pack["cases"][0]
    before = label_digest(pack, case)
    case["target"]["pr_eligibility"] = [{"change_set_id": "cs-1", "relation": "introduced",
                                         "code_scope": "changed"}]
    validate_document("case-pack", reanchor(pack))
    with_eligibility = label_digest(pack, case)
    assert with_eligibility != before
    # Editing the boundary the label names changes what an approval covered.
    pack["change_sets"][0]["review_scope"] = "change_affected_flow"
    assert label_digest(pack, case) != with_eligibility
    wrong = deepcopy(pack)
    wrong["cases"][0]["target"]["pr_eligibility"][0]["change_set_id"] = "cs-missing"
    with pytest.raises(ContractError, match="does not declare"):
        validate_document("case-pack", reanchor(wrong))
    repaired = deepcopy(pack)
    repaired["cases"][0]["target"]["pr_eligibility"][0]["relation"] = "repaired"
    with pytest.raises(ContractError, match="never repaired"):
        validate_document("case-pack", reanchor(repaired))


def test_a_case_naming_no_change_set_keeps_the_label_digest_it_always_had():
    """Recorded approvals stay applicable: the change-set key is added only where one is named."""
    pack = pr_pack()
    case = pack["cases"][0]
    assert "change_sets" not in contracts._label_projection(pack, case)
    as_2_0 = deepcopy(pack)
    as_2_0["schema_version"] = "2.0"
    del as_2_0["change_sets"]
    assert label_digest(as_2_0, as_2_0["cases"][0]) == label_digest(pack, case)


def test_the_pr_identity_hashes_are_canonical_and_move_with_every_part_of_the_trio():
    changes = {"added": ["a.py"], "deleted": [], "modified": [], "renamed": [], "mode_changed": []}
    digest = pr_diff_sha256(OTHER, HASH, changes)

    assert digest == canonical_sha256({"base_tree_hash": OTHER, "head_tree_hash": HASH, "changes": changes})
    assert pr_diff_sha256(OTHER, HASH, dict(reversed(list(changes.items())))) == digest
    assert len({digest, pr_diff_sha256(HASH, OTHER, changes),
                pr_diff_sha256(OTHER, HASH, {**changes, "added": ["b.py"]})}) == 3
    identity = pr_input_hash(OTHER, HASH, digest)
    assert identity == canonical_sha256({"mode": "pr", "base_tree_hash": OTHER, "head_tree_hash": HASH,
                                         "diff_sha256": digest})
    assert len({identity, pr_input_hash(HASH, OTHER, digest), pr_input_hash(OTHER, HASH, DIGEST),
                pr_input_hash(OTHER, OTHER, digest)}) == 4
    assert identity not in (OTHER, HASH, digest), "a PR input is never identified by one of its trees"
