"""The evaluation schedule a run freezes before it prepares any input.

Every assignment is listed, including the ones a failed input or a skipped system will never run;
each input carries the plan the pack gave it before execution, or says why it had none; and the
vulnerable/fixed pairs are matched in advance. The same configuration, pack, and moment always give
the same document. Runner-level checks that the schedule is written before preparation live in
``test_v2_runner_inputs.py``.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scaneval import cases
from scaneval.contracts import ContractError, canonical_json, canonical_sha256, validate_document
from scaneval.schedule import SCHEDULE_PATH, build_schedule


CLOCK = lambda: datetime(2026, 9, 20, 17, 0, tzinfo=timezone.utc)  # noqa: E731
CREATED_AT = "2026-09-20T17:00:00+00:00"
HASH = "sha256:" + "b" * 64
FIXED_HASH = "sha256:" + "d" * 64
DIGEST_IMAGE = "ghcr.io/example/scanner@sha256:" + "c" * 64
SNAPSHOT = {
    "snapshot_id": "widget-abc", "repository": {"url": "https://example.invalid/acme/widget.git", "name": "acme/widget"},
    "commit": "a" * 40, "reference": "parent of fix commit", "languages": ["python"],
    "workload": "conventional_application", "component_role": "application",
    "license": {"spdx": "MIT", "verified": False, "note": "not checked"},
}
FIXED_SNAPSHOT = {**SNAPSHOT, "snapshot_id": "widget-fixed", "commit": "e" * 40, "role": "fixed",
                  "reference": "maintainer fix commit"}
REPRESENTS = ("This case tests shell interpolation of a request parameter under a default deployment, "
              "and adds a Python command-injection target.")
SOURCE = "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
REPAIRED = "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=False)\n"


def export(tmp_path: Path, name: str, text: str) -> Path:
    source = tmp_path / name / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text(text, encoding="utf-8")
    return source


def two_snapshot_pack(tmp_path: Path, *, check: bool = True) -> dict:
    """A target on the vulnerable snapshot and its fixed-target control on the repaired one."""
    pack = cases.new_pack("org.example", "schedule", "schedule fixture")
    cases.add_snapshot(pack, SNAPSHOT)
    cases.add_snapshot(pack, FIXED_SNAPSHOT)
    case = cases.draft_case(
        "widget-shell", snapshot_id="widget-abc", kind="command_injection",
        description="cmd reaches subprocess with shell=True", represents=REPRESENTS,
        workload="conventional_application", component_role="application", aliases=[],
        variant_family="shell-interpolation",
        evidence=[cases.evidence("fix", origin="fix_without_advisory", kind="fix_commit",
                                 reference="acme/widget@" + "e" * 40)],
        accepted_locations=[{"path": "src/app.py", "start_line": 3, "end_line": 3, "role": "sink"}])
    case["controls"].append({
        "control_id": "C-widget-shell-fixed", "snapshot_id": "widget-fixed", "type": "fixed_target",
        "target_id": "T-widget-shell", "description": "The repaired call no longer builds a shell string.",
        "property": "The command is passed as an argument list under the same deployment assumptions.",
        "allowed_actors_inputs": "The same callers as the vulnerable snapshot.",
        "assumptions": ["Default deployment."],
        "ruled_out_allegation": "Caller-controlled shell interpolation at this call site.",
        "locations": [{"path": "src/app.py", "start_line": 3, "end_line": 3, "role": "operation"}],
        "evidence_ids": ["fix"],
    })
    cases.add_case(pack, case)
    if check:
        cases.mechanical_checks(pack, "widget-abc", export(tmp_path, "vulnerable", SOURCE), HASH, clock=CLOCK)
        cases.mechanical_checks(pack, "widget-fixed", export(tmp_path, "fixed", REPAIRED), FIXED_HASH, clock=CLOCK)
    return pack


def config(**changes) -> dict:
    document = {
        "schema_version": "2.1", "run_id": "run-schedule", "pack": "pack.json",
        "inputs": [{"snapshot_id": "widget-abc"}, {"snapshot_id": "widget-fixed"}],
        "systems": [{"system_id": "sys-a", "adapter": "fake", "config": {"knob": 1}},
                    {"system_id": "sys-b", "adapter": "fake", "config": {}, "model_id": "vendor/model-x",
                     "network_policy": "model_provider_only"}],
        "repetitions": 2, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none",
    }
    document.update(changes)
    return validate_document("run-config", document)


def test_every_assignment_is_listed_sorted_and_named_by_its_invocation_id(tmp_path):
    pack = two_snapshot_pack(tmp_path)

    schedule = build_schedule(config(), pack, created_at=CREATED_AT)

    assert validate_document("evaluation-schedule", schedule) is schedule
    assert SCHEDULE_PATH == "evaluator/schedule.json"
    assert [row["assignment_id"] for row in schedule["assignments"]] == [
        "widget-abc__sys-a__r1", "widget-abc__sys-a__r2", "widget-abc__sys-b__r1", "widget-abc__sys-b__r2",
        "widget-fixed__sys-a__r1", "widget-fixed__sys-a__r2", "widget-fixed__sys-b__r1",
        "widget-fixed__sys-b__r2"]
    assert schedule["assignments"][0] == {"assignment_id": "widget-abc__sys-a__r1", "input_id": "widget-abc",
                                          "system_id": "sys-a", "repetition": 1}
    assert schedule["repetitions"] == 2 and schedule["run_id"] == "run-schedule"
    assert schedule["created_at"] == CREATED_AT
    assert schedule["config_sha256"] == canonical_sha256(config())
    assert schedule["pack"] == {"namespace": "org.example", "pack_id": "schedule", "version": pack["version"],
                                "sha256": canonical_sha256(pack)}


def test_identical_arguments_give_a_byte_identical_schedule(tmp_path):
    pack = two_snapshot_pack(tmp_path)

    first = build_schedule(config(), pack, created_at=CREATED_AT)
    second = build_schedule(deepcopy(config()), deepcopy(pack), created_at=CREATED_AT)

    assert canonical_json(first) == canonical_json(second)


def test_a_declared_export_freezes_each_inputs_plan_with_its_case_facts(tmp_path):
    pack = two_snapshot_pack(tmp_path)

    schedule = build_schedule(config(), pack, created_at=CREATED_AT)

    vulnerable, fixed = schedule["inputs"]
    assert {key: vulnerable[key] for key in ("input_id", "mode", "profile", "snapshot_id", "change_set_id",
                                             "change_set", "blinding", "project", "workload",
                                             "component_role", "declared_tree_hash")} == {
        "input_id": "widget-abc", "mode": "full", "profile": "standard", "snapshot_id": "widget-abc",
        "change_set_id": None, "change_set": None, "blinding": None, "project": "acme/widget",
        "workload": "conventional_application", "component_role": "application", "declared_tree_hash": HASH}
    plan = vulnerable["plan"]
    assert plan["state"] == "frozen" and plan["scope"] == "draft" and plan["review_budgets"] == [5, 10, 20, 50]
    assert plan["targets"] == [{"target_id": "T-widget-shell", "case_id": "widget-shell",
                                "canonical_id": "T-widget-shell", "kind": "command_injection",
                                "variant_family": "shell-interpolation", "workload": "conventional_application",
                                "component_role": "application", "project": "acme/widget",
                                "validation_level": "L1"}]
    assert plan["controls"] == []
    assert fixed["plan"]["targets"] == []
    assert fixed["plan"]["controls"] == [{"control_id": "C-widget-shell-fixed", "case_id": "widget-shell",
                                          "canonical_id": "C-widget-shell-fixed", "type": "fixed_target",
                                          "target_id": "T-widget-shell", "validation_level": "L1"}]


def test_vulnerable_and_fixed_observations_are_paired_before_execution(tmp_path):
    pack = two_snapshot_pack(tmp_path)

    schedule = build_schedule(config(), pack, created_at=CREATED_AT)

    assert schedule["pairs"] == [{"target_id": "T-widget-shell", "canonical_id": "T-widget-shell",
                                  "vulnerable_input_id": "widget-abc", "control_id": "C-widget-shell-fixed",
                                  "fixed_input_id": "widget-fixed", "repetition_pairs": [[1, 1], [2, 2]]}]
    # Without the fixed input in the run there is nothing to pair the target with.
    alone = build_schedule(config(inputs=[{"snapshot_id": "widget-abc"}]), pack, created_at=CREATED_AT)
    assert alone["pairs"] == []


def test_a_snapshot_that_declares_no_export_has_no_pre_registered_plan(tmp_path):
    pack = two_snapshot_pack(tmp_path, check=False)

    schedule = build_schedule(config(), pack, created_at=CREATED_AT)

    for row in schedule["inputs"]:
        assert row["declared_tree_hash"] is None
        assert row["plan"]["state"] == "unavailable" and "declares no tree hash" in row["plan"]["reason"]
    assert schedule["pairs"] == [], "pairs are matched only between plans frozen before execution"
    assert any("not pre-registered" in note for note in schedule["notes"])
    assert len(schedule["assignments"]) == 8, "an input with no plan is still scheduled"


def test_a_pack_that_refuses_to_plan_an_input_is_recorded_rather_than_raised(tmp_path):
    pack = two_snapshot_pack(tmp_path)
    pack["cases"][0]["disposition"]["reason"] = "edited by hand without a new anchor"

    schedule = build_schedule(config(), pack, created_at=CREATED_AT)

    reasons = [row["plan"]["reason"] for row in schedule["inputs"]]
    assert all(reason.startswith("the pack does not plan this input: this pack does not load") for reason in reasons)
    assert len(schedule["assignments"]) == 8


def test_systems_record_their_configuration_digest_policy_and_declared_backend(tmp_path):
    pack = two_snapshot_pack(tmp_path)
    systems = [{"system_id": "sys-a", "adapter": "fake", "config": {"knob": 1}},
               {"system_id": "sys-oci", "adapter": "semgrep", "config": {},
                "execution": {"backend": "oci", "image": DIGEST_IMAGE}}]

    schedule = build_schedule(config(systems=systems), pack, created_at=CREATED_AT)

    assert schedule["systems"] == [
        {"system_id": "sys-a", "adapter": "fake", "model_id": None, "model_revision": None,
         "config_sha256": canonical_sha256({"knob": 1}), "network_policy": "none",
         "execution": {"backend": "local", "enforced_expected": False, "image": None}},
        {"system_id": "sys-oci", "adapter": "semgrep", "model_id": None, "model_revision": None,
         "config_sha256": canonical_sha256({}), "network_policy": "none",
         "execution": {"backend": "oci", "enforced_expected": True, "image": DIGEST_IMAGE}}]


def test_a_narrowed_run_schedules_only_what_it_covers_and_says_so(tmp_path):
    pack = two_snapshot_pack(tmp_path)
    document = config()

    schedule = build_schedule(document, pack, created_at=CREATED_AT, inputs=document["inputs"][:1],
                              systems=document["systems"][1:])

    assert [row["assignment_id"] for row in schedule["assignments"]] == [
        "widget-abc__sys-b__r1", "widget-abc__sys-b__r2"]
    assert schedule["config_sha256"] == canonical_sha256(document), "the digest is of the whole configuration"
    assert any("1 configured input(s) and 1 configured system(s) are not scheduled" in note
               for note in schedule["notes"])


def test_an_input_this_build_cannot_prepare_is_refused_rather_than_scheduled(tmp_path):
    pack = two_snapshot_pack(tmp_path)

    with pytest.raises(ContractError, match="unknown snapshot 'widget-zzz'"):
        build_schedule(config(inputs=[{"snapshot_id": "widget-zzz"}]), pack, created_at=CREATED_AT)
    with pytest.raises(ContractError, match="native PR input"):
        build_schedule(config(inputs=[{"mode": "pr", "change_set_id": "cs-1"}]), pack, created_at=CREATED_AT)


def test_the_contract_refuses_a_schedule_that_leaves_out_or_misnames_an_assignment(tmp_path):
    schedule = build_schedule(config(), two_snapshot_pack(tmp_path), created_at=CREATED_AT)

    missing = deepcopy(schedule)
    missing["assignments"].pop()
    with pytest.raises(ContractError, match="every input under every system for every repetition"):
        validate_document("evaluation-schedule", missing)
    misnamed = deepcopy(schedule)
    misnamed["assignments"][0]["repetition"] = 2
    with pytest.raises(ContractError, match="misnamed"):
        validate_document("evaluation-schedule", misnamed)
    duplicated = deepcopy(schedule)
    duplicated["inputs"].append(deepcopy(duplicated["inputs"][0]))
    with pytest.raises(ContractError, match="inputs.input_id values must be unique"):
        validate_document("evaluation-schedule", duplicated)


def test_the_contract_refuses_a_pair_the_frozen_plans_do_not_support(tmp_path):
    schedule = build_schedule(config(), two_snapshot_pack(tmp_path), created_at=CREATED_AT)

    same_input = deepcopy(schedule)
    same_input["pairs"][0]["fixed_input_id"] = "widget-abc"
    with pytest.raises(ContractError, match="on one input"):
        validate_document("evaluation-schedule", same_input)
    swapped = deepcopy(schedule)
    swapped["pairs"][0]["vulnerable_input_id"], swapped["pairs"][0]["fixed_input_id"] = "widget-fixed", "widget-abc"
    with pytest.raises(ContractError, match="planned on the vulnerable input"):
        validate_document("evaluation-schedule", swapped)
    beyond = deepcopy(schedule)
    beyond["pairs"][0]["repetition_pairs"].append([3, 3])
    with pytest.raises(ContractError, match="repetitions this schedule declares"):
        validate_document("evaluation-schedule", beyond)
    renamed = deepcopy(schedule)
    renamed["pairs"][0]["canonical_id"] = "something-else"
    with pytest.raises(ContractError, match="canonical_id"):
        validate_document("evaluation-schedule", renamed)


def test_the_contract_ties_a_blinding_identity_to_the_blinded_profile(tmp_path):
    schedule = build_schedule(config(), two_snapshot_pack(tmp_path), created_at=CREATED_AT)

    named = deepcopy(schedule)
    named["inputs"][0]["blinding"] = {"map_id": "m", "map_version": "1", "map_sha256": HASH}
    with pytest.raises(ContractError, match="exactly when the profile is metadata_blinded"):
        validate_document("evaluation-schedule", named)
    unnamed = deepcopy(schedule)
    unnamed["inputs"][0]["profile"] = "metadata_blinded"
    with pytest.raises(ContractError, match="exactly when the profile is metadata_blinded"):
        validate_document("evaluation-schedule", unnamed)
