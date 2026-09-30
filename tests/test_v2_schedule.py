"""The evaluation schedule a run freezes before it prepares any input.

Every assignment is listed, including the ones a failed input or a skipped system will never run;
each input carries the plan the pack gave it before execution, or says why it had none, and a
blinded input names the map it is transformed with; and the vulnerable/fixed pairs are matched in
advance, between full scans of one profile. The same configuration, pack, and moment always give
the same document. Runner-level checks that the schedule is written before preparation live in
``test_v2_runner_inputs.py``.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scaneval import blinding, cases
from scaneval.contracts import ContractError, canonical_json, canonical_sha256, validate_document
from scaneval.schedule import SCHEDULE_PATH, _pairs, build_schedule


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


def blinding_map() -> dict:
    """A map the contract accepts. The schedule records which map it is and never applies it."""
    return validate_document("blinding-map", {
        "schema_version": "2.1", "map_id": "widget-metadata", "map_version": "1",
        "repository": {"url": SNAPSHOT["repository"]["url"], "name": "acme/widget"},
        "pseudonyms": [{"original": "Widget", "replacement": "Sprocket"}],
        "variants": [{"snapshot_id": "widget-abc", "commit": "a" * 40, "tree_hash": HASH},
                     {"snapshot_id": "widget-fixed", "commit": "e" * 40, "tree_hash": FIXED_HASH}],
        "edits": [{"edit_id": "readme", "path": "README.md", "role": "non_runtime_branding",
                   "rationale": "The README names the project in prose.", "replacements": ["Widget"],
                   "expected": [{"snapshot_id": "widget-abc", "state": "present", "file_sha256": HASH,
                                 "occurrences": {"Widget": 1}},
                                {"snapshot_id": "widget-fixed", "state": "absent"}]}],
        "reviews": [],
    })


def test_every_assignment_is_listed_sorted_and_named_by_its_invocation_id(tmp_path):
    pack = two_snapshot_pack(tmp_path)

    schedule = build_schedule(config(), pack, base_dir=tmp_path, created_at=CREATED_AT)

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

    first = build_schedule(config(), pack, base_dir=tmp_path, created_at=CREATED_AT)
    second = build_schedule(deepcopy(config()), deepcopy(pack), base_dir=tmp_path, created_at=CREATED_AT)

    assert canonical_json(first) == canonical_json(second)


def test_a_declared_export_freezes_each_inputs_plan_with_its_case_facts(tmp_path):
    pack = two_snapshot_pack(tmp_path)

    schedule = build_schedule(config(), pack, base_dir=tmp_path, created_at=CREATED_AT)

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

    schedule = build_schedule(config(), pack, base_dir=tmp_path, created_at=CREATED_AT)

    assert schedule["pairs"] == [{"target_id": "T-widget-shell", "canonical_id": "T-widget-shell",
                                  "vulnerable_input_id": "widget-abc", "control_id": "C-widget-shell-fixed",
                                  "fixed_input_id": "widget-fixed", "repetition_pairs": [[1, 1], [2, 2]]}]
    # Without the fixed input in the run there is nothing to pair the target with.
    alone = build_schedule(config(inputs=[{"snapshot_id": "widget-abc"}]), pack, base_dir=tmp_path, created_at=CREATED_AT)
    assert alone["pairs"] == []


def test_a_snapshot_that_declares_no_export_has_no_pre_registered_plan(tmp_path):
    pack = two_snapshot_pack(tmp_path, check=False)

    schedule = build_schedule(config(), pack, base_dir=tmp_path, created_at=CREATED_AT)

    for row in schedule["inputs"]:
        assert row["declared_tree_hash"] is None
        assert row["plan"]["state"] == "unavailable" and "declares no tree hash" in row["plan"]["reason"]
    assert schedule["pairs"] == [], "pairs are matched only between plans frozen before execution"
    assert any("not pre-registered" in note for note in schedule["notes"])
    assert len(schedule["assignments"]) == 8, "an input with no plan is still scheduled"


def test_a_pack_that_refuses_to_plan_an_input_is_recorded_rather_than_raised(tmp_path):
    pack = two_snapshot_pack(tmp_path)
    pack["cases"][0]["disposition"]["reason"] = "edited by hand without a new anchor"

    schedule = build_schedule(config(), pack, base_dir=tmp_path, created_at=CREATED_AT)

    reasons = [row["plan"]["reason"] for row in schedule["inputs"]]
    assert all(reason.startswith("the pack does not plan this input: this pack does not load") for reason in reasons)
    assert len(schedule["assignments"]) == 8


def test_systems_record_their_configuration_digest_policy_and_declared_backend(tmp_path):
    pack = two_snapshot_pack(tmp_path)
    systems = [{"system_id": "sys-a", "adapter": "fake", "config": {"knob": 1}},
               {"system_id": "sys-oci", "adapter": "semgrep", "config": {},
                "execution": {"backend": "oci", "image": DIGEST_IMAGE}}]

    schedule = build_schedule(config(systems=systems), pack, base_dir=tmp_path, created_at=CREATED_AT)

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

    schedule = build_schedule(document, pack, base_dir=tmp_path, created_at=CREATED_AT, inputs=document["inputs"][:1],
                              systems=document["systems"][1:])

    assert [row["assignment_id"] for row in schedule["assignments"]] == [
        "widget-abc__sys-b__r1", "widget-abc__sys-b__r2"]
    assert schedule["config_sha256"] == canonical_sha256(document), "the digest is of the whole configuration"
    assert any("1 configured input(s) and 1 configured system(s) are not scheduled" in note
               for note in schedule["notes"])


def test_an_input_the_pack_does_not_declare_is_refused_rather_than_scheduled(tmp_path):
    """Renamed and changed deliberately: a native PR input is scheduled now, so what is refused is
    a change set, like a snapshot, that the pack does not declare."""
    pack = two_snapshot_pack(tmp_path)

    with pytest.raises(ContractError, match="unknown snapshot 'widget-zzz'"):
        build_schedule(config(inputs=[{"snapshot_id": "widget-zzz"}]), pack, base_dir=tmp_path, created_at=CREATED_AT)
    with pytest.raises(ContractError, match="unknown change set 'cs-1' in pack org.example/schedule; the pack "
                                            "declares: none"):
        build_schedule(config(inputs=[{"mode": "pr", "change_set_id": "cs-1"}]), pack, base_dir=tmp_path, created_at=CREATED_AT)


def test_a_blinded_input_is_scheduled_with_the_identity_of_its_map(tmp_path):
    """The map is named by id, version, and digest; whether it fits the export is asked later."""
    pack = two_snapshot_pack(tmp_path)
    document = blinding_map()
    (tmp_path / "widget-map.json").write_text(canonical_json(document) + "\n", encoding="utf-8")
    inputs = [{"snapshot_id": snapshot_id, "profile": "metadata_blinded", "blinding_map": "widget-map.json"}
              for snapshot_id in ("widget-abc", "widget-fixed")]

    schedule = build_schedule(config(inputs=inputs), pack, base_dir=tmp_path, created_at=CREATED_AT)

    identity = blinding.map_identity(document)
    assert identity["map_sha256"] == canonical_sha256(document)
    assert [(row["input_id"], row["profile"], row["blinding"]) for row in schedule["inputs"]] == [
        ("widget-abc.blinded", "metadata_blinded", identity), ("widget-fixed.blinded", "metadata_blinded", identity)]
    assert [(pair["vulnerable_input_id"], pair["fixed_input_id"]) for pair in schedule["pairs"]] == [
        ("widget-abc.blinded", "widget-fixed.blinded")]
    assert any(note.startswith("A blinded input names the map it is transformed with.") for note in schedule["notes"])
    # A map the caller already loaded is the map recorded: the runner schedules what it applies.
    loaded = {row["input_id"]: document for row in schedule["inputs"]}
    assert build_schedule(config(inputs=inputs), pack, base_dir=tmp_path / "elsewhere", created_at=CREATED_AT,
                          maps=loaded) == schedule
    with pytest.raises(ContractError, match="could not load .*widget-map.json"):
        build_schedule(config(inputs=inputs), pack, base_dir=tmp_path / "elsewhere", created_at=CREATED_AT)
    unnamed = config(schema_version="2.0", inputs=[{"snapshot_id": "widget-abc", "profile": "metadata_blinded"}])
    with pytest.raises(ContractError, match="widget-abc.blinded is metadata_blinded but names no blinding map"):
        build_schedule(unnamed, pack, base_dir=tmp_path, created_at=CREATED_AT)


def test_the_contract_refuses_a_schedule_that_leaves_out_or_misnames_an_assignment(tmp_path):
    schedule = build_schedule(config(), two_snapshot_pack(tmp_path), base_dir=tmp_path, created_at=CREATED_AT)

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
    schedule = build_schedule(config(), two_snapshot_pack(tmp_path), base_dir=tmp_path, created_at=CREATED_AT)

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


def test_a_pair_joins_two_full_scans_of_one_profile_and_nothing_else(tmp_path):
    """No vulnerable/fixed pair of change sets is defined, so neither side makes one up."""
    schedule = build_schedule(config(), two_snapshot_pack(tmp_path), base_dir=tmp_path, created_at=CREATED_AT)

    reviewed = deepcopy(schedule)
    for row in reviewed["inputs"]:
        # Changed deliberately: a PR input now carries its change set block and a scope on every
        # planned item, so these rows are made whole PR inputs, frozen plans included. That keeps
        # what the assertions below are about: the builder skips them because they are PR inputs,
        # not because they lack a plan, and the contract still refuses to pair them.
        row.update(mode="pr", change_set_id=f"cs-{row['input_id']}",
                   change_set={"change_set_id": f"cs-{row['input_id']}", "base_snapshot_id": "widget-base",
                               "head_snapshot_id": row["snapshot_id"], "boundary": "introducing",
                               "review_scope": "changed_files"})
        for item in row["plan"]["targets"] + row["plan"]["controls"]:
            item["pr_scope"] = {"relation": "introduced", "code_scope": "changed"}
    assert all(row["plan"]["state"] == "frozen" for row in reviewed["inputs"])
    assert _pairs(reviewed["inputs"], schedule["repetitions"]) == [], "the builder pairs no PR inputs"
    with pytest.raises(ContractError, match="two full-scan inputs"):
        validate_document("evaluation-schedule", reviewed)
    mixed = deepcopy(schedule)
    mixed["inputs"][1].update(profile="metadata_blinded",
                              blinding={"map_id": "m", "map_version": "1", "map_sha256": HASH})
    assert _pairs(mixed["inputs"], schedule["repetitions"]) == [], "the builder pairs within one profile"
    with pytest.raises(ContractError, match="inputs of one profile"):
        validate_document("evaluation-schedule", mixed)


def test_the_contract_ties_a_blinding_identity_to_the_blinded_profile(tmp_path):
    schedule = build_schedule(config(), two_snapshot_pack(tmp_path), base_dir=tmp_path, created_at=CREATED_AT)

    named = deepcopy(schedule)
    named["inputs"][0]["blinding"] = {"map_id": "m", "map_version": "1", "map_sha256": HASH}
    with pytest.raises(ContractError, match="exactly when the profile is metadata_blinded"):
        validate_document("evaluation-schedule", named)
    unnamed = deepcopy(schedule)
    unnamed["inputs"][0]["profile"] = "metadata_blinded"
    with pytest.raises(ContractError, match="exactly when the profile is metadata_blinded"):
        validate_document("evaluation-schedule", unnamed)


# --- native PR inputs: the change set and the eligibility are frozen before anything is exported ----

BASE_HASH = "sha256:" + "a" * 64
BASE_SNAPSHOT = {**SNAPSHOT, "snapshot_id": "widget-base", "commit": "1" * 40, "role": "ordinary",
                 "reference": "the commit the pull request branched from"}
BASE_SOURCE = "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd)\n"


def pr_pack(tmp_path: Path, *, declare_base: bool = True) -> dict:
    """The two-snapshot pack plus a base snapshot and a change set from it to the vulnerable head.

    The target is on the head and eligible under ``cs-shell``; the fixed-target control is on
    another snapshot, so the contract cannot make it eligible and the frozen plan carries no control.
    """
    pack = two_snapshot_pack(tmp_path)
    cases.add_snapshot(pack, BASE_SNAPSHOT)
    if declare_base:
        cases.mechanical_checks(pack, "widget-base", export(tmp_path, "base", BASE_SOURCE), BASE_HASH, clock=CLOCK)
    cases.add_change_set(pack, {"change_set_id": "cs-shell", "base_snapshot_id": "widget-base",
                                "head_snapshot_id": "widget-abc", "boundary": "introducing",
                                "review_scope": "changed_files", "description": "adds the shell sink",
                                "reference": "acme/widget#7"})
    cases.set_pr_eligibility(pack, "widget-shell", "cs-shell", "introduced", "changed")
    return pack


def pr_config(**changes) -> dict:
    return config(inputs=[{"mode": "pr", "change_set_id": "cs-shell"}], **changes)


def test_a_pr_input_is_scheduled_as_the_review_of_its_change_set_with_the_eligibility_frozen(tmp_path):
    pack = pr_pack(tmp_path)

    schedule = build_schedule(pr_config(), pack, base_dir=tmp_path, created_at=CREATED_AT)

    assert validate_document("evaluation-schedule", schedule) is schedule
    [row] = schedule["inputs"]
    assert (row["input_id"], row["mode"], row["profile"]) == ("cs-shell", "pr", "standard")
    assert row["snapshot_id"] == "widget-abc" and row["change_set_id"] == "cs-shell"
    assert row["change_set"] == {"change_set_id": "cs-shell", "base_snapshot_id": "widget-base",
                                 "head_snapshot_id": "widget-abc", "boundary": "introducing",
                                 "review_scope": "changed_files"}, "the reference and description stay in the pack"
    assert row["declared_tree_hash"] == HASH and row["project"] == "acme/widget"
    plan = row["plan"]
    assert plan["state"] == "frozen" and plan["scope"] == "draft"
    assert plan["review_budgets"] == [5, 10, 20], "a PR review is budgeted by the pack's pr budgets"
    assert plan["targets"] == [{
        "target_id": "T-widget-shell", "case_id": "widget-shell", "canonical_id": "T-widget-shell",
        "kind": "command_injection", "variant_family": "shell-interpolation",
        "workload": "conventional_application", "component_role": "application", "project": "acme/widget",
        "validation_level": "L1", "pr_scope": {"relation": "introduced", "code_scope": "changed"}}]
    assert plan["controls"] == [], "the fixed control is on another snapshot, so it is outside the review"
    assert plan["notes"] == [], "every item of the head snapshot is eligible, so nothing is named as outside"
    assert [a["assignment_id"] for a in schedule["assignments"]] == [
        "cs-shell__sys-a__r1", "cs-shell__sys-a__r2", "cs-shell__sys-b__r1", "cs-shell__sys-b__r2"]
    assert schedule["pairs"] == [], "no pair of PR inputs is defined"
    assert any(note.startswith("A PR input's plan is frozen from the eligibility the pack states") for note in
               schedule["notes"])


def test_the_pr_eligibility_frozen_before_a_run_is_the_pack_as_supplied_and_byte_stable(tmp_path):
    pack = pr_pack(tmp_path)

    first = build_schedule(pr_config(), pack, base_dir=tmp_path, created_at=CREATED_AT)
    second = build_schedule(deepcopy(pr_config()), deepcopy(pack), base_dir=tmp_path, created_at=CREATED_AT)
    assert canonical_json(first) == canonical_json(second)

    # Widening the eligibility in the pack is a different schedule; nothing the run finds later can be.
    widened = deepcopy(pack)
    cases.set_pr_eligibility(widened, "widget-shell", "cs-shell", "affected", "context")
    other = build_schedule(pr_config(), widened, base_dir=tmp_path, created_at=CREATED_AT)
    assert other["inputs"][0]["plan"]["targets"][0]["pr_scope"] == {"relation": "affected", "code_scope": "context"}
    assert other["pack"]["sha256"] != first["pack"]["sha256"]


def test_a_pr_plan_is_unavailable_until_both_snapshots_declare_their_exports(tmp_path):
    pack = pr_pack(tmp_path, declare_base=False)

    [row] = build_schedule(pr_config(), pack, base_dir=tmp_path, created_at=CREATED_AT)["inputs"]

    assert row["plan"]["state"] == "unavailable"
    assert row["plan"]["reason"].startswith(
        "snapshot widget-base declares no tree hash, so no PR plan binds to the exports of its change set")
    assert row["declared_tree_hash"] == HASH and row["change_set"]["change_set_id"] == "cs-shell"
    schedule = build_schedule(pr_config(), pack, base_dir=tmp_path, created_at=CREATED_AT)
    assert any("planned from the checked pack when its invocations run" in note for note in schedule["notes"])


def test_a_pr_input_of_an_undeclared_change_set_is_refused_and_a_narrowed_run_schedules_only_what_it_covers(tmp_path):
    pack = pr_pack(tmp_path)
    document = config(inputs=[{"snapshot_id": "widget-abc"}, {"mode": "pr", "change_set_id": "cs-shell"}])

    with pytest.raises(ContractError, match="unknown change set 'cs-missing'"):
        build_schedule(config(inputs=[{"mode": "pr", "change_set_id": "cs-missing"}]), pack,
                       base_dir=tmp_path, created_at=CREATED_AT)
    narrowed = build_schedule(document, pack, base_dir=tmp_path, created_at=CREATED_AT,
                              inputs=[document["inputs"][1]])
    assert [row["input_id"] for row in narrowed["inputs"]] == ["cs-shell"]
    assert any("1 configured input(s) and 0 configured system(s) are not scheduled" in n for n in narrowed["notes"])


def test_a_pr_input_never_takes_part_in_a_vulnerable_fixed_pair(tmp_path):
    pack = pr_pack(tmp_path)
    document = config(inputs=[{"snapshot_id": "widget-abc"}, {"snapshot_id": "widget-fixed"},
                              {"mode": "pr", "change_set_id": "cs-shell"}])

    schedule = build_schedule(document, pack, base_dir=tmp_path, created_at=CREATED_AT)

    assert [(pair["vulnerable_input_id"], pair["fixed_input_id"]) for pair in schedule["pairs"]] == [
        ("widget-abc", "widget-fixed")]
    assert [row["input_id"] for row in schedule["inputs"]] == ["widget-abc", "widget-fixed", "cs-shell"]
    assert schedule["inputs"][0]["change_set"] is None and "pr_scope" not in schedule["inputs"][0]["plan"]["targets"][0]


def test_a_blinded_pr_input_is_scheduled_under_its_own_id_with_the_identity_of_its_map(tmp_path):
    pack = pr_pack(tmp_path)
    document = blinding_map()
    (tmp_path / "widget-map.json").write_text(canonical_json(document) + "\n", encoding="utf-8")
    inputs = [{"mode": "pr", "change_set_id": "cs-shell", "profile": "metadata_blinded",
               "blinding_map": "widget-map.json"}]

    [row] = build_schedule(config(inputs=inputs), pack, base_dir=tmp_path, created_at=CREATED_AT)["inputs"]

    assert (row["input_id"], row["profile"], row["blinding"]) == (
        "cs-shell.blinded", "metadata_blinded", blinding.map_identity(document))
    assert row["mode"] == "pr" and row["change_set_id"] == "cs-shell"


def test_the_contract_ties_a_pr_input_to_its_change_set_and_to_a_scope_on_every_item(tmp_path):
    schedule = build_schedule(pr_config(), pr_pack(tmp_path), base_dir=tmp_path, created_at=CREATED_AT)
    assert validate_document("evaluation-schedule", schedule) is schedule

    bare = deepcopy(schedule)
    bare["inputs"][0]["change_set"] = None
    with pytest.raises(ContractError, match="a pr input carries the frozen identity of its change set"):
        validate_document("evaluation-schedule", bare)
    other_set = deepcopy(schedule)
    other_set["inputs"][0]["change_set"]["change_set_id"] = "cs-other"
    with pytest.raises(ContractError, match="the change set it names, ending at the snapshot the input reads"):
        validate_document("evaluation-schedule", other_set)
    not_the_head = deepcopy(schedule)
    not_the_head["inputs"][0]["change_set"]["head_snapshot_id"] = "widget-base"
    with pytest.raises(ContractError, match="ending at the snapshot the input reads"):
        validate_document("evaluation-schedule", not_the_head)
    unscoped = deepcopy(schedule)
    del unscoped["inputs"][0]["plan"]["targets"][0]["pr_scope"]
    with pytest.raises(ContractError, match="every item of a frozen pr plan states its pr_scope"):
        validate_document("evaluation-schedule", unscoped)
    stray = build_schedule(config(), two_snapshot_pack(tmp_path / "again"), base_dir=tmp_path, created_at=CREATED_AT)
    stray["inputs"][0]["plan"]["targets"][0]["pr_scope"] = {"relation": "introduced", "code_scope": "changed"}
    with pytest.raises(ContractError, match="only a pr input's frozen plan carries pr_scope"):
        validate_document("evaluation-schedule", stray)
    loose = deepcopy(schedule)
    loose["inputs"][0]["change_set"]["extra"] = "field"
    with pytest.raises(ContractError, match="extra"):
        validate_document("evaluation-schedule", loose)
