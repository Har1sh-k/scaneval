"""Corpus aggregation over frozen run directories, checked against numbers calculated by hand.

Every fixture is a run directory built in ``tmp_path`` by the helpers below: a hand-built schedule
that validates as ``evaluation-schedule``, a 2.1 run manifest, the run's configuration, and one
invocation bundle per assignment holding ``result.json``, ``execution.json``, and the evaluator's
plan, decisions, and review record. Reviewed evidence is approved through :mod:`scaneval.review` by
a reviewer who is explicitly fictional, so every binding is the real one. No scanner runs, and every
expected number is worked out in the test's docstring.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from scaneval import aggregate, cases, review, schedule
from scaneval.adapters.base import Adapter, NativeOutcome
from scaneval.contracts import ContractError, canonical_json, canonical_sha256, validate_document
from scaneval.resampling import Stream, resample_with_replacement
from scaneval.runner import run_from_config


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
CREATED_AT = "2026-09-20T15:00:00+00:00"
REVIEWER = "Fixture Reviewer (fictional)"
WORKLOAD = "conventional_application"
PACK = {"namespace": "org.example", "pack_id": "aggregate-fixture", "version": "1.0.0",
        "sha256": "sha256:" + "a" * 64}
NO_SELECTION = {"only_inputs": None, "only_systems": None, "excluded_inputs": [], "excluded_systems": []}


def digest(label: str) -> str:
    return canonical_sha256({"fixture": label})


def input_hash(input_id: str) -> str:
    return digest(f"tree/{input_id}")


def target(target_id: str, *, canonical: str | None = None, project: str = "acme/alpha", family: str = "shell",
           workload: str = WORKLOAD, level: str = "L3") -> dict:
    """One planned target as a schedule freezes it."""
    return {"target_id": target_id, "case_id": f"case-{target_id}", "canonical_id": canonical or target_id,
            "kind": "command_injection", "variant_family": family, "workload": workload,
            "component_role": "application", "project": project, "validation_level": level}


def control(control_id: str, *, kind: str = "capability_safe", target_id: str | None = None,
            canonical: str | None = None, level: str = "L3") -> dict:
    """One planned control as a schedule freezes it; a fixed-target control names its target."""
    return {"control_id": control_id, "case_id": f"case-{target_id or control_id}",
            "canonical_id": canonical or control_id, "type": kind, "target_id": target_id,
            "validation_level": level}


def planned(input_id: str, *, targets=(), controls=(), project: str = "acme/alpha", workload: str = WORKLOAD,
            profile: str = "standard", snapshot_id: str | None = None, scope: str = "reviewed",
            budgets=(1, 5), frozen: bool = True) -> dict:
    """One schedule input row with a frozen plan (or an unavailable one)."""
    plan = ({"state": "frozen", "scope": scope, "review_budgets": list(budgets), "targets": list(targets),
             "controls": list(controls), "notes": []} if frozen else
            {"state": "unavailable", "reason": f"snapshot {input_id} declares no tree hash"})
    return {"input_id": input_id, "mode": "full", "profile": profile,
            "snapshot_id": snapshot_id or input_id.removesuffix(".blinded"), "change_set_id": None,
            "change_set": None,
            "blinding": ({"map_id": "fixture-map", "map_version": "1", "map_sha256": digest("map")}
                         if profile == "metadata_blinded" else None),
            "project": project, "workload": workload, "component_role": "application",
            "declared_tree_hash": input_hash(input_id) if frozen else None, "plan": plan}


def scan(*, hits=None, claims: int | None = None, ranking: str = "native", status: str = "success",
         resolved: bool = True, controls=None, pending=None, usage=None, review_state: str = "approved",
         timing=None, execution: bool = True, drop=(), extra=(), scope: str | None = None) -> dict:
    """What one bundle holds.

    ``hits`` maps a target id to the 1-based position of the claim a reviewer accepted for it;
    ``pending`` does the same for an unresolved match; ``controls`` maps a control id to ``"quiet"``,
    ``"unresolved"``, or ``("false_allegation", position)``. ``drop`` leaves frozen targets out of the
    bundle's plan and ``extra`` adds targets to it.
    """
    return {"hits": hits or {}, "claims": claims, "ranking": ranking, "status": status, "resolved": resolved,
            "controls": controls or {}, "pending": pending or {}, "usage": usage or {"wall_seconds": 1.0},
            "review_state": review_state, "timing": timing, "execution": execution, "drop": set(drop),
            "extra": list(extra), "scope": scope}


def _plan_item(item: dict, kind: str) -> dict:
    if kind == "targets":
        return {"target_id": item["target_id"], "description": f"fixture target {item['target_id']}",
                "validation_level": item["validation_level"], "kind": "command_injection"}
    return {"control_id": item["control_id"], "description": f"fixture control {item['control_id']}",
            "type": item["type"], "validation_level": item["validation_level"],
            **({"target_id": item["target_id"]} if item["target_id"] else {})}


def write_bundle(bundle: Path, run_id: str, assignment: dict, row: dict, spec: dict) -> tuple[dict, dict, dict]:
    """Write one invocation bundle and return its result, plan, and review record."""
    frozen = row["plan"]
    items = frozen if frozen["state"] == "frozen" else {"targets": [], "controls": [], "scope": "draft",
                                                         "review_budgets": [1, 5]}
    bound = input_hash(row["input_id"])
    plan = {"schema_version": "2.0", "input_hash": bound, "scope": spec["scope"] or items["scope"],
            "targets": [_plan_item(item, "targets") for item in items["targets"]
                        if item["target_id"] not in spec["drop"]] + [_plan_item(item, "targets")
                                                                     for item in spec["extra"]],
            "controls": [_plan_item(item, "controls") for item in items["controls"]],
            "review_budgets": items["review_budgets"]}
    positions = list(spec["hits"].values()) + list(spec["pending"].values())
    positions += [value[1] for value in spec["controls"].values() if isinstance(value, tuple)]
    count = spec["claims"] if spec["claims"] is not None else max(positions, default=0)
    native = spec["ranking"] == "native"
    claims = [{"claim_id": f"c{index}", "allegation": f"fixture allegation {index}", "kind": "command_injection",
               "primary_location": {"path": f"src/file{index}.py", "start_line": index, "end_line": index},
               **({"rank": index} if native else {})} for index in range(1, count + 1)]
    usage = dict(spec["usage"])
    result = {"schema_version": "2.1" if usage.get("wall_seconds", 0) is None else "2.0", "run_id": run_id,
              "system_id": assignment["system_id"], "input_hash": bound, "status": spec["status"],
              "ranking": spec["ranking"], "claims": claims, "bundles_resolved": spec["resolved"], "usage": usage}
    matches = [{"claim_id": f"c{position}", "target_id": target_id, "decision": "accepted",
                "reason": "fixture: accepted by a fictional reviewer"}
               for target_id, position in spec["hits"].items()]
    matches += [{"claim_id": f"c{position}", "target_id": target_id, "decision": "unresolved",
                 "reason": "fixture: pending"} for target_id, position in spec["pending"].items()]
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
    if spec["execution"]:
        start, finish, wall = spec["timing"] or (CREATED_AT, "2026-09-20T15:00:01+00:00", 1.0)
        execution = {
            "schema_version": "2.0", "run_id": run_id, "invocation_id": assignment["assignment_id"],
            "input_id": assignment["input_id"], "system_id": assignment["system_id"],
            "repetition": assignment["repetition"], "adapter": {"name": "fake", "version": "1.0.0"},
            "versions": {}, "status": spec["status"], "exit_code": 0, "timed_out": spec["status"] == "timeout",
            "command": [], "started_at": start, "finished_at": finish, "wall_seconds": wall,
            "timeout_seconds": 60, "tool_versions": {}, "model_identity": None, "system_config": {},
            "network_policy": {"declared": "none", "enforced": False, "note": "fixture"},
            "environment": {"passthrough": []}, "capture": {}, "trace": None,
            "provenance": {"tree_hash": bound, "provenance_sha256": digest("provenance"),
                           "profile": row["profile"], "synthetic_history": None, "source_modified": False,
                           "modified_paths": [], "captured_state_dirs": []},
            "preparation": {}, "unsupported_languages": [], "error": None, "import_error": None, "notes": [],
            "raw_artifacts": []}
        validate_document("execution-record", execution)
        (bundle / "execution.json").write_text(canonical_json(execution) + "\n", encoding="utf-8")
    review.write_evaluator_records(bundle, plan, decisions, record)
    return result, plan, record


def write_run(root: Path, run_id: str, inputs: list[dict], *, systems=("sys-a",), repetitions: int = 1,
              outcomes=None, configs=None, failed_inputs=(), skipped_systems=(), pack=PACK) -> Path:
    """Write one run directory the way ``scaneval run`` lays it out, with hand-chosen outcomes.

    *outcomes* maps ``(input_id, system_id, repetition)`` to a :func:`scan` spec, or to
    ``"missing_row"`` (the manifest has no row) or ``"missing_bundle"`` (the row names a bundle that
    is not there); unlisted assignments are successful scans that detect nothing. An input in
    *failed_inputs* was never prepared, and a system in *skipped_systems* was never invoked.
    """
    outcomes = outcomes or {}
    configs = configs or {}
    directory = root / run_id
    (directory / "evaluator").mkdir(parents=True)
    entries = [{"system_id": system_id, "adapter": "fake", "config": {"knob": 1}, **configs.get(system_id, {})}
               for system_id in systems]
    config = {"schema_version": "2.1", "run_id": run_id, "pack": "pack.json",
              "inputs": [{"input_id": row["input_id"], "snapshot_id": row["snapshot_id"],
                          **({"profile": "metadata_blinded", "blinding_map": "fixture-map.json"}
                             if row["profile"] == "metadata_blinded" else {})} for row in inputs],
              "systems": entries, "repetitions": repetitions, "timeout_seconds": 60, "trace_mode": "off",
              "network_policy": "none"}
    validate_document("run-config", config)
    assignments = sorted(({"assignment_id": f"{row['input_id']}__{system_id}__r{repetition}",
                           "input_id": row["input_id"], "system_id": system_id, "repetition": repetition}
                          for row in inputs for system_id in systems for repetition in range(1, repetitions + 1)),
                         key=lambda item: (item["input_id"], item["system_id"], item["repetition"]))
    frozen_schedule = {
        "schema_version": "2.1", "run_id": run_id, "created_at": CREATED_AT,
        "config_sha256": canonical_sha256(config), "pack": pack, "repetitions": repetitions, "inputs": inputs,
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
        row = {key: assignment[key] for key in ("input_id", "system_id", "repetition")}
        row = {"invocation_id": assignment["assignment_id"], **row}
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
        if spec == "missing_row":
            continue
        path = f"invocations/{assignment['assignment_id']}"
        if spec == "missing_bundle":
            invocations.append({**row, "status": "success", "claim_records": 0, "plan_scope": "reviewed",
                                "targets_assigned": 0, "targets_detected": 0, "pending_matching_count": 0,
                                "bundle_path": path, "review_state": "draft", "skipped_reason": None})
            continue
        result, plan, record = write_bundle(directory / path, run_id, assignment, rows[assignment["input_id"]],
                                            spec)
        invocations.append({**row, "status": result["status"], "claim_records": len(result["claims"]),
                            "plan_scope": plan["scope"], "targets_assigned": len(plan["targets"]),
                            "targets_detected": 0, "pending_matching_count": 0, "bundle_path": path,
                            "review_state": record["state"], "skipped_reason": None})
    manifest = {
        "schema_version": "2.1", "run_id": run_id, "status": "completed", "created_at": CREATED_AT,
        "config_sha256": canonical_sha256(config),
        "pack": {"namespace": pack["namespace"], "pack_id": pack["pack_id"], "version": pack["version"],
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


def policy(**uncertainty) -> dict:
    """The default policy with a smaller replicate count, or other uncertainty settings, for speed."""
    document = json.loads(canonical_json(aggregate.DEFAULT_POLICY))
    document["uncertainty"].update({"replicates": 200, **uncertainty})
    return document


def view(report: dict, profile: str = "standard", mode: str = "full") -> dict:
    return next(item for item in report["views"] if (item["mode"], item["profile"]) == (mode, profile))


def system(block: dict, system_id: str = "sys-a") -> dict:
    return next(item for item in block["systems"] if item["system_id"] == system_id)


def slice_of(system_block: dict, dimension: str = "all", value: str | None = None) -> dict:
    return next(item for item in system_block["slices"]
                if item["slice"] == {"dimension": dimension, "value": value})


def detection(slice_block: dict, weighting: str = "equal_target") -> dict:
    return next(item for item in slice_block["detection"] if item["weighting"] == weighting)


def recall(report: dict, weighting: str = "equal_target", system_id: str = "sys-a", profile: str = "standard"):
    return detection(slice_of(system(view(report, profile), system_id)), weighting)["full_output_recall"]["value"]


def budget(block: dict, value: int) -> dict:
    return next(item for item in block["recall_at_budget"] if item["budget"] == value)


def two_project_run(tmp_path: Path) -> Path:
    """alpha-1 carries three targets from one scan, beta-1 one target; one hit in each input.

    Families: T-a1 shell, T-a2 and T-a3 sql, T-b1 path. Claims: alpha-1 accepts c1 for T-a1 among
    three claims; beta-1 accepts c2 for T-b1 among two.
    """
    inputs = [planned("alpha-1", project="acme/alpha", targets=[
                  target("T-a1", project="acme/alpha", family="shell"),
                  target("T-a2", project="acme/alpha", family="sql"),
                  target("T-a3", project="acme/alpha", family="sql")]),
              planned("beta-1", project="acme/beta", targets=[target("T-b1", project="acme/beta", family="path")])]
    return write_run(tmp_path, "run-counts", inputs, outcomes={
        ("alpha-1", "sys-a", 1): scan(hits={"T-a1": 1}, claims=3),
        ("beta-1", "sys-a", 1): scan(hits={"T-b1": 2}, claims=2)})


def five_project_inputs(prefix: str = "p", **extra) -> list[dict]:
    """Five projects, one input and one target each, every target in its own family."""
    return [planned(f"{prefix}{index}", project=f"acme/{prefix}{index}",
                    targets=[target(f"T-{prefix}{index}", project=f"acme/{prefix}{index}",
                                    family=f"family-{index}")],
                    **extra)
            for index in range(1, 6)]


# --- acceptance: hand-calculated corpus metrics -------------------------------------------------


def test_equal_target_and_equal_project_recall_differ_when_scans_carry_different_target_counts(tmp_path):
    """Three targets on one scan and one on another weigh differently by target and by project.

    Detected: T-a1 (alpha, rank 1) and T-b1 (beta, rank 2); T-a2 and T-a3 missed.
    - equal_target: w = 1/4 each, recall = (1 + 0 + 0 + 1)/4 = 1/2.
    - equal_project: alpha targets 1/(2*3) = 1/6 each, beta 1/2, recall = 1/6 + 1/2 = 2/3.
    - equal_family: shell {a1} 1/3, sql {a2, a3} 1/6 each, path {b1} 1/3, recall = 1/3 + 1/3 = 2/3.
    - recall@1: only T-a1 is at rank <= 1: equal_target 1/4, equal_project 1/6.
    - recall@5: both hits: 1/2 and 2/3.
    Targets per input: one input with 1 target, one with 3.
    """
    report = aggregate.aggregate([two_project_run(tmp_path)], policy=policy())

    whole = slice_of(system(view(report)))
    assert detection(whole)["full_output_recall"]["value"] == 0.5
    assert detection(whole, "equal_project")["full_output_recall"]["value"] == 2 / 3
    assert detection(whole, "equal_family")["full_output_recall"]["value"] == 2 / 3
    assert budget(detection(whole), 1)["value"] == 0.25
    assert budget(detection(whole, "equal_project"), 1)["value"] == 1 / 6
    assert budget(detection(whole), 5)["value"] == 0.5
    assert budget(detection(whole, "equal_project"), 5)["value"] == 2 / 3
    assert view(report)["targets_per_input"] == [{"targets": 1, "inputs": 1}, {"targets": 3, "inputs": 1}]
    assert view(report)["canonical_targets"] == 4
    assert system(view(report))["first_hit_ranks"] == {
        "ranks": [{"rank": 1, "target_observations": 1}, {"rank": 2, "target_observations": 1}],
        "detected_without_rank": 0, "not_detected": 2}
    assert validate_document("aggregate-report", report) is report


def test_one_canonical_target_on_several_snapshots_is_one_target_with_rho_weighted_observations(tmp_path):
    """Two snapshots of one root cause add observations of one target, never a second target's weight.

    CVE-X is planned on widget-v1 (detected) and widget-v2 (missed); T-g on gadget (detected).
    - p(CVE-X) = rho * 1 + rho * 0 with rho = 1/2, so 1/2; p(T-g) = 1.
    - equal_target over 2 canonical targets: (1/2 + 1)/2 = 3/4. Counting the two records as two
      targets would have given (1 + 0 + 1)/3 = 2/3.
    - The acme/widget project slice holds CVE-X alone: 1/2.
    """
    inputs = [planned(f"widget-{version}", project="acme/widget",
                      targets=[target(f"T-{version}", canonical="CVE-X", project="acme/widget")])
              for version in ("v1", "v2")]
    inputs.append(planned("gadget", project="acme/gadget", targets=[target("T-g", project="acme/gadget")]))
    run = write_run(tmp_path, "run-canonical", inputs, outcomes={
        ("widget-v1", "sys-a", 1): scan(hits={"T-v1": 1}), ("gadget", "sys-a", 1): scan(hits={"T-g": 1})})

    report = aggregate.aggregate([run], policy=policy())

    block = system(view(report))
    assert view(report)["canonical_targets"] == 2
    assert slice_of(block)["canonical_targets"] == 2
    assert recall(report) == 0.75
    assert recall(report, "equal_project") == 0.75
    assert detection(slice_of(block, "project", "acme/widget"))["full_output_recall"]["value"] == 0.5
    assert detection(slice_of(block))["coverage"]["target_observations"] == 3


def test_repetition_counts_that_differ_between_two_runs_of_one_input_are_averaged_per_run(tmp_path):
    """One input scanned once by one run and three times by another is two positive inputs.

    run-a (k=1) detects; run-b (k=3) detects in repetition 1 only.
    - p = 1/2 * (1/1) + 1/2 * (1/3) = 2/3. Pooling the four observations would give 2/4 = 1/2.
    - Run variability: run-a's input ran once, so its weight 1 * 1/2 is uncovered; run-b's has
      p = 1/3, v = p(1-p)k/(k-1) = (1/3)(2/3)(3/2) = 1/3, term = w^2 rho^2 v / k = (1/4)(1/3)/3 = 1/36,
      so the state is partial, variance 1/36, standard error 1/6.
    - Completion: every scan succeeded, 1.
    """
    row = [planned("widget", targets=[target("T-w")])]
    first = write_run(tmp_path, "run-a", row, outcomes={("widget", "sys-a", 1): scan(hits={"T-w": 1})})
    second = write_run(tmp_path, "run-b", row, repetitions=3,
                       outcomes={("widget", "sys-a", 1): scan(hits={"T-w": 1})})

    report = aggregate.aggregate([first, second], policy=policy())

    whole = slice_of(system(view(report)))
    assert detection(whole)["full_output_recall"]["value"] == 2 / 3
    variability = detection(whole)["run_variability"]["full_output_recall"]
    assert variability["state"] == "partial"
    assert variability["variance"] == 1 / 36
    assert variability["standard_error"] == pytest.approx(1 / 6)
    assert variability["uncovered_mass"] == 0.5
    assert whole["completion"]["value"] == 1.0
    assert [run["repetitions"] for run in report["runs"]] == [1, 3]


def test_failed_preparation_missing_bundles_and_skipped_systems_stay_in_every_denominator(tmp_path):
    """No failure leaves a denominator: each is a miss that did not complete.

    sys-a: i-ok detects T1; i-prep was never prepared; i-gone's bundle is missing; i-miss completes
    without a hit; i-norow has no manifest row.
    - Recall = 1/5 (dropping the three failures would have given 1/2).
    - Completion = (1 + 0 + 0 + 1 + 0)/5 = 2/5, and so is the completed target mass.
    sys-skip was never invoked: recall 0, completion 0, and its i-prep assignment is still a
    failed preparation.
    """
    inputs = [planned(f"i-{name}", project=f"acme/{name}", targets=[target(f"T-{name}", project=f"acme/{name}")])
              for name in ("ok", "prep", "gone", "miss", "norow")]
    run = write_run(tmp_path, "run-failures", inputs, systems=("sys-a", "sys-skip"),
                    failed_inputs=("i-prep",), skipped_systems=("sys-skip",),
                    outcomes={("i-ok", "sys-a", 1): scan(hits={"T-ok": 1}),
                              ("i-gone", "sys-a", 1): "missing_bundle", ("i-norow", "sys-a", 1): "missing_row"})

    report = aggregate.aggregate([run], policy=policy())

    block = system(view(report))
    whole = slice_of(block)
    assert detection(whole)["full_output_recall"]["value"] == 0.2
    assert whole["completion"]["value"] == 0.4
    assert detection(whole)["coverage"]["completed_mass"] == 0.4
    assert whole["completion"]["statuses"] == {"success": 2, "partial": 0, "unsupported": 0, "error": 0,
                                               "timeout": 0, "skipped": 1, "missing": 2}
    assert block["observations"]["failures"] == {"failed_preparation": 1, "skipped_system": 0, "skipped": 0,
                                                 "missing_row": 1, "missing_bundle": 1, "unusable_bundle": 0}
    assert {(row["assignment_id"], row["reason"]) for row in block["observations"]["failed_assignments"]} == {
        ("i-prep__sys-a__r1", "failed_preparation"), ("i-gone__sys-a__r1", "missing_bundle"),
        ("i-norow__sys-a__r1", "missing_row")}
    skipped = system(view(report), "sys-skip")
    assert detection(slice_of(skipped))["full_output_recall"]["value"] == 0.0
    assert slice_of(skipped)["completion"]["value"] == 0.0
    assert skipped["observations"]["failures"]["skipped_system"] == 4
    assert skipped["observations"]["failures"]["failed_preparation"] == 1
    assert report["runs"][0]["failures"]["skipped_system"] == 4
    assert any("stay in every denominator" in warning for warning in view(report)["warnings"])


def test_a_shared_scan_counts_its_cost_once_and_unknown_cost_stays_unknown(tmp_path):
    """Usage is summed over executed scans, not over the targets they cover.

    shared covers three targets in one scan (10 s, $0.50, 1000 input tokens); single reports 4 s and
    an unknown cost; imported reports neither wall time nor cost.
    - Wall: known 10 + 4 = 14 over 2 scans, 1 unknown (not 3 * 10 + 4 = 34).
    - Cost: known $0.50 over 1 scan, 2 unknown, coverage 1/3.
    - The acme/alpha slice holds the shared scan alone: 1 bundle, 10 s, $0.50.
    - Execution records span 15:00:00 to 15:00:25, so elapsed wall is 25 s, while the records' own
      wall times sum to 10 + 4 + 5 = 19 s.
    """
    inputs = [planned("shared", project="acme/alpha", targets=[target(f"T-s{index}", project="acme/alpha")
                                                              for index in range(1, 4)]),
              planned("single", project="acme/beta", targets=[target("T-single", project="acme/beta")]),
              planned("imported", project="acme/beta", targets=[target("T-imported", project="acme/beta")])]
    run = write_run(tmp_path, "run-usage", inputs, outcomes={
        ("shared", "sys-a", 1): scan(hits={"T-s1": 1, "T-s2": 2, "T-s3": 3},
                                     usage={"wall_seconds": 10.0, "cost_usd": 0.5, "input_tokens": 1000},
                                     timing=(CREATED_AT, "2026-09-20T15:00:10+00:00", 10.0)),
        ("single", "sys-a", 1): scan(usage={"wall_seconds": 4.0, "cost_usd": None},
                                     timing=("2026-09-20T15:00:10+00:00", "2026-09-20T15:00:14+00:00", 4.0)),
        ("imported", "sys-a", 1): scan(usage={"wall_seconds": None},
                                       timing=("2026-09-20T15:00:20+00:00", "2026-09-20T15:00:25+00:00", 5.0))})

    report = aggregate.aggregate([run], policy=policy())

    usage = slice_of(system(view(report)))["usage"]
    assert usage["bundles"] == 3
    assert usage["wall_seconds"] == {"known_sum": 14.0, "known": 2, "unknown": 1}
    assert usage["cost_usd"] == {"known_sum": 0.5, "known": 1, "unknown": 2, "coverage": 1 / 3}
    assert usage["input_tokens"] == {"sum": 1000, "reported": 1}
    assert usage["output_tokens"] == {"sum": None, "reported": 0}
    alpha = slice_of(system(view(report)), "project", "acme/alpha")["usage"]
    assert alpha["bundles"] == 1
    assert alpha["wall_seconds"]["known_sum"] == 10.0
    assert alpha["cost_usd"]["known_sum"] == 0.5
    assert report["runs"][0]["timing"] == {"execution_records": 3, "records_without_timestamps": 0,
                                           "elapsed_wall_seconds": 25.0, "summed_wall_seconds": 19.0}


def blinded_and_standard_run(tmp_path: Path) -> Path:
    """widget and gadget run standard; only widget has a blinded variant; widget-fixed pairs with widget.

    Standard: T-w detected, T-g missed, the fixed control quiet. Blinded: T-w missed.
    """
    widget = target("T-w", canonical="W", project="acme/widget")
    inputs = [planned("widget", project="acme/widget", targets=[widget]),
              planned("widget-fixed", project="acme/widget",
                      controls=[control("C-w-fixed", kind="fixed_target", target_id="T-w")]),
              planned("gadget", project="acme/gadget",
                      targets=[target("T-g", canonical="G", project="acme/gadget")]),
              planned("widget.blinded", project="acme/widget", profile="metadata_blinded", targets=[widget])]
    return write_run(tmp_path, "run-profiles", inputs, outcomes={("widget", "sys-a", 1): scan(hits={"T-w": 1})})


def test_blinded_and_standard_profiles_are_separate_views_with_their_own_availability(tmp_path):
    """A profile is never pooled with another, and what one profile lacks is listed, not hidden.

    Standard view: W detected, G missed, recall (1 + 0)/2 = 1/2; W pairs with widget-fixed, so
    pair availability is w(W) = 1/2, and the pair is correct (hit, fixed state quiet): Q = 1.
    Blinded view: W alone, missed: recall 0; no blinded fixed input, so availability 0 and Q null.
    Profile coverage: G is unavailable in the blinded profile; one canonical target is common.
    """
    report = aggregate.aggregate([blinded_and_standard_run(tmp_path)], policy=policy())

    assert [(item["mode"], item["profile"]) for item in report["views"]] == [
        ("full", "metadata_blinded"), ("full", "standard")]
    standard = detection(slice_of(system(view(report))))
    blinded = detection(slice_of(system(view(report, "metadata_blinded"))))
    assert view(report)["canonical_targets"] == 2 and view(report, "metadata_blinded")["canonical_targets"] == 1
    assert standard["full_output_recall"]["value"] == 0.5
    assert blinded["full_output_recall"]["value"] == 0.0
    assert standard["pairs"]["availability"] == 0.5 and standard["pairs"]["value"] == 1.0
    assert blinded["pairs"]["availability"] == 0.0 and blinded["pairs"]["value"] is None
    assert report["profile_coverage"] == [{
        "mode": "full",
        "profiles": [{"profile": "metadata_blinded", "inputs": 1, "canonical_targets": 1, "canonical_controls": 0},
                     {"profile": "standard", "inputs": 3, "canonical_targets": 2, "canonical_controls": 1}],
        "common_canonical_targets": 1,
        "unavailable": [{"profile": "metadata_blinded", "canonical_target_ids": ["G"]}]}]


def test_aggregation_is_byte_identical_twice_and_in_any_directory_order(tmp_path):
    """Two runs aggregated twice, and in the other order, give one document byte for byte."""
    first = two_project_run(tmp_path / "one")
    second = write_run(tmp_path / "two", "run-second", five_project_inputs(),
                       outcomes={("p1", "sys-a", 1): scan(hits={"T-p1": 1})})

    once = canonical_json(aggregate.aggregate([first, second], policy=policy()))
    again = canonical_json(aggregate.aggregate([first, second], policy=policy()))
    reversed_order = canonical_json(aggregate.aggregate([second, first], policy=policy()))

    assert once == again == reversed_order
    assert str(tmp_path) not in once


# --- uncertainty states -------------------------------------------------------------------------


def test_too_few_clusters_is_a_state_not_a_zero_width_interval(tmp_path):
    """Two projects are fewer than min_clusters 5: no bounds are reported at all."""
    report = aggregate.aggregate([two_project_run(tmp_path)], policy=policy())

    interval = detection(slice_of(system(view(report))))["full_output_recall"]["interval"]
    assert interval == {"state": "insufficient_clusters", "lower": None, "upper": None, "clusters": 2}


def test_an_interval_every_replicate_agrees_on_is_degenerate_and_carries_no_bounds(tmp_path):
    """Five projects, every target detected: each replicate gives 1, which is not certainty."""
    inputs = five_project_inputs()
    run = write_run(tmp_path, "run-all-hit", inputs, outcomes={
        (row["input_id"], "sys-a", 1): scan(hits={row["plan"]["targets"][0]["target_id"]: 1}) for row in inputs})

    report = aggregate.aggregate([run], policy=policy())

    metric = detection(slice_of(system(view(report))))["full_output_recall"]
    assert metric["value"] == 1.0
    assert metric["interval"] == {"state": "degenerate", "lower": None, "upper": None, "clusters": 5}


def share_of_draws(seed: int, family: str, universe: list[str], counted: set[str]) -> list[float]:
    """200 sorted replicates of (draws landing in *counted*) / len(universe), from one family's stream.

    With one equally weighted item per cluster, that share is the replicate's value of a mean such as
    recall; this recomputes it independently of the module, from the documented stream label.
    """
    stream = Stream(seed, label=f"bootstrap/full/standard/all/{family}")
    return sorted(sum(universe[index] in counted for index in resample_with_replacement(len(universe), stream))
                  / len(universe) for _ in range(200))


def test_a_bootstrap_interval_follows_the_documented_draws_and_percentile_rule(tmp_path):
    """Recomputed here from the stream, the draws, and the order statistics the module documents.

    Five projects, T-p1 and T-p2 detected: each replicate draws five projects with replacement and
    its recall is the share of draws landing on p1 or p2. The interval is the ceil(0.025 * 200) = 5th
    and ceil(0.975 * 200) = 195th of the 200 sorted replicate values.
    """
    run = write_run(tmp_path, "run-interval", five_project_inputs(), outcomes={
        ("p1", "sys-a", 1): scan(hits={"T-p1": 1}), ("p2", "sys-a", 1): scan(hits={"T-p2": 1})})

    report = aggregate.aggregate([run], policy=policy(seed=11))

    values = share_of_draws(11, "targets", [f"acme/p{index}" for index in range(1, 6)], {"acme/p1", "acme/p2"})
    assert aggregate.percentile_ranks(0.95, 200) == (5, 195)
    assert aggregate.percentile_ranks(0.95, 1000) == (25, 975)
    metric = detection(slice_of(system(view(report))))["full_output_recall"]
    assert metric["value"] == 0.4
    assert metric["interval"] == {"state": "ok", "lower": values[4], "upper": values[194], "clusters": 5}


def test_projects_carrying_only_controls_take_no_draw_from_target_intervals(tmp_path):
    """Target metrics resample the clusters carrying targets; control metrics those carrying controls.

    Five target projects (T-p1 and T-p2 detected) and five other projects carrying one control each
    (C-c1 falsely alleged, the rest quiet). Recall resamples the five target projects from the stream
    labelled .../all/targets, exactly as in the test above, so the control projects change nothing;
    over a union of ten, a replicate could draw no target at all. The resolved rate is 1/5 and
    resamples the five control projects from .../all/controls: a replicate's rate is the share of
    its five draws landing on c1.
    """
    inputs = five_project_inputs() + [planned(f"c{index}", project=f"acme/c{index}",
                                              controls=[control(f"C-c{index}")]) for index in range(1, 6)]
    run = write_run(tmp_path, "run-families", inputs, outcomes={
        ("p1", "sys-a", 1): scan(hits={"T-p1": 1}), ("p2", "sys-a", 1): scan(hits={"T-p2": 1}),
        ("c1", "sys-a", 1): scan(controls={"C-c1": ("false_allegation", 1)})})

    whole = slice_of(system(view(aggregate.aggregate([run], policy=policy(seed=11)))))

    assert whole["clusters"] == {"targets": 5, "controls": 5}
    targets = share_of_draws(11, "targets", [f"acme/p{index}" for index in range(1, 6)], {"acme/p1", "acme/p2"})
    assert detection(whole)["full_output_recall"]["interval"] == {
        "state": "ok", "lower": targets[4], "upper": targets[194], "clusters": 5}
    rate = whole["controls"]["capability_safe"]["resolved_rate"]
    controls = share_of_draws(11, "controls", [f"acme/c{index}" for index in range(1, 6)], {"acme/c1"})
    assert rate["value"] == 0.2
    assert rate["interval"] == {"state": "ok", "lower": controls[4], "upper": controls[194], "clusters": 5}


# --- controls, pairs, unranked output, run noise ------------------------------------------------


def test_zero_eligible_controls_give_null_rates_never_zero(tmp_path):
    """No control is planned, so no rate, mass, or bound exists; none is reported as 0."""
    report = aggregate.aggregate([two_project_run(tmp_path)], policy=policy())

    for name in ("capability_safe", "fixed_target"):
        block = slice_of(system(view(report)))["controls"][name]
        assert block["canonical_controls"] == 0 and block["observations"] == 0
        assert block["resolved_rate"]["value"] is None
        assert block["completed_upper"]["value"] is None
        assert block["completed_lower"] is None
        assert block["completed_mass"] is None and block["assessable_mass"] is None


def test_unresolved_control_assessments_bound_the_completed_false_alarm_rate(tmp_path):
    """The math note's example: ten completed observations, seven quiet, three unresolved.

    A = 7/10, C = 1, E = 0: the resolved rate E/A is 0 and the completed bounds are
    [E/C, (E + C - A)/C] = [0, 0.3].
    """
    inputs = [planned(f"safe-{index}", project=f"acme/safe{index % 5}", controls=[control(f"C-{index}")])
              for index in range(10)]
    run = write_run(tmp_path, "run-controls", inputs, outcomes={
        (f"safe-{index}", "sys-a", 1): scan(controls={f"C-{index}": "unresolved"}) for index in range(7, 10)})

    report = aggregate.aggregate([run], policy=policy())

    block = slice_of(system(view(report)))["controls"]["capability_safe"]
    assert block["canonical_controls"] == 10
    assert block["resolved"] == 7 and block["unresolved"] == 3 and block["completed"] == 10
    assert block["assessable_mass"] == 0.7
    assert block["completed_mass"] == 1.0
    assert block["resolved_rate"]["value"] == 0.0
    assert block["completed_lower"] == 0.0
    assert block["completed_upper"]["value"] == 0.3
    fixed = slice_of(system(view(report)))["controls"]["fixed_target"]
    assert fixed["canonical_controls"] == 0 and fixed["resolved_rate"]["value"] is None


def test_a_replicate_that_draws_no_resolved_control_makes_the_rate_interval_unstable(tmp_path):
    """Ten control projects, only s0 and s1 resolved (quiet), the other eight unresolved.

    The resolved rate E/A = 0/(2/10) = 0 is defined, but it rests on two clusters: a replicate whose
    ten draws all miss them has no resolved mass (chance (8/10)^10 per replicate), leaving the rate
    undefined there, so the interval is 'unstable' rather than a range. The completed upper bound
    rests on all ten clusters and keeps an interval. min_clusters is 2 here so the state is reached.
    """
    inputs = [planned(f"safe-{index}", project=f"acme/s{index}", controls=[control(f"C-{index}")])
              for index in range(10)]
    run = write_run(tmp_path, "run-unstable", inputs, outcomes={
        (f"safe-{index}", "sys-a", 1): scan(controls={f"C-{index}": "unresolved"}) for index in range(2, 10)})

    block = slice_of(system(view(aggregate.aggregate([run], policy=policy(min_clusters=2)))))
    rate = block["controls"]["capability_safe"]["resolved_rate"]

    universe = [f"acme/s{index}" for index in range(10)]
    empty = share_of_draws(0, "controls", universe, {"acme/s0", "acme/s1"})
    assert empty[0] == 0.0, "some replicate draws neither resolved cluster"
    assert rate == {"value": 0.0, "interval": {"state": "unstable", "lower": None, "upper": None, "clusters": 2}}
    assert block["controls"]["capability_safe"]["completed_upper"]["interval"]["state"] == "ok"


def test_a_control_on_a_failed_scan_is_neither_completed_nor_resolved(tmp_path):
    """One control observed once, by a scan that timed out: C = A = 0, so every rate is null.

    The false allegation it confirmed from incomplete output stays visible in the raw count only.
    """
    timed_out = scan(status="timeout", resolved=False, controls={"C-safe": ("false_allegation", 1)})
    run = write_run(tmp_path, "run-timeout", [planned("safe", controls=[control("C-safe")])],
                    outcomes={("safe", "sys-a", 1): timed_out})

    block = slice_of(system(view(aggregate.aggregate([run], policy=policy()))))["controls"]["capability_safe"]

    assert block["completed"] == 0 and block["resolved"] == 0
    assert block["observed_false_allegations"] == 1 and block["false_allegations"] == 0
    assert block["completed_mass"] == 0.0 and block["assessable_mass"] == 0.0
    assert block["resolved_rate"]["value"] is None and block["completed_upper"]["value"] is None


def pair_inputs() -> list[dict]:
    """Five vulnerable/fixed pairs in five projects and one target with no fixed state."""
    rows = []
    for index in range(1, 6):
        project = f"acme/pair{index}"
        rows.append(planned(f"v{index}", project=project, targets=[target(f"T{index}", project=project)]))
        rows.append(planned(f"f{index}", project=project,
                            controls=[control(f"C{index}", kind="fixed_target", target_id=f"T{index}")]))
    rows.append(planned("lonely", project="acme/lonely", targets=[target("T-lonely", project="acme/lonely")]))
    return rows


def test_pair_correctness_counts_confirmed_success_only_and_reports_the_four_outcomes(tmp_path):
    """Only a resolved pair with a hit and a quiet fixed state earns pair credit.

    Pairs: 1 correct (hit, quiet), 2 both flagged (hit, false allegation), 3 both silent (miss,
    quiet), 4 reversed (miss, false allegation), 5 unresolved (hit, fixed assessment unresolved).
    Six targets, equal weights 1/6; the five paired ones renormalize to 1/5 each.
    - Q = 1/5; assessable pair mass = 4/5; each resolved outcome has mass 1/5.
    - Availability = 5 * 1/6 = 5/6: T-lonely has no fixed state and is outside P, not a failed pair.
    """
    outcomes = {("v1", "sys-a", 1): scan(hits={"T1": 1}), ("v2", "sys-a", 1): scan(hits={"T2": 1}),
                ("v5", "sys-a", 1): scan(hits={"T5": 1}),
                ("f2", "sys-a", 1): scan(controls={"C2": ("false_allegation", 1)}),
                ("f4", "sys-a", 1): scan(controls={"C4": ("false_allegation", 1)}),
                ("f5", "sys-a", 1): scan(controls={"C5": "unresolved"})}
    run = write_run(tmp_path, "run-pairs", pair_inputs(), outcomes=outcomes)

    report = aggregate.aggregate([run], policy=policy())

    pairs = detection(slice_of(system(view(report))))["pairs"]
    assert pairs["pairable_targets"] == 5
    assert pairs["availability"] == 5 / 6
    assert pairs["value"] == 1 / 5
    assert pairs["assessable_mass"] == 4 / 5
    assert pairs["repetition_pairs"] == 5 and pairs["resolved_pairs"] == 4
    for name in ("correct", "both_flagged", "both_silent", "reversed"):
        assert pairs["outcomes"][name]["pairs"] == 1
        assert pairs["outcomes"][name]["mass"] == 1 / 5
    assert pairs["interval"]["state"] == "ok"


def test_unranked_output_leaves_native_recall_at_budget_null_and_reports_a_labelled_diagnostic(tmp_path):
    """No native order means no native recall@B; the random-order expectation is shown apart.

    ranked detects T-r at rank 1; unranked detects T-u among 4 unranked claims (1 accepted).
    - Full-output recall = (1 + 1)/2 = 1: a hit counts without a rank.
    - recall@1: value null; lower bound 1/2 (only the ranked hit is measured); unmeasured mass 1/2.
    - Random order over the unranked observation (mass 1/2): at B = 1, 1 - C(3,1)/C(4,1) = 1/4;
      at B = 5, b = min(5, 4) = 4 and 1 - C(3,4)/C(4,4) = 1.
    """
    inputs = [planned("ranked", project="acme/ranked", targets=[target("T-r", project="acme/ranked")]),
              planned("unranked", project="acme/unranked", targets=[target("T-u", project="acme/unranked")])]
    run = write_run(tmp_path, "run-unranked", inputs, outcomes={
        ("ranked", "sys-a", 1): scan(hits={"T-r": 1}),
        ("unranked", "sys-a", 1): scan(hits={"T-u": 2}, claims=4, ranking="unranked")})

    report = aggregate.aggregate([run], policy=policy())

    block = detection(slice_of(system(view(report))))
    assert block["full_output_recall"]["value"] == 1.0
    at_one = budget(block, 1)
    assert at_one["value"] is None and at_one["lower_bound"] == 0.5 and at_one["unmeasured_mass"] == 0.5
    assert at_one["interval"]["state"] == "unavailable"
    diagnostic = block["random_order_diagnostic"]
    assert "diagnostic" in diagnostic["label"] and "not native recall@B" in diagnostic["label"]
    assert diagnostic["observation_mass"] == 0.5 and diagnostic["pending_mass"] == 0.0
    assert diagnostic["expected_recall"] == [{"budget": 1, "value": 0.25}, {"budget": 5, "value": 1.0}]
    assert system(view(report))["first_hit_ranks"]["detected_without_rank"] == 1


def test_run_variability_is_separate_and_unavailable_with_one_repetition(tmp_path):
    """One repetition estimates no run noise; two repetitions give p(1-p)k/(k-1)/k per input.

    Once: state unavailable. Twice (hit, miss): p = 1/2, v = (1/2)(1/2)(2/1) = 1/2, variance
    = 1 * 1 * v / 2 = 1/4, standard error 1/2, labelled conditional run noise.
    """
    row = [planned("widget", targets=[target("T-w")])]
    once = write_run(tmp_path / "once", "run-once", row, outcomes={("widget", "sys-a", 1): scan(hits={"T-w": 1})})
    twice = write_run(tmp_path / "twice", "run-twice", row, repetitions=2,
                      outcomes={("widget", "sys-a", 1): scan(hits={"T-w": 1})})

    single = detection(slice_of(system(view(aggregate.aggregate([once], policy=policy())))))
    double = detection(slice_of(system(view(aggregate.aggregate([twice], policy=policy())))))

    assert single["run_variability"]["full_output_recall"] == {
        "state": "unavailable", "variance": None, "standard_error": None, "uncovered_mass": None}
    assert "not corpus uncertainty" in double["run_variability"]["label"]
    assert double["run_variability"]["full_output_recall"] == {
        "state": "ok", "variance": 0.25, "standard_error": 0.5, "uncovered_mass": 0.0}
    assert double["full_output_recall"]["interval"]["state"] == "insufficient_clusters"


def test_leave_one_project_out_recomputes_recall_without_each_project(tmp_path):
    """Two projects: without alpha only T-b1 remains (recall 1); without beta, alpha's three give 1/3."""
    report = aggregate.aggregate([two_project_run(tmp_path)], policy=policy())

    lopo = detection(slice_of(system(view(report))))["leave_one_project_out"]
    assert lopo["state"] == "ok"
    assert lopo["values"] == [{"left_out": "acme/alpha", "full_output_recall": 1.0},
                              {"left_out": "acme/beta", "full_output_recall": 1 / 3}]
    assert lopo["min"] == 1 / 3 and lopo["max"] == 1.0


# --- evidence scope -----------------------------------------------------------------------------


def test_reviewed_scope_needs_a_reviewed_plan_and_a_human_approved_record_everywhere(tmp_path):
    """Approved bundles of reviewed plans are reviewed evidence; one draft record degrades the view.

    A failure takes its schedule plan's scope, so a failed preparation does not degrade the view.
    """
    inputs = five_project_inputs()
    reviewed = write_run(tmp_path / "a", "run-reviewed", inputs, failed_inputs=("p5",))
    drafted = write_run(tmp_path / "b", "run-drafted", inputs,
                        outcomes={("p1", "sys-a", 1): scan(review_state="draft")})

    assert view(aggregate.aggregate([reviewed], policy=policy()))["evidence_scope"] == "reviewed"
    report = aggregate.aggregate([drafted], policy=policy())
    assert view(report)["evidence_scope"] == "draft"
    assert system(view(report))["evidence_scope"] == "draft"
    assert system(view(report))["observations"]["review_states"] == {
        "human_approved": 4, "draft": 1, "stale": 0, "missing": 0}
    assert any("not reviewed benchmark evidence" in warning for warning in view(report)["warnings"])


def test_a_view_mixing_diagnostic_fixtures_with_other_evidence_is_refused(tmp_path):
    inputs = [planned("fixture", scope="diagnostic", targets=[target("T-fixture", level="fixture")]),
              planned("real", targets=[target("T-real")])]
    run = write_run(tmp_path, "run-mixed", inputs)

    with pytest.raises(ContractError, match="mixes diagnostic fixture evidence with reviewed evidence"):
        aggregate.aggregate([run], policy=policy())


def test_items_frozen_but_absent_from_a_bundle_plan_are_misses_and_added_items_are_ignored(tmp_path):
    """The schedule decides what an input is scored on, not the plan a bundle happens to carry.

    The bundle's plan drops T-2 and adds T-extra, which it detects. Recall over the frozen T-1
    (detected) and T-2 (unscored, a miss) is 1/2, unscored mass 1/2; T-extra counts nowhere.
    """
    run = write_run(tmp_path, "run-unscored", [planned("widget", targets=[target("T-1"), target("T-2")])],
                    outcomes={("widget", "sys-a", 1): scan(hits={"T-1": 1, "T-extra": 2}, drop=("T-2",),
                                                           extra=[target("T-extra")])})

    report = aggregate.aggregate([run], policy=policy())

    block = detection(slice_of(system(view(report))))
    assert block["full_output_recall"]["value"] == 0.5
    assert block["coverage"]["unscored"] == 1 and block["coverage"]["unscored_mass"] == 0.5
    observations = system(view(report))["observations"]
    assert observations["unscored_items"] == 1 and observations["unregistered_items"] == 1
    assert view(report)["canonical_targets"] == 2


def test_an_input_without_a_frozen_plan_is_listed_and_left_out_of_target_metrics(tmp_path):
    inputs = [planned("widget", targets=[target("T-w")]), planned("undeclared", frozen=False)]
    run = write_run(tmp_path, "run-unplanned", inputs, outcomes={("widget", "sys-a", 1): scan(hits={"T-w": 1})})

    report = aggregate.aggregate([run], policy=policy())

    assert view(report)["inputs_without_frozen_plan"] == [
        {"run_id": "run-unplanned", "input_id": "undeclared",
         "reason": "snapshot undeclared declares no tree hash"}]
    assert recall(report) == 1.0
    assert slice_of(system(view(report)))["completion"]["inputs"] == 2


# --- weights and policies -----------------------------------------------------------------------


def test_explicit_target_weights_are_used_when_they_sum_to_one_and_refused_otherwise(tmp_path):
    """Declared 0.7 on T-a1 (hit), 0.1 on T-a2 and T-a3, 0.1 on T-b1 (hit): recall 0.8.

    Weights that sum to 0.9 over the view leave the explicit weighting unavailable, with a reason.
    """
    declared = {"T-a1": 0.7, "T-a2": 0.1, "T-a3": 0.1, "T-b1": 0.1}
    run = two_project_run(tmp_path)

    good = aggregate.aggregate([run], policy={**policy(), "views": ["equal_target", "explicit"],
                                              "target_weights": declared})
    short = aggregate.aggregate([run], policy={**policy(), "views": ["explicit"],
                                               "target_weights": {**declared, "T-a1": 0.6}})

    assert recall(good, "explicit") == 0.8
    refused = detection(slice_of(system(view(short))), "explicit")
    assert refused["state"] == "unavailable" and refused["full_output_recall"] is None
    assert "sum to 0.9" in refused["reason"]
    beta = detection(slice_of(system(view(good)), "project", "acme/beta"), "explicit")
    assert beta["full_output_recall"]["value"] == 1.0


def test_a_slice_across_workloads_needs_declared_workload_weights(tmp_path):
    """No summary crosses workloads without predeclared weights.

    Conventional: T-c1 hit, T-c2 missed (equal-target 1/2). Agentic: T-g hit (1).
    Without workload weights the whole-view slice has no number, but each workload slice does.
    With weights 0.25 conventional and 0.75 agentic: 0.25 * 1/2 + 0.75 * 1 = 7/8.
    """
    agentic = "agentic_application"
    inputs = [planned("conv", targets=[target("T-c1"), target("T-c2")]),
              planned("agent", project="acme/agent", workload=agentic,
                      targets=[target("T-g", project="acme/agent", workload=agentic)])]
    run = write_run(tmp_path, "run-workloads", inputs, outcomes={
        ("conv", "sys-a", 1): scan(hits={"T-c1": 1}), ("agent", "sys-a", 1): scan(hits={"T-g": 1})})

    plain = aggregate.aggregate([run], policy=policy())
    weighted = aggregate.aggregate([run], policy={**policy(), "workload_weights": {WORKLOAD: 0.25, agentic: 0.75}})

    whole = detection(slice_of(system(view(plain))))
    assert whole["state"] == "unavailable" and "declares no workload weights" in whole["reason"]
    assert detection(slice_of(system(view(plain)), "workload", WORKLOAD))["full_output_recall"]["value"] == 0.5
    assert detection(slice_of(system(view(plain)), "workload", agentic))["full_output_recall"]["value"] == 1.0
    assert recall(weighted) == 7 / 8


@pytest.mark.parametrize("change, message", [
    ({"views": ["explicit"]}, "'explicit' exactly when target_weights"),
    ({"target_weights": {"T-a1": 1.0}}, "'explicit' exactly when target_weights"),
    ({"workload_weights": {WORKLOAD: 0.5}}, "workload_weights must sum to 1"),
    ({"uncertainty": {**aggregate.DEFAULT_POLICY["uncertainty"], "confidence": 1}}, "confidence"),
    ({"uncertainty": {**aggregate.DEFAULT_POLICY["uncertainty"], "min_clusters": 1}}, "min_clusters"),
    ({"views": []}, "views"),
])
def test_a_policy_that_cannot_be_applied_is_refused(change, message):
    with pytest.raises(ContractError, match=message):
        aggregate.resolve_policy({**aggregate.DEFAULT_POLICY, **change})


def test_the_default_policy_is_complete_and_written_into_every_report(tmp_path):
    report = aggregate.aggregate([two_project_run(tmp_path)])

    assert report["policy"] == aggregate.DEFAULT_POLICY
    assert report["policy_sha256"] == canonical_sha256(aggregate.DEFAULT_POLICY)
    assert report["policy"]["uncertainty"] == {"method": "cluster_bootstrap", "cluster_by": "project",
                                               "replicates": 1000, "confidence": 0.95, "seed": 0,
                                               "min_clusters": 5}
    partial = {key: value for key, value in aggregate.DEFAULT_POLICY.items()
               if key not in ("target_weights", "workload_weights", "notes")}
    assert aggregate.resolve_policy(partial) == {**aggregate.DEFAULT_POLICY, "notes": []}


def test_resampling_clusters_can_be_families(tmp_path):
    """cluster_by family resamples variant families: alpha and beta carry three families here."""
    report = aggregate.aggregate([two_project_run(tmp_path)], policy=policy(cluster_by="family"))

    assert detection(slice_of(system(view(report))))["full_output_recall"]["interval"]["clusters"] == 3
    assert slice_of(system(view(report)))["clusters"] == {"targets": 3, "controls": 0}


# --- refusals -----------------------------------------------------------------------------------


def test_a_run_without_a_frozen_schedule_is_refused(tmp_path):
    """A 2.0 manifest names no schedule: nothing about that run was frozen before it ran."""
    run = two_project_run(tmp_path)
    legacy = {"schema_version": "2.0", "run_id": "run-counts", "status": "completed", "created_at": CREATED_AT,
              "config_sha256": digest("config"),
              "pack": json.loads((run / "run-manifest.json").read_text())["pack"], "selection": NO_SELECTION,
              "inputs": [], "systems": [], "invocations": [], "warnings": []}
    validate_document("run-manifest", legacy)
    (run / "run-manifest.json").write_text(canonical_json(legacy) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match="predates frozen schedules"):
        aggregate.aggregate([run])


def test_run_directory_mismatches_are_refused(tmp_path):
    first = two_project_run(tmp_path / "a")
    with pytest.raises(ContractError, match="holds no run-manifest.json"):
        aggregate.aggregate([tmp_path / "a"])
    with pytest.raises(ContractError, match="given more than once"):
        aggregate.aggregate([first, first])
    with pytest.raises(ContractError, match="at least one run directory"):
        aggregate.aggregate([])
    other_pack = write_run(tmp_path / "b", "run-other", five_project_inputs(), pack={**PACK, "version": "2.0.0"})
    with pytest.raises(ContractError, match="froze different packs"):
        aggregate.aggregate([first, other_pack])
    reconfigured = write_run(tmp_path / "c", "run-reconfigured", five_project_inputs(),
                             configs={"sys-a": {"config": {"knob": 2}}})
    with pytest.raises(ContractError, match="configured differently"):
        aggregate.aggregate([first, reconfigured])


def test_a_canonical_target_planned_under_two_projects_is_refused(tmp_path):
    inputs = [planned("one", project="acme/one", targets=[target("T-1", canonical="K", project="acme/one")]),
              planned("two", project="acme/two", targets=[target("T-2", canonical="K", project="acme/two")])]
    run = write_run(tmp_path, "run-split", inputs)

    with pytest.raises(ContractError, match="canonical target K is planned as"):
        aggregate.aggregate([run])


def test_a_bundle_edited_after_review_is_an_unusable_bundle_not_a_score(tmp_path):
    """A result whose bytes no longer match the decisions' binding is a failure with a reason."""
    run = two_project_run(tmp_path)
    result_path = run / "invocations" / "beta-1__sys-a__r1" / "result.json"
    edited = json.loads(result_path.read_text())
    edited["claims"].append({**edited["claims"][0], "claim_id": "c-added"})
    edited["claims"][-1]["rank"] = len(edited["claims"])
    result_path.write_text(canonical_json(edited) + "\n", encoding="utf-8")

    report = aggregate.aggregate([run], policy=policy())

    assert system(view(report))["observations"]["failures"]["unusable_bundle"] == 1
    assert recall(report) == 0.25


def test_a_manifest_recording_an_invocation_its_schedule_never_assigned_is_refused(tmp_path):
    run = two_project_run(tmp_path)
    manifest = json.loads((run / "run-manifest.json").read_text())
    extra = {**manifest["invocations"][0], "invocation_id": "alpha-1__sys-a__r2", "repetition": 2}
    manifest["invocations"].append(extra)
    validate_document("run-manifest", manifest)
    (run / "run-manifest.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match="records invocations its schedule never assigned: alpha-1__sys-a__r2"):
        aggregate.aggregate([run])


def test_a_schedule_that_does_not_bind_to_the_run_configuration_is_refused(tmp_path):
    run = two_project_run(tmp_path)
    config = json.loads((run / "run-config.json").read_text())
    config["timeout_seconds"] = 61
    (run / "run-config.json").write_text(canonical_json(config) + "\n", encoding="utf-8")

    with pytest.raises(ContractError, match="not the configuration its schedule froze"):
        aggregate.aggregate([run])


# --- a run directory written by the runner ------------------------------------------------------


VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
              "assumption, and adds a single-file Python sink for the aggregation tests.")


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "upstream"
    (repo / "src").mkdir(parents=True)
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "src" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    return repo, git("rev-parse", "HEAD", cwd=repo)


class FakeAdapter(Adapter):
    """Returns one claim on the accepted location. Never touches the network."""

    name = "fake"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})

    def prepare(self, spec, cache_root):
        return {"system": spec.system_id}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        native = raw_dir / "native.json"
        native.write_text('{"findings": [{"file": "src/app.py"}]}\n', encoding="utf-8")
        claims = [{"claim_id": "c1", "allegation": "shell=True with a caller-controlled command",
                   "kind": "command_injection", "native_rule_id": "fake.shell", "raw_artifact_id": "native",
                   "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5}}]
        return NativeOutcome(status="success", exit_code=0, command=["fake", "scan"], claims=claims,
                             artifacts=[{"id": "native", "path": native}], tool_versions={"fake": "1.0.0"},
                             capture={"model_requests": "not_applicable"}, notes=["fake run"])


def test_a_run_directory_written_by_the_runner_aggregates_as_draft_evidence(tmp_path, upstream):
    """Two real runs with a fake adapter: the first freezes no plan, the second freezes one.

    The first run's snapshot declares no tree hash, so its schedule froze no plan and its input is
    listed apart. Its frozen pack records the export's tree hash, so a second run from that pack has
    a frozen draft plan: one L1 target, whose one routed candidate stays unresolved in the machine
    draft. Recall is 0 with one pending match, completion 1, and the evidence scope is draft.
    """
    repo, commit = upstream
    pack = cases.new_pack("test", "aggregate-runner", "Local fixture pack for the aggregation tests.")
    cases.add_snapshot(pack, {
        "snapshot_id": "snap-a", "repository": {"url": str(repo), "name": "widget"}, "commit": commit,
        "reference": "Commit chosen by the test fixture; no advisory is claimed.", "languages": ["python"],
        "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}})
    cases.add_case(pack, cases.draft_case(
        "case-a", snapshot_id="snap-a", kind="command_injection",
        description="Caller-controlled command string reaches subprocess with shell=True.",
        represents=REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                 reference="src/app.py", note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "sink", "note": ""}]))
    cases.save_pack(tmp_path / "pack.json", pack)
    config = {"schema_version": "2.1", "run_id": "run-first", "pack": "pack.json", "cache_root": "cache",
              "inputs": [{"snapshot_id": "snap-a"}],
              "systems": [{"system_id": "fake-a", "adapter": "fake", "config": {"knob": 1}}],
              "repetitions": 1, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none"}
    (tmp_path / "run.json").write_text(canonical_json(config) + "\n", encoding="utf-8")
    first = tmp_path / "first"
    run_from_config(tmp_path / "run.json", first, clock=CLOCK, adapters={"fake": FakeAdapter()})

    unplanned = aggregate.aggregate([first], policy=policy())
    assert view(unplanned)["inputs_without_frozen_plan"][0]["input_id"] == "snap-a"
    assert detection(slice_of(system(view(unplanned), "fake-a")))["state"] == "unavailable"
    assert slice_of(system(view(unplanned), "fake-a"))["completion"]["value"] == 1.0

    shutil.copyfile(first / "evaluator" / "pack.json", tmp_path / "pack.json")
    (tmp_path / "run.json").write_text(canonical_json({**config, "run_id": "run-second"}) + "\n", encoding="utf-8")
    second = tmp_path / "second"
    run_from_config(tmp_path / "run.json", second, clock=CLOCK, adapters={"fake": FakeAdapter()})

    report = aggregate.aggregate([second], policy=policy())

    block = system(view(report), "fake-a")
    whole = slice_of(block)
    assert view(report)["evidence_scope"] == "draft" and view(report)["canonical_targets"] == 1
    assert detection(whole)["full_output_recall"]["value"] == 0.0
    assert whole["completion"]["value"] == 1.0
    assert whole["claims"]["records"] == 1 and whole["claims"]["pending_matching"] == 1
    assert block["observations"]["review_states"]["draft"] == 1
    assert report["runs"][0]["timing"]["execution_records"] == 1
