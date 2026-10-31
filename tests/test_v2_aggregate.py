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
import math
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from scaneval import aggregate, cases, review, schedule
from scaneval.adapters.base import Adapter, AdapterError, NativeOutcome
from scaneval.cli import main
from scaneval.contracts import ContractError, canonical_json, canonical_sha256, load_document, validate_document
from scaneval.resampling import Stream, resample_with_replacement
from scaneval.runner import run_from_config


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
CREATED_AT = "2026-09-20T15:00:00+00:00"
REVIEWER = "Fixture Reviewer (fictional)"
WORKLOAD = "conventional_application"
PACK = {"namespace": "org.example", "pack_id": "aggregate-fixture", "version": "1.0.0",
        "sha256": "sha256:" + "a" * 64}
NO_SELECTION = {"only_inputs": None, "only_systems": None, "excluded_inputs": [], "excluded_systems": []}
EXAMPLE_POLICY = Path(__file__).resolve().parents[1] / "examples" / "aggregation-policy.json"


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
            canonical: str | None = None, level: str = "L3", case: str | None = None) -> dict:
    """One planned control as a schedule freezes it; a fixed-target control names its target.

    ``case`` names the case record the control belongs to. A canonical control is registered under one family,
    so the records of one that guard no target must share a case.
    """
    return {"control_id": control_id, "case_id": case or f"case-{target_id or control_id}",
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
         timing=None, execution: bool = True, drop=(), extra=(), scope: str | None = None,
         omitted=None, paths=None, examined_nothing=None, processing=None) -> dict:
    """What one bundle holds.

    ``hits`` maps a target id to the 1-based position of the claim a reviewer accepted for it;
    ``pending`` does the same for an unresolved match; ``controls`` maps a control id to ``"quiet"``,
    ``"unresolved"``, or ``("false_allegation", position)``. ``drop`` leaves frozen targets or controls out
    of the bundle's plan and ``extra`` adds targets to it. ``omitted`` is the list of paths the result says
    its scanner did not examine, ``paths`` maps a control id to the paths its plan gives it, and
    ``examined_nothing`` is the result's statement that no part of its input was shown examined, and ``processing``
    the selection marker the result records for its system; each makes the document that carries it 2.1, and none
    is given by default.
    """
    return {"hits": hits or {}, "claims": claims, "ranking": ranking, "status": status, "resolved": resolved,
            "controls": controls or {}, "pending": pending or {}, "usage": usage or {"wall_seconds": 1.0},
            "review_state": review_state, "timing": timing, "execution": execution, "drop": set(drop),
            "extra": list(extra), "scope": scope, "omitted": omitted, "paths": paths or {},
            "examined_nothing": examined_nothing, "processing": processing}


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
    plan = {"schema_version": "2.1" if spec["paths"] else "2.0", "input_hash": bound,
            "scope": spec["scope"] or items["scope"],
            "targets": [_plan_item(item, "targets") for item in items["targets"]
                        if item["target_id"] not in spec["drop"]] + [_plan_item(item, "targets")
                                                                     for item in spec["extra"]],
            "controls": [{**_plan_item(item, "controls"),
                          **({"paths": spec["paths"][item["control_id"]]} if item["control_id"] in spec["paths"]
                             else {})}
                         for item in items["controls"] if item["control_id"] not in spec["drop"]],
            "review_budgets": items["review_budgets"]}
    positions = list(spec["hits"].values()) + list(spec["pending"].values())
    positions += [value[1] for value in spec["controls"].values() if isinstance(value, tuple)]
    count = spec["claims"] if spec["claims"] is not None else max(positions, default=0)
    native = spec["ranking"] == "native"
    claims = [{"claim_id": f"c{index}", "allegation": f"fixture allegation {index}", "kind": "command_injection",
               "primary_location": {"path": f"src/file{index}.py", "start_line": index, "end_line": index},
               **({"rank": index} if native else {})} for index in range(1, count + 1)]
    usage = dict(spec["usage"])
    result = {"schema_version": "2.1" if usage.get("wall_seconds", 0) is None or spec["omitted"] is not None
              or spec["examined_nothing"] is not None or spec.get("processing") is not None else "2.0",
              "run_id": run_id,
              "system_id": assignment["system_id"], "input_hash": bound, "status": spec["status"],
              "ranking": spec["ranking"], "claims": claims, "bundles_resolved": spec["resolved"], "usage": usage,
              **({"omitted_paths": spec["omitted"]} if spec["omitted"] is not None else {}),
              **({"examined_nothing": spec["examined_nothing"]} if spec["examined_nothing"] is not None else {}),
              **({"processing": spec["processing"]} if spec.get("processing") is not None else {})}
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
              outcomes=None, configs=None, failed_inputs=(), skipped_systems=(), pack=PACK, left_out=(),
              versions=None) -> Path:
    """Write one run directory the way ``scaneval run`` lays it out, with hand-chosen outcomes.

    *outcomes* maps ``(input_id, system_id, repetition)`` to a :func:`scan` spec, or to
    ``"missing_row"`` (the manifest has no row) or ``"missing_bundle"`` (the row names a bundle that
    is not there); unlisted assignments are successful scans that detect nothing. An input in
    *failed_inputs* was never prepared, and a system in *skipped_systems* was never invoked. *left_out*
    names configured inputs the run was narrowed away from, as ``--only-input`` does: the configuration
    keeps them, and the schedule, the manifest, and the manifest's selection say they were left out.
    *versions* maps a system id to the ``adapter_version`` its manifest row records, ``"1.0.0"`` when
    unnamed; ``None`` records none, as the runner does for an adapter it could not resolve.
    """
    outcomes = outcomes or {}
    configs = configs or {}
    versions = versions or {}
    directory = root / run_id
    (directory / "evaluator").mkdir(parents=True)
    entries = [{"system_id": system_id, "adapter": "fake", "config": {"knob": 1}, **configs.get(system_id, {})}
               for system_id in systems]
    config = {"schema_version": "2.1", "run_id": run_id, "pack": "pack.json",
              "inputs": [{"input_id": row["input_id"], "snapshot_id": row["snapshot_id"],
                          **({"profile": "metadata_blinded", "blinding_map": "fixture-map.json"}
                             if row["profile"] == "metadata_blinded" else {})} for row in inputs]
              + [{"input_id": name, "snapshot_id": name} for name in left_out],
              "systems": entries, "repetitions": repetitions, "timeout_seconds": 60, "trace_mode": "off",
              "network_policy": "none"}
    validate_document("run-config", config)
    selection = NO_SELECTION if not left_out else {
        "only_inputs": sorted(row["input_id"] for row in inputs), "only_systems": None,
        "excluded_inputs": list(left_out), "excluded_systems": []}
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
        "notes": ["Hand-built fixture schedule."] + ([
            f"This run was narrowed: {len(left_out)} configured input(s) and 0 configured system(s) are not "
            "scheduled here."] if left_out else [])}
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
        "selection": selection,
        "inputs": [{"input_id": row["input_id"], "mode": "full", "profile": row["profile"],
                    "snapshot_id": row["snapshot_id"],
                    "tree_hash": None if row["input_id"] in failed_inputs else input_hash(row["input_id"]),
                    "input_hash": None if row["input_id"] in failed_inputs else input_hash(row["input_id"]),
                    "provenance_path": None, "mechanical_checks": [],
                    "preparation_failure": ({"type": "MaterializationError", "message": "fixture export refused"}
                                            if row["input_id"] in failed_inputs else None)} for row in inputs],
        "systems": [{"system_id": entry["system_id"], "adapter": entry["adapter"],
                     "adapter_version": versions.get(entry["system_id"], "1.0.0"), "preparation": {},
                     "skipped_reason": ("AdapterError: fixture system not installed"
                                        if entry["system_id"] in skipped_systems else None)} for entry in entries],
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


def test_targets_per_input_counts_canonical_targets_and_not_the_alias_records_of_one(tmp_path):
    """One input plans a CVE record and a GHSA record of a single root cause, X, beside a target Y.

    a1 has three records and two canonical targets (X and Y); a2 has one. Counting records would report inputs
    with 3 and 1 targets, and a canonical target multiplied by its aliases; the count is 2 and 1, and the view
    holds 3 canonical targets in all (X, Y, and a2's).
    """
    inputs = [planned("a1", targets=[target("CVE-1", canonical="X"), target("GHSA-1", canonical="X"),
                                     target("T-2", canonical="Y")]),
              planned("a2", targets=[target("T-3")])]
    run = write_run(tmp_path, "run-aliases", inputs)

    report = aggregate.aggregate([run], policy=policy())

    assert view(report)["canonical_targets"] == 3
    assert view(report)["targets_per_input"] == [{"targets": 1, "inputs": 1}, {"targets": 2, "inputs": 1}]


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


def test_a_scan_the_manifest_records_as_run_stays_in_usage_and_claim_volume_when_its_bundle_is_gone(tmp_path):
    """An executed scan with a missing or unusable bundle spent something and delivered something: unknown, not zero.

    Five inputs, one system. ok ran and reads (4 s, $0.50, 2 claims). gone's manifest row names a bundle that is not
    there. edited delivered 40 claims, and its result was re-saved with another cost after review, so it no longer
    binds to its decisions and the bundle is unusable. norow has no manifest row and prep was never prepared, so
    neither of those ran.
    - Executed scans: ok, gone, and edited, 3 of the 5 assignments, of which 1 bundle reads.
    - Wall time is known for 1 and unknown for 2. Cost is known for 1 of 3, a coverage of 1/3, not 1 of 1.
    - Claim volume: 3 executed, 1 bundle read, 2 records over 5 assignments; the volume of gone and edited is
      in no sum, because it is unknown.
    - Slices count the same way: gone alone is 1 executed scan with no known cost, coverage 0, and norow alone
      has no executed scan, so its coverage is undefined.
    """
    inputs = [planned(f"i-{name}", project=f"acme/{name}", targets=[target(f"T-{name}", project=f"acme/{name}")])
              for name in ("ok", "gone", "edited", "norow", "prep")]
    run = write_run(tmp_path, "run-executed", inputs, failed_inputs=("i-prep",), outcomes={
        ("i-ok", "sys-a", 1): scan(hits={"T-ok": 1}, claims=2, usage={"wall_seconds": 4.0, "cost_usd": 0.5}),
        ("i-gone", "sys-a", 1): "missing_bundle",
        ("i-edited", "sys-a", 1): scan(hits={"T-edited": 1}, claims=40, usage={"wall_seconds": 3.0, "cost_usd": 0.25}),
        ("i-norow", "sys-a", 1): "missing_row"})
    result_path = run / "invocations" / "i-edited__sys-a__r1" / "result.json"
    edited = json.loads(result_path.read_text())
    edited["usage"]["cost_usd"] = 5.01
    result_path.write_text(canonical_json(edited) + "\n", encoding="utf-8")

    report = aggregate.aggregate([run], policy=policy())

    block = system(view(report))
    whole = slice_of(block)
    assert block["observations"]["failures"] == {"failed_preparation": 1, "skipped_system": 0, "skipped": 0,
                                                 "missing_row": 1, "missing_bundle": 1, "unusable_bundle": 1}
    assert whole["usage"]["cost_usd"] == {"known_sum": 0.5, "known": 1, "unknown": 2, "coverage": 1 / 3}
    assert whole["usage"]["wall_seconds"] == {"known_sum": 4.0, "known": 1, "unknown": 2}
    assert (whole["usage"]["bundles"], whole["usage"]["executed"]) == (1, 3)
    claims = whole["claims"]
    assert (claims["bundles"], claims["executed"], claims["assignments"], claims["records"]) == (1, 3, 5, 2)
    gone = slice_of(block, "project", "acme/gone")
    assert (gone["usage"]["bundles"], gone["usage"]["executed"]) == (0, 1)
    assert gone["usage"]["cost_usd"] == {"known_sum": None, "known": 0, "unknown": 1, "coverage": 0.0}
    assert (gone["claims"]["bundles"], gone["claims"]["executed"]) == (0, 1)
    norow = slice_of(block, "project", "acme/norow")
    assert norow["usage"]["executed"] == 0 and norow["usage"]["cost_usd"]["coverage"] is None
    assert any("2 of them ran, so their claim volume, wall time, and cost are unknown, not zero" in warning
               for warning in view(report)["warnings"])


def test_cost_is_summed_exactly_from_the_decimals_the_scanners_wrote(tmp_path):
    """sys-a's two scans report $0.10 and $0.20 and sys-b's $0.70 and $0.10: exactly 3/10 and 4/5 as written.

    As binary floats 0.1 + 0.2 and math.fsum([0.1, 0.2]) are both 0.30000000000000004, and fsum([0.7, 0.1]) is
    0.7999999999999999, because the doubles nearest the decimals do not add to the double nearest their sum. The
    cost a gate holds to a limit is read as the decimals the scanners wrote, summed exactly, and rounded once, so
    the sums are 0.3 and 0.8.
    """
    assert 0.1 + 0.2 != 0.3 and math.fsum([0.1, 0.2]) != 0.3 and math.fsum([0.7, 0.1]) != 0.8, "the float sums"
    run = write_run(tmp_path, "run-exact-cost", five_project_inputs()[:2], systems=("sys-a", "sys-b"), outcomes={
        ("p1", "sys-a", 1): scan(usage={"wall_seconds": 1.0, "cost_usd": 0.1}),
        ("p2", "sys-a", 1): scan(usage={"wall_seconds": 1.0, "cost_usd": 0.2}),
        ("p1", "sys-b", 1): scan(usage={"wall_seconds": 1.0, "cost_usd": 0.7}),
        ("p2", "sys-b", 1): scan(usage={"wall_seconds": 1.0, "cost_usd": 0.1})})

    report = aggregate.aggregate([run], policy=policy())

    cost = {name: slice_of(system(view(report), name))["usage"]["cost_usd"] for name in ("sys-a", "sys-b")}
    assert cost["sys-a"] == {"known_sum": 0.3, "known": 2, "unknown": 0, "coverage": 1.0}
    assert cost["sys-b"] == {"known_sum": 0.8, "known": 2, "unknown": 0, "coverage": 1.0}


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

    assert whole["clusters"] == {"targets": 5, "pairs": 0, "controls": 5}
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


def test_a_frozen_control_missing_from_a_completed_scans_plan_is_completed_and_unresolved_not_dropped(tmp_path):
    """Ten scans succeed; seven bundle plans hold the input's control (quiet) and three lack it.

    A control is frozen before the run, and each scan completed in the frozen scope, so c = 1 for all ten
    (math section 2), while b = 0 for the three with no assessment of it.
    - C = 10/10 = 1 and A = 7/10; nothing is confirmed false, so E = 0 and the resolved rate E/A is 0.
    - The completed bounds [E/C, (E + C - A)/C] are [0, 3/10]: the three count as unresolved, and as false in F+.
    - Counts: 10 observations, 10 completed, 7 resolved, 3 unresolved, and 3 unscored.
    Taking the three out of C would have made C = 7/10 and F+ = 0, a lower bound bought with bundles that
    lack the assessment.
    """
    inputs = [planned(f"safe-{index}", project=f"acme/safe{index % 5}", controls=[control(f"C-{index}")])
              for index in range(10)]
    run = write_run(tmp_path, "run-unscored-controls", inputs, outcomes={
        (f"safe-{index}", "sys-a", 1): scan(drop=(f"C-{index}",)) for index in range(7, 10)})

    block = slice_of(system(view(aggregate.aggregate([run], policy=policy()))))["controls"]["capability_safe"]

    assert (block["observations"], block["completed"], block["resolved"], block["unresolved"]) == (10, 10, 7, 3)
    assert block["unscored"] == 3
    assert block["completed_mass"] == 1.0 and block["assessable_mass"] == 0.7
    assert block["resolved_rate"]["value"] == 0.0
    assert block["completed_lower"] == 0.0 and block["completed_upper"]["value"] == 0.3


def test_a_quiet_control_on_a_path_its_scan_did_not_examine_is_completed_and_unresolved_not_dropped(tmp_path):
    """The reviewer's change touches only tests/server.test.js, DeepSec's filter drops it, and the scan succeeds.

    One input freezes one safe control. Its bundle's plan says the control is on tests/server.test.js, the result
    lists that path as not examined, and the reviewer assessed the control quiet. The scan completed in the frozen
    scope (c = 1) and nothing resolved the control (b = 0), where the quiet assessment used to (b = 1).
    - C = 1 and A = 0, and nothing is confirmed false, so E = 0 and the resolved rate E/A is undefined.
    - The completed bounds [E/C, (E + C - A)/C] are [0, 1], where they were [0, 0]: the control counts as false in F+.
    - Counts: 1 observation, completed and unresolved, and not unscored, since the plan holds it. Dropping it from the
      completed mass would have made C = 0 and left no bound at all.
    """
    run = write_run(tmp_path, "run-omitted", [planned("safe", controls=[control("C-server-test")])], outcomes={
        ("safe", "sys-a", 1): scan(paths={"C-server-test": ["tests/server.test.js"]},
                                   omitted=["tests/server.test.js"])})

    block = safe_controls(aggregate.aggregate([run], policy=policy()))

    assert block["canonical_controls"] == 1
    assert (block["observations"], block["completed"], block["resolved"], block["unresolved"]) == (1, 1, 0, 1)
    assert block["unscored"] == 0 and block["false_allegations"] == 0
    assert block["completed_mass"] == 1.0 and block["assessable_mass"] == 0.0
    assert block["resolved_rate"]["value"] is None
    assert block["completed_lower"] == 0.0 and block["completed_upper"]["value"] == 1.0


def test_only_a_control_on_an_omitted_path_or_placed_nowhere_loses_its_quiet_credit_in_a_corpus(tmp_path):
    """Four safe controls in four projects, each assessed quiet over a successful scan, and equal weights of 1/4.

    - C-omitted is on a path its result lists as not examined: completed, unresolved.
    - C-read is on src/b.js while the result lists tests/b.test.js: examined, so resolved quiet.
    - C-unplaced has no paths in its plan and its result lists README.md: it cannot be shown to be outside the
      omission, so it is completed and unresolved.
    - C-nothing-omitted has no paths either, but its result lists an empty set: nothing was left out, so resolved.
    Then C = 1 and A = 1/2, E = 0: the resolved rate is 0 and the completed bounds are [0, (0 + 1 - 1/2)/1] = [0, 0.5].
    Counts: 4 observations, 4 completed, 2 resolved, 2 unresolved, none unscored.
    """
    controls = {"omitted": "C-omitted", "read": "C-read", "unplaced": "C-unplaced", "nothing": "C-nothing-omitted"}
    inputs = [planned(name, project=f"acme/{name}", controls=[control(control_id)])
              for name, control_id in controls.items()]
    run = write_run(tmp_path, "run-corpus-omissions", inputs, outcomes={
        ("omitted", "sys-a", 1): scan(paths={"C-omitted": ["tests/a.test.js"]}, omitted=["tests/a.test.js"]),
        ("read", "sys-a", 1): scan(paths={"C-read": ["src/b.js"]}, omitted=["tests/b.test.js"]),
        ("unplaced", "sys-a", 1): scan(omitted=["README.md"]),
        ("nothing", "sys-a", 1): scan(omitted=[])})

    block = safe_controls(aggregate.aggregate([run], policy=policy()))

    assert block["canonical_controls"] == 4
    assert (block["observations"], block["completed"], block["resolved"], block["unresolved"]) == (4, 4, 2, 2)
    assert block["unscored"] == 0 and block["false_allegations"] == 0
    assert block["completed_mass"] == 1.0 and block["assessable_mass"] == 0.5
    assert block["resolved_rate"]["value"] == 0.0
    assert block["completed_lower"] == 0.0 and block["completed_upper"]["value"] == 0.5


def test_a_quiet_control_on_an_unchanged_file_is_completed_and_unresolved_when_its_scan_examined_nothing(tmp_path):
    """The reviewer's change again, with the safe control in src/server.js, a file the change does not touch.

    The result lists tests/server.test.js as not examined and says no part of the change was, and the plan places the
    one frozen control on the unchanged file, so no list of the change's paths names it. It was resolved quiet, and
    it is now a completed observation that nothing resolved, as the control on the omitted path is.
    - C = 1 and A = 0, and nothing is confirmed false, so E = 0 and the resolved rate E/A is undefined.
    - The completed bounds [E/C, (E + C - A)/C] are [0, 1], where they were [0, 0]: F+ counts the control as false.
    """
    run = write_run(tmp_path, "run-examined-nothing", [planned("safe", controls=[control("C-server")])], outcomes={
        ("safe", "sys-a", 1): scan(paths={"C-server": ["src/server.js"]}, omitted=["tests/server.test.js"],
                                   examined_nothing=True)})

    block = safe_controls(aggregate.aggregate([run], policy=policy()))

    assert block["canonical_controls"] == 1
    assert (block["observations"], block["completed"], block["resolved"], block["unresolved"]) == (1, 1, 0, 1)
    assert block["unscored"] == 0 and block["false_allegations"] == 0
    assert block["completed_mass"] == 1.0 and block["assessable_mass"] == 0.0
    assert block["resolved_rate"]["value"] is None
    assert block["completed_lower"] == 0.0 and block["completed_upper"]["value"] == 1.0


def test_only_a_scan_that_examined_nothing_loses_the_quiet_credit_of_its_control_on_an_unchanged_file(tmp_path):
    """Three safe controls in three projects, each on src/server.js and assessed quiet, with equal weights of 1/3.

    Each result lists the one path its change touched as not examined. Only the first also says nothing was examined.
    - C-nothing: unresolved. C-some says some was examined, and C-silent says nothing about it: resolved quiet.
    Then C = 1 and A = 2/3, E = 0: the resolved rate is 0 and the completed bounds are [0, (0 + 1 - 2/3)/1] = [0, 1/3].
    """
    controls = {"nothing": "C-nothing", "some": "C-some", "silent": "C-silent"}
    inputs = [planned(name, project=f"acme/{name}", controls=[control(control_id)])
              for name, control_id in controls.items()]
    on_server = {control_id: ["src/server.js"] for control_id in controls.values()}
    run = write_run(tmp_path, "run-corpus-examined-nothing", inputs, outcomes={
        ("nothing", "sys-a", 1): scan(paths={"C-nothing": on_server["C-nothing"]}, omitted=["tests/a.test.js"],
                                      examined_nothing=True),
        ("some", "sys-a", 1): scan(paths={"C-some": on_server["C-some"]}, omitted=["tests/b.test.js"],
                                   examined_nothing=False),
        ("silent", "sys-a", 1): scan(paths={"C-silent": on_server["C-silent"]}, omitted=["tests/c.test.js"])})

    block = safe_controls(aggregate.aggregate([run], policy=policy()))

    assert block["canonical_controls"] == 3
    assert (block["observations"], block["completed"], block["resolved"], block["unresolved"]) == (3, 3, 2, 1)
    assert block["unscored"] == 0 and block["false_allegations"] == 0
    assert block["completed_mass"] == 1.0 and abs(block["assessable_mass"] - 2 / 3) < 1e-12
    assert block["resolved_rate"]["value"] == 0.0
    assert block["completed_lower"] == 0.0 and abs(block["completed_upper"]["value"] - 1 / 3) < 1e-12


def alias_control_run(root: Path, run_id: str, **choices) -> Path:
    """One input freezes two records, C-1 and C-2, of one canonical safe control; one system scans it once.

    The records belong to one case, so the canonical control has one family. *choices* are the arguments of
    :func:`scan`: the scan succeeds with resolved bundles unless they say otherwise, and ``drop`` leaves a
    record out of the bundle's plan.
    """
    records = [control(name, canonical="C", case="case-C") for name in ("C-1", "C-2")]
    return write_run(root, run_id, [planned("safe", controls=records)],
                     outcomes={("safe", "sys-a", 1): scan(**choices)})


def safe_controls(report: dict) -> dict:
    """The capability-safe control block of a report's whole view, for its one system."""
    return slice_of(system(view(report)))["controls"]["capability_safe"]


def test_a_quiet_assessment_of_one_alias_of_a_control_leaves_it_unresolved_while_another_alias_is_unplanned(tmp_path):
    """Two frozen records of one safe control, C-1 and C-2; the bundle's plan holds C-1 only, assessed quiet.

    The scan succeeded with resolved bundles, so the control was observed in the frozen scope (c = 1); C-2 was
    never assessed, so the control has no resolved assessment (b = 0) however quiet C-1 was.
    - C = 1 and A = 0, and nothing is confirmed false, so E = 0 and the resolved rate E/A is undefined.
    - The completed bounds [E/C, (E + C - A)/C] are [0, 1]: the control counts as false in F+.
    - Counts: 1 observation, completed, unresolved, and unscored; the schedule froze one item the plan lacks.
    Crediting C-1's quiet to the control made A = 1, a resolved rate of 0, and F+ = 0.
    """
    run = alias_control_run(tmp_path, "run-alias-quiet", drop=("C-2",))

    report = aggregate.aggregate([run], policy=policy())

    block = safe_controls(report)
    assert block["canonical_controls"] == 1
    assert (block["observations"], block["completed"], block["resolved"], block["unresolved"]) == (1, 1, 0, 1)
    assert block["unscored"] == 1 and block["false_allegations"] == 0
    assert block["completed_mass"] == 1.0 and block["assessable_mass"] == 0.0
    assert block["resolved_rate"]["value"] is None
    assert block["completed_lower"] == 0.0 and block["completed_upper"]["value"] == 1.0
    assert system(view(report))["observations"]["unscored_items"] == 1


def test_a_false_allegation_on_one_alias_of_a_control_stands_while_another_alias_is_unplanned(tmp_path):
    """The same two records and a plan holding C-1 only, but the reviewer confirmed a false allegation on C-1.

    A false allegation about the control is evidence of a false alarm whether or not C-2 was ever assessed, so
    the control is resolved, and false: c = b = 1 and e = 1.
    - C = A = 1 and E = 1: the resolved rate E/A is 1 and the completed bounds are [1, (1 + 1 - 1)/1] = [1, 1].
    - Counts: 1 observation, completed, resolved, and false; it is still unscored, for the record C-2 lacks.
    """
    run = alias_control_run(tmp_path, "run-alias-false", drop=("C-2",), controls={"C-1": ("false_allegation", 1)})

    block = safe_controls(aggregate.aggregate([run], policy=policy()))

    assert (block["observations"], block["completed"], block["resolved"], block["unresolved"]) == (1, 1, 1, 0)
    assert block["false_allegations"] == 1 and block["observed_false_allegations"] == 1
    assert block["unscored"] == 1
    assert block["completed_mass"] == 1.0 and block["assessable_mass"] == 1.0
    assert block["resolved_rate"]["value"] == 1.0
    assert block["completed_lower"] == 1.0 and block["completed_upper"]["value"] == 1.0


def test_a_control_is_resolved_quiet_when_every_alias_the_schedule_froze_was_assessed_quiet(tmp_path):
    """The same two records, both in the bundle's plan: the credit an unplanned alias withholds is granted here.

    Both quiet: c = b = 1, so C = A = 1 and E = 0, the resolved rate is 0, and the completed bounds are
    [0, (0 + 1 - 1)/1] = [0, 0]. Counts: 1 observation, completed, and resolved; nothing is unscored.
    With the reviewer leaving C-2 unresolved instead, one record of the control is unsettled, as it is when C-2 is
    absent from the plan: b = 0, so A = 0, the resolved rate is undefined, and F+ = (0 + 1 - 0)/1 = 1.
    """
    quiet = safe_controls(aggregate.aggregate([alias_control_run(tmp_path, "run-alias-both")], policy=policy()))
    unsettled = safe_controls(aggregate.aggregate(
        [alias_control_run(tmp_path, "run-alias-unsettled", controls={"C-2": "unresolved"})], policy=policy()))

    assert (quiet["observations"], quiet["completed"], quiet["resolved"], quiet["unresolved"]) == (1, 1, 1, 0)
    assert quiet["unscored"] == 0 and quiet["false_allegations"] == 0
    assert quiet["assessable_mass"] == 1.0 and quiet["resolved_rate"]["value"] == 0.0
    assert quiet["completed_lower"] == 0.0 and quiet["completed_upper"]["value"] == 0.0
    assert (unsettled["completed"], unsettled["resolved"], unsettled["unresolved"]) == (1, 0, 1)
    assert unsettled["unscored"] == 0 and unsettled["assessable_mass"] == 0.0
    assert unsettled["resolved_rate"]["value"] is None and unsettled["completed_upper"]["value"] == 1.0


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
    - Q's interval resamples the five projects that carry a frozen pair, from the stream labelled
      .../all/pairs, never acme/lonely: a replicate's Q is the share of its five draws on pair1.
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
    whole = slice_of(system(view(report)))
    assert whole["clusters"] == {"targets": 6, "pairs": 5, "controls": 5}
    replicates = share_of_draws(0, "pairs", [f"acme/pair{index}" for index in range(1, 6)], {"acme/pair1"})
    assert pairs["interval"] == {"state": "ok", "lower": replicates[4], "upper": replicates[194], "clusters": 5}


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


def test_a_pending_match_leaves_the_random_order_diagnostic_unmeasured_and_counts_as_pending(tmp_path):
    """Three unranked scans with resolved bundles, one target each, equal weights 1/3.

    u1 delivers 3 claims and its match on T1 is pending. u2 delivers 4, of which the reviewer accepted the
    second for T2. u3 delivers 4, accepted the first for T3, and left a match on its third pending. While a match
    is unresolved the accepted count is only a lower bound, so the expectation for that target is not measured:
    u1 and u3 leave the observation mass and count in the pending mass, and are not read as an expectation of 0
    or of the accepted claims alone.
    - Measured: u2 only. At B = 1, 1 - C(3,1)/C(4,1) = 1/4; at B = 5, b = min(5, 4) = 4 and the expectation is 1.
    - observation_mass = 1/3 and pending_mass = 2/3; the expected recall is the measured mass's: 1/4 and 1.
    Full-output recall is untouched by the diagnostic: u2 and u3 hit, so 2/3, and u1's pending match is not
    assessable.
    """
    inputs = [planned(f"u{index}", targets=[target(f"T{index}")]) for index in (1, 2, 3)]
    run = write_run(tmp_path, "run-pending-random", inputs, outcomes={
        ("u1", "sys-a", 1): scan(ranking="unranked", claims=3, pending={"T1": 2}),
        ("u2", "sys-a", 1): scan(ranking="unranked", claims=4, hits={"T2": 2}),
        ("u3", "sys-a", 1): scan(ranking="unranked", claims=4, hits={"T3": 1}, pending={"T3": 3})})

    block = detection(slice_of(system(view(aggregate.aggregate([run], policy=policy())))))

    diagnostic = block["random_order_diagnostic"]
    assert diagnostic["observation_mass"] == 1 / 3 and diagnostic["pending_mass"] == 2 / 3
    assert diagnostic["expected_recall"] == [{"budget": 1, "value": 0.25}, {"budget": 5, "value": 1.0}]
    assert block["full_output_recall"]["value"] == 2 / 3
    assert block["coverage"]["assessable_mass"] == 2 / 3


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


def alias_target_run(root: Path, run_id: str, **choices) -> Path:
    """One input freezes two records, CVE-1 and GHSA-1, of one canonical target; one system scans it once.

    *choices* are the arguments of :func:`scan`: the scan succeeds with native-ranked, resolved bundles unless
    they say otherwise, and ``drop`` leaves a record out of the bundle's plan.
    """
    records = [target("CVE-1", canonical="X"), target("GHSA-1", canonical="X")]
    return write_run(root, run_id, [planned("widget", targets=records)],
                     outcomes={("widget", "sys-a", 1): scan(**choices)})


def test_a_target_hit_through_one_alias_is_detected_and_assessable_while_another_alias_is_unplanned(tmp_path):
    """CVE-1 and GHSA-1 are two records of one root cause; the bundle's plan holds CVE-1 only, and claim 1 hit it.

    A hit on any record detects the canonical target, and the record the plan lacks cannot undo it: recall is 1, the
    first hit is at rank 1, and the observation is completed and assessable (a confirmed hit is a resolved outcome).
    It is still unscored, for the record the plan lacks: the one target observation is completed, assessable,
    detected, and unscored, so the assessable mass and the unscored mass are both 1.
    """
    run = alias_target_run(tmp_path, "run-alias-hit", hits={"CVE-1": 1}, drop=("GHSA-1",))

    report = aggregate.aggregate([run], policy=policy())

    block = detection(slice_of(system(view(report))))
    assert block["full_output_recall"]["value"] == 1.0 and budget(block, 1)["value"] == 1.0
    coverage = block["coverage"]
    assert (coverage["target_observations"], coverage["completed"], coverage["assessable"],
            coverage["detected"], coverage["unscored"]) == (1, 1, 1, 1, 1)
    assert coverage["assessable_mass"] == 1.0 and coverage["unscored_mass"] == 1.0
    assert system(view(report))["first_hit_ranks"]["ranks"] == [{"rank": 1, "target_observations": 1}]


def test_a_miss_on_one_alias_of_a_target_is_not_assessable_while_another_alias_is_unplanned(tmp_path):
    """The same two records and a plan holding CVE-1 only, but no claim hit it.

    The scan completed with resolved bundles, yet GHSA-1 was never scored and may have been hit, so the miss on CVE-1
    is no resolved outcome for the root cause. The observation stays in the denominators as a miss, and it is unscored.
    - Recall is 0, and the one target observation is completed and unscored, neither detected nor assessable.
    - The completed mass is 1 and the unscored mass 1, but the assessable mass is 0: crediting the miss as resolved
      made it 1.
    With both records in the plan the same scan is a resolved miss: assessable, nothing unscored.
    """
    partial = aggregate.aggregate([alias_target_run(tmp_path, "run-alias-miss", drop=("GHSA-1",))],
                                  policy=policy())
    whole = aggregate.aggregate([alias_target_run(tmp_path, "run-alias-both-miss")], policy=policy())

    block = detection(slice_of(system(view(partial))))
    assert block["full_output_recall"]["value"] == 0.0
    coverage = block["coverage"]
    assert (coverage["target_observations"], coverage["completed"], coverage["assessable"],
            coverage["detected"], coverage["unscored"]) == (1, 1, 0, 0, 1)
    assert coverage["completed_mass"] == 1.0 and coverage["unscored_mass"] == 1.0
    assert coverage["assessable_mass"] == 0.0
    assert system(view(partial))["first_hit_ranks"]["not_detected"] == 1
    resolved = detection(slice_of(system(view(whole))))["coverage"]
    assert (resolved["completed"], resolved["assessable"], resolved["unscored"]) == (1, 1, 0)
    assert resolved["assessable_mass"] == 1.0 and resolved["unscored_mass"] == 0.0


def test_an_unplanned_alias_leaves_the_random_order_diagnostic_unmeasured_like_a_pending_match(tmp_path):
    """An unranked scan delivers 4 claims and a reviewer accepted the second for CVE-1; GHSA-1 is planned or not.

    With both records in the plan the observation is measured: one accepted claim among 4, so at B = 1 the expectation
    is 1 - C(3,1)/C(4,1) = 1/4 and at B = 5, b = min(5, 4) = 4 and it is 1; the observation mass is 1, the pending 0.
    With GHSA-1 absent the accepted claims are only a lower bound, as under a pending match: the observation leaves
    the observation mass and counts in the pending mass, and no expectation is reported for it. Recall is the same
    either way, because CVE-1's hit detects the target.
    """
    scanned = {"hits": {"CVE-1": 2}, "claims": 4, "ranking": "unranked"}
    partial = aggregate.aggregate([alias_target_run(tmp_path, "run-alias-random", drop=("GHSA-1",), **scanned)],
                                  policy=policy())
    whole = aggregate.aggregate([alias_target_run(tmp_path, "run-alias-random-both", **scanned)], policy=policy())

    measured = detection(slice_of(system(view(whole))))["random_order_diagnostic"]
    assert measured["observation_mass"] == 1.0 and measured["pending_mass"] == 0.0
    assert measured["expected_recall"] == [{"budget": 1, "value": 0.25}, {"budget": 5, "value": 1.0}]
    block = detection(slice_of(system(view(partial))))
    unmeasured = block["random_order_diagnostic"]
    assert unmeasured["observation_mass"] == 0.0 and unmeasured["pending_mass"] == 1.0
    assert unmeasured["expected_recall"] == [{"budget": 1, "value": None}, {"budget": 5, "value": None}]
    assert block["full_output_recall"]["value"] == 1.0
    assert block["coverage"]["assessable_mass"] == 1.0


def test_a_target_the_bundle_plan_holds_no_record_of_is_pending_in_the_random_order_diagnostic(tmp_path):
    """An unranked scan delivers 4 claims and none was accepted; the plan holds both records, one, or neither.

    A record the plan lacks was never scored, so the accepted claims are only a lower bound and no expectation is
    read for it, whether one record is absent or all of them are: the observation leaves the observation mass and
    counts in the pending mass. Every unranked valid output is measured or pending, so the two masses add to 1.
    - Both records planned: measured, observation mass 1 and pending mass 0; nothing was accepted, so 0 at B = 1 and 5.
    - GHSA-1 absent, or CVE-1 and GHSA-1 both absent: observation mass 0 and pending mass 1, and no expectation.
    - A target of one record, absent: the same, so absence of any size is pending.
    With every record absent the target is unscored and not assessable, and still a miss in recall (0). A partial scan
    still delivers valid output, so it is pending like a successful one; a scan that timed out delivered none to
    measure, so it is neither measured nor pending.
    """
    scanned = {"claims": 4, "ranking": "unranked"}

    def detected(run: Path) -> dict:
        return detection(slice_of(system(view(aggregate.aggregate([run], policy=policy())))))

    def masses(block: dict) -> tuple[float, float]:
        diagnostic = block["random_order_diagnostic"]
        return diagnostic["observation_mass"], diagnostic["pending_mass"]

    both = detected(alias_target_run(tmp_path, "run-random-both", **scanned))
    one = detected(alias_target_run(tmp_path, "run-random-one", drop=("GHSA-1",), **scanned))
    neither = detected(alias_target_run(tmp_path, "run-random-neither", drop=("CVE-1", "GHSA-1"), **scanned))
    lone = detected(write_run(tmp_path, "run-random-lone", [planned("widget", targets=[target("T-1")])],
                              outcomes={("widget", "sys-a", 1): scan(drop=("T-1",), **scanned)}))
    partial = detected(alias_target_run(tmp_path, "run-random-partial", drop=("CVE-1", "GHSA-1"), status="partial",
                                        **scanned))
    stopped = detected(alias_target_run(tmp_path, "run-random-timeout", drop=("CVE-1", "GHSA-1"), status="timeout",
                                        resolved=False, **scanned))

    assert masses(both) == (1.0, 0.0)
    assert both["random_order_diagnostic"]["expected_recall"] == [{"budget": 1, "value": 0.0},
                                                                   {"budget": 5, "value": 0.0}]
    assert masses(one) == (0.0, 1.0) and masses(neither) == (0.0, 1.0) and masses(lone) == (0.0, 1.0)
    assert masses(partial) == (0.0, 1.0)
    assert neither["random_order_diagnostic"]["expected_recall"] == [{"budget": 1, "value": None},
                                                                      {"budget": 5, "value": None}]
    assert neither["full_output_recall"]["value"] == 0.0
    coverage = neither["coverage"]
    assert (coverage["unscored"], coverage["assessable"]) == (1, 0)
    assert coverage["unscored_mass"] == 1.0 and coverage["assessable_mass"] == 0.0
    assert masses(stopped) == (0.0, 0.0)


def test_a_pair_is_resolved_through_an_alias_only_by_a_hit_while_another_alias_is_unplanned(tmp_path):
    """The vulnerable input freezes CVE-1 and GHSA-1 (one root cause, X); the fixed input a control of CVE-1, quiet.

    In both runs the vulnerable bundle's plan holds CVE-1 only.
    - No claim hit CVE-1: GHSA-1 was never scored, so the vulnerable side is not assessable and the pair is
      unresolved: it has no outcome, the resolved pairs and the assessable mass are 0, and Q = 0. Crediting the miss
      as resolved made the pair 'both silent'.
    - Claim 1 hit CVE-1: the hit is a resolved outcome whatever GHSA-1 would have said, so the pair is resolved and
      correct: Q = 1, with one resolved pair.
    """
    inputs = [planned("vulnerable", targets=[target("CVE-1", canonical="X"), target("GHSA-1", canonical="X")]),
              planned("fixed", controls=[control("C-fixed", kind="fixed_target", target_id="CVE-1")])]
    missed = write_run(tmp_path, "run-pair-miss", inputs,
                       outcomes={("vulnerable", "sys-a", 1): scan(drop=("GHSA-1",))})
    hit = write_run(tmp_path, "run-pair-hit", inputs,
                    outcomes={("vulnerable", "sys-a", 1): scan(hits={"CVE-1": 1}, drop=("GHSA-1",))})

    unresolved = detection(slice_of(system(view(aggregate.aggregate([missed], policy=policy())))))["pairs"]
    correct = detection(slice_of(system(view(aggregate.aggregate([hit], policy=policy())))))["pairs"]

    assert (unresolved["pairable_targets"], unresolved["repetition_pairs"], unresolved["resolved_pairs"]) == (1, 1, 0)
    assert unresolved["assessable_mass"] == 0.0 and unresolved["value"] == 0.0
    assert all(item["pairs"] == 0 for item in unresolved["outcomes"].values())
    assert (correct["repetition_pairs"], correct["resolved_pairs"]) == (1, 1)
    assert correct["assessable_mass"] == 1.0 and correct["value"] == 1.0
    assert correct["outcomes"]["correct"]["pairs"] == 1


def alias_pair_run(root: Path, run_id: str, *, canonical=("K", "K"), **fixed) -> Path:
    """Two frozen pairs whose fixed states are two records of one control; one system scans each input once.

    The vulnerable input freezes T-CVE and T-GHSA, two records of one root cause X, and the fixed input a fixed-target
    control of each: C-CVE of T-CVE and C-GHSA of T-GHSA, whose canonical ids are the two in *canonical* (both K by
    default, so one control). The schedule freezes the pairs (T-CVE, C-CVE) and (T-GHSA, C-GHSA), and the vulnerable
    scan accepts claim 1 for T-CVE, so the vulnerable side of both is a resolved hit whatever the fixed side says.
    *fixed* are the arguments of :func:`scan` for the fixed input, which succeeds with resolved bundles by default.
    """
    vulnerable = planned("vulnerable", targets=[target("T-CVE", canonical="X"), target("T-GHSA", canonical="X")])
    fixed_input = planned("fixed", controls=[
        control("C-CVE", kind="fixed_target", target_id="T-CVE", canonical=canonical[0]),
        control("C-GHSA", kind="fixed_target", target_id="T-GHSA", canonical=canonical[1])])
    return write_run(root, run_id, [vulnerable, fixed_input], outcomes={
        ("vulnerable", "sys-a", 1): scan(hits={"T-CVE": 1}), ("fixed", "sys-a", 1): scan(**fixed)})


def pair_block(report: dict) -> dict:
    """The pair correctness block of a report's whole view, for its one system."""
    return detection(slice_of(system(view(report))))["pairs"]


def fixed_controls(report: dict) -> dict:
    """The fixed-target control block of a report's whole view, for its one system."""
    return slice_of(system(view(report)))["controls"]["fixed_target"]


def test_a_pair_is_unresolved_while_an_alias_of_its_fixed_state_control_is_unplanned_or_unresolved(tmp_path):
    """C-CVE and C-GHSA are two records of one control K; C-CVE is assessed quiet and C-GHSA is absent or unsettled.

    K was never fully assessed, so the fixed_target block counts it completed and unresolved (F+ = 1): it is unscored
    when the bundle's plan drops C-GHSA, and not when the reviewer leaves C-GHSA unresolved. A pair earns no credit for
    a control that block counts as unresolved, and the vulnerable side (a hit on T-CVE) is a resolved hit in both pairs.
    - Neither pair is resolved: no outcome, resolved pairs 0, assessable mass 0, and Q = 0 over the two pairs.
    Reading each pair's own record alone resolved (T-CVE, C-CVE) as correct: one resolved pair of two, so the
    assessable mass and Q were 1/2, beside a fixed_target block that counted the control unresolved.
    """
    dropped = aggregate.aggregate([alias_pair_run(tmp_path, "run-pair-alias-dropped", drop=("C-GHSA",))],
                                  policy=policy())
    unsettled = aggregate.aggregate(
        [alias_pair_run(tmp_path, "run-pair-alias-unsettled", controls={"C-GHSA": "unresolved"})], policy=policy())

    for report, unscored in ((dropped, 1), (unsettled, 0)):
        pairs = pair_block(report)
        assert (pairs["pairable_targets"], pairs["repetition_pairs"], pairs["resolved_pairs"]) == (1, 2, 0)
        assert pairs["assessable_mass"] == 0.0 and pairs["value"] == 0.0
        assert all(item["pairs"] == 0 and item["mass"] == 0.0 for item in pairs["outcomes"].values())
        fixed = fixed_controls(report)
        assert (fixed["observations"], fixed["completed"], fixed["resolved"], fixed["unresolved"]) == (1, 1, 0, 1)
        assert fixed["unscored"] == unscored and fixed["completed_upper"]["value"] == 1.0


def test_a_false_allegation_on_an_alias_of_a_fixed_state_control_flags_every_pair_through_it(tmp_path):
    """The same two pairs; both records are planned, C-CVE is quiet, and a false allegation was confirmed on C-GHSA.

    A false allegation about any record of K is one about K, so the fixed_target block counts K resolved and false
    (E = A = C = 1, and F+ = 1). The fixed state of both pairs is flagged, and with the hit on T-CVE both are 'both
    flagged': two resolved pairs, assessable mass 1, no correct pair, so Q = 0 and the outcome has mass 2/2 = 1.
    Reading each pair's own record alone made (T-CVE, C-CVE) correct: one correct and one both flagged, Q = 1/2.
    The allegation stands the same when the pair's own record is absent: with C-CVE dropped from the plan both pairs
    are still both flagged, since K is resolved by the allegation whatever C-CVE would have said.
    """
    planned_both = aggregate.aggregate(
        [alias_pair_run(tmp_path, "run-pair-alias-false", controls={"C-GHSA": ("false_allegation", 1)})],
        policy=policy())
    own_absent = aggregate.aggregate(
        [alias_pair_run(tmp_path, "run-pair-alias-false-own-absent", drop=("C-CVE",),
                        controls={"C-GHSA": ("false_allegation", 1)})], policy=policy())

    for report in (planned_both, own_absent):
        pairs = pair_block(report)
        assert (pairs["pairable_targets"], pairs["repetition_pairs"], pairs["resolved_pairs"]) == (1, 2, 2)
        assert pairs["assessable_mass"] == 1.0 and pairs["value"] == 0.0
        assert (pairs["outcomes"]["both_flagged"]["pairs"], pairs["outcomes"]["both_flagged"]["mass"]) == (2, 1.0)
        assert pairs["outcomes"]["correct"]["pairs"] == 0 and pairs["outcomes"]["correct"]["mass"] == 0.0
        fixed = fixed_controls(report)
        assert (fixed["observations"], fixed["completed"], fixed["resolved"]) == (1, 1, 1)
        assert fixed["false_allegations"] == 1
        assert fixed["resolved_rate"]["value"] == 1.0 and fixed["completed_upper"]["value"] == 1.0
    assert fixed_controls(planned_both)["unscored"] == 0 and fixed_controls(own_absent)["unscored"] == 1


def test_a_pair_is_credited_when_every_alias_of_its_fixed_state_control_was_assessed_quiet(tmp_path):
    """The credit an unplanned or unsettled alias withholds is granted once every record of K was assessed quiet.

    Both records planned and quiet: K is resolved quiet, both pairs are correct, and Q = assessable mass = 1.
    A record of another control takes no part: with C-CVE and C-GHSA the only records of two controls, K-CVE and K-GHSA,
    and C-GHSA absent from the plan, (T-CVE, C-CVE) stays correct on K-CVE alone and only (T-GHSA, C-GHSA) is
    unresolved: one resolved pair of two, so Q = assessable mass = 1/2, and the fixed_target block counts two controls
    of which one is resolved.
    """
    quiet = aggregate.aggregate([alias_pair_run(tmp_path, "run-pair-alias-quiet")], policy=policy())
    apart = aggregate.aggregate([alias_pair_run(tmp_path, "run-pair-controls-apart", canonical=("K-CVE", "K-GHSA"),
                                                drop=("C-GHSA",))], policy=policy())

    pairs = pair_block(quiet)
    assert (pairs["repetition_pairs"], pairs["resolved_pairs"]) == (2, 2)
    assert pairs["assessable_mass"] == 1.0 and pairs["value"] == 1.0 and pairs["outcomes"]["correct"]["pairs"] == 2
    fixed = fixed_controls(quiet)
    assert (fixed["observations"], fixed["resolved"], fixed["unscored"]) == (1, 1, 0)
    assert fixed["resolved_rate"]["value"] == 0.0 and fixed["completed_upper"]["value"] == 0.0
    pairs = pair_block(apart)
    assert (pairs["repetition_pairs"], pairs["resolved_pairs"]) == (2, 1)
    assert pairs["assessable_mass"] == 0.5 and pairs["value"] == 0.5
    assert pairs["outcomes"]["correct"]["pairs"] == 1 and pairs["outcomes"]["correct"]["mass"] == 0.5
    fixed = fixed_controls(apart)
    assert (fixed["canonical_controls"], fixed["observations"], fixed["resolved"], fixed["unresolved"]) == (2, 2, 1, 1)


def test_a_pair_is_unresolved_only_in_the_repetition_whose_fixed_bundle_lacks_an_alias(tmp_path):
    """The same two pairs run twice: repetition 1's fixed bundle plans C-CVE and C-GHSA, repetition 2's only C-CVE.

    Every repetition pair reads the fixed bundle of its own repetition, so 2 pairs x 2 repetitions are 4 repetition
    pairs, and the two of repetition 1 are resolved and correct (a hit on T-CVE, K quiet) while the two of repetition
    2 are unresolved: K was never fully assessed there.
    - Resolved pairs 2 of 4, so the assessable mass and Q are 2/4 = 1/2, and the correct outcome has mass 1/2.
    - The fixed_target block has 2 observations of K, one per repetition: 1 resolved and 1 unresolved and unscored, so
      A = 1/2, C = 1, and F+ = (0 + 1 - 1/2)/1 = 1/2.
    Reading each pair's own record alone resolved (T-CVE, C-CVE) in repetition 2 as well: 3 of 4, and Q = 3/4.
    """
    vulnerable = planned("vulnerable", targets=[target("T-CVE", canonical="X"), target("T-GHSA", canonical="X")])
    fixed_input = planned("fixed", controls=[
        control("C-CVE", kind="fixed_target", target_id="T-CVE", canonical="K"),
        control("C-GHSA", kind="fixed_target", target_id="T-GHSA", canonical="K")])
    run = write_run(tmp_path, "run-pair-alias-repeated", [vulnerable, fixed_input], repetitions=2, outcomes={
        ("vulnerable", "sys-a", 1): scan(hits={"T-CVE": 1}), ("vulnerable", "sys-a", 2): scan(hits={"T-CVE": 1}),
        ("fixed", "sys-a", 2): scan(drop=("C-GHSA",))})

    report = aggregate.aggregate([run], policy=policy())

    pairs = pair_block(report)
    assert (pairs["pairable_targets"], pairs["repetition_pairs"], pairs["resolved_pairs"]) == (1, 4, 2)
    assert pairs["assessable_mass"] == 0.5 and pairs["value"] == 0.5
    assert pairs["outcomes"]["correct"]["pairs"] == 2 and pairs["outcomes"]["correct"]["mass"] == 0.5
    fixed = fixed_controls(report)
    assert (fixed["observations"], fixed["completed"], fixed["resolved"], fixed["unresolved"]) == (2, 2, 1, 1)
    assert fixed["unscored"] == 1 and fixed["assessable_mass"] == 0.5 and fixed["completed_mass"] == 1.0
    assert fixed["completed_upper"]["value"] == 0.5


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


def test_the_example_policy_is_valid_and_labelled_as_example_values():
    loaded = aggregate.load_policy(EXAMPLE_POLICY)

    assert loaded["policy_id"].startswith("example")
    assert any("example" in note.lower() and "fixture" in note.lower() for note in loaded["notes"])


def test_resampling_clusters_can_be_families(tmp_path):
    """cluster_by family resamples variant families: alpha and beta carry three families here."""
    report = aggregate.aggregate([two_project_run(tmp_path)], policy=policy(cluster_by="family"))

    assert detection(slice_of(system(view(report))))["full_output_recall"]["interval"]["clusters"] == 3
    assert slice_of(system(view(report)))["clusters"] == {"targets": 3, "pairs": 0, "controls": 0}


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


# --- paired comparison --------------------------------------------------------------------------


def comparison_run(tmp_path: Path, run_id: str = "run-compare") -> Path:
    """Five projects, one target each; the baseline detects T-p1 and T-p2, the candidate T-p1 to T-p4.

    The candidate's configuration differs in config.knob, adds config.depth.max, and names a model.
    """
    outcomes = {(f"p{index}", "baseline", 1): scan(hits={f"T-p{index}": 1}) for index in (1, 2)}
    outcomes.update({(f"p{index}", "candidate", 1): scan(hits={f"T-p{index}": 1}) for index in (1, 2, 3, 4)})
    candidate = {"config": {"knob": 2, "depth": {"max": 3}}, "model_id": "vendor/model-y"}
    return write_run(tmp_path, run_id, five_project_inputs(), systems=("baseline", "candidate"), outcomes=outcomes,
                     configs={"candidate": candidate})


def test_a_paired_comparison_reports_the_hand_calculated_difference_with_a_reproducible_interval(tmp_path):
    """Candidate minus baseline on one frozen workload, with the same replicates for both systems.

    - Baseline recall 2/5, candidate 4/5, difference 2/5 under equal_target and equal_project alike.
    - Each replicate draws five projects with replacement; p3 and p4 are the only projects where the
      two systems differ (by 1 each), so a replicate's difference is (draws of p3 + draws of p4)/5.
      With 200 replicates the interval is the 5th and 195th sorted values, recomputed here from the
      stream the policy's seed and the label bootstrap/full/standard/all/targets name.
    - Running the comparison again gives the same bytes.
    """
    run = comparison_run(tmp_path)

    report = aggregate.compare([run], baseline="baseline", candidate="candidate", policy=policy(seed=7))

    assert validate_document("comparison-report", report) is report
    difference = next(item for item in view(report)["differences"] if item["slice"]["dimension"] == "all")
    for weighting in ("equal_target", "equal_project"):
        block = detection(difference, weighting)
        assert block["full_output_recall"]["value"] == 0.4
    assert detection(slice_of(view(report)["systems"]["baseline"]))["full_output_recall"]["value"] == 0.4
    assert detection(slice_of(view(report)["systems"]["candidate"]))["full_output_recall"]["value"] == 0.8
    replicates = share_of_draws(7, "targets", [f"acme/p{index}" for index in range(1, 6)],
                                {"acme/p3", "acme/p4"})
    interval = detection(difference)["full_output_recall"]["interval"]
    assert interval == {"state": "ok", "lower": replicates[4], "upper": replicates[194], "clusters": 5}
    assert detection(difference)["pair_correctness"] == {"value": None, "interval": {
        "state": "unavailable", "lower": None, "upper": None, "clusters": 0}}
    assert difference["completion"] == 0.0
    assert difference["controls"]["capability_safe"]["resolved_rate"]["value"] is None
    again = aggregate.compare([run], baseline="baseline", candidate="candidate", policy=policy(seed=7))
    assert canonical_json(again) == canonical_json(report)


def test_configuration_differences_are_listed_as_dotted_keys(tmp_path):
    report = aggregate.compare([comparison_run(tmp_path)], baseline="baseline", candidate="candidate",
                               policy=policy())

    assert report["configuration_differences"] == [
        {"key": "config.depth.max", "baseline": None, "candidate": 3, "absent_in": "baseline"},
        {"key": "config.knob", "baseline": 1, "candidate": 2, "absent_in": None},
        {"key": "model_id", "baseline": None, "candidate": "vendor/model-y", "absent_in": None}]
    assert report["baseline"]["system_id"] == "baseline" and report["candidate"]["model_id"] == "vendor/model-y"
    assert report["contract"]["inputs"] == 5 and report["contract"]["pairs"] == 0


def test_systems_scheduled_by_separate_runs_compare_when_their_frozen_work_is_the_same(tmp_path):
    """Run ids are not part of the contract: the same inputs, plans, and repetitions compare."""
    base = write_run(tmp_path / "a", "run-base", five_project_inputs(), systems=("baseline",),
                     outcomes={("p1", "baseline", 1): scan(hits={"T-p1": 1})})
    cand = write_run(tmp_path / "b", "run-cand", five_project_inputs(), systems=("candidate",),
                     outcomes={("p1", "candidate", 1): scan(hits={"T-p1": 1}),
                               ("p2", "candidate", 1): scan(hits={"T-p2": 1})})

    report = aggregate.compare([cand, base], baseline="baseline", candidate="candidate", policy=policy())

    difference = next(item for item in view(report)["differences"] if item["slice"]["dimension"] == "all")
    assert detection(difference)["full_output_recall"]["value"] == 0.2
    assert [run["run_id"] for run in report["runs"]] == ["run-base", "run-cand"]


def test_a_candidate_whose_schedule_drops_an_input_is_refused(tmp_path):
    """Assigning the candidate less work cannot improve its numbers: the comparison is refused."""
    base = write_run(tmp_path / "a", "run-base", five_project_inputs(), systems=("baseline",))
    cand = write_run(tmp_path / "b", "run-cand", five_project_inputs()[:4], systems=("candidate",))

    with pytest.raises(ContractError, match="do not share the frozen evaluation contract: input p5 is scheduled "
                                           "for baseline but not for candidate"):
        aggregate.compare([base, cand], baseline="baseline", candidate="candidate")


def test_a_run_narrowed_after_its_configuration_was_written_records_its_selection_in_its_row(tmp_path):
    """``--only-input`` leaves the configuration whole and shortens the schedule; the run row says both.

    run-narrow's configuration names p1 to p5 and its schedule covers p1 to p4, so its selection lists p5 as
    excluded and its row counts 5 configured inputs against 4 scheduled. run-whole was scheduled in full and
    records no narrowing: an empty selection and equal counts. Both systems of run-narrow were assigned the
    same four inputs, so a comparison accepts it (its schedules agree), and its run row says the same.
    """
    outcomes = {(f"p{index}", system, 1): scan(hits={f"T-p{index}": 1})
                for index in range(1, 5) for system in ("baseline", "candidate")}
    narrowed = write_run(tmp_path / "a", "run-narrow", five_project_inputs()[:4], systems=("baseline", "candidate"),
                         outcomes=outcomes, left_out=("p5",))
    whole = write_run(tmp_path / "b", "run-whole", five_project_inputs(), systems=("baseline", "candidate"))

    report = aggregate.aggregate([narrowed, whole], policy=policy())
    comparison = aggregate.compare([narrowed], baseline="baseline", candidate="candidate", policy=policy())

    rows = {row["run_id"]: row for row in report["runs"]}
    assert rows["run-narrow"]["selection"] == {"only_inputs": ["p1", "p2", "p3", "p4"], "only_systems": None,
                                               "excluded_inputs": ["p5"], "excluded_systems": []}
    assert (rows["run-narrow"]["configured_inputs"], rows["run-narrow"]["inputs"]) == (5, 4)
    assert rows["run-whole"]["selection"] == NO_SELECTION
    assert (rows["run-whole"]["configured_inputs"], rows["run-whole"]["inputs"]) == (5, 5)
    assert comparison["runs"] == [rows["run-narrow"]]


def test_a_candidate_whose_frozen_plan_items_differ_is_refused(tmp_path):
    changed = five_project_inputs()
    changed[0]["plan"]["targets"][0]["validation_level"] = "L4"
    base = write_run(tmp_path / "a", "run-base", five_project_inputs(), systems=("baseline",))
    cand = write_run(tmp_path / "b", "run-cand", changed, systems=("candidate",))
    fewer_repetitions = write_run(tmp_path / "c", "run-twice", five_project_inputs(), systems=("candidate",),
                                  repetitions=2)

    with pytest.raises(ContractError, match=r"input p1 differs in its frozen plan \(targets\)"):
        aggregate.compare([base, cand], baseline="baseline", candidate="candidate")
    with pytest.raises(ContractError, match="input p1 differs in repetitions"):
        aggregate.compare([base, fewer_repetitions], baseline="baseline", candidate="candidate")


def test_a_comparison_needs_two_scheduled_systems(tmp_path):
    run = comparison_run(tmp_path)
    with pytest.raises(ContractError, match="one system"):
        aggregate.compare([run], baseline="baseline", candidate="baseline")
    with pytest.raises(ContractError, match="system ghost is not scheduled"):
        aggregate.compare([run], baseline="baseline", candidate="ghost")


# --- bundle plans that place a control differently ----------------------------------------------
#
# The schedule freezes which controls an input carries, never where they are; each bundle's plan says that. A
# plan written before full plans placed controls gave a standard input's controls no paths, and one written since
# gives each the pack locates, so two runs of one input made either side of that change score the same evidence
# under two rules: the scorer withholds quiet credit from a control placed nowhere once its result lists any
# omitted path. A result that lists none and does not say examined_nothing has nothing withheld for what its scan
# did not examine, so under it every placement earns the same credit.

PLACED = {"C-scanned": ["app.py"], "C-omitted": ["vendor/helper.py"]}
PLACED_TWO_WAYS = ("input widget: its bundle plans place C-omitted nowhere in run-a and on vendor/helper.py in run-b; "
                   "C-scanned nowhere in run-a and on app.py in run-b, ")
PLACEMENT_WARNING = PLACED_TWO_WAYS + (
    "so their quiet assessments are not credited under one rule: a control placed nowhere earns none once its "
    "result lists any omitted path")
NO_CREDIT_DEPENDS = PLACED_TWO_WAYS + (
    "and no result of that input lists an omitted path or says it examined nothing, so no credit depends on where "
    "they are placed")
WEIGHED = ", each bundle weighing one over its run's repetitions as the metrics weigh it"
# The refusal of a baseline whose plans place each control nowhere with weight 2 and by its paths with weight 1, and
# a candidate whose plans do the reverse.
MIXED_TWO_TO_ONE = (
    "the systems were not scored against one plan: input widget places C-omitted nowhere with weight 2 and on "
    "vendor/helper.py with weight 1 among the bundles of baseline, and nowhere with weight 1 and on vendor/helper.py "
    "with weight 2 among those of candidate; C-scanned nowhere with weight 2 and on app.py with weight 1 among the "
    "bundles of baseline, and nowhere with weight 1 and on app.py with weight 2 among those of candidate")
OMITTING = ", and a result of that input lists an omitted path or says it examined nothing; "
SCANNED_EVERYTHING = {"omitted": [], "examined_nothing": False}


def placement_run(root: Path, run_id: str, systems: tuple[str, ...], *, placed: bool, repetitions: int = 1,
                  omitted=("README.md", "vendor/helper.py"), examined_nothing=None) -> Path:
    """One input with two safe controls, each system's scans of it omitting README.md and vendor/helper.py.

    Each system scans it *repetitions* times, once by default, and every control is assessed quiet. ``placed`` has
    each bundle's plan place C-scanned on app.py and C-omitted on vendor/helper.py, as a plan written today does;
    without it the plans place nothing, as a standard input's plan written before full plans placed controls did.
    ``omitted`` and ``examined_nothing`` say what else each result says its scan left out (``None`` leaves the field
    out): an empty list and ``False`` say a scan that examined every path, as a Semgrep full scan that showed every
    file scanned does.
    """
    inputs = [planned("widget", controls=[control("C-scanned"), control("C-omitted")])]
    spec = scan(omitted=None if omitted is None else list(omitted), examined_nothing=examined_nothing,
                paths=PLACED if placed else None)
    return write_run(root, run_id, inputs, systems=systems, repetitions=repetitions,
                     outcomes={("widget", system_id, repetition): spec
                               for system_id in systems for repetition in range(1, repetitions + 1)})


def test_a_view_names_an_input_whose_bundle_plans_place_its_controls_in_two_ways(tmp_path):
    """run-a's plans place nothing and run-b's place each control, over the same evidence.

    Under run-b's plan C-scanned, on a file the scan read, is resolved quiet and C-omitted is not; under run-a's plan
    neither is. Pooled in one view, the two would read as a control improving between systems. The view says which
    input, which controls, where each run's plans put them, and which runs; a view whose plans agree says nothing.
    """
    run_a = placement_run(tmp_path / "a", "run-a", ("baseline",), placed=False)
    run_b = placement_run(tmp_path / "b", "run-b", ("candidate",), placed=True)

    report = aggregate.aggregate([run_a, run_b], policy=policy())

    assert view(report)["warnings"] == [PLACEMENT_WARNING]
    resolved = {system_id: slice_of(system(view(report), system_id))["controls"]["capability_safe"]["resolved"]
                for system_id in ("baseline", "candidate")}
    assert resolved == {"baseline": 0, "candidate": 1}, "the same quiet evidence, credited under two rules"
    for placed in (False, True):
        alike = placement_run(tmp_path / f"alike-{placed}", "run-c", ("candidate",), placed=placed)
        warnings = view(aggregate.aggregate([alike], policy=policy()))["warnings"]
        assert not [warning for warning in warnings if "bundle plans place" in warning]


def test_a_comparison_whose_systems_bundles_place_a_control_differently_is_refused(tmp_path):
    """A baseline run before full plans placed controls and a candidate run since, over the same evidence.

    Their frozen work is the same, so the frozen contract cannot tell them apart. Compared, the candidate would gain
    the quiet credit of C-scanned that the baseline's plan withheld, an improvement of the plans and not the system.
    """
    run_a = placement_run(tmp_path / "a", "run-a", ("baseline",), placed=False)
    run_b = placement_run(tmp_path / "b", "run-b", ("candidate",), placed=True)

    with pytest.raises(ContractError) as refused:
        aggregate.compare([run_a, run_b], baseline="baseline", candidate="candidate", policy=policy())

    assert str(refused.value).startswith(
        "the systems were not scored against one plan: input widget places C-omitted nowhere with weight 1 among the "
        "bundles of baseline, and on vendor/helper.py with weight 1 among those of candidate; C-scanned nowhere with "
        "weight 1 among the bundles of baseline, and on app.py with weight 1 among those of candidate" + WEIGHED
        + OMITTING + "a control placed nowhere earns no quiet credit once its result lists any omitted path, so a "
                     "difference in its credit may be the plans', not the systems'")



def test_a_comparison_whose_systems_bundles_place_a_control_differently_stands_when_no_result_lists_an_omission(
        tmp_path):
    """The baseline run before full plans placed controls and the candidate run since, both scans examining every path.

    No result lists an omitted path or says it examined nothing, so the scorer withholds no quiet credit for what a
    scan did not examine, and the baseline's pathless plan credits both quiet controls as the candidate's placed plan
    does. The comparison stands with no difference in any control figure. Its view, and an aggregate view of the same
    runs, name the input and the controls whose placement differs and say that no credit depends on it.
    """
    run_a = placement_run(tmp_path / "a", "run-a", ("baseline",), placed=False, **SCANNED_EVERYTHING)
    run_b = placement_run(tmp_path / "b", "run-b", ("candidate",), placed=True, **SCANNED_EVERYTHING)

    comparison = aggregate.compare([run_a, run_b], baseline="baseline", candidate="candidate", policy=policy())
    report = aggregate.aggregate([run_a, run_b], policy=policy())

    assert view(comparison)["warnings"] == view(report)["warnings"] == [NO_CREDIT_DEPENDS]
    resolved = {system_id: slice_of(system(view(report), system_id))["controls"]["capability_safe"]["resolved"]
                for system_id in ("baseline", "candidate")}
    assert resolved == {"baseline": 2, "candidate": 2}, "every placement credits a scan that examined every path"
    difference = next(item for item in view(comparison)["differences"] if item["slice"]["dimension"] == "all")
    safe = difference["controls"]["capability_safe"]
    assert (safe["assessable_mass"], safe["completed_upper"]["value"], safe["resolved_rate"]["value"]) == (0.0, 0.0, 0.0)


@pytest.mark.parametrize(("baseline_scan", "candidate_scan"), [
    ({}, SCANNED_EVERYTHING),
    (SCANNED_EVERYTHING, {}),
    ({"omitted": None, "examined_nothing": True}, {"omitted": None, "examined_nothing": True}),
], ids=["the-baseline-lists-omissions", "the-candidate-lists-omissions", "both-examined-nothing"])
def test_a_placement_difference_is_refused_once_any_result_of_the_input_lists_an_omission(
        tmp_path, baseline_scan, candidate_scan):
    """One system's result listing an omitted path is enough, and so is a result saying it examined nothing.

    The check reads every result of the input, whichever system's, as the scorer reads each: a control placed
    nowhere is withheld once its result lists any omitted path, so where one does, a difference in placement can be a
    difference in credit. A result that says examined_nothing withholds every control wherever it is placed, and is
    counted all the same, so the check errs toward refusing.
    """
    run_a = placement_run(tmp_path / "a", "run-a", ("baseline",), placed=False, **baseline_scan)
    run_b = placement_run(tmp_path / "b", "run-b", ("candidate",), placed=True, **candidate_scan)

    with pytest.raises(ContractError) as refused:
        aggregate.compare([run_a, run_b], baseline="baseline", candidate="candidate", policy=policy())

    assert str(refused.value).startswith("the systems were not scored against one plan: input widget places ")
    assert OMITTING in str(refused.value)
    assert view(aggregate.aggregate([run_a, run_b], policy=policy()))["warnings"] == [PLACEMENT_WARNING]

def test_a_comparison_whose_systems_bundles_place_a_control_both_ways_in_different_numbers_is_refused(tmp_path):
    """Each system has runs from both sides of the change, in different numbers, over the same evidence.

    run-1, made before full plans placed controls, and run-2, made since, scan the input for both systems; run-3,
    made before, scans it for the baseline alone, and run-4, made since, for the candidate alone. Each system's frozen
    work is three scans of the input, and each system's bundles place the controls both ways, so the two share a
    set of placements. They do not share a mix: two of the baseline's three bundles place nothing and two of the
    candidate's place each control, so the candidate's quiet control on a scanned file is credited in two scans and
    the baseline's in one, over the same evidence.
    """
    runs = [placement_run(tmp_path / "1", "run-1", ("baseline", "candidate"), placed=False),
            placement_run(tmp_path / "2", "run-2", ("baseline", "candidate"), placed=True),
            placement_run(tmp_path / "3", "run-3", ("baseline",), placed=False),
            placement_run(tmp_path / "4", "run-4", ("candidate",), placed=True)]
    report = aggregate.aggregate(runs, policy=policy())
    resolved = {system_id: slice_of(system(view(report), system_id))["controls"]["capability_safe"]["resolved"]
                for system_id in ("baseline", "candidate")}
    assert resolved == {"baseline": 1, "candidate": 2}, "the same quiet evidence, credited under two mixes of plans"

    with pytest.raises(ContractError) as refused:
        aggregate.compare(runs, baseline="baseline", candidate="candidate", policy=policy())

    assert str(refused.value).startswith(MIXED_TWO_TO_ONE + WEIGHED + OMITTING)


def test_a_comparison_whose_systems_bundles_place_a_control_alike_in_number_but_not_in_weight_is_refused(tmp_path):
    """Each system has runs of one, two, and three repetitions of the input, over the same evidence.

    The baseline's plans place nothing in its runs of one and two repetitions and place each control in its run of
    three; the candidate's do the reverse. Each system's bundles place each control nowhere three times and by its
    paths three times, so their counts agree, but the metrics do not count bundles: each run of the input weighs one
    and its repetitions share it, so the baseline's plans place each control nowhere with weight 2 and by its paths
    with weight 1, and the candidate's the reverse. C-scanned, quiet on a file every scan read, is resolved in three
    bundles of each system, yet in a third of the baseline's weight and two thirds of the candidate's: averaged with
    C-omitted, which no scan credits, the capability_safe assessable masses are 1/6 and 1/3, a difference of the
    plans alone.
    """
    runs = [placement_run(tmp_path, f"run-{system_id}-{repetitions}", (system_id,), repetitions=repetitions,
                          placed=repetitions == 3 if system_id == "baseline" else repetitions != 3)
            for system_id in ("baseline", "candidate") for repetitions in (1, 2, 3)]
    report = aggregate.aggregate(runs, policy=policy())
    safe = {system_id: slice_of(system(view(report), system_id))["controls"]["capability_safe"]
            for system_id in ("baseline", "candidate")}
    assert {system_id: block["resolved"] for system_id, block in safe.items()} == {"baseline": 3, "candidate": 3}
    assert {system_id: block["assessable_mass"] for system_id, block in safe.items()} == {
        "baseline": 1 / 6, "candidate": 1 / 3}, "the same quiet evidence, weighed under two mixes of plans"

    with pytest.raises(ContractError) as refused:
        aggregate.compare(runs, baseline="baseline", candidate="candidate", policy=policy())

    assert str(refused.value).startswith(MIXED_TWO_TO_ONE + WEIGHED + OMITTING)


@pytest.mark.parametrize("repetitions", [(1, 3), (2, 2)],
                         ids=["runs-of-one-and-three-repetitions", "runs-of-two-repetitions-each"])
def test_systems_whose_bundles_place_a_control_each_way_with_the_same_weight_compare(tmp_path, repetitions):
    """Each system has two runs of the input, its plans placing nothing in one and each control in the other, swapped.

    The baseline's plans place nothing in its first run and each control in its second; the candidate's do the
    reverse. Each run of the input weighs one and its repetitions share it, so both systems' plans place each control
    nowhere with weight 1 and by its paths with weight 1. Over the same evidence C-scanned is credited in half of
    each system's weight, so both capability_safe assessable masses are 1/4, averaged with C-omitted, and the
    comparison stands with no difference in any control figure; its view names both placements. With runs of one and
    three repetitions the counts differ, one bundle of the baseline placing nothing against three of the candidate,
    and are not what the metrics weigh.
    """
    first, second = repetitions
    runs = [placement_run(tmp_path, "run-baseline-1", ("baseline",), placed=False, repetitions=first),
            placement_run(tmp_path, "run-baseline-2", ("baseline",), placed=True, repetitions=second),
            placement_run(tmp_path, "run-candidate-1", ("candidate",), placed=True, repetitions=first),
            placement_run(tmp_path, "run-candidate-2", ("candidate",), placed=False, repetitions=second)]

    comparison = aggregate.compare(runs, baseline="baseline", candidate="candidate", policy=policy())

    assert [slice_of(view(comparison)["systems"][side])["controls"]["capability_safe"]["assessable_mass"]
            for side in ("baseline", "candidate")] == [0.25, 0.25]
    difference = next(item for item in view(comparison)["differences"] if item["slice"]["dimension"] == "all")
    safe = difference["controls"]["capability_safe"]
    assert (safe["assessable_mass"], safe["completed_upper"]["value"], safe["resolved_rate"]["value"]) == (0.0, 0.0, 0.0)
    nowhere, placed = "run-baseline-1, run-candidate-2", "run-baseline-2, run-candidate-1"
    assert view(comparison)["warnings"] == [
        f"input widget: its bundle plans place C-omitted nowhere in {nowhere} and on vendor/helper.py in {placed}; "
        f"C-scanned nowhere in {nowhere} and on app.py in {placed}, so their quiet assessments are not credited under "
        "one rule: a control placed nowhere earns none once its result lists any omitted path"]


def test_systems_whose_every_bundle_places_a_control_one_way_compare_though_one_read_fewer_bundles(tmp_path):
    """Both systems' plans place each control, and one of the candidate's two scans left no bundle.

    The baseline's bundles place C-scanned on app.py twice, with weight 1, and the candidate's once, with weight 1/2.
    A failure reads no plan, and every bundle either system has was planned alike, so the weights differ by the
    failure alone: the comparison stands, and nothing is said about placement.
    """
    inputs = [planned("widget", controls=[control("C-scanned"), control("C-omitted")])]
    spec = scan(omitted=["README.md", "vendor/helper.py"], paths=PLACED)
    outcomes = {("widget", system_id, repetition): spec
                for system_id in ("baseline", "candidate") for repetition in (1, 2)}
    outcomes[("widget", "candidate", 2)] = "missing_bundle"
    run = write_run(tmp_path, "run-b", inputs, systems=("baseline", "candidate"), repetitions=2, outcomes=outcomes)

    report = aggregate.compare([run], baseline="baseline", candidate="candidate", policy=policy())

    assert not [warning for warning in view(report)["warnings"] if "bundle plans place" in warning]


def test_systems_whose_bundles_place_controls_alike_compare_and_a_view_names_each_way_they_do(tmp_path):
    """Both systems in run-a, whose plans place nothing, and both in run-b, whose plans place each control.

    Each system's bundles place the controls the same two ways, one bundle each, so both were scored under the same
    mix of plans and the comparison stands; its view names the two placements as an aggregate view does. Plans that
    agree throughout compare with no such warning.
    """
    run_a = placement_run(tmp_path / "a", "run-a", ("baseline", "candidate"), placed=False)
    run_b = placement_run(tmp_path / "b", "run-b", ("baseline", "candidate"), placed=True)

    report = aggregate.compare([run_a, run_b], baseline="baseline", candidate="candidate", policy=policy())

    assert view(report)["warnings"] == [PLACEMENT_WARNING]
    alike = aggregate.compare([run_b], baseline="baseline", candidate="candidate", policy=policy())
    assert not [warning for warning in view(alike)["warnings"] if "bundle plans place" in warning]


def test_an_input_whose_schedule_froze_no_plan_is_not_named_for_where_its_bundles_place_a_control(tmp_path):
    """Its controls take no part in any control metric, so their placement changes no credit.

    The two runs of the first comparison above, with each schedule saying the input was not planned before the run:
    the bundles still place the controls two ways, and neither the view nor the comparison names them.
    """
    runs = [placement_run(tmp_path / "a", "run-a", ("baseline",), placed=False),
            placement_run(tmp_path / "b", "run-b", ("candidate",), placed=True)]
    for run in runs:
        path = run / "evaluator" / "schedule.json"
        document = json.loads(path.read_text())
        unplanned = planned("widget", frozen=False)
        document["inputs"][0].update(plan=unplanned["plan"], declared_tree_hash=unplanned["declared_tree_hash"])
        path.write_text(canonical_json(validate_document("evaluation-schedule", document)) + "\n")

    report = aggregate.aggregate(runs, policy=policy())
    comparison = aggregate.compare(runs, baseline="baseline", candidate="candidate", policy=policy())

    assert view(report)["inputs_without_frozen_plan"] == [
        {"run_id": run_id, "input_id": "widget", "reason": "snapshot widget declares no tree hash"}
        for run_id in ("run-a", "run-b")]
    for warnings in (view(report)["warnings"], view(comparison)["warnings"]):
        assert not [warning for warning in warnings if "bundle plans place" in warning]


def freeze_controls(run: Path, control_ids: tuple[str, ...]) -> None:
    """Rewrite *run*'s schedule so that its input froze only *control_ids*: each bundle's plan adds the others."""
    path = run / "evaluator" / "schedule.json"
    document = json.loads(path.read_text())
    plan = document["inputs"][0]["plan"]
    plan["controls"] = [item for item in plan["controls"] if item["control_id"] in control_ids]
    path.write_text(canonical_json(validate_document("evaluation-schedule", document)) + "\n")


def test_controls_no_schedule_froze_are_neither_compared_nor_named_for_where_bundle_plans_place_them(tmp_path):
    """The two runs of the first comparison above, with each schedule saying the input froze no control.

    The bundle plans still carry both controls, placed nowhere in run-a and by their paths in run-b, and every result
    lists omitted paths. A control a bundle's plan adds is ignored, as every metric ignores it, so where the plan
    places it changes no credit: the comparison stands, and neither its view nor an aggregate view names the
    placements. Each says only that the items the plans add are ignored.
    """
    runs = [placement_run(tmp_path / "a", "run-a", ("baseline",), placed=False),
            placement_run(tmp_path / "b", "run-b", ("candidate",), placed=True)]
    for run in runs:
        freeze_controls(run, ())

    report = aggregate.aggregate(runs, policy=policy())
    comparison = aggregate.compare(runs, baseline="baseline", candidate="candidate", policy=policy())

    for warnings in (view(report)["warnings"], view(comparison)["warnings"]):
        assert warnings == [f"{system_id}: 2 item(s) a bundle's plan adds beyond the frozen schedule are ignored"
                            for system_id in ("baseline", "candidate")]


def test_a_frozen_control_placed_differently_is_refused_and_named_apart_from_one_no_schedule_froze(tmp_path):
    """The same two runs with each schedule freezing C-scanned alone; the bundle plans also carry C-omitted.

    C-scanned is placed nowhere in run-a and on app.py in run-b, and the results list omitted paths, so the comparison
    is still refused. The refusal and the aggregate view's warning name C-scanned and not C-omitted, which no metric
    reads.
    """
    runs = [placement_run(tmp_path / "a", "run-a", ("baseline",), placed=False),
            placement_run(tmp_path / "b", "run-b", ("candidate",), placed=True)]
    for run in runs:
        freeze_controls(run, ("C-scanned",))

    with pytest.raises(ContractError) as refused:
        aggregate.compare(runs, baseline="baseline", candidate="candidate", policy=policy())

    assert str(refused.value).startswith(
        "the systems were not scored against one plan: input widget places C-scanned nowhere with weight 1 among the "
        "bundles of baseline, and on app.py with weight 1 among those of candidate" + WEIGHED + OMITTING)
    warnings = view(aggregate.aggregate(runs, policy=policy()))["warnings"]
    assert [warning for warning in warnings if "bundle plans place" in warning] == [
        "input widget: its bundle plans place C-scanned nowhere in run-a and on app.py in run-b, so their quiet "
        "assessments are not credited under one rule: a control placed nowhere earns none once its result lists any "
        "omitted path"]


def test_an_omission_listed_only_where_the_run_froze_no_control_leaves_a_placement_difference_compared(tmp_path):
    """The no-omission comparison above, with a third run of both systems whose schedule froze no control of the input.

    run-a and run-b froze both controls and place them two ways, and both scans examined every path, so no credit
    depends on where they are placed. run-c's bundle plans carry the controls too and its results list omitted
    paths, but no metric reads a control its schedule did not freeze, so what those results omit changes no
    control's credit: the comparison stands, and both views say that no credit depends on where the controls are
    placed.
    """
    runs = [placement_run(tmp_path / "a", "run-a", ("baseline",), placed=False, **SCANNED_EVERYTHING),
            placement_run(tmp_path / "b", "run-b", ("candidate",), placed=True, **SCANNED_EVERYTHING),
            placement_run(tmp_path / "c", "run-c", ("baseline", "candidate"), placed=True)]
    freeze_controls(runs[2], ())

    comparison = aggregate.compare(runs, baseline="baseline", candidate="candidate", policy=policy())
    report = aggregate.aggregate(runs, policy=policy())

    for warnings in (view(comparison)["warnings"], view(report)["warnings"]):
        assert [warning for warning in warnings if "bundle plans place" in warning] == [NO_CREDIT_DEPENDS]


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


def test_a_run_the_runner_narrowed_with_only_inputs_records_its_selection_in_the_report(tmp_path, upstream):
    """The real runner keeps the configuration whole, and the run row reports what it left out.

    One snapshot is configured as two inputs, in-1 and in-2, and the run is narrowed to in-1. Its schedule and
    manifest cover one input, its configuration still names two, and its manifest's selection excludes in-2.
    """
    repo, commit = upstream
    pack = cases.new_pack("test", "aggregate-narrowed", "Local fixture pack for the narrowing test.")
    cases.add_snapshot(pack, {
        "snapshot_id": "snap-a", "repository": {"url": str(repo), "name": "widget"}, "commit": commit,
        "reference": "Commit chosen by the test fixture; no advisory is claimed.", "languages": ["python"],
        "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}})
    cases.save_pack(tmp_path / "pack.json", pack)
    config = {"schema_version": "2.1", "run_id": "run-narrowed", "pack": "pack.json", "cache_root": "cache",
              "inputs": [{"input_id": "in-1", "snapshot_id": "snap-a"}, {"input_id": "in-2", "snapshot_id": "snap-a"}],
              "systems": [{"system_id": "fake-a", "adapter": "fake", "config": {"knob": 1}}],
              "repetitions": 1, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none"}
    (tmp_path / "run.json").write_text(canonical_json(config) + "\n", encoding="utf-8")
    run = tmp_path / "narrowed"
    run_from_config(tmp_path / "run.json", run, clock=CLOCK, adapters={"fake": FakeAdapter()}, only_inputs={"in-1"})

    report = aggregate.aggregate([run], policy=policy())

    row = report["runs"][0]
    assert row["selection"] == {"only_inputs": ["in-1"], "only_systems": None, "excluded_inputs": ["in-2"],
                                "excluded_systems": []}
    assert (row["configured_inputs"], row["inputs"], row["assignments"]) == (2, 1, 1)


# --- command line -------------------------------------------------------------------------------


def cli(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_cli_aggregate_writes_one_new_report_and_summarizes_it(tmp_path, capsys):
    run = two_project_run(tmp_path / "runs")
    output = tmp_path / "aggregate.json"

    code, out, err = cli(capsys, "aggregate", str(run), "--policy", str(EXAMPLE_POLICY), "--output", str(output))

    assert code == 0, err
    report = load_document(output, "aggregate-report")
    assert output.read_text(encoding="utf-8") == canonical_json(report) + "\n"
    assert "view full/standard scope=reviewed inputs=2 canonical_targets=4" in out
    assert "sys-a scope=reviewed full_output_recall equal_target=0.500 (insufficient_clusters)" in out
    assert f"Report: {output}" in out
    code, _out, err = cli(capsys, "aggregate", str(run), "--output", str(output))
    assert code == 2 and "scaneval:" in err
    assert output.read_text(encoding="utf-8") == canonical_json(report) + "\n"


def test_cli_aggregate_is_byte_identical_in_any_directory_order(tmp_path, capsys):
    first = two_project_run(tmp_path / "one")
    second = blinded_and_standard_run(tmp_path / "two")

    assert cli(capsys, "aggregate", str(first), str(second), "--output", str(tmp_path / "a.json"))[0] == 0
    assert cli(capsys, "aggregate", str(second), str(first), "--output", str(tmp_path / "b.json"))[0] == 0

    assert (tmp_path / "a.json").read_bytes() == (tmp_path / "b.json").read_bytes()


def test_cli_aggregate_refuses_an_output_inside_a_trial_directory_and_a_refused_run(tmp_path, capsys):
    run = two_project_run(tmp_path / "runs")
    trial = tmp_path / "trial"
    (trial / "source").mkdir(parents=True)
    (trial / "provenance.json").write_text("{}", encoding="utf-8")

    code, _out, err = cli(capsys, "aggregate", str(run), "--output", str(trial / "report.json"))
    assert code == 2 and "inside the trial directory" in err
    assert not (trial / "report.json").exists()

    code, _out, err = cli(capsys, "aggregate", str(tmp_path / "trial"), "--output", str(tmp_path / "out.json"))
    assert code == 2 and "holds no run-manifest.json" in err
    assert not (tmp_path / "out.json").exists()


def test_cli_help_describes_both_commands(capsys):
    for command in ("aggregate", "compare"):
        with pytest.raises(SystemExit) as raised:
            main([command, "--help"])
        assert raised.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "Every scheduled assignment is an observation; a failed one stays in every denominator." in text
    assert "Refused unless both were assigned exactly the same frozen work" in text
    assert ("and their bundles place alike the controls of each input where a result lists omitted paths or says "
            "it examined nothing" in text)
    assert "--baseline BASELINE" in text and "--policy POLICY" in text


def test_cli_compare_writes_a_new_report_or_refuses_with_exit_2(tmp_path, capsys):
    run = comparison_run(tmp_path / "runs")
    output = tmp_path / "comparison.json"

    code, out, err = cli(capsys, "compare", str(run), "--baseline", "baseline", "--candidate", "candidate",
                         "--policy", str(EXAMPLE_POLICY), "--output", str(output))

    assert code == 0, err
    report = load_document(output, "comparison-report")
    assert output.read_text(encoding="utf-8") == canonical_json(report) + "\n"
    assert "baseline=baseline candidate=candidate configuration_differences=3" in out
    assert "equal_target full_output_recall difference=+0.400 (insufficient_clusters)" not in out
    assert "equal_target full_output_recall difference=+0.400 [" in out
    assert f"Comparison: {output}" in out
    refused = tmp_path / "refused.json"
    code, _out, err = cli(capsys, "compare", str(run), "--baseline", "baseline", "--candidate", "ghost",
                          "--output", str(refused))
    assert code == 2 and "scaneval: system ghost is not scheduled" in err
    assert not refused.exists()


def test_configuration_paths_preserve_literal_and_nested_keys():
    left = {"config": {"scanner": {"enabled": False}, "scanner.enabled": "same", "": None}}
    right = {"config": {"scanner": {"enabled": True}, "scanner.enabled": "same"}}
    from scaneval import aggregate
    differences = aggregate.configuration_differences(left, right)
    assert {row["key"] for row in differences} == {"config.scanner.enabled", r"config.\e"}
    assert aggregate.configuration_differences({"a.b": [1]}, {"a": {"b": [1]}})
    assert aggregate.configuration_differences({"a": True}, {"a": 1})


def test_collision_cannot_pass_empty_configuration_allowlist(tmp_path):
    from scaneval import gate
    from test_v2_gate import minimal_policy
    run = write_run(tmp_path, "collision", [planned("i", targets=[target("T")])],
                    systems=("baseline", "candidate"), configs={
                        "baseline": {"config": {"a": {"b": False}, "a.b": "same"}},
                        "candidate": {"config": {"a": {"b": True}, "a.b": "same"}}})
    comparison = aggregate.compare([run], baseline="baseline", candidate="candidate", policy=policy())
    decision = gate.evaluate_gate(minimal_policy(), comparison)
    checked = next(row for row in decision["requirements"] if row["id"] == "configuration.allowed_differences")
    assert checked["status"] == "inconclusive"
    assert checked["observed"]["not_allowed"] == ["config.a.b"]


def test_effective_timeout_in_system_identity(tmp_path):
    from scaneval.contracts import canonical_sha256
    base = write_run(tmp_path, "short", [planned("i", targets=[target("T")])], systems=("baseline",))
    cand = write_run(tmp_path, "long", [planned("i", targets=[target("T")])], systems=("candidate",))
    config = json.loads((base / "run-config.json").read_text())
    config["timeout_seconds"] = 1
    (base / "run-config.json").write_text(canonical_json(config))
    for name in ("run-manifest.json", "evaluator/schedule.json"):
        path = base / name
        doc = json.loads(path.read_text())
        doc["config_sha256"] = canonical_sha256(config)
        path.write_text(canonical_json(doc))
    report = aggregate.compare([base, cand], baseline="baseline", candidate="candidate", policy=policy())
    assert report["configuration_differences"] == [
        {"key": "timeout_seconds", "baseline": 1, "candidate": 60, "absent_in": None}]


def test_timeout_identity_normalizes_equivalent_numbers(tmp_path):
    from scaneval.aggregate import _Run, _configuration, _systems
    config = {"timeout_seconds": 60, "network_policy": "none", "systems": [
        {"system_id": "same", "adapter": "fake", "config": {}}]}
    schedule = {"systems": [{"system_id": "same"}]}
    manifest = {"systems": [], "invocations": []}
    first = _Run("first", tmp_path, manifest, schedule, config)
    second = _Run("second", tmp_path, manifest, schedule, {**config, "timeout_seconds": 60.0})
    assert _configuration(first, 'same') == _configuration(second, 'same')
    assert _systems([first, second])['same']['runs'] == ['first', 'second']
    changed = _Run("changed", tmp_path, manifest, schedule, {**config, "timeout_seconds": 120})
    with pytest.raises(ContractError, match='configured differently'):
        _systems([first, changed])


# --- system identity ----------------------------------------------------------------------------


CURATED_TREE = "sha256:" + "1" * 64
DEEPSEC_FULL = {"adapter": "deepsec", "config": {"deepsec_root": "/opt/deepsec-workspace", "model": "fixture-model"}}
DEEPSEC_CURATED = {"adapter": "deepsec", "config": {**DEEPSEC_FULL["config"],
                                                   "process_manifest_by_tree": {CURATED_TREE: ["src/server.js"]}}}
CURATED_CAVEAT = ("processing is curated: deepsec config.process_manifest_by_tree chose before the run which paths are "
                  "assigned AI batches, so its figures are a diagnostic of those paths, not a detection rate, and not "
                  "comparable with a full run")


def configuration_requirement(comparison: dict, allowed: list[str]) -> dict:
    """The gate's configuration requirement over *comparison* when its policy allows exactly *allowed*."""
    from scaneval import gate
    from test_v2_gate import minimal_policy
    document = minimal_policy()
    document["configuration"]["allowed_differences"] = allowed
    decision = gate.evaluate_gate(document, comparison)
    return next(row for row in decision["requirements"] if row["id"] == "configuration.allowed_differences")


def test_one_system_id_recorded_with_two_adapter_versions_is_refused_like_two_configurations(tmp_path):
    """A blind DeepSec 1.1.0 run and a curated 1.2.0 run of one byte-identical configuration are two systems.

    DeepSec 1.1.0 ignores config.process_manifest_by_tree, so run-a is a blind full scan and run-b a curated
    diagnostic, and their configurations cannot tell them apart. Each aggregates alone, marked by what it ran;
    pooling them is refused wherever runs are pooled, naming both versions and both runs in either order.
    """
    inputs = [planned("p1", targets=[target("T-p1")])]
    blind = write_run(tmp_path / "a", "run-a", inputs, systems=("deepsec-x",), configs={"deepsec-x": DEEPSEC_CURATED},
                      versions={"deepsec-x": "1.1.0"})
    curated = write_run(tmp_path / "b", "run-b", inputs, systems=("deepsec-x", "other"),
                        configs={"deepsec-x": DEEPSEC_CURATED}, versions={"deepsec-x": "1.2.0"})
    message = ("system deepsec-x is recorded as adapter deepsec 1.1.0 in run run-a and as deepsec 1.2.0 in run run-b; "
               "one system id must name one adapter at one version to be aggregated")

    for refused in (lambda: aggregate.aggregate([blind, curated], policy=policy()),
                    lambda: aggregate.aggregate([curated, blind], policy=policy()),
                    lambda: aggregate.aggregate_by_condition([blind, curated], policy=policy()),
                    lambda: aggregate.compare([blind, curated], baseline="other", candidate="deepsec-x",
                                              policy=policy())):
        with pytest.raises(ContractError) as excinfo:
            refused()
        assert str(excinfo.value) == message
    assert [(row["adapter_version"], row["processing"]) for row in
            aggregate.aggregate([blind], policy=policy())["systems"]] == [("1.1.0", "full")]
    assert [(row["system_id"], row["adapter_version"], row["processing"]) for row in
            aggregate.aggregate([curated], policy=policy())["systems"]] == [
        ("deepsec-x", "1.2.0", "curated"), ("other", "1.0.0", "full")]


def test_a_run_that_recorded_no_adapter_version_ran_nothing_and_pools_with_any_version(tmp_path):
    """A version is unknown only where the system ran nothing, so those failures pool, and each view says so.

    run-a ran sys-a under adapter 1.2.0. run-b skipped it, its adapter unresolved, so its manifest records no
    version. run-c failed before preparing any system, so its manifest has no row for sys-a and no invocation row.
    Pooled, sys-a is 1.2.0 and both failures stay in every denominator: completion is 1/3. Alone, run-b's sys-a has
    no version and no such warning.
    """
    inputs = [planned("p1", targets=[target("T-p1")])]
    ran = write_run(tmp_path / "a", "run-a", inputs, outcomes={("p1", "sys-a", 1): scan(hits={"T-p1": 1})},
                    versions={"sys-a": "1.2.0"})
    skipped = write_run(tmp_path / "b", "run-b", inputs, skipped_systems=("sys-a",), versions={"sys-a": None})
    stopped = write_run(tmp_path / "c", "run-c", inputs, outcomes={("p1", "sys-a", 1): "missing_row"})
    manifest = json.loads((stopped / "run-manifest.json").read_text(encoding="utf-8"))
    manifest.update(status="failed", systems=[], failure={"type": "KeyboardInterrupt", "message": ""})
    validate_document("run-manifest", manifest)
    (stopped / "run-manifest.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8")

    report = aggregate.aggregate([stopped, skipped, ran], policy=policy())

    assert [(row["system_id"], row["adapter_version"], row["runs"]) for row in report["systems"]] == [
        ("sys-a", "1.2.0", ["run-a", "run-b", "run-c"])]
    failures = system(view(report))["observations"]["failures"]
    assert (failures["skipped_system"], failures["missing_row"]) == (1, 1)
    assert slice_of(system(view(report)))["completion"]["value"] == 1 / 3
    assert ("sys-a: run(s) run-b, run-c ran nothing for it, every assignment skipped or never started, so they "
            "pool with any adapter version, whatever they recorded, and add only failures; its adapter_version "
            "1.2.0 is the one the runs that ran it recorded") in view(report)["warnings"]
    alone = aggregate.aggregate([skipped], policy=policy())
    assert alone["systems"][0]["adapter_version"] is None
    assert not any("ran nothing for it" in warning for warning in view(alone)["warnings"])


def test_a_run_that_ran_nothing_for_a_system_pools_whatever_adapter_version_it_recorded(tmp_path):
    """Whether a run ran a system is read from its invocation rows, never from the version its manifest recorded.

    run-a skipped sys-a after resolving its adapter, as the runner does when a DeepSec prepare() fails, so its
    manifest records 1.2.0. run-c prepared sys-a under 1.1.0 and stopped before its first invocation, so it has no
    invocation row. Neither ran anything, so both pool with run-b, which ran sys-a under 1.2.1: the system is 1.2.1,
    both failures stay in every denominator, and the view names both runs.
    """
    inputs = [planned("p1", targets=[target("T-p1")])]
    skipped = write_run(tmp_path / "a", "run-a", inputs, skipped_systems=("sys-a",), versions={"sys-a": "1.2.0"})
    ran = write_run(tmp_path / "b", "run-b", inputs, outcomes={("p1", "sys-a", 1): scan(hits={"T-p1": 1})},
                    versions={"sys-a": "1.2.1"})
    stopped = write_run(tmp_path / "c", "run-c", inputs, outcomes={("p1", "sys-a", 1): "missing_row"},
                        versions={"sys-a": "1.1.0"})
    manifest = json.loads((stopped / "run-manifest.json").read_text(encoding="utf-8"))
    manifest.update(status="failed", failure={"type": "KeyboardInterrupt", "message": ""})
    validate_document("run-manifest", manifest)
    (stopped / "run-manifest.json").write_text(canonical_json(manifest) + "\n", encoding="utf-8")

    report = aggregate.aggregate([stopped, ran, skipped], policy=policy())

    assert [(row["system_id"], row["adapter_version"], row["runs"]) for row in report["systems"]] == [
        ("sys-a", "1.2.1", ["run-a", "run-b", "run-c"])]
    failures = system(view(report))["observations"]["failures"]
    assert (failures["skipped_system"], failures["missing_row"]) == (1, 1)
    assert slice_of(system(view(report)))["completion"]["value"] == 1 / 3
    assert ("sys-a: run(s) run-a, run-c ran nothing for it, every assignment skipped or never started, so they pool "
            "with any adapter version, whatever they recorded, and add only failures; its adapter_version 1.2.1 is "
            "the one the runs that ran it recorded") in view(report)["warnings"]


def test_a_version_only_a_run_that_ran_nothing_recorded_is_not_read(tmp_path):
    """A curated configuration whose one run skipped it under adapter 1.1.0 never ran unscoped, because nothing ran.

    The system therefore has no adapter version, its processing is taken as configured, and no view says the key
    was ignored.
    """
    inputs = [planned("p1", targets=[target("T-p1")])]
    skipped = write_run(tmp_path, "run-a", inputs, systems=("deepsec-x",), configs={"deepsec-x": DEEPSEC_CURATED},
                        skipped_systems=("deepsec-x",), versions={"deepsec-x": "1.1.0"})

    report = aggregate.aggregate([skipped], policy=policy())

    assert [(row["adapter_version"], row["processing"]) for row in report["systems"]] == [(None, "curated")]
    assert [warning for warning in view(report)["warnings"] if "processing" in warning] == [
        f"deepsec-x: {CURATED_CAVEAT}"]
    assert not any("ran unscoped" in warning for warning in view(report)["warnings"])


def test_a_run_that_ran_a_system_but_records_no_adapter_version_for_it_is_refused(tmp_path):
    """scaneval run skips a system whose adapter declares no usable version, so a manifest that records invocations of
    one under no version cannot say what ran, and it is refused rather than pooled as if it had run nothing."""
    inputs = [planned("p1", targets=[target("T-p1")])]
    unknown = write_run(tmp_path, "run-a", inputs, versions={"sys-a": None})

    with pytest.raises(ContractError, match="run run-a records invocations of system sys-a but no adapter version for "
                                            "it; a system that ran must record the adapter it ran with to be "
                                            "aggregated"):
        aggregate.aggregate([unknown], policy=policy())


def test_adapter_versions_are_in_every_system_row_and_a_difference_a_gate_policy_must_name(tmp_path):
    """One adapter configuration at two versions, under two ids, compares with the version as a difference.

    The configuration requirement isolates the version bump only when the policy names adapter_version: with an
    empty allowlist it is inconclusive, and with adapter_version allowed it passes.
    """
    run = write_run(tmp_path, "run-versions", five_project_inputs(), systems=("baseline", "candidate"),
                    versions={"baseline": "1.1.0", "candidate": "1.2.0"})

    report = aggregate.aggregate([run], policy=policy())
    comparison = aggregate.compare([run], baseline="baseline", candidate="candidate", policy=policy())

    assert [(row["system_id"], row["adapter"], row["adapter_version"], row["processing"])
            for row in report["systems"]] == [("baseline", "fake", "1.1.0", "full"),
                                              ("candidate", "fake", "1.2.0", "full")]
    assert [comparison[side]["adapter_version"] for side in ("baseline", "candidate")] == ["1.1.0", "1.2.0"]
    assert comparison["configuration_differences"] == [
        {"key": "adapter_version", "baseline": "1.1.0", "candidate": "1.2.0", "absent_in": None}]
    unintended = configuration_requirement(comparison, [])
    assert unintended["status"] == "inconclusive" and unintended["observed"]["not_allowed"] == ["adapter_version"]
    assert configuration_requirement(comparison, ["adapter_version"])["status"] == "pass"


def test_a_curated_system_is_marked_in_every_report_and_compared_with_a_full_one_only_explicitly(tmp_path):
    """config.process_manifest_by_tree makes a DeepSec 1.2.0 system curated; the marker changes no figure.

    Both systems delivered the same scans, so every figure of theirs is equal. The curated one is marked in the
    aggregate, condition-strata, and comparison rows, its caveat is in every view and in the strata notes, and the
    full one carries neither. Comparing them lists processing beside the key that curates, so a policy allowing
    every config key still leaves the configuration requirement inconclusive until it also names processing.
    """
    outcomes = {(f"p{index}", system_id, 1): scan(hits={f"T-p{index}": 1})
                for index in (1, 2) for system_id in ("deepsec-full", "deepsec-curated")}
    run = write_run(tmp_path, "run-curated", five_project_inputs(), systems=("deepsec-full", "deepsec-curated"),
                    outcomes=outcomes, configs={"deepsec-full": DEEPSEC_FULL, "deepsec-curated": DEEPSEC_CURATED},
                    versions={"deepsec-full": "1.2.0", "deepsec-curated": "1.2.0"})
    caveat = f"deepsec-curated: {CURATED_CAVEAT}"

    report = aggregate.aggregate([run], policy=policy())
    strata = aggregate.aggregate_by_condition([run], policy=policy())
    comparison = aggregate.compare([run], baseline="deepsec-full", candidate="deepsec-curated", policy=policy())

    for document in (report, strata):
        assert {row["system_id"]: row["processing"] for row in document["systems"]} == {
            "deepsec-curated": "curated", "deepsec-full": "full"}
    assert [warning for warning in view(report)["warnings"] if "processing" in warning] == [caveat]
    assert [note for note in strata["notes"] if "processing" in note] == [caveat]
    full, curated = (system(view(report), system_id) for system_id in ("deepsec-full", "deepsec-curated"))
    assert {**curated, "system_id": None} == {**full, "system_id": None}
    assert detection(slice_of(curated))["full_output_recall"]["value"] == 0.4

    assert [comparison[side]["processing"] for side in ("baseline", "candidate")] == ["full", "curated"]
    assert comparison["configuration_differences"] == [
        {"key": f"config.process_manifest_by_tree.{CURATED_TREE}", "baseline": None, "candidate": ["src/server.js"],
         "absent_in": "baseline"},
        {"key": "processing", "baseline": "full", "candidate": "curated", "absent_in": None}]
    assert [warning for warning in view(comparison)["warnings"] if "processing" in warning] == [caveat]
    broad = configuration_requirement(comparison, ["config"])
    assert broad["status"] == "inconclusive" and broad["observed"]["not_allowed"] == ["processing"]
    assert configuration_requirement(comparison, ["config", "processing"])["status"] == "pass"


@pytest.mark.parametrize("adapter, config, version, expected", [
    ("deepsec", {"model": "m"}, "1.2.0", ("full", None)),
    ("semgrep", {"process_manifest_by_tree": {CURATED_TREE: ["a.py"]}}, "2.1.0", ("full", None)),
    ("deepsec", {"process_manifest_by_tree": {CURATED_TREE: ["a.js"]}}, "1.2.0", ("curated", CURATED_CAVEAT)),
    ("deepsec", {"process_manifest_by_tree": None}, "1.2.0", ("curated", CURATED_CAVEAT)),
    ("deepsec", {"process_manifest_by_tree": {CURATED_TREE: ["a.js"]}}, "1.10.0", ("curated", CURATED_CAVEAT)),
    ("deepsec", {"process_manifest_by_tree": {CURATED_TREE: ["a.js"]}}, "1.2", ("curated", CURATED_CAVEAT)),
    ("deepsec", {"process_manifest_by_tree": {CURATED_TREE: ["a.js"]}}, None, ("curated", CURATED_CAVEAT)),
    ("deepsec", {"process_manifest_by_tree": {CURATED_TREE: ["a.js"]}}, "1.1.0-dev", ("curated", CURATED_CAVEAT)),
    ("deepsec", {"process_manifest_by_tree": {CURATED_TREE: ["a.js"]}}, "1.1.0\n", ("curated", CURATED_CAVEAT)),
    ("deepsec", {"process_manifest_by_tree": {CURATED_TREE: ["a.js"]}}, "1.1.0", ("full", (
        "its configuration names deepsec config.process_manifest_by_tree, which adapter deepsec 1.1.0 predates and "
        "ignores, so it ran unscoped and its processing is full"))),
    ("deepsec", {"process_manifest_by_tree": {CURATED_TREE: ["a.js"]}}, "0.9", ("full", (
        "its configuration names deepsec config.process_manifest_by_tree, which adapter deepsec 0.9 predates and "
        "ignores, so it ran unscoped and its processing is full"))),
    ("deepsec", {"process_manifest_by_tree": {CURATED_TREE: ["a.js"]}}, "1.1", ("full", (
        "its configuration names deepsec config.process_manifest_by_tree, which adapter deepsec 1.1 predates and "
        "ignores, so it ran unscoped and its processing is full"))),
])
def test_processing_is_curated_where_the_configuration_curates_and_no_recorded_version_ignored_it(
        adapter, config, version, expected):
    """Only DeepSec's key curates, whatever its value, since the adapter refuses a malformed map rather than run
    unscoped. A version ordered below 1.2.0 as release numbers, a missing trailing part counting as zero, ignored
    it, so 1.2 does not and 1.1 does; one that is unknown or not dot-separated numbers is taken as configured."""
    assert aggregate.system_processing(adapter, config, version) == expected


class FakeAdapterNext(FakeAdapter):
    adapter_version = "1.1.0"


class FakeAdapterUnversioned(FakeAdapter):
    # Not a string: the runner skips the system and its manifest records no version.
    adapter_version = 1.1


class FakeAdapterUnprepared(FakeAdapterNext):
    # A usable version and a failed preparation, as a DeepSec whose executable is missing: the runner skips the
    # system and its manifest records the version anyway.
    def prepare(self, spec, cache_root):
        raise AdapterError("fixture scanner executable not found")


def test_the_versions_the_runner_records_decide_whether_its_runs_pool(tmp_path, upstream):
    """Real manifests: one configuration run by fake 1.0.0 and by fake 1.1.0 is refused, and a run that skipped
    the system pools with the 1.0.0 run, whether its adapter declared no usable version or declared 1.1.0 and
    failed to prepare: the runner wrote no invocation of it, so nothing in that run ran under either version."""
    repo, commit = upstream
    pack = cases.new_pack("test", "aggregate-versions", "Local fixture pack for the adapter version tests.")
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

    def run(run_id: str, adapter: Adapter) -> Path:
        config = {"schema_version": "2.1", "run_id": run_id, "pack": "pack.json", "cache_root": "cache",
                  "inputs": [{"snapshot_id": "snap-a"}],
                  "systems": [{"system_id": "fake-a", "adapter": "fake", "config": {"knob": 1}}],
                  "repetitions": 1, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none"}
        (tmp_path / f"{run_id}.json").write_text(canonical_json(config) + "\n", encoding="utf-8")
        run_from_config(tmp_path / f"{run_id}.json", tmp_path / run_id, clock=CLOCK, adapters={"fake": adapter})
        return tmp_path / run_id

    first, second = run("run-first", FakeAdapter()), run("run-second", FakeAdapterNext())
    skipped, unprepared = run("run-skipped", FakeAdapterUnversioned()), run("run-unprepared", FakeAdapterUnprepared())
    assert [(row["adapter_version"], row["skipped_reason"] is not None)
            for run_dir in (first, second, skipped, unprepared)
            for row in json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))["systems"]] == [
        ("1.0.0", False), ("1.1.0", False), (None, True), ("1.1.0", True)]

    with pytest.raises(ContractError, match="recorded as adapter fake 1.0.0 in run run-first and as fake 1.1.0 in "
                                            "run run-second"):
        aggregate.aggregate([first, second], policy=policy())
    report = aggregate.aggregate([first, skipped], policy=policy())
    assert [(row["adapter_version"], row["runs"]) for row in report["systems"]] == [
        ("1.0.0", ["run-first", "run-skipped"])]
    assert system(view(report), "fake-a")["observations"]["failures"]["skipped_system"] == 1
    report = aggregate.aggregate([first, unprepared], policy=policy())
    assert [(row["adapter_version"], row["runs"]) for row in report["systems"]] == [
        ("1.0.0", ["run-first", "run-unprepared"])]
    assert system(view(report), "fake-a")["observations"]["failures"]["skipped_system"] == 1
    assert slice_of(system(view(report), "fake-a"))["completion"]["value"] == 1 / 2
    assert any(warning.startswith("fake-a: run(s) run-unprepared ran nothing for it")
               for warning in view(report)["warnings"])


@pytest.mark.parametrize("configured, version, recorded, derived", [
    (DEEPSEC_CURATED, "1.2.1", "full", "curated"),
    (DEEPSEC_FULL, "1.2.1", "curated", "full"),
    (DEEPSEC_CURATED, "1.1.0", "curated", "full"),
    ({}, "1.0.0", "curated", "full"),
], ids=["curated-edited-to-full", "full-edited-to-curated", "ignored-key-recorded-curated", "no-curated-mode"])
def test_a_bundle_whose_result_contradicts_its_system_s_processing_is_refused_wherever_runs_are_pooled(
        tmp_path, configured, version, recorded, derived):
    """An edited bundle does not pass silently, and it does not become a failure nobody traces back to it either.

    Every document of the edited bundle binds to every other, as an edit that rehashed them would leave them, and the
    other bundles record nothing, so the system's processing is the one its configuration and adapter version give.
    The one marker that contradicts it is named by run and invocation wherever runs are pooled: a DeepSec curated
    result edited to full, a full one edited to curated, curated recorded beside an adapter that predates the key, and
    curated recorded for an adapter with no curated mode this evaluator knows.
    """
    inputs = [planned("p1", targets=[target("T-p1")]), planned("p2", targets=[target("T-p2")], project="acme/beta")]
    edited = write_run(tmp_path, "run-a", inputs, systems=("other", "sys-a"),
                       configs={"sys-a": configured}, versions={"sys-a": version},
                       outcomes={("p2", "sys-a", 1): scan(hits={"T-p2": 1}, processing=recorded)})
    message = (f"system sys-a is recorded as processing {recorded} in run run-a (p2__sys-a__r1), but its configuration "
               f"and adapter version make it {derived}; a bundle must record the processing its system ran with to be "
               "aggregated, so this one was edited or comes from an adapter whose curation rule this evaluator does "
               "not know")

    for refused in (lambda: aggregate.aggregate([edited], policy=policy()),
                    lambda: aggregate.aggregate_by_condition([edited], policy=policy()),
                    lambda: aggregate.compare([edited], baseline="other", candidate="sys-a", policy=policy())):
        with pytest.raises(ContractError) as excinfo:
            refused()
        assert str(excinfo.value) == message


def test_a_result_edited_to_contradict_its_processing_without_rebinding_its_decisions_is_an_unusable_bundle(tmp_path):
    """The binding check reads first: the edited result no longer binds to the decisions written against it, so it is
    the failure any unbound edit already was, and the run aggregates with it in every denominator, still curated."""
    inputs = [planned("p1", targets=[target("T-p1")])]
    run = write_run(tmp_path, "run-a", inputs, systems=("deepsec-x",), configs={"deepsec-x": DEEPSEC_CURATED},
                    versions={"deepsec-x": "1.2.1"}, outcomes={("p1", "deepsec-x", 1): scan(hits={"T-p1": 1})})
    path = run / "invocations" / "p1__deepsec-x__r1" / "result.json"
    result = json.loads(path.read_text(encoding="utf-8"))
    path.write_text(canonical_json({**result, "schema_version": "2.1", "processing": "full"}) + "\n", encoding="utf-8")

    report = aggregate.aggregate([run], policy=policy())

    assert system(view(report), "deepsec-x")["observations"]["failures"]["unusable_bundle"] == 1
    assert [row["processing"] for row in report["systems"]] == ["curated"]


def test_results_that_record_their_system_s_processing_pool_with_results_written_before_the_marker(tmp_path):
    """One curated and one full DeepSec configuration at one adapter version, run before results recorded the marker
    and after: run-a's results record nothing and are read by the derivation, run-b's record what the derivation
    gives, so each system pools both runs, with the one caveat the curated system always had and no other."""
    inputs = [planned("p1", targets=[target("T-p1")])]
    configs = {"deepsec-full": DEEPSEC_FULL, "deepsec-x": DEEPSEC_CURATED}
    versions = {"deepsec-full": "1.2.1", "deepsec-x": "1.2.1"}
    before = write_run(tmp_path / "a", "run-a", inputs, systems=("deepsec-full", "deepsec-x"), configs=configs,
                       versions=versions, outcomes={("p1", "deepsec-x", 1): scan(hits={"T-p1": 1})})
    after = write_run(tmp_path / "b", "run-b", inputs, systems=("deepsec-full", "deepsec-x"), configs=configs,
                      versions=versions, outcomes={("p1", "deepsec-x", 1): scan(processing="curated"),
                                                   ("p1", "deepsec-full", 1): scan(processing="full")})
    recorded = json.loads((after / "invocations" / "p1__deepsec-x__r1" / "result.json").read_text(encoding="utf-8"))
    assert (recorded["schema_version"], recorded["processing"]) == ("2.1", "curated")

    report = aggregate.aggregate([before, after], policy=policy())

    assert [(row["system_id"], row["processing"], row["runs"]) for row in report["systems"]] == [
        ("deepsec-full", "full", ["run-a", "run-b"]), ("deepsec-x", "curated", ["run-a", "run-b"])]
    assert [warning for warning in view(report)["warnings"] if "processing" in warning] == [
        f"deepsec-x: {CURATED_CAVEAT}"]
    assert slice_of(system(view(report), "deepsec-x"))["completion"]["value"] == 1
    assert recall(report, system_id="deepsec-x") == 0.5


def test_the_comparison_schema_and_the_aggregation_doc_name_every_key_a_configuration_difference_starts_with(
        tmp_path):
    """A gate policy measures a configuration difference only by naming its key, and its author reads which keys a
    comparison can list from the comparison schema or from docs/AGGREGATION.md, so both name every top-level key
    compare reads a system's identity by, and no other."""
    run = write_run(tmp_path, "run-a", [planned("p1", targets=[target("T-p1")])])
    compared = set(aggregate._identity(aggregate._load_corpus([run]).systems["sys-a"]))
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "src" / "scaneval" / "schemas" / "comparison-report.schema.json")
                        .read_text(encoding="utf-8"))
    texts = {"comparison-report schema": schema["properties"]["configuration_differences"]["description"],
             "docs/AGGREGATION.md": (root / "docs" / "AGGREGATION.md").read_text(encoding="utf-8")}

    assert compared == {"adapter", "adapter_version", "config", "execution", "model_id", "model_revision",
                        "network_policy", "processing", "timeout_seconds"}
    for where, text in texts.items():
        listed = text.split("as a dotted key over ", 1)[1].split(".", 1)[0]
        names = {name.strip("` ").removeprefix("and ").strip("` ") for name in listed.split(",")}
        assert names == compared, where
