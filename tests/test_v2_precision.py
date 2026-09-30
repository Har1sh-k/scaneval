"""Precision sampling and human review: the frame, the seeded draw, the chained reviews, the estimate.

Most run directories here are built in ``tmp_path`` from fixture documents: a frozen schedule, a 2.1
manifest, and a saved result per invocation that ran, which is everything a precision frame reads.
The end-to-end tests run the real runner with a scripted fake adapter over a local ``git init``
fixture instead. Every reviewer is explicitly fictional. No network, no model calls, and no clock
reaches a derived document.

The hand-computed figures are in each test's docstring; the assertions compare against the same
fractions, so a figure that is exact on paper is checked exactly.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
from statistics import NormalDist
import subprocess

import pytest

from scaneval import cases, precision, review, scoring
from scaneval.adapters.base import Adapter, NativeOutcome
from scaneval.cli import main
from scaneval.contracts import (
    SCHEMA_VERSIONS,
    ContractError,
    canonical_json,
    canonical_sha256,
    load_document,
    validate_document,
)
from scaneval.resampling import ALGORITHM
from scaneval.runner import run_from_config


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
LATER = lambda: datetime(2026, 9, 21, 9, 30, tzinfo=timezone.utc)  # noqa: E731
CREATED_AT = "2026-09-20T15:00:00+00:00"
CONFIG_HASH = "sha256:" + "c" * 64
PACK_HASH = "sha256:" + "e" * 64
MAP_IDENTITY = {"map_id": "widget-metadata", "map_version": "1", "map_sha256": "sha256:" + "d" * 64}
REVIEWER_A = "Fixture Reviewer A (fictional)"
REVIEWER_B = "Fixture Reviewer B (fictional)"
ADJUDICATOR = "Fixture Adjudicator (fictional)"
Z95 = NormalDist().inv_cdf(0.975)


# --- fixture run directories -----------------------------------------------------------------------


def claim(claim_id: str, allegation: str, *, kind: str = "command_injection", path: str = "src/app.py",
          line: int = 5, rule: str | None = "fixture.rule", evidence: str | None = None) -> dict:
    value = {"claim_id": claim_id, "allegation": allegation, "kind": kind,
             "primary_location": {"path": path, "start_line": line, "end_line": line}}
    if rule is not None:
        value["native_rule_id"] = rule
    if evidence is not None:
        value["evidence_text"] = evidence
    return value


def distinct(prefix: str, count: int, **kwargs) -> list[dict]:
    """*count* claims that are all different allegations, ids ``<prefix>1`` onward."""
    return [claim(f"{prefix}{index}", f"allegation {prefix}{index}", line=index, **kwargs)
            for index in range(1, count + 1)]


def output(claims: list[dict], *, ranking: str = "native", bundles_resolved: bool = True,
           status: str = "success") -> dict:
    return {"claims": claims, "ranking": ranking, "bundles_resolved": bundles_resolved, "status": status}


def tree_hash(input_id: str) -> str:
    return canonical_sha256({"fixture tree": input_id})


def write_document(path: Path, kind: str, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(validate_document(kind, document)) + "\n", encoding="utf-8")


def write_run(root: Path, run_id: str, outputs: dict[tuple[str, str], dict | None], *,
              profiles: dict[str, str] | None = None) -> Path:
    """One run directory: a frozen schedule, a 2.1 manifest, and a saved result per invocation that ran.

    *outputs* maps (input id, system id) to an :func:`output`, or to ``None`` for an assignment that
    was skipped; every other pairing of the inputs and systems it names is skipped too. One
    repetition. Native claims get ranks in list order, as the scan-result contract requires.
    """
    profiles = profiles or {}
    inputs = sorted({input_id for input_id, _ in outputs})
    systems = sorted({system_id for _, system_id in outputs})
    run_dir = root / run_id
    schedule = {
        "schema_version": "2.1", "run_id": run_id, "created_at": CREATED_AT, "config_sha256": CONFIG_HASH,
        "pack": {"namespace": "org.example", "pack_id": "precision", "version": "1", "sha256": PACK_HASH},
        "repetitions": 1,
        "inputs": [{"input_id": input_id, "mode": "full", "profile": profiles.get(input_id, "standard"),
                    "snapshot_id": input_id, "change_set_id": None, "change_set": None,
                    "blinding": MAP_IDENTITY if profiles.get(input_id) == "metadata_blinded" else None,
                    "project": "acme/widget", "workload": "conventional_application",
                    "component_role": "application", "declared_tree_hash": None,
                    "plan": {"state": "unavailable", "reason": "fixture: no plan is needed to sample claims"}}
                   for input_id in inputs],
        "systems": [{"system_id": system_id, "adapter": "fake", "model_id": None, "model_revision": None,
                     "config_sha256": CONFIG_HASH, "network_policy": "none",
                     "execution": {"backend": "local", "enforced_expected": False, "image": None}}
                    for system_id in systems],
        "assignments": [{"assignment_id": f"{input_id}__{system_id}__r1", "input_id": input_id,
                         "system_id": system_id, "repetition": 1}
                        for input_id in inputs for system_id in systems],
        "pairs": [], "notes": ["Fixture schedule."],
    }
    invocations = []
    for input_id in inputs:
        for system_id in systems:
            invocation_id = f"{input_id}__{system_id}__r1"
            row = {"invocation_id": invocation_id, "input_id": input_id, "system_id": system_id, "repetition": 1}
            produced = outputs.get((input_id, system_id))
            if produced is None:
                invocations.append({**row, "status": "skipped", "claim_records": None, "plan_scope": None,
                                    "targets_assigned": None, "targets_detected": None,
                                    "pending_matching_count": None, "bundle_path": None, "review_state": None,
                                    "skipped_reason": "fixture: this assignment was never invoked"})
                continue
            claims = deepcopy(produced["claims"])
            if produced["ranking"] == "native":
                claims = [{**item, "rank": index} for index, item in enumerate(claims, start=1)]
            write_document(run_dir / "invocations" / invocation_id / "result.json", "scan-result", {
                "schema_version": "2.0", "run_id": run_id, "system_id": system_id,
                "input_hash": tree_hash(input_id), "status": produced["status"],
                "ranking": produced["ranking"], "claims": claims,
                "bundles_resolved": produced["bundles_resolved"], "usage": {"wall_seconds": 1}})
            invocations.append({**row, "status": produced["status"], "claim_records": len(claims),
                                "plan_scope": "draft", "targets_assigned": 0, "targets_detected": 0,
                                "pending_matching_count": 0, "bundle_path": f"invocations/{invocation_id}",
                                "review_state": "draft", "skipped_reason": None})
    write_document(run_dir / "evaluator" / "schedule.json", "evaluation-schedule", schedule)
    write_document(run_dir / "run-manifest.json", "run-manifest", {
        "schema_version": "2.1", "run_id": run_id, "status": "completed", "created_at": CREATED_AT,
        "config_sha256": CONFIG_HASH,
        "pack": {"namespace": "org.example", "pack_id": "precision", "version": "1", "status": "draft",
                 "snapshots": len(inputs), "cases": 0,
                 "review_states": {"draft": 0, "mechanically_checked": 0, "human_approved": 0},
                 "dispositions": {"validate": 0, "needs_evidence": 0, "extended_regression": 0, "exclude": 0},
                 "sha256": PACK_HASH},
        "selection": {"only_inputs": None, "only_systems": None, "excluded_inputs": [], "excluded_systems": []},
        "inputs": [{"input_id": input_id, "mode": "full", "profile": profiles.get(input_id, "standard"),
                    "snapshot_id": input_id, "tree_hash": tree_hash(input_id), "input_hash": tree_hash(input_id),
                    "provenance_path": None, "mechanical_checks": [], "preparation_failure": None}
                   for input_id in inputs],
        "systems": [{"system_id": system_id, "adapter": "fake", "adapter_version": "1.0.0", "preparation": {},
                     "skipped_reason": None} for system_id in systems],
        "invocations": invocations, "warnings": [], "schedule_path": "evaluator/schedule.json",
    })
    return run_dir


def two_strata_run(root: Path, run_id: str = "run-strata", *, sizes: tuple[int, int] = (6, 4)) -> Path:
    """sys-a and sys-b each deliver distinct claims on one input: ``sizes`` units each."""
    return write_run(root, run_id, {("snap-a", "sys-a"): output(distinct("a", sizes[0])),
                                    ("snap-a", "sys-b"): output(distinct("b", sizes[1]))})


def one_system_run(root: Path, count: int, run_id: str = "run-one") -> Path:
    return write_run(root, run_id, {("snap-a", "sys-a"): output(distinct("k", count))})


def selected_by_stratum(sample: dict) -> dict[str, list[str]]:
    """The sample's selected unit ids per stratum, in unit-id order."""
    out: dict[str, list[str]] = {}
    for entry in sample["selected"]:
        out.setdefault(entry["stratum"], []).append(entry["unit_id"])
    return out


def cli(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- the frame ---------------------------------------------------------------------------------------


def test_a_unit_is_one_exact_duplicate_group_within_one_invocation(tmp_path):
    """sys-a delivers c1, c2 (an exact duplicate of c1) and c3; sys-b delivers c1's allegation again.

    Hand count: 3 units, not 4 claims and not 2 allegations. sys-a's pair is one unit with 2 copies
    and first rank 1; c3 is a unit of its own at rank 3; sys-b's copy of the same allegation is a
    separate unit, because a unit never spans two invocations. The grouping is the one scoring uses.
    """
    shell = "shell=True with a caller-controlled command"
    sys_a = [claim("c1", shell), claim("c2", shell), claim("c3", "path traversal in the upload handler",
                                                           kind="path_traversal", line=9)]
    run_dir = write_run(tmp_path, "run-a", {("snap-a", "sys-a"): output(sys_a),
                                            ("snap-a", "sys-b"): output([claim("c1", shell)])})

    frame = precision.build_frame([run_dir], population="full")

    assert [(u["unit_id"], u["claim_ids"], u["delivered_copies"], u["population_copies"], u["first_rank"])
            for u in frame["units"]] == [
        ("run-a/snap-a__sys-a__r1/c1", ["c1", "c2"], 2, 2, 1),
        ("run-a/snap-a__sys-a__r1/c3", ["c3"], 1, 1, 3),
        ("run-a/snap-a__sys-b__r1/c1", ["c1"], 1, 1, 1)]
    first, _, other = frame["units"]
    assert first["fingerprint"] == other["fingerprint"] == scoring.claim_fingerprint(sys_a[1])
    assert first["claim"] == {key: value for key, value in sys_a[0].items() if key != "claim_id"}
    # The same duplicate identity observe() reports for this bundle: one group, two unique claims.
    result = load_document(run_dir / "invocations" / "snap-a__sys-a__r1" / "result.json", "scan-result")
    plan = {"schema_version": "2.0", "input_hash": result["input_hash"], "scope": "diagnostic",
            "targets": [], "controls": [], "review_budgets": [5]}
    decisions = {"schema_version": "2.0", "run_id": "run-a", "input_hash": result["input_hash"],
                 "result_sha256": canonical_sha256(result), "claim_matches": [], "control_assessments": []}
    observed = scoring.observe(plan, result, decisions)
    assert observed["duplicate_groups"] == [{"canonical_claim_id": "c1", "claim_ids": ["c1", "c2"]}]
    assert observed["claims"]["unique"] == 2 == sum(u["system_id"] == "sys-a" for u in frame["units"])
    assert frame["runs"] == [{"run_id": "run-a", "status": "completed",
                              "manifest_sha256": canonical_sha256(load_document(run_dir / "run-manifest.json",
                                                                                "run-manifest")),
                              "schedule_sha256": canonical_sha256(load_document(
                                  run_dir / "evaluator" / "schedule.json", "evaluation-schedule"))}]


def test_the_first_b_population_leaves_out_unranked_and_unresolved_invocations_and_counts_them(tmp_path):
    """B = 2 over four systems on one input.

    sys-a (native, resolved): X at ranks 1 and 2, Y at 3, Z at 4. Only X is inside first_b, with both
    of its copies; Y and Z are 2 units and 2 copies past B. sys-b (native, bundles unresolved): 2
    claims, 2 units, left out. sys-c (unranked): V, V again, W: 3 claims, 2 units, left out. sys-d
    was skipped: 1 assignment with no output. The full population of the same run holds 3 + 2 + 2 = 7
    units in 4 + 2 + 3 = 9 copies and leaves nothing out but the skipped assignment.
    """
    run_dir = write_run(tmp_path, "run-b", {
        ("snap-a", "sys-a"): output([claim("x1", "X"), claim("x2", "X"), claim("y1", "Y"), claim("z1", "Z")]),
        ("snap-a", "sys-b"): output([claim("u1", "U1"), claim("u2", "U2")], bundles_resolved=False),
        ("snap-a", "sys-c"): output([claim("v1", "V"), claim("v2", "V"), claim("w1", "W")], ranking="unranked"),
        ("snap-a", "sys-d"): None,
    })

    frame = precision.build_frame([run_dir], population="first_b", budget=2)

    assert [(u["unit_id"], u["population_copies"]) for u in frame["units"]] == [("run-b/snap-a__sys-a__r1/x1", 2)]
    assert {row["system_id"]: (row["state"], row["status"]) for row in frame["invocations"]} == {
        "sys-a": ("included", "success"), "sys-b": ("bundle_unresolved", "success"),
        "sys-c": ("unranked", "success"), "sys-d": ("no_output", "skipped")}
    assert frame["exclusions"] == {"no_output": {"invocations": 1},
                                   "unranked": {"invocations": 1, "claim_records": 3, "units": 2},
                                   "bundle_unresolved": {"invocations": 1, "claim_records": 2, "units": 2},
                                   "beyond_budget": {"units": 2, "copies": 2}}
    sample = precision.draw_sample(frame, size=1, seed=3)
    assert any("leaves out 1 unranked invocation(s) holding 2 unit(s) and 1 bundle-unresolved invocation(s) "
               "holding 2 unit(s)" in note and "2 unit(s) past B" in note for note in sample["notes"])

    full = precision.build_frame([run_dir], population="full")
    assert len(full["units"]) == 7 and sum(u["population_copies"] for u in full["units"]) == 9
    assert full["exclusions"] == {"no_output": {"invocations": 1},
                                  "unranked": {"invocations": 0, "claim_records": 0, "units": 0},
                                  "bundle_unresolved": {"invocations": 0, "claim_records": 0, "units": 0},
                                  "beyond_budget": {"units": 0, "copies": 0}}
    assert any("2 unit(s) come from invocations whose bundles are unresolved" in note
               for note in precision.draw_sample(full, size=1, seed=3)["notes"])


def test_a_frame_reads_only_the_declared_view_and_the_chosen_systems(tmp_path):
    """A standard and a metadata-blinded input in one run, two systems: each view holds only its own."""
    run_dir = write_run(tmp_path, "run-view", {
        ("snap-a", "sys-a"): output(distinct("s", 2)), ("snap-a", "sys-b"): output(distinct("t", 1)),
        ("snap-a.blinded", "sys-a"): output(distinct("m", 3)), ("snap-a.blinded", "sys-b"): None,
    }, profiles={"snap-a.blinded": "metadata_blinded"})

    standard = precision.build_frame([run_dir], population="full")
    blinded = precision.build_frame([run_dir], population="full", profile="metadata_blinded")
    only_b = precision.build_frame([run_dir], population="full", systems=["sys-b"])

    assert {u["input_id"] for u in standard["units"]} == {"snap-a"} and len(standard["units"]) == 3
    assert [u["claim_ids"] for u in blinded["units"]] == [["m1"], ["m2"], ["m3"]]
    assert blinded["exclusions"]["no_output"] == {"invocations": 1}
    assert only_b["population"]["systems"] == ["sys-b"] and len(only_b["units"]) == 1
    with pytest.raises(ContractError, match="not scheduled in any of these runs: sys-z"):
        precision.build_frame([run_dir], population="full", systems=["sys-z"])
    with pytest.raises(ContractError, match="systems must be a list of system ids, not the string 'sys-b'"):
        precision.build_frame([run_dir], population="full", systems="sys-b")
    with pytest.raises(ContractError, match="name at least one system"):
        precision.build_frame([run_dir], population="full", systems=[])
    with pytest.raises(ContractError, match="no assignment of sys-a, sys-b in these runs is a pr input"):
        precision.build_frame([run_dir], population="full", mode="pr")


def test_a_frame_refuses_what_it_cannot_bind_to(tmp_path):
    run_dir = one_system_run(tmp_path, 3)
    with pytest.raises(ContractError, match="first_b population needs a budget"):
        precision.build_frame([run_dir], population="first_b")
    with pytest.raises(ContractError, match="budget applies only to the first_b"):
        precision.build_frame([run_dir], population="full", budget=5)
    for budget in (0, True, 2.5):
        with pytest.raises(ContractError, match="budget must be an integer of at least 1"):
            precision.build_frame([run_dir], population="first_b", budget=budget)
    with pytest.raises(ContractError, match="at least one run directory"):
        precision.build_frame([], population="full")
    with pytest.raises(ContractError, match="both hold run run-one"):
        precision.build_frame([run_dir, run_dir], population="full")
    copy = tmp_path / "copy"
    copy.mkdir()
    one_system_run(copy, 3)
    with pytest.raises(ContractError, match="both hold run run-one"):
        precision.build_frame([run_dir, copy / "run-one"], population="full")

    # A 2.0 manifest names no schedule, so it cannot say what its claims were assigned to answer.
    manifest = json.loads((run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    legacy = {key: value for key, value in manifest.items() if key != "schedule_path"}
    legacy.update(schema_version="2.0", inputs=[{"snapshot_id": "snap-a", "tree_hash": tree_hash("snap-a"),
                                                 "provenance_path": "inputs/snap-a/provenance.json",
                                                 "mechanical_checks": []}])
    old = tmp_path / "old-run"
    write_document(old / "run-manifest.json", "run-manifest", legacy)
    with pytest.raises(ContractError, match="predates frozen schedules"):
        precision.build_frame([old], population="full")

    # A result that names another system than its manifest row is not the result that row names.
    result_path = run_dir / "invocations" / "snap-a__sys-a__r1" / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result_path.write_text(canonical_json({**result, "system_id": "sys-other"}) + "\n", encoding="utf-8")
    with pytest.raises(ContractError, match="not of run run-one and system sys-a"):
        precision.build_frame([run_dir], population="full")


def test_an_empty_population_cannot_be_sampled(tmp_path):
    run_dir = write_run(tmp_path, "run-empty", {("snap-a", "sys-a"): output([])})
    frame = precision.build_frame([run_dir], population="full")
    assert frame["units"] == [] and frame["invocations"][0]["state"] == "included"
    with pytest.raises(ContractError, match="the full population holds no unit"):
        precision.draw_sample(frame, size=1, seed=0)


# --- the design ----------------------------------------------------------------------------------------


def test_identical_frame_and_seed_give_byte_identical_samples(tmp_path):
    """Two frames built separately from one run, one seed: the same sample, byte for byte."""
    run_dir = two_strata_run(tmp_path)

    first = precision.draw_sample(precision.build_frame([run_dir], population="full"), size=4, seed=20260929,
                                  stratify_by="system")
    second = precision.draw_sample(precision.build_frame([run_dir], population="full"), size=4, seed=20260929,
                                   stratify_by="system")
    other_seed = precision.draw_sample(precision.build_frame([run_dir], population="full"), size=4, seed=7,
                                       stratify_by="system")

    assert canonical_json(first) == canonical_json(second)
    assert first["design"] == {"method": "stratified_srswor", "stratify_by": "system", "allocation": "proportional",
                               "size": 4, "seed": 20260929, "algorithm": ALGORITHM,
                               "stream_label": "precision/{frame_sha256}/{stratum}"}
    assert first["selected"] != other_seed["selected"]


def test_the_sample_does_not_depend_on_run_order_or_directory_listing_order(tmp_path, monkeypatch):
    """Runs named in either order, and every directory listed backwards, give one sample."""
    run_a = write_run(tmp_path, "run-a", {("snap-a", "sys-a"): output(distinct("a", 5)),
                                          ("snap-b", "sys-a"): output(distinct("b", 3))})
    run_b = write_run(tmp_path, "run-b", {("snap-a", "sys-a"): output(distinct("c", 4))})

    forward = precision.draw_sample(precision.build_frame([run_a, run_b], population="full"), size=5, seed=11,
                                    stratify_by="input")
    backward = precision.draw_sample(precision.build_frame([run_b, run_a], population="full"), size=5, seed=11,
                                     stratify_by="input")

    real_listdir, real_scandir, real_iterdir = os.listdir, os.scandir, Path.iterdir

    class ReversedScandir:
        def __init__(self, path="."):
            with real_scandir(path) as entries:
                self._entries = sorted(entries, key=lambda entry: entry.name, reverse=True)

        def __iter__(self):
            return iter(self._entries)

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def close(self):
            pass

    monkeypatch.setattr(os, "listdir", lambda path=".": sorted(real_listdir(path), reverse=True))
    monkeypatch.setattr(os, "scandir", ReversedScandir)
    monkeypatch.setattr(Path, "iterdir", lambda self: iter(sorted(real_iterdir(self), reverse=True)))
    listed_backwards = precision.draw_sample(precision.build_frame([run_b, run_a], population="full"), size=5,
                                             seed=11, stratify_by="input")

    assert canonical_json(forward) == canonical_json(backward) == canonical_json(listed_backwards)
    assert [row["run_id"] for row in forward["frame"]["runs"]] == ["run-a", "run-b"]
    unit_ids = [unit["unit_id"] for unit in forward["frame"]["units"]]
    assert unit_ids == sorted(unit_ids) and len(unit_ids) == 12


def test_simple_random_sampling_includes_every_unit_with_probability_n_over_n(tmp_path):
    """10 units, 3 drawn: pi = 3/10 = 0.3 for every unit, as recorded and as observed over 4000 seeds.

    The Monte Carlo loop calls the same :func:`precision.draw` the sample is made from (checked
    against :func:`precision.draw_sample` for the first seeds), so it tests the recorded algorithm.
    """
    frame = precision.build_frame([one_system_run(tmp_path, 10)], population="full")
    digest = canonical_sha256(frame)
    strata = precision.stratify(frame, None)
    allocated = precision.allocate({"all": 10}, 3, None)
    assert allocated == {"all": 3}

    counts: Counter[str] = Counter()
    trials = 4000
    for seed in range(trials):
        drawn = precision.draw(strata, allocated, seed=seed, frame_sha256=digest)["all"]
        if seed < 3:
            assert [entry["unit_id"] for entry in precision.draw_sample(frame, size=3, seed=seed)["selected"]] == drawn
        assert len(set(drawn)) == 3
        counts.update(drawn)

    sample = precision.draw_sample(frame, size=3, seed=0)
    assert sample["strata"] == [{"stratum": "all", "population_units": 10, "sampled_units": 3,
                                 "inclusion_probability": 0.3}]
    assert len(counts) == 10
    for unit_id in strata["all"]:
        assert abs(counts[unit_id] / trials - 0.3) < 0.03, unit_id


def test_stratified_sampling_includes_each_unit_with_its_strata_probability(tmp_path):
    """sys-a holds 6 units and sys-b 4. Equal allocation of 4 draws 2 from each, so pi = 2/6 = 1/3 in
    sys-a and 2/4 = 1/2 in sys-b; proportional allocation of 5 draws 5*6/10 = 3 and 5*4/10 = 2, so
    pi = 1/2 in both. Observed frequencies over 3000 seeds match within 0.035."""
    frame = precision.build_frame([two_strata_run(tmp_path)], population="full")
    digest = canonical_sha256(frame)
    strata = precision.stratify(frame, "system")
    sizes = {name: len(ids) for name, ids in strata.items()}
    assert sizes == {"sys-a": 6, "sys-b": 4}

    for allocation, size, expected in (("equal", 4, {"sys-a": 1 / 3, "sys-b": 1 / 2}),
                                       ("proportional", 5, {"sys-a": 1 / 2, "sys-b": 1 / 2})):
        allocated = precision.allocate(sizes, size, allocation)
        recorded = precision.draw_sample(frame, size=size, seed=0, stratify_by="system", allocation=allocation)
        assert {row["stratum"]: row["inclusion_probability"] for row in recorded["strata"]} == expected
        counts: Counter[str] = Counter()
        trials = 3000
        for seed in range(trials):
            drawn = precision.draw(strata, allocated, seed=seed, frame_sha256=digest)
            if seed < 2:
                redrawn = precision.draw_sample(frame, size=size, seed=seed, stratify_by="system",
                                                allocation=allocation)
                assert selected_by_stratum(redrawn) == drawn
            counts.update(unit_id for ids in drawn.values() for unit_id in ids)
        for name, ids in strata.items():
            for unit_id in ids:
                assert abs(counts[unit_id] / trials - expected[name]) < 0.035, (allocation, unit_id)


def test_allocation_follows_the_documented_rules_exactly():
    """Proportional, largest remainder: sizes 5, 5, 2 and n = 5 give exact shares 25/12, 25/12, 10/12;
    the whole parts 2, 2, 0 leave 1 unit, which goes to the largest fraction (c, 10/12). Sizes 3, 3 and
    n = 3 tie at 1.5 each, and the tie goes to the first name. Sizes 9, 1 and n = 5 tie at 4.5 and 0.5
    fractions of one half, so sys-a takes the unit and sys-b draws nothing.

    Equal: sizes 1, 10, 10 and n = 9 take the one-unit stratum whole and share the other 8 as 4 and 4;
    sizes 3, 8 and n = 7 take the first whole (3 <= 3) and give the rest 4; sizes 5, 5, 5 and n = 2 give
    the remainder to the first two names and leave c with nothing.
    """
    assert precision.allocate({"a": 5, "b": 5, "c": 2}, 5, "proportional") == {"a": 2, "b": 2, "c": 1}
    assert precision.allocate({"a": 3, "b": 3}, 3, "proportional") == {"a": 2, "b": 1}
    assert precision.allocate({"sys-a": 9, "sys-b": 1}, 5, "proportional") == {"sys-a": 5, "sys-b": 0}
    assert precision.allocate({"a": 4, "b": 6}, 10, "proportional") == {"a": 4, "b": 6}
    assert precision.allocate({"a": 1, "b": 10, "c": 10}, 9, "equal") == {"a": 1, "b": 4, "c": 4}
    assert precision.allocate({"a": 3, "b": 8}, 7, "equal") == {"a": 3, "b": 4}
    assert precision.allocate({"a": 5, "b": 5, "c": 5}, 2, "equal") == {"a": 1, "b": 1, "c": 0}
    with pytest.raises(ContractError, match="cannot draw 11 of 10 units"):
        precision.allocate({"a": 4, "b": 6}, 11, "equal")
    for size in (0, True, 1.0):
        with pytest.raises(ContractError, match="sample size must be an integer of at least 1"):
            precision.allocate({"a": 4}, size, None)
    with pytest.raises(ContractError, match="allocation must be one of"):
        precision.allocate({"a": 4}, 1, "neyman")


def test_a_design_names_its_stratification_and_allocation_together(tmp_path):
    frame = precision.build_frame([two_strata_run(tmp_path)], population="full")
    with pytest.raises(ContractError, match="applies to a stratified design"):
        precision.draw_sample(frame, size=2, seed=0, allocation="equal")
    with pytest.raises(ContractError, match="stratify_by must be one of"):
        precision.draw_sample(frame, size=2, seed=0, stratify_by="repository")
    for seed in (-1, True, "7"):
        with pytest.raises(ContractError, match="seed must be a non-negative integer"):
            precision.draw_sample(frame, size=2, seed=seed)
    by_kind = precision.draw_sample(frame, size=2, seed=0, stratify_by="kind")
    assert [row["stratum"] for row in by_kind["strata"]] == ["command_injection"]


def test_a_sample_edited_after_its_draw_is_refused(tmp_path):
    """A swapped unit keeps every count the contract checks, so only drawing again can catch it."""
    frame = precision.build_frame([one_system_run(tmp_path, 5)], population="full")
    sample = precision.draw_sample(frame, size=2, seed=4)
    drawn = {entry["unit_id"] for entry in sample["selected"]}
    undrawn = sorted(unit["unit_id"] for unit in frame["units"] if unit["unit_id"] not in drawn)[0]

    swapped = deepcopy(sample)
    swapped["selected"][0]["unit_id"] = undrawn
    swapped["selected"].sort(key=lambda entry: entry["unit_id"])
    validate_document("precision-sample", swapped)
    with pytest.raises(ContractError, match=r"not what seed 4 and its design draw from its frame \(selected differ\)"):
        precision.verify_sample(swapped)

    reseeded = {**deepcopy(sample), "design": {**sample["design"], "seed": 5}}
    with pytest.raises(ContractError, match="not what seed 5"):
        precision.verify_sample(reseeded)

    rewritten = deepcopy(sample)
    rewritten["frame"]["units"][0]["claim"]["allegation"] = "a different allegation"
    rewritten["frame_sha256"] = canonical_sha256(rewritten["frame"])
    with pytest.raises(ContractError, match="does not hash to the fingerprint"):
        precision.verify_sample(rewritten)

    unhashed = deepcopy(sample)
    unhashed["frame"]["units"][0]["delivered_copies"] = 1
    unhashed["frame"]["units"][0]["claim"]["kind"] = "other"
    with pytest.raises(ContractError, match="frame_sha256 does not hash the frame"):
        validate_document("precision-sample", unhashed)

    foreign = {**deepcopy(sample), "design": {**sample["design"], "algorithm": "mersenne-twister"}}
    with pytest.raises(ContractError, match="drawn with mersenne-twister"):
        precision.verify_sample(foreign)


def test_the_precision_sample_kind_is_published_at_2_1_and_holds_itself_to_its_frame(tmp_path, capsys):
    """The contract recomputes what a sample says about its frame: every count, stratum, and alias."""
    sample = precision.draw_sample(precision.build_frame([two_strata_run(tmp_path)], population="full"),
                                   size=4, seed=1, stratify_by="system")
    assert SCHEMA_VERSIONS["precision-sample"] == ("2.1",)
    assert validate_document("precision-sample", sample) is sample
    path = tmp_path / "sample.json"
    path.write_text(canonical_json(sample) + "\n", encoding="utf-8")
    code, out, _ = cli(capsys, "validate", "precision-sample", str(path))
    assert code == 0 and "Valid precision-sample" in out
    with pytest.raises(ContractError, match="schema_version"):
        validate_document("precision-sample", {**sample, "schema_version": "2.0"})

    def edited(change) -> dict:
        document = deepcopy(sample)
        change(document)
        document["frame_sha256"] = canonical_sha256(document["frame"])
        return document

    refusals = [
        (lambda d: d["strata"][0].update(inclusion_probability=0.5), "inclusion probability must be sampled"),
        (lambda d: d["selected"][0].update(stratum="sys-b" if d["selected"][0]["stratum"] == "sys-a" else "sys-a"),
         "is not a unit of stratum"),
        (lambda d: d["blinding"]["system_aliases"].pop(), "every population system one alias"),
        (lambda d: d["uncovered_strata"].append("sys-a"), "uncovered_strata must list exactly"),
        (lambda d: d["design"].update(size=5), "design.size is 5, but 4 units are selected"),
        (lambda d: d["frame"]["units"][0].update(population_copies=2), "copy counts do not match"),
        (lambda d: d["frame"]["units"][0].update(unit_id="run-strata/elsewhere/a1"),
         "is not named <run_id>/<invocation_id>/<first claim id>"),
        (lambda d: d["frame"]["exclusions"]["no_output"].update(invocations=3), "not the sum of the invocation rows"),
        (lambda d: d["frame"]["population"].update(budget=3), "budget is set exactly when the population is first_b"),
    ]
    for change, message in refusals:
        with pytest.raises(ContractError, match=message):
            validate_document("precision-sample", edited(change))


# --- review ----------------------------------------------------------------------------------------------


def review_all(sample: dict, outcomes: dict[str, str], *, reviewers=(REVIEWER_A, REVIEWER_B)) -> dict:
    """Every named unit reviewed by each of *reviewers* with the same outcome, in unit-id order."""
    reviews = None
    for unit_id in sorted(outcomes):
        for reviewer in reviewers:
            reviews = precision.record_review(sample, reviews, unit_id=unit_id, reviewer=reviewer,
                                              role="independent", outcome=outcomes[unit_id], clock=CLOCK)
    return reviews


def test_the_review_queue_blinds_system_identity_and_keeps_the_mapping_in_the_sample(tmp_path):
    """Nothing a reviewer receives names a system, a run, an invocation, a claim id, or a rule id."""
    run_dir = write_run(tmp_path, "run-queue", {
        ("snap-a", "tool-alpha"): output([claim(f"alpha-claim-{index}", f"unsafe shell call number {index}",
                                                line=index, rule="vendor.alpha.rule",
                                                evidence="the command string reaches the shell")
                                          for index in range(1, 4)]),
        ("snap-a", "tool-beta"): output([claim(f"beta-claim-{index}", f"unchecked input number {index}",
                                               line=index, rule="vendor.beta.rule")
                                         for index in range(1, 4)]),
    })
    sample = precision.draw_sample(precision.build_frame([run_dir], population="full"), size=6, seed=5)

    queue = precision.review_queue(sample)

    text = json.dumps(queue)
    for secret in ("tool-alpha", "tool-beta", "run-queue", "__r1", "alpha-claim-", "beta-claim-", "vendor."):
        assert secret not in text, secret
    items = queue["items"]
    assert [item["item_id"] for item in items] == sorted(item["item_id"] for item in items)
    assert [item["item_id"] for item in items] == [f"item-000{index}" for index in range(1, 7)]
    aliases = {row["system_id"]: row["alias"] for row in sample["blinding"]["system_aliases"]}
    assert sorted(aliases.values()) == ["system-1", "system-2"]
    units = {unit["unit_id"]: unit for unit in sample["frame"]["units"]}
    for item in items:
        unit = units[precision.unit_for_item(sample, item["item_id"])]
        assert item["system"] == aliases[unit["system_id"]]
        assert item["input"] == {"input_id": "snap-a", "snapshot_id": "snap-a", "input_hash": tree_hash("snap-a")}
        assert item["claim"]["allegation"] == unit["claim"]["allegation"]
        assert "native_rule_id" not in item["claim"]
    assert queue["sample_sha256"] == canonical_sha256(sample)
    assert set(queue["outcomes"]) == set(precision.OUTCOMES)
    # The item order is a seeded permutation, not the frame order, and the same sample exports the same queue.
    assert [precision.unit_for_item(sample, item["item_id"]) for item in items] != sorted(units)
    assert precision.review_queue(deepcopy(sample)) == queue


def test_reviews_disagreement_adjudication_and_revisions_are_chained_and_resolved_by_the_rule(tmp_path):
    """Five units, all drawn (a census, so every weight is 1), reviewed step by step.

    k1: A true, B true -> true (double review). k2: A true, B false -> unresolved (disagreement), then
    the adjudicator says false -> false (adjudicated). k3: A false, B true, then B revises to false ->
    false (double review; B's first entry stays in the history). k4: A true -> true (single review).
    k5: nobody -> unresolved (nonresponse). T = 2, F = 2, U = 1: resolved precision 2/4 = 0.5, unresolved
    share 1/5 = 0.2, sensitivity [2/5, 3/5] = [0.4, 0.6], grade incomplete. Once k5 is reviewed true by
    both and B confirms k4: T = 3, F = 2, U = 0, precision 3/5 = 0.6, grade double_review_or_adjudicated.
    """
    sample = precision.draw_sample(precision.build_frame([one_system_run(tmp_path, 5)], population="full"),
                                   size=5, seed=1)
    unit = {f"k{index}": f"run-one/snap-a__sys-a__r1/k{index}" for index in range(1, 6)}
    steps = [("k1", REVIEWER_A, "independent", "true"), ("k1", REVIEWER_B, "independent", "true"),
             ("k2", REVIEWER_A, "independent", "true"), ("k2", REVIEWER_B, "independent", "false"),
             ("k2", ADJUDICATOR, "adjudicator", "false"),
             ("k3", REVIEWER_A, "independent", "false"), ("k3", REVIEWER_B, "independent", "true"),
             ("k3", REVIEWER_B, "independent", "false"),
             ("k4", REVIEWER_A, "independent", "true")]
    reviews = None
    for index, (key, reviewer, role, outcome) in enumerate(steps):
        reviews = precision.record_review(sample, reviews, unit_id=unit[key], reviewer=reviewer, role=role,
                                          outcome=outcome, note=f"step {index}", clock=CLOCK)
        if index == 3:
            midway = precision.estimate(sample, reviews)
            assert {u["unit_id"]: u["basis"] for u in midway["units"]}[unit["k2"]] == "disagreement"

    estimated = precision.estimate(sample, reviews)

    resolved = {u["unit_id"]: (u["class"], u["basis"], u["entries"]) for u in estimated["units"]}
    assert resolved == {unit["k1"]: ("true", "double_review", 2), unit["k2"]: ("false", "adjudicated", 3),
                        unit["k3"]: ("false", "double_review", 3), unit["k4"]: ("true", "single_review", 1),
                        unit["k5"]: ("unresolved", "nonresponse", 0)}
    assert estimated["totals"] == {"true": 2.0, "false": 2.0, "unresolved": 1.0, "out_of_scope": 0.0}
    assert estimated["precision_resolved"] == 0.5 and estimated["unresolved_share"] == 0.2
    assert estimated["sensitivity"] == {"lower": 0.4, "upper": 0.6}
    assert estimated["sample"]["bases"] == {"adjudicated": 1, "double_review": 2, "single_review": 1,
                                            "disagreement": 0, "nonresponse": 1}
    assert estimated["evidence_grade"] == "incomplete"
    assert any("1 sampled unit(s) have no review" in note for note in estimated["notes"])
    assert estimated["interval"]["state"] == "census" and estimated["interval"]["lower"] == 0.5

    # The history keeps every entry, revisions and overruled reviews included, as a verified chain.
    assert [(entry["unit_id"], entry["reviewer"], entry["outcome"]) for entry in reviews["reviews"]] == [
        (unit[key], reviewer, outcome) for key, reviewer, _, outcome in steps]
    assert reviews["reviews_sha256"] == reviews["reviews"][-1]["chain_sha256"]
    assert reviews["sample_sha256"] == canonical_sha256(sample)

    for key, reviewer, outcome in (("k5", REVIEWER_A, "true"), ("k5", REVIEWER_B, "true"),
                                   ("k4", REVIEWER_B, "true")):
        reviews = precision.record_review(sample, reviews, unit_id=unit[key], reviewer=reviewer,
                                          role="independent", outcome=outcome, clock=LATER)
    complete = precision.estimate(sample, reviews)
    assert complete["totals"] == {"true": 3.0, "false": 2.0, "unresolved": 0.0, "out_of_scope": 0.0}
    assert complete["precision_resolved"] == 3 / 5 and complete["unresolved_share"] == 0.0
    assert complete["evidence_grade"] == "double_review_or_adjudicated" and complete["review_entries"] == 12


def test_an_edited_reordered_or_truncated_review_history_is_refused(tmp_path):
    sample = precision.draw_sample(precision.build_frame([one_system_run(tmp_path, 2)], population="full"),
                                   size=2, seed=1)
    reviews = review_all(sample, {"run-one/snap-a__sys-a__r1/k1": "true", "run-one/snap-a__sys-a__r1/k2": "false"})
    validate_document("precision-reviews", reviews)

    edited = deepcopy(reviews)
    edited["reviews"][1]["outcome"] = "false"
    with pytest.raises(ContractError, match=r"reviews\[1\] does not chain"):
        validate_document("precision-reviews", edited)
    reordered = deepcopy(reviews)
    reordered["reviews"][0], reordered["reviews"][1] = reordered["reviews"][1], reordered["reviews"][0]
    with pytest.raises(ContractError, match="does not chain"):
        validate_document("precision-reviews", reordered)
    truncated = deepcopy(reviews)
    truncated["reviews"].pop()
    with pytest.raises(ContractError, match="deleted from the end"):
        validate_document("precision-reviews", truncated)
    wiped = {**deepcopy(reviews), "reviews": []}
    with pytest.raises(ContractError, match="deleted whole"):
        validate_document("precision-reviews", wiped)
    blank = deepcopy(reviews)
    blank["reviews"][0]["reviewer"] = "​​"
    with pytest.raises(ContractError, match="must name its reviewer"):
        validate_document("precision-reviews", blank)


def test_a_blank_reviewer_is_refused_and_the_tool_never_supplies_one(tmp_path):
    sample = precision.draw_sample(precision.build_frame([one_system_run(tmp_path, 2)], population="full"),
                                   size=2, seed=1)
    unit_id = sample["selected"][0]["unit_id"]
    assert inspect.signature(precision.record_review).parameters["reviewer"].default is inspect.Parameter.empty
    for reviewer in ("", "   ", "​​", None):
        with pytest.raises(ContractError, match="must name its reviewer; the tool never supplies one"):
            precision.record_review(sample, None, unit_id=unit_id, reviewer=reviewer, role="independent",
                                    outcome="true")
    with pytest.raises(ContractError, match="review role must be one of"):
        precision.record_review(sample, None, unit_id=unit_id, reviewer=REVIEWER_A, role="curator", outcome="true")
    with pytest.raises(ContractError, match="review outcome must be one of"):
        precision.record_review(sample, None, unit_id=unit_id, reviewer=REVIEWER_A, role="independent",
                                outcome="probably")


def test_only_a_sampled_unit_of_this_sample_can_be_reviewed(tmp_path):
    frame = precision.build_frame([one_system_run(tmp_path, 5)], population="full")
    sample = precision.draw_sample(frame, size=2, seed=4)
    drawn = {entry["unit_id"] for entry in sample["selected"]}
    undrawn = sorted(unit["unit_id"] for unit in frame["units"] if unit["unit_id"] not in drawn)[0]

    with pytest.raises(ContractError, match="is not in this sample's frame"):
        precision.record_review(sample, None, unit_id="run-x/nowhere/c1", reviewer=REVIEWER_A,
                                role="independent", outcome="true")
    with pytest.raises(ContractError, match="in the frame but was not drawn"):
        precision.record_review(sample, None, unit_id=undrawn, reviewer=REVIEWER_A, role="independent",
                                outcome="true")
    with pytest.raises(ContractError, match="this sample has no item 'item-9999'"):
        precision.unit_for_item(sample, "item-9999")

    # Reviews are bound to the one sample they judge.
    reviews = review_all(sample, {unit_id: "true" for unit_id in drawn})
    other = precision.draw_sample(frame, size=2, seed=5)
    with pytest.raises(ContractError, match="these reviews judge sample"):
        precision.estimate(other, reviews)
    with pytest.raises(ContractError, match="these reviews judge sample"):
        precision.record_review(other, reviews, unit_id=other["selected"][0]["unit_id"], reviewer=REVIEWER_A,
                                role="independent", outcome="true")


# --- the estimate --------------------------------------------------------------------------------------


def test_a_hand_computed_stratified_sample_reproduces_the_horvitz_thompson_estimate(tmp_path):
    """sys-a holds 6 units and sys-b 4; equal allocation of 4 draws 2 from each: pi = 1/3 in sys-a
    (weight 3) and 1/2 in sys-b (weight 2). Reviewed, two fictional reviewers agreeing each time:
    sys-a's two draws true and unresolved, sys-b's true and false.

    Totals: T = 3 + 2 = 5, F = 2, U = 3, O = 0 (and 3*2 + 2*2 = 10 units covered, all of them).
    Resolved precision 5/7; unresolved share 3/10; sensitivity [5/10, 8/10].
    Linearized variance, with X = T + F = 7 and z = (1[T] - (5/7) 1[T or F]) / 7:
      sys-a: z = 2/49, 0; mean 1/49; s^2 = 2/2401; 6^2 (1 - 2/6) s^2 / 2 = 24/2401.
      sys-b: z = 2/49, -5/49; mean -3/98; s^2 = 1/98; 4^2 (1 - 2/4) s^2 / 2 = 98/2401.
      V = 122/2401 = 0.050812..., SE = sqrt(122)/49 = 0.225416..., 95% interval
      [5/7 - 1.959964 * 0.225416, 1] = [0.272479..., 1.0] after clipping at 1.
    Per stratum: sys-a T 3, U 3, precision 1, unresolved share 1/2; sys-b T 2, F 2, precision 1/2.
    """
    frame = precision.build_frame([two_strata_run(tmp_path)], population="full")
    sample = precision.draw_sample(frame, size=4, seed=29, stratify_by="system", allocation="equal")
    drawn = selected_by_stratum(sample)
    reviews = review_all(sample, {drawn["sys-a"][0]: "true", drawn["sys-a"][1]: "unresolved",
                                  drawn["sys-b"][0]: "true", drawn["sys-b"][1]: "false"})

    estimated = precision.estimate(sample, reviews)

    assert [(row["stratum"], row["population_units"], row["sampled_units"], row["inclusion_probability"])
            for row in sample["strata"]] == [("sys-a", 6, 2, 1 / 3), ("sys-b", 4, 2, 1 / 2)]
    assert estimated["totals"] == {"true": 5.0, "false": 2.0, "unresolved": 3.0, "out_of_scope": 0.0}
    assert estimated["precision_resolved"] == 5 / 7
    assert estimated["unresolved_share"] == 3 / 10
    assert estimated["sensitivity"] == {"lower": 5 / 10, "upper": 8 / 10}
    assert estimated["coverage"] == {"population_units": 10, "covered_units": 10, "share": 1.0,
                                     "uncovered_strata": []}
    interval = estimated["interval"]
    standard_error = math.sqrt(122 / 2401)
    assert interval == {"state": "ok", "method": "stratified_linearized_normal", "confidence": 0.95, "z": Z95,
                        "variance": 122 / 2401, "standard_error": standard_error,
                        "lower": 5 / 7 - Z95 * standard_error, "upper": 1.0, "insufficient_strata": []}
    assert round(interval["lower"], 6) == 0.272479 and round(standard_error, 6) == 0.225416
    by_stratum = {row["stratum"]: row for row in estimated["strata"]}
    assert by_stratum["sys-a"]["totals"] == {"true": 3.0, "false": 0.0, "unresolved": 3.0, "out_of_scope": 0.0}
    assert (by_stratum["sys-a"]["precision_resolved"], by_stratum["sys-a"]["unresolved_share"]) == (1.0, 0.5)
    assert by_stratum["sys-b"]["totals"] == {"true": 2.0, "false": 2.0, "unresolved": 0.0, "out_of_scope": 0.0}
    assert by_stratum["sys-b"]["precision_resolved"] == 0.5
    assert estimated["evidence_grade"] == "double_review_or_adjudicated"
    assert estimated["sample"]["classes"] == {"true": 2, "false": 1, "unresolved": 1, "out_of_scope": 0}
    assert canonical_json(precision.estimate(deepcopy(sample), deepcopy(reviews))) == canonical_json(estimated)


def test_a_sample_that_leaves_a_stratum_uncovered_is_never_reported_as_a_census(tmp_path):
    """Input strata of 1, 1, and 5 units; equal allocation of 2 takes the singletons whole and draws nothing from
    the third.

    Both drawn units are reviewed true, so resolved precision is 1 and the strata the sample covers have no
    sampling variance. But it covers 2 of 7 units, and nothing was observed of the other 5: calling it a census
    would report a zero-width interval [1, 1] over units nobody looked at. It is a zero variance from a sample
    that is not a census, so it is degenerate and carries no bounds, and coverage says how little it covers. The
    same population drawn whole (size 7) is a census, with bounds [1, 1].
    """
    run_dir = write_run(tmp_path, "run-census", {("in-a", "sys-a"): output(distinct("a", 1)),
                                                 ("in-b", "sys-a"): output(distinct("b", 1)),
                                                 ("in-c", "sys-a"): output(distinct("c", 5))})
    frame = precision.build_frame([run_dir], population="full")
    partial = precision.draw_sample(frame, size=2, seed=0, stratify_by="input", allocation="equal")
    assert partial["uncovered_strata"] == ["in-c"]

    estimated = precision.estimate(partial, review_all(partial, {entry["unit_id"]: "true"
                                                                 for entry in partial["selected"]}))

    assert estimated["precision_resolved"] == 1.0
    assert estimated["coverage"] == {"population_units": 7, "covered_units": 2, "share": 2 / 7,
                                     "uncovered_strata": [{"stratum": "in-c", "population_units": 5}]}
    interval = estimated["interval"]
    assert interval["state"] == "degenerate" and interval["lower"] is None and interval["upper"] is None
    assert interval["variance"] == 0.0 and interval["standard_error"] == 0.0

    whole = precision.draw_sample(frame, size=7, seed=0, stratify_by="input", allocation="equal")
    census = precision.estimate(whole, review_all(whole, {entry["unit_id"]: "true" for entry in whole["selected"]}))
    assert whole["uncovered_strata"] == []
    assert census["interval"]["state"] == "census"
    assert (census["interval"]["lower"], census["interval"]["upper"]) == (1.0, 1.0)


def test_an_oversampled_stratum_is_weighted_back_while_the_unweighted_share_is_biased(tmp_path):
    """sys-a delivered 18 claims, all real; sys-b delivered 2, both false. The population's precision
    is 18/20 = 0.9. Equal allocation of 4 oversamples sys-b: 2 of 18 from sys-a (weight 9) and both
    of sys-b (weight 1). The reviewed sample is 2 true and 2 false, so its unweighted share is 0.5,
    off by 0.4; the weighted totals T = 2*9 = 18 and F = 2*1 = 2 give back 18/20 = 0.9 exactly.

    Every sampled sys-a unit scores the same z, and sys-b is taken whole, so the variance is 0
    without being a census: the interval is degenerate and has no bounds, rather than claiming
    certainty from four reviews.
    """
    frame = precision.build_frame([two_strata_run(tmp_path, sizes=(18, 2))], population="full")
    truth = {unit["unit_id"]: ("true" if unit["system_id"] == "sys-a" else "false") for unit in frame["units"]}
    population_precision = sum(value == "true" for value in truth.values()) / len(truth)
    sample = precision.draw_sample(frame, size=4, seed=3, stratify_by="system", allocation="equal")
    reviews = review_all(sample, {entry["unit_id"]: truth[entry["unit_id"]] for entry in sample["selected"]})

    estimated = precision.estimate(sample, reviews)

    classes = estimated["sample"]["classes"]
    unweighted = classes["true"] / (classes["true"] + classes["false"])
    assert population_precision == 0.9
    assert unweighted == 0.5 and abs(unweighted - population_precision) == pytest.approx(0.4)
    assert estimated["totals"]["true"] == 18.0 and estimated["totals"]["false"] == 2.0
    assert estimated["precision_resolved"] == population_precision
    assert [(row["stratum"], row["inclusion_probability"]) for row in sample["strata"]] == [
        ("sys-a", 2 / 18), ("sys-b", 1.0)]
    assert estimated["interval"]["state"] == "degenerate"
    assert estimated["interval"]["lower"] is None and estimated["interval"]["upper"] is None


def test_an_unsampled_stratum_is_never_represented_and_coverage_says_so(tmp_path):
    """sys-a holds 9 units and sys-b 1. Proportional allocation of 5: shares 4.5 and 0.5 tie on their
    fractions, the first name takes the unit, and sys-b draws nothing. All five sys-a draws reviewed
    true: T = 5 * 9/5 = 9 and the estimate covers 9 of 10 units (0.9); sys-b gets no totals at all,
    not zeros, and a review of its unit is refused because it was never drawn."""
    frame = precision.build_frame([two_strata_run(tmp_path, sizes=(9, 1))], population="full")
    sample = precision.draw_sample(frame, size=5, seed=8, stratify_by="system")
    reviews = review_all(sample, {entry["unit_id"]: "true" for entry in sample["selected"]})

    estimated = precision.estimate(sample, reviews)

    assert sample["uncovered_strata"] == ["sys-b"]
    assert estimated["coverage"] == {"population_units": 10, "covered_units": 9, "share": 0.9,
                                     "uncovered_strata": [{"stratum": "sys-b", "population_units": 1}]}
    assert estimated["totals"] == {"true": 9.0, "false": 0.0, "unresolved": 0.0, "out_of_scope": 0.0}
    sys_b = {row["stratum"]: row for row in estimated["strata"]}["sys-b"]
    assert sys_b == {"stratum": "sys-b", "population_units": 1, "sampled_units": 0, "inclusion_probability": 0.0,
                     "covered": False, "classes": {"true": 0, "false": 0, "unresolved": 0, "out_of_scope": 0},
                     "totals": None, "precision_resolved": None, "unresolved_share": None,
                     "sensitivity": {"lower": None, "upper": None}}
    assert any("covers 9 of 10 units" in note for note in estimated["notes"])
    with pytest.raises(ContractError, match="in the frame but was not drawn"):
        precision.record_review(sample, reviews, unit_id="run-strata/snap-a__sys-b__r1/b1",
                                reviewer=REVIEWER_A, role="independent", outcome="false")


def test_duplicate_delivery_burden_is_reported_apart_from_precision(tmp_path):
    """snap-a: A three times, then B; snap-b: C. Full population: 3 units in 5 copies, burden 5/3.
    Census review: A true, B false, C true -> resolved precision 2/3, however many times A was sent
    (counting copies would say 4/5). first_b with B = 2: A (2 copies inside) and C, 3 copies over 2
    units, burden 1.5; B and A's third copy lie past B (1 unit, 2 copies)."""
    run_dir = write_run(tmp_path, "run-dup", {
        ("snap-a", "sys-a"): output([claim("a1", "A"), claim("a2", "A"), claim("a3", "A"), claim("b1", "B")]),
        ("snap-b", "sys-a"): output([claim("c1", "C")]),
    })
    sample = precision.draw_sample(precision.build_frame([run_dir], population="full"), size=3, seed=2)
    reviews = review_all(sample, {"run-dup/snap-a__sys-a__r1/a1": "true", "run-dup/snap-a__sys-a__r1/b1": "false",
                                  "run-dup/snap-b__sys-a__r1/c1": "true"})

    estimated = precision.estimate(sample, reviews)

    assert estimated["duplicate_burden"] == {"copies": 5, "units": 3, "duplicate_copies": 2,
                                             "copies_per_unit": 5 / 3}
    assert estimated["precision_resolved"] == 2 / 3
    first_b = precision.build_frame([run_dir], population="first_b", budget=2)
    bounded = precision.estimate(precision.draw_sample(first_b, size=2, seed=2))
    assert bounded["duplicate_burden"] == {"copies": 3, "units": 2, "duplicate_copies": 1, "copies_per_unit": 1.5}
    assert first_b["exclusions"]["beyond_budget"] == {"units": 1, "copies": 2}


def test_without_reviews_every_sampled_unit_stays_visible_as_nonresponse(tmp_path):
    """No reviews file: all 3 units are unresolved (nonresponse), U = 3 of 3, precision undefined."""
    sample = precision.draw_sample(precision.build_frame([one_system_run(tmp_path, 3)], population="full"),
                                   size=3, seed=0)

    estimated = precision.estimate(sample)

    assert [unit["basis"] for unit in estimated["units"]] == ["nonresponse"] * 3
    assert estimated["totals"] == {"true": 0.0, "false": 0.0, "unresolved": 3.0, "out_of_scope": 0.0}
    assert estimated["precision_resolved"] is None and estimated["unresolved_share"] == 1.0
    assert estimated["sensitivity"] == {"lower": 0.0, "upper": 1.0}
    assert estimated["interval"]["state"] == "unavailable" and estimated["interval"]["variance"] is None
    assert estimated["evidence_grade"] == "incomplete"
    assert estimated["reviews_sha256"] is None and estimated["review_entries"] == 0


def test_out_of_scope_is_reported_apart_and_a_single_draw_stratum_leaves_the_interval_insufficient(tmp_path):
    """sys-a 6 units, sys-b 4; proportional allocation of 3 draws 2 (shares 1.8 and 1.2) and 1. With
    sys-a's draws true and out of scope and sys-b's single draw false: T = 3, F = 4, O = 3, so
    precision 3/7 leaves the out-of-scope mass out; sys-b drew one unit of four, so its variance, and
    the interval, cannot be estimated."""
    sample = precision.draw_sample(precision.build_frame([two_strata_run(tmp_path)], population="full"),
                                   size=3, seed=12, stratify_by="system")
    drawn = selected_by_stratum(sample)
    reviews = review_all(sample, {drawn["sys-a"][0]: "true", drawn["sys-a"][1]: "out_of_scope",
                                  drawn["sys-b"][0]: "false"})

    estimated = precision.estimate(sample, reviews)

    assert estimated["totals"] == {"true": 3.0, "false": 4.0, "unresolved": 0.0, "out_of_scope": 3.0}
    assert estimated["precision_resolved"] == 3 / 7 and estimated["unresolved_share"] == 0.0
    assert estimated["interval"]["state"] == "insufficient"
    assert estimated["interval"]["insufficient_strata"] == ["sys-b"]
    assert estimated["interval"]["lower"] is None


def test_the_confidence_is_refused_outside_zero_and_one(tmp_path):
    sample = precision.draw_sample(precision.build_frame([one_system_run(tmp_path, 3)], population="full"),
                                   size=3, seed=0)
    for confidence in (0, 1, 1.5, True, "0.9"):
        with pytest.raises(ContractError, match="confidence must be a number strictly between 0 and 1"):
            precision.estimate(sample, confidence=confidence)
    assert precision.estimate(sample, confidence=0.9)["interval"]["z"] == NormalDist().inv_cdf(0.95)


def test_an_estimate_says_what_its_population_left_out_and_binds_what_it_read(tmp_path):
    """The first_b exclusions of the frame travel into the estimate, beside the digests it rests on."""
    run_dir = write_run(tmp_path, "run-left", {
        ("snap-a", "sys-a"): output(distinct("n", 3)),
        ("snap-a", "sys-b"): output(distinct("u", 2), ranking="unranked"),
    })
    frame = precision.build_frame([run_dir], population="first_b", budget=2)
    sample = precision.draw_sample(frame, size=2, seed=6)
    reviews = review_all(sample, {entry["unit_id"]: "true" for entry in sample["selected"]})

    estimated = precision.estimate(sample, reviews)

    assert estimated["exclusions"] == frame["exclusions"]
    assert estimated["exclusions"]["unranked"] == {"invocations": 1, "claim_records": 2, "units": 2}
    assert estimated["exclusions"]["beyond_budget"] == {"units": 1, "copies": 1}
    assert estimated["population"] == {"name": "first_b", "budget": 2, "mode": "full", "profile": "standard",
                                       "systems": ["sys-a", "sys-b"]}
    assert (estimated["sample_sha256"], estimated["frame_sha256"], estimated["reviews_sha256"]) == (
        canonical_sha256(sample), canonical_sha256(frame), canonical_sha256(reviews))
    assert estimated["runs"] == frame["runs"] and estimated["design"] == sample["design"]


def test_the_review_and_estimate_kinds_are_published_at_2_1_and_check_their_own_shape(tmp_path, capsys):
    sample = precision.draw_sample(precision.build_frame([two_strata_run(tmp_path)], population="full"),
                                   size=4, seed=1, stratify_by="system")
    reviews = review_all(sample, {entry["unit_id"]: "true" for entry in sample["selected"]})
    estimated = precision.estimate(sample, reviews)

    for kind, document in (("precision-reviews", reviews), ("precision-estimate", estimated)):
        assert SCHEMA_VERSIONS[kind] == ("2.1",)
        assert validate_document(kind, document) is document
        path = tmp_path / f"{kind}.json"
        path.write_text(canonical_json(document) + "\n", encoding="utf-8")
        code, out, _ = cli(capsys, "validate", kind, str(path))
        assert code == 0 and f"Valid {kind}" in out
        with pytest.raises(ContractError, match="schema_version"):
            validate_document(kind, {**document, "schema_version": "2.0"})

    for change, message in (
            (lambda d: d.update(sensitivity={"lower": 0.9, "upper": 0.1}), "both present and ordered"),
            (lambda d: d["interval"].update(state="ok", lower=None, upper=None),
             "bounds are recorded exactly in the ok and census states, and this one is ok"),
            (lambda d: d["interval"].update(state="insufficient", lower=None, upper=None),
             "insufficient_strata is named exactly when"),
            (lambda d: d["coverage"].update(covered_units=11), "covered_units cannot exceed"),
            (lambda d: d["units"].pop(), "selected_units must equal the number of units resolved")):
        document = deepcopy(estimated)
        change(document)
        with pytest.raises(ContractError, match=message):
            validate_document("precision-estimate", document)


# --- the command line, end to end ------------------------------------------------------------------------------


def test_the_cli_writes_the_sample_it_draws_byte_for_byte(tmp_path, capsys):
    """Two invocations with one seed write identical bytes: the canonical sample plus a newline."""
    run_dir = two_strata_run(tmp_path)
    for name in ("one.json", "two.json"):
        code, out, _ = cli(capsys, "precision", "sample", str(run_dir), "--population", "full", "--size", "4",
                           "--seed", "20260929", "--stratify-by", "system", "--output", str(tmp_path / name))
        assert code == 0
    assert "Design: stratified_srswor by system, proportional allocation, size 4, seed 20260929" in out
    assert "Stratum sys-a: 2 of 6 unit(s), inclusion probability 0.3333" in out
    drawn = precision.draw_sample(precision.build_frame([run_dir], population="full"), size=4, seed=20260929,
                                  stratify_by="system")
    assert (tmp_path / "one.json").read_bytes() == (tmp_path / "two.json").read_bytes()
    assert (tmp_path / "one.json").read_text(encoding="utf-8") == canonical_json(drawn) + "\n"


def test_the_cli_names_uncovered_strata_on_stderr(tmp_path, capsys):
    """sys-a 9 units, sys-b 1: proportional allocation of 5 leaves sys-b with nothing, and says so."""
    run_dir = two_strata_run(tmp_path, sizes=(9, 1))
    code, out, err = cli(capsys, "precision", "sample", str(run_dir), "--population", "full", "--size", "5",
                         "--seed", "8", "--stratify-by", "system", "--output", str(tmp_path / "sample.json"))
    assert code == 0 and "Stratum sys-b: 0 of 1 unit(s)" in out
    assert "scaneval: warning: 1 stratum/strata drew no unit (sys-b)" in err
    code, _, err = cli(capsys, "precision", "estimate", str(tmp_path / "sample.json"),
                       "--output", str(tmp_path / "estimate.json"))
    assert code == 0 and "the sample covers 9 of 10 units" in err


def test_the_cli_refuses_a_blank_reviewer_and_writes_nothing(tmp_path, capsys):
    run_dir = one_system_run(tmp_path, 2)
    sample_path, reviews_path = tmp_path / "sample.json", tmp_path / "reviews.json"
    assert cli(capsys, "precision", "sample", str(run_dir), "--population", "full", "--size", "2", "--seed", "1",
               "--output", str(sample_path))[0] == 0
    with pytest.raises(SystemExit):
        main(["precision", "record", str(reviews_path), "--sample", str(sample_path), "--item", "item-0001",
              "--role", "independent", "--outcome", "true"])
    code, _, err = cli(capsys, "precision", "record", str(reviews_path), "--sample", str(sample_path),
                       "--item", "item-0001", "--reviewer", " ", "--role", "independent", "--outcome", "true")
    assert code == 2 and "scaneval: a precision review must name its reviewer" in err
    code, _, err = cli(capsys, "precision", "record", str(reviews_path), "--sample", str(sample_path),
                       "--item", "item-0042", "--reviewer", REVIEWER_A, "--role", "independent", "--outcome", "true")
    assert code == 2 and "this sample has no item 'item-0042'" in err
    assert not reviews_path.exists()
    code, out, _ = cli(capsys, "precision", "record", str(reviews_path), "--sample", str(sample_path),
                       "--unit", "run-one/snap-a__sys-a__r1/k1", "--reviewer", REVIEWER_A, "--role", "adjudicator",
                       "--outcome", "out_of_scope")
    assert code == 0 and "Recorded an adjudicator review of unit run-one/snap-a__sys-a__r1/k1: out_of_scope" in out
    assert load_document(reviews_path, "precision-reviews")["reviews"][0]["reviewer"] == REVIEWER_A


VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
              "assumption, and adds a single-file Python sink for the precision tests.")


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


class ScriptedAdapter(Adapter):
    """Returns a fixed native-ordered claim list per system. Never touches the network."""

    name = "fake"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})
    CLAIMS = {
        "fake-a": [("c1", "shell=True with a caller-controlled command", "src/app.py", 5),
                   ("c2", "shell=True with a caller-controlled command", "src/app.py", 5),
                   ("c3", "the README documents a default password", "README.md", 1)],
        "fake-b": [("c1", "shell=True with a caller-controlled command", "src/app.py", 5),
                   ("c2", "subprocess output is logged unescaped", "src/app.py", 5)],
    }

    def prepare(self, spec, cache_root):
        return {"system": spec.system_id}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        claims = [{"claim_id": claim_id, "allegation": allegation, "kind": "command_injection", "rank": rank,
                   "primary_location": {"path": path, "start_line": line, "end_line": line}}
                  for rank, (claim_id, allegation, path, line) in enumerate(self.CLAIMS[spec.system_id], start=1)]
        return NativeOutcome(status="success", exit_code=0, command=["fake", "scan"], claims=claims,
                             ranking="native", tool_versions={"fake": "1.0.0"},
                             capture={"model_requests": "not_applicable"})


@pytest.fixture
def scripted_run(tmp_path: Path) -> Path:
    """A real run directory: one input, two scripted systems, draft decisions from the runner."""
    repo = tmp_path / "upstream"
    (repo / "src").mkdir(parents=True)
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "src" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    commit = git("rev-parse", "HEAD", cwd=repo)
    pack = cases.new_pack("test", "precision-pilot", "Local fixture pack for the precision tests.")
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
    config = {"schema_version": "2.0", "run_id": "run-precision", "pack": "pack.json", "cache_root": "cache",
              "inputs": [{"snapshot_id": "snap-a"}],
              "systems": [{"system_id": "fake-a", "adapter": "fake", "config": {}},
                          {"system_id": "fake-b", "adapter": "fake", "config": {}}],
              "repetitions": 1, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none"}
    (tmp_path / "run-config.json").write_text(canonical_json(config) + "\n", encoding="utf-8")
    workspace = tmp_path / "work"
    workspace.mkdir()
    run_dir = tmp_path / "out"
    run_from_config(tmp_path / "run-config.json", run_dir, clock=CLOCK, workspace_root=workspace,
                    adapters={"fake": ScriptedAdapter()})
    return run_dir


def run_state(run_dir: Path) -> tuple[dict, dict]:
    """Every file's digest under *run_dir*, and each bundle's observe, score, and review status."""
    files = {path.relative_to(run_dir).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in sorted(run_dir.rglob("*")) if path.is_file()}
    bundles = {}
    for bundle in sorted((run_dir / "invocations").iterdir()):
        plan, decisions, _record = review.load_evaluator(bundle.resolve(), guard_symlinks=False)
        result = load_document(bundle / "result.json", "scan-result")
        bundles[bundle.name] = {"observe": scoring.observe(plan, result, decisions),
                                "score": scoring.score(plan, result, decisions),
                                "review": review.review_status(bundle.resolve(), guard_symlinks=False)}
    return files, bundles


def test_sampling_and_review_never_change_decisions_scores_or_detection_credit(tmp_path, scripted_run, capsys):
    """The whole workflow through the CLI against a real run: sample, queue, record, estimate.

    The run's files are byte-identical afterwards, and so is what observe() and score() say about
    every bundle, detection credit and review state included: a claim reviewed true for precision is
    not a target hit. fake-a delivered c1, a duplicate c2, and c3; fake-b c1 and c2: 4 units in all.
    """
    before = run_state(scripted_run)
    work = tmp_path / "precision"
    work.mkdir()
    sample_path, queue_path = work / "sample.json", work / "queue.json"
    reviews_path, estimate_path = work / "reviews.json", work / "estimate.json"

    code, out, _ = cli(capsys, "precision", "sample", str(scripted_run), "--population", "first_b", "--budget", "2",
                       "--size", "3", "--seed", "42", "--stratify-by", "system", "--allocation", "equal",
                       "--output", str(sample_path))
    assert code == 0
    assert "Frame: first_b (B=2) over 1 run(s), systems fake-a, fake-b: 3 unit(s), 4 copies inside it" in out
    assert "Left out: 0 unranked invocation(s) (0 unit(s)), 0 bundle-unresolved invocation(s) (0 unit(s)), " \
           "1 unit(s) past B" in out
    code, out, _ = cli(capsys, "precision", "queue", str(sample_path), "--output", str(queue_path))
    assert code == 0 and "Wrote 3 blinded review item(s)" in out
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    assert queue == precision.review_queue(load_document(sample_path, "precision-sample"))
    assert "fake-a" not in queue_path.read_text(encoding="utf-8")
    items = [item["item_id"] for item in queue["items"]]
    assert len(items) == 3
    for item in items:
        for reviewer in (REVIEWER_A, REVIEWER_B):
            code, out, _ = cli(capsys, "precision", "record", str(reviews_path), "--sample", str(sample_path),
                               "--item", item, "--reviewer", reviewer, "--role", "independent",
                               "--outcome", "true", "--note", "fixture review")
            assert code == 0 and f"Recorded an independent review of {item}: true" in out
    code, out, err = cli(capsys, "precision", "estimate", str(sample_path), "--reviews", str(reviews_path),
                         "--output", str(estimate_path))
    assert code == 0 and err == ""
    assert "Resolved precision 1; unresolved share 0" in out and "Evidence grade: double_review_or_adjudicated" in out
    estimated = load_document(estimate_path, "precision-estimate")
    assert estimated["review_entries"] == 6 and estimated["totals"]["true"] == 3.0
    assert estimated["runs"][0]["manifest_sha256"] == canonical_sha256(
        load_document(scripted_run / "run-manifest.json", "run-manifest"))

    after = run_state(scripted_run)
    assert after[0] == before[0], "a precision command wrote into the run directory"
    assert after[1] == before[1], "observe, score, or review status changed"
    assert {name: state["score"]["metrics"]["targets_detected"] for name, state in after[1].items()} == {
        "snap-a__fake-a__r1": 0, "snap-a__fake-b__r1": 0}


def test_precision_commands_are_create_only_and_refuse_trial_and_run_directories(tmp_path, scripted_run, capsys):
    """No precision document lands in a trial or anywhere in a run it reads, so the run stays as recorded."""
    before = run_state(scripted_run)[0]
    sample_path = tmp_path / "sample.json"
    code, _, _ = cli(capsys, "precision", "sample", str(scripted_run), "--population", "full", "--size", "2",
                     "--seed", "1", "--output", str(sample_path))
    assert code == 0
    code, _, err = cli(capsys, "precision", "sample", str(scripted_run), "--population", "full", "--size", "2",
                       "--seed", "1", "--output", str(sample_path))
    assert code == 2 and "scaneval:" in err
    trial = scripted_run / "inputs" / "snap-a"
    assert (trial / "provenance.json").is_file()
    for argv in (["precision", "sample", str(scripted_run), "--population", "full", "--size", "2", "--seed", "1",
                  "--output", str(trial / "sample.json")],
                 ["precision", "queue", str(sample_path), "--output", str(trial / "queue.json")],
                 ["precision", "record", str(trial / "reviews.json"), "--sample", str(sample_path),
                  "--item", "item-0001", "--reviewer", REVIEWER_A, "--role", "independent", "--outcome", "true"],
                 ["precision", "estimate", str(sample_path), "--output", str(trial / "estimate.json")]):
        code, _, err = cli(capsys, *argv)
        assert code == 2 and "trial directory" in err, argv
    for place in (scripted_run, scripted_run / "evaluator", scripted_run / "invocations" / "snap-a__fake-a__r1"):
        for argv in (["precision", "sample", str(scripted_run), "--population", "full", "--size", "2",
                      "--seed", "1", "--output", str(place / "sample.json")],
                     ["precision", "queue", str(sample_path), "--output", str(place / "queue.json")],
                     ["precision", "record", str(place / "reviews.json"), "--sample", str(sample_path),
                      "--item", "item-0001", "--reviewer", REVIEWER_A, "--role", "independent", "--outcome", "true"],
                     ["precision", "estimate", str(sample_path), "--output", str(place / "estimate.json")]):
            code, _, err = cli(capsys, *argv)
            assert code == 2 and f"inside the run directory {scripted_run}" in err, argv
    assert run_state(scripted_run)[0] == before
    code, _, err = cli(capsys, "precision", "sample", str(scripted_run), "--population", "first_b", "--size", "2",
                       "--seed", "1", "--output", str(tmp_path / "other.json"))
    assert code == 2 and "first_b population needs a budget" in err
    code, _, err = cli(capsys, "precision", "estimate", str(sample_path), "--output", str(tmp_path / "e.json"))
    assert code == 0 and "the review is incomplete: 2 unit(s) unreviewed" in err
    with pytest.raises(SystemExit):
        main(["precision", "record", str(tmp_path / "r.json"), "--sample", str(sample_path), "--item", "item-0001",
              "--unit", "x", "--reviewer", REVIEWER_A, "--role", "independent", "--outcome", "true"])
