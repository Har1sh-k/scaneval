"""Precision sampling: the frame a population is listed in and the seeded draw from it.

Every run directory here is built in ``tmp_path`` from fixture documents: a frozen schedule, a 2.1
manifest, and a saved result per invocation that ran, which is everything a precision frame reads.
No network, no model calls, and no clock reaches a derived document.

The hand-computed figures are in each test's docstring; the assertions compare against the same
fractions, so a figure that is exact on paper is checked exactly.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from scaneval import precision, scoring
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


CREATED_AT = "2026-09-20T15:00:00+00:00"
CONFIG_HASH = "sha256:" + "c" * 64
PACK_HASH = "sha256:" + "e" * 64
MAP_IDENTITY = {"map_id": "widget-metadata", "map_version": "1", "map_sha256": "sha256:" + "d" * 64}


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
