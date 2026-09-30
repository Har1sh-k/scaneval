"""Reproducible precision sampling of delivered claims: the frame and the seeded draw.

Recall is asked of labeled targets; precision is asked of what a system delivered, and no label set
answers it, because nobody labels every line of a repository. It is answered the way
``docs/EVALUATION_MATH.md`` section 3 states: declare a population of claims, have people review a
probability sample of it, and weight each reviewed claim by the inverse of the probability it had
of being drawn (Horvitz and Thompson). This module builds the population and draws the sample:

- :func:`build_frame` lists the population from saved run directories. A unit is one exact-duplicate
  group of claims within one invocation, by :func:`scaneval.scoring.claim_fingerprint`, the identity
  scoring uses, so a claim delivered three times is judged once and its copies are counted apart as
  duplicate delivery burden. The ``first_b`` population holds the units with a copy at native rank
  at most B; an invocation without native order, or with unresolved bundles, has no measured
  position, so it is left out and counted. The ``full`` population holds every delivered unit.
- :func:`draw_sample` draws a simple or stratified random sample without replacement, one seeded
  :class:`scaneval.resampling.Stream` per stratum, and records every inclusion probability. A
  stratum that draws no unit is listed as uncovered.
- :func:`verify_sample` holds a sample to what its own frame, design, and seed draw.

What this never does. It calls no model and no judge. It never writes into a run directory, and it
reads no decision, plan, or review record, so sampling changes no decision, score, or detection
credit. Nothing here reads a clock or an unseeded random source: every draw comes from the seed the
caller states and units are handled in sorted order, so identical inputs give byte-identical
samples.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from fractions import Fraction
import math
from os import PathLike
from pathlib import Path
from typing import Iterable, Sequence

from .contracts import (
    ContractError,
    canonical_json,
    canonical_sha256,
    load_document,
    precision_exclusions,
    precision_stratum,
    validate_document,
)
from .resampling import ALGORITHM, Stream, sample_without_replacement
from .review import RESULT_FILE, RESULT_KIND
from .runner import MANIFEST_KIND, MANIFEST_NAME
from .schedule import SCHEDULE_KIND
from .scoring import claim_fingerprint


SAMPLE_KIND = "precision-sample"
SCHEMA_VERSION = "2.1"

POPULATIONS = ("first_b", "full")
MODES = ("full", "pr")
PROFILES = ("standard", "metadata_blinded")
STRATIFICATIONS = ("system", "input", "kind")
ALLOCATIONS = ("proportional", "equal")
# The label of the stream a stratum draws from. An unstratified sample has one stratum, "all".
STREAM_LABEL = "precision/{frame_sha256}/{stratum}"
# Blinding draws come from streams of their own, so they can never share one with a stratum.
ITEM_LABEL = "precision-blinding/{frame_sha256}/items"
ALIAS_LABEL = "precision-blinding/{frame_sha256}/systems"
# What a unit keeps of its first copy: exactly the fields its duplicate identity is computed from.
CLAIM_FIELDS = ("allegation", "kind", "native_rule_id", "primary_location", "related_locations",
                "evidence_text")


def _count(value: object, label: str, *, minimum: int) -> int:
    """*value* as an integer of at least *minimum*, refused rather than coerced."""
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer of at least {minimum}, not {value!r}")
    return value


# --- the frame ------------------------------------------------------------------------------------


def _load_run(run_dir: Path) -> tuple[Path, dict, dict]:
    """The manifest and frozen schedule of one run directory, refused unless they agree.

    A 2.0 manifest names no schedule, so it cannot say which assignments its claims answer; it is
    refused rather than read as a run that assigned whatever happens to be on disk.
    """
    manifest = load_document(run_dir / MANIFEST_NAME, MANIFEST_KIND)
    if manifest["schema_version"] == "2.0":
        raise ContractError(
            f"{run_dir} holds a 2.0 run manifest: that run predates frozen schedules, so no precision "
            "frame can say which assignments its claims came from")
    schedule = load_document(run_dir / manifest["schedule_path"], SCHEDULE_KIND)
    if schedule["run_id"] != manifest["run_id"]:
        raise ContractError(f"{run_dir}: the manifest is for run {manifest['run_id']}, but its schedule "
                            f"is for run {schedule['run_id']}")
    assigned = {row["assignment_id"] for row in schedule["assignments"]}
    unassigned = sorted({row["invocation_id"] for row in manifest["invocations"]} - assigned)
    if unassigned:
        raise ContractError(f"{run_dir}: the manifest records invocations its schedule never assigned: "
                            f"{', '.join(unassigned[:3])}")
    return run_dir, manifest, schedule


def _load_result(run_dir: Path, row: dict, run_id: str) -> dict:
    """The saved result of one manifest row, refused unless it is the result that row names.

    The bundle must resolve inside the run directory, and the result must name the run and the
    system the manifest row names. That compares documents; it says nothing about the scan.
    """
    bundle = (run_dir / row["bundle_path"]).resolve()
    if not bundle.is_relative_to(run_dir.resolve()):
        raise ContractError(f"{run_dir}: invocation {row['invocation_id']} names a bundle outside the run "
                            f"directory ({row['bundle_path']})")
    path = bundle / RESULT_FILE
    result = load_document(path, RESULT_KIND)
    if (result["run_id"], result["system_id"]) != (run_id, row["system_id"]):
        raise ContractError(f"{path} is a result of run {result['run_id']} and system {result['system_id']}, "
                            f"not of run {run_id} and system {row['system_id']} as the manifest says")
    return result


def _groups(claims: list[dict]) -> dict[str, list[dict]]:
    """Claims grouped by exact-duplicate identity, each group and its copies in delivery order."""
    groups: dict[str, list[dict]] = {}
    for claim in claims:
        groups.setdefault(claim_fingerprint(claim), []).append(claim)
    return groups


def _unit(record: dict, fingerprint: str, copies: list[dict], ranked: bool, inside: int) -> dict:
    first = copies[0]
    return {
        "unit_id": f"{record['run_id']}/{record['invocation_id']}/{first['claim_id']}",
        "run_id": record["run_id"], "invocation_id": record["invocation_id"],
        "system_id": record["system_id"], "input_id": record["input_id"],
        "fingerprint": fingerprint,
        "claim_ids": [copy["claim_id"] for copy in copies],
        "delivered_copies": len(copies),
        "population_copies": inside,
        # Native ranks follow delivery order, so the first copy holds the best rank.
        "first_rank": first["rank"] if ranked else None,
        "claim": {field: deepcopy(first[field]) for field in CLAIM_FIELDS if field in first},
    }


def _run_frame(run_dir: Path, manifest: dict, schedule: dict, systems: set[str], mode: str,
               profile: str, population: str, budget: int | None) -> tuple[list[dict], list[dict]]:
    """The invocation rows and population units one run contributes to a frame.

    Every assignment of a chosen system to an input of the view is a row, including one that
    delivered nothing, so the frame says which assignments it considered. The rows follow the
    schedule, not a directory listing.
    """
    run_id = manifest["run_id"]
    inputs = {row["input_id"]: row for row in schedule["inputs"]}
    prepared = {row["input_id"]: row for row in manifest["inputs"]}
    recorded = {row["invocation_id"]: row for row in manifest["invocations"]}
    rows: list[dict] = []
    units: list[dict] = []
    for assignment in sorted(schedule["assignments"], key=lambda item: item["assignment_id"]):
        scheduled = inputs[assignment["input_id"]]
        if assignment["system_id"] not in systems or (scheduled["mode"], scheduled["profile"]) != (mode, profile):
            continue
        record = {"run_id": run_id, "invocation_id": assignment["assignment_id"],
                  "input_id": assignment["input_id"], "system_id": assignment["system_id"],
                  "snapshot_id": scheduled["snapshot_id"], "repetition": assignment["repetition"]}
        row = recorded.get(assignment["assignment_id"])
        if row is not None and (row["input_id"], row["system_id"], row["repetition"]) != (
                assignment["input_id"], assignment["system_id"], assignment["repetition"]):
            raise ContractError(f"{run_dir}: manifest row {row['invocation_id']} does not describe the "
                                "assignment its schedule gives that id")
        if row is None or row["bundle_path"] is None:
            rows.append({**record, "status": "not_recorded" if row is None else row["status"],
                         "ranking": None, "bundles_resolved": None, "input_hash": None,
                         "result_sha256": None, "claim_records": 0, "units": 0,
                         "population_units": 0, "population_copies": 0, "state": "no_output"})
            continue
        result = _load_result(run_dir, row, run_id)
        declared = (prepared.get(assignment["input_id"]) or {}).get("input_hash")
        if declared is not None and result["input_hash"] != declared:
            raise ContractError(f"{run_dir}: invocation {row['invocation_id']} saved a result bound to "
                                f"{result['input_hash']}, but its input was prepared as {declared}")
        ranked = result["ranking"] == "native"
        state = "included"
        if population == "first_b" and not ranked:
            state = "unranked"
        elif population == "first_b" and not result["bundles_resolved"]:
            state = "bundle_unresolved"
        groups = _groups(result["claims"])
        found = []
        if state == "included":
            for fingerprint, copies in groups.items():
                inside = (sum(copy["rank"] <= budget for copy in copies) if population == "first_b"
                          else len(copies))
                if inside:
                    found.append(_unit(record, fingerprint, copies, ranked, inside))
        units.extend(found)
        rows.append({**record, "status": result["status"], "ranking": result["ranking"],
                     "bundles_resolved": result["bundles_resolved"], "input_hash": result["input_hash"],
                     "result_sha256": canonical_sha256(result), "claim_records": len(result["claims"]),
                     "units": len(groups), "population_units": len(found),
                     "population_copies": sum(unit["population_copies"] for unit in found),
                     "state": state})
    return rows, units


def build_frame(run_dirs: Sequence[str | PathLike[str]], *, population: str, budget: int | None = None,
                systems: Iterable[str] | None = None, mode: str = "full",
                profile: str = "standard") -> dict:
    """The sampling frame of one declared claim population over saved run directories.

    Each run directory must hold a 2.1 manifest and the schedule it names; every assignment of a
    chosen system (default: every system the runs schedule) to an input of the (*mode*, *profile*)
    view becomes an invocation row, and every unit its saved result delivers into the population
    becomes a unit. ``first_b`` needs *budget* B and holds the units with a copy at native rank at
    most B: an invocation whose output is unranked, or whose bundles are unresolved, has no measured
    position and is left out whole, counted by reason in ``exclusions``, as are the units of included
    invocations that lie past B. ``full`` takes no budget and holds every delivered unit, whatever the
    invocation's status. Every claim a saved result carries is delivered output: its status is
    recorded beside it and nothing is dropped for it.

    The frame is a function of the documents read and nothing else: runs are taken in run-id order,
    assignments in id order, and units sorted by unit id, so the order run directories are named in
    and the order a filesystem lists them in change nothing. Refused: no run directory, a run read
    twice, a 2.0 manifest, a schedule or manifest that disagrees with itself, a bundle outside its
    run, a result that cannot be read or names another run, system, or input, an unknown system,
    and a view no chosen assignment falls in. A result is never skipped: a frame that dropped an
    unreadable bundle's claims would misstate the population. Nothing is written.
    """
    if population not in POPULATIONS:
        raise ContractError(f"population must be one of {', '.join(POPULATIONS)}, not {population!r}")
    if population == "first_b":
        if budget is None:
            raise ContractError("the first_b population needs a budget B")
        _count(budget, "budget", minimum=1)
    elif budget is not None:
        raise ContractError("a budget applies only to the first_b population")
    if mode not in MODES:
        raise ContractError(f"mode must be one of {', '.join(MODES)}, not {mode!r}")
    if profile not in PROFILES:
        raise ContractError(f"profile must be one of {', '.join(PROFILES)}, not {profile!r}")
    runs = [_load_run(Path(run_dir)) for run_dir in run_dirs]
    if not runs:
        raise ContractError("a precision frame needs at least one run directory")
    seen: dict[str, Path] = {}
    for run_dir, manifest, _schedule in runs:
        if manifest["run_id"] in seen:
            raise ContractError(f"{seen[manifest['run_id']]} and {run_dir} both hold run {manifest['run_id']}; "
                                "a frame names units by run id, so each run is read once")
        seen[manifest["run_id"]] = run_dir
    scheduled = {system["system_id"] for _, _, schedule in runs for system in schedule["systems"]}
    chosen = sorted(scheduled) if systems is None else sorted(set(systems))
    if not chosen:
        raise ContractError("name at least one system")
    unknown = sorted(set(chosen) - scheduled)
    if unknown:
        raise ContractError(f"systems not scheduled in any of these runs: {', '.join(unknown)}")
    runs.sort(key=lambda run: run[1]["run_id"])
    invocations: list[dict] = []
    units: list[dict] = []
    for run_dir, manifest, schedule in runs:
        rows, found = _run_frame(run_dir, manifest, schedule, set(chosen), mode, profile, population, budget)
        invocations.extend(rows)
        units.extend(found)
    if not invocations:
        raise ContractError(f"no assignment of {', '.join(chosen)} in these runs is a {mode} input with the "
                            f"{profile} profile")
    units.sort(key=lambda unit: unit["unit_id"])
    return {
        "population": {"name": population, "budget": budget, "mode": mode, "profile": profile,
                       "systems": chosen},
        "runs": [{"run_id": manifest["run_id"], "status": manifest["status"],
                  "manifest_sha256": canonical_sha256(manifest),
                  "schedule_sha256": canonical_sha256(schedule)} for _, manifest, schedule in runs],
        "invocations": invocations,
        "units": units,
        "exclusions": precision_exclusions(invocations),
    }


# --- the design -----------------------------------------------------------------------------------


def stratify(frame: dict, stratify_by: str | None) -> dict[str, list[str]]:
    """Every stratum of *frame* under *stratify_by*, with its unit ids sorted, strata by name.

    Unstratified, the whole population is the one stratum ``all``. Only strata that hold a unit
    exist: a system that delivered nothing has no stratum to cover.
    """
    if stratify_by is not None and stratify_by not in STRATIFICATIONS:
        raise ContractError(f"stratify_by must be one of {', '.join(STRATIFICATIONS)}, not {stratify_by!r}")
    strata: dict[str, list[str]] = defaultdict(list)
    for unit in frame["units"]:
        strata[precision_stratum(unit, stratify_by)].append(unit["unit_id"])
    return {name: sorted(ids) for name, ids in sorted(strata.items())}


def allocate(sizes: dict[str, int], size: int, allocation: str | None) -> dict[str, int]:
    """How many units each stratum of the given sizes draws, *size* in all.

    ``None`` is the unstratified design and takes exactly one stratum. ``proportional`` gives each
    stratum the whole part of ``size * N_h / N`` and the units left over, one each, to the largest
    fractional parts, ties broken by stratum name; no stratum is ever given more than it holds. That
    can leave a small stratum with nothing, which is recorded as uncovered. ``equal`` shares *size*
    equally, the remainder one each to the first strata by name; a stratum no larger than its share
    is taken whole (a census) and what remains is shared again among the rest, so the sample is
    always *size* units. Fractions are exact, so no rounding error can move a unit. A size that is
    not a positive integer, or that exceeds the population, is refused.
    """
    names = sorted(sizes)
    total = sum(sizes.values())
    _count(size, "sample size", minimum=1)
    if size > total:
        raise ContractError(f"cannot draw {size} of {total} units without replacement")
    if allocation is None:
        if len(names) != 1:
            raise ContractError("an unstratified design draws from exactly one stratum")
        return {names[0]: size}
    if allocation == "proportional":
        shares = {name: Fraction(size * sizes[name], total) for name in names}
        allocated = {name: math.floor(share) for name, share in shares.items()}
        left = size - sum(allocated.values())
        for name in sorted(names, key=lambda name: (allocated[name] - shares[name], name))[:left]:
            allocated[name] += 1
        return allocated
    if allocation == "equal":
        allocated: dict[str, int] = {}
        open_strata, left = list(names), size
        while open_strata:
            share, extra = divmod(left, len(open_strata))
            whole = [name for name in open_strata if sizes[name] <= share]
            if not whole:
                for index, name in enumerate(open_strata):
                    allocated[name] = share + (1 if index < extra else 0)
                break
            for name in whole:
                allocated[name] = sizes[name]
                left -= sizes[name]
            open_strata = [name for name in open_strata if name not in whole]
        return {name: allocated[name] for name in names}
    raise ContractError(f"allocation must be one of {', '.join(ALLOCATIONS)}, not {allocation!r}")


def draw(strata: dict[str, list[str]], allocated: dict[str, int], *, seed: int,
         frame_sha256: str) -> dict[str, list[str]]:
    """The units each stratum draws: a simple random sample without replacement, sorted.

    Stratum h draws ``allocated[h]`` of its units from its own stream,
    ``Stream(seed, label=STREAM_LABEL.format(frame_sha256=..., stratum=h))``, over its unit ids in
    sorted order, so every unit of the stratum is drawn with probability ``n_h / N_h`` and adding,
    removing, or resizing another stratum never moves this one's draws. This is the whole of the
    sampling algorithm; :func:`draw_sample` records its result.
    """
    return {name: sorted(sample_without_replacement(
                ids, allocated[name],
                Stream(seed, label=STREAM_LABEL.format(frame_sha256=frame_sha256, stratum=name))))
            for name, ids in strata.items()}


def _design(stratify_by: str | None, allocation: str | None) -> tuple[str, str | None]:
    """The method and allocation a stratification choice names; an allocation alone is refused."""
    if stratify_by is None:
        if allocation is not None:
            raise ContractError("an allocation applies to a stratified design; name what to stratify by")
        return "srswor", None
    if stratify_by not in STRATIFICATIONS:
        raise ContractError(f"stratify_by must be one of {', '.join(STRATIFICATIONS)}, not {stratify_by!r}")
    allocation = allocation or "proportional"
    if allocation not in ALLOCATIONS:
        raise ContractError(f"allocation must be one of {', '.join(ALLOCATIONS)}, not {allocation!r}")
    return "stratified_srswor", allocation


def _permutation(items: list[str], seed: int, label: str) -> list[str]:
    """*items*, sorted, in the order one full draw of the labeled stream puts them."""
    return sample_without_replacement(sorted(items), len(items), Stream(seed, label=label))


def _sample_notes(frame: dict, uncovered: list[str]) -> list[str]:
    population = frame["population"]
    exclusions = frame["exclusions"]
    notes = [
        "A unit is one exact-duplicate group of claims within one invocation. It is reviewed once; its "
        "other copies are duplicate delivery burden, not more claims to judge.",
        "Each stratum is a simple random sample without replacement, so every unit of stratum h was "
        "drawn with probability n_h/N_h as recorded, and an estimate weights each reviewed unit by N_h/n_h.",
    ]
    if population["name"] == "first_b":
        unranked, unresolved = exclusions["unranked"], exclusions["bundle_unresolved"]
        notes.append(
            f"The first_b population (B={population['budget']}) leaves out {unranked['invocations']} unranked "
            f"invocation(s) holding {unranked['units']} unit(s) and {unresolved['invocations']} "
            f"bundle-unresolved invocation(s) holding {unresolved['units']} unit(s), whose claims have no "
            f"measured native position, and {exclusions['beyond_budget']['units']} unit(s) past B.")
    else:
        unresolved_rows = {(row["run_id"], row["invocation_id"]) for row in frame["invocations"]
                           if row["bundles_resolved"] is False}
        pending = sum((unit["run_id"], unit["invocation_id"]) in unresolved_rows for unit in frame["units"])
        if pending:
            notes.append(f"{pending} unit(s) come from invocations whose bundles are unresolved; such a unit "
                         "may carry more than one allegation.")
    if exclusions["no_output"]["invocations"]:
        notes.append(f"{exclusions['no_output']['invocations']} assignment(s) in this view delivered no output "
                     "(skipped or never recorded), so they add no claim to the population.")
    failed = [run["run_id"] for run in frame["runs"] if run["status"] != "completed"]
    if failed:
        notes.append(f"Run(s) {', '.join(failed)} did not complete; an assignment such a run never recorded "
                     "adds no claim to the population.")
    if uncovered:
        notes.append(f"{len(uncovered)} stratum/strata drew no unit ({', '.join(uncovered)}); no estimate from "
                     "this sample represents them.")
    notes.append("The review queue shows each system only by an alias, and each claim under an item id. "
                 "The mapping is in this document, which stays with the evaluator.")
    return notes


def draw_sample(frame: dict, *, size: int, seed: int, stratify_by: str | None = None,
                allocation: str | None = None) -> dict:
    """The validated precision sample *seed* draws from *frame* under the named design.

    Unstratified (``srswor``) draws *size* units from the one stratum ``all``; with *stratify_by*
    (``system``, ``input``, or ``kind``) the sample is stratified, *allocation* (default
    ``proportional``) decides each stratum's share (:func:`allocate`), and each stratum draws from
    its own stream (:func:`draw`). The document records the frame and its digest, the design and the
    algorithm, every stratum's ``N_h``, ``n_h``, and inclusion probability ``n_h / N_h``, the strata
    that drew nothing, the selected unit ids in sorted order with the item id each is reviewed
    under, and the system aliases the queue uses. Item order and aliases are seeded permutations
    from streams of their own, so they reveal neither a unit's position nor a system's name.

    The same frame, size, seed, and design always give the same document, byte for byte, and
    :func:`verify_sample` holds any sample to that. Choosing the seed after looking at what it
    draws defeats the purpose, so state it before drawing. Nothing here reads a run or writes a file.
    """
    method, allocation = _design(stratify_by, allocation)
    frame_sha256 = canonical_sha256(frame)
    strata = stratify(frame, stratify_by)
    if not strata:
        population = frame["population"]
        raise ContractError(f"the {population['name']} population holds no unit, so there is nothing to sample")
    sizes = {name: len(ids) for name, ids in strata.items()}
    allocated = allocate(sizes, size, allocation)
    drawn = draw(strata, allocated, seed=seed, frame_sha256=frame_sha256)
    selected = sorted((unit_id, name) for name, ids in drawn.items() for unit_id in ids)
    order = _permutation([unit_id for unit_id, _ in selected], seed, ITEM_LABEL.format(frame_sha256=frame_sha256))
    width = max(4, len(str(len(order))))
    item_of = {unit_id: f"item-{index:0{width}d}" for index, unit_id in enumerate(order, start=1)}
    systems = frame["population"]["systems"]
    alias_order = _permutation(systems, seed, ALIAS_LABEL.format(frame_sha256=frame_sha256))
    alias_of = {system: f"system-{index}" for index, system in enumerate(alias_order, start=1)}
    uncovered = [name for name in strata if not allocated[name]]
    sample = {
        "schema_version": SCHEMA_VERSION,
        "frame": deepcopy(frame),
        "frame_sha256": frame_sha256,
        "design": {"method": method, "stratify_by": stratify_by, "allocation": allocation, "size": size,
                   "seed": seed, "algorithm": ALGORITHM, "stream_label": STREAM_LABEL},
        "strata": [{"stratum": name, "population_units": sizes[name], "sampled_units": allocated[name],
                    "inclusion_probability": allocated[name] / sizes[name]} for name in strata],
        "uncovered_strata": uncovered,
        "selected": [{"unit_id": unit_id, "stratum": name, "item_id": item_of[unit_id]}
                     for unit_id, name in selected],
        "blinding": {"system_aliases": [{"system_id": system, "alias": alias_of[system]}
                                        for system in sorted(systems)]},
        "notes": _sample_notes(frame, uncovered),
    }
    return validate_document(SAMPLE_KIND, sample)


def verify_sample(sample: dict) -> dict:
    """Refuse a sample that is not exactly what its own frame, design, and seed draw; return it.

    The contract checks that the sample agrees with its frame. This also recomputes every unit's
    duplicate identity from the claim it records, and draws the sample again from its frame with its
    recorded size, seed, and design: a selection edited after the draw (a unit dropped, swapped, or
    added), a moved stratum, an edited alias, or a claim edited after the frame was built is refused.
    A sample drawn by a build with another algorithm is refused as one this build cannot reproduce.
    It proves self-consistency only: whoever holds the frame can draw with another seed, so a seed
    carries weight only when it was stated before the draw.
    """
    validate_document(SAMPLE_KIND, sample)
    design = sample["design"]
    if design["algorithm"] != ALGORITHM:
        raise ContractError(f"this sample was drawn with {design['algorithm']}; this build draws with "
                            f"{ALGORITHM} and cannot reproduce it")
    for unit in sample["frame"]["units"]:
        if claim_fingerprint(unit["claim"]) != unit["fingerprint"]:
            raise ContractError(f"unit {unit['unit_id']}: its claim does not hash to the fingerprint the frame "
                                "records; the claim was edited after the frame was built")
    redrawn = draw_sample(sample["frame"], size=design["size"], seed=design["seed"],
                          stratify_by=design["stratify_by"], allocation=design["allocation"])
    if canonical_json(redrawn) != canonical_json(sample):
        differing = sorted(key for key in sample if sample[key] != redrawn[key])
        raise ContractError(f"this sample is not what seed {design['seed']} and its design draw from its "
                            f"frame ({', '.join(differing)} differ); it was edited after it was drawn")
    return sample
