"""Corpus aggregation and paired comparison of frozen run directories.

:func:`aggregate` reads one or more run directories and reports, for every system, the corpus metrics
of ``docs/EVALUATION_MATH.md`` sections 1, 2, 4, and 5 under a frozen aggregation policy: full-output
and budgeted known-target recall, control false-alarm rates with their missing-assessment bounds,
vulnerable/fixed pair correctness, completion, claim volume, usage and cost, run variability, and
cluster bootstrap intervals. :func:`compare` does the same for two systems that were assigned exactly
the same frozen work and reports candidate minus baseline with paired intervals.
``docs/AGGREGATION.md`` states what every metric means and what its denominator is.

What is read. A run directory is read through its 2.1 run manifest, the schedule that manifest names,
and the configuration the run copied, each bound to the others by hash; a 2.0 manifest names no
schedule and is refused. Every assignment in the schedule is one observation, whatever became of it:
an input that could not be prepared, a skipped system, an assignment the manifest has no row for, and
a bundle that is missing or cannot be read are failures that detect nothing and complete nothing, and
they stay in every denominator with their reason. A bundle is read through
:func:`scaneval.scoring.observe`, which refuses a plan, result, and decisions that do not bind to one
another, and :func:`scaneval.review.review_status`; a refused bundle is a failure too.

What is scored against what. An input is scored on the targets and controls its schedule froze before
the run. An item frozen there but absent from the bundle's plan is a miss (``unscored``), and an item
a bundle's plan adds is ignored. An input whose schedule froze no plan takes no part in any target or
control metric and is listed as such; its assignments still count toward completion, claims, and
usage. Observations are keyed by run and input, so one input scanned by two runs is two positive
inputs of its targets, each averaged over its own repetitions.

Evidence scope. An observation is reviewed evidence only when its bundle's plan is reviewed and its
review record is human-approved; a failure takes the scope of the plan its schedule froze. A view that
mixes diagnostic fixtures with any other evidence is refused, and reviewed evidence mixed with draft
evidence is reported as draft.

Determinism and exactness. Runs are ordered by run id and every other collection is sorted. Weights,
means, masses, and ratios are exact rationals (:class:`fractions.Fraction`; a weight a policy states
as a decimal is read as that decimal), each rounded once to the nearest float when a report is
written, so a hand-calculated 2/3 is reported as the float nearest 2/3 and a degenerate interval
cannot pass for a narrow one through rounding. Usage figures the scanners reported are floats and are
summed with :func:`math.fsum`. Bootstrap draws come from :class:`scaneval.resampling.Stream` under the
policy's seed and a label naming the view, the slice, and the family resampled: the clusters carrying
targets, those carrying a frozen pair, or those carrying controls. The same run directories and policy
therefore give byte-identical documents under :func:`scaneval.contracts.canonical_json`, whatever
order the directories are named in. Nothing here reads a clock, the network, or an unseeded random
source, and no model or judge is consulted. A report carries no filesystem path.

What this is not. It scores no claim and approves nothing, and it reads no label content beyond the
schedule's ids, kinds, levels, and groupings. It does not estimate reviewed precision or review time
(``docs/EVALUATION_MATH.md`` section 3), mixed-intent correctness, or freshness, and it decides no
promotion. An interval describes resampling of the projects or families observed; it is not evidence
that they represent software beyond them. Run variability is conditional run noise, not corpus
uncertainty.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from fractions import Fraction
import math
from math import comb
from os import PathLike
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from . import __version__, review, scoring
from .contracts import (
    WEIGHT_TOLERANCE,
    ContractError,
    canonical_json,
    canonical_sha256,
    load_document,
    validate_document,
)
from .resampling import Stream, resample_with_replacement
from .runner import MANIFEST_KIND, MANIFEST_NAME
from .schedule import SCHEDULE_KIND


POLICY_KIND = "aggregation-policy"
REPORT_KIND = "aggregate-report"
COMPARISON_KIND = "comparison-report"
SCHEMA_VERSION = "2.1"
CONFIG_NAME = "run-config.json"

# The planned control types each separately reported control class admits; a control of type 'both'
# appears in both classes and is never pooled twice into one of them.
CONTROL_CLASSES = {"capability_safe": ("capability_safe", "both"), "fixed_target": ("fixed_target", "both")}
STATUSES = ("success", "partial", "unsupported", "error", "timeout", "skipped", "missing")
FAILURE_REASONS = ("failed_preparation", "skipped_system", "skipped", "missing_row", "missing_bundle",
                   "unusable_bundle")
REVIEW_STATES = ("human_approved", "draft", "stale", "missing")
PAIR_OUTCOMES = ("correct", "both_flagged", "both_silent", "reversed")
# Leave-one-project-out sensitivity is shown while projects are few (docs/EVALUATION_MATH.md, section 5).
LOPO_PROJECT_LIMIT = 10

RANDOM_ORDER_LABEL = ("diagnostic: expected recall under a uniform random order of the delivered claims, "
                      "over unranked observations with resolved bundles only; not native recall@B and not "
                      "a promotion metric")
RUN_VARIABILITY_LABEL = ("conditional run noise of repeated runs of one input, treating targets as "
                         "independent; not corpus uncertainty")

DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": SCHEMA_VERSION,
    "policy_id": "scaneval-default",
    "policy_version": "1",
    "views": ["equal_target", "equal_project", "equal_family"],
    "target_weights": None,
    "workload_weights": None,
    "uncertainty": {"method": "cluster_bootstrap", "cluster_by": "project", "replicates": 1000,
                    "confidence": 0.95, "seed": 0, "min_clusters": 5},
    "notes": ["The built-in default policy: equal weights, projects as resampling clusters, and seed 0, "
              "fixed in the evaluator rather than chosen after seeing any result."],
}


# --- policy -------------------------------------------------------------------------------------


def resolve_policy(policy: dict | None = None) -> dict:
    """The complete policy an aggregation runs under: *policy* with its optional fields filled in.

    ``None`` gives :data:`DEFAULT_POLICY`. A supplied policy is validated as written and again once
    completed, and the result is a new document: *policy* is not modified. Every report records the
    completed policy and its hash, so a report never depends on a default it does not show.
    """
    if policy is None:
        return validate_document(POLICY_KIND, deepcopy(DEFAULT_POLICY))
    validate_document(POLICY_KIND, policy)
    completed = {"target_weights": None, "workload_weights": None, "notes": [], **deepcopy(policy)}
    return validate_document(POLICY_KIND, completed)


def load_policy(path: str | PathLike[str]) -> dict:
    """Load an aggregation-policy file and return it completed by :func:`resolve_policy`."""
    return resolve_policy(load_document(path, POLICY_KIND))


# --- reading run directories --------------------------------------------------------------------


@dataclass(frozen=True)
class _Run:
    """One run directory as read: its manifest, the schedule it names, and its configuration."""

    run_id: str
    directory: Path
    manifest: dict = field(repr=False)
    schedule: dict = field(repr=False)
    config: dict = field(repr=False)

    @property
    def system_ids(self) -> tuple[str, ...]:
        return tuple(sorted(system["system_id"] for system in self.schedule["systems"]))

    @property
    def repetitions(self) -> int:
        return self.schedule["repetitions"]


@dataclass(frozen=True)
class _Observation:
    """One scheduled assignment and what its run directory says about it.

    ``observed`` is :func:`scaneval.scoring.observe` of the bundle, or ``None`` for a failure, whose
    ``reason`` then names why no bundle could be read. ``scope`` is the evidence scope, ``None`` for an
    input whose schedule froze no plan. ``unscored`` and ``unregistered`` count the frozen items the
    bundle's plan lacks and the items it adds. ``timing`` holds the execution record's start, finish,
    and wall seconds when the bundle carries one; a start or finish it cannot read is ``None``.
    """

    run_id: str
    input_id: str
    system_id: str
    repetition: int
    assignment_id: str
    status: str
    reason: str | None = None
    scope: str | None = None
    observed: dict | None = field(default=None, repr=False)
    review_state: str | None = None
    unscored: int = 0
    unregistered: int = 0
    timing: tuple[datetime | None, datetime | None, float] | None = None


def _inside(root: Path, relative: str, label: str) -> Path:
    """*relative* under *root*, refused when it resolves anywhere else (through a link, say)."""
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ContractError(f"{label} {relative!r} resolves outside the run directory {root}")
    return path


def _load_run(directory: str | PathLike[str]) -> _Run:
    """Read one run directory and check that its manifest, schedule, and configuration agree.

    Refused: a directory with no run manifest, a 2.0 manifest (it names no schedule, so nothing about
    the run was frozen before it ran), a schedule or configuration bound to a different run or
    configuration than the manifest, and a manifest recording an invocation its schedule never
    assigned. Bundles are read later, one assignment at a time, and never refuse the run.
    """
    root = Path(directory).expanduser().resolve()
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        raise ContractError(f"{root} holds no {MANIFEST_NAME}; aggregation reads run directories that "
                            "scaneval run wrote")
    manifest = load_document(manifest_path, MANIFEST_KIND)
    run_id = manifest["run_id"]
    if manifest["schema_version"] == "2.0":
        raise ContractError(
            f"run {run_id} at {root} predates frozen schedules: its 2.0 manifest names no schedule, so "
            "what it was assigned was never frozen and it cannot be aggregated")
    schedule = load_document(_inside(root, manifest["schedule_path"], "schedule_path"), SCHEDULE_KIND)
    if schedule["run_id"] != run_id:
        raise ContractError(f"the schedule of run {run_id} names run {schedule['run_id']}")
    if schedule["config_sha256"] != manifest["config_sha256"]:
        raise ContractError(f"the schedule and the manifest of run {run_id} bind to different configurations")
    config = load_document(root / CONFIG_NAME, "run-config")
    if canonical_sha256(config) != schedule["config_sha256"]:
        raise ContractError(f"{CONFIG_NAME} of run {run_id} is not the configuration its schedule froze")
    assigned = {row["assignment_id"] for row in schedule["assignments"]}
    unscheduled = sorted(row["invocation_id"] for row in manifest["invocations"]
                         if row["invocation_id"] not in assigned)
    if unscheduled:
        raise ContractError(f"run {run_id} records invocations its schedule never assigned: "
                            f"{', '.join(unscheduled[:3])}")
    return _Run(run_id, root, manifest, schedule, config)


def _instant(text: str) -> datetime | None:
    """The timezone-aware moment an execution record states, or ``None`` when it states none usable."""
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def _check_identity(run: _Run, assignment: dict, row: dict, prepared: dict | None, result: dict) -> None:
    """Refuse a result that is not the record of this assignment of this run."""
    if result["run_id"] != run.run_id:
        raise ContractError(f"result.json names run {result['run_id']!r}, not {run.run_id!r}")
    if result["system_id"] != assignment["system_id"]:
        raise ContractError(f"result.json names system {result['system_id']!r}, not "
                            f"{assignment['system_id']!r}")
    if row["status"] != result["status"]:
        raise ContractError(f"the manifest records status {row['status']!r} but result.json says "
                            f"{result['status']!r}")
    expected = (prepared or {}).get("input_hash")
    if expected and expected != result["input_hash"]:
        raise ContractError("result.json binds to a different input than the manifest recorded")


def _timing(bundle: Path, run: _Run, assignment: dict, result: dict) -> tuple | None:
    """The execution record's start, finish, and wall seconds, or ``None`` when the bundle has none.

    A record present but naming another invocation, or another status than the result, is refused:
    it is not the record of this scan.
    """
    path = bundle / "execution.json"
    if not path.exists():
        return None
    record = load_document(path, "execution-record")
    expected = {"run_id": run.run_id, "invocation_id": assignment["assignment_id"],
                "input_id": assignment["input_id"], "system_id": assignment["system_id"],
                "repetition": assignment["repetition"], "status": result["status"]}
    for key, value in expected.items():
        if record[key] != value:
            raise ContractError(f"execution.json records {key} {record[key]!r} where the assignment and "
                                f"its result say {value!r}")
    return _instant(record["started_at"]), _instant(record["finished_at"]), float(record["wall_seconds"])


def _observe(run: _Run, assignment: dict, row: dict | None, prepared: dict | None, system: dict | None,
             frozen: dict) -> _Observation:
    """What *run* says about one *assignment*: a read bundle, or a failure and why.

    The reason of a failure is the first that applies: ``missing_row`` (the manifest has no row, as in
    a run that stopped), ``failed_preparation`` or ``skipped_system`` or ``skipped`` (a skipped row,
    by the manifest's own record of the input and the system), ``missing_bundle`` (the row names a
    bundle that is not there), and ``unusable_bundle`` (a bundle whose documents do not load, do not
    bind to one another, or do not belong to this assignment).
    """
    identity = {"run_id": run.run_id, "input_id": assignment["input_id"],
                "system_id": assignment["system_id"], "repetition": assignment["repetition"],
                "assignment_id": assignment["assignment_id"]}
    planned = frozen["state"] == "frozen"

    def failure(status: str, reason: str) -> _Observation:
        return _Observation(**identity, status=status, reason=reason,
                            scope=frozen["scope"] if planned else None)

    if row is None:
        return failure("missing", "missing_row")
    if row["status"] == "skipped":
        if prepared is not None and prepared.get("preparation_failure") is not None:
            return failure("skipped", "failed_preparation")
        if system is not None and system.get("skipped_reason") is not None:
            return failure("skipped", "skipped_system")
        return failure("skipped", "skipped")
    try:
        bundle = _inside(run.directory, row["bundle_path"], "bundle_path")
    except ContractError:
        return failure("missing", "unusable_bundle")
    if not bundle.is_dir():
        return failure("missing", "missing_bundle")
    evaluator = bundle / review.EVALUATOR_DIR
    try:
        plan = load_document(evaluator / review.PLAN_FILE, review.PLAN_KIND)
        result = load_document(bundle / review.RESULT_FILE, review.RESULT_KIND)
        decisions = load_document(evaluator / review.DECISIONS_FILE, review.DECISIONS_KIND)
        observed = scoring.observe(plan, result, decisions)
        state = review.review_status(bundle, guard_symlinks=False)
        _check_identity(run, assignment, row, prepared, result)
        timing = _timing(bundle, run, assignment, result)
    except ContractError:
        return failure("missing", "unusable_bundle")
    scope = None
    unscored = unregistered = 0
    if planned:
        if plan["scope"] == "diagnostic":
            scope = "diagnostic"
        elif plan["scope"] == "reviewed" and state == "human_approved":
            scope = "reviewed"
        else:
            scope = "draft"
        for kind, key in (("targets", "target_id"), ("controls", "control_id")):
            frozen_ids = {item[key] for item in frozen[kind]}
            planned_ids = {item[key] for item in plan[kind]}
            unscored += len(frozen_ids - planned_ids)
            unregistered += len(planned_ids - frozen_ids)
    return _Observation(**identity, status=result["status"], scope=scope, observed=observed,
                        review_state=state, unscored=unscored, unregistered=unregistered, timing=timing)


@dataclass
class _Corpus:
    """Every run read, every assignment observed, and the canonical items the schedules froze.

    ``targets`` and ``controls`` map a canonical id to the project, workload, and family it is
    weighted and clustered by; ``inputs`` maps (run id, input id) to the schedule row.
    """

    runs: list[_Run]
    observations: dict[tuple[str, str, str, int], _Observation]
    targets: dict[str, dict]
    controls: dict[str, dict]
    inputs: dict[tuple[str, str], dict]
    systems: dict[str, dict]

    def repetitions(self, run_id: str) -> int:
        return next(run.repetitions for run in self.runs if run.run_id == run_id)


def _configuration(run: _Run, system_id: str) -> dict:
    """What one system is, as its run configured it: adapter, config, model, network policy, execution."""
    entry = next(item for item in run.config["systems"] if item["system_id"] == system_id)
    return {"adapter": entry["adapter"], "config": entry["config"], "model_id": entry.get("model_id"),
            "model_revision": entry.get("model_revision"),
            "network_policy": entry.get("network_policy", run.config["network_policy"]),
            "execution": entry.get("execution") or {"backend": "local"}}


def _systems(runs: list[_Run]) -> dict[str, dict]:
    """Every scheduled system, refusing one system id configured differently in two runs."""
    systems: dict[str, dict] = {}
    for run in runs:
        for row in run.schedule["systems"]:
            system_id = row["system_id"]
            configuration = _configuration(run, system_id)
            known = systems.get(system_id)
            if known is None:
                systems[system_id] = {"row": row, "configuration": configuration, "runs": [run.run_id]}
                continue
            if (canonical_json(known["configuration"]) != canonical_json(configuration)
                    or canonical_json(known["row"]) != canonical_json(row)):
                raise ContractError(
                    f"system {system_id} is configured differently in runs {known['runs'][0]} and "
                    f"{run.run_id}; one system id must name one configuration to be aggregated")
            known["runs"].append(run.run_id)
    return dict(sorted(systems.items()))


def _registry(runs: list[_Run]) -> tuple[dict[str, dict], dict[str, dict]]:
    """The project, workload, and family of every canonical target and control the schedules froze.

    A canonical item is one root cause or one property wherever it is planned, so it is weighted and
    resampled as one unit; one planned under two projects, workloads, or families cannot be, and is
    refused. A target's grouping is its case's; a control's project and workload are its input's, and
    its family is that of the target it guards or of its case's target, or its own case when neither
    is planned anywhere.
    """
    targets: dict[str, dict] = {}
    controls: dict[str, dict] = {}
    seen: dict[tuple[str, str], str] = {}
    families_by_target: dict[str, str] = {}
    families_by_case: dict[str, str] = {}

    def record(table: dict, kind: str, canonical: str, attributes: dict, where: str) -> None:
        known = table.setdefault(canonical, attributes)
        seen.setdefault((kind, canonical), where)
        if known != attributes:
            raise ContractError(
                f"canonical {kind} {canonical} is planned as {canonical_json(known)} at "
                f"{seen[(kind, canonical)]} and as {canonical_json(attributes)} at {where}; a canonical "
                f"{kind} belongs to one project, workload, and family")

    frozen = [(run, row) for run in runs for row in run.schedule["inputs"]
              if row["plan"]["state"] == "frozen"]
    for run, row in frozen:
        for target in row["plan"]["targets"]:
            record(targets, "target", target["canonical_id"],
                   {"project": target["project"], "workload": target["workload"],
                    "family": target["variant_family"]}, f"{run.run_id}/{row['input_id']}")
            families_by_target[target["target_id"]] = target["variant_family"]
            families_by_case[target["case_id"]] = target["variant_family"]
    for run, row in frozen:
        for control in row["plan"]["controls"]:
            family = (families_by_target.get(control["target_id"] or "")
                      or families_by_case.get(control["case_id"]) or f"case:{control['case_id']}")
            record(controls, "control", control["canonical_id"],
                   {"project": row["project"], "workload": row["workload"], "family": family},
                   f"{run.run_id}/{row['input_id']}")
    return targets, controls


def _load_corpus(run_dirs: Iterable[str | PathLike[str]]) -> _Corpus:
    """Read every run directory and observe every assignment its schedule lists.

    Refused: no directory at all, one run given twice, runs whose schedules froze different packs
    (canonical ids, levels, and families are comparable only within one frozen pack), a system id
    configured two ways, and a canonical item planned under two groupings.
    """
    runs = [_load_run(directory) for directory in run_dirs]
    if not runs:
        raise ContractError("aggregation needs at least one run directory")
    repeated = sorted(run_id for run_id, count in Counter(run.run_id for run in runs).items() if count > 1)
    if repeated:
        raise ContractError(f"run {repeated[0]} is given more than once; each run is aggregated once")
    runs.sort(key=lambda run: run.run_id)
    packs = sorted({canonical_json(run.schedule["pack"]) for run in runs})
    if len(packs) > 1:
        raise ContractError(f"the runs froze different packs ({'; '.join(packs)}); aggregate runs of one "
                            "pack, because canonical ids and levels are comparable only within one")
    systems = _systems(runs)
    targets, controls = _registry(runs)
    inputs = {(run.run_id, row["input_id"]): row for run in runs for row in run.schedule["inputs"]}
    observations: dict[tuple[str, str, str, int], _Observation] = {}
    for run in runs:
        rows = {row["invocation_id"]: row for row in run.manifest["invocations"]}
        prepared = {row["input_id"]: row for row in run.manifest["inputs"]}
        manifest_systems = {row["system_id"]: row for row in run.manifest["systems"]}
        for assignment in sorted(run.schedule["assignments"], key=lambda item: item["assignment_id"]):
            key = (run.run_id, assignment["input_id"], assignment["system_id"], assignment["repetition"])
            observations[key] = _observe(
                run, assignment, rows.get(assignment["assignment_id"]), prepared.get(assignment["input_id"]),
                manifest_systems.get(assignment["system_id"]), inputs[key[:2]]["plan"])
    return _Corpus(runs, observations, targets, controls, inputs, systems)


# --- weights ------------------------------------------------------------------------------------


_GROUP_FIELD = {"equal_target": None, "equal_project": "project", "equal_family": "family"}


def _decimal(value: float | int) -> Fraction:
    """A number a policy states, read as the decimal it is written as: 0.7 is 7/10."""
    return Fraction(repr(value)) if isinstance(value, float) else Fraction(value)


def _float(value: Fraction | None) -> float | None:
    """An exact value rounded once to the nearest float for the report; ``None`` stays undefined."""
    return None if value is None else float(value)


def _within(attributes: dict[str, dict], weighting: str) -> dict[str, Fraction]:
    """Equal weight per item, or per group of items and then per item within it: 1/(G n_g)."""
    field_name = _GROUP_FIELD[weighting]
    members: dict[str, list[str]] = defaultdict(list)
    for key in sorted(attributes):
        members[key if field_name is None else attributes[key][field_name]].append(key)
    groups = len(members)
    return {key: Fraction(1, groups * len(group)) for group in members.values() for key in group}


def _weights(attributes: dict[str, dict], weighting: str, policy: dict, *,
             whole_view: bool) -> tuple[dict[str, Fraction] | None, str | None, list[str]]:
    """Frozen weights over the canonical items of one slice, or ``None`` and the reason there are none.

    Weights sum to exactly 1 within the slice. ``explicit`` takes the policy's declared weight of each
    canonical target: over a whole view they must cover every target and sum to 1 (within
    :data:`scaneval.contracts.WEIGHT_TOLERANCE`), and a slice renormalizes them. Any other weighting
    of items from two or more workloads needs the policy's workload weights, renormalized over the
    workloads present, because a summary across workloads needs predeclared weights; without them
    there is no number. The notes say what was renormalized away.
    """
    keys = sorted(attributes)
    if weighting == "explicit":
        declared = {key: _decimal(value) for key, value in policy["target_weights"].items()}
        missing = [key for key in keys if key not in declared]
        if missing:
            return None, f"the policy declares no weight for canonical target {', '.join(missing[:3])}", []
        total = sum((declared[key] for key in keys), Fraction(0))
        if whole_view and abs(total - 1) > _decimal(WEIGHT_TOLERANCE):
            return None, (f"the declared weights of this view's canonical targets sum to {float(total)!r}, "
                          "not 1"), []
        if total <= 0:
            return None, "the declared weights of this slice's canonical targets sum to 0", []
        return {key: declared[key] / total for key in keys}, None, []
    workloads = sorted({attributes[key]["workload"] for key in keys})
    if len(workloads) == 1:
        return _within(attributes, weighting), None, []
    if policy["workload_weights"] is None:
        return None, (f"this slice spans {len(workloads)} workloads ({', '.join(workloads)}) and the policy "
                      "declares no workload weights; no summary crosses workloads without them"), []
    declared = {name: _decimal(value) for name, value in policy["workload_weights"].items()}
    undeclared = [name for name in workloads if name not in declared]
    if undeclared:
        return None, f"the policy declares no weight for workload {', '.join(undeclared)}", []
    total = sum((declared[name] for name in workloads), Fraction(0))
    if total <= 0:
        return None, "the declared weights of this slice's workloads sum to 0", []
    notes = []
    absent = sum((value for name, value in declared.items() if name not in workloads), Fraction(0))
    if absent > 0:
        notes.append(f"declared workload weight {float(absent)!r} on workloads absent from this slice is "
                     "renormalized over the workloads present")
    weights: dict[str, Fraction] = {}
    for name in workloads:
        members = {key: attributes[key] for key in keys if attributes[key]["workload"] == name}
        share = declared[name] / total
        weights.update({key: share * value for key, value in _within(members, weighting).items()})
    return dict(sorted(weights.items())), None, notes


# --- one ratio metric and its bootstrap ---------------------------------------------------------


@dataclass(frozen=True)
class _Ratio:
    """One metric as the exact ratio of two weighted sums, each also split by resampling cluster.

    ``value`` is ``Σ numerator / Σ denominator``, ``None`` when the denominator is 0; a bootstrap
    replicate reweights each cluster's two sums by how often it drew that cluster
    (:func:`_bootstrap`), so every weight stays the frozen one.
    """

    value: Fraction | None
    numerator: dict[str, Fraction]
    denominator: dict[str, Fraction]


def _ratio(weights: dict[str, Fraction], numerators: dict[str, Fraction],
           denominators: dict[str, Fraction] | None, cluster_of: Callable[[str], str]) -> _Ratio:
    """``Σ w a / Σ w b`` over *weights*; with no *denominators*, b is 1 and the weights sum to 1."""
    numerator: dict[str, Fraction] = defaultdict(Fraction)
    denominator: dict[str, Fraction] = defaultdict(Fraction)
    for key in sorted(weights):
        cluster = cluster_of(key)
        numerator[cluster] += weights[key] * numerators[key]
        denominator[cluster] += weights[key] * (1 if denominators is None else denominators[key])
    numerator, denominator = dict(sorted(numerator.items())), dict(sorted(denominator.items()))
    scale = sum(denominator.values(), Fraction(0))
    value = sum(numerator.values(), Fraction(0)) / scale if scale > 0 else None
    return _Ratio(value, numerator, denominator)


class _Resampler:
    """The replicate draws of one family of one slice: for each replicate, how often it drew each cluster.

    Replicates are drawn once, all together, from ``Stream(seed, label)``, the first time any metric
    asks for them, so every metric of the family and every system of the slice reads the same ones.
    """

    def __init__(self, universe: list[str], label: str, uncertainty: dict) -> None:
        self.universe = universe
        self.label = label
        self._uncertainty = uncertainty
        self._draws: list[Counter] | None = None

    @property
    def draws(self) -> list[Counter]:
        if self._draws is None:
            stream = Stream(self._uncertainty["seed"], label=self.label)
            self._draws = [Counter(self.universe[index]
                                   for index in resample_with_replacement(len(self.universe), stream))
                           for _ in range(self._uncertainty["replicates"])]
        return self._draws


def percentile_ranks(confidence: float, replicates: int) -> tuple[int, int]:
    """The 1-based order statistics bounding a percentile interval over *replicates* sorted values.

    ``l = max(1, ⌈(α/2)R⌉)`` and ``u = min(R, max(1, ⌈(1 − α/2)R⌉))`` with ``α = 1 − confidence``,
    where the confidence is read as the decimal the policy states (0.95 is 19/20, not the nearest
    binary float), so the ranks are exact: 25 and 975 of 1000 replicates at 0.95.
    """
    alpha = 1 - Fraction(repr(confidence))
    lower = max(1, math.ceil(alpha / 2 * replicates))
    upper = min(replicates, max(1, math.ceil((1 - alpha / 2) * replicates)))
    return lower, upper


def _unavailable_interval() -> dict:
    return {"state": "unavailable", "lower": None, "upper": None, "clusters": 0}


def _only(values: list[Fraction]) -> Fraction:
    return values[0]


def _minus(values: list[Fraction]) -> Fraction:
    return values[1] - values[0]


def _integers(part: _Ratio) -> tuple[dict[str, int], dict[str, int]]:
    """*part*'s cluster sums as integers over one common denominator, which every replicate cancels."""
    scale = math.lcm(*(value.denominator for value in (*part.numerator.values(), *part.denominator.values())))
    return ({cluster: int(value * scale) for cluster, value in part.numerator.items()},
            {cluster: int(value * scale) for cluster, value in part.denominator.items()})


def _bootstrap(parts: Sequence[_Ratio], combine: Callable[[list[Fraction]], Fraction],
               resampler: _Resampler | None, uncertainty: dict) -> dict:
    """A percentile cluster-bootstrap interval for ``combine`` of *parts*, or the state that replaces one.

    Every replicate recomputes each part exactly from the clusters it drew, with multiplicity and the
    frozen weights, then combines them: one part for a metric, two (baseline, candidate) for a paired
    difference. The bounds are the replicate values at :func:`percentile_ranks`. The states:
    ``unavailable`` when a part is undefined on the observed data, ``insufficient_clusters`` when fewer
    clusters carry the parts than the policy's ``min_clusters``, ``unstable`` when some replicate drew
    no cluster carrying a part so that part is undefined there, ``degenerate`` when the two bounds are
    equal, which is not certainty, and ``ok``. Only ``ok`` carries bounds, so a zero-width interval is
    never reported.
    """
    if resampler is None or any(part.value is None for part in parts):
        return _unavailable_interval()
    carrying = sorted({cluster for part in parts for cluster, mass in part.denominator.items() if mass > 0})
    if len(carrying) < uncertainty["min_clusters"]:
        return {"state": "insufficient_clusters", "lower": None, "upper": None, "clusters": len(carrying)}
    exact = [_integers(part) for part in parts]
    replicates: list[Fraction] = []
    for draw in resampler.draws:
        values = []
        for numerator, denominator in exact:
            bottom = sum(mass * draw[cluster] for cluster, mass in denominator.items())
            if bottom <= 0:
                return {"state": "unstable", "lower": None, "upper": None, "clusters": len(carrying)}
            values.append(Fraction(sum(mass * draw[cluster] for cluster, mass in numerator.items()), bottom))
        replicates.append(combine(values))
    replicates.sort()
    lower_rank, upper_rank = percentile_ranks(uncertainty["confidence"], len(replicates))
    lower, upper = replicates[lower_rank - 1], replicates[upper_rank - 1]
    if lower == upper:
        return {"state": "degenerate", "lower": None, "upper": None, "clusters": len(carrying)}
    return {"state": "ok", "lower": float(lower), "upper": float(upper), "clusters": len(carrying)}


# --- per-observation outcomes -------------------------------------------------------------------


def _random_order_expectation(delivered: int, hits: int, budget: int) -> Fraction:
    """``1 − C(M − h, b) / C(M, b)`` with ``b = min(B, M)``, exactly (``docs/EVALUATION_MATH.md`` §1).

    The chance that a uniform random order of *delivered* claims, duplicates included, puts one of the
    *hits* accepted claims in the first *budget* positions: the exact form of the probability
    :mod:`scaneval.scoring` computes in floating point. Zero for empty output and for no hit.
    """
    drawn = min(budget, delivered)
    if not (delivered and hits):
        return Fraction(0)
    if delivered - hits < drawn:
        return Fraction(1)
    return 1 - Fraction(comb(delivered - hits, drawn), comb(delivered, drawn))


def _target_outcome(observation: _Observation, target_ids: tuple[str, ...], budgets: list[int]) -> dict:
    """What one observation establishes about one canonical target planned on its input.

    The target ids are the input's planned records of that canonical target; any of them detected is
    the target detected, at the earliest measured rank. A failure detects nothing and completes
    nothing but has a known position under every budget (none). A valid output whose native order or
    bundles are unresolved leaves every budget of the observation unmeasurable, as scoring does; an
    output that is not valid cannot hit within any budget, so it stays measurable. ``assessable`` is a
    completed scan with a resolved outcome for the target: a confirmed hit, or no hit with no pending
    match and resolved bundles. ``random`` is the random-order expectation per budget for an unranked
    valid output with resolved bundles, and ``random_pending`` marks one whose bundles are unresolved.
    """
    observed = observation.observed
    failure = {"detected": False, "rank": None, "measurable": True, "completed": False, "assessable": False,
               "unscored": False, "random": None, "random_pending": False}
    if observed is None:
        return failure
    rows = {row["target_id"]: row for row in observed["targets"]}
    scored = [rows[target_id] for target_id in target_ids if target_id in rows]
    if not scored:
        return {**failure, "unscored": True}
    detected = any(row["detected"] for row in scored)
    ranks = [row["first_hit_rank"] for row in scored if row["first_hit_rank"] is not None]
    valid = observed["valid_positive_output"]
    pending = any(row["unresolved_match"] for row in scored)
    random = None
    if valid and observed["random_order"] is not None:
        delivered = observed["claims"]["records"]
        hits = sum(row["hit_claims"] for row in scored)
        random = {budget: _random_order_expectation(delivered, hits, budget) for budget in budgets}
    completed, resolved = observed["completed"], observed["bundles_resolved"]
    return {"detected": detected, "rank": min(ranks) if ranks else None,
            "measurable": not valid or observed["budget_measurable"], "completed": completed,
            "assessable": completed and (detected or (not pending and resolved)),
            "unscored": False, "random": random,
            "random_pending": valid and observed["ranking"] == "unranked" and not resolved}


def _control_outcome(observation: _Observation, control_ids: tuple[str, ...]) -> dict:
    """What one observation establishes about one canonical control planned on its input.

    A confirmed false allegation about any of the input's records of the control is one; the control
    is resolved quiet only when every record of it is. Completion and resolution follow
    :func:`scaneval.scoring.observe`: only a successful scan completes, and a failure resolves nothing.
    """
    observed = observation.observed
    empty = {"completed": False, "resolved": False, "false_allegation": False,
             "observed_false_allegation": False, "unscored": False}
    if observed is None:
        return empty
    rows = {row["control_id"]: row for row in observed["controls"]}
    scored = [rows[control_id] for control_id in control_ids if control_id in rows]
    if not scored:
        return {**empty, "unscored": True}
    false = any(row["false_allegation"] for row in scored)
    return {"completed": observed["completed"], "resolved": false or all(row["resolved"] for row in scored),
            "false_allegation": false,
            "observed_false_allegation": any(row["observed_false_allegation"] for row in scored),
            "unscored": False}


# --- one system in one view ---------------------------------------------------------------------


Key = tuple[str, str]
Units = dict[str, list[tuple[Key, int, list[dict]]]]


@dataclass
class _Frame:
    """What one system was assigned in one (mode, profile) view, across every run that schedules it.

    ``inputs`` lists every assigned (run id, input id), planned or not. ``targets`` and ``controls``
    (per control class) map each canonical id to its positive inputs with the planned record ids on
    each, from frozen plans only; ``pairs`` maps a canonical target to its frozen pairs.
    """

    mode: str
    profile: str
    system_id: str
    inputs: list[Key]
    targets: dict[str, list[tuple[Key, tuple[str, ...]]]]
    controls: dict[str, dict[str, list[tuple[Key, tuple[str, ...]]]]]
    pairs: dict[str, list[tuple[str, dict]]]


def _frame(corpus: _Corpus, mode: str, profile: str, system_id: str) -> _Frame:
    """Collect one system's assignments in one view from every run that schedules the system."""
    inputs: list[Key] = []
    targets: dict[str, list] = defaultdict(list)
    controls: dict[str, dict[str, list]] = {name: defaultdict(list) for name in CONTROL_CLASSES}
    pairs: dict[str, list] = defaultdict(list)
    for run in corpus.runs:
        if system_id not in run.system_ids:
            continue
        in_view = set()
        for row in sorted(run.schedule["inputs"], key=lambda item: item["input_id"]):
            if (row["mode"], row["profile"]) != (mode, profile):
                continue
            key = (run.run_id, row["input_id"])
            inputs.append(key)
            in_view.add(row["input_id"])
            plan = row["plan"]
            if plan["state"] != "frozen":
                continue
            grouped: dict[str, list[str]] = defaultdict(list)
            for target in plan["targets"]:
                grouped[target["canonical_id"]].append(target["target_id"])
            for canonical, ids in grouped.items():
                targets[canonical].append((key, tuple(sorted(ids))))
            for name, types in CONTROL_CLASSES.items():
                grouped = defaultdict(list)
                for control in plan["controls"]:
                    if control["type"] in types:
                        grouped[control["canonical_id"]].append(control["control_id"])
                for canonical, ids in grouped.items():
                    controls[name][canonical].append((key, tuple(sorted(ids))))
        for pair in run.schedule["pairs"]:
            if pair["vulnerable_input_id"] in in_view:
                pairs[pair["canonical_id"]].append((run.run_id, pair))
    return _Frame(mode, profile, system_id, inputs,
                  {canonical: targets[canonical] for canonical in sorted(targets)},
                  {name: {canonical: found[canonical] for canonical in sorted(found)}
                   for name, found in controls.items()},
                  {canonical: pairs[canonical] for canonical in sorted(pairs)})


def _in_slice(attributes: dict, slice_: tuple[str, str | None]) -> bool:
    """Whether an item with these project and workload attributes belongs to *slice_*."""
    dimension, value = slice_
    return dimension == "all" or attributes[dimension] == value


def _slice_key(slice_: tuple[str, str | None]) -> str:
    """``all``, ``project=<name>``, or ``workload=<name>``: the name a slice's bootstrap stream carries."""
    return "all" if slice_[0] == "all" else f"{slice_[0]}={slice_[1]}"


def _mean_per_item(units: Units, value: Callable[[dict], Any]) -> dict[str, Fraction]:
    """Per canonical item, ``Σ_m ρ_m (1/k_m) Σ_r value``: equal weight per positive input, then run."""
    return {canonical: sum((Fraction(value(outcome)) / (len(instances) * repetitions)
                            for _key, repetitions, outcomes in instances for outcome in outcomes),
                           Fraction(0))
            for canonical, instances in units.items()}


def _total(weights: dict[str, Fraction], means: dict[str, Fraction]) -> Fraction:
    """``Σ_i w_i m_i`` over the weighted items."""
    return sum((weights[key] * means[key] for key in sorted(weights)), Fraction(0))


def _variability(weights: dict[str, Fraction], units: Units, value: Callable[[dict], Any]) -> dict:
    """``Σ_i w_i² Σ_m ρ_im² v_im / k_m`` with ``v = p(1−p)k/(k−1)``, over inputs run at least twice.

    ``partial`` says some weight sits on inputs run once, whose run noise cannot be estimated and is
    not included (``uncovered_mass``); ``unavailable`` says every input ran once. Targets are treated
    as independent, which targets sharing one scan are not, so this is conditional run noise only.
    """
    terms: list[Fraction] = []
    uncovered = Fraction(0)
    for canonical in sorted(weights):
        weight = weights[canonical]
        share = Fraction(1, len(units[canonical]))
        for _key, repetitions, outcomes in units[canonical]:
            if repetitions < 2:
                uncovered += weight * share
                continue
            p = Fraction(sum(bool(value(outcome)) for outcome in outcomes), repetitions)
            estimate = p * (1 - p) * repetitions / (repetitions - 1)
            terms.append(weight * weight * share * share * estimate / repetitions)
    if not terms:
        return {"state": "unavailable", "variance": None, "standard_error": None, "uncovered_mass": None}
    variance = sum(terms, Fraction(0))
    return {"state": "partial" if uncovered > 0 else "ok", "variance": float(variance),
            "standard_error": math.sqrt(variance), "uncovered_mass": float(uncovered)}


def _pairs(weights: dict[str, Fraction], pair_units: dict[str, list[list[dict]]],
           cluster_of: Callable[[str], str], resampler: _Resampler | None,
           uncertainty: dict) -> tuple[dict, _Ratio | None, Fraction]:
    """Pair correctness over the slice's targets that have frozen pairs, its ratio, and its availability.

    Pair weights are the target weights renormalized over those targets; within a target every frozen
    pair weighs the same and every repetition pair within it too. Only confirmed success counts: both
    observations completed with resolved assessments, the target detected, and no false allegation
    in the fixed state. Availability is the target weight that has a pair at all.
    """
    pairable = {canonical: weights[canonical] for canonical in weights if canonical in pair_units}
    availability = sum(pairable.values(), Fraction(0))
    outcomes = [outcome for canonical in pairable for pair in pair_units[canonical] for outcome in pair]
    counts = {name: sum(outcome["outcome"] == name for outcome in outcomes) for name in PAIR_OUTCOMES}
    block = {"pairable_targets": len(pairable), "availability": float(availability), "value": None,
             "interval": _unavailable_interval(), "assessable_mass": None, "repetition_pairs": len(outcomes),
             "resolved_pairs": sum(outcome["resolved"] for outcome in outcomes),
             "outcomes": {name: {"pairs": counts[name], "mass": None} for name in PAIR_OUTCOMES}}
    if not pairable or availability <= 0:
        return block, None, availability

    def per_target(value: Callable[[dict], Any]) -> dict[str, Fraction]:
        return {canonical: sum((Fraction(value(outcome)) / (len(pair_units[canonical]) * len(pair))
                                for pair in pair_units[canonical] for outcome in pair), Fraction(0))
                for canonical in pairable}

    ones = {canonical: Fraction(1) for canonical in pairable}
    correctness = _ratio(pairable, per_target(lambda outcome: outcome["success"]), ones, cluster_of)
    block["value"] = _float(correctness.value)
    block["interval"] = _bootstrap([correctness], _only, resampler, uncertainty)
    block["assessable_mass"] = _float(
        _ratio(pairable, per_target(lambda outcome: outcome["resolved"]), ones, cluster_of).value)
    for name in PAIR_OUTCOMES:
        found = per_target(lambda outcome, name=name: outcome["outcome"] == name)
        block["outcomes"][name]["mass"] = _float(_ratio(pairable, found, ones, cluster_of).value)
    return block, correctness, availability


def _leave_one_project_out(corpus: _Corpus, units: Units, weighting: str, policy: dict) -> dict:
    """Full-output recall with each project's targets left out in turn, weights renormalized."""
    projects = sorted({corpus.targets[canonical]["project"] for canonical in units})
    empty = {"values": [], "min": None, "max": None}
    if len(projects) < 2:
        return {"state": "unavailable", "reason": "fewer than two projects carry targets in this slice",
                **empty}
    if len(projects) >= LOPO_PROJECT_LIMIT:
        reason = (f"{len(projects)} projects; leave-one-project-out is shown while there are fewer than "
                  f"{LOPO_PROJECT_LIMIT}")
        return {"state": "not_computed", "reason": reason, **empty}
    values = []
    for project in projects:
        remaining = {canonical: instances for canonical, instances in units.items()
                     if corpus.targets[canonical]["project"] != project}
        weights, _reason, _notes = _weights({canonical: corpus.targets[canonical] for canonical in remaining},
                                            weighting, policy, whole_view=False)
        value = None
        if weights:
            value = _total(weights, _mean_per_item(remaining, lambda outcome: outcome["detected"]))
        values.append({"left_out": project, "full_output_recall": _float(value)})
    present = [row["full_output_recall"] for row in values if row["full_output_recall"] is not None]
    return {"state": "ok", "reason": None, "values": values, "min": min(present) if present else None,
            "max": max(present) if present else None}


def _detection(corpus: _Corpus, units: Units, pair_units: dict, slice_: tuple[str, str | None],
               weighting: str, policy: dict, budgets: list[int], resampler: _Resampler | None,
               pair_resampler: _Resampler | None) -> tuple[dict, dict[str, _Ratio], dict[str, Fraction]]:
    """Every target metric of one slice under one weighting, the ratios a comparison pairs, and masses.

    Full-output recall counts a confirmed hit from valid output whether or not the output is ranked.
    Native recall@B needs a measured first-hit rank; it is null whenever any weighted observation's
    budget position is unmeasurable, and its lower bound then counts those observations as misses.
    Recall intervals draw from *resampler*; pair correctness draws from *pair_resampler*.
    """
    uncertainty = policy["uncertainty"]
    block: dict[str, Any] = {
        "weighting": weighting, "state": "unavailable", "reason": None, "notes": [],
        "full_output_recall": None, "recall_at_budget": [], "random_order_diagnostic": None, "coverage": None,
        "pairs": None, "run_variability": None, "leave_one_project_out": None}
    if not units:
        return {**block, "reason": "this slice has no target planned before execution"}, {}, {}
    attributes = {canonical: corpus.targets[canonical] for canonical in units}
    weights, reason, notes = _weights(attributes, weighting, policy, whole_view=slice_[0] == "all")
    if weights is None:
        return {**block, "reason": reason, "notes": notes}, {}, {}

    def cluster_of(canonical: str) -> str:
        return attributes[canonical][uncertainty["cluster_by"]]

    def mean(value: Callable[[dict], Any]) -> _Ratio:
        return _ratio(weights, _mean_per_item(units, value), None, cluster_of)

    def mass(value: Callable[[dict], Any]) -> Fraction:
        return _total(weights, _mean_per_item(units, value))

    def within(budget: int) -> Callable[[dict], bool]:
        return lambda outcome: outcome["rank"] is not None and outcome["rank"] <= budget

    parts: dict[str, _Ratio] = {}
    full = mean(lambda outcome: outcome["detected"])
    parts["full_output_recall"] = full
    unmeasured = mass(lambda outcome: not outcome["measurable"])
    budget_rows, budget_variability = [], []
    for budget in budgets:
        lower = mean(within(budget))
        value = lower.value if unmeasured == 0 else None
        parts[f"recall_at_budget_lower/{budget}"] = lower
        if value is not None:
            parts[f"recall_at_budget/{budget}"] = lower
        interval = (_bootstrap([lower], _only, resampler, uncertainty) if value is not None
                    else _unavailable_interval())
        budget_rows.append({"budget": budget, "value": _float(value), "lower_bound": _float(lower.value),
                            "unmeasured_mass": float(unmeasured), "interval": interval})
        budget_variability.append({"budget": budget, **(
            _variability(weights, units, within(budget)) if value is not None else
            {"state": "unavailable", "variance": None, "standard_error": None, "uncovered_mass": None})})

    observed_mass = _mean_per_item(units, lambda outcome: outcome["random"] is not None)
    expected = []
    for budget in budgets:
        numerators = _mean_per_item(units, lambda outcome, budget=budget: (
            outcome["random"][budget] if outcome["random"] is not None else 0))
        expected.append({"budget": budget,
                         "value": _float(_ratio(weights, numerators, observed_mass, cluster_of).value)})

    outcomes = [outcome for instances in units.values() for _key, _k, found in instances for outcome in found]
    pair_block, correctness, availability = _pairs(weights, pair_units, cluster_of, pair_resampler,
                                                   uncertainty)
    if correctness is not None:
        parts["pair_correctness"] = correctness
    completed = mass(lambda outcome: outcome["completed"])
    assessable = mass(lambda outcome: outcome["assessable"])
    block.update({
        "state": "ok", "notes": notes,
        "full_output_recall": {"value": _float(full.value),
                               "interval": _bootstrap([full], _only, resampler, uncertainty)},
        "recall_at_budget": budget_rows,
        "random_order_diagnostic": {
            "label": RANDOM_ORDER_LABEL,
            "observation_mass": float(mass(lambda outcome: outcome["random"] is not None)),
            "pending_mass": float(mass(lambda outcome: outcome["random_pending"])),
            "expected_recall": expected},
        "coverage": {
            "target_observations": len(outcomes),
            "completed": sum(outcome["completed"] for outcome in outcomes),
            "assessable": sum(outcome["assessable"] for outcome in outcomes),
            "detected": sum(outcome["detected"] for outcome in outcomes),
            "unscored": sum(outcome["unscored"] for outcome in outcomes),
            "completed_mass": float(completed), "assessable_mass": float(assessable),
            "unscored_mass": float(mass(lambda outcome: outcome["unscored"]))},
        "pairs": pair_block,
        "run_variability": {
            "label": RUN_VARIABILITY_LABEL,
            "full_output_recall": _variability(weights, units, lambda outcome: outcome["detected"]),
            "recall_at_budget": budget_variability},
        "leave_one_project_out": _leave_one_project_out(corpus, units, weighting, policy),
    })
    return block, parts, {"pair_availability": availability, "completed_mass": completed,
                          "assessable_mass": assessable}


def _controls(corpus: _Corpus, units: Units, slice_: tuple[str, str | None], policy: dict,
              resampler: _Resampler | None) -> tuple[dict, dict[str, _Ratio], dict[str, Fraction]]:
    """One control class in one slice: A, C, E masses, the resolved rate, and the completed bounds.

    ``A`` is the resolved mass, ``C`` the completed mass, and ``E`` the confirmed false-allegation
    mass, under equal weight per canonical control and, within it, per input and then per run. The
    resolved rate ``E/A`` is null when ``A`` is 0 and the completed bounds ``[E/C, (E+C−A)/C]`` are null
    when ``C`` is 0: no eligible, completed, or resolved control is never read as a rate of zero.
    """
    uncertainty = policy["uncertainty"]
    outcomes = [outcome for instances in units.values() for _key, _k, found in instances for outcome in found]
    block: dict[str, Any] = {
        "state": "ok", "reason": None, "notes": [], "canonical_controls": len(units),
        "observations": len(outcomes),
        "completed": sum(outcome["completed"] for outcome in outcomes),
        "resolved": sum(outcome["resolved"] for outcome in outcomes),
        "unresolved": sum(outcome["completed"] and not outcome["resolved"] for outcome in outcomes),
        "false_allegations": sum(outcome["false_allegation"] for outcome in outcomes),
        "observed_false_allegations": sum(outcome["observed_false_allegation"] for outcome in outcomes),
        "unscored": sum(outcome["unscored"] for outcome in outcomes),
        "completed_mass": None, "assessable_mass": None, "false_allegation_mass": None,
        "resolved_rate": {"value": None, "interval": _unavailable_interval()},
        "completed_lower": None, "completed_upper": {"value": None, "interval": _unavailable_interval()}}
    if not units:
        return block, {}, {}
    attributes = {canonical: corpus.controls[canonical] for canonical in units}
    weights, reason, notes = _weights(attributes, "equal_target", policy, whole_view=slice_[0] == "all")
    if weights is None:
        return {**block, "state": "unavailable", "reason": reason, "notes": notes}, {}, {}

    def cluster_of(canonical: str) -> str:
        return attributes[canonical][uncertainty["cluster_by"]]

    resolved = _mean_per_item(units, lambda outcome: outcome["resolved"])
    completed = _mean_per_item(units, lambda outcome: outcome["completed"])
    false = _mean_per_item(units, lambda outcome: outcome["resolved"] and outcome["false_allegation"])
    upper_numerators = _mean_per_item(units, lambda outcome: (
        (outcome["resolved"] and outcome["false_allegation"]) + outcome["completed"] - outcome["resolved"]))
    rate = _ratio(weights, false, resolved, cluster_of)
    upper = _ratio(weights, upper_numerators, completed, cluster_of)
    lower = _ratio(weights, false, completed, cluster_of)
    completed_mass, assessable_mass = _total(weights, completed), _total(weights, resolved)
    block.update({
        "notes": notes, "completed_mass": float(completed_mass), "assessable_mass": float(assessable_mass),
        "false_allegation_mass": float(_total(weights, false)),
        "resolved_rate": {"value": _float(rate.value),
                          "interval": _bootstrap([rate], _only, resampler, uncertainty)},
        "completed_lower": _float(lower.value),
        "completed_upper": {"value": _float(upper.value),
                            "interval": _bootstrap([upper], _only, resampler, uncertainty)}})
    return (block, {"resolved_rate": rate, "completed_upper": upper},
            {"completed_mass": completed_mass, "assessable_mass": assessable_mass})


def _completion(corpus: _Corpus, keys: list[Key],
                observations: list[_Observation]) -> tuple[dict, Fraction | None]:
    """Equal weight over assigned inputs, each averaged over its runs; only a successful scan completes."""
    statuses = Counter(observation.status for observation in observations)
    failures = Counter(observation.reason for observation in observations if observation.reason)
    by_input: dict[Key, list[_Observation]] = defaultdict(list)
    for observation in observations:
        by_input[(observation.run_id, observation.input_id)].append(observation)
    value = None
    if keys:
        value = sum((Fraction(observation.status == "success", len(keys) * corpus.repetitions(key[0]))
                     for key in keys for observation in by_input[key]), Fraction(0))
    return ({"value": _float(value), "inputs": len(keys), "assignments": len(observations),
             "statuses": {status: statuses[status] for status in STATUSES},
             "failures": {reason: failures[reason] for reason in FAILURE_REASONS}}, value)


def _claims(observations: list[_Observation]) -> dict:
    """Claim volume summed over the bundles read, each bundle once."""
    bundles = [observation.observed for observation in observations if observation.observed is not None]
    volume = [bundle["claims"] for bundle in bundles]
    return {"bundles": len(bundles), "assignments": len(observations),
            "records": sum(item["records"] for item in volume),
            "unique": sum(item["unique"] for item in volume),
            "duplicate_copies": sum(item["duplicate_copies"] for item in volume),
            "delivered": sum(item["delivered"] for item in volume if item["delivered"] is not None),
            "bundles_with_unresolved_delivery": sum(item["delivered"] is None for item in volume),
            "unmatched_unique": sum(item["unmatched_unique"] for item in volume),
            "pending_matching": sum(item["pending_matching"] for item in volume)}


def _usage(observations: list[_Observation]) -> dict:
    """Reported usage summed over bundles, each executed scan once however many targets it covers.

    An unknown value (a null or absent wall time or cost) is counted as unknown and never summed as 0,
    and a sum over no known value is null. These are the scanners' own figures, summed as floats.
    """
    usages = [observation.observed["usage"] for observation in observations
              if observation.observed is not None]

    def known(key: str) -> list:
        return [usage[key] for usage in usages if usage.get(key) is not None]

    wall, setup, cost = known("wall_seconds"), known("setup_seconds"), known("cost_usd")
    input_tokens, output_tokens = known("input_tokens"), known("output_tokens")
    return {"bundles": len(usages),
            "wall_seconds": {"known_sum": math.fsum(wall) if wall else None, "known": len(wall),
                             "unknown": len(usages) - len(wall)},
            "setup_seconds": {"sum": math.fsum(setup) if setup else None, "reported": len(setup)},
            "input_tokens": {"sum": sum(input_tokens) if input_tokens else None,
                             "reported": len(input_tokens)},
            "output_tokens": {"sum": sum(output_tokens) if output_tokens else None,
                              "reported": len(output_tokens)},
            "cost_usd": {"known_sum": math.fsum(cost) if cost else None, "known": len(cost),
                         "unknown": len(usages) - len(cost),
                         "coverage": _float(Fraction(len(cost), len(usages))) if usages else None}}


@dataclass
class _SliceResult:
    """One slice of one system: its report block, what a comparison pairs, and its draws.

    ``parts`` are the ratios paired intervals are drawn for, and ``exact`` the masses whose differences
    a comparison reports without an interval, both kept exact until the difference is taken; each is
    keyed first by its block, ``detection`` or ``controls``. ``resamplers`` holds the draws of each
    resampling family, ``targets``, ``pairs``, and ``controls`` (:func:`_family`).
    """

    slice_: tuple[str, str | None]
    block: dict
    parts: dict[tuple[str, ...], _Ratio]
    exact: dict[tuple[str, ...], Fraction | None]
    resamplers: dict[str, _Resampler | None]


@dataclass
class _SystemResult:
    """One system in one view: its report block, its slices, and the evidence scopes it observed."""

    frame: _Frame
    block: dict
    slices: list[_SliceResult]
    scopes: set[str]


class _Context:
    """One aggregation: the corpus, the policy, and the replicate draws each metric family shares."""

    def __init__(self, corpus: _Corpus, policy: dict) -> None:
        self.corpus = corpus
        self.policy = policy
        self._resamplers: dict[tuple[str, tuple[str, ...]], _Resampler] = {}

    def resampler(self, mode: str, profile: str, slice_: tuple[str, str | None], family: str,
                  universe: list[str]) -> _Resampler | None:
        """The draws of one family of one slice, labelled ``bootstrap/<mode>/<profile>/<slice>/<family>``.

        ``targets`` draws the clusters that carry the slice's targets and serves recall and recall@B;
        ``pairs`` draws the clusters that carry a target with a frozen pair and serves pair
        correctness; ``controls`` draws the clusters that carry its controls and serves every control
        metric. Each family's clusters are fixed by the schedules, never by an outcome, and resampling
        each over its own keeps every replicate a full cluster bootstrap of that family: a project with
        controls and no target never takes a draw from recall. Two systems whose slices resample the
        same clusters read the same draws, which is what makes a comparison's intervals paired.
        ``None`` when there is no cluster.
        """
        if not universe:
            return None
        label = f"bootstrap/{mode}/{profile}/{_slice_key(slice_)}/{family}"
        key = (label, tuple(universe))
        if key not in self._resamplers:
            self._resamplers[key] = _Resampler(universe, label, self.policy["uncertainty"])
        return self._resamplers[key]


def _observations_of(corpus: _Corpus, system_id: str, keys: Iterable[Key]) -> list[_Observation]:
    """Every repetition of every input in *keys* for one system, in input order."""
    return [corpus.observations[(run_id, input_id, system_id, repetition)]
            for run_id, input_id in keys for repetition in range(1, corpus.repetitions(run_id) + 1)]


def _slices(corpus: _Corpus, frame: _Frame) -> list[tuple[str, str | None]]:
    """The whole view, then each project, then each workload its targets, controls, or inputs carry."""
    groups = [corpus.targets[canonical] for canonical in frame.targets]
    groups += [corpus.controls[canonical] for found in frame.controls.values() for canonical in found]
    groups += [corpus.inputs[key] for key in frame.inputs]
    projects = sorted({group["project"] for group in groups})
    workloads = sorted({group["workload"] for group in groups})
    return ([("all", None)] + [("project", name) for name in projects]
            + [("workload", name) for name in workloads])


def _pair_outcomes(frame: _Frame, observation: Callable[[Key, int], _Observation],
                   budgets: list[int]) -> dict[str, list[list[dict]]]:
    """For each canonical target, the outcome of every repetition pair of every frozen pair it has.

    A pair is resolved when the vulnerable observation has a resolved outcome for the target and the
    fixed observation a resolved assessment of the control; only a resolved pair has an outcome.
    """
    pair_units: dict[str, list[list[dict]]] = {}
    for canonical, entries in frame.pairs.items():
        pair_units[canonical] = []
        for run_id, pair in entries:
            vulnerable = (run_id, pair["vulnerable_input_id"])
            target_ids = next(ids for key, ids in frame.targets[canonical] if key == vulnerable)
            outcomes = []
            for left, right in pair["repetition_pairs"]:
                hit = _target_outcome(observation(vulnerable, left), target_ids, budgets)
                fixed = _control_outcome(observation((run_id, pair["fixed_input_id"]), right),
                                         (pair["control_id"],))
                resolved = hit["assessable"] and fixed["resolved"]
                outcome = None
                if resolved:
                    outcome = {(True, False): "correct", (True, True): "both_flagged",
                               (False, False): "both_silent",
                               (False, True): "reversed"}[(hit["detected"], fixed["false_allegation"])]
                outcomes.append({"resolved": resolved, "outcome": outcome,
                                 "success": resolved and hit["detected"] and not fixed["false_allegation"]})
            pair_units[canonical].append(outcomes)
    return pair_units


def _evaluate_slice(context: _Context, frame: _Frame, slice_: tuple[str, str | None], units: Units,
                    control_units: dict[str, Units], pair_units: dict[str, list[list[dict]]],
                    budgets: list[int]) -> _SliceResult:
    """Every block of one slice of one system: detection per weighting, controls, and operations."""
    corpus, policy = context.corpus, context.policy
    cluster_by = policy["uncertainty"]["cluster_by"]
    slice_units = {canonical: rows for canonical, rows in units.items()
                   if _in_slice(corpus.targets[canonical], slice_)}
    slice_controls = {name: {canonical: rows for canonical, rows in found.items()
                             if _in_slice(corpus.controls[canonical], slice_)}
                      for name, found in control_units.items()}
    slice_pairs = {canonical: rows for canonical, rows in pair_units.items() if canonical in slice_units}
    keys = [key for key in frame.inputs if _in_slice(corpus.inputs[key], slice_)]
    clusters = {
        "targets": sorted({corpus.targets[canonical][cluster_by] for canonical in slice_units}),
        "pairs": sorted({corpus.targets[canonical][cluster_by] for canonical in slice_pairs}),
        "controls": sorted({corpus.controls[canonical][cluster_by]
                            for found in slice_controls.values() for canonical in found})}
    resamplers = {family: context.resampler(frame.mode, frame.profile, slice_, family, universe)
                  for family, universe in clusters.items()}
    parts: dict[tuple[str, ...], _Ratio] = {}
    exact: dict[tuple[str, ...], Fraction | None] = {}
    detection = []
    for weighting in policy["views"]:
        block, found, masses = _detection(corpus, slice_units, slice_pairs, slice_, weighting, policy,
                                          budgets, resamplers["targets"], resamplers["pairs"])
        detection.append(block)
        parts.update({("detection", weighting, name): ratio for name, ratio in found.items()})
        exact.update({("detection", weighting, name): value for name, value in masses.items()})
    controls = {}
    for name in CONTROL_CLASSES:
        block, found, masses = _controls(corpus, slice_controls[name], slice_, policy,
                                         resamplers["controls"])
        controls[name] = block
        parts.update({("controls", name, metric): ratio for metric, ratio in found.items()})
        exact.update({("controls", name, metric): value for metric, value in masses.items()})
    observations = _observations_of(corpus, frame.system_id, keys)
    completion, exact[("completion",)] = _completion(corpus, keys, observations)
    canonical_controls = {canonical for found in slice_controls.values() for canonical in found}
    block = {"slice": {"dimension": slice_[0], "value": slice_[1]},
             "canonical_targets": len(slice_units), "canonical_controls": len(canonical_controls),
             "inputs": len(keys),
             "clusters": {family: len(universe) for family, universe in clusters.items()},
             "detection": detection, "controls": controls,
             "completion": completion, "claims": _claims(observations), "usage": _usage(observations)}
    return _SliceResult(slice_, block, parts, exact, resamplers)


def _first_hit_ranks(units: Units) -> dict:
    """Unweighted target observations by first accepted rank, detections without one, and misses."""
    ranks: Counter = Counter()
    detected_without_rank = not_detected = 0
    for instances in units.values():
        for _key, _k, outcomes in instances:
            for outcome in outcomes:
                if outcome["rank"] is not None:
                    ranks[outcome["rank"]] += 1
                elif outcome["detected"]:
                    detected_without_rank += 1
                else:
                    not_detected += 1
    return {"ranks": [{"rank": rank, "target_observations": ranks[rank]} for rank in sorted(ranks)],
            "detected_without_rank": detected_without_rank, "not_detected": not_detected}


def _evaluate_system(context: _Context, mode: str, profile: str, system_id: str,
                     budgets: list[int]) -> _SystemResult:
    """Every block of one system in one view: what happened to its assignments, and each slice."""
    corpus = context.corpus
    frame = _frame(corpus, mode, profile, system_id)

    def observation(key: Key, repetition: int) -> _Observation:
        return corpus.observations[(key[0], key[1], system_id, repetition)]

    def instances_of(found: list[tuple[Key, tuple[str, ...]]], outcome: Callable) -> list:
        rows = []
        for key, ids in found:
            repetitions = range(1, corpus.repetitions(key[0]) + 1)
            rows.append((key, len(repetitions), [outcome(observation(key, r), ids) for r in repetitions]))
        return rows

    units = {canonical: instances_of(found, lambda item, ids: _target_outcome(item, ids, budgets))
             for canonical, found in frame.targets.items()}
    control_units = {name: {canonical: instances_of(found, _control_outcome)
                            for canonical, found in controls.items()}
                     for name, controls in frame.controls.items()}
    pair_units = _pair_outcomes(frame, observation, budgets)
    slices = [_evaluate_slice(context, frame, slice_, units, control_units, pair_units, budgets)
              for slice_ in _slices(corpus, frame)]

    everything = _observations_of(corpus, system_id, frame.inputs)
    planned = [item for item in everything
               if corpus.inputs[(item.run_id, item.input_id)]["plan"]["state"] == "frozen"]
    scopes = {item.scope for item in planned if item.scope is not None}
    statuses = Counter(item.status for item in everything)
    failures = Counter(item.reason for item in everything if item.reason)
    review_states = Counter(item.review_state for item in everything if item.review_state)
    block = {
        "system_id": system_id,
        "evidence_scope": _scope(scopes),
        "observations": {
            "assignments": len(everything),
            "bundles": sum(item.observed is not None for item in everything),
            "statuses": {status: statuses[status] for status in STATUSES},
            "failures": {reason: failures[reason] for reason in FAILURE_REASONS},
            "failed_assignments": [
                {"run_id": item.run_id, "assignment_id": item.assignment_id, "reason": item.reason}
                for item in everything if item.reason],
            "review_states": {state: review_states[state] for state in REVIEW_STATES},
            "unscored_items": sum(item.unscored for item in everything),
            "unregistered_items": sum(item.unregistered for item in everything)},
        "first_hit_ranks": _first_hit_ranks(units),
        "slices": [result.block for result in slices],
    }
    return _SystemResult(frame, block, slices, scopes)


def _scope(scopes: set[str]) -> str:
    """Reviewed only when every planned observation is reviewed evidence; diagnostic only when all are."""
    if scopes == {"reviewed"}:
        return "reviewed"
    if scopes == {"diagnostic"}:
        return "diagnostic"
    return "draft"


def _refuse_mixed_scopes(mode: str, profile: str, results: Iterable[_SystemResult]) -> None:
    """Refuse a view whose observations mix diagnostic fixtures with draft or reviewed evidence."""
    scopes = set().union(*(result.scopes for result in results))
    others = sorted(scopes - {"diagnostic"})
    if "diagnostic" in scopes and others:
        raise ContractError(f"view {mode}/{profile} mixes diagnostic fixture evidence with "
                            f"{' and '.join(others)} evidence; aggregate diagnostic fixtures on their own")


# --- views and the report -----------------------------------------------------------------------


def _view_keys(corpus: _Corpus, system_ids: Iterable[str]) -> list[tuple[str, str]]:
    """Every (mode, profile) an input assigned to one of *system_ids* has, sorted."""
    wanted = set(system_ids)
    return sorted({(row["mode"], row["profile"]) for run in corpus.runs if wanted & set(run.system_ids)
                   for row in run.schedule["inputs"]})


def _systems_in_view(corpus: _Corpus, mode: str, profile: str) -> list[str]:
    """The systems assigned at least one input of one view, sorted."""
    return sorted({system_id for run in corpus.runs for system_id in run.system_ids
                   if any((row["mode"], row["profile"]) == (mode, profile)
                          for row in run.schedule["inputs"])})


def _view_facts(corpus: _Corpus, mode: str, profile: str, system_ids: Iterable[str]) -> dict:
    """What the schedules of the runs assigning *system_ids* froze for one view; no outcome is read."""
    wanted = set(system_ids)
    rows = [(run, row) for run in corpus.runs if wanted & set(run.system_ids)
            for row in run.schedule["inputs"] if (row["mode"], row["profile"]) == (mode, profile)]
    frozen = [row for _run, row in rows if row["plan"]["state"] == "frozen"]
    targets = {target["canonical_id"] for row in frozen for target in row["plan"]["targets"]}
    controls = {control["canonical_id"] for row in frozen for control in row["plan"]["controls"]}
    per_input = Counter(len(row["plan"]["targets"]) for row in frozen)
    projects = {row["project"] for _run, row in rows} | {corpus.targets[key]["project"] for key in targets}
    workloads = {row["workload"] for _run, row in rows} | {corpus.targets[key]["workload"] for key in targets}
    return {
        "inputs": len(rows), "canonical_targets": len(targets), "canonical_controls": len(controls),
        "projects": sorted(projects), "workloads": sorted(workloads),
        "review_budgets": sorted({budget for row in frozen for budget in row["plan"]["review_budgets"]}),
        "targets_per_input": [{"targets": count, "inputs": per_input[count]} for count in sorted(per_input)],
        "inputs_without_frozen_plan": [
            {"run_id": run.run_id, "input_id": row["input_id"], "reason": row["plan"]["reason"]}
            for run, row in rows if row["plan"]["state"] != "frozen"],
    }


def _view_warnings(facts: dict, results: Sequence[_SystemResult]) -> list[str]:
    """What a reader of one view must not miss: unplanned inputs, unscored items, failures, scope."""
    warnings = []
    unplanned = len(facts["inputs_without_frozen_plan"])
    if unplanned:
        warnings.append(f"{unplanned} input(s) had no plan frozen before execution and take no part in any "
                        "target or control metric; their assignments still count toward completion, "
                        "claims, and usage")
    for result in results:
        system_id = result.block["system_id"]
        observations = result.block["observations"]
        if observations["unscored_items"]:
            warnings.append(f"{system_id}: {observations['unscored_items']} item observation(s) frozen in "
                            "the schedule are absent from their bundle's plan and are scored as misses")
        if observations["unregistered_items"]:
            warnings.append(f"{system_id}: {observations['unregistered_items']} item(s) a bundle's plan "
                            "adds beyond the frozen schedule are ignored")
        failed = sum(observations["failures"].values())
        if failed:
            warnings.append(f"{system_id}: {failed} assignment(s) produced no usable bundle and stay in "
                            "every denominator as failures")
        if result.block["evidence_scope"] != "reviewed":
            warnings.append(f"{system_id}: evidence scope is {result.block['evidence_scope']}, not "
                            "reviewed benchmark evidence")
    return warnings


def _run_row(corpus: _Corpus, run: _Run) -> dict:
    """One run as read: its hashes, its evidence digest, its failures, and its execution timing.

    The evidence digest hashes, per assignment in id order, its status, failure reason, review state,
    and the result, plan, and decisions digests of its bundle, so a report binds to exact evidence.
    """
    observations = [item for key, item in sorted(corpus.observations.items()) if key[0] == run.run_id]
    timings = [item.timing for item in observations if item.timing is not None]
    stamped = [(start, finish) for start, finish, _wall in timings
               if start is not None and finish is not None]
    elapsed = None
    if stamped:
        earliest = min(start for start, _finish in stamped)
        span = (max(finish for _start, finish in stamped) - earliest).total_seconds()
        elapsed = span if span >= 0 else None
    evidence = [{"assignment_id": item.assignment_id, "status": item.status, "reason": item.reason,
                 "review_state": item.review_state,
                 **({key: item.observed[key] for key in ("result_sha256", "plan_sha256", "decisions_sha256")}
                    if item.observed is not None else {})}
                for item in observations]
    failures = Counter(item.reason for item in observations if item.reason)
    summed = math.fsum(wall for _start, _finish, wall in timings) if timings else None
    return {
        "run_id": run.run_id, "status": run.manifest["status"], "created_at": run.schedule["created_at"],
        "manifest_sha256": canonical_sha256(run.manifest), "schedule_sha256": canonical_sha256(run.schedule),
        "config_sha256": run.schedule["config_sha256"], "evidence_sha256": canonical_sha256(evidence),
        "pack": run.schedule["pack"], "repetitions": run.repetitions, "inputs": len(run.schedule["inputs"]),
        "systems": list(run.system_ids), "assignments": len(observations),
        "bundles": sum(item.observed is not None for item in observations),
        "failures": {reason: failures[reason] for reason in FAILURE_REASONS},
        "timing": {"execution_records": len(timings),
                   "records_without_timestamps": len(timings) - len(stamped),
                   "elapsed_wall_seconds": elapsed, "summed_wall_seconds": summed},
    }


def _system_row(system_id: str, info: dict) -> dict:
    """What the schedules say one system is, and the runs that assigned it."""
    row = info["row"]
    return {"system_id": system_id, "adapter": row["adapter"], "model_id": row["model_id"],
            "model_revision": row["model_revision"], "config_sha256": row["config_sha256"],
            "network_policy": row["network_policy"], "execution": row["execution"],
            "runs": list(info["runs"])}


def _profile_coverage(corpus: _Corpus) -> list[dict]:
    """Per mode, the canonical targets each profile's view carries and those it lacks."""
    by_mode: dict[str, dict[str, dict]] = defaultdict(dict)
    for run in corpus.runs:
        for row in run.schedule["inputs"]:
            entry = by_mode[row["mode"]].setdefault(row["profile"],
                                                    {"inputs": 0, "targets": set(), "controls": set()})
            entry["inputs"] += 1
            if row["plan"]["state"] == "frozen":
                entry["targets"].update(target["canonical_id"] for target in row["plan"]["targets"])
                entry["controls"].update(control["canonical_id"] for control in row["plan"]["controls"])
    rows = []
    for mode in sorted(by_mode):
        profiles = dict(sorted(by_mode[mode].items()))
        every = set().union(*(entry["targets"] for entry in profiles.values()))
        common = set.intersection(*(entry["targets"] for entry in profiles.values()))
        rows.append({
            "mode": mode,
            "profiles": [{"profile": name, "inputs": entry["inputs"],
                          "canonical_targets": len(entry["targets"]),
                          "canonical_controls": len(entry["controls"])} for name, entry in profiles.items()],
            "common_canonical_targets": len(common),
            "unavailable": [{"profile": name, "canonical_target_ids": sorted(every - entry["targets"])}
                            for name, entry in profiles.items() if every - entry["targets"]]})
    return rows


def _notes(policy: dict) -> list[str]:
    """The statements every report carries about what its numbers are and are not."""
    uncertainty = policy["uncertainty"]
    clusters = uncertainty["cluster_by"]
    return [
        "Every scheduled assignment is an observation: a failed preparation, a skipped system, a missing "
        "manifest row, and a missing or unusable bundle detect nothing, complete nothing, and stay in every "
        "denominator.",
        f"Intervals resample {clusters} clusters with replacement ({uncertainty['replicates']} replicates, "
        f"seed {uncertainty['seed']}); they describe the observed {clusters}s, not software beyond them.",
        "Random-order expectations are diagnostics: not native recall@B and never a promotion metric.",
        "Run variability is conditional run noise under an independent-target approximation, not corpus "
        "uncertainty.",
        "Reviewed precision, review time, mixed-intent correctness, and freshness are not computed here, and "
        "nothing here is a promotion decision.",
    ]


def aggregate(run_dirs: Iterable[str | PathLike[str]], *, policy: dict | None = None) -> dict:
    """The validated aggregate report of *run_dirs* under *policy* (the built-in default when ``None``).

    Refused with :class:`ContractError`, before anything is computed: a directory that is not a 2.1 run
    directory, a run whose manifest, schedule, and configuration disagree, one run given twice, runs of
    different packs, a system id configured two ways, a canonical item planned under two groupings,
    and a view mixing diagnostic fixtures with other evidence. Nothing is written; the caller writes
    the returned document. The same directories and policy give the same document in any order.
    """
    context = _Context(_load_corpus(run_dirs), resolve_policy(policy))
    corpus = context.corpus
    views = []
    for mode, profile in _view_keys(corpus, corpus.systems):
        system_ids = _systems_in_view(corpus, mode, profile)
        facts = _view_facts(corpus, mode, profile, system_ids)
        results = [_evaluate_system(context, mode, profile, system_id, facts["review_budgets"])
                   for system_id in system_ids]
        _refuse_mixed_scopes(mode, profile, results)
        views.append({"mode": mode, "profile": profile,
                      "evidence_scope": _scope(set().union(*(result.scopes for result in results))),
                      **facts, "systems": [result.block for result in results],
                      "warnings": _view_warnings(facts, results)})
    report = {
        "schema_version": SCHEMA_VERSION, "evaluator_version": __version__,
        "policy": context.policy, "policy_sha256": canonical_sha256(context.policy),
        "runs": [_run_row(corpus, run) for run in corpus.runs],
        "systems": [_system_row(system_id, info) for system_id, info in corpus.systems.items()],
        "profile_coverage": _profile_coverage(corpus),
        "views": views,
        "notes": _notes(context.policy),
    }
    return validate_document(REPORT_KIND, report)


# --- paired comparison --------------------------------------------------------------------------


_CONTRACT_FIELDS = ("input_id", "mode", "profile", "snapshot_id", "change_set_id", "change_set", "blinding",
                    "declared_tree_hash", "project", "workload", "component_role")


def _contract(corpus: _Corpus, system_id: str) -> dict:
    """The frozen evaluation contract of one system: every input it was assigned, as frozen, and the pairs.

    Run ids are left out, so a baseline and a candidate scheduled by separate runs of one configuration
    have one contract. Plan notes are prose and are left out; everything a metric reads is kept.
    """
    inputs, pairs = [], []
    for run in corpus.runs:
        if system_id not in run.system_ids:
            continue
        for row in run.schedule["inputs"]:
            inputs.append({**{name: row[name] for name in _CONTRACT_FIELDS},
                           "plan": {key: value for key, value in row["plan"].items() if key != "notes"},
                           "repetitions": run.repetitions})
        pairs.extend(run.schedule["pairs"])
    return {"pack": corpus.runs[0].schedule["pack"], "inputs": sorted(inputs, key=canonical_json),
            "pairs": sorted(pairs, key=canonical_json)}


def _contract_gap(baseline: dict, candidate: dict, names: tuple[str, str]) -> str | None:
    """The first difference between two frozen contracts, in words, or ``None`` when they are one."""
    if canonical_json(baseline) == canonical_json(candidate):
        return None
    grouped = []
    for contract in (baseline, candidate):
        found: dict[str, list[dict]] = defaultdict(list)
        for entry in contract["inputs"]:
            found[entry["input_id"]].append(entry)
        grouped.append(found)
    left, right = grouped
    for input_id in sorted(set(left) | set(right)):
        if input_id not in right:
            return f"input {input_id} is scheduled for {names[0]} but not for {names[1]}"
        if input_id not in left:
            return f"input {input_id} is scheduled for {names[1]} but not for {names[0]}"
        if len(left[input_id]) != len(right[input_id]):
            return (f"input {input_id} is scheduled in {len(left[input_id])} run(s) for {names[0]} and "
                    f"{len(right[input_id])} for {names[1]}")
        for mine, theirs in zip(left[input_id], right[input_id]):
            for name in sorted(set(mine) | set(theirs)):
                if canonical_json(mine.get(name)) == canonical_json(theirs.get(name)):
                    continue
                if name == "plan":
                    differing = sorted(key for key in set(mine["plan"]) | set(theirs["plan"])
                                       if canonical_json(mine["plan"].get(key))
                                       != canonical_json(theirs["plan"].get(key)))
                    return f"input {input_id} differs in its frozen plan ({', '.join(differing)})"
                return f"input {input_id} differs in {name}"
    return "their frozen vulnerable/fixed pairs differ"


def _flatten(value: Any, prefix: str) -> dict[str, Any]:
    """Dotted keys to leaves: nested objects are walked, and a list or an empty object is one leaf."""
    if isinstance(value, dict) and value:
        flat: dict[str, Any] = {}
        for key in sorted(value):
            flat.update(_flatten(value[key], f"{prefix}.{key}" if prefix else key))
        return flat
    return {prefix: value}


def configuration_differences(baseline: dict, candidate: dict) -> list[dict]:
    """Every dotted key whose value differs between two system configurations, sorted by key.

    Values are compared as canonical JSON, so ``1`` and ``true`` differ. ``absent_in`` names the side
    that has no such key at all, which is different from a key present with a null value. A key that
    itself contains a dot is not escaped.
    """
    left, right = _flatten(baseline, ""), _flatten(candidate, "")
    rows = []
    for key in sorted(set(left) | set(right)):
        if key in left and key in right and canonical_json(left[key]) == canonical_json(right[key]):
            continue
        absent = "baseline" if key not in left else "candidate" if key not in right else None
        rows.append({"key": key, "baseline": left.get(key), "candidate": right.get(key), "absent_in": absent})
    return rows


def _family(key: tuple[str, ...]) -> str:
    """The resampling family a paired part draws from: ``controls``, ``pairs``, or ``targets``."""
    if key[0] == "controls":
        return "controls"
    return "pairs" if key[-1] == "pair_correctness" else "targets"


def _difference(context: _Context, baseline: _SliceResult, candidate: _SliceResult) -> dict:
    """Candidate minus baseline for one slice, each interval from the same replicates of both systems.

    Differences are taken between exact values and rounded once. A difference is null when either
    side is undefined, and so is its interval.
    """
    uncertainty = context.policy["uncertainty"]
    for family, mine in baseline.resamplers.items():
        theirs = candidate.resamplers[family]
        if (mine is None) != (theirs is None) or (mine is not None and mine.universe != theirs.universe):
            raise ContractError(f"slice {_slice_key(baseline.slice_)} resamples different {family} clusters "
                                "for the two systems")

    def minus(key: tuple[str, ...]) -> float | None:
        left, right = baseline.exact.get(key), candidate.exact.get(key)
        return None if left is None or right is None else float(right - left)

    def paired(key: tuple[str, ...]) -> dict:
        left, right = baseline.parts.get(key), candidate.parts.get(key)
        if left is None or right is None or left.value is None or right.value is None:
            return {"value": None, "interval": _unavailable_interval()}
        return {"value": float(right.value - left.value),
                "interval": _bootstrap([left, right], _minus, baseline.resamplers[_family(key)], uncertainty)}

    detection = []
    for left, right in zip(baseline.block["detection"], candidate.block["detection"]):
        weighting = left["weighting"]
        if left["state"] != "ok" or right["state"] != "ok":
            detection.append({"weighting": weighting, "state": "unavailable",
                              "reason": left["reason"] or right["reason"], "full_output_recall": None,
                              "recall_at_budget": [], "pair_correctness": None, "pair_availability": None,
                              "completed_mass": None, "assessable_mass": None})
            continue
        budgets = []
        for row in left["recall_at_budget"]:
            value = paired(("detection", weighting, f"recall_at_budget/{row['budget']}"))
            lower = paired(("detection", weighting, f"recall_at_budget_lower/{row['budget']}"))
            budgets.append({"budget": row["budget"], "value": value["value"], "lower_bound": lower["value"],
                            "interval": value["interval"]})
        detection.append({
            "weighting": weighting, "state": "ok", "reason": None,
            "full_output_recall": paired(("detection", weighting, "full_output_recall")),
            "recall_at_budget": budgets,
            "pair_correctness": paired(("detection", weighting, "pair_correctness")),
            "pair_availability": minus(("detection", weighting, "pair_availability")),
            "completed_mass": minus(("detection", weighting, "completed_mass")),
            "assessable_mass": minus(("detection", weighting, "assessable_mass"))})
    controls = {}
    for name in CONTROL_CLASSES:
        controls[name] = {"resolved_rate": paired(("controls", name, "resolved_rate")),
                          "completed_upper": paired(("controls", name, "completed_upper")),
                          "completed_mass": minus(("controls", name, "completed_mass")),
                          "assessable_mass": minus(("controls", name, "assessable_mass"))}
    return {"slice": baseline.block["slice"], "detection": detection, "controls": controls,
            "completion": minus(("completion",))}


def compare(run_dirs: Iterable[str | PathLike[str]], *, baseline: str, candidate: str,
            policy: dict | None = None) -> dict:
    """The validated comparison report of *candidate* against *baseline* over *run_dirs*.

    The two systems must have been assigned exactly the same frozen work: the same inputs with the same
    mode, profile, snapshot or change set, blinding map, declared tree hash, frozen plan items, levels,
    scope and budgets, the same repetitions, the same pairs, and the same pack. Anything else is refused
    before a metric is computed ("the systems do not share the frozen evaluation contract"), so a
    system cannot improve its numbers by being assigned less. Everything :func:`aggregate` refuses is
    refused here too. Differences are candidate minus baseline; each interval resamples the same
    clusters for both systems in every replicate.
    """
    if baseline == candidate:
        raise ContractError("the baseline and the candidate are one system; name two systems to compare")
    context = _Context(_load_corpus(run_dirs), resolve_policy(policy))
    corpus = context.corpus
    for system_id in (baseline, candidate):
        if system_id not in corpus.systems:
            raise ContractError(f"system {system_id} is not scheduled in any of the given runs")
    contracts = {system_id: _contract(corpus, system_id) for system_id in (baseline, candidate)}
    gap = _contract_gap(contracts[baseline], contracts[candidate], (baseline, candidate))
    if gap is not None:
        raise ContractError(f"the systems do not share the frozen evaluation contract: {gap}")
    views = []
    for mode, profile in _view_keys(corpus, (baseline,)):
        facts = _view_facts(corpus, mode, profile, (baseline,))
        left = _evaluate_system(context, mode, profile, baseline, facts["review_budgets"])
        right = _evaluate_system(context, mode, profile, candidate, facts["review_budgets"])
        _refuse_mixed_scopes(mode, profile, (left, right))
        views.append({
            "mode": mode, "profile": profile,
            "evidence_scope": {"baseline": left.block["evidence_scope"],
                               "candidate": right.block["evidence_scope"]},
            "inputs": facts["inputs"], "canonical_targets": facts["canonical_targets"],
            "canonical_controls": facts["canonical_controls"],
            "systems": {"baseline": left.block, "candidate": right.block},
            "differences": [_difference(context, mine, theirs)
                            for mine, theirs in zip(left.slices, right.slices)],
            "warnings": _view_warnings(facts, (left, right))})
    structure = contracts[baseline]
    report = {
        "schema_version": SCHEMA_VERSION, "evaluator_version": __version__,
        "policy": context.policy, "policy_sha256": canonical_sha256(context.policy),
        "runs": [_run_row(corpus, run) for run in corpus.runs
                 if baseline in run.system_ids or candidate in run.system_ids],
        "baseline": _system_row(baseline, corpus.systems[baseline]),
        "candidate": _system_row(candidate, corpus.systems[candidate]),
        "contract": {"structure_sha256": canonical_sha256(structure), "inputs": len(structure["inputs"]),
                     "pairs": len(structure["pairs"])},
        "configuration_differences": configuration_differences(corpus.systems[baseline]["configuration"],
                                                               corpus.systems[candidate]["configuration"]),
        "views": views,
        "notes": _notes(context.policy),
    }
    return validate_document(COMPARISON_KIND, report)


# --- summaries for the command line -------------------------------------------------------------


def _number(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _interval_text(interval: dict) -> str:
    if interval["state"] == "ok":
        return f"[{interval['lower']:.3f}, {interval['upper']:.3f}]"
    return f"({interval['state']})"


def summary(report: dict) -> list[str]:
    """One line per view and per system of an aggregate report: full-output recall per weighting."""
    lines = []
    for view in report["views"]:
        lines.append(f"view {view['mode']}/{view['profile']} scope={view['evidence_scope']} "
                     f"inputs={view['inputs']} canonical_targets={view['canonical_targets']} "
                     f"canonical_controls={view['canonical_controls']}")
        for system in view["systems"]:
            whole = system["slices"][0]
            recalls = []
            for block in whole["detection"]:
                if block["state"] != "ok":
                    recalls.append(f"{block['weighting']}=unavailable")
                    continue
                metric = block["full_output_recall"]
                recalls.append(f"{block['weighting']}={_number(metric['value'])} "
                               f"{_interval_text(metric['interval'])}")
            lines.append(f"  {system['system_id']} scope={system['evidence_scope']} full_output_recall "
                         f"{' '.join(recalls)} completion={_number(whole['completion']['value'])}")
    return lines


def comparison_summary(report: dict) -> list[str]:
    """One line per view and weighting of a comparison: the full-output recall difference."""
    lines = [f"baseline={report['baseline']['system_id']} candidate={report['candidate']['system_id']} "
             f"configuration_differences={len(report['configuration_differences'])}"]
    for view in report["views"]:
        scope = view["evidence_scope"]
        lines.append(f"view {view['mode']}/{view['profile']} scope baseline={scope['baseline']} "
                     f"candidate={scope['candidate']}")
        for block in view["differences"][0]["detection"]:
            if block["state"] != "ok":
                lines.append(f"  {block['weighting']} unavailable")
                continue
            metric = block["full_output_recall"]
            value = "n/a" if metric["value"] is None else f"{metric['value']:+.3f}"
            lines.append(f"  {block['weighting']} full_output_recall difference={value} "
                         f"{_interval_text(metric['interval'])}")
    return lines
