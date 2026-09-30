"""Deterministic promotion-gate decisions over a saved paired comparison.

:func:`evaluate_gate` holds one comparison of a candidate against a baseline
(:func:`scaneval.aggregate.compare`), and optionally a reviewed-precision estimate of each system
(:func:`scaneval.precision.estimate`), to one gate policy, and returns a decision: an outcome and one
record per requirement the policy declares. ``docs/GATE.md`` is the guide; this docstring states what
is guaranteed and what is not.

How the outcome is reached. A requirement is ``pass``, ``fail``, or ``inconclusive``, and reports
``{id, status, observed, threshold, explanation}``. The outcome is ``fail`` when any requirement
fails, else ``inconclusive`` when any is inconclusive, else ``pass``. Requirements are never weighed
against one another: detection cannot compensate for noise, false alarms, burden, cost, or failed
scans, and a strong figure on one requirement never turns another's failure into a pass. A requirement
is inconclusive, never a pass, when what it needs is missing or cannot be trusted: an unavailable or
unmeasurable metric, an interval that is not ``ok``, an aborted run, a difference the policy did not
intend to measure, evidence below the scope the policy requires, a precision estimate that is missing
or not bound to the comparison, no eligible control, a completed, assessable, or covered mass below
its minimum, or a claim volume or cost nobody recorded. No absent figure is read as a perfect one.

What is decided from what. Only the documents passed in: the policy, the comparison report, and the
precision estimates. The decision is a function of them and of the evaluator version, so the same
inputs give the same document byte for byte under :func:`scaneval.contracts.canonical_json`.
:func:`evaluate_gate` reads no clock, network, filesystem path, or unseeded random source, and no
model or judge is consulted; only :func:`load_policy` opens a file. The comparison is read as
recorded: nothing is recomputed from run directories, so the decision is exactly as trustworthy as
the comparison it names, and it says which by digest.

What the decision binds. Its policy is recorded whole beside its digest. The comparison, and each
precision estimate that was supplied, are recorded by digest, with the digests of the manifest,
schedule, and evidence of every run the comparison read and the evaluator versions involved. A
digest identifies a document; it authenticates no author and proves no reviewer read anything.

What this is not. It promotes nothing, edits no harness, and opens no change: the external workflow
that owns the harness owns any promotion. A ``pass`` says every requirement the policy declares held
on this comparison, not that the requirements were well chosen, that the corpus represents other
software, or that a label is right. A requirement the policy leaves out is not evaluated, and the
decision says which. The figures a requirement reads are whatever the comparison and the estimates
recorded; they are compared with the policy's thresholds as written, with no tolerance of their own.
"""

from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
from os import PathLike
from typing import Any, Callable

from . import __version__
from .contracts import (
    GATE_BLOCKS,
    ContractError,
    canonical_json,
    canonical_sha256,
    gate_declared_blocks,
    gate_requirement_ids,
    load_document,
    validate_document,
)
from .precision import GRADES


POLICY_KIND = "gate-policy"
DECISION_KIND = "gate-decision"
COMPARISON_KIND = "comparison-report"
ESTIMATE_KIND = "precision-estimate"
SCHEMA_VERSION = "2.1"

PASS, FAIL, INCONCLUSIVE = "pass", "fail", "inconclusive"
SIDES = ("baseline", "candidate")
WHOLE_VIEW = {"dimension": "all"}
# Evidence scopes, strongest first: a requirement for one scope is met by any scope before it.
SCOPE_RANK = {"reviewed": 2, "draft": 1, "diagnostic": 0}
# Review grades of a precision estimate, strongest first: a requirement for one grade is met by any
# grade before it, and an incomplete review meets none.
GRADE_RANK = {grade: len(GRADES) - index for index, grade in enumerate(GRADES)}
# What a paired interval's state means for a requirement that needs one; only "ok" carries bounds.
INTERVAL_STATES = {
    "insufficient_clusters": "too few clusters carry the metric to resample it",
    "degenerate": "every replicate agreed, which is not certainty",
    "unstable": "some replicate drew no cluster carrying the metric",
    "unavailable": "the metric is undefined",
}

# The statements every decision carries about what it is and is not. A decision's conditional notes, about
# what the policy left out or the gate did not read, follow them.
STANDING_NOTES = (
    "This decision holds one candidate to one policy over one saved comparison. It approves, promotes, and "
    "deploys nothing; the external workflow that owns the harness owns any promotion.",
    "No requirement is weighed against another: any failure fails the decision, so detection cannot "
    "compensate for noise, false alarms, review burden, cost, or failed scans.",
    "An absent figure is never a perfect one: a requirement whose evidence is missing, unmeasurable, or "
    "below the required scope is inconclusive, not passed.",
)

Result = tuple[str, Any, Any, str]


# --- policy -------------------------------------------------------------------------------------


def resolve_policy(policy: dict) -> dict:
    """The complete policy a decision is made under: *policy* with its optional fields filled in.

    The policy is validated as written and again once completed, and the result is a new document:
    *policy* is not modified. The only fields filled are the required evidence scope (``reviewed``)
    and the notes (none), so the decision records the scope it was held to and never depends on a
    default it does not show. No threshold is ever filled in. A policy whose primary metric is a
    random-order expectation or any other diagnostic is refused by validation, here and wherever a
    ``gate-policy`` is read.
    """
    validate_document(POLICY_KIND, policy)
    completed = {"required_scope": "reviewed", "notes": [], **deepcopy(policy)}
    return validate_document(POLICY_KIND, completed)


def load_policy(path: str | PathLike[str]) -> dict:
    """Load a gate-policy file and return it completed by :func:`resolve_policy`."""
    return resolve_policy(load_document(path, POLICY_KIND))


# --- formatting ---------------------------------------------------------------------------------


def _n(value: float | int | None) -> str:
    """A number as the explanations print it: six significant digits, or ``n/a`` when absent."""
    return "n/a" if value is None else format(value, ".6g")


def _signed(value: float | int | None) -> str:
    return "n/a" if value is None else format(value, "+.6g")


def _interval_text(interval: dict) -> str:
    return f"[{_n(interval['lower'])}, {_n(interval['upper'])}]"


def _metric_text(metric: dict) -> str:
    return "full-output recall" if metric["kind"] == "full_recall" else f"recall@{metric['budget']}"


def _slice_text(dimension: str, value: str | None) -> str:
    return "the whole view" if dimension == "all" else f"{dimension} {value}"


def _names(values: list[str], limit: int = 3) -> str:
    shown = ", ".join(values[:limit])
    return shown + (f" and {len(values) - limit} more" if len(values) > limit else "")


def _exact(value: float | int) -> Fraction:
    """A recorded or declared number read as the decimal it is written as: 0.15 is 3/20, not a binary float.

    A figure a comparison reports was rounded once from an exact value, so it is compared with a
    threshold as it stands. A figure the gate derives itself (a share, a ratio, a mean, or the difference
    of two recorded figures) is computed exactly from the decimals recorded, so a value that equals its
    threshold on paper never fails by a unit in the last place.
    """
    return Fraction(repr(value)) if isinstance(value, float) else Fraction(value)


def _open(reason: str, threshold: Any = None, observed: Any = None) -> Result:
    """An inconclusive result: the requirement's evidence is missing or cannot be trusted."""
    return INCONCLUSIVE, observed, threshold, reason


# --- what a decision reads of a comparison ------------------------------------------------------


class _Context:
    """One evaluation: the policy, the comparison, the estimates, and the policy's view of the comparison.

    ``view`` is the comparison's view for the policy's (mode, profile), ``None`` when it has none.
    ``slices`` maps each system side to its slice blocks keyed by (dimension, value), and
    ``differences`` maps the same keys to the comparison's candidate-minus-baseline blocks.
    """

    def __init__(self, policy: dict, comparison: dict, estimates: dict[str, dict | None]) -> None:
        self.policy = policy
        self.comparison = comparison
        self.estimates = estimates
        self.names = {side: comparison[side]["system_id"] for side in SIDES}
        wanted = policy["view"]
        self.view_name = f"{wanted['mode']}/{wanted['profile']}"
        self.view = next((view for view in comparison["views"]
                          if (view["mode"], view["profile"]) == (wanted["mode"], wanted["profile"])), None)
        self.slices: dict[str, dict[tuple[str, str | None], dict]] = {side: {} for side in SIDES}
        self.differences: dict[tuple[str, str | None], dict] = {}
        if self.view is not None:
            for side in SIDES:
                self.slices[side] = {(block["slice"]["dimension"], block["slice"]["value"]): block
                                     for block in self.view["systems"][side]["slices"]}
            self.differences = {(block["slice"]["dimension"], block["slice"]["value"]): block
                                for block in self.view["differences"]}
        self.regressions = {entry["id"]: entry for entry in policy.get("regressions", [])}

    def missing_view(self) -> str | None:
        """Why nothing can be read from the policy's view, or ``None`` when the comparison has it whole.

        A view is usable when it exists and both systems and the differences carry the whole-view
        slice every metric outside a named slice reads.
        """
        if self.view is None:
            return f"the comparison has no {self.view_name} view"
        if ("all", None) not in self.differences or any(("all", None) not in self.slices[side] for side in SIDES):
            return f"the comparison's {self.view_name} view has no whole-view slice"
        return None

    def whole(self, side: str) -> dict | None:
        """One system's whole-view slice block, or ``None`` when the comparison has no such view."""
        return self.slices[side].get(("all", None))


def _reading(ctx: _Context, metric: dict, weighting: str, dimension: str,
             value: str | None) -> tuple[dict | None, str | None]:
    """Both systems' figure for one recall metric in one slice, their difference, and its paired interval.

    Returns ``(reading, None)`` with ``baseline``, ``candidate``, ``difference``, and ``interval``, or
    ``(None, reason)`` when the comparison cannot supply the figure: no such view, slice, weighting,
    or budget; a detection block that is unavailable; or a recall@B that is unmeasurable for either
    system, which happens when its output is unranked or its bundles are unresolved and no native
    position is known. A random-order expectation is never substituted for a position nobody measured.
    """
    problem = ctx.missing_view()
    if problem is not None:
        return None, problem
    where = f"{_slice_text(dimension, value)} of {ctx.view_name}"
    difference = ctx.differences.get((dimension, value))
    if difference is None:
        return None, f"the comparison has no {where}"
    weightings = ctx.comparison["policy"]["views"]
    if weighting not in weightings:
        return None, (f"the comparison's aggregation policy reports no {weighting} weighting "
                      f"(it reports {', '.join(weightings)})")
    blocks = {side: next(block for block in ctx.slices[side][(dimension, value)]["detection"]
                         if block["weighting"] == weighting) for side in SIDES}
    changed = next(block for block in difference["detection"] if block["weighting"] == weighting)
    for block in (changed, *blocks.values()):
        if block["state"] != "ok":
            return None, f"{weighting} detection is unavailable for {where}: {block['reason']}"
    if metric["kind"] == "full_recall":
        figures = {side: blocks[side]["full_output_recall"]["value"] for side in SIDES}
        paired = changed["full_output_recall"]
    else:
        budget = metric["budget"]
        rows = {side: next((row for row in blocks[side]["recall_at_budget"] if row["budget"] == budget), None)
                for side in SIDES}
        paired = next((row for row in changed["recall_at_budget"] if row["budget"] == budget), None)
        if paired is None or None in rows.values():
            reported = [str(row["budget"]) for row in blocks["baseline"]["recall_at_budget"]]
            return None, (f"the comparison reports no recall@{budget} for {where} "
                          f"(its budgets are {', '.join(reported)})")
        unmeasured = [ctx.names[side] for side in SIDES if rows[side]["value"] is None]
        if unmeasured:
            return None, (f"recall@{budget} cannot be measured for {', '.join(unmeasured)}: its output is "
                          "unranked or its bundles are unresolved, so no native position is known, and a "
                          "random-order expectation is never substituted for one")
        figures = {side: rows[side]["value"] for side in SIDES}
    if paired["value"] is None or None in figures.values():
        return None, f"{_metric_text(metric)} is undefined for {where}"
    return {**figures, "difference": paired["value"], "interval": paired["interval"]}, None


# --- the frozen contract and its bindings -------------------------------------------------------


def _contract_violations(comparison: dict) -> list[str]:
    """Every way a comparison's own records contradict a shared frozen contract or its bindings.

    :func:`scaneval.aggregate.compare` refuses systems that were not assigned the same frozen work, so
    a comparison it wrote holds none of these. This reads the comparison again, as a document that
    may have been edited or produced elsewhere: the contract must cover an input, the aggregation
    policy must hash to its digest, each system must be scheduled by runs the comparison lists, those
    runs must have frozen one pack, and in every view the two systems must record the same structure
    (assignments, inputs, canonical targets and controls, clusters, target observations, and pairs),
    because what is frozen before execution cannot differ between systems that share a contract.
    """
    found: list[str] = []
    if comparison["contract"]["inputs"] < 1:
        found.append("the contract covers no input")
    if canonical_sha256(comparison["policy"]) != comparison["policy_sha256"]:
        found.append("policy_sha256 does not hash the aggregation policy the comparison carries")
    runs = {run["run_id"]: run for run in comparison["runs"]}
    for side in SIDES:
        system = comparison[side]
        if not system["runs"]:
            found.append(f"the {side} {system['system_id']} names no run")
        for run_id in system["runs"]:
            run = runs.get(run_id)
            if run is None:
                found.append(f"the {side} names run {run_id}, which the comparison does not list")
            elif system["system_id"] not in run["systems"]:
                found.append(f"run {run_id} does not schedule the {side} {system['system_id']}")
    if len({canonical_json(run["pack"]) for run in comparison["runs"]}) > 1:
        found.append("the compared runs froze different packs")
    for view in comparison["views"]:
        left, right = view["systems"]["baseline"], view["systems"]["candidate"]
        label = f"view {view['mode']}/{view['profile']}"
        for side, block in (("baseline", left), ("candidate", right)):
            if block["system_id"] != comparison[side]["system_id"]:
                found.append(f"{label} records {block['system_id']} as the {side}, not "
                             f"{comparison[side]['system_id']}")
        if left["observations"]["assignments"] != right["observations"]["assignments"]:
            found.append(f"{label}: the systems were assigned {left['observations']['assignments']} and "
                         f"{right['observations']['assignments']} scans")
        for mine, theirs in zip(left["slices"], right["slices"]):
            name = f"{label}, {_slice_text(mine['slice']['dimension'], mine['slice']['value'])}"
            for key in ("inputs", "canonical_targets", "canonical_controls", "clusters"):
                if mine[key] != theirs[key]:
                    found.append(f"{name}: {key} differ ({canonical_json(mine[key])} and "
                                 f"{canonical_json(theirs[key])})")
            for key in ("inputs", "assignments"):
                if mine["completion"][key] != theirs["completion"][key]:
                    found.append(f"{name}: completion {key} differ ({mine['completion'][key]} and "
                                 f"{theirs['completion'][key]})")
            if mine["claims"]["assignments"] != theirs["claims"]["assignments"]:
                found.append(f"{name}: the claim volumes cover {mine['claims']['assignments']} and "
                             f"{theirs['claims']['assignments']} assignments")
            for first, second in zip(mine["detection"], theirs["detection"]):
                if (first["coverage"] is None) != (second["coverage"] is None):
                    found.append(f"{name}: {first['weighting']} target coverage exists for one system only")
                elif first["coverage"] is not None:
                    if first["coverage"]["target_observations"] != second["coverage"]["target_observations"]:
                        found.append(f"{name}: {first['weighting']} target observations differ "
                                     f"({first['coverage']['target_observations']} and "
                                     f"{second['coverage']['target_observations']})")
                    if first["pairs"]["repetition_pairs"] != second["pairs"]["repetition_pairs"]:
                        found.append(f"{name}: {first['weighting']} repetition pairs differ")
            for control_class in mine["controls"]:
                for key in ("canonical_controls", "observations"):
                    if mine["controls"][control_class][key] != theirs["controls"][control_class][key]:
                        found.append(f"{name}: {control_class} {key} differ")
    return found


def _contract_shared(ctx: _Context) -> Result:
    comparison = ctx.comparison
    threshold = "one frozen contract for both systems, every recorded count agreeing, every binding named"
    violations = _contract_violations(comparison)
    if violations:
        return (FAIL, {"violations": violations}, threshold,
                "the comparison's own records show the two systems were not assigned the same frozen work, "
                f"or do not bind to the runs they name: {_names(violations)}")
    contract = comparison["contract"]
    return (PASS, {"contract_sha256": contract["structure_sha256"], "inputs": contract["inputs"],
                   "pairs": contract["pairs"], "views": len(comparison["views"])}, threshold,
            f"{ctx.names['baseline']} and {ctx.names['candidate']} share one frozen contract of "
            f"{contract['inputs']} input(s) and {contract['pairs']} pair(s), and every count the comparison "
            f"records for them agrees in each of its {len(comparison['views'])} view(s)")


def _runs_completed(ctx: _Context) -> Result:
    runs = ctx.comparison["runs"]
    threshold = "every compared run finished (manifest status completed)"
    observed = {run["run_id"]: run["status"] for run in runs}
    unfinished = [run["run_id"] for run in runs if run["status"] != "completed"]
    if unfinished:
        return (INCONCLUSIVE, observed, threshold,
                f"run {_names(unfinished)} did not finish, so assignments it never recorded stand as failures "
                "for whichever system they belonged to and the comparison rests on part of what was scheduled")
    return PASS, observed, threshold, f"all {len(runs)} compared run(s) finished"


def _configuration_differences(ctx: _Context) -> Result:
    allowed = ctx.policy["configuration"]["allowed_differences"]
    keys = [row["key"] for row in ctx.comparison["configuration_differences"]]
    unexpected = [key for key in keys if not any(key == name or key.startswith(f"{name}.") for name in allowed)]
    observed = {"differences": keys, "not_allowed": unexpected}
    threshold = {"allowed_differences": allowed}
    if unexpected:
        return (INCONCLUSIVE, observed, threshold,
                f"the systems also differ in {_names(unexpected)}, which the policy does not intend to "
                "measure, so the comparison does not isolate the intended change")
    if not keys:
        return PASS, observed, threshold, "the two systems are configured identically"
    return (PASS, observed, threshold,
            f"every configuration difference ({_names(keys)}) is one the policy intends to measure")


def _evidence_scope(ctx: _Context) -> Result:
    required = ctx.policy["required_scope"]
    threshold = {"required_scope": required}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    scopes = ctx.view["evidence_scope"]
    observed = {side: scopes[side] for side in SIDES}
    short = [side for side in SIDES if SCOPE_RANK[scopes[side]] < SCOPE_RANK[required]]
    if not short:
        if required == "draft":
            return (PASS, observed, threshold,
                    f"the evidence is {scopes['baseline']} for the baseline and {scopes['candidate']} for the "
                    "candidate, which meets the policy's draft scope; this is a development decision, not a "
                    "reviewed recommendation")
        return PASS, observed, threshold, "the evidence is reviewed for both systems"
    reasons = []
    for side in short:
        if scopes[side] == "diagnostic":
            reasons.append(f"the {side} evidence is diagnostic fixture evidence, which supports no recommendation")
        else:
            reasons.append(f"the {side} evidence is draft, not reviewed: labels or matches without a recorded "
                           "human approval are pipeline diagnostics, so no reviewed recommendation can rest on them")
    return _open("; ".join(reasons), threshold, observed)


# --- the primary metric and regressions ---------------------------------------------------------


def _primary_improvement(ctx: _Context) -> Result:
    primary = ctx.policy["primary"]
    slice_ = primary.get("slice", WHOLE_VIEW)
    minimum = primary["min_improvement"]
    threshold = {"metric": primary["metric"], "weighting": primary["weighting"], "slice": slice_,
                 "min_improvement": minimum}
    reading, problem = _reading(ctx, primary["metric"], primary["weighting"], slice_["dimension"],
                                slice_.get("value"))
    if reading is None:
        return _open(problem, threshold)
    observed = {"baseline": reading["baseline"], "candidate": reading["candidate"],
                "difference": reading["difference"]}
    text = (f"{_metric_text(primary['metric'])} ({primary['weighting']}, "
            f"{_slice_text(slice_['dimension'], slice_.get('value'))}) went from {_n(reading['baseline'])} to "
            f"{_n(reading['candidate'])}, {_signed(reading['difference'])}")
    if reading["difference"] >= minimum:
        return PASS, observed, threshold, f"{text}, at least the required {_signed(minimum)}"
    return FAIL, observed, threshold, f"{text}, below the required {_signed(minimum)}"


def _primary_uncertainty(ctx: _Context) -> Result:
    primary = ctx.policy["primary"]
    rule = primary["uncertainty"]
    slice_ = primary.get("slice", WHOLE_VIEW)
    threshold = dict(rule)
    reading, problem = _reading(ctx, primary["metric"], primary["weighting"], slice_["dimension"],
                                slice_.get("value"))
    if reading is None:
        return _open(problem, threshold)
    interval = reading["interval"]
    confidence = ctx.comparison["policy"]["uncertainty"]["confidence"]
    observed = {"interval": interval, "confidence": confidence}
    if interval["state"] != "ok":
        return _open(f"the paired interval is {interval['state']} ({INTERVAL_STATES[interval['state']]}), so it "
                     "cannot show that the improvement is real", threshold, observed)
    if "min_confidence" in rule and confidence < rule["min_confidence"]:
        return _open(f"the comparison's interval is at {_n(confidence)} confidence and the policy requires at "
                     f"least {_n(rule['min_confidence'])}", threshold, observed)
    if "min_clusters" in rule and interval["clusters"] < rule["min_clusters"]:
        return _open(f"the interval rests on {interval['clusters']} cluster(s) and the policy requires at "
                     f"least {rule['min_clusters']}", threshold, observed)
    bound = rule["lower_bound_above"]
    text = f"the paired interval {_interval_text(interval)} at {_n(confidence)} confidence"
    if interval["lower"] > bound:
        return PASS, observed, threshold, f"{text} has its lower bound above {_n(bound)}"
    if interval["upper"] <= bound:
        return (FAIL, observed, threshold,
                f"{text} lies wholly at or below {_n(bound)}, so the change is shown not to improve enough")
    return (INCONCLUSIVE, observed, threshold,
            f"{text} includes values at or below {_n(bound)}, so the improvement is not established at the "
            "comparison's confidence")


def _regression(ctx: _Context, entry: dict) -> Result:
    """One protected detection metric: it may not fall by more than the entry allows in any slice it covers.

    A slice with no value covers every project or workload the comparison holds that carries targets.
    The point difference decides pass or fail. With ``check_interval`` the lower bound of the paired
    interval must also stay within the allowed decrease: an interval wholly below it fails, one that
    straddles it is inconclusive, and one that is not ``ok`` is inconclusive.
    """
    metric, weighting = entry["metric"], entry["weighting"]
    slice_ = entry.get("slice", WHOLE_VIEW)
    dimension, value = slice_["dimension"], slice_.get("value")
    limit = entry["max_decrease"]
    threshold = {"metric": metric, "weighting": weighting, "slice": slice_, "max_decrease": limit,
                 "check_interval": entry.get("check_interval", False)}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    if value is None and dimension != "all":
        values = sorted(name for (kind, name) in ctx.differences if kind == dimension and name is not None
                        and ctx.slices["baseline"][(kind, name)]["canonical_targets"] > 0)
        if not values:
            return _open(f"the comparison has no {dimension} slice carrying targets in {ctx.view_name}", threshold)
    else:
        values = [value]
    rows, failures, unresolved = [], [], []
    for name in values:
        label = _slice_text(dimension, name)
        reading, problem = _reading(ctx, metric, weighting, dimension, name)
        if reading is None:
            unresolved.append(f"{label}: {problem}")
            rows.append({"slice": name, "difference": None})
            continue
        rows.append({"slice": name, "baseline": reading["baseline"], "candidate": reading["candidate"],
                     "difference": reading["difference"]})
        if -reading["difference"] > limit:
            failures.append(f"{label} fell from {_n(reading['baseline'])} to {_n(reading['candidate'])}, "
                            f"{_signed(reading['difference'])}")
        if entry.get("check_interval"):
            interval = reading["interval"]
            if interval["state"] != "ok":
                unresolved.append(f"{label}: the paired interval is {interval['state']} "
                                  f"({INTERVAL_STATES[interval['state']]})")
            elif interval["upper"] < -limit:
                failures.append(f"{label}: the whole paired interval {_interval_text(interval)} lies below "
                                f"{_signed(-limit)}")
            elif interval["lower"] < -limit:
                unresolved.append(f"{label}: the paired interval {_interval_text(interval)} allows a decrease "
                                  f"larger than {_n(limit)}")
    observed = {"slices": rows}
    where = _slice_text(dimension, value) if value is not None or dimension == "all" else f"each {dimension}"
    what = f"{_metric_text(metric)} ({weighting}) in {where}"
    if failures:
        return FAIL, observed, threshold, f"{what} may not fall by more than {_n(limit)}, but {_names(failures)}"
    if unresolved:
        return INCONCLUSIVE, observed, threshold, f"{what} could not be settled: {_names(unresolved)}"
    worst = max(-row["difference"] for row in rows)
    return (PASS, observed, threshold,
            f"{what} fell by at most {_n(max(worst, 0))} across {len(rows)} slice(s), within the allowed {_n(limit)}")


# --- reviewed precision -------------------------------------------------------------------------


def _population_text(population: dict) -> str:
    return "the full population" if population["name"] == "full" else f"the first-{population['budget']} population"


def _binding_problems(ctx: _Context, side: str) -> list[str]:
    """Why the estimate supplied for one system is not evidence about it in this comparison, if it is not.

    An estimate binds when it names only that system, the policy's view and declared population, and
    runs of this comparison: every run it rests on must be one the comparison read, with the same
    manifest and schedule digests, and every run of the comparison in which the system was scheduled
    must be among them, so it describes the compared workload and none other. This compares the
    documents' records; it cannot show the claims a person reviewed came from those runs. A first-B
    estimate also binds only when it leaves no invocation out for want of a measured native position:
    an unranked or bundle-unresolved invocation is outside that population, so noise in it would be
    invisible to the estimate.
    """
    estimate = ctx.estimates[side]
    system = ctx.names[side]
    if estimate is None:
        return [f"no precision estimate was supplied for the {side} {system}"]
    population = estimate["population"]
    problems = []
    if population["systems"] != [system]:
        problems.append(f"the estimate covers {', '.join(population['systems'])}, not only the {side} {system}")
    wanted = ctx.policy["view"]
    if (population["mode"], population["profile"]) != (wanted["mode"], wanted["profile"]):
        problems.append(f"the estimate is over {population['mode']}/{population['profile']} inputs, not "
                        f"{ctx.view_name}")
    declared = ctx.policy["precision"]["population"]
    if (population["name"], population["budget"]) != (declared["name"], declared.get("budget")):
        problems.append(f"the estimate is over {_population_text(population)}, but the policy declares "
                        f"{_population_text({'name': declared['name'], 'budget': declared.get('budget')})}")
    if population["name"] == "first_b":
        left_out = [f"{estimate['exclusions'][key]['invocations']} {label}" for key, label in (
            ("unranked", "unranked"), ("bundle_unresolved", "bundle-unresolved"))
            if estimate["exclusions"][key]["invocations"]]
        if left_out:
            problems.append(f"the estimate leaves out {' and '.join(left_out)} invocation(s), whose claims have no "
                            f"measured native position, so it does not describe all of the {side}'s output")
    compared = {run["run_id"]: run for run in ctx.comparison["runs"]}
    for run in estimate["runs"]:
        known = compared.get(run["run_id"])
        if known is None:
            problems.append(f"the estimate rests on run {run['run_id']}, which the comparison does not include")
        elif (run["manifest_sha256"], run["schedule_sha256"]) != (known["manifest_sha256"], known["schedule_sha256"]):
            problems.append(f"the estimate's record of run {run['run_id']} is not the comparison's (its manifest or "
                            "schedule digest differs)")
    named = {run["run_id"] for run in estimate["runs"]}
    for run_id in ctx.comparison[side]["runs"]:
        if run_id not in named:
            problems.append(f"the {side}'s run {run_id} is not among the estimate's runs")
    return problems


def _figure(estimate: dict, basis: str) -> float | None:
    """The figure a policy bounds: resolved precision, or the sensitivity lower bound."""
    return estimate["precision_resolved"] if basis == "resolved" else estimate["sensitivity"]["lower"]


def _figure_text(basis: str) -> str:
    return "resolved precision" if basis == "resolved" else "the sensitivity lower bound of precision"


def _bound_candidate(ctx: _Context) -> tuple[dict | None, str | None]:
    """The candidate's estimate when it binds to this comparison, else ``None`` and why it does not."""
    problems = _binding_problems(ctx, "candidate")
    return (None, "; ".join(problems)) if problems else (ctx.estimates["candidate"], None)


def _precision_binding(ctx: _Context) -> Result:
    rule = ctx.policy["precision"]
    threshold = {"systems": [ctx.names["candidate"]], "mode": ctx.policy["view"]["mode"],
                 "profile": ctx.policy["view"]["profile"], "population": rule["population"],
                 "runs": list(ctx.comparison["candidate"]["runs"])}
    estimate = ctx.estimates["candidate"]
    problems = _binding_problems(ctx, "candidate")
    if problems:
        observed = None if estimate is None else {
            "systems": estimate["population"]["systems"], "mode": estimate["population"]["mode"],
            "profile": estimate["population"]["profile"],
            "population": {"name": estimate["population"]["name"], "budget": estimate["population"]["budget"]},
            "runs": [run["run_id"] for run in estimate["runs"]]}
        return (INCONCLUSIVE, observed, threshold,
                f"the candidate's precision estimate is missing or not bound to this comparison: {'; '.join(problems)}")
    population = estimate["population"]
    return (PASS, {"systems": population["systems"], "mode": population["mode"], "profile": population["profile"],
                   "population": {"name": population["name"], "budget": population["budget"]},
                   "runs": [run["run_id"] for run in estimate["runs"]]}, threshold,
            f"the estimate covers only the candidate {ctx.names['candidate']}, over {_population_text(population)} of "
            f"{ctx.view_name} inputs, and rests on run(s) {', '.join(run['run_id'] for run in estimate['runs'])} "
            "of this comparison")


def _precision_min_value(ctx: _Context) -> Result:
    rule = ctx.policy["precision"]
    threshold = {"basis": rule["basis"], "min_value": rule["min_value"]}
    estimate, problem = _bound_candidate(ctx)
    if estimate is None:
        return _open(f"the candidate's precision is not established: {problem}", threshold)
    value = _figure(estimate, rule["basis"])
    label = _figure_text(rule["basis"])
    observed = {"value": value, "precision_resolved": estimate["precision_resolved"],
                "sensitivity": estimate["sensitivity"]}
    if value is None:
        return _open(f"{label} is undefined: no sampled claim was judged" +
                     (" true or false" if rule["basis"] == "resolved" else ""), threshold, observed)
    text = f"{label} is {_n(value)}"
    if value >= rule["min_value"]:
        return PASS, observed, threshold, f"{text}, at least the required {_n(rule['min_value'])}"
    return FAIL, observed, threshold, f"{text}, below the required {_n(rule['min_value'])}"


def _precision_unresolved_share(ctx: _Context) -> Result:
    rule = ctx.policy["precision"]
    threshold = {"max_unresolved_share": rule["max_unresolved_share"]}
    estimate, problem = _bound_candidate(ctx)
    if estimate is None:
        return _open(f"the candidate's unresolved share is not established: {problem}", threshold)
    share = estimate["unresolved_share"]
    observed = {"unresolved_share": share, "classes": estimate["sample"]["classes"],
                "bases": estimate["sample"]["bases"]}
    if share is None:
        return _open("the unresolved share is undefined: no sampled claim was judged", threshold, observed)
    if share <= rule["max_unresolved_share"]:
        return (PASS, observed, threshold,
                f"the unresolved share is {_n(share)}, within the allowed {_n(rule['max_unresolved_share'])}")
    return _open(f"the unresolved share is {_n(share)}, above the allowed {_n(rule['max_unresolved_share'])}: too "
                 "much of the review is unresolved for the figures to be trusted, so it is not a finding that "
                 "the claims are false", threshold, observed)


def _precision_grade(ctx: _Context) -> Result:
    required = ctx.policy["precision"]["min_evidence_grade"]
    threshold = {"min_evidence_grade": required}
    estimate, problem = _bound_candidate(ctx)
    if estimate is None:
        return _open(f"the candidate's review grade is not established: {problem}", threshold)
    grade = estimate["evidence_grade"]
    bases = estimate["sample"]["bases"]
    observed = {"evidence_grade": grade, "bases": bases}
    if GRADE_RANK[grade] >= GRADE_RANK[required]:
        return PASS, observed, threshold, f"the review's evidence grade is {grade}, which meets {required}"
    if grade == "incomplete":
        detail = (f"{bases['nonresponse']} sampled claim(s) have no review and {bases['disagreement']} have "
                  "disagreeing reviews with no adjudication")
    else:
        detail = f"{bases['single_review']} sampled claim(s) rest on a single reviewer"
    return _open(f"the review's evidence grade is {grade}, below the required {required}: {detail}", threshold,
                 observed)


def _precision_coverage(ctx: _Context) -> Result:
    minimum = ctx.policy["precision"]["min_coverage"]
    threshold = {"min_coverage": minimum}
    estimate, problem = _bound_candidate(ctx)
    if estimate is None:
        return _open(f"the candidate's coverage is not established: {problem}", threshold)
    coverage = estimate["coverage"]
    observed = {"share": coverage["share"], "covered_units": coverage["covered_units"],
                "population_units": coverage["population_units"], "uncovered_strata": coverage["uncovered_strata"]}
    text = (f"the sampled strata hold {coverage['covered_units']} of the population's {coverage['population_units']} "
            f"unit(s), a share of {_n(coverage['share'])}")
    if coverage["share"] >= minimum:
        return PASS, observed, threshold, f"{text}, at least the required {_n(minimum)}"
    return _open(f"{text}, below the required {_n(minimum)}; a stratum that drew no unit is not estimated at all",
                 threshold, observed)


def _precision_interval(ctx: _Context) -> Result:
    rule = ctx.policy["precision"]
    bound = rule["min_interval_lower_bound"]
    threshold = {"min_interval_lower_bound": bound}
    estimate, problem = _bound_candidate(ctx)
    if estimate is None:
        return _open(f"the candidate's precision interval is not established: {problem}", threshold)
    interval = estimate["interval"]
    observed = {"interval": {key: interval[key] for key in ("state", "lower", "upper", "confidence")}}
    if interval["state"] not in ("ok", "census"):
        return _open(f"the estimate's interval is {interval['state']}, so it carries no bounds", threshold, observed)
    text = f"the resolved-precision interval {_interval_text(interval)} at {_n(interval['confidence'])} confidence"
    if interval["lower"] >= bound:
        return PASS, observed, threshold, f"{text} has its lower bound at or above {_n(bound)}"
    if interval["upper"] < bound:
        return FAIL, observed, threshold, f"{text} lies wholly below {_n(bound)}"
    return (INCONCLUSIVE, observed, threshold,
            f"{text} reaches below {_n(bound)}, so precision at that level is not established")


def _precision_decrease(ctx: _Context) -> Result:
    rule = ctx.policy["precision"]
    limit = rule["max_decrease_vs_baseline"]
    threshold = {"basis": rule["basis"], "max_decrease_vs_baseline": limit}
    problems = [f"candidate: {item}" for item in _binding_problems(ctx, "candidate")]
    problems += [f"baseline: {item}" for item in _binding_problems(ctx, "baseline")]
    if problems:
        return _open(f"the change in precision is not established: {'; '.join(problems)}", threshold)
    figures = {side: _figure(ctx.estimates[side], rule["basis"]) for side in SIDES}
    weak = [side for side in SIDES if GRADE_RANK[ctx.estimates[side]["evidence_grade"]]
            < GRADE_RANK[rule["min_evidence_grade"]]]
    label = _figure_text(rule["basis"])
    if None in figures.values():
        return _open(f"{label} is undefined for the {', '.join(side for side in SIDES if figures[side] is None)}: no "
                     "sampled claim was judged", threshold, figures)
    decrease = _exact(figures["baseline"]) - _exact(figures["candidate"])
    observed = {**figures, "decrease": float(decrease)}
    if weak:
        return _open(f"the {' and '.join(weak)} estimate is below the required {rule['min_evidence_grade']} grade, so "
                     "the change in precision is not established", threshold, observed)
    text = f"{label} went from {_n(figures['baseline'])} to {_n(figures['candidate'])}"
    if decrease <= _exact(limit):
        return PASS, observed, threshold, f"{text}, a decrease of at most the allowed {_n(limit)}"
    return (FAIL, observed, threshold,
            f"{text}, a decrease of {_n(observed['decrease'])}, more than the allowed {_n(limit)}")


# --- controls, completion, and target coverage --------------------------------------------------


def _counts_text(counts: dict) -> str:
    """The non-zero entries of a status or failure count, as ``name n`` pairs."""
    shown = [f"{name} {count}" for name, count in counts.items() if count]
    return ", ".join(shown) if shown else "none"


def _control(ctx: _Context, name: str, check: str) -> Result:
    """One of the candidate's control requirements: the F+ bound, the completed mass, or the assessable mass.

    Read from the candidate's whole-view control block of one class. A class with no eligible control
    is unresolved, never a perfect score, and so is a rate with nothing completed or resolved behind it.
    A mass below its minimum is unresolved rather than failed, because failed and unresolved
    controls are not quiet ones and a bound over too little of the frozen weight says nothing. The
    F+ bound counts every unresolved assessment as a false allegation, so it fails when it exceeds the
    tolerance whatever the confirmed rate is; the explanation says how much of it is unresolved.
    """
    bounds = ctx.policy["controls"][name]
    key = {"false_alarm_upper": "max_false_alarm_upper", "completed_mass": "min_completed_mass",
           "assessable_mass": "min_assessable_mass"}[check]
    threshold = {"class": name, key: bounds[key]}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    block = ctx.whole("candidate")["controls"][name]
    if block["state"] != "ok":
        return _open(f"the {name} controls are unavailable: {block['reason']}", threshold)
    if block["canonical_controls"] == 0:
        return _open(f"the comparison plans no {name} control in {ctx.view_name}, so there is no false-alarm bound to "
                     "read, and none is assumed to be zero", threshold)
    counts = {"observations": block["observations"], "completed": block["completed"],
              "resolved": block["resolved"], "unresolved": block["unresolved"],
              "false_allegations": block["false_allegations"],
              "observed_false_allegations": block["observed_false_allegations"]}
    if check == "false_alarm_upper":
        upper = block["completed_upper"]["value"]
        observed = {"false_alarm_upper": upper, "resolved_rate": block["resolved_rate"]["value"],
                    "completed_lower": block["completed_lower"], "completed_mass": block["completed_mass"],
                    "assessable_mass": block["assessable_mass"], **counts}
        if upper is None:
            return _open(f"no {name} control observation completed, so the completed false-alarm bound is undefined; "
                         "a failed scan is not a quiet one", threshold, observed)
        text = (f"the {name} false-alarm upper bound F+ is {_n(upper)} (confirmed rate {_n(observed['resolved_rate'])} "
                f"on resolved controls; {block['unresolved']} unresolved assessment(s) counted as false allegations)")
        if upper <= bounds[key]:
            return PASS, observed, threshold, f"{text}, within the allowed {_n(bounds[key])}"
        return FAIL, observed, threshold, f"{text}, above the allowed {_n(bounds[key])}"
    mass = block[check]
    observed = {check: mass, **counts}
    word = "completed" if check == "completed_mass" else "resolved (assessable)"
    if mass is None:
        return _open(f"the {word} {name} control mass is undefined", threshold, observed)
    text = (f"the {word} {name} control mass is {_n(mass)} ({block['completed']} of {block['observations']} "
            f"observations completed, {block['resolved']} resolved)")
    if mass >= bounds[key]:
        return PASS, observed, threshold, f"{text}, at least the required {_n(bounds[key])}"
    return _open(f"{text}, below the required {_n(bounds[key])}: failed and unresolved controls are not quiet ones, "
                 "so the false-alarm bound rests on too little of the frozen weight", threshold, observed)


def _completion_minimum(ctx: _Context) -> Result:
    minimum = ctx.policy["completion"]["min"]
    threshold = {"min": minimum}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    completion = ctx.whole("candidate")["completion"]
    observed = {"baseline": ctx.whole("baseline")["completion"]["value"], "candidate": completion["value"],
                "statuses": completion["statuses"], "failures": completion["failures"]}
    if completion["value"] is None:
        return _open("no input was assigned in this view, so completion is undefined", threshold, observed)
    text = (f"the candidate completed {_n(completion['value'])} of the assigned work "
            f"({_counts_text(completion['statuses'])} scan(s) by status)")
    if completion["value"] >= minimum:
        return PASS, observed, threshold, f"{text}, at least the required {_n(minimum)}"
    return FAIL, observed, threshold, f"{text}, below the required {_n(minimum)}"


def _completion_decrease(ctx: _Context) -> Result:
    limit = ctx.policy["completion"]["max_decrease"]
    threshold = {"max_decrease": limit}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    change = ctx.differences[("all", None)]["completion"]
    observed = {"baseline": ctx.whole("baseline")["completion"]["value"],
                "candidate": ctx.whole("candidate")["completion"]["value"], "difference": change}
    if change is None:
        return _open("no input was assigned in this view, so completion is undefined", threshold, observed)
    text = (f"completion went from {_n(observed['baseline'])} to {_n(observed['candidate'])}, "
            f"{_signed(change)}")
    if -change <= limit:
        return PASS, observed, threshold, f"{text}, a decrease of at most the allowed {_n(limit)}"
    return FAIL, observed, threshold, f"{text}, a decrease of more than the allowed {_n(limit)}"


def _target_coverage(ctx: _Context) -> Result:
    """The assessable target mass of BOTH systems: an unresolved baseline flatters any candidate."""
    minimum = ctx.policy["target_coverage"]["min_assessable_mass"]
    weighting = ctx.policy["primary"]["weighting"]
    threshold = {"weighting": weighting, "min_assessable_mass": minimum}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    covered = {}
    for side in SIDES:
        block = next((item for item in ctx.whole(side)["detection"] if item["weighting"] == weighting), None)
        if block is None or block["state"] != "ok":
            return _open(f"{weighting} target coverage is unavailable for the {side}: "
                         f"{'no such weighting' if block is None else block['reason']}", threshold)
        covered[side] = block["coverage"]
    observed = {side: {key: covered[side][key] for key in ("assessable_mass", "completed_mass", "assessable",
                                                           "target_observations")} for side in SIDES}
    short = [side for side in SIDES if covered[side]["assessable_mass"] < minimum]
    if not short:
        return (PASS, observed, threshold,
                f"the assessable target mass is {_n(covered['baseline']['assessable_mass'])} for the baseline and "
                f"{_n(covered['candidate']['assessable_mass'])} for the candidate, at least the required {_n(minimum)}")
    parts = [f"the {side} has {covered[side]['assessable']} of {covered[side]['target_observations']} target "
             f"observations assessable, a mass of {_n(covered[side]['assessable_mass'])}" for side in short]
    return _open(f"{'; '.join(parts)}, below the required {_n(minimum)}: unresolved or failed observations count "
                 "as misses, so recall over them is a lower bound and the improvement is not established",
                 threshold, observed)


# --- review burden and cost ---------------------------------------------------------------------


def _ratio_reading(candidate: Fraction, baseline: Fraction, noun: str) -> tuple[Fraction | None, str]:
    """The exact ratio of *candidate* to *baseline* (``None`` when unbounded) and how it reads.

    A baseline of zero has no ratio: a candidate that is also zero has not increased, and any more is an
    unbounded increase, which is over every limit.
    """
    if baseline == 0:
        if candidate == 0:
            return Fraction(1), f"the {noun} is zero for both systems, so there is no increase"
        return None, f"the baseline's {noun} is zero, so any amount is an unbounded increase over it"
    ratio = candidate / baseline
    return ratio, (f"the candidate's {noun} is {_n(float(candidate))} against the baseline's "
                   f"{_n(float(baseline))}, a ratio of {_n(float(ratio))}")


def _volume(ctx: _Context, side: str) -> tuple[dict, dict[str, Fraction | None]]:
    """One system's whole-view claim volume as the burden requirements read it, and its exact shares.

    The claim counts are integers, so claims per assignment and the duplicate share are exact fractions;
    the first result records them as floats for the decision.
    """
    claims = ctx.whole(side)["claims"]
    records, assignments = claims["records"], claims["assignments"]
    exact = {"claims_per_assignment": Fraction(records, assignments) if assignments else None,
             "duplicate_share": Fraction(claims["duplicate_copies"], records) if records else None}
    seen = {"records": records, "unique": claims["unique"], "duplicate_copies": claims["duplicate_copies"],
            "assignments": assignments, "bundles": claims["bundles"],
            **{name: None if value is None else float(value) for name, value in exact.items()}}
    return seen, exact


def _burden(ctx: _Context, check: str) -> Result:
    """One review-burden requirement, from the claim records the candidate delivered.

    Claims per assignment is the delivered claim records over every assignment of the whole view, and
    the duplicate share is the exact-duplicate copies over the delivered records, so a candidate cannot
    lower either by failing to deliver output the requirement can see, and duplicates add burden
    without adding a claim. A system that delivered no result bundle at all has an unknown volume, not
    a zero one.
    """
    burden = ctx.policy["burden"]
    key = {"claims_per_assignment": "max_claims_per_assignment", "duplicate_share": "max_duplicate_share",
           "increase_ratio": "max_increase_ratio"}[check]
    threshold = {key: burden[key]}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    read = {side: _volume(ctx, side) for side in SIDES}
    volumes = {side: read[side][0] for side in SIDES}
    exact = {side: read[side][1] for side in SIDES}
    mine = volumes["candidate"]
    limit = _exact(burden[key])
    sides = SIDES if check == "increase_ratio" else ("candidate",)
    for side in sides:
        if volumes[side]["bundles"] == 0 or volumes[side]["assignments"] == 0:
            return _open(f"no result bundle was read for the {side}, so its delivered claim volume is unknown, not "
                         "zero", threshold, volumes[side])
    if check == "claims_per_assignment":
        text = (f"the candidate delivered {mine['records']} claim record(s) over {mine['assignments']} "
                f"assignment(s), {_n(mine['claims_per_assignment'])} per assignment")
        if exact["candidate"]["claims_per_assignment"] <= limit:
            return PASS, mine, threshold, f"{text}, within the allowed {_n(burden[key])}"
        return FAIL, mine, threshold, f"{text}, above the allowed {_n(burden[key])}"
    if check == "duplicate_share":
        if mine["records"] == 0:
            return PASS, mine, threshold, "the candidate delivered no claim record, so it delivered no duplicate copy"
        text = (f"{mine['duplicate_copies']} of the candidate's {mine['records']} delivered claim record(s) are exact "
                f"duplicates of another record of the same scan, a share of {_n(mine['duplicate_share'])}")
        if exact["candidate"]["duplicate_share"] <= limit:
            return PASS, mine, threshold, f"{text}, within the allowed {_n(burden[key])}"
        return FAIL, mine, threshold, f"{text}, above the allowed {_n(burden[key])}"
    ratio, reading = _ratio_reading(exact["candidate"]["claims_per_assignment"],
                                    exact["baseline"]["claims_per_assignment"], "claim volume per assignment")
    observed = {side: volumes[side]["claims_per_assignment"] for side in SIDES}
    observed["ratio"] = None if ratio is None else float(ratio)
    if ratio is not None and ratio <= limit:
        return PASS, observed, threshold, f"{reading}, within the allowed {_n(burden[key])}"
    return FAIL, observed, threshold, f"{reading}, above the allowed {_n(burden[key])}"


def _spend(ctx: _Context, side: str) -> dict:
    """One system's whole-view cost as the cost requirements read it.

    ``mean`` is the recorded cost of a scan, averaged over the scans whose cost is known, and ``None``
    when none is. Usage is counted once per executed scan, however many targets it covers.
    """
    usage = ctx.whole(side)["usage"]
    cost = usage["cost_usd"]
    spend = {"coverage": cost["coverage"], "known": cost["known"], "unknown": cost["unknown"],
             "scans": usage["bundles"], "known_sum": cost["known_sum"], "mean": None}
    mean = _mean(spend)
    spend["mean"] = None if mean is None else float(mean)
    return spend


def _mean(spend: dict) -> Fraction | None:
    """The exact mean cost of a scan whose cost is known: the recorded sum, read as a decimal, over their count."""
    return _exact(spend["known_sum"]) / spend["known"] if spend["known"] else None


def _cost_gap(ctx: _Context, sides: tuple[str, ...]) -> tuple[dict, str | None]:
    """The spend of each side, and why the cost cannot be relied on, if it cannot.

    The policy's ``min_coverage`` is the share of executed scans whose cost must be known; without it
    every cost must be. An unknown cost is unknown, never free, so a shortfall is unresolved.
    """
    required = ctx.policy["cost"].get("min_coverage", 1.0)
    spends = {side: _spend(ctx, side) for side in sides}
    for side in sides:
        spend = spends[side]
        if spend["coverage"] is None:
            return spends, f"no scan of the {side} recorded a result, so its cost is unknown, not zero"
        if spend["coverage"] < required:
            return spends, (f"the {side}'s cost is known for {spend['known']} of {spend['scans']} executed scan(s), a "
                            f"coverage of {_n(spend['coverage'])}, below the required {_n(required)}"
                            + ("" if "min_coverage" in ctx.policy["cost"] else
                               " (the policy states no lower minimum, so every cost must be known)"))
    return spends, None


def _cost_coverage(ctx: _Context) -> Result:
    cost = ctx.policy["cost"]
    required = cost.get("min_coverage", 1.0)
    threshold = {"min_coverage": required, "stated_by_policy": "min_coverage" in cost}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    sides = SIDES if "max_increase_ratio" in cost else ("candidate",)
    spends, gap = _cost_gap(ctx, sides)
    observed = {side: {key: spends[side][key] for key in ("coverage", "known", "unknown", "scans")} for side in sides}
    if gap is not None:
        return _open(gap, threshold, observed)
    known = "; ".join(f"the {side}'s cost is known for {spends[side]['known']} of {spends[side]['scans']} executed "
                      f"scan(s)" for side in sides)
    return PASS, observed, threshold, f"{known}, at least the required coverage of {_n(required)}"


def _cost_per_assignment(ctx: _Context) -> Result:
    limit = ctx.policy["cost"]["max_per_assignment_usd"]
    threshold = {"max_per_assignment_usd": limit}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    spends, gap = _cost_gap(ctx, ("candidate",))
    mine = spends["candidate"]
    if gap is not None:
        return _open(f"the candidate's cost per scan is not established: {gap}", threshold, mine)
    text = f"the candidate's recorded cost is {_n(mine['mean'])} USD per executed scan, over {mine['known']} scan(s)"
    if _mean(mine) <= _exact(limit):
        return PASS, mine, threshold, f"{text}, within the allowed {_n(limit)}"
    return FAIL, mine, threshold, f"{text}, above the allowed {_n(limit)}"


def _cost_increase(ctx: _Context) -> Result:
    limit = ctx.policy["cost"]["max_increase_ratio"]
    threshold = {"max_increase_ratio": limit}
    problem = ctx.missing_view()
    if problem is not None:
        return _open(problem, threshold)
    spends, gap = _cost_gap(ctx, SIDES)
    if gap is not None:
        return _open(f"the change in cost is not established: {gap}", threshold, spends)
    ratio, reading = _ratio_reading(_mean(spends["candidate"]), _mean(spends["baseline"]),
                                    "recorded cost per executed scan")
    observed = {"baseline": spends["baseline"]["mean"], "candidate": spends["candidate"]["mean"],
                "ratio": None if ratio is None else float(ratio)}
    if ratio is not None and ratio <= _exact(limit):
        return PASS, observed, threshold, f"{reading}, within the allowed {_n(limit)}"
    return FAIL, observed, threshold, f"{reading}, above the allowed {_n(limit)}"


# --- evaluation ---------------------------------------------------------------------------------


_FIXED: dict[str, Callable[[_Context], Result]] = {
    "contract.shared": _contract_shared,
    "contract.runs_completed": _runs_completed,
    "configuration.allowed_differences": _configuration_differences,
    "evidence.scope": _evidence_scope,
    "primary.improvement": _primary_improvement,
    "primary.uncertainty": _primary_uncertainty,
    "precision.binding": _precision_binding,
    "precision.min_value": _precision_min_value,
    "precision.max_unresolved_share": _precision_unresolved_share,
    "precision.min_evidence_grade": _precision_grade,
    "precision.min_coverage": _precision_coverage,
    "precision.interval": _precision_interval,
    "precision.max_decrease": _precision_decrease,
    "completion.min": _completion_minimum,
    "completion.max_decrease": _completion_decrease,
    "target_coverage.min_assessable_mass": _target_coverage,
    "cost.coverage": _cost_coverage,
    "cost.per_assignment": _cost_per_assignment,
    "cost.increase_ratio": _cost_increase,
}


def _requirement(requirement_id: str, ctx: _Context) -> Result:
    """Evaluate one requirement by its id; an id nothing evaluates is an internal error, not a pass."""
    fixed = _FIXED.get(requirement_id)
    if fixed is not None:
        return fixed(ctx)
    family, _, rest = requirement_id.partition(".")
    if family == "regression" and rest in ctx.regressions:
        return _regression(ctx, ctx.regressions[rest])
    if family == "controls":
        name, _, check = rest.partition(".")
        return _control(ctx, name, check)
    if family == "burden":
        return _burden(ctx, rest)
    raise ContractError(f"this build has no evaluator for the requirement {requirement_id}")


def _estimate_record(estimate: dict | None) -> dict | None:
    """What a decision binds of one precision estimate: its digest, version, and the digests it names."""
    if estimate is None:
        return None
    return {"sha256": canonical_sha256(estimate), "evaluator_version": estimate["evaluator_version"],
            "sample_sha256": estimate["sample_sha256"], "frame_sha256": estimate["frame_sha256"],
            "reviews_sha256": estimate["reviews_sha256"]}


def _comparison_record(comparison: dict) -> dict:
    """What a decision binds of the comparison: its digest, the systems, and the runs it read."""
    fields = ("run_id", "status", "manifest_sha256", "schedule_sha256", "config_sha256", "evidence_sha256")
    return {"sha256": canonical_sha256(comparison), "evaluator_version": comparison["evaluator_version"],
            "policy_sha256": comparison["policy_sha256"],
            "contract_sha256": comparison["contract"]["structure_sha256"],
            "baseline": {key: comparison["baseline"][key] for key in ("system_id", "config_sha256")},
            "candidate": {key: comparison["candidate"][key] for key in ("system_id", "config_sha256")},
            "runs": [{key: run[key] for key in fields} for run in comparison["runs"]]}


def _notes(ctx: _Context, declared: list[str]) -> list[str]:
    """The standing statements, then what the policy left out and what the gate was given and did not read."""
    notes = list(STANDING_NOTES)
    undeclared = [name for name in GATE_BLOCKS if name not in declared]
    if undeclared:
        notes.append(f"The policy declares no {', '.join(undeclared)} block, so those requirements are not part "
                     "of it and were not evaluated.")
    supplied = [side for side in SIDES if ctx.estimates[side] is not None]
    if "precision" not in ctx.policy and supplied:
        notes.append(f"A precision estimate was supplied for the {' and '.join(supplied)} but the policy declares "
                     "no precision block, so it is recorded by digest and was not read.")
    elif "baseline" in supplied and "max_decrease_vs_baseline" not in ctx.policy.get("precision", {}):
        notes.append("A baseline precision estimate was supplied, but the policy declares no maximum decrease from "
                     "the baseline, so it is recorded by digest and was not read.")
    comparison = ctx.comparison
    if comparison["evaluator_version"] != __version__:
        notes.append(f"The comparison was computed by evaluator {comparison['evaluator_version']} and this "
                     f"decision by {__version__}.")
    others = [f"{view['mode']}/{view['profile']}" for view in comparison["views"]
              if f"{view['mode']}/{view['profile']}" != ctx.view_name]
    if others:
        notes.append(f"The comparison also holds view(s) {', '.join(others)}; this policy reads only "
                     f"{ctx.view_name}.")
    return notes


def evaluate_gate(policy: dict, comparison: dict, precision_baseline: dict | None = None,
                  precision_candidate: dict | None = None) -> dict:
    """The validated gate decision of *comparison* under *policy*, with the optional precision estimates.

    *policy* is validated and completed (:func:`resolve_policy`); *comparison* is a ``comparison-report``
    and each estimate a ``precision-estimate``, all validated first. Nothing is modified and nothing is
    written. Every requirement the policy declares is evaluated (:func:`scaneval.contracts.
    gate_requirement_ids` names them, in order) and the outcome follows from their statuses: fail if any
    failed, else inconclusive if any is inconclusive, else pass. The recommendation scope says what the
    decision can support: ``reviewed`` when the policy requires reviewed evidence and the evidence was
    reviewed, ``development`` when the policy itself declares draft scope and the evidence met it, and
    ``none`` when the evidence did not meet the policy's scope. The decision binds its policy, comparison,
    estimates, evaluator version, and the runs and schedules the comparison read by digest, so the same
    inputs give the same bytes; there is no clock, network, randomness, or model here.

    Refused with :class:`ContractError` before anything is decided: a document that is not what it is
    named, and a policy whose primary metric is a random-order expectation or any other diagnostic. A
    comparison that contradicts itself is not refused: it fails ``contract.shared``.
    """
    policy = resolve_policy(policy)
    validate_document(COMPARISON_KIND, comparison)
    estimates = {"baseline": precision_baseline, "candidate": precision_candidate}
    for estimate in estimates.values():
        if estimate is not None:
            validate_document(ESTIMATE_KIND, estimate)
    ctx = _Context(policy, comparison, estimates)
    requirements = []
    for requirement_id in gate_requirement_ids(policy):
        status, observed, threshold, explanation = _requirement(requirement_id, ctx)
        requirements.append({"id": requirement_id, "status": status, "observed": observed,
                             "threshold": threshold, "explanation": explanation})
    statuses = [requirement["status"] for requirement in requirements]
    outcome = FAIL if FAIL in statuses else INCONCLUSIVE if INCONCLUSIVE in statuses else PASS
    evidence = next(requirement for requirement in requirements if requirement["id"] == "evidence.scope")
    scope = ("none" if evidence["status"] != PASS else
             "reviewed" if policy["required_scope"] == "reviewed" else "development")
    declared = gate_declared_blocks(policy)
    decision = {
        "schema_version": SCHEMA_VERSION, "evaluator_version": __version__,
        "outcome": outcome, "recommendation_scope": scope,
        "policy": policy, "policy_sha256": canonical_sha256(policy),
        "blocks": {"declared": declared, "not_declared": [name for name in GATE_BLOCKS if name not in declared]},
        "view": deepcopy(policy["view"]),
        "comparison": _comparison_record(comparison),
        "precision": {side: _estimate_record(estimate) for side, estimate in estimates.items()},
        "requirements": requirements,
        "summary": {"requirements": len(requirements), "passed": statuses.count(PASS),
                    "failed": statuses.count(FAIL), "inconclusive": statuses.count(INCONCLUSIVE)},
        "failed": [item["id"] for item in requirements if item["status"] == FAIL],
        "unresolved": [item["id"] for item in requirements if item["status"] == INCONCLUSIVE],
        "notes": _notes(ctx, declared),
    }
    return validate_document(DECISION_KIND, decision)


# --- summary for the command line ---------------------------------------------------------------


def summary(decision: dict) -> list[str]:
    """The lines a person needs: the outcome and its scope, every failed or unresolved requirement, and the notes.

    The notes are the decision's conditional ones (the blocks the policy left out, an estimate that was
    supplied and not read, another view left alone), not the statements every decision carries.
    """
    comparison = decision["comparison"]
    view = decision["view"]
    counts = decision["summary"]
    lines = [
        f"Gate {decision['outcome']}: baseline={comparison['baseline']['system_id']} "
        f"candidate={comparison['candidate']['system_id']} view={view['mode']}/{view['profile']} "
        f"recommendation_scope={decision['recommendation_scope']}",
        f"Policy {decision['policy']['policy_id']} {decision['policy']['policy_version']} "
        f"({decision['policy_sha256']})",
        f"Requirements: {counts['requirements']} evaluated, {counts['passed']} passed, {counts['failed']} "
        f"failed, {counts['inconclusive']} inconclusive",
    ]
    by_id = {requirement["id"]: requirement for requirement in decision["requirements"]}
    for requirement_id in decision["failed"]:
        lines.append(f"FAIL {requirement_id}: {by_id[requirement_id]['explanation']}")
    for requirement_id in decision["unresolved"]:
        lines.append(f"INCONCLUSIVE {requirement_id}: {by_id[requirement_id]['explanation']}")
    lines += [f"Note: {note}" for note in decision["notes"][len(STANDING_NOTES):]]
    return lines
