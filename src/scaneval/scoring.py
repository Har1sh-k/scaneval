"""Pure, single-input scoring of saved claims and frozen review decisions.

This module does not infer root causes from prose or location overlap. An
accepted match is a supplied evaluator decision, never a scanner's verdict.
Cross-input weighting and publication gates are deliberately not implemented.
"""

from collections import defaultdict
from math import comb
import posixpath

from . import __version__
from .contracts import ContractError, canonical_sha256, validate_document


def _text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _location(location: dict) -> dict:
    return {
        **location,
        "path": posixpath.normpath(location["path"].replace("\\", "/")),
    }


def claim_fingerprint(claim: dict) -> str:
    """v2 exact-structured duplicate identity, not semantic similarity.

Delivery IDs, raw-artifact references and native ranks are not an allegation.
Different evidence or related locations remain distinct, even at one sink.
"""
    return canonical_sha256({
        "allegation": _text(claim["allegation"]),
        "kind": claim["kind"],
        "native_rule_id": claim.get("native_rule_id"),
        "primary_location": _location(claim["primary_location"]),
        "related_locations": [_location(x) for x in claim.get("related_locations", [])],
        "evidence_text": _text(claim.get("evidence_text", "")),
    })


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _unexamined_controls(plan: dict, result: dict) -> set[str]:
    """The ids of the planned controls the saved scan is known not to have examined.

    A result may list ``omitted_paths``: paths of its input the adapter observed the scanner did not
    examine. A control is unexamined when it sits on one of them, or when the plan does not say where
    it is (it has no ``paths``) while the result lists any, because a control the plan does not place
    cannot be shown to lie outside an omission. A result that lists none leaves every control as
    examined as this can tell. Both lists are another party's statement, the pack's for the plan and
    the adapter's for the result, and this checks neither. It reads only the paths a result lists, so
    a control on a path the listing never names is not here, whether or not the scanner read it.
    """
    omitted = set(result.get("omitted_paths") or ())
    if not omitted:
        return set()
    return {control["control_id"] for control in plan["controls"]
            if not control.get("paths") or not omitted.isdisjoint(control["paths"])}


def _control_observations(plan: dict, result: dict, decisions: dict, claim_ids: set) -> dict:
    """Per control, what this one saved scan establishes about it, in plan order.

    ``completed`` is the scan's own claim to a valid complete observation, which only ``success``
    makes. ``resolved`` needs that completion and a resolved assessment: a confirmed false
    allegation, or a quiet assessment over output whose bundles are resolved, because silence
    about a claim nobody has split is not silence. A quiet assessment also resolves nothing for a
    control the scan is known not to have examined (:func:`_unexamined_controls`), because a scanner
    that never read a path says nothing about what is on it; the control stays a completed
    observation that is unresolved, and a confirmed false allegation about it still resolves it.
    ``false_allegation`` is the completed-only numerator, and ``observed_false_allegation`` keeps a
    reviewed failure from incomplete output visible without letting that output into the rate.
    """
    controls = {x["control_id"]: x for x in plan["controls"]}
    unexamined = _unexamined_controls(plan, result)
    assessments = {}
    for assessment in decisions["control_assessments"]:
        control_id = assessment["control_id"]
        if control_id not in controls:
            raise ContractError(f"Unknown control in review: {control_id}")
        if not set(assessment["claim_ids"]).issubset(claim_ids):
            raise ContractError(f"Unknown claim in control assessment: {control_id}")
        assessments[control_id] = assessment
    completed = result["status"] == "success"
    observations = {}
    for control_id, control in controls.items():
        assessment = assessments.get(control_id)
        decision = assessment["decision"] if assessment else "unresolved"
        # A confirmed allegation is enough for failure, but quietness
        # requires assessable full output, including unresolved bundles.
        confirmed_false = decision == "false_allegation"
        quiet = decision == "quiet" and result["bundles_resolved"] and control_id not in unexamined
        observations[control_id] = {
            "type": control["type"],
            "decision": decision,
            "completed": completed,
            "resolved": completed and (confirmed_false or quiet),
            "false_allegation": completed and confirmed_false,
            "observed_false_allegation": confirmed_false,
        }
    return observations


def _random_order_probability(delivered: int, hits: int, budget: int) -> float:
    """Chance that a uniform random order of *delivered* claims puts one of *hits* in the first *budget*.

    The complement of drawing no accepted claim in the first ``min(budget, delivered)`` positions,
    with duplicates delivered as the separate positions they occupy. Zero for empty output and for
    a target no claim hit.
    """
    b = min(budget, delivered)
    if not (delivered and hits):
        return 0.0
    return 1 - (comb(delivered - hits, b) / comb(delivered, b) if delivered - hits >= b else 0)


def observe(plan: dict, result: dict, decisions: dict) -> dict:
    """What one saved scan establishes about each planned target and control, one record each.

    This is the per-observation layer :func:`score` summarizes and corpus aggregation weights, so
    both read the same decisions the same way: bindings are checked first, one claim or exact
    duplicate group can hit at most one target, a duplicate earns no second hit, an unresolved
    match earns nothing and is counted as pending, and only ``success`` output can make a control
    observation complete. A quiet assessment resolves a control only when the scan is not known to
    have left it unexamined, which a result's ``omitted_paths`` and a plan control's ``paths`` say;
    the observation is complete and unresolved otherwise, so it is counted and never dropped. A
    target's ``first_hit_rank`` is measured only for native order over resolved bundles;
    ``budget_measurable`` says whether a finite budget can be read off this scan at all, which is a
    different fact from a measured miss.

    Inputs are immutable, and nothing here reads a clock, the network, or a random source.
    """
    validate_document("evaluation-plan", plan)
    validate_document("scan-result", result)
    validate_document("review-decisions", decisions)
    digest = canonical_sha256(result)
    if plan["input_hash"] != result["input_hash"] or decisions["input_hash"] != result["input_hash"]:
        raise ContractError("Plan, result and decisions must bind to the same input hash")
    if decisions["run_id"] != result["run_id"]:
        raise ContractError("Review run_id does not match the saved result")
    if decisions["result_sha256"] != digest:
        raise ContractError("Review result_sha256 does not match the saved result")

    targets = {x["target_id"]: x for x in plan["targets"]}
    claims = {x["claim_id"]: x for x in result["claims"]}
    fingerprints = {claim_id: claim_fingerprint(claim) for claim_id, claim in claims.items()}
    groups = defaultdict(list)
    for claim_id, fingerprint in fingerprints.items():
        groups[fingerprint].append(claim_id)

    by_group_target = {}
    accepted = {}
    pending = set()
    for match in decisions["claim_matches"]:
        claim_id, target_id = match["claim_id"], match["target_id"]
        if claim_id not in claims:
            raise ContractError(f"Unknown claim in review: {claim_id}")
        if target_id not in targets:
            raise ContractError(f"Unknown target in review: {target_id}")
        fingerprint = fingerprints[claim_id]
        key = (fingerprint, target_id)
        state = match["decision"]
        if key in by_group_target and by_group_target[key] != state:
            raise ContractError("Conflicting frozen decisions for exact duplicate claims")
        by_group_target[key] = state
        if state == "accepted":
            if fingerprint in accepted and accepted[fingerprint] != target_id:
                raise ContractError("One claim or exact duplicate group cannot hit multiple targets")
            accepted[fingerprint] = target_id
        elif state == "unresolved":
            pending.add(key)

    control_observations = _control_observations(plan, result, decisions, set(claims))
    false_control_groups = {
        fingerprints[claim_id]
        for assessment in decisions["control_assessments"]
        if assessment["decision"] == "false_allegation"
        for claim_id in assessment["claim_ids"]
    }
    if false_control_groups.intersection(accepted):
        raise ContractError("An atomic claim cannot be both an accepted target hit and a false allegation")
    valid_positive_output = result["status"] in ("success", "partial")
    hits = defaultdict(list)
    if valid_positive_output:
        for fingerprint, target_id in accepted.items():
            hits[target_id].extend(groups[fingerprint])
    pending_targets = {target_id for _fingerprint, target_id in pending}

    budget_ready = result["ranking"] == "native" and result["bundles_resolved"]
    target_results = []
    for target_id in sorted(targets):
        first = None
        if hits[target_id] and budget_ready:
            first = min(claims[claim_id]["rank"] for claim_id in hits[target_id])
        target_results.append({
            "target_id": target_id,
            "detected": bool(hits[target_id]),
            "first_hit_rank": first,
            "hit_claims": len(hits[target_id]),
            "unresolved_match": target_id in pending_targets,
        })
    budgets = sorted(plan["review_budgets"])
    random_order = None
    if result["ranking"] == "unranked" and result["bundles_resolved"]:
        delivered = len(claims)
        # Plan order, which is the order the per-input expectation has always been summed in.
        random_order = {
            str(budget): {target_id: _random_order_probability(delivered, len(hits[target_id]), budget)
                          for target_id in targets}
            for budget in budgets
        }
    return {
        "result_sha256": digest,
        "plan_sha256": canonical_sha256(plan),
        "decisions_sha256": canonical_sha256(decisions),
        "status": result["status"],
        "ranking": result["ranking"],
        "bundles_resolved": result["bundles_resolved"],
        "completed": result["status"] == "success",
        "valid_positive_output": valid_positive_output,
        "budget_measurable": budget_ready,
        "review_budgets": budgets,
        "targets": target_results,
        "controls": [{"control_id": control_id, **observation}
                     for control_id, observation in control_observations.items()],
        "random_order": random_order,
        "claims": {
            "records": len(claims),
            "unique": len(groups),
            "duplicate_copies": len(claims) - len(groups),
            "delivered": len(claims) if result["bundles_resolved"] else None,
            "unmatched_unique": len(set(groups) - set(accepted) - false_control_groups),
            "pending_matching": len(pending),
        },
        "duplicate_groups": [
            {"canonical_claim_id": ids[0], "claim_ids": list(ids)}
            for ids in groups.values() if len(ids) > 1
        ],
        "usage": dict(result["usage"]),
    }


def _control_summary(observations: list[dict]) -> dict:
    """The per-input control view :func:`score` reports, one entry per control class."""
    output = {}
    for kind in ("capability_safe", "fixed_target"):
        eligible = [x for x in observations if x["type"] in (kind, "both")]
        assigned = len(eligible)
        completed = sum(x["completed"] for x in eligible)
        observed_false = sum(x["observed_false_allegation"] for x in eligible)
        resolved = sum(x["resolved"] for x in eligible)
        false = sum(x["false_allegation"] for x in eligible)
        output[kind] = {
            "assigned": assigned,
            "completed": completed,
            "resolved": resolved,
            "false_allegations": false,
            # Keep explicit failures visible outside the completed-only rate.
            "observed_false_allegations": observed_false,
            "resolved_false_alarm_rate": _ratio(false, resolved),
            "sensitivity_lower": _ratio(false, completed),
            "sensitivity_upper": _ratio(false + completed - resolved, completed),
            "completion_mass": _ratio(completed, assigned),
            "assessable_mass": _ratio(resolved, assigned),
        }
    return output


def score(plan: dict, result: dict, decisions: dict) -> dict:
    """Replay a single scan, using equal target/control weights within it.

Inputs are immutable. Every reference and decision-to-result binding is
checked before scoring. Only packaged local schemas are read. No network,
clock, randomness or LLM calls are used.
    """
    observation = observe(plan, result, decisions)
    target_results = [{"target_id": x["target_id"], "detected": x["detected"],
                       "first_hit_rank": x["first_hit_rank"]} for x in observation["targets"]]
    target_count = len(target_results)
    hit_count = sum(x["detected"] for x in target_results)
    budgets = observation["review_budgets"]
    budget_ready = observation["budget_measurable"]
    recall = {
        str(b): _ratio(sum(x["first_hit_rank"] is not None and x["first_hit_rank"] <= b
                           for x in target_results), target_count) if budget_ready else None
        for b in budgets
    }
    expected = None
    if observation["random_order"] is not None:
        expected = {}
        for budget in budgets:
            probability_sum = 0.0
            for probability in observation["random_order"][str(budget)].values():
                probability_sum += probability
            expected[str(budget)] = probability_sum / target_count if target_count else None
    claims = observation["claims"]

    warnings = []
    if plan["scope"] == "diagnostic":
        warnings.append("Diagnostic fixture results are not real-world benchmark evidence.")
    if plan["scope"] == "draft":
        warnings.append("Draft labels (not independently reviewed): pipeline diagnostics, not benchmark evidence.")
    if not result["bundles_resolved"]:
        warnings.append("Unresolved bundles: claim budgets and total atomic-claim burden are pending.")
    if claims["pending_matching"]:
        warnings.append("Unresolved target matches earn no confirmed detection credit.")
    if result["ranking"] == "unranked":
        warnings.append("Random-order expectation is not native prioritization or a promotion metric.")
    if result["status"] != "success":
        warnings.append("Incomplete or failed execution cannot establish a successful negative control.")
    unexamined = _unexamined_controls(plan, result)
    # Counted from the observation, so it names exactly the quiet assessments that would have resolved a control
    # but for the omission, and never one that something else already left unresolved.
    withheld = sum(1 for row in observation["controls"]
                   if row["decision"] == "quiet" and row["completed"] and result["bundles_resolved"]
                   and row["control_id"] in unexamined)
    if withheld:
        warnings.append(
            f"{withheld} quiet control assessment(s) earn no credit: the scan lists paths it did not examine, and each "
            "of these controls is on one of them or is placed by no path, so its silence says nothing about it.")

    return {
        "schema_version": "2.0",
        "scorer_version": __version__,
        "scope": plan["scope"],
        "run_id": result["run_id"],
        "system_id": result["system_id"],
        "input_hash": result["input_hash"],
        "result_sha256": observation["result_sha256"],
        "plan_sha256": observation["plan_sha256"],
        "decisions_sha256": observation["decisions_sha256"],
        "status": result["status"],
        "metrics": {
            "known_target_recall": _ratio(hit_count, target_count),
            "recall_at_budget": recall,
            "random_order_expected_recall": expected,
            "targets_assigned": target_count,
            "targets_detected": hit_count,
            "completed": observation["completed"],
            "claims_delivered": claims["delivered"],
            "claim_records": claims["records"],
            "unique_claims": claims["unique"],
            "duplicate_copies": claims["duplicate_copies"],
            "unmatched_unique_claims": claims["unmatched_unique"],
            "pending_matching_count": claims["pending_matching"],
            "controls": _control_summary(observation["controls"]),
            "usage": observation["usage"],
        },
        "targets": target_results,
        "duplicate_groups": observation["duplicate_groups"],
        "warnings": warnings,
    }
