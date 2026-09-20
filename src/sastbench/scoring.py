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


def _controls(plan: dict, result: dict, decisions: dict, claim_ids: set) -> dict:
    controls = {x["control_id"]: x for x in plan["controls"]}
    assessments = {}
    for assessment in decisions["control_assessments"]:
        control_id = assessment["control_id"]
        if control_id not in controls:
            raise ContractError(f"Unknown control in review: {control_id}")
        if not set(assessment["claim_ids"]).issubset(claim_ids):
            raise ContractError(f"Unknown claim in control assessment: {control_id}")
        assessments[control_id] = assessment

    output = {}
    for kind in ("capability_safe", "fixed_target"):
        eligible = [x for x in controls.values() if x["type"] in (kind, "both")]
        assigned = len(eligible)
        completed = assigned if result["status"] == "success" else 0
        observed_false = sum(
            assessments.get(control["control_id"], {}).get("decision") == "false_allegation"
            for control in eligible
        )
        resolved = false = 0
        if completed:
            for control in eligible:
                assessment = assessments.get(control["control_id"])
                decision = assessment["decision"] if assessment else "unresolved"
                # A confirmed allegation is enough for failure, but quietness
                # requires assessable full output, including unresolved bundles.
                if decision == "false_allegation":
                    resolved += 1
                    false += 1
                elif decision == "quiet" and result["bundles_resolved"]:
                    resolved += 1
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

    controls = _controls(plan, result, decisions, set(claims))
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

    target_results = []
    for target_id in sorted(targets):
        first = None
        if hits[target_id] and result["ranking"] == "native" and result["bundles_resolved"]:
            first = min(claims[claim_id]["rank"] for claim_id in hits[target_id])
        target_results.append({
            "target_id": target_id,
            "detected": bool(hits[target_id]),
            "first_hit_rank": first,
        })
    target_count = len(targets)
    hit_count = sum(x["detected"] for x in target_results)
    budgets = sorted(plan["review_budgets"])
    budget_ready = result["ranking"] == "native" and result["bundles_resolved"]
    recall = {
        str(b): _ratio(sum(x["first_hit_rank"] is not None and x["first_hit_rank"] <= b
                           for x in target_results), target_count) if budget_ready else None
        for b in budgets
    }
    expected = None
    if result["ranking"] == "unranked" and result["bundles_resolved"]:
        delivered = len(claims)
        expected = {}
        for budget in budgets:
            b = min(budget, delivered)
            probability_sum = 0.0
            for target_id in targets:
                h = len(hits[target_id])
                if delivered and h:
                    probability_sum += 1 - (comb(delivered - h, b) / comb(delivered, b)
                                            if delivered - h >= b else 0)
            expected[str(budget)] = probability_sum / target_count if target_count else None

    warnings = []
    if plan["scope"] == "diagnostic":
        warnings.append("Diagnostic fixture results are not real-world benchmark evidence.")
    if plan["scope"] == "draft":
        warnings.append("Draft labels (not independently reviewed): pipeline diagnostics, not benchmark evidence.")
    if not result["bundles_resolved"]:
        warnings.append("Unresolved bundles: claim budgets and total atomic-claim burden are pending.")
    if pending:
        warnings.append("Unresolved target matches earn no confirmed detection credit.")
    if result["ranking"] == "unranked":
        warnings.append("Random-order expectation is not native prioritization or a promotion metric.")
    if result["status"] != "success":
        warnings.append("Incomplete or failed execution cannot establish a successful negative control.")

    return {
        "schema_version": "2.0",
        "scorer_version": __version__,
        "scope": plan["scope"],
        "run_id": result["run_id"],
        "system_id": result["system_id"],
        "input_hash": result["input_hash"],
        "result_sha256": digest,
        "plan_sha256": canonical_sha256(plan),
        "decisions_sha256": canonical_sha256(decisions),
        "status": result["status"],
        "metrics": {
            "known_target_recall": _ratio(hit_count, target_count),
            "recall_at_budget": recall,
            "random_order_expected_recall": expected,
            "targets_assigned": target_count,
            "targets_detected": hit_count,
            "completed": result["status"] == "success",
            "claims_delivered": len(claims) if result["bundles_resolved"] else None,
            "claim_records": len(claims),
            "unique_claims": len(groups),
            "duplicate_copies": len(claims) - len(groups),
            "unmatched_unique_claims": len(set(groups) - set(accepted) - false_control_groups),
            "pending_matching_count": len(pending),
            "controls": controls,
            "usage": dict(result["usage"]),
        },
        "targets": target_results,
        "duplicate_groups": [
            {"canonical_claim_id": ids[0], "claim_ids": list(ids)}
            for ids in groups.values() if len(ids) > 1
        ],
        "warnings": warnings,
    }
