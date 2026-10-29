"""Evidence-bound CVSS calibration, independent of detection credit."""
from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
from decimal import Decimal
from fractions import Fraction
from html import escape
import json
from pathlib import Path

from . import aggregate, cases, review
from .contracts import ContractError, canonical_sha256, load_document, validate_document

BANDS = ("none", "low", "medium", "high", "critical")
LEGACY_VERSION = "severity-calibration-1"
VERSION = "severity-calibration-2"
SELECTION = "lowest native rank then claim_id; unranked: claim_id; directly accepted claims only"
_REFERENCE_SELECTIONS = {
    LEGACY_VERSION: "frozen pack-selected reference; identical rating aliases: lowest case_id; preserve all sources and notes",
    VERSION: "frozen pack-selected reference; equivalent rating aliases: lowest case_id; preserve all sources and notes",
}
REFERENCE_SELECTION = _REFERENCE_SELECTIONS[VERSION]
_V3 = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC", "C": "NLH", "I": "NLH", "A": "NLH"}
_V4 = {"AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA", "VC": "NLH", "VI": "NLH", "VA": "NLH", "SC": "NLH", "SI": "NLH", "SA": "NLH"}


def validate_claimed_cvss(value: dict) -> None:
    """Validate supplied base-score evidence, without inventing or recomputing scores."""
    if not isinstance(value, dict) or set(value) - {"score", "version", "vector", "provenance"}:
        raise ContractError("claimed_cvss must contain only score, version, provenance and optional vector")
    if not {"score", "version", "provenance"} <= set(value):
        raise ContractError("claimed_cvss requires score, version and provenance")
    score = value["score"]
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
        raise ContractError("claimed CVSS score must be a finite number between 0 and 10")
    if Decimal(str(score)) * 10 != (Decimal(str(score)) * 10).to_integral_value():
        raise ContractError("claimed CVSS score must have at most one decimal place")
    if value["version"] not in ("3.0", "3.1", "4.0"):
        raise ContractError("claimed CVSS version must be 3.0, 3.1 or 4.0")
    if value["provenance"] not in ("native", "imported", "self_reported"):
        raise ContractError("claimed CVSS requires declared numeric provenance")
    if "vector" in value:
        vector = value["vector"]
        if not isinstance(vector, str) or not vector.startswith(f"CVSS:{value['version']}/"):
            raise ContractError("claimed CVSS vector prefix must match its version")
        tokens = vector.split("/")[1:]
        metrics = _V4 if value["version"] == "4.0" else _V3
        parsed = {}
        for token in tokens:
            pair = token.split(":")
            if len(pair) != 2 or pair[0] in parsed or pair[0] not in metrics or len(pair[1]) != 1 or pair[1] not in metrics[pair[0]]:
                raise ContractError("claimed CVSS vector must contain valid, unique base metrics only")
            parsed[pair[0]] = pair[1]
        if set(parsed) != set(metrics):
            raise ContractError("claimed CVSS vector is missing base metrics")


def band(score: float) -> str:
    return "none" if score == 0 else "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"


def compare_severity(claim: dict, references: list[dict], *, calibrator_version: str = VERSION) -> dict:
    """Compare one selected claim with the references of its canonical target."""
    native = claim.get("native_severity")
    numeric = deepcopy(claim.get("claimed_cvss"))
    result = {"native_severity": native, "claimed_cvss": numeric,
              "claimed_provenance": numeric["provenance"] if numeric else ("native" if native is not None else "unavailable"),
              "normalized_band": None, "reference": None, "reference_band": None,
              "status": "unavailable", "reason": None, "outcome": None, "band_error": None,
              "numeric_delta": None, "numeric_reason": None, "cross_version": False}

    def unavailable(reason):
        result["reason"] = result["numeric_reason"] = reason
        return result

    if calibrator_version not in _REFERENCE_SELECTIONS:
        raise ContractError(f"unsupported severity calibrator version {calibrator_version!r}")
    if not references or any(entry["severity"] is None for entry in references):
        return unavailable("reference_unavailable")
    if calibrator_version == LEGACY_VERSION:
        ratings = {canonical_sha256({k: entry["severity"][k] for k in ("score", "cvss_version", "vector")}) for entry in references}
        if len(ratings) != 1:
            return unavailable("conflicting_references")
        ref = deepcopy(sorted(references, key=lambda entry: entry["case_id"])[0]["severity"])
        result["reference"] = ref
        try:
            validate_claimed_cvss({"score": ref["score"], "version": ref["cvss_version"],
                                   "vector": ref["vector"], "provenance": "imported"})
        except ContractError:
            return unavailable("invalid_reference_cvss")
    else:
        ratings = []
        for entry in references:
            try:
                rating = {k: entry["severity"][k] for k in ("score", "cvss_version", "vector")}
                validate_claimed_cvss({"score": rating["score"], "version": rating["cvss_version"],
                                       "vector": rating["vector"], "provenance": "imported"})
                prefix, *tokens = rating["vector"].split("/")
                ratings.append((Decimal(str(rating["score"])), rating["cvss_version"],
                                "/".join((prefix, *sorted(tokens)))))
            except (ContractError, KeyError, TypeError):
                return unavailable("invalid_reference_cvss")
        if len(set(ratings)) != 1:
            return unavailable("conflicting_references")
        ref = deepcopy(sorted(references, key=lambda entry: entry["case_id"])[0]["severity"])
        result["reference"] = ref
    result["reference_band"] = band(ref["score"])
    label = native.strip().lower() if isinstance(native, str) else None
    label_band = label if label in BANDS else None
    if numeric is not None:
        validate_claimed_cvss(numeric)
        result["normalized_band"] = band(numeric["score"])
        result["cross_version"] = numeric["version"] != ref["cvss_version"]
        if result["cross_version"]:
            return unavailable("cvss_version_mismatch")
        if label_band is not None and label_band != result["normalized_band"]:
            return unavailable("conflicting_claimed_severity")
        result["numeric_delta"] = float(Decimal(str(numeric["score"])) - Decimal(str(ref["score"])))
    else:
        result["normalized_band"] = label_band
        if label_band is None:
            return unavailable("claimed_severity_missing" if native is None else "unmapped_severity_label")
        result["numeric_reason"] = "qualitative_only"
    error = BANDS.index(result["normalized_band"]) - BANDS.index(result["reference_band"])
    result.update(status="assessed", band_error=error,
                  outcome="exact" if error == 0 else "overestimated" if error > 0 else "underestimated")
    return result


def _read_observation(corpus, observation):
    run = next(run for run in corpus.runs if run.run_id == observation.run_id)
    invocation = next((row for row in run.manifest["invocations"] if row["invocation_id"] == observation.assignment_id), None)
    if invocation is None or not invocation.get("bundle_path") or observation.observed is None:
        return None
    bundle = aggregate._inside(run.directory, invocation["bundle_path"], "bundle_path")
    plan, decisions, record = review.load_evaluator(bundle, guard_symlinks=False)
    result = load_document(bundle / review.RESULT_FILE, "scan-result")
    # Recheck the exact documents we use, rather than rely on earlier cached observations.
    from .scoring import observe
    observe(plan, result, decisions)
    if any(observation.observed[name + "_sha256"] != canonical_sha256(value) for name, value in (("plan", plan), ("decisions", decisions), ("result", result))):
        raise ContractError("severity evidence changed while reading the run")
    state = ("missing" if record is None else "stale" if
             record["plan_sha256"] != canonical_sha256(plan) or record["decisions_sha256"] != canonical_sha256(decisions)
             or record["run_id"] != result["run_id"] else record["state"])
    if state != observation.review_state:
        raise ContractError("severity review state changed while reading the run")
    return plan, decisions, record, result


def _pack_content(pack):
    """Remove only fields mechanical checks can update; retain labels and review history."""
    projection = deepcopy(pack)
    projection.pop("anchor_sha256", None)
    for snapshot in projection["snapshots"]:
        snapshot.pop("tree_hash", None)
    for case in projection["cases"]:
        for field in ("checks", "check_sets", "checks_failed", "level", "review_state"):
            case["validation"].pop(field, None)
    return projection


def _frozen_packs(corpus, pack):
    frozen = {}
    expected = canonical_sha256(_pack_content(pack))
    for run in corpus.runs:
        path = aggregate._inside(run.directory, "evaluator/pack.json", "frozen evaluator pack")
        if not path.exists():
            frozen[run.run_id] = None
            continue
        current = load_document(path, "case-pack")
        if canonical_sha256(_pack_content(current)) != expected:
            raise ContractError("frozen evaluator pack changed configured labels, reference severity or review history")
        actual_snapshots = {s["snapshot_id"]: s for s in current["snapshots"]}
        if any(s.get("tree_hash") is not None and actual_snapshots[s["snapshot_id"]].get("tree_hash") != s["tree_hash"] for s in pack["snapshots"]):
            raise ContractError("frozen evaluator pack changed a configured source tree hash")
        frozen[run.run_id] = canonical_sha256(current)
    return frozen


def _records(corpus, pack, frozen_packs, calibrator_version):
    by_case = {case["case_id"]: case for case in pack["cases"]}
    references = defaultdict(list)
    for case in pack["cases"]:
        references[cases.target_canonical_id(case)].append({"case_id": case["case_id"], "severity": deepcopy(case.get("severity")),
                                                           "case_sha256": canonical_sha256(case)})
    for entries in references.values():
        entries.sort(key=lambda entry: entry["case_id"])
    rows = []
    unplanned = []
    for key, observation in sorted(corpus.observations.items()):
        scheduled = corpus.inputs[key[:2]]
        frozen = scheduled["plan"]
        condition = observation.condition or {}
        identity = {"run_id": observation.run_id, "input_id": observation.input_id,
                    "system_id": observation.system_id, "assignment_id": observation.assignment_id,
                    "repetition": observation.repetition, "mode": scheduled["mode"], "profile": scheduled["profile"],
                    "condition": condition.get("condition", "unavailable"), "condition_status": condition.get("status", "unavailable"),
                    "evidence_scope": observation.scope or "unavailable"}
        if frozen["state"] != "frozen":
            unplanned.append({**identity, "reason": "frozen_plan_unavailable", "detail": frozen.get("reason", "")})
            continue
        groups = defaultdict(list)
        for target in frozen.get("targets", []):
            case = by_case.get(target["case_id"])
            if case is None or case["target"]["target_id"] != target["target_id"] or cases.target_canonical_id(case) != target["canonical_id"]:
                raise ContractError("scheduled target identity does not match the supplied frozen pack")
            groups[target["canonical_id"]].append(target)
        evidence = _read_observation(corpus, observation)
        for canonical, targets in sorted(groups.items()):
            target_ids = sorted(target["target_id"] for target in targets)
            row = {**identity,
                   "canonical_id": canonical, "target_ids": target_ids, "status": "excluded",
                   "reason": observation.reason, "matched": False, "selected_claim": None, "accepted_claim_ids": [],
                   "references": sorted(references[canonical], key=lambda entry: entry["case_id"]),
                   "comparison": None, "bindings": {"targets_sha256": canonical_sha256(targets),
                                                      "references_sha256": canonical_sha256(references[canonical])}}
            if evidence is None:
                row["reason"] = row["reason"] or "evidence_unavailable"
                rows.append(row)
                continue
            plan, decisions, record, result = evidence
            row["bindings"].update({name + "_sha256": canonical_sha256(value) for name, value in (
                ("plan", plan), ("decisions", decisions), ("review_record", record), ("result", result))})
            claims = {claim["claim_id"]: claim for claim in result["claims"]}
            accepted = sorted({match["claim_id"] for match in decisions["claim_matches"] if match["target_id"] in target_ids and match["decision"] == "accepted"})
            row["accepted_claim_ids"] = accepted
            row["matched"] = bool(accepted)
            provenance = plan.get("provenance", {})
            planned = {target["target_id"]: target for target in plan["targets"]}
            if frozen_packs[observation.run_id] is None:
                row["reason"] = "frozen_pack_unavailable"
            elif provenance.get("pack_sha256") != frozen_packs[observation.run_id]:
                row["reason"] = "plan_pack_binding_unavailable"
            elif any(t not in planned or planned[t].get("canonical_id", canonical) != canonical for t in target_ids):
                row["reason"] = "planned_target_mismatch"
            elif result["status"] != "success":
                row["reason"] = "scan_" + result["status"]
            elif not result["bundles_resolved"]:
                row["reason"] = "unresolved_bundles"
            elif observation.review_state != "human_approved":
                row["reason"] = "review_" + str(observation.review_state)
            elif observation.scope != "reviewed":
                row["reason"] = "scope_" + str(observation.scope)
            elif any(match["target_id"] in target_ids and match["decision"] == "unresolved" for match in decisions["claim_matches"]):
                row["reason"] = "unresolved_match"
            elif not accepted:
                row["reason"] = "unmatched"
            else:
                selected = min((claims[c] for c in accepted), key=lambda claim: (claim.get("rank", 0), claim["claim_id"]))
                row["selected_claim"] = deepcopy(selected)
                row["comparison"] = compare_severity(selected, row["references"], calibrator_version=calibrator_version)
                row["status"] = row["comparison"]["status"]
                row["reason"] = row["comparison"]["reason"]
            rows.append(row)
    return rows, unplanned


def _counts(rows):
    return {"target_observations": len(rows), "canonical_targets": len({r["canonical_id"] for r in rows}),
            "matched": sum(r["matched"] for r in rows),
            "eligible_matched": sum(r["status"] != "excluded" for r in rows),
            **{state: sum(r["status"] == state for r in rows) for state in ("assessed", "unavailable", "excluded")},
            "reasons": dict(sorted(Counter(r["reason"] for r in rows if r["reason"]).items()))}


def _metrics(rows, attributes, weighting, policy, *, whole_view, parent_attributes=None):
    weights, reason, notes = aggregate._weights(attributes, weighting, policy, whole_view=whole_view)
    if not attributes:
        weights, reason, notes = None, "no planned targets in this stratum", []
    elif weighting == "explicit" and parent_attributes is not None:
        parent_weights, parent_reason, _ = aggregate._weights(parent_attributes, weighting, policy, whole_view=True)
        if parent_weights is None:
            weights, reason = None, parent_reason
        else:
            weights, reason, notes = aggregate._weights(attributes, weighting, policy, whole_view=False)
    answer = {"weighting": weighting, "counts": _counts(rows), "unavailable_reason": reason, "notes": notes,
              "weights": {key: float(value) for key, value in (weights or {}).items()}, "metrics": {}}
    # Per-target observation means preserve target weight across repetitions and aliases.
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["canonical_id"]].append(row)
    def mean_observation(group, value):
        units = defaultdict(list)
        for row in group:
            units[(row["run_id"], row["input_id"])].append(row)
        def exact(row):
            v = value(row)
            return Fraction(int(v)) if isinstance(v, bool) else Fraction(str(v))
        return sum(sum((exact(row) for row in unit), Fraction(0)) / len(unit) for unit in units.values()) / len(units)
    eligible = lambda r: r["status"] != "excluded"
    assessed = lambda r: r["status"] == "assessed"
    numeric = lambda r: assessed(r) and r["comparison"]["numeric_delta"] is not None
    definitions = {
        "assessment_coverage": (assessed, eligible),
        "exact_band_agreement": (lambda r: assessed(r) and r["comparison"]["outcome"] == "exact", assessed),
        "overestimation": (lambda r: assessed(r) and r["comparison"]["outcome"] == "overestimated", assessed),
        "underestimation": (lambda r: assessed(r) and r["comparison"]["outcome"] == "underestimated", assessed),
        "mean_absolute_band_error": (lambda r: abs(r["comparison"]["band_error"]) if assessed(r) else 0, assessed),
        "numeric_bias": (lambda r: r["comparison"]["numeric_delta"] if numeric(r) else 0, numeric),
        "numeric_mean_absolute_error": (lambda r: abs(r["comparison"]["numeric_delta"]) if numeric(r) else 0, numeric),
    }
    for error in range(-4, 5):
        definitions[f"band_error_{error}"] = (lambda r, e=error: assessed(r) and r["comparison"]["band_error"] == e, assessed)
    for name, (numerator, denominator) in definitions.items():
        n = d = None
        if weights is not None:
            n = sum((weights[t] * mean_observation(group, numerator) for t, group in grouped.items()), Fraction(0))
            d = sum((weights[t] * mean_observation(group, denominator) for t, group in grouped.items()), Fraction(0))
        answer["metrics"][name] = {"value": float(n / d) if d else None, "weighted_numerator": float(n) if n is not None else None, "weighted_denominator": float(d) if d is not None else None,
                                   "denominator_observations": sum(denominator(r) for r in rows),
                                   "denominator_targets": sum(any(denominator(r) for r in group) for group in grouped.values())}
    return answer


def _calibrate(run_dirs, pack: dict, *, policy: dict | None, calibrator_version: str) -> dict:
    """Recompute one declared calibration revision from exact saved evidence."""
    if calibrator_version not in _REFERENCE_SELECTIONS:
        raise ContractError(f"unsupported severity calibrator version {calibrator_version!r}")
    validate_document("case-pack", pack)
    corpus = aggregate._load_corpus(run_dirs)
    digest = cases.pack_sha256(pack)
    if any(run.schedule["pack"]["sha256"] != digest for run in corpus.runs):
        raise ContractError("severity pack must match the exact pack frozen by every run")
    policy = aggregate.resolve_policy(policy)
    frozen_packs = _frozen_packs(corpus, pack)
    rows, unplanned = _records(corpus, pack, frozen_packs, calibrator_version)
    fields = ("system_id", "mode", "profile", "condition", "condition_status", "evidence_scope")
    strata = defaultdict(list)
    unplanned_strata = defaultdict(list)
    for row in rows:
        strata[tuple(row[key] for key in fields)].append(row)
    for row in unplanned:
        unplanned_strata[tuple(row[key] for key in fields)].append(row)
    views = []
    for key in sorted(set(strata) | set(unplanned_strata)):
        group = strata[key]
        attrs = {r["canonical_id"]: corpus.targets[r["canonical_id"]] for r in group}
        parent_attrs = {r["canonical_id"]: corpus.targets[r["canonical_id"]] for r in rows
                        if tuple(r[field] for field in fields[:3]) == key[:3]}
        version_rows = defaultdict(list)
        for row in group:
            versions = {r["severity"]["cvss_version"] if r["severity"] else "unavailable" for r in row["references"]}
            version_rows["unavailable" if "unavailable" in versions else next(iter(versions)) if len(versions) == 1 else "conflicting"].append(row)
        views.append({**dict(zip(fields, key)),
                      "counts": _counts(group),
                      "unplanned_assignments": unplanned_strata[key],
                      "unplanned_assignment_count": len(unplanned_strata[key]),
                      "weightings": [_metrics(group, attrs, w, policy, whole_view=True, parent_attributes=parent_attrs) for w in policy["views"]],
                      "by_cvss_version": {version: [_metrics(subset, {r["canonical_id"]: attrs[r["canonical_id"]] for r in subset}, w, policy, whole_view=False, parent_attributes=parent_attrs) for w in policy["views"]] for version, subset in version_rows.items()}})
    report = {"schema_version": "2.1", "calibrator_version": calibrator_version, "pack_sha256": digest,
              "policy": policy, "policy_sha256": canonical_sha256(policy), "band_order": list(BANDS),
              "claim_selection": SELECTION, "reference_selection": _REFERENCE_SELECTIONS[calibrator_version],
              "label_mapping": {label: label for label in BANDS},
              "cross_version_policy": "exclude numeric and ordinal comparisons",
              "runs": [{"run_id": run.run_id, "manifest_sha256": canonical_sha256(run.manifest), "schedule_sha256": canonical_sha256(run.schedule), "config_sha256": canonical_sha256(run.config), "frozen_pack_sha256": frozen_packs[run.run_id]} for run in corpus.runs],
              "counts": _counts(rows), "records": rows, "views": views, "unplanned_assignments": unplanned,
              "assignment_counts": {"scheduled": len(corpus.observations), "unplanned": len(unplanned)},
              "limits": ["Review approval is recorded, not authenticated.", "Reference CVSS is a sourced rating, not absolute ground truth.",
                         "Vector syntax is checked; supplied scores are not recalculated from vectors.",
                         "No calibration confidence intervals; detection, precision and promotion decisions are unchanged."]}
    return validate_document("severity-report", report)


def calibrate(run_dirs, pack: dict, *, policy: dict | None = None) -> dict:
    """Generate a report under the current calibration semantics."""
    return _calibrate(run_dirs, pack, policy=policy, calibrator_version=VERSION)


def verify(report: dict, run_dirs, pack: dict) -> None:
    validate_document("severity-report", report)
    replay = _calibrate(run_dirs, pack, policy=report["policy"], calibrator_version=report["calibrator_version"])
    if canonical_sha256(report) != canonical_sha256(replay):
        raise ContractError("severity report is stale or changed: replay does not match current evidence")


def validate_report(report: dict) -> None:
    validate_document("aggregation-policy", report["policy"])
    if report["policy_sha256"] != canonical_sha256(report["policy"]):
        raise ContractError("severity policy digest mismatch")
    if report["counts"] != _counts(report["records"]):
        raise ContractError("severity coverage counts do not match records")
    unplanned_ids = {(r["run_id"], r["assignment_id"]) for r in report["unplanned_assignments"]}
    if (len(unplanned_ids) != len(report["unplanned_assignments"])
            or report["assignment_counts"]["unplanned"] != len(unplanned_ids)
            or report["assignment_counts"]["scheduled"] < len(unplanned_ids)):
        raise ContractError("severity unplanned assignment counts do not match records")
    calibrator_version = report["calibrator_version"]
    if (report["claim_selection"] != SELECTION or report["reference_selection"] != _REFERENCE_SELECTIONS[calibrator_version]
            or report["label_mapping"] != {label: label for label in BANDS}
            or report["cross_version_policy"] != "exclude numeric and ordinal comparisons"):
        raise ContractError("severity policy does not match the declared calibrator version")
    seen = set()
    for row in report["records"]:
        key = (row["run_id"], row["assignment_id"], row["canonical_id"])
        if key in seen:
            raise ContractError("duplicate canonical target observation in severity report")
        seen.add(key)
        if row["bindings"]["references_sha256"] != canonical_sha256(row["references"]):
            raise ContractError("severity reference digest mismatch")
        if row["status"] == "excluded":
            if row["comparison"] is not None or row["selected_claim"] is not None or not row["reason"]:
                raise ContractError("excluded severity record must state its reason without a comparison")
        else:
            claim = row["selected_claim"]
            if not row["matched"] or claim is None or claim["claim_id"] not in row["accepted_claim_ids"]:
                raise ContractError("severity comparison needs a selected accepted claim")
            computed = compare_severity(claim, row["references"], calibrator_version=calibrator_version)
            if row["comparison"] != computed or row["status"] != computed["status"] or row["reason"] != computed["reason"]:
                raise ContractError("severity comparison does not match its evidence")


def render_html(report: dict) -> str:
    validate_document("severity-report", report)
    def show(value):
        return escape(json.dumps(value, ensure_ascii=False, indent=2))
    rows = "".join(f"<tr><td>{escape(r['system_id'])}<br>{escape(r['canonical_id'])}<br>{escape(r['assignment_id'])}</td>"
                   f"<td>{escape(r['status'])}: {escape(r['reason'] or '')}</td>"
                   f"<td><pre>{show(r['references'])}</pre></td><td><pre>{show(r['comparison'])}</pre></td>"
                   f"<td><pre>{show(r['selected_claim'])}</pre></td></tr>" for r in report["records"])
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'"><title>CVSS severity calibration</title><style>body{font:16px system-ui;margin:2rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:.5rem;vertical-align:top}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-width:35rem}</style><h1>CVSS severity calibration</h1><p>Reference CVSS is a sourced rating. Calibration does not change detection credit. Excluded and unavailable observations remain visible.</p><h2>Coverage</h2><pre>' + show({"targets": report["counts"], "assignments": report["assignment_counts"], "unplanned_assignments": report["unplanned_assignments"]}) + '</pre><h2>Weighted metrics and version strata</h2><pre>' + show(report["views"]) + '</pre><h2>Target comparisons</h2><table><thead><tr><th>Target / observation</th><th>Status</th><th>Reference evidence</th><th>Comparison</th><th>Selected claim</th></tr></thead><tbody>' + rows + '</tbody></table><h2>Policy and limits</h2><pre>' + show({k: report[k] for k in ("band_order", "claim_selection", "reference_selection", "cross_version_policy", "limits")}) + '</pre></html>'
