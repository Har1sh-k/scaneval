"""Offline chronology checks against sourced, explicitly limited model cutoffs.

A passing result compares caller-reviewed public evidence with provider documentation.
It never certifies training exclusion, verifies sources, or admits a corpus case.
"""
from __future__ import annotations

import calendar
import hashlib
from datetime import date
from importlib.resources import files
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


class CutoffError(RuntimeError):
    """Invalid registry or candidate evidence."""


CUTOFF_FIELDS = ("training_data_cutoff", "knowledge_cutoff", "reliable_knowledge_cutoff")
TARGET = {"Low": 2, "Medium": 3, "High": 3, "Critical": 2}
ARTIFACT_KINDS = {"advisory", "issue", "pull_request", "release", "public_commit", "proof_of_concept"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CutoffError(message)


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _url(value: object) -> bool:
    if not _text(value):
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme in {"https", "http"} and bool(parsed.hostname) and not parsed.username
    except ValueError:
        return False


def date_bounds(value: str, precision: str) -> tuple[date, date]:
    """Return an inclusive interval; month endpoints are conservative inferences."""
    pattern = {"day": r"\d{4}-\d{2}-\d{2}", "month": r"\d{4}-\d{2}"}.get(precision) if isinstance(precision, str) else None
    _require(isinstance(value, str) and pattern is not None and re.fullmatch(pattern, value) is not None,
             f"invalid {precision!r} date: {value!r}")
    try:
        start = date.fromisoformat(value if precision == "day" else value + "-01")
    except ValueError as exc:
        raise CutoffError(f"invalid date: {value!r}") from exc
    end = start if precision == "day" else start.replace(day=calendar.monthrange(start.year, start.month)[1])
    return start, end


def _pairs(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict:
    try:
        result = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                            parse_constant=lambda value: (_ for _ in ()).throw(CutoffError(f"invalid JSON number: {value}")))
    except (OSError, ValueError, RecursionError) as exc:
        raise CutoffError(f"could not read {path}: {exc}") from exc
    _require(isinstance(result, dict), f"{path} must contain an object")
    return result


def validate_registry(registry: dict) -> None:
    _require(isinstance(registry, dict) and type(registry.get("schema_version")) is int and registry["schema_version"] == 1, "unsupported cutoff registry version")
    _require(_text(registry.get("registry_id")), "registry_id is required")
    _require(isinstance(registry.get("models"), list) and bool(registry["models"]), "models must be a nonempty list")
    ids = set()
    for model in registry["models"]:
        _require(isinstance(model, dict), "model must be an object")
        mid = model.get("model_id")
        _require(_text(mid) and mid not in ids, f"missing or duplicate model_id: {mid!r}")
        ids.add(mid)
        for key in ("provider", "display_name", "identity_status", "identity_notes", "evidence_status"):
            _require(_text(model.get(key)), f"{mid}: {key} is required")
        retrieved, _ = date_bounds(model.get("retrieved_date"), "day")
        _require(isinstance(model.get("sources"), list) and bool(model["sources"]) and all(_url(s) for s in model["sources"]), f"{mid}: source URLs required")
        for key in CUTOFF_FIELDS:
            _require(key in model, f"{mid}: explicitly record {key}, including null for unknown")
            bound = model[key]
            if bound is None:
                continue
            _require(isinstance(bound, dict), f"{mid}: invalid {key}")
            _require(_url(bound.get("source_url")) and _text(bound.get("source_label")), f"{mid}: cutoff source and label required")
            upper, _ = date_bounds(bound.get("upper_bound"), "day")
            _require(upper <= retrieved, f"{mid}: cutoff cannot follow its retrieval date")
            if bound.get("status") == "published":
                _, expected = date_bounds(bound.get("value"), bound.get("precision"))
                _require(expected == upper, f"{mid}: upper_bound disagrees with published date")
                _require(bound.get("upper_bound_is_inference") is (bound["precision"] == "month"), f"{mid}: mark month-end inference explicitly")
            elif bound.get("status") == "temporal_bound":
                _require(bound.get("value") is None and bound.get("precision") == "unknown" and bound.get("upper_bound_is_inference") is True and _text(bound.get("derivation")), f"{mid}: temporal bound needs explicit derivation, not an invented exact cutoff")
            else:
                raise CutoffError(f"{mid}: unsupported cutoff status")
    _require(isinstance(registry.get("aliases"), list), "aliases must be a list")
    aliases = set()
    for alias in registry["aliases"]:
        _require(isinstance(alias, dict), "alias must be an object")
        aid = alias.get("model_id")
        _require(_text(aid) and aid not in ids and aid not in aliases, f"missing, conflicting, or duplicate alias: {aid!r}")
        aliases.add(aid)
        _require(alias.get("target_model_id") is None or (_text(alias["target_model_id"]) and alias["target_model_id"] in ids), f"{aid}: unknown alias target")
        _require(_text(alias.get("provider")) and _text(alias.get("notes")), f"{aid}: alias provider and notes required")
        _require(alias.get("source_url") is None or _url(alias["source_url"]), f"{aid}: invalid alias source")


def load_registry(path: Path | None = None) -> dict:
    if path is None:
        registry = json.loads(files("scaneval").joinpath("data/model-cutoffs.json").read_text(encoding="utf-8"))
    else:
        registry = read_json(path)
    validate_registry(registry)
    return registry


def validate_candidates(document: dict) -> None:
    _require(isinstance(document, dict) and type(document.get("schema_version")) is int and document["schema_version"] == 1, "unsupported candidate document version")
    _require(_text(document.get("severity_authority")), "declare one severity_authority for the pack")
    _require(isinstance(document.get("candidates"), list), "candidates must be a list")
    ids = set()
    for candidate in document["candidates"]:
        _require(isinstance(candidate, dict), "candidate must be an object")
        cid = candidate.get("cve_id")
        _require(isinstance(cid, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", cid) is not None and cid not in ids, f"invalid or duplicate CVE: {cid!r}")
        ids.add(cid)
        _require(_text(candidate.get("severity")) and candidate["severity"] in TARGET, f"{cid}: invalid severity")
        _require(_url(candidate.get("severity_source_url")), f"{cid}: severity_source_url is required")
        chronology = candidate.get("chronology")
        _require(isinstance(chronology, dict) and _text(chronology.get("status")) and chronology["status"] in {"pending", "reviewed"}, f"{cid}: chronology must be pending or reviewed")
        _require(_text(chronology.get("review_note")), f"{cid}: chronology review_note is required")
        artifacts = chronology.get("public_artifacts")
        _require(isinstance(artifacts, list), f"{cid}: public_artifacts must be a list")
        _require(chronology["status"] != "reviewed" or bool(artifacts), f"{cid}: reviewed chronology needs public evidence")
        for artifact in artifacts:
            _require(isinstance(artifact, dict), f"{cid}: artifact must be an object")
            _require(_text(artifact.get("kind")) and artifact["kind"] in ARTIFACT_KINDS and _url(artifact.get("source_url")), f"{cid}: artifact kind and source URL required")
            date_bounds(artifact.get("date"), artifact.get("precision"))
            _require(artifact.get("date_basis") == "public_availability", f"{cid}: commit creation or CVE assignment timestamps are not public-availability evidence")


def _model_boundary(registry: dict, model_id: str, basis: str) -> dict:
    model = next((m for m in registry["models"] if m["model_id"] == model_id), None)
    if model is None:
        alias = next((a for a in registry["aliases"] if a["model_id"] == model_id), None)
        return {"model_id": model_id, "status": "unresolved", "reason": "alias_requires_served_model" if alias else "unknown_model", "alias": alias}
    if model["identity_status"] == "documented_alias":
        return {"model_id": model_id, "status": "unresolved", "reason": "alias_requires_served_model",
                "identity_notes": model["identity_notes"]}
    fields = CUTOFF_FIELDS if basis == "documented" else ("training_data_cutoff",)
    field = next((field for field in fields if model[field] is not None), None)
    return {"model_id": model_id, "status": "known" if field else "unresolved",
            "reason": None if field else "cutoff_unknown_for_basis", "cutoff_field": field,
            "cutoff": model[field] if field else None, "retrieved_date": model["retrieved_date"],
            "identity_status": model["identity_status"], "identity_notes": model["identity_notes"],
            "evidence_status": model["evidence_status"]}


def _digest(document: dict) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def assess_candidates(registry: dict, document: dict, model_ids: list[str], *, basis: str = "training") -> dict:
    """Compare reviewed chronology without performing or asserting source review."""
    validate_registry(registry)
    validate_candidates(document)
    _require(basis in {"training", "documented"}, "basis must be training or documented")
    _require(isinstance(model_ids, list) and bool(model_ids) and all(_text(m) for m in model_ids), "select at least one model")
    _require(len(set(model_ids)) == len(model_ids), "duplicate selected model")
    boundaries = [_model_boundary(registry, mid, basis) for mid in sorted(model_ids)]
    counts = dict.fromkeys(TARGET, 0)
    results = []
    for candidate in sorted(document["candidates"], key=lambda c: c["cve_id"]):
        chronology = candidate["chronology"]
        lower = min((date_bounds(a["date"], a["precision"])[0] for a in chronology["public_artifacts"]), default=None)
        decisions = []
        for boundary in boundaries:
            reasons = []
            if boundary["status"] != "known":
                reasons.append(boundary["reason"])
            if chronology["status"] != "reviewed":
                reasons.append("earliest_public_evidence_review_pending")
            if reasons:
                status = "unresolved"
            elif lower > date.fromisoformat(boundary["cutoff"]["upper_bound"]):
                status = "eligible"
            else:
                status = "ineligible"
                reasons.append("earliest_evidence_not_strictly_after_cutoff")
            decisions.append({"model_id": boundary["model_id"], "status": status, "reasons": reasons})
        status = "ineligible" if any(d["status"] == "ineligible" for d in decisions) else "unresolved" if any(d["status"] == "unresolved" for d in decisions) else "eligible"
        if status == "eligible":
            counts[candidate["severity"]] += 1
        results.append({"cve_id": candidate["cve_id"], "severity": candidate["severity"], "status": status,
                        "earliest_public_evidence_lower_bound": lower.isoformat() if lower and chronology["status"] == "reviewed" else None,
                        "earliest_observed_artifact_date_lower_bound": lower.isoformat() if lower else None,
                        "chronology_status": chronology["status"], "models": decisions})
    shortages = {key: max(0, target - counts[key]) for key, target in TARGET.items()}
    return {"schema_version": 1, "registry_id": registry["registry_id"], "basis": basis,
            "registry_sha256": _digest(registry), "candidate_document_sha256": _digest(document),
            "claim_scope": "Chronology relative to documented cutoffs and caller-reviewed evidence; not proof of training exclusion, uncontaminated evaluation, or corpus admission.",
            "severity_authority": document["severity_authority"], "models": boundaries, "candidates": results,
            "eligible_counts": counts, "required_counts": dict(TARGET), "shortages": shortages,
            "minimum_total": 10, "eligible_total": sum(counts.values()),
            "pack_target_met": sum(counts.values()) >= 10 and not any(shortages.values())}
