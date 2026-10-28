"""Project explicitly observed dossier evidence into pending chronology only."""
from __future__ import annotations

from datetime import datetime, timezone
import math
import re
from urllib.parse import urlsplit

from .model_cutoffs import (
    CutoffError, DOSSIER_SCHEMA_VERSION, PROJECTION_POLICY_VERSION,
    _canonical_cve_id, _digest, _require, _text, _url, date_bounds, validate_candidates,
)


# Versioned dossier field semantics, never inferred from a URL or advisory text.
NATIVE_KINDS = {
    "maintainer_advisory_publication": "advisory",
    "public_release_publication": "release",
    "public_pull_request_creation": "pull_request",
}
RELATED_SCOPE = (
    "Related predecessor observation only; publication alone does not establish "
    "contemporaneous wording or exact-weakness distinctness. Earlier-evidence "
    "chronology remains pending."
)
TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)


def _object(value: object, label: str) -> dict:
    _require(isinstance(value, dict), f"{label} must be an object")
    return value


def _source_url(value: object, label: str) -> str:
    _require(_url(value) and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value),
             f"{label} must be an HTTP(S) source URL")
    try:
        parsed = urlsplit(value)
        _require(parsed.username is None and parsed.password is None, f"{label} must not contain credentials")
        parsed.port  # Reject invalid ports, which hostname alone does not validate.
    except ValueError as exc:
        raise CutoffError(f"{label} has an invalid port") from exc
    return value


def _utc_day(value: object) -> str:
    _require(isinstance(value, str) and TIMESTAMP_PATTERN.fullmatch(value) is not None,
             f"public timestamp must include seconds and an explicit time zone: {value!r}")
    _require(not value.endswith("-00:00"), "public timestamp has an unknown -00:00 offset")
    if not value.endswith("Z"):
        _require(int(value[-5:-3]) <= 23 and int(value[-2:]) <= 59,
                 f"invalid public timestamp offset: {value!r}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).date().isoformat()
    except (ValueError, OverflowError) as exc:
        raise CutoffError(f"invalid public timestamp: {value!r}") from exc


def _selected_rating(candidate: dict, cid: str) -> dict:
    severity = _object(candidate.get("severity"), f"{cid}: severity")
    selected = _object(severity.get("selected"), f"{cid}: selected severity")
    version = selected.get("version")
    _require(_text(version) and version in {"3.0", "3.1", "4.0"}, f"{cid}: unsupported selected CVSS version")
    score = selected.get("score")
    _require(type(score) in (int, float) and 0.1 <= score <= 10 and math.isfinite(score) and round(score, 1) == score,
             f"{cid}: selected CVSS score must be a finite number in 0.1..10 with at most one decimal place")
    band = "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"
    _require(selected.get("severity") == band and candidate.get("proposed_stratum") == band,
             f"{cid}: selected severity, score and proposed stratum disagree")
    _require(_text(selected.get("authority")), f"{cid}: selected severity authority is required")
    source = _source_url(selected.get("source"), f"{cid}: selected severity source")
    return {"authority": selected["authority"], "source": source, "version": version,
            "score": score, "severity": band}


def _observed_artifacts(candidate: dict, cid: str) -> list[dict]:
    dates = _object(candidate.get("dates"), f"{cid}: dates")
    kind = dates.get("evidence_kind")
    _require(_text(kind) and kind in NATIVE_KINDS, f"{cid}: unsupported native public-evidence kind: {kind!r}")
    original = dates.get("earliest_observed_public_evidence_at")
    day = _utc_day(original)
    source = _source_url(dates.get("earliest_observed_public_evidence_url"), f"{cid}: observed evidence source")
    note = dates.get("note")
    _require(_text(note), f"{cid}: date note is required")
    scope = dates.get("earliest_observed_public_evidence_scope")
    if "earliest_observed_public_evidence_scope" in dates:
        _require(_text(scope), f"{cid}: observed evidence scope must be nonempty text")
    scope_note = note + (" " + scope if scope is not None else "")
    artifacts = [{"kind": NATIVE_KINDS[kind], "date": day, "precision": "day",
                  "date_basis": "public_availability", "source_url": source,
                  "original_timestamp": original, "native_evidence_kind": kind,
                  "relationship": "candidate", "scope_note": scope_note}]
    if "related_predecessor" in dates:
        related = _object(dates["related_predecessor"], f"{cid}: related predecessor")
        original = related.get("published_at")
        day = _utc_day(original)
        source = _source_url(related.get("url"), f"{cid}: related predecessor source")
        updated = related.get("current_body_updated_at_day")
        date_bounds(updated, "day")
        wording = related.get("publication_time_wording_established")
        _require(type(wording) is bool, f"{cid}: predecessor wording flag must be boolean")
        artifacts.append({"kind": "advisory", "date": day, "precision": "day",
                          "date_basis": "public_availability", "source_url": source,
                          "original_timestamp": original,
                          "native_evidence_kind": "related_predecessor_advisory_publication",
                          "relationship": "related_predecessor", "scope_note": RELATED_SCOPE + " " + scope_note,
                          "current_body_updated_at_day": updated,
                          "publication_time_wording_established": wording})
    return artifacts


def prepare_chronology(dossier: dict, severity_authority: str) -> dict:
    """Validate consumed fields and emit observations without promoting any case."""
    _object(dossier, "dossier")
    _require(dossier.get("schema_version") == DOSSIER_SCHEMA_VERSION, "unsupported research dossier version")
    _require(_text(severity_authority), "declare one severity_authority for the pack")
    candidates = dossier.get("candidates")
    _require(isinstance(candidates, list), "dossier candidates must be a list")
    projected = []
    ids = set()
    for candidate in candidates:
        _object(candidate, "dossier candidate")
        cid = candidate.get("cve_id")
        _require(_canonical_cve_id(cid) and cid not in ids, f"invalid or duplicate CVE: {cid!r}")
        ids.add(cid)
        rating = _selected_rating(candidate, cid)
        artifacts = _observed_artifacts(candidate, cid)
        projected.append({"cve_id": cid, "severity": rating["severity"].title(),
                          "severity_source_url": rating["source"], "selected_rating": rating,
                          "chronology": {"status": "pending",
                                         "review_note": "Projected observed public evidence only. Earlier-public-evidence chronology and related-weakness distinctness require review; dossier review or eligibility claims are not promoted.",
                                         "public_artifacts": artifacts}})
    document = {"schema_version": 1, "severity_authority": severity_authority,
                "projection_provenance": {"policy_version": PROJECTION_POLICY_VERSION,
                                          "dossier_schema_version": DOSSIER_SCHEMA_VERSION,
                                          "dossier_sha256": _digest(dossier)},
                "candidates": sorted(projected, key=lambda candidate: candidate["cve_id"])}
    validate_candidates(document)
    return document
