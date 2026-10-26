"""Validate the saved evidence for the open-context investigation condition.

Attested here means that the declared history and controlled retrieval boundary were observed.
Provider-side activity and opaque tunnels remain explicit gaps; fetched bytes alone never prove
that those bytes entered a model request or that a finding was derived independently from source.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from .contracts import ContractError, canonical_sha256
from .materialize import MaterializationError
from .open_context import HISTORY_POLICY, validate_policy


def _reason(code: str, message: str) -> dict:
    return {"code": code, "message": message}


def classify_condition(bundle: Path, execution: dict, policy: dict, evidence: dict) -> dict:
    """Check actual saved history, enforcement, event bytes, and retained response content."""
    from .conditions import _bytes, _json

    failures = []
    gaps = []
    artifacts = []
    isolation = execution.get("isolation") or {}
    retrieval = isolation.get("retrieval") or {}
    history = evidence.get("history_evidence") or {}
    details = {"history": history, "retrieval": retrieval,
               "interpretation": "Assisted investigation; known-vulnerability retrieval can contribute to detection.",
               "model_consumption": {"observed": 0, "unknown": 0},
               "live_content_replayable": False}
    result = {"status": "declared_only", "history": "unavailable", "network": "unenforced",
              "retrieval": "capture_gap", "provider_retrieval": "unverifiable", "details": details,
              "artifacts": artifacts,
              "assurance": {"network": "declared", "retrieval": "capture_gap", "provider": "unverifiable"}}
    try:
        validate_policy(policy)
    except MaterializationError as exc:
        failures.append(_reason("stale_open_context_policy", str(exc)))
    if (execution.get("provenance") or {}).get("mode", "full") != "full" or (
            execution.get("provenance") or {}).get("profile") != "standard":
        failures.append(_reason("ineligible_open_context_input", "Open-context requires the ordinary standard full input."))
    if (history.get("policy") == HISTORY_POLICY and history.get("status") == "available"
            and history.get("source_tree_hash") == (execution.get("provenance") or {}).get("tree_hash")
            and history.get("reachable_commit_count", 0) > 0
            and history.get("refs") == [{"name": "HEAD", "target": history.get("head_commit"), "symbolic": False}]):
        result["history"] = "bounded_ancestor_history"
    else:
        gaps.append(_reason("bounded_history_unavailable", "No matching constructed ancestor-history attestation is saved."))
    network = isolation.get("network") or {}
    if (isolation.get("backend") == "oci" and isolation.get("enforced") is True
            and network.get("policy") == "public_research" and network.get("enforced") is True
            and (execution.get("network_policy") or {}).get("declared") == "public_research"):
        result["network"] = "enforced"
        result["assurance"]["network"] = "external_enforcement"
    else:
        gaps.append(_reason("open_context_boundary_unenforced", "No observed OCI public-research boundary bounded this scanner."))
    actual_policy = retrieval.get("policy")
    if isinstance(actual_policy, dict):
        if (actual_policy.get("policy") != policy.get("retrieval") or
                any(actual_policy.get(key) != policy.get(key) for key in ("capture", "retention")) or
                retrieval.get("policy_sha256") != canonical_sha256(actual_policy)):
            failures.append(_reason("retrieval_policy_mismatch", "The actual retrieval policy differs from the condition declaration."))
    else:
        gaps.append(_reason("retrieval_policy_unavailable", "The execution did not retain its actual retrieval policy."))
    if retrieval.get("capture_status") != "recorded":
        gaps.append(_reason("retrieval_capture_gap", "Recorded retrieval capture is unavailable; missing events do not establish no retrieval."))
    else:
        try:
            relative = retrieval.get("events_path")
            if relative != "raw/retrieval-provenance/events.jsonl":
                raise ContractError("retrieval events use an unexpected artifact path")
            raw = _bytes(bundle, relative)
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            if digest != retrieval.get("events_sha256"):
                raise ContractError("retrieval event bytes contradict their execution-record hash")
            events = [_json(line) for line in raw.splitlines()]
            artifacts.append({"role": "retrieval_events", "path": relative, "sha256": digest})
            if len(events) != retrieval.get("attempts"):
                raise ContractError("retrieval event count contradicts its execution record")
            seen = set()
            retained = set()
            for event in events:
                if not isinstance(event.get("id"), str) or event["id"] in seen:
                    raise ContractError("retrieval event ids are missing or repeated")
                seen.add(event["id"])
                required = {"url", "query", "started_at", "finished_at", "outcome", "redirect_chain",
                            "content_sha256", "capture_status", "content_entered_model"}
                if required - set(event) or event["outcome"] not in ("ok", "http_error", "failed", "denied"):
                    raise ContractError("retrieval event lacks required capture provenance")
                if event.get("capture_status") == "preserved":
                    content = event.get("content_path")
                    if not isinstance(content, str) or not re.fullmatch(r"content/[0-9a-f]{64}\.bin", content):
                        raise ContractError("retained retrieval content has an invalid path")
                    path = "raw/retrieval-provenance/" + content
                    body = _bytes(bundle, path)
                    content_hash = "sha256:" + hashlib.sha256(body).hexdigest()
                    if content_hash != event.get("content_sha256") or len(body) != event.get("byte_count"):
                        raise ContractError("retained retrieval content contradicts its hash or length")
                    if path not in retained:
                        artifacts.append({"role": "retrieval_content:" + content_hash, "path": path, "sha256": content_hash})
                        retained.add(path)
                elif event.get("capture_status") == "hash_only":
                    if policy.get("retention") != "hashes_only":
                        gaps.append(_reason("retrieval_content_missing", "A fetched response was hashed but not preserved under content capture."))
                elif event.get("capture_status") != "unavailable":
                    raise ContractError("retrieval capture status is unknown")
                # This transport cannot observe a model request. A scanner acknowledgment is
                # self-reported and cannot upgrade an unknown model-use field to observed.
                if event["content_entered_model"] is not None:
                    raise ContractError("the retrieval transport cannot attest model consumption")
                details["model_consumption"]["unknown"] += int(event.get("content_sha256") is not None)
            result["retrieval"] = "recorded"
            result["assurance"]["retrieval"] = "recorded"
            details["attempts"] = len(events)
            details["retrieval_coverage"] = "Complete only for the recorded retrieval API; provider, opaque-tunnel, and direct-socket gaps remain."
        except (ContractError, ValueError, TypeError, UnicodeError) as exc:
            failures.append(_reason("retrieval_artifact_mismatch", str(exc)))
    if any(item.get("role") == "worker" and item.get("started") and not item.get("removed")
           for item in isolation.get("containers", [])):
        failures.append(_reason("scanner_cleanup_incomplete", "A scanner container remained after capture; the observation boundary is incomplete."))
    result["status"] = "failed" if failures else "declared_only" if gaps else "attested"
    result["reasons"] = failures + gaps
    return result
