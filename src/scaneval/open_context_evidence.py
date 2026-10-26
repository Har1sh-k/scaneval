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
from .isolation.public_retrieval import validate_settings


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
    if not isinstance(history, dict):
        history = {}
        failures.append(_reason("invalid_bounded_history", "The saved bounded-history attestation is malformed."))
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
            and type(history.get("reachable_commit_count")) is int and history["reachable_commit_count"] > 0
            and isinstance(history.get("head_commit"), str) and re.fullmatch(r"[0-9a-f]{40}", history["head_commit"])
            and isinstance(history.get("history_digest"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", history["history_digest"])
            and history.get("refs") == [{"name": "HEAD", "target": history.get("head_commit"), "symbolic": False}]):
        result["history"] = "bounded_ancestor_history"
    else:
        gaps.append(_reason("bounded_history_unavailable", "No matching constructed ancestor-history attestation is saved."))
    network = isolation.get("network") or {}
    containers = isolation.get("containers") or []
    workers = [item for item in containers if item.get("role") == "worker" and item.get("started") is True]
    proxies = [item for item in containers if item.get("role") == "proxy" and item.get("started") is True]
    networks = network.get("networks")
    internal = ([item for item in networks if isinstance(item, dict) and item.get("role") == "int"]
                if isinstance(networks, list) else [])
    proxy = network.get("proxy")
    allow = proxy.get("allow") if isinstance(proxy, dict) else None
    if (isolation.get("backend") == "oci" and isolation.get("enforced") is True
            and network.get("policy") == "public_research" and network.get("enforced") is True
            and (execution.get("network_policy") or {}).get("declared") == "public_research"
            and (execution.get("network_policy") or {}).get("enforced") is True
            and network.get("mode") == "internal network with egress proxy"
            and isinstance(allow, list) and allow and all(isinstance(item, str) and item.endswith(":443") for item in allow)
            and workers and proxies and all(item.get("removed") is True for item in workers + proxies)
            and len(internal) == 1 and internal[0].get("internal") is True
            and internal[0].get("gateway_mode_ipv4") == "isolated"
            and not internal[0].get("gateways") and internal[0].get("ipv6") is False):
        result["network"] = "enforced"
        result["assurance"]["network"] = "external_enforcement"
    else:
        if isolation.get("enforced") is True or network.get("enforced") is True or (
                execution.get("network_policy") or {}).get("enforced") is True:
            failures.append(_reason("network_evidence_inconsistent", "Public-research enforcement flags contradict recorded workers, proxy, or isolated network settings."))
        else:
            gaps.append(_reason("open_context_boundary_unenforced", "No observed OCI public-research boundary bounded this scanner."))
    actual_policy = retrieval.get("policy")
    if isinstance(actual_policy, dict):
        try:
            if validate_settings(actual_policy) != actual_policy:
                raise ValueError("retrieval settings are not the normalized policy the service used")
        except ValueError as exc:
            failures.append(_reason("invalid_retrieval_policy", str(exc)))
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
            attempts_path = retrieval.get("attempts_path")
            if attempts_path != "raw/retrieval-provenance/attempts.jsonl":
                raise ContractError("retrieval attempt journal is unavailable")
            attempts_raw = _bytes(bundle, attempts_path)
            attempts_hash = "sha256:" + hashlib.sha256(attempts_raw).hexdigest()
            if attempts_hash != retrieval.get("attempts_sha256"):
                raise ContractError("retrieval attempt journal contradicts its execution-record hash")
            attempts = [_json(line) for line in attempts_raw.splitlines()]
            if ({item.get("id") for item in attempts} != {item.get("id") for item in events}
                    or len(attempts) != len(events) or retrieval.get("incomplete_attempts") != 0
                    or retrieval.get("completed_attempts") != len(events)):
                raise ContractError("retrieval starts and completions do not establish complete API capture")
            by_id = {item["id"]: item for item in attempts}
            request_fields = {"url", "query", "operation", "source", "source_assurance", "started_at"}
            if any(request_fields - set(item) for item in attempts) or any(
                    any(event.get(key) != by_id[event["id"]].get(key) for key in request_fields) for event in events):
                raise ContractError("retrieval completion provenance differs from its started request")
            artifacts.append({"role": "retrieval_attempts", "path": attempts_path, "sha256": attempts_hash})
            if type(retrieval.get("attempts")) is not int or len(events) != retrieval["attempts"]:
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
                source_valid = event.get("source") in ("scanner_native", "browser_tool") or (
                    event.get("source") == "unavailable" and event["outcome"] == "denied")
                if not source_valid or event.get("operation") not in ("fetch", "search"):
                    raise ContractError("retrieval event has an unknown integration boundary")
                if event.get("capture_error"):
                    gaps.append(_reason("retrieval_content_capture_failed", "A fetched response could not be retained as declared."))
                if event["outcome"] in ("ok", "http_error") and (
                        not isinstance(event["content_sha256"], str) or
                        not re.fullmatch(r"sha256:[0-9a-f]{64}", event["content_sha256"]) or
                        type(event.get("byte_count")) is not int or event["byte_count"] < 0):
                    raise ContractError("fetched content lacks a valid hash or length")
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
                elif event["outcome"] in ("ok", "http_error"):
                    gaps.append(_reason("retrieval_content_missing", "A fetched response has unavailable content capture."))
                # This transport cannot observe a model request. A scanner acknowledgment is
                # self-reported and cannot upgrade an unknown model-use field to observed.
                if event["content_entered_model"] is not None:
                    raise ContractError("the retrieval transport cannot attest model consumption")
                details["model_consumption"]["unknown"] += int(event.get("content_sha256") is not None)
            counts = {"denied": sum(event["outcome"] == "denied" for event in events),
                      "failed": sum(event["outcome"] in ("failed", "http_error") for event in events),
                      "preserved": sum(event.get("capture_status") == "preserved" for event in events),
                      "hash_only": sum(event.get("capture_status") == "hash_only" for event in events)}
            if any(type(retrieval.get(key)) is not int or retrieval[key] != count for key, count in counts.items()):
                raise ContractError("retrieval coverage counts contradict saved event bytes")
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
