"""Read-only, offline investigation exports of saved runs.

Joins are scoped to the saved run, invocation, native run namespace and producer.
Nothing here scores, approves, executes, uploads, or rewrites original evidence.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any

from .contracts import _strict_object, canonical_sha256, validate_document
from .trace import parse_trace

MAX_FILE_BYTES = 64 * 1024 * 1024
FILTER_FIELDS = ("type", "producer_id", "call_id", "candidate_id", "claim_id")
DOCUMENTS = {
    "execution": ("execution.json", "execution-record"),
    "result": ("result.json", "scan-result"),
    "plan": ("evaluator/plan.json", "evaluation-plan"),
    "decisions": ("evaluator/decisions.json", "review-decisions"),
    "review": ("evaluator/review-record.json", "review-record"),
    "evaluation": ("evaluation.json", None),
}
SECRET_KEY = re.compile(r"api[_-]?key|authorization|credentials?|cookies?|password|secrets?|token|private[_-]?key", re.I | re.ASCII)
# Credential assignments only, not prose, source paths, token usage counters, or arbitrary IDs.
ASSIGNMENT = re.compile(r'''(?i)(\b(?:api[_-]?key|password|secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;<>]+)''')
BEARER = re.compile(r"(?i)(\b(?:authorization\s*:\s*)?bearer\s+)[A-Za-z0-9._~+/=-]+")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.S)


class InvestigationError(RuntimeError):
    pass


def _hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class Evidence:
    """Descriptor-relative regular-file reads, refusing every linked path component."""
    def __init__(self, root: Path):
        self.root = Path(root).expanduser().absolute()
        if self.root.is_symlink():
            raise InvestigationError("saved run root must not be a symbolic link")
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def close(self):
        os.close(self.fd)

    def read(self, relative: str) -> bytes:
        if not isinstance(relative, str) or "\\" in relative or "\x00" in relative:
            raise InvestigationError("evidence path is not a relative POSIX path")
        path = PurePosixPath(relative)
        if path.is_absolute() or not path.parts or any(p in ("", "..", ".") for p in relative.split("/")):
            raise InvestigationError("evidence path escapes its saved run")
        fd = os.dup(self.fd)
        try:
            for part in path.parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            child = os.open(path.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(child, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise InvestigationError("evidence path is not a regular file")
                raw = stream.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    raise InvestigationError("evidence file exceeds the 64 MiB export limit")
                return raw
        finally:
            os.close(fd)


def _read(evidence: Evidence, path: str) -> tuple[bytes | None, dict]:
    status = {"path": path, "state": "available", "sha256": None, "diagnostics": []}
    try:
        raw = evidence.read(path)
        status["sha256"] = _hash(raw)
        return raw, status
    except FileNotFoundError:
        status["state"] = "missing"
    except (OSError, ValueError, InvestigationError) as exc:
        status["state"] = "unavailable"
        status["diagnostics"] = [str(exc)]
    return None, status


def _document(evidence: Evidence, path: str, kind: str | None) -> dict:
    raw, result = _read(evidence, path)
    result.update(data=None, canonical_sha256=None)
    if raw is None:
        return result
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        if not isinstance(data, dict):
            raise ValueError("document must be an object")
        digest = canonical_sha256(data)  # refuses nonfinite numeric values
        if kind:
            validate_document(kind, data)
        result.update(data=data, canonical_sha256=digest)
    except (ValueError, UnicodeError, RecursionError) as exc:
        result.update(state="malformed", diagnostics=[f"invalid UTF-8, JSON or {kind or 'object'} contract"])
    return result


def _binding(documents: dict, owner: str, checks: list[tuple[str, str]]) -> str:
    owner_doc = documents[owner]
    if owner_doc["state"] != "available":
        return owner_doc["state"]
    if any(documents[target]["state"] != "available" for _, target in checks):
        return "unavailable"
    return "current" if all(owner_doc["data"].get(field) == documents[target]["canonical_sha256"]
                            for field, target in checks) else "stale"


def _export_copy(value: Any, changes: list[dict], path: str = "") -> Any:
    """Redact credentials in the copy; never apply the publication fixture sanitizer."""
    if isinstance(value, dict):
        copied = {}
        for key, item in value.items():
            location = f"{path}/{key}"
            if SECRET_KEY.fullmatch(key):
                copied[key] = "[REDACTED]"
                changes.append({"path": location, "reason": "credential_key"})
            else:
                copied[key] = _export_copy(item, changes, location)
        return copied
    if isinstance(value, list):
        return [_export_copy(item, changes, f"{path}/{index}") for index, item in enumerate(value)]
    if isinstance(value, str):
        cleaned = PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", value)
        cleaned = BEARER.sub(r"\1[REDACTED]", cleaned)
        cleaned = ASSIGNMENT.sub(lambda m: m[1] + "[REDACTED]", cleaned)
        if cleaned != value:
            changes.append({"path": path, "reason": "credential_text"})
        return cleaned
    return value


def _scoped(event: dict, run_id: str, invocation_id: str) -> list[str]:
    return [run_id, invocation_id, event["run_id"], event["producer_id"]]


def _event_rows(events: list[dict], run_id: str, invocation_id: str, mode: str | None,
                filters: dict, omissions: list[dict]) -> tuple[list[dict], list[dict]]:
    rows, index = [], defaultdict(list)
    for position, event in enumerate(events):
        event = dict(event)
        reference = f"event-{position + 1}"
        if mode != "content" and "content" in event:
            del event["content"]
            omissions.append({"invocation_id": invocation_id, "event_ref": reference,
                              "reason": "content excluded: trace mode is not content"})
        scope = _scoped(event, run_id, invocation_id)
        metadata = event["metadata"]
        imported = str(metadata.get("source", "")).startswith(("claude_code_", "codex_"))
        row = {"ref": reference, "scope": scope, "event": event,
               "timestamp_label": "import emission time" if imported else "observer emission time",
               "native_timestamp": metadata.get("source_timestamp"),
               "native_timestamp_of": metadata.get("source_timestamp_of"), "links": {}}
        rows.append(row)
        for field in ("event_id", "call_id", "candidate_id", "claim_id"):
            if event.get(field):
                index[(tuple(scope), field, event[field])].append(reference)
    for row in rows:
        event, scope = row["event"], tuple(row["scope"])
        for field in ("call_id", "candidate_id", "claim_id", "parent_event_id"):
            identifier = event.get(field)
            refs = index.get((scope, "event_id" if field == "parent_event_id" else field, identifier), [])
            refs = [ref for ref in refs if ref != row["ref"]]
            state = "not_linked" if not refs else "linked"
            if field == "parent_event_id" and len(refs) > 1:
                state = "ambiguous"
            row["links"][field] = {"state": state, "refs": refs}
    selected = [row for row in rows if all(row["event"].get(key) in values
                                         for key, values in filters.items() if values)]
    visible = {row["ref"] for row in selected}
    for row in rows:
        for link in row["links"].values():
            link["visible_refs"] = [ref for ref in link["refs"] if ref in visible]
            if link["refs"] and not link["visible_refs"] and link["state"] != "ambiguous":
                link["state"] = "filtered_out"
    # Order by the recorded observer/import time, never infer latency from native/import clocks.
    def time_key(row):
        stamp = row["event"]["timestamp"].upper().replace(":60", ":59")
        return datetime.fromisoformat(stamp).timestamp()
    selected.sort(key=time_key)
    return rows, selected


def _artifact_bindings(evidence: Evidence, prefix: str, result: dict) -> list[dict]:
    bindings = []
    for artifact in result.get("raw_artifacts", []):
        raw, actual = _read(evidence, prefix + "/" + artifact["path"])
        state = actual["state"]
        if raw is not None:
            state = "current" if actual["sha256"] == artifact["sha256"] else "stale"
        bindings.append({**artifact, "state": state, "actual_sha256": actual["sha256"],
                         "diagnostics": actual["diagnostics"]})
    return bindings


def _invocation(evidence: Evidence, manifest: dict, row: dict, filters: dict,
                omissions: list[dict]) -> dict:
    invocation = {"invocation_id": row["invocation_id"], "manifest": row, "documents": {},
                  "status": row["status"], "capture": {"state": "unavailable", "categories": {}},
                  "usage": {"state": "unavailable", "recorded": None}, "claims": [], "targets": [],
                  "events": [], "artifacts": [], "review_state": "missing"}
    prefix = row.get("bundle_path")
    if not prefix:
        invocation["trace"] = {"state": "unavailable", "display_state": "unavailable", "valid_events": 0,
                               "shown_events": 0, "diagnostics": ["no invocation bundle recorded"]}
        return invocation
    documents = {name: _document(evidence, prefix + "/" + path, kind)
                 for name, (path, kind) in DOCUMENTS.items()}
    invocation["documents"] = documents
    data = {key: document["data"] or {} for key, document in documents.items()}
    execution, result = data["execution"], data["result"]
    invocation["status"] = execution.get("status", row["status"])
    identity_current = (execution.get("run_id") == manifest["run_id"]
                        and execution.get("invocation_id") == row["invocation_id"]
                        and result.get("run_id") == manifest["run_id"]
                        and result.get("system_id") == row["system_id"])
    invocation["identity_binding"] = "current" if identity_current else "unavailable_or_mismatched"
    invocation["capture"] = {"state": documents["execution"]["state"],
                             "categories": execution.get("capture", {}),
                             "trace_capture_gap": (execution.get("trace") or {}).get("capture_gap"),
                             "dropped_events": (execution.get("trace") or {}).get("dropped_events")}
    usage = result.get("usage")
    invocation["usage"] = {"state": "available" if isinstance(usage, dict) and any(v is not None for v in usage.values()) else "unavailable",
                           "recorded": usage}
    decisions_binding = _binding(documents, "decisions", [("result_sha256", "result")])
    if decisions_binding == "current" and documents["plan"]["state"] != "available":
        decisions_binding = "unavailable"
    if decisions_binding == "current":
        if (data["decisions"].get("run_id") != result.get("run_id")
                or data["decisions"].get("input_hash") != data["plan"].get("input_hash")
                or data["decisions"].get("input_hash") != result.get("input_hash")):
            decisions_binding = "stale"
    review_binding = _binding(documents, "review", [("decisions_sha256", "decisions"), ("plan_sha256", "plan")])
    if review_binding == "current" and (decisions_binding != "current" or data["review"].get("run_id") != result.get("run_id")):
        review_binding = "stale"
    invocation["review_state"] = data["review"].get("state") if review_binding == "current" else review_binding
    invocation["bindings"] = {"decisions": decisions_binding, "review": review_binding,
        "evaluation": _binding(documents, "evaluation", [("result_sha256", "result"), ("plan_sha256", "plan"), ("decisions_sha256", "decisions")])}
    trace_info = execution.get("trace")
    if isinstance(trace_info, dict) and isinstance(trace_info.get("path"), str):
        raw, trace = _read(evidence, prefix + "/" + trace_info["path"])
        mode = trace_info.get("mode")
    else:
        raw, trace, mode = None, {"state": "unavailable", "path": None, "sha256": None, "diagnostics": ["no trace path recorded"]}, None
    events = []
    if raw is not None:
        parsed = parse_trace(raw)
        events = parsed.events
        trace.update(state=parsed.state, physical_lines=parsed.physical_lines,
                     rejected_records=parsed.rejected_records, diagnostics=parsed.diagnostics)
    all_rows, selected = _event_rows(events, manifest["run_id"], row["invocation_id"], mode, filters, omissions)
    trace.update(mode=mode, valid_events=len(events), shown_events=len(selected),
                 filtered_events=len(events) - len(selected), display_state="filtered_out" if events and not selected else trace["state"])
    invocation.update(trace=trace, events=selected)
    from .execution import _capture_record
    effective, capture_note = _capture_record(execution.get("capture", {}), trace_info,
        {"events": len(events) if raw is not None else None,
         "capture_gap": bool(trace.get("rejected_records")) or bool((trace_info or {}).get("capture_gap"))})
    invocation["capture"]["effective_categories"] = effective
    invocation["capture"]["validation_diagnostics"] = [capture_note] if capture_note else []
    artifacts = _artifact_bindings(evidence, prefix, result)
    invocation["artifacts"] = artifacts
    matches = data["decisions"].get("claim_matches", [])
    visible = {event["ref"] for event in selected}
    for claim in result.get("claims", []):
        direct = [event for event in all_rows if identity_current and event["event"]["run_id"] == result.get("run_id")
                  and event["event"].get("claim_id") == claim["claim_id"]]
        candidates = {(tuple(event["scope"]), event["event"]["candidate_id"]) for event in direct if event["event"].get("candidate_id")}
        related = [event["ref"] for event in all_rows if event in direct or
                   (tuple(event["scope"]), event["event"].get("candidate_id")) in candidates]
        bound_artifacts = [item for item in artifacts if item["id"] == claim.get("raw_artifact_id")]
        invocation["claims"].append({"claim": claim, "decisions": [m for m in matches if m["claim_id"] == claim["claim_id"]],
            "decision_binding": decisions_binding,
            "decision_state": "recorded" if any(m["claim_id"] == claim["claim_id"] for m in matches) else "not_linked",
            "control_assessments": [c for c in data["decisions"].get("control_assessments", []) if claim["claim_id"] in c["claim_ids"]],
            "event_refs": related,
            "visible_event_refs": [ref for ref in related if ref in visible],
            "event_state": ("linked" if any(ref in visible for ref in related) else "filtered_out") if related else "not_linked",
            "artifact_bindings": bound_artifacts, "artifact_state": ("ambiguous" if len(bound_artifacts) > 1 else "linked") if bound_artifacts else "not_linked"})
    outcomes = data["evaluation"].get("targets", [])
    outcomes = outcomes if isinstance(outcomes, list) else []
    for target in data["plan"].get("targets", []):
        judgments = [m for m in matches if m["target_id"] == target["target_id"]]
        related_claims = [claim for claim in invocation["claims"] if any(m["claim_id"] == claim["claim"]["claim_id"] for m in judgments)]
        invocation["targets"].append({"target": target, "decisions": judgments,
            "decision_binding": decisions_binding, "explanation_state": "recorded_decision" if judgments else "unexplained",
            "recorded_outcomes": [o for o in outcomes if isinstance(o, dict) and o.get("target_id") == target["target_id"]],
            "outcome_binding": invocation["bindings"]["evaluation"],
            "claim_ids": [c["claim"]["claim_id"] for c in related_claims],
            "event_refs": list(dict.fromkeys(ref for c in related_claims for ref in c["event_refs"]))})
    return invocation


def build_investigation(run_dir: Path, *, filters: dict[str, list[str]] | None = None) -> dict:
    """Return the credential-redacted export copy; every identifier join retains scope."""
    filters = filters or {}
    if any(key not in FILTER_FIELDS or not isinstance(values, list) or
           any(not isinstance(value, str) for value in values) for key, values in filters.items()):
        raise InvestigationError("filters must map event fields to lists of exact string values")
    evidence = Evidence(run_dir)
    try:
        manifest = _document(evidence, "run-manifest.json", "run-manifest")
        if manifest["state"] != "available":
            raise InvestigationError("run-manifest.json is " + manifest["state"])
        omissions = []
        document = {"format": "scaneval-investigation", "format_version": "1.0", "run": manifest,
                    "filters": filters, "invocations": [], "export_policy": {
                        "source_evidence_unchanged": True, "redactions": [], "omissions": omissions,
                        "content": "Content is retained only for content-mode traces. Credential redaction is narrow, not anonymization.",
                        "limits": "Recorded review attribution is not authenticated approval. Source delivery is not proof of attention. No latency is inferred from import order."}}
        for row in manifest["data"]["invocations"]:
            document["invocations"].append(_invocation(evidence, manifest["data"], row, filters, omissions))
        for invocation in document["invocations"]:
            if invocation["trace"].get("filtered_events"):
                omissions.append({"invocation_id": invocation["invocation_id"], "reason": "event filters",
                                  "count": invocation["trace"]["filtered_events"]})
        redactions = []
        exported = _export_copy(document, redactions)
        exported["export_policy"]["redactions"] = redactions
        return exported
    finally:
        evidence.close()


def export_investigation(run_dir: Path, output_dir: Path, *, filters: dict | None = None) -> dict:
    """Write a new standalone HTML/JSON directory outside runs and materialized trials."""
    source, output = Path(run_dir).expanduser().resolve(), Path(output_dir).expanduser().resolve()
    if output == source or output.is_relative_to(source):
        raise InvestigationError("investigation output must stay outside the source run")
    for parent in (output, *output.parents):
        if (parent / "run-manifest.json").exists() or ((parent / "provenance.json").exists() and (parent / "source").is_dir()):
            raise InvestigationError("investigation output must stay outside saved runs and materialized trials")
    if output.exists():
        raise InvestigationError("investigation output must be a new directory")
    document = build_investigation(run_dir, filters=filters)
    from .investigation_html import render_investigation
    rendered = render_investigation(document)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    (output / "investigation.json").write_text(json.dumps(document, ensure_ascii=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    (output / "index.html").write_text(rendered, encoding="utf-8")
    return document
