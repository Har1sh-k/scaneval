"""Validation and canonicalization helpers for SASTbench v2 contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from importlib.resources import files
from os import PathLike
from typing import Any

from jsonschema import Draft202012Validator


CONTRACT_KINDS = frozenset(
    {"scan-request", "scan-result", "evaluation-plan", "review-decisions", "execution-record",
     "case-pack", "review-record", "run-config", "run-manifest"}
)
_DRIVE_PATH = re.compile(r"^[A-Za-z]:")


class ContractError(ValueError):
    """A contract document is malformed or violates a v2 invariant."""


def canonical_json(value: Any) -> str:
    """Return the compact, deterministic JSON representation of *value*."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ContractError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    """Hash the UTF-8 bytes of :func:`canonical_json`."""

    try:
        encoded = canonical_json(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"value is not canonical UTF-8 JSON: {exc}") from exc
    digest = hashlib.sha256(encoded).hexdigest()
    return f"sha256:{digest}"


def _schema(kind: str) -> dict[str, Any]:
    if kind not in CONTRACT_KINDS:
        expected = ", ".join(sorted(CONTRACT_KINDS))
        raise ContractError(f"unknown contract kind {kind!r}; expected one of: {expected}")
    resource = files("sastbench").joinpath("schemas", f"{kind}.schema.json")
    return json.loads(resource.read_text(encoding="utf-8"))


def _format_error(error: Any) -> str:
    path = ".".join(str(part) for part in error.absolute_path)
    return f"{path}: {error.message}" if path else error.message


def _require_relative_path(path: str, label: str) -> None:
    normalized = path.replace("\\", "/")
    if (
        "\x00" in path
        or normalized.startswith("/")
        or _DRIVE_PATH.match(path)
        or any(part == ".." for part in normalized.split("/"))
    ):
        raise ContractError(f"{label} must be a relative path without '..' components")


def _reject_nonfinite(value: Any, path: str = "document") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError(f"{path} contains a non-finite number")
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_nonfinite(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_nonfinite(item, f"{path}[{index}]")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ContractError(f"non-finite JSON number is not allowed: {value}")


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise ContractError(f"{label} values must be unique")


def recorded_check_state(checks: list[dict[str, Any]], snapshot_id: str) -> str | None:
    """``pass`` or ``fail`` for one snapshot's recorded check set; ``None`` when none is recorded.

    A check set is every recorded check carrying *snapshot_id*, and it passes only when all of
    them passed. Checks recorded before check sets carried a ``snapshot_id`` belong to no
    snapshot and are ignored here rather than deleted, so they neither promote nor demote a
    case. Nothing is re-run: this reads what the pack already records.
    """
    recorded = [check for check in checks if check.get("snapshot_id") == snapshot_id]
    if not recorded:
        return None
    return "pass" if all(check["result"] == "pass" for check in recorded) else "fail"


def _validate_scan_request(document: dict[str, Any]) -> None:
    request_input = document["input"]
    _require_relative_path(request_input["root"], "input.root")
    has_pr = "pr" in request_input
    if (request_input["mode"] == "pr") != has_pr:
        raise ContractError("input.pr must be present if and only if input.mode is 'pr'")


def _validate_location(location: dict[str, Any], label: str) -> None:
    _require_relative_path(location["path"], f"{label}.path")
    has_start = "start_line" in location
    has_end = "end_line" in location
    if has_start != has_end:
        raise ContractError(f"{label} start_line and end_line must be supplied together")
    if has_start and location["start_line"] > location["end_line"]:
        raise ContractError(f"{label} start_line must not exceed end_line")


def _validate_scan_result(document: dict[str, Any]) -> None:
    claims = document["claims"]
    _unique([claim["claim_id"] for claim in claims], "claim_id")
    native = document["ranking"] == "native"
    for index, claim in enumerate(claims, start=1):
        _validate_location(claim["primary_location"], f"claims[{index - 1}].primary_location")
        for related_index, location in enumerate(claim.get("related_locations", [])):
            _validate_location(
                location, f"claims[{index - 1}].related_locations[{related_index}]"
            )
        if native and claim.get("rank") != index:
            raise ContractError("native claim ranks must be contiguous and match array order")
        if not native and "rank" in claim:
            raise ContractError("unranked claims must omit rank")
    for index, artifact in enumerate(document.get("raw_artifacts", [])):
        _require_relative_path(artifact["path"], f"raw_artifacts[{index}].path")


def _validate_evaluation_plan(document: dict[str, Any]) -> None:
    """Scope carries draft status; a draft plan keeps each item's real validation level.

    A draft plan may therefore carry an L3 or L4 item: the scope, not a rewritten level, says
    the plan as a whole is not reviewed evidence. A reviewed plan stays L3/L4 only, and a
    diagnostic plan stays fixture only.
    """
    _unique([target["target_id"] for target in document["targets"]], "target_id")
    _unique([control["control_id"] for control in document["controls"]], "control_id")
    levels = [item["validation_level"] for item in document["targets"]]
    levels += [item["validation_level"] for item in document["controls"]]
    allowed = {"reviewed": {"L3", "L4"}, "draft": {"L1", "L2", "L3", "L4"},
               "diagnostic": {"fixture"}}[document["scope"]]
    if any(level not in allowed for level in levels):
        label = {"reviewed": "L3 or L4", "draft": "L1, L2, L3, or L4",
                 "diagnostic": "fixture"}[document["scope"]]
        raise ContractError(f"{document['scope']} plans may only use {label} validation")


def _validate_review_decisions(document: dict[str, Any]) -> None:
    matches = [
        (decision["claim_id"], decision["target_id"])
        for decision in document["claim_matches"]
    ]
    if len(matches) != len(set(matches)):
        raise ContractError("claim_id/target_id decision pairs must be unique")
    controls = document["control_assessments"]
    _unique([assessment["control_id"] for assessment in controls], "control_id")
    for assessment in controls:
        references = assessment["claim_ids"]
        if assessment["decision"] == "false_allegation" and not references:
            raise ContractError("false_allegation assessments require at least one claim_id")
        if assessment["decision"] == "quiet" and references:
            raise ContractError("quiet assessments must have no claim_ids")


def _validate_execution_record(document: dict[str, Any]) -> None:
    for index, artifact in enumerate(document["raw_artifacts"]):
        _require_relative_path(artifact["path"], f"raw_artifacts[{index}].path")
    trace = document.get("trace")
    if trace and trace.get("path") is not None:
        _require_relative_path(trace["path"], "trace.path")
    if document["status"] == "timeout" and not document["timed_out"]:
        raise ContractError("status 'timeout' requires timed_out to be true")


def _validate_case_pack(document: dict[str, Any]) -> None:
    """Check what a pack asserts about its own label states; it never re-runs a check.

    ``mechanically_checked`` is the L1 state and claims a passing check set for every snapshot
    the case references, ``checks_failed`` belongs only to an approved case whose checks later
    failed, and an L3/L4 label belongs only to a case screened as worth validating. These
    compare recorded fields with each other: none of them reads source, a reviewer, or a
    scanner, so a pack that passes here is consistent, not correct.
    """
    snapshots = [snapshot["snapshot_id"] for snapshot in document["snapshots"]]
    _unique(snapshots, "snapshot_id")
    known = set(snapshots)
    _unique([case["case_id"] for case in document["cases"]], "case_id")
    target_ids: list[str] = []
    control_ids: list[str] = []
    for case in document["cases"]:
        label = f"case {case['case_id']}"
        target = case["target"]
        target_ids.append(target["target_id"])
        if target["snapshot_id"] not in known:
            raise ContractError(f"{label}: target snapshot {target['snapshot_id']} is not declared")
        for index, location in enumerate(target["accepted_locations"]):
            _validate_location(location, f"{label}.target.accepted_locations[{index}]")
        evidence_ids = [item["evidence_id"] for item in case["evidence"]]
        _unique(evidence_ids, f"{label} evidence_id")
        for control in case["controls"]:
            control_ids.append(control["control_id"])
            if control["snapshot_id"] not in known:
                raise ContractError(f"{label}: control snapshot {control['snapshot_id']} is not declared")
            if control["type"] in ("fixed_target", "both") and control.get("target_id") != target["target_id"]:
                raise ContractError(f"{label}: fixed-target control {control['control_id']} must reference the case target")
            for index, location in enumerate(control["locations"]):
                _validate_location(location, f"{label}.control {control['control_id']}.locations[{index}]")
            missing = set(control["evidence_ids"]) - set(evidence_ids)
            if missing:
                raise ContractError(f"{label}: control {control['control_id']} references unknown evidence {sorted(missing)}")
        validation = case["validation"]
        state = validation["review_state"]
        approvals = [r for r in validation["reviews"] if r["decision"] == "approve"]
        if state == "human_approved" and not approvals:
            raise ContractError(f"{label}: human_approved requires at least one recorded approving review")
        if state == "human_approved" and validation["level"] is None:
            raise ContractError(f"{label}: human_approved requires a validation level")
        if validation["level"] in ("L3", "L4") and state != "human_approved":
            raise ContractError(f"{label}: {validation['level']} requires human_approved review state")
        if state == "draft" and validation["level"] is not None:
            raise ContractError(f"{label}: draft cases cannot carry a validation level")
        if "checks_failed" in validation and state != "human_approved":
            raise ContractError(
                f"{label}: checks_failed records a check set that failed after approval, so it "
                f"belongs only to a human_approved case, not to a {state} one")
        if state == "mechanically_checked":
            if validation["level"] != "L1":
                raise ContractError(
                    f"{label}: mechanically_checked is the L1 state; level {validation['level']!r} "
                    "needs a recorded human review")
            referenced = [target["snapshot_id"]] + [control["snapshot_id"] for control in case["controls"]]
            unchecked = sorted({snapshot for snapshot in referenced
                                if recorded_check_state(validation["checks"], snapshot) != "pass"})
            if unchecked:
                raise ContractError(
                    f"{label}: mechanically_checked requires a recorded passing check set for every "
                    f"referenced snapshot; missing or failed for: {', '.join(unchecked)}")
        if validation["level"] in ("L3", "L4") and case["disposition"]["value"] != "validate":
            raise ContractError(
                f"{label}: {validation['level']} requires disposition validate, not "
                f"{case['disposition']['value']}")
    _unique(target_ids, "target_id")
    _unique(control_ids, "control_id")
    case_ids = {case["case_id"] for case in document["cases"]}
    for admission in document["admissions"]:
        if admission["case_id"] not in case_ids:
            raise ContractError(f"admission references unknown case {admission['case_id']}")


def _validate_review_record(document: dict[str, Any]) -> None:
    if document["state"] == "human_approved":
        if not document["reviews"]:
            raise ContractError("human_approved review records need at least one review entry")
        if document["reviews"][-1]["decisions_sha256"] != document["decisions_sha256"]:
            raise ContractError("the latest review must bind to the current decisions hash")


def _validate_run_config(document: dict[str, Any]) -> None:
    _unique([system["system_id"] for system in document["systems"]], "system_id")
    _unique([item["snapshot_id"] for item in document["inputs"]], "inputs.snapshot_id")


def _validate_run_manifest(document: dict[str, Any]) -> None:
    """Check what the manifest asserts about itself; it says nothing about scan correctness.

    A failed run carries its failure, a completed run carries none, a skipped invocation has a
    reason and no bundle, and an invocation that ran has a bundle and no reason. Paths are
    checked for portability only: this does not open them or confirm that a bundle exists.
    """
    failed = document["status"] == "failed"
    if failed and "failure" not in document:
        raise ContractError("a failed run manifest must record its failure")
    if not failed and "failure" in document:
        raise ContractError("only a failed run manifest may record a failure")
    _unique([item["snapshot_id"] for item in document["inputs"]], "inputs.snapshot_id")
    _unique([system["system_id"] for system in document["systems"]], "systems.system_id")
    _unique([row["invocation_id"] for row in document["invocations"]], "invocation_id")
    for index, item in enumerate(document["inputs"]):
        _require_relative_path(item["provenance_path"], f"inputs[{index}].provenance_path")
    for index, row in enumerate(document["invocations"]):
        label = f"invocations[{index}]"
        if row["status"] == "skipped":
            if row["bundle_path"] is not None:
                raise ContractError(f"{label}: a skipped invocation has no bundle")
            if row["skipped_reason"] is None:
                raise ContractError(f"{label}: a skipped invocation must record why it was skipped")
        else:
            if row["bundle_path"] is None:
                raise ContractError(f"{label}: an invocation that ran must record its bundle path")
            if row["skipped_reason"] is not None:
                raise ContractError(f"{label}: an invocation that ran is not skipped")
            _require_relative_path(row["bundle_path"], f"{label}.bundle_path")


_RUNTIME_VALIDATORS = {
    "case-pack": _validate_case_pack,
    "review-record": _validate_review_record,
    "run-config": _validate_run_config,
    "execution-record": _validate_execution_record,
    "scan-request": _validate_scan_request,
    "scan-result": _validate_scan_result,
    "evaluation-plan": _validate_evaluation_plan,
    "review-decisions": _validate_review_decisions,
    "run-manifest": _validate_run_manifest,
}


def validate_document(kind: str, document: dict[str, Any]) -> dict[str, Any]:
    """Validate and return *document* unchanged.

    JSON Schema checks the language-neutral shape. Runtime checks enforce invariants
    that depend on multiple fields or on portable path semantics.
    """

    if not isinstance(document, dict):
        raise ContractError("contract document must be a JSON object")
    _reject_nonfinite(document)
    validator = Draft202012Validator(_schema(kind))
    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        raise ContractError(_format_error(errors[0]))
    _RUNTIME_VALIDATORS[kind](document)
    return document


def load_document(path: str | PathLike[str], kind: str) -> dict[str, Any]:
    """Load a JSON object from *path* and validate it as *kind*."""

    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(
                handle,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_json_constant,
            )
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"could not load {path}: {exc}") from exc
    return validate_document(kind, document)
