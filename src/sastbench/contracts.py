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
    {"scan-request", "scan-result", "evaluation-plan", "review-decisions"}
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
    _unique([target["target_id"] for target in document["targets"]], "target_id")
    _unique([control["control_id"] for control in document["controls"]], "control_id")
    levels = [item["validation_level"] for item in document["targets"]]
    levels += [item["validation_level"] for item in document["controls"]]
    allowed = {"L3", "L4"} if document["scope"] == "reviewed" else {"fixture"}
    if any(level not in allowed for level in levels):
        label = "L3 or L4" if document["scope"] == "reviewed" else "fixture"
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


_RUNTIME_VALIDATORS = {
    "scan-request": _validate_scan_request,
    "scan-result": _validate_scan_result,
    "evaluation-plan": _validate_evaluation_plan,
    "review-decisions": _validate_review_decisions,
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
