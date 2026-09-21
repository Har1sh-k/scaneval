"""Validation and canonicalization helpers for ScanEval v2 contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from importlib.resources import files
from os import PathLike
from typing import Any

from jsonschema import Draft202012Validator


CONTRACT_KINDS = frozenset(
    {"scan-request", "scan-result", "evaluation-plan", "review-decisions", "execution-record",
     "case-pack", "review-record", "run-config", "run-manifest"}
)
_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
# Validation levels are ordered, so an approval at a higher level carries a lower claimed one.
_LEVEL_RANK = {"L1": 1, "L2": 2, "L3": 3, "L4": 4}


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


# Space, separator, format, and control characters: a string made only of these says nothing.
_BLANK_CATEGORIES = frozenset({"Zs", "Zl", "Zp", "Cf", "Cc"})


def is_stated(value: Any) -> bool:
    """True when *value* is a string that both survives stripping and holds a non-blank character.

    Blank here means Unicode category ``Zs`` (spaces), ``Zl``/``Zp`` (line and paragraph
    separators), ``Cf`` (zero-width and directional marks), or ``Cc`` (control characters), so a
    name made only of U+200B zero-width spaces is not a name even though stripping it leaves a
    non-empty string. Both tests must pass. This judges characters only: it says nothing about
    whether a name belongs to a person or a reason explains anything.

    :func:`scaneval.cases._is_stated` applies the same rule one layer up, where the write paths
    live; the copy here exists because :mod:`scaneval.cases` imports this module and not the
    other way round, and a test pins the two functions to the same answers.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    return any(unicodedata.category(ch) not in _BLANK_CATEGORIES for ch in value)


def _schema(kind: str) -> dict[str, Any]:
    if kind not in CONTRACT_KINDS:
        expected = ", ".join(sorted(CONTRACT_KINDS))
        raise ContractError(f"unknown contract kind {kind!r}; expected one of: {expected}")
    resource = files("scaneval").joinpath("schemas", f"{kind}.schema.json")
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


def reject_nonfinite(value: Any, path: str = "document") -> None:
    """Refuse a NaN or infinity anywhere in *value*, naming where it sits.

    This walks dicts and lists only, so a non-finite float hidden inside another container
    type is not found here; :func:`canonical_json` refuses that value for a different reason.
    """
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError(f"{path} contains a non-finite number")
    if isinstance(value, dict):
        for key, item in value.items():
            reject_nonfinite(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_nonfinite(item, f"{path}[{index}]")


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


def _label_projection(case: dict[str, Any]) -> dict[str, Any]:
    """The label content of *case*: what a reviewer of it passed judgment on.

    Only the fields that say what is being alleged are projected, and a reviewer approving a case
    approves what the case claims to be as well as where it claims it: the canonical target, the
    coverage signature, the represents statement, the workload, the component role, and whether a
    model was involved are projected alongside the target and the controls.

    The case identifier, its evidence records, its disclosure dates, its disposition, its split,
    its notes, and the recorded reviews and checks are left out: those say where a label came from
    or what is being done with it, not what it alleges, and changing one of them does not change
    what a reviewer read. The target's own identifier is projected, so an admission recorded
    against that identifier is bound to content this digest covers.

    Two orderings are normalized because neither carries content: controls are projected in
    ``control_id`` order, which the contract keeps unique pack-wide, and aliases are sorted, which
    the contract keeps unique within the case. Reordering either list alone is therefore not a
    content change, while adding, removing, renaming, or editing an entry is.
    """
    target = case["target"]
    canonical = case["canonical_target"]
    return {
        "represents": case["represents"],
        "workload": case["workload"],
        "component_role": case["component_role"],
        "model_involvement": case["model_involvement"],
        "coverage_signature": case["coverage_signature"],
        "canonical_target": {
            "kind": canonical["kind"],
            "variant_family": canonical["variant_family"],
            "aliases": sorted(canonical["aliases"]),
        },
        "target": {
            "target_id": target["target_id"],
            "snapshot_id": target["snapshot_id"],
            "kind": target["kind"],
            "description": target["description"],
            "affected_input_or_authority": target.get("affected_input_or_authority"),
            "accepted_locations": target["accepted_locations"],
            "assumptions": target["assumptions"],
            "matching_rules": target["matching_rules"],
        },
        "controls": [
            {
                "control_id": control["control_id"],
                "snapshot_id": control["snapshot_id"],
                "type": control["type"],
                "target_id": control.get("target_id"),
                "description": control["description"],
                "property": control["property"],
                "allowed_actors_inputs": control["allowed_actors_inputs"],
                "assumptions": control["assumptions"],
                "ruled_out_allegation": control["ruled_out_allegation"],
                "locations": control["locations"],
            }
            for control in sorted(case["controls"], key=lambda control: control["control_id"])
        ],
    }


def label_digest(case: dict[str, Any]) -> str:
    """The digest of one case's labels: what it claims to be, its target, and every control.

    A recorded approval carries this digest, so an approval is bound to the content it covered
    rather than to the case it sits on. Adding, removing, or editing a control changes it, as
    does editing the target's mechanism, description, affected input, accepted locations,
    assumptions, or matching rules, and so does editing what the case says it represents: its
    canonical kind, variant family, aliases, coverage signature, represents statement, workload,
    component role, or model involvement. None of those can ride on an earlier review.

    The snapshot each label names is projected too: moving a target or a control onto a
    different snapshot changes what was reviewed exactly as editing its text does.

    This lives here rather than in :mod:`scaneval.cases` because both the planning gate and the
    pack-load gate must ask the same question of the same content, and :mod:`scaneval.cases`
    imports this module and not the other way round. :mod:`scaneval.cases` re-exports it.
    """
    return canonical_sha256(_label_projection(case))


def covering_review(case: dict[str, Any]) -> dict[str, Any] | None:
    """The one recorded review that approves *case* as its labels now stand, or ``None``.

    The latest recorded review is the operative one, so this is that review when it approved the
    case and carries :func:`label_digest` of these labels. ``None`` when a later review rejected
    the case or reopened the question, when the labels changed after the approval, when no review
    is recorded, and when the latest review records no digest at all: a review that never named
    the content it read cannot be shown to cover this content.

    Every gate that asks whether an approval is in force asks this one review, so a plan and a
    pack load cannot end up resting on two different reviews. Nothing is rewritten or withdrawn
    here; this reads what the pack records.
    """
    reviews = case["validation"]["reviews"]
    if not reviews:
        return None
    review = reviews[-1]
    if review["decision"] != "approve" or not review.get("labels_sha256"):
        return None
    return review if review["labels_sha256"] == label_digest(case) else None


def level_gap(review: dict[str, Any], claimed: str | None) -> str | None:
    """Why *review* does not itself earn *claimed*, or ``None`` when it does.

    Levels are ordered, so an approval recorded at a higher level earns a lower claimed one. L3
    and L4 rest on an independent review, so the one review being asked must itself carry that
    role: an independent approval elsewhere in the history was an approval of other content and
    earns nothing here. ``None`` for a case claiming no level, which has nothing to earn.
    """
    if claimed is None:
        return None
    if review["decision"] != "approve":
        return f"the review covering these labels decided {review['decision']}, not approve"
    if _LEVEL_RANK[review["level"]] < _LEVEL_RANK[claimed]:
        return (f"the review covering these labels is recorded at {review['level']}; {claimed} "
                f"requires an approving review recorded at {claimed} or higher")
    if claimed in ("L3", "L4") and review["role"] != "independent_reviewer":
        return (f"the review covering these labels carries the role {review['role']}; {claimed} "
                f"requires an approving review at {claimed} or higher by an independent_reviewer")
    return None


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
    """Check claim ids, locations, ranking, and that every cited raw artifact is declared.

    A claim's ``raw_artifact_id`` is the evidence the claim rests on, so it must name one of
    the ``raw_artifacts`` entries this same result declares. A reference to an id the result
    does not register points at nothing the bundle holds, and it is refused here rather than in
    any one adapter, so no importer can hand out a citation the bundle cannot honor. This
    checks the reference only: whether the declared artifact's bytes support the allegation is
    a review question that nothing in this file can see.
    """
    claims = document["claims"]
    _unique([claim["claim_id"] for claim in claims], "claim_id")
    declared = {artifact["id"] for artifact in document.get("raw_artifacts", [])}
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
        reference = claim.get("raw_artifact_id")
        if reference is not None and reference not in declared:
            known = ", ".join(sorted(declared)) or "none"
            raise ContractError(
                f"claim {claim['claim_id']!r} cites raw_artifact_id {reference!r}, which this "
                f"result does not declare in raw_artifacts; declared ids: {known}")
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
    failed, and an L3/L4 label belongs only to a case screened as worth validating. A
    ``human_approved`` case makes the same claim about its check sets as a mechanically checked
    one unless it raises ``checks_failed``, and it cannot stand under a latest review that
    rejected it.

    Its level must be earned by the one review that covers the labels as they stand, which
    :func:`covering_review` names and :func:`level_gap` measures: that review must itself be
    recorded at the claimed level or higher, and for L3 or L4 must itself be by an
    ``independent_reviewer``. An independent approval elsewhere in the history approved other
    content and earns nothing here, so a case cannot be raised to a reviewed level by editing a
    label, collecting a lesser approval of the edit, and resting the level on the older review.
    :func:`scaneval.cases.approval_is_current` asks the same review the same question, so a plan
    and a pack load cannot rest on two different ones. When no recorded review covers the current
    labels the case plans nothing whatever it claims, and the weaker rule applies instead: the
    level must be one some recorded approval carries, so the pack still cannot claim a review
    nobody recorded.

    Which export a check set read is recorded three times, and the three must agree: the
    ``checked_trees`` entry for the snapshot, the ``detail`` of that set's passing
    ``snapshot_hash_recorded`` check, and the ``tree_hash`` the snapshot declares. A passing set
    that names its export must carry the check confirming it, and a ``checked_trees`` entry for a
    snapshot no recorded check set ran against records a check that never happened. Editing any
    two of the three therefore contradicts the third rather than pointing a standing approval at
    an export the checks never ran against. A failing set is exempt from the comparison with the
    declared hash, because recording the export that was read and rejected is exactly what it is
    for; a failing set keeps the case out of a plan anyway.

    Every recorded review names a reviewer and every admission names who decided it, by the same
    :func:`is_stated` rule the write paths apply, so a hand-edited pack cannot claim a review or an
    admission by an unnamed person. Every admission also names the ``target_id`` it decided, which
    :func:`label_digest` covers, and that target must still be the one the named case carries:
    renaming two cases around a standing decision no longer moves it onto different content.

    Whether a recorded approval still covers the labels as they stand is a planning question,
    answered by :func:`scaneval.cases.approval_is_current`, not a consistency one: a pack whose
    labels changed after a review is still a truthful record of that review and loads here.
    These compare recorded fields with each other: none of them reads source, a reviewer, or a
    scanner, so a pack that passes here is consistent, not correct. A stated name is a string
    with a character in it; whether it names a real person who did the work is outside anything
    this file can see.
    """
    snapshots = [snapshot["snapshot_id"] for snapshot in document["snapshots"]]
    _unique(snapshots, "snapshot_id")
    known = set(snapshots)
    snapshot_hashes = {snapshot["snapshot_id"]: snapshot.get("tree_hash") for snapshot in document["snapshots"]}
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
        reviews = validation["reviews"]
        for index, review in enumerate(reviews):
            if not is_stated(review["reviewer"]):
                raise ContractError(
                    f"{label}: a recorded review must name its reviewer; "
                    f"validation.reviews[{index}].reviewer is blank")
        approvals = [r for r in reviews if r["decision"] == "approve"]
        referenced = [target["snapshot_id"]] + [control["snapshot_id"] for control in case["controls"]]
        unchecked = sorted({snapshot for snapshot in referenced
                            if recorded_check_state(validation["checks"], snapshot) != "pass"})
        if state == "human_approved" and not approvals:
            raise ContractError(f"{label}: human_approved requires at least one recorded approving review")
        if state == "human_approved" and validation["level"] is None:
            raise ContractError(f"{label}: human_approved requires a validation level")
        if state == "human_approved" and reviews and reviews[-1]["decision"] == "reject":
            raise ContractError(
                f"{label}: the latest recorded review rejected this case, so it cannot also be "
                "human_approved; record the decision that reinstated it")
        if state == "human_approved" and unchecked and not validation.get("checks_failed"):
            raise ContractError(
                f"{label}: human_approved requires a recorded passing check set for every referenced "
                f"snapshot, or validation.checks_failed to record that one failed; missing or failed "
                f"for: {', '.join(unchecked)}")
        if state == "human_approved" and validation["level"] is not None:
            claimed = validation["level"]
            covering = covering_review(case)
            if covering is not None:
                # One review covers these labels, so that review alone earns the claimed level:
                # an approval elsewhere in the history approved other content.
                gap = level_gap(covering, claimed)
                if gap:
                    raise ContractError(f"{label}: {gap}")
            else:
                # No recorded review covers the labels as they stand, so planning leaves the case
                # out whatever it claims. The level must still be one the history records, or the
                # pack claims a review nobody recorded.
                carried = [r for r in approvals if _LEVEL_RANK[r["level"]] >= _LEVEL_RANK[claimed]]
                if not carried:
                    recorded = ", ".join(sorted({r["level"] for r in approvals})) or "none"
                    raise ContractError(
                        f"{label}: level {claimed} requires an approving review recorded at {claimed} or "
                        f"higher; the recorded approvals are at {recorded}")
                if claimed in ("L3", "L4") and not any(r["role"] == "independent_reviewer" for r in carried):
                    raise ContractError(
                        f"{label}: {claimed} requires an approving review at {claimed} or higher by an "
                        "independent_reviewer; no recorded approval carries that role")
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
            if unchecked:
                raise ContractError(
                    f"{label}: mechanically_checked requires a recorded passing check set for every "
                    f"referenced snapshot; missing or failed for: {', '.join(unchecked)}")
        if validation["level"] in ("L3", "L4") and case["disposition"]["value"] != "validate":
            raise ContractError(
                f"{label}: {validation['level']} requires disposition validate, not "
                f"{case['disposition']['value']}")
        # The three records of which export each check set read, compared with each other. These
        # run after the state rules so that a pack missing a check set is told that first: a
        # record of a set that is not there is a narrower complaint than the set being absent.
        recorded_trees = validation.get("checked_trees", {})
        for snapshot_id, entry in sorted(recorded_trees.items()):
            if not any(check.get("snapshot_id") == snapshot_id for check in validation["checks"]):
                raise ContractError(
                    f"{label}: validation.checked_trees records {entry} for snapshot {snapshot_id}, "
                    "but no recorded check set ran against that snapshot")
        for snapshot_id in sorted(set(referenced)):
            confirmed = {check["detail"] for check in validation["checks"]
                         if check.get("snapshot_id") == snapshot_id
                         and check["check"] == "snapshot_hash_recorded" and check["result"] == "pass"}
            declared = snapshot_hashes.get(snapshot_id)
            entry = recorded_trees.get(snapshot_id)
            if confirmed and not declared:
                raise ContractError(
                    f"{label}: snapshot {snapshot_id} records a passing snapshot_hash_recorded check "
                    "but the snapshot carries no tree_hash")
            if confirmed and {declared} != confirmed:
                raise ContractError(
                    f"{label}: snapshot {snapshot_id} records a passing snapshot_hash_recorded check "
                    f"for {', '.join(sorted(confirmed))}, but the snapshot declares {declared}; the "
                    "checks ran against an export the snapshot no longer names")
            if entry is not None and confirmed and {entry} != confirmed:
                raise ContractError(
                    f"{label}: validation.checked_trees records {entry} for snapshot {snapshot_id}, "
                    f"but that check set's passing snapshot_hash_recorded check records "
                    f"{', '.join(sorted(confirmed))}")
            if (entry is not None and not confirmed
                    and recorded_check_state(validation["checks"], snapshot_id) == "pass"):
                raise ContractError(
                    f"{label}: validation.checked_trees records {entry} for snapshot {snapshot_id}, "
                    "but that passing check set carries no passing snapshot_hash_recorded check to "
                    "confirm it")
    _unique(target_ids, "target_id")
    _unique(control_ids, "control_id")
    targets_by_case = {case["case_id"]: case["target"]["target_id"] for case in document["cases"]}
    for index, admission in enumerate(document["admissions"]):
        if admission["case_id"] not in targets_by_case:
            raise ContractError(f"admission references unknown case {admission['case_id']}")
        named = targets_by_case[admission["case_id"]]
        if admission["target_id"] != named:
            raise ContractError(
                f"admissions[{index}] was recorded against target {admission['target_id']} of case "
                f"{admission['case_id']}, which now carries target {named}; the decision no longer "
                "resolves to the content it named")
        if not is_stated(admission["by"]):
            raise ContractError(
                f"a recorded admission must name who decided it; admissions[{index}].by is blank")


def _validate_review_record(document: dict[str, Any]) -> None:
    """Check what the record asserts about itself; it says nothing about the decisions' quality.

    Every recorded review names a reviewer, by the same :func:`is_stated` rule the write paths
    apply, so a hand-edited record cannot report an approval by an unnamed person. An approved
    record carries at least one review and its latest review binds to the current decisions
    hash. Whether the named person read anything is outside what this can see.
    """
    for index, review in enumerate(document["reviews"]):
        if not is_stated(review["reviewer"]):
            raise ContractError(
                f"a recorded review must name its reviewer; reviews[{index}].reviewer is blank")
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
    reject_nonfinite(document)
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
    """Load a JSON object from *path* and validate it as *kind*.

    A file that cannot be opened or read, whose bytes are not UTF-8, or whose text the JSON
    parser will not turn into a value is refused as a :class:`ContractError` naming *path*, so a
    caller reporting the failure can say which file it was. Reading is why :class:`ValueError`
    is caught whole rather than by subclass: a non-UTF-8 file raises :class:`UnicodeDecodeError`,
    malformed syntax raises :class:`json.JSONDecodeError`, an integer literal longer than
    :func:`sys.get_int_max_str_digits` (4300 digits unless the interpreter was told otherwise;
    this module does not change that limit) raises a bare :class:`ValueError`, and the hooks here
    raise :class:`ContractError` for a duplicate key or a non-finite constant. A document nested
    past the interpreter's recursion limit raises :class:`RecursionError`, which is not a
    :class:`ValueError` at all, so it is named too rather than escaping as the
    :class:`RuntimeError` it also is. Anything the document itself violates is reported by
    :func:`validate_document`, whose messages name the field, not the file; that call sits
    outside this ``try`` so its messages are not rewritten to look like a read failure.
    """

    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(
                handle,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_json_constant,
            )
    except (OSError, ValueError, RecursionError) as exc:
        raise ContractError(f"could not load {path}: {exc}") from exc
    return validate_document(kind, document)
