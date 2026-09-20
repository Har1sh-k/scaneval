"""Case packs: draft records, mechanical checks, explicit human approval, and plan generation.

A pack is evaluator-side data. Nothing in it is ever copied into a scanner workspace.
Code can create drafts and run mechanical (L1) checks; only a recorded human review can
raise a case beyond that, and the plan builder degrades to the lowest state present.

Mechanical checks are recorded per snapshot, so a case spanning a vulnerable and a fixed
snapshot reaches L1 only once every snapshot it references has passed. Nothing here reads
source semantics, establishes a root cause, infers a reviewer, or withdraws a human review:
a check that fails after approval is recorded and keeps the case out of a plan, and the
recorded review state and level stay exactly as the reviewer left them.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Callable

from .contracts import ContractError, canonical_json, canonical_sha256, load_document, validate_document


PACK_KIND = "case-pack"
LEVELS = ("L1", "L2", "L3", "L4")
DISPOSITIONS = ("validate", "needs_evidence", "extended_regression", "exclude")
REVIEWED_LEVELS = ("L3", "L4")
_ALIAS = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})$")
_REPRESENTS = re.compile(r"^This case tests .+ under .+, and adds .+", re.DOTALL)


def _now(clock: Callable[[], datetime] | None) -> str:
    moment = (clock or (lambda: datetime.now(timezone.utc)))()
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def field_state(state: str, reason: str = "") -> dict:
    value = {"state": state}
    if reason:
        value["reason"] = reason
    return value


def not_reviewed() -> dict:
    return field_state("not_reviewed")


def new_pack(namespace: str, pack_id: str, description: str, *, version: str = "0.1.0-draft",
             review_budgets: dict | None = None) -> dict:
    pack = {
        "schema_version": "2.0", "namespace": namespace, "pack_id": pack_id, "version": version,
        "status": "draft", "description": description,
        "review_budgets": review_budgets or {"full": [5, 10, 20, 50], "pr": [5, 10, 20]},
        "snapshots": [], "cases": [], "admissions": [],
        "notes": ["Draft pack. Labels become evidence only after recorded human review and admission."],
    }
    return validate_document(PACK_KIND, pack)


def load_pack(path: Path) -> dict:
    return load_document(path, PACK_KIND)


def save_pack(path: Path, pack: dict) -> None:
    validate_document(PACK_KIND, pack)
    path.write_text(json.dumps(pack, indent=2, ensure_ascii=False, sort_keys=False) + "\n", encoding="utf-8")


def pack_sha256(pack: dict) -> str:
    return canonical_sha256(pack)


def snapshot_by_id(pack: dict, snapshot_id: str) -> dict:
    for snapshot in pack["snapshots"]:
        if snapshot["snapshot_id"] == snapshot_id:
            return snapshot
    raise ContractError(f"unknown snapshot {snapshot_id!r} in pack {pack['namespace']}/{pack['pack_id']}")


def case_by_id(pack: dict, case_id: str) -> dict:
    for case in pack["cases"]:
        if case["case_id"] == case_id:
            return case
    raise ContractError(f"unknown case {case_id!r}")


def cases_for_snapshot(pack: dict, snapshot_id: str) -> list[dict]:
    return [case for case in pack["cases"]
            if case["target"]["snapshot_id"] == snapshot_id
            or any(control["snapshot_id"] == snapshot_id for control in case["controls"])]


def add_snapshot(pack: dict, snapshot: dict) -> dict:
    if any(existing["snapshot_id"] == snapshot["snapshot_id"] for existing in pack["snapshots"]):
        raise ContractError(f"snapshot {snapshot['snapshot_id']} already exists")
    record = {"tree_hash": None, "git_tree": None, "role": "vulnerable", **snapshot}
    pack["snapshots"].append(record)
    validate_document(PACK_KIND, pack)
    return record


def draft_case(case_id: str, *, snapshot_id: str, kind: str, description: str, represents: str,
               workload: str, component_role: str, aliases: list[str], evidence: list[dict],
               accepted_locations: list[dict] | None = None, assumptions: list[str] | None = None,
               matching_rules: list[str] | None = None, disposition: str = "needs_evidence",
               disposition_reason: str = "Draft record awaiting evidence review.",
               disclosure: dict | None = None, variant_family: str | None = None,
               model_involvement: Any = None, coverage_signature: dict | None = None,
               notes: list[str] | None = None) -> dict:
    """A draft case: every unresolved field is explicitly ``not_reviewed``, never guessed."""
    signature = {key: not_reviewed() for key in
                 ("idiom", "input_source", "trust_boundary", "security_operation", "guard_failure", "analysis_span")}
    signature.update(coverage_signature or {})
    case = {
        "case_id": case_id, "represents": represents, "workload": workload, "component_role": component_role,
        "model_involvement": model_involvement if model_involvement is not None else not_reviewed(),
        "coverage_signature": signature,
        "canonical_target": {"kind": kind, "variant_family": variant_family or case_id, "aliases": sorted(set(aliases))},
        "target": {"target_id": f"T-{case_id}", "snapshot_id": snapshot_id, "kind": kind, "description": description,
                   "affected_input_or_authority": not_reviewed(),
                   "accepted_locations": list(accepted_locations or []), "assumptions": list(assumptions or []),
                   "matching_rules": list(matching_rules or [])},
        "controls": [], "evidence": list(evidence),
        "disclosure": {"earliest_public_artifact": None, "cve_published": None, "ghsa_published": None,
                       "fix_commit_date": None, "note": "", **(disclosure or {})},
        "disposition": {"value": disposition, "reason": disposition_reason},
        "validation": {"level": None, "review_state": "draft", "checks": [], "reviews": []},
        "split": "unassigned", "notes": list(notes or []),
    }
    return case


def add_case(pack: dict, case: dict) -> dict:
    if any(existing["case_id"] == case["case_id"] for existing in pack["cases"]):
        raise ContractError(f"case {case['case_id']} already exists")
    pack["cases"].append(case)
    validate_document(PACK_KIND, pack)
    return case


def evidence(evidence_id: str, *, origin: str, kind: str, reference: str, note: str = "",
             revision: str | None = None, retrieved: str | None = None) -> dict:
    item = {"evidence_id": evidence_id, "origin": origin, "kind": kind, "reference": reference, "note": note}
    if revision:
        item["revision"] = revision
    if retrieved:
        item["retrieved"] = retrieved
    return item


def draft_case_from_legacy(legacy: dict, *, case_id: str, snapshot_id: str, legacy_path: str,
                           workload: str, component_role: str, represents: str) -> dict:
    """Migrate a legacy v1 case as draft evidence. Regions become candidate locations, not labels."""
    real = legacy.get("realWorld") or {}
    aliases = [value for value in (real.get("cve"), real.get("ghsa")) if value]
    items = [evidence("legacy-record", origin="legacy_case_record", kind="other", reference=legacy_path,
                      note=f"Legacy case {legacy.get('id')} ({legacy.get('caseType')}); prior draft regions, not v2-reviewed labels.")]
    if real.get("fixCommit"):
        items.append(evidence("fix-commit", origin="public_advisory_and_maintainer_fix", kind="fix_commit",
                              reference=f"{real.get('repo')}@{real['fixCommit']}", note="Fix commit named by the legacy record."))
    if real.get("ghsa"):
        items.append(evidence("ghsa", origin="public_advisory_and_maintainer_fix", kind="ghsa_advisory",
                              reference=f"https://github.com/advisories/{real['ghsa']}", note=""))
    if real.get("cve"):
        items.append(evidence("cve", origin="public_advisory_and_maintainer_fix", kind="cve_record",
                              reference=f"https://www.cve.org/CVERecord?id={real['cve']}", note=""))
    locations = []
    for region in legacy.get("regions", []):
        location = {"path": region["path"], "role": "other",
                    "note": f"legacy region {region.get('id')} label={region.get('label')} capability={region.get('capability')}"}
        if "startLine" in region and "endLine" in region:
            location.update({"start_line": int(region["startLine"]), "end_line": int(region["endLine"])})
        locations.append(location)
    disclosure = legacy.get("realWorld", {}).get("disclosure") or {}
    return draft_case(
        case_id, snapshot_id=snapshot_id, kind=legacy.get("canonicalKind", "unmapped"),
        description=legacy.get("description") or legacy.get("title") or case_id, represents=represents,
        workload=workload, component_role=component_role, aliases=aliases, evidence=items,
        accepted_locations=locations,
        disclosure={"ghsa_published": disclosure.get("ghsaPublished"), "fix_commit_date": disclosure.get("fixCommitDate"),
                    "note": "Dates copied from the legacy record; earliest public artifact not yet established."},
        disposition_reason="Migrated from a legacy v1 record: mapped regions are prior draft evidence and need v2 review.",
        notes=[f"legacy_id={legacy.get('id')}", f"legacy_title={legacy.get('title')}"],
    )


def _count_lines(path: Path) -> int:
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def referenced_snapshots(case: dict) -> list[str]:
    """Every snapshot a case needs checked: its target's snapshot, then each control's."""
    ordered = [case["target"]["snapshot_id"]] + [control["snapshot_id"] for control in case["controls"]]
    unique: list[str] = []
    for snapshot_id in ordered:
        if snapshot_id not in unique:
            unique.append(snapshot_id)
    return unique


def _recorded_check_state(case: dict, snapshot_id: str) -> str | None:
    """``pass`` or ``fail`` for one snapshot's recorded check set; ``None`` when none is recorded.

    Checks recorded before check sets carried a ``snapshot_id`` belong to no snapshot and are
    ignored here rather than deleted, so they neither promote nor demote a case.
    """
    recorded = [check for check in case["validation"]["checks"] if check.get("snapshot_id") == snapshot_id]
    if not recorded:
        return None
    return "pass" if all(check["result"] == "pass" for check in recorded) else "fail"


def mechanical_checks(pack: dict, snapshot_id: str, source_dir: Path, tree_hash: str,
                      *, clock: Callable[[], datetime] | None = None) -> list[dict]:
    """Run L1 checks against one exported tree for every case that references *snapshot_id*.

    Results are recorded per snapshot: this replaces only the check set carrying *snapshot_id*
    and leaves every other snapshot's results in place, so checking two snapshots of one case
    in either order ends in the same state. A case becomes ``mechanically_checked`` (L1) only
    once every snapshot it references has a recorded passing check set.

    A failing set demotes a ``mechanically_checked`` case to ``draft``. For a ``human_approved``
    case it records ``validation.checks_failed`` and leaves the review state and level untouched,
    because code never withdraws a human review; :func:`build_plan` then keeps that case out of
    the plan with a note. The flag is cleared only when every referenced snapshot passes again.

    These checks establish artifacts, paths, and ranges. They do not parse or read the code,
    establish a root cause, or approve anything, so they never raise a case past L1. A snapshot
    whose pack record already carries a different tree hash is not rewritten: every case on it
    records a failing ``snapshot_hash_recorded`` check instead, and both :func:`build_plan` and
    the runner still refuse that input.
    """
    snapshot = snapshot_by_id(pack, snapshot_id)
    declared = snapshot.get("tree_hash")
    hash_agrees = not declared or declared == tree_hash
    if hash_agrees:
        snapshot["tree_hash"] = tree_hash
    now = _now(clock)
    outcomes = []
    for case in cases_for_snapshot(pack, snapshot_id):
        checks = []

        def check(name: str, passed: bool, detail: str) -> None:
            checks.append({"check": name, "result": "pass" if passed else "fail", "at": now,
                           "detail": detail, "snapshot_id": snapshot_id})

        locations = [(case["target"]["target_id"], loc) for loc in case["target"]["accepted_locations"]
                     if case["target"]["snapshot_id"] == snapshot_id]
        locations += [(control["control_id"], loc) for control in case["controls"]
                      if control["snapshot_id"] == snapshot_id for loc in control["locations"]]
        missing = [loc["path"] for _, loc in locations if not (source_dir / loc["path"]).is_file()]
        check("locations_exist_in_snapshot", not missing and bool(locations),
              "missing: " + ", ".join(missing) if missing else ("no locations declared" if not locations else f"{len(locations)} locations found"))
        bad_ranges = []
        for owner, loc in locations:
            if "start_line" in loc and (source_dir / loc["path"]).is_file():
                if loc["end_line"] > _count_lines(source_dir / loc["path"]):
                    bad_ranges.append(f"{owner}:{loc['path']}:{loc['end_line']}")
        check("line_ranges_within_files", not bad_ranges, ", ".join(bad_ranges) or "all ranges within file length")
        aliases = case["canonical_target"]["aliases"]
        check("aliases_well_formed", all(_ALIAS.match(a) for a in aliases), ", ".join(aliases) or "no aliases")
        check("represents_statement", bool(_REPRESENTS.match(case["represents"])), "template: This case tests ... under ..., and adds ...")
        check("evidence_recorded", bool(case["evidence"]), f"{len(case['evidence'])} evidence records")
        check("snapshot_hash_recorded", hash_agrees,
              tree_hash if hash_agrees else f"pack records {declared}; this export is {tree_hash}")
        validation = case["validation"]
        validation["checks"] = [c for c in validation["checks"]
                                if c.get("snapshot_id") != snapshot_id] + checks
        passed = all(c["result"] == "pass" for c in checks)
        states = [_recorded_check_state(case, referenced) for referenced in referenced_snapshots(case)]
        every_snapshot_passed = all(state == "pass" for state in states)
        if validation["review_state"] == "human_approved":
            if "fail" in states:
                validation["checks_failed"] = True
            elif every_snapshot_passed:
                validation.pop("checks_failed", None)
        elif every_snapshot_passed:
            validation["review_state"] = "mechanically_checked"
            validation["level"] = "L1"
        elif "fail" in states and validation["review_state"] == "mechanically_checked":
            validation["review_state"] = "draft"
            validation["level"] = None
        outcomes.append({"case_id": case["case_id"], "passed": passed, "checks": checks,
                         "review_state": validation["review_state"], "level": validation["level"]})
    validate_document(PACK_KIND, pack)
    return outcomes


def approve_case(pack: dict, case_id: str, *, reviewer: str, role: str, level: str, note: str,
                 clock: Callable[[], datetime] | None = None) -> dict:
    """Record one explicit human review of a case label.

    The reviewer name comes from the caller and is stored verbatim; a blank or whitespace-only
    name is refused, because an unnamed approval is not an approval. This does not authenticate
    the reviewer, check their independence, or verify that anything was read, and it records a
    claim of review rather than establishing the label.
    """
    if level not in LEVELS:
        raise ContractError(f"level must be one of {LEVELS}")
    if not reviewer or not reviewer.strip():
        raise ContractError("approval requires an explicit reviewer name; the tool never supplies one")
    case = case_by_id(pack, case_id)
    validation = case["validation"]
    if validation["review_state"] == "draft":
        raise ContractError(f"case {case_id} has not passed mechanical checks; run corpus validate first")
    if level in REVIEWED_LEVELS and role != "independent_reviewer":
        raise ContractError("L3/L4 labels require an independent_reviewer decision")
    if level in REVIEWED_LEVELS and case["disposition"]["value"] != "validate":
        raise ContractError("L3/L4 require disposition validate")
    review = {"reviewer": reviewer, "role": role, "decision": "approve", "level": level, "at": _now(clock), "note": note}
    validation["reviews"].append(review)
    validation["review_state"] = "human_approved"
    validation["level"] = level
    validate_document(PACK_KIND, pack)
    return review


def set_disposition(pack: dict, case_id: str, value: str, reason: str) -> dict:
    """Record a screening-disposition change and the stated reason for it.

    A disposition is a screening decision about whether a candidate is worth validating. It is
    not a label, an approval, or an admission, and changing it neither re-runs a check nor
    alters a recorded review. The previous value stays visible in the case notes.
    """
    if value not in DISPOSITIONS:
        raise ContractError(f"disposition must be one of {DISPOSITIONS}")
    if not reason or not reason.strip():
        raise ContractError("a disposition change requires a non-blank reason")
    case = case_by_id(pack, case_id)
    previous = case["disposition"]["value"]
    case["disposition"] = {"value": value, "reason": reason}
    case["notes"].append(f"disposition changed from {previous} to {value}: {reason}")
    validate_document(PACK_KIND, pack)
    return case["disposition"]


def latest_admission(pack: dict, case_id: str) -> dict | None:
    """The last admission record for *case_id* by list order, or ``None`` when there is none.

    Order in the list is the only ordering used; timestamps are recorded text and are not parsed
    or sorted here.
    """
    latest = None
    for admission in pack["admissions"]:
        if admission["case_id"] == case_id:
            latest = admission
    return latest


def admit_case(pack: dict, case_id: str, *, decision: str, by: str, reason: str,
               clock: Callable[[], datetime] | None = None) -> dict:
    """Append one admission decision made by a named person, with a stated reason.

    The name and reason come from the caller and are stored verbatim; blank or whitespace-only
    values are refused. This records who decided, not that the decision is correct, and it does
    not change a case's review state or level.
    """
    case_by_id(pack, case_id)
    if not by or not by.strip():
        raise ContractError("an admission decision requires an explicit name; the tool never supplies one")
    if not reason or not reason.strip():
        raise ContractError("an admission decision requires a non-blank reason")
    admission = {"case_id": case_id, "decision": decision, "by": by, "at": _now(clock), "reason": reason}
    pack["admissions"].append(admission)
    validate_document(PACK_KIND, pack)
    return admission


def plan_scope(cases: list[dict]) -> str:
    states = {case["validation"]["review_state"] for case in cases}
    levels = {case["validation"]["level"] for case in cases}
    if cases and states == {"human_approved"} and levels <= {"L3", "L4"}:
        return "reviewed"
    return "draft"


def build_plan(pack: dict, snapshot_id: str, tree_hash: str, *, mode: str = "full") -> tuple[dict, list[str]]:
    """Targets and controls for one materialized input, with every exclusion stated in the notes.

    A case is planned only when its disposition is not ``exclude``, no check set failed after
    approval, its latest admission decision is not ``rejected``, and it passed mechanical checks
    on every snapshot it references. Planned items keep their real validation level; the plan's
    scope, not a rewritten level, says whether the labels are reviewed drafts.

    This builds a plan. It does not approve, admit, re-check, or correct anything, and a case
    left out here is unplanned for this input, not judged wrong.
    """
    snapshot = snapshot_by_id(pack, snapshot_id)
    if snapshot.get("tree_hash") and snapshot["tree_hash"] != tree_hash:
        raise ContractError(f"snapshot {snapshot_id} tree hash does not match the materialized input")
    notes: list[str] = []
    included: list[dict] = []
    for case in cases_for_snapshot(pack, snapshot_id):
        case_id = case["case_id"]
        validation = case["validation"]
        admission = latest_admission(pack, case_id)
        if case["disposition"]["value"] == "exclude":
            notes.append(f"{case_id}: excluded by disposition ({case['disposition']['reason']})")
        elif validation.get("checks_failed"):
            notes.append(f"{case_id}: excluded because a mechanical check set failed after approval; "
                         "the recorded review stands and needs a correction decision")
        elif admission is not None and admission["decision"] == "rejected":
            notes.append(f"{case_id}: excluded by the latest admission decision "
                         f"(rejected by {admission['by']}: {admission['reason']})")
        elif validation["review_state"] == "draft" or validation["level"] is None:
            notes.append(f"{case_id}: draft without passed mechanical checks; not planned")
        else:
            included.append(case)
    scope = plan_scope(included)
    targets, controls = [], []
    for case in included:
        level = case["validation"]["level"]
        target = case["target"]
        if target["snapshot_id"] == snapshot_id:
            targets.append({"target_id": target["target_id"], "description": target["description"],
                            "kind": target["kind"], "validation_level": level})
        for control in case["controls"]:
            if control["snapshot_id"] == snapshot_id:
                entry = {"control_id": control["control_id"], "description": control["description"],
                         "type": control["type"], "validation_level": level}
                if control.get("target_id"):
                    entry["target_id"] = control["target_id"]
                controls.append(entry)
    if scope == "reviewed" and not (targets or controls):
        scope = "draft"
    plan = {
        "schema_version": "2.0", "input_hash": tree_hash, "scope": scope,
        "targets": targets, "controls": controls,
        "review_budgets": list(pack["review_budgets"]["full" if mode == "full" else "pr"]),
        "provenance": {"namespace": pack["namespace"], "pack_id": pack["pack_id"], "pack_version": pack["version"],
                       "pack_sha256": pack_sha256(pack), "snapshot_id": snapshot_id, "mode": mode,
                       "case_ids": [case["case_id"] for case in included]},
    }
    validate_document("evaluation-plan", plan)
    if not targets and not controls:
        notes.append("no planned targets or controls for this input; scores will be N/A")
    return plan, notes


def accepted_paths_for_targets(pack: dict, target_ids: set[str]) -> dict[str, set[str]]:
    """Evaluator-side helper: accepted location paths per target, for routing claims to review."""
    paths: dict[str, set[str]] = {}
    for case in pack["cases"]:
        target = case["target"]
        if target["target_id"] in target_ids:
            paths[target["target_id"]] = {loc["path"] for loc in target["accepted_locations"]}
    return paths


def control_paths(pack: dict, control_ids: set[str]) -> dict[str, set[str]]:
    paths: dict[str, set[str]] = {}
    for case in pack["cases"]:
        for control in case["controls"]:
            if control["control_id"] in control_ids:
                paths[control["control_id"]] = {loc["path"] for loc in control["locations"]}
    return paths


def pack_summary(pack: dict) -> dict:
    return {
        "namespace": pack["namespace"], "pack_id": pack["pack_id"], "version": pack["version"], "status": pack["status"],
        "snapshots": len(pack["snapshots"]), "cases": len(pack["cases"]),
        "review_states": {state: sum(1 for c in pack["cases"] if c["validation"]["review_state"] == state)
                          for state in ("draft", "mechanically_checked", "human_approved")},
        "dispositions": {value: sum(1 for c in pack["cases"] if c["disposition"]["value"] == value)
                         for value in ("validate", "needs_evidence", "extended_regression", "exclude")},
        "sha256": pack_sha256(pack),
    }


def dump_json(value: dict) -> str:
    return canonical_json(value) + "\n"
