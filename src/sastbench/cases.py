"""Case packs: draft records, mechanical checks, explicit human approval, and plan generation.

A pack is evaluator-side data. Nothing in it is ever copied into a scanner workspace.
Code can create drafts and run mechanical (L1) checks; only a recorded human review can
raise a case beyond that, and the plan builder degrades to the lowest state present.
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


def mechanical_checks(pack: dict, snapshot_id: str, source_dir: Path, tree_hash: str,
                      *, clock: Callable[[], datetime] | None = None) -> list[dict]:
    """Run L1 checks for every case on *snapshot_id* against an exported tree; record results in the pack."""
    snapshot = snapshot_by_id(pack, snapshot_id)
    if snapshot.get("tree_hash") and snapshot["tree_hash"] != tree_hash:
        raise ContractError(f"snapshot {snapshot_id} tree hash {snapshot['tree_hash']} != materialized {tree_hash}")
    snapshot["tree_hash"] = tree_hash
    now = _now(clock)
    outcomes = []
    for case in cases_for_snapshot(pack, snapshot_id):
        checks = []

        def check(name: str, passed: bool, detail: str) -> None:
            checks.append({"check": name, "result": "pass" if passed else "fail", "at": now, "detail": detail})

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
        check("snapshot_hash_recorded", True, tree_hash)
        validation = case["validation"]
        validation["checks"] = [c for c in validation["checks"] if not c["at"] == now] + checks
        passed = all(c["result"] == "pass" for c in checks)
        if validation["review_state"] == "draft" and passed:
            validation["review_state"] = "mechanically_checked"
            validation["level"] = "L1"
        elif validation["review_state"] == "mechanically_checked" and not passed:
            validation["review_state"] = "draft"
            validation["level"] = None
        outcomes.append({"case_id": case["case_id"], "passed": passed, "checks": checks,
                         "review_state": validation["review_state"], "level": validation["level"]})
    validate_document(PACK_KIND, pack)
    return outcomes


def approve_case(pack: dict, case_id: str, *, reviewer: str, role: str, level: str, note: str,
                 clock: Callable[[], datetime] | None = None) -> dict:
    """Record an explicit human review. The tool never infers approval."""
    if level not in LEVELS:
        raise ContractError(f"level must be one of {LEVELS}")
    case = case_by_id(pack, case_id)
    validation = case["validation"]
    if validation["review_state"] == "draft":
        raise ContractError(f"case {case_id} has not passed mechanical checks; run corpus validate first")
    if level in ("L3", "L4") and role != "independent_reviewer":
        raise ContractError("L3/L4 labels require an independent_reviewer decision")
    review = {"reviewer": reviewer, "role": role, "decision": "approve", "level": level, "at": _now(clock), "note": note}
    validation["reviews"].append(review)
    validation["review_state"] = "human_approved"
    validation["level"] = level
    validate_document(PACK_KIND, pack)
    return review


def admit_case(pack: dict, case_id: str, *, decision: str, by: str, reason: str,
               clock: Callable[[], datetime] | None = None) -> dict:
    case_by_id(pack, case_id)
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
    """Targets and controls for one materialized input. Draft cases without checks are left out, visibly."""
    snapshot = snapshot_by_id(pack, snapshot_id)
    if snapshot.get("tree_hash") and snapshot["tree_hash"] != tree_hash:
        raise ContractError(f"snapshot {snapshot_id} tree hash does not match the materialized input")
    notes: list[str] = []
    included: list[dict] = []
    for case in cases_for_snapshot(pack, snapshot_id):
        state = case["validation"]["review_state"]
        if case["disposition"]["value"] == "exclude":
            notes.append(f"{case['case_id']}: excluded by disposition ({case['disposition']['reason']})")
        elif state == "draft" or case["validation"]["level"] is None:
            notes.append(f"{case['case_id']}: draft without passed mechanical checks; not planned")
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
    if scope == "draft":
        for item in targets + controls:
            if item["validation_level"] in ("L3", "L4"):
                item["validation_level"] = "L2"
                notes.append(f"{item.get('target_id') or item.get('control_id')}: reported at L2 inside a draft plan")
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
