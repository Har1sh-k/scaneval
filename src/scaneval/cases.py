"""Case packs: draft records, mechanical checks, explicit human approval, and plan generation.

A pack is evaluator-side data. Nothing in it is ever copied into a scanner workspace.
Code can create drafts and run mechanical (L1) checks; only a recorded human review can
raise a case beyond that, and the plan builder degrades to the lowest state present.

Mechanical checks are recorded per snapshot, so a case spanning a vulnerable and a fixed
snapshot reaches L1 only once every snapshot it references has passed. Nothing here reads
source semantics, establishes a root cause, infers a reviewer, or withdraws a human review:
a check that fails after approval is recorded and keeps the case out of a plan, and the
recorded review state and level stay exactly as the reviewer left them.

An approval covers the label content it was recorded against, not the case id: each approving
review carries :func:`label_digest` of the target and controls as they stood, so a label edited
or a control added afterwards is outside every recorded review. Such a case keeps its reviews,
because a review is a historical fact, and :func:`build_plan` leaves it out until a review
covers the labels as they stand.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Callable
import unicodedata

from .contracts import (
    ContractError,
    canonical_json,
    canonical_sha256,
    load_document,
    recorded_check_state,
    validate_document,
)


PACK_KIND = "case-pack"
LEVELS = ("L1", "L2", "L3", "L4")
DISPOSITIONS = ("validate", "needs_evidence", "extended_regression", "exclude")
REVIEWED_LEVELS = ("L3", "L4")
# A public identifier must be well formed, so a typo in a CVE or GHSA id is caught. Any other
# identifier shape is accepted: a private pack names its cases by internal ticket or review id,
# and the design states a CVE is neither required nor sufficient.
_PUBLIC_ALIAS = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})$")
_PUBLIC_ALIAS_PREFIX = re.compile(r"^(CVE|GHSA)[-_]", re.IGNORECASE)


def alias_problem(alias: str) -> str | None:
    """Return why *alias* is unusable as an identifier, or None when it is fine."""
    if not isinstance(alias, str) or not alias.strip():
        return "an identifier cannot be blank"
    if _PUBLIC_ALIAS_PREFIX.match(alias) and not _PUBLIC_ALIAS.match(alias):
        return f"{alias} is not a well formed CVE or GHSA identifier"
    return None
_REPRESENTS = re.compile(r"^This case tests .+ under .+, and adds .+", re.DOTALL)
_TREE_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


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


# Space, separator, format, and control characters: a string made only of these says nothing.
_BLANK_CATEGORIES = frozenset({"Zs", "Zl", "Zp", "Cf", "Cc"})


def _is_stated(value: Any) -> bool:
    """True when *value* is a string that both survives stripping and holds a non-blank character.

    Blank here means Unicode category ``Zs`` (spaces), ``Zl``/``Zp`` (line and paragraph
    separators), ``Cf`` (zero-width and directional marks), or ``Cc`` (control characters), so a
    name made only of U+200B zero-width spaces is not a name even though stripping it leaves a
    non-empty string. Both tests must pass. Against the Unicode data this build sees, the
    category test is the stricter of the two: every character Python strips already falls in one
    of these categories, while many characters in them survive stripping. The strip is kept
    because it is the plain reading of blank and does not depend on that staying true. This
    judges characters only: it says nothing about whether a name belongs to a person or a reason
    explains anything.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    return any(unicodedata.category(ch) not in _BLANK_CATEGORIES for ch in value)


def _require_stated(value: Any, message: str) -> str:
    if not _is_stated(value):
        raise ContractError(message)
    return value


def _apply_validated(pack: dict, mutate: Callable[[dict], Any]) -> Any:
    """Apply *mutate* to a deep copy of *pack*, validate it, and only then swap it in.

    A refused change leaves *pack* exactly as it was, because the mutation never touched it.
    On success the validated copy replaces the pack's contents in place, so the caller's
    pack reference stays valid while references taken to nested objects beforehand point at
    the superseded copy. Validation checks the document against the contract; it does not
    check that the change was a good idea.
    """
    candidate = copy.deepcopy(pack)
    result = mutate(candidate)
    validate_document(PACK_KIND, candidate)
    pack.clear()
    pack.update(candidate)
    return result


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
    """Record one pinned snapshot. A snapshot the contract refuses leaves the pack unchanged."""
    if any(existing["snapshot_id"] == snapshot["snapshot_id"] for existing in pack["snapshots"]):
        raise ContractError(f"snapshot {snapshot['snapshot_id']} already exists")
    record = copy.deepcopy({"tree_hash": None, "git_tree": None, "role": "vulnerable", **snapshot})

    def mutate(candidate: dict) -> dict:
        candidate["snapshots"].append(record)
        return record

    return _apply_validated(pack, mutate)


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
    """Record one case. A case the contract refuses leaves the pack unchanged."""
    if any(existing["case_id"] == case["case_id"] for existing in pack["cases"]):
        raise ContractError(f"case {case['case_id']} already exists")
    record = copy.deepcopy(case)

    def mutate(candidate: dict) -> dict:
        candidate["cases"].append(record)
        return record

    return _apply_validated(pack, mutate)


def evidence(evidence_id: str, *, origin: str, kind: str, reference: str, note: str = "",
             revision: str | None = None, retrieved: str | None = None) -> dict:
    item = {"evidence_id": evidence_id, "origin": origin, "kind": kind, "reference": reference, "note": note}
    if revision:
        item["revision"] = revision
    if retrieved:
        item["retrieved"] = retrieved
    return item


def _legacy_mapping(value: Any, label: str) -> dict:
    """The legacy object at *label*, or an empty one when it is absent."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ContractError(f"legacy {label} must be a JSON object, not {type(value).__name__}")
    return value


def _legacy_line(region: dict, key: str, index: int) -> int:
    value = region[key]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ContractError(
            f"legacy region {index}: {key} must be an integer line number of at least 1, not {value!r}")
    return value


def _legacy_locations(legacy: dict) -> list[dict]:
    """Legacy regions as candidate locations, refusing a shape this cannot read faithfully.

    A malformed region is refused rather than guessed at or silently dropped: a region with
    one line bound, a non-integer bound, or no path would otherwise become a location that
    claims less, or something other, than the legacy record said.
    """
    regions = legacy.get("regions", [])
    if not isinstance(regions, list):
        raise ContractError(f"legacy regions must be a list of region objects, not {type(regions).__name__}")
    locations = []
    for index, region in enumerate(regions):
        if not isinstance(region, dict):
            raise ContractError(f"legacy region {index} must be a JSON object, not {type(region).__name__}")
        path = region.get("path")
        if not isinstance(path, str) or not path:
            raise ContractError(f"legacy region {index} must name its path as a non-empty string")
        location = {"path": path, "role": "other",
                    "note": f"legacy region {region.get('id')} label={region.get('label')} capability={region.get('capability')}"}
        bounds = [key for key in ("startLine", "endLine") if key in region]
        if len(bounds) == 1:
            raise ContractError(
                f"legacy region {index}: startLine and endLine must be supplied together; got only {bounds[0]}")
        if bounds:
            location.update({"start_line": _legacy_line(region, "startLine", index),
                             "end_line": _legacy_line(region, "endLine", index)})
        locations.append(location)
    return locations


def draft_case_from_legacy(legacy: dict, *, case_id: str, snapshot_id: str, legacy_path: str,
                           workload: str, component_role: str, represents: str) -> dict:
    """Migrate a legacy v1 case as draft evidence. Regions become candidate locations, not labels.

    The legacy record is read, not trusted: a shape this cannot read faithfully is refused with
    a :class:`ContractError` instead of producing a case that misstates it.
    """
    real = _legacy_mapping(legacy.get("realWorld"), "realWorld")
    aliases = [value for value in (real.get("cve"), real.get("ghsa")) if value]
    items = [evidence("legacy-record", origin="legacy_case_record", kind="other", reference=legacy_path,
                      note=f"Legacy case {legacy.get('id')} ({legacy.get('caseType')}); prior draft regions, not v2-reviewed labels.")]
    if real.get("fixCommit"):
        # Only an advisory in the record makes this a public advisory plus maintainer fix. A fix
        # commit alone is a fix without an advisory, which is the ordinary shape of an internal one.
        advised = bool(real.get("ghsa") or real.get("cve"))
        items.append(evidence("fix-commit",
                              origin="public_advisory_and_maintainer_fix" if advised else "fix_without_advisory",
                              kind="fix_commit", reference=f"{real.get('repo')}@{real['fixCommit']}",
                              note="Fix commit named by the legacy record."
                                   + ("" if advised else " The record names no advisory, so no public disclosure is claimed.")))
    if real.get("ghsa"):
        items.append(evidence("ghsa", origin="public_advisory_and_maintainer_fix", kind="ghsa_advisory",
                              reference=f"https://github.com/advisories/{real['ghsa']}", note=""))
    if real.get("cve"):
        items.append(evidence("cve", origin="public_advisory_and_maintainer_fix", kind="cve_record",
                              reference=f"https://www.cve.org/CVERecord?id={real['cve']}", note=""))
    locations = _legacy_locations(legacy)
    disclosure = _legacy_mapping(real.get("disclosure"), "realWorld.disclosure")
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
    """Count the newline-separated lines of *path*, reading its bytes and nothing else."""
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def exported_file_paths(source_dir: Path) -> set[str]:
    """Every regular file under *source_dir*, as exact POSIX-relative paths.

    Declared paths are compared against this listing rather than probed on the filesystem, so
    a path whose case differs from the file on disk fails on a case-insensitive filesystem
    exactly as it does on a case-sensitive one. Symbolic links and ``.git`` contents are left
    out, which is what an export holds anyway.
    """
    listing: set[str] = set()
    for directory, dirnames, filenames in os.walk(source_dir):
        dirnames[:] = [name for name in dirnames if name != ".git"]
        base = Path(directory)
        for name in filenames:
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            listing.add(path.relative_to(source_dir).as_posix())
    return listing


def referenced_snapshots(case: dict) -> list[str]:
    """Every snapshot a case needs checked: its target's snapshot, then each control's."""
    ordered = [case["target"]["snapshot_id"]] + [control["snapshot_id"] for control in case["controls"]]
    unique: list[str] = []
    for snapshot_id in ordered:
        if snapshot_id not in unique:
            unique.append(snapshot_id)
    return unique


def _label_projection(case: dict) -> dict:
    """The label content of *case*: what a reviewer of its target and controls passed judgment on.

    Only the fields that say what is being alleged are projected. The case identifier, its
    evidence records, its disposition, its notes, and the recorded reviews and checks are left
    out: those are provenance and process around the labels, and changing one of them does not
    change what a reviewer read. Controls are projected in ``control_id`` order, which the
    contract keeps unique pack-wide, so reordering the list alone is not a content change while
    adding, removing, renaming, or editing a control is.
    """
    target = case["target"]
    return {
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


def label_digest(case: dict) -> str:
    """The digest of one case's labels: its target and every control, canonically serialized.

    A recorded approval carries this digest, so an approval is bound to the content it covered
    rather than to the case it sits on. Adding, removing, or editing a control changes it, as
    does editing the target's mechanism, description, affected input, accepted locations,
    assumptions, or matching rules, so none of those can ride on an earlier review.

    The snapshot each label names is projected too: moving a target or a control onto a
    different snapshot changes what was reviewed exactly as editing its text does.
    """
    return canonical_sha256(_label_projection(case))


def latest_approving_review(case: dict) -> dict | None:
    """The last recorded review of *case* that approved it, by list order, or ``None``.

    List order is the only ordering used; recorded timestamps are text and are not parsed here.
    """
    latest = None
    for review in case["validation"]["reviews"]:
        if review["decision"] == "approve":
            latest = review
    return latest


def approval_is_current(case: dict) -> bool:
    """True when the latest approving review covers the labels as they now stand.

    False when the labels have changed since that review, when no review approved the case, and
    when the latest approving review records no digest at all. A pack written before approvals
    carried a digest therefore degrades to unplanned rather than silently claiming coverage: a
    review that never named the content it read cannot be shown to cover this content. Nothing
    is rewritten or withdrawn here; this reads what the pack records.
    """
    review = latest_approving_review(case)
    if review is None or not review.get("labels_sha256"):
        return False
    return review["labels_sha256"] == label_digest(case)


def _approval_gap(case: dict) -> str:
    """Why the latest approving review does not cover the labels as they stand.

    Said separately from :func:`approval_is_current` because the two gaps are different facts: a
    review recorded before approvals carried a digest never said what it covered, while a review
    that carries one covered content these labels no longer match.
    """
    review = latest_approving_review(case)
    if review is None:
        return "no recorded review approved this case"
    if not review.get("labels_sha256"):
        return ("the recorded review does not say which label content it covered, so nothing binds "
                "it to these labels")
    return "the labels changed after the review, which covers different label content"


def _recorded_check_state(case: dict, snapshot_id: str) -> str | None:
    """One case's recorded check state for *snapshot_id*: ``pass``, ``fail``, or ``None``."""
    return recorded_check_state(case["validation"]["checks"], snapshot_id)


def _unchecked_snapshots(case: dict) -> list[str]:
    """Referenced snapshots without a recorded passing check set, in reference order."""
    return [snapshot for snapshot in referenced_snapshots(case)
            if _recorded_check_state(case, snapshot) != "pass"]


def mechanical_checks(pack: dict, snapshot_id: str, source_dir: Path, tree_hash: str,
                      *, clock: Callable[[], datetime] | None = None) -> list[dict]:
    """Run L1 checks against one exported tree for every case that references *snapshot_id*.

    Results are recorded per snapshot: this replaces only the check set carrying *snapshot_id*
    and leaves every other snapshot's results in place, so checking two snapshots of one case
    in either order ends in the same state. A case becomes ``mechanically_checked`` (L1) only
    once every snapshot it references has a recorded passing check set.

    A referenced snapshot that failed, or that has no recorded check set at all, demotes a
    ``mechanically_checked`` case to ``draft``. For a ``human_approved`` case the same situation
    records ``validation.checks_failed`` and leaves the review state and level untouched, because
    code never withdraws a human review; :func:`build_plan` then keeps that case out of the plan
    with a note. The flag is cleared only when every referenced snapshot passes again.

    These checks establish artifacts, paths, and ranges. Declared paths are compared against an
    exact listing of the exported tree, and file bytes are read only to count lines: nothing here
    parses source, establishes a root cause, or approves anything, so no check raises a case past
    L1. A snapshot whose pack record already carries a different tree hash is not rewritten: every
    case on it records a failing ``snapshot_hash_recorded`` check instead, and both
    :func:`build_plan` and the runner still refuse that input.

    The results are applied to a validated copy, so a check set the contract would refuse leaves
    *pack* exactly as it was. The caller's pack reference stays valid; references taken to cases,
    snapshots, or validation blocks beforehand point at the superseded copy and must be re-read.
    """
    if not isinstance(tree_hash, str) or not _TREE_HASH.match(tree_hash):
        raise ContractError(f"tree_hash must be a sha256:<64 hex digits> digest, not {tree_hash!r}")
    snapshot_by_id(pack, snapshot_id)
    now = _now(clock)
    present = exported_file_paths(source_dir)

    def mutate(candidate: dict) -> list[dict]:
        snapshot = snapshot_by_id(candidate, snapshot_id)
        declared = snapshot.get("tree_hash")
        hash_agrees = not declared or declared == tree_hash
        if hash_agrees:
            snapshot["tree_hash"] = tree_hash
        outcomes = []
        for case in cases_for_snapshot(candidate, snapshot_id):
            checks = []

            def check(name: str, passed: bool, detail: str) -> None:
                checks.append({"check": name, "result": "pass" if passed else "fail", "at": now,
                               "detail": detail, "snapshot_id": snapshot_id})

            locations = [(case["target"]["target_id"], loc) for loc in case["target"]["accepted_locations"]
                         if case["target"]["snapshot_id"] == snapshot_id]
            locations += [(control["control_id"], loc) for control in case["controls"]
                          if control["snapshot_id"] == snapshot_id for loc in control["locations"]]
            missing = [loc["path"] for _, loc in locations if loc["path"] not in present]
            check("locations_exist_in_snapshot", not missing and bool(locations),
                  "missing: " + ", ".join(missing) if missing else ("no locations declared" if not locations else f"{len(locations)} locations found"))
            bad_ranges = []
            for owner, loc in locations:
                if "start_line" in loc and loc["path"] in present:
                    if loc["end_line"] > _count_lines(source_dir / loc["path"]):
                        bad_ranges.append(f"{owner}:{loc['path']}:{loc['end_line']}")
            check("line_ranges_within_files", not bad_ranges, ", ".join(bad_ranges) or "all ranges within file length")
            aliases = case["canonical_target"]["aliases"]
            problems = [problem for problem in (alias_problem(alias) for alias in aliases) if problem]
            check("aliases_well_formed", not problems,
                  "; ".join(problems) if problems else (", ".join(aliases) or "no aliases"))
            check("represents_statement", bool(_REPRESENTS.match(case["represents"])), "template: This case tests ... under ..., and adds ...")
            check("evidence_recorded", bool(case["evidence"]), f"{len(case['evidence'])} evidence records")
            check("snapshot_hash_recorded", hash_agrees,
                  tree_hash if hash_agrees else f"pack records {declared}; this export is {tree_hash}")
            validation = case["validation"]
            validation["checks"] = [c for c in validation["checks"]
                                    if c.get("snapshot_id") != snapshot_id] + checks
            passed = all(c["result"] == "pass" for c in checks)
            every_snapshot_passed = not _unchecked_snapshots(case)
            if validation["review_state"] == "human_approved":
                # A snapshot that failed and one that was never checked are both missing evidence
                # for this label, so both raise the flag; only code, never a reviewer, is overruled.
                if every_snapshot_passed:
                    validation.pop("checks_failed", None)
                else:
                    validation["checks_failed"] = True
            elif every_snapshot_passed:
                validation["review_state"] = "mechanically_checked"
                validation["level"] = "L1"
            elif validation["review_state"] == "mechanically_checked":
                validation["review_state"] = "draft"
                validation["level"] = None
            outcomes.append({"case_id": case["case_id"], "passed": passed, "checks": checks,
                             "review_state": validation["review_state"], "level": validation["level"]})
        return outcomes

    return _apply_validated(pack, mutate)


def approve_case(pack: dict, case_id: str, *, reviewer: str, role: str, level: str, note: str,
                 clock: Callable[[], datetime] | None = None) -> dict:
    """Record one explicit human review of a case label.

    The review carries :func:`label_digest` of the target and controls as they stand at approval
    time, so it says which label content it covers. A later edit to those labels leaves the
    review recorded and covering the old content, and :func:`build_plan` then leaves the case
    out; approving again is what covers the new content.

    The reviewer name comes from the caller and is stored verbatim; a name holding no character
    beyond spaces, zero-width marks, or control characters is refused, because an unnamed
    approval is not an approval. This does not authenticate the reviewer, check their
    independence, or verify that anything was read, and it records a claim of review rather than
    establishing the label. A refused approval leaves the pack unchanged.
    """
    if level not in LEVELS:
        raise ContractError(f"level must be one of {LEVELS}")
    _require_stated(reviewer, "approval requires an explicit reviewer name; the tool never supplies one")
    case = case_by_id(pack, case_id)
    if case["validation"]["review_state"] == "draft":
        raise ContractError(f"case {case_id} has not passed mechanical checks; run corpus validate first")
    if level in REVIEWED_LEVELS and role != "independent_reviewer":
        raise ContractError("L3/L4 labels require an independent_reviewer decision")
    if level in REVIEWED_LEVELS and case["disposition"]["value"] != "validate":
        raise ContractError("L3/L4 require disposition validate")
    review = {"reviewer": reviewer, "role": role, "decision": "approve", "level": level, "at": _now(clock),
              "note": note, "labels_sha256": label_digest(case)}

    def mutate(candidate: dict) -> dict:
        validation = case_by_id(candidate, case_id)["validation"]
        validation["reviews"].append(dict(review))
        validation["review_state"] = "human_approved"
        validation["level"] = level
        return validation["reviews"][-1]

    return _apply_validated(pack, mutate)


def set_disposition(pack: dict, case_id: str, value: str, reason: str) -> dict:
    """Record a screening-disposition change and the stated reason for it.

    A disposition is a screening decision about whether a candidate is worth validating. It is
    not a label, an approval, or an admission, and changing it neither re-runs a check nor
    alters a recorded review. The previous value stays visible in the case notes.

    A change the contract refuses leaves the pack unchanged, which includes moving an approved
    L3 or L4 case off ``validate``: that label was approved on the screening decision behind it,
    so withdrawing the decision under a standing approval needs a review decision, not this call.
    """
    if value not in DISPOSITIONS:
        raise ContractError(f"disposition must be one of {DISPOSITIONS}")
    _require_stated(reason, "a disposition change requires a non-blank reason")
    previous = case_by_id(pack, case_id)["disposition"]["value"]

    def mutate(candidate: dict) -> dict:
        case = case_by_id(candidate, case_id)
        case["disposition"] = {"value": value, "reason": reason}
        case["notes"].append(f"disposition changed from {previous} to {value}: {reason}")
        return case["disposition"]

    return _apply_validated(pack, mutate)


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

    The name and reason come from the caller and are stored verbatim; a value holding no
    character beyond spaces, zero-width marks, or control characters is refused. This records
    who decided, not that the decision is correct, and it does not change a case's review state
    or level. A refused decision leaves the pack unchanged.
    """
    case_by_id(pack, case_id)
    _require_stated(by, "an admission decision requires an explicit name; the tool never supplies one")
    _require_stated(reason, "an admission decision requires a non-blank reason")
    admission = {"case_id": case_id, "decision": decision, "by": by, "at": _now(clock), "reason": reason}

    def mutate(candidate: dict) -> dict:
        candidate["admissions"].append(dict(admission))
        return candidate["admissions"][-1]

    return _apply_validated(pack, mutate)


def plan_scope(cases: list[dict]) -> str:
    states = {case["validation"]["review_state"] for case in cases}
    levels = {case["validation"]["level"] for case in cases}
    if cases and states == {"human_approved"} and levels <= {"L3", "L4"}:
        return "reviewed"
    return "draft"


def build_plan(pack: dict, snapshot_id: str, tree_hash: str, *, mode: str = "full") -> tuple[dict, list[str]]:
    """Targets and controls for one materialized input, with every exclusion stated in the notes.

    A case is planned only when its disposition is not ``exclude``, no check set failed after
    approval, its latest admission decision is not ``rejected``, the pack records a passing
    mechanical check set for every snapshot it references, and an approved case's labels are
    still the ones its latest approving review covered. The check state is read per snapshot, so
    a case approved on one snapshot is still left out while another snapshot it references is
    unchecked or failing. Planned items keep their real validation level; the plan's scope, not a
    rewritten level, says whether the labels are reviewed drafts.

    An approved case whose labels no longer match its review (see :func:`approval_is_current`)
    contributes no level to any plan: it is left out with a note rather than planned at the level
    the review recorded, so a control added or a target edited after approval cannot reach a
    reviewed-scope plan on that review. The review itself stands, untouched and still recorded.

    A snapshot that carries recorded mechanical checks but no tree hash is refused outright: the
    checks describe some exported tree, and without the hash nothing says it was this one.

    This builds a plan. It does not approve, admit, re-check, or correct anything, and a case
    left out here is unplanned for this input, not judged wrong.
    """
    snapshot = snapshot_by_id(pack, snapshot_id)
    if snapshot.get("tree_hash") and snapshot["tree_hash"] != tree_hash:
        raise ContractError(f"snapshot {snapshot_id} tree hash does not match the materialized input")
    if not snapshot.get("tree_hash") and any(check.get("snapshot_id") == snapshot_id
                                             for case in pack["cases"]
                                             for check in case["validation"]["checks"]):
        raise ContractError(
            f"snapshot {snapshot_id} records mechanical checks but carries no tree hash, so nothing "
            "binds those checks to this export; re-run the checks against the materialized input")
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
        elif _unchecked_snapshots(case):
            notes.append(f"{case_id}: no recorded passing mechanical check set for snapshot(s) "
                         f"{', '.join(_unchecked_snapshots(case))}; not planned")
        elif validation["review_state"] == "human_approved" and not approval_is_current(case):
            notes.append(f"{case_id}: excluded because {_approval_gap(case)}; the recorded review "
                         "stands as recorded, and a review of the labels as they stand is needed")
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
