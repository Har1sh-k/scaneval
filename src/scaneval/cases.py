"""Case packs: draft records, mechanical checks, explicit human approval, and plan generation.

A pack is evaluator-side data. Nothing in it is ever copied into a scanner workspace.
Code can create drafts and run mechanical (L1) checks; only a recorded human review can
raise a case beyond that, and the plan builder degrades to the lowest state present.

Mechanical checks are recorded per snapshot, so a case spanning a vulnerable and a fixed
snapshot reaches L1 only once every snapshot it references has passed. Nothing here reads
source semantics, establishes a root cause, infers a reviewer, or withdraws a human review of
its own accord: a check that fails after approval is recorded and keeps the case out of a plan,
and the recorded review state and level stay exactly as the reviewer left them. A withdrawal is
a decision a named reviewer records, through :func:`record_review`, and the state that follows
it is the state the reviewer's decision leaves the case in.

An approval covers the label content it was recorded against, not the case id: each approving
review carries :func:`label_digest` of what the case claims to be, its target, its controls, the
evidence it rests on, and the identity of every snapshot those name, as they stood. A label edited,
a control added, an advisory deleted, or a snapshot repinned or re-declared afterwards is outside
every recorded review, because an approval covers the exact bytes that were reviewed. Such a case
keeps its reviews, because a review is a historical fact, and :func:`build_plan` leaves it out
until a review covers the labels as they stand. The latest recorded review is the operative one: a
later review that rejects the case or reopens the question withdraws it from planning, moves the
recorded state back to what the mechanical checks earn, and leaves the whole recorded history in
place. That rule is written once, in :func:`scaneval.contracts.operative_review_gap`, and the load,
the planning gate, and :func:`record_review` all read it.

One review covers the labels as they stand, and that one review answers every question about the
approval. Whether the case is planned, how high it is planned, and whether a pack claiming that
level loads at all are all read from it, so a case cannot be raised to a reviewed level by editing
a label, collecting a lesser approval of the edit, and resting the level on an independent review
of what the case used to say.

No decision is made from ``validation.level``. Nothing plans a case, claims a level, or clears a
gate on its word: it is a cached copy of the covering review's level, and
:func:`scaneval.contracts.recorded_level_gap` refuses a pack whose copy disagrees with that review
in either direction, so the two records of one fact cannot drift apart. A case recorded at L2 under
an L4 curator approval is neither loaded nor planned, where before it loaded and planned at L4 with
no independent reviewer behind it. Every decision reads
:func:`scaneval.contracts.effective_level`, which is the covering review's own level.

Every field a planning decision reads is inside one of two records, and which one is decided by
subtraction rather than by a list someone has to remember to extend. The labels are inside
:func:`label_digest`, which the covering review carries. Everything else a case, a snapshot, or the
pack itself records is inside ``anchor_sha256``, because
:func:`scaneval.contracts.pack_anchor_projection` is the whole record minus a stated allowlist and
minus the labels a recorded review already holds by digest. A case's ``notes`` are the only field of
a case in that allowlist; the pack's own identity and status are in it because every plan binds them
by hashing the whole file it was built from. So the screening disposition a plan reads, the whole
validation block with its check sets and its ``checks_failed`` flag, and the ``review_budgets``
every recall-at-k number is computed at are anchored, and a field added to the contract later is
anchored the day it is added rather than the day someone notices. A test holds every field of a
case, a snapshot, and the pack to that split.

Each subtraction is made for a record that exists rather than for one that might be recorded later.
A draft or mechanically checked case has no review, so no digest holds what it alleges, and its
target, controls, evidence, and represents statement are anchored along with everything else; they
leave the anchor when an approval records :func:`label_digest` over them, which is what lets an
edited label be re-approved without an anchor rebuilt by hand first, and that is the only reason
they ever leave it. Every snapshot's identity is anchored in the same way until every case in the
pack binds its own labels, because until then some case reads those bytes with no digest speaking
for them.

Inside those two records the chains do the rest, so that deleting one entry is visible rather than
quiet. The recorded reviews are a chain rather than an array: each carries ``chain_sha256`` over
its own fields and the entry before it, and ``validation.reviews_sha256`` records where the chain
ends. The admissions are a chain in the same way. A mechanical check set is one record in
``validation.check_sets``, carrying what the set decided, the export it read, and a digest over
both together with its own checks, so a check set is never reconstituted by gathering whichever
checks still carry a snapshot id, and deleting the record itself is an anchored record that is no
longer there rather than a snapshot nobody checked.
:func:`scaneval.contracts.review_chain_gap` and :func:`scaneval.contracts.pack_anchor_gap` say what
all of that does and does not prove. In short, anyone who can edit the pack can recompute an
anchor; what an anchor removes is the deletion that looks like the file it came from.

One function is the gate for reading a planning decision out of a pack: :func:`require_loadable`
is the pack load, and :func:`build_plan` calls it, so a pack the load refuses is never planned
from. A write asks the narrower deletion question, :func:`require_anchored`, because a write
re-validates what it produces and repairing an inconsistent pack is what the write paths are for.

A review is recorded through one write path, :func:`record_review`, whether it approves a label or
withdraws that approval, so an approval and its withdrawal share every gate and every record. A
rejection moves the case back to the state its mechanical checks earn, and the case is planned
under neither: the latest recorded review is the operative one.

Admission is an explicit decision, never an absence. Only a recorded ``admitted`` decision admits a
case to a reviewed-scope plan; a case nobody has decided on, or one recorded ``deferred``, is
planned as the draft evidence it is.

Case identity stays outside the digest, because an identifier says where a label came from rather
than what it alleges. Admissions are bound to content instead: each records the ``target_id`` it
decided, which the digest covers, planning routes decisions by it, and a pack whose admission no
longer names the target of the case it names is refused. Renaming two cases around a standing
rejection therefore moves neither.

An approval also covers the tree the checks behind it ran against. Which export a check set read
is recorded twice in a case, in its ``validation.check_sets`` record and in the ``detail`` of its
passing ``snapshot_hash_recorded`` check, and a third time in the snapshot's declared ``tree_hash``.
Loading a pack requires the three to agree, and :func:`build_plan` leaves out a case whose records
disagree or whose checks ran against a tree the snapshot no longer declares, so editing any two of
the three contradicts the third instead of pointing a standing approval at a different export.
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
    admission_chain_digest,
    canonical_json,
    canonical_sha256,
    check_set_digest,
    claimed_level_gap,
    covering_review,
    effective_level,
    label_digest,
    latest_review,
    load_document,
    operative_review_gap,
    pack_anchor_digest,
    pack_anchor_gap,
    recorded_check_state,
    recorded_level_gap,
    review_chain_digest,
    review_chain_gap,
    validate_document,
)


PACK_KIND = "case-pack"
LEVELS = ("L1", "L2", "L3", "L4")
DISPOSITIONS = ("validate", "needs_evidence", "extended_regression", "exclude")
REVIEWED_LEVELS = ("L3", "L4")
# The three decisions a recorded review can carry: one approval and the two withdrawals.
REVIEW_DECISIONS = ("approve", "reject", "unresolved")
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


def require_loadable(pack: dict, purpose: str) -> None:
    """Refuse *pack* unless it is a pack this build would load, naming *purpose* in the refusal.

    One function and one question for every path that reads a planning decision out of a pack:
    :func:`load_pack` asks it through :func:`scaneval.contracts.load_document`, and
    :func:`build_plan` asks it here, because it can be handed a pack that never went through a
    load. The question is the whole contract, not the anchor alone. Planning used to re-check only
    the anchor, so a pack the load refuses, a case recorded at a level its covering review does not
    earn for instance, still produced a plan out of whatever else the pack held.

    A write asks the narrower question instead (:func:`require_anchored`), and deliberately: a
    write re-validates what it produces, so it cannot leave an inconsistent pack behind, and
    refusing to write to one would take away the only way to repair it, which is to re-run the
    checks or record the decision that resolves it.

    The refusal carries the load's own message, so a caller is told which record is wrong rather
    than that something is.
    """
    try:
        validate_document(PACK_KIND, pack)
    except ContractError as exc:
        raise ContractError(f"this pack does not load as a case pack, so {purpose}: {exc}") from exc


def require_anchored(pack: dict, purpose: str) -> None:
    """Refuse *pack* unless its anchored records verify, naming *purpose* in the refusal.

    This is the deletion question, and it is what a write asks before touching anything: a pack
    whose anchor does not verify has had a record removed, and writing to it would replace the
    evidence of that with a fresh anchor over what remains. It is the narrower half of
    :func:`require_loadable`, which asks it too.

    A pack too malformed to hold records at all is refused here as well, in the same shape of
    message, because :func:`scaneval.contracts.pack_anchor_gap` establishes the shape before it
    reads one (see :func:`scaneval.contracts.pack_shape_gap`). Before touching anything is meant
    literally: every write path in this module reads the pack inside its own ``mutate``, so a
    caller handing in something that is not a pack is told so rather than being given a
    ``KeyError`` or a ``TypeError`` from whichever line happened to look first.
    """
    gap = pack_anchor_gap(pack)
    if gap:
        raise ContractError(f"this pack's anchored records do not verify, so {purpose}: {gap}")


def _apply_validated(pack: dict, mutate: Callable[[dict], Any]) -> Any:
    """Apply *mutate* to a deep copy of *pack*, re-anchor and validate it, then swap it in.

    A refused change leaves *pack* exactly as it was, because the mutation never touched it.
    On success the validated copy replaces the pack's contents in place, so the caller's
    pack reference stays valid while references taken to nested objects beforehand point at
    the superseded copy. Validation checks the document against the contract; it does not
    check that the change was a good idea.

    Every write goes through here, so this is where ``anchor_sha256`` is kept true: the pack the
    caller hands in must already anchor to the records it holds (see :func:`require_anchored`), and
    the copy is re-anchored after the change. Refusing first is the point of the order. A pack
    whose anchor does not verify has had a record deleted, and writing to it would replace the
    evidence of that with a fresh anchor over what remains, so a hand-edited pack cannot be
    laundered by calling any function in this module on it.

    The question asked here is the deletion one and not the whole contract, which is what
    :func:`build_plan` and the load ask. A write re-validates what it produces, so it cannot leave
    an inconsistent pack behind; what it can do is repair one, by re-running the checks a
    hand-added control left uncovered or by recording the decision that resolves a withdrawal, and
    a write path that refused an inconsistent pack would leave no way to do either.

    This is also the one place a write establishes that it was handed a pack at all, which is why
    every write in this module does its looking up, its duplicate checking, and its state checking
    inside *mutate*, against the candidate. A lookup done before the call would reach into the
    caller's object before this gate had said there was anything there, and the caller would get a
    ``KeyError`` naming a field rather than a refusal naming the pack. The checks themselves are
    unchanged and so are their messages; only where they run moved.
    """
    require_anchored(pack, "nothing may be written to it")
    candidate = copy.deepcopy(pack)
    result = mutate(candidate)
    candidate["anchor_sha256"] = pack_anchor_digest(candidate)
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
    pack["anchor_sha256"] = pack_anchor_digest(pack)
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
    """Record one pinned snapshot. A snapshot the contract refuses leaves the pack unchanged.

    The duplicate check reads the candidate rather than *pack*, so nothing reads a record out of
    the pack before :func:`_apply_validated` has established that there is a pack to read.
    """
    record = copy.deepcopy({"tree_hash": None, "git_tree": None, "role": "vulnerable", **snapshot})

    def mutate(candidate: dict) -> dict:
        if any(existing["snapshot_id"] == record["snapshot_id"]
               for existing in candidate["snapshots"]):
            raise ContractError(f"snapshot {record['snapshot_id']} already exists")
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
    """Record one case. A case the contract refuses leaves the pack unchanged.

    The duplicate check reads the candidate, for the reason :func:`add_snapshot` gives.
    """
    record = copy.deepcopy(case)

    def mutate(candidate: dict) -> dict:
        if any(existing["case_id"] == record["case_id"] for existing in candidate["cases"]):
            raise ContractError(f"case {record['case_id']} already exists")
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


# ``label_digest``, ``covering_review``, ``effective_level``, ``latest_review``, and
# ``operative_review_gap`` live in :mod:`scaneval.contracts`, imported above and re-exported here:
# the planning gates and write paths in this module and the pack-load gate there must ask the same
# question of the same content, and that module cannot import this one.


def latest_approving_review(case: dict) -> dict | None:
    """The last recorded review of *case* that approved it, by list order, or ``None``.

    This reads the review history, so it still finds an approval a later review reopened or
    rejected. Whether the case is approved as it now stands is :func:`approval_is_current`, which
    reads :func:`latest_review` instead. List order is the only ordering used; recorded timestamps
    are text and are not parsed here.
    """
    latest = None
    for review in case["validation"]["reviews"]:
        if review["decision"] == "approve":
            latest = review
    return latest


def approval_is_current(pack: dict, case: dict) -> bool:
    """True when the one review covering these labels approves them and establishes their level.

    :func:`scaneval.contracts.covering_review` names that review: the latest recorded review, when
    it approved the case and carries the digest of the labels as they stand. False when a later
    review rejected the case or left the question unresolved, because the latest review is the
    operative one and a reopened question is not an approval. False when the labels have changed
    since that approval, which includes repinning a snapshot they name, when no review approved the
    case, and when the approving review records no digest at all. A pack written before approvals
    carried a digest therefore degrades to unplanned rather than silently claiming coverage: a
    review that never named the content it read cannot be shown to cover this content.

    False, too, when that one review does not establish ``validation.level``: a review recorded at a
    level its role does not support earns nothing, and a cached level that disagrees with the review
    in either direction is a second record of a fact the review alone holds (see
    :func:`scaneval.contracts.recorded_level_gap`). The same question is asked at pack load by
    :func:`scaneval.contracts._validate_case_pack`, so a plan and a load cannot disagree. Nothing is
    rewritten or withdrawn here; this reads what the pack records.
    """
    return covering_review(pack, case) is not None and recorded_level_gap(pack, case) is None


def _approval_gap(pack: dict, case: dict) -> str:
    """Why the recorded reviews do not approve the labels as they stand at the level recorded.

    Said separately from :func:`approval_is_current` because the gaps are different facts: a later
    review may have reopened or rejected the case, a review recorded before approvals carried a
    digest never said what it covered, a review that carries one covered content these labels no
    longer match, and a review that covers this content may still be recorded at a level its role
    does not support or beside a cached level that says something else. The recorded history may
    also not verify at all, which is asked first: a history whose entries no longer account for
    each other says nothing about the decisions inside it.

    Whether the latest review withdrew the approval is not decided here: it is
    :func:`scaneval.contracts.operative_review_gap`, the one rule the load and
    :func:`record_review` read, and its own words are the reason this returns.
    """
    validation = case["validation"]
    chain = review_chain_gap(validation["reviews"], validation.get("reviews_sha256"))
    if chain:
        return f"the recorded review history does not verify: {chain}"
    withdrawn = operative_review_gap(case)
    if withdrawn:
        return withdrawn
    review = latest_review(case)
    if not review.get("labels_sha256"):
        return ("the recorded review does not say which label content it covered, so nothing binds "
                "it to these labels")
    covering = covering_review(pack, case)
    if covering is None:
        return "the labels changed after the review, which covers different label content"
    return (claimed_level_gap(covering, case["validation"]["level"])
            or "the recorded approval does not stand for these labels")


def _planning_review_gap(pack: dict, case: dict) -> str | None:
    """Why the recorded reviews keep *case* out of a plan, or ``None`` when they do not.

    Every question a plan asks of a review history is asked here. A case with no recorded review is
    planned on its mechanical state, which is what an L1 case is. Once a review is recorded the
    latest one is the operative record, whatever review state the case carries: it must be an
    approval, so a rejection or an unresolved reopening keeps the case out even after the
    withdrawal moved the case back to ``mechanically_checked``, and withdrawing an approval is
    therefore not a way of handing a case back to its mechanical L1. An approved case must also be
    covered by that review at the level it records (see :func:`approval_is_current`). The reason is
    :func:`_approval_gap`, so the plan states which of those it was.
    """
    review = latest_review(case)
    if review is not None and review["decision"] != "approve":
        return _approval_gap(pack, case)
    if case["validation"]["review_state"] == "human_approved" and not approval_is_current(pack, case):
        return _approval_gap(pack, case)
    return None


def _recorded_check_state(case: dict, snapshot_id: str) -> str | None:
    """One case's recorded check state for *snapshot_id*: ``pass``, ``fail``, or ``None``.

    Read from the one anchored check set record, never gathered from the checks that carry the
    snapshot id (see :func:`scaneval.contracts.recorded_check_state`), so a set edited into
    disagreeing with itself reads as no set at all rather than as a passing one.
    """
    return recorded_check_state(case["validation"], snapshot_id)


def _unchecked_snapshots(case: dict) -> list[str]:
    """Referenced snapshots without a recorded passing check set, in reference order."""
    return [snapshot for snapshot in referenced_snapshots(case)
            if _recorded_check_state(case, snapshot) != "pass"]


def _tree_records(case: dict, snapshot_id: str) -> set[str]:
    """Every digest *case* records as the export its check set for *snapshot_id* read.

    Two records speak. The ``validation.check_sets`` record for the snapshot names the export the
    set ran against, and the ``detail`` of that set's passing ``snapshot_hash_recorded`` check
    names it again. A failing set writes a sentence in that detail instead, so it names only the
    one record, which costs nothing because a failing set keeps the case out of a plan anyway. A
    value that is not a sha256 digest is not a record of an export and is left out. The set is
    returned rather than one preferred record, so a caller can see the two records disagreeing
    instead of reading whichever was edited last.
    """
    recorded = [(case["validation"].get("check_sets", {}).get(snapshot_id) or {}).get("tree_hash")]
    recorded += [check["detail"] for check in case["validation"]["checks"]
                 if check.get("snapshot_id") == snapshot_id and check["result"] == "pass"
                 and check["check"] == "snapshot_hash_recorded"]
    return {value for value in recorded if isinstance(value, str) and _TREE_HASH.match(value)}


def checked_tree_hash(case: dict, snapshot_id: str) -> str | None:
    """The export *case*'s recorded check set for *snapshot_id* ran against, or ``None``.

    ``None`` when no check set is recorded for the snapshot at all, since the record that would
    name the export is the record that is missing. ``None`` too when the records that do speak
    disagree: two records of one fact that contradict each other establish neither, so no export is
    returned and :func:`build_plan` leaves the case out. Editing one of them to match a newly
    declared ``tree_hash`` therefore contradicts the other rather than retargeting the check set;
    loading such a pack is refused outright.

    A recorded set always names an export, because the record requires one, so there is no case
    where a set ran against a tree nothing names. Re-running the checks is what writes the record.
    """
    records = _tree_records(case, snapshot_id)
    return records.pop() if len(records) == 1 else None


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

    An approval covers the export that was reviewed, and that binding lives in one place: the
    snapshot's identity is inside :func:`label_digest`, so re-running these checks against a
    snapshot repinned to a different commit or export leaves every recorded approval covering
    content the case no longer states, and :func:`build_plan` drops the case with the same note an
    edited label earns. Nothing here withdraws the review, and no second flag records the same
    fact: the digest already says the approval covers other bytes.

    A check set is recorded as one record under that snapshot's id in ``validation.check_sets``:
    what the set decided, the digest of the export it ran against, and a ``checks_sha256`` covering
    both together with every check of the set. Every gate reads that record rather than gathering
    whichever checks still carry the snapshot id, so deleting a failing check, or dropping its
    ``snapshot_id`` so it leaves the set, leaves the record hashing to something that is no longer
    there instead of quietly turning a failed set into a passing one.

    The export digest is also written into the ``detail`` of the set's passing
    ``snapshot_hash_recorded`` check. The two are records of one fact and must agree, and a pack
    load requires the snapshot's declared hash to agree with them as well, so a declared hash
    edited afterwards contradicts both rather than retargeting the set: :func:`build_plan` then
    leaves every case on that snapshot out, and a pack that edits one of the records to match is
    refused at load. The digest is recorded whether the set passed or failed: it says which export
    was read, not whether the case survived it. A failing set is the one case where it may differ
    from the declared hash, because the export it read is exactly what the set rejected.

    The results are applied to a validated copy, so a check set the contract would refuse leaves
    *pack* exactly as it was. The caller's pack reference stays valid; references taken to cases,
    snapshots, or validation blocks beforehand point at the superseded copy and must be re-read.
    """
    if not isinstance(tree_hash, str) or not _TREE_HASH.match(tree_hash):
        raise ContractError(f"tree_hash must be a sha256:<64 hex digits> digest, not {tree_hash!r}")
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
            # The set is recorded once, as one record: what it decided, the export it ran against,
            # and the digest of both together with its own checks. Everything downstream reads the
            # record, so no later deletion inside the array can restate what this set decided.
            recorded_set = {"result": "pass" if passed else "fail", "tree_hash": tree_hash}
            recorded_set["checks_sha256"] = check_set_digest(snapshot_id, recorded_set, checks)
            validation.setdefault("check_sets", {})[snapshot_id] = recorded_set
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


def record_review(pack: dict, case_id: str, *, reviewer: str, role: str, decision: str,
                  note: str, level: str | None = None,
                  clock: Callable[[], datetime] | None = None) -> dict:
    """Record one explicit human review decision on a case label: an approval or a withdrawal.

    ``approve`` is the decision :func:`approve_case` records, and it requires the *level* it
    claims. ``reject`` and ``unresolved`` are the two withdrawals the contract names: a rejection
    says the label is wrong, and ``unresolved`` says the reviewer reopened the question without
    settling it. Both are recorded as reviews, because the history of what reviewers decided is the
    record every gate reads, and the latest entry is the operative one.

    The review carries :func:`label_digest` of the target, the controls, and the identity of the
    snapshots they name as they stand at the time, so it says which content it covers, down to the
    export. A later edit to those labels, or a repin of one of those snapshots, leaves the review
    recorded and covering the old content, and :func:`build_plan` then leaves the case out;
    approving again is what covers the new content.

    The review is also chained to the one before it by ``chain_sha256``, and becomes the history's
    recorded end in ``validation.reviews_sha256`` (see
    :func:`scaneval.contracts.review_chain_gap`), which the pack anchor in turn records, so the
    history it joins cannot later lose an entry unnoticed, from the middle, off the end, or by
    being wiped whole.

    An approval sets ``validation.level`` to its own level, and that field is a cached copy of it:
    the contract refuses a pack where the two disagree, and every decision reads the review.

    A withdrawal also moves the recorded state, because a case cannot be ``human_approved`` under a
    review that withdrew the approval. Changed deliberately this round: a rejection and an
    ``unresolved`` reopening now do the same thing, because they are the same thing to every gate
    that reads them. Either one moves the case back to the state its mechanical checks earn:
    ``mechanically_checked`` at L1 when every snapshot it references still records a passing check
    set, and ``draft`` with no level otherwise. The case is not planned either way while that
    review is the latest one (see :func:`build_plan`), so withdrawing an approval is not a way of
    handing a case back to its mechanical L1. The rule is written once, in
    :func:`scaneval.contracts.operative_review_gap`, and the pack load refuses exactly the state
    this refuses to leave behind: a reopened case recorded as ``human_approved`` at a level no
    standing review earns. A withdrawal carries the level it withdraws, which is the level the case
    records, or L1 when it records none; only an approving review's level is read by any gate.

    The reviewer name comes from the caller and is stored verbatim; a name holding no character
    beyond spaces, zero-width marks, or control characters is refused, because an unnamed decision
    is not a decision. This does not authenticate the reviewer, check their independence, or verify
    that anything was read, and it records a claim of review rather than establishing the label. A
    refused decision leaves the pack unchanged.

    The decision and the reviewer name are checked here, because they are arguments; everything
    that reads the case is checked inside the write, against the candidate, so that a pack whose
    anchored records do not verify is refused before a state rule reads a record out of it (see
    :func:`_apply_validated`).
    """
    if decision not in REVIEW_DECISIONS:
        raise ContractError(f"decision must be one of {REVIEW_DECISIONS}")
    approving = decision == "approve"
    _require_stated(reviewer, f"{'approval' if approving else 'a recorded withdrawal'} requires an "
                              "explicit reviewer name; the tool never supplies one")

    def mutate(candidate: dict) -> dict:
        recorded_case = case_by_id(candidate, case_id)
        validation = recorded_case["validation"]
        claimed = level
        if approving:
            if claimed not in LEVELS:
                raise ContractError(f"level must be one of {LEVELS}")
            if validation["review_state"] == "draft":
                raise ContractError(f"case {case_id} has not passed mechanical checks; run corpus validate first")
            if claimed in REVIEWED_LEVELS and role != "independent_reviewer":
                raise ContractError("L3/L4 labels require an independent_reviewer decision")
            if claimed in REVIEWED_LEVELS and recorded_case["disposition"]["value"] != "validate":
                raise ContractError("L3/L4 require disposition validate")
        else:
            claimed = claimed or validation["level"] or "L1"
            if claimed not in LEVELS:
                raise ContractError(f"level must be one of {LEVELS}")
        recorded = {"reviewer": reviewer, "role": role, "decision": decision, "level": claimed,
                    "at": _now(clock), "note": note,
                    "labels_sha256": label_digest(candidate, recorded_case)}
        previous = validation["reviews"][-1]["chain_sha256"] if validation["reviews"] else None
        recorded["chain_sha256"] = review_chain_digest(previous, recorded)
        validation["reviews"].append(recorded)
        validation["reviews_sha256"] = recorded["chain_sha256"]
        if approving:
            validation["review_state"] = "human_approved"
            validation["level"] = claimed
        elif validation["review_state"] == "human_approved":
            # A withdrawal is a withdrawal: under the operative-review rule the contract reads
            # (:func:`scaneval.contracts.operative_review_gap`), a case whose latest review
            # rejected it or reopened the question is not human_approved, so it falls back to what
            # its own mechanical checks earn. Nothing here re-runs a check; this reads what is
            # recorded, and the recorded reviews themselves are untouched.
            checked = not _unchecked_snapshots(recorded_case)
            validation["review_state"] = "mechanically_checked" if checked else "draft"
            validation["level"] = "L1" if checked else None
            validation.pop("checks_failed", None)
        return validation["reviews"][-1]

    return _apply_validated(pack, mutate)


def approve_case(pack: dict, case_id: str, *, reviewer: str, role: str, level: str, note: str,
                 clock: Callable[[], datetime] | None = None) -> dict:
    """Record one explicit human approval of a case label at *level*.

    This is :func:`record_review` with an approving decision, and the two share every gate and
    every record they write, so an approval and the withdrawal of one cannot drift apart. A
    refused approval leaves the pack unchanged.
    """
    return record_review(pack, case_id, reviewer=reviewer, role=role, decision="approve",
                         level=level, note=note, clock=clock)


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

    def mutate(candidate: dict) -> dict:
        case = case_by_id(candidate, case_id)
        previous = case["disposition"]["value"]
        case["disposition"] = {"value": value, "reason": reason}
        case["notes"].append(f"disposition changed from {previous} to {value}: {reason}")
        return case["disposition"]

    return _apply_validated(pack, mutate)


def latest_admission(pack: dict, case_id: str) -> dict | None:
    """The last admission decision covering what *case_id* names, by list order, or ``None``.

    Decisions are routed by the ``target_id`` they were recorded against rather than by the case
    name. The target identifier is inside :func:`label_digest`, so an admission is bound to content
    a review covers: renaming a case carries its decisions with it, and renaming two cases around a
    standing decision moves neither onto the other's content. A pack whose admission no longer
    names the target of the case it names is refused at load.

    Order in the list is the only ordering used; timestamps are recorded text and are not parsed
    or sorted here.
    """
    target_id = case_by_id(pack, case_id)["target"]["target_id"]
    latest = None
    for admission in pack["admissions"]:
        if admission.get("target_id") == target_id:
            latest = admission
    return latest


def admit_case(pack: dict, case_id: str, *, decision: str, by: str, reason: str,
               clock: Callable[[], datetime] | None = None) -> dict:
    """Append one admission decision made by a named person, with a stated reason.

    The decision records the case it was made on and the ``target_id`` that case carries, which is
    the content :func:`label_digest` covers, so the decision stays with the content rather than
    with the name. Case identity is deliberately outside the digest, because an identifier says
    where a label came from and not what it alleges, and this is the binding that keeps that choice
    from routing a decision by name alone.

    The decision is chained to the one before it by ``chain_sha256``, and the pack anchor records
    where the chain now ends, so the admissions are a history rather than an append-only array that
    anything can be lifted out of: deleting the rejection that kept a case out of a plan leaves the
    decisions after it chaining to something that is no longer there, and deleting the last one
    leaves the pack anchoring to a decision it no longer holds.

    The name and reason come from the caller and are stored verbatim; a value holding no
    character beyond spaces, zero-width marks, or control characters is refused. This records
    who decided, not that the decision is correct, and it does not change a case's review state
    or level. A refused decision leaves the pack unchanged.
    """
    _require_stated(by, "an admission decision requires an explicit name; the tool never supplies one")
    _require_stated(reason, "an admission decision requires a non-blank reason")

    def mutate(candidate: dict) -> dict:
        case = case_by_id(candidate, case_id)
        recorded = {"case_id": case_id, "target_id": case["target"]["target_id"],
                    "decision": decision, "by": by, "at": _now(clock), "reason": reason}
        previous = candidate["admissions"][-1]["chain_sha256"] if candidate["admissions"] else None
        recorded["chain_sha256"] = admission_chain_digest(previous, recorded)
        candidate["admissions"].append(recorded)
        return candidate["admissions"][-1]

    return _apply_validated(pack, mutate)


def planned_level(pack: dict, case: dict) -> str | None:
    """The validation level a plan may claim for *case*, or ``None`` when it may claim none.

    This is :func:`scaneval.contracts.effective_level` and nothing else, so the plan, the pack load,
    and the gates in between read one source. For an approved case that source is the one review
    covering the labels as they stand, not the separately stored ``validation.level``: the review
    records what a person read, while the stored level is a cached copy an edit can change. The two
    must agree or the case has no level at all, so the plan can never carry a level above or below
    the review that earned it. For a case no review covers there is no level to claim. For an
    unapproved case the mechanical state's own L1 is the level, and no review is involved.
    """
    return effective_level(pack, case)


def plan_scope(planned: list[tuple[dict, str, dict | None]]) -> str:
    """``reviewed`` only when every planned case is approved, reviewed-level, and admitted.

    Takes each planned case with the level it is planned at and the admission decision covering its
    content, because neither is on the case record: the level comes from the review covering the
    labels (see :func:`planned_level`) and the decision from the admission history (see
    :func:`latest_admission`).

    Only an explicit ``admitted`` decision admits. A case the pack records no decision about has
    not been admitted, it has not been decided, and a case recorded ``deferred`` was decided the
    other way for now; both are planned as draft evidence, which is what they are. Reading the
    absence of a decision as an admission would have made ``deferred`` mean nothing at all and made
    a reviewed-scope plan reachable without the admission step the pack says it needs.
    """
    states = {case["validation"]["review_state"] for case, _, _ in planned}
    levels = {level for _, level, _ in planned}
    admitted = all(admission is not None and admission["decision"] == "admitted"
                   for _, _, admission in planned)
    if planned and admitted and states == {"human_approved"} and levels <= {"L3", "L4"}:
        return "reviewed"
    return "draft"


def build_plan(pack: dict, snapshot_id: str, tree_hash: str, *, mode: str = "full") -> tuple[dict, list[str]]:
    """Targets and controls for one materialized input, with every exclusion stated in the notes.

    A case is planned only when its disposition is not ``exclude``, no check set failed after
    approval, the latest admission decision covering its content is not ``rejected``, the pack
    records a passing mechanical check set for every snapshot it references, and the recorded
    reviews do not stand in the way (see :func:`_planning_review_gap`): the latest review must not
    be a rejection or an unresolved reopening, and an approved case's labels must still be the ones
    that review covered. The check state is read per snapshot from the one anchored check set
    record for it, so a case approved on one snapshot is still left out while another snapshot it
    references is unchecked or failing. Admissions are matched by the ``target_id`` they were
    recorded against (see :func:`latest_admission`), so renaming cases does not move a rejection
    onto content nobody rejected. Planned items keep their real validation level; the plan's scope,
    not a rewritten level, says whether the labels are reviewed drafts.

    Scope is the narrower claim of the two. A plan is ``reviewed`` only when every case in it is
    approved, planned at a reviewed level, and admitted by an explicit ``admitted`` decision (see
    :func:`plan_scope`); a case with no recorded decision, or one recorded ``deferred``, is planned
    as the draft evidence it is.

    A pack this build would not load is refused outright rather than planned around, and that is
    one function, :func:`require_loadable`, which is the load itself. A pack whose anchored records
    do not verify has had a record deleted, and the record that would say what is missing is the
    record that was deleted: a case dropped whole, a review history wiped, a check set lifted out,
    or an admission removed leaves nothing to exclude and nothing to note. A pack that is
    inconsistent in any other way the contract names is refused here for the same reason it is
    refused there. Planning used to ask only about the anchor, so a pack the load refuses still
    produced a plan out of whatever else it held.

    That level is read from the review covering the labels rather than from ``validation.level``
    (see :func:`planned_level`), so the review deciding whether the case is planned is the same
    one deciding how high it is planned. An approved case whose labels no longer match its review,
    whose covering review is recorded at a level its role does not support, or whose cached
    ``validation.level`` says anything other than that review's level (see
    :func:`approval_is_current`), contributes no level to any plan: it is left out with a note
    rather than planned at the level some earlier review recorded, so a control added or a target
    edited after approval cannot reach a reviewed-scope plan on that review, and neither can a
    lesser approval of the edit with an older independent review behind it, nor a case whose
    recorded level was lowered to slip a curator approval past the role rule. A later review that
    rejected the case or reopened the question does the same, because the latest recorded review is
    the operative one. The reviews themselves stand, untouched and still recorded.

    The labels a review covers include the identity of every snapshot they name, so a snapshot
    repinned to another commit or another export leaves the case unplanned exactly as an edited
    target does: an approval covers the bytes that were reviewed.

    An approved case whose recorded review history does not verify as a chain is left out too, and
    for the same reason it is refused at load: a history whose entries no longer account for each
    other names no operative review, so nothing establishes that the approval still stands. That is
    asked inside :func:`scaneval.contracts.covering_review`, which every gate here goes through, so
    planning a pack that never went through a load cannot walk past it.

    A snapshot that carries recorded mechanical checks but no tree hash is refused outright: the
    checks describe some exported tree, and without the hash nothing says it was this one.

    A pack whose records of which tree a check set ran against disagree is refused rather than
    planned around, and that refusal is the load's, not a second copy of it here. The three records
    are the ``check_sets`` entry, the detail of that set's passing ``snapshot_hash_recorded``
    check, and the ``tree_hash`` the snapshot declares, and :func:`require_loadable` requires them
    to agree. Editing a declared tree hash therefore cannot point a standing check set, or an
    approval resting on one, at a different export: the edit contradicts the records the checks
    wrote, and no plan is built from a pack that contradicts itself. This used to be a note here as
    well, which is two records of one rule, and the one that stayed is the one every path passes
    through. :func:`checked_tree_hash` still reads what a case records, for a caller that wants to
    see it.

    This builds a plan. It does not approve, admit, re-check, or correct anything, and a case
    left out here is unplanned for this input, not judged wrong.
    """
    require_loadable(pack, "no plan can be built from it")
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
    included: list[tuple[dict, str, dict | None]] = []
    for case in cases_for_snapshot(pack, snapshot_id):
        case_id = case["case_id"]
        validation = case["validation"]
        admission = latest_admission(pack, case_id)
        review_gap = _planning_review_gap(pack, case)
        if case["disposition"]["value"] == "exclude":
            notes.append(f"{case_id}: excluded by disposition ({case['disposition']['reason']})")
        elif validation.get("checks_failed"):
            notes.append(f"{case_id}: excluded because a mechanical check set failed after approval; "
                         "the recorded review stands and needs a correction decision")
        elif admission is not None and admission["decision"] == "rejected":
            notes.append(f"{case_id}: excluded by the latest admission decision "
                         f"(rejected by {admission['by']}: {admission['reason']})")
        elif validation["review_state"] == "draft":
            notes.append(f"{case_id}: draft without passed mechanical checks; not planned")
        elif _unchecked_snapshots(case):
            notes.append(f"{case_id}: no recorded passing mechanical check set for snapshot(s) "
                         f"{', '.join(_unchecked_snapshots(case))}; not planned")
        elif review_gap is not None:
            notes.append(f"{case_id}: excluded because {review_gap}; the recorded "
                         "review stands as recorded, and a review of the labels as they stand is "
                         "needed")
        elif planned_level(pack, case) is None:
            notes.append(f"{case_id}: excluded because nothing in the pack establishes a validation "
                         f"level for it ({recorded_level_gap(pack, case) or 'no level is recorded'})"
                         "; not planned")
        else:
            included.append((case, planned_level(pack, case), admission))
    scope = plan_scope(included)
    targets, controls = [], []
    for case, level, _ in included:
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
                       "case_ids": [case["case_id"] for case, _, _ in included]},
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
