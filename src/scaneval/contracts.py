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


# Every contract kind and the protocol versions this build reads, oldest first. A 2.0 document is
# validated against its 2.0 schema exactly as it always was: 2.1 adds optional fields to some kinds
# and adds new kinds, and a writer uses 2.1 only for a document that carries one of those fields, so
# a record written before 2.1 existed is never reread under rules it was not written against.
SCHEMA_VERSIONS: dict[str, tuple[str, ...]] = {
    "scan-request": ("2.0",),
    "scan-result": ("2.0", "2.1"),
    "evaluation-plan": ("2.0", "2.1"),
    "review-decisions": ("2.0",),
    "execution-record": ("2.0", "2.1"),
    "case-pack": ("2.0", "2.1"),
    "review-record": ("2.0",),
    "run-config": ("2.0", "2.1"),
    "run-manifest": ("2.0", "2.1"),
    # Kinds first published at 2.1, one per feature: the frozen evaluation schedule a run writes
    # before it prepares any input, and the reviewed map a metadata-blinded input is transformed
    # with. 2.1 is each one's only version, so its schema keeps the plain file name.
    "evaluation-schedule": ("2.1",),
    "blinding-map": ("2.1",),
    # SARIF import (profile sarif-import-1): the record scaneval.sarif writes beside the scan
    # result it produced from a saved log. A kind first published at 2.1 keeps the plain file name.
    "import-record": ("2.1",),
    # Corpus aggregation and paired comparison (scaneval.aggregate): the policy an aggregation runs
    # under, and the two reports it writes. First published at 2.1, so plain file names.
    "aggregation-policy": ("2.1",),
    "aggregate-report": ("2.1",),
    "comparison-report": ("2.1",),
    # Precision sampling and review (scaneval.precision, docs/PRECISION.md): the seeded sample of
    # delivered claims with the frame it was drawn from, the chained human reviews of that sample,
    # and the estimate computed from both. Each is first published at 2.1.
    "precision-sample": ("2.1",),
    "precision-reviews": ("2.1",),
    "precision-estimate": ("2.1",),
    # Promotion gate decisions (scaneval.gate, docs/GATE.md): the policy a gate is evaluated under,
    # frozen before any result is read, and the decision made over a comparison. Each is first
    # published at 2.1, so plain file names.
    "gate-policy": ("2.1",),
    "gate-decision": ("2.1",),
}
CONTRACT_KINDS = frozenset(SCHEMA_VERSIONS)
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


def schema_file(kind: str, version: str) -> str:
    """The packaged schema file for *kind* at *version*.

    The first version a kind was published at keeps the plain ``<kind>.schema.json`` name, which is
    every 2.0 schema this package has ever shipped, and a later version of the same kind is
    ``<kind>-<version>.schema.json`` beside it, so publishing 2.1 never edits a 2.0 file.
    """
    if kind not in SCHEMA_VERSIONS:
        expected = ", ".join(sorted(CONTRACT_KINDS))
        raise ContractError(f"unknown contract kind {kind!r}; expected one of: {expected}")
    versions = SCHEMA_VERSIONS[kind]
    if version not in versions:
        raise ContractError(
            f"{kind} schema_version {version!r} is not one this build reads; supported: "
            f"{', '.join(versions)}")
    return f"{kind}.schema.json" if version == versions[0] else f"{kind}-{version}.schema.json"


def _schema(kind: str, version: str | None = None) -> dict[str, Any]:
    """The packaged schema for *kind* at *version*, the oldest supported version when omitted."""
    if kind not in SCHEMA_VERSIONS:
        expected = ", ".join(sorted(CONTRACT_KINDS))
        raise ContractError(f"unknown contract kind {kind!r}; expected one of: {expected}")
    name = schema_file(kind, SCHEMA_VERSIONS[kind][0] if version is None else version)
    resource = files("scaneval").joinpath("schemas", name)
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


def check_set_digest(snapshot_id: str, record: dict[str, Any], checks: list[dict[str, Any]]) -> str:
    """The digest a check set record carries: its own fields together with the checks it holds.

    The record's own ``checks_sha256`` is left out, exactly as a review's ``chain_sha256`` is left
    out of its chain value, so the digest covers the result, the export, and every check of the
    set in recorded order.
    """
    entry = {key: value for key, value in record.items() if key != "checks_sha256"}
    return canonical_sha256({"snapshot_id": snapshot_id, "set": entry, "checks": checks})


def recorded_checks(validation: dict[str, Any], snapshot_id: str) -> list[dict[str, Any]]:
    """The checks *validation* records against *snapshot_id*, in recorded order."""
    return [check for check in validation["checks"] if check.get("snapshot_id") == snapshot_id]


def check_set_gap(validation: dict[str, Any], snapshot_id: str) -> str | None:
    """Why the recorded check set for *snapshot_id* does not verify, or ``None``.

    ``None``, too, when no set is recorded for it: a set that is not there is absent, not broken,
    and the case is unchecked for that snapshot. Nothing inside a case can tell an absent set from
    a deleted one, because the deletion takes the record that would have complained, which is why
    the whole validation block is inside the pack anchor (see :func:`case_anchor_projection`): a
    set deleted after the pack was anchored is a pack that no longer anchors to its own records.

    A check set is one record in ``validation.check_sets``, not the checks that happen to carry a
    snapshot id. The record states the result and the export the set ran against, and its
    ``checks_sha256`` covers those fields together with every check of the set, so deleting a
    failing check, dropping its ``snapshot_id`` so it leaves the set, reordering two of them, or
    editing one leaves the record hashing to something that is no longer there. The recorded result
    must also be the result its own checks state, so the two records of that one fact cannot
    disagree.

    What this proves is the same narrow thing the review chain proves: anyone who can edit the pack
    can delete a check and rebuild the record around it. What it removes is the quiet deletion, the
    edit that looks like the file it came from and turns a failed set into a passing one.
    """
    record = (validation.get("check_sets") or {}).get(snapshot_id)
    checks = recorded_checks(validation, snapshot_id)
    if record is None:
        if checks:
            return (f"validation.checks records {len(checks)} check(s) against snapshot "
                    f"{snapshot_id}, but validation.check_sets records no check set for it; a check "
                    "set is one record, not the checks that still carry its snapshot")
        return None
    if not checks:
        return (f"validation.check_sets records a check set for snapshot {snapshot_id}, but no "
                "recorded check carries that snapshot; the checks it names were deleted")
    recorded = record.get("checks_sha256")
    expected = check_set_digest(snapshot_id, record, checks)
    if recorded != expected:
        return (f"validation.check_sets[{snapshot_id}] records {recorded}, and the set as it now "
                f"stands hashes to {expected}; a check was deleted, unattributed, reordered, or "
                "edited")
    stated = "pass" if all(check["result"] == "pass" for check in checks) else "fail"
    if record["result"] != stated:
        return (f"validation.check_sets[{snapshot_id}] records {record['result']}, but the checks it "
                f"holds are {stated}")
    return None


def recorded_check_state(validation: dict[str, Any], snapshot_id: str) -> str | None:
    """``pass`` or ``fail`` for one snapshot's recorded check set; ``None`` when none is recorded.

    The state is read from the one anchored record in ``validation.check_sets``, never
    reconstituted by gathering whichever checks still carry the snapshot id. ``None`` when that
    record is absent and ``None`` when it does not verify (see :func:`check_set_gap`), so a set
    edited into disagreeing with itself neither promotes nor demotes a case: it leaves the case
    unchecked for that snapshot, and a pack recording one is refused at load. Nothing is re-run
    here; this reads what the pack already records.
    """
    if check_set_gap(validation, snapshot_id) is not None:
        return None
    record = (validation.get("check_sets") or {}).get(snapshot_id)
    return None if record is None else record["result"]


def chain_digest(previous: str | None, entry: dict[str, Any], kind: str) -> str:
    """The chain value of *entry*, a record of *kind*, recorded after the one valued *previous*.

    The digest covers every field of the entry except the chain value itself, the kind of record it
    is, and the chain value of the one before it, so each entry commits to the whole history that
    precedes it and a record of one kind cannot be replayed as a record of another. ``None`` as
    *previous* starts a history.
    """
    fields = {key: value for key, value in entry.items() if key != "chain_sha256"}
    return canonical_sha256({"previous": previous, "kind": kind, "entry": fields})


def review_chain_digest(previous: str | None, review: dict[str, Any]) -> str:
    """The chain value of *review* recorded after the review whose chain value is *previous*."""
    return chain_digest(previous, review, "review")


def admission_chain_digest(previous: str | None, admission: dict[str, Any]) -> str:
    """The chain value of *admission* recorded after the one whose chain value is *previous*."""
    return chain_digest(previous, admission, "admission")


def chain_link_gap(entries: list[dict[str, Any]], *, kind: str, label: str) -> tuple[str | None, str | None]:
    """Why the entries of a chain do not account for each other, and where the chain now ends.

    Every entry carries ``chain_sha256``, which covers its own fields and the chain value of the
    entry before it, so the history is a chain rather than an array of entries that stand alone.
    Editing any field, reordering two entries, or deleting one from the middle leaves every later
    entry chaining to something that is no longer there. An entry recorded without a chain value is
    refused too: an optional chain would be no chain at all, because dropping the field is the same
    deletion the chain exists to make visible.

    The head is returned rather than compared here, because what a chain cannot see on its own is
    the deletion off the end: the entries that remain still chain to each other. Every caller
    therefore holds the head somewhere the deletion would have to be rewritten deliberately.
    """
    previous: str | None = None
    for index, entry in enumerate(entries):
        recorded = entry.get("chain_sha256")
        if not recorded:
            return (f"{label}[{index}] records no chain_sha256, so nothing binds it to the "
                    f"{kind}s recorded before it"), previous
        expected = chain_digest(previous, entry, kind)
        if recorded != expected:
            return (f"{label}[{index}] does not chain to the {kind} before it: it records "
                    f"{recorded}, and the history as it now stands hashes to {expected}; a {kind} "
                    "was deleted, reordered, or edited"), previous
        previous = recorded
    return None, previous


def review_chain_gap(reviews: list[dict[str, Any]], head: str | None) -> str | None:
    """Why a recorded review history does not verify, or ``None`` when it does.

    The entries are a chain (see :func:`chain_link_gap`), and the history also records where it
    ends: ``validation.reviews_sha256`` is the chain value of the last review, present exactly when
    there is a review, and a history that ends anywhere else is refused. That is what catches the
    truncation, because dropping the trailing review that withdrew an approval would otherwise
    restore the approval under it.

    An empty history with no recorded end verifies here, and on its own that would be the same
    deletion one step further: wiping a history whole leaves nothing for a head to disagree with.
    What makes an empty history distinguishable from a deleted one is not in this function and
    cannot be, because nothing inside a case survives the wipe. The pack anchor records, for each
    case, where its review history ends, so a wiped history is an anchored ``null`` where the
    anchor says a digest belongs (see :func:`pack_anchor_gap`). A history that was always empty is
    what the anchor says it is.

    What all of this proves is narrow, and it is worth being exact about. Anyone who can edit the
    pack can also recompute the chain and rewrite the head and the anchor, so this is not a
    signature: it says nothing about who recorded a review, whether they read anything, or whether
    an entry that verifies was ever written by the person it names. What it removes is the quiet
    deletion. A history cannot lose a review through an edit that looks like the file it came from.
    """
    gap, previous = chain_link_gap(reviews, kind="review", label="validation.reviews")
    if gap:
        return gap
    if previous is None:
        if head is not None:
            return (f"validation.reviews_sha256 records {head}, but this case records no review at "
                    "all; the history it names was deleted whole")
        return None
    if head is None:
        return ("validation.reviews_sha256 is missing, so nothing says where the recorded review "
                "history ends and a review deleted from the end of it would leave no trace")
    if head != previous:
        return (f"validation.reviews_sha256 records {head}, but the recorded history ends at "
                f"{previous}; a review was deleted from the end of it")
    return None


# Where every field of a case lives. Every field is inside a digest, and the anchor is the default:
# the label projection holds the fields a recorded review binds by :func:`label_digest`, the anchor
# projection holds every field of the case that projection does not currently hold, and this
# allowlist holds the fields no planning decision reads at all. The projections are defined as the
# whole record minus a list rather than as a list of fields to cover, so a field added to the schema
# is anchored by default instead of escaping quietly, and
# ``tests/test_v2_contracts.py::test_every_declared_case_field_is_anchored_or_allowlisted_with_a_reason``
# fails when a new field is in neither record nor named in the allowlist that test states.
#
# "Currently" is the part that used to be missing. A label field leaves the anchor only while a
# recorded digest holds it (:func:`labels_are_bound`); a case nobody has reviewed, and one whose
# latest review predates approvals carrying a digest, has no digest holding anything, so the anchor
# holds its labels too. See :func:`case_anchor_projection`.
CASE_LABEL_FIELDS = frozenset({
    "represents", "workload", "component_role", "model_involvement", "coverage_signature",
    "canonical_target", "target", "controls", "evidence",
})
CASE_UNREAD_FIELDS = frozenset({"notes"})

# The same split for a snapshot, held by
# ``tests/test_v2_contracts.py::test_every_declared_snapshot_field_is_anchored_or_allowlisted_with_a_reason``.
# Its identity is the part a label points at, so it travels inside :func:`label_digest` for the
# snapshots a case names; everything else about it is anchored, and so is the identity itself for
# every snapshot :func:`snapshots_bound_by_labels` does not find a recorded digest holding. Nothing
# about a snapshot is unread.
SNAPSHOT_IDENTITY_FIELDS = frozenset({"commit", "tree_hash", "languages"})
SNAPSHOT_UNREAD_FIELDS: frozenset[str] = frozenset()

# And for the pack itself. ``anchor_sha256`` cannot cover itself, ``description`` and ``notes`` are
# free text, and the pack's identity and status are bound after the fact rather than here: every
# plan records ``pack_sha256`` over the whole file it was built from, so a pack renamed,
# renumbered, or released is a different pack to every plan, manifest, and report that cites one.
# What that after-the-fact binding does not cover is the edit made before anything cites the pack.
# Nothing inside the file records what its version or status was, so renumbering a version, or
# flipping ``status`` from ``draft`` to ``released`` on a pack no plan has yet been built from,
# leaves no trace and no second record to disagree with. That is affordable only because no
# decision in this build reads either field: :mod:`scaneval.cases` gates on neither,
# :func:`scaneval.cases.build_plan` copies the version into a plan's provenance beside the digest of
# the whole file, and the release rule in :func:`scaneval.cli._pack_for_change` is a workflow gate
# on the file in hand rather than a claim about a label. Anchoring them would also put that
# workflow, which reopens a released pack by rewriting ``version`` and ``status``, behind a digest
# a person would have to recompute by hand.
PACK_UNANCHORED_FIELDS = frozenset({
    "anchor_sha256", "description", "notes",
    "schema_version", "namespace", "pack_id", "version", "status",
})
# The three pack-level arrays the anchor projects in their own way rather than verbatim.
_PACK_RECORD_FIELDS = frozenset({"snapshots", "cases", "admissions"})


def case_label_projection(case: dict[str, Any]) -> dict[str, Any]:
    """The fields of *case* that say what is alleged: what a reviewer of it passed judgment on.

    Every field named in :data:`CASE_LABEL_FIELDS` is projected whole, subfields included, so a
    field added inside a target, a control, or an evidence record is covered the day it is added
    rather than the day someone remembers to list it here. Three orderings are normalized because
    none of them carries content: controls are read in ``control_id`` order, each control's evidence
    ids are sorted, evidence records are read in ``evidence_id`` order, and aliases are sorted. The
    contract keeps all four unique, so reordering one of those lists alone is not a content change
    while adding, removing, renaming, or editing an entry is.

    The evidence records are in here, not beside it: an L3 label is an allegation plus the evidence
    it rests on, so deleting the advisory a case cites, or rewriting what it says, is a change to
    what was reviewed and costs the approval exactly as an edited target does.

    What is left out is left out deliberately, and every one of those fields is anchored instead
    (see :func:`case_anchor_projection`): the case identifier and its disclosure dates say where a
    label came from, the disposition and the split say what is being done with it, and the
    validation block is the record of the reviews and checks themselves. Only ``notes`` is read by
    nothing at all.

    This says what a review covers when one is recorded. It does not say that these fields are
    outside the anchor: they leave the anchor only while a recorded review holds them by digest
    (:func:`labels_are_bound`), so the labels of a case nobody has reviewed are anchored like
    everything else.
    """
    projected = {key: value for key, value in case.items() if key in CASE_LABEL_FIELDS}
    if "canonical_target" in projected:
        canonical = projected["canonical_target"]
        projected["canonical_target"] = {**canonical, "aliases": sorted(canonical["aliases"])}
    if "controls" in projected:
        projected["controls"] = [
            {**control, "evidence_ids": sorted(control["evidence_ids"])}
            for control in sorted(projected["controls"], key=lambda item: item["control_id"])]
    if "evidence" in projected:
        projected["evidence"] = sorted(projected["evidence"],
                                       key=lambda item: item["evidence_id"])
    return projected


def labels_are_bound(case: dict[str, Any]) -> bool:
    """True when a recorded review already binds what *case* alleges to a digest.

    The operative review is the latest recorded one (:func:`operative_review_gap`), and it carries
    ``labels_sha256`` over the label content it read (:func:`label_digest`). While one is there the
    labels are held by a digest, so :func:`case_anchor_projection` leaves them out and an edited
    label can be re-approved without an anchor being rebuilt by hand first.

    False when the case records no review at all, and false when its latest review carries no
    digest, which is how a pack written before approvals were bound to content reads. Both mean no
    record anywhere holds these labels, so the anchor holds them instead. Whether the digest that is
    there covers the labels *as they now stand* is a different question, asked by
    :func:`covering_review`: an approval that lapsed because a label was edited is still a recorded
    digest of that label content, and the edit is exactly what it makes visible.

    Read tolerantly, because a write path anchors its candidate before validating it: a case this
    cannot read records no digest, so its labels are anchored, and the contract refuses the case a
    moment later.
    """
    if not isinstance(case, dict):
        return False
    validation = case.get("validation")
    reviews = validation.get("reviews") if isinstance(validation, dict) else None
    latest = reviews[-1] if isinstance(reviews, list) and reviews else None
    return isinstance(latest, dict) and bool(latest.get("labels_sha256"))


def case_anchor_projection(case: dict[str, Any]) -> dict[str, Any]:
    """Every field of *case* no other record holds: the whole record minus the allowlist, and minus
    the labels only while a recorded digest holds them.

    Everything that is not a label is always here, whether or not anyone has thought about it yet:
    the case identifier and the target id an admission is routed by, the disclosure dates, the
    screening disposition a plan reads, the split, and the whole validation block, which is the
    review history, its recorded end, every mechanical check, every check set record, and the
    ``checks_failed`` flag.

    That is the point of defining it by subtraction. A case's mechanical check record used to be
    deletable because an absent check set reads as an unchecked snapshot rather than as a deleted
    record, and a disposition could be edited to drop an approved, admitted case out of a plan.
    Both are in here now because everything is, and a field added later is in here the day it is
    added.

    The labels are the one conditional subtraction, and the condition is :func:`labels_are_bound`:
    a review carrying ``labels_sha256`` is a record of them, so binding them here as well would
    mean an edited label could not be re-approved without an anchor being rebuilt by hand. Changed
    deliberately this round: they used to be subtracted unconditionally, which left every case no
    review has bound, a draft or a mechanically checked one, with its target, its controls, its
    evidence, and what it claims to represent inside no record at all. Editing the target of a
    draft case was invisible to the anchor and to every digest, and the claim that every field is
    inside one of two records was false for exactly those cases.

    The labels are projected verbatim when they are here, not through
    :func:`case_label_projection`, because the anchor records what the file holds rather than what
    a reviewer read: reordering a list is a change to the recorded pack even where it is not a
    change to the allegation, and every other array the anchor covers is already read in the order
    it was recorded.
    """
    skipped = CASE_LABEL_FIELDS if labels_are_bound(case) else frozenset()
    return {key: value for key, value in case.items()
            if key not in skipped and key not in CASE_UNREAD_FIELDS}


def snapshot_identity_projection(snapshot: dict[str, Any]) -> dict[str, Any]:
    """The fields of *snapshot* that say which bytes a label points at and how they are read.

    The commit and the exported tree hash each name bytes. The declared languages are here because
    they decide which adapters are run against those bytes (see
    :func:`scaneval.runner.run_invocation`), so a snapshot re-declared as holding no Python is a
    different scan of the same export, and an approval that covered the one did not cover the
    other. Languages are sorted because the adapters read the list as a set, so its order carries
    no content.

    The repository is deliberately not here. A commit hash and a tree hash each name bytes, so a
    snapshot moved to a mirror or a fork that holds the same commit and exports the same tree is
    the content the reviewer read; where those bytes were fetched from is provenance, which the
    snapshot record keeps, which the anchor covers, and which no approval rests on.
    """
    projected = {key: value for key, value in snapshot.items()
                 if key in SNAPSHOT_IDENTITY_FIELDS}
    if "languages" in projected:
        projected["languages"] = sorted(projected["languages"])
    return projected


def snapshot_anchor_projection(snapshot: dict[str, Any], *,
                               identity_bound: bool = False) -> dict[str, Any]:
    """Every field of *snapshot* no other record holds: the whole record, minus its identity only
    when *identity_bound* says a recorded digest already holds the identity of this snapshot.

    The repository, the reference, the workload, the component role, the licence, and the role the
    snapshot plays are always anchored here. The identity is subtracted when it is held elsewhere,
    for the same reason a case's labels are: it travels inside :func:`label_digest`, so repinning a
    snapshot must cost the approvals recorded against those bytes rather than stop the pack loading
    and leave nothing able to re-approve it.

    The caller answers *identity_bound* for this one record, and for a pack the answer is
    :func:`snapshots_bound_by_labels`: a digest holds this snapshot's identity only when some case
    names the snapshot, so a digest of that case's labels carries it, and every case in the pack
    binds its own labels. The default here is false, so a caller that does not know anchors the
    identity too.

    Changed deliberately this round: the subtraction used to be unconditional, and then conditional
    on a pack-wide answer applied to every snapshot alike. Both left an identity no digest holds
    outside every record. A snapshot a draft or mechanically checked case reads is named by no
    digest, and so is a snapshot the pack declares that no case names at all, however thoroughly
    the rest of the pack is reviewed; repinning either to another commit, or re-declaring the
    languages it is scanned as, changed which bytes a plan is built against with no record anywhere
    disagreeing. Covering a field in two records costs a rebuilt anchor; leaving it out of both is
    the hole this parameter exists to close.
    """
    skipped = SNAPSHOT_IDENTITY_FIELDS if identity_bound else frozenset()
    return {key: value for key, value in snapshot.items()
            if key not in skipped and key not in SNAPSHOT_UNREAD_FIELDS}


def every_case_binds_its_labels(pack: dict[str, Any]) -> bool:
    """True when every case in *pack* holds its own labels by digest, and there is a case.

    This is one half of what lets a snapshot's identity leave the anchor, and it is the half asked
    of the pack rather than of each snapshot. A label digest is recorded per case, so a pack
    holding a single unreviewed case is a pack where some reader of some snapshot's bytes speaks
    through no digest at all, and no identity may leave. Asking it per snapshot instead, of the
    cases that name that snapshot, was written and then withdrawn: which snapshots a case names is
    itself label content, so that let pointing a control at another snapshot move a third record in
    and out of the anchor, and a label edit on an approved case would then have cost the anchor
    rebuild that the subtraction exists to avoid.

    The other half is the snapshot itself, and this function does not answer it:
    :func:`snapshots_bound_by_labels` also requires that some case names the snapshot, because a
    declared snapshot no case names is inside no label digest whatever every case binds. Coarse
    here means anchoring an identity some digest does hold, which costs a rebuild after a hand
    repin; neither half ever means leaving out one no digest holds.

    Every flip of this answer happens inside a write, which re-anchors: recording the first review
    on the last unreviewed case, or adding a case to a pack of reviewed ones. A hand edit that
    would flip it, deleting a review or adding a case, already leaves the review chain or the case
    roster anchoring to something that is no longer there.
    """
    cases = pack.get("cases")
    if not isinstance(cases, list) or not cases:
        return False
    return all(labels_are_bound(case) for case in cases)


def snapshots_bound_by_labels(pack: dict[str, Any]) -> frozenset[str]:
    """The snapshot ids whose identity a recorded label digest demonstrably holds.

    Two things must hold before an identity may leave the anchor, and this asks both. Every case in
    the pack must bind its own labels (:func:`every_case_binds_its_labels`), because one unreviewed
    case is a reader of bytes that no digest speaks for. And this particular snapshot must be named
    by some case, as a target's or a control's snapshot, because :func:`label_digest` carries the
    identity of the snapshots a case names and of no others.

    That second condition is the one this round added, and without it a pack of fully reviewed
    cases subtracted the commit, the tree hash, and the declared languages of a snapshot no case
    named, leaving those fields inside no record at all: the anchor had dropped them and no label
    digest could ever have held them. Such a snapshot is not idle.
    :func:`scaneval.cases.build_plan` is asked for a plan by snapshot id, and the runner reads the
    declared languages to decide which adapters see the bytes, so repinning one that no case names
    today is a silent change to what a later case, pointed at it by an ordinary review, will be
    planned and scanned against.

    Read tolerantly, like every other projection here, because a write anchors its candidate before
    the contract has validated it: a case whose target or controls cannot be read names no
    snapshot, which anchors more rather than less.
    """
    if not every_case_binds_its_labels(pack):
        return frozenset()
    named: set[str] = set()
    for case in pack["cases"]:
        if not isinstance(case, dict):
            continue
        target = case.get("target")
        records = [target] if isinstance(target, dict) else []
        controls = case.get("controls")
        if isinstance(controls, list):
            records += [control for control in controls if isinstance(control, dict)]
        for record in records:
            snapshot_id = record.get("snapshot_id")
            if isinstance(snapshot_id, str):
                named.add(snapshot_id)
    return frozenset(named)


def pack_anchor_projection(pack: dict[str, Any]) -> dict[str, Any]:
    """Every record in *pack* that a planning decision reads and that nothing else would anchor.

    This is the whole pack minus three subtractions, each of them named and each of them because
    the field is covered somewhere else or covered by nothing because it is read by nothing.

    Pack-level fields are projected verbatim, :data:`PACK_UNANCHORED_FIELDS` aside, so
    ``review_budgets`` is in here: it is the list of cut-offs every recall-at-k number is computed
    at, it is copied into each plan, and it was previously in neither the digest nor the anchor.

    The snapshots are projected by :func:`snapshot_anchor_projection` and the cases by
    :func:`case_anchor_projection`, so the roster of each is anchored together with every field of
    them that no digest holds. Both subtractions are made per record, for a digest that exists and
    that holds that record, rather than for one that might be recorded later: a case no review has
    bound is anchored with its labels, and a snapshot's identity is anchored unless
    :func:`snapshots_bound_by_labels` finds a label digest carrying it, which needs both that every
    case in the pack binds its own labels and that some case names this snapshot. Until both hold,
    something reads those bytes, or the next case pointed at them will, with no digest speaking for
    them. Deleting a case whole, its chained review history included, leaves every case that
    remains consistent, and :func:`scaneval.cases.plan_scope` reads the cases that are there:
    dropping the one draft case out of a pack of approved ones would otherwise turn a draft plan
    into a reviewed one. A review history wiped whole is an anchored ``null`` where a
    ``reviews_sha256`` belongs, which is how an empty history stays distinguishable from a deleted
    one, and a deleted check set is an anchored ``check_sets`` record that is no longer there.

    The admissions are projected as the chain value of the last recorded decision, or ``null`` when
    the pack records none. Each decision's own fields are covered by the chain, which binds it to
    the decision before it, so what is left for the anchor is the deletion off the end of the
    history, the one that would restore a case to a reviewed-scope plan by dropping the rejection
    that kept it out.
    """
    bound = snapshots_bound_by_labels(pack)
    projected = {key: value for key, value in pack.items()
                 if key not in PACK_UNANCHORED_FIELDS and key not in _PACK_RECORD_FIELDS}
    projected["snapshots"] = [
        snapshot_anchor_projection(snapshot,
                                   identity_bound=snapshot.get("snapshot_id") in bound)
        for snapshot in pack["snapshots"]]
    projected["cases"] = [case_anchor_projection(case) for case in pack["cases"]]
    projected["admissions_sha256"] = (pack["admissions"][-1].get("chain_sha256")
                                      if pack["admissions"] else None)
    return projected


def pack_anchor_digest(pack: dict[str, Any]) -> str:
    """The digest a pack's ``anchor_sha256`` carries for the records it now holds."""
    return canonical_sha256(pack_anchor_projection(pack))


def pack_shape_gap(pack: Any) -> str | None:
    """Why *pack* is not shaped like a case pack at all, or ``None`` when it is readable.

    It asks for the three arrays every projection walks, and that each entry of them is a JSON
    object. That is all: the field-by-field contract is :func:`validate_document`, and this says
    only that there is something here to read.

    It exists because :func:`pack_anchor_gap` is asked before anything has established the shape.
    A write asks it of whatever the caller handed in (:func:`scaneval.cases.require_anchored` is the
    first thing every write path does), so without this the first gate on a hand-built or truncated
    pack raised ``KeyError: 'admissions'``, which is a crash rather than a refusal naming what is
    wrong. Every deeper read in the projections is tolerant for the same reason, and tolerant is
    safe there because an unreadable record anchors more rather than less.
    """
    if not isinstance(pack, dict):
        return f"a case pack is a JSON object, not {type(pack).__name__}"
    for name in ("snapshots", "cases", "admissions"):
        value = pack.get(name)
        if not isinstance(value, list):
            held = "nothing" if name not in pack else f"a {type(value).__name__}"
            return (f"this pack records {held} as its {name}, so nothing says which records it "
                    "anchors")
        if any(not isinstance(entry, dict) for entry in value):
            return f"every entry of {name} must be a JSON object"
    return None


def pack_anchor_gap(pack: dict[str, Any]) -> str | None:
    """Why a pack's anchored records do not verify, or ``None`` when they do.

    The shape is established first (:func:`pack_shape_gap`), then the admission history is checked
    as a chain, then everything :func:`pack_anchor_projection` covers is checked against
    ``anchor_sha256``. A pack recording no anchor at all is refused rather than read leniently,
    because an optional anchor is no anchor: dropping the field is the same deletion it exists to
    make visible.

    Every path that reads a planning decision out of a pack passes through here: the pack load in
    :func:`_validate_case_pack`, every library write, and :func:`scaneval.cases.build_plan`, both of
    which reach it through that same load. As with the review chain, anyone who can edit the pack
    can recompute this; what it removes is the deletion that passes unnoticed.
    """
    shape = pack_shape_gap(pack)
    if shape:
        return shape
    gap, _ = chain_link_gap(pack["admissions"], kind="admission", label="admissions")
    if gap:
        return gap
    recorded = pack.get("anchor_sha256")
    if not recorded:
        return ("anchor_sha256 is missing, so nothing says which snapshots, cases, review "
                "histories, check sets, and admissions this pack recorded, and deleting one of "
                "them would leave no trace")
    expected = pack_anchor_digest(pack)
    if recorded != expected:
        return (f"anchor_sha256 records {recorded}, and the records this pack anchors now anchor "
                f"to {expected}; a record a planning decision reads was deleted, reordered, or "
                "edited")
    return None


def _snapshot_identity(pack: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """The identity of every snapshot *case* names, keyed by snapshot id.

    A label points at bytes, so what a reviewer read is the label text together with the tree it
    describes and the languages that decide how that tree is read (see
    :func:`snapshot_identity_projection`). A snapshot the pack does not declare is projected as
    ``None``: a label naming a snapshot that is not there names no bytes at all, which is itself a
    change from one that named a declared snapshot.
    """
    declared = {snapshot["snapshot_id"]: snapshot for snapshot in pack["snapshots"]}
    named = [case["target"]["snapshot_id"]] + [control["snapshot_id"] for control in case["controls"]]
    identity: dict[str, Any] = {}
    for snapshot_id in named:
        snapshot = declared.get(snapshot_id)
        identity[snapshot_id] = None if snapshot is None else snapshot_identity_projection(snapshot)
    return identity


def _label_projection(pack: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """The label content of *case* together with the identity of the snapshots it names.

    The case's own half is :func:`case_label_projection`, which is every field of the case that
    says what is alleged, projected whole. The other half is the bytes those labels point at: each
    referenced snapshot contributes its commit, its recorded export, and its declared languages
    (see :func:`_snapshot_identity`). Repinning a snapshot to another commit, recording a different
    export for it, or re-declaring the languages it is scanned as therefore costs the approval
    exactly as editing the target's text does.

    Everything left out of the case half is anchored instead, so nothing escapes both records; the
    split between them is stated once, in :data:`CASE_LABEL_FIELDS` and :data:`CASE_UNREAD_FIELDS`,
    and a test holds every field of a case to it.
    """
    projected = {**case_label_projection(case), "snapshots": _snapshot_identity(pack, case)}
    change_sets = _change_set_identity(pack, case)
    if change_sets:
        # Only a case that names a change set carries this key, so every digest recorded before
        # change sets existed still hashes the same content it always did.
        projected["change_sets"] = change_sets
    return projected


def _change_set_identity(pack: dict[str, Any], case: dict[str, Any]) -> dict[str, Any]:
    """The identity of every change set *case*'s PR eligibility names, keyed by change set id.

    A PR eligibility entry says an item is scored in the review of one base/head boundary, so what
    a reviewer approved includes that boundary: which snapshots it runs between, what kind of
    boundary it is, and which scope it declares, with each snapshot's identity projected the way a
    label's own snapshot is (:func:`snapshot_identity_projection`). Free text about the change set
    is left to the anchor. A change set the pack does not declare is projected as ``None``, which is
    itself a change from one that named a declared change set. Empty when the case names none.
    """
    records = [case.get("target")] + list(case.get("controls") or [])
    named = sorted({entry.get("change_set_id") for record in records if isinstance(record, dict)
                    for entry in record.get("pr_eligibility") or [] if isinstance(entry, dict)
                    and isinstance(entry.get("change_set_id"), str)})
    if not named:
        return {}
    declared = {entry.get("change_set_id"): entry for entry in pack.get("change_sets") or []
                if isinstance(entry, dict)}
    snapshots = {snapshot.get("snapshot_id"): snapshot for snapshot in pack.get("snapshots") or []
                 if isinstance(snapshot, dict)}
    identity: dict[str, Any] = {}
    for change_set_id in named:
        change_set = declared.get(change_set_id)
        if change_set is None:
            identity[change_set_id] = None
            continue
        projected = {key: value for key, value in change_set.items()
                     if key not in ("description", "reference")}
        for side in ("base", "head"):
            snapshot = snapshots.get(change_set.get(f"{side}_snapshot_id"))
            projected[f"{side}_snapshot"] = (None if snapshot is None
                                             else snapshot_identity_projection(snapshot))
        identity[change_set_id] = projected
    return identity


def label_digest(pack: dict[str, Any], case: dict[str, Any]) -> str:
    """The digest of one case's labels: what it claims to be, its target, controls, and bytes.

    A recorded approval carries this digest, so an approval is bound to the content it covered
    rather than to the case it sits on. Adding, removing, or editing a control changes it, as
    does pointing a control at other evidence, as does editing the target's mechanism,
    description, affected input, accepted locations, assumptions, or matching rules, and so does
    editing what the case says it represents: its canonical kind, variant family, aliases,
    coverage signature, represents statement, workload, component role, or model involvement.
    Deleting or rewriting an evidence record does too, because an allegation at a reviewed level is
    the allegation together with the evidence it rests on. None of those can ride on an earlier
    review.

    The snapshots each label names are projected too, by commit, recorded tree hash, and declared
    languages as well as by name: moving a target or a control onto a different snapshot changes
    what was reviewed, so does repinning a snapshot the label already named, because the review
    covered the bytes that snapshot stood for and not the identifier, and so does re-declaring the
    languages those bytes are scanned as, because that decides which adapters ever see them.

    This takes the pack because a snapshot's identity lives there rather than on the case. It lives
    here rather than in :mod:`scaneval.cases` because both the planning gate and the pack-load gate
    must ask the same question of the same content, and :mod:`scaneval.cases` imports this module
    and not the other way round. :mod:`scaneval.cases` re-exports it.
    """
    return canonical_sha256(_label_projection(pack, case))


def latest_review(case: dict[str, Any]) -> dict[str, Any] | None:
    """The last recorded review of *case* by list order, whatever it decided, or ``None``.

    List order is the only ordering used; recorded timestamps are text and are not parsed here.
    :mod:`scaneval.cases` re-exports this, because the write paths there and the load gate here
    must read the same review.
    """
    reviews = case["validation"]["reviews"]
    return reviews[-1] if reviews else None


def operative_review_gap(case: dict[str, Any]) -> str | None:
    """Why the latest recorded review of *case* is not an approval, or ``None`` when it is one.

    The latest recorded review is the operative one, and this is the one place that rule is
    written down. A rejection says the label is wrong and an ``unresolved`` entry says the reviewer
    reopened the question without settling it; both are withdrawals, and neither leaves a case
    approved. A case with no review at all has no approval in force either.

    Three paths read this and now cannot disagree: :func:`_validate_case_pack` refuses a
    ``human_approved`` case whose latest review is any of the three, :func:`covering_review` names
    no covering review under one, and :func:`scaneval.cases.record_review` moves the recorded state
    back to what the mechanical checks earn when it records one. It used to be three rules, and the
    seam between them was ``unresolved``: the load refused a rejection but accepted a reopening,
    and the write path demoted on a rejection but not on a reopening, so a reopened case stayed
    recorded as ``human_approved`` at the level of an approval nothing stood behind.

    This reads the decision only. Whether an approval that is in force covers the labels as they
    stand is :func:`covering_review`, and what level it earns is :func:`claimed_level_gap`.
    """
    review = latest_review(case)
    if review is None:
        return "no review is recorded for this case"
    if review["decision"] == "unresolved":
        return "the latest recorded review reopened the question and left it unresolved"
    if review["decision"] == "reject":
        return "the latest recorded review rejected this case"
    return None


def covering_review(pack: dict[str, Any], case: dict[str, Any]) -> dict[str, Any] | None:
    """The one recorded review that approves *case* as its labels now stand, or ``None``.

    The latest recorded review is the operative one (:func:`operative_review_gap`), so this is that
    review when it approved the case and carries :func:`label_digest` of these labels. ``None``
    when a later review rejected the case or reopened the question, when the labels changed after
    the approval, when the snapshots they name were repinned or re-declared, when no review is
    recorded, and when the latest review records no digest at all: a review that never named the
    content it read cannot be shown to cover this content.

    ``None``, too, when the recorded history does not verify as a chain (see
    :func:`review_chain_gap`). A review is read as the last entry of a history, so a history whose
    entries no longer account for each other names no operative review at all: an approval is not
    in force because the entry that withdrew it was deleted. That check lives here rather than
    beside each gate so that no path can reach an approval without passing it, including planning
    on a pack that never went through a load.

    Every gate that asks whether an approval is in force asks this one review, and every level a
    decision is made on is read from it (see :func:`effective_level`), so a plan and a pack load
    cannot end up resting on two different reviews. Nothing is rewritten or withdrawn here; this
    reads what the pack records.
    """
    validation = case["validation"]
    if review_chain_gap(validation["reviews"], validation.get("reviews_sha256")):
        return None
    if operative_review_gap(case) is not None:
        return None
    review = latest_review(case)
    if not review.get("labels_sha256"):
        return None
    return review if review["labels_sha256"] == label_digest(pack, case) else None


def level_gap(review: dict[str, Any], claimed: str | None) -> str | None:
    """Why *review* does not itself earn *claimed*, or ``None`` when it does.

    Levels are ordered, so an approval recorded at a higher level earns a lower claimed one. L3
    and L4 rest on an independent review, so the one review being asked must itself carry that
    role: an independent approval elsewhere in the history was an approval of other content and
    earns nothing here. ``None`` for a case claiming no level, which has nothing to earn.

    This answers what a review is capable of earning. It is not the question a gate asks about a
    case, because a claim lower than the review is still a claim that disagrees with the only
    record of the level; :func:`claimed_level_gap` asks that one.
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


def claimed_level_gap(review: dict[str, Any], claimed: str | None) -> str | None:
    """Why *claimed* is not the level *review* establishes, or ``None`` when it is.

    Two things must hold, and both are asked of this one review. It must earn the level it is
    itself recorded at, which for L3 and L4 means it was made by an ``independent_reviewer``: a
    review recorded at a level its role does not support earns nothing, whatever a case claims
    beside it. And the claim must be that level exactly. A claim below the review is as much a
    disagreement as a claim above it, because the covering review is the only source of the level
    and every gate reads the review rather than the claim: a case recorded at L2 under an L4 review
    is planned at L4, so measuring the review against the L2 claim asks a question no decision
    depends on. Levels stay ordered for :func:`level_gap`, which asks what a review can earn; this
    asks whether a cached claim is the level that review established.
    """
    own = level_gap(review, review["level"])
    if own:
        return own
    if claimed != review["level"]:
        return level_gap(review, claimed) or (
            f"validation.level records {claimed}, but the review covering these labels is recorded "
            f"at {review['level']}; the recorded level is a cached copy of that review's level and "
            "may not say anything else")
    return None


def recorded_level_gap(pack: dict[str, Any], case: dict[str, Any]) -> str | None:
    """Why ``validation.level`` is not the level *case*'s own records establish, or ``None``.

    ``validation.level`` is a cached claim, never a fact: the level of an approved case is the level
    of the one review covering its labels, and the level of a checked case is the L1 its mechanical
    state carries. This compares the cached value with that, so the two records of one fact cannot
    disagree without the pack being refused and the case going unplanned.

    A human approved case whose labels no recorded review covers is the one case with nothing to
    compare against: no review speaks for this content, so nothing here establishes a level, the
    case plans nothing whatever it claims, and :func:`_validate_case_pack` applies the weaker rule
    that some recorded approval must at least carry the claim.
    """
    validation = case["validation"]
    claimed = validation["level"]
    state = validation["review_state"]
    if state == "human_approved":
        covering = covering_review(pack, case)
        return None if covering is None else claimed_level_gap(covering, claimed)
    if state == "mechanically_checked":
        if claimed != "L1":
            return (f"mechanically_checked is the L1 state; level {claimed!r} needs a recorded "
                    "human review")
        return None
    if claimed is not None:
        return "draft cases cannot carry a validation level"
    return None


def effective_level(pack: dict[str, Any], case: dict[str, Any]) -> str | None:
    """The validation level *case* actually has, or ``None`` when nothing establishes one.

    This is the single source of the level anywhere a decision is made: the level of the review
    covering the labels as they stand for an approved case, ``L1`` for one the mechanical checks
    have reached, and ``None`` for a draft. ``None`` too when the covering review does not earn the
    level it records, when no review covers these labels, and when the cached ``validation.level``
    disagrees with the review (see :func:`recorded_level_gap`), because a fact two records state
    differently is established by neither.

    Nothing reads ``validation.level`` to decide anything; it is compared with this and otherwise
    only displayed. A case this returns ``None`` for is unplanned, not judged wrong.
    """
    if recorded_level_gap(pack, case) is not None:
        return None
    state = case["validation"]["review_state"]
    if state == "human_approved":
        covering = covering_review(pack, case)
        return None if covering is None else covering["level"]
    if state == "mechanically_checked":
        return "L1"
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
    provenance = document.get("provenance")
    if document["schema_version"] != "2.0" and provenance is not None:
        # A PR plan names the boundary it scores and the scope of every item in it; a full plan
        # names neither. A blinded plan names the map its input was transformed with.
        is_pr = provenance["mode"] == "pr"
        if is_pr != ("pr" in provenance):
            raise ContractError("provenance.pr is required exactly when the plan mode is pr")
        scoped = [item for item in document["targets"] + document["controls"] if "pr_scope" in item]
        if is_pr and len(scoped) != len(document["targets"]) + len(document["controls"]):
            raise ContractError("every item of a pr plan states its pr_scope")
        if not is_pr and scoped:
            raise ContractError("only a pr plan carries pr_scope")
        blinded = provenance.get("profile") == "metadata_blinded"
        if blinded != ("blinding" in provenance):
            raise ContractError("provenance.blinding is required exactly when the profile is metadata_blinded")
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
    if document["schema_version"] == "2.0":
        return
    provenance = document["provenance"]
    if (provenance["mode"] == "pr") != (provenance.get("pr") is not None):
        raise ContractError("provenance.pr is recorded exactly for a pr invocation")
    isolation = document["isolation"]
    if isolation["enforced"] and isolation["backend"] == "local":
        raise ContractError("the local backend enforces nothing, so it cannot be recorded as enforced")
    if document["network_policy"]["enforced"] and not isolation["enforced"]:
        raise ContractError("a network policy is enforced only inside an enforced isolation backend")


def _validate_case_pack(document: dict[str, Any]) -> None:
    """Check what a pack asserts about its own label states; it never re-runs a check.

    ``mechanically_checked`` is the L1 state and claims a passing check set for every snapshot
    the case references, ``checks_failed`` belongs only to an approved case whose checks later
    failed, and an L3/L4 label belongs only to a case screened as worth validating. A
    ``human_approved`` case makes the same claim about its check sets as a mechanically checked
    one unless it raises ``checks_failed``.

    The recorded review state and the latest recorded review are two records of one fact, and they
    must agree in both directions (:func:`operative_review_gap`, which
    :func:`scaneval.cases.record_review` reads too, so the states this refuses are the states no
    write path can leave behind). ``human_approved`` cannot stand under a latest review that
    withdrew the approval, whether that review rejected the case or reopened the question; and a
    case recorded ``draft`` or ``mechanically_checked`` cannot stand under a latest review that
    approved it. Changed deliberately this round: only the first direction was checked, so the
    mirror state loaded, and in it the two records disagreed the other way round. What it bought
    was not an escalation, because ``plan_scope`` reads ``review_state`` and a mechanical state
    never reaches a reviewed plan; what it bought was the disagreement itself. A pack could record
    a standing, unwithdrawn L3 or L4 approval and beside it a state saying there is none, plan the
    case at the L1 of its mechanical checks, and dodge the rules ``human_approved`` carries, the
    disposition and the covering review among them, while :func:`scaneval.cases.pack_summary` and
    the CLI listing reported the case as never reviewed. A withdrawal is a decision a named
    reviewer records, and this is the load refusing to read one out of an edited scalar.

    ``validation.level`` is a cached claim and decides nothing. The level of an approved case is
    the level of the one review covering its labels, which :func:`covering_review` names and
    :func:`effective_level` reads, and the cached field must be exactly that level:
    :func:`recorded_level_gap` refuses a pack where the two records of one fact disagree, in either
    direction. A review recorded at L3 or L4 must itself be by an ``independent_reviewer`` to earn
    what it records, so a claim recorded below such a review no longer hides a role the level does
    not support. An independent approval elsewhere in the history approved other content and earns
    nothing here, so a case cannot be raised to a reviewed level by editing a label, collecting a
    lesser approval of the edit, and resting the level on the older review.
    :func:`scaneval.cases.approval_is_current` asks the same review the same question, so a plan
    and a pack load cannot rest on two different ones. When no recorded review covers the current
    labels the case plans nothing whatever it claims, and the weaker rule applies instead: the
    level must be one some recorded approval carries, so the pack still cannot claim a review
    nobody recorded.

    Every field a planning decision reads is inside one of two records, and which one is decided by
    subtraction rather than by a list of fields anyone has to remember to extend. The labels are
    bound to the approval that covered them by :func:`label_digest`. Everything else about a
    snapshot, a case, or the pack itself is bound to ``anchor_sha256`` by
    :func:`pack_anchor_projection`: the disposition a plan reads, the whole validation block with
    its check sets and its ``checks_failed`` flag, the disclosure dates, the split, and the
    ``review_budgets`` every recall-at-k number is computed at. The labels of a case no review has
    bound to a digest are in the anchor too (:func:`labels_are_bound`), and so is the identity of
    every snapshot no label digest holds (:func:`snapshots_bound_by_labels`), which means every
    snapshot until every case in the pack binds its own labels, and a snapshot no case names for as
    long as none does. The first record is a record only where one was recorded: an unreviewed case
    has no digest covering anything, and no digest covers a snapshot nothing points at. What sits
    outside both is stated in three allowlists a test pins: a case's ``notes``, which nothing
    reads, and the pack's own identity and status, which every plan binds by hashing the whole file
    it was built from.

    Inside those records the chains do the rest, and they are checked here as they are everywhere
    else. The recorded reviews are a chain ending at ``validation.reviews_sha256``
    (:func:`review_chain_gap`). Each mechanical check set is one record in ``validation.check_sets``
    whose digest covers its result, its export, and its own checks (:func:`check_set_gap`), so
    deleting or unattributing a failing check cannot turn a failed set into a passing one, and
    deleting the record itself no longer reads as a snapshot nobody checked, because the anchor
    holds it. The admissions are a chain whose end the anchor records, so deleting an admission,
    wiping a case's review history, or deleting a whole case is not a consistent pack. Those
    docstrings say what that does and does not prove; in short, anyone who can edit the pack can
    recompute an anchor, so they catch the quiet deletion rather than a determined forger.

    Which export a check set read is recorded three times, and the three must agree: the
    ``check_sets`` record for the snapshot, the ``detail`` of that set's passing
    ``snapshot_hash_recorded`` check, and the ``tree_hash`` the snapshot declares. A passing set
    must carry the check confirming its export. Editing any two of the three therefore contradicts
    the third rather than pointing a standing approval at an export the checks never ran against. A
    failing set is exempt from the comparison with the declared hash, because recording the export
    that was read and rejected is exactly what it is for; a failing set keeps the case out of a
    plan anyway.

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
    if document["schema_version"] != "2.0":
        _validate_change_sets(document, known)
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
        chain = review_chain_gap(reviews, validation.get("reviews_sha256"))
        if chain:
            raise ContractError(f"{label}: {chain}")
        # Every recorded check set, before anything reads a state out of one. A set that does not
        # verify says nothing about the snapshot it names, so the state rules below read `None`
        # for it and would otherwise report a missing set rather than a broken record.
        recorded_sets = validation.get("check_sets", {})
        attributed = {check.get("snapshot_id") for check in validation["checks"]}
        for snapshot_id in sorted(set(recorded_sets) | attributed):
            broken = check_set_gap(validation, snapshot_id)
            if broken:
                raise ContractError(f"{label}: {broken}")
        approvals = [r for r in reviews if r["decision"] == "approve"]
        referenced = [target["snapshot_id"]] + [control["snapshot_id"] for control in case["controls"]]
        unchecked = sorted({snapshot for snapshot in referenced
                            if recorded_check_state(validation, snapshot) != "pass"})
        # One rule, read in both directions, and the same one the write path and the planning gate
        # read: the latest recorded review is the operative one, so a case is human_approved
        # exactly when its latest recorded review is an approving one. A rejection and a reopening
        # are both withdrawals. The second direction was missing, and it is the mirror of the
        # first: a case recorded draft or mechanically_checked under an approving latest review is
        # the same disagreement between two records of one fact, and no write path can leave it,
        # because :func:`scaneval.cases.record_review` sets human_approved on every approval.
        withdrawn = operative_review_gap(case)
        if state == "human_approved" and withdrawn:
            raise ContractError(
                f"{label}: human_approved requires the latest recorded review to be an "
                f"approving review, and {withdrawn}; record the decision that reinstated it")
        if state != "human_approved" and withdrawn is None:
            raise ContractError(
                f"{label}: the latest recorded review approved this case, so the recorded review "
                f"state must be human_approved, not {state}; record the review that withdrew that "
                "approval, or record the state that approval leaves behind")
        if state == "human_approved" and validation["level"] is None:
            raise ContractError(f"{label}: human_approved requires a validation level")
        if state == "human_approved" and unchecked and not validation.get("checks_failed"):
            raise ContractError(
                f"{label}: human_approved requires a recorded passing check set for every referenced "
                f"snapshot, or validation.checks_failed to record that one failed; missing or failed "
                f"for: {', '.join(unchecked)}")
        if validation["level"] in ("L3", "L4") and state != "human_approved":
            raise ContractError(f"{label}: {validation['level']} requires human_approved review state")
        # The cached level against the records that establish one. One review covers these labels,
        # so that review alone says what the level is, and the cached field may only repeat it.
        gap = recorded_level_gap(document, case)
        if gap:
            raise ContractError(f"{label}: {gap}")
        if state == "human_approved" and covering_review(document, case) is None:
            # No recorded review covers the labels as they stand, so planning leaves the case out
            # whatever it claims. The level must still be one the history records, or the pack
            # claims a review nobody recorded.
            claimed = validation["level"]
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
        if "checks_failed" in validation and state != "human_approved":
            raise ContractError(
                f"{label}: checks_failed records a check set that failed after approval, so it "
                f"belongs only to a human_approved case, not to a {state} one")
        if state == "mechanically_checked" and unchecked:
            raise ContractError(
                f"{label}: mechanically_checked requires a recorded passing check set for every "
                f"referenced snapshot; missing or failed for: {', '.join(unchecked)}")
        # The screening decision is measured against the level the case actually has. A stale claim
        # no review covers establishes nothing, so it is measured instead: a pack may not record a
        # reviewed level on a case screened out, whether or not anything plans it.
        level = effective_level(document, case) or validation["level"]
        if level in ("L3", "L4") and case["disposition"]["value"] != "validate":
            raise ContractError(
                f"{label}: {level} requires disposition validate, not "
                f"{case['disposition']['value']}")
        # The three records of which export each check set read, compared with each other. These
        # run after the state rules so that a pack missing a check set is told that first: a
        # record of a set that is not there is a narrower complaint than the set being absent.
        for snapshot_id in sorted(set(referenced)):
            confirmed = {check["detail"] for check in validation["checks"]
                         if check.get("snapshot_id") == snapshot_id
                         and check["check"] == "snapshot_hash_recorded" and check["result"] == "pass"}
            declared = snapshot_hashes.get(snapshot_id)
            recorded_set = recorded_sets.get(snapshot_id)
            entry = None if recorded_set is None else recorded_set["tree_hash"]
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
                    f"{label}: validation.check_sets records {entry} for snapshot {snapshot_id}, "
                    f"but that check set's passing snapshot_hash_recorded check records "
                    f"{', '.join(sorted(confirmed))}")
            if (entry is not None and not confirmed
                    and recorded_check_state(validation, snapshot_id) == "pass"):
                raise ContractError(
                    f"{label}: validation.check_sets records {entry} for snapshot {snapshot_id}, "
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
    # The pack-level anchor last: it says which cases, review histories, and admissions were
    # recorded, so a complaint about one of them that is still there is the more specific one.
    anchor = pack_anchor_gap(document)
    if anchor:
        raise ContractError(anchor)


def _validate_change_sets(document: dict[str, Any], known: set[str]) -> None:
    """A change set runs between two declared snapshots of one repository, and PR eligibility names one.

    Base and head must be declared, distinct, and fetched from the same repository URL, since a
    diff between two unrelated repositories is not a change anybody reviewed. An item may be
    eligible only under a change set whose head is its own snapshot: a PR review reads the head
    tree, so a label on any other snapshot is not something that review can observe. Relations are
    checked against the kind of item: a target is introduced or affected by a change, and only a
    control can be repaired by one. Whether the eligibility is right is a reviewed judgment, never
    a line-overlap computation here.
    """
    by_id = {snapshot["snapshot_id"]: snapshot for snapshot in document["snapshots"]}
    change_sets = document.get("change_sets", [])
    _unique([entry["change_set_id"] for entry in change_sets], "change_set_id")
    heads: dict[str, str] = {}
    for entry in change_sets:
        label = f"change set {entry['change_set_id']}"
        for side in ("base", "head"):
            if entry[f"{side}_snapshot_id"] not in known:
                raise ContractError(f"{label}: {side} snapshot {entry[f'{side}_snapshot_id']} is not declared")
        if entry["base_snapshot_id"] == entry["head_snapshot_id"]:
            raise ContractError(f"{label}: base and head must be different snapshots")
        base = by_id[entry["base_snapshot_id"]]["repository"]["url"]
        head = by_id[entry["head_snapshot_id"]]["repository"]["url"]
        if base != head:
            raise ContractError(f"{label}: base and head come from different repositories ({base}, {head})")
        heads[entry["change_set_id"]] = entry["head_snapshot_id"]
    for case in document["cases"]:
        records = [("target", case["target"])] + [("control", control) for control in case["controls"]]
        for kind, record in records:
            owner = record.get("target_id") if kind == "target" else record["control_id"]
            entries = record.get("pr_eligibility", [])
            _unique([entry["change_set_id"] for entry in entries], f"{owner} pr_eligibility change_set_id")
            for entry in entries:
                label = f"case {case['case_id']}: {kind} {owner} pr_eligibility {entry['change_set_id']}"
                if entry["change_set_id"] not in heads:
                    raise ContractError(f"{label} names a change set the pack does not declare")
                if heads[entry["change_set_id"]] != record["snapshot_id"]:
                    raise ContractError(
                        f"{label}: the item is on snapshot {record['snapshot_id']}, but a PR review "
                        f"reads the change set's head, {heads[entry['change_set_id']]}")
                if kind == "target" and entry["relation"] == "repaired":
                    raise ContractError(f"{label}: a target is introduced or affected, never repaired")


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


_PINNED_IMAGE = re.compile(r"^(?:[^@\s]+@sha256:[0-9a-f]{64}|sha256:[0-9a-f]{64})$")
BLINDED_INPUT_SUFFIX = ".blinded"


def input_identity(entry: dict[str, Any]) -> str:
    """The evaluator-side id of one configured input: its ``input_id``, or the default for its shape.

    A full input defaults to its snapshot id and a PR input to its change set id, each with
    :data:`BLINDED_INPUT_SUFFIX` when the input is metadata-blinded, so a standard and a blinded
    input of one snapshot can sit in one run. A 2.0 configuration has only snapshot ids, and this
    returns exactly that for it. The id names directories and invocations on the evaluator side
    and is never shown to a scanner.
    """
    if entry.get("input_id"):
        return entry["input_id"]
    base = entry.get("change_set_id") if entry.get("mode", "full") == "pr" else entry.get("snapshot_id")
    return f"{base}{BLINDED_INPUT_SUFFIX}" if entry.get("profile") == "metadata_blinded" else base


def _validate_run_config(document: dict[str, Any]) -> None:
    """Unique ids, and for 2.1 an input shape that says exactly one thing and a backend that can hold.

    A full input names a snapshot and a PR input names a change set, never both; a blinded input
    names its reviewed map and nothing else carries one. An ``oci`` backend must name an image
    pinned by digest, and ``model_provider_only`` under it must declare the egress it allows and
    the proxy image that enforces it, because a policy with no enforcement behind it would be
    recorded as enforced. A ``local`` backend carries none of those settings, so a configuration
    cannot look sandboxed while nothing is. These are shape rules: whether an image exists or a
    map is reviewed is checked when the run prepares it.
    """
    _unique([system["system_id"] for system in document["systems"]], "system_id")
    if document["schema_version"] == "2.0":
        _unique([item["snapshot_id"] for item in document["inputs"]], "inputs.snapshot_id")
        return
    for index, item in enumerate(document["inputs"]):
        label = f"inputs[{index}]"
        mode = item.get("mode", "full")
        if mode == "full" and ("snapshot_id" not in item or "change_set_id" in item):
            raise ContractError(f"{label}: a full input names a snapshot_id and no change_set_id")
        if mode == "pr" and ("change_set_id" not in item or "snapshot_id" in item):
            raise ContractError(f"{label}: a pr input names a change_set_id and no snapshot_id")
        blinded = item.get("profile", "standard") == "metadata_blinded"
        if blinded != ("blinding_map" in item):
            raise ContractError(
                f"{label}: blinding_map is required exactly when profile is metadata_blinded")
    _unique([input_identity(item) for item in document["inputs"]], "input id")
    for index, system in enumerate(document["systems"]):
        execution = system.get("execution") or {"backend": "local"}
        label = f"systems[{index}].execution"
        policy = system.get("network_policy", document["network_policy"])
        if execution["backend"] == "local":
            extra = sorted(set(execution) - {"backend"})
            if extra:
                raise ContractError(
                    f"{label}: the local backend enforces nothing, so it takes no {', '.join(extra)}")
            continue
        image = execution.get("image")
        if not isinstance(image, str) or not _PINNED_IMAGE.match(image):
            raise ContractError(f"{label}: an oci backend needs an image pinned by digest, not {image!r}")
        if policy == "model_provider_only":
            if not execution.get("egress"):
                raise ContractError(f"{label}: model_provider_only needs the egress it allows declared")
            proxy = execution.get("proxy_image")
            if not isinstance(proxy, str) or not _PINNED_IMAGE.match(proxy):
                raise ContractError(
                    f"{label}: model_provider_only needs a proxy_image pinned by digest, not {proxy!r}")
        elif execution.get("egress") or execution.get("proxy_image"):
            raise ContractError(f"{label}: egress and proxy_image apply only to model_provider_only")


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
    version = document["schema_version"]
    key = "snapshot_id" if version == "2.0" else "input_id"
    _unique([item[key] for item in document["inputs"]], f"inputs.{key}")
    _unique([system["system_id"] for system in document["systems"]], "systems.system_id")
    _unique([row["invocation_id"] for row in document["invocations"]], "invocation_id")
    for index, item in enumerate(document["inputs"]):
        if item["provenance_path"] is not None:
            _require_relative_path(item["provenance_path"], f"inputs[{index}].provenance_path")
    if version != "2.0":
        _require_relative_path(document["schedule_path"], "schedule_path")
        unprepared = {item["input_id"] for item in document["inputs"] if item["preparation_failure"]}
        for index, row in enumerate(document["invocations"]):
            if row["input_id"] in unprepared and row["status"] != "skipped":
                raise ContractError(
                    f"invocations[{index}]: input {row['input_id']} was never prepared, so no "
                    "invocation of it can have run")
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


# --- evaluation schedule ------------------------------------------------------------------------


def _validate_evaluation_schedule(document: dict[str, Any]) -> None:
    """Check that a schedule is complete and consistent with itself; it says nothing about outcomes.

    Every input, system, and assignment id is unique, and the assignments are exactly every input
    under every system for every repetition, each named by the invocation id its bundle carries
    (``<input>__<system>__r<n>``, the one format :func:`scaneval.execution.invocation_id` writes), so
    a schedule cannot leave out the assignment that later failed. A full input names its snapshot
    and no change set; a PR input names its change set. A blinded input names the map it is
    transformed with, and no other input names one. A pair joins a target planned on one full-scan
    input with a fixed-target control of that target planned on a different full-scan input of the
    same profile, and pairs repetitions this schedule declares. Nothing here reads a pack, an
    export, or a result.
    """
    inputs = {item["input_id"]: item for item in document["inputs"]}
    _unique([item["input_id"] for item in document["inputs"]], "inputs.input_id")
    _unique([system["system_id"] for system in document["systems"]], "systems.system_id")
    _unique([row["assignment_id"] for row in document["assignments"]], "assignment_id")
    for item in document["inputs"]:
        label = f"input {item['input_id']}"
        if item["mode"] == "full" and (item["snapshot_id"] is None or item["change_set_id"] is not None
                                       or item["change_set"] is not None):
            raise ContractError(f"{label}: a full input names a snapshot_id and no change set")
        if item["mode"] == "pr" and item["change_set_id"] is None:
            raise ContractError(f"{label}: a pr input names its change_set_id")
        if (item["profile"] == "metadata_blinded") != (item["blinding"] is not None):
            raise ContractError(f"{label}: a blinding map is named exactly when the profile is metadata_blinded")
    repetitions = document["repetitions"]
    expected = {f"{input_id}__{system['system_id']}__r{repetition}": (input_id, system["system_id"], repetition)
                for input_id in inputs for system in document["systems"]
                for repetition in range(1, repetitions + 1)}
    recorded = {row["assignment_id"]: (row["input_id"], row["system_id"], row["repetition"])
                for row in document["assignments"]}
    if recorded != expected:
        missing = sorted(set(expected) - set(recorded))
        extra = sorted(set(recorded) - set(expected))
        mismatched = sorted(key for key in set(recorded) & set(expected) if recorded[key] != expected[key])
        raise ContractError(
            "assignments must be every input under every system for every repetition, each named by "
            f"its invocation id; missing {missing[:3]}, unexpected {extra[:3]}, misnamed {mismatched[:3]}")
    for index, pair in enumerate(document["pairs"]):
        label = f"pairs[{index}]"
        vulnerable = inputs.get(pair["vulnerable_input_id"])
        fixed = inputs.get(pair["fixed_input_id"])
        if vulnerable is None or fixed is None:
            raise ContractError(f"{label} names an input this schedule does not declare")
        if pair["vulnerable_input_id"] == pair["fixed_input_id"]:
            raise ContractError(f"{label}: the vulnerable and fixed observations are on one input")
        if vulnerable["mode"] != "full" or fixed["mode"] != "full":
            raise ContractError(f"{label}: a pair joins two full-scan inputs; no pair of PR inputs is defined")
        if vulnerable["profile"] != fixed["profile"]:
            raise ContractError(f"{label}: a pair joins inputs of one profile")
        if vulnerable["plan"]["state"] != "frozen" or fixed["plan"]["state"] != "frozen":
            raise ContractError(f"{label}: a pair is matched only between plans frozen before execution")
        targets = {target["target_id"]: target for target in vulnerable["plan"]["targets"]}
        controls = {control["control_id"]: control for control in fixed["plan"]["controls"]}
        target = targets.get(pair["target_id"])
        control = controls.get(pair["control_id"])
        if target is None or control is None:
            raise ContractError(f"{label}: the target must be planned on the vulnerable input and the "
                                "control on the fixed input")
        if control["type"] not in ("fixed_target", "both") or control["target_id"] != pair["target_id"]:
            raise ContractError(f"{label}: control {pair['control_id']} is not a fixed-target control of "
                                f"{pair['target_id']}")
        if pair["canonical_id"] != target["canonical_id"]:
            raise ContractError(f"{label}: canonical_id is not the planned target's canonical id")
        seen: set[tuple[int, int]] = set()
        for left, right in pair["repetition_pairs"]:
            if not (1 <= left <= repetitions and 1 <= right <= repetitions) or (left, right) in seen:
                raise ContractError(f"{label}: repetition pairs name repetitions this schedule declares, "
                                    "each pair once")
            seen.add((left, right))


# --- metadata blinding map ---------------------------------------------------------------------


# Every character str.splitlines treats as a line break. A pseudonym holding one could move a line
# and break the line-for-line mapping a blinded input's claim locations rely on.
_LINE_BREAKS = frozenset("\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029")


def _validate_blinding_map(document: dict[str, Any]) -> None:
    """Check what a blinding map asserts about itself; whether it fits an export is asked when applied.

    Pseudonyms: neither side blank or holding a line break, an original never its own replacement,
    originals unique, replacements unique, and, ignoring case, no replacement containing any
    original (a replaced file would still carry it) and no original containing another pseudonym's
    replacement (a transformed file could not say which token it came from). Variants are unique by
    snapshot. Edits are unique by id and by path, each path a normalized relative POSIX path, each
    rationale stated, a ``display_metadata`` edit carrying a stated ``role_check``, each replaced
    token a declared original, and exactly one expectation per variant, whose occurrence counts
    name exactly the edit's replacements. The review history is a chain (kind ``blinding_review``)
    whose end ``reviews_sha256`` records, present exactly when a review is, and every review names
    its reviewer. Approval, path classes, and file hashes are not asked here:
    :mod:`scaneval.blinding` asks them against the export, where a refusal is that input's own
    preparation failure.
    """
    pseudonyms = document["pseudonyms"]
    for index, pseudonym in enumerate(pseudonyms):
        for side in ("original", "replacement"):
            value = pseudonym[side]
            if not is_stated(value):
                raise ContractError(f"pseudonyms[{index}].{side} is blank")
            if any(character in _LINE_BREAKS for character in value):
                raise ContractError(f"pseudonyms[{index}].{side} holds a line break, which would move a line")
        if pseudonym["original"] == pseudonym["replacement"]:
            raise ContractError(f"pseudonyms[{index}] replaces {pseudonym['original']!r} with itself")
    originals = [pseudonym["original"] for pseudonym in pseudonyms]
    replacements = [pseudonym["replacement"] for pseudonym in pseudonyms]
    _unique(originals, "pseudonyms.original")
    _unique(replacements, "pseudonyms.replacement")
    for index, replacement in enumerate(replacements):
        for original in originals:
            if original.casefold() in replacement.casefold():
                raise ContractError(
                    f"pseudonyms[{index}].replacement {replacement!r} contains the original {original!r}, "
                    "so a replaced file would still carry it")
    for index, original in enumerate(originals):
        for other, replacement in enumerate(replacements):
            if other != index and replacement.casefold() in original.casefold():
                raise ContractError(
                    f"pseudonyms[{index}].original {original!r} contains {replacement!r}, the replacement "
                    f"in pseudonyms[{other}], so a transformed file could not say which token it came from")
    variants = [variant["snapshot_id"] for variant in document["variants"]]
    _unique(variants, "variants.snapshot_id")
    edits = document["edits"]
    _unique([edit["edit_id"] for edit in edits], "edits.edit_id")
    _unique([edit["path"] for edit in edits], "edits.path")
    for edit in edits:
        label = f"edit {edit['edit_id']}"
        path = edit["path"]
        _require_relative_path(path, f"{label}.path")
        if "\\" in path or any(part in ("", ".") for part in path.split("/")):
            raise ContractError(f"{label}.path must be a normalized relative POSIX path, not {path!r}")
        if not is_stated(edit["rationale"]):
            raise ContractError(f"{label} must state its rationale")
        if "role_check" in edit and not is_stated(edit["role_check"]):
            raise ContractError(f"{label}.role_check is blank")
        if edit["role"] == "display_metadata" and "role_check" not in edit:
            raise ContractError(f"{label}: a display_metadata edit states its role_check, the reason the "
                                "field is not read at runtime")
        unknown = sorted(set(edit["replacements"]) - set(originals))
        if unknown:
            raise ContractError(f"{label} replaces tokens no pseudonym declares: {unknown}")
        expected = [entry["snapshot_id"] for entry in edit["expected"]]
        _unique(expected, f"{label} expected.snapshot_id")
        if set(expected) != set(variants):
            raise ContractError(f"{label} must state one expectation for every variant and no other: "
                                f"it names {sorted(expected)}, the map covers {sorted(variants)}")
        for entry in edit["expected"]:
            if entry["state"] == "present" and set(entry["occurrences"]) != set(edit["replacements"]):
                raise ContractError(f"{label}: the occurrence counts for {entry['snapshot_id']} must name "
                                    "exactly the tokens the edit replaces")
    reviews = document["reviews"]
    for index, review in enumerate(reviews):
        if not is_stated(review["reviewer"]):
            raise ContractError(f"a recorded map review must name its reviewer; reviews[{index}].reviewer is blank")
    gap, head = chain_link_gap(reviews, kind="blinding_review", label="reviews")
    if gap:
        raise ContractError(gap)
    recorded = document.get("reviews_sha256")
    if head is None and recorded is not None:
        raise ContractError(f"reviews_sha256 records {recorded}, but no review is recorded; the history it "
                            "names was deleted whole")
    if head is not None and recorded is None:
        raise ContractError("reviews_sha256 is missing, so nothing says where the review history ends and a "
                            "review deleted from the end of it would leave no trace")
    if head != recorded:
        raise ContractError(f"reviews_sha256 records {recorded}, but the review history ends at {head}; a "
                            "review was deleted from the end of it")
# SARIF import (profile sarif-import-1).
def _validate_import_record(document: dict[str, Any]) -> None:
    """Check what an import record asserts about its own accounting; it says nothing about the log.

    Every result of the imported run is accounted for exactly once: as a claim, an exclusion the
    profile states, or a loss, so a result cannot disappear between the three lists and the
    counts are the lengths of the lists they summarize. A run whose result list was absent
    accounts for nothing. The record binds the tree hash and system it names in two places each,
    and they must agree. A recorded normalization decision names a result this import flagged
    for bundle review, at most once, and names its reviewer by the same :func:`is_stated` rule
    every other recorded review follows. Whether the reviewer read anything, and whether the log
    told the truth about its own execution, is outside what this can see.
    """
    _require_relative_path(document["artifact"]["path"], "artifact.path")
    if document["source_binding"]["tree_hash"] != document["input_hash"]:
        raise ContractError("source_binding.tree_hash must equal input_hash")
    if document["system"]["system_id"] != document["system_id"]:
        raise ContractError("system.system_id must equal system_id")
    if document["sarif"]["run_index"] >= document["sarif"]["run_count"]:
        raise ContractError("sarif.run_index must name one of the log's runs")
    claims, excluded, losses = document["claims"], document["excluded"], document["losses"]
    _unique([entry["claim_id"] for entry in claims], "claims.claim_id")
    _unique([entry["pointer"] for entry in claims + excluded + losses],
            "result pointer across claims, excluded, and losses")
    counts = document["counts"]
    for key, entries in (("claims", claims), ("excluded", excluded), ("losses", losses)):
        if counts[key] != len(entries):
            raise ContractError(f"counts.{key} is {counts[key]}, but {len(entries)} are recorded")
    accounted = len(claims) + len(excluded) + len(losses)
    if document["execution"]["results"] == "absent" and accounted:
        raise ContractError("a run whose results are absent has no result to account for")
    if counts["results"] != accounted:
        raise ContractError(f"counts.results is {counts['results']}, but {accounted} results are "
                            "accounted for as claims, exclusions, and losses")
    if counts["evidence_losses"] != sum(len(entry["evidence_losses"]) for entry in claims):
        raise ContractError("counts.evidence_losses must equal the evidence losses recorded per claim")
    flagged = {entry["pointer"] for entry in claims if entry["bundle_review"]}
    if counts["bundle_review_flagged"] != len(flagged):
        raise ContractError("counts.bundle_review_flagged must equal the claims flagged for bundle review")
    normalization = document["normalization"]
    decided = [decision["pointer"] for decision in normalization["decisions"]] if normalization else []
    _unique(decided, "normalization.decisions.pointer")
    for index, pointer in enumerate(decided):
        if pointer not in flagged:
            raise ContractError(f"normalization.decisions[{index}] names {pointer}, which this import "
                                "did not flag for bundle review")
        if not is_stated(normalization["decisions"][index]["reviewer"]):
            raise ContractError(f"normalization.decisions[{index}].reviewer is blank")
    if counts["bundle_review_resolved"] != len(decided):
        raise ContractError("counts.bundle_review_resolved must equal the recorded normalization decisions")


# --- corpus aggregation and paired comparison ---------------------------------------------------


# How far a declared weight total may sit from 1 and still be read as 1; scaneval.aggregate reads
# the same tolerance when it checks explicit target weights over one view.
WEIGHT_TOLERANCE = 1e-9


def _validate_aggregation_policy(document: dict[str, Any]) -> None:
    """Check that a policy's weightings and weights can be applied; it says nothing about their merit.

    The explicit weighting is listed exactly when explicit target weights are declared, so a policy
    cannot ask for a view it gives no weights for, or declare weights no view reads. Declared
    workload weights sum to 1. Whether explicit target weights cover a view's canonical targets and
    sum to 1 over them depends on the runs aggregated, and is checked, per view, when they are.
    """
    if ("explicit" in document["views"]) != (document.get("target_weights") is not None):
        raise ContractError("views lists 'explicit' exactly when target_weights is declared")
    workloads = document.get("workload_weights")
    if workloads is not None:
        total = math.fsum(workloads.values())
        if abs(total - 1) > WEIGHT_TOLERANCE:
            raise ContractError(f"workload_weights must sum to 1, not {total!r}")


def _validate_aggregate_report(document: dict[str, Any]) -> None:
    """Check that an aggregate report is internally keyed; it says nothing about the numbers in it.

    The embedded policy is a valid aggregation policy, run, system, and view keys are unique, and each
    system appears once per view with one block per slice and one detection block per weighting the
    policy lists. Nothing here reads a run directory or recomputes a metric.
    """
    validate_document("aggregation-policy", document["policy"])
    _unique([run["run_id"] for run in document["runs"]], "runs.run_id")
    _unique([system["system_id"] for system in document["systems"]], "systems.system_id")
    _unique([f"{view['mode']}/{view['profile']}" for view in document["views"]], "views (mode, profile)")
    for view in document["views"]:
        _unique([system["system_id"] for system in view["systems"]], "view systems.system_id")
        for system in view["systems"]:
            _check_slices(system["slices"], document["policy"]["views"])


def _check_slices(slices: list[dict[str, Any]], weightings: list[str]) -> None:
    """Each slice once, only the whole-view slice without a value, and every weighting in order."""
    _unique([f"{block['slice']['dimension']}={block['slice']['value']}" for block in slices], "slices")
    for block in slices:
        if (block["slice"]["dimension"] == "all") != (block["slice"]["value"] is None):
            raise ContractError("only the 'all' slice has no value")
        if [detection["weighting"] for detection in block["detection"]] != list(weightings):
            raise ContractError("each slice carries one detection block per weighting, in policy order")


def _validate_comparison_report(document: dict[str, Any]) -> None:
    """Check that a comparison names two systems and lines their slices up; not that the numbers hold.

    The embedded policy is valid, the baseline and candidate are different systems, and in every view
    both systems and the differences carry the same slices in the same order.
    """
    validate_document("aggregation-policy", document["policy"])
    if document["baseline"]["system_id"] == document["candidate"]["system_id"]:
        raise ContractError("a comparison names two different systems")
    _unique([run["run_id"] for run in document["runs"]], "runs.run_id")
    _unique([f"{view['mode']}/{view['profile']}" for view in document["views"]], "views (mode, profile)")
    for view in document["views"]:
        keys = []
        for side in ("baseline", "candidate"):
            slices = view["systems"][side]["slices"]
            _check_slices(slices, document["policy"]["views"])
            keys.append([block["slice"] for block in slices])
        keys.append([block["slice"] for block in view["differences"]])
        if not keys[0] == keys[1] == keys[2]:
            raise ContractError("the baseline, the candidate, and the differences cover different slices")


# --- precision sampling and review ---------------------------------------------------------------


# The one stratum of an unstratified precision sample.
PRECISION_SINGLE_STRATUM = "all"


def precision_stratum(unit: dict[str, Any], stratify_by: str | None) -> str:
    """The stratum a precision frame unit falls in when a sample is stratified by *stratify_by*.

    One definition, read by :mod:`scaneval.precision` when it draws and by the sample contract when
    it checks the recorded strata, so the two cannot disagree about where a unit belongs.
    """
    if stratify_by is None:
        return PRECISION_SINGLE_STRATUM
    return {"system": unit["system_id"], "input": unit["input_id"], "kind": unit["claim"]["kind"]}[stratify_by]


def precision_exclusions(invocations: list[dict[str, Any]]) -> dict[str, Any]:
    """What a precision frame leaves out, summed from its invocation rows, one entry per reason.

    ``no_output`` counts assignments that delivered nothing (skipped, or never recorded);
    ``unranked`` and ``bundle_unresolved`` count the invocations a ``first_b`` population leaves out
    because their claims have no measured native position, with the claims and units they hold;
    ``beyond_budget`` counts the units and copies of included invocations that lie past B.
    """
    out: dict[str, Any] = {
        "no_output": {"invocations": 0},
        "unranked": {"invocations": 0, "claim_records": 0, "units": 0},
        "bundle_unresolved": {"invocations": 0, "claim_records": 0, "units": 0},
        "beyond_budget": {"units": 0, "copies": 0},
    }
    for row in invocations:
        state = row["state"]
        if state == "no_output":
            out["no_output"]["invocations"] += 1
        elif state == "included":
            out["beyond_budget"]["units"] += row["units"] - row["population_units"]
            out["beyond_budget"]["copies"] += row["claim_records"] - row["population_copies"]
        else:
            out[state]["invocations"] += 1
            out[state]["claim_records"] += row["claim_records"]
            out[state]["units"] += row["units"]
    return out


def _precision_state(row: dict[str, Any], first_b: bool) -> str:
    """The population state an invocation row's own output fields call for."""
    if row["result_sha256"] is None:
        return "no_output"
    if first_b and row["ranking"] != "native":
        return "unranked"
    if first_b and not row["bundles_resolved"]:
        return "bundle_unresolved"
    return "included"


def _validate_precision_frame(frame: dict[str, Any]) -> None:
    """Check that a precision frame's units, invocation rows, and exclusion totals agree."""
    population = frame["population"]
    first_b = population["name"] == "first_b"
    if first_b != (population["budget"] is not None):
        raise ContractError("frame.population.budget is set exactly when the population is first_b")
    _unique([run["run_id"] for run in frame["runs"]], "frame.runs.run_id")
    runs = {run["run_id"] for run in frame["runs"]}
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for row in frame["invocations"]:
        key = (row["run_id"], row["invocation_id"])
        label = f"frame.invocations {key[0]}/{key[1]}"
        if key in rows:
            raise ContractError(f"{label} is listed twice")
        if row["run_id"] not in runs or row["system_id"] not in population["systems"]:
            raise ContractError(f"{label} names a run or a system outside this frame's population")
        state = _precision_state(row, first_b)
        if row["state"] != state:
            raise ContractError(f"{label} records state {row['state']}, but its output calls for {state}")
        empty = row["state"] == "no_output"
        if empty != (row["ranking"] is None) or empty != (row["bundles_resolved"] is None) \
                or empty != (row["input_hash"] is None) or (empty and row["claim_records"]):
            raise ContractError(f"{label}: an assignment with no output records no result fields, and "
                                "one with output records all of them")
        if not row["population_units"] <= row["units"] <= row["claim_records"] \
                or row["population_copies"] > row["claim_records"]:
            raise ContractError(f"{label}: its population counts exceed the claims it delivered")
        rows[key] = row
    unit_ids = [unit["unit_id"] for unit in frame["units"]]
    _unique(unit_ids, "frame.units.unit_id")
    if unit_ids != sorted(unit_ids):
        raise ContractError("frame.units must be sorted by unit_id")
    counted: dict[tuple[str, str], tuple[int, int]] = {}
    for unit in frame["units"]:
        label = f"frame unit {unit['unit_id']}"
        if unit["unit_id"] != f"{unit['run_id']}/{unit['invocation_id']}/{unit['claim_ids'][0]}":
            raise ContractError(f"{label} is not named <run_id>/<invocation_id>/<first claim id>")
        if unit["delivered_copies"] != len(unit["claim_ids"]) \
                or unit["population_copies"] > unit["delivered_copies"]:
            raise ContractError(f"{label}: its copy counts do not match the claims it lists")
        key = (unit["run_id"], unit["invocation_id"])
        row = rows.get(key)
        if row is None or row["state"] != "included" \
                or (row["system_id"], row["input_id"]) != (unit["system_id"], unit["input_id"]):
            raise ContractError(f"{label} does not come from an included invocation of this frame")
        if (row["ranking"] == "native") != (unit["first_rank"] is not None):
            raise ContractError(f"{label}: a first rank is recorded exactly for native output")
        if first_b and unit["first_rank"] > population["budget"]:
            raise ContractError(f"{label} lies past B={population['budget']}, outside the first_b population")
        found, copies = counted.get(key, (0, 0))
        counted[key] = (found + 1, copies + unit["population_copies"])
    for key, row in rows.items():
        if (row["population_units"], row["population_copies"]) != counted.get(key, (0, 0)):
            raise ContractError(f"frame.invocations {key[0]}/{key[1]}: its population counts are not "
                                "the units the frame lists for it")
    if frame["exclusions"] != precision_exclusions(frame["invocations"]):
        raise ContractError("frame.exclusions is not the sum of the invocation rows it summarizes")


def _validate_precision_sample(document: dict[str, Any]) -> None:
    """Check that a precision sample agrees with its own frame; it says nothing about any claim.

    The frame hashes to the recorded ``frame_sha256``, and every count the sample records is one its
    frame and selection hold: each unit is named ``<run_id>/<invocation_id>/<first claim id>``,
    comes from an included invocation of its frame, and lies inside the population (at native rank
    at most B for ``first_b``); per-invocation counts and the exclusion totals are the sums of the
    rows they summarize; each stratum's population and sample sizes are the units and selected units
    that fall in it (:func:`precision_stratum`), and its inclusion probability is their ratio; a
    stratum that drew nothing is listed as uncovered; and every population system has one alias.
    Whether the selection is the one the recorded seed draws is checked by
    :func:`scaneval.precision.verify_sample`, which can re-draw it. Nothing here reads a run.
    """
    frame = document["frame"]
    if canonical_sha256(frame) != document["frame_sha256"]:
        raise ContractError("frame_sha256 does not hash the frame this sample carries; the frame was "
                            "edited after the sample was drawn")
    _validate_precision_frame(frame)
    design = document["design"]
    stratified = design["stratify_by"] is not None
    if (design["method"] == "stratified_srswor") != stratified or stratified != (design["allocation"] is not None):
        raise ContractError("design: a stratified_srswor design names what it stratifies by and its "
                            "allocation, and an srswor design names neither")
    stratum_of = {unit["unit_id"]: precision_stratum(unit, design["stratify_by"]) for unit in frame["units"]}
    population_counts: dict[str, int] = {}
    for stratum in stratum_of.values():
        population_counts[stratum] = population_counts.get(stratum, 0) + 1
    selected_ids = [entry["unit_id"] for entry in document["selected"]]
    _unique(selected_ids, "selected.unit_id")
    _unique([entry["item_id"] for entry in document["selected"]], "selected.item_id")
    if selected_ids != sorted(selected_ids):
        raise ContractError("selected must be sorted by unit_id")
    sample_counts: dict[str, int] = {}
    for entry in document["selected"]:
        if stratum_of.get(entry["unit_id"]) != entry["stratum"]:
            raise ContractError(f"selected unit {entry['unit_id']} is not a unit of stratum "
                                f"{entry['stratum']} in this frame")
        sample_counts[entry["stratum"]] = sample_counts.get(entry["stratum"], 0) + 1
    if design["size"] != len(selected_ids):
        raise ContractError(f"design.size is {design['size']}, but {len(selected_ids)} units are selected")
    names = [row["stratum"] for row in document["strata"]]
    if names != sorted(population_counts):
        raise ContractError("strata must list every stratum that holds a unit, once each, sorted by name")
    for row in document["strata"]:
        name = row["stratum"]
        sampled = sample_counts.get(name, 0)
        if (row["population_units"], row["sampled_units"]) != (population_counts[name], sampled):
            raise ContractError(f"stratum {name} records {row['sampled_units']} of {row['population_units']} "
                                f"units, but the frame and selection hold {sampled} of {population_counts[name]}")
        if row["inclusion_probability"] != sampled / population_counts[name]:
            raise ContractError(f"stratum {name}: the inclusion probability must be sampled/population units")
    if document["uncovered_strata"] != [row["stratum"] for row in document["strata"] if not row["sampled_units"]]:
        raise ContractError("uncovered_strata must list exactly the strata that drew no unit, sorted by name")
    aliases = document["blinding"]["system_aliases"]
    if [row["system_id"] for row in aliases] != sorted(frame["population"]["systems"]):
        raise ContractError("blinding.system_aliases must give every population system one alias, "
                            "sorted by system id")
    _unique([row["alias"] for row in aliases], "blinding.system_aliases.alias")


def _validate_precision_reviews(document: dict[str, Any]) -> None:
    """Check that a precision review history is a chain that ends where it says it ends.

    Every entry names its reviewer by the :func:`is_stated` rule and carries the chain value of its
    own fields and of the entry before it (:func:`chain_link_gap`, kind ``precision_review``), and
    ``reviews_sha256`` is the chain value of the last entry, present exactly when there is one, so an
    entry edited, reordered, or deleted anywhere, the end included, is refused. A history wiped whole
    and saved with no head reads as a fresh one; an estimate records the digest of the history it
    used, which is where such a wipe shows. That the history belongs to a given sample and names
    only units it drew is checked by :mod:`scaneval.precision` against that sample. Like every
    recorded review here, this is not a signature: it says nothing about who typed an entry or
    whether they read the claim.
    """
    reviews = document["reviews"]
    for index, entry in enumerate(reviews):
        if not is_stated(entry["reviewer"]):
            raise ContractError(f"a precision review must name its reviewer; reviews[{index}].reviewer is blank")
    gap, head = chain_link_gap(reviews, kind="precision_review", label="reviews")
    if gap:
        raise ContractError(gap)
    recorded = document["reviews_sha256"]
    if recorded == head:
        return
    if head is None:
        raise ContractError(f"reviews_sha256 records {recorded}, but no review is recorded; the history "
                            "it names was deleted whole")
    if recorded is None:
        raise ContractError("reviews_sha256 is missing, so nothing says where the recorded history ends "
                            "and a review deleted from the end of it would leave no trace")
    raise ContractError(f"reviews_sha256 records {recorded}, but the recorded history ends at {head}; a "
                        "review was deleted from the end of it")


def _validate_precision_estimate(document: dict[str, Any]) -> None:
    """Check the estimate's shape rules; its numbers are recomputed by :mod:`scaneval.precision`, not here.

    The sensitivity range is present or absent as a whole and ordered, the interval carries bounds
    exactly in the states that have them and names its insufficient strata exactly when it is
    insufficient, coverage cannot exceed the population, and every sampled unit appears once.
    """
    lower, upper = document["sensitivity"]["lower"], document["sensitivity"]["upper"]
    if (lower is None) != (upper is None) or (lower is not None and lower > upper):
        raise ContractError("sensitivity: lower and upper are both present and ordered, or both null")
    interval = document["interval"]
    bounded = interval["state"] in ("ok", "census")
    if bounded != (interval["lower"] is not None and interval["upper"] is not None) \
            or (not bounded and (interval["lower"] is not None or interval["upper"] is not None)):
        raise ContractError(f"interval: bounds are recorded exactly in the ok and census states, and this "
                            f"one is {interval['state']}")
    if bounded and interval["lower"] > interval["upper"]:
        raise ContractError("interval: lower must not exceed upper")
    if (interval["state"] == "insufficient") != bool(interval["insufficient_strata"]):
        raise ContractError("interval: insufficient_strata is named exactly when the interval is insufficient")
    coverage = document["coverage"]
    if coverage["covered_units"] > coverage["population_units"]:
        raise ContractError("coverage: covered_units cannot exceed population_units")
    _unique([unit["unit_id"] for unit in document["units"]], "units.unit_id")
    if document["sample"]["selected_units"] != len(document["units"]):
        raise ContractError("sample.selected_units must equal the number of units resolved")


# --- promotion gate decisions ---------------------------------------------------------------------


# The requirement blocks a gate policy may declare, in the order a decision lists them. A policy always
# declares primary and configuration; every other block is a requirement it makes only by writing it.
GATE_BLOCKS = ("primary", "configuration", "regressions", "precision", "controls", "completion",
               "target_coverage", "burden", "cost")
GATE_CONTROL_CLASSES = ("capability_safe", "fixed_target")
# The only metrics a gate reads for detection: measured known-target recall. Whatever else the
# comparison reports about detection is a diagnostic, or is not read by a gate at all.
GATE_METRICS = ("full_recall", "recall_at_budget")
# Names a comparison or the math gives a diagnostic. A policy naming one is told so, rather than
# only that its metric is not one of two.
_GATE_DIAGNOSTICS = frozenset({
    "random_order_diagnostic", "run_variability", "leave_one_project_out", "first_hit_ranks",
    "targets_per_input", "claims", "usage"})


def gate_declared_blocks(policy: dict[str, Any]) -> list[str]:
    """The requirement blocks *policy* declares, in the order a decision lists them."""
    return [name for name in GATE_BLOCKS if name in policy]


def gate_requirement_ids(policy: dict[str, Any]) -> list[str]:
    """Every requirement id a decision under *policy* must carry, in decision order.

    The ids follow from the policy alone, never from what a comparison holds, so a decision that
    drops a requirement its policy declares (a failed one, say) is refused by
    :func:`_validate_gate_decision`, and :mod:`scaneval.gate` evaluates exactly these, in this order.
    The first five are always there; each other block adds what it declares.
    """
    ids = ["contract.shared", "contract.runs_completed", "configuration.allowed_differences",
           "evidence.scope", "primary.improvement"]
    if "uncertainty" in policy["primary"]:
        ids.append("primary.uncertainty")
    ids += [f"regression.{entry['id']}" for entry in policy.get("regressions", [])]
    if "precision" in policy:
        precision = policy["precision"]
        ids += ["precision.binding", "precision.min_value", "precision.max_unresolved_share",
                "precision.min_evidence_grade"]
        ids += [f"precision.{name}" for field, name in (
            ("min_coverage", "min_coverage"), ("min_interval_lower_bound", "interval"),
            ("max_decrease_vs_baseline", "max_decrease")) if field in precision]
    for name in GATE_CONTROL_CLASSES:
        if name in policy.get("controls", {}):
            ids += [f"controls.{name}.{check}" for check in
                    ("false_alarm_upper", "completed_mass", "assessable_mass")]
    completion = policy.get("completion", {})
    ids += [f"completion.{name}" for name in ("min", "max_decrease") if name in completion]
    if "target_coverage" in policy:
        ids.append("target_coverage.min_assessable_mass")
    burden = policy.get("burden", {})
    ids += [f"burden.{name}" for field, name in (
        ("max_claims_per_assignment", "claims_per_assignment"), ("max_duplicate_share", "duplicate_share"),
        ("max_increase_ratio", "increase_ratio")) if field in burden]
    cost = policy.get("cost")
    if cost is not None:
        ids.append("cost.coverage")
        ids += [f"cost.{name}" for field, name in (
            ("max_per_assignment_usd", "per_assignment"), ("max_increase_ratio", "increase_ratio"))
            if field in cost]
    return ids


def _gate_metric(metric: dict[str, Any], where: str) -> None:
    """Refuse a gate metric that is not measured known-target recall, naming a diagnostic as one."""
    kind = metric["kind"]
    if kind == "recall_at_budget":
        if "budget" not in metric:
            raise ContractError(f"{where}: recall_at_budget names the budget B it reads")
    elif kind == "full_recall":
        if "budget" in metric:
            raise ContractError(f"{where}: full_recall takes no budget")
    elif "random" in kind.lower():
        raise ContractError(
            f"{where}: {kind!r} is a random-order expectation, a diagnostic over an order the system never "
            "chose and never a promotion metric; use full_recall or recall_at_budget")
    elif kind in _GATE_DIAGNOSTICS:
        raise ContractError(
            f"{where}: {kind!r} is a diagnostic, not a promotion metric; use full_recall or recall_at_budget")
    else:
        raise ContractError(f"{where}: {kind!r} is not a metric a gate reads; use full_recall or recall_at_budget")


def _gate_slice(slice_: dict[str, Any], where: str, *, single: bool) -> None:
    """The whole view has no value; a project or workload slice names one unless it may cover each."""
    value = slice_.get("value")
    if slice_["dimension"] == "all":
        if value is not None:
            raise ContractError(f"{where}: the whole-view slice has no value")
    elif value is None and single:
        raise ContractError(f"{where}: a {slice_['dimension']} slice names which {slice_['dimension']} it is")


def _validate_gate_policy(document: dict[str, Any]) -> None:
    """Check that a policy's requirements can be read; it says nothing about their merit.

    The primary metric and every regression's metric must be measured known-target recall: a
    random-order expectation or any other diagnostic is refused here, by name, so no policy can ask a
    decision to rest on one. The primary metric names one slice, regression ids are unique, a budget
    is named exactly for recall_at_budget and for the first_b population, and a precision interval
    bound is asked of resolved precision only, the one figure that has an interval.
    """
    primary = document["primary"]
    _gate_metric(primary["metric"], "primary.metric")
    _gate_slice(primary.get("slice", {"dimension": "all"}), "primary.slice", single=True)
    regressions = document.get("regressions", [])
    _unique([entry["id"] for entry in regressions], "regressions.id")
    for entry in regressions:
        _gate_metric(entry["metric"], f"regressions[{entry['id']}].metric")
        _gate_slice(entry.get("slice", {"dimension": "all"}), f"regressions[{entry['id']}].slice", single=False)
    precision = document.get("precision")
    if precision is not None:
        if (precision["population"]["name"] == "first_b") != ("budget" in precision["population"]):
            raise ContractError("precision.population: a budget is named exactly for the first_b population")
        if precision["basis"] != "resolved" and "min_interval_lower_bound" in precision:
            raise ContractError("precision.min_interval_lower_bound: only resolved precision has an interval")


def _validate_gate_decision(document: dict[str, Any]) -> None:
    """Check that a decision is derived from what it records; the requirements are not recomputed here.

    The embedded policy is a valid gate policy and hashes to ``policy_sha256``. The requirements are
    exactly the ones the policy declares (:func:`gate_requirement_ids`), in order, so a decision cannot
    leave out one that failed. The outcome, the failed and unresolved lists, and the counts follow from
    the requirement statuses, the declared and undeclared blocks from the policy, and the
    recommendation scope from the policy's required scope and the evidence-scope requirement. Nothing
    here reads a comparison or an estimate: :func:`scaneval.gate.evaluate_gate` is what decides, and a
    replay of it is what checks a decision against the documents it names.
    """
    policy = document["policy"]
    validate_document("gate-policy", policy)
    if document["policy_sha256"] != canonical_sha256(policy):
        raise ContractError("policy_sha256 does not hash the policy this decision carries")
    requirements = document["requirements"]
    ids = [requirement["id"] for requirement in requirements]
    if ids != gate_requirement_ids(policy):
        raise ContractError("the requirements must be exactly the ones the embedded policy declares, in order")
    statuses = [requirement["status"] for requirement in requirements]
    outcome = "fail" if "fail" in statuses else "inconclusive" if "inconclusive" in statuses else "pass"
    if document["outcome"] != outcome:
        raise ContractError(f"outcome is {document['outcome']}, but the requirement statuses give {outcome}")
    for field, status in (("failed", "fail"), ("unresolved", "inconclusive")):
        if document[field] != [requirement["id"] for requirement in requirements
                               if requirement["status"] == status]:
            raise ContractError(f"{field} must list the {status} requirements, in decision order")
    summary = document["summary"]
    counts = {"requirements": len(requirements), "passed": statuses.count("pass"),
              "failed": statuses.count("fail"), "inconclusive": statuses.count("inconclusive")}
    if summary != counts:
        raise ContractError(f"summary must count the requirements ({counts}), not {summary}")
    declared = gate_declared_blocks(policy)
    blocks = document["blocks"]
    if blocks["declared"] != declared or blocks["not_declared"] != [
            name for name in GATE_BLOCKS if name not in declared]:
        raise ContractError("blocks must list the policy's declared and undeclared requirement blocks")
    if document["view"] != policy["view"]:
        raise ContractError("view must be the policy's view")
    if document["comparison"]["baseline"]["system_id"] == document["comparison"]["candidate"]["system_id"]:
        raise ContractError("a decision names two different systems")
    evidence = requirements[ids.index("evidence.scope")]
    expected = ("none" if evidence["status"] != "pass" else
                "reviewed" if policy.get("required_scope", "reviewed") == "reviewed" else "development")
    if document["recommendation_scope"] != expected:
        raise ContractError(f"recommendation_scope is {document['recommendation_scope']}, but the evidence "
                            f"requirement and the policy's required scope give {expected}")


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
    # Kinds first published at 2.1, one per feature.
    "evaluation-schedule": _validate_evaluation_schedule,
    "blinding-map": _validate_blinding_map,
    # SARIF import (profile sarif-import-1).
    "import-record": _validate_import_record,
    # Corpus aggregation and paired comparison.
    "aggregation-policy": _validate_aggregation_policy,
    "aggregate-report": _validate_aggregate_report,
    "comparison-report": _validate_comparison_report,
    # Precision sampling and review.
    "precision-sample": _validate_precision_sample,
    "precision-reviews": _validate_precision_reviews,
    "precision-estimate": _validate_precision_estimate,
    # Promotion gate decisions.
    "gate-policy": _validate_gate_policy,
    "gate-decision": _validate_gate_decision,
}


def validate_document(kind: str, document: dict[str, Any]) -> dict[str, Any]:
    """Validate and return *document* unchanged.

    JSON Schema checks the language-neutral shape. Runtime checks enforce invariants
    that depend on multiple fields or on portable path semantics.
    """

    if not isinstance(document, dict):
        raise ContractError("contract document must be a JSON object")
    reject_nonfinite(document)
    # The version is read before a schema is chosen, and a version this build does not read is
    # refused rather than validated against another version's rules: a record is only ever checked
    # against the contract it says it was written to.
    version = document.get("schema_version")
    versions = SCHEMA_VERSIONS.get(kind)
    if versions is not None and (not isinstance(version, str) or version not in versions):
        raise ContractError(
            f"schema_version: {version!r} is not a {kind} version this build reads; supported: "
            f"{', '.join(versions)}")
    validator = Draft202012Validator(_schema(kind, version))
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
