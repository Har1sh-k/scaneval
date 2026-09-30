"""Metadata blinding: a reviewed map of identity tokens, applied to documentation and display text.

The ``metadata_blinded`` input profile (``docs/DESIGN_DECISIONS.md``, configurable identity
profiles) reduces selected identity cues in an exported snapshot: branding, documentation
identifiers, and display metadata. It never renames a package, module, import, source identifier,
or path, and never changes a dependency, executable logic, or build, CI, or security
configuration. It is partial blinding: package names and recognizable code may still reveal the
repository, and every export records which cues remain. It is not anonymization and not a defence
against memorization.

The map. A blinding map (contract kind ``blinding-map``) is evaluator-side data and never enters a
scanner workspace. It declares pseudonyms (an original token and its replacement), the snapshot
variants it covers, each pinned by commit and export tree hash, and its edits: one file each, a
stated role and rationale, the originals replaced there, and for every variant either the exact
file hash and occurrence count expected or that the file is absent. One map covers every variant
of one repository, so a vulnerable and a fixed snapshot are blinded with the same pseudonyms.

Approval. A map is applied only when its latest recorded review approves the map's content as it
stands now. Reviews are a chain (:func:`scaneval.contracts.chain_digest`, kind
``blinding_review``) whose end the map records in ``reviews_sha256``, and each review binds
:func:`content_digest`, the map without its review history. An unreviewed map, one whose latest
review rejected it or reopened the question, and one edited after the approval its latest review
recorded are all refused. The tool records the reviewer name a person supplies and never supplies
one. Like every chain in this package, this makes a quiet deletion visible; it is not a signature.

This module holds the map as a document: loading and saving it, its digests and the identity other
records carry, its review history, and whether it is approved. Nothing here applies a map to an
export yet.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Callable

from .contracts import (
    ContractError,
    canonical_sha256,
    chain_digest,
    is_stated,
    load_document,
    validate_document,
)


MAP_KIND = "blinding-map"
# The version of the map contract.
SCHEMA_VERSION = "2.1"
# The chain kind of a map review, so a map review can never be replayed as a case review.
REVIEW_KIND = "blinding_review"
# These mirror the blinding-map contract enums; the schema stays authoritative.
REVIEW_ROLES = ("curator", "independent_reviewer")
REVIEW_DECISIONS = ("approve", "reject", "unresolved")


def _now(clock: Callable[[], datetime] | None) -> str:
    moment = (clock or (lambda: datetime.now(timezone.utc)))()
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


# --- the map as a document ---------------------------------------------------------------------


def load_map(path: str | os.PathLike[str]) -> dict:
    """Load and validate one blinding map. Approval is not asked here; applying the map asks it."""
    return load_document(path, MAP_KIND)


def save_map(path: Path, document: dict) -> None:
    """Validate *document* and write it to *path* as indented JSON, as a pack is written."""
    validate_document(MAP_KIND, document)
    Path(path).write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def content_digest(document: dict) -> str:
    """What a review approves: the canonical digest of the map without its review history."""
    return canonical_sha256({key: value for key, value in document.items()
                             if key not in ("reviews", "reviews_sha256")})


def map_sha256(document: dict) -> str:
    """The canonical digest of the whole map, reviews included: which map document was used."""
    return canonical_sha256(document)


def map_identity(document: dict) -> dict:
    """The identity plans, schedules, and execution records carry; the map itself stays here."""
    return {"map_id": document["map_id"], "map_version": document["map_version"],
            "map_sha256": map_sha256(document)}


def _named(document: dict) -> str:
    return f"map {document['map_id']} {document['map_version']}"


def approval_gap(document: dict) -> str | None:
    """Why *document* may not be applied as it stands, or ``None`` when its latest review approves it.

    The latest recorded review is the operative one, as it is for a case: a rejection and an
    unresolved reopening both withdraw an earlier approval, and an approval covers the content
    digest it recorded, so a map edited afterwards is unapproved until a review covers the edit.
    The chain itself is verified when the map is loaded; this reads what it records.
    """
    reviews = document["reviews"]
    if not reviews:
        return f"{_named(document)} is unreviewed: no review is recorded"
    latest = reviews[-1]
    who = f"{latest['reviewer']} ({latest['role']}) at {latest['at']}"
    if latest["decision"] == "reject":
        return f"{_named(document)} was rejected by {who}"
    if latest["decision"] == "unresolved":
        return f"{_named(document)} was reopened by {who}, so it is not approved"
    current = content_digest(document)
    if latest["content_sha256"] != current:
        return (f"{_named(document)}: the latest approval, by {who}, covers content "
                f"{latest['content_sha256']}, but the map now hashes to {current}; it was edited "
                "after it was approved")
    return None


def approving_reviews(document: dict) -> list[dict]:
    """The approvals standing behind the map as it is now: after its last withdrawal, of this content."""
    current = content_digest(document)
    standing: list[dict] = []
    for review in document["reviews"]:
        if review["decision"] != "approve":
            standing = []
        elif review["content_sha256"] == current:
            standing.append({"reviewer": review["reviewer"], "role": review["role"], "at": review["at"]})
    return standing


def record_review(document: dict, *, reviewer: str, role: str, decision: str, note: str,
                  clock: Callable[[], datetime] | None = None) -> dict:
    """Append one review of the map as it stands, chained to the review before it; return it.

    The reviewer is the name the caller supplies; a blank one is refused and none is ever
    supplied here. The review binds :func:`content_digest` of the map at this moment, so an
    approval says exactly which content was approved. The decision is recorded as made: nothing
    here checks the map against an export first. A refused review leaves *document* exactly as it
    was; a recorded one replaces its contents.
    """
    validate_document(MAP_KIND, document)
    if not is_stated(reviewer):
        raise ContractError("a map review must name its reviewer; the tool never supplies one")
    if role not in REVIEW_ROLES:
        raise ContractError(f"review role must be one of {', '.join(REVIEW_ROLES)}, not {role!r}")
    if decision not in REVIEW_DECISIONS:
        raise ContractError(f"review decision must be one of {', '.join(REVIEW_DECISIONS)}, not {decision!r}")
    candidate = copy.deepcopy(document)
    entry = {"reviewer": reviewer, "role": role, "decision": decision, "at": _now(clock), "note": note,
             "content_sha256": content_digest(candidate)}
    previous = candidate["reviews"][-1]["chain_sha256"] if candidate["reviews"] else None
    entry["chain_sha256"] = chain_digest(previous, entry, REVIEW_KIND)
    candidate["reviews"].append(entry)
    candidate["reviews_sha256"] = entry["chain_sha256"]
    validate_document(MAP_KIND, candidate)
    document.clear()
    document.update(candidate)
    return entry
