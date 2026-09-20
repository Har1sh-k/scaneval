"""Evaluator-side review workflow: candidate routing, a draft decisions file, recorded approval.

Routing proposes candidates by accepted location path only. It does not read claim
prose, compare line ranges, weigh severities, or establish a root cause, and it decides
nothing: every decision this module produces is ``unresolved``, so a draft can never
earn detection credit, a rejection, or a quiet control. Only :func:`approve_review`,
called with a reviewer name supplied by the caller, records a human review; no path here
infers approval from a passing check, a matching hash, or the absence of an objection.

A review record is an evaluator-side sidecar. :mod:`scaneval.scoring` never reads it,
so it cannot raise a draft into evidence, and it is not a signature, an identity check,
or proof that the named reviewer saw the decisions. Pack material stays here: nothing in
this module writes into a scanner workspace or copies accepted locations into a bundle.

The bindings enforced here are document-to-document hashes: a plan, a decisions file, a
review record, and a saved result agree with each other or a call is refused. Matching
hashes say nothing about the input tree, the scanner run, the pack's evidence, or whether
a human read anything.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from datetime import datetime, timezone
import os
from os import PathLike
from pathlib import Path
import posixpath
import tempfile
from typing import Any, Callable, Iterable

# _is_stated is imported rather than re-implemented so a reviewer name is judged by one rule
# across the tool: what corpus approve refuses, review approve refuses the same way.
from .cases import _is_stated, accepted_paths_for_targets, pack_sha256
from .contracts import ContractError, canonical_json, canonical_sha256, load_document, validate_document


PLAN_KIND = "evaluation-plan"
RESULT_KIND = "scan-result"
DECISIONS_KIND = "review-decisions"
RECORD_KIND = "review-record"

EVALUATOR_DIR = "evaluator"
PLAN_FILE = "plan.json"
DECISIONS_FILE = "decisions.json"
RECORD_FILE = "review-record.json"
RESULT_FILE = "result.json"

# The only decision a machine may write. Every other value in either contract states a
# human conclusion: accepted/rejected for a claim, false_allegation/quiet for a control.
DRAFT_DECISION = "unresolved"
HUMAN_DECISIONS = frozenset({"accepted", "rejected", "false_allegation", "quiet"})
CANDIDATE_REASON = "candidate by accepted location path; pending human review"
PENDING_REASON = "pending human review"

INPUT_MISMATCH = "the decisions and the plan bind to different input hashes"
RUN_MISMATCH = "the decisions and the review record name different runs"
PACK_MISMATCH = "the routing pack is not the pack the plan was built from"
RECORD_CURRENT = "the existing review record already binds to these decisions and plan"


def _now(clock: Callable[[], datetime] | None) -> str:
    moment = (clock or (lambda: datetime.now(timezone.utc)))()
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _normalize(path: str) -> str:
    """Compare paths the way :mod:`scaneval.scoring` fingerprints them, not by resolving them.

    This is textual: no symlink, case, or filesystem lookup happens, so two spellings of
    the same file on disk can still compare as different paths.
    """
    return posixpath.normpath(path.replace("\\", "/"))


def _write_new(path: Path, content: str) -> None:
    # Refuse overwrite, including symlinks, rather than destroy a prior review.
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _keep_mode(temporary: Path, existing: Path) -> None:
    """Give *temporary* the permissions of the regular file it is about to replace.

    A temporary file is created owner-only, so a replacement that skipped this would quietly
    narrow who can read the document. Bits are copied only when *existing* is a regular file
    that is not a symlink: when the name reaches a symlink, a directory, or nothing at all, the
    replacement keeps the owner-only mode of the temporary file rather than adopting the mode of
    whatever that name currently leads to. This copies permission bits only, not ownership, and
    not any access control the filesystem keeps elsewhere. :mod:`scaneval.cli` calls this same
    function before it renames a pack into place, so a replaced pack and a replaced review
    record follow exactly this rule, symlinked paths included.
    """
    if existing.is_file() and not existing.is_symlink():
        os.chmod(temporary, existing.stat().st_mode & 0o777)


def _refuse_symlinked_dirs(bundle_dir: str | PathLike[str]) -> Path:
    """Refuse a bundle reached through a symlink, and return it as a :class:`~pathlib.Path`.

    Three spellings are refused: a symlinked bundle directory, a symlinked ``evaluator``
    directory inside it, and a bundle whose resolved path differs from its absolute path,
    which is how a symlink higher up the path shows itself. This keeps a write from landing
    outside the directory the caller named. It refuses those three spellings and nothing
    else: it is not an isolation boundary and says nothing about hard links, bind mounts, a
    directory swapped after the check, or where the files a bundle already holds point.

    A ``..`` segment survives into the absolute form and is removed by resolution, so a path
    spelled with one is refused by the third check as well; the message names both causes
    because this cannot tell them apart. A ``.`` segment is dropped when the path is built,
    so it is not refused. The reading functions here accept ``guard_symlinks=False``, which
    skips this check entirely; that belongs to a caller that resolved the path itself.
    """
    bundle = Path(bundle_dir)
    for directory in (bundle, bundle / EVALUATOR_DIR):
        if directory.is_symlink():
            raise ContractError(f"refusing to write through a symlinked directory at {directory}")
    if bundle.resolve() != bundle.absolute():
        raise ContractError(
            f"refusing to use {bundle}: it does not resolve to itself (a symlink or a .. segment "
            f"in the path); it leads to {bundle.resolve()}; name the bundle by its real path")
    return bundle


def _bundle_path(bundle_dir: str | PathLike[str], guard_symlinks: bool) -> Path:
    """The bundle as a :class:`~pathlib.Path`, guarded against symlinked spellings or not.

    With the guard off the path is used exactly as given, symlinks and all. That is for a
    read whose caller has already resolved the path; it is never right for a write, which is
    why every writing function here keeps the guard.
    """
    return _refuse_symlinked_dirs(bundle_dir) if guard_symlinks else Path(bundle_dir)


def _replace_document(path: Path, document: dict) -> None:
    """Replace one document atomically through a temporary file in its own directory.

    This is the only overwrite in this module, and :mod:`scaneval.cli` routes ``review
    approve`` through it, so every replacement of a review record behaves the same way. It does
    not merge, keep a backup, or copy the previous version anywhere, and it replaces a symlink
    sitting at *path* rather than writing through it. Permission bits are carried over by
    :func:`_keep_mode`, which copies them from a regular file and from nothing else.
    """
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=str(path.parent),
        prefix=path.name + ".", suffix=".tmp", delete=False,
    )
    try:
        with handle:
            handle.write(_document(document))
        _keep_mode(Path(handle.name), path)
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise


def _document(value: dict) -> str:
    return canonical_json(value) + "\n"


def _assert_draft_only(decisions: dict) -> dict:
    """Guard the one invariant this module exists for; a drafted verdict is a bug, not a fallback."""
    for match in decisions["claim_matches"]:
        if match["decision"] in HUMAN_DECISIONS:
            raise ContractError(f"drafted claim decisions must stay {DRAFT_DECISION!r}")
    for assessment in decisions["control_assessments"]:
        if assessment["decision"] in HUMAN_DECISIONS:
            raise ContractError(f"drafted control decisions must stay {DRAFT_DECISION!r}")
    return decisions


def _assert_binds_to_plan(plan: dict, decisions: dict) -> None:
    if decisions["input_hash"] != plan["input_hash"]:
        raise ContractError(INPUT_MISMATCH)


def _assert_binds_to_result(bundle: Path, decisions: dict) -> None:
    """Refuse decisions that do not bind to the ``result.json`` beside *bundle*'s evaluator dir.

    A bundle holding no ``result.json`` is not checked: nothing here fetches one, and this
    compares two saved documents, so agreement says the decisions were filed against these
    exact result bytes and nothing about the scan that produced them. Both the re-draft in
    :func:`record_decisions` and ``review approve`` in :mod:`scaneval.cli` call it, so
    neither writes a record against a result edited after the decisions were filed.
    """
    result_path = bundle / RESULT_FILE
    if not result_path.is_file():
        return
    result = load_document(result_path, RESULT_KIND)
    if decisions["result_sha256"] != canonical_sha256(result):
        raise ContractError(
            f"the decisions were filed against a different result than {result_path}")
    if decisions["run_id"] != result["run_id"]:
        raise ContractError(f"the decisions and {result_path} name different runs")


def draft_decisions(plan: dict, result: dict, pack: dict | None = None, *,
                    clock: Callable[[], datetime] | None = None) -> dict:
    """Route saved claims to plan targets as unresolved candidates, bound to *result*.

    A candidate means only that the claim's primary location path is an accepted location
    path of that target. Path equality is not an allegation: the same file can hold a
    different issue, and a real hit elsewhere in the target is left unrouted rather than
    guessed. Claims are never rejected here, so an empty draft is not evidence of absence.

    With *pack* omitted there are no candidates at all; the pack is read only through
    :func:`scaneval.cases.accepted_paths_for_targets` and is not re-validated here. When
    the plan carries provenance, a supplied pack must hash to the ``pack_sha256`` the plan
    was built from; that compares documents, not the evidence or reviews inside them, and a
    plan without provenance is not checked at all. ``clock`` is accepted so one clock can be
    threaded through the whole workflow, but the review-decisions contract carries no
    timestamp, so this function does not use it.
    """
    validate_document(PLAN_KIND, plan)
    validate_document(RESULT_KIND, result)
    if plan["input_hash"] != result["input_hash"]:
        raise ContractError("plan and result must bind to the same input hash")
    provenance = plan.get("provenance")
    if pack is not None and provenance is not None and pack_sha256(pack) != provenance["pack_sha256"]:
        raise ContractError(PACK_MISMATCH)

    targets_by_path: dict[str, set[str]] = defaultdict(set)
    if pack is not None:
        accepted = accepted_paths_for_targets(pack, {target["target_id"] for target in plan["targets"]})
        for target_id, paths in accepted.items():
            for path in paths:
                targets_by_path[_normalize(path)].add(target_id)

    matches = []
    for claim in result["claims"]:
        path = _normalize(claim["primary_location"]["path"])
        for target_id in sorted(targets_by_path.get(path, ())):
            matches.append({"claim_id": claim["claim_id"], "target_id": target_id,
                            "decision": DRAFT_DECISION, "reason": CANDIDATE_REASON})
    decisions = {
        "schema_version": "2.0",
        "run_id": result["run_id"],
        "input_hash": result["input_hash"],
        "result_sha256": canonical_sha256(result),
        "claim_matches": matches,
        "control_assessments": [
            {"control_id": control["control_id"], "decision": DRAFT_DECISION,
             "claim_ids": [], "reason": PENDING_REASON}
            for control in plan["controls"]
        ],
    }
    return validate_document(DECISIONS_KIND, _assert_draft_only(decisions))


def review_record(plan: dict, decisions: dict, *, clock: Callable[[], datetime] | None = None,
                  notes: Iterable[str] = ()) -> dict:
    """Open a draft review record bound to *plan* and *decisions* by canonical hash.

    The record states who produced a decisions file and whether it has been reviewed. It
    does not make the decisions true, and the hashes bind documents only: they say nothing
    about the input tree, the scanner run, or who ran either. Decisions filed against a
    different input than the plan are refused rather than recorded; nothing here checks the
    decisions against a saved result.
    """
    validate_document(PLAN_KIND, plan)
    validate_document(DECISIONS_KIND, decisions)
    _assert_binds_to_plan(plan, decisions)
    record = {
        "schema_version": "2.0",
        "run_id": decisions["run_id"],
        "decisions_sha256": canonical_sha256(decisions),
        "plan_sha256": canonical_sha256(plan),
        "state": "draft",
        "created_at": _now(clock),
        "reviews": [],
        "notes": list(notes),
    }
    return validate_document(RECORD_KIND, record)


def record_decisions(bundle_dir: str | PathLike[str], *, clock: Callable[[], datetime] | None = None,
                     notes: Iterable[str] = ()) -> dict:
    """Re-draft ``evaluator/review-record.json`` for decisions a human edited on disk.

    This is the path a person takes after editing ``evaluator/decisions.json`` by hand. It
    loads the plan and the decisions from the bundle, refuses decisions that do not bind to
    the plan's input hash or, when ``result.json`` sits beside ``evaluator/``, to that saved
    result, and writes a fresh draft record by temporary file plus :func:`os.replace`.

    The tool does not validate the human's verdicts beyond that contract: an ``accepted``
    match or a ``quiet`` control assessment is copied into the record's scope untouched and
    unread. The fresh record is a draft, so re-drafting never carries an approval forward:
    the reviews an existing record holds are copied into the new draft as history, each one
    still naming the decisions hash it was recorded against, and the state returns to
    ``draft`` because none of them was given for the decisions now on disk. Notes are not
    carried forward; the new record holds the notes this call supplies. The record is
    replaced only when no record exists or the existing one is stale; a record that still
    binds to these decisions and this plan is kept and the call is refused, so an approval
    already on disk is never overwritten by this function. A bundle reached through a
    symlink is refused before anything is read or written.
    """
    bundle = _refuse_symlinked_dirs(bundle_dir)
    evaluator = bundle / EVALUATOR_DIR
    plan = load_document(evaluator / PLAN_FILE, PLAN_KIND)
    decisions = load_document(evaluator / DECISIONS_FILE, DECISIONS_KIND)
    _assert_binds_to_plan(plan, decisions)
    _assert_binds_to_result(bundle, decisions)

    record = review_record(plan, decisions, clock=clock, notes=notes)
    record_path = evaluator / RECORD_FILE
    if record_path.exists() or record_path.is_symlink():
        existing = load_document(record_path, RECORD_KIND)
        if (existing["decisions_sha256"] == record["decisions_sha256"]
                and existing["plan_sha256"] == record["plan_sha256"]):
            raise ContractError(RECORD_CURRENT)
        # Keep the reviewer entries as history. The state stays draft, so a record that
        # was approved before the edit no longer claims approval of what is on disk now.
        record = validate_document(
            RECORD_KIND, {**record, "reviews": deepcopy(existing["reviews"])})
    _replace_document(record_path, record)
    return record


def approve_review(record: dict, decisions: dict, plan: dict, *, reviewer: str, note: str,
                   clock: Callable[[], datetime] | None = None) -> dict:
    """Return a new record carrying one explicit human approval of *decisions* under *plan*.

    The reviewer name comes from the caller and is stored verbatim; anything that is not a
    non-blank string is refused rather than coerced, by the same rule
    :mod:`scaneval.cases` applies to a reviewer name, so a name made only of zero-width or
    other format characters is refused here too. This function does not authenticate the
    reviewer, check their independence, or verify that anything was read; it records a claim
    of review and refuses one whose record no longer matches the decisions, the plan, or the
    run it would approve, or whose decisions and plan bind to different inputs. The original
    *record* is not modified, and nothing is written to disk. Reviews the record already
    carries stay in place: this appends one entry and does not re-check the older ones.
    """
    validate_document(RECORD_KIND, record)
    validate_document(DECISIONS_KIND, decisions)
    validate_document(PLAN_KIND, plan)
    _assert_binds_to_plan(plan, decisions)
    if not _is_stated(reviewer):
        raise ContractError("approval requires an explicit reviewer name; the tool never supplies one")
    digest = canonical_sha256(decisions)
    if record["decisions_sha256"] != digest:
        raise ContractError(
            "the decisions changed after this record was made; draft a new record before approving")
    if record["plan_sha256"] != canonical_sha256(plan):
        raise ContractError(
            "the plan changed after this record was made; draft a new record before approving")
    if record["run_id"] != decisions["run_id"]:
        raise ContractError(RUN_MISMATCH)
    review = {"reviewer": reviewer, "at": _now(clock), "decisions_sha256": digest, "note": note}
    approved = {**deepcopy(record), "state": "human_approved",
                "reviews": [*deepcopy(record["reviews"]), review]}
    return validate_document(RECORD_KIND, approved)


def write_evaluator_records(bundle_dir: str | PathLike[str], plan: dict, decisions: dict,
                            record: dict) -> dict[str, Path]:
    """Write ``evaluator/{plan,decisions,review-record}.json`` beside an invocation bundle.

    Nothing is overwritten. An existing ``plan.json`` is kept when it loads as the same plan
    by canonical hash, because a bundle written by the runner already carries one; a file
    whose bytes differ only in spacing is therefore kept as it stands rather than rewritten.
    Any other existing file, a symlink in their place, a bundle reached through a symlink,
    or a plan that hashes differently refuses the whole write before a byte is written. The
    three documents must also agree with each other: mismatched input hashes, run ids, or
    record hashes are refused the same way.

    Checks happen before the first write, but a write can still fail part way through, for
    example when the disk fills. This call then removes the files it created and re-raises;
    it does not remove a kept ``plan.json``, a directory it made, or anything another writer
    put there, so cleanup restores the files, not the whole prior state of the bundle. This
    places evaluator files in a directory the scanner is not given; that separation is
    documented, not enforced, by this module.
    """
    validate_document(PLAN_KIND, plan)
    validate_document(DECISIONS_KIND, decisions)
    validate_document(RECORD_KIND, record)
    _assert_binds_to_plan(plan, decisions)
    if record["run_id"] != decisions["run_id"]:
        raise ContractError(RUN_MISMATCH)
    if record["decisions_sha256"] != canonical_sha256(decisions):
        raise ContractError("the review record does not bind to these decisions")
    if record["plan_sha256"] != canonical_sha256(plan):
        raise ContractError("the review record does not bind to this plan")

    bundle = _refuse_symlinked_dirs(bundle_dir)
    evaluator = bundle / EVALUATOR_DIR
    paths = {"plan": evaluator / PLAN_FILE, "decisions": evaluator / DECISIONS_FILE,
             "record": evaluator / RECORD_FILE}
    plan_text = _document(plan)
    keep_plan = False
    if paths["plan"].is_symlink():
        raise ContractError(f"refusing to follow a symlink at {paths['plan']}")
    if paths["plan"].exists():
        # Compare the documents, not their bytes: review_status binds by canonical hash too,
        # so a plan that only differs in spacing is the same plan to every later check.
        if canonical_sha256(load_document(paths["plan"], PLAN_KIND)) != canonical_sha256(plan):
            raise ContractError(
                f"{paths['plan']} holds a different plan; decisions must be filed against the planned targets")
        keep_plan = True
    for key in ("decisions", "record"):
        if paths[key].exists() or paths[key].is_symlink():
            raise FileExistsError(f"refusing to overwrite {paths[key]}")

    created: list[Path] = []
    try:
        evaluator.mkdir(parents=True, exist_ok=True)
        for key, content in (("plan", plan_text), ("decisions", _document(decisions)),
                             ("record", _document(record))):
            if key == "plan" and keep_plan:
                continue
            _write_new(paths[key], content)
            created.append(paths[key])
    except BaseException:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return paths


def review_status(bundle_dir: str | PathLike[str], *, guard_symlinks: bool = True) -> str:
    """Report ``missing``, ``stale``, or the record's own state for one bundle.

    ``stale`` means the decisions file or the plan changed after the record was written, that
    the two no longer bind to the same input hash, or that the record and the decisions name
    different runs. That is the only tampering this can see: it does not check the result, the
    source tree, or the pack the plan came from. A ``human_approved`` state is the record's own
    assertion, not a verified one, and a bundle with no record is unreviewed, not rejected. A
    record beside an unreadable or invalid plan or decisions file raises instead of reporting a
    state.

    This reads and never writes, so ``guard_symlinks=False`` is available to a caller that has
    already resolved the bundle path and wants a status for the bundle that path reaches. The
    default refuses a symlinked spelling, which is what an unresolved caller wants.
    """
    evaluator = _bundle_path(bundle_dir, guard_symlinks) / EVALUATOR_DIR
    record_path = evaluator / RECORD_FILE
    if not record_path.is_file():
        return "missing"
    record = load_document(record_path, RECORD_KIND)
    decisions = load_document(evaluator / DECISIONS_FILE, DECISIONS_KIND)
    plan = load_document(evaluator / PLAN_FILE, PLAN_KIND)
    if record["decisions_sha256"] != canonical_sha256(decisions):
        return "stale"
    if record["plan_sha256"] != canonical_sha256(plan):
        return "stale"
    if decisions["input_hash"] != plan["input_hash"]:
        return "stale"
    if record["run_id"] != decisions["run_id"]:
        return "stale"
    return record["state"]


def load_evaluator(bundle_dir: str | PathLike[str], *,
                   guard_symlinks: bool = True) -> tuple[dict, dict, dict | None]:
    """Load and validate the evaluator side of a bundle; the record is ``None`` when absent.

    Loading validates each document against its contract. It does not check that the three
    agree with each other or with ``result.json``; use :func:`review_status` for staleness
    and :func:`scaneval.scoring.score` for the result binding. ``guard_symlinks=False``
    reads the bundle the given path reaches, symlinks and all, and belongs to a caller that
    resolved the path itself; the default refuses a symlinked spelling instead, which is what
    a caller that is about to write through this path needs.
    """
    evaluator = _bundle_path(bundle_dir, guard_symlinks) / EVALUATOR_DIR
    plan = load_document(evaluator / PLAN_FILE, PLAN_KIND)
    decisions = load_document(evaluator / DECISIONS_FILE, DECISIONS_KIND)
    record_path = evaluator / RECORD_FILE
    record: dict[str, Any] | None = None
    if record_path.is_file():
        record = load_document(record_path, RECORD_KIND)
    return plan, decisions, record
