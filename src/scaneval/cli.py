"""Local validation, saved-output scoring, deterministic replay, and the corpus-to-run workflow.

The evaluation commands (validate, score, replay, report, demo) stay offline and read saved
documents only. ``import sarif`` is offline too: it reads one saved SARIF 2.1.0 log into a new
bundle through :mod:`scaneval.sarif` and never fetches or opens anything the log names. The
corpus, plan, review, and run commands drive :mod:`scaneval.cases`, :mod:`scaneval.materialize`,
:mod:`scaneval.review`, and :mod:`scaneval.runner`; this module holds no pack, planning, routing,
import, execution, or scoring logic of its own.

Boundaries this module keeps. No command infers approval: ``corpus approve`` and ``review
approve`` record the reviewer name the caller supplies, and nothing else raises a case or a
review record above the state it already has. An imported artifact becomes a draft case with a
``needs_evidence`` disposition, never a label, and a license is never recorded as verified here.
Pack files, plans, and decisions stay evaluator-side: no command writes them into an exported
source tree or a scanner workspace.

What each command writes:

- A pack file is rewritten in place. Every corpus command that changes a pack (``add-snapshot``,
  ``import``, ``validate --snapshot-id``, ``approve``, ``admit``, ``disposition``, and the three
  that write 2.1 labels, ``add-change-set``, ``pr-scope``, and ``canonical``) writes a
  temporary file beside it and renames that over the pack, so a reader sees the whole old pack
  or the whole new one. The previous version is not kept, and a pack whose status is no longer
  ``draft`` is refused unless ``--new-version`` opens a new draft version of it.
- A blinding map is rewritten in place the same way by ``blinding review``, which appends one
  chained review and changes nothing else. ``blinding check`` only reads the map.
- ``evaluator/review-record.json`` is replaced the same way by ``review record`` and
  ``review approve``, through the one replace function :mod:`scaneval.review` uses. Both
  refuse a bundle reached through a symlink before writing.
- A precision reviews file only grows. ``precision record`` creates it with its first review
  and appends each later one through that same replace function, after checking the recorded
  chain and the sample it is bound to, so no earlier entry is changed or dropped.
- Everything else is create-only: an existing output path is refused, never overwritten.

The read-only bundle commands do not refuse a symlink: ``replay``, ``report`` and ``review
status`` resolve the bundle path and report on the bundle it reaches, so a bundle named through
a symlinked parent is read rather than refused. They write nothing into the bundle.

No command writes inside a materialized trial directory: the output path of ``plan``, ``run``,
``import sarif``, ``demo``, ``score``, ``replay``, ``report``, ``aggregate`` and ``compare``, the
pack path of ``corpus init`` and of every corpus command that rewrites a pack, the map ``blinding
review`` rewrites, the bundle argument of all four ``review`` subcommands, the output of
``precision sample``, ``queue`` and ``estimate`` and the reviews file of ``precision record``, and
the directory ``corpus validate`` exports a snapshot into, are each refused when a trial's
``provenance.json`` and ``source`` sit in them or above them. That keeps evaluator material out of
the tree a scanner is handed; it is a check on the path, not an isolation boundary. ``review
status`` is checked although it only reads, so the ``review`` group is uniform; the other read-only
commands read whatever path they are given. The output of ``gate`` is refused in the same places
and inside a run directory too.

Exit codes. 2 means the command could not be carried out: a usage or contract error, a refused
overwrite, a failed fetch or export, a SARIF log refused whole. 1 means the command ran and
reports a negative result: a mechanical check set failed, a run could not prepare some input or
produced no usable scan from some system, an imported log holds no usable scan, a blinding map is
not approved or a variant refused it, or ``diagnose`` was given something that is not a bundle it
can read. 0 means it ran and reports nothing wrong, which is not a statement that any label or
decision is correct. ``gate`` also exits 1 for a decision that is not a pass.

``diagnose`` reads a saved invocation bundle and writes a diagnostic document. It scores nothing,
changes nothing in the bundle, and its answer never reaches a metric: a target whose code was
never supplied to the model is still a target the scan did not detect.

``blinding check`` fetches and exports each variant a blinding map covers into a temporary
directory, applies the map exactly as a run would, and prints what it changed, every check it
passed, and the identity cues that remain; approval is reported rather than required, and an
unapproved or refused map exits 1. ``blinding review`` records one review the caller names; the
tool never supplies a reviewer.

``aggregate`` and ``compare`` read run directories through :mod:`scaneval.aggregate` and write one
new report each; they write nothing into a run directory or a bundle. Both exit 0 once the report is
computed, whatever it says, and 2 when they refuse: a directory that is not a run with a frozen
schedule, runs of different packs, or, for ``compare``, two systems that were not assigned the same
frozen work.

``precision`` draws a seeded probability sample of delivered claims from saved run directories,
exports it for human review with system identity blinded, records the reviews people state, and
estimates reviewed precision from them (:mod:`scaneval.precision`, ``docs/PRECISION.md``). It reads
runs and never writes into one: each of its outputs is refused inside a run directory as well as
inside a trial. It supplies no reviewer and changes no decision, score, or detection credit. It
exits 0 once its document is written, whatever the document reports, and 2 when refused.

``gate`` holds one saved comparison, and optionally a precision estimate of each system, to a gate
policy and writes the decision (:mod:`scaneval.gate`, ``docs/GATE.md``). It runs no scan, model, or
judge, approves nothing, and promotes nothing: it reads documents and writes one new one, refused
inside a trial or a run directory like every precision output. It prints the outcome and every failed
or unresolved requirement with its reason, and exits 0 for a pass, 1 for a fail or an inconclusive
decision, and 2 when it could not evaluate: a document that is not what it is named, a policy that is
refused, or an output that cannot be written.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Callable
from urllib.parse import urlsplit

from . import __version__, aggregate, blinding, cases, gate, materialize, precision, review, runner, sarif
from .adapters.base import AdapterError
# _is_stated is imported rather than re-implemented so a blank value is judged by one rule here,
# in cases, and in review: a string made only of zero-width or control characters is not a value.
from .cases import _is_stated
from .contracts import CONTRACT_KINDS, ContractError, canonical_json, load_document
from .demo import SOURCE, demo_documents
from .diagnostics import DiagnosticsError, context_coverage_for_invocation
from .execution import ExecutionError
from .materialize import MaterializationError
from .report import render_report
from .review import (
    _assert_binds_to_result,
    _keep_mode,
    _refuse_symlinked_dirs,
    _replace_document,
)
from .scoring import score


# These mirror the case-pack contract enums so the CLI can reject a typo early. The schema in
# scaneval/schemas stays authoritative: every value below is validated again on the way in.
LANGUAGES = ("python", "typescript", "javascript", "go", "rust")
WORKLOADS = ("conventional_application", "conventional_automation", "ai_assisted_application",
             "agentic_application")
COMPONENT_ROLES = ("application", "library_sdk", "infrastructure")
SNAPSHOT_ROLES = ("vulnerable", "fixed", "ordinary")
REVIEW_ROLES = ("curator", "independent_reviewer", "adjudicator")
ADMISSION_DECISIONS = ("admitted", "rejected", "deferred")
# A pack read by a tool is not a license check; only a human edit may set verified true.
LICENSE_NOTE = "Not checked by the CLI; a reviewer must confirm the license of this exact snapshot."
IMPORT_LOCATION_NOTE = "imported allegation, not a reviewed label"
UNREVIEWED_REVIEW_STATES = ("draft", "stale", "missing")
APPROVED_REVIEW_STATE = "human_approved"
# Invocation statuses that delivered no usable scan. 'partial' and 'unsupported' are excluded:
# a partial scan can still carry valid claims, and unsupported work stays in the denominator.
INCOMPLETE_INVOCATION_STATUSES = ("error", "timeout", "skipped")
# A trial directory: exported source beside the provenance record of that export.
TRIAL_MARKER = "provenance.json"
TRIAL_SOURCE = "source"


def _write_new(path: Path, content: str) -> None:
    # Refuse overwrite, including symlinks, rather than destroy a prior run.
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _json(value: dict) -> str:
    return canonical_json(value) + "\n"


def _readable_json(value: dict) -> str:
    """Sorted keys, indented two spaces, one trailing newline.

    A diagnostic document is read by a person and diffed between runs, not hashed and not bound
    to by anything, so it is printed rather than written in the compact canonical form the
    contract documents use. Keys are still sorted, so two runs over one bundle are byte-identical
    and a diff shows only what changed about the run.
    """
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2) + "\n"


def _read_json(path: Path) -> dict:
    """Load a supplied JSON artifact that has no contract of its own. Content is data, not truth.

    Every way the parser can refuse the text is named as a refusal carrying *path*, the same way
    :func:`scaneval.contracts.load_document` names a contract file: bytes that are not UTF-8 and
    malformed syntax raise a :class:`ValueError` subclass, an integer literal longer than the
    interpreter's ``int_max_str_digits`` limit raises a bare :class:`ValueError`, and a document
    nested past the recursion limit raises :class:`RecursionError`. None of them should reach the
    caller as a traceback or as an unnamed file.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError, RecursionError) as exc:
        raise ContractError(f"could not load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{path} must contain a JSON object")
    return value


def _create_pack(path: Path, pack: dict) -> None:
    """Claim *path* exclusively, then let :func:`scaneval.cases.save_pack` write the pack into it."""
    with path.open("x", encoding="utf-8", newline="\n"):
        pass
    cases.save_pack(path, pack)


def _replace_file(path: Path, write: Callable[[Path], None]) -> None:
    """Have *write* write the new document to a temporary file beside *path*, then rename it over *path*.

    The replacement is a rename, so a concurrent reader sees the old document or the new one and
    never a half-written file, and a *write* that raises (an invalid document, say) leaves the
    old file untouched and no temporary file behind. The previous version is not kept here:
    version history belongs in the repository, not in a backup copy this command leaves behind.
    A symlink at *path* is replaced rather than written through, and the regular file that
    replaces it keeps the owner-only mode of the temporary file rather than the mode of the
    symlink's target: permissions are carried over by :func:`scaneval.review._keep_mode`, which
    every replaced review record goes through as well.
    """
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=str(path.parent),
        prefix=path.name + ".", suffix=".tmp", delete=False,
    )
    handle.close()
    temporary = Path(handle.name)
    try:
        write(temporary)
        _keep_mode(temporary, path)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _save_pack(path: Path, pack: dict) -> None:
    """Validate *pack* and replace the pack file at *path* through a temporary file beside it.

    A pack is one of the two kinds of document this module rewrites, and it is replaced the one
    way :func:`_replace_file` states. *path* is expected to already exist, because every caller
    loads the pack from it first; :func:`_create_pack` is what writes a new one.
    """
    _replace_file(path, lambda temporary: cases.save_pack(temporary, pack))


def _pack_for_change(args: argparse.Namespace) -> dict:
    """Load the pack a command is about to rewrite, applying ``--new-version`` when it is given.

    This is the one door to a pack this tool rewrites, so the trial-directory check on
    ``args.pack`` sits here and covers every command that goes through it. It runs before the
    pack is read, so a pack named inside an exported source tree is refused whether or not a file
    is there.

    A pack that is no longer a draft is what plans, manifests, and reports already cite by
    version and hash, so this refuses to edit one in place. ``--new-version`` opens a new draft
    version instead and records the version and status it came from in the pack notes. Reopening
    a pack changes nothing else: it re-checks nothing, approves nothing, and withdraws no
    recorded review or admission.
    """
    _refuse_trial_path(args.pack)
    pack = cases.load_pack(args.pack)
    version = getattr(args, "new_version", None)
    if version is None:
        if pack["status"] != "draft":
            raise ContractError(
                f"pack status is {pack['status']}, not draft; changing it needs "
                "--new-version <version>, which opens a new draft version of this pack")
        return pack
    version = version.strip()
    if not _is_stated(version):
        raise ContractError("--new-version requires a non-blank version")
    if version == pack["version"]:
        raise ContractError(
            f"--new-version {version} is the version this pack already carries; a new version "
            "must be a different string, so the reopened pack is distinguishable from the one "
            "plans and reports already cite")
    pack["notes"].append(
        f"version {pack['version']} (status {pack['status']}) reopened as {version} (status draft)")
    pack["version"] = version
    pack["status"] = "draft"
    return pack


def _reject_credentials(option: str, url: str) -> None:
    """Refuse a URL whose authority carries userinfo, so a pack never records a credential.

    One userinfo is allowed: the bare user ``git`` with no password, which is how an ssh clone
    URL names the git account rather than a secret. Anything else in the authority, including
    ``git`` with a password, is refused.

    This reads the authority of the URL only. It does not find a token in a path, a query, or a
    fragment, does not recognize an scp-style ssh address such as ``git@host:path`` as carrying
    userinfo, and it says nothing about whether the URL resolves or what it points at.

    A string :func:`~urllib.parse.urlsplit` cannot split at all, such as one with an unclosed
    ``[`` in its authority, is refused here naming *option*. The authority was never read, so
    this refusal says the URL could not be checked for credentials, not that it carries none.
    """
    try:
        netloc = urlsplit(url).netloc
    except ValueError as exc:
        raise ContractError(
            f"{option} is not a URL this tool can read ({exc}), so its authority could not be "
            "checked for credentials; supply a URL that parses") from exc
    userinfo, marker, _host = netloc.rpartition("@")
    if marker and userinfo != "git":
        raise ContractError(
            f"{option} carries credentials in the URL authority; supply a URL without userinfo "
            "and keep the credential in the git or network configuration")


def _finding_lines(finding: dict, source: Path) -> dict:
    """The ``start_line``/``end_line`` pair of a supplied allegation, or an empty mapping.

    Both are required together and each must be an integer of at least 1. A supplied pair is
    recorded as it stands; a missing pair leaves the imported location file-only. Anything else
    is refused rather than coerced or dropped, because a guessed range would enter the pack as
    an accepted reporting location.
    """
    present = [key for key in ("start_line", "end_line") if finding.get(key) is not None]
    if not present:
        return {}
    if len(present) == 1:
        raise ContractError(
            f"{source}: start_line and end_line must be supplied together; {present[0]} is alone")
    lines = {}
    for key in ("start_line", "end_line"):
        value = finding[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ContractError(f"{source}: {key} must be an integer of at least 1, not {value!r}")
        lines[key] = value
    if lines["start_line"] > lines["end_line"]:
        raise ContractError(f"{source}: start_line must not exceed end_line")
    return lines


def _refuse_trial_path(output: Path) -> None:
    """Refuse an output path that lies inside a materialized trial directory.

    A trial holds the exported source a scanner is handed, so anything this tool writes inside
    one would put evaluator material where the scanned tree lives. Every command that names a
    path it may write checks it: ``plan``, ``run``, ``demo``, the bundle ``import sarif``
    creates, the ``--output`` of ``score``, ``replay``, ``report``, ``aggregate`` and
    ``compare``, the pack ``corpus init`` creates, the pack every corpus command that rewrites one
    is given (``add-snapshot``, ``import``, ``validate --snapshot-id``, ``approve``, ``admit``,
    ``disposition``, ``add-change-set``, ``pr-scope``, ``canonical``, all through
    :func:`_pack_for_change`), the map ``blinding review`` rewrites,
    the bundle ``review init``, ``review record`` and ``review approve`` write into, the output of
    every ``precision`` command and the reviews file ``precision record`` appends to, and the trial
    ``corpus validate`` is about to export into. ``review status`` checks the bundle it reads as
    well, so every ``review`` subcommand refuses the same paths. Commands that only read are
    otherwise not checked: a bundle handed to ``replay`` or ``report``, a run directory handed to
    ``aggregate`` or ``compare``, a pack that is only summarized by ``corpus validate`` or read by
    ``plan`` and ``review init``, a map ``blinding check`` reads, and a supplied artifact are read
    wherever they sit. A trial is recognized by a ``provenance.json`` file beside a ``source``
    directory; any other directory is left alone. *output* itself is examined along with its
    parents, so a bundle that is itself a trial root is refused as well as one sitting under one; a
    path that does not exist yet carries no marker and is judged by its parents alone. The
    comparison resolves symlinks in the path but follows no bind mount or hard link, so it catches
    the obvious mistake and is not an isolation boundary. The decision ``gate`` writes is checked
    here too, and by :func:`_refuse_gate_path` against run directories.
    """
    resolved = output.expanduser().resolve()
    for directory in (resolved, *resolved.parents):
        if (directory / TRIAL_MARKER).is_file() and (directory / TRIAL_SOURCE).is_dir():
            where = ("which is itself the trial directory" if directory == resolved
                     else f"inside the trial directory {directory}")
            raise ContractError(
                f"refusing to write {output} {where}; evaluator plans, packs, and decisions "
                "stay outside an exported input tree")


def load_bundle(directory: Path) -> tuple[dict, dict, dict]:
    plan = load_document(directory / "evaluator" / "plan.json", "evaluation-plan")
    result = load_document(directory / "result.json", "scan-result")
    decisions = load_document(directory / "evaluator" / "decisions.json", "review-decisions")
    return plan, result, decisions


def _demo(directory: Path) -> None:
    _refuse_trial_path(directory)
    documents = demo_documents()
    record = score(documents["plan"], documents["result"], documents["decisions"])
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "scan-input").mkdir()
    (directory / "evaluator").mkdir()
    _write_new(directory / "scan-input" / "app.py", SOURCE)
    for name, relative in [("request", "request.json"), ("result", "result.json"),
                           ("plan", "evaluator/plan.json"), ("decisions", "evaluator/decisions.json")]:
        _write_new(directory / relative, _json(documents[name]))
    _write_new(directory / "evaluation.json", _json(record))
    _write_new(directory / "report.html", render_report(record, documents["result"], documents["plan"]))
    _write_new(directory / "README.txt", "Diagnostic fixture only. No scanner was run.\n"
               "scan-input contains source only; evaluator contains scripted labels and decisions.\n"
               "Directory separation illustrates the contract, not a sandbox or access restriction.\n"
               "Input hash: canonical SHA-256 of the app.py path/content map, not a git archive.\n"
               "Replay reads result.json and evaluator/{plan,decisions}.json, not source or request.\n"
               "It verifies the decision-to-result binding, not the actual input tree or a signature.\n")
    print(f"Created diagnostic bundle: {directory}\nOpen {directory / 'report.html'}")


def _corpus_init(args: argparse.Namespace) -> int:
    _refuse_trial_path(args.pack)
    pack = cases.new_pack(args.namespace, args.pack_id, args.description, version=args.version)
    _create_pack(args.pack, pack)
    print(f"Created draft pack {pack['namespace']}/{pack['pack_id']} {pack['version']}: {args.pack}")
    return 0


def _corpus_add_snapshot(args: argparse.Namespace) -> int:
    _reject_credentials("--url", args.url)
    if args.historical_url:
        _reject_credentials("--historical-url", args.historical_url)
    pack = _pack_for_change(args)
    repository = {"url": args.url, "name": args.name}
    if args.historical_url:
        repository["historical_url"] = args.historical_url
    snapshot = cases.add_snapshot(pack, {
        "snapshot_id": args.snapshot_id, "repository": repository, "commit": args.commit,
        "reference": args.reference, "languages": args.languages, "workload": args.workload,
        "component_role": args.component_role, "role": args.role,
        "license": {"spdx": args.license_spdx, "verified": False, "note": args.license_note},
    })
    _save_pack(args.pack, pack)
    print(f"Added {snapshot['role']} snapshot {snapshot['snapshot_id']} at {snapshot['commit'][:12]}; "
          f"license verified: false")
    return 0


def _supplied_artifact(args: argparse.Namespace) -> dict:
    """Draft-case arguments for one supplied artifact. Nothing here reads the artifact as truth."""
    common = {"represents": args.represents, "workload": args.workload,
              "component_role": args.component_role, "aliases": args.aliases,
              "disposition": "needs_evidence", "accepted_locations": []}
    if args.fix_commit:
        if not args.repo:
            raise ContractError("--fix-commit requires --repo; the reference is recorded as '<repo>@<sha>'")
        _reject_credentials("--repo", args.repo)
        return {**common, "kind": args.kind or "unmapped",
                "description": args.description or f"Imported fix commit {args.fix_commit} for {args.case_id}.",
                "evidence": [cases.evidence(
                    "fix-commit", origin="fix_without_advisory", kind="fix_commit",
                    reference=f"{args.repo}@{args.fix_commit}",
                    note="Supplied fix commit. The CLI did not fetch, read, or verify it.")],
                "disposition_reason": "Imported from a supplied fix commit; the fix has not been reviewed here."}
    if args.finding:
        finding = _read_json(args.finding)
        missing = [key for key in ("allegation", "path") if not finding.get(key)]
        if missing:
            raise ContractError(f"{args.finding} must supply: {', '.join(missing)}")
        location = {"path": finding["path"], "role": "other", "note": IMPORT_LOCATION_NOTE}
        location.update(_finding_lines(finding, args.finding))
        source = finding.get("source") or "an unnamed system"
        return {**common, "kind": args.kind or finding.get("kind") or "unmapped",
                "description": args.description or f"Imported allegation: {finding['allegation']}",
                "evidence": [cases.evidence(
                    "allegation", origin="research_note", kind="scanner_allegation",
                    reference=str(args.finding),
                    note=f"Allegation from {source}, imported verbatim. An allegation is not a reviewed label.")],
                "accepted_locations": [location],
                "disposition_reason": "Imported from a scanner allegation; it has not been reviewed here."}
    section = f"section {args.section}. " if args.section else ""
    return {**common, "kind": args.kind or "unmapped",
            "description": args.description or f"Imported from internal document {Path(args.document).name}.",
            "evidence": [cases.evidence(
                "document", origin="research_note", kind="internal_document", reference=str(args.document),
                note=f"{section}Supplied document, recorded as a reference and not read by the CLI.")],
            "disposition_reason": "Imported from an internal document; the document has not been reviewed here."}


def _corpus_import(args: argparse.Namespace) -> int:
    pack = _pack_for_change(args)
    case = cases.draft_case(args.case_id, snapshot_id=args.snapshot_id, **_supplied_artifact(args))
    cases.add_case(pack, case)
    _save_pack(args.pack, pack)
    validation = case["validation"]
    print(f"Imported draft case {case['case_id']}: {len(case['evidence'])} evidence records, "
          f"disposition {case['disposition']['value']}, review state {validation['review_state']}, "
          f"level {validation['level']}")
    return 0


def _corpus_validate(args: argparse.Namespace) -> int:
    if not args.snapshot_id:
        if args.new_version is not None:
            raise ContractError("--new-version applies to a check that rewrites the pack; add --snapshot-id")
        sys.stdout.write(cases.dump_json(cases.pack_summary(cases.load_pack(args.pack))))
        return 0
    pack = _pack_for_change(args)
    snapshot = cases.snapshot_by_id(pack, args.snapshot_id)
    cache_root = args.cache_root or args.pack.parent / runner.DEFAULT_CACHE_ROOT
    trial = None
    if args.trial_root is not None:
        trial = args.trial_root / args.snapshot_id
        _refuse_trial_path(trial)
        if trial.exists() or trial.is_symlink():
            raise ContractError(
                f"trial directory already exists: {trial}; export every snapshot into a new directory")
    cached = materialize.fetch_snapshot(snapshot["repository"]["url"], snapshot["commit"], cache_root)
    if trial is None:
        # Created only now, so a failed fetch leaves no empty temporary directory behind.
        trial = Path(tempfile.mkdtemp(prefix="scaneval-trial-")) / args.snapshot_id
    record = materialize.export_snapshot(cached, trial)
    materialize.write_provenance(trial, record)
    outcomes = cases.mechanical_checks(pack, args.snapshot_id, trial / "source", record["trial"]["tree_hash"])
    _save_pack(args.pack, pack)
    print(f"Exported {args.snapshot_id} to {trial} ({record['trial']['tree_hash']})")
    for outcome in outcomes:
        failed = [check["check"] for check in outcome["checks"] if check["result"] != "pass"]
        detail = f"; failed: {', '.join(failed)}" if failed else ""
        print(f"{outcome['case_id']}: {'pass' if outcome['passed'] else 'fail'} "
              f"({outcome['review_state']}, level {outcome['level']}){detail}")
    if not outcomes:
        print(f"No case references snapshot {args.snapshot_id}; nothing was checked.")
        return 0
    unchecked = [outcome["case_id"] for outcome in outcomes if not outcome["passed"]]
    if unchecked:
        print(f"scaneval: mechanical checks failed for {len(unchecked)} case(s): "
              f"{', '.join(unchecked)}; the results are recorded in the pack", file=sys.stderr)
        return 1
    return 0


def _corpus_approve(args: argparse.Namespace) -> int:
    pack = _pack_for_change(args)
    recorded = cases.approve_case(pack, args.case_id, reviewer=args.reviewer, role=args.role,
                                  level=args.level, note=args.note)
    _save_pack(args.pack, pack)
    sys.stdout.write(cases.dump_json(recorded))
    return 0


def _corpus_admit(args: argparse.Namespace) -> int:
    pack = _pack_for_change(args)
    admission = cases.admit_case(pack, args.case_id, decision=args.decision, by=args.by, reason=args.reason)
    _save_pack(args.pack, pack)
    sys.stdout.write(cases.dump_json(admission))
    return 0


def _corpus_disposition(args: argparse.Namespace) -> int:
    pack = _pack_for_change(args)
    recorded = cases.set_disposition(pack, args.case_id, args.value, args.reason)
    _save_pack(args.pack, pack)
    sys.stdout.write(cases.dump_json(recorded))
    return 0


def _corpus_add_change_set(args: argparse.Namespace) -> int:
    """Declare one change set: a base and a head snapshot the pack already holds, and a review scope.

    The first one upgrades the pack to 2.1, which is the only version that can carry it. Nothing is
    fetched: this records a boundary, and neither reads the two commits nor checks that one
    descends from the other. Which items are scored under it is stated separately, by ``pr-scope``.
    """
    pack = _pack_for_change(args)
    change_set = {"change_set_id": args.change_set_id, "base_snapshot_id": args.base_snapshot_id,
                  "head_snapshot_id": args.head_snapshot_id, "boundary": args.boundary,
                  "review_scope": args.review_scope, "description": args.description,
                  **({"reference": args.reference} if args.reference else {})}
    recorded = cases.add_change_set(pack, change_set)
    _save_pack(args.pack, pack)
    sys.stdout.write(cases.dump_json(recorded))
    return 0


def _say_if_approval_lapsed(pack: dict, case_id: str, was_current: bool) -> None:
    """Say on stderr that a label write left the case's recorded approval covering other labels.

    The write never carries an approval onto the labels it changed, so this is a statement of what
    the write did, not a warning that something went wrong: the review stays recorded as it was,
    the case is left out of a plan, and a review of the labels as they now stand plans it again.
    """
    if was_current and not cases.approval_is_current(pack, cases.case_by_id(pack, case_id)):
        print(f"note: the recorded approval of case {case_id} no longer covers its labels, which this "
              "write changed; it is left out of a plan until a review covers them as they now stand "
              "(corpus approve)", file=sys.stderr)


def _corpus_pr_scope(args: argparse.Namespace) -> int:
    """State how a target, or one control, is scored in the PR review of a declared change set.

    A label write: an approval recorded before it no longer covers the labels it changed, and this
    never carries one onto them. An item with no entry for a change set is outside that review.
    """
    pack = _pack_for_change(args)
    was_current = cases.approval_is_current(pack, cases.case_by_id(pack, args.case_id))
    recorded = cases.set_pr_eligibility(pack, args.case_id, args.change_set_id, args.relation,
                                        args.code_scope, note=args.note, control_id=args.control_id)
    _save_pack(args.pack, pack)
    sys.stdout.write(cases.dump_json(recorded))
    _say_if_approval_lapsed(pack, args.case_id, was_current)
    return 0


def _corpus_canonical(args: argparse.Namespace) -> int:
    """State which canonical root cause a target, or which property one control, belongs to.

    A label write, with the same effect on a recorded approval as ``pr-scope``. Two records given
    one canonical id are one root cause or one property because the person running this said so.
    """
    pack = _pack_for_change(args)
    was_current = cases.approval_is_current(pack, cases.case_by_id(pack, args.case_id))
    recorded = cases.set_canonical_id(pack, args.case_id, args.canonical_id, control_id=args.control_id)
    _save_pack(args.pack, pack)
    owner = ({"control_id": args.control_id} if args.control_id
             else {"target_id": cases.case_by_id(pack, args.case_id)["target"]["target_id"]})
    sys.stdout.write(cases.dump_json({"case_id": args.case_id, **owner, "canonical_id": recorded}))
    _say_if_approval_lapsed(pack, args.case_id, was_current)
    return 0


def _corpus(args: argparse.Namespace) -> int:
    return {"init": _corpus_init, "add-snapshot": _corpus_add_snapshot, "import": _corpus_import,
            "validate": _corpus_validate, "approve": _corpus_approve, "admit": _corpus_admit,
            "disposition": _corpus_disposition, "add-change-set": _corpus_add_change_set,
            "pr-scope": _corpus_pr_scope, "canonical": _corpus_canonical}[args.corpus_command](args)


def _plan(args: argparse.Namespace) -> int:
    """Write one evaluation plan: a full plan of a snapshot, or the PR plan of a declared change set.

    ``--mode pr`` alone keeps meaning what it always did, a full plan of the snapshot carrying the
    pack's ``pr`` review budgets, and says so, because it names no change and reviews none. A PR plan
    needs ``--change-set-id`` and the three hashes that identify the input: the tree a scanner is
    handed as the base and as the head, and the digest of the recorded diff between them, all of which
    a run prepares and records. ``--snapshot-id`` is then the change set's head snapshot and
    ``--tree-hash`` its export, which the labels refer to. Nothing here exports a tree or computes a
    diff: the hashes are taken as given, and the plan is refused when they contradict the pack.
    """
    _refuse_trial_path(args.output)
    pack = cases.load_pack(args.pack)
    identity = {"--base-tree-hash": args.base_tree_hash, "--head-tree-hash": args.head_tree_hash,
                "--diff-sha256": args.diff_sha256}
    if args.change_set_id is None:
        stray = [flag for flag, value in identity.items() if value is not None]
        if stray:
            raise ContractError(f"{', '.join(stray)} identify a PR input and belong with --change-set-id")
        plan, notes = cases.build_plan(pack, args.snapshot_id, args.tree_hash, mode=args.mode)
        if args.mode == "pr":
            notes.insert(0, "--mode pr without --change-set-id only selects the pack's pr review budgets; "
                            "this is a full plan of the snapshot, not the review of any change")
    else:
        if args.mode != "pr":
            raise ContractError("--change-set-id plans the PR review of a change set; add --mode pr")
        missing = [flag for flag, value in identity.items() if value is None]
        if missing:
            raise ContractError(f"a PR plan binds to the base tree, the head tree, and the diff between "
                                f"them, so it needs {', '.join(missing)}")
        plan, notes = cases.build_plan(
            pack, args.snapshot_id, args.tree_hash, mode="pr", change_set_id=args.change_set_id,
            base_tree_hash=args.base_tree_hash, head_tree_hash=args.head_tree_hash,
            diff_sha256=args.diff_sha256)
    _write_new(args.output, _json(plan))
    for note in notes:
        print(f"note: {note}", file=sys.stderr)
    kind = f"PR plan for change set {args.change_set_id}" if args.change_set_id else "plan"
    print(f"Wrote a {plan['scope']} {kind} with {len(plan['targets'])} targets and "
          f"{len(plan['controls'])} controls: {args.output}")
    return 0


def _review_init(args: argparse.Namespace) -> int:
    _refuse_trial_path(args.bundle)
    evaluator = args.bundle / review.EVALUATOR_DIR
    plan = load_document(evaluator / review.PLAN_FILE, "evaluation-plan")
    result = load_document(args.bundle / "result.json", "scan-result")
    pack = cases.load_pack(args.pack)
    decisions = review.draft_decisions(plan, result, pack)
    record = review.review_record(plan, decisions)
    review.write_evaluator_records(args.bundle, plan, decisions, record)
    print(f"Routed {len(decisions['claim_matches'])} candidate claim matches and "
          f"{len(decisions['control_assessments'])} control assessments; every decision stays unresolved.")
    return 0


def _review_record(args: argparse.Namespace) -> int:
    """Re-draft the review record for decisions a human edited, and print what it now binds to."""
    _refuse_trial_path(args.bundle)
    record = review.record_decisions(args.bundle, notes=args.notes)
    print(f"Review record state: {record['state']} ({len(record['reviews'])} recorded reviews)")
    print(f"decisions_sha256: {record['decisions_sha256']}")
    print(f"plan_sha256: {record['plan_sha256']}")
    return 0


def _review_approve(args: argparse.Namespace) -> int:
    """Record one human approval of the decisions a bundle holds, and replace only its record."""
    _refuse_trial_path(args.bundle)
    # This writes, so the bundle is guarded rather than resolved, and the guarded path is what
    # the load, the result check, and the replace all use.
    bundle = _refuse_symlinked_dirs(args.bundle)
    plan, decisions, record = review.load_evaluator(bundle)
    if record is None:
        raise ContractError(f"no review record in {bundle}; run 'review init' first")
    # An approval names the decisions, and the decisions name a saved result. A result edited
    # after they were filed is refused here, so no approval is recorded against stale output.
    _assert_binds_to_result(bundle, decisions)
    approved = review.approve_review(record, decisions, plan, reviewer=args.reviewer, note=args.note)
    _replace_document(bundle / review.EVALUATOR_DIR / review.RECORD_FILE, approved)
    print(f"Review record state: {approved['state']} ({len(approved['reviews'])} recorded reviews)")
    return 0


def _review_status(args: argparse.Namespace) -> int:
    """Print the review state of one bundle. This reads; it writes nothing and approves nothing.

    The bundle is refused inside a trial directory the way the writing review commands refuse
    one, so no spelling of ``review`` treats an exported source tree as a place a bundle lives.
    """
    _refuse_trial_path(args.bundle)
    if not args.bundle.is_dir():
        raise ContractError(f"{args.bundle} is not a bundle directory; review status reads "
                            "evaluator/review-record.json inside one")
    # Resolved here, so a bundle named through a symlinked parent is reported on rather than
    # refused. Nothing is written, so the symlink guard the writing commands keep is not needed.
    print(review.review_status(args.bundle.resolve(), guard_symlinks=False))
    return 0


def _review(args: argparse.Namespace) -> int:
    return {"init": _review_init, "record": _review_record, "approve": _review_approve,
            "status": _review_status}[args.review_command](args)


def _run(args: argparse.Namespace) -> int:
    """Execute one run configuration and report each invocation, each unprepared input, and the result.

    An input the run could not prepare is named on stderr with the failure recorded in the
    manifest; its assignments are skipped invocations, never scans that found nothing, so the
    command reports a negative result (1) whenever any input or invocation delivered no usable scan.
    """
    _refuse_trial_path(args.output)
    manifest = runner.run_from_config(
        args.config, args.output, workspace_root=args.workspace_root,
        only_systems=set(args.only_system) if args.only_system else None,
        only_inputs=set(args.only_input) if args.only_input else None,
    )
    for invocation in manifest["invocations"]:
        print(f"{invocation['invocation_id']} status={invocation['status']} "
              f"claims={invocation['claim_records']} plan={invocation['plan_scope']} "
              f"review={invocation['review_state']}")
    print(f"Manifest: {args.output / runner.MANIFEST_NAME}")
    print(f"Schedule: {args.output / manifest['schedule_path']}")
    unprepared = [row for row in manifest["inputs"] if row["preparation_failure"] is not None]
    for row in unprepared:
        failure = row["preparation_failure"]
        print(f"scaneval: input {row['input_id']} could not be prepared: {failure['type']}: "
              f"{failure['message']}", file=sys.stderr)
    incomplete = [invocation["invocation_id"] for invocation in manifest["invocations"]
                  if invocation["status"] in INCOMPLETE_INVOCATION_STATUSES]
    if incomplete:
        print(f"scaneval: no usable scan from {len(incomplete)} invocation(s): "
              f"{', '.join(incomplete)}", file=sys.stderr)
    if manifest["status"] != "completed":
        print(f"scaneval: the run manifest status is {manifest['status']}", file=sys.stderr)
    return 1 if unprepared or incomplete or manifest["status"] != "completed" else 0


# How many of the files that still carry an original token ``blinding check`` names, most first;
# the preparation record lists up to :data:`scaneval.blinding.CUE_PATH_LIMIT` of them.
RETAINED_CUE_PATHS_SHOWN = 10


def _occurrences(counts: dict) -> str:
    return ", ".join(f"{token}={count}" for token, count in sorted(counts.items())) or "none"


def _retained_in(cues: dict) -> str:
    """The files of a blinded record's ``retained_identity_cues`` that still carry an original, most first."""
    shown = cues["paths"][:RETAINED_CUE_PATHS_SHOWN]
    more = cues["path_count"] - len(shown)
    return ("retained in: " + ", ".join(f"{entry['path']} ({entry['count']})" for entry in shown)
            + (f", and {more} more file(s)" if more > 0 else ""))


def _blinding_check(args: argparse.Namespace) -> int:
    """Dry-run a blinding map against every variant it covers, or one, and report what it would do.

    Each variant is fetched into the source cache (default: ``.repos`` beside the pack) and
    exported into a temporary directory that is removed afterwards; the map file is never written.
    The report names the files that still carry an original token, most occurrences first, so a
    curator can decide whether each is a cue to leave or an edit the map is missing.
    A fetch that fails means the check could not be carried out (2). A map that is not approved,
    or that any checked variant refuses, is a negative result (1): a run would refuse it.
    """
    document = blinding.load_map(args.map)
    pack = cases.load_pack(args.pack)
    covered = [variant["snapshot_id"] for variant in document["variants"]]
    if args.snapshot_id is not None:
        if args.snapshot_id not in covered:
            raise ContractError(f"map {document['map_id']} has no variant for snapshot {args.snapshot_id}; "
                                f"it covers {', '.join(covered)}")
        covered = [args.snapshot_id]
    cache_root = args.cache_root or args.pack.parent / runner.DEFAULT_CACHE_ROOT
    identity = blinding.map_identity(document)
    print(f"Map {identity['map_id']} {identity['map_version']}: {identity['map_sha256']}; content "
          f"{blinding.content_digest(document)}")
    gap = blinding.approval_gap(document)
    if gap is None:
        approvers = ", ".join(f"{review['reviewer']} ({review['role']})"
                              for review in blinding.approving_reviews(document))
        print(f"approval: approved by {approvers}")
    else:
        print(f"approval: not approved: {gap}")
    refused = []
    with tempfile.TemporaryDirectory(prefix="scaneval-blinding-check-") as scratch:
        for snapshot_id in covered:
            snapshot = cases.snapshot_by_id(pack, snapshot_id)
            cached = materialize.fetch_snapshot(snapshot["repository"]["url"], snapshot["commit"], cache_root)
            try:
                record = blinding.dry_run(document, cached, snapshot_id, Path(scratch) / snapshot_id)
            except (MaterializationError, ContractError) as exc:
                refused.append(snapshot_id)
                print(f"{snapshot_id}: refused: {exc}")
                continue
            applied = record["blinding"]
            print(f"{snapshot_id}: pass; original {applied['original_tree_hash']}, transformed "
                  f"{applied['transformed_tree_hash']}")
            for edit in applied["edits"]:
                lines = ", ".join(str(line) for line in edit["changed_lines"]) or "none"
                print(f"  {edit['edit_id']} {edit['path']}: {_occurrences(edit['occurrences'])}; "
                      f"changed line(s): {lines}")
            cues = applied["retained_identity_cues"]
            print(f"  {len(applied['validation'])} check(s) passed; retained identity cues: "
                  f"{cues['token_count']} token(s), {cues['total_occurrences']} occurrence(s) in "
                  f"{cues['path_count']} file(s); instruction files: "
                  f"{', '.join(cues['instruction_files']) or 'none'}")
            if cues["paths"]:
                print(f"  {_retained_in(cues)}")
    if refused:
        print(f"scaneval: blinding map refused for {len(refused)} variant(s): {', '.join(refused)}",
              file=sys.stderr)
    if gap is not None:
        print("scaneval: blinding map is not approved; a run refuses it", file=sys.stderr)
    return 1 if refused or gap is not None else 0


def _blinding_review(args: argparse.Namespace) -> int:
    """Record one review of a blinding map, by the reviewer the caller names, and replace the map."""
    _refuse_trial_path(args.map)
    document = blinding.load_map(args.map)
    recorded = blinding.record_review(document, reviewer=args.reviewer, role=args.role,
                                      decision=args.decision, note=args.note)
    _replace_file(args.map, lambda temporary: blinding.save_map(temporary, document))
    sys.stdout.write(cases.dump_json(recorded))
    return 0


def _blinding(args: argparse.Namespace) -> int:
    return {"check": _blinding_check, "review": _blinding_review}[args.blinding_command](args)


def _uri_bases(values: list[str]) -> dict[str, str]:
    """The ``--uri-base NAME=URI`` values as a mapping, refusing a malformed or repeated name.

    The name is everything before the first ``=``, so a value may itself hold one. Whether a value
    can name a directory inside the scanned tree is decided by :class:`scaneval.sarif.UriSettings`,
    not here; a name given twice is refused rather than letting the later value win unseen.
    """
    bases: dict[str, str] = {}
    for value in values:
        name, separator, uri = value.partition("=")
        if not separator or not name:
            raise ContractError(f"--uri-base {value!r} must be NAME=URI, a base id and where it points")
        if name in bases:
            raise ContractError(f"--uri-base names {name!r} twice; say where it points once")
        bases[name] = uri
    return bases


def _import_sarif(args: argparse.Namespace) -> int:
    """Import one run of a saved SARIF 2.1.0 log into a new bundle and say what it made of it.

    The work is :func:`scaneval.sarif.import_sarif`; this reads the operator's files, refuses a
    bundle path inside a trial directory, and reports. The pack is read and never rewritten. A log
    refused whole is exit 2 and leaves nothing behind. A bundle whose status is ``error`` (the
    log has no result list, or reports a failed run that left no claim) holds no usable scan and
    exits 1, as ``run`` does for such an invocation; ``partial`` exits 0 as it does there, with
    the reason printed. Every decision in the bundle is an unresolved machine draft, and the
    execution evidence is the log's own report, which this command says rather than verifies.
    """
    _refuse_trial_path(args.output)
    pack = cases.load_pack(args.pack)
    system_config = (None if args.system_config is None
                     else sarif.load_json_object(args.system_config, "--system-config"))
    normalization = (None if args.normalization is None
                     else sarif.load_json_object(args.normalization, "--normalization"))
    outcome = sarif.import_sarif(
        args.sarif_file, pack=pack, snapshot_id=args.snapshot_id, tree_hash=args.tree_hash,
        system_id=args.system_id, output=args.output, run_index=args.run_index, run_id=args.run_id,
        system_config=system_config, source_dir=args.source_dir, uri_bases=_uri_bases(args.uri_bases),
        source_root_uri=args.source_root_uri, normalization=normalization,
        include_suppressed=args.include_suppressed, max_bytes=args.max_bytes)
    result, record = outcome.result, outcome.record
    counts = record["counts"]
    print(f"Imported run {record['sarif']['run_index']} of {record['sarif']['run_count']} from "
          f"{args.sarif_file} as {result['run_id']}: status={result['status']} claims={counts['claims']} "
          f"excluded={counts['excluded']} losses={counts['losses']} "
          f"evidence_losses={counts['evidence_losses']}")
    print(f"Bundle review: {counts['bundle_review_flagged']} flagged, {counts['bundle_review_resolved']} "
          f"decided in the normalization file; bundles_resolved={str(result['bundles_resolved']).lower()}")
    print(f"Execution evidence: {record['execution']['evidence']}, as the log reports it; not verified")
    checked = "yes" if record["source_binding"]["source_dir_verified"] else "no"
    print(f"Locations checked against an exported tree: {checked}")
    print(f"Review state: {outcome.review_record['state']}; every decision stays unresolved until a "
          "person records one")
    print(f"Bundle: {args.output}")
    if "error" in result:
        print(f"scaneval: status {result['status']} ({result['error']['code']}): {result['error']['message']}",
              file=sys.stderr)
    if result["status"] == "error":
        print("scaneval: the imported log holds no usable scan", file=sys.stderr)
        return 1
    return 0


def _import(args: argparse.Namespace) -> int:
    return {"sarif": _import_sarif}[args.import_command](args)


def _diagnose_context_coverage(args: argparse.Namespace) -> int:
    """Attribute each labeled target to the invocations that were supplied its code region.

    Nothing is written into the bundle: a diagnostic is a reading of a run, not a part of it, and
    a bundle that grew a file every time someone asked a question of it would stop being the
    record the run left. The output path is create-only like every other one here.

    A bundle this cannot read is reported as 1 rather than 2, because the command ran and has an
    answer: this is not a bundle coverage attribution can be computed over. A usage error, a
    refused overwrite or an unreadable output path is still 2, from :func:`main`.
    """
    if args.out is not None:
        _refuse_trial_path(args.out)
    try:
        document = context_coverage_for_invocation(args.invocation, pack_path=args.pack)
    except DiagnosticsError as exc:
        print(f"scaneval: {exc}", file=sys.stderr)
        return 1
    content = _readable_json(document)
    if args.out is not None:
        _write_new(args.out, content)
    else:
        sys.stdout.write(content)
    return 0


def _diagnose(args: argparse.Namespace) -> int:
    return {"context-coverage": _diagnose_context_coverage}[args.diagnose_command](args)


def _aggregate(args: argparse.Namespace) -> int:
    """Aggregate run directories into one new report and print a one-line summary per system.

    The report is computed in full before the output file is created, so a refused aggregation
    leaves nothing behind. 0 means the report was computed; failed assignments, draft evidence, and
    unavailable intervals are recorded in it rather than turned into an exit code.
    """
    _refuse_trial_path(args.output)
    policy = aggregate.load_policy(args.policy) if args.policy else None
    report = aggregate.aggregate(args.run_dirs, policy=policy)
    _write_new(args.output, _json(report))
    for line in aggregate.summary(report):
        print(line)
    print(f"Report: {args.output}")
    return 0


def _compare(args: argparse.Namespace) -> int:
    """Compare two systems over run directories into one new report; refused unless their work matches.

    Two systems whose frozen evaluation contracts differ are refused (2) before anything is written.
    0 means the comparison was computed; it decides nothing about promotion.
    """
    _refuse_trial_path(args.output)
    policy = aggregate.load_policy(args.policy) if args.policy else None
    report = aggregate.compare(args.run_dirs, baseline=args.baseline, candidate=args.candidate,
                               policy=policy)
    _write_new(args.output, _json(report))
    for line in aggregate.comparison_summary(report):
        print(line)
    print(f"Comparison: {args.output}")
    return 0


def _figure(value: float | None) -> str:
    """A ratio or total as printed in a summary line: four significant digits, or n/a when null."""
    return "n/a" if value is None else f"{value:.4g}"


def _refuse_precision_path(output: Path) -> None:
    """Refuse a precision output inside a trial directory or inside a run directory.

    A run directory is what a precision frame is read from and bound to by digest, so a sample,
    queue, reviews file, or estimate written into one would change the run it describes. A run is
    recognized by a ``run-manifest.json`` in *output* or in any of its parents. Like the trial
    check, this compares resolved paths only: it is a check on the path, not an isolation boundary.
    """
    _refuse_trial_path(output)
    resolved = output.expanduser().resolve()
    for directory in (resolved, *resolved.parents):
        if (directory / runner.MANIFEST_NAME).is_file():
            raise ContractError(
                f"refusing to write {output} inside the run directory {directory}; precision documents "
                "stay outside the runs they are drawn from")


def _precision_sample(args: argparse.Namespace) -> int:
    """Build the frame from the run directories, draw the sample, and write it create-only.

    Strata that drew no unit are named on stderr, because no estimate from this sample will say
    anything about them; the sample is still written, and the command still exits 0.
    """
    _refuse_precision_path(args.output)
    frame = precision.build_frame(args.runs, population=args.population, budget=args.budget,
                                  systems=args.system, mode=args.mode, profile=args.profile)
    sample = precision.draw_sample(frame, size=args.size, seed=args.seed, stratify_by=args.stratify_by,
                                   allocation=args.allocation)
    _write_new(args.output, _json(sample))
    population = frame["population"]
    budget = f" (B={population['budget']})" if population["budget"] is not None else ""
    copies = sum(unit["population_copies"] for unit in frame["units"])
    print(f"Frame: {population['name']}{budget} over {len(frame['runs'])} run(s), systems "
          f"{', '.join(population['systems'])}: {len(frame['units'])} unit(s), {copies} copies inside it")
    exclusions = frame["exclusions"]
    if population["name"] == "first_b":
        print(f"Left out: {exclusions['unranked']['invocations']} unranked invocation(s) "
              f"({exclusions['unranked']['units']} unit(s)), {exclusions['bundle_unresolved']['invocations']} "
              f"bundle-unresolved invocation(s) ({exclusions['bundle_unresolved']['units']} unit(s)), "
              f"{exclusions['beyond_budget']['units']} unit(s) past B")
    design = sample["design"]
    stratified = (f" by {design['stratify_by']}, {design['allocation']} allocation"
                  if design["stratify_by"] else "")
    print(f"Design: {design['method']}{stratified}, size {design['size']}, seed {design['seed']} "
          f"({design['algorithm']})")
    for row in sample["strata"]:
        print(f"Stratum {row['stratum']}: {row['sampled_units']} of {row['population_units']} unit(s), "
              f"inclusion probability {_figure(row['inclusion_probability'])}")
    if sample["uncovered_strata"]:
        print(f"scaneval: warning: {len(sample['uncovered_strata'])} stratum/strata drew no unit "
              f"({', '.join(sample['uncovered_strata'])}); no estimate from this sample represents them",
              file=sys.stderr)
    print(f"Sample: {args.output}")
    return 0


def _precision_queue(args: argparse.Namespace) -> int:
    """Write the blinded review queue for reviewers; the sample itself stays with the evaluator."""
    _refuse_precision_path(args.output)
    sample = load_document(args.sample, precision.SAMPLE_KIND)
    queue = precision.review_queue(sample)
    _write_new(args.output, _readable_json(queue))
    print(f"Wrote {len(queue['items'])} blinded review item(s): {args.output}")
    return 0


def _precision_record(args: argparse.Namespace) -> int:
    """Append one stated human review to a reviews file, creating the file with the first one.

    The reviewer is whoever ``--reviewer`` names; nothing here fills one in. An existing file is
    verified (its chain, and the sample it is bound to) before anything is written, and replaced
    whole through the one replace function review records use; a new file is created exclusively.
    Appends are not locked, so record one review at a time.
    """
    _refuse_precision_path(args.reviews)
    sample = load_document(args.sample, precision.SAMPLE_KIND)
    unit_id = precision.unit_for_item(sample, args.item) if args.item is not None else args.unit
    existing = None
    if args.reviews.exists() or args.reviews.is_symlink():
        existing = load_document(args.reviews, precision.REVIEWS_KIND)
    updated = precision.record_review(sample, existing, unit_id=unit_id, reviewer=args.reviewer,
                                      role=args.role, outcome=args.outcome, note=args.note)
    if existing is None:
        _write_new(args.reviews, _json(updated))
    else:
        _replace_document(args.reviews, updated)
    named = args.item if args.item is not None else f"unit {unit_id}"
    print(f"Recorded an {args.role} review of {named}: {args.outcome} "
          f"({len(updated['reviews'])} review(s) in {args.reviews})")
    return 0


def _precision_estimate(args: argparse.Namespace) -> int:
    """Estimate reviewed precision from a sample and its reviews, write it, and summarize it.

    An incomplete review or a partly covered population is reported, not refused: the document
    says so, and so does stderr. Without ``--reviews`` every sampled unit is nonresponse.
    """
    _refuse_precision_path(args.output)
    sample = load_document(args.sample, precision.SAMPLE_KIND)
    reviews = load_document(args.reviews, precision.REVIEWS_KIND) if args.reviews is not None else None
    document = precision.estimate(sample, reviews, confidence=args.confidence)
    _write_new(args.output, _json(document))
    coverage = document["coverage"]
    classes = document["sample"]["classes"]
    bases = document["sample"]["bases"]
    totals = document["totals"]
    sensitivity = document["sensitivity"]
    interval = document["interval"]
    print(f"Sample: {document['sample']['selected_units']} unit(s) of {coverage['population_units']}; "
          f"coverage {_figure(coverage['share'])}")
    print(f"Reviewed: true {classes['true']}, false {classes['false']}, unresolved {classes['unresolved']} "
          f"(disagreement {bases['disagreement']}, nonresponse {bases['nonresponse']}), "
          f"out of scope {classes['out_of_scope']}")
    print(f"Weighted totals: true {_figure(totals['true'])}, false {_figure(totals['false'])}, "
          f"unresolved {_figure(totals['unresolved'])}, out of scope {_figure(totals['out_of_scope'])}")
    print(f"Resolved precision {_figure(document['precision_resolved'])}; unresolved share "
          f"{_figure(document['unresolved_share'])}; sensitivity range [{_figure(sensitivity['lower'])}, "
          f"{_figure(sensitivity['upper'])}] (not a confidence interval)")
    bounds = (f"[{_figure(interval['lower'])}, {_figure(interval['upper'])}]"
              if interval["lower"] is not None else "no bounds")
    print(f"Approximate {_figure(interval['confidence'])} interval: {bounds} ({interval['state']})")
    burden = document["duplicate_burden"]
    print(f"Duplicate burden: {burden['copies']} copies over {burden['units']} unit(s) "
          f"({_figure(burden['copies_per_unit'])} per unit)")
    print(f"Evidence grade: {document['evidence_grade']}")
    if coverage["uncovered_strata"]:
        print(f"scaneval: warning: the sample covers {coverage['covered_units']} of "
              f"{coverage['population_units']} units; uncovered strata are not estimated", file=sys.stderr)
    if document["evidence_grade"] == "incomplete":
        print(f"scaneval: warning: the review is incomplete: {bases['nonresponse']} unit(s) unreviewed and "
              f"{bases['disagreement']} in disagreement without adjudication", file=sys.stderr)
    print(f"Estimate: {args.output}")
    return 0


def _precision(args: argparse.Namespace) -> int:
    return {"sample": _precision_sample, "queue": _precision_queue, "record": _precision_record,
            "estimate": _precision_estimate}[args.precision_command](args)


def _refuse_gate_path(output: Path) -> None:
    """Refuse a gate decision inside a trial directory or inside a run directory.

    A decision binds by digest to the runs its comparison read, so one written into a run directory
    would sit inside the evidence it judges. A run is recognized by a ``run-manifest.json`` in *output*
    or in any of its parents. Like the trial check, this compares resolved paths only: it is a check on
    the path, not an isolation boundary.
    """
    _refuse_trial_path(output)
    resolved = output.expanduser().resolve()
    for directory in (resolved, *resolved.parents):
        if (directory / runner.MANIFEST_NAME).is_file():
            raise ContractError(
                f"refusing to write {output} inside the run directory {directory}; a gate decision binds to the "
                "runs its comparison read and stays outside them")


def _gate(args: argparse.Namespace) -> int:
    """Hold a comparison to a policy, write the decision create-only, and say what did not pass.

    The decision is computed in full before the output file is created, so a refusal leaves nothing
    behind. 0 means the outcome is a pass; 1 means it is a fail or is inconclusive, and the summary
    names every failed and every unresolved requirement with its reason; a refusal is 2.
    """
    _refuse_gate_path(args.output)
    policy = gate.load_policy(args.policy)
    comparison = load_document(args.comparison, gate.COMPARISON_KIND)
    estimates = [load_document(path, gate.ESTIMATE_KIND) if path is not None else None
                 for path in (args.precision_baseline, args.precision_candidate)]
    decision = gate.evaluate_gate(policy, comparison, *estimates)
    _write_new(args.output, _json(decision))
    for line in gate.summary(decision):
        print(line)
    print(f"Decision: {args.output}")
    return 0 if decision["outcome"] == gate.PASS else 1


def _warn_unreviewed(state: str) -> None:
    """Say on stderr that a bundle carries no recorded review. The report itself is unchanged."""
    if state in UNREVIEWED_REVIEW_STATES:
        print(f"scaneval: warning: review record is {state}; this report shows unreviewed decisions, "
              "not benchmark evidence", file=sys.stderr)


def _add_new_version(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--new-version", help="open a new draft version of a pack that is no longer "
                                              "a draft; required before changing a reviewed or released pack")


def _add_corpus_commands(sub: argparse._SubParsersAction) -> None:
    corpus = sub.add_parser("corpus", help="build and mechanically check an evaluator-side case pack")
    commands = corpus.add_subparsers(dest="corpus_command", required=True)

    started = commands.add_parser("init", help="create a new draft pack file; the path must not exist")
    started.add_argument("pack", type=Path)
    started.add_argument("--namespace", required=True)
    started.add_argument("--pack-id", required=True)
    started.add_argument("--description", required=True)
    started.add_argument("--version", default="0.1.0-draft")

    snapshot = commands.add_parser("add-snapshot", help="pin one repository commit; license stays unverified")
    snapshot.add_argument("pack", type=Path)
    snapshot.add_argument("--snapshot-id", required=True)
    snapshot.add_argument("--url", required=True, help="repository URL without credentials")
    snapshot.add_argument("--name", required=True)
    snapshot.add_argument("--commit", required=True, help="full 40-hex commit SHA")
    snapshot.add_argument("--language", required=True, action="append", dest="languages", choices=LANGUAGES)
    snapshot.add_argument("--workload", required=True, choices=WORKLOADS)
    snapshot.add_argument("--component-role", required=True, choices=COMPONENT_ROLES)
    snapshot.add_argument("--reference", required=True, help="how this commit was chosen")
    snapshot.add_argument("--license-spdx")
    snapshot.add_argument("--license-note", default=LICENSE_NOTE)
    snapshot.add_argument("--historical-url")
    snapshot.add_argument("--role", choices=SNAPSHOT_ROLES, default="vulnerable")
    _add_new_version(snapshot)

    imported = commands.add_parser("import", help="draft one case from a supplied artifact; never a label")
    imported.add_argument("pack", type=Path)
    imported.add_argument("--case-id", required=True)
    imported.add_argument("--snapshot-id", required=True)
    imported.add_argument("--represents", required=True,
                          help="This case tests <mechanism> under <assumptions>, and adds <coverage>.")
    imported.add_argument("--workload", required=True, choices=WORKLOADS)
    imported.add_argument("--component-role", required=True, choices=COMPONENT_ROLES)
    artifact = imported.add_mutually_exclusive_group(required=True)
    artifact.add_argument("--fix-commit", help="fix commit SHA; requires --repo")
    artifact.add_argument("--finding", type=Path, help="JSON allegation: allegation, path, kind, lines, source")
    artifact.add_argument("--document", type=Path, help="internal document to reference")
    imported.add_argument("--repo", help="repository URL that --fix-commit belongs to")
    imported.add_argument("--section", help="section of --document to reference")
    imported.add_argument("--kind")
    imported.add_argument("--description")
    imported.add_argument("--alias", action="append", dest="aliases", default=[],
                          help="CVE or GHSA identifier; repeatable")
    _add_new_version(imported)

    checked = commands.add_parser("validate", help="schema-check a pack, or export one snapshot and run L1 checks")
    checked.add_argument("pack", type=Path)
    checked.add_argument("--snapshot-id")
    checked.add_argument("--cache-root", type=Path)
    checked.add_argument("--trial-root", type=Path)
    _add_new_version(checked)

    approved = commands.add_parser("approve", help="record one explicit human review of a case")
    approved.add_argument("pack", type=Path)
    approved.add_argument("--case-id", required=True)
    approved.add_argument("--reviewer", required=True, help="the reviewer's own name; never supplied by the tool")
    approved.add_argument("--role", required=True, choices=REVIEW_ROLES)
    approved.add_argument("--level", required=True, choices=cases.LEVELS)
    approved.add_argument("--note", required=True)
    _add_new_version(approved)

    admitted = commands.add_parser("admit", help="record an admission decision for a case")
    admitted.add_argument("pack", type=Path)
    admitted.add_argument("--case-id", required=True)
    admitted.add_argument("--decision", required=True, choices=ADMISSION_DECISIONS)
    admitted.add_argument("--by", required=True)
    admitted.add_argument("--reason", required=True)
    _add_new_version(admitted)

    disposition = commands.add_parser(
        "disposition", help="record a screening disposition and the stated reason for it")
    disposition.add_argument("pack", type=Path)
    disposition.add_argument("--case-id", required=True)
    disposition.add_argument("--value", required=True, choices=cases.DISPOSITIONS)
    disposition.add_argument("--reason", required=True)
    _add_new_version(disposition)

    change_set = commands.add_parser(
        "add-change-set",
        help="declare a base/head boundary a native PR review runs between; the first one upgrades "
             "the pack to 2.1")
    change_set.add_argument("pack", type=Path)
    change_set.add_argument("--change-set-id", required=True)
    change_set.add_argument("--base-snapshot-id", required=True, help="a snapshot the pack declares")
    change_set.add_argument("--head-snapshot-id", required=True,
                            help="a snapshot of the same repository; a PR review reads this tree, and "
                                 "every item scored under the change set is on it")
    change_set.add_argument("--boundary", required=True, choices=cases.CHANGE_SET_BOUNDARIES,
                            help="introducing: the head introduces a root cause the base lacks; repair: "
                                 "the head repairs one the base carries; ordinary: neither")
    change_set.add_argument("--review-scope", required=True, choices=cases.CHANGE_SET_SCOPES,
                            help="the scope the review is declared to score at, stated before any run")
    change_set.add_argument("--description", required=True)
    change_set.add_argument("--reference", help="where the change came from, such as a pull request URL")
    _add_new_version(change_set)

    scoped = commands.add_parser(
        "pr-scope",
        help="state how a target, or one control, is scored in a change set's PR review; an approval "
             "recorded before it no longer covers the changed labels")
    scoped.add_argument("pack", type=Path)
    scoped.add_argument("--case-id", required=True)
    scoped.add_argument("--control-id", help="a control of the case; without it the entry is the target's")
    scoped.add_argument("--change-set-id", required=True)
    scoped.add_argument("--relation", required=True, choices=cases.PR_RELATIONS,
                        help="how the item relates to the change; a target is never repaired")
    scoped.add_argument("--code-scope", required=True, choices=cases.PR_CODE_SCOPES,
                        help="changed: the code the item is about is part of the change; context: it is "
                             "reached from the change")
    scoped.add_argument("--note")
    _add_new_version(scoped)

    canonical = commands.add_parser(
        "canonical",
        help="state which canonical root cause a target, or which property a control, belongs to; an "
             "approval recorded before it no longer covers the changed labels")
    canonical.add_argument("pack", type=Path)
    canonical.add_argument("--case-id", required=True)
    canonical.add_argument("--control-id", help="a control of the case; without it the id is the target's")
    canonical.add_argument("--canonical-id", required=True)
    _add_new_version(canonical)


def _add_diagnose_commands(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser("diagnose", help="read one saved invocation bundle and report a "
                                             "diagnostic; no score changes")
    commands = parser.add_subparsers(dest="diagnose_command", required=True)

    coverage = commands.add_parser(
        "context-coverage",
        help="for each labeled target, whether its code region was supplied to the model, "
             "and in which invocation")
    coverage.add_argument("invocation", type=Path, help="an invocations/<name>/ directory")
    coverage.add_argument("--pack", type=Path,
                          help="case pack holding the accepted locations; default is "
                               "evaluator/pack.json of the run the invocation belongs to")
    coverage.add_argument("--out", type=Path, help="new JSON file; default stdout")


def _add_blinding_commands(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser("blinding", help="dry-run and review a metadata blinding map")
    commands = parser.add_subparsers(dest="blinding_command", required=True)

    checked = commands.add_parser(
        "check", help="apply a map to each variant in a temporary directory and report the result; "
                      "writes nothing to the map")
    checked.add_argument("map", type=Path, help="the blinding map to apply; never written")
    checked.add_argument("--pack", required=True, type=Path, help="the pack declaring the variants' snapshots")
    checked.add_argument("--snapshot-id", help="check this variant only")
    checked.add_argument("--cache-root", type=Path, help="source cache; default .repos beside the pack")

    reviewed = commands.add_parser("review", help="record one review of the map as it stands")
    reviewed.add_argument("map", type=Path, help="the blinding map; rewritten in place with the review appended")
    reviewed.add_argument("--reviewer", required=True, help="the reviewer's own name; never supplied by the tool")
    reviewed.add_argument("--role", required=True, choices=blinding.REVIEW_ROLES)
    reviewed.add_argument("--decision", required=True, choices=blinding.REVIEW_DECISIONS,
                          help="the latest review decides: a run applies the map only after an approve "
                               "of its current content")
    reviewed.add_argument("--note", required=True)


def _add_review_commands(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser("review", help="draft, record, approve, and inspect the review of one bundle")
    commands = parser.add_subparsers(dest="review_command", required=True)

    started = commands.add_parser("init", help="route saved claims to planned targets as unresolved candidates")
    started.add_argument("bundle", type=Path)
    started.add_argument("--pack", required=True, type=Path)

    recorded = commands.add_parser(
        "record", help="re-draft the review record after a human edited evaluator/decisions.json")
    recorded.add_argument("bundle", type=Path)
    recorded.add_argument("--note", action="append", dest="notes", default=[],
                          help="note to store in the new record; repeatable")

    approved = commands.add_parser("approve", help="record one explicit human approval of the decisions")
    approved.add_argument("bundle", type=Path)
    approved.add_argument("--reviewer", required=True, help="the reviewer's own name; never supplied by the tool")
    approved.add_argument("--note", required=True)

    status = commands.add_parser("status", help="report missing, stale, draft, or human_approved")
    status.add_argument("bundle", type=Path)


def _add_import_commands(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser("import", help="import a saved scanner log into a new bundle, offline")
    commands = parser.add_subparsers(dest="import_command", required=True)

    log = commands.add_parser(
        "sarif", help="import one run of a saved SARIF 2.1.0 log (profile sarif-import-1)",
        description="Import one run of a saved SARIF 2.1.0 log into a new bundle that review, score, "
                    "replay, and report read unchanged. Nothing the log names is fetched or opened, "
                    "every decision is an unresolved draft, and the log's execution report is recorded "
                    "unverified. See docs/SARIF_IMPORT.md.")
    log.add_argument("sarif_file", type=Path, metavar="SARIF_FILE", help="the saved log; read once, never changed")
    log.add_argument("--pack", required=True, type=Path, help="case pack holding the snapshot; read, never rewritten")
    log.add_argument("--snapshot-id", required=True, help="the pack snapshot the scan read")
    log.add_argument("--tree-hash", required=True,
                     help="sha256:<64 hex> of the exported tree the scan read; the result binds to it")
    log.add_argument("--system-id", required=True, help="the system that produced the log; recorded as stated")
    log.add_argument("--output", required=True, type=Path, help="new bundle directory, must not exist")
    log.add_argument("--run-index", type=int, help="which run to import from a log holding several, from 0")
    log.add_argument("--run-id", help="run id; default import-<12 hex of the log's SHA-256>-r<run index>")
    log.add_argument("--system-config", type=Path,
                     help="JSON object describing the system; only its canonical SHA-256 is recorded")
    log.add_argument("--source-dir", type=Path,
                     help="the exported tree; it must hash to --tree-hash, and every mapped path and line is "
                          "checked against it")
    log.add_argument("--uri-base", action="append", dest="uri_bases", default=[], metavar="NAME=URI",
                     help="where a uriBaseId points: a directory inside the scanned tree ending in '/' ('.' for "
                          "its root), or a file URI under --source-root-uri; used before the log's own "
                          "originalUriBaseIds; repeatable")
    log.add_argument("--source-root-uri", metavar="FILE_URI",
                     help="absolute file URI of the scanned tree's root where the log was written; an absolute "
                          "file URI in the log maps only under it")
    log.add_argument("--normalization", type=Path,
                     help="recorded bundle-review decisions for this log, bound to its SHA-256; never written "
                          "by the tool")
    log.add_argument("--include-suppressed", action="store_true",
                     help="import suppressed results as claims; every suppression is recorded either way")
    log.add_argument("--max-bytes", type=int, default=sarif.DEFAULT_MAX_BYTES,
                     help="refuse a log larger than this many bytes (default %(default)s)")


def _add_aggregate_commands(sub: argparse._SubParsersAction) -> None:
    run_dirs_help = "a run directory written by scaneval run (run manifest 2.1 and its frozen schedule)"
    policy_help = ("aggregation-policy JSON; default: the built-in policy, which the report records in "
                   "full with its hash")
    output_help = "new JSON file, outside any trial directory"
    aggregating = sub.add_parser(
        "aggregate",
        help="weight every scheduled assignment of saved runs into corpus metrics; no scan, no judge",
        description="Read run directories and report, per (mode, profile) view, system, slice, and "
                    "weighting, full-output and budgeted recall, control false-alarm rates and bounds, "
                    "pair correctness, completion, claim volume, usage, and cluster-bootstrap intervals. "
                    "Every scheduled assignment is an observation; a failed one stays in every "
                    "denominator.")
    aggregating.add_argument("run_dirs", nargs="+", type=Path, metavar="RUN_DIR", help=run_dirs_help)
    aggregating.add_argument("--policy", type=Path, help=policy_help)
    aggregating.add_argument("--output", required=True, type=Path, help=output_help)

    comparing = sub.add_parser(
        "compare",
        help="compare a candidate with a baseline assigned the same frozen work; paired intervals",
        description="Aggregate two systems over run directories and report candidate minus baseline "
                    "with paired cluster-bootstrap intervals. Refused unless both were assigned exactly "
                    "the same frozen work (inputs, plans, levels, budgets, repetitions, pairs, and "
                    "pack). Decides no promotion.")
    comparing.add_argument("run_dirs", nargs="+", type=Path, metavar="RUN_DIR", help=run_dirs_help)
    comparing.add_argument("--baseline", required=True, help="system id of the baseline")
    comparing.add_argument("--candidate", required=True, help="system id of the candidate")
    comparing.add_argument("--policy", type=Path, help=policy_help)
    comparing.add_argument("--output", required=True, type=Path, help=output_help)


def _add_precision_commands(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser(
        "precision", help="sample delivered claims for human review and estimate reviewed precision; "
                          "no decision or score changes")
    commands = parser.add_subparsers(dest="precision_command", required=True)

    sampled = commands.add_parser(
        "sample", help="list a claim population from run directories and draw a seeded probability sample")
    sampled.add_argument("runs", nargs="+", type=Path, metavar="RUN_DIR",
                         help="run directory written by 'scaneval run' (2.1 manifest and schedule)")
    sampled.add_argument("--output", required=True, type=Path, help="new JSON file, outside any trial directory")
    sampled.add_argument("--population", required=True, choices=precision.POPULATIONS,
                         help="first_b: unique claims with a copy in the first --budget native positions; "
                              "full: every unique delivered claim")
    sampled.add_argument("--budget", type=int, help="B, required for first_b")
    sampled.add_argument("--size", required=True, type=int, help="number of units to draw")
    sampled.add_argument("--seed", required=True, type=int,
                         help="non-negative integer, stated before the draw and recorded in the sample")
    sampled.add_argument("--system", action="append",
                         help="system id whose claims to sample; repeatable; default every scheduled system")
    sampled.add_argument("--mode", choices=precision.MODES, default="full")
    sampled.add_argument("--profile", choices=precision.PROFILES, default="standard")
    sampled.add_argument("--stratify-by", choices=precision.STRATIFICATIONS)
    sampled.add_argument("--allocation", choices=precision.ALLOCATIONS,
                         help="stratum sizes for --stratify-by; default proportional")

    queued = commands.add_parser(
        "queue", help="export the sampled claims for reviewers, each system shown only by an alias")
    queued.add_argument("sample", type=Path)
    queued.add_argument("--output", required=True, type=Path, help="new JSON file")

    recorded = commands.add_parser(
        "record", help="append one human review of a sampled claim to a chained reviews file")
    recorded.add_argument("reviews", type=Path, help="reviews file; the first review creates it")
    recorded.add_argument("--sample", required=True, type=Path)
    target = recorded.add_mutually_exclusive_group(required=True)
    target.add_argument("--item", help="item id from the review queue")
    target.add_argument("--unit", help="unit id from the sample")
    recorded.add_argument("--reviewer", required=True, help="the reviewer's own name; never supplied by the tool")
    recorded.add_argument("--role", required=True, choices=precision.ROLES)
    recorded.add_argument("--outcome", required=True, choices=precision.OUTCOMES)
    recorded.add_argument("--note", default="")

    estimated = commands.add_parser(
        "estimate", help="estimate reviewed precision from a sample and its recorded reviews")
    estimated.add_argument("sample", type=Path)
    estimated.add_argument("--reviews", type=Path, help="reviews file; without one every sampled unit is "
                                                        "unreviewed")
    estimated.add_argument("--output", required=True, type=Path, help="new JSON file")
    estimated.add_argument("--confidence", type=float, default=precision.DEFAULT_CONFIDENCE,
                           help="confidence of the approximate interval; default 0.95")


def _add_gate_commands(sub: argparse._SubParsersAction) -> None:
    gating = sub.add_parser(
        "gate",
        help="hold a comparison to a gate policy and write a decision; promotes nothing",
        description="Hold a saved comparison of a candidate against a baseline, and optionally a reviewed-precision "
                    "estimate of each system, to a gate policy, and write the decision: pass only when every "
                    "requirement the policy declares holds, fail when any fails, inconclusive when none fails and "
                    "any could not be settled. Every failed or unresolved requirement is named on stdout with its "
                    "reason. Exit 0 for a pass, 1 for a fail or an inconclusive decision, 2 when it could not "
                    "evaluate. No scan, model, or judge runs, and nothing is approved or promoted.")
    gating.add_argument("--policy", required=True, type=Path,
                        help="gate-policy JSON, frozen before any result is read")
    gating.add_argument("--comparison", required=True, type=Path,
                        help="comparison-report JSON written by 'scaneval compare'")
    gating.add_argument("--precision-baseline", type=Path,
                        help="precision-estimate JSON of the baseline system; needed only when the policy bounds a "
                             "decrease in precision from it")
    gating.add_argument("--precision-candidate", type=Path,
                        help="precision-estimate JSON of the candidate system alone; needed when the policy "
                             "declares precision")
    gating.add_argument("--output", required=True, type=Path,
                        help="new JSON file, outside any trial or run directory")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate a versioned JSON contract")
    validate.add_argument("kind", choices=sorted(CONTRACT_KINDS))
    validate.add_argument("path", type=Path)
    scoring = sub.add_parser("score", help="score saved output with frozen evaluator decisions")
    for name in ("plan", "result", "decisions"):
        scoring.add_argument(f"--{name}", required=True, type=Path)
    scoring.add_argument("--output", type=Path, help="new JSON file; default stdout")
    replay = sub.add_parser("replay", help="recompute a saved bundle offline")
    replay.add_argument("bundle", type=Path)
    replay.add_argument("--output", type=Path, help="new JSON file; default stdout")
    report = sub.add_parser("report", help="score a saved bundle and render a standalone HTML report")
    report.add_argument("bundle", type=Path)
    report.add_argument("--output", required=True, type=Path)
    demo = sub.add_parser("demo", help="create a fabricated conformance bundle, no scanner execution")
    demo.add_argument("directory", type=Path, help="new directory, must not exist")
    _add_corpus_commands(sub)
    planning = sub.add_parser("plan", help="build one evaluation plan from a pack and a materialized input")
    planning.add_argument("--pack", required=True, type=Path)
    planning.add_argument("--snapshot-id", required=True,
                          help="the snapshot the labels refer to; for a PR plan, the change set's head snapshot")
    planning.add_argument("--tree-hash", required=True,
                          help="the export of --snapshot-id the labels and mechanical checks refer to")
    planning.add_argument("--output", required=True, type=Path, help="new JSON file, outside any trial directory")
    planning.add_argument("--mode", choices=("full", "pr"), default="full",
                          help="pr alone selects the pack's pr review budgets for a full plan; with "
                               "--change-set-id it plans that change set's PR review")
    planning.add_argument("--change-set-id", help="a change set the pack declares; plans its PR review, and "
                                                  "needs --base-tree-hash, --head-tree-hash, and --diff-sha256")
    planning.add_argument("--base-tree-hash", help="sha256:<64 hex> of the tree a scanner is handed as the base")
    planning.add_argument("--head-tree-hash",
                          help="sha256:<64 hex> of the tree a scanner is handed as the head; the export's own "
                               "hash for a standard input")
    planning.add_argument("--diff-sha256", help="sha256:<64 hex> of the recorded diff between the two trees")
    _add_review_commands(sub)
    _add_diagnose_commands(sub)
    _add_blinding_commands(sub)
    _add_precision_commands(sub)
    running = sub.add_parser("run", help="execute one frozen run configuration into a new directory")
    running.add_argument("config", type=Path)
    running.add_argument("--output", required=True, type=Path, help="new directory, must not exist")
    running.add_argument("--only-system", action="append", help="system id to run; repeatable")
    running.add_argument("--only-input", action="append",
                         help="input id to run (a 2.0 configuration's snapshot id); repeatable")
    running.add_argument("--workspace-root", type=Path)
    _add_import_commands(sub)
    _add_aggregate_commands(sub)
    _add_gate_commands(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            load_document(args.path, args.kind)
            print(f"Valid {args.kind}: {args.path}")
        elif args.command == "precision":
            return _precision(args)
        elif args.command == "gate":
            return _gate(args)
        elif args.command == "demo":
            _demo(args.directory)
        elif args.command in ("aggregate", "blinding", "compare", "corpus", "diagnose", "import", "plan",
                              "review", "run"):
            return {"aggregate": _aggregate, "blinding": _blinding, "compare": _compare, "corpus": _corpus,
                    "diagnose": _diagnose, "import": _import, "plan": _plan, "review": _review,
                    "run": _run}[args.command](args)
        else:
            if args.output:
                _refuse_trial_path(args.output)
            review_state = None
            if args.command == "score":
                plan = load_document(args.plan, "evaluation-plan")
                result = load_document(args.result, "scan-result")
                decisions = load_document(args.decisions, "review-decisions")
            else:
                # replay and report only read, so the bundle path is resolved and used as it
                # lands: a bundle named through a symlinked parent is replayed, not refused.
                bundle = args.bundle.resolve()
                plan, result, decisions = load_bundle(bundle)
                # The state is reported, never checked: it says what the record on disk claims.
                review_state = review.review_status(bundle, guard_symlinks=False)
            if args.command == "report":
                _warn_unreviewed(review_state)
            elif args.command == "replay" and review_state != APPROVED_REVIEW_STATE:
                print(f"scaneval: review state {review_state}: these numbers come from decisions with "
                      "no recorded human approval", file=sys.stderr)
            record = score(plan, result, decisions)
            content = (render_report(record, result, plan, review_state=review_state)
                       if args.command == "report" else _json(record))
            if args.output:
                _write_new(args.output, content)
            else:
                sys.stdout.write(content)
        return 0
    except (ContractError, MaterializationError, AdapterError, ExecutionError, RuntimeError,
            OSError, UnicodeError) as exc:
        print(f"scaneval: {exc}", file=sys.stderr)
        return 2
