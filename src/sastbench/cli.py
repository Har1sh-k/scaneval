"""Local validation, saved-output scoring, deterministic replay, and the corpus-to-run workflow.

The evaluation commands (validate, score, replay, report, demo) stay offline and read saved
documents only. The corpus, plan, review, and run commands drive :mod:`sastbench.cases`,
:mod:`sastbench.materialize`, :mod:`sastbench.review`, and :mod:`sastbench.runner`; this module
holds no pack, planning, routing, execution, or scoring logic of its own.

Boundaries this module keeps. No command infers approval: ``corpus approve`` and ``review
approve`` record the reviewer name the caller supplies, and nothing else raises a case or a
review record above the state it already has. An imported artifact becomes a draft case with a
``needs_evidence`` disposition, never a label, and a license is never recorded as verified here.
Pack files, plans, and decisions stay evaluator-side: no command writes them into an exported
source tree or a scanner workspace.

What each command writes:

- A pack file is rewritten in place. Every corpus command that changes a pack (``add-snapshot``,
  ``import``, ``validate --snapshot-id``, ``approve``, ``admit``, ``disposition``) writes a
  temporary file beside it and renames that over the pack, so a reader sees the whole old pack
  or the whole new one. The previous version is not kept, and a pack whose status is no longer
  ``draft`` is refused unless ``--new-version`` opens a new draft version of it.
- ``evaluator/review-record.json`` is replaced the same way by ``review record`` and
  ``review approve``, through the one replace function :mod:`sastbench.review` uses. Both
  refuse a bundle reached through a symlink before writing.
- Everything else is create-only: an existing output path is refused, never overwritten.

The read-only bundle commands do not refuse a symlink: ``replay``, ``report`` and ``review
status`` resolve the bundle path and report on the bundle it reaches, so a bundle named through
a symlinked parent is read rather than refused. They write nothing into the bundle.

No command writes inside a materialized trial directory: the output path of ``plan``, ``run``,
``demo``, ``score``, ``replay`` and ``report``, the pack path of ``corpus init``, the bundle
argument of ``review init``, ``review record`` and ``review approve``, and the directory
``corpus validate`` exports a snapshot into, are each refused when a trial's ``provenance.json``
and ``source`` sit in them or above them. That keeps evaluator material out of the tree a
scanner is handed; it is a check on the path, not an isolation boundary.

Exit codes. 2 means the command could not be carried out: a usage or contract error, a refused
overwrite, a failed fetch or export. 1 means the command ran and reports a negative result: a
mechanical check set failed, or a run produced no usable scan from some system. 0 means it ran
and reports nothing wrong, which is not a statement that any label or decision is correct.
"""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from urllib.parse import urlsplit

from . import __version__, cases, materialize, review, runner
from .adapters.base import AdapterError
from .contracts import CONTRACT_KINDS, ContractError, canonical_json, load_document
from .demo import SOURCE, demo_documents
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
# sastbench/schemas stays authoritative: every value below is validated again on the way in.
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


def _read_json(path: Path) -> dict:
    """Load a supplied JSON artifact that has no contract of its own. Content is data, not truth."""
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"could not load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{path} must contain a JSON object")
    return value


def _create_pack(path: Path, pack: dict) -> None:
    """Claim *path* exclusively, then let :func:`sastbench.cases.save_pack` write the pack into it."""
    with path.open("x", encoding="utf-8", newline="\n"):
        pass
    cases.save_pack(path, pack)


def _save_pack(path: Path, pack: dict) -> None:
    """Validate *pack* and replace the pack file at *path* through a temporary file beside it.

    A pack is the one kind of document this module rewrites. The replacement is a rename, so a
    concurrent reader sees the old pack or the new one and never a half-written file, and an
    invalid pack raises before the old file is touched. The previous version is not kept here:
    version history belongs in the repository, not in a backup copy this command leaves behind.
    A symlink at *path* is replaced rather than written through, and the regular file that
    replaces it keeps the owner-only mode of the temporary file rather than the mode of the
    symlink's target: permissions are carried over by :func:`sastbench.review._keep_mode`, which
    every replaced review record goes through as well. *path* is expected to already exist,
    because every caller loads the pack from it first; :func:`_create_pack` is what writes a new
    one.
    """
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=str(path.parent),
        prefix=path.name + ".", suffix=".tmp", delete=False,
    )
    handle.close()
    temporary = Path(handle.name)
    try:
        cases.save_pack(temporary, pack)
        _keep_mode(temporary, path)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _pack_for_change(args: argparse.Namespace) -> dict:
    """Load the pack a command is about to rewrite, applying ``--new-version`` when it is given.

    A pack that is no longer a draft is what plans, manifests, and reports already cite by
    version and hash, so this refuses to edit one in place. ``--new-version`` opens a new draft
    version instead and records the version and status it came from in the pack notes. Reopening
    a pack changes nothing else: it re-checks nothing, approves nothing, and withdraws no
    recorded review or admission.
    """
    pack = cases.load_pack(args.pack)
    version = getattr(args, "new_version", None)
    if version is None:
        if pack["status"] != "draft":
            raise ContractError(
                f"pack status is {pack['status']}, not draft; changing it needs "
                "--new-version <version>, which opens a new draft version of this pack")
        return pack
    version = version.strip()
    if not version:
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


def _legacy_line(value, label: str) -> None:
    """Refuse a legacy line number that is not an integer of at least 1. ``True`` is not 1."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ContractError(f"{label} must be an integer of at least 1, not {value!r}")


def _legacy_document(path: Path) -> dict:
    """Load a legacy v1 case record and refuse the shapes the migration cannot read.

    This checks structure, not truth: it says nothing about whether the record's regions,
    identifiers, or dates are correct, and every value it accepts still enters the pack as
    draft evidence. It exists so a malformed file is reported as a refusal naming the file
    rather than raising out of :func:`sastbench.cases.draft_case_from_legacy` as a traceback,
    so every refusal here names the file. Fields the migration does not read are left alone,
    and the schema check in ``cases`` remains the authority on the case this produces.

    The strings the migration copies into a case must already be strings: an identifier, kind,
    title, or description of another type would become an alias or a description that misstates
    the record, and a ``canonicalKind``, ``title``, ``description``, ``cve``, ``ghsa``, or
    ``fixCommit`` key present as ``null`` is refused rather than read as absent, so a record
    that meant to name one is corrected instead of quietly losing it. ``canonicalKind`` in
    particular is read with a default by the migration, so a present ``null`` would defeat that
    default and fail later against the case schema instead of here. A line bound present as
    ``null`` counts as present, because dropping it would silently widen the region to the whole
    file, and a fix commit without a repository is refused because the evidence reference it
    would produce is ``'<repo>@<sha>'``.
    """
    legacy = _read_json(path)
    for key in ("canonicalKind", "title", "description"):
        if key in legacy and not isinstance(legacy[key], str):
            raise ContractError(f"{path}: {key} must be a string")
    real = legacy.get("realWorld")
    if real is not None and not isinstance(real, dict):
        raise ContractError(f"{path}: realWorld must be a JSON object")
    real = real or {}
    disclosure = real.get("disclosure")
    if disclosure is not None and not isinstance(disclosure, dict):
        raise ContractError(f"{path}: realWorld.disclosure must be a JSON object")
    for key in ("cve", "ghsa", "fixCommit"):
        if key in real and not isinstance(real[key], str):
            raise ContractError(f"{path}: realWorld.{key} must be a string")
    repository = real.get("repo")
    if repository is not None:
        if not isinstance(repository, str):
            raise ContractError(f"{path}: realWorld.repo must be a string")
        _reject_credentials(f"{path}: realWorld.repo", repository)
    if real.get("fixCommit") and not (isinstance(repository, str) and repository.strip()):
        raise ContractError(f"{path}: realWorld.fixCommit needs realWorld.repo as a non-blank "
                            "string; the fix evidence is recorded as '<repo>@<sha>'")
    regions = legacy.get("regions", [])
    if not isinstance(regions, list):
        raise ContractError(f"{path}: regions must be a list of region objects")
    for index, region in enumerate(regions):
        label = f"{path}: regions[{index}]"
        if not isinstance(region, dict):
            raise ContractError(f"{label} must be a JSON object")
        if not isinstance(region.get("path"), str) or not region["path"].strip():
            raise ContractError(f"{label} must carry a non-blank path string")
        bounds = [key for key in ("startLine", "endLine") if key in region]
        if len(bounds) == 1:
            raise ContractError(
                f"{label}: startLine and endLine must be supplied together; {bounds[0]} is alone")
        for key in bounds:
            _legacy_line(region[key], f"{label}.{key}")
        if bounds and region["startLine"] > region["endLine"]:
            raise ContractError(f"{label}: startLine must not exceed endLine")
    return legacy


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
    path it may write checks it: ``plan``, ``run``, ``demo``, the ``--output`` of ``score``,
    ``replay`` and ``report``, the pack ``corpus init`` creates, the bundle ``review init``,
    ``review record`` and ``review approve`` write into, and the trial ``corpus validate`` is
    about to export into. A trial is recognized by a ``provenance.json`` file beside a
    ``source`` directory; any other directory is left alone. *output* itself is examined along
    with its parents, so a bundle that is itself a trial root is refused as well as one sitting
    under one; a path that does not exist yet carries no marker and is judged by its parents
    alone. The comparison resolves symlinks in the path but follows no bind mount or hard link,
    so it catches the obvious mistake and is not an isolation boundary.
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
    if args.legacy_case:
        case = cases.draft_case_from_legacy(
            _legacy_document(args.legacy_case), case_id=args.case_id, snapshot_id=args.snapshot_id,
            legacy_path=str(args.legacy_case), workload=args.workload,
            component_role=args.component_role, represents=args.represents)
    else:
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
        trial = Path(tempfile.mkdtemp(prefix="sastbench-trial-")) / args.snapshot_id
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
        print(f"sastbench: mechanical checks failed for {len(unchecked)} case(s): "
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


def _corpus(args: argparse.Namespace) -> int:
    return {"init": _corpus_init, "add-snapshot": _corpus_add_snapshot, "import": _corpus_import,
            "validate": _corpus_validate, "approve": _corpus_approve, "admit": _corpus_admit,
            "disposition": _corpus_disposition}[args.corpus_command](args)


def _plan(args: argparse.Namespace) -> int:
    _refuse_trial_path(args.output)
    pack = cases.load_pack(args.pack)
    plan, notes = cases.build_plan(pack, args.snapshot_id, args.tree_hash, mode=args.mode)
    _write_new(args.output, _json(plan))
    for note in notes:
        print(f"note: {note}", file=sys.stderr)
    print(f"Wrote a {plan['scope']} plan with {len(plan['targets'])} targets and "
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
    """Print the review state of one bundle. This reads; it writes nothing and approves nothing."""
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
    incomplete = [invocation["invocation_id"] for invocation in manifest["invocations"]
                  if invocation["status"] in INCOMPLETE_INVOCATION_STATUSES]
    if incomplete:
        print(f"sastbench: no usable scan from {len(incomplete)} invocation(s): "
              f"{', '.join(incomplete)}", file=sys.stderr)
    if manifest["status"] != "completed":
        print(f"sastbench: the run manifest status is {manifest['status']}", file=sys.stderr)
    return 1 if incomplete or manifest["status"] != "completed" else 0


def _warn_unreviewed(state: str) -> None:
    """Say on stderr that a bundle carries no recorded review. The report itself is unchanged."""
    if state in UNREVIEWED_REVIEW_STATES:
        print(f"sastbench: warning: review record is {state}; this report shows unreviewed decisions, "
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
    artifact.add_argument("--legacy-case", type=Path, help="legacy v1 case record")
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
    planning.add_argument("--snapshot-id", required=True)
    planning.add_argument("--tree-hash", required=True)
    planning.add_argument("--output", required=True, type=Path, help="new JSON file, outside any trial directory")
    planning.add_argument("--mode", choices=("full", "pr"), default="full")
    _add_review_commands(sub)
    running = sub.add_parser("run", help="execute one frozen run configuration into a new directory")
    running.add_argument("config", type=Path)
    running.add_argument("--output", required=True, type=Path, help="new directory, must not exist")
    running.add_argument("--only-system", action="append")
    running.add_argument("--only-input", action="append")
    running.add_argument("--workspace-root", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            load_document(args.path, args.kind)
            print(f"Valid {args.kind}: {args.path}")
        elif args.command == "demo":
            _demo(args.directory)
        elif args.command in ("corpus", "plan", "review", "run"):
            return {"corpus": _corpus, "plan": _plan, "review": _review, "run": _run}[args.command](args)
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
                print(f"sastbench: review state {review_state}: these numbers come from decisions with "
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
        print(f"sastbench: {exc}", file=sys.stderr)
        return 2
