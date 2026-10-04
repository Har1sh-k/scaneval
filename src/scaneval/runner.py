"""Execute one frozen run configuration end to end and write an evaluator-side run directory.

Layout, all evaluator-side; a scanner only ever sees a private workspace copy of one export:

    <out>/
      run-config.json          canonical copy of the configuration that was executed
      run-manifest.json        what ran, what was skipped, and where every artifact landed
      evaluator/schedule.json  every assignment, frozen plan, and pair, written before any input
      evaluator/pack.json      the pack copy this run froze, with its mechanical check results
      inputs/<input id>/       exported source tree plus preparation provenance beside it
      invocations/<id>/        one invocation bundle per input, system, and repetition

Inputs are named by their input id (:func:`scaneval.contracts.input_identity`): a 2.0
configuration's snapshot id, or a 2.1 configuration's ``input_id`` or its default, which for a
native PR input is its change set id. Invocation ids join that id, the system id, and the
repetition. A metadata-blinded input's directory also keeps the original export under
``original/source``; it is evaluator-side like everything else here, and only the transformed
``source`` is ever copied into a scanner workspace. A native PR input's directory holds two
exports, the head in ``source`` and the base in ``base/source``, and a scanner is handed the head
with a neutral two-commit history built from both, never the base as a directory.

A scanner is handed a private workspace copy of one export and writes its raw output and any
trace into staging directories inside that workspace; :mod:`scaneval.execution` moves them
into the invocation bundle once the scan returns or raises. No path handed to an adapter
resolves inside this run directory.

Boundaries this module keeps. It never edits the source pack on disk: mechanical check
results land only in the frozen copy, and that copy is written exactly once, after every
input is prepared and checked and before the first invocation, so no file here is ever
rewritten. The schedule is written once too, before the first input is fetched, so nothing the
run observes changes what it was assigned. It never writes labels, plans, decisions, or pack
data inside an exported source tree. It never approves anything, so every decisions file it
writes is a machine draft; a plan's scope follows the label state already recorded in the pack,
which means a pack carrying independent reviews yields a reviewed plan and a freshly checked one
yields a draft plan.

What fails where. A configuration this run cannot honour (an input the pack does not declare,
a PR input naming a change set the pack does not declare, colliding invocation ids, a cache or
workspace inside evaluator storage, a blinding map that cannot be loaded, blinded inputs of one
repository naming different maps, a run, system, or path that names an original token of a
blinded input's map) is refused before the output directory exists, so nothing is written. An input that
cannot be prepared (a failed fetch or export, a declared tree hash the export contradicts, a
change with nothing in it, a history git reads differently from the export, a blinding map that is
not approved or does not fit the export) is recorded against that input: its manifest row carries the failure,
every one of its assignments is a skipped invocation carrying the reason, and the other inputs
still run. Once the output directory exists, any other failure is recorded as well: a manifest
with status ``failed`` is written before the exception leaves this module.

A system runs under the execution backend its 2.1 ``execution`` block names
(:mod:`scaneval.isolation`): ``local`` records the declared network policy without enforcing it,
and ``oci`` runs every scanner process in a container built for one invocation and torn down
after it. A system whose backend refuses it outright is skipped with the reason, an invocation
whose backend preflight fails is a recorded failed invocation, and neither is ever run under a
weaker backend. The runner produces single-invocation numbers only: no corpus weighting,
repeated-run uncertainty, promotion gate, or cross-system comparison is computed here.
A failed invocation stays a failed invocation and is never rewritten as an empty successful scan,
and an input that was never prepared is never rewritten as one that had nothing in it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import blinding, cases, execution, isolation, materialize, report, review, schedule, scoring
from .adapters import get_adapter
from .adapters.base import Adapter, AdapterError, SystemSpec
from .contracts import (
    ContractError,
    canonical_json,
    canonical_sha256,
    input_identity,
    load_document,
    reject_nonfinite,
    validate_document,
)


MANIFEST_NAME = "run-manifest.json"
MANIFEST_KIND = "run-manifest"
DEFAULT_CACHE_ROOT = ".repos"
SCHEMA_VERSION = "2.1"
PLAN_MODE = "full"
# The scan modes an input can have and an adapter can declare (:attr:`Adapter.scan_modes`).
SCAN_MODES = ("full", "pr")


@dataclass(frozen=True)
class _InputSpec:
    """One configured input as this run resolved it before anything was written.

    ``input_id`` names the input's directory, its invocations, and its manifest row; ``entry`` is
    the configuration entry it was resolved from. ``snapshot_id`` is the snapshot a full input
    exports and the head snapshot of a PR input, whose ``change_set`` is the one the pack declares
    for the id its entry names: a PR input is prepared as the review of that change and never as a
    full scan of its head. A metadata-blinded one carries its loaded map; whether that map is
    approved and fits the export is asked when the input is prepared.
    """

    input_id: str
    snapshot_id: str
    mode: str
    profile: str
    entry: dict = field(compare=False, repr=False)
    # The reviewed map of a metadata-blinded input, loaded once at configuration time so the
    # schedule, the checks below, and the preparation all read the same document.
    blinding_map: dict | None = field(default=None, compare=False, repr=False)
    # The change set a native PR input reviews, as the pack declares it.
    change_set: dict | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class _PreparedSystem:
    """One configured system after adapter resolution and its preparation phase.

    ``skipped`` holds the failure's own message when resolution or preparation failed.
    A skipped system is never invoked and never reported as a scan of any kind. ``execution`` is
    the backend its invocations run under; ``None`` is the local one.
    """

    spec: SystemSpec
    adapter: Adapter | None
    preparation: dict
    network_policy: str
    skipped: str | None
    execution: isolation.ExecutionSettings | None = None

    def summary(self) -> dict:
        """What the manifest records about this system.

        ``adapter_version`` is the adapter's own value only when it is a non-empty string, which
        is what the manifest contract allows; an adapter declaring anything else is a skipped
        system whose reason names the offending value, and its version is recorded as unknown.
        """
        version = getattr(self.adapter, "adapter_version", None)
        return {"system_id": self.spec.system_id, "adapter": self.spec.adapter,
                "adapter_version": version if isinstance(version, str) and version else None,
                "preparation": self.preparation, "skipped_reason": self.skipped}


def _now(clock: Callable[[], datetime] | None) -> str:
    moment = (clock or (lambda: datetime.now(timezone.utc)))()
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _utf8(text: str, label: str) -> bytes:
    """The UTF-8 bytes of *text*, refused before any file is created.

    A lone UTF-16 surrogate survives :func:`canonical_json` and every contract check but cannot
    be encoded, so the encoding happens here rather than inside an open file, where it would
    leave an empty record behind.
    """
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{label} is not UTF-8 text: {exc}") from exc


def _write_new(path: Path, value: dict) -> None:
    """Write one canonical JSON document, refusing to overwrite an existing path.

    The document is serialized and encoded before the file is created, so a value canonical JSON
    or UTF-8 cannot represent leaves no empty file behind for a reader to mistake for a record.
    """
    payload = _utf8(canonical_json(value) + "\n", "the canonical JSON document")
    with path.open("xb") as handle:
        handle.write(payload)


def _write_new_text(path: Path, content: str) -> None:
    """Write one text file, refusing to overwrite an existing path.

    The text is encoded before the file is created, for the same reason the JSON writer above
    encodes first: an empty file would read as a report this run never produced.
    """
    payload = _utf8(content, f"the content of {path.name}")
    with path.open("xb") as handle:
        handle.write(payload)


def _relative(path: Path, out_dir: Path) -> str:
    return path.relative_to(out_dir).as_posix()


def _resolved(path: Path) -> Path:
    """The absolute, symlink-resolved form of *path*. Nothing needs to exist yet."""
    return Path(path).expanduser().resolve()


def _inside(child: Path, parent: Path) -> bool:
    return child == parent or child.is_relative_to(parent)


def _sanitized(text: str) -> str:
    """*text* with whatever UTF-8 cannot encode written out as an escape.

    A lone UTF-16 surrogate survives :func:`canonical_json` and every contract check but cannot
    be encoded, so text that reaches the manifest from outside this module (an exception message,
    say) is escaped here rather than left to make the whole manifest unwritable, including the
    partial manifest a failing run depends on.
    """
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _message(exc: BaseException) -> str:
    """The exception's own message, escaped where UTF-8 cannot encode it, capped for a record."""
    return _sanitized(str(exc) or repr(exc))[:2000]


def _selected(items: list[dict], key: str, only: set[str] | None, label: str) -> list[dict]:
    """Filter configured entries, refusing a filter that names something the config does not have."""
    if only is None:
        return list(items)
    unknown = sorted(set(only) - {item[key] for item in items})
    if unknown:
        raise ContractError(f"{label} not present in the run configuration: {', '.join(unknown)}")
    return [item for item in items if item[key] in only]


def _input_specs(config: dict, only: set[str] | None, base: Path,
                 pack: dict) -> tuple[list[_InputSpec], list[str]]:
    """The configured inputs this run covers, resolved, and the ids of those narrowed away.

    Inputs are selected by input id, which for a 2.0 configuration is the snapshot id. Naming an
    id the configuration does not contain is refused rather than read as an empty selection.

    A covered native PR input is resolved against the change sets *pack* declares, and one it does
    not declare is refused here, before anything is written: a PR input is the review of a declared
    boundary, and a full scan of its head is never a silent stand-in for one. A covered
    metadata-blinded input has its map loaded here, from the path its entry names relative to the
    configuration (*base*); a map that cannot be read or does not validate is refused here too, and
    so is a blinded input of a 2.0 configuration, which has no way to name one. Only a 2.1
    configuration can. An input narrowed away is not prepared, so none of this is asked of it.
    """
    identified = [(index, input_identity(entry), entry) for index, entry in enumerate(config["inputs"])]
    if only is not None:
        unknown = sorted(set(only) - {input_id for _, input_id, _ in identified})
        if unknown:
            raise ContractError(f"inputs not present in the run configuration: {', '.join(unknown)}")
    specs: list[_InputSpec] = []
    excluded: list[str] = []
    for index, input_id, entry in identified:
        if only is not None and input_id not in only:
            excluded.append(input_id)
            continue
        mode = entry.get("mode", "full")
        profile = entry.get("profile", "standard")
        label = f"inputs[{index}] ({input_id})"
        change_set = None
        snapshot_id = entry.get("snapshot_id")
        if mode == "pr":
            try:
                change_set = cases.change_set_by_id(pack, entry["change_set_id"])
            except ContractError as exc:
                raise ContractError(f"{label} is a native PR input that cannot be run: {exc}") from exc
            snapshot_id = change_set["head_snapshot_id"]
        document = None
        if profile == "metadata_blinded":
            if "blinding_map" not in entry:
                raise ContractError(
                    f"{label} asks for metadata_blinded, but a {config['schema_version']} run "
                    "configuration cannot name the reviewed blinding map it needs; write it at "
                    "schema_version 2.1 with blinding_map, since blinding is never replaced by the "
                    "standard export")
            path = base / entry["blinding_map"]
            try:
                document = blinding.load_map(path)
            except ContractError as exc:
                raise ContractError(f"{label}: the blinding map {path} cannot be used: {exc}") from exc
        specs.append(_InputSpec(input_id, snapshot_id, mode, profile, entry, document, change_set))
    return specs, excluded


def _check_blinding(config: dict, pack: dict, inputs: list[_InputSpec], systems: list[dict], *,
                    workspace_root: Path | None = None, cache_root: Path | None = None,
                    config_dir: Path | None = None) -> None:
    """Refuse blinded inputs that disagree about their map, or that a system or a path would unblind.

    Related inputs, those whose snapshots are fetched from one repository, are blinded with one
    map: the same map id and the same content digest, so a vulnerable and a fixed snapshot, or a
    base and a head, carry the same pseudonyms and a comparison between them compares one
    transformation. A map's own fit to each export is asked when the input is prepared.

    A scanner is told the run id, and a system's id, model id, model revision, and configuration
    reach its request or its adapter, so any of them naming an original token of a blinded input's
    map would carry the identity the map removes straight into the scan. So do the paths: a scanner
    runs in a workspace whose absolute path it can read (the llm-harness adapter is handed the path
    of the tree it reviews, and the oci backend mounts every path where it is), its rules and
    runtime files sit under the cache root, and the configuration directory holds both by default.
    Such a run is refused, ignoring case, reading every key and value of the configuration and each
    path both as it was named, made absolute, and as it resolves. All the checks run before the
    output directory exists. What this does not read: the temporary directory a workspace is made
    in when no *workspace_root* is given, and any path a scanner finds for itself.
    """
    blinded = [spec for spec in inputs if spec.blinding_map is not None]
    by_repository: dict[str, _InputSpec] = {}
    for spec in blinded:
        url = cases.snapshot_by_id(pack, spec.snapshot_id)["repository"]["url"]
        first = by_repository.setdefault(url, spec)
        if (first.blinding_map["map_id"], blinding.content_digest(first.blinding_map)) != (
                spec.blinding_map["map_id"], blinding.content_digest(spec.blinding_map)):
            raise ContractError(
                f"inputs {first.input_id} and {spec.input_id} are blinded snapshots of one repository "
                f"({url}) but name different maps ({first.blinding_map['map_id']} and "
                f"{spec.blinding_map['map_id']}, or one map's content in two versions); related inputs "
                "are blinded with one map")
    paths = (("workspace_root", workspace_root), ("cache_root", cache_root),
             ("the configuration directory", config_dir))
    for spec in blinded:
        fields = [("the run id", config["run_id"])]
        for system in systems:
            fields += [(f"system {system['system_id']}'s {name}", system.get(key))
                       for name, key in (("id", "system_id"), ("model_id", "model_id"),
                                         ("model_revision", "model_revision"), ("configuration", "config"))]
        for label, path in paths:
            if path is not None:
                named = Path(path).expanduser().absolute()
                fields += [(f"{label} {spelling}", spelling)
                           for spelling in dict.fromkeys((str(named), str(_resolved(path))))]
        for where, value in fields:
            leaked = blinding.leaked_originals(spec.blinding_map, value)
            if leaked:
                raise ContractError(
                    f"{where} names {leaked[0]!r}, an original identity token of blinding map "
                    f"{spec.blinding_map['map_id']}, which would reach the scan of blinded input "
                    f"{spec.input_id}; rename it, or leave that input standard")


def _check_invocation_ids(inputs: list[_InputSpec], systems: list[dict], repetitions: int) -> None:
    """Refuse a configuration whose triples collide into one invocation id.

    An invocation id joins the input id, the system id, and the repetition, so two distinct
    triples can still produce one id when an id contains the separator. Colliding invocations
    would share a bundle directory and destroy each other's records, so this runs before the
    output directory is created and nothing is written.
    """
    seen: dict[str, tuple[str, str, int]] = {}
    for spec in inputs:
        for system in systems:
            for repetition in range(1, repetitions + 1):
                triple = (spec.input_id, system["system_id"], repetition)
                identifier = execution.invocation_id(*triple)
                if identifier in seen:
                    raise ContractError(
                        f"invocation id {identifier!r} is produced by both {seen[identifier]} and "
                        f"{triple}; rename the input or the system")
                seen[identifier] = triple


def _check_workspace_root(workspace_root: Path | None, out_dir: Path, cache_root: Path,
                          input_dirs: list[Path]) -> None:
    """Refuse a scanner workspace that would sit inside evaluator-owned storage.

    A workspace under the run output, the immutable source cache, or an exported input would
    put the scanner's private copy where evaluator artifacts live, where it would be hashed,
    copied, or deleted with them. The comparison is by resolved path only: it does not follow
    bind mounts or hard links, so it guards against the obvious mistake and is not an
    isolation boundary.
    """
    if workspace_root is None:
        return
    workspace = _resolved(workspace_root)
    candidates = [("the run output directory", out_dir), ("the source cache", cache_root)]
    candidates += [("an exported input directory", path) for path in input_dirs]
    for label, path in candidates:
        owned = _resolved(path)
        if _inside(workspace, owned):
            raise ContractError(
                f"workspace_root {workspace} resolves inside {label} ({owned}); give the scanner "
                "a workspace outside the evaluator's directories")


def _check_cache_root(cache_root: Path, out_dir: Path) -> None:
    """Refuse a source cache that overlaps the run output directory.

    A cache inside the output would be exported, hashed, and removed along with the run; an
    output inside the cache would write run artifacts into storage this module treats as
    immutable. The comparison is by resolved path only: it does not follow bind mounts or hard
    links, so it guards against the obvious mistake and is not an isolation boundary.
    """
    cache = _resolved(cache_root)
    out = _resolved(out_dir)
    if _inside(cache, out):
        raise ContractError(
            f"cache_root {cache} resolves inside the run output directory ({out}); keep the "
            "immutable source cache outside the run output")
    if _inside(out, cache):
        raise ContractError(
            f"the run output directory {out} resolves inside cache_root ({cache}); write the run "
            "somewhere outside the immutable source cache")


def _check_input_snapshots(pack: dict, inputs: list[_InputSpec]) -> None:
    """Refuse a configured input the pack does not declare, before anything is written.

    A PR input names two snapshots, the base and the head of its change set, and both must be
    declared; the pack contract already requires it of every change set, so this asks it of the
    pack as it was handed in.
    """
    for spec in inputs:
        cases.snapshot_by_id(pack, spec.snapshot_id)
        if spec.change_set is not None:
            cases.snapshot_by_id(pack, spec.change_set["base_snapshot_id"])


def _input_row(spec: _InputSpec) -> dict:
    """The manifest row of *spec* before anything about its preparation is known.

    A PR input's row is about its head snapshot and names its change set; a full input's row names
    no change set at all.
    """
    row = {"input_id": spec.input_id, "mode": spec.mode, "profile": spec.profile,
           "snapshot_id": spec.snapshot_id, "tree_hash": None, "input_hash": None,
           "provenance_path": None, "mechanical_checks": [], "preparation_failure": None}
    if spec.change_set is not None:
        row["change_set_id"] = spec.change_set["change_set_id"]
    return row


def _prepare_input(spec: _InputSpec, pack: dict, out_dir: Path, cache_root: Path,
                   clock: Callable[[], datetime] | None,
                   row: dict) -> execution.PreparedInput:
    """Fetch, export, verify, and mechanically check one configured input, filling in *row*.

    *row* is this input's manifest row, filled in as each step completes, so a preparation that
    fails part way still records what it had written: a provenance record that exists is named
    even when the export it describes was then refused. The tree hash and the checks are recorded
    only once they stand.

    A metadata-blinded input is exported twice over by :func:`scaneval.blinding.export_blinded`:
    the original to ``original/source``, which stays evaluator-side, and the transformed copy to
    ``source``, which is what a scanner is handed and what the result binds to. The labels were
    written against the original, so the declared tree hash is compared with the original and the
    mechanical checks run against it; every refusal of the map is raised before ``source`` exists.

    The row records this input's raw check outcomes and nothing that depends on the other
    inputs. A case spanning two snapshots is only fully checked once every configured input has
    been prepared, so its label state and its planning notes are derived later, by
    :func:`_planning_records`, rather than read here from an incomplete check set.

    A native PR input is prepared by :func:`_prepare_pr_input`, which does all of this for a pair of
    snapshots.
    """
    if spec.mode == "pr":
        return _prepare_pr_input(spec, pack, out_dir, cache_root, clock, row)
    snapshot = cases.snapshot_by_id(pack, spec.snapshot_id)
    languages = tuple(snapshot["languages"])
    cached = materialize.fetch_snapshot(snapshot["repository"]["url"], snapshot["commit"], cache_root)
    trial = out_dir / "inputs" / spec.input_id
    record = materialize.export_snapshot(cached, trial, profile=spec.profile, blinding_map=spec.blinding_map,
                                         snapshot_id=spec.snapshot_id, clock=clock)
    provenance_path = materialize.write_provenance(trial, record)
    row["provenance_path"] = _relative(provenance_path, out_dir)
    tree_hash = record["trial"]["tree_hash"]
    blinded = spec.blinding_map is not None
    source_tree_hash = record["original"]["tree_hash"] if blinded else tree_hash
    labelled_tree = trial / blinding.ORIGINAL_ROOT if blinded else trial / "source"
    declared = snapshot.get("tree_hash")
    if declared and declared != source_tree_hash:
        raise ContractError(
            f"snapshot {spec.snapshot_id} declares tree hash {declared} but the export produced {source_tree_hash}"
        )
    outcomes = cases.mechanical_checks(pack, spec.snapshot_id, labelled_tree, source_tree_hash, clock=clock)
    identity = None
    if blinded:
        identity = {**blinding.map_identity(spec.blinding_map), "original_tree_hash": source_tree_hash,
                    "transformed_tree_hash": tree_hash}
    prepared = execution.PreparedInput(
        spec.input_id, trial / "source", tree_hash, languages, record, spec.profile, spec.mode,
        input_hash=tree_hash, source_tree_hash=source_tree_hash, blinding=identity,
    )
    row.update({"tree_hash": tree_hash, "input_hash": prepared.binding_hash,
                "mechanical_checks": [{"case_id": outcome["case_id"], "passed": outcome["passed"],
                                       "checks": outcome["checks"]} for outcome in outcomes]})
    return prepared


def _prepare_pr_input(spec: _InputSpec, pack: dict, out_dir: Path, cache_root: Path,
                      clock: Callable[[], datetime] | None,
                      row: dict) -> execution.PreparedInput:
    """Fetch, export, verify, and mechanically check the two snapshots of a native PR input.

    The head is exported to ``inputs/<id>/source`` and the base to ``inputs/<id>/base/source``, and
    a blinded input has both transformed with its one reviewed map and both originals kept under
    ``original``. What the labels and the mechanical checks refer to is the original export of each
    snapshot, so each declared tree hash is compared with its original and every case that
    references either snapshot is checked against it; a hash the export contradicts refuses the
    whole input before any check is recorded. The diff, its digest, and the input hash are over the
    trees a scanner is handed, and a change with nothing in it is refused as no change to review.

    The neutral synthetic history is computed here once, in a scratch copy, and verified against the
    recorded diff (:func:`scaneval.materialize.compute_pr_history`) before any check is recorded;
    the two commit ids it yields are what the request will name and what every invocation's
    workspace must reproduce. What lands in :attr:`~scaneval.execution.PreparedInput.pr` is
    evaluator-side identity only, with no absolute path: the change set, both trees, the diff and
    its digest, the two commits, and that the run starts from a fresh state, since nothing is
    carried between invocations.

    The row records this input's raw check outcomes, base snapshot first, and what a PR review
    cannot know until it has exported both trees is recorded only once it does.
    """
    change_set = spec.change_set
    base_snapshot = cases.snapshot_by_id(pack, change_set["base_snapshot_id"])
    head_snapshot = cases.snapshot_by_id(pack, change_set["head_snapshot_id"])
    base_cached = materialize.fetch_snapshot(base_snapshot["repository"]["url"], base_snapshot["commit"], cache_root)
    head_cached = materialize.fetch_snapshot(head_snapshot["repository"]["url"], head_snapshot["commit"], cache_root)
    trial = out_dir / "inputs" / spec.input_id
    record = materialize.export_pr(
        base_cached, head_cached, trial, profile=spec.profile, blinding_map=spec.blinding_map,
        base_snapshot_id=base_snapshot["snapshot_id"], head_snapshot_id=head_snapshot["snapshot_id"], clock=clock)
    provenance_path = materialize.write_provenance(trial, record)
    row["provenance_path"] = _relative(provenance_path, out_dir)
    blinded = spec.blinding_map is not None
    sides = []
    for side, snapshot in (("base", base_snapshot), ("head", head_snapshot)):
        exported = record[side]
        source_hash = exported["original"]["tree_hash"] if blinded else exported["trial"]["tree_hash"]
        labelled_tree = trial / (exported["original"]["root"] if blinded else exported["trial"]["root"])
        declared = snapshot.get("tree_hash")
        if declared and declared != source_hash:
            raise ContractError(
                f"snapshot {snapshot['snapshot_id']} declares tree hash {declared} but the export produced "
                f"{source_hash}")
        sides.append((snapshot, labelled_tree, source_hash))
    diff = record["diff"]
    head_source_hash = sides[1][2]
    # Before any check is recorded, so an input refused for its history leaves the pack exactly as
    # an input refused for its declared hash does: no check is recorded against an export whose
    # input could not be prepared.
    history = materialize.compute_pr_history(trial / "source", trial / materialize.PR_BASE_DIR / "source",
                                             diff["changes"])
    outcomes = []
    for snapshot, labelled_tree, source_hash in sides:
        outcomes += cases.mechanical_checks(pack, snapshot["snapshot_id"], labelled_tree, source_hash, clock=clock)
    pr = {"change_set_id": change_set["change_set_id"], "base_snapshot_id": base_snapshot["snapshot_id"],
          "head_snapshot_id": head_snapshot["snapshot_id"], "boundary": change_set["boundary"],
          "review_scope": change_set["review_scope"], "base_tree_hash": diff["base_tree_hash"],
          "head_tree_hash": diff["head_tree_hash"], "diff_sha256": diff["diff_sha256"], "changes": diff["changes"],
          "base_commit": history["base_commit"], "head_commit": history["head_commit"],
          "history": {key: history[key] for key in ("messages", "identity", "date")},
          "prepared_state": "fresh"}
    identity = None
    if blinded:
        identity = {**blinding.map_identity(spec.blinding_map), "original_tree_hash": head_source_hash,
                    "transformed_tree_hash": diff["head_tree_hash"], "base_original_tree_hash": sides[0][2],
                    "base_transformed_tree_hash": diff["base_tree_hash"]}
    prepared = execution.PreparedInput(
        spec.input_id, trial / "source", diff["head_tree_hash"], tuple(head_snapshot["languages"]), record,
        spec.profile, "pr", input_hash=record["input_hash"], source_tree_hash=head_source_hash, blinding=identity,
        pr=pr, base_source_dir=trial / materialize.PR_BASE_DIR / "source")
    row.update({"tree_hash": prepared.tree_hash, "input_hash": prepared.binding_hash,
                "mechanical_checks": [{"case_id": outcome["case_id"], "passed": outcome["passed"],
                                       "checks": outcome["checks"]} for outcome in outcomes]})
    return prepared


def _vet_adapter_identity(spec: SystemSpec, adapter: Adapter) -> None:
    """Refuse an adapter whose declared attributes no record here can carry.

    The manifest and every execution record copy ``adapter.name`` and ``adapter.adapter_version``
    verbatim, and both contracts require a non-empty string, so an adapter declaring anything
    else (a float version, say) would make each of its execution records unwritable. Every
    execution record also copies ``adapter.env_passthrough`` into its environment record and
    walks ``adapter.state_dirs`` to capture harness state, so a value that is not a sequence of
    non-empty strings fails every invocation of that system, or quietly means something else: the
    string ``"PATH"`` is a sequence of four one-letter names. Text UTF-8 cannot encode is refused
    here too, for the same reason :func:`_utf8` refuses it before a file exists. Checking the
    attributes here turns each of those into one skipped system with a reason instead of a failed
    run. This checks the attributes the records are built from; it says nothing about whether the
    adapter scans correctly or reports its real version.

    ``scan_modes`` is read the same way, because it decides whether an invocation runs at all: it
    must be a non-empty set drawn from the modes this build knows, ``full`` and ``pr``, since
    anything else could never match an input and would leave every invocation of the system
    quietly unsupported. An adapter naming none, or one this build does not know, is a skipped
    system with that reason and not a system whose inputs all read as unsupported.
    """
    for attribute in ("name", "adapter_version"):
        value = getattr(adapter, attribute, None)
        if not isinstance(value, str) or not value:
            raise AdapterError(
                f"{spec.adapter}.{attribute} must be a non-empty string, not {value!r}; the run "
                "manifest and every execution record copy it verbatim")
        _utf8(value, f"{spec.adapter}.{attribute}")
    for attribute, carried in (("env_passthrough", "every execution record copies it into "
                                                   "environment.passthrough"),
                               ("state_dirs", "every invocation walks it to capture harness state")):
        value = getattr(adapter, attribute, ())
        if not isinstance(value, (tuple, list, set, frozenset)):
            raise AdapterError(
                f"{spec.adapter}.{attribute} must be a tuple, list, or set of non-empty strings, "
                f"not {value!r}; {carried}")
        for item in value:
            if not isinstance(item, str) or not item:
                raise AdapterError(
                    f"{spec.adapter}.{attribute} must hold non-empty strings, not {item!r}; "
                    f"{carried}")
            _utf8(item, f"{spec.adapter}.{attribute}")
    modes = getattr(adapter, "scan_modes", None)
    if not isinstance(modes, (tuple, list, set, frozenset)) or not modes:
        raise AdapterError(
            f"{spec.adapter}.scan_modes must be a non-empty set of scan modes, not {modes!r}; the run "
            "decides from it whether an invocation is carried out or recorded as unsupported")
    unknown = sorted(str(mode) for mode in modes if mode not in SCAN_MODES)
    if unknown:
        raise AdapterError(
            f"{spec.adapter}.scan_modes names {', '.join(unknown)}, which this build does not know; the "
            f"scan modes are {', '.join(SCAN_MODES)}")


def _prepare_system(entry: dict, cache_root: Path, default_policy: str,
                    adapters: dict[str, Adapter] | None) -> tuple[_PreparedSystem, list[str]]:
    """Resolve one system's adapter and run its preparation phase once.

    Any failure resolving, vetting, or preparing the adapter is recorded as a skip carrying the
    exception's own type name and message, whether it failed as an adapter, while materializing
    what it needs, on the filesystem, because its module is not installed, or because an
    attribute the manifest and execution records are built from is not something they can carry.
    A preparation that returns something other than a record is a preparation failure too, and so
    is one holding a value the manifest cannot carry: the record goes into the manifest verbatim,
    so a value canonical JSON cannot represent, a non-finite number, or text UTF-8 cannot encode
    would make the whole manifest unwritable, including the partial manifest a failing run
    depends on. The skip reason carries the refusal's own message, escaped where UTF-8 cannot
    encode it, which names the offending type or the field holding it. None of this aborts the
    run, no invocation of a skipped system is attempted, and a skipped system never becomes an
    empty successful scan.

    The system's ``execution`` block is resolved first, and an adapter the selected backend
    refuses (under ``oci``, any adapter not declaring ``oci_compatible``, which today means
    ``llm-harness`` and ``deepsec``) is skipped before its preparation runs, so a refused system
    fetches nothing and is never run locally in its place.
    """
    spec = SystemSpec(entry["system_id"], entry["adapter"], dict(entry["config"]),
                      entry.get("model_id"), entry.get("model_revision"))
    adapter: Adapter | None = None
    preparation: dict = {}
    skipped: str | None = None
    warnings: list[str] = []
    policy = entry.get("network_policy", default_policy)
    settings: isolation.ExecutionSettings | None = None
    try:
        settings = isolation.resolve_execution(entry.get("execution"), policy)
        if adapters is not None and spec.adapter in adapters:
            adapter = adapters[spec.adapter]
        else:
            adapter = get_adapter(spec.adapter)
        # Checked before the preparation phase runs: a system this run cannot record is not one
        # to spend a checkout or a download on.
        _vet_adapter_identity(spec, adapter)
        refusal = isolation.refusal_for(adapter, settings)
        if refusal is not None:
            raise isolation.IsolationError(refusal)
        prepared = adapter.prepare(spec, cache_root)
        if not isinstance(prepared, dict):
            raise AdapterError(
                f"{spec.adapter}.prepare returned {type(prepared).__name__}; a preparation phase "
                "must report what it prepared as a record")
        reject_nonfinite(prepared, f"{spec.adapter}.prepare record")
        _utf8(canonical_json(prepared), f"{spec.adapter}.prepare record")
        preparation = prepared
    except Exception as exc:
        preparation = {}
        skipped = f"{type(exc).__name__}: {_message(exc)}"
        warnings.append(f"{spec.system_id}: not invoked ({skipped})")
    return _PreparedSystem(spec, adapter, preparation, policy, skipped,
                           settings if settings is not None and settings.enforcing else None), warnings


def _invoke(system: _PreparedSystem, prepared: execution.PreparedInput, repetition: int, *,
            config: dict, out_dir: Path, cache_root: Path, workspace_root: Path | None,
            clock: Callable[[], datetime] | None, warnings: list[str]) -> Path:
    """Run one invocation under its system's execution backend and tear the backend down after it.

    A local system runs exactly as it always has. An ``oci`` system gets a backend built for this
    one invocation: its private scratch directory, inside which the invocation's workspace is
    created, sits under *workspace_root*, no mount it makes may overlap the run directory, and a
    runtime path the adapter declares must sit strictly inside the source cache. Its teardown runs
    whatever the invocation did, and anything it could not remove is added to the run's warnings
    rather than raised over the invocation's own outcome.
    """
    backend = None
    if system.execution is not None:
        backend = isolation.backend_for(
            system.execution, adapter=system.adapter, spec=system.spec, preparation=system.preparation,
            run_id=config["run_id"],
            invocation_id=execution.invocation_id(prepared.input_id, system.spec.system_id, repetition),
            scratch_root=workspace_root, protected=(out_dir,), runtime_roots=(cache_root,))
    try:
        return execution.run_invocation(
            prepared=prepared, adapter=system.adapter, spec=system.spec,
            preparation=system.preparation, out_dir=out_dir / "invocations",
            run_id=config["run_id"], repetition=repetition,
            timeout_seconds=config["timeout_seconds"], trace_mode=config["trace_mode"],
            network_policy=system.network_policy,
            workspace_root=backend.workspace_root if backend is not None else workspace_root,
            clock=clock, backend=backend,
        )
    finally:
        if backend is not None:
            identifier = execution.invocation_id(prepared.input_id, system.spec.system_id, repetition)
            warnings.extend(f"{identifier}: {problem}" for problem in backend.close())


def _record_label_states(pack: dict, manifest_inputs: list[dict]) -> None:
    """Give every recorded check outcome the label state the pack carries right now.

    A case spanning several snapshots is only fully checked once every input has been prepared,
    so the state belongs to the pack as a whole and not to the moment one input was checked.
    The manifest cannot be written without these fields, so a failed run fills them too, from
    however far the pack got.
    """
    validations = {case["case_id"]: case["validation"] for case in pack["cases"]}
    for summary in manifest_inputs:
        for outcome in summary["mechanical_checks"]:
            validation = validations[outcome["case_id"]]
            outcome["review_state"] = validation["review_state"]
            outcome["level"] = validation["level"]


def _plan(pack: dict, spec: _InputSpec, prepared: execution.PreparedInput) -> tuple[dict, list[str]]:
    """The plan one prepared input is scored against, and the notes on what it left out.

    The labels refer to the snapshot's original export, so that is the tree the plan is built
    against; the plan binds to what the result binds to. For a standard input named as its own
    snapshot the two are one tree and the plan is the 2.0 plan it always was. A native PR input is
    planned as the review of its change set, at evaluation time and from the frozen pack: only the
    items the pack's eligibility names for it, bound to the base tree, head tree, and diff the
    input recorded, whatever the schedule froze before the trees existed.
    """
    pr = prepared.pr if prepared.mode == "pr" else None
    return cases.build_plan(
        pack, spec.snapshot_id, prepared.source_tree_hash or prepared.tree_hash,
        mode=prepared.mode if pr else PLAN_MODE, input_id=prepared.input_id, input_hash=prepared.binding_hash,
        profile=prepared.profile, blinding=prepared.blinding,
        **({"change_set_id": pr["change_set_id"], "base_tree_hash": pr["base_tree_hash"],
            "head_tree_hash": pr["head_tree_hash"], "diff_sha256": pr["diff_sha256"]} if pr else {}))


def _planning_records(pack: dict, prepared_inputs: list[tuple[_InputSpec, execution.PreparedInput]],
                      manifest_inputs: list[dict]) -> list[str]:
    """Fill in each input's label state from the frozen pack and return the planning warnings.

    This runs once the pack is frozen, so it reads the same state every invocation plans
    against. The notes come from :func:`cases.build_plan`, so they state what was actually
    planned and why a case was left out rather than restating a check outcome that may not
    decide the question. An input that was never prepared has no plan and contributes no note.
    """
    _record_label_states(pack, manifest_inputs)
    warnings: list[str] = []
    for spec, prepared in prepared_inputs:
        _, notes = _plan(pack, spec, prepared)
        warnings.extend(f"{prepared.input_id}: {note}" for note in notes)
    return warnings


def _evaluate_bundle(bundle: Path, pack: dict, spec: _InputSpec, prepared: execution.PreparedInput,
                     clock: Callable[[], datetime] | None) -> tuple[dict, dict, dict, list[str]]:
    """Plan, draft review decisions, score, and report one finished invocation bundle.

    Every decision written here is a machine draft, so no claim earns confirmed detection
    credit on this path, and the report says so: it carries the review record's own state, which
    is what that record claims rather than a verification of it. The plan's scope is whatever the
    pack's recorded label state supports; nothing here changes that state.
    """
    plan, notes = _plan(pack, spec, prepared)
    result = load_document(bundle / "result.json", "scan-result")
    decisions = review.draft_decisions(plan, result, pack, clock=clock)
    record = review.review_record(plan, decisions, clock=clock, notes=notes)
    review.write_evaluator_records(bundle, plan, decisions, record)
    evaluation = scoring.score(plan, result, decisions)
    _write_new(bundle / "evaluation.json", evaluation)
    _write_new_text(bundle / "report.html",
                    report.render_report(evaluation, result, plan, review_state=record["state"]))
    return plan, record, evaluation, notes


def _skipped_invocation(row: dict, reason: str) -> dict:
    """A manifest row for an assignment that was never invoked, and why. No scan happened."""
    return {**row, "status": "skipped", "claim_records": None, "plan_scope": None,
            "targets_assigned": None, "targets_detected": None, "pending_matching_count": None,
            "bundle_path": None, "review_state": None, "skipped_reason": reason}


def _manifest(*, config: dict, pack: dict, selection: dict, manifest_inputs: list[dict],
              systems: list[_PreparedSystem], invocations: list[dict], warnings: list[str],
              status: str, failure: dict | None, clock: Callable[[], datetime] | None) -> dict:
    """Build and validate one run manifest. A failed manifest carries what finished, not a score."""
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "run_id": config["run_id"],
        "status": status,
        "created_at": _now(clock),
        "config_sha256": canonical_sha256(config),
        "pack": cases.pack_summary(pack),
        "selection": selection,
        "inputs": manifest_inputs,
        "systems": [system.summary() for system in systems],
        "invocations": invocations,
        "warnings": warnings,
        "schedule_path": schedule.SCHEDULE_PATH,
        **({"failure": failure} if failure is not None else {}),
    }
    return validate_document(MANIFEST_KIND, manifest)


def run_from_config(
    config_path: Path,
    out_dir: Path,
    *,
    clock: Callable[[], datetime] | None = None,
    workspace_root: Path | None = None,
    adapters: dict[str, Adapter] | None = None,
    only_systems: set[str] | None = None,
    only_inputs: set[str] | None = None,
) -> dict:
    """Run every configured (input, system, repetition) and return the run manifest.

    A run configuration at 2.0 or 2.1 is accepted; the manifest is always written at 2.1.
    ``adapters`` maps adapter names to instances and replaces the registry lookup, so a test
    can supply a fake without touching the registry. ``only_inputs`` (input ids) and
    ``only_systems`` narrow the run; naming something the configuration does not contain is an
    error rather than a silently empty run, and what was narrowed away is recorded in the
    manifest and the schedule. ``out_dir`` must not exist, and ``workspace_root`` must be outside
    it.

    ``out_dir`` is resolved once before anything is written, so every recorded path is relative
    to the same real directory. The schedule is built from the configuration and the pack as
    supplied before the output directory exists, and written to ``evaluator/schedule.json`` before
    the first input is fetched. The manifest's planning notes and per-input label states are
    derived after every input has been checked and the pack has been frozen, which is what the
    invocations then plan against.

    Refused before the output directory is created, so a refused run writes nothing at all: an
    input the pack does not declare, a native PR input whose change set the pack does not declare,
    a metadata-blinded input of a 2.0 configuration (which cannot name a map) or one whose map
    cannot be loaded, blinded inputs of
    one repository naming different maps, a run id or a system id, model, revision, or
    configuration, or a workspace root, cache root, or configuration directory, naming an original
    token of a blinded input's map, colliding invocation ids, a cache root that overlaps the
    output directory, and a workspace inside evaluator storage.

    A native PR input is prepared, scheduled, planned, and invoked as the review of its change set:
    once per change set, system, and repetition, with the head as the tree a scanner is handed and
    a synthetic two-commit history for the base and head. An adapter that does not declare ``pr``
    is recorded as unsupported for it, and stays in every denominator.

    An input whose preparation raises (a failed fetch or export, a declared tree hash the export
    contradicts, a change with nothing in it, a blinding map that is not approved or does not fit
    the export) is recorded, not
    raised: its manifest row carries the failure's type and message, every one of its assignments
    becomes a skipped invocation naming it, no adapter is ever called for it, and the remaining
    inputs still run. A run in which every input failed is still a completed run, because the
    loop finished; its invocations are all skipped. A system whose adapter cannot be resolved or
    prepared is recorded as a skipped system the same way.
    Any other failure once the output directory exists (writing the schedule or the frozen pack,
    recording an invocation, or an interrupt such as ``KeyboardInterrupt`` at any point,
    preparation included) writes a manifest with status ``failed`` recording what had finished,
    and the exception is re-raised; if writing that partial manifest itself fails, that error
    propagates with the original as its context.

    This does not approve any label, does not retry or rerun a failed invocation, and does not
    aggregate across inputs or systems. It enforces the declared network policy only for a system
    whose 2.1 ``execution`` block selects the ``oci`` backend; for every other system the policy
    is recorded, not enforced. Under ``oci`` the scanner's workspace is created inside a private
    directory under ``workspace_root``, which must therefore be one the Docker daemon can see.
    """
    config_path = Path(config_path)
    # Resolved once, here: every path recorded, compared, or handed on below is built from this
    # one, so a run under a symlinked prefix (/tmp on macOS) stays consistent end to end.
    out_dir = _resolved(out_dir)
    config = load_document(config_path, "run-config")
    base = config_path.resolve().parent
    pack_path = base / config["pack"]
    cache_root = base / config.get("cache_root", DEFAULT_CACHE_ROOT)
    pack = cases.load_pack(pack_path)

    inputs, excluded_inputs = _input_specs(config, only_inputs, base, pack)
    systems = _selected(config["systems"], "system_id", only_systems, "systems")
    _check_invocation_ids(inputs, systems, config["repetitions"])
    _check_input_snapshots(pack, inputs)
    _check_blinding(config, pack, inputs, systems, workspace_root=workspace_root, cache_root=cache_root,
                    config_dir=base)
    _check_cache_root(cache_root, out_dir)
    _check_workspace_root(workspace_root, out_dir, cache_root,
                          [out_dir / "inputs" / spec.input_id for spec in inputs])

    selected_systems = {entry["system_id"] for entry in systems}
    selection = {
        "only_inputs": sorted(only_inputs) if only_inputs is not None else None,
        "only_systems": sorted(only_systems) if only_systems is not None else None,
        "excluded_inputs": excluded_inputs,
        "excluded_systems": [entry["system_id"] for entry in config["systems"]
                             if entry["system_id"] not in selected_systems],
    }
    # Built from the pack as it was supplied, before any check has run against an export, and
    # before anything is written: a schedule that cannot be built refuses the run here.
    frozen_schedule = schedule.build_schedule(
        config, pack, base_dir=base, created_at=_now(clock), inputs=[spec.entry for spec in inputs],
        systems=systems, maps={spec.input_id: spec.blinding_map for spec in inputs if spec.blinding_map})

    out_dir.mkdir(parents=True, exist_ok=False)

    warnings: list[str] = []
    prepared_inputs: list[tuple[_InputSpec, execution.PreparedInput]] = []
    manifest_inputs: list[dict] = []
    prepared_systems: list[_PreparedSystem] = []
    invocations: list[dict] = []
    # Everything from here on is inside the run directory, so every failure is recorded there.
    try:
        _write_new(out_dir / "run-config.json", config)
        evaluator_dir = out_dir / "evaluator"
        evaluator_dir.mkdir()
        # On disk before the first input is fetched, so what the run was assigned is recorded
        # before anything about how the run went is known.
        _write_new(out_dir / schedule.SCHEDULE_PATH, frozen_schedule)

        for spec in inputs:
            row = _input_row(spec)
            try:
                prepared = _prepare_input(spec, pack, out_dir, cache_root, clock, row)
            except Exception as exc:
                # This input is recorded as unprepared and its assignments as skipped below; an
                # interrupt is not an Exception and still stops the whole run.
                row["preparation_failure"] = {"type": type(exc).__name__, "message": _message(exc)}
                warnings.append(f"{spec.input_id}: not prepared ({type(exc).__name__}: {_message(exc)})")
                manifest_inputs.append(row)
                continue
            manifest_inputs.append(row)
            prepared_inputs.append((spec, prepared))

        # The pack is frozen once, here: every input has been checked and nothing is invoked yet.
        _write_new(evaluator_dir / "pack.json", pack)
        # Only now does the pack say what each case's check set amounts to, so the manifest's
        # planning notes and per-input label states are derived from the frozen copy.
        warnings.extend(_planning_records(pack, prepared_inputs, manifest_inputs))

        for entry in systems:
            system, system_warnings = _prepare_system(entry, cache_root, config["network_policy"], adapters)
            prepared_systems.append(system)
            warnings.extend(system_warnings)

        prepared_by_id = {spec.input_id: prepared for spec, prepared in prepared_inputs}
        failures = {row["input_id"]: row["preparation_failure"] for row in manifest_inputs
                    if row["preparation_failure"] is not None}
        for spec in inputs:
            prepared = prepared_by_id.get(spec.input_id)
            for system in prepared_systems:
                system_spec = system.spec
                for repetition in range(1, config["repetitions"] + 1):
                    row: dict[str, Any] = {
                        "invocation_id": execution.invocation_id(spec.input_id, system_spec.system_id, repetition),
                        "input_id": spec.input_id, "system_id": system_spec.system_id, "repetition": repetition,
                    }
                    if prepared is None:
                        failure = failures[spec.input_id]
                        invocations.append(_skipped_invocation(
                            row, f"input {spec.input_id} could not be prepared: "
                                 f"{failure['type']}: {failure['message']}"))
                        continue
                    if system.skipped is not None:
                        invocations.append(_skipped_invocation(row, system.skipped))
                        continue
                    bundle = _invoke(system, prepared, repetition, config=config, out_dir=out_dir,
                                     cache_root=cache_root, workspace_root=workspace_root, clock=clock,
                                     warnings=warnings)
                    plan, record, evaluation, _notes = _evaluate_bundle(bundle, pack, spec, prepared, clock)
                    metrics = evaluation["metrics"]
                    invocations.append({**row, "status": evaluation["status"],
                                        "claim_records": metrics["claim_records"], "plan_scope": plan["scope"],
                                        "targets_assigned": metrics["targets_assigned"],
                                        "targets_detected": metrics["targets_detected"],
                                        "pending_matching_count": metrics["pending_matching_count"],
                                        "bundle_path": _relative(bundle, out_dir),
                                        "review_state": record["state"], "skipped_reason": None})
    except BaseException as exc:
        # Inputs prepared before the failure may never have reached the derivation above, and
        # the manifest cannot record them without a label state.
        _record_label_states(pack, manifest_inputs)
        partial = _manifest(config=config, pack=pack, selection=selection, manifest_inputs=manifest_inputs,
                            systems=prepared_systems, invocations=invocations, warnings=warnings,
                            status="failed", failure={"type": type(exc).__name__, "message": _message(exc)},
                            clock=clock)
        _write_new(out_dir / MANIFEST_NAME, partial)
        raise

    manifest = _manifest(config=config, pack=pack, selection=selection, manifest_inputs=manifest_inputs,
                         systems=prepared_systems, invocations=invocations, warnings=warnings,
                         status="completed", failure=None, clock=clock)
    _write_new(out_dir / MANIFEST_NAME, manifest)
    return manifest
