"""Execute one frozen run configuration end to end and write an evaluator-side run directory.

Layout, all evaluator-side; a scanner only ever sees a private workspace copy of one export:

    <out>/
      run-config.json        canonical copy of the configuration that was executed
      run-manifest.json      what ran, what was skipped, and where every artifact landed
      evaluator/pack.json    the pack copy this run froze, with its mechanical check results
      inputs/<snapshot>/     exported source tree plus preparation provenance beside it
      invocations/<id>/      one invocation bundle per input, system, and repetition

A scanner is handed a private workspace copy of one export and writes its raw output and any
trace into staging directories inside that workspace; :mod:`sastbench.execution` moves them
into the invocation bundle once the scan returns or raises. No path handed to an adapter
resolves inside this run directory.

Boundaries this module keeps. It never edits the source pack on disk: mechanical check
results land only in the frozen copy, and that copy is written exactly once, after every
input is prepared and checked and before the first invocation, so no file here is ever
rewritten. It never writes labels, plans, decisions, or pack data inside an exported source
tree. It never approves anything, so every decisions file it writes is a machine draft; a
plan's scope follows the label state already recorded in the pack, which means a pack
carrying independent reviews yields a reviewed plan and a freshly checked one yields a draft
plan. Once the output directory exists, every later failure is recorded: a manifest with
status ``failed`` is written before the exception leaves this module. It records the declared
network policy without enforcing it, and it produces single-invocation numbers only: no corpus
weighting, repeated-run uncertainty, promotion gate, or cross-system comparison is computed
here. A failed invocation stays a failed invocation and is never rewritten as an empty
successful scan.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import cases, execution, materialize, report, review, scoring
from .adapters import get_adapter
from .adapters.base import Adapter, AdapterError, SystemSpec
from .contracts import (
    ContractError,
    canonical_json,
    canonical_sha256,
    load_document,
    validate_document,
)


MANIFEST_NAME = "run-manifest.json"
MANIFEST_KIND = "run-manifest"
DEFAULT_CACHE_ROOT = ".repos"
SCHEMA_VERSION = "2.0"
PLAN_MODE = "full"


@dataclass(frozen=True)
class _PreparedSystem:
    """One configured system after adapter resolution and its preparation phase.

    ``skipped`` holds the failure's own message when resolution or preparation failed.
    A skipped system is never invoked and never reported as a scan of any kind.
    """

    spec: SystemSpec
    adapter: Adapter | None
    preparation: dict
    network_policy: str
    skipped: str | None

    def summary(self) -> dict:
        return {"system_id": self.spec.system_id, "adapter": self.spec.adapter,
                "adapter_version": self.adapter.adapter_version if self.adapter is not None else None,
                "preparation": self.preparation, "skipped_reason": self.skipped}


def _now(clock: Callable[[], datetime] | None) -> str:
    moment = (clock or (lambda: datetime.now(timezone.utc)))()
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _write_new(path: Path, value: dict) -> None:
    """Write one canonical JSON document, refusing to overwrite an existing path."""
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical_json(value) + "\n")


def _write_new_text(path: Path, content: str) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _relative(path: Path, out_dir: Path) -> str:
    return path.relative_to(out_dir).as_posix()


def _resolved(path: Path) -> Path:
    """The absolute, symlink-resolved form of *path*. Nothing needs to exist yet."""
    return Path(path).expanduser().resolve()


def _inside(child: Path, parent: Path) -> bool:
    return child == parent or child.is_relative_to(parent)


def _message(exc: BaseException) -> str:
    return (str(exc) or repr(exc))[:2000]


def _selected(items: list[dict], key: str, only: set[str] | None, label: str) -> list[dict]:
    """Filter configured entries, refusing a filter that names something the config does not have."""
    if only is None:
        return list(items)
    unknown = sorted(set(only) - {item[key] for item in items})
    if unknown:
        raise ContractError(f"{label} not present in the run configuration: {', '.join(unknown)}")
    return [item for item in items if item[key] in only]


def _check_invocation_ids(inputs: list[dict], systems: list[dict], repetitions: int) -> None:
    """Refuse a configuration whose triples collide into one invocation id.

    An invocation id joins the input id, the system id, and the repetition, so two distinct
    triples can still produce one id when an id contains the separator. Colliding invocations
    would share a bundle directory and destroy each other's records, so this runs before the
    output directory is created and nothing is written.
    """
    seen: dict[str, tuple[str, str, int]] = {}
    for entry in inputs:
        for system in systems:
            for repetition in range(1, repetitions + 1):
                triple = (entry["snapshot_id"], system["system_id"], repetition)
                identifier = execution.invocation_id(*triple)
                if identifier in seen:
                    raise ContractError(
                        f"invocation id {identifier!r} is produced by both {seen[identifier]} and "
                        f"{triple}; rename the snapshot or the system")
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


def _check_input_snapshots(pack: dict, inputs: list[dict]) -> None:
    """Refuse a configured input the pack does not declare, before anything is written."""
    for entry in inputs:
        cases.snapshot_by_id(pack, entry["snapshot_id"])


def _prepare_input(entry: dict, pack: dict, out_dir: Path, cache_root: Path,
                   clock: Callable[[], datetime] | None) -> tuple[execution.PreparedInput, dict, list[str]]:
    """Fetch, export, verify, and mechanically check one configured input.

    The warnings returned are this input's planning notes, so they state what will actually be
    planned and why a case was left out, rather than restating a check outcome that may not
    decide the question.
    """
    snapshot_id = entry["snapshot_id"]
    profile = entry.get("profile", "standard")
    snapshot = cases.snapshot_by_id(pack, snapshot_id)
    cached = materialize.fetch_snapshot(snapshot["repository"]["url"], snapshot["commit"], cache_root)
    trial = out_dir / "inputs" / snapshot_id
    record = materialize.export_snapshot(cached, trial, profile=profile, clock=clock)
    provenance_path = materialize.write_provenance(trial, record)
    tree_hash = record["trial"]["tree_hash"]
    declared = snapshot.get("tree_hash")
    if declared and declared != tree_hash:
        raise ContractError(
            f"snapshot {snapshot_id} declares tree hash {declared} but the export produced {tree_hash}"
        )
    outcomes = cases.mechanical_checks(pack, snapshot_id, trial / "source", tree_hash, clock=clock)
    _, notes = cases.build_plan(pack, snapshot_id, tree_hash, mode=PLAN_MODE)
    warnings = [f"{snapshot_id}: {note}" for note in notes]
    prepared = execution.PreparedInput(
        snapshot_id, trial / "source", tree_hash, tuple(snapshot["languages"]), record, profile,
    )
    summary = {"snapshot_id": snapshot_id, "tree_hash": tree_hash,
               "provenance_path": _relative(provenance_path, out_dir), "mechanical_checks": outcomes}
    return prepared, summary, warnings


def _prepare_system(entry: dict, cache_root: Path, default_policy: str,
                    adapters: dict[str, Adapter] | None) -> tuple[_PreparedSystem, list[str]]:
    """Resolve one system's adapter and run its preparation phase once.

    Any failure resolving or preparing the adapter is recorded as a skip carrying the
    exception's own type name and message, whether it failed as an adapter, while materializing
    what it needs, on the filesystem, or because its module is not installed. A preparation that
    returns something other than a record is a preparation failure too, because the manifest
    records what preparation produced. None of this aborts the run, no invocation of a skipped
    system is attempted, and a skipped system never becomes an empty successful scan.
    """
    spec = SystemSpec(entry["system_id"], entry["adapter"], dict(entry["config"]),
                      entry.get("model_id"), entry.get("model_revision"))
    adapter: Adapter | None = None
    preparation: dict = {}
    skipped: str | None = None
    warnings: list[str] = []
    try:
        if adapters is not None and spec.adapter in adapters:
            adapter = adapters[spec.adapter]
        else:
            adapter = get_adapter(spec.adapter)
        prepared = adapter.prepare(spec, cache_root)
        if not isinstance(prepared, dict):
            raise AdapterError(
                f"{spec.adapter}.prepare returned {type(prepared).__name__}; a preparation phase "
                "must report what it prepared as a record")
        preparation = prepared
    except Exception as exc:
        preparation = {}
        skipped = f"{type(exc).__name__}: {_message(exc)}"
        warnings.append(f"{spec.system_id}: not invoked ({skipped})")
    policy = entry.get("network_policy", default_policy)
    return _PreparedSystem(spec, adapter, preparation, policy, skipped), warnings


def _evaluate_bundle(bundle: Path, pack: dict, prepared: execution.PreparedInput,
                     clock: Callable[[], datetime] | None) -> tuple[dict, dict, dict, list[str]]:
    """Plan, draft review decisions, score, and report one finished invocation bundle.

    Every decision written here is a machine draft, so no claim earns confirmed detection
    credit on this path, and the report says so: it carries the review record's own state, which
    is what that record claims rather than a verification of it. The plan's scope is whatever the
    pack's recorded label state supports; nothing here changes that state.
    """
    plan, notes = cases.build_plan(pack, prepared.input_id, prepared.tree_hash, mode=PLAN_MODE)
    result = load_document(bundle / "result.json", "scan-result")
    decisions = review.draft_decisions(plan, result, pack, clock=clock)
    record = review.review_record(plan, decisions, clock=clock, notes=notes)
    review.write_evaluator_records(bundle, plan, decisions, record)
    evaluation = scoring.score(plan, result, decisions)
    _write_new(bundle / "evaluation.json", evaluation)
    _write_new_text(bundle / "report.html",
                    report.render_report(evaluation, result, plan, review_state=record["state"]))
    return plan, record, evaluation, notes


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

    ``adapters`` maps adapter names to instances and replaces the registry lookup, so a test
    can supply a fake without touching the registry. ``only_inputs`` and ``only_systems``
    narrow the run; naming something the configuration does not contain is an error rather
    than a silently empty run, and what was narrowed away is recorded in the manifest.
    ``out_dir`` must not exist, and ``workspace_root`` must be outside it.

    An input snapshot the pack does not declare, colliding invocation ids, a cache root that
    overlaps the output directory, and a workspace inside evaluator storage are all refused
    before the output directory is created, so a refused run writes nothing at all. Once that
    directory exists, any failure (preparing an input, preparing an adapter, or running an
    invocation) writes a manifest with status ``failed`` recording what had finished, and the
    exception is re-raised; if writing that partial manifest itself fails, that error propagates
    with the original as its context.

    This does not approve any label, does not retry or rerun a failed invocation, does not
    aggregate across inputs or systems, and does not enforce the declared network policy.
    """
    config_path = Path(config_path)
    out_dir = Path(out_dir)
    config = load_document(config_path, "run-config")
    base = config_path.resolve().parent
    pack_path = base / config["pack"]
    cache_root = base / config.get("cache_root", DEFAULT_CACHE_ROOT)
    pack = cases.load_pack(pack_path)

    inputs = _selected(config["inputs"], "snapshot_id", only_inputs, "inputs")
    systems = _selected(config["systems"], "system_id", only_systems, "systems")
    _check_invocation_ids(inputs, systems, config["repetitions"])
    _check_input_snapshots(pack, inputs)
    _check_cache_root(cache_root, out_dir)
    _check_workspace_root(workspace_root, out_dir, cache_root,
                          [out_dir / "inputs" / entry["snapshot_id"] for entry in inputs])

    selected_inputs = {entry["snapshot_id"] for entry in inputs}
    selected_systems = {entry["system_id"] for entry in systems}
    selection = {
        "only_inputs": sorted(only_inputs) if only_inputs is not None else None,
        "only_systems": sorted(only_systems) if only_systems is not None else None,
        "excluded_inputs": [entry["snapshot_id"] for entry in config["inputs"]
                            if entry["snapshot_id"] not in selected_inputs],
        "excluded_systems": [entry["system_id"] for entry in config["systems"]
                             if entry["system_id"] not in selected_systems],
    }

    out_dir.mkdir(parents=True, exist_ok=False)

    warnings: list[str] = []
    prepared_inputs: list[execution.PreparedInput] = []
    manifest_inputs: list[dict] = []
    prepared_systems: list[_PreparedSystem] = []
    invocations: list[dict] = []
    # Everything from here on is inside the run directory, so every failure is recorded there.
    try:
        _write_new(out_dir / "run-config.json", config)

        for entry in inputs:
            prepared, summary, input_warnings = _prepare_input(entry, pack, out_dir, cache_root, clock)
            prepared_inputs.append(prepared)
            manifest_inputs.append(summary)
            warnings.extend(input_warnings)

        # The pack is frozen once, here: every input has been checked and nothing is invoked yet.
        evaluator_dir = out_dir / "evaluator"
        evaluator_dir.mkdir()
        _write_new(evaluator_dir / "pack.json", pack)

        for entry in systems:
            system, system_warnings = _prepare_system(entry, cache_root, config["network_policy"], adapters)
            prepared_systems.append(system)
            warnings.extend(system_warnings)

        for prepared in prepared_inputs:
            for system in prepared_systems:
                spec = system.spec
                for repetition in range(1, config["repetitions"] + 1):
                    row: dict[str, Any] = {
                        "invocation_id": execution.invocation_id(prepared.input_id, spec.system_id, repetition),
                        "input_id": prepared.input_id, "system_id": spec.system_id, "repetition": repetition,
                    }
                    if system.skipped is not None:
                        invocations.append({**row, "status": "skipped", "claim_records": None, "plan_scope": None,
                                            "targets_assigned": None, "targets_detected": None,
                                            "pending_matching_count": None, "bundle_path": None,
                                            "review_state": None, "skipped_reason": system.skipped})
                        continue
                    bundle = execution.run_invocation(
                        prepared=prepared, adapter=system.adapter, spec=spec,
                        preparation=system.preparation, out_dir=out_dir / "invocations",
                        run_id=config["run_id"], repetition=repetition,
                        timeout_seconds=config["timeout_seconds"], trace_mode=config["trace_mode"],
                        network_policy=system.network_policy, workspace_root=workspace_root, clock=clock,
                    )
                    plan, record, evaluation, notes = _evaluate_bundle(bundle, pack, prepared, clock)
                    for note in notes:
                        warning = f"{prepared.input_id}: {note}"
                        if warning not in warnings:
                            warnings.append(warning)
                    metrics = evaluation["metrics"]
                    invocations.append({**row, "status": evaluation["status"],
                                        "claim_records": metrics["claim_records"], "plan_scope": plan["scope"],
                                        "targets_assigned": metrics["targets_assigned"],
                                        "targets_detected": metrics["targets_detected"],
                                        "pending_matching_count": metrics["pending_matching_count"],
                                        "bundle_path": _relative(bundle, out_dir),
                                        "review_state": record["state"], "skipped_reason": None})
    except BaseException as exc:
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
