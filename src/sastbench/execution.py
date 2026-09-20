"""Run one system once on one prepared input and write a reproducible invocation bundle.

Bundle layout (all evaluator-side; the scanner only ever sees a private workspace copy):

    <out>/<invocation_id>/
      request.json      sanitized scan request, no labels
      result.json       normalized claims with explicit status
      execution.json    exit status, timing, versions, policy, capture, provenance
      raw/              stdout, stderr, native artifacts, captured harness state
      trace/            observer events when the adapter captured any

``raw/`` and ``trace/`` are staged inside the private workspace while the scanner runs and
are moved into the bundle once it returns or raises, so no path handed to an adapter resolves
inside the run directory and declared artifact paths are re-rooted before they are hashed.

An outcome that breaks the adapter contract, an execution record the contract refuses, and a
trace file that is not UTF-8 text are all recorded failures: the bundle then holds an error
result and an execution record carrying the message, never a successful result beside a
missing execution record. The staged raw output is preserved either way.

Directory separation documents the boundary; it does not enforce it. Network and
filesystem policy are declared here and must be enforced outside this process.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePath
import shutil
import tempfile
import time
from typing import Callable

from . import __version__
from .adapters.base import Adapter, NativeOutcome, SystemSpec
from .contracts import ContractError, canonical_json, canonical_sha256, validate_document
from .kinds import mapping_version
from .materialize import hash_exported_tree, prepare_synthetic_history, sha256_file


NETWORK_POLICIES = ("none", "model_provider_only", "unrestricted")
_USAGE_KEYS = ("wall_seconds", "setup_seconds", "cost_usd", "input_tokens", "output_tokens")


class ExecutionError(RuntimeError):
    """The invocation could not be set up or recorded."""


@dataclass(frozen=True)
class PreparedInput:
    input_id: str
    source_dir: Path
    tree_hash: str
    languages: tuple[str, ...]
    provenance: dict
    profile: str = "standard"
    mode: str = "full"


def invocation_id(input_id: str, system_id: str, repetition: int) -> str:
    return f"{input_id}__{system_id}__r{repetition}"


def _now(clock: Callable[[], datetime] | None) -> str:
    moment = (clock or (lambda: datetime.now(timezone.utc)))()
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _write_new(path: Path, value: dict) -> None:
    """Write one canonical JSON document, refusing to overwrite an existing path.

    The document is serialized before the file is created, so a value canonical JSON cannot
    represent leaves no empty file behind for a reader to mistake for a record.
    """
    text = canonical_json(value) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def build_request(run_id: str, prepared: PreparedInput, spec: SystemSpec, *, timeout_seconds: float,
                  trace_mode: str, pr: dict | None = None) -> dict:
    request = {
        "schema_version": "2.0",
        "run_id": run_id,
        "input": {"tree_hash": prepared.tree_hash, "root": ".", "languages": list(prepared.languages),
                  "mode": prepared.mode, "profile": prepared.profile, **({"pr": pr} if pr else {})},
        "system": {"id": spec.system_id, **({"model_id": spec.model_id} if spec.model_id else {}),
                   **({"model_revision": spec.model_revision} if spec.model_revision else {})},
        "limits": {"timeout_seconds": timeout_seconds},
        "trace_mode": trace_mode,
    }
    return validate_document("scan-request", request)


def _failure_message(exc: BaseException) -> str:
    """The exception's own type name and message, for a recorded failure."""
    return f"{type(exc).__name__}: {str(exc) or repr(exc)}"[:2000]


def _move_into_bundle(staging: Path, destination: Path) -> None:
    """Move one staged directory out of the private workspace and into the bundle.

    A staging directory the adapter removed is recreated empty at the destination, so the
    bundle always holds the directory the execution record describes.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    if staging.exists():
        shutil.move(str(staging), str(destination))
    else:
        destination.mkdir(parents=True, exist_ok=True)


def _rebase(path: Path, areas: list[tuple[Path, Path, Path]]) -> Path:
    """Re-root a path the adapter reported in a staging area to its place in the bundle.

    Both the staging path as handed out and its resolved form are tried, because an adapter may
    report either. A path in no staging area is returned unchanged rather than guessed at.
    """
    for staged, resolved, final in areas:
        for base in (staged, resolved):
            try:
                relative = path.relative_to(base)
            except ValueError:
                continue
            return final / relative
    return path


def _file_map(source_dir: Path, ignore_top_level: frozenset[str]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in sorted(source_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(source_dir).as_posix()
        parts = rel.split("/")
        if parts[0] in ignore_top_level or ".git" in parts:
            continue
        hashes[rel] = sha256_file(path)[0]
    return hashes


def _empty_trace(trace_mode: str) -> dict:
    """The trace record for a bundle whose trace was never read: counted as unavailable."""
    return {"path": None, "events": None, "mode": trace_mode, "capture_gap": None, "dropped_events": None}


def _read_trace(outcome: NativeOutcome, staged_areas: list[tuple[Path, Path, Path]], trace_dir: Path,
                trace_mode: str, bundle: Path) -> dict:
    """Count the events in the staged trace file and record where it landed.

    A missing trace file is an unavailable count, not a failure. A file that is not UTF-8 text
    raises, because a count taken from bytes this cannot decode would be an invented number.
    """
    events_path = (_rebase(Path(outcome.trace_path), staged_areas) if outcome.trace_path
                   else trace_dir / "events.jsonl")
    count = None
    recorded_trace_path = None
    if events_path.exists():
        count = sum(1 for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip())
        try:
            recorded_trace_path = events_path.relative_to(bundle).as_posix()
        except ValueError:
            outcome.notes.append("trace file left outside the bundle; its path is not recorded")
    return {"path": recorded_trace_path, "events": count, "mode": trace_mode,
            "capture_gap": (outcome.capture_state or {}).get("capture_gap"),
            "dropped_events": (outcome.capture_state or {}).get("dropped_events")}


def _outcome_violation(outcome: object) -> str | None:
    """The first way *outcome* breaks the adapter contract, or ``None`` when it keeps it.

    This checks only the shapes the bundle documents are built from: the outcome type itself,
    artifact entries, tool versions, command words, usage numbers, notes, and the containers
    this module copies or walks. It says nothing about whether the scan was correct, complete,
    or honest, and it does not check the claims, the ranking, or the status: the scan-result
    contract checks those, and a violation there is recorded as a failed import. A field only
    the execution record constrains, such as a non-integer exit code, is caught when that record
    is validated.
    """
    if not isinstance(outcome, NativeOutcome):
        return f"adapter returned {type(outcome).__name__}, not a NativeOutcome"
    if not isinstance(outcome.artifacts, list):
        return f"artifacts must be a list, not {type(outcome.artifacts).__name__}"
    for index, artifact in enumerate(outcome.artifacts):
        if not isinstance(artifact, dict):
            return f"artifacts[{index}] must be a mapping, not {type(artifact).__name__}"
        identifier = artifact.get("id")
        if not isinstance(identifier, str) or not identifier:
            return f"artifacts[{index}].id must be a non-empty string, not {identifier!r}"
        path = artifact.get("path")
        if not isinstance(path, (str, PurePath)):
            return f"artifacts[{index}].path must be a string or a path, not {type(path).__name__}"
    if not isinstance(outcome.tool_versions, dict):
        return f"tool_versions must be a mapping, not {type(outcome.tool_versions).__name__}"
    for name, version in outcome.tool_versions.items():
        if not isinstance(name, str) or not isinstance(version, str):
            return f"tool_versions[{name!r}] must be a string, not {type(version).__name__}"
    if not isinstance(outcome.command, list):
        return f"command must be a list, not {type(outcome.command).__name__}"
    for index, word in enumerate(outcome.command):
        if not isinstance(word, str):
            return f"command[{index}] must be a string, not {type(word).__name__}"
    if not isinstance(outcome.usage, dict):
        return f"usage must be a mapping, not {type(outcome.usage).__name__}"
    for key, value in outcome.usage.items():
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f"usage[{key!r}] must be a number, not {type(value).__name__}"
    if not isinstance(outcome.notes, list):
        return f"notes must be a list, not {type(outcome.notes).__name__}"
    for index, note in enumerate(outcome.notes):
        if not isinstance(note, str):
            return f"notes[{index}] must be a string, not {type(note).__name__}"
    if not isinstance(outcome.capture, dict):
        return f"capture must be a mapping, not {type(outcome.capture).__name__}"
    if outcome.capture_state is not None and not isinstance(outcome.capture_state, dict):
        return f"capture_state must be a mapping or None, not {type(outcome.capture_state).__name__}"
    if outcome.model_identity is not None and not isinstance(outcome.model_identity, dict):
        return f"model_identity must be a mapping or None, not {type(outcome.model_identity).__name__}"
    if outcome.trace_path is not None and not isinstance(outcome.trace_path, (str, PurePath)):
        return f"trace_path must be a string, a path, or None, not {type(outcome.trace_path).__name__}"
    return None


def _violation_outcome(message: str) -> NativeOutcome:
    """The outcome recorded in place of one that broke the contract.

    Nothing the adapter reported is carried over: an outcome this module could not read is not
    a source of claims, artifact paths, versions, or usage. The raw output the scanner already
    wrote is still staged into the bundle, so what the scan produced on disk is preserved.
    """
    return NativeOutcome(
        status="error", exit_code=None, command=[],
        error={"code": "outcome_contract_violation", "message": message[:2000]},
        notes=[f"The adapter outcome was discarded: {message}"[:2000]])


def run_invocation(
    *,
    prepared: PreparedInput,
    adapter: Adapter,
    spec: SystemSpec,
    preparation: dict,
    out_dir: Path,
    run_id: str,
    repetition: int = 1,
    timeout_seconds: float = 1800,
    trace_mode: str = "off",
    network_policy: str = "none",
    workspace_root: Path | None = None,
    clock: Callable[[], datetime] | None = None,
) -> Path:
    """Execute one invocation and return its bundle directory. Never overwrites.

    ``result.json`` and ``execution.json`` are written only once both documents validate, so a
    bundle never holds a successful result beside a missing execution record. An outcome this
    module cannot read, an execution record the contract refuses, and a trace file that is not
    UTF-8 text all end as an error result carrying code ``outcome_contract_violation`` and a
    message naming what was wrong. The adapter's own outcome is discarded in that case, because
    nothing in it can be trusted to describe the scan; the raw output it had already written is
    still staged into the bundle.
    """
    if network_policy not in NETWORK_POLICIES:
        raise ExecutionError(f"unknown network policy {network_policy!r}")
    if trace_mode not in ("off", "metadata", "content"):
        raise ExecutionError(f"unknown trace mode {trace_mode!r}")
    unsupported = [lang for lang in prepared.languages if lang not in adapter.supported_languages]
    bundle = out_dir / invocation_id(prepared.input_id, spec.system_id, repetition)
    bundle.mkdir(parents=True, exist_ok=False)
    raw_dir = bundle / "raw"
    trace_dir = bundle / "trace" if trace_mode != "off" else None
    request = build_request(run_id, prepared, spec, timeout_seconds=timeout_seconds, trace_mode=trace_mode)
    _write_new(bundle / "request.json", request)

    state_dirs = frozenset(getattr(adapter, "state_dirs", ()))
    workspace = Path(tempfile.mkdtemp(prefix="sastbench-trial-", dir=str(workspace_root) if workspace_root else None))
    # The scanner writes into the workspace, never into the run directory; both staged
    # directories are moved into the bundle below, whether the scan returns or raises.
    resolved_workspace = workspace.resolve()
    staging_raw = workspace / "raw"
    staging_trace = None
    staged_areas = [(staging_raw, resolved_workspace / "raw", raw_dir)]
    if trace_dir is not None:
        staging_trace = workspace / "trace"
        staged_areas.append((staging_trace, resolved_workspace / "trace", trace_dir))
    started_at = _now(clock)
    started = time.monotonic()
    synthetic = None
    outcome: NativeOutcome
    violation: str | None = None
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    try:
        staging_raw.mkdir()
        if staging_trace is not None:
            staging_trace.mkdir()
        source = workspace / "source"
        shutil.copytree(prepared.source_dir, source, symlinks=False)
        before = _file_map(source, state_dirs)
        actual = hash_exported_tree(source)["tree_hash"]
        if actual != prepared.tree_hash:
            raise ExecutionError(f"workspace tree hash {actual} does not match prepared input {prepared.tree_hash}")
        if adapter.requires_git and not (source / ".git").exists():
            synthetic = prepare_synthetic_history(source)
        if unsupported:
            outcome = NativeOutcome(status="unsupported", exit_code=None, command=[],
                                    error={"code": "unsupported_language",
                                           "message": f"{adapter.name} does not declare support for: {', '.join(unsupported)}"},
                                    notes=["Unsupported work stays in the denominator; nothing was executed."])
        else:
            try:
                outcome = adapter.scan(request=request, source_dir=source, raw_dir=staging_raw, spec=spec,
                                       preparation=preparation, timeout_seconds=timeout_seconds,
                                       trace_mode=trace_mode, trace_dir=staging_trace)
            except Exception as exc:
                # Any failure inside the adapter is a recorded error with its own type name,
                # never an empty successful scan and never a crash of the whole run.
                outcome = NativeOutcome(status="error", exit_code=None, command=[],
                                        error={"code": "adapter_failure", "message": _failure_message(exc)})
            else:
                # An outcome this module cannot read is a recorded failure too, checked here so
                # that nothing further reads an attribute the adapter did not really supply.
                violation = _outcome_violation(outcome)
        captured_state = []
        for name in sorted(state_dirs):
            state_path = source / name
            if state_path.exists():
                destination = staging_raw / "harness-state" / name.lstrip(".")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(state_path, destination, symlinks=False)
                captured_state.append(name)
        after = _file_map(source, state_dirs)
    finally:
        try:
            for staged, _resolved, final in staged_areas:
                _move_into_bundle(staged, final)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
    wall = time.monotonic() - started
    finished_at = _now(clock)
    modified = sorted(set(before) ^ set(after) | {p for p in before if p in after and before[p] != after[p]})
    trace_record: dict | None = None

    def build_documents() -> tuple[dict, dict]:
        """The result and execution documents for the outcome as it currently stands."""
        raw_artifacts: list[dict] = []
        for artifact in outcome.artifacts:
            path = _rebase(Path(artifact["path"]), staged_areas)
            if not path.exists():
                outcome.notes.append(f"declared artifact missing: {artifact['id']}")
                continue
            try:
                relative = path.relative_to(bundle).as_posix()
            except ValueError:
                # An artifact the adapter left outside its staging areas is reported, not copied:
                # this records what the scan produced, and never moves files it was not handed.
                outcome.notes.append(f"declared artifact outside the bundle: {artifact['id']}")
                continue
            raw_artifacts.append({"id": artifact["id"], "path": relative, "sha256": sha256_file(path)[0]})
        usage = {key: value for key, value in outcome.usage.items() if key in _USAGE_KEYS and value is not None}
        usage["wall_seconds"] = round(wall, 3)
        if "cost_usd" not in usage:
            usage["cost_usd"] = None
        result = {
            "schema_version": "2.0", "run_id": run_id, "system_id": spec.system_id,
            "input_hash": prepared.tree_hash, "status": outcome.status, "ranking": outcome.ranking,
            "claims": outcome.claims, "bundles_resolved": outcome.bundles_resolved, "usage": usage,
            **({"error": outcome.error} if outcome.error else {}),
            **({"raw_artifacts": raw_artifacts} if raw_artifacts else {}),
        }
        import_error = None
        try:
            validate_document("scan-result", result)
        except ContractError as exc:
            # A normalization that violates the contract is a failed import, not a quiet empty success.
            import_error = str(exc)
            result = {**result, "status": "error", "claims": [], "ranking": "unranked", "bundles_resolved": True,
                      "error": {"code": "import_contract_violation", "message": import_error[:2000]}}
            validate_document("scan-result", result)
        execution = {
            "schema_version": "2.0", "run_id": run_id, "invocation_id": bundle.name,
            "input_id": prepared.input_id, "system_id": spec.system_id, "repetition": repetition,
            "adapter": {"name": adapter.name, "version": adapter.adapter_version},
            "versions": {"sastbench": __version__, "kind_mapping": mapping_version()},
            "status": result["status"], "exit_code": outcome.exit_code,
            "timed_out": bool(outcome.timed_out or outcome.status == "timeout"), "command": list(outcome.command),
            "started_at": started_at, "finished_at": finished_at, "wall_seconds": round(wall, 3),
            "timeout_seconds": timeout_seconds,
            "tool_versions": dict(outcome.tool_versions), "model_identity": outcome.model_identity,
            "system_config": dict(spec.config),
            "network_policy": {"declared": network_policy, "enforced": False,
                               "note": "Policy is recorded, not enforced by this runner; enforce it in the execution environment."},
            "environment": {"passthrough": sorted(set(("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "USER", "SHELL")
                                                      + tuple(adapter.env_passthrough)))},
            "capture": dict(outcome.capture), "trace": trace_record,
            "provenance": {"tree_hash": prepared.tree_hash, "provenance_sha256": canonical_sha256(prepared.provenance),
                           "profile": prepared.profile, "synthetic_history": synthetic,
                           "source_modified": bool(modified), "modified_paths": modified[:200],
                           "captured_state_dirs": captured_state},
            "preparation": preparation, "unsupported_languages": unsupported,
            "error": result.get("error"), "import_error": import_error,
            "notes": list(outcome.notes), "raw_artifacts": raw_artifacts,
        }
        return result, execution

    if violation is None and trace_dir is not None:
        try:
            trace_record = _read_trace(outcome, staged_areas, trace_dir, trace_mode, bundle)
        except (UnicodeDecodeError, OSError) as exc:
            # A trace this module cannot read as UTF-8 text is a recorded failure, not a
            # silently missing count beside an otherwise successful result.
            violation = f"trace file could not be read as UTF-8 text: {_failure_message(exc)}"

    if violation is not None:
        outcome = _violation_outcome(violation)
        trace_record = _empty_trace(trace_mode) if trace_dir is not None else None
    result, execution = build_documents()
    try:
        validate_document("execution-record", execution)
    except ContractError as exc:
        # The record the outcome produced is not writable, so the outcome is discarded and the
        # refusal itself becomes the recorded failure; the result never stays a success.
        outcome = _violation_outcome(f"execution record violates its contract: {exc}")
        trace_record = _empty_trace(trace_mode) if trace_dir is not None else None
        result, execution = build_documents()
        validate_document("execution-record", execution)
    _write_new(bundle / "result.json", result)
    _write_new(bundle / "execution.json", execution)
    return bundle
