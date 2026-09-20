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

An outcome that breaks the adapter contract, an execution record the contract refuses, a trace
file that is not UTF-8 text, and anything raised while capturing harness state, moving the
staged directories, collecting artifacts, or serializing what the adapter reported are all
recorded failures: the bundle then holds an error result and an execution record carrying the
message, never a successful result beside a missing execution record. The staged raw output is
preserved either way.

Directory separation documents the boundary; it does not enforce it. Network and
filesystem policy are declared here and must be enforced outside this process.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import os
from pathlib import Path, PurePath
import shutil
import tempfile
import time
from typing import Callable
import uuid

from . import __version__
from .adapters.base import Adapter, NativeOutcome, SystemSpec
from .contracts import ContractError, canonical_json, canonical_sha256, validate_document
from .kinds import mapping_version
from .materialize import hash_exported_tree, prepare_synthetic_history, sha256_file


NETWORK_POLICIES = ("none", "model_provider_only", "unrestricted")
_USAGE_KEYS = ("wall_seconds", "setup_seconds", "cost_usd", "input_tokens", "output_tokens")


class ExecutionError(RuntimeError):
    """The invocation could not be set up or recorded."""


class _BundleRefused(Exception):
    """The bundle documents cannot be written as built; the message names the refusal.

    Raised only inside :func:`run_invocation`, which then discards the adapter's outcome and
    records the refusal itself. It never leaves this module: a refusal that survives the rebuild
    becomes an :class:`ExecutionError` and no document is written.
    """


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


def _canonical_bytes(value: dict) -> bytes:
    """The exact UTF-8 bytes of one canonical JSON document.

    A lone UTF-16 surrogate survives :func:`canonical_json` and every contract check but cannot
    be encoded, so the encoding happens here, before any file exists, rather than inside an open
    file where it would leave an empty record behind.
    """
    text = canonical_json(value) + "\n"
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"value is not canonical UTF-8 JSON: {exc}") from exc


def _write_new_bytes(path: Path, payload: bytes) -> None:
    """Write *payload* at *path* in one step, refusing to overwrite an existing path.

    The bytes go to a temporary file in the same directory and are renamed into place, so a
    reader never sees a partially written document: a bundle document is either absent or
    complete, and a truncated ``execution.json`` never appears beside a valid ``result.json``.
    The existence check and the rename are two operations rather than one, so this refuses a
    record that is already there; it does not arbitrate between concurrent writers for one path.
    """
    if os.path.lexists(path):
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(path))
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.part")
    # Created the way a plain create would be, so the umask still decides the mode, and with
    # O_EXCL so this never writes through a name something else put there first.
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _write_new(path: Path, value: dict) -> None:
    """Write one canonical JSON document, refusing to overwrite an existing path.

    The document is serialized and encoded before the file is created, so a value canonical JSON
    or UTF-8 cannot represent leaves no empty file behind for a reader to mistake for a record.
    """
    _write_new_bytes(path, _canonical_bytes(value))


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


def _resolves_inside(path: Path, base: Path) -> bool:
    """True when *path* resolves inside *base*, every symbolic link on the way followed first.

    Used to refuse a path an adapter reported that leaves the bundle through a link. It compares
    resolved paths only: it does not follow bind mounts or hard links, so it catches the obvious
    escape and is not an isolation boundary. A path that cannot be resolved at all is not inside
    anything: the filesystem refused it (``OSError``) or it is not a path the filesystem accepts,
    such as one holding an embedded NUL byte (``ValueError``).
    """
    try:
        resolved = path.resolve()
        root = base.resolve()
    except (OSError, ValueError):
        return False
    return resolved == root or resolved.is_relative_to(root)


def _move_into_bundle(staging: Path, destination: Path) -> None:
    """Move one staged directory out of the private workspace and into the bundle.

    A staging directory the adapter removed is recreated empty at the destination, so the
    bundle always holds the directory the execution record describes. A staging directory the
    adapter replaced with a symbolic link is refused instead of moved: moving it would make the
    bundle's own ``raw/`` or ``trace/`` a link to somewhere outside the bundle while the run
    recorded a success. The caller records that refusal as an outcome contract violation.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    if staging.is_symlink():
        raise ExecutionError(
            f"the staging directory {staging.name} is a symbolic link, not a directory; it was "
            "not moved into the bundle")
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

    Only a regular file this bundle actually holds is read: a trace path that is a symbolic link,
    that resolves outside the bundle, or that is not a regular file is refused with a note and no
    count. A number taken from a file the run never staged would describe something the bundle
    does not contain, and opening a named pipe for reading would block until something wrote to
    it, which nothing here ever does. A missing trace file is an unavailable count, not a
    failure. A file that is not UTF-8 text raises, because a count taken from bytes this cannot
    decode would be an invented number.
    """
    events_path = (_rebase(Path(outcome.trace_path), staged_areas) if outcome.trace_path
                   else trace_dir / "events.jsonl")
    count = None
    recorded_trace_path = None
    if events_path.is_symlink():
        outcome.notes.append("declared trace file is a symbolic link; it was not read or counted")
    elif not _resolves_inside(events_path, bundle):
        outcome.notes.append("declared trace file is outside the bundle; it was not read or counted")
    elif events_path.exists() and not events_path.is_file():
        outcome.notes.append("declared trace file is not a regular file; it was not read or "
                             f"counted: {events_path.name}")
    elif events_path.is_file():
        try:
            recorded_trace_path = events_path.relative_to(bundle).as_posix()
        except ValueError:
            outcome.notes.append("trace file left outside the bundle; its path is not recorded")
        else:
            count = sum(1 for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip())
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


def _error_result(run_id: str, system_id: str, input_hash: str, wall: float, error: dict) -> dict:
    """A scan result carrying an explicit error and nothing the adapter supplied.

    Only fields the scan request already validated and this module computed are used, so a value
    the adapter reported cannot carry its own contract violation into the record that reports
    the refusal. The raw artifacts stay in the execution record, which is where a failed import
    leaves the evidence of what the scan wrote.
    """
    return {"schema_version": "2.0", "run_id": run_id, "system_id": system_id,
            "input_hash": input_hash, "status": "error", "claims": [], "ranking": "unranked",
            "bundles_resolved": True, "usage": {"wall_seconds": round(wall, 3), "cost_usd": None},
            "error": error}


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

    ``result.json`` and ``execution.json`` are written only once both documents validate and
    encode, so a bundle never holds a successful result beside a missing execution record. An
    outcome this module cannot read, an execution record the contract refuses, a trace file that
    is not UTF-8 text, and any failure while capturing harness state, moving the staged
    directories into the bundle, collecting or hashing declared artifacts, or serializing what
    the adapter reported all end as an error result carrying code ``outcome_contract_violation``
    and a message naming what was wrong. The adapter's own outcome is discarded in that case,
    because nothing in it can be trusted to describe the scan; the raw output it had already
    written is still staged into the bundle where the failure allowed it.

    Two things are narrower than they look. When the post-scan re-hash of the source fails, the
    comparison never completed, so the provenance reports no observed modification and the
    violation names the failed re-hash. And an adapter whose own ``name`` or ``adapter_version``
    is not a non-empty string makes the execution record unwritable: that raises
    :class:`ExecutionError` once the bundle directory, its ``request.json``, and the staged
    ``raw/`` and ``trace/`` trees are already there, so what remains is a bundle holding the
    request and the scanner's own output with neither ``result.json`` nor ``execution.json``.
    That is why :mod:`sastbench.runner` vets the attributes every record copies when it prepares
    a system rather than when it invokes one.
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
    captured_state: list[str] = []
    move_failures: list[str] = []
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
        try:
            for name in sorted(state_dirs):
                state_path = source / name
                if state_path.exists():
                    destination = staging_raw / "harness-state" / name.lstrip(".")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(state_path, destination, symlinks=False)
                    captured_state.append(name)
        except Exception as exc:
            # The scanner owns both ends of this copy: the state directory it wrote and the
            # staging path it may have created there first. A failure is a recorded violation,
            # never a crash of the run, and the directories copied before it stay recorded.
            violation = violation or f"harness state could not be captured: {_failure_message(exc)}"
        try:
            after = _file_map(source, state_dirs)
        except Exception as exc:
            # The comparison never completed, so nothing is claimed about the source: `before`
            # stands in for `after`, the provenance reports no observed modification, and the
            # violation says the re-hash failed.
            after = dict(before)
            violation = violation or f"the source tree could not be re-hashed: {_failure_message(exc)}"
    finally:
        try:
            for staged, _resolved, final in staged_areas:
                try:
                    _move_into_bundle(staged, final)
                except Exception as exc:
                    # A staged directory that cannot be moved is recorded below rather than
                    # raised here, where it would replace whatever failure is already in flight.
                    move_failures.append(f"{final.name}: {_failure_message(exc)}")
        finally:
            shutil.rmtree(workspace, ignore_errors=True)
    if move_failures:
        violation = violation or ("staged output could not be moved into the bundle: "
                                  + "; ".join(move_failures))
    wall = time.monotonic() - started
    finished_at = _now(clock)
    modified = sorted(set(before) ^ set(after) | {p for p in before if p in after and before[p] != after[p]})
    trace_record: dict | None = None

    def build_documents() -> tuple[dict, dict]:
        """The result and execution documents for the outcome as it currently stands."""
        raw_artifacts: list[dict] = []
        for artifact in outcome.artifacts:
            path = _rebase(Path(artifact["path"]), staged_areas)
            if path.is_symlink():
                # A link is never followed and never hashed: what it points at is not the file
                # this bundle preserved, and need not be inside the bundle at all.
                outcome.notes.append(f"declared artifact is a symbolic link and was not followed: {artifact['id']}")
                continue
            if path.exists() and not _resolves_inside(path, bundle):
                outcome.notes.append(f"declared artifact resolves outside the bundle: {artifact['id']}")
                continue
            if not path.exists():
                outcome.notes.append(f"declared artifact missing: {artifact['id']}")
                continue
            if not path.is_file():
                # Only a regular file is hashed. A directory has no bytes of its own, and opening
                # a named pipe for reading would block until something wrote to it.
                outcome.notes.append(
                    f"declared artifact is not a regular file and was not hashed: {artifact['id']}")
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
            # A normalization that violates the contract is a failed import, not a quiet empty
            # success. The replacement is built from known-good fields only: spreading the
            # refused document would carry its usage or artifacts, and their violation with
            # them, straight into the record that reports the refusal.
            import_error = str(exc)
            result = _error_result(run_id, spec.system_id, prepared.tree_hash, wall,
                                   {"code": "import_contract_violation", "message": import_error[:2000]})
            try:
                validate_document("scan-result", result)
            except ContractError as refusal:
                raise _BundleRefused(
                    f"scan result violates its contract and its error record was refused too: "
                    f"{refusal}") from refusal
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

    def finished_documents() -> tuple[bytes, bytes]:
        """The exact bytes of both bundle documents, built, validated, and encoded together.

        Every way the documents can fail to be written is a :class:`_BundleRefused` naming it:
        anything raised while collecting or hashing declared artifacts, a scan result the
        contract refuses even as an explicit error record, an execution record the contract
        refuses, anything else raised while validating that record, and a document holding text
        UTF-8 cannot encode. Nothing is written until both documents survive all of it.
        """
        try:
            result, execution = build_documents()
        except _BundleRefused:
            raise
        except Exception as exc:
            raise _BundleRefused(
                f"the bundle documents could not be built: {_failure_message(exc)}") from exc
        try:
            validate_document("execution-record", execution)
        except ContractError as exc:
            raise _BundleRefused(f"execution record violates its contract: {exc}") from exc
        except Exception as exc:
            # Validating walks what the adapter supplied, so a cyclic capture or model_identity
            # mapping raises here rather than violating the contract. Contained the same way the
            # build step is, so no adapter-supplied mapping escapes as a crash of the run.
            raise _BundleRefused(
                f"the execution record could not be validated: {_failure_message(exc)}") from exc
        try:
            return _canonical_bytes(result), _canonical_bytes(execution)
        except ContractError as exc:
            raise _BundleRefused(f"the bundle documents could not be encoded: {exc}") from exc

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
    try:
        result_bytes, execution_bytes = finished_documents()
    except _BundleRefused as refused:
        # The documents the outcome produced are not writable, so the outcome is discarded and
        # the refusal itself becomes the recorded failure; the result never stays a success.
        outcome = _violation_outcome(str(refused))
        trace_record = _empty_trace(trace_mode) if trace_dir is not None else None
        try:
            result_bytes, execution_bytes = finished_documents()
        except _BundleRefused as again:
            # Nothing the adapter supplied is left in these documents, so the refusal is about
            # the invocation itself; writing half a bundle would be worse than writing none.
            raise ExecutionError(f"the invocation could not be recorded: {again}") from again
    _write_new_bytes(bundle / "result.json", result_bytes)
    _write_new_bytes(bundle / "execution.json", execution_bytes)
    return bundle
