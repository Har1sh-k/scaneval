"""Run one system once on one prepared input and write a reproducible invocation bundle.

Bundle layout (all evaluator-side; the scanner only ever sees a private workspace copy):

    <out>/<invocation_id>/
      request.json      sanitized scan request, no labels
      result.json       normalized claims with explicit status
      execution.json    exit status, timing, versions, policy, capture, provenance
      raw/              stdout, stderr, native artifacts, captured harness state
      trace/            observer events when the adapter captured any

Directory separation documents the boundary; it does not enforce it. Network and
filesystem policy are declared here and must be enforced outside this process.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import shutil
import tempfile
import time
from typing import Callable

from . import __version__
from .adapters.base import Adapter, AdapterError, NativeOutcome, SystemSpec
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
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical_json(value) + "\n")


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
    """Execute one invocation and return its bundle directory. Never overwrites."""
    if network_policy not in NETWORK_POLICIES:
        raise ExecutionError(f"unknown network policy {network_policy!r}")
    if trace_mode not in ("off", "metadata", "content"):
        raise ExecutionError(f"unknown trace mode {trace_mode!r}")
    unsupported = [lang for lang in prepared.languages if lang not in adapter.supported_languages]
    bundle = out_dir / invocation_id(prepared.input_id, spec.system_id, repetition)
    bundle.mkdir(parents=True, exist_ok=False)
    raw_dir = bundle / "raw"
    raw_dir.mkdir()
    trace_dir = None
    if trace_mode != "off":
        trace_dir = bundle / "trace"
        trace_dir.mkdir()
    request = build_request(run_id, prepared, spec, timeout_seconds=timeout_seconds, trace_mode=trace_mode)
    _write_new(bundle / "request.json", request)

    state_dirs = frozenset(getattr(adapter, "state_dirs", ()))
    workspace = Path(tempfile.mkdtemp(prefix="sastbench-trial-", dir=str(workspace_root) if workspace_root else None))
    started_at = _now(clock)
    started = time.monotonic()
    synthetic = None
    outcome: NativeOutcome
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    try:
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
                outcome = adapter.scan(request=request, source_dir=source, raw_dir=raw_dir, spec=spec,
                                       preparation=preparation, timeout_seconds=timeout_seconds,
                                       trace_mode=trace_mode, trace_dir=trace_dir)
            except AdapterError as exc:
                outcome = NativeOutcome(status="error", exit_code=None, command=[],
                                        error={"code": "adapter_failure", "message": str(exc)[:2000]})
        captured_state = []
        for name in sorted(state_dirs):
            state_path = source / name
            if state_path.exists():
                destination = raw_dir / "harness-state" / name.lstrip(".")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(state_path, destination, symlinks=False)
                captured_state.append(name)
        after = _file_map(source, state_dirs)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
    wall = time.monotonic() - started
    finished_at = _now(clock)

    raw_artifacts = []
    for artifact in outcome.artifacts:
        path = Path(artifact["path"])
        if not path.exists():
            outcome.notes.append(f"declared artifact missing: {artifact['id']}")
            continue
        raw_artifacts.append({"id": artifact["id"], "path": path.relative_to(bundle).as_posix(),
                              "sha256": sha256_file(path)[0]})
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
    _write_new(bundle / "result.json", result)

    modified = sorted(set(before) ^ set(after) | {p for p in before if p in after and before[p] != after[p]})
    trace_record = None
    if trace_dir is not None:
        events_path = outcome.trace_path if outcome.trace_path else trace_dir / "events.jsonl"
        count = None
        if events_path.exists():
            count = sum(1 for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip())
        trace_record = {"path": events_path.relative_to(bundle).as_posix() if events_path.exists() else None,
                        "events": count, "mode": trace_mode,
                        "capture_gap": (outcome.capture_state or {}).get("capture_gap"),
                        "dropped_events": (outcome.capture_state or {}).get("dropped_events")}
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
    validate_document("execution-record", execution)
    _write_new(bundle / "execution.json", execution)
    return bundle
