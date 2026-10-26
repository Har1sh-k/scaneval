"""Execute already frozen matrix cells and bind immutable scanner artifacts to assignments."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Callable

from . import experiment, runner
from .adapters import get_adapter
from .artifacts import write_new
from .contracts import (ContractError, _reject_json_constant, _strict_object, canonical_json,
                        canonical_sha256, load_document, refuse_trial_path)
from .execution import read_regular_file


BINDING_FILE = "experiment-binding.json"
EXECUTION_FILE = "matrix-execution.json"
IMMUTABLE_INVOCATION_FILES = (
    "request.json", "result.json", "execution.json", "condition.json", "condition-policy.json",
    "condition-configuration.json", "condition-evidence.json", "input-provenance.json",
    "evaluator/identity-transform.json",
)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(read_regular_file(Path(path)).decode("utf-8"), object_pairs_hook=_strict_object,
                           parse_constant=_reject_json_constant)
    except (OSError, ValueError, UnicodeError) as exc:
        raise ContractError(f"cannot read experiment artifact {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("experiment artifact must be a JSON object")
    return value


def load_matrix(path: Path) -> dict:
    value = read_json(path)
    return experiment.validate_matrix(value)


def _write(path: Path, value: dict) -> None:
    write_new(path, canonical_json(value) + "\n")


def artifact_hash(root: Path, relative: str) -> str | None:
    if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
            or ".." in Path(relative).parts):
        raise ContractError("experiment artifact path escapes its evaluator directory")
    path = root / relative
    current = path
    while current != root:
        if current.is_symlink():
            raise ContractError("experiment artifact traverses a symbolic link")
        current = current.parent
    if not path.exists():
        return None
    raw = read_regular_file(path)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def freeze_file(declaration_path: Path, output_path: Path, *, created_at: str,
                adapters: dict | None = None) -> dict:
    refuse_trial_path(output_path)
    frozen = experiment.freeze(load_matrix(declaration_path), base_dir=Path(declaration_path).resolve().parent,
                               created_at=created_at, adapters=adapters)
    _write(output_path, frozen)
    return frozen


def _base_binding(matrix: dict, cell: dict) -> dict:
    return {"schema_version": "2.1", "binding_version": "1", "experiment_id": matrix["experiment_id"],
            "experiment_version": matrix["experiment_version"], "matrix_sha256": matrix["matrix_sha256"],
            "condition": cell["name"], "cell_config_sha256": cell["config_sha256"],
            "population_sha256": matrix["bindings"]["population_sha256"],
            "adjudication_sha256": matrix["bindings"]["adjudication_sha256"]}


def _verify_staged(matrix: dict, cell: dict, out: Path) -> None:
    expected = {"matrix.json": matrix,
                "assignments.json": {"matrix_sha256": matrix["matrix_sha256"], "assignments": matrix["assignments"]}}
    prefix = "cells/" + cell["name"] + "/"
    expected.update({prefix + "run-config.json": cell["config"], prefix + "pack.json": matrix["pack"],
        prefix + "assignments.json": {"matrix_sha256": matrix["matrix_sha256"], "assignments": cell["assignments"]},
        prefix + BINDING_FILE: _base_binding(matrix, cell)})
    for entry in cell["config"]["inputs"]:
        if "blinding_map" in entry:
            path = entry["blinding_map"]
            expected[prefix + path] = matrix["maps"]["sha256:" + Path(path).stem]
    for relative, value in expected.items():
        if artifact_hash(out, relative) is None or read_json(out / relative) != value:
            raise ContractError(f"staged matrix artifact changed before scanner invocation: {relative}")


def _verify_run_semantics(matrix: dict, cell: dict, root: Path) -> None:
    if (root / "run-config.json").exists() and read_json(root / "run-config.json") != cell["config"]:
        raise ContractError("executed run configuration differs from its frozen matrix cell")
    expected = {row["assignment_id"]: row for row in cell["assignments"]}
    if (root / "run-manifest.json").exists():
        manifest = load_document(root / "run-manifest.json", "run-manifest")
        if manifest["run_id"] != cell["config"]["run_id"] or manifest["config_sha256"] != cell["config_sha256"]:
            raise ContractError("run manifest does not bind the frozen cell configuration")
        ids = [row["invocation_id"] for row in manifest["invocations"]]
        if not set(ids) <= set(expected) or (manifest["status"] == "completed" and set(ids) != set(expected)):
            raise ContractError("run manifest omits or adds frozen matrix assignments")
    if (root / "evaluator/schedule.json").exists():
        scheduled = load_document(root / "evaluator/schedule.json", "evaluation-schedule")
        ids = [row["assignment_id"] for row in scheduled["assignments"]]
        if scheduled["config_sha256"] != cell["config_sha256"] or set(ids) != set(expected):
            raise ContractError("executed schedule differs from the complete frozen matrix population")
        snapshots = {source["snapshot_id"]: source for source in matrix["population"]}
        if {row["input_id"] for row in scheduled["inputs"]} != set(snapshots):
            raise ContractError("executed schedule changes the frozen source population")
        for source in scheduled["inputs"]:
            if source["plan"] != snapshots[source["snapshot_id"]]["schedule_plan"]:
                raise ContractError("executed target/control eligibility differs from its frozen matrix population")


def _bind_run(matrix: dict, cell: dict, root: Path) -> list[dict]:
    base = _base_binding(matrix, cell)
    recorded = []
    if root.is_symlink() or not root.is_dir():
        return recorded
    _verify_run_semantics(matrix, cell, root)
    _write(root / BINDING_FILE, {**base, "artifact_hashes": {
        relative: artifact_hash(root, relative) for relative in
        ("run-config.json", "run-manifest.json", "evaluator/schedule.json", "evaluator/pack.json")}})
    for assignment in cell["assignments"]:
        bundle = root / "invocations" / assignment["assignment_id"]
        if bundle.is_symlink():
            raise ContractError("matrix invocation bundle is a symbolic link")
        if not bundle.is_dir():
            continue
        documents = {}
        for kind, relative in (("scan-request", "request.json"), ("scan-result", "result.json"),
                               ("execution-record", "execution.json")):
            if (bundle / relative).exists():
                value = load_document(bundle / relative, kind)
                documents[relative] = value
                system_id = (value.get("system") or {}).get("id") if kind == "scan-request" else value.get("system_id")
                if value.get("run_id") != assignment["run_id"] or system_id != assignment["system_id"]:
                    raise ContractError("saved scanner artifacts name a different matrix assignment")
        if "request.json" in documents and "result.json" in documents and (
                documents["request.json"]["input"]["tree_hash"] != documents["result.json"]["input_hash"]):
            raise ContractError("matrix request and result bind different source trees")
        value = {**base, "assignment": assignment, "artifact_hashes": {
            relative: artifact_hash(bundle, relative) for relative in IMMUTABLE_INVOCATION_FILES}}
        _write(bundle / BINDING_FILE, value)
        recorded.append({"assignment_id": assignment["assignment_id"], "binding_sha256": canonical_sha256(value)})
    return recorded


def verify_binding(root: Path, matrix: dict, cell: dict, *, assignment: dict | None = None) -> dict:
    """Verify both the frozen experiment identity and every immutable saved scanner byte."""
    root = Path(root).resolve()
    marker = read_json(root / BINDING_FILE)
    for key, value in _base_binding(matrix, cell).items():
        if marker.get(key) != value:
            raise ContractError("saved run/result binds to a different matrix version, condition, population, or adjudication")
    if assignment is not None and marker.get("assignment") != assignment:
        raise ContractError("saved result binds to a different scheduled matrix assignment")
    expected = (set(IMMUTABLE_INVOCATION_FILES) if assignment is not None else
                {"run-config.json", "run-manifest.json", "evaluator/schedule.json", "evaluator/pack.json"})
    hashes = marker.get("artifact_hashes")
    if not isinstance(hashes, dict) or set(hashes) != expected:
        raise ContractError("matrix artifact binding inventory is missing or unexpected")
    if any(artifact_hash(root, relative) != digest for relative, digest in hashes.items()):
        raise ContractError("saved scanner artifacts changed after matrix execution")
    return marker


def execute(frozen_path: Path, out_dir: Path, *, workspace_root: Path | None = None,
            adapters: dict | None = None, clock: Callable[[], datetime] | None = None,
            progress=None) -> dict:
    """Stage all cells before the first scanner, then execute each under its frozen run config.

    A cell failure does not remove any assignment or prevent other cells from running. Every
    immutable scanner artifact receives a matrix/assignment binding; later human review remains
    separate and is checked for cross-condition consistency by the matrix reporter.
    """
    matrix = experiment.validate_frozen(load_matrix(frozen_path))
    out = Path(out_dir).expanduser().resolve()
    refuse_trial_path(out)
    if out.exists():
        raise FileExistsError(f"matrix output directory already exists: {out}")
    if workspace_root is not None:
        workspace_root = Path(workspace_root).expanduser().resolve()
        if not workspace_root.is_dir() or workspace_root == out or workspace_root.is_relative_to(out):
            raise ContractError("matrix workspace must already exist outside the evaluator output")
    for system in matrix["systems"]:
        adapter = (adapters or {}).get(system["adapter"]) or get_adapter(system["adapter"])
        if {"name": adapter.name, "version": adapter.adapter_version} != system["adapter_identity"]:
            raise ContractError(f"adapter version changed after freezing system {system['system_id']}")
    cells = {cell["name"]: cell for cell in matrix["cells"]}
    out.mkdir(parents=True, exist_ok=False)
    _write(out / "matrix.json", matrix)
    _write(out / "assignments.json", {"matrix_sha256": matrix["matrix_sha256"], "assignments": matrix["assignments"]})
    # Every config, label pack, transformation map, and assignment exists before any runner call.
    for name in matrix["cell_order"]:
        cell = cells[name]
        root = out / "cells" / name
        root.mkdir(parents=True)
        _write(root / "run-config.json", cell["config"])
        _write(root / "pack.json", matrix["pack"])
        _write(root / "assignments.json", {"matrix_sha256": matrix["matrix_sha256"], "assignments": cell["assignments"]})
        _write(root / BINDING_FILE, _base_binding(matrix, cell))
        selected = {entry["blinding_map"] for entry in cell["config"]["inputs"] if "blinding_map" in entry}
        for path in selected:
            digest = "sha256:" + Path(path).stem
            mapping = matrix["maps"].get(digest)
            if mapping is None:
                raise ContractError("frozen cell references an unavailable transformation map")
            (root / "maps").mkdir(exist_ok=True)
            _write(root / path, mapping)
    finished = []
    interrupted = None
    try:
        for name in matrix["cell_order"]:
            cell = cells[name]
            row = {"condition": name, "run_path": "runs/" + name,
                   "assignments": len(cell["assignments"]), "status": "unavailable", "error": None,
                   "recorded_bindings": []}
            finished.append(row)
            try:
                _verify_staged(matrix, cell, out)
                manifest = runner.run_from_config(out / "cells" / name / "run-config.json", out / row["run_path"],
                    workspace_root=workspace_root, adapters=adapters, clock=clock, progress=progress)
                row["status"] = manifest["status"]
            except Exception as exc:
                row["status"] = "failed"
                row["error"] = {"type": type(exc).__name__, "message": str(exc)[:2000]}
            finally:
                try:
                    row["recorded_bindings"] = _bind_run(matrix, cell, out / row["run_path"])
                except Exception as exc:
                    row["status"] = "failed"
                    row["binding_error"] = {"type": type(exc).__name__, "message": str(exc)[:2000]}
    except BaseException as exc:
        interrupted = {"type": type(exc).__name__, "message": str(exc)[:2000]}
        raise
    finally:
        moment = (clock or (lambda: datetime.now(timezone.utc)))()
        manifest = {"schema_version": "2.1", "experiment_id": matrix["experiment_id"],
            "experiment_version": matrix["experiment_version"], "matrix_sha256": matrix["matrix_sha256"],
            "finished_at": moment.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "status": "interrupted" if interrupted else "completed", "interruption": interrupted,
            "assignments": len(matrix["assignments"]), "cells": finished}
        _write(out / EXECUTION_FILE, manifest)
    return manifest
