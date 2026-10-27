"""Execute already frozen matrix cells and bind immutable scanner artifacts to assignments."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
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
    "evaluator/identity-context.json",
)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(read_regular_file(Path(path)).decode("utf-8"), object_pairs_hook=_strict_object,
                           parse_constant=_reject_json_constant)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
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
    try:
        raw = read_regular_file(path)
    except (OSError, ValueError) as exc:
        raise ContractError(f"cannot hash a regular experiment artifact: {relative}: {exc}") from exc
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


def _check_schedule(matrix: dict, cell: dict, scheduled: dict) -> None:
    """Require one cell schedule's inputs, assignments, and frozen plans to equal the frozen cell.

    Pure: shared by the prepared-cell guard and post-run verification. ``created_at`` and the
    pack digest are not compared, so independently refreshed check timestamps are not drift.
    """
    expected = {row["assignment_id"]: row for row in cell["assignments"]}
    ids = [row["assignment_id"] for row in scheduled["assignments"]]
    if scheduled["config_sha256"] != cell["config_sha256"] or set(ids) != set(expected):
        raise ContractError("executed schedule differs from the complete frozen matrix population")
    for row in scheduled["assignments"]:
        assignment = expected[row["assignment_id"]]
        if any(row[key] != assignment[expected_key] for key, expected_key in
               (("input_id", "snapshot_id"), ("system_id", "system_id"), ("repetition", "repetition"))):
            raise ContractError("scheduled assignment identity differs from the frozen matrix")
    snapshots = {source["snapshot_id"]: source for source in matrix["population"]}
    if {row["input_id"] for row in scheduled["inputs"]} != set(snapshots):
        raise ContractError("executed schedule changes the frozen source population")
    for source in scheduled["inputs"]:
        if source["plan"] != snapshots[source["snapshot_id"]]["schedule_plan"]:
            raise ContractError("executed target/control eligibility differs from its frozen matrix population")


def _prepared_guard(matrix: dict, cell: dict) -> Callable[[dict, dict], None]:
    """Refuse a cell whose input preparation changed frozen labels or eligibility.

    The runner calls this after every input of the cell is prepared and its runtime pack is saved,
    before any system is prepared or adapter invoked, with that pack and a schedule rebuilt from it.
    """
    def guard(pack: dict, rebuilt: dict) -> None:
        try:
            if experiment.label_contract(pack) != experiment.label_contract(matrix["pack"]):
                raise ContractError("runtime corpus labels, source bindings, review state, or eligibility differ from the frozen pack")
            _check_schedule(matrix, cell, rebuilt)
        except ContractError as exc:
            raise ContractError(
                f"input preparation changed frozen labels or eligibility for matrix cell {cell['name']} "
                f"({exc}); no scanner was prepared or invoked. Run case checks, review the resulting pack, "
                "and freeze a new matrix") from exc
    return guard


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
        for row in manifest["invocations"]:
            assignment = expected[row["invocation_id"]]
            if any(row[key] != assignment[expected_key] for key, expected_key in
                   (("input_id", "snapshot_id"), ("system_id", "system_id"), ("repetition", "repetition"))):
                raise ContractError("manifest assignment identity differs from the frozen matrix")
    if (root / "evaluator/schedule.json").exists():
        _check_schedule(matrix, cell, load_document(root / "evaluator/schedule.json", "evaluation-schedule"))
    invocations = root / "invocations"
    if invocations.is_dir() and any(path.name not in expected for path in invocations.iterdir()):
        raise ContractError("run contains unexpected invocation output outside the frozen schedule")


def _assignment_states(cell: dict, status: str, reason: str | None = None) -> list[dict]:
    return [{"assignment_id": row["assignment_id"], "status": status, "reason": reason,
             "binding_sha256": None} for row in cell["assignments"]]


def load_execution(directory: Path, matrix: dict) -> dict:
    """Validate execution bookkeeping separately from scanner evidence and scoring outcomes."""
    digest = artifact_hash(directory, EXECUTION_FILE)
    if digest is None:
        return {"state": "unavailable", "reason": "No execution manifest was saved; execution state is unknown.",
                "sha256": None, "manifest": None}
    value = read_json(directory / EXECUTION_FILE)
    if (value.get("schema_version") != "2.1" or any(value.get(key) != matrix[key] for key in
            ("experiment_id", "experiment_version", "matrix_sha256"))
            or value.get("assignments") != len(matrix["assignments"])
            or value.get("status") not in ("completed", "incomplete", "interrupted")
            or not isinstance(value.get("finished_at"), str)):
        raise ContractError("execution manifest differs from its frozen matrix identity or assignment count")
    rows = value.get("cells")
    if not isinstance(rows, list) or [row.get("condition") for row in rows if isinstance(row, dict)] != matrix["cell_order"]:
        raise ContractError("execution manifest omits, duplicates, or reorders frozen cells")
    cells = {cell["name"]: cell for cell in matrix["cells"]}
    for row in rows:
        cell = cells[row["condition"]]
        if (row.get("run_path") != "runs/" + cell["name"] or row.get("assignments") != len(cell["assignments"])
                or row.get("status") not in ("not_started", "running", "completed", "incomplete", "failed", "interrupted")):
            raise ContractError("execution cell state differs from the frozen assignment or run path")
        states = row.get("assignment_states")
        if (not isinstance(states, list) or len(states) != len(cell["assignments"])
                or [state.get("assignment_id") for state in states if isinstance(state, dict)] !=
                   [assignment["assignment_id"] for assignment in cell["assignments"]]):
            raise ContractError("execution manifest changes scheduled assignment states")
        for state in states:
            if (state.get("status") not in ("not_started", "bound", "incomplete", "missing", "skipped", "invalid")
                    or (state.get("reason") is not None and not isinstance(state["reason"], str))
                    or (state.get("status") in ("bound", "incomplete") and
                        (not isinstance(state.get("binding_sha256"), str) or
                         not re.fullmatch(r"sha256:[0-9a-f]{64}", state["binding_sha256"])) )):
                raise ContractError("execution assignment state or binding digest is malformed")
        if row.get("recorded_bindings") != [state for state in states if state["status"] == "bound"]:
            raise ContractError("execution recorded bindings contradict per-assignment states")
        if row["status"] == "completed" and any(state["status"] != "bound" for state in states):
            raise ContractError("execution cell claims completion without all scheduled bindings")
        for error in (row.get("error"), row.get("binding_error")):
            if error is not None and (not isinstance(error, dict) or
                    any(not isinstance(error.get(key), str) for key in ("type", "message"))):
                raise ContractError("execution failure provenance is malformed")
    expected = "interrupted" if value.get("interruption") is not None else (
        "completed" if all(row["status"] == "completed" for row in rows) else "incomplete")
    if value["status"] != expected:
        raise ContractError("execution overall status contradicts its saved cell states")
    return {"state": "recorded", "sha256": digest, "manifest": value}


def _bind_run(matrix: dict, cell: dict, root: Path) -> list[dict]:
    base = _base_binding(matrix, cell)
    recorded = _assignment_states(cell, "missing", "No saved scanner bundle for this scheduled assignment.")
    if root.is_symlink() or not root.is_dir():
        return recorded
    _verify_run_semantics(matrix, cell, root)
    run_hashes = {
        relative: artifact_hash(root, relative) for relative in
        ("run-config.json", "run-manifest.json", "evaluator/schedule.json", "evaluator/pack.json")}
    _write(root / BINDING_FILE, {**base, "artifact_hashes": run_hashes})
    manifest = read_json(root / "run-manifest.json") if run_hashes["run-manifest.json"] else {}
    manifest_rows = {row["invocation_id"]: row for row in manifest.get("invocations", [])}
    for assignment, state in zip(cell["assignments"], recorded, strict=True):
        declared = manifest_rows.get(assignment["assignment_id"])
        if declared is not None and declared["status"] == "skipped":
            state.update(status="skipped", reason=declared["skipped_reason"])
            continue
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
        mandatory = set(IMMUTABLE_INVOCATION_FILES) - {"evaluator/identity-transform.json", "evaluator/identity-context.json"}
        if cell["name"] == "identity_reduced":
            mandatory |= {"evaluator/identity-transform.json", "evaluator/identity-context.json"}
        complete = all(run_hashes.values()) and all(value["artifact_hashes"][path] for path in mandatory)
        state.update(status="bound" if complete else "incomplete",
                     reason=None if complete else "The run or invocation lacks mandatory saved scanner artifacts.",
                     binding_sha256=canonical_sha256(value))
    return recorded


def verify_binding(root: Path, matrix: dict, cell: dict, *, assignment: dict | None = None) -> dict:
    """Verify both the frozen experiment identity and every immutable saved scanner byte."""
    root = Path(root)
    if root.is_symlink():
        raise ContractError("matrix binding root is a symbolic link")
    root = root.resolve()
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
    mandatory = expected if assignment is None else expected - {"evaluator/identity-transform.json", "evaluator/identity-context.json"}
    if assignment is not None and cell["name"] == "identity_reduced":
        mandatory = expected
    if any(hashes[relative] is None for relative in mandatory):
        raise ContractError("matrix binding lacks required saved artifacts")
    if any(artifact_hash(root, relative) != digest for relative, digest in hashes.items()):
        raise ContractError("saved scanner artifacts changed after matrix execution")
    return marker


def execute(frozen_path: Path, out_dir: Path, *, workspace_root: Path | None = None,
            adapters: dict | None = None, clock: Callable[[], datetime] | None = None,
            progress=None) -> dict:
    """Stage all cells before the first scanner, then execute each under its frozen run config.

    Each cell's runner refuses the cell after preparing all its inputs, before any system is
    prepared, when the runtime pack's label contract or rebuilt schedule differs from the frozen
    matrix. A cell failure does not remove any assignment or prevent other cells from running. Every
    immutable scanner artifact receives a matrix/assignment binding; later human review remains
    separate and is checked for cross-condition consistency by the matrix reporter.
    """
    matrix = load_matrix(frozen_path)
    if matrix.get("stage") != "frozen":
        raise ContractError("execute requires a frozen experiment matrix")
    out = Path(out_dir).expanduser().resolve()
    refuse_trial_path(out)
    if out.exists():
        raise FileExistsError(f"matrix output directory already exists: {out}")
    if workspace_root is not None:
        workspace_root = Path(workspace_root).expanduser().resolve()
        if not workspace_root.is_dir() or workspace_root == out or workspace_root.is_relative_to(out):
            raise ContractError("matrix workspace must already exist outside the evaluator output")
    experiment.check_identity_cues(matrix, output_dir=out, workspace_root=workspace_root)
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
    finished = [{"condition": name, "run_path": "runs/" + name, "assignments": len(cells[name]["assignments"]),
                 "status": "not_started", "error": None, "recorded_bindings": [],
                 "assignment_states": _assignment_states(cells[name], "not_started")}
                for name in matrix["cell_order"]]
    interrupted = None
    try:
        for row in finished:
            name = row["condition"]
            cell = cells[name]
            row["status"] = "running"
            try:
                _verify_staged(matrix, cell, out)
                manifest = runner.run_from_config(out / "cells" / name / "run-config.json", out / row["run_path"],
                    workspace_root=workspace_root, adapters=adapters, clock=clock, progress=progress,
                    prepared_guard=_prepared_guard(matrix, cell))
                row["status"] = manifest["status"]
            except Exception as exc:
                row["status"] = "failed"
                row["error"] = {"type": type(exc).__name__, "message": str(exc)[:2000]}
            except BaseException as exc:
                row["status"] = "interrupted"
                row["error"] = {"type": type(exc).__name__, "message": str(exc)[:2000]}
                raise
            finally:
                try:
                    row["assignment_states"] = _bind_run(matrix, cell, out / row["run_path"])
                    row["recorded_bindings"] = [item for item in row["assignment_states"] if item["status"] == "bound"]
                    if row["status"] == "completed" and len(row["recorded_bindings"]) != row["assignments"]:
                        row["status"] = "incomplete"
                except Exception as exc:
                    if row["status"] != "interrupted":
                        row["status"] = "failed"
                    row["assignment_states"] = _assignment_states(cell, "invalid", str(exc)[:2000])
                    row["binding_error"] = {"type": type(exc).__name__, "message": str(exc)[:2000]}
    except BaseException as exc:
        interrupted = {"type": type(exc).__name__, "message": str(exc)[:2000]}
        raise
    finally:
        moment = (clock or (lambda: datetime.now(timezone.utc)))()
        manifest = {"schema_version": "2.1", "experiment_id": matrix["experiment_id"],
            "experiment_version": matrix["experiment_version"], "matrix_sha256": matrix["matrix_sha256"],
            "finished_at": moment.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "status": "interrupted" if interrupted else "completed" if all(row["status"] == "completed" for row in finished) else "incomplete",
            "interruption": interrupted,
            "assignments": len(matrix["assignments"]), "cells": finished}
        _write(out / EXECUTION_FILE, manifest)
    return manifest
