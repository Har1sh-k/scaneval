"""Executor ordering and byte bindings in isolation from lower-layer scanner integrations."""

from copy import deepcopy
import json

import pytest

from scaneval import experiment
from scaneval import experiment_execution as execution
from scaneval.adapters import get_adapter
from scaneval.contracts import ContractError, canonical_sha256
from test_v2_experiment_matrix import declaration


def frozen_shell():
    document = declaration()
    population = [{"snapshot_id": "source"}]
    mapping = {"fixture": "reviewed map bytes are validated by the separate freeze layer"}
    digest = canonical_sha256(mapping)
    cells = []
    for cell in document["conditions"]:
        config = experiment._config(document, cell, population, {"map.json": digest})
        cells.append({"name": cell["name"], "config": config, "config_sha256": canonical_sha256(config),
                      "assignments": experiment._assignments(document, cell["name"], population)})
    adapter = get_adapter("semgrep")
    return {"experiment_id": "fixture", "experiment_version": "1", "matrix_sha256": "sha256:" + "a" * 64,
        "pack": {}, "maps": {digest: mapping}, "cells": cells, "cell_order": list(experiment.NAMES),
        "assignments": [row for cell in cells for row in cell["assignments"]],
        "systems": [{**document["systems"][0], "adapter_identity": {"name": adapter.name, "version": adapter.adapter_version}}],
        "bindings": {"population_sha256": "sha256:" + "b" * 64, "adjudication_sha256": "sha256:" + "c" * 64}}


def staged_executor(monkeypatch, matrix):
    # These tests isolate executor control flow. Complete freeze and actual three-condition
    # scanner execution are exercised after the identity/open-context dependency layers land.
    monkeypatch.setattr(execution, "load_matrix", lambda _path: matrix)
    monkeypatch.setattr(experiment, "validate_frozen", lambda value: value)


def test_every_cell_and_assignment_is_on_disk_before_first_runner(tmp_path, monkeypatch):
    matrix = frozen_shell()
    staged_executor(monkeypatch, matrix)
    output = tmp_path / "matrix-run"
    calls = []
    def runner(config_path, out_dir, **_kwargs):
        assert json.loads((output / "assignments.json").read_text())["assignments"] == matrix["assignments"]
        for name in matrix["cell_order"]:
            root = output / "cells" / name
            assert (root / "run-config.json").is_file() and (root / "pack.json").is_file()
            assert (root / "assignments.json").is_file() and (root / execution.BINDING_FILE).is_file()
        calls.append(config_path.parent.name)
        out_dir.mkdir(parents=True)
        (out_dir / "run-config.json").write_bytes(config_path.read_bytes())
        (out_dir / "run-manifest.json").write_text('{"status":"completed"}')
        return {"status": "completed"}
    monkeypatch.setattr(execution.runner, "run_from_config", runner)
    manifest = execution.execute(tmp_path / "frozen.json", output)
    assert calls == matrix["cell_order"] and manifest["assignments"] == 6
    assert manifest["status"] == "completed" and len(manifest["cells"]) == 3


def test_a_failed_cell_keeps_all_assignments_and_other_cells_run(tmp_path, monkeypatch):
    matrix = frozen_shell()
    staged_executor(monkeypatch, matrix)
    calls = []
    def runner(config_path, _out_dir, **_kwargs):
        calls.append(config_path.parent.name)
        if len(calls) == 1:
            raise RuntimeError("fixture unavailable condition")
        return {"status": "completed"}
    monkeypatch.setattr(execution.runner, "run_from_config", runner)
    manifest = execution.execute(tmp_path / "frozen.json", tmp_path / "out")
    assert calls == matrix["cell_order"]
    assert manifest["cells"][0]["status"] == "failed" and manifest["cells"][0]["assignments"] == 2
    assert sum(cell["assignments"] for cell in manifest["cells"]) == len(matrix["assignments"])


def test_runtime_adapter_drift_refuses_before_any_output_or_scan(tmp_path, monkeypatch):
    matrix = frozen_shell()
    matrix["systems"][0]["adapter_identity"]["version"] = "different frozen version"
    staged_executor(monkeypatch, matrix)
    output = tmp_path / "out"
    with pytest.raises(ContractError, match="adapter version changed"):
        execution.execute(tmp_path / "frozen.json", output)
    assert not output.exists()


def test_result_binding_rejects_relabeling_and_changed_result_bytes(tmp_path):
    matrix = frozen_shell()
    cell = matrix["cells"][0]
    root = tmp_path / "run"
    bundle = root / "invocations" / cell["assignments"][0]["assignment_id"]
    bundle.mkdir(parents=True)
    (bundle / "result.json").write_text('{"fixture":true}')
    execution._bind_run(matrix, cell, root)
    assignment = cell["assignments"][0]
    assert execution.verify_binding(bundle, matrix, cell, assignment=assignment)["matrix_sha256"] == matrix["matrix_sha256"]
    other = deepcopy(assignment)
    other["repetition"] += 1
    with pytest.raises(ContractError, match="different scheduled"):
        execution.verify_binding(bundle, matrix, cell, assignment=other)
    (bundle / "result.json").write_text('{"fixture":false}')
    with pytest.raises(ContractError, match="artifacts changed"):
        execution.verify_binding(bundle, matrix, cell, assignment=assignment)
