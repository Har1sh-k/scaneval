import json
from pathlib import Path

import pytest

from scaneval import experiment
from scaneval.cli import main
from scaneval.contracts import ContractError, validate_document
from test_v2_experiment_matrix import declaration


def test_matrix_is_a_versioned_contract_and_validate_command(tmp_path, capsys):
    value = declaration()
    assert validate_document("experiment-matrix", value) is value
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(value))
    assert main(["validate", "experiment-matrix", str(path)]) == 0
    assert "Valid experiment-matrix" in capsys.readouterr().out
    value["conditions"][1]["history"] = "bounded_ancestor"
    with pytest.raises(ContractError, match="incompatible"):
        validate_document("experiment-matrix", value)


def test_matrix_freeze_cli_preserves_explicit_timestamp_and_paths(tmp_path, monkeypatch, capsys):
    source, output = tmp_path / "declaration.json", tmp_path / "frozen.json"
    called = []
    def freeze(path, destination, *, created_at):
        called.append((path, destination, created_at))
        return {"assignments": [{}, {}, {}]}
    monkeypatch.setattr(experiment, "freeze_file", freeze)
    assert main(["matrix", "freeze", str(source), "--output", str(output),
                 "--created-at", "2000-01-01T00:00:00Z"]) == 0
    assert called == [(source, output, "2000-01-01T00:00:00Z")]
    assert "3 assignments" in capsys.readouterr().out


@pytest.mark.parametrize("status,code", [("completed", 0), ("incomplete", 1)])
def test_matrix_run_cli_reports_missingness_in_exit_status(tmp_path, monkeypatch, capsys, status, code):
    source, output, work = tmp_path / "frozen.json", tmp_path / "out", tmp_path / "work"
    def execute(path, destination, *, workspace_root, progress):
        assert (path, destination, workspace_root, progress) == (source, output, work, None)
        return {"status": status, "cells": [{"condition": "open_context", "status": status,
            "assignments": 2, "recorded_bindings": []}]}
    monkeypatch.setattr(experiment, "execute", execute)
    assert main(["matrix", "run", str(source), "--output", str(output), "--workspace-root", str(work), "--quiet"]) == code
    assert "0/2 bound" in capsys.readouterr().out


def test_matrix_report_cli_writes_json_to_stdout_and_reports_refusal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(experiment, "report", lambda directory, *, output: {"evidence_scope": "diagnostic", "conditions": []})
    assert main(["matrix", "report", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["evidence_scope"] == "diagnostic"
    def refuse(*args, **kwargs):
        raise ContractError("frozen source drift")
    monkeypatch.setattr(experiment, "report", refuse)
    assert main(["matrix", "report", str(tmp_path)]) == 2
    assert "frozen source drift" in capsys.readouterr().err
