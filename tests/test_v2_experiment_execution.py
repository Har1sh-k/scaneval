"""Executor ordering and byte bindings in isolation from lower-layer scanner integrations."""

from copy import deepcopy
from datetime import datetime, timezone
import json

import pytest

from scaneval import blinding, cases, experiment
from scaneval import experiment_execution as execution
from scaneval.adapters import get_adapter
from scaneval.contracts import ContractError, canonical_json, canonical_sha256, pack_anchor_digest
from scaneval.adapters.base import AdapterError, SystemSpec
from scaneval.execution import PreparedInput, run_invocation
from scaneval.materialize import hash_exported_tree
from test_v2_conditions import Offline, Enforced
from test_v2_experiment_freeze import fixture_builder
from test_v2_experiment_matrix import declaration


def frozen_shell():
    document = declaration()
    population = [{"snapshot_id": "source"}]
    mapping = {"pseudonyms": [{"original": "AcmeCorp", "replacement": "Neutral"}]}
    digest = canonical_sha256(mapping)
    cells = []
    for cell in document["conditions"]:
        config = experiment._config(document, cell, population, {"map.json": digest})
        cells.append({"name": cell["name"], "config": config, "config_sha256": canonical_sha256(config),
                      "assignments": experiment._assignments(document, cell["name"], population)})
    adapter = get_adapter("semgrep")
    return {"stage": "frozen", "experiment_id": "fixture", "experiment_version": "1", "matrix_sha256": "sha256:" + "a" * 64,
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
    assert manifest["status"] == "incomplete" and len(manifest["cells"]) == 3
    assert all(len(cell["assignment_states"]) == 2 for cell in manifest["cells"])


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
    cell = matrix["cells"][1]
    root = tmp_path / "run"
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('fixture')\n")
    tree = hash_exported_tree(source)["tree_hash"]
    prepared = PreparedInput("source", source, tree, ("python",), {"profile": "standard", "trial": {"tree_hash": tree}},
                             condition={"name": "closed_book_standard", "policy": {}})
    bundle = run_invocation(prepared=prepared, adapter=Offline(), spec=SystemSpec("scan", "fixture", {}),
        preparation={}, out_dir=root / "invocations", run_id=cell["config"]["run_id"],
        network_policy="none", backend=Enforced("none"))
    states = execution._bind_run(matrix, cell, root)
    assert [row["status"] for row in states] == ["incomplete", "missing"]
    assignment = cell["assignments"][0]
    assert execution.verify_binding(bundle, matrix, cell, assignment=assignment)["matrix_sha256"] == matrix["matrix_sha256"]
    other = deepcopy(assignment)
    other["repetition"] += 1
    with pytest.raises(ContractError, match="different scheduled"):
        execution.verify_binding(bundle, matrix, cell, assignment=other)
    (bundle / "result.json").write_text('{"fixture":false}')
    with pytest.raises(ContractError, match="artifacts changed"):
        execution.verify_binding(bundle, matrix, cell, assignment=assignment)


def test_missing_mandatory_run_artifacts_and_symlink_root_do_not_verify(tmp_path):
    matrix = frozen_shell()
    cell = matrix["cells"][0]
    root = tmp_path / "run"
    root.mkdir()
    execution._bind_run(matrix, cell, root)
    with pytest.raises(ContractError, match="required saved artifacts"):
        execution.verify_binding(root, matrix, cell)
    alias = tmp_path / "linked-run"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(ContractError, match="symbolic link"):
        execution.verify_binding(alias, matrix, cell)


def test_completed_return_without_bundles_remains_explicitly_incomplete(tmp_path, monkeypatch):
    matrix = frozen_shell()
    staged_executor(monkeypatch, matrix)
    monkeypatch.setattr(execution.runner, "run_from_config", lambda *_args, **_kwargs: {"status": "completed"})
    result = execution.execute(tmp_path / "frozen.json", tmp_path / "out")
    assert result["status"] == "incomplete"
    assert all(row["status"] == "incomplete" and not row["recorded_bindings"] for row in result["cells"])
    assert sum(item["status"] == "missing" for row in result["cells"] for item in row["assignment_states"]) == 6


def test_misnamed_invocation_cannot_stand_for_frozen_assignment(tmp_path):
    matrix = frozen_shell()
    root = tmp_path / "run"
    (root / "invocations" / "source.blinded__scan__r1").mkdir(parents=True)
    with pytest.raises(ContractError, match="unexpected invocation"):
        execution._bind_run(matrix, matrix["cells"][0], root)


def test_interrupt_preserves_current_and_unstarted_cells(tmp_path, monkeypatch):
    matrix = frozen_shell()
    staged_executor(monkeypatch, matrix)
    calls = []
    def runner(*_args, **_kwargs):
        calls.append(True)
        if len(calls) == 2:
            raise KeyboardInterrupt("fixture interrupt")
        return {"status": "completed"}
    monkeypatch.setattr(execution.runner, "run_from_config", runner)
    output = tmp_path / "out"
    with pytest.raises(KeyboardInterrupt):
        execution.execute(tmp_path / "frozen.json", output)
    manifest = execution.read_json(output / execution.EXECUTION_FILE)
    assert manifest["status"] == "interrupted"
    assert [row["status"] for row in manifest["cells"]] == ["incomplete", "interrupted", "not_started"]
    assert manifest["cells"][1]["error"]["type"] == "KeyboardInterrupt"
    assert len(manifest["cells"][2]["assignment_states"]) == 2


def test_a_later_staged_cell_changed_between_runs_is_never_invoked(tmp_path, monkeypatch):
    matrix = frozen_shell()
    staged_executor(monkeypatch, matrix)
    output = tmp_path / "out"
    calls = []
    def runner(config_path, _out_dir, **_kwargs):
        calls.append(config_path.parent.name)
        if len(calls) == 1:
            later = output / "cells" / matrix["cell_order"][1] / "run-config.json"
            changed = json.loads(later.read_text())
            changed["timeout_seconds"] += 1
            later.write_text(json.dumps(changed))
        return {"status": "completed"}
    monkeypatch.setattr(execution.runner, "run_from_config", runner)
    result = execution.execute(tmp_path / "frozen.json", output)
    assert calls == [matrix["cell_order"][0], matrix["cell_order"][2]]
    refused = result["cells"][1]
    assert refused["status"] == "failed" and "changed before scanner invocation" in refused["error"]["message"]


class Counting(Offline):
    """Counts adapter work. Preparation then stops the system; the Docker matrix test scans."""

    name = "counting-fixture"
    oci_compatible = True

    def __init__(self):
        super().__init__()
        self.calls = []

    def prepare(self, spec, cache_root):
        self.calls.append("prepare")
        raise AdapterError("fixture stops after the prepared-cell guard admitted the cell")

    def scan(self, **kwargs):
        self.calls.append("scan")
        return super().scan(**kwargs)


def drafted(case_id, snapshot_id, path, *,
            represents="This case tests a fabricated second sink under caller-controlled input, and adds a guard fixture.",
            **options):
    return cases.draft_case(case_id, snapshot_id=snapshot_id, kind="command_injection",
        description="Second fabricated subprocess sink.", workload="conventional_application",
        component_role="application", aliases=[], represents=represents,
        evidence=[cases.evidence("fixture-source", origin="research_note", kind="source_inspection",
                                 reference="app.py", note="Fabricated integration fixture only.")],
        accepted_locations=[{"path": path, "start_line": 4, "end_line": 4, "role": "sink", "note": ""}], **options)


def guarded_run(tmp_path, monkeypatch, edit=None, *, later=False):
    """Freeze the complete fabricated matrix, then execute it through the actual runner."""
    declaration_path = fixture_builder(monkeypatch)(tmp_path / "study")
    root = declaration_path.parent
    document = json.loads(declaration_path.read_text())
    pack = cases.load_pack(root / "pack.json")
    mapping = blinding.load_map(root / "map.json")
    if later:
        # A second population input of the same reviewed export, prepared after the first.
        cases.add_snapshot(pack, {**deepcopy(pack["snapshots"][0]), "snapshot_id": "later"})
        document["population"]["snapshot_ids"].append("later")
        document["conditions"][2]["transformation_maps"]["later"] = "map.json"
        mapping["variants"].append({**mapping["variants"][0], "snapshot_id": "later"})
        expected = mapping["removals"][0]["expected"]
        expected.append({**expected[0], "snapshot_id": "later"})
    if edit is not None:
        edit(pack)
    pack["anchor_sha256"] = pack_anchor_digest(pack)
    cases.save_pack(root / "pack.json", pack)
    blinding.record_review(mapping, reviewer="Fictional diagnostic map reviewer", role="independent_reviewer",
                           decision="approve", note="Synthetic plumbing fixture only; not benchmark evidence.")
    blinding.save_map(root / "map.json", mapping)
    adapter = Counting()
    frozen = experiment.freeze(document, base_dir=root, created_at="2000-01-01T00:00:00Z",
                               adapters={"semgrep": adapter})
    frozen_path = root / "frozen.json"
    frozen_path.write_text(canonical_json(frozen) + "\n")
    output = tmp_path / "out"
    # A fixed later clock makes every runtime mechanical check carry a refreshed timestamp.
    manifest = experiment.execute(frozen_path, output, workspace_root=root / "work", adapters={"semgrep": adapter},
                                  clock=lambda: datetime(2001, 1, 1, tzinfo=timezone.utc))
    return frozen, adapter, output, manifest


def test_unchanged_prepared_cells_with_refreshed_check_timestamps_reach_their_adapter(tmp_path, monkeypatch):
    frozen, adapter, output, manifest = guarded_run(tmp_path, monkeypatch)
    assert adapter.calls == ["prepare"] * 3
    assert all(row["error"] is None and row["status"] == "incomplete" for row in manifest["cells"]), manifest
    for name in experiment.NAMES:
        runtime = cases.load_pack(output / "runs" / name / "evaluator/pack.json")
        assert runtime != frozen["pack"]
        assert experiment.label_contract(runtime) == experiment.label_contract(frozen["pack"])
        run = json.loads((output / "runs" / name / "run-manifest.json").read_text())
        assert run["status"] == "completed" and {row["status"] for row in run["invocations"]} == {"skipped"}


def newly_eligible(pack):
    cases.add_case(pack, drafted("fixture-newly-eligible", "fixture", "app.py"))


def failing_draft(pack):
    cases.add_case(pack, drafted("fixture-failing", "fixture", "app.py", represents="Not the case template."))


def unchecked_excluded(pack):
    cases.add_case(pack, drafted("fixture-excluded", "fixture", "app.py", disposition="exclude",
                                 disposition_reason="Predeclared fixture exclusion."))


def stale_checks(pack):
    # The recorded passing check set no longer describes the edited location.
    pack["cases"][0]["target"]["accepted_locations"][0]["end_line"] = 40


@pytest.mark.parametrize("edit,eligibility_changes", [
    (newly_eligible, True), (failing_draft, False), (unchecked_excluded, False), (stale_checks, True)])
def test_preparation_drift_refuses_every_cell_before_adapter_preparation(tmp_path, monkeypatch, edit,
                                                                        eligibility_changes):
    frozen, adapter, output, manifest = guarded_run(tmp_path, monkeypatch, edit)
    assert adapter.calls == []
    assert manifest["status"] == "incomplete"
    frozen_targets = {row["target_id"] for row in frozen["population"][0]["schedule_plan"]["targets"]}
    for row in manifest["cells"]:
        assert row["status"] == "failed" and row["error"]["type"] == "ContractError"
        assert "freeze a new matrix" in row["error"]["message"] and "binding_error" not in row
        assert {state["status"] for state in row["assignment_states"]} == {"missing"}
        run = output / row["run_path"]
        assert json.loads((run / "run-manifest.json").read_text())["status"] == "failed"
        assert (run / "evaluator/schedule.json").is_file() and not (run / "invocations").exists()
        runtime = cases.load_pack(run / "evaluator/pack.json")
        assert experiment.label_contract(runtime) != experiment.label_contract(frozen["pack"])
        replanned = cases.build_plan(runtime, "fixture", frozen["population"][0]["source_tree_hash"])[0]
        assert ({target["target_id"] for target in replanned["targets"]} != frozen_targets) == eligibility_changes


def test_drift_from_a_later_input_has_no_adapter_work_for_an_earlier_input(tmp_path, monkeypatch):
    def later_draft(pack):
        cases.add_case(pack, drafted("later-newly-eligible", "later", "app.py"))
    frozen, adapter, output, manifest = guarded_run(tmp_path, monkeypatch, later_draft, later=True)
    assert [source["snapshot_id"] for source in frozen["population"]] == ["fixture", "later"]
    assert adapter.calls == []
    for row in manifest["cells"]:
        assert row["status"] == "failed" and "freeze a new matrix" in row["error"]["message"]
        run = json.loads((output / row["run_path"] / "run-manifest.json").read_text())
        assert [(item["input_id"], item["preparation_failure"]) for item in run["inputs"]] == [
            ("fixture", None), ("later", None)]


def test_an_input_refused_before_checks_keeps_skipped_behavior_while_checked_cells_refuse(tmp_path, monkeypatch):
    # The identity export refuses a missing scoring path before any check, so that cell's pack is
    # unchanged and its input is skipped as before; the other cells record a failing check set.
    _frozen, adapter, output, manifest = guarded_run(
        tmp_path, monkeypatch, lambda pack: cases.add_case(pack, drafted("fixture-missing", "fixture", "missing.py")))
    states = {row["condition"]: row for row in manifest["cells"]}
    assert all(states[name]["status"] == "failed" for name in ("open_context", "closed_book_standard"))
    assert states["identity_reduced"]["error"] is None and adapter.calls == ["prepare"]
    assert {state["status"] for state in states["identity_reduced"]["assignment_states"]} == {"skipped"}
    run = json.loads((output / "runs/identity_reduced/run-manifest.json").read_text())
    assert run["status"] == "completed"
    assert run["inputs"][0]["preparation_failure"]["type"] == "IdentityConditionUnavailable"
