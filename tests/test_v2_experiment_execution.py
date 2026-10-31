"""Executor ordering and byte bindings in isolation from lower-layer scanner integrations."""

from copy import deepcopy
from datetime import datetime, timezone
import json

import pytest

from scaneval import blinding, cases, experiment, isolation
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
    # The shell freezes no population, so neither validation nor the placement its plans were
    # frozen with is read.
    monkeypatch.setattr(execution, "load_matrix", lambda _path: matrix)
    monkeypatch.setattr(experiment, "validate_frozen", lambda value: value)
    monkeypatch.setattr(experiment, "frozen_before_control_paths", lambda _value: False)


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


# --- a matrix frozen before full plans placed controls --------------------------------------------------------------
#
# A full plan now gives each control the pack locates its paths. The plan of a standard input, which a matrix's
# population embeds and its open-context and closed-book cells are scored against, gave none before: it was the 2.0
# plan. A matrix frozen then, whose population plans a located control, holds those pathless plans as its frozen
# contract, and an experiment executed from it saved them in its bundles. Such a matrix is still validated and
# reported, but this build refuses to execute it. Nothing here runs the old code: the helpers below write what it
# wrote, a standard plan with its paths taken out and its version put back to 2.0, which is all it did differently,
# and execute as it did, without that refusal. The scanner is a stand-in that finds nothing, under a recorded
# stand-in for the OCI backend;
# the freeze, the runner, the plans, the bindings, and the report are the real ones. The open-context cell needs a
# real OCI backend and fails here before any scan (the Docker matrix test runs it); the closed-book cell is planned
# exactly as it is, a standard full input of the same snapshot, so it carries the standard plan for both.

LOCATED_CONTROL = {
    "control_id": "C-fixture-safe", "snapshot_id": "fixture", "type": "capability_safe",
    "description": "The fixture's import line is a safe capability.",
    "property": "No caller-supplied string reaches a shell at this line.",
    "allowed_actors_inputs": "Operators on the host.", "assumptions": ["Default deployment."],
    "ruled_out_allegation": "Caller-controlled shell interpolation at the import.",
    "locations": [{"path": "app.py", "start_line": 1, "end_line": 1, "role": "operation"}],
    "evidence_ids": ["fixture-source"]}
DRIFT = "frozen_plan_eligibility_or_label_drift"


def before_control_paths(plan: dict) -> dict:
    """*plan* as a build before full plans placed controls wrote it.

    A standard plan, one whose provenance names no input of its own, was 2.0 and gave no control paths; a renamed,
    blinded, or PR plan was 2.1 and placed its controls then as now.
    """
    if "input_id" in plan["provenance"]:
        return plan
    return {**deepcopy(plan), "schema_version": "2.0",
            "controls": [{key: value for key, value in control.items() if key != "paths"}
                         for control in plan["controls"]]}


def matrix_before_control_paths(frozen: dict) -> dict:
    """*frozen* as a build before full plans placed controls froze it: the same matrix with that build's plans."""
    value = deepcopy(frozen)
    for source in value["population"]:
        source["plan"] = before_control_paths(source["plan"])
    value["bindings"]["population_sha256"] = canonical_sha256(value["population"])
    for cell in value["cells"]:
        cell["population_sha256"] = value["bindings"]["population_sha256"]
    value["matrix_sha256"] = experiment.matrix_digest(value)
    return value


class Scanning(Offline):
    """Scans each cell's input and finds nothing; preparation succeeds, unlike :class:`Counting`."""

    name = "scanning-fixture"
    oci_compatible = True


class RecordedBackend(Enforced):
    """The OCI backend's record without a container: the invocation runs in place."""

    workspace_root = None

    def close(self):
        return []


def located_control_matrix(tmp_path, monkeypatch, adapter):
    """Freeze the fabricated matrix with one capability_safe control located on app.py, checked with its case."""
    declaration_path = fixture_builder(monkeypatch)(tmp_path / "study")
    root = declaration_path.parent
    document = json.loads(declaration_path.read_text())
    pack = cases.load_pack(root / "pack.json")
    case = pack["cases"][0]
    case["controls"].append(deepcopy(LOCATED_CONTROL))
    case["validation"].update(level=None, review_state="draft", checks=[], check_sets={})
    pack["anchor_sha256"] = pack_anchor_digest(pack)
    cases.mechanical_checks(pack, "fixture", root / "probe/source", pack["snapshots"][0]["tree_hash"])
    cases.save_pack(root / "pack.json", pack)
    document["population"]["canonical_control_ids"] = [cases.control_canonical_id(LOCATED_CONTROL)]
    mapping = blinding.load_map(root / "map.json")
    blinding.record_review(mapping, reviewer="Fictional diagnostic map reviewer", role="independent_reviewer",
                           decision="approve", note="Synthetic plumbing fixture only; not benchmark evidence.")
    blinding.save_map(root / "map.json", mapping)
    frozen = experiment.freeze(document, base_dir=root, created_at="2000-01-01T00:00:00Z",
                               adapters={"semgrep": adapter})
    return root, frozen


def execute_matrix(root, frozen, adapter, monkeypatch, *, before_placement=False, unrefused=False):
    """Execute *frozen* through the actual runner; return the output directory and the execution manifest.

    ``before_placement`` executes it as a build before full plans placed controls did: the runner writes each plan
    as that build wrote it, so the bundles are those an execution before then saved, and a matrix frozen then is not
    refused, since nothing refused one then. ``unrefused`` lifts only that refusal, so the runner writes today's
    plans into the cells of a matrix frozen then, as a build that executed one without refusing it would have.
    Either way the matrix is still validated as this build validates it.
    """
    path = root / "frozen.json"
    path.write_text(canonical_json(frozen) + "\n")
    monkeypatch.setattr(isolation, "backend_for", lambda settings, **_kwargs: RecordedBackend(settings.network_policy))
    if before_placement:
        planned = execution.runner._plan
        def plan_before_placement(pack, spec, prepared):
            plan, notes = planned(pack, spec, prepared)
            return before_control_paths(plan), notes
        monkeypatch.setattr(execution.runner, "_plan", plan_before_placement)
    output = root.parent / "out"
    with monkeypatch.context() as patch:
        if before_placement or unrefused:
            frozen_before = experiment.frozen_before_control_paths
            def validated_but_not_refused(document):
                frozen_before(document)
                return False
            patch.setattr(experiment, "frozen_before_control_paths", validated_but_not_refused)
        manifest = experiment.execute(path, output, workspace_root=root / "work", adapters={"semgrep": adapter},
                                      clock=lambda: datetime(2001, 1, 1, tzinfo=timezone.utc))
    return output, manifest


SCANNED = ("closed_book_standard", "identity_reduced")


def saved_plans(output):
    """The saved bundle plan of each cell that scanned, as ``(schema_version, [(control_id, paths)])``."""
    plans = {}
    for name in SCANNED:
        plan = json.loads((output / "runs" / name / "invocations/fixture__semgrep__r1/evaluator/plan.json").read_text())
        plans[name] = (plan["schema_version"], [(c["control_id"], c.get("paths")) for c in plan["controls"]])
    return plans


def scanned_cells(manifest, report):
    """Check what the stand-ins allow, and return the report's observations of the cells that scanned by name.

    Every cell but open-context completed with its assignment bound; open-context failed on its backend before any
    scan. Each observation of a cell that scanned was read and its plan compared, so no reason says its bundle could
    not be read.
    """
    cells = {row["condition"]: row for row in manifest["cells"]}
    assert "OCI public_research backend" in cells["open_context"]["error"]["message"]
    assert all(cells[name]["status"] == "completed" and cells[name]["error"] is None for name in SCANNED), manifest
    rows = {row["condition"]: row for row in report["observations"]}
    assert all(rows[name]["status"] == "success" for name in SCANNED), report["observations"]
    assert not [reason for name in SCANNED for reason in rows[name]["reasons"]
                if reason.startswith("observation_binding_unavailable")], report["observations"]
    return rows


def test_a_matrix_frozen_before_full_plans_placed_controls_validates_and_loads_with_the_plans_it_froze(
        tmp_path, monkeypatch):
    """The population differs from today's rebuild only in placement, which a frozen contract keeps as it froze it.

    The plan validation rebuilds is today's, 2.1 with the control on app.py. The frozen one is the pathless 2.0 plan,
    and both the validation and the loader that execute and report go through accept it as frozen. Any other
    difference is refused as it always was: a label edited in the embedded pack, and a frozen plan that places the
    control somewhere the pack does not.
    """
    root, frozen = located_control_matrix(tmp_path, monkeypatch, Counting())
    assert [(c["control_id"], c.get("paths")) for c in frozen["population"][0]["plan"]["controls"]] == [
        ("C-fixture-safe", ["app.py"])], "a matrix frozen today places the control"
    legacy = matrix_before_control_paths(frozen)
    assert legacy["population"][0]["plan"]["schema_version"] == "2.0"

    assert experiment.validate_frozen(legacy) is legacy
    path = root / "frozen.json"
    path.write_text(canonical_json(legacy) + "\n")
    assert execution.load_matrix(path) == legacy
    assert experiment.frozen_before_control_paths(legacy) is True
    assert experiment.frozen_before_control_paths(frozen) is False

    relabeled = deepcopy(legacy)
    relabeled["pack"]["cases"][0]["target"]["description"] = "Changed source-property allegation"
    relabeled["pack"]["anchor_sha256"] = pack_anchor_digest(relabeled["pack"])
    relabeled["bindings"]["pack_sha256"] = canonical_sha256(relabeled["pack"])
    relabeled["matrix_sha256"] = experiment.matrix_digest(relabeled)
    misplaced = deepcopy(frozen)
    misplaced["population"][0]["plan"]["controls"][0]["paths"] = ["README.md"]
    misplaced["bindings"]["population_sha256"] = canonical_sha256(misplaced["population"])
    for cell in misplaced["cells"]:
        cell["population_sha256"] = misplaced["bindings"]["population_sha256"]
    misplaced["matrix_sha256"] = experiment.matrix_digest(misplaced)
    for drifted in (relabeled, misplaced):
        with pytest.raises(ContractError, match="differ from the common pack"):
            experiment.validate_frozen(drifted)


PLACED = ("2.1", [("C-fixture-safe", ["app.py"])])


def test_an_experiment_executed_before_full_plans_placed_controls_reports_without_drift(tmp_path, monkeypatch):
    """The matrix and the bundles an execution of it saved then, reported as they were saved.

    The closed-book cell saved the pathless 2.0 plan the matrix froze, and the identity-reduced cell the 2.1 plan,
    which placed the control then as now. Each is the frozen form of its input's plan, so no observation is
    ineligible as drift.
    """
    adapter = Scanning()
    root, frozen = located_control_matrix(tmp_path, monkeypatch, adapter)
    output, manifest = execute_matrix(root, matrix_before_control_paths(frozen), adapter, monkeypatch,
                                      before_placement=True)

    assert saved_plans(output) == {"closed_book_standard": ("2.0", [("C-fixture-safe", None)]),
                                   "identity_reduced": PLACED}
    report = experiment.report(output)
    scanned_cells(manifest, report)
    assert [row["reasons"] for row in report["observations"] if DRIFT in row["reasons"]] == []


def test_a_matrix_frozen_before_full_plans_placed_controls_reports_a_placed_standard_plan_as_drift(
        tmp_path, monkeypatch):
    """A matrix frozen with the pathless plans accepts them alone: a standard cell that saved today's plan is drift.

    This build refuses to execute such a matrix, so the matrix is executed here as a build that did not refuse it
    would have. The closed-book cell's bundle holds the plan that places the control on app.py, which is not the
    plan the matrix froze for its input, so it is ineligible like any other plan the frozen contract does not give.
    The identity-reduced cell's plan placed the control under either rule and is its frozen form.
    """
    adapter = Scanning()
    root, frozen = located_control_matrix(tmp_path, monkeypatch, adapter)
    output, manifest = execute_matrix(root, matrix_before_control_paths(frozen), adapter, monkeypatch, unrefused=True)

    assert saved_plans(output) == {"closed_book_standard": PLACED, "identity_reduced": PLACED}
    rows = scanned_cells(manifest, experiment.report(output))
    assert DRIFT in rows["closed_book_standard"]["reasons"]
    assert DRIFT not in rows["identity_reduced"]["reasons"], "its plan placed the control under either rule"



def test_a_matrix_frozen_before_full_plans_placed_controls_is_not_executed_and_says_to_freeze_it_again(
        tmp_path, monkeypatch):
    """Execution refuses the matrix before it writes anything, and the matrix frozen again executes without drift.

    A cell executed now would save today's plan, which places the control, and the report accepts only the plan the
    matrix froze, so every standard cell would run and then be ineligible as drift. Validation still accepts the
    matrix, as the report of an experiment executed from it before needs. Its declaration frozen again gives the
    matrix this test froze, whose plans place the control: it executes, and its report has no drift.
    """
    adapter = Scanning()
    root, frozen = located_control_matrix(tmp_path, monkeypatch, adapter)
    legacy = matrix_before_control_paths(frozen)

    with pytest.raises(ContractError) as refused:
        execute_matrix(root, legacy, adapter, monkeypatch)

    assert str(refused.value) == (
        "matrix was frozen before full plans placed controls, so its standard plans place none, and a cell executed "
        "now would save a plan that places them, which its report would mark as drift; freeze its declaration "
        "again with scaneval matrix freeze and execute the new matrix")
    assert not (root.parent / "out").exists(), "nothing is written before the refusal"
    assert experiment.validate_frozen(legacy) is legacy
    output, manifest = execute_matrix(root, frozen, adapter, monkeypatch)
    assert saved_plans(output) == {"closed_book_standard": PLACED, "identity_reduced": PLACED}
    report = experiment.report(output)
    scanned_cells(manifest, report)
    assert [row["reasons"] for row in report["observations"] if DRIFT in row["reasons"]] == []

def test_a_matrix_frozen_since_full_plans_placed_controls_reports_a_pathless_standard_plan_as_drift(
        tmp_path, monkeypatch):
    """Only a matrix that froze the pathless plans accepts them: one frozen today accepts today's plan alone."""
    adapter = Scanning()
    root, frozen = located_control_matrix(tmp_path, monkeypatch, adapter)
    output, manifest = execute_matrix(root, frozen, adapter, monkeypatch, before_placement=True)

    rows = scanned_cells(manifest, experiment.report(output))
    assert DRIFT in rows["closed_book_standard"]["reasons"]
    assert DRIFT not in rows["identity_reduced"]["reasons"], "its plan placed the control under either build"
