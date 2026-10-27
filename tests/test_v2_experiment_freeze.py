"""Real pack/map semantic freeze checks; no scanner or target application executes."""

from copy import deepcopy
from dataclasses import replace
import importlib.util
from pathlib import Path

import pytest

from scaneval import blinding, experiment
from scaneval.contracts import ContractError, canonical_json, canonical_sha256


def fixture_builder(monkeypatch):
    pytest.importorskip("scaneval.identity_policy", reason="requires the strict identity dependency")
    pytest.importorskip("scaneval.open_context", reason="requires the open-context dependency")
    path = Path(__file__).resolve().parents[1] / "examples/experiment_matrix_fixture.py"
    monkeypatch.syspath_prepend(str(path.parent))
    spec = importlib.util.spec_from_file_location("matrix_fixture_example", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.create


@pytest.fixture
def declared_fixture(tmp_path, monkeypatch):
    path = fixture_builder(monkeypatch)(tmp_path / "study")
    mapping = blinding.load_map(path.parent / "map.json")
    # Fictional diagnostic map review, never an approval of real corpus labels.
    blinding.record_review(mapping, reviewer="Fictional diagnostic map reviewer", role="independent_reviewer",
                           decision="approve", note="Synthetic plumbing fixture only; not benchmark evidence.")
    blinding.save_map(path.parent / "map.json", mapping)
    import json
    return path, json.loads(path.read_text())


@pytest.fixture
def real_frozen(declared_fixture):
    path, document = declared_fixture
    return experiment.freeze(document, base_dir=path.parent, created_at="2000-01-01T00:00:00Z")


def test_real_three_cell_freeze_recomputes_exact_pack_maps_and_assignments(real_frozen):
    assert experiment.validate_frozen(real_frozen) is real_frozen
    assert len(real_frozen["cells"]) == 3 and len(real_frozen["assignments"]) == 3
    assert {row["condition"] for row in real_frozen["assignments"]} == set(experiment.NAMES)
    assert len(real_frozen["population"][0]["schedule_plan"]["targets"]) == 1


@pytest.mark.parametrize("mutation", ["cell", "assignment", "source", "scope", "timeout", "order", "maps", "pack_labels"])
def test_rebinding_outer_hash_cannot_hide_semantic_frozen_drift(real_frozen, mutation):
    value = deepcopy(real_frozen)
    if mutation == "cell": value["cells"].pop()
    elif mutation == "assignment": value["assignments"].pop()
    elif mutation == "source":
        value["population"][0]["source_tree_hash"] = "sha256:" + "0" * 64
        value["bindings"]["population_sha256"] = canonical_sha256(value["population"])
        for cell in value["cells"]: cell["population_sha256"] = value["bindings"]["population_sha256"]
    elif mutation in ("scope", "timeout"):
        cell = value["cells"][0]
        if mutation == "scope": cell["config"]["systems"][0]["config"]["paths"] = ["different"]
        else: cell["config"]["timeout_seconds"] += 1
        cell["config_sha256"] = canonical_sha256(cell["config"])
    elif mutation == "order": value["cell_order"].reverse()
    elif mutation == "maps":
        mapping = next(iter(value["maps"].values()))
        mapping["repository"]["url"] = "https://other.example/source"
        new_digest = canonical_sha256(mapping)
        value["maps"] = {new_digest: mapping}
        for key in value["bindings"]:
            if key.startswith("map."): value["bindings"][key] = new_digest
    else:
        value["pack"]["cases"][0]["target"]["description"] = "Changed source-property allegation"
        value["bindings"]["pack_sha256"] = canonical_sha256(value["pack"])
    value["matrix_sha256"] = experiment.matrix_digest(value)
    with pytest.raises(ContractError):
        experiment.validate_frozen(value)


def test_declared_strict_policy_missing_a_required_alias_refuses_at_freeze(declared_fixture):
    from scaneval import cases
    from scaneval.contracts import pack_anchor_digest
    path, declaration = declared_fixture
    pack = cases.load_pack(path.parent / "pack.json")
    pack["cases"][0]["canonical_target"]["aliases"].append("CVE-2025-12345")
    pack["anchor_sha256"] = pack_anchor_digest(pack)
    cases.save_pack(path.parent / "pack.json", pack)
    with pytest.raises(ContractError, match="strict identity policy does not cover"):
        experiment.freeze(declaration, base_dir=path.parent, created_at="2000-01-01T00:00:00Z")


def test_actual_identity_workspace_preflight_refuses_before_any_runner(real_frozen, tmp_path, monkeypatch):
    from scaneval import experiment_execution
    frozen = tmp_path / "frozen.json"
    frozen.write_text(canonical_json(real_frozen) + "\n")
    called = []
    monkeypatch.setattr(experiment_execution.runner, "run_from_config", lambda *args, **kwargs: called.append(args))
    output = tmp_path / "AcmeCorp-results"
    with pytest.raises(ContractError, match="reviewed original cues|strict identity"):
        experiment.execute(frozen, output)
    assert not called and not output.exists()


def test_private_cve_snapshot_id_freezes_without_weakening_true_scanner_field_checks(declared_fixture):
    from scaneval import cases
    from scaneval.adapters.base import SystemSpec
    from scaneval.contracts import pack_anchor_digest
    from scaneval.execution import PreparedInput, build_request

    path, declaration = declared_fixture
    alias = "CVE-2025-12345"
    pack = cases.load_pack(path.parent / "pack.json")
    snapshot = pack["snapshots"][0]
    snapshot["snapshot_id"] = alias
    case = pack["cases"][0]
    case["target"]["snapshot_id"] = alias
    case["canonical_target"]["aliases"] = [alias]
    case["validation"].update(level=None, review_state="draft", checks=[], check_sets={})
    pack["anchor_sha256"] = pack_anchor_digest(pack)
    cases.mechanical_checks(pack, alias, path.parent / "probe/source", snapshot["tree_hash"])
    cases.save_pack(path.parent / "pack.json", pack)
    mapping = blinding.load_map(path.parent / "map.json")
    mapping["variants"][0]["snapshot_id"] = alias
    for removal in mapping["removals"]:
        for expected in removal["expected"]:
            expected["snapshot_id"] = alias
    mapping["identity_policy"]["answer_aliases"] = [{"category": "target_alias", "value": alias, "forms": []}]
    mapping["reviews"] = []
    mapping.pop("reviews_sha256", None)
    blinding.record_review(mapping, reviewer="Fictional diagnostic map reviewer", role="independent_reviewer",
                           decision="approve", note="Consistent private fixture ID rename; no real corpus approval.")
    blinding.save_map(path.parent / "map.json", mapping)
    declaration["population"]["snapshot_ids"] = [alias]
    declaration["conditions"][2]["transformation_maps"] = {alias: "map.json"}
    frozen = experiment.freeze(declaration, base_dir=path.parent, created_at="2000-01-01T00:00:00Z")
    assert experiment.validate_frozen(frozen) is frozen
    assert all(assignment["snapshot_id"] == alias for assignment in frozen["assignments"])

    prepared = PreparedInput("neutral-id", path.parent / "probe/source", snapshot["tree_hash"], ("python",), {},
                             profile="identity_reduced")
    arguments = {"timeout_seconds": 120, "trace_mode": "metadata"}
    request = build_request("diagnostic-matrix.identity_reduced", prepared, SystemSpec("semgrep", "semgrep"), **arguments)
    renamed_request = build_request("diagnostic-matrix.identity_reduced", replace(prepared, input_id=alias),
                                    SystemSpec("semgrep", "semgrep"), **arguments)
    assert canonical_json(request).encode() == canonical_json(renamed_request).encode()
    assert alias not in canonical_json(renamed_request)

    declaration["experiment_id"] = alias + "-study"
    with pytest.raises(ContractError, match="strict identity cue"):
        experiment.freeze(declaration, base_dir=path.parent, created_at="2000-01-01T00:00:00Z")
