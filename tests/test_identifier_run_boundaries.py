"""Malformed run identities fail before any input preparation or scanner work."""

from copy import deepcopy

import pytest

from scaneval import cases
from scaneval.contracts import ContractError, canonical_json, validate_document
from scaneval.runner import run_from_config


def config(version="2.1"):
    return {
        "schema_version": version, "run_id": "boundary-test", "pack": "missing-pack.json",
        "inputs": [{"snapshot_id": "snapshot-a"}],
        "systems": [{"system_id": "scanner-a", "adapter": "fake", "config": {}}],
        "repetitions": 1, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none",
    }


COLLIDING_INPUTS = [
    [{"snapshot_id": "Snapshot-A"}, {"snapshot_id": "snapshot-a"}],
    [{"snapshot_id": "a", "input_id": "Input-A"}, {"snapshot_id": "b", "input_id": "input-a"}],
    [{"snapshot_id": "Snapshot-A"}, {"snapshot_id": "b", "input_id": "snapshot-a"}],
    [{"mode": "pr", "change_set_id": "Change-A"}, {"mode": "pr", "change_set_id": "change-a"}],
    [{"snapshot_id": "Snapshot-A", "profile": "metadata_blinded", "blinding_map": "map.json"},
     {"snapshot_id": "b", "input_id": "snapshot-a.blinded"}],
]


@pytest.mark.parametrize("inputs", COLLIDING_INPUTS)
def test_effective_input_ids_are_unique_ignoring_case(inputs):
    document = config()
    document["inputs"] = inputs
    with pytest.raises(ContractError, match="input id values must be unique ignoring case"):
        validate_document("run-config", document)


@pytest.mark.parametrize("version", ["2.0", "2.1"])
@pytest.mark.parametrize("field", ["systems", "inputs"])
def test_case_collisions_refuse_before_output_or_preparation(tmp_path, monkeypatch, version, field):
    document = config(version)
    if field == "systems":
        document[field].append({**document[field][0], "system_id": "Scanner-A"})
    else:
        document[field].append({"snapshot_id": "Snapshot-A"})
    path = tmp_path / "config.json"
    path.write_text(canonical_json(document), encoding="utf-8")

    def must_not_prepare(*args, **kwargs):
        pytest.fail("a colliding identity reached pack loading or input preparation")

    monkeypatch.setattr(cases, "load_pack", must_not_prepare)
    output = tmp_path / "not-created"
    with pytest.raises(ContractError, match="unique ignoring case"):
        run_from_config(path, output)
    assert not output.exists()


@pytest.mark.parametrize("version,field", [
    (version, field)
    for version in ("2.0", "2.1")
    for field in ("run_id", "system_id", "snapshot_id", "input_id")
    if version == "2.1" or field != "input_id"
])
def test_newline_ids_refuse_before_output_or_preparation(tmp_path, monkeypatch, version, field):
    document = config(version)
    if field == "run_id":
        document[field] += "\n"
    elif field == "system_id":
        document["systems"][0][field] += "\n"
    else:
        document["inputs"][0][field] = "snapshot-a\n"
    path = tmp_path / "config.json"
    path.write_text(canonical_json(document), encoding="utf-8")

    def must_not_prepare(*args, **kwargs):
        pytest.fail("a newline identity reached pack loading or input preparation")

    monkeypatch.setattr(cases, "load_pack", must_not_prepare)
    output = tmp_path / "not-created"
    with pytest.raises(ContractError):
        run_from_config(path, output)
    assert not output.exists()


@pytest.mark.parametrize("version", ["2.0", "2.1"])
def test_distinct_mixed_case_ids_keep_their_original_spelling(version):
    document = config(version)
    document["systems"] += [{"system_id": "Scanner-B", "adapter": "fake", "config": {}}]
    document["inputs"] += [{"snapshot_id": "Snapshot-B"}]
    original = deepcopy(document)
    assert validate_document("run-config", document) == original


def test_composite_invocation_case_collision_refuses_before_any_output(tmp_path, monkeypatch):
    document = config()
    document["inputs"] = [{"snapshot_id": "source", "input_id": name} for name in ("A__B", "a")]
    document["systems"] = [{"system_id": name, "adapter": "fake", "config": {}}
                           for name in ("c", "b__C")]
    # No individual input or system id collides: the collision appears only after joining them.
    validate_document("run-config", document)
    path = tmp_path / "config.json"
    path.write_text(canonical_json(document), encoding="utf-8")
    monkeypatch.setattr(cases, "load_pack", lambda *args: {})
    output = tmp_path / "not-created"
    with pytest.raises(ContractError, match="invocation id .* produced by both"):
        run_from_config(path, output)
    assert not output.exists()


@pytest.mark.parametrize("field", ["image", "proxy_image"])
def test_contract_refuses_newline_in_pinned_oci_image(field):
    document = config()
    execution = {"backend": "oci", "image": "scanner@sha256:" + "a" * 64}
    if field == "proxy_image":
        document["network_policy"] = "model_provider_only"
        execution.update(proxy_image="proxy@sha256:" + "b" * 64,
                         egress=[{"host": "api.example.test", "port": 443}])
    execution[field] += "\n"
    document["systems"][0]["execution"] = execution
    with pytest.raises(ContractError, match="pinned by digest"):
        validate_document("run-config", document)
