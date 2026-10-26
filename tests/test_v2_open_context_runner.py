"""Preflight refusals must happen before output, input fetching, or scanner preparation."""

import json
from pathlib import Path
import runpy

import pytest

from scaneval.contracts import ContractError, validate_document
from scaneval.runner import run_from_config
from scaneval import materialize


create_fixture = runpy.run_path(str(Path(__file__).parents[1] / "examples/open_context_fixture.py"))["create"]


@pytest.mark.parametrize("mutation,reason", [
    ("stale", "stale"),
    ("local", "requires oci"),
    ("capture", "capture/retention differs"),
    ("profile", "requires a standard full input"),
])
def test_invalid_open_condition_refuses_before_preparation(tmp_path, monkeypatch, mutation, reason):
    config = create_fixture(tmp_path / "fixture")
    document = json.loads(config.read_text())
    if mutation == "stale":
        document["inputs"][0]["condition"]["policy"]["history"] = "ancestor_history_v0"
    elif mutation == "local":
        document["network_policy"] = "none"
        document["systems"][0]["execution"] = {"backend": "local"}
    elif mutation == "capture":
        document["inputs"][0]["condition"]["policy"].update(capture="hashes", retention="hashes_only")
    else:
        # PR mode would require a separately declared change set; an invalid profile is already
        # ineligible before its missing blinding map could reach source preparation.
        document["inputs"][0].update(profile="metadata_blinded", blinding_map="unavailable-map.json")
    config.write_text(json.dumps(document))
    def unexpected(*_args, **_kwargs):
        pytest.fail("invalid open condition reached input fetching")
    monkeypatch.setattr(materialize, "fetch_snapshot", unexpected)
    out = tmp_path / "out"
    with pytest.raises(ContractError, match=reason):
        run_from_config(config, out)
    assert not out.exists()


def test_public_network_config_without_recorded_policy_is_invalid(tmp_path):
    config = create_fixture(tmp_path / "fixture")
    document = json.loads(config.read_text())
    del document["systems"][0]["execution"]["retrieval"]
    with pytest.raises(ContractError, match="stale"):
        validate_document("run-config", document)
