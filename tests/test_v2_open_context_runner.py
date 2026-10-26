"""Preflight refusals must happen before output, input fetching, or scanner preparation."""

import json
from pathlib import Path
import runpy
from copy import deepcopy

import pytest

from scaneval.contracts import ContractError, validate_document
from scaneval.runner import run_from_config
from scaneval import materialize
from scaneval.adapters.base import SystemSpec
from scaneval.execution import ExecutionError, PreparedInput, run_invocation
from test_v2_conditions import Offline, Enforced
from scaneval.isolation import resolve_execution
from scaneval.isolation.oci import OciBackend
from scaneval.open_context_evidence import classify_condition


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


def test_declared_provider_route_cannot_override_denied_evaluator_infrastructure(tmp_path):
    config = create_fixture(tmp_path / "fixture")
    document = json.loads(config.read_text())
    document["systems"][0]["execution"]["retrieval"]["denied_hosts"] = ["example.com"]
    with pytest.raises(ContractError, match="denied evaluator infrastructure"):
        validate_document("run-config", document)


@pytest.mark.parametrize("backend", [None, Enforced("none"), Enforced("public_research")])
def test_direct_invocation_cannot_downgrade_open_context_to_an_unenforced_scan(tmp_path, backend):
    config = create_fixture(tmp_path / "fixture")
    document = json.loads(config.read_text())
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('fixture')\n")
    digest = materialize.hash_exported_tree(source)["tree_hash"]
    prepared = PreparedInput("fixture", source, digest, ("python",), {},
                             condition=document["inputs"][0]["condition"])
    called = []
    adapter = Offline(mutate=lambda _source: called.append(True))
    adapter.oci_compatible = True
    out = tmp_path / "out"
    with pytest.raises(ExecutionError, match="requires an OCI public_research backend"):
        run_invocation(prepared=prepared, adapter=adapter, spec=SystemSpec("fixture", "fixture", {}),
                       preparation={}, out_dir=out, run_id="open-fixture", network_policy="public_research",
                       backend=backend)
    assert called == [] and not out.exists()


@pytest.mark.parametrize("changed_field", [None, "url", "query", "source", "operation", "started_at", "source_assurance"])
def test_attempt_journal_preserves_interruption_and_rejects_request_mismatch(tmp_path, changed_field):
    config = create_fixture(tmp_path / "fixture")
    system = json.loads(config.read_text())["systems"][0]
    backend = OciBackend(resolve_execution(system["execution"], "public_research"),
                         run_id="fixture", invocation_id="interrupted", scratch_root=tmp_path)
    workspace = backend.workspace_root / "scaneval-trial-interrupted"
    (workspace / "source").mkdir(parents=True)
    (workspace / "raw").mkdir()
    logs = tmp_path / "proxy-log"
    logs.mkdir()
    (logs / "retrieval.jsonl").write_bytes(b"")
    start = {"id": "attempt", "started_at": "2026-10-25T00:00:00Z", "operation": "fetch",
             "url": "https://example.com/", "query": None, "source": "scanner_native",
             "source_assurance": "self_reported"}
    (logs / "retrieval-started.jsonl").write_text(json.dumps(start) + "\n")
    if changed_field is not None:
        terminal = {**start, changed_field: "changed-" + changed_field, "outcome": "denied",
                    "capture_status": "unavailable", "content_path": None}
        (logs / "retrieval.jsonl").write_text(json.dumps(terminal) + "\n")
    backend._proxy = {"log_dir": logs}
    try:
        summary = backend._capture_retrieval()
        assert summary["attempts"] == 1
        if changed_field is None:
            assert summary["capture_status"] == "partial", summary
            assert summary["completed_attempts"] == 0
            assert summary["incomplete_attempts"] == 1 and summary["unfinished_attempt_ids"] == ["attempt"]
            assert any("no terminal capture" in gap for gap in summary["gaps"])
        else:
            assert summary["capture_status"] == "unavailable", summary
            assert any("completed request differs" in gap for gap in summary["gaps"])
        saved = workspace / summary["attempts_path"]
        assert json.loads(saved.read_text()) == start
    finally:
        backend._proxy = None
        assert backend.close() == []


@pytest.mark.parametrize("contradiction", ["execution_flag", "worker", "proxy", "mode", "gateway", "network_shape"])
def test_contradictory_network_evidence_cannot_attest_public_research(tmp_path, contradiction):
    policy = {"history": "ancestor_history_v1", "retrieval": "recorded_public_v1", "web_mode": "live",
              "capture": "content", "retention": "bundle"}
    execution = {"provenance": {"mode": "full", "profile": "standard"},
        "network_policy": {"declared": "public_research", "enforced": True},
        "isolation": {"backend": "oci", "enforced": True,
            "containers": [{"role": "worker", "started": True, "removed": True},
                           {"role": "proxy", "started": True, "removed": True}],
            "network": {"policy": "public_research", "enforced": True,
                "mode": "internal network with egress proxy", "proxy": {"allow": ["example.com:443"]},
                "networks": [{"role": "int", "internal": True, "gateway_mode_ipv4": "isolated",
                              "gateways": [], "ipv6": False}]}}}
    assert classify_condition(tmp_path, execution, policy, {})["network"] == "enforced"
    bad = deepcopy(execution)
    if contradiction == "execution_flag":
        bad["network_policy"]["enforced"] = False
    elif contradiction in ("worker", "proxy"):
        bad["isolation"]["containers"] = [item for item in bad["isolation"]["containers"] if item["role"] != contradiction]
    elif contradiction == "mode":
        bad["isolation"]["network"]["mode"] = "bridge"
    elif contradiction == "gateway":
        bad["isolation"]["network"]["networks"][0]["gateways"] = ["172.18.0.1"]
    else:
        bad["isolation"]["network"]["networks"] = "malformed"
    result = classify_condition(tmp_path, bad, policy, {})
    assert result["status"] == "failed" and result["network"] == "unenforced"
    assert any(reason["code"] == "network_evidence_inconsistent" for reason in result["reasons"])
