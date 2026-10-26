"""Closed-book evidence distinguishes enforcement, observations, and provider assertions."""

from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

from scaneval import conditions
from scaneval.adapters.base import Adapter, NativeOutcome, SystemSpec
from scaneval.contracts import ContractError, canonical_json, canonical_sha256, load_document, validate_document
from scaneval.execution import PreparedInput, run_invocation
from scaneval.materialize import hash_exported_tree


CLOCK = lambda: datetime(2026, 10, 25, tzinfo=timezone.utc)


class Offline(Adapter):
    name = "offline-fixture"
    adapter_version = "1"
    supported_languages = frozenset({"python"})

    def __init__(self, *, git=False, tools=True, events=None, gap=False, mutate=None):
        self.requires_git = git
        self.disabled_tools = tools
        self.events = events
        self.gap = gap
        self.mutate = mutate

    def condition_controls(self, spec, preparation):
        return {"inference": "offline", "basis": "adapter_controls", "tools": {
            name: "disabled" for name in conditions.TOOLS} if self.disabled_tools else {},
            "provider": {"capability": "not_applicable", "control": "not_applicable", "attestation": None}}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        if self.mutate:
            self.mutate(source_dir)
        trace_path = None
        if self.events is not None:
            trace_path = trace_dir / "events.jsonl"
            events = [{"schema_version": "2.0", "event_id": str(index), "run_id": request["run_id"],
                       "producer_id": "fixture", "sequence": index, "type": "tool.start", "category": "tool",
                       "capture_status": "complete", "timestamp": "2026-10-25T00:00:00Z", **event}
                      for index, event in enumerate(self.events)]
            trace_path.write_text("".join(canonical_json(event) + "\n" for event in events))
        return NativeOutcome("success", 0, ["fixture"], capture={"tool_calls": "complete" if self.events is not None else "not_applicable"},
                             trace_path=trace_path, capture_state={"capture_gap": self.gap, "dropped_events": 1 if self.gap else 0})


class Enforced:
    def __init__(self, policy="none", *, allow=None):
        self.policy = policy
        self.allow = allow or ["inference.example:443"]
        self.network_enforced = policy != "unrestricted"

    def activate(self):
        return nullcontext()

    def isolation_record(self):
        network = {"policy": self.policy, "mode": "none", "enforced": self.network_enforced}
        containers = [{"role": "worker", "started": True}]
        if self.policy == "model_provider_only":
            network.update({"mode": "internal network with egress proxy", "proxy": {"allow": self.allow}})
            containers.append({"role": "proxy", "started": True})
        return {"backend": "oci", "enforced": True, "note": "fixture of recorded backend evidence",
                "network": network, "containers": containers}


def invoke(tmp_path, adapter=None, *, policy="none", enforced=True, config=None, model_id=None):
    source = tmp_path / "source"
    source.mkdir()
    for name, text in {"app.py": "print('hello')\n", "AGENTS.md": "Read the project.\n",
                       "README.md": "Example project\n", "package.json": '{"name":"example"}\n'}.items():
        (source / name).write_text(text)
    tree = hash_exported_tree(source)["tree_hash"]
    provenance = {"profile": "standard", "trial": {"tree_hash": tree}, "instruction_files": ["AGENTS.md"],
                  "retained_identity_cues": {"instruction_files": ["AGENTS.md"], "documentation": ["README.md"],
                                               "package_metadata": ["package.json"], "source_identifiers": "retained"}}
    prepared = PreparedInput("input", source, tree, ("python",), provenance)
    adapter = adapter or Offline()
    bundle = run_invocation(prepared=prepared, adapter=adapter,
                            spec=SystemSpec("scanner", "fixture", config or {}, model_id=model_id), preparation={},
                            out_dir=tmp_path / "out", run_id="conditions", trace_mode="content" if adapter.events is not None else "off",
                            network_policy=policy, backend=Enforced(policy) if enforced else None, clock=CLOCK)
    return bundle, load_document(bundle / conditions.RECORD_FILE, conditions.KIND)


def codes(record):
    return {reason["code"] for reason in record["reasons"]}


def test_offline_enforcement_attests_and_preserves_identity_cues(tmp_path):
    bundle, record = invoke(tmp_path)
    assert (record["condition"], record["status"], record["identity_profile"]) == ("closed_book_standard", "attested", "standard")
    assert record["history"] == "original_absent" and record["retrieval"] == "disabled"
    assert record["provider_retrieval"] == "not_applicable" and record["network"] == "enforced"
    assert record["retained_identity_cues"]["instruction_files"] == ["AGENTS.md"]
    assert record["retained_identity_cues"]["package_metadata"] == ["package.json"]
    assert conditions.classify_observation(bundle) == record
    assert {item["role"] for item in record["artifacts"]} == {"request", "result", "execution", "configuration", "policy", "provenance", "evidence"}


def test_local_declaration_is_never_attested(tmp_path):
    _bundle, record = invoke(tmp_path, enforced=False)
    assert record["status"] == "declared_only" and record["network"] == "unenforced"
    assert "network_unenforced" in codes(record)


def test_neutral_single_commit_history_is_recorded_and_unchanged(tmp_path):
    _bundle, record = invoke(tmp_path, Offline(git=True))
    assert record["status"] == "attested" and record["history"] == "neutral_synthetic"


@pytest.mark.parametrize("mutate", [
    lambda source: (source / ".git").mkdir(),
    lambda source: (source / "nested" / ".git").mkdir(parents=True),
])
def test_unexpected_history_fails_even_when_empty(tmp_path, mutate):
    _bundle, record = invoke(tmp_path, Offline(mutate=mutate))
    assert record["status"] == "failed" and record["history"] == "unexpected"


def test_synthetic_metadata_symlink_is_not_an_unchanged_hash(tmp_path):
    sentinel = tmp_path / "outside"
    sentinel.write_text("outside bytes")

    def symlink(source):
        (source / ".git" / "objects" / "info" / "alternates").symlink_to(sentinel)

    _bundle, record = invoke(tmp_path, Offline(git=True, mutate=symlink))
    assert record["status"] == "failed" and record["history"] == "unexpected"
    assert sentinel.read_text() == "outside bytes"


@pytest.mark.parametrize("policy,config,expected", [
    ("unrestricted", {}, "unrestricted_network"),
    ("none", {"tools": ["WebSearch"]}, "retrieval_enabled"),
    ("none", {"tools": {"browser": True}}, "retrieval_enabled"),
])
def test_enabled_network_or_retrieval_cannot_validate(tmp_path, policy, config, expected):
    _bundle, record = invoke(tmp_path, policy=policy, config=config)
    assert record["status"] == "failed" and expected in codes(record)


def test_missing_tool_visibility_is_a_gap(tmp_path):
    _bundle, record = invoke(tmp_path, Offline(tools=False))
    assert record["status"] == "declared_only" and record["retrieval"] == "capture_gap"


def test_lost_events_do_not_become_observed_none(tmp_path):
    _bundle, record = invoke(tmp_path, Offline(events=[{"metadata": {"tool_name": "Read"}}], gap=True))
    assert record["status"] == "declared_only" and record["retrieval"] == "capture_gap"


def test_complete_local_tool_observation_ignores_benign_retrieval_mentions(tmp_path):
    events = [{"metadata": {"tool_name": "Read", "input_summary": "docs/browser.md"},
               "content": {"text": "Do not run curl or WebSearch"}},
              {"metadata": {"tool_name": "Grep", "input_summary": "curl"}}]
    _bundle, record = invoke(tmp_path, Offline(tools=False, events=events))
    assert record["status"] == "attested" and record["retrieval"] == "observed_none"


@pytest.mark.parametrize("name,state", [("WebSearch", "enabled"), ("Bash", "capture_gap")])
def test_structured_retrieval_is_distinct_from_opaque_shell_observation(tmp_path, name, state):
    _bundle, record = invoke(tmp_path, Offline(tools=False, events=[{"metadata": {"tool_name": name, "input_summary": "curl https://example.com"}}]))
    assert record["retrieval"] == state
    assert record["status"] == ("failed" if state == "enabled" else "declared_only")


class Remote(Offline):
    def condition_controls(self, spec, preparation):
        value = super().condition_controls(spec, preparation)
        value.update({"inference": "remote", "provider": {"name": "example", "capability": "configurable",
                      "control": "disabled", "attestation": None, "inference_hosts": ["inference.example:443"]}})
        return value


def test_remote_inference_is_distinct_from_provider_retrieval_assurance(tmp_path):
    _bundle, record = invoke(tmp_path, Remote(), policy="model_provider_only", model_id="model-a")
    assert record["network"] == "enforced" and record["provider_retrieval"] == "unverifiable"
    assert record["status"] == "declared_only" and "provider_unverifiable" in codes(record)
    assert record["provider"]["capability"] == "configurable" and record["provider"]["control"] == "disabled"


def test_remote_route_cannot_allow_unrelated_egress(tmp_path):
    bundle, _record = invoke(tmp_path, Remote(), policy="model_provider_only", model_id="model-a")
    (bundle / conditions.RECORD_FILE).unlink()
    execution = json.loads((bundle / "execution.json").read_text())
    execution["isolation"]["network"]["proxy"]["allow"].append("search.example:443")
    (bundle / "execution.json").write_text(canonical_json(execution))
    record = conditions.classify_observation(bundle)
    assert record["status"] == "failed" and "unrelated_egress" in codes(record)


def test_scanner_json_assertion_is_not_authenticated_provider_attestation(tmp_path):
    bundle, _record = invoke(tmp_path, Remote(), policy="model_provider_only", model_id="model-a")
    (bundle / conditions.RECORD_FILE).unlink()
    assertion = {"scope": "invocation", "invocation_id": bundle.name, "system_id": "scanner", "model_id": "model-a",
                 "provider": "example", "retrieval_disabled": True}
    raw = canonical_json(assertion).encode()
    path = bundle / "raw" / "provider.json"
    path.write_bytes(raw)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    execution = json.loads((bundle / "execution.json").read_text())
    execution["raw_artifacts"].append({"id": "provider-assertion", "path": "raw/provider.json", "sha256": digest})
    (bundle / "execution.json").write_text(canonical_json(execution))
    evidence = json.loads((bundle / conditions.EVIDENCE_FILE).read_text())
    evidence["controls"]["provider"]["attestation"] = {"path": "raw/provider.json", "sha256": digest}
    (bundle / conditions.EVIDENCE_FILE).write_text(canonical_json(evidence))
    record = conditions.classify_observation(bundle)
    assert record["status"] == "declared_only" and record["provider_retrieval"] == "unverifiable"
    assert record["provider"]["attestation"] == "self_reported"


@pytest.mark.parametrize("file", ["request.json", "execution.json", "result.json", conditions.POLICY_FILE,
                                   conditions.CONFIGURATION_FILE, conditions.PROVENANCE_FILE, conditions.EVIDENCE_FILE])
def test_record_binds_exact_saved_bytes_not_just_equivalent_json(tmp_path, file):
    bundle, _record = invoke(tmp_path)
    path = bundle / file
    path.write_bytes(path.read_bytes() + b" ")
    record = conditions.classify_observation(bundle)
    assert record["status"] == "failed" and "stale_condition_record" in codes(record)


def test_legacy_runs_remain_readable_without_retroactive_attestation(tmp_path):
    bundle, _record = invoke(tmp_path)
    for name in (conditions.RECORD_FILE, conditions.POLICY_FILE, conditions.CONFIGURATION_FILE,
                 conditions.PROVENANCE_FILE, conditions.EVIDENCE_FILE):
        (bundle / name).unlink()
    record = conditions.classify_observation(bundle)
    assert record["condition"] == "closed_book_standard" and record["status"] == "unavailable"
    assert record["history"] == "unavailable" and record["retrieval"] == "capture_gap"


def test_condition_schema_refuses_attestation_of_an_unenforced_declaration(tmp_path):
    _bundle, record = invoke(tmp_path)
    record["network"] = "unenforced"
    with pytest.raises(ContractError, match="unenforced"):
        validate_document(conditions.KIND, record)
    assert record["status"] == "attested"
