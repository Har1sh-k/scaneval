"""Closed-book evidence distinguishes enforcement, observations, and provider assertions."""

from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

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


def invoke(tmp_path, adapter=None, *, policy="none", enforced=True, config=None, model_id=None, declared=True):
    source = tmp_path / "source"
    source.mkdir()
    for name, text in {"app.py": "print('hello')\n", "AGENTS.md": "Read the project.\n",
                       "README.md": "Example project\n", "package.json": '{"name":"example"}\n'}.items():
        (source / name).write_text(text)
    tree = hash_exported_tree(source)["tree_hash"]
    provenance = {"profile": "standard", "trial": {"tree_hash": tree}, "instruction_files": ["AGENTS.md"],
                  "retained_identity_cues": {"instruction_files": ["AGENTS.md"], "documentation": ["README.md"],
                                               "package_metadata": ["package.json"], "source_identifiers": "retained"}}
    prepared = PreparedInput("input", source, tree, ("python",), provenance,
                             condition={"name": "closed_book_standard", "policy": {}} if declared else None)
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


def test_undeclared_unrestricted_input_is_unavailable_not_a_requested_condition_failure(tmp_path):
    _bundle, record = invoke(tmp_path, policy="unrestricted", declared=False)
    assert record["status"] == "unavailable" and record["declared"] is False
    assert "unrestricted_network" in codes(record)


def test_an_eligible_inferred_condition_can_be_classified_from_saved_evidence(tmp_path):
    _bundle, record = invoke(tmp_path, declared=False)
    assert record["status"] == "attested" and record["declared"] is False


@pytest.mark.parametrize("policy", ["none", "unrestricted"])
def test_expectation_keyword_cannot_change_saved_declaration_state(tmp_path, policy):
    bundle, record = invoke(tmp_path, declared=False, policy=policy)
    assert conditions.classify_observation(bundle, condition=conditions.resolve_condition()) == record


@pytest.mark.parametrize("change", ["source", "history"])
def test_inferred_ineligible_source_or_history_is_unavailable(tmp_path, change):
    def mutate(source):
        if change == "source":
            (source / "app.py").write_text("print('modified')\n")
        else:
            (source / "history.data").write_bytes(b"# v2 git bundle\nfixture\n")
    _bundle, record = invoke(tmp_path, Offline(mutate=mutate), declared=False)
    assert record["status"] == "unavailable" and record["declared"] is False


def test_inferred_condition_still_fails_genuine_artifact_binding_corruption(tmp_path):
    bundle, _record = invoke(tmp_path, declared=False)
    (bundle / conditions.RECORD_FILE).unlink()
    path = bundle / conditions.CONFIGURATION_FILE
    configuration = json.loads(path.read_text())
    configuration["config"] = {"different": True}
    path.write_text(canonical_json(configuration))
    record = conditions.classify_observation(bundle)
    assert record["status"] == "failed" and "configuration_mismatch" in codes(record)


def test_undeclared_pr_keeps_neutral_history_but_is_outside_closed_book_standard(tmp_path):
    from test_v2_execution import pr_input, run, PrAdapter
    bundle = run(tmp_path, PrAdapter(), pr_input(tmp_path))
    record = load_document(bundle / conditions.RECORD_FILE, conditions.KIND)
    assert record["history"] == "neutral_synthetic"
    assert record["status"] == "unavailable" and record["declared"] is False
    assert "non_neutral_history" not in codes(record)


def test_missing_open_context_extension_refuses_before_creating_output(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    tree = hash_exported_tree(source)["tree_hash"]
    prepared = PreparedInput("input", source, tree, ("python",), {"profile": "standard", "trial": {"tree_hash": tree}},
                             condition={"name": "open_context", "policy": {}})
    from scaneval.execution import ExecutionError
    with pytest.raises(ExecutionError, match="open_context is unavailable"):
        run_invocation(prepared=prepared, adapter=Offline(), spec=SystemSpec("scanner", "fixture"),
                       preparation={}, out_dir=tmp_path / "out", run_id="missing-extension")
    assert not (tmp_path / "out").exists()


def test_unencodable_configuration_refuses_before_creating_output(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    tree = hash_exported_tree(source)["tree_hash"]
    prepared = PreparedInput("input", source, tree, ("python",), {})
    with pytest.raises(ContractError, match="UTF-8"):
        run_invocation(prepared=prepared, adapter=Offline(), spec=SystemSpec("scanner", "fixture", {"bad": chr(0xD800)}),
                       preparation={}, out_dir=tmp_path / "out", run_id="unencodable")
    assert not (tmp_path / "out").exists()


def test_prescan_history_read_error_has_execution_error_context(tmp_path, monkeypatch):
    from scaneval import execution
    def unreadable(*args, **kwargs):
        raise PermissionError("audit fixture denied")
    monkeypatch.setattr(execution, "audit_condition_history", unreadable)
    with pytest.raises(execution.ExecutionError, match="exported history could not be audited.*PermissionError"):
        invoke(tmp_path)


def test_neutral_single_commit_history_is_recorded_and_unchanged(tmp_path):
    _bundle, record = invoke(tmp_path, Offline(git=True))
    assert record["status"] == "attested" and record["history"] == "neutral_synthetic"


@pytest.mark.parametrize("git,inventory", [
    (False, {"git_paths": ["nested/.git"]}),
    (False, {"controller_paths": [".codex"]}),
    (False, {"history_artifacts": [{"path": "upstream.data", "kind": "git_bundle"}]}),
    (False, {"git_files_sha256": "sha256:" + "a" * 64}),
    (True, {"git_paths": [".git", "nested/.git"]}),
    (True, {"git_paths": []}),
    (True, {"controller_paths": [".codex"]}),
])
def test_history_summary_cannot_override_contradictory_saved_inventory(tmp_path, git, inventory):
    bundle, _record = invoke(tmp_path, Offline(git=git))
    (bundle / conditions.RECORD_FILE).unlink()
    evidence_path = bundle / conditions.EVIDENCE_FILE
    evidence = json.loads(evidence_path.read_text())
    for audit in evidence["history"].values():
        audit.update(deepcopy(inventory))
    evidence_path.write_text(canonical_json(evidence))
    record = conditions.classify_observation(bundle)
    assert record["status"] == "failed" and record["history"] == "unexpected"
    assert "history_inventory_mismatch" in codes(record)


@pytest.mark.parametrize("inventory", [None, "not-an-inventory", [None]])
def test_missing_or_malformed_history_inventory_cannot_attest(tmp_path, inventory):
    bundle, _record = invoke(tmp_path)
    (bundle / conditions.RECORD_FILE).unlink()
    evidence_path = bundle / conditions.EVIDENCE_FILE
    evidence = json.loads(evidence_path.read_text())
    for audit in evidence["history"].values():
        if inventory is None:
            audit.pop("git_paths")
        else:
            audit["git_paths"] = inventory
    evidence_path.write_text(canonical_json(evidence))
    record = conditions.classify_observation(bundle)
    assert record["status"] != "attested"
    assert codes(record) & {"history_inventory_gap", "invalid_history_inventory"}


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
    ("none", {"tools": {"web_search": {"enabled": True}}}, "retrieval_enabled"),
    ("none", {"web_search": "on"}, "retrieval_enabled"),
    ("none", {"tools": "Read,WebSearch"}, "retrieval_enabled"),
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


@pytest.mark.parametrize("name,state", [("WebSearch", "enabled"), ("Bash", "capture_gap"),
                                         ("mcp:browser/navigate", "enabled"), ("mcp:api/web_search", "enabled"),
                                         ("mcp:web_search", "enabled"), ("mcp__playwright__navigate", "enabled")])
def test_structured_retrieval_is_distinct_from_opaque_shell_observation(tmp_path, name, state):
    _bundle, record = invoke(tmp_path, Offline(tools=False, events=[{"metadata": {"tool_name": name, "input_summary": "curl https://example.com"}}]))
    assert record["retrieval"] == state
    assert record["status"] == ("failed" if state == "enabled" else "declared_only")


def test_browser_and_web_options_are_not_retrieval_enabling_flags(tmp_path):
    _bundle, record = invoke(tmp_path, config={"browser.headless": True, "web.cache": True})
    assert record["status"] == "attested" and "retrieval_enabled" not in codes(record)


def test_same_count_trace_substitution_fails_without_a_previous_condition_record(tmp_path):
    bundle, _record = invoke(tmp_path, Offline(tools=False, events=[{"metadata": {"tool_name": "Read"}}]))
    (bundle / conditions.RECORD_FILE).unlink()
    trace = bundle / "trace" / "events.jsonl"
    event = json.loads(trace.read_text())
    event["metadata"]["tool_name"] = "Grep"
    trace.write_text(canonical_json(event) + "\n")
    record = conditions.classify_observation(bundle)
    assert record["status"] == "failed" and "trace_binding_mismatch" in codes(record)


def test_foreign_run_trace_cannot_attest_even_when_hash_matches(tmp_path):
    _bundle, record = invoke(tmp_path, Offline(tools=False, events=[{"run_id": "another-run", "metadata": {"tool_name": "Read"}}]))
    assert record["status"] == "failed" and "trace_run_mismatch" in codes(record)


def test_legacy_trace_without_execution_time_digest_does_not_attest(tmp_path):
    bundle, _record = invoke(tmp_path, Offline(tools=False, events=[{"metadata": {"tool_name": "Read"}}]))
    (bundle / conditions.RECORD_FILE).unlink()
    evidence_path = bundle / conditions.EVIDENCE_FILE
    evidence = json.loads(evidence_path.read_text())
    evidence.pop("trace")
    evidence_path.write_text(canonical_json(evidence))
    record = conditions.classify_observation(bundle)
    assert record["status"] == "declared_only" and "trace_binding_unavailable" in codes(record)


@pytest.mark.parametrize("key,value,code", [
    ("adapter_identity", {"name": "wrong", "version": "1"}, "adapter_identity_mismatch"),
    ("model_id", "other-model", "model_configuration_mismatch"),
    ("model_revision", "other-revision", "model_configuration_mismatch"),
])
def test_adapter_and_model_configuration_are_independently_bound(tmp_path, key, value, code):
    bundle, _record = invoke(tmp_path, model_id="model-a")
    (bundle / conditions.RECORD_FILE).unlink()
    path = bundle / conditions.CONFIGURATION_FILE
    configuration = json.loads(path.read_text())
    configuration[key] = value
    path.write_text(canonical_json(configuration))
    record = conditions.classify_observation(bundle)
    assert record["status"] == "failed" and code in codes(record)


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


def test_adapter_model_namespace_is_bound_to_adapter_config_not_system_label(tmp_path):
    class Routed(Remote):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            outcome.model_identity = {"requested": "provider/model-a", "resolved": None, "verification": "self_reported"}
            return outcome
    _bundle, record = invoke(tmp_path, Routed(), policy="model_provider_only", model_id="model-a", config={"model": "provider/model-a"})
    assert record["status"] == "declared_only" and "model_identity_mismatch" not in codes(record)


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


def test_legacy_classification_is_independent_of_bundle_location(tmp_path):
    bundle, _record = invoke(tmp_path)
    for name in (conditions.RECORD_FILE, conditions.POLICY_FILE, conditions.CONFIGURATION_FILE,
                 conditions.PROVENANCE_FILE, conditions.EVIDENCE_FILE):
        (bundle / name).unlink()
    first = conditions.classify_observation(bundle)
    moved = tmp_path / "relocated" / bundle.name
    shutil.copytree(bundle, moved)
    assert conditions.classify_observation(moved) == first
    assert str(tmp_path) not in canonical_json(first)


def test_historical_provenance_without_optional_cue_inventory_remains_readable(tmp_path):
    bundle, _record = invoke(tmp_path)
    (bundle / conditions.RECORD_FILE).unlink()
    path = bundle / conditions.PROVENANCE_FILE
    provenance = json.loads(path.read_text())
    provenance.pop("retained_identity_cues")
    path.write_text(canonical_json(provenance))
    execution_path = bundle / "execution.json"
    execution = json.loads(execution_path.read_text())
    execution["provenance"]["provenance_sha256"] = canonical_sha256(provenance)
    execution_path.write_text(canonical_json(execution))
    record = conditions.classify_observation(bundle)
    assert record["status"] == "attested"
    assert record["retained_identity_cues"]["instruction_files"] == ["AGENTS.md"]


def test_condition_schema_refuses_attestation_of_an_unenforced_declaration(tmp_path):
    _bundle, record = invoke(tmp_path)
    record["network"] = "unenforced"
    with pytest.raises(ContractError, match="unenforced"):
        validate_document(conditions.KIND, record)
    assert record["status"] == "attested"
