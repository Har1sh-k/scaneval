"""Own-harness adapter: file-only import, driver contract, and a mock-runner engine run."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from scaneval.adapters import get_adapter
from scaneval.adapters import llm_harness
from scaneval.adapters.base import AdapterError, CommandResult, SystemSpec
from scaneval.adapters.llm_harness import (
    HARNESS_PRESETS,
    TOOL_POLICY,
    capture_status,
    import_harness_findings,
    parse_frontmatter,
)
from scaneval.contracts import canonical_sha256, load_document
from scaneval.execution import PreparedInput, run_invocation
from scaneval.materialize import hash_exported_tree
from scaneval.scoring import score


ROOT = Path(__file__).resolve().parents[1]
SECUREVIBES = ROOT.parent / "securevibes-agent"
FIELDGLASS = ROOT.parent / "runsortie" / "fieldglass"
CLOCK = lambda: datetime(2026, 9, 20, 16, 0, tzinfo=timezone.utc)  # noqa: E731

FINDING = '''---
id: SV-AUTH-AUTHBYPASS-001
title: "Route handler skips auth: token check missing"
vulnerability_class: authbypass
severity: high
status: new
component: AUTH
file_path: ./src/routes/admin.ts
impact_tags: [privilege-escalation, data-exposure]
confidence: 0.812
crown_jewel: true
scanner_sources: [llm-hypothesis, specialist:route-auth]
created_at: 2026-09-20T00:00:00.000Z
updated_at: 2026-09-20T00:00:00.000Z
fingerprint: abc
---
# Route handler skips auth: token check missing

## Reasoning
The admin route registers before the auth middleware, so requests reach it unauthenticated.
'''


def test_frontmatter_parser_handles_arrays_quoted_strings_and_numbers():
    record, body = parse_frontmatter(FINDING)
    assert record["title"] == "Route handler skips auth: token check missing"
    assert record["impact_tags"] == ["privilege-escalation", "data-exposure"]
    assert record["scanner_sources"] == ["llm-hypothesis", "specialist:route-auth"]
    assert record["confidence"] == 0.812 and record["crown_jewel"] is True
    assert body.startswith("# Route handler")
    assert parse_frontmatter("no frontmatter") == ({}, "no frontmatter")


def test_import_keeps_findings_file_only_with_full_native_text(tmp_path):
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    (findings / "b.md").write_text(FINDING.replace("SV-AUTH-AUTHBYPASS-001", "SV-X-002").replace("./src/routes/admin.ts", "/abs/path.ts"), encoding="utf-8")
    (findings / "c.md").write_text("---\ntitle: no id\n---\nbody\n", encoding="utf-8")
    stage = tmp_path / "raw" / "harness-findings"
    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings", stage_dir=stage)
    assert imported.claims == [{
        "claim_id": "SV-AUTH-AUTHBYPASS-001", "allegation": "Route handler skips auth: token check missing",
        "kind": "auth_bypass", "primary_location": {"path": "src/routes/admin.ts"},
        "native_id": "SV-AUTH-AUTHBYPASS-001", "native_rule_id": "securevibes-agent:authbypass",
        "raw_artifact_id": "harness-findings/a.md",
        "evidence_text": "The admin route registers before the auth middleware, so requests reach it unauthenticated.",
        "native_severity": "high",
    }]
    assert imported.artifacts == [{"id": "harness-findings/a.md", "path": stage / "a.md"}]
    assert (stage / "a.md").read_text(encoding="utf-8") == FINDING
    assert not (stage / "b.md").exists() and not (stage / "c.md").exists()
    assert any("SV-X-002" in note and "unusable file_path" in note for note in imported.notes)
    assert any("c.md" in note for note in imported.notes)
    assert imported.lost == 2, "a record that yields no claim is import loss, not a note on a clean scan"
    missing = import_harness_findings(tmp_path / "missing", harness="x", artifact_prefix="y",
                                      stage_dir=tmp_path / "unused")
    assert missing == ([], [], ["no findings directory was written by the harness"], 0)
    assert not (tmp_path / "unused").exists(), "nothing is staged when the harness wrote no findings"


def test_a_finding_record_that_is_not_a_regular_file_is_counted_as_import_loss(tmp_path):
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    (findings / "link.md").symlink_to(findings / "a.md")
    (findings / "dir.md").mkdir()
    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings",
                                       stage_dir=tmp_path / "raw" / "harness-findings")

    assert [claim["claim_id"] for claim in imported.claims] == ["SV-AUTH-AUTHBYPASS-001"]
    assert imported.lost == 2
    assert sum("not a regular file" in note for note in imported.notes) == 2


def test_prepare_validates_configuration(tmp_path):
    adapter = get_adapter("llm-harness")
    with pytest.raises(AdapterError, match="config.harness"):
        adapter.prepare(SystemSpec("s", "llm-harness", {}), tmp_path)
    with pytest.raises(AdapterError, match="does not exist"):
        adapter.prepare(SystemSpec("s", "llm-harness", {"harness": "fieldglass", "root": str(tmp_path / "nope")}), tmp_path)
    fake_root = tmp_path / "harness"
    fake_root.mkdir()
    with pytest.raises(AdapterError, match="missing"):
        adapter.prepare(SystemSpec("s", "llm-harness", {"harness": "securevibes-agent", "root": str(fake_root), "model": "m"}), tmp_path)


def _prepared(tmp_path: Path) -> PreparedInput:
    source = tmp_path / "trial" / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "server.js").write_text(
        "const { exec } = require('child_process');\n"
        "const express = require('express');\nconst app = express();\n"
        "app.get('/run', (req, res) => { exec(req.query.cmd, (e, out) => res.send(out)); });\n"
        "app.get('/admin', (req, res) => { res.send(eval(req.query.code)); });\n"
        "app.listen(3000);\n", encoding="utf-8")
    (source / "package.json").write_text('{"name": "pilot-fixture", "version": "1.0.0"}\n', encoding="utf-8")
    (source / "README.md").write_text("# fixture\n", encoding="utf-8")
    return PreparedInput("fixture-js", source, hash_exported_tree(source)["tree_hash"], ("javascript",), {"source": {"commit": "fixture"}})


@pytest.mark.parametrize("harness,root", [("securevibes-agent", SECUREVIBES), ("fieldglass", FIELDGLASS)])
def test_mock_runner_engine_run_produces_observed_bundle(tmp_path, harness, root):
    if not (root / "node_modules" / ".bin" / "tsx").exists():
        pytest.skip(f"{harness} checkout with node_modules not available at {root}")
    adapter = get_adapter("llm-harness")
    spec = SystemSpec(f"{harness}-mock", "llm-harness", {
        "harness": harness, "root": str(root), "model": "test/mock-llm", "runner": "mock",
        "qmd_profile": "lite", "llm_max_files": 5, "llm_timeout_ms": 20000, "flush_timeout_ms": 5000,
    })
    preparation = adapter.prepare(spec, tmp_path / "cache")
    assert preparation["harness"]["state_dir"] == HARNESS_PRESETS[harness]["state_dir"]
    bundle = run_invocation(prepared=_prepared(tmp_path), adapter=adapter, spec=spec, preparation=preparation,
                            out_dir=tmp_path / "out", run_id="run-mock", timeout_seconds=600, trace_mode="content",
                            network_policy="none", clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    output = json.loads((bundle / "raw" / "driver-output.json").read_text(encoding="utf-8"))

    assert result["status"] in ("success", "partial"), execution["error"]
    assert output["runner"] == "mock" and output["model_calls"] >= 1
    assert execution["model_identity"]["verification"] == "not_applicable"
    assert any("DIAGNOSTIC" in note for note in execution["notes"])
    assert execution["provenance"]["synthetic_history"]["message"] == "snapshot"
    assert execution["provenance"]["captured_state_dirs"] == [HARNESS_PRESETS[harness]["state_dir"]]
    assert execution["provenance"]["source_modified"] is False
    assert execution["capture"]["model_requests"] == "partial" and execution["capture"]["finding_candidate"] == "unavailable"
    registered = {artifact["id"]: artifact["path"] for artifact in execution["raw_artifacts"]}
    for claim in result["claims"]:
        assert "start_line" not in claim["primary_location"], "file-level findings must stay file-level"
        assert claim["native_rule_id"].startswith(f"{harness}:")
        assert claim["raw_artifact_id"] in registered, "a claim must name an artifact the bundle holds"
        assert (bundle / registered[claim["raw_artifact_id"]]).is_file()

    events = [json.loads(line) for line in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert execution["trace"]["events"] == len(events) == output["trace"]["events_written"]
    types = {event["type"] for event in events}
    assert {"model.request", "model.response"} <= types
    requests = [e for e in events if e["type"] == "model.request"]
    assert all(e["run_id"] == "run-mock" and e["producer_id"] == f"{harness}-driver" for e in events)
    for event in requests:
        content = event["content"]
        prompt = content["args"][-1] if "args" in content else content["request"]["prompt"]
        assert isinstance(prompt, str) and len(prompt) == event["metadata"]["prompt_chars"] > 0
    assert [e["sequence"] for e in events] == list(range(len(events)))
    submitted = [e for e in events if e["type"] == "finding.submitted"]
    assert {e["claim_id"] for e in submitted} == {c["claim_id"] for c in result["claims"]}
    assert execution["trace"]["capture_gap"] is False and execution["trace"]["dropped_events"] == 0
    assert (bundle / "raw" / "harness-state").exists()

    # The harness writes its plan inside the workspace, which is gone by the time the bundle is
    # sealed. Every declared artifact must still resolve, and its hash must cover real bytes.
    assert not any("declared artifact missing" in note for note in execution["notes"]), execution["notes"]
    for artifact in execution["raw_artifacts"]:
        assert (bundle / artifact["path"]).is_file(), artifact
    plans = {a["id"] for a in execution["raw_artifacts"] if a["id"].startswith("harness-")}
    assert "harness-threat-model.md" in plans and "harness-scan-log.md" in plans


def test_metadata_mode_omits_prompt_content(tmp_path):
    root = SECUREVIBES
    if not (root / "node_modules" / ".bin" / "tsx").exists():
        pytest.skip("securevibes-agent checkout not available")
    adapter = get_adapter("llm-harness")
    spec = SystemSpec("sv-mock-meta", "llm-harness", {"harness": "securevibes-agent", "root": str(root), "model": "test/mock-llm",
                                                     "runner": "mock", "qmd_profile": "lite", "llm_max_files": 3})
    preparation = adapter.prepare(spec, tmp_path / "cache")
    bundle = run_invocation(prepared=_prepared(tmp_path), adapter=adapter, spec=spec, preparation=preparation,
                            out_dir=tmp_path / "out", run_id="run-meta", timeout_seconds=600, trace_mode="metadata", clock=CLOCK)
    events = [json.loads(line) for line in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events and all("content" not in event for event in events)
    assert all(event["capture_status"] in ("partial", "redacted") for event in events if event["type"].startswith("model."))
    off = run_invocation(prepared=_prepared(tmp_path / "off"), adapter=adapter, spec=spec, preparation=preparation,
                         out_dir=tmp_path / "out-off", run_id="run-off", timeout_seconds=600, trace_mode="off", clock=CLOCK)
    execution = load_document(off / "execution.json", "execution-record")
    assert execution["trace"] is None and execution["capture"]["model_requests"] == "unavailable"
    on_result = load_document(bundle / "result.json", "scan-result")
    off_result = load_document(off / "result.json", "scan-result")
    assert [c["claim_id"] for c in on_result["claims"]] == [c["claim_id"] for c in off_result["claims"]], "tracing must not change findings"


@pytest.mark.parametrize("routes", [["claude"], ["pi"], ["claude", "pi"], ["unknown"], []])
def test_tool_dispatch_is_unavailable_on_every_real_route(routes):
    capture = capture_status("content", routes, has_summary=True)

    assert capture["tool_calls"] == "unavailable", "an unobserved tool surface is not an absent one"
    assert capture["finding_candidate"] == "unavailable"
    assert capture["finding_validation"] == "unavailable"
    assert capture["finding_filtered"] == "unavailable"


def test_only_the_mock_runner_makes_tool_dispatch_inapplicable():
    assert capture_status("content", ["mock"], has_summary=True)["tool_calls"] == "not_applicable"
    assert capture_status("content", ["mock", "claude"], has_summary=True)["tool_calls"] == "unavailable"


@pytest.mark.parametrize("mode,expected", [("off", "unavailable"), ("metadata", "partial"), ("content", "partial")])
def test_model_events_are_never_complete_because_retries_are_below_the_boundary(mode, expected):
    capture = capture_status(mode, ["claude"], has_summary=True)

    assert capture["model_requests"] == capture["model_responses"] == expected
    assert capture["context_selection"] == ("unavailable" if mode == "off" else "partial")
    assert capture["finding_submitted"] == ("unavailable" if mode == "off" else "complete")
    assert capture_status(mode, ["claude"], has_summary=False)["finding_submitted"] == "unavailable"


def test_every_declared_tool_policy_says_who_declared_it():
    assert set(TOOL_POLICY) == {"pi", "claude", "mock"}
    assert "--no-tools" in TOOL_POLICY["pi"]
    assert "file tools" in TOOL_POLICY["claude"] and "remain permitted" in TOOL_POLICY["claude"]


def test_mock_run_records_the_mock_route_and_its_policy_note(tmp_path):
    root = SECUREVIBES
    if not (root / "node_modules" / ".bin" / "tsx").exists():
        pytest.skip("securevibes-agent checkout not available")
    adapter = get_adapter("llm-harness")
    spec = SystemSpec("sv-mock-routes", "llm-harness", {"harness": "securevibes-agent", "root": str(root),
                                                        "model": "test/mock-llm", "runner": "mock",
                                                        "qmd_profile": "lite", "llm_max_files": 3})
    preparation = adapter.prepare(spec, tmp_path / "cache")
    bundle = run_invocation(prepared=_prepared(tmp_path), adapter=adapter, spec=spec, preparation=preparation,
                            out_dir=tmp_path / "out", run_id="run-routes", timeout_seconds=600,
                            trace_mode="content", clock=CLOCK)
    execution = load_document(bundle / "execution.json", "execution-record")
    output = json.loads((bundle / "raw" / "driver-output.json").read_text(encoding="utf-8"))

    assert output["observed_routes"] == ["mock"]
    assert "tool.start" in output["trace"]["unavailable"] and "tool.end" in output["trace"]["unavailable"]
    assert execution["capture"]["tool_calls"] == "not_applicable"
    assert any("no model process is spawned" in note for note in execution["notes"])
    assert execution["adapter"]["version"] == "2.1.0"


SECOND_FINDING = (FINDING.replace("SV-AUTH-AUTHBYPASS-001", "SV-INJ-CMDI-002")
                  .replace("vulnerability_class: authbypass", "vulnerability_class: cmdi")
                  .replace("./src/routes/admin.ts", "src/routes/run.ts"))
NO_ID_FINDING = "---\ntitle: a record with no id\nfile_path: src/a.ts\n---\n# body\n"
ESCAPING_FINDING = (FINDING.replace("SV-AUTH-AUTHBYPASS-001", "SV-ESC-003")
                    .replace("./src/routes/admin.ts", "../outside/secrets.ts"))
# What the driver writes when a harness run completed normally.
DRIVER_OUTPUT = {
    "driver_version": "stub-driver-1",
    "observed_routes": ["mock"],
    "summary": {"bootstrapScan": {"llmCalls": 1, "failedCalls": 0, "status": "complete",
                                  "hypothesisCoverage": 1.0},
                "runtimeProfile": "lite", "degraded": False},
}


def _fake_harness_root(tmp_path: Path) -> Path:
    """The layout ``prepare`` checks for, with no harness and no node behind it."""
    root = tmp_path / "harness"
    (root / "node_modules" / ".bin").mkdir(parents=True)
    (root / "node_modules" / ".bin" / "tsx").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (root / "src" / "runtime").mkdir(parents=True)
    for entry in ("engine.ts", "pi-runner.ts"):
        (root / "src" / "runtime" / entry).write_text("// stub\n", encoding="utf-8")
    (root / "package.json").write_text('{"name": "stub-harness", "version": "9.9.9"}\n', encoding="utf-8")
    return root


def _stub_driver(monkeypatch, records: dict[str, str], *, state_dir: str = ".securevibes",
                 plan_as_link: bool = False) -> None:
    """Stand in for the tsx driver and leave exactly the records a harness run would leave.

    No process is spawned and no model is called: the stub reads the driver config the adapter
    wrote and writes the finding records, the plan, and the driver output itself.
    """

    def fake_run_command(argv, *, cwd, timeout_seconds, env, stdout_path, stderr_path, stdin_text=None):
        config = json.loads(Path(argv[-1]).read_text(encoding="utf-8"))
        state = Path(config["repo_path"]) / state_dir
        (state / "findings").mkdir(parents=True, exist_ok=True)
        for name, text in records.items():
            (state / "findings" / name).write_text(text, encoding="utf-8")
        if plan_as_link:
            (state / "elsewhere.md").write_text("# plan\n", encoding="utf-8")
            (state / "bootstrap-plan.md").symlink_to(state / "elsewhere.md")
        else:
            (state / "bootstrap-plan.md").write_text("# plan\n", encoding="utf-8")
        Path(config["output_path"]).write_text(json.dumps(DRIVER_OUTPUT), encoding="utf-8")
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        return CommandResult(list(argv), 0, False, 0.0, stdout_path, stderr_path)

    monkeypatch.setattr(llm_harness, "run_command", fake_run_command)


def _stubbed_bundle(tmp_path: Path, monkeypatch, records: dict[str, str], *, run_id: str = "run-stub",
                    root_config: str | None = None, plan_as_link: bool = False) -> Path:
    root = _fake_harness_root(tmp_path)
    sdk = tmp_path / "observer-sdk.js"
    sdk.write_text("// stub\n", encoding="utf-8")
    adapter = get_adapter("llm-harness")
    spec = SystemSpec("sv-stub", "llm-harness", {
        "harness": "securevibes-agent", "root": root_config or str(root), "model": "test/mock-llm",
        "runner": "mock", "observer_sdk": str(sdk)})
    preparation = adapter.prepare(spec, tmp_path / "cache")
    _stub_driver(monkeypatch, records, plan_as_link=plan_as_link)
    return run_invocation(prepared=_prepared(tmp_path), adapter=adapter, spec=spec, preparation=preparation,
                          out_dir=tmp_path / "out", run_id=run_id, timeout_seconds=60, trace_mode="off",
                          network_policy="none", clock=CLOCK)


def _quiet_review(result: dict, *, accept_claim: str | None = None) -> tuple[dict, dict]:
    """One capability-safe control and a supplied quiet decision over the saved result."""
    plan = {
        "schema_version": "2.0", "input_hash": result["input_hash"], "scope": "diagnostic",
        "targets": [{"target_id": "T1", "description": "the planted root cause", "validation_level": "fixture"}],
        "controls": [{"control_id": "C1", "description": "safe capability", "type": "capability_safe",
                      "validation_level": "fixture"}],
        "review_budgets": [3],
    }
    decisions = {
        "schema_version": "2.0", "run_id": result["run_id"], "input_hash": result["input_hash"],
        "result_sha256": canonical_sha256(result),
        "claim_matches": [{"claim_id": accept_claim, "target_id": "T1", "decision": "accepted",
                           "reason": "the reviewer accepted this claim as the target"}] if accept_claim else [],
        "control_assessments": [{"control_id": "C1", "decision": "quiet", "claim_ids": [],
                                 "reason": "the scanner said nothing about the safe capability"}],
    }
    return plan, decisions


def test_a_finding_record_the_importer_cannot_read_blocks_completeness_and_quiet_credit(tmp_path, monkeypatch):
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {
        "good.md": FINDING, "no-id.md": NO_ID_FINDING, "escaping.md": ESCAPING_FINDING})
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert [claim["claim_id"] for claim in result["claims"]] == ["SV-AUTH-AUTHBYPASS-001"]
    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert result["error"]["code"] == "import_loss"
    assert "2 harness finding record(s)" in result["error"]["message"]
    assert "no-id.md" in result["error"]["message"] and "SV-ESC-003" in result["error"]["message"]
    assert execution["status"] == "partial" and execution["error"]["code"] == "import_loss"

    plan, decisions = _quiet_review(result, accept_claim="SV-AUTH-AUTHBYPASS-001")
    report = score(plan, result, decisions)
    controls = report["metrics"]["controls"]["capability_safe"]
    assert controls["completed"] == 0 and controls["resolved"] == 0, "a dropped record must not earn silence credit"
    assert controls["assessable_mass"] == 0.0 and report["metrics"]["completed"] is False
    assert "Incomplete or failed execution cannot establish a successful negative control." in report["warnings"]
    # The asymmetry the scoring contract intends: the confirmed hit in partial output still counts.
    assert report["metrics"]["targets_detected"] == 1 and report["metrics"]["known_target_recall"] == 1.0
    assert report["metrics"]["claims_delivered"] is None, "an incomplete claim set has no delivered count"


def test_an_import_with_nothing_lost_still_earns_quiet_credit(tmp_path, monkeypatch):
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"good.md": FINDING}, run_id="run-clean")
    result = load_document(bundle / "result.json", "scan-result")

    assert result["status"] == "success" and result["bundles_resolved"] is True
    plan, decisions = _quiet_review(result)
    controls = score(plan, result, decisions)["metrics"]["controls"]["capability_safe"]
    assert controls["completed"] == 1 and controls["resolved"] == 1


def test_every_claim_points_at_a_raw_artifact_the_bundle_registers(tmp_path, monkeypatch):
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING, "b.md": SECOND_FINDING})
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    registered = {artifact["id"]: artifact["path"] for artifact in execution["raw_artifacts"]}

    assert len(result["claims"]) == 2
    for claim in result["claims"]:
        assert claim["raw_artifact_id"] in registered, "a claim must name an artifact the bundle holds"
        assert (bundle / registered[claim["raw_artifact_id"]]).is_file()
    assert {artifact["id"] for artifact in result["raw_artifacts"]} == set(registered)
    staged = bundle / registered["harness-findings/a.md"]
    assert staged.read_text(encoding="utf-8") == FINDING, "the registered artifact is the native record itself"


def test_a_relative_harness_root_is_resolved_before_it_prefixes_a_path_or_becomes_a_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, root_config="harness")
    execution = load_document(bundle / "execution.json", "execution-record")
    config = json.loads((bundle / "raw" / "driver-config.json").read_text(encoding="utf-8"))
    resolved = (tmp_path / "harness").resolve()

    assert execution["preparation"]["harness"]["root"] == str(resolved)
    assert execution["preparation"]["harness"]["configured_root"] == "harness"
    assert config["harness_root"] == str(resolved)
    assert execution["command"][0] == str(resolved / "node_modules" / ".bin" / "tsx")


def test_a_plan_record_that_is_not_a_regular_file_is_noted_rather_than_dropped(tmp_path, monkeypatch):
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, plan_as_link=True)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert result["status"] == "success", "a plan record is not a claim, so it does not degrade the scan"
    assert any("bootstrap-plan.md" in note and "not staged" in note for note in execution["notes"])
    assert "harness-bootstrap-plan.md" not in {artifact["id"] for artifact in execution["raw_artifacts"]}
