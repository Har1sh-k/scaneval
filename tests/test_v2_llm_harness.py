"""Own-harness adapter: file-only import, driver contract, and a mock-runner engine run."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from scaneval.adapters import get_adapter
from scaneval.adapters.base import AdapterError, SystemSpec
from scaneval.adapters.llm_harness import (
    HARNESS_PRESETS,
    TOOL_POLICY,
    capture_status,
    import_harness_findings,
    parse_frontmatter,
)
from scaneval.contracts import load_document
from scaneval.execution import PreparedInput, run_invocation
from scaneval.materialize import hash_exported_tree


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
    claims, notes = import_harness_findings(findings, harness="securevibes-agent", artifact_id="harness-findings")
    assert claims == [{
        "claim_id": "SV-AUTH-AUTHBYPASS-001", "allegation": "Route handler skips auth: token check missing",
        "kind": "auth_bypass", "primary_location": {"path": "src/routes/admin.ts"},
        "native_id": "SV-AUTH-AUTHBYPASS-001", "native_rule_id": "securevibes-agent:authbypass",
        "raw_artifact_id": "harness-findings",
        "evidence_text": "The admin route registers before the auth middleware, so requests reach it unauthenticated.",
        "native_severity": "high",
    }]
    assert any("SV-X-002" in note and "unusable file_path" in note for note in notes)
    assert any("c.md" in note for note in notes)
    assert import_harness_findings(tmp_path / "missing", harness="x", artifact_id="y") == ([], ["no findings directory was written by the harness"])


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
    for claim in result["claims"]:
        assert "start_line" not in claim["primary_location"], "file-level findings must stay file-level"
        assert claim["native_rule_id"].startswith(f"{harness}:")

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
