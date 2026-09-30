"""Own-harness adapter: file-only import, driver contract, and a mock-runner engine run."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import threading

import pytest

from scaneval.adapters import get_adapter
from scaneval.adapters import llm_harness
from scaneval.adapters.base import AdapterError, CommandResult, SystemSpec
from scaneval.adapters.llm_harness import (
    HARNESS_PRESETS,
    TOOL_POLICY,
    Enclosure,
    FindingsBaseline,
    HarnessImport,
    LostRecord,
    SelfReport,
    capture_status,
    import_harness_findings,
    parse_frontmatter,
    read_self_report,
    reconcile_import,
    snapshot_findings,
)
from scaneval.contracts import canonical_sha256, load_document
from scaneval.execution import ExecutionError, PreparedInput, run_invocation
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


mkfifo_required = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")


def call_with_deadline(function, seconds: float = 30.0):
    """Call *function* on a daemon thread and fail the test if it does not return in time.

    Opening a named pipe for reading blocks until something writes to it, so a regression in the
    guards below would wait forever rather than fail. The worker is a daemon thread, so a
    blocked call cannot hold up the rest of the suite or the interpreter's exit either.
    """
    outcome: dict[str, object] = {}

    def call() -> None:
        try:
            outcome["value"] = function()
        except BaseException as exc:  # re-raised below, on the thread running the test
            outcome["error"] = exc

    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        pytest.fail(f"the call was still running after {seconds} seconds; it is blocked on a read")
    if "error" in outcome:
        raise outcome["error"]  # type: ignore[misc]
    return outcome["value"]


def _enclosure(workspace: Path, staging: Path | None = None) -> Enclosure:
    """The two roots the importer is allowed to read from and write into, for a unit test.

    Every path the adapter touches after the harness starts is proved to resolve inside one of
    these, which is what catches a symbolic link above a record rather than only one at it. A
    unit test that is not about escaping hands both roots the temporary directory it built in.

    Captured, as the adapter captures them: the real path of each root is read here, before the
    call under test, and the checks inside it compare against that rather than resolving the root
    again afterwards.
    """
    return Enclosure.capture(workspace, staging if staging is not None else workspace)


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
    baseline = snapshot_findings(findings, _enclosure(tmp_path))
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    (findings / "b.md").write_text(FINDING.replace("SV-AUTH-AUTHBYPASS-001", "SV-X-002").replace("./src/routes/admin.ts", "/abs/path.ts"), encoding="utf-8")
    (findings / "c.md").write_text("---\ntitle: no id\n---\nbody\n", encoding="utf-8")
    stage = tmp_path / "raw" / "harness-findings"
    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings", stage_dir=stage,
                                       baseline=baseline, enclosure=_enclosure(tmp_path))
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
                                      stage_dir=tmp_path / "unused",
                                      baseline=snapshot_findings(tmp_path / "missing", _enclosure(tmp_path)),
                                      enclosure=_enclosure(tmp_path))
    # The fourth field is the losses themselves, not a separate count: ``lost`` is derived from
    # it, so the number and the reasons cannot disagree, and each loss carries the finding id it
    # knows so the self-report reconciliation can tell which reported finding it explains.
    assert missing == ([], [], ["no findings directory was written by the harness"], ())
    assert missing.lost == 0
    assert not (tmp_path / "unused").exists(), "nothing is staged when the harness wrote no findings"


def test_a_finding_record_that_is_not_a_regular_file_is_counted_as_import_loss(tmp_path):
    findings = tmp_path / "findings"
    findings.mkdir()
    baseline = snapshot_findings(findings, _enclosure(tmp_path))
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    (findings / "link.md").symlink_to(findings / "a.md")
    (findings / "dir.md").mkdir()
    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings",
                                       stage_dir=tmp_path / "raw" / "harness-findings",
                                       baseline=baseline, enclosure=_enclosure(tmp_path))

    assert [claim["claim_id"] for claim in imported.claims] == ["SV-AUTH-AUTHBYPASS-001"]
    assert imported.lost == 2
    assert sum("not a regular file" in note for note in imported.notes) == 2


@mkfifo_required
def test_a_named_pipe_where_a_finding_record_belongs_is_counted_rather_than_opened(tmp_path):
    """The same rule as the driver output, one directory down: the read must not be able to block.

    A record was classified with ``is_file()`` and then read with ``read_bytes()``, two separate
    operations on a path the harness owns. Every read goes through one function now, which
    proves the file is a regular file in the open that reads it, so a named pipe is one more
    record that could not be read rather than an import that never returns. The call runs behind
    a deadline, so a regression fails here instead of stalling the suite.
    """
    findings = tmp_path / "findings"
    findings.mkdir()
    baseline = snapshot_findings(findings, _enclosure(tmp_path))
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    os.mkfifo(findings / "pipe.md")

    imported = call_with_deadline(
        lambda: import_harness_findings(findings, harness="securevibes-agent",
                                        artifact_prefix="harness-findings",
                                        stage_dir=tmp_path / "raw" / "harness-findings",
                                        baseline=baseline, enclosure=_enclosure(tmp_path)))

    assert [claim["claim_id"] for claim in imported.claims] == ["SV-AUTH-AUTHBYPASS-001"]
    assert imported.lost == 1
    assert any("pipe.md" in note and "not a regular file" in note for note in imported.notes)
    # The baseline is taken before the harness runs and must not block on one either.
    with_pipe = call_with_deadline(lambda: snapshot_findings(findings, _enclosure(tmp_path)))
    assert with_pipe.established is True and with_pipe.digests["pipe.md"] is None


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
    """One engine run per harness family, with the capture matrix read against what it exported.

    The finding-candidate assertion used to be the constant ``unavailable``. It is now read off
    the capabilities the driver reported, because it stopped being a property of this adapter: a
    harness build exporting the engine observer reports every candidate it mints, and one that
    does not exports no boundary for them at all. Both builds are exercised here whenever both
    checkouts are present, so the two halves of that branch are covered by real engines.
    """
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
    engine_hooks = bool(output["hooks"]["engine"])
    assert execution["capture"]["model_requests"] == "partial"
    assert execution["capture"]["finding_candidate"] == ("complete" if engine_hooks else "unavailable")
    registered = {artifact["id"]: artifact["path"] for artifact in execution["raw_artifacts"]}
    for claim in result["claims"]:
        assert "start_line" not in claim["primary_location"], "file-level findings must stay file-level"
        assert claim["native_rule_id"].startswith(f"{harness}:")
        assert claim["raw_artifact_id"] in registered, "a claim must name an artifact the bundle holds"
        assert (bundle / registered[claim["raw_artifact_id"]]).is_file()

    # The premise the self-report reconciliation rests on, checked against the real engine:
    # every finding the harness names in its own summary is a record it wrote and the importer
    # read, so a clean run reports no import loss.
    reported = read_self_report(output.get("summary"))
    assert set(reported.ids) <= {claim["claim_id"] for claim in result["claims"]}
    assert not any("Import loss" in note for note in execution["notes"]), execution["notes"]

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
    """The capture state is supplied here because ``complete`` now requires a gap-free one.

    This test asserted ``finding_submitted`` complete for any traced run with a summary, which
    is the claim the next test shows was wrong; the gap-free state keeps it as the control for
    what the model categories say.
    """
    gapless = {"capture_gap": False, "dropped_events": 0}
    capture = capture_status(mode, ["claude"], has_summary=True, capture_state=gapless)

    assert capture["model_requests"] == capture["model_responses"] == expected
    assert capture["context_selection"] == ("unavailable" if mode == "off" else "partial")
    assert capture["finding_submitted"] == ("unavailable" if mode == "off" else "complete")
    assert capture_status(mode, ["claude"], has_summary=False,
                          capture_state=gapless)["finding_submitted"] == "unavailable"


@pytest.mark.parametrize(
    ("state", "expected"),
    [({"capture_gap": False, "dropped_events": 0}, "complete"),
     ({"capture_gap": True, "dropped_events": 0}, "partial"),
     ({"capture_gap": False, "dropped_events": 3}, "partial"),
     ({}, "partial"),
     (None, "partial")],
    ids=["gapless", "gap", "dropped", "empty-state", "no-state"],
)
def test_finding_submitted_follows_the_capture_state_the_same_record_carries(state, expected):
    """``complete`` used to follow from tracing at all, contradicting the record it sits in.

    The execution record carries ``capture_gap`` and ``dropped_events`` from the same observer
    state, so a run that reported a gap or a dropped event was calling its finding capture
    complete on one line and admitting a hole in it on the next. A state that reports neither is
    still complete; a state that reports either, and a run that reported no state at all, are
    partial, because nothing there rules a gap out.
    """
    capture = capture_status("content", ["claude"], has_summary=True, capture_state=state)

    assert capture["finding_submitted"] == expected


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
    # 2.2.0 is the release that made the capture matrix depend on the harness build: the same
    # adapter now reports different categories against different harnesses, which is a change a
    # reader of an old execution record must be able to date. 2.3.0 is the release that runs the
    # harness's pr mode as well (changed deliberately from the value 2.2.0 this line pinned).
    assert execution["adapter"]["version"] == "2.3.0"


# Where an observation came from, as the trace event contract spells it. Two of these are this
# package's own: ``driver_runner_wrapper`` for what the driver sees by wrapping a harness runner
# that reports nothing itself, and ``harness_summary`` for findings read off the summary the
# engine returned rather than reported as it submitted them.
EVENT_SOURCES = {"harness_runner_hook", "harness_emitted", "harness_self_report", "harness_record",
                 "harness_summary", "driver_runner_wrapper", "claude_code_transcript",
                 "claude_code_stream_json", "codex_exec_json", "pi_json"}


def assert_every_event_names_its_source(events: list[dict]) -> set[str]:
    """Every event says where it came from, and says it with a name from the vocabulary.

    An absent source is the failure this exists for: a reader cannot tell a record the engine
    reported from one this driver inferred by standing outside it, and the two do not support
    the same claims. Returns the set found, so a caller can also say which ones a path produces.
    """
    assert events, "no events to check"
    found = set()
    for event in events:
        source = event["metadata"].get("source")
        assert isinstance(source, str) and source, f"{event['type']} names no source: {event['metadata']}"
        assert source in EVENT_SOURCES, f"{event['type']} names {source!r}, which is not in the vocabulary"
        found.add(source)
    return found


def _hooked_bundle(tmp_path, *, run_id: str, trace_mode: str = "content"):
    """One real engine run against the securevibes-agent checkout, or a skip.

    Two skips, not one. The checkout may be missing, and the checkout that is there may predate
    the harness observation hooks: this package is about what the driver does when they exist,
    and asserting that against a build without them would be asserting the fallback twice.
    """
    root = SECUREVIBES
    if not (root / "node_modules" / ".bin" / "tsx").exists():
        pytest.skip("securevibes-agent checkout not available")
    adapter = get_adapter("llm-harness")
    spec = SystemSpec("sv-hooks", "llm-harness", {
        "harness": "securevibes-agent", "root": str(root), "model": "test/mock-llm", "runner": "mock",
        "qmd_profile": "lite", "llm_max_files": 5, "llm_timeout_ms": 20000, "flush_timeout_ms": 5000,
    })
    preparation = adapter.prepare(spec, tmp_path / "cache")
    bundle = run_invocation(prepared=_prepared(tmp_path), adapter=adapter, spec=spec, preparation=preparation,
                            out_dir=tmp_path / "out", run_id=run_id, timeout_seconds=600, trace_mode=trace_mode,
                            network_policy="none", clock=CLOCK)
    output = json.loads((bundle / "raw" / "driver-output.json").read_text(encoding="utf-8"))
    hooks = output.get("hooks")
    if hooks is None:
        # The driver never got as far as reporting its capabilities. That is a broken checkout,
        # which test_mock_runner_engine_run_produces_observed_bundle fails on rather than skips;
        # here it would only produce an assertion about a run that did not happen.
        pytest.skip(f"the securevibes-agent checkout did not complete a driver run: {output.get('error')}")
    if not (hooks["runner"] and hooks["engine"]):
        pytest.skip(f"this securevibes-agent checkout exports {hooks}, not both observation hooks")
    events = [json.loads(line) for line in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    return bundle, output, events


def test_the_runner_hooks_make_every_cli_attempt_a_paired_request_and_response(tmp_path):
    """Attempts are events now, each one joined to the call it belongs to.

    Before the hooks the driver saw one call and emitted one pair for it, whatever the harness
    did underneath, and said so with ``retries_observable: false``. The runner reports each
    attempt from inside its own retry loop now, so the pair is per attempt and carries the
    attempt number, the maximum and the decision the runner made. ``attempt_id`` is checked
    against its own ``call_id`` here rather than merely being present, because an attempt id
    that did not name the call it came from would pair two different calls' attempts.
    """
    bundle, output, events = _hooked_bundle(tmp_path, run_id="run-hooked-attempts")
    requests = [event for event in events if event["type"] == "model.request"]
    responses = [event for event in events if event["type"] == "model.response"]

    assert output["driver_version"] == "2.3.0"
    assert output["hooks"] == {"runner": 1, "engine": 1}
    assert len(requests) == output["model_attempts"] >= output["model_calls"] >= 1
    for event in requests + responses:
        assert event["metadata"]["source"] == "harness_runner_hook"
        assert "attempt_id" in event, "a hooked attempt must say which attempt it was"
        assert event["attempt_id"] == f"{event['call_id']}/attempt-{event['metadata']['attempt']}"
    assert all(event["metadata"]["retries_observable"] is True for event in requests)
    assert all(event["metadata"]["route"] == "mock" for event in requests)
    assert all(event["metadata"]["max_attempts"] >= event["metadata"]["attempt"] >= 1 for event in requests)
    # Every request has its response and every response its request, by the pair of ids.
    assert ({(e["call_id"], e["attempt_id"]) for e in requests}
            == {(e["call_id"], e["attempt_id"]) for e in responses})
    for event in requests:
        prompt = event["content"]["args"][-1]
        assert len(prompt) == event["metadata"]["prompt_chars"] > 0


def test_a_context_selection_event_names_the_spans_and_the_invocation_they_were_sent_to(tmp_path):
    """The engine's own report of what it put in a prompt, joined to the call that carried it.

    The progress-note self-reports this replaces named a file and nothing else. These name the
    exact text: a path, the line range, the character count, the sha256 of what was supplied,
    and ``location_known``, which is false when the lines are 1..N of the supplied text rather
    than positions in the file. The shared ``call_id`` is the point of the whole exercise, so it
    is checked against the model events rather than assumed, and the self-reports are asserted
    absent: two events about one selection would be counted twice by anything reading them.
    """
    bundle, output, events = _hooked_bundle(tmp_path, run_id="run-hooked-context")
    selections = [event for event in events if event["type"] == "context.selection"]
    request_calls = {event["call_id"] for event in events if event["type"] == "model.request"}

    assert selections, "the engine reported no context for any invocation"
    assert output["observer_records"]["context_selection"] == len(selections)
    for event in selections:
        assert event["metadata"]["source"] == "harness_emitted"
        assert event["capture_status"] == "complete"
        assert event["call_id"] in request_calls, "a context event must name a call the model events name"
        spans = event["metadata"]["spans"]
        assert spans and len(spans) == event["metadata"]["span_count"]
        assert event["metadata"]["truncated_spans"] == sum(1 for span in spans if span["truncated"])
        for span in spans:
            assert {"path", "start_line", "end_line", "sha256", "location_known"} <= set(span)
            assert span["end_line"] >= span["start_line"] >= 1
            assert len(span["sha256"]) == 64 and isinstance(span["location_known"], bool)
            assert not span["path"].startswith("/") and "\\" not in span["path"]
    assert output["progress_notes"] > 0, "the harness still reports progress; it is just not the source here"
    assert not [event for event in events if event["metadata"].get("source") == "harness_self_report"]


def test_a_submitted_finding_names_the_candidates_it_came_from(tmp_path):
    """The link the engine hooks exist for: a written finding back to the model's own claims.

    ``candidate_id`` and ``claim_id`` on a submitted event are still the harness's finding id,
    so the importer's claim linkage is unchanged; what is new is ``candidate_ids``, which names
    the candidates that became it. Every id named must be one the run actually emitted a
    candidate event for, or the trace would link a claim to nothing.
    """
    bundle, output, events = _hooked_bundle(tmp_path, run_id="run-hooked-linkage")
    result = load_document(bundle / "result.json", "scan-result")
    candidates = {event["candidate_id"] for event in events if event["type"] == "finding.candidate"}
    submitted = [event for event in events if event["type"] == "finding.submitted"]

    assert candidates and submitted
    assert {event["claim_id"] for event in submitted} == {claim["claim_id"] for claim in result["claims"]}
    for event in submitted:
        assert event["candidate_id"] == event["claim_id"]
        assert event["metadata"]["source"] == "harness_emitted"
        assert event["metadata"]["disposition"] in ("new", "updated")
        assert set(event["metadata"]["candidate_ids"]) <= candidates
    assert [event for event in submitted if event["metadata"]["candidate_ids"]], \
        "no submitted finding named a candidate; the linkage would be empty in every run"
    for event in (event for event in events if event["type"] == "finding.filtered"):
        assert event["candidate_id"] in candidates
        assert event["metadata"]["reason"]


def test_a_hooked_run_reports_what_it_could_not_see_and_claims_no_usage_it_did_not_get(tmp_path):
    """The capability-dependent declarations, on a route that reports no tokens at all.

    Retries and token usage left ``trace.unavailable`` because the runner hooks report both, and
    the two finding categories left it because the engine reports them. What did not leave is
    tool dispatch, and what replaced the token-usage line is the narrower claim about the pi
    route. The mock runner calls no model, so this run must claim no usage anywhere: absent
    counts are not zero counts, and ``usage_available: false`` is what says so per event.
    """
    bundle, output, events = _hooked_bundle(tmp_path, run_id="run-hooked-declares")
    execution = load_document(bundle / "execution.json", "execution-record")
    result = load_document(bundle / "result.json", "scan-result")
    unavailable = output["trace"]["unavailable"]

    assert "tool.start" in unavailable and "tool.end" in unavailable
    assert "finding.candidate" not in unavailable and "finding.filtered" not in unavailable
    assert "token usage" not in unavailable and "model retries inside the harness runner" not in unavailable
    assert not any("retries" in entry for entry in unavailable), unavailable
    assert "token usage on the pi route" in unavailable
    assert any(entry.startswith("finding.validation") and "not applicable" in entry for entry in unavailable)
    # The planner's own model call is untagged, so this run has a counted gap in context, and
    # the entry states the count rather than describing the split in prose that would go stale.
    assert output["model_calls_without_context"] >= 1
    assert output["model_calls_with_context"] + output["model_calls_without_context"] == output["model_calls"]
    assert output["context_without_model_call"] == 0
    assert any("untagged" in entry and str(output["model_calls_without_context"]) in entry
               for entry in unavailable)

    assert output["usage_totals"] is None and output["cost_usd_cli_reported_total"] is None
    assert output["models_served"] == []
    assert output["observer_hook_failures"] == 0
    assert all(event["metadata"]["usage_available"] is False
               for event in events if event["type"] == "model.response")
    assert result["usage"]["cost_usd"] is None
    assert "input_tokens" not in result["usage"] and "output_tokens" not in result["usage"]
    assert execution["capture"] == {
        "model_requests": "partial", "model_responses": "partial",
        "tool_calls": "not_applicable", "context_selection": "partial",
        "finding_submitted": "complete", "finding_candidate": "complete",
        "finding_validation": "not_applicable", "finding_filtered": "complete",
    }
    assert any("per CLI attempt" in note for note in execution["notes"])
    assert any("uninstrumented one" in note and "model invocation(s)" in note for note in execution["notes"])
    assert output["runner_hook_failures"] == 0, "the driver's own attempt hooks must not be failing"


def test_every_event_a_hooked_run_emits_names_where_it_came_from(tmp_path):
    """Provenance on every event, not only the ones that were interesting to write.

    A reader deciding what an event supports needs to know which boundary saw it, and the two
    hooked boundaries support different claims: the runner hook saw a CLI attempt, the engine
    reported its own decision. An event with no source is one a reader has to guess about.
    """
    bundle, output, events = _hooked_bundle(tmp_path, run_id="run-hooked-sources")

    found = assert_every_event_names_its_source(events)
    assert found == {"harness_runner_hook", "harness_emitted"}, found


def test_every_event_a_run_without_hooks_emits_names_where_it_came_from(tmp_path):
    """The same rule on the older path, where the sources are weaker and must say so.

    Nothing inside the harness reported any of these: the model events are what this driver saw
    by wrapping the runner from outside, the context events are the harness describing its own
    progress, and the submitted events are read off the summary it returned. Each of those is a
    different kind of evidence from the hooked equivalent, which is the whole reason the field
    is mandatory.
    """
    root = _stub_harness(tmp_path, "harness-no-hooks", engine=NO_HOOKS_ENGINE, runner=NO_HOOKS_RUNNER)
    bundle = _stub_harness_bundle(tmp_path, root, run_id="run-no-hooks-sources", runner="mock")
    events = [json.loads(line) for line in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8").splitlines()]

    found = assert_every_event_names_its_source(events)
    assert found == {"driver_runner_wrapper", "harness_self_report", "harness_summary"}, found
    model = [event for event in events if event["type"].startswith("model.")]
    assert model and all(event["metadata"]["source"] == "driver_runner_wrapper" for event in model)
    submitted = [event for event in events if event["type"] == "finding.submitted"]
    assert submitted and all(event["metadata"]["source"] == "harness_summary" for event in submitted)


@pytest.mark.parametrize(
    ("state", "expected"),
    [({"capture_gap": False, "dropped_events": 0}, "complete"),
     ({"capture_gap": True, "dropped_events": 0}, "partial"),
     ({"capture_gap": False, "dropped_events": 3}, "partial"),
     (None, "partial")],
    ids=["gapless", "gap", "dropped", "no-state"],
)
def test_the_engine_hooks_move_only_the_categories_they_actually_observe(state, expected):
    """What a harness build changes in the matrix, and what it does not.

    Candidates and filters become observable and follow the same capture state the submitted
    category does. Validation becomes ``not_applicable``, which is a statement about a bootstrap
    scan having no validation stage rather than about the observer. Model events and context
    selection do not move at all: an attempt is a CLI invocation and not an API request, and not
    every model invocation is instrumented, so neither category is complete for a run.

    Every call here reports zero hook failures, which is what the capture state alone cannot
    establish; the next test is about what happens when it does not.
    """
    hooked = capture_status("content", ["claude"], has_summary=True, capture_state=state,
                            hooks={"runner": 1, "engine": 1}, hook_failures=0)

    assert hooked["finding_candidate"] == hooked["finding_filtered"] == expected
    assert hooked["finding_validation"] == "not_applicable"
    assert hooked["model_requests"] == hooked["model_responses"] == "partial"
    assert hooked["context_selection"] == "partial"
    # Runner hooks alone move nothing here, and neither does a shape this cannot read.
    for hooks in ({"runner": 1, "engine": None}, None, {}, "1"):
        without = capture_status("content", ["claude"], has_summary=True, capture_state=state,
                                 hooks=hooks, hook_failures=0)
        assert without["finding_candidate"] == "unavailable", hooks
        assert without["finding_filtered"] == "unavailable", hooks
        assert without["finding_validation"] == "unavailable", hooks
    # An untraced run observed nothing, whatever the harness exported.
    off = capture_status("off", ["claude"], has_summary=True, capture_state=state,
                         hooks={"runner": 1, "engine": 1}, hook_failures=0)
    assert off["finding_candidate"] == off["finding_filtered"] == "unavailable"


@pytest.mark.parametrize("count", [1, 7, None, "0", True], ids=["one", "seven", "none", "text", "bool"])
def test_a_hook_failure_count_that_is_not_a_zero_downgrades_what_the_hooks_feed(count):
    """A record lost before the emitter saw it leaves no mark on the observer's capture state.

    The engine calls its hooks and swallows what they raise, so a hook that failed never reached
    the emitter: nothing was dropped on the way to a sink, the capture gap is false and the drop
    count is zero, and a matrix reading only those would call the capture complete while an
    unknown number of candidates, filters and submissions were missing from it. Only a count the
    run reported as a real zero rules that out. A nonzero count, an absent one and a value in a
    shape this cannot read are all the same answer: partial.

    The categories the hooks do not feed do not move. Model events were already partial, context
    selection was already partial, and validation is still inapplicable to a bootstrap scan.
    """
    gapless = {"capture_gap": False, "dropped_events": 0}
    hooked = {"runner": 1, "engine": 1}
    capture = capture_status("content", ["claude"], has_summary=True, capture_state=gapless,
                             hooks=hooked, hook_failures=count)

    assert capture["finding_candidate"] == "partial"
    assert capture["finding_filtered"] == "partial"
    assert capture["finding_submitted"] == "partial"
    assert capture["finding_validation"] == "not_applicable"
    assert capture["model_requests"] == capture["model_responses"] == "partial"
    assert capture["context_selection"] == "partial"
    # A clean count is the only thing that gets the stronger answer back.
    clean = capture_status("content", ["claude"], has_summary=True, capture_state=gapless,
                           hooks=hooked, hook_failures=0)
    assert clean["finding_candidate"] == clean["finding_filtered"] == clean["finding_submitted"] == "complete"
    # Without the engine hooks there is nothing for a hook failure to have lost: the submitted
    # category comes off the summary, so an unknown engine count must not weaken it.
    unhooked = capture_status("content", ["claude"], has_summary=True, capture_state=gapless,
                              hooks=None, hook_failures=count)
    assert unhooked["finding_submitted"] == "complete"
    assert unhooked["finding_candidate"] == "unavailable"


STUB_RECORD = FINDING.replace("./src/routes/admin.ts", "src/server.js")

# A harness build from before either observation surface existed: ordinary modules, and only the
# two exported version constants missing. The driver imports these for real, so what the
# fallback test exercises is the branch an older checkout takes, not a simulation of it.
NO_HOOKS_RUNNER = """
// No PI_RUNNER_HOOKS_VERSION: this build's runner reports no attempts.
export function resolveRunnerBinary(): string { return "pi"; }
export function createDefaultPiRunner() {
  return { async runPi() { return { code: 0, stdout: "", stderr: "" }; } };
}
"""
NO_HOOKS_MOCK = """
export function createDeterministicTestLlmRunner() {
  return { async runPi() { return { code: 0, stdout: "stub model output", stderr: "" }; } };
}
"""
NO_HOOKS_ENGINE = """
// No HARNESS_OBSERVER_VERSION either, and runRuntimeScan accepts no observer.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const RECORD = __RECORD__;
export async function runRuntimeScan(options: any): Promise<any> {
  options.progressReporter("stub scan file=src/server.js");
  await options.llmRunner.runPi({
    args: ["-p", "--no-session", "--model", options.llmModel, "--thinking", "high", "stub prompt"],
    cwd: options.repoPath, timeoutMs: 1000, env: {},
  });
  const findings = join(options.repoPath, ".securevibes", "findings");
  mkdirSync(findings, { recursive: true });
  writeFileSync(join(findings, "SV-AUTH-AUTHBYPASS-001.md"), RECORD);
  return {
    newFindings: [{ id: "SV-AUTH-AUTHBYPASS-001", filePath: "src/server.js", vulnerabilityClass: "authbypass",
                    severity: "high", status: "new", component: "AUTH", confidence: 0.812,
                    scannerSources: ["llm-hypothesis"] }],
    updatedFindings: [],
    bootstrapScan: { llmCalls: 1, failedCalls: 0, status: "ok", hypothesisCoverage: 1 },
    runtimeProfile: "full", degraded: false,
  };
}
""".replace("__RECORD__", json.dumps(STUB_RECORD))

# A harness build that exports both surfaces, with a runner that fabricates its attempt records
# rather than spawning a CLI. The real mock engine cannot produce a retry, a token count, a cost
# estimate or a call whose backoff was aborted, and each of those is a branch of the driver that
# would otherwise be reasoned about instead of run.
HOOKED_RUNNER = """
export const PI_RUNNER_HOOKS_VERSION = 1;
export function resolveRunnerBinary(): string { return "claude"; }

const STRUCTURED = {
  subtype: "success", isError: false, numTurns: 2, sessionId: "session-stub",
  durationMs: 12, durationApiMs: 9, totalCostUsd: 0.0123,
  usage: { input_tokens: 120, output_tokens: 34, cache_read_input_tokens: 7, cache_creation_input_tokens: 0 },
  modelUsage: { "claude-haiku-4-5": { inputTokens: 120 } },
  permissionDenials: [], stopReason: null,
};
// A result object the CLI printed for a call that went wrong: it exists, and it reports no
// usage and no served model. Its cost is smaller than the plain-decimal window both emitters
// share, which the driver must keep verbatim rather than round to zero.
const ERROR_STRUCTURED = {
  subtype: "error_during_execution", isError: true, numTurns: 1, sessionId: "session-error",
  durationMs: 4, durationApiMs: 3, totalCostUsd: 0.00002,
  usage: null, modelUsage: {}, permissionDenials: [], stopReason: null,
};

export function createDefaultPiRunner(options: any) {
  const hooks = options.hooks;
  let call = 0;
  return {
    async runPi(invocation: any) {
      call += 1;
      const prompt = String(invocation.args[invocation.args.length - 1]);
      // The argv carries the prompt, so a message built from it carries the source. Both throws
      // below are shaped like execCommand's, which is what the driver has to cut back.
      const argvBearing = "Command aborted: claude --model claude-haiku-4-5 " + prompt;
      const start = {
        invocationId: invocation.meta?.invocationId,
        stage: invocation.meta?.stage,
        attempt: 1, maxAttempts: 2, binary: "claude", modelRequested: "claude-haiku-4-5", thinking: "high",
        outputFormat: options.claudeOutputFormat ?? "text",
        promptChars: prompt.length, timeoutMs: invocation.timeoutMs, startedAt: new Date().toISOString(),
      };
      hooks.onAttemptStart(start);
      if (call === 2) {
        // What the harness runner does when a retry backoff is aborted: one end record per
        // attempt, saying it will not retry after all, with its own argv-free reason.
        hooks.onAttemptEnd({ ...start, durationMs: 5, code: 1, stdoutChars: 0, stderrChars: 18,
          failureKind: "transient", willRetry: false, error: "aborted during retry backoff",
          structured: ERROR_STRUCTURED });
        throw new Error(argvBearing);
      }
      if (call === 3) {
        // A runner whose last word on a call was "I will retry" and that then ended it. No
        // build here does that today; the driver still must not pair a response into an
        // attempt nobody reported the end of.
        hooks.onAttemptEnd({ ...start, durationMs: 5, code: 1, stdoutChars: 0, stderrChars: 18,
          failureKind: "transient", willRetry: true, retryDelayMs: 500, structured: null });
        throw new Error(argvBearing);
      }
      hooks.onAttemptEnd({ ...start, durationMs: 5, code: 1, stdoutChars: 0, stderrChars: 18,
        failureKind: "transient", willRetry: true, retryDelayMs: 500, structured: null,
        structuredParseError: "claude json stdout did not parse as JSON" });
      hooks.onAttemptStart({ ...start, attempt: 2 });
      hooks.onAttemptEnd({ ...start, attempt: 2, durationMs: 7, code: 0, stdoutChars: 15, stderrChars: 0,
        willRetry: false, structured: STRUCTURED });
      return { code: 0, stdout: "{\\"findings\\":[]}", stderr: "", binary: "claude", outputFormat: "json",
               structured: STRUCTURED };
    },
  };
}
"""
HOOKED_ENGINE = """
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
export const HARNESS_OBSERVER_VERSION = 1;
const RECORD = __RECORD__;
const ARGS = (prompt: string) =>
  ["-p", "--no-session", "--model", "claude-haiku-4-5", "--thinking", "high", prompt];

export async function runRuntimeScan(options: any): Promise<any> {
  const observer = options.observer;
  observer.onContextSupplied({
    invocationId: "llm-bootstrap.hypothesis-1", stage: "llm-bootstrap.hypothesis", hypothesisId: "TM-001",
    model: options.llmModel, promptChars: 40,
    spans: [
      { path: "src/server.js", startLine: 1, endLine: 6, chars: 274, sha256: "a".repeat(64),
        truncated: false, originalChars: 274, role: "primary" },
      { path: "src/server.js", startLine: 1, endLine: 2, chars: 40, sha256: "b".repeat(64),
        truncated: true, role: "fragment", locationKnown: false },
    ],
    truncatedSpans: 1, omittedPaths: ["README.md"],
  });
  await options.llmRunner.runPi({ args: ARGS("hypothesis prompt"), cwd: options.repoPath, timeoutMs: 1000,
    env: {}, meta: { invocationId: "llm-bootstrap.hypothesis-1", stage: "llm-bootstrap.hypothesis" } });
  for (const id of ["llm-static.file-1", "llm-static.file-2"]) {
    try {
      await options.llmRunner.runPi({ args: ARGS("file prompt"), cwd: options.repoPath, timeoutMs: 1000,
        env: {}, meta: { invocationId: id, stage: "llm-static.file" } });
    } catch {
      // The scan survives an aborted call; the driver still has to report what it saw of it.
    }
  }
  observer.onFindingCandidate({ candidateId: "cand-1", invocationId: "llm-bootstrap.hypothesis-1",
    stage: "llm-bootstrap", filePath: "src/server.js", lineNumbers: [4], vulnerabilityClass: "authbypass",
    severity: "high", confidence: 0.812 });
  observer.onFindingCandidate({ candidateId: "cand-2", invocationId: "llm-bootstrap.hypothesis-1",
    stage: "llm-bootstrap", filePath: "src/server.js", vulnerabilityClass: "authbypass", severity: "medium" });
  observer.onFindingFiltered({ candidateId: "cand-2", stage: "llm-bootstrap",
    reason: "duplicate_scanner_finding", mergedIntoCandidateId: "cand-1" });
  const findings = join(options.repoPath, ".securevibes", "findings");
  mkdirSync(findings, { recursive: true });
  writeFileSync(join(findings, "SV-AUTH-AUTHBYPASS-001.md"), RECORD);
  observer.onFindingSubmitted({ candidateIds: ["cand-1", "cand-2"], findingId: "SV-AUTH-AUTHBYPASS-001",
    filePath: "src/server.js", vulnerabilityClass: "authbypass", severity: "high", status: "new",
    disposition: "new" });
  // Reported after the summary was built, so it is a second, later reading of the same counter.
  observer.onScanComplete?.({ hookFailures: 0, unattributablePayloads: 2 });
  return {
    newFindings: [{ id: "SV-AUTH-AUTHBYPASS-001", filePath: "src/server.js", vulnerabilityClass: "authbypass",
                    severity: "high", status: "new", component: "AUTH", confidence: 0.812,
                    scannerSources: ["llm-hypothesis"] }],
    updatedFindings: [],
    bootstrapScan: { llmCalls: 3, failedCalls: 2, status: "ok", hypothesisCoverage: 1 },
    runtimeProfile: "full", degraded: false,
    observer: { version: 1, hookFailures: 0 },
  };
}
""".replace("__RECORD__", json.dumps(STUB_RECORD))


def _tsx_root() -> Path:
    """A checkout to borrow tsx and node_modules from, or a skip.

    Which harness it is does not matter: these builds are written here and only need a node with
    TypeScript loading in front of them.
    """
    root = next((candidate for candidate in (SECUREVIBES, FIELDGLASS)
                 if (candidate / "node_modules" / ".bin" / "tsx").exists()), None)
    if root is None:
        pytest.skip("no harness checkout with node_modules to borrow tsx from")
    return root


def _stub_harness(tmp_path: Path, name: str, *, engine: str, runner: str,
                  mock: str = NO_HOOKS_MOCK) -> Path:
    """A harness root the real driver imports, with the three entry modules given.

    Only the exports differ between the builds these tests drive, so the scaffolding is one
    function: the preset's entry paths, a package.json, and node_modules borrowed by link,
    because what is under test is what a harness exports rather than which tsx compiles it.
    """
    root = tmp_path / name
    (root / "src" / "runtime").mkdir(parents=True)
    (root / "src" / "testing").mkdir(parents=True)
    (root / "node_modules").symlink_to(_tsx_root() / "node_modules", target_is_directory=True)
    (root / "package.json").write_text(json.dumps({"name": name, "version": "0.0.0-stub"}) + "\n", encoding="utf-8")
    (root / "src" / "runtime" / "engine.ts").write_text(engine, encoding="utf-8")
    (root / "src" / "runtime" / "pi-runner.ts").write_text(runner, encoding="utf-8")
    (root / "src" / "testing" / "mock-llm-runner.ts").write_text(mock, encoding="utf-8")
    return root


def _stub_harness_bundle(tmp_path: Path, root: Path, *, run_id: str, runner: str) -> Path:
    adapter = get_adapter("llm-harness")
    spec = SystemSpec(f"stub-{runner}", "llm-harness", {"harness": "securevibes-agent", "root": str(root),
                                                        "model": "test/mock-llm", "runner": runner})
    preparation = adapter.prepare(spec, tmp_path / "cache")
    return run_invocation(prepared=_prepared(tmp_path), adapter=adapter, spec=spec, preparation=preparation,
                          out_dir=tmp_path / "out", run_id=run_id, timeout_seconds=600,
                          trace_mode="content", network_policy="none", clock=CLOCK)


def test_a_harness_that_exports_no_hooks_is_observed_the_way_it_was_before_them(tmp_path):
    """The fallback, driven by the real driver against a harness that exports neither surface.

    Every capability this package added is optional, and an older harness checkout must produce
    exactly what it produced before: one request and one response per logical call with no
    attempt id and ``retries_observable: false``, context read off the progress notes and marked
    as the harness's self-report, no candidate or filter events, submitted events read off the
    returned summary, and the fixed ``trace.unavailable`` list that names all of it.
    """
    root = _stub_harness(tmp_path, "harness-no-hooks", engine=NO_HOOKS_ENGINE, runner=NO_HOOKS_RUNNER)
    bundle = _stub_harness_bundle(tmp_path, root, run_id="run-no-hooks", runner="mock")
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    output = json.loads((bundle / "raw" / "driver-output.json").read_text(encoding="utf-8"))
    events = [json.loads(line) for line in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8").splitlines()]

    assert output["hooks"] == {"runner": None, "engine": None}
    assert output["model_calls"] == 1 and output["model_attempts"] == 0
    assert output["usage_totals"] is None and output["cost_usd_cli_reported_total"] is None
    assert output["models_served"] == [] and output["observer_hook_failures"] is None
    requests = [event for event in events if event["type"] == "model.request"]
    assert len(requests) == 1 and requests[0]["metadata"]["retries_observable"] is False
    assert all("attempt_id" not in event for event in events)
    selections = [event for event in events if event["type"] == "context.selection"]
    assert [event["metadata"]["source"] for event in selections] == ["harness_self_report"]
    assert all(event["capture_status"] == "partial" for event in selections)
    assert not [event for event in events if event["type"] in ("finding.candidate", "finding.filtered")]
    submitted = [event for event in events if event["type"] == "finding.submitted"]
    assert [event["claim_id"] for event in submitted] == ["SV-AUTH-AUTHBYPASS-001"]
    assert submitted[0]["metadata"]["stage"] == "new"
    assert output["trace"]["unavailable"] == [
        "tool.start", "tool.end", "finding.candidate", "finding.validation", "finding.filtered",
        "model retries inside the harness runner", "token usage"]
    assert execution["capture"] == {
        "model_requests": "partial", "model_responses": "partial",
        "tool_calls": "not_applicable", "context_selection": "partial",
        "finding_submitted": "complete", "finding_candidate": "unavailable",
        "finding_validation": "unavailable", "finding_filtered": "unavailable",
    }
    assert any("not observable at this boundary" in note for note in execution["notes"])
    assert [claim["claim_id"] for claim in result["claims"]] == ["SV-AUTH-AUTHBYPASS-001"]
    assert result["status"] == "success", execution["error"]


def test_a_retried_call_records_each_attempt_and_the_usage_the_cli_reported(tmp_path):
    """The branches a deterministic mock engine cannot reach: a retry, and what json adds.

    The first call fails once and succeeds on its second attempt, so the trace must hold two
    request/response pairs for one logical call, the first saying it would retry and carrying no
    content because a retried attempt's stdout is not handed back. The successful attempt carries
    what the claude json result object reports: the four token counts, the CLI's cost estimate,
    the session id, the turn count and the served model, summed into the driver's own totals.
    """
    root = _stub_harness(tmp_path, "harness-hooked", engine=HOOKED_ENGINE, runner=HOOKED_RUNNER)
    bundle = _stub_harness_bundle(tmp_path, root, run_id="run-hooked-stub", runner="default")
    output = json.loads((bundle / "raw" / "driver-output.json").read_text(encoding="utf-8"))
    events = [json.loads(line) for line in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    requests = [event for event in events if event["type"] == "model.request"]
    responses = [event for event in events if event["type"] == "model.response"]

    assert output["hooks"] == {"runner": 1, "engine": 1}
    assert output["model_calls"] == 3 and output["model_attempts"] == 4
    assert output["model_call_failures"] == 2 and output["observed_routes"] == ["claude"]
    retried = [event for event in requests if event["call_id"] == "llm-bootstrap.hypothesis-1"]
    assert [event["attempt_id"] for event in retried] == ["llm-bootstrap.hypothesis-1/attempt-1",
                                                          "llm-bootstrap.hypothesis-1/attempt-2"]
    assert all(event["metadata"]["output_format"] == "json" for event in retried)
    first, final = [event for event in responses if event["call_id"] == "llm-bootstrap.hypothesis-1"]
    # Each attempt's own duration, as the runner measured it. The wrapper's elapsed time spans
    # both attempts and the backoff between them, so it is a different number kept beside it.
    assert first["duration_ms"] == 5 and final["duration_ms"] == 7
    assert isinstance(final["metadata"]["call_elapsed_ms"], int)
    assert final["metadata"]["call_elapsed_ms"] >= 0
    assert first["metadata"]["will_retry"] is True and first["metadata"]["retry_delay_ms"] == 500
    assert first["metadata"]["failure_kind"] == "transient" and first["metadata"]["exit_code"] == 1
    assert first["metadata"]["structured_parse_error"] == "claude json stdout did not parse as JSON"
    assert first["capture_status"] == "partial" and "content" not in first
    assert final["metadata"]["will_retry"] is False and final["metadata"]["attempt_record"] == "paired"
    assert final["capture_status"] == "complete"
    assert final["metadata"]["usage_available"] is True
    assert final["metadata"]["usage"] == {"input_tokens": 120, "output_tokens": 34,
                                          "cache_read_input_tokens": 7, "cache_creation_input_tokens": 0}
    assert final["metadata"]["cost_usd_cli_reported"] == pytest.approx(0.0123)
    assert final["metadata"]["model_served"] == "claude-haiku-4-5"
    assert final["metadata"]["session_id"] == "session-stub" and final["metadata"]["num_turns"] == 2
    assert final["content"]["stdout"] == '{"findings":[]}'

    # One attempt of the four reported usage, and only that one is summed. Both attempts that
    # reported a cost are, including the one whose cost is too small for an event to carry.
    assert output["usage_totals"] == {"input_tokens": 120, "output_tokens": 34,
                                      "cache_read_input_tokens": 7, "cache_creation_input_tokens": 0}
    assert output["cost_usd_cli_reported_total"] == pytest.approx(0.01232)
    assert output["models_served"] == ["claude-haiku-4-5"]
    # Two readings of the observer's own health, kept apart: the snapshot the summary carries
    # and the engine's later closing one, which also names what it could not attribute.
    assert output["observer_hook_failures"] == 0
    assert output["observer_scan_complete"] == {"hook_failures": 0, "unattributable_payloads": 2}
    # This build's runner keeps no hook-failure counter, and a counter nobody keeps is null
    # rather than a reported zero.
    assert output["runner_hook_failures"] is None
    assert output["finding_submitted_source"] == "engine_records"
    result = load_document(bundle / "result.json", "scan-result")
    assert result["usage"]["input_tokens"] == 120 and result["usage"]["output_tokens"] == 34
    assert result["usage"]["cost_usd"] == pytest.approx(0.01232), "the record carries the run's whole estimate"
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["model_identity"]["resolved"] == "claude-haiku-4-5"
    assert execution["model_identity"]["verification"] == "self_reported"


def test_a_call_that_ended_in_a_throw_reports_the_attempt_the_runner_did_describe(tmp_path):
    """An aborted retry backoff: one end record per attempt, and the runner's own reason for it.

    The runner reports the attempt as one that will not retry after all and names why in a
    message it built without the argv. The driver pairs that record, so the event names the
    attempt, but it stays ``partial``: the call threw, so the text the attempt produced never
    came back, and the record says there was some. The thrown message carries the argv, which
    carries the prompt, so the runner's message is preferred over it and the fallback is cut
    back to the part that carries neither.
    """
    root = _stub_harness(tmp_path, "harness-hooked", engine=HOOKED_ENGINE, runner=HOOKED_RUNNER)
    bundle = _stub_harness_bundle(tmp_path, root, run_id="run-threw", runner="default")
    events = [json.loads(line) for line in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    threw = [event for event in events
             if event["type"] == "model.response" and event["call_id"] == "llm-static.file-1"]

    assert len(threw) == 1, "one attempt was reported, and it is the one the call ended on"
    assert threw[0]["attempt_id"] == "llm-static.file-1/attempt-1"
    assert threw[0]["metadata"]["attempt_record"] == "paired"
    assert threw[0]["metadata"]["will_retry"] is False
    assert threw[0]["metadata"]["exit_code"] == 1
    assert threw[0]["metadata"]["failure_kind"] == "transient"
    assert threw[0]["metadata"]["error"] == "aborted during retry backoff"
    assert threw[0]["capture_status"] == "partial", "the attempt's own output never came back"
    assert "content" not in threw[0]
    assert "file prompt" not in json.dumps(threw[0]), "metadata must never carry the prompt"
    assert threw[0]["duration_ms"] == 5, "the attempt's own duration, not the call's elapsed time"
    # The CLI printed a result object for this attempt and put no usage and no served model in
    # it. A result object is not a usage report, so the flag reads off the counts themselves.
    assert threw[0]["metadata"]["usage_available"] is False
    assert threw[0]["metadata"]["usage"] is None
    assert threw[0]["metadata"]["model_served"] is None
    assert threw[0]["metadata"]["result_subtype"] == "error_during_execution"
    assert threw[0]["metadata"]["is_error"] is True
    # 0.00002 is below the decimal window both emitters share, so the number field says the
    # trace cannot carry it and the CLI's own figure is kept verbatim beside it.
    assert threw[0]["metadata"]["cost_usd_cli_reported"] is None
    assert threw[0]["metadata"]["cost_usd_cli_reported_text"] == "0.00002"


def test_a_call_with_no_final_attempt_record_is_not_paired_into_an_attempt_it_never_had(tmp_path):
    """The defensive half: a runner whose last word on a call was that it would retry.

    No harness build does this today -- the runner emits exactly one end record per attempt, the
    aborted one included -- but the driver must not answer a missing record by inventing the
    attempt id it would have had, which is what pairing the call's outcome into the last
    attempt it saw would do. It names the call, says the record is missing, and is partial.
    """
    root = _stub_harness(tmp_path, "harness-hooked", engine=HOOKED_ENGINE, runner=HOOKED_RUNNER)
    bundle = _stub_harness_bundle(tmp_path, root, run_id="run-unpaired", runner="default")
    events = [json.loads(line) for line in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    unpaired = [event for event in events
                if event["type"] == "model.response" and event["call_id"] == "llm-static.file-2"]

    assert len(unpaired) == 2, "the attempt that ran is reported, and so is the call that ended"
    attempted, ended = unpaired
    assert attempted["attempt_id"] == "llm-static.file-2/attempt-1"
    assert attempted["metadata"]["will_retry"] is True
    assert "attempt_id" not in ended, "no attempt record, so no attempt id to name"
    assert ended["capture_status"] == "partial"
    assert ended["metadata"]["attempt_record"] == "missing"
    assert ended["metadata"]["exit_code"] is None
    assert ended["metadata"]["error"] == "Command aborted: claude"
    assert "file prompt" not in json.dumps(ended), "metadata must never carry the prompt"


def test_a_supplied_span_that_could_not_be_located_says_so_rather_than_naming_file_lines(tmp_path):
    """``location_known`` is the difference between a file position and a position in a prompt.

    A span the engine could not find in the original file is reported with lines 1..N of the text
    it supplied. Anything joining spans against source locations has to be able to tell the two
    apart, so the flag is carried on every span rather than only on the ones where it is false.
    """
    root = _stub_harness(tmp_path, "harness-hooked", engine=HOOKED_ENGINE, runner=HOOKED_RUNNER)
    bundle = _stub_harness_bundle(tmp_path, root, run_id="run-spans", runner="default")
    events = [json.loads(line) for line in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    selection = next(event for event in events if event["type"] == "context.selection")

    located, unlocated = selection["metadata"]["spans"]
    assert located["location_known"] is True and located["role"] == "primary"
    assert located["original_chars"] == 274 and located["truncated"] is False
    assert unlocated["location_known"] is False and unlocated["role"] == "fragment"
    assert unlocated["truncated"] is True and unlocated["original_chars"] is None
    assert selection["metadata"]["truncated_spans"] == 1
    assert selection["metadata"]["omitted_paths"] == ["README.md"]
    assert selection["metadata"]["hypothesis_id"] == "TM-001"
    assert selection["call_id"] == "llm-bootstrap.hypothesis-1"
    # The candidate the same invocation produced names the same call, which is the whole point
    # of the id being minted by the engine rather than by the driver.
    candidate = next(event for event in events if event["type"] == "finding.candidate")
    assert candidate["call_id"] == "llm-bootstrap.hypothesis-1"
    assert candidate["metadata"]["line_numbers"] == [4]
    assert candidate["metadata"]["confidence"] == pytest.approx(0.812)
    submitted = next(event for event in events if event["type"] == "finding.submitted")
    assert submitted["metadata"]["candidate_ids"] == ["cand-1", "cand-2"]
    assert submitted["metadata"]["component"] == "AUTH", "the summary's own fields survive the join"


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
                 plan_as_link: bool = False, output: dict | None = None,
                 block_plan_staging: bool = False, state_as_link: Path | None = None,
                 stage_as_link: Path | None = None, observed: dict | None = None,
                 output_as_pipe: bool = False) -> None:
    """Stand in for the tsx driver and leave exactly the records a harness run would leave.

    No process is spawned and no model is called: the stub reads the driver config the adapter
    wrote and writes the finding records, the plan, and the driver output itself.

    *state_as_link* makes the harness state directory a symbolic link to that path before it
    writes anything, so the records it writes land outside the workspace and are reached only
    through an ancestor. *stage_as_link* does the same to the directory the adapter stages
    imported records into. *output_as_pipe* leaves a named pipe where the driver output belongs,
    which nothing ever writes to. *observed* collects the argv and environment the driver was
    started with, for a test about what the process inherits.
    """

    def fake_run_command(argv, *, cwd, timeout_seconds, env, stdout_path, stderr_path, stdin_text=None):
        config = json.loads(Path(argv[-1]).read_text(encoding="utf-8"))
        if observed is not None:
            observed.update({"argv": list(argv), "env": dict(env), "config": config})
        state = Path(config["repo_path"]) / state_dir
        if state_as_link is not None:
            state_as_link.mkdir(parents=True, exist_ok=True)
            state.symlink_to(state_as_link, target_is_directory=True)
        if stage_as_link is not None:
            stage_as_link.mkdir(parents=True, exist_ok=True)
            (Path(config["output_path"]).parent / "harness-findings").symlink_to(
                stage_as_link, target_is_directory=True)
        (state / "findings").mkdir(parents=True, exist_ok=True)
        for name, text in records.items():
            (state / "findings" / name).write_text(text, encoding="utf-8")
        if plan_as_link:
            (state / "elsewhere.md").write_text("# plan\n", encoding="utf-8")
            (state / "bootstrap-plan.md").symlink_to(state / "elsewhere.md")
        else:
            (state / "bootstrap-plan.md").write_text("# plan\n", encoding="utf-8")
        if block_plan_staging:
            # A harness that wrote a regular file where the adapter stages its plan records.
            (Path(config["output_path"]).parent / "harness-plan").write_text("not a directory\n", encoding="utf-8")
        if config.get("trace_path"):
            trace_path = Path(config["trace_path"])
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            trace_path.write_text(
                '{"type":"model.request"}\n{"type":"model.response"}\n', encoding="utf-8")
        if output_as_pipe:
            os.mkfifo(Path(config["output_path"]))
        else:
            Path(config["output_path"]).write_text(json.dumps(output or DRIVER_OUTPUT), encoding="utf-8")
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text("the driver left no output\n" if output_as_pipe else "", encoding="utf-8")
        return CommandResult(list(argv), 0, False, 0.0, stdout_path, stderr_path)

    monkeypatch.setattr(llm_harness, "run_command", fake_run_command)


def _stubbed_bundle(tmp_path: Path, monkeypatch, records: dict[str, str], *, run_id: str = "run-stub",
                    root_config: str | None = None, plan_as_link: bool = False,
                    trace_mode: str = "off", output: dict | None = None,
                    block_plan_staging: bool = False, state_as_link: Path | None = None,
                    stage_as_link: Path | None = None, observed: dict | None = None,
                    output_as_pipe: bool = False, runner: str = "mock",
                    prepared: PreparedInput | None = None) -> Path:
    root = _fake_harness_root(tmp_path)
    sdk = tmp_path / "observer-sdk.js"
    sdk.write_text("// stub\n", encoding="utf-8")
    adapter = get_adapter("llm-harness")
    # ``runner`` is a parameter because the mock runner short-circuits model identity: a run that
    # calls no model cannot have a served one, so the branch that records what a CLI reported is
    # only reachable from a spec that asked for a real route.
    spec = SystemSpec("sv-stub", "llm-harness", {
        "harness": "securevibes-agent", "root": root_config or str(root), "model": "test/mock-llm",
        "runner": runner, "observer_sdk": str(sdk)})
    preparation = adapter.prepare(spec, tmp_path / "cache")
    _stub_driver(monkeypatch, records, plan_as_link=plan_as_link, output=output,
                 block_plan_staging=block_plan_staging, state_as_link=state_as_link,
                 stage_as_link=stage_as_link, observed=observed, output_as_pipe=output_as_pipe)
    return run_invocation(prepared=prepared or _prepared(tmp_path), adapter=adapter, spec=spec,
                          preparation=preparation, out_dir=tmp_path / "out", run_id=run_id, timeout_seconds=60,
                          trace_mode=trace_mode, network_policy="none", clock=CLOCK)


USAGE_OUTPUT = {**DRIVER_OUTPUT, "observed_routes": ["claude"], "hooks": {"runner": 1, "engine": 1},
                "usage_totals": {"input_tokens": 12000, "output_tokens": 800,
                                 "cache_read_input_tokens": 4096, "cache_creation_input_tokens": 0},
                "cost_usd_cli_reported_total": 0.0123, "models_served": ["claude-haiku-4-5"]}


def test_the_cli_s_own_usage_and_served_model_are_recorded_as_the_cli_s_own_report(tmp_path, monkeypatch):
    """What the claude json route adds to a run record, and how carefully it is labelled.

    The driver sums the tokens and the cost estimate the CLI printed per attempt and names the
    served model when the run named exactly one. All three are the CLI reporting on itself: the
    cost is an estimate and never a bill, an attempt that reported nothing contributes nothing,
    and ``self_reported`` is the execution record's existing word for a value the scanner stated
    about itself rather than one anything here verified.
    """
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, run_id="run-usage",
                             runner="default", output=USAGE_OUTPUT)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert result["usage"]["input_tokens"] == 12000 and result["usage"]["output_tokens"] == 800
    assert result["usage"]["cost_usd"] == pytest.approx(0.0123)
    # The cache counts are outside the record's usage vocabulary, so they are dropped rather
    # than folded into the two counts that are in it.
    assert "cache_read_input_tokens" not in result["usage"]
    assert execution["model_identity"]["resolved"] == "claude-haiku-4-5"
    assert execution["model_identity"]["verification"] == "self_reported"
    assert any("reporting on itself" in note for note in execution["model_identity"]["notes"])
    assert any("never a bill" in note and "floors" in note for note in execution["notes"])


def test_a_run_that_reported_no_usage_and_no_served_model_claims_neither(tmp_path, monkeypatch):
    """An absent count is not a measured zero, and an unreported model is not an unused one.

    The same fields are absent in three quite different runs: a harness with no runner hooks, a
    pi-route run that prints no usage, and a claude run whose attempts all failed before the
    result object. None of them is a run that spent nothing, so none of them records a zero.
    """
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, run_id="run-no-usage",
                             runner="default", output={**DRIVER_OUTPUT, "observed_routes": ["pi"],
                                                       "hooks": {"runner": 1, "engine": None}})
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert result["usage"]["cost_usd"] is None
    assert "input_tokens" not in result["usage"] and "output_tokens" not in result["usage"]
    assert execution["model_identity"]["resolved"] is None
    assert execution["model_identity"]["verification"] == "unverified"
    assert not any("never a bill" in note for note in execution["notes"])
    assert execution["capture"]["finding_candidate"] == "unavailable", "runner hooks alone observe no candidate"


def test_a_run_that_saw_more_than_one_served_model_resolves_none_of_them(tmp_path, monkeypatch):
    """Two served models is a fact about the run, not a choice between them.

    The result object names one model per attempt, so a run whose attempts disagree has no
    single served model; recording either would be recording a guess. Both are named in a note
    instead, and ``resolved`` stays null.
    """
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, run_id="run-two-models", runner="default",
                             output={**USAGE_OUTPUT, "models_served": ["claude-haiku-4-5", "claude-sonnet-4-5"]})
    execution = load_document(bundle / "execution.json", "execution-record")

    assert execution["model_identity"]["resolved"] is None
    assert execution["model_identity"]["verification"] == "unverified"
    assert any("claude-haiku-4-5, claude-sonnet-4-5" in note for note in execution["model_identity"]["notes"])


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


# --- provenance of the imported finding records ------------------------------------------


PLANTED = FINDING.replace("SV-AUTH-AUTHBYPASS-001", "SV-PLANTED-000")


def test_a_finding_record_the_input_already_shipped_is_not_imported_as_this_scan_s_finding(tmp_path):
    """Importing whatever the directory holds at the end credited the scan with planted records.

    The repository under test can ship a ``.securevibes/findings`` directory of its own. The
    baseline taken before the scan is what separates those records from the ones this run wrote.
    """
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "planted.md").write_text(PLANTED, encoding="utf-8")
    baseline = snapshot_findings(findings, _enclosure(tmp_path))
    (findings / "produced.md").write_text(FINDING, encoding="utf-8")

    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings",
                                       stage_dir=tmp_path / "raw" / "harness-findings",
                                       baseline=baseline, enclosure=_enclosure(tmp_path))

    assert [claim["claim_id"] for claim in imported.claims] == ["SV-AUTH-AUTHBYPASS-001"]
    assert [artifact["id"] for artifact in imported.artifacts] == ["harness-findings/produced.md"]
    assert imported.lost == 0, "a record the scan did not write is not a record the scan lost"
    assert any("already in the exported input before the scan" in note for note in imported.notes)
    assert not (tmp_path / "raw" / "harness-findings" / "planted.md").exists()


def test_a_record_the_scan_rewrote_is_imported_even_though_its_name_was_already_there(tmp_path):
    """Provenance is by bytes, not by name: new content under an old name is this scan's output."""
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "a.md").write_text(PLANTED, encoding="utf-8")
    baseline = snapshot_findings(findings, _enclosure(tmp_path))
    (findings / "a.md").write_text(FINDING, encoding="utf-8")

    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings",
                                       stage_dir=tmp_path / "raw" / "harness-findings",
                                       baseline=baseline, enclosure=_enclosure(tmp_path))

    assert [claim["claim_id"] for claim in imported.claims] == ["SV-AUTH-AUTHBYPASS-001"]
    assert imported.lost == 0


def test_a_findings_directory_that_cannot_be_listed_is_counted_and_noted(tmp_path):
    """An enumeration failure used to read as an empty directory: no claims, no loss, no note.

    ``Path.glob`` swallows the ``OSError`` the walk raises, so records the importer could not
    even see contradicted the loss contract. The count is a floor, since the number of records
    behind the failure is unknown.
    """
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    findings.chmod(0o000)
    try:
        imported = import_harness_findings(findings, harness="securevibes-agent",
                                           artifact_prefix="harness-findings",
                                           stage_dir=tmp_path / "raw" / "harness-findings",
                                           baseline=snapshot_findings(findings, _enclosure(tmp_path)),
                                           enclosure=_enclosure(tmp_path))
    finally:
        findings.chmod(0o700)

    assert imported.claims == [] and imported.artifacts == []
    assert imported.lost == 1
    assert any("could not be listed" in note and "unknown number" in note for note in imported.notes)


def test_a_findings_path_that_is_not_a_directory_is_counted_and_noted(tmp_path):
    """A regular file where the findings directory belongs is loss, not an empty harness run."""
    findings = tmp_path / "findings"
    findings.write_text("not a directory\n", encoding="utf-8")

    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings",
                                       stage_dir=tmp_path / "raw" / "harness-findings",
                                       baseline=snapshot_findings(findings, _enclosure(tmp_path)),
                                       enclosure=_enclosure(tmp_path))

    assert imported.lost == 1
    assert any("not a directory" in note for note in imported.notes)


def test_a_baseline_that_could_not_be_established_attributes_nothing_to_the_scan(tmp_path):
    """With no pre-scan listing, no record can be shown to be this scan's, so none is imported.

    Every record is counted as lost instead, because one of them may have been the scan's own
    and the outcome must not read as a complete or quiet observation.
    """
    findings = tmp_path / "findings"
    findings.mkdir()
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    (findings / "b.md").write_text(PLANTED, encoding="utf-8")

    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings",
                                       stage_dir=tmp_path / "raw" / "harness-findings",
                                       baseline=FindingsBaseline({}, False, "the directory could not be listed"),
                                       enclosure=_enclosure(tmp_path))

    assert imported.claims == [] and imported.lost == 2
    assert any("provenance could not be established" in note for note in imported.notes)


def test_the_import_docstring_states_how_provenance_is_established_and_what_it_does_not_prove():
    doc = " ".join((import_harness_findings.__doc__ or "").split())
    assert "taken before the harness process started" in doc
    assert "What this does not prove." in doc
    assert "does not show that the harness's model produced them" in doc


def test_an_input_that_ships_the_harness_state_directory_never_reaches_the_importer(tmp_path, monkeypatch):
    """The outer layer: such an input is refused before the harness runs, so nothing is imported.

    A repository that committed a ``.securevibes`` directory carries those bytes inside the
    input hash the result would bind to, and the scanner would rewrite them. ``run_invocation``
    refuses it. The baseline inside :func:`import_harness_findings` is the inner layer, for
    records that appear in the directory after the run began.
    """
    prepared = _prepared(tmp_path)
    findings = prepared.source_dir / HARNESS_PRESETS["securevibes-agent"]["state_dir"] / "findings"
    findings.mkdir(parents=True)
    (findings / "planted.md").write_text(PLANTED, encoding="utf-8")
    prepared = PreparedInput(prepared.input_id, prepared.source_dir,
                             hash_exported_tree(prepared.source_dir)["tree_hash"],
                             prepared.languages, prepared.provenance)

    root = _fake_harness_root(tmp_path)
    sdk = tmp_path / "observer-sdk.js"
    sdk.write_text("// stub\n", encoding="utf-8")
    adapter = get_adapter("llm-harness")
    spec = SystemSpec("sv-stub", "llm-harness", {
        "harness": "securevibes-agent", "root": str(root), "model": "test/mock-llm",
        "runner": "mock", "observer_sdk": str(sdk)})
    preparation = adapter.prepare(spec, tmp_path / "cache")
    _stub_driver(monkeypatch, {"good.md": FINDING})

    with pytest.raises(ExecutionError, match=r"already contains adapter state directories \(\.securevibes\)"):
        run_invocation(prepared=prepared, adapter=adapter, spec=spec, preparation=preparation,
                       out_dir=tmp_path / "out", run_id="run-planted", timeout_seconds=60,
                       trace_mode="off", network_policy="none", clock=CLOCK)


# --- area B: the findings directory itself, and capture that matches the record -----------


def test_a_findings_path_that_leaves_the_workspace_is_refused_whether_the_link_is_it_or_above_it(tmp_path):
    """Checking the last component of a path is not a containment check.

    The findings path itself was checked for being a link, and each record inside it was checked
    too, but nothing checked the components in between. A link one level up, where the harness
    state directory goes, points every record behind it at bytes outside the workspace this scan
    was handed while each one still looks like an ordinary regular file in an ordinary directory:
    they were imported as findings of this scan, staged into the bundle, and credited. Both
    shapes are refused by one rule now, which resolves the whole path and proves it is still
    inside the workspace, and the records nobody could read are counted as loss.
    """
    workspace = tmp_path / "source"
    workspace.mkdir()
    outside = tmp_path / "outside"
    (outside / "findings").mkdir(parents=True)
    (outside / "findings" / "planted.md").write_text(FINDING, encoding="utf-8")
    enclosure = _enclosure(workspace, tmp_path / "raw")

    # The link one level above the path the importer checks: only the ancestor is a link.
    (workspace / ".securevibes").symlink_to(outside, target_is_directory=True)
    through_ancestor = workspace / ".securevibes" / "findings"
    assert not through_ancestor.is_symlink() and through_ancestor.is_dir(), "the ancestor is the link"
    assert (through_ancestor / "planted.md").is_file()

    baseline = snapshot_findings(through_ancestor, enclosure)
    imported = import_harness_findings(through_ancestor, harness="securevibes-agent",
                                       artifact_prefix="harness-findings",
                                       stage_dir=tmp_path / "raw" / "harness-findings",
                                       baseline=baseline, enclosure=enclosure)

    assert baseline.established is False, "nothing behind the link is attributed to this scan"
    assert imported.claims == [] and imported.artifacts == []
    assert imported.lost == 1
    assert any("does not resolve inside the workspace" in note for note in imported.notes)
    assert not (tmp_path / "raw").exists(), "nothing behind the link is staged"

    # The same rule covers the older shape, a link at the findings directory itself.
    direct = workspace / "findings"
    direct.symlink_to(outside / "findings", target_is_directory=True)
    at_the_path = import_harness_findings(direct, harness="securevibes-agent",
                                          artifact_prefix="harness-findings",
                                          stage_dir=tmp_path / "raw" / "harness-findings",
                                          baseline=snapshot_findings(direct, enclosure),
                                          enclosure=enclosure)

    assert at_the_path.claims == [] and at_the_path.lost == 1
    assert snapshot_findings(direct, enclosure).established is False
    assert not (tmp_path / "raw").exists()
    # The planted records are still exactly where they were: nothing outside was read or moved.
    assert [path.name for path in (outside / "findings").iterdir()] == ["planted.md"]


def test_a_link_where_the_staging_directory_goes_cannot_redirect_a_staged_record(tmp_path):
    """The other end of the same copy: the harness owns the directory these records are copied to.

    ``stage_record`` created the destination's parent with ``exist_ok=True``, which succeeds on a
    symbolic link to a directory, and then copied through it, so a link the harness left where
    the adapter stages evidence wrote the record to any absolute path the harness chose. The
    destination is resolved and proved to be inside this run's raw output now, so the copy is
    refused and the record is counted as loss instead of landing outside the bundle.
    """
    workspace = tmp_path / "source"
    findings = workspace / "findings"
    findings.mkdir(parents=True)
    baseline = snapshot_findings(findings, _enclosure(workspace, tmp_path / "raw"))
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (raw / "harness-findings").symlink_to(outside, target_is_directory=True)

    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings",
                                       stage_dir=raw / "harness-findings", baseline=baseline,
                                       enclosure=_enclosure(workspace, raw))

    assert imported.claims == [] and imported.artifacts == []
    assert imported.lost == 1
    assert any("could not be staged" in note and "does not resolve inside" in note
               for note in imported.notes)
    assert list(outside.iterdir()) == [], "the copy landed outside the bundle"


@mkfifo_required
def test_a_named_pipe_where_a_record_is_staged_does_not_block_the_invocation(tmp_path):
    """Defence in depth against one instance of a class ``docs/THREAT_MODEL.md`` documents.

    The staging path is decided and then opened, and the harness owns the directory in between,
    so it can leave a named pipe there. Opening a pipe for writing waits for a reader, nothing in
    ScanEval ever reads this one, and the invocation hung with no bundle and no execution record:
    the write-side twin of the pipe that used to block the record read. ``O_NONBLOCK`` makes the
    open fail at once instead, and the record is counted as import loss like any other record
    that could not be staged.

    This narrows one instance. It does not close the class, which is why the document carries it
    as a worked example rather than as a fixed bug, and why
    ``tests/test_v2_execution.py::test_the_threat_model_document_names_the_class_two_reported_findings_belong_to``
    asserts the document still says so.
    """
    workspace = tmp_path / "source"
    findings = workspace / "findings"
    findings.mkdir(parents=True)
    raw = tmp_path / "raw"
    stage = raw / "harness-findings"
    stage.mkdir(parents=True)
    baseline = snapshot_findings(findings, _enclosure(workspace, raw))
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    os.mkfifo(stage / "a.md")

    imported = call_with_deadline(
        lambda: import_harness_findings(findings, harness="securevibes-agent",
                                        artifact_prefix="harness-findings", stage_dir=stage,
                                        baseline=baseline, enclosure=_enclosure(workspace, raw)))

    assert imported.claims == [] and imported.artifacts == []
    assert imported.lost == 1
    assert any("could not be staged" in note for note in imported.notes)
    assert stat.S_ISFIFO(os.lstat(stage / "a.md").st_mode), "the pipe is untouched and unread"


def test_a_staging_destination_hard_linked_to_a_host_file_is_not_overwritten(tmp_path):
    """The other worked example of the same class: ``O_NOFOLLOW`` stops a link it can see.

    A hard link is a second directory entry for one inode, not a symbolic link, so ``O_NOFOLLOW``
    has nothing to refuse: the open truncated the host file the harness had linked where the
    record goes and wrote the record into it, with the operator's privileges. The destination is
    proved to be a regular file carrying one link, on the descriptor the open returned and before
    anything is truncated, so the host file keeps its bytes and the record is counted as loss.

    Defence in depth against one instance, not a closed class: the harness can still link a file
    there after this check and before another operation, which is what the threat model states.
    """
    workspace = tmp_path / "source"
    findings = workspace / "findings"
    findings.mkdir(parents=True)
    raw = tmp_path / "raw"
    stage = raw / "harness-findings"
    stage.mkdir(parents=True)
    baseline = snapshot_findings(findings, _enclosure(workspace, raw))
    (findings / "a.md").write_text(FINDING, encoding="utf-8")
    host = tmp_path / "host.md"
    host.write_text("host bytes the scan never wrote\n", encoding="utf-8")
    os.link(host, stage / "a.md")

    imported = import_harness_findings(findings, harness="securevibes-agent",
                                       artifact_prefix="harness-findings", stage_dir=stage,
                                       baseline=baseline, enclosure=_enclosure(workspace, raw))

    assert imported.claims == [] and imported.artifacts == []
    assert imported.lost == 1
    assert any("could not be staged" in note and "second name for another file" in note
               for note in imported.notes)
    assert host.read_text(encoding="utf-8") == "host bytes the scan never wrote\n"
    assert host.stat().st_nlink == 2, "the link is the harness's own doing and is left alone"


def test_a_traced_run_reports_the_capture_gap_its_own_trace_record_carries(tmp_path, monkeypatch):
    """The execution record used to say finding capture was complete beside its own gap.

    ``capture.finding_submitted`` and ``trace.capture_gap`` come from the same observer state
    and are written into the same document, so the record contradicted itself whenever the
    observer reported a gap or a dropped event.
    """
    gap = {**DRIVER_OUTPUT, "trace": {"mode": "content", "state": {"capture_gap": True, "dropped_events": 2}}}
    bundle = _stubbed_bundle(tmp_path / "gap", monkeypatch, {"a.md": FINDING}, run_id="run-gap",
                             trace_mode="content", output=gap)
    execution = load_document(bundle / "execution.json", "execution-record")

    assert execution["trace"]["capture_gap"] is True and execution["trace"]["dropped_events"] == 2
    assert execution["trace"]["events"] == 2 and execution["trace"]["path"] == "trace/events.jsonl"
    assert execution["capture"]["finding_submitted"] == "partial"

    clean = {**DRIVER_OUTPUT, "trace": {"mode": "content", "state": {"capture_gap": False, "dropped_events": 0}}}
    control = _stubbed_bundle(tmp_path / "clean", monkeypatch, {"a.md": FINDING}, run_id="run-clean-trace",
                              trace_mode="content", output=clean)
    control_execution = load_document(control / "execution.json", "execution-record")

    assert control_execution["trace"]["capture_gap"] is False
    assert control_execution["capture"]["finding_submitted"] == "complete"


# --- area B: what the harness says it wrote, against what the importer could read ---------


REPORTED_TWO = {**DRIVER_OUTPUT,
                "summary": {**DRIVER_OUTPUT["summary"],
                            "newFindings": [{"id": "SV-AUTH-AUTHBYPASS-001"}],
                            "updatedFindings": [{"id": "SV-INJ-CMDI-002"}]}}


def test_a_scan_that_lost_every_finding_it_reported_does_not_reach_scoring_as_a_clean_success(tmp_path, monkeypatch):
    """The importer counted only what it could see, so losing everything looked like finding nothing.

    A harness run whose finding records never reached the findings directory left no record for
    the importer to fail on: zero claims, zero losses, ``success`` with resolved bundles, and
    full quiet credit for saying nothing. The harness's own summary names the findings it wrote,
    and a name with no claim behind it is import loss like any other.
    """
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {}, run_id="run-vanished", output=REPORTED_TWO)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert result["claims"] == []
    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert result["error"]["code"] == "import_loss"
    assert "2 harness finding record(s)" in result["error"]["message"]
    assert "SV-AUTH-AUTHBYPASS-001" in result["error"]["message"]
    assert "SV-INJ-CMDI-002" in result["error"]["message"]
    assert execution["status"] == "partial" and execution["error"] == result["error"]
    assert any("Import loss" in note for note in execution["notes"])

    plan, decisions = _quiet_review(result)
    report = score(plan, result, decisions)
    controls = report["metrics"]["controls"]["capability_safe"]
    assert controls["completed"] == 0 and controls["resolved"] == 0
    assert controls["assessable_mass"] == 0.0 and report["metrics"]["completed"] is False
    assert "Incomplete or failed execution cannot establish a successful negative control." in report["warnings"]


def test_the_self_report_is_reconciled_against_the_claims_that_actually_arrived(tmp_path, monkeypatch):
    """Half of what the harness says it wrote arrived; the other half is loss, named by id."""
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, run_id="run-half", output=REPORTED_TWO)
    result = load_document(bundle / "result.json", "scan-result")

    assert [claim["claim_id"] for claim in result["claims"]] == ["SV-AUTH-AUTHBYPASS-001"]
    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert result["error"]["code"] == "import_loss"
    assert "1 harness finding record(s)" in result["error"]["message"]
    assert "SV-INJ-CMDI-002" in result["error"]["message"]
    assert "SV-AUTH-AUTHBYPASS-001" not in result["error"]["message"], "the finding that arrived is not lost"


def test_a_scan_that_delivered_every_finding_it_reported_is_still_a_clean_success(tmp_path, monkeypatch):
    """The control: a self-report the claims account for changes nothing about the outcome."""
    matched = {**DRIVER_OUTPUT, "summary": {**DRIVER_OUTPUT["summary"],
                                            "newFindings": [{"id": "SV-AUTH-AUTHBYPASS-001"}]}}
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, run_id="run-matched", output=matched)
    result = load_document(bundle / "result.json", "scan-result")

    assert [claim["claim_id"] for claim in result["claims"]] == ["SV-AUTH-AUTHBYPASS-001"]
    assert result["status"] == "success" and result["bundles_resolved"] is True
    assert "error" not in result


def test_the_self_report_is_read_from_the_findings_the_harness_names():
    """Ids where the summary carries records, a number where it carries a count, a count of what it could not read.

    The fourth field is new: a part of the self-report the reader cannot parse is counted rather
    than only noted. It stays out of ``total``, because an unreadable field says nothing about
    how many records were written; it is evidence the run offered that the importer could not
    use, which :func:`reconcile_import` turns into loss.
    """
    report = read_self_report({"newFindings": [{"id": "A"}, {"id": "A"}, {"severity": "high"}],
                               "updatedFindings": [{"id": "B"}]})
    assert report.ids == ("A", "B") and report.unnamed == 1 and report.total == 3
    assert report.unreadable == 0

    assert read_self_report({"newFindings": 3}).unnamed == 3
    unreadable = read_self_report({"updatedFindings": "two"})
    assert unreadable.total == 0 and "not a list of findings" in (unreadable.note or "")
    assert unreadable.unreadable == 1
    both = read_self_report({"newFindings": {"count": 2}, "updatedFindings": "two"})
    assert both.unreadable == 2 and both.total == 0
    # A summary that is not a mapping at all was offered and could not be read either.
    assert read_self_report("done").unreadable == 1
    assert "not a mapping" in (read_self_report("done").note or "")
    # No self-report at all asserts nothing: the run that wrote no summary is failed already.
    assert read_self_report(None) == SelfReport((), 0, 0, None)
    assert read_self_report({}) == SelfReport((), 0, 0, None)


def test_a_self_report_the_reader_cannot_parse_is_counted_as_loss_not_as_nothing_lost():
    """An unreadable self-report produced a shortfall of zero, so losing everything read as clean.

    The reconciliation compares what the harness says it wrote against what arrived. When the
    part naming the findings is a shape the reader does not expect there is nothing to compare,
    and treating that as agreement let a scan whose entire self-report was unreadable reach
    scoring as a complete success. It is counted as loss now, one record per unreadable part,
    which the message says is a floor rather than a measurement.
    """
    delivered = HarnessImport([{"claim_id": "A"}], [], [], ())

    unreadable = reconcile_import(delivered, read_self_report({"newFindings": "two"}))
    assert unreadable.lost == 1
    assert "could not be read" in (unreadable.message or "") and "floor" in (unreadable.message or "")

    # A readable part beside an unreadable one is still reconciled on its own terms: the claim
    # that arrived accounts for the finding that was named, and only the unreadable part is loss.
    mixed = reconcile_import(delivered, read_self_report({"newFindings": [{"id": "A"}],
                                                         "updatedFindings": "two"}))
    assert mixed.lost == 1
    assert "did not arrive as claims" not in (mixed.message or "")
    # The control: a self-report the reader can parse and the claims account for is no loss.
    assert reconcile_import(delivered, read_self_report({"newFindings": [{"id": "A"}]})).lost == 0


def test_a_record_the_harness_reported_and_the_importer_rejected_is_counted_once():
    """The reconciliation is over records, not a sum of two counts that overlap.

    A record the importer read and refused is already loss with a reason of its own; the same
    finding named in the summary must not be counted a second time. A finding named there that
    no rejection explains is the shortfall.
    """
    rejected = HarnessImport([], [], [], (LostRecord("b.md", "SV-X-002", "unusable file_path; not imported"),))

    once = reconcile_import(rejected, read_self_report({"newFindings": [{"id": "SV-X-002"}]}))
    assert once.lost == 1
    assert "did not arrive as claims" not in (once.message or "")

    both = reconcile_import(rejected, read_self_report({"newFindings": [{"id": "SV-X-002"}, {"id": "SV-Y-003"}]}))
    assert both.lost == 2
    assert both.message.count("SV-X-002") == 1 and "SV-Y-003" in both.message

    # A report that names no ids is compared by number, and delivered claims account for it.
    delivered = HarnessImport([{"claim_id": "A"}, {"claim_id": "B"}], [], [], ())
    assert reconcile_import(delivered, read_self_report({"newFindings": 2})).lost == 0
    assert reconcile_import(delivered, read_self_report({"newFindings": 3})).lost == 1
    # And a summary that names nothing asserts nothing: the importer's own count stands alone.
    assert reconcile_import(rejected, read_self_report({})).lost == 1
    assert reconcile_import(delivered, read_self_report({})) == (0, None, ())


def test_a_plan_record_that_cannot_be_staged_is_noted_and_keeps_the_claims(tmp_path, monkeypatch):
    """The staging loop raised, so one unstageable plan record discarded the whole import.

    The plan records are copied after the findings have already been imported. A harness that
    wrote a regular file where the staging directory goes made ``mkdir`` raise, the exception
    left ``scan`` entirely, and the invocation was recorded as an adapter failure with no claims
    at all, even though every finding had been read and staged. It is contained and noted now.
    """
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, run_id="run-plan-block",
                             block_plan_staging=True)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert result["status"] == "success", "a plan record is evidence, not a claim"
    assert [claim["claim_id"] for claim in result["claims"]] == ["SV-AUTH-AUTHBYPASS-001"]
    assert any("bootstrap-plan.md" in note and "could not be staged" in note for note in execution["notes"])
    assert "harness-bootstrap-plan.md" not in {artifact["id"] for artifact in execution["raw_artifacts"]}
    # The claim's own record is still staged and registered, which is what was being discarded.
    registered = {artifact["id"] for artifact in execution["raw_artifacts"]}
    assert result["claims"][0]["raw_artifact_id"] in registered


def test_a_scanner_that_links_its_state_directory_out_of_the_workspace_imports_nothing(tmp_path, monkeypatch):
    """End to end: a link one level above the findings directory, through a whole invocation.

    The importer checked the findings path and each record for being a link and never the
    components between them, so a harness that replaced its own state directory with a link to
    anywhere on the host had every record behind it read, staged into the bundle, and imported as
    a claim of this scan. Nothing outside the workspace is read or written now: the records are
    counted as import loss, the plan record behind the same link is noted rather than staged, the
    state capture refuses the link, and the planted files are exactly where they were.
    """
    outside = tmp_path / "outside"
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"planted.md": FINDING}, run_id="run-ancestor",
                             state_as_link=outside, output=REPORTED_TWO)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert result["claims"] == [], "a record reached through a link out of the workspace is not a claim"
    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert result["error"]["code"] == "import_loss"
    assert any("does not resolve inside the workspace" in note for note in execution["notes"])
    assert any("bootstrap-plan.md" in note and "not staged" in note for note in execution["notes"])
    # The capture refuses the same link from the other side, so nothing behind it is preserved.
    assert execution["provenance"]["captured_state_dirs"] == []
    assert not (bundle / "raw" / "harness-state").exists()
    assert not (bundle / "raw" / "harness-findings").exists()
    # Nothing outside the workspace was read, moved, or written: the planted files are untouched.
    assert sorted(path.name for path in outside.iterdir()) == ["bootstrap-plan.md", "findings"]
    assert (outside / "findings" / "planted.md").read_text(encoding="utf-8") == FINDING
    assert not list(bundle.rglob("planted.md"))


def test_a_link_where_the_adapter_stages_records_writes_nothing_outside_the_bundle(tmp_path, monkeypatch):
    """The same rule on the destination, through a whole invocation.

    The harness writes into the staging directory while it runs, so a link it leaves where the
    adapter copies imported records sent each copy to an absolute path of its choosing. The
    destination is proved to resolve back inside this run's raw output now.
    """
    outside = tmp_path / "outside"
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, run_id="run-stage-link",
                             stage_as_link=outside)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert result["claims"] == [] and result["status"] == "partial"
    assert result["error"]["code"] == "import_loss"
    assert any("could not be staged" in note and "does not resolve inside" in note
               for note in execution["notes"])
    assert list(outside.iterdir()) == [], "a record was copied outside the bundle"


@mkfifo_required
def test_a_named_pipe_where_the_driver_output_belongs_does_not_block_the_invocation(tmp_path, monkeypatch):
    """The harness owns this path, and reading it had no regular-file guard at all.

    ``driver-output.json`` was checked for resolving inside the staging directory and then read
    with ``read_text()``. A named pipe passes that check and holds the read open until something
    writes to it, which nothing ever does: ``run_invocation`` never returned, so the run produced
    no bundle, no execution record, and nothing to tell it apart from a run still in progress. It
    is read through the one function that proves the file is a regular file in the same open now,
    so the run is recorded as one that produced no summary. The invocation runs behind a
    deadline, so a regression fails here rather than stalling the suite.
    """
    bundle = call_with_deadline(
        lambda: _stubbed_bundle(tmp_path, monkeypatch, {}, run_id="run-pipe", output_as_pipe=True))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["error"]["code"] == "driver_exit_0"
    assert "the driver left no output" in result["error"]["message"]
    assert any("the driver output was not read" in note and "not a regular file" in note
               for note in execution["notes"])
    # The pipe is still in the bundle exactly as the harness left it: staged, never opened.
    assert stat.S_ISFIFO((bundle / "raw" / "driver-output.json").stat().st_mode)
    assert ("declared artifact is not a regular file and was not hashed: driver-output"
            in execution["notes"])


def test_a_self_report_the_reader_cannot_parse_does_not_reach_scoring_as_a_clean_success(tmp_path, monkeypatch):
    """A harness that reported its findings in an unexpected shape read as one that reported none.

    ``read_self_report`` produced a note and no number, the reconciliation had nothing to
    compare, and the shortfall was zero, so the scan reached scoring as a complete success with
    full credit for saying nothing. An unreadable self-report is missing evidence, so it is loss.
    """
    unreadable = {**DRIVER_OUTPUT, "summary": {**DRIVER_OUTPUT["summary"], "newFindings": "two"}}
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, run_id="run-unreadable",
                             output=unreadable)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert [claim["claim_id"] for claim in result["claims"]] == ["SV-AUTH-AUTHBYPASS-001"]
    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert result["error"]["code"] == "import_loss"
    assert "not a list of findings" in result["error"]["message"]
    assert any("Import loss" in note for note in execution["notes"])

    plan, decisions = _quiet_review(result)
    report = score(plan, result, decisions)
    controls = report["metrics"]["controls"]["capability_safe"]
    assert controls["completed"] == 0 and controls["resolved"] == 0
    assert "Incomplete or failed execution cannot establish a successful negative control." in report["warnings"]


def test_node_options_is_not_forwarded_from_the_operator_environment_to_the_driver(tmp_path, monkeypatch):
    """NODE_OPTIONS names code for node to run, so forwarding it let the operator environment in.

    ``--require`` or ``--import`` in that variable runs before the driver's own entry point, so
    one variable in the shell that started the run changed what the run did, while the execution
    record listed only the variable's name and never its value. It is not passed through now, and
    the record's passthrough list, which is built from the same tuple, says so.
    """
    monkeypatch.setenv("NODE_OPTIONS", "--require /tmp/injected.js")
    observed: dict = {}
    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, run_id="run-node-options",
                             observed=observed)
    execution = load_document(bundle / "execution.json", "execution-record")

    assert "NODE_OPTIONS" not in observed["env"], "the driver inherited a code-injection channel"
    assert "NODE_OPTIONS" not in execution["environment"]["passthrough"]
    assert "NODE_OPTIONS" not in get_adapter("llm-harness").env_passthrough
    # The keys the harness needs to call a model are still passed: this removed one variable.
    assert "ANTHROPIC_API_KEY" in get_adapter("llm-harness").env_passthrough
    assert "injected" not in json.dumps(execution)


def test_the_harness_provenance_is_read_from_the_harness_root_not_an_inherited_git_dir(tmp_path, monkeypatch):
    """``prepare`` ran git with the operator environment, so GIT_DIR named the recorded HEAD.

    The preparation record reports the harness commit the scan ran against. With ``GIT_DIR`` set
    it reported an unrelated repository's HEAD instead, and every bundle from that run carried a
    version string for a checkout that was never involved.
    """
    root = _fake_harness_root(tmp_path)
    sdk = tmp_path / "observer-sdk.js"
    sdk.write_text("// stub\n", encoding="utf-8")
    import subprocess

    def git(*args: str, cwd: Path) -> str:
        environment = {**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x",
                       "GIT_COMMITTER_NAME": "u", "GIT_COMMITTER_EMAIL": "u@x",
                       "GIT_CONFIG_GLOBAL": os.devnull}
        for name in ("GIT_DIR", "GIT_WORK_TREE"):
            environment.pop(name, None)
        return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True,
                              text=True, env=environment).stdout.strip()

    elsewhere = tmp_path / "elsewhere"
    for repository in (root, elsewhere):
        repository.mkdir(exist_ok=True)
        git("init", "-q", "-b", "main", cwd=repository)
        (repository / "marker.txt").write_text(f"{repository.name}\n", encoding="utf-8")
        git("add", "-A", cwd=repository)
        git("commit", "-q", "-m", repository.name, cwd=repository)
    monkeypatch.setenv("GIT_DIR", str(elsewhere / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(elsewhere))

    adapter = get_adapter("llm-harness")
    preparation = adapter.prepare(SystemSpec("sv-stub", "llm-harness", {
        "harness": "securevibes-agent", "root": str(root), "model": "test/mock-llm",
        "runner": "mock", "observer_sdk": str(sdk)}), tmp_path / "cache")
    monkeypatch.undo()

    assert preparation["harness"]["git_head"] == git("rev-parse", "HEAD", cwd=root)
    assert preparation["harness"]["git_head"] != git("rev-parse", "HEAD", cwd=elsewhere)


def test_a_workspace_swapped_after_the_enclosure_was_captured_cannot_move_the_boundary(tmp_path):
    """The enclosure resolved its own roots on every check, after the harness had run.

    A harness that replaces the workspace it was handed with a symbolic link to a tree it
    controls moved the base along with the path: the records behind the link resolved inside the
    base that now pointed at them, every check passed, and they were read, staged, and imported
    as findings of this scan. Both roots have their real path read once, when the enclosure is
    captured before the harness process starts, so the substituted tree does not resolve inside
    the workspace this run created.
    """
    workspace = tmp_path / "source"
    (workspace / "findings").mkdir(parents=True)
    (workspace / "findings" / "real.md").write_text(FINDING, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "findings").mkdir(parents=True)
    (elsewhere / "findings" / "planted.md").write_text(PLANTED, encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()

    enclosure = Enclosure.capture(workspace, raw)
    baseline = snapshot_findings(workspace / "findings", enclosure)
    assert baseline.established is True

    workspace.rename(tmp_path / "source-real")
    workspace.symlink_to(elsewhere, target_is_directory=True)
    assert (workspace / "findings" / "planted.md").is_file(), "the substituted tree is reachable"

    imported = import_harness_findings(workspace / "findings", harness="securevibes-agent",
                                       artifact_prefix="harness-findings",
                                       stage_dir=raw / "harness-findings",
                                       baseline=baseline, enclosure=enclosure)

    assert imported.claims == [] and imported.artifacts == []
    assert imported.lost == 1
    assert any("does not resolve inside the workspace" in note for note in imported.notes)
    assert not (raw / "harness-findings").exists(), "nothing from the substituted tree was staged"
    assert [path.name for path in (elsewhere / "findings").iterdir()] == ["planted.md"]


# --- PR mode: the harness's pr mode over the synthetic base and head commits ---------------------------

BASE_SERVER = ("const express = require('express');\nconst app = express();\n"
               "app.get('/', (req, res) => res.send('ok'));\napp.listen(3000);\n")
HELPER_JS = "module.exports = function helper() { return 'shared by the rename'; };\n"
PR_CHANGES = {"added": ["src/routes.js"], "deleted": ["docs/old.md"], "modified": ["src/server.js"],
              "renamed": [["lib/a.js", "lib/b.js"]], "mode_changed": ["bin/start.sh"]}


def _pr_prepared(tmp_path: Path) -> PreparedInput:
    """A real PR input over a small JavaScript project: an edit, an addition, a deletion, a rename, a mode change.

    The head is the fixture :func:`_prepared` writes plus a routes module, and the base is that
    project before the pull request added the shell routes. The synthetic commits are the ones
    preparation computes, so the workspace history the run builds must reproduce them.
    """
    import dataclasses

    from scaneval.contracts import pr_diff_sha256, pr_input_hash
    from scaneval.materialize import compute_pr_history, diff_trees

    head, base = tmp_path / "trial" / "source", tmp_path / "trial" / "base" / "source"
    for root, server in ((base, BASE_SERVER), (head, _prepared(tmp_path / "scratch").source_dir / "src" / "server.js")):
        (root / "src").mkdir(parents=True)
        (root / "src" / "server.js").write_text(server if isinstance(server, str) else server.read_text(encoding="utf-8"),
                                                encoding="utf-8")
        (root / "package.json").write_text('{"name": "pilot-fixture", "version": "1.0.0"}\n', encoding="utf-8")
        (root / "README.md").write_text("# fixture\n", encoding="utf-8")
    (base / "docs").mkdir()
    (base / "docs" / "old.md").write_text("removed by the pull request\n", encoding="utf-8")
    (base / "lib").mkdir()
    (base / "lib" / "a.js").write_text(HELPER_JS, encoding="utf-8")
    (base / "bin").mkdir()
    (base / "bin" / "start.sh").write_text("#!/bin/sh\necho start\n", encoding="utf-8")
    (head / "src" / "routes.js").write_text("module.exports = { added: true };\n", encoding="utf-8")
    (head / "lib").mkdir()
    (head / "lib" / "b.js").write_text(HELPER_JS, encoding="utf-8")
    (head / "bin").mkdir()
    (head / "bin" / "start.sh").write_text("#!/bin/sh\necho start\n", encoding="utf-8")
    (head / "bin" / "start.sh").chmod(0o755)
    head_hash, base_hash = hash_exported_tree(head)["tree_hash"], hash_exported_tree(base)["tree_hash"]
    changes = diff_trees(base, head)
    assert changes == PR_CHANGES
    digest = pr_diff_sha256(base_hash, head_hash, changes)
    history = compute_pr_history(head, base, changes)
    pr = {"change_set_id": "cs-1", "base_snapshot_id": "snap-base", "head_snapshot_id": "snap-head",
          "boundary": "introducing", "review_scope": "changed_files", "base_tree_hash": base_hash,
          "head_tree_hash": head_hash, "diff_sha256": digest, "changes": changes,
          "base_commit": history["base_commit"], "head_commit": history["head_commit"],
          "history": {key: history[key] for key in ("messages", "identity", "date")}, "prepared_state": "fresh"}
    return PreparedInput("fixture-pr", head, head_hash, ("javascript",), {"source": {"commit": "fixture"}},
                         mode="pr", input_hash=pr_input_hash(base_hash, head_hash, digest), pr=pr,
                         base_source_dir=base)


PR_OUTPUT = {**DRIVER_OUTPUT, "mode": "pr",
             "summary": {"changeScan": {"llmCalls": 2, "failedCalls": 0, "status": "complete",
                                        "hypothesisCoverage": 1.0},
                         "runtimeProfile": "lite", "degraded": False}}


def test_the_adapter_declares_full_and_pr_scans():
    adapter = get_adapter("llm-harness")

    assert adapter.scan_modes == frozenset({"full", "pr"})
    assert adapter.adapter_version == "2.3.0"


def test_a_pr_request_runs_the_harness_in_pr_mode_between_the_commits_the_request_names(tmp_path, monkeypatch):
    prepared = _pr_prepared(tmp_path)
    observed: dict = {}

    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, prepared=prepared, output=PR_OUTPUT,
                             observed=observed)

    config = observed["config"]
    request = json.loads((bundle / "request.json").read_text(encoding="utf-8"))
    assert request["input"]["mode"] == "pr"
    assert config["mode"] == "pr", "the harness mode follows the request, whatever the configuration"
    assert (config["base_ref"], config["head_ref"]) == (prepared.pr["base_commit"], prepared.pr["head_commit"]) == (
        request["input"]["pr"]["base"], request["input"]["pr"]["head"]), \
        "the engine is told the two commits the request names and never resolves a base of its own"
    assert set(config) == {"harness_root", "engine_entry", "runner_entry", "mock_entry", "observer_sdk",
                           "repo_path", "mode", "base_ref", "head_ref", "model", "runner", "trace_mode",
                           "run_id", "producer_id", "output_path", "progress_path", "flush_timeout_ms"}, \
        "pr writability and trust are left unset, so the engine keeps its own default"
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success" and result["location_basis"] == "pr_head"
    assert [claim["claim_id"] for claim in result["claims"]] == ["SV-AUTH-AUTHBYPASS-001"]
    assert execution["provenance"]["mode"] == "pr" and execution["adapter"]["version"] == "2.3.0"
    assert execution["provenance"]["pr"]["prepared_state"] == "fresh"
    assert any(note.startswith("Prepared state: fresh.") for note in execution["notes"])
    assert all(not note.startswith("Prepared state") for note in
               load_document(_stubbed_bundle(tmp_path / "full", monkeypatch, {"a.md": FINDING}) / "execution.json",
                             "execution-record")["notes"]), "a full run makes no such statement"


def test_a_full_request_keeps_running_bootstrap_and_hands_the_driver_no_refs(tmp_path, monkeypatch):
    observed: dict = {}

    _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, observed=observed)

    assert observed["config"]["mode"] == "bootstrap"
    assert "base_ref" not in observed["config"] and "head_ref" not in observed["config"]


@pytest.mark.parametrize(("summary", "status", "code"), [
    ({"changeScan": {"llmCalls": 2, "failedCalls": 0, "status": "complete", "hypothesisCoverage": 1.0}},
     "success", None),
    ({"changeScan": {"llmCalls": 3, "failedCalls": 3, "status": "complete"}}, "partial", "llm_path_failed"),
    ({"changeScan": {"llmCalls": 2, "failedCalls": 0, "status": "inconclusive", "reasons": ["quota"]}},
     "partial", "harness_inconclusive"),
    ({"changeScan": {"llmCalls": 0, "failedCalls": 0, "status": "skipped", "reasons": [],
                     "advisories": ["no_scan_required"]}}, "success", None),
    # A bootstrap record beside a change scan is not what a pr run reports; it is never read.
    ({"changeScan": {"llmCalls": 1, "failedCalls": 0, "status": "complete"},
      "bootstrapScan": {"llmCalls": 9, "failedCalls": 9, "status": "inconclusive"}}, "success", None),
], ids=["complete", "every-call-failed", "inconclusive", "skipped-by-the-harness", "bootstrap-record-ignored"])
def test_a_pr_run_reads_its_status_and_call_counts_from_the_change_scan(tmp_path, monkeypatch, summary, status, code):
    output = {**PR_OUTPUT, "summary": {**summary, "runtimeProfile": "lite", "degraded": False}}

    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, prepared=_pr_prepared(tmp_path),
                             output=output)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == status and (result.get("error") or {}).get("code") == code
    counted = summary["changeScan"]
    assert any(f"llm_calls={counted['llmCalls']} failed_calls={counted['failedCalls']}" in note
               for note in execution["notes"]), "the self-report note is the change scan's own numbers"
    if counted.get("status") == "skipped":
        assert any("skips is its native scope, not a failure of this run" in note for note in execution["notes"])


def test_a_bootstrap_run_never_reads_a_change_scan_record(tmp_path, monkeypatch):
    output = {**DRIVER_OUTPUT, "summary": {
        "changeScan": {"llmCalls": 9, "failedCalls": 9, "status": "inconclusive"},
        "bootstrapScan": {"llmCalls": 1, "failedCalls": 0, "status": "complete"},
        "runtimeProfile": "lite", "degraded": False}}

    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, output=output)

    assert load_document(bundle / "result.json", "scan-result")["status"] == "success"


def test_a_pr_run_whose_summary_carries_no_change_scan_says_so_instead_of_reading_zero_calls_as_a_fact(tmp_path,
                                                                                                      monkeypatch):
    output = {**PR_OUTPUT, "summary": {"runtimeProfile": "lite", "degraded": False, "newFindings": []}}

    bundle = _stubbed_bundle(tmp_path, monkeypatch, {}, prepared=_pr_prepared(tmp_path), output=output)

    execution = load_document(bundle / "execution.json", "execution-record")
    assert any("carried no changeScan record" in note for note in execution["notes"])


def test_a_pr_request_the_adapter_cannot_honour_is_refused_and_never_run_as_a_full_scan(tmp_path):
    adapter = get_adapter("llm-harness")
    root = _fake_harness_root(tmp_path)
    sdk = tmp_path / "observer-sdk.js"
    sdk.write_text("// stub\n", encoding="utf-8")
    spec = SystemSpec("sv", "llm-harness", {"harness": "securevibes-agent", "root": str(root),
                                            "model": "m", "observer_sdk": str(sdk)})
    preparation = adapter.prepare(spec, tmp_path / "cache")
    base = {"tree_hash": "sha256:" + "a" * 64, "root": ".", "languages": ["python"], "profile": "standard"}
    arguments = {"source_dir": tmp_path / "source", "raw_dir": tmp_path / "raw", "spec": spec,
                 "preparation": preparation, "timeout_seconds": 5, "trace_mode": "off", "trace_dir": None}

    for request_input, message in (
        ({**base, "mode": "pr"}, "must name the base and head commits"),
        ({**base, "mode": "pr", "pr": {"base": "a" * 40}}, "must name the base and head commits"),
        ({**base, "mode": "pr", "pr": {"base": "", "head": "b" * 40}}, "must name the base and head commits"),
        ({**base, "mode": "batch"}, "carries out full, pr scans, not 'batch'"),
    ):
        with pytest.raises(AdapterError, match=message):
            adapter.scan(request={"run_id": "r", "input": request_input}, **arguments)
    odd = SystemSpec("sv", "llm-harness", {**spec.config, "mode": "batch"})
    with pytest.raises(AdapterError, match="config.mode names the harness mode of a full request"):
        adapter.scan(request={"run_id": "r", "input": {**base, "mode": "full"}}, **{**arguments, "spec": odd})
    with pytest.raises(AdapterError, match="config.mode names the harness mode of a full request"):
        adapter.scan(request={"run_id": "r", "input": {**base, "mode": "pr", "pr": {"base": "a", "head": "b"}}},
                     **{**arguments, "spec": odd})


def test_a_pr_run_is_the_only_run_that_says_why_no_validation_stage_ran_in_pr_terms(tmp_path, monkeypatch):
    hooked = {**PR_OUTPUT, "hooks": {"runner": 1, "engine": 1}}

    bundle = _stubbed_bundle(tmp_path, monkeypatch, {"a.md": FINDING}, prepared=_pr_prepared(tmp_path),
                             output=hooked, trace_mode="content")

    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["capture"]["finding_validation"] == "not_applicable"
    assert any("a pr scan runs no validation stage either, because the consensus judge is the only one and "
               "this adapter never configures consensus, so there is no validation to miss" in note
               for note in execution["notes"])
    assert not any("a bootstrap scan runs no validation stage" in note for note in execution["notes"])


def test_capture_is_described_for_the_two_modes_this_adapter_runs_and_refuses_any_other():
    gapless = {"capture_gap": False, "dropped_events": 0}
    hooked = {"runner": 1, "engine": 1}

    for mode in ("bootstrap", "pr"):
        matrix = capture_status("content", ["claude"], has_summary=True, capture_state=gapless, hooks=hooked,
                                hook_failures=0, mode=mode)
        assert matrix["finding_validation"] == "not_applicable" and matrix["finding_candidate"] == "complete"
    assert capture_status("content", ["claude"], has_summary=True, capture_state=gapless) == capture_status(
        "content", ["claude"], has_summary=True, capture_state=gapless, mode="bootstrap"), \
        "a caller that names no mode is given the bootstrap matrix, which is what every caller was given before"
    with pytest.raises(ValueError, match="bootstrap, pr, not 'batch'"):
        capture_status("content", ["claude"], has_summary=True, mode="batch")
