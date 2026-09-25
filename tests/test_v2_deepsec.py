"""Third-party DeepSec adapter: a fake CLI, the records it writes, and what the run may claim.

Nothing here calls a model. The fake DeepSec below writes the records the real 2.3.10 writes
(``FileRecord`` with candidates, findings and an append-only ``analysisHistory`` whose numbers
are per-file *shares* of a batch, ``RunMeta``, parse-failure dumps, and the ``export --format
json`` payload) and is driven by a control file beside it, so every failure mode the adapter
classifies can be produced on demand.

The control file replaces the environment variable such a switch would normally be: the
adapter builds its child environment with :func:`~scaneval.adapters.base.build_env`, which
passes a fixed set of names and nothing else, so a test variable would never reach the process.
A file next to the executable is read by the executable itself and needs no passthrough.

The transcript collector is WP-D's module and may not exist on this checkout, so
:func:`scaneval.adapters.deepsec.collector` is replaced wherever the import path is exercised
and the test asserts what the adapter hands it: an observer, the transcript path, the workspace
root, and the session's own ``call_id``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading

import pytest

from scaneval.adapters import adapter_names, get_adapter
from scaneval.adapters import deepsec as deepsec_module
from scaneval.adapters.base import AdapterError, SystemSpec
from scaneval.adapters.deepsec import (
    Candidate,
    capture_status,
    candidates_from,
    claim_path,
    finding_ids,
    import_export,
    kind_for_slug,
    line_span,
    project_id_for,
    sessions_from,
    settings,
    workspace_config,
)
from scaneval.contracts import load_document
from scaneval.execution import PreparedInput, run_invocation
from scaneval.materialize import hash_exported_tree


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "DEEPSEC.md"
RUN_CONFIG = ROOT / "corpus" / "pilot" / "run-deepsec.json"
CLOCK = lambda: datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)  # noqa: E731

# A fake ``deepsec`` executable. It writes the records the real one writes and reads a control
# file beside itself for the failure modes a test wants. It never writes outside its working
# directory, and it refuses to run without the generated config, so a run that forgot to build
# the private workspace fails loudly here rather than producing an empty scan.
FAKE_CLI = '''
import json, os, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROL = HERE / "control.json"


def control():
    try:
        return json.loads(CONTROL.read_text(encoding="utf-8"))
    except OSError:
        return {}


def option(argv, name, default=None):
    return argv[argv.index(name) + 1] if name in argv else default


def data_dir(project):
    return Path(os.environ.get("DEEPSEC_DATA_ROOT", "data")) / project


def source_files(root):
    found = []
    for path in sorted(Path(root).rglob("*")):
        if path.is_file() and path.suffix in (".py", ".js", ".ts", ".go"):
            found.append(path.relative_to(root).as_posix())
    return found


def write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\\n", encoding="utf-8")


def step_failure(knob, step):
    settings = control()
    if settings.get("hang") == step:
        time.sleep(60)
    code = settings.get(knob)
    if isinstance(code, int) and code != 0:
        sys.stderr.write("fake deepsec %s failed on purpose\\n" % step)
        sys.exit(code)


def do_scan(argv):
    if not Path("deepsec.config.ts").is_file():
        sys.stderr.write("no deepsec.config.ts in the working directory\\n")
        sys.exit(3)
    step_failure("scan_exit", "scan")
    project = option(argv, "--project-id")
    root = option(argv, "--root")
    base = data_dir(project)
    write(base / "project.json", {"projectId": project, "rootPath": root,
                                  "createdAt": "2026-09-25T12:00:00.000Z"})
    for name in source_files(root):
        write(base / "files" / (name + ".json"), {
            "filePath": name, "projectId": project,
            "candidates": [{"vulnSlug": "command-injection", "lineNumbers": [4],
                            "snippet": "exec(", "matchedPattern": "shell exec"},
                           {"vulnSlug": "sql-injection", "lineNumbers": [9, 11],
                            "snippet": "query(", "matchedPattern": "string-built query"}],
            "lastScannedAt": "2026-09-25T12:00:00.000Z",
            "lastScannedRunId": "20260925120000-scan",
            "fileHash": "0" * 64, "findings": [], "analysisHistory": [], "status": "pending"})
    write(base / "runs" / "20260925120000-scan.json", {
        "runId": "20260925120000-scan", "projectId": project, "rootPath": root,
        "createdAt": "2026-09-25T12:00:00.000Z", "completedAt": "2026-09-25T12:00:05.000Z",
        "type": "scan", "phase": "done", "scannerConfig": {"matcherSlugs": ["command-injection"]}})
    print("scanned %d file(s)" % len(source_files(root)))


def do_process(argv):
    step_failure("process_exit", "process")
    settings = control()
    project = option(argv, "--project-id")
    model = option(argv, "--model")
    root = option(argv, "--root")
    base = data_dir(project)
    limit = int(option(argv, "--limit", "1000"))
    batch_size = int(option(argv, "--batch-size", "5"))
    names = sorted(p.relative_to(base / "files").as_posix()[:-5]
                   for p in (base / "files").rglob("*.json"))[:limit]
    run_id = "20260925120100-process"
    sessions = settings.get("session_ids") or ["session-aaaa", "session-bbbb"]
    lines = settings.get("lines", [4])
    batches = [names[i:i + batch_size] for i in range(0, len(names), batch_size)]
    for index, batch in enumerate(batches):
        session = sessions[index % len(sessions)]
        share = float(len(batch)) or 1.0
        for name in batch:
            path = base / "files" / (name + ".json")
            record = json.loads(path.read_text(encoding="utf-8"))
            entry = {"runId": run_id, "investigatedAt": "2026-09-25T12:01:00.000Z",
                     "durationMs": 9000.0 / share, "durationApiMs": 6000.0 / share,
                     "agentType": "claude-agent-sdk", "model": model,
                     "modelConfig": {"model": model}, "agentSessionId": session,
                     "findingCount": 1, "numTurns": 4.0 / share, "phase": "process",
                     "costUsd": 0.12 / share,
                     "usage": {"inputTokens": 1000.0 / share, "outputTokens": 200.0 / share,
                               "cacheReadInputTokens": 40.0 / share,
                               "cacheCreationInputTokens": 8.0 / share}}
            if settings.get("refusal") and name == batch[0]:
                entry["refusal"] = {"refused": True, "reason": "the file was not readable",
                                    "skipped": [{"filePath": name, "reason": "unreadable"}]}
            record["analysisHistory"].append(entry)
            record["findings"] = [{
                "severity": "HIGH", "vulnSlug": "command-injection",
                "title": "Shell command built from request input in " + name,
                "description": "The handler passes request input to a shell.",
                "lineNumbers": list(lines), "recommendation": "Use an argv array.",
                "confidence": "high", "producedByRunId": run_id,
                "findingId": "finding_" + str(abs(hash(name)) % (16 ** 16)).rjust(16, "0")[:16]}]
            record["status"] = "error" if (settings.get("file_error") and name == names[0]) else "analyzed"
            write(path, record)
    write(base / "runs" / (run_id + ".json"), {
        "runId": run_id, "projectId": project, "rootPath": root,
        "createdAt": "2026-09-25T12:01:00.000Z", "completedAt": "2026-09-25T12:02:00.000Z",
        "type": "process", "phase": "done",
        "processorConfig": {"agentType": "claude-agent-sdk", "model": model, "modelConfig": {}}})
    transcripts = settings.get("transcript_dir")
    if transcripts:
        # What the Claude Agent SDK leaves behind: the session transcript, with every path it
        # read written under the platform's REAL path, which is not the path deepsec was handed.
        real = os.path.realpath(root)
        for session in sessions[:len(batches)]:
            out = Path(transcripts) / "slug-for-the-cwd" / (session + ".jsonl")
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("\\n".join(json.dumps(record) for record in [
                {"type": "assistant", "uuid": "u1", "sessionId": session, "message": {
                    "role": "assistant", "model": model,
                    "usage": {"input_tokens": 17, "output_tokens": 3652,
                              "cache_read_input_tokens": 55807,
                              "cache_creation_input_tokens": 13211},
                    "content": [{"type": "tool_use", "id": "toolu_1", "name": "Read",
                                 "input": {"file_path": real + "/src/server.js"}}]}},
                {"type": "user", "uuid": "u2", "sessionId": session, "message": {
                    "role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": "toolu_1",
                         "content": "     1\\tconst x = 1;\\n"}]},
                 "toolUseResult": {"file": {"filePath": real + "/src/server.js",
                                            "startLine": 1, "numLines": 1,
                                            "content": "const x = 1;\\n"}}},
            ]) + "\\n", encoding="utf-8")
    if settings.get("parse_error"):
        dump = base / "debug" / "parse-error-investigate-2026-09-25T12-01-30-000Z.txt"
        dump.parent.mkdir(parents=True, exist_ok=True)
        dump.write_text("# deepsec parse-failure debug dump\\n# phase: investigate\\n", encoding="utf-8")
    print("processed %d file(s)" % len(names))


def do_export(argv):
    step_failure("export_exit", "export")
    settings = control()
    project = option(argv, "--project-id")
    out = option(argv, "--out")
    base = data_dir(project)
    if settings.get("no_export"):
        print("wrote nothing on purpose")
        return
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    if settings.get("bad_export"):
        Path(out).write_text("this is not json\\n", encoding="utf-8")
        return
    findings = []
    for path in sorted((base / "files").rglob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        for finding in record.get("findings", []):
            findings.append({
                "title": "[%s] %s" % (finding["severity"], finding["title"]),
                "description": "**File:** `%s`\\n\\n## Finding\\n\\n%s" % (record["filePath"],
                                                                          finding["description"]),
                "severity": finding["severity"],
                "labels": ["security", "project:" + project],
                "metadata": {"projectId": project, "filePath": record["filePath"],
                             "lineNumbers": finding["lineNumbers"], "severity": finding["severity"],
                             "vulnSlug": finding["vulnSlug"], "confidence": finding["confidence"],
                             "discoveredAt": "2026-09-25T12:01:00.000Z",
                             "runId": "20260925120100-process"}})
    Path(out).write_text(json.dumps(findings, indent=2) + "\\n", encoding="utf-8")
    print("Exported %d finding(s)" % len(findings))


argv = sys.argv[1:]
if "--version" in argv or "-V" in argv:
    print("2.3.10")
elif argv and argv[0] == "scan":
    do_scan(argv)
elif argv and argv[0] == "process":
    do_process(argv)
elif argv and argv[0] == "export":
    do_export(argv)
else:
    sys.stderr.write("fake deepsec: unknown command %r\\n" % argv)
    sys.exit(2)
'''


def fake_deepsec_root(tmp_path: Path, **control) -> Path:
    """A DeepSec installation whose executable is the fake CLI above, with its control file."""
    root = tmp_path / "deepsec-workspace-install"
    binary = root / "node_modules" / ".bin" / "deepsec"
    binary.parent.mkdir(parents=True)
    binary.write_text(f"#!{sys.executable}\n{FAKE_CLI}", encoding="utf-8")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    (binary.parent / "control.json").write_text(json.dumps(control), encoding="utf-8")
    package = root / "node_modules" / "deepsec"
    package.mkdir(parents=True)
    (package / "package.json").write_text(json.dumps({"name": "deepsec", "version": "2.3.10"}),
                                          encoding="utf-8")
    return root


def prepared_input(tmp_path: Path) -> PreparedInput:
    source = tmp_path / "trial" / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "server.js").write_text(
        "const { exec } = require('child_process');\n"
        "const express = require('express');\nconst app = express();\n"
        "app.get('/run', (req, res) => { exec(req.query.cmd, (e, out) => res.send(out)); });\n"
        "app.listen(3000);\n", encoding="utf-8")
    (source / "src" / "db.js").write_text(
        "module.exports = (db, id) => db.query('select * from t where id = ' + id);\n",
        encoding="utf-8")
    (source / "README.md").write_text("# fixture\n", encoding="utf-8")
    return PreparedInput("fixture-js", source, hash_exported_tree(source)["tree_hash"],
                         ("javascript",), {"source": {"commit": "fixture"}})


def system_spec(root: Path, **overrides) -> SystemSpec:
    config = {"deepsec_root": str(root), "model": "claude-haiku-4-5", "agent": "claude",
              "thinking_level": "low", "limit": 6, "batch_size": 3, "concurrency": 1,
              "max_turns": 60}
    config.update(overrides)
    return SystemSpec("deepsec-fake", "deepsec", config)


def invoke(tmp_path: Path, root: Path, *, trace_mode: str = "content", out: str = "out",
           timeout_seconds: float = 300, workspace_root: Path | None = None, **overrides) -> Path:
    adapter = get_adapter("deepsec")
    spec = system_spec(root, **overrides)
    preparation = adapter.prepare(spec, tmp_path / "cache")
    return run_invocation(prepared=prepared_input(tmp_path), adapter=adapter, spec=spec,
                          preparation=preparation, out_dir=tmp_path / out, run_id="run-deepsec",
                          timeout_seconds=timeout_seconds, trace_mode=trace_mode,
                          network_policy="model_provider_only", workspace_root=workspace_root,
                          clock=CLOCK)


def linked_workspace_root(tmp_path: Path) -> Path:
    """A directory reached through a symbolic link, so the handed path is not the real one.

    This is the macOS ``/var`` → ``/private/var`` situation made deterministic on any POSIX
    platform: a scan run under this root is handed a path whose ``resolve()`` differs.
    """
    real = tmp_path / "real-workspaces"
    real.mkdir()
    link = tmp_path / "linked-workspaces"
    link.symlink_to(real, target_is_directory=True)
    return link


def collector_accepts_several_spellings() -> bool:
    """Whether WP-D's importers take a sequence of workspace roots yet."""
    import inspect
    import scaneval.collectors as collectors
    from scaneval.collectors import claude_code

    if hasattr(collectors, "workspace_roots"):
        return True
    parameter = inspect.signature(claude_code.import_transcript).parameters["workspace_root"]
    return "Sequence" in str(parameter.annotation)


def documents(bundle: Path) -> tuple[dict, dict]:
    return (load_document(bundle / "result.json", "scan-result"),
            load_document(bundle / "execution.json", "execution-record"))


def trace_events(bundle: Path) -> list[dict]:
    text = (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


# --- the transcript collector stub ------------------------------------------------------


@dataclass
class StubSummary:
    """The shape of WP-D's ``ImportSummary`` this adapter reads, and nothing more."""

    malformed_lines: int = 0
    unmatched_tool_results: int = 0
    events: int = 2
    capture: dict = field(default_factory=dict)


def transcript_fixture(tmp_path: Path) -> Path:
    """A tiny synthetic Claude Code transcript, structured as WP-D's importer expects one.

    The stub importer below does not parse it, so this exists to prove a real path is passed
    through unchanged. It is synthetic: no real session content, no operator paths.
    """
    path = tmp_path / "transcripts" / "session-aaaa.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(record) for record in [
        {"type": "assistant", "uuid": "u1", "message": {
            "role": "assistant", "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 1000, "output_tokens": 200,
                      "cache_read_input_tokens": 40, "cache_creation_input_tokens": 8},
            "content": [{"type": "tool_use", "id": "toolu_1", "name": "Read",
                         "input": {"file_path": "src/server.js"}}]}},
        {"type": "user", "uuid": "u2", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}]},
         "toolUseResult": {"file": {"filePath": "src/server.js", "startLine": 1,
                                    "numLines": 5, "content": "const x = 1;\n"}}},
    ]) + "\n", encoding="utf-8")
    return path


def stub_collector(monkeypatch, tmp_path: Path, *, found: bool = True, subagent: bool = False,
                   malformed: int = 0, unmatched: int = 0) -> list[dict]:
    """Replace the collector with a recording stub and return the list of calls it saw."""
    calls: list[dict] = []
    main = transcript_fixture(tmp_path)
    sub = main.parent / "session-aaaa" / "subagents" / "agent-1.jsonl"
    if subagent:
        sub.parent.mkdir(parents=True, exist_ok=True)
        sub.write_text(main.read_text(encoding="utf-8"), encoding="utf-8")

    def find_transcripts(session_id, *, projects_dir=None):
        calls.append({"call": "find", "session_id": session_id, "projects_dir": projects_dir})
        if not found:
            return []
        return [main, sub] if subagent else [main]

    def import_transcript(observer, path, *, workspace_root, call_id, sidechain=False,
                          agent_id=None):
        # A sequence of spellings, exactly as WP-D's importers now accept it. Recorded as a
        # tuple of paths so a test can say which spellings the adapter offered and in what
        # order; a bare path is normalized to a one-tuple so an older collector still reads.
        roots = (workspace_root,) if isinstance(workspace_root, (str, Path)) else tuple(workspace_root)
        calls.append({"call": "import", "observer": observer, "path": Path(path),
                      "workspace_roots": tuple(Path(root) for root in roots), "call_id": call_id,
                      "sidechain": sidechain, "agent_id": agent_id})
        observer.emit(type="tool.start", category="tool", capture_status="partial",
                      call_id="toolu_1", metadata={"source": "claude_code_transcript",
                                                   "tool_name": "Read",
                                                   "input_summary": "src/server.js",
                                                   "sidechain": sidechain, "agent_id": agent_id})
        observer.emit(type="tool.end", category="tool", capture_status="partial",
                      call_id="toolu_1", metadata={"source": "claude_code_transcript",
                                                   "is_error": False, "result_chars": 13})
        return StubSummary(malformed_lines=malformed, unmatched_tool_results=unmatched)

    monkeypatch.setattr(deepsec_module, "collector", lambda: (find_transcripts, import_transcript))
    return calls


# --- registration and configuration -----------------------------------------------------


def test_the_adapter_is_registered_under_the_name_runs_ask_for():
    assert "deepsec" in adapter_names()
    adapter = get_adapter("deepsec")
    assert adapter.name == "deepsec"
    assert isinstance(adapter.adapter_version, str) and adapter.adapter_version
    # Node executes what NODE_OPTIONS names, so it must never reach the scanner from the
    # operator's environment while the record shows only the variable's name.
    assert "NODE_OPTIONS" not in adapter.env_passthrough
    assert "ANTHROPIC_API_KEY" in adapter.env_passthrough


def test_configuration_is_validated_before_anything_runs(tmp_path):
    with pytest.raises(AdapterError, match="deepsec_root"):
        settings(SystemSpec("s", "deepsec", {"model": "m"}))
    with pytest.raises(AdapterError, match="does not exist"):
        settings(SystemSpec("s", "deepsec", {"deepsec_root": str(tmp_path / "nope"), "model": "m"}))
    root = fake_deepsec_root(tmp_path)
    with pytest.raises(AdapterError, match="config.model is required"):
        settings(SystemSpec("s", "deepsec", {"deepsec_root": str(root)}))
    with pytest.raises(AdapterError, match="config.agent"):
        settings(system_spec(root, agent="gemini"))
    with pytest.raises(AdapterError, match="config.thinking_level"):
        settings(system_spec(root, thinking_level="enormous"))
    with pytest.raises(AdapterError, match="config.limit must be at least 1"):
        settings(system_spec(root, limit=0))
    with pytest.raises(AdapterError, match="project_id"):
        settings(system_spec(root, project_id="../escape"))


def test_a_deepsec_root_written_with_a_tilde_is_expanded_rather_than_taken_literally(tmp_path, monkeypatch):
    """The frozen run configuration writes the root with a leading ``~`` on purpose.

    A path that stayed literal would name a directory called ``~`` under the process's working
    directory, which exists on nobody's machine, so the failure would arrive as a missing
    workspace rather than as the configuration mistake it is not.
    """
    root = fake_deepsec_root(tmp_path)
    monkeypatch.setenv("HOME", str(root.parent))
    monkeypatch.setattr(Path, "home", lambda: root.parent)
    resolved = settings(SystemSpec("s", "deepsec", {"deepsec_root": f"~/{root.name}", "model": "m"}))
    assert resolved.root == root.resolve()
    assert resolved.configured_root.startswith("~/")


def test_prepare_records_both_versions_and_refuses_an_installation_without_the_executable(tmp_path):
    adapter = get_adapter("deepsec")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(AdapterError, match="executable not found"):
        adapter.prepare(system_spec(empty), tmp_path / "cache")
    root = fake_deepsec_root(tmp_path)
    preparation = adapter.prepare(system_spec(root), tmp_path / "cache")
    assert preparation["deepsec"]["cli_version"] == "2.3.10"
    assert preparation["deepsec"]["package_version"] == "2.3.10"
    assert preparation["deepsec"]["root"] == str(root.resolve())
    assert preparation["model"] == "claude-haiku-4-5" and preparation["agent"] == "claude"


def test_a_non_executable_deepsec_is_a_setup_failure_rather_than_a_scan_that_produced_nothing(tmp_path):
    root = fake_deepsec_root(tmp_path)
    binary = root / "node_modules" / ".bin" / "deepsec"
    binary.chmod(0o644)
    with pytest.raises(AdapterError, match="not executable"):
        get_adapter("deepsec").prepare(system_spec(root), tmp_path / "cache")


def test_the_project_id_is_derived_from_the_input_hash_because_the_request_carries_no_snapshot_id():
    request = {"run_id": "r", "input": {"tree_hash": "sha256:" + "ab" * 32}}
    derived = project_id_for(request, None)
    assert derived == "scaneval-abababababababab"
    assert deepsec_module.PROJECT_ID.match(derived)
    assert project_id_for(request, "chosen-name") == "chosen-name"


def test_the_generated_config_declares_one_project_no_plugins_and_the_local_route(tmp_path):
    text = workspace_config("scaneval-abc", tmp_path / "src", "claude", "claude-haiku-4-5")
    assert 'import { defineConfig } from "deepsec/config";' in text
    assert '"claude-agent-sdk"' in text and '"claude-haiku-4-5"' in text
    assert '"scaneval-abc"' in text and json.dumps(str(tmp_path / "src")) in text
    assert 'ai: { mode: "local", provider: "local" }' in text
    assert "plugins: []" in text


# --- a whole run ------------------------------------------------------------------------


def test_a_clean_run_produces_claims_artifacts_and_a_trace_of_what_deepsec_recorded(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    calls = stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    result, execution = documents(bundle)

    assert result["status"] == "success", execution["error"]
    assert execution["adapter"]["name"] == "deepsec"
    assert execution["provenance"]["source_modified"] is False
    assert execution["timed_out"] is False

    # Two source files, one finding each, both joined to the native id in the file records.
    assert len(result["claims"]) == 2
    registered = {artifact["id"]: artifact["path"] for artifact in execution["raw_artifacts"]}
    for claim in result["claims"]:
        assert claim["native_rule_id"] == "deepsec:command-injection"
        assert claim["claim_id"].startswith("finding_") and claim["native_id"] == claim["claim_id"]
        assert claim["primary_location"]["start_line"] == claim["primary_location"]["end_line"] == 4
        assert claim["primary_location"]["path"].startswith("src/")
        assert claim["native_severity"] == "HIGH"
        assert not claim["allegation"].startswith("[HIGH]"), "the rendered severity prefix is dropped"
        assert claim["raw_artifact_id"] in registered
        assert (bundle / registered[claim["raw_artifact_id"]]).is_file()

    # The records DeepSec wrote are all registered where it wrote them.
    assert "deepsec-export" in registered and "deepsec-config" in registered
    assert any(name.startswith("deepsec-file/") for name in registered)
    assert any(name.startswith("deepsec-run/") for name in registered)
    assert "deepsec-project/project.json" in registered, "whatever the project directory holds"
    assert "deepsec-scan-stdout" in registered and "deepsec-process-stderr" in registered
    for artifact in execution["raw_artifacts"]:
        assert (bundle / artifact["path"]).is_file(), artifact
    assert not any("declared artifact missing" in note for note in execution["notes"]), execution["notes"]

    # The private workspace is in the raw output and nowhere else.
    workspace = bundle / "raw" / "deepsec-workspace"
    assert (workspace / "deepsec.config.ts").is_file()
    assert (workspace / "data").is_dir()
    assert not (workspace / "node_modules").exists(), "the node_modules link is cut on the way in"

    # Usage is the per-file shares summed back into batch totals, and says it is an estimate.
    assert result["usage"]["cost_usd"] == pytest.approx(0.12)
    assert result["usage"]["input_tokens"] == 1000 and result["usage"]["output_tokens"] == 200
    assert any("estimate" in note for note in execution["notes"])

    assert execution["model_identity"] == {
        "requested": "claude-haiku-4-5", "resolved": "claude-haiku-4-5",
        "verification": "self_reported",
        "notes": execution["model_identity"]["notes"]}
    assert "harness_reported" in execution["model_identity"]["notes"][0]

    assert execution["capture"]["tool_calls"] == "complete"
    assert execution["capture"]["finding_candidate"] == "complete"
    assert execution["capture"]["finding_submitted"] == "complete"
    assert execution["capture"]["finding_validation"] == "unavailable"
    assert execution["trace"]["capture_gap"] is False and execution["trace"]["dropped_events"] == 0

    events = trace_events(bundle)
    assert execution["trace"]["events"] == len(events)
    assert [event["sequence"] for event in events] == list(range(len(events)))
    assert all(event["run_id"] == "run-deepsec" for event in events)
    assert all(event["producer_id"] in ("deepsec-adapter",) for event in events)
    types = [event["type"] for event in events]
    assert types.count("finding.candidate") == 4, "two candidates on each of two files"
    assert types.count("finding.submitted") == 2
    assert "tool.start" in types, "the stub importer's events land in the same trace"

    # The session's transcript imported, so the transcript is the record of that call and this
    # adapter adds no summed pair beside it: one model call is described once.
    assert "model.request" not in types and "model.response" not in types

    # Everything the adapter itself emitted says where it came from.
    own = [event for event in events if event["metadata"].get("source") == "harness_record"]
    assert len(own) == len(events) - 2

    submitted = [event for event in events if event["type"] == "finding.submitted"]
    assert {event["claim_id"] for event in submitted} == {c["claim_id"] for c in result["claims"]}
    for event in submitted:
        assert event["candidate_id"] == event["claim_id"]
        assert event["metadata"]["disposition"] == "new"
        # Line 4 is the command-injection candidate's line, not the sql-injection one's.
        assert event["metadata"]["candidate_ids"] == [
            f"{event['metadata']['file_path']}#command-injection#4"]
    candidates = [event for event in events if event["type"] == "finding.candidate"]
    assert len({event["candidate_id"] for event in candidates}) == len(candidates)

    # The transcript import was handed the observer, the real path, the scanned workspace root
    # and the session's own call id.
    imports = [call for call in calls if call["call"] == "import"]
    assert len(imports) == 1
    assert imports[0]["path"].name == "session-aaaa.jsonl"
    assert imports[0]["call_id"].endswith("/session-aaaa")
    assert imports[0]["sidechain"] is False and imports[0]["agent_id"] is None
    assert [call["session_id"] for call in calls if call["call"] == "find"] == ["session-aaaa"]

    # Both spellings of the workspace are offered, the handed one first, because the SDK writes
    # the transcript under the real one and the collectors match textually.
    roots = imports[0]["workspace_roots"]
    assert 1 <= len(roots) <= 2 and len(roots) == len(set(roots)), roots
    assert all(root.name == "source" and root.is_absolute() for root in roots), roots
    assert roots[-1] == roots[-1].resolve(), "the real path is the last spelling offered"
    assert any("Transcript paths were matched against" in note for note in execution["notes"])


def test_no_trace_event_carries_the_operator_home_directory(tmp_path, monkeypatch):
    """A trace is shared evidence; a path into somebody's home is not part of the run."""
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    text = (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8")
    assert str(Path.home()) not in text
    for event in trace_events(bundle):
        for path in event["metadata"].get("batch_paths", []):
            assert not path.startswith("/") and ".." not in path.split("/")


def test_nothing_the_run_does_is_written_into_the_deepsec_installation(tmp_path, monkeypatch):
    """The operator's DeepSec workspace is read-only to this adapter, data directory included."""
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)

    def snapshot() -> dict[str, tuple[int, int]]:
        return {str(p.relative_to(root)): (p.stat().st_size, p.stat().st_mtime_ns)
                for p in sorted(root.rglob("*")) if p.is_file()}

    before = snapshot()
    invoke(tmp_path, root)
    assert snapshot() == before
    assert not (root / "data").exists()


def test_a_subagent_transcript_is_imported_as_a_sidechain_with_its_agent_id(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path, session_ids=["session-aaaa"])
    calls = stub_collector(monkeypatch, tmp_path, subagent=True)
    invoke(tmp_path, root)
    imports = [call for call in calls if call["call"] == "import"]
    assert [(call["sidechain"], call["agent_id"]) for call in imports] == [(False, None), (True, "agent-1")]
    assert {call["call_id"] for call in imports} == {imports[0]["call_id"]}, "one call id per session"


def test_the_configured_projects_directory_is_the_one_the_collector_is_asked_about(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    calls = stub_collector(monkeypatch, tmp_path)
    invoke(tmp_path, root, claude_projects_dir=str(tmp_path / "elsewhere"))
    assert all(call["projects_dir"] == tmp_path / "elsewhere"
               for call in calls if call["call"] == "find")


def test_a_run_with_no_transcript_leaves_tool_calls_unavailable_and_says_so(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path, found=False)
    bundle = invoke(tmp_path, root)
    result, execution = documents(bundle)
    assert result["status"] == "success"
    assert execution["capture"]["tool_calls"] == "unavailable"
    assert execution["capture"]["context_selection"] == "unavailable"
    assert execution["capture"]["finding_candidate"] == "complete"
    assert any("0 of 1 agent session" in note or "0 of 2 agent session" in note
               for note in execution["notes"]), execution["notes"]


def test_a_missing_transcript_collector_costs_the_import_and_not_the_scan(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    monkeypatch.setattr(deepsec_module, "collector", lambda: None)
    bundle = invoke(tmp_path, root)
    result, execution = documents(bundle)
    assert result["status"] == "success", execution["error"]
    assert execution["capture"]["tool_calls"] == "unavailable"
    assert any("transcript collector is not installed" in note for note in execution["notes"])
    assert len(result["claims"]) == 2, "the claims do not depend on the transcript import"


def test_an_import_that_reported_malformed_lines_is_partial_rather_than_complete(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path, malformed=3)
    bundle = invoke(tmp_path, root)
    _result, execution = documents(bundle)
    assert execution["capture"]["tool_calls"] == "partial"
    assert any("malformed" in note for note in execution["notes"]), execution["notes"]


def test_trace_off_writes_no_trace_and_claims_no_observation(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root, trace_mode="off")
    result, execution = documents(bundle)
    assert result["status"] == "success", execution["error"]
    assert execution["trace"] is None
    assert set(execution["capture"].values()) == {"unavailable"}
    assert not (bundle / "trace").exists()
    assert len(result["claims"]) == 2, "claims do not depend on tracing"


# --- how a run fails --------------------------------------------------------------------


def test_a_non_zero_process_exit_is_an_error_naming_the_step(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path, process_exit=4)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    result, execution = documents(bundle)
    assert result["status"] == "error"
    assert result["error"]["code"] == "process_exit_4"
    assert "failed on purpose" in result["error"]["message"]
    assert result["claims"] == []
    assert execution["exit_code"] == 4
    # The evidence of the failed step is still in the bundle.
    registered = {artifact["id"] for artifact in execution["raw_artifacts"]}
    assert {"deepsec-scan-stdout", "deepsec-process-stderr"} <= registered


def test_a_failed_scan_never_reaches_the_later_steps_and_is_named_as_the_scan(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path, scan_exit=3)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    result, _execution = documents(bundle)
    assert result["status"] == "error" and result["error"]["code"] == "scan_exit_3"
    assert "deepsec scan exited 3" in result["error"]["message"]


def test_an_export_that_cannot_be_read_is_never_a_successful_scan(tmp_path, monkeypatch):
    stub_collector(monkeypatch, tmp_path)
    missing = fake_deepsec_root(tmp_path / "a", no_export=True)
    result, _ = documents(invoke(tmp_path / "a", missing, out="out-missing"))
    assert result["status"] == "error" and result["error"]["code"] == "unreadable_export"
    assert result["claims"] == []

    broken = fake_deepsec_root(tmp_path / "b", bad_export=True)
    result, _ = documents(invoke(tmp_path / "b", broken, out="out-broken"))
    assert result["status"] == "error" and result["error"]["code"] == "unreadable_export"
    assert "not readable JSON" in result["error"]["message"]


def test_a_step_that_exhausts_the_shared_budget_is_a_timeout(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path, hang="process")
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root, timeout_seconds=3)
    result, execution = documents(bundle)
    assert result["status"] == "timeout" and result["error"]["code"] == "timeout"
    assert "deepsec process" in result["error"]["message"]
    assert execution["timed_out"] is True


@pytest.mark.parametrize("knob,detail", [
    ("file_error", "status 'error'"),
    ("parse_error", "parse-failure dump"),
    ("refusal", "refusal"),
])
def test_a_batch_that_reached_no_verdict_makes_the_run_partial(tmp_path, monkeypatch, knob, detail):
    """A file with no verdict is not a quiet file: the scan covered less than it was given."""
    root = fake_deepsec_root(tmp_path, **{knob: True})
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    result, execution = documents(bundle)
    assert result["status"] == "partial"
    assert result["error"]["code"] == "deepsec_batches_failed"
    assert detail in result["error"]["message"] or detail in " ".join(execution["notes"])
    assert result["claims"], "the findings DeepSec did produce are still reported"
    assert execution["capture"]["finding_submitted"] == "partial"


def test_a_parse_failure_dump_is_an_observer_error_and_never_shaped_like_an_attempt(tmp_path, monkeypatch):
    """DeepSec failing to read its own agent's output is not a model attempt.

    It used to be emitted as a ``model.response`` with no request, so anything counting
    attempts over the trace counted it as one, and the pairing every other response keeps was
    broken by an event that was never a call.
    """
    root = fake_deepsec_root(tmp_path, parse_error=True)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    _result, execution = documents(bundle)
    assert any(artifact["id"].startswith("deepsec-debug/") for artifact in execution["raw_artifacts"])
    events = trace_events(bundle)
    failures = [event for event in events if event["type"] == "observer.error"]
    assert len(failures) == 1
    assert failures[0]["category"] == "observer"
    assert failures[0]["capture_status"] == "unavailable"
    assert failures[0]["metadata"]["error_code"] == "agent_output_parse_failure"
    assert failures[0]["metadata"]["source"] == "harness_record"
    assert failures[0]["metadata"]["debug_dump"].startswith("parse-error-")
    assert "call_id" not in failures[0], "nothing here is a call"
    assert not any(event["metadata"].get("failure_kind") == "parse_error" for event in events)


def test_a_refusal_rides_on_the_call_s_own_response_and_every_response_is_paired(tmp_path, monkeypatch):
    """A refusal is a fact about the call that happened, not a second attempt at it.

    It used to be a ``model.response`` with an attempt id no request ever carried, so the trace
    held responses that paired with nothing and an accounting over attempts counted one call
    twice. The facts now ride on the response the call already has.
    """
    root = fake_deepsec_root(tmp_path, refusal=True)
    stub_collector(monkeypatch, tmp_path, found=False)
    bundle = invoke(tmp_path, root)
    events = trace_events(bundle)
    requests = {(event["call_id"], event["attempt_id"]) for event in events
                if event["type"] == "model.request"}
    responses = {(event["call_id"], event["attempt_id"]) for event in events
                 if event["type"] == "model.response"}
    assert responses and responses == requests, "every response pairs with a request"
    refused = [event for event in events if event["metadata"].get("refusals")]
    assert refused, "the refusal is recorded on the response of the call it belongs to"
    reported = refused[0]["metadata"]["refusals"][0]
    assert reported["reason_code"] == "refused_with_skipped_files"
    assert reported["file_path"] == "src/db.js", "the path is where DeepSec put the record"
    assert reported["summary"] == "the file was not readable"
    assert refused[0]["metadata"]["failure_kind"] == "refusal"
    assert refused[0]["metadata"]["is_error"] is True


def test_a_record_that_is_not_a_regular_file_is_counted_rather_than_opened(tmp_path, monkeypatch):
    """A named pipe where a FileRecord belongs must not block the invocation forever."""
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    adapter = get_adapter("deepsec")
    spec = system_spec(root)
    preparation = adapter.prepare(spec, tmp_path / "cache")
    original = deepsec_module.run_command

    def run_command(argv, **kwargs):
        result = original(argv, **kwargs)
        if argv[1] == "export":
            # Planted after the last step, which is when DeepSec itself could have left one and
            # is the only moment that does not also block the fake CLI's own export read.
            records = sorted((Path(kwargs["cwd"]) / "data").rglob("files/**/*.json"))
            os.mkfifo(records[0].with_name("blocked.json"))
        return result

    monkeypatch.setattr(deepsec_module, "run_command", run_command)
    bundle = run_invocation(prepared=prepared_input(tmp_path), adapter=adapter, spec=spec,
                            preparation=preparation, out_dir=tmp_path / "out",
                            run_id="run-deepsec", timeout_seconds=120, trace_mode="content",
                            network_policy="model_provider_only", clock=CLOCK)
    result, execution = documents(bundle)
    assert result["status"] == "partial" and result["error"]["code"] == "import_loss"
    assert any("blocked.json" in note for note in execution["notes"]), execution["notes"]
    assert result["bundles_resolved"] is False


# --- the importer on its own ------------------------------------------------------------


def test_a_finding_that_cited_no_line_stays_file_level_and_says_so():
    payload = [{"title": "[HIGH] Something", "description": "d", "severity": "HIGH",
                "metadata": {"filePath": "src/a.py", "lineNumbers": [], "severity": "HIGH",
                             "vulnSlug": "sql-injection", "confidence": "low"}}]
    imported = import_export(payload)
    assert imported.lost == 0
    assert imported.claims[0]["primary_location"] == {"path": "src/a.py"}
    assert any("cited no line number" in note for note in imported.notes)


def test_one_line_number_is_a_single_line_claim_and_several_span_the_outermost():
    single = import_export([{"title": "[LOW] t", "description": "", "metadata": {
        "filePath": "a.py", "lineNumbers": [7], "vulnSlug": "x", "severity": "LOW"}}])
    assert single.claims[0]["primary_location"] == {"path": "a.py", "start_line": 7, "end_line": 7}
    several = import_export([{"title": "[LOW] t", "description": "", "metadata": {
        "filePath": "a.py", "lineNumbers": [9, 2, 5], "vulnSlug": "x", "severity": "LOW"}}])
    assert several.claims[0]["primary_location"] == {"path": "a.py", "start_line": 2, "end_line": 9}


def test_an_export_entry_whose_path_leaves_the_tree_is_import_loss_and_not_a_claim():
    imported = import_export([
        {"title": "[HIGH] a", "description": "", "metadata": {"filePath": "/etc/shadow",
                                                              "lineNumbers": [1], "vulnSlug": "x"}},
        {"title": "[HIGH] b", "description": "", "metadata": {"filePath": "../out.py",
                                                              "lineNumbers": [1], "vulnSlug": "x"}},
        {"title": "[HIGH] c", "description": "", "metadata": "not an object"},
        "not an object at all",
    ])
    assert imported.claims == [] and imported.lost == 4
    assert any("absolute path" in note for note in imported.notes)
    assert any("'..' segment" in note for note in imported.notes)


def test_a_finding_is_joined_to_the_native_id_the_file_records_hold_and_noted_when_it_is_not():
    files = (("src/a.py.json", {"filePath": "./src/a.py", "findings": [
        {"title": "Shell injection", "findingId": "finding_deadbeefdeadbeef"}]}),)
    index = finding_ids(files)
    assert index[("src/a.py", "Shell injection")] == "finding_deadbeefdeadbeef"
    joined = import_export([{"title": "[HIGH] Shell injection", "description": "", "metadata": {
        "filePath": "src/a.py", "lineNumbers": [3], "vulnSlug": "command-injection"}}], ids=index)
    assert joined.claims[0]["native_id"] == "finding_deadbeefdeadbeef"
    assert joined.claims[0]["claim_id"] == "finding_deadbeefdeadbeef"
    stranger = import_export([{"title": "[HIGH] Other", "description": "", "metadata": {
        "filePath": "src/a.py", "lineNumbers": [3], "vulnSlug": "x"}}], ids=index)
    assert "native_id" not in stranger.claims[0]
    assert any("no native finding id" in note for note in stranger.notes)


def test_a_payload_that_is_not_an_array_of_findings_is_refused_rather_than_read_as_empty():
    with pytest.raises(AdapterError, match="not an array"):
        import_export({"findings": []})


def test_the_per_file_shares_of_one_batch_sum_back_to_the_batch(tmp_path):
    """DeepSec divides a batch's numbers across its files; one file's number measures nothing."""
    files = tuple((f"f{i}.py.json", {"filePath": f"f{i}.py", "analysisHistory": [{
        "runId": "r1", "agentSessionId": "s1", "model": "claude-haiku-4-5",
        "numTurns": 4 / 3, "costUsd": 0.09 / 3, "durationMs": 900.0 / 3,
        "durationApiMs": 600.0 / 3,
        "usage": {"inputTokens": 999 / 3, "outputTokens": 300 / 3,
                  "cacheReadInputTokens": 30 / 3, "cacheCreationInputTokens": 3 / 3}}]})
                 for i in range(3))
    sessions = sessions_from(files)
    assert len(sessions) == 1
    session = sessions[0]
    assert session.paths == ("f0.py", "f1.py", "f2.py")
    assert session.num_turns == pytest.approx(4.0)
    assert session.cost_usd == pytest.approx(0.09)
    assert session.usage == {"cache_creation_input_tokens": 3, "cache_read_input_tokens": 30,
                             "input_tokens": 999, "output_tokens": 300}
    assert session.model == "claude-haiku-4-5"
    assert session.call_id == "deepsec/r1/s1"


def test_a_session_whose_entries_disagree_about_the_model_reports_none():
    files = (("a.py.json", {"filePath": "a.py", "analysisHistory": [
        {"runId": "r", "agentSessionId": "s", "model": "one"},
        {"runId": "r", "agentSessionId": "s", "model": "two"}]}),)
    assert sessions_from(files)[0].model is None


def test_every_regex_candidate_is_read_with_the_id_a_submitted_finding_links_to():
    files = (("src/a.py.json", {"filePath": "src/a.py", "candidates": [
        {"vulnSlug": "sql-injection", "lineNumbers": [12, 14], "matchedPattern": "concat"}]}),)
    found = candidates_from(files)
    assert found == (Candidate("src/a.py", "sql-injection", (12, 14), ("concat",), 1),)
    assert found[0].candidate_id == "src/a.py#sql-injection#12"


def test_several_matchers_on_one_site_are_one_candidate_rather_than_colliding_ids():
    """A real DeepSec scan fires two `js-sql-raw` patterns on one line; the id names the site.

    Emitting one event per matcher hit would put two events carrying the same ``candidate_id``
    and different metadata into the same trace, which is a link nobody can follow.
    """
    files = (("src/a.js.json", {"filePath": "src/a.js", "candidates": [
        {"vulnSlug": "js-sql-raw", "lineNumbers": [5], "matchedPattern": ".query() concat"},
        {"vulnSlug": "js-sql-raw", "lineNumbers": [5], "matchedPattern": "generic .query()"},
        {"vulnSlug": "missing-auth", "lineNumbers": [4], "matchedPattern": "app handler"},
        {"vulnSlug": "missing-auth", "lineNumbers": [5], "matchedPattern": "app handler"}]}),)
    found = candidates_from(files)
    assert [candidate.candidate_id for candidate in found] == [
        "src/a.js#js-sql-raw#5", "src/a.js#missing-auth#4", "src/a.js#missing-auth#5"]
    assert found[0].hits == 2 and found[0].patterns == (".query() concat", "generic .query()")
    assert found[1].hits == 1


def test_a_slug_maps_to_a_kind_through_its_separators_and_an_unknown_one_stays_unmapped():
    assert kind_for_slug("sql-injection") == kind_for_slug("sqlinjection") != "unmapped"
    assert kind_for_slug("auth-bypass") != "unmapped"
    assert kind_for_slug("other-race-condition") == "unmapped"
    assert kind_for_slug(None) == "unmapped"


def test_a_path_that_cannot_name_a_file_inside_the_tree_is_returned_with_its_reason():
    assert claim_path("src/a.py") == ("src/a.py", "")
    assert claim_path(".//src/a.py") == ("src/a.py", "")
    assert claim_path("/abs")[1] == "it is an absolute path"
    assert claim_path("a/../../b")[1] == "it leaves the scanned tree through a '..' segment"
    assert claim_path("./")[1] == "it names nothing once its dot segments are removed"
    assert claim_path("a\x00b")[1].startswith("it holds a NUL byte")
    assert line_span("not a list") == (None, None)
    assert line_span([0, -3, True]) == (None, None)


# --- the capture matrix -----------------------------------------------------------------


def doc_table(header_first_cell: str) -> tuple[list[str], list[list[str]]]:
    """The one markdown table in ``docs/DEEPSEC.md`` whose first header cell is *header_first_cell*."""
    rows = [line for line in DOC.read_text(encoding="utf-8").splitlines() if line.startswith("|")]
    cells = [[cell.strip() for cell in line.strip("|").split("|")] for line in rows]
    for index, row in enumerate(cells):
        if row and row[0] == header_first_cell:
            body = []
            for candidate in cells[index + 1:]:
                if set("".join(candidate)) <= set("- "):
                    continue
                if len(candidate) != len(row):
                    break
                body.append(candidate)
            return row, body
    raise AssertionError(f"docs/DEEPSEC.md has no table headed {header_first_cell!r}")


def doc_values(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def documented_columns() -> dict[str, list[dict]]:
    """Every call each documented column stands for, built from the column table in the guide.

    The column definitions live in the document rather than here on purpose: a definition the
    test owned could be changed on one side alone, and then the guide could describe a column
    nothing ever checked.
    """
    header, rows = doc_table("Column")
    names = ("trace_mode", "transcripts_found", "sessions", "batches_failed", "imports_clean",
             "record_failures", "findings_lost", "capture_gap")
    assert header[1:] == [f"`{name}`" for name in names], header
    columns: dict[str, list[dict]] = {}
    for row in rows:
        calls = [{}]
        for name, cell in zip(names, row[1:], strict=True):
            values = [json.loads(value) for value in doc_values(cell)]
            assert values, (row[0], name, cell)
            calls = [{**call, name: value} for call in calls for value in values]
        columns[row[0]] = calls
    return columns


def test_the_documented_capture_matrix_is_the_one_capture_status_returns():
    """``docs/DEEPSEC.md`` is the only copy of this matrix, and this is what makes that true.

    Both tables are read out of the guide: the column definitions and the cells. Every run a
    column describes is built and compared against :func:`capture_status`, so a guide edited
    into disagreeing with the code fails here rather than being quoted by a reader.
    """
    columns = documented_columns()
    header, rows = doc_table("Event type")
    assert header[1] == "`capture_status` key"
    assert header[2:] == list(columns), (header[2:], list(columns))
    documented_keys: set[str] = set()
    for row in rows:
        keys = doc_values(row[1])
        documented_keys |= set(keys)
        for column, cell in zip(header[2:], row[2:], strict=True):
            expected = doc_values(cell)
            assert len(expected) == 1, (row[0], column, cell)
            for call in columns[column]:
                returned = capture_status(
                    call["trace_mode"],
                    **{name: call[name] for name in call if name != "trace_mode"})
                for key in keys:
                    assert returned[key] == expected[0], (row[0], column, key, call, returned[key])
    assert documented_keys == set(capture_status("off", transcripts_found=0, sessions=0,
                                                 batches_failed=0)), documented_keys


def test_two_claims_hold_across_the_whole_input_space_the_columns_only_sample():
    """What the guide says holds everywhere is driven everywhere, not only in the columns."""
    from itertools import product

    space = product(("off", "metadata", "content"), (0, 1, 2, 5), (0, 1, 2), (0, 1, 7),
                    (True, False), (0, 3), (0, 3), (True, False))
    for mode, transcripts, sessions, failed, clean, lost_records, lost_findings, gap in space:
        matrix = capture_status(mode, transcripts_found=transcripts, sessions=sessions,
                                batches_failed=failed, imports_clean=clean,
                                record_failures=lost_records, findings_lost=lost_findings,
                                capture_gap=gap)
        assert matrix["finding_validation"] == "unavailable"
        assert matrix["finding_filtered"] == "unavailable"
        if mode == "off":
            assert set(matrix.values()) == {"unavailable"}
            continue
        # No category claims completeness over a hole this run already reported.
        if gap:
            assert "complete" not in matrix.values(), (mode, gap, matrix)
        if lost_records:
            assert matrix["finding_candidate"] == "partial"
        if lost_findings or failed:
            assert matrix["finding_submitted"] == "partial"


def test_capture_status_refuses_a_trace_mode_no_run_can_have():
    with pytest.raises(AdapterError, match="unknown trace mode"):
        capture_status("verbose", transcripts_found=0, sessions=0, batches_failed=0)


def test_the_guide_describes_the_commands_the_adapter_actually_builds(tmp_path):
    """A document that named a flag the adapter never passes would mislead an operator."""
    text = DOC.read_text(encoding="utf-8")
    for flag in ("--project-id", "--root", "--agent", "--model", "--concurrency",
                 "--thinking-level", "--limit", "--batch-size", "--max-turns",
                 "--format json", "--out"):
        assert flag in text, flag
    for key in ("deepsec_root", "model", "agent", "thinking_level", "limit", "batch_size",
                "concurrency", "max_turns", "claude_projects_dir", "claude_code_executable"):
        assert f"`{key}`" in text, key


# --- the frozen pilot run ----------------------------------------------------------------


def test_the_frozen_pilot_run_configuration_validates_and_names_this_adapter():
    config = load_document(RUN_CONFIG, "run-config")
    system = config["systems"][0]
    assert system["adapter"] == "deepsec"
    assert system["config"]["deepsec_root"].startswith("~/")
    assert system["config"]["model"] == "claude-haiku-4-5"
    assert system["config"]["limit"] == 6 and system["config"]["batch_size"] == 3
    assert system["config"]["concurrency"] == 1 and system["config"]["max_turns"] == 60
    assert system["config"]["thinking_level"] == "low"
    assert config["trace_mode"] == "content"
    assert [entry["snapshot_id"] for entry in config["inputs"]] == [
        entry["snapshot_id"] for entry in
        load_document(RUN_CONFIG.with_name("run-harness.json"), "run-config")["inputs"]]
    assert config["pack"] == "pack.json"
    joined = " ".join(config["notes"]).lower()
    assert "cost" in joined and "estimate" in joined
    assert "pipeline exercise" in joined


def test_the_frozen_run_configuration_is_one_this_adapter_accepts(tmp_path):
    """The recorded configuration must survive the adapter's own validation, not just a schema."""
    config = load_document(RUN_CONFIG, "run-config")
    root = fake_deepsec_root(tmp_path)
    system = dict(config["systems"][0]["config"])
    system["deepsec_root"] = str(root)
    resolved = settings(SystemSpec("pilot", "deepsec", system))
    assert resolved.model == "claude-haiku-4-5" and resolved.thinking_level == "low"
    assert resolved.limit == 6 and resolved.batch_size == 3 and resolved.max_turns == 60
    assert resolved.projects_dir == Path("~/.claude/projects").expanduser()


# --- reads of the record tree -------------------------------------------------------------


def test_each_registered_artifact_is_the_file_its_record_was_read_from(tmp_path):
    """The name, the payload and the path have to travel together, whatever order disk gives.

    The walk visits directories off a stack, so a tree with two subdirectories is enumerated in
    the opposite order to the sorted names the records are reported in. Sorting the records and
    the paths as two separate lists made the artifact a claim cites depend on that order.
    """
    from scaneval.adapters.deepsec import read_records
    from scaneval.adapters.llm_harness import Enclosure

    data = tmp_path / "raw" / "data" / "p"
    for directory, name in (("a", "first"), ("z", "second"), ("", "third")):
        path = data / "files" / directory / f"{name}.js.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"filePath": f"{directory}/{name}.js".lstrip("/"),
                                    "candidates": [], "findings": [], "analysisHistory": []}),
                        encoding="utf-8")
    enclosure = Enclosure.capture(tmp_path / "raw", tmp_path / "raw")
    records = read_records(data, enclosure)
    assert records.failures == ()
    assert [name for name, _record in records.files] == [
        "a/first.js.json", "third.js.json", "z/second.js.json"]
    for artifact in records.artifacts:
        name = artifact["id"].split("/", 1)[1]
        stored = dict(records.files)[name]
        assert json.loads(Path(artifact["path"]).read_text(encoding="utf-8")) == stored


def test_a_revalidation_object_with_no_verdict_reads_as_reported_rather_than_the_string_none():
    imported = import_export([{"title": "[HIGH] t", "description": "", "metadata": {
        "filePath": "a.py", "lineNumbers": [1], "vulnSlug": "x", "revalidation": {}}}])
    assert imported.findings[0]["status"] == "reported"
    verdicts = import_export([{"title": "[HIGH] t", "description": "", "metadata": {
        "filePath": "a.py", "lineNumbers": [1], "vulnSlug": "x",
        "revalidation": {"verdict": "true-positive", "reasoning": "r"}}}])
    assert verdicts.findings[0]["status"] == "true-positive"


def test_a_trace_that_cannot_be_written_costs_the_trace_and_not_the_claims(tmp_path, monkeypatch):
    """Instrumentation may never discard the claims the import already built."""
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)

    def explode(**_kwargs):
        raise RuntimeError("the sink is on fire")

    monkeypatch.setattr(deepsec_module, "write_trace", explode)
    bundle = invoke(tmp_path, root)
    result, execution = documents(bundle)
    assert len(result["claims"]) == 2, "the claims survive a failed trace"
    assert any("the trace could not be written" in note for note in execution["notes"])
    # A bundle holding no trace event may claim no observation at all, and the run is not clean.
    assert set(execution["capture"].values()) == {"unavailable"}
    assert result["status"] == "partial" and result["error"]["code"] == "trace_capture_gap"


def test_a_run_that_failed_before_the_export_declares_no_artifact_it_does_not_hold(tmp_path, monkeypatch):
    """A record whose failure is already named must not also complain about a missing file."""
    root = fake_deepsec_root(tmp_path, process_exit=5)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    result, execution = documents(bundle)
    assert result["status"] == "error" and result["error"]["code"] == "process_exit_5"
    registered = {artifact["id"] for artifact in execution["raw_artifacts"]}
    assert "deepsec-export" not in registered
    assert "deepsec-export-stdout" not in registered, "the step never ran"
    assert not any("declared artifact missing" in note for note in execution["notes"]), execution["notes"]


# --- against the real collector ------------------------------------------------------------


def test_the_adapter_composes_with_the_real_claude_code_collector(tmp_path):
    """The stub above pins what is passed; this pins that the real importer accepts it.

    Nothing is replaced here: the adapter resolves the collector by name, finds a synthetic
    transcript under a projects directory this test owns, and hands it to WP-D's importer. The
    transcript is synthetic — no real session content and no operator path — and it is written
    here rather than kept as a fixture so the shape it asserts is visible beside the assertion.
    """
    if deepsec_module.collector() is None:
        pytest.skip("the Claude Code transcript collector is not installed on this checkout")
    root = fake_deepsec_root(tmp_path, session_ids=["session-aaaa"])
    projects = tmp_path / "claude-projects" / "-tmp-workspace"
    projects.mkdir(parents=True)
    (projects / "session-aaaa.jsonl").write_text("\n".join(json.dumps(record) for record in [
        {"type": "assistant", "uuid": "u1", "sessionId": "session-aaaa", "message": {
            "role": "assistant", "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 1200, "output_tokens": 210,
                      "cache_read_input_tokens": 40, "cache_creation_input_tokens": 8},
            "content": [{"type": "text", "text": "Reading the route handler."},
                        {"type": "tool_use", "id": "toolu_1", "name": "Read",
                         "input": {"file_path": "src/server.js"}}]}},
        {"type": "user", "uuid": "u2", "sessionId": "session-aaaa", "message": {
            "role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1",
                 "content": "     1\tconst { exec } = require('child_process');\n"}]},
         "toolUseResult": {"file": {"filePath": "src/server.js", "startLine": 1, "numLines": 2,
                                    "content": "const { exec } = require('child_process');\n"
                                               "const express = require('express');\n"}}},
    ]) + "\n", encoding="utf-8")

    bundle = invoke(tmp_path, root, claude_projects_dir=str(tmp_path / "claude-projects"))
    result, execution = documents(bundle)
    assert result["status"] == "success", execution["error"]
    events = trace_events(bundle)
    by_type: dict[str, list[dict]] = {}
    for event in events:
        by_type.setdefault(event["type"], []).append(event)

    assert by_type["tool.start"] and by_type["tool.end"], sorted(by_type)
    assert by_type["tool.start"][0]["metadata"]["source"] == "claude_code_transcript"
    assert by_type["tool.start"][0]["metadata"]["tool_name"] == "Read"
    assert by_type["context.selection"], "a Read result with a known span is a context event"
    span = by_type["context.selection"][0]["metadata"]["spans"][0]
    assert span["path"] == "src/server.js" and span["start_line"] == 1
    assert by_type["context.selection"][0]["capture_status"] == "partial"

    # The transcript describes the call, turn by turn, and the adapter adds no summed pair
    # beside it: every model event in this trace came from the importer, none from the records.
    assert by_type["model.request"] and by_type["model.response"]
    assert all(event["metadata"]["source"] == "claude_code_transcript"
               for event in by_type["model.request"] + by_type["model.response"])
    call_ids = {event["call_id"] for event in
                by_type["context.selection"] + by_type["model.request"]}
    assert len(call_ids) == 1 and call_ids.pop().endswith("/session-aaaa")
    assert execution["capture"]["tool_calls"] == "complete"
    assert execution["capture"]["context_selection"] == "partial"
    assert str(Path.home()) not in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8")


# --- the workspace spellings a transcript can name -----------------------------------------


def test_workspace_spellings_offers_the_handed_path_and_the_real_one_without_repeating_it(tmp_path):
    """Both spellings, handed first, and only one when the filesystem has only one."""
    from scaneval.adapters.deepsec import workspace_spellings

    real = tmp_path / "real"
    (real / "source").mkdir(parents=True)
    plain = workspace_spellings(real / "source")
    assert plain == (real / "source",), "no link, no second spelling"

    link = tmp_path / "linked"
    link.symlink_to(real, target_is_directory=True)
    through = workspace_spellings(link / "source")
    assert through == (link / "source", real / "source")
    assert len(through) == len(set(through))
    assert through[0] != through[-1] and through[-1] == through[-1].resolve()


def test_a_path_a_note_carries_is_written_with_a_tilde_rather_than_a_home_directory(monkeypatch, tmp_path):
    """A note is recorded evidence; a home directory in one names the operator, not the run."""
    from scaneval.adapters.deepsec import portable

    home = tmp_path / "home" / "someone"
    (home / "work" / "repo").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    assert portable(home / "work" / "repo") == "~/work/repo"
    assert portable(home) == "~"
    assert portable(Path("/var/folders/xy/source")) == "/var/folders/xy/source"

    def no_home():
        raise RuntimeError("no home directory")

    monkeypatch.setattr(Path, "home", staticmethod(no_home))
    assert portable(home / "work") == (home / "work").as_posix(), "an unreadable HOME costs nothing"


def test_the_note_naming_the_spellings_never_writes_a_raw_home_path(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    _result, execution = documents(bundle)
    note = next(note for note in execution["notes"]
                if "Transcript paths were matched against" in note)
    assert "both spellings" in note or "the one spelling" in note
    assert str(Path.home()) not in note
    assert "the collectors compare textually" in note


def test_the_batch_wall_clock_is_taken_once_rather_than_summed_over_the_files_that_repeat_it():
    """Every other number on an AnalysisEntry is a share; ``durationMs`` is not.

    A real run wrote ``durationMs: 40847`` onto all three files of one batch while dividing
    ``durationApiMs``, ``numTurns``, ``costUsd`` and every token count by three. Summing it
    reported a forty-second batch as a two-minute one.
    """
    files = tuple((f"f{i}.py.json", {"filePath": f"f{i}.py", "analysisHistory": [{
        "runId": "r1", "agentSessionId": "s1", "model": "m",
        "durationMs": 40847, "durationApiMs": 121684 / 3, "numTurns": 13 / 3,
        "costUsd": 0.15 / 3}]}) for i in range(3))
    session = sessions_from(files)[0]
    assert session.duration_ms == 40847, "the wall clock is repeated, not divided"
    assert session.duration_api_ms == pytest.approx(121684)
    assert session.num_turns == pytest.approx(13)
    assert session.cost_usd == pytest.approx(0.15)


def test_the_response_event_carries_the_batch_wall_clock_as_the_schema_s_own_duration(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path, found=False)
    bundle = invoke(tmp_path, root)
    response = next(event for event in trace_events(bundle)
                    if event["type"] == "model.response")
    assert isinstance(response["duration_ms"], int) and response["duration_ms"] >= 0
    assert response["metadata"]["duration_api_ms"] > 0
    assert response["metadata"]["transcript_imported"] is False


def test_a_transcript_naming_the_workspace_by_its_real_path_still_yields_a_relative_span(tmp_path):
    """The regression: one spelling turned every span into ``external:<basename>``.

    The Claude Agent SDK records its working directory and every file it read under the
    platform's real path. A workspace handed over through a symbolic link — which is exactly
    what ``/var/folders/...`` is on macOS — is therefore named in the transcript by a path the
    adapter never saw. The collectors match textually and never resolve a link, by design, so
    passing one spelling made a real run produce eleven context events whose every span read
    ``external:server.js`` and which the coverage attribution could join to nothing.

    Nothing is stubbed here: the fake DeepSec writes the transcript the way the SDK does, under
    the real path, and WP-D's own importer reads it.
    """
    if not collector_accepts_several_spellings():
        pytest.skip("the collectors do not accept a sequence of workspace roots yet")
    from scaneval.collectors import workspace_path

    projects = tmp_path / "claude-projects"
    root = fake_deepsec_root(tmp_path, session_ids=["session-aaaa"],
                             transcript_dir=str(projects))
    bundle = invoke(tmp_path, root, claude_projects_dir=str(projects),
                    workspace_root=linked_workspace_root(tmp_path))
    result, execution = documents(bundle)
    assert result["status"] == "success", execution["error"]

    events = trace_events(bundle)
    selections = [event for event in events if event["type"] == "context.selection"]
    assert selections, "a Read result with a known span is a context event"
    spans = [span for event in selections for span in event["metadata"]["spans"]]
    assert spans and all(span["path"] == "src/server.js" for span in spans), spans
    assert not any(span["path"].startswith("external:") for span in spans)
    starts = [event for event in events if event["type"] == "tool.start"]
    assert starts and not any("external:" in event["metadata"]["input_summary"]
                              for event in starts), starts
    assert execution["capture"]["tool_calls"] == "complete"
    assert execution["capture"]["context_selection"] == "partial"
    assert str(Path.home()) not in (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8")

    # And the proof that one spelling is not enough: the handed path alone does not match the
    # real one the transcript wrote, which is the whole defect.
    handed = next(note for note in execution["notes"]
                  if "Transcript paths were matched against" in note)
    assert "both spellings" in handed
    real_workspace = (tmp_path / "real-workspaces").resolve()
    link_workspace = tmp_path / "linked-workspaces"
    rendered, external = workspace_path(f"{real_workspace}/trial/source/src/server.js",
                                        f"{link_workspace}/trial/source")
    assert external and rendered.startswith("external:")


def test_the_guide_states_the_two_spellings_and_the_duration_field_that_is_not_a_share():
    """Both findings came out of a real run; a guide that omits them would mislead the next one."""
    text = DOC.read_text(encoding="utf-8")
    assert "source_dir.resolve()" in text
    assert "external:server.js" in text, "the guide names the failure the fix closes"
    assert "durationMs" in text and "maximum, not a sum" in text
    assert "cacheReadInputTokens" in text


def test_files_the_ai_stage_never_reached_are_counted_because_silence_about_them_proves_nothing(tmp_path, monkeypatch):
    """``--limit`` is a cost bound, and a real run left 29 of 35 records pending.

    A ``success`` there let the scoring contract treat every assigned control as completed and
    grant quiet credit for files no model ever opened, which is exactly what the adapter's own
    note said the run did not establish. The status and ``bundles_resolved`` say it too now.
    """
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root, limit=1)
    result, execution = documents(bundle)
    assert result["status"] == "partial"
    assert result["error"]["code"] == "scope_incomplete"
    assert "1 of 2 file record(s)" in result["error"]["message"]
    assert "under config.limit 1" in result["error"]["message"]
    assert result["bundles_resolved"] is False, "no quiet credit for a file nothing opened"
    note = next(note for note in execution["notes"] if "'pending'" in note)
    assert "config.limit (1)" in note and "not a negative result" in note
    assert len(result["claims"]) == 1, "the finding the run did produce is still reported"


def test_the_guide_says_a_limited_run_is_a_success_that_covered_part_of_the_tree():
    text = DOC.read_text(encoding="utf-8")
    assert 'status: "pending"' in text
    assert "not a negative result about it" in text


# --- reading a path the scanner owns -------------------------------------------------------


def test_a_bounded_tail_refuses_a_link_a_pipe_and_a_path_outside_this_run(tmp_path):
    """The failure message quotes scanner-owned stderr, so that read must not be exploitable.

    Following a link let a scanner choose which host file the bundle quotes, opening a named
    pipe held the invocation open forever with no record that it had happened, and reading the
    whole file before keeping the tail made a large one a memory problem. One read, three rules.
    """
    from scaneval.adapters.deepsec import bounded_tail
    from scaneval.adapters.llm_harness import Enclosure

    raw = tmp_path / "raw"
    raw.mkdir()
    enclosure = Enclosure.capture(tmp_path, raw)
    secret = tmp_path / "host-secret.txt"
    secret.write_text("PRIVATE KEY MATERIAL\n", encoding="utf-8")

    plain = raw / "plain.txt"
    plain.write_text("the scanner said this\n", encoding="utf-8")
    assert bounded_tail(plain, enclosure.write(plain)) == "the scanner said this\n"

    link = raw / "link.txt"
    link.symlink_to(secret)
    assert bounded_tail(link, enclosure.write(link)) == "", "a link is never followed"
    assert "PRIVATE" not in bounded_tail(link, enclosure.write(link))

    outside = tmp_path / "outside.txt"
    outside.write_text("not this run's\n", encoding="utf-8")
    assert bounded_tail(outside, enclosure.write(outside)) == ""

    missing = raw / "never-written.txt"
    assert bounded_tail(missing, enclosure.write(missing)) == ""

    directory = raw / "a-directory"
    directory.mkdir()
    assert bounded_tail(directory, enclosure.write(directory)) == ""


def test_a_bounded_tail_does_not_block_on_a_named_pipe(tmp_path):
    """The read must return at once, so the test needs no reader on the other end."""
    from scaneval.adapters.deepsec import bounded_tail
    from scaneval.adapters.llm_harness import Enclosure

    raw = tmp_path / "raw"
    raw.mkdir()
    enclosure = Enclosure.capture(tmp_path, raw)
    pipe = raw / "blocked.txt"
    os.mkfifo(pipe)
    finished: list[str] = []

    def read() -> None:
        finished.append(bounded_tail(pipe, enclosure.write(pipe)))

    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "opening a named pipe must not wait for a writer"
    assert finished == [""]


def test_a_bounded_tail_reads_only_the_last_bytes_of_an_oversized_file(tmp_path):
    from scaneval.adapters.deepsec import bounded_tail
    from scaneval.adapters.llm_harness import Enclosure

    raw = tmp_path / "raw"
    raw.mkdir()
    enclosure = Enclosure.capture(tmp_path, raw)
    big = raw / "big.txt"
    big.write_text("A" * 50_000 + "THE TAIL\n", encoding="utf-8")
    tail = bounded_tail(big, enclosure.write(big), limit=64)
    assert len(tail) <= 64 and tail.endswith("THE TAIL\n")
    assert bounded_tail(big, enclosure.write(big)).endswith("THE TAIL\n")
    assert len(bounded_tail(big, enclosure.write(big))) <= 2000


def test_a_failed_step_quotes_its_stderr_through_the_bounded_read(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path, process_exit=6)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    result, _execution = documents(bundle)
    assert result["error"]["code"] == "process_exit_6"
    assert "failed on purpose" in result["error"]["message"]


# --- paths that must never reach an event --------------------------------------------------


@pytest.mark.parametrize("name,expected", [
    ("src/a.py.json", "src/a.py"),
    ("./src/a.py.json", "src/a.py"),
    ("a.py.json", "a.py"),
    ("/etc/shadow.json", "external:shadow"),
    ("../../outside.py.json", "external:outside.py"),
    ("x\x00y.json", "external:x\x00y"),
])
def test_a_record_path_comes_from_where_deepsec_put_it_and_never_leaves_the_tree(name, expected):
    """``filePath`` is scanner-written text; the record's own location is not.

    Publishing the text verbatim into ``batch_paths`` and refusal metadata would have put the
    run's workspace, and with it the operator's home, into a trace that Contract 3 forbids one
    to appear in.
    """
    from scaneval.adapters.deepsec import record_path

    path, external = record_path(name, {"filePath": "/Users/someone/secret/thing.py"})
    assert path == expected
    assert external is (expected.startswith("external:"))
    assert "/Users/" not in path


def test_a_hostile_file_path_never_reaches_a_session_or_a_candidate(tmp_path, monkeypatch):
    """Absolute, traversal and outside-workspace values, through the whole session builder."""
    from scaneval.adapters.deepsec import candidates_from, sessions_from

    files = (
        ("/etc/passwd.json", {"filePath": "/etc/passwd",
                              "candidates": [{"vulnSlug": "x", "lineNumbers": [1]}],
                              "analysisHistory": [{"runId": "r", "agentSessionId": "s"}]}),
        ("../../escape.py.json", {"filePath": "../../escape.py",
                                  "candidates": [{"vulnSlug": "y", "lineNumbers": [2]}],
                                  "analysisHistory": [{"runId": "r", "agentSessionId": "s"}]}),
        ("src/ok.py.json", {"filePath": "/var/tmp/run/source/src/ok.py",
                            "candidates": [{"vulnSlug": "z", "lineNumbers": [3]}],
                            "analysisHistory": [{"runId": "r", "agentSessionId": "s"}]}),
    )
    session = sessions_from(files)[0]
    assert session.paths == ("external:escape.py", "external:passwd", "src/ok.py")
    assert session.external_paths == 2
    assert not any(path.startswith("/") or ".." in path.split("/") for path in session.paths)
    sites = candidates_from(files)
    assert sorted(site.path for site in sites) == ["external:escape.py", "external:passwd", "src/ok.py"]
    assert sum(site.external for site in sites) == 2


def test_every_path_in_a_trace_is_relative_or_external(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    for event in trace_events(bundle):
        for key in ("file_path", "batch_paths", "candidate_ids"):
            values = event["metadata"].get(key)
            for value in ([values] if isinstance(values, str) else (values or [])):
                assert not value.startswith("/"), (event["type"], key, value)
                assert ".." not in value.split("/"), (event["type"], key, value)


# --- one call, described once ---------------------------------------------------------------


def test_a_session_with_a_transcript_gets_no_reconstructed_pair_beside_it(tmp_path, monkeypatch):
    """Emitting both counted every call and every token of such a session twice."""
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    events = trace_events(bundle)
    own = [event for event in events if event["type"].startswith("model.")
           and event["metadata"].get("source") == "harness_record"]
    assert own == [], "the transcript is the record of the call"
    _result, execution = documents(bundle)
    # DeepSec's own totals still reach the record, so nothing is lost by not repeating them.
    assert execution["capture"]["tool_calls"] == "complete"
    assert any("No call is described both ways." in note for note in execution["notes"])


def test_a_session_without_a_transcript_gets_the_reconstructed_pair_as_the_fallback(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path, found=False)
    bundle = invoke(tmp_path, root)
    events = trace_events(bundle)
    requests = [event for event in events if event["type"] == "model.request"]
    responses = [event for event in events if event["type"] == "model.response"]
    assert len(requests) == len(responses) == 1
    assert requests[0]["metadata"]["transcript_imported"] is False
    assert requests[0]["metadata"]["route"] == "claude_agent_sdk"
    assert requests[0]["metadata"]["retries_observable"] is False
    assert requests[0]["metadata"]["aggregation"] == "sum_of_per_file_shares"
    assert requests[0]["metadata"]["model_requested"] == "claude-haiku-4-5"
    assert requests[0]["metadata"]["thinking"] == "low"
    assert responses[0]["metadata"]["usage"]["input_tokens"] == 1000
    assert responses[0]["metadata"]["cost_usd_cli_reported"] == pytest.approx(0.12)
    assert responses[0]["metadata"]["model_served"] == "claude-haiku-4-5"
    assert responses[0]["attempt_id"] == requests[0]["attempt_id"]


# --- correlation ------------------------------------------------------------------------------


def test_two_entries_with_no_session_id_are_two_calls_and_never_one_merged_call():
    """The one case where the native identifier is missing was the one case it was invented."""
    files = (
        ("src/a.py.json", {"analysisHistory": [
            {"runId": "r1", "numTurns": 3, "costUsd": 0.10,
             "usage": {"inputTokens": 100, "outputTokens": 10}}]}),
        ("src/b.py.json", {"analysisHistory": [
            {"runId": "r2", "numTurns": 5, "costUsd": 0.20,
             "usage": {"inputTokens": 200, "outputTokens": 20}}]}),
    )
    groups = sessions_from(files)
    assert len(groups) == 2, "unrelated batches are not merged"
    assert [group.key for group in groups] == [
        "uncorrelated/src/a.py/0", "uncorrelated/src/b.py/0"]
    assert [group.correlation for group in groups] == ["missing_session_id"] * 2
    assert [group.paths for group in groups] == [("src/a.py",), ("src/b.py",)]
    assert [group.num_turns for group in groups] == [3, 5]
    assert [group.cost_usd for group in groups] == [0.10, 0.20]
    assert len({group.call_id for group in groups}) == 2


def test_two_entries_in_one_record_with_no_session_id_stay_two_calls():
    files = (("src/a.py.json", {"analysisHistory": [
        {"runId": "r1", "numTurns": 1}, {"runId": "r2", "numTurns": 2}]}),)
    groups = sessions_from(files)
    assert [group.key for group in groups] == [
        "uncorrelated/src/a.py/0", "uncorrelated/src/a.py/1"]


def test_a_correlated_session_says_so_on_its_events(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path, found=False)
    bundle = invoke(tmp_path, root)
    request = next(event for event in trace_events(bundle) if event["type"] == "model.request")
    assert request["metadata"]["correlation"] == "agent_session_id"


# --- what a refusal reason may carry ---------------------------------------------------------


def test_a_refusal_reason_is_a_closed_code_and_a_bounded_relocated_summary():
    """Free model prose can quote source and name a machine; metadata may carry neither."""
    from scaneval.adapters.deepsec import sessions_from

    reason = ("could not read /var/tmp/run/source/src/secret.py: " + "verbose model prose " * 40)
    files = (("src/a.py.json", {"analysisHistory": [{
        "runId": "r", "agentSessionId": "s",
        "refusal": {"refused": True, "reason": reason}}]}),)
    refusal = sessions_from(files, (Path("/var/tmp/run/source"),))[0].refusals[0]
    assert refusal.code == "refused", "no skipped list, so the structural code is the bare one"
    assert len(refusal.summary) <= 120
    assert "/var/tmp/run/source" not in refusal.summary
    assert refusal.summary.startswith("could not read src/secret.py:")
    assert refusal.reason == reason, "the untouched prose is kept for content"

    with_skips = (("src/a.py.json", {"analysisHistory": [{
        "runId": "r", "agentSessionId": "s",
        "refusal": {"refused": True, "reason": "x", "skipped": [{"filePath": "y"}]}}]}),)
    assert sessions_from(with_skips)[0].refusals[0].code == "refused_with_skipped_files"


def test_the_raw_refusal_reason_reaches_content_only_and_metadata_stays_bounded(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path, refusal=True)
    stub_collector(monkeypatch, tmp_path, found=False)
    content_bundle = invoke(tmp_path / "c", root, out="out-content", trace_mode="content")
    response = next(event for event in trace_events(content_bundle)
                    if event["metadata"].get("refusals"))
    assert response["content"]["refusal_reasons"][0]["reason"] == "the file was not readable"
    assert "reason" not in response["metadata"]["refusals"][0]

    metadata_bundle = invoke(tmp_path / "m", root, out="out-metadata", trace_mode="metadata")
    metadata_response = next(event for event in trace_events(metadata_bundle)
                             if event["metadata"].get("refusals"))
    assert "content" not in metadata_response, "metadata mode stores no reason text at all"
    assert metadata_response["metadata"]["refusals"][0]["summary"]


# --- the matrix no longer overclaims ----------------------------------------------------------


def test_a_record_this_run_could_not_read_makes_the_candidate_population_partial(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    adapter = get_adapter("deepsec")
    spec = system_spec(root)
    preparation = adapter.prepare(spec, tmp_path / "cache")
    original = deepsec_module.run_command

    def run_command(argv, **kwargs):
        result = original(argv, **kwargs)
        if argv[1] == "export":
            records = sorted((Path(kwargs["cwd"]) / "data").rglob("files/**/*.json"))
            records[0].write_bytes(b"{not json")
        return result

    monkeypatch.setattr(deepsec_module, "run_command", run_command)
    bundle = run_invocation(prepared=prepared_input(tmp_path), adapter=adapter, spec=spec,
                            preparation=preparation, out_dir=tmp_path / "out",
                            run_id="run-deepsec", timeout_seconds=120, trace_mode="content",
                            network_policy="model_provider_only", clock=CLOCK)
    result, execution = documents(bundle)
    assert result["status"] == "partial" and result["error"]["code"] == "import_loss"
    assert execution["capture"]["finding_candidate"] == "partial"


def test_an_export_finding_that_was_lost_makes_finding_submitted_partial(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    adapter = get_adapter("deepsec")
    spec = system_spec(root)
    preparation = adapter.prepare(spec, tmp_path / "cache")
    original = deepsec_module.run_command

    def run_command(argv, **kwargs):
        result = original(argv, **kwargs)
        if argv[1] == "export":
            export = Path(kwargs["cwd"]).parent / "deepsec-export.json"
            payload = json.loads(export.read_text(encoding="utf-8"))
            payload.append({"title": "[HIGH] escaped", "description": "",
                            "metadata": {"filePath": "/etc/shadow", "lineNumbers": [1],
                                         "vulnSlug": "x", "severity": "HIGH"}})
            export.write_text(json.dumps(payload), encoding="utf-8")
        return result

    monkeypatch.setattr(deepsec_module, "run_command", run_command)
    bundle = run_invocation(prepared=prepared_input(tmp_path), adapter=adapter, spec=spec,
                            preparation=preparation, out_dir=tmp_path / "out",
                            run_id="run-deepsec", timeout_seconds=120, trace_mode="content",
                            network_policy="model_provider_only", clock=CLOCK)
    result, execution = documents(bundle)
    assert result["status"] == "partial" and result["error"]["code"] == "import_loss"
    assert execution["capture"]["finding_submitted"] == "partial"
    assert execution["capture"]["finding_candidate"] == "complete", "the records were all read"


def test_the_pilot_notes_say_the_limited_run_is_recorded_as_partial():
    """The frozen run is deliberately limited, so its own notes must not surprise a reader."""
    config = load_document(RUN_CONFIG, "run-config")
    joined = " ".join(config["notes"])
    assert "scope_incomplete" in joined and "bundles_resolved false" in joined
    assert "scope_incomplete" in DOC.read_text(encoding="utf-8")
