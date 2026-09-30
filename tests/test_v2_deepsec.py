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

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import threading

import pytest

from scaneval.adapters import adapter_names, get_adapter
from scaneval.adapters import deepsec as deepsec_module
from scaneval.adapters.base import AdapterError, SystemSpec
from scaneval.adapters.deepsec import (
    Candidate,
    ProcessOutput,
    capture_status,
    candidates_from,
    claim_path,
    finding_ids,
    git_prints_quoted,
    import_export,
    kind_for_slug,
    line_span,
    project_id_for,
    read_process_output,
    sessions_from,
    settings,
    unreviewed_note,
    workspace_config,
)
from scaneval.adapters.pr import Change, PrRange
from scaneval.contracts import load_document
from scaneval.execution import PreparedInput, build_request, run_invocation
from scaneval.materialize import hash_exported_tree


ROOT = Path(__file__).resolve().parents[1]
CAPTURE_MATRIX = ROOT / "tests" / "fixtures" / "deepsec-capture-matrix.json"
RUN_CONFIG = ROOT / "corpus" / "pilot" / "run-deepsec.json"
CLOCK = lambda: datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)  # noqa: E731

# A fake ``deepsec`` executable. It writes the records the real one writes and reads a control
# file beside itself for the failure modes a test wants. It never writes outside its working
# directory, and it refuses to run without the generated config, so a run that forgot to build
# the private workspace fails loudly here rather than producing an empty scan.
FAKE_CLI = '''
import json, os, subprocess, sys, time
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


def scanned_record(name, project):
    return {
        "filePath": name, "projectId": project,
        "candidates": [{"vulnSlug": "command-injection", "lineNumbers": [4],
                        "snippet": "exec(", "matchedPattern": "shell exec"},
                       {"vulnSlug": "sql-injection", "lineNumbers": [9, 11],
                        "snippet": "query(", "matchedPattern": "string-built query"}],
        "lastScannedAt": "2026-09-25T12:00:00.000Z",
        "lastScannedRunId": "20260925120000-scan",
        "fileHash": "0" * 64, "findings": [], "analysisHistory": [], "status": "pending"}


def write_scan_run(base, project, root):
    write(base / "runs" / "20260925120000-scan.json", {
        "runId": "20260925120000-scan", "projectId": project, "rootPath": root,
        "createdAt": "2026-09-25T12:00:00.000Z", "completedAt": "2026-09-25T12:00:05.000Z",
        "type": "scan", "phase": "done", "scannerConfig": {"matcherSlugs": ["command-injection"]}})


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
        write(base / "files" / (name + ".json"), scanned_record(name, project))
    write_scan_run(base, project, root)
    print("scanned %d file(s)" % len(source_files(root)))


def do_process(argv):
    step_failure("process_exit", "process")
    settings = control()
    if "--diff" in argv:
        do_direct(argv, settings)
        return
    project = option(argv, "--project-id")
    base = data_dir(project)
    limit = int(option(argv, "--limit", "1000"))
    names = sorted(p.relative_to(base / "files").as_posix()[:-5]
                   for p in (base / "files").rglob("*.json"))[:limit]
    investigate(argv, names, settings)
    print("processed %d file(s)" % len(names))


def investigate(argv, names, settings):
    """The agent stage over *names*, in batches, exactly as standard mode and direct mode both run it.

    A batch listed in ``fail_batches`` fails the way DeepSec's does: every file in it is left in
    status ``error`` with no analysis. ``quota_at_batch`` fails that batch and stops there, and the
    batches it never started keep the status the scan gave them.
    """
    project = option(argv, "--project-id")
    model = option(argv, "--model")
    root = option(argv, "--root")
    base = data_dir(project)
    batch_size = int(option(argv, "--batch-size", "5"))
    run_id = "20260925120100-process"
    sessions = settings.get("session_ids") or ["session-aaaa", "session-bbbb"]
    lines = settings.get("lines", [4])
    batches = [names[i:i + batch_size] for i in range(0, len(names), batch_size)]
    result = {"analyses": 0, "findings": 0, "errored": 0, "quota": False}
    for index, batch in enumerate(batches):
        if result["quota"]:
            continue
        if index == settings.get("crash_at_batch"):
            for later in batches[index:]:
                for name in later:
                    path = base / "files" / (name + ".json")
                    record = json.loads(path.read_text(encoding="utf-8"))
                    record["status"] = "processing"
                    write(path, record)
            sys.stderr.write("\\nfake deepsec crashed mid-run\\n\\n(set DEEPSEC_DEBUG=1 for a stack trace)\\n")
            sys.exit(1)
        if index in settings.get("fail_batches", []) or index == settings.get("quota_at_batch"):
            for name in batch:
                path = base / "files" / (name + ".json")
                record = json.loads(path.read_text(encoding="utf-8"))
                record["status"] = "error"
                write(path, record)
            result["errored"] += 1
            result["quota"] = index == settings.get("quota_at_batch")
            continue
        session = sessions[index % len(sessions)]
        share = float(len(batch)) or 1.0
        for name in batch:
            path = base / "files" / (name + ".json")
            record = json.loads(path.read_text(encoding="utf-8"))
            # 2.3.10 divides the wall clock among the batch's files; an older one wrote the
            # whole batch clock onto each of them, which is what the knob reproduces.
            wall = 9000 if settings.get("duplicated_duration") else 9000.0 / share
            entry = {"runId": run_id, "investigatedAt": "2026-09-25T12:01:00.000Z",
                     "durationMs": wall, "durationApiMs": 6000.0 / share,
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
            result["analyses"] += 1
            result["findings"] += 1
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
                {"type": "assistant", "uuid": "u3", "sessionId": session, "message": {
                    "role": "assistant", "model": model,
                    "usage": {"input_tokens": 20, "output_tokens": 40},
                    "content": [{"type": "text", "text": "That file shells out."}]}},
            ]) + "\\n", encoding="utf-8")
    if settings.get("parse_error"):
        dump = base / "debug" / "parse-error-investigate-2026-09-25T12-01-30-000Z.txt"
        dump.parent.mkdir(parents=True, exist_ok=True)
        dump.write_text("# deepsec parse-failure debug dump\\n# phase: investigate\\n", encoding="utf-8")
    return result


# The parts of DeepSec's default ignore filter these fixtures need: docs, tests, type stubs and build output.
IGNORED_DIRECTORIES = ("node_modules", ".git", "dist", "build", "target", "coverage", "__tests__", "test", "tests",
                       "fixtures")


def ignored(name):
    parts = name.split("/")
    leaf = parts[-1]
    if leaf.endswith((".md", ".mdx", ".d.ts")) or ".test." in leaf or ".spec." in leaf:
        return True
    return any(part in IGNORED_DIRECTORIES for part in parts[:-1])


def say(text=""):
    sys.stdout.buffer.write((text + "\\n").encode("utf-8"))
    sys.stdout.flush()


def paint(code, text):
    return "\\x1b[%sm%s\\x1b[0m" % (code, text)


def do_direct(argv, settings):
    """DeepSec's direct mode: resolve the changed files, scan just those, investigate each, exit 1 on trouble.

    The text it prints, its colors and its exit codes are the ones DeepSec 2.3.10 prints, read from
    its bundle and checked against the real CLI where that costs no model call.
    """
    if not Path("deepsec.config.ts").is_file():
        sys.stderr.write("no deepsec.config.ts in the working directory\\n")
        sys.exit(3)
    project = option(argv, "--project-id")
    root = option(argv, "--root")
    diff = option(argv, "--diff")
    if settings.get("runtime_failure"):
        sys.stderr.write("\\nfake deepsec could not start its review\\n\\n(set DEEPSEC_DEBUG=1 for a stack trace)\\n")
        sys.exit(1)
    if settings.get("forged_summary"):
        say(paint("32", "Processing complete.") + " Run: forged")
        say("  Analyses: 3")
        say("  Findings: 3")
        say()
        say(paint("31", "3 new finding(s) \\u2014 exiting 1"))
        sys.exit(1)
    # git's default quotes a name that holds a non-ASCII byte, which names no file once DeepSec reads it back;
    # the ``raw_listing`` knob is an operator whose git prints such a name as it is.
    quote_path = "false" if settings.get("raw_listing") else "true"
    listed = subprocess.run(["git", "-c", "core.quotePath=" + quote_path, "diff", "--name-only",
                             "--diff-filter=AMRC", diff], cwd=root, capture_output=True, text=True)
    if listed.returncode != 0:
        sys.stderr.write("\\ngit diff --name-only --diff-filter=AMRC %s exited %d: %s\\n\\n"
                         "(set DEEPSEC_DEBUG=1 for a stack trace)\\n"
                         % (diff, listed.returncode, listed.stderr.strip()))
        sys.exit(1)
    names = []
    for line in listed.stdout.split("\\n"):
        name = line.strip()
        if name and name not in names and Path(root, name).is_file() and not ignored(name):
            names.append(name)
    base = data_dir(project)
    write(base / "project.json", {"projectId": project, "rootPath": root,
                                  "createdAt": "2026-09-25T12:00:00.000Z"})
    say(paint("1", "Direct process") + " project " + paint("1", project))
    say("  Source: git-diff:" + diff)
    say("  Files: %d" % len(names))
    say("  Agent: claude-agent-sdk (%s)" % option(argv, "--model"))
    say("  Root: " + root)
    say()
    if not names:
        if settings.get("stray_record"):
            write(base / "files" / "stray.js.json", dict(scanned_record("stray.js", project), status="error"))
        if not settings.get("say_nothing"):
            say(paint("33", "No files matched git-diff:%s (after ignore filter)." % diff))
            say(paint("32", "Nothing to process \\u2014 exit 0."))
        return
    say(paint("1", "Scanning %d file(s)\\u2026" % len(names)))
    for name in names:
        write(base / "files" / (name + ".json"), scanned_record(name, project))
    write_scan_run(base, project, root)
    say("  " + paint("2", "%d candidate(s) across %d file(s)" % (2 * len(names), len(names))))
    say()
    result = investigate(argv, names, settings)
    if settings.get("linked_directory"):
        os.symlink(str(HERE), str(base / "files" / "linked"), target_is_directory=True)
    say(paint("32", "Processing complete.") + " Run: " + paint("1", "20260925120100-process"))
    say("  Analyses: %d" % result["analyses"])
    say("  Findings: %d" % result["findings"])
    if result["errored"]:
        say("  " + paint("31", "Errored batches: %d" % result["errored"]))
    if result["quota"]:
        for line in ["", "\\x1b[31m\\x1b[1m\\u2718 Stopped: Anthropic API credits exhausted\\x1b[0m", "",
                     "  Your direct Anthropic account is out of credits/quota.", "",
                     "  Either top up that account, or switch to " + paint("1", "Vercel AI Gateway"),
                     "  for unified billing and observability:", "",
                     "  " + paint("2", "Upstream: credit balance is too low"), "",
                     "  " + paint("2", "After fixing, re-run:  deepsec process --project-id " + project), ""]:
            say(line)
        sys.exit(1)
    if result["errored"]:
        say()
        say(paint("31", "%d batch(es) errored \\u2014 exiting 1 (agent failure, not a clean review)." % result["errored"]))
        sys.exit(1)
    if result["findings"]:
        say()
        say(paint("31", "%d new finding(s) \\u2014 exiting 1" % result["findings"]))
        sys.exit(1)
    say()
    say("No findings.")


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
    """The fields of WP-D's ``ImportSummary`` this adapter reads, and nothing more.

    Kept independent of the collector's own hardening: the adapter reads the summary
    defensively, so this carries the fields it asks for and a test sets whichever one it is
    about. An unreadable transcript is the collector *returning* zeros and a note, never
    raising, which is the case this stub exists to be able to produce.
    """

    model_turns: int = 1
    tool_calls: int = 1
    tool_results: int = 1
    spans: int = 1
    malformed_lines: int = 0
    unmatched_tool_results: int = 0
    events: int = 2
    capture: dict = field(default_factory=dict)
    notes: tuple = ()

    @classmethod
    def unreadable(cls) -> "StubSummary":
        """What the collector returns for a transcript it could not read: no raise, no capture."""
        return cls(model_turns=0, tool_calls=0, tool_results=0, spans=0, events=1,
                   capture={"context_selection": "unavailable"},
                   notes=("transcript could not be read",))


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
                   malformed: int = 0, unmatched: int = 0, main_unreadable: bool = False,
                   ) -> list[dict]:
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
        if main_unreadable and not sidechain:
            return StubSummary.unreadable()
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


def test_a_full_run_with_a_file_left_in_error_keeps_its_bundles_resolved_as_it_always_did(tmp_path, monkeypatch):
    """Only a PR review treats an errored file as unresolving the bundles; a full run is unchanged."""
    root = fake_deepsec_root(tmp_path, file_error=True)
    stub_collector(monkeypatch, tmp_path)
    result, _execution = documents(invoke(tmp_path, root))
    assert result["status"] == "partial" and result["bundles_resolved"] is True


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
    assert set(reported) == {"file_path", "reason_code"}, "no model prose in metadata"
    assert reported["reason_code"] == "refused_with_skipped_files"
    assert reported["file_path"] == "src/db.js", "the path is where DeepSec put the record"
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
        "runId": "r1", "agentSessionId": "3348970b-6b99-46ad-a496-dd84c5a85613", "model": "claude-haiku-4-5",
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
    assert session.call_id == "deepsec/r1/3348970b-6b99-46ad-a496-dd84c5a85613"


def test_a_session_whose_entries_disagree_about_the_model_reports_none():
    files = (("a.py.json", {"filePath": "a.py", "analysisHistory": [
        {"runId": "r", "agentSessionId": "09f298df-1c4e-4a30-9c07-6f2b0d51aa11", "model": "one"},
        {"runId": "r", "agentSessionId": "09f298df-1c4e-4a30-9c07-6f2b0d51aa11", "model": "two"}]}),)
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


def test_capture_status_matches_the_frozen_matrix():
    """Keep every scenario and expected cell independent of the adapter implementation."""
    from itertools import product

    matrix = json.loads(CAPTURE_MATRIX.read_text(encoding="utf-8"))
    names = ["trace_mode", "transcripts_found", "sessions", "batches_failed", "imports_clean",
             "record_failures", "findings_lost", "capture_gap"]
    assert matrix["fields"] == names
    assert len(matrix["columns"]) == 9
    assert set(matrix["expectations"]) == set(capture_status(
        "off", transcripts_found=0, sessions=0, batches_failed=0))
    for expected in matrix["expectations"].values():
        assert len(expected) == len(matrix["columns"])
    for index, (column, value_lists) in enumerate(matrix["columns"].items()):
        assert len(value_lists) == len(names) and all(value_lists)
        for values in product(*value_lists):
            call = dict(zip(names, values, strict=True))
            mode = call.pop("trace_mode")
            returned = capture_status(mode, **call)
            expected = {key: row[index] for key, row in matrix["expectations"].items()}
            assert returned == expected, (column, mode, call, returned)


def test_two_claims_hold_across_the_whole_input_space_the_columns_only_sample():
    """Global invariants hold beyond the sampled matrix columns."""
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
        # The turn that consumes the read. The collector claims a context selection only for a
        # file a later model turn actually saw, so a transcript that ends on the tool result
        # describes a read nothing consumed.
        {"type": "assistant", "uuid": "u3", "sessionId": "session-aaaa", "message": {
            "role": "assistant", "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 1400, "output_tokens": 90},
            "content": [{"type": "text", "text": "The handler shells out with request input."}]}},
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


def test_the_batch_wall_clock_is_summed_from_its_shares_like_every_other_number():
    """DeepSec 2.3.10 divides ``durationMs`` among the batch's files, so it is summed.

    A real run of this adapter recorded 45316.33 ms on each of a batch's three files for a
    batch its own stdout timed at 135.9 seconds. Taking a maximum, which an older DeepSec's
    duplicated whole numbers had suggested, reported that batch as a third of its length.
    """
    files = tuple((f"f{i}.py.json", {"filePath": f"f{i}.py", "analysisHistory": [{
        "runId": "r1", "agentSessionId": "3348970b-6b99-46ad-a496-dd84c5a85613", "model": "m",
        "durationMs": 135949 / 3, "durationApiMs": 121684 / 3, "numTurns": 13 / 3,
        "costUsd": 0.15 / 3}]}) for i in range(3))
    session = sessions_from(files)[0]
    assert session.duration_ms == pytest.approx(135949)
    assert session.duration_suspect is False
    assert session.duration_api_ms == pytest.approx(121684)
    assert session.num_turns == pytest.approx(13)
    assert session.cost_usd == pytest.approx(0.15)


def test_the_older_duplicated_wall_clock_is_flagged_and_never_guessed_at():
    """An older DeepSec wrote the whole batch clock onto every file instead of dividing it.

    The sum is wrong for such a record and there is no honest way to know which version wrote
    it, so the number stays the sum and the run says the number may be duplicated. Guessing a
    different total from a guess about the writer would be worse than a flagged one.
    """
    old = tuple((f"f{i}.py.json", {"filePath": f"f{i}.py", "analysisHistory": [{
        "runId": "r1", "agentSessionId": "3348970b-6b99-46ad-a496-dd84c5a85613", "model": "m",
        "durationMs": 40847, "durationApiMs": 121684 / 3, "numTurns": 13 / 3,
        "costUsd": 0.15 / 3}]}) for i in range(3))
    session = sessions_from(old)[0]
    assert session.duration_suspect is True
    assert session.duration_ms == pytest.approx(3 * 40847), "the number is not guessed at"

    # One file in a batch is one share and one whole at the same time, so it is never suspect.
    single = (("f0.py.json", {"analysisHistory": [{
        "runId": "r1", "agentSessionId": "3348970b-6b99-46ad-a496-dd84c5a85613", "durationMs": 40847, "numTurns": 4.5}]}),)
    assert sessions_from(single)[0].duration_suspect is False

    # Nor is a batch whose other shares are whole numbers too: there is nothing to contrast.
    whole = tuple((f"f{i}.py.json", {"analysisHistory": [{
        "runId": "r1", "agentSessionId": "3348970b-6b99-46ad-a496-dd84c5a85613", "durationMs": 100, "numTurns": 2,
        "costUsd": 1}]}) for i in range(2))
    assert sessions_from(whole)[0].duration_suspect is False


def test_a_suspect_duration_is_named_in_the_run_record(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path, duplicated_duration=True)
    stub_collector(monkeypatch, tmp_path, found=False)
    bundle = invoke(tmp_path, root)
    _result, execution = documents(bundle)
    note = next(note for note in execution["notes"] if "durationMs" in note)
    assert "possibly duplicated" in note and "older than 2.3.10" in note


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
    assert "(pending)" in result["error"]["message"]
    assert result["bundles_resolved"] is False, "no quiet credit for a file nothing opened"
    note = next(note for note in execution["notes"] if "left unfinished" in note)
    assert "config.limit (1)" in note and "not a negative result" in note
    assert len(result["claims"]) == 1, "the finding the run did produce is still reported"


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

    path, external = record_path(name, {"filePath": "/outside/the-workspace/thing.py"})
    assert path == expected
    assert external is (expected.startswith("external:"))
    assert not path.startswith("/")


def test_a_hostile_file_path_never_reaches_a_session_or_a_candidate(tmp_path, monkeypatch):
    """Absolute, traversal and outside-workspace values, through the whole session builder."""
    from scaneval.adapters.deepsec import candidates_from, sessions_from

    files = (
        ("/etc/passwd.json", {"filePath": "/etc/passwd",
                              "candidates": [{"vulnSlug": "x", "lineNumbers": [1]}],
                              "analysisHistory": [{"runId": "r", "agentSessionId": "09f298df-1c4e-4a30-9c07-6f2b0d51aa11"}]}),
        ("../../escape.py.json", {"filePath": "../../escape.py",
                                  "candidates": [{"vulnSlug": "y", "lineNumbers": [2]}],
                                  "analysisHistory": [{"runId": "r", "agentSessionId": "09f298df-1c4e-4a30-9c07-6f2b0d51aa11"}]}),
        ("src/ok.py.json", {"filePath": "/var/tmp/run/source/src/ok.py",
                            "candidates": [{"vulnSlug": "z", "lineNumbers": [3]}],
                            "analysisHistory": [{"runId": "r", "agentSessionId": "09f298df-1c4e-4a30-9c07-6f2b0d51aa11"}]}),
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


def test_a_refusal_reason_is_a_closed_code_and_relocated_prose_kept_for_content():
    """Free model prose can quote source and name a machine; metadata may carry neither.

    A 120-character prefix of it used to. That was still prose, and a window that size can open
    part way through a line of source the model was quoting, so it is gone rather than narrowed.
    """
    from scaneval.adapters.deepsec import sessions_from

    reason = ("could not read /var/tmp/run/source/src/secret.py: " + "verbose model prose " * 40)
    files = (("src/a.py.json", {"analysisHistory": [{
        "runId": "r", "agentSessionId": "09f298df-1c4e-4a30-9c07-6f2b0d51aa11",
        "refusal": {"refused": True, "reason": reason}}]}),)
    refusal = sessions_from(files, (Path("/var/tmp/run/source"),))[0].refusals[0]
    assert refusal.code == "refused", "no skipped list, so the structural code is the bare one"
    assert not hasattr(refusal, "summary"), "there is no metadata-bound prefix any more"
    # The prose is kept whole for content, with its paths relocated: an event may not carry a
    # home directory in any recording mode.
    assert "/var/tmp/run/source" not in refusal.reason
    assert refusal.reason.startswith("could not read src/secret.py:")
    assert "verbose model prose" in refusal.reason

    with_skips = (("src/a.py.json", {"analysisHistory": [{
        "runId": "r", "agentSessionId": "09f298df-1c4e-4a30-9c07-6f2b0d51aa11",
        "refusal": {"refused": True, "reason": "x", "skipped": [{"filePath": "y"}]}}]}),)
    assert sessions_from(with_skips)[0].refusals[0].code == "refused_with_skipped_files"


def test_the_refusal_reason_reaches_content_only_and_metadata_carries_a_code(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path, refusal=True)
    stub_collector(monkeypatch, tmp_path, found=False)
    content_bundle = invoke(tmp_path / "c", root, out="out-content", trace_mode="content")
    response = next(event for event in trace_events(content_bundle)
                    if event["metadata"].get("refusals"))
    assert response["content"]["refusal_reasons"][0]["reason"] == "the file was not readable"
    assert set(response["metadata"]["refusals"][0]) == {"file_path", "reason_code"}

    metadata_bundle = invoke(tmp_path / "m", root, out="out-metadata", trace_mode="metadata")
    metadata_response = next(event for event in trace_events(metadata_bundle)
                             if event["metadata"].get("refusals"))
    assert "content" not in metadata_response, "metadata mode stores no reason text at all"
    assert metadata_response["metadata"]["refusals"][0]["reason_code"] == "refused_with_skipped_files"
    text = json.dumps(metadata_response)
    assert "not readable" not in text, "no prose from the model in a metadata-mode event"


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


# --- a transcript that exists is not a transcript that was read --------------------------


def test_an_unreadable_main_transcript_keeps_the_fallback_pair_and_never_claims_complete(tmp_path, monkeypatch):
    """The collector reports a read failure by returning, not by raising.

    Taking "it returned" for "it worked" suppressed the reconstructed pair for a session whose
    transcript nobody could read, so the call vanished from the trace, while ``tool_calls``
    went on reading ``complete`` over it. A call must never disappear because a log was
    unreadable.
    """
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path, main_unreadable=True)
    bundle = invoke(tmp_path, root)
    result, execution = documents(bundle)
    assert result["status"] == "success", execution["error"]

    events = trace_events(bundle)
    requests = [event for event in events if event["type"] == "model.request"]
    responses = [event for event in events if event["type"] == "model.response"]
    assert requests and len(requests) == len(responses), "the call is still in the trace"
    assert all(event["metadata"]["source"] == "harness_record" for event in requests)
    assert requests[0]["metadata"]["transcript_imported"] is False

    assert execution["capture"]["tool_calls"] in ("partial", "unavailable")
    assert execution["capture"]["tool_calls"] != "complete"
    assert any("produced no model turn" in note for note in execution["notes"]), execution["notes"]
    assert any("could not be read" in note for note in execution["notes"]), execution["notes"]


def test_a_subagent_transcript_that_imported_does_not_rescue_an_unreadable_main_one(tmp_path, monkeypatch):
    """Main failed, subagent imported: the sidechain is captured, the call is not."""
    root = fake_deepsec_root(tmp_path, session_ids=["session-aaaa"])
    stub_collector(monkeypatch, tmp_path, subagent=True, main_unreadable=True)
    bundle = invoke(tmp_path, root)
    _result, execution = documents(bundle)
    events = trace_events(bundle)

    # The subagent's tool events are there, so something was captured...
    assert [event for event in events if event["type"] == "tool.start"]
    # ...and the call itself is still described by DeepSec's own record.
    requests = [event for event in events if event["type"] == "model.request"]
    assert requests and requests[0]["metadata"]["source"] == "harness_record"
    # Captured, but not completely: a session whose main transcript said nothing is not one
    # this run saw the tool calls of.
    assert execution["capture"]["tool_calls"] == "partial"
    assert execution["capture"]["context_selection"] == "partial"


def test_a_transcript_import_that_reports_a_capture_loss_is_never_clean(tmp_path, monkeypatch):
    """Whatever the collector says it was short of, the matrix reads it."""
    from scaneval.adapters.deepsec import ImportHealth, import_health

    assert import_health(StubSummary()) == ImportHealth(1, True, ())
    assert import_health(StubSummary.unreadable()).turns == 0
    assert import_health(StubSummary.unreadable()).captured is False
    assert "transcript could not be read" in import_health(StubSummary.unreadable()).loss
    assert any("no capture of context_selection" in reason
               for reason in import_health(StubSummary.unreadable()).loss)
    assert import_health(StubSummary(malformed_lines=2)).loss == ("2 malformed line(s)",)
    assert import_health(StubSummary(unmatched_tool_results=3)).loss == (
        "3 unmatched tool result(s)",)
    assert import_health(StubSummary(capture={"tool_calls": "unavailable"})).loss == (
        "the importer reported no capture of tool_calls",)
    assert import_health(StubSummary(notes=("transcript was truncated",))).loss == (
        "transcript was truncated",)
    # A summary from a collector this adapter has never seen must not raise or mislead.
    assert import_health(object()).captured is False


def test_a_reported_capture_loss_makes_tool_calls_partial_in_a_whole_run(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path, unmatched=2)
    bundle = invoke(tmp_path, root)
    _result, execution = documents(bundle)
    assert execution["capture"]["tool_calls"] == "partial"
    assert any("short of the file" in note and "unmatched tool result" in note
               for note in execution["notes"]), execution["notes"]


# --- only ``analyzed`` says DeepSec finished with a file ------------------------------------


def test_every_status_but_analyzed_is_classified_as_unfinished_or_unreadable():
    """DeepSec declares four statuses and exactly one of them means it is done.

    ``pending`` and ``processing`` were not treated alike: only ``pending`` counted, so a record
    a run was still holding when it ended read as a finished one. A status the enum does not
    have, or none at all, is not a state to interpret at all.
    """
    from scaneval.adapters.deepsec import RECORD_STATUSES, record_statuses

    assert RECORD_STATUSES == ("pending", "processing", "analyzed", "error")
    statuses = record_statuses((
        ("done.json", {"status": "analyzed"}),
        ("held.json", {"status": "processing"}),
        ("waiting.json", {"status": "pending"}),
        ("broken.json", {"status": "error"}),
        ("odd.json", {"status": "finished"}),
        ("silent.json", {}),
        ("numeric.json", {"status": 3}),
    ))
    assert statuses.finished == 1
    assert statuses.unfinished == ("held.json (processing)", "waiting.json (pending)")
    assert statuses.errored == ("broken.json",)
    assert [name for name, _reason in statuses.invalid] == ["numeric.json", "odd.json", "silent.json"]
    assert statuses.incomplete == 5


@pytest.mark.parametrize("status,code", [
    ("processing", "scope_incomplete"),
    ("pending", "scope_incomplete"),
    ("finished-ish", "invalid_record_status"),
    (None, "invalid_record_status"),
])
def test_a_record_deepsec_did_not_finish_never_earns_quiet_credit(tmp_path, monkeypatch, status, code):
    """A run that abandoned a file in flight used to return success with bundles resolved."""
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    adapter = get_adapter("deepsec")
    spec = system_spec(root)
    preparation = adapter.prepare(spec, tmp_path / "cache")
    original = deepsec_module.run_command

    def run_command(argv, **kwargs):
        result = original(argv, **kwargs)
        if argv[1] == "export":
            record_path = sorted((Path(kwargs["cwd"]) / "data").rglob("files/**/*.json"))[0]
            record = json.loads(record_path.read_text(encoding="utf-8"))
            if status is None:
                record.pop("status", None)
            else:
                record["status"] = status
            record_path.write_text(json.dumps(record), encoding="utf-8")
        return result

    monkeypatch.setattr(deepsec_module, "run_command", run_command)
    bundle = run_invocation(prepared=prepared_input(tmp_path), adapter=adapter, spec=spec,
                            preparation=preparation, out_dir=tmp_path / "out",
                            run_id="run-deepsec", timeout_seconds=120, trace_mode="content",
                            network_policy="model_provider_only", clock=CLOCK)
    result, execution = documents(bundle)
    assert result["status"] == "partial", execution["error"]
    assert result["error"]["code"] == code
    assert result["bundles_resolved"] is False
    assert result["claims"], "the findings the run did produce are still reported"


def test_a_record_with_no_readable_status_is_named_in_the_run_record(tmp_path, monkeypatch):
    from scaneval.adapters.deepsec import record_statuses

    statuses = record_statuses((("odd.json", {"status": "halfway"}),))
    assert "is not one DeepSec declares" in statuses.invalid[0][1]
    assert record_statuses((("x.json", {}),)).invalid[0][1] == "the record carries no status at all"


# --- a record path this run refused is import loss, never an absent record -------------------


def _scan_with_planted(tmp_path, monkeypatch, plant) -> tuple[dict, dict]:
    """Run a whole scan, letting *plant* touch the record tree after the last step."""
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    adapter = get_adapter("deepsec")
    spec = system_spec(root)
    preparation = adapter.prepare(spec, tmp_path / "cache")
    original = deepsec_module.run_command

    def run_command(argv, **kwargs):
        result = original(argv, **kwargs)
        if argv[1] == "export":
            plant(Path(kwargs["cwd"]))
        return result

    monkeypatch.setattr(deepsec_module, "run_command", run_command)
    bundle = run_invocation(prepared=prepared_input(tmp_path), adapter=adapter, spec=spec,
                            preparation=preparation, out_dir=tmp_path / "out",
                            run_id="run-deepsec", timeout_seconds=120, trace_mode="content",
                            network_policy="model_provider_only", clock=CLOCK)
    return documents(bundle)


def test_a_symlinked_record_directory_is_counted_rather_than_passed_over(tmp_path, monkeypatch):
    """Refusing to follow it is right; reading the run as complete without it is not.

    A link standing where a record directory belongs matched neither the directory branch nor
    the record branch of the walk, so every record behind it vanished in silence and a
    two-file scan read as a complete one.
    """
    def plant(workspace: Path) -> None:
        files = next(iter((workspace / "data").glob("*/files")))
        directory = next(entry for entry in files.iterdir() if entry.is_dir())
        elsewhere = workspace.parent / "not-this-run"
        elsewhere.mkdir(exist_ok=True)
        shutil.rmtree(directory)
        directory.symlink_to(elsewhere, target_is_directory=True)

    result, execution = _scan_with_planted(tmp_path, monkeypatch, plant)
    assert result["status"] == "partial"
    assert result["error"]["code"] == "import_loss"
    assert result["bundles_resolved"] is False
    assert any("symbolic link" in note and "nothing behind it was read" in note
               for note in execution["notes"]), execution["notes"]
    assert execution["capture"]["finding_candidate"] == "partial"


def test_a_symlinked_record_file_is_counted_rather_than_passed_over(tmp_path, monkeypatch):
    def plant(workspace: Path) -> None:
        files = next(iter((workspace / "data").glob("*/files")))
        record = sorted(files.rglob("*.json"))[0]
        record.unlink()
        record.symlink_to(workspace.parent / "elsewhere.json")

    result, execution = _scan_with_planted(tmp_path, monkeypatch, plant)
    assert result["status"] == "partial" and result["error"]["code"] == "import_loss"
    assert result["bundles_resolved"] is False
    assert any("symbolic link" in note for note in execution["notes"]), execution["notes"]


def test_a_named_pipe_wearing_a_record_name_is_counted_rather_than_opened(tmp_path, monkeypatch):
    def plant(workspace: Path) -> None:
        files = next(iter((workspace / "data").glob("*/files")))
        os.mkfifo(files / "pretend.json")

    result, execution = _scan_with_planted(tmp_path, monkeypatch, plant)
    assert result["status"] == "partial" and result["error"]["code"] == "import_loss"
    assert any("not a regular file" in note for note in execution["notes"]), execution["notes"]


def test_a_file_under_files_that_is_not_a_record_is_not_counted_as_loss(tmp_path, monkeypatch):
    """Only a path that should have been read counts; an ordinary stray file is not one."""
    def plant(workspace: Path) -> None:
        files = next(iter((workspace / "data").glob("*/files")))
        (files / "notes.txt").write_text("not a record\n", encoding="utf-8")

    result, _execution = _scan_with_planted(tmp_path, monkeypatch, plant)
    assert result["status"] == "success"
    assert result["bundles_resolved"] is True


# --- a session id is scanner-written text before it is a lookup key -------------------------


@pytest.mark.parametrize("session_id,usable", [
    ("3348970b-6b99-46ad-a496-dd84c5a85613", True),
    ("09f298df1c4e4a309c076f2b0d51aa11", True),
    ("session-aaaa", True),
    ("*", False),
    ("?", False),
    ("[abcdefgh]", False),
    ("{a,b}cdefgh", False),
    ("**/../secrets", False),
    ("../../etc/passwd", False),
    ("with space and more", False),
    ("with\ttab-chars", False),
    ("short", False),
    ("", False),
    ("-leading-hyphen", False),
    ("a" * 129, False),
    (None, False),
    (12345678, False),
])
def test_only_an_id_transcript_discovery_may_be_handed_is_usable(session_id, usable):
    """The id comes off a scanner-written record and is handed to a lookup, so it is checked."""
    from scaneval.adapters.deepsec import session_id_usable

    assert session_id_usable(session_id) is usable


def test_a_crafted_session_id_never_reaches_discovery_and_imports_nobody_else(tmp_path, monkeypatch):
    """``*`` interpolated into a glob pulled every transcript on the machine into one trace.

    Discovery is literal now; this is the other half, at the boundary where the value enters.
    The projects directory here holds transcripts of unrelated sessions, and none of them may
    appear in this run's trace.
    """
    projects = tmp_path / "claude-projects" / "-some-other-run"
    projects.mkdir(parents=True)
    for other in ("11111111-1111-4111-8111-111111111111",
                  "22222222-2222-4222-8222-222222222222"):
        (projects / f"{other}.jsonl").write_text(json.dumps(
            {"type": "assistant", "uuid": "u1", "sessionId": other, "message": {
                "role": "assistant", "model": "someone-elses-model",
                "usage": {"input_tokens": 9, "output_tokens": 9},
                "content": [{"type": "text", "text": "not this run"}]}}) + "\n", encoding="utf-8")

    root = fake_deepsec_root(tmp_path, session_ids=["*"])
    calls = stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root, claude_projects_dir=str(tmp_path / "claude-projects"))
    result, execution = documents(bundle)
    assert result["status"] == "success", execution["error"]

    assert calls == [], "an unusable id is never handed to the finder"
    events = trace_events(bundle)
    assert "someone-elses-model" not in json.dumps(events)
    assert not [event for event in events if event["metadata"].get("source")
                == "claude_code_transcript"]

    # It is treated exactly like a missing id: its own uncorrelated call, saying which.
    requests = [event for event in events if event["type"] == "model.request"]
    assert requests, "the call is still described by DeepSec's own record"
    assert all(event["metadata"]["correlation"] == "invalid_session_id" for event in requests)
    assert all(event["call_id"].startswith("deepsec/uncorrelated/") for event in requests)
    assert any("not one transcript discovery may be handed" in note
               for note in execution["notes"]), execution["notes"]
    assert execution["capture"]["tool_calls"] == "unavailable"


def test_a_valid_session_id_still_resolves_to_its_own_transcript(tmp_path, monkeypatch):
    """The control: the rule must not cost a real lookup."""
    root = fake_deepsec_root(tmp_path, session_ids=["3348970b-6b99-46ad-a496-dd84c5a85613"])
    calls = stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    _result, execution = documents(bundle)
    assert [call["session_id"] for call in calls if call["call"] == "find"] == [
        "3348970b-6b99-46ad-a496-dd84c5a85613"]
    request = next((event for event in trace_events(bundle)
                    if event["type"] == "model.request"
                    and event["metadata"].get("source") == "harness_record"), None)
    assert request is None, "the transcript described the call, so no fallback pair"
    assert execution["capture"]["tool_calls"] == "complete"


def test_an_unusable_id_is_its_own_call_and_never_merged_with_another():
    files = (
        ("src/a.py.json", {"analysisHistory": [{"runId": "r", "agentSessionId": "*"}]}),
        ("src/b.py.json", {"analysisHistory": [{"runId": "r", "agentSessionId": "*"}]}),
        ("src/c.py.json", {"analysisHistory": [{"runId": "r", "agentSessionId": ""}]}),
    )
    groups = sessions_from(files)
    assert [group.correlation for group in groups] == [
        "invalid_session_id", "invalid_session_id", "missing_session_id"]
    assert len({group.key for group in groups}) == 3
    assert all(not group.correlated for group in groups)


# --- PR mode ----------------------------------------------------------------------------
#
# A PR request runs DeepSec's own direct mode over a two-commit workspace: ``process --diff
# <base>..<head>`` and ``export``, with no separate scan step. The fake CLI's direct mode prints
# what DeepSec 2.3.10 prints (its colors, its summary lines, its exit codes), which was read from
# the bundle and, for the paths that cost no model call, checked against the real CLI.


def workspace_git(cwd: Path, *args: str) -> str:
    environment = {**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
                   "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
                          env=environment).stdout.strip()


BASE_TREE = {
    "src/server.js": "const { exec } = require('child_process');\nexec(process.argv[2]);\n",
    "src/db.js": "module.exports = (db, id) => db.query('select * from t where id = ' + id);\n",
    "README.md": "# fixture\n",
}


def pr_workspace(tmp_path: Path, head: dict, *, base: dict | None = None,
                 name: str = "pr-source") -> tuple[Path, PrRange]:
    """A workspace shaped like the one the runner builds for a PR input.

    A base commit holding *base* (the fixture tree by default), a head commit that applies *head*
    to it (a value of ``None`` deletes the path), ``HEAD`` at head, and a clean status.
    """
    workspace = tmp_path / name
    workspace.mkdir()
    workspace_git(workspace, "init", "-q", "-b", "main")

    def commit(files: dict, message: str) -> str:
        for relative, content in files.items():
            target = workspace / relative
            if content is None:
                target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        workspace_git(workspace, "add", "-A", "-f", ".")
        workspace_git(workspace, "commit", "-q", "--no-verify", "--allow-empty", "-m", message)
        return workspace_git(workspace, "rev-parse", "HEAD")

    base_commit = commit(BASE_TREE if base is None else base, "base")
    return workspace, PrRange(base_commit, commit(head, "head"))


def pr_request(pr: PrRange, spec: SystemSpec, *, trace_mode: str = "off", timeout_seconds: float = 300) -> dict:
    """The scan request the runner would build for a PR input, checked against the request contract."""
    prepared = PreparedInput("pr-fixture", Path("."), "sha256:" + "0" * 64, ("javascript",), {}, mode="pr",
                             pr={"base_commit": pr.base, "head_commit": pr.head})
    return build_request("run-deepsec-pr", prepared, spec, timeout_seconds=timeout_seconds, trace_mode=trace_mode,
                         pr={"base": pr.base, "head": pr.head})


def scan_pr(tmp_path: Path, root: Path, workspace: Path, pr: PrRange, *, trace_mode: str = "off",
            timeout_seconds: float = 300, request: dict | None = None, **overrides):
    """One PR-mode scan by the adapter itself, over *workspace*: ``(outcome, raw dir, trace dir or None)``."""
    adapter = get_adapter("deepsec")
    spec = system_spec(root, **overrides)
    preparation = adapter.prepare(spec, tmp_path / "cache")
    raw = tmp_path / "raw"
    raw.mkdir()
    trace = None
    if trace_mode != "off":
        trace = tmp_path / "trace"
        trace.mkdir()
    outcome = adapter.scan(request=request or pr_request(pr, spec, trace_mode=trace_mode,
                                                         timeout_seconds=timeout_seconds),
                           source_dir=workspace, raw_dir=raw, spec=spec, preparation=preparation,
                           timeout_seconds=timeout_seconds, trace_mode=trace_mode, trace_dir=trace)
    return outcome, raw, trace


def binary_of(root: Path) -> str:
    return str(root.resolve() / "node_modules" / ".bin" / "deepsec")


PR_PROJECT = "scaneval-" + "0" * 16
CHANGED_SOURCE = {"src/server.js": "const x = 1;\n", "src/routes.js": "module.exports = 1;\n"}


def test_deepsec_declares_pr_beside_full():
    assert get_adapter("deepsec").scan_modes == frozenset({"full", "pr"})


def test_a_pr_request_runs_direct_mode_and_export_and_no_separate_scan(tmp_path):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, {**CHANGED_SOURCE, "README.md": "# more\n"})

    outcome, raw, _ = scan_pr(tmp_path, root, workspace, pr)

    binary = binary_of(root)
    assert outcome.command == [
        binary, "process", "--project-id", PR_PROJECT, "--root", str(workspace), "--diff", f"{pr.base}..{pr.head}",
        "--agent", "claude", "--model", "claude-haiku-4-5", "--concurrency", "1", "--thinking-level", "low",
        "--batch-size", "3", "--max-turns", "60",
        "&&", binary, "export", "--format", "json", "--project-id", PR_PROJECT, "--out", str(raw / "deepsec-export.json")]
    assert "--limit" not in outcome.command, "direct mode never applies --limit, so it is not sent"
    assert "scan" not in outcome.command
    artifact_ids = {artifact["id"] for artifact in outcome.artifacts}
    assert {"deepsec-process-stdout", "deepsec-process-stderr", "deepsec-export-stdout", "deepsec-export"} <= artifact_ids
    assert not any(identifier.startswith("deepsec-scan-") for identifier in artifact_ids)
    assert not (raw / "deepsec-scan.stdout.txt").exists()
    assert (raw / "deepsec-process.stdout.txt").is_file()


def test_the_pr_notes_say_two_steps_and_never_the_three_of_a_full_run(tmp_path):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)
    assert not any("three CLI steps" in note for note in outcome.notes)
    steps = next(note for note in outcome.notes if note.startswith("DeepSec ran as two CLI steps"))
    assert f"--diff {pr.base}..{pr.head}" in steps and "no separate scan step was run" in steps
    assert "those two argv lists" in steps


def test_a_pr_run_records_that_limit_had_no_effect_and_sends_none(tmp_path):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr, limit=1)
    assert "--limit" not in outcome.command
    assert any("config.limit (1) was not passed to DeepSec" in note and "never applies --limit" in note
               for note in outcome.notes)
    # Both changed files were investigated: the limit had no effect, exactly as the note says.
    assert len(outcome.claims) == 2


def test_a_pr_run_with_no_limit_configured_says_nothing_about_one(tmp_path):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr, limit=None)
    assert not any("config.limit" in note for note in outcome.notes)


def test_an_exit_of_1_with_findings_is_a_normal_review_that_is_recorded_as_one(tmp_path):
    """Direct mode exits 1 when it produced findings, which is a review that worked."""
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)

    outcome, raw, _ = scan_pr(tmp_path, root, workspace, pr)

    stdout = (raw / "deepsec-process.stdout.txt").read_bytes().decode("utf-8")
    assert "2 new finding(s)" in stdout and "exiting 1" in stdout
    assert outcome.status == "success" and outcome.error is None and outcome.bundles_resolved is True
    assert outcome.exit_code == 0, "the last step's exit code is the export's"
    assert sorted(claim["primary_location"]["path"] for claim in outcome.claims) == ["src/routes.js", "src/server.js"]
    assert all(claim["native_rule_id"] == "deepsec:command-injection" for claim in outcome.claims)
    note = next(note for note in outcome.notes if note.startswith("deepsec process exited 1 and the run went on"))
    assert "2 finding(s), 0 file(s) in status 'error' and 0 unfinished file(s)" in note
    assert "DeepSec's own summary said 2 finding(s)" in note


# --- PR mode: what an exit 1 means ------------------------------------------------------
#
# Direct mode exits 1 for findings, for an errored batch and for an exhausted quota, and also for
# a runtime failure. The status is made from the records DeepSec left; what it printed only names
# the reason.


def test_a_pr_run_with_an_errored_batch_and_a_finished_one_is_partial_and_keeps_the_findings(tmp_path):
    root = fake_deepsec_root(tmp_path, fail_batches=[0])
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)

    outcome, raw, _ = scan_pr(tmp_path, root, workspace, pr, batch_size=1)

    assert "1 batch(es) errored" in (raw / "deepsec-process.stdout.txt").read_text(encoding="utf-8")
    assert outcome.status == "partial" and outcome.bundles_resolved is False
    assert outcome.error["code"] == "deepsec_batches_failed"
    assert "1 file(s) in status 'error'" in outcome.error["message"]
    assert "DeepSec itself counted 1 errored batch(es)" in outcome.error["message"]
    assert "part of the change reached no verdict" in outcome.error["message"]
    assert len(outcome.claims) == 1, "the batch that finished still reports what it found"
    assert any("deepsec process exited 1 and the run went on" in note for note in outcome.notes)


def test_a_pr_run_in_which_every_batch_errored_observed_nothing_and_is_an_error(tmp_path):
    """The real CLI, given a Claude executable that fails at once, ends exactly here: exit 1, files in error."""
    root = fake_deepsec_root(tmp_path, fail_batches=[0])
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)

    outcome, *_ = scan_pr(tmp_path, root, workspace, pr, batch_size=5)

    assert outcome.status == "error" and outcome.claims == []
    assert outcome.error["code"] == "deepsec_batches_failed"
    assert "2 file(s) in status 'error'" in outcome.error["message"]
    assert outcome.error["message"].endswith("no file reached a verdict, so none of the change was observed")
    assert outcome.bundles_resolved is False


def test_an_exhausted_quota_is_partial_with_the_source_deepsec_named_when_some_file_finished(tmp_path):
    root = fake_deepsec_root(tmp_path, quota_at_batch=1)
    workspace, pr = pr_workspace(tmp_path, {"src/a.js": "1\n", "src/b.js": "2\n", "src/c.js": "3\n"})

    outcome, raw, _ = scan_pr(tmp_path, root, workspace, pr, batch_size=1)

    assert "Stopped: Anthropic API credits exhausted" in (
        ANSI.sub("", (raw / "deepsec-process.stdout.txt").read_text(encoding="utf-8")))
    assert outcome.status == "partial" and outcome.bundles_resolved is False
    assert outcome.error["code"] == "quota_exhausted"
    assert outcome.error["message"] == (
        "deepsec process stopped: Anthropic API credits exhausted, in DeepSec's own words. 1 of 3 file record(s) "
        "reached a verdict, 1 were left in status 'error' and 1 were never finished, so the rest of the change "
        "was not reviewed")
    assert [claim["primary_location"]["path"] for claim in outcome.claims] == ["src/a.js"]
    assert any("1 of 3 file record(s) were left unfinished" in note and "quota runs out" in note
               for note in outcome.notes)
    assert any("DeepSec's own summary said Anthropic API credits exhausted, 1 errored batch(es)" in note
               for note in outcome.notes)


def test_an_exhausted_quota_before_any_file_finished_is_an_error_with_no_claims(tmp_path):
    root = fake_deepsec_root(tmp_path, quota_at_batch=0)
    workspace, pr = pr_workspace(tmp_path, {"src/a.js": "1\n", "src/b.js": "2\n"})

    outcome, *_ = scan_pr(tmp_path, root, workspace, pr, batch_size=1)

    assert outcome.status == "error" and outcome.claims == []
    assert outcome.error["code"] == "quota_exhausted"
    assert "0 of 2 file record(s) reached a verdict" in outcome.error["message"]
    assert outcome.error["message"].endswith("no file reached a verdict, so none of the change was observed")


def test_a_run_that_crashed_mid_way_leaves_unfinished_files_and_says_what_deepsec_wrote(tmp_path):
    """A crash exits 1 too. The files it was holding are unfinished, which is what explains the exit."""
    root = fake_deepsec_root(tmp_path, crash_at_batch=1)
    workspace, pr = pr_workspace(tmp_path, {"src/a.js": "1\n", "src/b.js": "2\n", "src/c.js": "3\n"})

    outcome, *_ = scan_pr(tmp_path, root, workspace, pr, batch_size=1)

    assert outcome.status == "partial" and outcome.bundles_resolved is False
    assert outcome.error["code"] == "scope_incomplete"
    assert outcome.error["message"].startswith("2 of 3 file record(s) were left unfinished (src/b.js.json (processing), "
                                               "src/c.js.json (processing)): DeepSec reached no verdict on them, so "
                                               "this run observed part of the change and says nothing about the rest")
    assert "under config.limit" not in outcome.error["message"], "direct mode never applies the limit"
    assert outcome.error["message"].endswith("deepsec process stderr: fake deepsec crashed mid-run\n\n"
                                             "(set DEEPSEC_DEBUG=1 for a stack trace)")
    assert [claim["primary_location"]["path"] for claim in outcome.claims] == ["src/a.js"]


def test_a_run_that_crashed_before_any_file_finished_is_an_error(tmp_path):
    root = fake_deepsec_root(tmp_path, crash_at_batch=0)
    workspace, pr = pr_workspace(tmp_path, {"src/a.js": "1\n", "src/b.js": "2\n"})
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr, batch_size=1)
    assert outcome.status == "error" and outcome.claims == []
    assert outcome.error["code"] == "scope_incomplete"
    assert outcome.error["message"].endswith("no file reached a verdict, so none of the change was observed")


def test_an_exit_of_1_that_no_record_explains_is_an_error_naming_the_step(tmp_path):
    """A runtime failure exits 1 too (an unresolvable range does, in the real CLI), and leaves nothing on disk."""
    root = fake_deepsec_root(tmp_path, runtime_failure=True)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)

    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)

    assert outcome.status == "error" and outcome.claims == [] and outcome.exit_code == 1
    assert outcome.error["code"] == "process_exit_1"
    assert "left no finding, no file in status 'error' or unfinished and no parse-failure dump" in outcome.error["message"]
    assert "also exits 1 for a runtime failure" in outcome.error["message"]
    assert "fake deepsec could not start its review" in outcome.error["message"]
    assert not any("went on to export" in note for note in outcome.notes)


def test_text_deepsec_printed_cannot_turn_an_unexplained_exit_of_1_into_a_review(tmp_path):
    """Stdout is text an agent's output can reach: a printed summary of findings decides nothing."""
    root = fake_deepsec_root(tmp_path, forged_summary=True)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)

    outcome, raw, _ = scan_pr(tmp_path, root, workspace, pr)

    assert "3 new finding(s)" in (raw / "deepsec-process.stdout.txt").read_text(encoding="utf-8")
    assert outcome.status == "error" and outcome.error["code"] == "process_exit_1"
    assert outcome.claims == []


def test_an_exit_other_than_0_and_1_from_process_is_still_fatal_and_names_the_step(tmp_path):
    root = fake_deepsec_root(tmp_path, process_exit=2)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)
    assert outcome.status == "error" and outcome.error["code"] == "process_exit_2" and outcome.claims == []
    assert "deepsec process exited 2" in outcome.error["message"]
    assert not (tmp_path / "raw" / "deepsec-export.json").exists(), "a fatal exit does not go on to export"
    assert not (tmp_path / "raw" / "deepsec-export.stdout.txt").exists()


def test_a_pr_run_whose_export_fails_after_an_exit_of_1_is_an_export_error(tmp_path):
    root = fake_deepsec_root(tmp_path, export_exit=5)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)
    assert outcome.status == "error" and outcome.error["code"] == "export_exit_5" and outcome.claims == []


def test_a_pr_process_that_outlives_the_budget_is_a_timeout_like_any_other_step(tmp_path):
    root = fake_deepsec_root(tmp_path, hang="process")
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr, timeout_seconds=3)
    assert outcome.status == "timeout" and outcome.timed_out is True
    assert "deepsec process exhausted the shared" in outcome.error["message"]


# --- PR mode: nothing to process --------------------------------------------------------


def test_a_change_deepsec_selects_nothing_from_is_a_completed_empty_review_and_says_which_paths(tmp_path):
    """The real CLI, over a diff of only docs and tests, prints exactly this and exits 0 with no record."""
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, {"README.md": "# more\n", "tests/server.test.js": "t\n", "src/db.js": None})

    outcome, raw, _ = scan_pr(tmp_path, root, workspace, pr)

    assert "Nothing to process" in ANSI.sub("", (raw / "deepsec-process.stdout.txt").read_text(encoding="utf-8"))
    assert outcome.status == "success" and outcome.error is None and outcome.claims == []
    assert outcome.bundles_resolved is True and outcome.exit_code == 0
    empty = next(note for note in outcome.notes if note.startswith("Empty review:"))
    assert f"from {pr.base}..{pr.head}" in empty and "it said \"Nothing to process\"" in empty
    assert "not a failure" in empty
    unreviewed = next(note for note in outcome.notes if note.startswith("DeepSec did not investigate"))
    assert "2 of the 2 path(s) this change leaves at head" in unreviewed
    assert "(README.md, tests/server.test.js)" in unreviewed
    assert "The change also removed 1 path(s) (src/db.js)" in unreviewed
    assert not (raw / "deepsec-workspace" / "data" / PR_PROJECT / "files").exists()


def test_silence_without_deepseccs_own_statement_is_an_error_and_not_an_empty_review(tmp_path):
    """No record and no "Nothing to process": the run may simply not have read the change."""
    root = fake_deepsec_root(tmp_path, say_nothing=True)
    workspace, pr = pr_workspace(tmp_path, {"README.md": "# more\n"})
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)
    assert outcome.status == "error" and outcome.claims == []
    assert outcome.error["code"] == "nothing_processed"
    assert "cannot be told from a run that read nothing" in outcome.error["message"]
    assert not any(note.startswith("Empty review:") for note in outcome.notes)


def test_nothing_to_process_is_not_a_completed_review_when_a_record_says_a_file_errored(tmp_path):
    root = fake_deepsec_root(tmp_path, stray_record=True)
    workspace, pr = pr_workspace(tmp_path, {"README.md": "# more\n"})
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)
    assert outcome.status == "error" and outcome.error["code"] == "deepsec_batches_failed"
    assert not any(note.startswith("Empty review:") for note in outcome.notes)


# --- PR mode: the changed files DeepSec did not investigate -----------------------------


def test_a_pr_run_names_the_changed_paths_deepsecs_own_filter_dropped(tmp_path):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, {**CHANGED_SOURCE, "README.md": "# more\n", "tests/server.test.js": "t\n",
                                            "src/db.js": None, "types/api.d.ts": "export {};\n"})

    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)

    assert outcome.status == "success"
    note = next(note for note in outcome.notes if note.startswith("DeepSec did not investigate"))
    assert note.startswith("DeepSec did not investigate 3 of the 5 path(s) this change leaves at head")
    assert "(README.md, tests/server.test.js, types/api.d.ts)" in note
    assert "keeps only added, modified, renamed and copied paths" in note
    assert "DeepSec's own scope and not a failure of the run" in note
    assert "silence about these paths is not a negative result" in note
    assert "The change also removed 1 path(s) (src/db.js)" in note
    assert "prints quoted" not in note and "except for" not in note, "no name here is one git quotes"
    assert outcome.error is None and outcome.bundles_resolved is True


def test_a_record_the_run_could_not_read_is_said_to_possibly_belong_to_a_path_it_lists(tmp_path):
    """A link where a record directory belongs hides whatever is behind it, so the comparison is short."""
    root = fake_deepsec_root(tmp_path, linked_directory=True)
    workspace, pr = pr_workspace(tmp_path, {**CHANGED_SOURCE, "README.md": "# more\n"})
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)
    assert outcome.status == "partial" and outcome.error["code"] == "import_loss"
    note = next(note for note in outcome.notes if note.startswith("DeepSec did not investigate"))
    assert "(README.md)" in note
    assert note.endswith("1 DeepSec record(s) could not be read, so a path listed here may have had one.")


def test_a_changed_path_git_prints_quoted_makes_the_review_partial_and_is_named_in_the_error_and_the_note(tmp_path):
    """Checked against the real 2.3.10 CLI: a changed src/café.js never reaches it, and nothing says why.

    DeepSec did review src/routes.js, so what it found stays. The change it was handed is not the change it read.
    """
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, {"src/routes.js": "module.exports = 1;\n",
                                            "src/caf\u00e9.js": "module.exports = 2;\n", "README.md": "# more\n"})

    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)

    assert outcome.status == "partial" and outcome.error["code"] == "scope_incomplete"
    assert outcome.bundles_resolved is False, "the claims about the rest are a part delivered; no budget reads off it"
    message = outcome.error["message"]
    assert message.startswith("1 changed path(s) (src/caf\u00e9.js) have a name git prints quoted (a non-ASCII name")
    assert ("cannot resolve a quoted name to a file, so it never investigated them, whatever its ignore filter says"
            in message)
    assert message.endswith("This run therefore observed only part of the change (or none of it) and says nothing "
                            "about them")
    assert "README.md" not in message, "a path that only the ignore filter dropped is DeepSec's scope, and stays a note"
    assert [claim["primary_location"]["path"] for claim in outcome.claims] == ["src/routes.js"]
    note = next(note for note in outcome.notes if note.startswith("DeepSec did not investigate"))
    assert "2 of the 3 path(s) this change leaves at head" in note and "(README.md, src/caf\u00e9.js)" in note
    assert "not a failure of the run, except for the 1 named next;" in note
    assert ("1 of them (src/caf\u00e9.js) have a name git prints quoted by default" in note
            and "for these the omission is a limit of DeepSec's own listing, not a choice of scope" in note)
    assert note.endswith("so this run observed nothing about them and does not stand as a complete or quiet "
                         "observation of the change.")


def test_a_change_that_touches_only_a_quoted_name_is_an_error_and_never_an_empty_review(tmp_path):
    """The reviewer's case: DeepSec says "Nothing to process" and exits 0, and the run is still not a review.

    Recorded as an empty review it was a ``success`` with resolved bundles, and a quiet assessment of the control on
    that file earned credit for a file no model opened.
    """
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, {"src/caf\u00e9.js": "module.exports = 2;\n"})

    outcome, raw, _ = scan_pr(tmp_path, root, workspace, pr)

    assert "Nothing to process" in ANSI.sub("", (raw / "deepsec-process.stdout.txt").read_text(encoding="utf-8"))
    assert outcome.exit_code == 0, "DeepSec itself ran to the end; it is the change it read that was short"
    assert outcome.status == "error" and outcome.claims == [] and outcome.bundles_resolved is False
    assert outcome.error["code"] == "scope_incomplete"
    assert outcome.error["message"].startswith("1 changed path(s) (src/caf\u00e9.js) have a name git prints quoted")
    assert outcome.error["message"].endswith("no file reached a verdict, so none of the change was observed")
    assert not any(note.startswith("Empty review:") for note in outcome.notes)
    assert any("1 of them (src/caf\u00e9.js) have a name git prints quoted by default" in note
               for note in outcome.notes)


def test_the_error_and_the_note_name_the_same_quoted_paths_and_only_those(tmp_path):
    """Each spelling git quotes, a non-ASCII byte and a double quote, beside a docs path the filter dropped."""
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, {"src/routes.js": "1\n", "src/na\u00efve.js": "2\n",
                                            'src/we"ird.js': "3\n", "docs/guide.md": "g\n"})

    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)

    assert outcome.status == "partial" and outcome.error["code"] == "scope_incomplete"
    assert outcome.error["message"].startswith(
        '2 changed path(s) (src/na\u00efve.js, src/we"ird.js) have a name git prints quoted')
    assert "docs/guide.md" not in outcome.error["message"]
    note = next(note for note in outcome.notes if note.startswith("DeepSec did not investigate"))
    assert "3 of the 4 path(s) this change leaves at head" in note
    assert '(docs/guide.md, src/na\u00efve.js, src/we"ird.js)' in note
    assert '2 of them (src/na\u00efve.js, src/we"ird.js) have a name git prints quoted by default' in note


def test_a_quoted_omission_beside_an_unfinished_record_is_still_scope_incomplete(tmp_path):
    """The unfinished file is reported first, with the same code; the omission stays in the note."""
    root = fake_deepsec_root(tmp_path, crash_at_batch=1)
    workspace, pr = pr_workspace(tmp_path, {"src/a.js": "1\n", "src/b.js": "2\n", "src/caf\u00e9.js": "3\n"})

    outcome, *_ = scan_pr(tmp_path, root, workspace, pr, batch_size=1)

    assert outcome.status == "partial" and outcome.error["code"] == "scope_incomplete"
    assert outcome.bundles_resolved is False
    assert outcome.error["message"].startswith("1 of 2 file record(s) were left unfinished (src/b.js.json "
                                               "(processing)): DeepSec reached no verdict on them")
    assert [claim["primary_location"]["path"] for claim in outcome.claims] == ["src/a.js"]
    note = next(note for note in outcome.notes if note.startswith("DeepSec did not investigate"))
    assert "1 of them (src/caf\u00e9.js) have a name git prints quoted by default" in note


def test_a_quoted_name_deepsec_did_investigate_is_not_an_omission(tmp_path):
    """Where git is set to print such a name as it is, DeepSec lists the file and records it: nothing is missing."""
    root = fake_deepsec_root(tmp_path, raw_listing=True)
    workspace, pr = pr_workspace(tmp_path, {"src/routes.js": "1\n", "src/caf\u00e9.js": "2\n"})

    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)

    assert outcome.status == "success" and outcome.error is None and outcome.bundles_resolved is True
    assert sorted(claim["primary_location"]["path"] for claim in outcome.claims) == ["src/caf\u00e9.js",
                                                                                  "src/routes.js"]
    assert not any("did not investigate" in note for note in outcome.notes)


@pytest.mark.parametrize("path, quoted", [
    ("src/app.js", False), ("docs/read me.md", False), ("a-b_c.d/e~f.js", False),
    ("src/caf\u00e9.js", True), ('we"ird.js', True), ("back\\slash.js", True), ("tab\tname.js", True),
    ("new\nline.js", True), ("del\x7f.js", True), ("escaped\\xe9.js", True),
])
def test_git_quotes_a_name_exactly_when_it_holds_a_non_ascii_byte_a_quote_a_backslash_or_a_control(path, quoted):
    assert git_prints_quoted(path) is quoted


def test_a_pr_run_that_investigated_every_changed_path_has_no_such_note(tmp_path):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)
    assert not any("did not investigate" in note for note in outcome.notes)


def test_a_renamed_file_is_investigated_under_its_new_name_and_its_old_name_is_a_removal(tmp_path):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, {"src/db.js": None, "src/store.js": BASE_TREE["src/db.js"]})
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)
    assert [claim["primary_location"]["path"] for claim in outcome.claims] == ["src/store.js"]
    assert not any("did not investigate" in note and "src/store.js" in note for note in outcome.notes)
    assert any(note == "The change also removed 1 path(s) (src/db.js); DeepSec never reads a path that no longer "
                       "exists at head." for note in outcome.notes)


def test_the_unreviewed_note_lists_a_bounded_number_of_paths_and_counts_the_rest():
    changes = tuple(Change("A", f"docs/page-{index:02d}.md") for index in range(12)) + (Change("A", "src/a.js"),)
    files = (("src/a.js.json", {}),)
    note = unreviewed_note(changes, files)
    assert note.startswith("DeepSec did not investigate 12 of the 13 path(s) this change leaves at head")
    assert "docs/page-00.md, docs/page-01.md" in note and "docs/page-07.md and 4 more)" in note
    assert "docs/page-08.md" not in note


def test_the_unreviewed_note_is_none_when_every_present_path_has_a_record_and_nothing_was_removed():
    changes = (Change("M", "src/a.js"), Change("A", "src/b.js"), Change("R", "src/c.js", "src/old.js"))
    files = (("src/a.js.json", {}), ("src/b.js.json", {}), ("src/c.js.json", {}))
    assert unreviewed_note(changes, files) == (
        "The change also removed 1 path(s) (src/old.js); DeepSec never reads a path that no longer exists at head.")
    assert unreviewed_note(changes[:2], files) is None


def test_a_record_that_names_no_path_in_the_tree_cannot_hide_a_dropped_one():
    changes = (Change("A", "src/a.js"),)
    assert unreviewed_note(changes, (("/etc/passwd.json", {}), ("../escape.js.json", {}))) is not None


def test_the_quoted_omissions_are_the_paths_left_at_head_with_no_record_whose_name_git_prints_quoted():
    changes = (Change("M", "src/a.js"), Change("A", "src/caf\u00e9.js"), Change("A", "docs/r\u00e9sum\u00e9.md"),
               Change("A", "docs/readme.md"), Change("A", "src/recorded-\u00e9.js"), Change("D", "src/na\u00efve.js"),
               Change("R", "src/renamed-\u00e9.js", "src/renamed.js"), Change("R", "src/plain.js", "src/old-\u00e9.js"))
    files = (("src/a.js.json", {}), ("src/recorded-\u00e9.js.json", {}), ("src/plain.js.json", {}))

    paths = deepsec_module.dropped_paths(changes, files)

    assert paths.present == ("docs/readme.md", "docs/r\u00e9sum\u00e9.md", "src/a.js", "src/caf\u00e9.js",
                             "src/plain.js", "src/recorded-\u00e9.js", "src/renamed-\u00e9.js"), \
        "a deletion and the old name of a rename are not at head"
    assert paths.dropped == ("docs/readme.md", "docs/r\u00e9sum\u00e9.md", "src/caf\u00e9.js",
                             "src/renamed-\u00e9.js")
    assert paths.quoted == ("docs/r\u00e9sum\u00e9.md", "src/caf\u00e9.js", "src/renamed-\u00e9.js"), \
        "a quoted name DeepSec did record is not one, and neither is a plain name it dropped"
    note = unreviewed_note(changes, files)
    assert ("3 of them (docs/r\u00e9sum\u00e9.md, src/caf\u00e9.js, src/renamed-\u00e9.js) "
            "have a name git prints quoted") in note
    assert note.count("prints quoted") == 1


def test_a_change_with_no_dropped_path_has_no_quoted_omission_and_no_quoted_sentence():
    changes = (Change("M", "src/a.js"), Change("D", "src/caf\u00e9.js"))
    paths = deepsec_module.dropped_paths(changes, (("src/a.js.json", {}),))
    assert paths.dropped == () and paths.quoted == ()
    note = unreviewed_note(changes, (("src/a.js.json", {}),))
    assert "prints quoted" not in note and "did not investigate" not in note, \
        "a deletion is never read, so it is no omission"


def test_a_record_that_names_no_path_in_the_tree_cannot_hide_a_quoted_omission():
    changes = (Change("A", "src/caf\u00e9.js"),)
    files = (("/etc/passwd.json", {}), ("../escape.js.json", {}))
    assert deepsec_module.dropped_paths(changes, files).quoted == ("src/caf\u00e9.js",)


# --- PR mode: what is refused before anything runs --------------------------------------


@pytest.mark.parametrize("mode", ["batch", "bootstrap", "PR", ""])
def test_deepsec_refuses_a_mode_it_does_not_implement_and_runs_nothing(tmp_path, mode):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    with pytest.raises(AdapterError, match="deepsec does not implement scan mode"):
        scan_pr(tmp_path, root, workspace, pr, request={"input": {"mode": mode}})
    assert list((tmp_path / "raw").iterdir()) == [], "no workspace was built and no process ran"


def test_deepsec_refuses_a_pr_request_without_two_commits_and_a_full_request_carrying_a_pr(tmp_path):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    with pytest.raises(AdapterError, match="input.pr is absent"):
        scan_pr(tmp_path, root, workspace, pr, request={"input": {"mode": "pr"}})
    (tmp_path / "raw").rmdir()
    with pytest.raises(AdapterError, match="full-mode request that also carries input.pr"):
        scan_pr(tmp_path, root, workspace, pr, request={"input": {"mode": "full", "pr": {"base": pr.base,
                                                                                         "head": pr.head}}})
    assert list((tmp_path / "raw").iterdir()) == []


def test_deepsec_refuses_a_pr_request_over_a_workspace_that_does_not_hold_its_history(tmp_path):
    """DeepSec would otherwise fail inside its own git call, after paying for nothing but a workspace."""
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    workspace_git(workspace, "checkout", "-q", "--detach", pr.base)
    with pytest.raises(AdapterError, match="not at the request's head commit"):
        scan_pr(tmp_path, root, workspace, pr)
    assert list((tmp_path / "raw").iterdir()) == []


# --- PR mode: the trace and the capture matrix ------------------------------------------


def test_a_pr_run_traces_the_scoped_scan_and_the_findings_and_changes_no_capture_cell(tmp_path, monkeypatch):
    stub_collector(monkeypatch, tmp_path)
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, {**CHANGED_SOURCE, "README.md": "# more\n"})

    outcome, _raw, trace = scan_pr(tmp_path, root, workspace, pr, trace_mode="metadata")

    events = [json.loads(line) for line in (trace / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    types = [event["type"] for event in events]
    assert types.count("finding.candidate") == 4, "two candidates on each of the two files direct mode scanned"
    assert types.count("finding.submitted") == 2
    assert {event["metadata"]["file_path"] for event in events if event["type"] == "finding.candidate"} == {
        "src/routes.js", "src/server.js"}, "nothing about a file DeepSec dropped"
    assert outcome.capture == {"model_requests": "partial", "model_responses": "partial", "tool_calls": "complete",
                               "context_selection": "partial", "finding_candidate": "complete",
                               "finding_submitted": "complete", "finding_validation": "unavailable",
                               "finding_filtered": "unavailable"}


def test_a_pr_run_with_tracing_off_claims_no_observation(tmp_path):
    root = fake_deepsec_root(tmp_path)
    workspace, pr = pr_workspace(tmp_path, CHANGED_SOURCE)
    outcome, *_ = scan_pr(tmp_path, root, workspace, pr)
    assert set(outcome.capture.values()) == {"unavailable"}


# --- PR mode: what DeepSec printed ------------------------------------------------------

ANSI = deepsec_module.ANSI_ESCAPE
# Excerpts of what the real 2.3.10 CLI printed, with its escape sequences: a run whose batch failed
# (a Claude executable that exits at once), and a run whose diff selected nothing.
REAL_ERRORED = ("\x1b[32mProcessing complete.\x1b[0m Run: \x1b[1m20260930055356-1ea8d1485890fae3\x1b[0m\n"
                "  Analyses: 0\n  Findings: 0\n  \x1b[31mErrored batches: 1\x1b[0m\n\n"
                "\x1b[31m1 batch(es) errored — exiting 1 (agent failure, not a clean review).\x1b[0m\n")
REAL_NOTHING = ("\x1b[33mNo files matched git-diff:a..b (after ignore filter).\x1b[0m\n"
                "\x1b[32mNothing to process — exit 0.\x1b[0m\n")


def test_the_process_summary_is_read_through_its_colors():
    assert read_process_output(REAL_ERRORED) == ProcessOutput(errored_batches=1, findings=0)
    assert read_process_output(REAL_NOTHING) == ProcessOutput(nothing_to_process=True)
    quota = ("  Findings: 4\n\n\x1b[31m\x1b[1m✘ Stopped: Vercel AI Gateway credits exhausted\x1b[0m\n\n"
             "  Upstream: 402\n")
    assert read_process_output(quota) == ProcessOutput(quota="Vercel AI Gateway credits", findings=4)
    assert read_process_output("") == ProcessOutput()
    assert read_process_output("\x1b[31m1 new finding(s) — exiting 1\x1b[0m\n") == ProcessOutput()


def test_a_summary_line_counts_only_where_deepsec_prints_it():
    """A line an agent could echo mid-sentence is not a summary line."""
    assert read_process_output("the agent wrote: Nothing to process — exit 0. and more\n") == ProcessOutput()
    assert read_process_output("note Findings: 9\nnote Errored batches: 9\n") == ProcessOutput()


def test_the_last_summary_line_wins():
    text = "  Findings: 1\n  Findings: 7\n"
    assert read_process_output(text).findings == 7


# --- PR mode: a full run is untouched ---------------------------------------------------


def test_a_full_run_still_runs_three_steps_sends_its_limit_and_says_so(tmp_path, monkeypatch):
    root = fake_deepsec_root(tmp_path)
    stub_collector(monkeypatch, tmp_path)
    bundle = invoke(tmp_path, root)
    result, execution = documents(bundle)
    binary = binary_of(root)
    command = execution["command"]
    project, workspace_source, export = command[3], command[5], command[-1]
    assert result["status"] == "success"
    assert command == [
        binary, "scan", "--project-id", project, "--root", workspace_source,
        "&&", binary, "process", "--project-id", project, "--root", workspace_source, "--agent", "claude",
        "--model", "claude-haiku-4-5", "--concurrency", "1", "--thinking-level", "low", "--limit", "6",
        "--batch-size", "3", "--max-turns", "60",
        "&&", binary, "export", "--format", "json", "--project-id", project, "--out", export]
    assert any(note.startswith("DeepSec ran as three CLI steps in one workspace under raw/deepsec-workspace: scan, "
                               "process and export.") for note in execution["notes"])
    assert not any("PR mode" in note or "direct mode" in note or "Empty review" in note
                   for note in execution["notes"])
    assert not any("did not investigate" in note for note in execution["notes"])


def test_a_full_run_over_a_tree_holding_a_name_git_would_quote_is_unaffected(tmp_path, monkeypatch):
    """Full mode walks the tree and reads no git listing, so such a name costs it nothing and it names no omission."""
    stub_collector(monkeypatch, tmp_path)
    root = fake_deepsec_root(tmp_path)
    prepared = prepared_input(tmp_path)
    (prepared.source_dir / "src" / "caf\u00e9.js").write_text("module.exports = 2;\n", encoding="utf-8")
    prepared = replace(prepared, tree_hash=hash_exported_tree(prepared.source_dir)["tree_hash"])
    adapter = get_adapter("deepsec")
    spec = system_spec(root)

    bundle = run_invocation(prepared=prepared, adapter=adapter, spec=spec,
                            preparation=adapter.prepare(spec, tmp_path / "cache"), out_dir=tmp_path / "out",
                            run_id="run-deepsec", timeout_seconds=300, trace_mode="content",
                            network_policy="model_provider_only", clock=CLOCK)

    result, execution = documents(bundle)
    assert result["status"] == "success" and "error" not in result
    assert "src/caf\u00e9.js" in {claim["primary_location"]["path"] for claim in result["claims"]}
    assert not any("did not investigate" in note or "prints quoted" in note for note in execution["notes"])
