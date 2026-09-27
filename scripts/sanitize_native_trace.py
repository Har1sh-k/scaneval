#!/usr/bin/env python3
"""Scrub a real agent-CLI record file so it can be committed as a collector fixture.

A fixture has to be a real record file, because the point of the collectors is that they
read what the CLIs actually write and not what a contract said they would. But the files the
CLIs write are the operator's: a Claude Code transcript is stored under the operator's home,
quotes absolute paths from that machine, and its ``attachment`` records carry the session's
whole system prompt, the MCP servers configured, the skills installed, the hook commands
that ran, and the account email. None of that is the run, and none of it may be published.

So this script is a filter with an allowlist at its centre, not a search-and-replace over a
denylist. The record types the collectors actually read are rewritten field by field; every
other record is reduced to a stub that keeps only its type and its structural links, because
a record nobody reads has nothing to contribute but its name, and its name is what the
importer's untranslated-record counter is about. A denylist would have to anticipate every
field a future CLI version adds; this way a new field in an unread record is dropped by
default and a new field in a read record is dropped unless it is named here.

Identifiers are replaced deterministically rather than removed: the same session ID always
becomes the same placeholder, so a fixture regenerated from a new run of the same shape
still diffs cleanly, and the cross-references inside the file (``parentUuid`` pointing at a
``uuid``, ``tool_use_id`` pointing at a ``tool_use``) survive the substitution and the
fixture still exercises the pairing logic.

Usage::

    python scripts/sanitize_native_trace.py --kind transcript \\
        --workspace /abs/path/to/the/scratch/repo \\
        --in ~/.claude/projects/<slug>/<session>.jsonl \\
        --out schema/v2/fixtures/collectors/claude-code-transcript.jsonl

``--kind`` is one of ``transcript``, ``stream-json``, ``result-json`` or ``codex-exec``.
``--workspace`` is the absolute path of the directory the run happened in; it becomes
``/workspace`` in the output, which is an absolute path so the fixture stays a file the
importers can parse, and which the tests pass as ``workspace_root``. Any other absolute path
that survives becomes ``/redacted/<basename>``, so a leftover home directory cannot reach
the repository even if a record type grows a path field this script does not know about.
``docs/COLLECTORS.md`` documents the procedure this implements.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any


# The workspace root every fixture is rewritten to. Absolute, so the fixture is still a
# parseable record file and the importers' real path handling is what the tests exercise.
WORKSPACE = "/workspace"

# Where an absolute path that is not inside the workspace lands. The basename survives so a
# fixture can still exercise the external-path branch of the importers.
REDACTED_ROOT = "/redacted"

# Any absolute path on a POSIX machine, greedy enough to swallow a path embedded in prose.
ABSOLUTE_PATH = re.compile(r"/(?:[A-Za-z0-9._@+-]+/)+[A-Za-z0-9._@+-]*")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

# Record fields kept on a message record. Everything else on the record is dropped, which is
# how the system prompt, the environment snapshot and the hook output stay out of a fixture
# without this script having to know they exist.
TRANSCRIPT_KEEP = (
    "type", "uuid", "parentUuid", "sessionId", "timestamp", "cwd", "version", "userType",
    "gitBranch", "isSidechain", "agentId", "requestId", "apiBlockIndex", "message",
    "toolUseResult", "sourceToolAssistantUUID",
)
STREAM_KEEP = (
    "type", "subtype", "uuid", "session_id", "request_id", "parent_tool_use_id", "timestamp",
    "message", "tool_use_result", "model", "tools", "cwd",
)
RESULT_KEEP = (
    "type", "subtype", "is_error", "num_turns", "session_id", "duration_ms",
    "duration_api_ms", "total_cost_usd", "usage", "result", "stop_reason",
    "permission_denials",
)
# The message body. ``signature`` is dropped: it is a long opaque server token that adds
# nothing a collector reads and everything a reviewer has to squint at.
MESSAGE_KEEP = ("id", "role", "type", "model", "content", "usage", "stop_reason")
BLOCK_KEEP = (
    "type", "text", "thinking", "id", "name", "input", "tool_use_id", "content", "is_error",
)
USAGE_KEEP = (
    "input_tokens", "output_tokens", "cache_read_input_tokens",
    "cache_creation_input_tokens", "cached_input_tokens", "cache_write_input_tokens",
    "reasoning_output_tokens",
)
# The Read result shape the span logic reads, and the Bash shape beside it.
TOOL_RESULT_KEEP = (
    "type", "file", "stdout", "stderr", "interrupted", "listing", "filenames", "numFiles",
    "agentId", "status", "mode", "numLines", "originalFileContents",
)
FILE_KEEP = ("filePath", "content", "numLines", "startLine", "totalLines")
CODEX_ITEM_KEEP = (
    "id", "type", "text", "command", "aggregated_output", "exit_code", "status", "query",
    "server", "tool", "arguments", "changes", "path", "message",
)
CODEX_KEEP = ("type", "thread_id", "item", "usage", "error", "message")


class Ids:
    """Deterministic placeholder minting. The same native ID always maps to the same stub."""

    def __init__(self) -> None:
        self._issued: dict[tuple[str, str], str] = {}
        self._counts: dict[str, int] = {}

    def __call__(self, kind: str, value: Any) -> Any:
        if not isinstance(value, str) or not value:
            return value
        key = (kind, value)
        if key in self._issued:
            return self._issued[key]
        self._counts[kind] = self._counts.get(kind, 0) + 1
        index = self._counts[kind]
        minted = {
            "uuid": f"00000000-0000-4000-8000-{index:012d}",
            "session": "11111111-2222-4333-8444-555555555555" if index == 1
                       else f"11111111-2222-4333-8444-{index:012d}",
            "request": f"req_fixture{index:012d}",
            "message": f"msg_fixture{index:012d}",
            "tool": f"toolu_fixture{index:012d}",
            "thread": f"01a00000-0000-7000-8000-{index:012d}",
        }[kind]
        self._issued[key] = minted
        return minted


def scrub_text(text: Any, workspace: str) -> Any:
    """Rewrite every absolute path and email address inside one string."""
    if not isinstance(text, str):
        return text

    def replace_path(match: re.Match[str]) -> str:
        found = match.group(0)
        # Idempotent on purpose. A value can be reached by more than one rewrite path, and a
        # second pass that re-read an already-rewritten "/workspace/app.py" as a foreign path
        # would quietly demote it to "/redacted/app.py" and cost the fixture the very case it
        # exists to exercise.
        if found.startswith(WORKSPACE) or found.startswith(REDACTED_ROOT):
            return found
        if found == workspace or found.startswith(workspace.rstrip("/") + "/"):
            tail = found[len(workspace.rstrip("/")):]
            return WORKSPACE + tail
        name = found.rstrip("/").rsplit("/", 1)[-1]
        return f"{REDACTED_ROOT}/{name}" if name else REDACTED_ROOT

    scrubbed = ABSOLUTE_PATH.sub(replace_path, text)
    return EMAIL.sub("operator@example.invalid", scrubbed)


def pick(record: Any, keep: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    return {key: record[key] for key in keep if key in record}


def scrub_value(value: Any, workspace: str) -> Any:
    """Recursively scrub text inside a value that has already been allowlisted."""
    if isinstance(value, str):
        return scrub_text(value, workspace)
    if isinstance(value, list):
        return [scrub_value(item, workspace) for item in value]
    if isinstance(value, dict):
        return {key: scrub_value(item, workspace) for key, item in value.items()}
    return value


def scrub_message(message: Any, workspace: str, ids: Ids) -> Any:
    if not isinstance(message, dict):
        return message
    out = pick(message, MESSAGE_KEEP)
    if "id" in out:
        out["id"] = ids("message", out["id"])
    if isinstance(out.get("usage"), dict):
        out["usage"] = pick(out["usage"], USAGE_KEEP)
    content = out.get("content")
    if isinstance(content, list):
        blocks = []
        for block in content:
            if not isinstance(block, dict):
                continue
            kept = pick(block, BLOCK_KEEP)
            if "id" in kept:
                kept["id"] = ids("tool", kept["id"])
            if "tool_use_id" in kept:
                kept["tool_use_id"] = ids("tool", kept["tool_use_id"])
            if kept.get("type") == "thinking":
                # Replaced rather than kept: reasoning text is model output about the
                # operator's real session and adds nothing a collector reads.
                kept["thinking"] = "[thinking omitted from fixture]"
            blocks.append(scrub_value(kept, workspace))
        out["content"] = blocks
    elif isinstance(content, str):
        out["content"] = scrub_text(content, workspace)
    return scrub_value(out, workspace)


def scrub_tool_result(native: Any, workspace: str) -> Any:
    if not isinstance(native, dict):
        return scrub_value(native, workspace)
    out = pick(native, TOOL_RESULT_KEEP)
    if isinstance(out.get("file"), dict):
        out["file"] = pick(out["file"], FILE_KEEP)
    if "agentId" in out:
        out["agentId"] = "agentfixture000001"
    return scrub_value(out, workspace)


def transcript_record(record: dict[str, Any], workspace: str, ids: Ids) -> dict[str, Any]:
    kind = record.get("type")
    if kind not in ("user", "assistant"):
        # Every other record type keeps its name and its place in the file and nothing else.
        # This is the line that keeps the system prompt, the environment snapshot, the hook
        # commands and the account email out of the repository.
        stub = {"type": kind}
        for key in ("uuid", "parentUuid", "sessionId", "timestamp", "isSidechain"):
            if key in record:
                stub[key] = record[key]
        return _relabel(stub, ids)
    out = pick(record, TRANSCRIPT_KEEP)
    out = _relabel(out, ids)
    if "message" in out:
        out["message"] = scrub_message(out["message"], workspace, ids)
    if "toolUseResult" in out:
        out["toolUseResult"] = scrub_tool_result(out["toolUseResult"], workspace)
    if "agentId" in out:
        out["agentId"] = "agentfixture000001"
    for key in ("cwd",):
        if key in out:
            out[key] = scrub_text(out[key], workspace)
    return out


def stream_record(record: dict[str, Any], workspace: str, ids: Ids) -> dict[str, Any]:
    kind = record.get("type")
    if kind == "result":
        out = pick(record, RESULT_KEEP)
        if isinstance(out.get("usage"), dict):
            out["usage"] = pick(out["usage"], USAGE_KEEP)
        out = _relabel(out, ids)
        return scrub_value(out, workspace)
    if kind == "system" and record.get("subtype") == "init":
        out = {
            "type": "system",
            "subtype": "init",
            "session_id": record.get("session_id"),
            "model": record.get("model"),
            # Counted, never listed: the tool list names the operator's MCP servers.
            "tools": ["Read", "Bash", "Glob", "Grep"],
            "cwd": scrub_text(record.get("cwd"), workspace),
        }
        return _relabel(out, ids)
    if kind in ("user", "assistant"):
        out = pick(record, STREAM_KEEP)
        out = _relabel(out, ids)
        if "message" in out:
            out["message"] = scrub_message(out["message"], workspace, ids)
        if "tool_use_result" in out:
            out["tool_use_result"] = scrub_tool_result(out["tool_use_result"], workspace)
        if "cwd" in out:
            out["cwd"] = scrub_text(out["cwd"], workspace)
        return out
    stub = {"type": kind}
    if "subtype" in record:
        stub["subtype"] = record["subtype"]
    if "uuid" in record:
        stub["uuid"] = record["uuid"]
    if "session_id" in record:
        stub["session_id"] = record["session_id"]
    return _relabel(stub, ids)


def codex_record(record: dict[str, Any], workspace: str, ids: Ids) -> dict[str, Any]:
    out = pick(record, CODEX_KEEP)
    if "thread_id" in out:
        out["thread_id"] = ids("thread", out["thread_id"])
    if isinstance(out.get("item"), dict):
        out["item"] = pick(out["item"], CODEX_ITEM_KEEP)
    if isinstance(out.get("usage"), dict):
        out["usage"] = pick(out["usage"], USAGE_KEEP)
    return scrub_value(out, workspace)


def _relabel(record: dict[str, Any], ids: Ids) -> dict[str, Any]:
    for key in ("uuid", "parentUuid", "leafUuid", "sourceToolAssistantUUID"):
        if key in record:
            record[key] = ids("uuid", record[key])
    for key in ("sessionId", "session_id"):
        if key in record:
            record[key] = ids("session", record[key])
    for key in ("requestId", "request_id"):
        if key in record:
            record[key] = ids("request", record[key])
    for key in ("parent_tool_use_id",):
        if key in record and record[key]:
            record[key] = ids("tool", record[key])
    return record


SCRUBBERS = {
    "transcript": transcript_record,
    "stream-json": stream_record,
    "codex-exec": codex_record,
}


def sanitize(kind: str, text: str, workspace: str) -> str:
    ids = Ids()
    if kind == "result-json":
        parsed = json.loads(text)
        out = pick(parsed, RESULT_KEEP)
        if isinstance(out.get("usage"), dict):
            out["usage"] = pick(out["usage"], USAGE_KEEP)
        out = _relabel(out, ids)
        return json.dumps(scrub_value(out, workspace), indent=2, sort_keys=False) + "\n"
    scrubber = SCRUBBERS[kind]
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        record = json.loads(stripped)
        if not isinstance(record, dict):
            continue
        lines.append(json.dumps(scrubber(record, workspace, ids), ensure_ascii=False))
    return "\n".join(lines) + "\n"


def audit(text: str, workspace: str) -> list[str]:
    """Last line of defence: refuse to write a file that still names somebody's home."""
    offenders = []
    home = re.compile(r"/(?:Users|home)/([A-Za-z0-9._-]+)/")
    for number, line in enumerate(text.splitlines(), start=1):
        match = home.search(line)
        if match:
            offenders.append(f"line {number}: {match.group(0)}")
        if workspace and workspace in line:
            offenders.append(f"line {number}: unscrubbed workspace path")
        if EMAIL.search(line) and "example.invalid" not in line:
            offenders.append(f"line {number}: email address")
    return offenders


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--kind", required=True, choices=sorted({*SCRUBBERS, "result-json"}))
    parser.add_argument("--workspace", required=True,
                        help="absolute path of the directory the run happened in")
    parser.add_argument("--in", dest="source", required=True, type=Path)
    parser.add_argument("--out", dest="target", required=True, type=Path)
    args = parser.parse_args(argv)

    workspace = str(Path(args.workspace)).rstrip("/")
    text = args.source.read_text(encoding="utf-8")
    scrubbed = sanitize(args.kind, text, workspace)
    offenders = audit(scrubbed, workspace)
    if offenders:
        print("refusing to write: private detail survived scrubbing", file=sys.stderr)
        for offender in offenders:
            print(f"  {offender}", file=sys.stderr)
        return 1
    args.target.parent.mkdir(parents=True, exist_ok=True)
    args.target.write_text(scrubbed, encoding="utf-8")
    print(f"wrote {args.target} ({len(scrubbed.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
