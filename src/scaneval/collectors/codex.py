"""Import ``codex exec --json`` output: thread events, item lifecycles, and turn usage.

Codex streams a flat JSONL event log rather than a conversation: a ``thread.started`` naming
the thread, ``turn.started`` and ``turn.completed`` bracketing each model turn, and
``item.started`` / ``item.updated`` / ``item.completed`` for everything the turn did. An item
carries its own ``id`` and ``type``, and the type decides whether it is a tool call
(``command_execution``, ``file_change``, ``mcp_tool_call``, ``web_search``), the model's
answer (``agent_message``), or neither (``reasoning``, ``todo_list``, ``error``).

Two things the format does not give, and neither is a gap this reader can close.

It reports no model identity anywhere, so ``model_served`` is null on every response and a
harness that needs to know which model answered has to record that itself when it chooses
the route. And it attributes no file reads: Codex reads a file by running ``cat``, ``nl`` or
``rg`` in a shell, which arrives as a ``command_execution`` whose output happens to contain
source. The lines a shell command printed are not a span, because nothing in the record says
which file they came from or which lines of it they are, so ``context_selection`` is
``unavailable`` for every Codex import rather than guessed at from command text.

Its usage counters are spelled in Codex's own vocabulary and are mapped onto the four
Contract 3 keys here: ``cached_input_tokens`` is a cache read and ``cache_write_input_tokens``
is a cache creation. ``reasoning_output_tokens`` has no Contract 3 key and is deliberately
not folded into ``output_tokens``, which would inflate a counter a reader compares across
routes.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from . import ImportSummary, _Import, clip, parse_lines


SOURCE = "codex_exec_json"
ROUTE = "codex"

# Item types that are a tool call and become a ``tool.start`` / ``tool.end`` pair.
TOOL_ITEM_TYPES = ("command_execution", "file_change", "mcp_tool_call", "web_search")

# Item types this reader knows and deliberately does not turn into an event. Listed rather
# than ignored silently, so an item type Codex adds later lands in ``unknown_records``
# instead of being quietly dropped by a catch-all.
NON_TOOL_ITEM_TYPES = ("agent_message", "reasoning", "todo_list", "error")

# Codex's usage vocabulary mapped onto the four Contract 3 counters, in the same shape
# :mod:`scaneval.collectors.claude_code` spells its identity mapping, so the two are
# comparable by eye.
USAGE_KEYS = {
    "input_tokens": "input_tokens",
    "output_tokens": "output_tokens",
    "cache_read_input_tokens": "cached_input_tokens",
    "cache_creation_input_tokens": "cache_write_input_tokens",
}


def import_exec_jsonl(
    observer: Any,
    lines: Iterable[str],
    *,
    workspace_root: Path | str | Sequence[Path | str],
    call_id: str,
) -> ImportSummary:
    """Read ``codex exec --json`` stdout and emit its turns and tool calls.

    A turn that never completed still emits a response: ``turn.failed`` becomes a response
    with the error on it, and a stream that simply stops mid-turn is closed at end of input
    with ``is_error`` null and a note, because a turn whose end was never written is not a
    turn that succeeded.
    """
    tracker = _Import(
        observer,
        source=SOURCE,
        route=ROUTE,
        workspace_root=workspace_root,
        call_id=call_id,
    )
    records = parse_lines(lines, tracker)

    thread_id: str | None = None
    turn_index = 0
    request_event_id: str | None = None
    open_turn = False
    answer: list[str] = []
    # Raw failure prose from ``error`` items in the turn now open. Held here rather than
    # emitted on sight because an error item is something that happened *inside* a turn, and
    # the turn's own response is where a reader looks for how the turn went.
    item_errors: list[str] = []
    open_items: dict[str, dict[str, Any]] = {}
    items: dict[str, dict[str, Any]] = {}
    incomplete_turns = 0

    def start_turn() -> None:
        nonlocal turn_index, request_event_id, open_turn, answer
        turn_index += 1
        open_turn = True
        answer = []
        attempt_id = f"{call_id}/turn-{turn_index}"
        request_event_id = tracker.emit(
            type="model.request",
            capture_status="partial",
            call_id=call_id,
            attempt_id=attempt_id,
            metadata={
                "source": SOURCE,
                "route": ROUTE,
                # Codex names no model in its exec output, so neither does this trace.
                "model_requested": None,
                "thinking": None,
                "stage": None,
                "attempt": 1,
                "max_attempts": None,
                "retries_observable": False,
                "prompt_chars": None,
                "timeout_ms": None,
                "output_format": "json",
            },
        )

    def end_turn(record: dict[str, Any] | None, *, failed: bool, complete: bool) -> None:
        nonlocal open_turn, request_event_id
        if not open_turn:
            # A completion with no start: emit the request that must have happened, so the
            # response is not an orphan and the attempt IDs stay paired.
            start_turn()
        attempt_id = f"{call_id}/turn-{turn_index}"
        usage, available = _usage((record or {}).get("usage"))
        # The raw message stays local to this function and reaches only ``content``. A turn
        # that failed outranks an error item inside it: both are real, and the one that ended
        # the turn is the one a reader is looking for.
        if failed:
            raw_error, kind = _error_text(record), "turn_failed"
        elif item_errors:
            raw_error, kind = item_errors[0], "item_error"
        else:
            raw_error, kind = None, None
        failure_kind, error = tracker.failure(kind, raw_error)
        text = "".join(answer)
        metadata: dict[str, Any] = {
            "source": SOURCE,
            "exit_code": None,
            "error": error,
            "attempt": 1,
            "will_retry": False,
            "failure_kind": failure_kind,
            "usage_available": available,
            "usage": usage,
            "cost_usd_cli_reported": None,
            "num_turns": None,
            "session_id": thread_id,
            "result_subtype": "failed" if failed else ("completed" if complete else None),
            "is_error": True if failed else (False if complete else None),
            "duration_api_ms": None,
            "model_served": None,
            "stdout_chars": len(text),
            "stderr_chars": None,
        }
        fields: dict[str, Any] = {
            "type": "model.response",
            "capture_status": "partial",
            "call_id": call_id,
            "attempt_id": attempt_id,
            "metadata": metadata,
        }
        if request_event_id:
            fields["parent_event_id"] = request_event_id
        if tracker.content_mode:
            # The one place the CLI's own failure prose is stored, and only here. In any
            # other mode it is read, bounded into the summary above, and dropped.
            payload = {}
            if text:
                payload["stdout"] = text
            if raw_error:
                payload["error"] = raw_error
            if payload:
                fields["content"] = payload
        tracker.emit(**fields)
        tracker.model_turns += 1
        open_turn = False
        request_event_id = None
        item_errors.clear()

    for record in records:
        kind = record.get("type")
        if kind == "thread.started":
            value = record.get("thread_id")
            thread_id = value if isinstance(value, str) and value else None
            continue
        if kind == "turn.started":
            if open_turn:
                # Two starts with no end between them: close the first honestly.
                incomplete_turns += 1
                end_turn(None, failed=False, complete=False)
            start_turn()
            continue
        if kind == "turn.completed":
            end_turn(record, failed=False, complete=True)
            continue
        if kind == "turn.failed":
            end_turn(record, failed=True, complete=False)
            continue
        if kind in ("item.started", "item.updated", "item.completed"):
            item = record.get("item")
            if not isinstance(item, dict):
                tracker.unknown(kind)
                continue
            item_type = item.get("type")
            item_id = item.get("id")
            if item_type in TOOL_ITEM_TYPES:
                if isinstance(item_id, str) and item_id:
                    items[item_id] = item
                if kind == "item.started":
                    _tool_start(tracker, item, request_event_id, open_items, call_id)
                elif kind == "item.completed":
                    _tool_end(tracker, item, open_items, request_event_id)
                # item.updated refreshes the stored item and emits nothing: the pair a
                # reader joins on is start and end, and an update between them would be a
                # third event describing the same call.
                continue
            if item_type == "agent_message":
                text = item.get("text")
                if kind == "item.completed" and isinstance(text, str) and text:
                    answer.append(text)
                continue
            if item_type == "error":
                # Recorded, not dropped: Codex reporting an error item is the only trace of
                # a failure that a later ``turn.completed`` would otherwise paper over.
                message = _error_text(item)
                if kind == "item.completed" and message and message not in item_errors:
                    item_errors.append(message)
                continue
            if item_type in NON_TOOL_ITEM_TYPES:
                continue
            tracker.unknown(f"item:{item_type}" if isinstance(item_type, str) else kind)
            continue
        tracker.unknown(kind)

    if open_turn:
        incomplete_turns += 1
        end_turn(None, failed=False, complete=False)
    for item_id, opened in sorted(open_items.items()):
        # A tool call whose completion never arrived. Emitting nothing would leave a
        # ``tool.start`` a reader could mistake for a call still running.
        tracker.notes.append(f"tool call never completed: {opened.get('tool_name') or item_id}")

    if thread_id:
        tracker.notes.append(f"thread: {thread_id}")
    if incomplete_turns:
        tracker.notes.append(f"turns with no completion record: {incomplete_turns}")
    tracker.report_malformed()
    return tracker.summary(_capture())


def _capture() -> dict[str, str]:
    """What a Codex import can claim.

    ``context_selection`` is ``unavailable`` rather than ``partial``: it is not that the
    spans are incomplete, it is that this format carries no file attribution at all, and a
    consumer deciding whether an absent span means "not supplied" needs those two answers
    kept apart. Contract 5 reads exactly this distinction.
    """
    return {
        "model_requests": "partial",
        "model_responses": "partial",
        "tool_calls": "partial",
        "context_selection": "unavailable",
        "finding_submitted": "not_applicable",
        "finding_candidate": "not_applicable",
        "finding_validation": "not_applicable",
        "finding_filtered": "not_applicable",
    }


def _tool_name(item: dict[str, Any]) -> str:
    """What to call this tool in a trace: the item type, refined by what it names."""
    item_type = item.get("type")
    if item_type == "mcp_tool_call":
        server = item.get("server")
        tool = item.get("tool")
        if isinstance(server, str) and isinstance(tool, str):
            return f"mcp:{server}/{tool}"
        if isinstance(tool, str):
            return f"mcp:{tool}"
    return item_type if isinstance(item_type, str) else "unknown"


def _input_summary(item: dict[str, Any], tracker: _Import) -> str | None:
    item_type = item.get("type")
    if item_type == "command_execution":
        # The command text is where an operator path reaches metadata: Codex reads files by
        # running a shell, so this string routinely holds absolute paths.
        return tracker.summarize(item.get("command"))
    if item_type == "file_change":
        changes = item.get("changes")
        if isinstance(changes, list) and changes:
            paths = []
            for change in changes:
                if isinstance(change, dict):
                    located = tracker.path(change.get("path"))
                    if located:
                        paths.append(located)
                elif isinstance(change, str):
                    located = tracker.path(change)
                    if located:
                        paths.append(located)
            if paths:
                return clip(", ".join(paths))
        return clip(tracker.path(item.get("path")))
    if item_type == "web_search":
        return tracker.summarize(item.get("query"))
    if item_type == "mcp_tool_call":
        arguments = item.get("arguments")
        return tracker.summarize(arguments if arguments is not None else item.get("tool"))
    return None


def _result_text(item: dict[str, Any]) -> str:
    for key in ("aggregated_output", "output", "result", "text"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    return ""


def _tool_start(
    tracker: _Import,
    item: dict[str, Any],
    parent_event_id: str | None,
    open_items: dict[str, dict[str, Any]],
    call_id: str,
) -> None:
    item_id = item.get("id")
    if not isinstance(item_id, str) or not item_id:
        tracker.unknown("item.started")
        return
    name = _tool_name(item)
    fields: dict[str, Any] = {
        "type": "tool.start",
        "capture_status": "partial",
        "call_id": item_id,
        "metadata": {
            "source": SOURCE,
            "tool_name": name,
            "input_summary": _input_summary(item, tracker),
            # Codex exec reports no subagent structure, so this is never true rather than
            # sometimes unknown: there is no sidechain in the format to miss.
            "sidechain": False,
            "agent_id": None,
        },
    }
    if parent_event_id:
        fields["parent_event_id"] = parent_event_id
    if tracker.content_mode:
        payload = _start_content(item)
        if payload:
            fields["content"] = {"input": payload}
    event_id = tracker.emit(**fields)
    tracker.tool_calls += 1
    open_items[item_id] = {
        "parent_event_id": parent_event_id,
        "start_event_id": event_id,
        "tool_name": name,
    }


def _start_content(item: dict[str, Any]) -> dict[str, Any] | None:
    payload = {
        key: value
        for key, value in item.items()
        if key in ("command", "query", "tool", "server", "arguments", "changes", "path")
    }
    return payload or None


def _tool_end(
    tracker: _Import,
    item: dict[str, Any],
    open_items: dict[str, dict[str, Any]],
    fallback_parent: str | None,
) -> None:
    item_id = item.get("id")
    if not isinstance(item_id, str) or not item_id:
        tracker.unknown("item.completed")
        return
    opened = open_items.pop(item_id, None)
    if opened is None:
        tracker.unmatched_tool_results += 1
    exit_code = item.get("exit_code")
    exit_code = exit_code if isinstance(exit_code, int) and not isinstance(exit_code, bool) else None
    status = item.get("status")
    if exit_code is not None:
        is_error = exit_code != 0
    elif isinstance(status, str):
        is_error = status in ("failed", "error")
    else:
        is_error = False
    text = _result_text(item)
    fields: dict[str, Any] = {
        "type": "tool.end",
        "capture_status": "partial",
        "call_id": item_id,
        "metadata": {
            "source": SOURCE,
            "is_error": is_error,
            "result_chars": len(text),
            # A shell command's stdout is not a file attribution, so no Codex tool end
            # carries spans. See the module docstring.
            "spans": None,
            "duration_ms": None,
            "exit_code": exit_code,
            # Bounded like every other CLI-authored string that reaches metadata. It is a
            # short enum today, and "today" is not a property metadata should rely on.
            "status": clip(status, 60) if isinstance(status, str) else None,
        },
    }
    parent = (opened or {}).get("parent_event_id") or fallback_parent
    if parent:
        fields["parent_event_id"] = parent
    if tracker.content_mode and text:
        fields["content"] = {"result": text}
    tracker.emit(**fields)
    tracker.tool_results += 1


def _usage(raw: Any) -> tuple[dict[str, Any] | None, bool]:
    if not isinstance(raw, dict):
        return None, False
    mapped = {}
    for target, native in USAGE_KEYS.items():
        value = raw.get(native)
        mapped[target] = value if isinstance(value, int) and not isinstance(value, bool) else None
    if all(value is None for value in mapped.values()):
        return None, False
    return mapped, True


def _error_text(record: dict[str, Any] | None) -> str | None:
    """The CLI's failure message, **raw**. Never put the result of this into metadata.

    It is free text written for a human terminal: it quotes the command that failed, the
    output it produced, source excerpts, and absolute paths on the operator's machine. Its
    only two destinations are ``content.error`` under content mode and
    :meth:`~scaneval.collectors._Import.failure`, which bounds and relocates it.
    """
    if not isinstance(record, dict):
        return None
    error = record.get("error")
    if isinstance(error, str) and error:
        return error
    if isinstance(error, dict):
        message = error.get("message")
        if isinstance(message, str) and message:
            return message
    message = record.get("message")
    return message if isinstance(message, str) and message else None


__all__ = [
    "NON_TOOL_ITEM_TYPES",
    "ROUTE",
    "SOURCE",
    "TOOL_ITEM_TYPES",
    "import_exec_jsonl",
]
