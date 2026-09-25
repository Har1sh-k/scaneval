"""Import Claude Code's native records: session transcripts and ``-p`` stream JSON.

Three shapes, one vocabulary. A session transcript
(``~/.claude/projects/<slug>/<session-id>.jsonl``) is what the CLI writes for itself as it
runs, including the subagent files beside it. ``claude -p --output-format stream-json`` is
the same conversation streamed to stdout by a non-interactive run, in a near but not
identical record shape. ``claude -p --output-format json`` emits a single result object.
All three land as the Contract 3 event vocabulary, so a harness that shells out to any of
them becomes observable without being edited.

Two structural facts about the real files drive most of the code here, and neither is
obvious from the shape of one record.

The first is that an assistant *record* is not an assistant *turn*. One API response is
written as several records, one per content block, each repeating the same ``message.id``,
``message.usage`` and ``requestId`` and distinguished only by ``apiBlockIndex``. A reader
that emitted a ``model.response`` per record would report a two-block turn as two turns and
count its token usage twice, which is the one thing a usage number must never do. So blocks
are accumulated per ``message.id`` and flushed as one turn when the next record shows the
message has ended.

The second is that a transcript is the operator's file, not the run's. Its ``cwd`` and every
``filePath`` in it are absolute paths on the machine that ran it, and its ``attachment``
records carry the session's system prompt and environment. Nothing here passes a native path
through: every path goes through the workspace-relative rendering, and no record type
outside the message stream is read for anything but its name.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
import json
import os
from pathlib import Path
import stat
from typing import Any

from . import (
    ImportSummary,
    _Import,
    block_text,
    clip,
    parse_lines,
    sha256_text,
    workspace_roots,
)


SOURCE_TRANSCRIPT = "claude_code_transcript"
SOURCE_STREAM = "claude_code_stream_json"
ROUTE = "claude"

# Where the CLI keeps session transcripts. Read at call time rather than at import, so a
# test can point at its own directory and importing this module touches no home directory.
PROJECTS_DIR = (".claude", "projects")

# Tool inputs whose interesting field is a path, and the field it is called by. Used only
# to build ``input_summary``; a tool absent from here still gets a summary, from its input.
PATH_INPUT_KEYS = ("file_path", "path", "notebook_path")

# The most a single transcript may contribute to memory. A transcript is written by another
# process after the scan began, so its size is not a number this collector gets to assume:
# past this bound the read stops and the import says it was truncated. 64 MiB is far above
# any real session (the largest observed was under 200 KiB) and far below a figure that
# could exhaust a scanning host.
MAX_TRANSCRIPT_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 1 << 20

# The usage keys Contract 3 fixes for ``metadata.usage``, mapped from the names the
# Anthropic message usage object uses. The mapping is the identity for Claude and is spelled
# out anyway, because :mod:`scaneval.collectors.codex` maps a different vocabulary onto the
# same four keys and a reader should be able to see both mappings side by side.
USAGE_KEYS = {
    "input_tokens": "input_tokens",
    "output_tokens": "output_tokens",
    "cache_read_input_tokens": "cache_read_input_tokens",
    "cache_creation_input_tokens": "cache_creation_input_tokens",
}


def _inside(candidate: Path, boundary: Path) -> bool:
    """True when ``candidate`` is a regular file whose directory really is under ``boundary``.

    Two checks, because one is not enough. ``lstat`` refuses a symlink, a FIFO, a socket and
    a device *at the name itself*, without following it. Resolving the parent then refuses a
    symlinked directory somewhere above the name, which is the redirection ``lstat`` on the
    leaf cannot see: swapping ``<projects>/<slug>`` for a link to ``/etc`` would otherwise
    make every ``*.jsonl`` under it look like a transcript.

    This function resolves symlinks, which the rest of the package never does. The two rules
    are about different things and do not conflict: workspace paths are *rendered* for a
    trace that may be read on another machine, so resolving them would answer a question
    about the reader's filesystem, while this is a security check on the very filesystem the
    read is about to happen on, where the resolved answer is the only true one.
    """
    try:
        if not stat.S_ISREG(os.lstat(candidate).st_mode):
            return False
        parent = candidate.parent.resolve(strict=True)
    except OSError:
        return False
    return parent == boundary or boundary in parent.parents


def _read_transcript(path: Path) -> tuple[list[str], str | None]:
    """Read a transcript safely. Returns ``(lines, loss)``; ``loss`` is the capture loss.

    ``loss`` is ``None``, ``"refused"`` or ``"truncated"``, and it is a return value rather
    than an exception because a harness calling this has already finished its scan: a log
    that turned out to be a device node must cost the trace, never the run.

    Three guards, and each one closes a hole the others leave open.

    ``O_NOFOLLOW`` refuses a symlink at the moment of opening rather than at the moment of
    listing, which is the only moment that counts: the file is written by another process
    after the scan began, so a name that was a regular file when :func:`find_transcripts`
    checked it can be a link to ``/etc/shadow`` by the time it is opened.

    ``O_NONBLOCK`` is why a FIFO cannot hang the import. Opening a FIFO for reading blocks
    until somebody opens the write end, so without this flag swapping a transcript for a
    named pipe stops the importing process forever, with no error and nothing to time out.
    With it the open returns at once and ``fstat`` on the descriptor then refuses the pipe
    for what it is. The flag is cleared afterwards, because on a regular file it would turn
    a slow read into a spurious ``EAGAIN``.

    ``fstat`` on the *descriptor* is what makes the check race-free. Stat-then-open asks
    about a name twice and can get two different files; this asks about the one object that
    is actually open.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return [], "refused"
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            return [], "refused"
        os.set_blocking(descriptor, True)
        stream = os.fdopen(descriptor, "rb", closefd=True)
    except OSError:
        os.close(descriptor)
        return [], "refused"

    lines: list[str] = []
    pending = b""
    used = 0
    truncated = False
    try:
        with stream:
            while True:
                room = MAX_TRANSCRIPT_BYTES - used
                if room <= 0:
                    # One byte past the bound decides whether anything was actually left.
                    truncated = bool(stream.read(1))
                    break
                chunk = stream.read(min(_READ_CHUNK, room))
                if not chunk:
                    break
                used += len(chunk)
                parts = (pending + chunk).split(b"\n")
                pending = parts.pop()
                lines.extend(part.decode("utf-8", "replace") for part in parts)
            if pending and not truncated:
                lines.append(pending.decode("utf-8", "replace"))
            # A trailing partial line is dropped when the read was cut short: it is not a
            # damaged record, it is half of one this reader chose not to finish, and
            # counting it as malformed would blame the file for the bound.
    except OSError:
        return lines, "refused"
    return lines, ("truncated" if truncated else None)


def find_transcripts(session_id: str, *, projects_dir: Path | None = None) -> list[Path]:
    """Locate the transcript files one session wrote, main file first, then subagents.

    The project directory a session lands in is derived from the working directory it ran
    in, so the caller who knows the session ID usually does not know the directory: the
    search is a glob across all of them. Subagent transcripts live in a directory named for
    the session, which the CLI creates only when a subagent actually ran. Their absence is
    therefore not evidence that no subagent ran, only that none wrote a file here, which is
    why this returns what exists rather than asserting a count.

    The boundary is captured once, before anything is listed, and every candidate must be a
    regular file that really lives under it. These files are written by a CLI *after* the
    scan this collector is describing began, by a process the collector does not control, so
    between the run and the import a name here can become a link to a host file, a FIFO, or
    something that is not a transcript at all. Discovery refuses those by name; the read in
    :func:`import_transcript` refuses them again on the descriptor, because a name that was
    safe when it was listed can be something else by the time it is opened.

    Returns an empty list when nothing matches. A missing transcript is an ordinary outcome
    for a harness that ran a CLI which was configured not to keep one, and a collector that
    raised on it would turn a capture gap into a scan failure.
    """
    if not session_id or "/" in session_id or "\\" in session_id or session_id in (".", ".."):
        return []
    root = projects_dir if projects_dir is not None else Path.home().joinpath(*PROJECTS_DIR)
    try:
        boundary = root.resolve(strict=True)
    except OSError:
        return []
    if not boundary.is_dir():
        return []
    found: list[Path] = []
    for main in sorted(root.glob(f"*/{session_id}.jsonl")):
        if _inside(main, boundary):
            found.append(main)
    for sub in sorted(root.glob(f"*/{session_id}/subagents/*.jsonl")):
        if _inside(sub, boundary):
            found.append(sub)
    return found


def parse_result_object(text: str) -> dict | None:
    """Parse ``claude -p --output-format json`` stdout. None when it is not a result object.

    None rather than an exception, and None rather than an empty dict: a harness asks this
    about stdout it did not choose the shape of, and an error message printed where a result
    was expected must not become a result that claims success with no fields in it.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict) or parsed.get("type") != "result":
        return None
    return parsed


def import_transcript(
    observer: Any,
    path: Path,
    *,
    workspace_root: Path | str | Sequence[Path | str],
    call_id: str,
    sidechain: bool = False,
    agent_id: str | None = None,
) -> ImportSummary:
    """Read one transcript file and emit its turns, tool calls, and file reads.

    ``workspace_root`` is one root or a sequence of spellings of the same root, tried in
    order; pass every spelling the run could have used. On macOS that means passing both the
    path a harness handed the CLI and its realpath, because a run under ``/var/folders/...``
    records ``/private/var/folders/...`` in every ``filePath`` and a single-root import would
    file every file the agent read as external. See :func:`~scaneval.collectors.workspace_roots`.

    ``sidechain`` and ``agent_id`` are what the caller knows about the file: a subagent
    transcript found by :func:`find_transcripts` is a sidechain and its agent ID is in its
    filename. Both are overridden per record when the record says otherwise, because the
    records carry ``isSidechain`` and ``agentId`` themselves and the file's own claim is the
    more reliable one.

    A file that cannot be read at all is reported as a capture gap rather than raised: a
    harness calling this has already finished its scan, and a permission error on a log must
    not retroactively fail it. The same is true of a file that is refused for what it is (a
    symlink, a FIFO, a device) or that ran past :data:`MAX_TRANSCRIPT_BYTES`: both come back
    as a note, an ``observer.error``, and a downgraded ``capture``, so a caller learns the
    trace is thin from the summary it already reads rather than from an exception it has to
    know to catch. An unusable ``workspace_root`` does raise, before the file is opened,
    because that is wiring rather than a record.
    """
    workspace_root = workspace_roots(workspace_root)
    lines, loss = _read_transcript(path)
    if loss == "refused":
        tracker = _Import(
            observer,
            source=SOURCE_TRANSCRIPT,
            route=ROUTE,
            workspace_root=workspace_root,
            call_id=call_id,
        )
        tracker.emit(
            type="observer.error",
            capture_status="unavailable",
            call_id=call_id,
            metadata={
                "source": SOURCE_TRANSCRIPT,
                "error": "transcript could not be read, or was not a regular file",
            },
        )
        tracker.notes.append("refused: transcript could not be read, or was not a regular file")
        return tracker.summary(_unavailable())
    return _import_records(
        observer,
        lines,
        source=SOURCE_TRANSCRIPT,
        workspace_root=workspace_root,
        call_id=call_id,
        sidechain=sidechain,
        agent_id=agent_id,
        loss=loss,
        output_format=None,
    )


def import_stream_json(
    observer: Any,
    lines: Iterable[str],
    *,
    workspace_root: Path | str | Sequence[Path | str],
    call_id: str,
) -> ImportSummary:
    """Read ``claude -p --output-format stream-json --verbose`` output.

    The record shape is the transcript's with different spellings: ``tool_use_result`` where
    a transcript writes ``toolUseResult``, ``request_id`` where it writes ``requestId``. Both
    spellings are accepted everywhere here, so the same reader serves both files.

    The stream carries what a transcript does not: a ``system``/``init`` record naming the
    model and the tools the session was given, and a final ``result`` record with the CLI's
    own accounting of the whole invocation. Those result fields are attached to the last
    ``model.response`` rather than to an event of their own, because they describe that
    invocation's outcome and a reader joining cost to a turn should not have to join two
    events to do it. They are repeated in ``ImportSummary.notes`` for a caller that wants
    them without reading the trace back.

    What the stream does *not* carry is the tool calls a subagent made: a ``Task`` tool use
    appears, its result appears, and the subagent's own turns are absent. That is a capture
    gap of the format, not of this reader, and it is why ``tool_calls`` is never ``complete``.
    """
    return _import_records(
        observer,
        lines,
        source=SOURCE_STREAM,
        workspace_root=workspace_root,
        call_id=call_id,
        sidechain=False,
        agent_id=None,
        output_format="stream-json",
    )


def _unavailable() -> dict[str, str]:
    """Capture for an import that read nothing at all. Every observable key is unavailable.

    Not ``partial``: partial says some of a category was captured, and a refused read
    captured none of it. The difference is the whole question a consumer asks of this dict,
    and an adapter that saw ``partial`` here would report a thin trace as a working one.
    """
    return {
        "model_requests": "unavailable",
        "model_responses": "unavailable",
        "tool_calls": "unavailable",
        "context_selection": "unavailable",
        "finding_submitted": "not_applicable",
        "finding_candidate": "not_applicable",
        "finding_validation": "not_applicable",
        "finding_filtered": "not_applicable",
    }


def _capture(tracker: _Import, *, context: str = "partial",
             truncated: bool = False) -> dict[str, str]:
    """What this import can claim, per Contract 3 key.

    Nothing is ever ``complete``. A transcript records the turns that happened and not the
    attempts behind them, so a retry the CLI made internally is invisible here and the
    request record is a reconstruction; a tool call a subagent made is in another file or in
    no file; and a span is derived from a tool result rather than observed being placed in a
    prompt. Findings are ``not_applicable`` because a CLI transcript has no finding
    lifecycle in it at all: the harness that reads the model's answer is where a finding
    becomes a finding, and that boundary is the harness's to emit at.
    """
    return {
        "model_requests": "partial",
        "model_responses": "partial",
        "tool_calls": "partial",
        "context_selection": context if tracker.selections else "unavailable",
        "finding_submitted": "not_applicable",
        "finding_candidate": "not_applicable",
        "finding_validation": "not_applicable",
        "finding_filtered": "not_applicable",
    }


def _tool_result_blocks(record: dict[str, Any]) -> list[dict[str, Any]]:
    message = record.get("message")
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]


def _user_prompt(record: dict[str, Any]) -> str | None:
    """The text of a user turn, when this record is one rather than a tool result."""
    message = record.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list) and content and not _tool_result_blocks(record):
        text = block_text(content)
        return text or None
    return None


def _native_result(record: dict[str, Any]) -> Any:
    """The tool's structured result, under either spelling the two formats use."""
    for key in ("toolUseResult", "tool_use_result"):
        if key in record:
            return record[key]
    return None


def _input_summary(tool_name: Any, tool_input: Any, tracker: _Import) -> str | None:
    """One short, path-safe line identifying a tool call.

    Paths are relativized here as they are everywhere else: an ``input_summary`` is metadata
    and a native path in it would be an operator's home directory in a trace, arriving by a
    field nobody thinks of as a path field.
    """
    if not isinstance(tool_input, dict):
        return tracker.summarize(tool_input)
    for key in PATH_INPUT_KEYS:
        if isinstance(tool_input.get(key), str):
            return clip(tracker.path(tool_input[key]))
    if isinstance(tool_input.get("command"), str):
        return tracker.summarize(tool_input["command"])
    if isinstance(tool_input.get("pattern"), str):
        where = tool_input.get("path")
        located = tracker.path(where) if isinstance(where, str) else None
        pattern = tool_input["pattern"]
        return tracker.summarize(f"{pattern} in {located}" if located else pattern)
    for key in ("description", "prompt", "url", "query"):
        if isinstance(tool_input.get(key), str):
            return tracker.summarize(tool_input[key])
    return tracker.summarize(tool_input)


def _usage(message: dict[str, Any]) -> tuple[dict[str, Any] | None, bool]:
    """The four Contract 3 usage counters, or None when the record reported none."""
    raw = message.get("usage")
    if not isinstance(raw, dict):
        return None, False
    mapped = {}
    for target, native in USAGE_KEYS.items():
        value = raw.get(native)
        mapped[target] = value if isinstance(value, int) and not isinstance(value, bool) else None
    if all(value is None for value in mapped.values()):
        return None, False
    return mapped, True


def _span_from_result(native: Any, tracker: _Import) -> tuple[dict[str, Any] | None, str | None]:
    """Build a span from a ``Read`` result. Returns ``(span, delivered_text)``.

    Only a result that says which file it read and hands back the text it delivered can
    become a span, because a span claims a hash of exactly the delivered text. A ``Bash``
    result that happens to contain a file's contents is deliberately not a span: the
    collector did not observe which file that was, and guessing would put a path into a
    coverage claim that nothing in the record supports.

    ``truncated`` is left null when the record did not say how long the file was. A span that
    claimed ``false`` there would be asserting the read was complete on evidence that is
    simply absent.
    """
    if not isinstance(native, dict):
        return None, None
    file_record = native.get("file")
    if not isinstance(file_record, dict):
        return None, None
    path = tracker.path(file_record.get("filePath"))
    if not path:
        return None, None
    delivered = file_record.get("content")
    if not isinstance(delivered, str):
        return None, None
    start_raw = file_record.get("startLine")
    start_line = start_raw if isinstance(start_raw, int) and start_raw > 0 else 1
    num_lines = file_record.get("numLines")
    total_lines = file_record.get("totalLines")
    end_line = (
        start_line + num_lines - 1
        if isinstance(num_lines, int) and num_lines > 0
        else start_line
    )
    truncated: bool | None = None
    if isinstance(num_lines, int) and isinstance(total_lines, int):
        truncated = num_lines < total_lines
    span = {
        "path": path,
        "start_line": start_line,
        "end_line": end_line,
        "chars": len(delivered),
        "sha256": sha256_text(delivered),
        "truncated": truncated,
        "original_chars": None,
        # Not "primary": a role says why a harness supplied a span, and this span was read
        # out of a tool result that says only that the model asked for it.
        "role": "other",
    }
    return span, delivered


class _Turn:
    """One assistant message, accumulated across the per-block records that spell it."""

    __slots__ = ("message_id", "model", "usage", "usage_available", "text", "tool_uses",
                 "sidechain", "agent_id", "session_id")

    def __init__(self, message_id: str) -> None:
        self.message_id = message_id
        self.model: str | None = None
        self.usage: dict[str, Any] | None = None
        self.usage_available = False
        self.text: list[str] = []
        self.tool_uses: list[dict[str, Any]] = []
        self.sidechain = False
        self.agent_id: str | None = None
        self.session_id: str | None = None


def _import_records(
    observer: Any,
    lines: Iterable[str],
    *,
    source: str,
    workspace_root: Path | str | Sequence[Path | str],
    call_id: str,
    sidechain: bool,
    agent_id: str | None,
    output_format: str | None,
    loss: str | None = None,
) -> ImportSummary:
    """The one reader both Claude formats go through."""
    tracker = _Import(
        observer,
        source=source,
        route=ROUTE,
        workspace_root=workspace_root,
        call_id=call_id,
    )
    records = parse_lines(lines, tracker)

    # First pass: the invocation-level facts that arrive after the turns they describe.
    result_record = None
    init_record = None
    message_order: list[str] = []
    for record in records:
        kind = record.get("type")
        if kind == "result":
            result_record = record
        elif kind == "system" and record.get("subtype") == "init":
            init_record = record
        elif kind == "assistant":
            key = _message_key(record)
            if key and key not in message_order:
                message_order.append(key)
    last_message = message_order[-1] if message_order else None

    session_hint = None
    if isinstance(init_record, dict):
        session_hint = init_record.get("session_id")
        model = init_record.get("model")
        if isinstance(model, str) and model:
            tracker.notes.append(f"session model: {model}")
        tools = init_record.get("tools")
        if isinstance(tools, list):
            tracker.notes.append(f"session tools: {len(tools)}")

    state = _State(
        tracker=tracker,
        call_id=call_id,
        source=source,
        output_format=output_format,
        default_sidechain=sidechain,
        default_agent_id=agent_id,
        result_record=result_record if isinstance(result_record, dict) else None,
        last_message=last_message,
        session_hint=session_hint if isinstance(session_hint, str) else None,
    )

    for record in records:
        kind = record.get("type")
        if kind == "assistant":
            state.assistant(record)
            continue
        state.flush()
        if kind == "user":
            state.user(record)
        elif kind == "result" or (kind == "system" and record.get("subtype") == "init"):
            # Consumed in the first pass; counting them as untranslated would misreport a
            # record this importer does read.
            continue
        else:
            tracker.unknown(kind)
    state.flush()

    # Whatever is still held never reached a model turn: the file ends here. The tool.end
    # events and their spans stay exactly as they were emitted, because the tool really did
    # return that text; what is withdrawn is only the claim that a model was given it.
    tracker.undelivered_tool_results += state.drop_selections()

    if state.result_note:
        tracker.notes.append(state.result_note)
    tracker.report_malformed()
    if loss == "truncated":
        # The events already emitted are real and are kept. What is unknown is what came
        # after the bound, so the loss is reported and every count stays as measured.
        tracker.emit(
            type="observer.error",
            capture_status="unavailable",
            call_id=call_id,
            metadata={
                "source": source,
                "error": "transcript exceeded the read bound and was truncated",
                "max_bytes": MAX_TRANSCRIPT_BYTES,
            },
        )
        tracker.notes.append(
            f"truncated: transcript exceeded {MAX_TRANSCRIPT_BYTES} bytes and was read only "
            "up to that bound"
        )
    return tracker.summary(_capture(tracker, truncated=loss == "truncated"))


def _message_key(record: dict[str, Any]) -> str | None:
    """What identifies the API response a record is one block of.

    ``message.id`` first, because it is the response's own identity and is repeated on every
    block of it. ``requestId`` is the fallback for a record whose message carries no ID, and
    the record's ``uuid`` is the last resort, which groups nothing but at least never merges
    two different responses into one turn.
    """
    message = record.get("message")
    if isinstance(message, dict):
        identity = message.get("id")
        if isinstance(identity, str) and identity:
            return identity
    for key in ("requestId", "request_id", "uuid"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    return None


class _State:
    """The walk's mutable state. Separate from :class:`_Import` because it is format-specific."""

    def __init__(
        self,
        *,
        tracker: _Import,
        call_id: str,
        source: str,
        output_format: str | None,
        default_sidechain: bool,
        default_agent_id: str | None,
        result_record: dict[str, Any] | None,
        last_message: str | None,
        session_hint: str | None,
    ) -> None:
        self.tracker = tracker
        self.call_id = call_id
        self.source = source
        self.output_format = output_format
        self.default_sidechain = default_sidechain
        self.default_agent_id = default_agent_id
        self.result_record = result_record
        self.last_message = last_message
        self.session_hint = session_hint
        self.turn_index = 0
        self.pending: _Turn | None = None
        self.prompt: str | None = None
        # tool_use id -> what the start event knew, so the end event can be linked to it.
        self.open_tools: dict[str, dict[str, Any]] = {}
        # File reads whose text has not yet been shown to reach a model turn. See
        # :meth:`release_selections`.
        self.pending_selections: list[tuple[dict[str, Any], str | None, str | None]] = []
        self.result_note: str | None = None

    def release_selections(self) -> None:
        """Emit the held selections. Called when a later assistant turn proves delivery."""
        held, self.pending_selections = self.pending_selections, []
        for span, delivered, end_event_id in held:
            self._context_selection(span, delivered, end_event_id)

    def drop_selections(self) -> int:
        """Discard the selections no turn ever consumed and say how many there were."""
        held, self.pending_selections = self.pending_selections, []
        return len(held)

    def assistant(self, record: dict[str, Any]) -> None:
        key = _message_key(record)
        if key is None:
            self.tracker.unknown("assistant")
            return
        if self.pending is not None and self.pending.message_id != key:
            self.flush()
        if self.pending is None:
            self.pending = _Turn(key)
        turn = self.pending
        message = record.get("message")
        if isinstance(message, dict):
            model = message.get("model")
            if isinstance(model, str) and model:
                turn.model = model
            usage, available = _usage(message)
            if available:
                turn.usage, turn.usage_available = usage, True
            content = message.get("content")
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text" and isinstance(block.get("text"), str):
                        turn.text.append(block["text"])
                    elif block.get("type") == "tool_use":
                        turn.tool_uses.append(block)
        if record.get("isSidechain") is True:
            turn.sidechain = True
        for key_name in ("agentId", "agent_id"):
            value = record.get(key_name)
            if isinstance(value, str) and value:
                turn.agent_id = value
        for key_name in ("sessionId", "session_id"):
            value = record.get(key_name)
            if isinstance(value, str) and value:
                turn.session_id = value

    def flush(self) -> None:
        """Emit the accumulated turn: request, response, then one start per tool use.

        Any tool result waiting for proof of delivery is released first. This turn existing
        is that proof, and emitting the selections just ahead of the request reads in the
        order the conversation happened: these lines arrived, then the model was asked again.
        """
        turn = self.pending
        if turn is None:
            return
        self.release_selections()
        self.pending = None
        tracker = self.tracker
        self.turn_index += 1
        attempt_id = f"{self.call_id}/turn-{self.turn_index}"
        # Consumed, not reused. Only the turn a user prompt actually drove may report that
        # prompt's length: a later turn in the same session was driven by a tool result, and
        # repeating the prompt's character count onto it would describe a request that was
        # never made.
        prompt, self.prompt = self.prompt, None
        sidechain = turn.sidechain or self.default_sidechain
        agent_id = turn.agent_id or self.default_agent_id

        request_metadata = {
            "source": self.source,
            "route": ROUTE,
            # A transcript records what was served, never what the caller asked for: a
            # harness that requested an alias sees the resolved ID here or nothing.
            "model_requested": None,
            "thinking": None,
            "stage": None,
            "attempt": 1,
            "max_attempts": None,
            # The decisive one. A CLI that retried internally wrote one turn, so an absent
            # retry in this trace is not evidence that none happened.
            "retries_observable": False,
            "prompt_chars": len(prompt) if isinstance(prompt, str) else None,
            "timeout_ms": None,
            "output_format": self.output_format,
        }
        request_fields: dict[str, Any] = {
            "type": "model.request",
            "capture_status": "partial",
            "call_id": self.call_id,
            "attempt_id": attempt_id,
            "metadata": request_metadata,
        }
        if tracker.content_mode and isinstance(prompt, str) and prompt:
            request_fields["content"] = {"prompt": prompt}
        request_id = tracker.emit(**request_fields)

        answer = "".join(turn.text)
        response_metadata: dict[str, Any] = {
            "source": self.source,
            "exit_code": None,
            "error": None,
            "attempt": 1,
            "will_retry": False,
            "failure_kind": None,
            "usage_available": turn.usage_available,
            "usage": turn.usage,
            "cost_usd_cli_reported": None,
            "num_turns": None,
            "session_id": turn.session_id or self.session_hint,
            "result_subtype": None,
            "is_error": None,
            "duration_api_ms": None,
            "model_served": turn.model,
            # Present on every response and null on all but the last, so a consumer reads
            # one key shape rather than testing for absence. Only the response the CLI
            # printed its totals against ever fills them.
            "invocation_usage": None,
            "invocation_cost_usd_cli_reported": None,
            "invocation_num_turns": None,
            "invocation_duration_api_ms": None,
            "stdout_chars": len(answer),
            "stderr_chars": None,
        }
        raw_error: str | None = None
        if self.result_record is not None and turn.message_id == self.last_message:
            raw_error = self._apply_result(response_metadata)
        response_fields: dict[str, Any] = {
            "type": "model.response",
            "capture_status": "partial",
            "call_id": self.call_id,
            "attempt_id": attempt_id,
            "metadata": response_metadata,
        }
        if request_id:
            response_fields["parent_event_id"] = request_id
        if tracker.content_mode:
            # The only destination for the CLI's raw failure prose, and only in this mode.
            payload = {}
            if answer:
                payload["stdout"] = answer
            if raw_error:
                payload["error"] = raw_error
            if payload:
                response_fields["content"] = payload
        tracker.emit(**response_fields)
        tracker.model_turns += 1

        for block in turn.tool_uses:
            self._tool_start(block, request_id, sidechain, agent_id)

    def _apply_result(self, metadata: dict[str, Any]) -> str | None:
        """Attach the CLI's own accounting of the invocation to its last response.

        Returns the raw failure prose, for the caller to put in ``content`` under content
        mode, and never writes it into ``metadata``. On a failed invocation the ``result``
        field is not the model's answer but the CLI's error message, which is free text that
        can quote a command, a source excerpt or an absolute path; metadata gets the closed
        ``failure_kind`` and nothing else.
        """
        tracker = self.tracker
        record = self.result_record or {}
        usage = record.get("usage")
        cost = record.get("total_cost_usd")
        # Bounded even though it is an enum in every release seen so far: it is a string the
        # CLI chooses, and metadata should not depend on the CLI keeping it short.
        metadata["result_subtype"] = tracker.summarize(_as_str(record.get("subtype")), 60)
        metadata["is_error"] = record.get("is_error") if isinstance(record.get("is_error"), bool) else None
        metadata["session_id"] = _as_str(record.get("session_id")) or metadata["session_id"]
        # Invocation scope, under its own names. These describe the whole ``claude -p`` call,
        # not the turn this event is about, and the last turn is merely where the CLI happened
        # to print them. Writing them into the per-turn keys made the last response claim the
        # invocation's totals as its own, so summing ``usage`` across responses counted the
        # last turn twice: in the committed fixture, 10 + 18 tokens of per-turn input against
        # an invocation total of 18. A reader that wants the invocation total reads one
        # ``invocation_*`` key; a reader that wants per-turn cost adds up ``usage``; and
        # neither can silently get the other.
        metadata["invocation_num_turns"] = _as_int(record.get("num_turns"))
        metadata["invocation_duration_api_ms"] = _as_int(record.get("duration_api_ms"))
        metadata["invocation_cost_usd_cli_reported"] = (
            cost if isinstance(cost, (int, float)) and not isinstance(cost, bool) else None
        )
        metadata["invocation_usage"] = None
        if isinstance(usage, dict):
            mapped, available = _usage({"usage": usage})
            if available:
                metadata["invocation_usage"] = mapped
        # Untouched. ``usage`` and ``usage_available`` stay this turn's own, as read from its
        # own ``message.usage``, and the per-turn cost and duration keys stay null because a
        # transcript reports neither per turn.
        raw_error = record.get("result") if metadata["is_error"] else None
        raw_error = raw_error if isinstance(raw_error, str) and raw_error else None
        metadata["failure_kind"] = tracker.failure(
            "result_error" if metadata["is_error"] else None, raw_error
        )
        # Stays null. See :meth:`~scaneval.collectors._Import.failure`: the CLI's message is
        # prose, and a bounded prefix of prose is still prose.
        metadata["error"] = None
        note = (
            f"result: subtype={metadata['result_subtype']} is_error={metadata['is_error']} "
            f"num_turns={metadata['invocation_num_turns']} session_id={metadata['session_id']} "
            f"cost_usd_cli_reported={metadata['invocation_cost_usd_cli_reported']} "
            f"duration_api_ms={metadata['invocation_duration_api_ms']}"
        )
        self.result_note = note
        return raw_error

    def _tool_start(
        self,
        block: dict[str, Any],
        parent_event_id: str | None,
        sidechain: bool,
        agent_id: str | None,
    ) -> None:
        tracker = self.tracker
        tool_id = block.get("id")
        if not isinstance(tool_id, str) or not tool_id:
            tracker.unknown("tool_use")
            return
        tool_name = block.get("name")
        tool_input = block.get("input")
        fields: dict[str, Any] = {
            "type": "tool.start",
            "capture_status": "partial",
            "call_id": tool_id,
            "metadata": {
                "source": self.source,
                "tool_name": tool_name if isinstance(tool_name, str) else None,
                "input_summary": _input_summary(tool_name, tool_input, tracker),
                "sidechain": bool(sidechain),
                "agent_id": agent_id,
            },
        }
        if parent_event_id:
            fields["parent_event_id"] = parent_event_id
        if tracker.content_mode and tool_input is not None:
            fields["content"] = {"input": _content_payload(tool_input)}
        event_id = tracker.emit(**fields)
        tracker.tool_calls += 1
        self.open_tools[tool_id] = {
            "parent_event_id": parent_event_id,
            "start_event_id": event_id,
            "tool_name": tool_name if isinstance(tool_name, str) else None,
        }

    def user(self, record: dict[str, Any]) -> None:
        results = _tool_result_blocks(record)
        if not results:
            prompt = _user_prompt(record)
            if prompt is not None:
                self.prompt = prompt
            else:
                self.tracker.unknown("user")
            return
        native = _native_result(record)
        for block in results:
            self._tool_end(block, native, record)

    def _tool_end(
        self,
        block: dict[str, Any],
        native: Any,
        record: dict[str, Any],
    ) -> None:
        tracker = self.tracker
        tool_id = block.get("tool_use_id")
        if not isinstance(tool_id, str) or not tool_id:
            tracker.unknown("tool_result")
            return
        opened = self.open_tools.pop(tool_id, None)
        if opened is None:
            # Still emitted. A result that arrived is a fact; only the link to its request
            # is missing, and the counter says so.
            tracker.unmatched_tool_results += 1
        delivered = block_text(block.get("content"))
        span, span_text = _span_from_result(native, tracker)
        metadata: dict[str, Any] = {
            "source": self.source,
            "is_error": bool(block.get("is_error")),
            "result_chars": len(delivered),
            "spans": [span] if span else None,
            "duration_ms": None,
        }
        fields: dict[str, Any] = {
            "type": "tool.end",
            "capture_status": "partial",
            "call_id": tool_id,
            "metadata": metadata,
        }
        parent = (opened or {}).get("parent_event_id")
        if parent:
            fields["parent_event_id"] = parent
        if tracker.content_mode and delivered:
            fields["content"] = {"result": delivered}
        end_event_id = tracker.emit(**fields)
        tracker.tool_results += 1

        if span:
            tracker.spans += 1
            # Held, not emitted. A tool result proves the tool returned the text, which is a
            # different fact from the model having received it: a transcript that stops right
            # here recorded a read whose output no turn ever consumed. The selection is
            # released by :meth:`flush` once a later assistant turn proves delivery.
            self.pending_selections.append((span, span_text, end_event_id))

    def _context_selection(
        self,
        span: dict[str, Any],
        delivered: str | None,
        parent_event_id: str | None,
    ) -> None:
        """One selection event per tool result that actually delivered file text.

        ``partial`` always: this says a file's lines reached the conversation, not that a
        harness chose to supply them, and not that the model attended to them.
        """
        tracker = self.tracker
        fields: dict[str, Any] = {
            "type": "context.selection",
            "capture_status": "partial",
            "call_id": self.call_id,
            "metadata": {
                "source": self.source,
                "stage": "tool_result",
                "prompt_chars": None,
                "spans": [span],
                "truncated_spans": 1 if span.get("truncated") else 0,
                "omitted_paths": None,
                "span_count": 1,
            },
        }
        if parent_event_id:
            fields["parent_event_id"] = parent_event_id
        if tracker.content_mode and delivered:
            fields["content"] = {"text": delivered}
        tracker.emit(**fields)
        tracker.selections += 1


def _content_payload(value: Any) -> Any:
    """Content-mode payloads stay JSON-shaped; anything else is rendered as text."""
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        return value if isinstance(value, dict) else {"value": block_text(value)}
    return {"value": str(value)}


def _as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


__all__ = [
    "ROUTE",
    "SOURCE_STREAM",
    "SOURCE_TRANSCRIPT",
    "find_transcripts",
    "import_stream_json",
    "import_transcript",
    "parse_result_object",
]
