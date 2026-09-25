"""Importers that turn an agent CLI's own records into ScanEval trace events.

A collector is a reader, never a wrapper. It spawns no process, patches no client, and
changes nothing about the harness it observes: a harness that already shells out to Claude
Code or Codex keeps running exactly as it did, and a collector is pointed afterwards at the
records that run left behind. That is the whole reason these exist. Instrumenting a harness
means editing it; importing its CLI's transcript means editing nothing, so observability
costs the harness author no behavior change and can be added to a harness nobody owns.

What a collector may claim is bounded by that same distance. It sees what the CLI chose to
write down, which is never the whole invocation: a transcript records the turns that
happened, not the attempts that were retried behind them, and it records the text a tool
returned without saying what the harness did with it. So every event a collector emits
carries ``metadata.source`` naming the record it was read out of, a
:class:`~scaneval.observer.Observer` ``capture_status`` of ``partial`` wherever the reading
was derived rather than observed, and an :class:`ImportSummary` whose ``capture`` dict says,
per Contract 3 key, how much of that category this import can honestly claim. An event a
collector did not emit is not evidence that the thing did not happen; it is evidence that
the CLI did not write it down where the collector could read it.

The two hard rules from the trace contract are enforced here rather than left to the caller.
File content reaches an event only through ``content``, only in an observer whose mode is
``content``; ``metadata`` carries hashes, line ranges, and sizes and never a byte of source.
And a path in an event is relative to the scanned workspace root with forward slashes: a
path outside that root becomes ``external:<basename>`` and is counted, so an operator's home
directory cannot arrive in a trace by way of a transcript that was written under it.

``ImportSummary`` is the only public name here; the importers live in
:mod:`scaneval.collectors.claude_code` and :mod:`scaneval.collectors.codex`. See
``docs/COLLECTORS.md`` for what each one captures, what it cannot, and how a fixture
generated from a real CLI run is scrubbed before it is committed.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePath, PurePosixPath
import hashlib
import json
import re
from typing import Any


# An absolute POSIX path of at least two segments, as it appears embedded in free text. Used
# to find the paths inside a shell command, which is the one place an operator's home
# directory can enter metadata without anyone thinking of the field as a path field.
ABSOLUTE_PATH = re.compile(r"/(?:[A-Za-z0-9._@+-]+/)+[A-Za-z0-9._@+-]*")


# The capture-status keys Contract 3 fixes for a run, in the contract's order. A collector
# answers every one of them, including the ones it can say nothing about, because a key left
# out of the dict would read as an oversight where ``not_applicable`` reads as an answer.
CAPTURE_KEYS = (
    "model_requests",
    "model_responses",
    "tool_calls",
    "context_selection",
    "finding_submitted",
    "finding_candidate",
    "finding_validation",
    "finding_filtered",
)

# How much of a command or a tool input reaches ``metadata.input_summary``. Long enough to
# identify the call in a trace, short enough that metadata stays a description of the run
# rather than a second copy of it.
SUMMARY_CHARS = 120

# What a path outside the workspace root is recorded as. The basename survives because a
# reader needs to tell two external reads apart; the directories do not, because they are
# the operator's machine and not the run.
EXTERNAL_PREFIX = "external:"

# The closed vocabulary ``metadata.failure_kind`` carries, and the whole reason it is closed.
# A native failure message is free text a CLI wrote for a human: it routinely quotes the
# command that failed, the output it produced, a source excerpt, and an absolute path on the
# operator's machine. Copying one into metadata would walk all of that straight past the
# metadata/content separation the rest of this package keeps, through a field nobody reads as
# a content field. So metadata carries a code from this set and nothing else: not the message
# and not a bounded prefix of it either, because the first hundred characters of a traceback
# are the line of source that raised, and bounded source is still source. The message goes to
# ``content.error`` in content mode, or nowhere at all.
FAILURE_KINDS = ("turn_failed", "item_error", "result_error", "unknown")


@dataclass(frozen=True)
class ImportSummary:
    """What one import produced and what it could not read. Returned, never raised.

    The counters are the import's own account of itself. ``events`` counts events the
    observer accepted, so an observer in ``off`` mode reports zero here while the other
    counters still describe the records that were read: the summary says what the file
    contained either way. ``unknown_records`` counts records whose type this importer does
    not translate, which is not a defect but the normal state of a transcript, most of whose
    records are bookkeeping; the distinct type names are preserved in ``notes`` so a reader
    can see what went untranslated without the importer inventing an event for it.

    ``malformed_lines`` counts lines that were not JSON. They are summarized once as an
    ``observer.error`` event with ``capture_status: unavailable`` rather than one event each,
    because the interesting fact is that the file was damaged, not which byte offset proved
    it. ``unmatched_tool_results`` counts results whose ``tool_use`` was never seen, usually
    because the import began mid-file; those still emit a ``tool.end``, because a result that
    arrived is a fact even when its request is missing.

    ``capture`` carries the Contract 3 keys with values ``complete``, ``partial``,
    ``unavailable`` or ``not_applicable``. Collectors say ``complete`` for nothing: every
    reading here is derived from a record written for another purpose.
    """

    events: int
    model_turns: int
    tool_calls: int
    tool_results: int
    spans: int
    unknown_records: int
    malformed_lines: int
    unmatched_tool_results: int
    capture: dict[str, str]
    notes: tuple[str, ...]


def workspace_roots(root_or_roots: Any) -> tuple[str, ...]:
    """Normalize the ``workspace_root`` argument to an ordered, deduplicated tuple of roots.

    One workspace can have more than one true spelling, and the collector cannot discover
    that for itself. On macOS the temporary directory a harness runs in is
    ``/var/folders/...`` while its realpath is ``/private/var/folders/...``, so an adapter
    that passed ``/var/...`` as the root against an agent that recorded ``/private/var/...``
    in every ``filePath`` classified every file the agent read as external, and no span could
    be joined to a label. Nothing in the record says the two are the same directory, and this
    module will not ask the filesystem, so the caller passes both spellings.

    Order is the caller's and is kept: the first root is the spelling the caller itself used,
    and it is the one a relative path is resolved against. Duplicates are dropped, so a
    caller can pass ``(source_dir, source_dir.resolve())`` unconditionally and get one root on
    the platforms where those are the same string.

    Raises :class:`ValueError` for an empty sequence or a non-path element. This is wiring,
    not a record: a caller fixes it once, and a collector that quietly accepted "no workspace"
    would mark every path in the run external and report a clean import while doing it.
    """
    if isinstance(root_or_roots, (str, PurePath)) or hasattr(root_or_roots, "__fspath__"):
        candidates: list[Any] = [root_or_roots]
    elif isinstance(root_or_roots, Sequence):
        candidates = list(root_or_roots)
    else:
        raise ValueError(
            f"workspace_root must be a path or a sequence of paths, not {type(root_or_roots).__name__}"
        )
    normalized: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, (str, PurePath)) and not hasattr(candidate, "__fspath__"):
            raise ValueError(
                f"workspace_root entries must be paths, not {type(candidate).__name__}"
            )
        text = str(candidate).replace("\\", "/")
        if not text:
            raise ValueError("workspace_root must not contain an empty path")
        spelled = PurePosixPath(text).as_posix()
        if spelled not in normalized:
            normalized.append(spelled)
    if not normalized:
        raise ValueError("workspace_root must name at least one root")
    return tuple(normalized)


def _normalized(raw: str, base: str) -> PurePosixPath:
    """Resolve textually against ``base`` and fold away ``.`` and ``..``. Touches no disk."""
    candidate = PurePosixPath(raw.replace("\\", "/"))
    if not candidate.is_absolute():
        candidate = PurePosixPath(base) / candidate
    # PurePosixPath keeps "..", which would let a relative input escape the root while
    # still comparing as though it were inside it.
    parts: list[str] = []
    for part in candidate.parts:
        if part == "..":
            if parts[1:]:
                parts.pop()
            continue
        if part == ".":
            continue
        parts.append(part)
    return PurePosixPath(*parts)


def workspace_path(raw: Any, workspace_root: Any) -> tuple[str | None, bool]:
    """Render one native path as a workspace-relative path. Returns ``(path, external)``.

    ``workspace_root`` is one root or a sequence of them; each is tried in order and the
    first that contains the path wins. See :func:`workspace_roots` for why a caller passes
    more than one.

    A relative input is resolved against the *first* root, because that is the spelling the
    caller used and therefore what a CLI running in the workspace meant by it. Anything that
    lands outside every root becomes ``external:<basename>``, which is the whole point: a
    Claude Code transcript is written under the operator's home and quotes absolute paths
    from that machine, so an importer that passed them through would put a home directory
    into a trace.

    Comparison is textual on the normalized paths and never resolves a symlink. That rule is
    deliberate and survives the multi-root change: resolving would touch the filesystem the
    trace is being *read* on, which may not be the one the run happened on and may no longer
    have the directory at all. Supplying the second spelling is the caller's job because only
    the caller was there when the run happened.
    """
    if not isinstance(raw, str) or not raw:
        return None, False
    roots = workspace_roots(workspace_root)
    normalized = _normalized(raw, roots[0])
    for root in roots:
        try:
            relative = normalized.relative_to(PurePosixPath(root))
        except ValueError:
            continue
        text = relative.as_posix()
        return (text if text != "." else ""), False
    return EXTERNAL_PREFIX + (normalized.name or raw), True


def relocate_paths(text: Any, workspace_root: Any) -> Any:
    """Rewrite every absolute path embedded in free text to its workspace-relative form.

    A shell command is the leak nobody plans for. ``file_path`` is obviously a path and gets
    relativized; ``command`` is a string, and ``cat /outside/private/credentials`` puts a
    home directory into ``metadata.input_summary`` by a field no one audits as a path field.
    Contract 3 says a home directory never appears in an event, so the rule is applied to the
    text rather than to the fields somebody remembered to list.

    The command stays readable: a path under the workspace becomes the relative one a reader
    wants anyway, and a path outside becomes ``external:<basename>``, which says what ran
    without saying whose machine it ran on.

    ``workspace_root`` takes one root or a sequence of them, exactly as
    :func:`workspace_path` does, and for the same reason: a command that names the workspace
    by its other spelling must relativize, not be filed as external.
    """
    if not isinstance(text, str) or "/" not in text:
        return text
    # Normalized once, not once per match: a long command line can hold many paths and each
    # of them would otherwise re-validate the same roots.
    roots = workspace_roots(workspace_root)

    def replace(match: re.Match[str]) -> str:
        rendered, _ = workspace_path(match.group(0), roots)
        return rendered if rendered else match.group(0)

    return ABSOLUTE_PATH.sub(replace, text)


def sha256_text(text: str) -> str:
    """Hex digest of exactly the text that was delivered, so a span can be joined by hash."""
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def block_text(value: Any) -> str:
    """Flatten a tool result's content to the text a reader would have seen.

    The Anthropic content shape is a string sometimes and a list of blocks other times, and
    an importer that handled only one of them would report a result length of zero for half
    the tools in a real transcript.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text")
                parts.append(text if isinstance(text, str) else json.dumps(item, sort_keys=True))
        return "".join(parts)
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True)


def clip(text: Any, limit: int = SUMMARY_CHARS) -> str | None:
    """Shorten a summary string. Returns None for a value there is no summary to make of."""
    if text is None:
        return None
    rendered = text if isinstance(text, str) else json.dumps(text, sort_keys=True)
    rendered = " ".join(rendered.split())
    if not rendered:
        return None
    return rendered if len(rendered) <= limit else rendered[: limit - 1] + "…"


class _Import:
    """Shared bookkeeping for one import: counters, path handling, and event emission.

    Private because it is a factoring, not a contract. Both importers hold one of these so
    that an event's shape, a path's spelling, and a counter's meaning are decided in one
    place; if they were decided twice, a Claude span and a Codex span would drift apart and
    :mod:`scaneval.diagnostics` would be joining two different vocabularies.
    """

    def __init__(
        self,
        observer: Any,
        *,
        source: str,
        route: str,
        workspace_root: Any,
        call_id: str,
    ) -> None:
        self.observer = observer
        self.source = source
        self.route = route
        # Validated and normalized once, here, so a wiring mistake surfaces at the start of
        # an import rather than as every path in the run quietly reading as external.
        self.workspace_root = workspace_roots(workspace_root)
        self.call_id = call_id
        self.events = 0
        self.model_turns = 0
        self.tool_calls = 0
        self.tool_results = 0
        self.spans = 0
        self.unknown_records = 0
        self.malformed_lines = 0
        self.unmatched_tool_results = 0
        self.external_paths = 0
        self.unknown_types: dict[str, int] = {}
        self.notes: list[str] = []

    @property
    def content_mode(self) -> bool:
        """Whether this observer stores content at all. Read once, per Contract rule 5.

        An observer whose mode is anything but ``content`` must never be handed a payload of
        source, so the check happens before the payload is built rather than being left to
        the emitter to drop: building it would mean holding a file's text in a dict that a
        future edit could route into metadata.
        """
        return getattr(self.observer, "mode", "off") == "content"

    def path(self, raw: Any) -> str | None:
        text, external = workspace_path(raw, self.workspace_root)
        if external:
            self.external_paths += 1
        return text

    def summarize(self, value: Any, limit: int = SUMMARY_CHARS) -> str | None:
        """Render one short summary with every absolute path inside it relativized.

        Counted separately from :meth:`path`, which is to say not counted at all: a
        ``/bin/sh`` in a command line is not a file the run read, and letting it into
        ``external_paths`` would bury the count that matters under interpreter paths.
        """
        if value is None:
            return None
        rendered = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        return clip(relocate_paths(rendered, self.workspace_root), limit)

    def failure(self, kind: str | None, text: Any) -> str | None:
        """Classify a native failure. Returns the closed kind and nothing else.

        It takes the message and gives none of it back, which is the entire design. A first
        attempt returned a 120-character relocated summary beside the kind, and that summary
        was still a prefix of prose the CLI wrote: relocating it made an operator path
        impossible, but nothing made the first 120 characters stop being whatever the
        message happened to open with, which for a traceback is the line of source that
        raised. Bounded source is still source, and metadata may hold none. So the prose has
        exactly one destination, ``content`` under content mode, and a caller that wants it
        reads it from the record itself rather than receiving it from here.

        ``text`` is still a parameter because passing it is how a caller says a failure has
        a message at all: a kind with no text and no kind at all are different facts.

        An unrecognized kind becomes ``"unknown"`` rather than being passed through, because
        ``failure_kind`` is a field consumers group by: one CLI's stray string appearing
        there would turn a closed vocabulary into an open one without anyone deciding to.
        """
        if kind is None and text is None:
            return None
        return kind if kind in FAILURE_KINDS else "unknown"

    def unknown(self, native_type: Any) -> None:
        """Count a record this importer does not translate and remember what it was called."""
        self.unknown_records += 1
        name = native_type if isinstance(native_type, str) and native_type else "<untyped>"
        self.unknown_types[name] = self.unknown_types.get(name, 0) + 1

    def emit(self, **fields: Any) -> str | None:
        """Emit one event and hand back its ID so the next event can point at it."""
        event = self.observer.emit(**fields)
        if event is None:
            return None
        self.events += 1
        event_id = event.get("event_id")
        return event_id if isinstance(event_id, str) and event_id else None

    def report_malformed(self) -> None:
        """Summarize damaged lines once, as the one event that admits a reading gap.

        One event rather than one per line: a reader acts on "this file was damaged and the
        import is therefore incomplete", and a thousand identical events would bury the rest
        of the trace to say it a thousand times.
        """
        if not self.malformed_lines:
            return
        self.emit(
            type="observer.error",
            capture_status="unavailable",
            call_id=self.call_id,
            metadata={
                "source": self.source,
                "error": "native record lines were not valid JSON and could not be read",
                "malformed_lines": self.malformed_lines,
            },
        )

    def summary(self, capture: dict[str, str]) -> ImportSummary:
        notes = list(self.notes)
        if self.unknown_types:
            listed = ", ".join(
                f"{name}:{count}" for name, count in sorted(self.unknown_types.items())
            )
            notes.append(f"untranslated record types: {listed}")
        if self.external_paths:
            notes.append(f"paths outside the workspace root: {self.external_paths}")
        if self.malformed_lines:
            notes.append(f"malformed lines: {self.malformed_lines}")
        if self.unmatched_tool_results:
            notes.append(f"tool results with no matching tool use: {self.unmatched_tool_results}")
        return ImportSummary(
            events=self.events,
            model_turns=self.model_turns,
            tool_calls=self.tool_calls,
            tool_results=self.tool_results,
            spans=self.spans,
            unknown_records=self.unknown_records,
            malformed_lines=self.malformed_lines,
            unmatched_tool_results=self.unmatched_tool_results,
            capture=dict(capture),
            notes=tuple(notes),
        )


def _read_lines(lines: Any) -> list[str]:
    """Materialize the input. Both importers need a second look before they emit.

    Claude's ``result`` record and Codex's final usage arrive after the turns they describe,
    so an importer that emitted strictly as it read would have to either skip those fields
    or emit an event it later wished to amend. Reading twice costs one pass over a file that
    a CLI just finished writing, and buys a trace whose last response carries the summary
    the CLI reported for it.
    """
    return [line for line in lines]


def parse_lines(lines: Any, tracker: _Import) -> list[dict[str, Any]]:
    """Parse JSONL into records, counting the lines that were not JSON rather than raising.

    A blank line is not damage and is not counted: every one of these files ends with a
    newline, and a trailing empty string is how that newline reads after a split.
    """
    records = []
    for line in _read_lines(lines):
        text = line.strip() if isinstance(line, str) else ""
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            tracker.malformed_lines += 1
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
        else:
            # Valid JSON that is not a record: a bare number or list is as unreadable as a
            # broken line for this purpose, and counting it as malformed says so honestly.
            tracker.malformed_lines += 1
    return records


__all__ = [
    "CAPTURE_KEYS",
    "EXTERNAL_PREFIX",
    "FAILURE_KINDS",
    "SUMMARY_CHARS",
    "ImportSummary",
    "block_text",
    "clip",
    "parse_lines",
    "relocate_paths",
    "sha256_text",
    "workspace_path",
    "workspace_roots",
]
