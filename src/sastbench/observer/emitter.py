"""Native Python trace emitter, behaviorally matched to the TypeScript observer SDK.

The emitter records what a harness explicitly hands it and nothing more. It does not wrap,
patch, or discover a model client, a tool dispatcher, or a scanner; it opens no file, starts
no thread, spawns no process, and makes no network call. An :class:`Observer` in the default
``off`` mode is a no-op that never calls the clock, the ID factory, or the sink given to it,
so constructing one costs nothing until a harness turns recording on.

Every instrumentation failure becomes a visible capture gap rather than an exception: a sink,
clock, ID factory, or redactor that raises, a payload that is not JSON or is cyclic, and an
event the wire contract rejects are all counted in :class:`CaptureState` and dropped. Nothing
here can change the value an observed operation returns or the exception it raises. A gap says
the trace is incomplete; an absent event is not evidence of absent activity.

Redaction is a key-name filter over values the caller chose to pass. It is not PII removal,
not a privacy certification, and not a safe-to-upload guarantee. The emitter never reaches
into the caller's objects: metadata and content are deep copied into plain JSON types before
anything is stored, and a caller-supplied redactor is treated as untrusted instrumentation
whose output is copied and revalidated the same way.

This module holds no truth labels, computes no score, calls no model, and changes no scanner
decision. It does not read or write the evaluation contracts, and it imports nothing from the
evaluator so that a harness can depend on it alone.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import re
from typing import Any, Protocol
import uuid


SCHEMA_VERSION = "2.0"

# Ordered exactly as the wire contract enumerates them so a reader can diff the two by eye.
RECORDING_MODES = ("off", "metadata", "content")
EVENT_TYPES = (
    "model.request",
    "model.response",
    "tool.start",
    "tool.end",
    "context.selection",
    "finding.candidate",
    "finding.validation",
    "finding.filtered",
    "finding.submitted",
    "observer.error",
)
EVENT_CATEGORIES = ("model", "tool", "context", "finding", "observer")
CAPTURE_STATUSES = ("complete", "partial", "redacted", "unavailable")

# The category of an event is a property of its type, never an independent claim by the caller.
_CATEGORY_FOR = {event_type: event_type.split(".", 1)[0] for event_type in EVENT_TYPES}

# Lifecycle links, in the order the wire contract lists them.
_ID_FIELDS = ("parent_event_id", "call_id", "attempt_id", "candidate_id", "claim_id")
_INPUT_FIELDS = frozenset(
    {"type", "category", "capture_status", "metadata", "content", "duration_ms", *_ID_FIELDS}
)

# The same alternation the TypeScript emitter uses. ``fullmatch`` supplies the anchors, so a
# key is matched whole: this deliberately does not match input_tokens, output_tokens, or any
# other telemetry counter that merely contains a credential-looking word.
_SECRET_KEY = re.compile(
    r"api[_-]?key|authorization|credential(?:s)?|cookie(?:s)?|password|secret(?:s)?|token"
    r"|private[_-]?key",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"

# One opaque message for every instrumentation failure. The emitter reports that capture broke,
# not where: a sink's exception text can carry the payload it failed to write.
_GAP_MESSAGE = "observer instrumentation failure"

JsonObject = dict[str, Any]
Redactor = Callable[[str, Any, "tuple[str, ...]"], Any]


class TraceSink(Protocol):
    """An object a harness owns that accepts one finished event. It may be sync or async."""

    def write(self, event: JsonObject) -> Any:
        ...


@dataclass(frozen=True)
class CaptureState:
    """What the emitter failed to record. It is a snapshot, so it never changes underfoot.

    ``dropped_events`` counts instrumentation failures, not scanner findings, and
    ``last_sink_error`` names the failure class rather than quoting an exception, so a state
    snapshot cannot leak a payload a sink refused. Zero dropped events is not a claim that the
    harness emitted everything it should have: it only says nothing the harness did emit was
    lost here.
    """

    dropped_events: int = 0
    capture_gap: bool = False
    last_sink_error: str | None = None


@dataclass(frozen=True)
class JsonlSink:
    """Adapts a caller-owned line writer. The SDK never opens or closes a file itself.

    ``write_line`` receives one serialized event with a trailing newline and may be either a
    plain callable or a coroutine function. Where those lines go, when they are fsynced, and
    whether they are ever deleted are the caller's decisions, not this class's.
    """

    write_line: Callable[[str], Any]

    def write(self, event: JsonObject) -> Any:
        return self.write_line(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")


def create_jsonl_sink(write_line: Callable[[str], Any]) -> JsonlSink:
    """Wrap a caller-owned line writer as a sink. Opens nothing and captures no global stream."""
    return JsonlSink(write_line)


def _is_awaitable(value: Any) -> bool:
    """True for coroutines, futures, and tasks. Deliberately false for async generators."""
    return hasattr(value, "__await__")


def _running_loop() -> Any:
    """Return the event loop running in this thread, or None. Never starts one."""
    import asyncio

    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _copy_json(value: Any, seen: set[int] | None = None) -> Any:
    """Deep copy into plain JSON types, refusing anything that would not survive the wire.

    Non-finite floats, cyclic structures, non-string object keys, and objects that are not
    dicts, lists, tuples, or JSON scalars raise :class:`TypeError`. This is a copy, not a
    coercion: nothing is stringified to make it fit, because a silently reshaped payload would
    misdescribe the run it claims to observe.
    """
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("non-finite JSON number")
        return value
    seen = set() if seen is None else seen
    marker = id(value)
    if marker in seen:
        raise TypeError("cyclic JSON value")
    if isinstance(value, dict):
        seen.add(marker)
        copied: JsonObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("non-string JSON object key")
            copied[key] = _copy_json(item, seen)
        seen.discard(marker)
        return copied
    if isinstance(value, (list, tuple)):
        seen.add(marker)
        items = [_copy_json(item, seen) for item in value]
        seen.discard(marker)
        return items
    raise TypeError("non-JSON value")


def _differs(original: Any, replacement: Any) -> bool:
    """Whether a redactor returned something other than what it was given."""
    if original is replacement:
        return False
    if type(original) is not type(replacement):
        return True
    return original != replacement


def _redact(value: Any, redactor: Redactor, path: tuple[str, ...] = ()) -> tuple[Any, bool]:
    """Apply the redactor at every object key and report whether anything was replaced.

    The redactor sees keys, never bare list elements, and its replacement is copied and walked
    again: a redactor is caller code, so its output is no more trusted than the payload it
    replaced. Raising from a redactor aborts the event; it never partially stores one.
    """
    if isinstance(value, dict):
        output: JsonObject = {}
        changed = False
        for key, original in value.items():
            replacement = redactor(key, original, path)
            nested, nested_changed = _redact(_copy_json(replacement), redactor, (*path, key))
            changed = changed or nested_changed or _differs(original, replacement)
            output[key] = nested
        return output, changed
    if isinstance(value, list):
        items = []
        changed = False
        for index, item in enumerate(value):
            nested, nested_changed = _redact(item, redactor, (*path, str(index)))
            changed = changed or nested_changed
            items.append(nested)
        return items, changed
    return value, False


def default_redactor(key: str, value: Any, path: tuple[str, ...]) -> Any:
    """Replace values under credential-looking key names. Not PII removal, not policy."""
    return _REDACTED if _SECRET_KEY.fullmatch(key) else value


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


def _default_id_factory() -> Callable[[str], str]:
    counter = 0

    def next_id(prefix: str) -> str:
        nonlocal counter
        counter += 1
        return f"{prefix}-{counter}-{uuid.uuid4().hex}"

    return next_id


def _iso_timestamp(moment: Any) -> str:
    """Format an aware datetime the way the wire fixture spells it: UTC, milliseconds, Z.

    A naive datetime is refused rather than assumed to be UTC or local: guessing a zone would
    put an invented offset into a record other tools join on.
    """
    if not isinstance(moment, datetime):
        raise TypeError("clock did not return a datetime")
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise TypeError("clock returned a naive datetime")
    utc = moment.astimezone(timezone.utc)
    return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond // 1000:03d}Z"


def _is_id(value: Any) -> bool:
    return isinstance(value, str) and value != ""


class Observer:
    """Emits trace events a harness hands it, and never anything it was not handed.

    Every constructor argument is keyword only and optional. ``mode`` defaults to ``"off"``,
    which makes :meth:`emit` a no-op; ``"metadata"`` stores events without content; ``"content"``
    stores a copied, redacted content payload as well. ``sink`` is either a callable taking one
    event mapping or an object with such a ``write`` method, sync or async in both shapes. An
    unknown ``mode`` or an unusable ``sink`` raises at construction, because a harness author
    fixes that once at wiring time; nothing during a scan raises.

    Synchronous harnesses need no event loop: :meth:`emit`, :meth:`observe`, :meth:`flush`, and
    :meth:`close` are ordinary methods, and a sink that returns an awaitable is driven to
    completion before ``emit`` returns. Inside a running loop the same sink is scheduled as a
    task instead, and :meth:`aflush`, :meth:`aclose`, and :meth:`observe_async`, which are
    coroutines, are the ones to use there.

    This class is not thread safe, does not batch, does not retry, and does not sample. It holds
    no truth labels, computes no score, calls no model, and changes no scanner decision.
    """

    def __init__(
        self,
        *,
        mode: str = "off",
        sink: Any = None,
        run_id: str | None = None,
        producer_id: str | None = None,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        if mode not in RECORDING_MODES:
            raise ValueError(f"unknown recording mode: {mode!r}")
        self._mode = mode
        self._sink = self._normalize_sink(sink)
        self._clock = clock if clock is not None else _default_clock
        self._ids = id_factory if id_factory is not None else _default_id_factory()
        self._redactor = redactor if redactor is not None else default_redactor
        self._sequence = 0
        self._fallback_sequence = 0
        self._pending: set[Any] = set()
        self._closed = False
        self._dropped_events = 0
        self._capture_gap = False
        self._last_sink_error: str | None = None
        # Off mode must not invoke a caller's ID factory merely by existing.
        self.run_id = run_id if _is_id(run_id) else ("off" if mode == "off" else self._next_id("run"))
        self.producer_id = (
            producer_id
            if _is_id(producer_id)
            else ("off" if mode == "off" else self._next_id("producer"))
        )

    @property
    def mode(self) -> str:
        """The recording mode fixed at construction. It is not switchable mid run."""
        return self._mode

    @property
    def closed(self) -> bool:
        return self._closed

    @staticmethod
    def _normalize_sink(sink: Any) -> Callable[[JsonObject], Any] | None:
        if sink is None:
            return None
        write = getattr(sink, "write", None)
        if callable(write):
            return write
        if callable(sink):
            return sink
        raise ValueError("sink must be callable or expose a callable write method")

    def get_state(self) -> CaptureState:
        """Return a snapshot of what capture lost. Later failures do not alter the snapshot."""
        return CaptureState(
            dropped_events=self._dropped_events,
            capture_gap=self._capture_gap,
            last_sink_error=self._last_sink_error,
        )

    def emit(self, **fields: Any) -> JsonObject | None:
        """Record one event and return it, or return None when nothing was recorded.

        Not a coroutine: a synchronous harness calls this directly. The event is validated
        against the wire contract before it is built, and an input the contract rejects, an
        instrumentation failure, or a closed observer is counted as a capture gap instead of
        raising. In ``off`` mode this returns None without touching the clock, the ID factory,
        the redactor, or the sink, including when the observer has been closed.

        The returned mapping is the same object handed to the sink. Treat it as owned by the
        trace; the emitter will not read it again, but a sink may still hold it.

        A sink that returns an awaitable is driven to completion here when no event loop is
        running, so a synchronous harness whose sink never returns blocks here for as long as
        :meth:`aflush` would wait in an asynchronous one. The emitter imposes no timeout on a
        caller's own writer.
        """
        return self._emit_fields(fields)

    def observe(
        self,
        start: Mapping[str, Any],
        success: Callable[[float], Mapping[str, Any]],
        failure: Callable[[BaseException, float], Mapping[str, Any]],
        operation: Callable[[], Any],
    ) -> Any:
        """Run a synchronous operation between a start event and a success or failure event.

        Not a coroutine. ``success`` and ``failure`` build their event from the elapsed
        milliseconds, measured with the injected clock; ``failure`` also receives the exception,
        which is then re-raised unchanged, as the original object with its original traceback.
        The operation's return value is passed back untouched.

        Untouched is literal: if the operation returns a generator, an iterator, a file, or an
        awaitable, that object is returned as it is and the duration covers only the call that
        produced it, not the work a caller later drives out of it. Nothing here consumes,
        wraps, or replaces a stream. Emit your own events at the boundaries you care about if
        you need to time consumption. In ``off`` mode the operation runs with no instrumentation
        at all and the two event builders are never called.
        """
        if self._mode == "off":
            return operation()
        self._emit_fields(start)
        began = self._now_ms()
        try:
            value = operation()
        except BaseException as error:  # re-raised below, unchanged, in every case
            self._emit_built(failure, error, self._now_ms() - began)
            raise
        self._emit_built(success, self._now_ms() - began)
        return value

    async def observe_async(
        self,
        start: Mapping[str, Any],
        success: Callable[[float], Mapping[str, Any]],
        failure: Callable[[BaseException, float], Mapping[str, Any]],
        operation: Callable[[], Any],
    ) -> Any:
        """Coroutine form of :meth:`observe` for an operation that returns an awaitable.

        The operation is called, and its result is awaited only when it is awaitable, so a
        plain value works too. An async generator is not awaitable: it is returned untouched
        and the duration covers only the call that created it, never the stream a caller later
        consumes. The awaited value is returned unchanged and an exception is re-raised as the
        original object.

        Writes this starts are not awaited here. Call :meth:`aflush` when the harness operation
        is finished if you need them on disk before reading :meth:`get_state`.
        """
        if self._mode == "off":
            return await _resolve(operation())
        self._emit_fields(start)
        began = self._now_ms()
        try:
            value = await _resolve(operation())
        except BaseException as error:  # re-raised below, unchanged, in every case
            self._emit_built(failure, error, self._now_ms() - began)
            raise
        self._emit_built(success, self._now_ms() - began)
        return value

    def flush(self) -> None:
        """Wait for writes :meth:`emit` started and did not finish. Not a coroutine.

        In a synchronous harness each write has already been driven to completion by ``emit``,
        so this returns at once. Writes started while an event loop was running belong to that
        loop and only it can run them: waiting for them from synchronous code would deadlock
        the loop, so this records a capture gap and returns instead. An asynchronous harness
        must await :meth:`aflush`.
        """
        if self._pending:
            self._mark_gap()

    async def aflush(self) -> None:
        """Coroutine that waits for writes :meth:`emit` started and did not await.

        A sink that never returns makes this wait forever. That is deliberate: the emitter
        imposes no timeout, because cancelling a harness's write is a policy decision only the
        caller can make. Apply your own timeout around this call and report the result as
        incomplete capture.
        """
        import asyncio

        while self._pending:
            batch = tuple(self._pending)
            self._pending.difference_update(batch)
            await asyncio.gather(*batch, return_exceptions=True)

    def close(self) -> None:
        """Flush, then refuse later events. Not a coroutine, and it closes no caller resource.

        After this, :meth:`emit` records a capture gap and returns None instead of writing, so a
        late event is visible as loss rather than silently appearing after the run it postdates.
        A sink the caller opened stays the caller's to close.
        """
        self.flush()
        self._closed = True

    async def aclose(self) -> None:
        """Coroutine form of :meth:`close`: await :meth:`aflush`, then refuse later events."""
        await self.aflush()
        self._closed = True

    def _emit_fields(self, fields: Any) -> JsonObject | None:
        if self._mode == "off":
            return None
        if self._closed:
            self._mark_gap()
            return None
        event = self._build(fields)
        if event is None:
            return None
        self._write(event)
        return event

    def _emit_built(
        self, build: Callable[..., Mapping[str, Any]], *arguments: Any
    ) -> JsonObject | None:
        """Build an event from a caller's callback. A callback that raises is a capture gap."""
        try:
            fields = build(*arguments)
        except Exception:
            self._mark_gap()
            return None
        return self._emit_fields(fields)

    def _build(self, fields: Any) -> JsonObject | None:
        try:
            if not isinstance(fields, Mapping) or not self._valid_input(fields):
                raise TypeError("invalid trace event input")
            metadata, metadata_redacted = _redact(
                _copy_json(dict(fields["metadata"])), self._redactor
            )
            supplied_content = fields.get("content")
            if self._mode == "content" and supplied_content is not None:
                content, content_redacted = _redact(
                    _copy_json(dict(supplied_content)), self._redactor
                )
            else:
                content, content_redacted = None, False
            event_type = fields["type"]
            # Built in the order the wire contract declares, so a JSONL line reads as the schema does.
            event: JsonObject = {
                "schema_version": SCHEMA_VERSION,
                "event_id": self._next_id("event"),
                "run_id": self.run_id,
                "producer_id": self.producer_id,
                "sequence": self._sequence,
                "type": event_type,
                "category": _CATEGORY_FOR[event_type],
                "capture_status": self._downgraded(
                    fields["capture_status"], metadata_redacted or content_redacted
                ),
                "timestamp": self._now(),
            }
            self._sequence += 1
            for name in _ID_FIELDS:
                value = fields.get(name)
                if value is not None:
                    event[name] = value
            duration_ms = fields.get("duration_ms")
            if duration_ms is not None:
                event["duration_ms"] = duration_ms
            event["metadata"] = metadata
            if content is not None:
                event["content"] = content
        except Exception:
            self._mark_gap()
            return None
        return event

    def _valid_input(self, fields: Mapping[str, Any]) -> bool:
        """Check an event against the wire contract. An unknown field name is refused too.

        Python has no compile-time check on keyword arguments, so a misspelled field would
        otherwise be dropped in silence and the event would understate what the harness saw.
        """
        if not set(fields).issubset(_INPUT_FIELDS):
            return False
        event_type = fields.get("type")
        if not isinstance(event_type, str) or event_type not in _CATEGORY_FOR:
            return False
        category = fields.get("category")
        if category is not None and category != _CATEGORY_FOR[event_type]:
            return False
        if fields.get("capture_status") not in CAPTURE_STATUSES:
            return False
        if not isinstance(fields.get("metadata"), Mapping):
            return False
        content = fields.get("content")
        if content is not None and not isinstance(content, Mapping):
            return False
        duration_ms = fields.get("duration_ms")
        if duration_ms is not None:
            if isinstance(duration_ms, bool) or not isinstance(duration_ms, (int, float)):
                return False
            if not math.isfinite(duration_ms) or duration_ms < 0:
                return False
        return all(_is_id(fields[name]) for name in _ID_FIELDS if fields.get(name) is not None)

    def _downgraded(self, requested: str, redacted: bool) -> str:
        """Never report more capture than was stored: metadata mode is partial, not complete."""
        if requested == "unavailable":
            return "unavailable"
        if redacted:
            return "redacted"
        if self._mode == "metadata" and requested == "complete":
            return "partial"
        return requested

    def _write(self, event: JsonObject) -> None:
        if self._sink is None:
            return
        try:
            result = self._sink(event)
        except Exception:
            self._mark_gap()
            return
        if _is_awaitable(result):
            self._schedule(result)

    def _schedule(self, awaitable: Any) -> None:
        """Finish an async write now if nothing is running, or hand it to the running loop."""
        import asyncio

        loop = _running_loop()
        if loop is None:
            try:
                asyncio.run(self._await_write(awaitable))
            except Exception:
                self._mark_gap()
            return
        task = loop.create_task(self._await_write(awaitable))
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)

    async def _await_write(self, awaitable: Any) -> None:
        try:
            await awaitable
        except Exception:
            self._mark_gap()

    def _mark_gap(self) -> None:
        self._dropped_events += 1
        self._capture_gap = True
        self._last_sink_error = _GAP_MESSAGE

    def _next_id(self, prefix: str) -> str:
        try:
            value = self._ids(prefix)
            if not _is_id(value):
                raise TypeError("id factory returned an unusable id")
            return value
        except Exception:
            self._mark_gap()
            self._fallback_sequence += 1
            return f"{prefix}-fallback-{self._fallback_sequence}"

    def _now(self) -> str:
        try:
            return _iso_timestamp(self._clock())
        except Exception:
            self._mark_gap()
            return _iso_timestamp(datetime.fromtimestamp(0, timezone.utc))

    def _now_ms(self) -> float:
        try:
            moment = self._clock()
            if not isinstance(moment, datetime) or moment.tzinfo is None:
                raise TypeError("clock did not return an aware datetime")
            value = moment.timestamp() * 1000.0
            if not math.isfinite(value):
                raise TypeError("clock returned an unusable instant")
            return value
        except Exception:
            self._mark_gap()
            return 0.0


async def _resolve(value: Any) -> Any:
    """Await an awaitable, pass anything else back untouched. Never iterates a generator."""
    if _is_awaitable(value):
        return await value
    return value
