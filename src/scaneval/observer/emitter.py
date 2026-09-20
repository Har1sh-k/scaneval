"""Native Python trace emitter, behaviorally matched to the TypeScript observer SDK.

The emitter records what a harness explicitly hands it and nothing more. It does not wrap,
patch, or discover a model client, a tool dispatcher, or a scanner; it opens no file of its
own, starts no thread, spawns no process, and makes no network call. An :class:`Observer` in
the default ``off`` mode is a no-op that never calls the clock, the ID factory, the redactor,
or the sink given to it, and never reads an attribute of the sink object either, so
constructing one runs no caller code at all. The one resource the emitter can ever own is a
private event loop, with the selector it allocates, created lazily and only when a synchronous
harness hands it a sink that returns an awaitable, and closed by :meth:`Observer.close`.

Instrumentation never alters the caller. Every caller-supplied hook (clock, monotonic source,
ID factory, redactor, event builder) and every sink write runs under a ``BaseException`` guard:
the failure becomes a visible capture gap and only :class:`KeyboardInterrupt` and
:class:`SystemExit` are re-raised, because those are the caller's own interrupt rather than an
instrumentation defect. An :class:`asyncio.CancelledError` raised by a sink is a recorded gap,
not an escape. One lost event counts once: the guard that owns a caller call records the gap,
and the containment guards outside it re-raise an interrupt without counting it again. An
interrupt raised inside a redactor or a caller's own Mapping propagates unrecorded, because the
run a capture state would describe is the one that is ending. A payload that is not JSON or is
cyclic, a :class:`RecursionError` raised near the stack limit, and an event the wire contract
rejects are all counted in :class:`CaptureState` and dropped. An event built while
instrumentation failed carries a fabricated ID or timestamp, so it is downgraded to ``partial``
and marked with ``observer_capture_gap`` in its metadata rather than left claiming to be a
measurement. A gap says the trace is incomplete; an absent event is not evidence of absent
activity.

The wire contract is shared with ``sdk/typescript``, so the two emitters accept and reject the
same inputs and, where they once differed, the stricter rule is the shared one:

* A field present with the value ``None`` is refused rather than read as absent. ``None`` is not
  absence: the contract distinguishes a field a harness did not send from one it sent empty.
* ``duration_ms`` is a whole number of milliseconds. A non-integral, negative, non-finite, or
  ``None`` duration is refused, and an integral float is stored as an integer so both languages
  write the same bytes.
* A field name the contract does not list is refused, so a misspelling is loud rather than
  silently dropped.
* The default redactor folds case over ASCII only (``re.IGNORECASE | re.ASCII``), so it hides
  the same key names the JavaScript regex hides and does not fold, say, a Kelvin sign into a
  ``k``.
* Whether a redactor changed a value is decided by reference identity, never by value equality.
* Keys are emitted in the order the wire schema declares them.

A rejected event consumes no sequence number, no event ID, and no clock read in either language.
That is only safe because the two rejection sets are identical, so the rejection rule above is
part of the contract rather than an implementation detail.

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
import time
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
# other telemetry counter that merely contains a credential-looking word. ``re.ASCII`` keeps
# case folding ASCII-only, so a Kelvin sign or a long s is left alone exactly as the JavaScript
# regex leaves it alone.
_SECRET_KEY = re.compile(
    r"api[_-]?key|authorization|credential(?:s)?|cookie(?:s)?|password|secret(?:s)?|token"
    r"|private[_-]?key",
    re.IGNORECASE | re.ASCII,
)
_REDACTED = "[REDACTED]"

# One opaque message for every instrumentation failure. The emitter reports that capture broke,
# not where: a sink's exception text can carry the payload it failed to write.
_GAP_MESSAGE = "observer instrumentation failure"

# Set in an event's metadata when instrumentation failed while that event was being built, so a
# reader cannot mistake a fabricated ID or an epoch timestamp for a measured one. The emitter
# owns this key and overwrites a caller value of the same name.
_GAP_KEY = "observer_capture_gap"

# The timestamp an event carries when the clock could not be read. Spelled as a literal so the
# degraded path allocates nothing and calls nothing.
_EPOCH_TIMESTAMP = "1970-01-01T00:00:00.000Z"

_INTERRUPTS = (KeyboardInterrupt, SystemExit)
_MISSING = object()

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
    snapshot cannot leak a payload a sink refused. A write started inside a caller's event loop
    and not yet finished is neither counted nor reported here: it is not lost, and awaiting
    :meth:`Observer.aflush` is what settles it into either a delivered event or a counted gap.
    The three fields are the ones the TypeScript emitter's capture state carries, so a reader
    joins the two by name. Zero dropped events is not a claim that the harness emitted
    everything it should have: it only says nothing the harness did emit was lost here.
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


def _redact(value: Any, redactor: Redactor, path: tuple[str, ...] = ()) -> tuple[Any, bool]:
    """Apply the redactor at every object key and report whether anything was replaced.

    The redactor sees keys, never bare list elements, and its replacement is copied and walked
    again: a redactor is caller code, so its output is no more trusted than the payload it
    replaced. A replacement counts as a redaction when it is not the object it replaced, by
    reference and never by value, so a redactor that hands back an equal copy is still reported
    as having changed the value. Raising from a redactor aborts the event; it never partially
    stores one.
    """
    if isinstance(value, dict):
        output: JsonObject = {}
        changed = False
        for key, original in value.items():
            replacement = redactor(key, original, path)
            nested, nested_changed = _redact(_copy_json(replacement), redactor, (*path, key))
            changed = changed or nested_changed or replacement is not original
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
    """Replace values under credential-looking key names. Not PII removal, not policy.

    Key matching is whole-key and case-insensitive over ASCII only, so it hides exactly the
    names the TypeScript emitter's regex hides.
    """
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
    _require_aware(moment)
    utc = moment.astimezone(timezone.utc)
    return f"{utc.strftime('%Y-%m-%dT%H:%M:%S')}.{utc.microsecond // 1000:03d}Z"


def _require_aware(moment: Any) -> datetime:
    """Return the moment only if it is a timezone-aware datetime, else raise."""
    if not isinstance(moment, datetime):
        raise TypeError("clock did not return a datetime")
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise TypeError("clock returned a naive datetime")
    return moment


def _is_id(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _sink_target(sink: Any) -> Callable[[JsonObject], Any]:
    """Resolve the one callable a sink object exposes, running as little caller code as possible.

    Reading ``sink.write`` can run a descriptor the caller wrote, so a failure there is reported
    as an unusable sink rather than allowed out of the constructor as whatever it raised.
    """
    try:
        write = getattr(sink, "write", None)
    except _INTERRUPTS:
        raise
    except BaseException as error:
        raise ValueError("reading sink.write raised") from error
    if callable(write):
        return write
    if callable(sink):
        return sink
    raise ValueError("sink must be callable or expose a callable write method")


class Observer:
    """Emits trace events a harness hands it, and never anything it was not handed.

    Every constructor argument is keyword only and optional. ``mode`` defaults to ``"off"``,
    which makes :meth:`emit` a no-op; ``"metadata"`` stores events without content; ``"content"``
    stores a copied, redacted content payload as well. ``sink`` is either a callable taking one
    event mapping or an object with such a ``write`` method, sync or async in both shapes. An
    unknown ``mode`` or an unusable ``sink`` raises at construction, because a harness author
    fixes that once at wiring time; nothing during a scan raises. A generator function or async
    generator function is an unusable sink: calling one returns an iterator and writes nothing,
    which is a wiring mistake rather than a runtime failure. In ``off`` mode the sink is not
    inspected at all, because it is never used.

    ``clock`` names the wall clock that timestamps events. ``monotonic`` is the separate source
    :meth:`observe` measures elapsed time with; it returns a float number of seconds and
    defaults to :func:`time.monotonic`, or to the supplied ``clock`` when a caller injects one
    and no monotonic source, so a fixture that pins time stays reproducible without wiring two
    factories. A duration that cannot be measured, because a read failed or the source went
    backwards, is omitted from the event and recorded as a capture gap rather than invented.

    Synchronous harnesses need no event loop: :meth:`emit`, :meth:`observe`, :meth:`flush`, and
    :meth:`close` are ordinary methods, and a sink that returns an awaitable is driven to
    completion before ``emit`` returns, on one private event loop this observer creates on first
    need and :meth:`close` closes. That loop is never installed as the thread's current loop, so
    it cannot disturb a loop the caller owns. Inside a running loop the same sink is scheduled
    as a task on the caller's loop instead, and :meth:`aflush`, :meth:`aclose`, and
    :meth:`observe_async`, which are coroutines, are the ones to use there.

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
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        if mode not in RECORDING_MODES:
            raise ValueError(f"unknown recording mode: {mode!r}")
        self._mode = mode
        # Off mode reads nothing off the caller's sink, not even an attribute: a descriptor
        # there is caller code, and an observer that records nothing must run none of it.
        self._sink = None if mode == "off" else self._normalize_sink(sink)
        self._clock = clock if clock is not None else _default_clock
        self._monotonic = self._choose_monotonic(monotonic, clock)
        self._ids = id_factory if id_factory is not None else _default_id_factory()
        self._redactor = redactor if redactor is not None else default_redactor
        self._sequence = 0
        self._fallback_sequence = 0
        self._pending: set[Any] = set()
        self._runner_loop: Any = None
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
        """Resolve and vet the sink callable. Called only in a recording mode."""
        if sink is None:
            return None
        target = _sink_target(sink)
        # Imported here so importing the emitter stays cheap; this runs once, at wiring time.
        import inspect

        if inspect.isgeneratorfunction(target) or inspect.isasyncgenfunction(target):
            raise ValueError(
                "sink must not be a generator function: calling one returns an iterator and "
                "writes nothing"
            )
        return target

    @staticmethod
    def _choose_monotonic(
        monotonic: Callable[[], float] | None, clock: Callable[[], datetime] | None
    ) -> Callable[[], float]:
        """Pick the elapsed-time source: the injected one, else the injected clock, else time."""
        if monotonic is not None:
            return monotonic
        if clock is None:
            return time.monotonic

        def from_clock() -> float:
            return _require_aware(clock()).timestamp()

        return from_clock

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
        raising. A field passed explicitly as None is refused rather than read as absent. In
        ``off`` mode this returns None without touching the clock, the ID factory, the redactor,
        or the sink, including when the observer has been closed.

        The returned mapping is the same object handed to the sink. Treat it as owned by the
        trace; the emitter will not read it again, but a sink may still hold it.

        A sink that returns an awaitable is driven to completion here when no event loop is
        running, so a synchronous harness whose sink never returns blocks here for as long as
        :meth:`aflush` would wait in an asynchronous one. The emitter imposes no timeout on a
        caller's own writer.

        A harness that calls this with almost no stack left gets a capture gap and None rather
        than a :class:`RecursionError`. The one thing the emitter cannot contain is the
        interpreter refusing to enter this method at all, which is the same wall the harness's
        own next call would hit.
        """
        try:
            return self._emit_fields(fields)
        except BaseException as error:
            if isinstance(error, _INTERRUPTS):
                raise
            # Recorded inline: a RecursionError leaves no stack to call a helper with.
            self._dropped_events += 1
            self._capture_gap = True
            self._last_sink_error = _GAP_MESSAGE
            return None

    def observe(
        self,
        start: Mapping[str, Any],
        success: Callable[[Any], Mapping[str, Any]],
        failure: Callable[[BaseException, Any], Mapping[str, Any]],
        operation: Callable[[], Any],
    ) -> Any:
        """Run a synchronous operation between a start event and a success or failure event.

        Not a coroutine. ``success`` and ``failure`` build their event from the elapsed whole
        milliseconds, measured with the monotonic source rather than the wall clock; ``failure``
        also receives the exception, which is then re-raised unchanged, as the original object
        with its original traceback. The operation's return value is passed back untouched. Both
        builders receive None when the duration could not be measured, and any ``duration_ms``
        they return is then dropped from the event, which is still emitted, downgraded to
        ``partial``, and marked with ``observer_capture_gap`` in its metadata. A builder that
        raises is a capture gap too, and only its own KeyboardInterrupt or SystemExit reaches
        the caller.

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
        began = self._read_monotonic()
        try:
            value = operation()
        except BaseException as error:  # re-raised below, unchanged, in every case
            self._emit_completion(failure, began, error)
            raise
        self._emit_completion(success, began)
        return value

    async def observe_async(
        self,
        start: Mapping[str, Any],
        success: Callable[[Any], Mapping[str, Any]],
        failure: Callable[[BaseException, Any], Mapping[str, Any]],
        operation: Callable[[], Any],
    ) -> Any:
        """Coroutine form of :meth:`observe` for an operation that returns an awaitable.

        The operation is called, and its result is awaited only when it is awaitable, so a
        plain value works too. An async generator is not awaitable: it is returned untouched
        and the duration covers only the call that created it, never the stream a caller later
        consumes. The awaited value is returned unchanged and an exception is re-raised as the
        original object. An unmeasurable duration is omitted and recorded as a gap, exactly as
        in :meth:`observe`.

        Writes this starts are not awaited here. Call :meth:`aflush` when the harness operation
        is finished if you need them on disk before reading :meth:`get_state`.
        """
        if self._mode == "off":
            return await _resolve(operation())
        self._emit_fields(start)
        began = self._read_monotonic()
        try:
            value = await _resolve(operation())
        except BaseException as error:  # re-raised below, unchanged, in every case
            self._emit_completion(failure, began, error)
            raise
        self._emit_completion(success, began)
        return value

    def flush(self) -> None:
        """Wait for writes :meth:`emit` started and did not finish. Not a coroutine.

        In a synchronous harness each write has already been driven to completion by ``emit``,
        so this returns at once. Writes started while an event loop was running belong to that
        loop and only it can run them: waiting for them from synchronous code would deadlock
        the loop, so this returns instead and records nothing. A write in flight is not a lost
        event, and counting one as dropped would report a loss that never happened; a write
        that does fail counts itself. An asynchronous harness must await :meth:`aflush`.
        """
        return None

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
        The private event loop an async sink made this observer create is closed here, because
        that loop is the emitter's own and nobody else can close it. A sink the caller opened
        stays the caller's to close.
        """
        self.flush()
        self._closed = True
        self._close_runner()

    async def aclose(self) -> None:
        """Coroutine form of :meth:`close`: await :meth:`aflush`, then refuse later events."""
        await self.aflush()
        self._closed = True
        self._close_runner()

    def _emit_fields(self, fields: Any, drop_duration: bool = False) -> JsonObject | None:
        """Build and write one event. Nothing but a caller's own interrupt leaves this method."""
        if self._mode == "off":
            return None
        try:
            if self._closed:
                self._mark_gap()
                return None
            event = self._build(fields, drop_duration)
        except BaseException as error:
            if isinstance(error, _INTERRUPTS):
                raise
            # Reached only when a guard further in could not run, which is what a
            # RecursionError does to a handler that has to call something. Recorded inline
            # for the same reason.
            self._dropped_events += 1
            self._capture_gap = True
            self._last_sink_error = _GAP_MESSAGE
            return None
        if event is None:
            return None
        try:
            self._write(event)
        except BaseException as error:
            if isinstance(error, _INTERRUPTS):
                raise
            self._dropped_events += 1
            self._capture_gap = True
            self._last_sink_error = _GAP_MESSAGE
        return event

    def _emit_completion(
        self, build: Callable[..., Mapping[str, Any]], began: float | None, error: Any = _MISSING
    ) -> JsonObject | None:
        """Emit the event that closes an observed operation, with its measured duration or none.

        Guarded like :meth:`_emit_fields`, so an instrumentation failure here cannot travel out
        of :meth:`observe` into the operation's own result or exception.
        """
        try:
            elapsed = self._elapsed_ms(began)
            arguments = (elapsed,) if error is _MISSING else (error, elapsed)
            return self._emit_built(build, arguments, drop_duration=elapsed is None)
        except BaseException as failure:
            if isinstance(failure, _INTERRUPTS):
                raise
            self._dropped_events += 1
            self._capture_gap = True
            self._last_sink_error = _GAP_MESSAGE
            return None

    def _emit_built(
        self,
        build: Callable[..., Mapping[str, Any]],
        arguments: tuple[Any, ...],
        drop_duration: bool = False,
    ) -> JsonObject | None:
        """Build an event from a caller's callback. A callback that raises is a capture gap."""
        try:
            fields = build(*arguments)
        except BaseException as error:
            self._fail(error)
            return None
        return self._emit_fields(fields, drop_duration)

    def _build(self, fields: Any, drop_duration: bool = False) -> JsonObject | None:
        gaps_before = self._dropped_events
        try:
            snapshot = self._snapshot(fields)
            if drop_duration:
                snapshot.pop("duration_ms", None)
            if not self._valid_input(snapshot):
                raise TypeError("invalid trace event input")
            metadata, metadata_redacted = _redact(snapshot["metadata"], self._redactor)
            supplied_content = snapshot.get("content")
            if self._mode == "content" and supplied_content is not None:
                content, content_redacted = _redact(supplied_content, self._redactor)
            else:
                content, content_redacted = None, False
            event_type = snapshot["type"]
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
                    snapshot["capture_status"], metadata_redacted or content_redacted
                ),
                "timestamp": self._now(),
            }
            self._sequence += 1
            for name in _ID_FIELDS:
                if name in snapshot:
                    event[name] = snapshot[name]
            if "duration_ms" in snapshot:
                event["duration_ms"] = int(snapshot["duration_ms"])
            event["metadata"] = metadata
            if content is not None:
                event["content"] = content
            if drop_duration or self._dropped_events > gaps_before:
                # Instrumentation failed while this event was built, or the duration it should
                # carry could not be measured. Either way part of it is missing or fabricated:
                # say so rather than let a reader take an epoch timestamp for a measurement or
                # a missing duration for one the harness never had.
                if event["capture_status"] != "unavailable":
                    event["capture_status"] = "partial"
                metadata[_GAP_KEY] = True
        except BaseException as error:
            if isinstance(error, _INTERRUPTS):
                raise
            # Marked inline: a RecursionError leaves no room to call another method, and this
            # handler must record the loss even when the interpreter is out of stack.
            self._dropped_events += 1
            self._capture_gap = True
            self._last_sink_error = _GAP_MESSAGE
            return None
        return event

    def _snapshot(self, fields: Any) -> JsonObject:
        """Read the caller's mapping once, so validation and building see the same payload.

        A caller's Mapping is caller code: reading it twice lets it answer differently the
        second time and put a value in the event that no check ever saw. Metadata, and content
        when it will be stored, are deep copied here for the same reason.
        """
        if not isinstance(fields, Mapping):
            raise TypeError("trace event input must be a mapping")
        snapshot = dict(fields)
        if isinstance(snapshot.get("metadata"), Mapping):
            snapshot["metadata"] = _copy_json(dict(snapshot["metadata"]))
        if self._mode == "content" and isinstance(snapshot.get("content"), Mapping):
            snapshot["content"] = _copy_json(dict(snapshot["content"]))
        return snapshot

    def _valid_input(self, fields: JsonObject) -> bool:
        """Check a snapshot against the wire contract. An unknown field name is refused too.

        Python has no compile-time check on keyword arguments, so a misspelled field would
        otherwise be dropped in silence and the event would understate what the harness saw. A
        field present with the value None is refused for the same reason: the contract has no
        null, and reading None as absence would silently record a different event than the one
        the harness described.
        """
        if not set(fields).issubset(_INPUT_FIELDS):
            return False
        if any(value is None for value in fields.values()):
            return False
        event_type = fields.get("type")
        if not isinstance(event_type, str) or event_type not in _CATEGORY_FOR:
            return False
        if "category" in fields and fields["category"] != _CATEGORY_FOR[event_type]:
            return False
        if fields.get("capture_status") not in CAPTURE_STATUSES:
            return False
        if not isinstance(fields.get("metadata"), Mapping):
            return False
        if "content" in fields and not isinstance(fields["content"], Mapping):
            return False
        if "duration_ms" in fields and not _is_duration(fields["duration_ms"]):
            return False
        return all(_is_id(fields[name]) for name in _ID_FIELDS if name in fields)

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
        except BaseException as error:
            self._fail(error)
            return
        if _is_awaitable(result):
            self._drive(result)

    def _drive(self, awaitable: Any) -> None:
        """Finish an async write on this observer's own loop, or hand it to the caller's loop."""
        loop = _running_loop()
        if loop is not None:
            try:
                task = loop.create_task(self._await_write(awaitable))
            except BaseException as error:
                self._discard(awaitable)
                self._fail(error)
                return
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)
            return
        runner = self._runner()
        if runner is None:
            self._discard(awaitable)
            return
        try:
            runner.run_until_complete(self._await_write(awaitable))
        except BaseException as error:
            self._fail(error)

    def _runner(self) -> Any:
        """This observer's private event loop, created on first need and never installed.

        ``asyncio.run`` would create and tear down a loop per event and clear the calling
        thread's current loop as a side effect. One loop, never set as the thread's current one,
        drives the writes instead and leaves a loop the caller owns exactly as it found it.
        """
        import asyncio

        if self._runner_loop is None:
            try:
                self._runner_loop = asyncio.new_event_loop()
            except BaseException as error:
                self._fail(error)
                return None
        return self._runner_loop

    def _close_runner(self) -> None:
        """Close the private loop, if one was ever created. Touches no caller resource."""
        loop, self._runner_loop = self._runner_loop, None
        if loop is None:
            return
        try:
            loop.close()
        except BaseException as error:
            self._fail(error)

    def _discard(self, awaitable: Any) -> None:
        """Close a write that will never run, so an unawaited coroutine warns nobody."""
        try:
            close = getattr(awaitable, "close", None)
            if callable(close):
                close()
        except _INTERRUPTS:
            raise
        except BaseException:
            pass

    async def _await_write(self, awaitable: Any) -> None:
        try:
            await awaitable
        except _INTERRUPTS:
            raise
        except BaseException:
            # A cancelled write is a lost event, not an escape: cancellation from a caller's
            # sink must not travel out of instrumentation into the harness.
            self._mark_gap()

    def _fail(self, error: BaseException) -> None:
        """Record an instrumentation failure and let only a caller's own interrupt through."""
        self._mark_gap()
        if isinstance(error, _INTERRUPTS):
            raise error

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
        except BaseException as error:
            self._fail(error)
            self._fallback_sequence += 1
            return f"{prefix}-fallback-{self._fallback_sequence}"

    def _now(self) -> str:
        try:
            return _iso_timestamp(self._clock())
        except BaseException as error:
            self._fail(error)
            return _EPOCH_TIMESTAMP

    def _read_monotonic(self) -> float | None:
        """Read the elapsed-time source in seconds, or None with a gap when it is unusable."""
        try:
            value = self._monotonic()
        except BaseException as error:
            self._fail(error)
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            self._mark_gap()
            return None
        if not math.isfinite(value):
            self._mark_gap()
            return None
        return float(value)

    def _elapsed_ms(self, began: float | None) -> int | None:
        """Whole milliseconds between two reads, or None when the span cannot be measured.

        A failed read, a non-finite span, or a source that went backwards yields None and a
        capture gap. The emitter never invents a duration: an omitted one says the span is
        unknown, while a fabricated one would be read as a measurement.
        """
        if began is None:
            return None
        ended = self._read_monotonic()
        if ended is None:
            return None
        elapsed = (ended - began) * 1000.0
        if not math.isfinite(elapsed) or elapsed < 0:
            self._mark_gap()
            return None
        return round(elapsed)


def _is_duration(value: Any) -> bool:
    """A duration is a whole, finite, nonnegative number of milliseconds, and never a bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if not math.isfinite(value) or value < 0:
        return False
    return not isinstance(value, float) or value.is_integer()


async def _resolve(value: Any) -> Any:
    """Await an awaitable, pass anything else back untouched. Never iterates a generator."""
    if _is_awaitable(value):
        return await value
    return value
