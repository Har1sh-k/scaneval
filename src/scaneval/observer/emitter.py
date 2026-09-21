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
not an escape. One lost event counts once: the guard that owns a caller call records the loss,
and the containment guards outside it re-raise an interrupt without counting it again. An
interrupt raised inside a redactor or a caller's own Mapping propagates unrecorded, because the
run a capture state would describe is the one that is ending. A payload that is not JSON, is
cyclic, or is nested deeper than :data:`MAX_PAYLOAD_DEPTH`, a :class:`RecursionError` raised
near the stack limit, and an event the wire contract rejects are all dropped and counted. An
event built while instrumentation failed carries a fabricated ID or timestamp, so it is
downgraded to ``partial`` and marked with ``observer_capture_gap`` in its metadata rather than
left claiming to be a measurement. A gap says the trace is incomplete; an absent event is not
evidence of absent activity.

``dropped_events`` counts events that reached no sink, and nothing else. A clock read, an ID
read, or an elapsed-time read that failed sets ``capture_gap`` and marks the event it degraded,
but it does not increment the counter, because the event was still delivered: counting it there
would report a loss that did not happen and hide the ones that did. A write queued on an event
loop that is torn down before it runs is the opposite case, and is counted, because that event
reached nobody.

The wire contract is shared with ``sdk/typescript``, so the two emitters accept and reject the
same inputs and, where they once differed, the stricter rule is the shared one:

* A field present with the value ``None`` is refused rather than read as absent. ``None`` is not
  absence: the contract distinguishes a field a harness did not send from one it sent empty.
* ``duration_ms`` is a whole number of milliseconds and a safe integer. A non-integral,
  negative, non-finite, ``None``, boolean, or larger than ``2 ** 53 - 1`` duration is refused,
  and an integral float is stored as an integer so both languages write the same bytes. The
  bound is JavaScript's: past it a JSON number stops round-tripping, so a value Python could
  hold exactly would reach a reader as a different one.
* A field name the contract does not list is refused, so a misspelling is loud rather than
  silently dropped.
* The default redactor folds case over ASCII only (``re.IGNORECASE | re.ASCII``), so it hides
  the same key names the JavaScript regex hides and does not fold, say, a Kelvin sign into a
  ``k``.
* Whether a redactor changed a value follows JavaScript strict inequality: an immutable scalar
  (string, number, boolean, ``None``) is compared by value, and a container by identity. Python
  must mirror that rather than ask ``is``, because CPython gives two equal strings or two equal
  large integers separate identities and the two emitters would then disagree about whether an
  event was redacted.
* A payload nested deeper than :data:`MAX_PAYLOAD_DEPTH` containers is refused as a capture
  gap, so neither language accepts a payload the other refuses and neither recurses without a
  documented bound.
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

# The shared nesting bound for a metadata or content payload, counted in containers: the
# payload object itself is the first, a dict or list inside it is the second, and a payload
# that would need a thirty-third is refused as a capture gap. Both emitters enforce this exact
# number, so neither accepts a payload the other refuses, and neither recurses over caller data
# without a documented limit. Raising it is a contract change in both languages at once.
MAX_PAYLOAD_DEPTH = 32

# JavaScript's Number.MAX_SAFE_INTEGER. Past it a JSON number no longer round-trips through a
# double, so a duration above this would reach a reader as a different value than it left as.
_MAX_SAFE_INTEGER = 2**53 - 1

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

    ``dropped_events`` counts events that reached no sink, not scanner findings and not
    instrumentation failures in general: a clock, ID, or elapsed-time read that failed sets
    ``capture_gap`` and marks the event it degraded, but the event was delivered, so it is not
    counted here. ``capture_gap`` is therefore the broader flag, and it can be true while the
    counter is zero.

    ``last_sink_error`` is one opaque constant, ``"observer instrumentation failure"``, for
    every failure the emitter contains. It reports that capture broke, never which call broke
    or why: a sink's exception text can quote the payload it failed to write, and an emitter
    that repeated it would put that payload into the state a harness prints. Read the marked
    events, not this field, to see where capture degraded.

    A write started inside a caller's event loop and not yet finished is neither counted nor
    reported here: it is not lost, and awaiting :meth:`Observer.aflush` is what settles it into
    either a delivered event or a counted loss. A write whose loop is torn down before it runs
    is counted, because that event reached nobody. The three fields are the ones the TypeScript
    emitter's capture state carries, so a reader joins the two by name. Zero dropped events is
    not a claim that the harness emitted everything it should have: it only says nothing the
    harness did emit was lost here.
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
    """True for coroutines, futures, and tasks, decided the way ``await`` itself decides.

    The test is for ``__await__`` on the type, never on the instance. ``await`` resolves that
    name as a type slot, so an instance attribute named ``__await__`` is not awaitable however
    it looks, and reading the name off the instance would both answer differently than the
    language does and run caller code: a property or a ``__getattr__`` on an operation's return
    value is the caller's code, and instrumentation must not run it merely to classify the
    value. Deliberately false for async generators, which define ``__aiter__`` instead.
    """
    return any("__await__" in base.__dict__ for base in type(value).__mro__)


def _running_loop() -> Any:
    """Return the event loop running in this thread, or None. Never starts one."""
    import asyncio

    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _copy_json(value: Any, seen: set[int] | None = None, depth: int = 1) -> Any:
    """Deep copy into plain JSON types, refusing anything that would not survive the wire.

    Non-finite floats, cyclic structures, non-string object keys, objects that are not dicts,
    lists, tuples, or JSON scalars, and containers nested deeper than :data:`MAX_PAYLOAD_DEPTH`
    raise :class:`TypeError`. ``depth`` counts containers, and the payload object a caller
    passed is the first, so the limit is a property of the payload rather than of this call.
    This is a copy, not a coercion: nothing is stringified or truncated to make it fit, because
    a silently reshaped payload would misdescribe the run it claims to observe.
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
    if depth > MAX_PAYLOAD_DEPTH:
        # Refused, not truncated: both emitters draw the line here, so a payload one accepts
        # is one the other accepts, and neither walks a caller's structure without a bound.
        raise TypeError("JSON value nested deeper than the shared payload limit")
    if isinstance(value, dict):
        seen.add(marker)
        copied: JsonObject = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("non-string JSON object key")
            copied[key] = _copy_json(item, seen, depth + 1)
        seen.discard(marker)
        return copied
    if isinstance(value, (list, tuple)):
        seen.add(marker)
        items = [_copy_json(item, seen, depth + 1) for item in value]
        seen.discard(marker)
        return items
    raise TypeError("non-JSON value")


def _strictly_equal(replacement: Any, original: Any) -> bool:
    """JavaScript ``===`` over JSON values, so both emitters answer "was this replaced" alike.

    An immutable scalar (string, number, boolean, ``None``) is compared by value, because
    JavaScript gives it no separate identity: two equal strings are the same value there, and a
    redactor that rebuilt one changed nothing. A container is compared by identity, so a
    structurally equal rebuild is a replacement. Python must mirror this instead of asking
    ``is``: CPython gives two equal strings or two equal large integers separate identities,
    and an emitter that read that as a change would mark an event ``redacted`` where the
    TypeScript emitter marked it ``complete``. ``True`` and ``1`` stay different values here,
    as they do under ``===`` and unlike under Python's ``==``.
    """
    if replacement is original:
        # NaN is the one value that is not equal to itself in either language. It cannot reach
        # this function through a copied payload, which refuses non-finite numbers, so this is
        # the rule stated rather than a case that fires.
        return not (isinstance(replacement, float) and math.isnan(replacement))
    if replacement is None or original is None:
        return False
    if isinstance(replacement, bool) or isinstance(original, bool):
        return replacement is original
    if isinstance(replacement, (int, float)) and isinstance(original, (int, float)):
        return replacement == original
    if isinstance(replacement, str) and isinstance(original, str):
        return replacement == original
    return False


def _redact(
    value: Any, redactor: Redactor, path: tuple[str, ...] = (), depth: int = 1
) -> tuple[Any, bool]:
    """Apply the redactor at every object key and report whether anything was replaced.

    The redactor sees keys, never bare list elements, and its replacement is copied and walked
    again at the depth it would occupy: a redactor is caller code, so its output is no more
    trusted than the payload it replaced and cannot smuggle a value past the shared nesting
    limit. A replacement counts as a redaction when :func:`_strictly_equal` says it is not the
    value it replaced, which is JavaScript's rule: an equal rebuilt container is a replacement,
    an equal scalar is not. Raising from a redactor aborts the event; it never partially stores
    one.
    """
    if isinstance(value, dict):
        output: JsonObject = {}
        changed = False
        for key, original in value.items():
            replacement = redactor(key, original, path)
            copied = _copy_json(replacement, None, depth + 1)
            nested, nested_changed = _redact(copied, redactor, (*path, key), depth + 1)
            changed = changed or nested_changed or not _strictly_equal(replacement, original)
            output[key] = nested
        return output, changed
    if isinstance(value, list):
        items = []
        changed = False
        for index, item in enumerate(value):
            nested, nested_changed = _redact(item, redactor, (*path, str(index)), depth + 1)
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


def _is_generator_callable(target: Any) -> bool:
    """True when calling ``target`` would return a generator instead of writing anything.

    A plain generator function is the obvious shape. A callable object whose ``__call__`` is a
    generator function is the same wiring mistake wearing a different hat: calling it builds an
    iterator nobody drives, so the sink writes nothing and reports no loss. ``__call__`` is read
    off the type rather than the instance, so vetting a sink runs no caller code.
    """
    # Imported here so importing the emitter stays cheap; this runs once, at wiring time.
    import inspect

    if inspect.isgeneratorfunction(target) or inspect.isasyncgenfunction(target):
        return True
    call = getattr(type(target), "__call__", None)
    if call is None:
        return False
    return inspect.isgeneratorfunction(call) or inspect.isasyncgenfunction(call)


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
    generator function is an unusable sink, including as the ``__call__`` of a callable object:
    calling one returns an iterator and writes nothing, which is a wiring mistake rather than a
    runtime failure. In ``off`` mode the sink is not inspected at all, because it is never used.

    A recording mode with no sink at all is allowed and is not silent: :meth:`emit` still builds
    the event and returns it, so the observer can be used as a builder, but every event it
    builds reached nobody and is counted as a lost event in :class:`CaptureState`. Recording it
    honestly is the deliberate half of that choice, rather than refusing the observer at
    construction: the returned event is a real use, and a state that reported zero for events
    nobody received would be a black hole.

    ``clock`` names the wall clock that timestamps events. ``monotonic`` is the separate source
    :meth:`observe` measures elapsed time with; it returns a float number of seconds and
    defaults to :func:`time.monotonic`. It never falls back to ``clock``: a wall clock can be
    adjusted backwards or forwards between two reads, so measuring a span with one would record
    an elapsed time that never elapsed. A fixture that needs a pinned duration injects
    ``monotonic`` explicitly. A duration that cannot be measured, because a read failed, the
    source went backwards, or the span exceeds the shared safe-integer bound, is omitted from
    the event and recorded as a capture gap rather than invented.

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
        # Never the injected clock: a wall clock is not a monotonic source, and a fabricated
        # duration is worse than an omitted one.
        self._monotonic = monotonic if monotonic is not None else time.monotonic
        self._ids = id_factory if id_factory is not None else _default_id_factory()
        self._redactor = redactor if redactor is not None else default_redactor
        self._sequence = 0
        self._fallback_sequence = 0
        self._pending: set[Any] = set()
        self._runner_loop: Any = None
        self._closed = False
        self._dropped_events = 0
        # Every gap, counted or not, so :meth:`_build` can tell that instrumentation failed
        # while an event was being built even when that failure lost no event.
        self._gaps = 0
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
        if _is_generator_callable(target):
            raise ValueError(
                "sink must not be a generator function: calling one returns an iterator and "
                "writes nothing"
            )
        return target

    def get_state(self) -> CaptureState:
        """Return a snapshot of what capture lost. Later failures do not alter the snapshot.

        Writes whose event loop was torn down before they ran are counted first: a write that
        can never run is a lost event, and reporting a clean state for it would say the trace
        is complete when the sink never saw those events.
        """
        self._reap_lost_writes()
        return CaptureState(
            dropped_events=self._dropped_events,
            capture_gap=self._capture_gap,
            last_sink_error=self._last_sink_error,
        )

    def emit(self, **fields: Any) -> JsonObject | None:
        """Record one event and return it, or return None when nothing was recorded.

        Not a coroutine: a synchronous harness calls this directly. The event is validated
        against the wire contract before it is built, and an input the contract rejects, an
        instrumentation failure that stopped the event, or a closed observer is counted as a
        lost event instead of raising. A failure that only degraded an event, such as a clock
        read that raised, is a capture gap on a delivered event and is not counted as a loss.
        A field passed explicitly as None is refused rather than read as absent. In
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
            # Recorded inline: a RecursionError leaves no stack to call a helper with. The
            # event never reached a sink, so it counts as a lost one.
            self._gaps += 1
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
        milliseconds, measured with the monotonic source and never with the wall clock, not even
        one a caller injected; ``failure`` also receives the exception, which is then re-raised
        unchanged, as the original object with its original traceback. The operation's return
        value is passed back untouched. Both builders receive None when the duration could not
        be measured, and any ``duration_ms`` they return is then dropped from the event, which
        is still emitted, downgraded to ``partial``, and marked with ``observer_capture_gap`` in
        its metadata. A builder that raises loses its event, and only its own KeyboardInterrupt
        or SystemExit reaches the caller.

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
        plain value works too. Awaitable is decided on the result's type, the way ``await``
        decides it, so classifying the result runs none of the caller's own code: in ``off``
        mode this is as much a pass-through as the synchronous :meth:`observe`, which reads
        nothing off the value at all. An async generator is not awaitable: it is returned
        untouched and the duration covers only the call that created it, never the stream a
        caller later consumes. The awaited value is returned unchanged and an exception is
        re-raised as the original object. An unmeasurable duration is omitted and recorded as a
        gap, exactly as in :meth:`observe`.

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
        """Settle what can be settled here and release the private loop. Not a coroutine.

        In a synchronous harness each write has already been driven to completion by ``emit``,
        so there is nothing to wait for and the private event loop those writes ran on is
        closed here rather than held until :meth:`close`; the next async write creates another.
        Writes started while an event loop was running belong to that loop and only it can run
        them: waiting for them from synchronous code would deadlock the loop, so this leaves
        them pending. A write in flight is not a lost event, and counting one as dropped would
        report a loss that never happened; a write that fails counts itself, and a write whose
        loop was torn down before it ran is counted here. An asynchronous harness must await
        :meth:`aflush`.
        """
        self._reap_lost_writes()
        self._close_runner()

    async def aflush(self) -> None:
        """Coroutine that waits for writes :meth:`emit` started and did not await.

        Only writes belonging to the loop this runs on are awaited. A write queued on a
        different loop is left pending rather than gathered: awaiting a future from another
        loop raises, and an emitter that let that raise would turn a harness's flush into an
        instrumentation error and, by clearing the pending set first, destroy the record of the
        very writes it failed to settle. Those writes are still the other loop's to run, and
        they are counted as lost only once that loop is gone.

        A sink that never returns makes this wait forever. That is deliberate: the emitter
        imposes no timeout, because cancelling a harness's write is a policy decision only the
        caller can make. Apply your own timeout around this call and report the result as
        incomplete capture.
        """
        import asyncio

        loop = _running_loop()
        while True:
            self._reap_lost_writes()
            batch = tuple(write for write in self._pending if self._settles_on(write, loop))
            if not batch:
                return
            self._pending.difference_update(batch)
            try:
                await asyncio.gather(*batch, return_exceptions=True)
            except BaseException as error:
                # Evidence first: an unsettled write goes back into the pending set so the
                # failure cannot erase the record of what it failed to settle.
                self._pending.update(write for write in batch if not write.done())
                if isinstance(error, _INTERRUPTS):
                    raise
                self._mark_gap()
                return

    def close(self) -> None:
        """Flush, then refuse later events. Not a coroutine, and it closes no caller resource.

        After this, :meth:`emit` records a lost event and returns None instead of writing, so a
        late event is visible as loss rather than silently appearing after the run it postdates.
        The private event loop an async sink made this observer create is released by the flush,
        because that loop is the emitter's own and nobody else can close it, and pending writes
        whose loop is already gone are counted rather than kept as references to tasks that can
        never run. A write still live on a caller's loop is left alone: it is not lost, and only
        that loop can settle it. A sink the caller opened stays the caller's to close.
        """
        self.flush()
        self._closed = True

    async def aclose(self) -> None:
        """Coroutine form of :meth:`close`: await :meth:`aflush`, then refuse later events.

        The private loop is released here too, so neither closing path leaves the emitter's own
        resource open.
        """
        await self.aflush()
        self._closed = True
        self._close_runner()

    def _reap_lost_writes(self) -> None:
        """Count writes that can never run, and forget writes that already settled.

        A queued write is not lost while its loop can still run it, so a live one is left
        pending and uncounted. Once that loop is closed the write can never run: the event
        reached no sink, nobody else will ever count it, and a capture state that still read
        clean would be claiming a delivery that never happened. A write cancelled before it
        started is the same loss: :meth:`_await_write` never ran, so it never recorded itself.
        """
        for write in tuple(self._pending):
            try:
                settled = write.done()
                cancelled = settled and write.cancelled()
                loop = write.get_loop()
                unusable = loop is None or loop.is_closed()
            except _INTERRUPTS:
                raise
            except BaseException:
                # A pending entry the emitter cannot even inspect is not a write it can claim
                # was delivered.
                self._pending.discard(write)
                self._lost_event()
                continue
            if settled:
                self._pending.discard(write)
                if cancelled:
                    self._lost_event()
            elif unusable:
                self._pending.discard(write)
                self._lost_event()

    @staticmethod
    def _settles_on(write: Any, loop: Any) -> bool:
        """True when ``loop`` is the one that can run this write, so awaiting it is safe."""
        if loop is None:
            return False
        try:
            return write.get_loop() is loop
        except _INTERRUPTS:
            raise
        except BaseException:
            return False

    def _emit_fields(self, fields: Any, drop_duration: bool = False) -> JsonObject | None:
        """Build and write one event. Nothing but a caller's own interrupt leaves this method."""
        if self._mode == "off":
            return None
        try:
            if self._closed:
                self._lost_event()
                return None
            event = self._build(fields, drop_duration)
        except BaseException as error:
            if isinstance(error, _INTERRUPTS):
                raise
            # Reached only when a guard further in could not run, which is what a
            # RecursionError does to a handler that has to call something. Recorded inline
            # for the same reason.
            self._gaps += 1
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
            self._gaps += 1
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
            self._gaps += 1
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
        """Build an event from a caller's callback. A callback that raises loses that event."""
        try:
            fields = build(*arguments)
        except BaseException as error:
            self._fail_lost(error)
            return None
        return self._emit_fields(fields, drop_duration)

    def _build(self, fields: Any, drop_duration: bool = False) -> JsonObject | None:
        gaps_before = self._gaps
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
            if drop_duration or self._gaps > gaps_before:
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
            self._gaps += 1
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
        the harness described. ``duration_ms`` must also be a safe integer, so neither emitter
        accepts a count of milliseconds the other could not write back unchanged.
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
            # A recording mode with no sink. The event was built, spent a sequence number and
            # an ID, and reached nobody, so it is a lost event rather than a clean state.
            self._lost_event()
            return
        try:
            result = self._sink(event)
        except BaseException as error:
            self._fail_lost(error)
            return
        if _is_awaitable(result):
            self._drive(result)

    def _drive(self, awaitable: Any) -> None:
        """Finish an async write on this observer's own loop, or hand it to the caller's loop.

        Both failure paths close the wrapper coroutine as well as the write it wraps. Closing a
        coroutine never touches what it would have awaited, so discarding only one of the two
        leaves the other un-awaited, and an un-awaited coroutine becomes a ``RuntimeWarning``
        in the caller's process at collection time. Instrumentation that failed must not also
        print into a harness's output.
        """
        loop = _running_loop()
        writer = self._await_write(awaitable)
        if loop is not None:
            try:
                task = loop.create_task(writer)
            except BaseException as error:
                self._discard(writer)
                self._discard(awaitable)
                self._fail_lost(error)
                return
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)
            return
        runner = self._runner()
        if runner is None:
            self._discard(writer)
            self._discard(awaitable)
            self._lost_event()
            return
        try:
            runner.run_until_complete(writer)
        except BaseException as error:
            self._discard(writer)
            self._discard(awaitable)
            self._fail_lost(error)

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
            self._lost_event()

    def _fail(self, error: BaseException) -> None:
        """Record a failure that degraded an event without losing it, and re-raise interrupts.

        The clock, the ID factory, and the elapsed-time source reach here: their failure leaves
        a delivered event carrying a fabricated field, which :meth:`_build` marks in the event
        itself. Counting it as a dropped event would claim a loss that did not happen.
        """
        self._mark_gap()
        if isinstance(error, _INTERRUPTS):
            raise error

    def _fail_lost(self, error: BaseException) -> None:
        """Record a failure that lost one event, and let only a caller's own interrupt through."""
        self._lost_event()
        if isinstance(error, _INTERRUPTS):
            raise error

    def _mark_gap(self) -> None:
        """Capture broke here, but no event was lost by it."""
        self._gaps += 1
        self._capture_gap = True
        self._last_sink_error = _GAP_MESSAGE

    def _lost_event(self) -> None:
        """One event reached no sink. Counted once, by whichever guard owns that loss."""
        self._mark_gap()
        self._dropped_events += 1

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

        A failed read, a non-finite span, a source that went backwards, or a span past the
        shared safe-integer bound yields None and a capture gap. The last is a measurement the
        wire cannot carry exactly, so it is refused here rather than allowed to reject the whole
        completion event at validation. The emitter never invents a duration: an omitted one
        says the span is unknown, while a fabricated one would be read as a measurement.
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
        whole = round(elapsed)
        if whole > _MAX_SAFE_INTEGER:
            self._mark_gap()
            return None
        return whole


def _is_duration(value: Any) -> bool:
    """A duration is a whole, finite, nonnegative, safe-integer count of milliseconds.

    Never a bool, and never larger than ``2 ** 53 - 1``: past that bound a JSON number stops
    round-tripping through a double, so Python could hold a value the TypeScript emitter and a
    JavaScript reader could not, and the two would write different bytes for the same input.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if not math.isfinite(value) or value < 0:
        return False
    if value > _MAX_SAFE_INTEGER:
        return False
    return not isinstance(value, float) or value.is_integer()


async def _resolve(value: Any) -> Any:
    """Await an awaitable, pass anything else back untouched. Never iterates a generator.

    What counts as awaitable is decided on the type, so a value that merely looks awaitable
    from the outside is handed back rather than probed; nothing of the caller's runs here.
    """
    if _is_awaitable(value):
        return await value
    return value
