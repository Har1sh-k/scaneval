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
not an escape. One lost event counts once. While an event is being built, the guard that owns a
caller call records the loss and the containment guards outside it re-raise an interrupt without
counting it again. Once it reaches a sink the accounting belongs to one :class:`_Delivery` record
per write, settled from a ``finally`` that every exit from that write crosses and settled only
once, so a path that re-raises cannot skip the count and a path that notices late cannot repeat
it. An interrupt raised inside a redactor, a caller's own Mapping, the clock, the ID factory, or
the elapsed-time source travels on to the caller unchanged, but the event it stopped is counted as
lost before it does: that event reached no sink, and a state reading clean would say the run
ended having recorded everything it was handed. A payload that is not JSON, is
cyclic, or is nested deeper than :data:`MAX_PAYLOAD_DEPTH`, a :class:`RecursionError` raised
near the stack limit, and an event the wire contract rejects are all dropped and counted. An
event built while instrumentation failed carries a fabricated ID or timestamp, so it is
downgraded to ``partial`` and marked with ``observer_capture_gap`` in its metadata rather than
left claiming to be a measurement. A gap says the trace is incomplete; an absent event is not
evidence of absent activity.

``dropped_events`` counts events no sink acknowledged taking, and nothing else; the exact
promise, and why acknowledgement rather than arrival is the word, is on :class:`CaptureState`.
A clock read, an ID read, or an elapsed-time read that failed sets ``capture_gap`` and marks
the event it degraded, but it does not increment the counter, because the sink still took that
event: counting it there would report a loss that did not happen and hide the ones that did. A
write queued on an event loop that is torn down before it runs, one cancelled before it ever
starts, and one whose sink handed back an iterator nobody drives are the opposite case, and are
counted, because those events reached nobody.

The wire contract is shared with ``sdk/typescript``, so the two emitters accept and reject the
same inputs and, where they once differed, the stricter rule is the shared one:

* A field present with the value ``None`` is refused rather than read as absent. ``None`` is not
  absence: the contract distinguishes a field a harness did not send from one it sent empty.
* ``duration_ms`` is a whole number of milliseconds and a safe integer. A non-integral,
  negative, non-finite, ``None``, boolean, or larger than ``2 ** 53 - 1`` duration is refused,
  and an integral float is stored as an integer so both languages write the same bytes. The
  bound is JavaScript's: past it a JSON number stops round-tripping, so a value Python could
  hold exactly would reach a reader as a different one.
* A number in a payload is stored only when both languages write it as the same bytes, which
  :func:`_wire_number` decides for every payload number in one place. An integral one is held
  to the same safe-integer bound as ``duration_ms`` and stored as an integer, because
  JavaScript has one number type and writes ``5`` where ``json.dumps`` writes ``5.0``. A
  non-integral one must be at least :data:`_MIN_PLAIN_DECIMAL` in magnitude, the plain decimal
  window the two share; below it they switch to exponent notation at different magnitudes and
  spell an exponent differently. Anything else is refused as a capture gap rather than written
  as bytes a reader in the other language would read as a different number, or fail to read,
  and that includes the magnitudes below 1e-9 where the two agree again.
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
* A string no UTF-8 sink could write is refused as a capture gap, in a payload value, a payload
  key, a link, run or producer ID, an ID a factory produced, and the timestamp a caller's clock
  spelled alike. Python held an unpaired surrogate and copied it into
  the line, where a real JSONL file failed to encode it and lost the event at the sink, while
  JavaScript escaped it and wrote a line that parses. A surrogate pair spelling a real astral
  character is text and both write it. Each language decides "may this string go on the wire" in
  one place, :func:`_is_id` here and ``validId`` there, so no path can carry a weaker copy of
  the rule.
* A ``metadata`` or ``content`` that is not a payload object the emitter can store is refused,
  in every recording mode. A payload object is a Mapping here and a plain object in JavaScript,
  decided by :func:`_is_payload_object` and by ``isJsonObject``, each asked by the input gate
  and by the payload copy, so a mode cannot change what a caller may hand over. What is inside a
  stored payload is the separate rule the copy owns, which is why a ``content`` whose contents
  the copy would refuse is accepted in ``metadata`` mode, where content is never copied.
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
from types import AsyncGeneratorType, GeneratorType
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

# JavaScript's Number.MAX_SAFE_INTEGER. Past it a JSON number no longer distinguishes
# neighbouring integers, so a value above this would reach a reader as a different one than it
# left as. It bounds every integer the wire carries: a ``duration_ms`` and, through
# :func:`_wire_number`, a number a caller put in a payload.
_MAX_SAFE_INTEGER = 2**53 - 1

# The smallest magnitude both languages spell in plain decimal notation, and therefore the
# smallest number the wire carries that is not an integer. Python's ``repr`` switches to
# exponent notation below 1e-4 and JavaScript's number formatting below 1e-6, and where both do
# use an exponent they spell it differently: Python pads it to two digits, writing ``1e-07``
# where JavaScript writes ``1e-7``. A smaller payload number would therefore leave the two
# emitters as different bytes, up to a point: below 1e-9 every exponent has two digits in both
# languages and the two agree again. Those are refused all the same, so the accepted range is
# one window rather than two with a hole from 1e-9 to 1e-4 in the middle of it. A harness
# carrying numbers that small scales them once, into a unit the wire carries, rather than
# discovering that 1e-10 is written and 1e-8 is not. The window needs no upper end: every
# double at or above ``2 ** 52`` is an integer, so a non-integral number never reaches the
# magnitude where Python's ``repr`` switches to an exponent.
_MIN_PLAIN_DECIMAL = 1e-4

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
# reader cannot mistake a fabricated ID or an epoch timestamp for a measured one. The name is
# reserved, and the emitter's claim on it runs one way: it writes ``True`` here whenever a gap
# degraded the event, overwriting a caller value of the same name, and it writes nothing at all
# when no gap occurred, so a caller that put this key in its own metadata keeps what it put
# there on an undegraded event. The emitter can only ever strengthen the claim the key makes,
# never weaken one, which is the half that matters: no event says "no gap" over a gap.
_GAP_KEY = "observer_capture_gap"

# The timestamp an event carries when the clock could not be read. Spelled as a literal so the
# degraded path allocates nothing and calls nothing.
_EPOCH_TIMESTAMP = "1970-01-01T00:00:00.000Z"

_INTERRUPTS = (KeyboardInterrupt, SystemExit)
# What a write guard re-raises instead of containing: the caller's own interrupt, and the
# ``GeneratorExit`` the language raises inside a coroutine somebody closed. Neither is the
# write failing, and neither may be swallowed, so the guard re-raises both and accounts for
# the event on the way out rather than at the raise site.
_UNCONTAINED = (KeyboardInterrupt, SystemExit, GeneratorExit)
_MISSING = object()

# The UTF-16 surrogate range. A code point in it is half of a surrogate pair rather than a
# character, and no UTF-8 encoder will write one. Spelled as a pattern rather than a scan
# over ``ord`` so checking a long payload string stays a single C-level search: this runs
# over every string in every payload, and the copy it guards is already the hot path.
_SURROGATE = re.compile("[\ud800-\udfff]")

# ``CO_ITERABLE_COROUTINE``, the code flag :func:`types.coroutine` sets so ``await`` accepts a
# generator. Spelled as the literal the interpreter uses rather than imported from ``inspect``,
# so classifying a value costs no import and reads nothing off the caller's object beyond a
# generator's own code flags.
_CO_ITERABLE_COROUTINE = 0x100

JsonObject = dict[str, Any]
Redactor = Callable[[str, Any, "tuple[str, ...]"], Any]


class TraceSink(Protocol):
    """An object a harness owns that accepts one finished event. It may be sync or async.

    Exported for annotation, and structural: a harness's own sink satisfies it by having the
    method, never by inheriting from it, and nothing at runtime checks against this class. It
    describes the object shape :class:`Observer` accepts, which is not the only one it accepts:
    a bare callable taking the event works too, and :meth:`Observer._normalize_sink` is where
    that choice is made.
    """

    def write(self, event: JsonObject) -> Any:
        ...


@dataclass(frozen=True)
class CaptureState:
    """What the emitter failed to record. It is a snapshot, so it never changes underfoot.

    ``dropped_events`` counts events no sink acknowledged taking, not scanner findings and not
    instrumentation failures in general: a clock, ID, or elapsed-time read that failed sets
    ``capture_gap`` and marks the event it degraded, but the sink still took that event, so it
    is not counted here. ``capture_gap`` is therefore the broader flag, and it can be true while
    the counter is zero.

    Acknowledgement is the exact word, and it is the only thing the emitter can observe. A sink
    is caller code the emitter never looks inside: it learns that an event arrived when a
    synchronous write returns or an asynchronous one completes, and it learns nothing at all
    from a write that was cut short. A write cancelled while the sink's own coroutine was
    suspended is the case where that matters, because the sink may well have stored the event
    before it suspended, and this counter charges it anyway. That is deliberate and it is the
    safe direction: the count is an upper bound on what the trace is missing, so zero still
    means nothing was lost, while a counter that guessed "delivered" from a cancellation would
    report a complete trace for a write that really did reach nobody. Read a nonzero count as
    "this many events the sink never acknowledged", not as proof that exactly that many lines
    are missing from the file.

    ``last_sink_error`` is one opaque constant, ``"observer instrumentation failure"``, for
    every failure the emitter contains. It reports that capture broke, never which call broke
    or why: a sink's exception text can quote the payload it failed to write, and an emitter
    that repeated it would put that payload into the state a harness prints. Read the marked
    events, not this field, to see where capture degraded.

    A write started inside a caller's event loop and not yet finished is neither counted nor
    reported here: it is not lost, and awaiting :meth:`Observer.aflush` is what settles it into
    either a delivered event or a counted loss. A write whose loop is torn down before it runs
    and a write cancelled before it ever starts are both counted, because those events reached
    nobody. The three fields are the ones the TypeScript emitter's capture state carries, so a
    reader joins the two by name. Zero dropped events is not a claim that the harness emitted
    everything it should have: it only says nothing the harness did emit was lost here.
    """

    dropped_events: int = 0
    capture_gap: bool = False
    last_sink_error: str | None = None


@dataclass(frozen=True)
class JsonlSink:
    """Adapts a caller-owned line writer. The SDK never opens or closes a file itself.

    ``write_line`` receives one serialized event with a trailing newline and may be either a
    plain callable or a coroutine function. A generator function, or a callable object whose
    ``__call__`` is one, is refused here rather than accepted: calling one returns an iterator
    nobody drives, so the line is never written, the sink reports no failure, and every event
    is lost with a capture state that still reads clean. That is the classification
    :meth:`Observer._normalize_sink` already applies to a sink, applied one layer down to the
    writer a sink is built from, so the same wiring mistake is refused at creation in both
    places rather than losing every line at runtime in one of them. A writer that returns a
    generator instead of being one cannot be classified from the outside and is not refused
    here; :meth:`Observer._write` sees the iterator this ``write`` hands back and counts the
    event as lost. Where those lines go, when they are fsynced, and whether they are ever
    deleted are the caller's decisions, not this class's.
    """

    write_line: Callable[[str], Any]

    def __post_init__(self) -> None:
        if _is_generator_callable(self.write_line):
            raise ValueError(
                "jsonl write_line must not be a generator function: calling one returns an "
                "iterator and writes nothing"
            )

    def write(self, event: JsonObject) -> Any:
        return self.write_line(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")


def create_jsonl_sink(write_line: Callable[[str], Any]) -> JsonlSink:
    """Wrap a caller-owned line writer as a sink. Opens nothing and captures no global stream.

    A generator-function writer raises here, at wiring time, exactly as one handed to the
    :class:`Observer` constructor does, because a writer that returns an iterator writes
    nothing and would cost every line in silence. The TypeScript ``createJsonlSink`` refuses
    the same writer for the same reason. A writer that is an ordinary function returning an
    undriven generator is the same silence wearing a shape no wiring check can see, so it is
    not refused here and is counted, event by event, by the observer that writes through it.
    """
    return JsonlSink(write_line)


def _is_awaitable(value: Any) -> bool:
    """True for coroutines, futures, tasks, and iterable coroutines, as ``await`` decides it.

    The test is for ``__await__`` on the type, never on the instance. ``await`` resolves that
    name as a type slot, so an instance attribute named ``__await__`` is not awaitable however
    it looks, and reading the name off the instance would both answer differently than the
    language does and run caller code: a property or a ``__getattr__`` on an operation's return
    value is the caller's code, and instrumentation must not run it merely to classify the
    value.

    A generator marked by :func:`types.coroutine` is the one shape ``await`` accepts with no
    ``__await__`` slot at all, so it is matched on the flag the interpreter itself reads.
    Missing it meant :meth:`Observer.observe_async` handed such an awaitable straight back,
    unrun, where the caller's own ``await`` would have run it: instrumentation decided whether
    the caller's work happened, which is the one thing it may never do. The flag is read only
    once the value is exactly a generator, a type that cannot be subclassed and whose
    ``gi_code`` is an interpreter-level slot, so this still runs none of the caller's code.
    Deliberately false for async generators, which define ``__aiter__`` instead.
    """
    if type(value) is GeneratorType:
        return bool(value.gi_code.co_flags & _CO_ITERABLE_COROUTINE)
    return any("__await__" in base.__dict__ for base in type(value).__mro__)


def _running_loop() -> Any:
    """Return the event loop running in this thread, or None. Never starts one."""
    import asyncio

    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _wire_number(value: int | float) -> int | float:
    """Return the one spelling of a payload number both emitters write, or refuse it.

    A number is stored only when Python and JavaScript write it as the same bytes. This is the
    single place that decides that, for every number in every payload, because a trace one
    language can write and the other cannot read is worse than a missing event: it looks
    complete.

    An integral value, a Python ``int`` or a ``float`` with nothing after the point, must be a
    safe integer. Past ``2 ** 53 - 1`` a JSON number stops distinguishing neighbouring integers,
    so Python could hold a count a JavaScript reader would round to a different one. That is the
    bound ``duration_ms`` already carries, applied to the numbers a caller puts in a payload.
    The value is stored as an ``int`` because JavaScript has one number type and writes ``5``
    where :func:`json.dumps` writes ``5.0`` for the same number; ``duration_ms`` is normalized
    the same way for the same reason. It is also why ``-0.0`` is stored as ``0``, which is what
    JavaScript writes for it.

    A non-integral value must be at least :data:`_MIN_PLAIN_DECIMAL` in magnitude, the plain
    decimal window the two languages share. Below it they switch to exponent notation at
    different magnitudes and spell an exponent differently, so one payload would leave the two
    emitters as different bytes. Below 1e-9 they agree again, and those are refused all the
    same: the accepted range is one window, not two with a hole between them, and the constant
    says why.

    Refusing is a capture gap, never a rounded or reshaped value: a silently altered number
    would misdescribe the run it claims to observe.
    """
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TypeError("non-finite JSON number")
        if not value.is_integer():
            if abs(value) < _MIN_PLAIN_DECIMAL:
                raise TypeError("JSON number below the shared plain-decimal window")
            return value
        # An integral float is the integer it equals, converted here so the bound below is the
        # one safe-integer check a payload number meets, rather than one per spelling of it.
        value = int(value)
    if abs(value) > _MAX_SAFE_INTEGER:
        raise TypeError("JSON number outside the shared safe-integer range")
    return value


def _copy_json(value: Any, seen: set[int] | None = None, depth: int = 1) -> Any:
    """Deep copy into plain JSON types, refusing anything that would not survive the wire.

    Non-finite floats, numbers outside the range both languages write alike, cyclic structures,
    non-string object keys, a string or a key carrying an unpaired surrogate, objects that are
    not dicts, lists, tuples, or JSON scalars, and containers nested deeper than
    :data:`MAX_PAYLOAD_DEPTH` raise :class:`TypeError`. ``depth`` counts containers, and the
    payload object a caller passed is the first, so the limit is a property of the payload
    rather than of this call.
    This is a copy, not a coercion: nothing is stringified or truncated to make it fit, because
    a silently reshaped payload would misdescribe the run it claims to observe. The one thing it
    does normalize is the spelling of an integral number, in :func:`_wire_number`, which chooses
    between two spellings of one value rather than changing the value.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if not _is_encodable(value):
            # Refused rather than escaped or replaced: a sink cannot encode it, and the two
            # emitters would otherwise write different bytes for the same payload.
            raise TypeError("JSON string carries an unpaired surrogate")
        return value
    if isinstance(value, (int, float)):
        # One branch for both spellings: which of the two a caller used is not a property of
        # the number, and the wire carries the number.
        return _wire_number(value)
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
            if not _is_encodable(key):
                raise TypeError("JSON object key carries an unpaired surrogate")
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

    Every field is spelled here, at a fixed width, rather than through ``strftime``. A timestamp
    is a wire value, so its bytes must be a property of this contract and of nothing else, and
    ``strftime`` delegates ``%Y`` to the platform C library: a year below 1000 is padded to four
    digits by one libc and written bare by another, so the same clock reading would leave two
    machines as ``0999-...`` and ``999-...``. The second spells no RFC 3339 timestamp at all,
    fails the schema's ``date-time`` format, and no longer matches the four digits JavaScript's
    ``toISOString`` writes for the same instant, which is the byte equality the two emitters
    claim. The year is the only field ``strftime`` treats that way, and formatting all of them
    alike is what keeps a second, platform-shaped spelling from reappearing beside this one.

    The formatted string passes :func:`_is_id` before it is returned, because a ``datetime``
    subclass owns its own ``year`` and ``microsecond`` and this is a caller string reaching the
    wire like any other: it is held to the one rule all of them are held to rather than trusted
    for having come from a clock. A reading this refuses costs the timestamp and a capture gap,
    never the event, exactly as a naive one does.
    """
    _require_aware(moment)
    utc = moment.astimezone(timezone.utc)
    text = (
        f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}"
        f"T{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}"
        f".{utc.microsecond // 1000:03d}Z"
    )
    if not _is_id(text):
        raise TypeError("clock produced a timestamp no UTF-8 sink could write")
    return text


def _require_aware(moment: Any) -> datetime:
    """Return the moment only if it is a timezone-aware datetime, else raise."""
    if not isinstance(moment, datetime):
        raise TypeError("clock did not return a datetime")
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise TypeError("clock returned a naive datetime")
    return moment


def _is_encodable(text: str) -> bool:
    """True when every code point in ``text`` is a character a UTF-8 sink can write.

    Python stores code points, so any surrogate in a ``str`` is an unpaired one: there is no
    pair to join it to, ``"\\ud83d\\ude00"`` is two surrogates and not an emoji, and encoding
    either of them raises. Such a string survives :func:`json.dumps` unchanged and fails only
    at the sink, where a real JSONL file cannot encode the line and the event is lost at write
    time; JavaScript escapes the same code unit instead, so one payload would leave the two
    emitters as different bytes. Both refuse it, and refusing it is the stricter shared rule:
    the emitter never hands a sink a line UTF-8 cannot carry.

    An astral character is one code point outside this range and is accepted. JavaScript
    spells the same character as a surrogate pair of code units and accepts that pair, so a
    payload either language can write is a payload both languages write identically.
    """
    return _SURROGATE.search(text) is None


def _is_payload_object(value: Any) -> bool:
    """The one test for a payload the emitter can store, asked by every path that decides.

    A ``metadata`` or ``content`` a caller hands over is any :class:`~collections.abc.Mapping`,
    because :meth:`Observer._snapshot` reads it once into a ``dict`` before anything is copied.
    Everything below that top level must be a ``dict``, a list or a tuple, which
    :func:`_copy_json` decides.

    It is one function because the gate and the copy must not be able to disagree about what a
    payload is: the TypeScript emitter gated ``content`` on "any non-array object" while its copy
    applied a stricter rule, so a payload was acceptable in ``metadata`` mode and refused in
    ``content`` mode. The recording mode decides whether content is stored, never what a caller
    may hand over. :meth:`Observer._valid_input` and :meth:`Observer._snapshot` both ask here,
    and the TypeScript ``isJsonObject`` is the same question in the other language.
    """
    return isinstance(value, Mapping)


def _is_id(value: Any) -> bool:
    """A usable wire string: a nonempty string of characters a UTF-8 sink can write.

    The surrogate rule a payload string is held to is the rule every caller string on the wire
    is held to, because a lone surrogate in a link ID, a run ID, a producer ID, an ID a factory
    produced, or a timestamp a caller's clock spelled costs the same line the same way.
    Checking it here covers all of them: the constructor, the ID factory, the link fields the
    wire contract validates, and :func:`_iso_timestamp` all decide "may this string go on the
    wire" here, so no path can carry a second, weaker spelling of the rule. The TypeScript
    ``validId`` decides the same set.
    """
    return isinstance(value, str) and value != "" and _is_encodable(value)


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


def _is_undriven_generator(value: Any) -> bool:
    """True for a generator a write handed back instead of writing, which nobody will drive.

    The wiring guards classify a callable, so they see a writer or sink that *is* a generator
    function. One that merely *returns* a generator is the same wiring mistake one layer in and
    is invisible to them: calling such a function runs none of its body, the sink reports no
    failure, and every event is lost behind a capture state that still reads clean. That shape
    is caught here instead, at write time, on the value the sink returned.

    The type is compared exactly, as :func:`_is_awaitable` compares it, so this reads none of
    the caller's own code: neither generator type can be subclassed, and asking an object what
    it is would run a property the caller wrote. A generator :func:`types.coroutine` marked is
    awaitable and is driven, so it never reaches this test.
    """
    return type(value) is GeneratorType or type(value) is AsyncGeneratorType


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


class _Delivery:
    """The outcome of exactly one write, and the only place a write's loss is counted.

    A write ends in more ways than any one code path sees. The sink can return, hand back an
    iterator nobody drives, raise, or raise the caller's own interrupt; a queued write can be
    cancelled before its first step or after it, torn down with the loop it was queued on,
    closed by the emitter while it is suspended, or settled by a flush a cancellation cut
    short. Every one of those exits used to count its own loss, and each round of review found
    a new exit that counted none or counted one twice. The counting lives here now:
    :meth:`settle` holds the one statement that charges a write to ``dropped_events``, and
    every exit from a write calls it.

    The record takes each of its two transitions once. :meth:`confirm` is called on the single
    path where the sink accepted the event. :meth:`settle` ends the write: it counts one lost
    event unless the write was confirmed, and does nothing at all the second time it is called.
    That is what makes it safe for an exit to settle a write another exit may already have
    settled, so no path has to know what the others did. An event no sink acknowledged is
    counted once however many paths notice it, and an event the sink accepted is never counted
    at all, however the task that carried it was later marked. Acknowledgement, not arrival, is
    the line: a cancelled write that had already handed its event to a sink acknowledged
    nothing and is charged, which :class:`CaptureState` states as the promise it is.
    """

    __slots__ = ("_observer", "_confirmed", "_settled")

    def __init__(self, observer: "Observer") -> None:
        self._observer = observer
        self._confirmed = False
        self._settled = False

    def confirm(self) -> None:
        """The sink accepted this event. Called only where the write really came back."""
        self._confirmed = True

    def settle(self) -> None:
        """End this write, counting one lost event unless the sink accepted it."""
        if self._settled:
            return
        self._settled = True
        if not self._confirmed:
            self._observer._lost_event()


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
    runtime failure. That check is syntactic, so a sink that merely *returns* a generator passes
    it; that shape is caught at write time instead, where the returned iterator is visible, and
    each event it swallows is counted as a lost event. In ``off`` mode the sink is not inspected
    at all, because it is never used.

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
    ``monotonic`` explicitly. A duration that cannot be measured, because a read failed, a
    reading could not even be checked, the source went backwards, or the span exceeds the
    shared safe-integer bound, is omitted from the event and recorded as a capture gap rather
    than invented. A timing hook costs at most that duration and a capture gap, and every other
    failure a caller hook can produce, including a reading the emitter cannot even check, costs
    at most a capture gap and the event it was building.

    :class:`KeyboardInterrupt` and :class:`SystemExit` are the single exception, and they are
    not the timing hook's alone. :meth:`observe` and :meth:`observe_async` emit the start event
    and take the first elapsed-time reading before the operation runs, so an interrupt raised by
    any caller code either one touches first travels out where it was raised and the operation
    never runs: the start Mapping, the redactor, the clock, the ID factory, the sink, and the
    elapsed-time source can each stop it. That is deliberate, because an interrupt is the
    caller's own and instrumentation may not swallow one, and it is the only way any of those
    hooks can reach the operation at all. The event such an interrupt stopped is counted as a
    lost event on the way out, so a run cut short still says what it failed to record.

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
        # Each outstanding write, mapped to the record that owns its accounting. The map
        # says only which writes are still outstanding; whether a write has been counted is
        # the record's to say, so the two cannot disagree about the same write.
        self._pending: dict[Any, _Delivery] = {}
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

    def emit(self, /, *positional: Any, **fields: Any) -> JsonObject | None:
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

        How the call is spelled cannot raise into the harness either, which is why the receiver
        is positional only and stray positional arguments are swallowed rather than bound.
        Python binds arguments before the first statement of a method runs, so a field named
        ``self`` was a :class:`TypeError` raised by the call itself, before any guard existed to
        contain it: the one field name the contract happens to share with the receiver cost the
        harness an exception and the capture state nothing, and the same event named anything
        else was a counted refusal. It is an unknown field name now, exactly like ``metdata``,
        refused and counted once. A positional argument is the other half of that mistake and
        reaches the same refusal by the same path, because the tuple that collects it is not a
        Mapping.
        """
        try:
            return self._emit_fields(positional or fields)
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
        decides it, which includes a generator :func:`types.coroutine` marked: that awaitable
        is run here exactly as the caller's own ``await`` would have run it, because an
        operation the observer quietly left unexecuted would be a behavior change and not
        instrumentation. Classifying the result runs none of the caller's own code, so in
        ``off`` mode this is as much a pass-through as the synchronous :meth:`observe`, which
        reads nothing off the value at all. An async generator is not awaitable: it is returned
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
        report a loss that never happened; a write that failed settled its own record when it
        ended, and a write whose loop was torn down before it ran is settled here. An
        asynchronous harness must await :meth:`aflush`.
        """
        self._reap_lost_writes()
        self._close_runner()

    async def aflush(self) -> None:
        """Coroutine that waits for writes :meth:`emit` started and did not await.

        Only writes belonging to the loop this runs on are awaited. A write queued on a
        different loop is left pending rather than gathered: awaiting a future from another
        loop raises, and an emitter that let that raise would turn a harness's flush into an
        instrumentation error and, by clearing the pending map first, destroy the record of the
        very writes it failed to settle. Those writes are still the other loop's to run, and
        they are counted as lost only once that loop is gone.

        The pending map is read again on every turn, so a write another task starts while this
        flush is suspended on its gather is gathered by the next turn rather than left for
        nobody to await. A flush that returned with a write outstanding would tell a harness
        capture had settled while an event was still on its way to the sink, which is what the
        TypeScript ``flush`` did until both were made to drain rather than to await a snapshot.

        Every write in a batch is settled once the gather returns, without asking how it
        ended: a write the sink accepted confirmed its record before it finished, so settling
        it costs nothing, and a write cancelled before its first step ran no guard of its own
        and is out of the pending map :meth:`_reap_lost_writes` reads, so this is the only
        place left that can count it. That holds however the gather ends. When a cancellation
        that settled those writes travels on out of this await, the gather returns nothing at
        all and the batch in hand is the last record of them, so :meth:`_reap_batch` settles
        them before the cancellation is re-raised.

        A sink that never returns makes this wait forever. That is deliberate: the emitter
        imposes no timeout, because cancelling a harness's write is a policy decision only the
        caller can make. Apply your own timeout around this call and report the result as
        incomplete capture: a :class:`asyncio.CancelledError` delivered to the task awaiting
        this coroutine, by a timeout or by anything else, is re-raised unchanged, because it is
        aimed at the caller and swallowing it would defeat the one mitigation this docstring
        prescribes. ``gather`` here collects a cancelled write into its results rather than
        raising it, so a cancellation that does come out of that await is the caller's, never a
        write's. Whatever the cancellation settles, the writes it left unsettled go back into
        the pending map and the writes it did settle are settled here, before it is re-raised,
        so neither the record of them nor their loss dies with it.
        """
        import asyncio

        loop = _running_loop()
        while True:
            self._reap_lost_writes()
            batch = tuple(
                (write, delivery)
                for write, delivery in self._pending.items()
                if self._settles_on(write, loop)
            )
            if not batch:
                # Nothing outstanding on this loop, including anything a write started while
                # this flush was already waiting: the loop above re-reads the pending map
                # rather than a snapshot of it, so a write that began during a gather is
                # gathered by the next turn instead of being left for nobody to await.
                return
            for write, _ in batch:
                self._pending.pop(write, None)
            try:
                await asyncio.gather(*(write for write, _ in batch), return_exceptions=True)
            except BaseException as error:
                # Evidence first, before anything is re-raised: an unsettled write goes back
                # into the pending map so the failure cannot erase the record of what it failed
                # to settle, and a write this failure did settle is settled here, because this
                # batch is out of the pending map and nothing else will ever see it again.
                self._reap_batch(batch)
                if isinstance(error, (*_INTERRUPTS, asyncio.CancelledError)):
                    # The caller's own cancellation, not a write's: ``return_exceptions=True``
                    # hands a cancelled write back as a result, so nothing but a cancellation
                    # of this await reaches here. Containing it would swallow the timeout a
                    # caller wrapped around this call, which is the mitigation this coroutine
                    # documents for a sink that never returns.
                    raise
                self._mark_gap()
                return
            for _, delivery in batch:
                # The gather returned, so every write in the batch is finished. Settling each
                # record charges the ones that reached no sink and passes over the ones the
                # sink accepted, so this needs to ask nothing about how any of them ended.
                delivery.settle()

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

        A cancellation delivered to the caller while the flush waits travels on out of here, as
        it does out of :meth:`aflush`, so a timeout wrapped around this call reports as a
        timeout. The observer is still closed and the private loop still released on the way
        out, because a caller who cancelled a close asked for the close: leaving it open would
        let a late event postdate the run in silence. The flush accounts for the writes that
        cancellation settled before letting it through, so a close a timeout cut short still
        reports the events it cost rather than a clean state.
        """
        try:
            await self.aflush()
        finally:
            self._closed = True
            self._close_runner()

    def _reap_lost_writes(self) -> None:
        """Settle writes that can never run, and forget writes that already finished.

        A queued write is not lost while its loop can still run it, so a live one is left
        pending and unsettled. Once that loop is closed the write can never run: the event
        reached no sink, nobody else will ever see it, and a capture state that still read
        clean would be claiming a delivery that never happened. A write cancelled before it
        started is the same loss, because :meth:`_await_write` never ran to record it. Neither
        case is asked about here: settling the record charges a write that reached no sink and
        passes over one the sink accepted, and settling a record another path already settled
        does nothing, so this and :meth:`_write_settled` can both reach the same write.
        """
        for write, delivery in tuple(self._pending.items()):
            try:
                finished = write.done()
                loop = write.get_loop()
                unusable = loop is None or loop.is_closed()
            except _INTERRUPTS:
                raise
            except BaseException:
                # A pending entry the emitter cannot even inspect is not a write it can claim
                # was delivered.
                self._pending.pop(write, None)
                delivery.settle()
                continue
            if finished or unusable:
                self._pending.pop(write, None)
                delivery.settle()

    def _reap_batch(self, batch: tuple[tuple[Any, _Delivery], ...]) -> None:
        """Account for a gathered batch a failure cut short: keep the unfinished, settle the rest.

        A write that has not finished goes back into the pending map, because it is not lost
        and only its loop can settle it. A write the failure did finish is settled here,
        because :meth:`aflush` took this batch out of the pending map before awaiting it:
        :meth:`_reap_lost_writes` can no longer see it, and a cancellation delivered before the
        write's first step ran no guard inside it either. Settling it here is safe whatever it
        did, because a write the sink accepted confirmed its record and a record settled twice
        counts once; settling it nowhere left an event that reached no sink behind a capture
        state reading zero dropped events and no gap.
        """
        for write, delivery in batch:
            try:
                finished = write.done()
            except _INTERRUPTS:
                raise
            except BaseException:
                # A write the emitter cannot even inspect is not one it can claim was delivered.
                delivery.settle()
                continue
            if finished:
                delivery.settle()
            else:
                self._pending[write] = delivery

    def _write_settled(self, task: Any, awaitable: Any, delivery: _Delivery) -> None:
        """Settle the record of one queued write that has finished, however it finished.

        A write cancelled before :meth:`_await_write` could run records nothing itself: the
        wrapper coroutine is closed at its first line, so no guard inside it ever runs, and
        simply forgetting the task here, as this callback once did, left an event that reached
        no sink behind a capture state reading zero dropped events and no gap. Settling the
        record covers that without asking how the task ended, which is what the asking got
        wrong twice: a task whose sink accepted the event and then cancelled the task around it
        was counted as a loss that never happened, and a task that raised inside the guard and
        was then marked cancelled was counted twice. A confirmed record settles for nothing and
        a record settled elsewhere settles for nothing, so this callback can be unconditional.

        A cancelled task leaves the write the wrapper never awaited un-awaited, and an
        un-awaited coroutine becomes a ``RuntimeWarning`` in the caller's process at collection
        time, so it is closed here; closing a finished or already closed awaitable does nothing.
        A task that ended in an exception has that exception read off it for the same reason:
        asyncio logs one nobody retrieved, and the event it cost is already in the capture
        state. Instrumentation that failed must not also print into a harness's output.
        """
        try:
            cancelled = task.cancelled()
        except _INTERRUPTS:
            raise
        except BaseException:
            # A task the emitter cannot even ask about is not one it can claim was delivered.
            cancelled = True
        if cancelled:
            self._discard(awaitable)
        else:
            self._retrieve(task)
        self._pending.pop(task, None)
        delivery.settle()

    @staticmethod
    def _silence(task: Any) -> None:
        """Stop asyncio reporting one of the emitter's own writes into the harness's output.

        The general rule is the one the whole emitter is built on: instrumentation never alters
        the caller, and a line printed into a harness's log is an alteration like any other.
        :meth:`_retrieve` and :meth:`_discard` keep two of the three ways asyncio speaks up
        about an abandoned write, an unretrieved exception and an un-awaited coroutine, out of
        that output. This keeps the third. A caller's loop can be closed with a write still
        queued on it; the task is then destroyed while pending, and asyncio's exception handler
        logs ``Task was destroyed but it is pending!``, naming the emitter's internals in a
        harness's output for an event the harness never asked about. The flag cleared here is
        the one asyncio's own ``gather`` clears on the tasks it takes responsibility for, which
        is exactly the relationship this emitter has to its writes.

        Nothing is hidden by it. That write reached no sink, and the loss is reported where
        every other loss is reported, as a ``dropped_events`` count and a capture gap in
        :class:`CaptureState`, which is the one channel instrumentation may use. The silencing
        is done here, at the single statement that ever creates a task, rather than where a
        stranded write is later noticed, because a write the emitter never gets to reap, one
        outstanding when a harness simply drops the observer, is destroyed pending just the
        same. A task object with no such flag, which is not asyncio's, is left alone.
        """
        try:
            task._log_destroy_pending = False
        except _INTERRUPTS:
            raise
        except BaseException:
            pass

    @staticmethod
    def _retrieve(task: Any) -> None:
        """Read a finished write's exception, so asyncio logs no unretrieved one at collection."""
        try:
            task.exception()
        except _INTERRUPTS:
            raise
        except BaseException:
            pass

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
        of :meth:`observe` into the operation's own result or exception. The elapsed-time read
        is guarded separately because it is the one step whose failure stops the completion
        event from being built at all: an interrupt from that hook is the caller's and travels
        on, but the event it stopped reached no sink, so the loss is counted before it does.
        Past that read, :meth:`_emit_built` owns the builder call and counts its own losses, so
        this guard re-raises an interrupt without counting it a second time.
        """
        try:
            elapsed = self._elapsed_ms(began)
        except BaseException as failure:
            self._gaps += 1
            self._dropped_events += 1
            self._capture_gap = True
            self._last_sink_error = _GAP_MESSAGE
            if isinstance(failure, _INTERRUPTS):
                raise
            return None
        try:
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
            # Marked inline: a RecursionError leaves no room to call another method, and this
            # handler must record the loss even when the interpreter is out of stack. An
            # interrupt is recorded here too and then travels on. It is the caller's own and is
            # never contained, but the event it stopped, from a redactor, a caller's Mapping,
            # the clock or the ID factory, reached no sink all the same, and leaving it uncounted
            # said the run ended having recorded everything it was handed. This is the guard that
            # owns those calls, so it is the one that counts them, once: the guards outside it
            # re-raise an interrupt without counting it again.
            self._gaps += 1
            self._dropped_events += 1
            self._capture_gap = True
            self._last_sink_error = _GAP_MESSAGE
            if isinstance(error, _INTERRUPTS):
                raise
            return None
        return event

    def _snapshot(self, fields: Any) -> JsonObject:
        """Read the caller's mapping once, so validation and building see the same payload.

        A caller's Mapping is caller code: reading it twice lets it answer differently the
        second time and put a value in the event that no check ever saw. Metadata, and content
        when it will be stored, are deep copied here for the same reason.

        What counts as a payload worth copying is :func:`_is_payload_object`, the same test
        :meth:`_valid_input` applies, so a payload this declines to copy is one the gate refuses
        rather than one that slips through unstored.
        """
        if not isinstance(fields, Mapping):
            raise TypeError("trace event input must be a mapping")
        snapshot = dict(fields)
        if _is_payload_object(snapshot.get("metadata")):
            snapshot["metadata"] = _copy_json(dict(snapshot["metadata"]))
        if self._mode == "content" and _is_payload_object(snapshot.get("content")):
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

        ``metadata`` and ``content`` are held to :func:`_is_payload_object`, the one test the
        copy asks as well, and ``content`` is held to it in every recording mode: the mode
        decides whether content is stored, never what shape a caller may hand over. A link ID is
        held to :func:`_is_id`, the one test every caller string on the wire passes.
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
        if not _is_payload_object(fields.get("metadata")):
            return False
        if "content" in fields and not _is_payload_object(fields["content"]):
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
        """Hand one event to the sink, and settle exactly one delivery record for it.

        Every way out of this method passes through the ``finally``: a recording mode with no
        sink at all, the sink returning, the sink raising, the sink handing back an iterator
        nobody drives, and the caller's own interrupt on its way through. The record counts one
        lost event unless something confirmed that the sink accepted this one, so an exit added
        here later can neither forget the count nor repeat it.

        A write handed to a task on a caller's loop is the one case the ``finally`` leaves alone,
        because it is not over yet: :meth:`_drive` reports that the write is still outstanding,
        and the task's done callback, a flush, or the reaper settles the same record when it
        ends. A write driven on the private loop is over by the time :meth:`_drive` returns and
        has already settled its own record, so the ``finally`` finds nothing left to count.
        """
        delivery = _Delivery(self)
        outstanding = False
        try:
            if self._sink is None:
                # A recording mode with no sink. The event was built, spent a sequence number
                # and an ID, and reached nobody, so its record settles as a lost event.
                return
            result = self._sink(event)
            if _is_awaitable(result):
                outstanding = self._drive(result, delivery)
            elif _is_undriven_generator(result):
                # The sink returned an iterator rather than writing. Its body never ran, so the
                # event reached nobody: the value written was never consumed, and an emitter
                # that reported a clean state here would claim a delivery that never happened.
                # The emitter does not drive it, because consuming a caller's stream is not
                # instrumentation's to do.
                return
            else:
                delivery.confirm()
        except BaseException as error:
            if isinstance(error, _INTERRUPTS):
                raise
        finally:
            if not outstanding:
                delivery.settle()

    def _drive(self, awaitable: Any, delivery: _Delivery) -> bool:
        """Finish an async write on this observer's own loop, or hand it to the caller's loop.

        True when the write is still outstanding: a task owns it now, and that task's done
        callback, a flush, or the reaper settles ``delivery`` when it ends. Every other return
        leaves the write over, settled either by the guard inside it or by :meth:`_write`, which
        is why no branch here counts a loss of its own.

        Both failure paths close the wrapper coroutine as well as the write it wraps. Closing a
        coroutine never touches what it would have awaited, so discarding only one of the two
        leaves the other un-awaited, and an un-awaited coroutine becomes a ``RuntimeWarning``
        in the caller's process at collection time. Instrumentation that failed must not also
        print into a harness's output. Closing the wrapper is also what settles a write the
        private loop refused to start at all: the close raises ``GeneratorExit`` inside a
        suspended wrapper, which settles the record on its way out, and a wrapper that never
        started closes without running, leaving the record for :meth:`_write` to settle.

        The task the caller's loop takes is silenced as it is created, for the same rule one
        step further on: see :meth:`_silence`.
        """
        loop = _running_loop()
        writer = self._await_write(awaitable, delivery)
        if loop is not None:
            try:
                task = loop.create_task(writer)
            except BaseException as error:
                self._discard(writer)
                self._discard(awaitable)
                if isinstance(error, _INTERRUPTS):
                    raise
                return False
            self._silence(task)
            self._pending[task] = delivery

            def settled(
                finished: Any, write: Any = awaitable, record: _Delivery = delivery
            ) -> None:
                self._write_settled(finished, write, record)

            task.add_done_callback(settled)
            return True
        runner = self._runner()
        if runner is None:
            self._discard(writer)
            self._discard(awaitable)
            return False
        try:
            runner.run_until_complete(writer)
        except BaseException as error:
            self._discard(writer)
            self._discard(awaitable)
            if isinstance(error, _INTERRUPTS):
                raise
        return False

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

    async def _await_write(self, awaitable: Any, delivery: _Delivery) -> None:
        """Await one write and settle its record, whichever way the await ends.

        The settlement sits in a ``finally``, so every exit this coroutine has crosses it: the
        sink returning, the sink raising anything at all, a cancellation aimed at the write, the
        caller's own :class:`KeyboardInterrupt` or :class:`SystemExit` travelling on unchanged,
        and the :class:`GeneratorExit` raised here when the emitter closes a write it can no
        longer run. That is the guarantee: the count is not at the raise sites, which is where
        each round of review found one missing, but on the single path out of the ``try`` that
        every raise site has to cross. Settling charges a lost event only when nothing confirmed
        delivery, so a write whose sink returned costs nothing and a write another path also
        settles is charged once.

        A cancelled write is a lost event, not an escape: a cancellation aimed at a write the
        observer started is contained here rather than travelling out of instrumentation into
        the harness. An interrupt and a ``GeneratorExit`` are re-raised instead, the first
        because it is the caller's own and the second because the language requires a closing
        coroutine to finish closing, and the ``finally`` has already accounted for the event
        either one cost.
        """
        try:
            await awaitable
        except BaseException as error:
            if isinstance(error, _UNCONTAINED):
                raise
        else:
            delivery.confirm()
        finally:
            delivery.settle()

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
        """One event no sink acknowledged taking, which is what :class:`CaptureState` counts.

        Reached once per lost event: for a write, only from :meth:`_Delivery.settle`, which
        takes that transition once; for an event that never got as far as a write, from the
        guard that owned the caller call it died in.
        """
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
        return self._checked_monotonic(value)

    def _checked_monotonic(self, value: Any) -> float | None:
        """Classify one reading, containing whatever checking it raises.

        Checking a reading is as much caller code as taking it: :func:`math.isfinite` and
        :class:`float` both run a subclass's ``__float__`` and both raise on an integer too
        large to convert to a float, and an unchecked raise here travelled out of
        :meth:`observe` before the operation ran, so a timing hook could abort the very work it
        was there to observe. Instrumentation may cost a duration and a capture gap; it may
        never cost the operation. Only a caller's own interrupt still travels out.
        """
        try:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                self._mark_gap()
                return None
            if not math.isfinite(value):
                self._mark_gap()
                return None
            return float(value)
        except BaseException as error:
            self._fail(error)
            return None

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
    """Await an awaitable, pass anything else back untouched. Never iterates a stream.

    What counts as awaitable is :func:`_is_awaitable`, which answers as ``await`` answers, so a
    value that merely looks awaitable from the outside is handed back rather than probed and a
    generator :func:`types.coroutine` marked is awaited rather than handed back unrun; nothing
    of the caller's runs here either way. A plain generator, an iterator, and an async
    generator are streams and are passed through, never consumed.
    """
    if _is_awaitable(value):
        return await value
    return value
