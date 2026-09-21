# Observer SDK

Two emitters, one wire contract. `scaneval.observer` (Python, `src/scaneval/observer/`) and `@scaneval/observer` (TypeScript, `sdk/typescript/`) are small, opt-in emitters for observing an existing harness.

Neither is an integration with SecureVibes, Fieldglass, or any other product. Neither makes model or provider calls, retrieves data, enforces policy, opens a file of its own, starts a thread, spawns a process, or monkeypatches a global client. One exception is named rather than glossed: a synchronous Python harness whose sink returns an awaitable makes the observer create a private event loop, which allocates the selector and wakeup descriptors any loop allocates. That loop is the only resource either emitter ever owns, it is never installed as the thread's current loop, and `flush` or `close` releases it. Importing either records nothing. A harness must explicitly emit at its real model-client, tool-dispatch, context-selection, and finding-lifecycle boundaries for anything to be recorded at all. An absent event is never evidence of absent activity.

The language-neutral event contract is [`schema/v2/trace-event.schema.json`](../schema/v2/trace-event.schema.json), and the byte-level example both emitters reproduce is [`schema/v2/fixtures/trace-event-v2.json`](../schema/v2/fixtures/trace-event-v2.json). Every event carries schema version `2.0`, run, producer and event IDs, a producer-local nonnegative `sequence`, a `timestamp`, a `type` and its `category`, a `capture_status`, and `metadata`. `candidate_id` is a stable lifecycle link; emitting validation or filtering is optional and must reflect actually observed stages rather than invented ones.

## Installation and import

**Python.** The emitter ships inside the `scaneval` distribution and has no dependencies of its own. Install the project (`python -m pip install -e .` from the repository root) and import the package directly:

```python
from scaneval.observer import CaptureState, MAX_PAYLOAD_DEPTH, Observer, create_jsonl_sink
```

`scaneval.observer` deliberately imports nothing from the evaluator: not the contracts, scoring, runner, execution, review, report, or adapter modules. A harness can depend on the emitter without acquiring the machinery that judges it, and a test pins that boundary.

**TypeScript.** `@scaneval/observer` is marked `private` in its `package.json` and is not published to a registry. Build it locally and consume it by path:

```sh
cd sdk/typescript
npm install
npm run build
```

The build output is conventional `dist/` JavaScript plus declarations (`dist/index.js`, `dist/index.d.ts`), and the package is ESM only (`"type": "module"`). Depend on it with a file specifier (`npm install file:../scaneval/sdk/typescript`) or import the build output directly:

```ts
import { MAX_PAYLOAD_DEPTH, Observer, createJsonlSink } from "@scaneval/observer";
```

The package has no runtime dependencies.

## The shared parity contract

These are rules of the contract, not implementation details of either emitter. Changing one changes both, the schema where it is expressible, and the parity matrix in `tests/test_v2_observer_parity.py`, in the same edit.

**1. One rejection set.** The two emitters accept and reject exactly the same inputs. Where they differ, the stricter rule becomes the shared one. An event is refused when it carries an unknown field name, an unknown `type`, a `category` that contradicts its `type`, an unknown `capture_status`, a missing `metadata` or one that is not a storable payload object, a `content` that is present and is not one, a `duration_ms` that is not a nonnegative whole safe integer, or a link ID (`parent_event_id`, `call_id`, `attempt_id`, `candidate_id`, `claim_id`) that is present but is not a nonempty string. A cyclic payload, a non-finite number in a payload, a number in a payload outside the range both languages write alike (rule 4), a non-string object key, a value that is not JSON, and a payload nested past the shared depth limit are refused the same way. A symbol-keyed property is JavaScript's spelling of that non-string key and is refused as one; so is a non-enumerable own property, which is a value the caller put in the payload and which the copy would otherwise leave out of the record with nothing on the event to say so. Refusing is the rule everywhere here: a payload the emitter cannot store whole is a visible capture gap, never a quietly shortened line. So is a string no UTF-8 sink could write: an unpaired surrogate in a payload value, in a payload key, or in a link, run or producer ID is refused as a capture gap in both languages. Python held such a code point and copied it into the line, where a real JSONL file failed to encode it and the event was lost at the sink, while JavaScript escaped it and wrote a line that parses, so one payload meant two things; refusing it is the stricter rule and it is enforced where every caller string enters the record. A surrogate pair spelling a real astral character is text, and both write it unescaped. Absence is spelled by omitting the field: a field present with the value `null` (Python `None`) is refused, never read as absent, because reading it as absent would record an event the harness did not describe. A storable payload object is a `Mapping` in Python and a plain object (an object literal, or one built on a null prototype) in JavaScript; a list, a `Map`, a `Date`, a boxed primitive and a class instance are none of those. Each emitter decides that in exactly one place, asked by the input gate and by the payload copy alike, so the two cannot drift apart: Python's `_is_payload_object` and TypeScript's `isJsonObject`. That shape rule applies to `content` in every recording mode, because what a caller may hand over is a property of the contract and not of the mode. What is *inside* a payload is the separate question, and it belongs to the copy: `content` is copied, and therefore its contents validated, only in `content` mode, so a payload whose contents only the copy would refuse is accepted in `metadata` mode by both emitters. Every caller string that reaches the wire, a link ID, a run or producer ID, an ID a factory produced, and the timestamp a caller's clock spelled, passes one validator per language for the same reason: Python's `_is_id` and TypeScript's `validId`.

**2. A refused event costs nothing.** It consumes no sequence number, no event ID, and no clock read in either language. That is only safe because the rejection sets are identical: if one emitter refused an input the other accepted, every later event in that producer's stream would carry a different sequence number, a different ID, and a different timestamp in the two languages. This is why rule 1 is a contract and not an implementation detail.

**3. `duration_ms` is a whole number of milliseconds, and a safe integer.** Non-integral, negative, non-finite, `null`, boolean, and anything above `2 ** 53 - 1` are refused in both languages. An integral float is stored as an integer so both write the same bytes. The bound is JavaScript's `Number.MAX_SAFE_INTEGER`: past it a JSON number no longer round-trips through a double, so a value Python could hold exactly would reach a reader as a different one. The schema says `"type": "integer"`, so an event that violated this would also fail schema validation.

**4. A payload number is stored only when both languages write it as the same bytes.** Two bounds, and both are applied in one place per emitter, on every number in every payload: Python's `_wire_number`, called from `_copy_json`, and TypeScript's `wireNumber`, called from `copyJson`. An integral number, a Python `int` or a `float` with nothing after the point, must be within `2 ** 53 - 1` in magnitude, the same safe-integer bound `duration_ms` carries by rule 3 and for the same reason: past it a JSON number stops distinguishing neighbouring integers, so Python could write a count a JavaScript reader would read as a different one. It is stored as an integer, because JavaScript has one number type and writes `5` where `json.dumps` writes `5.0`; that is also why `-0.0` is stored as `0`, which is what `JSON.stringify` writes for it. A non-integral number must be at least `1e-4` in magnitude, the plain decimal window the two languages share: below it Python's `repr` switches to exponent notation while JavaScript keeps plain decimals down to `1e-6`, and where both do use an exponent Python pads it to two digits (`1e-07`) and JavaScript does not (`1e-7`). The window needs no upper bound, because every double at or above `2 ** 52` is an integer and so is held to the integer rule instead. A number outside either bound is refused as a capture gap, never rounded or reshaped, because a silently altered number would misdescribe the run it claims to observe. Magnitudes below `1e-9` are the deliberate over-refusal in that: there both languages use an exponent of at least two digits and write the same bytes, and both emitters refuse them anyway, so the accepted range is one window rather than two with a hole from `1e-9` to `1e-4` in the middle of it. A harness carrying numbers that small scales them once, into a unit the wire carries, rather than discovering that `1e-10` is written and `1e-8` is not. The same bounds apply to a redactor's replacement, which is copied and checked like any other caller value.

**5. Elapsed time comes from a monotonic source, and is never invented.** The observe helpers measure with a monotonic source that is separate from the wall clock, read in seconds. If the span cannot be measured, because a read failed, the source returned something that is not a finite number, the source went backwards, or the span exceeds the safe-integer bound, then `duration_ms` is omitted, the completion event is still emitted, it is downgraded to `partial` unless it is already `unavailable`, `observer_capture_gap: true` is written into its metadata, and one capture gap is recorded. A duration the builder supplies anyway is dropped. An omitted duration says the span is unknown; a fabricated one would be read as a measurement.

**6. Whether a redactor changed a value follows JavaScript strict inequality.** An immutable scalar (string, number, boolean, `null`) compares by value; a container compares by identity. A redactor that hands back a structurally equal copy of an object or array therefore counts as having replaced it, and the event is marked `redacted` in both languages, while a redactor that returns an equal string or an equal number changes nothing in either. Python mirrors these semantics rather than asking `is`: CPython gives two equal strings, and two equal integers past the small-integer cache, separate identities, and an emitter that read that as a change would mark an event `redacted` where the TypeScript emitter marked it `complete`.

**7. The default redactor folds case over ASCII only.** Python spells it `re.IGNORECASE | re.ASCII`; JavaScript uses `/.../i` without the `u` flag. Both hide the same whole key names (`api_key`, `apikey`, `api-key`, `authorization`, `credential(s)`, `cookie(s)`, `password`, `secret(s)`, `token`, `private_key`, `private-key`, any case) and neither hides a key that merely contains one, such as `input_tokens`. A Unicode character whose ASCII uppercase looks like part of a credential name, for example U+212A KELVIN SIGN or U+017F LATIN SMALL LETTER LONG S, is left alone by both. Without `re.ASCII`, Python would hide a key spelling `token` with U+212A in place of its `k`, and one spelling `secret` with U+017F in place of its `s`, while JavaScript kept both, which the parity matrix carries a case for. The code points are named rather than pasted here, because the two glyphs are indistinguishable from the ASCII letters they imitate and this sentence spent a revision saying `toKen` with an ordinary `K`, which both languages hide and always did. `test_the_redactor_key_names_the_guide_lists_are_the_ones_it_hides` reads the key list above and these two code points out of this paragraph and asks `default_redactor` about each of them.

**8. Payload nesting stops at `MAX_PAYLOAD_DEPTH`, which is 32.** The limit is counted in containers entered, and the `metadata` or `content` object a caller passes is the first of them, so that object plus 31 further levels is stored whole and one container deeper is refused as a capture gap. Objects and arrays count the same. A too-deep payload is refused, never truncated, because a silently reshaped payload would misdescribe the run it claims to observe, and it is refused at the same container in both languages so neither accepts what the other refuses. A redactor's replacement is held to the same budget at the depth it sits at, so a replacement cannot smuggle deeper nesting past the limit. The number is exported from both packages (`MAX_PAYLOAD_DEPTH`) so a harness can check its own payloads against it; raising it is a contract change in both languages at once.

**9. An event built while instrumentation failed says so, in itself.** When a clock read, an ID read, or an elapsed-time read fails while an event is being built, that event carries a fabricated timestamp, a fabricated ID, or no duration. Both emitters then downgrade its `capture_status` to `partial`, unless it is already `unavailable`, and set `observer_capture_gap: true` in its metadata. The name is reserved, and the emitter's claim on it runs one way. `true` is written there whenever a gap degraded the event, overwriting a caller value of the same name; nothing at all is written when no gap occurred, so a caller that puts this key in its own metadata keeps what it put there on an undegraded event. Neither emitter ever writes `false`. The claim can therefore only be strengthened by the emitter and never weakened by it, which is the half a reader depends on: no event says "no gap" over a gap. A reader can tell a measurement from a fallback without consulting the capture state, and should read the key as "instrumentation failed while this event was built, or the harness said so itself".

**10. Emitted key order is the schema's declaration order.** `schema_version`, `event_id`, `run_id`, `producer_id`, `sequence`, `type`, `category`, `capture_status`, `timestamp`, then the link fields in the order the schema lists them, then `duration_ms`, `metadata`, and `content`. That list is read out of this sentence and compared with a real event's keys and with the schema's declaration order by `test_the_key_order_the_guide_spells_is_the_order_an_event_carries`.

Byte equality is the stronger claim, and it holds under stated conditions rather than unconditionally. Two emitters produce byte identical JSONL lines, key order included, when: both were handed the same event input and the same injected clock, ID factory, run and producer IDs, redactor and monotonic source; the line was written through the JSONL sink the package ships (`create_jsonl_sink` / `createJsonlSink`, which is where `ensure_ascii=False` and the compact separators live) rather than a caller's own serializer; the event was one both emitters accepted; and the payload carries no key JavaScript orders as an array index. Each condition is load bearing. A caller's sink serializes however the caller wrote it. A generated ID and a real elapsed measurement are each language's own, which is why the parity matrix injects both and compares the one unscripted duration as a shape. And `duration_ms` and `timestamp` are millisecond resolution in both, so a finer source loses its fraction before either emitter sees it.

The array-index key is the one shape both emitters accept and do not write alike: JavaScript orders an integer-like own property name such as `"2"` ahead of its siblings while Python keeps insertion order. It reorders more than the bytes, because that ordering is how JavaScript enumerates an object everywhere, the redactor walk included: the same payload is offered to the redactor key by key in a different order in the two languages. A redactor that answers only from the key, value and path it is handed stores the same values either way, so only the bytes differ; one that keeps state across calls, or that answers differently depending on what it was asked before, can store different values. It is listed under the known limits below and the parity matrix excludes it by name. Avoid such keys if byte-level joins matter, and do not write an order-dependent redactor.

Everything else that the two would otherwise spell differently is refused by both rather than written by one: a payload number outside the shared window (rule 4), a string no UTF-8 sink could write, in a payload value, a payload key, or any ID, and the timestamp a caller's clock spelled (rule 1), a payload nested past the shared limit (rule 8), a cyclic or non-JSON payload, and a `metadata` or `content` that is not a storable payload object. A refusal is a capture gap in both languages, which is the trade this rule makes: a missing event is visible, while a line that means one thing in Python and another in JavaScript is not.

**11. Instrumentation never alters the caller.** Every caller-supplied hook (clock, monotonic source, ID factory, redactor, event builder) and every sink write runs under the widest guard the language has. Python guards `BaseException` and re-raises only `KeyboardInterrupt` and `SystemExit`, because those are the caller's own interrupt rather than an instrumentation defect; an `asyncio.CancelledError` raised by a sink is a recorded gap, not an escape. The one addition is inside a queued write, where a `GeneratorExit` is re-raised as well, because the language requires a coroutine somebody is closing to finish closing; the event it cost is accounted for on the way out, exactly as an interrupt's is, and it reaches no caller of the emitter's API. An interrupt travels on unchanged, but the event it stopped is counted as a lost event before it does, so a run an operator cut short reports what it failed to record instead of a clean capture state. Python's `observe` and `observe_async` emit the start event and take the first elapsed-time reading before the operation runs, so an interrupt from the start Mapping, the redactor, the clock, the ID factory, the sink, or the elapsed-time source is the one thing instrumentation can do that stops the operation from running at all. TypeScript contains everything, including a thrown value that is not an `Error`. The observed operation's return value is passed back untouched and its error is re-raised as the original object, with the original traceback in Python.

**12. Every exit from a write counts exactly one lost event, or none.** A write no sink acknowledged taking is one lost event, counted once, whichever path noticed: the sink returning an iterator, the sink raising, a cancellation arriving before the write's first step or after it, a queued write torn down with its loop, a write the emitter closed while it was suspended, a flush a caller's timeout cut short, and the caller's own `KeyboardInterrupt` or `SystemExit` travelling on out of the write unchanged. A write the sink accepted is not counted at all, however the task carrying it was marked afterwards. Python enforces this with one record per write whose `settle` holds the only statement that charges a write to `dropped_events`, reached from a `finally` so a path that re-raises cannot skip it and taken only once so a path that settles late cannot repeat it; the exits therefore do not need to agree with each other about what the others did. TypeScript has no interrupts and no cancellation, so the rule needs no record there: every exit from its write crosses one `finally`, which is the same guarantee written in a language with fewer ways out.

**13. A flush covers the writes that begin during it.** The awaiting flush in each language, Python's `aflush` and TypeScript's `flush`, drains until nothing is outstanding rather than awaiting a snapshot taken when it was called, because a write started while the flush was already waiting belongs to that flush too. (Python's synchronous `flush` awaits nothing at all: each write it can settle was already driven to completion by `emit`.) Python's `aflush` re-reads its pending map on every turn; TypeScript's `flush` re-reads its pending set, and `close` drains and sets its closed flag in one loop, because in JavaScript a microtask can start a write between the last drain and the flag while in Python nothing runs between `aflush` returning and `_closed` being set. A flush that resolved with a write outstanding would tell a harness capture had settled while an event was still on its way to the sink.

**14. Capture state carries the same three fields.** `dropped_events`, `capture_gap`, and `last_sink_error`, with `last_sink_error` present and `null` (Python `None`) until something fails. It is one opaque constant, `"observer instrumentation failure"`, for every contained failure: it reports that capture broke, never which call broke or why, because a sink's exception text can quote the payload it failed to write. Read the marked events, not this field, to see where capture degraded. `capture_gap: true` and a nonzero `dropped_events` both mean the trace is incomplete. Zero is not a claim that the harness emitted everything it should have; it only says nothing the harness did emit was lost here. Both emitters count the same thing: an event no sink acknowledged taking. A degraded but delivered event is a capture gap without a drop.

Acknowledgement, not arrival, is the promise, and it is the only one either emitter can keep. A sink is caller code neither looks inside: an event counts as taken when a synchronous write returns or an asynchronous one completes, and a write cut short teaches the emitter nothing. Python's cancelled write is where that matters, because the sink may well have stored the event before it suspended, and a cancellation is delivered at whichever suspension point the sink happens to be at; the emitter cannot tell that write from one that stored nothing, so it charges both. The count is therefore an upper bound on what the trace is missing: zero still means nothing was lost, while a counter that guessed "delivered" from a cancellation would report a complete trace for a write that really did reach nobody. Read a nonzero count as "this many events the sink never acknowledged", not as proof that exactly that many lines are absent from the file. JavaScript has no cancellation, so there the only write cut short is one that threw or rejected, which is the sink refusing the event.

## Python API

Everything below is exported from `scaneval.observer`, and that sentence is checked rather than asserted: `tests/test_v2_observer.py::test_the_documented_python_api_is_the_package_export_list` reads the names out of the code blocks in this section and compares them with the package's `__all__` in both directions, and reads the member table below against a real `Observer`, the field list in its `emit` row against the emitter's own accepted-field set included. A name documented here and not exported, or exported and left undocumented, fails there. `TraceSink` was the first kind until it was exported. Every test this guide cites is looked up the same way, by `test_every_test_the_guide_names_still_exists`: a Python test by its function name, and a TypeScript one by the `observer.test.mjs::` prefix and its exact name in double quotes, looked up in `sdk/typescript/test/observer.test.mjs`. So a claim pinned to a renamed test cannot go on reading as a checked one. That lookup covered the Python names only until a review counted them: the four TypeScript names beside them were quoted prose that read exactly like citations, in the paragraphs describing the divergences most likely to be quoted.

```python
SCHEMA_VERSION      # "2.0"
MAX_PAYLOAD_DEPTH   # 32
RECORDING_MODES     # ("off", "metadata", "content")
EVENT_TYPES         # the ten wire event types, in schema order
EVENT_CATEGORIES    # ("model", "tool", "context", "finding", "observer")
CAPTURE_STATUSES    # ("complete", "partial", "redacted", "unavailable")
```

The comment beside each name is the value, not a gloss of it, and `tests/test_v2_observer.py::test_the_constants_the_guide_states_are_the_constants_both_emitters_use` compares each one with what the package exports. The same test reads the numbers this guide states in prose and compares them with the code that enforces them: `MAX_PAYLOAD_DEPTH` and the one-less count of further levels in rule 8, the safe-integer bound in rules 3 and 4, the plain-decimal floor and the over-refusal floor in rule 4, the count of event types and the position of `observer.error` among them, the count of capture-state fields in rule 14, and the two reserved strings, `observer_capture_gap` and `observer instrumentation failure`. It reads the TypeScript vocabulary out of the block below and out of `sdk/typescript/src/index.ts` as well, so one language cannot be renumbered alone. Every number stated here was unchecked until a review pointed out that a guide stating a limit is the place a reader goes to learn it.

```python
@dataclass(frozen=True)
class CaptureState:
    dropped_events: int = 0
    capture_gap: bool = False
    last_sink_error: str | None = None

@dataclass(frozen=True)
class JsonlSink:
    write_line: Callable[[str], Any]
    def write(self, event: dict[str, Any]) -> Any: ...

def create_jsonl_sink(write_line: Callable[[str], Any]) -> JsonlSink: ...
def default_redactor(key: str, value: Any, path: tuple[str, ...]) -> Any: ...

class TraceSink(Protocol):
    def write(self, event: dict[str, Any]) -> Any: ...
```

```python
class Observer:
    def __init__(
        self,
        *,
        mode: str = "off",
        sink: Any = None,
        run_id: str | None = None,
        producer_id: str | None = None,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[str], str] | None = None,
        redactor: Callable[[str, Any, tuple[str, ...]], Any] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None: ...
```

Every argument is keyword only and optional. `clock` returns a timezone-aware `datetime`; a naive one is refused rather than assumed to be UTC or local. `monotonic` returns a float number of seconds and defaults to `time.monotonic`; it never falls back to `clock`. `id_factory` takes a prefix and returns a nonempty string. An unknown `mode` or an unusable `sink` raises `ValueError` at construction, because a harness author fixes wiring once; nothing during a scan raises. In `off` mode the sink is not inspected at all, not even for an attribute, because it is never used.

| Member | Kind | Behavior |
| --- | --- | --- |
| `run_id`, `producer_id` | attributes | The IDs stamped on every event. A usable `run_id` or `producer_id` the caller passed is kept in every mode, `off` included. The emitter supplies only the one the caller left out or spelled unusably: from the ID factory in a recording mode, and as the literal `"off"` in `off` mode, which is how `off` mode calls no ID factory. |
| `mode` | property | The recording mode fixed at construction. Not switchable mid run. |
| `closed` | property | `True` once `close` or `aclose` has run. |
| `get_state() -> CaptureState` | method | A snapshot, so it does not change underfoot. Counts writes whose event loop is already gone before reporting. |
| `emit(**fields) -> dict \| None` | method | Records one event and returns it, or returns `None` when nothing was recorded. Not a coroutine. Accepts `type`, `capture_status`, `metadata`, and optionally `category`, `content`, `duration_ms`, `parent_event_id`, `call_id`, `attempt_id`, `candidate_id`, `claim_id`. An unknown keyword is refused rather than dropped, because Python catches no misspelled field at compile time. `self` is one of those keywords, not the receiver: the receiver is positional only, so an event carrying a field of that name is a refused event like any other misspelling rather than a `TypeError` out of the call. A stray positional argument is refused the same way. The returned mapping is the same object the sink was handed. |
| `observe(start, success, failure, operation) -> Any` | method | Runs a synchronous operation between a start event and a completion event. `success(duration_ms)` and `failure(error, duration_ms)` build the completion event; both receive `None` when the span could not be measured. The operation's value is returned untouched and its exception is re-raised as the original object with its original traceback. In `off` mode the operation runs with no instrumentation and neither builder is called. |
| `observe_async(start, success, failure, operation) -> Any` | coroutine | The same, for an operation whose result may be awaitable. Awaitable is decided on the result's type, the way `await` decides it, so classifying the result runs none of the caller's code. An async generator is not awaitable: it is returned untouched and the duration covers only the call that created it. Writes started here are not awaited; call `aflush`. |
| `flush() -> None` | method | Settles what can be settled synchronously and releases the private event loop. Not a coroutine. |
| `aflush() -> None` | coroutine | Awaits the writes `emit` and `observe_async` started on the loop this runs on, including the ones that start while it is already waiting. A write queued on a different loop is left pending rather than gathered, because awaiting a future from another loop raises. |
| `close() -> None` | method | `flush`, then refuse later events. Closes no caller resource. |
| `aclose() -> None` | coroutine | `aflush`, then refuse later events, then release the private loop. |

Neither `observe` nor `observe_async` consumes, wraps, or replaces a stream. If the operation returns a generator, an iterator, a file, or an awaitable, that object is returned as it is, and the duration covers only the call that produced it, not the work a caller later drives out of it.

## TypeScript API

Everything below is exported from `@scaneval/observer`, and that sentence is now checked the way the Python one is: `tests/test_v2_observer.py::test_the_documented_typescript_api_is_the_sdk_export_list` reads the exported names out of the code blocks in this section, reads them out of `sdk/typescript/src/index.ts`, and compares the two in both directions, along with the public members of the `Observer` class below. It reads the source rather than the build, so it needs neither node nor `dist/`. Only the Python list was checked before, while this section carried the same promise with nothing behind it.

```ts
export const SCHEMA_VERSION: "2.0";
export const MAX_PAYLOAD_DEPTH = 32;

export type RecordingMode = "off" | "metadata" | "content";
export type EventType = "model.request" | "model.response" | "tool.start" | "tool.end"
  | "context.selection" | "finding.candidate" | "finding.validation" | "finding.filtered"
  | "finding.submitted" | "observer.error";
export type EventCategory = "model" | "tool" | "context" | "finding" | "observer";
export type CaptureStatus = "complete" | "partial" | "redacted" | "unavailable";
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject { [key: string]: JsonValue }

export interface TraceEvent { /* the wire event, in schema declaration order */ }
export type EventInput = Omit<TraceEvent,
  "schema_version" | "event_id" | "run_id" | "producer_id" | "sequence" | "timestamp" | "category">
  & { category?: EventCategory };

export interface Clock { now(): Date }
export interface Monotonic { now(): number }        // seconds
export interface IdFactory { next(prefix: string): string }
export interface TraceSink { write(event: TraceEvent): void | Promise<void> }
export interface CaptureState {
  dropped_events: number;
  capture_gap: boolean;
  last_sink_error: string | null;
}
export type Redactor = (key: string, value: JsonValue, path: readonly string[]) => JsonValue;

export interface ObserverOptions {
  mode?: RecordingMode;
  sink?: TraceSink;
  runId?: string;
  producerId?: string;
  clock?: Clock;
  monotonic?: Monotonic;
  idFactory?: IdFactory;
  redactor?: Redactor;
}

export function createJsonlSink(
  writeLine: (line: string) => void | Promise<void>,
): TraceSink;
```

```ts
export class Observer {
  constructor(options: ObserverOptions = {});
  readonly runId: string;
  readonly producerId: string;
  get closed(): boolean;
  getState(): CaptureState;
  emit(input: EventInput): Promise<TraceEvent | undefined>;
  observeAsync<T>(
    start: EventInput,
    success: (duration_ms: number | undefined) => EventInput,
    failure: (error: unknown, duration_ms: number | undefined) => EventInput,
    operation: () => Promise<T>,
  ): Promise<T>;
  flush(): Promise<void>;
  close(): Promise<void>;
}
```

`emit` resolves for every input and never rejects, and a hook that throws anything at all is a recorded capture gap rather than the caller's exception. What it resolves *with* is a separate question, and it has two answers rather than one. This guide said `undefined` for every failure until a review ran each hook and found that two of the four resolve with the event instead, which matters to a caller that reads the returned value: it would have expected `undefined` where a real event was waiting.

- **It resolves `undefined`** when no event was built: an event the wire contract refuses, a payload that is not JSON or is nested too deeply, an emit after `close`, and a **redactor** that throws, which runs during the build and takes the event down with it. Each is a capture gap, and each of these is a lost event as well.
- **It resolves with the event** when the event was built and something else failed. A **clock** that throws gives it the epoch timestamp; an **ID factory** that throws gives it the next `event-fallback-N`; either way the event is downgraded to `partial` unless it is already `unavailable`, carries `observer_capture_gap: true`, records a gap, and is still handed to the sink, so nothing is lost and `dropped_events` stays where it was. A **sink** that throws is the other one: the event was built and is returned, and it is the write that is counted as the loss.

Python behaves identically, case for case, returning `None` where TypeScript resolves `undefined`. The matrix drives all four hooks in both languages and compares the built-or-not decision for every input: `tests/test_v2_observer_parity.py::test_a_clock_that_throws_degrades_both_emitters_identically` and `::test_an_id_factory_that_throws_degrades_both_emitters_identically` each assert the event came back, and `::test_both_emitters_agree_on_which_matrix_events_were_recorded` holds the redactor and sink halves.

`observeAsync` returns the operation's value untouched and re-throws its error as the original value, whatever was thrown. `flush` waits for the writes `emit` and `observeAsync` started and did not await, the ones that start while it is already waiting included, and never rejects, because an awaiting harness must not inherit an instrumentation failure as its own error. `close` drains and refuses later events in one loop, so it cannot resolve with a write outstanding. In `off` mode `emit` resolves `undefined` without touching the clock, the ID factory, the redactor, or the sink, and `observeAsync` is a pass-through.

Neither emitter ever derives elapsed time from a wall clock, injected or not: a wall clock can be adjusted forwards or backwards between two reads, so a span measured with one would record time that never elapsed. When no `monotonic` is given, Python reads `time.monotonic` and TypeScript reads `performance.now()`. A host with no `performance.now()` gives the TypeScript emitter no monotonic source at all, and it reports the span as unmeasurable rather than substituting `Date.now()`, which omits `duration_ms` and marks the event. A test that needs a pinned duration injects `monotonic` into both.

### Where the two API shapes differ

Neither difference changes a recorded event. They matter to someone reading both SDKs side by side.

| Python | TypeScript | Note |
| --- | --- | --- |
| `emit(**fields)` returns the event synchronously | `emit(input)` returns a `Promise` | The Python write is driven to completion before `emit` returns when no event loop is running. |
| `observe` (synchronous) and `observe_async` | `observeAsync` only | Every TypeScript boundary is a promise, so there is no synchronous counterpart to compare. |
| `flush`/`close` synchronous, `aflush`/`aclose` coroutines | `flush`/`close` are async only | Python needs both because a synchronous harness must be able to flush without a loop. |
| `mode` is a public property | the mode is private | There is no TypeScript accessor for the recording mode. |
| `default_redactor`, `RECORDING_MODES`, `EVENT_TYPES`, `EVENT_CATEGORIES`, `CAPTURE_STATUSES` are exported values | the equivalents are types, not runtime values | Only `SCHEMA_VERSION` and `MAX_PAYLOAD_DEPTH` exist as runtime constants in TypeScript. |
| a sink may be a bare callable or an object with `write` | a sink must be an object with `write` | Both accept sync and async writes. |

## Sink, flush and close lifecycle

**What a sink is.** A sink is caller-owned. The SDK never opens a file, never captures a global stream, and never closes anything the caller opened. `create_jsonl_sink` / `createJsonlSink` adapt a caller-owned line writer: it receives one serialized event with a trailing newline. Where those lines go, when they are fsynced, and whether they are ever deleted are the caller's decisions.

**Wiring is checked once.** In a recording mode the Python constructor resolves and vets the sink and raises `ValueError` if it is unusable, including when it is a generator function or async generator function, because calling one returns an iterator and writes nothing. Reading `sink.write` can run a caller descriptor, so a failure there is reported as an unusable sink rather than allowed out of the constructor as whatever it raised. In `off` mode nothing is read off the sink at all.

**A recording mode with no sink is allowed.** `emit` still builds the event and returns it, so the observer can be used as a builder. Every event it builds reached nobody, which both emitters record as a lost event; that they now agree on it is one of the closed divergences below.

**Writes.** A sink that returns an awaitable is driven to completion inside Python's `emit` when no event loop is running, on one private event loop this observer creates on first need. That loop is never installed as the thread's current loop, so it cannot disturb a loop the caller owns. Inside a running loop the write is scheduled as a task on the caller's loop instead, and `aflush`, `aclose`, and `observe_async` are the ones to use there. In TypeScript every write is a promise held in a pending set until it settles.

**Flush.** Call `await observer.flush()` (TypeScript) or `await observer.aflush()` (Python, in an async harness) after the scan operation has finished and before reading the capture state or terminating the process: it drains the writes that `emit` and the async observe helpers intentionally do not await, and keeps draining while new ones appear, so a write another task starts during the flush is settled by it rather than left outstanding. Python's synchronous `flush()` has nothing to wait for, because each write was already driven to completion, and it releases the private loop; writes belonging to a caller's loop are left pending, because waiting for them from synchronous code would deadlock that loop. A write still in flight is not a lost event. A write whose loop is torn down before it can run is counted, because that event reached nobody.

**Close.** `close` (and Python's `aclose`) flushes and then refuses later events: a subsequent `emit` records a lost event and returns nothing, so an event arriving after the run it postdates is visible as loss rather than silently appended. Neither returns while a write on its own loop is still outstanding; a write queued on a different loop is not one either can settle, so it is left pending and counted only once that loop is gone. Python's synchronous `close` waits for nothing, because the writes it can settle were already driven to completion by `emit`. Calling it twice is harmless. It closes no caller resource.

**Instrumentation reports only through the capture state.** A failure of the emitter's own is a `dropped_events` count, a `capture_gap`, and a marked event, never a line in the harness's output. Python keeps three asyncio reports out of that output for writes it abandons: an unretrieved exception on a write that failed, a `RuntimeWarning` for a coroutine a cancelled write never awaited, and `Task was destroyed but it is pending!` for a write still queued on a caller's loop when that loop is closed. The last is suppressed on every task the emitter creates, with the flag asyncio's own `gather` clears for the tasks it owns. Nothing is hidden by any of the three: each of those writes reached no sink, and each is counted where every other loss is counted.

**When a sink never returns.** Neither emitter imposes a timeout, ever. A sink that never settles makes `flush` and `aflush` wait forever, and, in a synchronous Python harness whose sink returns an awaitable, makes `emit` itself block for as long as the write takes. That is deliberate: cancelling a harness's write is a policy decision only the caller can make, and an emitter that cancelled it would decide for you whether a partially written trace is acceptable. Apply your own timeout or abort around the flush, outside the scan operation, and report the result as incomplete capture. The `llm-harness` adapter does exactly that and reports `flush_timed_out` alongside `events_written`.

## Recording modes and privacy

Modes are `off` (the default), `metadata`, and `content`, and the mode is fixed at construction. `off` is a no-op: it never calls the clock, the ID factory, the redactor, or the sink, so constructing one runs no caller code at all. Where a recording mode would ask the ID factory for a run or producer ID the caller did not supply, `off` mode uses the literal `"off"` instead. It does not overwrite an ID the caller did supply: a harness that names its run once and builds an observer per mode gets that name back from the `off` one too. This is pinned by `test_off_mode_keeps_explicit_run_and_producer_ids` and by `observer.test.mjs::"a caller's run and producer ID are kept in off mode"`; the guide read "in `off` mode both are the string `off`" until a review checked it. `metadata` stores events without `content`. `content` additionally stores a cloned, redacted copy of `content`.

Neither SDK changes the objects passed to it: metadata, and content when it will be stored, are deep copied into plain JSON types before anything is stored, and a caller-supplied redactor is treated as untrusted instrumentation whose output is copied and revalidated the same way. Pass a `redactor` for local policy.

Capture status is never more generous than what was stored. `metadata` mode downgrades a requested `complete` to `partial`, because it omits content; a redacted stored value marks the event `redacted`, unless a capture gap degraded the same event, in which case rule 9 runs last and the status is `partial`; an explicitly `unavailable` status survives all three downgrades.

That ordering is worth being exact about, because the status is one field answering two questions and the more serious answer wins. `redacted` says the event is complete except for values the redactor replaced. A capture gap says part of the event is fabricated or missing, which is the worse fact, so it takes the field. Nothing about the redaction is lost when it does: the values are still replaced in the stored payload, and `observer_capture_gap: true` is in the metadata beside them. Read `capture_status` as the worst thing true of the event, never as an enumeration of everything true of it, and read a `partial` event's payload rather than assuming nothing in it was hidden.

Redaction is a key-name filter over values the caller chose to pass. It is not automatic PII removal, not a privacy certification, and not a safe-to-upload guarantee. Keep traces locally unless a separate, approved retention and upload policy permits otherwise. Neither SDK requests hidden model reasoning or infers CVE knowledge; only harness-exposed data explicitly supplied in events is recorded.

## What the securevibes-agent and Fieldglass integration actually captures

The `llm-harness` adapter runs the securevibes-agent and Fieldglass engine family through its own entry point, injecting only the harness's default model runner wrapped by this observer plus a progress reporter. That injection point decides what can be seen, so the matrix below is the honest one. It is the matrix `scaneval.adapters.llm_harness.capture_status` returns for a run, cell for cell, and it is checked as such: `tests/test_v2_observer.py::test_the_documented_capture_matrix_is_the_one_capture_status_returns` parses the cells, the column definitions, the input space and the three coverage counts out of the three tables below, builds every run they describe, and compares each cell against what that function returns, so the document and the code cannot drift apart again. They had: this table read `finding.submitted` as **complete** whenever a traced run returned a summary, which is more than the code has reported since `capture_status` began reading the observer's own capture state. The column definitions were prose the test kept its own copy of, so the document could be edited into contradicting the code with nothing failing; they are a table now, and the test has no copy of its own.

No adapter in this repository captures every supported event type, and this one captures fewer than half of them.

Each column stands for a set of runs, and the sets are written down here rather than in the test, because a column definition the test owned could be changed on one side alone. Every backticked value in a cell is one value that column covers, and a column covers every combination of them: `metadata` and `content` are one column because the adapter's capture does not distinguish them, and a real model route is either route list that is not mock-only. The test reads this table, builds every run it describes, and compares each one against the matrix below.

| Column | `trace_mode` | `routes` | `has_summary` | `capture_state` |
| --- | --- | --- | --- | --- |
| trace off | `"off"` | `["claude"]` `["claude", "mock"]` | `true` | `{"capture_gap": false, "dropped_events": 0}` |
| traced | `"metadata"` `"content"` | `["claude"]` `["claude", "mock"]` | `true` | `{"capture_gap": false, "dropped_events": 0}` |
| traced, gap | `"metadata"` `"content"` | `["claude"]` `["claude", "mock"]` | `true` | `{"capture_gap": true, "dropped_events": 0}` `{"capture_gap": false, "dropped_events": 3}` `{}` `null` |
| no summary | `"metadata"` `"content"` | `["claude"]` `["claude", "mock"]` | `false` | `{"capture_gap": false, "dropped_events": 0}` |
| mock route | `"metadata"` `"content"` | `["mock"]` | `true` | `{"capture_gap": false, "dropped_events": 0}` |

**The columns are a sample, not a partition.** They do not cover the whole input space, and reading the matrix as if they did would answer a question it never asked. The space `capture_status` accepts is this:

| Input | Values the count below enumerates |
| --- | --- |
| `trace_mode` | `"off"` `"metadata"` `"content"` |
| `routes` | `[]` `["mock"]` `["claude"]` `["claude", "mock"]` |
| `has_summary` | `true` `false` |
| `capture_state` | `{"capture_gap": false, "dropped_events": 0}` `{"capture_gap": true, "dropped_events": 0}` `{"capture_gap": false, "dropped_events": 3}` `{}` `null` |

The five columns name 28 of the 120 combinations that enumerates, and the remaining 92 are outside the table. Those three counts are computed from the two tables above by the same test, so a column widened or a value added moves them. What falls outside is every crossing the columns do not pair: a `trace off` run that saw only the mock route, or returned no summary, or reported a gap; a traced run that is both mock-only and summary-less; and every run that observed no route at all. Two claims do hold across the whole space, and the test drives every combination in it to say so: `tool_calls` is `not_applicable` exactly when the observed routes are `["mock"]` and nothing else, and `finding_candidate`, `finding_validation` and `finding_filtered` are `unavailable` in every run this adapter can have. The rest of the matrix is a claim about the runs its columns name, and about no others.

| Event type | `capture_status` key | trace off | traced | traced, gap | no summary | mock route |
| --- | --- | --- | --- | --- | --- | --- |
| `model.request`, `model.response` | `model_requests`, `model_responses` | `unavailable` | `partial` | `partial` | `partial` | `partial` |
| `tool.start`, `tool.end` | `tool_calls` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `not_applicable` |
| `context.selection` | `context_selection` | `unavailable` | `partial` | `partial` | `partial` | `partial` |
| `finding.submitted` | `finding_submitted` | `unavailable` | `complete` | `partial` | `unavailable` | `complete` |
| `finding.candidate` | `finding_candidate` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` |
| `finding.validation` | `finding_validation` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` |
| `finding.filtered` | `finding_filtered` | `unavailable` | `unavailable` | `unavailable` | `unavailable` | `unavailable` |

`observer.error` is the tenth event type and has no row, because the adapter never emits one: instrumentation loss is reported in the capture state the driver writes alongside `events_written` and `flush_timed_out`, not as an event in the stream. The same test asserts that the nine types above plus `observer.error` are exactly the `EVENT_TYPES` the contract declares, so a type added to the contract cannot quietly miss this table.

Why each row says what it says:

- **`model.request`, `model.response`.** One request and one response event per logical call, at the runner boundary. The harness retries inside its own runner, below that boundary, so retries are not observable (`retries_observable: false`), and the CLI route exposes no token usage (`usage_available: false`). What is recorded is the outgoing CLI request, the returned stdout, stderr and exit code, and the measured duration. A single recorded pair can therefore stand for several real attempts, which is why no run and no column reads better than `partial`.
- **`tool.start`, `tool.end`.** Tool dispatch happens inside the model CLI subprocess this driver spawns, where the driver cannot see. No tool event is emitted, and the absence of one establishes nothing about whether a tool ran. Only the mock runner, which spawns no process at all, makes the concept `not_applicable`, and only when it is the sole observed route: a run that saw both `mock` and a real route is `unavailable`.
- **`context.selection`.** Only the harness's own progress notes that name a file are emitted, marked `source: harness_self_report`. That is the harness describing itself, not the engine's actual selection decision.
- **`finding.submitted`.** Every finding in the returned summary that carries an id, new and updated, is emitted with its `candidate_id` and `claim_id`, both set to that id. A record with no id is skipped rather than emitted with empty links, which the emitter would refuse as a capture gap anyway; such a record is import loss and is counted there, not here. A scan that throws produces no summary, so the category is `unavailable` rather than empty. `complete` does not follow from tracing alone: it requires an observer capture state that explicitly reports no gap and no dropped event, because the execution record carries `capture_gap` and `dropped_events` from that same state, and a record that called finding capture complete on one line while admitting a hole in it on the next would be answering one question twice. A state that reports either, and a run that reported no state at all, are `partial`. Whether the trace file then reached the bundle is the other half of that question and is settled once, in `scaneval.execution`, which rewrites every value in this table that claims an observation, `complete` and `partial` alike, to `unavailable` when the bundle it lands in holds no counted trace. The cells in the table above are what this adapter reports; they are not a promise about what a bundle ends up carrying.
- **`finding.candidate`.** Candidate creation happens inside the harness, which exposes no boundary for it. Only the findings it finally wrote are visible.
- **`finding.validation`.** Validation happens inside the harness, with no injection point for it.
- **`finding.filtered`.** Same reason. A finding the harness discarded leaves no trace the driver can observe, so no filtering event is emitted and no claim about filtering is made.

Read an `unavailable` row as "this driver cannot see this", never as "this did not happen".

The driver repeats part of this in its own output, and only part: `trace.unavailable` names `tool.start`, `tool.end`, `finding.candidate`, `finding.validation` and `finding.filtered`, plus the two surfaces that are not event types at all, model retries inside the harness runner and token usage. That list is fixed. It still names the two tool events on the mock route, where the table above says `not_applicable`, and it does not grow when `trace_mode` is `off` and every row above is unavailable. The table is the matrix the execution record carries; the driver's list is a note beside it.

## Known divergences and tested limits

These are known, each one is pinned by a test, and none of them is an oversight. Every behavioral divergence found by review has been closed: the parity matrix now compares both emitters in full, with no scenario excluded from the capture-state comparison. What remains are limits of the two languages themselves, plus a small number of exclusions the matrix makes deliberately so the byte comparison stays meaningful.

**Closed, and how.** Four behavioral divergences were open during development and were closed by changing the TypeScript emitter to match Python. `dropped_events` now counts only events that reached no sink in both, so a failure that degrades an event without losing it is a capture gap alone. A recording observer with no sink now reports that loss in both. Both constructors now refuse the same three wiring mistakes: an unknown recording mode, a sink with no callable `write`, and a generator-function sink. And the default elapsed-time source no longer differs: TypeScript used to derive it from an injected `Clock`, so a fixture that injected only a clock got a clock-derived duration there and a real measurement from Python, and it now defaults to `performance.now()` and never reads a wall clock, injected or not. The first three were each held open by a strict `xfail` naming the change that would close it, which is how none of them quietly became permanent; the fourth is pinned across the two languages by `tests/test_v2_observer_parity.py::test_neither_emitter_measures_elapsed_time_with_an_injected_wall_clock`, which drives the one operation scenario that injects a clock and no monotonic source, and on the Python side alone, without node, by `test_python_never_measures_elapsed_time_with_the_injected_wall_clock`.

**Closed since, and how.** A fifth divergence was an unpaired surrogate in a payload string. Python wrote the raw code point, which a real JSONL sink cannot encode, so the event was lost at write time with an error the harness saw, while JavaScript escaped it and wrote a line that parses. This one was closed by changing both emitters rather than one: a string no UTF-8 sink could write is refused as a capture gap, wherever a caller string reaches the wire, which is rule 1. It is pinned by the matrix cases `unpaired_surrogate_in_metadata`, `unpaired_surrogate_in_a_link_id` and `unpaired_surrogate_in_content`, each named in `test_the_parity_matrix_covers_every_input_shape_the_contract_names`, and in each language alone by `test_a_string_no_utf8_sink_could_encode_is_refused_as_a_capture_gap` and `observer.test.mjs::"a string no UTF-8 sink could encode is refused as a capture gap"`. The astral character in `TRICKY_TEXT` is the control: what both can write, both still write.

**Closed since that, and how.** A sixth divergence was a number in a payload. Python accepted an integer of any magnitude and wrote it exactly, so a count past `2 ** 53 - 1` reached a JavaScript reader as a different number; a payload float and a payload integer that were the same value wrote as `1.0` and `1`; and a non-integral value below `1e-4` wrote as `1e-05` from Python and `0.00001` from JavaScript, because the two leave plain decimal notation at different magnitudes and spell an exponent differently. This was closed in both emitters at once, by rule 4: a payload number is kept only when both write it as the same bytes, an integral one is stored as an integer, and anything outside the shared range is a capture gap. It is pinned by the matrix scenarios `payload-numbers` and `payload-numbers-metadata-mode` and by every `payload_*` case in `PAYLOAD_NUMBER_REJECTIONS`, compared in `test_both_emitters_write_one_spelling_for_every_payload_number_they_accept` and `test_both_emitters_refuse_the_payload_numbers_they_would_spell_differently`, and in each language alone by `test_a_payload_number_is_stored_only_when_both_languages_write_it_alike` and `observer.test.mjs::"a payload number is stored only when both languages write it alike"`. The integral float a payload could once carry is therefore no longer a known limit: it is normalized, and the matrix now carries it rather than avoiding it.

**Closed after that, and how.** A seventh and an eighth divergence were the same mistake twice: a rule that already lived in one place had a second, weaker copy of itself somewhere else in the TypeScript emitter. `nextId` checked a factory-produced ID with its own type-and-length test instead of the shared validator, so an ID carrying an unpaired surrogate went onto the wire where Python's `_next_id` refused the same value through `_is_id` and fell back to `event-fallback-1`; one event then had two event IDs and one of the two lines could not have been written by a UTF-8 sink at all. And the input gate asked whether `content` was any non-array object while the payload copy applied the plain-object rule, so a `content` built on another prototype was accepted in `metadata` mode, where the copy never runs, and refused in `content` mode by the same emitter, while Python asked one question in both places. Neither was closed by fixing the instance. The second spelling was deleted in each case: `validId` is now the only test any caller-derived string on the wire passes, ID factory output and the timestamp a caller's clock spelled included, as `_is_id` is in Python, and `isJsonObject` is the only test a payload object passes, asked by the gate and by the copy alike, as `_is_payload_object` is in Python. Python gained the timestamp half of the first rule in the same edit, because a `datetime` subclass owns the fields its timestamp is spelled from and can hand back a string of its own choosing. They are pinned across the two languages by `tests/test_v2_observer_parity.py::test_an_unusable_id_from_a_factory_is_refused_by_both_and_never_written` and `::test_a_payload_that_is_not_a_storable_object_is_refused_in_every_mode`, by the matrix scenarios `id-factory-returns-unusable-ids` and `unusable-run-and-producer-ids` and the rejection cases `metadata_is_not_a_payload_object` and `content_is_not_a_payload_object`, and in each language alone by `test_every_string_the_emitter_puts_on_the_wire_passes_the_one_validator` and `test_a_payload_that_is_not_a_mapping_is_refused_in_every_recording_mode`, with `observer.test.mjs::"every string this emitter puts on the wire passes the one validator"` and `observer.test.mjs::"a payload that is not a plain object is refused in every recording mode"` in the TypeScript suite.

**Closed in this round, and how.** A ninth was a payload property the copy could not see. TypeScript's `copyJson` walked an object with `Object.keys`, which reports own enumerable string keys and nothing else, so a symbol-keyed property and a non-enumerable own property were left out of the stored copy: the event was recorded, the capture state read clean, and the line was short of what the caller handed over, which is the silent reshaping every other rule here refuses. Python has no symbol and no hidden dict entry, and refuses a non-string key outright, so there was nothing on that side to match. It was closed by making the copy read `getOwnPropertyNames` and `getOwnPropertySymbols` and refuse both shapes as a capture gap, which is rule 1 applied to the one place it was not. It is pinned in the TypeScript suite by `observer.test.mjs::"a payload property Object.keys cannot see is refused, never dropped"`; the parity matrix carries no case for it, because neither shape can be spelled in Python.

**Timestamps cannot carry sub-millisecond precision.** The TypeScript `Clock` hands back a `Date`, which counts whole milliseconds since the epoch, so a microsecond-resolution source loses its fractional milliseconds before the emitter ever sees the value; Python formats its `datetime` to the same millisecond resolution. Neither language leaves any field of that timestamp to the platform: Python spells the year, month, day, hour, minute, second and millisecond itself, at fixed widths, because `strftime` hands `%Y` to the C library, which pads a year below 1000 to four digits on one platform and writes it bare on another. The bare spelling is no RFC 3339 timestamp, fails the schema's `date-time` format, and is not the four digits `toISOString` writes for the same instant, so a trace's timestamps would have depended on the machine that wrote them. Neither rounds or pads a reading to hide that. Two events emitted inside one millisecond therefore carry the same `timestamp`, and `sequence` is the only ordering a reader may rely on. Do not read a trailing `.000` as a measurement. `duration_ms` has the matching limit: it is a whole number of milliseconds in both, rounded half to even, so a span under half a millisecond records as `0` and not as an absent measurement.

**Neither `Observer` is thread safe, and only Python has threads to be unsafe with.** The Python class docstring has said this since it was written and no document repeated it, which is the wrong way round: a harness author reads the guide. There is no lock anywhere in either emitter, and neither takes one for you.

What that costs in Python, concretely. `emit` reads `self._sequence` into the event it is building, then calls the clock and the ID factory, and increments the counter afterwards. Two threads inside that window both take the same number: four threads emitting through one observer can write four events that all carry `sequence: 0`. Nothing is lost, four lines reach the sink, the capture state reports no gap and no dropped event, and what is gone is the only ordering the contract lets a reader rely on, with nothing in the record to say so. The counters behind `get_state`, and the ID factory's own, are ordinary increments too, so a count can be lost the same way. `flush`, `aflush`, and `close` walk the pending map while another thread may be adding to it.

So give each thread its own `Observer`, each with its own `producer_id`, which is what `sequence` is scoped to anyway, or hold your own lock around `emit`. `tests/test_v2_observer_parity.py::test_two_threads_sharing_one_python_observer_lose_the_ordering_the_contract_promises` drives the collision deterministically, by making the injected clock wait on a barrier so every thread is provably inside the window, and asserts the four events that all say `sequence: 0`. It documents the limit rather than pretending it is closed.

TypeScript cannot reach this. An `emit` builds its event in one synchronous stretch, before the first `await`, and JavaScript gives that stretch no second caller to interleave with; a worker thread there is a separate isolate with its own `Observer`. Asynchronous concurrency is a different thing and is handled: overlapping writes are what `flush` and `close` drain, and rule 13 is about exactly that.

**A payload key that looks like an array index.** JavaScript orders integer-like own property names ahead of the rest, so a metadata key such as `"2"` serializes in a different position than Python's insertion order. That order is not only the serializer's: it is how JavaScript enumerates an object at all, so the redactor is also *called* in a different order, `"2"` first in JavaScript and in insertion order in Python. A redactor that is a function of the key, value and path it is given stores the same values in both, and only the byte order differs; a redactor that carries state between calls can store different values in the two languages, and neither emitter can detect that. Each language's own order is pinned in its own suite, by `test_a_payload_key_that_looks_like_an_array_index_reorders_the_redactor_too` and `observer.test.mjs::"a payload key that looks like an array index reorders the redactor too"`, and compared across the two nowhere, because the parity matrix deliberately excludes such keys. Avoid them if byte-level joins matter, and keep redactors stateless.

**What else the parity matrix deliberately excludes.** Python cannot raise a value that is not a `BaseException`, so the "sink throws a non-error value" case pairs a JavaScript `throw "text"` with the nearest Python analogue, a bare `BaseException` that is not an `Exception`. Object and exception identity is compared as a per-language boolean rather than across the boundary, because neither can cross into the node subprocess the driver runs in. A sink that returns an awaitable is driven by machinery only one language has, so the private event loop, the cancelled write, and the interrupt travelling out of a write live in the Python suite rather than in the matrix: JavaScript has neither cancellation nor a loop of the emitter's own, and a matrix case for them would compare one language against nothing. The synchronous `observe` and `flush`/`close` pair is excluded for the same reason, being Python's alone. What the matrix does drive of that lifecycle is what both languages have: a sink that throws, a sink that hands back an iterator nobody drives, an observer with no sink, and an emit after `close`. Nothing in the matrix reads a real clock, the network, or a model, and every duration but one is a property of the plan rather than of how fast the test ran. The exception is the single operation scenario that injects no monotonic source, which exists to keep the closed wall-clock divergence closed: each language measures that span with its own real monotonic source, so the measured milliseconds are compared as a shape, a whole nonnegative count, and blanked before the bytes are compared. Nothing sleeps for it; the operation returns immediately. And the matrix proves nothing about a harness that never emits: it compares two emitters, not two integrations.

## How parity is tested

```sh
python -m pytest                       # the Python emitter and the cross-language matrix
cd sdk/typescript && npm test          # builds, then runs the TypeScript suite
```

Cross-language parity lives in [`tests/test_v2_observer_parity.py`](../tests/test_v2_observer_parity.py). It runs both emitters over one matrix of inputs with the same injected clock, monotonic source, ID factory, sink and redactor, and compares the JSONL byte for byte, the recorded-or-refused decision per input, the sequence numbers and event IDs, the capture state field for field with no scenario excluded (the two divergence sets it keeps for that comparison are named constants and are both empty, so reopening one means writing a scenario name into a diff), and, for the operation-boundary helpers, the value or error that passed through, the duration each builder was handed, and the completion event each one wrote. It drives the TypeScript side with a throwaway driver run under `node` against `sdk/typescript/dist/index.js`, which is gitignored and therefore local, and skips with a reason when either node or that build is missing, so a skipped run is never reported as a checked one.

The matrix also asserts its own completeness, in `test_the_parity_matrix_covers_every_input_shape_the_contract_names`, which needs no node: every recording mode, every event type, every capture status, every field a caller may supply (each one accepted somewhere as well as refused somewhere), every link field the schema declares as an optional link (the list is derived from the schema rather than copied from it), every constructor option (each driven by a named plan key), every redactor the file defines, and every unusable elapsed-time reading the scripted source can produce. A case deleted from the matrix fails there rather than passing quietly on less evidence.

## What this document checks about itself

A guide that advertises a check it does not perform is worse than one that claims nothing, because a reader has no way to tell the two apart and takes the checked-looking claim on trust. This section is the list, so the distinction is readable rather than inferred. Everything named here is read out of this file by a test and compared with the code; everything else is prose.

Checked in `tests/test_v2_observer.py` except where another file is named, and none of it needing node or a build:

- **Both export lists.** The names in the Python API code blocks against `scaneval.observer.__all__`, in both directions, and the member table against a real `Observer` (`test_the_documented_python_api_is_the_package_export_list`). The names in the TypeScript API code blocks against the `export` declarations in `sdk/typescript/src/index.ts`, in both directions, and the documented `Observer` class members against that class's public members (`test_the_documented_typescript_api_is_the_sdk_export_list`).
- **Both constructor option lists**, in `tests/test_v2_observer_parity.py::test_the_constructor_options_the_guide_documents_are_the_ones_the_code_takes`: the Python `__init__` block parsed out of this file with `ast` and compared, names and defaults, with `inspect.signature(Observer.__init__)`, and the `ObserverOptions` interface in the TypeScript block compared line for line with the one in `sdk/typescript/src/index.ts`. These two lists were the gap a review found in this very section: they sit inside code blocks the export checks read, so they looked checked, but the Python check skips every indented line and the TypeScript one compares interface names rather than their bodies, so neither list had anything behind it.
- **Every test this guide cites**, Python by function name and TypeScript by the `observer.test.mjs::` prefix, looked up in the suite that defines it (`test_every_test_the_guide_names_still_exists`).
- **The capture matrix**, cell by cell, against what `scaneval.adapters.llm_harness.capture_status` returns: its column definitions and its input space parsed from their own tables, the three coverage counts recomputed from those tables, and the two claims that hold everywhere driven across every combination that space enumerates (`test_the_documented_capture_matrix_is_the_one_capture_status_returns`).
- **Rule 7's key list**, every name in it asked of `default_redactor` in three cases, along with the key that merely contains one and the two Unicode lookalikes the rule names by code point (`test_the_redactor_key_names_the_guide_lists_are_the_ones_it_hides`), and **rule 10's key order**, built from this file and the schema and compared with a real event (`test_the_key_order_the_guide_spells_is_the_order_an_event_carries`).
- **The constants and counts this guide states**: the values beside the Python constants, the four TypeScript vocabulary types in this file and in the SDK source, `MAX_PAYLOAD_DEPTH` and the levels it leaves, the safe-integer bound wherever it is spelled, the plain-decimal floor and the over-refusal floor, the number of event types and `observer.error`'s position among them, the three capture-state fields, and the two reserved strings `observer_capture_gap` and `observer instrumentation failure` (`test_the_constants_the_guide_states_are_the_constants_both_emitters_use`), with the payload-number window driven at the bounds it states (`test_the_payload_number_window_the_guide_states_is_the_one_the_emitter_enforces`).

Prose, and pinned only by the tests it cites: the fourteen numbered rules of the parity contract and their rationale, the lifecycle descriptions, the divergence history, the per-row explanations under the capture matrix, the thread-safety limit and what it costs, what `emit` resolves with per failing hook, the order the status downgrades run in, and every claim about what a reader may conclude from an event or its absence. A cited test name is checked to exist; that the test holds the claim beside it is not something this file can check, and is a matter for review. Treat an uncited sentence here as a description written by someone reading the code, because that is what it is.
