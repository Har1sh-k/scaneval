# Observer SDK

Two emitters, one wire contract. `scaneval.observer` (Python, `src/scaneval/observer/`) and `@scaneval/observer` (TypeScript, `sdk/typescript/`) are small, opt-in emitters for observing an existing harness.

Neither is an integration with SecureVibes, Fieldglass, or any other product. Neither makes model or provider calls, retrieves data, enforces policy, opens a file of its own, starts a thread, spawns a process, or monkeypatches a global client. Importing either records nothing. A harness must explicitly emit at its real model-client, tool-dispatch, context-selection, and finding-lifecycle boundaries for anything to be recorded at all. An absent event is never evidence of absent activity.

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

**1. One rejection set.** The two emitters accept and reject exactly the same inputs. Where they differ, the stricter rule becomes the shared one. An event is refused when it carries an unknown field name, an unknown `type`, a `category` that contradicts its `type`, an unknown `capture_status`, a missing or non-object `metadata`, a non-object `content`, a `duration_ms` that is not a nonnegative whole safe integer, or a link ID (`parent_event_id`, `call_id`, `attempt_id`, `candidate_id`, `claim_id`) that is present but is not a nonempty string. A cyclic payload, a non-finite number in a payload, a non-string object key, a value that is not JSON, and a payload nested past the shared depth limit are refused the same way. Absence is spelled by omitting the field: a field present with the value `null` (Python `None`) is refused, never read as absent, because reading it as absent would record an event the harness did not describe. `content` is copied, and therefore validated, only in `content` mode, so a payload that only the copy would refuse is accepted in `metadata` mode by both emitters.

**2. A refused event costs nothing.** It consumes no sequence number, no event ID, and no clock read in either language. That is only safe because the rejection sets are identical: if one emitter refused an input the other accepted, every later event in that producer's stream would carry a different sequence number, a different ID, and a different timestamp in the two languages. This is why rule 1 is a contract and not an implementation detail.

**3. `duration_ms` is a whole number of milliseconds, and a safe integer.** Non-integral, negative, non-finite, `null`, boolean, and anything above `2 ** 53 - 1` are refused in both languages. An integral float is stored as an integer so both write the same bytes. The bound is JavaScript's `Number.MAX_SAFE_INTEGER`: past it a JSON number no longer round-trips through a double, so a value Python could hold exactly would reach a reader as a different one. The schema says `"type": "integer"`, so an event that violated this would also fail schema validation.

**4. Elapsed time comes from a monotonic source, and is never invented.** The observe helpers measure with a monotonic source that is separate from the wall clock, read in seconds. If the span cannot be measured, because a read failed, the source returned something that is not a finite number, the source went backwards, or the span exceeds the safe-integer bound, then `duration_ms` is omitted, the completion event is still emitted, it is downgraded to `partial` unless it is already `unavailable`, `observer_capture_gap: true` is written into its metadata, and one capture gap is recorded. A duration the builder supplies anyway is dropped. An omitted duration says the span is unknown; a fabricated one would be read as a measurement.

**5. Whether a redactor changed a value follows JavaScript strict inequality.** An immutable scalar (string, number, boolean, `null`) compares by value; a container compares by identity. A redactor that hands back a structurally equal copy of an object or array therefore counts as having replaced it, and the event is marked `redacted` in both languages, while a redactor that returns an equal string or an equal number changes nothing in either. Python mirrors these semantics rather than asking `is`: CPython gives two equal strings, and two equal integers past the small-integer cache, separate identities, and an emitter that read that as a change would mark an event `redacted` where the TypeScript emitter marked it `complete`.

**6. The default redactor folds case over ASCII only.** Python spells it `re.IGNORECASE | re.ASCII`; JavaScript uses `/.../i` without the `u` flag. Both hide the same whole key names (`api_key`, `apikey`, `api-key`, `authorization`, `credential(s)`, `cookie(s)`, `password`, `secret(s)`, `token`, `private_key`, `private-key`, any case) and neither hides a key that merely contains one, such as `input_tokens`. A Unicode character whose ASCII uppercase looks like part of a credential name, for example U+212A KELVIN SIGN or U+017F LATIN SMALL LETTER LONG S, is left alone by both. Without `re.ASCII`, Python would hide `toKen` and `ſecret` while JavaScript kept them, which the parity matrix carries a case for.

**7. Payload nesting stops at `MAX_PAYLOAD_DEPTH`, which is 32.** The limit is counted in containers entered, and the `metadata` or `content` object a caller passes is the first of them, so that object plus 31 further levels is stored whole and one container deeper is refused as a capture gap. Objects and arrays count the same. A too-deep payload is refused, never truncated, because a silently reshaped payload would misdescribe the run it claims to observe, and it is refused at the same container in both languages so neither accepts what the other refuses. A redactor's replacement is held to the same budget at the depth it sits at, so a replacement cannot smuggle deeper nesting past the limit. The number is exported from both packages (`MAX_PAYLOAD_DEPTH`) so a harness can check its own payloads against it; raising it is a contract change in both languages at once.

**8. An event built while instrumentation failed says so, in itself.** When a clock read, an ID read, or an elapsed-time read fails while an event is being built, that event carries a fabricated timestamp, a fabricated ID, or no duration. Both emitters then downgrade its `capture_status` to `partial`, unless it is already `unavailable`, and set `observer_capture_gap: true` in its metadata. The emitter owns that key and overwrites a caller value of the same name. A reader can therefore tell a measurement from a fallback without consulting the capture state.

**9. Emitted key order is the schema's declaration order.** `schema_version`, `event_id`, `run_id`, `producer_id`, `sequence`, `type`, `category`, `capture_status`, `timestamp`, then the link fields in the order the schema lists them, then `duration_ms`, `metadata`, and `content`. A JSONL line from either language is byte identical, key order included.

**10. Instrumentation never alters the caller.** Every caller-supplied hook (clock, monotonic source, ID factory, redactor, event builder) and every sink write runs under the widest guard the language has. Python guards `BaseException` and re-raises only `KeyboardInterrupt` and `SystemExit`, because those are the caller's own interrupt rather than an instrumentation defect; an `asyncio.CancelledError` raised by a sink is a recorded gap, not an escape. An interrupt travels on unchanged, but the event it stopped is counted as a lost event before it does, so a run an operator cut short reports what it failed to record instead of a clean capture state. Python's `observe` and `observe_async` emit the start event and take the first elapsed-time reading before the operation runs, so an interrupt from the start Mapping, the redactor, the clock, the ID factory, the sink, or the elapsed-time source is the one thing instrumentation can do that stops the operation from running at all. TypeScript contains everything, including a thrown value that is not an `Error`. The observed operation's return value is passed back untouched and its error is re-raised as the original object, with the original traceback in Python.

**11. Capture state carries the same three fields.** `dropped_events`, `capture_gap`, and `last_sink_error`, with `last_sink_error` present and `null` (Python `None`) until something fails. It is one opaque constant, `"observer instrumentation failure"`, for every contained failure: it reports that capture broke, never which call broke or why, because a sink's exception text can quote the payload it failed to write. Read the marked events, not this field, to see where capture degraded. `capture_gap: true` and a nonzero `dropped_events` both mean the trace is incomplete. Zero is not a claim that the harness emitted everything it should have; it only says nothing the harness did emit was lost here. Both emitters count the same thing: an event that reached no sink. A degraded but delivered event is a capture gap without a drop.

## Python API

Everything below is exported from `scaneval.observer`.

```python
SCHEMA_VERSION      # "2.0"
MAX_PAYLOAD_DEPTH   # 32
RECORDING_MODES     # ("off", "metadata", "content")
EVENT_TYPES         # the ten wire event types, in schema order
EVENT_CATEGORIES    # ("model", "tool", "context", "finding", "observer")
CAPTURE_STATUSES    # ("complete", "partial", "redacted", "unavailable")
```

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
| `run_id`, `producer_id` | attributes | The IDs stamped on every event. In `off` mode both are the string `"off"` and no ID factory is called. |
| `mode` | property | The recording mode fixed at construction. Not switchable mid run. |
| `closed` | property | `True` once `close` or `aclose` has run. |
| `get_state() -> CaptureState` | method | A snapshot, so it does not change underfoot. Counts writes whose event loop is already gone before reporting. |
| `emit(**fields) -> dict \| None` | method | Records one event and returns it, or returns `None` when nothing was recorded. Not a coroutine. Accepts `type`, `capture_status`, `metadata`, and optionally `category`, `content`, `duration_ms`, `parent_event_id`, `call_id`, `attempt_id`, `candidate_id`, `claim_id`. An unknown keyword is refused rather than dropped, because Python catches no misspelled field at compile time. The returned mapping is the same object the sink was handed. |
| `observe(start, success, failure, operation) -> Any` | method | Runs a synchronous operation between a start event and a completion event. `success(duration_ms)` and `failure(error, duration_ms)` build the completion event; both receive `None` when the span could not be measured. The operation's value is returned untouched and its exception is re-raised as the original object with its original traceback. In `off` mode the operation runs with no instrumentation and neither builder is called. |
| `observe_async(start, success, failure, operation) -> Any` | coroutine | The same, for an operation whose result may be awaitable. Awaitable is decided on the result's type, the way `await` decides it, so classifying the result runs none of the caller's code. An async generator is not awaitable: it is returned untouched and the duration covers only the call that created it. Writes started here are not awaited; call `aflush`. |
| `flush() -> None` | method | Settles what can be settled synchronously and releases the private event loop. Not a coroutine. |
| `aflush() -> None` | coroutine | Awaits the writes `emit` and `observe_async` started on the loop this runs on. A write queued on a different loop is left pending rather than gathered, because awaiting a future from another loop raises. |
| `close() -> None` | method | `flush`, then refuse later events. Closes no caller resource. |
| `aclose() -> None` | coroutine | `aflush`, then refuse later events, then release the private loop. |

Neither `observe` nor `observe_async` consumes, wraps, or replaces a stream. If the operation returns a generator, an iterator, a file, or an awaitable, that object is returned as it is, and the duration covers only the call that produced it, not the work a caller later drives out of it.

## TypeScript API

Everything below is exported from `@scaneval/observer`.

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

`emit` resolves for every input and never rejects: a refused event, a hook that throws anything at all, a payload that is not JSON or is nested too deeply, and an emit after `close` all resolve `undefined` and record a capture gap, so instrumentation cannot become the caller's exception. `observeAsync` returns the operation's value untouched and re-throws its error as the original value, whatever was thrown. `flush` waits for the writes `emit` and `observeAsync` started and did not await, and never rejects, because an awaiting harness must not inherit an instrumentation failure as its own error. `close` flushes, then refuses later events. In `off` mode `emit` resolves `undefined` without touching the clock, the ID factory, the redactor, or the sink, and `observeAsync` is a pass-through.

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

**A recording mode with no sink is allowed.** `emit` still builds the event and returns it, so the observer can be used as a builder. Every event it builds reached nobody, which Python records as a lost event.

**Writes.** A sink that returns an awaitable is driven to completion inside Python's `emit` when no event loop is running, on one private event loop this observer creates on first need. That loop is never installed as the thread's current loop, so it cannot disturb a loop the caller owns. Inside a running loop the write is scheduled as a task on the caller's loop instead, and `aflush`, `aclose`, and `observe_async` are the ones to use there. In TypeScript every write is a promise held in a pending set until it settles.

**Flush.** Call `await observer.flush()` (TypeScript) or `await observer.aflush()` (Python, in an async harness) after the scan operation has finished and before reading the capture state or terminating the process: it drains the writes that `emit` and the async observe helpers intentionally do not await. Python's synchronous `flush()` has nothing to wait for, because each write was already driven to completion, and it releases the private loop; writes belonging to a caller's loop are left pending, because waiting for them from synchronous code would deadlock that loop. A write still in flight is not a lost event. A write whose loop is torn down before it can run is counted, because that event reached nobody.

**Close.** `close` (and Python's `aclose`) flushes and then refuses later events: a subsequent `emit` records a lost event and returns nothing, so an event arriving after the run it postdates is visible as loss rather than silently appended. Calling it twice is harmless. It closes no caller resource.

**When a sink never returns.** Neither emitter imposes a timeout, ever. A sink that never settles makes `flush` and `aflush` wait forever, and, in a synchronous Python harness whose sink returns an awaitable, makes `emit` itself block for as long as the write takes. That is deliberate: cancelling a harness's write is a policy decision only the caller can make, and an emitter that cancelled it would decide for you whether a partially written trace is acceptable. Apply your own timeout or abort around the flush, outside the scan operation, and report the result as incomplete capture. The `llm-harness` adapter does exactly that and reports `flush_timed_out` alongside `events_written`.

## Recording modes and privacy

Modes are `off` (the default), `metadata`, and `content`, and the mode is fixed at construction. `off` is a no-op: it never calls the clock, the ID factory, the redactor, or the sink, and names its run and producer `off` rather than consuming an ID, so constructing one runs no caller code at all. `metadata` stores events without `content`. `content` additionally stores a cloned, redacted copy of `content`.

Neither SDK changes the objects passed to it: metadata, and content when it will be stored, are deep copied into plain JSON types before anything is stored, and a caller-supplied redactor is treated as untrusted instrumentation whose output is copied and revalidated the same way. Pass a `redactor` for local policy.

Capture status is never more generous than what was stored. `metadata` mode downgrades a requested `complete` to `partial`, because it omits content; any redacted stored value marks the event `redacted`; an explicitly `unavailable` status survives both downgrades and the capture-gap downgrade of rule 8.

Redaction is a key-name filter over values the caller chose to pass. It is not automatic PII removal, not a privacy certification, and not a safe-to-upload guarantee. Keep traces locally unless a separate, approved retention and upload policy permits otherwise. Neither SDK requests hidden model reasoning or infers CVE knowledge; only harness-exposed data explicitly supplied in events is recorded.

## What the securevibes-agent and Fieldglass integration actually captures

The `llm-harness` adapter runs the securevibes-agent and Fieldglass engine family through its own entry point, injecting only the harness's default model runner wrapped by this observer plus a progress reporter. That injection point decides what can be seen, so the matrix below is the honest one. It is the same matrix `scaneval.adapters.llm_harness.capture_status` returns for a run, and the driver repeats the unavailable list in its own output.

No adapter in this repository captures every supported event type, and this one captures fewer than half of them.

| Category | Capture | Why |
| --- | --- | --- |
| `model.request`, `model.response` | **partial** when tracing, `unavailable` when `trace_mode` is `off` | One request and one response event per logical call, at the runner boundary. The harness retries inside its own runner, below that boundary, so retries are not observable (`retries_observable: false`), and the CLI route exposes no token usage (`usage_available: false`). What is recorded is the outgoing CLI request, the returned stdout, stderr and exit code, and the measured duration. A single recorded pair can therefore stand for several real attempts. |
| `tool.start`, `tool.end` | **unavailable** on every real route | Tool dispatch happens inside the model CLI subprocess this driver spawns, where the driver cannot see. No tool event is emitted, and the absence of one establishes nothing about whether a tool ran. Only the mock runner, which spawns no process at all, makes the concept `not_applicable`. |
| `context.selection` | **partial** when tracing, `unavailable` otherwise | Only the harness's own progress notes that name a file are emitted, marked `source: harness_self_report`. That is the harness describing itself, not the engine's actual selection decision. |
| `finding.submitted` | **complete** when tracing and the scan returned a summary, `unavailable` otherwise | Every finding in the returned summary, new and updated, is emitted with its `candidate_id` and `claim_id`. A scan that throws produces no summary, so the category is `unavailable` rather than empty. |
| `finding.candidate` | **unavailable** | Candidate creation happens inside the harness, which exposes no boundary for it. Only the findings it finally wrote are visible. |
| `finding.validation` | **unavailable** | Validation happens inside the harness, with no injection point for it. |
| `finding.filtered` | **unavailable** | Same reason. A finding the harness discarded leaves no trace the driver can observe, so no filtering event is emitted and no claim about filtering is made. |
| `observer.error` | not emitted | Instrumentation loss shows up in the capture state the driver reports alongside `events_written` and `flush_timed_out`, not as an event in the stream. |

Read an `unavailable` row as "this driver cannot see this", never as "this did not happen".

## Known divergences and tested limits

These are known, each one is pinned by a test, and none of them is an oversight. Every behavioral divergence found by review has been closed: the parity matrix now compares both emitters in full, with no scenario excluded from the capture-state comparison. What remains are limits of the two languages themselves, plus a small number of exclusions the matrix makes deliberately so the byte comparison stays meaningful.




**Closed, and how.** Four behavioral divergences were open during development and were closed by changing the TypeScript emitter to match Python. `dropped_events` now counts only events that reached no sink in both, so a failure that degrades an event without losing it is a capture gap alone. A recording observer with no sink now reports that loss in both. Both constructors now refuse the same three wiring mistakes: an unknown recording mode, a sink with no callable `write`, and a generator-function sink. And the default elapsed-time source no longer differs: TypeScript used to derive it from an injected `Clock`, so a fixture that injected only a clock got a clock-derived duration there and a real measurement from Python, and it now defaults to `performance.now()` and never reads a wall clock, injected or not. The first three were each held open by a strict `xfail` naming the change that would close it, which is how none of them quietly became permanent; the fourth is pinned across the two languages by `tests/test_v2_observer_parity.py::test_neither_emitter_measures_elapsed_time_with_an_injected_wall_clock`, which drives the one operation scenario that injects a clock and no monotonic source, and on the Python side alone, without node, by `test_python_never_measures_elapsed_time_with_the_injected_wall_clock`.

**Timestamps cannot carry sub-millisecond precision.** The TypeScript `Clock` hands back a `Date`, which counts whole milliseconds since the epoch, so a microsecond-resolution source loses its fractional milliseconds before the emitter ever sees the value; Python formats its `datetime` to the same millisecond resolution. Neither rounds or pads a reading to hide that. Two events emitted inside one millisecond therefore carry the same `timestamp`, and `sequence` is the only ordering a reader may rely on. Do not read a trailing `.000` as a measurement. `duration_ms` has the matching limit: it is a whole number of milliseconds in both, rounded half to even, so a span under half a millisecond records as `0` and not as an absent measurement.

**An integral float in a payload.** Python writes `1.0` where JavaScript writes `1`, because JavaScript has one number type. This is reachable only through a caller's own metadata or content value, never through a field the emitters own: `duration_ms` is normalized to an integer by rule 3. The parity matrix deliberately keeps integral floats out of payloads so the byte comparison stays meaningful.

**A payload key that looks like an array index.** JavaScript orders integer-like own property names ahead of the rest, so a metadata key such as `"2"` serializes in a different position than Python's insertion order. Both languages emit the same object; only the byte order differs. The parity matrix deliberately excludes such keys. Avoid them if byte-level joins matter.

**What else the parity matrix deliberately excludes.** Python cannot raise a value that is not a `BaseException`, so the "sink throws a non-error value" case pairs a JavaScript `throw "text"` with the nearest Python analogue, a bare `BaseException` that is not an `Exception`. Object and exception identity is compared as a per-language boolean rather than across the boundary, because neither can cross into the node subprocess the driver runs in. Nothing in the matrix reads a real clock, the network, or a model, and every duration but one is a property of the plan rather than of how fast the test ran. The exception is the single operation scenario that injects no monotonic source, which exists to keep the closed wall-clock divergence closed: each language measures that span with its own real monotonic source, so the measured milliseconds are compared as a shape, a whole nonnegative count, and blanked before the bytes are compared. Nothing sleeps for it; the operation returns immediately. And the matrix proves nothing about a harness that never emits: it compares two emitters, not two integrations.

## How parity is tested

```sh
python -m pytest                       # the Python emitter and the cross-language matrix
cd sdk/typescript && npm test          # builds, then runs the TypeScript suite
```

Cross-language parity lives in [`tests/test_v2_observer_parity.py`](../tests/test_v2_observer_parity.py). It runs both emitters over one matrix of inputs with the same injected clock, monotonic source, ID factory, sink and redactor, and compares the JSONL byte for byte, the recorded-or-refused decision per input, the sequence numbers and event IDs, the capture state field for field outside the two named exclusion sets above, and, for the operation-boundary helpers, the value or error that passed through, the duration each builder was handed, and the completion event each one wrote. It drives the TypeScript side with a throwaway driver run under `node` against `sdk/typescript/dist/index.js`, which is gitignored and therefore local, and skips with a reason when either node or that build is missing, so a skipped run is never reported as a checked one.
