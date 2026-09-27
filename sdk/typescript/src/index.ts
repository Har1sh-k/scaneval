/**
 * A deliberately small, opt-in observer emitter. Importing it records nothing.
 *
 * It is behaviorally matched to the Python emitter in `src/scaneval/observer`: the two accept
 * and reject the same inputs, write the same keys in the wire schema's declaration order,
 * redact by the same ASCII key-name rule, decide "was this value replaced" by the same
 * strict-inequality rule, refuse the same payload nesting depth, refuse the same strings no
 * UTF-8 sink could write, refuse the same payload objects, refuse the same payload numbers,
 * and report the same capture state fields.
 *
 * Two of those rules are one function each, because a rule with a second, weaker copy of itself
 * somewhere is a divergence waiting to be found. `validId` decides every caller-derived string
 * that reaches the wire: a link ID, a run or producer ID, an ID a factory produced, and the
 * timestamp a caller's clock spelled. `isJsonObject` decides every payload object, asked by the
 * input gate and by the copy alike, so a recording mode cannot change what a caller may hand
 * over. A payload number is the one value either language would otherwise spell its own way:
 * `wireNumber` keeps only the numbers both write identically, an integer inside the safe-integer
 * range or a non-integral value at least `MIN_PLAIN_DECIMAL` in magnitude, and refuses the rest
 * as a capture gap. A rejected event consumes
 * no sequence number, no event ID, and no clock read; that is only safe because the rejection
 * sets are identical, so the rule in `validInput` is a contract rather than an implementation
 * detail. Where the two once differed, the stricter rule
 * is now the shared one.
 *
 * The caller's input object is read exactly once, into a snapshot, and the snapshot is what is
 * validated and what is built from. A caller object whose property getters answer differently
 * on a second read therefore cannot slip a value past validation into the record.
 *
 * Elapsed time comes from a monotonic source, never from the wall clock, and is omitted rather
 * than invented when it cannot be measured. An event built while instrumentation failed, or one
 * whose duration could not be measured, is downgraded to `partial` and carries
 * `observer_capture_gap: true` in its metadata, so a reader cannot mistake a fabricated ID, an
 * epoch timestamp, or a missing duration for a measured one.
 *
 * Nothing here can change the value an observed operation returns or the error it raises.
 * Every instrumentation failure, including a thrown value that is not an Error, becomes a
 * visible capture gap. A gap says the trace is incomplete; an absent event is not evidence
 * of absent activity.
 *
 * `dropped_events` counts events no sink acknowledged taking, and nothing else; `CaptureState`
 * states that promise and why acknowledgement rather than arrival is the word. A clock read, an
 * ID read, or an elapsed-time read that failed sets `capture_gap` and marks the event it
 * degraded, but it does not increment the counter, because the sink still took that event:
 * counting it there would report a loss that did not happen and hide the ones that did. A
 * recording observer with no sink is the opposite case and is counted, because every event it
 * builds reaches nobody. Python draws the same line, between `_mark_gap` and `_lost_event`.
 *
 * A flush settles the writes that begin while it is already waiting, not a snapshot of the set
 * taken when it was called, and `close` drains and sets its closed flag in one loop: a close that
 * resolved with a write outstanding would tell a harness capture had settled while an event was
 * still on its way to the sink. The Python `aflush` re-reads its pending map for the same reason.
 *
 * Wiring mistakes are refused at construction rather than degraded at runtime: an unknown
 * recording mode, a sink with no callable `write`, and a sink or a `write` that is a generator
 * function each throw from the constructor, exactly as the Python `__init__` and
 * `_normalize_sink` raise on them, and `createJsonlSink` throws on a generator-function writer
 * for the same reason, as the Python `create_jsonl_sink` does. A harness author fixes wiring
 * once, before a run; nothing during a scan raises. Those checks are syntactic: a write that
 * returns a generator rather than being one is invisible to them and is caught at write time,
 * where the undriven iterator it handed back is counted as a lost event. Python draws that
 * second line in the same place.
 */
export const SCHEMA_VERSION = "2.0" as const;
/**
 * The deepest payload nesting either emitter stores, counted in containers entered.
 *
 * The `metadata` or `content` object a caller passes is the first container, so this allows
 * that object plus 31 further levels of nesting inside it. A deeper payload is refused as a
 * capture gap rather than truncated, because a silently truncated payload would misdescribe
 * the run it claims to observe, and it is refused in both languages so neither emitter accepts
 * what the other refuses. The bound exists because copying a payload recurses: without it a
 * deep enough object exhausts the JavaScript stack in one language and Python's recursion
 * limit in the other, at different depths, which would be a divergent rejection set.
 *
 * Changing this number changes the shared contract, so it changes the Python constant of the
 * same name and `docs/OBSERVER_SDK.md` in the same edit.
 */
export const MAX_PAYLOAD_DEPTH = 32;
export type RecordingMode = "off" | "metadata" | "content";
export type EventType =
  | "model.request"
  | "model.response"
  | "tool.start"
  | "tool.end"
  | "context.selection"
  | "finding.candidate"
  | "finding.validation"
  | "finding.filtered"
  | "finding.submitted"
  | "observer.error";
export type EventCategory =
  | "model"
  | "tool"
  | "context"
  | "finding"
  | "observer";
export type CaptureStatus = "complete" | "partial" | "redacted" | "unavailable";
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}
export interface TraceEvent {
  schema_version: typeof SCHEMA_VERSION;
  event_id: string;
  run_id: string;
  producer_id: string;
  sequence: number;
  type: EventType;
  category: EventCategory;
  capture_status: CaptureStatus;
  timestamp: string;
  parent_event_id?: string;
  call_id?: string;
  attempt_id?: string;
  candidate_id?: string;
  claim_id?: string;
  duration_ms?: number;
  metadata: JsonObject;
  content?: JsonObject;
}
export type EventInput =
  & Omit<
    TraceEvent,
    | "schema_version"
    | "event_id"
    | "run_id"
    | "producer_id"
    | "sequence"
    | "timestamp"
    | "category"
  >
  & { category?: EventCategory };
/**
 * Wall-clock source for `timestamp`, and nothing else.
 *
 * It hands back a `Date`, which counts whole milliseconds since the epoch, so this interface
 * cannot carry sub-millisecond precision: a microsecond-resolution source loses its fractional
 * milliseconds inside `Date` before the emitter ever sees the value, and the emitter neither
 * rounds nor pads a reading to hide that. A recorded `timestamp` is therefore a
 * millisecond-resolution reading, two events emitted inside one millisecond carry the same
 * timestamp, and `sequence` is the only ordering a reader may rely on. This is a limit of the
 * declared interface, not of the clock a caller injects; it is stated here rather than worked
 * around so nobody reads a trailing `.000` as a measurement.
 *
 * Elapsed time never comes from here. See `Monotonic`.
 */
export interface Clock {
  now(): Date;
}
/**
 * Elapsed-time source for the observe helpers, read in SECONDS.
 *
 * Seconds, not milliseconds, because the Python emitter takes a `time.monotonic` compatible
 * source and the two must read one injected source the same way; a harness that injects the
 * same notion of time into both languages gets the same `duration_ms` out of both. The
 * emitter multiplies by 1000 and rounds to a whole millisecond, halves to the even neighbour,
 * which is what Python's `round` does.
 *
 * A source that steps backwards, throws, or returns something that is not a finite number
 * makes the span unmeasurable: the completion event is still emitted, `duration_ms` is
 * omitted, the event is downgraded to `partial` and marked with `observer_capture_gap`, and a
 * capture gap is reported. No lost event is counted for it, because the completion event was
 * still delivered. The emitter never writes an invented duration, because an omitted one says
 * the span is unknown while a fabricated one would be read as a measurement.
 *
 * When no source is injected, elapsed time comes from `performance.now()`. It never comes from
 * the `Clock`, not even one a caller injected, because a wall clock can be adjusted forwards or
 * backwards between two reads and a span measured with one would record time that never
 * elapsed. The Python emitter draws that line in the same place, defaulting to `time.monotonic`
 * and never falling back to its `clock`, so a fixture that injects only a clock gets a real
 * measurement from both rather than a clock-derived number from one of them. A test that needs
 * a pinned duration injects `monotonic` explicitly.
 *
 * On a host with no `performance.now()` at all there is no monotonic source to read: the
 * default reports every reading as unusable rather than substituting `Date.now()`, so the span
 * is omitted and marked as a capture gap the way any other unmeasurable span is. An omitted
 * duration says the span is unknown; one taken off a wall clock would be read as a measurement.
 */
export interface Monotonic {
  now(): number;
}
export interface IdFactory {
  next(prefix: string): string;
}
/**
 * An object a harness owns that accepts one finished event. `write` may be sync or async.
 *
 * It is vetted once, at construction, and only in a recording mode: a sink whose `write` is not
 * callable, and a sink or a `write` that is a generator function, are refused there rather than
 * left to fail per event. Off mode reads nothing off it at all. See `Observer`.
 */
export interface TraceSink {
  write(event: TraceEvent): void | Promise<void>;
}
/**
 * What capture lost, field for field with the Python `CaptureState` dataclass.
 *
 * `last_sink_error` is always present and is `null` until something fails, mirroring the
 * Python default of `None`, so a state snapshot from either language compares field for
 * field. It names the failure class rather than quoting an exception, because a sink's
 * error text can carry the payload it failed to write.
 *
 * `dropped_events` counts events no sink acknowledged taking, not scanner findings and not
 * instrumentation failures in general: a clock, ID, or elapsed-time read that failed sets
 * `capture_gap` and marks the event it degraded, but the sink still took that event, so it is
 * not counted here. `capture_gap` is therefore the broader flag, and it can be true while the
 * counter is zero. Zero is not a claim that the harness emitted everything it should have; it
 * only says nothing the harness did emit was lost here.
 *
 * Acknowledgement is the exact word, and it is the only thing either emitter can observe: a
 * sink is caller code neither looks inside, so an event counts as taken when the write returns
 * or its promise resolves, and a write cut short teaches the emitter nothing. JavaScript has no
 * cancellation, so here the only way a write is cut short is by throwing or rejecting, which is
 * the sink refusing the event. Python's `CaptureState` carries the longer form of this, for the
 * cancelled write it can have and this language cannot.
 */
export interface CaptureState {
  dropped_events: number;
  capture_gap: boolean;
  last_sink_error: string | null;
}
export type Redactor = (
  key: string,
  value: JsonValue,
  path: readonly string[],
) => JsonValue;
const categoryFor: Record<EventType, EventCategory> = {
  "model.request": "model",
  "model.response": "model",
  "tool.start": "tool",
  "tool.end": "tool",
  "context.selection": "context",
  "finding.candidate": "finding",
  "finding.validation": "finding",
  "finding.filtered": "finding",
  "finding.submitted": "finding",
  "observer.error": "observer",
};
const captureStatuses = new Set<CaptureStatus>([
  "complete",
  "partial",
  "redacted",
  "unavailable",
]);
/* The modes the wire contract names, spelled in the order the Python tuple spells them. A mode
   outside this set is a wiring mistake, refused at construction rather than read as some
   content-less recording mode nobody asked for. */
const recordingModes = new Set<RecordingMode>(["off", "metadata", "content"]);
/* Lifecycle links, in the order the wire contract lists them. */
const idFields = [
  "parent_event_id",
  "call_id",
  "attempt_id",
  "candidate_id",
  "claim_id",
] as const;
/* Every field a caller may supply. An unknown name is a rejected event, not a silently
   dropped one, because a misspelled field would make the record understate what the harness
   saw; TypeScript catches the typo at compile time, nothing catches it at a JS call site. */
const inputFields = new Set<string>([
  "type",
  "category",
  "capture_status",
  "metadata",
  "content",
  "duration_ms",
  ...idFields,
]);
/* One opaque message for every instrumentation failure, spelled as Python spells it. */
const gapMessage = "observer instrumentation failure";
/* Set in an event's metadata when instrumentation failed while that event was being built, or
   when its duration could not be measured. The name is reserved, and the emitter's claim on it
   runs one way: `true` is written here whenever a gap degraded the event, overwriting a caller
   value of the same name, and nothing at all is written when no gap occurred, so a caller that
   put this key in its own metadata keeps what it put there on an undegraded event. The emitter
   can only ever strengthen the claim the key makes, never weaken one: no event says "no gap"
   over a gap. Python behaves the same way, in `_GAP_KEY`. */
const gapKey = "observer_capture_gap";
/* The timestamp an event carries when the clock could not be read, spelled as Python spells it. */
const epochTimestamp = "1970-01-01T00:00:00.000Z";
/* Deliberately do not match input_tokens/output_tokens or other telemetry counters.
   The `i` flag folds ASCII only: without a `u` flag, JavaScript leaves a non-ASCII character
   whose uppercase is ASCII (for example U+017F long s) unmatched. Python spells the same rule
   re.IGNORECASE | re.ASCII, so the two default redactors hide the same key names. */
const secretKey =
  /^(?:api[_-]?key|authorization|credential(?:s)?|cookie(?:s)?|password|secret(?:s)?|token|private[_-]?key)$/i;
const defaultRedactor: Redactor = (key, value) =>
  secretKey.test(key) ? "[REDACTED]" : value;
/* A lone surrogate: a high surrogate with no low one after it, or a low one with no high one
   before it. A JavaScript string is a sequence of UTF-16 code units, so a PAIR is one real
   astral character and is left alone; only an unpaired half is not text at all. */
const unpairedSurrogate =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
/**
 * True when every code unit in `text` belongs to a character a UTF-8 sink can write.
 *
 * `JSON.stringify` escapes a lone surrogate as `\ud800`, so JavaScript would write a line that
 * parses, while Python holds the same code point in its string, copies it straight through
 * `json.dumps`, and only fails when a real JSONL file tries to encode it, losing the event at
 * write time. One payload, two outcomes. Both emitters refuse it instead, which is the stricter
 * shared rule: a payload the emitter cannot hand every sink is a capture gap, not a line that
 * means one thing here and nothing there. Python spells the same check over code points, where
 * every surrogate is by definition unpaired.
 */
function isEncodable(text: string): boolean {
  return !unpairedSurrogate.test(text);
}
/* The smallest magnitude both languages spell in plain decimal notation, and therefore the
   smallest number the wire carries that is not an integer. JavaScript switches to exponent
   notation below 1e-6 and Python's repr below 1e-4, and where both use an exponent they spell
   it differently: Python pads it to two digits, writing 1e-07 where JavaScript writes 1e-7. A
   smaller payload number would therefore leave the two emitters as different bytes, up to a
   point: below 1e-9 every exponent has two digits in both languages and the two agree again.
   Those are refused all the same, so the accepted range is one window rather than two with a
   hole from 1e-9 to 1e-4 in the middle of it. A harness carrying numbers that small scales
   them once, into a unit the wire carries, rather than discovering that 1e-10 is written and
   1e-8 is not. Python spells the same constant `_MIN_PLAIN_DECIMAL`; changing it changes the
   shared contract in both languages at once. */
const MIN_PLAIN_DECIMAL = 1e-4;
/**
 * The one spelling of a payload number both emitters write, or a throw refusing it.
 *
 * A number is stored only when JavaScript and Python write it as the same bytes. This is the
 * single place that decides that, for every number in every payload, because a trace one
 * language can write and the other cannot read is worse than a missing event: it looks
 * complete.
 *
 * An integral value must be a safe integer. Past `Number.MAX_SAFE_INTEGER` a JSON number stops
 * distinguishing neighbouring integers, so Python could hold a value this language would read
 * as a different one; that is the bound `duration_ms` already carries, applied to the numbers a
 * caller puts in a payload. A non-integral value must be at least `MIN_PLAIN_DECIMAL` in
 * magnitude, the plain decimal window the two share, including the magnitudes below 1e-9 where
 * the two agree again and this refuses them anyway; the constant says why. The window's upper
 * end needs no check: every double at or above 2 ** 52 is an integer, so a non-integral value
 * never reaches it.
 *
 * `-0` is normalized to `0`, which is what `JSON.stringify` writes for it anyway and what
 * Python's integral-float normalization produces, so the two hold the same value in memory as
 * well as writing the same bytes. Nothing else is coerced: a number outside the shared range is
 * a capture gap, never a rounded value, because a silently altered number would misdescribe the
 * run it claims to observe. Python's `_wire_number` draws all of these lines in the same place.
 */
function wireNumber(value: number): number {
  if (!Number.isFinite(value)) throw new TypeError("non-finite JSON number");
  if (!Number.isInteger(value)) {
    if (Math.abs(value) < MIN_PLAIN_DECIMAL) {
      throw new TypeError("JSON number below the shared plain-decimal window");
    }
    return value;
  }
  if (!Number.isSafeInteger(value)) {
    throw new TypeError("JSON number outside the shared safe-integer range");
  }
  return value === 0 ? 0 : value;
}
/** Python's `round`: a half goes to the even neighbour, so both languages write one integer. */
function roundHalfToEven(value: number): number {
  const floor = Math.floor(value);
  const remainder = value - floor;
  if (remainder > 0.5) return floor + 1;
  if (remainder < 0.5) return floor;
  return floor % 2 === 0 ? floor : floor + 1;
}
/**
 * The one test for an object the emitter can store, asked by every path that has to decide.
 *
 * A stored payload object is a plain object: an object literal, or one built on a null
 * prototype. An array, a `Map`, a `Date`, a boxed primitive and a class instance all fail it,
 * because copying one would either invent keys it does not carry or drop the state it does.
 *
 * It is one function because this used to be two tests that disagreed. `validInput` asked only
 * whether a value was a non-array object, while `copyJson` applied the plain-prototype rule, so
 * a `content` built on some other prototype was refused in `content` mode, where the copy runs,
 * and accepted in `metadata` mode, where it does not. The recording mode decided what shape of
 * payload was acceptable, which is not something a mode may decide. One predicate answers for
 * the gate and for the copy now, so there is no mode in which the two can differ. Python asks
 * the same question in the same two places, in `_is_payload_object`.
 */
function isJsonObject(value: unknown): value is JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
/**
 * Deep copy into plain JSON types, refusing anything that would not survive the wire.
 *
 * `depth` counts the containers already entered, so the payload object itself is checked at
 * depth 0 and nesting beyond `MAX_PAYLOAD_DEPTH` containers is refused. Non-finite numbers,
 * numbers outside the range both languages write alike, cycles, non-plain objects, values that
 * are not JSON, and a string or key carrying an unpaired surrogate are refused too. This is a
 * copy, not a coercion: nothing is stringified or truncated to make it fit. The one thing it
 * normalizes is `-0`, in `wireNumber`, which chooses between two spellings of one value rather
 * than changing the value.
 *
 * It refuses rather than drops, which is why the own properties are read through
 * `getOwnPropertyNames` and `getOwnPropertySymbols` instead of `Object.keys`. A symbol-keyed
 * property is JavaScript's own spelling of the non-string object key Python's `_copy_json`
 * refuses, and a non-enumerable own property is a value the caller put in the payload; walking
 * with `Object.keys` silently left both out of the stored copy, so a payload could be stored
 * short of what it carried with nothing marking the event. A dropped property misdescribes the
 * run exactly as a truncated one would, so both are a refusal and therefore a capture gap.
 */
function copyJson(
  value: JsonValue,
  seen = new WeakSet<object>(),
  depth = 0,
): JsonValue {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    // Refused rather than escaped: a lone surrogate is a line Python's sink cannot encode, and
    // the two emitters would otherwise write different bytes for the same payload.
    if (!isEncodable(value)) {
      throw new TypeError("JSON string carries an unpaired surrogate");
    }
    return value;
  }
  if (typeof value === "number") return wireNumber(value);
  if (typeof value !== "object") throw new TypeError("non-JSON value");
  if (depth >= MAX_PAYLOAD_DEPTH) {
    throw new TypeError("JSON value nested deeper than MAX_PAYLOAD_DEPTH");
  }
  if (seen.has(value)) throw new TypeError("cyclic JSON value");
  seen.add(value);
  if (Array.isArray(value)) {
    const result = value.map((item) => copyJson(item, seen, depth + 1));
    seen.delete(value);
    return result;
  }
  // The same predicate the input gate asks, so the copy cannot refuse a shape the gate allowed.
  if (!isJsonObject(value)) throw new TypeError("non-plain JSON object");
  if (Object.getOwnPropertySymbols(value).length > 0) {
    // JavaScript's non-string object key. Python refuses one outright rather than dropping it.
    throw new TypeError("non-string JSON object key");
  }
  const result = Object.create(null) as JsonObject;
  for (const key of Object.getOwnPropertyNames(value)) {
    if (!isEncodable(key)) {
      throw new TypeError("JSON object key carries an unpaired surrogate");
    }
    if (!Object.getOwnPropertyDescriptor(value, key)!.enumerable) {
      // Storing the payload without it would record less than the caller handed over, and
      // nothing on the event would say so.
      throw new TypeError("non-enumerable JSON object property");
    }
    Object.defineProperty(result, key, {
      value: copyJson(value[key], seen, depth + 1),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  seen.delete(value);
  return result;
}
/**
 * Apply the redactor at every object key and report whether anything was replaced.
 *
 * A value counts as redacted when the redactor handed back something that is not the value it
 * was given, decided by JavaScript strict inequality (`!==`): an immutable scalar (string,
 * number, boolean, null) compares by value, and a container compares by identity, so a
 * redactor that rebuilds an equal object still marks the event redacted while one that returns
 * the same string changes nothing. That is the shared rule, and the Python emitter mirrors
 * these semantics rather than using its own identity test on scalars. The redactor sees keys,
 * never bare list elements, and its replacement is copied and walked again, at the depth it
 * sits at, because a redactor is caller code and no more trusted than the payload it replaced.
 */
function redact(
  value: JsonValue,
  redactor: Redactor,
  path: string[] = [],
  depth = 0,
): { value: JsonValue; redacted: boolean } {
  if (Array.isArray(value)) {
    let changed = false;
    const copied = value.map((item, index) => {
      const result = redact(item, redactor, [...path, String(index)], depth + 1);
      changed ||= result.redacted;
      return result.value;
    });
    return { value: copied, redacted: changed };
  }
  if (value !== null && typeof value === "object") {
    const output = Object.create(null) as JsonObject;
    let changed = false;
    for (const key of Object.keys(value)) {
      const original = value[key];
      const replacement = redactor(key, original, path);
      // A custom redactor is untrusted instrumentation: validate/copy its output too, and hold
      // it to the same depth budget so a replacement cannot smuggle in deeper nesting.
      const nested = redact(
        copyJson(replacement, new WeakSet<object>(), depth + 1),
        redactor,
        [...path, key],
        depth + 1,
      );
      // Strict inequality: scalars by value, containers by identity.
      changed ||= replacement !== original || nested.redacted;
      Object.defineProperty(output, key, {
        value: nested.value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return { value: output, redacted: changed };
  }
  return { value, redacted: false };
}
/**
 * Elapsed time from `performance.now()`, read in seconds, and from nothing else.
 *
 * A host without `performance.now()` offers this emitter no monotonic source, so every reading
 * is reported as unusable: `NaN` is what `readMonotonic` already refuses, so the span is omitted
 * and the event is marked, exactly as a source that throws or steps backwards is handled.
 * `Date.now()` is deliberately not the fallback. It is a wall clock, it can be adjusted between
 * two reads, and a duration taken off it would be read as a measurement of work that may never
 * have taken that long.
 */
function defaultMonotonic(): Monotonic {
  const host = (globalThis as { performance?: { now?: () => number } })
    .performance;
  const highResolution = host?.now;
  if (typeof highResolution === "function") {
    return { now: () => highResolution.call(host) / 1000 };
  }
  return { now: () => Number.NaN };
}
/* The two prototypes every generator function and async generator function is built on, read
   once from generators this module owns. Classifying a caller's function by comparing its
   prototype runs none of the caller's code, which is the point: Python reads `__call__` off the
   type for the same reason. `instanceof` and `Symbol.toStringTag` would both consult properties
   a caller can define. */
const generatorFunctionPrototype = Object.getPrototypeOf(function* () {});
const asyncGeneratorFunctionPrototype = Object.getPrototypeOf(async function* () {});
/**
 * True when calling `target` would return an iterator instead of writing anything.
 *
 * A generator function and an async generator function are the same wiring mistake: calling
 * either builds an iterator nobody drives, so the sink writes nothing and reports no loss,
 * which is the quietest way for a trace to be empty. This is the analogue of the Python
 * `_is_generator_callable`.
 */
function isGeneratorCallable(target: unknown): boolean {
  if (typeof target !== "function") return false;
  const prototype = Object.getPrototypeOf(target);
  return prototype === generatorFunctionPrototype ||
    prototype === asyncGeneratorFunctionPrototype;
}
/* The prototypes every generator object and async generator object inherits, read once from
   generators this module owns. A caller's `write` may RETURN one of these rather than being a
   generator function, which `isGeneratorCallable` cannot see: that shape is only visible in the
   value the write handed back. Comparing prototypes runs none of the caller's code, which is
   why the value is not asked what it is. */
const generatorObjectPrototype = Object.getPrototypeOf(
  Object.getPrototypeOf((function* () {})()),
);
const asyncGeneratorObjectPrototype = Object.getPrototypeOf(
  Object.getPrototypeOf((async function* () {})()),
);
/**
 * True when a write handed back a generator instead of writing.
 *
 * The wiring guard classifies a callable, so a `write` that merely returns a generator passes
 * it: calling such a function runs none of its body, the sink reports no failure, and every
 * event is lost behind a capture state that still reads clean. That shape is caught here
 * instead, at write time, and counted as a lost event, because the value written was never
 * consumed. The emitter does not drive the iterator: consuming a caller's stream is not
 * instrumentation's to do. Python's `_is_undriven_generator` makes the same call on the same
 * two shapes, where the type can be compared exactly.
 *
 * The prototype chain is walked rather than the object questioned, because asking an object
 * what it is reads properties a caller wrote and runs their code. That buys the guarantee at a
 * stated price: a generator whose function's `prototype` was reassigned to a plain object
 * carries no marker on its chain and is not recognized here, and no check that runs none of
 * the caller's code can see it. The shape this catches is the one a harness actually writes.
 */
function isUndrivenGenerator(value: unknown): boolean {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function")
  ) return false;
  let prototype = Object.getPrototypeOf(value as object);
  while (prototype !== null) {
    if (
      prototype === generatorObjectPrototype ||
      prototype === asyncGeneratorObjectPrototype
    ) return true;
    prototype = Object.getPrototypeOf(prototype);
  }
  return false;
}
/**
 * Vet the one callable a sink exposes, or throw. Called only in a recording mode.
 *
 * These are wiring mistakes, not runtime failures, so they are refused here, at construction,
 * the way the Python `_normalize_sink` refuses them: a harness author fixes wiring once, before
 * a run, while nothing during a scan may raise. Left to runtime, a sink with no callable
 * `write` costs one lost event per emit and a generator function costs every event in silence,
 * with a capture state that still reads clean. The check is syntactic, so a `write` that
 * returns a generator instead of being one passes it and is caught at write time by
 * `isUndrivenGenerator` instead, where the returned iterator is visible. Reading `write` can
 * run a caller's getter, so a failure there is reported as an unusable sink rather than
 * allowed out of the constructor as whatever it threw.
 */
function vetSink(sink: unknown): TraceSink {
  if (isGeneratorCallable(sink)) {
    throw new TypeError(
      "sink must not be a generator function: calling one returns an iterator and writes nothing",
    );
  }
  let write: unknown;
  try {
    write = (sink as { write?: unknown } | null)?.write;
  } catch {
    throw new TypeError("reading sink.write threw, so the sink cannot be used");
  }
  if (typeof write !== "function") {
    throw new TypeError("sink must expose a callable write method");
  }
  if (isGeneratorCallable(write)) {
    throw new TypeError(
      "sink.write must not be a generator function: calling one returns an iterator and writes nothing",
    );
  }
  return sink as TraceSink;
}
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
/**
 * Emits trace events a harness hands it, and never anything it was not handed.
 *
 * Every option is optional. `mode` defaults to `off`, which makes `emit` a no-op; `metadata`
 * stores events without content; `content` stores a copied, redacted content payload as well.
 * An unknown mode and an unusable sink both throw here, at construction, because a harness
 * author fixes wiring once at wiring time and nothing during a scan raises. An unusable sink is
 * one whose `write` is not callable, one whose `write` is a generator or async generator
 * function, and the sink itself being such a function: calling one of those returns an iterator
 * and writes nothing. A `write` that returns a generator rather than being one is the same
 * silence in a shape no wiring check can see, so it constructs and is counted at write time,
 * one lost event per event it swallowed. The mode is checked before anything else, and an
 * unknown mode is by definition not `off`, so there is no mode in which a misspelled one is
 * tolerated. In `off`
 * mode the sink is not inspected at all, not even for that `write` property: a getter there is
 * caller code, and an observer that records nothing must run none of it.
 *
 * A recording mode with no sink at all is allowed and is not silent: `emit` still builds the
 * event and resolves with it, so the observer can be used as a builder, but every event it
 * builds reached nobody and is counted as a lost event in `CaptureState`. That is the
 * deliberate half of the choice: the returned event is a real use, and a state reporting zero
 * for events nobody received would be a black hole. The Python `Observer` makes the same two
 * choices.
 */
export class Observer {
  private sequence = 0;
  private fallbackSequence = 0;
  private isClosed = false;
  private readonly pending = new Set<Promise<TraceEvent | undefined>>();
  private readonly state: CaptureState = {
    dropped_events: 0,
    capture_gap: false,
    last_sink_error: null,
  };
  /* Every gap, counted as a loss or not, so `emitInternal` can tell that instrumentation failed
     while an event was being built even when that failure lost no event. It is not reported:
     `CaptureState` carries the three fields Python's carries and no fourth. */
  private gaps = 0;
  private readonly mode: RecordingMode;
  private readonly sink?: TraceSink;
  private readonly clock: Clock;
  private readonly monotonic: Monotonic;
  private readonly ids: IdFactory;
  private readonly redactor: Redactor;
  readonly runId: string;
  readonly producerId: string;
  constructor(options: ObserverOptions = {}) {
    // The mode is settled first, as in Python, and an unknown one is refused outright: it can
    // never be `off`, so there is no mode whose privileges could excuse it.
    const mode = options.mode ?? "off";
    if (!recordingModes.has(mode)) {
      throw new TypeError(`unknown recording mode: ${JSON.stringify(options.mode)}`);
    }
    this.mode = mode;
    // Off mode reads nothing off the caller's sink, not even a property: a descriptor there is
    // caller code, and an observer that records nothing must run none of it. An absent sink is
    // builder mode, which is allowed and counts each built event as a lost one.
    this.sink = mode === "off" || options.sink === undefined || options.sink === null
      ? undefined
      : vetSink(options.sink);
    this.clock = options.clock ?? { now: () => new Date() };
    // The same choice the Python emitter makes: the injected monotonic source, else a real
    // monotonic source, and never the clock. A wall clock can be adjusted between two reads, so
    // a span measured with one is time that may never have elapsed, and an injected clock is
    // still a wall clock. A fixture that needs a pinned duration injects `monotonic`.
    this.monotonic = options.monotonic ?? defaultMonotonic();
    let n = 0;
    this.ids = options.idFactory ??
      {
        next: (prefix) =>
          prefix + "-" + (++n) + "-" + Math.random().toString(36).slice(2),
      };
    this.redactor = options.redactor ?? defaultRedactor;
    // Off mode must not invoke user-provided ID factories merely by being used.
    this.runId = this.validId(options.runId)
      ? options.runId
      : this.mode === "off"
      ? "off"
      : this.nextId("run");
    this.producerId = this.validId(options.producerId)
      ? options.producerId
      : this.mode === "off"
      ? "off"
      : this.nextId("producer");
  }
  /** True once `close` has run. A closed observer records gaps instead of events. */
  get closed(): boolean {
    return this.isClosed;
  }
  getState(): CaptureState {
    return { ...this.state };
  }
  /**
   * Wait for writes started by emit/observeAsync after the harness operation has finished.
   *
   * It drains until the set is empty rather than awaiting one snapshot of it, because a write
   * started while the flush was already waiting belongs to this flush too: awaiting a snapshot
   * resolved with that write still outstanding, and a harness that read `getState` next saw a
   * clean capture state for an event no sink had taken yet. The Python `aflush` loops over its
   * pending map for the same reason, so the two settle the same set of writes.
   *
   * A never-settling sink also makes flush wait forever. It never rejects: a write that
   * somehow failed is already a recorded gap, and an awaiting harness must not inherit an
   * instrumentation failure as its own error.
   */
  async flush(): Promise<void> {
    while (this.pending.size > 0) {
      const batch = [...this.pending];
      await Promise.all(
        batch.map((write) => write.then(() => undefined, () => undefined)),
      );
      // Each write removes itself as it settles; removing the batch here as well means the
      // loop condition reads the set rather than racing the handlers that empty it.
      for (const write of batch) this.pending.delete(write);
    }
  }
  /**
   * Flush, then refuse later events. It closes no caller resource.
   *
   * This is the analogue of the Python `aclose`. After it, `emit` counts a lost event and
   * resolves undefined instead of writing, so an event that arrives after the run it belongs
   * to is visible as loss rather than silently postdating that run. In `off` mode there is
   * nothing to close and a later emit still records nothing, gap included. Calling it twice is
   * harmless. A sink the caller opened stays the caller's to close.
   *
   * The drain and the flag are one loop because `await` is a turn of the microtask queue:
   * something scheduled in that turn can emit between the last drain and the flag, and a close
   * that resolved there would report a finished run with a write still outstanding. Once the
   * flag is set no further write can start, so the loop runs at most one more time. Python has
   * no such gap, because nothing runs between its `aflush` returning and `_closed` being set.
   */
  async close(): Promise<void> {
    do {
      await this.flush();
      this.isClosed = true;
    } while (this.pending.size > 0);
  }
  /**
   * Capture broke here, but no event was lost by it.
   *
   * The clock, the ID factory, and the elapsed-time source reach here: their failure leaves a
   * delivered event carrying a fabricated or absent field, which `emitInternal` marks in the
   * event itself. Counting it in `dropped_events` would claim a loss that did not happen, so
   * this is the half of the Python split that `_mark_gap` is, and `lostEvent` is the other.
   */
  private markGap(): void {
    this.gaps += 1;
    this.state.capture_gap = true;
    this.state.last_sink_error = gapMessage;
  }
  /** One event reached no sink. Counted once, by whichever guard owns that loss. */
  private lostEvent(): void {
    this.markGap();
    this.state.dropped_events += 1;
  }
  private nextId(prefix: string): string {
    try {
      const id = this.ids.next(prefix);
      // The shared validator, not a local spelling of part of it: a factory is caller code, so
      // the id it hands back is held to exactly what a caller-supplied ID is held to. Checking
      // only the type and the length here let an id carrying an unpaired surrogate reach the
      // wire, where Python's `_next_id` refused the same value through `_is_id`.
      if (!this.validId(id)) throw new TypeError("invalid id");
      return id;
    } catch {
      this.markGap();
      return prefix + "-fallback-" + (++this.fallbackSequence);
    }
  }
  /**
   * A usable wire string: a nonempty string of characters a UTF-8 sink can write.
   *
   * The surrogate rule a payload string is held to is the rule every caller string on the wire
   * is held to, because a lone surrogate in a link ID, a run ID, a producer ID, an ID a factory
   * produced, or a timestamp a caller's clock spelled costs the same line the same way. This is
   * where every one of them is decided, so there is no second, weaker spelling of the rule for
   * one of the paths to use. Python decides the same set in `_is_id`.
   */
  private validId(value: unknown): value is string {
    return typeof value === "string" && value.length > 0 && isEncodable(value);
  }
  /**
   * The wall-clock reading, as the wire spells it, or the epoch with one gap.
   *
   * The string is held to `validId` like any other caller string on the wire: a `Clock` is
   * typed to hand back a `Date`, but nothing at a JavaScript call site makes it, and a stand-in
   * whose `toISOString` returns something no UTF-8 sink can write would otherwise put it in
   * every event. Python reaches the same place from the other side, refusing a clock reading
   * that is not an aware `datetime` and spelling the timestamp itself.
   */
  private now(): string {
    try {
      const timestamp = this.clock.now().toISOString();
      if (!this.validId(timestamp)) throw new TypeError("invalid clock");
      return timestamp;
    } catch {
      this.markGap();
      return epochTimestamp;
    }
  }
  /** Read the elapsed-time source in seconds, or null with one gap when it is unusable. */
  private readMonotonic(): number | null {
    let value: unknown;
    try {
      value = this.monotonic.now();
    } catch {
      this.markGap();
      return null;
    }
    if (typeof value !== "number" || !Number.isFinite(value)) {
      this.markGap();
      return null;
    }
    return value;
  }
  /**
   * Whole milliseconds between two reads, or undefined when the span cannot be measured.
   *
   * A failed read, a non-finite span, a source that went backwards, and a span too large to be
   * a safe integer all yield undefined and one capture gap, which counts no lost event: the
   * completion event is still emitted, without the duration. The emitter never invents a
   * duration: an omitted one says the span is unknown, a fabricated one would be read as a
   * measurement.
   */
  private elapsedMs(began: number | null): number | undefined {
    if (began === null) return undefined;
    const ended = this.readMonotonic();
    if (ended === null) return undefined;
    const elapsed = (ended - began) * 1000;
    if (!Number.isFinite(elapsed) || elapsed < 0) {
      this.markGap();
      return undefined;
    }
    const whole = roundHalfToEven(elapsed);
    if (!Number.isSafeInteger(whole)) {
      this.markGap();
      return undefined;
    }
    return whole;
  }
  private downgradedStatus(
    requested: CaptureStatus,
    redacted: boolean,
  ): CaptureStatus {
    return requested === "unavailable"
      ? "unavailable"
      : redacted
      ? "redacted"
      : this.mode === "metadata" && requested === "complete"
      ? "partial"
      : requested;
  }
  /**
   * Record one event, resolving with it, or with undefined when nothing was recorded.
   *
   * It resolves for every input. An event the wire contract refuses, a redactor, clock, ID
   * factory or sink that throws anything at all, a payload that is not JSON or is nested too
   * deeply, and an emit after `close` are all capture gaps, so instrumentation cannot become
   * the caller's exception. The ones that stopped the event reaching a sink are counted in
   * `dropped_events` as well; a failure that only degraded a delivered event, such as a clock
   * read that threw, is a gap on that event and is not counted. An observer in a recording
   * mode with no sink still builds and resolves with the event, and counts each one as lost,
   * because it reached nobody. In off mode this resolves undefined without touching the clock,
   * the ID factory, the redactor, or the sink, and without counting a gap even when the
   * observer is closed, because an observer that records nothing has lost nothing.
   */
  emit(input: EventInput): Promise<TraceEvent | undefined> {
    return this.emitEvent(input, false);
  }
  private emitEvent(
    input: EventInput,
    dropDuration: boolean,
  ): Promise<TraceEvent | undefined> {
    if (this.mode === "off") return Promise.resolve(undefined);
    if (this.isClosed) {
      // The event arrived after the run it belongs to and reaches no sink, so it is a loss.
      this.lostEvent();
      return Promise.resolve(undefined);
    }
    const write = this.emitInternal(input, dropDuration).catch(() => {
      // emitInternal already handles its own failures; this guarantees the contract holds
      // even if that ever stops being true, rather than rejecting into a caller's await.
      this.lostEvent();
      return undefined;
    });
    this.pending.add(write);
    void write.then(
      () => this.pending.delete(write),
      () => this.pending.delete(write),
    );
    return write;
  }
  /**
   * Read the caller's input once, so validation and building see the same event.
   *
   * A caller's object is caller code: a getter read twice may answer differently the second
   * time and put a value in the record that no check ever saw, which is how a negative
   * `duration_ms` or a missing `metadata` would reach the wire with no capture gap to show for
   * it. Every field is read exactly once here, and metadata, plus content when it will be
   * stored, are deep copied at the same moment for the same reason. This mirrors the Python
   * `_snapshot`.
   *
   * What counts as a payload object worth copying is `isJsonObject`, the same test `validInput`
   * applies, so a payload this declines to copy is one the gate refuses rather than one that
   * slips through unstored.
   */
  private snapshot(input: EventInput): Record<string, unknown> {
    const raw = input as unknown;
    if (raw === null || typeof raw !== "object") {
      throw new TypeError("trace event input must be an object");
    }
    const supplied = raw as Record<string, unknown>;
    const snapshot = Object.create(null) as Record<string, unknown>;
    for (const name of Object.keys(supplied)) {
      snapshot[name] = supplied[name];
    }
    if (isJsonObject(snapshot["metadata"])) {
      snapshot["metadata"] = copyJson(snapshot["metadata"]);
    }
    if (this.mode === "content" && isJsonObject(snapshot["content"])) {
      snapshot["content"] = copyJson(snapshot["content"]);
    }
    return snapshot;
  }
  /**
   * Check a snapshot against the wire contract. The rejection set is a contract, not a detail.
   *
   * It has to match the Python emitter name for name, because a rejected event consumes no
   * sequence number, no event ID, and no clock read in either language: that is only safe
   * while both refuse exactly the same inputs. Refused here: an unknown field name, an
   * unknown type, a category that contradicts the type, an unknown capture status, a missing
   * metadata or one that is not a storable object, a content that is present and is not one, a
   * `duration_ms` that is null, not a number,
   * boolean, non-finite, non-integral, negative, or beyond the safe integer range, and a link
   * ID that is present but is not a usable one. Absent is spelled `undefined`; an
   * explicit null is a rejection, never a shorthand for absent. It reads the snapshot, never
   * the caller's object, so what is validated is exactly what is built.
   *
   * "Storable object" is `isJsonObject`, the one test the copy applies too, and it is applied
   * to `content` in every recording mode. The mode decides whether content is stored, never
   * what a caller may hand over: gating it on the looser "any non-array object" test here left
   * `metadata` mode accepting a payload `content` mode refused. Whether a link ID is usable is
   * `validId`, the one test every caller string on the wire passes.
   */
  private validInput(snapshot: Record<string, unknown>): boolean {
    for (const name of Object.keys(snapshot)) {
      if (!inputFields.has(name)) return false;
    }
    const type = snapshot["type"];
    if (
      typeof type !== "string" ||
      !Object.prototype.hasOwnProperty.call(categoryFor, type)
    ) return false;
    const category = snapshot["category"];
    if (
      category !== undefined && category !== categoryFor[type as EventType]
    ) return false;
    if (!captureStatuses.has(snapshot["capture_status"] as CaptureStatus)) {
      return false;
    }
    if (!isJsonObject(snapshot["metadata"])) return false;
    if (
      snapshot["content"] !== undefined && !isJsonObject(snapshot["content"])
    ) return false;
    if (!this.validDuration(snapshot["duration_ms"])) return false;
    return idFields.every((name) =>
      snapshot[name] === undefined || this.validId(snapshot[name])
    );
  }

  /**
   * A duration is absent or a whole, nonnegative, safe-integer count of milliseconds.
   *
   * Null is not absent. Beyond `Number.MAX_SAFE_INTEGER` a JavaScript number no longer
   * distinguishes neighbouring integers, so such a value is not a millisecond count that
   * survives a round trip and is refused rather than written as an approximation. Python
   * refuses the same range, which keeps one rejection set across the two.
   */
  private validDuration(value: unknown): boolean {
    if (value === undefined) return true;
    if (typeof value !== "number") return false;
    return Number.isSafeInteger(value) && value >= 0;
  }
  /**
   * Build one event and hand it to the sink. It never rejects and never throws to a caller.
   *
   * Validation runs on a snapshot of the caller's input before anything is consumed, so a
   * rejected event takes no sequence number, no event ID, and no clock read, exactly as in
   * Python, and the event that is built is the event that was checked. Keys are written in the
   * order the wire schema declares them, link fields and `duration_ms` ahead of `metadata`, so
   * a JSONL line from either language reads as the schema does. Every failure, including a
   * thrown value that is not an Error, becomes a capture gap, and an event that reached no sink
   * is counted once, at one of two statements: the `catch` that owns the build, and the
   * `finally` that every exit from the write crosses. When `dropDuration` is set, or
   * when instrumentation failed while this event was being built, the event is downgraded to
   * `partial` unless it is already `unavailable` and its metadata is marked with
   * `observer_capture_gap`, so a reader cannot take a fabricated ID, an epoch timestamp, or a
   * missing duration for a measurement. "Instrumentation failed while building this" is read
   * off `gaps`, every gap whether or not it lost an event, rather than off `dropped_events`,
   * which the degrading failures deliberately no longer touch; Python compares its own `_gaps`
   * for the same reason. A build that failed, a write that threw, and an event nobody was
   * there to receive are the losses, and each is counted once.
   */
  private async emitInternal(
    input: EventInput,
    dropDuration: boolean,
  ): Promise<TraceEvent | undefined> {
    if (this.mode === "off") return undefined;
    let event: TraceEvent;
    const gapsBefore = this.gaps;
    try {
      const snapshot = this.snapshot(input);
      if (dropDuration) delete snapshot["duration_ms"];
      if (!this.validInput(snapshot)) {
        throw new TypeError("invalid trace event input");
      }
      const type = snapshot["type"] as EventType;
      const metadata = redact(snapshot["metadata"] as JsonObject, this.redactor);
      const suppliedContent = snapshot["content"];
      const content = this.mode === "content" && suppliedContent !== undefined
        ? redact(suppliedContent as JsonObject, this.redactor)
        : undefined;
      const stored = metadata.value as JsonObject;
      event = {
        schema_version: SCHEMA_VERSION,
        event_id: this.nextId("event"),
        run_id: this.runId,
        producer_id: this.producerId,
        sequence: this.sequence++,
        type,
        category: categoryFor[type],
        capture_status: this.downgradedStatus(
          snapshot["capture_status"] as CaptureStatus,
          metadata.redacted || content?.redacted === true,
        ),
        timestamp: this.now(),
        ...(snapshot["parent_event_id"] === undefined
          ? {}
          : { parent_event_id: snapshot["parent_event_id"] as string }),
        ...(snapshot["call_id"] === undefined
          ? {}
          : { call_id: snapshot["call_id"] as string }),
        ...(snapshot["attempt_id"] === undefined
          ? {}
          : { attempt_id: snapshot["attempt_id"] as string }),
        ...(snapshot["candidate_id"] === undefined
          ? {}
          : { candidate_id: snapshot["candidate_id"] as string }),
        ...(snapshot["claim_id"] === undefined
          ? {}
          : { claim_id: snapshot["claim_id"] as string }),
        ...(snapshot["duration_ms"] === undefined
          ? {}
          : { duration_ms: snapshot["duration_ms"] as number }),
        metadata: stored,
        ...(content ? { content: content.value as JsonObject } : {}),
      };
      if (dropDuration || this.gaps > gapsBefore) {
        if (event.capture_status !== "unavailable") {
          event.capture_status = "partial";
        }
        Object.defineProperty(stored, gapKey, {
          value: true,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
    } catch {
      // The one exit for an event that was never built. It reached no sink either, so it is
      // counted here, and the write below never runs for it.
      this.lostEvent();
      return undefined;
    }
    let delivered = false;
    try {
      if (!this.sink) {
        // A recording mode with no sink. The event was built, spent a sequence number and an
        // ID, and reached nobody, so it is a lost event rather than a clean state. It is still
        // returned, because builder mode is a real use; only the accounting says so.
        return event;
      }
      const written: unknown = this.sink.write(event);
      if (isUndrivenGenerator(written)) {
        // The sink returned an iterator rather than writing. Its body never ran, so this event
        // reached nobody: the value written was never consumed, and a state that still read
        // clean here would claim a delivery that never happened.
        return event;
      }
      await written;
      delivered = true;
    } catch {
      // Contained: a sink that threw or rejected still leaves a built event to return, and the
      // `finally` below is what says the event it carried reached nobody.
    } finally {
      // Every exit from the write crosses this: no sink, an iterator instead of a write, a
      // throw, a rejection, and the one path that delivered. That is the rule the Python
      // `_Delivery` record enforces where there are more ways out, written here as the one
      // statement a JavaScript write can reach it by.
      if (!delivered) this.lostEvent();
    }
    return event;
  }
  /**
   * Build an event from a caller's callback and emit it without awaiting the write.
   *
   * The callback is caller code. Anything it throws, Error or not, loses that event and is a
   * counted capture gap here, and never reaches the operation being observed.
   */
  private emitDetached(build: () => EventInput): void {
    try {
      void this.emit(build());
    } catch {
      this.lostEvent();
    }
  }
  /**
   * Emit the event that closes an observed operation, with its measured duration or none.
   *
   * When the span could not be measured the builder is told so, by being handed undefined, and
   * any `duration_ms` it returns anyway is dropped from the event, which is still emitted,
   * downgraded to `partial`, and marked with `observer_capture_gap`. The gap for the failed
   * measurement was already flagged once by the read that failed, and it counts no loss because
   * the completion event is still delivered. A builder that throws is the other case: that
   * event reaches nobody, so it is counted.
   */
  private emitCompletion(
    build: (durationMs: number | undefined) => EventInput,
    began: number | null,
  ): void {
    try {
      const elapsed = this.elapsedMs(began);
      void this.emitEvent(build(elapsed), elapsed === undefined);
    } catch {
      this.lostEvent();
    }
  }
  /**
   * Promise-boundary helper. It never consumes/wraps streams; timing ends at Promise
   * resolution, not at a returned stream's end.
   *
   * The operation's value is returned untouched and its error is re-thrown as the original
   * value, whatever was thrown. Every instrumentation failure around it, including a callback
   * or sink that throws a string, a symbol, or null, is recorded as a capture gap instead.
   * `duration_ms` is a whole number of milliseconds measured with the monotonic source, never
   * with the wall clock, so a clock that steps backwards or a source that fails costs the
   * duration and not the completion event: the builders are handed undefined, the event is
   * emitted without `duration_ms`, downgraded to `partial`, and marked with
   * `observer_capture_gap`.
   */
  async observeAsync<T>(
    start: EventInput,
    success: (duration_ms: number | undefined) => EventInput,
    failure: (error: unknown, duration_ms: number | undefined) => EventInput,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (this.mode === "off") return operation();
    this.emitDetached(() => start);
    const began = this.readMonotonic();
    let value: T;
    try {
      value = await operation();
    } catch (error) {
      this.emitCompletion((elapsed) => failure(error, elapsed), began);
      throw error;
    }
    this.emitCompletion((elapsed) => success(elapsed), began);
    return value;
  }
}
/**
 * Adapt a caller-owned JSONL writer; the SDK never opens files automatically.
 *
 * A generator or async generator function is refused here, at creation, exactly as the
 * constructor refuses a sink that is one: calling it returns an iterator nobody drives, so the
 * line is never written, the sink reports no failure, and every event is lost in silence behind
 * a capture state that still reads clean. This is `isGeneratorCallable`, the classification
 * `vetSink` already applies to a sink, applied one layer down to the writer a sink is built
 * from. The Python `create_jsonl_sink` refuses the same writer for the same reason. A writer
 * that is an ordinary function returning an undriven generator cannot be classified from the
 * outside and is not refused here: the observer writing through this sink sees the iterator
 * that comes back and counts the event as lost.
 */
export function createJsonlSink(
  writeLine: (line: string) => void | Promise<void>,
): TraceSink {
  if (isGeneratorCallable(writeLine)) {
    throw new TypeError(
      "jsonl writeLine must not be a generator function: calling one returns an iterator and writes nothing",
    );
  }
  return { write: (event) => writeLine(JSON.stringify(event) + "\n") };
}
