/**
 * A deliberately small, opt-in observer emitter. Importing it records nothing.
 *
 * It is behaviorally matched to the Python emitter in `src/scaneval/observer`: the two accept
 * and reject the same inputs, write the same keys in the wire schema's declaration order,
 * redact by the same ASCII key-name rule, decide "was this value replaced" by the same
 * strict-inequality rule, refuse the same payload nesting depth, and report the same capture
 * state fields. A rejected event consumes no sequence number, no event ID, and no clock read;
 * that is only safe because the rejection sets are identical, so the rule in `validInput` is a
 * contract rather than an implementation detail. Where the two once differed, the stricter rule
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
 * omitted, the event is downgraded to `partial` and marked with `observer_capture_gap`, and
 * one capture gap is counted. The emitter never writes an invented duration, because an
 * omitted one says the span is unknown while a fabricated one would be read as a measurement.
 *
 * When no source is injected, elapsed time is derived from the injected `Clock` if there is
 * one, so a test with a fixed clock measures against that clock, and otherwise from
 * `performance.now()`, falling back to `Date.now()` on a host without it. Deriving from a wall
 * clock inherits the wall clock's jumps; that is why an injectable monotonic source exists.
 */
export interface Monotonic {
  now(): number;
}
export interface IdFactory {
  next(prefix: string): string;
}
export interface TraceSink {
  write(event: TraceEvent): void | Promise<void>;
}
/**
 * What capture lost, field for field with the Python `CaptureState` dataclass.
 *
 * `last_sink_error` is always present and is `null` until something fails, mirroring the
 * Python default of `None`, so a state snapshot from either language compares field for
 * field. It names the failure class rather than quoting an exception, because a sink's
 * error text can carry the payload it failed to write. `dropped_events` counts
 * instrumentation failures, not scanner findings; zero is not a claim that the harness
 * emitted everything it should have.
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
   when its duration could not be measured. The emitter owns this key and overwrites a caller
   value of the same name, which is the Python behavior too. */
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
/** Python's `round`: a half goes to the even neighbour, so both languages write one integer. */
function roundHalfToEven(value: number): number {
  const floor = Math.floor(value);
  const remainder = value - floor;
  if (remainder > 0.5) return floor + 1;
  if (remainder < 0.5) return floor;
  return floor % 2 === 0 ? floor : floor + 1;
}
/**
 * Deep copy into plain JSON types, refusing anything that would not survive the wire.
 *
 * `depth` counts the containers already entered, so the payload object itself is checked at
 * depth 0 and nesting beyond `MAX_PAYLOAD_DEPTH` containers is refused. Non-finite numbers,
 * cycles, non-plain objects, and values that are not JSON are refused too. This is a copy, not
 * a coercion: nothing is stringified or truncated to make it fit.
 */
function copyJson(
  value: JsonValue,
  seen = new WeakSet<object>(),
  depth = 0,
): JsonValue {
  if (
    value === null || typeof value === "string" || typeof value === "boolean"
  ) return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite JSON number");
    return value;
  }
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
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("non-plain JSON object");
  }
  const result = Object.create(null) as JsonObject;
  for (const key of Object.keys(value)) {
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
/** Elapsed time from `performance.now()` when the host has it, else from the wall clock. */
function defaultMonotonic(): Monotonic {
  const host = (globalThis as { performance?: { now?: () => number } })
    .performance;
  const highResolution = host?.now;
  if (typeof highResolution === "function") {
    return { now: () => highResolution.call(host) / 1000 };
  }
  return { now: () => Date.now() / 1000 };
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
  private readonly mode: RecordingMode;
  private readonly sink?: TraceSink;
  private readonly clock: Clock;
  private readonly monotonic: Monotonic;
  private readonly ids: IdFactory;
  private readonly redactor: Redactor;
  readonly runId: string;
  readonly producerId: string;
  constructor(options: ObserverOptions = {}) {
    this.mode = options.mode ?? "off";
    this.sink = options.sink;
    this.clock = options.clock ?? { now: () => new Date() };
    // The same choice the Python emitter makes: the injected monotonic source, else the
    // injected clock read as seconds, else a real monotonic source.
    this.monotonic = options.monotonic ??
      (options.clock === undefined
        ? defaultMonotonic()
        : { now: () => this.clock.now().getTime() / 1000 });
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
   * A never-settling sink also makes flush wait forever. It never rejects: a write that
   * somehow failed is already a recorded gap, and an awaiting harness must not inherit an
   * instrumentation failure as its own error.
   */
  async flush(): Promise<void> {
    await Promise.all(
      [...this.pending].map((write) =>
        write.then(() => undefined, () => undefined)
      ),
    );
  }
  /**
   * Flush, then refuse later events. It closes no caller resource.
   *
   * This is the analogue of the Python `aclose`. After it, `emit` counts a capture gap and
   * resolves undefined instead of writing, so an event that arrives after the run it belongs
   * to is visible as loss rather than silently postdating that run. In `off` mode there is
   * nothing to close and a later emit still records nothing, gap included. Calling it twice is
   * harmless. A sink the caller opened stays the caller's to close.
   */
  async close(): Promise<void> {
    await this.flush();
    this.isClosed = true;
  }
  private markGap(): void {
    this.state.dropped_events += 1;
    this.state.capture_gap = true;
    this.state.last_sink_error = gapMessage;
  }
  private nextId(prefix: string): string {
    try {
      const id = this.ids.next(prefix);
      if (typeof id !== "string" || id.length === 0) {
        throw new TypeError("invalid id");
      }
      return id;
    } catch {
      this.markGap();
      return prefix + "-fallback-" + (++this.fallbackSequence);
    }
  }
  private validId(value: unknown): value is string {
    return typeof value === "string" && value.length > 0;
  }
  private now(): string {
    try {
      const timestamp = this.clock.now().toISOString();
      if (!timestamp) throw new TypeError("invalid clock");
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
   * a safe integer all yield undefined and one capture gap. The emitter never invents a
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
   * the caller's exception. In off mode this resolves undefined without touching the clock,
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
      this.markGap();
      return Promise.resolve(undefined);
    }
    const write = this.emitInternal(input, dropDuration).catch(() => {
      // emitInternal already handles its own failures; this guarantees the contract holds
      // even if that ever stops being true, rather than rejecting into a caller's await.
      this.markGap();
      return undefined;
    });
    this.pending.add(write);
    void write.then(
      () => this.pending.delete(write),
      () => this.pending.delete(write),
    );
    return write;
  }
  private isObject(value: unknown): value is JsonObject {
    return value !== null && typeof value === "object" && !Array.isArray(value);
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
    if (this.isObject(snapshot["metadata"])) {
      snapshot["metadata"] = copyJson(snapshot["metadata"]);
    }
    if (this.mode === "content" && this.isObject(snapshot["content"])) {
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
   * or non-object metadata, a non-object content, a `duration_ms` that is null, not a number,
   * boolean, non-finite, non-integral, negative, or beyond the safe integer range, and a link
   * ID that is present but is not a nonempty string. Absent is spelled `undefined`; an
   * explicit null is a rejection, never a shorthand for absent. It reads the snapshot, never
   * the caller's object, so what is validated is exactly what is built.
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
    if (!this.isObject(snapshot["metadata"])) return false;
    if (
      snapshot["content"] !== undefined && !this.isObject(snapshot["content"])
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
   * thrown value that is not an Error, becomes a capture gap. When `dropDuration` is set, or
   * when instrumentation failed while this event was being built, the event is downgraded to
   * `partial` unless it is already `unavailable` and its metadata is marked with
   * `observer_capture_gap`, so a reader cannot take a fabricated ID, an epoch timestamp, or a
   * missing duration for a measurement.
   */
  private async emitInternal(
    input: EventInput,
    dropDuration: boolean,
  ): Promise<TraceEvent | undefined> {
    if (this.mode === "off") return undefined;
    let event: TraceEvent;
    const gapsBefore = this.state.dropped_events;
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
      if (dropDuration || this.state.dropped_events > gapsBefore) {
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
      this.markGap();
      return undefined;
    }
    if (!this.sink) return event;
    try {
      await this.sink.write(event);
    } catch {
      this.markGap();
    }
    return event;
  }
  /**
   * Build an event from a caller's callback and emit it without awaiting the write.
   *
   * The callback is caller code. Anything it throws, Error or not, is a capture gap here and
   * never reaches the operation being observed.
   */
  private emitDetached(build: () => EventInput): void {
    try {
      void this.emit(build());
    } catch {
      this.markGap();
    }
  }
  /**
   * Emit the event that closes an observed operation, with its measured duration or none.
   *
   * When the span could not be measured the builder is told so, by being handed undefined, and
   * any `duration_ms` it returns anyway is dropped from the event, which is still emitted,
   * downgraded to `partial`, and marked with `observer_capture_gap`. The gap for the failed
   * measurement was already counted once by the read that failed.
   */
  private emitCompletion(
    build: (durationMs: number | undefined) => EventInput,
    began: number | null,
  ): void {
    try {
      const elapsed = this.elapsedMs(began);
      void this.emitEvent(build(elapsed), elapsed === undefined);
    } catch {
      this.markGap();
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
/** Adapt a caller-owned JSONL writer; the SDK never opens files automatically. */
export function createJsonlSink(
  writeLine: (line: string) => void | Promise<void>,
): TraceSink {
  return { write: (event) => writeLine(JSON.stringify(event) + "\n") };
}
