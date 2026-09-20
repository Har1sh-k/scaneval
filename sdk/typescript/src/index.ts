/**
 * A deliberately small, opt-in observer emitter. Importing it records nothing.
 *
 * It is behaviorally matched to the Python emitter in `src/scaneval/observer`: the two accept
 * and reject the same inputs, write the same keys in the wire schema's declaration order,
 * redact by the same ASCII key-name rule, decide "was this value replaced" by reference
 * identity, and report the same capture state fields. A rejected event consumes no sequence
 * number, no event ID, and no clock read; that is only safe because the rejection sets are
 * identical, so the rule in `validInput` is a contract rather than an implementation detail.
 *
 * Nothing here can change the value an observed operation returns or the error it raises.
 * Every instrumentation failure, including a thrown value that is not an Error, becomes a
 * visible capture gap. A gap says the trace is incomplete; an absent event is not evidence
 * of absent activity.
 */
export const SCHEMA_VERSION = "2.0" as const;
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
export interface Clock {
  now(): Date;
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
/* Deliberately do not match input_tokens/output_tokens or other telemetry counters.
   The `i` flag folds ASCII only: without a `u` flag, JavaScript leaves a non-ASCII character
   whose uppercase is ASCII (for example U+017F long s) unmatched. Python spells the same rule
   re.IGNORECASE | re.ASCII, so the two default redactors hide the same key names. */
const secretKey =
  /^(?:api[_-]?key|authorization|credential(?:s)?|cookie(?:s)?|password|secret(?:s)?|token|private[_-]?key)$/i;
const defaultRedactor: Redactor = (key, value) =>
  secretKey.test(key) ? "[REDACTED]" : value;
function copyJson(value: JsonValue, seen = new WeakSet<object>()): JsonValue {
  if (
    value === null || typeof value === "string" || typeof value === "boolean"
  ) return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite JSON number");
    return value;
  }
  if (typeof value !== "object") throw new TypeError("non-JSON value");
  if (seen.has(value)) throw new TypeError("cyclic JSON value");
  seen.add(value);
  if (Array.isArray(value)) {
    const result = value.map((item) => copyJson(item, seen));
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
      value: copyJson(value[key], seen),
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
 * A value counts as redacted when the redactor handed back something that is not the value
 * it was given: identity (`!==`), never a deep value comparison, so a redactor that rebuilds
 * an equal object still marks the event redacted. That is the shared rule the Python emitter
 * follows too. JavaScript has no distinct reference for a primitive, so two equal strings are
 * necessarily the same value there and a redactor that returns an equal string changes
 * nothing. The redactor sees keys, never bare list elements, and its replacement is copied and
 * walked again, because a redactor is caller code and no more trusted than the payload it
 * replaced.
 */
function redact(
  value: JsonValue,
  redactor: Redactor,
  path: string[] = [],
): { value: JsonValue; redacted: boolean } {
  if (Array.isArray(value)) {
    let changed = false;
    const copied = value.map((item, index) => {
      const result = redact(item, redactor, [...path, String(index)]);
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
      // A custom redactor is untrusted instrumentation: validate/copy its output too.
      const nested = redact(copyJson(replacement), redactor, [...path, key]);
      // Reference identity, not value equality: a rebuilt equal object is still a replacement.
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
export interface ObserverOptions {
  mode?: RecordingMode;
  sink?: TraceSink;
  runId?: string;
  producerId?: string;
  clock?: Clock;
  idFactory?: IdFactory;
  redactor?: Redactor;
}
export class Observer {
  private sequence = 0;
  private fallbackSequence = 0;
  private readonly pending = new Set<Promise<TraceEvent | undefined>>();
  private readonly state: CaptureState = {
    dropped_events: 0,
    capture_gap: false,
    last_sink_error: null,
  };
  private readonly mode: RecordingMode;
  private readonly sink?: TraceSink;
  private readonly clock: Clock;
  private readonly ids: IdFactory;
  private readonly redactor: Redactor;
  readonly runId: string;
  readonly producerId: string;
  constructor(options: ObserverOptions = {}) {
    this.mode = options.mode ?? "off";
    this.sink = options.sink;
    this.clock = options.clock ?? { now: () => new Date() };
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
      [...this.pending].map((write) => write.then(() => undefined, () => undefined)),
    );
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
      return new Date(0).toISOString();
    }
  }
  private nowMs(): number {
    try {
      const value = this.clock.now().getTime();
      if (!Number.isFinite(value)) throw new TypeError("invalid clock");
      return value;
    } catch {
      this.markGap();
      return 0;
    }
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
   * factory or sink that throws anything at all, and a payload that is not JSON are all
   * capture gaps, so instrumentation cannot become the caller's exception. In off mode this
   * resolves undefined without touching the clock, the ID factory, the redactor, or the sink.
   */
  emit(input: EventInput): Promise<TraceEvent | undefined> {
    if (this.mode === "off") return Promise.resolve(undefined);
    const write = this.emitInternal(input).catch(() => {
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
   * Check an event against the wire contract. The rejection set is a contract, not a detail.
   *
   * It has to match the Python emitter name for name, because a rejected event consumes no
   * sequence number, no event ID, and no clock read in either language: that is only safe
   * while both refuse exactly the same inputs. Refused here: an unknown field name, an
   * unknown type, a category that contradicts the type, an unknown capture status, a missing
   * or non-object metadata, a non-object content, a `duration_ms` that is null, not a number,
   * boolean, non-finite, non-integral, or negative, and a link ID that is present but is not
   * a nonempty string. Absent is spelled `undefined`; an explicit null is a rejection, never
   * a shorthand for absent.
   */
  private validInput(input: EventInput): boolean {
    const raw = input as unknown;
    if (raw === null || typeof raw !== "object") return false;
    const supplied = raw as Record<string, unknown>;
    for (const name of Object.keys(supplied)) {
      if (!inputFields.has(name)) return false;
    }
    if (
      !Object.prototype.hasOwnProperty.call(categoryFor, input.type) ||
      (input.category !== undefined &&
        input.category !== categoryFor[input.type])
    ) return false;
    if (!captureStatuses.has(input.capture_status)) return false;
    if (
      !this.isObject(input.metadata) ||
      (input.content !== undefined && !this.isObject(input.content))
    ) return false;
    if (!this.validDuration(supplied["duration_ms"])) return false;
    return idFields.every((name) =>
      supplied[name] === undefined || this.validId(supplied[name])
    );
  }

  /** A duration is absent or a nonnegative integer count of milliseconds. Null is not absent. */
  private validDuration(value: unknown): boolean {
    if (value === undefined) return true;
    if (typeof value !== "number") return false;
    return Number.isInteger(value) && value >= 0;
  }
  /**
   * Build one event and hand it to the sink. It never rejects and never throws to a caller.
   *
   * Validation runs before anything is consumed, so a rejected event takes no sequence
   * number, no event ID, and no clock read, exactly as in Python. Keys are written in the
   * order the wire schema declares them, link fields and `duration_ms` ahead of `metadata`,
   * so a JSONL line from either language reads as the schema does. Every failure, including
   * a thrown value that is not an Error, becomes a capture gap.
   */
  private async emitInternal(
    input: EventInput,
  ): Promise<TraceEvent | undefined> {
    if (this.mode === "off") return undefined;
    let event: TraceEvent;
    try {
      if (!this.validInput(input)) {
        throw new TypeError("invalid trace event input");
      }
      const metadata = redact(copyJson(input.metadata), this.redactor);
      const content = this.mode === "content" && input.content !== undefined
        ? redact(copyJson(input.content), this.redactor)
        : undefined;
      event = {
        schema_version: SCHEMA_VERSION,
        event_id: this.nextId("event"),
        run_id: this.runId,
        producer_id: this.producerId,
        sequence: this.sequence++,
        type: input.type,
        category: input.category ?? categoryFor[input.type],
        capture_status: this.downgradedStatus(
          input.capture_status,
          metadata.redacted || content?.redacted === true,
        ),
        timestamp: this.now(),
        ...(input.parent_event_id === undefined
          ? {}
          : { parent_event_id: input.parent_event_id }),
        ...(input.call_id === undefined ? {} : { call_id: input.call_id }),
        ...(input.attempt_id === undefined
          ? {}
          : { attempt_id: input.attempt_id }),
        ...(input.candidate_id === undefined
          ? {}
          : { candidate_id: input.candidate_id }),
        ...(input.claim_id === undefined ? {} : { claim_id: input.claim_id }),
        ...(input.duration_ms === undefined
          ? {}
          : { duration_ms: input.duration_ms }),
        metadata: metadata.value as JsonObject,
        ...(content ? { content: content.value as JsonObject } : {}),
      };
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
   * Promise-boundary helper. It never consumes/wraps streams; timing ends at Promise
   * resolution, not at a returned stream's end.
   *
   * The operation's value is returned untouched and its error is re-thrown as the original
   * value, whatever was thrown. Every instrumentation failure around it, including a callback
   * or sink that throws a string, a symbol, or null, is recorded as a capture gap instead.
   * `duration_ms` is a whole number of milliseconds measured with the injected clock.
   */
  async observeAsync<T>(
    start: EventInput,
    success: (duration_ms: number) => EventInput,
    failure: (error: unknown, duration_ms: number) => EventInput,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (this.mode === "off") return operation();
    this.emitDetached(() => start);
    const began = this.nowMs();
    try {
      const value = await operation();
      this.emitDetached(() => success(this.nowMs() - began));
      return value;
    } catch (error) {
      this.emitDetached(() => failure(error, this.nowMs() - began));
      throw error;
    }
  }
}
/** Adapt a caller-owned JSONL writer; the SDK never opens files automatically. */
export function createJsonlSink(
  writeLine: (line: string) => void | Promise<void>,
): TraceSink {
  return { write: (event) => writeLine(JSON.stringify(event) + "\n") };
}
