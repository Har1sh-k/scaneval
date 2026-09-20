/** A deliberately small, opt-in observer emitter. Importing it records nothing. */
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
export interface CaptureState {
  dropped_events: number;
  capture_gap: boolean;
  last_sink_error?: string;
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
/* Deliberately do not match input_tokens/output_tokens or other telemetry counters. */
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
  /** Wait for writes started by emit/observeAsync after the harness operation has finished. A never-settling sink also makes flush wait forever. */
  async flush(): Promise<void> {
    await Promise.all([...this.pending]);
  }
  private markGap(): void {
    this.state.dropped_events += 1;
    this.state.capture_gap = true;
    this.state.last_sink_error = "observer instrumentation failure";
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
  emit(input: EventInput): Promise<TraceEvent | undefined> {
    if (this.mode === "off") return Promise.resolve(undefined);
    const write = this.emitInternal(input);
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
  private validInput(input: EventInput): boolean {
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
    if (
      !Number.isFinite(input.duration_ms ?? 0) ||
      (input.duration_ms !== undefined && input.duration_ms < 0)
    ) return false;
    return [
      input.parent_event_id,
      input.call_id,
      input.attempt_id,
      input.candidate_id,
      input.claim_id,
    ].every((id) => id === undefined || this.validId(id));
  }
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
        metadata: metadata.value as JsonObject,
        ...(input.parent_event_id
          ? { parent_event_id: input.parent_event_id }
          : {}),
        ...(input.call_id ? { call_id: input.call_id } : {}),
        ...(input.attempt_id ? { attempt_id: input.attempt_id } : {}),
        ...(input.candidate_id ? { candidate_id: input.candidate_id } : {}),
        ...(input.claim_id ? { claim_id: input.claim_id } : {}),
        ...(input.duration_ms === undefined
          ? {}
          : { duration_ms: input.duration_ms }),
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
  /** Promise-boundary helper. It never consumes/wraps streams; timing ends at Promise resolution, not at a returned stream's end. */
  async observeAsync<T>(
    start: EventInput,
    success: (duration_ms: number) => EventInput,
    failure: (error: unknown, duration_ms: number) => EventInput,
    operation: () => Promise<T>,
  ): Promise<T> {
    if (this.mode === "off") return operation();
    void this.emit(start);
    const began = this.nowMs();
    try {
      const value = await operation();
      try {
        void this.emit(success(this.nowMs() - began));
      } catch {
        this.markGap();
      }
      return value;
    } catch (error) {
      try {
        void this.emit(failure(error, this.nowMs() - began));
      } catch {
        this.markGap();
      }
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
