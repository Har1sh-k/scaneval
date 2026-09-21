import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { MAX_PAYLOAD_DEPTH, Observer, createJsonlSink } from "../dist/index.js";

const ids = () => { let i = 0; return { next: (prefix) => `${prefix}-${++i}` }; };
const clock = () => { let i = 0; return { now: () => new Date(1_700_000_000_000 + i++ * 10) }; };
const event = (extra = {}) => ({ type: "model.request", capture_status: "complete", metadata: { model: "x" }, content: { authorization: "keep-out", body: "hello" }, ...extra });

test("off mode is a no-op", async () => {
  const seen = []; const observer = new Observer({ sink: { write: e => seen.push(e) } });
  assert.equal(await observer.emit(event()), undefined); assert.deepEqual(seen, []);
});

test("metadata mode omits content and never mutates supplied data", async () => {
  const seen = []; const supplied = event({ metadata: { apiKey: "original", nested: { x: 1 } } });
  const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) }, idFactory: ids(), clock: clock(), runId: "r", producerId: "p" });
  await observer.emit(supplied); await observer.emit(event());
  assert.equal(seen[0].content, undefined); assert.equal(supplied.metadata.apiKey, "original");
  assert.equal(seen[0].metadata.apiKey, "[REDACTED]"); assert.equal(seen[0].sequence, 0); assert.equal(seen[1].sequence, 1);
  assert.equal(seen[0].capture_status, "redacted"); assert.equal(seen[1].capture_status, "partial");
  assert.equal(seen[0].event_id, "event-1"); assert.equal(seen[0].timestamp, "2023-11-14T22:13:20.000Z");
});

test("content redaction, lifecycle links, and custom redaction are stored copies", async () => {
  const seen = []; const observer = new Observer({ mode: "content", sink: { write: e => seen.push(e) }, idFactory: ids(), redactor: (key, value) => key === "body" ? "masked" : key === "authorization" ? "[REDACTED]" : value });
  await observer.emit(event({ candidate_id: "cand-7", call_id: "call-2", parent_event_id: "event-parent" }));
  assert.equal(seen[0].content.body, "masked"); assert.equal(seen[0].content.authorization, "[REDACTED]");
  assert.equal(seen[0].candidate_id, "cand-7"); assert.equal(seen[0].call_id, "call-2"); assert.equal(seen[0].parent_event_id, "event-parent");
});

test("sink failures create visible capture gaps without throwing", async () => {
  const observer = new Observer({ mode: "content", sink: { write: () => { throw new Error("disk full"); } } });
  const recorded = await observer.emit(event());
  assert.ok(recorded); assert.deepEqual(observer.getState(), { dropped_events: 1, capture_gap: true, last_sink_error: "observer instrumentation failure" });
});

test("async wrapper preserves successful values and original failures", async () => {
  const seen = []; const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) }, clock: clock() });
  const start = { type: "tool.start", capture_status: "complete", metadata: {} };
  const complete = duration_ms => ({ type: "tool.end", capture_status: "complete", duration_ms, metadata: {} });
  assert.equal(await observer.observeAsync(start, complete, complete, async () => 42), 42);
  const boom = new Error("original");
  await assert.rejects(() => observer.observeAsync(start, complete, complete, async () => { throw boom; }), error => error === boom);
  await observer.flush();
  assert.ok(seen.length >= 3);
});

test("JSONL sink delegates writing to the caller", async () => {
  const lines = []; const observer = new Observer({ mode: "metadata", sink: createJsonlSink(line => lines.push(line)) });
  await observer.emit(event()); assert.equal(lines.length, 1); assert.ok(lines[0].endsWith("\n"));
});

test("all emitter helper failures become capture gaps", async () => {
  const cyclic = { value: "x" }; cyclic.self = cyclic;
  const observer = new Observer({
    mode: "content", idFactory: { next: () => { throw new Error("ids"); } },
    clock: { now: () => { throw new Error("clock"); } }, redactor: () => { throw new Error("redactor"); }
  });
  assert.equal(await observer.emit(event()), undefined);
  assert.equal(await observer.emit(event({ metadata: cyclic })), undefined);
  assert.equal(observer.getState().capture_gap, true);
  // Two emits, each lost before its event could be built. The ID factory failures in the
  // constructor degraded nothing that was delivered, so they flag the gap without counting a
  // loss, which is the line Python draws between _mark_gap and _lost_event.
  assert.equal(observer.getState().dropped_events, 2);
});

test("credential redaction excludes token counters and handles __proto__ safely", async () => {
  const seen = []; const metadata = Object.create(null);
  Object.defineProperty(metadata, "__proto__", { value: "literal", enumerable: true });
  metadata.token = "secret"; metadata.input_tokens = 12; metadata.output_tokens = 7;
  const observer = new Observer({ mode: "content", sink: { write: e => seen.push(e) } });
  await observer.emit(event({ metadata }));
  assert.equal(seen[0].metadata.token, "[REDACTED]"); assert.equal(seen[0].metadata.input_tokens, 12);
  assert.equal(seen[0].metadata.output_tokens, 7); assert.equal(seen[0].metadata.__proto__, "literal");
  assert.equal(seen[0].capture_status, "redacted");
});

test("async instrumentation failures never replace result/error or consume iterators", async () => {
  const observer = new Observer({ mode: "content", sink: { write: () => { throw new Error("sink"); } }, clock: { now: () => { throw new Error("clock"); } } });
  let calls = 0;
  const result = await observer.observeAsync(event(), () => { throw new Error("success callback"); }, () => { throw new Error("failure callback"); }, async () => { calls++; return "ok"; });
  assert.equal(result, "ok"); assert.equal(calls, 1);
  const original = new Error("original");
  await assert.rejects(() => observer.observeAsync(event(), () => { throw new Error("success"); }, () => { throw new Error("failure"); }, async () => { calls++; throw original; }), error => error === original);
  async function* chunks() { yield "one"; yield "two"; }
  const stream = chunks();
  const returned = await observer.observeAsync(event(), () => event(), () => event(), async () => stream);
  assert.equal(returned, stream); assert.deepEqual([...(await (async () => { const out = []; for await (const chunk of returned) out.push(chunk); return out; })())], ["one", "two"]);
  assert.equal(calls, 2); assert.equal(observer.getState().capture_gap, true);
});

test("flush waits for pending async writes and records their rejection", async () => {
  let release; const observer = new Observer({ mode: "content", sink: { write: () => new Promise((resolve) => { release = resolve; }) } });
  void observer.emit(event());
  let settled = false; const flushed = observer.flush().then(() => { settled = true; });
  await Promise.resolve(); assert.equal(settled, false); release(); await flushed; assert.equal(settled, true);
  const rejected = new Observer({ mode: "content", sink: { write: async () => { throw new Error("late"); } } });
  void rejected.emit(event()); await rejected.flush(); assert.equal(rejected.getState().capture_gap, true);
});

test("off observeAsync bypasses all instrumentation factories", async () => {
  let ids = 0; let clocks = 0; let callbacks = 0; let calls = 0;
  const observer = new Observer({ mode: "off", idFactory: { next: () => { ids++; throw new Error("no ids"); } }, clock: { now: () => { clocks++; throw new Error("no clock"); } } });
  assert.equal(await observer.observeAsync(event(), () => { callbacks++; throw new Error("no success"); }, () => { callbacks++; throw new Error("no failure"); }, async () => { calls++; return 9; }), 9);
  assert.deepEqual({ ids, clocks, callbacks, calls }, { ids: 0, clocks: 0, callbacks: 0, calls: 1 });
});

test("invalid JavaScript event fields are dropped before the sink", async () => {
  const seen = []; const observer = new Observer({ mode: "content", sink: { write: e => seen.push(e) } });
  assert.equal(await observer.emit(event({ duration_ms: -1 })), undefined);
  assert.equal(await observer.emit(event({ category: "tool" })), undefined);
  assert.equal(await observer.emit(event({ type: "toString" })), undefined);
  assert.equal(await observer.emit(event({ capture_status: "made-up" })), undefined);
  assert.equal(await observer.emit(event({ metadata: [] })), undefined);
  assert.deepEqual(seen, []); assert.equal(observer.getState().dropped_events, 5);
});

test("emits the shared v2 schema fixture exactly", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../../schema/v2/fixtures/trace-event-v2.json", import.meta.url)));
  const values = ["run-example-1", "dispatcher-example", "event-example-1"];
  const observer = new Observer({ mode: "content", idFactory: { next: () => values.shift() }, clock: { now: () => new Date("2026-09-20T12:00:00.000Z") } });
  const emitted = await observer.emit({ type: "model.request", capture_status: "complete", call_id: "call-example-1", metadata: { model: "example-model", input_tokens: 42 }, content: { authorization: "real credential" } });
  assert.deepEqual(JSON.parse(JSON.stringify(emitted)), fixture);
});

// The wire schema declaration order, which both emitters now write keys in.
const WIRE_ORDER = ["schema_version", "event_id", "run_id", "producer_id", "sequence", "type", "category", "capture_status", "timestamp", "parent_event_id", "call_id", "attempt_id", "candidate_id", "claim_id", "duration_ms", "metadata", "content"];
const plain = value => JSON.parse(JSON.stringify(value));

test("a null duration_ms is rejected instead of emitting a schema-invalid event", async () => {
  const seen = []; const observer = new Observer({ mode: "content", sink: { write: e => seen.push(e) } });
  assert.equal(await observer.emit(event({ duration_ms: null })), undefined);
  assert.deepEqual(seen, []); assert.equal(observer.getState().dropped_events, 1);
  const kept = await observer.emit(event({ duration_ms: 0 }));
  assert.equal(kept.duration_ms, 0); assert.equal(seen.length, 1);
  assert.ok(!Object.keys(plain(kept)).includes("undefined"));
});

test("emitted keys follow the wire schema declaration order", async () => {
  const lines = []; const observer = new Observer({ mode: "content", sink: createJsonlSink(line => lines.push(line)), idFactory: ids(), clock: clock(), runId: "r", producerId: "p" });
  const full = await observer.emit(event({ parent_event_id: "event-0", call_id: "call-1", attempt_id: "attempt-1", candidate_id: "cand-1", claim_id: "claim-1", duration_ms: 12 }));
  assert.deepEqual(Object.keys(full), WIRE_ORDER);
  assert.deepEqual(Object.keys(JSON.parse(lines[0])), WIRE_ORDER);
  const sparse = await observer.emit({ type: "tool.start", capture_status: "complete", metadata: {} });
  const optional = ["parent_event_id", "call_id", "attempt_id", "candidate_id", "claim_id", "duration_ms", "content"];
  assert.deepEqual(Object.keys(sparse), WIRE_ORDER.filter(key => !optional.includes(key)));
});

test("capture state carries the same fields the Python emitter records", async () => {
  const observer = new Observer({ mode: "metadata", sink: { write: () => {} } });
  const before = observer.getState();
  assert.deepEqual(before, { dropped_events: 0, capture_gap: false, last_sink_error: null });
  await observer.emit(event({ duration_ms: 1.5 }));
  assert.deepEqual(observer.getState(), { dropped_events: 1, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  assert.deepEqual(before, { dropped_events: 0, capture_gap: false, last_sink_error: null });
});

test("duration_ms is a whole number of milliseconds", async () => {
  const seen = []; const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) }, clock: clock() });
  const refused = [1.5, -1, Number.NaN, Number.POSITIVE_INFINITY, "12", true, null];
  for (const bad of refused) assert.equal(await observer.emit(event({ duration_ms: bad })), undefined);
  assert.deepEqual(seen, []); assert.equal(observer.getState().dropped_events, refused.length);
  assert.equal((await observer.emit(event({ duration_ms: 120 }))).duration_ms, 120);
  const durations = [];
  const start = { type: "tool.start", capture_status: "complete", metadata: {} };
  const done = duration_ms => { durations.push(duration_ms); return { type: "tool.end", capture_status: "complete", duration_ms, metadata: {} }; };
  assert.equal(await observer.observeAsync(start, done, done, async () => "value"), "value");
  await observer.flush();
  assert.equal(durations.length, 1); assert.ok(durations.every(Number.isInteger));
  assert.equal(seen.at(-1).duration_ms, durations.at(-1));
});

test("the default redactor folds case over ASCII only", async () => {
  const seen = []; const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) } });
  // Long s (U+017F), Cyrillic te (U+0442), and the Kelvin sign (U+212A): Unicode-aware
  // folding would read these as secret/token, ASCII folding does not, and Python spells
  // the same rule re.IGNORECASE | re.ASCII.
  await observer.emit(event({ metadata: { AUTHORIZATION: "a", Api_Key: "b", "ſecret": "c", "тoken": "d", "toKen": "e" } }));
  const stored = seen[0].metadata;
  assert.equal(stored.AUTHORIZATION, "[REDACTED]"); assert.equal(stored.Api_Key, "[REDACTED]");
  assert.equal(stored["ſecret"], "c"); assert.equal(stored["тoken"], "d"); assert.equal(stored["toKen"], "e");
  assert.equal(seen[0].capture_status, "redacted");
});

test("redaction is decided by reference identity, not value equality", async () => {
  const rebuilt = [];
  const rebuilding = new Observer({ mode: "content", sink: { write: e => rebuilt.push(e) }, redactor: (key, value) => key === "nested" ? { ...value } : value });
  await rebuilding.emit({ type: "tool.start", capture_status: "complete", metadata: { nested: { same: 1 } } });
  assert.deepEqual(plain(rebuilt[0].metadata), { nested: { same: 1 } });
  assert.equal(rebuilt[0].capture_status, "redacted");
  const untouched = [];
  const identity = new Observer({ mode: "content", sink: { write: e => untouched.push(e) }, redactor: (key, value) => value });
  await identity.emit({ type: "tool.start", capture_status: "complete", metadata: { token: "kept", nested: { same: 1 } } });
  assert.equal(untouched[0].capture_status, "complete"); assert.equal(untouched[0].metadata.token, "kept");
});

test("instrumentation that throws a non-Error value never reaches the caller", async () => {
  const observer = new Observer({ mode: "content", sink: { write: () => { throw "sink string"; } }, clock: { now: () => new Date(1_700_000_000_000) } });
  assert.ok(await observer.emit(event()));
  assert.deepEqual(observer.getState(), { dropped_events: 1, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  const hostile = new Observer({ mode: "content", sink: { write: () => { throw Symbol("sink"); } }, idFactory: { next: () => { throw null; } }, clock: { now: () => { throw "no clock"; } }, redactor: () => { throw 42; } });
  assert.equal(await hostile.emit(event()), undefined);
  let calls = 0;
  assert.equal(await hostile.observeAsync(event(), () => { throw "success"; }, () => { throw Symbol("failure"); }, async () => { calls++; return "value"; }), "value");
  const thrown = { code: "caller" };
  await assert.rejects(() => hostile.observeAsync(event(), () => { throw "success"; }, () => { throw null; }, async () => { calls++; throw thrown; }), error => error === thrown);
  await hostile.flush();
  assert.equal(calls, 2); assert.equal(hostile.getState().capture_gap, true);
});

test("the shared rejection set is refused and costs no sequence, id, or clock read", async () => {
  const seen = []; let reads = 0; let issued = 0;
  const observer = new Observer({
    mode: "content", sink: { write: e => seen.push(e) }, runId: "r", producerId: "p",
    idFactory: { next: prefix => `${prefix}-${++issued}` },
    clock: { now: () => { reads++; return new Date(1_700_000_000_000); } },
  });
  const refused = [
    event({ oops: 1 }),                                      // unknown field name
    { type: "model.request", capture_status: "complete" },   // metadata is required
    event({ metadata: null }),
    event({ duration_ms: null }),                            // null is not absent
    event({ duration_ms: 2.5 }),                             // whole milliseconds only
    // Null is never a shorthand for absent: an explicitly null content or link ID is refused
    // the same way, which is the stricter reading of the shared rule.
    event({ content: null }),
    event({ call_id: null }),
    event({ call_id: "" }),
  ];
  for (const input of refused) assert.equal(await observer.emit(input), undefined);
  assert.deepEqual(seen, []);
  assert.deepEqual(observer.getState(), { dropped_events: refused.length, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  assert.equal(reads, 0); assert.equal(issued, 0);
  const kept = await observer.emit(event());
  assert.equal(kept.sequence, 0); assert.equal(kept.event_id, "event-1"); assert.equal(reads, 1);
});

// A payload nested `depth` containers deep, the outermost being the metadata object itself.
const nest = depth => { let value = { leaf: true }; for (let i = 1; i < depth; i += 1) value = { child: value }; return value; };

test("the caller's event object is read once, so a second read cannot reach the wire", async () => {
  // Time of check versus time of use: validation and building must see one snapshot, or a
  // getter answering differently the second time writes a schema-invalid event with no gap.
  const seen = []; let types = 0; let durations = 0; let metadatas = 0; let statuses = 0;
  const hostile = {
    get type() { types += 1; return types === 1 ? "tool.end" : "not-a-type"; },
    get capture_status() { statuses += 1; return statuses === 1 ? "complete" : "made-up"; },
    get duration_ms() { durations += 1; return durations === 1 ? 5 : -1.5; },
    get metadata() { metadatas += 1; return metadatas === 1 ? { read: 1 } : "not-an-object"; },
  };
  const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) }, idFactory: ids(), clock: clock() });
  const emitted = await observer.emit(hostile);
  assert.deepEqual({ types, durations, metadatas, statuses }, { types: 1, durations: 1, metadatas: 1, statuses: 1 });
  assert.equal(emitted.type, "tool.end"); assert.equal(emitted.duration_ms, 5);
  assert.deepEqual(plain(emitted.metadata), { read: 1 });
  assert.deepEqual(Object.keys(plain(seen[0])), WIRE_ORDER.filter(key => !["parent_event_id", "call_id", "attempt_id", "candidate_id", "claim_id", "content"].includes(key)));
  assert.deepEqual(observer.getState(), { dropped_events: 0, capture_gap: false, last_sink_error: null });
  // A snapshot whose one read is already invalid is refused, and costs no sequence or id.
  let reads = 0;
  const refused = await observer.emit({ get type() { reads += 1; return "not-a-type"; }, capture_status: "complete", metadata: {} });
  assert.equal(refused, undefined); assert.equal(reads, 1); assert.equal(observer.getState().dropped_events, 1);
});

test("a monotonic source that steps backwards costs the duration, not the completion event", async () => {
  const seen = []; const steps = [100, 90];
  const observer = new Observer({
    mode: "metadata", sink: { write: e => seen.push(e) }, idFactory: ids(), clock: clock(),
    monotonic: { now: () => steps.shift() },
  });
  const durations = [];
  const start = { type: "tool.start", capture_status: "complete", metadata: {} };
  const done = duration_ms => { durations.push(duration_ms); return { type: "tool.end", capture_status: "complete", duration_ms, metadata: { tool: "grep" } }; };
  assert.equal(await observer.observeAsync(start, done, done, async () => "value"), "value");
  await observer.flush();
  assert.deepEqual(durations, [undefined]);
  const completion = seen.at(-1);
  assert.equal(Object.keys(plain(completion)).includes("duration_ms"), false);
  assert.equal(completion.capture_status, "partial");
  assert.equal(completion.metadata.observer_capture_gap, true);
  assert.equal(completion.metadata.tool, "grep");
  // The completion event was delivered, without its duration, so the unmeasurable span is a
  // capture gap rather than a lost event.
  assert.deepEqual(observer.getState(), { dropped_events: 0, capture_gap: true, last_sink_error: "observer instrumentation failure" });
});

test("a clock that throws during observeAsync costs the timestamp, not the duration", async () => {
  // This test used to assert that a throwing clock also cost the duration, which was true only
  // because the emitter derived its elapsed-time source from the injected clock. It no longer
  // does, for the reason Python never did: a wall clock can be adjusted between two reads. The
  // two failures are independent now, and each costs exactly its own field.
  const seen = [];
  const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) }, idFactory: ids(), clock: { now: () => { throw new Error("clock"); } } });
  const durations = [];
  const start = { type: "tool.start", capture_status: "complete", metadata: {} };
  const done = duration_ms => { durations.push(duration_ms); return { type: "tool.end", capture_status: "complete", duration_ms, metadata: {} }; };
  assert.equal(await observer.observeAsync(start, done, done, async () => "value"), "value");
  await observer.flush();
  // The span was measured with a real monotonic source, so the builder was handed a whole
  // number of milliseconds rather than the undefined a clock-derived source produced here.
  assert.equal(durations.length, 1);
  assert.ok(Number.isInteger(durations[0]) && durations[0] >= 0);
  const completion = seen.at(-1);
  assert.equal(completion.duration_ms, durations[0]);
  assert.equal(completion.timestamp, "1970-01-01T00:00:00.000Z");
  // The event is still marked, because the clock read that failed left a fabricated timestamp.
  assert.equal(completion.capture_status, "partial");
  assert.equal(completion.metadata.observer_capture_gap, true);
  // One gap per failed clock read, one event each. Neither event was lost: both reached the
  // sink, so the drop counter stays at zero.
  assert.deepEqual(observer.getState(), { dropped_events: 0, capture_gap: true, last_sink_error: "observer instrumentation failure" });

  // The unmeasurable span is now reachable only through the elapsed-time source itself, which
  // is the whole point of it being a separate source.
  const timed = [];
  const unmeasurable = new Observer({
    mode: "metadata", sink: { write: e => timed.push(e) }, idFactory: ids(), clock: clock(),
    monotonic: { now: () => { throw new Error("monotonic"); } },
  });
  const spans = [];
  const record = duration_ms => { spans.push(duration_ms); return { type: "tool.end", capture_status: "complete", duration_ms, metadata: {} }; };
  assert.equal(await unmeasurable.observeAsync(start, record, record, async () => "value"), "value");
  await unmeasurable.flush();
  assert.deepEqual(spans, [undefined]);
  assert.equal(Object.keys(plain(timed.at(-1))).includes("duration_ms"), false);
  assert.equal(timed.at(-1).capture_status, "partial");
  assert.equal(timed.at(-1).metadata.observer_capture_gap, true);
  assert.equal(timed.at(-1).timestamp, "2023-11-14T22:13:20.010Z");
  assert.deepEqual(unmeasurable.getState(), { dropped_events: 0, capture_gap: true, last_sink_error: "observer instrumentation failure" });
});

test("an injected clock never measures elapsed time, in either language", async () => {
  // The divergence this closes: the emitter used to derive its default monotonic source from an
  // injected Clock, so a fixture that injected a 10 ms-per-read clock got duration_ms 10 out of
  // TypeScript and a real measurement out of Python for the same code. A wall clock can be
  // adjusted between two reads, so a span measured with one is time that may never have
  // elapsed. Python's `monotonic` defaults to time.monotonic and never falls back to its
  // `clock`; this is the same rule, pinned on this side.
  const seen = [];
  let reads = 0;
  const observer = new Observer({
    mode: "metadata", sink: { write: e => seen.push(e) }, idFactory: ids(), runId: "r", producerId: "p",
    clock: { now: () => new Date(1_700_000_000_000 + (reads++) * 10) },
  });
  const start = { type: "tool.start", capture_status: "complete", metadata: { tool: "grep" } };
  const done = duration_ms => ({ type: "tool.end", capture_status: "complete", duration_ms, metadata: { tool: "grep" } });
  assert.equal(await observer.observeAsync(start, done, done, async () => "value"), "value");
  await observer.flush();
  // One clock read per event and no more. Two extra reads would be the operation being timed
  // with the wall clock, and they would shift every timestamp after them as well.
  assert.equal(reads, 2);
  assert.deepEqual(seen.map(e => e.timestamp), ["2023-11-14T22:13:20.000Z", "2023-11-14T22:13:20.010Z"]);
  // The duration is a real measurement, not the 10 ms step this clock would have implied.
  const measured = seen.at(-1).duration_ms;
  assert.ok(Number.isInteger(measured) && measured >= 0);
  assert.equal(seen.at(-1).capture_status, "partial");
  assert.equal(seen.at(-1).metadata.observer_capture_gap, undefined);
  assert.deepEqual(observer.getState(), { dropped_events: 0, capture_gap: false, last_sink_error: null });

  // A host with no performance.now() offers no monotonic source at all. The span is reported
  // unmeasurable rather than taken off Date.now(), which is a wall clock like any other: an
  // omitted duration says the span is unknown, a wall-clock one would be read as a measurement.
  const host = globalThis.performance;
  const hostless = [];
  try {
    delete globalThis.performance;
    const bare = new Observer({ mode: "metadata", sink: { write: e => hostless.push(e) }, idFactory: ids(), clock: clock() });
    const spans = [];
    const record = duration_ms => { spans.push(duration_ms); return { type: "tool.end", capture_status: "complete", duration_ms, metadata: {} }; };
    assert.equal(await bare.observeAsync(start, record, record, async () => "value"), "value");
    await bare.flush();
    assert.deepEqual(spans, [undefined]);
    assert.equal(Object.keys(plain(hostless.at(-1))).includes("duration_ms"), false);
    assert.equal(hostless.at(-1).capture_status, "partial");
    assert.equal(hostless.at(-1).metadata.observer_capture_gap, true);
    // The completion event is still delivered, so this costs the duration and not the event.
    assert.deepEqual(bare.getState(), { dropped_events: 0, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  } finally {
    globalThis.performance = host;
  }
  assert.equal(hostless.length, 2);
});

test("close refuses later events as counted capture gaps", async () => {
  const seen = []; const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) }, idFactory: ids(), clock: clock() });
  assert.equal(observer.closed, false);
  assert.ok(await observer.emit(event()));
  await observer.close();
  assert.equal(observer.closed, true);
  assert.equal(await observer.emit(event()), undefined);
  assert.equal(await observer.emit(event()), undefined);
  assert.equal(seen.length, 1);
  assert.deepEqual(observer.getState(), { dropped_events: 2, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  await observer.close();
  assert.equal(observer.getState().dropped_events, 2);
  // close waits for a write already in flight, the way flush does.
  let release; const slow = new Observer({ mode: "metadata", sink: { write: () => new Promise(resolve => { release = resolve; }) } });
  void slow.emit(event());
  let settled = false; const closing = slow.close().then(() => { settled = true; });
  await Promise.resolve(); assert.equal(settled, false); release(); await closing; assert.equal(settled, true);
  // Off mode records nothing, so a closed off observer has lost nothing to count.
  const quiet = new Observer({ mode: "off", sink: { write: () => {} } });
  await quiet.close();
  assert.equal(await quiet.emit(event()), undefined);
  assert.deepEqual(quiet.getState(), { dropped_events: 0, capture_gap: false, last_sink_error: null });
});

test("payload nesting deeper than MAX_PAYLOAD_DEPTH is refused as a capture gap", async () => {
  const seen = []; const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) }, idFactory: ids(), clock: clock() });
  assert.equal(MAX_PAYLOAD_DEPTH, 32);
  const accepted = await observer.emit(event({ metadata: nest(MAX_PAYLOAD_DEPTH) }));
  assert.ok(accepted);
  assert.equal(await observer.emit(event({ metadata: nest(MAX_PAYLOAD_DEPTH + 1) })), undefined);
  assert.equal(await observer.emit(event({ metadata: { deep: nest(MAX_PAYLOAD_DEPTH) } })), undefined);
  assert.equal(seen.length, 1);
  assert.deepEqual(observer.getState(), { dropped_events: 2, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  // The budget counts where a value sits, so a redactor cannot smuggle deeper nesting in.
  const smuggling = new Observer({ mode: "metadata", sink: { write: () => {} }, redactor: (key, value) => key === "smuggled" ? nest(MAX_PAYLOAD_DEPTH) : value });
  assert.equal(await smuggling.emit(event({ metadata: { smuggled: 1 } })), undefined);
  assert.equal(smuggling.getState().dropped_events, 1);
  // Content is copied, and therefore depth checked, only in content mode.
  const contentMode = new Observer({ mode: "content", sink: { write: () => {} } });
  assert.equal(await contentMode.emit(event({ content: nest(MAX_PAYLOAD_DEPTH + 1) })), undefined);
  const metadataMode = new Observer({ mode: "metadata", sink: { write: () => {} } });
  assert.ok(await metadataMode.emit(event({ content: nest(MAX_PAYLOAD_DEPTH + 1) })));
});

test("duration_ms must be a safe integer count of milliseconds", async () => {
  const seen = []; const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) }, idFactory: ids(), clock: clock() });
  const refused = [2 ** 53, 2 ** 60, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER + 2];
  for (const bad of refused) assert.equal(await observer.emit(event({ duration_ms: bad })), undefined);
  assert.deepEqual(seen, []); assert.equal(observer.getState().dropped_events, refused.length);
  assert.equal((await observer.emit(event({ duration_ms: Number.MAX_SAFE_INTEGER }))).duration_ms, Number.MAX_SAFE_INTEGER);
  // A measured span too large to be a safe integer is unmeasurable, never rounded into range.
  const wide = []; const steps = [0, 1e300];
  const measured = new Observer({ mode: "metadata", sink: { write: e => wide.push(e) }, idFactory: ids(), clock: clock(), monotonic: { now: () => steps.shift() } });
  const done = duration_ms => ({ type: "tool.end", capture_status: "complete", duration_ms, metadata: {} });
  await measured.observeAsync({ type: "tool.start", capture_status: "complete", metadata: {} }, done, done, async () => "value");
  await measured.flush();
  assert.equal(Object.keys(plain(wide.at(-1))).includes("duration_ms"), false);
  assert.equal(wide.at(-1).capture_status, "partial");
  assert.equal(wide.at(-1).metadata.observer_capture_gap, true);
  // A span the wire cannot carry exactly is a gap on a delivered event, not a lost one.
  assert.deepEqual(measured.getState(), { dropped_events: 0, capture_gap: true, last_sink_error: "observer instrumentation failure" });
});

test("an event built while instrumentation failed is downgraded to partial and marked", async () => {
  const seen = []; let reads = 0;
  const observer = new Observer({
    mode: "content", sink: { write: e => seen.push(e) }, runId: "r", producerId: "p", idFactory: ids(),
    clock: { now: () => { reads += 1; if (reads === 1) throw new Error("clock"); return new Date(1_700_000_000_000); } },
  });
  const degraded = await observer.emit(event());
  assert.equal(degraded.timestamp, "1970-01-01T00:00:00.000Z");
  assert.equal(degraded.capture_status, "partial");
  assert.equal(degraded.metadata.observer_capture_gap, true);
  // The clock read that failed marked this event and flagged the gap. The event still reached
  // the sink, so nothing was lost and nothing is counted.
  assert.deepEqual(observer.getState(), { dropped_events: 0, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  const healthy = await observer.emit({ type: "model.response", capture_status: "complete", metadata: { model: "x" } });
  assert.equal(healthy.capture_status, "complete");
  assert.equal(healthy.metadata.observer_capture_gap, undefined);
  // An explicitly unavailable event survives the downgrade and still carries the marker.
  const unavailable = new Observer({ mode: "content", sink: { write: e => seen.push(e) }, runId: "r", producerId: "p", idFactory: { next: () => { throw new Error("ids"); } }, clock: { now: () => new Date(1_700_000_000_000) } });
  const marked = await unavailable.emit({ type: "observer.error", capture_status: "unavailable", metadata: { reason: "fixture gap" } });
  assert.equal(marked.capture_status, "unavailable");
  assert.equal(marked.metadata.observer_capture_gap, true);
  assert.equal(marked.event_id, "event-fallback-1");
  // The emitter owns the key and overwrites a caller value of the same name.
  const claimed = new Observer({ mode: "content", sink: { write: () => {} }, clock: { now: () => { throw new Error("clock"); } } });
  const overwritten = await claimed.emit(event({ metadata: { observer_capture_gap: "not mine to set" } }));
  assert.equal(overwritten.metadata.observer_capture_gap, true);
});

test("the Clock interface cannot carry sub-millisecond precision", async () => {
  // Date counts whole milliseconds, so a finer clock loses its fraction before the emitter
  // sees it. The emitter neither rounds nor pads to hide that, and never orders by timestamp.
  const seen = [];
  const observer = new Observer({ mode: "metadata", sink: { write: e => seen.push(e) }, idFactory: ids(), clock: { now: () => new Date(1_700_000_000_000.75) } });
  await observer.emit(event()); await observer.emit(event());
  assert.equal(seen[0].timestamp, "2023-11-14T22:13:20.000Z");
  assert.equal(seen[0].timestamp, seen[1].timestamp);
  assert.deepEqual([seen[0].sequence, seen[1].sequence], [0, 1]);
  assert.deepEqual(observer.getState(), { dropped_events: 0, capture_gap: false, last_sink_error: null });
});

test("dropped_events counts only events that reached no sink", async () => {
  // A clock, an ID factory, or an elapsed-time source that fails leaves a delivered event
  // carrying a fabricated or absent field. The event is marked, the gap is flagged, and the
  // counter is left alone, because counting it would report a loss that did not happen and
  // hide the ones that did. Python splits _mark_gap from _lost_event over exactly this.
  const seen = [];
  const degraded = new Observer({
    mode: "content", sink: { write: e => seen.push(e) }, runId: "r", producerId: "p",
    idFactory: { next: () => { throw new Error("ids"); } },
    clock: { now: () => { throw new Error("clock"); } },
    monotonic: { now: () => { throw new Error("monotonic"); } },
  });
  const marked = await degraded.emit({ type: "model.request", capture_status: "complete", metadata: { model: "x" } });
  assert.equal(seen.length, 1);
  assert.equal(marked.event_id, "event-fallback-1");
  assert.equal(marked.timestamp, "1970-01-01T00:00:00.000Z");
  assert.equal(marked.capture_status, "partial");
  assert.equal(marked.metadata.observer_capture_gap, true);
  assert.deepEqual(degraded.getState(), { dropped_events: 0, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  // An unmeasurable span is the same shape: both boundary events are delivered, so the failed
  // elapsed-time reads flag gaps and cost the duration, never a lost event.
  const done = duration_ms => ({ type: "tool.end", capture_status: "complete", duration_ms, metadata: {} });
  assert.equal(await degraded.observeAsync({ type: "tool.start", capture_status: "complete", metadata: {} }, done, done, async () => "value"), "value");
  await degraded.flush();
  assert.equal(seen.length, 3);
  assert.equal(seen.at(-1).capture_status, "partial");
  assert.equal(degraded.getState().dropped_events, 0);
  // The counter is not simply switched off: a failure that really did lose an event still
  // counts, and so does one that never reached a sink at all.
  const lost = new Observer({ mode: "content", sink: { write: () => { throw new Error("disk full"); } }, clock: clock(), idFactory: ids() });
  assert.ok(await lost.emit(event()));
  assert.equal(await lost.emit(event({ duration_ms: -1 })), undefined);
  assert.equal(lost.getState().dropped_events, 2);
});

test("a recording observer with no sink counts every event it builds as lost", async () => {
  // Builder mode is a real use, so the event is still built and returned; only the accounting
  // changes. Python's _write counts the same loss, because a state reporting zero for events
  // nobody received would be a black hole.
  const builder = new Observer({ mode: "content", idFactory: ids(), clock: clock(), runId: "r", producerId: "p" });
  const built = await builder.emit(event());
  assert.ok(built);
  assert.equal(built.event_id, "event-1"); assert.equal(built.sequence, 0);
  // The event itself is not marked: it was built cleanly and simply reached nobody, so the
  // loss belongs in the capture state rather than in the event's own metadata.
  assert.equal(built.capture_status, "redacted");
  assert.equal(built.metadata.observer_capture_gap, undefined);
  assert.deepEqual(builder.getState(), { dropped_events: 1, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  // One loss per event, and the previous loss never leaks into the next event's marking.
  const second = await builder.emit(event());
  assert.equal(second.sequence, 1);
  assert.equal(second.metadata.observer_capture_gap, undefined);
  assert.equal(builder.getState().dropped_events, 2);
  // A sink explicitly handed as null is the same builder mode, not a wiring mistake.
  const nulled = new Observer({ mode: "content", sink: null });
  assert.ok(await nulled.emit(event()));
  assert.equal(nulled.getState().dropped_events, 1);
  // Off mode has no sink either, but it records nothing, so it has lost nothing to count.
  const quiet = new Observer({ mode: "off" });
  assert.equal(await quiet.emit(event()), undefined);
  assert.deepEqual(quiet.getState(), { dropped_events: 0, capture_gap: false, last_sink_error: null });
});

test("the constructor refuses the wiring mistakes the Python constructor refuses", async () => {
  // Wiring is a programming mistake, fixed once before a run, so it throws here rather than
  // degrading every event during one. Python raises on the same three, and nothing during a
  // scan raises in either language.
  assert.throws(() => new Observer({ mode: "not-a-mode", sink: { write: () => {} } }), /unknown recording mode/);
  assert.throws(() => new Observer({ mode: "content", sink: {} }), /callable write/);
  assert.throws(() => new Observer({ mode: "content", sink: { *write(e) { yield e; } } }), /generator function/);
  assert.throws(() => new Observer({ mode: "content", sink: { async *write(e) { yield e; } } }), /generator function/);
  assert.throws(() => new Observer({ mode: "content", sink: function* (e) { yield e; } }), /generator function/);
  // Reading write can run a caller's getter, so a failure there is reported as an unusable
  // sink rather than escaping the constructor as whatever it threw.
  assert.throws(() => new Observer({ mode: "content", sink: { get write() { throw new Error("hostile getter"); } } }), /sink cannot be used/);
  // The mode is checked first and an unknown one is refused with or without a sink; it can
  // never be off, so no mode's privileges excuse it.
  assert.throws(() => new Observer({ mode: "not-a-mode" }), /unknown recording mode/);
  assert.throws(() => new Observer({ mode: "metadata", sink: 7 }), /callable write/);
  // Off mode reads nothing off the sink it was handed, not even that one property, so a sink
  // a recording mode would refuse is simply never looked at.
  let reads = 0;
  const quiet = new Observer({ mode: "off", sink: { get write() { reads += 1; return function* () {}; } } });
  assert.equal(await quiet.emit(event()), undefined);
  assert.equal(reads, 0);
  // Usable wiring still constructs, sync sink, async sink, and no sink at all.
  assert.ok(new Observer({ mode: "content", sink: { write: () => {} } }));
  assert.ok(new Observer({ mode: "content", sink: { write: async () => {} } }));
  assert.ok(new Observer({ mode: "content", sink: createJsonlSink(() => {}) }));
  assert.ok(new Observer({ mode: "content" }));
});

test("createJsonlSink refuses the generator writers the constructor refuses", () => {
  // Calling a generator writer returns an iterator and writes nothing: accepted, it would cost
  // every line in silence, with no thrown error and a capture state that still read clean.
  // This is the constructor's own classification applied to the writer a sink is built from,
  // and Python's create_jsonl_sink raises on the same writers.
  const lines = [];
  assert.throws(() => createJsonlSink(function* (line) { lines.push(line); yield line; }), /generator function/);
  assert.throws(() => createJsonlSink(async function* (line) { lines.push(line); yield line; }), /generator function/);
  assert.deepEqual(lines, []);
  // A plain writer and a promise-returning writer are both usable and still accepted.
  assert.equal(typeof createJsonlSink(line => lines.push(line)).write, "function");
  assert.equal(typeof createJsonlSink(async line => { lines.push(line); }).write, "function");
});

test("a write that returns an undriven generator is a lost event, not clean capture", async () => {
  // The wiring guard classifies a callable, so it catches a writer or sink that IS a generator
  // function. One that merely RETURNS a generator passes createJsonlSink and the constructor,
  // runs none of its body, throws nothing, and used to leave a capture state reading clean
  // while every event was lost: the quietest way for a trace to be empty. It is caught at
  // write time now, on the value the write handed back, and Python's _write counts the same
  // loss on the same shapes.
  const lines = [];
  const sink = createJsonlSink((line) => (function* () { lines.push(line); })());
  const observer = new Observer({ mode: "metadata", sink, idFactory: ids(), clock: clock() });
  assert.ok(await observer.emit(event()));
  assert.deepEqual(lines, []);
  assert.deepEqual(observer.getState(), { dropped_events: 1, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  // One loss per event it swallowed, not one for the wiring.
  assert.ok(await observer.emit(event()));
  assert.equal(observer.getState().dropped_events, 2);
  // An async generator is the same silence in the other shape.
  const streamed = new Observer({ mode: "metadata", sink: { write: (e) => (async function* () { yield e; })() }, idFactory: ids(), clock: clock() });
  assert.ok(await streamed.emit(event()));
  assert.deepEqual(streamed.getState(), { dropped_events: 1, capture_gap: true, last_sink_error: "observer instrumentation failure" });
  // The control: writes that really do write are untouched, sync and async alike, and neither
  // is read as an iterator nobody drives.
  const written = [];
  const plain = new Observer({ mode: "metadata", sink: { write: (e) => { written.push(e); } }, idFactory: ids(), clock: clock() });
  assert.ok(await plain.emit(event()));
  const awaited = new Observer({ mode: "metadata", sink: { write: async (e) => { written.push(e); } }, idFactory: ids(), clock: clock() });
  assert.ok(await awaited.emit(event()));
  await awaited.flush();
  assert.equal(written.length, 2);
  assert.deepEqual(plain.getState(), { dropped_events: 0, capture_gap: false, last_sink_error: null });
  assert.deepEqual(awaited.getState(), { dropped_events: 0, capture_gap: false, last_sink_error: null });
});
