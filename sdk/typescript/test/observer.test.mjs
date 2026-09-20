import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Observer, createJsonlSink } from "../dist/index.js";

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
  assert.ok(observer.getState().dropped_events >= 4);
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
