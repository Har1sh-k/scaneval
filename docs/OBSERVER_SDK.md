# Observer SDK

Two emitters, one wire contract. `scaneval.observer` (Python, `src/scaneval/observer/`) and `@scaneval/observer` (TypeScript, `sdk/typescript/`) are small, opt-in emitters for observing an existing harness. Neither is an integration with SecureVibes or any other product, neither makes model or provider calls, retrieves data, enforces policy, or monkeypatches global clients. Importing either captures nothing. A harness must explicitly emit at its real model-client, tool-dispatch, context-selection, and finding-lifecycle boundaries.

The language-neutral event contract is [`schema/v2/trace-event.schema.json`](../schema/v2/trace-event.schema.json). Every event has schema version `2.0`, run/producer/event IDs, a producer-local nonnegative sequence, timestamp, type/category, capture status, and metadata. Parent and call references retain a chronological partial order across concurrent producers. `candidate_id` is a stable lifecycle link; emitting validation or filtering is optional and must reflect actual observed stages rather than invented ones.

## Build and test

From `sdk/typescript`:

```sh
npm install
npm run build
npm test
```

The package has no runtime dependencies. Build output is conventional `dist/` JavaScript and declarations; consumers import `@scaneval/observer` after publishing or use the local package path.

The Python emitter is tested by `python -m pytest`. Cross-language parity is tested by [`tests/test_v2_observer_parity.py`](../tests/test_v2_observer_parity.py), which runs both emitters over one input matrix with the same injected clock, ID factory, sink, and redactor and compares the JSONL byte for byte, the recorded/refused decision per input, the sequence numbers and event IDs, and the final capture state. It drives the TypeScript side with a throwaway driver under `node` against `sdk/typescript/dist/index.js` and skips with a reason when either is missing, so a skipped run is never reported as a checked one.

## The parity contract

These are rules of the contract, not implementation details of either emitter. Changing one changes both, the schema where it is expressible, and the parity matrix in the same edit.

**1. One rejection set.** The two emitters accept and reject exactly the same inputs. Where they once differed, the stricter rule is the shared one. An event is refused when it carries an unknown field name, an unknown `type`, a `category` that contradicts its `type`, an unknown `capture_status`, a missing or non-object `metadata`, a non-object `content`, a `duration_ms` that is not a nonnegative whole number, or a link ID (`parent_event_id`, `call_id`, `attempt_id`, `candidate_id`, `claim_id`) that is present but is not a nonempty string. A cyclic payload, a non-finite number in a payload, a non-string object key, and a value that is not JSON are refused the same way. Absence is spelled by omitting the field: a field present with the value `null` (Python `None`) is refused, never read as absent, because reading it as absent would record an event the harness did not describe. `content` is copied and therefore validated only in `content` mode, so a payload that only the copy would refuse is accepted in `metadata` mode by both emitters.

**2. A refused event costs nothing.** It consumes no sequence number, no event ID, and no clock read in either language. That is only safe because the rejection sets are identical: if one emitter refused an input the other accepted, every later event in that producer's stream would carry a different sequence number, a different ID, and a different timestamp in the two languages. This is why rule 1 is a contract.

**3. `duration_ms` is an integer number of milliseconds.** A non-integral, negative, non-finite, or null duration is refused in both languages, and an integral float is stored as an integer so both write the same bytes. The schema says `"type": "integer"`, so an event that violated this would also fail schema validation.

**4. The default redactor folds case over ASCII only.** Python spells it `re.IGNORECASE | re.ASCII`; JavaScript uses `/.../i` without the `u` flag. Both hide the same whole key names (`api_key`, `apikey`, `api-key`, `authorization`, `credential(s)`, `cookie(s)`, `password`, `secret(s)`, `token`, `private_key`, `private-key`, any case) and neither hides a key that merely contains one, such as `input_tokens`. A Unicode character whose ASCII uppercase looks like part of a credential name, for example U+212A KELVIN SIGN or U+017F LATIN SMALL LETTER LONG S, is left alone by both. Without `re.ASCII` Python would hide `toKen` and `ſecret` while JavaScript kept them, which is a divergence the parity matrix now carries a case for.

**5. Redaction is decided by reference identity, never by value equality.** A redactor that hands back a structurally equal copy still counts as having replaced the value, so the event is marked `redacted` in both languages. JavaScript has no distinct reference for a primitive, so a redactor that returns an equal string changes nothing in either language; use a container to see the rule.

**6. Emitted key order is the schema's declaration order.** `schema_version`, `event_id`, `run_id`, `producer_id`, `sequence`, `type`, `category`, `capture_status`, `timestamp`, then the link fields in the order the schema lists them, then `duration_ms`, `metadata`, and `content`. A JSONL line from either language is byte identical, key order included.

**7. Instrumentation never alters the caller.** Every caller-supplied hook (clock, monotonic source, ID factory, redactor, event builder) and every sink write runs under a `BaseException` guard. A failure becomes a counted capture gap and only `KeyboardInterrupt` and `SystemExit` are re-raised, because those are the caller's own interrupt rather than an instrumentation defect. An `asyncio.CancelledError` raised by a sink is a recorded gap, not an escape. The observed operation's return value and its exception, including a JavaScript throw of a non-`Error` value, pass through untouched.

**8. Capture state carries the same three fields.** `dropped_events`, `capture_gap`, and `last_sink_error`, with `last_sink_error` present and `null` until something fails. It names the failure class rather than quoting an exception, because a sink's error text can carry the payload it failed to write.

## Recording and privacy

Modes are `off` (the default), `metadata`, and `content`. Off is a no-op: it never calls the clock, the ID factory, the redactor, or the sink, and names its run and producer `off` rather than consuming an ID. Metadata mode deliberately omits `content`; content mode stores a cloned, redacted copy of both metadata and content. Neither SDK changes the objects passed to the harness: metadata and content are deep copied into plain JSON types before anything is stored, and a caller-supplied redactor is treated as untrusted instrumentation whose output is copied and revalidated the same way. Pass a `redactor` for local policy.

This is not automatic PII removal, a privacy certification, or a safe-to-upload guarantee. Keep traces locally unless a separate, approved retention and upload policy permits otherwise. Neither SDK requests hidden model reasoning or infers CVE knowledge; only harness-exposed data explicitly supplied in events is recorded.

All instrumentation failures (sink, clock, ID factory, redactor, event builder, and non-serializable or cyclic payloads) are converted into a visible capture gap so they cannot alter the observed harness operation. After the scan has completed, call `await observer.flush()` (TypeScript) or `await observer.aflush()` (Python, in an async harness) before reading the capture state or terminating the process: it drains writes that `emit` and the async observe helpers intentionally do not await. A sink that never settles makes the flush wait forever, so integrations must apply their own timeout or abort policy outside the scan operation and report that as incomplete capture. `capture_gap: true` and `dropped_events` mean the trace is incomplete. Do not interpret absent events as absent activity unless that category was captured completely. The JSONL helper accepts a caller-owned writer; it never opens or globally captures a filesystem stream. Metadata mode marks a formerly complete event as `partial` because it omits content; any redacted stored value marks it `redacted`; an explicitly `unavailable` capture status survives both downgrades.

## Known divergences and representational limits

Recorded here because a parity claim is only worth what its exceptions say.

**Open divergence: degraded events are marked in Python only.** When instrumentation fails while an event is being built, so that the event carries a fabricated ID or an epoch timestamp, the Python emitter downgrades its `capture_status` to `partial` (unless it is `unavailable`) and stamps `observer_capture_gap: true` into its metadata. The TypeScript emitter records the gap in the capture state but leaves the event itself claiming `complete`. Both count the gap identically, so the capture state agrees; the event does not. `tests/test_v2_observer_parity.py::test_a_clock_that_throws_marks_the_degraded_event_identically_in_both_languages` is a strict `xfail` over exactly this, so implementing the marking in TypeScript will fail the suite until the expectation is flipped. Until then, a reader joining traces from both languages must treat a fabricated-timestamp TypeScript event as unmarked.

**An integral float in a payload.** Python writes `1.0` where JavaScript writes `1`, because JavaScript has one number type. This is reachable only through a caller's own metadata or content value, never through a field the emitters own: `duration_ms` is normalized to an integer by rule 3. The parity matrix keeps integral floats out of payloads so the byte comparison stays meaningful.

**A payload key that looks like an array index.** JavaScript orders integer-like own property names ahead of the rest, so a metadata key such as `"2"` serializes in a different position than Python's insertion order. Both languages emit the same object; only the byte order differs. Avoid integer-like payload keys if byte-level joins matter.

## What the securevibes-agent and Fieldglass integration actually captures

The `llm-harness` adapter runs the securevibes-agent and Fieldglass engine family through its own entry point, injecting only the harness's default model runner wrapped by this observer plus a progress reporter. That injection point decides what can be seen, so the honest per-category matrix is the one below. It is the same matrix `scaneval.adapters.llm_harness.capture_status` returns for a run, and the driver repeats the unavailable list in its own output.

| Category | Capture | Why |
| --- | --- | --- |
| `model.request`, `model.response` | **partial** when tracing, `unavailable` when `trace_mode` is `off` | One request and one response event per logical call at the runner boundary. The harness retries inside its own runner, below that boundary, so retries are not observable (`retries_observable: false`), and the CLI route exposes no token usage (`usage_available: false`). What is recorded is the outgoing CLI request, the returned stdout, stderr, and exit code, and the measured duration. |
| `tool.start`, `tool.end` | **unavailable** on every real route | Tool dispatch happens inside the model CLI subprocess this driver spawns and cannot see into. No tool event is emitted, and the absence of one establishes nothing about whether a tool ran. Only the mock runner, which spawns no process at all, makes the concept not applicable. |
| `context.selection` | **partial** when tracing | Only the harness's own progress notes that name a file are emitted, marked `source: harness_self_report`. That is the harness describing itself, not the engine's actual selection decision. |
| `finding.submitted` | **complete** when tracing and the scan returned a summary, `unavailable` otherwise | Every finding in the returned summary, new and updated, is emitted with its `candidate_id` and `claim_id`. A scan that throws produces no summary, so the category is unavailable rather than empty. |
| `finding.candidate` | **unavailable** | The engine exposes no boundary for candidate creation. Only the findings it finally wrote are visible. |
| `finding.validation` | **unavailable** | Same reason: validation happens inside the engine, with no injection point for it. |
| `finding.filtered` | **unavailable** | Same reason. A finding the engine discarded leaves no trace the driver can observe, so no filtering event is emitted and no claim about filtering is made. |

`observer.error` is not emitted by this integration. Instrumentation loss shows up in the capture state the driver reports alongside `events_written` and `flush_timed_out`.

## Minimal hypothetical harness instrumentation

This illustrates calls an existing dispatcher or model client could make. It is not a claim that a second integration already exists.

```ts
import { Observer, createJsonlSink } from "@scaneval/observer";

const observer = new Observer({
  mode: "content",
  sink: createJsonlSink(existingTraceWriter),
  runId: existingRunId,
  producerId: "existing-dispatcher"
});

await observer.emit({
  type: "context.selection", capture_status: "complete",
  call_id, metadata: { included_count: snippets.length },
  content: { included_snippets: snippets }
});
await observer.emit({
  type: "model.request", capture_status: "complete",
  call_id, metadata: { model: resolvedModel }, content: { outgoing_request }
});
const response = await existingModelClient.send(outgoing_request); // unchanged request
await observer.emit({
  type: "model.response", capture_status: "complete", call_id,
  metadata: { model: resolvedModel }, content: { response }
});
```

The Python emitter takes the same fields as keyword arguments (`observer.emit(type="model.request", capture_status="complete", call_id=call_id, metadata={...})`) and refuses an unknown keyword rather than dropping it, because Python catches no misspelled field at compile time.

Emit `tool.start` and `tool.end` around the actual dispatcher boundary, linking them with `call_id` and `parent_event_id`; emit model-visible input separately from tool arguments and results. For streaming, leave the iterator untouched and explicitly emit only the lifecycle facts available at chosen boundaries. `observeAsync` (TypeScript) and `observe`/`observe_async` (Python) are optional helpers for one call boundary; they re-raise the original operation error and do not consume or rewrite streams. Their duration ends when that call's promise or awaitable resolves, so an operation that returns an async iterator does **not** time consumption of the full stream.
