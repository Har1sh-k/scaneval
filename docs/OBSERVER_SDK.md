# Experimental TypeScript observer SDK

`@sastbench/observer-sdk` is a small, opt-in emitter for observing an existing harness. It is not an integration with SecureVibes (or any other product), does not make model/provider calls, does not retrieve data, does not enforce policy, and does not monkeypatch global clients. Importing it captures nothing. A harness must explicitly emit at its real model-client, tool-dispatch, context-selection, and finding-lifecycle boundaries.

The language-neutral event contract is [`schema/v2/trace-event.schema.json`](../schema/v2/trace-event.schema.json). Every event has schema version `2.0`, run/producer/event IDs, a producer-local nonnegative sequence, timestamp, type/category, capture status, and metadata. Parent and call references retain a chronological partial order across concurrent producers. `candidate_id` is a stable lifecycle link; emitting validation or filtering is optional and must reflect actual observed stages rather than invented ones.

## Build and test

From `sdk/typescript`:

```sh
npm install
npm run build
npm test
```

The package has no runtime dependencies. Build output is conventional `dist/` JavaScript and declarations; consumers import `@sastbench/observer-sdk` after publishing or use the local package path.

## Recording and privacy

Modes are `off` (the default), `metadata`, and `content`. Off is a no-op. Metadata mode deliberately omits `content`; content mode stores a cloned, redacted copy of both metadata and content. The SDK never changes the objects passed to the harness. Its default redactor replaces values for common credential-looking keys (for example `authorization`, `apiKey`, `token`, and `password`); pass a `redactor` for local policy.

This is not automatic PII removal, a privacy certification, or a safe-to-upload guarantee. Keep traces locally unless a separate, approved retention and upload policy permits otherwise. It never requests hidden model reasoning or infers CVE knowledge; only harness-exposed data explicitly supplied in events is recorded.

All instrumentation failures (including sink, clock, ID factory, redactor, and non-serializable/cyclic payload failures) are converted into a visible capture gap so they cannot alter the observed harness operation. After the scan has completed, call `await observer.flush()` before reading `getState()` or terminating the process: it drains writes that `emit`/`observeAsync` intentionally do not await. A sink that never settles makes `flush()` wait forever, so integrations must apply their own timeout/abort policy outside the scan operation and report that as incomplete capture. `capture_gap: true` and `dropped_events` mean the trace is incomplete. Do not interpret absent events as absent activity unless that category was captured completely. The JSONL helper accepts a caller-owned writer; it never opens or globally captures a filesystem stream. Metadata mode marks a formerly complete event as `partial` because it omits content; any redacted stored value marks it `redacted` (except explicitly `unavailable` capture, which remains unavailable).

## Minimal hypothetical harness instrumentation

This illustrates calls an existing dispatcher/model client could make. It is not a claim that an integration already exists.

```ts
import { Observer, createJsonlSink } from "@sastbench/observer-sdk";

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

Emit `tool.start` and `tool.end` around the actual dispatcher boundary, linking them with `call_id`/`parent_event_id`; emit model-visible input separately from tool arguments/results. For streaming, leave the iterator untouched and explicitly emit only the lifecycle facts available at chosen boundaries. `observeAsync` is an optional helper for a Promise boundary; it rethrows the original operation error and does not consume or rewrite streams. Its duration ends when that Promise resolves, so a Promise that returns an async iterator does **not** time consumption of the full stream. This repository has no actual model-provider or SecureVibes integration yet.
