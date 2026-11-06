# ScanEval Observer

An opt-in emitter for recording what an instrumented security-scanner harness does.
It records model calls, tool use, supplied context, and finding lifecycle events using
ScanEval's versioned trace contract. It makes no model calls and has no runtime dependencies.

This is an **alpha** package. The package version is `0.1.0-alpha.1`; emitted events use
wire schema version `2.0`. APIs may change during the alpha.

## Install

Requires Node.js 22 or later. The package is ESM only and includes TypeScript declarations.

```sh
npm install @scaneval/observer@next
# Or pin this release:
npm install @scaneval/observer@0.1.0-alpha.1
```

## Record an event

```js
import { Observer, createJsonlSink } from "@scaneval/observer";

const lines = [];
const observer = new Observer({
  mode: "metadata",
  runId: "example-run",
  producerId: "example-harness",
  sink: createJsonlSink((line) => { lines.push(line); }),
});

await observer.emit({
  type: "model.request",
  capture_status: "complete",
  call_id: "call-1",
  metadata: { model: "example-model", input_tokens: 12 },
});
await observer.close();

console.log(lines.join(""));
console.log(observer.getState());
```

The sink belongs to your harness; this example stores JSONL in memory. Instrument your
actual model-client and tool-dispatch boundaries to record activity. Importing the package
records nothing, and an observer defaults to `mode: "off"`.

`metadata` omits event content. `content` also retains supplied prompts, responses, and
other content. The default redactor filters known secret key names; it does not scrub
arbitrary text or establish that a trace is safe to share.

Await `close()` to drain pending writes when the harness finishes, then inspect
`getState()`. `capture_gap: true` reports incomplete capture; `dropped_events` counts writes
the sink never acknowledged. Neither a clean state nor an absent event proves the harness
emitted everything it should have observed. Instrumentation failures are contained and
reported as capture gaps.

See the [Observer guide](https://github.com/Har1sh-k/scaneval/blob/main/docs/OBSERVER_SDK.md)
for the complete API, modes, Python parity, and capture limits, and the
[trace schema](https://github.com/Har1sh-k/scaneval/blob/main/schema/v2/trace-event.schema.json)
for event fields. Emitters observe a harness; they do not judge whether a finding is correct.

## Development

From `sdk/typescript` in the repository:

```sh
npm ci --ignore-scripts
npm test
npm run test:package
```

`npm pack` builds JavaScript and declarations before creating the package.
`test:package` packs and installs the tarball in a temporary consumer, then checks ESM
behavior and TypeScript imports. It can also check an existing tarball:
`npm run test:package -- /absolute/path/to/package.tgz`.

## License

[MIT](LICENSE).
