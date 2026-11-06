// Verify the package boundary a registry consumer receives, without model or network calls.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const scratch = mkdtempSync(join(tmpdir(), "scaneval-observer-package-"));
const run = (command, args, cwd = scratch) => execFileSync(command, args, {
  cwd, encoding: "utf8", timeout: 120_000, stdio: "pipe",
  env: { ...process.env, npm_config_cache: join(scratch, "npm-cache") },
});

try {
  let tarball;
  if (process.argv[2]) {
    tarball = resolve(process.argv[2]);
  } else {
    run("npm", ["pack", "--pack-destination", scratch], root);
    const packages = readdirSync(scratch).filter((name) => name.endsWith(".tgz"));
    assert.equal(packages.length, 1, "npm pack must create one tarball");
    tarball = join(scratch, packages[0]);
  }
  writeFileSync(join(scratch, "package.json"), JSON.stringify({ private: true, type: "module" }));
  run("npm", ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false", tarball]);
  const installed = join(scratch, "node_modules", "@scaneval", "observer");
  const manifest = JSON.parse(readFileSync(join(installed, "package.json"), "utf8"));
  assert.equal(manifest.name, "@scaneval/observer");
  assert.equal(manifest.version, JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version);
  assert.equal(manifest.license, "MIT");
  assert.equal(manifest.private, undefined);
  assert.deepEqual(manifest.dependencies ?? {}, {}, "the observer has no runtime dependencies");
  for (const name of ["README.md", "LICENSE", "dist/index.js", "dist/index.d.ts"]) {
    assert.ok(readFileSync(join(installed, name)).length, `missing package file ${name}`);
  }
  const readme = readFileSync(join(installed, "README.md"), "utf8");
  const quickstart = readme.match(/```js\n([\s\S]*?)\n```/);
  assert.ok(quickstart, "the package README needs a runnable quickstart");
  writeFileSync(join(scratch, "quickstart.mjs"), quickstart[1]);
  const quickstartOutput = run(process.execPath, ["quickstart.mjs"]);
  assert.match(quickstartOutput, /"schema_version":"2.0"/);
  assert.match(quickstartOutput, /capture_gap: false/);

  writeFileSync(join(scratch, "consumer.mjs"), `
import assert from "node:assert/strict";
import { Observer, SCHEMA_VERSION, createJsonlSink } from "@scaneval/observer";
const lines = [];
const observer = new Observer({ mode: "metadata", runId: "consumer", producerId: "harness",
  sink: createJsonlSink((line) => { lines.push(line); }) });
await observer.emit({ type: "model.request", capture_status: "complete",
  metadata: { model: "fixture", api_key: "never-store-this" } });
const event = JSON.parse(lines[0]);
assert.equal(SCHEMA_VERSION, "2.0");
assert.equal(event.schema_version, SCHEMA_VERSION);
assert.equal(event.sequence, 0);
assert.equal(event.metadata.api_key, "[REDACTED]");
assert.equal(event.capture_status, "redacted");
assert.equal(event.content, undefined);
assert.equal(await observer.observeAsync(
  { type: "tool.start", capture_status: "complete", metadata: {} },
  (duration_ms) => ({ type: "tool.end", capture_status: "complete", duration_ms, metadata: {} }),
  (duration_ms) => ({ type: "tool.end", capture_status: "partial", duration_ms, metadata: {} }),
  async () => 42), 42);
await observer.close();
assert.equal(lines.length, 3);
assert.deepEqual(observer.getState(), { dropped_events: 0, capture_gap: false, last_sink_error: null });
`);
  run(process.execPath, ["consumer.mjs"]);
  writeFileSync(join(scratch, "consumer.mts"), `
import { Observer, createJsonlSink, type CaptureState, type RecordingMode, type TraceEvent } from "@scaneval/observer";
const mode: RecordingMode = "metadata";
const observer = new Observer({ mode, sink: createJsonlSink((_line: string) => {}) });
const event: TraceEvent | undefined = await observer.emit({
  type: "model.request", capture_status: "complete", metadata: { input_tokens: 12 },
});
const state: CaptureState = observer.getState();
void event; void state;
// @ts-expect-error The public declaration must reject unknown event types.
await observer.emit({ type: "unknown.event", capture_status: "complete", metadata: {} });
await observer.close();
`);
  run(process.execPath, [join(root, "node_modules", "typescript", "bin", "tsc"),
    "--noEmit", "--strict", "--target", "ES2022", "--module", "NodeNext",
    "--moduleResolution", "NodeNext", "--lib", "ES2022", "consumer.mts"]);
  process.stdout.write(`Package install, README example, ESM behavior, and TypeScript declarations passed on ${process.version}.\n`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
