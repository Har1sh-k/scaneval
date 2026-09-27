/**
 * Offline integration fixture for the TypeScript observer SDK. Not a scanner evaluation.
 *
 * Everything this file calls a "model" or a "tool" is a canned function defined below. It sends
 * no request, opens no socket, reads no repository, loads no ruleset, and holds no truth label,
 * so the findings it prints are fabricated fixture data and the numbers mean nothing about any
 * scanner. Nothing here scores, ranks, or compares anything.
 *
 * It is the mirror of examples/observer/python_harness.py: same boundaries, same order, same
 * printed shape. Running both is how a reader sees that the two emitters agree; the tests in
 * tests/test_v2_observer_parity.py are what actually pin that.
 *
 * The clock, the ID factory, and the tool duration are fixed constants rather than measurements,
 * so two runs of this file print the same bytes. A real harness passes the real clock and times
 * real work; this fixture times nothing.
 *
 * Run it with no arguments, with any tsx, against the built SDK under sdk/typescript/dist:
 *
 *   tsx examples/observer/typescript_harness.mts
 */

import { createJsonlSink, Observer, type TraceEvent } from "../../sdk/typescript/dist/index.js";

// Fixed so the printed output is reproducible. A real harness passes the real clock.
const EPOCH_MS = Date.UTC(2026, 8, 20, 12, 0, 0, 0);
const CLOCK_STEP_MS = 10;
// Not a measurement. This fixture dispatches a function that returns a constant.
const FAKE_TOOL_MS = 7;
const TYPE_WIDTH = 19;
const STATUS_WIDTH = 9;

/** A clock that advances a fixed step per read. It never consults the wall clock. */
function fixedClock() {
  let reads = 0;
  return { now: () => new Date(EPOCH_MS + CLOCK_STEP_MS * reads++) };
}

/** An ID factory that counts. Deterministic on purpose; not unique across processes. */
function countingIds() {
  let issued = 0;
  return { next: (prefix: string) => `${prefix}-${++issued}` };
}

/** Return a canned completion. Calls no provider, reads no key, and ignores the prompt. */
function fakeModel(_prompt: string) {
  return { text: "two candidates in app/runner.py", finish_reason: "stop", output_tokens: 18 };
}

/** Return a canned tool result. Opens no file and never touches `path` on disk. */
function fakeTool(path: string) {
  return { matched: 2, path };
}

/** The event ID to hang a child event from, or undefined when nothing was recorded. */
function link(event: TraceEvent | undefined): string | undefined {
  return event === undefined ? undefined : event.event_id;
}

interface Report {
  findings: { rule: string; path: string; line: number }[];
}

/**
 * Run the fake scan, emitting at each boundary. Returns the report, tracing or not.
 *
 * The emitter is handed explicit events at a fake model boundary, a fake tool dispatch, and
 * each finding transition. It discovers none of them: an `off` observer makes every call here
 * a no-op and the returned report is unchanged.
 */
async function runScan(observer: Observer): Promise<Report> {
  // Model boundary. The credential below is fixture text, and the default redactor hides it
  // because of its key name, which is why this event is stored as redacted rather than
  // complete. input_tokens is kept: a counter is not a credential.
  const request = await observer.emit({
    type: "model.request",
    capture_status: "complete",
    call_id: "call-1",
    metadata: { model: "fake-model-v0", input_tokens: 31 },
    content: { api_key: "fixture-not-a-real-credential", prompt: "review app/runner.py" },
  });
  const completion = fakeModel("review app/runner.py");
  await observer.emit({
    type: "model.response",
    capture_status: "complete",
    call_id: "call-1",
    parent_event_id: link(request),
    metadata: { model: "fake-model-v0", output_tokens: completion.output_tokens },
    content: { text: completion.text, finish_reason: completion.finish_reason },
  });

  // Tool dispatch boundary.
  const started = await observer.emit({
    type: "tool.start",
    capture_status: "complete",
    call_id: "call-2",
    metadata: { tool: "grep", path: "app/runner.py" },
    content: { arguments: { pattern: "shell=True" } },
  });
  const result = fakeTool("app/runner.py");
  await observer.emit({
    type: "tool.end",
    capture_status: "complete",
    call_id: "call-2",
    parent_event_id: link(started),
    duration_ms: FAKE_TOOL_MS,
    metadata: { tool: "grep", matched: result.matched },
    content: { result },
  });

  // A candidate the harness drops before reporting. candidate_id links the two events.
  await observer.emit({
    type: "finding.candidate",
    capture_status: "complete",
    candidate_id: "candidate-1",
    metadata: { rule: "py.subprocess-shell-true", path: "tests/fixtures/shell.py", line: 8 },
  });
  await observer.emit({
    type: "finding.filtered",
    capture_status: "complete",
    candidate_id: "candidate-1",
    metadata: { reason: "path is test fixture material" },
  });

  // A candidate that survives to the report. The submitted event carries the claim ID.
  await observer.emit({
    type: "finding.candidate",
    capture_status: "complete",
    candidate_id: "candidate-2",
    metadata: { rule: "py.subprocess-shell-true", path: "app/runner.py", line: 42 },
  });
  await observer.emit({
    type: "finding.validation",
    capture_status: "complete",
    candidate_id: "candidate-2",
    metadata: { verdict: "kept", checked: "reachability" },
  });
  await observer.emit({
    type: "finding.submitted",
    capture_status: "complete",
    candidate_id: "candidate-2",
    claim_id: "claim-1",
    metadata: { rule: "py.subprocess-shell-true", path: "app/runner.py", line: 42 },
  });
  return { findings: [{ rule: "py.subprocess-shell-true", path: "app/runner.py", line: 42 }] };
}

/** One readable line per event. The JSONL block below is the authoritative record. */
function describe(event: TraceEvent): string {
  const links = (["call_id", "parent_event_id", "candidate_id", "claim_id", "duration_ms"] as const)
    .filter((name) => event[name] !== undefined)
    .map((name) => `${name}=${event[name]}`);
  return `  event ${event.sequence}  ${event.type.padEnd(TYPE_WIDTH)}${
    event.capture_status.padEnd(STATUS_WIDTH)
  } ${links.join(" ")}`.replace(/\s+$/, "");
}

const EXPECTED_TYPES = [
  "model.request",
  "model.response",
  "tool.start",
  "tool.end",
  "finding.candidate",
  "finding.filtered",
  "finding.candidate",
  "finding.validation",
  "finding.submitted",
];

async function main(): Promise<number> {
  console.log("ScanEval observer example harness (TypeScript)");
  console.log("Integration fixture only: fake model and fake tool functions, no model call, no");
  console.log("network call, no real scanner, no truth labels.");
  console.log("");

  console.log("step 1  run with tracing off");
  const silent: TraceEvent[] = [];
  const off = new Observer({
    sink: { write: (event) => { silent.push(event); } },
    clock: fixedClock(),
    idFactory: countingIds(),
  });
  const untraced = await runScan(off);
  console.log(`  events recorded: ${silent.length}`);
  console.log(`  findings reported: ${untraced.findings.length}`);
  console.log("");

  console.log("step 2  the same run with tracing turned on by the caller (mode=content)");
  const lines: string[] = [];
  const recorded: TraceEvent[] = [];
  const jsonl = createJsonlSink((line) => { lines.push(line); });
  const observer = new Observer({
    mode: "content",
    sink: { write: (event) => { recorded.push(event); return jsonl.write(event); } },
    runId: "run-observer-example",
    producerId: "example-harness",
    clock: fixedClock(),
    idFactory: countingIds(),
  });
  const traced = await runScan(observer);
  for (const event of recorded) console.log(describe(event));
  console.log(`  events recorded: ${recorded.length}`);
  console.log(`  findings reported: ${traced.findings.length}`);
  const identical = JSON.stringify(traced) === JSON.stringify(untraced);
  console.log(`  report identical to the untraced run: ${identical}`);
  console.log("");

  console.log("step 3  explicit flush");
  await observer.flush();
  const state = observer.getState();
  console.log(
    `  capture state: dropped_events=${state.dropped_events} ` +
      `capture_gap=${state.capture_gap} ` +
      `last_sink_error=${state.last_sink_error ?? "none"}`,
  );
  console.log("");

  console.log(`trace jsonl (${lines.length} lines)`);
  for (const line of lines) console.log(`  ${line.replace(/\n$/, "")}`);

  // A fixture that recorded nothing would still print the headings above, so fail loudly.
  const seen = recorded.map((event) => event.type);
  if (seen.length !== EXPECTED_TYPES.length || seen.join(",") !== EXPECTED_TYPES.join(",")) {
    console.error(`unexpected trace: ${recorded.length} events`);
    return 1;
  }
  if (JSON.parse(lines[0]).type !== EXPECTED_TYPES[0]) {
    console.error("jsonl sink disagreed with the recorded events");
    return 1;
  }
  return 0;
}

process.exitCode = await main();
