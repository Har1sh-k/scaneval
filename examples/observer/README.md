# Observer example harnesses

Two runnable fixtures, one per language, that call the observer emitter the way a real harness
would. They exist so a reader can see the emission order and the resulting trace without wiring
anything up, and so the examples cannot rot silently: a test runs the Python one and compares
what it prints.

Both are integration fixtures and nothing else. Every "model" and "tool" in them is a canned
local function. **They make no model call and no network call**, read no repository, load no
ruleset, and hold no truth label, so the findings they print are fabricated and the numbers say
nothing about any scanner. Neither file evaluates, scores, or ranks anything.

Their clock, ID factory, and tool duration are fixed constants rather than measurements, which
is why two runs print the same bytes and why the timestamps below are in the future. A real
harness passes the real clock and times real work.

## The emitter follows the harness, not the scanned repository

**Pick the emitter that matches the language the harness is written in, not the language of the
repository being scanned.** A TypeScript agent scanning a Python repository emits with the
TypeScript SDK; a Python agent scanning a TypeScript repository emits with
`sastbench.observer`. The trace records what the harness did, so it is written in the harness's
own process, and the scanned tree's language never enters into it. A harness that spans both
languages runs one emitter per producer and gives each its own `producer_id`; the shared
`run_id` is what joins those traces afterwards.

The two emitters are behaviorally matched against one wire contract,
[`schema/v2/trace-event.schema.json`](../../schema/v2/trace-event.schema.json), and
`tests/test_v2_observer_parity.py` runs both over the same inputs to pin that. One difference
survives today: the Python emitter writes `metadata` after the optional link fields
(`parent_event_id`, `call_id`, `attempt_id`, `candidate_id`, `claim_id`, `duration_ms`) and the
TypeScript emitter writes it before them. The two lines parse to the same JSON object, and JSON
object key order is not significant, but they are not byte identical. Compare traces as parsed
events, not as text.

## Run them

Python, from the repository root, with no arguments:

```sh
.venv/bin/python examples/observer/python_harness.py
```

TypeScript, with any `tsx`, against the committed SDK build in `sdk/typescript/dist`:

```sh
tsx examples/observer/typescript_harness.mts
```

This repository vendors no `tsx`. The output below came from the one in a sibling checkout:

```sh
/Users/hk/Documents/GitHub/securevibes-agent/node_modules/.bin/tsx \
  examples/observer/typescript_harness.mts
```

Build the SDK first if `sdk/typescript/dist/index.js` is missing
(`npm --prefix sdk/typescript run build`). `tsx` prints a `module.register()` deprecation
warning to stderr on current node; it comes from `tsx` itself and has nothing to do with the
emitter.

Each harness demonstrates, in this order: a run with tracing off that records nothing; the same
run with tracing turned on by the caller; model request and response events at the fake model
boundary; tool start and end events at the fake tool dispatch; a candidate finding that is
filtered out; a finding that reaches the report, linked to the same `candidate_id` and carrying
a `claim_id`; and an explicit flush with the resulting capture state.

Two things in the output are worth reading twice. The report is identical with tracing on and
off, because the emitter never touches the value an observed operation returns. And the first
event is stored as `redacted` rather than `complete`: the default redactor replaced the
`api_key` value by key name while leaving `input_tokens` alone, and capture status never claims
more than was stored. That redactor is a key-name filter, not PII removal and not a
safe-to-upload guarantee.

## Real output: Python

```
ScanEval observer example harness (Python)
Integration fixture only: fake model and fake tool functions, no model call, no
network call, no real scanner, no truth labels.

step 1  run with tracing off
  events recorded: 0
  findings reported: 1

step 2  the same run with tracing turned on by the caller (mode=content)
  event 0  model.request      redacted  call_id=call-1
  event 1  model.response     complete  call_id=call-1 parent_event_id=event-1
  event 2  tool.start         complete  call_id=call-2
  event 3  tool.end           complete  call_id=call-2 parent_event_id=event-3 duration_ms=7
  event 4  finding.candidate  complete  candidate_id=candidate-1
  event 5  finding.filtered   complete  candidate_id=candidate-1
  event 6  finding.candidate  complete  candidate_id=candidate-2
  event 7  finding.validation complete  candidate_id=candidate-2
  event 8  finding.submitted  complete  candidate_id=candidate-2 claim_id=claim-1
  events recorded: 9
  findings reported: 1
  report identical to the untraced run: true

step 3  explicit flush
  capture state: dropped_events=0 capture_gap=false last_sink_error=none

trace jsonl (9 lines)
  {"schema_version":"2.0","event_id":"event-1","run_id":"run-observer-example","producer_id":"example-harness","sequence":0,"type":"model.request","category":"model","capture_status":"redacted","timestamp":"2026-09-20T12:00:00.000Z","call_id":"call-1","metadata":{"model":"fake-model-v0","input_tokens":31},"content":{"api_key":"[REDACTED]","prompt":"review app/runner.py"}}
  {"schema_version":"2.0","event_id":"event-2","run_id":"run-observer-example","producer_id":"example-harness","sequence":1,"type":"model.response","category":"model","capture_status":"complete","timestamp":"2026-09-20T12:00:00.010Z","parent_event_id":"event-1","call_id":"call-1","metadata":{"model":"fake-model-v0","output_tokens":18},"content":{"text":"two candidates in app/runner.py","finish_reason":"stop"}}
  {"schema_version":"2.0","event_id":"event-3","run_id":"run-observer-example","producer_id":"example-harness","sequence":2,"type":"tool.start","category":"tool","capture_status":"complete","timestamp":"2026-09-20T12:00:00.020Z","call_id":"call-2","metadata":{"tool":"grep","path":"app/runner.py"},"content":{"arguments":{"pattern":"shell=True"}}}
  {"schema_version":"2.0","event_id":"event-4","run_id":"run-observer-example","producer_id":"example-harness","sequence":3,"type":"tool.end","category":"tool","capture_status":"complete","timestamp":"2026-09-20T12:00:00.030Z","parent_event_id":"event-3","call_id":"call-2","duration_ms":7,"metadata":{"tool":"grep","matched":2},"content":{"result":{"matched":2,"path":"app/runner.py"}}}
  {"schema_version":"2.0","event_id":"event-5","run_id":"run-observer-example","producer_id":"example-harness","sequence":4,"type":"finding.candidate","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.040Z","candidate_id":"candidate-1","metadata":{"rule":"py.subprocess-shell-true","path":"tests/fixtures/shell.py","line":8}}
  {"schema_version":"2.0","event_id":"event-6","run_id":"run-observer-example","producer_id":"example-harness","sequence":5,"type":"finding.filtered","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.050Z","candidate_id":"candidate-1","metadata":{"reason":"path is test fixture material"}}
  {"schema_version":"2.0","event_id":"event-7","run_id":"run-observer-example","producer_id":"example-harness","sequence":6,"type":"finding.candidate","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.060Z","candidate_id":"candidate-2","metadata":{"rule":"py.subprocess-shell-true","path":"app/runner.py","line":42}}
  {"schema_version":"2.0","event_id":"event-8","run_id":"run-observer-example","producer_id":"example-harness","sequence":7,"type":"finding.validation","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.070Z","candidate_id":"candidate-2","metadata":{"verdict":"kept","checked":"reachability"}}
  {"schema_version":"2.0","event_id":"event-9","run_id":"run-observer-example","producer_id":"example-harness","sequence":8,"type":"finding.submitted","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.080Z","candidate_id":"candidate-2","claim_id":"claim-1","metadata":{"rule":"py.subprocess-shell-true","path":"app/runner.py","line":42}}
```

## Real output: TypeScript

```
ScanEval observer example harness (TypeScript)
Integration fixture only: fake model and fake tool functions, no model call, no
network call, no real scanner, no truth labels.

step 1  run with tracing off
  events recorded: 0
  findings reported: 1

step 2  the same run with tracing turned on by the caller (mode=content)
  event 0  model.request      redacted  call_id=call-1
  event 1  model.response     complete  call_id=call-1 parent_event_id=event-1
  event 2  tool.start         complete  call_id=call-2
  event 3  tool.end           complete  call_id=call-2 parent_event_id=event-3 duration_ms=7
  event 4  finding.candidate  complete  candidate_id=candidate-1
  event 5  finding.filtered   complete  candidate_id=candidate-1
  event 6  finding.candidate  complete  candidate_id=candidate-2
  event 7  finding.validation complete  candidate_id=candidate-2
  event 8  finding.submitted  complete  candidate_id=candidate-2 claim_id=claim-1
  events recorded: 9
  findings reported: 1
  report identical to the untraced run: true

step 3  explicit flush
  capture state: dropped_events=0 capture_gap=false last_sink_error=none

trace jsonl (9 lines)
  {"schema_version":"2.0","event_id":"event-1","run_id":"run-observer-example","producer_id":"example-harness","sequence":0,"type":"model.request","category":"model","capture_status":"redacted","timestamp":"2026-09-20T12:00:00.000Z","metadata":{"model":"fake-model-v0","input_tokens":31},"call_id":"call-1","content":{"api_key":"[REDACTED]","prompt":"review app/runner.py"}}
  {"schema_version":"2.0","event_id":"event-2","run_id":"run-observer-example","producer_id":"example-harness","sequence":1,"type":"model.response","category":"model","capture_status":"complete","timestamp":"2026-09-20T12:00:00.010Z","metadata":{"model":"fake-model-v0","output_tokens":18},"parent_event_id":"event-1","call_id":"call-1","content":{"text":"two candidates in app/runner.py","finish_reason":"stop"}}
  {"schema_version":"2.0","event_id":"event-3","run_id":"run-observer-example","producer_id":"example-harness","sequence":2,"type":"tool.start","category":"tool","capture_status":"complete","timestamp":"2026-09-20T12:00:00.020Z","metadata":{"tool":"grep","path":"app/runner.py"},"call_id":"call-2","content":{"arguments":{"pattern":"shell=True"}}}
  {"schema_version":"2.0","event_id":"event-4","run_id":"run-observer-example","producer_id":"example-harness","sequence":3,"type":"tool.end","category":"tool","capture_status":"complete","timestamp":"2026-09-20T12:00:00.030Z","metadata":{"tool":"grep","matched":2},"parent_event_id":"event-3","call_id":"call-2","duration_ms":7,"content":{"result":{"matched":2,"path":"app/runner.py"}}}
  {"schema_version":"2.0","event_id":"event-5","run_id":"run-observer-example","producer_id":"example-harness","sequence":4,"type":"finding.candidate","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.040Z","metadata":{"rule":"py.subprocess-shell-true","path":"tests/fixtures/shell.py","line":8},"candidate_id":"candidate-1"}
  {"schema_version":"2.0","event_id":"event-6","run_id":"run-observer-example","producer_id":"example-harness","sequence":5,"type":"finding.filtered","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.050Z","metadata":{"reason":"path is test fixture material"},"candidate_id":"candidate-1"}
  {"schema_version":"2.0","event_id":"event-7","run_id":"run-observer-example","producer_id":"example-harness","sequence":6,"type":"finding.candidate","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.060Z","metadata":{"rule":"py.subprocess-shell-true","path":"app/runner.py","line":42},"candidate_id":"candidate-2"}
  {"schema_version":"2.0","event_id":"event-8","run_id":"run-observer-example","producer_id":"example-harness","sequence":7,"type":"finding.validation","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.070Z","metadata":{"verdict":"kept","checked":"reachability"},"candidate_id":"candidate-2"}
  {"schema_version":"2.0","event_id":"event-9","run_id":"run-observer-example","producer_id":"example-harness","sequence":8,"type":"finding.submitted","category":"finding","capture_status":"complete","timestamp":"2026-09-20T12:00:00.080Z","metadata":{"rule":"py.subprocess-shell-true","path":"app/runner.py","line":42},"candidate_id":"candidate-2","claim_id":"claim-1"}
```

The two runs differ only in the first line and in where each emitter places `metadata` inside a
JSONL line. Event IDs, sequence numbers, timestamps, capture statuses, links, and payloads are
the same.
