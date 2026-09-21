"""Cross-language parity: the Python emitter and the TypeScript SDK must record the same events.

The wire contract is one document, ``schema/v2/trace-event.schema.json``, so a trace has to mean
the same thing whichever language wrote it. These tests run both emitters over one matrix of
inputs with the same injected clock, the same injected monotonic source, the same injected ID
factory, the same sink, and the same redactor, and compare five things for every case:

* the JSONL each emitter wrote, byte for byte, key order included;
* whether each input was recorded at all, so a divergent rejection is visible on the input that
  caused it rather than only in the wreckage after it;
* the sequence number and event ID of every recorded event, so a rejection that consumes a
  sequence number in one language and not the other desynchronizes the streams and fails loudly;
* the capture state fields, ``dropped_events``, ``capture_gap`` and ``last_sink_error``, with the
  two deliberate, named exclusions described below;
* for the operation-boundary helpers, the value or error that passed through, the duration each
  builder was handed, and the completion event each one wrote.

The matrix is the point of this file. A rejected event consumes no sequence number, no event ID,
and no clock read in either language, which is only safe while both languages refuse exactly the
same inputs, so the matrix carries every rejection shape the contract names as well as the
payload shapes that could plausibly serialize differently: every event type, all three recording
modes, an explicitly unavailable capture status, integral, non-integral, negative, non-finite,
null and beyond-safe-integer durations, a payload nested one container past the shared depth
limit and one exactly at it, an unknown field name, a missing metadata, a metadata that is a list
and one that is a string, an empty and a non-string link ID, a cyclic payload, a non-finite
number inside a payload, credential-like and Unicode payload keys, a redactor that returns a
structurally equal copy of a container, a redactor that returns an equal copy of a scalar, a
redactor that throws, a sink that throws an ordinary error, a sink that throws a value that is
not an error, an ID factory that throws, a clock that throws, a clock that steps backwards, and
an observer with no sink at all.

The operation-boundary helpers are compared too, not only ``emit``: Python's ``observe_async``
and TypeScript's ``observeAsync`` are driven over the same success, failure and unmeasurable
duration scenarios, with a monotonic source scripted read for read, and their completion events
are compared byte for byte. One operation scenario deliberately injects no monotonic source at
all, only a clock, because that is the case in which the two emitters once disagreed: TypeScript
derived elapsed time from an injected ``Clock`` and Python never did. Both now measure with a
real monotonic source, so that scenario's duration is the one value in the whole matrix that is
a property of how fast the test ran, and it is compared as a shape rather than as a value, by
name, in ``REAL_TIME_OPERATIONS``.

What these tests do not prove: that the two emitters share code, that either is correct about a
harness that never emits, or that a trace says anything about a scanner's findings. Three known
representational limits are excluded from the byte comparison rather than hidden: an integral
float in a payload writes as ``1.0`` from Python and ``1`` from JavaScript, a payload key that
looks like an array index sorts ahead of its siblings in JavaScript only, and a timestamp cannot
carry sub-millisecond precision in either language because the TypeScript ``Clock`` hands back a
``Date``. Those three are representational limits of the two languages, not defects, and they
are excluded from the byte comparison by name rather than by loosening it. The fourth exclusion
is not a limit but a measurement: the one operation scenario that injects no monotonic source
has each language time the same trivial operation with its own real one, so that duration is
compared as a shape and blanked before the bytes are. Every behavioral divergence found by
review has been closed, so both divergence sets below are empty. All of this is recorded in
``docs/OBSERVER_SDK.md``.

Nothing here calls a model, reaches the network, or sleeps, and no timestamp comes from
anywhere but an injected clock. The one real reading in the file is the monotonic source of the
clock-only operation scenario, which is there to prove that neither emitter reaches for a wall
clock when no monotonic source is injected. The TypeScript
side is a throwaway driver written into a temporary directory and run under node against the
SDK's build output, which is gitignored and therefore local. The tests skip with a reason when
node or that build is absent rather than pretend parity was checked. Each plan is run through
both emitters once per session and shared by the tests that read it, so adding a case costs one
more scenario rather than one more node process.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

import pytest

from scaneval.observer import (
    CAPTURE_STATUSES,
    EVENT_TYPES,
    MAX_PAYLOAD_DEPTH,
    RECORDING_MODES,
    CaptureState,
    Observer,
    create_jsonl_sink,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "schema/v2/fixtures/trace-event-v2.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text())
SDK_BUILD = ROOT / "sdk/typescript/dist/index.js"
NODE = shutil.which("node")

EPOCH = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
EPOCH_MS = int(EPOCH.timestamp() * 1000)
STEP_MS = 10
GAP_MESSAGE = "observer instrumentation failure"
MAX_SAFE_INTEGER = 2**53 - 1

needs_node = pytest.mark.skipif(
    NODE is None or not SDK_BUILD.exists(),
    reason=(
        "cross-language parity needs node and a built TypeScript SDK; sdk/typescript/dist is "
        "gitignored, so run npm --prefix sdk/typescript run build and install node to check it"
    ),
)


class SinkFailureValue(BaseException):
    """The nearest Python analogue to a JavaScript ``throw "sink unavailable"``.

    JavaScript can throw any value; Python can only raise a ``BaseException``. A bare
    ``BaseException`` that is not an ``Exception`` is the closest thing Python has to a thrown
    non-error, and it is the case worth testing: an ``except Exception`` guard would miss it, so
    containing it is evidence that both emitters guard the widest thing their language can throw.
    """


def generator_function_sink(event):
    """A sink that is a generator function: calling it returns an iterator and writes nothing."""
    yield event


# The driver is written into a temporary directory per session rather than committed: it is a
# test harness for the SDK, not part of it, and nothing outside these tests should import it. It
# mirrors the Python runner below call for call, because a driver that wired the two emitters
# differently would compare the harness rather than the emitters.
DRIVER = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [, , planPath, sdkPath] = process.argv;
const { Observer, createJsonlSink, MAX_PAYLOAD_DEPTH } = await import(
  pathToFileURL(sdkPath).href
);
const plan = JSON.parse(readFileSync(planPath, "utf8"));

/* JSON cannot carry a cycle or a non-finite number, so the plan spells them as markers and
   both languages build the real value here. */
function materialize(value) {
  if (Array.isArray(value)) return value.map(materialize);
  if (value !== null && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 1 && keys[0] === "$special") {
      if (value.$special === "cycle") {
        const loop = {};
        loop.self = loop;
        return loop;
      }
      if (value.$special === "nan") return NaN;
      if (value.$special === "inf") return Infinity;
      if (value.$special === "-inf") return -Infinity;
      throw new Error("unknown special: " + value.$special);
    }
    const out = {};
    for (const key of keys) {
      // defineProperty, not assignment: `out.__proto__ = x` would set the prototype instead of
      // handing the emitter the own key the Python side hands it, and the two would then be
      // compared on different inputs.
      Object.defineProperty(out, key, {
        value: materialize(value[key]),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return out;
  }
  return value;
}

const redactors = {
  default: undefined,
  // Hands back a structurally equal copy of every container and leaves scalars alone. Under
  // strict inequality a rebuilt container is a replacement, so this must mark the event redacted
  // in both languages.
  equal_copy: (key, value) =>
    Array.isArray(value)
      ? value.slice()
      : (value !== null && typeof value === "object" ? { ...value } : value),
  // The mirror image: rebuilds every scalar to an equal value and leaves containers alone.
  // Under strict inequality an equal scalar is not a replacement, so this must mark nothing.
  equal_copy_scalar: (key, value) => {
    if (typeof value === "string") return value.split("").join("");
    if (typeof value === "number") return Number(String(value));
    return value;
  },
  throws: () => {
    throw new Error("redactor unavailable");
  },
};

function scriptedMonotonic(values) {
  let reads = 0;
  return {
    now: () => {
      const index = reads++;
      if (index >= values.length) throw new Error("monotonic source exhausted");
      const value = values[index];
      if (value === "throw") throw new Error("monotonic unavailable");
      if (value === "nan") return NaN;
      if (value === "inf") return Infinity;
      return value;
    },
  };
}

const results = [];
for (const scenario of plan.scenarios) {
  const lines = [];
  const jsonl = createJsonlSink((line) => {
    lines.push(line);
  });
  const sinkThrows = new Set(scenario.sink_throws_on ?? []);
  const sinkThrowKind = scenario.sink_throw_kind ?? "error";
  let writes = 0;
  const sink = {
    write(event) {
      const index = writes++;
      if (sinkThrows.has(index)) {
        // A JavaScript throw carries any value at all; the Python side raises the closest thing
        // it has, a BaseException that is not an Exception.
        throw sinkThrowKind === "non_error"
          ? "sink unavailable"
          : new Error("sink unavailable");
      }
      return jsonl.write(event);
    },
  };
  const clockThrows = new Set(scenario.clock_throws_on ?? []);
  const clockOffsets = scenario.clock_offsets_ms ?? null;
  let reads = 0;
  const supplied = (scenario.id_values ?? []).slice();
  const idThrows = new Set(scenario.id_throws_on ?? []);
  let issued = 0;
  let idCalls = 0;
  const observer = new Observer({
    mode: scenario.mode,
    ...(scenario.no_sink ? {} : { sink }),
    runId: scenario.run_id ?? undefined,
    producerId: scenario.producer_id ?? undefined,
    idFactory: {
      next: (prefix) => {
        const index = idCalls++;
        if (idThrows.has(index)) throw new Error("id factory unavailable");
        return supplied.length > 0 ? supplied.shift() : `${prefix}-${++issued}`;
      },
    },
    clock: {
      now: () => {
        const index = reads++;
        if (clockThrows.has(index)) throw new Error("clock unavailable");
        const offset = clockOffsets !== null && index < clockOffsets.length
          ? clockOffsets[index]
          : plan.step_ms * index;
        return new Date(plan.epoch_ms + offset);
      },
    },
    ...(scenario.monotonic_values === undefined
      ? {}
      : { monotonic: scriptedMonotonic(scenario.monotonic_values) }),
    redactor: redactors[scenario.redactor ?? "default"],
  });
  const recorded = [];
  const eventIds = [];
  const sequences = [];
  for (const input of scenario.events ?? []) {
    const emitted = await observer.emit(materialize(input));
    recorded.push(emitted !== undefined);
    eventIds.push(emitted === undefined ? null : emitted.event_id);
    sequences.push(emitted === undefined ? null : emitted.sequence);
  }
  const operations = [];
  for (const step of scenario.operations ?? []) {
    const sentinel = { operation: step.name };
    const original = new Error("operation failed: " + step.name);
    let durationSeen = null;
    let sawOriginal = null;
    const complete = (template, durationMs) => {
      durationSeen = durationMs === undefined ? null : durationMs;
      const fields = materialize(template);
      if (durationMs !== undefined) fields.duration_ms = durationMs;
      if (step.forced_duration_ms !== undefined) {
        fields.duration_ms = step.forced_duration_ms;
      }
      return fields;
    };
    let outcome;
    let identity;
    try {
      const value = await observer.observeAsync(
        materialize(step.start),
        (durationMs) => complete(step.success, durationMs),
        (error, durationMs) => {
          sawOriginal = error === original;
          return complete(step.failure, durationMs);
        },
        async () => {
          if (step.outcome === "failure") throw original;
          return sentinel;
        },
      );
      outcome = "value";
      identity = value === sentinel;
    } catch (error) {
      outcome = "error";
      identity = error === original;
    }
    operations.push({
      name: step.name,
      outcome,
      passthrough_identity: identity,
      duration_seen: durationSeen,
      builder_saw_original_error: sawOriginal,
    });
  }
  await observer.flush();
  results.push({
    name: scenario.name,
    run_id: observer.runId,
    producer_id: observer.producerId,
    lines,
    recorded,
    event_ids: eventIds,
    sequences,
    operations,
    state: observer.getState(),
    max_payload_depth: MAX_PAYLOAD_DEPTH,
  });
}
process.stdout.write(JSON.stringify(results));
"""


# A second driver that constructs and nothing else. Wiring mistakes are refused at construction
# by one emitter and not the other, so this reports only whether the constructor raised.
WIRING_DRIVER = """
import { pathToFileURL } from "node:url";

const [, , sdkPath] = process.argv;
const { Observer } = await import(pathToFileURL(sdkPath).href);

const attempts = {
  unknown_mode: () => new Observer({ mode: "not-a-mode", sink: { write: () => {} } }),
  sink_without_write: () => new Observer({ mode: "content", sink: {} }),
  generator_function_sink: () =>
    new Observer({ mode: "content", sink: { *write(event) { yield event; } } }),
};

const results = {};
for (const [name, build] of Object.entries(attempts)) {
  try {
    build();
    results[name] = "constructed";
  } catch {
    results[name] = "refused";
  }
}
process.stdout.write(JSON.stringify(results));
"""


def materialize(value):
    """Build the values JSON cannot carry: a cycle and the non-finite numbers.

    The node driver runs the identical substitution, so both emitters see the same object graph
    rather than two hand-written approximations of it.
    """
    if isinstance(value, list):
        return [materialize(item) for item in value]
    if isinstance(value, dict):
        if len(value) == 1 and "$special" in value:
            name = value["$special"]
            if name == "cycle":
                loop: dict = {}
                loop["self"] = loop
                return loop
            if name == "nan":
                return float("nan")
            if name == "inf":
                return float("inf")
            if name == "-inf":
                return float("-inf")
            raise AssertionError(f"unknown special: {name}")
        return {key: materialize(item) for key, item in value.items()}
    return value


def equal_copy_redactor(key, value, path):
    """Return a structurally equal copy of every container. Replacement, not value change."""
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, list):
        return list(value)
    return value


def equal_copy_scalar_redactor(key, value, path):
    """Rebuild every scalar into an equal but separately allocated value, containers untouched.

    This is the case Python cannot answer with ``is``. CPython gives ``"".join(list("grep"))``
    and ``"grep"`` different identities, and gives two equal integers past the small-integer
    cache different identities as well, while JavaScript has no separate identity for a
    primitive at all. Under the shared rule, strict inequality, none of these count as a
    replacement, so both emitters must leave the capture status alone.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return "".join(list(value))
    if isinstance(value, int):
        return int(str(value))
    if isinstance(value, float):
        return float(str(value))
    return value


def throwing_redactor(key, value, path):
    raise RuntimeError("redactor unavailable")


# ``default`` is None so each emitter uses its own built-in redactor: that is the thing under
# comparison, and substituting one shared implementation would hide a divergence between them.
REDACTORS = {
    "default": None,
    "equal_copy": equal_copy_redactor,
    "equal_copy_scalar": equal_copy_scalar_redactor,
    "throws": throwing_redactor,
}


def id_factory(supplied: list[str] | None, throws_on=()):
    """Pop caller-supplied IDs first, then count. The same rule the node driver applies.

    ``throws_on`` names call indices, counted over every call including the failing ones, so a
    failing read costs the same turn in both languages and the IDs issued after it line up.
    """
    remaining = list(supplied or [])
    throwing = set(throws_on)
    issued = 0
    calls = 0

    def next_id(prefix: str) -> str:
        nonlocal issued, calls
        index = calls
        calls += 1
        if index in throwing:
            raise RuntimeError("id factory unavailable")
        if remaining:
            return remaining.pop(0)
        issued += 1
        return f"{prefix}-{issued}"

    return next_id


def fixed_clock(epoch_ms: int, step_ms: int, throws_on=(), offsets=None):
    """A clock that advances a fixed step per read, matching the node driver's arithmetic.

    A read listed in ``throws_on`` raises after taking its turn, so a throwing read costs the
    same tick in both languages and a later timestamp still says which read produced it.
    ``offsets`` replaces the fixed step for the reads it covers, which is how a clock that steps
    backwards is expressed without any real clock being involved.
    """
    throwing = set(throws_on)
    scripted = list(offsets or ())
    reads = 0

    def now() -> datetime:
        nonlocal reads
        index = reads
        reads += 1
        if index in throwing:
            raise RuntimeError("clock unavailable")
        offset = scripted[index] if index < len(scripted) else step_ms * index
        return datetime.fromtimestamp(epoch_ms / 1000, timezone.utc) + timedelta(
            milliseconds=offset
        )

    return now


def scripted_monotonic(values):
    """Read the elapsed-time source from a script, in seconds, exactly as the node driver does.

    A ``"throw"`` entry raises, ``"nan"`` and ``"inf"`` return the non-finite readings the
    emitter has to refuse. Nothing here reads a real clock, so a duration is a property of the
    plan rather than of how fast the test ran.
    """
    scripted = list(values)
    reads = 0

    def now() -> float:
        nonlocal reads
        index = reads
        reads += 1
        if index >= len(scripted):
            raise RuntimeError("monotonic source exhausted")
        value = scripted[index]
        if value == "throw":
            raise RuntimeError("monotonic unavailable")
        if value == "nan":
            return float("nan")
        if value == "inf":
            return float("inf")
        return float(value)

    return now


def counting_sink(lines: list[str], throws_on=(), kind="error"):
    """The JSONL sink, wrapped so named write attempts fail. Serialization stays the SDK's."""
    throwing = set(throws_on)
    jsonl = create_jsonl_sink(lines.append)
    writes = 0

    def write(event):
        nonlocal writes
        index = writes
        writes += 1
        if index in throwing:
            if kind == "non_error":
                raise SinkFailureValue("sink unavailable")
            raise RuntimeError("sink unavailable")
        return jsonl.write(event)

    return write


def run_python_operations(observer: Observer, steps: list[dict]) -> list[dict]:
    """Drive ``observe_async`` over the plan's operations and report what the driver reports.

    One event loop for the whole scenario, so the emitter sees the same loop the node driver's
    single async context gives it, and ``aflush`` settles the writes before the loop goes away.
    """
    results: list[dict] = []

    async def drive() -> None:
        for step in steps:
            sentinel = {"operation": step["name"]}
            original = RuntimeError("operation failed: " + step["name"])
            seen: dict[str, Any] = {"duration": None, "original": None}

            def complete(template, elapsed, step=step, seen=seen):
                seen["duration"] = elapsed
                fields = materialize(template)
                if elapsed is not None:
                    fields["duration_ms"] = elapsed
                if step.get("forced_duration_ms") is not None:
                    fields["duration_ms"] = step["forced_duration_ms"]
                return fields

            def on_success(elapsed, step=step):
                return complete(step["success"], elapsed)

            def on_failure(error, elapsed, step=step, seen=seen, original=original):
                seen["original"] = error is original
                return complete(step["failure"], elapsed)

            async def operation(step=step, sentinel=sentinel, original=original):
                if step["outcome"] == "failure":
                    raise original
                return sentinel

            try:
                value = await observer.observe_async(
                    materialize(step["start"]), on_success, on_failure, operation
                )
                outcome, identity = "value", value is sentinel
            except BaseException as error:  # the helper re-raises the operation's own error
                outcome, identity = "error", error is original
            results.append(
                {
                    "name": step["name"],
                    "outcome": outcome,
                    "passthrough_identity": identity,
                    "duration_seen": seen["duration"],
                    "builder_saw_original_error": seen["original"],
                }
            )
        await observer.aflush()

    asyncio.run(drive())
    return results


def python_results(plan: dict) -> list[dict]:
    """Run every scenario through the Python emitter and report what the driver reports."""
    results: list[dict] = []
    for scenario in plan["scenarios"]:
        lines: list[str] = []
        sink = (
            None
            if scenario.get("no_sink")
            else counting_sink(
                lines,
                scenario.get("sink_throws_on", ()),
                scenario.get("sink_throw_kind", "error"),
            )
        )
        monotonic = (
            scripted_monotonic(scenario["monotonic_values"])
            if "monotonic_values" in scenario
            else None
        )
        observer = Observer(
            mode=scenario["mode"],
            sink=sink,
            run_id=scenario.get("run_id"),
            producer_id=scenario.get("producer_id"),
            id_factory=id_factory(
                scenario.get("id_values"), scenario.get("id_throws_on", ())
            ),
            clock=fixed_clock(
                plan["epoch_ms"],
                plan["step_ms"],
                scenario.get("clock_throws_on", ()),
                scenario.get("clock_offsets_ms"),
            ),
            monotonic=monotonic,
            redactor=REDACTORS[scenario.get("redactor", "default")],
        )
        recorded: list[bool] = []
        event_ids: list[str | None] = []
        sequences: list[int | None] = []
        for fields in scenario.get("events", []):
            emitted = observer.emit(**materialize(fields))
            recorded.append(emitted is not None)
            event_ids.append(None if emitted is None else emitted["event_id"])
            sequences.append(None if emitted is None else emitted["sequence"])
        operations = run_python_operations(observer, scenario.get("operations", []))
        observer.flush()
        state = observer.get_state()
        results.append(
            {
                "name": scenario["name"],
                "run_id": observer.run_id,
                "producer_id": observer.producer_id,
                "lines": lines,
                "recorded": recorded,
                "event_ids": event_ids,
                "sequences": sequences,
                "operations": operations,
                "state": {
                    "dropped_events": state.dropped_events,
                    "capture_gap": state.capture_gap,
                    "last_sink_error": state.last_sink_error,
                },
                "max_payload_depth": MAX_PAYLOAD_DEPTH,
            }
        )
    return results


def node_results(directory: Path, plan: dict) -> list[dict]:
    """Run the same scenarios through the built TypeScript SDK under node."""
    driver = directory / "parity_driver.mjs"
    driver.write_text(DRIVER)
    plan_path = directory / "plan.json"
    plan_path.write_text(json.dumps(plan, ensure_ascii=False))
    completed = subprocess.run(
        [NODE, str(driver), str(plan_path), str(SDK_BUILD)],
        capture_output=True,
        cwd=str(ROOT),
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    return json.loads(completed.stdout.decode("utf-8"))


def both(directory: Path, plan: dict):
    """Run one plan through both emitters and pair the scenarios up by name."""
    from_python = python_results(plan)
    from_node = node_results(directory, plan)
    assert [case["name"] for case in from_python] == [case["name"] for case in from_node]
    return list(zip(from_python, from_node))


def paired(directory: Path, plan: dict) -> dict[str, tuple[dict, dict]]:
    return {
        python_case["name"]: (python_case, node_case)
        for python_case, node_case in both(directory, plan)
    }


def python_wiring_results() -> dict[str, str]:
    """Try the same three wiring mistakes against the Python constructor."""
    attempts = {
        "unknown_mode": lambda: Observer(mode="not-a-mode", sink=lambda event: None),
        "sink_without_write": lambda: Observer(mode="content", sink=object()),
        "generator_function_sink": lambda: Observer(mode="content", sink=generator_function_sink),
    }
    results: dict[str, str] = {}
    for name, build in attempts.items():
        try:
            build()
            results[name] = "constructed"
        except Exception:
            results[name] = "refused"
    return results


def node_wiring_results(directory: Path) -> dict[str, str]:
    driver = directory / "wiring_driver.mjs"
    driver.write_text(WIRING_DRIVER)
    completed = subprocess.run(
        [NODE, str(driver), str(SDK_BUILD)],
        capture_output=True,
        cwd=str(ROOT),
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    return json.loads(completed.stdout.decode("utf-8"))


def parsed(lines: list[str]) -> list[dict]:
    return [json.loads(line) for line in lines]


def measurement_free(case: dict) -> dict:
    """One scenario's record with every real measured duration replaced by a marker.

    Only a scenario named in :data:`REAL_TIME_OPERATIONS` needs this, and only for the one field
    nothing scripts: two languages measuring the same trivial operation with their own monotonic
    sources write their own numbers of milliseconds. Everything else, the JSONL bytes included,
    still compares exactly, so blanking the measurement keeps the rest of the comparison instead
    of dropping the scenario out of it. The marker is a string, so a duration that went missing
    in one language is still a failure rather than a match.
    """
    lines = []
    for emitted in parsed(case["lines"]):
        if "duration_ms" in emitted:
            emitted["duration_ms"] = "<measured>"
        lines.append(json.dumps(emitted, ensure_ascii=False, separators=(",", ":")))
    operations = [
        {
            **step,
            "duration_seen": None if step["duration_seen"] is None else "<measured>",
        }
        for step in case["operations"]
    ]
    return {**case, "lines": lines, "operations": operations}


def iso_timestamp(read_index: int) -> str:
    """The timestamp the injected clock produces on its nth read, spelled as the wire spells it."""
    moment = EPOCH + timedelta(milliseconds=STEP_MS * read_index)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


def event(event_type: str, **extra) -> dict:
    fields = {"type": event_type, "capture_status": "complete", "metadata": {"stage": event_type}}
    fields.update(extra)
    return fields


def nested_object(containers: int) -> dict:
    """A payload of exactly ``containers`` nested objects, the payload object itself included."""
    root: dict = {}
    inner = root
    for _ in range(containers - 1):
        child: dict = {}
        inner["child"] = child
        inner = child
    inner["leaf"] = "bottom"
    return root


def nested_lists(containers: int) -> dict:
    """A payload object holding a chain of ``containers - 1`` nested lists, so it counts alike."""
    value: Any = "bottom"
    for _ in range(containers - 1):
        value = [value]
    return {"chain": value}


CYCLE = {"$special": "cycle"}
NAN = {"$special": "nan"}
INFINITY = {"$special": "inf"}
NEGATIVE_INFINITY = {"$special": "-inf"}

# Text that has to escape and encode identically in both languages.
TRICKY_TEXT = 'quote " backslash \\ tab \t newline \n accented é kanji 漢'

# One event per wire type, carrying the link fields that type actually uses, plus payload shapes
# that could plausibly serialize differently: credential keys, nested arrays, a non-integral
# float, a negative number, a nested null, booleans, escapes, and non-ASCII text. Every capture
# status the contract allows is requested by one of them, ``unavailable`` included.
ACCEPTED_EVENTS = [
    event(
        "model.request",
        call_id="call-1",
        metadata={"model": "fake-model-v0", "input_tokens": 31, "api_key": "fixture-credential"},
        content={"prompt": "review app/runner.py", "authorization": "fixture-credential"},
    ),
    event(
        "model.response",
        call_id="call-1",
        parent_event_id="event-1",
        attempt_id="attempt-1",
        duration_ms=120,
        metadata={"model": "fake-model-v0", "output_tokens": 18, "cost_ratio": 1.5},
        content={"text": TRICKY_TEXT},
    ),
    event(
        "tool.start",
        call_id="call-2",
        metadata={"tool": "grep", "argv": ["grep", "-n", "shell=True"]},
        content={"arguments": {"pattern": "shell=True", "case_sensitive": True}},
    ),
    event(
        "tool.end",
        call_id="call-2",
        parent_event_id="event-3",
        duration_ms=12,
        capture_status="partial",
        metadata={"tool": "grep", "matched": 2, "exit_code": 0},
        content={"result": {"matched": 2, "truncated": False, "next_cursor": None}},
    ),
    event(
        "context.selection",
        call_id="call-1",
        metadata={"included_count": 2, "budget_remaining": -3},
        content={"paths": ["app/runner.py", "app/util.py"], "nested": [[1, 2], [{"deep": True}]]},
    ),
    event(
        "finding.candidate",
        candidate_id="candidate-1",
        metadata={"rule": "py.subprocess-shell-true", "path": "tests/fixtures/shell.py", "line": 8},
    ),
    event(
        "finding.validation",
        candidate_id="candidate-1",
        capture_status="redacted",
        metadata={"verdict": "dropped", "checked": "reachability"},
        content={"notes": "fixture text, no judgment about any scanner"},
    ),
    event(
        "finding.filtered",
        candidate_id="candidate-1",
        duration_ms=0,
        metadata={"reason": "path is test fixture material"},
    ),
    event(
        "finding.submitted",
        candidate_id="candidate-2",
        claim_id="claim-1",
        metadata={"rule": "py.subprocess-shell-true", "path": "app/runner.py", "line": 42},
    ),
    # An explicitly unavailable capture status must survive every downgrade rule in both.
    event(
        "observer.error",
        capture_status="unavailable",
        metadata={"reason": "fixture gap", "detail": None},
    ),
    # Every link field at once, so key order is compared over the whole declared schema.
    event(
        "tool.end",
        parent_event_id="event-1",
        call_id="call-9",
        attempt_id="attempt-9",
        candidate_id="candidate-9",
        claim_id="claim-9",
        duration_ms=5,
        metadata={"tool": "grep"},
        content={"result": {}},
    ),
    # An integral float duration is stored as an integer in both languages.
    event("tool.end", call_id="call-3", duration_ms=120.0, metadata={"tool": "grep"}),
    # The largest duration the wire can carry exactly, in both its integer and float spellings.
    # One past this is refused; see REJECTED_EVENTS.
    event("tool.end", call_id="call-4", duration_ms=MAX_SAFE_INTEGER, metadata={"tool": "grep"}),
    event(
        "tool.end",
        call_id="call-5",
        duration_ms=float(MAX_SAFE_INTEGER),
        metadata={"tool": "grep"},
    ),
    # Payloads sitting exactly on the shared nesting limit. One container deeper is refused.
    event("tool.start", metadata=nested_object(MAX_PAYLOAD_DEPTH)),
    event("tool.start", metadata=nested_lists(MAX_PAYLOAD_DEPTH)),
    event("tool.start", metadata={"tool": "grep"}, content=nested_object(MAX_PAYLOAD_DEPTH)),
    # Edge shapes that carry no optional field at all.
    event("tool.start", metadata={}),
    event("model.request", metadata={"empty_list": [], "empty_object": {}}, content={}),
]

# Every input the shared rejection rule refuses. Each is refused by both emitters, and refusing
# one must cost no sequence number, no event ID, and no clock read in either.
REJECTED_EVENTS = {
    "unknown_field_name": event("tool.start", unknown_field=1),
    "misspelled_field_name": event("tool.start", metdata={"tool": "grep"}),
    "missing_metadata": {"type": "tool.start", "capture_status": "complete"},
    "metadata_is_null": event("tool.start", metadata=None),
    "metadata_is_a_list": event("tool.start", metadata=[{"tool": "grep"}]),
    "metadata_is_a_string": event("tool.start", metadata="tool=grep"),
    "content_is_a_list": event("tool.start", content=["grep"]),
    "content_is_null": event("tool.start", content=None),
    "empty_call_id": event("tool.start", call_id=""),
    "non_string_call_id": event("tool.start", call_id=7),
    "empty_claim_id": event("finding.submitted", claim_id=""),
    "null_duration": event("tool.end", duration_ms=None),
    "non_integral_duration": event("tool.end", duration_ms=12.5),
    "negative_duration": event("tool.end", duration_ms=-1),
    "non_finite_duration": event("tool.end", duration_ms=INFINITY),
    "negative_infinite_duration": event("tool.end", duration_ms=NEGATIVE_INFINITY),
    "nan_duration": event("tool.end", duration_ms=NAN),
    "boolean_duration": event("tool.end", duration_ms=True),
    "text_duration": event("tool.end", duration_ms="12"),
    # One past Number.MAX_SAFE_INTEGER: Python could hold it exactly and JavaScript could not,
    # so both refuse it rather than write bytes that mean different numbers.
    "duration_one_past_the_safe_integer_bound": event("tool.end", duration_ms=2**53),
    "duration_far_past_the_safe_integer_bound": event("tool.end", duration_ms=2**53 + 2),
    # 1e21 is where JavaScript's own number formatting switches to exponent notation, so it is
    # the shape most likely to serialize differently if either emitter ever accepted it.
    "duration_above_1e21_as_a_float": event("tool.end", duration_ms=1e21),
    "duration_above_1e21_as_an_integer": event("tool.end", duration_ms=10**21),
    "unknown_type": event("model.reqest"),
    "null_type": event(None),
    "prototype_named_type": event("toString"),
    "constructor_named_type": event("constructor"),
    "category_contradicts_type": event("model.request", category="tool"),
    "unknown_capture_status": event("tool.start", capture_status="pretend_complete"),
    "null_capture_status": event("tool.start", capture_status=None),
    "cyclic_metadata": event("tool.start", metadata={"loop": CYCLE}),
    "non_finite_number_in_metadata": event("tool.start", metadata={"ratio": NAN}),
    "negative_infinity_in_metadata": event("tool.start", metadata={"ratio": NEGATIVE_INFINITY}),
    # One container past the shared limit, in both container shapes. Refused as a capture gap,
    # never truncated, and refused at the same depth in both languages.
    "metadata_nested_past_the_depth_limit": event(
        "tool.start", metadata=nested_object(MAX_PAYLOAD_DEPTH + 1)
    ),
    "metadata_lists_nested_past_the_depth_limit": event(
        "tool.start", metadata=nested_lists(MAX_PAYLOAD_DEPTH + 1)
    ),
}

# Refused in content mode only, because metadata mode never copies content and therefore never
# sees the payload the copy would refuse. Both languages must draw that line in the same place.
CONTENT_ONLY_REJECTIONS = {
    "cyclic_content": event("tool.start", content={"loop": CYCLE}),
    "non_finite_number_in_content": event("tool.start", content={"score": INFINITY}),
    "content_nested_past_the_depth_limit": event(
        "tool.start", content=nested_object(MAX_PAYLOAD_DEPTH + 1)
    ),
}

# Key names the default redactor must hide, and names it must leave alone. The Unicode keys are
# the point: JavaScript's case-insensitive regex folds ASCII only, so Python has to spell the
# same rule with re.ASCII or it would hide a key JavaScript keeps.
REDACTION_EVENTS = [
    event(
        "model.request",
        metadata={
            "api_key": "hide me",
            "Api-Key": "hide me",
            "APIKEY": "hide me",
            "authorization": "hide me",
            "Cookies": "hide me",
            "password": "hide me",
            "secrets": "hide me",
            "TOKEN": "hide me",
            "private-key": "hide me",
            "credential": "hide me",
            "input_tokens": 31,
            "output_tokens": 18,
            "token_budget": 4096,
            "keep": "kept",
        },
    ),
    event(
        "model.request",
        metadata={
            # U+212A KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S uppercase to ASCII, so a
            # Unicode-aware fold would hide these and an ASCII fold must not.
            "toKen": "kept",
            "ſecret": "kept",
            "PASSWORDſ": "kept",
            "clé_api": "kept",
            "パスワード": "kept",
            "": "kept",
        },
    ),
    event(
        "model.request",
        metadata={"nested": {"token": "hide me", "safe": "kept"}, "list": [{"cookie": "hide me"}]},
        content={"headers": {"Authorization": "hide me", "accept": "kept"}},
    ),
]

REDACTOR_PROBE_EVENTS = [
    # Only scalars, so an equal-copy redactor replaces nothing and the status stays put.
    event("tool.start", metadata={"tool": "grep", "matched": 2}),
    # A nested container, so an equal-copy redactor replaces something that compares equal.
    event("tool.start", metadata={"argv": ["grep", "-n"], "flags": {"case": True}}),
    event("tool.start", metadata={"tool": "grep"}, content={"arguments": {"pattern": "x"}}),
]

# Scalars a redactor can rebuild into an equal but separately allocated value. The strings are
# long enough not to be interned by CPython and the integer is past the small-integer cache, so
# the Python rebuild really does produce a different object with the same value: exactly the case
# an identity test would misread as a redaction and a value test must not.
SCALAR_REDACTOR_PROBE_EVENTS = [
    event(
        "tool.start",
        metadata={
            "tool": "a tool name long enough that CPython will not intern it",
            "matched": MAX_SAFE_INTEGER,
            "ratio": 1.5,
            "enabled": True,
            "missing": None,
        },
    ),
    event(
        "tool.start",
        metadata={"argv": ["grep", "-n"], "flags": {"case": True}},
        content={"note": "another string that CPython has no reason to intern"},
    ),
]

PAYLOAD_EDGE_EVENTS = [
    event("model.response", metadata={"finish_reason": "stop"}, content={"text": TRICKY_TEXT}),
    event(
        "model.response",
        metadata={"cost_ratio": 1.5, "over_budget": -3, "big": 9007199254740991},
        content={"flags": [True, False, None], "deep": {"a": {"b": {"c": [1, {"d": []}]}}}},
    ),
    event("model.response", metadata={"__proto__": "kept", "constructor": "kept"}),
    event("model.response", metadata={"unicode": "漢 é ß", "escapes": "\\ \" \t"}),
]

DEGRADED_EVENTS = [
    event("model.request", metadata={"model": "fake-model-v0"}),
    event("model.response", metadata={"model": "fake-model-v0"}),
    event("observer.error", capture_status="unavailable", metadata={"reason": "fixture gap"}),
    event("tool.start", metadata={"tool": "grep"}),
]

# Scenarios whose ``dropped_events`` counters do not yet agree. Every one of them fails in a way
## Both emitters once disagreed on two capture-state facts: whether a failure that degrades an
# event without losing it counts as a dropped event, and whether an observer with no sink has
# lost anything. Both were closed by bringing the TypeScript emitter in line with the Python
# one, so these exclusion sets are empty and every scenario is compared in full. They stay as
# named, asserted constants rather than being deleted, so reopening a divergence means writing
# a scenario name here in a diff rather than silently loosening a comparison.
DIVERGENT_DROPPED_EVENTS: frozenset[str] = frozenset()

DIVERGENT_CAPTURE_STATE: frozenset[str] = frozenset()

# The one scenario whose duration nothing scripts. It injects a clock and no monotonic source,
# which is exactly the case the two emitters once disagreed about, so both now read their own
# real monotonic source and measure their own elapsed milliseconds for the same work. Every
# other thing about it is compared exactly, bytes included; only the measured number is compared
# as a shape, by :func:`measurement_free` and
# :func:`test_neither_emitter_measures_elapsed_time_with_an_injected_wall_clock`.
REAL_TIME_OPERATIONS: frozenset[str] = frozenset({"operation-clock-only-no-monotonic"})


def interleaved(rejections: dict) -> list[dict]:
    """Alternate refused and accepted events so a divergent rejection desynchronizes the streams.

    An emitter that charged a sequence number, an event ID, or a clock read for a refused event
    would number and timestamp every later event differently, which the accepted events between
    the rejections make visible.
    """
    events: list[dict] = []
    for index, fields in enumerate(rejections.values()):
        events.append(fields)
        events.append(event("finding.candidate", candidate_id=f"candidate-{index}"))
    return events


def scenario(name: str, mode: str, events: list[dict], **extra) -> dict:
    return {
        "name": name,
        "mode": mode,
        "run_id": f"run-{name}",
        "producer_id": f"producer-{name}",
        "events": events,
        **extra,
    }


def matrix_plan() -> dict:
    """The parity matrix: every input shape the contract names, in every recording mode."""
    all_rejections = {**REJECTED_EVENTS, **CONTENT_ONLY_REJECTIONS}
    scenarios = [
        scenario(f"every-event-type-{mode}", mode, ACCEPTED_EVENTS) for mode in RECORDING_MODES
    ]
    scenarios += [
        scenario("rejected-inputs-only", "content", list(all_rejections.values())),
        scenario("rejections-interleaved-content", "content", interleaved(all_rejections)),
        # Metadata mode accepts the content-only rejections, because it never copies content.
        # Both languages have to accept them, and to accept exactly the same ones.
        scenario("rejections-interleaved-metadata", "metadata", interleaved(all_rejections)),
        scenario("redaction-key-names", "content", REDACTION_EVENTS),
        scenario("equal-copy-redactor", "content", REDACTOR_PROBE_EVENTS, redactor="equal_copy"),
        scenario(
            "equal-copy-scalar-redactor",
            "content",
            SCALAR_REDACTOR_PROBE_EVENTS,
            redactor="equal_copy_scalar",
        ),
        scenario("throwing-redactor", "content", REDACTOR_PROBE_EVENTS, redactor="throws"),
        scenario("sink-throws", "content", ACCEPTED_EVENTS, sink_throws_on=[0, 3, 4]),
        # A JavaScript throw of a string, and the closest Python analogue: a BaseException that
        # is not an Exception. Both must be contained and counted as one lost event each.
        scenario(
            "sink-throws-a-non-error-value",
            "content",
            DEGRADED_EVENTS,
            sink_throws_on=[0, 2],
            sink_throw_kind="non_error",
        ),
        scenario("payload-edges", "content", PAYLOAD_EDGE_EVENTS),
        scenario("payload-edges-metadata-mode", "metadata", PAYLOAD_EDGE_EVENTS),
        # A clock that raises on two of its reads. The event is still emitted, with the epoch
        # timestamp, downgraded to partial, and marked in its own metadata, in both languages.
        scenario("clock-throws", "content", DEGRADED_EVENTS, clock_throws_on=[0, 2]),
        # A wall clock that jumps backwards is not an instrumentation failure: it costs nothing
        # but the order of the timestamps, and both emitters record what it said.
        scenario(
            "clock-steps-backwards",
            "content",
            DEGRADED_EVENTS,
            clock_offsets_ms=[0, -50, 25, 10],
        ),
        # An ID factory that raises on two of its reads. Both fall back to the same spelling.
        scenario("id-factory-throws", "content", DEGRADED_EVENTS, id_throws_on=[0, 2]),
        # A recording observer with no sink at all: both build and return the event and neither
        # writes a line. What they report about it is the open divergence below.
        scenario("no-sink-builder-mode", "content", DEGRADED_EVENTS, no_sink=True),
        # No run_id or producer_id: both must draw them from the injected factory in the same
        # order, so the event IDs that follow are offset identically.
        {
            "name": "generated-run-and-producer-ids",
            "mode": "metadata",
            "events": ACCEPTED_EVENTS,
        },
        # Off mode names itself "off" in both languages without calling the factory at all.
        {"name": "off-mode-defaults", "mode": "off", "events": ACCEPTED_EVENTS},
    ]
    return {"epoch_ms": EPOCH_MS, "step_ms": STEP_MS, "scenarios": scenarios}


def operation_step(name: str, outcome: str, **extra) -> dict:
    """One observed operation: a start event, a success builder, and a failure builder."""
    return {
        "name": name,
        "outcome": outcome,
        "start": {
            "type": "tool.start",
            "capture_status": "complete",
            "call_id": name,
            "metadata": {"tool": "grep"},
        },
        "success": {
            "type": "tool.end",
            "capture_status": "complete",
            "call_id": name,
            "metadata": {"tool": "grep", "outcome": "ok"},
        },
        "failure": {
            "type": "tool.end",
            "capture_status": "complete",
            "call_id": name,
            "metadata": {"tool": "grep", "outcome": "failed"},
        },
        **extra,
    }


def operation_scenario(name: str, monotonic_values: list, steps: list[dict], **extra) -> dict:
    return {
        "name": name,
        "mode": "content",
        "run_id": f"run-{name}",
        "producer_id": f"producer-{name}",
        "events": [],
        "operations": steps,
        "monotonic_values": monotonic_values,
        **extra,
    }


def operations_plan() -> dict:
    """The operation-boundary matrix: Python ``observe_async`` against TypeScript ``observeAsync``.

    Every scenario but one scripts the monotonic source read for read, in seconds, so the
    duration is a property of the plan and not of how fast the test ran. The differences between
    100.0 and 100.25 seconds, and between 0.0 and 0.0005, are exact in binary floating point, so
    both languages compute the same product before rounding and the half-way case really does
    test half-to-even rounding rather than a representation accident.

    The exception is ``operation-clock-only-no-monotonic``, which injects no monotonic source on
    purpose: a fixture that injects only a clock is the case in which TypeScript used to measure
    the span with that wall clock while Python measured it with a real monotonic source. Neither
    derives elapsed time from a clock now, so the scenario is here to keep that closed, and its
    duration is the one measured value in the matrix.
    """
    return {
        "epoch_ms": EPOCH_MS,
        "step_ms": STEP_MS,
        "scenarios": [
            operation_scenario(
                "operation-success-measurable",
                [100.0, 100.25],
                [operation_step("call-success", "success")],
            ),
            operation_scenario(
                "operation-failure-measurable",
                [100.0, 100.25],
                [operation_step("call-failure", "failure")],
            ),
            # 0.5 ms and 1.5 ms: Python's round and the TypeScript roundHalfToEven must send
            # both halves to the even neighbour, so these write 0 and 2, not 1 and 2.
            operation_scenario(
                "operation-durations-round-half-to-even",
                [0.0, 0.0005, 0.0, 0.0015],
                [
                    operation_step("call-half-down", "success"),
                    operation_step("call-half-up", "success"),
                ],
            ),
            operation_scenario(
                "operation-monotonic-throws-at-start",
                ["throw", 100.25],
                [operation_step("call-no-start-read", "success")],
            ),
            operation_scenario(
                "operation-monotonic-throws-at-end",
                [100.0, "throw"],
                [operation_step("call-no-end-read", "failure")],
            ),
            operation_scenario(
                "operation-monotonic-steps-backwards",
                [100.0, 99.0],
                [operation_step("call-backwards", "success")],
            ),
            operation_scenario(
                "operation-monotonic-returns-nan",
                [100.0, "nan"],
                [operation_step("call-nan", "success")],
            ),
            # The builder insists on a duration the emitter could not measure. Both must drop it
            # rather than write a number nothing measured.
            operation_scenario(
                "operation-forced-duration-is-dropped",
                [100.0, "throw"],
                [operation_step("call-forced", "success", forced_duration_ms=4242)],
            ),
            # The clock fails on the completion event only, so the duration is measurable and the
            # timestamp is not. Both write the measured duration and the epoch timestamp.
            operation_scenario(
                "operation-clock-throws-on-completion",
                [100.0, 100.25],
                [operation_step("call-clock", "success")],
                clock_throws_on=[1],
            ),
            # A clock and no monotonic source: the case that used to diverge. Neither emitter
            # may time the operation with that wall clock, so the clock is read exactly once
            # per event in both, the two timestamps are the injected ones, and the duration is
            # each language's own real measurement rather than the injected 10 ms step.
            {
                "name": "operation-clock-only-no-monotonic",
                "mode": "content",
                "run_id": "run-operation-clock-only-no-monotonic",
                "producer_id": "producer-operation-clock-only-no-monotonic",
                "events": [],
                "operations": [operation_step("call-clock-only", "success")],
            },
            # Off mode runs the operation and instruments nothing, in both languages.
            {
                "name": "operation-off-mode",
                "mode": "off",
                "events": [],
                "operations": [operation_step("call-off", "success")],
                "monotonic_values": [100.0, 100.25],
            },
        ],
    }


@pytest.fixture(scope="session")
def matrix_pairs(tmp_path_factory) -> dict[str, tuple[dict, dict]]:
    """Both emitters over the whole matrix, once per session rather than once per test."""
    return paired(tmp_path_factory.mktemp("observer-parity-matrix"), matrix_plan())


@pytest.fixture(scope="session")
def operation_pairs(tmp_path_factory) -> dict[str, tuple[dict, dict]]:
    """Both operation-boundary helpers over the same scenarios, once per session."""
    return paired(tmp_path_factory.mktemp("observer-parity-operations"), operations_plan())


def test_the_python_emitter_reproduces_the_shared_v2_fixture_byte_for_byte():
    """The fixture is the byte-level example a reader compares a JSONL line to."""
    supplied = ["run-example-1", "dispatcher-example", "event-example-1"]
    observer = Observer(
        mode="content",
        id_factory=id_factory(supplied),
        clock=fixed_clock(EPOCH_MS, 0),
    )
    emitted = observer.emit(
        type="model.request",
        capture_status="complete",
        call_id="call-example-1",
        metadata={"model": "example-model", "input_tokens": 42},
        content={"authorization": "real credential"},
    )
    assert emitted == FIXTURE
    # Key order too.
    assert list(emitted) == list(FIXTURE)
    assert json.dumps(emitted, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        FIXTURE, ensure_ascii=False, separators=(",", ":")
    )
    # The credential the caller passed never reaches the record.
    assert "real credential" not in json.dumps(emitted)
    # This observer has no sink, so it is being used as a builder and the event it returned
    # reached nobody. Python records that honestly as one lost event rather than a clean state.
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP_MESSAGE
    )


@needs_node
def test_the_typescript_emitter_reproduces_the_same_shared_v2_fixture(tmp_path):
    plan = {
        "epoch_ms": EPOCH_MS,
        "step_ms": 0,
        "scenarios": [
            {
                "name": "shared-fixture",
                "mode": "content",
                "id_values": ["run-example-1", "dispatcher-example", "event-example-1"],
                "events": [
                    {
                        "type": "model.request",
                        "capture_status": "complete",
                        "call_id": "call-example-1",
                        "metadata": {"model": "example-model", "input_tokens": 42},
                        "content": {"authorization": "real credential"},
                    }
                ],
            }
        ],
    }
    python_case, node_case = both(tmp_path, plan)[0]
    assert parsed(node_case["lines"]) == [FIXTURE]
    assert node_case["lines"] == python_case["lines"]


@needs_node
def test_both_emitters_write_byte_identical_jsonl_for_the_whole_parity_matrix(matrix_pairs):
    """Byte for byte, key order included. A reordered or reshaped field fails here."""
    written = 0
    for name, (python_case, node_case) in matrix_pairs.items():
        assert len(python_case["lines"]) == len(node_case["lines"]), name
        for index, (python_line, node_line) in enumerate(
            zip(python_case["lines"], node_case["lines"])
        ):
            assert python_line == node_line, f"{name} line {index}"
        written += len(python_case["lines"])
    # Guard against a matrix that agreed because it recorded nothing. The count only grows as
    # cases are added, so a shrinking matrix fails here rather than passing on less evidence.
    assert written >= 180
    # Key order is the schema's declaration order in both, on every line either wrote.
    declared = list(
        json.loads((ROOT / "schema/v2/trace-event.schema.json").read_text())["properties"]
    )
    for python_case, _ in matrix_pairs.values():
        for emitted in parsed(python_case["lines"]):
            assert list(emitted) == [name for name in declared if name in emitted]


@needs_node
def test_both_emitters_agree_on_which_matrix_events_were_recorded(matrix_pairs):
    """Per input, not per run: a divergent rejection names the case that caused it."""
    by_name = {}
    for name, (python_case, node_case) in matrix_pairs.items():
        assert python_case["recorded"] == node_case["recorded"], name
        by_name[name] = python_case["recorded"]

    # The rejection set is the contract, so pin it rather than only comparing the two.
    assert by_name["rejected-inputs-only"] == [False] * (
        len(REJECTED_EVENTS) + len(CONTENT_ONLY_REJECTIONS)
    )
    # Metadata mode never copies content, so the content-only rejections are recorded there.
    metadata_mode = by_name["rejections-interleaved-metadata"]
    content_mode = by_name["rejections-interleaved-content"]
    refused_in_metadata_mode = sum(1 for flag in metadata_mode[::2] if not flag)
    assert refused_in_metadata_mode == len(REJECTED_EVENTS)
    assert sum(1 for flag in content_mode[::2] if not flag) == len(REJECTED_EVENTS) + len(
        CONTENT_ONLY_REJECTIONS
    )
    # Every interleaved valid event was recorded in both modes.
    assert all(metadata_mode[1::2]) and all(content_mode[1::2])
    # A sink that throws loses the line but still records the event, whatever it threw; a
    # redactor that throws rejects the event outright in both languages.
    assert all(by_name["sink-throws"])
    assert all(by_name["sink-throws-a-non-error-value"])
    assert not any(by_name["throwing-redactor"])
    assert not any(by_name["off-mode-defaults"])
    # A recording observer with no sink still builds and returns every event in both languages.
    assert all(by_name["no-sink-builder-mode"])


@needs_node
def test_both_emitters_assign_the_same_sequence_numbers_and_event_ids(matrix_pairs):
    """A rejection that costs a sequence number in one language desynchronizes the streams."""
    for name, (python_case, node_case) in matrix_pairs.items():
        assert python_case["sequences"] == node_case["sequences"], name
        assert python_case["event_ids"] == node_case["event_ids"], name
        assert python_case["run_id"] == node_case["run_id"], name
        assert python_case["producer_id"] == node_case["producer_id"], name

    # Refused events consume nothing: the accepted ones are still numbered densely from zero and
    # carry consecutive IDs from the injected factory.
    interleaved_case = matrix_pairs["rejections-interleaved-content"][0]
    accepted = [value for value in interleaved_case["sequences"] if value is not None]
    assert accepted == list(range(len(accepted)))
    ids = [value for value in interleaved_case["event_ids"] if value is not None]
    assert ids == [f"event-{index + 1}" for index in range(len(ids))]
    # Nothing at all was consumed by the scenario in which every event was refused.
    rejected_only = matrix_pairs["rejected-inputs-only"][0]
    assert rejected_only["sequences"] == [None] * len(rejected_only["sequences"])
    # A clock read is not consumed either: the accepted events walk the injected clock one tick
    # at a time, so a refused event that had read it would shift every timestamp after it.
    timestamps = [line["timestamp"] for line in parsed(interleaved_case["lines"])]
    assert timestamps[0] == "2026-09-20T12:00:00.000Z"
    assert timestamps == [iso_timestamp(index) for index in range(len(timestamps))]
    # Off mode invents no run or producer ID in either language.
    assert matrix_pairs["off-mode-defaults"][0]["run_id"] == "off"
    assert matrix_pairs["off-mode-defaults"][0]["producer_id"] == "off"
    assert matrix_pairs["generated-run-and-producer-ids"][0]["run_id"] == "run-1"
    assert matrix_pairs["generated-run-and-producer-ids"][0]["producer_id"] == "producer-2"


@needs_node
def test_both_emitters_report_the_same_capture_state_for_every_matrix_case(matrix_pairs):
    """``capture_gap`` and ``last_sink_error`` everywhere, ``dropped_events`` outside two lists.

    The two exclusion lists are named constants, empty today, so a reopened divergence stays
    a divergence rather than becoming a quiet allowance. Everything not named in them is
    compared field for field.
    """
    by_name = {}
    for name, (python_case, node_case) in matrix_pairs.items():
        python_state = python_case["state"]
        node_state = node_case["state"]
        if name not in DIVERGENT_CAPTURE_STATE:
            assert python_state["capture_gap"] == node_state["capture_gap"], name
            assert python_state["last_sink_error"] == node_state["last_sink_error"], name
        if name not in DIVERGENT_DROPPED_EVENTS and name not in DIVERGENT_CAPTURE_STATE:
            assert python_state["dropped_events"] == node_state["dropped_events"], name
            assert python_state == node_state, name
        by_name[name] = python_state

    clean = {"dropped_events": 0, "capture_gap": False, "last_sink_error": None}
    assert by_name["every-event-type-content"] == clean
    assert by_name["off-mode-defaults"] == clean
    assert by_name["redaction-key-names"] == clean
    assert by_name["equal-copy-scalar-redactor"] == clean
    assert by_name["clock-steps-backwards"] == clean
    # One gap per refused event, one per failed write, one per redactor failure.
    refused = len(REJECTED_EVENTS) + len(CONTENT_ONLY_REJECTIONS)
    assert by_name["rejected-inputs-only"] == {
        "dropped_events": refused,
        "capture_gap": True,
        "last_sink_error": GAP_MESSAGE,
    }
    assert by_name["sink-throws"] == {
        "dropped_events": 3,
        "capture_gap": True,
        "last_sink_error": GAP_MESSAGE,
    }
    assert by_name["sink-throws-a-non-error-value"] == {
        "dropped_events": 2,
        "capture_gap": True,
        "last_sink_error": GAP_MESSAGE,
    }
    assert by_name["throwing-redactor"] == {
        "dropped_events": len(REDACTOR_PROBE_EVENTS),
        "capture_gap": True,
        "last_sink_error": GAP_MESSAGE,
    }


@needs_node
def test_a_redactor_returning_an_equal_copy_of_a_container_marks_both_emitters_redacted(
    matrix_pairs,
):
    """Strict inequality: a container compares by identity, so an equal rebuild is a replacement."""
    python_case, node_case = matrix_pairs["equal-copy-redactor"]
    assert python_case["lines"] == node_case["lines"]
    statuses = [emitted["capture_status"] for emitted in parsed(python_case["lines"])]
    # The scalar-only event is untouched; the two carrying a container are marked redacted.
    assert statuses == ["complete", "redacted", "redacted"]
    # The values themselves are unchanged: an equal copy replaces nothing a reader can see.
    assert parsed(python_case["lines"])[1]["metadata"] == {
        "argv": ["grep", "-n"],
        "flags": {"case": True},
    }
    default = [
        emitted["capture_status"]
        for emitted in parsed(matrix_pairs["redaction-key-names"][0]["lines"])
    ]
    assert default == ["redacted", "complete", "redacted"]


@needs_node
def test_a_redactor_returning_an_equal_copy_of_a_scalar_marks_neither_emitter_redacted(
    matrix_pairs,
):
    """The other half of the same rule, and the half Python cannot answer with ``is``.

    A redactor that hands back an equal string, integer, or float replaced nothing under
    JavaScript strict inequality, so neither emitter may mark the event ``redacted``. Python
    reaches that answer by comparing immutable scalars by value; an identity test would report
    a redaction here that the TypeScript emitter never reports.
    """
    python_case, node_case = matrix_pairs["equal-copy-scalar-redactor"]
    assert python_case["lines"] == node_case["lines"]
    emitted = parsed(python_case["lines"])
    assert [line["capture_status"] for line in emitted] == ["complete", "complete"]
    # The payload survives unchanged, scalars and containers alike.
    assert emitted[0]["metadata"] == {
        "tool": "a tool name long enough that CPython will not intern it",
        "matched": MAX_SAFE_INTEGER,
        "ratio": 1.5,
        "enabled": True,
        "missing": None,
    }
    assert emitted[1]["metadata"] == {"argv": ["grep", "-n"], "flags": {"case": True}}
    assert python_case["state"] == node_case["state"]


def test_python_compares_redactor_scalars_by_value_and_not_by_identity():
    """Pinned without node, because this is the Python half of rule 5 and it is easy to regress.

    The redactor here returns values that are equal to what it was given and are not the same
    objects, which CPython makes easy to do by accident. An emitter that asked ``is`` would call
    this a redaction; the shared rule says it is not one.
    """
    seen: list[dict] = []
    original_text = "a tool name long enough that CPython will not intern it"
    rebuilt: dict[str, Any] = {}

    def redactor(key, value, path):
        replacement = equal_copy_scalar_redactor(key, value, path)
        rebuilt[key] = replacement
        return replacement

    observer = Observer(
        mode="content",
        sink=seen.append,
        run_id="run-1",
        producer_id="producer-1",
        id_factory=id_factory(None),
        clock=fixed_clock(EPOCH_MS, 0),
        redactor=redactor,
    )
    emitted = observer.emit(
        type="tool.start",
        capture_status="complete",
        metadata={"tool": original_text, "matched": MAX_SAFE_INTEGER},
    )
    # The premise: the replacements really are different objects with the same values.
    assert rebuilt["tool"] is not original_text
    assert rebuilt["tool"] == original_text
    assert rebuilt["matched"] is not MAX_SAFE_INTEGER
    assert rebuilt["matched"] == MAX_SAFE_INTEGER
    # The conclusion: neither counts as a replacement, so the event is not downgraded.
    assert emitted["capture_status"] == "complete"
    assert emitted["metadata"] == {"tool": original_text, "matched": MAX_SAFE_INTEGER}
    assert seen == [emitted]


@needs_node
def test_neither_emitter_measures_elapsed_time_with_an_injected_wall_clock(operation_pairs):
    """The closed divergence, pinned across the two languages on the case that used to show it.

    A fixture that injects a clock and no monotonic source used to get a clock-derived duration
    from TypeScript and a real elapsed time from Python: the TypeScript emitter read its default
    elapsed-time source off the injected ``Clock``, which is a wall clock and can be adjusted
    forwards or backwards between two reads. Both now default to a real monotonic source, so the
    clock is read exactly once per event in each language, the two timestamps are the injected
    ones rather than the third and fourth ticks of a clock that also timed the operation, and
    the duration is a measurement in both.

    The measured milliseconds are the one value here that is not a property of the plan, so they
    are asserted as a shape, a whole nonnegative count, and blanked before the bytes are
    compared. Nothing sleeps: the operation is an immediate return.
    """
    python_case, node_case = operation_pairs["operation-clock-only-no-monotonic"]
    # Byte for byte apart from the two measurements, which no plan pins.
    assert measurement_free(python_case)["lines"] == measurement_free(node_case)["lines"]
    assert python_case["state"] == node_case["state"] == {
        "dropped_events": 0,
        "capture_gap": False,
        "last_sink_error": None,
    }
    for case, language in ((python_case, "python"), (node_case, "node")):
        start, completion = parsed(case["lines"])
        # One clock read per event. Two more would be the wall clock timing the operation, and
        # they would move the completion timestamp two ticks further on.
        assert [start["timestamp"], completion["timestamp"]] == [
            iso_timestamp(0),
            iso_timestamp(1),
        ], language
        assert "duration_ms" not in start, language
        # A real measurement, so it is an integer and nonnegative, and it is not asserted to be
        # the 10 ms step the injected clock would have implied.
        measured = completion["duration_ms"]
        assert isinstance(measured, int) and not isinstance(measured, bool), language
        assert measured >= 0, language
        # Nothing was degraded: a measured span leaves the completion event complete.
        assert completion["capture_status"] == "complete", language
        assert "observer_capture_gap" not in completion["metadata"], language
        assert case["operations"][0]["duration_seen"] == measured, language


def test_python_never_measures_elapsed_time_with_the_injected_wall_clock():
    """The Python half of the same rule, pinned without node so it holds in a skipped run.

    Python's ``monotonic`` argument defaults to :func:`time.monotonic` and never falls back to
    the injected ``clock``, because a wall clock can be adjusted between two reads and a span
    measured with one would record time that never elapsed. The TypeScript emitter now makes the
    same choice, and the two are compared on it by
    :func:`test_neither_emitter_measures_elapsed_time_with_an_injected_wall_clock`, which needs
    node and the built SDK. This one needs neither: what it asserts is that the wall clock is
    read exactly twice, once per event, and never a third and fourth time to time the operation.
    It also covers the synchronous ``observe``, which has no TypeScript counterpart at all.
    """
    reads = {"count": 0}

    def counting_clock():
        reads["count"] += 1
        return EPOCH

    seen: list[dict] = []
    observer = Observer(
        mode="metadata",
        sink=seen.append,
        run_id="run-1",
        producer_id="producer-1",
        clock=counting_clock,
        id_factory=id_factory(None),
    )
    returned = observer.observe(
        {"type": "tool.start", "capture_status": "complete", "metadata": {"tool": "grep"}},
        lambda elapsed: {
            "type": "tool.end",
            "capture_status": "complete",
            "metadata": {"tool": "grep"},
            "duration_ms": elapsed,
        },
        lambda error, elapsed: {
            "type": "tool.end",
            "capture_status": "complete",
            "metadata": {"tool": "grep"},
        },
        lambda: {"matched": 2},
    )
    assert returned == {"matched": 2}
    # One read per event and no more: the elapsed-time source is a separate source.
    assert reads["count"] == 2
    assert [line["type"] for line in seen] == ["tool.start", "tool.end"]
    # The duration is a real measurement from time.monotonic, so it is a whole nonnegative
    # number of milliseconds rather than the 10 ms step this clock would have implied.
    assert isinstance(seen[1]["duration_ms"], int)
    assert seen[1]["duration_ms"] >= 0
    assert observer.get_state() == CaptureState()


@needs_node
def test_the_default_redactor_hides_the_same_keys_in_both_languages(matrix_pairs):
    """ASCII case folding only, so a Unicode key JavaScript keeps is not hidden by Python."""
    python_case, node_case = matrix_pairs["redaction-key-names"]
    assert python_case["lines"] == node_case["lines"]
    hidden, unicode_keys, nested = parsed(python_case["lines"])
    assert hidden["metadata"] == {
        "api_key": "[REDACTED]",
        "Api-Key": "[REDACTED]",
        "APIKEY": "[REDACTED]",
        "authorization": "[REDACTED]",
        "Cookies": "[REDACTED]",
        "password": "[REDACTED]",
        "secrets": "[REDACTED]",
        "TOKEN": "[REDACTED]",
        "private-key": "[REDACTED]",
        "credential": "[REDACTED]",
        "input_tokens": 31,
        "output_tokens": 18,
        "token_budget": 4096,
        "keep": "kept",
    }
    # Every Unicode key survives: none of them is an ASCII credential name.
    assert "[REDACTED]" not in json.dumps(unicode_keys["metadata"], ensure_ascii=False)
    assert nested["metadata"]["nested"] == {"token": "[REDACTED]", "safe": "kept"}
    assert nested["metadata"]["list"] == [{"cookie": "[REDACTED]"}]
    assert nested["content"]["headers"] == {"Authorization": "[REDACTED]", "accept": "kept"}


@needs_node
def test_both_emitters_draw_the_payload_depth_limit_at_the_same_container(matrix_pairs):
    """Neither language accepts a payload the other refuses, and neither truncates one.

    The limit is counted in containers, the payload object itself included, so a payload of
    exactly ``MAX_PAYLOAD_DEPTH`` containers is stored whole and one container deeper is refused
    as a capture gap. Objects and lists count the same. In metadata mode the content payload is
    never copied, so a too-deep ``content`` is accepted there by both, which is the one place
    the depth rule is mode-dependent.
    """
    python_case, node_case = matrix_pairs["rejected-inputs-only"]
    assert python_case["recorded"] == node_case["recorded"]
    refusals = list({**REJECTED_EVENTS, **CONTENT_ONLY_REJECTIONS})
    for name in (
        "metadata_nested_past_the_depth_limit",
        "metadata_lists_nested_past_the_depth_limit",
        "content_nested_past_the_depth_limit",
    ):
        assert python_case["recorded"][refusals.index(name)] is False, name

    # In metadata mode the too-deep content is accepted by both, and the too-deep metadata is
    # still refused by both.
    metadata_mode = matrix_pairs["rejections-interleaved-metadata"][0]["recorded"][::2]
    interleaved_names = list({**REJECTED_EVENTS, **CONTENT_ONLY_REJECTIONS})
    assert metadata_mode[interleaved_names.index("content_nested_past_the_depth_limit")] is True
    assert (
        metadata_mode[interleaved_names.index("metadata_nested_past_the_depth_limit")] is False
    )

    # The payloads sitting exactly on the limit survive whole, with the same bytes.
    accepted = parsed(matrix_pairs["every-event-type-content"][0]["lines"])
    at_limit = [line for line in accepted if "child" in line["metadata"]]
    assert len(at_limit) == 1
    depth = 1
    walk = at_limit[0]["metadata"]
    while "child" in walk:
        walk = walk["child"]
        depth += 1
    assert depth == MAX_PAYLOAD_DEPTH
    assert walk == {"leaf": "bottom"}


@needs_node
def test_both_emitters_share_one_payload_depth_limit_constant(matrix_pairs):
    """The constant is exported from both packages, so a harness can check its own payloads."""
    for name, (python_case, node_case) in matrix_pairs.items():
        assert python_case["max_payload_depth"] == MAX_PAYLOAD_DEPTH, name
        assert node_case["max_payload_depth"] == MAX_PAYLOAD_DEPTH, name


@needs_node
def test_both_emitters_refuse_a_duration_past_the_safe_integer_bound(matrix_pairs):
    """``duration_ms`` stops at ``2 ** 53 - 1`` in both, and is stored as an integer in both."""
    python_case, node_case = matrix_pairs["rejected-inputs-only"]
    refusals = list({**REJECTED_EVENTS, **CONTENT_ONLY_REJECTIONS})
    for name in (
        "duration_one_past_the_safe_integer_bound",
        "duration_far_past_the_safe_integer_bound",
        "duration_above_1e21_as_a_float",
        "duration_above_1e21_as_an_integer",
    ):
        index = refusals.index(name)
        assert python_case["recorded"][index] is False, name
        assert node_case["recorded"][index] is False, name

    # The bound itself is accepted, in both spellings, and written as one integer by both.
    accepted = parsed(matrix_pairs["every-event-type-content"][0]["lines"])
    durations = [line["duration_ms"] for line in accepted if "duration_ms" in line]
    assert durations.count(MAX_SAFE_INTEGER) == 2
    assert all(isinstance(value, int) for value in durations)
    assert matrix_pairs["every-event-type-content"][0]["lines"] == (
        matrix_pairs["every-event-type-content"][1]["lines"]
    )


@needs_node
def test_a_clock_that_throws_degrades_both_emitters_identically(matrix_pairs):
    """The clock is caller code: a read that raises is a recorded gap in both, not an escape.

    Both emitters still emit the event, fall back to the same epoch timestamp, downgrade the
    event to ``partial`` unless it is already ``unavailable``, and stamp ``observer_capture_gap``
    into its metadata, so a reader cannot take a fabricated timestamp for a measured one.
    """
    python_case, node_case = matrix_pairs["clock-throws"]
    assert python_case["lines"] == node_case["lines"]
    assert python_case["recorded"] == node_case["recorded"] == [True, True, True, True]
    assert python_case["sequences"] == node_case["sequences"] == [0, 1, 2, 3]
    assert python_case["event_ids"] == node_case["event_ids"]
    assert python_case["state"]["capture_gap"] == node_case["state"]["capture_gap"] is True
    assert python_case["state"]["last_sink_error"] == node_case["state"]["last_sink_error"]

    emitted = parsed(python_case["lines"])
    timestamps = [line["timestamp"] for line in emitted]
    assert timestamps[0] == timestamps[2] == "1970-01-01T00:00:00.000Z"
    # The degraded events say so in themselves, the healthy ones do not.
    assert [line["capture_status"] for line in emitted] == [
        "partial",
        "complete",
        "unavailable",
        "complete",
    ]
    assert [line["metadata"].get("observer_capture_gap") for line in emitted] == [
        True,
        None,
        True,
        None,
    ]


@needs_node
def test_a_clock_that_steps_backwards_costs_both_emitters_nothing_but_the_order(matrix_pairs):
    """A wall clock that jumps is not an instrumentation failure, and neither emitter invents one.

    The timestamps come out unordered because that is what the clock said. ``sequence`` is the
    ordering a reader may rely on, and it is still dense and ascending in both languages.
    """
    python_case, node_case = matrix_pairs["clock-steps-backwards"]
    assert python_case["lines"] == node_case["lines"]
    assert python_case["state"] == node_case["state"]
    assert python_case["state"] == {
        "dropped_events": 0,
        "capture_gap": False,
        "last_sink_error": None,
    }
    emitted = parsed(python_case["lines"])
    assert [line["timestamp"] for line in emitted] == [
        "2026-09-20T12:00:00.000Z",
        "2026-09-20T11:59:59.950Z",
        "2026-09-20T12:00:00.025Z",
        "2026-09-20T12:00:00.010Z",
    ]
    assert [line["sequence"] for line in emitted] == [0, 1, 2, 3]
    # Nothing is marked: the clock answered every read, so no event carries a fabricated field.
    assert all("observer_capture_gap" not in line["metadata"] for line in emitted)


@needs_node
def test_an_id_factory_that_throws_degrades_both_emitters_identically(matrix_pairs):
    """A failed ID read leaves a fabricated ID, so both mark the event that carries one."""
    python_case, node_case = matrix_pairs["id-factory-throws"]
    assert python_case["lines"] == node_case["lines"]
    assert python_case["event_ids"] == node_case["event_ids"]
    assert python_case["recorded"] == node_case["recorded"] == [True, True, True, True]
    assert python_case["state"]["capture_gap"] == node_case["state"]["capture_gap"] is True
    assert python_case["state"]["last_sink_error"] == node_case["state"]["last_sink_error"]
    # The fallback IDs are spelled identically, and the reads that succeeded still count from
    # one, so a failed read costs the ID it would have issued and nothing after it.
    assert python_case["event_ids"] == [
        "event-fallback-1",
        "event-1",
        "event-fallback-2",
        "event-2",
    ]
    emitted = parsed(python_case["lines"])
    assert [line["capture_status"] for line in emitted] == [
        "partial",
        "complete",
        "unavailable",
        "complete",
    ]
    assert [line["metadata"].get("observer_capture_gap") for line in emitted] == [
        True,
        None,
        True,
        None,
    ]


@needs_node
def test_a_sink_that_throws_a_value_that_is_not_an_error_is_contained_by_both(matrix_pairs):
    """A JavaScript ``throw "text"`` and a bare Python ``BaseException`` are both contained.

    Neither reaches the caller, both cost exactly the line that failed to be written, and the
    events around the failure are unaffected in both languages.
    """
    python_case, node_case = matrix_pairs["sink-throws-a-non-error-value"]
    assert python_case["lines"] == node_case["lines"]
    assert python_case["state"] == node_case["state"]
    assert python_case["recorded"] == node_case["recorded"] == [True, True, True, True]
    # Writes 0 and 2 failed, so only two lines were written, and they are the other two events.
    assert len(python_case["lines"]) == 2
    assert [line["sequence"] for line in parsed(python_case["lines"])] == [1, 3]
    assert python_case["state"] == {
        "dropped_events": 2,
        "capture_gap": True,
        "last_sink_error": GAP_MESSAGE,
    }


@needs_node
def test_the_operation_boundary_helpers_agree_across_languages(operation_pairs):
    """Python ``observe_async`` against TypeScript ``observeAsync``, over one set of scenarios.

    Both take the same four positional arguments in the same order, a start event, a success
    builder taking the elapsed milliseconds, a failure builder taking the operation's error and
    the elapsed milliseconds, and a zero-argument operation, so no adaptation is needed beyond
    spelling "unmeasurable" as Python's ``None`` and TypeScript's ``undefined``. The comparison
    covers the value or error that passed through, the duration each builder was handed, and the
    start and completion events each wrote.

    What could not be compared, and why:

    * Python's synchronous ``observe`` has no TypeScript counterpart at all, because every
      TypeScript boundary is a promise; it is exercised by the Python-only tests instead. The
      same is true of Python's synchronous ``flush`` and ``close``, whose TypeScript spellings
      are coroutines.
    * Identity of the returned value and of the re-raised error is compared as a per-language
      boolean rather than across the boundary: neither an object nor an exception can cross the
      process the node driver runs in, so each language checks its own ``is``/``===`` and the
      two booleans are compared.
    * Sub-millisecond spans are compared only after rounding, because ``duration_ms`` is a whole
      number of milliseconds in both and the TypeScript ``Clock`` cannot carry finer than a
      millisecond anyway.
    * The duration of a scenario named in :data:`REAL_TIME_OPERATIONS` is a real measurement in
      each language, so it is blanked by :func:`measurement_free` and compared as a shape by
      :func:`test_neither_emitter_measures_elapsed_time_with_an_injected_wall_clock`. Everything
      else about that scenario, the bytes included, is compared here like any other.
    """
    for name, (python_case, node_case) in operation_pairs.items():
        if name in REAL_TIME_OPERATIONS:
            python_case, node_case = measurement_free(python_case), measurement_free(node_case)
        assert python_case["operations"] == node_case["operations"], name
        assert python_case["lines"] == node_case["lines"], name
        assert python_case["event_ids"] == node_case["event_ids"], name
        assert python_case["state"]["capture_gap"] == node_case["state"]["capture_gap"], name
        assert (
            python_case["state"]["last_sink_error"] == node_case["state"]["last_sink_error"]
        ), name
        if name not in DIVERGENT_DROPPED_EVENTS:
            assert python_case["state"] == node_case["state"], name

    # A measured success: the value passes through untouched and the duration is written.
    success = operation_pairs["operation-success-measurable"][0]
    assert success["operations"] == [
        {
            "name": "call-success",
            "outcome": "value",
            "passthrough_identity": True,
            "duration_seen": 250,
            "builder_saw_original_error": None,
        }
    ]
    start, completion = parsed(success["lines"])
    assert start["type"] == "tool.start" and "duration_ms" not in start
    assert completion["type"] == "tool.end"
    assert completion["duration_ms"] == 250
    assert completion["capture_status"] == "complete"
    assert "observer_capture_gap" not in completion["metadata"]

    # A measured failure: the original error is re-raised and is what the builder was handed.
    failure = operation_pairs["operation-failure-measurable"][0]
    assert failure["operations"] == [
        {
            "name": "call-failure",
            "outcome": "error",
            "passthrough_identity": True,
            "duration_seen": 250,
            "builder_saw_original_error": True,
        }
    ]
    assert parsed(failure["lines"])[1]["metadata"]["outcome"] == "failed"

    # Half to even, in both languages: 0.5 ms becomes 0 and 1.5 ms becomes 2.
    halves = operation_pairs["operation-durations-round-half-to-even"][0]
    assert [step["duration_seen"] for step in halves["operations"]] == [0, 2]
    assert [
        line["duration_ms"] for line in parsed(halves["lines"]) if line["type"] == "tool.end"
    ] == [0, 2]

    # Off mode runs the operation and instruments nothing at all.
    off = operation_pairs["operation-off-mode"][0]
    assert off["lines"] == []
    assert off["operations"] == [
        {
            "name": "call-off",
            "outcome": "value",
            "passthrough_identity": True,
            "duration_seen": None,
            "builder_saw_original_error": None,
        }
    ]
    assert off["state"] == {
        "dropped_events": 0,
        "capture_gap": False,
        "last_sink_error": None,
    }


@needs_node
def test_an_unmeasurable_duration_is_omitted_and_marked_by_both_helpers(operation_pairs):
    """Never a fabricated duration: the completion event is still written, and says it is partial.

    Four ways to lose the measurement, all handled the same by both emitters: the first read
    raises, the second read raises, the source steps backwards, and the source returns a value
    that is not finite. In every one the builder is handed no duration, the completion event is
    emitted without ``duration_ms``, downgraded to ``partial``, and marked with
    ``observer_capture_gap``, and one capture gap is recorded.
    """
    unmeasurable = (
        "operation-monotonic-throws-at-start",
        "operation-monotonic-throws-at-end",
        "operation-monotonic-steps-backwards",
        "operation-monotonic-returns-nan",
    )
    for name in unmeasurable:
        python_case, node_case = operation_pairs[name]
        assert python_case["lines"] == node_case["lines"], name
        assert python_case["operations"] == node_case["operations"], name
        assert [step["duration_seen"] for step in python_case["operations"]] == [None], name
        completion = parsed(python_case["lines"])[1]
        assert "duration_ms" not in completion, name
        assert completion["capture_status"] == "partial", name
        assert completion["metadata"]["observer_capture_gap"] is True, name
        assert python_case["state"]["capture_gap"] is True, name
        assert node_case["state"]["capture_gap"] is True, name

    # A builder that returns a duration anyway, having been told there is none, does not get it
    # written: the emitter drops it rather than record a number nothing measured.
    forced_python, forced_node = operation_pairs["operation-forced-duration-is-dropped"]
    assert forced_python["lines"] == forced_node["lines"]
    completion = parsed(forced_python["lines"])[1]
    assert "duration_ms" not in completion
    assert completion["capture_status"] == "partial"
    assert completion["metadata"]["observer_capture_gap"] is True

    # A clock that fails on the completion event costs the timestamp and not the duration.
    clock_python, clock_node = operation_pairs["operation-clock-throws-on-completion"]
    assert clock_python["lines"] == clock_node["lines"]
    completion = parsed(clock_python["lines"])[1]
    assert completion["duration_ms"] == 250
    assert completion["timestamp"] == "1970-01-01T00:00:00.000Z"
    assert completion["capture_status"] == "partial"
    assert completion["metadata"]["observer_capture_gap"] is True


def test_the_parity_matrix_covers_every_input_shape_the_contract_names():
    """The matrix is the test. Deleting a case has to fail here rather than pass quietly."""
    plan = matrix_plan()
    modes = {case["mode"] for case in plan["scenarios"]}
    assert modes == set(RECORDING_MODES)
    emitted_types = {
        fields.get("type") for case in plan["scenarios"] for fields in case["events"]
    }
    assert set(EVENT_TYPES) <= emitted_types
    statuses = {
        fields.get("capture_status") for case in plan["scenarios"] for fields in case["events"]
    }
    assert set(CAPTURE_STATUSES) <= statuses
    required_rejections = {
        "unknown_field_name",
        "missing_metadata",
        "metadata_is_a_list",
        "metadata_is_a_string",
        "empty_call_id",
        "non_string_call_id",
        "null_duration",
        "non_integral_duration",
        "negative_duration",
        "non_finite_duration",
        "duration_one_past_the_safe_integer_bound",
        "duration_above_1e21_as_a_float",
        "duration_above_1e21_as_an_integer",
        "cyclic_metadata",
        "non_finite_number_in_metadata",
        "metadata_nested_past_the_depth_limit",
        "metadata_lists_nested_past_the_depth_limit",
    }
    assert required_rejections <= set(REJECTED_EVENTS)
    assert {
        "cyclic_content",
        "non_finite_number_in_content",
        "content_nested_past_the_depth_limit",
    } <= set(CONTENT_ONLY_REJECTIONS)
    # An integral duration is accepted, an integral float is stored as an integer, and the
    # safe-integer bound itself is accepted.
    assert any(fields.get("duration_ms") == 120 for fields in ACCEPTED_EVENTS)
    assert any(isinstance(fields.get("duration_ms"), float) for fields in ACCEPTED_EVENTS)
    assert any(fields.get("duration_ms") == MAX_SAFE_INTEGER for fields in ACCEPTED_EVENTS)
    # The degraded hooks each have a scenario, and every one of them is a caller-supplied hook
    # the emitter has to contain rather than propagate.
    names = {case["name"] for case in plan["scenarios"]}
    assert {
        "sink-throws",
        "sink-throws-a-non-error-value",
        "throwing-redactor",
        "equal-copy-redactor",
        "equal-copy-scalar-redactor",
        "clock-throws",
        "clock-steps-backwards",
        "id-factory-throws",
        "no-sink-builder-mode",
    } <= names
    # Every excluded scenario is a scenario that actually exists, in one plan or the other, so a
    # renamed case cannot leave a stale exclusion silently suppressing a comparison.
    operation_names = {case["name"] for case in operations_plan()["scenarios"]}
    assert DIVERGENT_DROPPED_EVENTS <= (names | operation_names)
    assert DIVERGENT_CAPTURE_STATE <= names
    assert REAL_TIME_OPERATIONS <= operation_names
    # The closed divergence keeps its scenario: exactly one operation case injects a clock and
    # no monotonic source, which is the shape that used to be measured with the wall clock.
    clock_only = {
        case["name"]
        for case in operations_plan()["scenarios"]
        if case["mode"] != "off" and "monotonic_values" not in case
    }
    assert clock_only == REAL_TIME_OPERATIONS
    # Every operation-boundary outcome the helpers can reach has a scenario.
    outcomes = {
        step["outcome"]
        for case in operations_plan()["scenarios"]
        for step in case["operations"]
    }
    assert outcomes == {"success", "failure"}


@needs_node
def test_dropped_events_still_diverges_for_failures_that_lose_no_event(
    matrix_pairs, operation_pairs
):
    """The counter the two emitters once disagreed on, now compared in every scenario."""
    for name in sorted(DIVERGENT_DROPPED_EVENTS):
        pair = matrix_pairs.get(name) or operation_pairs.get(name)
        assert pair is not None, name
        python_case, node_case = pair
        assert python_case["state"]["dropped_events"] == node_case["state"]["dropped_events"], name


@needs_node
def test_a_sinkless_observer_reports_the_same_capture_state_in_both_languages(matrix_pairs):
    """Builder mode is a real use, and an event nobody received is a loss in both languages."""
    python_case, node_case = matrix_pairs["no-sink-builder-mode"]
    # Not in dispute: both build and return every event, and neither writes a line.
    assert python_case["recorded"] == node_case["recorded"] == [True, True, True, True]
    assert python_case["lines"] == node_case["lines"] == []
    assert python_case["state"] == node_case["state"]


@needs_node
def test_both_constructors_refuse_the_same_wiring_mistakes(tmp_path):
    """Wiring is checked once, at construction, so a harness author fixes it before a run.

    These are not events, so they are not part of the emitted-bytes comparison; they are the
    other half of "the two emitters accept and reject the same inputs", applied to the observer
    itself rather than to an event.
    """
    assert python_wiring_results() == node_wiring_results(tmp_path)
    assert python_wiring_results() == {
        "unknown_mode": "refused",
        "sink_without_write": "refused",
        "generator_function_sink": "refused",
    }
