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
same inputs, so the matrix carries every rejection shape the contract names as well as the payload
shapes that could plausibly serialize differently: every event type, all three recording modes, an
explicitly unavailable capture status, integral, non-integral, negative, non-finite, null and
beyond-safe-integer durations, the same shapes again as payload numbers, where the two languages
disagree about a trailing ``.0``, about a negative zero, about an integer past the safe-integer
bound, and about where plain decimal notation ends, a payload nested one container past the shared
depth limit and one exactly at it, an unknown field name, a missing metadata, a metadata that is a
list and one that is a string, a metadata and a content that are objects no payload copy can
read, an empty and a non-string value for every link ID the contract names, a cyclic payload, a
non-finite
number inside a payload, an unpaired surrogate in a payload and in a link ID against an astral
character that is written, credential-like and Unicode payload keys, a redactor that returns a
structurally equal copy of a container, a redactor that returns an equal copy of a scalar, a
redactor that throws, a redactor whose replacement is not JSON, a redactor whose replacement is
one container too deep, a sink that throws an ordinary error, a sink that throws a value that is not
an error, a sink that hands back an iterator nobody drives, an ID factory that throws, an ID
factory that returns a string the wire refuses, a run and producer ID the wire refuses, a clock
that throws, a clock that steps backwards, an emit after close, and an
observer with no sink at all.

The operation-boundary helpers are compared too, not only ``emit``: Python's ``observe_async``
and TypeScript's ``observeAsync`` are driven over the same success, failure and unmeasurable
duration scenarios, with a monotonic source scripted read for read, including every unusable
reading it can produce, one that raises, a NaN, an infinity and a value that is not a number at
all, and their completion events are compared byte for byte. One operation scenario deliberately injects no monotonic source at
all, only a clock, because that is the case in which the two emitters once disagreed: TypeScript
derived elapsed time from an injected ``Clock`` and Python never did. Both now measure with a
real monotonic source, so that scenario's duration is the one value in the whole matrix that is
a property of how fast the test ran, and it is compared as a shape rather than as a value, by
name, in ``REAL_TIME_OPERATIONS``.

What these tests do not prove: that the two emitters share code, that either is correct about a
harness that never emits, or that a trace says anything about a scanner's findings. Two known
representational limits are excluded from the byte comparison rather than hidden: a payload key
that looks like an array index sorts ahead of its siblings in JavaScript only, and a timestamp
cannot carry sub-millisecond precision in either language because the TypeScript ``Clock`` hands
back a ``Date``. Those two are representational limits of the two languages, not defects, and they
are excluded from the byte comparison by name rather than by loosening it. An integral float in a
payload was a third until the emitters stopped leaving it to chance: it is stored as the integer
it equals in both languages now, so the matrix carries it rather than avoiding it. The third
exclusion is not a limit but a measurement: the one operation scenario that injects no monotonic
source has each language time the same trivial operation with its own real one, so that duration
is compared as a shape and blanked before the bytes are. Every behavioral divergence found by
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

import ast
import asyncio
from datetime import datetime, timedelta, timezone
import inspect
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import threading
from types import SimpleNamespace
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
OBSERVER_GUIDE = ROOT / "docs" / "OBSERVER_SDK.md"
TS_SOURCE = ROOT / "sdk/typescript/src/index.ts"

EPOCH = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
EPOCH_MS = int(EPOCH.timestamp() * 1000)
STEP_MS = 10
GAP_MESSAGE = "observer instrumentation failure"
MAX_SAFE_INTEGER = 2**53 - 1
# The lifecycle links the wire contract names, in the order the schema lists them. Checked
# against the schema below, so this cannot drift into a private copy of a shorter list.
LINK_FIELDS = ("parent_event_id", "call_id", "attempt_id", "candidate_id", "claim_id")

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
      /* A lone high surrogate. JSON cannot carry one, so the plan spells it as a marker and
         each language builds its own: one UTF-16 code unit here, one code point in Python. */
      if (value.$special === "surrogate") return "\\uD800";
      /* An object that is not a plain object: a class instance carrying the same field. The
         Python side builds a SimpleNamespace, which is not a Mapping, for the same reason.
         Neither emitter may store either one, in either recording mode. */
      if (value.$special === "exotic_object") {
        class Exotic {
          constructor() {
            this.tool = "grep";
          }
        }
        return new Exotic();
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

/* The Python ``nested_object``, spelled here: a payload of exactly ``containers`` nested
   objects, the payload object itself included. */
function nestedObject(containers) {
  const root = {};
  let inner = root;
  for (let i = 1; i < containers; i += 1) {
    const child = {};
    inner.child = child;
    inner = child;
  }
  inner.leaf = "bottom";
  return root;
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
  // A replacement that is not JSON in either language. A redactor is caller code, so its output
  // is copied and revalidated like any payload, and the event is refused in both.
  non_json: () => () => {},
  // A replacement sitting exactly on the shared nesting limit, which is one container too many
  // where it lands. The budget is per position, so a redactor cannot smuggle depth past it.
  deepens: (key, value) => (key === "smuggled" ? nestedObject(MAX_PAYLOAD_DEPTH) : value),
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
      // A reading that is not a number at all. Both emitters refuse it without calling it, so
      // the span is unmeasurable rather than a duration built from a string.
      if (value === "text") return "100.0";
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
      // A write that hands back an iterator nobody drives writes nothing and reports nothing.
      if (scenario.sink_returns_generator) {
        return (function* () {
          yield event;
        })();
      }
      return jsonl.write(event);
    },
  };
  const clockThrows = new Set(scenario.clock_throws_on ?? []);
  const clockOffsets = scenario.clock_offsets_ms ?? null;
  let reads = 0;
  // Materialized, so a scripted ID can be a string the wire refuses: the marker the plan
  // carries cannot survive a JSON file as a raw code point.
  const supplied = (scenario.id_values ?? []).map(materialize);
  const idThrows = new Set(scenario.id_throws_on ?? []);
  let issued = 0;
  let idCalls = 0;
  const observer = new Observer({
    mode: scenario.mode,
    ...(scenario.no_sink ? {} : { sink }),
    runId: materialize(scenario.run_id ?? undefined),
    producerId: materialize(scenario.producer_id ?? undefined),
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
  for (const [index, input] of (scenario.events ?? []).entries()) {
    // A scenario that closes mid stream: every event after this point is refused and counted
    // as a lost one, because it postdates the run it belongs to.
    if (index === scenario.close_after) await observer.close();
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
            if name == "surrogate":
                return "\ud800"
            if name == "exotic_object":
                # Not a Mapping, and the node driver's analogue is a class instance: an object
                # carrying the same field that neither emitter may read as a payload.
                return SimpleNamespace(tool="grep")
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


def non_json_redactor(key, value, path):
    """Replace every value with something that is not JSON. The event is refused in both."""
    return lambda: None


def deepening_redactor(key, value, path):
    """Replace one named key with a payload that is one container too deep where it lands."""
    return nested_object(MAX_PAYLOAD_DEPTH) if key == "smuggled" else value


# ``default`` is None so each emitter uses its own built-in redactor: that is the thing under
# comparison, and substituting one shared implementation would hide a divergence between them.
REDACTORS = {
    "default": None,
    "equal_copy": equal_copy_redactor,
    "equal_copy_scalar": equal_copy_scalar_redactor,
    "throws": throwing_redactor,
    "non_json": non_json_redactor,
    "deepens": deepening_redactor,
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
    emitter has to refuse, and ``"text"`` returns a reading that is not a number at all, which
    both emitters must refuse without calling it. Nothing here reads a real clock, so a duration
    is a property of the plan rather than of how fast the test ran.

    The return annotation is deliberately wide: a monotonic source is caller code, and the
    unusable readings are exactly what the emitter has to classify rather than trust.
    """
    scripted = list(values)
    reads = 0

    def now() -> Any:
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
        if value == "text":
            return "100.0"
        return float(value)

    return now


def counting_sink(lines: list[str], throws_on=(), kind="error", returns_generator=False):
    """The JSONL sink, wrapped so named write attempts fail. Serialization stays the SDK's.

    ``returns_generator`` makes every write hand back an iterator nobody drives instead of
    writing, which is the wiring mistake no constructor check can see: the line is never
    written, the sink reports no failure, and both emitters must count the event as lost.
    """
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
        if returns_generator:
            return (item for item in (event,))
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
                scenario.get("sink_returns_generator", False),
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
            run_id=materialize(scenario.get("run_id")),
            producer_id=materialize(scenario.get("producer_id")),
            id_factory=id_factory(
                [materialize(value) for value in scenario.get("id_values") or ()],
                scenario.get("id_throws_on", ()),
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
        for index, fields in enumerate(scenario.get("events", [])):
            # A scenario that closes mid stream: every event after this point is refused and
            # counted as a lost one, because it postdates the run it belongs to.
            if index == scenario.get("close_after"):
                observer.close()
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
SURROGATE = {"$special": "surrogate"}
# An object neither emitter may read as a payload: a class instance in JavaScript, a
# SimpleNamespace in Python. Both languages have the same rule, spelled in their own terms, and
# both apply it to metadata and to content in every recording mode.
EXOTIC_OBJECT = {"$special": "exotic_object"}
NAN = {"$special": "nan"}
INFINITY = {"$special": "inf"}
NEGATIVE_INFINITY = {"$special": "-inf"}

# Text that has to escape and encode identically in both languages.
TRICKY_TEXT = (
    'quote " backslash \\ tab \t newline \n accented é kanji 漢 clef 𝄞'
)

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
    # The category a caller may state, agreeing with the type. The contract allows it, derives
    # the stored value from the type anyway, and refuses one that contradicts it; only the
    # contradiction was exercised before.
    event("tool.start", category="tool", call_id="call-6", metadata={"tool": "grep"}),
    # Edge shapes that carry no optional field at all.
    event("tool.start", metadata={}),
    event("model.request", metadata={"empty_list": [], "empty_object": {}}, content={}),
]

# Payload numbers the two languages would write as different bytes, so neither accepts them.
# Each name says which half of the rule refuses it: the safe-integer bound duration_ms already
# carries, or the plain-decimal window below which the two switch to exponent notation at
# different magnitudes and spell an exponent differently.
PAYLOAD_NUMBER_REJECTIONS = {
    "payload_integer_one_past_the_safe_integer_bound": event(
        "tool.start", metadata={"count": 2**53}
    ),
    "payload_integer_far_past_the_safe_integer_bound": event(
        "tool.start", metadata={"count": 10**30}
    ),
    "payload_negative_integer_past_the_safe_integer_bound": event(
        "tool.start", metadata={"count": -(2**53)}
    ),
    "payload_integral_float_past_the_safe_integer_bound": event(
        "tool.start", metadata={"count": 1e16}
    ),
    "payload_number_past_the_safe_integer_bound_in_a_list": event(
        "tool.start", metadata={"counts": [1, 2**53]}
    ),
    "payload_number_past_the_safe_integer_bound_nested": event(
        "tool.start", metadata={"nested": {"count": 2**53}}
    ),
    # Python writes 1e-05 where JavaScript writes 0.00001.
    "payload_float_below_the_plain_decimal_window": event(
        "tool.start", metadata={"ratio": 1e-5}
    ),
    # The double just below the floor: Python writes 9.999999999999999e-05 where JavaScript
    # writes 0.00009999999999999999, so the boundary is tested from beneath as well as on it.
    "payload_float_just_below_the_plain_decimal_window": event(
        "tool.start", metadata={"ratio": 9.999999999999999e-05}
    ),
    # Both use an exponent here and still disagree: Python pads it to two digits, 1e-07, and
    # JavaScript does not, 1e-7.
    "payload_float_with_a_single_digit_exponent": event(
        "tool.start", metadata={"ratio": 1e-7}
    ),
    # Below 1e-9 both languages use a two-digit exponent and write the same bytes, and both
    # refuse these anyway: the accepted range is one window, not two with a hole between them.
    "payload_float_far_below_the_plain_decimal_window": event(
        "tool.start", metadata={"ratio": 1e-10}
    ),
}

# Every input the shared rejection rule refuses. Each is refused by both emitters, and refusing
# one must cost no sequence number, no event ID, and no clock read in either.
REJECTED_EVENTS = {
    "unknown_field_name": event("tool.start", unknown_field=1),
    # A field named for the receiver of the Python method. Python binds arguments before the
    # first statement of ``emit`` runs, so this used to be a TypeError out of the call itself,
    # counted nowhere, while JavaScript refused it as the unknown field name it is. It is an
    # unknown field name in both now.
    "field_named_self": event("tool.start", self="shadowed"),
    "misspelled_field_name": event("tool.start", metdata={"tool": "grep"}),
    "missing_metadata": {"type": "tool.start", "capture_status": "complete"},
    "metadata_is_null": event("tool.start", metadata=None),
    "metadata_is_a_list": event("tool.start", metadata=[{"tool": "grep"}]),
    "metadata_is_a_string": event("tool.start", metadata="tool=grep"),
    "content_is_a_list": event("tool.start", content=["grep"]),
    "content_is_null": event("tool.start", content=None),
    # A payload object neither language can store: what counts as one is a property of the
    # contract, not of the recording mode, so this is refused in metadata mode too. The
    # TypeScript gate once asked only whether the value was a non-array object while its copy
    # applied the real rule, so this shape was accepted in metadata mode and refused in content
    # mode by the same emitter.
    "metadata_is_not_a_payload_object": event("tool.start", metadata=EXOTIC_OBJECT),
    "content_is_not_a_payload_object": event(
        "tool.start", metadata={"tool": "grep"}, content=EXOTIC_OBJECT
    ),
    # Every link field the contract names is validated, not only the two a rejection happened
    # to cover: a field missing from either emitter's list would be a divergent rejection.
    "empty_call_id": event("tool.start", call_id=""),
    "non_string_call_id": event("tool.start", call_id=7),
    "empty_claim_id": event("finding.submitted", claim_id=""),
    "empty_parent_event_id": event("tool.end", parent_event_id=""),
    "empty_attempt_id": event("model.response", attempt_id=""),
    "empty_candidate_id": event("finding.candidate", candidate_id=""),
    "non_string_candidate_id": event("finding.candidate", candidate_id=7),
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
    # A lone surrogate is not a character: Python writes the raw code point, which no UTF-8
    # sink can encode, and JavaScript writes an escaped one, so the same payload meant two
    # things. Refused in both, wherever a caller string reaches the wire.
    "unpaired_surrogate_in_metadata": event("tool.start", metadata={"text": SURROGATE}),
    "unpaired_surrogate_in_a_link_id": event("tool.start", call_id=SURROGATE),
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
    # Folded in rather than kept beside: every count in this file is derived from
    # REJECTED_EVENTS, so a rejection shape that lived in its own dict would be refused by both
    # emitters and counted by none of the assertions.
    **PAYLOAD_NUMBER_REJECTIONS,
}

# Refused in content mode only, because metadata mode never copies content and therefore never
# sees the payload the copy would refuse. Both languages must draw that line in the same place.
CONTENT_ONLY_REJECTIONS = {
    "cyclic_content": event("tool.start", content={"loop": CYCLE}),
    "payload_number_past_the_safe_integer_bound_in_content": event(
        "tool.start", content={"count": 2**53}
    ),
    "payload_float_below_the_plain_decimal_window_in_content": event(
        "tool.start", content={"ratio": 1e-5}
    ),
    "unpaired_surrogate_in_content": event("tool.start", content={"text": SURROGATE}),
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

# One event whose payload the deepening redactor replaces, and one it leaves alone. The
# replacement lands one container past the shared limit, so the first is refused by both
# emitters and the second is recorded by both.
SMUGGLED_PAYLOAD_EVENTS = [
    event("tool.start", metadata={"smuggled": 1}),
    event("tool.start", metadata={"tool": "grep"}),
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

# Payload numbers both languages write as the same bytes, and the two normalizations that make
# that true. An integral float is stored as the integer it equals, because JavaScript has one
# number type and writes 5 where json.dumps writes 5.0, and a negative zero is stored as zero
# for the same reason. Everything else here sits on a boundary: the largest and smallest safe
# integers, the smallest non-integral magnitude both spell in plain decimal notation, and a
# list and a content payload so the rule is shown to apply wherever a number can sit rather
# than only at the top of metadata.
NUMBER_EDGE_EVENTS = [
    event(
        "model.response",
        metadata={
            "ratio": 1.5,
            "small": 0.0001,
            "negative_small": -0.0001,
            "integral_float": 2.0,
            "negative_zero": -0.0,
            "zero": 0,
            "max_safe": MAX_SAFE_INTEGER,
            "min_safe": -MAX_SAFE_INTEGER,
            "large_integral_float": 1.5e15,
        },
        content={"scores": [1.5, 2.0, -0.0, 0.0001], "nested": {"cost": 0.125}},
    ),
    event(
        "model.response",
        metadata={"counts": [0, 1, MAX_SAFE_INTEGER], "deep": {"inner": {"ratio": -2.5}}},
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
        # A redactor whose replacement is not JSON. Its output is caller data, copied and
        # revalidated like any payload, so the event is refused in both languages.
        scenario("non-json-redactor", "content", REDACTOR_PROBE_EVENTS, redactor="non_json"),
        # A redactor whose replacement is one container too deep where it lands. The depth
        # budget is per position in both languages, so the replaced event is refused and the
        # untouched one is recorded.
        scenario(
            "depth-smuggling-redactor",
            "content",
            SMUGGLED_PAYLOAD_EVENTS,
            redactor="deepens",
        ),
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
        # The numbers both languages write alike, including the two a Python emitter has to
        # normalize to write them alike at all. Metadata mode repeats them because it never
        # copies content, so the content numbers are only checked by the content-mode run.
        scenario("payload-numbers", "content", NUMBER_EDGE_EVENTS),
        scenario("payload-numbers-metadata-mode", "metadata", NUMBER_EDGE_EVENTS),
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
        # A sink whose write hands back an iterator nobody drives. No constructor check can see
        # that shape, the line is never written, and the sink reports no failure, so both
        # emitters must count every event it swallowed rather than report clean capture.
        scenario(
            "sink-returns-an-undriven-generator",
            "content",
            DEGRADED_EVENTS,
            sink_returns_generator=True,
        ),
        # An ID factory that hands back strings the wire refuses: a lone surrogate, then an
        # empty one. Both must fall back to the same spelling and mark the events they degraded,
        # rather than one language writing an event ID no UTF-8 sink can encode. The supplied
        # run and producer IDs keep the factory for the event IDs alone.
        scenario(
            "id-factory-returns-unusable-ids",
            "content",
            DEGRADED_EVENTS,
            id_values=[SURROGATE, "", "event-3"],
        ),
        # Run and producer IDs a caller supplied that the wire refuses. Both must ignore them
        # and draw from the factory instead, in the same order, so the event IDs line up.
        {
            "name": "unusable-run-and-producer-ids",
            "mode": "content",
            "run_id": "",
            "producer_id": SURROGATE,
            "events": DEGRADED_EVENTS,
        },
        # A close in the middle of a stream. Every event after it postdates the run it belongs
        # to, so both emitters refuse it and count it as lost.
        scenario("emit-after-close", "content", DEGRADED_EVENTS, close_after=2),
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
            operation_scenario(
                "operation-monotonic-returns-infinity",
                [100.0, "inf"],
                [operation_step("call-infinite", "success")],
            ),
            # A reading that is not a number at all. Checking a reading is as much caller code
            # as taking one, so both emitters classify it rather than convert it, and the span
            # is unmeasurable instead of a duration built from a string.
            operation_scenario(
                "operation-monotonic-returns-a-non-number",
                ["text", 100.25],
                [operation_step("call-not-a-number", "success")],
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
    assert written >= 248
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
    # A sink that hands back an iterator writes nothing, and the event is still built in both.
    assert all(by_name["sink-returns-an-undriven-generator"])
    # A redactor whose replacement is not JSON refuses the event in both; one that replaces a
    # named key with a too-deep payload refuses that event and records the one it left alone.
    assert not any(by_name["non-json-redactor"])
    assert by_name["depth-smuggling-redactor"] == [False, True]
    # A close in the middle of the stream: the events after it are refused by both.
    assert by_name["emit-after-close"] == [True, True, False, False]


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
    assert by_name["non-json-redactor"] == {
        "dropped_events": len(REDACTOR_PROBE_EVENTS),
        "capture_gap": True,
        "last_sink_error": GAP_MESSAGE,
    }
    # Every event the undriven-generator sink swallowed is a lost event, not clean capture.
    assert by_name["sink-returns-an-undriven-generator"] == {
        "dropped_events": len(DEGRADED_EVENTS),
        "capture_gap": True,
        "last_sink_error": GAP_MESSAGE,
    }
    # Two events arrived after the close, and each is one lost event in both languages.
    assert by_name["emit-after-close"] == {
        "dropped_events": 2,
        "capture_gap": True,
        "last_sink_error": GAP_MESSAGE,
    }
    # A run or producer ID the wire refuses costs nothing at all: it is not used, and the
    # factory supplies the IDs instead, so there is no event to lose and nothing to degrade.
    assert by_name["unusable-run-and-producer-ids"] == clean


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


def test_two_threads_sharing_one_python_observer_lose_the_ordering_the_contract_promises():
    """The Python class is not thread safe, and this is what that costs. See the guide.

    ``Observer.emit`` reads ``self._sequence`` into the event it is building, calls the clock and
    the ID factory, and increments afterwards. The read and the increment are separate bytecode
    with caller code between them, so two threads inside that window both take the same number.
    Nothing here is a race the test hopes to win: the injected clock waits on a barrier, so every
    thread is provably inside the window before any of them leaves it.

    The damage is the quiet kind. Four events are written, four lines land in the sink, and the
    capture state reports no gap and no dropped event, because nothing was lost; what is gone is
    ``sequence``, which the contract makes the only ordering a reader may rely on. The
    TypeScript emitter cannot reach this state: its build runs to completion inside one
    synchronous stretch before the first ``await``, and JavaScript gives it no second caller to
    interleave with.

    A harness that emits from more than one thread needs one observer per thread, each with its
    own ``producer_id``, or its own lock around ``emit``. Neither emitter provides one.
    """
    threads = 4
    at_the_window = threading.Barrier(threads)

    def barrier_clock():
        # Called after the sequence number has been read and before it has been incremented.
        at_the_window.wait(timeout=30)
        return EPOCH

    written: list[dict] = []
    guard = threading.Lock()

    def sink(event: dict) -> None:
        with guard:
            written.append(event)

    observer = Observer(
        mode="metadata",
        sink=sink,
        run_id="run-1",
        producer_id="producer-1",
        clock=barrier_clock,
        id_factory=id_factory(None),
    )

    def emit_one(index: int) -> None:
        observer.emit(
            type="tool.start", capture_status="complete", metadata={"thread": index}
        )

    workers = [threading.Thread(target=emit_one, args=(index,)) for index in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=30)
    assert not any(worker.is_alive() for worker in workers), "an emit never returned"

    assert len(written) == threads, "every event was built and delivered"
    assert [event["sequence"] for event in written] == [0] * threads, (
        "one sequence number for four events: the counter is read and incremented without a lock"
    )
    assert sorted(event["metadata"]["thread"] for event in written) == list(range(threads))
    # The ID factory's own counter is read and written the same unlocked way, so whether the
    # four IDs come out distinct is not something this can assert either way. That is the same
    # defect one field along, and it is why the guide says one observer per thread rather than
    # naming the fields that survive.
    # And nothing in the record says the ordering is gone, which is the point.
    assert observer.get_state() == CaptureState()
    observer.close()


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
def test_both_emitters_write_one_spelling_for_every_payload_number_they_accept(matrix_pairs):
    """A number either language accepts is a number both write as the same bytes.

    Two of them need a normalization to be true at all, and both are Python's, because
    JavaScript has one number type: an integral float is stored as the integer it equals, so
    ``2.0`` is written ``2`` and not ``2.0``, and a negative zero is stored as zero, which is
    what ``JSON.stringify`` writes for it. Neither changes the value, only which of two
    spellings of it reaches the wire. The rest of the matrix sits on the boundaries: the
    largest and smallest safe integers, and the smallest non-integral magnitude both languages
    spell in plain decimal notation.
    """
    for name in ("payload-numbers", "payload-numbers-metadata-mode"):
        python_case, node_case = matrix_pairs[name]
        assert python_case["lines"] == node_case["lines"], name
        assert python_case["recorded"] == node_case["recorded"] == [True, True], name
        assert python_case["state"] == node_case["state"], name

    python_case, _ = matrix_pairs["payload-numbers"]
    first, second = parsed(python_case["lines"])
    assert first["metadata"] == {
        "ratio": 1.5,
        "small": 0.0001,
        "negative_small": -0.0001,
        "integral_float": 2,
        "negative_zero": 0,
        "zero": 0,
        "max_safe": MAX_SAFE_INTEGER,
        "min_safe": -MAX_SAFE_INTEGER,
        "large_integral_float": 1500000000000000,
    }
    assert first["content"] == {"scores": [1.5, 2, 0, 0.0001], "nested": {"cost": 0.125}}
    assert second["metadata"]["deep"] == {"inner": {"ratio": -2.5}}
    # The bytes, not only the parsed values: a trailing ".0" or a "-0" is exactly what the two
    # languages would otherwise disagree about, and it would survive a parsed comparison.
    line = python_case["lines"][0]
    assert '"integral_float":2,' in line
    assert '"negative_zero":0,' in line
    assert '"ratio":1.5' in line and '"small":0.0001' in line
    assert '"scores":[1.5,2,0,0.0001]' in line
    assert ".0," not in line and "-0," not in line and "e-" not in line
    # Nothing was lost to get there: an accepted number is stored, never dropped or reshaped.
    assert python_case["state"] == {
        "dropped_events": 0,
        "capture_gap": False,
        "last_sink_error": None,
    }


@needs_node
def test_both_emitters_refuse_the_payload_numbers_they_would_spell_differently(matrix_pairs):
    """A payload number outside the shared range is a capture gap in both, never a rounded value.

    Two bounds, both shared. An integral number past ``2 ** 53 - 1`` is refused because a JSON
    number stops distinguishing neighbouring integers there, so Python could write a count a
    JavaScript reader would read as a different one: the bound ``duration_ms`` already carries,
    applied to the numbers a caller puts in a payload. A non-integral number below 1e-4 is
    refused because the two languages leave plain decimal notation at different magnitudes and
    spell an exponent differently, so one payload would leave the two emitters as different
    bytes. ``payload_float_far_below_the_plain_decimal_window`` is the deliberate over-refusal:
    below 1e-9 both languages use a two-digit exponent and write the same bytes, and both refuse
    it anyway, so the accepted range is one window rather than two with a hole between them.
    """
    python_case, node_case = matrix_pairs["rejected-inputs-only"]
    refusals = list({**REJECTED_EVENTS, **CONTENT_ONLY_REJECTIONS})
    names = (
        *PAYLOAD_NUMBER_REJECTIONS,
        "payload_number_past_the_safe_integer_bound_in_content",
        "payload_float_below_the_plain_decimal_window_in_content",
    )
    for name in names:
        index = refusals.index(name)
        assert python_case["recorded"][index] is False, name
        assert node_case["recorded"][index] is False, name
    # Refusing costs nothing but the event: no line, and the same sequence numbers on both
    # sides, which is the whole reason the rejection set has to be identical.
    assert python_case["lines"] == node_case["lines"] == []
    assert python_case["sequences"] == node_case["sequences"]

    # Content is copied, and therefore number checked, only in content mode, exactly as the
    # depth and surrogate rules are. Both emitters draw that line in the same place.
    metadata_mode = matrix_pairs["rejections-interleaved-metadata"][0]["recorded"][::2]
    node_metadata_mode = matrix_pairs["rejections-interleaved-metadata"][1]["recorded"][::2]
    interleaved = list({**REJECTED_EVENTS, **CONTENT_ONLY_REJECTIONS})
    in_content = interleaved.index("payload_number_past_the_safe_integer_bound_in_content")
    in_metadata = interleaved.index("payload_integer_one_past_the_safe_integer_bound")
    assert metadata_mode[in_content] is node_metadata_mode[in_content] is True
    assert metadata_mode[in_metadata] is node_metadata_mode[in_metadata] is False


@needs_node
def test_a_field_named_for_the_python_receiver_is_refused_and_counted_in_both(matrix_pairs):
    """``emit(self=...)`` is an unknown field name, not a TypeError out of the call itself.

    Python binds arguments before the first statement of a method runs, so a caller field named
    ``self`` raised from the call rather than from anything inside it: the one field name the
    contract happens to share with the receiver escaped into the harness and was counted
    nowhere, while the TypeScript emitter refused the same key as the unknown field name it is.
    The receiver is positional only now, so the two rejection sets cover this name as they cover
    ``metdata``.
    """
    python_case, node_case = matrix_pairs["rejected-inputs-only"]
    refusals = list({**REJECTED_EVENTS, **CONTENT_ONLY_REJECTIONS})
    index = refusals.index("field_named_self")
    assert python_case["recorded"][index] is False
    assert node_case["recorded"][index] is False
    assert python_case["state"]["dropped_events"] == node_case["state"]["dropped_events"]


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
    # The link list this file checks against is the schema's own: every declared property that
    # is optional and is not a payload or a duration. A link added to the contract and not to
    # LINK_FIELDS fails here rather than going untested.
    schema = json.loads((ROOT / "schema/v2/trace-event.schema.json").read_text())
    optional = [name for name in schema["properties"] if name not in schema["required"]]
    assert [name for name in optional if name not in ("duration_ms", "content")] == list(
        LINK_FIELDS
    )
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
        "unpaired_surrogate_in_metadata",
        "unpaired_surrogate_in_a_link_id",
        "non_finite_number_in_metadata",
        "metadata_nested_past_the_depth_limit",
        "metadata_lists_nested_past_the_depth_limit",
        "field_named_self",
        # A payload object neither language can store, refused in every mode by both: what a
        # payload object is belongs to the contract, not to the recording mode.
        "metadata_is_not_a_payload_object",
        "content_is_not_a_payload_object",
    }
    assert required_rejections <= set(REJECTED_EVENTS)
    # Every field a caller may supply is exercised, and every one of them is accepted somewhere
    # as well as refused somewhere, so a field the matrix only ever refuses cannot hide a
    # divergence in how the two emitters store it.
    supplied = {
        name for case in plan["scenarios"] for fields in case["events"] for name in fields
    }
    declared_input_fields = {
        "type",
        "category",
        "capture_status",
        "metadata",
        "content",
        "duration_ms",
        *LINK_FIELDS,
    }
    assert declared_input_fields <= supplied
    assert declared_input_fields <= {name for fields in ACCEPTED_EVENTS for name in fields}
    # Each link field is refused somewhere too: they share one rule, and a field left out of
    # one emitter's list would be a divergent rejection nothing else in the matrix would see.
    refused_links = {
        name for fields in REJECTED_EVENTS.values() for name in fields if name in LINK_FIELDS
    }
    assert refused_links == set(LINK_FIELDS)
    # Every payload-number shape the rule names, on both sides of both bounds.
    assert set(PAYLOAD_NUMBER_REJECTIONS) <= set(REJECTED_EVENTS)
    assert {
        "payload_integer_one_past_the_safe_integer_bound",
        "payload_integral_float_past_the_safe_integer_bound",
        "payload_float_below_the_plain_decimal_window",
        "payload_float_with_a_single_digit_exponent",
    } <= set(PAYLOAD_NUMBER_REJECTIONS)
    assert {
        "payload_number_past_the_safe_integer_bound_in_content",
        "payload_float_below_the_plain_decimal_window_in_content",
    } <= set(CONTENT_ONLY_REJECTIONS)
    # The accepted side of the same rule: the bounds themselves, and the two spellings Python
    # has to normalize to write what JavaScript writes.
    numbers = [value for fields in NUMBER_EDGE_EVENTS for value in fields["metadata"].values()]
    assert MAX_SAFE_INTEGER in numbers and -MAX_SAFE_INTEGER in numbers
    assert 0.0001 in numbers
    assert any(isinstance(value, float) and value.is_integer() for value in numbers)
    assert any(
        isinstance(value, float) and math.copysign(1.0, value) < 0 and value == 0
        for value in numbers
    )
    assert {
        "cyclic_content",
        "non_finite_number_in_content",
        "unpaired_surrogate_in_content",
        "content_nested_past_the_depth_limit",
    } <= set(CONTENT_ONLY_REJECTIONS)
    # The control for that rejection: a real astral character is written by both, so the rule
    # refuses what no sink can encode rather than everything outside the basic plane.
    assert "\U0001d11e" in TRICKY_TEXT
    assert any(
        "\U0001d11e" in json.dumps(fields, ensure_ascii=False) for fields in ACCEPTED_EVENTS
    )
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
        "sink-returns-an-undriven-generator",
        "throwing-redactor",
        "non-json-redactor",
        "depth-smuggling-redactor",
        "equal-copy-redactor",
        "equal-copy-scalar-redactor",
        "clock-throws",
        "clock-steps-backwards",
        "id-factory-throws",
        "id-factory-returns-unusable-ids",
        "unusable-run-and-producer-ids",
        "no-sink-builder-mode",
        "emit-after-close",
    } <= names
    # Every public constructor option is driven by some scenario, and a plan key is what drives
    # it. An option with no key here is one the matrix never varies, which is the gap this
    # assertion exists to make loud.
    plan_keys = {key for case in plan["scenarios"] for key in case}
    assert {
        "mode",
        "run_id",
        "producer_id",
        "redactor",
        "no_sink",
        "sink_throws_on",
        "sink_throw_kind",
        "sink_returns_generator",
        "clock_throws_on",
        "clock_offsets_ms",
        "id_values",
        "id_throws_on",
        "close_after",
    } <= plan_keys
    # Every redactor the file defines is used by a scenario, so adding one without driving it
    # fails here rather than sitting unused.
    assert {case.get("redactor", "default") for case in plan["scenarios"]} == set(REDACTORS)
    # The elapsed-time source is the one option only the operation plan can drive, and every
    # unusable reading it can produce is scripted by some scenario.
    operation_plan = operations_plan()
    readings = {
        value
        for case in operation_plan["scenarios"]
        for value in case.get("monotonic_values", ())
        if isinstance(value, str)
    }
    assert readings == {"throw", "nan", "inf", "text"}
    # Every excluded scenario is a scenario that actually exists, in one plan or the other, so a
    # renamed case cannot leave a stale exclusion silently suppressing a comparison.
    operation_names = {case["name"] for case in operation_plan["scenarios"]}
    assert DIVERGENT_DROPPED_EVENTS <= (names | operation_names)
    assert DIVERGENT_CAPTURE_STATE <= names
    assert REAL_TIME_OPERATIONS <= operation_names
    # The closed divergence keeps its scenario: exactly one operation case injects a clock and
    # no monotonic source, which is the shape that used to be measured with the wall clock.
    clock_only = {
        case["name"]
        for case in operation_plan["scenarios"]
        if case["mode"] != "off" and "monotonic_values" not in case
    }
    assert clock_only == REAL_TIME_OPERATIONS
    # Every operation-boundary outcome the helpers can reach has a scenario.
    outcomes = {
        step["outcome"]
        for case in operation_plan["scenarios"]
        for step in case["operations"]
    }
    assert outcomes == {"success", "failure"}


@needs_node
def test_no_scenario_is_excluded_from_the_dropped_events_comparison(
    matrix_pairs, operation_pairs
):
    """The counter the two emitters once disagreed on, compared in every scenario there is.

    This test was ``test_dropped_events_still_diverges_for_failures_that_lose_no_event``, and it
    looped over ``DIVERGENT_DROPPED_EVENTS`` asserting that the excluded scenarios agreed. The
    set went empty when that divergence was closed, so the loop body stopped running: the test
    could not fail, and it went on reading as coverage of the very counter it no longer touched.
    A review found it, and this is the replacement rather than a deletion, because the claim
    behind the empty set is worth asserting and nothing else asserted it directly.

    What the empty set means is that the two comparisons that consult it,
    :func:`test_both_emitters_report_the_same_capture_state_for_every_matrix_case` and
    :func:`test_the_operation_boundary_helpers_agree_across_languages`,
    suppress nothing. That is a claim about coverage, so it is asserted over the scenarios
    themselves: every case in both plans, with a guard so an empty plan fails here rather than
    passing on no evidence. Writing a name back into the exclusion set now fails this test, which
    is what the set was always supposed to cost.
    """
    assert DIVERGENT_DROPPED_EVENTS == frozenset(), sorted(DIVERGENT_DROPPED_EVENTS)
    assert DIVERGENT_CAPTURE_STATE == frozenset(), sorted(DIVERGENT_CAPTURE_STATE)

    pairs = {**matrix_pairs, **operation_pairs}
    assert len(pairs) == len(matrix_pairs) + len(operation_pairs), "a scenario name is in both plans"
    assert len(pairs) > 30, f"only {len(pairs)} scenarios: the plans did not run"
    for name, (python_case, node_case) in sorted(pairs.items()):
        assert python_case["state"]["dropped_events"] == node_case["state"]["dropped_events"], name


@needs_node
def test_an_unusable_id_from_a_factory_is_refused_by_both_and_never_written(matrix_pairs):
    """Every caller string on the wire passes one validator, wherever the string came from.

    The TypeScript ``nextId`` checked a factory-produced ID with a local type-and-length test
    instead of the shared ``validId``, so an ID carrying an unpaired surrogate went straight
    onto the wire while Python's ``_next_id`` refused the same value through ``_is_id`` and fell
    back. One event, two event IDs, and a line no UTF-8 sink could have written in one of the
    two languages. Both refuse it now, and the fallback spelling is the same, so the streams
    stay aligned: a degraded ID is a capture gap on a delivered event, never a lost one, and the
    events after it keep the factory's own numbering.

    The same rule covers the run and producer IDs a caller supplies, which the second scenario
    here hands over as an empty string and as a lone surrogate: both are ignored in both
    languages and the factory is asked instead, in the same order.
    """
    python_case, node_case = matrix_pairs["id-factory-returns-unusable-ids"]
    assert python_case["lines"] == node_case["lines"]
    assert python_case["event_ids"] == node_case["event_ids"]
    assert python_case["event_ids"] == [
        "event-fallback-1",
        "event-fallback-2",
        "event-3",
        "event-1",
    ]
    for line in parsed(python_case["lines"]):
        assert line["event_id"].encode("utf-8").decode("utf-8") == line["event_id"]
    # The two refused IDs degraded their events without losing them: marked, downgraded, kept.
    marked = parsed(python_case["lines"])[:2]
    assert [line["capture_status"] for line in marked] == ["partial", "partial"]
    assert all(line["metadata"]["observer_capture_gap"] is True for line in marked)
    assert python_case["state"] == node_case["state"]
    assert python_case["state"]["dropped_events"] == 0
    assert python_case["state"]["capture_gap"] is True

    supplied = matrix_pairs["unusable-run-and-producer-ids"]
    assert supplied[0]["run_id"] == supplied[1]["run_id"] == "run-1"
    assert supplied[0]["producer_id"] == supplied[1]["producer_id"] == "producer-2"


@needs_node
def test_a_payload_that_is_not_a_storable_object_is_refused_in_every_mode(matrix_pairs):
    """What a payload object is belongs to the contract, not to the recording mode.

    The TypeScript gate asked only whether ``content`` was a non-array object while the copy
    applied the plain-object rule, so an object built on some other prototype was accepted in
    ``metadata`` mode, where content is never copied, and refused in ``content`` mode by the
    same emitter. Python refused it in both, because one predicate answered for both paths
    there. Both emitters now ask one predicate as well, so the mode decides whether content is
    stored and never what a caller may hand over.

    What is inside a stored payload is the separate rule, and it still belongs to the copy:
    the ``CONTENT_ONLY_REJECTIONS`` are accepted in ``metadata`` mode by both emitters.
    """
    refusals = list({**REJECTED_EVENTS, **CONTENT_ONLY_REJECTIONS})
    shapes = ["metadata_is_not_a_payload_object", "content_is_not_a_payload_object"]
    for mode in ("metadata", "content"):
        python_case, node_case = matrix_pairs[f"rejections-interleaved-{mode}"]
        assert python_case["recorded"] == node_case["recorded"]
        for name in shapes:
            # The interleaved stream is a refusal followed by an accepted event, so the input
            # at twice the index is the refusal itself.
            index = refusals.index(name) * 2
            assert python_case["recorded"][index] is False, (mode, name)
            assert node_case["recorded"][index] is False, (mode, name)


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


def guide_code_block(section_title: str, language: str, containing: str) -> str:
    """One fenced ``language`` block under one ``##`` heading of the SDK guide.

    The block is chosen by a string it contains rather than by position, so inserting another
    block into that section ahead of it fails nothing and renaming the thing it documents fails
    here instead of silently checking a different block.
    """
    lines = OBSERVER_GUIDE.read_text(encoding="utf-8").splitlines()
    headings = [index for index, line in enumerate(lines) if line.startswith("## ")]
    span: list[str] | None = None
    for position, start in enumerate(headings):
        if lines[start][3:].strip() == section_title:
            end = headings[position + 1] if position + 1 < len(headings) else len(lines)
            span = lines[start:end]
            break
    assert span is not None, f"{OBSERVER_GUIDE} has no section titled {section_title!r}"
    blocks: list[list[str]] = []
    inside = False
    for line in span:
        if line.startswith("```"):
            inside = line.strip() == f"```{language}"
            if inside:
                blocks.append([])
            continue
        if inside:
            blocks[-1].append(line)
    matching = ["\n".join(block) for block in blocks if containing in "\n".join(block)]
    assert len(matching) == 1, (
        f"{len(matching)} {language} blocks under {section_title!r} contain {containing!r}"
    )
    return matching[0]


def documented_keyword_options(block: str) -> dict[str, object]:
    """``{name: default}`` for the keyword-only parameters of ``__init__`` in a guide block.

    Parsed with :mod:`ast` rather than by regular expression, because what this compares against
    is a real signature and the two have to be read the same way. The guide writes the body as
    ``...``, which is valid Python, so the block parses as it stands.
    """
    tree = ast.parse(block)
    initializers = [
        node
        for classdef in tree.body
        if isinstance(classdef, ast.ClassDef)
        for node in classdef.body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    ]
    assert len(initializers) == 1, "the guide block no longer documents one __init__"
    signature = initializers[0].args
    assert [argument.arg for argument in signature.args] == ["self"], (
        "the guide documents a positional parameter besides the receiver"
    )
    assert not signature.posonlyargs and signature.vararg is None and signature.kwarg is None
    assert len(signature.kwonlyargs) == len(signature.kw_defaults)
    options: dict[str, object] = {}
    for argument, default in zip(signature.kwonlyargs, signature.kw_defaults):
        assert default is not None, f"{argument.arg} is documented without a default"
        options[argument.arg] = ast.literal_eval(default)
    return options


def ts_interface_body(text: str, name: str) -> list[str]:
    """The declaration lines of ``export interface <name> { ... }``, comments and blanks dropped."""
    match = re.search(rf"^export interface {name} \{{(.*?)^\}}", text, re.M | re.S)
    assert match, f"no exported interface named {name}"
    body = []
    for line in match.group(1).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        # Drop a trailing line comment so a note beside a field is not a difference.
        body.append(" ".join(stripped.split("//")[0].split()))
    return body


def test_the_constructor_options_the_guide_documents_are_the_ones_the_code_takes():
    """Both option lists, read out of this guide and compared with the code that takes them.

    The guide's "what this document checks about itself" section separates what a test reads out
    of the file from what is prose, and both API sections carry an "everything below is exported"
    promise that is checked. A review pointed out that the constructor option lists sat inside
    those checked-looking blocks while nothing read them: the Python export check skips every
    indented line, so the ``__init__`` parameters are not in it, and the TypeScript export check
    compares interface *names* and only ``CaptureState``'s fields, so ``ObserverOptions`` was a
    name with an unchecked body under it. An option renamed, removed, or given a different
    default in either language would have left the guide telling a harness author to pass
    something the constructor does not take.

    Both halves are read out of the document rather than stated here, so this cannot drift into
    a third copy of the same list: the Python parameters and their defaults are parsed from the
    guide's own code block and compared with :func:`inspect.signature`, and the TypeScript
    ``ObserverOptions`` body is compared line for line with the one in the SDK source. Neither
    half needs node or a build.
    """
    documented = documented_keyword_options(
        guide_code_block("Python API", "python", "class Observer:")
    )
    signature = inspect.signature(Observer.__init__)
    parameters = list(signature.parameters.values())
    assert parameters[0].name == "self"
    actual = {
        parameter.name: parameter.default
        for parameter in parameters[1:]
        if parameter.kind is inspect.Parameter.KEYWORD_ONLY
    }
    assert len(actual) == len(parameters) - 1, "the constructor takes something that is not keyword only"
    assert documented == actual, "the guide's Python constructor block is not the signature"
    assert documented, "the guide documents no constructor option at all"

    # The TypeScript half: one options interface, compared with the SDK source line for line.
    guide_interface = ts_interface_body(
        guide_code_block("TypeScript API", "ts", "export interface ObserverOptions"),
        "ObserverOptions",
    )
    source_interface = ts_interface_body(TS_SOURCE.read_text(encoding="utf-8"), "ObserverOptions")
    assert guide_interface == source_interface
    assert len(guide_interface) == len(documented), (
        "the two languages document a different number of constructor options"
    )
