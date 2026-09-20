"""Cross-language parity: the Python emitter and the TypeScript SDK must record the same events.

The wire contract is one document, ``schema/v2/trace-event.schema.json``, so a trace has to mean
the same thing whichever language wrote it. These tests run both emitters over one matrix of
inputs with the same injected clock, the same injected ID factory, the same sink, and the same
redactor, and compare four things for every case:

* the JSONL each emitter wrote, byte for byte, key order included;
* whether each input was recorded at all, so a divergent rejection is visible on the input that
  caused it rather than only in the wreckage after it;
* the sequence number and event ID of every recorded event, so a rejection that consumes a
  sequence number in one language and not the other desynchronizes the streams and fails loudly;
* the final capture state field for field: ``dropped_events``, ``capture_gap``, and
  ``last_sink_error``.

The matrix is the point of this file. A rejected event consumes no sequence number, no event ID,
and no clock read in either language, which is only safe while both languages refuse exactly the
same inputs, so the matrix carries every rejection shape the contract names as well as the
payload shapes that could plausibly serialize differently: every event type, all three recording
modes, an explicitly unavailable capture status, integral, non-integral, negative, non-finite and
null durations, an unknown field name, a missing metadata, a metadata that is a list and one that
is a string, an empty and a non-string link ID, a cyclic payload, a non-finite number inside a
payload, credential-like and Unicode payload keys, a redactor that returns a structurally equal
copy, a redactor that throws, a sink that throws, and a clock that throws.

What these tests do not prove: that the two emitters share code, that either is correct about a
harness that never emits, or that a trace says anything about a scanner's findings. Two known
representational limits are excluded from the byte comparison rather than hidden: an integral
float in a payload writes as ``1.0`` from Python and ``1`` from JavaScript, and a payload key
that looks like an array index sorts ahead of its siblings in JavaScript only. Both are recorded
in ``docs/OBSERVER_SDK.md``; neither is reachable from the emitters' own fields.

Nothing here calls a model, reaches the network, sleeps, or reads a real clock. The TypeScript
side is a throwaway driver written into ``tmp_path`` and run under node against the SDK's build
output, which is gitignored and therefore local. The tests skip with a reason when node or that
build is absent rather than pretend parity was checked.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from scaneval.observer import (
    CAPTURE_STATUSES,
    CaptureState,
    EVENT_TYPES,
    Observer,
    RECORDING_MODES,
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

needs_node = pytest.mark.skipif(
    NODE is None or not SDK_BUILD.exists(),
    reason=(
        "cross-language parity needs node and a built TypeScript SDK; sdk/typescript/dist is "
        "gitignored, so run npm --prefix sdk/typescript run build and install node to check it"
    ),
)

# The driver is written into tmp_path per test rather than committed: it is a test harness for
# the SDK, not part of it, and nothing outside these tests should import it. It mirrors the
# Python runner below call for call, because a driver that wired the two emitters differently
# would compare the harness rather than the emitters.
DRIVER = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [, , planPath, sdkPath] = process.argv;
const { Observer, createJsonlSink } = await import(pathToFileURL(sdkPath).href);
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
  // Hands back a structurally equal copy. Redaction is decided by reference identity, so this
  // must count as a replacement in both languages.
  equal_copy: (key, value) =>
    Array.isArray(value)
      ? value.slice()
      : (value !== null && typeof value === "object" ? { ...value } : value),
  throws: () => {
    throw new Error("redactor unavailable");
  },
};

const results = [];
for (const scenario of plan.scenarios) {
  const lines = [];
  const jsonl = createJsonlSink((line) => {
    lines.push(line);
  });
  const sinkThrows = new Set(scenario.sink_throws_on ?? []);
  let writes = 0;
  const sink = {
    write(event) {
      const index = writes++;
      if (sinkThrows.has(index)) throw new Error("sink unavailable");
      return jsonl.write(event);
    },
  };
  const clockThrows = new Set(scenario.clock_throws_on ?? []);
  let reads = 0;
  const supplied = (scenario.id_values ?? []).slice();
  let issued = 0;
  const observer = new Observer({
    mode: scenario.mode,
    sink,
    runId: scenario.run_id ?? undefined,
    producerId: scenario.producer_id ?? undefined,
    idFactory: {
      next: (prefix) => supplied.length > 0 ? supplied.shift() : `${prefix}-${++issued}`,
    },
    clock: {
      now: () => {
        const index = reads++;
        if (clockThrows.has(index)) throw new Error("clock unavailable");
        return new Date(plan.epoch_ms + plan.step_ms * index);
      },
    },
    redactor: redactors[scenario.redactor ?? "default"],
  });
  const recorded = [];
  const eventIds = [];
  const sequences = [];
  for (const input of scenario.events) {
    const emitted = await observer.emit(materialize(input));
    recorded.push(emitted !== undefined);
    eventIds.push(emitted === undefined ? null : emitted.event_id);
    sequences.push(emitted === undefined ? null : emitted.sequence);
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
    state: observer.getState(),
    clock_reads: reads,
  });
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


def throwing_redactor(key, value, path):
    raise RuntimeError("redactor unavailable")


# ``default`` is None so each emitter uses its own built-in redactor: that is the thing under
# comparison, and substituting one shared implementation would hide a divergence between them.
REDACTORS = {"default": None, "equal_copy": equal_copy_redactor, "throws": throwing_redactor}


def id_factory(supplied: list[str] | None):
    """Pop caller-supplied IDs first, then count. The same rule the node driver applies."""
    remaining = list(supplied or [])
    issued = 0

    def next_id(prefix: str) -> str:
        nonlocal issued
        if remaining:
            return remaining.pop(0)
        issued += 1
        return f"{prefix}-{issued}"

    return next_id


def fixed_clock(epoch_ms: int, step_ms: int, throws_on=()):
    """A clock that advances a fixed step per read, matching the node driver's arithmetic.

    A read listed in ``throws_on`` raises after taking its turn, so a throwing read costs the
    same tick in both languages and a later timestamp still says which read produced it.
    """
    throwing = set(throws_on)
    reads = 0

    def now() -> datetime:
        nonlocal reads
        index = reads
        reads += 1
        if index in throwing:
            raise RuntimeError("clock unavailable")
        return datetime.fromtimestamp(epoch_ms / 1000, timezone.utc) + timedelta(
            milliseconds=step_ms * index
        )

    return now


def counting_sink(lines: list[str], throws_on=()):
    """The JSONL sink, wrapped so named write attempts fail. Serialization stays the SDK's."""
    throwing = set(throws_on)
    jsonl = create_jsonl_sink(lines.append)
    writes = 0

    def write(event):
        nonlocal writes
        index = writes
        writes += 1
        if index in throwing:
            raise RuntimeError("sink unavailable")
        return jsonl.write(event)

    return write


def python_results(plan: dict) -> list[dict]:
    """Run every scenario through the Python emitter and report what the driver reports."""
    results: list[dict] = []
    for scenario in plan["scenarios"]:
        lines: list[str] = []
        observer = Observer(
            mode=scenario["mode"],
            sink=counting_sink(lines, scenario.get("sink_throws_on", ())),
            run_id=scenario.get("run_id"),
            producer_id=scenario.get("producer_id"),
            id_factory=id_factory(scenario.get("id_values")),
            clock=fixed_clock(
                plan["epoch_ms"], plan["step_ms"], scenario.get("clock_throws_on", ())
            ),
            redactor=REDACTORS[scenario.get("redactor", "default")],
        )
        recorded: list[bool] = []
        event_ids: list[str | None] = []
        sequences: list[int | None] = []
        for fields in scenario["events"]:
            emitted = observer.emit(**materialize(fields))
            recorded.append(emitted is not None)
            event_ids.append(None if emitted is None else emitted["event_id"])
            sequences.append(None if emitted is None else emitted["sequence"])
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
                "state": {
                    "dropped_events": state.dropped_events,
                    "capture_gap": state.capture_gap,
                    "last_sink_error": state.last_sink_error,
                },
            }
        )
    return results


def node_results(tmp_path: Path, plan: dict) -> list[dict]:
    """Run the same scenarios through the built TypeScript SDK under node."""
    driver = tmp_path / "parity_driver.mjs"
    driver.write_text(DRIVER)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, ensure_ascii=False))
    completed = subprocess.run(
        [NODE, str(driver), str(plan_path), str(SDK_BUILD)],
        capture_output=True,
        cwd=str(ROOT),
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    return json.loads(completed.stdout.decode("utf-8"))


def both(tmp_path: Path, plan: dict):
    """Run one plan through both emitters and pair the scenarios up by name."""
    from_python = python_results(plan)
    from_node = node_results(tmp_path, plan)
    assert [case["name"] for case in from_python] == [case["name"] for case in from_node]
    return list(zip(from_python, from_node))


def parsed(lines: list[str]) -> list[dict]:
    return [json.loads(line) for line in lines]


def iso_timestamp(read_index: int) -> str:
    """The timestamp the injected clock produces on its nth read, spelled as the wire spells it."""
    moment = EPOCH + timedelta(milliseconds=STEP_MS * read_index)
    return f"{moment.strftime('%Y-%m-%dT%H:%M:%S')}.{moment.microsecond // 1000:03d}Z"


def event(event_type: str, **extra) -> dict:
    fields = {"type": event_type, "capture_status": "complete", "metadata": {"stage": event_type}}
    fields.update(extra)
    return fields


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
}

# Refused in content mode only, because metadata mode never copies content and therefore never
# sees the payload the copy would refuse. Both languages must draw that line in the same place.
CONTENT_ONLY_REJECTIONS = {
    "cyclic_content": event("tool.start", content={"loop": CYCLE}),
    "non_finite_number_in_content": event("tool.start", content={"score": INFINITY}),
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
        # Metadata mode accepts the two content-only rejections, because it never copies content.
        # Both languages have to accept them, and to accept exactly the same ones.
        scenario("rejections-interleaved-metadata", "metadata", interleaved(all_rejections)),
        scenario("redaction-key-names", "content", REDACTION_EVENTS),
        scenario("equal-copy-redactor", "content", REDACTOR_PROBE_EVENTS, redactor="equal_copy"),
        scenario("throwing-redactor", "content", REDACTOR_PROBE_EVENTS, redactor="throws"),
        scenario("sink-throws", "content", ACCEPTED_EVENTS, sink_throws_on=[0, 3, 4]),
        scenario("payload-edges", "content", PAYLOAD_EDGE_EVENTS),
        scenario("payload-edges-metadata-mode", "metadata", PAYLOAD_EDGE_EVENTS),
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


def degraded_plan() -> dict:
    """A clock that throws on the first and third read. Both emitters must degrade alike."""
    events = [
        event("model.request", metadata={"model": "fake-model-v0"}),
        event("model.response", metadata={"model": "fake-model-v0"}),
        event("observer.error", capture_status="unavailable", metadata={"reason": "fixture gap"}),
        event("tool.start", metadata={"tool": "grep"}),
    ]
    return {
        "epoch_ms": EPOCH_MS,
        "step_ms": STEP_MS,
        "scenarios": [scenario("clock-throws", "content", events, clock_throws_on=[0, 2])],
    }


def test_the_python_emitter_reproduces_the_shared_v2_fixture_byte_for_byte():
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
    # Key order too: the fixture is the byte-level example a reader compares a JSONL line to.
    assert list(emitted) == list(FIXTURE)
    assert json.dumps(emitted, ensure_ascii=False, separators=(",", ":")) == json.dumps(
        FIXTURE, ensure_ascii=False, separators=(",", ":")
    )
    # The credential the caller passed never reaches the record.
    assert "real credential" not in json.dumps(emitted)
    assert observer.get_state() == CaptureState()


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
def test_both_emitters_write_byte_identical_jsonl_for_the_whole_parity_matrix(tmp_path):
    """Byte for byte, key order included. A reordered or reshaped field fails here."""
    pairs = both(tmp_path, matrix_plan())
    written = 0
    for python_case, node_case in pairs:
        assert len(python_case["lines"]) == len(node_case["lines"]), python_case["name"]
        for index, (python_line, node_line) in enumerate(
            zip(python_case["lines"], node_case["lines"])
        ):
            assert python_line == node_line, f"{python_case['name']} line {index}"
        written += len(python_case["lines"])
    # Guard against a matrix that agreed because it recorded nothing. The count only grows as
    # cases are added, so a shrinking matrix fails here rather than passing on less evidence.
    assert written >= 120
    # Key order is the schema's declaration order in both, on every line either wrote.
    declared = list(json.loads((ROOT / "schema/v2/trace-event.schema.json").read_text())["properties"])
    for python_case, _ in pairs:
        for emitted in parsed(python_case["lines"]):
            assert list(emitted) == [name for name in declared if name in emitted]


@needs_node
def test_both_emitters_agree_on_which_matrix_events_were_recorded(tmp_path):
    """Per input, not per run: a divergent rejection names the case that caused it."""
    by_name = {}
    for python_case, node_case in both(tmp_path, matrix_plan()):
        name = python_case["name"]
        assert python_case["recorded"] == node_case["recorded"], name
        by_name[name] = python_case["recorded"]

    # The rejection set is the contract, so pin it rather than only comparing the two.
    assert by_name["rejected-inputs-only"] == [False] * (
        len(REJECTED_EVENTS) + len(CONTENT_ONLY_REJECTIONS)
    )
    # Metadata mode never copies content, so the two content-only rejections are recorded there.
    metadata_mode = by_name["rejections-interleaved-metadata"]
    content_mode = by_name["rejections-interleaved-content"]
    refused_in_metadata_mode = sum(1 for flag in metadata_mode[::2] if not flag)
    assert refused_in_metadata_mode == len(REJECTED_EVENTS)
    assert sum(1 for flag in content_mode[::2] if not flag) == len(REJECTED_EVENTS) + len(
        CONTENT_ONLY_REJECTIONS
    )
    # Every interleaved valid event was recorded in both modes.
    assert all(metadata_mode[1::2]) and all(content_mode[1::2])
    # A sink that throws loses the line but still records the event; a redactor that throws
    # rejects the event outright in both languages.
    assert all(by_name["sink-throws"])
    assert not any(by_name["throwing-redactor"])
    assert not any(by_name["off-mode-defaults"])


@needs_node
def test_both_emitters_assign_the_same_sequence_numbers_and_event_ids(tmp_path):
    """A rejection that costs a sequence number in one language desynchronizes the streams."""
    by_name = {}
    for python_case, node_case in both(tmp_path, matrix_plan()):
        name = python_case["name"]
        assert python_case["sequences"] == node_case["sequences"], name
        assert python_case["event_ids"] == node_case["event_ids"], name
        assert python_case["run_id"] == node_case["run_id"], name
        assert python_case["producer_id"] == node_case["producer_id"], name
        by_name[name] = python_case

    # Refused events consume nothing: the accepted ones are still numbered densely from zero and
    # carry consecutive IDs from the injected factory.
    interleaved_case = by_name["rejections-interleaved-content"]
    accepted = [value for value in interleaved_case["sequences"] if value is not None]
    assert accepted == list(range(len(accepted)))
    ids = [value for value in interleaved_case["event_ids"] if value is not None]
    assert ids == [f"event-{index + 1}" for index in range(len(ids))]
    # Nothing at all was consumed by the scenario in which every event was refused.
    assert by_name["rejected-inputs-only"]["sequences"] == [None] * len(
        by_name["rejected-inputs-only"]["sequences"]
    )
    # A clock read is not consumed either: the accepted events walk the injected clock one tick
    # at a time, so a refused event that had read it would shift every timestamp after it.
    timestamps = [line["timestamp"] for line in parsed(interleaved_case["lines"])]
    assert timestamps[0] == "2026-09-20T12:00:00.000Z"
    assert timestamps == [iso_timestamp(index) for index in range(len(timestamps))]
    # Off mode invents no run or producer ID in either language.
    assert by_name["off-mode-defaults"]["run_id"] == "off"
    assert by_name["off-mode-defaults"]["producer_id"] == "off"
    assert by_name["generated-run-and-producer-ids"]["run_id"] == "run-1"
    assert by_name["generated-run-and-producer-ids"]["producer_id"] == "producer-2"


@needs_node
def test_both_emitters_report_the_same_capture_state_for_every_matrix_case(tmp_path):
    """dropped_events, capture_gap and last_sink_error, field for field, per scenario."""
    by_name = {}
    for python_case, node_case in both(tmp_path, matrix_plan()):
        name = python_case["name"]
        assert python_case["state"] == node_case["state"], name
        by_name[name] = python_case["state"]

    clean = {"dropped_events": 0, "capture_gap": False, "last_sink_error": None}
    gap = "observer instrumentation failure"
    assert by_name["every-event-type-content"] == clean
    assert by_name["off-mode-defaults"] == clean
    assert by_name["redaction-key-names"] == clean
    # One gap per refused event, one per failed write, one per redactor failure.
    refused = len(REJECTED_EVENTS) + len(CONTENT_ONLY_REJECTIONS)
    assert by_name["rejected-inputs-only"] == {
        "dropped_events": refused,
        "capture_gap": True,
        "last_sink_error": gap,
    }
    assert by_name["sink-throws"] == {
        "dropped_events": 3,
        "capture_gap": True,
        "last_sink_error": gap,
    }
    assert by_name["throwing-redactor"] == {
        "dropped_events": len(REDACTOR_PROBE_EVENTS),
        "capture_gap": True,
        "last_sink_error": gap,
    }


@needs_node
def test_a_redactor_returning_an_equal_copy_marks_both_emitters_redacted(tmp_path):
    """Reference identity, not value equality: an equal copy is still a replacement."""
    plan = matrix_plan()
    pairs = {
        python_case["name"]: (python_case, node_case) for python_case, node_case in both(tmp_path, plan)
    }
    python_case, node_case = pairs["equal-copy-redactor"]
    assert python_case["lines"] == node_case["lines"]
    statuses = [emitted["capture_status"] for emitted in parsed(python_case["lines"])]
    # The scalar-only event is untouched; the two carrying a container are marked redacted.
    assert statuses == ["complete", "redacted", "redacted"]
    # The values themselves are unchanged: an equal copy replaces nothing a reader can see.
    assert parsed(python_case["lines"])[1]["metadata"] == {
        "argv": ["grep", "-n"],
        "flags": {"case": True},
    }
    default = [emitted["capture_status"] for emitted in parsed(pairs["redaction-key-names"][0]["lines"])]
    assert default == ["redacted", "complete", "redacted"]


@needs_node
def test_the_default_redactor_hides_the_same_keys_in_both_languages(tmp_path):
    """ASCII case folding only, so a Unicode key JavaScript keeps is not hidden by Python."""
    plan = matrix_plan()
    for python_case, node_case in both(tmp_path, plan):
        if python_case["name"] != "redaction-key-names":
            continue
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
        return
    raise AssertionError("the redaction scenario is missing from the matrix")


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
        "cyclic_metadata",
        "non_finite_number_in_metadata",
    }
    assert required_rejections <= set(REJECTED_EVENTS)
    assert {"cyclic_content", "non_finite_number_in_content"} <= set(CONTENT_ONLY_REJECTIONS)
    # An integral duration is accepted and an integral float is stored as an integer.
    assert any(fields.get("duration_ms") == 120 for fields in ACCEPTED_EVENTS)
    assert any(
        isinstance(fields.get("duration_ms"), float) for fields in ACCEPTED_EVENTS
    )
    # The degraded hooks each have a scenario: a sink that throws, a redactor that throws, a
    # redactor that returns an equal copy, and a clock that throws.
    names = {case["name"] for case in plan["scenarios"]}
    assert {"sink-throws", "throwing-redactor", "equal-copy-redactor"} <= names
    assert {case["name"] for case in degraded_plan()["scenarios"]} == {"clock-throws"}


@needs_node
def test_a_clock_that_throws_costs_both_emitters_the_same_state_ids_and_timestamps(tmp_path):
    """The clock is caller code: a read that raises is a recorded gap in both, not an escape."""
    python_case, node_case = both(tmp_path, degraded_plan())[0]
    assert python_case["state"] == node_case["state"]
    assert python_case["state"] == {
        "dropped_events": 2,
        "capture_gap": True,
        "last_sink_error": "observer instrumentation failure",
    }
    assert python_case["recorded"] == node_case["recorded"] == [True, True, True, True]
    assert python_case["sequences"] == node_case["sequences"] == [0, 1, 2, 3]
    assert python_case["event_ids"] == node_case["event_ids"]
    # The failed reads fall back to the epoch timestamp, spelled identically in both.
    timestamps = [emitted["timestamp"] for emitted in parsed(python_case["lines"])]
    assert timestamps == [emitted["timestamp"] for emitted in parsed(node_case["lines"])]
    assert timestamps[0] == timestamps[2] == "1970-01-01T00:00:00.000Z"


@needs_node
@pytest.mark.xfail(
    strict=True,
    reason=(
        "open divergence, verified 2026-09-20: Python downgrades an event built while "
        "instrumentation failed to capture_status partial and stamps observer_capture_gap in "
        "its metadata; the TypeScript emitter leaves the event claiming complete. Fixing the "
        "TypeScript emitter is what closes this, not relaxing the test. See the known "
        "divergences section of docs/OBSERVER_SDK.md."
    ),
)
def test_a_clock_that_throws_marks_the_degraded_event_identically_in_both_languages(tmp_path):
    """Both emitters must say, in the event itself, that its timestamp was fabricated."""
    python_case, node_case = both(tmp_path, degraded_plan())[0]
    assert python_case["lines"] == node_case["lines"]
