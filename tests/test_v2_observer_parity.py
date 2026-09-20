"""Cross-language parity: the Python emitter and the TypeScript SDK must record the same events.

The wire contract is one document, ``schema/v2/trace-event.schema.json``, so a trace has to mean
the same thing whichever language wrote it. These tests run both emitters over identical inputs
with identical injected clocks and ID factories and compare what came out.

They prove agreement about recorded events only. They do not prove the two emitters share code,
that either one is correct about a harness that never emits, or that a trace says anything about
a scanner's findings. Nothing here calls a model, reaches the network, sleeps, or reads a real
clock: the TypeScript side is a throwaway driver run under node against the committed build
output, and the tests skip with a reason when node or that build is absent rather than pretend
parity was checked.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from scaneval.observer import CaptureState, EVENT_TYPES, Observer, create_jsonl_sink


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
        "cross-language parity needs node and the committed TypeScript build; "
        "run npm --prefix sdk/typescript run build and install node to check it"
    ),
)

# The driver is written into tmp_path per test rather than committed: it is a test harness for
# the SDK, not part of it, and nothing outside these tests should import it.
DRIVER = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const [, , planPath, sdkPath] = process.argv;
const { Observer, createJsonlSink } = await import(pathToFileURL(sdkPath).href);
const plan = JSON.parse(readFileSync(planPath, "utf8"));
const lines = [];
for (const scenario of plan.scenarios) {
  const supplied = (scenario.id_values ?? []).slice();
  let issued = 0;
  let reads = 0;
  const epoch = scenario.epoch_ms ?? plan.epoch_ms;
  const step = scenario.step_ms ?? plan.step_ms;
  const observer = new Observer({
    mode: scenario.mode,
    sink: createJsonlSink((line) => { lines.push(line); }),
    runId: scenario.run_id ?? undefined,
    producerId: scenario.producer_id ?? undefined,
    idFactory: {
      next: (prefix) => supplied.length > 0 ? supplied.shift() : `${prefix}-${++issued}`,
    },
    clock: { now: () => new Date(epoch + step * reads++) },
  });
  for (const event of scenario.events) {
    await observer.emit(event);
  }
  await observer.flush();
}
process.stdout.write(lines.join(""));
"""


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


def fixed_clock(epoch_ms: int, step_ms: int):
    """A clock that advances a fixed step per read, matching the node driver's arithmetic."""
    reads = 0

    def now() -> datetime:
        nonlocal reads
        moment = datetime.fromtimestamp(epoch_ms / 1000, timezone.utc) + timedelta(
            milliseconds=step_ms * reads
        )
        reads += 1
        return moment

    return now


def python_lines(plan: dict) -> list[str]:
    """Run every scenario through the Python emitter and return the JSONL it produced."""
    lines: list[str] = []
    for scenario in plan["scenarios"]:
        observer = Observer(
            mode=scenario["mode"],
            sink=create_jsonl_sink(lines.append),
            run_id=scenario.get("run_id"),
            producer_id=scenario.get("producer_id"),
            id_factory=id_factory(scenario.get("id_values")),
            clock=fixed_clock(
                scenario.get("epoch_ms", plan["epoch_ms"]),
                scenario.get("step_ms", plan["step_ms"]),
            ),
        )
        for event in scenario["events"]:
            observer.emit(**event)
        observer.flush()
    return lines


def node_lines(tmp_path: Path, plan: dict) -> list[str]:
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
    text = completed.stdout.decode("utf-8")
    return [line + "\n" for line in text.split("\n") if line]


def parsed(lines: list[str]) -> list[dict]:
    return [json.loads(line) for line in lines]


def event(event_type: str, **extra) -> dict:
    fields = {"type": event_type, "capture_status": "complete", "metadata": {"stage": event_type}}
    fields.update(extra)
    return fields


# One representative event per wire type, carrying the link fields that type actually uses,
# plus payload shapes that could plausibly serialize differently in the two languages:
# credential keys, a nested array, a float, a negative number, null, booleans, escapes, and
# non-ASCII text.
REPRESENTATIVE_EVENTS = [
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
        content={"text": 'quote " backslash \\ tab \t newline \n accented é kanji 漢'},
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
        metadata={"verdict": "dropped", "checked": "reachability"},
        content={"notes": "fixture text, no judgment about any scanner"},
    ),
    event(
        "finding.filtered",
        candidate_id="candidate-1",
        metadata={"reason": "path is test fixture material"},
    ),
    event(
        "finding.submitted",
        candidate_id="candidate-2",
        claim_id="claim-1",
        metadata={"rule": "py.subprocess-shell-true", "path": "app/runner.py", "line": 42},
    ),
    event(
        "observer.error",
        capture_status="unavailable",
        metadata={"reason": "fixture gap", "detail": None},
    ),
    # Edge shapes that carry no optional field at all.
    event("tool.start", metadata={}),
    event("model.request", metadata={"empty_list": [], "empty_object": {}}, content={}),
]

LINK_FREE_EVENTS = [
    event("tool.start", metadata={"tool": "grep"}, content={"arguments": {"pattern": "x"}}),
    event("model.request", metadata={"model": "fake-model-v0", "token": "fixture-credential"}),
    event("observer.error", capture_status="unavailable", metadata={"reason": "fixture gap"}),
    event("context.selection", metadata={"included_count": 0}),
    # Escaping and non-ASCII text have to serialize the same way in both languages, so keep
    # one such event where a byte comparison is possible.
    event(
        "model.response",
        metadata={"finish_reason": "stop", "cost_ratio": 1.5, "over_budget": -3},
        content={
            "text": 'quote " backslash \\ tab \t newline \n accented é kanji 漢',
            "flags": [True, False, None],
        },
    ),
]


def plan_for(events: list[dict], modes=("off", "metadata", "content")) -> dict:
    return {
        "epoch_ms": EPOCH_MS,
        "step_ms": STEP_MS,
        "scenarios": [
            {
                "mode": mode,
                "run_id": f"run-{mode}",
                "producer_id": f"producer-{mode}",
                "events": events,
            }
            for mode in modes
        ],
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
    emitted = parsed(node_lines(tmp_path, plan))
    assert emitted == [FIXTURE]
    assert emitted == parsed(python_lines(plan))


@needs_node
def test_both_emitters_record_the_same_events_for_every_type_and_recording_mode(tmp_path):
    plan = plan_for(REPRESENTATIVE_EVENTS)
    from_python = parsed(python_lines(plan))
    from_node = parsed(node_lines(tmp_path, plan))
    assert from_python == from_node

    # Off records nothing in either language, and the other two modes record everything.
    recorded = len(REPRESENTATIVE_EVENTS)
    assert len(from_python) == 2 * recorded
    assert [event["run_id"] for event in from_python[:recorded]] == ["run-metadata"] * recorded
    assert [event["run_id"] for event in from_python[recorded:]] == ["run-content"] * recorded
    # Every wire type is represented, so parity was checked across all of them.
    assert {event["type"] for event in from_python} == set(EVENT_TYPES)
    # Metadata mode stored no content in either language; content mode stored some.
    assert not any("content" in event for event in from_python[:recorded])
    assert any("content" in event for event in from_python[recorded:])
    # The credential keys are hidden identically, values included.
    hidden = [
        event["metadata"]["api_key"] for event in from_python if "api_key" in event["metadata"]
    ]
    assert hidden == ["[REDACTED]", "[REDACTED]"]


@needs_node
def test_both_emitters_write_byte_identical_jsonl_for_events_without_link_fields(tmp_path):
    plan = plan_for(LINK_FREE_EVENTS)
    from_python = python_lines(plan)
    from_node = node_lines(tmp_path, plan)
    assert from_python == from_node
    assert len(from_python) == 2 * len(LINK_FREE_EVENTS)


@needs_node
def test_link_field_placement_is_the_only_wire_difference_between_the_emitters(tmp_path):
    """Both emitters write the same JSON object; they order metadata against the link fields
    differently, which JSON does not make significant but a byte comparison would. This states
    which difference is tolerated rather than hiding it; it does not require it to persist.
    """
    plan = plan_for(REPRESENTATIVE_EVENTS, modes=("content",))
    from_python = python_lines(plan)
    from_node = node_lines(tmp_path, plan)
    assert len(from_python) == len(from_node) == len(REPRESENTATIVE_EVENTS)
    for python_line, node_line in zip(from_python, from_node):
        python_event = json.loads(python_line)
        node_event = json.loads(node_line)
        assert python_event == node_event
        assert sorted(python_event) == sorted(node_event)
        canonical = json.dumps(python_event, ensure_ascii=False, sort_keys=True)
        assert canonical == json.dumps(node_event, ensure_ascii=False, sort_keys=True)
        # The prefix through the timestamp is identical in both, link fields aside.
        fixed = ["schema_version", "event_id", "run_id", "producer_id", "sequence", "type",
                 "category", "capture_status", "timestamp"]
        assert list(python_event)[: len(fixed)] == fixed
        assert list(node_event)[: len(fixed)] == fixed


@needs_node
def test_both_emitters_number_and_timestamp_a_run_identically(tmp_path):
    plan = plan_for(REPRESENTATIVE_EVENTS, modes=("content",))
    from_python = parsed(python_lines(plan))
    from_node = parsed(node_lines(tmp_path, plan))
    count = len(REPRESENTATIVE_EVENTS)
    assert [event["sequence"] for event in from_python] == list(range(count))
    assert [event["sequence"] for event in from_node] == list(range(count))
    assert [event["event_id"] for event in from_python] == [
        f"event-{index + 1}" for index in range(count)
    ]
    assert [event["event_id"] for event in from_node] == [event["event_id"] for event in from_python]
    assert [event["timestamp"] for event in from_node] == [
        event["timestamp"] for event in from_python
    ]
    assert from_python[0]["timestamp"] == "2026-09-20T12:00:00.000Z"
    assert from_python[-1]["timestamp"] == "2026-09-20T12:00:00.110Z"
