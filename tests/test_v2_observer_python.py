"""Behavioral pins for the Python emitter, one named test per promise it makes.

These tests exercise :class:`scaneval.observer.Observer` directly. They start no scanner, read
no corpus, load no contract, call no model, and reach no network; every clock and ID factory is
injected, so nothing here depends on wall-clock time, ordering luck, or a sleep.

They also do not test the wire contract itself, only that what this emitter produces satisfies
it. A passing suite says the emitter records what a harness handed it and loses nothing
silently; it says nothing about whether a harness emits at the right boundaries, and nothing at
all about the quality of any finding whose lifecycle appears in a trace.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from scaneval.observer import CaptureState, EVENT_TYPES, Observer, create_jsonl_sink


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema/v2/trace-event.schema.json").read_text())
HARNESS = ROOT / "examples/observer/python_harness.py"
GAP = "observer instrumentation failure"
EPOCH = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)

# The order examples/observer/python_harness.py emits in. The example is a fixture, so this
# list is an expectation about that file and not a required shape for any real harness.
HARNESS_EVENTS = (
    "model.request",
    "model.response",
    "tool.start",
    "tool.end",
    "finding.candidate",
    "finding.filtered",
    "finding.candidate",
    "finding.validation",
    "finding.submitted",
)


def validator() -> Draft202012Validator:
    return Draft202012Validator(SCHEMA, format_checker=FormatChecker())


def ids():
    """A counting ID factory. Deterministic, and deliberately not unique across processes."""
    issued = 0

    def next_id(prefix: str) -> str:
        nonlocal issued
        issued += 1
        return f"{prefix}-{issued}"

    return next_id


def clock(step_ms: int = 10):
    """A clock that advances a fixed step per read and never consults the system time."""
    reads = 0

    def now() -> datetime:
        nonlocal reads
        moment = EPOCH + timedelta(milliseconds=step_ms * reads)
        reads += 1
        return moment

    return now


def recorder():
    seen: list[dict] = []
    return seen, seen.append


def raising(message: str):
    def boom(*_args, **_kwargs):
        raise RuntimeError(message)

    return boom


def model_request(**extra) -> dict:
    fields = {
        "type": "model.request",
        "capture_status": "complete",
        "metadata": {"model": "fake-model-v0"},
        "content": {"authorization": "fixture-credential", "prompt": "hello"},
    }
    fields.update(extra)
    return fields


def tool_start() -> dict:
    return {"type": "tool.start", "capture_status": "complete", "metadata": {"tool": "grep"}}


def tool_end(duration_ms) -> dict:
    return {
        "type": "tool.end",
        "capture_status": "complete",
        "duration_ms": duration_ms,
        "metadata": {"tool": "grep"},
    }


def tool_failed(error: BaseException, duration_ms) -> dict:
    return {
        "type": "tool.end",
        "capture_status": "unavailable",
        "duration_ms": duration_ms,
        "metadata": {"tool": "grep", "error": type(error).__name__},
    }


def traced(mode: str = "content") -> tuple[list[dict], Observer]:
    """An observer wired to a list sink with every source of nondeterminism injected."""
    seen, sink = recorder()
    observer = Observer(
        mode=mode, sink=sink, run_id="run-1", producer_id="producer-1",
        clock=clock(), id_factory=ids(),
    )
    return seen, observer


def test_off_mode_emits_nothing_and_never_calls_the_clock_or_id_factory():
    seen, sink = recorder()
    calls = {"clock": 0, "ids": 0, "sink": 0}

    def counted_clock() -> datetime:
        calls["clock"] += 1
        return EPOCH

    def counted_ids(prefix: str) -> str:
        calls["ids"] += 1
        return f"{prefix}-counted"

    def counted_sink(event: dict) -> None:
        calls["sink"] += 1
        sink(event)

    observer = Observer(sink=counted_sink, clock=counted_clock, id_factory=counted_ids)
    assert observer.mode == "off"
    assert observer.emit(**model_request()) is None
    assert observer.observe(tool_start(), tool_end, tool_failed, lambda: "value") == "value"
    assert seen == []
    assert calls == {"clock": 0, "ids": 0, "sink": 0}
    # Off mode names the run without asking the caller's factory for an ID it will never use.
    assert (observer.run_id, observer.producer_id) == ("off", "off")
    assert observer.get_state() == CaptureState(dropped_events=0, capture_gap=False)


def test_metadata_mode_omits_content_and_marks_the_status_partial():
    seen, observer = traced("metadata")
    observer.emit(**model_request(content={"prompt": "hello"}))
    observer.emit(type="tool.start", capture_status="complete", metadata={"tool": "grep"})
    observer.emit(**model_request(capture_status="unavailable", content={"prompt": "hello"}))
    assert all("content" not in event for event in seen)
    # Complete becomes partial because content was dropped. Explicit unavailable is the
    # caller's own claim about capture and is never upgraded or downgraded.
    assert [event["capture_status"] for event in seen] == ["partial", "partial", "unavailable"]


def test_content_mode_stores_a_redacted_copy_while_the_caller_object_is_unchanged():
    seen, observer = traced()
    metadata = {"model": "fake-model-v0", "token": "fixture-credential"}
    content = {"authorization": "fixture-credential", "body": {"nested": [1, 2]}}
    before = (deepcopy(metadata), deepcopy(content))
    event = observer.emit(
        type="model.request", capture_status="complete", metadata=metadata, content=content
    )
    assert (metadata, content) == before
    assert event["metadata"]["token"] == "[REDACTED]"
    assert event["content"]["authorization"] == "[REDACTED]"
    assert event["content"]["body"] == {"nested": [1, 2]}
    # A copy, not a view: mutating the caller's object later cannot rewrite a stored event.
    assert event["content"]["body"] is not content["body"]
    content["body"]["nested"].append(3)
    assert event["content"]["body"] == {"nested": [1, 2]}
    assert event["capture_status"] == "redacted"
    assert seen == [event]


def test_the_default_redactor_hides_credential_keys_but_not_token_counters():
    seen, observer = traced()
    observer.emit(
        type="model.response",
        capture_status="complete",
        metadata={
            "api_key": "x", "apiKey": "x", "api-key": "x", "Authorization": "x",
            "cookie": "x", "cookies": "x", "credential": "x", "credentials": "x",
            "password": "x", "secret": "x", "secrets": "x", "token": "x",
            "private_key": "x", "private-key": "x",
            "input_tokens": 31, "output_tokens": 18, "token_budget": 4096,
            "secret_count": 0, "model": "fake-model-v0",
        },
    )
    stored = seen[0]["metadata"]
    hidden = [key for key, value in stored.items() if value == "[REDACTED]"]
    assert hidden == [
        "api_key", "apiKey", "api-key", "Authorization", "cookie", "cookies",
        "credential", "credentials", "password", "secret", "secrets", "token",
        "private_key", "private-key",
    ]
    # Whole-key matching: a counter that merely contains a credential word is telemetry.
    assert stored["input_tokens"] == 31
    assert stored["output_tokens"] == 18
    assert stored["token_budget"] == 4096
    assert stored["secret_count"] == 0
    assert stored["model"] == "fake-model-v0"


def test_sequence_ids_and_timestamps_are_deterministic_under_injected_factories():
    first, observer = traced("metadata")
    for _ in range(3):
        observer.emit(**model_request())
    assert [event["sequence"] for event in first] == [0, 1, 2]
    assert [event["event_id"] for event in first] == ["event-1", "event-2", "event-3"]
    assert [event["timestamp"] for event in first] == [
        "2026-09-20T12:00:00.000Z", "2026-09-20T12:00:00.010Z", "2026-09-20T12:00:00.020Z"
    ]
    assert {event["run_id"] for event in first} == {"run-1"}
    assert {event["producer_id"] for event in first} == {"producer-1"}

    # A second observer built the same way records the same bytes. Nothing is read from the
    # process, the wall clock, or a random source.
    second, replayed = traced("metadata")
    for _ in range(3):
        replayed.emit(**model_request())
    assert second == first

    # Sequence numbers count recorded events, so a dropped event leaves no hole.
    third, counting = traced("metadata")
    counting.emit(**model_request())
    counting.emit(**model_request(capture_status="invented"))
    counting.emit(**model_request())
    assert [event["sequence"] for event in third] == [0, 1]


def _cyclic() -> dict:
    value: dict = {"value": "x"}
    value["self"] = value
    return value


@pytest.mark.parametrize("fields", [
    pytest.param(model_request(type="model.unknown"), id="unknown_event_type"),
    pytest.param(model_request(type="toString"), id="type_from_the_object_protocol"),
    pytest.param(model_request(type=7), id="non_string_event_type"),
    pytest.param(model_request(category="tool"), id="category_contradicts_type"),
    pytest.param(model_request(capture_status="invented"), id="unknown_capture_status"),
    pytest.param(model_request(capture_status=None), id="missing_capture_status"),
    pytest.param({"type": "tool.start", "capture_status": "complete"}, id="metadata_missing"),
    pytest.param(model_request(metadata=[]), id="metadata_is_a_list"),
    pytest.param(model_request(metadata="text"), id="metadata_is_a_string"),
    pytest.param(model_request(content=[]), id="content_is_a_list"),
    pytest.param(model_request(duration_ms=-1), id="negative_duration"),
    pytest.param(model_request(duration_ms=float("nan")), id="non_finite_duration"),
    pytest.param(model_request(duration_ms="12"), id="duration_as_text"),
    pytest.param(model_request(duration_ms=True), id="duration_as_a_boolean"),
    pytest.param(model_request(call_id=""), id="empty_link_id"),
    pytest.param(model_request(candidate_id=7), id="non_string_link_id"),
    pytest.param(model_request(severity="high"), id="field_name_the_contract_lacks"),
    pytest.param(model_request(metadata=_cyclic()), id="cyclic_metadata"),
    pytest.param(model_request(metadata={"bad": object()}), id="non_json_metadata_value"),
    pytest.param(model_request(metadata={"bad": float("inf")}), id="non_finite_metadata_number"),
    pytest.param(model_request(metadata={7: "x"}), id="non_string_metadata_key"),
    pytest.param(model_request(content={"bad": {object(): 1}}), id="non_string_content_key"),
])
def test_every_invalid_input_shape_is_dropped_as_a_capture_gap(fields):
    seen, observer = traced()
    # Nothing a harness can pass raises out of emit: a scan must not die of instrumentation.
    assert observer.emit(**fields) is None
    assert seen == []
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_sink_that_raises_is_a_capture_gap_and_the_emitted_event_is_still_returned():
    observer = Observer(
        mode="content", sink=raising("disk full"), run_id="run-1", producer_id="producer-1",
        clock=clock(), id_factory=ids(),
    )
    event = observer.emit(**model_request())
    # The caller still gets the event it emitted; only the write was lost.
    assert event is not None
    assert event["event_id"] == "event-1"
    assert event["sequence"] == 0
    state = observer.get_state()
    assert state == CaptureState(dropped_events=1, capture_gap=True, last_sink_error=GAP)
    # The gap names the failure class and never quotes the sink, whose message could carry
    # the payload it refused.
    assert "disk full" not in state.last_sink_error


def test_flush_waits_for_pending_writes_and_close_makes_later_emits_no_ops():
    seen, sink = recorder()
    synchronous = Observer(mode="metadata", sink=sink, run_id="r", producer_id="p")
    synchronous.emit(**model_request())
    synchronous.flush()
    synchronous.close()
    assert synchronous.closed is True
    assert synchronous.emit(**model_request()) is None
    assert len(seen) == 1
    assert synchronous.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )

    async def scenario() -> CaptureState:
        gate = asyncio.Event()
        written: list[dict] = []

        async def slow_sink(event: dict) -> None:
            await gate.wait()
            written.append(event)

        observer = Observer(mode="content", sink=slow_sink, run_id="r", producer_id="p")
        assert observer.emit(**model_request()) is not None
        await asyncio.sleep(0)
        assert written == []
        gate.set()
        await observer.aflush()
        assert [event["type"] for event in written] == ["model.request"]
        await observer.aclose()
        assert observer.emit(**model_request()) is None
        assert len(written) == 1
        return observer.get_state()

    assert asyncio.run(scenario()) == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_synchronous_operation_returns_its_value_and_reraises_its_original_exception():
    seen, observer = traced("metadata")
    assert observer.observe(tool_start(), tool_end, tool_failed, lambda: {"matched": 2}) == {
        "matched": 2
    }
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
    assert seen[1]["duration_ms"] == pytest.approx(10.0)
    assert seen[1]["capture_status"] == "partial"

    boom = RuntimeError("original")

    def failing():
        raise boom

    with pytest.raises(RuntimeError) as caught:
        observer.observe(tool_start(), tool_end, tool_failed, failing)
    # The same object, not a copy and not a wrapper: a harness may match on identity.
    assert caught.value is boom
    assert caught.value.args == ("original",)
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"] * 2
    assert seen[3]["metadata"]["error"] == "RuntimeError"
    assert seen[3]["capture_status"] == "unavailable"


def test_an_asynchronous_operation_returns_its_value_and_reraises_its_original_exception():
    seen, observer = traced("metadata")
    boom = RuntimeError("original")

    async def succeeding():
        return {"matched": 2}

    async def failing():
        raise boom

    async def scenario():
        assert await observer.observe_async(
            tool_start(), tool_end, tool_failed, succeeding
        ) == {"matched": 2}
        with pytest.raises(RuntimeError) as caught:
            await observer.observe_async(tool_start(), tool_end, tool_failed, failing)
        assert caught.value is boom
        await observer.aflush()

    asyncio.run(scenario())
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"] * 2
    assert seen[1]["duration_ms"] == pytest.approx(10.0)
    assert seen[3]["metadata"]["error"] == "RuntimeError"


def test_returned_generators_pass_through_unconsumed_and_still_yield_every_item():
    seen, observer = traced("metadata")
    started: list[str] = []

    def chunks():
        started.append("sync")
        yield "one"
        yield "two"

    stream = chunks()
    returned = observer.observe(tool_start(), tool_end, tool_failed, lambda: stream)
    assert returned is stream
    # observe timed the call that built the generator, and drew nothing out of it.
    assert started == []
    assert list(returned) == ["one", "two"]
    assert started == ["sync"]

    async def achunks():
        started.append("async")
        yield "three"
        yield "four"

    async def scenario():
        astream = achunks()
        areturned = await observer.observe_async(
            tool_start(), tool_end, tool_failed, lambda: astream
        )
        assert areturned is astream
        assert started == ["sync"]
        return [chunk async for chunk in areturned]

    assert asyncio.run(scenario()) == ["three", "four"]
    assert started == ["sync", "async"]
    # Four events, and none of them describes the stream: a duration here covers the call
    # that produced an iterator, never the work a caller later drives out of it.
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"] * 2


def test_finding_lifecycle_events_link_through_a_stable_candidate_id_and_a_claim_id():
    seen, observer = traced("metadata")
    dropped = "candidate-1"
    kept = "candidate-2"
    observer.emit(
        type="finding.candidate", capture_status="complete", candidate_id=dropped,
        metadata={"rule": "py.subprocess-shell-true", "path": "tests/fixtures/shell.py"},
    )
    observer.emit(
        type="finding.filtered", capture_status="complete", candidate_id=dropped,
        metadata={"reason": "path is test fixture material"},
    )
    observer.emit(
        type="finding.candidate", capture_status="complete", candidate_id=kept,
        metadata={"rule": "py.subprocess-shell-true", "path": "app/runner.py"},
    )
    observer.emit(
        type="finding.validation", capture_status="complete", candidate_id=kept,
        metadata={"verdict": "kept"},
    )
    observer.emit(
        type="finding.submitted", capture_status="complete", candidate_id=kept,
        claim_id="claim-1", metadata={"rule": "py.subprocess-shell-true"},
    )
    assert [event["type"] for event in seen] == [
        "finding.candidate", "finding.filtered",
        "finding.candidate", "finding.validation", "finding.submitted",
    ]
    assert all(event["category"] == "finding" for event in seen)
    # Every event has its own ID; the candidate ID is what joins the stages of one finding.
    assert len({event["event_id"] for event in seen}) == 5
    assert [event["candidate_id"] for event in seen] == [dropped, dropped, kept, kept, kept]
    assert [event["candidate_id"] for event in seen if event["type"] == "finding.filtered"] == [
        dropped
    ]
    # Only the submitted event names a claim, and a filtered candidate never acquires one.
    assert [event for event in seen if "claim_id" in event] == [seen[-1]]
    assert seen[-1]["claim_id"] == "claim-1"
    assert seen[-1]["candidate_id"] == kept


def test_a_sample_of_emitted_events_validates_against_the_wire_schema():
    lines: list[str] = []
    seen, sink = recorder()

    def both(event: dict) -> None:
        sink(event)
        create_jsonl_sink(lines.append).write(event)

    observer = Observer(
        mode="content", sink=both, run_id="run-1", producer_id="producer-1",
        clock=clock(), id_factory=ids(),
    )
    for event_type in EVENT_TYPES:
        observer.emit(
            type=event_type, capture_status="complete", parent_event_id="event-0",
            call_id="call-1", attempt_id="attempt-1", candidate_id="candidate-1",
            claim_id="claim-1", duration_ms=3,
            metadata={"stage": event_type}, content={"token": "fixture-credential"},
        )
    assert len(seen) == len(EVENT_TYPES)
    check = validator()
    for event in seen:
        assert not list(check.iter_errors(event)), event
        assert datetime.fromisoformat(event["timestamp"]).tzinfo is not None
        assert event["content"]["token"] == "[REDACTED]"
        assert event["capture_status"] == "redacted"
    # The JSONL a caller-owned writer received parses back to the same events.
    assert [json.loads(line) for line in lines] == seen


def test_the_python_example_harness_runs_and_prints_its_expected_event_sequence():
    completed = subprocess.run(
        [sys.executable, str(HARNESS)], capture_output=True, text=True, cwd=str(ROOT)
    )
    assert completed.returncode == 0, completed.stderr
    stdout = completed.stdout
    assert "no model call" in stdout
    assert "events recorded: 0" in stdout
    assert "events recorded: 9" in stdout
    assert "report identical to the untraced run: true" in stdout
    assert "capture state: dropped_events=0 capture_gap=false last_sink_error=none" in stdout

    events = [json.loads(line) for line in stdout.splitlines() if line.startswith('  {"')]
    assert [event["type"] for event in events] == list(HARNESS_EVENTS)
    assert [event["sequence"] for event in events] == list(range(len(HARNESS_EVENTS)))
    check = validator()
    for event in events:
        assert not list(check.iter_errors(event)), event
    # The fake credential is stored hidden and the token counter beside it is not.
    assert events[0]["content"]["api_key"] == "[REDACTED]"
    assert events[0]["metadata"]["input_tokens"] == 31
    assert events[0]["capture_status"] == "redacted"
    # Model response and tool end hang off the events that opened them.
    assert events[1]["parent_event_id"] == events[0]["event_id"]
    assert events[3]["parent_event_id"] == events[2]["event_id"]
    assert events[3]["duration_ms"] == 7
    # One candidate is filtered, the other reaches the report with a claim ID.
    assert events[4]["candidate_id"] == events[5]["candidate_id"]
    assert events[6]["candidate_id"] == events[7]["candidate_id"] == events[8]["candidate_id"]
    assert events[4]["candidate_id"] != events[6]["candidate_id"]
    assert events[8]["claim_id"] == "claim-1"

    # The example is a fixture with an injected clock, so a second run prints the same bytes.
    again = subprocess.run(
        [sys.executable, str(HARNESS)], capture_output=True, text=True, cwd=str(ROOT)
    )
    assert again.returncode == 0
    assert again.stdout == stdout
