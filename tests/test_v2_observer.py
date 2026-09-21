"""Python observer emitter: no-op by default, copied payloads, and visible capture gaps.

These tests pin the behaviors the TypeScript emitter's own suite pins, plus the boundary that
keeps the emitter importable without the evaluator. Nothing here sleeps, reaches the network,
or calls a model: every clock and ID factory is injected and deterministic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import gc
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import warnings

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from scaneval.observer import (
    CAPTURE_STATUSES,
    EVENT_CATEGORIES,
    EVENT_TYPES,
    MAX_PAYLOAD_DEPTH,
    RECORDING_MODES,
    SCHEMA_VERSION,
    CaptureState,
    JsonlSink,
    Observer,
    create_jsonl_sink,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema/v2/trace-event.schema.json").read_text())
FIXTURE = json.loads((ROOT / "schema/v2/fixtures/trace-event-v2.json").read_text())
GAP = "observer instrumentation failure"
EVALUATOR_MODULES = (
    "scaneval.contracts",
    "scaneval.scoring",
    "scaneval.cli",
    "scaneval.runner",
    "scaneval.execution",
    "scaneval.cases",
    "scaneval.review",
    "scaneval.report",
    "scaneval.adapters",
)


def ids():
    counter = 0

    def next_id(prefix: str) -> str:
        nonlocal counter
        counter += 1
        return f"{prefix}-{counter}"

    return next_id


def clock(step_ms: int = 10):
    counter = 0

    def now() -> datetime:
        nonlocal counter
        moment = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)
        moment = moment.replace(microsecond=counter * step_ms * 1000)
        counter += 1
        return moment

    return now


def event_fields(**extra):
    fields = {
        "type": "model.request",
        "capture_status": "complete",
        "metadata": {"model": "x"},
        "content": {"authorization": "keep-out", "body": "hello"},
    }
    fields.update(extra)
    return fields


def recorder():
    seen: list[dict] = []
    return seen, seen.append


def raising(message):
    def boom(*_args, **_kwargs):
        raise RuntimeError(message)

    return boom


def test_off_mode_records_nothing_and_never_calls_instrumentation():
    seen, sink = recorder()
    observer = Observer(
        sink=sink, id_factory=raising("ids"), clock=raising("clock"), redactor=raising("redactor")
    )
    assert observer.mode == "off"
    assert observer.emit(**event_fields()) is None
    assert seen == []
    assert (observer.run_id, observer.producer_id) == ("off", "off")
    assert observer.get_state() == CaptureState(dropped_events=0, capture_gap=False)


def test_off_mode_keeps_explicit_run_and_producer_ids():
    observer = Observer(run_id="r", producer_id="p", id_factory=raising("ids"))
    assert (observer.run_id, observer.producer_id) == ("r", "p")


def test_metadata_mode_omits_content_and_downgrades_complete_to_partial():
    seen, sink = recorder()
    observer = Observer(
        mode="metadata", sink=sink, id_factory=ids(), clock=clock(), run_id="r", producer_id="p"
    )
    observer.emit(**event_fields(metadata={"api_key": "original", "nested": {"x": 1}}))
    observer.emit(**event_fields())
    assert "content" not in seen[0] and "content" not in seen[1]
    assert seen[0]["metadata"]["api_key"] == "[REDACTED]"
    assert (seen[0]["sequence"], seen[1]["sequence"]) == (0, 1)
    assert (seen[0]["capture_status"], seen[1]["capture_status"]) == ("redacted", "partial")
    assert seen[0]["event_id"] == "event-1"
    assert seen[0]["timestamp"] == "2023-11-14T22:13:20.000Z"
    assert seen[1]["timestamp"] == "2023-11-14T22:13:20.010Z"


def test_emit_never_mutates_the_payloads_it_was_given():
    seen, sink = recorder()
    metadata = {"token": "original", "nested": {"kept": [1, 2]}}
    content = {"authorization": "original", "body": {"deep": "value"}}
    before = (deepcopy(metadata), deepcopy(content))
    observer = Observer(mode="content", sink=sink)
    event = observer.emit(type="tool.start", capture_status="complete", metadata=metadata, content=content)
    assert (metadata, content) == before
    assert event["metadata"]["nested"] is not metadata["nested"]
    assert event["content"]["body"] is not content["body"]
    assert event["metadata"]["token"] == "[REDACTED]"


def test_content_mode_stores_redacted_copies_and_lifecycle_links():
    seen, sink = recorder()
    observer = Observer(
        mode="content",
        sink=sink,
        id_factory=ids(),
        redactor=lambda key, value, path: "masked" if key == "body" else value,
    )
    observer.emit(
        **event_fields(
            candidate_id="cand-7", call_id="call-2", parent_event_id="event-parent",
            attempt_id="attempt-1", claim_id="claim-1", duration_ms=12,
        )
    )
    # A caller's redactor replaces the default one rather than layering on top of it, so this
    # policy stores authorization untouched. Local policy is the caller's to get right.
    assert seen[0]["content"] == {"authorization": "keep-out", "body": "masked"}
    assert seen[0]["candidate_id"] == "cand-7"
    assert seen[0]["call_id"] == "call-2"
    assert seen[0]["parent_event_id"] == "event-parent"
    assert seen[0]["attempt_id"] == "attempt-1"
    assert seen[0]["claim_id"] == "claim-1"
    assert seen[0]["duration_ms"] == 12


def test_a_custom_redactor_output_is_copied_and_revalidated():
    seen, sink = recorder()
    shared = {"nested": {"x": 1}}
    observer = Observer(
        mode="content", sink=sink,
        redactor=lambda key, value, path: shared if key == "body" else value,
    )
    observer.emit(**event_fields())
    stored = seen[0]["content"]["body"]
    assert stored == shared and stored is not shared
    assert stored["nested"] is not shared["nested"]
    assert seen[0]["capture_status"] == "redacted"


def test_a_redactor_returning_a_non_json_value_is_a_capture_gap():
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink, redactor=lambda key, value, path: object())
    assert observer.emit(**event_fields()) is None
    assert seen == []
    assert observer.get_state().capture_gap is True


def test_default_redactor_matches_credential_keys_but_not_token_counters():
    seen, sink = recorder()
    metadata = {
        "token": "secret", "apiKey": "secret", "api-key": "secret", "Authorization": "secret",
        "private_key": "secret", "cookies": "secret", "credentials": "secret",
        "input_tokens": 12, "output_tokens": 7, "model": "x", "token_budget": 5,
    }
    observer = Observer(mode="content", sink=sink)
    observer.emit(**event_fields(metadata=metadata))
    stored = seen[0]["metadata"]
    assert stored["token"] == stored["apiKey"] == stored["api-key"] == "[REDACTED]"
    assert stored["Authorization"] == stored["private_key"] == "[REDACTED]"
    assert stored["cookies"] == stored["credentials"] == "[REDACTED]"
    assert stored["input_tokens"] == 12 and stored["output_tokens"] == 7
    assert stored["model"] == "x" and stored["token_budget"] == 5
    assert seen[0]["capture_status"] == "redacted"


def test_explicitly_unavailable_capture_stays_unavailable():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink)
    observer.emit(**event_fields(capture_status="unavailable", metadata={"token": "secret"}))
    assert seen[0]["capture_status"] == "unavailable"


def test_sink_failure_is_a_capture_gap_and_the_event_is_still_returned():
    observer = Observer(mode="content", sink=raising("disk full"))
    assert observer.emit(**event_fields()) is not None
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_sink_object_with_a_write_method_is_accepted():
    class Collector:
        def __init__(self):
            self.events = []

        def write(self, event):
            self.events.append(event)

    collector = Collector()
    observer = Observer(mode="metadata", sink=collector)
    observer.emit(**event_fields())
    assert len(collector.events) == 1


def test_every_instrumentation_failure_becomes_a_capture_gap():
    seen, sink = recorder()
    observer = Observer(
        mode="content", sink=sink, id_factory=raising("ids"), clock=raising("clock"),
        redactor=raising("redactor"),
    )
    assert observer.run_id == "run-fallback-1"
    assert observer.producer_id == "producer-fallback-2"
    # Two ID failures at construction, and neither lost an event: there was no event yet.
    assert observer.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )
    assert observer.emit(**event_fields()) is None
    assert seen == []
    # The redactor is what stopped this event, so exactly one event was lost.
    assert observer.get_state().dropped_events == 1
    assert observer.get_state().capture_gap is True
    assert observer.get_state().last_sink_error == GAP


def test_a_failing_clock_falls_back_to_the_epoch_and_records_a_gap():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink, run_id="r", producer_id="p", clock=raising("clock"))
    observer.emit(**event_fields())
    assert seen[0]["timestamp"] == "1970-01-01T00:00:00.000Z"
    # The epoch is a fallback, not a measurement, so the event says its capture was partial.
    assert seen[0]["capture_status"] == "partial"
    assert seen[0]["metadata"]["observer_capture_gap"] is True
    assert observer.get_state().capture_gap is True


def test_a_naive_clock_is_refused_rather_than_assumed_to_be_utc():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink, clock=lambda: datetime(2026, 9, 20, 12, 0))
    observer.emit(**event_fields())
    assert seen[0]["timestamp"] == "1970-01-01T00:00:00.000Z"
    assert seen[0]["capture_status"] == "partial"
    assert seen[0]["metadata"]["observer_capture_gap"] is True
    assert observer.get_state().capture_gap is True


def test_unserializable_and_cyclic_payloads_are_capture_gaps():
    seen, sink = recorder()
    cyclic = {"value": "x"}
    cyclic["self"] = cyclic
    observer = Observer(mode="content", sink=sink)
    assert observer.emit(**event_fields(metadata=cyclic)) is None
    assert observer.emit(**event_fields(metadata={"bad": object()})) is None
    assert observer.emit(**event_fields(metadata={"bad": float("inf")})) is None
    assert observer.emit(**event_fields(metadata={1: "non-string key"})) is None
    assert seen == []
    assert observer.get_state().dropped_events == 4


@pytest.mark.parametrize("extra", [
    pytest.param({"duration_ms": -1}, id="negative_duration"),
    pytest.param({"duration_ms": float("nan")}, id="non_finite_duration"),
    pytest.param({"duration_ms": "12"}, id="duration_as_text"),
    pytest.param({"category": "tool"}, id="category_contradicts_type"),
    pytest.param({"type": "toString"}, id="type_from_object_protocol"),
    pytest.param({"type": "model.unknown"}, id="unknown_type"),
    pytest.param({"capture_status": "made-up"}, id="unknown_capture_status"),
    pytest.param({"metadata": []}, id="metadata_is_a_list"),
    pytest.param({"metadata": "text"}, id="metadata_is_a_string"),
    pytest.param({"content": []}, id="content_is_a_list"),
    pytest.param({"call_id": ""}, id="empty_id"),
    pytest.param({"candidate_id": 7}, id="non_string_id"),
    pytest.param({"severity": "high"}, id="unknown_field_name"),
])
def test_invalid_event_input_is_dropped_before_the_sink(extra):
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink)
    assert observer.emit(**event_fields(**extra)) is None
    assert seen == []
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_missing_metadata_field_is_refused():
    observer = Observer(mode="metadata")
    assert observer.emit(type="tool.start", capture_status="complete") is None
    assert observer.get_state().dropped_events == 1


def test_sequence_counts_only_recorded_events():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink)
    observer.emit(**event_fields())
    observer.emit(**event_fields(capture_status="made-up"))
    observer.emit(**event_fields())
    assert [event["sequence"] for event in seen] == [0, 1]


def test_get_state_returns_a_snapshot_not_a_live_reference():
    observer = Observer(mode="metadata", sink=raising("sink"))
    observer.emit(**event_fields())
    snapshot = observer.get_state()
    observer.emit(**event_fields())
    assert snapshot.dropped_events == 1
    assert observer.get_state().dropped_events == 2


def test_jsonl_sink_delegates_writing_to_the_caller():
    lines: list[str] = []
    observer = Observer(mode="metadata", sink=create_jsonl_sink(lines.append))
    observer.emit(**event_fields())
    assert len(lines) == 1 and lines[0].endswith("\n")
    assert json.loads(lines[0])["type"] == "model.request"
    assert isinstance(create_jsonl_sink(lines.append), JsonlSink)


def test_a_generator_function_line_writer_is_refused_when_the_sink_is_made():
    """Calling a generator writer returns an iterator and writes nothing, so it is wiring.

    Accepted, it costs every line in silence: the sink raises nothing, the capture state stays
    clean, and the absence of the events reads as the absence of the activity. The Observer
    constructor already refuses a sink shaped this way, and this is the same classification one
    layer down, at the writer a JSONL sink is built from.
    """
    lines: list[str] = []

    def generator_writer(line):
        lines.append(line)
        yield line

    class GeneratorCallWriter:
        def __call__(self, line):
            lines.append(line)
            yield line

    async def async_generator_writer(line):
        lines.append(line)
        yield line

    for unusable in (generator_writer, GeneratorCallWriter(), async_generator_writer):
        with pytest.raises(ValueError):
            create_jsonl_sink(unusable)
        # The dataclass is exported, so the same mistake is refused through it as well.
        with pytest.raises(ValueError):
            JsonlSink(unusable)
    # Nothing was written by the refused writers, and nothing was silently swallowed either.
    assert lines == []

    async def coroutine_writer(line):
        lines.append(line)

    # A plain callable and a coroutine function are both usable and still accepted.
    assert isinstance(create_jsonl_sink(lines.append), JsonlSink)
    assert isinstance(create_jsonl_sink(coroutine_writer), JsonlSink)


def test_observe_returns_the_value_and_records_a_duration():
    seen, sink = recorder()
    ticks = iter([100.0, 100.01])
    observer = Observer(mode="metadata", sink=sink, clock=clock(), monotonic=lambda: next(ticks))
    start = {"type": "tool.start", "capture_status": "complete", "metadata": {}}
    done = lambda duration_ms: {
        "type": "tool.end", "capture_status": "complete", "duration_ms": duration_ms, "metadata": {}
    }
    assert observer.observe(start, done, lambda error, duration_ms: done(duration_ms), lambda: 42) == 42
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
    # Whole milliseconds, measured from the injected monotonic source. The wall clock beside it
    # is never the elapsed-time source, so pinning a duration means injecting ``monotonic``.
    assert seen[1]["duration_ms"] == 10
    assert isinstance(seen[1]["duration_ms"], int)


def test_observe_reraises_the_original_exception_object():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink, clock=clock())
    start = {"type": "tool.start", "capture_status": "complete", "metadata": {}}
    failure = lambda error, duration_ms: {
        "type": "tool.end", "capture_status": "unavailable", "duration_ms": duration_ms,
        "metadata": {"error": type(error).__name__},
    }
    boom = RuntimeError("original")

    def operation():
        raise boom

    with pytest.raises(RuntimeError) as caught:
        observer.observe(start, lambda duration_ms: start, failure, operation)
    assert caught.value is boom
    assert seen[1]["metadata"] == {"error": "RuntimeError"}


def test_observe_passes_a_generator_through_untouched():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink, clock=clock())
    start = {"type": "tool.start", "capture_status": "complete", "metadata": {}}

    def chunks():
        yield "one"
        yield "two"

    stream = chunks()
    returned = observer.observe(start, lambda duration_ms: start, lambda e, d: start, lambda: stream)
    assert returned is stream
    assert list(returned) == ["one", "two"]


def test_observe_survives_event_builders_that_raise():
    observer = Observer(mode="content", sink=raising("sink"), clock=raising("clock"))
    calls = 0

    def operation():
        nonlocal calls
        calls += 1
        return "ok"

    assert observer.observe(
        event_fields(), raising("success callback"), raising("failure callback"), operation
    ) == "ok"
    assert calls == 1
    assert observer.get_state().capture_gap is True


def test_off_mode_observe_bypasses_every_factory():
    calls = 0

    def operation():
        nonlocal calls
        calls += 1
        return 9

    observer = Observer(mode="off", id_factory=raising("ids"), clock=raising("clock"))
    assert observer.observe(
        event_fields(), raising("success"), raising("failure"), operation
    ) == 9
    assert calls == 1
    assert observer.get_state() == CaptureState()


def test_observe_async_awaits_the_operation_and_records_a_duration():
    seen, sink = recorder()
    ticks = iter([100.0, 100.01])
    observer = Observer(mode="metadata", sink=sink, clock=clock(), monotonic=lambda: next(ticks))
    start = {"type": "tool.start", "capture_status": "complete", "metadata": {}}
    done = lambda duration_ms: {
        "type": "tool.end", "capture_status": "complete", "duration_ms": duration_ms, "metadata": {}
    }

    async def operation():
        return 42

    async def scenario():
        return await observer.observe_async(
            start, done, lambda error, duration_ms: done(duration_ms), operation
        )

    assert asyncio.run(scenario()) == 42
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
    assert seen[1]["duration_ms"] == 10
    assert isinstance(seen[1]["duration_ms"], int)


def test_observe_async_reraises_the_original_exception_object():
    observer = Observer(mode="metadata", sink=raising("sink"))
    boom = RuntimeError("original")

    async def operation():
        raise boom

    async def scenario():
        await observer.observe_async(
            event_fields(), lambda d: event_fields(), lambda e, d: event_fields(), operation
        )

    with pytest.raises(RuntimeError) as caught:
        asyncio.run(scenario())
    assert caught.value is boom


def test_observe_async_passes_an_async_generator_through_untouched():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink, clock=clock())

    async def chunks():
        yield "one"
        yield "two"

    async def scenario():
        stream = chunks()
        returned = await observer.observe_async(
            event_fields(), lambda d: event_fields(), lambda e, d: event_fields(), lambda: stream
        )
        assert returned is stream
        return [chunk async for chunk in returned]

    assert asyncio.run(scenario()) == ["one", "two"]
    assert len(seen) == 2


def test_observe_async_accepts_an_operation_that_returns_a_plain_value():
    observer = Observer(mode="metadata", clock=clock())

    async def scenario():
        return await observer.observe_async(
            event_fields(), lambda d: event_fields(), lambda e, d: event_fields(), lambda: "plain"
        )

    assert asyncio.run(scenario()) == "plain"


def test_observe_async_runs_an_awaitable_that_types_coroutine_produced():
    """``await`` runs this awaitable, so the observer must run it too, in every mode.

    :func:`types.coroutine` marks a generator awaitable without giving its type an
    ``__await__`` slot, which is the one shape the emitter used to miss: it handed the
    generator straight back, unrun, so the operation the harness asked for never happened and
    the caller got an object instead of a value. Instrumentation may cost a trace event; it may
    never decide whether the caller's work runs.
    """
    runs: list[str] = []

    @types.coroutine
    def operation():
        runs.append("ran")
        return 42
        yield  # never reached: the decorator needs a generator function to mark

    async def scenario(observer):
        return await observer.observe_async(
            TOOL_START, completion, lambda error, duration: completion(duration), operation
        )

    off = Observer(mode="off", sink=raising("sink"), clock=raising("clock"))
    seen, sink = recorder()
    ticks = iter([100.0, 100.01])
    recording = Observer(mode="metadata", sink=sink, clock=clock(), monotonic=lambda: next(ticks))
    results = [asyncio.run(scenario(off)), asyncio.run(scenario(recording))]

    # The operation ran exactly once per call and returned the same value with recording off
    # and on, which is the whole of the pass-through guarantee.
    assert results == [42, 42]
    assert runs == ["ran", "ran"]
    assert off.get_state() == CaptureState()
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
    assert seen[1]["duration_ms"] == 10
    assert recording.get_state() == CaptureState()


def test_observe_async_still_passes_an_unmarked_generator_through_untouched():
    """Only the flag ``await`` reads makes a generator awaitable; a stream stays a stream."""
    observer = Observer(mode="metadata", sink=recorder()[1], clock=clock())

    def chunks():
        yield "one"
        yield "two"

    async def scenario(stream):
        return await observer.observe_async(
            TOOL_START, completion, lambda error, duration: completion(duration), lambda: stream
        )

    stream = chunks()
    # Unmarked, this generator is a stream the caller drives, not work the emitter resolves,
    # and the duration covers only the call that produced it.
    assert asyncio.run(scenario(stream)) is stream
    assert list(stream) == ["one", "two"]


def test_a_synchronous_harness_completes_an_async_sink_without_an_event_loop():
    written: list[dict] = []

    async def sink(event):
        written.append(event)

    observer = Observer(mode="metadata", sink=sink)
    assert observer.emit(**event_fields()) is not None
    assert len(written) == 1
    observer.flush()
    assert observer.get_state() == CaptureState()
    # close releases the private loop the emitter created to drive that write.
    observer.close()


def test_aflush_waits_for_pending_writes_and_records_their_rejection():
    async def scenario():
        released = asyncio.Event()
        seen: list[dict] = []

        async def sink(event):
            await released.wait()
            seen.append(event)

        observer = Observer(mode="content", sink=sink)
        observer.emit(**event_fields())
        await asyncio.sleep(0)
        assert seen == []
        released.set()
        await observer.aflush()
        assert len(seen) == 1

        async def failing(event):
            raise RuntimeError("late")

        late = Observer(mode="content", sink=failing)
        late.emit(**event_fields())
        await late.aflush()
        assert late.get_state() == CaptureState(
            dropped_events=1, capture_gap=True, last_sink_error=GAP
        )

    asyncio.run(scenario())


def test_flush_inside_a_running_loop_leaves_pending_writes_for_aflush():
    async def scenario():
        released = asyncio.Event()

        async def sink(event):
            await released.wait()

        observer = Observer(mode="content", sink=sink)
        observer.emit(**event_fields())
        observer.flush()
        # The write belongs to this loop and only it can run it. A write in flight is not a
        # lost event, so flush counts nothing and aflush is what settles it.
        assert observer.get_state() == CaptureState()
        released.set()
        await observer.aflush()
        assert observer.get_state() == CaptureState()

    asyncio.run(scenario())


def test_close_makes_later_emits_a_recorded_gap():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink)
    observer.emit(**event_fields())
    observer.close()
    assert observer.closed is True
    assert observer.emit(**event_fields()) is None
    assert len(seen) == 1
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_aclose_flushes_then_refuses_later_events():
    async def scenario():
        seen: list[dict] = []

        async def sink(event):
            seen.append(event)

        observer = Observer(mode="content", sink=sink)
        observer.emit(**event_fields())
        await observer.aclose()
        assert len(seen) == 1
        assert observer.emit(**event_fields()) is None
        assert observer.get_state().capture_gap is True

    asyncio.run(scenario())


def test_a_closed_off_mode_observer_stays_a_pure_no_op():
    observer = Observer()
    observer.close()
    assert observer.emit(**event_fields()) is None
    assert observer.get_state() == CaptureState()


def test_unknown_mode_and_unusable_sink_fail_at_construction():
    with pytest.raises(ValueError):
        Observer(mode="everything")
    with pytest.raises(ValueError):
        Observer(mode="metadata", sink="not-a-sink")


def test_emitted_events_satisfy_the_wire_schema():
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink, run_id="r", producer_id="p")
    # A whole number of milliseconds: a fractional duration is refused, which its own test pins.
    observer.emit(**event_fields(call_id="call-1", duration_ms=2))
    observer.emit(type="finding.candidate", capture_status="unavailable", candidate_id="c-1",
                  metadata={"rule": "r"})
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    for event in seen:
        assert not list(validator.iter_errors(event))
        assert datetime.fromisoformat(event["timestamp"]).tzinfo is not None
    assert seen[1]["category"] == "finding"


def test_emits_the_shared_v2_fixture_byte_for_byte():
    values = ["run-example-1", "dispatcher-example", "event-example-1"]
    observer = Observer(
        mode="content",
        id_factory=lambda prefix: values.pop(0),
        clock=lambda: datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc),
    )
    emitted = observer.emit(
        type="model.request", capture_status="complete", call_id="call-example-1",
        metadata={"model": "example-model", "input_tokens": 42},
        content={"authorization": "real credential"},
    )
    assert emitted == FIXTURE
    assert json.dumps(emitted) == json.dumps(FIXTURE)


def test_exported_constants_match_the_wire_schema():
    properties = SCHEMA["properties"]
    assert SCHEMA_VERSION == properties["schema_version"]["const"]
    assert list(EVENT_TYPES) == properties["type"]["enum"]
    assert list(EVENT_CATEGORIES) == properties["category"]["enum"]
    assert list(CAPTURE_STATUSES) == properties["capture_status"]["enum"]
    assert RECORDING_MODES == ("off", "metadata", "content")


def test_a_sink_raising_a_base_exception_is_a_capture_gap_not_an_escape():
    # asyncio.CancelledError is a BaseException, so a guard that only caught Exception let it
    # out of emit and into the harness, losing the event with no gap recorded.
    def cancelling(event):
        raise asyncio.CancelledError("gone")

    observer = Observer(mode="content", sink=cancelling)
    assert observer.emit(**event_fields()) is not None
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_an_async_sink_that_cancels_is_a_capture_gap_in_and_out_of_a_loop():
    async def cancelling(event):
        raise asyncio.CancelledError("gone")

    # No loop running: the write is driven here and its cancellation stays here.
    synchronous = Observer(mode="content", sink=cancelling)
    assert synchronous.emit(**event_fields()) is not None
    assert synchronous.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )
    synchronous.close()

    async def scenario():
        observer = Observer(mode="content", sink=cancelling)
        assert observer.emit(**event_fields()) is not None
        await observer.aflush()
        return observer.get_state()

    assert asyncio.run(scenario()) == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_keyboard_interrupt_from_a_sink_is_recorded_once_and_reaches_the_caller():
    def interrupting(event):
        raise KeyboardInterrupt()

    observer = Observer(mode="content", sink=interrupting)
    with pytest.raises(KeyboardInterrupt):
        observer.emit(**event_fields())
    # The caller's own interrupt is the one exception instrumentation may not swallow, and the
    # containment guards outside the sink must not count the same loss again.
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_base_exception_from_a_caller_hook_never_leaves_observe():
    class Abort(BaseException):
        """Not an Exception, and not an interrupt either."""

    def aborting(*_args, **_kwargs):
        raise Abort()

    observer = Observer(
        mode="content", sink=aborting, clock=aborting, monotonic=aborting, id_factory=aborting
    )
    calls = 0

    def operation():
        nonlocal calls
        calls += 1
        return "ok"

    assert observer.observe(event_fields(), aborting, aborting, operation) == "ok"
    assert calls == 1
    assert observer.get_state().capture_gap is True


def test_async_writes_share_one_private_loop_and_leave_the_callers_loop_alone():
    loops: list[int] = []

    async def sink(event):
        loops.append(id(asyncio.get_running_loop()))

    caller_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(caller_loop)
    try:
        observer = Observer(mode="content", sink=sink)
        for _ in range(3):
            assert observer.emit(**event_fields()) is not None
        # One loop for three writes: asyncio.run built and tore one down per event.
        assert len(loops) == 3 and len(set(loops)) == 1
        assert id(caller_loop) not in loops
        # asyncio.run also cleared the thread's current loop as a side effect. This does not.
        assert asyncio.get_event_loop() is caller_loop
        assert observer.get_state() == CaptureState()
        observer.close()
    finally:
        caller_loop.close()
        asyncio.set_event_loop(None)


def test_a_generator_function_sink_is_refused_at_construction():
    def generator_sink(event):
        yield event

    async def async_generator_sink(event):
        yield event

    # Calling either returns an iterator and writes nothing, so it records silently nothing at
    # all. That is a wiring mistake, and wiring mistakes are raised once, at construction.
    for unusable in (generator_sink, async_generator_sink):
        with pytest.raises(ValueError):
            Observer(mode="content", sink=unusable)

    class GeneratorWrite:
        def write(self, event):
            yield event

    with pytest.raises(ValueError):
        Observer(mode="metadata", sink=GeneratorWrite())


def test_off_mode_never_reads_an_attribute_of_the_sink_it_was_given():
    reads = 0

    class Hostile:
        @property
        def write(self):
            nonlocal reads
            reads += 1
            raise RuntimeError("descriptor ran")

    observer = Observer(mode="off", sink=Hostile())
    assert observer.emit(**event_fields()) is None
    assert reads == 0
    assert observer.get_state() == CaptureState()
    # In a recording mode the same sink is unusable, and that is a construction-time error.
    with pytest.raises(ValueError):
        Observer(mode="metadata", sink=Hostile())
    assert reads == 1


def completion(duration_ms):
    """A tool.end builder that also records whether it was handed a measured duration."""
    return {
        "type": "tool.end",
        "capture_status": "complete",
        "duration_ms": duration_ms,
        "metadata": {"measured": duration_ms is not None},
    }


TOOL_START = {"type": "tool.start", "capture_status": "complete", "metadata": {}}


def test_elapsed_time_comes_from_the_injected_monotonic_source():
    seen, sink = recorder()
    ticks = iter([100.0, 100.25])
    observer = Observer(
        mode="metadata", sink=sink, clock=clock(), monotonic=lambda: next(ticks)
    )
    assert observer.observe(TOOL_START, completion, lambda e, d: completion(d), lambda: 42) == 42
    # 250 ms from the monotonic source, not the 10 ms step of the wall clock beside it.
    assert seen[1]["duration_ms"] == 250
    assert observer.get_state() == CaptureState()


def test_an_unmeasurable_duration_is_omitted_and_recorded_as_a_gap():
    seen, sink = recorder()
    observer = Observer(
        mode="metadata", sink=sink, clock=clock(), monotonic=raising("monotonic")
    )
    assert observer.observe(TOOL_START, completion, lambda e, d: completion(d), lambda: 42) == 42
    # The completion event is still recorded, without a duration it could not measure. A
    # fabricated one would be read as a measurement.
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
    assert "duration_ms" not in seen[1]
    assert seen[1]["metadata"]["measured"] is False
    # The event says its own capture was partial, so a missing duration cannot be read as a
    # span the harness simply never timed.
    assert seen[1]["capture_status"] == "partial"
    assert seen[1]["metadata"]["observer_capture_gap"] is True
    assert observer.get_state().capture_gap is True


def test_a_backwards_monotonic_source_omits_the_duration_instead_of_dropping_the_event():
    seen, sink = recorder()
    ticks = iter([100.0, 99.0])
    observer = Observer(
        mode="metadata", sink=sink, clock=clock(), monotonic=lambda: next(ticks)
    )
    assert observer.observe(TOOL_START, completion, lambda e, d: completion(d), lambda: 42) == 42
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
    assert "duration_ms" not in seen[1]
    assert seen[1]["metadata"]["observer_capture_gap"] is True
    # Both events reached the sink, so nothing was lost: the unmeasurable span is a gap on a
    # delivered event, and counting it as a dropped event would report a loss that never was.
    assert observer.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )


class Shifting(Mapping):
    """A caller Mapping that answers differently every time a key is read."""

    def __init__(self, stable, shifting):
        self._stable = dict(stable)
        self._shifting = {key: list(values) for key, values in shifting.items()}
        self.reads = 0

    def __getitem__(self, key):
        self.reads += 1
        if key in self._shifting:
            values = self._shifting[key]
            return values.pop(0) if len(values) > 1 else values[0]
        return self._stable[key]

    def __iter__(self):
        return iter([*self._stable, *self._shifting])

    def __len__(self):
        return len(self._stable) + len(self._shifting)


def test_an_unstable_mapping_is_read_once_so_the_event_matches_what_was_validated():
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink, run_id="r", producer_id="p", clock=clock())
    # Reading this twice once let a value past validation and a different one into the event.
    fields = Shifting(
        {"type": "model.request", "metadata": {"model": "x"}},
        {"capture_status": ["complete", "made-up", "made-up"]},
    )
    observer.observe(fields, completion, lambda e, d: completion(d), lambda: "value")
    assert fields.reads == len(fields)
    assert seen[0]["capture_status"] in CAPTURE_STATUSES
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    assert not list(validator.iter_errors(seen[0]))
    assert observer.get_state() == CaptureState()


def test_an_event_built_during_an_instrumentation_failure_is_marked_partial():
    seen, sink = recorder()
    observer = Observer(
        mode="content", sink=sink, run_id="r", producer_id="p", clock=raising("clock")
    )
    event = observer.emit(**event_fields())
    # The timestamp is fabricated and the status says so, even though the caller asked for
    # complete and redaction alone would have said redacted.
    assert event["timestamp"] == "1970-01-01T00:00:00.000Z"
    assert event["capture_status"] == "partial"
    assert event["metadata"]["observer_capture_gap"] is True
    assert event["content"]["authorization"] == "[REDACTED]"

    # A caller who already declared the capture unavailable keeps that claim.
    observer.emit(**event_fields(capture_status="unavailable"))
    assert seen[1]["capture_status"] == "unavailable"
    assert seen[1]["metadata"]["observer_capture_gap"] is True
    # Two events, two failed clock reads, and both events delivered: a gap, no loss.
    assert observer.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )


def test_a_recursion_error_inside_emit_is_a_capture_gap():
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink)
    deep = current = {}
    for _ in range(sys.getrecursionlimit() * 4):
        current["next"] = {}
        current = current["next"]
    assert observer.emit(**event_fields(metadata=deep)) is None
    assert seen == []
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def stack_capacity() -> int:
    """How many more nested Python frames this interpreter allows from here."""
    depth = 0

    def descend():
        nonlocal depth
        depth += 1
        descend()

    try:
        descend()
    except RecursionError:
        pass
    return depth


def at_depth(frames: int, call):
    """Call ``call`` with ``frames`` frames of this function stacked beneath it."""
    if frames <= 0:
        return call()
    return at_depth(frames - 1, call)


def test_emit_near_the_stack_limit_records_a_gap_instead_of_raising():
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink)
    emitter_file = Observer.emit.__code__.co_filename
    escaped: list[int] = []
    losses: list[int] = []
    capacity = stack_capacity()
    for offset in range(1, 31):
        before = observer.get_state().dropped_events
        try:
            event = at_depth(capacity - offset, lambda: observer.emit(**event_fields()))
        except RecursionError as error:
            files = []
            traceback = error.__traceback__
            while traceback is not None:
                files.append(traceback.tb_frame.f_code.co_filename)
                traceback = traceback.tb_next
            # The interpreter refusing to enter emit at all is the caller's own wall. An error
            # raised from inside the emitter is instrumentation escaping into the harness.
            if emitter_file in files:
                escaped.append(offset)
            continue
        if event is None:
            losses.append(observer.get_state().dropped_events - before)
    assert escaped == []
    # Emit was entered with almost no stack left, and every time it gave up it said so: one
    # gap per lost event, recorded with no stack left to record it from.
    assert losses and set(losses) == {1}
    assert observer.get_state().capture_gap is True
    assert len(seen) > 0


def test_pending_writes_are_not_counted_as_drops_by_flush_or_close():
    async def scenario():
        gate = asyncio.Event()
        written: list[dict] = []

        async def slow(event):
            await gate.wait()
            written.append(event)

        observer = Observer(mode="content", sink=slow)
        for _ in range(3):
            assert observer.emit(**event_fields()) is not None
        observer.flush()
        # Three writes are in flight in this loop. Nothing is lost yet, so nothing is dropped,
        # and close must not count the same three again.
        assert observer.get_state() == CaptureState()
        observer.close()
        assert observer.get_state() == CaptureState()
        gate.set()
        await observer.aflush()
        assert observer.get_state() == CaptureState()
        assert len(written) == 3

    asyncio.run(scenario())


def test_only_whole_millisecond_durations_are_recorded():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink)
    end = {"type": "tool.end", "capture_status": "complete", "metadata": {}}
    assert observer.emit(**end, duration_ms=1.5) is None
    assert observer.emit(**end, duration_ms=12.0) is not None
    assert observer.emit(**end, duration_ms=7) is not None
    stored = [event["duration_ms"] for event in seen]
    # An integral float is stored as an integer so both emitters write the same bytes.
    assert stored == [12, 7]
    assert [type(value) for value in stored] == [int, int]
    assert '"duration_ms":12' in json.dumps(seen[0], separators=(",", ":"))
    assert observer.get_state().dropped_events == 1


def test_the_default_redactor_folds_case_over_ascii_only():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink)
    observer.emit(**event_fields(metadata={
        "TOKEN": "hide",
        "Api_Key": "hide",
        # A Unicode fold reads the Kelvin sign as a k and the long s as an s. The JavaScript
        # regex does not, so neither does this one.
        "to\u212aen": "keep",
        "\u017fecret": "keep",
    }))
    stored = seen[0]["metadata"]
    assert stored["TOKEN"] == stored["Api_Key"] == "[REDACTED]"
    assert stored["to\u212aen"] == "keep"
    assert stored["\u017fecret"] == "keep"


def test_a_redactor_that_returns_an_equal_copy_still_counts_as_redaction():
    copied, copying_sink = recorder()
    copying = Observer(
        mode="content",
        sink=copying_sink,
        redactor=lambda key, value, path: dict(value) if isinstance(value, dict) else value,
    )
    copying.emit(**event_fields(metadata={"nested": {"x": 1}}, content={"body": "hello"}))
    # Equal by value, a different object by reference. Reference decides.
    assert copied[0]["metadata"] == {"nested": {"x": 1}}
    assert copied[0]["capture_status"] == "redacted"

    kept, keeping_sink = recorder()
    keeping = Observer(
        mode="content", sink=keeping_sink, redactor=lambda key, value, path: value
    )
    keeping.emit(**event_fields(metadata={"nested": {"x": 1}}, content={"body": "hello"}))
    assert kept[0]["capture_status"] == "complete"


def test_emitted_keys_follow_the_wire_schema_declaration_order():
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink, run_id="r", producer_id="p")
    observer.emit(**event_fields(
        parent_event_id="event-0", call_id="call-1", attempt_id="attempt-1",
        candidate_id="candidate-1", claim_id="claim-1", duration_ms=5,
    ))
    declared = list(SCHEMA["properties"])
    assert list(seen[0]) == declared
    observer.emit(type="tool.start", capture_status="complete", metadata={})
    assert list(seen[1]) == [name for name in declared if name in seen[1]]


def test_a_rejected_event_costs_no_sequence_no_id_and_no_clock_read():
    seen, sink = recorder()
    reads = 0
    issued = 0

    def counting_clock():
        nonlocal reads
        reads += 1
        return datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)

    def counting_ids(prefix):
        nonlocal issued
        issued += 1
        return f"{prefix}-{issued}"

    observer = Observer(
        mode="content", sink=sink, run_id="r", producer_id="p",
        clock=counting_clock, id_factory=counting_ids,
    )
    # The same set the TypeScript suite refuses, in the same order. Charging nothing for a
    # rejected event is only safe while both emitters reject exactly these.
    refused = [
        event_fields(oops=1),                                      # a field name the contract lacks
        {"type": "model.request", "capture_status": "complete"},   # metadata is required
        event_fields(metadata=None),
        event_fields(duration_ms=None),                            # None is not absence
        event_fields(duration_ms=2.5),                             # whole milliseconds only
        event_fields(content=None),
        event_fields(call_id=None),
        event_fields(call_id=""),
    ]
    for fields in refused:
        assert observer.emit(**fields) is None
    assert seen == []
    assert observer.get_state() == CaptureState(
        dropped_events=len(refused), capture_gap=True, last_sink_error=GAP
    )
    assert (reads, issued) == (0, 0)
    kept = observer.emit(**event_fields())
    assert (kept["sequence"], kept["event_id"], reads) == (0, "event-1", 1)


@pytest.mark.parametrize("field", [
    "type", "category", "capture_status", "metadata", "content", "duration_ms",
    "parent_event_id", "call_id", "attempt_id", "candidate_id", "claim_id",
])
def test_a_field_passed_as_none_is_refused_rather_than_read_as_absent(field):
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink)
    # None is not absence. The TypeScript emitter refuses a null here, so this one does too.
    assert observer.emit(**event_fields(**{field: None})) is None
    assert seen == []
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_importing_the_observer_does_not_import_the_evaluator():
    program = (
        "import json, sys; import scaneval.observer; "
        "print(json.dumps(sorted(m for m in sys.modules if m.startswith('scaneval'))))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    assert completed.returncode == 0, completed.stderr
    loaded = json.loads(completed.stdout)
    assert not [name for name in loaded if name in EVALUATOR_MODULES]
    assert loaded == [name for name in loaded if name == "scaneval" or name.startswith("scaneval.observer")]


def never_settling_sink():
    """An async sink whose write is queued and never finishes. It sleeps on nothing."""

    async def write(event):
        await asyncio.Event().wait()

    return write


def quiet_loop():
    """A caller-owned loop that does not log about the tasks its teardown strands."""
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(lambda loop, context: None)
    return loop


def test_writes_stranded_by_a_torn_down_loop_are_counted_not_reported_clean():
    observer = Observer(mode="content", sink=never_settling_sink())
    loop = quiet_loop()

    async def queue_three():
        for _ in range(3):
            assert observer.emit(**event_fields()) is not None
        # Let the writes start, so they are genuinely in flight rather than merely scheduled.
        await asyncio.sleep(0)

    try:
        loop.run_until_complete(queue_three())
        # While the loop lives the writes are not lost: only that loop can settle them.
        assert observer.get_state() == CaptureState()
    finally:
        loop.close()
    # The loop is gone, so those three writes can never run and the sink saw none of them.
    # A capture state that still read clean would claim a delivery that never happened.
    assert observer.get_state() == CaptureState(
        dropped_events=3, capture_gap=True, last_sink_error=GAP
    )
    # Counted once: reaping the same stranded writes again adds nothing.
    assert observer.get_state().dropped_events == 3


def test_aflush_from_another_loop_contains_the_failure_and_keeps_the_evidence():
    observer = Observer(mode="content", sink=never_settling_sink())
    owner = quiet_loop()

    async def queue_one():
        assert observer.emit(**event_fields()) is not None
        await asyncio.sleep(0)

    owner.run_until_complete(queue_one())

    async def flush_from_elsewhere():
        # A different loop. Gathering another loop's write raises, and an emitter that emptied
        # the pending set before gathering would erase the record of what it failed to settle.
        await observer.aflush()
        await observer.aclose()

    asyncio.run(flush_from_elsewhere())
    # Nothing raised into the caller, and nothing was counted: the write is still the owning
    # loop's to run, so it is not lost yet.
    assert observer.get_state() == CaptureState()
    owner.close()
    # The evidence survived the failed flush, so the loss is visible once the loop is gone.
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_elapsed_time_comes_from_a_real_monotonic_source_not_an_injected_clock():
    seen, sink = recorder()
    reads = 0

    def walking_backwards():
        nonlocal reads
        reads += 1
        # A wall clock a caller may legitimately inject, adjusted backwards between reads.
        return datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc) - timedelta(seconds=reads)

    observer = Observer(mode="metadata", sink=sink, clock=walking_backwards)
    assert observer.observe(TOOL_START, completion, lambda e, d: completion(d), lambda: 42) == 42
    # Two events, two timestamps, and not one clock read spent on the duration: measuring a
    # span with a wall clock would record an elapsed time that never elapsed.
    assert reads == 2
    assert seen[1]["metadata"]["measured"] is True
    assert isinstance(seen[1]["duration_ms"], int)
    # Nothing sleeps here, so the real monotonic span is small, and it is never negative.
    assert 0 <= seen[1]["duration_ms"] < 1000
    # No gap marker: the span was measured, not fabricated and not abandoned.
    assert "observer_capture_gap" not in seen[1]["metadata"]
    assert observer.get_state() == CaptureState()


def test_dropped_events_counts_lost_events_not_degraded_ones():
    seen, sink = recorder()
    degraded = Observer(
        mode="metadata", sink=sink, clock=raising("clock"), id_factory=raising("ids")
    )
    assert degraded.emit(**event_fields()) is not None
    # The event carries a fabricated ID and an epoch timestamp and says so, and it reached the
    # sink intact enough to read. Nothing was lost, so nothing is counted as dropped.
    assert len(seen) == 1
    assert seen[0]["capture_status"] == "partial"
    assert seen[0]["metadata"]["observer_capture_gap"] is True
    assert degraded.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )

    # A sink that refuses the write is the case the counter exists for.
    lost = Observer(mode="metadata", sink=raising("disk full"))
    assert lost.emit(**event_fields()) is not None
    assert lost.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_callable_object_whose_call_is_a_generator_is_refused_at_construction():
    class GeneratorCall:
        def __call__(self, event):
            yield event

    class AsyncGeneratorCall:
        async def __call__(self, event):
            yield event

    # Calling either returns an iterator and writes nothing, exactly as a bare generator
    # function does, so the same wiring mistake is caught in the same place.
    for unusable in (GeneratorCall(), AsyncGeneratorCall()):
        with pytest.raises(ValueError):
            Observer(mode="content", sink=unusable)

    class GeneratorWriteMethod:
        def write(self, event):
            yield event

    with pytest.raises(ValueError):
        Observer(mode="metadata", sink=GeneratorWriteMethod())


def test_a_recording_mode_without_a_sink_counts_every_event_as_lost():
    observer = Observer(
        mode="metadata", run_id="r", producer_id="p", clock=clock(), id_factory=ids()
    )
    event = observer.emit(**event_fields())
    # The event is built and returned, so the observer still works as a builder. It reached
    # nobody, and the capture state says that rather than reporting a clean run.
    assert event["sequence"] == 0 and event["event_id"] == "event-1"
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )
    observer.emit(**event_fields())
    assert observer.get_state().dropped_events == 2


def test_a_write_that_cannot_be_scheduled_leaks_no_unawaited_coroutine():
    handed: list = []

    async def write(event):
        return None

    def sink(event):
        awaitable = write(event)
        handed.append(awaitable)
        return awaitable

    async def scenario():
        observer = Observer(mode="content", sink=sink)
        loop = asyncio.get_running_loop()

        def refuse(*args, **kwargs):
            raise RuntimeError("no more tasks")

        loop.create_task = refuse
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                assert observer.emit(**event_fields()) is not None
                gc.collect()
        finally:
            # The loop is the test runner's, and its own teardown schedules tasks too.
            del loop.create_task
        return observer.get_state(), [str(entry.message) for entry in caught]

    state, messages = asyncio.run(scenario())
    # Both the write and the coroutine that would have awaited it are closed. Discarding only
    # one leaves the other un-awaited, and an un-awaited coroutine prints a RuntimeWarning
    # into the caller's process at collection time.
    assert [message for message in messages if "never awaited" in message] == []
    assert handed[0].cr_frame is None
    assert state == CaptureState(dropped_events=1, capture_gap=True, last_sink_error=GAP)


class Probed:
    """A value whose every attribute lookup is caller code that must not run."""

    def __init__(self):
        object.__setattr__(self, "reads", [])

    def __getattr__(self, name):
        self.reads.append(name)
        raise RuntimeError("instrumentation read an attribute off a caller's value")


def test_observe_async_reads_nothing_off_the_value_an_operation_returned():
    probe = Probed()
    off = Observer(mode="off", id_factory=raising("ids"), clock=raising("clock"))

    async def scenario(observer):
        return await observer.observe_async(
            event_fields(), lambda d: event_fields(), lambda e, d: event_fields(), lambda: probe
        )

    # Off mode is a pass-through in both forms: the synchronous observe never looks at the
    # value, so the coroutine form must not look either.
    assert asyncio.run(scenario(off)) is probe
    assert off.observe(event_fields(), raising("s"), raising("f"), lambda: probe) is probe
    assert probe.reads == []
    assert off.get_state() == CaptureState()

    # Awaitability is a property of the type, so a recording mode does not probe it either.
    seen, sink = recorder()
    recording = Observer(mode="metadata", sink=sink, clock=clock())
    assert asyncio.run(scenario(recording)) is probe
    assert probe.reads == []
    assert len(seen) == 2


def test_flush_releases_the_private_loop_and_close_releases_the_next_one():
    loops: list = []

    async def sink(event):
        loops.append(asyncio.get_running_loop())

    observer = Observer(mode="metadata", sink=sink)
    assert observer.emit(**event_fields()) is not None
    assert loops[0].is_closed() is False
    observer.flush()
    # The loop is the emitter's own resource, so a flush releases it rather than holding a
    # selector open until close.
    assert loops[0].is_closed() is True
    assert observer.emit(**event_fields()) is not None
    assert len(loops) == 2 and loops[1] is not loops[0]
    observer.close()
    assert loops[1].is_closed() is True
    assert observer.get_state() == CaptureState()


def test_close_forgets_writes_whose_loop_is_already_gone():
    observer = Observer(mode="content", sink=never_settling_sink())
    loop = quiet_loop()

    async def queue_one():
        assert observer.emit(**event_fields()) is not None
        await asyncio.sleep(0)

    loop.run_until_complete(queue_one())
    loop.close()
    observer.close()
    # close counts the stranded write once and stops holding a task that can never run.
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )
    assert observer.emit(**event_fields()) is None
    assert observer.get_state().dropped_events == 2


def cancel_queued_writes(before):
    """Cancel the write tasks emitted since ``before`` and report them. Nothing sleeps here."""
    queued = asyncio.all_tasks() - before
    for task in queued:
        task.cancel()
    return queued


def test_a_write_cancelled_before_it_starts_is_a_counted_lost_event():
    """A write that never ran reached no sink, so it is a loss, not a clean state.

    Cancelling a task before its first step closes the wrapper coroutine at its first line, so
    no guard inside it ever runs and nothing records the loss from the inside. The done
    callback used to just forget the task, which left an event nobody received behind
    ``dropped_events`` zero and no capture gap: absence of an event read as absence of an
    action.
    """
    written: list[dict] = []

    async def sink(event):
        written.append(event)

    async def scenario():
        observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            before = asyncio.all_tasks()
            assert observer.emit(**event_fields()) is not None
            queued = cancel_queued_writes(before)
            assert len(queued) == 1
            # Two turns of the loop: one delivers the cancellation, one runs the callback.
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            cancelled = [task.cancelled() for task in queued]
            queued.clear()
            gc.collect()
        return observer.get_state(), cancelled, [str(entry.message) for entry in caught]

    state, cancelled, messages = asyncio.run(scenario())
    assert cancelled == [True]
    assert written == []
    assert state == CaptureState(dropped_events=1, capture_gap=True, last_sink_error=GAP)
    # The write the cancelled wrapper never awaited is closed, so instrumentation that failed
    # does not also print a RuntimeWarning into the harness's output.
    assert [message for message in messages if "never awaited" in message] == []


def test_aflush_counts_a_write_cancelled_before_it_started():
    """The same loss, reached through the flush that gathers the write instead.

    ``aflush`` takes the batch out of the pending set before awaiting it, so the reaper and the
    done callback can no longer see those writes: the cancellation gather reports is the only
    evidence left that the event reached nobody, and counting it there is what keeps the two
    paths agreeing.
    """
    written: list[dict] = []

    async def sink(event):
        written.append(event)

    async def scenario():
        observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
        before = asyncio.all_tasks()
        assert observer.emit(**event_fields()) is not None
        cancel_queued_writes(before)
        await observer.aflush()
        return observer.get_state()

    assert written == []
    assert asyncio.run(scenario()) == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_write_cancelled_after_it_started_is_counted_exactly_once():
    """The guard inside the write records that loss, and no second path counts it again."""
    started = []

    async def sink(event):
        started.append(event)
        await asyncio.Event().wait()

    async def scenario():
        observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
        before = asyncio.all_tasks()
        assert observer.emit(**event_fields()) is not None
        # One turn lets the write start, so cancellation lands inside the guard rather than
        # before it.
        await asyncio.sleep(0)
        queued = cancel_queued_writes(before)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        queued.clear()
        return observer.get_state()

    assert asyncio.run(scenario()) == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )
    assert len(started) == 1


def cancelled_during_flush(settle):
    """Cancel the awaiting task while a queued write is still waiting for its first step.

    The cancel callback is scheduled before ``emit`` creates the write task, so the loop
    delivers it while the flush is already suspended on its gather and the write has not run
    yet. ``gather`` then cancels that write, it settles as cancelled with no guard of its own
    having run, and the cancellation travels on out of the await. Nothing sleeps and no real
    clock is read: the ordering is the ready queue's, not a timer's.
    """
    written: list[dict] = []

    async def sink(event):
        written.append(event)

    async def scenario():
        observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
        before = asyncio.all_tasks()
        asyncio.get_running_loop().call_soon(asyncio.current_task().cancel)
        assert observer.emit(**event_fields()) is not None
        queued = asyncio.all_tasks() - before
        try:
            await settle(observer)
        except asyncio.CancelledError:
            pass
        return observer.get_state(), [task.cancelled() for task in queued]

    state, cancelled = asyncio.run(scenario())
    return state, cancelled, written


def test_aflush_counts_a_write_its_own_cancellation_settled_as_cancelled():
    """The batch is out of the pending set, so the cancellation is the last record of it.

    ``aflush`` removes the batch it is about to gather from the pending set, and a cancellation
    of the awaiting task makes ``gather`` raise instead of returning results. The write it
    cancelled before that write's first step therefore ran no guard inside itself, is invisible
    to the reaper and to the done callback, and never appeared in any result list: it used to
    leave an event that reached no sink behind a capture state reading zero dropped events and
    no gap at all. It is accounted in the batch now, before the cancellation is re-raised.
    """
    state, cancelled, written = cancelled_during_flush(lambda observer: observer.aflush())
    # The premise: the write really did settle as cancelled without ever reaching the sink.
    assert cancelled == [True]
    assert written == []
    # The conclusion: that event is a counted loss, not a clean state.
    assert state == CaptureState(dropped_events=1, capture_gap=True, last_sink_error=GAP)


def test_aclose_counts_the_writes_a_cancellation_settled_before_it_closes():
    """The same loss through the close, which is the path a caller's timeout actually takes."""
    state, cancelled, written = cancelled_during_flush(lambda observer: observer.aclose())
    assert cancelled == [True]
    assert written == []
    assert state == CaptureState(dropped_events=1, capture_gap=True, last_sink_error=GAP)


def test_last_sink_error_is_one_opaque_constant_for_every_failure():
    seen, sink = recorder()
    failing_sink = Observer(mode="content", sink=raising("disk full: /tmp/trace.jsonl"))
    failing_clock = Observer(mode="content", sink=sink, clock=raising("clock says 2026"))
    failing_redactor = Observer(mode="content", sink=sink, redactor=raising("policy exploded"))
    failing_timer = Observer(mode="metadata", sink=sink, monotonic=raising("no timer"))
    for observer in (failing_sink, failing_clock, failing_redactor):
        observer.emit(**event_fields())
    failing_timer.observe(TOOL_START, completion, lambda e, d: completion(d), lambda: 1)

    reported = {
        observer.get_state().last_sink_error
        for observer in (failing_sink, failing_clock, failing_redactor, failing_timer)
    }
    # Four different failures, one message. The field says that capture broke, never which
    # call broke or why: a sink's own text can quote the payload it refused to write.
    assert reported == {GAP}
    assert "disk full" not in GAP and "policy exploded" not in GAP
    # The documented promise is that one constant, not a failure class it cannot produce.
    assert GAP in CaptureState.__doc__
    assert "names the failure class" not in CaptureState.__doc__


def test_redaction_follows_javascript_strict_inequality():
    seen, sink = recorder()
    rebuilt: list[bool] = []

    def rebuilding(key, value, path):
        if isinstance(value, str):
            copy = "".join(list(value))
            rebuilt.append(copy is not value)
            return copy
        if isinstance(value, int) and not isinstance(value, bool):
            copy = int(str(value))
            rebuilt.append(copy is not value)
            return copy
        return value

    scalars = Observer(mode="content", sink=sink, redactor=rebuilding)
    scalars.emit(
        type="tool.start", capture_status="complete",
        metadata={"tool": "grep", "matched": 10**18}, content={},
    )
    # Every scalar came back as a different Python object holding the same value. JavaScript
    # gives a scalar no separate identity, so an equal string or number is not a replacement
    # and this event is not redacted. Asking ``is`` would have said it was.
    assert rebuilt == [True, True]
    assert seen[0]["capture_status"] == "complete"
    assert seen[0]["metadata"] == {"tool": "grep", "matched": 10**18}

    # A container is compared by identity, so an equal rebuild is a replacement.
    containers, container_sink = recorder()
    Observer(
        mode="metadata", sink=container_sink,
        redactor=lambda key, value, path: dict(value) if isinstance(value, dict) else value,
    ).emit(type="tool.start", capture_status="complete", metadata={"flags": {"case": True}})
    assert containers[0]["capture_status"] == "redacted"

    # true !== 1 under strict equality, while Python's == calls them equal.
    swapped, swap_sink = recorder()
    Observer(
        mode="metadata", sink=swap_sink,
        redactor=lambda key, value, path: 1 if value is True else value,
    ).emit(type="tool.start", capture_status="complete", metadata={"cached": True})
    assert swapped[0]["capture_status"] == "redacted"
    assert swapped[0]["metadata"] == {"cached": 1}


def nested_payload(levels: int) -> dict:
    """A payload of exactly ``levels`` nested containers, the outer object included."""
    payload: dict = {"leaf": True}
    for _ in range(levels - 1):
        payload = {"next": payload}
    return payload


def test_a_payload_nested_deeper_than_the_shared_limit_is_a_capture_gap():
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink)
    assert observer.emit(**event_fields(metadata=nested_payload(MAX_PAYLOAD_DEPTH))) is not None
    assert observer.emit(**event_fields(metadata=nested_payload(MAX_PAYLOAD_DEPTH + 1))) is None
    assert observer.emit(**event_fields(content=nested_payload(MAX_PAYLOAD_DEPTH + 1))) is None
    # A list is a container too, so mixing shapes buys no extra depth.
    assert observer.emit(**event_fields(metadata={"items": [nested_payload(MAX_PAYLOAD_DEPTH)]})) is None
    assert len(seen) == 1
    assert observer.get_state() == CaptureState(
        dropped_events=3, capture_gap=True, last_sink_error=GAP
    )

    # A redactor is caller code, and its output is measured at the depth it would occupy, so
    # it cannot hand back a value deeper than the shared limit.
    smuggled, smuggling_sink = recorder()
    smuggling = Observer(
        mode="content", sink=smuggling_sink,
        redactor=lambda key, value, path: (
            nested_payload(MAX_PAYLOAD_DEPTH) if key == "body" else value
        ),
    )
    assert smuggling.emit(
        type="tool.start", capture_status="complete", metadata={}, content={"body": "x"}
    ) is None
    assert smuggled == []
    assert smuggling.get_state().dropped_events == 1


def test_a_duration_beyond_the_safe_integer_bound_is_refused():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink)
    end = {"type": "tool.end", "capture_status": "complete", "metadata": {}}
    assert observer.emit(**end, duration_ms=9007199254740991) is not None
    # Past 2 ** 53 - 1 a JSON number stops round-tripping, so a value Python can hold exactly
    # would reach a JavaScript reader as a different one.
    assert observer.emit(**end, duration_ms=9007199254740992) is None
    assert observer.emit(**end, duration_ms=1e300) is None
    assert [event["duration_ms"] for event in seen] == [9007199254740991]
    assert observer.get_state() == CaptureState(
        dropped_events=2, capture_gap=True, last_sink_error=GAP
    )


def test_an_elapsed_span_beyond_the_safe_integer_bound_is_omitted_not_written():
    seen, sink = recorder()
    ticks = iter([0.0, 1e300])
    observer = Observer(
        mode="metadata", sink=sink, clock=clock(), monotonic=lambda: next(ticks)
    )
    assert observer.observe(TOOL_START, completion, lambda e, d: completion(d), lambda: 42) == 42
    # A span the wire cannot carry exactly is treated as unmeasurable: the completion event is
    # still recorded, without a duration, and says its own capture was partial.
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
    assert "duration_ms" not in seen[1]
    assert seen[1]["metadata"]["measured"] is False
    assert seen[1]["capture_status"] == "partial"
    assert seen[1]["metadata"]["observer_capture_gap"] is True
    assert observer.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )


def test_a_timing_hook_the_emitter_cannot_check_never_stops_the_operation():
    """Checking a reading is caller code too, so its failure costs the duration, not the work.

    An integer too large to convert to a float raises ``OverflowError`` inside ``math.isfinite``
    and ``float``, and that raise used to travel out of ``observe`` before the operation ran:
    instrumentation aborted the work it was wired in to measure. It is contained now, and the
    completion event is still written, without a duration and marked as a gap.
    """

    class UnconvertibleInt(int):
        def __float__(self):
            raise ValueError("this reading cannot be checked")

    for unusable in (10**400, UnconvertibleInt(1)):
        seen, sink = recorder()
        ran: list[str] = []
        observer = Observer(
            mode="metadata", sink=sink, clock=clock(), monotonic=lambda: unusable
        )

        def operation():
            ran.append("ran")
            return "value"

        assert observer.observe(
            TOOL_START, completion, lambda error, duration: completion(duration), operation
        ) == "value"
        assert ran == ["ran"]
        assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
        assert "duration_ms" not in seen[1]
        assert seen[1]["metadata"]["measured"] is False
        assert seen[1]["capture_status"] == "partial"
        assert seen[1]["metadata"]["observer_capture_gap"] is True
        # The event was delivered, so the failure is a gap and not a dropped event.
        assert observer.get_state() == CaptureState(
            dropped_events=0, capture_gap=True, last_sink_error=GAP
        )


def test_a_timing_hook_that_cannot_be_checked_never_stops_an_async_operation():
    """The coroutine form contains the same reading the same way."""
    seen, sink = recorder()
    ran: list[str] = []
    observer = Observer(mode="metadata", sink=sink, clock=clock(), monotonic=lambda: 10**400)

    async def operation():
        ran.append("ran")
        return 42

    async def scenario():
        return await observer.observe_async(
            TOOL_START, completion, lambda error, duration: completion(duration), operation
        )

    assert asyncio.run(scenario()) == 42
    assert ran == ["ran"]
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
    assert "duration_ms" not in seen[1]
    assert seen[1]["capture_status"] == "partial"
    assert observer.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )


def test_closing_a_write_suspended_mid_flight_counts_one_lost_event_not_two():
    """One lost event counts once, even when the emitter tears the suspended write down itself.

    ``_drive`` closes a write it could not finish, which raises ``GeneratorExit`` inside the
    coroutine that was awaiting the sink. That guard used to record the loss and then the path
    that closed it recorded the same loss again, so one event that reached no sink was reported
    as two dropped events. A close is not the write failing: it is the emitter discarding a
    write whose loss the closing path is already counting, so the guard re-raises it now.
    """
    written: list[dict] = []

    async def sink(event):
        loop = asyncio.get_running_loop()
        # Queue a stop, so the private loop gives up while this write is still suspended.
        # Nothing sleeps here: the stop is scheduled, not timed, and the wait never settles.
        loop.call_soon(loop.stop)
        await asyncio.Event().wait()
        written.append(event)

    observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
    assert observer.emit(**event_fields()) is not None
    assert written == []
    # One event, one loss. Two would say the trace lost an event the harness never emitted.
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )
    observer.close()
    assert observer.get_state().dropped_events == 1


def test_aflush_lets_a_cancellation_aimed_at_the_caller_through():
    """A cancellation of the awaiting task is the caller's, not a capture gap to swallow.

    ``aflush`` documents a caller-applied timeout as the mitigation for a sink that never
    returns, and a timeout works by cancelling the task that awaits it. Catching that
    cancellation, marking a gap and returning normally defeated exactly that mitigation: the
    awaiting task finished as though the writes had settled. ``gather`` hands a cancelled write
    back in its results rather than raising it, so a cancellation raised out of that await is
    the caller's and is re-raised unchanged.
    """

    async def scenario():
        observer = Observer(
            mode="metadata", sink=never_settling_sink(), clock=clock(), id_factory=ids()
        )
        assert observer.emit(**event_fields()) is not None
        # One turn starts the write, one lets the flush reach its gather. Neither sleeps.
        await asyncio.sleep(0)
        flush = asyncio.ensure_future(observer.aflush())
        await asyncio.sleep(0)
        flush.cancel()
        with pytest.raises(asyncio.CancelledError):
            await flush
        assert flush.cancelled()
        # The cancellation took the write with it, so the event reached nobody: counted once,
        # by the guard inside the write that saw the cancellation arrive.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return observer.get_state()

    assert asyncio.run(scenario()) == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_caller_timeout_around_aclose_reports_a_timeout_and_still_closes():
    """The mitigation the docstring prescribes, run end to end against a sink that never returns.

    The deadline is already past when the block is entered, so the timeout fires on the next
    turn of the loop and nothing waits on real time. A swallowed cancellation used to make this
    block finish quietly, which is the harness being told capture completed when it did not.
    """

    async def scenario():
        observer = Observer(
            mode="metadata", sink=never_settling_sink(), clock=clock(), id_factory=ids()
        )
        assert observer.emit(**event_fields()) is not None
        await asyncio.sleep(0)
        loop = asyncio.get_running_loop()
        with pytest.raises(TimeoutError):
            async with asyncio.timeout_at(loop.time()):
                await observer.aclose()
        # The caller asked for a close and gets one: a late event is refused rather than
        # allowed to postdate the run, and the state reports the write the timeout cancelled.
        assert observer.closed
        assert observer.emit(**event_fields()) is None
        await asyncio.sleep(0)
        return observer.get_state()

    state = asyncio.run(scenario())
    assert state.capture_gap is True
    assert state.last_sink_error == GAP
    # The cancelled write and the emit refused after the close, each counted once.
    assert state.dropped_events == 2


def test_a_sink_that_returns_an_undriven_generator_counts_every_event_as_lost():
    """A write that hands back an iterator wrote nothing, so the event reached nobody.

    The wiring guards classify a callable, so they catch a writer or a sink that *is* a
    generator function. One that merely returns a generator passes both ``create_jsonl_sink``
    and the constructor, runs none of its body, raises nothing, and used to leave a capture
    state reading clean while every event was lost. It is caught at write time now, on the
    value the sink handed back, in both languages.
    """
    lines: list[str] = []

    def write_line(line):
        # An ordinary function that returns a generator: calling it runs none of this body.
        return (lines.append(line) for _ in (0,))

    # Still accepted at wiring time: no check on a callable can see what it will return.
    sink = create_jsonl_sink(write_line)
    observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
    assert observer.emit(**event_fields()) is not None
    assert lines == []
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )
    # One loss per event it swallowed, not one for the wiring.
    assert observer.emit(**event_fields()) is not None
    assert observer.get_state().dropped_events == 2

    def generator_returning_sink(event):
        return (event for _ in (0,))

    bare = Observer(mode="metadata", sink=generator_returning_sink, clock=clock(), id_factory=ids())
    assert bare.emit(**event_fields()) is not None
    assert bare.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )

    def async_generator_returning_sink(event):
        async def stream():
            yield event

        return stream()

    streamed = Observer(
        mode="metadata", sink=async_generator_returning_sink, clock=clock(), id_factory=ids()
    )
    assert streamed.emit(**event_fields()) is not None
    assert streamed.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )


def test_a_sink_returning_an_awaitable_is_still_driven_not_counted_as_a_generator():
    """The control for the check above: an awaitable write still runs and loses nothing.

    A generator :func:`types.coroutine` marked is a generator object and an awaitable at once,
    so it is driven, exactly as ``await`` would drive it, rather than read as an iterator
    nobody consumes.
    """
    written: list[dict] = []

    async def async_sink(event):
        written.append(event)

    observer = Observer(mode="metadata", sink=async_sink, clock=clock(), id_factory=ids())
    assert observer.emit(**event_fields()) is not None
    observer.flush()
    assert [event["type"] for event in written] == ["model.request"]
    assert observer.get_state() == CaptureState()

    @types.coroutine
    def marked(event):
        written.append(event)
        return
        yield  # pragma: no cover - makes this a generator function

    def returns_a_marked_awaitable(event):
        # A generator object that ``await`` accepts. It is a generator and an awaitable at
        # once, so the write-time check must read it as the awaitable it is and drive it.
        return marked(event)

    driven = Observer(
        mode="metadata", sink=returns_a_marked_awaitable, clock=clock(), id_factory=ids()
    )
    assert driven.emit(**event_fields()) is not None
    driven.flush()
    assert len(written) == 2
    assert driven.get_state() == CaptureState()


def interrupting(*_args, **_kwargs):
    """A caller hook that raises the caller's own interrupt rather than an instrumentation one."""
    raise KeyboardInterrupt("operator")


class InterruptingMapping(Mapping):
    """A start Mapping that interrupts the moment the emitter reads it.

    Reading a caller's Mapping is running the caller's code, so this is one more hook, not a
    payload: ``dict(fields)`` in :meth:`Observer._snapshot` is what runs ``__iter__`` here.
    """

    def __iter__(self):
        raise KeyboardInterrupt("operator")

    def __len__(self):
        return 0

    def __getitem__(self, key):
        raise KeyError(key)


def test_every_caller_hook_that_raises_an_interrupt_stops_the_operation_as_documented():
    """The exception to "instrumentation never alters the caller", named rather than hidden.

    ``KeyboardInterrupt`` and ``SystemExit`` are the caller's own and are re-raised where the
    hook raised them. ``observe`` emits the start event and takes the first elapsed-time reading
    before the operation runs, so every caller hook either step touches can stop the work: the
    start Mapping, the redactor, the clock, the ID factory, the sink, and the elapsed-time
    source. The class docstring named only the timing hook, which is one of six, and this pins
    the list rather than the one member of it that was easiest to reach.
    """
    ran: list[str] = []

    def observer_with(**hooks):
        seen, sink = recorder()
        settings = {"clock": clock(), "id_factory": ids(), "sink": sink}
        settings.update(hooks)
        return seen, Observer(mode="metadata", run_id="r", producer_id="p", **settings)

    wired = {
        "start_mapping": observer_with(),
        "redactor": observer_with(redactor=interrupting),
        "clock": observer_with(clock=interrupting),
        "id_factory": observer_with(id_factory=interrupting),
        "sink": observer_with(sink=interrupting),
        "monotonic": observer_with(monotonic=interrupting),
    }
    # A metadata key of its own, because the redactor is called per key and an empty payload
    # would never reach it: the hook that cannot run cannot stop anything.
    start_event = dict(TOOL_START, metadata={"tool": "grep"})
    for name, (seen, observer) in wired.items():
        start = InterruptingMapping() if name == "start_mapping" else start_event
        with pytest.raises(KeyboardInterrupt):
            observer.observe(
                start, completion, lambda error, duration: completion(duration),
                lambda: ran.append(name),
            )
        # The operation never ran, so there is no completion event to write either.
        assert ran == [], name
        # Only the timing hook lets the start event through: it is read after that event is
        # written, which is exactly why it costs no event of its own.
        assert [event["type"] for event in seen] == (["tool.start"] if name == "monotonic" else [])

    # Every other failure from the same hooks is contained and the operation still runs.
    seen, contained = observer_with(
        redactor=raising("redactor"), monotonic=raising("monotonic"), sink=recorder()[1]
    )
    assert contained.observe(
        TOOL_START, completion, lambda error, duration: completion(duration),
        lambda: ran.append("contained") or "value",
    ) == "value"
    assert ran == ["contained"]

    # The docstring names every hook that can do this instead of claiming it away or naming one.
    claim = " ".join(Observer.__doc__.split())
    assert "KeyboardInterrupt` and :class:`SystemExit` are the single exception" in claim
    assert (
        "the start Mapping, the redactor, the clock, the ID factory, the sink, and the "
        "elapsed-time source can each stop it" in claim
    )
    assert "it never stops the operation it was wired in to measure from running" not in claim
    assert "with one exception" not in claim


def test_an_interrupt_that_stops_an_event_counts_the_event_it_lost():
    """An interrupt travels on, but the event it stopped reached no sink and is counted.

    A redactor, a caller's Mapping, the clock and the ID factory used to lose their event with a
    capture state reading zero dropped events, no gap, and no sink error: a run cut short by an
    operator reported that it had recorded everything it was handed. The interrupt is still the
    caller's and is still re-raised unchanged; only the accounting changed. ``dropped_events``
    counts events that reached no sink, and these reached no sink.
    """
    clean = CaptureState()
    lost = CaptureState(dropped_events=1, capture_gap=True, last_sink_error=GAP)

    def lose_one(**hooks):
        seen, sink = recorder()
        settings = {"clock": clock(), "id_factory": ids(), "sink": sink}
        settings.update(hooks)
        observer = Observer(mode="metadata", run_id="r", producer_id="p", **settings)
        fields = hooks.pop("fields", None) or event_fields()
        with pytest.raises(KeyboardInterrupt):
            observer.emit(**fields)
        assert seen == []
        return observer.get_state()

    assert lose_one(redactor=interrupting) == lost
    assert lose_one(clock=interrupting) == lost
    assert lose_one(id_factory=interrupting) == lost
    assert lose_one(sink=interrupting) == lost

    # The start Mapping is read through observe, which is the only entry that takes one.
    seen, sink = recorder()
    mapping_observer = Observer(
        mode="metadata", sink=sink, clock=clock(), id_factory=ids(), run_id="r", producer_id="p"
    )
    ran: list[str] = []
    with pytest.raises(KeyboardInterrupt):
        mapping_observer.observe(
            InterruptingMapping(), completion, lambda error, duration: completion(duration),
            lambda: ran.append("ran"),
        )
    assert (seen, ran) == ([], [])
    assert mapping_observer.get_state() == lost

    # The elapsed-time hook on the completion read is the same loss one step later: the start
    # event was delivered, and the completion event the interrupt stopped was not.
    reads = 0

    def interrupting_at_the_end():
        nonlocal reads
        reads += 1
        if reads == 2:
            raise KeyboardInterrupt("operator")
        return 100.0

    seen, sink = recorder()
    timed = Observer(
        mode="metadata",
        sink=sink,
        clock=clock(),
        id_factory=ids(),
        run_id="r",
        producer_id="p",
        monotonic=interrupting_at_the_end,
    )
    with pytest.raises(KeyboardInterrupt):
        timed.observe(
            TOOL_START, completion, lambda error, duration: completion(duration), lambda: "value"
        )
    assert [event["type"] for event in seen] == ["tool.start"]
    assert timed.get_state() == lost

    # The read taken before the operation is the one case that loses no event at all: nothing
    # was being built, so it is a gap and not a loss, and the counter must not claim otherwise.
    seen, sink = recorder()
    at_the_start = Observer(
        mode="metadata",
        sink=sink,
        clock=clock(),
        id_factory=ids(),
        run_id="r",
        producer_id="p",
        monotonic=interrupting,
    )
    with pytest.raises(KeyboardInterrupt):
        at_the_start.observe(
            TOOL_START, completion, lambda error, duration: completion(duration), lambda: "value"
        )
    assert [event["type"] for event in seen] == ["tool.start"]
    assert at_the_start.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )
    assert clean == CaptureState(dropped_events=0, capture_gap=False, last_sink_error=None)
