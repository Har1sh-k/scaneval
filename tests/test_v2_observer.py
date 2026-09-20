"""Python observer emitter: no-op by default, copied payloads, and visible capture gaps.

These tests pin the behaviors the TypeScript emitter's own suite pins, plus the boundary that
keeps the emitter importable without the evaluator. Nothing here sleeps, reaches the network,
or calls a model: every clock and ID factory is injected and deterministic.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from scaneval.observer import (
    CAPTURE_STATUSES,
    EVENT_CATEGORIES,
    EVENT_TYPES,
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
    observer = Observer(
        mode="content", id_factory=raising("ids"), clock=raising("clock"),
        redactor=raising("redactor"),
    )
    assert observer.run_id == "run-fallback-1"
    assert observer.producer_id == "producer-fallback-2"
    assert observer.emit(**event_fields()) is None
    assert observer.get_state().dropped_events == 3
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


def test_observe_returns_the_value_and_records_a_duration():
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink, clock=clock())
    start = {"type": "tool.start", "capture_status": "complete", "metadata": {}}
    done = lambda duration_ms: {
        "type": "tool.end", "capture_status": "complete", "duration_ms": duration_ms, "metadata": {}
    }
    assert observer.observe(start, done, lambda error, duration_ms: done(duration_ms), lambda: 42) == 42
    assert [event["type"] for event in seen] == ["tool.start", "tool.end"]
    # Whole milliseconds, measured from the injected clock because no monotonic source was given.
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
    observer = Observer(mode="metadata", sink=sink, clock=clock())
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
    assert observer.get_state() == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
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
    assert observer.get_state().dropped_events == 2


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
