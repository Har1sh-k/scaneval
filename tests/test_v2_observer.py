"""Python observer emitter: no-op by default, copied payloads, and visible capture gaps.

These tests pin the behaviors the TypeScript emitter's own suite pins, plus the boundary that
keeps the emitter importable without the evaluator. Nothing here sleeps, reaches the network,
or calls a model: every clock and ID factory is injected and deterministic.
"""

from __future__ import annotations

import ast
import asyncio
from collections.abc import Mapping
from copy import deepcopy
import dataclasses
from datetime import datetime, timedelta, timezone
import gc
import itertools
import json
import math
import os
from pathlib import Path
import re
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
# JavaScript's Number.MAX_SAFE_INTEGER, the largest integer the wire carries in either
# language, spelled here rather than imported so the test states the bound it is checking.
MAX_SAFE_INTEGER = 2**53 - 1
# The smallest magnitude both languages spell in plain decimal notation, and so the smallest
# non-integral number a payload can carry.
MIN_PLAIN_DECIMAL = 1e-4
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
    """``off`` mode consumes no ID from the factory; it does not discard the caller's own.

    The guide said "in ``off`` mode both are the string ``off``" until a review read it against
    this. What ``off`` mode owes the caller is that no ID factory runs, and the literal is the
    fallback for an ID that was not supplied or was not usable, not a replacement for one that
    was. A harness naming its run once and building an observer per mode would otherwise find
    the ``off`` one reporting a different run than the rest.
    """
    observer = Observer(run_id="r", producer_id="p", id_factory=raising("ids"))
    assert (observer.run_id, observer.producer_id) == ("r", "p")
    absent = Observer(id_factory=raising("ids"))
    assert (absent.run_id, absent.producer_id) == ("off", "off")
    # Unusable is the other fallback: an empty string and a non-string are not IDs.
    unusable = Observer(run_id="", producer_id=7, id_factory=raising("ids"))
    assert (unusable.run_id, unusable.producer_id) == ("off", "off")
    # A recording mode keeps a supplied ID the same way and asks the factory only for the rest,
    # so off mode is not a special case about the caller's IDs, only about the factory.
    recording = Observer(mode="metadata", sink=lambda event: None, run_id="r", id_factory=ids())
    assert (recording.run_id, recording.producer_id) == ("r", "producer-1")


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


def test_a_string_no_utf8_sink_could_encode_is_refused_as_a_capture_gap():
    """A lone surrogate is refused, because writing it loses the event at the sink instead.

    Python holds an unpaired surrogate in a ``str`` and ``json.dumps`` copies it into the line
    unchanged, so the failure lands on the caller's own file, as a ``UnicodeEncodeError`` out of
    ``write_line``, one event at a time. JavaScript escapes the same code unit and writes a line
    that parses, so one payload meant two things. The rule now is one rule, enforced where every
    caller string enters the record: payload values, payload keys, and the link, run and producer
    IDs are all refused when they carry a code point no UTF-8 encoder can write.
    """
    lone = "\ud800"
    lines: list[str] = []
    observer = Observer(mode="content", sink=create_jsonl_sink(lines.append), clock=clock())
    assert observer.emit(**event_fields(metadata={"text": lone})) is None
    assert observer.emit(**event_fields(metadata={"text": "ok"}, content={"text": lone})) is None
    assert observer.emit(**event_fields(metadata={lone: "keyed"})) is None
    assert observer.emit(**event_fields(metadata={"tool": "grep"}, call_id=lone)) is None
    # The redactor's output is caller data too, and goes through the same copy.
    smuggling = Observer(
        mode="metadata",
        sink=create_jsonl_sink(lines.append),
        clock=clock(),
        redactor=lambda key, value, path: lone if key == "smuggled" else value,
    )
    assert smuggling.emit(**event_fields(metadata={"smuggled": "x"})) is None
    assert lines == []
    assert observer.get_state() == CaptureState(
        dropped_events=4, capture_gap=True, last_sink_error=GAP
    )
    assert smuggling.get_state().dropped_events == 1
    # The control: a real astral character is one code point, not a surrogate, and is written.
    # Its UTF-16 spelling is the surrogate pair the TypeScript emitter accepts for the same
    # reason, so a payload either language can write is one both languages write identically.
    astral = Observer(mode="content", sink=create_jsonl_sink(lines.append), clock=clock())
    assert astral.emit(**event_fields(metadata={"clef \U0001d11e": "\U0001d11e"})) is not None
    assert lines[0].encode("utf-8").decode("utf-8") == lines[0]
    assert astral.get_state() == CaptureState()


def test_every_string_the_emitter_puts_on_the_wire_passes_the_one_validator():
    """The rule is not "payload strings are checked": it is every caller string on the wire.

    An ID factory is caller code, so the ID it hands back is held to exactly what a caller
    supplied ID is held to, in :func:`~scaneval.observer.emitter._is_id`. A clock is caller code
    too, and a ``datetime`` subclass owns the fields its timestamp is spelled from, so that
    timestamp is held to the same rule rather than trusted for having come from a clock. Both
    failures cost the field and a capture gap, never the event: the sink still took it, so
    nothing is counted as lost. The TypeScript emitter spelled a weaker version of this check inside its own
    ``nextId`` and wrote an event ID no UTF-8 sink could encode; one validator in each language
    is what keeps the two rejection sets identical.
    """
    lone = "\ud800"
    supplied = [lone, "", "event-3"]

    def factory(prefix: str) -> str:
        return supplied.pop(0) if supplied else f"{prefix}-x"

    seen, sink = recorder()
    observer = Observer(
        mode="metadata", sink=sink, run_id="r", producer_id="p", id_factory=factory, clock=clock()
    )
    for _ in range(3):
        observer.emit(**event_fields())
    assert [line["event_id"] for line in seen] == [
        "event-fallback-1",
        "event-fallback-2",
        "event-3",
    ]
    assert [line["capture_status"] for line in seen[:2]] == ["partial", "partial"]
    assert all(line["metadata"]["observer_capture_gap"] is True for line in seen[:2])
    assert observer.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )
    # A run or producer ID the wire refuses is not used at all: the factory supplies one.
    ignored = Observer(mode="metadata", sink=sink, run_id=lone, producer_id="", id_factory=ids())
    assert (ignored.run_id, ignored.producer_id) == ("run-1", "producer-2")
    assert ignored.get_state() == CaptureState()

    class SurrogateYear(int):
        """A year that formats itself as a code point no UTF-8 sink can write."""

        def __format__(self, _spec: str) -> str:
            return lone

    class Hostile(datetime):
        """A clock reading whose year spells itself with a lone surrogate.

        This overrode ``strftime`` until the emitter stopped calling it: every field of a
        timestamp is formatted at a fixed width now, so the platform C library cannot decide
        how wide a year is. A field that is not a plain ``int`` is how a caller's own datetime
        can still put a string of its choosing on the wire, and it is still held to the one
        validator rather than trusted for having come from a clock.
        """

        @property
        def year(self) -> int:
            return SurrogateYear(datetime.year.__get__(self))

    stamped, stamping_sink = recorder()
    fake = Observer(
        mode="metadata",
        sink=stamping_sink,
        run_id="r",
        producer_id="p",
        id_factory=ids(),
        clock=lambda: Hostile(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc),
    )
    degraded = fake.emit(**event_fields())
    assert degraded["timestamp"] == "1970-01-01T00:00:00.000Z"
    assert degraded["capture_status"] == "partial"
    assert stamped[0]["metadata"]["observer_capture_gap"] is True
    assert fake.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )


@pytest.mark.parametrize("year,digits", [(1, "0001"), (99, "0099"), (999, "0999"), (2026, "2026")])
def test_a_timestamp_spells_every_field_itself_at_a_fixed_width(year, digits):
    """A wire value is this contract's to spell, never the platform C library's.

    The emitter formatted the date and time through ``strftime``, which hands ``%Y`` to the C
    library: a year below 1000 comes back as ``0999`` from one libc and ``999`` from another.
    The bare spelling is not an RFC 3339 timestamp, fails the schema's ``date-time`` format, and
    is not the four digits JavaScript's ``toISOString`` writes for the same instant, so two
    machines running the same harness would have written timestamps that do not join. Every
    field is spelled here now, at a fixed width, which is why the year the C library treats
    differently is the interesting case and why the others are checked beside it.
    """
    seen, sink = recorder()
    moment = datetime(year, 1, 2, 3, 4, 5, 600000, tzinfo=timezone.utc)
    observer = Observer(
        mode="metadata", sink=sink, run_id="r", producer_id="p",
        id_factory=ids(), clock=lambda: moment,
    )
    assert observer.emit(**event_fields()) is not None
    assert seen[0]["timestamp"] == f"{digits}-01-02T03:04:05.600Z"
    # The schema's own format checker is the reader this protects: a bare year is not a date-time.
    assert not list(Draft202012Validator(SCHEMA, format_checker=FormatChecker()).iter_errors(seen[0]))
    assert observer.get_state() == CaptureState()


def test_the_capture_gap_key_is_written_over_a_gap_and_never_written_without_one():
    """The emitter can only strengthen the claim that key makes, which is the documented rule.

    ``observer_capture_gap`` was documented as a key the emitter owns and overwrites, full stop,
    which overstated it in the direction that matters least but overstated it all the same:
    nothing is written when no gap occurred, so a caller's own value of that name survives on an
    undegraded event. What a reader actually relies on is the other half, and that half does
    hold: an event degraded by instrumentation carries ``True`` whatever the caller passed, so no
    event ever says "no gap" over a gap. Both halves are pinned here because the document now
    states both.
    """
    seen, sink = recorder()
    clean = Observer(mode="metadata", sink=sink, run_id="r", producer_id="p",
                     clock=clock(), id_factory=ids())
    assert clean.emit(**event_fields(metadata={"observer_capture_gap": False, "model": "x"})) is not None
    # Nothing failed, so nothing is written there and the harness's own value is what is recorded.
    assert seen[0]["metadata"] == {"observer_capture_gap": False, "model": "x"}
    assert seen[0]["capture_status"] == "partial"  # metadata mode, not a gap
    assert clean.get_state() == CaptureState()

    degraded = Observer(mode="metadata", sink=sink, run_id="r", producer_id="p",
                        clock=raising("clock"), id_factory=ids())
    assert degraded.emit(**event_fields(metadata={"observer_capture_gap": False, "model": "x"})) is not None
    # The clock failed, so the caller's False is overwritten rather than left to describe an
    # event built with a fabricated timestamp.
    assert seen[1]["metadata"] == {"observer_capture_gap": True, "model": "x"}
    assert seen[1]["timestamp"] == "1970-01-01T00:00:00.000Z"
    assert degraded.get_state() == CaptureState(
        dropped_events=0, capture_gap=True, last_sink_error=GAP
    )


def test_a_payload_key_that_looks_like_an_array_index_reorders_the_redactor_too():
    """Python's half of the one shape the two emitters accept and do not write alike.

    The documented limit used to say only that the bytes differ. JavaScript orders an
    integer-like own property name ahead of its siblings everywhere it enumerates an object,
    and the redactor walk is one of those places, so the redactor is CALLED in a different
    order in the two languages: ``"2"`` first there, insertion order here. A redactor that
    answers from the key, value and path it is handed stores the same values either way, which
    is why the stored payload below is the one the caller passed; a redactor carrying state
    across calls can store different values in the two languages, and neither emitter can tell.

    The two orders are compared against each other nowhere, because the parity matrix excludes
    such keys by name. Each language pins its own, this one here and JavaScript's in its own
    suite, so the guide's claim about the divergence has both halves behind it.
    """
    order = []
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids(),
                        redactor=lambda key, value, path: order.append(key) or value)
    assert observer.emit(**event_fields(metadata={"alpha": 1, "2": 2, "beta": 3})) is not None
    assert order == ["alpha", "2", "beta"]
    # The stored object is the same one either language stores; only the order of these calls,
    # and of the bytes a sink writes, is the language's own.
    assert seen[0]["metadata"] == {"alpha": 1, "2": 2, "beta": 3}
    assert list(seen[0]["metadata"]) == ["alpha", "2", "beta"]


def test_a_payload_that_is_not_a_mapping_is_refused_in_every_recording_mode():
    """What a payload object is belongs to the contract, never to the recording mode.

    ``metadata`` and ``content`` are held to
    :func:`~scaneval.observer.emitter._is_payload_object`, the one test the copy asks as well,
    and ``content`` is held to it in both recording modes even though only ``content`` mode
    stores it. The mode decides whether content is stored, not what a caller may hand over. The
    TypeScript emitter gated content on a looser test than its copy applied and therefore
    accepted in ``metadata`` mode what it refused in ``content`` mode.

    What is INSIDE a stored payload is the separate rule and still belongs to the copy, which
    is why the last two lines accept in ``metadata`` mode a content that ``content`` mode
    refuses.
    """
    carrier = types.SimpleNamespace(tool="grep")
    for mode in ("metadata", "content"):
        seen, sink = recorder()
        observer = Observer(mode=mode, sink=sink, clock=clock(), id_factory=ids())
        assert observer.emit(**event_fields(metadata=carrier)) is None, mode
        assert observer.emit(**event_fields(content=carrier)) is None, mode
        assert observer.emit(**event_fields(content=["grep"])) is None, mode
        assert seen == [], mode
        assert observer.get_state().dropped_events == 3, mode
        # The control: any Mapping is storable, because the snapshot reads it into a dict.
        assert observer.emit(**event_fields(metadata=types.MappingProxyType({"tool": "grep"})))

    metadata_mode = Observer(mode="metadata", sink=recorder()[1], clock=clock())
    assert metadata_mode.emit(**event_fields(content={"ratio": 1e-5})) is not None
    content_mode = Observer(mode="content", sink=recorder()[1], clock=clock())
    assert content_mode.emit(**event_fields(content={"ratio": 1e-5})) is None


def test_a_payload_number_is_stored_only_when_both_languages_write_it_alike():
    """A number either emitter accepts is one both write as the same bytes, or it is refused.

    Two bounds, both shared with the TypeScript emitter and both applied in one place, on every
    number in every payload. An integral number stops at the safe-integer bound ``duration_ms``
    already carries: past ``2 ** 53 - 1`` a JSON number no longer distinguishes neighbouring
    integers, so Python could write a count a JavaScript reader would read as a different one.
    A non-integral number stops at 1e-4, the smallest magnitude both languages spell in plain
    decimal notation: below it Python writes ``1e-05`` where JavaScript writes ``0.00001``, and
    where both do use an exponent Python pads it to two digits and JavaScript does not. Below
    1e-9 every exponent has two digits in both and the two agree again; those are refused all
    the same, so the accepted range is one window rather than two with a hole between them.

    An integral float is stored as the integer it equals, which is not a coercion but a choice
    between two spellings of one value: JavaScript has one number type and writes ``5`` where
    ``json.dumps`` writes ``5.0``. It is the normalization ``duration_ms`` already gets, for the
    same reason, and it is why ``-0.0`` is stored as ``0``, which is what JavaScript writes.
    """
    lines: list[str] = []
    observer = Observer(mode="content", sink=create_jsonl_sink(lines.append), clock=clock())
    assert observer.emit(**event_fields(
        metadata={
            "ratio": 1.5,
            "floor": MIN_PLAIN_DECIMAL,
            "negative_floor": -MIN_PLAIN_DECIMAL,
            "integral_float": 2.0,
            "negative_zero": -0.0,
            "max_safe": MAX_SAFE_INTEGER,
            "min_safe": -MAX_SAFE_INTEGER,
            "large_integral_float": 1.5e15,
        },
        content={"scores": [1.5, 2.0, -0.0]},
    )) is not None
    stored = json.loads(lines[0])
    assert stored["metadata"]["integral_float"] == 2
    assert stored["metadata"]["large_integral_float"] == 1500000000000000
    # The bytes, not only the values: a trailing ".0" and a "-0" are exactly what the two
    # languages would otherwise disagree about, and both survive a parsed comparison.
    assert '"integral_float":2,' in lines[0]
    assert '"negative_zero":0,' in lines[0]
    assert '"scores":[1.5,2,0]' in lines[0]
    assert '"ratio":1.5' in lines[0] and '"floor":0.0001' in lines[0]
    assert "e-" not in lines[0]

    refused = [
        {"count": 2**53},
        {"count": -(2**53)},
        {"count": 10**30},
        {"count": 1e16},
        {"counts": [1, 2**53]},
        {"nested": {"count": 2**53}},
        {"ratio": 1e-5},
        {"ratio": 9.999999999999999e-05},
        # Below 1e-9 both languages write the same bytes, and both refuse these anyway: the
        # accepted range is one window, not two with a hole between them.
        {"ratio": 1e-10},
    ]
    for payload in refused:
        assert observer.emit(**event_fields(metadata=payload)) is None, payload
    # Content is copied, and therefore number checked, only in content mode, exactly as the
    # depth and surrogate rules are.
    assert observer.emit(**event_fields(content={"count": 2**53})) is None
    metadata_mode = Observer(mode="metadata", sink=create_jsonl_sink(lines.append))
    assert metadata_mode.emit(**event_fields(content={"count": 2**53})) is not None
    # A redactor's replacement is caller data and goes through the same one check.
    smuggling = Observer(
        mode="metadata",
        sink=create_jsonl_sink(lines.append),
        redactor=lambda key, value, path: 2**53 if key == "smuggled" else value,
    )
    assert smuggling.emit(**event_fields(metadata={"smuggled": 1})) is None
    assert len(lines) == 2
    assert observer.get_state() == CaptureState(
        dropped_events=len(refused) + 1, capture_gap=True, last_sink_error=GAP
    )
    assert smuggling.get_state().dropped_events == 1


def test_how_an_emit_call_is_spelled_never_raises_into_the_harness():
    """A field named ``self``, and a stray positional argument, are refused events.

    Python binds arguments before the first statement of a method runs, so neither could be
    contained by any guard inside ``emit``: a caller whose event carried a field named ``self``
    got a :class:`TypeError` out of the call itself and a capture state that counted nothing,
    while the same event named anything else was a counted refusal. The receiver is positional
    only now, so ``self`` is an unknown field name like ``metdata``, and the tuple that
    collects stray positional arguments is not a Mapping, so it reaches the same refusal by the
    same path.
    """
    seen, sink = recorder()
    observer = Observer(
        mode="metadata", sink=sink, clock=clock(), id_factory=ids(),
        run_id="run-spelling", producer_id="producer-spelling",
    )
    assert observer.emit(self="shadowed", **event_fields()) is None
    assert observer.emit(event_fields()) is None
    assert observer.emit(event_fields(), self="shadowed") is None
    assert seen == []
    assert observer.get_state() == CaptureState(
        dropped_events=3, capture_gap=True, last_sink_error=GAP
    )
    # The control: the same event without that name is recorded, and the refusals above cost it
    # no sequence number, no event ID and no clock read.
    assert observer.emit(**event_fields()) is not None
    assert seen[0]["sequence"] == 0
    assert seen[0]["event_id"] == "event-1"
    assert seen[0]["timestamp"] == "2023-11-14T22:13:20.000Z"


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


def test_aflush_waits_for_writes_started_while_it_was_already_waiting():
    """A flush covers the writes that begin during it, not a snapshot taken when it started.

    The pending set is read again on every turn of the loop, so a write another task starts
    while the flush is suspended on its gather is gathered by the next turn rather than left for
    nobody to await. A flush that resolved with that write outstanding would tell a harness that
    capture had settled while an event was still on its way to the sink, and the TypeScript
    ``flush`` awaited exactly such a snapshot until this rule was made one rule for both.
    """
    written: list[dict] = []

    async def scenario():
        gates = [asyncio.Event(), asyncio.Event()]
        order: list[int] = []

        async def sink(event):
            index = len(order)
            order.append(index)
            await gates[index].wait()
            written.append(event)

        observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
        assert observer.emit(**event_fields()) is not None
        # One turn starts the first write, one lets the flush reach its gather. Neither sleeps.
        await asyncio.sleep(0)
        flush = asyncio.ensure_future(observer.aflush())
        await asyncio.sleep(0)
        # Started after the flush read the pending set, and before it could return.
        assert observer.emit(**event_fields()) is not None
        gates[0].set()
        for _ in range(4):
            await asyncio.sleep(0)
        # The first write is done and the second is not, so the flush must still be waiting.
        assert (len(written), flush.done()) == (1, False)
        gates[1].set()
        await flush
        return observer.get_state()

    assert asyncio.run(scenario()) == CaptureState()
    assert len(written) == 2


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


def test_an_interrupt_out_of_a_queued_write_counts_the_event_it_lost():
    """The interrupt travels on, and the event it stopped is counted on its way out.

    Inside a running loop a write is a task, and an interrupt raised by the sink ends that task
    and breaks out of the loop rather than returning through ``emit``. The guard inside the
    write re-raised it, as it must, and counted nothing, so a run an operator stopped reported
    that it had recorded everything it was handed. The count is in a ``finally`` now, which is
    the one path every exit from a write crosses, so a re-raise costs its event exactly one
    count whichever way it leaves.
    """
    written: list[dict] = []

    def run(interrupt):
        held: list[Observer] = []

        async def sink(event):
            raise interrupt

        async def scenario():
            observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
            held.append(observer)
            assert observer.emit(**event_fields()) is not None
            # Two turns: one runs the write, one delivers what it raised. Neither sleeps.
            await asyncio.sleep(0)
            await asyncio.sleep(0)

        with pytest.raises(type(interrupt)):
            asyncio.run(scenario())
        return held[0].get_state()

    lost = CaptureState(dropped_events=1, capture_gap=True, last_sink_error=GAP)
    assert run(KeyboardInterrupt("operator")) == lost
    assert run(SystemExit(3)) == lost
    assert written == []
    # The synchronous path already counted this, and still counts it exactly once: the same
    # rule, reached through the private loop rather than through a task.
    def interrupting_sink(event):
        raise KeyboardInterrupt("operator")

    synchronous = Observer(mode="metadata", sink=interrupting_sink, clock=clock())
    with pytest.raises(KeyboardInterrupt):
        synchronous.emit(**event_fields())
    assert synchronous.get_state() == lost


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


def caller_loop():
    """A caller-owned loop that keeps what asyncio reports, instead of discarding it.

    This installed a handler that threw every report away, and that is what let the emitter
    strand a task on a torn down loop and log ``Task was destroyed but it is pending!`` into a
    harness's output with no test noticing: the only witness there was is the one the fixture
    silenced. It records now, and every test here that tears a loop down with the emitter's
    writes still on it asserts the emitter left asyncio nothing to say about them.
    """
    loop = asyncio.new_event_loop()
    reports: list[str] = []
    loop.set_exception_handler(lambda _loop, context: reports.append(str(context.get("message"))))
    return loop, reports


def test_writes_stranded_by_a_torn_down_loop_are_counted_not_reported_clean():
    observer = Observer(mode="content", sink=never_settling_sink())
    loop, reports = caller_loop()

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
    gc.collect()
    # And counted is all: the capture state is the only place instrumentation reports from.
    assert reports == []


@pytest.mark.parametrize("started", [True, False], ids=["suspended", "never-started"])
def test_a_write_the_emitter_abandons_reports_itself_to_nobody_but_the_capture_state(started):
    """Instrumentation never alters the caller, and a line in the caller's log is an alteration.

    A caller's loop can be closed with the emitter's writes still queued on it. Every such task
    was destroyed while pending, and asyncio's exception handler then printed ``Task was
    destroyed but it is pending!`` into the harness's own output, once per stranded event,
    naming the emitter's internals in a log the harness did not write. The loss was never in
    question: it is counted in ``dropped_events`` either way. Only the reporting channel was,
    and there is one channel, the capture state.

    The two parameters are the two shapes a stranded write has, a task that ran and suspended
    inside the sink and one whose first step never ran, because the fix has to cover a write the
    emitter can inspect and a write that never began the same way. The other two noises asyncio
    can make about an abandoned write, an unretrieved exception and a coroutine nobody awaited,
    are pinned by their own tests; this is the third.
    """
    observer = Observer(mode="content", sink=never_settling_sink(), clock=clock(), id_factory=ids())
    loop, reports = caller_loop()

    async def queue_two():
        for _ in range(2):
            assert observer.emit(**event_fields()) is not None
        if started:
            # One turn, so the writes are suspended inside the sink rather than merely queued.
            await asyncio.sleep(0)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        loop.run_until_complete(queue_two())
        loop.close()
        # Reaping drops the emitter's last reference to those tasks, which is when a destroyed
        # pending task would have spoken up.
        assert observer.get_state() == CaptureState(
            dropped_events=2, capture_gap=True, last_sink_error=GAP
        )
        gc.collect()
        messages = [str(entry.message) for entry in caught]

    assert reports == []
    assert [message for message in messages if "never awaited" in message] == []


def test_aflush_from_another_loop_contains_the_failure_and_keeps_the_evidence():
    observer = Observer(mode="content", sink=never_settling_sink())
    owner, reports = caller_loop()

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
    gc.collect()
    assert reports == []


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
    loop, reports = caller_loop()

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
    gc.collect()
    assert reports == []


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
    """The guard inside the write records that loss, and no second path counts it again.

    The sink here stored the event before it suspended, and the count stands anyway. That is
    the counter's promise, which is acknowledgement and not arrival: see
    :func:`test_a_cancelled_write_is_counted_whether_or_not_the_sink_kept_the_event` for why
    the emitter cannot tell this write from one that stored nothing, and why the direction it
    guesses is this one.
    """
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


def test_a_cancelled_write_is_counted_whether_or_not_the_sink_kept_the_event():
    """``dropped_events`` counts what no sink acknowledged taking, which is all there is to see.

    Two writes cancelled at the same point, one of which had already stored its event and one
    of which never would have. Nothing the emitter can read tells them apart: a sink is caller
    code it never looks inside, a cancellation is delivered at whichever suspension point the
    sink happens to be at, and a coroutine that raises ``CancelledError`` of its own marks its
    task cancelled exactly as a real cancellation does. So both are counted, and the counter is
    an upper bound on what the trace is missing rather than a claim about which lines are
    absent from the file.

    Counting neither would be the other reading of "events that reached no sink", and it is the
    wrong one: it would report a clean capture state for the second write here, which reached
    nobody, and a trace that looks complete is the failure this module exists to prevent.
    Counting both costs one event of precision in a case the emitter cannot resolve, and
    ``capture_gap`` says the trace is incomplete either way. The promise is stated where the
    counter is defined rather than in each place that charges it.
    """
    kept: list[dict] = []

    async def stored_it_first(event):
        kept.append(event)
        await asyncio.Event().wait()

    async def stored_nothing(event):
        await asyncio.Event().wait()
        kept.append(event)

    def run(sink):
        async def scenario():
            observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
            before = asyncio.all_tasks()
            assert observer.emit(**event_fields()) is not None
            # One turn lets the write start and reach the sink's own suspension point, so the
            # cancellation lands inside the sink rather than before it. Nothing sleeps.
            await asyncio.sleep(0)
            queued = cancel_queued_writes(before)
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            queued.clear()
            return observer.get_state()

        return asyncio.run(scenario())

    lost = CaptureState(dropped_events=1, capture_gap=True, last_sink_error=GAP)
    assert run(stored_it_first) == lost
    assert len(kept) == 1
    assert run(stored_nothing) == lost
    # The premise: one sink really did take the event and the other really did not, and the two
    # capture states are identical all the same.
    assert len(kept) == 1
    # The promise is written where the counter is defined, not restated loosely elsewhere.
    promise = " ".join(CaptureState.__doc__.split())
    assert "counts events no sink acknowledged taking" in promise
    assert "upper bound" in promise


def test_a_sink_that_cancels_its_own_write_task_is_counted_once_and_only_when_lost():
    """Whoever cancels a write, the event it carried is counted once, and only if it was lost.

    A sink can cancel the task its own write runs on. Asking the task afterwards how it ended
    answered for the write, and answered wrong twice. A sink that raised after requesting the
    cancellation was counted by the guard that contained the raise and again by the callback
    that saw a cancelled task: one event, two dropped events. A sink that took the event and
    then cancelled its task was counted as a loss that never happened: the write reached the
    sink, and ``dropped_events`` counts events that reached no sink. The delivery record settles
    once and knows whether the sink accepted the event, so neither question is asked of the task
    any more.
    """
    fields = event_fields()

    def run(sink):
        async def scenario():
            observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
            assert observer.emit(**fields) is not None
            for _ in range(4):
                await asyncio.sleep(0)
            return observer.get_state()

        in_loop = asyncio.run(scenario())
        # The same sink through the private loop a synchronous harness gets.
        synchronous = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
        assert synchronous.emit(**fields) is not None
        alone = synchronous.get_state()
        synchronous.close()
        assert in_loop == alone, (in_loop, alone)
        return in_loop

    written: list[dict] = []

    async def cancel_then_raise(event):
        asyncio.current_task().cancel()
        raise RuntimeError("sink unavailable")

    async def cancel_after_writing(event):
        written.append(event)
        asyncio.current_task().cancel()

    async def cancel_then_wait(event):
        asyncio.current_task().cancel()
        await asyncio.Event().wait()
        written.append(event)

    # One event, one loss: the guard contained the failure and the cancelled task it left
    # behind is not a second event.
    assert run(cancel_then_raise) == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )
    # The write never reached the sink, so it is a loss, counted once.
    assert run(cancel_then_wait) == CaptureState(
        dropped_events=1, capture_gap=True, last_sink_error=GAP
    )
    assert written == []
    # The sink took this one before cancelling, so nothing was lost and nothing is counted.
    assert run(cancel_after_writing) == CaptureState()
    assert [event["type"] for event in written] == ["model.request", "model.request"]


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
    # The integer is the largest the wire carries, which is far past CPython's small-integer
    # cache, so rebuilding it really does produce a different object with the same value. It
    # used to be 10 ** 18, which the payload-number bound now refuses: a value JavaScript
    # cannot hold exactly never reaches a redactor in either language.
    scalars.emit(
        type="tool.start", capture_status="complete",
        metadata={"tool": "grep", "matched": MAX_SAFE_INTEGER}, content={},
    )
    # Every scalar came back as a different Python object holding the same value. JavaScript
    # gives a scalar no separate identity, so an equal string or number is not a replacement
    # and this event is not redacted. Asking ``is`` would have said it was.
    assert rebuilt == [True, True]
    assert seen[0]["capture_status"] == "complete"
    assert seen[0]["metadata"] == {"tool": "grep", "matched": MAX_SAFE_INTEGER}

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


# --- the SDK guide against the code it describes -----------------------------------------
# A document is not checked by being written carefully, and a document that advertises a check
# it does not perform is worse than one that claims nothing, because a reader takes a checked
# claim on trust. Everything ``docs/OBSERVER_SDK.md`` says about itself is checked here, and it
# is checked by reading the claim out of the document rather than by keeping a second copy of
# it: both export lists, every test name it cites in either language, the capture matrix with
# its column definitions and its coverage counts, and the constants it states. A review found
# each of those four advertised and only the first performed, which is how the guide came to
# describe a column set the test was free to disagree with.
OBSERVER_DOC = ROOT / "docs/OBSERVER_SDK.md"
TS_SOURCE = ROOT / "sdk/typescript/src/index.ts"
TS_SUITE = ROOT / "sdk/typescript/test/observer.test.mjs"
CAPTURE_SECTION = "What the securevibes-agent and Fieldglass integration actually captures"
# The keyword arguments ``capture_status`` takes, in the order the guide's column table lists
# them. The names are asserted against that header rather than assumed.
CAPTURE_INPUTS = ("trace_mode", "routes", "has_summary", "capture_state")
# The guide counts small things in words. Spelling them out here is what lets a sentence like
# "the ten wire event types" be compared with ``len(EVENT_TYPES)``.
COUNT_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "ten": 10,
               "fourteen": 14, "tenth": 10, "fourth": 4}


def doc_text() -> str:
    return OBSERVER_DOC.read_text(encoding="utf-8")


def doc_section(title: str) -> list[str]:
    """The lines under one ``##`` heading of the SDK guide, up to the next one."""
    lines = doc_text().splitlines()
    headings = [index for index, line in enumerate(lines) if line.startswith("## ")]
    for position, start in enumerate(headings):
        if lines[start][3:].strip() == title:
            end = headings[position + 1] if position + 1 < len(headings) else len(lines)
            return lines[start:end]
    raise AssertionError(f"{OBSERVER_DOC} has no section titled {title!r}")


def doc_tables(lines: list[str]) -> list[tuple[list[str], list[list[str]]]]:
    """Every markdown table in ``lines``, each as a header row and its body rows."""
    blocks: list[list[str]] = []
    for line in lines:
        if line.startswith("|"):
            if not blocks or not blocks[-1] or not blocks[-1][-1].startswith("|"):
                blocks.append([])
            blocks[-1].append(line)
        elif blocks and blocks[-1]:
            blocks.append([])
    tables = []
    for rows in (block for block in blocks if block):
        # Split on the pipes that separate cells, never on an escaped one inside a cell: a
        # member whose behavior column spells ``dict \| None`` is one cell, not two.
        cells = [
            [cell.strip().replace("\\|", "|")
             for cell in re.split(r"(?<!\\)\|", row.strip().strip("|"))]
            for row in rows
        ]
        header, divider, *body = cells
        assert set("".join(divider)) <= set("- :"), divider
        assert all(len(row) == len(header) for row in body), body
        tables.append((header, body))
    return tables


def doc_table(lines: list[str], first_header: str) -> tuple[list[str], list[list[str]]]:
    """The one table in ``lines`` whose first header cell is ``first_header``.

    A section carries more than one table now, so a table is chosen by what it says it is
    rather than by being the first one. A renamed header fails here instead of silently
    checking a different table than the one the claim is about.
    """
    for header, body in doc_tables(lines):
        if header[0] == first_header:
            return header, body
    raise AssertionError(f"no table headed {first_header!r} in that section")


def doc_names(cell: str) -> list[str]:
    """The names a table cell spells in backticks, one cell often naming more than one.

    A name is what its backticked span starts with, so a member written as a signature,
    ``observe(start, success, failure, operation) -> Any``, is read as ``observe`` rather than
    split at the commas inside its own parentheses.
    """
    names = re.findall(r"`([^`]+)`", cell)
    assert names, f"a table cell names nothing this test can read: {cell!r}"
    return [name.split("(")[0].strip() for name in names]


def doc_literals(cell: str) -> list[object]:
    """Every JSON literal a table cell spells in backticks, in the order it spells them.

    This is how a column definition in the guide becomes a set of calls: the cell is the
    document's own list of the values that column covers, so the test builds runs from what the
    document says rather than from a copy of it kept here.
    """
    spans = re.findall(r"`([^`]+)`", cell)
    assert spans, f"a table cell states no value this test can read: {cell!r}"
    return [json.loads(span) for span in spans]


def doc_code(lines: list[str], language: str) -> list[str]:
    """Every line inside the fenced code blocks of one language in ``lines``."""
    collected, inside = [], False
    for line in lines:
        if line.startswith("```"):
            inside = line.strip() == f"```{language}"
            continue
        if inside:
            collected.append(line)
    assert collected, f"no {language} code block in that section"
    return collected


def ts_exports(text: str) -> set[str]:
    """Top-level ``export`` names in a TypeScript file or in a documented code block.

    Only column zero counts, so the members of an exported class, which are indented in both
    the source and the guide, are not read as exports of their own.
    """
    return set(re.findall(
        r"^export (?:declare )?(?:const|type|interface|function|class) (\w+)", text, re.M
    ))


def ts_union(text: str, name: str) -> tuple[str, ...]:
    """The string members of ``export type <name> = "a" | "b";``, however it is line wrapped."""
    match = re.search(rf"^export type {name} =(.*?);", text, re.M | re.S)
    assert match, f"no exported union named {name}"
    return tuple(re.findall(r'"([^"]*)"', match.group(1)))


def ts_interface_fields(text: str, name: str) -> tuple[str, ...]:
    """The field names of ``export interface <name> { ... }``, in declaration order."""
    match = re.search(rf"^export interface {name} \{{(.*?)^\}}", text, re.M | re.S)
    assert match, f"no exported interface named {name}"
    return tuple(re.findall(r"^\s*(\w+)\??:", match.group(1), re.M))


def ts_public_members(text: str, name: str) -> set[str]:
    """The public members of ``export class <name>``: what a caller of the SDK can reach."""
    match = re.search(rf"^export class {name} \{{(.*?)^\}}", text, re.M | re.S)
    assert match, f"no exported class named {name}"
    members = re.findall(
        r"^  (?!private |#)(?:readonly |get |set |async )*([A-Za-z_$][\w$]*)\s*[(<:]",
        match.group(1), re.M,
    )
    return set(members)


def documented_capture_columns() -> dict[str, list[dict]]:
    """Each capture-matrix column, as every ``capture_status`` call the guide says it covers.

    The guide spells one row per column and one backticked value per value that column covers,
    so the calls are the cartesian product of its cells. The definitions used to live here as a
    dict of hand-written calls, which left the guide free to describe a different column set
    than the one being checked.
    """
    header, rows = doc_table(doc_section(CAPTURE_SECTION), "Column")
    assert [cell.strip("`") for cell in header[1:]] == list(CAPTURE_INPUTS), header
    columns = {}
    for row in rows:
        values = [doc_literals(cell) for cell in row[1:]]
        columns[row[0]] = [
            dict(zip(CAPTURE_INPUTS, combination, strict=True))
            for combination in itertools.product(*values)
        ]
    return columns


def documented_capture_space() -> list[dict]:
    """Every combination of inputs the guide's input-space table enumerates."""
    header, rows = doc_table(doc_section(CAPTURE_SECTION), "Input")
    values = {row[0].strip("`"): doc_literals(row[1]) for row in rows}
    assert list(values) == list(CAPTURE_INPUTS), list(values)
    return [
        dict(zip(CAPTURE_INPUTS, combination, strict=True))
        for combination in itertools.product(*values.values())
    ]


def call_key(call: dict) -> str:
    """A hashable spelling of one call, so covered and uncovered can be counted as sets."""
    return json.dumps(call, sort_keys=True)


def test_the_documented_capture_matrix_is_the_one_capture_status_returns():
    """The adapter's capture table, its column definitions and its coverage are all read here.

    The document claimed ``finding.submitted`` was **complete** for any traced run that returned
    a summary. The code stopped saying that when ``capture_status`` began reading the observer's
    own capture state: a run that reported a gap or a dropped event is ``partial``, and so is one
    that reported no state at all. The document was more generous than the code in the one place
    a reader is most likely to quote, and nothing failed, because the table was prose.

    The columns then moved into a grid but their *inputs* stayed here, hardcoded, which left the
    same hole one level up: the guide could be edited to describe a column the test never built
    and nothing would fail. The inputs are a table in the guide now and this reads them, so the
    document is the only copy.

    The columns are a sample of the input space and not a partition of it, which the guide now
    says and this counts: the covered and uncovered totals are compared with the three numbers
    the guide states. What holds across the whole space is driven across the whole space.

    The adapter is imported inside the test rather than at module scope: this file also pins that
    importing the observer does not import the evaluator, and that boundary is checked in a
    subprocess so nothing here can quietly depend on the order the tests run in.
    """
    from scaneval.adapters.llm_harness import capture_status

    section = doc_section(CAPTURE_SECTION)
    columns = documented_capture_columns()
    header, rows = doc_table(section, "Event type")
    assert header[1] == "`capture_status` key"
    assert header[2:] == list(columns), (header[2:], list(columns))
    documented_types: set[str] = set()
    documented_keys: set[str] = set()
    for row in rows:
        types, keys = doc_names(row[0]), doc_names(row[1])
        documented_types |= set(types)
        documented_keys |= set(keys)
        for column, cell in zip(header[2:], row[2:], strict=True):
            documented = doc_names(cell)
            assert len(documented) == 1, (row[0], column, cell)
            for call in columns[column]:
                returned = capture_status(
                    call["trace_mode"], call["routes"],
                    has_summary=call["has_summary"], capture_state=call["capture_state"],
                )
                for key in keys:
                    assert returned[key] == documented[0], (key, column, call)

    # Both directions. A key the adapter returns and the table does not carry would be an
    # undocumented capture claim, and an event type the contract declares and the table does not
    # mention would be a category nobody said anything about.
    gapless = {"capture_gap": False, "dropped_events": 0}
    returned = capture_status("content", ["claude"], has_summary=True, capture_state=gapless)
    assert documented_keys == set(returned)
    assert documented_types | {"observer.error"} == set(EVENT_TYPES)
    # "fewer than half of them", in the sentence above the table, counted rather than asserted.
    captured = [key for key, value in returned.items()
                if value not in ("unavailable", "not_applicable")]
    assert len(captured) * 2 < len(EVENT_TYPES)

    # The columns are a sample of the space, and the guide states by how much. Every column's
    # runs must be runs the space enumerates, or the sample would be of something else.
    space = documented_capture_space()
    covered = {call_key(call) for calls in columns.values() for call in calls}
    every = {call_key(call) for call in space}
    assert covered <= every, sorted(covered - every)
    stated = re.search(
        r"The (\w+) columns name (\d+) of the (\d+) combinations that enumerates, "
        r"and the remaining (\d+) are outside the table",
        "\n".join(section),
    )
    assert stated, "the guide no longer states its coverage in the sentence this reads"
    assert COUNT_WORDS[stated.group(1)] == len(columns)
    assert int(stated.group(2)) == len(covered)
    assert int(stated.group(3)) == len(every) == len(space)
    assert int(stated.group(4)) == len(every) - len(covered)

    # What the guide claims across the whole space, driven across the whole space: the columns
    # cover 28 runs, so a claim about all 120 needs the other 92 exercised too.
    for call in space:
        every_run = capture_status(
            call["trace_mode"], call["routes"],
            has_summary=call["has_summary"], capture_state=call["capture_state"],
        )
        assert set(every_run) == documented_keys, call
        assert (every_run["tool_calls"] == "not_applicable") == (call["routes"] == ["mock"]), call
        for key in ("finding_candidate", "finding_validation", "finding_filtered"):
            assert every_run[key] == "unavailable", (key, call)


def test_the_documented_python_api_is_the_package_export_list():
    """The guide's "everything below is exported" line is checked rather than asserted.

    ``TraceSink`` was listed in that section and was not exported, so a harness following the
    guide got an :class:`ImportError` from a line the guide told it to write. Fixing the export
    alone would have left the next name free to drift, so the list is read out of the document
    and compared with ``__all__`` in both directions, and the member table is read against a
    real observer the same way.
    """
    import scaneval.observer as package

    section = doc_section("Python API")
    documented: set[str] = set()
    for line in doc_code(section, "python"):
        if not line or line[0] in " \t)@#":
            continue
        if line.startswith("class "):
            documented.add(line[len("class "):].split("(")[0].split(":")[0].strip())
        elif line.startswith("def "):
            documented.add(line[len("def "):].split("(")[0].strip())
        else:
            documented.add(line.split()[0])
    assert documented == set(package.__all__)
    assert all(hasattr(package, name) for name in package.__all__)

    # The member table is the same claim about one class, so it is read the same way.
    header, rows = doc_table(section, "Member")
    members = {name.split("(")[0] for row in rows for name in doc_names(row[0])}
    observer = Observer()
    assert members == {name for name in dir(observer) if not name.startswith("_")}

    # And the field list in that table's ``emit`` row, which is the other export-shaped claim
    # the section makes: a caller writes these names and no others, and an unknown one is a
    # refused event rather than a dropped field.
    from scaneval.observer.emitter import _INPUT_FIELDS

    accepts = re.search(r"Accepts ((?:`\w+`, )+)and optionally ((?:`\w+`, )+`\w+`)\.",
                        doc_text())
    assert accepts, "the emit row no longer lists the fields this reads"
    listed = re.findall(r"`(\w+)`", accepts.group(1) + accepts.group(2))
    assert set(listed) == set(_INPUT_FIELDS) and len(listed) == len(_INPUT_FIELDS)


def test_the_documented_typescript_api_is_the_sdk_export_list():
    """The other "everything below is exported" line, which nothing checked until now.

    The guide said it of both packages and the test read only the Python one, so the TypeScript
    section carried the same promise with nothing behind it: a name added to the SDK and left
    undocumented, or documented and never exported, would have gone on reading as checked.

    It reads ``sdk/typescript/src/index.ts`` rather than ``dist/``, so it needs neither node nor
    a build and cannot be skipped into passing. The class members are compared too, because the
    guide's ``Observer`` block is a claim about what a caller can reach: anything ``private``
    there is not part of it.
    """
    source = TS_SOURCE.read_text(encoding="utf-8")
    section = doc_section("TypeScript API")
    block = "\n".join(doc_code(section, "ts"))
    assert ts_exports(block) == ts_exports(source)
    assert ts_public_members(block, "Observer") == ts_public_members(source, "Observer")
    # The guide's own note that the mode is private in TypeScript, checked rather than trusted.
    assert "mode" not in ts_public_members(source, "Observer")
    assert {"runId", "producerId", "emit", "observeAsync", "flush", "close", "getState",
            "closed"} <= ts_public_members(source, "Observer")
    # And its claim that only two of these exports survive as runtime values, which is what a
    # JavaScript caller can actually import: the rest are types and vanish at the build.
    runtime = set(re.findall(r"^export const (\w+)", source, re.M))
    stated = re.search(r"Only `(\w+)` and `(\w+)` exist as runtime constants in TypeScript",
                       doc_text())
    assert runtime == set(stated.groups()) == {"SCHEMA_VERSION", "MAX_PAYLOAD_DEPTH"}


def test_the_constants_the_guide_states_are_the_constants_both_emitters_use():
    """Every number and reserved name the guide states, against the code that enforces it.

    These were prose. A guide is where a harness author goes to learn a limit, so a stated
    number that no longer matches the code is a worse failure than an unstated one: the reader
    has no reason to doubt it. The Python block's comments are the values themselves, the
    TypeScript block's unions are the same vocabulary spelled as types, and the numbers in the
    rules are read out of the sentences that state them.
    """
    import scaneval.observer as package
    from scaneval.observer import emitter

    text = doc_text()
    source = TS_SOURCE.read_text(encoding="utf-8")

    # 1. The Python constants block: ``NAME  # <value>`` is the value, not a gloss of it.
    for line in doc_code(doc_section("Python API"), "python"):
        comment = re.fullmatch(r"([A-Z_]+) +# (.+)", line)
        if not comment:
            continue
        name, stated = comment.group(1), comment.group(2)
        value = getattr(package, name)
        if stated[0] in '("' or stated[0].isdigit():
            assert ast.literal_eval(stated) == value, name
        else:
            # The one comment that states a count rather than a literal, because ten event
            # types would not fit the line: "the ten wire event types, in schema order".
            count = re.match(r"the (\w+) ", stated)
            assert count and COUNT_WORDS[count.group(1)] == len(value), (name, stated)

    # 2. The same vocabulary on the TypeScript side, in the guide and in the SDK source.
    block = "\n".join(doc_code(doc_section("TypeScript API"), "ts"))
    for union, constant in (("RecordingMode", RECORDING_MODES), ("EventType", EVENT_TYPES),
                            ("EventCategory", EVENT_CATEGORIES),
                            ("CaptureStatus", CAPTURE_STATUSES)):
        assert ts_union(block, union) == ts_union(source, union) == constant, union
    assert re.search(r'export const SCHEMA_VERSION: "([^"]+)"', block).group(1) == SCHEMA_VERSION
    assert re.search(r'SCHEMA_VERSION = "([^"]+)"', source).group(1) == SCHEMA_VERSION
    documented_depth = int(re.search(r"export const MAX_PAYLOAD_DEPTH = (\d+)", block).group(1))
    assert documented_depth == MAX_PAYLOAD_DEPTH
    assert int(re.search(r"^export const MAX_PAYLOAD_DEPTH = (\d+)", source, re.M).group(1)) \
        == MAX_PAYLOAD_DEPTH

    # 3. Rule 8's two numbers: the limit, and the further levels it leaves inside the payload.
    assert int(re.search(r"`MAX_PAYLOAD_DEPTH`, which is (\d+)", text).group(1)) \
        == MAX_PAYLOAD_DEPTH
    further = int(re.search(r"that object plus (\d+) further levels", text).group(1))
    assert further == MAX_PAYLOAD_DEPTH - 1

    # 4. The safe-integer bound, everywhere the guide spells it, and the float-integer
    # threshold rule 4 leans on for not needing an upper bound on the decimal window.
    spelled = re.findall(r"`2 \*\* (\d+) - (\d+)`", text)
    assert spelled, "the guide no longer spells the safe-integer bound"
    for base, less in spelled:
        assert 2 ** int(base) - int(less) == emitter._MAX_SAFE_INTEGER
    integral_from = int(re.search(r"every double at or above `2 \*\* (\d+)` is an integer",
                                  text).group(1))
    assert math.nextafter(2.0 ** integral_from, math.inf) - 2.0 ** integral_from == 1.0

    # 5. Rule 4's two floors, and the spellings Python's repr gives them.
    floor = float(re.search(r"A non-integral number must be at least `([\d.e+-]+)` in magnitude",
                            text).group(1))
    assert floor == emitter._MIN_PLAIN_DECIMAL
    assert float(re.search(r"const MIN_PLAIN_DECIMAL = ([\d.e+-]+);", source).group(1)) == floor
    assert "e" not in repr(floor) and "e" in repr(floor / 10)
    over_refused = float(re.search(r"Magnitudes below `([\d.e+-]+)` are the deliberate "
                                   r"over-refusal", text).group(1))
    assert 0 < over_refused < floor
    padded = re.search(r"Python pads it to two digits \(`([\de.+-]+)`\) and JavaScript does not",
                       text).group(1)
    assert repr(float(padded)) == padded

    # 6. The counts the guide states in words.
    numbered = [int(number) for number in re.findall(r"^\*\*(\d+)\. ", text, re.M)]
    assert numbered == list(range(1, len(numbered) + 1)), numbered
    rules = re.search(r"the (\w+) numbered rules of the parity contract", text).group(1)
    assert COUNT_WORDS[rules] == len(numbered)
    types = re.search(r"the (\w+) wire event types", text).group(1)
    assert COUNT_WORDS[types] == len(EVENT_TYPES)
    ordinal = re.search(r"`observer\.error` is the (\w+) event type", text).group(1)
    assert EVENT_TYPES[COUNT_WORDS[ordinal] - 1] == "observer.error"
    state = re.search(r"Capture state carries the same (\w+) fields\.\*\* "
                      r"`(\w+)`, `(\w+)`, and `(\w+)`", text)
    fields = tuple(field.name for field in dataclasses.fields(CaptureState))
    assert COUNT_WORDS[state.group(1)] == len(fields) == 3
    assert state.groups()[1:] == fields == ts_interface_fields(source, "CaptureState")

    # 7. The two reserved strings, read off the behavior rather than off a constant.
    gap_key = re.search(r"and set `(\w+): true` in its metadata", text).group(1)
    message = re.search(r'one opaque constant, `"([^"]+)"`', text).group(1)
    seen, sink = recorder()
    clean = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
    # "Neither emitter ever writes false": nothing at all is written without a gap.
    assert gap_key not in clean.emit(**event_fields(metadata={}))["metadata"]
    assert clean.get_state().last_sink_error is None
    broken = Observer(mode="metadata", sink=raising("sink"), clock=raising("clock"),
                      id_factory=ids())
    assert broken.emit(**event_fields(metadata={}))["metadata"][gap_key] is True
    assert broken.get_state().last_sink_error == message
    assert len(seen) == 1
    assert re.search(rf'const gapKey = "{gap_key}"', source)
    assert re.search(rf'const gapMessage = "{message}"', source)


def test_the_key_order_the_guide_spells_is_the_order_an_event_carries():
    """Rule 10's list, read out of the guide and compared with a real event and the schema.

    The rule names nine keys, defers the five link fields to the schema's own order, and names
    three more. A reader joining traces on field position takes that list literally, so it is
    built here exactly as the sentence describes it, including the deferral, and compared with
    the keys an event actually carries when every optional field is supplied.
    """
    text = doc_text()
    rule = re.search(r"\*\*10\. Emitted key order is the schema's declaration order\.\*\* "
                     r"(.+?), then the link fields in the order the schema lists them, then (.+?)\.",
                     text)
    assert rule, "rule 10 no longer spells its order in the sentence this reads"
    head = re.findall(r"`(\w+)`", rule.group(1))
    tail = re.findall(r"`(\w+)`", rule.group(2))
    # The schema's own link list: every declared property that is optional and is neither a
    # payload nor the duration, in declaration order, which is what the sentence defers to.
    optional = [name for name in SCHEMA["properties"] if name not in SCHEMA["required"]]
    links = [name for name in optional if name not in ("duration_ms", "content")]
    assert len(links) == 5, links
    seen, sink = recorder()
    observer = Observer(mode="content", sink=sink, run_id="r", producer_id="p",
                        clock=clock(), id_factory=ids())
    assert observer.emit(**event_fields(duration_ms=5, **dict.fromkeys(links, "link"))) is not None
    assert list(seen[0]) == head + links + tail
    # And the schema's own declaration order is that same list, which is what the rule claims
    # the emitter follows rather than merely agreeing with by accident.
    assert list(SCHEMA["properties"]) == head + links + tail


def test_the_redactor_key_names_the_guide_lists_are_the_ones_it_hides():
    """Rule 7's key list and its two Unicode counterexamples, read out of the guide.

    The list is what a harness author reads to know whether their own key name will be hidden,
    so it is the list most worth being wrong about, and it was prose. The counterexamples were
    worse than prose: the sentence spelled the Kelvin-sign key as ``toKen`` with an ordinary
    ASCII ``K``, which both languages hide and always did, so the example demonstrated the
    opposite of the rule it was under. The code points are named in the guide now, and read
    from it here.
    """
    from scaneval.observer import default_redactor

    text = doc_text()
    listed = re.search(r"Both hide the same whole key names \((.+?), any case\)", text).group(1)
    names = re.findall(r"`([^`]+)`", listed)
    assert len(names) >= 11, names
    for name in names:
        # ``credential(s)`` is two names in one span: the plural is optional in the pattern.
        for spelled in ([name] if "(" not in name else
                        [name.replace("(s)", ""), name.replace("(s)", "s")]):
            for cased in (spelled, spelled.upper(), spelled.title()):
                assert default_redactor(cased, "value", ()) == "[REDACTED]", cased
    contains = re.search(r"neither hides a key that merely contains one, such as `(\w+)`", text)
    assert default_redactor(contains.group(1), "value", ()) == "value"
    # The two lookalikes, by code point rather than by glyph.
    token = re.search(r"spelling `token` with (U\+[0-9A-F]{4}) in place of its `k`", text).group(1)
    secret = re.search(r"one spelling `secret` with (U\+[0-9A-F]{4}) in place of its `s`",
                       text).group(1)
    folded = "to" + chr(int(token[2:], 16)) + "en"
    long_s = chr(int(secret[2:], 16)) + "ecret"
    assert default_redactor(folded, "value", ()) == "value", folded
    assert default_redactor(long_s, "value", ()) == "value", long_s
    # The control: the ASCII spellings of the same two keys are hidden, so the counterexamples
    # are about the code points and not about the words.
    assert default_redactor("token", "value", ()) == default_redactor("secret", "value", ()) \
        == "[REDACTED]"


def test_the_payload_number_window_the_guide_states_is_the_one_the_emitter_enforces():
    """The guide's accepted range for a payload number, driven at the bounds it names.

    The numbers in rule 4 are the reason a harness scales a small value before it emits it, so
    they are the numbers most worth being wrong about. Each bound is read out of the sentence
    that states it and then emitted, rather than restated here.
    """
    text = doc_text()
    bound = 2 ** int(re.search(r"`2 \*\* (\d+) - 1`", text).group(1)) - 1
    floor = float(re.search(r"A non-integral number must be at least `([\d.e+-]+)` in magnitude",
                            text).group(1))
    over_refused = float(re.search(r"Magnitudes below `([\d.e+-]+)` are the deliberate "
                                   r"over-refusal", text).group(1))
    seen, sink = recorder()
    observer = Observer(mode="metadata", sink=sink, clock=clock(), id_factory=ids())
    kept = observer.emit(**event_fields(metadata={
        "bound": bound, "floor": floor, "negative_floor": -floor,
        # "It is stored as an integer, because JavaScript has one number type", and -0.0 with it.
        "integral_float": 5.0, "negative_zero": -0.0,
    }))
    assert kept["metadata"] == {"bound": bound, "floor": floor, "negative_floor": -floor,
                                "integral_float": 5, "negative_zero": 0}
    assert isinstance(kept["metadata"]["integral_float"], int)
    for refused in (bound + 1, -(bound + 1), floor / 10, over_refused, over_refused / 10):
        assert observer.emit(**event_fields(metadata={"value": refused})) is None, refused
    assert len(seen) == 1
    assert observer.get_state().dropped_events == 5


def test_every_test_the_guide_names_still_exists():
    """The guide pins its claims to tests by name, so the names have to be real, in both suites.

    Most of what this document promises is followed by the test that holds it, cited in
    backticks. A renamed or deleted test leaves the promise standing with nothing behind it,
    and reads exactly like a checked one.

    It used to look up the Python names alone while the guide said "every test this guide cites
    by name is looked up the same way", which was false of the four TypeScript tests it cited
    as quoted prose, in the paragraphs about the divergences most likely to be quoted. A
    TypeScript test is cited as ``observer.test.mjs::"its exact name"`` now, so it can be looked
    up in the suite that defines it, and the guide is held to citing at least those four: a
    citation rewritten back into bare prose would otherwise take its claim out of this check
    without failing it.
    """
    text = doc_text()
    cited = set(re.findall(r"\btest_[a-z0-9_]+", text))
    # ``test_v2_...`` in a path is a module, not a test function, and is checked as a file.
    modules = {name for name in cited if name.startswith("test_v2_")}
    for module in modules:
        assert (ROOT / "tests" / f"{module}.py").is_file(), module
    defined = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "tests").glob("test_*.py"))
    )
    missing = sorted(name for name in cited - modules if f"def {name}(" not in defined)
    assert missing == [], missing

    typescript = set(re.findall(r'`observer\.test\.mjs::"([^"]+)"`', text))
    assert len(typescript) >= 4, sorted(typescript)
    suite = TS_SUITE.read_text(encoding="utf-8")
    absent = sorted(name for name in typescript if f'test("{name}"' not in suite)
    assert absent == [], absent
