#!/usr/bin/env python3
"""Offline integration fixture for the Python observer emitter. Not a scanner evaluation.

Everything this file calls a "model" or a "tool" is a canned function defined below. It sends
no request, opens no socket, reads no repository, loads no ruleset, and holds no truth label,
so the findings it prints are fabricated fixture data and the numbers mean nothing about any
scanner. Nothing here scores, ranks, or compares anything.

What it does demonstrate is the order a harness emits in, and that the emitter is inert until
the caller turns it on: the same scan runs twice, once with an ``off`` observer and once with a
``content`` one, and the report is byte identical both times because the emitter never touches
the values an observed operation returns.

The clock, the ID factory, and the tool duration are fixed constants rather than measurements,
so two runs of this file print the same bytes. A real harness passes the real clock and times
real work; this fixture times nothing.

Run it from the repository venv with no arguments::

    .venv/bin/python examples/observer/python_harness.py
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

try:
    from scaneval.observer import Observer, create_jsonl_sink
except ModuleNotFoundError:  # a plain checkout with nothing installed
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    from scaneval.observer import Observer, create_jsonl_sink


# Fixed so the printed output is reproducible. A real harness passes the real clock.
EPOCH = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
CLOCK_STEP_MS = 10
# Not a measurement. This fixture dispatches a function that returns a constant.
FAKE_TOOL_MS = 7
TYPE_WIDTH = 19
STATUS_WIDTH = 9


def fixed_clock():
    """A clock that advances a fixed step per read. It never consults the system time."""
    reads = 0

    def now() -> datetime:
        nonlocal reads
        moment = EPOCH + timedelta(milliseconds=CLOCK_STEP_MS * reads)
        reads += 1
        return moment

    return now


def counting_ids():
    """An ID factory that counts. Deterministic on purpose; not unique across processes."""
    issued = 0

    def next_id(prefix: str) -> str:
        nonlocal issued
        issued += 1
        return f"{prefix}-{issued}"

    return next_id


def fake_model(prompt: str) -> dict:
    """Return a canned completion. Calls no provider, reads no key, and ignores the prompt."""
    return {"text": "two candidates in app/runner.py", "finish_reason": "stop", "output_tokens": 18}


def fake_tool(path: str) -> dict:
    """Return a canned tool result. Opens no file and never touches ``path`` on disk."""
    return {"matched": 2, "path": path}


def link(event: dict | None) -> str | None:
    """The event ID to hang a child event from, or None when nothing was recorded."""
    return None if event is None else event["event_id"]


def run_scan(observer: Observer) -> dict:
    """Run the fake scan, emitting at each boundary. Returns the report, tracing or not.

    The emitter is handed explicit events at a fake model boundary, a fake tool dispatch, and
    each finding transition. It discovers none of them: an ``off`` observer makes every call
    here a no-op and the returned report is unchanged.
    """
    # Model boundary. The credential below is fixture text, and the default redactor hides it
    # because of its key name, which is why this event is stored as redacted rather than
    # complete. input_tokens is kept: a counter is not a credential.
    request = observer.emit(
        type="model.request",
        capture_status="complete",
        call_id="call-1",
        metadata={"model": "fake-model-v0", "input_tokens": 31},
        content={"api_key": "fixture-not-a-real-credential", "prompt": "review app/runner.py"},
    )
    completion = fake_model("review app/runner.py")
    observer.emit(
        type="model.response",
        capture_status="complete",
        call_id="call-1",
        parent_event_id=link(request),
        metadata={"model": "fake-model-v0", "output_tokens": completion["output_tokens"]},
        content={"text": completion["text"], "finish_reason": completion["finish_reason"]},
    )

    # Tool dispatch boundary.
    started = observer.emit(
        type="tool.start",
        capture_status="complete",
        call_id="call-2",
        metadata={"tool": "grep", "path": "app/runner.py"},
        content={"arguments": {"pattern": "shell=True"}},
    )
    result = fake_tool("app/runner.py")
    observer.emit(
        type="tool.end",
        capture_status="complete",
        call_id="call-2",
        parent_event_id=link(started),
        duration_ms=FAKE_TOOL_MS,
        metadata={"tool": "grep", "matched": result["matched"]},
        content={"result": result},
    )

    # A candidate the harness drops before reporting. candidate_id links the two events.
    observer.emit(
        type="finding.candidate",
        capture_status="complete",
        candidate_id="candidate-1",
        metadata={"rule": "py.subprocess-shell-true", "path": "tests/fixtures/shell.py", "line": 8},
    )
    observer.emit(
        type="finding.filtered",
        capture_status="complete",
        candidate_id="candidate-1",
        metadata={"reason": "path is test fixture material"},
    )

    # A candidate that survives to the report. The submitted event carries the claim ID.
    observer.emit(
        type="finding.candidate",
        capture_status="complete",
        candidate_id="candidate-2",
        metadata={"rule": "py.subprocess-shell-true", "path": "app/runner.py", "line": 42},
    )
    observer.emit(
        type="finding.validation",
        capture_status="complete",
        candidate_id="candidate-2",
        metadata={"verdict": "kept", "checked": "reachability"},
    )
    observer.emit(
        type="finding.submitted",
        capture_status="complete",
        candidate_id="candidate-2",
        claim_id="claim-1",
        metadata={"rule": "py.subprocess-shell-true", "path": "app/runner.py", "line": 42},
    )
    return {"findings": [{"rule": "py.subprocess-shell-true", "path": "app/runner.py", "line": 42}]}


def describe(event: dict) -> str:
    """One readable line per event. The JSONL block below is the authoritative record."""
    links = [
        f"{name}={event[name]}"
        for name in ("call_id", "parent_event_id", "candidate_id", "claim_id", "duration_ms")
        if name in event
    ]
    return (
        f"  event {event['sequence']}  {event['type']:<{TYPE_WIDTH}}"
        f"{event['capture_status']:<{STATUS_WIDTH}} {' '.join(links)}".rstrip()
    )


def main() -> int:
    print("ScanEval observer example harness (Python)")
    print("Integration fixture only: fake model and fake tool functions, no model call, no")
    print("network call, no real scanner, no truth labels.")
    print()

    print("step 1  run with tracing off")
    silent: list[dict] = []
    off = Observer(sink=silent.append, clock=fixed_clock(), id_factory=counting_ids())
    untraced = run_scan(off)
    print(f"  events recorded: {len(silent)}")
    print(f"  findings reported: {len(untraced['findings'])}")
    print()

    print("step 2  the same run with tracing turned on by the caller (mode=content)")
    lines: list[str] = []
    recorded: list[dict] = []

    def sink(event: dict) -> None:
        recorded.append(event)
        create_jsonl_sink(lines.append).write(event)

    observer = Observer(
        mode="content",
        sink=sink,
        run_id="run-observer-example",
        producer_id="example-harness",
        clock=fixed_clock(),
        id_factory=counting_ids(),
    )
    traced = run_scan(observer)
    for event in recorded:
        print(describe(event))
    print(f"  events recorded: {len(recorded)}")
    print(f"  findings reported: {len(traced['findings'])}")
    print(f"  report identical to the untraced run: {str(traced == untraced).lower()}")
    print()

    print("step 3  explicit flush")
    observer.flush()
    state = observer.get_state()
    print(
        f"  capture state: dropped_events={state.dropped_events} "
        f"capture_gap={str(state.capture_gap).lower()} "
        f"last_sink_error={state.last_sink_error or 'none'}"
    )
    print()

    print(f"trace jsonl ({len(lines)} lines)")
    for line in lines:
        print(f"  {line.rstrip()}")

    # A fixture that recorded nothing would still print the headings above, so fail loudly.
    expected = len(EXPECTED_TYPES)
    if len(recorded) != expected or [event["type"] for event in recorded] != list(EXPECTED_TYPES):
        print(f"unexpected trace: {len(recorded)} events", file=sys.stderr)
        return 1
    if json.loads(lines[0])["type"] != EXPECTED_TYPES[0]:
        print("jsonl sink disagreed with the recorded events", file=sys.stderr)
        return 1
    return 0


EXPECTED_TYPES = (
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


if __name__ == "__main__":
    raise SystemExit(main())
