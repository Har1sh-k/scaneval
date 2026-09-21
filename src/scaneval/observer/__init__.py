"""Opt-in observer emitter for a harness under evaluation. Importing it records nothing.

This package is instrumentation and nothing else. It holds no truth labels, computes no score,
calls no model, retrieves no data, enforces no policy, and never alters a scanner decision or
the result of the operation it observes. It monkeypatches nothing, opens no file of its own,
starts no thread, and makes no network call: a harness must emit at its own model-client,
tool-dispatch, context-selection, and finding-lifecycle boundaries for anything to be recorded
at all. The one resource an :class:`~scaneval.observer.Observer` can own is a private event
loop, created only when a synchronous harness gives it a sink that returns an awaitable and
closed by ``close()``.

Never altering the caller is enforced, not hoped for: every caller-supplied hook and every sink
write runs under a ``BaseException`` guard that records a capture gap and re-raises only
:class:`KeyboardInterrupt` and :class:`SystemExit`, so a cancelled, failing, or recursion-bound
sink costs a trace event and never the run being observed. ``dropped_events`` counts the events
that reached no sink; a failure that only degraded an event sets ``capture_gap`` and marks that
event instead, because the event was still delivered.

The guard covers checking what a hook returned as well as calling it, so a monotonic source
whose reading cannot even be converted to a number costs the duration and a capture gap rather
than the operation it was wired in to measure. An awaitable an observed operation returns is
run exactly as the caller's own ``await`` would run it, in every mode, because an operation
instrumentation quietly left unexecuted would be a behavior change rather than an observation.
A write that reached no sink is counted whether it failed, was cancelled before it ever
started, or was stranded by a loop closed before it could run: an event nobody received must
never read as a complete trace.

Wiring mistakes are refused once, at wiring time, rather than degraded through a whole run:
:func:`create_jsonl_sink` refuses a generator-function line writer exactly as the
:class:`Observer` constructor refuses a generator-function sink, because calling one returns an
iterator and writes nothing.

:data:`MAX_PAYLOAD_DEPTH` is exported because it is part of the shared contract rather than an
implementation detail: both emitters refuse a metadata or content payload nested deeper than
that many containers, so a harness can check its own payloads against the same number.

It is also independent of the evaluator. Importing :mod:`scaneval.observer` must not pull in
the contracts, scoring, runner, execution, review, report, or adapter modules, so a harness can
depend on the emitter without acquiring the machinery that judges it. That boundary is pinned
by a test.

The wire contract is ``schema/v2/trace-event.schema.json`` and is shared with the TypeScript
SDK under ``sdk/typescript``; both emitters reproduce the same fixture. See
``docs/OBSERVER_SDK.md`` for what recording modes, capture status, and capture gaps mean.
"""

from .emitter import (
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
    default_redactor,
)

__all__ = [
    "CAPTURE_STATUSES",
    "EVENT_CATEGORIES",
    "EVENT_TYPES",
    "MAX_PAYLOAD_DEPTH",
    "RECORDING_MODES",
    "SCHEMA_VERSION",
    "CaptureState",
    "JsonlSink",
    "Observer",
    "create_jsonl_sink",
    "default_redactor",
]
