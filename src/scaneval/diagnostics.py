"""Coverage attribution: was a labeled target's code region delivered to the model, and where?

A run that missed a known vulnerability leaves two very different questions looking identical in
the result: the model was never shown the code, or the model was shown the code and said nothing.
Only the second is a detection failure. This module answers the first, and only the first, by
joining the evaluator's accepted locations to the ``context.selection`` events a trace holds.

The join happens here, after the run, because a label must never reach a scanner. Nothing in a
trace names a target, a case, or a line the evaluator cares about; the spans a harness reports say
what it supplied, and this module asks whether the lines the label names fall inside them. That
ordering is what keeps the answer evidence rather than a hint the harness could have acted on.

What a classification claims, and what it does not. ``included`` says the target's lines were in
the prompt of that invocation. It does not say the model read them, that what was supplied was
enough to recognize the vulnerability, or that a miss on top of it is the model's fault.

``absent`` is the only negative claim, and a hole in the record weakens it long before it weakens
anything else. That asymmetry is the judgement this module exists to make, and
:data:`REASON_EFFECTS` is where it is written down. A record holding nothing - no trace file, no
context event, a capture record claiming the category was never observed - supports no
classification at all. A record that is merely incomplete - a reported capture gap, a dropped
event, a line that would not parse - still supports every positive one: a span that is in the
trace was delivered whatever else went missing, and a lost event cannot un-deliver it. Only the
negative claim falls there, to ``unknown``. Reading a hole as a negative result would invent the
most interesting finding this can produce; reading one as a reason to discard a span that is
sitting right there would be the same mistake pointing the other way.

Not every span is a file position. A harness that reassembles fragments marks them
``location_known: false``, and their line numbers count the supplied text rather than the file;
they cover nothing here, and one landing on a target's own path is a reason the target's absence
cannot be proved in that invocation.

Only ``context.selection`` events are read. A model that pulled a file in through its own tool call
is reported on ``tool.end`` spans, and counting those here would mix two claims with different
provenance: what a harness chose to supply, and what a model went and fetched. ``absent`` therefore
means no supplied-context span covered the lines, not that the file was never read.

The output is a plain JSON document, not a registered contract. It is derived from documents that
have contracts, the way a score record is, and nothing binds to its shape, so registering a kind
for it would widen ``scaneval validate`` with no reader on the other side.

Determinism. Targets are sorted by ``target_id``, invocations by first sequence then producer
then group key, event IDs by sequence then ID, and reason codes lexically. No clock, no
randomness, and no timestamp of this module's own reaches the document, so two runs over the same
bundle produce the same bytes.

Nothing here lists supplied source: the per-invocation records carry counts of spans and of
distinct paths, never the paths themselves. The only paths in the document are the evaluator's own
accepted locations, which the evaluator already holds.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import json
from pathlib import Path
import posixpath

from . import __version__
from .contracts import ContractError, load_document


DIAGNOSTIC_NAME = "context_coverage"
# The shape of this document. Bumped when a field changes meaning, not when a field is added.
DIAGNOSTIC_VERSION = 1

# Ordered best to worst. A rank comparison decides ``best`` and ``scattered``, so the order is
# data rather than a chain of comparisons that could disagree with the table in the docs.
CLASSIFICATIONS = ("included", "partial", "absent", "unknown")
_RANK = {"unknown": 0, "absent": 1, "partial": 2, "included": 3}

# The ``capture`` values that claim the category was observed at all. The same three
# :mod:`scaneval.execution` treats as observation claims; ``unavailable`` and ``not_applicable``
# claim nothing, and a run recording either of them cannot support a negative answer here.
_OBSERVED_CAPTURE = ("complete", "partial", "redacted")

# Why a classification could not be made from the record, and what each reason actually costs.
# One table, because the split is the whole judgement of this module and getting it wrong in
# either direction is a real error: blanketing on a capture gap discards evidence sitting right
# there in the trace, and failing to block absence on one invents the most interesting finding
# this diagnostic can produce.
#
# "blanket"        nothing was recorded, so nothing may be concluded: every target, every
#                  invocation, unknown.
# "absence"        the record is incomplete, not empty. A span that is in it was still delivered
#                  and a lost event cannot un-deliver one, so included and partial stand and only
#                  the negative claim falls, wherever it is made.
# "target_absence" blocks the negative claim only in a target's best and union. A per-invocation
#                  absent is a statement about the events that invocation produced, and stays
#                  true; a target-level one would also have to answer for the invocations that
#                  produced no event at all, which is exactly what a run-level partial admits to.
# "invocation"     scoped to one invocation, for every target: the record of what that invocation
#                  supplied has a hole in it, and a hole could have held anything.
# "target"         scoped to one target, or to one target within one invocation.
REASON_EFFECTS = {
    "capture_context_selection_not_observed": "blanket",
    "no_context_selection_events": "blanket",
    "trace_file_missing": "blanket",
    "context_capture_partial_at_run_level": "target_absence",
    "execution_record_invalid": "absence",
    "run_capture_facts_unavailable": "absence",
    "trace_capture_gap": "absence",
    "trace_dropped_events": "absence",
    "trace_events_malformed": "absence",
    "trace_lines_unparsed": "absence",
    "context_event_without_spans": "invocation",
    "unusable_span_without_path": "invocation",
    "target_locations_unavailable": "target",
    "target_locations_without_line_range": "target",
    "unlocated_span_on_target_path": "target",
    "unusable_span_on_target_path": "target",
}
REASON_CODES = tuple(sorted(REASON_EFFECTS))

# A reason this table does not name blocks the negative claim and nothing else. It is the one
# default that cannot make the document say more than it knows: an unrecognized reason is not
# grounds to discard a recorded span, and it is not grounds to prove an absence either.
_DEFAULT_EFFECT = "absence"

# Carried verbatim into every document. These are the claims a reader is most likely to make on
# this diagnostic's behalf if the document does not refuse them first.
NOTES = (
    "An included classification says the target's lines were delivered to the model in that "
    "invocation. It does not say the model attended to them, that what was delivered was "
    "sufficient to recognize the vulnerability, or that a miss is a model failure.",
    "Partial capture weakens the negative claim, never the positive one. A context event that "
    "did not claim complete capture, a reported capture gap, a dropped event, a trace line that "
    "would not parse, and a run whose capture record claims only partial context selection each "
    "leave absence unproven and turn absent into unknown; a span that was recorded was still "
    "delivered, and a lost event cannot un-deliver it. Where nothing was recorded at all - no "
    "trace, no context event, or a capture record claiming no observation - nothing at all may "
    "be concluded. An absent event is never evidence of absent activity.",
    "A span marked location_known false carries text the harness reassembled out of fragments, "
    "whose line numbers count the supplied text rather than the file. Such a span covers nothing "
    "here, and one landing on a target's own path blocks absent for that invocation: the "
    "target's lines may well have been inside it.",
    "An event that reported no spans at all, and a span this could not read, block absent for "
    "their invocation the same way. What a record does not say was supplied cannot be shown not "
    "to have been supplied, and a span missing its coordinates is a hole exactly where the "
    "answer would have come from.",
    "A span's line range is the range of the text actually supplied, so a truncated span is not "
    "discounted for being truncated. The truncated flag is read only for the counts in capture, "
    "where a null value is counted as unknown and never as untruncated.",
    "Whether a candidate the harness produced was later filtered out is a different question. "
    "The finding.candidate, finding.validation, finding.filtered and finding.submitted events "
    "answer that one, and this diagnostic reads none of them.",
    "Only context.selection events are read. File content a model pulled in through its own tool "
    "call is reported on tool.end spans, which are not counted here, so absent means no supplied "
    "context span covered the lines, not that the file was never read.",
    "Labels stay evaluator-side. Accepted locations come from the evaluation plan and the case "
    "pack and never enter a trace; the join happens after the run, in the evaluator.",
)

_TRACE_RELATIVE = "trace/events.jsonl"
_EXECUTION_RECORD = "execution.json"
_PLAN_RELATIVE = "evaluator/plan.json"
_PACK_RELATIVE = "evaluator/pack.json"


class DiagnosticsError(ValueError):
    """A diagnostic could not be computed from the inputs it was given.

    Raised for a directory that is not an invocation bundle, an execution record that is not
    readable JSON, and a bundle with no way to learn what the targets are. A record that is
    readable but breaks its contract, a trace that is absent, and a trace line that will not
    parse are not failures: they are reported inside the document as reasons, because a
    diagnostic about capture gaps has to survive one.
    """


def _normal_path(value: str) -> str:
    """One spelling for a path, so a span and a label that name the same file compare equal.

    Backslashes become forward slashes and ``posixpath.normpath`` drops a leading ``./`` and
    collapses redundant separators, which is exactly what :func:`scaneval.scoring._location` does
    to a claim location: two modules comparing evaluator paths must not disagree about spelling.
    A value that normalizes to nothing addresses no file and is returned as the empty string so it
    matches nothing rather than matching everything.
    """
    normalized = posixpath.normpath(value.replace("\\", "/"))
    return "" if normalized in (".", "..", "/") else normalized


# What one span item turned out to be. A located span places text at file lines; an unlocated one
# names a file but numbers its lines against the prompt; an unusable one names a file and nothing
# this can read. The last two fix a path and no position, which is still worth holding: text from
# that file reached the prompt, so an absence on that path is no longer provable.
_LOCATED = "located"
_UNLOCATED = "unlocated"
_UNUSABLE = "unusable"


def _span_item(item: object) -> tuple[str, str, int, int] | None:
    """Read one span item as a file position, as a path with no position, or as nothing at all.

    Returns ``(_LOCATED, path, start, end)`` when the lines are file lines,
    ``(_UNLOCATED, path, 0, 0)`` when they are not, ``(_UNUSABLE, path, 0, 0)`` when the
    coordinates cannot be read but the path can, and ``None`` when not even the path can.

    The difference between the last two is the difference between a hole this can attribute and
    one it cannot. A span naming the target's file with coordinates this cannot read may well
    have carried the target's lines, and saying ``absent`` over it would be a false negative
    built out of a defect in the emitter. Dropping the path, as this used to, threw away the one
    piece of the span that was still readable.

    ``location_known: false`` marks supplied text the harness reassembled out of fragments: the
    line numbers run 1..N over what was placed in the prompt and name nothing in the file.
    Counting those as file lines would report a target as delivered because some fragment
    happened to be the right number of lines long, which is a false positive with a number
    attached. The flag is opt-in, so absence is the ordinary case: an item that does not carry it
    at all, and one carrying ``True``, are both file positions. An explicit value other than
    ``True`` is read as not known to be one - ``False`` says so outright, and ``null`` is a
    harness saying it does not know, which is never a harness saying it does.

    Unusable means the item places text nowhere at all: it is not a mapping, its ``path`` is
    missing, not a string, or normalizes to nothing, or - for a located span - its lines are
    missing, are not integers (a bool is not an integer here, however Python counts it), start
    below the 1-based first line, or end before they start. Such an item is counted, never
    guessed at.
    """
    if not isinstance(item, Mapping):
        return None
    path = item.get("path")
    if not isinstance(path, str):
        return None
    normalized = _normal_path(path)
    if not normalized:
        return None
    if item.get("location_known", True) is not True:
        return (_UNLOCATED, normalized, 0, 0)
    start, end = item.get("start_line"), item.get("end_line")
    if isinstance(start, bool) or isinstance(end, bool):
        return (_UNUSABLE, normalized, 0, 0)
    if not isinstance(start, int) or not isinstance(end, int):
        return (_UNUSABLE, normalized, 0, 0)
    if start < 1 or end < start:
        return (_UNUSABLE, normalized, 0, 0)
    return (_LOCATED, normalized, start, end)


def _merge(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge closed 1-based line intervals, joining ones that touch as well as ones that overlap.

    Lines 9-10 and 11-12 are a contiguous block of supplied text, not two, so they merge: the
    question this module asks is whether every line of a region was delivered, and a gap of zero
    lines is not a gap.
    """
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _covered_lines(union: Sequence[tuple[int, int]], start: int, end: int) -> int:
    """How many lines of the closed range ``[start, end]`` fall inside a merged union."""
    total = 0
    for low, high in union:
        first, last = max(low, start), min(high, end)
        if first <= last:
            total += last - first + 1
    return total


def _location(item: object) -> tuple[str, int, int] | None:
    """A judgeable accepted location, or ``None`` when the label names no line range.

    A pack location is required to carry a path and a role; its lines are optional, and a case
    whose region has not been narrowed yet carries a path alone. Such a location is counted and
    reported rather than read as "the whole file", because nothing here knows how long the file
    is, and reading it either way would invent a boundary the label did not draw.
    """
    if not isinstance(item, Mapping):
        return None
    path = item.get("path")
    start, end = item.get("start_line"), item.get("end_line")
    if not isinstance(path, str):
        return None
    if isinstance(start, bool) or isinstance(end, bool):
        return None
    if not isinstance(start, int) or not isinstance(end, int):
        return None
    if start < 1 or end < start:
        return None
    normalized = _normal_path(path)
    return (normalized, start, end) if normalized else None


class _ContextEvent:
    """One usable ``context.selection`` event, reduced to what coverage attribution reads."""

    __slots__ = ("event_id", "sequence", "call_id", "producer_id", "capture_status", "spans",
                 "unlocated_paths", "unusable_paths", "span_count", "unusable_spans",
                 "unusable_spans_without_path", "unlocated_spans", "truncated_spans",
                 "truncation_unknown_spans", "has_span_list")

    def __init__(self, event: Mapping) -> None:
        self.event_id: str = event["event_id"]
        self.sequence: int = event["sequence"]
        call_id = event.get("call_id")
        self.call_id: str | None = call_id if isinstance(call_id, str) and call_id else None
        producer = event.get("producer_id")
        self.producer_id: str | None = producer if isinstance(producer, str) and producer else None
        self.capture_status: str = event["capture_status"]
        metadata = event.get("metadata")
        raw = metadata.get("spans") if isinstance(metadata, Mapping) else None
        self.has_span_list = isinstance(raw, list)
        by_path: dict[str, list[tuple[int, int]]] = {}
        unlocated: set[str] = set()
        unreadable: set[str] = set()
        usable = unusable = pathless = adrift = truncated = truncation_unknown = 0
        for item in raw if isinstance(raw, list) else ():
            span = _span_item(item)
            if span is None:
                # Not even a path. Nothing here can be attributed to a target, so it counts
                # against the invocation as a whole rather than against any one of them.
                unusable += 1
                pathless += 1
                continue
            kind, path, start, end = span
            if kind == _UNUSABLE:
                unusable += 1
                unreadable.add(path)
                continue
            if kind == _UNLOCATED:
                # The path is all this span establishes, and that is still worth holding: text
                # from this file reached the prompt, at lines nobody can place.
                adrift += 1
                unlocated.add(path)
                continue
            usable += 1
            by_path.setdefault(path, []).append((start, end))
            # Read for the counts alone. A present False is the only value that says untruncated;
            # True and null and absent all leave it unknown, and none of the three changes a line.
            if item.get("truncated") is True:
                truncated += 1
            elif item.get("truncated") is not False:
                truncation_unknown += 1
        self.spans = {path: _merge(ranges) for path, ranges in by_path.items()}
        self.unlocated_paths = unlocated
        self.unusable_paths = unreadable
        self.span_count = usable
        self.unusable_spans = unusable
        self.unusable_spans_without_path = pathless
        self.unlocated_spans = adrift
        self.truncated_spans = truncated
        self.truncation_unknown_spans = truncation_unknown

    @property
    def sort_key(self) -> tuple[int, str]:
        return (self.sequence, self.event_id)


class _Group:
    """The ``context.selection`` events of one invocation, and the union of their spans.

    An invocation is a ``call_id`` *within one producer*, never a ``call_id`` alone. A call ID is
    minted by whoever emits it and is unique only to that emitter, so two producers that both
    number their first invocation ``call-1`` are two invocations. Merging them would pool their
    spans, and a target whose halves were supplied to two different producers would read as
    fully included in one prompt that never existed. The union across invocations is where that
    question belongs, and it answers it with ``scattered``.

    An event carrying no usable ``call_id`` or no usable ``producer_id`` - absent, or not a
    non-empty string, which the wire contract forbids anyway - is its own group, keyed by its
    event ID. Two such events say nothing about belonging together.
    """

    __slots__ = ("call_id", "producer_id", "key", "group_key", "events", "spans",
                 "unlocated_paths", "unusable_paths")

    def __init__(self, key: tuple[str | None, str], events: list[_ContextEvent]) -> None:
        self.key = key
        self.events = sorted(events, key=lambda event: event.sort_key)
        first = self.events[0]
        correlated = key[0] is not None
        self.producer_id = first.producer_id if correlated else None
        self.call_id = first.call_id if correlated else None
        # Readable, and unique only beside ``producer_id``: two producers may both say "call-1".
        self.group_key = self.call_id if correlated else first.event_id
        self.spans = _union_spans(self.events)
        self.unlocated_paths = _union_unlocated_paths(self.events)
        self.unusable_paths = _union_unusable_paths(self.events)

    @property
    def first_sequence(self) -> int:
        return self.events[0].sequence

    @property
    def sort_key(self) -> tuple[int, str, str]:
        return (self.first_sequence, self.producer_id or "", self.group_key)

    @property
    def all_complete(self) -> bool:
        return all(event.capture_status == "complete" for event in self.events)

    @property
    def events_without_spans(self) -> int:
        return sum(1 for event in self.events if not event.has_span_list)

    @property
    def unusable_spans_without_path(self) -> int:
        return sum(event.unusable_spans_without_path for event in self.events)


def _union_spans(events: Iterable[_ContextEvent]) -> dict[str, list[tuple[int, int]]]:
    by_path: dict[str, list[tuple[int, int]]] = {}
    for event in events:
        for path, ranges in event.spans.items():
            by_path.setdefault(path, []).extend(ranges)
    return {path: _merge(ranges) for path, ranges in by_path.items()}


def _union_unlocated_paths(events: Iterable[_ContextEvent]) -> set[str]:
    """Every path some span reached without saying where in the file it landed."""
    paths: set[str] = set()
    for event in events:
        paths |= event.unlocated_paths
    return paths


def _union_unusable_paths(events: Iterable[_ContextEvent]) -> set[str]:
    """Every path some span named with coordinates this could not read."""
    paths: set[str] = set()
    for event in events:
        paths |= event.unusable_paths
    return paths


def _event_ids(events: Iterable[_ContextEvent]) -> list[str]:
    return [event.event_id for event in sorted(events, key=lambda event: event.sort_key)]


def _overlap(locations: Sequence[tuple[str, int, int]],
             spans: Mapping[str, Sequence[tuple[int, int]]]) -> dict:
    """The arithmetic of coverage: how much of each judgeable location a span union holds.

    This is deliberately separate from classification. It makes no claim about capture, so it
    stays true and reportable even where the verdict has to be ``unknown``, and a reader can see
    that the lines were in fact present in a run whose record was too broken to say so.
    """
    details = []
    covered = needed = full_locations = 0
    for path, start, end in locations:
        lines = end - start + 1
        hit = _covered_lines(spans.get(path, ()), start, end)
        covered += hit
        needed += lines
        if hit == lines:
            full_locations += 1
        details.append({
            "path": path,
            "start_line": start,
            "end_line": end,
            "lines": lines,
            "covered_lines": hit,
            "coverage": "full" if hit == lines else ("partial" if hit else "none"),
        })
    if locations and full_locations == len(locations):
        overlap = "full"
    elif covered:
        overlap = "partial"
    else:
        overlap = "none"
    return {
        "overlap": overlap,
        "covered_lines": covered,
        "needed_lines": needed,
        "locations_covered": full_locations,
        "locations_total": len(locations),
        "locations": details,
    }


def _classify(overlap: str, *, all_complete: bool, blanket_unknown: bool, absence_blocked: bool,
              unjudgeable: bool) -> str:
    """Turn an overlap and the capture facts behind it into one of the four classifications.

    Everything here can only weaken a verdict, never strengthen one, and the weakenings are not
    all the same size. That is the point of the split.

    ``blanket_unknown`` is the only one that reaches a positive verdict, and it is reserved for a
    record that holds nothing: no trace file, no context event, or a capture record claiming the
    category was never observed. There is no span to discuss, so there is nothing to conclude.

    ``absence_blocked`` is the ordinary incomplete record - a reported capture gap, a dropped
    event, a trace line that would not parse, an unlocated span sitting on this target's path. It
    takes ``absent`` to ``unknown`` and leaves ``included`` and ``partial`` exactly where they
    were, because a span that is in the trace was delivered whatever else went missing, and a
    lost event cannot un-deliver one. Discarding that evidence would be its own kind of dishonesty:
    the diagnostic would report "we do not know" about something the record plainly shows.

    ``all_complete`` is the same rule at the finest grain: ``absent`` needs every context event of
    the invocation to have claimed complete capture, or no overlap means only that no overlap was
    *recorded*.

    ``unjudgeable`` is about the label rather than the trace. A location the pack left without a
    line range caps the verdict at ``partial``: it might be covered or might not, so ``included``
    would overclaim and ``absent`` would deny something never looked at.
    """
    if blanket_unknown:
        return "unknown"
    if overlap == "full":
        return "partial" if unjudgeable else "included"
    if overlap == "partial":
        return "partial"
    if unjudgeable or absence_blocked or not all_complete:
        return "unknown"
    return "absent"


def _contributing(events: Iterable[_ContextEvent],
                  locations: Sequence[tuple[str, int, int]]) -> list[str]:
    """The events whose own spans covered at least one line the label names.

    A group's verdict rests on the union of its spans, but a reader chasing a span back to its
    source wants the events that actually carried it, not the ones that happened to sit in the
    same invocation.
    """
    hits = []
    for event in events:
        if any(_covered_lines(event.spans.get(path, ()), start, end)
               for path, start, end in locations):
            hits.append(event)
    return _event_ids(hits)


def _run_reasons(execution_record: Mapping | None, *, trace_read: bool, malformed_lines: int,
                 malformed_events: int, context_events: int) -> set[str]:
    """Every way the record as a whole falls short, whatever each one costs.

    What each costs is :data:`REASON_EFFECTS`; this only finds them. They are reported together
    rather than first-wins: a bundle with two holes in it should say so, and a reader fixing one
    wants to know about the other.
    """
    reasons: set[str] = set()
    if not trace_read:
        reasons.add("trace_file_missing")
    elif not context_events:
        # Only when a trace was actually read: a missing file already says why there are none.
        reasons.add("no_context_selection_events")
    if malformed_lines:
        reasons.add("trace_lines_unparsed")
    if malformed_events:
        reasons.add("trace_events_malformed")
    if execution_record is None:
        reasons.add("run_capture_facts_unavailable")
        return reasons
    capture = execution_record.get("capture")
    value = capture.get("context_selection") if isinstance(capture, Mapping) else None
    if not isinstance(value, str):
        reasons.add("run_capture_facts_unavailable")
    elif value not in _OBSERVED_CAPTURE:
        reasons.add("capture_context_selection_not_observed")
    elif value != "complete":
        # The run says it observed context selection and did not see all of it. Every event in
        # the trace may be complete in itself and the trace still be missing whole invocations,
        # and one of those could have carried this target. A per-invocation absent is unharmed -
        # it answers only for the events that invocation produced - but a target's own verdict
        # has to answer for the invocations that left no event at all, so it cannot be absent.
        # "redacted" lands here too: a record stored with values hidden is not a whole one.
        reasons.add("context_capture_partial_at_run_level")
    trace = execution_record.get("trace")
    if isinstance(trace, Mapping):
        if trace.get("capture_gap") is True:
            reasons.add("trace_capture_gap")
        dropped = trace.get("dropped_events")
        if isinstance(dropped, int) and not isinstance(dropped, bool) and dropped > 0:
            reasons.add("trace_dropped_events")
    return reasons


def _read_context_events(events: Iterable[Mapping] | None) -> tuple[list[_ContextEvent], int, int]:
    """Usable ``context.selection`` events, how many events were read, and how many were malformed.

    An event missing the fields the schema requires is counted and skipped rather than patched:
    without an ID it cannot be cited, without a sequence it cannot be ordered, and without a
    capture status it cannot say how much it saw. A malformed event could have been the one
    carrying the span that matters, which is why the count becomes a reason of its own.
    """
    usable: list[_ContextEvent] = []
    total = malformed = 0
    for event in events or ():
        if not isinstance(event, Mapping):
            malformed += 1
            continue
        total += 1
        if event.get("type") != "context.selection":
            continue
        event_id, sequence = event.get("event_id"), event.get("sequence")
        status = event.get("capture_status")
        if (not isinstance(event_id, str) or not event_id
                or isinstance(sequence, bool) or not isinstance(sequence, int)
                or not isinstance(status, str)):
            malformed += 1
            continue
        usable.append(_ContextEvent(event))
    return usable, total, malformed


def _group(events: Sequence[_ContextEvent]) -> list[_Group]:
    """Partition context events into invocations, keyed by producer and call together.

    The key is a pair rather than a string so no spelling of a producer or a call ID can collide
    with another pair by concatenation. An event missing either half is keyed by its own event ID
    under a ``None`` producer, which cannot collide with a correlated key.
    """
    by_key: dict[tuple[str | None, str], list[_ContextEvent]] = {}
    for event in events:
        if event.call_id is not None and event.producer_id is not None:
            key: tuple[str | None, str] = (event.producer_id, event.call_id)
        else:
            key = (None, event.event_id)
        by_key.setdefault(key, []).append(event)
    groups = [_Group(key, members) for key, members in by_key.items()]
    return sorted(groups, key=lambda group: group.sort_key)


def _target_locations(target: Mapping) -> tuple[list[tuple[str, int, int]], int, int, set[str]]:
    """The judgeable locations of a target, how many it declared, how many lack line ranges, and
    every path it named.

    The path set covers locations with no line range as well, because an unlocated span landing on
    one of those is still a reason to doubt an absence, and saying so costs nothing where the
    verdict was going to be ``unknown`` anyway.
    """
    declared = target.get("accepted_locations")
    declared = declared if isinstance(declared, list) else []
    judgeable = [location for location in (_location(item) for item in declared)
                 if location is not None]
    paths = set()
    for item in declared:
        path = item.get("path") if isinstance(item, Mapping) else None
        normalized = _normal_path(path) if isinstance(path, str) else ""
        if normalized:
            paths.add(normalized)
    return judgeable, len(declared), len(declared) - len(judgeable), paths


def context_coverage(*, plan_targets: Iterable[Mapping], events: Iterable[Mapping] | None,
                     execution_record: Mapping | None, malformed_lines: int = 0,
                     extra_reasons: Iterable[str] = (), sources: Mapping | None = None) -> dict:
    """Attribute each labeled target to the invocations whose supplied context held its lines.

    ``plan_targets`` are mappings carrying ``target_id`` and ``accepted_locations``; the locations
    come from the evaluator's pack, joined to the plan by target ID upstream of this call.
    ``events`` are the trace's events as parsed mappings, or ``None`` to say the trace file was
    not read at all, which is not the same fact as a trace holding no events and is not reported
    as one. ``execution_record`` supplies the run's own capture claims; ``None`` says they could
    not be read, which leaves every negative answer unproven. ``malformed_lines`` and
    ``extra_reasons`` let a loader report what it could not parse without this function reading a
    file. ``sources`` is copied into the document verbatim to say where the inputs came from.

    Pure: no clock, no filesystem, no network, and no mutation of anything passed in.
    """
    context_events, events_read, malformed_events = _read_context_events(events)
    groups = _group(context_events)
    trace_read = events is not None
    reasons = _run_reasons(execution_record, trace_read=trace_read, malformed_lines=malformed_lines,
                           malformed_events=malformed_events, context_events=len(context_events))
    reasons.update(str(reason) for reason in extra_reasons)
    effects = {REASON_EFFECTS.get(reason, _DEFAULT_EFFECT) for reason in reasons}
    blanket = "blanket" in effects
    absence_blocked_run = "absence" in effects
    absence_blocked_target = absence_blocked_run or "target_absence" in effects
    run_spans = _union_spans(context_events)
    run_complete = all(event.capture_status == "complete" for event in context_events)

    targets = []
    for target in sorted(plan_targets, key=lambda item: str(item.get("target_id", ""))):
        locations, declared, without_range, target_paths = _target_locations(target)
        unjudgeable = without_range > 0 or not locations
        target_reasons = set(reasons)
        if not declared:
            target_reasons.add("target_locations_unavailable")
        elif without_range:
            target_reasons.add("target_locations_without_line_range")

        by_invocation = []
        for group in groups:
            detail = _overlap(locations, group.spans)
            adrift = sorted(group.unlocated_paths & target_paths)
            unreadable = sorted(group.unusable_paths & target_paths)
            # Every way this invocation's record of what it supplied has a hole in it. Each is a
            # place the target's lines could have been without the trace showing it, so each
            # takes absent to unknown and leaves a recorded span exactly where it was.
            group_reasons = []
            if group.events_without_spans:
                group_reasons.append("context_event_without_spans")
            if group.unusable_spans_without_path:
                group_reasons.append("unusable_span_without_path")
            if adrift:
                group_reasons.append("unlocated_span_on_target_path")
            if unreadable:
                group_reasons.append("unusable_span_on_target_path")
            group_reasons.sort()
            classification = _classify(detail["overlap"], all_complete=group.all_complete,
                                       blanket_unknown=blanket, unjudgeable=unjudgeable,
                                       absence_blocked=absence_blocked_run or bool(group_reasons))
            target_reasons.update(group_reasons)
            by_invocation.append({
                "producer_id": group.producer_id,
                "call_id": group.call_id,
                "group_key": group.group_key,
                "first_sequence": group.first_sequence,
                "classification": classification,
                "event_ids": _event_ids(group.events),
                "contributing_event_ids": _contributing(group.events, locations),
                "capture_status": sorted({event.capture_status for event in group.events}),
                "all_capture_complete": group.all_complete,
                "unlocated_spans": sum(event.unlocated_spans for event in group.events),
                "unlocated_target_paths": adrift,
                "unusable_target_paths": unreadable,
                "events_without_spans": group.events_without_spans,
                "reasons": group_reasons,
                **detail,
            })

        # A target's absence has to answer for every invocation, so one invocation that cannot
        # prove its own absence is enough to stop the target claiming one. Without this, an
        # invocation with a hole in its record reads unknown while a second, cleaner one carries
        # the target-level verdict all the way to absent - the false negative in miniature.
        blocked_anywhere = any(entry["reasons"] for entry in by_invocation)
        best = max((entry["classification"] for entry in by_invocation),
                   key=lambda name: _RANK[name], default="unknown")
        if best == "absent" and (absence_blocked_target or blocked_anywhere):
            best = "unknown"
        union_detail = _overlap(locations, run_spans)
        union_classification = _classify(
            union_detail["overlap"], all_complete=run_complete, blanket_unknown=blanket,
            unjudgeable=unjudgeable,
            absence_blocked=absence_blocked_target or blocked_anywhere)
        scattered = bool(by_invocation) and all(
            _RANK[union_classification] > _RANK[entry["classification"]] for entry in by_invocation)
        # Grouped by verdict, then ordered the way every other event list here is ordered, so a
        # reader can line the IDs up against the trace without first sorting them.
        by_class: dict[str, list[_ContextEvent]] = {name: [] for name in CLASSIFICATIONS}
        for group, entry in zip(groups, by_invocation):
            by_class[entry["classification"]].extend(group.events)
        by_class_ids = {name: _event_ids(members) for name, members in by_class.items()}
        union_events = (_contributing(context_events, locations)
                        if union_classification in ("included", "partial")
                        else _event_ids(context_events))
        targets.append({
            "target_id": target.get("target_id"),
            "best": best,
            "union": {
                "classification": union_classification,
                "scattered": scattered,
                "event_ids": union_events,
                **union_detail,
            },
            "by_invocation": by_invocation,
            "event_ids": by_class_ids,
            "locations": [{"path": path, "start_line": start, "end_line": end,
                           "lines": end - start + 1} for path, start, end in locations],
            "locations_declared": declared,
            "locations_without_line_range": without_range,
            "reasons": sorted(target_reasons),
        })

    return {
        "schema_version": "2.0",
        "diagnostic": DIAGNOSTIC_NAME,
        "diagnostic_version": DIAGNOSTIC_VERSION,
        "scaneval_version": __version__,
        "run_id": _field(execution_record, "run_id"),
        "invocation_id": _field(execution_record, "invocation_id"),
        "input_id": _field(execution_record, "input_id"),
        "system_id": _field(execution_record, "system_id"),
        "sources": dict(sources) if sources else {},
        "capture": _capture_facts(execution_record, trace_read=trace_read,
                                  events_read=events_read, malformed_lines=malformed_lines,
                                  malformed_events=malformed_events, context_events=context_events,
                                  groups=groups, run_complete=run_complete),
        "reasons": sorted(reasons),
        # The same codes split by what they cost, so a reader does not have to carry
        # REASON_EFFECTS in their head to know whether a verdict was weakened or erased.
        "reasons_blocking_all_classification": sorted(
            reason for reason in reasons
            if REASON_EFFECTS.get(reason, _DEFAULT_EFFECT) == "blanket"),
        "reasons_blocking_absence": sorted(
            reason for reason in reasons
            if REASON_EFFECTS.get(reason, _DEFAULT_EFFECT) in ("absence", "target_absence")),
        "counts": _counts(targets),
        "invocations": [
            {
                "producer_id": group.producer_id,
                "call_id": group.call_id,
                "group_key": group.group_key,
                "first_sequence": group.first_sequence,
                "events": len(group.events),
                "event_ids": _event_ids(group.events),
                "capture_status": sorted({event.capture_status for event in group.events}),
                "all_capture_complete": group.all_complete,
                "spans": sum(event.span_count for event in group.events),
                "unusable_spans": sum(event.unusable_spans for event in group.events),
                "unlocated_spans": sum(event.unlocated_spans for event in group.events),
                "events_without_spans": group.events_without_spans,
                "paths": len(group.spans),
            }
            for group in groups
        ],
        "targets": targets,
        "notes": list(NOTES),
    }


def _field(record: Mapping | None, name: str):
    value = record.get(name) if isinstance(record, Mapping) else None
    return value if isinstance(value, str) else None


def _capture_facts(execution_record: Mapping | None, *, trace_read: bool, events_read: int,
                   malformed_lines: int, malformed_events: int,
                   context_events: Sequence[_ContextEvent], groups: Sequence[_Group],
                   run_complete: bool) -> dict:
    """The capture facts every classification in this document rests on, stated once.

    Both halves are here on purpose: what the run said about itself (the execution record's
    ``capture`` and ``trace``) and what this read of the trace actually found. They can disagree,
    and a reader deciding whether to trust an ``absent`` needs to see both rather than a single
    number that hides which one it came from. Counts only: a span's path is supplied source, and
    listing the files a harness sent a model is not this diagnostic's business.
    """
    capture = execution_record.get("capture") if isinstance(execution_record, Mapping) else None
    trace = execution_record.get("trace") if isinstance(execution_record, Mapping) else None
    capture = capture if isinstance(capture, Mapping) else {}
    trace = trace if isinstance(trace, Mapping) else {}
    by_status: dict[str, int] = {}
    for event in context_events:
        by_status[event.capture_status] = by_status.get(event.capture_status, 0) + 1
    return {
        "context_selection": capture.get("context_selection"),
        "trace_mode": trace.get("mode"),
        "trace_events_recorded": trace.get("events"),
        "trace_capture_gap": trace.get("capture_gap"),
        "trace_dropped_events": trace.get("dropped_events"),
        "trace_file_read": trace_read,
        "trace_lines_unparsed": malformed_lines,
        "events_read": events_read if trace_read else None,
        "context_selection_events": len(context_events),
        "context_selection_events_malformed": malformed_events,
        "context_selection_events_by_capture_status": dict(sorted(by_status.items())),
        "context_selection_events_all_complete": run_complete if context_events else False,
        "invocations_with_context": len(groups),
        "spans": sum(event.span_count for event in context_events),
        "unusable_spans": sum(event.unusable_spans for event in context_events),
        "unusable_spans_without_path": sum(event.unusable_spans_without_path
                                           for event in context_events),
        "unlocated_spans": sum(event.unlocated_spans for event in context_events),
        "truncated_spans": sum(event.truncated_spans for event in context_events),
        "truncation_unknown_spans": sum(event.truncation_unknown_spans
                                        for event in context_events),
        "events_without_span_list": sum(1 for event in context_events if not event.has_span_list),
    }


def _counts(targets: Sequence[Mapping]) -> dict:
    best: dict[str, int] = {name: 0 for name in CLASSIFICATIONS}
    union: dict[str, int] = {name: 0 for name in CLASSIFICATIONS}
    for target in targets:
        best[target["best"]] += 1
        union[target["union"]["classification"]] += 1
    return {
        "targets": len(targets),
        "locations_declared": sum(target["locations_declared"] for target in targets),
        "locations_without_line_range": sum(target["locations_without_line_range"]
                                            for target in targets),
        "best": best,
        "union": union,
        "scattered_targets": sum(1 for target in targets if target["union"]["scattered"]),
    }


def _read_json(path: Path, what: str) -> dict:
    """Read one supplied JSON object, naming the file when it cannot be read.

    Used for the plan and the pack, which are read for their labels rather than validated here.
    A pack that no longer satisfies its contract still names the regions a case is about, and
    refusing to run the diagnostic over it would withhold the answer over a defect in a field
    coverage attribution never reads. ``scaneval validate case-pack`` is the command that judges
    a pack; this one only asks it where the target is.
    """
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError, RecursionError) as exc:
        raise DiagnosticsError(f"could not read the {what} {path.name}: {exc}") from exc
    if not isinstance(document, dict):
        raise DiagnosticsError(f"the {what} {path.name} is not a JSON object")
    return document


def _trace_path(invocation_dir: Path, execution_record: Mapping | None) -> Path | None:
    """Where this bundle's trace file is, or ``None`` when it holds none this module will read.

    The execution record names the path the run actually wrote, relative to the bundle root, so
    that is preferred over the conventional location. It is still checked: a declared path that
    escapes the bundle, or that arrives through a symbolic link, is refused rather than followed,
    the same way :func:`scaneval.execution._read_trace` refuses to count one. A diagnostic reading
    a file the bundle does not contain would describe some other run.
    """
    declared = execution_record.get("trace") if isinstance(execution_record, Mapping) else None
    relative = declared.get("path") if isinstance(declared, Mapping) else None
    candidate = invocation_dir / (relative if isinstance(relative, str) and relative
                                  else _TRACE_RELATIVE)
    if candidate.is_symlink() or not candidate.is_file():
        return None
    root = invocation_dir.resolve()
    return candidate if candidate.resolve().is_relative_to(root) else None


def _read_trace(path: Path) -> tuple[list[dict], int]:
    """Parse a JSONL trace into event mappings, counting the lines that would not parse.

    A line this cannot read is counted, never dropped silently: it might have been the
    ``context.selection`` event that settles a target, so the count becomes a reason that turns
    every answer in the document ``unknown``.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError) as exc:
        raise DiagnosticsError(f"could not read the trace {path.name}: {exc}") from exc
    events: list[dict] = []
    malformed = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        if isinstance(event, dict):
            events.append(event)
        else:
            malformed += 1
    return events, malformed


def _pack_locations(pack: Mapping) -> dict[str, dict]:
    """Accepted locations from a case pack, keyed by target ID."""
    cases = pack.get("cases")
    by_target: dict[str, dict] = {}
    for case in cases if isinstance(cases, list) else ():
        target = case.get("target") if isinstance(case, Mapping) else None
        if not isinstance(target, Mapping):
            continue
        target_id = target.get("target_id")
        if isinstance(target_id, str) and target_id:
            by_target[target_id] = dict(target)
    return by_target


def _targets_for(invocation_dir: Path, execution_record: Mapping | None,
                 pack_path: Path | None) -> tuple[list[dict], dict]:
    """The targets to attribute, and a record of where their locations came from.

    The plan in the bundle is preferred, because it is what this invocation was actually scored
    against: a pack can hold cases for snapshots this run never saw. The plan alone is not enough,
    though. Its target contract carries an ID, a description, a kind and a validation level and
    nothing about lines, so the accepted locations have to come from the pack and be joined on
    the target ID. A plan target the pack does not name keeps its place in the output with no
    locations, and is reported as ``unknown``: a target the diagnostic cannot locate is not a
    target that was never supplied.

    With no plan, the pack alone is used, narrowed to the snapshot the execution record says this
    invocation scanned, so a three-case pack does not answer for three repositories at once.
    """
    plan_file = invocation_dir / _PLAN_RELATIVE
    plan = _read_json(plan_file, "evaluation plan") if plan_file.is_file() else None
    if pack_path is not None:
        pack_file = Path(pack_path)
        if not pack_file.is_file():
            raise DiagnosticsError(f"{pack_file} is not a case pack file")
    else:
        candidate = invocation_dir.parent.parent / _PACK_RELATIVE
        pack_file = candidate if candidate.is_file() else None
    pack = _read_json(pack_file, "case pack") if pack_file is not None else None
    by_target = _pack_locations(pack) if pack is not None else {}
    source = {
        "execution_record": _EXECUTION_RECORD,
        "plan": _PLAN_RELATIVE if plan is not None else None,
        "pack": _pack_identity(pack),
        "targets_from": ("plan" if plan is not None and pack is None else
                         "plan+pack" if plan is not None else "pack"),
    }

    if plan is not None:
        declared = plan.get("targets")
        targets = []
        for entry in declared if isinstance(declared, list) else ():
            if not isinstance(entry, Mapping):
                continue
            target_id = entry.get("target_id")
            located = by_target.get(target_id) if isinstance(target_id, str) else None
            targets.append({
                "target_id": target_id,
                "accepted_locations": (located or {}).get("accepted_locations") or [],
            })
        return targets, source
    if pack is None:
        raise DiagnosticsError(
            f"{invocation_dir} holds no {_PLAN_RELATIVE} and no case pack was found beside it; "
            "pass --pack to name the pack that carries the accepted locations")
    snapshot = _field(execution_record, "input_id")
    targets = [
        {"target_id": target_id, "accepted_locations": target.get("accepted_locations") or []}
        for target_id, target in by_target.items()
        if snapshot is None or target.get("snapshot_id") == snapshot
    ]
    return targets, source


def _pack_identity(pack: Mapping | None) -> dict | None:
    """Name a pack by what it says it is, never by where it sits on this machine."""
    if pack is None:
        return None
    return {key: pack.get(key) if isinstance(pack.get(key), str) else None
            for key in ("namespace", "pack_id", "version")}


def context_coverage_for_invocation(invocation_dir: Path, pack_path: Path | None = None) -> dict:
    """Run coverage attribution over one saved invocation bundle.

    Reads ``execution.json`` for the run's capture claims, the trace it declares for the
    ``context.selection`` events, and the plan and pack for the targets. Only the execution record
    is required: a bundle whose trace was never written, or was written and lost, produces a
    document that says so and classifies every target ``unknown``, which is the whole point of
    reporting capture facts beside classifications.

    An execution record that parses but breaks its contract is used anyway, with a reason
    recorded. The diagnostic reads two of its fields, and refusing the answer because some other
    field is wrong would withhold evidence over a defect that does not touch it.
    """
    invocation_dir = Path(invocation_dir)
    if not invocation_dir.is_dir():
        raise DiagnosticsError(
            f"{invocation_dir} is not an invocation directory; context coverage reads "
            f"{_EXECUTION_RECORD} and {_TRACE_RELATIVE} inside one")
    record_path = invocation_dir / _EXECUTION_RECORD
    if not record_path.is_file():
        raise DiagnosticsError(f"{invocation_dir} holds no {_EXECUTION_RECORD}; it is not an "
                               "invocation bundle this diagnostic can read")
    extra_reasons = []
    try:
        execution_record: dict | None = load_document(record_path, "execution-record")
    except ContractError:
        execution_record = _read_json(record_path, "execution record")
        extra_reasons.append("execution_record_invalid")

    trace_file = _trace_path(invocation_dir, execution_record)
    events, malformed_lines = _read_trace(trace_file) if trace_file is not None else (None, 0)
    targets, source = _targets_for(invocation_dir, execution_record, pack_path)
    source["trace"] = (trace_file.relative_to(invocation_dir).as_posix()
                       if trace_file is not None else None)
    return context_coverage(plan_targets=targets, events=events,
                            execution_record=execution_record, malformed_lines=malformed_lines,
                            extra_reasons=extra_reasons, sources=source)
