"""Coverage attribution over saved invocation bundles.

Every bundle here is built in ``tmp_path`` from synthetic records. The spans, the paths and the
accepted locations are invented; no real source, no real run and no operator path is involved,
which is what lets the interesting cases (a capture gap, a malformed line, a trace that was never
written) be tested at all. One test reads a real bundle under ``results/`` when the working copy
happens to hold one, and skips when it does not: run records are not committed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scaneval import diagnostics
from scaneval.cli import main


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "run-diagnostics"
SNAPSHOT = "example-0123abcd"
SYSTEM = "example-system"
INVOCATION = f"{SNAPSHOT}__{SYSTEM}__r1"
TARGET = "T-example-1"
DIGEST = "sha256:" + "0" * 64


def execution_record(**overrides) -> dict:
    """A contract-valid execution record for a bundle that traced in metadata mode.

    Only ``capture`` and ``trace`` matter to this diagnostic; the rest is here so the record
    loads as the contract it claims to be, the way a real one does.
    """
    record = {
        "schema_version": "2.0",
        "run_id": RUN_ID,
        "invocation_id": INVOCATION,
        "input_id": SNAPSHOT,
        "system_id": SYSTEM,
        "repetition": 1,
        "adapter": {"name": "example-adapter", "version": "1.0.0"},
        "versions": {"scaneval": "2.0.0a1"},
        "status": "success",
        "exit_code": 0,
        "timed_out": False,
        "command": ["example-adapter", "--scan"],
        "started_at": "2026-09-20T00:00:00+00:00",
        "finished_at": "2026-09-20T00:01:00+00:00",
        "wall_seconds": 60.0,
        "timeout_seconds": 600.0,
        "tool_versions": {"example-adapter": "1.0.0"},
        "model_identity": {"requested": "example/model", "resolved": None,
                           "verification": "unverified"},
        "system_config": {"mode": "full"},
        "network_policy": {"declared": "none", "enforced": False, "note": "recorded, not enforced"},
        "environment": {"passthrough": ["PATH"]},
        "capture": {"context_selection": "complete", "model_requests": "complete",
                    "model_responses": "complete", "tool_calls": "unavailable",
                    "finding_candidate": "unavailable", "finding_filtered": "unavailable",
                    "finding_submitted": "complete", "finding_validation": "unavailable"},
        "trace": {"path": "trace/events.jsonl", "events": 1, "mode": "metadata",
                  "capture_gap": False, "dropped_events": 0},
        "provenance": {"tree_hash": DIGEST, "provenance_sha256": DIGEST, "profile": "standard",
                       "synthetic_history": None, "source_modified": False,
                       "modified_paths": [], "captured_state_dirs": []},
        "preparation": {},
        "unsupported_languages": [],
        "error": None,
        "import_error": None,
        "notes": [],
        "raw_artifacts": [],
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(record.get(key), dict):
            record[key] = {**record[key], **value}
        else:
            record[key] = value
    return record


def span(path: str, start: int, end: int, **overrides) -> dict:
    """One supplied span in the shape Contract 3 puts in ``metadata.spans``."""
    item = {"path": path, "start_line": start, "end_line": end, "chars": (end - start + 1) * 30,
            "sha256": "0" * 64, "truncated": False, "role": "primary"}
    item.update(overrides)
    return item


def event(sequence: int, *, spans=(), call_id="call-1", capture_status="complete",
          event_id=None, event_type="context.selection", metadata=None,
          producer_id="example-producer") -> dict:
    """One trace event with the fields the v2 schema requires, spans in metadata only."""
    record = {
        "schema_version": "2.0",
        "event_id": event_id or f"event-{sequence}",
        "run_id": RUN_ID,
        "producer_id": producer_id,
        "sequence": sequence,
        "type": event_type,
        "category": event_type.split(".", 1)[0],
        "capture_status": capture_status,
        "timestamp": "2026-09-20T00:00:30.000Z",
        "metadata": metadata if metadata is not None else {
            "source": "harness_emitted", "stage": "llm-static.file",
            "prompt_chars": 4000, "spans": list(spans), "span_count": len(spans),
            "truncated_spans": 0, "omitted_paths": [],
        },
    }
    if call_id is not None:
        record["call_id"] = call_id
    return record


def pack(locations, *, target_id=TARGET, snapshot_id=SNAPSHOT) -> dict:
    """A case pack reduced to what coverage attribution reads out of one."""
    return {
        "schema_version": "2.0",
        "namespace": "example.local",
        "pack_id": "example-pack",
        "version": "0.1.0-draft",
        "cases": [{
            "case_id": "example-case",
            "target": {"target_id": target_id, "snapshot_id": snapshot_id,
                       "accepted_locations": list(locations)},
        }],
    }


def plan(*target_ids) -> dict:
    return {
        "schema_version": "2.0",
        "input_hash": DIGEST,
        "scope": "draft",
        "targets": [{"target_id": target_id, "description": "example mechanism",
                     "validation_level": "L1", "kind": "ssrf"} for target_id in target_ids],
        "controls": [],
        "review_budgets": [5, 10],
    }


def build_bundle(tmp_path: Path, *, events=(), record=None, locations=(), targets=(TARGET,),
                 write_trace=True, write_plan=True, write_pack=True, trace_text=None) -> Path:
    """Write a run directory holding one invocation bundle, and return the invocation directory.

    The layout mirrors a real run: ``<run>/evaluator/pack.json`` beside
    ``<run>/invocations/<name>/{execution.json,evaluator/plan.json,trace/events.jsonl}``, which is
    where the loader looks when it is given the invocation directory alone.
    """
    run = tmp_path / "run"
    invocation = run / "invocations" / INVOCATION
    (invocation / "evaluator").mkdir(parents=True)
    (run / "evaluator").mkdir(parents=True, exist_ok=True)
    (invocation / "execution.json").write_text(
        json.dumps(record if record is not None else execution_record()), encoding="utf-8")
    if write_plan:
        (invocation / "evaluator" / "plan.json").write_text(json.dumps(plan(*targets)),
                                                            encoding="utf-8")
    if write_pack:
        (run / "evaluator" / "pack.json").write_text(json.dumps(pack(locations)), encoding="utf-8")
    if write_trace:
        (invocation / "trace").mkdir()
        text = trace_text if trace_text is not None else "".join(
            json.dumps(item) + "\n" for item in events)
        (invocation / "trace" / "events.jsonl").write_text(text, encoding="utf-8")
    return invocation


def only_target(document: dict) -> dict:
    assert len(document["targets"]) == 1
    return document["targets"][0]


def region(path="src/example.py", start=10, end=20, **overrides) -> dict:
    location = {"path": path, "start_line": start, "end_line": end, "role": "sink"}
    location.update(overrides)
    return location


# --- classification ---------------------------------------------------------------------------


def test_a_target_whose_every_line_was_supplied_in_one_invocation_is_included(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        events=[event(1, spans=[span("src/example.py", 1, 40)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    target = only_target(document)
    assert target["best"] == "included"
    assert target["union"]["classification"] == "included"
    assert target["union"]["scattered"] is False
    assert target["event_ids"]["included"] == ["event-1"]
    assert target["by_invocation"][0]["covered_lines"] == 11
    assert target["by_invocation"][0]["contributing_event_ids"] == ["event-1"]
    assert document["reasons"] == []


def test_covering_half_the_lines_of_a_location_is_partial(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=19)],
        events=[event(1, spans=[span("src/example.py", 10, 14)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "partial"
    assert target["union"]["covered_lines"] == 5
    assert target["union"]["needed_lines"] == 10
    assert target["by_invocation"][0]["locations"][0]["coverage"] == "partial"
    assert target["event_ids"]["partial"] == ["event-1"]


def test_covering_one_of_two_accepted_locations_is_partial(tmp_path):
    invocation = build_bundle(
        tmp_path,
        locations=[region("src/a.py", 1, 5), region("src/b.py", 1, 5)],
        events=[event(1, spans=[span("src/a.py", 1, 5)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "partial"
    assert target["union"]["locations_covered"] == 1
    assert target["union"]["locations_total"] == 2
    assert [item["coverage"] for item in target["union"]["locations"]] == ["full", "none"]


def test_no_overlap_under_complete_capture_is_absent(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        events=[event(1, spans=[span("src/other.py", 1, 400),
                                span("src/example.py", 100, 140)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    target = only_target(document)
    assert target["best"] == "absent"
    assert target["union"]["classification"] == "absent"
    assert target["union"]["covered_lines"] == 0
    assert target["event_ids"]["absent"] == ["event-1"]
    assert target["reasons"] == []


def test_adjacent_spans_in_one_invocation_cover_a_region_neither_covers_alone(tmp_path):
    """Lines 10-14 and 15-20 are one contiguous block of supplied text, so the region is there."""
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        events=[event(1, spans=[span("src/example.py", 10, 14)]),
                event(2, spans=[span("src/example.py", 15, 20)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "included"
    assert target["by_invocation"][0]["contributing_event_ids"] == ["event-1", "event-2"]


# --- unknown: every way the record cannot support an answer ------------------------------------


def test_a_context_event_that_did_not_claim_complete_capture_leaves_absence_unknown(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        events=[event(1, spans=[span("src/other.py", 1, 40)], capture_status="partial")])

    document = diagnostics.context_coverage_for_invocation(invocation)

    target = only_target(document)
    assert target["best"] == "unknown"
    assert target["by_invocation"][0]["all_capture_complete"] is False
    assert target["by_invocation"][0]["overlap"] == "none"
    # The run itself is intact, so nothing run-level is blamed: only this invocation is in doubt.
    assert document["reasons"] == []
    assert document["capture"]["context_selection_events_by_capture_status"] == {"partial": 1}


def test_a_trace_with_no_context_selection_events_leaves_every_target_unknown(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region()],
        events=[event(1, event_type="model.request", metadata={"source": "harness_emitted"})])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["reasons"] == ["no_context_selection_events"]
    assert only_target(document)["best"] == "unknown"
    assert document["capture"]["events_read"] == 1
    assert document["capture"]["context_selection_events"] == 0


def test_a_missing_trace_file_leaves_every_target_unknown(tmp_path):
    invocation = build_bundle(tmp_path, locations=[region()], write_trace=False)

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["reasons"] == ["trace_file_missing"]
    assert document["capture"]["trace_file_read"] is False
    assert document["capture"]["events_read"] is None
    assert only_target(document)["best"] == "unknown"


def test_a_run_whose_capture_record_does_not_claim_context_selection_leaves_every_target_unknown(
        tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        record=execution_record(capture={"context_selection": "unavailable"}),
        events=[event(1, spans=[span("src/example.py", 1, 40)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["reasons"] == ["capture_context_selection_not_observed"]
    target = only_target(document)
    assert target["best"] == "unknown"
    # The arithmetic is still reported: the lines were there, the record just cannot vouch for it.
    assert target["union"]["overlap"] == "full"


# Each of these makes the trace an incomplete account of what was supplied. Incomplete is not
# empty: what is in it was still delivered, so each blocks the negative claim and leaves the
# positive one standing. The parametrization pairs one bundle that covers the target with one
# that does not, and asserts both halves of that rule at once.
INCOMPLETE_RECORDS = [
    ("trace_capture_gap", dict(record=execution_record(trace={"capture_gap": True}))),
    ("trace_dropped_events", dict(record=execution_record(trace={"dropped_events": 3}))),
    ("execution_record_invalid", dict(record={**execution_record(), "status": "not-a-status"})),
]


@pytest.mark.parametrize("code,overrides", INCOMPLETE_RECORDS,
                         ids=[code for code, _ in INCOMPLETE_RECORDS])
def test_an_incomplete_record_blocks_the_negative_claim_and_leaves_a_recorded_span_standing(
        tmp_path, code, overrides):
    covered = diagnostics.context_coverage_for_invocation(build_bundle(
        tmp_path / "covered", locations=[region(start=10, end=20)],
        events=[event(1, spans=[span("src/example.py", 1, 40)])], **overrides))
    uncovered = diagnostics.context_coverage_for_invocation(build_bundle(
        tmp_path / "uncovered", locations=[region(start=10, end=20)],
        events=[event(1, spans=[span("src/example.py", 100, 140)])], **overrides))

    assert code in covered["reasons"] and code in uncovered["reasons"]
    assert covered["reasons_blocking_absence"] == [code]
    assert covered["reasons_blocking_all_classification"] == []
    # A lost event cannot un-deliver a span that was recorded.
    assert only_target(covered)["best"] == "included"
    # It can very easily be the event that would have shown the target was supplied.
    assert only_target(uncovered)["best"] == "unknown"
    assert only_target(uncovered)["union"]["overlap"] == "none"


def test_a_reported_capture_gap_is_named_in_the_capture_facts(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        record=execution_record(trace={"capture_gap": True}),
        events=[event(1, spans=[span("src/example.py", 100, 140)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["reasons"] == ["trace_capture_gap"]
    assert document["capture"]["trace_capture_gap"] is True


def test_a_trace_line_that_will_not_parse_blocks_absence_but_not_a_recorded_span(tmp_path):
    covered = json.dumps(event(1, spans=[span("src/example.py", 1, 40)])) + "\n"
    missed = json.dumps(event(1, spans=[span("src/example.py", 100, 140)])) + "\n"
    first = diagnostics.context_coverage_for_invocation(build_bundle(
        tmp_path / "covered", locations=[region(start=10, end=20)],
        trace_text=covered + "{not json\n"))
    second = diagnostics.context_coverage_for_invocation(build_bundle(
        tmp_path / "missed", locations=[region(start=10, end=20)],
        trace_text=missed + "{not json\n"))

    assert first["reasons"] == ["trace_lines_unparsed"]
    assert first["capture"]["trace_lines_unparsed"] == 1
    assert only_target(first)["best"] == "included"
    assert only_target(second)["best"] == "unknown"


def test_a_context_event_missing_a_required_field_blocks_absence_but_not_a_recorded_span(tmp_path):
    def bundle(where, supplied):
        broken = event(2, spans=[span("src/example.py", 1, 40)])
        del broken["capture_status"]
        return build_bundle(where, locations=[region(start=10, end=20)],
                            events=[event(1, spans=[supplied]), broken])

    first = diagnostics.context_coverage_for_invocation(
        bundle(tmp_path / "covered", span("src/example.py", 1, 40)))
    second = diagnostics.context_coverage_for_invocation(
        bundle(tmp_path / "missed", span("src/example.py", 100, 140)))

    assert first["reasons"] == ["trace_events_malformed"]
    assert first["capture"]["context_selection_events_malformed"] == 1
    assert only_target(first)["best"] == "included"
    assert only_target(second)["best"] == "unknown"


@pytest.mark.parametrize("code,overrides", [
    ("trace_file_missing", dict(write_trace=False)),
    ("no_context_selection_events", dict(events=[event(1, event_type="model.request",
                                                       metadata={})])),
    ("capture_context_selection_not_observed",
     dict(record=execution_record(capture={"context_selection": "unavailable"}),
          events=[event(1, spans=[span("src/example.py", 1, 40)])])),
])
def test_a_record_holding_nothing_leaves_every_target_unknown(tmp_path, code, overrides):
    """No trace, no context event, or a capture record claiming no observation: nothing to read."""
    document = diagnostics.context_coverage_for_invocation(
        build_bundle(tmp_path, locations=[region(start=10, end=20)], **overrides))

    assert document["reasons_blocking_all_classification"] == [code]
    assert only_target(document)["best"] == "unknown"
    assert only_target(document)["union"]["classification"] == "unknown"


def test_the_document_splits_its_reasons_by_what_each_one_costs(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        record=execution_record(capture={"context_selection": "partial"},
                                trace={"capture_gap": True}),
        events=[event(1, spans=[span("src/example.py", 1, 40)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["reasons"] == ["context_capture_partial_at_run_level", "trace_capture_gap"]
    assert document["reasons_blocking_all_classification"] == []
    assert document["reasons_blocking_absence"] == ["context_capture_partial_at_run_level",
                                                    "trace_capture_gap"]
    assert only_target(document)["best"] == "included"


# --- a run that admits it did not observe every context selection --------------------------------


def test_a_run_level_partial_capture_leaves_the_target_absence_unknown(tmp_path):
    """An invocation answers for its own events; a target answers for the ones that left none."""
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        record=execution_record(capture={"context_selection": "partial"}),
        events=[event(1, spans=[span("src/example.py", 100, 140)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["reasons"] == ["context_capture_partial_at_run_level"]
    target = only_target(document)
    assert target["by_invocation"][0]["classification"] == "absent"
    assert target["by_invocation"][0]["overlap"] == "none"
    assert target["best"] == "unknown"
    assert target["union"]["classification"] == "unknown"


def test_a_run_level_partial_capture_does_not_touch_a_positive_verdict(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        record=execution_record(capture={"context_selection": "partial"}),
        events=[event(1, spans=[span("src/example.py", 1, 40)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "included"
    assert target["union"]["classification"] == "included"


def test_a_redacted_run_capture_is_read_the_same_way_as_a_partial_one(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        record=execution_record(capture={"context_selection": "redacted"}),
        events=[event(1, spans=[span("src/example.py", 100, 140)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["reasons"] == ["context_capture_partial_at_run_level"]
    assert only_target(document)["best"] == "unknown"


def test_only_a_complete_run_capture_lets_a_target_be_absent(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region(start=10, end=20)],
        record=execution_record(capture={"context_selection": "complete"}),
        events=[event(1, spans=[span("src/example.py", 100, 140)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "absent"
    assert target["union"]["classification"] == "absent"


def test_a_target_the_pack_does_not_locate_is_unknown_rather_than_absent(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region()], targets=(TARGET, "T-unlocated"),
        events=[event(1, spans=[span("src/example.py", 1, 40)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    unlocated = [t for t in document["targets"] if t["target_id"] == "T-unlocated"][0]
    assert unlocated["best"] == "unknown"
    assert unlocated["reasons"] == ["target_locations_unavailable"]
    assert unlocated["locations_declared"] == 0


def test_a_label_location_with_no_line_range_caps_the_target_at_partial(tmp_path):
    """A pack may name a file with no reviewed range; nothing here invents one for it."""
    invocation = build_bundle(
        tmp_path,
        locations=[region("src/a.py", 1, 5), {"path": "src/b.py", "role": "missing_guard"}],
        events=[event(1, spans=[span("src/a.py", 1, 200)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "partial"
    assert target["locations_without_line_range"] == 1
    assert target["reasons"] == ["target_locations_without_line_range"]
    assert target["union"]["overlap"] == "full"


def test_a_label_with_only_an_unranged_location_and_no_overlap_is_unknown(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[{"path": "src/b.py", "role": "missing_guard"}],
        events=[event(1, spans=[span("src/a.py", 1, 200)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "unknown"
    assert target["union"]["classification"] == "unknown"


# --- grouping, the union, and paths ------------------------------------------------------------


def test_two_invocations_each_covering_one_location_are_scattered_in_the_union(tmp_path):
    invocation = build_bundle(
        tmp_path,
        locations=[region("src/a.py", 1, 5), region("src/b.py", 1, 5)],
        events=[event(1, call_id="call-1", spans=[span("src/a.py", 1, 5)]),
                event(2, call_id="call-2", spans=[span("src/b.py", 1, 5)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    target = only_target(document)
    assert [entry["classification"] for entry in target["by_invocation"]] == ["partial", "partial"]
    assert target["best"] == "partial"
    assert target["union"]["classification"] == "included"
    assert target["union"]["scattered"] is True
    assert document["counts"]["scattered_targets"] == 1
    assert [entry["call_id"] for entry in document["invocations"]] == ["call-1", "call-2"]


def test_a_single_invocation_that_covers_everything_is_not_reported_as_scattered(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("src/a.py", 1, 5)],
        events=[event(1, call_id="call-1", spans=[span("src/a.py", 1, 5)]),
                event(2, call_id="call-2", spans=[span("src/a.py", 1, 5)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["union"]["classification"] == "included"
    assert target["union"]["scattered"] is False


def test_an_event_without_a_call_id_is_its_own_invocation(tmp_path):
    invocation = build_bundle(
        tmp_path,
        locations=[region("src/a.py", 1, 5), region("src/b.py", 1, 5)],
        events=[event(1, call_id=None, spans=[span("src/a.py", 1, 5)]),
                event(2, call_id=None, spans=[span("src/b.py", 1, 5)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert [entry["call_id"] for entry in document["invocations"]] == [None, None]
    assert [entry["group_key"] for entry in document["invocations"]] == ["event-1", "event-2"]
    target = only_target(document)
    assert target["best"] == "partial"
    assert target["union"]["scattered"] is True


def test_two_producers_sharing_a_call_id_are_two_invocations(tmp_path):
    """A call ID is minted by whoever emits it and is unique only to that emitter.

    Pooling them would let a target whose halves went to two different producers read as fully
    included in one prompt that never existed.
    """
    invocation = build_bundle(
        tmp_path,
        locations=[region("src/a.py", 1, 5), region("src/b.py", 1, 5)],
        events=[event(1, call_id="call-1", producer_id="producer-one",
                      spans=[span("src/a.py", 1, 5)]),
                event(2, call_id="call-1", producer_id="producer-two",
                      spans=[span("src/b.py", 1, 5)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert [entry["producer_id"] for entry in document["invocations"]] == ["producer-one",
                                                                          "producer-two"]
    assert [entry["call_id"] for entry in document["invocations"]] == ["call-1", "call-1"]
    target = only_target(document)
    assert [entry["classification"] for entry in target["by_invocation"]] == ["partial", "partial"]
    assert target["best"] == "partial"
    # The union is still allowed to say the region reached the run, in pieces.
    assert target["union"]["classification"] == "included"
    assert target["union"]["scattered"] is True


def test_one_producer_reusing_a_call_id_is_still_one_invocation(tmp_path):
    invocation = build_bundle(
        tmp_path,
        locations=[region("src/a.py", 1, 5), region("src/b.py", 1, 5)],
        events=[event(1, call_id="call-1", producer_id="producer-one",
                      spans=[span("src/a.py", 1, 5)]),
                event(2, call_id="call-1", producer_id="producer-one",
                      spans=[span("src/b.py", 1, 5)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert len(target["by_invocation"]) == 1
    assert target["best"] == "included"
    assert target["union"]["scattered"] is False


@pytest.mark.parametrize("producer_id", ["", 7, None], ids=["empty", "not-a-string", "absent"])
def test_an_event_with_no_usable_producer_keeps_its_own_group(tmp_path, producer_id):
    first = event(1, call_id="call-1", spans=[span("src/a.py", 1, 5)])
    second = event(2, call_id="call-1", spans=[span("src/b.py", 1, 5)])
    for record in (first, second):
        if producer_id is None:
            del record["producer_id"]
        else:
            record["producer_id"] = producer_id
    invocation = build_bundle(
        tmp_path, locations=[region("src/a.py", 1, 5), region("src/b.py", 1, 5)],
        events=[first, second])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert [entry["group_key"] for entry in document["invocations"]] == ["event-1", "event-2"]
    assert [entry["producer_id"] for entry in document["invocations"]] == [None, None]
    assert only_target(document)["best"] == "partial"


@pytest.mark.parametrize("call_id", ["", 7, None], ids=["empty", "not-a-string", "absent"])
def test_a_call_id_the_wire_contract_would_reject_is_treated_as_none_at_all(tmp_path, call_id):
    """An empty or non-string call_id correlates nothing, so it must not correlate two events."""
    first = event(1, spans=[span("src/a.py", 1, 5)], call_id=None)
    second = event(2, spans=[span("src/b.py", 1, 5)], call_id=None)
    if call_id is not None:
        first["call_id"] = second["call_id"] = call_id
    invocation = build_bundle(tmp_path, locations=[region("src/a.py", 1, 5)],
                              events=[first, second])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert [entry["call_id"] for entry in document["invocations"]] == [None, None]
    assert [entry["group_key"] for entry in document["invocations"]] == ["event-1", "event-2"]


def test_paths_are_compared_after_normalizing_separators_and_a_leading_dot(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("src/pkg/example.py", 10, 20)],
        events=[event(1, spans=[span(".\\src\\pkg\\example.py", 1, 40)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "included"


def test_a_leading_dot_slash_on_the_label_side_normalizes_too(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("./src//pkg/example.py", 10, 20)],
        events=[event(1, spans=[span("src/pkg/example.py", 1, 40)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "included"
    assert target["locations"][0]["path"] == "src/pkg/example.py"


def test_a_span_that_does_not_say_where_it_landed_is_counted_and_covers_nothing(tmp_path):
    """Corrected: two of these name the target's own file, so absence is no longer provable."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[{"path": "src/example.py", "chars": 100},
                                {"path": "src/example.py", "start_line": 10},
                                {"start_line": 10, "end_line": 20},
                                span("src/example.py", 30, 40)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["capture"]["unusable_spans"] == 3
    assert document["capture"]["unusable_spans_without_path"] == 1
    assert document["capture"]["spans"] == 1
    assert only_target(document)["union"]["covered_lines"] == 0
    assert only_target(document)["best"] == "unknown"


def test_unusable_spans_that_name_no_path_this_target_uses_leave_absence_provable(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[{"path": "src/elsewhere.py", "chars": 100},
                                span("src/example.py", 30, 40)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["capture"]["unusable_spans"] == 1
    assert only_target(document)["best"] == "absent"


def test_a_span_whose_lines_run_backwards_is_unusable(tmp_path):
    """Corrected: it names the target's own file, so it blocks the negative claim."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[span("src/example.py", 20, 10)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["capture"]["unusable_spans"] == 1
    target = only_target(document)
    assert target["best"] == "unknown"
    assert target["reasons"] == ["unusable_span_on_target_path"]
    assert target["by_invocation"][0]["unusable_target_paths"] == ["src/example.py"]


def test_a_span_naming_the_target_file_with_coordinates_that_cannot_be_read_blocks_absence(
        tmp_path):
    """The false negative this closes: a defect in the emitter must not read as a clean miss."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[{"path": "src/example.py", "start_line": "10", "end_line": "20"},
                                span("src/other.py", 1, 400)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    target = only_target(document)
    assert target["best"] == "unknown"
    assert target["by_invocation"][0]["reasons"] == ["unusable_span_on_target_path"]


def test_a_context_event_that_reported_no_spans_at_all_blocks_absence(tmp_path):
    """What a record does not say was supplied cannot be shown not to have been supplied."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, metadata={"source": "harness_self_report", "stage": "llm-static.file"}),
                event(2, spans=[span("src/other.py", 1, 400)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    target = only_target(document)
    assert target["best"] == "unknown"
    assert "context_event_without_spans" in target["reasons"]
    assert target["by_invocation"][0]["events_without_spans"] == 1


def test_an_unusable_span_with_no_path_blocks_absence_for_every_target_of_its_invocation(tmp_path):
    """Nothing about it can be attributed, so it counts against the invocation as a whole."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[{"start_line": 1, "end_line": 50},
                                span("src/other.py", 1, 400)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    target = only_target(document)
    assert target["best"] == "unknown"
    assert target["by_invocation"][0]["reasons"] == ["unusable_span_without_path"]


def test_a_hole_in_one_invocation_stops_a_cleaner_one_carrying_the_target_to_absent(tmp_path):
    """A target's absence answers for every invocation, not for the tidiest one."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, call_id="call-a", spans=[span("src/example.py", 20, 10)]),
                event(2, call_id="call-b", spans=[span("src/other.py", 1, 400)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert [entry["classification"] for entry in target["by_invocation"]] == ["unknown", "absent"]
    assert target["best"] == "unknown"
    assert target["union"]["classification"] == "unknown"


def test_a_missing_span_list_does_not_weaken_a_span_that_was_recorded(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, metadata={"source": "harness_self_report"}),
                event(2, spans=[span("src/example.py", 1, 40)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "included"


def adrift(path: str, start: int, end: int, **overrides) -> dict:
    """A span whose lines count the supplied text rather than the file."""
    return span(path, start, end, location_known=False, role="fragment", **overrides)


def test_a_span_whose_lines_are_not_file_lines_covers_nothing(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[adrift("src/example.py", 1, 40)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    target = only_target(document)
    assert target["union"]["covered_lines"] == 0
    assert target["union"]["overlap"] == "none"
    assert document["capture"]["unlocated_spans"] == 1
    assert document["capture"]["spans"] == 0


def test_an_unlocated_span_on_the_target_path_blocks_absence_for_that_invocation(tmp_path):
    """Text from this very file reached the prompt at lines nobody can place."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[adrift("src/example.py", 1, 40)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    target = only_target(document)
    assert target["best"] == "unknown"
    assert target["reasons"] == ["unlocated_span_on_target_path"]
    assert target["by_invocation"][0]["reasons"] == ["unlocated_span_on_target_path"]
    assert target["by_invocation"][0]["unlocated_target_paths"] == ["src/example.py"]
    assert target["by_invocation"][0]["unlocated_spans"] == 1
    # It is a doubt about this run, not about the record as a whole.
    assert document["reasons"] == []


def test_an_unlocated_span_on_another_path_leaves_absence_provable(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[adrift("src/elsewhere.py", 1, 40)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "absent"
    assert target["reasons"] == []


def test_an_unlocated_span_does_not_weaken_a_located_one_beside_it(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[span("src/example.py", 1, 40),
                                adrift("src/example.py", 1, 9)])])

    target = only_target(diagnostics.context_coverage_for_invocation(invocation))

    assert target["best"] == "included"
    assert target["union"]["covered_lines"] == 11


@pytest.mark.parametrize("flag", [False, None, "no", 0])
def test_an_explicit_location_known_other_than_true_is_not_a_file_position(tmp_path, flag):
    """null is a harness saying it does not know, which is never a harness saying it does."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[span("src/example.py", 1, 40, location_known=flag)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["capture"]["unlocated_spans"] == 1
    assert only_target(document)["best"] == "unknown"


@pytest.mark.parametrize("flag", [True, "absent"])
def test_a_span_without_the_flag_or_with_it_true_is_an_ordinary_file_position(tmp_path, flag):
    extra = {} if flag == "absent" else {"location_known": flag}
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[span("src/example.py", 1, 40, **extra)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["capture"]["unlocated_spans"] == 0
    assert only_target(document)["best"] == "included"


def test_an_unlocated_span_needs_no_line_range_to_fix_a_path(tmp_path):
    """Its lines mean nothing anyway, so their absence is not what makes a span unusable."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[{"path": "src/example.py", "location_known": False,
                                 "role": "fragment"}])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["capture"]["unlocated_spans"] == 1
    assert document["capture"]["unusable_spans"] == 0
    assert only_target(document)["best"] == "unknown"


def test_an_unlocated_span_with_no_usable_path_is_merely_unusable(tmp_path):
    """It is still a hole: nothing about it can be attributed, so absence is not provable."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[{"location_known": False, "role": "fragment"},
                                span("src/example.py", 100, 140)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["capture"]["unusable_spans"] == 1
    assert document["capture"]["unusable_spans_without_path"] == 1
    assert document["capture"]["unlocated_spans"] == 0
    assert only_target(document)["best"] == "unknown"


def test_a_truncated_span_still_covers_the_lines_it_names(tmp_path):
    """Contract 2 says a span's end line is that of the text supplied, so it is not discounted."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, spans=[span("src/example.py", 1, 40, truncated=True,
                                     original_chars=99999)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert only_target(document)["best"] == "included"
    assert document["capture"]["truncated_spans"] == 1
    assert document["capture"]["truncation_unknown_spans"] == 0


@pytest.mark.parametrize("value,extra", [(None, {"truncated": None}), ("absent", {})])
def test_an_unknown_truncated_flag_is_never_counted_as_untruncated(tmp_path, value, extra):
    supplied = span("src/example.py", 1, 40)
    supplied.pop("truncated")
    supplied.update(extra)
    invocation = build_bundle(tmp_path, locations=[region("src/example.py", 10, 20)],
                              events=[event(1, spans=[supplied])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["capture"]["truncated_spans"] == 0
    assert document["capture"]["truncation_unknown_spans"] == 1


def test_a_context_event_with_no_span_list_is_counted_separately(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("src/example.py", 10, 20)],
        events=[event(1, metadata={"source": "harness_self_report", "stage": "llm-static.file"})])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["capture"]["events_without_span_list"] == 1
    assert document["capture"]["invocations_with_context"] == 1


# --- the shape of the document -----------------------------------------------------------------


def test_the_document_is_byte_identical_when_the_same_bundle_is_read_twice(tmp_path):
    invocation = build_bundle(
        tmp_path,
        locations=[region("src/a.py", 1, 5), region("src/b.py", 7, 9)],
        events=[event(3, call_id="call-b", spans=[span("src/b.py", 7, 8)]),
                event(1, call_id="call-a", spans=[span("src/a.py", 1, 5)]),
                event(2, call_id="call-a", spans=[span("src/b.py", 1, 4)])])

    first = diagnostics.context_coverage_for_invocation(invocation)
    second = diagnostics.context_coverage_for_invocation(invocation)

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert [entry["group_key"] for entry in first["invocations"]] == ["call-a", "call-b"]


def test_the_document_never_lists_a_path_the_harness_supplied(tmp_path):
    """Counts of spans and paths, never the paths. Only the evaluator's own labels appear."""
    invocation = build_bundle(
        tmp_path, locations=[region("src/labelled.py", 1, 5)],
        events=[event(1, spans=[span("src/secret-internal.py", 1, 900),
                                span("src/labelled.py", 1, 5)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert "secret-internal" not in json.dumps(document)
    assert document["invocations"][0]["paths"] == 2
    assert document["invocations"][0]["spans"] == 2


def test_the_document_says_what_inclusion_does_not_establish(tmp_path):
    invocation = build_bundle(tmp_path, locations=[region()],
                              events=[event(1, spans=[span("src/example.py", 1, 40)])])

    notes = " ".join(diagnostics.context_coverage_for_invocation(invocation)["notes"])

    assert "does not say the model attended to them" in notes
    assert "Partial capture weakens the negative claim, never the positive one" in notes
    assert "a lost event cannot un-deliver it" in notes
    assert "location_known false" in notes
    assert "never as untruncated" in notes
    assert "finding.filtered" in notes


def test_the_document_reports_the_run_capture_facts_it_relied_on(tmp_path):
    invocation = build_bundle(tmp_path, locations=[region()],
                              events=[event(1, spans=[span("src/example.py", 1, 40)])])

    capture = diagnostics.context_coverage_for_invocation(invocation)["capture"]

    assert capture["context_selection"] == "complete"
    assert capture["trace_mode"] == "metadata"
    assert capture["trace_capture_gap"] is False
    assert capture["trace_dropped_events"] == 0
    assert capture["trace_file_read"] is True
    assert capture["context_selection_events"] == 1


def test_counts_roll_up_the_per_target_classifications(tmp_path):
    invocation = build_bundle(
        tmp_path, locations=[region("src/a.py", 1, 5)], targets=(TARGET, "T-unlocated"),
        events=[event(1, spans=[span("src/a.py", 1, 5)])])

    counts = diagnostics.context_coverage_for_invocation(invocation)["counts"]

    assert counts["targets"] == 2
    assert counts["best"] == {"included": 1, "partial": 0, "absent": 0, "unknown": 1}
    assert counts["locations_declared"] == 1


# --- the pure function and the pack fallback ---------------------------------------------------


def test_the_pure_function_reads_no_file_at_all():
    document = diagnostics.context_coverage(
        plan_targets=[{"target_id": TARGET,
                       "accepted_locations": [region("src/a.py", 1, 5)]}],
        events=[event(1, spans=[span("src/a.py", 1, 5)])],
        execution_record=execution_record())

    assert only_target(document)["best"] == "included"
    assert document["sources"] == {}


def test_the_pure_function_told_of_no_trace_says_so_rather_than_reporting_an_empty_one():
    missing = diagnostics.context_coverage(
        plan_targets=[{"target_id": TARGET, "accepted_locations": [region()]}],
        events=None, execution_record=execution_record())
    empty = diagnostics.context_coverage(
        plan_targets=[{"target_id": TARGET, "accepted_locations": [region()]}],
        events=[], execution_record=execution_record())

    assert missing["reasons"] == ["trace_file_missing"]
    assert empty["reasons"] == ["no_context_selection_events"]


def test_without_an_execution_record_the_run_capture_facts_are_unavailable():
    covered = diagnostics.context_coverage(
        plan_targets=[{"target_id": TARGET, "accepted_locations": [region("src/a.py", 1, 5)]}],
        events=[event(1, spans=[span("src/a.py", 1, 5)])], execution_record=None)
    missed = diagnostics.context_coverage(
        plan_targets=[{"target_id": TARGET, "accepted_locations": [region("src/a.py", 1, 5)]}],
        events=[event(1, spans=[span("src/a.py", 90, 95)])], execution_record=None)

    assert covered["reasons"] == ["run_capture_facts_unavailable"]
    assert covered["reasons_blocking_absence"] == ["run_capture_facts_unavailable"]
    assert only_target(covered)["best"] == "included"
    assert only_target(missed)["best"] == "unknown"
    assert covered["run_id"] is None


def test_the_pack_alone_answers_for_the_snapshot_this_invocation_scanned(tmp_path):
    invocation = build_bundle(tmp_path, locations=[region("src/a.py", 1, 5)], write_plan=False,
                              events=[event(1, spans=[span("src/a.py", 1, 5)])])
    other = tmp_path / "other-pack.json"
    document = pack([region("src/a.py", 1, 5)])
    document["cases"].append({"case_id": "elsewhere",
                              "target": {"target_id": "T-elsewhere", "snapshot_id": "other-snap",
                                         "accepted_locations": [region("src/a.py", 1, 5)]}})
    other.write_text(json.dumps(document), encoding="utf-8")

    result = diagnostics.context_coverage_for_invocation(invocation, pack_path=other)

    assert [target["target_id"] for target in result["targets"]] == [TARGET]
    assert result["sources"]["targets_from"] == "pack"
    assert result["sources"]["plan"] is None


def test_a_bundle_with_neither_plan_nor_pack_is_refused_with_a_message_naming_both(tmp_path):
    invocation = build_bundle(tmp_path, write_plan=False, write_pack=False,
                              events=[event(1, spans=[span("src/a.py", 1, 5)])])

    with pytest.raises(diagnostics.DiagnosticsError) as raised:
        diagnostics.context_coverage_for_invocation(invocation)

    assert "--pack" in str(raised.value)


def test_an_execution_record_that_breaks_its_contract_is_read_anyway_and_reported(tmp_path):
    """Two fields are read out of it; a defect in a third should not withhold the answer."""
    broken = execution_record()
    broken["status"] = "not-a-status"
    invocation = build_bundle(tmp_path, locations=[region(start=10, end=20)], record=broken,
                              events=[event(1, spans=[span("src/example.py", 1, 40)])])

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert "execution_record_invalid" in document["reasons"]
    assert only_target(document)["best"] == "included"
    assert only_target(document)["union"]["overlap"] == "full"


def test_a_trace_reached_through_a_symbolic_link_is_not_followed(tmp_path):
    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps(event(1, spans=[span("src/example.py", 1, 40)])) + "\n",
                       encoding="utf-8")
    invocation = build_bundle(tmp_path, locations=[region(start=10, end=20)], write_trace=False)
    (invocation / "trace").mkdir()
    (invocation / "trace" / "events.jsonl").symlink_to(outside)

    document = diagnostics.context_coverage_for_invocation(invocation)

    assert document["reasons"] == ["trace_file_missing"]


# --- the command line ---------------------------------------------------------------------------


def test_the_command_prints_the_document_with_sorted_keys_and_two_space_indent(tmp_path, capsys):
    invocation = build_bundle(tmp_path, locations=[region(start=10, end=20)],
                              events=[event(1, spans=[span("src/example.py", 1, 40)])])

    assert main(["diagnose", "context-coverage", str(invocation)]) == 0

    out = capsys.readouterr().out
    document = json.loads(out)
    assert out == json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    assert document["diagnostic"] == "context_coverage"
    assert only_target(document)["best"] == "included"


def test_the_command_writes_the_document_to_a_new_file(tmp_path, capsys):
    invocation = build_bundle(tmp_path, locations=[region(start=10, end=20)],
                              events=[event(1, spans=[span("src/example.py", 1, 40)])])
    out = tmp_path / "coverage.json"

    assert main(["diagnose", "context-coverage", str(invocation), "--out", str(out)]) == 0

    assert capsys.readouterr().out == ""
    assert json.loads(out.read_text())["targets"][0]["best"] == "included"


def test_the_command_refuses_to_overwrite_an_existing_output_file(tmp_path, capsys):
    invocation = build_bundle(tmp_path, locations=[region()], events=[event(1)])
    out = tmp_path / "coverage.json"
    out.write_text("keep me", encoding="utf-8")

    assert main(["diagnose", "context-coverage", str(invocation), "--out", str(out)]) == 2

    assert out.read_text() == "keep me"


def test_the_command_reports_a_directory_that_is_not_an_invocation_bundle(tmp_path, capsys):
    assert main(["diagnose", "context-coverage", str(tmp_path / "nowhere")]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "is not an invocation directory" in captured.err


def test_the_command_reports_a_directory_holding_no_execution_record(tmp_path, capsys):
    (tmp_path / "empty").mkdir()

    assert main(["diagnose", "context-coverage", str(tmp_path / "empty")]) == 1

    assert "execution.json" in capsys.readouterr().err


def test_the_command_takes_a_pack_path_for_a_bundle_with_none_beside_it(tmp_path, capsys):
    invocation = build_bundle(tmp_path, write_pack=False, locations=[region("src/a.py", 1, 5)],
                              events=[event(1, spans=[span("src/a.py", 1, 5)])])
    elsewhere = tmp_path / "pack.json"
    elsewhere.write_text(json.dumps(pack([region("src/a.py", 1, 5)])), encoding="utf-8")

    assert main(["diagnose", "context-coverage", str(invocation),
                 "--pack", str(elsewhere)]) == 0

    assert only_target(json.loads(capsys.readouterr().out))["best"] == "included"


def test_the_command_reports_a_pack_path_that_is_not_a_file(tmp_path, capsys):
    invocation = build_bundle(tmp_path, write_pack=False, locations=[region()],
                              events=[event(1)])

    assert main(["diagnose", "context-coverage", str(invocation),
                 "--pack", str(tmp_path / "no-pack.json")]) == 1

    assert "is not a case pack file" in capsys.readouterr().err


def test_the_command_leaves_the_bundle_untouched(tmp_path, capsys):
    invocation = build_bundle(tmp_path, locations=[region()],
                              events=[event(1, spans=[span("src/example.py", 1, 40)])])
    before = sorted(path.relative_to(invocation).as_posix()
                    for path in invocation.rglob("*") if path.is_file())

    assert main(["diagnose", "context-coverage", str(invocation)]) == 0

    after = sorted(path.relative_to(invocation).as_posix()
                   for path in invocation.rglob("*") if path.is_file())
    assert before == after


# --- the document and the document about the document --------------------------------------------


def every_reason_the_module_can_emit(tmp_path: Path) -> set[str]:
    """Drive each reason out of a bundle built to produce it, so the set is observed, not listed."""
    produced: set[str] = set()
    cases = [
        dict(write_trace=False),
        dict(events=[event(1, event_type="model.request", metadata={})]),
        dict(record=execution_record(capture={"context_selection": "unavailable"}),
             events=[event(1)]),
        dict(record=execution_record(trace={"capture_gap": True}), events=[event(1)]),
        dict(record=execution_record(trace={"dropped_events": 1}), events=[event(1)]),
        dict(trace_text="{not json\n"),
        dict(events=[{**event(1), "capture_status": None}]),
        dict(record={**execution_record(), "status": "not-a-status"}, events=[event(1)]),
        dict(targets=("T-unlocated",), events=[event(1)]),
        dict(locations=[{"path": "src/b.py", "role": "sink"}], events=[event(1)]),
        dict(record=execution_record(capture={"context_selection": "partial"}),
             events=[event(1)]),
        dict(events=[event(1, spans=[adrift("src/example.py", 1, 40)])]),
        dict(events=[event(1, metadata={"source": "harness_self_report"})]),
        dict(events=[event(1, spans=[{"start_line": 1, "end_line": 2}])]),
        dict(events=[event(1, spans=[{"path": "src/example.py", "start_line": 1}])]),
    ]
    for index, case in enumerate(cases):
        case.setdefault("locations", [region()])
        document = diagnostics.context_coverage_for_invocation(
            build_bundle(tmp_path / f"case-{index}", **case))
        produced.update(document["reasons"])
        for target in document["targets"]:
            produced.update(target["reasons"])
    produced.add("run_capture_facts_unavailable")  # only reachable through the pure function
    return produced


def test_every_reason_code_the_module_can_emit_is_in_the_published_tuple(tmp_path):
    assert every_reason_the_module_can_emit(tmp_path) <= set(diagnostics.REASON_CODES)


def test_the_published_reason_codes_are_all_reachable(tmp_path):
    """A code nothing can produce is a promise the document never keeps."""
    assert set(diagnostics.REASON_CODES) == every_reason_the_module_can_emit(tmp_path)


def test_the_diagnostics_document_explains_every_reason_code_and_classification():
    """docs/DIAGNOSTICS.md is the reader's table; it must not fall behind the module."""
    text = (ROOT / "docs" / "DIAGNOSTICS.md").read_text(encoding="utf-8")

    for code in diagnostics.REASON_CODES:
        assert f"`{code}`" in text, f"docs/DIAGNOSTICS.md does not explain {code}"
    for name in diagnostics.CLASSIFICATIONS:
        assert f"`{name}`" in text


def test_the_reason_table_names_an_effect_for_every_published_code():
    """A code with no effect would weaken nothing, and the split is the whole judgement here."""
    assert set(diagnostics.REASON_EFFECTS) == set(diagnostics.REASON_CODES)
    assert set(diagnostics.REASON_EFFECTS.values()) == {"blanket", "absence", "target_absence",
                                                        "invocation", "target"}


def test_a_reason_the_table_does_not_name_blocks_absence_and_nothing_else():
    """The conservative default: it cannot discard a recorded span, nor prove an absence."""
    covered = diagnostics.context_coverage(
        plan_targets=[{"target_id": TARGET, "accepted_locations": [region("src/a.py", 1, 5)]}],
        events=[event(1, spans=[span("src/a.py", 1, 5)])],
        execution_record=execution_record(), extra_reasons=["something_new"])
    missed = diagnostics.context_coverage(
        plan_targets=[{"target_id": TARGET, "accepted_locations": [region("src/a.py", 1, 5)]}],
        events=[event(1, spans=[span("src/a.py", 90, 95)])],
        execution_record=execution_record(), extra_reasons=["something_new"])

    assert only_target(covered)["best"] == "included"
    assert only_target(missed)["best"] == "unknown"
    assert missed["reasons_blocking_absence"] == ["something_new"]


# --- a real bundle, when the working copy happens to hold one ------------------------------------


def _real_invocations() -> list[Path]:
    return sorted(path.parent for path in ROOT.glob("results/*/invocations/*/execution.json"))


@pytest.mark.skipif(not _real_invocations(), reason="no run bundle in this working copy")
def test_a_real_run_bundle_reads_without_raising():
    """Traces written before spans were emitted classify unknown, which is the honest answer."""
    for invocation in _real_invocations():
        document = diagnostics.context_coverage_for_invocation(invocation)
        assert document["diagnostic"] == "context_coverage"
        assert document["targets"], f"{invocation.name} planned no target"
        for target in document["targets"]:
            assert target["best"] in diagnostics.CLASSIFICATIONS
            if not document["capture"]["context_selection_events"]:
                # Nothing was observed, so nothing may be concluded, and the document must say
                # which hole in the record it is declining to read as a result.
                assert target["best"] == "unknown"
                assert document["reasons"]
