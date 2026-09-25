"""Behavioral pins for the native-CLI collectors, one named test per promise they make.

Most fixtures under ``schema/v2/fixtures/collectors/`` were produced by a real CLI run
against a two-file synthetic repository and then scrubbed by
``scripts/sanitize_native_trace.py``. Three are hand-built in the same record shape, for the
branches a short successful run cannot reach: ``claude-code-edge-cases.jsonl`` for damaged
and unpaired records, and ``codex-exec-edge-cases.jsonl`` and
``claude-code-stream-json-error.jsonl`` for failure messages that quote an operator's home
path and a source excerpt. That provenance is the point: these tests assert what the CLIs
actually write, so a record shape that changes under us fails here rather than silently
producing a thinner trace.

Nothing here runs a CLI, reaches a network, or reads a home directory. Every clock and ID
factory is injected, so the events are byte-deterministic and a test can compare two imports
directly. A passing suite says the importers translate these records faithfully and lose
nothing silently. It says nothing about whether the events describe everything the CLI did:
that is what ``ImportSummary.capture`` and ``docs/COLLECTORS.md`` are for.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from scaneval.collectors import ImportSummary, workspace_path, workspace_roots
from scaneval.collectors import claude_code, codex
from scaneval.observer import Observer


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema/v2/trace-event.schema.json").read_text())
FIXTURES = ROOT / "schema/v2/fixtures/collectors"
TRANSCRIPT = FIXTURES / "claude-code-transcript.jsonl"
SUBAGENT = FIXTURES / "claude-code-subagent.jsonl"
STREAM = FIXTURES / "claude-code-stream-json.jsonl"
EDGE = FIXTURES / "claude-code-edge-cases.jsonl"
CODEX = FIXTURES / "codex-exec.jsonl"
RESULT = FIXTURES / "claude-code-result.json"
# Hand-built, and built for one purpose: their failure text quotes an operator's absolute
# home path and an excerpt of the source that was being read, which is exactly what a CLI
# writes into an error message and exactly what must not reach metadata.
CODEX_ERRORS = FIXTURES / "codex-exec-edge-cases.jsonl"
STREAM_ERROR = FIXTURES / "claude-code-stream-json-error.jsonl"
# The line of the fixtures' failure text that is a source excerpt, and the credential path
# it names. Both are asserted absent from metadata and present in content.
SOURCE_EXCERPT = "return eval(raw)"
HOME_PATH = "/Users/someone/.aws/credentials"

# The root the fixtures were scrubbed to. It is spelled absolutely so a fixture stays a file
# the importers parse exactly as they parse a real one.
WORKSPACE = Path("/workspace")
EPOCH = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)

# The Contract 3 capture keys, which every importer must answer in full.
CAPTURE_KEYS = {
    "model_requests", "model_responses", "tool_calls", "context_selection",
    "finding_submitted", "finding_candidate", "finding_validation", "finding_filtered",
}
CAPTURE_VALUES = {"complete", "partial", "unavailable", "not_applicable"}


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


def recording(mode: str = "metadata") -> tuple[list[dict], Observer]:
    seen: list[dict] = []
    observer = Observer(
        mode=mode,
        sink=seen.append,
        run_id="run-fixture",
        producer_id="producer-fixture",
        clock=clock(),
        id_factory=ids(),
    )
    return seen, observer


def import_file(path: Path, *, mode: str = "metadata", **kwargs) -> tuple[list[dict], ImportSummary]:
    seen, observer = recording(mode)
    summary = claude_code.import_transcript(
        observer, path, workspace_root=WORKSPACE, call_id="call-1", **kwargs
    )
    return seen, summary


def import_stream(path: Path, *, mode: str = "metadata") -> tuple[list[dict], ImportSummary]:
    seen, observer = recording(mode)
    summary = claude_code.import_stream_json(
        observer, path.read_text().splitlines(), workspace_root=WORKSPACE, call_id="call-1"
    )
    return seen, summary


def import_codex(path: Path, *, mode: str = "metadata") -> tuple[list[dict], ImportSummary]:
    seen, observer = recording(mode)
    summary = codex.import_exec_jsonl(
        observer, path.read_text().splitlines(), workspace_root=WORKSPACE, call_id="call-1"
    )
    return seen, summary


def of_type(events: list[dict], kind: str) -> list[dict]:
    return [event for event in events if event["type"] == kind]


def as_jsonl(events: list[dict]) -> str:
    return "".join(json.dumps(event, sort_keys=True) + "\n" for event in events)


# --- finding the files ------------------------------------------------------------------


def test_find_transcripts_returns_the_main_file_first_then_its_subagent_files(tmp_path: Path):
    """The main transcript is the session; the subagent files are the sidechains under it.

    Order matters to a caller that imports the main file with one call ID and the subagent
    files with another, so it is asserted rather than left to glob ordering.
    """
    projects = tmp_path / "projects"
    slug = projects / "-some-scanned-repo"
    (slug / "session-1" / "subagents").mkdir(parents=True)
    main = slug / "session-1.jsonl"
    main.write_text("{}\n")
    first = slug / "session-1" / "subagents" / "agent-aaa.jsonl"
    second = slug / "session-1" / "subagents" / "agent-bbb.jsonl"
    first.write_text("{}\n")
    second.write_text("{}\n")
    (slug / "session-1" / "subagents" / "agent-aaa.meta.json").write_text("{}")

    found = claude_code.find_transcripts("session-1", projects_dir=projects)

    assert found == [main, first, second]


def test_find_transcripts_returns_nothing_rather_than_raising_when_nothing_matches(tmp_path: Path):
    """A harness whose CLI kept no transcript has a capture gap, not a failed scan."""
    assert claude_code.find_transcripts("session-1", projects_dir=tmp_path / "absent") == []
    (tmp_path / "projects").mkdir()
    assert claude_code.find_transcripts("session-1", projects_dir=tmp_path / "projects") == []


def test_find_transcripts_refuses_a_session_id_that_would_escape_the_projects_directory(
    tmp_path: Path,
):
    """A session ID reaches this from a CLI's stdout, so it is input and not a constant."""
    projects = tmp_path / "projects"
    projects.mkdir()
    assert claude_code.find_transcripts("../../etc", projects_dir=projects) == []
    assert claude_code.find_transcripts("", projects_dir=projects) == []


# --- turns ------------------------------------------------------------------------------


def test_an_assistant_message_split_across_block_records_is_one_turn_with_one_usage():
    """The fact that drives the whole reader: a record is a content block, not a response.

    The real transcript writes one API response as several records sharing ``message.id``,
    ``message.usage`` and ``requestId``, differing only in ``apiBlockIndex``. A reader that
    emitted per record would report twice the turns and twice the tokens, and a token count
    that double-counts is worse than no token count at all.
    """
    records = [json.loads(line) for line in TRANSCRIPT.read_text().splitlines() if line.strip()]
    assistant_records = [r for r in records if r.get("type") == "assistant"]
    message_ids = {r["message"]["id"] for r in assistant_records}
    assert len(assistant_records) > len(message_ids), "fixture no longer splits a message"

    events, summary = import_file(TRANSCRIPT)

    assert summary.model_turns == len(message_ids)
    assert len(of_type(events, "model.request")) == len(message_ids)
    assert len(of_type(events, "model.response")) == len(message_ids)
    usages = [e["metadata"]["usage"] for e in of_type(events, "model.response")]
    assert all(u is not None for u in usages)
    assert usages[0]["input_tokens"] == assistant_records[0]["message"]["usage"]["input_tokens"]


def test_every_turn_says_its_retries_were_not_observable():
    """A transcript records the turns that happened, never the attempts behind them.

    This is the honesty rule with the sharpest consequence: without it a reader would take
    one request event per turn as evidence that the CLI tried once.
    """
    events, _ = import_file(TRANSCRIPT)
    for request in of_type(events, "model.request"):
        assert request["metadata"]["retries_observable"] is False
        assert request["metadata"]["attempt"] == 1
        assert request["capture_status"] == "partial"


def test_a_turn_reports_the_model_that_served_it_and_never_one_that_was_requested():
    """``model_served`` is what the record says; ``model_requested`` is what it cannot say."""
    events, _ = import_file(TRANSCRIPT)
    responses = of_type(events, "model.response")
    assert all(r["metadata"]["model_served"] for r in responses)
    assert all(r["metadata"]["model_served"].startswith("claude-") for r in responses)
    assert all(r["metadata"]["model_requested"] is None for r in of_type(events, "model.request"))


def test_attempt_ids_number_the_turns_under_the_callers_call_id():
    """Contract 4's join key: one call ID for the invocation, one attempt ID per turn."""
    events, _ = import_file(TRANSCRIPT)
    pairs = [(e["call_id"], e["attempt_id"]) for e in of_type(events, "model.request")]
    assert pairs == [("call-1", "call-1/turn-1"), ("call-1", "call-1/turn-2")]


def test_a_response_points_at_the_request_of_its_own_turn():
    events, _ = import_file(TRANSCRIPT)
    requests = {e["attempt_id"]: e["event_id"] for e in of_type(events, "model.request")}
    for response in of_type(events, "model.response"):
        assert response["parent_event_id"] == requests[response["attempt_id"]]


# --- tools and spans --------------------------------------------------------------------


def test_tool_starts_and_tool_ends_pair_by_the_native_tool_use_id():
    """``call_id`` on a tool event is the CLI's own ID, so the pair joins without a guess."""
    events, summary = import_file(TRANSCRIPT)
    starts = of_type(events, "tool.start")
    ends = of_type(events, "tool.end")
    assert summary.tool_calls == len(starts) == 1
    assert summary.tool_results == len(ends) == 1
    assert [e["call_id"] for e in starts] == [e["call_id"] for e in ends]
    assert starts[0]["call_id"].startswith("toolu_")
    assert starts[0]["metadata"]["tool_name"] == "Read"


def test_a_tool_start_points_at_the_request_event_of_the_turn_that_issued_it():
    events, _ = import_file(TRANSCRIPT)
    request_ids = {e["event_id"] for e in of_type(events, "model.request")}
    for start in of_type(events, "tool.start"):
        assert start["parent_event_id"] in request_ids


def test_a_read_result_becomes_a_span_whose_path_is_relative_to_the_workspace():
    """The span is the one claim a collector makes that Contract 5 later joins against.

    It carries the hash of exactly the text the tool delivered, so a coverage claim rests on
    the bytes the model saw rather than on the file as it stands now.
    """
    import hashlib

    events, summary = import_file(TRANSCRIPT)
    assert summary.spans == 1
    end = of_type(events, "tool.end")[0]
    span = end["metadata"]["spans"][0]
    assert span["path"] == "app.py"
    assert span["start_line"] == 1
    assert span["end_line"] == 18
    assert span["truncated"] is False

    delivered = None
    for line in TRANSCRIPT.read_text().splitlines():
        record = json.loads(line)
        native = record.get("toolUseResult")
        if isinstance(native, dict) and isinstance(native.get("file"), dict):
            delivered = native["file"]["content"]
    assert span["chars"] == len(delivered)
    assert span["sha256"] == hashlib.sha256(delivered.encode()).hexdigest()


def test_a_read_result_also_emits_one_context_selection_under_the_callers_call_id():
    """A file's lines reaching the conversation is a context event, and only a partial one.

    ``partial`` is the whole claim: the collector saw text arrive, not a harness choosing to
    supply it, and certainly not a model attending to it.
    """
    events, _ = import_file(TRANSCRIPT)
    selections = of_type(events, "context.selection")
    assert len(selections) == 1
    selection = selections[0]
    assert selection["capture_status"] == "partial"
    assert selection["call_id"] == "call-1"
    assert selection["metadata"]["stage"] == "tool_result"
    assert selection["metadata"]["span_count"] == 1
    assert selection["metadata"]["source"] == claude_code.SOURCE_TRANSCRIPT
    assert selection["parent_event_id"] == of_type(events, "tool.end")[0]["event_id"]


def test_a_truncated_read_says_it_was_truncated_and_carries_the_lines_it_delivered():
    events, _ = import_file(EDGE)
    spans = [
        span
        for end in of_type(events, "tool.end")
        for span in (end["metadata"]["spans"] or [])
    ]
    truncated = [span for span in spans if span["truncated"]]
    assert len(truncated) == 1
    assert truncated[0]["start_line"] == 5
    assert truncated[0]["end_line"] == 24


def test_a_path_outside_the_workspace_becomes_external_and_is_counted():
    """A transcript quotes paths from the machine that ran it, so this is the guard rail."""
    events, summary = import_file(EDGE)
    external = [
        span
        for end in of_type(events, "tool.end")
        for span in (end["metadata"]["spans"] or [])
        if span["path"].startswith("external:")
    ]
    assert external and external[0]["path"] == "external:app.conf"
    assert any(note.startswith("paths outside the workspace root:") for note in summary.notes)


def test_a_failed_tool_says_so_and_a_shell_command_is_never_attributed_as_a_span():
    """A ``cat`` that prints a file is not a read this collector can attribute.

    Nothing in a Bash result says which file the output came from or which of its lines
    those were, so guessing would put a path into a coverage claim on no evidence.
    """
    events, _ = import_file(EDGE)
    bash = [e for e in of_type(events, "tool.end")
            if e["call_id"] == "toolu_fixture000000000002"]
    assert len(bash) == 1
    assert bash[0]["metadata"]["is_error"] is True
    assert bash[0]["metadata"]["spans"] is None


# --- the ways a file can be incomplete ----------------------------------------------------


def test_a_tool_result_with_no_tool_use_is_counted_and_still_emitted():
    """An import that began mid-file still saw the result. Only the link is missing."""
    events, summary = import_file(EDGE)
    assert summary.unmatched_tool_results == 1
    orphan = [e for e in of_type(events, "tool.end")
              if e["call_id"] == "toolu_fixture000000000099"]
    assert len(orphan) == 1
    assert "parent_event_id" not in orphan[0]
    assert any("no matching tool use" in note for note in summary.notes)


def test_malformed_lines_are_counted_and_summarized_as_one_unavailable_event():
    """One event, not one per line: the fact is that the file was damaged."""
    events, summary = import_file(EDGE)
    assert summary.malformed_lines == 2
    errors = of_type(events, "observer.error")
    assert len(errors) == 1
    assert errors[0]["capture_status"] == "unavailable"
    assert errors[0]["metadata"]["malformed_lines"] == 2


def test_record_types_the_importer_does_not_translate_are_counted_and_never_raise():
    """Most of a real transcript is bookkeeping, and reading one must not depend on knowing it.

    The distinct names are preserved in the notes so a reader can see what went
    untranslated without the importer inventing an event to carry it.
    """
    _, summary = import_file(TRANSCRIPT)
    assert summary.unknown_records > 0
    listed = [note for note in summary.notes if note.startswith("untranslated record types:")]
    assert len(listed) == 1
    assert "attachment" in listed[0]


def test_an_unreadable_transcript_is_a_capture_gap_and_not_an_exception(tmp_path: Path):
    """The scan already finished. A permission error on a log may not fail it now."""
    events, summary = import_file(tmp_path / "does-not-exist.jsonl")
    assert summary.events == 1
    assert of_type(events, "observer.error")[0]["capture_status"] == "unavailable"
    assert summary.capture["context_selection"] == "unavailable"


def test_a_file_with_no_records_at_all_imports_to_nothing(tmp_path: Path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n\n")
    events, summary = import_file(empty)
    assert events == []
    assert summary.events == 0
    assert summary.malformed_lines == 0


# --- sidechains ---------------------------------------------------------------------------


def test_a_subagent_transcript_marks_its_tool_calls_as_sidechain_with_its_agent_id():
    """Read off the records themselves, so a caller that knows neither still gets both."""
    events, _ = import_file(SUBAGENT)
    starts = of_type(events, "tool.start")
    assert starts
    for start in starts:
        assert start["metadata"]["sidechain"] is True
        assert start["metadata"]["agent_id"] == "agentfixture000001"


def test_a_subagent_transcript_carries_no_structured_tool_result_so_it_yields_no_spans():
    """A real capture limit, not a reader defect, and one Contract 5 has to know about.

    The CLI writes ``toolUseResult`` only on the main transcript. A subagent's ``Read``
    appears with its delivered text and no file path, line range, or length, so there is
    nothing a span could honestly claim.
    """
    records = [json.loads(line) for line in SUBAGENT.read_text().splitlines() if line.strip()]
    assert not any("toolUseResult" in r for r in records)

    events, summary = import_file(SUBAGENT)

    assert of_type(events, "tool.end")
    assert summary.spans == 0
    assert of_type(events, "context.selection") == []
    assert summary.capture["context_selection"] == "unavailable"


# --- stream json and the result object ------------------------------------------------------


def test_stream_json_emits_the_same_vocabulary_as_a_transcript_under_its_own_source():
    events, summary = import_stream(STREAM)
    assert summary.model_turns == 2
    assert summary.tool_calls == summary.tool_results == 1
    assert summary.spans == 1
    assert {e["metadata"]["source"] for e in events} == {claude_code.SOURCE_STREAM}


def test_stream_json_puts_the_cli_result_record_on_the_last_response_and_in_the_notes():
    """The CLI's own accounting of the invocation belongs to the turn it describes.

    Cost is named ``cost_usd_cli_reported`` everywhere it appears because it is the CLI's
    estimate and never a bill.
    """
    events, summary = import_stream(STREAM)
    responses = of_type(events, "model.response")
    last, earlier = responses[-1], responses[:-1]

    assert last["metadata"]["result_subtype"] == "success"
    assert last["metadata"]["is_error"] is False
    assert last["metadata"]["num_turns"] == 2
    assert isinstance(last["metadata"]["cost_usd_cli_reported"], float)
    assert isinstance(last["metadata"]["duration_api_ms"], int)
    assert all(e["metadata"]["result_subtype"] is None for e in earlier)
    assert all(e["metadata"]["cost_usd_cli_reported"] is None for e in earlier)
    assert any(note.startswith("result: subtype=success") for note in summary.notes)


def test_stream_json_reads_the_init_record_for_the_session_model_without_listing_its_tools():
    _, summary = import_stream(STREAM)
    assert any(note.startswith("session model: claude-") for note in summary.notes)
    assert any(note.startswith("session tools: ") for note in summary.notes)


def test_parse_result_object_returns_the_object_and_none_for_anything_that_is_not_one():
    """An error printed where a result was expected must never become an empty success."""
    parsed = claude_code.parse_result_object(RESULT.read_text())
    assert parsed is not None
    assert parsed["subtype"] == "success"
    assert parsed["num_turns"] == 1
    assert parsed["usage"]["input_tokens"] == 10

    assert claude_code.parse_result_object("") is None
    assert claude_code.parse_result_object("not json at all") is None
    assert claude_code.parse_result_object('{"type": "assistant"}') is None
    assert claude_code.parse_result_object("[]") is None


# --- codex ----------------------------------------------------------------------------------


def test_codex_turns_become_a_request_and_a_response_with_its_usage_mapped_to_ours():
    """Codex spells its cache counters differently; the trace does not.

    ``reasoning_output_tokens`` is deliberately not folded into ``output_tokens``: it has no
    Contract 3 key, and adding it would inflate a counter read across routes.
    """
    events, summary = import_codex(CODEX)
    assert summary.model_turns == 1
    response = of_type(events, "model.response")[0]
    native = [json.loads(line) for line in CODEX.read_text().splitlines() if line.strip()]
    usage = next(r["usage"] for r in native if r.get("type") == "turn.completed")

    assert response["metadata"]["usage"] == {
        "input_tokens": usage["input_tokens"],
        "output_tokens": usage["output_tokens"],
        "cache_read_input_tokens": usage["cached_input_tokens"],
        "cache_creation_input_tokens": usage["cache_write_input_tokens"],
    }
    assert response["metadata"]["usage_available"] is True
    assert response["metadata"]["result_subtype"] == "completed"
    assert of_type(events, "model.request")[0]["metadata"]["route"] == "codex"


def test_codex_reports_no_model_so_the_response_claims_none():
    events, _ = import_codex(CODEX)
    assert of_type(events, "model.response")[0]["metadata"]["model_served"] is None


def test_codex_command_items_pair_as_tool_start_and_tool_end_carrying_the_exit_code():
    events, summary = import_codex(CODEX)
    starts = of_type(events, "tool.start")
    ends = of_type(events, "tool.end")
    assert summary.tool_calls == len(starts) == 2
    assert [e["call_id"] for e in starts] == [e["call_id"] for e in ends]
    assert all(e["metadata"]["tool_name"] == "command_execution" for e in starts)
    assert all(e["metadata"]["exit_code"] == 0 for e in ends)
    assert all(e["metadata"]["is_error"] is False for e in ends)
    assert all(e["metadata"]["input_summary"] for e in starts)


def test_codex_attributes_no_file_reads_so_context_selection_is_unavailable_not_partial():
    """Unavailable and partial are different answers, and Contract 5 reads the difference.

    Codex reads files by running a shell command, so the format carries no file attribution
    at all. Saying ``partial`` would suggest some spans were captured and others missed.
    """
    events, summary = import_codex(CODEX)
    assert of_type(events, "context.selection") == []
    assert summary.spans == 0
    assert summary.capture["context_selection"] == "unavailable"
    assert all(e["metadata"]["spans"] is None for e in of_type(events, "tool.end"))


def test_a_codex_turn_that_failed_becomes_a_response_that_says_so():
    lines = [
        json.dumps({"type": "thread.started", "thread_id": "thread-1"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "turn.failed", "error": {"message": "sandbox denied the write"}}),
    ]
    seen, observer = recording()
    summary = codex.import_exec_jsonl(
        observer, lines, workspace_root=WORKSPACE, call_id="call-1"
    )
    response = of_type(seen, "model.response")[0]
    assert response["metadata"]["is_error"] is True
    assert response["metadata"]["error"] == "sandbox denied the write"
    assert response["metadata"]["result_subtype"] == "failed"
    assert response["metadata"]["session_id"] == "thread-1"
    assert summary.model_turns == 1


def test_a_codex_turn_with_no_completion_record_is_reported_rather_than_dropped():
    """A turn whose end was never written is not a turn that succeeded."""
    lines = [
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "item.completed",
                    "item": {"id": "item_0", "type": "agent_message", "text": "hi"}}),
    ]
    seen, observer = recording()
    summary = codex.import_exec_jsonl(observer, lines, workspace_root=WORKSPACE, call_id="call-1")
    response = of_type(seen, "model.response")[0]
    assert response["metadata"]["is_error"] is None
    assert response["metadata"]["result_subtype"] is None
    assert any("no completion record" in note for note in summary.notes)


def test_a_codex_item_type_nobody_knows_is_counted_and_never_raises():
    lines = [
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "item.completed", "item": {"id": "item_0", "type": "future_thing"}}),
        json.dumps({"type": "quantum.event"}),
        json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}}),
    ]
    seen, observer = recording()
    summary = codex.import_exec_jsonl(observer, lines, workspace_root=WORKSPACE, call_id="call-1")
    assert summary.unknown_records == 2
    assert of_type(seen, "model.response")


def test_a_codex_result_with_no_start_still_pairs_a_request_with_its_response():
    """An orphan response would break the attempt-ID join every consumer uses."""
    lines = [json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}})]
    seen, observer = recording()
    codex.import_exec_jsonl(observer, lines, workspace_root=WORKSPACE, call_id="call-1")
    request = of_type(seen, "model.request")[0]
    response = of_type(seen, "model.response")[0]
    assert request["attempt_id"] == response["attempt_id"] == "call-1/turn-1"
    assert response["parent_event_id"] == request["event_id"]


def test_codex_malformed_lines_are_counted_and_summarized_once():
    lines = ["{not json", json.dumps({"type": "turn.started"}), "also not json"]
    seen, observer = recording()
    summary = codex.import_exec_jsonl(observer, lines, workspace_root=WORKSPACE, call_id="call-1")
    assert summary.malformed_lines == 2
    assert len(of_type(seen, "observer.error")) == 1


# --- the two modes ---------------------------------------------------------------------------


def test_metadata_mode_holds_no_file_content_anywhere_and_content_mode_holds_it():
    """Contract rule 5, checked by searching every metadata payload for the delivered text.

    The check is a search rather than a key list, because the rule is about where source
    ends up and not about which key somebody remembered to look at.
    """
    delivered = None
    for line in TRANSCRIPT.read_text().splitlines():
        native = json.loads(line).get("toolUseResult")
        if isinstance(native, dict) and isinstance(native.get("file"), dict):
            delivered = native["file"]["content"]
    assert delivered and "eval" in delivered
    # A line with no quote characters in it, so a JSON-escaped payload still contains it.
    needle = next(line.strip() for line in delivered.splitlines() if "eval(" in line)

    metadata_events, _ = import_file(TRANSCRIPT, mode="metadata")
    for event in metadata_events:
        assert "content" not in event
        assert needle not in json.dumps(event["metadata"])

    content_events, _ = import_file(TRANSCRIPT, mode="content")
    payloads = [e["content"] for e in content_events if "content" in e]
    assert any(needle in json.dumps(payload) for payload in payloads)
    for event in content_events:
        assert needle not in json.dumps(event["metadata"])


def test_content_mode_puts_the_tool_input_on_the_start_and_the_result_on_the_end():
    events, _ = import_file(TRANSCRIPT, mode="content")
    start = of_type(events, "tool.start")[0]
    end = of_type(events, "tool.end")[0]
    assert start["content"]["input"]["file_path"].endswith("app.py")
    assert "eval" in end["content"]["result"] or end["content"]["result"]


def test_a_user_prompt_is_reported_on_the_turn_it_drove_and_on_no_later_one():
    """A later turn in the same session was driven by a tool result, not by that prompt.

    Reusing the prompt's length across every turn would describe a request that was never
    made, which is the same class of mistake as counting one turn's tokens twice.
    """
    events, _ = import_file(TRANSCRIPT, mode="content")
    first, *rest = of_type(events, "model.request")
    assert "eval" in first["content"]["prompt"]
    assert first["metadata"]["prompt_chars"] == len(first["content"]["prompt"])
    assert rest
    for request in rest:
        assert request["metadata"]["prompt_chars"] is None
        assert "content" not in request


def test_an_observer_that_is_off_still_reports_what_the_file_held():
    """The summary describes the records, not the emission, so a caller can survey first."""
    observer = Observer(mode="off")
    summary = claude_code.import_transcript(
        observer, TRANSCRIPT, workspace_root=WORKSPACE, call_id="call-1"
    )
    assert summary.events == 0
    assert summary.model_turns == 2
    assert summary.tool_calls == 1
    assert summary.spans == 1


# --- the wire contract -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,importer",
    [
        ("transcript", lambda: import_file(TRANSCRIPT, mode="content")),
        ("subagent", lambda: import_file(SUBAGENT, mode="content")),
        ("edge-cases", lambda: import_file(EDGE, mode="content")),
        ("stream-json", lambda: import_stream(STREAM, mode="content")),
        ("stream-json-error", lambda: import_stream(STREAM_ERROR, mode="content")),
        ("codex", lambda: import_codex(CODEX, mode="content")),
        ("codex-errors", lambda: import_codex(CODEX_ERRORS, mode="content")),
    ],
)
def test_every_event_an_importer_emits_validates_against_the_wire_contract(name, importer):
    events, _ = importer()
    assert events, f"{name} produced no events"
    check = validator()
    for event in events:
        errors = sorted(check.iter_errors(event), key=lambda error: error.path)
        assert not errors, f"{name}: {[error.message for error in errors]}"


@pytest.mark.parametrize(
    "name,importer",
    [
        ("transcript", lambda: import_file(TRANSCRIPT, mode="content")),
        ("subagent", lambda: import_file(SUBAGENT, mode="content")),
        ("edge-cases", lambda: import_file(EDGE, mode="content")),
        ("stream-json", lambda: import_stream(STREAM, mode="content")),
        ("stream-json-error", lambda: import_stream(STREAM_ERROR, mode="content")),
        ("codex", lambda: import_codex(CODEX, mode="content")),
        ("codex-errors", lambda: import_codex(CODEX_ERRORS, mode="content")),
    ],
)
def test_the_same_fixture_and_the_same_injected_clock_produce_the_same_bytes(name, importer):
    """Determinism is what makes a trace diffable, and it is why the hooks are injectable."""
    first, first_summary = importer()
    second, second_summary = importer()
    assert as_jsonl(first) == as_jsonl(second), name
    assert first_summary == second_summary


@pytest.mark.parametrize(
    "name,importer",
    [
        ("transcript", lambda: import_file(TRANSCRIPT, mode="content")),
        ("subagent", lambda: import_file(SUBAGENT, mode="content")),
        ("edge-cases", lambda: import_file(EDGE, mode="content")),
        ("stream-json", lambda: import_stream(STREAM, mode="content")),
        ("stream-json-error", lambda: import_stream(STREAM_ERROR, mode="content")),
        ("codex", lambda: import_codex(CODEX, mode="content")),
        ("codex-errors", lambda: import_codex(CODEX_ERRORS, mode="content")),
    ],
)
def test_no_event_any_importer_emits_carries_an_absolute_path_in_its_metadata(name, importer):
    """The reason the collectors exist at all is also the thing that could leak a home.

    Every string in every metadata payload is searched, not a list of the keys someone
    remembered were paths: the leak that matters is the one in a field nobody audits, such
    as the shell command inside ``input_summary``.

    Metadata only. Content mode may hold the text a tool returned, and that text is the
    run's own output rather than a path this importer chose to record.
    """
    import re

    absolute = re.compile(r"/(?:[A-Za-z0-9._@+-]+/)+[A-Za-z0-9._@+-]*")

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    events, _ = importer()
    for event in events:
        for text in strings(event["metadata"]):
            found = absolute.search(text)
            assert found is None, f"{name}: absolute path {found.group(0)!r} in {text[:120]!r}"


@pytest.mark.parametrize(
    "name,importer",
    [
        ("transcript", lambda: import_file(TRANSCRIPT)),
        ("subagent", lambda: import_file(SUBAGENT)),
        ("stream-json", lambda: import_stream(STREAM)),
        ("stream-json-error", lambda: import_stream(STREAM_ERROR)),
        ("codex", lambda: import_codex(CODEX)),
        ("codex-errors", lambda: import_codex(CODEX_ERRORS)),
    ],
)
def test_every_importer_answers_every_contract_capture_key_and_claims_nothing_complete(
    name, importer
):
    """A key left out would read as an oversight; ``not_applicable`` reads as an answer.

    Nothing is ever ``complete``: every reading here is derived from a record the CLI wrote
    for its own purposes, so no collector can say it saw the whole of anything.
    """
    _, summary = importer()
    assert set(summary.capture) == CAPTURE_KEYS, name
    assert set(summary.capture.values()) <= CAPTURE_VALUES, name
    assert "complete" not in summary.capture.values(), name
    assert summary.capture["finding_submitted"] == "not_applicable", name


@pytest.mark.parametrize(
    "name,importer",
    [
        ("transcript", lambda: import_file(TRANSCRIPT)),
        ("stream-json", lambda: import_stream(STREAM)),
        ("stream-json-error", lambda: import_stream(STREAM_ERROR)),
        ("codex", lambda: import_codex(CODEX)),
        ("codex-errors", lambda: import_codex(CODEX_ERRORS)),
    ],
)
def test_every_event_names_the_record_it_was_read_out_of(name, importer):
    """Contract rule 6: an observation that cannot say where it came from is a guess."""
    sources = {"claude_code_transcript", "claude_code_stream_json", "codex_exec_json"}
    events, _ = importer()
    for event in events:
        assert event["metadata"]["source"] in sources, name


# --- path handling ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected,external",
    [
        ("/workspace/app.py", "app.py", False),
        ("/workspace/src/deep/app.py", "src/deep/app.py", False),
        ("app.py", "app.py", False),
        ("./app.py", "app.py", False),
        ("/workspace/./src/../app.py", "app.py", False),
        ("/etc/passwd", "external:passwd", True),
        ("/workspace/../secrets.env", "external:secrets.env", True),
        ("/Users/someone/.claude/projects/a.jsonl", "external:a.jsonl", True),
        ("", None, False),
        (None, None, False),
    ],
)
def test_a_native_path_becomes_workspace_relative_or_is_marked_external(raw, expected, external):
    """Textual and never resolved: the trace may be read on a machine the run never touched."""
    assert workspace_path(raw, Path("/workspace")) == (expected, external)


def test_an_absolute_path_inside_a_shell_command_is_rewritten_before_it_reaches_metadata():
    """The leak nobody plans for: a command is a string, and strings are not audited as paths.

    Codex reads files by running a shell, and a Claude ``Bash`` call can name anything on the
    machine, so an ``input_summary`` that passed the command through verbatim would put an
    operator's home directory into a trace through a field no one thinks of as a path.
    """
    from scaneval.collectors import relocate_paths

    rewritten = relocate_paths(
        "cat /workspace/app.py && cat /Users/someone/.aws/credentials", Path("/workspace")
    )
    assert rewritten == "cat app.py && cat external:credentials"
    assert relocate_paths("rg -n 'eval' app.py", Path("/workspace")) == "rg -n 'eval' app.py"
    assert relocate_paths(None, Path("/workspace")) is None


def test_a_codex_command_summary_names_the_command_without_naming_the_machine():
    events, _ = import_codex(CODEX)
    summaries = [e["metadata"]["input_summary"] for e in of_type(events, "tool.start")]
    assert all("app.py" in summary for summary in summaries)
    assert all("/" not in summary.split()[0] for summary in summaries)


# --- failure text ------------------------------------------------------------------------------


def metadata_strings(event: dict):
    def walk(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for item in value.values():
                yield from walk(item)
        elif isinstance(value, list):
            for item in value:
                yield from walk(item)

    return list(walk(event["metadata"]))


@pytest.mark.parametrize(
    "name,importer",
    [
        ("codex", lambda mode: import_codex(CODEX_ERRORS, mode=mode)),
        ("stream-json", lambda mode: import_stream(STREAM_ERROR, mode=mode)),
    ],
)
def test_a_native_failure_message_never_reaches_metadata_whole(name, importer):
    """The finding this rule exists for: a CLI error message is free text, not a code.

    It is written for a human terminal, so it quotes the command that failed, the traceback
    it produced, the source line that raised, and absolute paths on the operator's machine.
    Copying it into ``metadata.error`` walks all of that past the metadata/content
    separation the rest of the package keeps, through a field nobody reads as a content
    field.
    """
    for mode in ("metadata", "content"):
        events, _ = importer(mode)
        for event in events:
            for text in metadata_strings(event):
                assert HOME_PATH not in text, f"{name}/{mode}: home path in metadata"
                assert SOURCE_EXCERPT not in text, f"{name}/{mode}: source excerpt in metadata"
                assert "Traceback (most recent call last)" not in text or len(text) <= 120


@pytest.mark.parametrize(
    "name,importer,expected_kind",
    [
        ("codex", lambda: import_codex(CODEX_ERRORS), "turn_failed"),
        ("stream-json", lambda: import_stream(STREAM_ERROR), "result_error"),
    ],
)
def test_a_failure_is_named_by_a_closed_kind_and_summarized_within_the_bound(
    name, importer, expected_kind
):
    """``failure_kind`` is a field consumers group by, so its vocabulary is closed.

    One CLI's stray string appearing there would turn a closed vocabulary into an open one
    without anybody deciding to.
    """
    from scaneval.collectors import FAILURE_KINDS, SUMMARY_CHARS

    events, _ = importer()
    failed = [e for e in of_type(events, "model.response") if e["metadata"]["failure_kind"]]
    assert failed, name
    for response in failed:
        assert response["metadata"]["failure_kind"] == expected_kind
        assert response["metadata"]["failure_kind"] in FAILURE_KINDS
        summary = response["metadata"]["error"]
        assert summary and len(summary) <= SUMMARY_CHARS
        # Relocated, not merely shortened: the paths that survive the bound are workspace
        # relative or external, never the operator's.
        assert "external:credentials" in summary or "/" not in summary


@pytest.mark.parametrize(
    "name,importer",
    [
        ("codex", lambda mode: import_codex(CODEX_ERRORS, mode=mode)),
        ("stream-json", lambda mode: import_stream(STREAM_ERROR, mode=mode)),
    ],
)
def test_the_whole_failure_message_is_kept_in_content_mode_and_nowhere_else(name, importer):
    """Bounding metadata must not throw the message away: content mode is where it lives."""
    events, _ = importer("content")
    payloads = [e["content"]["error"] for e in events if "error" in e.get("content", {})]
    assert payloads, name
    assert any(HOME_PATH in payload for payload in payloads)
    assert any(SOURCE_EXCERPT in payload for payload in payloads)

    events, _ = importer("metadata")
    assert all("content" not in e for e in events), name


def test_a_codex_error_item_is_reported_on_the_turn_it_happened_in():
    """An error item is the only trace of a failure a later ``turn.completed`` papers over."""
    lines = [
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "item.completed", "item": {
            "id": "item_0", "type": "error",
            "message": f"read blocked: {HOME_PATH}\n    {SOURCE_EXCERPT}"}}),
        json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}}),
    ]
    seen, observer = recording("content")
    codex.import_exec_jsonl(observer, lines, workspace_root=WORKSPACE, call_id="call-1")
    response = of_type(seen, "model.response")[0]

    assert response["metadata"]["failure_kind"] == "item_error"
    # The turn itself completed, and that stays true: the two facts are orthogonal and the
    # trace reports both rather than picking one.
    assert response["metadata"]["is_error"] is False
    assert response["metadata"]["result_subtype"] == "completed"
    assert HOME_PATH not in json.dumps(response["metadata"])
    assert HOME_PATH in response["content"]["error"]


def test_a_turn_that_failed_outranks_an_error_item_inside_it():
    lines = [
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "item.completed",
                    "item": {"id": "item_0", "type": "error", "message": "an item went wrong"}}),
        json.dumps({"type": "turn.failed", "error": {"message": "the turn went wrong"}}),
    ]
    seen, observer = recording("content")
    codex.import_exec_jsonl(observer, lines, workspace_root=WORKSPACE, call_id="call-1")
    response = of_type(seen, "model.response")[0]
    assert response["metadata"]["failure_kind"] == "turn_failed"
    assert response["content"]["error"] == "the turn went wrong"


def test_a_turn_that_did_not_fail_carries_no_failure_kind_and_no_error():
    events, _ = import_codex(CODEX)
    for response in of_type(events, "model.response"):
        assert response["metadata"]["failure_kind"] is None
        assert response["metadata"]["error"] is None


def test_an_unrecognized_failure_kind_is_recorded_as_unknown_rather_than_passed_through():
    from scaneval.collectors import _Import

    tracker = _Import(Observer(mode="off"), source="s", route="r",
                      workspace_root=WORKSPACE, call_id="call-1")
    assert tracker.failure("something_new", "boom") == ("unknown", "boom")
    assert tracker.failure(None, None) == (None, None)


def test_a_cli_authored_status_string_is_bounded_before_it_reaches_metadata():
    """Short enums today. "Today" is not a property metadata should rely on."""
    long_status = "failed:" + "x" * 500
    lines = [
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "item.started", "item": {
            "id": "item_0", "type": "command_execution", "command": "ls"}}),
        json.dumps({"type": "item.completed", "item": {
            "id": "item_0", "type": "command_execution", "command": "ls",
            "status": long_status, "aggregated_output": ""}}),
    ]
    seen, observer = recording()
    codex.import_exec_jsonl(observer, lines, workspace_root=WORKSPACE, call_id="call-1")
    assert len(of_type(seen, "tool.end")[0]["metadata"]["status"]) <= 60


def test_a_cli_authored_result_subtype_is_bounded_too():
    long_subtype = "error_" + "y" * 500
    lines = [
        json.dumps({"type": "assistant", "session_id": "s",
                    "message": {"id": "m1", "role": "assistant", "model": "claude-haiku-4-5",
                                "usage": {"input_tokens": 1, "output_tokens": 1},
                                "content": [{"type": "text", "text": "hi"}]}}),
        json.dumps({"type": "result", "subtype": long_subtype, "is_error": True,
                    "session_id": "s", "result": "boom"}),
    ]
    seen, observer = recording()
    claude_code.import_stream_json(observer, lines, workspace_root=WORKSPACE, call_id="call-1")
    assert len(of_type(seen, "model.response")[0]["metadata"]["result_subtype"]) <= 60


# --- more than one spelling of the same workspace --------------------------------------------

# The shape of the real failure this pair of roots was added for: a harness handed the CLI
# the temporary directory by the path macOS gives it, and the agent recorded every read
# under the realpath of that same directory.
HANDED = "/var/folders/qx/T/scaneval-trial-x/source"
REALPATH = "/private/var/folders/qx/T/scaneval-trial-x/source"


def transcript_reading(path: str, tmp_path: Path) -> Path:
    """A minimal real-shaped transcript in which the agent read one file at ``path``."""
    delivered = "def handler():\n    return eval(request.args['q'])\n"
    records = [
        {"type": "user", "uuid": "u-1", "parentUuid": None, "sessionId": "s-1",
         "isSidechain": False,
         "message": {"role": "user", "content": "Read the handler."}},
        {"type": "assistant", "uuid": "a-1", "parentUuid": "u-1", "sessionId": "s-1",
         "requestId": "req-1", "isSidechain": False,
         "message": {"id": "msg-1", "role": "assistant", "model": "claude-haiku-4-5",
                     "usage": {"input_tokens": 5, "output_tokens": 6,
                               "cache_read_input_tokens": 0,
                               "cache_creation_input_tokens": 0},
                     "content": [{"type": "tool_use", "id": "toolu-1", "name": "Read",
                                  "input": {"file_path": path}}]}},
        {"type": "user", "uuid": "u-2", "parentUuid": "a-1", "sessionId": "s-1",
         "isSidechain": False,
         "message": {"role": "user", "content": [
             {"type": "tool_result", "tool_use_id": "toolu-1", "content": "1\tdef handler():\n"}]},
         "toolUseResult": {"type": "text", "file": {
             "filePath": path, "content": delivered,
             "numLines": 2, "startLine": 1, "totalLines": 2}}},
    ]
    target = tmp_path / "transcript.jsonl"
    target.write_text("".join(json.dumps(r) + "\n" for r in records))
    return target


def test_a_transcript_that_spells_the_workspace_the_other_way_still_relativizes(tmp_path: Path):
    """The real bug: one root, two true spellings, and every span silently filed external.

    A harness passed its source directory as ``/var/folders/.../source`` while the agent
    recorded ``/private/var/folders/.../source`` in every ``filePath``. The textual
    comparison is correct and the two strings genuinely differ, so nothing was wrong except
    that the collector was only told one of the two names for the directory.
    """
    transcript = transcript_reading(f"{REALPATH}/app/handler.py", tmp_path)

    seen, observer = recording()
    summary = claude_code.import_transcript(
        observer, transcript, workspace_root=(Path(HANDED), Path(REALPATH)), call_id="call-1"
    )

    assert summary.spans == 1
    span = of_type(seen, "tool.end")[0]["metadata"]["spans"][0]
    assert span["path"] == "app/handler.py"
    assert not span["path"].startswith("external:")
    assert of_type(seen, "context.selection")[0]["metadata"]["span_count"] == 1
    assert of_type(seen, "tool.start")[0]["metadata"]["input_summary"] == "app/handler.py"
    assert not any(note.startswith("paths outside") for note in summary.notes)


def test_that_same_transcript_with_only_the_handed_root_files_the_read_as_external(
    tmp_path: Path,
):
    """The behaviour before the fix, kept as a test so the fix cannot be read as cosmetic.

    Nothing in the records says the two directories are the same, and the collector will not
    ask the filesystem, so with one spelling this outcome is the honest one: the path really
    is outside the only root it was given.
    """
    transcript = transcript_reading(f"{REALPATH}/app/handler.py", tmp_path)

    seen, observer = recording()
    summary = claude_code.import_transcript(
        observer, transcript, workspace_root=Path(HANDED), call_id="call-1"
    )

    span = of_type(seen, "tool.end")[0]["metadata"]["spans"][0]
    assert span["path"] == "external:handler.py"
    assert any(note.startswith("paths outside") for note in summary.notes)


def test_one_root_behaves_exactly_as_it_did_whether_it_is_passed_bare_or_in_a_sequence():
    """The widened argument must not change the single-root case that every caller uses."""
    bare, bare_summary = import_file(TRANSCRIPT, mode="content")
    seen, observer = recording("content")
    wrapped_summary = claude_code.import_transcript(
        observer, TRANSCRIPT, workspace_root=[WORKSPACE], call_id="call-1"
    )
    assert as_jsonl(bare) == as_jsonl(seen)
    assert bare_summary == wrapped_summary

    duplicated, observer = recording("content")
    claude_code.import_transcript(
        observer, TRANSCRIPT, workspace_root=(WORKSPACE, WORKSPACE, str(WORKSPACE)),
        call_id="call-1",
    )
    assert as_jsonl(bare) == as_jsonl(duplicated)


def test_the_first_root_is_the_one_a_relative_path_is_resolved_against():
    """A relative path meant the workspace the caller itself named, not its alias."""
    assert workspace_path("app.py", (HANDED, REALPATH)) == ("app.py", False)
    assert workspace_path("app.py", (REALPATH, HANDED)) == ("app.py", False)


@pytest.mark.parametrize(
    "roots,expected",
    [
        ("/workspace", ("/workspace",)),
        (Path("/workspace"), ("/workspace",)),
        (["/workspace"], ("/workspace",)),
        ((Path("/a"), Path("/b")), ("/a", "/b")),
        # Deduplicated and order-preserving, so a caller can pass (dir, dir.resolve())
        # unconditionally and get one root where those are the same string.
        ((Path("/a"), "/a", Path("/b"), "/a"), ("/a", "/b")),
        (["/workspace/"], ("/workspace",)),
    ],
)
def test_workspace_roots_normalizes_deduplicates_and_keeps_the_callers_order(roots, expected):
    assert workspace_roots(roots) == expected


@pytest.mark.parametrize("bad", [[], (), "", [""], [Path("/a"), 7], 7, None, {"/a"}])
def test_workspace_roots_refuses_a_root_list_it_cannot_use(bad):
    """Wiring, so it raises. A collector that accepted "no workspace" would mark every path
    external and report a clean import while doing it."""
    with pytest.raises(ValueError):
        workspace_roots(bad)


def test_an_importer_refuses_an_empty_root_sequence_before_it_reads_anything(tmp_path: Path):
    observer = Observer(mode="off")
    with pytest.raises(ValueError):
        claude_code.import_transcript(
            observer, tmp_path / "never-opened.jsonl", workspace_root=[], call_id="call-1"
        )
    with pytest.raises(ValueError):
        claude_code.import_stream_json(observer, [], workspace_root=(), call_id="call-1")
    with pytest.raises(ValueError):
        codex.import_exec_jsonl(observer, [], workspace_root=[], call_id="call-1")


def test_a_shell_command_naming_the_other_spelling_relativizes_too():
    """``relocate_paths`` shares the root list, so a command is not filed external either."""
    from scaneval.collectors import relocate_paths

    rewritten = relocate_paths(
        f"cat {REALPATH}/app.py {HANDED}/util.py /etc/passwd", (HANDED, REALPATH)
    )
    assert rewritten == "cat app.py util.py external:passwd"


def test_codex_accepts_the_same_root_list_for_the_paths_in_its_commands():
    lines = [
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "item.started", "item": {
            "id": "item_0", "type": "command_execution",
            "command": f"nl -ba {REALPATH}/app.py", "status": "in_progress"}}),
        json.dumps({"type": "item.completed", "item": {
            "id": "item_0", "type": "command_execution",
            "command": f"nl -ba {REALPATH}/app.py", "exit_code": 0, "status": "completed",
            "aggregated_output": "1\tdef handler():\n"}}),
        json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1}}),
    ]
    seen, observer = recording()
    codex.import_exec_jsonl(
        observer, lines, workspace_root=(Path(HANDED), Path(REALPATH)), call_id="call-1"
    )
    assert of_type(seen, "tool.start")[0]["metadata"]["input_summary"] == "nl -ba app.py"
