"""Real frozen files through the native collector and coverage diagnostic."""
import json

import pytest

from scaneval.collectors.claude_code import import_stream_json, import_transcript
from scaneval.collectors.source import FrozenSource
from scaneval.diagnostics import context_coverage
from scaneval.observer import Observer


def native_read(path):
    return [
        {"type": "assistant", "message": {"id": "a", "content": [
            {"type": "tool_use", "id": "read", "name": "Read",
             "input": {"file_path": str(path), "offset": 5, "limit": 2}}]}},
        {"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "read", "content": "     5\tx = 1\n     6\ty = 2\n"}]},
         "toolUseResult": {"type": "text", "file": {"filePath": str(path),
             "content": "x = 1\ny = 2\n", "numLines": 2, "startLine": 5, "totalLines": 10}}},
        {"type": "assistant", "message": {"id": "b", "content": [{"type": "text", "text": "Done."}]}}
    ]


@pytest.mark.parametrize("transport", ["stream", "transcript"])
@pytest.mark.parametrize("case", ["exact", "metadata", "no-followup", "no-binding", "changed-source",
    "missing-file", "symlink", "directory-symlink", "traversal", "wrong-request", "wrong-result-path",
    "wrong-result-id", "wrong-start", "wrong-content", "omitted-line", "rendered-envelope", "error", "wrong-delivery", "missing-root", "wrong-tool"])
def test_bounded_read_requires_request_delivery_and_frozen_correspondence(tmp_path, case, transport):
    workspace = tmp_path / "source"
    workspace.mkdir()
    path = workspace / "example.py"
    path.write_text("a\nb\nc\nd\nx = 1\ny = 2\ng\nh\ni\nj\n")
    frozen = FrozenSource.capture(workspace)
    records = native_read(path)
    request = records[0]["message"]["content"][0]
    result = records[1]["message"]["content"][0]
    file = records[1]["toolUseResult"]["file"]
    if case == "no-followup": records.pop()
    if case == "no-binding": frozen = None
    if case == "missing-root": frozen = FrozenSource.capture(tmp_path / "missing")
    if case == "wrong-delivery": result["content"] = "     5\tx = 9\n     6\ty = 2\n"
    if case == "wrong-tool": request["name"] = "Bash"
    if case == "changed-source": path.write_text("changed\n")
    if case == "missing-file": path.unlink()
    if case == "symlink":
        other = tmp_path / "other.py"
        path.rename(other)
        path.symlink_to(other)
    if case == "directory-symlink":
        other = tmp_path / "elsewhere"
        workspace.rename(other)
        workspace.symlink_to(other, target_is_directory=True)
    if case == "traversal": request["input"]["file_path"] = str(workspace / "child/../example.py")
    if case == "wrong-request": request["input"]["offset"] = 4
    if case == "wrong-result-path": file["filePath"] = str(workspace / "other.py")
    if case == "wrong-result-id": result["tool_use_id"] = "other"
    if case == "wrong-start": file["startLine"] = 4
    if case == "wrong-content": file["content"] = "invented\ntext\n"
    if case == "omitted-line": result["content"] = "     5\tx = 1\n     7\ty = 2\n"
    if case == "rendered-envelope": result["content"] += "... omitted ...\n"
    if case == "error": result["is_error"] = True
    events = []
    observer = Observer(mode="metadata" if case == "metadata" else "content", sink=events.append,
                        run_id="audit", producer_id="audit")
    if transport == "stream":
        summary = import_stream_json(observer, map(json.dumps, records), workspace_root=workspace,
                                     call_id="call", frozen_source=frozen)
    else:
        transcript = tmp_path / "transcript.jsonl"
        transcript.write_text("\n".join(map(json.dumps, records)))
        summary = import_transcript(observer, transcript, workspace_root=workspace,
                                    call_id="call", frozen_source=frozen)
    report = context_coverage(plan_targets=[{"target_id": "t", "accepted_locations": [
        {"path": "example.py", "start_line": 5, "end_line": 6}]}], events=events,
        execution_record={"capture": summary.capture})
    target = report["targets"][0]
    selections = [e for e in events if e["type"] == "context.selection"]
    if case in ("exact", "metadata"):
        assert target["best"] == "included"
        assert target["union"]["covered_lines"] == 2
        selected = selections[0]["metadata"]["spans"][0]
        assert selected["source_mapping"] == "verified_exact"
        assert selected["source_sha256"] == frozen.hashes["example.py"]
    else:
        assert target["best"] == "unknown"
        assert target["union"]["covered_lines"] == 0
        assert all("source_mapping" not in span for e in selections for span in e["metadata"]["spans"])
    if case == "no-followup":
        assert selections == []
        assert "verified_exact" not in json.dumps(events)
    if case == "metadata":
        assert all("content" not in event for event in events)
        assert "x = 1" not in json.dumps(events)
