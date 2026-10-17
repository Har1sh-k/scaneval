"""Publication sanitizer CLI controls; no private trace data is involved."""
import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/sanitize_native_trace.py"


@pytest.mark.parametrize("source,expected", [
    ("/Users/user/project/private.py", "/redacted/private.py"),
    ("/Users/审计用户/project/private.py", "/redacted/private.py"),
    ("/home/José/project/private.py", "/redacted/private.py"),
    ("/workspace-private/client/private.py", "/redacted/private.py"),
    ("/redacted-secret/client/private.py", "/redacted/private.py"),
    ("/workspace", "/workspace"),
    ("/workspace/app.py", "/workspace/app.py"),
    ("/redacted/app.py", "/redacted/app.py"),
    ("/tmp/synthetic-workspace/app.py", "/workspace/app.py"),
    ("ordinary text", "ordinary text"),
])
def test_cli_scrubs_whole_unicode_paths_and_only_exempts_placeholder_components(tmp_path, source, expected):
    raw, target = tmp_path / "raw.json", tmp_path / "clean.json"
    raw.write_text(json.dumps({"type": "result", "subtype": "success", "result": source}))
    subprocess.run([sys.executable, str(SCRIPT), "--kind", "result-json", "--workspace",
                    "/tmp/synthetic-workspace", "--in", str(raw), "--out", str(target)], check=True, capture_output=True)
    clean = target.read_text()
    assert json.loads(clean)["result"] == expected
    sanitizer = runpy.run_path(str(SCRIPT))
    assert sanitizer["audit"](clean, "/tmp/synthetic-workspace") == []
    assert sanitizer["sanitize"]("result-json", clean, "/tmp/synthetic-workspace") == clean
    if source != expected:
        assert sanitizer["audit"](json.dumps({"result": source}, ensure_ascii=False), "/tmp/synthetic-workspace")


@pytest.mark.parametrize("payload", [
    {"result": {"content": [{"type": "text", "text": "/Users/审计用户/private/finding.py"}],
                "structured_content": {"api_key": "CREDENTIAL", "output_tokens": 2}}},
    {"result": {"structured_content": {"path": "/workspace-private/client/a.py", "password": "CREDENTIAL"}}},
    {"result": {"content": [{"type": "image", "data": "SYNTHETIC_IMAGE", "mimeType": "image/png"}],
                "_meta": {"nested": {"Authorization": "CREDENTIAL"}}}},
    {"error": {"message": "failure at /redacted-secret/client/a.py"}},
])
def test_codex_mcp_publication_preserves_supported_payloads_through_import(tmp_path, payload):
    from scaneval.collectors import codex
    from scaneval.observer import Observer

    item = {"id": "tool", "type": "mcp_tool_call", "server": "fixture", "tool": "scan",
            "arguments": {"secret": "CREDENTIAL", "input_tokens": 2}}
    records = [{"type": "turn.started"}, {"type": "item.started", "item": item},
               {"type": "item.completed", "item": {**item, **payload,
                 "status": "failed" if "error" in payload else "completed"}}, {"type": "turn.completed"}]
    raw, target = tmp_path / "raw.jsonl", tmp_path / "clean.jsonl"
    raw.write_text("\n".join(map(json.dumps, records)))
    subprocess.run([sys.executable, str(SCRIPT), "--kind", "codex-exec", "--workspace", "/tmp/work",
                    "--in", str(raw), "--out", str(target)], check=True, capture_output=True)
    clean = target.read_text()
    sanitizer = runpy.run_path(str(SCRIPT))
    assert "CREDENTIAL" not in clean
    assert "审计用户" not in clean
    assert sanitizer["audit"](clean, "/tmp/work") == []
    assert sanitizer["sanitize"]("codex-exec", clean, "/tmp/work") == clean
    completed = json.loads(clean.splitlines()[2])["item"]
    for key in payload:
        assert key in completed
    seen = []
    observer = Observer(mode="content", sink=seen.append)
    summary = codex.import_exec_jsonl(observer, clean.splitlines(), workspace_root="/workspace", call_id="call")
    end = next(e for e in seen if e["type"] == "tool.end")
    if "result" in payload:
        assert end["content"]["result"] == completed["result"]
        assert end["metadata"]["result_available"] is True
    else:
        assert end["content"]["error"] == completed["error"]["message"]
        assert end["metadata"]["is_error"] is True
    assert summary.tool_results == 1
    assert observer.get_state().dropped_events == 0


def test_publication_credential_keys_match_observer_and_preserve_usage():
    from scaneval.observer import default_redactor
    sanitizer = runpy.run_path(str(SCRIPT))
    keys = ["api_key", "API-KEY", "Authorization", "credentials", "password", "privateKey",
            "token", "input_tokens", "output_tokens", "secret_count", "ſecret"]
    values = {key: "fixture" for key in keys}
    expected = {key: default_redactor(key, value, ()) for key, value in values.items()}
    assert sanitizer["scrub_value"](values, "/tmp/work") == expected
