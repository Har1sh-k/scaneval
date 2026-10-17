"""Publication sanitizer CLI controls; no private trace data is involved."""
import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/sanitize_native_trace.py"


@pytest.mark.parametrize("source,expected", [
    ("/Users/AuditUser/project/private.py", "/redacted/private.py"),
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
