"""Public saved-run investigation CLI fixtures."""
import json
import pytest
from scaneval.cli import main
from test_v2_runner import upstream
from test_v2_investigation import make_run, fingerprints, MALICIOUS


@pytest.mark.parametrize("status,malformed,failed", [("success",False,False),("partial",True,False),("error",False,True)])
def test_cli_opens_complete_partial_and_failed_runs_without_changing_evidence(tmp_path, upstream, status, malformed, failed):
    run = make_run(tmp_path, upstream, status=status, malformed=malformed, failed=failed)
    before = fingerprints(run)
    out = tmp_path / "investigation"
    assert main(["investigate", str(run), "--output", str(out)]) == 0
    document = json.loads((out / "investigation.json").read_text())
    assert document["run"]["data"]["status"] == ("failed" if failed else "completed")
    inv = document["invocations"][0]
    assert inv["status"] == status
    assert inv["trace"]["state"] == ("partial" if malformed else "valid")
    assert inv["trace"]["valid_events"] == 5
    assert inv["claims"][0]["decisions"][0]["reason"].startswith("Recorded fixture judgment")
    assert inv["claims"][0]["decision_binding"] == "current"
    assert inv["targets"][-1]["explanation_state"] == "unexplained"
    assert inv["targets"][-1]["event_refs"] == []
    assert inv["claims"][0]["artifact_bindings"][0]["state"] == "current"
    assert fingerprints(run) == before
    html = (out / "index.html").read_text()
    assert MALICIOUS not in html
    assert 'default-src \'none\'' in html and 'connect-src \'none\'' in html
    assert "innerHTML" not in html and "fetch(" not in html and 'eval(' not in html
    exported = json.dumps(document)
    assert "/workspace/company/billing.py" in exported
    assert "test-credential-value" not in exported and "structured-secret" not in exported
    assert "a secret with spaces" not in exported
    assert document["export_policy"]["redactions"]



def test_all_cli_filters_apply_and_zero_events_keep_capture_visible(tmp_path, upstream):
    run = make_run(tmp_path, upstream)
    out = tmp_path / "filtered"
    assert main(["investigate", str(run), "--output", str(out), "--type", "finding.submitted",
                 "--producer", "producer-a", "--call", "shared-call", "--candidate", "same-candidate", "--claim", "c1"]) == 0
    inv = json.loads((out / "investigation.json").read_text())["invocations"][0]
    assert len(inv["events"]) == 1
    assert inv["capture"]["categories"]["model_requests"] == "complete"
    assert inv["trace"]["filtered_events"] == 4

