"""Real OCI boundary and benign public retrieval checks; no scanner/model experiment runs.

Uses the existing pinned images and shared-home scratch convention. Set
SCANEVAL_REQUIRE_DOCKER=1 to make a missing engine/image fail instead of skip.
"""

import json
from pathlib import Path
import shutil

from scaneval.adapters.base import build_env, run_command
from scaneval.isolation import resolve_execution
from scaneval.isolation.oci import OciBackend
from scaneval.open_context import export_history, install_history
from scaneval.runner import run_from_config
from scaneval import conditions
from scaneval.contracts import load_document

from test_v2_isolation_docker import PYTHON_IMAGE, ScriptAdapter, pilot, run_id, scratch, scratch_parent  # noqa: F401
from test_v2_open_context import history_fixture


RETRIEVAL = {"policy": "recorded_public_v1", "allowed_origins": ["https://example.com", "https://127.0.0.1"],
             "capture": "content", "retention": "bundle"}
CONDITION = {"name": "open_context", "policy": {"history": "ancestor_history_v1", "retrieval": "recorded_public_v1",
              "web_mode": "live", "capture": "content", "retention": "bundle"}}


def test_live_recorded_retrieval_and_private_denial_run_inside_real_boundary(scratch):
    snapshot, exported, digest, *_ = history_fixture(scratch)
    history = scratch / "history.git"
    attestation = export_history(snapshot, history, source_dir=exported, expected_tree_hash=digest)
    settings = resolve_execution({"backend": "oci", "image": PYTHON_IMAGE, "proxy_image": PYTHON_IMAGE,
        "egress": [{"host": "example.com", "port": 443}, {"host": "127.0.0.1", "port": 443}],
        "retrieval": RETRIEVAL}, "public_research")
    backend = OciBackend(settings, run_id=run_id(scratch), invocation_id="public-fixture",
                         scratch_root=scratch)
    workspace = backend.workspace_root / "scaneval-trial-public-fixture"
    workspace.mkdir()
    source = workspace / "source"
    shutil.copytree(exported, source)
    install_history(history, source, expected=attestation)
    raw = workspace / "raw"
    raw.mkdir()
    labels = scratch / "evaluator-labels.json"
    labels.write_text("must remain outside the scanner\n")
    script = r'''
import json, os, pathlib, socket, sys, urllib.request, urllib.error
base = os.environ['SCANEVAL_RETRIEVAL_URL']
def fetch(url):
    request = urllib.request.Request(base+'/fetch', data=json.dumps({'url':url}).encode(),
                                     headers={'Content-Type':'application/json'})
    try:
        reply = urllib.request.urlopen(request, timeout=60)
    except urllib.error.HTTPError as exc:
        reply = exc
    return json.load(reply)
live = fetch('https://example.com/')
denied = fetch('https://127.0.0.1/metadata')
source = pathlib.Path.cwd()
try:
    (source/'source.py').write_text('modified')
    read_only = False
except OSError:
    read_only = True
try:
    upstream = socket.create_connection(('1.1.1.1',443), timeout=2)
    upstream.close()
    direct_blocked = False
except OSError:
    direct_blocked = True
proxy = urllib.request.getproxies()['https']
from urllib.parse import urlsplit
parts = urlsplit(proxy)
with socket.create_connection((parts.hostname,parts.port), timeout=5) as stream:
    stream.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n')
    private_connect_denied = b' 403 ' in stream.recv(100)
print(json.dumps({'live':live['outcome'], 'live_capture':live['capture_status'],
                  'private':denied['outcome'], 'read_only':read_only,
                  'direct_blocked':direct_blocked, 'private_connect_denied':private_connect_denied,
                  'labels_hidden':not pathlib.Path(sys.argv[1]).exists(),
                  'head':(source/'.git/HEAD').read_text().strip(),
                  'git_global':os.environ['GIT_CONFIG_GLOBAL']}))
'''
    try:
        with backend.activate():
            result = run_command(["python3", "-c", script, str(labels)], cwd=source, timeout_seconds=120,
                                 env=build_env(), stdout_path=raw / "checks.json", stderr_path=raw / "checks.stderr")
        assert result.exit_code == 0, (raw / "checks.stderr").read_text()
        facts = json.loads((raw / "checks.json").read_text())
        assert facts == {"live": "ok", "live_capture": "preserved", "private": "denied",
                         "read_only": True, "direct_blocked": True, "private_connect_denied": True,
                         "labels_hidden": True, "head": snapshot.commit, "git_global": "/dev/null"}
        record = backend.isolation_record()
        assert record["network"]["enforced"] is True and record["enforced"] is True
        capture = record["retrieval"]
        assert capture["capture_status"] == "recorded" and capture["attempts"] == 2
        assert capture["denied"] == 1 and capture["preserved"] == 1
        assert capture["provider_retrieval"] == "unverifiable"
        assert capture["replayable"] is False
        events = [json.loads(line) for line in (raw / "retrieval-provenance/events.jsonl").read_text().splitlines()]
        assert all(event["content_entered_model"] is None for event in events)
        assert record["network"]["proxy"]["denied"] == 1
        assert all(item["removed"] for item in record["containers"])
    finally:
        assert backend.close() == []


def test_configured_runner_saves_and_revalidates_open_context_observation(scratch):
    config = pilot(scratch, [{"system_id": "research-fixture", "adapter": "script", "config": {},
        "execution": {"backend": "oci", "image": PYTHON_IMAGE, "proxy_image": PYTHON_IMAGE,
                      "egress": [{"host": "example.com", "port": 443}], "retrieval": RETRIEVAL}}],
        policy="public_research")
    declaration = json.loads(config.read_text())
    declaration["inputs"][0]["condition"] = CONDITION
    config.write_text(json.dumps(declaration))
    script = """
import json, os, urllib.request
request = urllib.request.Request(os.environ['SCANEVAL_RETRIEVAL_URL']+'/fetch',
    data=json.dumps({'url':'https://example.com/'}).encode(), headers={'Content-Type':'application/json'})
with urllib.request.urlopen(request, timeout=60) as response:
    result=json.load(response)
assert result['outcome']=='ok' and result['content_entered_model'] is None
print('Recorded benign retrieval fixture completed.')
"""
    out = scratch / "out"
    manifest = run_from_config(config, out, workspace_root=scratch / "work", adapters={"script": ScriptAdapter(script)})
    [row] = manifest["invocations"]
    assert row["status"] == "success", row
    bundle = out / row["bundle_path"]
    record = load_document(bundle / "condition.json", "condition-record")
    assert record["condition"] == "open_context" and record["status"] == "attested", record
    assert record["history"] == "bounded_ancestor_history" and record["retrieval"] == "recorded"
    assert record["provider_retrieval"] == "unverifiable"
    assert record["details"]["model_consumption"] == {"observed": 0, "unknown": 1}
    assert record["assurance"]["network"] == "external_enforcement"
    assert conditions.classify_observation(bundle) == record
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["condition"] == CONDITION
    assert execution["isolation"]["retrieval"]["attempts"] == 1
    assert manifest["inputs"][0]["condition"] == CONDITION
    schedule = load_document(out / "evaluator/schedule.json", "evaluation-schedule")
    assert schedule["inputs"][0]["condition"] == CONDITION
    (bundle / "raw/retrieval-provenance/events.jsonl").unlink()
    failed = conditions.classify_observation(bundle)
    assert failed["status"] == "failed"
    assert any(reason["code"] == "retrieval_artifact_mismatch" for reason in failed["reasons"])
