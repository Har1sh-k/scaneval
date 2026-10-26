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

from test_v2_isolation_docker import PYTHON_IMAGE, run_id, scratch, scratch_parent  # noqa: F401
from test_v2_open_context import history_fixture


RETRIEVAL = {"policy": "recorded_public_v1", "allowed_origins": ["https://example.com", "https://127.0.0.1"],
             "capture": "content", "retention": "bundle"}


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
