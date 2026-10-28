"""SV-Agent image runtime inside the real OCI boundary, with a synthetic model. DIAGNOSTIC ONLY.

Runs the real adapter, the real driver and the pinned upstream harness inside the pinned SV-Agent
image, under the oci backend with public_research and the open_context condition. The model is the
image's synthetic in-process Pi provider: it calls no model, and nothing here is scanner evidence or
a publishable approval of the route. What it does exercise is everything around the model: Pi's real
tool selection and extension loading, research through the recorded proxy (one public fetch, one
private destination denied), original ancestor history through the history tool with the later
commit absent, a read-only source, no host or evaluator path in the boundary, cleanup, and the
open-context classification of the saved bundle.

Requires a built image: set SCANEVAL_SV_IMAGE to its digest-pinned reference (name@sha256:... or
sha256:...). SCANEVAL_SV_PROXY_IMAGE names the proxy image (default: the pinned Python image the
other container tests use). Skipped when either is unavailable unless SCANEVAL_REQUIRE_DOCKER=1.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest

from scaneval import cases, conditions
from scaneval.adapters.llm_harness import SYNTHETIC_MODEL
from scaneval.contracts import canonical_json, load_document
from scaneval.runner import run_from_config


PYTHON_IMAGE = "python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"
SV_IMAGE = os.environ.get("SCANEVAL_SV_IMAGE", "")
PROXY_IMAGE = os.environ.get("SCANEVAL_SV_PROXY_IMAGE", PYTHON_IMAGE)
REQUIRED = os.environ.get("SCANEVAL_REQUIRE_DOCKER") == "1"
HARNESS_COMMIT = "f959cbcf010c7e41f780c718b65b1724d3aecb43"
CLOCK = lambda: datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)  # noqa: E731
RETRIEVAL = {"policy": "recorded_public_v1", "allowed_origins": ["https://example.com", "https://127.0.0.1"],
             "capture": "content", "retention": "bundle"}
CONDITION = {"name": "open_context", "policy": {"history": "ancestor_history_v1", "retrieval": "recorded_public_v1",
             "web_mode": "live", "capture": "content", "retention": "bundle"}}
VULNERABLE = ("import subprocess\n\n\ndef run(cmd):\n    # ancestor-visible fixture\n"
              "    return subprocess.run(cmd, shell=True)\n")


def _docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _problem() -> str | None:
    if not SV_IMAGE:
        return "SCANEVAL_SV_IMAGE does not name a built, digest-pinned SV-Agent image"
    if not shutil.which("docker"):
        return "the docker CLI is not installed"
    try:
        version = _docker("version", "--format", "{{.Server.Version}}", timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"the docker CLI could not reach an engine: {exc}"
    if version.returncode != 0:
        return "no Docker engine is reachable"
    missing = [image for image in (SV_IMAGE, PROXY_IMAGE) if _docker("image", "inspect", image, timeout=60).returncode]
    return f"image(s) not present locally: {', '.join(missing)}" if missing else None


PROBLEM = _problem()
if PROBLEM is not None:
    if REQUIRED:
        raise RuntimeError(f"SCANEVAL_REQUIRE_DOCKER=1 but {PROBLEM}")
    pytest.skip(PROBLEM, allow_module_level=True)

SCRATCH_PARENT = Path.home() / ".cache" / "scaneval-oci-tests"


@pytest.fixture
def scratch():
    """A scratch tree the daemon can see (under the home directory, for Colima), removed after."""
    SCRATCH_PARENT.mkdir(parents=True, exist_ok=True)
    root = SCRATCH_PARENT / f"sv{uuid.uuid4().hex[:10]}"
    root.mkdir()
    try:
        yield root
    finally:
        for listing, remove in ((["ps", "--all", "--quiet"], ["rm", "--force"]), (["network", "ls", "--quiet"], ["network", "rm"])):
            found = _docker(*listing, "--filter", f"label=scaneval.run=run-{root.name}").stdout.split()
            if found:
                _docker(*remove, *found)
        for directory, directories, _files in os.walk(root):
            for name in directories:
                try:
                    os.chmod(os.path.join(directory, name), 0o700)
                except OSError:
                    pass
        shutil.rmtree(root, ignore_errors=True)
        if root.exists():
            _docker("run", "--rm", "--network", "none", "--user", "0:0", "--mount", f"type=bind,src={root},dst={root}",
                    "--entrypoint", "rm", PYTHON_IMAGE, "-rf", *[str(root / name) for name in os.listdir(root)])
            shutil.rmtree(root, ignore_errors=True)


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
                               "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"}).stdout.strip()


def _config(scratch: Path, system: dict) -> Path:
    """A pack whose snapshot has two ancestors and one later commit the scan must never see."""
    upstream = scratch / "upstream"
    (upstream / "src").mkdir(parents=True)
    _git("init", "-q", "-b", "main", cwd=upstream)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=upstream)
    (upstream / "src" / "app.py").write_text("def run(cmd):\n    return cmd\n")
    _git("add", "-A", cwd=upstream)
    _git("commit", "-q", "-m", "ANCESTOR-ONE initial", cwd=upstream)
    (upstream / "src" / "app.py").write_text(VULNERABLE)
    _git("commit", "-q", "-am", "ANCESTOR-TWO shell runner", cwd=upstream)
    snapshot = _git("rev-parse", "HEAD", cwd=upstream)
    (upstream / "src" / "app.py").write_text("def run(cmd):\n    return None\n")
    _git("commit", "-q", "-am", "LATER-COMMIT-MUST-NOT-APPEAR fix", cwd=upstream)
    pack = cases.new_pack("test", "sv-oc", "Diagnostic SV-Agent open-context fixture.")
    cases.add_snapshot(pack, {
        "snapshot_id": "snap-a", "repository": {"url": str(upstream), "name": "widget"}, "commit": snapshot,
        "reference": "Fixture commit; no advisory is claimed.", "languages": ["python"],
        "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}})
    cases.add_case(pack, cases.draft_case(
        "case-a", snapshot_id="snap-a", kind="command_injection",
        description="Caller-controlled command string reaches subprocess with shell=True.",
        represents="Diagnostic fixture for the SV-Agent image route; not a detection benchmark.",
        workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                 reference="src/app.py", note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "src/app.py", "start_line": 6, "end_line": 6, "role": "sink", "note": ""}]))
    cases.save_pack(scratch / "pack.json", pack)
    config = {"schema_version": "2.1", "run_id": f"run-{scratch.name}", "pack": "pack.json", "cache_root": "cache",
              "inputs": [{"snapshot_id": "snap-a", "condition": CONDITION}], "systems": [system], "repetitions": 1,
              "timeout_seconds": 1800, "trace_mode": "content", "network_policy": "public_research"}
    path = scratch / "run-config.json"
    path.write_text(canonical_json(config) + "\n", encoding="utf-8")
    (scratch / "work").mkdir()
    return path


def _system(config: dict, **execution) -> dict:
    return {"system_id": "sv-agent-image", "adapter": "llm-harness",
            "config": {"harness": "securevibes-agent", "runtime": "oci_image", "expected_harness_commit": HARNESS_COMMIT,
                       **config},
            "execution": {"backend": "oci", "image": SV_IMAGE, "proxy_image": PROXY_IMAGE,
                          "egress": [{"host": "example.com", "port": 443}], "retrieval": RETRIEVAL, **execution}}


def test_synthetic_image_run_researches_reads_ancestor_history_and_attests_open_context(scratch):
    calls = [{"name": "scaneval_git", "arguments": {"op": "log", "max_count": 50}},
             {"name": "scaneval_fetch", "arguments": {"url": "https://example.com/"}},
             {"name": "scaneval_fetch", "arguments": {"url": "https://127.0.0.1/metadata"}},
             {"name": "scaneval_read", "arguments": {"path": "../../evaluator"}},
             {"name": "bash", "arguments": {"command": "id"}}]
    config = _config(scratch, _system({"model": SYNTHETIC_MODEL, "synthetic_tool_calls": calls,
                                       "capture_pi_sessions": True, "llm_max_files": 2}))
    out = scratch / "out"
    manifest = run_from_config(config, out, workspace_root=scratch / "work", clock=CLOCK)
    [row] = manifest["invocations"]
    bundle = out / row["bundle_path"]
    execution = load_document(bundle / "execution.json", "execution-record")
    result = load_document(bundle / "result.json", "scan-result")
    assert row["status"] == "success", (result.get("error"), result.get("notes"))
    assert any("DIAGNOSTIC: synthetic" in note for note in result["notes"])
    assert execution["model_identity"]["verification"] == "not_applicable"
    output = json.loads((bundle / "raw" / "driver-output.json").read_text())
    assert output["runtime"]["receipt"] is not None and output["runtime"]["pi_version"]
    assert output["observed_routes"] == ["pi-oci"]
    calls_seen = output["pi_calls"]
    assert calls_seen["calls"] >= 1
    assert calls_seen["tool_executions"]["scaneval_git"]["ok"] >= 1
    assert calls_seen["tool_executions"]["scaneval_fetch"]["ok"] >= 1
    assert calls_seen["tool_executions"]["scaneval_fetch"]["error"] >= 1  # the private destination
    assert calls_seen["tool_executions"]["scaneval_read"]["error"] >= 1  # outside the repository
    assert calls_seen["tool_executions"].get("bash", {"ok": 0})["ok"] == 0  # never declared
    # Original ancestry is visible to the model through the history tool; the later commit is not.
    sessions = "\n".join(path.read_text(errors="replace") for path in (bundle / "raw" / "pi-sessions").rglob("*.jsonl"))
    assert "ANCESTOR-TWO shell runner" in sessions and "ANCESTOR-ONE initial" in sessions
    assert "LATER-COMMIT-MUST-NOT-APPEAR" not in sessions
    # The boundary: read-only unmodified source, no host or evaluator path mounted, everything removed.
    assert execution["provenance"]["source_modified"] is False
    isolation = execution["isolation"]
    targets = [mount["target"] for mount in isolation["mounts"]]
    assert not any(str(out) in target or target in ("~", "/") for target in targets)
    assert {mount["mode"] for mount in isolation["mounts"] if mount["role"] == "source"} == {"ro"}
    assert all(item["removed"] for item in isolation["containers"])
    assert isolation["retrieval"]["denied"] >= 1 and isolation["retrieval"]["capture_status"] == "recorded"
    record = load_document(bundle / "condition.json", "condition-record")
    assert record["condition"] == "open_context" and record["status"] == "attested", record["reasons"]
    assert record["history"] == "bounded_ancestor_history" and record["retrieval"] == "recorded"
    assert record["provider_retrieval"] == "unverifiable"
    assert record["details"]["model_consumption"]["observed"] == 0
    assert conditions.classify_observation(bundle) == record
    assert not _docker("ps", "--all", "--quiet", "--filter", f"label=scaneval.run=run-{scratch.name}").stdout.split()


def test_a_real_route_without_its_credential_is_refused_before_any_scanner_container(scratch, monkeypatch):
    monkeypatch.delenv("SV_AGENT_PI_AUTH_JSON", raising=False)
    config = _config(scratch, _system({"model": "openai-codex/gpt-5.6-sol"},
                                      credentials=[{"env": "SV_AGENT_PI_AUTH_JSON", "provider": "openai-codex"}],
                                      egress=[{"host": "chatgpt.com", "port": 443}]))
    out = scratch / "out"
    manifest = run_from_config(config, out, workspace_root=scratch / "work", clock=CLOCK)
    [row] = manifest["invocations"]
    bundle = out / row["bundle_path"]
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and "SV_AGENT_PI_AUTH_JSON is not set" in result["error"]["message"]
    assert not [item for item in execution["isolation"]["containers"] if item["role"] == "worker"]
