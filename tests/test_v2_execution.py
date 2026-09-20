"""Invocation bundles: explicit status, preserved raw output, provenance, and no silent successes."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from sastbench.adapters import get_adapter
from sastbench.adapters.base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command
from sastbench.adapters.semgrep import SemgrepAdapter, import_semgrep_results
from sastbench.contracts import ContractError, load_document, validate_document
from sastbench.execution import ExecutionError, PreparedInput, invocation_id, run_invocation
from sastbench.materialize import hash_exported_tree


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731


def prepared_input(tmp_path: Path, *, languages=("python",)) -> PreparedInput:
    source = tmp_path / "trial" / "source"
    source.mkdir(parents=True)
    (source / "app.py").write_text("import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    (source / "README.md").write_text("demo\n", encoding="utf-8")
    digest = hash_exported_tree(source)["tree_hash"]
    return PreparedInput("input-a", source, digest, tuple(languages), {"source": {"commit": "x"}})


class FakeAdapter(Adapter):
    name = "fake"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})
    state_dirs = (".fakestate",)

    def __init__(self, behavior: str = "success", requires_git: bool = False):
        self.behavior = behavior
        self.requires_git = requires_git
        self.calls = 0

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        self.calls += 1
        native = raw_dir / "native.json"
        native.write_text('{"findings": [{"file": "app.py"}]}\n', encoding="utf-8")
        (source_dir / ".fakestate").mkdir()
        (source_dir / ".fakestate" / "notes.md").write_text("harness state\n", encoding="utf-8")
        if self.behavior == "raise":
            raise AdapterError("binary exploded")
        if self.behavior == "modify":
            (source_dir / "app.py").write_text("changed by scanner\n", encoding="utf-8")
        if self.behavior == "git":
            assert (source_dir / ".git").exists()
        claims = [{"claim_id": "c1", "allegation": "shell=True with caller-controlled cmd", "kind": "command_injection",
                   "primary_location": {"path": "app.py", "start_line": 3, "end_line": 3},
                   "native_rule_id": "fake.rule", "raw_artifact_id": "native"}]
        if self.behavior == "bad-claim":
            claims[0]["primary_location"]["path"] = "/etc/passwd"
        if self.behavior == "timeout":
            result = run_command([sys.executable, "-c", "import time; time.sleep(30)"], cwd=source_dir,
                                 timeout_seconds=0.5, env=build_env(), stdout_path=raw_dir / "out.txt",
                                 stderr_path=raw_dir / "err.txt")
            assert result.timed_out and result.exit_code is None
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True, command=result.argv,
                                 error={"code": "timeout", "message": "killed"},
                                 artifacts=[{"id": "native", "path": native}])
        return NativeOutcome(status="success", exit_code=0, command=["fake", "scan"], claims=claims,
                             artifacts=[{"id": "native", "path": native}, {"id": "missing", "path": raw_dir / "nope"}],
                             tool_versions={"fake": "1"}, usage={"cost_usd": None, "setup_seconds": 2},
                             capture={"model_requests": "unavailable"}, notes=["fake run"])


def run(tmp_path: Path, adapter: FakeAdapter, prepared: PreparedInput | None = None, **kwargs) -> Path:
    prepared = prepared or prepared_input(tmp_path)
    return run_invocation(prepared=prepared, adapter=adapter, spec=SystemSpec("fake-sys", "fake", {"knob": 1}),
                          preparation={"ruleset": "none"}, out_dir=tmp_path / "out", run_id="run-1", clock=CLOCK, **kwargs)


def test_successful_invocation_writes_validated_bundle_and_captures_state(tmp_path):
    adapter = FakeAdapter()
    bundle = run(tmp_path, adapter)
    assert bundle.name == invocation_id("input-a", "fake-sys", 1) == "input-a__fake-sys__r1"
    request = load_document(bundle / "request.json", "scan-request")
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert request["input"]["tree_hash"] == result["input_hash"] == execution["provenance"]["tree_hash"]
    assert "targets" not in json.dumps(request)
    assert result["status"] == "success" and result["claims"][0]["kind"] == "command_injection"
    assert result["usage"]["cost_usd"] is None and result["usage"]["setup_seconds"] == 2
    assert result["raw_artifacts"] == [{"id": "native", "path": "raw/native.json", "sha256": execution["raw_artifacts"][0]["sha256"]}]
    assert (bundle / "raw" / "harness-state" / "fakestate" / "notes.md").read_text(encoding="utf-8") == "harness state\n"
    assert execution["provenance"]["captured_state_dirs"] == [".fakestate"]
    assert execution["provenance"]["source_modified"] is False and execution["provenance"]["synthetic_history"] is None
    assert execution["started_at"] == "2026-09-20T15:00:00+00:00"
    assert execution["network_policy"] == {"declared": "none", "enforced": False,
                                           "note": "Policy is recorded, not enforced by this runner; enforce it in the execution environment."}
    assert "declared artifact missing: missing" in execution["notes"]
    assert execution["system_config"] == {"knob": 1} and execution["versions"]["kind_mapping"] == "1.0.0"
    assert not list(Path(tmp_path).glob("sastbench-trial-*"))
    with pytest.raises(FileExistsError):
        run(tmp_path, adapter)


def test_scanner_edits_to_source_are_detected(tmp_path):
    bundle = run(tmp_path, FakeAdapter("modify"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert execution["provenance"]["source_modified"] is True
    assert execution["provenance"]["modified_paths"] == ["app.py"]


def test_unsupported_language_is_not_executed_and_stays_visible(tmp_path):
    adapter = FakeAdapter()
    bundle = run(tmp_path, adapter, prepared_input(tmp_path, languages=("python", "rust")))
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    assert adapter.calls == 0
    assert result["status"] == "unsupported" and result["error"]["code"] == "unsupported_language"
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert execution["unsupported_languages"] == ["rust"]


def test_adapter_failure_and_contract_violation_never_become_empty_success(tmp_path):
    bundle = run(tmp_path, FakeAdapter("raise"))
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "error" and result["error"] == {"code": "adapter_failure", "message": "binary exploded"}
    assert (bundle / "raw" / "native.json").exists()

    bundle = run(tmp_path / "second", FakeAdapter("bad-claim"))
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "import_contract_violation"
    assert "relative path" in execution["import_error"]
    assert execution["raw_artifacts"][0]["path"] == "raw/native.json"


def test_timeout_is_recorded_as_timeout_with_partial_artifacts(tmp_path):
    bundle = run(tmp_path, FakeAdapter("timeout"), timeout_seconds=5)
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert result["status"] == "timeout" and execution["timed_out"] is True
    assert execution["exit_code"] is None and result["raw_artifacts"][0]["id"] == "native"


def test_git_dependent_adapter_gets_synthetic_history_without_changing_tree_hash(tmp_path):
    bundle = run(tmp_path, FakeAdapter("git", requires_git=True))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    history = execution["provenance"]["synthetic_history"]
    assert history["message"] == "snapshot" and len(history["commit"]) == 40
    assert execution["provenance"]["source_modified"] is False


def test_workspace_hash_mismatch_and_bad_policies_are_rejected(tmp_path):
    prepared = prepared_input(tmp_path)
    wrong = PreparedInput(prepared.input_id, prepared.source_dir, "sha256:" + "0" * 64, prepared.languages, {})
    with pytest.raises(ExecutionError, match="does not match"):
        run(tmp_path, FakeAdapter(), wrong)
    with pytest.raises(ExecutionError, match="network policy"):
        run(tmp_path / "b", FakeAdapter(), network_policy="lan")
    with pytest.raises(ExecutionError, match="trace mode"):
        run(tmp_path / "c", FakeAdapter(), trace_mode="verbose")


def test_execution_record_contract_rejects_inconsistent_timeout_and_escaping_paths():
    execution = {
        "schema_version": "2.0", "run_id": "r", "invocation_id": "i", "input_id": "a", "system_id": "s", "repetition": 1,
        "adapter": {"name": "x", "version": "1"}, "versions": {}, "status": "timeout", "exit_code": None,
        "timed_out": False, "command": [], "started_at": "t", "finished_at": "t", "wall_seconds": 1, "timeout_seconds": 5,
        "tool_versions": {}, "model_identity": None, "system_config": {},
        "network_policy": {"declared": "none", "enforced": False, "note": ""}, "environment": {"passthrough": []},
        "capture": {}, "trace": None,
        "provenance": {"tree_hash": "sha256:" + "a" * 64, "provenance_sha256": "sha256:" + "b" * 64, "profile": "standard",
                       "synthetic_history": None, "source_modified": False, "modified_paths": [], "captured_state_dirs": []},
        "preparation": {}, "unsupported_languages": [], "error": None, "import_error": None, "notes": [],
        "raw_artifacts": [],
    }
    with pytest.raises(ContractError, match="timed_out"):
        validate_document("execution-record", execution)
    execution["timed_out"] = True
    validate_document("execution-record", execution)
    execution["raw_artifacts"] = [{"id": "x", "path": "../raw/x", "sha256": "sha256:" + "c" * 64}]
    with pytest.raises(ContractError, match="relative path"):
        validate_document("execution-record", execution)


def test_semgrep_import_preserves_native_identity_and_never_invents_evidence():
    payload = {"results": [
        {"check_id": "python.lang.security.audit.subprocess-shell-true", "path": "./src/app.py",
         "start": {"line": 3, "col": 1}, "end": {"line": 4, "col": 2},
         "extra": {"message": "shell=True is dangerous", "severity": "WARNING", "fingerprint": "requires login",
                   "lines": "requires login", "metadata": {"cwe": ["CWE-78: OS Command Injection", "CWE-78"]}}},
        {"check_id": "custom.rule", "path": "lib/x.py", "start": {"line": 9, "col": 1}, "end": {"line": 8, "col": 1},
         "extra": {"message": "", "fingerprint": "abc123", "lines": "x = eval(y)", "metadata": {"cwe": "CWE-95: Eval"}}},
    ]}
    claims, notes = import_semgrep_results(payload, config_dirs=["/tmp/cache/rules__abc/python"])
    payload["results"][0]["check_id"] = "tmp.cache.rules__abc.python.python.lang.security.audit.subprocess-shell-true"
    claims, notes = import_semgrep_results(payload, config_dirs=["/tmp/cache/rules__abc/python"])
    assert claims[0] == {"claim_id": "c1", "allegation": "shell=True is dangerous", "kind": "command_injection",
                         "primary_location": {"path": "src/app.py", "start_line": 3, "end_line": 4},
                         "native_rule_id": "python.lang.security.audit.subprocess-shell-true",
                         "raw_artifact_id": "semgrep-json", "native_severity": "WARNING", "native_cwe": ["CWE-78"]}
    assert claims[1]["kind"] == "unmapped" and claims[1]["allegation"] == "custom.rule"
    assert claims[1]["native_id"] == "abc123" and claims[1]["evidence_text"] == "x = eval(y)"
    assert claims[1]["primary_location"] == {"path": "lib/x.py", "start_line": 9, "end_line": 9}
    assert claims[1]["native_cwe"] == ["CWE-95"]
    assert any("requires login" in note for note in notes)
    with pytest.raises(AdapterError):
        import_semgrep_results({"errors": []})


def test_semgrep_prepare_refuses_registry_configs(tmp_path):
    adapter = SemgrepAdapter()
    with pytest.raises(AdapterError, match="registry"):
        adapter.prepare(SystemSpec("s", "semgrep", {"ruleset": {"url": "x", "commit": "a" * 40, "paths": ["p/python"]}}), tmp_path)
    with pytest.raises(AdapterError, match="pinned rules checkout"):
        adapter.prepare(SystemSpec("s", "semgrep", {}), tmp_path)


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
                               "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"}).stdout.strip()


@pytest.mark.skipif(not (Path(sys.executable).with_name("semgrep").exists() or shutil.which("semgrep")),
                    reason="semgrep binary not installed")
def test_semgrep_adapter_runs_pinned_local_ruleset_end_to_end(tmp_path):
    rules = tmp_path / "rules-repo"
    (rules / "python").mkdir(parents=True)
    (rules / "python" / "shell.yaml").write_text(
        "rules:\n  - id: probe.subprocess-shell\n    languages: [python]\n    severity: WARNING\n"
        "    message: subprocess call with shell=True\n    metadata:\n      cwe:\n        - 'CWE-78: OS Command Injection'\n"
        "    patterns:\n      - pattern: subprocess.$F(..., shell=True, ...)\n", encoding="utf-8")
    _git("init", "-q", "-b", "main", cwd=rules)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=rules)
    _git("add", "-A", cwd=rules)
    _git("commit", "-q", "-m", "rules", cwd=rules)
    commit = _git("rev-parse", "HEAD", cwd=rules)

    adapter = get_adapter("semgrep")
    spec = SystemSpec("semgrep-pinned", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    preparation = adapter.prepare(spec, tmp_path / "cache")
    assert preparation["ruleset"]["rule_files"] == 1 and preparation["ruleset"]["commit"] == commit
    bundle = run_invocation(prepared=prepared_input(tmp_path), adapter=adapter, spec=spec, preparation=preparation,
                            out_dir=tmp_path / "out", run_id="run-semgrep", timeout_seconds=300, clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success" and result["ranking"] == "unranked"
    assert [c["primary_location"] for c in result["claims"]] == [{"path": "app.py", "start_line": 3, "end_line": 3}]
    assert result["claims"][0]["kind"] == "command_injection" and result["claims"][0]["native_rule_id"] == "probe.subprocess-shell"
    assert result["usage"]["cost_usd"] == 0.0
    assert execution["tool_versions"]["semgrep"] == execution["tool_versions"]["semgrep_reported"]
    assert execution["tool_versions"]["ruleset_commit"] == commit
    assert "--metrics=off" in execution["command"] and not any(a.startswith("p/") for a in execution["command"])
    assert (bundle / "raw" / "semgrep.json").exists()
    assert execution["capture"]["model_requests"] == "not_applicable"
