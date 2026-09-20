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
from sastbench.execution import ExecutionError, PreparedInput, _write_new, invocation_id, run_invocation
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
        if self.behavior == "crash":
            raise RuntimeError("the harness died mid scan")
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
    assert result["status"] == "error"
    assert result["error"] == {"code": "adapter_failure", "message": "AdapterError: binary exploded"}
    assert (bundle / "raw" / "native.json").exists()

    bundle = run(tmp_path / "second", FakeAdapter("bad-claim"))
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "import_contract_violation"
    assert "relative path" in execution["import_error"]
    assert execution["raw_artifacts"][0]["path"] == "raw/native.json"


def test_an_unexpected_adapter_exception_is_an_error_with_its_raw_directory_preserved(tmp_path):
    """A crash that is not an AdapterError is still a recorded error, never a lost invocation."""
    bundle = run(tmp_path, FakeAdapter("crash"))

    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"] == {"code": "adapter_failure",
                               "message": "RuntimeError: the harness died mid scan"}
    assert execution["status"] == "error" and execution["error"] == result["error"]
    # The raw output the adapter had already written is staged out of the workspace anyway.
    assert (bundle / "raw" / "native.json").read_text(encoding="utf-8").startswith('{"findings"')
    assert (bundle / "raw" / "harness-state" / "fakestate" / "notes.md").is_file()


def test_no_path_handed_to_the_adapter_is_inside_the_run_directory(tmp_path):
    """raw/ and trace/ are staged in the private workspace and moved into the bundle after scan."""
    seen: dict[str, Path] = {}

    class RecordingAdapter(FakeAdapter):
        def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds,
                 trace_mode, trace_dir):
            seen.update({"source_dir": Path(source_dir), "raw_dir": Path(raw_dir),
                         "trace_dir": Path(trace_dir)})
            (trace_dir / "events.jsonl").write_text('{"type":"model_request"}\n', encoding="utf-8")
            outcome = super().scan(request=request, source_dir=source_dir, raw_dir=raw_dir, spec=spec,
                                   preparation=preparation, timeout_seconds=timeout_seconds,
                                   trace_mode=trace_mode, trace_dir=trace_dir)
            outcome.trace_path = trace_dir / "events.jsonl"
            return outcome

    out = (tmp_path / "out").resolve()
    bundle = run(tmp_path, RecordingAdapter(), trace_mode="metadata")

    assert set(seen) == {"source_dir", "raw_dir", "trace_dir"}
    for name, path in seen.items():
        assert not path.resolve().is_relative_to(out), f"{name} was handed inside the run directory"
        assert not path.exists(), f"{name} outlived the private workspace"

    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert result["raw_artifacts"][0]["path"] == "raw/native.json"
    assert (bundle / "raw" / "native.json").is_file()
    assert execution["trace"]["path"] == "trace/events.jsonl" and execution["trace"]["events"] == 1
    assert (bundle / "trace" / "events.jsonl").is_file()


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


class OutcomeAdapter(FakeAdapter):
    """Writes real raw output, then hands back whatever *mutate* makes of the outcome."""

    def __init__(self, mutate):
        super().__init__()
        self.mutate = mutate

    def scan(self, **kwargs):
        return self.mutate(super().scan(**kwargs))


def _with(outcome: NativeOutcome, **fields) -> NativeOutcome:
    for name, value in fields.items():
        setattr(outcome, name, value)
    return outcome


@pytest.mark.parametrize(
    ("mutate", "fragment"),
    [
        (lambda outcome: _with(outcome, tool_versions={"fake": 1.0}), "tool_versions['fake'] must be a string, not float"),
        (lambda outcome: _with(outcome, command=[Path("/bin/fake"), "scan"]), "command[0] must be a string, not"),
        (lambda outcome: {"status": "success", "claims": []}, "adapter returned dict, not a NativeOutcome"),
        (lambda outcome: _with(outcome, artifacts=[{"id": 7, "path": "raw/native.json"}]), "artifacts[0].id must be a non-empty string"),
        (lambda outcome: _with(outcome, usage={"cost_usd": "free"}), "usage['cost_usd'] must be a number, not str"),
        (lambda outcome: _with(outcome, notes=[object()]), "notes[0] must be a string, not object"),
    ],
    ids=["float-version", "path-in-command", "dict-outcome", "artifact-id", "usage-string", "note-object"],
)
def test_an_outcome_that_breaks_the_adapter_contract_is_a_recorded_error(tmp_path, mutate, fragment):
    """An outcome this module cannot read is an error bundle, never a success with fields dropped."""
    bundle = run(tmp_path, OutcomeAdapter(mutate))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "outcome_contract_violation"
    assert fragment in result["error"]["message"]
    assert "raw_artifacts" not in result and result["usage"]["cost_usd"] is None
    assert execution["status"] == "error" and execution["error"] == result["error"]
    assert execution["command"] == [] and execution["tool_versions"] == {} and execution["raw_artifacts"] == []
    assert execution["import_error"] is None
    assert execution["notes"] == [f"The adapter outcome was discarded: {execution['error']['message']}"]
    # The scanner's own output is still preserved: only the outcome it reported was discarded.
    assert (bundle / "raw" / "native.json").read_text(encoding="utf-8").startswith('{"findings"')
    assert (bundle / "raw" / "harness-state" / "fakestate" / "notes.md").is_file()


def test_a_trace_file_that_is_not_utf8_is_recorded_as_a_failure_not_an_invented_count(tmp_path):
    """A count taken from bytes this cannot decode would be a number nothing observed."""

    class BadTraceAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            events = kwargs["trace_dir"] / "events.jsonl"
            events.write_bytes(b'{"type":"model_request"}\n\xff\xfe\n')
            outcome.trace_path = events
            return outcome

    bundle = run(tmp_path, BadTraceAdapter(), trace_mode="metadata")

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["error"]["code"] == "outcome_contract_violation"
    assert "trace file could not be read as UTF-8 text" in result["error"]["message"]
    assert "UnicodeDecodeError" in result["error"]["message"]
    assert execution["trace"] == {"path": None, "events": None, "mode": "metadata",
                                  "capture_gap": None, "dropped_events": None}
    # The undecodable file itself is kept exactly as the adapter wrote it.
    assert (bundle / "trace" / "events.jsonl").read_bytes().endswith(b"\xff\xfe\n")


def test_an_execution_record_the_contract_refuses_never_leaves_a_successful_result(tmp_path):
    """The two documents are written together, so result.json cannot outlive a refused record."""

    class OddCaptureAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            outcome.capture = {"model_requests": "sometimes"}
            return outcome

    bundle = run(tmp_path, OddCaptureAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "outcome_contract_violation"
    assert "execution record violates its contract" in result["error"]["message"]
    assert "sometimes" in result["error"]["message"]
    assert execution["capture"] == {} and execution["error"] == result["error"]
    assert (bundle / "raw" / "native.json").is_file()


def test_writing_a_document_canonical_json_cannot_represent_creates_no_file(tmp_path):
    """The serialization must fail before the file exists; an empty file would read as a record."""
    path = tmp_path / "result.json"

    with pytest.raises(ContractError, match="not canonical JSON"):
        _write_new(path, {"claims": {"c1"}})

    assert not path.exists()


def test_a_scanner_gets_an_export_for_source_while_a_ruleset_path_may_be_in_the_cache(tmp_path):
    """The narrowed boundary: no cache path for evaluated source, adapter rulesets excepted."""
    cache_rules = tmp_path / "cache" / "rules__abc" / "python"
    cache_rules.mkdir(parents=True)
    seen: dict[str, Path] = {}

    class RulesetAdapter(FakeAdapter):
        def scan(self, **kwargs):
            seen["source_dir"] = Path(kwargs["source_dir"])
            seen["config_dir"] = Path(kwargs["preparation"]["config_dirs"][0])
            return super().scan(**kwargs)

    prepared = prepared_input(tmp_path)
    bundle = run_invocation(prepared=prepared, adapter=RulesetAdapter(), spec=SystemSpec("s", "fake", {}),
                            preparation={"config_dirs": [str(cache_rules)]}, out_dir=tmp_path / "out",
                            run_id="run-1", clock=CLOCK)

    assert not seen["source_dir"].is_relative_to(tmp_path / "cache")
    assert not seen["source_dir"].is_relative_to(prepared.source_dir)
    assert seen["config_dir"].is_relative_to(tmp_path / "cache")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["preparation"] == {"config_dirs": [str(cache_rules)]}


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


def pinned_rules_repo(tmp_path: Path) -> tuple[Path, str]:
    """A tiny git repository holding one pinned Semgrep rule, as an offline ruleset source."""
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
    return rules, _git("rev-parse", "HEAD", cwd=rules)


semgrep_required = pytest.mark.skipif(
    not (Path(sys.executable).with_name("semgrep").exists() or shutil.which("semgrep")),
    reason="semgrep binary not installed")


@semgrep_required
def test_semgrep_adapter_runs_pinned_local_ruleset_end_to_end(tmp_path):
    rules, commit = pinned_rules_repo(tmp_path)
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
    assert result["claims"][0]["kind"] == "command_injection"
    # The rule is declared as probe.subprocess-shell in python/, so the ruleset-relative id
    # keeps that directory; only the cache path is stripped.
    assert result["claims"][0]["native_rule_id"] == "python.probe.subprocess-shell"
    assert result["usage"]["cost_usd"] == 0.0
    assert execution["tool_versions"]["semgrep"] == execution["tool_versions"]["semgrep_reported"]
    assert execution["tool_versions"]["ruleset_commit"] == commit
    assert "--metrics=off" in execution["command"] and not any(a.startswith("p/") for a in execution["command"])
    assert (bundle / "raw" / "semgrep.json").exists()
    assert execution["capture"]["model_requests"] == "not_applicable"


@semgrep_required
def test_semgrep_prepare_resolves_config_dirs_against_a_relative_cache_root(tmp_path, monkeypatch):
    # scan() runs semgrep inside a private workspace, so a config path recorded relative to the
    # controller's working directory would not exist there: semgrep would exit nonzero having
    # scanned nothing. Preparation must record absolute config directories.
    rules, commit = pinned_rules_repo(tmp_path)
    prepared = prepared_input(tmp_path)
    monkeypatch.chdir(tmp_path)
    adapter = get_adapter("semgrep")
    spec = SystemSpec("semgrep-relcache", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    preparation = adapter.prepare(spec, Path("cache"))

    assert preparation["config_dirs"], "preparation recorded no config directories"
    assert all(Path(directory).is_absolute() for directory in preparation["config_dirs"])
    assert preparation["ruleset"]["rule_files"] == 1

    bundle = run_invocation(prepared=prepared, adapter=adapter, spec=spec, preparation=preparation,
                            out_dir=tmp_path / "out", run_id="run-relcache", timeout_seconds=300, clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success" and "error" not in result
    assert [c["primary_location"] for c in result["claims"]] == [{"path": "app.py", "start_line": 3, "end_line": 3}]
    assert result["claims"][0]["native_rule_id"] == "python.probe.subprocess-shell"
    assert all(not arg.startswith("--config=.") for arg in execution["command"] if arg.startswith("--config="))


def fake_semgrep(tmp_path: Path, payload: dict, exit_code: int) -> Path:
    """A stand-in binary that answers ``--version`` and then prints *payload* and exits *exit_code*."""
    script = tmp_path / "fake-semgrep"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        "if '--version' in sys.argv:\n"
        "    print('9.9.9')\n"
        "    raise SystemExit(0)\n"
        f"print(json.dumps({payload!r}))\n"
        f"raise SystemExit({exit_code})\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def _scan_with_fake(tmp_path: Path, payload: dict, exit_code: int):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("import subprocess\n", encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    spec = SystemSpec("semgrep-fake", "semgrep", {"binary": str(fake_semgrep(tmp_path, payload, exit_code))})
    preparation = {"ruleset": {"commit": "a" * 40, "tree_hash": "sha256:" + "b" * 64},
                   "config_dirs": [str(tmp_path / "rules" / "python")],
                   "ruleset_root": str(tmp_path / "rules")}
    outcome = SemgrepAdapter().scan(request={}, source_dir=source, raw_dir=raw, spec=spec, preparation=preparation,
                                    timeout_seconds=60, trace_mode="off", trace_dir=None)
    return outcome, raw


def test_semgrep_nonzero_exit_with_nothing_scanned_is_an_error_not_partial(tmp_path):
    payload = {"version": "9.9.9", "results": [], "paths": {"scanned": []},
               "errors": [{"level": "error", "code": 7,
                           "message": "unable to find a config; path `rules/python` does not exist"}]}
    outcome, raw = _scan_with_fake(tmp_path, payload, 7)
    assert outcome.status == "error"
    assert outcome.exit_code == 7 and outcome.error["code"] == "exit_7"
    assert "unable to find a config" in outcome.error["message"]
    assert outcome.claims == []
    # --quiet leaves stderr empty, so the raw JSON is the only record of why the run failed.
    assert (raw / "semgrep.json").exists()
    assert json.loads((raw / "semgrep.json").read_text(encoding="utf-8"))["errors"][0]["level"] == "error"
    assert [artifact["id"] for artifact in outcome.artifacts] == ["semgrep-json", "semgrep-stderr"]


def test_semgrep_nonzero_exit_after_scanning_paths_stays_partial(tmp_path):
    payload = {"version": "9.9.9", "paths": {"scanned": ["app.py"]},
               "errors": [{"level": "error", "message": "Rule timeout on app.py"}],
               "results": [{"check_id": "probe.rule", "path": "app.py", "start": {"line": 1}, "end": {"line": 1},
                            "extra": {"message": "finding", "severity": "WARNING", "metadata": {}}}]}
    outcome, _ = _scan_with_fake(tmp_path, payload, 7)
    assert outcome.status == "partial"
    assert outcome.exit_code == 7 and outcome.error["code"] == "exit_7"
    assert "Rule timeout" in outcome.error["message"]
    assert [claim["native_rule_id"] for claim in outcome.claims] == ["probe.rule"]


def test_semgrep_import_keeps_the_rule_id_relative_to_the_pinned_ruleset_root():
    # semgrep-rules declares this rule as `shared-url-struct-mutation` in go/lang/security/,
    # and semgrep prefixes check_id with the config path it was given. Stripping only the
    # checkout root keeps the ruleset-relative id; stripping each config directory would drop
    # the language and category segments and collide with same-named rules in other languages.
    payload = {"results": [
        {"check_id": "Users.x.cache.rules__abc.go.lang.security.shared-url-struct-mutation",
         "path": "pkg/proxy.go", "start": {"line": 12, "col": 1}, "end": {"line": 12, "col": 40},
         "extra": {"message": "shared url struct mutated", "severity": "ERROR", "metadata": {}}},
    ]}
    claims, _ = import_semgrep_results(payload, ruleset_roots=["/Users/x/cache/rules__abc"])
    assert claims[0]["native_rule_id"] == "go.lang.security.shared-url-struct-mutation"
    # The machine path is still absent, which is the property the config_dirs behavior had.
    assert "Users" not in claims[0]["native_rule_id"] and "cache" not in claims[0]["native_rule_id"]

    # A supplied root wins over config_dirs; config_dirs alone keeps its older, narrower behavior.
    claims, _ = import_semgrep_results(payload, ruleset_roots=["/Users/x/cache/rules__abc"],
                                       config_dirs=["/Users/x/cache/rules__abc/go"])
    assert claims[0]["native_rule_id"] == "go.lang.security.shared-url-struct-mutation"
    claims, _ = import_semgrep_results(payload, config_dirs=["/Users/x/cache/rules__abc/go"])
    assert claims[0]["native_rule_id"] == "lang.security.shared-url-struct-mutation"


def test_semgrep_prepare_records_the_ruleset_root_covering_every_config_dir(tmp_path):
    rules, commit = pinned_rules_repo(tmp_path)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    preparation = SemgrepAdapter().prepare(spec, tmp_path / "cache")
    root = preparation["ruleset_root"]
    assert Path(root).is_absolute() and Path(root).resolve() == Path(root)
    assert (Path(root) / "python" / "shell.yaml").is_file()
    assert preparation["config_dirs"] == [str(Path(root) / "python")]
    assert all(directory.startswith(root + os.sep) for directory in preparation["config_dirs"])


def test_semgrep_scan_shortens_rule_ids_against_the_recorded_ruleset_root(tmp_path):
    # The fake binary reports the check_id semgrep would build for a rule declared in
    # <root>/python/, so scan() must hand the importer the recorded root, not the config dirs.
    dotted_root = str(tmp_path / "rules").replace("\\", "/").strip("/").replace("/", ".")
    payload = {"version": "9.9.9", "paths": {"scanned": ["app.py"]}, "errors": [],
               "results": [{"check_id": f"{dotted_root}.python.probe.subprocess-shell", "path": "app.py",
                            "start": {"line": 1}, "end": {"line": 1},
                            "extra": {"message": "shell=True", "severity": "WARNING", "metadata": {}}}]}
    outcome, _ = _scan_with_fake(tmp_path, payload, 0)
    assert outcome.status == "success"
    assert [claim["native_rule_id"] for claim in outcome.claims] == ["python.probe.subprocess-shell"]


def test_semgrep_zero_exit_with_fatal_diagnostics_and_nothing_scanned_is_an_error(tmp_path):
    # Semgrep can exit 0 while every target failed to parse or be reached. Nothing was scanned
    # and nothing was reported, so this observed no source at all: silence here is missing
    # evidence, not a quiet negative control.
    payload = {"version": "9.9.9", "results": [], "paths": {"scanned": []},
               "errors": [{"level": "error", "code": 3, "message": "Invalid rule schema in go/lang.yaml"}]}
    outcome, raw = _scan_with_fake(tmp_path, payload, 0)
    assert outcome.status == "error"
    assert outcome.exit_code == 0 and outcome.error["code"] == "scan_errors"
    assert "Invalid rule schema" in outcome.error["message"]
    assert "no scanned paths and no results" in outcome.error["message"]
    assert outcome.claims == []
    assert json.loads((raw / "semgrep.json").read_text(encoding="utf-8"))["errors"][0]["level"] == "error"


def test_semgrep_zero_exit_with_fatal_diagnostics_after_scanning_stays_partial(tmp_path):
    payload = {"version": "9.9.9", "paths": {"scanned": ["app.py"]},
               "errors": [{"level": "error", "message": "Rule timeout on app.py"}],
               "results": [{"check_id": "probe.rule", "path": "app.py", "start": {"line": 1}, "end": {"line": 1},
                            "extra": {"message": "finding", "severity": "WARNING", "metadata": {}}}]}
    outcome, _ = _scan_with_fake(tmp_path, payload, 0)
    assert outcome.status == "partial"
    assert outcome.exit_code == 0 and outcome.error == {"code": "scan_errors", "message": "Rule timeout on app.py"}
    assert [claim["native_rule_id"] for claim in outcome.claims] == ["probe.rule"]
