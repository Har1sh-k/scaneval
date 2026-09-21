"""Invocation bundles: explicit status, preserved raw output, provenance, and no silent successes."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import threading

import pytest

from scaneval import execution as execution_module
from scaneval.adapters import get_adapter
from scaneval.adapters.base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command
from scaneval.adapters.semgrep import SemgrepAdapter, import_semgrep_results
from scaneval.contracts import ContractError, canonical_sha256, load_document, validate_document
from scaneval.execution import ExecutionError, PreparedInput, _write_new, invocation_id, run_invocation
from scaneval.materialize import hash_exported_tree, sha256_file
from scaneval.scoring import score


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
# A lone UTF-16 surrogate: canonical JSON keeps it and every contract check passes it, but UTF-8
# cannot encode it, so it only fails at the moment the bytes are produced.
LONE_SURROGATE = chr(0xD800)
mkfifo_required = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")


def call_with_deadline(function, seconds: float = 30.0):
    """Call *function* on a daemon thread and fail the test if it does not return in time.

    Opening a named pipe for reading blocks until something writes to it, so a regression in the
    guards below would wait forever. The worker is a daemon thread, so a blocked call cannot hold
    up the rest of the suite or the interpreter's exit either.
    """
    outcome: dict[str, object] = {}

    def call() -> None:
        try:
            outcome["value"] = function()
        except BaseException as exc:  # re-raised below, on the thread running the test
            outcome["error"] = exc

    worker = threading.Thread(target=call, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        pytest.fail(f"the call was still running after {seconds} seconds; it is blocked on a read")
    if "error" in outcome:
        raise outcome["error"]  # type: ignore[misc]
    return outcome["value"]


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
        if self.behavior == "modify-partial":
            # A scanner that both degraded on its own and edited the source: the outcome already
            # carries an error code, so the changed condition must not overwrite it.
            (source_dir / "app.py").write_text("changed by scanner\n", encoding="utf-8")
            return NativeOutcome(status="partial", exit_code=1, command=["fake", "scan"], claims=claims,
                                 error={"code": "scanner_degraded", "message": "half the rules failed"},
                                 artifacts=[{"id": "native", "path": native}])
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


class HidingAdapter(FakeAdapter):
    """Writes a file into the source it was handed, then closes the directory holding it."""

    def scan(self, **kwargs):
        outcome = super().scan(**kwargs)
        hidden = kwargs["source_dir"] / "hidden"
        hidden.mkdir()
        (hidden / "dropped.py").write_text("planted by the scanner\n", encoding="utf-8")
        hidden.chmod(0o000)
        return outcome


def restore_directory_modes(root: Path) -> None:
    """Make every directory under *root* readable again so the temporary tree can be removed.

    A test that takes a directory away from the walker leaves it unreadable on disk, and the
    private workspace holding it is then deliberately left behind by the runner, so pytest's own
    cleanup of ``tmp_path`` would trip over it. The walk is top down, so a directory reopened
    here is descended into afterwards.
    """
    for parent, directories, _files in os.walk(root):
        for name in directories:
            try:
                os.chmod(os.path.join(parent, name), 0o700)
            except OSError:
                pass


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
    assert not list(Path(tmp_path).glob("scaneval-trial-*"))
    with pytest.raises(FileExistsError):
        run(tmp_path, adapter)


def test_scanner_edits_to_source_are_detected(tmp_path):
    bundle = run(tmp_path, FakeAdapter("modify"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert execution["provenance"]["source_modified"] is True
    assert execution["provenance"]["modified_paths"] == ["app.py"]


def test_a_modified_source_is_a_changed_condition_that_cannot_claim_a_clean_observation(tmp_path):
    bundle = run(tmp_path, FakeAdapter("modify"))
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert result["error"]["code"] == "source_modified" and "app.py" in result["error"]["message"]
    assert execution["status"] == "partial" and execution["error"]["code"] == "source_modified"
    # The condition changed; the scanner did not fail, so what it alleged is still reported.
    assert [claim["claim_id"] for claim in result["claims"]] == ["c1"]
    assert execution["provenance"]["source_modified"] is True
    assert execution["provenance"]["modified_paths"] == ["app.py"]
    assert any("not a clean observation" in note for note in execution["notes"])


def test_a_modified_source_keeps_the_error_code_the_adapter_already_reported(tmp_path):
    bundle = run(tmp_path, FakeAdapter("modify-partial"))
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert result["error"]["code"] == "scanner_degraded"
    assert any("not a clean observation" in note for note in execution["notes"])
    assert execution["provenance"]["source_modified"] is True


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


def test_a_document_utf8_cannot_encode_creates_no_file(tmp_path):
    """The encoding must fail before the file exists; an empty result.json reads as a record."""
    path = tmp_path / "result.json"

    with pytest.raises(ContractError, match="not canonical UTF-8 JSON"):
        _write_new(path, {"claims": [{"allegation": f"lone surrogate {LONE_SURROGATE}"}]})

    assert not path.exists()


def test_a_claim_utf8_cannot_encode_is_a_recorded_violation_not_a_half_written_bundle(tmp_path):
    """The claim passes every contract check, so the encoding refusal is what gets recorded."""
    bundle = run(tmp_path, OutcomeAdapter(lambda outcome: _with(
        outcome, claims=[{**outcome.claims[0], "allegation": f"lone surrogate {LONE_SURROGATE}"}])))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "outcome_contract_violation"
    assert "could not be encoded" in result["error"]["message"]
    assert execution["error"] == result["error"]
    assert (bundle / "result.json").stat().st_size > 0
    assert (bundle / "execution.json").stat().st_size > 0
    assert (bundle / "raw" / "native.json").is_file()


def test_an_import_failure_builds_its_error_record_from_known_good_fields_only(tmp_path):
    """Spreading the refused result carried its own violation into the record reporting it."""
    bundle = run(tmp_path, OutcomeAdapter(lambda outcome: _with(
        outcome, usage={"input_tokens": 1.5, "cost_usd": 4.0, "setup_seconds": 2})))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "import_contract_violation"
    assert "input_tokens" in execution["import_error"]
    assert result["usage"] == {"wall_seconds": execution["wall_seconds"], "cost_usd": None}
    # The refused usage is gone from the result, and so are the artifacts it carried; the
    # execution record still says what the scan wrote.
    assert "raw_artifacts" not in result
    assert execution["raw_artifacts"][0]["path"] == "raw/native.json"
    assert (bundle / "raw" / "native.json").is_file()


def test_an_error_record_the_result_contract_refuses_is_still_recorded_as_an_error(tmp_path, monkeypatch):
    """The guard on the rebuilt record: a refusal there must not escape as an exception.

    Building the record from known-good fields makes this unreachable through an adapter, so the
    contract is refused directly to prove the second refusal still writes a bundle.
    """
    real_validate = execution_module.validate_document
    refused_statuses: list[str] = []

    def refusing(kind: str, document: dict) -> dict:
        if kind == "scan-result" and (document.get("error") or {}).get("code") != "outcome_contract_violation":
            refused_statuses.append(document["status"])
            raise ContractError("usage.input_tokens: 1.5 is not of type 'integer'")
        return real_validate(kind, document)

    monkeypatch.setattr(execution_module, "validate_document", refusing)
    bundle = run(tmp_path, FakeAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert refused_statuses == ["success", "error"]
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "outcome_contract_violation"
    assert "error record was refused too" in result["error"]["message"]
    assert execution["error"] == result["error"]
    assert (bundle / "raw" / "native.json").is_file()


class HostileAdapter(FakeAdapter):
    """Writes real raw output, then reports an outcome that breaks the bundle after the scan."""

    def __init__(self, hostility: str):
        super().__init__()
        self.hostility = hostility

    def scan(self, **kwargs):
        outcome = super().scan(**kwargs)
        raw_dir = kwargs["raw_dir"]
        if self.hostility == "directory-artifact":
            (raw_dir / "dump").mkdir()
            # Declared beside the real artifact the claim cites, not instead of it: a claim
            # left citing a dropped artifact is a contract violation of its own, tested below.
            outcome.artifacts.append({"id": "dump", "path": raw_dir / "dump"})
        if self.hostility == "duplicate-artifact-id":
            second = raw_dir / "second.json"
            second.write_text('{"findings": [{"file": "other.py"}]}\n', encoding="utf-8")
            outcome.artifacts.append({"id": "native", "path": second})
        if self.hostility == "state-squat":
            (raw_dir / "harness-state" / "fakestate").mkdir(parents=True)
        if self.hostility == "cyclic-claim":
            claim = outcome.claims[0]
            claim["related_locations"] = []
            claim["related_locations"].append(claim)
        if self.hostility == "deep-claim":
            nested: dict = {"path": "app.py"}
            for _ in range(3000):
                nested = {"path": "app.py", "nested": nested}
            outcome.claims[0]["related_locations"] = [nested]
        return outcome


@pytest.mark.parametrize(
    ("hostility", "fragment"),
    [("state-squat", "harness state could not be captured"),
     ("cyclic-claim", "RecursionError"),
     ("deep-claim", "RecursionError")],
    ids=["state-squat", "cyclic-claim", "deep-claim"],
)
def test_a_post_scan_failure_the_adapter_caused_is_a_recorded_violation(tmp_path, hostility, fragment):
    """Each of these raised out of run_invocation, losing the invocation and its raw output."""
    bundle = run(tmp_path, HostileAdapter(hostility))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "outcome_contract_violation"
    assert fragment in result["error"]["message"]
    assert execution["error"] == result["error"] and execution["raw_artifacts"] == []
    # The scanner's own output is preserved: only the outcome it reported was discarded.
    assert (bundle / "raw" / "native.json").read_text(encoding="utf-8").startswith('{"findings"')


def test_a_directory_declared_as_an_artifact_is_noted_rather_than_hashed(tmp_path):
    """A directory has no bytes of its own, so it joins the symlink and the missing file as a note.

    The directory is now declared alongside the regular file this adapter's claim cites, rather
    than replacing it. Declaring it alone used to leave the claim citing ``native``, an id the
    result no longer registered, and the bundle still read success; the scan-result contract
    refuses that reference, so keeping the old fixture would test the dangling reference instead
    of the unhashable directory this test is about.
    """
    bundle = run(tmp_path, HostileAdapter("directory-artifact"))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success"
    assert [artifact["id"] for artifact in result["raw_artifacts"]] == ["native"]
    assert [artifact["id"] for artifact in execution["raw_artifacts"]] == ["native"]
    assert "declared artifact is not a regular file and was not hashed: dump" in execution["notes"]
    assert (bundle / "raw" / "dump").is_dir()


@mkfifo_required
def test_a_named_pipe_in_a_staging_directory_is_skipped_rather_than_opened(tmp_path):
    """Both guards gated on exists() alone, so hashing or counting a FIFO blocked forever.

    The invocation runs behind a deadline, so a regression fails here instead of stalling the run.
    """

    class PipeAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            pipe = kwargs["raw_dir"] / "stream.jsonl"
            events = kwargs["trace_dir"] / "events.jsonl"
            os.mkfifo(pipe)
            os.mkfifo(events)
            outcome.artifacts = [{"id": "native", "path": kwargs["raw_dir"] / "native.json"},
                                 {"id": "stream", "path": pipe}]
            outcome.trace_path = events
            return outcome

    bundle = call_with_deadline(
        lambda: run(tmp_path, PipeAdapter(), trace_mode="metadata", workspace_root=tmp_path))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success"
    assert [artifact["id"] for artifact in result["raw_artifacts"]] == ["native"]
    assert "declared artifact is not a regular file and was not hashed: stream" in execution["notes"]
    assert execution["trace"] == {"path": None, "events": None, "mode": "metadata",
                                  "capture_gap": None, "dropped_events": None}
    assert ("declared trace file is not a regular file; it was not read or counted: events.jsonl"
            in execution["notes"])
    # Both pipes are still in the bundle exactly as the scanner left them: staged, never opened.
    assert stat.S_ISFIFO((bundle / "raw" / "stream.jsonl").stat().st_mode)
    assert stat.S_ISFIFO((bundle / "trace" / "events.jsonl").stat().st_mode)


@pytest.mark.parametrize("field", ["capture", "model_identity"], ids=["capture", "model-identity"])
def test_a_cyclic_mapping_the_adapter_supplied_is_a_recorded_violation(tmp_path, field):
    """Validating the execution record walks what the adapter supplied, so a cycle raises there.

    Only the build step was contained, so the cycle escaped run_invocation as a RecursionError.
    """

    def mutate(outcome: NativeOutcome) -> NativeOutcome:
        cyclic: dict = {"model_requests": "unavailable"}
        cyclic["self"] = cyclic
        return _with(outcome, **{field: cyclic})

    bundle = run(tmp_path, OutcomeAdapter(mutate))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "outcome_contract_violation"
    assert "the execution record could not be validated" in result["error"]["message"]
    assert "RecursionError" in result["error"]["message"]
    assert execution["capture"] == {} and execution["model_identity"] is None
    assert (bundle / "raw" / "native.json").is_file()


def test_a_trace_path_holding_a_nul_byte_is_recorded_rather_than_raised(tmp_path):
    """Path.resolve() raises ValueError, not OSError, for an embedded NUL; that escaped as a crash."""

    class NulTraceAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            (kwargs["trace_dir"] / "events.jsonl").write_text('{"type":"model_request"}\n', encoding="utf-8")
            outcome.trace_path = Path(str(kwargs["trace_dir"] / "events.jsonl") + "\x00")
            return outcome

    bundle = run(tmp_path, NulTraceAdapter(), trace_mode="metadata")

    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["status"] == "success"
    assert execution["trace"] == {"path": None, "events": None, "mode": "metadata",
                                  "capture_gap": None, "dropped_events": None}
    assert "declared trace file is outside the bundle; it was not read or counted" in execution["notes"]
    assert (bundle / "trace" / "events.jsonl").is_file()


def test_a_staging_directory_replaced_with_a_symlink_is_refused_not_moved(tmp_path):
    """Moving it made bundle/raw a link pointing outside the bundle while the run recorded success."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("not part of the scan output\n", encoding="utf-8")

    class SwappingAdapter(FakeAdapter):
        state_dirs = ()  # nothing is copied back into the staging area after the scan

        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            raw_dir = kwargs["raw_dir"]
            shutil.rmtree(raw_dir)
            raw_dir.symlink_to(outside, target_is_directory=True)
            return outcome

    bundle = run(tmp_path, SwappingAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["error"]["code"] == "outcome_contract_violation"
    assert "staged output could not be moved into the bundle" in result["error"]["message"]
    assert "raw: ExecutionError: the staging directory raw is a symbolic link" in result["error"]["message"]
    assert not (bundle / "raw").exists() and not (bundle / "raw").is_symlink()
    assert execution["raw_artifacts"] == []
    assert [path.name for path in outside.iterdir()] == ["secret.txt"]


def test_a_document_write_that_fails_part_way_leaves_no_file_and_no_leftover(tmp_path, monkeypatch):
    """A truncated execution.json beside a valid result.json would read as a finished record."""
    directory = tmp_path / "bundle"
    directory.mkdir()
    path = directory / "execution.json"

    def failing(source, destination):
        raise OSError("No space left on device")

    monkeypatch.setattr(os, "replace", failing)
    with pytest.raises(OSError, match="No space left on device"):
        _write_new(path, {"status": "success"})

    assert not path.exists()
    assert list(directory.iterdir()) == []


def test_a_written_document_keeps_the_mode_a_plain_create_would_have_given_it(tmp_path):
    """The bytes land through a temporary file, so the umask must still decide the mode."""
    written = tmp_path / "result.json"
    plain = tmp_path / "plain.json"

    _write_new(written, {"status": "success"})
    with plain.open("xb") as handle:
        handle.write(b"{}\n")

    assert written.read_text(encoding="utf-8") == '{"status":"success"}\n'
    assert written.stat().st_mode == plain.stat().st_mode
    # The temporary file is gone: only the two documents are in the directory.
    assert sorted(entry.name for entry in tmp_path.iterdir()) == ["plain.json", "result.json"]


def test_a_document_write_refuses_a_destination_that_already_exists(tmp_path):
    """The create-only guarantee survives the rename: an existing record is never replaced."""
    path = tmp_path / "result.json"
    path.write_text("{}\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        _write_new(path, {"status": "success"})

    assert path.read_text(encoding="utf-8") == "{}\n"
    assert [entry.name for entry in tmp_path.iterdir()] == ["result.json"]


def test_staged_output_that_cannot_be_moved_into_the_bundle_is_a_recorded_violation(tmp_path, monkeypatch):
    """A move that fails is recorded; raising there would lose the invocation entirely."""
    real_move = execution_module._move_into_bundle

    def failing(staging: Path, destination: Path) -> None:
        if destination.name == "raw":
            raise OSError("Cross-device link is not permitted")
        real_move(staging, destination)

    monkeypatch.setattr(execution_module, "_move_into_bundle", failing)
    bundle = run(tmp_path, FakeAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["error"]["code"] == "outcome_contract_violation"
    assert "staged output could not be moved into the bundle" in result["error"]["message"]
    assert "raw: OSError: Cross-device link is not permitted" in result["error"]["message"]
    assert execution["raw_artifacts"] == [] and not (bundle / "raw").exists()


def test_a_trace_path_outside_the_staging_area_is_not_counted(tmp_path):
    """The count described a file the run never staged, recorded beside a null trace path."""
    elsewhere = tmp_path / "elsewhere.jsonl"
    elsewhere.write_text('{"type":"model_request"}\n{"type":"finding"}\n', encoding="utf-8")

    class OutsideTraceAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            outcome.trace_path = elsewhere
            return outcome

    bundle = run(tmp_path, OutsideTraceAdapter(), trace_mode="metadata")

    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["status"] == "success"
    assert execution["trace"] == {"path": None, "events": None, "mode": "metadata",
                                  "capture_gap": None, "dropped_events": None}
    assert "declared trace file is outside the bundle; it was not read or counted" in execution["notes"]


def test_an_artifact_symlink_out_of_the_bundle_is_refused_rather_than_hashed(tmp_path):
    """Following the link would record a hash of a file this bundle does not contain."""
    secret = tmp_path / "secret.txt"
    secret.write_text("not part of the scan output\n", encoding="utf-8")

    class LinkingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            link = kwargs["raw_dir"] / "link.json"
            link.symlink_to(secret)
            outcome.artifacts = [{"id": "native", "path": kwargs["raw_dir"] / "native.json"},
                                 {"id": "link", "path": link}]
            return outcome

    bundle = run(tmp_path, LinkingAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success"
    assert [artifact["id"] for artifact in result["raw_artifacts"]] == ["native"]
    assert sha256_file(secret)[0] not in [artifact["sha256"] for artifact in result["raw_artifacts"]]
    assert "declared artifact is a symbolic link and was not followed: link" in execution["notes"]
    assert (bundle / "raw" / "link.json").is_symlink()


def test_an_adapter_version_the_record_cannot_carry_writes_no_bundle_documents(tmp_path):
    """The execution record copies the adapter's own version, so a float makes it unwritable.

    The runner vets these attributes when it prepares a system, so this path is what remains for
    a direct call: an explicit failure with neither bundle document written. What the invocation
    had already created stays, which is what the docstring now says.
    """

    class FloatVersionAdapter(FakeAdapter):
        adapter_version = 1.0

    with pytest.raises(ExecutionError, match="the invocation could not be recorded"):
        run(tmp_path, FloatVersionAdapter())

    bundle = tmp_path / "out" / invocation_id("input-a", "fake-sys", 1)
    assert (bundle / "request.json").is_file()
    assert not (bundle / "result.json").exists() and not (bundle / "execution.json").exists()
    # The bundle directory and the staged raw tree are already there when the refusal happens.
    assert (bundle / "raw" / "native.json").read_text(encoding="utf-8").startswith('{"findings"')
    assert (bundle / "raw" / "harness-state" / "fakestate" / "notes.md").is_file()


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
    claims, notes, lost = import_semgrep_results(payload, config_dirs=["/tmp/cache/rules__abc/python"])
    payload["results"][0]["check_id"] = "tmp.cache.rules__abc.python.python.lang.security.audit.subprocess-shell-true"
    claims, notes, _lost = import_semgrep_results(payload, config_dirs=["/tmp/cache/rules__abc/python"])
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
    claims, _notes, _lost = import_semgrep_results(payload, ruleset_roots=["/Users/x/cache/rules__abc"])
    assert claims[0]["native_rule_id"] == "go.lang.security.shared-url-struct-mutation"
    # The machine path is still absent, which is the property the config_dirs behavior had.
    assert "Users" not in claims[0]["native_rule_id"] and "cache" not in claims[0]["native_rule_id"]

    # A supplied root wins over config_dirs; config_dirs alone keeps its older, narrower behavior.
    claims, _notes, _lost = import_semgrep_results(payload, ruleset_roots=["/Users/x/cache/rules__abc"],
                                       config_dirs=["/Users/x/cache/rules__abc/go"])
    assert claims[0]["native_rule_id"] == "go.lang.security.shared-url-struct-mutation"
    claims, _notes, _lost = import_semgrep_results(payload, config_dirs=["/Users/x/cache/rules__abc/go"])
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
    # The reason the adapter reports must carry the diagnostic; its wording is the adapter's own.
    assert outcome.exit_code == 0 and outcome.error["code"] == "scan_errors"
    assert "Rule timeout on app.py" in outcome.error["message"]
    assert [claim["native_rule_id"] for claim in outcome.claims] == ["probe.rule"]


# --- referential integrity of cited evidence --------------------------------------------


class CitingAdapter(FakeAdapter):
    """Declares one real artifact and makes its claim cite the id named at construction."""

    def __init__(self, cited: str, *, declare: bool = True):
        super().__init__()
        self.cited = cited
        self.declare = declare

    def scan(self, **kwargs):
        raw_dir = kwargs["raw_dir"]
        native = raw_dir / "native.json"
        native.write_text('{"findings": []}\n', encoding="utf-8")
        artifacts = [{"id": "native", "path": native}] if self.declare else []
        return NativeOutcome(
            status="success", exit_code=0, command=["citing", "scan"],
            claims=[{"claim_id": "c1", "allegation": "shell=True with caller-controlled cmd",
                     "kind": "command_injection",
                     "primary_location": {"path": "app.py", "start_line": 3, "end_line": 3},
                     "raw_artifact_id": self.cited}],
            artifacts=artifacts)


def test_a_claim_citing_an_artifact_the_bundle_never_registered_is_a_recorded_import_failure(tmp_path):
    """A claim's evidence must exist: an invented artifact id is a failed import, not a success.

    The dangling reference used to survive untouched, so the bundle read success with
    bundles_resolved true while the claim pointed at a record nobody could open.
    """
    bundle = run(tmp_path, CitingAdapter("nothing-here"))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "import_contract_violation"
    assert "nothing-here" in result["error"]["message"]
    assert execution["import_error"] is not None and "nothing-here" in execution["import_error"]
    # The scanner's own output is still preserved; only the outcome it reported was refused.
    assert (bundle / "raw" / "native.json").is_file()


def test_a_claim_citing_an_artifact_dropped_while_collecting_is_a_recorded_import_failure(tmp_path):
    """The artifact was declared, but the bundle could not hash it, so the citation dangles too.

    ``build_documents`` drops a declared artifact that is missing, a link, or outside the
    bundle. A claim still citing it names an id the result does not register, which the
    scan-result contract now refuses.
    """
    bundle = run(tmp_path, CitingAdapter("native", declare=False))

    result = load_document(bundle / "result.json", "scan-result")
    assert result["status"] == "error"
    assert result["error"]["code"] == "import_contract_violation"
    assert "'native'" in result["error"]["message"]


def test_a_claim_citing_a_declared_artifact_is_untouched(tmp_path):
    """The control for the two tests above: a citation the bundle honors stays a clean success."""
    bundle = run(tmp_path, CitingAdapter("native"))

    result = load_document(bundle / "result.json", "scan-result")
    assert result["status"] == "success" and result["bundles_resolved"] is True
    assert result["claims"][0]["raw_artifact_id"] == "native"
    assert [artifact["id"] for artifact in result["raw_artifacts"]] == ["native"]


# --- one definition of the input tree ---------------------------------------------------


def test_the_input_tree_is_the_same_tree_the_exported_hash_covers(tmp_path):
    """``_input_tree`` with nothing excluded must select exactly what ``hash_exported_tree`` does.

    The two used to disagree: the modification check excluded the adapter's state directories
    and the hash did not, so a scanner writing into one changed the hashed tree without being
    reported as having modified the source. They are pinned to each other here.
    """
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tree / ".fakestate").mkdir()
    (tree / ".fakestate" / "notes.md").write_text("scanner scratch\n", encoding="utf-8")
    (tree / ".git").mkdir()
    (tree / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (tree / "link.py").symlink_to(tree / "src" / "app.py")

    full = execution_module._input_tree(tree, frozenset())
    assert sorted(full) == [".fakestate/notes.md", "src/app.py"], "no .git, no symlink"
    assert execution_module.tree_hash(full) == hash_exported_tree(tree)["tree_hash"]
    assert hash_exported_tree(tree)["file_count"] == len(full)

    carved = execution_module._input_tree(tree, frozenset({".fakestate"}))
    assert sorted(carved) == ["src/app.py"]
    assert execution_module.tree_hash(carved) != hash_exported_tree(tree)["tree_hash"]


def test_an_input_that_already_holds_an_adapter_state_directory_is_refused(tmp_path):
    """The carve-out for state directories is only sound while the input carries none.

    ``prepared.tree_hash`` covers the whole export, and the pre-scan check now hashes the same
    map the modification check watches, so an input shipping ``.fakestate`` cannot match and is
    refused before the scanner runs instead of having those bytes rewritten unwatched.
    """
    prepared = prepared_input(tmp_path)
    (prepared.source_dir / ".fakestate").mkdir()
    (prepared.source_dir / ".fakestate" / "planted.md").write_text("shipped by the repo\n", encoding="utf-8")
    prepared = PreparedInput(prepared.input_id, prepared.source_dir,
                             hash_exported_tree(prepared.source_dir)["tree_hash"],
                             prepared.languages, prepared.provenance)

    with pytest.raises(ExecutionError, match=r"already contains adapter state directories \(\.fakestate\)"):
        run(tmp_path, FakeAdapter(), prepared)


def test_a_scanner_writing_only_its_state_directory_is_not_reported_as_modifying_the_source(tmp_path):
    """The state directory the scanner creates is its own scratch space, preserved separately.

    It is outside the input tree on both sides of the comparison now, rather than outside one
    of them, so this stays a clean observation of the frozen input and the captured state is
    still recorded.
    """
    bundle = run(tmp_path, FakeAdapter())

    execution = load_document(bundle / "execution.json", "execution-record")
    result = load_document(bundle / "result.json", "scan-result")
    assert execution["provenance"]["source_modified"] is False
    assert execution["provenance"]["captured_state_dirs"] == [".fakestate"]
    assert result["status"] == "success"
    assert (bundle / "raw" / "harness-state" / "fakestate" / "notes.md").is_file()


def test_the_input_tree_docstring_names_what_it_excludes_and_why():
    doc = " ".join((execution_module._input_tree.__doc__ or "").split())
    assert "one definition of the input tree" in doc
    assert "``.git`` component" in doc and "state_dirs*" in doc
    assert "scanner's private scratch space" in doc


# --- neither failure mode can buy silence credit -----------------------------------------


def _quiet_plan(result: dict) -> tuple[dict, dict]:
    """One capability-safe control the reviewer assessed as quiet, over *result*."""
    plan = {
        "schema_version": "2.0", "input_hash": result["input_hash"], "scope": "diagnostic",
        "targets": [{"target_id": "T1", "description": "the planted root cause",
                     "validation_level": "fixture"}],
        "controls": [{"control_id": "C1", "description": "safe capability",
                      "type": "capability_safe", "validation_level": "fixture"}],
        "review_budgets": [3],
    }
    decisions = {
        "schema_version": "2.0", "run_id": result["run_id"], "input_hash": result["input_hash"],
        "result_sha256": canonical_sha256(result),
        "claim_matches": [],
        "control_assessments": [{"control_id": "C1", "decision": "quiet", "claim_ids": [],
                                 "reason": "the scanner said nothing about the safe capability"}],
    }
    return plan, decisions


def test_neither_a_dangling_artifact_reference_nor_a_semgrep_import_loss_earns_silence_credit(tmp_path):
    """Both defects reach scoring as something other than a clean success, so quiet pays nothing.

    A scan that cites evidence the bundle never registered, and a Semgrep run that lost a
    result during import, both used to reach the scorer as ``success`` with resolved bundles
    and collect full credit for saying nothing about the safe capability.
    """
    dangling = load_document(run(tmp_path / "a", CitingAdapter("nothing-here")) / "result.json",
                             "scan-result")
    assert dangling["status"] == "error" and dangling["error"]["code"] == "import_contract_violation"
    plan, decisions = _quiet_plan(dangling)
    report = score(plan, dangling, decisions)
    controls = report["metrics"]["controls"]["capability_safe"]
    assert controls["completed"] == 0 and controls["resolved"] == 0
    assert controls["assessable_mass"] == 0.0 and report["metrics"]["completed"] is False
    assert "Incomplete or failed execution cannot establish a successful negative control." in report["warnings"]

    payload = {"version": "9.9.9", "paths": {"scanned": ["app.py"]}, "errors": [], "results": [
        {"check_id": "probe.rule", "path": "app.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "a finding ScanEval can place", "severity": "WARNING", "metadata": {}}},
        {"check_id": "probe.rule", "path": "/etc/passwd", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "a finding ScanEval cannot place", "severity": "WARNING", "metadata": {}}},
    ]}
    lossy = load_document(_semgrep_bundle(tmp_path / "b", payload) / "result.json", "scan-result")
    assert lossy["status"] == "partial" and lossy["bundles_resolved"] is False
    assert lossy["error"]["code"] == "import_loss" and "1 semgrep result(s)" in lossy["error"]["message"]
    assert [claim["claim_id"] for claim in lossy["claims"]] == ["c1"]
    plan, decisions = _quiet_plan(lossy)
    report = score(plan, lossy, decisions)
    controls = report["metrics"]["controls"]["capability_safe"]
    assert controls["completed"] == 0 and controls["resolved"] == 0
    assert controls["assessable_mass"] == 0.0 and report["metrics"]["claims_delivered"] is None
    assert "Unresolved bundles: claim budgets and total atomic-claim burden are pending." in report["warnings"]


def _semgrep_bundle(tmp_path: Path, payload: dict, exit_code: int = 0) -> Path:
    """One real invocation bundle from the Semgrep adapter driven by the fake binary."""
    prepared = prepared_input(tmp_path)
    spec = SystemSpec("semgrep-fake", "semgrep", {"binary": str(fake_semgrep(tmp_path, payload, exit_code))})
    preparation = {"ruleset": {"commit": "a" * 40, "tree_hash": "sha256:" + "b" * 64},
                   "config_dirs": [str(tmp_path / "rules" / "python")],
                   "ruleset_root": str(tmp_path / "rules")}
    return run_invocation(prepared=prepared, adapter=SemgrepAdapter(), spec=spec, preparation=preparation,
                          out_dir=tmp_path / "out", run_id="run-semgrep", clock=CLOCK)


# --- area B: an input tree that cannot be walked, and two documents that land together ----


def test_a_source_the_scan_made_unwalkable_is_a_failed_observation_not_a_clean_one(tmp_path):
    """A scanner cannot hide what it wrote by closing the directory it wrote it in.

    ``_input_tree`` enumerated with :meth:`Path.rglob`, which swallows the ``OSError`` the walk
    raises, so a directory the scanner created, filled, and then made unreadable simply did not
    appear in the after map. The comparison found nothing changed and the bundle recorded a
    clean success over a source the scan had edited. The walk now raises, the re-hash guard
    catches it, and the invocation is recorded as a failed observation instead.
    """
    workspace_root = tmp_path / "ws"
    workspace_root.mkdir()
    try:
        bundle = run(tmp_path, HidingAdapter(), workspace_root=workspace_root)

        result = load_document(bundle / "result.json", "scan-result")
        execution = load_document(bundle / "execution.json", "execution-record")
        assert result["status"] == "error" and result["claims"] == []
        assert result["error"]["code"] == "outcome_contract_violation"
        assert "the source tree could not be re-hashed" in result["error"]["message"]
        assert "PermissionError" in result["error"]["message"]
        # Nothing is claimed about the source either way: the comparison never completed.
        assert execution["provenance"]["source_modified"] is False
        assert execution["provenance"]["modified_paths"] == []
        # What the scan wrote into the bundle is still preserved.
        assert (bundle / "raw" / "native.json").is_file()
    finally:
        restore_directory_modes(workspace_root)


def test_the_input_tree_raises_rather_than_dropping_a_directory_it_cannot_list(tmp_path):
    """The unit behind the test above, and the limit of it: an excluded directory is not walked.

    A directory the map already leaves out is never descended into, so a ``.git`` or a state
    directory that cannot be listed still cannot fail the walk; only a directory whose files the
    map is supposed to cover can.
    """
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    closed = tree / "closed"
    closed.mkdir()
    (closed / "hidden.py").write_text("y = 2\n", encoding="utf-8")
    closed.chmod(0o000)
    try:
        with pytest.raises(PermissionError):
            execution_module._input_tree(tree, frozenset())
        # The same tree with that directory excluded walks cleanly and hashes what is left.
        assert sorted(execution_module._input_tree(tree, frozenset({"closed"}))) == ["src/app.py"]

        for excluded in (tree / ".git", tree / ".fakestate"):
            excluded.mkdir()
            (excluded / "notes.md").write_text("scratch\n", encoding="utf-8")
            excluded.chmod(0o000)
        assert sorted(execution_module._input_tree(tree, frozenset({"closed", ".fakestate"}))) == ["src/app.py"]
    finally:
        restore_directory_modes(tree)


def test_an_exported_input_that_cannot_be_walked_is_refused_before_the_scanner_runs(tmp_path):
    """An input tree with no honest map is refused, the way a hash mismatch is.

    The copy into the private workspace normally fails first on a tree that cannot be read, so
    this guards the narrow case where the copy succeeded and the walk still cannot finish. It is
    driven here by making the walk fail, because nothing a test can put on disk reaches it.
    """
    adapter = FakeAdapter()
    real_input_tree = execution_module._input_tree
    calls: list[int] = []

    def failing(source_dir, state_dirs):
        calls.append(1)
        if len(calls) == 1:
            raise PermissionError(13, "Permission denied", str(source_dir / "closed"))
        return real_input_tree(source_dir, state_dirs)

    execution_module._input_tree = failing
    try:
        with pytest.raises(ExecutionError, match="the exported input could not be walked"):
            run(tmp_path, adapter)
    finally:
        execution_module._input_tree = real_input_tree

    assert adapter.calls == 0, "nothing is scanned when the input cannot be enumerated"
    bundle = tmp_path / "out" / invocation_id("input-a", "fake-sys", 1)
    assert not (bundle / "result.json").exists() and not (bundle / "execution.json").exists()


def test_a_private_workspace_that_could_not_be_removed_is_named_in_the_record(tmp_path, monkeypatch):
    """A leftover workspace used to be swallowed by ``ignore_errors``: no note, no path, nothing.

    The bundle is still exactly as good as it was, so this is not a violation of the outcome.
    What changes is that the execution record names the directory that is still on disk, so an
    operator can find it instead of discovering it as unexplained growth under the temporary
    root.
    """
    workspace_root = tmp_path / "ws"
    workspace_root.mkdir()
    real_rmtree = shutil.rmtree

    def failing(target, *args, **kwargs):
        if Path(target).name.startswith("scaneval-trial-"):
            raise PermissionError(13, "Permission denied", str(target))
        return real_rmtree(target, *args, **kwargs)

    monkeypatch.setattr(shutil, "rmtree", failing)
    bundle = run(tmp_path, FakeAdapter(), workspace_root=workspace_root)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success", "a cleanup failure does not change what the scan observed"
    leftover = [entry for entry in workspace_root.iterdir() if entry.name.startswith("scaneval-trial-")]
    assert len(leftover) == 1
    note = [line for line in execution["notes"] if "private workspace could not be removed" in line]
    assert len(note) == 1 and str(leftover[0]) in note[0] and "PermissionError" in note[0]


def test_a_total_import_failure_does_not_report_resolved_bundles(tmp_path):
    """Maximal import loss must not carry the numeric shape of a fully imported scan.

    ``_error_result`` hardcoded ``bundles_resolved`` true on the record that reports that every
    claim was refused, and the outcome that replaces one this module could not read carried the
    dataclass default, which is also true. Both are false now: no claim survived either.
    """
    dangling = load_document(run(tmp_path / "a", CitingAdapter("nothing-here")) / "result.json", "scan-result")
    assert dangling["status"] == "error" and dangling["error"]["code"] == "import_contract_violation"
    assert dangling["bundles_resolved"] is False and dangling["claims"] == []

    discarded = load_document(run(tmp_path / "b", HostileAdapter("state-squat")) / "result.json", "scan-result")
    assert discarded["status"] == "error" and discarded["error"]["code"] == "outcome_contract_violation"
    assert discarded["bundles_resolved"] is False and discarded["claims"] == []


def test_one_artifact_id_may_not_name_two_files(tmp_path):
    """A claim cites one id, so an id naming two files makes the evidence it rests on ambiguous.

    The adapter contract now refuses the duplicate. The scan-result contract still accepts two
    ``raw_artifacts`` entries sharing an id, which is a change to ``contracts.py`` and belongs to
    whoever owns that file; this closes the path an adapter reaches it through.
    """
    bundle = run(tmp_path, HostileAdapter("duplicate-artifact-id"))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["error"]["code"] == "outcome_contract_violation"
    assert "'native' is declared twice" in result["error"]["message"]
    assert result.get("raw_artifacts", []) == [] and execution["raw_artifacts"] == []
    # Both files the scan wrote are still in the bundle; only the outcome naming them was refused.
    assert (bundle / "raw" / "native.json").is_file() and (bundle / "raw" / "second.json").is_file()


def test_a_result_is_never_written_without_the_execution_record_beside_it(tmp_path, monkeypatch):
    """The two documents were two separate writes, so a failure between them split the bundle.

    ``result.json`` landed and ``execution.json`` did not, leaving a successful result with no
    record of the run that produced it, which is exactly what the module promises never happens.
    Both are staged first and renamed together now, and a rename that fails removes the one that
    already landed.
    """
    real_replace = os.replace

    def failing(source, destination):
        if str(destination).endswith("execution.json"):
            raise OSError("No space left on device")
        return real_replace(source, destination)

    monkeypatch.setattr(os, "replace", failing)
    with pytest.raises(OSError, match="No space left on device"):
        run(tmp_path, FakeAdapter())

    bundle = tmp_path / "out" / invocation_id("input-a", "fake-sys", 1)
    assert not (bundle / "result.json").exists(), "the result must not outlive its execution record"
    assert not (bundle / "execution.json").exists()
    # The request and the scanner's own output stay; no temporary file is left behind either.
    assert sorted(entry.name for entry in bundle.iterdir()) == ["raw", "request.json"]
