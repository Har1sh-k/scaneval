"""Invocation bundles: explicit status, preserved raw output, provenance, and no silent successes."""

from __future__ import annotations

from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading

import pytest

from scaneval import execution as execution_module
from scaneval.adapters import get_adapter
from scaneval.adapters.base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command
from scaneval.adapters.semgrep import SemgrepAdapter, import_semgrep_results
from scaneval.contracts import (
    ContractError,
    canonical_sha256,
    load_document,
    pr_diff_sha256,
    pr_input_hash,
    validate_document,
)
from scaneval.execution import ExecutionError, PreparedInput, _write_new, invocation_id, run_invocation
from scaneval import materialize as materialize_module
from scaneval.materialize import compute_pr_history, diff_trees, hash_exported_tree, sha256_file
from scaneval.scoring import score


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
# A lone UTF-16 surrogate: canonical JSON keeps it and every contract check passes it, but UTF-8
# cannot encode it, so it only fails at the moment the bytes are produced.
LONE_SURROGATE = chr(0xD800)
mkfifo_required = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")


def _filesystem_accepts_undecodable_names(directory: Path) -> bool:
    """Whether a file name that is not valid UTF-8 can exist here at all.

    ext4 and most Linux filesystems store file names as bytes and accept these; APFS and HFS+
    refuse them at ``open`` with ``EILSEQ``. The behavior under test is what this package does
    once such a name reaches it, so the test that needs a real one skips where none can be made.
    """
    probe = os.path.join(os.fsencode(str(directory)), b"scaneval-probe\xff")
    try:
        with open(probe, "wb") as handle:
            handle.write(b"probe")
    except (OSError, ValueError):
        return False
    os.unlink(probe)
    return True


undecodable_names_required = pytest.mark.skipif(
    not _filesystem_accepts_undecodable_names(Path(tempfile.gettempdir())),
    reason="this filesystem refuses file names that are not valid UTF-8")


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


def test_a_local_record_lists_the_names_the_runner_offers_the_scanner_and_the_adapters_own(tmp_path):
    """Without a backend the scanner gets the operator's own variables, so the record names the offer."""

    class Keyed(FakeAdapter):
        env_passthrough = ("FIXTURE_API_KEY",)

    execution = load_document(run(tmp_path, Keyed()) / "execution.json", "execution-record")
    assert execution["environment"]["passthrough"] == [
        "FIXTURE_API_KEY", "HOME", "LANG", "LC_ALL", "PATH", "SHELL", "TERM", "TMPDIR", "USER"]


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


def test_a_claim_utf8_cannot_encode_is_rendered_into_the_record_rather_than_costing_the_scan(tmp_path):
    """Deliberately changed: this used to discard every claim the scan made over one character.

    The allegation holds a lone surrogate, which passes every contract check and fails only when
    the documents become bytes. That refusal was recorded as an outcome violation, so a scanner
    reached it by naming one thing badly and lost the whole claim set with it. Both documents go
    through the one rendering step now, so the text is recorded with backslash escapes, the scan
    stands, and the execution record says how many strings had to be rendered. The bundle is
    still written whole, which is what the old assertion was really protecting.
    """
    bundle = run(tmp_path, OutcomeAdapter(lambda outcome: _with(
        outcome, claims=[{**outcome.claims[0], "allegation": f"lone surrogate {LONE_SURROGATE}"}])))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success" and "error" not in result
    assert result["claims"][0]["allegation"] == "lone surrogate \\ud800"
    assert any("bytes UTF-8 cannot encode" in note for note in execution["notes"])
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
    """Building the execution record walks what the adapter supplied, so a cycle raises there.

    Only the build step was contained, so the cycle escaped run_invocation as a RecursionError.
    It is caught one step earlier than it used to be, in the rendering pass both documents go
    through before they are validated, and it is contained exactly the same way: the outcome is
    discarded, the refusal names the RecursionError, and the bundle is written.
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
    assert "the bundle documents could not be built" in result["error"]["message"]
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
    """Following the link would record a hash of a file this bundle does not contain.

    Changed deliberately: this used to assert the link was still in the bundle, which is the
    behavior the staged-tree rule now refuses. A link is a live name for a file the bundle does
    not hold, and whoever opens ``raw/link.json`` afterwards by hand gets the host file, so it
    is cut as the staged tree lands and named with its target in the record instead. The
    artifact is therefore missing rather than a link by the time it is collected, and the two
    notes together say what the scanner left and why it is not here.
    """
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
    assert "declared artifact missing: link" in execution["notes"]
    assert any("symbolic link(s) staged into raw/ were cut" in note and f"link.json -> {secret}" in note
               for note in execution["notes"])
    # Nothing in the bundle leads to the host file, and the host file is untouched.
    assert not (bundle / "raw" / "link.json").exists() and not (bundle / "raw" / "link.json").is_symlink()
    assert secret.read_text(encoding="utf-8") == "not part of the scan output\n"


def test_a_cut_link_into_the_operator_home_is_recorded_with_a_tilde_not_the_account_name(tmp_path, monkeypatch):
    """The record keeps where the link went, not whose machine it went to.

    A run record travels with the bundle, and a cut link's target is written into it as a fact
    about the run. A target under the home directory would put the operator's account name into
    every copy, which is the leak class ``docs/THREAT_MODEL.md`` names, so the home prefix is
    spelled ``~`` and the rest of the path is kept: the DeepSec adapter's workspace links its
    ``node_modules`` to the operator's installation, and that note is where the target appears.
    """
    home = tmp_path / "home"
    (home / "tools" / "node_modules").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    class LinkingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            (kwargs["raw_dir"] / "node_modules").symlink_to(home / "tools" / "node_modules")
            return outcome

    bundle = run(tmp_path, LinkingAdapter())

    execution = load_document(bundle / "execution.json", "execution-record")
    note = next(note for note in execution["notes"] if "were cut" in note)
    assert "node_modules -> ~/tools/node_modules" in note
    assert str(home) not in note


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

    Changed deliberately: the pinning holds for the run that created its own ``.git``, which is
    the only run that may leave one out. ``created_git`` false is the other half of the same
    rule and is asserted below: the directory is counted, the two hashes then differ by design,
    and ``run_invocation`` refuses an input that reaches it in that state.
    """
    tree = tmp_path / "tree"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tree / ".fakestate").mkdir()
    (tree / ".fakestate" / "notes.md").write_text("scanner scratch\n", encoding="utf-8")
    (tree / ".git").mkdir()
    (tree / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (tree / "link.py").symlink_to(tree / "src" / "app.py")

    full = execution_module._input_tree(tree, frozenset(), created_git=True)
    assert sorted(full) == [".fakestate/notes.md", "src/app.py"], "no .git, no symlink"
    assert execution_module.tree_hash(full) == hash_exported_tree(tree)["tree_hash"]
    assert hash_exported_tree(tree)["file_count"] == len(full)

    carved = execution_module._input_tree(tree, frozenset({".fakestate"}), created_git=True)
    assert sorted(carved) == ["src/app.py"]
    assert execution_module.tree_hash(carved) != hash_exported_tree(tree)["tree_hash"]

    watched = execution_module._input_tree(tree, frozenset(), created_git=False)
    assert sorted(watched) == [".fakestate/notes.md", ".git/HEAD", "src/app.py"]
    assert execution_module.tree_hash(watched) != hash_exported_tree(tree)["tree_hash"]


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
    # The exclusion is conditional, and the docstring has to say on what.
    assert "only when *created_git* says this run wrote one" in doc


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

    A directory the map already leaves out is never descended into, so a ``.git`` this run
    created or a state directory that cannot be listed still cannot fail the walk; only a
    directory whose files the map is supposed to cover can. A ``.git`` this run did not create
    is one of those, which is the point of counting it: an unreadable one raises rather than
    passing for empty.
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
            execution_module._input_tree(tree, frozenset(), created_git=True)
        # The same tree with that directory excluded walks cleanly and hashes what is left.
        assert sorted(execution_module._input_tree(tree, frozenset({"closed"}), created_git=True)) == ["src/app.py"]

        for excluded in (tree / ".git", tree / ".fakestate"):
            excluded.mkdir()
            (excluded / "notes.md").write_text("scratch\n", encoding="utf-8")
            excluded.chmod(0o000)
        assert sorted(execution_module._input_tree(tree, frozenset({"closed", ".fakestate"}),
                                                   created_git=True)) == ["src/app.py"]
        # The one this run did not create is inside the map, so closing it fails the walk.
        with pytest.raises(PermissionError):
            execution_module._input_tree(tree, frozenset({"closed", ".fakestate"}), created_git=False)
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

    def failing(source_dir, state_dirs, *, created_git):
        calls.append(1)
        if len(calls) == 1:
            raise PermissionError(13, "Permission denied", str(source_dir / "closed"))
        return real_input_tree(source_dir, state_dirs, created_git=created_git)

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


# --- area B: no tree is copied through a symbolic link -------------------------------------


def test_a_state_directory_that_is_a_symbolic_link_is_not_followed_into_the_bundle(tmp_path):
    """The capture copied with ``symlinks=False``, so a link as the state directory was followed.

    A scanner that replaced its own state directory with a link had every file behind it copied
    into ``raw/harness-state/`` and preserved as if the scan had produced it, which is how host
    files outside the workspace reached the bundle. The link is refused whole now: nothing behind
    it is read, it is not counted as captured state, and the record says so.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "id_rsa").write_text("a host file the scan never produced\n", encoding="utf-8")

    class LinkedStateAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            state = kwargs["source_dir"] / ".fakestate"
            shutil.rmtree(state)
            state.symlink_to(outside, target_is_directory=True)
            return outcome

    bundle = run(tmp_path, LinkedStateAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success", "a refused link is not a failure of the scan itself"
    assert execution["provenance"]["captured_state_dirs"] == []
    assert not (bundle / "raw" / "harness-state").exists()
    assert any("symbolic link" in note and ".fakestate" in note for note in execution["notes"])
    # Nothing behind the link was read, so the host file is nowhere in the bundle.
    assert "id_rsa" not in json.dumps(execution)
    assert not list(bundle.rglob("id_rsa"))
    assert (outside / "id_rsa").is_file()


def test_a_link_where_the_captured_state_goes_writes_nothing_outside_the_bundle(tmp_path):
    """The destination of the capture is a path the scanner owns, and it was never checked.

    The scanner writes into the staging directory while it runs, so a link it leaves at
    ``raw/harness-state`` redirected this copy to any absolute path it chose: the source of the
    copy was checked for being a link and the destination was not, and ``mkdir(exist_ok=True)``
    succeeds on a link to a directory. The destination is resolved and proved to be inside the
    staged raw output now, so nothing is copied and the record says where it did not go.
    """
    outside = tmp_path / "outside"
    outside.mkdir()

    class RedirectingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            (kwargs["raw_dir"] / "harness-state").symlink_to(outside, target_is_directory=True)
            return outcome

    bundle = run(tmp_path, RedirectingAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success", "a refused destination is not a failure of the scan"
    assert execution["provenance"]["captured_state_dirs"] == []
    assert any("does not resolve inside the staged raw output" in note for note in execution["notes"])
    assert list(outside.iterdir()) == [], "the capture was copied outside the bundle"
    assert not list(bundle.rglob("notes.md"))


def test_a_source_replaced_by_a_link_is_not_read_after_the_scan(tmp_path):
    """The exported source is a path the scanner can replace too, and everything else reads it.

    A link where the workspace source belongs points the state capture and the re-hash at
    whatever it names, so both would walk and copy a tree outside the workspace and the bundle
    would report it as the scan's own observation. It is resolved and proved to be inside the
    private workspace before either of them runs.
    """
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "id_rsa").write_text("a host file the scan never produced\n", encoding="utf-8")

    class SourceSwappingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            source = Path(kwargs["source_dir"])
            shutil.rmtree(source)
            source.symlink_to(outside, target_is_directory=True)
            return outcome

    bundle = run(tmp_path, SourceSwappingAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "outcome_contract_violation"
    assert "the exported source no longer resolves inside the private workspace" in result["error"]["message"]
    assert execution["provenance"]["captured_state_dirs"] == []
    assert execution["provenance"]["source_modified"] is False, "the comparison never completed"
    # Nothing behind the link was read or copied: the host file is nowhere in the bundle.
    assert "id_rsa" not in json.dumps(execution)
    assert not list(bundle.rglob("id_rsa")) and (outside / "id_rsa").is_file()


def test_a_nested_git_directory_is_not_a_place_a_scanner_can_hide_what_it_wrote(tmp_path):
    """Every ``.git`` component was excluded from the input tree, not only the one the runner makes.

    That gave a scanner one directory name it could write under at any depth and stay out of the
    map entirely: the files it left there were not hashed, not compared, and the bundle recorded
    a clean observation of a tree it had changed. Only the top-level ``.git`` this module creates
    for a git-dependent adapter is excluded now.
    """

    class NestedGitAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            hidden = Path(kwargs["source_dir"]) / "vendor" / ".git"
            hidden.mkdir(parents=True)
            (hidden / "planted.py").write_text("written by the scanner\n", encoding="utf-8")
            return outcome

    bundle = run(tmp_path, NestedGitAdapter("git", requires_git=True))

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["provenance"]["source_modified"] is True
    assert execution["provenance"]["modified_paths"] == ["vendor/.git/planted.py"]
    assert result["status"] == "partial" and result["error"]["code"] == "source_modified"
    # The one the runner creates itself is still excluded, so its bookkeeping is not a change.
    assert execution["provenance"]["synthetic_history"]["message"] == "snapshot"
    assert not any(path.startswith(".git/") for path in execution["provenance"]["modified_paths"])


class GitPlantingAdapter(FakeAdapter):
    """Creates a top-level ``.git`` this run never asked for and writes inside it."""

    def __init__(self, *, close_it: bool = False):
        super().__init__()
        self.close_it = close_it

    def scan(self, **kwargs):
        outcome = super().scan(**kwargs)
        planted = Path(kwargs["source_dir"]) / ".git"
        planted.mkdir()
        (planted / "planted.py").write_text("written by the scanner\n", encoding="utf-8")
        if self.close_it:
            planted.chmod(0o000)
        return outcome


def test_a_git_directory_this_run_did_not_create_is_watched_like_the_rest_of_the_source(tmp_path):
    """The exclusion was unconditional, so ``.git`` was a hiding place on every run.

    This adapter does not require git and the runner created no repository, so nothing here is
    the runner's own bookkeeping: a scanner that makes a top-level ``.git`` and writes in it is
    writing into the tree it was given. It used to fall out of the map on both sides of the
    comparison, and the bundle recorded a clean observation of a tree the scan had changed. The
    name is excluded only on a run that created one for a git-dependent adapter now.
    """
    adapter = GitPlantingAdapter()
    assert adapter.requires_git is False
    bundle = run(tmp_path, adapter)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["provenance"]["synthetic_history"] is None, "this run created no repository"
    assert execution["provenance"]["source_modified"] is True
    assert execution["provenance"]["modified_paths"] == [".git/planted.py"]
    assert result["status"] == "partial" and result["error"]["code"] == "source_modified"


def test_a_git_directory_the_scan_made_unreadable_is_a_failed_observation(tmp_path):
    """The same directory, now inside the map, so closing it is a walk that cannot complete.

    This is the enumeration rule reaching the one directory the map used to skip: a ``.git`` the
    scanner filled and then closed raises out of the re-hash instead of reading as empty.
    """
    workspace_root = tmp_path / "ws"
    workspace_root.mkdir()
    try:
        bundle = run(tmp_path, GitPlantingAdapter(close_it=True), workspace_root=workspace_root)

        result = load_document(bundle / "result.json", "scan-result")
        execution = load_document(bundle / "execution.json", "execution-record")
        assert result["status"] == "error" and result["claims"] == []
        assert result["error"]["code"] == "outcome_contract_violation"
        assert "the source tree could not be re-hashed" in result["error"]["message"]
        assert "PermissionError" in result["error"]["message"]
        assert execution["provenance"]["source_modified"] is False, "the comparison never completed"
    finally:
        restore_directory_modes(workspace_root)


def test_an_input_that_already_ships_a_git_directory_is_refused_before_the_scanner_runs(tmp_path):
    """Counting ``.git`` is sound only while the exported hash and the watched tree agree.

    ``hash_exported_tree`` leaves a top-level ``.git`` out and this map now counts one the run
    did not create, so an input that ships one can never match. It is refused the way an input
    shipping an adapter state directory is, rather than scanned with bytes the two sides
    disagree about; a real export strips ``.git`` and never reaches this.
    """
    prepared = prepared_input(tmp_path)
    (prepared.source_dir / ".git").mkdir()
    (prepared.source_dir / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    prepared = PreparedInput(prepared.input_id, prepared.source_dir,
                             hash_exported_tree(prepared.source_dir)["tree_hash"],
                             prepared.languages, prepared.provenance)
    adapter = FakeAdapter()

    with pytest.raises(ExecutionError, match="already contains a top-level .git"):
        run(tmp_path, adapter, prepared)

    assert adapter.calls == 0, "nothing is scanned when the input and the hash disagree"


def test_a_run_whose_observer_reported_a_capture_gap_is_not_recorded_as_a_clean_success(tmp_path):
    """The gap lived only in the execution record while the result said success.

    A run that recorded its own capture as broken cannot also stand as a complete observation of
    what the scanner did, so the result is partial with an explicit code. It is not import loss:
    the claims all arrived, so ``bundles_resolved`` is left alone and the claim set is untouched.
    """

    class GappyAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            (kwargs["trace_dir"] / "events.jsonl").write_text('{"type":"model.request"}\n', encoding="utf-8")
            outcome.trace_path = kwargs["trace_dir"] / "events.jsonl"
            outcome.capture_state = {"capture_gap": True, "dropped_events": 4}
            return outcome

    bundle = run(tmp_path, GappyAdapter(), trace_mode="content")

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "partial" and result["error"]["code"] == "trace_capture_gap"
    assert "a capture gap and 4 dropped event(s)" in result["error"]["message"]
    assert result["bundles_resolved"] is True, "a dropped trace event is not a lost claim"
    assert [claim["claim_id"] for claim in result["claims"]] == ["c1"]
    assert execution["status"] == "partial" and execution["error"] == result["error"]
    assert execution["trace"]["capture_gap"] is True and execution["trace"]["dropped_events"] == 4
    assert any("not a complete record of what the scanner did" in note for note in execution["notes"])


def test_a_run_whose_observer_reported_no_gap_is_still_a_clean_success(tmp_path):
    """The control: only a reported break degrades the result, not tracing itself.

    A state that reports neither a gap nor a dropped event, and a run that reported no state at
    all, both leave the outcome exactly as the adapter gave it.
    """

    class CleanTraceAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            (kwargs["trace_dir"] / "events.jsonl").write_text('{"type":"model.request"}\n', encoding="utf-8")
            outcome.trace_path = kwargs["trace_dir"] / "events.jsonl"
            outcome.capture_state = {"capture_gap": False, "dropped_events": 0}
            return outcome

    traced = load_document(run(tmp_path / "a", CleanTraceAdapter(), trace_mode="content") / "result.json",
                           "scan-result")
    silent = load_document(run(tmp_path / "b", FakeAdapter(), trace_mode="content") / "result.json",
                           "scan-result")

    assert traced["status"] == "success" and "error" not in traced
    assert silent["status"] == "success" and "error" not in silent


def test_a_capture_gap_does_not_overwrite_the_failure_the_adapter_already_named(tmp_path):
    """A run that degraded on its own keeps its own code; the gap travels as a note beside it."""

    class DegradedGappyAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            outcome.status = "partial"
            outcome.error = {"code": "scanner_degraded", "message": "half the rules failed"}
            outcome.capture_state = {"capture_gap": False, "dropped_events": 2}
            return outcome

    bundle = run(tmp_path, DegradedGappyAdapter(), trace_mode="content")

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "partial" and result["error"]["code"] == "scanner_degraded"
    assert any("2 dropped event(s)" in note for note in execution["notes"])


def test_a_link_inside_the_captured_state_is_never_resolved_and_does_not_reach_the_bundle(tmp_path):
    """The same copy, one level down: a link inside the state directory was followed too.

    Changed deliberately: this used to assert the copied link was still a link in the bundle.
    Copying it as a link is still the rule for the copy, which is what keeps the bytes behind it
    out, but a bundle may hold no name for a file it does not contain, so the link is cut when
    the staged output lands and its target is recorded. Both halves are asserted here: nothing
    behind the link was ever read, and nothing in the bundle points at it now.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("not part of the scan output\n", encoding="utf-8")

    class LinkingStateAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            (kwargs["source_dir"] / ".fakestate" / "escape.txt").symlink_to(secret)
            return outcome

    bundle = run(tmp_path, LinkingStateAdapter())

    execution = load_document(bundle / "execution.json", "execution-record")
    captured = bundle / "raw" / "harness-state" / "fakestate"
    assert execution["provenance"]["captured_state_dirs"] == [".fakestate"]
    assert (captured / "notes.md").read_text(encoding="utf-8") == "harness state\n"
    assert not (captured / "escape.txt").is_symlink() and not (captured / "escape.txt").exists()
    assert any("copied as links rather than copied through" in note and "escape.txt" in note
               for note in execution["notes"])
    assert any("were cut" in note and f"escape.txt -> {secret}" in note for note in execution["notes"])
    # The bytes behind the link were never copied, and the host file is untouched.
    assert "not part of the scan output" not in json.dumps(execution)
    assert secret.read_text(encoding="utf-8") == "not part of the scan output\n"


def test_the_exported_input_is_copied_into_the_workspace_without_following_a_link(tmp_path):
    """The other end of the same rule: the copy in must not resolve a link either.

    Copying the export with ``symlinks=False`` turned a link in the input into a regular file
    holding whatever it pointed at, which is content the input hash never covered.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("not part of the exported input\n", encoding="utf-8")
    prepared = prepared_input(tmp_path)
    (prepared.source_dir / "link.py").symlink_to(secret)
    # The link is outside the hashed tree on both sides, so the hash the input binds to is
    # unchanged by it; what must not happen is the copy turning it into covered content.
    prepared = PreparedInput(prepared.input_id, prepared.source_dir,
                             hash_exported_tree(prepared.source_dir)["tree_hash"],
                             prepared.languages, prepared.provenance)
    seen: dict[str, object] = {}

    class LookingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            link = Path(kwargs["source_dir"]) / "link.py"
            seen["is_symlink"] = link.is_symlink()
            seen["target"] = os.readlink(link) if link.is_symlink() else link.read_text(encoding="utf-8")
            return super().scan(**kwargs)

    bundle = run(tmp_path, LookingAdapter(), prepared)

    assert seen["is_symlink"] is True, "the copy resolved the link into a regular file"
    assert seen["target"] == str(secret)
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["provenance"]["source_modified"] is False


# --- what the isolation in this package does and does not reach: docs/THREAT_MODEL.md -----


def test_a_scanner_that_restores_the_source_before_returning_is_recorded_as_a_clean_run(tmp_path):
    """The honest limit, documented rather than claimed closed. See ``docs/THREAT_MODEL.md``.

    This adapter modifies the exported source, scans the mutation, and puts the original bytes
    back before it returns. Every check this module makes runs before the scanner starts or
    after it returns, so both see the frozen input and the bundle records a clean success with
    ``source_modified`` false: the result binds to a tree hash the scanner did not scan, and
    nothing in the record says so.

    No in-process check can close this. It is a time-of-check to time-of-use race against a
    process running concurrently in a directory it controls, and the only fix is to take the
    control away: an operator who needs that must run the scanner under OS-level isolation with
    the input read-only, which this package does not provide. This test asserts the outcome the
    code actually produces, so nobody mistakes the gap for a defended edge.
    """
    scanned: dict[str, str] = {}

    class RestoringAdapter(FakeAdapter):
        def scan(self, **kwargs):
            source = Path(kwargs["source_dir"]) / "app.py"
            original = source.read_text(encoding="utf-8")
            source.write_text("# what the scanner actually scanned\n", encoding="utf-8")
            scanned["during"] = source.read_text(encoding="utf-8")
            outcome = super().scan(**kwargs)
            source.write_text(original, encoding="utf-8")  # restored before this returns
            return outcome

    bundle = run(tmp_path, RestoringAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert scanned["during"] == "# what the scanner actually scanned\n"
    assert result["status"] == "success" and "error" not in result
    assert execution["provenance"]["source_modified"] is False
    assert execution["provenance"]["modified_paths"] == []
    assert result["input_hash"] == execution["provenance"]["tree_hash"]


@mkfifo_required
def test_a_scanner_that_changes_the_input_in_ways_the_walk_cannot_see_is_recorded_as_a_clean_run(tmp_path):
    """The structural half of the same limit, which has nothing to do with timing.

    The before-and-after comparison is over ``walk_regular_files``, which enumerates regular
    files and hashes their contents. Everything else a directory can hold is outside it in both
    directions, and so is every attribute of a file that is not its bytes. This adapter waits
    until the scan is over and then plants a symbolic link to a host file, a named pipe, and an
    empty directory in the exported source, and makes a file executable. Nothing races anything:
    the walk could run a week later and still see two identical maps.

    The document says so under source-modification detection rather than claiming the check is
    narrower than it is, and this asserts the clean-looking bundle the code really produces. The
    control is in the same run: a hard link to a file already in the tree is a new regular file
    name, so that one is caught, which is what makes the rest a gap in the map and not in the walk.
    """
    host = tmp_path / "host-secret"
    host.write_text("a host file the scan never produced\n", encoding="utf-8")
    planted: dict[str, bool] = {}

    class StructuralAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            source = Path(kwargs["source_dir"])
            (source / "planted.link").symlink_to(host)
            os.mkfifo(source / "planted.fifo")
            (source / "planted-empty").mkdir()
            (source / "README.md").chmod(0o777)
            # Asserted from inside the scan, because the private workspace holding them is
            # removed once the bundle is taken out of it.
            planted["link"] = (source / "planted.link").is_symlink()
            planted["fifo"] = stat.S_ISFIFO(os.lstat(source / "planted.fifo").st_mode)
            planted["directory"] = (source / "planted-empty").is_dir()
            planted["mode"] = bool(os.lstat(source / "README.md").st_mode & stat.S_IXUSR)
            return outcome

    bundle = run(tmp_path, StructuralAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert planted == {"link": True, "fifo": True, "directory": True, "mode": True}
    assert result["status"] == "success" and "error" not in result
    assert execution["provenance"]["source_modified"] is False
    assert execution["provenance"]["modified_paths"] == []
    assert "planted" not in json.dumps(execution), "nothing about them reached the record"

    # The control: a regular file the scanner adds does move the map, so the gap is what the
    # walk cannot enumerate rather than the comparison failing to compare.
    class LinkingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            os.link(Path(kwargs["source_dir"]) / "app.py", Path(kwargs["source_dir"]) / "app.py.alias")
            return outcome

    other = run(tmp_path / "second", LinkingAdapter())
    caught = load_document(other / "execution.json", "execution-record")
    assert caught["provenance"]["source_modified"] is True
    assert caught["provenance"]["modified_paths"] == ["app.py.alias"]


def test_a_rollback_removal_that_fails_leaves_the_result_without_its_execution_record(tmp_path, monkeypatch):
    """The stated exception to "written together or not at all", driven rather than asserted.

    A rename that fails removes the document that already landed, which is what keeps the pair
    together for every failure this module can observe. That removal is itself a filesystem
    operation and can fail: a read-only filesystem, a directory whose permissions changed under
    the run. The rollback is then incomplete, its own error is what travels out, and the bundle
    holds ``result.json`` with no ``execution.json`` beside it.

    The other way there is a process killed between the two renames, which no test can drive from
    inside the process doing the renaming. Both are named in ``docs/THREAT_MODEL.md``, which is
    why this asserts the split bundle rather than a promise the code does not keep.
    """
    real_replace = os.replace
    real_unlink = Path.unlink

    def failing_replace(source, destination):
        if str(destination).endswith("execution.json"):
            raise OSError("No space left on device")
        return real_replace(source, destination)

    def failing_unlink(self, missing_ok=False):
        if self.name == "result.json":
            raise PermissionError("the rollback removal was refused too")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(os, "replace", failing_replace)
    monkeypatch.setattr(Path, "unlink", failing_unlink)
    with pytest.raises(PermissionError, match="the rollback removal was refused too"):
        run(tmp_path, FakeAdapter())
    monkeypatch.undo()

    bundle = tmp_path / "out" / invocation_id("input-a", "fake-sys", 1)
    assert (bundle / "result.json").is_file(), "the document the rollback could not remove"
    assert not (bundle / "execution.json").exists()
    assert sorted(entry.name for entry in bundle.iterdir()) == ["raw", "request.json", "result.json"]


def test_a_failure_the_trace_read_does_not_contain_ends_the_invocation_with_no_documents(tmp_path, monkeypatch):
    """The unbounded read, and what it costs when the bytes do not fit.

    ``_read_trace`` reads the declared trace file whole, with no size check anywhere on the path,
    and the call site contains ``OSError`` and ``UnicodeDecodeError``. A file too large to hold
    raises neither: ``MemoryError`` travels out of ``run_invocation``, and the invocation ends
    with a bundle directory holding the request and the scanner's own output and neither bundle
    document. The scanner picks the size, so it picks whether the run is recorded at all.

    The failure is injected rather than provoked, because provoking it means exhausting the
    machine running the suite. What is under test is the containment, not the allocator: this
    fails if that call site ever grows a guard wide enough to record the failure instead.
    """

    class TracingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            events = Path(kwargs["trace_dir"]) / "events.jsonl"
            events.write_text('{"type":"finding.submitted"}\n', encoding="utf-8")
            outcome.trace_path = events
            return outcome

    def too_large(path):
        raise MemoryError("the trace did not fit in memory")

    monkeypatch.setattr(execution_module, "read_regular_file", too_large)
    with pytest.raises(MemoryError, match="the trace did not fit in memory"):
        run(tmp_path, TracingAdapter(), trace_mode="metadata")
    monkeypatch.undo()

    bundle = tmp_path / "out" / invocation_id("input-a", "fake-sys", 1)
    assert sorted(entry.name for entry in bundle.iterdir()) == ["raw", "request.json", "trace"]
    assert not (bundle / "result.json").exists() and not (bundle / "execution.json").exists()


def test_the_threat_model_document_states_the_limit_this_package_does_not_defend():
    """The module docstrings point at it, so it has to say the things they rely on it saying."""
    threat_model = Path(__file__).resolve().parents[1] / "docs" / "THREAT_MODEL.md"
    text = threat_model.read_text(encoding="utf-8")

    assert "untrusted" in text
    assert "restore" in text and "time-of-check" in text
    for expected in ("read-only", "container", "virtual machine"):
        assert expected in text, f"the document must name {expected} as what an operator needs"
    assert "docs/THREAT_MODEL.md" in execution_module.__doc__
    assert "docs/THREAT_MODEL.md" in materialize_module.__doc__


def test_the_threat_model_document_states_the_three_claims_a_review_found_overstated():
    """Three sentences a reviewer reproduced as false or narrower than they read.

    Each is a claim the document made about the code, so each is checked against the document
    rather than left to the next reader to re-derive. The exception to the bundle-write pairing,
    the structural half of the source-modification gap, and the absence of any bound on what a
    scanner can make this package read, copy, or spend, which is the one that can end an
    invocation with no record of it at all.
    """
    text = (Path(__file__).resolve().parents[1] / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    # One line, so a claim this looks for is found wherever the paragraph happens to wrap.
    lowered = " ".join(text.lower().split())

    # The pairing, with its exception rather than as an unconditional guarantee.
    assert "no failure this process can observe leaves" in lowered
    assert "the exception to the first of those" in lowered
    assert "killed" in lowered and "removal that undoes the first rename" in lowered
    # The structural half of the modification gap, named as structural rather than temporal.
    assert "structural rather than temporal" in lowered
    for shape in ("symbolic link", "named pipe", "device node", "empty"):
        assert shape in lowered, f"the document must name {shape} as outside the comparison"
    # The bound that does not exist, named as a limit of its own.
    assert "read, copy, or spend" in lowered
    assert "sets no ceiling" in lowered
    assert "memoryerror" in lowered and "no record of the run at all" in lowered


def test_the_threat_model_document_names_the_class_two_reported_findings_belong_to():
    """Two findings are documented here rather than patched, so the document has to say so.

    A named pipe planted where a record is staged, and a staging destination hard-linked to a
    host file, both need the scanner to put something at a path between the moment ScanEval
    decides that path and the moment it opens it. Neither can be closed from inside this process,
    so the document names that class, carries both as worked examples beside the
    restore-before-return race already there, and says what an operator gets from OS-level
    isolation that no check in here provides. The cheap hardening that happens to cover these two
    is stated as defence in depth and explicitly not as a closed class, which is asserted here
    too: a package that patches instances of an unwinnable class and then reads as defending the
    class is overstating itself, and this test is what stops the document drifting into that.
    """
    text = (Path(__file__).resolve().parents[1] / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    lowered = text.lower()

    assert "deciding a path and using it are two operations" in lowered, "the class is named"
    for example in ("named pipe planted where a record is staged",
                    "destination hard-linked to a host file"):
        assert example in lowered, f"the document must carry {example!r} as a worked example"
    assert "stage_record" in text and "O_NONBLOCK" in text and "O_NOFOLLOW" in text
    assert "restore-before-return" in text, "the two examples sit beside the race already there"
    # The hardening is named as defence in depth, and the class is explicitly not closed by it.
    assert "defence in depth" in lowered and "does not close the class" in lowered
    # And what only the operating system provides, which is why these are documented, not patched.
    assert "read-only mount" in lowered and "no in-process" in lowered


# --- a base captured before the scanner ran, not resolved after it -------------------------


def test_a_workspace_swapped_after_the_capture_cannot_move_the_boundary_it_is_checked_against(tmp_path):
    """The containment check resolved its own base, which made it vacuous against a swap.

    The scanner is handed a directory inside the private workspace, so it can reach the
    workspace itself. Moving the real one aside and leaving a symbolic link to a directory it
    controls used to satisfy every post-scan check: the base resolved into the scanner's
    directory, the source resolved under it, and the runner walked, hashed, and captured the
    tree the scanner had substituted. The workspace's real path is read once, before the scan,
    and the substituted source does not resolve inside it.
    """
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "source").mkdir(parents=True)
    (elsewhere / "source" / "planted.py").write_text("planted by the scanner\n", encoding="utf-8")

    class WorkspaceSwappingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            workspace = Path(kwargs["source_dir"]).parent
            workspace.rename(workspace.with_name(workspace.name + "-real"))
            workspace.symlink_to(elsewhere, target_is_directory=True)
            # What the old check compared: both sides now resolve inside the scanner's own tree.
            assert (workspace / "source").resolve() == (elsewhere / "source").resolve()
            return outcome

    bundle = run(tmp_path, WorkspaceSwappingAdapter(), workspace_root=tmp_path)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "outcome_contract_violation"
    assert "the exported source no longer resolves inside the private workspace" in result["error"]["message"]
    assert execution["provenance"]["source_modified"] is False, "the comparison never completed"
    assert execution["provenance"]["captured_state_dirs"] == []
    # Nothing from the substituted tree was walked, hashed, or copied into the bundle.
    assert "planted.py" not in json.dumps(execution)
    assert not list(bundle.rglob("planted.py"))
    assert (elsewhere / "source" / "planted.py").read_text(encoding="utf-8") == "planted by the scanner\n"


# --- no file in the bundle is a second name for a file outside it --------------------------


def test_a_hard_link_staged_into_the_bundle_is_copied_rather_than_left_aliasing_a_host_file(tmp_path):
    """``raw/`` and ``trace/`` are moved, and a move keeps inodes, so a planted link aliased a host file.

    The bundle's file and the host's file were one file. ScanEval hashed it and counted its
    lines, the host file went on changing under the recorded hash afterwards, and a later write
    through the bundle's name would have landed in the host file. Each staged tree is
    de-aliased as it enters the bundle now, so the bundle holds its own inode either way.
    """
    host = tmp_path / "host.json"
    host.write_text('{"host": "bytes"}\n', encoding="utf-8")
    host_events = tmp_path / "host-events.jsonl"
    host_events.write_text('{"type":"one"}\n{"type":"two"}\n', encoding="utf-8")

    class LinkPlantingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            aliased = Path(kwargs["raw_dir"]) / "aliased.json"
            events = Path(kwargs["trace_dir"]) / "events.jsonl"
            os.link(host, aliased)
            os.link(host_events, events)
            assert aliased.stat().st_nlink == 2 and events.stat().st_nlink == 2
            outcome.artifacts.append({"id": "aliased", "path": aliased})
            outcome.trace_path = events
            return outcome

    bundle = run(tmp_path, LinkPlantingAdapter(), trace_mode="metadata", workspace_root=tmp_path)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    staged = bundle / "raw" / "aliased.json"
    staged_events = bundle / "trace" / "events.jsonl"
    assert result["status"] == "success"
    assert staged.stat().st_nlink == 1 and host.stat().st_nlink == 1
    assert staged_events.stat().st_nlink == 1 and host_events.stat().st_nlink == 1
    assert execution["trace"]["events"] == 2
    recorded = {artifact["id"]: artifact["sha256"] for artifact in result["raw_artifacts"]}
    assert recorded["aliased"] == sha256_file(staged)[0]
    # The host files are untouched, and what the bundle holds no longer follows them.
    host.write_text("changed after the scan\n", encoding="utf-8")
    host_events.write_text("", encoding="utf-8")
    assert staged.read_text(encoding="utf-8") == '{"host": "bytes"}\n'
    assert staged_events.read_text(encoding="utf-8").splitlines() == ['{"type":"one"}', '{"type":"two"}']
    assert recorded["aliased"] == sha256_file(staged)[0], "the recorded hash still describes the bundle"
    assert any("hard links" in note and "aliased.json" in note for note in execution["notes"])
    assert any("hard links" in note and "events.jsonl" in note for note in execution["notes"])


def test_a_staged_file_with_one_name_is_left_exactly_as_the_scanner_wrote_it(tmp_path):
    """The control: de-aliasing touches a multiply linked file and nothing else."""
    bundle = run(tmp_path, FakeAdapter(), workspace_root=tmp_path)

    execution = load_document(bundle / "execution.json", "execution-record")
    native = bundle / "raw" / "native.json"
    assert native.read_text(encoding="utf-8").startswith('{"findings"')
    assert native.stat().st_nlink == 1
    assert not any("hard link" in note for note in execution["notes"])
    assert not any("were cut" in note for note in execution["notes"])
    assert not list(bundle.rglob("*.dealias"))


# --- one enumeration, one read, and one rule for what a bundle may hold --------------------


def test_one_listing_raises_where_os_walk_reports_a_directory_it_could_not_read_as_empty(tmp_path):
    """The general rule, as a unit: an enumeration that cannot complete is a failed observation.

    ``os.walk`` is what three of the walks in this module used, and its default is to ignore the
    ``OSError`` the listing raises and yield the directory as holding nothing, which is the
    contrast asserted first here. Everything in this module now enumerates through
    ``list_directory`` and ``walk_entries``, which raise instead, so no caller can mistake a
    directory it could not read for one that was empty.
    """
    tree = tmp_path / "tree"
    (tree / "closed").mkdir(parents=True)
    (tree / "closed" / "hidden.txt").write_text("planted\n", encoding="utf-8")
    (tree / "open.txt").write_text("visible\n", encoding="utf-8")
    (tree / "closed").chmod(0o000)
    try:
        # What the swallowing walk reports: the closed directory simply holds nothing.
        assert [name for _parent, _dirs, files in os.walk(tree) for name in files] == ["open.txt"]
        with pytest.raises(PermissionError):
            execution_module.list_directory(tree / "closed")
        with pytest.raises(PermissionError):
            list(execution_module.walk_entries(tree))
    finally:
        restore_directory_modes(tree)

    readable = tmp_path / "readable"
    (readable / "sub").mkdir(parents=True)
    (readable / "sub" / "a.txt").write_text("a\n", encoding="utf-8")
    (readable / "link").symlink_to(readable / "sub", target_is_directory=True)
    seen = {path.relative_to(readable).as_posix() for path, _entry in execution_module.walk_entries(readable)}
    assert seen == {"sub", "sub/a.txt", "link"}, "the link is yielded and never descended into"


@mkfifo_required
def test_the_one_read_of_a_scanner_written_path_refuses_anything_but_a_regular_file(tmp_path):
    """The other general rule, as a unit: the proof and the read are the same open.

    The refusals run behind a deadline because the regression they guard is a read that never
    returns: opening a named pipe for reading waits for a writer that never comes.
    """
    (tmp_path / "real.json").write_text("host bytes\n", encoding="utf-8")
    pipe = tmp_path / "pipe.json"
    os.mkfifo(pipe)
    link = tmp_path / "link.json"
    link.symlink_to(tmp_path / "real.json")

    def refusals() -> dict[str, int | None]:
        errnos: dict[str, int | None] = {}
        for name, path in (("pipe", pipe), ("link", link), ("directory", tmp_path)):
            with pytest.raises(OSError) as refused:
                execution_module.read_regular_file(path)
            errnos[name] = refused.value.errno
        return errnos

    errnos = call_with_deadline(refusals)
    assert set(errnos) == {"pipe", "link", "directory"}
    assert errnos["link"] == errno.ELOOP, "a link is refused by the open, not by a check before it"
    assert errnos["pipe"] == errnos["directory"] == errno.EINVAL
    assert execution_module.read_regular_file(tmp_path / "real.json") == b"host bytes\n"


def test_a_hard_link_in_a_staged_directory_the_walk_cannot_read_is_a_recorded_failure(tmp_path):
    """The blocker: ``os.walk`` skipped the unreadable directory and the alias survived it.

    A scanner could plant a hard link to a host file, close the directory holding it, and the
    de-alias walk reported that directory as empty: the bundle went on aliasing a live host file
    behind a result that read as a clean success. The listing raises now, the sweep collects that
    failure and carries on, and the invocation is recorded as a failure rather than as a scan
    that found nothing to de-alias.

    Changed deliberately in the last round: this used to assert the walk raised out of the sweep
    and ended it. The sweep completes and collects every failure now, so the assertion is on the
    recorded failure naming the directory rather than on the exception that once escaped.
    """
    host = tmp_path / "host.json"
    host.write_text('{"host": "bytes"}\n', encoding="utf-8")

    class ClosedStagingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            hidden = Path(kwargs["raw_dir"]) / "hidden"
            hidden.mkdir()
            os.link(host, hidden / "aliased.json")
            hidden.chmod(0o000)
            return outcome

    try:
        bundle = run(tmp_path, ClosedStagingAdapter(), workspace_root=tmp_path)

        result = load_document(bundle / "result.json", "scan-result")
        execution = load_document(bundle / "execution.json", "execution-record")
        assert result["status"] == "error" and result["claims"] == []
        assert result["error"]["code"] == "outcome_contract_violation"
        assert "staged output could not be moved into the bundle" in result["error"]["message"]
        assert "PermissionError" in result["error"]["message"]
        assert "hidden: the directory could not be listed" in result["error"]["message"]
        assert execution["status"] == "error" and execution["raw_artifacts"] == []
        assert any("may still hold a second name for a file outside it" in note
                   and "hidden" in note for note in execution["notes"])
        # The alias is still on disk, which is exactly why the run must not read as a clean one.
        assert host.stat().st_nlink == 2
    finally:
        restore_directory_modes(tmp_path)


def test_a_hard_link_the_sweep_cannot_inspect_is_recorded_rather_than_skipped(tmp_path):
    """The silent skip: an entry ``lstat`` refused left the alias in the bundle and said nothing.

    A directory the scanner leaves readable but not searchable answers the listing and refuses
    every stat of what is in it. The de-alias sweep therefore saw a hard link's name, could not
    learn it was one, and skipped it: the bundle kept a live second name for a host file behind
    a result that read as a clean success, with no note, no error, and no count anywhere in the
    record. That is the same silent-swallow shape as a walk that reads an unreadable directory
    as an empty one, one level down. A failure to inspect an entry is a recorded failed
    observation now, and the invocation is refused because the alias may still be there.
    """
    host = tmp_path / "host.json"
    host.write_text('{"host": "bytes"}\n', encoding="utf-8")

    class UnsearchableStagingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            closed = Path(kwargs["raw_dir"]) / "closed"
            closed.mkdir()
            os.link(host, closed / "aliased.json")
            # Readable, so the listing succeeds; not searchable, so no stat of an entry does.
            closed.chmod(0o400)
            return outcome

    try:
        bundle = run(tmp_path, UnsearchableStagingAdapter(), workspace_root=tmp_path)

        result = load_document(bundle / "result.json", "scan-result")
        execution = load_document(bundle / "execution.json", "execution-record")
        # The premise, asserted rather than assumed: the listing works and the stat does not.
        assert [entry.name for entry in execution_module.list_directory(bundle / "raw" / "closed")] == ["aliased.json"]
        with pytest.raises(PermissionError):
            os.lstat(bundle / "raw" / "closed" / "aliased.json")
        assert result["status"] == "error" and result["claims"] == []
        assert result["error"]["code"] == "outcome_contract_violation"
        assert "closed/aliased.json: the entry could not be inspected" in result["error"]["message"]
        assert any("may still hold a second name for a file outside it" in note
                   and "closed/aliased.json" in note for note in execution["notes"])
        assert execution["raw_artifacts"] == []
        # The alias really did survive, which is exactly why nothing may call this run clean.
        assert host.stat().st_nlink == 2
    finally:
        restore_directory_modes(tmp_path)


def test_the_sweep_finishes_and_records_every_entry_it_could_not_de_alias(tmp_path):
    """The abort: the first failing entry ended the sweep, so everything after it stayed aliased.

    ``_privatize`` raised on the first copy that failed, which left every entry the walk had not
    reached still a second name for a host file while the record named only the problem that
    stopped it. The sweep completes now: the two links it cannot copy are both named, and the
    third, which it can copy, is de-aliased rather than left behind the first failure.
    """
    hosts = {name: tmp_path / f"{name}-host.json"
             for name in ("a-unreadable", "b-unreadable", "z-readable")}
    for name, host in hosts.items():
        host.write_text(f'{{"host": "{name}"}}\n', encoding="utf-8")

    class ManyLinksAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            raw = Path(kwargs["raw_dir"])
            for name, host in hosts.items():
                os.link(host, raw / f"{name}.json")
            for name in ("a-unreadable", "b-unreadable"):
                # The inode is shared, so this closes the host file too; the copy that would
                # de-alias it has to read it and cannot.
                (raw / f"{name}.json").chmod(0o000)
            return outcome

    bundle = run(tmp_path, ManyLinksAdapter(), workspace_root=tmp_path)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "error" and result["error"]["code"] == "outcome_contract_violation"
    message = result["error"]["message"]
    for name in ("a-unreadable.json", "b-unreadable.json"):
        assert f"{name}: the hard link could not be copied" in message, "every failure is named"
        assert hosts[name.removesuffix(".json")].stat().st_nlink == 2, "still aliased, and said so"
    assert "z-readable.json" not in message
    # The entry after the failures was still swept, and it is recorded as the copy it was.
    assert (bundle / "raw" / "z-readable.json").stat().st_nlink == 1
    assert hosts["z-readable"].stat().st_nlink == 1
    assert (bundle / "raw" / "z-readable.json").read_text(encoding="utf-8") == '{"host": "z-readable"}\n'
    assert any("2 staged path(s) under raw/ could not be inspected or de-aliased" in note
               and "a-unreadable.json" in note and "b-unreadable.json" in note
               for note in execution["notes"])
    assert any("hard links" in note and "z-readable.json" in note for note in execution["notes"])
    assert not list(bundle.rglob("*.dealias"))


def test_a_copied_state_directory_that_cannot_be_listed_is_a_recorded_failure(tmp_path, monkeypatch):
    """The same rule at the other walk: naming the links in a tree this module just copied.

    Under ``os.walk`` a copied directory that could not be listed contributed no links, so the
    record said a captured state directory held none while it held some. The listing is driven
    to fail here because copying the tree reads the source first, so nothing a test can put on
    disk lets the copy succeed and the walk after it fail.
    """
    real_list = execution_module.list_directory
    failed: list[int] = []

    def failing(directory):
        if Path(directory).name == "fakestate" and not failed:
            failed.append(1)
            raise PermissionError(13, "Permission denied", str(directory))
        return real_list(directory)

    monkeypatch.setattr(execution_module, "list_directory", failing)
    bundle = run(tmp_path, FakeAdapter(), workspace_root=tmp_path)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert failed == [1], "the copy's own walk is the one that failed"
    assert result["status"] == "error" and result["error"]["code"] == "outcome_contract_violation"
    assert "harness state could not be captured" in result["error"]["message"]
    assert "PermissionError" in result["error"]["message"]
    assert execution["provenance"]["captured_state_dirs"] == []


def test_a_symbolic_link_staged_into_the_bundle_is_cut_and_named_with_its_target(tmp_path):
    """The one rule for what a staged tree may carry in: no path may name a file outside.

    A link was kept, on the argument that it is visibly a link and nothing here follows one.
    But ``bundle/raw/escape.json`` is what whoever opens the bundle by hand actually reads, and
    what it reads is a host file the scan never produced. The link is cut as the tree lands and
    its target goes into the record, so what the scanner did is a fact about the run rather than
    a live path out of the bundle.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("a host file the scan never produced\n", encoding="utf-8")

    class LinkStagingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            (Path(kwargs["raw_dir"]) / "escape.json").symlink_to(secret)
            (Path(kwargs["trace_dir"]) / "events.jsonl").symlink_to(secret)
            return outcome

    bundle = run(tmp_path, LinkStagingAdapter(), trace_mode="metadata", workspace_root=tmp_path)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success", "a cut link is not a failure of the scan itself"
    for cut in (bundle / "raw" / "escape.json", bundle / "trace" / "events.jsonl"):
        assert not cut.exists() and not cut.is_symlink()
    assert any("staged into raw/ were cut" in note and f"escape.json -> {secret}" in note
               for note in execution["notes"])
    assert any("staged into trace/ were cut" in note and f"events.jsonl -> {secret}" in note
               for note in execution["notes"])
    assert execution["trace"]["events"] is None and execution["trace"]["path"] is None
    # Nothing was written through either link and nothing behind them reached the record.
    assert secret.read_text(encoding="utf-8") == "a host file the scan never produced\n"
    assert "a host file the scan never produced" not in json.dumps(execution)


def test_a_hard_link_behind_a_symlinked_directory_never_reaches_the_bundle(tmp_path):
    """The two defects together: the walk cannot enter a link, so a link above one hid the alias.

    De-aliasing never descends through a symbolic link, which is right, and keeping the link was
    therefore a way to carry a whole aliased subtree into the bundle untouched: every file
    behind ``raw/sub`` was reachable through the bundle and was the same inode as a host file.
    Cutting the link removes the subtree from the bundle with it, so the de-alias rule covers
    every directory a bundle actually has.
    """
    host = tmp_path / "host.json"
    host.write_text('{"host": "bytes"}\n', encoding="utf-8")
    behind = tmp_path / "behind"
    behind.mkdir()
    os.link(host, behind / "aliased.json")
    assert host.stat().st_nlink == 2

    class HidingLinkAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            (Path(kwargs["raw_dir"]) / "sub").symlink_to(behind, target_is_directory=True)
            return outcome

    bundle = run(tmp_path, HidingLinkAdapter(), workspace_root=tmp_path)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success"
    assert not (bundle / "raw" / "sub").exists() and not (bundle / "raw" / "sub").is_symlink()
    assert not list(bundle.rglob("aliased.json")), "no path in the bundle reaches the aliased file"
    assert any("were cut" in note and f"sub -> {behind}" in note for note in execution["notes"])
    # The host alias is left exactly as the scanner made it: this cuts the name, not the file.
    assert host.stat().st_nlink == 2
    host.write_text("changed after the scan\n", encoding="utf-8")
    assert (behind / "aliased.json").read_text(encoding="utf-8") == "changed after the scan\n"


# --- nothing a scanner names can make the bundle unrecordable ------------------------------


def test_a_file_name_utf8_cannot_encode_is_recorded_rather_than_costing_the_whole_bundle(tmp_path, monkeypatch):
    """One file name used to leave an invocation with no ``result.json`` and no ``execution.json``.

    A file name is bytes. A filesystem that accepts bytes UTF-8 cannot decode hands Python a
    name holding escaped surrogates, which canonical JSON keeps and every contract check passes
    but the encoding refuses. The refusal arrived where the documents became bytes, the rebuilt
    refusal record carried the same modified path and was refused again, and the invocation
    raised with ``request.json`` and ``raw/`` written and neither document beside them. The name
    is injected into the walk here rather than created, because the filesystem this test runs on
    may be one that refuses such a name at ``open``.
    """
    real_walk = execution_module.walk_regular_files
    walks: list[int] = []

    def walk_with_an_undecodable_name(root: Path, *, skip_top_level=frozenset()):
        found = real_walk(root, skip_top_level=skip_top_level)
        walks.append(1)
        if len(walks) > 1 and "app.py" in found:
            # What os.scandir returns for such a name: a string only os.fsencode turns back into
            # the bytes on disk. Mapped to a real file, because the walk's values get hashed.
            found[f"planted{LONE_SURROGATE}.py"] = found["app.py"]
        return found

    monkeypatch.setattr(execution_module, "walk_regular_files", walk_with_an_undecodable_name)
    bundle = run(tmp_path, FakeAdapter())

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "partial" and result["error"]["code"] == "source_modified"
    assert [claim["claim_id"] for claim in result["claims"]] == ["c1"], "the claims are not the casualty"
    assert execution["provenance"]["source_modified"] is True
    assert execution["provenance"]["modified_paths"] == ["planted\\ud800.py"]
    assert any("bytes UTF-8 cannot encode" in note for note in execution["notes"])
    assert (bundle / "result.json").is_file() and (bundle / "execution.json").is_file()


def test_the_rendering_touches_only_what_utf8_cannot_encode_and_counts_what_it_touched():
    """The one pass both documents go through, on keys and values alike."""
    document = {"notes": [f"name {LONE_SURROGATE}"], f"key{LONE_SURROGATE}": "value",
                "count": 3, "ok": "plain text", "nothing": None}

    rendered, count = execution_module._recordable(document)

    assert rendered == {"notes": ["name \\ud800"], "key\\ud800": "value",
                        "count": 3, "ok": "plain text", "nothing": None}
    assert count == 2
    assert json.dumps(rendered, ensure_ascii=False).encode("utf-8"), "the rendering is writable"
    assert execution_module._recordable({"ok": "plain text"}) == ({"ok": "plain text"}, 0)


@undecodable_names_required
def test_an_artifact_named_in_bytes_the_record_cannot_carry_is_dropped_with_a_note(tmp_path):
    """A rendered path does not open, and an artifact is evidence a claim has to be able to cite.

    So this one artifact is dropped where the links, the missing files, and the directories are
    dropped, rather than registered under a name that names nothing. The file itself stays in
    the bundle exactly as the scanner wrote it.
    """

    class OddNameAdapter(FakeAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            raw = os.fsencode(str(kwargs["raw_dir"]))
            odd = os.path.join(raw, b"native\xff.json")
            with open(odd, "wb") as handle:
                handle.write(b'{"findings": []}\n')
            outcome.artifacts.append({"id": "odd-name", "path": Path(os.fsdecode(odd))})
            return outcome

    bundle = run(tmp_path, OddNameAdapter(), workspace_root=tmp_path)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "success"
    assert [artifact["id"] for artifact in result["raw_artifacts"]] == ["native"]
    assert ("declared artifact has a name this record cannot carry and was not registered: odd-name"
            in execution["notes"])
    assert b"native\xff.json" in os.listdir(os.fsencode(str(bundle / "raw")))


# --- one derivation of how completely the run was observed ---------------------------------


class CompleteCaptureAdapter(FakeAdapter):
    """Reports capture of four categories; *trace* decides what trace the bundle ends up with.

    One category per value the schema's enumeration carries, so every one of them meets the
    reconciliation: ``complete`` and ``partial`` and ``redacted`` each claim the category was
    observed, to a different extent, and ``not_applicable`` claims the category does not apply
    to this scan at all. The first three need a trace behind them and the fourth needs none,
    which is what the downgrade tests below and their control are about.
    """

    def __init__(self, trace: str, elsewhere: Path | None = None):
        super().__init__()
        self.trace = trace
        self.elsewhere = elsewhere

    def scan(self, **kwargs):
        outcome = super().scan(**kwargs)
        outcome.capture = {"model_requests": "partial", "finding_submitted": "complete",
                           "context_selection": "redacted", "tool_calls": "not_applicable"}
        trace_dir = kwargs["trace_dir"]
        if trace_dir is None:
            return outcome
        events = Path(trace_dir) / "events.jsonl"
        if self.trace == "written":
            events.write_text('{"type":"finding_submitted"}\n', encoding="utf-8")
            outcome.trace_path = events
        elif self.trace == "symlink":
            events.symlink_to(Path(kwargs["raw_dir"]) / "native.json")
            outcome.trace_path = events
        elif self.trace == "empty":
            events.write_text("", encoding="utf-8")
            outcome.trace_path = events
        elif self.trace == "outside":
            outcome.trace_path = self.elsewhere
        return outcome


@pytest.mark.parametrize(
    ("trace", "trace_mode"),
    [("missing", "content"), ("symlink", "content"), ("outside", "content"), ("written", "off")],
    ids=["no-trace-file", "trace-is-a-link", "trace-outside-the-bundle", "tracing-off"],
)
def test_no_capture_category_may_claim_observation_in_a_bundle_with_no_counted_trace(tmp_path, trace, trace_mode):
    """``trace.events`` null beside a ``capture`` that says the run was observed, in four ways.

    The two used to be written independently into one document: the count came from the file
    this module could find in the bundle, and the category came from the adapter, which reports
    what its observer saw and cannot know whether the file landed. Every way the count goes
    missing left the record claiming an observation with no observation behind it, and the run
    still read as a clean success. Both now come from one derivation, so the categories are
    downgraded and the run is partial with the reason named.

    The reconciliation used to cover ``complete`` alone, and rewrite it to ``partial``. A review
    pointed out that it was then writing the very thing it refuses: ``partial`` claims the
    category was observed and some of it was missed, ``redacted`` claims it was observed and
    stored with values hidden, and a bundle holding no trace backs neither any better than it
    backs ``complete``. Every value that claims an observation is downgraded now, to the one
    value that claims none, and the two here that claim none are left exactly as the adapter
    wrote them.
    """
    elsewhere = tmp_path / "elsewhere.jsonl"
    elsewhere.write_text('{"type":"finding_submitted"}\n', encoding="utf-8")
    bundle = run(tmp_path, CompleteCaptureAdapter(trace, elsewhere), trace_mode=trace_mode)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["capture"] == {"finding_submitted": "unavailable",
                                    "model_requests": "unavailable",
                                    "context_selection": "unavailable",
                                    "tool_calls": "not_applicable"}, (
        "every claim of observation is downgraded; a category that does not apply is untouched")
    assert execution["trace"] is None or execution["trace"]["events"] is None
    assert result["status"] == "partial" and result["error"]["code"] == "trace_capture_gap"
    assert ("observed capture of context_selection, finding_submitted, model_requests claimed "
            "with no trace event in this bundle") in result["error"]["message"]
    assert "tool_calls" not in result["error"]["message"], "nothing was withdrawn from it"
    assert result["bundles_resolved"] is True, "a missing trace is not a lost claim"
    assert [claim["claim_id"] for claim in result["claims"]] == ["c1"]
    assert execution["status"] == result["status"] and execution["error"] == result["error"]


def test_a_capture_claim_is_not_backed_by_a_trace_with_no_events_in_it(tmp_path):
    """A trace file that exists and holds nothing is the fifth way, and it counted as a trace.

    The count was a trace as long as it was an integer, so zero read as a bundle that held an
    observation. It holds the same record a run that observed nothing at all leaves, and no
    category can claim observation on the strength of it, so the bundle could say
    ``trace.events`` zero beside ``capture.finding_submitted`` complete and still be a clean
    success. A count backs a claim only when there is at least one event behind it.
    """
    bundle = run(tmp_path, CompleteCaptureAdapter("empty"), trace_mode="content")

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["trace"]["events"] == 0 and execution["trace"]["path"] == "trace/events.jsonl"
    assert execution["capture"] == {"finding_submitted": "unavailable",
                                    "model_requests": "unavailable",
                                    "context_selection": "unavailable",
                                    "tool_calls": "not_applicable"}
    assert result["status"] == "partial" and result["error"]["code"] == "trace_capture_gap"
    assert "observed capture of context_selection, finding_submitted, model_requests claimed with no trace event" in result["error"]["message"]
    assert result["bundles_resolved"] is True, "an empty trace is not a lost claim"
    assert [claim["claim_id"] for claim in result["claims"]] == ["c1"]


def test_every_capture_claim_a_counted_trace_backs_is_left_alone(tmp_path):
    """The control: the rule downgrades an unbacked claim, not tracing itself.

    One counted event backs every category the adapter reported, whatever each one claims, so
    the mapping reaches the record exactly as it was written and the run stays a clean success.
    """
    bundle = run(tmp_path, CompleteCaptureAdapter("written"), trace_mode="content")

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["trace"]["events"] == 1 and execution["trace"]["path"] == "trace/events.jsonl"
    assert execution["capture"] == {"finding_submitted": "complete", "model_requests": "partial",
                                    "context_selection": "redacted",
                                    "tool_calls": "not_applicable"}
    assert result["status"] == "success" and "error" not in result


def test_a_capture_gap_and_an_unbacked_capture_claim_are_reported_together(tmp_path):
    """One derivation, so a record that breaks both ways says both rather than the first one."""

    class GappyUnbackedAdapter(CompleteCaptureAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            outcome.capture_state = {"capture_gap": True, "dropped_events": 3}
            return outcome

    bundle = run(tmp_path, GappyUnbackedAdapter("missing"), trace_mode="content")

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    message = result["error"]["message"]
    assert result["status"] == "partial" and result["error"]["code"] == "trace_capture_gap"
    assert "a capture gap" in message and "3 dropped event(s)" in message
    assert "observed capture of context_selection, finding_submitted, model_requests" in message
    assert execution["capture"]["finding_submitted"] == "unavailable"
    assert execution["trace"]["capture_gap"] is True and execution["trace"]["events"] is None


def test_a_standard_full_local_invocation_keeps_writing_2_0_records(tmp_path):
    """The record version moves only when a 2.1 field is needed; the standard local path is unchanged."""
    bundle = run(tmp_path, FakeAdapter())
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert result["schema_version"] == "2.0" and execution["schema_version"] == "2.0"
    assert "isolation" not in execution and "input_hash" not in execution["provenance"]
    assert execution["network_policy"]["enforced"] is False


def test_a_blinded_input_writes_a_2_1_record_naming_its_identities_and_the_local_backend(tmp_path):
    import dataclasses

    base = prepared_input(tmp_path)
    blinding = {"map_id": "m", "map_version": "1", "map_sha256": "sha256:" + "e" * 64,
                "original_tree_hash": "sha256:" + "f" * 64, "transformed_tree_hash": base.tree_hash}
    prepared = dataclasses.replace(base, profile="metadata_blinded", blinding=blinding,
                                   source_tree_hash="sha256:" + "f" * 64)
    bundle = run(tmp_path, FakeAdapter(), prepared)
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    validate_document("execution-record", execution)
    assert result["schema_version"] == "2.0" and result["input_hash"] == base.tree_hash
    assert execution["schema_version"] == "2.1"
    assert execution["provenance"]["input_hash"] == base.tree_hash
    assert execution["provenance"]["blinding"] == blinding and execution["provenance"]["pr"] is None
    assert execution["isolation"]["backend"] == "local" and execution["isolation"]["enforced"] is False


class PrAdapter(FakeAdapter):
    """A fake adapter that declares it reviews a change, and looks at the workspace it is handed."""

    scan_modes = frozenset({"full", "pr"})

    def __init__(self, behavior: str = "success"):
        super().__init__(behavior)
        self.seen: dict = {}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        pr = request["input"].get("pr")
        if pr is not None:
            self.seen = {
                "request": request,
                "name_status": workspace_git(source_dir, "diff", "--name-status", pr["base"], pr["head"]),
                "head": workspace_git(source_dir, "rev-parse", "HEAD"),
                "commits": workspace_git(source_dir, "rev-list", "--count", "HEAD"),
                "status": workspace_git(source_dir, "status", "--porcelain", "--untracked-files=all"),
                "listing": sorted(path.name for path in source_dir.iterdir()),
            }
        return super().scan(request=request, source_dir=source_dir, raw_dir=raw_dir, spec=spec,
                            preparation=preparation, timeout_seconds=timeout_seconds,
                            trace_mode=trace_mode, trace_dir=trace_dir)


def workspace_git(workspace: Path, *args: str) -> str:
    """What git says inside a workspace, read the way a scanner would, with no operator configuration."""
    argv, env = materialize_module.git_command(list(args))
    return subprocess.run(argv, cwd=str(workspace), env=env, capture_output=True, text=True, check=True).stdout


def pr_input(tmp_path: Path) -> PreparedInput:
    """A PR input whose head is :func:`prepared_input`'s tree and whose base is an older one beside it.

    The change holds every kind the record names: an edited file, an added one, a deleted one, an
    exact-content rename, and a mode change. The synthetic commits are the ones preparation computes.
    """
    import dataclasses

    head = prepared_input(tmp_path)
    base = tmp_path / "trial" / "base" / "source"
    base.mkdir(parents=True)
    (base / "app.py").write_text("import subprocess\ndef run(cmd):\n    return subprocess.run(cmd)\n", encoding="utf-8")
    (base / "README.md").write_text("demo\n", encoding="utf-8")
    (base / "legacy.txt").write_text("removed in the head\n", encoding="utf-8")
    (base / "util.py").write_text("def helper():\n    return 'moved by the rename'\n", encoding="utf-8")
    (base / "tool.sh").write_text("#!/bin/sh\necho tool\n", encoding="utf-8")
    for name, contents, mode in (("added.txt", "added in the head\n", 0o644),
                                 ("helpers.py", "def helper():\n    return 'moved by the rename'\n", 0o644)):
        (head.source_dir / name).write_text(contents, encoding="utf-8")
        (head.source_dir / name).chmod(mode)
    (head.source_dir / "tool.sh").write_text("#!/bin/sh\necho tool\n", encoding="utf-8")
    (head.source_dir / "tool.sh").chmod(0o755)
    head_hash = hash_exported_tree(head.source_dir)["tree_hash"]
    base_hash = hash_exported_tree(base)["tree_hash"]
    changes = diff_trees(base, head.source_dir)
    diff = pr_diff_sha256(base_hash, head_hash, changes)
    history = compute_pr_history(head.source_dir, base, changes)
    pr = {"change_set_id": "cs-1", "base_snapshot_id": "snap-base", "head_snapshot_id": "snap-head",
          "boundary": "introducing", "review_scope": "changed_files", "base_tree_hash": base_hash,
          "head_tree_hash": head_hash, "diff_sha256": diff, "changes": changes,
          "base_commit": history["base_commit"], "head_commit": history["head_commit"],
          "history": {key: history[key] for key in ("messages", "identity", "date")},
          "prepared_state": "fresh"}
    return dataclasses.replace(head, tree_hash=head_hash, mode="pr", input_hash=pr_input_hash(base_hash, head_hash, diff),
                               pr=pr, base_source_dir=base)


def test_a_pr_input_binds_its_result_to_the_change_set_identity_and_locates_against_head(tmp_path):
    """Changed deliberately: a PR input now needs the base tree its history is built from, and an
    adapter that declares it reviews a change (the default fake declares only full scans), so the
    input is a real one and the synthetic commits in the request are the ones the workspace holds."""
    prepared = pr_input(tmp_path)
    adapter = PrAdapter()

    bundle = run(tmp_path, adapter, prepared)

    request = json.loads((bundle / "request.json").read_text(encoding="utf-8"))
    assert request["input"]["mode"] == "pr"
    assert request["input"]["pr"] == {"base": prepared.pr["base_commit"], "head": prepared.pr["head_commit"]}
    # Nothing evaluator-side about the change reaches the scanner's request.
    for private in ("cs-1", "snap-base", "snap-head", prepared.input_hash, prepared.pr["base_tree_hash"],
                    prepared.pr["diff_sha256"]):
        assert private not in json.dumps(request)
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    validate_document("scan-result", result)
    validate_document("execution-record", execution)
    assert result["schema_version"] == "2.1" and result["location_basis"] == "pr_head"
    assert result["status"] == "success" and adapter.calls == 1
    assert result["input_hash"] == prepared.input_hash and execution["provenance"]["tree_hash"] == prepared.tree_hash
    assert execution["provenance"]["mode"] == "pr" and execution["provenance"]["pr"] == prepared.pr
    assert execution["provenance"]["synthetic_history"] == {
        "base_commit": prepared.pr["base_commit"], "head_commit": prepared.pr["head_commit"],
        "messages": {"base": "base", "head": "head"}, "identity": "ScanEval <scaneval@localhost>",
        "date": "2000-01-01T00:00:00+00:00"}
    assert execution["provenance"]["source_modified"] is False and execution["provenance"]["modified_paths"] == []
    assert not any(str(prepared.base_source_dir) in json.dumps(document) for document in (request, result, execution))


def test_the_workspace_git_diff_between_the_synthetic_commits_is_the_recorded_diff(tmp_path):
    """One native invocation hands the scanner the recorded change, kind by kind, and nothing else."""
    prepared = pr_input(tmp_path)
    adapter = PrAdapter()

    run(tmp_path, adapter, prepared)

    changes = prepared.pr["changes"]
    assert changes == {"added": ["added.txt"], "deleted": ["legacy.txt"], "modified": ["app.py"],
                       "renamed": [["util.py", "helpers.py"]], "mode_changed": ["tool.sh"]}, \
        "the fixture covers added, deleted, modified, renamed, and mode-changed files"
    lines = sorted(line.split("\t") for line in adapter.seen["name_status"].splitlines())
    assert lines == sorted([["A", "added.txt"], ["D", "legacy.txt"], ["M", "app.py"],
                            ["R100", "util.py", "helpers.py"], ["M", "tool.sh"]])
    assert adapter.seen["head"].strip() == prepared.pr["head_commit"]
    assert adapter.seen["commits"].strip() == "2", "the base and the head, no filler commits"
    assert adapter.seen["status"] == "", "HEAD is the head and the worktree is clean"
    assert ".git" in adapter.seen["listing"] and "base" not in adapter.seen["listing"], \
        "the base is reachable through git only, never as a directory beside the head"


def test_the_request_names_only_the_synthetic_commits(tmp_path):
    prepared = pr_input(tmp_path)
    adapter = PrAdapter()

    run(tmp_path, adapter, prepared)

    request = adapter.seen["request"]
    assert request["input"] == {"tree_hash": prepared.tree_hash, "root": ".", "languages": ["python"],
                                "mode": "pr", "profile": "standard",
                                "pr": {"base": prepared.pr["base_commit"], "head": prepared.pr["head_commit"]}}
    assert set(request["input"]["pr"]) == {"base", "head"}


def test_an_adapter_that_does_not_declare_pr_yields_unsupported_and_is_never_called(tmp_path):
    prepared = pr_input(tmp_path)
    adapter = FakeAdapter()
    assert adapter.scan_modes == frozenset({"full"}), "an adapter that declares nothing carries out full scans"

    bundle = run(tmp_path, adapter, prepared)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert adapter.calls == 0, "scan() is never called for a mode the adapter does not declare"
    assert result["status"] == execution["status"] == "unsupported" and result["claims"] == []
    assert result["error"]["code"] == execution["error"]["code"] == "unsupported_mode"
    assert "does not declare support for pr scans; it carries out: full" in result["error"]["message"]
    assert any("stays in the denominator" in note for note in execution["notes"])
    assert result["schema_version"] == "2.1" and result["location_basis"] == "pr_head"
    assert result["input_hash"] == prepared.input_hash
    assert execution["provenance"]["mode"] == "pr" and execution["provenance"]["synthetic_history"] is None
    assert execution["provenance"]["source_modified"] is False
    assert not (bundle / "raw" / "native.json").exists(), "no scan ran, so it produced nothing"


def test_an_unsupported_mode_stays_in_the_denominator_and_earns_no_quiet_credit(tmp_path):
    prepared = pr_input(tmp_path)
    bundle = run(tmp_path, FakeAdapter(), prepared)
    result = load_document(bundle / "result.json", "scan-result")
    plan, decisions = _quiet_plan(result)

    evaluation = score(plan, result, decisions)

    assert evaluation["status"] == "unsupported" and evaluation["metrics"]["completed"] is False
    assert evaluation["metrics"]["targets_assigned"] == 1 and evaluation["metrics"]["targets_detected"] == 0
    control = evaluation["metrics"]["controls"]["capability_safe"]
    assert control["assigned"] == 1 and control["completed"] == 0 and control["resolved"] == 0, \
        "an unsupported invocation completes no control, so silence earns nothing"
    assert "Incomplete or failed execution cannot establish a successful negative control." in evaluation["warnings"]


def test_an_adapter_that_declares_only_pr_is_not_run_on_a_full_input(tmp_path):
    class PrOnlyAdapter(PrAdapter):
        scan_modes = frozenset({"pr"})

    adapter = PrOnlyAdapter()

    bundle = run(tmp_path, adapter)

    execution = load_document(bundle / "execution.json", "execution-record")
    assert adapter.calls == 0 and execution["status"] == "unsupported"
    assert execution["error"]["code"] == "unsupported_mode"
    assert "does not declare support for full scans; it carries out: pr" in execution["error"]["message"]
    assert execution["schema_version"] == "2.0", "a full local input still needs no 2.1 field"


def test_a_pr_input_gets_the_history_even_from_an_adapter_that_asked_for_no_git(tmp_path):
    adapter = PrAdapter()
    assert adapter.requires_git is False

    run(tmp_path, adapter, pr_input(tmp_path))

    assert adapter.seen["commits"].strip() == "2"


def test_a_full_scan_of_a_git_adapter_still_gets_its_one_commit_and_no_pr_history(tmp_path):
    adapter = PrAdapter(behavior="git")
    adapter.requires_git = True

    bundle = run(tmp_path, adapter)

    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["provenance"]["synthetic_history"]["message"] == "snapshot"
    assert "base_commit" not in execution["provenance"]["synthetic_history"]


def test_the_runner_own_history_is_not_a_modification_and_a_scanner_write_still_is(tmp_path):
    clean = run(tmp_path / "clean", PrAdapter(), pr_input(tmp_path / "clean"))
    assert load_document(clean / "execution.json", "execution-record")["provenance"]["source_modified"] is False

    prepared = pr_input(tmp_path / "dirty")
    bundle = run(tmp_path / "dirty", PrAdapter("modify"), prepared)

    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == "partial" and result["error"]["code"] == "source_modified"
    assert execution["provenance"]["source_modified"] is True and execution["provenance"]["modified_paths"] == ["app.py"]
    assert result["bundles_resolved"] is False


def test_the_history_directory_the_runner_created_is_left_out_of_the_watched_tree_as_a_whole(tmp_path):
    """A PR scanner may legitimately move the history's own state (a baseline scan resets the tree in
    place and restores it), so the runner's ``.git`` is not a modification, exactly as the single
    commit a git-dependent full scan gets is not; what a scanner writes in the tree is still seen."""

    class WritesToGit(PrAdapter):
        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            (kwargs["source_dir"] / ".git" / "hooks").mkdir(exist_ok=True)
            (kwargs["source_dir"] / "app.py").write_text("changed\n", encoding="utf-8")
            return outcome

    bundle = run(tmp_path, WritesToGit(), pr_input(tmp_path))

    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["provenance"]["modified_paths"] == ["app.py"], "only app.py, never anything under .git"


def test_a_workspace_history_that_is_not_the_recorded_one_is_refused_before_the_scanner_runs(tmp_path):
    import dataclasses

    prepared = pr_input(tmp_path)
    forged = dataclasses.replace(prepared, pr={**prepared.pr, "head_commit": "f" * 40})
    adapter = PrAdapter()

    with pytest.raises(ExecutionError, match="synthetic PR history is not reproducible") as refused:
        run(tmp_path, adapter, forged)

    assert "f" * 40 in str(refused.value) and prepared.pr["head_commit"] in str(refused.value)
    assert adapter.calls == 0


def test_a_base_tree_other_than_the_recorded_one_cannot_reproduce_the_recorded_history(tmp_path):
    prepared = pr_input(tmp_path)
    (prepared.base_source_dir / "legacy.txt").write_text("edited after preparation\n", encoding="utf-8")
    adapter = PrAdapter()

    with pytest.raises(ExecutionError, match="synthetic PR history is not reproducible"):
        run(tmp_path, adapter, prepared)
    assert adapter.calls == 0


def test_a_pr_input_without_a_base_tree_is_refused_before_a_bundle_exists(tmp_path):
    import dataclasses

    prepared = pr_input(tmp_path)
    for base in (None, tmp_path / "no-such-base"):
        with pytest.raises(ExecutionError, match="must carry the base export its synthetic history is built from"):
            run(tmp_path, PrAdapter(), dataclasses.replace(prepared, base_source_dir=base))
    assert not (tmp_path / "out").exists()


def test_a_backend_is_active_around_the_scan_and_its_isolation_record_is_written(tmp_path):
    from contextlib import contextmanager

    seen = []

    class RecordingBackend:
        network_enforced = True

        @contextmanager
        def activate(self):
            seen.append("enter")
            yield
            seen.append("exit")

        def isolation_record(self):
            return {"backend": "oci", "enforced": True, "note": "fixture backend"}

    class ObservingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            seen.append("scan")
            return super().scan(**kwargs)

    bundle = run(tmp_path, ObservingAdapter(), backend=RecordingBackend())
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert seen == ["enter", "scan", "exit"]
    assert execution["schema_version"] == "2.1" and execution["isolation"]["backend"] == "oci"
    assert execution["network_policy"]["enforced"] is True


def test_a_pr_input_without_its_synthetic_commits_is_refused_before_a_bundle_exists(tmp_path):
    import dataclasses

    prepared = dataclasses.replace(prepared_input(tmp_path), mode="pr", pr={"change_set_id": "cs-1"})
    with pytest.raises(ExecutionError, match="base_commit and head_commit"):
        run(tmp_path, FakeAdapter(), prepared)
    assert not (tmp_path / "out").exists()
