"""One frozen run configuration end to end: export, invoke, draft review, score, freeze.

Every repository here is a local fixture created by ``git init``. No network, no model
calls, and no sleeping: the adapter is a fake that returns one claim.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

import pytest

from scaneval import cases
from scaneval.adapters.base import Adapter, AdapterError, NativeOutcome
from scaneval.cli import main
from scaneval.contracts import ContractError, canonical_json, canonical_sha256, load_document
from scaneval.materialize import MaterializationError
from scaneval.runner import MANIFEST_NAME, _write_new, _write_new_text, run_from_config


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
# A lone UTF-16 surrogate: canonical JSON keeps it and every contract check passes it, but UTF-8
# cannot encode it, so it only fails at the moment the bytes are produced.
LONE_SURROGATE = chr(0xD800)
VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
REPAIRED = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=False)\n"
REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
              "assumption, and adds a single-file Python sink for the runner pilot.")


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "upstream"
    (repo / "src").mkdir(parents=True)
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "src" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    return repo, git("rev-parse", "HEAD", cwd=repo)


def write_pack(path: Path, repo: Path, commit: str, *, tree_hash: str | None = None) -> dict:
    pack = cases.new_pack("test", "runner-pilot", "Local fixture pack for the runner tests.")
    snapshot = {
        "snapshot_id": "snap-a", "repository": {"url": str(repo), "name": "widget"}, "commit": commit,
        "reference": "Commit chosen by the test fixture; no advisory is claimed.",
        "languages": ["python"], "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Local fixture repository."},
    }
    if tree_hash:
        snapshot["tree_hash"] = tree_hash
    cases.add_snapshot(pack, snapshot)
    cases.add_case(pack, cases.draft_case(
        "case-a", snapshot_id="snap-a", kind="command_injection",
        description="Caller-controlled command string reaches subprocess with shell=True.",
        represents=REPRESENTS, workload="conventional_application", component_role="application",
        aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                 reference="src/app.py", note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "sink", "note": ""}],
    ))
    cases.save_pack(path, pack)
    return pack


def write_config(path: Path, *, systems: list[dict], run_id: str = "run-pilot", repetitions: int = 1,
                 inputs: list[dict] | None = None, cache_root: str = "cache") -> dict:
    config = {
        "schema_version": "2.0", "run_id": run_id, "pack": "pack.json", "cache_root": cache_root,
        "inputs": inputs or [{"snapshot_id": "snap-a"}], "systems": systems, "repetitions": repetitions,
        "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none",
    }
    path.write_text(canonical_json(config) + "\n", encoding="utf-8")
    return config


def system_entry(system_id: str, adapter: str) -> dict:
    return {"system_id": system_id, "adapter": adapter, "config": {"knob": 1}}


class FakeAdapter(Adapter):
    """Returns one claim on the accepted location. Never touches the network."""

    name = "fake"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})

    def __init__(self, *, prepare_error: str | None = None, prepare_exception: BaseException | None = None,
                 scan_exception: BaseException | None = None):
        self.prepare_error = prepare_error
        self.prepare_exception = prepare_exception
        self.scan_exception = scan_exception
        self.prepared = 0
        self.calls = 0

    def prepare(self, spec, cache_root):
        self.prepared += 1
        if self.prepare_exception is not None:
            raise self.prepare_exception
        if self.prepare_error:
            raise AdapterError(self.prepare_error)
        return {"ruleset": "none", "system": spec.system_id}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        self.calls += 1
        if self.scan_exception is not None:
            raise self.scan_exception
        assert not list(source_dir.rglob("pack.json"))
        native = raw_dir / "native.json"
        native.write_text('{"findings": [{"file": "src/app.py"}]}\n', encoding="utf-8")
        claims = [{"claim_id": "c1", "allegation": "shell=True with a caller-controlled command",
                   "kind": "command_injection", "native_rule_id": "fake.shell", "raw_artifact_id": "native",
                   "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5}}]
        return NativeOutcome(status="success", exit_code=0, command=["fake", "scan"], claims=claims,
                             artifacts=[{"id": "native", "path": native}], tool_versions={"fake": "1.0.0"},
                             capture={"model_requests": "not_applicable"}, notes=["fake run"])


@pytest.fixture
def pilot(tmp_path: Path, upstream) -> dict:
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake")])
    workspace = tmp_path / "work"
    workspace.mkdir()
    return {"config_path": config_path, "pack_path": tmp_path / "pack.json", "repo": repo,
            "commit": commit, "workspace": workspace, "adapter": FakeAdapter()}


def run(pilot: dict, out_dir: Path, **kwargs) -> dict:
    adapters = kwargs.pop("adapters", {"fake": pilot["adapter"]})
    return run_from_config(pilot["config_path"], out_dir, clock=CLOCK, workspace_root=pilot["workspace"],
                           adapters=adapters, **kwargs)


def test_run_writes_a_complete_run_directory_and_leaves_the_source_pack_untouched(tmp_path, pilot):
    source_pack_before = pilot["pack_path"].read_bytes()
    out = tmp_path / "out"
    manifest = run(pilot, out)

    assert pilot["adapter"].prepared == 1 and pilot["adapter"].calls == 1
    bundle = out / "invocations" / "snap-a__fake-a__r1"
    written = {path.relative_to(out).as_posix() for path in out.rglob("*") if path.is_file()}
    assert {"run-config.json", "run-manifest.json", "evaluator/pack.json", "evaluator/schedule.json",
            "inputs/snap-a/provenance.json", "inputs/snap-a/source/src/app.py",
            "invocations/snap-a__fake-a__r1/request.json",
            "invocations/snap-a__fake-a__r1/result.json",
            "invocations/snap-a__fake-a__r1/execution.json",
            "invocations/snap-a__fake-a__r1/evaluator/plan.json",
            "invocations/snap-a__fake-a__r1/evaluator/decisions.json",
            "invocations/snap-a__fake-a__r1/evaluation.json",
            "invocations/snap-a__fake-a__r1/report.html"} <= written

    exported = sorted(path.relative_to(out / "inputs" / "snap-a" / "source").as_posix()
                      for path in (out / "inputs" / "snap-a" / "source").rglob("*") if path.is_file())
    assert exported == ["README.md", "src/app.py"]
    assert pilot["pack_path"].read_bytes() == source_pack_before

    assert json.loads((out / "run-config.json").read_text(encoding="utf-8"))["run_id"] == "run-pilot"
    assert manifest == json.loads((out / "run-manifest.json").read_text(encoding="utf-8"))
    # Every run writes a 2.1 manifest now, whatever version its configuration is: the manifest
    # names the schedule the run froze and records each input's preparation outcome.
    assert manifest["schema_version"] == "2.1" and manifest["run_id"] == "run-pilot"
    assert manifest["schedule_path"] == "evaluator/schedule.json"
    assert manifest["created_at"] == "2026-09-20T15:00:00+00:00"
    assert manifest["config_sha256"] == canonical_sha256(
        load_document(pilot["config_path"], "run-config"))
    assert manifest["pack"]["review_states"] == {"draft": 0, "mechanically_checked": 1, "human_approved": 0}
    assert manifest["systems"] == [{"system_id": "fake-a", "adapter": "fake", "adapter_version": "1.0.0",
                                    "preparation": {"ruleset": "none", "system": "fake-a"},
                                    "skipped_reason": None}]
    [recorded_input] = manifest["inputs"]
    assert recorded_input["provenance_path"] == "inputs/snap-a/provenance.json"
    assert recorded_input["tree_hash"].startswith("sha256:")
    assert (recorded_input["input_id"], recorded_input["snapshot_id"], recorded_input["mode"],
            recorded_input["profile"]) == ("snap-a", "snap-a", "full", "standard")
    assert recorded_input["input_hash"] == recorded_input["tree_hash"]
    assert recorded_input["preparation_failure"] is None
    assert [outcome["case_id"] for outcome in recorded_input["mechanical_checks"]] == ["case-a"]
    assert recorded_input["mechanical_checks"][0]["passed"] is True
    [invocation] = manifest["invocations"]
    assert invocation == {"invocation_id": "snap-a__fake-a__r1", "input_id": "snap-a", "system_id": "fake-a",
                          "repetition": 1, "status": "success", "claim_records": 1, "plan_scope": "draft",
                          "targets_assigned": 1, "targets_detected": 0, "pending_matching_count": 1,
                          "bundle_path": "invocations/snap-a__fake-a__r1", "review_state": "draft",
                          "skipped_reason": None}
    assert bundle.is_dir() and not list(bundle.glob("pack.json"))


def test_mechanical_checks_land_only_in_the_frozen_pack_copy_and_keep_the_plan_draft(tmp_path, pilot):
    out = tmp_path / "out"
    run(pilot, out)

    source_pack = json.loads(pilot["pack_path"].read_text(encoding="utf-8"))
    frozen = json.loads((out / "evaluator" / "pack.json").read_text(encoding="utf-8"))
    assert source_pack["cases"][0]["validation"] == {"level": None, "review_state": "draft",
                                                     "checks": [], "reviews": []}
    assert source_pack["snapshots"][0]["tree_hash"] is None
    frozen_validation = frozen["cases"][0]["validation"]
    assert frozen_validation["review_state"] == "mechanically_checked" and frozen_validation["level"] == "L1"
    assert {check["check"] for check in frozen_validation["checks"]} == {
        "locations_exist_in_snapshot", "line_ranges_within_files", "aliases_well_formed",
        "represents_statement", "evidence_recorded", "snapshot_hash_recorded"}
    assert frozen_validation["reviews"] == []
    assert frozen["snapshots"][0]["tree_hash"] == json.loads(
        (out / "run-manifest.json").read_text(encoding="utf-8"))["inputs"][0]["tree_hash"]

    bundle = out / "invocations" / "snap-a__fake-a__r1"
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    assert plan["scope"] == "draft"
    assert [target["validation_level"] for target in plan["targets"]] == ["L1"]
    assert plan["provenance"]["pack_sha256"] == canonical_sha256(frozen)


def test_draft_decisions_stay_unresolved_and_earn_no_detection_credit(tmp_path, pilot):
    out = tmp_path / "out"
    run(pilot, out)
    bundle = out / "invocations" / "snap-a__fake-a__r1"

    decisions = load_document(bundle / "evaluator" / "decisions.json", "review-decisions")
    assert [(match["claim_id"], match["target_id"], match["decision"]) for match in decisions["claim_matches"]] == [
        ("c1", "T-case-a", "unresolved")]
    assert all(match["decision"] != "accepted" for match in decisions["claim_matches"])

    evaluation = json.loads((bundle / "evaluation.json").read_text(encoding="utf-8"))
    assert evaluation["metrics"]["targets_detected"] == 0
    assert evaluation["metrics"]["pending_matching_count"] == 1
    assert "Draft labels (not independently reviewed): pipeline diagnostics, not benchmark evidence." \
        in evaluation["warnings"]
    report = (bundle / "report.html").read_text(encoding="utf-8")
    assert '<p class="notice">Draft labels.' in report
    assert "not independently reviewed" in report


def test_bundle_evaluation_is_byte_identical_to_an_offline_replay(tmp_path, pilot):
    out = tmp_path / "out"
    run(pilot, out)
    bundle = out / "invocations" / "snap-a__fake-a__r1"
    replayed = tmp_path / "replayed.json"

    assert main(["replay", str(bundle), "--output", str(replayed)]) == 0
    assert replayed.read_bytes() == (bundle / "evaluation.json").read_bytes()


def test_existing_output_directory_and_unknown_filters_are_refused(tmp_path, pilot):
    out = tmp_path / "out"
    run(pilot, out)
    with pytest.raises(FileExistsError):
        run(pilot, out)

    with pytest.raises(ContractError, match="systems not present"):
        run(pilot, tmp_path / "other", only_systems={"absent"})
    with pytest.raises(ContractError, match="inputs not present"):
        run(pilot, tmp_path / "other", only_inputs={"snap-z"})
    assert not (tmp_path / "other").exists()


def test_a_declared_tree_hash_that_does_not_match_the_export_is_refused(tmp_path, upstream):
    """The input is refused, and the refusal is recorded against it rather than failing the run.

    This used to raise out of the run. An input whose preparation fails is now a recorded
    preparation failure (its provenance, written before the hash was compared, stays named) and
    its assignment is a skipped invocation, so no scanner is ever handed the export.
    """
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit, tree_hash="sha256:" + "0" * 64)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake")])
    adapter = FakeAdapter()

    manifest = run_from_config(config_path, tmp_path / "out", clock=CLOCK, adapters={"fake": adapter})

    assert manifest["status"] == "completed" and adapter.calls == 0
    [recorded] = manifest["inputs"]
    assert recorded["preparation_failure"]["type"] == "ContractError"
    assert "declares tree hash" in recorded["preparation_failure"]["message"]
    assert recorded["tree_hash"] is None and recorded["input_hash"] is None
    assert recorded["provenance_path"] == "inputs/snap-a/provenance.json"
    assert recorded["mechanical_checks"] == []
    [row] = manifest["invocations"]
    assert row["status"] == "skipped" and row["bundle_path"] is None
    assert row["skipped_reason"].startswith("input snap-a could not be prepared: ContractError: ")


def test_an_adapter_that_cannot_prepare_is_skipped_while_the_other_system_still_runs(tmp_path, upstream):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("broken-b", "broken")])
    working = FakeAdapter()
    broken = FakeAdapter(prepare_error="ruleset checkout is missing")
    out = tmp_path / "out"

    manifest = run_from_config(config_path, out, clock=CLOCK,
                               adapters={"fake": working, "broken": broken})

    assert working.calls == 1 and broken.calls == 0
    reason = "AdapterError: ruleset checkout is missing"
    assert [system["skipped_reason"] for system in manifest["systems"]] == [None, reason]
    assert manifest["systems"][1]["adapter_version"] == "1.0.0" and manifest["systems"][1]["preparation"] == {}
    statuses = [(row["system_id"], row["status"], row["bundle_path"]) for row in manifest["invocations"]]
    assert statuses == [("fake-a", "success", "invocations/snap-a__fake-a__r1"),
                        ("broken-b", "skipped", None)]
    assert manifest["invocations"][1]["skipped_reason"] == reason
    assert f"broken-b: not invoked ({reason})" in manifest["warnings"]
    assert not (out / "invocations" / "snap-a__broken-b__r1").exists()


def test_only_systems_narrows_the_run_and_repetitions_are_separate_invocations(tmp_path, upstream):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("fake-b", "fake")],
                 repetitions=2)
    adapter = FakeAdapter()

    manifest = run_from_config(config_path, tmp_path / "out", clock=CLOCK, adapters={"fake": adapter},
                               only_systems={"fake-b"}, only_inputs={"snap-a"})

    assert [system["system_id"] for system in manifest["systems"]] == ["fake-b"]
    assert [(row["system_id"], row["repetition"]) for row in manifest["invocations"]] == [
        ("fake-b", 1), ("fake-b", 2)]
    assert adapter.prepared == 1 and adapter.calls == 2
    assert sorted(path.name for path in (tmp_path / "out" / "invocations").iterdir()) == [
        "snap-a__fake-b__r1", "snap-a__fake-b__r2"]


@pytest.mark.parametrize(
    ("failure", "message"),
    [(MaterializationError, "git fetch of the pinned ruleset failed"),
     (OSError, "ruleset directory is unreadable")],
    ids=["materialization", "oserror"],
)
def test_a_system_whose_preparation_fails_is_skipped_while_the_others_run(tmp_path, upstream, failure, message):
    """A preparation failure is recorded as a skip, never as an empty successful scan."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("broken-b", "broken")])
    working = FakeAdapter()
    broken = FakeAdapter(prepare_exception=failure(message))
    out = tmp_path / "out"

    manifest = run_from_config(config_path, out, clock=CLOCK, adapters={"fake": working, "broken": broken})

    reason = f"{failure.__name__}: {message}"
    assert working.calls == 1 and broken.calls == 0
    assert [system["skipped_reason"] for system in manifest["systems"]] == [None, reason]
    assert [(row["system_id"], row["status"], row["bundle_path"]) for row in manifest["invocations"]] == [
        ("fake-a", "success", "invocations/snap-a__fake-a__r1"), ("broken-b", "skipped", None)]
    assert f"broken-b: not invoked ({reason})" in manifest["warnings"]
    assert not (out / "invocations" / "snap-a__broken-b__r1").exists()
    assert manifest["status"] == "completed"


def test_colliding_invocation_ids_are_refused_before_the_output_directory_exists(tmp_path, pilot):
    """Two distinct triples that join into one id would share a bundle directory."""
    config_path = tmp_path / "colliding.json"
    write_config(config_path, systems=[system_entry("a__b", "fake"), system_entry("b", "fake")],
                 inputs=[{"snapshot_id": "snap"}, {"snapshot_id": "snap__a"}])
    out = tmp_path / "out"

    with pytest.raises(ContractError, match="invocation id 'snap__a__b__r1' is produced by both"):
        run_from_config(config_path, out, clock=CLOCK, workspace_root=pilot["workspace"],
                        adapters={"fake": pilot["adapter"]})
    assert not out.exists()
    assert pilot["adapter"].prepared == 0


def test_a_workspace_root_inside_evaluator_storage_is_refused(tmp_path, pilot):
    """The scanner's private workspace may not sit in the run output, the cache, or an export."""
    out = tmp_path / "out"
    for workspace in (out, out / "inputs" / "snap-a" / "trial", tmp_path / "cache" / "w"):
        with pytest.raises(ContractError, match="workspace_root"):
            run_from_config(pilot["config_path"], out, clock=CLOCK, workspace_root=workspace,
                            adapters={"fake": pilot["adapter"]})
        assert not out.exists()
    assert pilot["adapter"].prepared == 0


def test_an_interrupt_on_the_second_invocation_leaves_a_failed_manifest_listing_the_first(tmp_path, upstream):
    """A run stopped part way still records what finished, and the failure is not a scan outcome."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("crash-b", "crash")])
    interrupted = FakeAdapter(scan_exception=KeyboardInterrupt("the operator stopped the run"))
    out = tmp_path / "out"

    with pytest.raises(KeyboardInterrupt, match="the operator stopped the run"):
        run_from_config(config_path, out, clock=CLOCK, adapters={"fake": FakeAdapter(), "crash": interrupted})

    manifest = load_document(out / MANIFEST_NAME, "run-manifest")
    assert manifest["status"] == "failed"
    assert manifest["failure"] == {"type": "KeyboardInterrupt", "message": "the operator stopped the run"}
    assert [(row["invocation_id"], row["status"]) for row in manifest["invocations"]] == [
        ("snap-a__fake-a__r1", "success")]
    assert [system["system_id"] for system in manifest["systems"]] == ["fake-a", "crash-b"]
    assert (out / "invocations" / "snap-a__fake-a__r1" / "evaluation.json").is_file()
    assert not (out / "invocations" / "snap-a__crash-b__r1" / "result.json").exists()


def test_an_adapter_exception_is_an_error_invocation_and_the_run_still_completes(tmp_path, upstream):
    """A scanner that crashes yields a recorded error bundle, not a lost or empty invocation."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("crash-b", "crash")])
    crashing = FakeAdapter(scan_exception=RuntimeError("the harness died mid scan"))
    out = tmp_path / "out"

    manifest = run_from_config(config_path, out, clock=CLOCK,
                               adapters={"fake": FakeAdapter(), "crash": crashing})

    assert manifest["status"] == "completed"
    assert [(row["invocation_id"], row["status"]) for row in manifest["invocations"]] == [
        ("snap-a__fake-a__r1", "success"), ("snap-a__crash-b__r1", "error")]
    result = load_document(out / "invocations" / "snap-a__crash-b__r1" / "result.json", "scan-result")
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"] == {"code": "adapter_failure",
                               "message": "RuntimeError: the harness died mid scan"}


def test_a_failing_export_is_recorded_against_its_input_and_never_invokes_a_system(tmp_path, upstream):
    """A pinned commit the repository cannot supply fails that input, not the run.

    This used to leave a failed manifest with nothing in it. The failure is now the input's own
    record: the run completes, the input's row carries the error, its assignment is a skipped
    invocation naming it, and the adapter is never called for it.
    """
    repo, _commit = upstream
    write_pack(tmp_path / "pack.json", repo, "f" * 40)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake")])
    adapter = FakeAdapter()
    out = tmp_path / "out"

    manifest = run_from_config(config_path, out, clock=CLOCK, adapters={"fake": adapter})

    assert load_document(out / MANIFEST_NAME, "run-manifest") == manifest
    assert manifest["status"] == "completed" and "failure" not in manifest
    [recorded] = manifest["inputs"]
    assert recorded["preparation_failure"]["type"] == "MaterializationError"
    assert "git" in recorded["preparation_failure"]["message"]
    assert (recorded["tree_hash"], recorded["provenance_path"], recorded["mechanical_checks"]) == (None, None, [])
    [row] = manifest["invocations"]
    assert row["status"] == "skipped" and row["bundle_path"] is None
    assert row["skipped_reason"] == ("input snap-a could not be prepared: MaterializationError: "
                                     + recorded["preparation_failure"]["message"])
    assert adapter.calls == 0
    assert not (out / "invocations").exists()
    # The run still froze its pack and its schedule; nothing about the input was invented.
    assert (out / "evaluator" / "pack.json").is_file() and (out / "evaluator" / "schedule.json").is_file()


def test_an_input_snapshot_the_pack_does_not_declare_is_refused_before_the_output_exists(tmp_path, pilot):
    """The configuration names the snapshot; only the pack can say what that snapshot is."""
    config_path = tmp_path / "absent-input.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake")], inputs=[{"snapshot_id": "snap-z"}])
    out = tmp_path / "out"

    with pytest.raises(ContractError, match="unknown snapshot 'snap-z'"):
        run_from_config(config_path, out, clock=CLOCK, workspace_root=pilot["workspace"],
                        adapters={"fake": pilot["adapter"]})

    assert not out.exists()
    assert pilot["adapter"].prepared == 0 and pilot["adapter"].calls == 0


def test_a_cache_root_overlapping_the_output_is_refused_before_the_output_exists(tmp_path, pilot):
    """The immutable source cache and the run output may not contain one another."""
    inside = tmp_path / "inside.json"
    write_config(inside, systems=[system_entry("fake-a", "fake")], cache_root="out/cache")
    out = tmp_path / "out"
    with pytest.raises(ContractError, match="cache_root .* resolves inside the run output directory"):
        run_from_config(inside, out, clock=CLOCK, adapters={"fake": pilot["adapter"]})
    assert not out.exists()

    with pytest.raises(ContractError, match="resolves inside cache_root"):
        run_from_config(pilot["config_path"], tmp_path / "cache" / "run", clock=CLOCK,
                        adapters={"fake": pilot["adapter"]})
    assert not (tmp_path / "cache" / "run").exists()
    assert pilot["adapter"].prepared == 0


def test_an_adapter_module_that_is_not_installed_is_a_skipped_system(tmp_path, upstream, monkeypatch):
    """Resolution failure is a skip with its own type and message, never an empty scan."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("absent-b", "absent")])

    def resolve(name: str):
        raise ModuleNotFoundError(f"No module named 'scaneval.adapters.{name}'")

    monkeypatch.setattr("scaneval.runner.get_adapter", resolve)
    manifest = run_from_config(config_path, tmp_path / "out", clock=CLOCK, adapters={"fake": FakeAdapter()})

    reason = "ModuleNotFoundError: No module named 'scaneval.adapters.absent'"
    assert manifest["status"] == "completed"
    assert manifest["systems"][1] == {"system_id": "absent-b", "adapter": "absent", "adapter_version": None,
                                      "preparation": {}, "skipped_reason": reason}
    assert [(row["system_id"], row["status"]) for row in manifest["invocations"]] == [
        ("fake-a", "success"), ("absent-b", "skipped")]
    assert f"absent-b: not invoked ({reason})" in manifest["warnings"]


def test_a_preparation_that_reports_no_record_is_a_skipped_system(tmp_path, upstream):
    """The manifest records what preparation produced, so a non-record preparation is a failure."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("odd-a", "odd")])

    class OddAdapter(FakeAdapter):
        def prepare(self, spec, cache_root):
            self.prepared += 1
            return "ruleset ready"

    manifest = run_from_config(config_path, tmp_path / "out", clock=CLOCK, adapters={"odd": OddAdapter()})

    [system] = manifest["systems"]
    assert system["preparation"] == {}
    assert system["skipped_reason"] == ("AdapterError: odd.prepare returned str; a preparation "
                                        "phase must report what it prepared as a record")
    assert [row["status"] for row in manifest["invocations"]] == ["skipped"]


def test_the_bundle_report_carries_the_machine_drafted_review_banner(tmp_path, pilot):
    """The runner writes the decisions, so the report states that no human reviewed them."""
    out = tmp_path / "out"
    run(pilot, out)

    html = (out / "invocations" / "snap-a__fake-a__r1" / "report.html").read_text(encoding="utf-8")
    assert '<p class="notice">Decisions: machine-drafted, all unresolved; no human review recorded.</p>' in html
    assert "recorded human review" not in html


def test_the_manifest_records_which_inputs_and_systems_the_run_covered(tmp_path, upstream):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("fake-b", "fake")])

    narrowed = run_from_config(config_path, tmp_path / "narrow", clock=CLOCK, adapters={"fake": FakeAdapter()},
                               only_systems={"fake-b"}, only_inputs={"snap-a"})
    assert narrowed["selection"] == {"only_inputs": ["snap-a"], "only_systems": ["fake-b"],
                                     "excluded_inputs": [], "excluded_systems": ["fake-a"]}

    whole = run_from_config(config_path, tmp_path / "whole", clock=CLOCK, adapters={"fake": FakeAdapter()})
    assert whole["selection"] == {"only_inputs": None, "only_systems": None,
                                  "excluded_inputs": [], "excluded_systems": []}


def test_the_written_manifest_validates_against_the_run_manifest_contract(tmp_path, pilot):
    out = tmp_path / "out"
    manifest = run(pilot, out)

    assert load_document(out / MANIFEST_NAME, "run-manifest") == manifest
    assert manifest["status"] == "completed" and "failure" not in manifest
    assert manifest["invocations"][0]["bundle_path"] == "invocations/snap-a__fake-a__r1"


def test_the_frozen_pack_is_written_once_before_the_first_invocation(tmp_path, pilot):
    """The frozen copy already carries the checks the first invocation planned against."""
    frozen: list[bytes] = []

    class RecordingAdapter(FakeAdapter):
        def scan(self, **kwargs):
            frozen.append((out / "evaluator" / "pack.json").read_bytes())
            return super().scan(**kwargs)

    out = tmp_path / "out"
    adapter = RecordingAdapter()
    manifest = run(pilot, out, adapters={"fake": adapter})

    assert len(frozen) == 1
    assert frozen[0] == (out / "evaluator" / "pack.json").read_bytes()
    checked = json.loads(frozen[0])["cases"][0]["validation"]
    assert checked["review_state"] == "mechanically_checked" and checked["level"] == "L1"
    assert manifest["pack"]["sha256"] == canonical_sha256(json.loads(frozen[0]))


def repaired_commit(repo: Path) -> str:
    """A second local commit whose ``src/app.py`` no longer builds a shell string."""
    (repo / "src" / "app.py").write_text(REPAIRED, encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "repair", cwd=repo)
    return git("rev-parse", "HEAD", cwd=repo)


def write_two_snapshot_pack(path: Path, repo: Path, commit: str, repaired: str) -> dict:
    """One case whose target is on the vulnerable snapshot and whose control is on the repaired one."""
    pack = cases.new_pack("test", "runner-pilot", "Local fixture pack spanning two snapshots.")
    base = {"repository": {"url": str(repo), "name": "widget"},
            "reference": "Commit chosen by the test fixture; no advisory is claimed.",
            "languages": ["python"], "workload": "conventional_application", "component_role": "application",
            "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}}
    cases.add_snapshot(pack, {**base, "snapshot_id": "snap-a", "commit": commit})
    cases.add_snapshot(pack, {**base, "snapshot_id": "snap-fixed", "commit": repaired, "role": "fixed"})
    case = cases.draft_case(
        "case-a", snapshot_id="snap-a", kind="command_injection",
        description="Caller-controlled command string reaches subprocess with shell=True.",
        represents=REPRESENTS, workload="conventional_application", component_role="application",
        aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                 reference="src/app.py", note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "sink", "note": ""}],
    )
    case["controls"].append({
        "control_id": "C-case-a-fixed", "snapshot_id": "snap-fixed", "type": "fixed_target",
        "target_id": "T-case-a", "description": "The repaired call passes an argument list.",
        "property": "No shell string is built at this call site.",
        "allowed_actors_inputs": "The same callers as the vulnerable snapshot.",
        "assumptions": ["Default deployment."],
        "ruled_out_allegation": "Caller-controlled shell interpolation at this call site.",
        "locations": [{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "operation", "note": ""}],
        "evidence_ids": ["source"],
    })
    cases.add_case(pack, case)
    cases.save_pack(path, pack)
    return pack


def test_a_run_whose_output_sits_under_a_symlinked_parent_completes(tmp_path, pilot):
    """macOS puts /tmp behind a symlink, and the bundle writer refuses a path that resolves away."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    manifest = run(pilot, link / "out")

    out = real / "out"
    assert manifest["status"] == "completed"
    assert [(row["status"], row["bundle_path"]) for row in manifest["invocations"]] == [
        ("success", "invocations/snap-a__fake-a__r1")]
    assert load_document(out / MANIFEST_NAME, "run-manifest") == manifest
    bundle = out / "invocations" / "snap-a__fake-a__r1"
    assert (bundle / "evaluator" / "plan.json").is_file() and (bundle / "evaluation.json").is_file()
    assert (out / "evaluator" / "pack.json").is_file()


def test_a_document_canonical_json_cannot_represent_leaves_no_file_behind(tmp_path):
    """The serialization must fail before the file exists; an empty file would read as a record."""
    path = tmp_path / "run-manifest.json"

    with pytest.raises(ContractError, match="not canonical JSON"):
        _write_new(path, {"warnings": {"a", "b"}})

    assert not path.exists()


def test_a_document_utf8_cannot_encode_leaves_no_file_behind(tmp_path):
    """The encoding must fail before the file exists; an empty file would read as a record."""
    path = tmp_path / "run-manifest.json"

    with pytest.raises(ContractError, match="is not UTF-8 text"):
        _write_new(path, {"warnings": [f"lone surrogate {LONE_SURROGATE}"]})

    assert not path.exists()

    report = tmp_path / "report.html"
    with pytest.raises(ContractError, match="is not UTF-8 text"):
        _write_new_text(report, f"<p>lone surrogate {LONE_SURROGATE}</p>")

    assert not report.exists()


@pytest.mark.parametrize(
    ("attribute", "value", "shown"),
    [("name", "", "''"), ("adapter_version", 1.0, "1.0")],
    ids=["empty-name", "float-version"],
)
def test_an_adapter_identity_the_records_cannot_carry_is_a_skipped_system(tmp_path, upstream, attribute,
                                                                          value, shown):
    """The manifest and every execution record copy these two attributes verbatim.

    An adapter declaring a float version made every one of its execution records unwritable, so
    vetting it at preparation time is what keeps that from failing the whole run.
    """
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("odd-b", "odd")])
    odd = type("OddIdentityAdapter", (FakeAdapter,), {attribute: value})()
    out = tmp_path / "out"

    manifest = run_from_config(config_path, out, clock=CLOCK, adapters={"fake": FakeAdapter(), "odd": odd})

    assert manifest["status"] == "completed" and odd.prepared == 0 and odd.calls == 0
    assert manifest["systems"][1]["skipped_reason"] == (
        f"AdapterError: odd.{attribute} must be a non-empty string, not {shown}; the run manifest "
        "and every execution record copy it verbatim")
    assert manifest["systems"][1]["adapter_version"] == (None if attribute == "adapter_version" else "1.0.0")
    assert manifest["systems"][1]["preparation"] == {}
    assert [(row["system_id"], row["status"]) for row in manifest["invocations"]] == [
        ("fake-a", "success"), ("odd-b", "skipped")]
    assert load_document(out / MANIFEST_NAME, "run-manifest") == manifest
    assert not (out / "invocations" / "snap-a__odd-b__r1").exists()


@pytest.mark.parametrize(
    ("record", "fragment"),
    [({"ruleset": {"paths"}}, "Object of type set is not JSON serializable"),
     ({"ruleset": {"cost_usd": float("inf")}}, "odd.prepare record.ruleset.cost_usd contains a non-finite number"),
     ({"ruleset": f"lone surrogate {LONE_SURROGATE}"}, "odd.prepare record is not UTF-8 text")],
    ids=["not-json", "non-finite", "not-utf8"],
)
def test_a_preparation_record_the_manifest_cannot_carry_is_a_skipped_system(tmp_path, upstream, record, fragment):
    """The record is copied into the manifest verbatim, so an unwritable one is a preparation failure."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("odd-b", "odd")])

    class OddAdapter(FakeAdapter):
        def prepare(self, spec, cache_root):
            self.prepared += 1
            return record

    odd = OddAdapter()
    out = tmp_path / "out"
    manifest = run_from_config(config_path, out, clock=CLOCK, adapters={"fake": FakeAdapter(), "odd": odd})

    assert manifest["status"] == "completed" and odd.calls == 0
    assert manifest["systems"][1]["preparation"] == {}
    assert fragment in manifest["systems"][1]["skipped_reason"]
    assert manifest["systems"][1]["skipped_reason"].startswith("ContractError: ")
    assert [(row["system_id"], row["status"]) for row in manifest["invocations"]] == [
        ("fake-a", "success"), ("odd-b", "skipped")]
    assert load_document(out / MANIFEST_NAME, "run-manifest") == manifest
    assert not (out / "invocations" / "snap-a__odd-b__r1").exists()


def test_a_preparation_failure_whose_message_utf8_cannot_encode_is_still_a_skipped_system(tmp_path, upstream):
    """The skip reason goes into the manifest verbatim, so a surrogate there destroyed the record.

    The exception came from the adapter, so its message is escaped rather than trusted: an
    unencodable reason made the whole run unrecordable, including its partial manifest.
    """
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("odd-b", "odd")])
    odd = FakeAdapter(prepare_exception=AdapterError(f"ruleset {LONE_SURROGATE} is missing"))
    out = tmp_path / "out"

    manifest = run_from_config(config_path, out, clock=CLOCK, adapters={"fake": FakeAdapter(), "odd": odd})

    assert manifest["status"] == "completed" and odd.calls == 0
    reason = manifest["systems"][1]["skipped_reason"]
    assert reason == "AdapterError: ruleset \\ud800 is missing" and LONE_SURROGATE not in reason
    assert f"odd-b: not invoked ({reason})" in manifest["warnings"]
    assert [(row["system_id"], row["status"]) for row in manifest["invocations"]] == [
        ("fake-a", "success"), ("odd-b", "skipped")]
    assert load_document(out / MANIFEST_NAME, "run-manifest") == manifest


@pytest.mark.parametrize(
    ("attribute", "value", "fragment"),
    [("env_passthrough", "PATH",
      "odd.env_passthrough must be a tuple, list, or set of non-empty strings, not 'PATH'"),
     ("env_passthrough", ("PATH", 3), "odd.env_passthrough must hold non-empty strings, not 3"),
     ("state_dirs", None,
      "odd.state_dirs must be a tuple, list, or set of non-empty strings, not None"),
     ("state_dirs", (".fakestate", ""), "odd.state_dirs must hold non-empty strings, not ''")],
    ids=["env-passthrough-string", "env-passthrough-entry", "state-dirs-none", "state-dirs-empty"],
)
def test_an_adapter_attribute_every_execution_record_copies_is_a_skipped_system(tmp_path, upstream,
                                                                                attribute, value, fragment):
    """Every execution record copies env_passthrough and walks state_dirs, so both are vetted here.

    A bad value failed every invocation of that system with an error naming neither the adapter
    nor the attribute, and the string ``"PATH"`` quietly meant four one-letter variable names.
    """
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("odd-b", "odd")])
    odd = type("OddAttributeAdapter", (FakeAdapter,), {attribute: value})()
    out = tmp_path / "out"

    manifest = run_from_config(config_path, out, clock=CLOCK, adapters={"fake": FakeAdapter(), "odd": odd})

    assert manifest["status"] == "completed" and odd.prepared == 0 and odd.calls == 0
    reason = manifest["systems"][1]["skipped_reason"]
    assert reason.startswith("AdapterError: ") and fragment in reason
    assert manifest["systems"][1]["preparation"] == {}
    assert [(row["system_id"], row["status"]) for row in manifest["invocations"]] == [
        ("fake-a", "success"), ("odd-b", "skipped")]
    assert load_document(out / MANIFEST_NAME, "run-manifest") == manifest
    assert not (out / "invocations" / "snap-a__odd-b__r1").exists()


def test_a_two_input_run_records_the_state_and_notes_of_the_plan_it_actually_built(tmp_path, upstream):
    """A case spanning both inputs is complete only after both are checked, so the manifest waits."""
    repo, commit = upstream
    repaired = repaired_commit(repo)
    write_two_snapshot_pack(tmp_path / "pack.json", repo, commit, repaired)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake")],
                 inputs=[{"snapshot_id": "snap-a"}, {"snapshot_id": "snap-fixed"}])
    out = tmp_path / "out"

    manifest = run_from_config(config_path, out, clock=CLOCK, adapters={"fake": FakeAdapter()})

    assert manifest["status"] == "completed"
    assert [recorded["snapshot_id"] for recorded in manifest["inputs"]] == ["snap-a", "snap-fixed"]
    for recorded in manifest["inputs"]:
        assert [(o["case_id"], o["passed"], o["review_state"], o["level"])
                for o in recorded["mechanical_checks"]] == [("case-a", True, "mechanically_checked", "L1")]
    assert all("not planned" not in warning for warning in manifest["warnings"])

    frozen = cases.load_pack(out / "evaluator" / "pack.json")
    expected: list[str] = []
    planned: dict[str, dict] = {}
    for recorded in manifest["inputs"]:
        plan, notes = cases.build_plan(frozen, recorded["snapshot_id"], recorded["tree_hash"], mode="full")
        planned[recorded["snapshot_id"]] = plan
        expected += [f"{recorded['snapshot_id']}: {note}" for note in notes]
    assert manifest["warnings"] == expected

    for snapshot_id, plan in planned.items():
        written = load_document(out / "invocations" / f"{snapshot_id}__fake-a__r1" / "evaluator" / "plan.json",
                                "evaluation-plan")
        assert written == plan
    assert [target["target_id"] for target in planned["snap-a"]["targets"]] == ["T-case-a"]
    assert [control["control_id"] for control in planned["snap-fixed"]["controls"]] == ["C-case-a-fixed"]
    assert [(row["input_id"], row["targets_assigned"]) for row in manifest["invocations"]] == [
        ("snap-a", 1), ("snap-fixed", 0)]


def test_a_second_input_that_fails_to_export_still_leaves_the_first_one_recorded(tmp_path, upstream):
    """The first input is recorded and now also runs; the second is recorded as unprepared.

    This used to end the run with a failed manifest listing only the first input. A preparation
    failure is the input's own record now, so the run continues without it, and the label state
    recorded for the first input is still the one the incomplete check set supports.
    """
    repo, commit = upstream
    repaired_commit(repo)
    write_two_snapshot_pack(tmp_path / "pack.json", repo, commit, "f" * 40)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake")],
                 inputs=[{"snapshot_id": "snap-a"}, {"snapshot_id": "snap-fixed"}])
    adapter = FakeAdapter()
    out = tmp_path / "out"

    manifest = run_from_config(config_path, out, clock=CLOCK, adapters={"fake": adapter})

    assert load_document(out / MANIFEST_NAME, "run-manifest") == manifest
    assert manifest["status"] == "completed"
    assert [recorded["snapshot_id"] for recorded in manifest["inputs"]] == ["snap-a", "snap-fixed"]
    # snap-fixed was never checked, so the case is still short of a complete check set.
    assert [(o["case_id"], o["passed"], o["review_state"], o["level"])
            for o in manifest["inputs"][0]["mechanical_checks"]] == [("case-a", True, "draft", None)]
    assert manifest["inputs"][0]["preparation_failure"] is None
    assert manifest["inputs"][1]["preparation_failure"]["type"] == "MaterializationError"
    assert manifest["inputs"][1]["mechanical_checks"] == []
    assert [(row["invocation_id"], row["status"]) for row in manifest["invocations"]] == [
        ("snap-a__fake-a__r1", "success"), ("snap-fixed__fake-a__r1", "skipped")]
    assert adapter.prepared == 1 and adapter.calls == 1
    assert any(warning.startswith("snap-fixed: not prepared (MaterializationError: ")
               for warning in manifest["warnings"])
