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

from sastbench import cases
from sastbench.adapters.base import Adapter, AdapterError, NativeOutcome
from sastbench.cli import main
from sastbench.contracts import ContractError, canonical_json, canonical_sha256, load_document
from sastbench.materialize import MaterializationError
from sastbench.runner import MANIFEST_NAME, run_from_config


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
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
                 inputs: list[dict] | None = None) -> dict:
    config = {
        "schema_version": "2.0", "run_id": run_id, "pack": "pack.json", "cache_root": "cache",
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
    assert {"run-config.json", "run-manifest.json", "evaluator/pack.json",
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
    assert manifest["schema_version"] == "2.0" and manifest["run_id"] == "run-pilot"
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
    assert "Draft labels (L1/L2, not independently reviewed): pipeline diagnostics, not benchmark evidence." \
        in evaluation["warnings"]
    report = (bundle / "report.html").read_text(encoding="utf-8")
    assert '<p class="notice">Draft labels.' in report
    assert "without independent human review" in report


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
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit, tree_hash="sha256:" + "0" * 64)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake")])

    with pytest.raises(ContractError, match="tree hash"):
        run_from_config(config_path, tmp_path / "out", clock=CLOCK, adapters={"fake": FakeAdapter()})


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
    assert [system["skipped_reason"] for system in manifest["systems"]] == [None, "ruleset checkout is missing"]
    assert manifest["systems"][1]["adapter_version"] == "1.0.0" and manifest["systems"][1]["preparation"] == {}
    statuses = [(row["system_id"], row["status"], row["bundle_path"]) for row in manifest["invocations"]]
    assert statuses == [("fake-a", "success", "invocations/snap-a__fake-a__r1"),
                        ("broken-b", "skipped", None)]
    assert manifest["invocations"][1]["skipped_reason"] == "ruleset checkout is missing"
    assert "broken-b: not invoked (ruleset checkout is missing)" in manifest["warnings"]
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

    assert working.calls == 1 and broken.calls == 0
    assert [system["skipped_reason"] for system in manifest["systems"]] == [None, message]
    assert [(row["system_id"], row["status"], row["bundle_path"]) for row in manifest["invocations"]] == [
        ("fake-a", "success", "invocations/snap-a__fake-a__r1"), ("broken-b", "skipped", None)]
    assert f"broken-b: not invoked ({message})" in manifest["warnings"]
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


def test_a_crash_on_the_second_invocation_leaves_a_failed_manifest_listing_the_first(tmp_path, upstream):
    """A run that raises still records what finished, and the failure is not a scan outcome."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, commit)
    config_path = tmp_path / "run-config.json"
    write_config(config_path, systems=[system_entry("fake-a", "fake"), system_entry("crash-b", "crash")])
    crashing = FakeAdapter(scan_exception=RuntimeError("the harness died mid scan"))
    out = tmp_path / "out"

    with pytest.raises(RuntimeError, match="the harness died mid scan"):
        run_from_config(config_path, out, clock=CLOCK, adapters={"fake": FakeAdapter(), "crash": crashing})

    manifest = load_document(out / MANIFEST_NAME, "run-manifest")
    assert manifest["status"] == "failed"
    assert manifest["failure"] == {"type": "RuntimeError", "message": "the harness died mid scan"}
    assert [(row["invocation_id"], row["status"]) for row in manifest["invocations"]] == [
        ("snap-a__fake-a__r1", "success")]
    assert [system["system_id"] for system in manifest["systems"]] == ["fake-a", "crash-b"]
    assert (out / "invocations" / "snap-a__fake-a__r1" / "evaluation.json").is_file()
    assert not (out / "invocations" / "snap-a__crash-b__r1" / "result.json").exists()


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
