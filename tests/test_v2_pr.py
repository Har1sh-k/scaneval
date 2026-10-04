"""Native PR review through the runner: one invocation per change set, system, and repetition.

The fixture is a local repository with a base commit and a head commit one pull request apart, and
a pack that declares the change set between them and states which of the head's targets and
controls are eligible for it. The only scanners are fake adapters; nothing touches the network,
calls a model, or sleeps. Every approval-shaped fact is drafted by the tool, never a review: the
pack is checked, not approved, so every plan here is a draft and says so.

The change under review holds every kind the diff record names: an edited file that introduces the
sink, an added file, a deleted one, an exact-content rename, and a mode change.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

import pytest

from scaneval import cases, materialize
from scaneval.adapters.base import Adapter, NativeOutcome
from scaneval.cli import main
from scaneval.contracts import (
    ContractError,
    canonical_json,
    load_document,
    pack_anchor_digest,
    pr_input_hash,
)
from scaneval.runner import MANIFEST_NAME, run_from_config
from scaneval.scoring import score


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
FETCH = materialize.fetch_snapshot
SAFE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd)\n"
VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
HELPER = "def helper():\n    return 'shared by the rename'\n"
RUN_SH = "#!/bin/sh\necho run\n"
REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
              "assumption, and adds a single-file Python sink for the PR tests.")
CHANGES = {"added": ["src/new_module.py"], "deleted": ["src/legacy.py"], "modified": ["src/app.py"],
           "renamed": [["lib/util.py", "lib/helpers.py"]], "mode_changed": ["scripts/run.sh"]}


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


def write(root: Path, relative: str, text: str, mode: int = 0o644) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)


@pytest.fixture
def pull_request(tmp_path: Path) -> dict:
    """A repository with a base commit and the head commit of one pull request that changes it."""
    repo = tmp_path / "upstream"
    write(repo, "src/app.py", SAFE)
    write(repo, "src/legacy.py", "print('removed by the pull request')\n")
    write(repo, "lib/util.py", HELPER)
    write(repo, "scripts/run.sh", RUN_SH, 0o644)
    write(repo, "README.md", "fixture\n")
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "base", cwd=repo)
    base = git("rev-parse", "HEAD", cwd=repo)
    write(repo, "src/app.py", VULNERABLE)
    (repo / "src" / "legacy.py").unlink()
    (repo / "lib" / "util.py").rename(repo / "lib" / "helpers.py")
    write(repo, "src/new_module.py", "print('added by the pull request')\n")
    (repo / "scripts" / "run.sh").chmod(0o755)
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "head", cwd=repo)
    return {"repo": repo, "base": base, "head": git("rev-parse", "HEAD", cwd=repo)}


def control(control_id: str, line: int) -> dict:
    return {
        "control_id": control_id, "snapshot_id": "snap-head", "type": "capability_safe",
        "description": f"The helper {control_id} runs a fixed argument list.",
        "property": "No caller-supplied string reaches a shell at this call site.",
        "allowed_actors_inputs": "Operators on the host.", "assumptions": ["Default deployment."],
        "ruled_out_allegation": "Caller-controlled shell interpolation in the helper.",
        "locations": [{"path": "src/app.py", "start_line": line, "end_line": line, "role": "operation"}],
        "evidence_ids": ["source"],
    }


def write_pack(path: Path, fixture: dict, *, eligible: bool = True) -> dict:
    """The pack: two snapshots, one case with a target and two controls, and the change set between them.

    The target and ``C-eligible`` are eligible under ``cs-1``; ``C-outside`` is a control of the same
    case that the change set does not name, so a PR review of it carries no claim about it.
    """
    pack = cases.new_pack("test", "pr-pilot", "Local fixture pack for the PR tests.")
    for snapshot_id, commit in (("snap-base", fixture["base"]), ("snap-head", fixture["head"])):
        cases.add_snapshot(pack, {
            "snapshot_id": snapshot_id, "repository": {"url": str(fixture["repo"]), "name": "widget"},
            "commit": commit, "reference": "Commit chosen by the test fixture; no advisory is claimed.",
            "languages": ["python"], "workload": "conventional_application", "component_role": "application",
            "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}})
    case = cases.draft_case(
        "case-shell", snapshot_id="snap-head", kind="command_injection",
        description="Caller-controlled command string reaches subprocess with shell=True.",
        represents=REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                 reference="src/app.py", note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "sink", "note": ""}])
    case["controls"] += [control("C-eligible", 1), control("C-outside", 4)]
    cases.add_case(pack, case)
    cases.add_change_set(pack, {"change_set_id": "cs-1", "base_snapshot_id": "snap-base",
                                "head_snapshot_id": "snap-head", "boundary": "introducing",
                                "review_scope": "changed_files", "description": "The change that adds the sink."})
    if eligible:
        cases.set_pr_eligibility(pack, "case-shell", "cs-1", "introduced", "changed")
        cases.set_pr_eligibility(pack, "case-shell", "cs-1", "affected", "context", control_id="C-eligible")
    cases.save_pack(path, pack)
    return pack


def write_config(path: Path, *, systems: list[dict], inputs: list[dict] | None = None, repetitions: int = 1,
                 trace_mode: str = "off", version: str = "2.1") -> dict:
    config = {
        "schema_version": version, "run_id": "run-pr", "pack": "pack.json", "cache_root": "cache",
        "inputs": inputs or [{"mode": "pr", "change_set_id": "cs-1"}], "systems": systems,
        "repetitions": repetitions, "timeout_seconds": 60, "trace_mode": trace_mode, "network_policy": "none",
    }
    path.write_text(canonical_json(config) + "\n", encoding="utf-8")
    return config


def system(system_id: str, adapter: str = "fake") -> dict:
    return {"system_id": system_id, "adapter": adapter, "config": {"knob": 1}}


def workspace_git(workspace: Path, *args: str) -> str:
    argv, env = materialize.git_command(list(args))
    return subprocess.run(argv, cwd=str(workspace), env=env, capture_output=True, text=True, check=True).stdout


class PrAdapter(Adapter):
    """Reviews a change: reports one claim on the sink, and looks at the workspace it is handed."""

    name = "fake"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})
    scan_modes = frozenset({"full", "pr"})

    def __init__(self, status: str = "success"):
        self.status = status
        self.calls = 0
        self.seen: list[dict] = []
        self.prepared = 0

    def prepare(self, spec, cache_root):
        self.prepared += 1
        return {"system": spec.system_id}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        self.calls += 1
        pr = request["input"].get("pr")
        seen = {"system": spec.system_id, "request": request, "workspace": source_dir}
        if pr is not None:
            seen.update({
                "name_status": workspace_git(source_dir, "diff", "--name-status", pr["base"], pr["head"]),
                "head": workspace_git(source_dir, "rev-parse", "HEAD").strip(),
                "commits": workspace_git(source_dir, "rev-list", "--count", "HEAD").strip(),
                "status": workspace_git(source_dir, "status", "--porcelain", "--untracked-files=all"),
                "listing": sorted(path.name for path in source_dir.iterdir()),
                "tree": {path.relative_to(source_dir).as_posix(): path.read_text(encoding="utf-8")
                         for path in source_dir.rglob("*") if path.is_file() and ".git" not in path.parts},
            })
        self.seen.append(seen)
        native = raw_dir / "native.json"
        native.write_text('{"findings": [{"file": "src/app.py"}]}\n', encoding="utf-8")
        trace_path = None
        if trace_dir is not None:
            trace_path = Path(trace_dir) / "events.jsonl"
            trace_path.write_text('{"type": "finding.submitted"}\n', encoding="utf-8")
        if self.status != "success":
            return NativeOutcome(status=self.status, exit_code=1, command=["fake", "scan"],
                                 error={"code": "scanner_failed", "message": "the fake scanner failed"})
        claims = [{"claim_id": "c1", "allegation": "shell=True with a caller-controlled command",
                   "kind": "command_injection", "native_rule_id": "fake.shell", "raw_artifact_id": "native",
                   "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5}}]
        return NativeOutcome(status="success", exit_code=0, command=["fake", "scan"], claims=claims,
                             artifacts=[{"id": "native", "path": native}], tool_versions={"fake": "1.0.0"},
                             capture={"finding_submitted": "complete"} if trace_path else {},
                             capture_state={"capture_gap": False, "dropped_events": 0} if trace_path else None,
                             trace_path=trace_path, notes=["fake run"])


class FullOnlyAdapter(PrAdapter):
    """An adapter that declares nothing about modes, so it carries out full scans only."""

    scan_modes = frozenset({"full"})


def run_pr(tmp_path: Path, fixture: dict, *, adapters: dict[str, Adapter] | None = None, systems=None,
           inputs=None, repetitions: int = 1, trace_mode: str = "off", eligible: bool = True) -> tuple[dict, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    write_pack(tmp_path / "pack.json", fixture, eligible=eligible)
    write_config(tmp_path / "run.json", systems=systems or [system("fake-a")], inputs=inputs,
                 repetitions=repetitions, trace_mode=trace_mode)
    out = tmp_path / "out"
    manifest = run_from_config(tmp_path / "run.json", out, clock=CLOCK,
                               adapters=adapters if adapters is not None else {"fake": PrAdapter()})
    return manifest, out


def bundle_of(out: Path, invocation: str) -> Path:
    return out / "invocations" / invocation


# --- one native invocation per change set, system, and repetition ------------------------------------


def test_a_pr_input_runs_once_per_change_set_system_and_repetition(tmp_path, pull_request):
    adapter = PrAdapter()

    manifest, out = run_pr(tmp_path, pull_request, adapters={"fake": adapter}, repetitions=2,
                           systems=[system("fake-a"), system("fake-b")])

    assert manifest["status"] == "completed"
    assert [(row["invocation_id"], row["status"]) for row in manifest["invocations"]] == [
        ("cs-1__fake-a__r1", "success"), ("cs-1__fake-a__r2", "success"),
        ("cs-1__fake-b__r1", "success"), ("cs-1__fake-b__r2", "success")]
    assert adapter.calls == 4, "one native invocation per system and repetition, and never one per changed file"
    frozen = load_document(out / "evaluator" / "schedule.json", "evaluation-schedule")
    assert [row["assignment_id"] for row in frozen["assignments"]] == [row["invocation_id"] for row in manifest["invocations"]]
    assert [row["input_id"] for row in manifest["inputs"]] == ["cs-1"]
    [recorded] = manifest["inputs"]
    assert (recorded["mode"], recorded["snapshot_id"], recorded["change_set_id"]) == ("pr", "snap-head", "cs-1")
    assert recorded["provenance_path"] == "inputs/cs-1/provenance.json" and recorded["preparation_failure"] is None
    assert (out / "inputs" / "cs-1" / "source" / "src" / "app.py").read_text(encoding="utf-8") == VULNERABLE
    assert (out / "inputs" / "cs-1" / "base" / "source" / "src" / "app.py").read_text(encoding="utf-8") == SAFE


def test_the_workspace_git_diff_is_the_recorded_diff_for_every_kind_of_change(tmp_path, pull_request):
    adapter = PrAdapter()

    manifest, out = run_pr(tmp_path, pull_request, adapters={"fake": adapter})

    execution = load_document(bundle_of(out, "cs-1__fake-a__r1") / "execution.json", "execution-record")
    changes = execution["provenance"]["pr"]["changes"]
    assert changes == CHANGES
    [seen] = adapter.seen
    lines = sorted(line.split("\t") for line in seen["name_status"].splitlines())
    assert lines == sorted([["A", "src/new_module.py"], ["D", "src/legacy.py"], ["M", "src/app.py"],
                            ["R100", "lib/util.py", "lib/helpers.py"], ["M", "scripts/run.sh"]])
    assert seen["head"] == execution["provenance"]["pr"]["head_commit"]
    assert seen["commits"] == "2" and seen["status"] == "", "two commits and a clean worktree"
    assert set(seen["listing"]) == {".git", "README.md", "lib", "scripts", "src"}
    assert seen["tree"]["src/app.py"] == VULNERABLE and "src/legacy.py" not in seen["tree"]


def test_the_request_carries_only_the_synthetic_commits(tmp_path, pull_request):
    adapter = PrAdapter()

    manifest, out = run_pr(tmp_path, pull_request, adapters={"fake": adapter})

    [seen] = adapter.seen
    request = seen["request"]
    execution = load_document(bundle_of(out, "cs-1__fake-a__r1") / "execution.json", "execution-record")
    pr = execution["provenance"]["pr"]
    assert request["input"]["mode"] == "pr"
    assert request["input"]["pr"] == {"base": pr["base_commit"], "head": pr["head_commit"]}
    assert pr["base_commit"] not in (pull_request["base"], pull_request["head"])
    assert pr["head_commit"] not in (pull_request["base"], pull_request["head"]), \
        "neither is a real commit of the repository"
    shown = json.dumps(request)
    for private in ("cs-1", "snap-base", "snap-head", pull_request["base"], pull_request["head"], str(tmp_path),
                    pr["diff_sha256"], pr["base_tree_hash"]):
        assert private not in shown
    assert load_document(bundle_of(out, "cs-1__fake-a__r1") / "request.json", "scan-request") == request


def test_the_execution_record_names_the_change_evaluator_side_and_holds_no_path(tmp_path, pull_request):
    manifest, out = run_pr(tmp_path, pull_request)

    execution = load_document(bundle_of(out, "cs-1__fake-a__r1") / "execution.json", "execution-record")
    pr = execution["provenance"]["pr"]
    assert execution["schema_version"] == "2.1" and execution["provenance"]["mode"] == "pr"
    assert {key: pr[key] for key in ("change_set_id", "base_snapshot_id", "head_snapshot_id", "boundary",
                                     "review_scope", "prepared_state")} == {
        "change_set_id": "cs-1", "base_snapshot_id": "snap-base", "head_snapshot_id": "snap-head",
        "boundary": "introducing", "review_scope": "changed_files", "prepared_state": "fresh"}
    assert pr["history"] == {"messages": {"base": "base", "head": "head"},
                             "identity": "ScanEval <scaneval@localhost>", "date": "2000-01-01T00:00:00+00:00"}
    assert execution["provenance"]["synthetic_history"] == {
        "base_commit": pr["base_commit"], "head_commit": pr["head_commit"], **pr["history"]}
    assert execution["provenance"]["input_hash"] == pr_input_hash(pr["base_tree_hash"], pr["head_tree_hash"],
                                                                 pr["diff_sha256"])
    assert execution["provenance"]["tree_hash"] == pr["head_tree_hash"] != pr["base_tree_hash"]
    assert str(tmp_path) not in json.dumps(pr) and str(tmp_path) not in json.dumps(execution["provenance"])
    result = load_document(bundle_of(out, "cs-1__fake-a__r1") / "result.json", "scan-result")
    assert result["schema_version"] == "2.1" and result["location_basis"] == "pr_head"
    assert result["input_hash"] == execution["provenance"]["input_hash"]


def test_the_synthetic_commits_are_computed_once_in_preparation_and_every_workspace_reproduces_them(
        tmp_path, pull_request, monkeypatch):
    calls = []
    compute = materialize.compute_pr_history

    def counting(*args, **kwargs):
        calls.append(args)
        return compute(*args, **kwargs)

    monkeypatch.setattr("scaneval.runner.materialize.compute_pr_history", counting)
    adapter = PrAdapter()

    manifest, out = run_pr(tmp_path, pull_request, adapters={"fake": adapter}, repetitions=2,
                           systems=[system("fake-a"), system("fake-b")])

    assert len(calls) == 1, "once per input, whatever the systems and repetitions"
    requests = {json.dumps(seen["request"]["input"]["pr"], sort_keys=True) for seen in adapter.seen}
    assert len(requests) == 1 and len(adapter.seen) == 4
    assert {seen["head"] for seen in adapter.seen} == {adapter.seen[0]["request"]["input"]["pr"]["head"]}


# --- unsupported: an adapter that cannot review a change is never run on the head ---------------------


def test_an_adapter_without_pr_is_unsupported_and_stays_in_the_denominators(tmp_path, pull_request):
    adapter = FullOnlyAdapter()

    manifest, out = run_pr(tmp_path, pull_request, adapters={"fake": adapter})

    assert adapter.calls == 0, "scan() is never called for a mode the adapter does not declare"
    [row] = manifest["invocations"]
    assert row["status"] == "unsupported" and row["bundle_path"] == "invocations/cs-1__fake-a__r1"
    bundle = bundle_of(out, "cs-1__fake-a__r1")
    result = load_document(bundle / "result.json", "scan-result")
    assert result["status"] == "unsupported" and result["claims"] == []
    assert result["error"]["code"] == "unsupported_mode"
    evaluation = json.loads((bundle / "evaluation.json").read_text(encoding="utf-8"))
    assert evaluation["status"] == "unsupported" and evaluation["metrics"]["completed"] is False
    assert evaluation["metrics"]["targets_assigned"] == 1 and evaluation["metrics"]["targets_detected"] == 0
    controls = evaluation["metrics"]["controls"]["capability_safe"]
    assert (controls["assigned"], controls["completed"], controls["resolved"]) == (1, 0, 0), \
        "the eligible control is assigned and never completed, so it stays in the denominator and earns nothing"


def test_a_system_that_declares_pr_and_one_that_does_not_share_one_run(tmp_path, pull_request):
    reviewer, full_only = PrAdapter(), FullOnlyAdapter()

    manifest, out = run_pr(tmp_path, pull_request, adapters={"fake": reviewer, "full": full_only},
                           systems=[system("fake-a"), system("full-b", "full")])

    assert [(row["system_id"], row["status"]) for row in manifest["invocations"]] == [
        ("fake-a", "success"), ("full-b", "unsupported")]
    assert (reviewer.calls, full_only.calls) == (1, 0)
    assert manifest["status"] == "completed"


# --- the plan: only what the change set names, and what earns nothing ----------------------------------


def test_the_pr_plan_carries_only_the_eligible_items_and_the_out_of_scope_control_is_absent(tmp_path, pull_request):
    manifest, out = run_pr(tmp_path, pull_request)

    bundle = bundle_of(out, "cs-1__fake-a__r1")
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    assert plan["schema_version"] == "2.1" and plan["scope"] == "draft"
    assert plan["review_budgets"] == [5, 10, 20]
    assert [(t["target_id"], t["pr_scope"]) for t in plan["targets"]] == [
        ("T-case-shell", {"relation": "introduced", "code_scope": "changed"})]
    assert [(c["control_id"], c["pr_scope"]) for c in plan["controls"]] == [
        ("C-eligible", {"relation": "affected", "code_scope": "context"})]
    provenance = plan["provenance"]
    execution = load_document(bundle / "execution.json", "execution-record")
    assert provenance["mode"] == "pr" and provenance["input_id"] == "cs-1" and provenance["snapshot_id"] == "snap-head"
    assert provenance["pr"] == {
        "change_set_id": "cs-1", "base_snapshot_id": "snap-base", "head_snapshot_id": "snap-head",
        "base_tree_hash": execution["provenance"]["pr"]["base_tree_hash"],
        "head_tree_hash": execution["provenance"]["pr"]["head_tree_hash"],
        "diff_sha256": execution["provenance"]["pr"]["diff_sha256"], "boundary": "introducing",
        "review_scope": "changed_files", "location_basis": "pr_head"}
    assert plan["input_hash"] == execution["provenance"]["input_hash"]
    # The out-of-scope control is in no evaluator record of this review: it cannot earn anything.
    decisions = load_document(bundle / "evaluator" / "decisions.json", "review-decisions")
    assert [entry["control_id"] for entry in decisions["control_assessments"]] == ["C-eligible"]
    assert "C-outside" not in (bundle / "evaluation.json").read_text(encoding="utf-8")
    assert any("outside change set cs-1" in warning and "C-outside" in warning for warning in manifest["warnings"])


def test_an_eligible_control_still_needs_a_completed_run_and_the_out_of_scope_one_never_counts(tmp_path, pull_request):
    ok, ok_out = run_pr(tmp_path / "ok", pull_request, adapters={"fake": PrAdapter()})
    failed, failed_out = run_pr(tmp_path / "failed", pull_request, adapters={"fake": PrAdapter("error")})

    completed = json.loads((bundle_of(ok_out, "cs-1__fake-a__r1") / "evaluation.json").read_text(encoding="utf-8"))
    errored = json.loads((bundle_of(failed_out, "cs-1__fake-a__r1") / "evaluation.json").read_text(encoding="utf-8"))
    for evaluation in (completed, errored):
        assert evaluation["metrics"]["controls"]["capability_safe"]["assigned"] == 1, \
            "one eligible control, and never the out-of-scope one"
    assert completed["metrics"]["controls"]["capability_safe"]["completed"] == 1
    assert errored["metrics"]["controls"]["capability_safe"]["completed"] == 0, \
        "an eligible control needs a completed run, so an error earns it nothing"
    assert errored["metrics"]["completed"] is False and completed["metrics"]["targets_detected"] == 0, \
        "the machine-drafted decisions confirm nothing"


class OmittingAdapter(PrAdapter):
    """Reviews the change but leaves ``src/app.py`` unexamined, as a scanner's own filter would, and says so."""

    def scan(self, **kwargs):
        outcome = super().scan(**kwargs)
        outcome.omitted_paths = ["src/app.py"]
        return outcome


def quiet_control_score(bundle: Path) -> dict:
    """The control block of *bundle*'s score once a reviewer has assessed its one eligible control quiet."""
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    result = load_document(bundle / "result.json", "scan-result")
    decisions = load_document(bundle / "evaluator" / "decisions.json", "review-decisions")
    [assessment] = decisions["control_assessments"]
    assessment["decision"] = "quiet"
    return score(plan, result, decisions)["metrics"]["controls"]["capability_safe"]


def test_a_quiet_control_on_a_path_the_adapter_reported_omitted_earns_nothing_through_a_whole_run(tmp_path,
                                                                                               pull_request):
    """The plan places the control, the adapter says what its scanner left out, and the scorer reads both off the bundle."""
    _, kept = run_pr(tmp_path / "kept", pull_request)
    _, omitted = run_pr(tmp_path / "omitted", pull_request, adapters={"fake": OmittingAdapter()})
    kept_bundle, omitted_bundle = bundle_of(kept, "cs-1__fake-a__r1"), bundle_of(omitted, "cs-1__fake-a__r1")

    plan = load_document(omitted_bundle / "evaluator" / "plan.json", "evaluation-plan")
    assert [(c["control_id"], c["paths"]) for c in plan["controls"]] == [("C-eligible", ["src/app.py"])]
    result = load_document(omitted_bundle / "result.json", "scan-result")
    assert result["status"] == "success" and result["omitted_paths"] == ["src/app.py"]
    assert "omitted_paths" not in load_document(kept_bundle / "result.json", "scan-result")
    for bundle, resolved in ((kept_bundle, 1), (omitted_bundle, 0)):
        control = quiet_control_score(bundle)
        assert (control["assigned"], control["completed"], control["resolved"]) == (1, 1, resolved)


def schedule_seen_before_the_first_fetch(monkeypatch, out: Path) -> list[dict]:
    """The schedule on disk each time a run fetches a snapshot, which is before anything is exported."""
    seen: list[dict] = []

    def watching(*args, **kwargs):
        seen.append(load_document(out / "evaluator" / "schedule.json", "evaluation-schedule"))
        return FETCH(*args, **kwargs)

    monkeypatch.setattr("scaneval.runner.materialize.fetch_snapshot", watching)
    return seen


def test_pr_eligibility_is_frozen_in_the_schedule_before_execution(tmp_path, pull_request, monkeypatch):
    seen = schedule_seen_before_the_first_fetch(monkeypatch, tmp_path / "out")

    manifest, out = run_pr(tmp_path, pull_request)

    [row] = seen[0]["inputs"]
    assert (row["input_id"], row["mode"], row["change_set_id"]) == ("cs-1", "pr", "cs-1")
    assert row["change_set"] == {"change_set_id": "cs-1", "base_snapshot_id": "snap-base",
                                 "head_snapshot_id": "snap-head", "boundary": "introducing",
                                 "review_scope": "changed_files"}
    assert row["declared_tree_hash"] is None and row["plan"]["state"] == "unavailable", \
        "no snapshot declares its tree hash before this run has exported it"
    assert "declares no tree hash" in row["plan"]["reason"]


def test_a_pack_that_declares_both_exports_freezes_the_eligibility_the_finished_plan_carries(
        tmp_path, pull_request, monkeypatch):
    first, out = run_pr(tmp_path / "first", pull_request)
    hashes = {snapshot["snapshot_id"]: snapshot["tree_hash"]
              for snapshot in cases.load_pack(out / "evaluator" / "pack.json")["snapshots"]}
    assert all(hashes.values())
    declared = tmp_path / "declared"
    declared.mkdir()
    (declared / "run.json").write_text((tmp_path / "first" / "run.json").read_text(encoding="utf-8"), encoding="utf-8")
    document = json.loads((tmp_path / "first" / "pack.json").read_text(encoding="utf-8"))
    for snapshot in document["snapshots"]:
        snapshot["tree_hash"] = hashes[snapshot["snapshot_id"]]
    document["anchor_sha256"] = pack_anchor_digest(document)
    (declared / "pack.json").write_text(json.dumps(document), encoding="utf-8")
    seen = schedule_seen_before_the_first_fetch(monkeypatch, declared / "out")

    run_from_config(declared / "run.json", declared / "out", clock=CLOCK, adapters={"fake": PrAdapter()})

    [frozen] = seen[0]["inputs"]
    assert frozen["plan"]["state"] == "frozen" and frozen["declared_tree_hash"] == hashes["snap-head"]
    plan = load_document(declared / "out" / "invocations" / "cs-1__fake-a__r1" / "evaluator" / "plan.json",
                         "evaluation-plan")
    # The pack as supplied is draft, so the frozen plan says so and carries what the pack scoped; the
    # run's own checks then promote the case, which the finished plan reflects and the schedule does not.
    assert frozen["plan"]["targets"] == [] and [t["target_id"] for t in plan["targets"]] == ["T-case-shell"]
    assert plan["review_budgets"] == frozen["plan"]["review_budgets"] == [5, 10, 20]
    assert any("outside change set cs-1" in note for note in frozen["plan"]["notes"])


# --- the trace lands in the PR bundle -------------------------------------------------------------------


def test_the_trace_lands_in_the_pr_bundle(tmp_path, pull_request):
    manifest, out = run_pr(tmp_path, pull_request, trace_mode="metadata")

    bundle = bundle_of(out, "cs-1__fake-a__r1")
    assert (bundle / "trace" / "events.jsonl").read_text(encoding="utf-8") == '{"type": "finding.submitted"}\n'
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["trace"] == {"path": "trace/events.jsonl", "events": 1, "mode": "metadata",
                                  "capture_gap": False, "dropped_events": 0}
    assert execution["capture"]["finding_submitted"] == "complete"
    assert load_document(bundle / "result.json", "scan-result")["status"] == "success"


# --- input failures are per input, as for every other input --------------------------------------------


def test_a_change_with_nothing_in_it_is_an_input_failure_and_the_other_inputs_still_run(tmp_path, pull_request):
    repo = pull_request["repo"]
    git("commit", "-q", "--allow-empty", "-m", "an empty commit", cwd=repo)
    same_tree = git("rev-parse", "HEAD", cwd=repo)
    fixture = {**pull_request, "empty_head": same_tree}
    write_pack(tmp_path / "pack.json", fixture)
    document = json.loads((tmp_path / "pack.json").read_text(encoding="utf-8"))
    document["snapshots"].append({**document["snapshots"][1], "snapshot_id": "snap-same", "commit": same_tree})
    document["change_sets"].append({"change_set_id": "cs-empty", "base_snapshot_id": "snap-head",
                                    "head_snapshot_id": "snap-same", "boundary": "ordinary",
                                    "review_scope": "changed_files", "description": "an empty commit"})
    document["anchor_sha256"] = pack_anchor_digest(document)
    (tmp_path / "pack.json").write_text(json.dumps(document), encoding="utf-8")
    write_config(tmp_path / "run.json", systems=[system("fake-a")],
                 inputs=[{"mode": "pr", "change_set_id": "cs-empty"}, {"mode": "pr", "change_set_id": "cs-1"}])
    adapter = PrAdapter()
    out = tmp_path / "out"

    manifest = run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": adapter})

    assert manifest["status"] == "completed" and adapter.calls == 1, "the adapter ran for the prepared input only"
    failed, ran = manifest["inputs"]
    assert failed["preparation_failure"]["type"] == "MaterializationError"
    assert "no change to review" in failed["preparation_failure"]["message"]
    assert (failed["tree_hash"], failed["input_hash"]) == (None, None) and failed["mechanical_checks"] == []
    assert [(row["invocation_id"], row["status"]) for row in manifest["invocations"]] == [
        ("cs-empty__fake-a__r1", "skipped"), ("cs-1__fake-a__r1", "success")]
    assert manifest["invocations"][0]["skipped_reason"].startswith(
        "input cs-empty could not be prepared: MaterializationError: no change to review")
    assert not (out / "invocations" / "cs-empty__fake-a__r1").exists()
    frozen = load_document(out / "evaluator" / "schedule.json", "evaluation-schedule")
    assert "cs-empty__fake-a__r1" in [row["assignment_id"] for row in frozen["assignments"]], \
        "a failed input stays scheduled and stays in every denominator"


def test_a_declared_tree_hash_the_head_export_contradicts_fails_only_that_input(tmp_path, pull_request):
    write_pack(tmp_path / "pack.json", pull_request)
    document = json.loads((tmp_path / "pack.json").read_text(encoding="utf-8"))
    document["snapshots"][1]["tree_hash"] = "sha256:" + "0" * 64
    document["anchor_sha256"] = pack_anchor_digest(document)
    (tmp_path / "pack.json").write_text(json.dumps(document), encoding="utf-8")
    write_config(tmp_path / "run.json", systems=[system("fake-a")])
    adapter = PrAdapter()

    manifest = run_from_config(tmp_path / "run.json", tmp_path / "out", clock=CLOCK, adapters={"fake": adapter})

    [row] = manifest["inputs"]
    assert row["preparation_failure"]["type"] == "ContractError"
    assert "snapshot snap-head declares tree hash sha256:" + "0" * 64 in row["preparation_failure"]["message"]
    assert row["mechanical_checks"] == [], "no check is recorded against an export the pack contradicts"
    assert adapter.calls == 0 and manifest["invocations"][0]["status"] == "skipped"


def test_a_change_set_the_pack_does_not_declare_is_refused_before_the_output_exists(tmp_path, pull_request):
    """Changed deliberately from the phase-1 refusal, which pinned that no PR input could be prepared."""
    write_pack(tmp_path / "pack.json", pull_request)
    write_config(tmp_path / "run.json", systems=[system("fake-a")],
                 inputs=[{"mode": "pr", "change_set_id": "cs-missing"}])
    adapter = PrAdapter()
    out = tmp_path / "out"

    with pytest.raises(ContractError, match=r"inputs\[0\] \(cs-missing\) is a native PR input that cannot be run: "
                                            r"unknown change set 'cs-missing'"):
        run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": adapter})

    assert not out.exists() and adapter.prepared == 0
    # Narrowed away, the input is never resolved, so it does not stand in the way.
    write_config(tmp_path / "run.json", systems=[system("fake-a")],
                 inputs=[{"mode": "pr", "change_set_id": "cs-missing"}, {"mode": "pr", "change_set_id": "cs-1"}])
    manifest = run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": adapter},
                               only_inputs={"cs-1"})
    assert manifest["selection"]["excluded_inputs"] == ["cs-missing"]


def test_a_pack_that_declares_no_change_set_refuses_a_pr_input_with_that_fact(tmp_path):
    cases.save_pack(tmp_path / "pack.json", cases.new_pack("test", "plain", "A pack that declares no change set."))
    write_config(tmp_path / "run.json", systems=[system("fake-a")], inputs=[{"mode": "pr", "change_set_id": "cs-1"}])
    adapter = PrAdapter()

    with pytest.raises(ContractError, match=r"unknown change set 'cs-1' in pack test/plain; the pack declares: none"):
        run_from_config(tmp_path / "run.json", tmp_path / "out", clock=CLOCK, adapters={"fake": adapter})

    assert not (tmp_path / "out").exists() and adapter.prepared == 0


def test_a_full_input_and_a_pr_input_of_one_head_share_a_run_and_keep_their_own_plans(tmp_path, pull_request):
    adapter = PrAdapter()

    manifest, out = run_pr(tmp_path, pull_request, adapters={"fake": adapter},
                           inputs=[{"snapshot_id": "snap-head"}, {"mode": "pr", "change_set_id": "cs-1"}])

    statuses = {row["input_id"]: row["status"] for row in manifest["invocations"]}
    assert statuses == {"snap-head": "success", "cs-1": "success"}
    full_plan = load_document(bundle_of(out, "snap-head__fake-a__r1") / "evaluator" / "plan.json", "evaluation-plan")
    pr_plan = load_document(bundle_of(out, "cs-1__fake-a__r1") / "evaluator" / "plan.json", "evaluation-plan")
    assert full_plan["provenance"]["mode"] == "full" and "pr" not in full_plan["provenance"]
    assert {c["control_id"] for c in full_plan["controls"]} == {"C-eligible", "C-outside"}, \
        "the full plan of the head carries every item of the snapshot"
    assert [c["control_id"] for c in pr_plan["controls"]] == ["C-eligible"]
    frozen = load_document(out / "evaluator" / "schedule.json", "evaluation-schedule")
    assert frozen["pairs"] == [], "no pair of PR inputs is defined, and a lone head pairs with nothing"
    modes = {seen["request"]["input"]["mode"] for seen in adapter.seen}
    assert modes == {"full", "pr"}
    assert [seen for seen in adapter.seen if seen["request"]["input"]["mode"] == "full"][0].get("head") is None, \
        "a full scan is handed no history and no PR request"


# --- replay, the CLI, and the adapter declaration --------------------------------------------------------


def test_a_pr_bundle_replays_to_the_evaluation_it_wrote(tmp_path, pull_request):
    manifest, out = run_pr(tmp_path, pull_request)
    bundle = bundle_of(out, "cs-1__fake-a__r1")

    assert main(["replay", str(bundle), "--output", str(tmp_path / "replayed.json")]) == 0

    assert (tmp_path / "replayed.json").read_bytes() == (bundle / "evaluation.json").read_bytes()
    assert (bundle / "report.html").is_file()
    assert (out / MANIFEST_NAME).is_file() and not list(out.rglob("base/source/.git"))


def test_the_cli_runs_a_pr_input_and_names_an_unsupported_one_without_calling_it_a_failure(tmp_path, pull_request,
                                                                                          monkeypatch, capsys):
    write_pack(tmp_path / "pack.json", pull_request)
    write_config(tmp_path / "run.json", systems=[system("fake-a")])
    adapter = FullOnlyAdapter()
    monkeypatch.setattr("scaneval.runner.get_adapter", lambda name: adapter)

    code = main(["run", str(tmp_path / "run.json"), "--output", str(tmp_path / "out")])
    captured = capsys.readouterr()

    assert code == 0 and "cs-1__fake-a__r1 status=unsupported claims=0" in captured.out
    assert adapter.calls == 0


@pytest.mark.parametrize(("modes", "fragment"), [
    (None, "scan_modes must be a non-empty set of scan modes, not None"),
    (frozenset(), "scan_modes must be a non-empty set of scan modes, not frozenset()"),
    ("pr", "scan_modes must be a non-empty set of scan modes, not 'pr'"),
    (frozenset({"full", "batch"}), "scan_modes names batch, which this build does not know; the scan modes are full, pr"),
    (frozenset({"full", 3}), "scan_modes names 3, which this build does not know"),
], ids=["none", "empty", "string", "unknown-mode", "not-a-string"])
def test_an_adapter_declaration_the_run_cannot_read_is_a_skipped_system(tmp_path, pull_request, modes, fragment):
    write_pack(tmp_path / "pack.json", pull_request)
    write_config(tmp_path / "run.json", systems=[system("fake-a"), system("odd-b", "odd")])
    odd = type("OddModes", (PrAdapter,), {"scan_modes": modes})()
    out = tmp_path / "out"

    manifest = run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": PrAdapter(), "odd": odd})

    assert manifest["status"] == "completed" and odd.prepared == 0 and odd.calls == 0
    reason = manifest["systems"][1]["skipped_reason"]
    assert reason.startswith("AdapterError: odd.") and fragment in reason
    assert [(row["system_id"], row["status"]) for row in manifest["invocations"]] == [
        ("fake-a", "success"), ("odd-b", "skipped")]
    assert load_document(out / MANIFEST_NAME, "run-manifest") == manifest


def crlf_base_under_text_auto(tmp_path: Path) -> dict:
    """An upstream whose base holds a CRLF file beside ``* text=auto`` and whose head holds it as LF.

    The attribute was added after the file, so the repository stores the CRLF bytes, and the export
    writes them as they are. The change records one modification of ``src/app.py``.
    """
    repo = tmp_path / "upstream"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_bytes(SAFE.replace("\n", "\r\n").encode())
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "crlf bytes, no attributes yet", cwd=repo)
    write(repo, ".gitattributes", "* text=auto\n")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "base: attributes added, file untouched", cwd=repo)
    base = git("rev-parse", "HEAD", cwd=repo)
    (repo / "src" / "app.py").write_bytes(SAFE.encode())
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "head: the file is LF now", cwd=repo)
    return {"repo": repo, "base": base, "head": git("rev-parse", "HEAD", cwd=repo)}


def test_an_upstream_whose_attributes_would_have_made_git_read_a_different_change_is_reviewed_exactly(tmp_path):
    """The upstream below used to be refused; the history now stores the bytes that were exported.

    ``* text=auto`` made ScanEval's own ``git add`` store one blob for the CRLF base file and the LF
    head file, so a scanner's ``git diff`` would have shown nothing where the record scores a change.
    Conversion is off in the history now: the change is prepared, the workspace's git names the file
    as modified, and the workspace holds the head file's own bytes.
    """
    fixture = crlf_base_under_text_auto(tmp_path)
    adapter = PrAdapter()

    manifest, out = run_pr(tmp_path, fixture, adapters={"fake": adapter})

    [row] = manifest["inputs"]
    assert not row.get("preparation_failure") and adapter.calls == 1
    assert manifest["invocations"][0]["status"] == "success"
    seen = adapter.seen[0]
    assert seen["name_status"].splitlines() == ["M\tsrc/app.py"]
    assert seen["tree"]["src/app.py"] == SAFE and seen["status"] == ""
    execution = load_document(bundle_of(out, "cs-1__fake-a__r1") / "execution.json", "execution-record")
    assert execution["provenance"]["pr"]["changes"]["modified"] == ["src/app.py"]
    assert execution["provenance"]["source_modified"] is False


def test_a_history_git_reads_differently_from_the_export_fails_that_input_and_records_no_check(tmp_path, monkeypatch):
    """A conversion that survives the history's own override refuses the input before any check is recorded.

    The upstream is the one above, and the override that switches conversion off is replaced by a
    comment, which is what a git that did not honor it would amount to. ``* text=auto`` then makes
    ScanEval's own ``git add`` store LF for the base file the export wrote with CRLF; the blob is not
    the exported bytes, and the input is refused before any mechanical check is recorded, so no adapter
    is ever called for it.
    """
    monkeypatch.setattr(materialize, "PR_HISTORY_ATTRIBUTES", "# nothing is overridden\n")
    fixture = crlf_base_under_text_auto(tmp_path)
    adapter = PrAdapter()

    manifest, out = run_pr(tmp_path, fixture, adapters={"fake": adapter})

    [row] = manifest["inputs"]
    assert row["preparation_failure"]["type"] == "MaterializationError"
    assert "does not hold the exported bytes" in row["preparation_failure"]["message"]
    assert "src/app.py" in row["preparation_failure"]["message"]
    assert row["mechanical_checks"] == [] and adapter.calls == 0
    frozen = cases.load_pack(out / "evaluator" / "pack.json")
    assert all(case["validation"]["checks"] == [] for case in frozen["cases"]), \
        "an input that could not be prepared leaves no check recorded"
    assert manifest["invocations"][0]["status"] == "skipped"
