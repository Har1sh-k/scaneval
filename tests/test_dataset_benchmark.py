"""End-to-end local Git fixtures; no real scanner, network, or model is used."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess

import pytest

from scaneval import benchmark, materialize
from scaneval.adapters.base import Adapter, NativeOutcome
from scaneval.cli import main
from scaneval.contracts import ContractError, canonical_sha256
from scaneval.datasets import read_json, write_json


class FixtureScanner(Adapter):
    name = "fixture"
    adapter_version = "1.0"
    supported_languages = frozenset({"python"})
    scan_modes = frozenset({"full", "pr"})
    requires_git = True
    calls = []

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        assert "annotations" not in json.dumps(request)
        assert "LABEL-ONLY" not in json.dumps(request)
        assert not (source_dir / "dataset.json").exists()
        self.calls.append(request)
        text = (source_dir / "app.py").read_text()
        if request["input"]["mode"] == "pr":
            history = request["input"]["pr"]
            assert history["base"] != history["head"]
            cmd, env = materialize.git_command(["show", history["base"] + ":app.py"])
            assert "unsafe" in subprocess.run(cmd, env=env, cwd=source_dir, capture_output=True,
                                               text=True, check=True).stdout
        claims = []
        if "unsafe" in text or request["input"]["mode"] == "pr" or spec.config.get("always_flag"):
            claims = [{"claim_id": "c1", "allegation": "request reaches query", "kind": "unmapped",
                       "primary_location": {"path": "app.py", "start_line": 1, "end_line": 1}}]
        status = spec.config.get("status", "success")
        return NativeOutcome(status=status, exit_code=0, command=["fixture-only"], claims=claims,
                             bundles_resolved=status == "success", usage={"cost_usd": None})


@pytest.fixture
def environment(tmp_path, monkeypatch):
    repo = tmp_path / "upstream"
    repo.mkdir()
    def git(*args):
        cmd, env = materialize.git_command(list(args))
        return subprocess.run(cmd, env=env, cwd=repo, text=True, capture_output=True, check=True).stdout.strip()
    git("init", "-q")
    (repo / "app.py").write_text("query(unsafe)\n")
    git("add", "app.py")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "base")
    base = git("rev-parse", "HEAD")
    (repo / "app.py").write_text("query('safe')\n")
    git("add", "app.py")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "head")
    head = git("rev-parse", "HEAD")
    fetch = materialize.fetch_snapshot
    monkeypatch.setattr(materialize, "fetch_snapshot", lambda url, commit, cache: fetch(repo.as_uri(), commit, cache))
    monkeypatch.setattr(benchmark, "get_adapter", lambda name: FixtureScanner())
    FixtureScanner.calls = []
    annotation = {"annotation_id": "issue", "label": "positive", "text": "LABEL-ONLY query uses untrusted data",
                  "locations": [{"path": "app.py", "start_line": 1, "end_line": 1}],
                  "severity": "high", "category": "security"}
    task = {"task_id": "change", "case_id": "case", "repository_url": "https://example.org/repo",
            "commit": head, "base_commit": base, "variant": "pr", "languages": ["python"],
            "annotations": [annotation]}
    dataset = {"schema_version": "1.0", "dataset_id": "local-fixture", "mode": "pr-review",
               "source": {"name": "test fixture only", "revision": "v1", "license": "MIT"}, "tasks": [task]}
    return dataset


def run_fixture(dataset, tmp_path, *, repetitions=1, config=None):
    systems = [{"system_id": "fixture-system", "adapter": "fixture", "config": config or {}}]
    plan = benchmark.build_plan(dataset, systems, run_id="fixture-run", repetitions=repetitions)
    output = tmp_path / "run"
    benchmark.run(plan, dataset, output, tmp_path / "cache", progress=lambda _: None)
    return output


def judgments_for(output, *, annotation_ids=None, status="decided"):
    packet = benchmark.judge_packet(output)
    decisions = [{"invocation_id": r["invocation_id"], "claim_id": c["claim_id"],
                  "annotation_ids": annotation_ids if annotation_ids is not None else ["issue"],
                  "status": status, "reason": "Fabricated decision for this local fixture only."}
                 for r in packet["invocations"] for c in r["claims"]]
    return {"schema_version": "1.0", "packet_sha256": canonical_sha256(packet),
            "judge": {"kind": "test", "name": "test-fixture"}, "decisions": decisions}


def cve_dataset(pr_dataset):
    dataset = deepcopy(pr_dataset)
    dataset["mode"] = "cve-detection"
    original = dataset["tasks"][0]
    vulnerable = {**deepcopy(original), "task_id": "vulnerable", "variant": "vulnerable", "commit": original["base_commit"]}
    fixed = {**deepcopy(original), "task_id": "fixed", "variant": "fixed"}
    for task in (vulnerable, fixed):
        task.pop("base_commit")
    fixed["annotations"][0]["label"] = "fixed-control"
    dataset["tasks"] = [vulnerable, fixed]
    return dataset


def test_pr_end_to_end_repeat_runs_and_offline_scores(environment, tmp_path):
    output = run_fixture(environment, tmp_path, repetitions=2)
    assert len(FixtureScanner.calls) == 2
    packet = benchmark.judge_packet(output)
    assert len(packet["invocations"]) == 2
    assert "label" not in packet["invocations"][0]["annotations"][0]
    judgments = judgments_for(output)
    first = benchmark.score(output, judgments)
    assert first == benchmark.score(output, judgments)
    result = first["systems"][0]
    assert result["statuses"] == {"success": 2}
    assert result["planned_positive_annotations"] == 2
    assert result["covered_positive_annotations"] == 2
    assert result["reference_coverage"] == 1
    assert result["by_severity"]["high"] == {"planned": 2, "covered": 2}
    assert result["cost_usd"] == {"known_invocations": 0, "total_known": None}


def test_cve_full_scan_and_fixed_control_are_separate(environment, tmp_path):
    output = run_fixture(cve_dataset(environment), tmp_path)
    result = benchmark.score(output, judgments_for(output))["systems"][0]
    assert result["reference_coverage"] == 1
    assert result["fixed_controls"] == {"planned": 1, "alerted": 0, "quiet": 1, "unresolved": 0}
    assert {r["input"]["mode"] for r in FixtureScanner.calls} == {"full"}


def test_fixed_control_alerts_and_partial_silence_are_not_quiet(environment, tmp_path):
    output = run_fixture(cve_dataset(environment), tmp_path, config={"always_flag": True, "status": "partial"})
    result = benchmark.score(output, judgments_for(output))["systems"][0]
    assert result["statuses"] == {"partial": 2}
    assert result["fixed_controls"] == {"planned": 1, "alerted": 1, "quiet": 0, "unresolved": 0}


def test_partial_empty_fixed_control_stays_unresolved(environment, tmp_path):
    output = run_fixture(cve_dataset(environment), tmp_path, config={"status": "partial"})
    result = benchmark.score(output, judgments_for(output))["systems"][0]
    assert result["fixed_controls"] == {"planned": 1, "alerted": 0, "quiet": 0, "unresolved": 1}


def test_missing_judgments_are_not_false_misses(environment, tmp_path):
    output = run_fixture(environment, tmp_path)
    result = benchmark.score(output)["systems"][0]
    assert result["reference_coverage"] is None
    assert result["reference_coverage_lower_bound"] == 0
    assert result["unjudged_or_uncertain_claims"] == 1
    assert not result["judging_complete"]


def test_unsupported_language_is_retained_and_not_scanned(environment, tmp_path):
    environment["tasks"][0]["languages"] = ["cpp"]
    output = run_fixture(environment, tmp_path, repetitions=2)
    result = benchmark.score(output)["systems"][0]
    assert FixtureScanner.calls == []
    assert result["statuses"] == {"unsupported": 2}
    assert result["planned_positive_annotations"] == 2
    assert result["reference_coverage"] == 0


def test_fetch_failure_retains_scheduled_denominator(environment, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise materialize.MaterializationError("test fetch failure")
    monkeypatch.setattr(materialize, "fetch_snapshot", fail)
    output = run_fixture(environment, tmp_path, repetitions=3)
    result = benchmark.score(output)["systems"][0]
    assert FixtureScanner.calls == []
    assert result["statuses"] == {"error": 3}
    assert result["planned_positive_annotations"] == 3
    assert result["reference_coverage"] == 0


def test_negative_comment_is_not_a_safe_control(environment, tmp_path):
    environment["tasks"][0]["annotations"][0]["label"] = "negative"
    output = run_fixture(environment, tmp_path)
    result = benchmark.score(output, judgments_for(output))["systems"][0]
    assert result["planned_positive_annotations"] == 0
    assert result["reference_coverage"] is None
    assert result["fixed_controls"]["planned"] == 0
    assert result["claims_matching_rejected_annotations"] == 1


def test_interrupted_assignments_remain_missing_in_denominator(environment, tmp_path):
    output = run_fixture(environment, tmp_path, repetitions=2)
    path = output / "benchmark-run.json"
    record = read_json(path)
    record["invocations"].pop()
    path.write_text(json.dumps(record))
    result = benchmark.score(output, judgments_for(output))["systems"][0]
    assert result["statuses"] == {"success": 1, "missing": 1}
    assert result["planned_positive_annotations"] == 2
    assert result["reference_coverage"] is None
    assert result["reference_coverage_lower_bound"] == 0.5


def test_uncertain_decision_preserves_pending_state(environment, tmp_path):
    output = run_fixture(environment, tmp_path)
    result = benchmark.score(output, judgments_for(output, annotation_ids=[], status="uncertain"))["systems"][0]
    assert result["reference_coverage"] is None
    assert result["unjudged_or_uncertain_claims"] == 1


def test_one_claim_can_cover_multiple_references_but_counts_once(environment, tmp_path):
    other = deepcopy(environment["tasks"][0]["annotations"][0])
    other["annotation_id"] = "issue-two"
    environment["tasks"][0]["annotations"].append(other)
    output = run_fixture(environment, tmp_path)
    result = benchmark.score(output, judgments_for(output, annotation_ids=["issue", "issue-two"]))["systems"][0]
    assert result["covered_positive_annotations"] == 2
    assert result["generated_claims"] == 1
    assert result["novel_reference_match_rate"] == 1


@pytest.mark.parametrize("mutation", [
    lambda j: j.update(packet_sha256="sha256:" + "0" * 64),
    lambda j: j["decisions"][0].update(annotation_ids=["foreign-reference"]),
    lambda j: j["decisions"].append(deepcopy(j["decisions"][0])),
    lambda j: j["decisions"][0].update(status="uncertain"),
    lambda j: j["judge"].update(kind="llm"),
])
def test_malformed_or_stale_judgments_fail_closed(environment, tmp_path, mutation):
    output = run_fixture(environment, tmp_path)
    judgments = judgments_for(output)
    mutation(judgments)
    with pytest.raises(ContractError):
        benchmark.score(output, judgments)


def test_changed_output_and_dataset_are_not_replayable(environment, tmp_path):
    output = run_fixture(environment, tmp_path)
    path = next((output / "invocations").glob("*/result.json"))
    result = read_json(path)
    result["claims"][0]["allegation"] = "changed after judging"
    path.write_text(json.dumps(result))
    with pytest.raises(ContractError, match="saved result changed"):
        benchmark.score(output)


def test_judge_does_not_read_changed_source(environment, tmp_path):
    output = run_fixture(environment, tmp_path)
    (output / "inputs/change/source/app.py").write_text("changed after the scan\n")
    with pytest.raises(ContractError, match="source changed before judging"):
        benchmark.judge_packet(output)


@pytest.mark.parametrize("variant", ["snapshot", "pr-head", "pr-base"])
def test_source_and_provenance_replacement_cannot_reuse_judgments(environment, tmp_path, variant):
    dataset = cve_dataset(environment) if variant == "snapshot" else environment
    output = run_fixture(dataset, tmp_path)
    judgments = judgments_for(output)
    tid = "vulnerable" if variant == "snapshot" else "change"
    trial = output / "inputs" / tid
    source = trial / ("base/source" if variant == "pr-base" else "source")
    (source / "app.py").write_text("unrelated_replacement()\n")
    provenance_path = trial / "provenance.json"
    provenance = read_json(provenance_path)
    snapshot = provenance if variant == "snapshot" else provenance[variant.removeprefix("pr-")]
    snapshot["trial"]["tree_hash"] = materialize.hash_exported_tree(source)["tree_hash"]
    provenance_path.write_text(json.dumps(provenance))
    with pytest.raises(ContractError, match="provenance changed before judging"):
        benchmark.score(output, judgments)


def test_pr_mode_change_is_checked_against_original_input(environment, tmp_path):
    output = run_fixture(environment, tmp_path)
    source = output / "inputs/change/source/app.py"
    source.chmod(source.stat().st_mode ^ 0o111)
    # Content hashes alone do not detect a change in the executable bit.
    with pytest.raises(ContractError, match="source differs from scanned input"):
        benchmark.judge_packet(output)


def test_judge_packet_binds_the_verified_source_and_execution(environment, tmp_path):
    output = run_fixture(environment, tmp_path)
    packet = benchmark.judge_packet(output)
    row = packet["invocations"][0]
    bundle = output / "invocations" / row["invocation_id"]
    result = read_json(bundle / "result.json")
    receipt = read_json(bundle / "execution.json")
    assert row["source_binding"]["input_hash"] == result["input_hash"]
    assert row["source_binding"]["provenance_sha256"] == receipt["provenance"]["provenance_sha256"]
    assert row["execution_sha256"] == canonical_sha256(receipt)
    assert row["source_binding"]["head_tree_hash"] != row["source_binding"]["base_tree_hash"]


def test_changed_execution_receipt_is_not_replayable(environment, tmp_path):
    output = run_fixture(environment, tmp_path)
    path = next((output / "invocations").glob("*/execution.json"))
    receipt = read_json(path)
    receipt["provenance"]["provenance_sha256"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(receipt))
    with pytest.raises(ContractError, match="saved execution changed"):
        benchmark.judge_packet(output)


def test_copied_receipt_cannot_reassign_a_repetition(environment, tmp_path):
    output = run_fixture(environment, tmp_path, repetitions=2)
    path = output / "benchmark-run.json"
    record = read_json(path)
    first, second = record["invocations"]
    original = output / "invocations" / first["invocation_id"] / "execution.json"
    replacement = output / "invocations" / second["invocation_id"] / "execution.json"
    replacement.write_bytes(original.read_bytes())
    # Even a replacement digest must still fit the scheduled assignment.
    second["execution_sha256"] = first["execution_sha256"]
    path.write_text(json.dumps(record))
    with pytest.raises(ContractError, match="execution identity mismatch"):
        benchmark.saved_run(output)


def test_plan_rejects_changed_labels_and_unknown_selection(environment):
    systems = [{"system_id": "fixture", "adapter": "fixture"}]
    plan = benchmark.build_plan(environment, systems, run_id="frozen")
    changed = deepcopy(environment)
    changed["tasks"][0]["annotations"][0]["text"] += "modified"
    with pytest.raises(ContractError, match="exact dataset"):
        benchmark.validate_plan(plan, changed)
    with pytest.raises(ContractError, match="unknown or duplicate"):
        benchmark.build_plan(environment, systems, run_id="frozen", task_ids=["absent"])


def test_cli_native_dataset_to_run_and_report(environment, tmp_path):
    dataset, systems, plan = [tmp_path / name for name in ("dataset.json", "systems.json", "plan.json")]
    write_json(dataset, environment)
    systems.write_text(json.dumps([{"system_id": "fixture", "adapter": "fixture"}]))
    assert main(["benchmark", "plan", "--dataset", str(dataset), "--systems", str(systems),
                 "--run-id", "cli", "--repetitions", "1", "--output", str(plan)]) == 0
    output = tmp_path / "run"
    assert main(["benchmark", "run", "--plan", str(plan), "--dataset", str(dataset),
                 "--cache", str(tmp_path / "cache"), "--output", str(output), "--quiet"]) == 0
    assert main(["benchmark", "judge-packet", str(output), "--output", str(tmp_path / "packet.json")]) == 0
    judgments = tmp_path / "judgments.json"
    write_json(judgments, judgments_for(output))
    assert main(["benchmark", "score", str(output), "--judgments", str(judgments),
                 "--output", str(tmp_path / "score.json")]) == 0
