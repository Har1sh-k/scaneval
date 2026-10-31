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
        statuses = spec.config.get("statuses")
        status = statuses[len(self.calls) - 1] if statuses else spec.config.get("status", "success")
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
    assert (result["generated_claims"], result["scorable_claims"], result["excluded_claims"]) == (2, 2, 0)
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
    assert (result["generated_claims"], result["scorable_claims"], result["excluded_claims"]) == (2, 2, 0)
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
    assert result["runtime_seconds"] == {"known_invocations": 0, "total": None, "mean": None}


def test_system_setup_failure_has_unknown_runtime_and_keeps_failure(environment, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("test setup failure")
    monkeypatch.setattr(FixtureScanner, "prepare", fail)
    output = run_fixture(environment, tmp_path)
    result = benchmark.score(output)["systems"][0]
    assert result["statuses"] == {"error": 1}
    assert result["planned_positive_annotations"] == 1
    assert result["reference_coverage"] == 0
    assert result["runtime_seconds"] == {"known_invocations": 0, "total": None, "mean": None}


@pytest.mark.parametrize("failed_status", ["timeout", "error"])
def test_failed_claims_are_retained_but_excluded_from_matching(environment, tmp_path, failed_status):
    output = run_fixture(environment, tmp_path, repetitions=2,
                         config={"statuses": ["success", failed_status]})
    packet = benchmark.judge_packet(output)
    assert [(row["generated_claims"], row["scorable_claims"], row["excluded_claims"], len(row["claims"]))
            for row in packet["invocations"]] == [(1, 1, 0, 1), (1, 0, 1, 0)]
    failed = packet["invocations"][1]
    retained = read_json(output / "invocations" / failed["invocation_id"] / "result.json")
    assert len(retained["claims"]) == 1

    judgments = judgments_for(output)
    result = benchmark.score(output, judgments)["systems"][0]
    assert result["statuses"] == {failed_status: 1, "success": 1}
    assert result["judging_complete"] is True
    assert result["reference_coverage"] == 0.5
    assert result["novel_reference_match_rate"] == 1
    assert (result["generated_claims"], result["scorable_claims"], result["excluded_claims"]) == (2, 1, 1)
    assert result["unjudged_or_uncertain_claims"] == 0

    judgments["decisions"].append({"invocation_id": failed["invocation_id"], "claim_id": "c1",
                                   "annotation_ids": ["issue"], "status": "decided",
                                   "reason": "Excluded claims cannot be submitted for matching."})
    with pytest.raises(ContractError, match="unknown or duplicate judged claim"):
        benchmark.score(output, judgments)


def test_failed_only_claims_do_not_resolve_fixed_controls(environment, tmp_path):
    output = run_fixture(cve_dataset(environment), tmp_path,
                         config={"always_flag": True, "status": "error"})
    result = benchmark.score(output)["systems"][0]
    assert result["judging_complete"] is True
    assert result["reference_coverage"] == 0
    assert result["novel_reference_match_rate"] is None
    assert (result["generated_claims"], result["scorable_claims"], result["excluded_claims"]) == (2, 0, 2)
    assert result["fixed_controls"] == {"planned": 1, "alerted": 0, "quiet": 0, "unresolved": 1}


def test_claim_eligibility_is_isolated_per_system(environment, tmp_path):
    systems = [
        {"system_id": "complete", "adapter": "fixture", "config": {}},
        {"system_id": "failed", "adapter": "fixture", "config": {"status": "timeout"}},
    ]
    plan = benchmark.build_plan(environment, systems, run_id="fixture-run", repetitions=1)
    output = tmp_path / "run"
    benchmark.run(plan, environment, output, tmp_path / "cache", progress=lambda _: None)
    scores = {row["system_id"]: row for row in benchmark.score(output, judgments_for(output))["systems"]}
    assert (scores["complete"]["scorable_claims"], scores["complete"]["reference_coverage"]) == (1, 1)
    assert (scores["failed"]["generated_claims"], scores["failed"]["scorable_claims"],
            scores["failed"]["excluded_claims"], scores["failed"]["reference_coverage"]) == (1, 0, 1, 0)


@pytest.mark.parametrize("version, processing, caveat", [
    ("1.2.0", "curated", "processing is curated: deepsec config.process_manifest_by_tree chose before the run "
                         "which paths are assigned AI batches, so its figures are a diagnostic of those paths, not "
                         "a detection rate, and not comparable with a full run"),
    ("1.1.0", "full", "its configuration names deepsec config.process_manifest_by_tree, which adapter deepsec "
                      "1.1.0 predates and ignores, so it ran unscoped and its processing is full"),
])
def test_a_deepsec_system_is_marked_by_the_processing_its_receipts_ran_and_its_score_is_unchanged(
        environment, tmp_path, monkeypatch, version, processing, caveat):
    """A DeepSec configuration naming process_manifest_by_tree is curated when the recorded adapter honors the key.

    Both systems run the fixture scanner over the same full-scan tasks, so every figure of the DeepSec one but its
    measured wall time equals the other's: the adapter version its receipts record, its processing, and its line in
    limits are the only additions. A receipt recording adapter 1.1.0, which predates the key, marks it full and says
    the key was ignored.
    """
    class RecordedVersion(FixtureScanner):
        adapter_version = version

    monkeypatch.setattr(benchmark, "get_adapter",
                        lambda name: RecordedVersion() if name == "deepsec" else FixtureScanner())
    dataset = cve_dataset(environment)
    systems = [{"system_id": "fixture-system", "adapter": "fixture", "config": {}},
               {"system_id": "deepsec-system", "adapter": "deepsec",
                "config": {"process_manifest_by_tree": {"sha256:" + "1" * 64: ["app.py"]}}}]
    plan = benchmark.build_plan(dataset, systems, run_id="fixture-run", repetitions=1)
    output = tmp_path / "run"
    benchmark.run(plan, dataset, output, tmp_path / "cache", progress=lambda _: None)

    score = benchmark.score(output, judgments_for(output))

    rows = {row["system_id"]: row for row in score["systems"]}
    assert (rows["fixture-system"]["adapter_version"], rows["fixture-system"]["processing"]) == ("1.0", "full")
    assert (rows["deepsec-system"]["adapter_version"], rows["deepsec-system"]["processing"]) == (version, processing)
    figures = {name: {key: value for key, value in row.items()
                      if key not in ("system_id", "adapter_version", "processing", "runtime_seconds")}
               for name, row in rows.items()}
    assert figures["deepsec-system"] == figures["fixture-system"]
    assert figures["deepsec-system"]["reference_coverage"] == 1
    assert [line for line in score["limits"] if "process_manifest_by_tree" in line] == [f"deepsec-system: {caveat}"]


def test_one_system_whose_saved_receipts_record_two_adapter_versions_is_not_scored(environment, tmp_path):
    """One run prepares one adapter per system, so receipts naming two versions of it are not one system's."""
    output = run_fixture(environment, tmp_path, repetitions=2)
    path = output / "benchmark-run.json"
    record = read_json(path)
    receipt_path = output / "invocations" / record["invocations"][1]["invocation_id"] / "execution.json"
    receipt = read_json(receipt_path)
    receipt["adapter"]["version"] = "9.9.9"
    receipt_path.write_text(json.dumps(receipt))
    record["invocations"][1]["execution_sha256"] = canonical_sha256(receipt)
    path.write_text(json.dumps(record))
    with pytest.raises(ContractError, match="saved invocations of system fixture-system record different adapter "
                                            "versions: 1.0, 9.9.9"):
        benchmark.score(output)


@pytest.mark.parametrize("version, recorded", [("1.2.0", "curated"), ("1.2.0", "full"), ("1.1.0", "curated")],
                         ids=["agrees", "curated-recorded-full", "ignored-key-recorded-curated"])
def test_a_deepsec_system_s_saved_results_must_record_the_processing_its_receipts_and_plan_give(
        environment, tmp_path, monkeypatch, version, recorded):
    """The marker a scan records on its result is what the score reports, and only when the plan and receipts agree.

    The DeepSec-named system's scanner records *recorded* on every result. With adapter 1.2.0 and the key configured
    it is curated, so curated is scored exactly as the unrecorded marker was, and full is refused; adapter 1.1.0
    ignored the key, so a result recording curated is refused.
    """
    class Recording(FixtureScanner):
        adapter_version = version

        def scan(self, **kwargs):
            outcome = super().scan(**kwargs)
            outcome.processing = recorded
            return outcome

    monkeypatch.setattr(benchmark, "get_adapter", lambda name: Recording() if name == "deepsec" else FixtureScanner())
    dataset = cve_dataset(environment)
    systems = [{"system_id": "fixture-system", "adapter": "fixture", "config": {}},
               {"system_id": "deepsec-system", "adapter": "deepsec",
                "config": {"process_manifest_by_tree": {"sha256:" + "1" * 64: ["app.py"]}}}]
    plan = benchmark.build_plan(dataset, systems, run_id="fixture-run", repetitions=1)
    output = tmp_path / "run"
    benchmark.run(plan, dataset, output, tmp_path / "cache", progress=lambda _: None)
    saved = {read_json(path)["processing"] for path in (output / "invocations").glob("*deepsec-system*/result.json")}
    assert saved == {recorded}
    judgments = judgments_for(output)

    if (version, recorded) != ("1.2.0", "curated"):
        derived = "curated" if version == "1.2.0" else "full"
        with pytest.raises(ContractError, match=f"saved results of system deepsec-system record processing "
                                                f"{recorded}, but its configuration and adapter version make it "
                                                f"{derived}"):
            benchmark.score(output, judgments)
        return
    score = benchmark.score(output, judgments)
    rows = {row["system_id"]: row for row in score["systems"]}
    assert (rows["deepsec-system"]["adapter_version"], rows["deepsec-system"]["processing"]) == ("1.2.0", "curated")
    figures = {name: {key: value for key, value in row.items()
                      if key not in ("system_id", "adapter_version", "processing", "runtime_seconds")}
               for name, row in rows.items()}
    assert figures["deepsec-system"] == figures["fixture-system"]


def test_a_saved_result_edited_to_record_a_processing_its_system_did_not_run_with_is_not_scored(environment,
                                                                                               tmp_path):
    """An edit that rehashes the run record still leaves a marker the plan's configuration contradicts."""
    output = run_fixture(environment, tmp_path)
    path = output / "benchmark-run.json"
    record = read_json(path)
    row = next(row for row in record["invocations"] if "result_sha256" in row)
    result_path = output / "invocations" / row["invocation_id"] / "result.json"
    result = read_json(result_path)
    result.update(schema_version="2.1", processing="curated")
    result_path.write_text(json.dumps(result))
    row["result_sha256"] = canonical_sha256(result)
    path.write_text(json.dumps(record))
    with pytest.raises(ContractError, match="saved results of system fixture-system record processing curated, but "
                                            "its configuration and adapter version make it full"):
        benchmark.score(output)


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
    assert (result["generated_claims"], result["scorable_claims"], result["excluded_claims"]) == (1, 1, 0)


@pytest.mark.parametrize("phase", ["scanner-setup", "source-preparation"])
def test_interrupted_preparation_preserves_a_replayable_schedule(environment, tmp_path, monkeypatch, phase):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt
    if phase == "scanner-setup":
        monkeypatch.setattr(FixtureScanner, "prepare", interrupt)
    else:
        monkeypatch.setattr(benchmark, "prepare_task", interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_fixture(environment, tmp_path, repetitions=2)
    result = benchmark.score(tmp_path / "run")["systems"][0]
    assert result["statuses"] == {"missing": 2}
    assert result["planned_positive_annotations"] == 2
    assert result["reference_coverage"] is None
    assert result["reference_coverage_lower_bound"] == 0


def test_completed_invocations_are_checkpointed_before_the_next_scan(environment, tmp_path, monkeypatch):
    original = FixtureScanner.scan
    calls = 0
    def interrupt_second(scanner, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            # This is observable before run's finally executes, including on abrupt process exit.
            saved = benchmark.score(tmp_path / "run")["systems"][0]
            assert saved["statuses"] == {"missing": 1, "success": 1}
            assert saved["planned_positive_annotations"] == 2
            raise KeyboardInterrupt
        return original(scanner, **kwargs)
    monkeypatch.setattr(FixtureScanner, "scan", interrupt_second)
    with pytest.raises(KeyboardInterrupt):
        run_fixture(environment, tmp_path, repetitions=2)
    output = tmp_path / "run"
    result = benchmark.score(output, judgments_for(output))["systems"][0]
    assert result["statuses"] == {"missing": 1, "success": 1}
    assert result["reference_coverage"] is None
    assert result["reference_coverage_lower_bound"] == 0.5


def test_failed_checkpoint_keeps_the_previous_record(tmp_path, monkeypatch):
    previous = {"completed": ["one"]}
    benchmark._checkpoint(tmp_path, previous)
    def fail_replace(*args):
        raise OSError("fixture disk failure")
    monkeypatch.setattr(Path, "replace", fail_replace)
    with pytest.raises(OSError, match="fixture disk failure"):
        benchmark._checkpoint(tmp_path, {"completed": ["one", "two"]})
    assert read_json(tmp_path / "benchmark-run.json") == previous
    assert not list(tmp_path.glob(".benchmark-run-*.tmp"))


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


@pytest.mark.parametrize("variant", ["snapshot", "pr-head", "pr-base"])
def test_frozen_provenance_must_name_dataset_commits(environment, tmp_path, variant):
    dataset = cve_dataset(environment) if variant == "snapshot" else environment
    output = run_fixture(dataset, tmp_path)
    task_id = "vulnerable" if variant == "snapshot" else "change"
    provenance_path = output / "inputs" / task_id / "provenance.json"
    provenance = read_json(provenance_path)
    if variant == "snapshot":
        provenance["source"]["commit"] = environment["tasks"][0]["commit"]
    elif variant == "pr-head":
        provenance["head"]["source"]["commit"] = environment["tasks"][0]["base_commit"]
    else:
        provenance["base"]["source"]["commit"] = environment["tasks"][0]["commit"]
    provenance_path.write_text(json.dumps(provenance))

    provenance_sha256 = canonical_sha256(provenance)
    record_path = output / "benchmark-run.json"
    record = read_json(record_path)
    record["tasks"][task_id]["provenance_sha256"] = provenance_sha256
    invocation = next(row for row in record["invocations"] if row["task_id"] == task_id)
    receipt_path = output / "invocations" / invocation["invocation_id"] / "execution.json"
    receipt = read_json(receipt_path)
    receipt["provenance"]["provenance_sha256"] = provenance_sha256
    receipt_path.write_text(json.dumps(receipt))
    invocation["execution_sha256"] = canonical_sha256(receipt)
    record_path.write_text(json.dumps(record))

    with pytest.raises(ContractError, match="wrong original commit"):
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


def test_plan_rejects_stale_scoring_protocol(environment):
    systems = [{"system_id": "fixture", "adapter": "fixture"}]
    plan = benchmark.build_plan(environment, systems, run_id="frozen")
    plan["protocol"] = "scaneval-reference-coverage-1"
    with pytest.raises(ContractError, match="protocol scaneval-reference-coverage-2"):
        benchmark.validate_plan(plan, environment)


def test_plan_rejects_case_colliding_systems(environment):
    systems = [{"system_id": name, "adapter": "fixture"} for name in ("scanner", "SCANNER")]
    with pytest.raises(ContractError, match="duplicate system_id"):
        benchmark.build_plan(environment, systems, run_id="frozen")


@pytest.mark.parametrize("field", ["execution", "network_policy"])
def test_plan_names_unsupported_case_pack_system_fields(environment, field):
    system = {"system_id": "fixture", "adapter": "fixture", field: {}}
    with pytest.raises(ContractError, match=rf"unsupported benchmark system fields: {field}"):
        benchmark.build_plan(environment, [system], run_id="frozen")


def test_plan_rejects_case_colliding_composite_invocations(environment):
    first = environment["tasks"][0]
    first["task_id"] = "first"
    environment["tasks"].append({**deepcopy(first), "task_id": "FIRST__second"})
    systems = [{"system_id": name, "adapter": "fixture"} for name in ("second__THIRD", "third")]
    with pytest.raises(ContractError, match="invocation IDs collide"):
        benchmark.build_plan(environment, systems, run_id="frozen")


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
