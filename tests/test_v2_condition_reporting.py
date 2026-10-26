"""Condition coverage is visible without pooling incompatible measurements."""

import json
import shutil

import pytest

from scaneval import aggregate
from scaneval.cli import main
from scaneval.contracts import ContractError, canonical_json, load_document
from test_v2_conditions import Enforced, Offline, invoke
from test_v2_runner import upstream


def test_cli_reports_distinct_coverage_without_scoring(tmp_path, capsys):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first, _ = invoke(tmp_path / "a")
    second, _ = invoke(tmp_path / "b", enforced=False)
    assert main(["condition", str(first), str(second)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {item["status"] for item in report["coverage"]} == {"attested", "declared_only"}


def test_aggregation_reports_legacy_condition_coverage_and_refuses_mixed_status(tmp_path):
    from test_v2_aggregate import two_project_run, policy
    run = two_project_run(tmp_path)
    report = aggregate.aggregate([run], policy=policy(replicates=10))
    assert {row["status"] for row in report["condition_coverage"]} == {"unavailable"}
    manifest = load_document(run / "run-manifest.json", "run-manifest")
    bundle = run / manifest["invocations"][0]["bundle_path"]
    execution_path = bundle / "execution.json"
    execution = json.loads(execution_path.read_text())
    execution["network_policy"]["declared"] = "unrestricted"
    execution_path.write_text(canonical_json(execution))
    (bundle / "condition-policy.json").write_text(canonical_json({
        "name": "closed_book_standard", "policy": {}, "declared": True}))
    with pytest.raises(ContractError, match="mixes evaluation condition strata"):
        aggregate.aggregate([run], policy=policy(replicates=10))


@pytest.mark.parametrize("declaration", [
    {"name": "open_context", "policy": {}},
    {"name": "closed_book_standard", "policy": {"revision": "different"}},
])
def test_aggregation_cannot_pool_conditions_or_policy_variants(tmp_path, declaration):
    from test_v2_aggregate import two_project_run, policy
    run = two_project_run(tmp_path)
    manifest = load_document(run / "run-manifest.json", "run-manifest")
    bundle = run / manifest["invocations"][0]["bundle_path"]
    (bundle / "condition-policy.json").write_text(canonical_json(declaration))
    with pytest.raises(ContractError, match="mixes evaluation condition strata"):
        aggregate.aggregate([run], policy=policy(replicates=10))


def test_comparison_reports_each_systems_condition_coverage(tmp_path):
    from test_v2_aggregate import write_run, planned, target, policy
    run = write_run(tmp_path, "comparison", [planned("a", targets=[target("T-a")])], systems=("sys-a", "sys-b"))
    report = aggregate.compare([run], baseline="sys-a", candidate="sys-b", policy=policy(replicates=10))
    assert {row["system_id"] for row in report["condition_coverage"]} == {"sys-a", "sys-b"}
    assert {row["status"] for row in report["condition_coverage"]} == {"unavailable"}
    assert any("condition closed_book_standard status=unavailable" in line for line in aggregate.comparison_summary(report))


def test_report_and_evidence_identities_survive_relocating_legacy_run(tmp_path):
    from test_v2_aggregate import two_project_run, policy
    run = two_project_run(tmp_path / "original")
    first = aggregate.aggregate([run], policy=policy(replicates=10))
    moved = tmp_path / "moved" / run.name
    shutil.copytree(run, moved)
    assert canonical_json(aggregate.aggregate([moved], policy=policy(replicates=10))) == canonical_json(first)


def test_historical_blinded_input_with_missing_execution_keeps_frozen_profile(tmp_path):
    from test_v2_aggregate import write_run, planned, target, policy, scan
    run = write_run(tmp_path, "blinded", [planned("a", profile="metadata_blinded", targets=[target("T-a")]),
                                         planned("b", profile="metadata_blinded", targets=[target("T-b")])],
                    outcomes={("b", "sys-a", 1): scan(execution=False)})
    report = aggregate.aggregate([run], policy=policy(replicates=10))
    assert {row["condition"] for row in report["condition_coverage"]} == {"identity_reduced"}
    assert sum(row["observations"] for row in report["condition_coverage"]) == 2


def test_cli_separates_policy_variants_and_refuses_nonexistent_bundle(tmp_path, capsys):
    from scaneval import conditions
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first, _ = invoke(tmp_path / "a")
    second, _ = invoke(tmp_path / "b")
    (second / conditions.RECORD_FILE).unlink()
    policy = json.loads((second / conditions.POLICY_FILE).read_text())
    policy["policy"] = {"revision": "other"}
    (second / conditions.POLICY_FILE).write_text(canonical_json(policy))
    execution = json.loads((second / "execution.json").read_text())
    execution["condition"]["policy"] = policy["policy"]
    (second / "execution.json").write_text(canonical_json(execution))
    output = tmp_path / "coverage.json"
    assert main(["condition", str(first), str(second), "--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert len(report["coverage"]) == 2
    assert {row["status"] for row in report["coverage"]} == {"attested"}
    assert len({row["policy_sha256"] for row in report["coverage"]}) == 2
    assert main(["condition", str(tmp_path / "typo")]) == 2
    assert "not a directory" in capsys.readouterr().err


def condition_run(tmp_path, upstream, monkeypatch, systems, *, repetitions=1):
    """A real runner/execution pipeline with a fixture of recorded OS-level evidence."""
    from collections import Counter
    from scaneval import cases, isolation
    from scaneval.adapters.base import NativeOutcome
    from scaneval.materialize import hash_exported_tree
    from scaneval.runner import run_from_config
    from test_v2_runner import CLOCK, write_pack
    repo, commit = upstream
    digest = hash_exported_tree(repo)["tree_hash"]
    pack = write_pack(tmp_path / "pack.json", repo, commit, tree_hash=digest)
    cases.mechanical_checks(pack, "snap-a", repo, digest, clock=CLOCK)
    cases.save_pack(tmp_path / "pack.json", pack)

    class RecordedBackend(Enforced):
        workspace_root = None
        def close(self):
            return []

    class ReportingAdapter(Offline):
        name = "fixture"
        oci_compatible = True
        calls = Counter()
        def scan(self, **kwargs):
            system_id = kwargs["spec"].system_id
            self.calls[system_id] += 1
            behavior = kwargs["spec"].config.get("behavior")
            if behavior == "unsupported_second" and self.calls[system_id] == 2:
                return NativeOutcome("unsupported", None, [], error={"code": "fixture", "message": "unsupported fixture"})
            outcome = super().scan(**kwargs)
            if behavior in {"mixed", "error_claims"}:
                outcome.claims = [{"claim_id": "fixture", "kind": "command_injection", "allegation": "fixture claim",
                                   "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5}}]
                if self.calls[system_id] == 2:
                    outcome.capture_state = {"capture_gap": True, "dropped_events": 1}
                    if behavior == "error_claims":
                        outcome.status = "error"
                        outcome.error = {"code": "fixture", "message": "error after delivering a claim"}
            return outcome
    monkeypatch.setattr(isolation, "backend_for", lambda settings, **kwargs: RecordedBackend(settings.network_policy))
    config = {"schema_version": "2.1", "run_id": "condition-pipeline", "pack": "pack.json", "cache_root": "cache",
              "inputs": [{"snapshot_id": "snap-a"}], "systems": systems, "repetitions": repetitions,
              "timeout_seconds": 30, "trace_mode": "content", "network_policy": "none"}
    config_path = tmp_path / "config.json"
    config_path.write_text(canonical_json(config))
    output = tmp_path / "run"
    run_from_config(config_path, output, adapters={"fixture": ReportingAdapter(events=[{"metadata": {"tool_name": "Read"}}])}, clock=CLOCK)
    return output


def reporting_system(name, *, held=True, behavior=None):
    return {"system_id": name, "adapter": "fixture", "config": {"behavior": behavior} if behavior else {},
            "execution": {"backend": "oci", "image": "fixture@sha256:" + "a" * 64} if held else {"backend": "local"}}


def test_new_condition_records_from_different_systems_are_reported_separately(tmp_path, upstream, monkeypatch):
    from test_v2_aggregate import policy
    run = condition_run(tmp_path, upstream, monkeypatch, [reporting_system("held"), reporting_system("local", held=False)])
    report = aggregate.aggregate([run], policy=policy(replicates=10))
    assert {(row["system_id"], row["status"]) for row in report["condition_coverage"]} == {
        ("held", "attested"), ("local", "declared_only")}


def test_unsupported_assignment_stays_in_denominator_without_refusing_supported_evidence(tmp_path, upstream, monkeypatch):
    from test_v2_aggregate import policy
    run = condition_run(tmp_path, upstream, monkeypatch, [reporting_system("scanner", behavior="unsupported_second")], repetitions=2)
    report = aggregate.aggregate([run], policy=policy(replicates=10))
    assert {row["status"] for row in report["condition_coverage"]} == {"attested", "unavailable"}
    observations = report["views"][0]["systems"][0]["observations"]
    assert observations["assignments"] == 2 and observations["statuses"]["unsupported"] == 1


def test_compare_does_not_refuse_an_uncompared_systems_strata(tmp_path, upstream, monkeypatch):
    from test_v2_aggregate import policy
    run = condition_run(tmp_path, upstream, monkeypatch,
                        [reporting_system("base"), reporting_system("candidate"), reporting_system("other", behavior="mixed")],
                        repetitions=2)
    report = aggregate.compare([run], baseline="base", candidate="candidate", policy=policy(replicates=10))
    assert {row["system_id"] for row in report["condition_coverage"]} == {"base", "candidate"}


def test_malformed_condition_artifact_is_a_failed_record_not_an_anonymous_exception(tmp_path, upstream, monkeypatch):
    from test_v2_aggregate import policy
    run = condition_run(tmp_path, upstream, monkeypatch, [reporting_system("scanner")])
    bundle = next((run / "invocations").iterdir())
    (bundle / "condition-policy.json").write_text('{"name":"bogus"}')
    report = aggregate.aggregate([run], policy=policy(replicates=10))
    assert report["condition_coverage"][0]["status"] == "failed"
    assert "invalid_condition_policy" in {reason["code"] for reason in report["condition_coverage"][0]["assignments"][0]["reasons"]}
