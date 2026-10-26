"""Condition coverage is visible without pooling incompatible measurements."""

import json

import pytest

from scaneval import aggregate
from scaneval.cli import main
from scaneval.contracts import ContractError, canonical_json, load_document
from test_v2_conditions import invoke


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
