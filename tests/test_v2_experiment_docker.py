"""Actual three-condition Semgrep plumbing over a fabricated diagnostic source property.

No real CVE or model experiment runs. The fictional review below tests adjudication software;
it is never written as real corpus approval or presented as benchmark evidence.
"""

import json
import shutil

from scaneval import blinding, conditions, experiment
from scaneval.cli import main
from scaneval.contracts import canonical_json

from test_v2_isolation_docker import scratch, scratch_parent  # noqa: F401
from test_v2_experiment_freeze import fixture_builder


def test_documented_semgrep_matrix_runs_all_conditions_and_preserves_pairing(scratch, monkeypatch):
    declaration = fixture_builder(monkeypatch)(scratch / "study")
    mapping = blinding.load_map(declaration.parent / "map.json")
    blinding.record_review(mapping, reviewer="Fictional diagnostic map reviewer", role="independent_reviewer",
        decision="approve", note="Synthetic integration fixture only, not real corpus evidence.")
    blinding.save_map(declaration.parent / "map.json", mapping)
    frozen = declaration.parent / "frozen.json"
    assert main(["matrix", "freeze", str(declaration), "--output", str(frozen)]) == 0
    output = scratch / "experiment"
    assert main(["matrix", "run", str(frozen), "--output", str(output), "--workspace-root",
                 str(declaration.parent / "work"), "--quiet"]) == 0
    manifest = json.loads((output / "matrix-execution.json").read_text())
    assert manifest["status"] == "completed", manifest
    assert [cell["status"] for cell in manifest["cells"]] == ["completed"] * 3
    for name in experiment.NAMES:
        bundle = output / "runs" / name / "invocations/fixture__semgrep__r1"
        result = json.loads((bundle / "result.json").read_text())
        assert result["status"] == "success" and len(result["claims"]) == 1, result
        assert conditions.classify_observation(bundle)["status"] == "attested"
    before = experiment.report(output)
    assert before["evidence_scope"] == "diagnostic" and before["corpus_evidence_scope"] == "draft"
    assert all(cell["condition_coverage"] == {"attested": 1} and cell["eligible_assignments"] == 1
               for cell in before["conditions"]), before["observations"]
    assert all(cell["target_detection"]["value"] is None for cell in before["conditions"])
    assert all(cell["target_outcomes"]["unreviewed"] == 1 and cell["target_outcomes"]["unresolved_matches"] == 1
               for cell in before["conditions"])
    assert all(cell["claims"]["records"] == 1 and cell["reviewed_precision"]["status"] == "unavailable"
               for cell in before["conditions"])
    for name in experiment.NAMES:
        run = output / "runs" / name
        bundle = run / "invocations/fixture__semgrep__r1"
        path = bundle / "evaluator/decisions.json"
        decisions = json.loads(path.read_text())
        assert len(decisions["claim_matches"]) == 1
        decisions["claim_matches"][0].update(decision="accepted", reason="Fictional diagnostic assertion of this exact fixture sink.")
        path.write_text(canonical_json(decisions) + "\n")
        assert main(["review", "record", str(bundle)]) == 0
        assert main(["review", "approve", str(bundle), "--reviewer", "Fictional diagnostic finding reviewer",
                     "--note", "Synthetic plumbing fixture only; this is not a real benchmark approval."]) == 0
    report_path = scratch / "paired-report.json"
    assert main(["matrix", "report", str(output), "--output", str(report_path)]) == 0
    after = json.loads(report_path.read_text())
    assert after["evidence_scope"] == "diagnostic" and after["assignments_scheduled"] == 3
    assert all(cell["target_detection"]["value"] == 1 for cell in after["conditions"]), after["observations"]
    assert all(row["resolved_pairs"] == row["planned_pairs"] == 1 and row["full_population_effect"]["value"] == 0
               for row in after["contrasts"]), after["contrasts"]
    identity = next(cell for cell in after["conditions"] if cell["condition"] == "identity_reduced")
    assert identity["identity_transformation_coverage"]["verified_invocations"] == 1
    assert identity["identity_transformation_coverage"]["invocation_totals"]["removed_files"] == 1
    assert isinstance(identity["identity_transformation_coverage"]["residual_category_occurrences"], dict)
    # One missing bundle preserves the frozen denominator, recorded execution state, and unknown
    # claim/usage coverage. Previously resolved other cells still contribute tighter bounds.
    missing = output / "runs/identity_reduced/invocations/fixture__semgrep__r1"
    shutil.rmtree(missing)
    incomplete = experiment.report(output)
    assert incomplete["assignments_scheduled"] == 3
    [contrast] = [row for row in incomplete["contrasts"] if row["right"] == "identity_reduced"]
    assert contrast["planned_pairs"] == 1 and contrast["full_population_effect"]["value"] is None
    row = next(row for row in incomplete["observations"] if row["condition"] == "identity_reduced")
    assert row["execution_state"] == "completed" and row["assignment_execution_state"] == "bound"
    assert row["status"] == "error" and row["reason"] == "unusable_bundle"
