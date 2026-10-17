"""Public numeric representations and saved reader boundary regressions."""
from copy import deepcopy
import json
import math

import pytest

from scaneval import aggregate, gate, precision
from scaneval.cli import main
from scaneval.contracts import ContractError, canonical_sha256, load_document, validate_document
from test_v2_aggregate import two_project_run, policy
from test_v2_gate import small_comparison
from test_v2_precision import one_system_run, review_all


@pytest.mark.parametrize('spelling', ['3.0', '3e0'])
def test_integral_bootstrap_and_schedule(tmp_path, spelling):
    run = two_project_run(tmp_path)
    configured = policy(replicates=3, min_clusters=2)
    configured['uncertainty']['replicates'] = json.loads(spelling)
    before = canonical_sha256(configured)
    report = aggregate.aggregate([run], policy=configured)
    assert report['views']
    assert canonical_sha256(configured) == before
    schedule = json.loads((run / 'evaluator/schedule.json').read_text())
    schedule['repetitions'] = json.loads('1e0')
    before = canonical_sha256(schedule)
    path = tmp_path / 'schedule.json'
    path.write_text(json.dumps(schedule))
    assert load_document(path, 'evaluation-schedule') == schedule
    assert main(['validate', 'evaluation-schedule', str(path)]) == 0
    assert canonical_sha256(schedule) == before


@pytest.mark.parametrize('value', [True, 1.5])
def test_nonintegral_count_refusal(value):
    configured = policy(replicates=3)
    configured['uncertainty']['replicates'] = value
    with pytest.raises(ContractError):
        validate_document('aggregation-policy', configured)

@pytest.mark.parametrize('spelling', ['1.0', '1e0'])
def test_integral_review_budget_uses_integer_metric_keys(spelling):
    from scaneval.scoring import score
    from test_v2_scoring import make_plan, make_result, make_decisions, claim
    plan = make_plan(controls=[])
    plan['review_budgets'] = [json.loads(spelling)]
    result = make_result([claim('a', 'first'), claim('b', 'second')], ranking='unranked')
    decisions = make_decisions(result, matches=[('a', 'T1', 'accepted', 'fixture')])
    before = canonical_sha256(plan)
    actual = score(plan, result, decisions)
    integer = deepcopy(plan)
    integer['review_budgets'] = [1]
    assert actual['metrics'] == score(integer, result, decisions)['metrics']
    assert actual['metrics']['random_order_expected_recall'] == {'1': .25}
    assert canonical_sha256(plan) == before

@pytest.mark.parametrize('case', ['missing', 'duplicate', 'pairs', 'full_output_recall', 'coverage'])
def test_saved_comparison_reader_rejects_inconsistent_shapes(tmp_path, case):
    comparison = small_comparison(tmp_path, 'reader')
    view = comparison['views'][0]
    if case == 'missing':
        view['differences'][0]['detection'] = []
    elif case == 'duplicate':
        view['differences'][0]['detection'].append(deepcopy(view['differences'][0]['detection'][0]))
    else:
        view['systems']['baseline']['slices'][0]['detection'][0][case] = None
    with pytest.raises(ContractError):
        validate_document('comparison-report', comparison)
    from test_v2_gate import full_policy
    with pytest.raises(ContractError):
        gate.evaluate_gate(full_policy(), comparison)
    path, policy_path, output = (tmp_path / name for name in ['comparison.json', 'policy.json', 'decision.json'])
    path.write_text(json.dumps(comparison))
    policy_path.write_text(json.dumps(full_policy()))
    assert main(['gate', '--policy', str(policy_path), '--comparison', str(path), '--output', str(output)]) == 2
    assert not output.exists()

def test_generated_unavailable_detection_remains_supported(tmp_path):
    from test_v2_aggregate import write_run, planned
    run = write_run(tmp_path, 'empty', [planned('input')], systems=('baseline', 'candidate'))
    comparison = aggregate.compare([run], baseline='baseline', candidate='candidate', policy=policy(replicates=3))
    validate_document('comparison-report', comparison)
    for block in comparison['views'][0]['differences'][0]['detection']:
        assert block['state'] == 'unavailable'
        assert block['full_output_recall'] is None
