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
