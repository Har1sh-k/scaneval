"""Deterministic, versioned draws: identical seeds give identical samples on every Python."""

from __future__ import annotations

from collections import Counter
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scaneval.contracts import ContractError
from scaneval.resampling import (
    ALGORITHM,
    Stream,
    resample_with_replacement,
    sample_without_replacement,
)


def test_the_algorithm_is_pinned_by_a_regression_vector():
    """A change to how words become integers must fail here, because recorded samples depend on it."""
    assert ALGORITHM == "sha256-counter-v1"
    stream = Stream(0, label="regression-vector")
    assert [stream.below(1000) for _ in range(8)] == [645, 788, 563, 85, 478, 487, 396, 156]
    units = [f"u{i:02d}" for i in range(20)]
    assert sample_without_replacement(units, 5, Stream(20260929, label="regression-vector")) == [
        "u01", "u12", "u00", "u04", "u17"]
    assert resample_with_replacement(6, Stream(7, label="bootstrap")) == [2, 0, 3, 4, 2, 1]


def test_seed_and_label_each_select_an_independent_stream():
    first = [Stream(1, label="stratum-a").below(10**9) for _ in range(3)]
    again = [Stream(1, label="stratum-a").below(10**9) for _ in range(3)]
    assert first == again
    assert Stream(1, label="stratum-a").below(10**9) != Stream(1, label="stratum-b").below(10**9)
    assert Stream(1, label="stratum-a").below(10**9) != Stream(2, label="stratum-a").below(10**9)


def test_inclusion_probability_matches_simple_random_sampling_without_replacement():
    """Each of N units is drawn with probability n/N; checked over many independent seeds."""
    units = [f"unit-{index}" for index in range(10)]
    counts: Counter[str] = Counter()
    trials = 4000
    for seed in range(trials):
        drawn = sample_without_replacement(units, 3, Stream(seed, label="inclusion"))
        assert len(set(drawn)) == 3
        counts.update(drawn)
    for unit in units:
        assert abs(counts[unit] / trials - 0.3) < 0.03, unit


def test_draws_are_uniform_across_residues():
    stream = Stream(11, label="uniformity")
    counts = Counter(stream.below(7) for _ in range(7000))
    assert set(counts) == set(range(7))
    assert all(abs(count - 1000) < 120 for count in counts.values())


@pytest.mark.parametrize("seed", [-1, 1.5, "7", True, None])
def test_a_seed_must_be_a_non_negative_integer(seed):
    with pytest.raises(ContractError, match="seed"):
        Stream(seed, label="x")


def test_sizes_and_bounds_are_refused_rather_than_coerced():
    stream = Stream(0, label="bounds")
    with pytest.raises(ContractError):
        stream.below(0)
    with pytest.raises(ContractError):
        sample_without_replacement(["a", "b"], 3, stream)
    with pytest.raises(ContractError):
        sample_without_replacement(["a"], -1, stream)
    with pytest.raises(ContractError):
        resample_with_replacement(0, stream)
    assert sample_without_replacement(["a", "b"], 0, stream) == []
