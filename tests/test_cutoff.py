"""Tests for model knowledge-cutoff gating (scripts/cutoff.py)."""

import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from cutoff import (
    case_horizon,
    case_passes_cutoff,
    load_models,
    parse_date,
    partition_by_cutoff,
    resolve_model_cutoff,
)


def _rw_case(case_id, **dates):
    return {"id": case_id, "caseType": "real_world_disclosed", "realWorld": {"disclosure": dates}}


def test_registry_has_opus_48():
    _, cutoff = resolve_model_cutoff("opus-4.8")
    assert cutoff == date(2026, 1, 31)


def test_registry_resolves_aliases():
    canonical, cutoff = resolve_model_cutoff("claude-opus-4-8[1m]")
    assert canonical == "opus-4.8"
    assert cutoff == date(2026, 1, 31)
    # case-insensitive
    assert resolve_model_cutoff("OPUS4.8")[0] == "opus-4.8"


def test_unknown_model_raises():
    with pytest.raises(KeyError):
        resolve_model_cutoff("totally-made-up-model")


def test_horizon_is_min_of_present_dates():
    case = _rw_case("X", ghsaPublished="2026-06-18", fixCommitDate="2026-05-06")
    assert case_horizon(case) == date(2026, 5, 6)


def test_horizon_none_when_no_disclosure():
    assert case_horizon({"id": "X", "caseType": "synthetic_vulnerable"}) is None


def test_passes_cutoff_strictly_after():
    cutoff = date(2026, 1, 31)
    assert case_passes_cutoff(_rw_case("after", fixCommitDate="2026-02-01"), cutoff) is True
    assert case_passes_cutoff(_rw_case("before", fixCommitDate="2026-01-30"), cutoff) is False
    # exact cutoff is NOT strictly after -> excluded
    assert case_passes_cutoff(_rw_case("equal", fixCommitDate="2026-01-31"), cutoff) is False


def test_undated_cases_are_never_gated():
    cutoff = date(2026, 1, 31)
    synthetic = {"id": "S", "caseType": "synthetic_vulnerable"}
    assert case_passes_cutoff(synthetic, cutoff) is True


def test_partition_splits_and_reports_horizon():
    cutoff = date(2026, 1, 31)
    cases = [
        (Path("a"), _rw_case("KEEP", ghsaPublished="2026-06-18", fixCommitDate="2026-05-06")),
        (Path("b"), _rw_case("DROP", fixCommitDate="2025-12-30")),
        (Path("c"), {"id": "SYN", "caseType": "synthetic_vulnerable"}),
    ]
    kept, excluded = partition_by_cutoff(cases, cutoff)
    kept_ids = {c["id"] for _, c in kept}
    assert kept_ids == {"KEEP", "SYN"}
    assert excluded == [("DROP", "2025-12-30")]


def test_parse_date():
    assert parse_date("2026-01-31") == date(2026, 1, 31)


def test_models_registry_well_formed():
    registry = load_models()
    assert registry["models"], "registry must list at least one model"
    for model in registry["models"]:
        assert model["id"]
        assert parse_date(model["knowledgeCutoff"])
