"""Bounded generated checks for the actual SV completion decision boundary."""

from __future__ import annotations

import pytest

from scripts.check_sv_completion_properties import (
    case_summary,
    generated_cases,
    oracle,
    production_decision,
    run_checker,
)


@pytest.fixture(scope="module")
def checker_result() -> dict:
    return run_checker()


def test_bounded_checker_calls_production_for_all_711_expected_states(checker_result):
    assert checker_result["checked"] == 711
    assert checker_result["family_counts"] == {
        "all_excluded": 1,
        "completion_compatibility": 90,
        "finding_reachability": 2,
        "inventory_assignment": 144,
        "malformed_boundaries": 20,
        "native_health": 32,
        "pairing_binding": 288,
        "terminal_product": 102,
        "workflow_stages": 32,
    }
    assert checker_result["production_mismatches"] == []
    assert checker_result["ok"] is True


def test_positive_boundaries_are_reachable_and_rejected_all_is_not_conforming():
    cases = {case.name: case for case in generated_cases()}
    names = [
        "all-excluded-not-required",
        "two-independent-files-findings-0",
        "two-independent-files-findings-1",
    ]
    for name in names:
        case = cases[name]
        assert oracle(case.state) is True
        assert production_decision(case_summary(case)).accepted is True


def test_checker_finds_concrete_witnesses_for_every_faulty_acceptance_function(checker_result):
    checks = checker_result["faulty_acceptance_checks"]
    assert set(checks) == {
        "always_accept",
        "always_reject",
        "ignore_missing_receipt",
        "collapse_duplicate_receipts",
        "ignore_native_failure",
    }
    for name, check in checks.items():
        assert check["kind"] == "abstract_acceptance_function", name
        assert check["detected"] is True, name
        assert check["witness"]["case"], name
        assert check["witness"]["expected"] != check["witness"]["faulty_accepted"], name


def test_critical_predicates_have_non_vacuity_witnesses_and_runtime_source_hashes(checker_result):
    witnesses = checker_result["non_vacuity_witnesses"]
    assert {
        "accepted_complete", "accepted_all_excluded", "accepted_two_independent_files",
        "accepted_zero_findings", "accepted_findings", "rejected_unassigned",
        "rejected_unsupported", "rejected_missing_receipt", "rejected_duplicate_receipt",
        "rejected_inconclusive_terminal", "rejected_missing_terminal",
        "rejected_workflow_stage", "rejected_native_health", "rejected_failed_call",
        "rejected_pending_call", "rejected_bad_legacy_reason", "rejected_partial_source",
        "rejected_malformed", "rejected_duplicate_inventory",
        "rejected_duplicate_obligation", "rejected_duplicate_terminal",
        "rejected_binding_invocation", "rejected_binding_model", "rejected_binding_hypothesis",
        "rejected_binding_shard", "rejected_binding_source", "rejected_binding_request",
        "rejected_binding_file",
    } == set(witnesses)
    hashes = checker_result["source_binding"]["sha256"]
    assert "src/scaneval/adapters/llm_harness.py" in hashes
    assert "scripts/check_sv_completion_properties.py" in hashes
    assert all(len(digest) == 64 for digest in hashes.values())
    assert "no full formal proof artifact" in checker_result["claim"]
