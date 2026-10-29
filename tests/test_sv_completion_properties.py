"""Bounded generated checks for the actual SV completion decision boundary."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_sv_completion_properties", ROOT / "scripts/check_sv_completion_properties.py")
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)
case_summary = checker.case_summary
generated_cases = checker.generated_cases
oracle = checker.oracle
production_decision = checker.production_decision
run_checker = checker.run_checker


@pytest.fixture(scope="module")
def checker_result() -> dict:
    return run_checker()


def test_bounded_checker_calls_production_for_all_expected_states(checker_result):
    assert checker_result["checked"] == 851
    assert checker_result["family_counts"] == {
        "all_excluded": 1,
        "completion_compatibility": 90,
        "contract_guards": 40,
        "finding_reachability": 2,
        "inventory_assignment": 144,
        "malformed_boundaries": 24,
        "native_health": 32,
        "pairing_binding": 288,
        "terminal_product": 102,
        "workflow_stages": 128,
    }
    assert checker_result["expected_accepted"] == 40
    assert checker_result["expected_rejected"] == 811
    assert checker_result["production_mismatches"] == []
    assert checker_result["ok"] is True


def test_positive_boundaries_are_reachable_and_rejected_all_is_not_conforming():
    cases = {case.name: case for case in generated_cases()}
    names = [
        "all-excluded-not-required",
        "two-independent-files-findings-0",
        "two-independent-files-findings-1",
        "configured-disabled-lint",
        "recognized-metadata-readme-md",
        "recognized-code-scope-exclusion",
        "recognized-no-source-review",
        "recognized-known-non-code-filename",
        "recognized-known-non-code-format",
        "recognized-known-non-code-data",
    ]
    for name in names:
        case = cases[name]
        assert checker.expected_decision(case) is True
        assert production_decision(case_summary(case)).accepted is True


def test_checker_finds_concrete_witnesses_for_abstract_faults_and_guard_removals(checker_result):
    checks = checker_result["faulty_acceptance_checks"]
    assert set(checks) == {
        "always_accept",
        "always_reject",
        "ignore_missing_receipt",
        "collapse_duplicate_receipts",
        "ignore_native_failure",
        "remove_digest_guard",
        "remove_input_guard",
        "remove_stage_evidence_guard",
        "remove_original_binding_guards",
        "remove_inventory_policy_guard",
    }
    for name, check in checks.items():
        expected_kind = "production_guard_removal" if name.startswith("remove_") else "abstract_acceptance_function"
        assert check["kind"] == expected_kind, name
        assert check["detected"] is True, name
        assert check["witness"]["case"], name
        assert check["witness"]["expected"] != check["witness"]["faulty_accepted"], name


def test_critical_predicates_have_non_vacuity_witnesses_and_runtime_source_hashes(checker_result):
    witnesses = checker_result["non_vacuity_witnesses"]
    required = {
        "accepted_complete", "accepted_all_excluded", "accepted_two_independent_files",
        "accepted_zero_findings", "accepted_findings", "accepted_disabled_lint",
        "accepted_recognized_metadata", "accepted_code_scope_exclusion", "accepted_no_source_review",
        "accepted_known_non_code_filename", "accepted_known_non_code_format", "accepted_known_non_code_data",
        "rejected_unassigned", "rejected_unsupported", "rejected_missing_receipt",
        "rejected_duplicate_receipt", "rejected_inconclusive_terminal", "rejected_missing_terminal",
        "rejected_workflow_stage", "rejected_native_health", "rejected_failed_call",
        "rejected_pending_call", "rejected_bad_legacy_reason", "rejected_partial_source",
        "rejected_malformed", "rejected_duplicate_inventory", "rejected_duplicate_obligation",
        "rejected_duplicate_terminal", "rejected_digest_tamper", "rejected_input_binding",
        "rejected_input_removal", "rejected_stage_evidence", "rejected_metadata_code_bypass",
        "rejected_unknown_metadata_suffix", "rejected_executable_metadata_suffix",
        "rejected_extensionless_metadata_forgery", "rejected_forged_known_non_code_filename",
        "rejected_forged_known_non_code_format", "rejected_forged_known_non_code_data",
        "rejected_forged_no_source_review", "rejected_forged_code_scope_exclusion",
        "rejected_boundary_bom_forged_exclusion", "rejected_additional_extension_bypass",
        "rejected_original_invocation",
        "rejected_original_request", "rejected_original_response", "rejected_obligation_inventory_bytes",
        "rejected_stale_head", "rejected_positive_mode", "rejected_multiple_models",
        "rejected_positive_reasons", "rejected_call_outside_inventory",
        "rejected_assigned_undelivered_inventory", "rejected_assigned_undelivered_outside_inventory",
        "rejected_malformed_selection_entry", "rejected_missing_anchor_summary",
        "rejected_null_anchor_summary", "rejected_list_anchor_summary",
        "rejected_not_required_stage", "rejected_unknown_field", "rejected_unknown_enum",
        "rejected_unknown_preimage",
        *{f"rejected_binding_{binding}" for binding in
          ("invocation", "model", "hypothesis", "shard", "source", "request", "file")},
    }
    assert required == set(witnesses)
    hashes = checker_result["source_binding"]["sha256"]
    assert "src/scaneval/adapters/llm_harness.py" in hashes
    assert "scripts/check_sv_completion_properties.py" in hashes
    assert all(len(digest) == 64 for digest in hashes.values())
    assert "no full formal proof artifact" in checker_result["claim"]
