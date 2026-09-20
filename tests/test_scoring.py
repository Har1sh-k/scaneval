"""Tests for the ScanEval scoring engine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from scoring import Finding, classify_findings, compute_summary, regions_overlap


def test_regions_overlap_same_file():
    assert regions_overlap("tools/runner.py", 10, 20, "tools/runner.py", 15, 25)
    assert regions_overlap("tools/runner.py", 10, 20, "tools/runner.py", 10, 20)
    assert regions_overlap("tools/runner.py", 10, 20, "tools/runner.py", 5, 15)


def test_regions_no_overlap():
    assert not regions_overlap("tools/runner.py", 10, 20, "tools/runner.py", 25, 30)
    assert not regions_overlap("tools/runner.py", 10, 20, "tools/other.py", 10, 20)


def test_regions_overlap_normalizes_paths():
    assert regions_overlap("tools\\runner.py", 10, 20, "tools/runner.py", 10, 20)


def test_classify_true_positive():
    case = {
        "id": "SB-PY-SV-001",
        "caseType": "synthetic_vulnerable",
        "regions": [
            {
                "id": "R1",
                "path": "project/tools/fetcher.py",
                "startLine": 15,
                "endLine": 34,
                "label": "vulnerable",
                "acceptedKinds": ["ssrf"],
            }
        ],
        "expectedOutcome": {
            "mustDetectRegionIds": ["R1"],
            "mustNotFlagRegionIds": [],
        },
    }

    findings = [
        Finding(
            rule_id="python.ssrf",
            mapped_kind="ssrf",
            path="project/tools/fetcher.py",
            start_line=20,
            end_line=25,
        )
    ]

    scoring, classifications = classify_findings(case, findings)
    assert scoring.true_positives == 1
    assert scoring.false_negatives == 0
    assert classifications[0].classification == "true_positive"
    assert classifications[0].matched_region_id == "R1"


def test_classify_false_negative():
    case = {
        "id": "SB-PY-SV-001",
        "caseType": "synthetic_vulnerable",
        "regions": [
            {
                "id": "R1",
                "path": "project/tools/fetcher.py",
                "startLine": 15,
                "endLine": 34,
                "label": "vulnerable",
                "acceptedKinds": ["ssrf"],
            }
        ],
        "expectedOutcome": {
            "mustDetectRegionIds": ["R1"],
            "mustNotFlagRegionIds": [],
        },
    }

    findings = []  # No findings

    scoring, classifications = classify_findings(case, findings)
    assert scoring.true_positives == 0
    assert scoring.false_negatives == 1


def test_classify_capability_false_positive():
    case = {
        "id": "SB-PY-CS-001",
        "caseType": "capability_safe",
        "regions": [
            {
                "id": "R1",
                "path": "project/tools/runner.py",
                "startLine": 10,
                "endLine": 30,
                "label": "capability_safe",
                "capability": "code_execution",
                "requiredGuards": ["allowlist"],
            }
        ],
        "expectedOutcome": {
            "mustDetectRegionIds": [],
            "mustNotFlagRegionIds": ["R1"],
        },
    }

    # Kind matches capability: command_injection -> code_execution
    findings = [
        Finding(
            rule_id="python.subprocess",
            mapped_kind="command_injection",
            path="project/tools/runner.py",
            start_line=15,
            end_line=20,
        )
    ]

    scoring, classifications = classify_findings(case, findings)
    assert scoring.capability_false_positives == 1
    assert scoring.true_positives == 0
    assert classifications[0].classification == "capability_false_positive"


def test_classify_capability_safe_kind_mismatch():
    """Finding with wrong kind for the capability should NOT count as cap FP."""
    case = {
        "id": "SB-PY-CS-001",
        "caseType": "capability_safe",
        "regions": [
            {
                "id": "R1",
                "path": "project/tools/runner.py",
                "startLine": 10,
                "endLine": 30,
                "label": "capability_safe",
                "capability": "code_execution",
                "requiredGuards": ["allowlist"],
            }
        ],
        "expectedOutcome": {
            "mustDetectRegionIds": [],
            "mustNotFlagRegionIds": ["R1"],
        },
    }

    # ssrf does NOT match code_execution capability
    findings = [
        Finding(
            rule_id="python.ssrf",
            mapped_kind="ssrf",
            path="project/tools/runner.py",
            start_line=15,
            end_line=20,
        )
    ]

    scoring, _ = classify_findings(case, findings)
    assert scoring.capability_false_positives == 0
    assert scoring.false_positives == 1


def test_classify_mixed_intent():
    case = {
        "id": "SB-PY-MI-001",
        "caseType": "mixed_intent",
        "regions": [
            {
                "id": "R1",
                "path": "project/tools/safe.py",
                "startLine": 10,
                "endLine": 30,
                "label": "capability_safe",
                "capability": "network",
                "requiredGuards": ["host_allowlist"],
            },
            {
                "id": "R2",
                "path": "project/tools/unsafe.py",
                "startLine": 10,
                "endLine": 30,
                "label": "vulnerable",
                "acceptedKinds": ["ssrf"],
            },
        ],
        "expectedOutcome": {
            "mustDetectRegionIds": ["R2"],
            "mustNotFlagRegionIds": ["R1"],
        },
    }

    # Perfect result: finds vuln, doesn't flag safe
    findings = [
        Finding(
            rule_id="python.ssrf",
            mapped_kind="ssrf",
            path="project/tools/unsafe.py",
            start_line=15,
            end_line=20,
        )
    ]

    scoring, _ = classify_findings(case, findings)
    assert scoring.true_positives == 1
    assert scoring.false_negatives == 0
    assert scoring.capability_false_positives == 0


def test_compute_summary_perfect():
    cases = [
        {"id": "SB-PY-SV-001", "caseType": "synthetic_vulnerable", "regions": [{"label": "vulnerable"}]},
        {"id": "SB-PY-CS-001", "caseType": "capability_safe", "regions": [{"label": "capability_safe"}]},
        {"id": "SB-PY-MI-001", "caseType": "mixed_intent", "regions": [{"label": "vulnerable"}, {"label": "capability_safe"}]},
    ]

    from scoring import CaseScoring

    scorings = [
        CaseScoring(case_id="SB-PY-SV-001", case_type="synthetic_vulnerable", true_positives=1, false_negatives=0),
        CaseScoring(case_id="SB-PY-CS-001", case_type="capability_safe", capability_false_positives=0),
        CaseScoring(case_id="SB-PY-MI-001", case_type="mixed_intent", true_positives=1, false_negatives=0, capability_false_positives=0),
    ]

    summary = compute_summary(scorings, cases)
    assert summary.recall == 1.0
    assert summary.capability_fp_rate == 0.0
    assert summary.mixed_intent_accuracy == 1.0
    assert summary.agentic_score == 1.0


def test_capability_fp_rate_counts_cases_not_regions():
    cases = [
        {
            "id": "SB-PY-CS-001",
            "caseType": "capability_safe",
            "regions": [
                {"label": "capability_safe"},
                {"label": "capability_safe"},
            ],
        },
        {
            "id": "SB-PY-MI-001",
            "caseType": "mixed_intent",
            "regions": [
                {"label": "vulnerable"},
                {"label": "capability_safe"},
            ],
        },
    ]

    from scoring import CaseScoring

    scorings = [
        CaseScoring(
            case_id="SB-PY-CS-001",
            case_type="capability_safe",
            capability_false_positives=2,
        ),
        CaseScoring(
            case_id="SB-PY-MI-001",
            case_type="mixed_intent",
            capability_false_positives=0,
        ),
    ]

    summary = compute_summary(scorings, cases)
    assert summary.capability_fp_rate == 0.5


if __name__ == "__main__":
    test_regions_overlap_same_file()
    test_regions_no_overlap()
    test_regions_overlap_normalizes_paths()
    test_classify_true_positive()
    test_classify_false_negative()
    test_classify_capability_false_positive()
    test_classify_capability_safe_kind_mismatch()
    test_classify_mixed_intent()
    test_compute_summary_perfect()
    test_capability_fp_rate_counts_cases_not_regions()
    print("All tests passed.")
