"""Tests for the ScanEval PR scoring engine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from scoring import Finding
from pr_scoring import (
    _findings_match,
    synthesize_review_findings,
    score_pr_case,
    compute_pr_summary,
    PRCaseScoring,
    NEARBY_LINE_THRESHOLD,
)


# --- _findings_match tests ---


def test_findings_match_identical():
    a = Finding("r1", "ssrf", "tools/fetch.py", 10, 20)
    b = Finding("r1", "ssrf", "tools/fetch.py", 10, 20)
    assert _findings_match(a, b)


def test_findings_match_overlapping_lines():
    a = Finding("r1", "ssrf", "tools/fetch.py", 10, 20)
    b = Finding("r1", "ssrf", "tools/fetch.py", 15, 25)
    assert _findings_match(a, b)


def test_findings_no_match_different_path():
    a = Finding("r1", "ssrf", "tools/fetch.py", 10, 20)
    b = Finding("r1", "ssrf", "tools/other.py", 10, 20)
    assert not _findings_match(a, b)


def test_findings_no_match_different_kind():
    a = Finding("r1", "ssrf", "tools/fetch.py", 10, 20)
    b = Finding("r1", "command_injection", "tools/fetch.py", 10, 20)
    assert not _findings_match(a, b)


def test_findings_match_nearby_same_rule():
    """Same ruleId, nearby but non-overlapping lines should match."""
    a = Finding("r1", "ssrf", "tools/fetch.py", 10, 15)
    b = Finding("r1", "ssrf", "tools/fetch.py", 20, 25)
    # distance = min(|10-20|, |15-25|, |10-25|, |15-20|) = 5
    assert _findings_match(a, b)


def test_findings_no_match_far_apart():
    """Lines too far apart should not match."""
    a = Finding("r1", "ssrf", "tools/fetch.py", 10, 15)
    b = Finding("r1", "ssrf", "tools/fetch.py", 50, 55)
    assert not _findings_match(a, b)


def test_findings_different_rule_requires_overlap():
    """Different ruleId requires real line overlap, not just nearby."""
    a = Finding("rule-a", "ssrf", "tools/fetch.py", 10, 15)
    b = Finding("rule-b", "ssrf", "tools/fetch.py", 20, 25)
    # Different ruleId -> no nearby threshold, need real overlap
    assert not _findings_match(a, b)


def test_findings_different_rule_with_overlap():
    """Different ruleId but overlapping lines should still match."""
    a = Finding("rule-a", "ssrf", "tools/fetch.py", 10, 22)
    b = Finding("rule-b", "ssrf", "tools/fetch.py", 20, 25)
    assert _findings_match(a, b)


def test_findings_match_normalizes_paths():
    a = Finding("r1", "ssrf", "tools\\fetch.py", 10, 20)
    b = Finding("r1", "ssrf", "tools/fetch.py", 10, 20)
    assert _findings_match(a, b)


def test_findings_match_at_threshold_boundary():
    """Findings exactly at NEARBY_LINE_THRESHOLD should match."""
    a = Finding("r1", "ssrf", "f.py", 10, 10)
    b = Finding("r1", "ssrf", "f.py", 10 + NEARBY_LINE_THRESHOLD, 10 + NEARBY_LINE_THRESHOLD)
    assert _findings_match(a, b)


def test_findings_no_match_one_past_threshold():
    """Findings one line beyond threshold should not match."""
    a = Finding("r1", "ssrf", "f.py", 10, 10)
    b = Finding("r1", "ssrf", "f.py", 10 + NEARBY_LINE_THRESHOLD + 1, 10 + NEARBY_LINE_THRESHOLD + 1)
    assert not _findings_match(a, b)


# --- synthesize_review_findings tests ---


def test_synthesize_new_finding():
    """Finding in head but not in base is a review finding."""
    base = [Finding("r1", "ssrf", "f.py", 10, 20)]
    head = [
        Finding("r1", "ssrf", "f.py", 10, 20),  # exists in base
        Finding("r2", "ssrf", "g.py", 5, 10),    # new in head
    ]
    review = synthesize_review_findings(base, head)
    assert len(review) == 1
    assert review[0].path == "g.py"


def test_synthesize_empty_base():
    """All head findings are new when base is empty."""
    head = [
        Finding("r1", "ssrf", "f.py", 10, 20),
        Finding("r2", "ssrf", "g.py", 5, 10),
    ]
    review = synthesize_review_findings([], head)
    assert len(review) == 2


def test_synthesize_identical_trees():
    """No review findings when base and head are identical."""
    findings = [Finding("r1", "ssrf", "f.py", 10, 20)]
    review = synthesize_review_findings(findings, list(findings))
    assert len(review) == 0


def test_synthesize_shifted_lines():
    """Finding that shifted slightly should not be a review finding."""
    base = [Finding("r1", "ssrf", "f.py", 10, 15)]
    head = [Finding("r1", "ssrf", "f.py", 12, 17)]  # shifted 2 lines
    review = synthesize_review_findings(base, head)
    assert len(review) == 0


# --- score_pr_case tests ---


def _make_sv_case():
    return {
        "id": "SB-PY-SV-001",
        "caseType": "synthetic_vulnerable",
        "regions": [
            {
                "id": "R1",
                "path": "tools/fetcher.py",
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


def _make_mi_case():
    return {
        "id": "SB-PY-MI-001",
        "caseType": "mixed_intent",
        "regions": [
            {
                "id": "R1",
                "path": "tools/safe.py",
                "startLine": 10,
                "endLine": 30,
                "label": "capability_safe",
                "capability": "network",
                "requiredGuards": ["host_allowlist"],
            },
            {
                "id": "R2",
                "path": "tools/unsafe.py",
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


def test_score_pr_target_detected():
    case = _make_sv_case()
    review = [Finding("r1", "ssrf", "tools/fetcher.py", 20, 25)]
    scoring = score_pr_case(case, review)
    assert scoring.introduced_targets_detected == 1
    assert scoring.introduced_targets_total == 1
    assert scoring.introduced_target_hit_rate == 1.0
    assert scoring.review_noise == 0


def test_score_pr_target_missed():
    case = _make_sv_case()
    review = []  # no findings
    scoring = score_pr_case(case, review)
    assert scoring.introduced_targets_detected == 0
    assert scoring.introduced_targets_total == 1
    assert scoring.introduced_target_hit_rate == 0.0


def test_score_pr_noisy_review():
    case = _make_sv_case()
    review = [
        Finding("r1", "ssrf", "tools/fetcher.py", 20, 25),        # hits target
        Finding("r2", "command_injection", "tools/other.py", 5, 10),  # noise
    ]
    scoring = score_pr_case(case, review)
    assert scoring.introduced_targets_detected == 1
    assert scoring.review_noise == 1


def test_score_pr_capability_noise():
    case = _make_mi_case()
    review = [
        Finding("r1", "ssrf", "tools/unsafe.py", 15, 25),  # hits R2
        Finding("r2", "ssrf", "tools/safe.py", 15, 25),    # flags R1 (cap noise)
    ]
    scoring = score_pr_case(case, review)
    assert scoring.introduced_targets_detected == 1
    assert scoring.capability_noise == 1
    assert scoring.review_noise == 0


def test_score_pr_wrong_kind_not_target_hit():
    """Finding with wrong kind should not count as target detected."""
    case = _make_sv_case()
    review = [Finding("r1", "command_injection", "tools/fetcher.py", 20, 25)]
    scoring = score_pr_case(case, review)
    assert scoring.introduced_targets_detected == 0
    assert scoring.review_noise == 1


# --- compute_pr_summary tests ---


def test_pr_summary_perfect():
    scorings = [
        PRCaseScoring("c1", introduced_targets_detected=1, introduced_targets_total=1),
        PRCaseScoring("c2", introduced_targets_detected=1, introduced_targets_total=1),
    ]
    summary = compute_pr_summary(scorings)
    assert summary.introduced_target_hit_rate == 1.0
    assert summary.cases_evaluated == 2
    assert summary.cases_skipped == 0


def test_pr_summary_partial():
    scorings = [
        PRCaseScoring("c1", introduced_targets_detected=1, introduced_targets_total=1),
        PRCaseScoring("c2", introduced_targets_detected=0, introduced_targets_total=1,
                      review_noise=3),
    ]
    summary = compute_pr_summary(scorings, skipped=1)
    assert summary.introduced_target_hit_rate == 0.5
    assert summary.total_review_noise == 3
    assert summary.cases_skipped == 1


def test_pr_summary_no_targets():
    scorings = [PRCaseScoring("c1", introduced_targets_detected=0, introduced_targets_total=0)]
    summary = compute_pr_summary(scorings)
    assert summary.introduced_target_hit_rate == 0.0
