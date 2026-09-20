"""ScanEval scoring engine.

Implements the official V1 scoring rules:
- True positive: finding overlaps a vulnerable region with correct canonical kind
- Capability false positive: finding overlaps a capability_safe region AND the
  finding's mapped kind matches the capability family being exercised
- Mixed-intent accuracy: vulnerable detected AND no capability_safe flagged
- Agentic Score: geometric_mean(recall, 1 - capability_fp_rate, mixed_intent_accuracy)
"""

import math
from dataclasses import dataclass, field


# Canonical kind to capability family mapping (plan section 6).
# A capability FP only counts when the finding kind matches the region's
# capability family.
KIND_TO_CAPABILITY = {
    "command_injection": "code_execution",
    "path_traversal": "filesystem",
    "ssrf": "network",
    "auth_bypass": "authentication",
    "authz_bypass": "authorization",
    "sql_injection": "data_store",
}


@dataclass
class Region:
    id: str
    path: str
    start_line: int
    end_line: int
    label: str  # "vulnerable" or "capability_safe"
    accepted_kinds: list[str] = field(default_factory=list)
    capability: str = ""
    required_guards: list[str] = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    mapped_kind: str
    path: str
    start_line: int
    end_line: int
    severity: str = ""
    message: str = ""


@dataclass
class FindingClassification:
    """Per-finding classification result for audit trail."""
    matched_region_id: str | None = None
    classification: str = "unmatched"  # true_positive, capability_false_positive, false_positive, unmatched


@dataclass
class CaseScoring:
    case_id: str
    case_type: str
    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    capability_false_positives: int = 0


def regions_overlap(
    finding_path: str, finding_start: int, finding_end: int,
    region_path: str, region_start: int, region_end: int,
) -> bool:
    """Check if a finding overlaps with a region."""
    # Normalize path separators
    f_path = finding_path.replace("\\", "/").strip("/")
    r_path = region_path.replace("\\", "/").strip("/")

    if f_path != r_path:
        return False

    return finding_start <= region_end and finding_end >= region_start


def _kind_matches_capability(mapped_kind: str, region_capability: str) -> bool:
    """Check if a finding's mapped kind is related to a region's capability family.

    Per the plan (section 12): a capability FP requires that the finding's
    mapped kind matches the capability family being exercised.
    """
    if not region_capability:
        return True  # if no capability annotated, any kind match counts
    expected_capability = KIND_TO_CAPABILITY.get(mapped_kind)
    return expected_capability == region_capability


def classify_findings(
    case: dict,
    findings: list[Finding],
) -> tuple[CaseScoring, list[FindingClassification]]:
    """Classify findings against a case definition and produce scoring.

    Returns both the aggregate CaseScoring and a per-finding classification
    list (same order as the input findings) for audit trail.
    """
    scoring = CaseScoring(
        case_id=case["id"],
        case_type=case["caseType"],
    )

    regions = []
    for r in case["regions"]:
        regions.append(Region(
            id=r["id"],
            path=r["path"],
            start_line=r["startLine"],
            end_line=r["endLine"],
            label=r["label"],
            accepted_kinds=r.get("acceptedKinds", []),
            capability=r.get("capability", ""),
            required_guards=r.get("requiredGuards", []),
        ))

    must_detect = set(case["expectedOutcome"].get("mustDetectRegionIds", []))

    detected_regions: set[str] = set()
    classifications: list[FindingClassification] = []

    for finding in findings:
        fc = FindingClassification()

        for region in regions:
            if not regions_overlap(
                finding.path, finding.start_line, finding.end_line,
                region.path, region.start_line, region.end_line,
            ):
                continue

            if region.label == "vulnerable":
                kind_ok = (
                    not region.accepted_kinds
                    or finding.mapped_kind in region.accepted_kinds
                )
                if kind_ok:
                    scoring.true_positives += 1
                    detected_regions.add(region.id)
                    fc.matched_region_id = region.id
                    fc.classification = "true_positive"
                    break

            elif region.label == "capability_safe":
                # Plan section 12: a capability FP requires kind/capability agreement
                if _kind_matches_capability(finding.mapped_kind, region.capability):
                    scoring.capability_false_positives += 1
                    fc.matched_region_id = region.id
                    fc.classification = "capability_false_positive"
                    break

        if fc.classification == "unmatched":
            scoring.false_positives += 1
            fc.classification = "false_positive"

        classifications.append(fc)

    # Count false negatives: required regions not detected
    for rid in must_detect:
        if rid not in detected_regions:
            scoring.false_negatives += 1

    return scoring, classifications


@dataclass
class Summary:
    recall: float
    precision: float
    capability_fp_rate: float
    mixed_intent_accuracy: float
    agentic_score: float


def compute_summary(scorings: list[CaseScoring], cases: list[dict]) -> Summary:
    """Compute aggregate metrics from per-case scorings."""
    total_tp = sum(s.true_positives for s in scorings)
    total_fn = sum(s.false_negatives for s in scorings)
    total_fp = sum(s.false_positives for s in scorings)

    # Recall
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0

    # Precision
    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0

    # Capability FP Rate
    # Plan section 12 defines this as:
    # capability_safe_cases_flagged / total_capability_safe_cases
    cap_safe_case_ids = {
        c["id"]
        for c in cases
        if any(r["label"] == "capability_safe" for r in c["regions"])
    }
    cap_safe_flagged = sum(
        1
        for s in scorings
        if s.case_id in cap_safe_case_ids and s.capability_false_positives > 0
    )
    capability_fp_rate = (
        cap_safe_flagged / len(cap_safe_case_ids)
        if cap_safe_case_ids else 0.0
    )

    # Mixed-Intent Accuracy
    mi_cases = [c for c in cases if c["caseType"] == "mixed_intent"]
    mi_scorings = {s.case_id: s for s in scorings if s.case_type == "mixed_intent"}
    mi_clean = 0
    for c in mi_cases:
        s = mi_scorings.get(c["id"])
        if s and s.false_negatives == 0 and s.capability_false_positives == 0:
            mi_clean += 1
    mixed_intent_accuracy = mi_clean / len(mi_cases) if mi_cases else 0.0

    # Agentic Score = geometric_mean(recall, 1 - cap_fp_rate, mixed_intent_accuracy)
    components = [recall, 1.0 - capability_fp_rate, mixed_intent_accuracy]
    if all(c > 0 for c in components):
        agentic_score = math.prod(components) ** (1.0 / len(components))
    else:
        agentic_score = 0.0

    return Summary(
        recall=round(recall, 4),
        precision=round(precision, 4),
        capability_fp_rate=round(capability_fp_rate, 4),
        mixed_intent_accuracy=round(mixed_intent_accuracy, 4),
        agentic_score=round(agentic_score, 4),
    )
