"""ScanEval PR mode scoring engine.

Implements PR-specific scoring rules:
- Review findings: new-in-head findings not present in base
- Introduced target detection: review findings that hit mustDetectRegionIds
- Review noise: review findings that don't match introduced targets
- Capability noise: review findings that match capability_safe regions

Reuses overlap helpers from scoring.py where applicable.
"""

from dataclasses import dataclass, field

from scoring import Finding, Region, regions_overlap, _kind_matches_capability


NEARBY_LINE_THRESHOLD = 10


@dataclass
class PRCaseScoring:
    """PR-specific scoring for a single case."""
    case_id: str
    introduced_targets_detected: int = 0
    introduced_targets_total: int = 0
    review_noise: int = 0
    capability_noise: int = 0

    @property
    def introduced_target_hit_rate(self) -> float:
        if self.introduced_targets_total == 0:
            return 0.0
        return self.introduced_targets_detected / self.introduced_targets_total


@dataclass
class PRSummary:
    """Aggregate PR metrics across all cases."""
    introduced_target_hit_rate: float = 0.0
    total_review_noise: int = 0
    total_capability_noise: int = 0
    cases_evaluated: int = 0
    cases_skipped: int = 0


def _findings_match(a: Finding, b: Finding) -> bool:
    """Check if two findings are the 'same' finding using conservative matching.

    Match criteria (strict):
    - same normalized path
    - same mappedKind
    - same ruleId if both have one (preferred)
    - overlapping line ranges OR endpoints within NEARBY_LINE_THRESHOLD lines
    """
    a_path = a.path.replace("\\", "/").strip("/")
    b_path = b.path.replace("\\", "/").strip("/")

    if a_path != b_path:
        return False

    if a.mapped_kind != b.mapped_kind:
        return False

    # If both have ruleId, require it to match
    if a.rule_id and b.rule_id and a.rule_id != b.rule_id:
        # ruleId differs — require real line overlap (no nearby threshold)
        return (a.start_line <= b.end_line and a.end_line >= b.start_line)

    # Check overlapping ranges
    if a.start_line <= b.end_line and a.end_line >= b.start_line:
        return True

    # Check nearby (within threshold)
    closest_distance = min(
        abs(a.start_line - b.start_line),
        abs(a.end_line - b.end_line),
        abs(a.start_line - b.end_line),
        abs(a.end_line - b.start_line),
    )
    return closest_distance <= NEARBY_LINE_THRESHOLD


def synthesize_review_findings(
    base_findings: list[Finding],
    head_findings: list[Finding],
) -> list[Finding]:
    """Compute new-in-head findings by diffing head against base.

    A head finding is "new" if no base finding matches it
    (same path, same kind, overlapping/nearby lines).
    """
    review: list[Finding] = []
    for hf in head_findings:
        is_existing = any(_findings_match(hf, bf) for bf in base_findings)
        if not is_existing:
            review.append(hf)
    return review


def _build_regions(case: dict) -> list[Region]:
    """Build Region objects from case definition."""
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
    return regions


def score_pr_case(
    case: dict,
    review_findings: list[Finding],
) -> PRCaseScoring:
    """Score review findings against case targets for PR mode.

    - Checks each mustDetectRegionId to see if any review finding hits it
    - Counts review noise (findings that don't hit any target)
    - Counts capability noise (findings that hit capability_safe regions)
    """
    must_detect = set(case["expectedOutcome"].get("mustDetectRegionIds", []))
    regions = _build_regions(case)

    scoring = PRCaseScoring(
        case_id=case["id"],
        introduced_targets_total=len(must_detect),
    )

    detected_regions: set[str] = set()

    for finding in review_findings:
        matched_any_target = False
        matched_cap_safe = False

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
                if kind_ok and region.id in must_detect:
                    detected_regions.add(region.id)
                    matched_any_target = True
                    break

            elif region.label == "capability_safe":
                if _kind_matches_capability(finding.mapped_kind, region.capability):
                    matched_cap_safe = True
                    break

        if matched_cap_safe:
            scoring.capability_noise += 1
        elif not matched_any_target:
            scoring.review_noise += 1

    scoring.introduced_targets_detected = len(detected_regions)
    return scoring


def compute_pr_summary(scorings: list[PRCaseScoring], skipped: int = 0) -> PRSummary:
    """Compute aggregate PR metrics across all cases."""
    total_detected = sum(s.introduced_targets_detected for s in scorings)
    total_targets = sum(s.introduced_targets_total for s in scorings)

    hit_rate = total_detected / total_targets if total_targets > 0 else 0.0

    return PRSummary(
        introduced_target_hit_rate=round(hit_rate, 4),
        total_review_noise=sum(s.review_noise for s in scorings),
        total_capability_noise=sum(s.capability_noise for s in scorings),
        cases_evaluated=len(scorings),
        cases_skipped=skipped,
    )
