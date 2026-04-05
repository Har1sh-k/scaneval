"""SASTbench case validator.

Validates all case.json files against the case schema and checks
that referenced files and line ranges exist.
"""

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema" / "case.schema.json"
CASES_DIR = REPO_ROOT / "cases"

VALID_SCHEMA_VERSIONS = {"1.0.0"}
VALID_TRACKS = {"core", "full"}
VALID_CASE_TYPES = {
    "synthetic_vulnerable",
    "capability_safe",
    "mixed_intent",
    "real_world_disclosed",
}
VALID_LANGUAGES = {"python", "typescript", "rust", "swift"}
VALID_KINDS = {"command_injection", "path_traversal", "ssrf", "auth_bypass", "authz_bypass", "sql_injection"}
VALID_LABELS = {"vulnerable", "capability_safe"}
VALID_CAPABILITIES = {"code_execution", "filesystem", "network", "authentication", "authorization", "data_store"}
VALID_GUARDS = {"allowlist", "workspace_root", "host_allowlist", "scheme_allowlist", "caller_verification", "secret_validation", "scope_binding", "role_check", "parameterized_query"}
VALID_ASI_IDS = {f"ASI{i:02d}" for i in range(1, 11)}
VALID_PR_MODES = {"vendored_base", "git_commit_pair"}
DISALLOWED_SCAN_ROOT_DIRS = {
    ".claude",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
}


class ValidationError:
    def __init__(self, case_id: str, message: str):
        self.case_id = case_id
        self.message = message

    def __str__(self) -> str:
        return f"[{self.case_id}] {self.message}"


def find_disallowed_scan_root_dirs(root_path: Path) -> list[Path]:
    """Return disallowed directories found under a case scan root."""
    disallowed: list[Path] = []
    for current_root, dirnames, _filenames in os.walk(root_path, topdown=True):
        banned = [name for name in dirnames if name in DISALLOWED_SCAN_ROOT_DIRS]
        for name in banned:
            disallowed.append((Path(current_root) / name).relative_to(root_path))
        dirnames[:] = [name for name in dirnames if name not in DISALLOWED_SCAN_ROOT_DIRS]
    return sorted(disallowed)


def has_checked_out_files(root_path: Path) -> bool:
    """Return whether a git snapshot contains files beyond the .git dir."""
    try:
        return any(child.name != ".git" for child in root_path.iterdir())
    except OSError:
        return False


def validate_case(case_dir: Path) -> list[ValidationError]:
    """Validate a single case directory."""
    errors: list[ValidationError] = []
    case_file = case_dir / "case.json"
    case_id = case_dir.name

    if not case_file.exists():
        errors.append(ValidationError(case_id, "Missing case.json"))
        return errors

    try:
        with open(case_file) as f:
            case = json.load(f)
    except json.JSONDecodeError as e:
        errors.append(ValidationError(case_id, f"Invalid JSON: {e}"))
        return errors

    # Required fields
    for field in [
        "schemaVersion", "id", "track", "caseType", "language",
        "canonicalKind", "files", "regions", "expectedOutcome",
    ]:
        if field not in case:
            errors.append(ValidationError(case_id, f"Missing required field: {field}"))

    if errors:
        return errors

    # Enum validations
    if case["schemaVersion"] not in VALID_SCHEMA_VERSIONS:
        errors.append(ValidationError(case_id, f"Invalid schemaVersion: {case['schemaVersion']}"))
    if case["track"] not in VALID_TRACKS:
        errors.append(ValidationError(case_id, f"Invalid track: {case['track']}"))
    if case["caseType"] not in VALID_CASE_TYPES:
        errors.append(ValidationError(case_id, f"Invalid caseType: {case['caseType']}"))
    if case["language"] not in VALID_LANGUAGES:
        errors.append(ValidationError(case_id, f"Invalid language: {case['language']}"))
    if case["canonicalKind"] not in VALID_KINDS:
        errors.append(ValidationError(case_id, f"Invalid canonicalKind: {case['canonicalKind']}"))

    # Files root must exist
    root = case["files"].get("root", "")
    root_path = case_dir / root
    scan_root_ready = False
    if not root_path.exists():
        errors.append(ValidationError(case_id, f"Files root does not exist: {root}"))
    elif (root_path / ".git").exists() and not has_checked_out_files(root_path):
        errors.append(
            ValidationError(
                case_id,
                f"Files root checkout is incomplete: {root} (rerun python scripts/setup_repos.py)",
            )
        )
    else:
        scan_root_ready = True
        for disallowed in find_disallowed_scan_root_dirs(root_path):
            errors.append(
                ValidationError(
                    case_id,
                    f"Disallowed directory in scan root: {disallowed.as_posix()}",
                )
            )

    # Validate regions
    region_ids = set()
    for region in case["regions"]:
        rid = region.get("id", "<missing>")

        if rid in region_ids:
            errors.append(ValidationError(case_id, f"Duplicate region ID: {rid}"))
        region_ids.add(rid)

        if region.get("label") not in VALID_LABELS:
            errors.append(ValidationError(case_id, f"Region {rid}: invalid label: {region.get('label')}"))

        if "capability" in region and region["capability"] not in VALID_CAPABILITIES:
            errors.append(ValidationError(case_id, f"Region {rid}: invalid capability: {region['capability']}"))

        if "requiredGuards" in region:
            for guard in region["requiredGuards"]:
                if guard not in VALID_GUARDS:
                    errors.append(ValidationError(case_id, f"Region {rid}: invalid guard: {guard}"))

        if "acceptedKinds" in region:
            for kind in region["acceptedKinds"]:
                if kind not in VALID_KINDS:
                    errors.append(ValidationError(case_id, f"Region {rid}: invalid accepted kind: {kind}"))

        # Enforce required fields per label (plan section 9 / section 10)
        label = region.get("label")
        if label == "capability_safe":
            if "requiredGuards" not in region or not region["requiredGuards"]:
                errors.append(ValidationError(case_id, f"Region {rid}: capability_safe region must have requiredGuards"))
            if "capability" not in region:
                errors.append(ValidationError(case_id, f"Region {rid}: capability_safe region must have capability"))
        if label == "vulnerable":
            if "acceptedKinds" not in region or not region["acceptedKinds"]:
                errors.append(ValidationError(case_id, f"Region {rid}: vulnerable region must have acceptedKinds"))

        # Check file exists and line range is valid
        # Region paths are relative to scan_root (files.root), not case_dir
        if scan_root_ready:
            region_path = root_path / region.get("path", "")
            if not region_path.exists():
                errors.append(ValidationError(case_id, f"Region {rid}: file does not exist: {region.get('path')}"))
            else:
                line_count = len(region_path.read_text(encoding="utf-8").splitlines())
                start = region.get("startLine", 0)
                end = region.get("endLine", 0)
                if start < 1 or end < 1:
                    errors.append(ValidationError(case_id, f"Region {rid}: line numbers must be >= 1"))
                elif start > end:
                    errors.append(ValidationError(case_id, f"Region {rid}: startLine ({start}) > endLine ({end})"))
                elif end > line_count:
                    errors.append(ValidationError(case_id, f"Region {rid}: endLine ({end}) exceeds file length ({line_count})"))

    # Validate expectedOutcome references
    outcome = case["expectedOutcome"]
    for rid in outcome.get("mustDetectRegionIds", []):
        if rid not in region_ids:
            errors.append(ValidationError(case_id, f"mustDetectRegionIds references unknown region: {rid}"))
    for rid in outcome.get("mustNotFlagRegionIds", []):
        if rid not in region_ids:
            errors.append(ValidationError(case_id, f"mustNotFlagRegionIds references unknown region: {rid}"))

    # Case type consistency checks
    case_type = case["caseType"]
    if case_type == "capability_safe":
        if outcome.get("mustDetectRegionIds"):
            errors.append(ValidationError(case_id, "capability_safe case should have empty mustDetectRegionIds"))
        safe_regions = [r for r in case["regions"] if r["label"] == "capability_safe"]
        if not safe_regions:
            errors.append(ValidationError(case_id, "capability_safe case must have at least one capability_safe region"))

    if case_type == "mixed_intent":
        safe_regions = [r for r in case["regions"] if r["label"] == "capability_safe"]
        vuln_regions = [r for r in case["regions"] if r["label"] == "vulnerable"]
        if not safe_regions:
            errors.append(ValidationError(case_id, "mixed_intent case must have at least one capability_safe region"))
        if not vuln_regions:
            errors.append(ValidationError(case_id, "mixed_intent case must have at least one vulnerable region"))

    if case_type == "synthetic_vulnerable":
        vuln_regions = [r for r in case["regions"] if r["label"] == "vulnerable"]
        if not vuln_regions:
            errors.append(ValidationError(case_id, "synthetic_vulnerable case must have at least one vulnerable region"))

    if case_type == "real_world_disclosed" and "realWorld" not in case:
        errors.append(ValidationError(case_id, "real_world_disclosed case must have realWorld metadata"))

    # Validate standards field (optional)
    if "standards" in case:
        standards = case["standards"]
        if not isinstance(standards, dict):
            errors.append(ValidationError(case_id, "standards must be an object"))
        elif "owaspAgenticTop10" in standards:
            owasp = standards["owaspAgenticTop10"]
            if not isinstance(owasp, dict):
                errors.append(ValidationError(case_id, "standards.owaspAgenticTop10 must be an object"))
            else:
                primary = owasp.get("primary")
                if not primary:
                    errors.append(ValidationError(case_id, "standards.owaspAgenticTop10 must have a primary ASI ID"))
                elif primary not in VALID_ASI_IDS:
                    errors.append(ValidationError(case_id, f"Invalid primary ASI ID: {primary}"))
                for asi_id in owasp.get("secondary", []):
                    if asi_id not in VALID_ASI_IDS:
                        errors.append(ValidationError(case_id, f"Invalid secondary ASI ID: {asi_id}"))
                if primary and primary in owasp.get("secondary", []):
                    errors.append(ValidationError(case_id, f"Primary ASI ID {primary} should not repeat in secondary"))

    # Validate prSimulation (optional)
    if "prSimulation" in case:
        pr_sim = case["prSimulation"]
        if not isinstance(pr_sim, dict):
            errors.append(ValidationError(case_id, "prSimulation must be an object"))
        else:
            pr_mode = pr_sim.get("mode")
            if pr_mode not in VALID_PR_MODES:
                errors.append(ValidationError(case_id, f"prSimulation.mode must be one of {sorted(VALID_PR_MODES)}"))

            if pr_mode == "vendored_base":
                base_root = pr_sim.get("baseRoot")
                if not base_root:
                    errors.append(ValidationError(case_id, "vendored_base mode requires prSimulation.baseRoot"))
                else:
                    base_path = case_dir / base_root
                    if not base_path.exists():
                        errors.append(ValidationError(case_id, f"prSimulation.baseRoot does not exist: {base_root}"))
                    elif not base_path.is_dir():
                        errors.append(ValidationError(case_id, f"prSimulation.baseRoot is not a directory: {base_root}"))

            elif pr_mode == "git_commit_pair":
                if not pr_sim.get("baseCommit"):
                    errors.append(ValidationError(case_id, "git_commit_pair mode requires prSimulation.baseCommit"))
                if case_type != "real_world_disclosed":
                    errors.append(ValidationError(case_id, "git_commit_pair mode is only valid for real_world_disclosed cases"))

    # Validate fixValidation (optional)
    if "fixValidation" in case:
        fv = case["fixValidation"]
        if not isinstance(fv, dict):
            errors.append(ValidationError(case_id, "fixValidation must be an object"))
        else:
            fv_mode = fv.get("mode")
            if fv_mode not in ("slice_absent", "mitigation_anchor_present"):
                errors.append(ValidationError(case_id, "fixValidation.mode must be slice_absent or mitigation_anchor_present"))
            if fv_mode == "mitigation_anchor_present":
                anchors = fv.get("anchors")
                if not anchors or not isinstance(anchors, list):
                    errors.append(ValidationError(case_id, "mitigation_anchor_present mode requires fixValidation.anchors"))
                else:
                    for i, anchor in enumerate(anchors):
                        if not isinstance(anchor, dict):
                            errors.append(ValidationError(case_id, f"fixValidation.anchors[{i}] must be an object"))
                            continue
                        if not anchor.get("path"):
                            errors.append(ValidationError(case_id, f"fixValidation.anchors[{i}] missing path"))
                        if not anchor.get("mustContainAll") or not isinstance(anchor.get("mustContainAll"), list):
                            errors.append(ValidationError(case_id, f"fixValidation.anchors[{i}] missing or empty mustContainAll"))

    # Context file should exist
    if not (case_dir / "context.md").exists():
        errors.append(ValidationError(case_id, "Missing context.md"))

    return errors


def find_cases(base_dir: Path) -> list[Path]:
    """Find all case directories under the given base."""
    cases = []
    for case_json in sorted(base_dir.rglob("case.json")):
        cases.append(case_json.parent)
    return cases


def find_cases_for_track(track: str) -> list[Path]:
    """Find case directories for the requested benchmark track."""
    if track == "core":
        search_dirs = [CASES_DIR / "core"]
    elif track == "full":
        search_dirs = [CASES_DIR / "core", CASES_DIR / "full"]
    else:
        raise ValueError(f"Unknown track: {track}")

    cases: list[Path] = []
    for search_dir in search_dirs:
        cases.extend(find_cases(search_dir))
    return cases


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate SASTbench case definitions")
    parser.add_argument(
        "--track",
        choices=["core", "full"],
        default="core",
        help="Validate Core Track only (default) or Full Track (core + full cases)",
    )
    args = parser.parse_args()

    cases = find_cases_for_track(args.track)
    if not cases:
        print("No cases found.")
        return 1

    all_errors: list[ValidationError] = []
    for case_dir in cases:
        errors = validate_case(case_dir)
        all_errors.extend(errors)

    print(f"Validated {len(cases)} cases ({args.track} track).")

    if all_errors:
        print(f"\n{len(all_errors)} error(s) found:\n")
        for error in all_errors:
            print(f"  ERROR: {error}")
        if args.track == "full":
            print("\nHint: run `python scripts/setup_repos.py` to populate Full Track snapshots.")
        return 1

    print("All cases valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
