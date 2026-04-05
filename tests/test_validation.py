"""Tests for the SASTbench case validator."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from validate import CASES_DIR, find_cases, find_cases_for_track, validate_case


def load_case(case_dir: Path) -> dict:
    """Load a case.json document."""
    with open(case_dir / "case.json", encoding="utf-8") as f:
        return json.load(f)


def full_track_snapshots_ready() -> bool:
    """Return whether all Full Track snapshot roots are present and checked out."""
    for case_dir in find_cases(CASES_DIR / "full"):
        case = load_case(case_dir)
        root = case_dir / case["files"]["root"]
        if not root.exists():
            return False
        try:
            if (root / ".git").exists() and not any(child.name != ".git" for child in root.iterdir()):
                return False
        except OSError:
            return False
    return True


def test_core_cases_are_valid():
    """Core Track should validate cleanly in a fresh clone."""
    cases = find_cases_for_track("core")
    assert len(cases) > 0, "No cases found"

    all_errors = []
    for case_dir in cases:
        errors = validate_case(case_dir)
        all_errors.extend(errors)

    if all_errors:
        for error in all_errors:
            print(f"  ERROR: {error}")

    assert len(all_errors) == 0, f"{len(all_errors)} validation error(s)"


def test_full_cases_are_valid_when_snapshots_are_ready():
    """Full Track should validate cleanly once repo snapshots are populated."""
    if not full_track_snapshots_ready():
        pytest.skip("Full Track snapshots are not ready; run python scripts/setup_repos.py")

    cases = find_cases(CASES_DIR / "full")
    all_errors = []
    for case_dir in cases:
        errors = validate_case(case_dir)
        all_errors.extend(errors)

    if all_errors:
        for error in all_errors:
            print(f"  ERROR: {error}")

    assert len(all_errors) == 0, f"{len(all_errors)} full-track validation error(s)"


def test_minimum_case_count():
    """V1 requires at least 15 official cases (12 core + 3 full)."""
    cases = find_cases(CASES_DIR)
    assert len(cases) >= 15, f"Only {len(cases)} cases found, need at least 15 for V1"


def test_case_type_distribution():
    """Check we have the right mix of case types per the plan."""
    cases = find_cases(CASES_DIR)
    type_counts = {}

    for case_dir in cases:
        case = load_case(case_dir)
        ct = case["caseType"]
        type_counts[ct] = type_counts.get(ct, 0) + 1

    # Core Track minimums (plan section 8)
    assert type_counts.get("synthetic_vulnerable", 0) >= 6, "Need at least 6 synthetic_vulnerable"
    assert type_counts.get("capability_safe", 0) >= 3, "Need at least 3 capability_safe"
    assert type_counts.get("mixed_intent", 0) >= 3, "Need at least 3 mixed_intent"


def test_full_track_release_bar():
    """V1 release requires at least 3 real_world_disclosed cases (plan section 8)."""
    full_dir = CASES_DIR / "full"
    rw_count = 0
    for case_json in full_dir.rglob("case.json"):
        with open(case_json, encoding="utf-8") as f:
            case = json.load(f)
        if case.get("caseType") == "real_world_disclosed":
            rw_count += 1

    assert rw_count >= 3, (
        f"Full Track has {rw_count}/3 real_world_disclosed cases -- below v1.0.0 release bar"
    )


def test_language_distribution():
    """Check all three languages are represented."""
    cases = find_cases(CASES_DIR)
    languages = set()

    for case_dir in cases:
        case = load_case(case_dir)
        languages.add(case["language"])

    assert "python" in languages
    assert "typescript" in languages
    assert "rust" in languages


def test_owasp_standards_when_present():
    """Cases with standards field must have valid ASI IDs."""
    VALID_ASI_IDS = {f"ASI{i:02d}" for i in range(1, 11)}
    cases = find_cases(CASES_DIR)

    for case_dir in cases:
        case = load_case(case_dir)
        standards = case.get("standards", {})
        owasp = standards.get("owaspAgenticTop10")
        if owasp:
            assert owasp["primary"] in VALID_ASI_IDS, \
                f"{case['id']}: invalid primary ASI ID {owasp['primary']}"
            for s in owasp.get("secondary", []):
                assert s in VALID_ASI_IDS, \
                    f"{case['id']}: invalid secondary ASI ID {s}"
            assert owasp["primary"] not in owasp.get("secondary", []), \
                f"{case['id']}: primary ASI ID should not repeat in secondary"


def test_all_cases_have_owasp_mapping():
    """Every case should have OWASP Agentic Top 10 mapping."""

    cases = find_cases(CASES_DIR)
    unmapped = []
    for case_dir in cases:
        case = load_case(case_dir)
        standards = case.get("standards", {})
        if not standards.get("owaspAgenticTop10"):
            unmapped.append(case["id"])

    assert not unmapped, f"Cases without OWASP mapping: {unmapped}"


def test_disallowed_scan_root_directories_are_rejected(tmp_path):
    """Case scan roots should not contain vendored or tool-generated junk."""
    case_dir = tmp_path / "SB-TMP-SV-001"
    project_dir = case_dir / "project"
    project_dir.mkdir(parents=True)
    (case_dir / "context.md").write_text("Temporary test case.\n", encoding="utf-8")
    (project_dir / "tool.py").write_text("print('ok')\n", encoding="utf-8")
    (project_dir / "node_modules").mkdir()
    (project_dir / "node_modules" / "junk.js").write_text("eval('bad')\n", encoding="utf-8")

    case = {
        "schemaVersion": "1.0.0",
        "id": "SB-TMP-SV-001",
        "track": "core",
        "caseType": "synthetic_vulnerable",
        "language": "python",
        "canonicalKind": "command_injection",
        "files": {"root": "project/"},
        "regions": [
            {
                "id": "R1",
                "path": "tool.py",
                "startLine": 1,
                "endLine": 1,
                "label": "vulnerable",
                "capability": "code_execution",
                "acceptedKinds": ["command_injection"],
            }
        ],
        "expectedOutcome": {
            "mustDetectRegionIds": ["R1"],
            "mustNotFlagRegionIds": [],
        },
        "standards": {
            "owaspAgenticTop10": {"primary": "ASI05"},
        },
    }
    (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")

    errors = validate_case(case_dir)

    assert any("Disallowed directory in scan root: node_modules" in str(err) for err in errors)


def test_pr_simulation_vendored_base_validates(tmp_path):
    """vendored_base prSimulation with existing baseRoot should validate."""
    case_dir = tmp_path / "SB-TMP-SV-002"
    project_dir = case_dir / "project"
    project_dir.mkdir(parents=True)
    base_dir = case_dir / "pr" / "base"
    base_dir.mkdir(parents=True)
    (case_dir / "context.md").write_text("test\n", encoding="utf-8")
    (project_dir / "tool.py").write_text("print('vuln')\n", encoding="utf-8")
    (base_dir / "tool.py").write_text("print('safe')\n", encoding="utf-8")

    case = {
        "schemaVersion": "1.0.0",
        "id": "SB-TMP-SV-002",
        "track": "core",
        "caseType": "synthetic_vulnerable",
        "language": "python",
        "canonicalKind": "command_injection",
        "files": {"root": "project/"},
        "regions": [
            {
                "id": "R1", "path": "tool.py", "startLine": 1, "endLine": 1,
                "label": "vulnerable", "acceptedKinds": ["command_injection"],
            }
        ],
        "expectedOutcome": {"mustDetectRegionIds": ["R1"], "mustNotFlagRegionIds": []},
        "prSimulation": {"mode": "vendored_base", "baseRoot": "pr/base"},
        "standards": {"owaspAgenticTop10": {"primary": "ASI05"}},
    }
    (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")

    errors = validate_case(case_dir)
    assert len(errors) == 0, f"Unexpected errors: {errors}"


def test_pr_simulation_vendored_base_missing_dir(tmp_path):
    """vendored_base with missing baseRoot directory should fail."""
    case_dir = tmp_path / "SB-TMP-SV-003"
    project_dir = case_dir / "project"
    project_dir.mkdir(parents=True)
    (case_dir / "context.md").write_text("test\n", encoding="utf-8")
    (project_dir / "tool.py").write_text("print('vuln')\n", encoding="utf-8")

    case = {
        "schemaVersion": "1.0.0",
        "id": "SB-TMP-SV-003",
        "track": "core",
        "caseType": "synthetic_vulnerable",
        "language": "python",
        "canonicalKind": "command_injection",
        "files": {"root": "project/"},
        "regions": [
            {
                "id": "R1", "path": "tool.py", "startLine": 1, "endLine": 1,
                "label": "vulnerable", "acceptedKinds": ["command_injection"],
            }
        ],
        "expectedOutcome": {"mustDetectRegionIds": ["R1"], "mustNotFlagRegionIds": []},
        "prSimulation": {"mode": "vendored_base", "baseRoot": "pr/base"},
        "standards": {"owaspAgenticTop10": {"primary": "ASI05"}},
    }
    (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")

    errors = validate_case(case_dir)
    assert any("does not exist" in str(e) for e in errors)


def test_pr_simulation_git_commit_pair_requires_real_world(tmp_path):
    """git_commit_pair mode on non-real_world_disclosed case should fail."""
    case_dir = tmp_path / "SB-TMP-SV-004"
    project_dir = case_dir / "project"
    project_dir.mkdir(parents=True)
    (case_dir / "context.md").write_text("test\n", encoding="utf-8")
    (project_dir / "tool.py").write_text("print('vuln')\n", encoding="utf-8")

    case = {
        "schemaVersion": "1.0.0",
        "id": "SB-TMP-SV-004",
        "track": "core",
        "caseType": "synthetic_vulnerable",
        "language": "python",
        "canonicalKind": "command_injection",
        "files": {"root": "project/"},
        "regions": [
            {
                "id": "R1", "path": "tool.py", "startLine": 1, "endLine": 1,
                "label": "vulnerable", "acceptedKinds": ["command_injection"],
            }
        ],
        "expectedOutcome": {"mustDetectRegionIds": ["R1"], "mustNotFlagRegionIds": []},
        "prSimulation": {"mode": "git_commit_pair", "baseCommit": "abc123"},
        "standards": {"owaspAgenticTop10": {"primary": "ASI05"}},
    }
    (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")

    errors = validate_case(case_dir)
    assert any("real_world_disclosed" in str(e) for e in errors)


def test_pr_simulation_invalid_mode(tmp_path):
    """Invalid prSimulation mode should fail validation."""
    case_dir = tmp_path / "SB-TMP-SV-005"
    project_dir = case_dir / "project"
    project_dir.mkdir(parents=True)
    (case_dir / "context.md").write_text("test\n", encoding="utf-8")
    (project_dir / "tool.py").write_text("print('vuln')\n", encoding="utf-8")

    case = {
        "schemaVersion": "1.0.0",
        "id": "SB-TMP-SV-005",
        "track": "core",
        "caseType": "synthetic_vulnerable",
        "language": "python",
        "canonicalKind": "command_injection",
        "files": {"root": "project/"},
        "regions": [
            {
                "id": "R1", "path": "tool.py", "startLine": 1, "endLine": 1,
                "label": "vulnerable", "acceptedKinds": ["command_injection"],
            }
        ],
        "expectedOutcome": {"mustDetectRegionIds": ["R1"], "mustNotFlagRegionIds": []},
        "prSimulation": {"mode": "invalid_mode"},
        "standards": {"owaspAgenticTop10": {"primary": "ASI05"}},
    }
    (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")

    errors = validate_case(case_dir)
    assert any("mode" in str(e) for e in errors)


def test_pr_seeded_cases_validate():
    """All seeded PR cases should pass validation."""
    pr_cases = []
    for case_json in CASES_DIR.rglob("case.json"):
        with open(case_json, encoding="utf-8") as f:
            case = json.load(f)
        if "prSimulation" in case:
            pr_cases.append(case_json.parent)

    assert len(pr_cases) >= 2, f"Expected at least 2 PR-seeded cases, found {len(pr_cases)}"

    all_errors = []
    for case_dir in pr_cases:
        errors = validate_case(case_dir)
        all_errors.extend(errors)

    assert len(all_errors) == 0, f"PR case validation errors: {all_errors}"


def _make_base_case(tmp_path, case_id="SB-TMP-SV-099", extra=None):
    """Helper: create a minimal valid case dir and return (case_dir, case_dict)."""
    case_dir = tmp_path / case_id
    project_dir = case_dir / "project"
    project_dir.mkdir(parents=True)
    (case_dir / "context.md").write_text("test\n", encoding="utf-8")
    (project_dir / "tool.py").write_text("print('vuln')\n", encoding="utf-8")

    case = {
        "schemaVersion": "1.0.0",
        "id": case_id,
        "track": "core",
        "caseType": "synthetic_vulnerable",
        "language": "python",
        "canonicalKind": "command_injection",
        "files": {"root": "project/"},
        "regions": [
            {
                "id": "R1", "path": "tool.py", "startLine": 1, "endLine": 1,
                "label": "vulnerable", "acceptedKinds": ["command_injection"],
            }
        ],
        "expectedOutcome": {"mustDetectRegionIds": ["R1"], "mustNotFlagRegionIds": []},
        "standards": {"owaspAgenticTop10": {"primary": "ASI05"}},
    }
    if extra:
        case.update(extra)
    (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
    return case_dir, case


# --- fixValidation schema regression tests ---

def test_schema_has_fix_validation_property():
    """Top-level properties must include fixValidation referencing $defs."""
    schema_path = Path(__file__).resolve().parent.parent / "schema" / "case.schema.json"
    with open(schema_path) as f:
        schema = json.load(f)

    props = schema["properties"]
    assert "fixValidation" in props, "fixValidation missing from top-level properties"
    assert props["fixValidation"].get("$ref") == "#/$defs/fixValidation", \
        "fixValidation should reference #/$defs/fixValidation"


def test_fix_validation_string_does_not_crash(tmp_path):
    """fixValidation as a string must produce errors, not crash."""
    case_dir, _ = _make_base_case(tmp_path, extra={"fixValidation": "oops"})
    errors = validate_case(case_dir)
    assert any("fixValidation must be an object" in str(e) for e in errors)


def test_fix_validation_anchor_entry_not_object(tmp_path):
    """Non-object anchor entries must produce errors, not crash."""
    case_dir, _ = _make_base_case(tmp_path, extra={
        "fixValidation": {
            "mode": "mitigation_anchor_present",
            "anchors": ["not_an_object"],
        }
    })
    errors = validate_case(case_dir)
    assert any("must be an object" in str(e) for e in errors)


def test_fix_validation_valid_mitigation_anchor(tmp_path):
    """Valid mitigation_anchor_present structure should not produce fixValidation errors."""
    case_dir, _ = _make_base_case(tmp_path, extra={
        "fixValidation": {
            "mode": "mitigation_anchor_present",
            "anchors": [
                {"path": "src/server.ts", "mustContainAll": ["cors({", "localhost"]}
            ],
        }
    })
    errors = validate_case(case_dir)
    fv_errors = [e for e in errors if "fixValidation" in str(e)]
    assert len(fv_errors) == 0, f"Unexpected fixValidation errors: {fv_errors}"


if __name__ == "__main__":
    test_core_cases_are_valid()
    test_minimum_case_count()
    test_case_type_distribution()
    test_full_track_release_bar()
    test_language_distribution()
    test_owasp_standards_when_present()
    test_all_cases_have_owasp_mapping()
    test_full_cases_are_valid_when_snapshots_are_ready()
    print("All tests passed.")
