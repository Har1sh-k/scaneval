"""Case packs: drafts stay drafts, mechanical checks stop at L1, approval is explicit, plans degrade."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from sastbench.cases import (
    accepted_paths_for_targets,
    add_case,
    add_snapshot,
    admit_case,
    approve_case,
    build_plan,
    draft_case,
    draft_case_from_legacy,
    evidence,
    load_pack,
    mechanical_checks,
    new_pack,
    pack_summary,
    save_pack,
)
from sastbench.contracts import ContractError, validate_document


CLOCK = lambda: datetime(2026, 9, 20, 17, 0, tzinfo=timezone.utc)  # noqa: E731
HASH = "sha256:" + "b" * 64
SNAPSHOT = {
    "snapshot_id": "widget-abc", "repository": {"url": "https://example.invalid/acme/widget.git", "name": "acme/widget"},
    "commit": "a" * 40, "reference": "parent of fix commit", "languages": ["python"],
    "workload": "conventional_application", "component_role": "application",
    "license": {"spdx": "MIT", "verified": False, "note": "not checked"},
}
REPRESENTS = "This case tests shell interpolation of a request parameter under a default deployment, and adds a Python command-injection target."


def make_pack() -> dict:
    pack = new_pack("org.example", "pilot", "test pack")
    add_snapshot(pack, SNAPSHOT)
    add_case(pack, draft_case(
        "widget-shell", snapshot_id="widget-abc", kind="command_injection", description="cmd reaches subprocess with shell=True",
        represents=REPRESENTS, workload="conventional_application", component_role="application",
        aliases=["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"],
        evidence=[evidence("fix", origin="fix_without_advisory", kind="fix_commit", reference="acme/widget@" + "c" * 40)],
        accepted_locations=[{"path": "src/app.py", "start_line": 3, "end_line": 3, "role": "sink"}],
    ))
    return pack


def export(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text("import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    return source


def test_new_pack_and_draft_case_are_valid_and_explicitly_unreviewed(tmp_path):
    pack = make_pack()
    case = pack["cases"][0]
    assert case["validation"] == {"level": None, "review_state": "draft", "checks": [], "reviews": []}
    assert case["disposition"]["value"] == "needs_evidence"
    assert case["coverage_signature"]["guard_failure"] == {"state": "not_reviewed"}
    assert case["target"]["target_id"] == "T-widget-shell"
    path = tmp_path / "pack.json"
    save_pack(path, pack)
    assert load_pack(path) == pack
    assert pack_summary(pack)["review_states"] == {"draft": 1, "mechanically_checked": 0, "human_approved": 0}
    with pytest.raises(ContractError, match="already exists"):
        add_snapshot(pack, SNAPSHOT)
    with pytest.raises(ContractError, match="already exists"):
        add_case(pack, pack["cases"][0])


def test_contract_rejects_inconsistent_review_states_and_dangling_references():
    pack = make_pack()
    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"]["level"] = "L3"
    with pytest.raises(ContractError, match="requires human_approved"):
        validate_document("case-pack", broken)
    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["validation"].update({"review_state": "human_approved", "level": "L3"})
    with pytest.raises(ContractError, match="approving review"):
        validate_document("case-pack", broken)
    broken = json.loads(json.dumps(pack))
    broken["cases"][0]["target"]["snapshot_id"] = "nope"
    with pytest.raises(ContractError, match="not declared"):
        validate_document("case-pack", broken)
    broken = json.loads(json.dumps(pack))
    broken["admissions"].append({"case_id": "ghost", "decision": "admitted", "by": "x", "at": "t", "reason": "r"})
    with pytest.raises(ContractError, match="unknown case"):
        validate_document("case-pack", broken)


def test_mechanical_checks_reach_l1_only_and_record_failures(tmp_path):
    pack = make_pack()
    source = export(tmp_path)
    outcomes = mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    case = pack["cases"][0]
    assert outcomes[0]["passed"] is True
    assert case["validation"]["review_state"] == "mechanically_checked" and case["validation"]["level"] == "L1"
    assert {c["check"]: c["result"] for c in case["validation"]["checks"]}["locations_exist_in_snapshot"] == "pass"
    assert pack["snapshots"][0]["tree_hash"] == HASH
    with pytest.raises(ContractError, match="tree hash"):
        mechanical_checks(pack, "widget-abc", source, "sha256:" + "c" * 64, clock=CLOCK)

    case["target"]["accepted_locations"][0]["end_line"] = 99
    outcomes = mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    assert outcomes[0]["passed"] is False
    assert case["validation"]["review_state"] == "draft" and case["validation"]["level"] is None
    assert any(c["check"] == "line_ranges_within_files" and c["result"] == "fail" for c in case["validation"]["checks"])


def test_plan_degrades_to_draft_and_needs_explicit_approval_for_reviewed(tmp_path):
    pack = make_pack()
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["targets"] == [] and any("not planned" in note for note in notes)
    mechanical_checks(pack, "widget-abc", export(tmp_path), HASH, clock=CLOCK)
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"][0]["validation_level"] == "L1"
    assert plan["review_budgets"] == [5, 10, 20, 50] and plan["provenance"]["case_ids"] == ["widget-shell"]
    assert plan["input_hash"] == HASH
    assert accepted_paths_for_targets(pack, {"T-widget-shell"}) == {"T-widget-shell": {"src/app.py"}}

    with pytest.raises(ContractError, match="independent_reviewer"):
        approve_case(pack, "widget-shell", reviewer="curator", role="curator", level="L3", note="", clock=CLOCK)
    approve_case(pack, "widget-shell", reviewer="curator", role="curator", level="L2", note="structure reviewed", clock=CLOCK)
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "draft" and plan["targets"][0]["validation_level"] == "L2"
    approve_case(pack, "widget-shell", reviewer="second", role="independent_reviewer", level="L3", note="label established", clock=CLOCK)
    plan, _ = build_plan(pack, "widget-abc", HASH)
    assert plan["scope"] == "reviewed" and plan["targets"][0]["validation_level"] == "L3"
    assert pack["cases"][0]["validation"]["reviews"][-1]["reviewer"] == "second"
    admit_case(pack, "widget-shell", decision="admitted", by="second", reason="pilot", clock=CLOCK)
    assert pack["admissions"][0]["decision"] == "admitted"

    pack["cases"][0]["disposition"] = {"value": "exclude", "reason": "duplicate target"}
    plan, notes = build_plan(pack, "widget-abc", HASH)
    assert plan["targets"] == [] and plan["scope"] == "draft" and any("excluded" in note for note in notes)


def test_approval_requires_prior_mechanical_checks():
    pack = make_pack()
    with pytest.raises(ContractError, match="mechanical checks"):
        approve_case(pack, "widget-shell", reviewer="r", role="independent_reviewer", level="L3", note="", clock=CLOCK)


def test_legacy_migration_keeps_regions_as_draft_evidence(tmp_path):
    legacy = {
        "id": "SB-GO-RG-001", "caseType": "real_world_generic", "canonicalKind": "auth_bypass", "title": "skip regex on full URI",
        "description": "regex matched path plus query", "regions": [{"id": "R1", "path": "oauthproxy.go", "startLine": 582, "endLine": 590,
                                                                     "label": "vulnerable", "capability": "authentication"}],
        "realWorld": {"repo": "oauth2-proxy/oauth2-proxy", "vulnerableCommit": "f" * 40, "fixCommit": "9" * 40,
                      "ghsa": "GHSA-7rh7-c77v-6434", "cve": "CVE-2025-54576",
                      "disclosure": {"ghsaPublished": "2025-07-30", "fixCommitDate": "2025-07-29"}},
    }
    case = draft_case_from_legacy(legacy, case_id="oauth2-proxy-cve-2025-54576", snapshot_id="widget-abc",
                                  legacy_path="cases/full/real_world_generic/SB-GO-RG-001/case.json",
                                  workload="conventional_application", component_role="infrastructure", represents=REPRESENTS)
    pack = new_pack("sastbench.public", "pilot", "x")
    add_snapshot(pack, SNAPSHOT)
    add_case(pack, case)
    assert case["validation"]["review_state"] == "draft" and case["validation"]["level"] is None
    assert case["target"]["accepted_locations"] == [{"path": "oauthproxy.go", "start_line": 582, "end_line": 590, "role": "other",
                                                     "note": "legacy region R1 label=vulnerable capability=authentication"}]
    assert case["canonical_target"]["aliases"] == ["CVE-2025-54576", "GHSA-7rh7-c77v-6434"]
    assert {e["kind"] for e in case["evidence"]} == {"other", "fix_commit", "ghsa_advisory", "cve_record"}
    assert case["evidence"][0]["origin"] == "legacy_case_record"
    assert case["disclosure"]["ghsa_published"] == "2025-07-30" and case["disclosure"]["earliest_public_artifact"] is None
