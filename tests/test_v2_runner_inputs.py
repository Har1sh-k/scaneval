"""Input identity from the configuration through the plan: ids, profiles, and 2.1 plans.

A standard full input that is its snapshot's own export keeps the 2.0 plan it always had, byte for
byte. Any other input (a renamed one, or a metadata-blinded one bound to a transformed tree) plans
at 2.1 and says which input it is, which export its labels refer to, and which map transformed it.
Which cases are planned, at which level and in which scope, never depends on that identity.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from scaneval import cases
from scaneval.contracts import ContractError, canonical_json, pack_anchor_digest, validate_document


CLOCK = lambda: datetime(2026, 9, 20, 17, 0, tzinfo=timezone.utc)  # noqa: E731
HASH = "sha256:" + "b" * 64
TRANSFORMED = "sha256:" + "c" * 64
MAP_IDENTITY = {"map_id": "widget-metadata", "map_version": "1", "map_sha256": "sha256:" + "d" * 64}
SNAPSHOT = {
    "snapshot_id": "widget-abc", "repository": {"url": "https://example.invalid/acme/widget.git", "name": "acme/widget"},
    "commit": "a" * 40, "reference": "parent of fix commit", "languages": ["python"],
    "workload": "conventional_application", "component_role": "application",
    "license": {"spdx": "MIT", "verified": False, "note": "not checked"},
}
REPRESENTS = ("This case tests shell interpolation of a request parameter under a default deployment, "
              "and adds a Python command-injection target.")


def checked_pack(tmp_path: Path) -> dict:
    """One mechanically checked case with a capability-safe control, both on one export."""
    pack = cases.new_pack("org.example", "inputs", "input identity fixture")
    cases.add_snapshot(pack, SNAPSHOT)
    case = cases.draft_case(
        "widget-shell", snapshot_id="widget-abc", kind="command_injection",
        description="cmd reaches subprocess with shell=True", represents=REPRESENTS,
        workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("fix", origin="fix_without_advisory", kind="fix_commit",
                                 reference="acme/widget@" + "c" * 40)],
        accepted_locations=[{"path": "src/app.py", "start_line": 3, "end_line": 3, "role": "sink"}])
    case["controls"].append({
        "control_id": "C-widget-safe", "snapshot_id": "widget-abc", "type": "capability_safe",
        "description": "The admin helper runs a fixed argument list.",
        "property": "No caller-supplied string reaches a shell at this call site.",
        "allowed_actors_inputs": "Operators on the host.", "assumptions": ["Default deployment."],
        "ruled_out_allegation": "Caller-controlled shell interpolation in the admin helper.",
        "locations": [{"path": "src/app.py", "start_line": 1, "end_line": 1, "role": "operation"}],
        "evidence_ids": ["fix"],
    })
    cases.add_case(pack, case)
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text(
        "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    cases.mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    return pack


def test_a_snapshot_input_named_as_itself_keeps_the_2_0_plan_byte_for_byte(tmp_path):
    pack = checked_pack(tmp_path)

    plain, notes = cases.build_plan(pack, "widget-abc", HASH)
    named, named_notes = cases.build_plan(pack, "widget-abc", HASH, input_id="widget-abc",
                                          input_hash=HASH, profile="standard", blinding=None)

    assert canonical_json(named) == canonical_json(plain) and named_notes == notes
    assert plain["schema_version"] == "2.0" and plain["input_hash"] == HASH
    assert set(plain["provenance"]) == {"namespace", "pack_id", "pack_version", "pack_sha256",
                                        "snapshot_id", "mode", "case_ids"}
    assert all("canonical_id" not in item for item in plain["targets"] + plain["controls"])


def test_a_blinded_input_plans_at_2_1_bound_to_the_transformed_tree(tmp_path):
    pack = checked_pack(tmp_path)
    plain, _ = cases.build_plan(pack, "widget-abc", HASH)

    plan, _ = cases.build_plan(pack, "widget-abc", HASH, input_id="widget-abc.blinded",
                               input_hash=TRANSFORMED, profile="metadata_blinded",
                               blinding={**MAP_IDENTITY, "original_tree_hash": HASH})

    assert validate_document("evaluation-plan", plan) is plan
    assert plan["schema_version"] == "2.1" and plan["input_hash"] == TRANSFORMED
    provenance = plan["provenance"]
    assert provenance["input_id"] == "widget-abc.blinded" and provenance["profile"] == "metadata_blinded"
    assert provenance["source_tree_hash"] == HASH, "the labels refer to the original export"
    assert provenance["blinding"] == MAP_IDENTITY, "only the map identity travels into a plan"
    assert provenance["snapshot_id"] == "widget-abc"
    assert [(t["target_id"], t["canonical_id"]) for t in plan["targets"]] == [("T-widget-shell", "T-widget-shell")]
    assert [(c["control_id"], c["canonical_id"]) for c in plan["controls"]] == [("C-widget-safe", "C-widget-safe")]
    # The identity changes what the plan says about its input, never what it plans.
    assert plan["scope"] == plain["scope"] and plan["review_budgets"] == plain["review_budgets"]
    assert [{k: v for k, v in t.items() if k != "canonical_id"} for t in plan["targets"]] == plain["targets"]
    assert [{k: v for k, v in c.items() if k != "canonical_id"} for c in plan["controls"]] == plain["controls"]


def test_a_renamed_standard_input_plans_at_2_1_without_a_blinding_identity(tmp_path):
    pack = checked_pack(tmp_path)

    plan, _ = cases.build_plan(pack, "widget-abc", HASH, input_id="widget-main")

    assert plan["schema_version"] == "2.1" and plan["input_hash"] == HASH
    assert plan["provenance"]["input_id"] == "widget-main" and plan["provenance"]["profile"] == "standard"
    assert plan["provenance"]["source_tree_hash"] == HASH and "blinding" not in plan["provenance"]


def test_a_blinded_profile_and_a_map_identity_come_together_or_not_at_all(tmp_path):
    pack = checked_pack(tmp_path)

    with pytest.raises(ContractError, match="identity of the map it was transformed with"):
        cases.build_plan(pack, "widget-abc", HASH, profile="metadata_blinded", input_hash=TRANSFORMED)
    with pytest.raises(ContractError, match="identity of the map it was transformed with"):
        cases.build_plan(pack, "widget-abc", HASH, profile="standard", blinding=MAP_IDENTITY)


def test_a_2_1_plan_carries_the_canonical_ids_the_pack_declares(tmp_path):
    """Several target records can be one root cause; the plan carries the pack's grouping."""
    pack = checked_pack(tmp_path)
    pack["schema_version"] = "2.1"
    case = pack["cases"][0]
    case["canonical_target"]["canonical_id"] = "widget-shell-root"
    case["controls"][0]["canonical_id"] = "widget-admin-fixed-argv"
    pack["anchor_sha256"] = pack_anchor_digest(pack)
    validate_document("case-pack", pack)

    plan, _ = cases.build_plan(pack, "widget-abc", HASH, input_id="widget-main")

    assert [t["canonical_id"] for t in plan["targets"]] == ["widget-shell-root"]
    assert [c["canonical_id"] for c in plan["controls"]] == ["widget-admin-fixed-argv"]
    assert cases.target_canonical_id(case) == "widget-shell-root"
    assert cases.control_canonical_id(case["controls"][0]) == "widget-admin-fixed-argv"
