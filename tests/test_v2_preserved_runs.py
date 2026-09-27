"""Committed run bundles are immutable evidence and must stay self-consistent.

Every bundle under ``corpus/pilot/runs`` records what was actually executed. Its
documents are bound to each other by content hash, so editing one, to match a later
project name or for any other reason, silently invalidates the binding and turns a real
record into a forged one. These tests re-verify those bindings on the files as
committed. The bundles produced under the project's former name were removed rather
than rewritten, and replaced by runs this build actually produced.

They assert nothing about detection. Every preserved decision is unresolved.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scaneval.contracts import canonical_sha256, load_document
from scaneval.scoring import score


RUNS = Path(__file__).resolve().parents[1] / "corpus" / "pilot" / "runs"


def bundles() -> list[Path]:
    return sorted(p.parent for p in RUNS.glob("*/invocations/*/result.json"))


def bundle_ids() -> list[str]:
    return [f"{p.parents[2].name}/{p.name}" for p in bundles()]


pytestmark = pytest.mark.skipif(not bundles(), reason="no preserved run bundles in this checkout")


@pytest.mark.parametrize("bundle", bundles(), ids=bundle_ids())
def test_every_preserved_document_still_hashes_to_what_references_it(bundle: Path):
    result = load_document(bundle / "result.json", "scan-result")
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    decisions = load_document(bundle / "evaluator" / "decisions.json", "review-decisions")
    record = load_document(bundle / "evaluator" / "review-record.json", "review-record")
    evaluation = json.loads((bundle / "evaluation.json").read_text(encoding="utf-8"))

    assert decisions["result_sha256"] == canonical_sha256(result)
    assert evaluation["result_sha256"] == canonical_sha256(result)
    assert evaluation["plan_sha256"] == canonical_sha256(plan)
    assert evaluation["decisions_sha256"] == canonical_sha256(decisions)
    assert record["plan_sha256"] == canonical_sha256(plan)
    assert record["decisions_sha256"] == canonical_sha256(decisions)
    assert decisions["run_id"] == result["run_id"] == record["run_id"]
    assert plan["input_hash"] == result["input_hash"] == decisions["input_hash"]


@pytest.mark.parametrize("bundle", bundles(), ids=bundle_ids())
def test_every_preserved_bundle_still_replays_byte_for_byte(bundle: Path):
    result = load_document(bundle / "result.json", "scan-result")
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    decisions = load_document(bundle / "evaluator" / "decisions.json", "review-decisions")
    stored = json.loads((bundle / "evaluation.json").read_text(encoding="utf-8"))

    assert score(plan, result, decisions) == stored


@pytest.mark.parametrize("bundle", bundles(), ids=bundle_ids())
def test_no_preserved_decision_was_ever_approved(bundle: Path):
    decisions = load_document(bundle / "evaluator" / "decisions.json", "review-decisions")
    record = load_document(bundle / "evaluator" / "review-record.json", "review-record")
    evaluation = json.loads((bundle / "evaluation.json").read_text(encoding="utf-8"))

    assert record["state"] == "draft" and record["reviews"] == []
    assert {match["decision"] for match in decisions["claim_matches"]} <= {"unresolved"}
    assert {a["decision"] for a in decisions["control_assessments"]} <= {"unresolved"}
    assert evaluation["metrics"]["targets_detected"] == 0


def test_the_frozen_pack_in_each_run_matches_the_plans_built_from_it():
    for run in sorted(RUNS.iterdir()):
        pack = json.loads((run / "evaluator" / "pack.json").read_text(encoding="utf-8"))
        digest = canonical_sha256(pack)
        for bundle in sorted(run.glob("invocations/*")):
            plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
            assert plan["provenance"]["pack_sha256"] == digest, bundle.name
            assert plan["provenance"]["pack_version"] == pack["version"]
