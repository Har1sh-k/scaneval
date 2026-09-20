"""Preserved run bundles are immutable evidence, and a rename must not rewrite them.

Every bundle under ``corpus/pilot/runs`` records what was actually executed. Its
documents are bound to each other by content hash, so editing one to match a later
project name silently invalidates the binding and turns a real record into a forged
one. These tests re-verify those bindings on the files as committed, and pin the
historical identifiers that a sweep must leave alone.

They assert nothing about detection. Every preserved decision is unresolved.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastbench.contracts import canonical_sha256, load_document
from sastbench.scoring import score


RUNS = Path(__file__).resolve().parents[1] / "corpus" / "pilot" / "runs"
# The name this project carried when these runs were executed. It stays in the
# preserved records after the rename to ScanEval, because the records state what ran.
HISTORICAL_NAMESPACE = "sastbench.public"
HISTORICAL_PACKAGE = "sastbench"


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


@pytest.mark.parametrize("bundle", bundles(), ids=bundle_ids())
def test_the_rename_did_not_relabel_historical_records(bundle: Path):
    """A sweep that renamed these would break the bindings checked above.

    Editing the namespace inside a preserved plan changes its canonical hash, so the
    evaluation record and the review record would no longer bind to it. The old name
    therefore stays here on purpose; it is what the run recorded.
    """
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    execution = load_document(bundle / "execution.json", "execution-record")

    assert plan["provenance"]["namespace"] == HISTORICAL_NAMESPACE
    assert HISTORICAL_PACKAGE in execution["versions"]

    # Demonstrate the reason rather than asserting it: relabeling breaks the binding.
    evaluation = json.loads((bundle / "evaluation.json").read_text(encoding="utf-8"))
    relabeled = json.loads(json.dumps(plan))
    relabeled["provenance"]["namespace"] = "scaneval.public"
    assert canonical_sha256(relabeled) != evaluation["plan_sha256"]


def test_the_frozen_pack_in_each_run_matches_the_plans_built_from_it():
    for run in sorted(RUNS.iterdir()):
        pack = json.loads((run / "evaluator" / "pack.json").read_text(encoding="utf-8"))
        digest = canonical_sha256(pack)
        for bundle in sorted(run.glob("invocations/*")):
            plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
            assert plan["provenance"]["pack_sha256"] == digest, bundle.name
            assert plan["provenance"]["pack_version"] == pack["version"]
