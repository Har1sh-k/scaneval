"""Verification of saved RunSortie v2 receipts with local inert Git fixtures."""

import json
import subprocess

import pytest

from scaneval.adapters import runsortie_evidence as ev
from scaneval.cli import main
from scaneval.contracts import canonical_json
from scaneval.materialize import git_command


ATTEMPT = "11111111-2222-4333-8444-555555555555"
TIME = "2026-11-20T16:35:22.317Z"
INPUT_HASH = "a" * 64


def _git(repo, *args):
    argv, env = git_command(["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", *args])
    return subprocess.run(argv, cwd=repo, env=env, capture_output=True, check=True, text=True).stdout.strip()


def _save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _fixture(root, change):
    source = root / "source"
    source.mkdir(parents=True)
    _git(source, "init", "-q", "-b", "main")
    (source / "label.py").write_text('LABEL = "fixture"\n', encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "-qm", "source")
    head = _git(source, "rev-parse", "HEAD")
    policy = ev.expected_absent_policy({})
    recovery = {
        "status": "complete", "planHash": "c" * 64, "reasons": [],
        "hypotheses": {"planned": 1, "scheduled": 1, "succeeded": 1, "failed": 0, "exhausted": 0,
                       "stillUnevaluated": 0},
        "workItems": {"scheduled": 1, "succeeded": 1, "retryable": 0, "exhausted": 0, "terminal": 0,
                      "capacityExhausted": False},
        "limits": {"maxWorkItems": 1024, "maxAttemptsPerItem": 8},
    }
    plan = {"version": 2, "findingCount": 0, "packetCount": 0, "packets": [], "rejectedRelationships": [],
            "targetSecurityPolicy": policy}
    if change == "packets":
        plan.update({"findingCount": 1, "packetCount": 1, "packets": [{"version": 2}]})
    evidence_dir = source / ".fieldglass"
    plan_path = evidence_dir / "primary-review-packets.json"
    _save(plan_path, plan)
    lists = dict.fromkeys(("missingDispositionFindingIds", "conflictingDispositionFindingIds",
                          "staleDispositionFindingIds", "invalidIdentityFindingIds", "falsePositiveFindingIds"), [])
    policy_state = {"version": 7, "complete": True, "assuranceMode": "identity", "evaluatedAt": TIME,
                    "primaryReviewManifestValid": True, "primaryReviewPlanValid": True, "primaryRationalePresent": False,
                    "capturedHighRiskFindingIds": [], "missingPrimaryReviewPacketIds": [],
                    "conflictingPrimaryReviewPacketIds": [], "stalePrimaryReviewPacketIds": [],
                    "unexpectedPrimaryReviewPacketIds": [], "challengedRootCauseKeys": [], **lists}
    primary = {
        "version": 2, "state": "complete", "manifestValid": True, "planValid": True,
        "manifestBytes": plan_path.stat().st_size, "findingCount": 0, "packetCount": 0, "dispositionCount": 0,
        "decisionsAvoided": 0, "agentCalls": 0, "liveCalls": 0, "reusedCalls": 0, "failedCalls": 0,
        "exhaustedItems": 0, "attempts": 0, "durationMs": 0, "promptBytes": 0, "rawFindingEvidenceBytes": 0,
        "rejectedRelationships": [], "missingPacketIds": [], "conflictingPacketIds": [], "stalePacketIds": [],
        "unexpectedPacketIds": [],
    }
    if change == "calls":
        primary["agentCalls"] = 1
    challenger = {"state": "complete", "groupCount": 0, "attemptedCalls": 0, "reusedCalls": 0,
                  "succeededCalls": 0, "failedCalls": 0, "exhaustedItems": 0, "budgetExhaustedItems": 0,
                  "attempts": 0, "journalFailedAttempts": 0, "journalSuccessfulAttempts": 0, "durationMs": 0}
    engine_calls = {role: {"reserved": int(role in ("planner", "validation"))}
                    for role in ("planner", "exploration", "validation", "specialist", "consensus")}
    budget = {"version": 1, "status": "complete", "sourceHead": head, "target": "inert", "startedAt": TIME,
              "updatedAt": TIME, "deadlineAt": "2026-11-20T16:35:23.317Z",
              "limits": {"version": 1, "maxElapsedMs": 1000, "maxModelFiles": 2}, "exhaustions": [],
              "modelCalls": {**engine_calls, "primaryReview": {"reserved": 0}, "challenger": {"reserved": 0}},
              "modelFiles": {"reserved": 1, "limit": 2}, "runId": "9d28f4d7-00e2-4a08-8a89-1af5c54b3384"}
    fieldglass_budget = {k: budget[k] for k in ("version", "runId", "status", "exhaustions", "modelFiles",
                                                 "startedAt", "updatedAt", "deadlineAt")}
    fieldglass_budget.update({"limits": {"maxModelFiles": 2}, "modelCalls": engine_calls,
                               "modelFileHashes": [ev._sha("wrong.py" if change == "file-hash" else "label.py")]})
    fieldglass_budget["integrity"] = "a" * 64 if change == "budget-seal" else ev._sha(ev._js_json(fieldglass_budget))
    docs = {
        ".state.json": {"lastBatchHead": head},
        "target-security-policy.json": policy,
        "baseline-acceptance.json": {"policyVersion": 2, "sourceHead": head, "status": "accepted",
                                     "checkpointEligible": True, "reasons": [], "recovery": recovery,
                                     "securityQuestionExecution": {"status": "complete", "required": 0, "answered": 0,
                                         "completed": 0, "semanticAnswers": 0, "inspectionsCompleted": 0,
                                         "incompleteQuestionIds": [], "reasons": [], "questions": []}},
        "sortie-state.json": {**dict.fromkeys(("confirmedFindingIds", "dismissedFindingIds", "inconclusiveFindingIds",
                                              "identityEvidence", "dispositionEvidence"), []), "reviewPolicy": policy_state},
        "verification-summary.json": {"version": 6, "complete": True, "assuranceMode": "identity", "groups": [],
                                      "evaluatedAt": TIME, "primaryRationalePresent": False, "capturedFindingIds": [],
                                      "requiredFor": ["critical", "high"], "primaryReview": primary, "challenger": challenger,
                                      "outcomes": dict.fromkeys(("confirmed", "dismissed", "inconclusive", "downgraded",
                                                                 "promoted", "restoredActive", "falsePositive"), 0), **lists},
        "work-budget.json": budget,
        "fieldglass-work-budget.json": fieldglass_budget,
    }
    for name, doc in docs.items():
        _save(evidence_dir / name, doc)
    if change == "product":
        (source / "label.py").write_text('LABEL = "changed"\n', encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "-qm", "saved evidence")
    commit, tree = (_git(source, "rev-parse", ref) for ref in ("HEAD", "HEAD^{tree}"))
    if change == "bytes":
        plan_path.write_bytes(plan_path.read_bytes() + b"\n")
    failures = dict.fromkeys(("auth", "content", "quota", "route", "timeout", "transport", "unclassified"), 0)
    ledger = {"version": 9, "manifestVersion": 7, "integrity": "ok", "outcome": "committed",
              "reviewerCalls": {"primary": [], "challenger": []}, "target": "inert", "attemptId": ATTEMPT,
              "reviewerCallsTruncated": {"primary": False, "challenger": False},
              "engineFailureEventsTruncated": False, "engineFailureClasses": {"success": 2, **failures},
              "reviewerFailureClasses": dict.fromkeys(("primary", "challenger"), {"success": 0, **failures}),
              "range": {"head": head}, "attemptedAt": TIME, "mode": "bootstrap",
              "engineInputHash": INPUT_HASH, "engineVerdict": {"status": "complete", "reasons": [], "provenance": "observed"},
              "coverageCounts": {"mode": "bootstrap", "inventoryFiles": 1, "eligibleFiles": 1, "focusedFiles": 1,
                                 "llmFilesInspected": 1}}
    if change == "ledger":
        ledger["outcome"] = "committed-incomplete"
    digest = ev._sha(canonical_json(ledger))
    _save(root / f"state/gaps/inert/attempts/{ATTEMPT}.json", {**ledger, "digest": digest})
    settlement = {"version": 1, "attemptId": ATTEMPT, "commit": commit, "tree": tree}
    _save(root / f"state/settlements/inert/{ATTEMPT}.receipt.json",
          {**settlement, "target": "inert", "range": {"head": head}, "recordDigest": digest,
           "attemptedAt": "2026-11-20T16:35:24.317Z" if change == "attempt-time" else TIME})
    _save(root / f"state/settlements/inert/{ATTEMPT}.committed.json",
          {**settlement, "ledgerDigest": digest, "postCommitChecks": "passed",
           "run": {"attemptId": ATTEMPT, "lastAttemptAt": TIME, "recordDigest": "f" * 64
                   if change == "marker" else digest}})
    record = {"target": "inert", "outcome": "committed", "checkpoint": head, "repositoryHead": head,
              "productHead": head, "evidenceHead": commit, "lastAttemptAt": TIME, "workBudget": budget,
              "baseline": {"version": 1, "status": "ready", "attemptedHead": head, "checkpoint": head,
                           "acceptancePolicyVersion": 2, "acceptanceReasons": [], "recovery": recovery},
              "engineRun": {"version": 2, "sourceHead": head, "status": "complete", "reasons": [],
                            "provenance": {"kind": "observed"}, "inputHash": INPUT_HASH,
                            "targetSecurityPolicyEvidenceHash": policy["evidenceHash"]},
              "reviewRun": {"version": 1, "status": "complete", "sourceHead": head, "engineInputHash": INPUT_HASH,
                            "primaryReviewPlanHash": ev._sha(ev._js_json(plan))},
              "gapSummary": {"attemptId": ATTEMPT, "attemptedAt": TIME, "recordDigest": digest,
                             "ledgerStatus": "recorded"}}
    _save(root / "state/state.json", {"version": 1, "minimumReader": 6, "targets": {"inert": record}})
    return ["diagnose", "runsortie", str(root), "--target", "inert",
            "--source-head", head, "--evidence-head", commit]


def test_validates_saved_v2_capture_without_a_scanner(tmp_path, capsys):
    args = _fixture(tmp_path / "capture", None)
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report == {"status": "verified", "profile": "runsortie-8c5031c-zero-packet-capture",
                      "target": "inert", "source_head": args[-3], "evidence_head": args[-1],
                      "reported_inspected_files": 1, "packets": 0, "evidence_files": 8}


@pytest.mark.parametrize(("change", "message"), [
    ("product", "adds only .fieldglass evidence"),
    ("bytes", "differs from the evidence commit"),
    ("packets", "different packet or finding verification profile"),
    ("calls", "inconsistent agentCalls"),
    ("ledger", "coverage ledger has missing or inconsistent outcome"),
    ("attempt-time", "settlement receipt has missing or inconsistent attemptedAt"),
    ("marker", "settlement committed marker has missing or inconsistent run"),
    ("file-hash", "model-file hashes do not bind"),
    ("budget-seal", "Fieldglass work budget has missing or inconsistent integrity"),
])
def test_revokes_verification_when_saved_receipts_conflict(tmp_path, capsys, change, message):
    args = _fixture(tmp_path / "capture", change)
    assert main(args) == 2
    captured = capsys.readouterr()
    assert not captured.out and message in captured.err
