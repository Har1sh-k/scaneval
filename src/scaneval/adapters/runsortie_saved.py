"""Offline verification of the pinned RunSortie empty-review-queue capture."""

from __future__ import annotations

import json
import math
from pathlib import Path
import uuid

from . import runsortie as rs
from . import runsortie_evidence as ev
from .base import AdapterError
from ..contracts import canonical_json


_RECEIPTS = (
    ".state.json", "baseline-acceptance.json", "target-security-policy.json",
    "primary-review-packets.json", "sortie-state.json", "verification-summary.json",
    "work-budget.json", "fieldglass-work-budget.json",
)
_ZERO_PRIMARY = (
    "findingCount", "packetCount", "dispositionCount", "decisionsAvoided", "agentCalls",
    "liveCalls", "reusedCalls", "failedCalls", "exhaustedItems", "attempts", "durationMs",
    "promptBytes", "rawFindingEvidenceBytes",
)
_ZERO_CHALLENGER = (
    "groupCount", "attemptedCalls", "reusedCalls", "succeededCalls", "failedCalls",
    "exhaustedItems", "budgetExhaustedItems", "attempts", "journalFailedAttempts",
    "journalSuccessfulAttempts", "durationMs",
)
_FAILURES = ("auth", "content", "quota", "route", "timeout", "transport", "unclassified")
_ENGINE_ROLES = ("planner", "exploration", "validation", "specialist", "consensus")


def _object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise AdapterError(f"{label} must be a JSON object")
    return value


def _json_record(data: bytes, label: str) -> dict:
    def pairs(entries: list[tuple[str, object]]) -> dict:
        result = dict(entries)
        if len(result) != len(entries):
            raise ValueError("duplicate JSON key")
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant {value}")

    def finite_float(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("JSON number is outside the finite range")
        return result

    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant,
                            parse_float=finite_float)
    except (ValueError, RecursionError) as exc:
        raise AdapterError(f"{label} is not strict UTF-8 JSON") from exc
    return _object(result, label)


def _expect(record: dict, expected: dict, label: str) -> None:
    for key, value in expected.items():
        if key not in record or canonical_json(record[key]) != canonical_json(value):
            raise AdapterError(f"{label} has missing or inconsistent {key}")


def _read_capture(capture: Path, source_head: str, evidence_head: str, deadline: rs.Deadline):
    source = capture / "source"
    guard = rs._capture_root(capture)
    source_guard = rs._capture_root(source)
    repository_guard = rs._capture_git_repository(source, deadline)
    git = rs._git_dir(source, guard=repository_guard, deadline=deadline)
    product = rs._verified_commit_tree(source, git, source_head, deadline)
    committed = rs._verified_commit_tree(source, git, evidence_head, deadline)
    rs._git_dir(source, guard=repository_guard, deadline=deadline)
    prefix = b".fieldglass/"
    evidence_entries = {path: entry for path, entry in committed.entries.items() if path.startswith(prefix)}
    if (committed.parents != (source_head,) or
            {path: entry for path, entry in committed.entries.items() if path not in evidence_entries}
            != product.entries or any(path.startswith(prefix) for path in product.entries)):
        raise AdapterError("the evidence commit must be a direct child that adds only .fieldglass evidence")
    if not evidence_entries or len(evidence_entries) > rs.MAX_EVIDENCE_FILES:
        raise AdapterError("the committed evidence inventory is empty or exceeds its file limit")

    receipts = {}
    total = 0
    for path, (mode, oid) in evidence_entries.items():
        deadline.check()
        relative = path.decode("utf-8")
        if mode not in ("100644", "100755"):
            raise AdapterError(f"{relative} must be committed as a regular file")
        payload = rs._read_relative_regular(source, source_guard, relative, rs.MAX_RECEIPT_BYTES, deadline)
        total += len(payload)
        if total > rs.MAX_STATE_TOTAL_BYTES or rs._blob_id(payload) != oid:
            raise AdapterError(f"{relative} exceeds the capture limit or differs from the evidence commit")
        name = relative.removeprefix(".fieldglass/")
        if name in _RECEIPTS:
            receipts[name] = payload
    if set(receipts) != set(_RECEIPTS):
        raise AdapterError("the evidence commit lacks one or more required RunSortie receipts")
    return guard, product, committed, evidence_entries, receipts


def _verify_review(receipts: dict, parsed: dict, policy: dict, target_state: dict,
                   source_head: str, engine_input_hash: str) -> None:
    plan = parsed["primary-review-packets.json"]
    review = parsed["sortie-state.json"]
    summary = parsed["verification-summary.json"]
    _expect(plan, {"version": 2, "findingCount": 0, "packetCount": 0, "packets": [],
                   "rejectedRelationships": [], "targetSecurityPolicy": policy}, "review packet plan")
    if ev._native_iso(summary.get("evaluatedAt")) is None:
        raise AdapterError("the verification summary has no native review timestamp")
    _expect(summary, {"version": 6, "complete": True, "assuranceMode": "identity", "groups": [],
                      "primaryRationalePresent": False, "requiredFor": ["critical", "high"],
                      **dict.fromkeys(("capturedFindingIds", "missingDispositionFindingIds",
                                       "conflictingDispositionFindingIds", "staleDispositionFindingIds",
                                       "invalidIdentityFindingIds", "falsePositiveFindingIds"), [])}, "verification summary")
    _expect(_object(summary.get("primaryReview"), "primary review"),
            {"version": 2, "state": "complete", "manifestValid": True, "planValid": True,
             "manifestBytes": len(receipts["primary-review-packets.json"]), **dict.fromkeys(_ZERO_PRIMARY, 0),
             **dict.fromkeys(("rejectedRelationships", "missingPacketIds", "conflictingPacketIds",
                              "stalePacketIds", "unexpectedPacketIds"), [])}, "primary review")
    _expect(_object(summary.get("challenger"), "challenger"), {"state": "complete", **dict.fromkeys(_ZERO_CHALLENGER, 0)},
            "challenger")
    _expect(_object(summary.get("outcomes"), "review outcomes"),
            dict.fromkeys(("confirmed", "dismissed", "inconclusive", "downgraded", "promoted",
                           "restoredActive", "falsePositive"), 0), "review outcomes")
    _expect(review, dict.fromkeys(("confirmedFindingIds", "dismissedFindingIds", "inconclusiveFindingIds",
                                   "identityEvidence", "dispositionEvidence"), []), "review state")
    _expect(_object(review.get("reviewPolicy"), "review policy"),
            {"version": 7, "complete": True, "assuranceMode": "identity", "evaluatedAt": summary["evaluatedAt"],
             "primaryReviewManifestValid": True, "primaryReviewPlanValid": True, "primaryRationalePresent": False,
             **dict.fromkeys(("capturedHighRiskFindingIds", "missingDispositionFindingIds",
                              "conflictingDispositionFindingIds", "staleDispositionFindingIds",
                              "invalidIdentityFindingIds", "falsePositiveFindingIds", "missingPrimaryReviewPacketIds",
                              "conflictingPrimaryReviewPacketIds", "stalePrimaryReviewPacketIds",
                              "unexpectedPrimaryReviewPacketIds", "challengedRootCauseKeys"), [])}, "review policy")
    review_run = _object(target_state.get("reviewRun"), "target review receipt")
    _expect(review_run, {"version": 1, "status": "complete", "sourceHead": source_head,
                         "engineInputHash": engine_input_hash,
                         "primaryReviewPlanHash": ev._sha(ev._js_json(plan))}, "target review receipt")


def _verify_budget(parsed: dict, record: dict, product: rs.VerifiedGitTree, *, target: str,
                   source_head: str, attempted_at: str, count: int) -> int:
    budget = parsed["work-budget.json"]
    internal = parsed["fieldglass-work-budget.json"]
    _expect(budget, {"version": 1, "status": "complete", "sourceHead": source_head, "target": target,
                     "startedAt": attempted_at, "exhaustions": []}, "work budget")
    _expect(record, {"workBudget": budget}, "target state record")
    limits = _object(budget.get("limits"), "work budget limits")
    elapsed, max_files = limits.get("maxElapsedMs"), limits.get("maxModelFiles")
    if (set(limits) != {"version", "maxElapsedMs", "maxModelFiles"} or
            not ev._count(elapsed) or not elapsed or not ev._count(max_files) or count > max_files):
        raise AdapterError("the captured budget does not use the bounded smoke limits")
    _expect(limits, {"version": 1}, "work budget limits")
    started, end, updated, internal_updated = map(
        ev._native_iso, (attempted_at, budget.get("deadlineAt"), budget.get("updatedAt"), internal.get("updatedAt")))
    if (None in (started, end, updated, internal_updated) or not started <= internal_updated <= updated <= end
            or (end - started).total_seconds() * 1000 != elapsed):
        raise AdapterError("work budget timestamps contradict its bound limits")
    files = {"limit": max_files, "reserved": count}
    _expect(budget, {"modelFiles": files}, "work budget")
    _expect(internal, {"version": 1, "runId": budget.get("runId"), "startedAt": attempted_at,
                       "deadlineAt": budget["deadlineAt"], "limits": {"maxModelFiles": max_files},
                       "status": "complete", "exhaustions": [], "modelFiles": files}, "Fieldglass work budget")
    if not ev._text(budget.get("runId")):
        raise AdapterError("the captured budget has no native run id")
    digest = ev._sha(ev._js_json({key: value for key, value in internal.items() if key != "integrity"}))
    _expect(internal, {"integrity": digest}, "Fieldglass work budget")
    hashes = ev._ids(internal.get("modelFileHashes"))
    source_hashes = {ev._sha(path.replace(b"\\", b"/")) for path, (mode, _) in product.entries.items()
                     if mode in ("100644", "100755")}
    if hashes is None or len(hashes) != count or not set(hashes) <= source_hashes:
        raise AdapterError("Fieldglass model-file hashes do not bind the reported files to the source commit")
    calls = _object(budget.get("modelCalls"), "call budget")
    if set(calls) != {*_ENGINE_ROLES, "primaryReview", "challenger"}:
        raise AdapterError("the call budget has missing or unknown native roles")
    _expect(internal, {"modelCalls": {role: calls[role] for role in _ENGINE_ROLES}}, "Fieldglass work budget")
    total = 0
    for role, value in calls.items():
        counter = _object(value, f"{role} call budget")
        reserved = counter.get("reserved")
        if set(counter) != {"reserved"} or not ev._count(reserved) or bool(reserved) != (role in ("planner", "validation")):
            raise AdapterError(f"the {role} work budget has inconsistent native call reservations")
        total += reserved
    return total


def verify_capture(capture: Path, *, target: str, source_head: str, evidence_head: str) -> dict:
    """Verify the saved native zero-finding smoke profile without launching a scanner."""
    if not all(ev.HEX40.fullmatch(head) for head in (source_head, evidence_head)):
        raise AdapterError("source and evidence heads must be exact 40-hex Git commit ids")
    if not rs._BRANCH.fullmatch(target) or "/" in target:
        raise AdapterError("the target must be one native path component")
    capture = Path(capture)
    deadline = rs.Deadline(30)
    guard, product, committed, entries, receipts = _read_capture(capture, source_head, evidence_head, deadline)

    def read_state(relative: str) -> dict:
        return _json_record(rs._read_relative_regular(capture, guard, relative, rs.MAX_RECEIPT_BYTES, deadline), relative)

    parsed = {name: _json_record(data, name) for name, data in receipts.items()}
    packet_plan = parsed["primary-review-packets.json"]
    if packet_plan.get("version") != 2 or packet_plan.get("packets") != [] or any(
            path.startswith(b".fieldglass/findings/") for path in entries):
        raise AdapterError("this saved capture requires a different packet or finding verification profile")
    state = read_state("state/state.json")
    _expect(state, {"version": 1, "minimumReader": 6}, "target state")
    targets = _object(state.get("targets"), "target state targets")
    if set(targets) != {target}:
        raise AdapterError("the captured state must name exactly the requested target")
    record = _object(targets[target], "target state record")
    _expect(record, {"target": target, "outcome": "committed", "checkpoint": source_head, "productHead": source_head,
                     "repositoryHead": source_head, "evidenceHead": evidence_head}, "target state record")
    baseline = _object(record.get("baseline"), "target baseline")
    _expect(baseline, {"version": 1, "status": "ready", "attemptedHead": source_head, "checkpoint": source_head,
                       "acceptancePolicyVersion": 2, "acceptanceReasons": []}, "target baseline")
    acceptance = parsed["baseline-acceptance.json"]
    _expect(acceptance, {"policyVersion": 2, "sourceHead": source_head, "status": "accepted",
                         "checkpointEligible": True, "reasons": [], "recovery": baseline.get("recovery")},
            "baseline acceptance")
    recovery = acceptance["recovery"]
    if not ev._recovery_valid(recovery) or recovery["status"] != "complete" or not recovery["hypotheses"]["succeeded"]:
        raise AdapterError("baseline acceptance lacks reconciled successful hypothesis work")
    _expect(_object(acceptance.get("securityQuestionExecution"), "security question coverage"),
            {"status": "complete", "required": 0, "answered": 0, "completed": 0, "semanticAnswers": 0,
             "inspectionsCompleted": 0, "incompleteQuestionIds": [], "reasons": [], "questions": []},
            "security question coverage")
    if ev.read_checkpoint(receipts[".state.json"], source_head).state != "bound":
        raise AdapterError("Fieldglass checkpoint is not bound to the source head")
    if any(path.encode() in product.entries for path in ev.POLICY_SOURCE_CANDIDATES):
        raise AdapterError("this saved capture requires repository policy proposal verification")
    policy = ev.read_policy(receipts["target-security-policy.json"], repository_proposals={})
    if policy.state != "valid" or policy.value["status"] != "absent":
        raise AdapterError("this saved capture requires an absent, valid target security policy")
    engine_run = _object(record.get("engineRun"), "target engine receipt")
    _expect(engine_run, {"version": 2, "sourceHead": source_head, "status": "complete", "reasons": [],
                         "provenance": {"kind": "observed"},
                         "targetSecurityPolicyEvidenceHash": policy.value["evidenceHash"]}, "target engine receipt")
    input_hash = engine_run.get("inputHash")
    if not isinstance(input_hash, str) or not ev.HEX64.fullmatch(input_hash):
        raise AdapterError("the target engine receipt has no native input digest")
    _verify_review(receipts, parsed, policy.value, record, source_head, input_hash)

    gap = _object(record.get("gapSummary"), "target gap summary")
    attempt = gap.get("attemptId")
    attempted_at = record.get("lastAttemptAt")
    if ev._native_iso(attempted_at) is None:
        raise AdapterError("the target state has no native attempt timestamp")
    try:
        attempt_id = uuid.UUID(str(attempt))
        if str(attempt_id) != attempt or attempt_id.version != 4:
            raise ValueError
    except ValueError as exc:
        raise AdapterError("the target gap summary has no native attempt UUID") from exc
    receipt = read_state(f"state/settlements/{target}/{attempt}.receipt.json")
    committed_marker = read_state(f"state/settlements/{target}/{attempt}.committed.json")
    ledger = read_state(f"state/gaps/{target}/attempts/{attempt}.json")
    _expect(receipt, {"version": 1, "target": target, "attemptId": attempt, "attemptedAt": attempted_at,
                      "commit": evidence_head, "tree": committed.tree, "range": {"head": source_head}},
            "settlement receipt")
    ledger_digest = ledger.get("digest")
    if not isinstance(ledger_digest, str) or ledger_digest != ev._sha(canonical_json(
            {key: value for key, value in ledger.items() if key != "digest"})):
        raise AdapterError("the native coverage ledger digest does not match its content")
    _expect(gap, {"attemptedAt": attempted_at, "recordDigest": ledger_digest, "ledgerStatus": "recorded"},
            "target gap summary")
    _expect(receipt, {"recordDigest": ledger_digest}, "settlement receipt")
    _expect(committed_marker, {"version": 1, "attemptId": attempt, "commit": evidence_head,
                               "tree": committed.tree, "ledgerDigest": ledger_digest, "postCommitChecks": "passed",
                               "run": {"attemptId": attempt, "lastAttemptAt": attempted_at,
                                       "recordDigest": ledger_digest}},
            "settlement committed marker")
    _expect(ledger, {"version": 9, "manifestVersion": 7, "integrity": "ok", "outcome": "committed",
                     "target": target, "attemptId": attempt, "range": {"head": source_head},
                     "attemptedAt": attempted_at, "mode": "bootstrap", "reviewerCalls": {"primary": [], "challenger": []},
                     "reviewerCallsTruncated": {"primary": False, "challenger": False},
                     "engineFailureEventsTruncated": False,
                     "engineInputHash": input_hash,
                     "engineVerdict": {"status": "complete", "reasons": [], "provenance": "observed"}},
            "coverage ledger")
    coverage = _object(ledger.get("coverageCounts"), "coverage ledger counts")
    count = coverage.get("inventoryFiles")
    if not ev._count(count) or not count:
        raise AdapterError("the coverage ledger records no inspected source")
    _expect(coverage, {"mode": "bootstrap", "eligibleFiles": count, "focusedFiles": count,
                       "llmFilesInspected": count}, "coverage ledger counts")
    calls = _verify_budget(parsed, record, product, target=target, source_head=source_head,
                           attempted_at=attempted_at, count=count)
    failures = dict.fromkeys(_FAILURES, 0)
    _expect(ledger, {"engineFailureClasses": {"success": calls, **failures},
                     "reviewerFailureClasses": dict.fromkeys(("primary", "challenger"), {"success": 0, **failures})},
            "coverage ledger")
    return {"status": "verified", "profile": "runsortie-8c5031c-zero-packet-capture",
            "source_head": source_head, "evidence_head": evidence_head, "target": target,
            "reported_inspected_files": count, "packets": 0, "evidence_files": len(entries)}
