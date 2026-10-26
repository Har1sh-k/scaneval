from copy import deepcopy
import hashlib
import json

import pytest

from scaneval.contracts import canonical_json, canonical_sha256
from scaneval.isolation import resolve_execution
from scaneval.isolation.oci import OciBackend
from scaneval.isolation.public_retrieval import validate_settings
from scaneval.open_context_evidence import classify_condition


POLICY = {"history": "ancestor_history_v1", "retrieval": "recorded_public_v1", "web_mode": "live",
          "capture": "content", "retention": "bundle"}
RETRIEVAL = validate_settings({"policy": "recorded_public_v1", "allowed_origins": ["https://example.com"],
                               "capture": "content", "retention": "bundle"})


def base_execution():
    return {"provenance": {"mode": "full", "profile": "standard", "tree_hash": "sha256:" + "a" * 64},
            "network_policy": {"declared": "public_research", "enforced": False},
            "isolation": {"backend": "oci", "enforced": False, "containers": []}}


def journal_capture(tmp_path, starts, events, *, state):
    root = tmp_path / "raw" / "retrieval-provenance"
    root.mkdir(parents=True)
    raw = "".join(canonical_json(row) + "\n" for row in events).encode()
    started = "".join(canonical_json(row) + "\n" for row in starts).encode()
    (root / "events.jsonl").write_bytes(raw)
    (root / "attempts.jsonl").write_bytes(started)
    return {"policy": RETRIEVAL, "policy_sha256": canonical_sha256(RETRIEVAL), "capture_status": state,
        "events_path": "raw/retrieval-provenance/events.jsonl", "events_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "attempts_path": "raw/retrieval-provenance/attempts.jsonl", "attempts_sha256": "sha256:" + hashlib.sha256(started).hexdigest(),
        "attempts": len(starts), "completed_attempts": len(events), "incomplete_attempts": len(starts) - len(events),
        "denied": 0, "failed": 0, "preserved": 0, "hash_only": 0}


def test_idless_journals_are_a_structured_failure(tmp_path):
    execution = base_execution()
    execution["isolation"]["retrieval"] = journal_capture(tmp_path, [{}], [{}], state="recorded")
    result = classify_condition(tmp_path, execution, POLICY, {})
    assert result["status"] == "failed"
    assert any(reason["code"] == "retrieval_artifact_mismatch" for reason in result["reasons"])


@pytest.mark.parametrize("mutation", [None, "bytes", "counts"])
def test_partial_capture_artifacts_and_counts_remain_bound(tmp_path, mutation):
    start = {"id": "started", "operation": "fetch", "url": "https://example.com/", "query": None,
             "source": "scanner_native", "source_assurance": "self_reported", "started_at": "2026-10-25T00:00:00Z"}
    execution = base_execution()
    capture = journal_capture(tmp_path, [start], [], state="partial")
    execution["isolation"]["retrieval"] = capture
    if mutation == "bytes":
        (tmp_path / capture["attempts_path"]).write_text(json.dumps({**start, "url": "https://changed.example/"}) + "\n")
    elif mutation == "counts":
        capture["attempts"] = 0
    result = classify_condition(tmp_path, execution, POLICY, {})
    assert result["retrieval"] == "capture_gap"
    if mutation is None:
        assert result["status"] == "declared_only"
        assert {item["role"] for item in result["artifacts"]} == {"retrieval_events", "retrieval_attempts"}
    else:
        assert result["status"] == "failed"
        assert any(reason["code"] == "retrieval_artifact_mismatch" for reason in result["reasons"])


def history_evidence(tmp_path):
    execution = base_execution()
    head = "b" * 40
    history = {"status": "available", "policy": "ancestor_history_v1", "head_commit": head,
               "source_tree_hash": execution["provenance"]["tree_hash"], "reachable_commit_count": 1,
               "history_digest": "sha256:" + "c" * 64,
               "refs": [{"name": "HEAD", "target": head, "symbolic": False}]}
    (tmp_path / "input-provenance.json").write_text(canonical_json({"history": history}))
    audit = {"state": "bounded_ancestor_history", "git_files_sha256": "sha256:" + "d" * 64}
    return execution, {"history_evidence": history, "history": {"before": deepcopy(audit), "after": deepcopy(audit)}}


def test_substituted_history_attestation_does_not_override_bound_provenance(tmp_path):
    execution, evidence = history_evidence(tmp_path)
    assert classify_condition(tmp_path, execution, POLICY, evidence)["history"] == "bounded_ancestor_history"
    evidence["history_evidence"]["history_digest"] = "sha256:" + "e" * 64
    result = classify_condition(tmp_path, execution, POLICY, evidence)
    assert result["status"] == "failed" and result["history"] != "bounded_ancestor_history"
    assert any(reason["code"] == "history_provenance_mismatch" for reason in result["reasons"])


@pytest.mark.parametrize("mutation", ["unexpected", "digest", "missing_digest"])
def test_failed_mechanical_git_audit_stays_unexpected(tmp_path, mutation):
    execution, evidence = history_evidence(tmp_path)
    if mutation == "unexpected": evidence["history"]["after"]["state"] = "unexpected"
    elif mutation == "digest": evidence["history"]["after"]["git_files_sha256"] = "sha256:" + "f" * 64
    else:
        evidence["history"]["before"].pop("git_files_sha256")
        evidence["history"]["after"].pop("git_files_sha256")
    result = classify_condition(tmp_path, execution, POLICY, evidence)
    assert result["status"] == "failed" and result["history"] == "unexpected"


def test_unstarted_backend_retains_policy_hash_without_a_false_mismatch(tmp_path):
    image = "fixture@sha256:" + "a" * 64
    settings = resolve_execution({"backend": "oci", "image": image, "proxy_image": image,
        "egress": [{"host": "example.com", "port": 443}], "retrieval": RETRIEVAL}, "public_research")
    backend = OciBackend(settings, run_id="fixture", invocation_id="unstarted", scratch_root=tmp_path)
    try:
        execution = base_execution()
        execution["isolation"] = backend.isolation_record()
        result = classify_condition(tmp_path, execution, POLICY, {})
        assert result["status"] == "declared_only"
        assert not any(reason["code"] == "retrieval_policy_mismatch" for reason in result["reasons"])
    finally:
        assert backend.close() == []
