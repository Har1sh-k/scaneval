"""Machine review can replace a workflow gate without impersonating a human review."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from scaneval import machine_review as mr
from scaneval.cases import mechanical_checks, save_pack
from scaneval.cli import main
from scaneval.contracts import ContractError, canonical_sha256, pack_anchor_digest
from scaneval.materialize import hash_exported_tree
from test_v2_cases import export, make_pack


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def digest(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def review(tmp_path):
    source = export(tmp_path)
    pack = make_pack()
    tree = hash_exported_tree(source)["tree_hash"]
    mechanical_checks(pack, "widget-abc", source, tree)
    pack_path = tmp_path / "pack.json"
    save_pack(pack_path, pack)
    write(tmp_path / "provenance.json", {"trial": {"tree_hash": tree}, "source": {"commit": "a" * 40}})
    payloads = {"cve": {"cveMetadata": {"cveId": "CVE-2026-0001", "state": "PUBLISHED"}},
                "fix-commit": {"sha": "c" * 40, "parents": [{"sha": "a" * 40}]},
                "fix-patch": {"patch": "replace shell interpolation with argument array"}}
    receipts = []
    for kind, payload in payloads.items():
        path = tmp_path / f"{kind}.json"
        write(path, payload)
        receipts.append({"case_id": "widget-shell", "kind": kind, "local_path": path.name,
                         "url": "https://example.invalid/" + kind, "http_status": 200, "sha256": digest(path)})
    receipts.append({"case_id": "widget-shell", "kind": "source-1-vulnerable", "local_path": "source/src/app.py",
                     "url": "https://example.invalid/source", "http_status": 200, "sha256": digest(source / "src/app.py")})
    manifest = {"pack_id": pack["pack_id"], "pack_version": pack["version"],
                "cases": [{"case_id": "widget-shell", "cve": "CVE-2026-0001", "vulnerable_commit": "a" * 40,
                           "fixed_candidate_commit": "c" * 40, "vulnerable_pin_is_fix_parent": True}],
                "snapshots": [{"snapshot_id": "widget-abc", "source_root": "source", "provenance_path": "provenance.json"}],
                "sources": receipts}
    evidence = tmp_path / "evidence.json"
    write(evidence, manifest)
    packets = tmp_path / "packets"
    index = mr.prepare(pack_path, evidence, tmp_path, packets)
    row = {"case_id": "widget-shell", "packet_sha256": index["packets"][0]["sha256"], "verdict": "accept",
           "rationale": "Test fixture: caller input reaches a shell; patch replaces shell interpretation.",
           "criteria": {k: "supported" for k in mr.CRITERIA}, "blockers": [],
           "limitations": ["Synthetic validator fixture, not a reviewed real CVE."],
           "citations": [{"artifact_id": k, "start_line": start, "end_line": start}
                         for k, start in [("cve", 1), ("fix-patch", 1), ("source:src/app.py", 3)]]}
    prompt = tmp_path / "prompt.txt"
    prompt.write_text("Test-fixture prompt; no model was invoked.\n")
    provenance = {"requested_model": "test-model", "reported_model": "test-model",
                  "identity_basis": "orchestrator_task_metadata", "identity_ambiguous": False,
                  "run_id": "fixture-only", "prompt_path": "prompt.txt", "prompt_sha256": digest(prompt),
                  "receipt_path": "receipt.json", "receipt_sha256": "sha256:" + "0" * 64,
                  "reviewed_at": "2026-10-22T00:00:00Z"}
    document = {"schema_version": "1.0", "review_kind": "machine", "scope": "static_labels",
                "provenance": provenance, "judgments": [row]}
    state = {"root": tmp_path, "pack_path": pack_path, "pack": pack, "index": index,
             "packets": packets, "document": document, "manifest": manifest, "evidence": evidence,
             "judgments_path": tmp_path / "judgments.json", "report": tmp_path / "report.json"}
    persist_response(state)
    return state


def persist_response(state):
    root, doc = state["root"], state["document"]
    write(root / "raw-response.json", {"judgments": doc["judgments"]})
    receipt = {k: v for k, v in doc["provenance"].items() if k not in ("receipt_path", "receipt_sha256")}
    receipt.update(status="completed", packet_set_sha256=canonical_sha256(state["index"]),
                   response_path="raw-response.json", response_sha256=digest(root / "raw-response.json"))
    write(root / "receipt.json", receipt)
    doc["provenance"]["receipt_sha256"] = digest(root / "receipt.json")
    write(state["judgments_path"], doc)


def record(state):
    return mr.record(state["pack_path"], state["packets"], state["judgments_path"], state["report"])


def test_machine_roundtrip_never_changes_human_state_or_pack(review):
    before = review["pack_path"].read_bytes()
    report = record(review)
    assert report["review_kind"] == "machine"
    assert mr.check(review["pack_path"], review["packets"], review["report"])["counts"] == {"accept": 1, "revise": 0, "abstain": 0}
    assert review["pack_path"].read_bytes() == before
    assert review["pack"]["admissions"] == []
    assert review["pack"]["cases"][0]["validation"]["reviews"] == []


@pytest.mark.parametrize("change", ["unknown_citation", "invalid_line", "location_uncovered", "blocker", "criterion", "duplicate", "missing", "packet_hash"])
def test_invalid_judgments_are_refused_without_report(review, change):
    row = review["document"]["judgments"][0]
    if change == "unknown_citation": row["citations"][0]["artifact_id"] = "invented"
    elif change == "invalid_line": row["citations"][0]["end_line"] = 10000
    elif change == "location_uncovered": row["citations"][-1].update(start_line=1, end_line=1)
    elif change == "blocker": row["blockers"] = ["Unresolved source contradiction"]
    elif change == "criterion": row["criteria"]["mapping"] = "uncertain"
    elif change == "duplicate": review["document"]["judgments"].append(deepcopy(row))
    elif change == "missing": review["document"]["judgments"] = []
    elif change == "packet_hash": row["packet_sha256"] = "sha256:" + "9" * 64
    persist_response(review)
    with pytest.raises(ContractError): record(review)
    assert not review["report"].exists()


@pytest.mark.parametrize("change", ["source", "advisory", "label", "packet", "prompt", "raw_response", "receipt", "parsed_decision"])
def test_stale_or_tampered_evidence_is_refused(review, change):
    root = review["root"]
    if change == "source": (root / "source/src/app.py").write_text("changed source\n")
    elif change == "advisory": (root / "cve.json").write_text("{}")
    elif change == "label":
        review["pack"]["cases"][0]["target"]["description"] = "Different causal allegation"
        review["pack"]["anchor_sha256"] = pack_anchor_digest(review["pack"])
        save_pack(review["pack_path"], review["pack"])
    elif change == "packet": write(review["packets"] / "widget-shell.json", {})
    elif change == "prompt": (root / "prompt.txt").write_text("changed prompt")
    elif change == "raw_response": (root / "raw-response.json").write_text("{}")
    elif change == "receipt": (root / "receipt.json").write_text("{}")
    elif change == "parsed_decision":
        review["document"]["judgments"][0]["rationale"] = "A different model answer"
        write(review["judgments_path"], review["document"])
    with pytest.raises(ContractError): record(review)
    assert not review["report"].exists()


def test_ambiguous_identity_is_retained_but_not_accepted(review):
    review["document"]["provenance"]["identity_ambiguous"] = True
    persist_response(review)
    report = record(review)
    assert report["summary"]["counts"]["abstain"] == 1
    assert report["summary"]["decisions"][0]["judge_verdict"] == "accept"
    assert main(["corpus", "machine-check", str(review["pack_path"]), "--packets", str(review["packets"]), "--report", str(review["report"])]) == 1


@pytest.mark.parametrize("value", ["../outside", "/tmp/outside", "escape"])
def test_evidence_paths_cannot_escape_root(review, value, tmp_path):
    (tmp_path / "escape").symlink_to(tmp_path.parent)
    review["manifest"]["sources"][0]["local_path"] = value
    write(review["evidence"], review["manifest"])
    with pytest.raises(ContractError, match="root"):
        mr.prepare(review["pack_path"], review["evidence"], tmp_path, tmp_path / "new-packets")


def test_wrong_receipt_packet_set_is_refused(review):
    path = review["root"] / "receipt.json"
    receipt = json.loads(path.read_text())
    receipt["packet_set_sha256"] = "sha256:" + "0" * 64
    write(path, receipt)
    review["document"]["provenance"]["receipt_sha256"] = digest(path)
    write(review["judgments_path"], review["document"])
    with pytest.raises(ContractError, match="packet set"): record(review)


@pytest.mark.parametrize("status", ["failed", "truncated", "running"])
def test_an_incomplete_model_run_cannot_approve_labels(review, status):
    path = review["root"] / "receipt.json"
    receipt = json.loads(path.read_text())
    receipt["status"] = status
    write(path, receipt)
    review["document"]["provenance"]["receipt_sha256"] = digest(path)
    write(review["judgments_path"], review["document"])
    with pytest.raises(ContractError, match="incomplete"): record(review)


def test_malformed_manifest_is_a_cli_refusal(review):
    review["manifest"]["sources"] = [None]
    write(review["evidence"], review["manifest"])
    assert main(["corpus", "machine-prepare", str(review["pack_path"]), "--evidence", str(review["evidence"]),
                 "--repository-root", str(review["root"]), "--output", str(review["root"] / "new-packets")]) == 2


def test_machine_output_cannot_be_written_into_scanner_source(review):
    assert main(["corpus", "machine-record", str(review["pack_path"]), "--packets", str(review["packets"]),
                 "--judgments", str(review["judgments_path"]), "--output", str(review["root"] / "source/answer.json")]) == 2
    assert not (review["root"] / "source/answer.json").exists()
