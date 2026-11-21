"""Saved, nonempty RunSortie v2 packet receipts and member evidence."""

from hashlib import sha256
import json

import pytest

from scaneval.cli import main


def _sha(text):
    return sha256(text.encode()).hexdigest()


def _queue(tmp_path, change=None):
    root = tmp_path / ".fieldglass"
    (root / "findings").mkdir(parents=True)
    members = []
    preimages = []
    scope = {"version": 1, "paths": ["app.py"], "maxAdditionalPaths": 6, "expansion": "direct-callers-or-callees"}
    for letter in ("A", "B"):
        data = f"Fabricated receipt {letter}\n"
        path = f".fieldglass/findings/{letter}.md"
        (tmp_path / path).write_text(data, encoding="utf-8")
        member = {
            "findingId": f"FG-{letter}", "severity": "medium" if change == "promotion" else "high",
            "reviewClaimSeverity": "high",
            "reviewSelectionReason": "configured-severity", "rootCauseFingerprint": "fixture",
            "rootCauseEvidenceHash": "a" * 64, "evidencePath": path, "evidenceHash": _sha(data),
        }
        members.append(member)
        preimages.append("\0".join((f"FG-{letter}", "high", "configured-severity", "fixture", "a" * 64,
                                   "no-review-equivalence", "", "", _sha(data), path, "null")))
    packet_hash = _sha("\n".join(("no-target-security-policy", json.dumps(scope, separators=(",", ":")), *preimages)))
    packet = {"version": 2, "packetId": "RCP-" + "a" * 24, "packetEvidenceHash": packet_hash,
              "grouping": "exact-root-cause", "canonicalFindingId": "FG-A", "memberFindingIds": ["FG-A", "FG-B"],
              "members": members, "reviewClaimSeverity": "high", "reviewScope": scope}
    plan = {"version": 2, "findingCount": 2, "packetCount": 1, "packets": [packet], "rejectedRelationships": []}
    if change == "scope":
        scope["paths"] = ["other.py"]
    if change == "member-order":
        packet["memberFindingIds"].reverse()
    if change == "traversal":
        members[0]["evidencePath"] = ".fieldglass/findings/../../other.py"
    if change == "bytes":
        (root / "findings/A.md").write_text("altered\n", encoding="utf-8")
    if change == "symlink":
        (root / "findings/A.md").unlink()
        (root / "findings/A.md").symlink_to(root / "findings/B.md")
    if change == "count":
        plan["findingCount"] = 1
    if change == "empty":
        plan.update({"findingCount": 0, "packetCount": 0, "packets": []})
    if change == "overflow":
        members[0]["targetPolicyClassification"] = {"severityScore": "OVERFLOW"}
    text = json.dumps(plan, indent=2) + "\n"
    if change == "overflow":
        text = text.replace('"OVERFLOW"', "1e999")
    path = root / "primary-review-packets.json"
    path.write_text(text, encoding="utf-8")
    pin = "0" * 64 if change == "pin" else _sha(text)
    return ["diagnose", "runsortie-packets", str(path), "--expect-sha256", "sha256:" + pin], packet_hash


def test_verifies_two_findings_without_assigning_dispositions(tmp_path, capsys):
    args, packet_hash = _queue(tmp_path)
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "packet_evidence_verified"
    assert (report["packet_count"], report["finding_count"]) == (1, 2)
    assert report["packets"] == [{
        "packet_id": "RCP-" + "a" * 24, "packet_evidence_sha256": "sha256:" + packet_hash,
        "members": [{"finding_id": f"FG-{letter}", **dict.fromkeys(
                        ("evidence_sha256", "observed_review_sha256", "observed_content_sha256"),
                        "sha256:" + _sha(f"Fabricated receipt {letter}\n"))}
                    for letter in ("A", "B")],
    }]
    assert "dispositions" not in report and "scan_complete" not in report


@pytest.mark.parametrize(("change", "reason"), [
    ("pin", "pinned SHA-256"),
    ("scope", "scope and members"),
    ("member-order", "ordered, unique finding list"),
    ("traversal", "relative slash-separated path"),
    ("bytes", "bytes do not match"),
    ("symlink", "A.md"),
    ("count", "inconsistent findingCount"),
    ("empty", "requires a nonempty packet list"),
    ("overflow", "not strict UTF-8 JSON"),
])
def test_refuses_corrupted_saved_queue(tmp_path, capsys, change, reason):
    args, _ = _queue(tmp_path, change)
    assert main(args) == 2
    capture = capsys.readouterr()
    assert capture.out == "" and reason in capture.err


@pytest.mark.parametrize(("change", "message"), [
    ("valid", None),
    ("stale", "inconsistent fromEvidenceHash"),
    ("wrong-mode", "severity promotion requires"),
    ("wrong-order", "restoration must precede"),
    ("wrong-identity", "inconsistent evidenceHash"),
    ("duplicate-group", "duplicate review-group members"),
    ("two-steps", None),
])
def test_rewritten_evidence_requires_the_pinned_native_transition(tmp_path, capsys, change, message):
    multiple = change in ("wrong-order", "two-steps")
    args, packet_hash = _queue(tmp_path, "promotion" if multiple or change == "wrong-mode" else None)
    root = tmp_path / ".fieldglass"
    previous = _sha("Fabricated receipt A\n")
    current = "Updated receipt A\n"
    (root / "findings/A.md").write_text(current, encoding="utf-8")
    assert main(args) == 2
    assert "pinned transition" in capsys.readouterr().err
    hashes = [previous, _sha("Fabricated receipt B\n")]
    mode = "strict" if multiple else "identity"
    transitions = [{"findingId": "FG-A", "version": 1,
                    "kind": "confirmed-severity-promotion" if change in ("wrong-mode", "wrong-order")
                    else "confirmed-pending-restoration",
                    "fromEvidenceHash": "f" * 64 if change == "stale" else previous,
                    "toEvidenceHash": _sha("Intermediate receipt\n") if multiple else _sha(current)}]
    if multiple:
        transitions.append({"findingId": "FG-A", "version": 1,
                            "kind": "confirmed-pending-restoration" if change == "wrong-order"
                            else "confirmed-severity-promotion",
                            "fromEvidenceHash": transitions[0]["toEvidenceHash"], "toEvidenceHash": _sha(current)})
    group = {
        "primaryReviewPacketId": "RCP-" + "a" * 24, "primaryReviewPacketEvidenceHash": packet_hash,
        "assuranceMode": mode, "finalDisposition": "confirmed", "verdict": "CONFIRMED VULNERABLE",
        "challengerSucceeded": True,
        "findingIds": ["FG-A", "FG-B"],
        "findingIdentities": [{"id": f"FG-{letter}", "rootCauseFingerprint": "fixture",
                               "rootCauseEvidenceHash": "a" * 64, "evidenceHash": digest}
                              for letter, digest in zip(("A", "B"), hashes, strict=True)],
        "evidenceHashes": hashes, "evidenceTransitions": transitions,
    }
    if change == "wrong-identity":
        group["findingIdentities"][0]["evidenceHash"] = hashes[1]
    summary = {"version": 6, "complete": True, "assuranceMode": mode, "capturedFindingIds": ["FG-A", "FG-B"],
               "groups": [group, {"findingIds": ["FG-A"]}] if change == "duplicate-group" else [group]}
    payload = json.dumps(summary) + "\n"
    (root / "verification-summary.json").write_text(payload, encoding="utf-8")
    result = main([*args, "--verification-sha256", "sha256:" + _sha(payload)])
    captured = capsys.readouterr()
    if message:
        assert result == 2 and message in captured.err
    else:
        assert result == 0
        report = json.loads(captured.out)
        assert report["evidence_transition_count"] == len(transitions)
        assert report["packets"][0]["members"][0]["observed_review_sha256"] == "sha256:" + _sha(current)
