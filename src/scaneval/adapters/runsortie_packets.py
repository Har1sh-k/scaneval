"""Verify a pinned, saved RunSortie v2 review queue and its member bytes."""

from __future__ import annotations

from pathlib import Path

from . import runsortie as rs
from . import runsortie_evidence as ev
from .base import AdapterError
from .runsortie_saved import _expect, _json_record, _object


_MANIFEST = "primary-review-packets.json"
_SUMMARY = "verification-summary.json"
_MAX_ARTIFACT_BYTES = 256 * 1024
_GROUPINGS = ("isolated", "exact-root-cause", "review-equivalence", "explicit-structural-relationship")
_SELECTION_REASONS = {
    "configured-severity", "evidence-complete-severity-boundary", "unresolved-reachability-severity-boundary",
    "incremental-model-validation", "lifecycle-verification",
}
_TRANSITION_KINDS = {"confirmed-severity-promotion", "confirmed-pending-restoration"}


def _relative_path(value: object, label: str) -> list[str]:
    if not isinstance(value, str) or "\\" in value or "\0" in value:
        raise AdapterError(f"{label} must use a relative slash-separated path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise AdapterError(f"{label} must use a relative slash-separated path")
    return parts


def _required_text(record: dict, field: str, label: str) -> str:
    value = record.get(field)
    if not ev._text(value) or "\0" in value or ev._js_trim(value) != value:
        raise AdapterError(f"{label} lacks a valid {field}")
    return value


def _digest(record: dict, field: str, label: str) -> str:
    value = _required_text(record, field, label)
    if not ev.HEX64.fullmatch(value):
        raise AdapterError(f"{label} lacks a lowercase SHA-256 {field}")
    return value


def _member_binding(member: dict, finding_id: str, path: str, member_digest: str, grouping: str) -> str:
    """Match the v2 writer's packet-evidence preimage for one member."""
    version = member.get("reviewEquivalenceVersion")
    equivalence = member.get("reviewEquivalenceEvidence", [])
    fields = ("reviewEquivalenceFingerprint", "reviewEquivalenceEvidenceHash", "reviewEquivalenceEvidence")
    if version is None:
        if "reviewEquivalenceVersion" in member or any(field in member for field in fields):
            raise AdapterError("review equivalence fields require their native version")
        fingerprint, equivalence_digest = "", ""
    else:
        if type(version) is not int or version not in (1, 2, 3, 4) or not isinstance(equivalence, list) or not all(
                isinstance(entry, str) and "\0" not in entry for entry in equivalence):
            raise AdapterError("review equivalence fields are malformed")
        fingerprint = _required_text(member, fields[0], "review equivalence")
        equivalence_digest = _digest(member, fields[1], "review equivalence")
        if (fingerprint != equivalence_digest[:24] or equivalence != ev._js_sorted(equivalence)
                or not equivalence or ev._sha("\n".join(equivalence)) != equivalence_digest):
            raise AdapterError("review equivalence evidence does not match its native digest")
    severity = _required_text(member, "reviewClaimSeverity", "packet member")
    reason = _required_text(member, "reviewSelectionReason", "packet member")
    if severity not in ev.REVIEW_SEVERITY_ORDER or reason not in _SELECTION_REASONS:
        raise AdapterError("packet member has an unsupported claim severity or selection reason")
    root, root_digest = member.get("rootCauseFingerprint"), member.get("rootCauseEvidenceHash")
    # The producer encodes legacy-ambiguous identity as two empty strings.
    if (root, root_digest) != ("", "") or grouping != "isolated":
        root = _required_text(member, "rootCauseFingerprint", "packet member")
        root_digest = _required_text(member, "rootCauseEvidenceHash", "packet member")
        if not ev.HEX64.fullmatch(root_digest.lower()):
            raise AdapterError("packet member lacks its root-cause evidence digest")
    return "\0".join((
        finding_id, severity, reason, root, root_digest,
        "no-review-equivalence" if version is None else str(version),
        fingerprint, equivalence_digest, *equivalence, member_digest, path,
        ev._js_json(member.get("targetPolicyClassification")),
    ))


def _review_digest(payload: bytes) -> str:
    # reviewEvidenceHash excludes only the two volatile top-level frontmatter lines.
    text = payload.decode("utf-8")
    boundary = text.find("\n---\n", 4) if text.startswith("---\n") else -1
    if boundary < 0:
        return ev._sha(payload)
    stable = "\n".join(line for line in text[:boundary].split("\n")
                        if not line.startswith(("created_at:", "updated_at:")))
    return ev._sha(stable + text[boundary:])


def _pinned(data: bytes, digest: str, label: str) -> None:
    if not digest.startswith("sha256:") or not ev.HEX64.fullmatch(digest[7:]):
        raise AdapterError(f"the expected {label} digest must be sha256: followed by 64 lowercase hex digits")
    if "sha256:" + ev._sha(data) != digest:
        raise AdapterError(f"the saved {label} does not match its pinned SHA-256")


def _transitions(summary: dict, originals: dict, packets: dict) -> tuple[dict, int]:
    _expect(summary, {"version": 6}, "verification summary")
    captured = ev._ids(summary.get("capturedFindingIds"))
    groups = summary.get("groups")
    if captured is None or set(captured) != set(originals) or not isinstance(groups, list):
        raise AdapterError("verification summary membership differs from the review queue")
    bindings = {}
    owners = set()
    count = 0
    for value in groups:
        group = _object(value, "review group")
        ids = ev._ids(group.get("findingIds"))
        if not ids or not set(ids) <= originals.keys() or owners.intersection(ids):
            raise AdapterError("the summary has unknown or duplicate review-group members")
        owners.update(ids)
        if "evidenceTransitions" not in group:
            continue
        _expect(summary, {"complete": True}, "verification summary")
        packet_id = _required_text(group, "primaryReviewPacketId", "review group")
        if packet_id not in packets:
            raise AdapterError("evidence transitions refer to an unknown review packet")
        digest, packet_members = packets[packet_id]
        _expect(group, {"primaryReviewPacketEvidenceHash": digest, "finalDisposition": "confirmed",
                        "verdict": "CONFIRMED VULNERABLE"}, "review group")
        if (group.get("challengerSucceeded") is not True and group.get("challengerReused") is not True
                and group.get("resolutionSource") != "single-reviewer"):
            raise AdapterError("the review group lacks the native authorization for evidence transitions")
        transitions = group["evidenceTransitions"]
        if not set(ids) <= packet_members or not isinstance(transitions, list) or not transitions:
            raise AdapterError("evidence transitions lack their native review membership")
        hashes = group.get("evidenceHashes")
        if (not isinstance(hashes, list) or not all(isinstance(item, str) for item in hashes)
                or sorted(hashes) != sorted(originals[finding]["evidenceHash"] for finding in ids)):
            raise AdapterError("review group evidence digests differ from the packet")
        identities = group.get("findingIdentities")
        if not isinstance(identities, list) or len(identities) != len(ids):
            raise AdapterError("the review group lacks its native finding identities")
        identity_ids = set()
        for value in identities:
            identity = _object(value, "review group finding identity")
            finding = _required_text(identity, "id", "review group finding identity")
            if finding not in ids or finding in identity_ids:
                raise AdapterError("the review group has unknown or duplicate finding identities")
            identity_ids.add(finding)
            _expect(identity, {key: originals[finding][key] for key in
                               ("evidenceHash", "rootCauseFingerprint", "rootCauseEvidenceHash")},
                    "review group finding identity")
        by_id: dict[str, list[dict]] = {}
        for raw_transition in transitions:
            transition = _object(raw_transition, "evidence transition")
            finding = _required_text(transition, "findingId", "evidence transition")
            if finding not in ids or finding in bindings:
                raise AdapterError("evidence transition refers to an unknown or previously bound finding")
            by_id.setdefault(finding, []).append(transition)
        for finding, steps in by_id.items():
            original = originals[finding]
            current = original["evidenceHash"]
            kinds = set()
            for step in steps:
                kind = _required_text(step, "kind", "evidence transition")
                following = _digest(step, "toEvidenceHash", "evidence transition")
                _expect(step, {"version": 1, "fromEvidenceHash": current}, "evidence transition")
                if kind not in _TRANSITION_KINDS or kind in kinds or following == current:
                    raise AdapterError("evidence transition is duplicate, unrecognized, or changes no evidence")
                if kind == "confirmed-severity-promotion" and (
                        summary.get("assuranceMode") != "strict" or group.get("assuranceMode") != "strict"
                        or original["severity"] != "medium" or original["reviewClaimSeverity"] != "high"):
                    raise AdapterError("severity promotion requires a medium finding bound to a strict high claim")
                if kind == "confirmed-pending-restoration" and "confirmed-severity-promotion" in kinds:
                    raise AdapterError("a restoration must precede severity promotion")
                kinds.add(kind)
                current = following
                count += 1
            bindings[finding] = current
    return bindings, count


def verify_saved_queue(manifest: Path, *, expected_sha256: str,
                       verification_sha256: str | None = None) -> dict:
    """Check a pinned queue's inventory and evidence bindings without running a reviewer."""
    manifest = Path(manifest)
    if manifest.name != _MANIFEST or manifest.parent.name != ".fieldglass":
        raise AdapterError(f"the manifest path must end with .fieldglass/{_MANIFEST}")
    root = manifest.parent
    deadline = rs.Deadline(30)
    guard = rs._capture_root(root)
    data = rs._read_relative_regular(root, guard, manifest.name, _MAX_ARTIFACT_BYTES, deadline)
    _pinned(data, expected_sha256, "packet manifest")
    plan = _json_record(data, "saved packet manifest")
    packets = plan.get("packets")
    _expect(plan, {"version": 2}, "saved packet manifest")
    if not isinstance(packets, list) or not packets or not isinstance(plan.get("rejectedRelationships"), list):
        raise AdapterError("the v2 packet manifest requires a nonempty packet list and a rejected relationship list")
    _expect(plan, {"packetCount": len(packets)}, "saved packet manifest")
    policy = plan.get("targetSecurityPolicy")
    manifest_has_policy = "targetSecurityPolicy" in plan
    policy_digest = (_digest(_object(policy, "target security policy"), "evidenceHash", "target security policy")
                     if manifest_has_policy else "no-target-security-policy")
    packet_ids = set()
    originals = {}
    packet_bindings = {}
    paths = set()
    evidence_bytes = 0
    verified_packets = []
    for raw_packet in packets:
        deadline.check()
        packet = _object(raw_packet, "review packet")
        _expect(packet, {"version": 2}, "review packet")
        packet_id = _required_text(packet, "packetId", "review packet")
        if not ev.PACKET_ID.fullmatch(packet_id) or packet_id in packet_ids:
            raise AdapterError("the manifest has an invalid or duplicate packet id")
        packet_ids.add(packet_id)
        if packet.get("grouping") not in _GROUPINGS or ("targetSecurityPolicy" in packet) != manifest_has_policy:
            raise AdapterError("the review packet has an invalid grouping or policy binding")
        if manifest_has_policy:
            _expect(packet, {"targetSecurityPolicy": policy}, "review packet")
        scope = _object(packet.get("reviewScope"), "review scope")
        if set(scope) != {"version", "paths", "maxAdditionalPaths", "expansion"}:
            raise AdapterError("the review scope has missing or unknown fields")
        _expect(scope, {"version": 1, "maxAdditionalPaths": 6, "expansion": "direct-callers-or-callees"},
                "review scope")
        scope_paths = ev._ids(scope.get("paths"))
        if scope_paths is None or scope_paths != ev._js_sorted(scope_paths):
            raise AdapterError("the review scope lacks a sorted, unique path list")
        for path in scope_paths:
            _relative_path(path, "review scope path")

        ids = ev._ids(packet.get("memberFindingIds"))
        members = packet.get("members")
        if (not ids or not isinstance(members, list) or len(members) != len(ids)
                or packet.get("canonicalFindingId") not in ids
                or (packet["grouping"] == "isolated") != (len(ids) == 1)):
            raise AdapterError("the review packet has inconsistent finding membership")
        verified = []
        bindings = []
        severities = []
        for raw_member, expected_id in zip(members, ids, strict=True):
            member = _object(raw_member, "packet member")
            finding_id = _required_text(member, "findingId", "packet member")
            if finding_id != expected_id or finding_id in originals:
                raise AdapterError("member ids do not match the ordered, unique finding list")
            path = _required_text(member, "evidencePath", "packet member")
            parts = _relative_path(path, "member evidence path")
            if len(parts) < 3 or parts[:2] != [".fieldglass", "findings"] or path in paths:
                raise AdapterError("member evidence must have a unique path under .fieldglass/findings")
            paths.add(path)
            payload = rs._read_relative_regular(root, guard, "/".join(parts[1:]), _MAX_ARTIFACT_BYTES, deadline)
            evidence_bytes += len(payload)
            if evidence_bytes > rs.MAX_STATE_TOTAL_BYTES:
                raise AdapterError("member evidence exceeds the queue byte limit")
            member_digest = _digest(member, "evidenceHash", "packet member")
            if member.get("severity") not in ev.REVIEW_SEVERITY_ORDER:
                raise AdapterError("packet member has an unsupported finding severity")
            originals[finding_id] = member
            bindings.append(_member_binding(member, finding_id, path, member_digest, packet["grouping"]))
            severities.append(member["reviewClaimSeverity"])
            verified.append({"finding_id": finding_id, "evidence_sha256": "sha256:" + member_digest,
                             "observed_review_sha256": "sha256:" + _review_digest(payload),
                             "observed_content_sha256": "sha256:" + ev._sha(payload)})
        _expect(packet, {"reviewClaimSeverity": max(severities, key=ev.REVIEW_SEVERITY_ORDER.index)},
                "review packet")
        expected = ev._sha("\n".join((policy_digest, ev._js_json(scope), *ev._js_sorted(bindings))))
        if _digest(packet, "packetEvidenceHash", "review packet") != expected:
            raise AdapterError("the native packet evidence digest does not match the scope and members")
        packet_bindings[packet_id] = (expected, set(ids))
        verified_packets.append({"packet_id": packet_id, "packet_evidence_sha256": "sha256:" + expected,
                                 "members": verified})
    _expect(plan, {"findingCount": len(originals)}, "saved packet manifest")
    transitions, transition_count = {}, 0
    if verification_sha256 is not None:
        raw = rs._read_relative_regular(root, guard, _SUMMARY, _MAX_ARTIFACT_BYTES, deadline)
        _pinned(raw, verification_sha256, "verification summary")
        transitions, transition_count = _transitions(_json_record(raw, "verification summary"), originals, packet_bindings)
    for packet in verified_packets:
        for member in packet["members"]:
            finding = member["finding_id"]
            expected = "sha256:" + transitions.get(finding, originals[finding]["evidenceHash"])
            if member["observed_review_sha256"] != expected:
                raise AdapterError("member evidence bytes do not match the saved finding digest or pinned transition")
    return {"status": "packet_evidence_verified", "manifest_sha256": expected_sha256,
            "verification_summary_sha256": verification_sha256, "evidence_transition_count": transition_count,
            "packet_schema_version": 2, "finding_count": len(originals), "packet_count": len(packets),
            "packets": verified_packets}
