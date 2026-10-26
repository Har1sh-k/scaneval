"""Verify saved controller-side identity evidence without trusting a summary scalar.

The source inspection is the exporter's saved observation bound to the executed tree. A
standalone invocation bundle has no source tree to reinspect; this limitation is reported.
The saved configured pack/map permit independent policy, population, and structural rechecks.
"""

from pathlib import Path

from . import blinding, cases, identity_policy
from .conditions import _bytes, _digest, _json, _reason
from .contracts import ContractError, canonical_sha256, validate_document
from .materialize import MaterializationError


def verify_saved_identity(bundle: Path, execution: dict, provenance: dict, evidence: dict,
                          artifacts: list[dict]) -> dict:
    details = {"source_inspection": "recorded_export_inspection",
               "standalone_source_reinspection": "unavailable_from_bundle",
               "expected_requirements": "recomputed_from_saved_configured_pack"}

    def unavailable(code: str, message: str) -> dict:
        return {"state": "unavailable", "details": details, "reasons": [_reason(code, message)]}

    def load(role: str, expected_path: str) -> dict:
        reference = evidence[role]
        if not isinstance(reference, dict) or reference.get("path") != expected_path:
            raise ContractError(f"{role} must name its controller-owned evaluator artifact")
        raw = _bytes(bundle, expected_path)
        actual = _digest(raw)
        artifacts.append({"role": role, "path": expected_path, "sha256": actual})
        value = _json(raw)
        if actual != reference.get("sha256") or canonical_sha256(value) != reference.get("canonical_sha256"):
            raise ContractError(f"{role} does not bind to its saved bytes and canonical document")
        details[role] = dict(reference)
        return value

    if execution["provenance"]["profile"] != "identity_reduced":
        return unavailable("identity_profile_unavailable", "A metadata-blinded or standard profile is not the strict identity-reduced condition.")
    source_record = provenance.get("head", provenance) if execution["provenance"].get("mode") == "pr" else provenance
    if not isinstance(source_record, dict) or not isinstance(source_record.get("identity_reduction"), dict):
        return unavailable("identity_summary_unavailable", "No saved strict identity transformation summary is available.")
    summary = source_record["identity_reduction"]
    details["summary"] = summary
    if not evidence.get("identity_manifest") or not evidence.get("identity_context"):
        return unavailable("identity_evidence_unavailable", "Strict identity validation requires the saved manifest and configured pack/map context.")
    try:
        manifest = load("identity_manifest", "evaluator/identity-transform.json")
        context = load("identity_context", "evaluator/identity-context.json")
        if set(context) != {"schema_version", "pack", "map", "snapshot_id"} or context["schema_version"] != "2.1":
            raise ContractError("identity context has an unsupported shape or version")
        pack, mapping, snapshot_id = context["pack"], context["map"], context["snapshot_id"]
        validate_document("case-pack", pack)
        validate_document("blinding-map", mapping)
        gap = blinding.approval_gap(mapping)
        if gap:
            raise ContractError(gap)
        snapshot = cases.snapshot_by_id(pack, snapshot_id)
        recorded_source = source_record.get("source") or {}
        if (snapshot["commit"] != recorded_source.get("commit")
                or snapshot["repository"]["url"] != recorded_source.get("url")):
            raise ContractError("identity context names a different source snapshot than the executed provenance")
        original = (source_record.get("original") or {}).get("tree_hash")
        transformed = execution["provenance"]["tree_hash"]
        binding = execution["provenance"].get("blinding") or {}
        map_digest = blinding.map_sha256(mapping)
        if (binding.get("map_sha256") != map_digest or binding.get("original_tree_hash") != original
                or binding.get("transformed_tree_hash") != transformed
                or (source_record.get("trial") or {}).get("tree_hash") != transformed
                or (snapshot.get("tree_hash") is not None and snapshot["tree_hash"] != original)):
            raise ContractError("identity map and original/transformed trees do not bind to the executed input")
        variant = next((row for row in mapping["variants"] if row["snapshot_id"] == snapshot_id), None)
        if variant is None or (variant["commit"], variant["tree_hash"]) != (snapshot["commit"], original):
            raise ContractError("identity map variant is not bound to the configured source snapshot")
        policy = mapping.get("identity_policy")
        if policy is None:
            return unavailable("identity_policy_unavailable", "A reviewed removal map without a verified strict identity policy cannot attest the named condition.")
        requirements, paths = identity_policy.snapshot_requirements(pack, snapshot_id)
        identity_policy.verify_manifest(
            manifest, summary, policy=policy, map_sha256=map_digest,
            original_tree_hash=original, transformed_tree_hash=transformed,
            requirements=requirements, required_source_paths=paths,
            source_snapshot={"snapshot_id": snapshot_id, **{key: recorded_source[key] for key in ("url", "commit", "git_tree")}})
        details.update({"configured_pack_sha256": canonical_sha256(pack), "map_sha256": map_digest,
                        "requirements_sha256": canonical_sha256(requirements), "transformation_verified": True})
        if summary["validation"]["state"] != "available":
            return unavailable("identity_validation_unavailable", "The saved transformation did not establish strict policy availability.")
        if execution["provenance"].get("mode", "full") != "full":
            return unavailable("identity_full_scan_required", "A PR transformation can be valid but is outside the named full-scan identity condition.")
        return {"state": "available", "details": details, "reasons": []}
    except (ContractError, MaterializationError, KeyError, TypeError, AttributeError) as exc:
        return {"state": "failed", "details": details,
                "reasons": [_reason("identity_evidence_mismatch", str(exc).replace(str(bundle), "<bundle>"))]}
