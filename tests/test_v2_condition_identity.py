"""Strict condition attestation rechecks saved policy evidence outside every scanner input."""

from copy import deepcopy
import hashlib
import json
import shutil

import pytest

import test_v2_blinding as fixture
from test_v2_identity_exports import strict_map
from test_v2_conditions import Enforced, Offline
from scaneval import blinding, conditions, isolation
from scaneval.contracts import ContractError, canonical_json, canonical_sha256, load_document
from scaneval.execution import PreparedInput, build_request
from scaneval.adapters.base import SystemSpec
from scaneval.runner import run_from_config


@pytest.fixture
def prepared_source(tmp_path):
    return fixture.build_widget(tmp_path, fixture.FILES)


def run_identity(tmp_path, prepared_source, monkeypatch, *, mapping=None, held=True, pr=False, explicit=True):
    mapping = strict_map(prepared_source) if mapping is None else mapping
    pack = (fixture.write_pr_pack if pr else fixture.write_pack)(tmp_path / "pack.json", prepared_source)
    original_pack = deepcopy(pack)
    blinding.save_map(tmp_path / "map.json", mapping)
    entry = {**(fixture.BLINDED_PR if pr else fixture.IDENTITY_REDUCED), "profile": "identity_reduced", "blinding_map": "map.json"}
    if explicit:
        entry["condition"] = {"name": "identity_reduced", "policy": {}}
    config = fixture.write_config(tmp_path / "run.json", [entry])
    config["systems"][0]["execution"] = ({"backend": "oci", "image": "fixture@sha256:" + "a" * 64}
                                                 if held else {"backend": "local"})
    (tmp_path / "run.json").write_text(canonical_json(config))

    class RecordedBackend(Enforced):
        workspace_root = None
        def close(self):
            return []

    base = fixture.InspectingPrAdapter if pr else fixture.IdentityInspectingAdapter
    class ControlledAdapter(base):
        oci_compatible = True
        disabled_tools = True
        condition_controls = Offline.condition_controls
        def scan(self, *, request, source_dir, raw_dir, **kwargs):
            private_names = {"identity-context.json", "identity-transform.json", "pack.json", "map.json"}
            assert not any(path.name in private_names for path in source_dir.parent.rglob("*"))
            assert not {"identity_context", "identity_manifest", "pack", "map"} & set(request)
            return super().scan(request=request, source_dir=source_dir, raw_dir=raw_dir, **kwargs)
    monkeypatch.setattr(isolation, "backend_for", lambda settings, **kwargs: RecordedBackend(settings.network_policy))
    adapter = ControlledAdapter()
    output = tmp_path / "out"
    manifest = run_from_config(tmp_path / "run.json", output, adapters={"fake": adapter}, clock=fixture.CLOCK)
    row = manifest["invocations"][0]
    bundle = output / row["bundle_path"]
    return bundle, conditions.classify_observation(bundle), original_pack, adapter


def codes(record):
    return {item["code"] for item in record["reasons"]}


def test_verified_context_and_manifest_attest_with_closed_controls(tmp_path, prepared_source, monkeypatch):
    bundle, record, original_pack, adapter = run_identity(tmp_path, prepared_source, monkeypatch)
    assert adapter.calls == 1
    assert record["condition"] == record["identity_profile"] == "identity_reduced"
    assert record["status"] == "attested" and record["network"] == "enforced"
    assert record["assurance"]["identity"] == "saved_manifest_verified"
    details = record["details"]["identity_reduction"]
    assert details["transformation_verified"] is True
    assert details["standalone_source_reinspection"] == "unavailable_from_bundle"
    assert {"identity_context", "identity_manifest"} <= {item["role"] for item in record["artifacts"]}
    context = json.loads((bundle / "evaluator" / "identity-context.json").read_text())
    assert context["pack"] == original_pack
    runtime_pack = load_document(bundle.parent.parent / "evaluator" / "pack.json", "case-pack")
    assert canonical_json(runtime_pack) != canonical_json(context["pack"]), "fresh mechanical checks must not replace configured-pack expectations"
    execution = load_document(bundle / "execution.json", "execution-record")
    provenance = json.loads((bundle / conditions.PROVENANCE_FILE).read_text())
    assert execution["provenance"]["provenance_sha256"] == canonical_sha256(provenance)
    assert details["summary"] == provenance["identity_reduction"]


def test_identity_policy_does_not_attest_an_unenforced_network(tmp_path, prepared_source, monkeypatch):
    _bundle, record, _pack, _adapter = run_identity(tmp_path, prepared_source, monkeypatch, held=False)
    assert record["status"] == "declared_only" and record["network"] == "unenforced"
    assert record["assurance"]["identity"] == "saved_manifest_verified"


def test_strict_identity_bundle_remains_classifiable_after_relocation(tmp_path, prepared_source, monkeypatch):
    bundle, record, _pack, _adapter = run_identity(tmp_path, prepared_source, monkeypatch)
    relocated = tmp_path / "copied-bundle"
    shutil.copytree(bundle, relocated)
    copied = conditions.classify_observation(relocated)
    assert copied["status"] == "attested"
    assert conditions.record_identity(copied) == conditions.record_identity(record)


def test_named_identity_with_legacy_removal_map_is_unavailable(tmp_path, prepared_source, monkeypatch):
    _bundle, record, _pack, _adapter = run_identity(tmp_path, prepared_source, monkeypatch,
                                                 mapping=fixture.identity_reduced_map(prepared_source))
    assert record["status"] == "unavailable" and "identity_policy_unavailable" in codes(record)


def test_missing_saved_context_cannot_attest_from_profile_or_summary(tmp_path, prepared_source, monkeypatch):
    bundle, _record, _pack, _adapter = run_identity(tmp_path, prepared_source, monkeypatch)
    (bundle / conditions.RECORD_FILE).unlink()
    evidence_path = bundle / conditions.EVIDENCE_FILE
    evidence = json.loads(evidence_path.read_text())
    evidence.pop("identity_context")
    evidence_path.write_text(canonical_json(evidence))
    record = conditions.classify_observation(bundle)
    assert record["status"] == "unavailable" and "identity_evidence_unavailable" in codes(record)


@pytest.mark.parametrize("artifact", ["identity-context.json", "identity-transform.json"])
def test_identity_artifacts_follow_regular_file_and_hash_rules(tmp_path, prepared_source, monkeypatch, artifact):
    bundle, _record, _pack, _adapter = run_identity(tmp_path, prepared_source, monkeypatch)
    (bundle / conditions.RECORD_FILE).unlink()
    path = bundle / "evaluator" / artifact
    saved = path.with_suffix(".saved")
    path.rename(saved)
    path.symlink_to(saved)
    record = conditions.classify_observation(bundle)
    assert record["status"] == "failed" and "identity_evidence_mismatch" in codes(record)


def rewrite_reference(bundle, role, value):
    path = bundle / "evaluator" / ("identity-context.json" if role == "identity_context" else "identity-transform.json")
    raw = (canonical_json(value) + "\n").encode()
    path.write_bytes(raw)
    evidence_path = bundle / conditions.EVIDENCE_FILE
    evidence = json.loads(evidence_path.read_text())
    evidence[role].update({"sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "canonical_sha256": canonical_sha256(value)})
    evidence_path.write_text(canonical_json(evidence))


def test_rehashed_context_still_must_match_executed_map(tmp_path, prepared_source, monkeypatch):
    bundle, _record, _pack, _adapter = run_identity(tmp_path, prepared_source, monkeypatch)
    (bundle / conditions.RECORD_FILE).unlink()
    context = json.loads((bundle / "evaluator" / "identity-context.json").read_text())
    context["map"]["identity_policy"]["identity_tokens"].append("different-token")
    fixture.reapproved(context["map"])
    rewrite_reference(bundle, "identity_context", context)
    record = conditions.classify_observation(bundle)
    assert record["status"] == "failed" and "identity_evidence_mismatch" in codes(record)


def test_rehashed_available_scalar_cannot_hide_structural_blockers(tmp_path, prepared_source, monkeypatch):
    bundle, _record, _pack, _adapter = run_identity(tmp_path, prepared_source, monkeypatch)
    (bundle / conditions.RECORD_FILE).unlink()
    manifest = json.loads((bundle / "evaluator" / "identity-transform.json").read_text())
    manifest["unsafe_entries"].append({"path": "unsafe", "reason": "symbolic link"})
    rewrite_reference(bundle, "identity_manifest", manifest)
    provenance_path = bundle / conditions.PROVENANCE_FILE
    provenance = json.loads(provenance_path.read_text())
    provenance["identity_reduction"]["manifest_sha256"] = canonical_sha256(manifest)
    provenance_path.write_text(canonical_json(provenance))
    execution_path = bundle / "execution.json"
    execution = json.loads(execution_path.read_text())
    execution["provenance"]["provenance_sha256"] = canonical_sha256(provenance)
    execution_path.write_text(canonical_json(execution))
    record = conditions.classify_observation(bundle)
    assert record["status"] == "failed" and "identity_evidence_mismatch" in codes(record)


def test_valid_pr_transformation_is_outside_named_full_scan_condition(tmp_path, prepared_source, monkeypatch):
    _bundle, record, _pack, _adapter = run_identity(tmp_path, prepared_source, monkeypatch, pr=True, explicit=False)
    assert record["status"] == "unavailable" and "identity_full_scan_required" in codes(record)
    assert record["details"]["identity_reduction"]["transformation_verified"] is True


def test_explicit_pr_identity_condition_is_refused_before_output(tmp_path, prepared_source, monkeypatch):
    with pytest.raises(ContractError, match="named identity_reduced condition"):
        run_identity(tmp_path, prepared_source, monkeypatch, pr=True)
    assert not (tmp_path / "out").exists()


def test_private_identity_data_cannot_enter_scan_request(tmp_path):
    prepared = PreparedInput("input", tmp_path, "sha256:" + "a" * 64, ("python",), {},
                             identity_manifest={"private_manifest": "PRIVATE-ANSWER"},
                             identity_context={"pack": {"private_alias": "PRIVATE-ANSWER"}, "map": {"secret": True}})
    request = build_request("run", prepared, SystemSpec("scanner", "fake"), timeout_seconds=5, trace_mode="off")
    assert "PRIVATE-ANSWER" not in canonical_json(request)
    assert "identity_context" not in request and "identity_manifest" not in request
