"""Create a fabricated, diagnostic three-condition Semgrep experiment for operator review.

No scanner runs and no approval is fabricated. Inspect the generated map, record your own
review, then use matrix freeze/run/report as shown in docs/EXPERIMENT_MATRIX.md.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from open_context_fixture import create as create_open_fixture, commit, SEMGREP_IMAGE
from scaneval import blinding, cases, experiment, materialize
from scaneval.contracts import canonical_json, pack_anchor_digest


def create(root: Path) -> Path:
    config_path = create_open_fixture(root)
    root = config_path.parent
    config = json.loads(config_path.read_text())
    pack = cases.load_pack(root / "pack.json")
    source = root / "upstream"
    (source / "README.md").write_text("AcmeCorp fabricated integration fixture; no real vulnerability advisory.\n")
    head = commit(source, "Fixture identity documentation")
    snapshot = pack["snapshots"][0]
    snapshot["commit"] = head
    snapshot["repository"]["name"] = "AcmeCorp"
    pack["cases"][0]["represents"] = (
        "This case tests a fabricated subprocess sink under caller-controlled input, and adds "
        "a diagnostic single-file fixture for evaluation-condition plumbing.")
    pack["anchor_sha256"] = pack_anchor_digest(pack)
    cached = materialize.fetch_snapshot(str(source), head, root / "cache")
    probe = root / "probe"
    exported = materialize.export_snapshot(cached, probe)
    digest = exported["trial"]["tree_hash"]
    cases.mechanical_checks(pack, "fixture", probe / "source", digest)
    cases.save_pack(root / "pack.json", pack)
    readme_hash = materialize.sha256_file(probe / "source/README.md")[0]
    mapping = {"schema_version": "2.1", "map_id": "fixture-identity", "map_version": "1",
        "repository": snapshot["repository"], "pseudonyms": [{"original": "AcmeCorp", "replacement": "Neutral"}],
        "variants": [{"snapshot_id": "fixture", "commit": head, "tree_hash": digest}], "edits": [],
        "removals": [{"removal_id": "readme", "path": "README.md", "role": "identity_document",
            "rationale": "Fixture branding only; no executable, build, security, or scoring logic.",
            "expected": [{"snapshot_id": "fixture", "state": "present", "file_sha256": readme_hash}]}],
        "identity_policy": {"policy_id": "scaneval.identity-reduced", "version": "1", "answer_aliases": [],
            "identity_tokens": ["AcmeCorp"], "instruction_paths": [], "forbidden_artifacts": []}, "reviews": []}
    blinding.save_map(root / "map.json", mapping)
    open_policy = config["inputs"][0]["condition"]["policy"]
    open_execution = config["systems"][0]["execution"]
    matrix = {"schema_version": "2.1", "stage": "declared", "experiment_id": "diagnostic-matrix",
        "experiment_version": "1", "evidence_scope": "diagnostic", "pack": "pack.json",
        "population": {"snapshot_ids": ["fixture"], "canonical_target_ids": [cases.target_canonical_id(pack["cases"][0])],
            "canonical_control_ids": [], "source_property": "Fabricated caller-controlled subprocess shell invocation."},
        "systems": [{"system_id": "semgrep", "adapter": "semgrep", "inference": "offline",
            "config": config["systems"][0]["config"], "execution": {"backend": "oci", "image": SEMGREP_IMAGE}}],
        "conditions": [
            {"name": "open_context", "profile": "standard", "history": "bounded_ancestor", "retrieval": "recorded_public",
             "identity": "preserved", "policy": open_policy, "system_context": {"semgrep": {
                 "network_policy": "public_research", "execution": {key: open_execution[key] for key in
                     ("proxy_image", "egress", "retrieval")}}}},
            {"name": "closed_book_standard", "profile": "standard", "history": "none", "retrieval": "disabled",
             "identity": "preserved", "policy": {}, "system_context": {"semgrep": {"network_policy": "none"}}},
            {"name": "identity_reduced", "profile": "identity_reduced", "history": "none", "retrieval": "disabled",
             "identity": "reduced", "policy": {}, "system_context": {"semgrep": {"network_policy": "none"}},
             "transformation_maps": {"fixture": "map.json"}}],
        "repetitions": 1, "timeout_seconds": 120, "trace_mode": "metadata", "run_order": {"method": "fixed", "cells": list(experiment.NAMES)},
        "required_capture": {"open_context": ["external_isolation", "history", "retrieval_events"],
            "closed_book_standard": ["external_isolation", "history", "tool_controls"],
            "identity_reduced": ["external_isolation", "history", "tool_controls", "identity_manifest"]},
        "allowed_differences": sorted(experiment.CONTEXT_DIFFERENCES), "exclusions": [], "missingness": "report_unavailable",
        "adjudication": {"policy_id": "diagnostic-structured-review", "version": "1", "matching": "exact_structured_v2"},
        "aggregation_policy": experiment.AGGREGATION_POLICY, "uncertainty": {"method": "none"}}
    experiment.validate_matrix(matrix)
    path = root / "matrix-declaration.json"
    path.write_text(canonical_json(matrix) + "\n")
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New directory visible to your OCI daemon")
    print(create(parser.parse_args().destination))
