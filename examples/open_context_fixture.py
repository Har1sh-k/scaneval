"""Create a local, fabricated open-context configuration runnable with pinned Semgrep.

This creates a new directory and prints the run-config path. It does not run the target program,
contact a model, fetch public evidence, approve labels, or publish benchmark results.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scaneval import cases
from scaneval.contracts import canonical_json
from scaneval.materialize import _git


PYTHON_IMAGE = "python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"
SEMGREP_IMAGE = "semgrep/semgrep:1.177.0@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198"


def commit(root: Path, message: str) -> str:
    _git(["add", "-A", "-f", "."], root)
    _git(["-c", "user.name=ScanEval fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", message],
         root, extra_env={"GIT_AUTHOR_DATE": "2000-01-01T00:00:00+00:00",
                          "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+00:00"})
    return _git(["rev-parse", "HEAD"], root).strip()


def create(root: Path) -> Path:
    root = root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=False)
    source = root / "upstream"
    source.mkdir()
    _git(["init", "-q"], source)
    (source / "README.md").write_text("Fabricated integration fixture; no real vulnerability advisory.\n")
    (source / "app.py").write_text("import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd)\n")
    commit(source, "Initial local fixture")
    (source / "app.py").write_text("import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n")
    evaluated = commit(source, "Evaluated fabricated input")
    (source / "app.py").write_text("import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd)\n")
    commit(source, "Later fixture correction; excluded from scanner history")
    _git(["checkout", "-q", "--detach", evaluated], source)
    rules = root / "rules-upstream"
    rules.mkdir()
    _git(["init", "-q"], rules)
    (rules / "rules.yaml").write_text(
        "rules:\n- id: fixture-shell\n  languages: [python]\n  severity: WARNING\n"
        "  message: Fixture shell=True sink\n  metadata:\n    cwe: ['CWE-78']\n"
        "  pattern: subprocess.run(..., shell=True, ...)\n")
    rules_commit = commit(rules, "Pinned fixture rule")
    pack = cases.new_pack("local", "open-context-fixture", "Fabricated integration input; not a benchmark.")
    cases.add_snapshot(pack, {"snapshot_id": "fixture", "repository": {"url": str(source), "name": "fixture"},
        "commit": evaluated, "reference": "Fabricated local commit; no advisory.", "languages": ["python"],
        "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Fabricated local fixture."}})
    cases.add_case(pack, cases.draft_case("fixture-shell", snapshot_id="fixture", kind="command_injection",
        description="Fabricated caller-controlled shell invocation.",
        represents="A fabricated single-file subprocess sink for testing evaluation-condition plumbing.",
        workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("fixture-source", origin="research_note", kind="source_inspection",
                                 reference="app.py", note="Fabricated integration fixture only.")],
        accepted_locations=[{"path": "app.py", "start_line": 4, "end_line": 4, "role": "sink", "note": ""}]))
    cases.save_pack(root / "pack.json", pack)
    config = {"schema_version": "2.1", "run_id": "open-context-fixture", "pack": "pack.json", "cache_root": "cache",
        "inputs": [{"snapshot_id": "fixture", "profile": "standard", "condition": {"name": "open_context",
            "policy": {"history": "ancestor_history_v1", "retrieval": "recorded_public_v1", "web_mode": "live",
                       "capture": "content", "retention": "bundle"}}}],
        "systems": [{"system_id": "semgrep-fixture", "adapter": "semgrep",
            "config": {"ruleset": {"url": str(rules), "commit": rules_commit, "paths": ["."]}, "jobs": 1},
            "execution": {"backend": "oci", "image": SEMGREP_IMAGE, "proxy_image": PYTHON_IMAGE,
                "egress": [{"host": "example.com", "port": 443}],
                "retrieval": {"policy": "recorded_public_v1", "allowed_origins": ["https://example.com"],
                              "capture": "content", "retention": "bundle"}}}],
        "repetitions": 1, "timeout_seconds": 120, "trace_mode": "off", "network_policy": "public_research",
        "notes": ["Fabricated integration fixture. Semgrep does not use web research; zero API events are expected."]}
    path = root / "run-config.json"
    path.write_text(canonical_json(config) + "\n")
    (root / "work").mkdir()
    return path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New directory visible to your Docker daemon")
    print(create(parser.parse_args().destination))
