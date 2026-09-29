"""Corpus, plan, review, and run subcommands, exercised through ``main`` on local fixtures.

Every repository here is a ``git init`` fixture and the only scanner is a fake adapter, so no
network call, model call, or sleep is involved. No test approves anything implicitly: a pack
reaches ``human_approved`` only where ``corpus approve`` names a reviewer, and a bundle reaches
it only through ``review approve``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

from scaneval.adapters.base import Adapter, AdapterError, NativeOutcome
from scaneval.cli import main
from scaneval.contracts import canonical_json, canonical_sha256, load_document


VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
              "assumption, and adds a single-file Python sink for the CLI tests.")
ALLEGATION = "shell=True with a caller-controlled command"


def cli(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "upstream"
    (repo / "src").mkdir(parents=True)
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "src" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    return repo, git("rev-parse", "HEAD", cwd=repo)


class FakeAdapter(Adapter):
    """Returns one claim on the accepted location. Never touches the network."""

    name = "fake"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        assert not list(source_dir.rglob("pack.json"))
        native = raw_dir / "native.json"
        native.write_text('{"findings": [{"file": "src/app.py"}]}\n', encoding="utf-8")
        claims = [{"claim_id": "c1", "allegation": ALLEGATION, "kind": "command_injection",
                   "native_rule_id": "fake.shell", "raw_artifact_id": "native",
                   "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5}}]
        return NativeOutcome(status="success", exit_code=0, command=["fake", "scan"], claims=claims,
                             artifacts=[{"id": "native", "path": native}], tool_versions={"fake": "1.0.0"},
                             capture={"model_requests": "not_applicable"}, notes=["fake run"])


def init_argv(pack: Path) -> list[str]:
    return ["corpus", "init", str(pack), "--namespace", "org.example", "--pack-id", "cli-pilot",
            "--description", "Local fixture pack for the CLI tests."]


def snapshot_argv(pack: Path, repo: Path, commit: str, snapshot_id: str = "snap-a") -> list[str]:
    return ["corpus", "add-snapshot", str(pack), "--snapshot-id", snapshot_id, "--url", str(repo),
            "--name", "acme/widget", "--commit", commit, "--language", "python",
            "--workload", "conventional_application", "--component-role", "application",
            "--reference", "Commit chosen by the test fixture; no advisory is claimed."]


def import_argv(pack: Path, case_id: str, *artifact: str) -> list[str]:
    return ["corpus", "import", str(pack), "--case-id", case_id, "--snapshot-id", "snap-a",
            "--represents", REPRESENTS, "--workload", "conventional_application",
            "--component-role", "application", *artifact]


def write_finding(tmp_path: Path) -> Path:
    path = tmp_path / "finding.json"
    path.write_text(json.dumps({"allegation": ALLEGATION, "path": "src/app.py", "kind": "command_injection",
                                "start_line": 5, "end_line": 5, "source": "fake-scanner"}) + "\n",
                    encoding="utf-8")
    return path


def read_pack(pack: Path) -> dict:
    return json.loads(pack.read_text(encoding="utf-8"))


def case_by_id(pack: Path, case_id: str) -> dict:
    return next(case for case in read_pack(pack)["cases"] if case["case_id"] == case_id)


@pytest.fixture
def checked_pack(tmp_path: Path, capsys, upstream) -> dict:
    """A pack with one snapshot, one imported allegation case, and passed mechanical checks."""
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    assert main(snapshot_argv(pack, repo, commit)) == 0
    assert main(import_argv(pack, "case-finding", "--finding", str(write_finding(tmp_path)))) == 0
    assert main(["corpus", "validate", str(pack), "--snapshot-id", "snap-a",
                 "--cache-root", str(tmp_path / "cache"), "--trial-root", str(tmp_path / "trial")]) == 0
    capsys.readouterr()
    return {"pack": pack, "repo": repo, "commit": commit,
            "tree_hash": read_pack(pack)["snapshots"][0]["tree_hash"]}


def test_corpus_init_creates_a_draft_pack_and_refuses_to_overwrite_one(tmp_path, capsys):
    pack = tmp_path / "pack.json"

    code, out, _ = cli(capsys, *init_argv(pack))
    assert code == 0 and "Created draft pack org.example/cli-pilot" in out
    document = read_pack(pack)
    assert document["status"] == "draft" and document["version"] == "0.1.0-draft"
    assert document["cases"] == [] and document["snapshots"] == [] and document["admissions"] == []

    before = pack.read_bytes()
    code, _, err = cli(capsys, *init_argv(pack))
    assert code == 2 and "scaneval:" in err and "File exists" in err
    assert pack.read_bytes() == before


def test_add_snapshot_never_records_a_verified_license_and_refuses_a_duplicate(tmp_path, capsys, upstream):
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0

    code, out, _ = cli(capsys, *snapshot_argv(pack, repo, commit), "--license-spdx", "MIT",
                       "--historical-url", "https://example.invalid/old", "--role", "fixed")
    assert code == 0 and "license verified: false" in out
    [snapshot] = read_pack(pack)["snapshots"]
    assert snapshot["license"]["spdx"] == "MIT" and snapshot["license"]["verified"] is False
    assert snapshot["license"]["note"]
    assert snapshot["tree_hash"] is None and snapshot["git_tree"] is None and snapshot["role"] == "fixed"
    assert snapshot["repository"]["historical_url"] == "https://example.invalid/old"

    code, _, err = cli(capsys, *snapshot_argv(pack, repo, commit))
    assert code == 2 and "already exists" in err
    assert len(read_pack(pack)["snapshots"]) == 1


def test_every_import_produces_an_unapproved_draft_with_recorded_provenance(tmp_path, capsys, upstream):
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    assert main(snapshot_argv(pack, repo, commit)) == 0
    document = tmp_path / "incident.md"
    document.write_text("internal write-up\n", encoding="utf-8")

    code, out, _ = cli(capsys, *import_argv(pack, "case-fix", "--fix-commit", "a" * 40, "--repo",
                                            "https://example.invalid/acme/widget"))
    assert code == 0 and "review state draft" in out and "disposition needs_evidence" in out
    code, _, _ = cli(capsys, *import_argv(pack, "case-finding", "--finding", str(write_finding(tmp_path))))
    assert code == 0
    code, _, _ = cli(capsys, *import_argv(pack, "case-doc", "--document", str(document),
                                          "--section", "3.2"))
    assert code == 0

    fix = case_by_id(pack, "case-fix")
    assert fix["evidence"] == [{"evidence_id": "fix-commit", "origin": "fix_without_advisory",
                                "kind": "fix_commit",
                                "reference": "https://example.invalid/acme/widget@" + "a" * 40,
                                "note": "Supplied fix commit. The CLI did not fetch, read, or verify it."}]
    assert fix["target"]["accepted_locations"] == []
    finding = case_by_id(pack, "case-finding")
    assert [item["kind"] for item in finding["evidence"]] == ["scanner_allegation"]
    assert "fake-scanner" in finding["evidence"][0]["note"]
    assert finding["target"]["accepted_locations"] == [
        {"path": "src/app.py", "role": "other", "note": "imported allegation, not a reviewed label",
         "start_line": 5, "end_line": 5}]
    assert finding["canonical_target"]["kind"] == "command_injection"
    doc = case_by_id(pack, "case-doc")
    assert doc["evidence"][0]["kind"] == "internal_document"
    assert doc["evidence"][0]["reference"] == str(document) and "section 3.2" in doc["evidence"][0]["note"]

    for case in read_pack(pack)["cases"]:
        assert case["disposition"]["value"] == "needs_evidence"
        assert case["validation"] == {"level": None, "review_state": "draft", "checks": [], "reviews": []}
    assert "human_approved" not in pack.read_text(encoding="utf-8")


def test_import_refuses_a_fix_commit_without_a_repository_and_two_artifacts_at_once(tmp_path, capsys, upstream):
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    assert main(snapshot_argv(pack, repo, commit)) == 0

    code, _, err = cli(capsys, *import_argv(pack, "case-fix", "--fix-commit", "a" * 40))
    assert code == 2 and "--fix-commit requires --repo" in err
    assert read_pack(pack)["cases"] == []

    with pytest.raises(SystemExit):
        main(import_argv(pack, "case-two", "--fix-commit", "a" * 40, "--document", str(tmp_path / "x.md")))


def test_retired_import_flag_is_rejected_without_mutating_the_pack(checked_pack, tmp_path, capsys):
    pack = checked_pack["pack"]
    before = pack.read_bytes()
    # Supply a supported artifact too, so rejection is specifically the removed flag.
    with pytest.raises(SystemExit) as exc:
        main(import_argv(pack, "case-old", "--finding", str(write_finding(tmp_path)),
                         "--legacy-case", str(tmp_path / "old-case.json")))
    assert exc.value.code == 2
    assert "unrecognized arguments: --legacy-case" in capsys.readouterr().err
    assert pack.read_bytes() == before


def test_corpus_help_advertises_only_current_intake_forms(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["corpus", "import", "--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "--legacy-case" not in help_text
    assert all(flag in help_text for flag in ("--fix-commit", "--finding", "--document"))


def test_corpus_validate_exports_the_snapshot_and_records_mechanical_checks_only(tmp_path, capsys, upstream):
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    assert main(snapshot_argv(pack, repo, commit)) == 0
    assert main(import_argv(pack, "case-finding", "--finding", str(write_finding(tmp_path)))) == 0
    assert main(import_argv(pack, "case-fix", "--fix-commit", "a" * 40, "--repo", "https://example.invalid/w")) == 0
    capsys.readouterr()

    code, out, err = cli(capsys, "corpus", "validate", str(pack), "--snapshot-id", "snap-a",
                         "--cache-root", str(tmp_path / "cache"), "--trial-root", str(tmp_path / "trial"))
    assert code == 1
    assert "case-finding: pass (mechanically_checked, level L1)" in out
    assert "case-fix: fail (draft, level None); failed: locations_exist_in_snapshot" in out
    assert "mechanical checks failed for 1 case(s): case-fix" in err

    source = tmp_path / "trial" / "snap-a" / "source"
    assert (source / "src" / "app.py").read_text(encoding="utf-8") == VULNERABLE
    assert (tmp_path / "trial" / "snap-a" / "provenance.json").is_file()
    assert not [path for path in source.rglob("*")
                if path.name in ("pack.json", "plan.json", "decisions.json", "provenance.json")]

    document = read_pack(pack)
    assert document["snapshots"][0]["tree_hash"].startswith("sha256:")
    checked = case_by_id(pack, "case-finding")["validation"]
    assert checked["review_state"] == "mechanically_checked" and checked["level"] == "L1" and not checked["reviews"]
    assert case_by_id(pack, "case-fix")["validation"]["review_state"] == "draft"

    code, out, _ = cli(capsys, "corpus", "validate", str(pack))
    summary = json.loads(out)
    assert summary["cases"] == 2 and summary["snapshots"] == 1
    assert summary["review_states"] == {"draft": 1, "mechanically_checked": 1, "human_approved": 0}


def test_a_pack_gains_human_approved_only_through_corpus_approve(tmp_path, capsys, upstream):
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    assert main(snapshot_argv(pack, repo, commit)) == 0
    assert main(import_argv(pack, "case-finding", "--finding", str(write_finding(tmp_path)))) == 0
    capsys.readouterr()

    approve = ["corpus", "approve", str(pack), "--case-id", "case-finding", "--reviewer", "R. Eviewer",
               "--role", "independent_reviewer", "--level", "L3", "--note", "read the source"]
    code, _, err = cli(capsys, *approve)
    assert code == 2 and "mechanical checks" in err
    assert case_by_id(pack, "case-finding")["validation"]["review_state"] == "draft"

    assert main(["corpus", "validate", str(pack), "--snapshot-id", "snap-a",
                 "--cache-root", str(tmp_path / "cache"), "--trial-root", str(tmp_path / "trial")]) == 0
    capsys.readouterr()
    assert case_by_id(pack, "case-finding")["validation"]["review_state"] == "mechanically_checked"

    code, _, err = cli(capsys, *(approve[:-4] + ["--role", "curator", "--level", "L3", "--note", "n"]))
    assert code == 2 and "independent_reviewer" in err
    assert case_by_id(pack, "case-finding")["validation"]["review_state"] == "mechanically_checked"

    assert main(["corpus", "disposition", str(pack), "--case-id", "case-finding", "--value", "validate",
                 "--reason", "advisory and source both read by the curator"]) == 0
    capsys.readouterr()

    code, out, _ = cli(capsys, *approve)
    assert code == 0
    recorded = json.loads(out)
    assert recorded["reviewer"] == "R. Eviewer" and recorded["decision"] == "approve" and recorded["level"] == "L3"
    validation = case_by_id(pack, "case-finding")["validation"]
    assert validation["review_state"] == "human_approved" and validation["level"] == "L3"
    assert [item["reviewer"] for item in validation["reviews"]] == ["R. Eviewer"]


def test_corpus_admit_records_the_named_decider(tmp_path, capsys, checked_pack):
    pack = checked_pack["pack"]

    code, out, _ = cli(capsys, "corpus", "admit", str(pack), "--case-id", "case-finding",
                       "--decision", "admitted", "--by", "J. Curator", "--reason", "pilot slice")
    assert code == 0
    admission = json.loads(out)
    assert admission["case_id"] == "case-finding" and admission["by"] == "J. Curator"
    assert read_pack(pack)["admissions"] == [admission]

    code, _, err = cli(capsys, "corpus", "admit", str(pack), "--case-id", "absent",
                       "--decision", "admitted", "--by", "J. Curator", "--reason", "typo")
    assert code == 2 and "unknown case" in err


def test_plan_writes_a_draft_plan_reports_skipped_cases_and_refuses_to_overwrite(tmp_path, capsys, checked_pack):
    pack = checked_pack["pack"]
    assert main(import_argv(pack, "case-fix", "--fix-commit", "a" * 40, "--repo", "https://example.invalid/w")) == 0
    capsys.readouterr()
    output = tmp_path / "plan.json"

    code, out, err = cli(capsys, "plan", "--pack", str(pack), "--snapshot-id", "snap-a",
                         "--tree-hash", checked_pack["tree_hash"], "--output", str(output))
    assert code == 0 and "Wrote a draft plan with 1 targets" in out
    assert "note: case-fix: draft without passed mechanical checks; not planned" in err
    plan = load_document(output, "evaluation-plan")
    assert plan["scope"] == "draft" and plan["controls"] == []
    assert [(target["target_id"], target["validation_level"]) for target in plan["targets"]] == [
        ("T-case-finding", "L1")]
    assert plan["provenance"]["snapshot_id"] == "snap-a" and plan["provenance"]["mode"] == "full"

    before = output.read_bytes()
    code, _, err = cli(capsys, "plan", "--pack", str(pack), "--snapshot-id", "snap-a",
                       "--tree-hash", checked_pack["tree_hash"], "--output", str(output))
    assert code == 2 and "File exists" in err and output.read_bytes() == before

    code, _, err = cli(capsys, "plan", "--pack", str(pack), "--snapshot-id", "snap-a",
                       "--tree-hash", "sha256:" + "0" * 64, "--output", str(tmp_path / "other.json"))
    assert code == 2 and "tree hash" in err and not (tmp_path / "other.json").exists()


def make_bundle(tmp_path: Path, checked_pack: dict) -> Path:
    """One saved bundle: a planned input and a scanner result, with no evaluator decisions yet."""
    bundle = tmp_path / "bundle"
    (bundle / "evaluator").mkdir(parents=True)
    assert main(["plan", "--pack", str(checked_pack["pack"]), "--snapshot-id", "snap-a",
                 "--tree-hash", checked_pack["tree_hash"],
                 "--output", str(bundle / "evaluator" / "plan.json")]) == 0
    result = {"schema_version": "2.0", "run_id": "run-cli", "system_id": "fake-a",
              "input_hash": checked_pack["tree_hash"], "status": "success", "ranking": "unranked",
              "claims": [{"claim_id": "c1", "allegation": ALLEGATION, "kind": "command_injection",
                          "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5}}],
              "bundles_resolved": True, "usage": {"wall_seconds": 1.0, "cost_usd": None}}
    (bundle / "result.json").write_text(canonical_json(result) + "\n", encoding="utf-8")
    return bundle


def test_review_init_routes_unresolved_candidates_and_refuses_to_overwrite_them(tmp_path, capsys, checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    capsys.readouterr()

    code, out, _ = cli(capsys, "review", "init", str(bundle), "--pack", str(checked_pack["pack"]))
    assert code == 0 and "Routed 1 candidate claim matches" in out and "stays unresolved" in out
    decisions = load_document(bundle / "evaluator" / "decisions.json", "review-decisions")
    assert [(match["claim_id"], match["target_id"], match["decision"]) for match in decisions["claim_matches"]] == [
        ("c1", "T-case-finding", "unresolved")]
    record = load_document(bundle / "evaluator" / "review-record.json", "review-record")
    assert record["state"] == "draft" and record["reviews"] == []

    code, _, err = cli(capsys, "review", "init", str(bundle), "--pack", str(checked_pack["pack"]))
    assert code == 2 and "refusing to overwrite" in err


def test_review_approve_replaces_only_the_record_and_needs_an_explicit_reviewer(tmp_path, capsys, checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    record_path = bundle / "evaluator" / "review-record.json"

    code, _, err = cli(capsys, "review", "approve", str(bundle), "--reviewer", "R. Eviewer", "--note", "n")
    assert code == 2 and "could not load" in err

    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    record_path.unlink()
    code, _, err = cli(capsys, "review", "approve", str(bundle), "--reviewer", "R. Eviewer", "--note", "n")
    assert code == 2 and "no review record" in err
    (bundle / "evaluator" / "decisions.json").unlink()
    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    capsys.readouterr()
    code, out, _ = cli(capsys, "review", "status", str(bundle))
    assert code == 0 and out.strip() == "draft"
    decisions_before = (bundle / "evaluator" / "decisions.json").read_bytes()
    plan_before = (bundle / "evaluator" / "plan.json").read_bytes()

    code, _, err = cli(capsys, "review", "approve", str(bundle), "--reviewer", "   ", "--note", "n")
    assert code == 2 and "explicit reviewer name" in err
    assert load_document(record_path, "review-record")["state"] == "draft"

    code, out, _ = cli(capsys, "review", "approve", str(bundle), "--reviewer", "R. Eviewer",
                       "--note", "read every routed claim")
    assert code == 0 and "human_approved" in out
    approved = load_document(record_path, "review-record")
    assert approved["state"] == "human_approved" and len(approved["reviews"]) == 1
    assert approved["reviews"][0]["reviewer"] == "R. Eviewer"
    assert (bundle / "evaluator" / "decisions.json").read_bytes() == decisions_before
    assert (bundle / "evaluator" / "plan.json").read_bytes() == plan_before
    assert not list((bundle / "evaluator").glob("*.tmp"))

    code, out, _ = cli(capsys, "review", "status", str(bundle))
    assert code == 0 and out.strip() == "human_approved"


def test_review_status_and_report_warn_while_a_bundle_is_unreviewed(tmp_path, capsys, checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    capsys.readouterr()

    code, out, _ = cli(capsys, "review", "status", str(bundle))
    assert code == 0 and out.strip() == "missing"

    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    capsys.readouterr()
    code, _, err = cli(capsys, "report", str(bundle), "--output", str(tmp_path / "draft.html"))
    assert code == 0 and "warning: review record is draft" in err and "not benchmark evidence" in err
    drafted = (tmp_path / "draft.html").read_text(encoding="utf-8")
    assert '<p class="notice">Decisions: machine-drafted, all unresolved; no human review recorded.</p>' in drafted

    assert main(["review", "approve", str(bundle), "--reviewer", "R. Eviewer", "--note", "read them"]) == 0
    capsys.readouterr()
    code, _, err = cli(capsys, "report", str(bundle), "--output", str(tmp_path / "approved.html"))
    assert code == 0 and "warning" not in err
    approved = (tmp_path / "approved.html").read_text(encoding="utf-8")
    assert '<p class="notice">Decisions: recorded human review (human_approved).</p>' in approved
    assert "machine-drafted" not in approved


def test_report_of_a_demo_bundle_warns_about_the_missing_review_record(tmp_path, capsys):
    bundle = tmp_path / "demo"
    assert main(["demo", str(bundle)]) == 0
    capsys.readouterr()

    code, _, err = cli(capsys, "report", str(bundle), "--output", str(tmp_path / "report.html"))
    assert code == 0 and "warning: review record is missing" in err


def write_config(tmp_path: Path, *, systems: list[dict] | None = None) -> Path:
    config = {"schema_version": "2.0", "run_id": "run-cli", "pack": "pack.json", "cache_root": "cache",
              "inputs": [{"snapshot_id": "snap-a"}],
              "systems": systems or [{"system_id": "fake-a", "adapter": "fake", "config": {}}],
              "repetitions": 1, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none"}
    path = tmp_path / "run-config.json"
    path.write_text(canonical_json(config) + "\n", encoding="utf-8")
    return path


def test_run_executes_one_configuration_and_leaves_the_source_pack_a_draft(tmp_path, capsys, monkeypatch,
                                                                          checked_pack):
    monkeypatch.setattr("scaneval.runner.get_adapter", lambda name: FakeAdapter())
    config = write_config(tmp_path)
    workspace = tmp_path / "work"
    workspace.mkdir()
    out_dir = tmp_path / "out"
    pack_before = checked_pack["pack"].read_bytes()

    code, out, _ = cli(capsys, "run", str(config), "--output", str(out_dir),
                       "--workspace-root", str(workspace))
    assert code == 0
    assert "snap-a__fake-a__r1 status=success claims=1 plan=draft review=draft" in out
    assert f"Manifest: {out_dir / 'run-manifest.json'}" in out
    manifest = json.loads((out_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert [row["invocation_id"] for row in manifest["invocations"]] == ["snap-a__fake-a__r1"]
    assert (out_dir / "invocations" / "snap-a__fake-a__r1" / "evaluation.json").is_file()
    assert checked_pack["pack"].read_bytes() == pack_before
    assert "human_approved" not in checked_pack["pack"].read_text(encoding="utf-8")

    code, _, err = cli(capsys, "run", str(config), "--output", str(out_dir))
    assert code == 2 and "scaneval:" in err

    code, _, err = cli(capsys, "run", str(config), "--output", str(tmp_path / "other"),
                       "--only-system", "absent")
    assert code == 2 and "systems not present" in err and not (tmp_path / "other").exists()


def test_run_reports_a_skipped_system_without_inventing_a_scan(tmp_path, capsys, monkeypatch, checked_pack):
    def resolve(name: str):
        if name == "broken":
            raise AdapterError("unknown adapter 'broken'")
        return FakeAdapter()

    monkeypatch.setattr("scaneval.runner.get_adapter", resolve)
    config = write_config(tmp_path, systems=[{"system_id": "fake-a", "adapter": "fake", "config": {}},
                                             {"system_id": "broken-b", "adapter": "broken", "config": {}}])
    out_dir = tmp_path / "out"

    code, out, err = cli(capsys, "run", str(config), "--output", str(out_dir))
    assert code == 1
    assert "snap-a__fake-a__r1 status=success" in out
    assert "snap-a__broken-b__r1 status=skipped claims=None plan=None review=None" in out
    assert "no usable scan from 1 invocation(s): snap-a__broken-b__r1" in err
    assert not (out_dir / "invocations" / "snap-a__broken-b__r1").exists()


def test_corpus_validate_falls_back_to_a_cache_beside_the_pack(tmp_path, capsys, upstream):
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    assert main(snapshot_argv(pack, repo, commit)) == 0
    assert main(import_argv(pack, "case-finding", "--finding", str(write_finding(tmp_path)))) == 0
    capsys.readouterr()

    code, out, _ = cli(capsys, "corpus", "validate", str(pack), "--snapshot-id", "snap-a",
                       "--trial-root", str(tmp_path / "trial"))
    assert code == 0 and "case-finding: pass" in out
    assert (tmp_path / ".repos").is_dir()

    code, _, err = cli(capsys, "corpus", "validate", str(pack), "--snapshot-id", "absent",
                       "--trial-root", str(tmp_path / "trial2"))
    assert code == 2 and "unknown snapshot" in err
    assert not (tmp_path / "trial2").exists()


class FailingAdapter(FakeAdapter):
    """Fails inside scan, so the invocation records status error instead of an empty success."""

    def scan(self, **kwargs):
        raise AdapterError("the fake scanner crashed")


def accept_one_match(bundle: Path) -> dict:
    """Do by hand what a reviewer does in an editor: accept one routed candidate."""
    path = bundle / "evaluator" / "decisions.json"
    decisions = json.loads(path.read_text(encoding="utf-8"))
    decisions["claim_matches"][0]["decision"] = "accepted"
    decisions["claim_matches"][0]["reason"] = "the claim names the shell call this target is about"
    path.write_text(canonical_json(decisions) + "\n", encoding="utf-8")
    return decisions


def test_review_record_then_approve_carries_an_edited_decision_into_replay(tmp_path, capsys, checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    capsys.readouterr()
    decisions = accept_one_match(bundle)

    code, out, _ = cli(capsys, "review", "record", str(bundle), "--note", "accepted one routed claim")
    assert code == 0 and "Review record state: draft (0 recorded reviews)" in out
    assert f"decisions_sha256: {canonical_sha256(decisions)}" in out
    record = load_document(bundle / "evaluator" / "review-record.json", "review-record")
    assert record["state"] == "draft" and record["notes"] == ["accepted one routed claim"]
    assert f"plan_sha256: {record['plan_sha256']}" in out
    assert not list((bundle / "evaluator").glob("*.tmp"))

    code, out, _ = cli(capsys, "review", "approve", str(bundle), "--reviewer", "R. Eviewer",
                       "--note", "read the claim and the target")
    assert code == 0 and "human_approved" in out

    code, out, err = cli(capsys, "replay", str(bundle))
    assert code == 0 and "review state" not in err
    assert json.loads(out)["metrics"]["targets_detected"] == 1

    code, out, _ = cli(capsys, "review", "status", str(bundle))
    assert code == 0 and out.strip() == "human_approved"

    plan_path = bundle / "evaluator" / "plan.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["targets"][0]["description"] = "edited after the approval was recorded"
    plan_path.write_text(canonical_json(plan) + "\n", encoding="utf-8")

    code, out, _ = cli(capsys, "review", "status", str(bundle))
    assert code == 0 and out.strip() == "stale"


def test_replay_warns_about_an_unapproved_review_state_without_changing_its_json(tmp_path, capsys,
                                                                                checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    capsys.readouterr()

    code, drafted, err = cli(capsys, "replay", str(bundle))
    assert code == 0 and "scaneval: review state draft: these numbers come from decisions" in err

    (bundle / "evaluator" / "review-record.json").unlink()
    code, out, err = cli(capsys, "replay", str(bundle))
    assert code == 0 and "scaneval: review state missing:" in err and out == drafted

    assert main(["review", "record", str(bundle)]) == 0
    assert main(["review", "approve", str(bundle), "--reviewer", "R. Eviewer", "--note", "read them"]) == 0
    capsys.readouterr()
    code, out, err = cli(capsys, "replay", str(bundle))
    assert code == 0 and err == "" and out == drafted


def test_corpus_disposition_records_the_new_value_and_keeps_the_previous_one_visible(tmp_path, capsys,
                                                                                    checked_pack):
    pack = checked_pack["pack"]

    code, out, _ = cli(capsys, "corpus", "disposition", str(pack), "--case-id", "case-finding",
                       "--value", "validate", "--reason", "advisory and source both read")
    assert code == 0
    assert json.loads(out) == {"value": "validate", "reason": "advisory and source both read"}
    case = case_by_id(pack, "case-finding")
    assert case["disposition"] == {"value": "validate", "reason": "advisory and source both read"}
    assert "disposition changed from needs_evidence to validate: advisory and source both read" in case["notes"]
    assert case["validation"]["review_state"] == "mechanically_checked"
    assert not case["validation"]["reviews"]

    code, _, err = cli(capsys, "corpus", "disposition", str(pack), "--case-id", "absent",
                       "--value", "exclude", "--reason", "typo")
    assert code == 2 and "unknown case" in err

    with pytest.raises(SystemExit):
        main(["corpus", "disposition", str(pack), "--case-id", "case-finding", "--value", "approved",
              "--reason", "not a disposition"])


def test_corpus_approve_and_admit_refuse_a_blank_name(tmp_path, capsys, checked_pack):
    pack = checked_pack["pack"]
    before = pack.read_bytes()

    code, _, err = cli(capsys, "corpus", "approve", str(pack), "--case-id", "case-finding",
                       "--reviewer", "   ", "--role", "independent_reviewer", "--level", "L3",
                       "--note", "looks fine")
    assert code == 2 and "explicit reviewer name" in err

    code, _, err = cli(capsys, "corpus", "admit", str(pack), "--case-id", "case-finding",
                       "--decision", "admitted", "--by", "\t", "--reason", "pilot slice")
    assert code == 2 and "explicit name" in err

    assert pack.read_bytes() == before
    assert read_pack(pack)["admissions"] == []
    assert case_by_id(pack, "case-finding")["validation"]["review_state"] == "mechanically_checked"


def test_corpus_approve_at_l3_requires_the_validate_disposition(tmp_path, capsys, checked_pack):
    pack = checked_pack["pack"]
    approve = ["corpus", "approve", str(pack), "--case-id", "case-finding", "--reviewer", "R. Eviewer",
               "--role", "independent_reviewer", "--level", "L3", "--note", "read the source"]

    code, _, err = cli(capsys, *approve)
    assert code == 2 and "L3/L4 require disposition validate" in err
    assert case_by_id(pack, "case-finding")["validation"]["review_state"] == "mechanically_checked"

    assert main(["corpus", "disposition", str(pack), "--case-id", "case-finding", "--value", "validate",
                 "--reason", "evidence reviewed; worth validating"]) == 0
    capsys.readouterr()

    code, out, _ = cli(capsys, *approve)
    assert code == 0 and json.loads(out)["level"] == "L3"
    validation = case_by_id(pack, "case-finding")["validation"]
    assert validation["review_state"] == "human_approved" and validation["level"] == "L3"


def test_run_returns_one_when_an_invocation_records_an_error_status(tmp_path, capsys, monkeypatch,
                                                                   checked_pack):
    monkeypatch.setattr("scaneval.runner.get_adapter", lambda name: FailingAdapter())
    config = write_config(tmp_path)
    out_dir = tmp_path / "out"

    code, out, err = cli(capsys, "run", str(config), "--output", str(out_dir))
    assert code == 1
    assert "snap-a__fake-a__r1 status=error" in out
    assert "no usable scan from 1 invocation(s): snap-a__fake-a__r1" in err
    manifest = json.loads((out_dir / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed"
    assert [row["status"] for row in manifest["invocations"]] == ["error"]


def release_pack(pack: Path) -> None:
    """Mark a pack released the way a release step would, without going through the CLI."""
    document = read_pack(pack)
    document["status"] = "released"
    document["version"] = "1.0.0"
    pack.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def test_a_pack_that_is_no_longer_a_draft_changes_only_through_a_new_version(tmp_path, capsys, checked_pack):
    pack = checked_pack["pack"]
    release_pack(pack)
    before = pack.read_bytes()

    refused = [
        ["corpus", "admit", str(pack), "--case-id", "case-finding", "--decision", "admitted",
         "--by", "J. Curator", "--reason", "pilot slice"],
        ["corpus", "disposition", str(pack), "--case-id", "case-finding", "--value", "validate",
         "--reason", "evidence reviewed"],
        ["corpus", "approve", str(pack), "--case-id", "case-finding", "--reviewer", "R. Eviewer",
         "--role", "curator", "--level", "L2", "--note", "structural review"],
        snapshot_argv(pack, checked_pack["repo"], checked_pack["commit"], "snap-b"),
        import_argv(pack, "case-second", "--fix-commit", "a" * 40, "--repo", "https://example.invalid/w"),
        ["corpus", "validate", str(pack), "--snapshot-id", "snap-a", "--trial-root", str(tmp_path / "again")],
    ]
    for argv in refused:
        code, _, err = cli(capsys, *argv)
        assert code == 2 and "pack status is released" in err and "--new-version" in err
        assert pack.read_bytes() == before
    assert not (tmp_path / "again").exists()

    code, out, _ = cli(capsys, "corpus", "admit", str(pack), "--case-id", "case-finding",
                       "--decision", "admitted", "--by", "J. Curator", "--reason", "pilot slice",
                       "--new-version", "1.1.0-draft")
    assert code == 0 and json.loads(out)["by"] == "J. Curator"
    document = read_pack(pack)
    assert document["status"] == "draft" and document["version"] == "1.1.0-draft"
    assert [admission["by"] for admission in document["admissions"]] == ["J. Curator"]
    assert "version 1.0.0 (status released) reopened as 1.1.0-draft (status draft)" in document["notes"]
    assert not list(tmp_path.glob("pack.json.*"))


def test_a_refused_pack_change_leaves_the_pack_and_no_temporary_file_behind(tmp_path, capsys, checked_pack):
    pack = checked_pack["pack"]
    before = pack.read_bytes()

    code, _, err = cli(capsys, "corpus", "approve", str(pack), "--case-id", "absent", "--reviewer", "R. Eviewer",
                       "--role", "curator", "--level", "L2", "--note", "structural review")
    assert code == 2 and "unknown case" in err
    assert pack.read_bytes() == before
    assert not list(tmp_path.glob("pack.json.*"))

    assert main(["corpus", "admit", str(pack), "--case-id", "case-finding", "--decision", "deferred",
                 "--by", "J. Curator", "--reason", "waiting on evidence"]) == 0
    assert pack.read_bytes() != before
    assert not list(tmp_path.glob("pack.json.*"))
    assert read_pack(pack)["admissions"][0]["decision"] == "deferred"


def pack_with_snapshot(tmp_path: Path, upstream) -> Path:
    """One draft pack holding the fixture snapshot and no cases yet."""
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    assert main(snapshot_argv(pack, repo, commit)) == 0
    return pack


@pytest.mark.parametrize("lines, message", [
    ({"start_line": 5}, "supplied together"),
    ({"end_line": 5}, "supplied together"),
    ({"start_line": "5", "end_line": "9"}, "must be an integer of at least 1"),
    ({"start_line": 0, "end_line": 9}, "must be an integer of at least 1"),
    ({"start_line": 5, "end_line": True}, "must be an integer of at least 1"),
    ({"start_line": 9, "end_line": 5}, "must not exceed"),
])
def test_import_refuses_finding_lines_that_are_not_a_pair_of_positive_integers(tmp_path, capsys, upstream,
                                                                              lines, message):
    pack = pack_with_snapshot(tmp_path, upstream)
    finding = tmp_path / "partial-finding.json"
    finding.write_text(json.dumps({"allegation": ALLEGATION, "path": "src/app.py", **lines}) + "\n",
                       encoding="utf-8")
    capsys.readouterr()

    code, _, err = cli(capsys, *import_argv(pack, "case-finding", "--finding", str(finding)))
    assert code == 2 and message in err
    assert "Traceback" not in err and err.startswith("scaneval: ")
    assert read_pack(pack)["cases"] == []


def test_import_keeps_a_finding_without_line_numbers_file_only(tmp_path, capsys, upstream):
    pack = pack_with_snapshot(tmp_path, upstream)
    finding = tmp_path / "file-only-finding.json"
    finding.write_text(json.dumps({"allegation": ALLEGATION, "path": "src/app.py"}) + "\n", encoding="utf-8")
    capsys.readouterr()

    code, _, _ = cli(capsys, *import_argv(pack, "case-finding", "--finding", str(finding)))
    assert code == 0
    assert case_by_id(pack, "case-finding")["target"]["accepted_locations"] == [
        {"path": "src/app.py", "role": "other", "note": "imported allegation, not a reviewed label"}]


def test_add_snapshot_refuses_a_url_that_carries_credentials(tmp_path, capsys, upstream):
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    capsys.readouterr()
    before = pack.read_bytes()

    with_credentials = snapshot_argv(pack, repo, commit)
    with_credentials[with_credentials.index("--url") + 1] = "https://user:token@example.invalid/acme/widget.git"
    code, _, err = cli(capsys, *with_credentials)
    assert code == 2 and "--url carries credentials in the URL authority" in err
    assert pack.read_bytes() == before

    code, _, err = cli(capsys, *snapshot_argv(pack, repo, commit), "--historical-url",
                       "https://user:token@example.invalid/old")
    assert code == 2 and "--historical-url carries credentials in the URL authority" in err
    assert pack.read_bytes() == before and read_pack(pack)["snapshots"] == []


def test_corpus_validate_refuses_an_existing_trial_directory_before_fetching(tmp_path, capsys, upstream):
    pack = pack_with_snapshot(tmp_path, upstream)
    assert main(import_argv(pack, "case-finding", "--finding", str(write_finding(tmp_path)))) == 0
    (tmp_path / "trial" / "snap-a").mkdir(parents=True)
    capsys.readouterr()

    code, _, err = cli(capsys, "corpus", "validate", str(pack), "--snapshot-id", "snap-a",
                       "--cache-root", str(tmp_path / "cache"), "--trial-root", str(tmp_path / "trial"))
    assert code == 2 and "trial directory already exists" in err
    assert not (tmp_path / "cache").exists()
    assert not list((tmp_path / "trial" / "snap-a").iterdir())
    assert case_by_id(pack, "case-finding")["validation"]["checks"] == []


def test_plan_refuses_an_output_path_inside_a_trial_directory(tmp_path, capsys, checked_pack):
    trial = tmp_path / "trial" / "snap-a"
    assert (trial / "provenance.json").is_file() and (trial / "source").is_dir()
    plan_argv = ["plan", "--pack", str(checked_pack["pack"]), "--snapshot-id", "snap-a",
                 "--tree-hash", checked_pack["tree_hash"], "--output"]
    capsys.readouterr()

    for output in (trial / "plan.json", trial / "source" / "evaluator" / "plan.json"):
        code, _, err = cli(capsys, *plan_argv, str(output))
        assert code == 2 and "inside the trial directory" in err
        assert not output.exists()

    outside = tmp_path / "plan.json"
    code, out, _ = cli(capsys, *plan_argv, str(outside))
    assert code == 0 and "Wrote a draft plan" in out and outside.is_file()


def test_the_cli_docstring_states_which_files_are_rewritten_and_which_are_create_only():
    from scaneval import cli

    assert "A pack file is rewritten in place" in cli.__doc__
    assert "review-record.json" in cli.__doc__ and "review record" in cli.__doc__
    assert "Everything else is create-only" in cli.__doc__


def test_corpus_validate_makes_no_temporary_trial_directory_when_the_fetch_fails(tmp_path, capsys,
                                                                                 upstream, monkeypatch):
    pack = pack_with_snapshot(tmp_path, upstream)
    assert main(import_argv(pack, "case-finding", "--finding", str(write_finding(tmp_path)))) == 0
    document = read_pack(pack)
    document["snapshots"][0]["repository"]["url"] = str(tmp_path / "absent-repository")
    pack.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary = tmp_path / "tmp"
    temporary.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temporary))
    capsys.readouterr()

    code, _, err = cli(capsys, "corpus", "validate", str(pack), "--snapshot-id", "snap-a",
                       "--cache-root", str(tmp_path / "cache"))
    assert code == 2 and "scaneval:" in err
    assert list(temporary.iterdir()) == []
    assert case_by_id(pack, "case-finding")["validation"]["checks"] == []


def test_a_rewritten_pack_keeps_its_file_permissions(tmp_path, capsys, checked_pack):
    pack = checked_pack["pack"]
    pack.chmod(0o644)
    capsys.readouterr()

    assert main(["corpus", "disposition", str(pack), "--case-id", "case-finding", "--value", "validate",
                 "--reason", "evidence reviewed"]) == 0

    assert pack.stat().st_mode & 0o777 == 0o644


def test_review_approve_refuses_a_bundle_reached_through_a_symlink(tmp_path, capsys, checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    capsys.readouterr()
    record_path = bundle / "evaluator" / "review-record.json"
    before = record_path.read_bytes()
    linked_bundle = tmp_path / "linked-bundle"
    linked_bundle.symlink_to(bundle, target_is_directory=True)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)

    code, _, err = cli(capsys, "review", "approve", str(linked_bundle), "--reviewer", "R. Eviewer",
                       "--note", "read them")
    assert code == 2 and "symlinked directory" in err

    code, _, err = cli(capsys, "review", "approve", str(linked_parent / "bundle"),
                       "--reviewer", "R. Eviewer", "--note", "read them")
    assert code == 2 and "does not resolve to itself" in err

    assert record_path.read_bytes() == before
    assert load_document(record_path, "review-record")["state"] == "draft"
    assert not list((bundle / "evaluator").glob("*.tmp"))


def test_review_status_refuses_a_bundle_path_that_is_not_a_directory(tmp_path, capsys, checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    capsys.readouterr()

    code, out, err = cli(capsys, "review", "status", str(bundle / "result.json"))
    assert code == 2 and "not a bundle directory" in err and out == ""

    code, _, err = cli(capsys, "review", "status", str(tmp_path / "absent-bundle"))
    assert code == 2 and "not a bundle directory" in err

    code, out, _ = cli(capsys, "review", "status", str(bundle))
    assert code == 0 and out.strip() == "missing"


def test_import_refuses_a_fix_commit_repository_that_carries_credentials(tmp_path, capsys, upstream):
    pack = pack_with_snapshot(tmp_path, upstream)
    capsys.readouterr()
    before = pack.read_bytes()

    code, _, err = cli(capsys, *import_argv(pack, "case-fix", "--fix-commit", "a" * 40, "--repo",
                                            "https://user:token@example.invalid/acme/widget.git"))
    assert code == 2 and "--repo carries credentials in the URL authority" in err
    assert pack.read_bytes() == before and read_pack(pack)["cases"] == []

    code, _, _ = cli(capsys, *import_argv(pack, "case-fix", "--fix-commit", "a" * 40, "--repo",
                                          "ssh://git@example.invalid/acme/widget.git"))
    assert code == 0
    assert case_by_id(pack, "case-fix")["evidence"][0]["reference"] == \
        "ssh://git@example.invalid/acme/widget.git@" + "a" * 40


def test_add_snapshot_accepts_an_ssh_url_whose_only_userinfo_is_the_git_account(tmp_path, capsys, upstream):
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    capsys.readouterr()

    accepted = snapshot_argv(pack, repo, commit)
    accepted[accepted.index("--url") + 1] = "ssh://git@example.invalid/acme/widget.git"
    code, _, _ = cli(capsys, *accepted)
    assert code == 0
    assert read_pack(pack)["snapshots"][0]["repository"]["url"] == "ssh://git@example.invalid/acme/widget.git"

    refused = snapshot_argv(pack, repo, commit, "snap-b")
    refused[refused.index("--url") + 1] = "ssh://git:token@example.invalid/acme/widget.git"
    code, _, err = cli(capsys, *refused)
    assert code == 2 and "--url carries credentials in the URL authority" in err
    assert [snapshot["snapshot_id"] for snapshot in read_pack(pack)["snapshots"]] == ["snap-a"]


def test_run_refuses_an_output_directory_inside_a_trial_directory(tmp_path, capsys, checked_pack):
    config = write_config(tmp_path)
    trial = tmp_path / "trial" / "snap-a"
    assert (trial / "provenance.json").is_file() and (trial / "source").is_dir()
    output = trial / "source" / "out"
    capsys.readouterr()

    code, _, err = cli(capsys, "run", str(config), "--output", str(output))
    assert code == 2 and "inside the trial directory" in err
    assert not output.exists()


def test_evaluation_outputs_are_refused_inside_a_trial_directory(tmp_path, capsys, checked_pack):
    trial = tmp_path / "trial" / "snap-a"
    demo = tmp_path / "demo"
    assert main(["demo", str(demo)]) == 0
    capsys.readouterr()
    evaluator = demo / "evaluator"

    refused = {
        "demo": ["demo", str(trial / "source" / "fixture")],
        "replay": ["replay", str(demo), "--output", str(trial / "replay.json")],
        "report": ["report", str(demo), "--output", str(trial / "source" / "report.html")],
        "score": ["score", "--plan", str(evaluator / "plan.json"), "--result", str(demo / "result.json"),
                  "--decisions", str(evaluator / "decisions.json"), "--output", str(trial / "score.json")],
    }
    for argv in refused.values():
        code, _, err = cli(capsys, *argv)
        assert code == 2 and "inside the trial directory" in err

    assert not (trial / "source" / "fixture").exists()
    assert not (trial / "replay.json").exists() and not (trial / "score.json").exists()
    assert not (trial / "source" / "report.html").exists()


def test_corpus_validate_refuses_a_trial_root_inside_a_trial_directory(tmp_path, capsys, checked_pack):
    pack = checked_pack["pack"]
    nested = tmp_path / "trial" / "snap-a" / "source" / "nested"
    capsys.readouterr()

    code, _, err = cli(capsys, "corpus", "validate", str(pack), "--snapshot-id", "snap-a",
                       "--cache-root", str(tmp_path / "second-cache"), "--trial-root", str(nested))
    assert code == 2 and "inside the trial directory" in err
    assert not nested.exists() and not (tmp_path / "second-cache").exists()


def test_new_version_is_stripped_and_refused_when_it_repeats_the_current_version(tmp_path, capsys,
                                                                                checked_pack):
    pack = checked_pack["pack"]
    release_pack(pack)
    before = pack.read_bytes()
    admit = ["corpus", "admit", str(pack), "--case-id", "case-finding", "--decision", "admitted",
             "--by", "J. Curator", "--reason", "pilot slice"]

    code, _, err = cli(capsys, *admit, "--new-version", "  1.0.0  ")
    assert code == 2 and "already carries" in err
    assert pack.read_bytes() == before

    code, _, err = cli(capsys, *admit, "--new-version", "   ")
    assert code == 2 and "non-blank version" in err
    assert pack.read_bytes() == before

    code, _, _ = cli(capsys, *admit, "--new-version", "  1.1.0-draft  ")
    assert code == 0
    document = read_pack(pack)
    assert document["version"] == "1.1.0-draft" and document["status"] == "draft"
    assert "version 1.0.0 (status released) reopened as 1.1.0-draft (status draft)" in document["notes"]


def test_read_only_bundle_commands_read_a_bundle_under_a_symlinked_parent(tmp_path, capsys, checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(tmp_path, target_is_directory=True)
    reached = linked_parent / "bundle"
    capsys.readouterr()

    code, out, _ = cli(capsys, "review", "status", str(reached))
    assert code == 0 and out.strip() == "draft"

    code, out, err = cli(capsys, "replay", str(reached))
    assert code == 0 and json.loads(out)["metrics"]["pending_matching_count"] == 1
    assert "review state draft" in err

    code, _, err = cli(capsys, "report", str(reached), "--output", str(tmp_path / "linked.html"))
    assert code == 0 and "review record is draft" in err
    assert (tmp_path / "linked.html").is_file()

    # Reading through the link changed nothing: approving still refuses that spelling.
    code, _, err = cli(capsys, "review", "approve", str(reached), "--reviewer", "R. Eviewer",
                       "--note", "read them")
    assert code == 2 and "does not resolve to itself" in err
    assert load_document(bundle / "evaluator" / "review-record.json", "review-record")["state"] == "draft"


def test_review_approve_refuses_decisions_that_do_not_bind_to_the_saved_result(tmp_path, capsys,
                                                                              checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    record_path = bundle / "evaluator" / "review-record.json"
    before = record_path.read_bytes()
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    result["claims"][0]["allegation"] = "rewritten after the decisions were filed"
    (bundle / "result.json").write_text(canonical_json(result) + "\n", encoding="utf-8")
    capsys.readouterr()

    code, _, err = cli(capsys, "review", "approve", str(bundle), "--reviewer", "R. Eviewer",
                       "--note", "read them")
    assert code == 2 and "filed against a different result" in err
    assert record_path.read_bytes() == before
    assert load_document(record_path, "review-record")["state"] == "draft"
    assert not list((bundle / "evaluator").glob("*.tmp"))


def test_corpus_init_refuses_a_pack_path_inside_a_trial_directory(tmp_path, capsys, checked_pack):
    trial = tmp_path / "trial" / "snap-a"
    assert (trial / "provenance.json").is_file() and (trial / "source").is_dir()
    capsys.readouterr()

    for pack in (trial / "pack.json", trial / "source" / "pack.json"):
        code, _, err = cli(capsys, *init_argv(pack))
        assert code == 2 and "inside the trial directory" in err
        assert not pack.exists()

    outside = tmp_path / "second-pack.json"
    code, out, _ = cli(capsys, *init_argv(outside))
    assert code == 0 and "Created draft pack" in out and outside.is_file()


def test_review_commands_refuse_a_bundle_inside_a_trial_directory(tmp_path, capsys, checked_pack):
    trial = tmp_path / "trial" / "snap-a"
    bundle = trial / "source" / "bundle"
    capsys.readouterr()

    refused = {
        "init": ["review", "init", str(bundle), "--pack", str(checked_pack["pack"])],
        "record": ["review", "record", str(bundle)],
        "approve": ["review", "approve", str(bundle), "--reviewer", "R. Eviewer", "--note", "n"],
    }
    for argv in refused.values():
        code, _, err = cli(capsys, *argv)
        assert code == 2 and "inside the trial directory" in err

    assert not bundle.exists()


UNPARSABLE_URL = "https://[::1/acme/widget.git"


def test_a_snapshot_url_that_cannot_be_parsed_is_refused_naming_the_flag(tmp_path, capsys, upstream):
    repo, commit = upstream
    pack = tmp_path / "pack.json"
    assert main(init_argv(pack)) == 0
    capsys.readouterr()
    before = pack.read_bytes()

    unparsable = snapshot_argv(pack, repo, commit)
    unparsable[unparsable.index("--url") + 1] = UNPARSABLE_URL
    code, _, err = cli(capsys, *unparsable)
    assert code == 2 and "--url is not a URL this tool can read" in err
    assert "Invalid IPv6 URL" in err and "could not be checked for credentials" in err
    assert err.startswith("scaneval: ") and "Traceback" not in err

    code, _, err = cli(capsys, *snapshot_argv(pack, repo, commit),
                       "--historical-url", UNPARSABLE_URL)
    assert code == 2 and "--historical-url is not a URL this tool can read" in err
    assert err.startswith("scaneval: ") and "Traceback" not in err

    assert pack.read_bytes() == before and read_pack(pack)["snapshots"] == []


def test_an_import_repository_url_that_cannot_be_parsed_is_refused_naming_the_flag(tmp_path, capsys,
                                                                                  upstream):
    pack = pack_with_snapshot(tmp_path, upstream)
    capsys.readouterr()
    before = pack.read_bytes()

    code, _, err = cli(capsys, *import_argv(pack, "case-fix", "--fix-commit", "a" * 40,
                                            "--repo", UNPARSABLE_URL))
    assert code == 2 and "--repo is not a URL this tool can read" in err
    assert err.startswith("scaneval: ") and "Traceback" not in err
    assert pack.read_bytes() == before and read_pack(pack)["cases"] == []


def test_a_document_that_is_not_utf_8_is_refused_naming_the_file(tmp_path, capsys, checked_pack):
    broken = tmp_path / "broken-pack.json"
    broken.write_bytes(b'{"schema_version": "2.\xff0", "namespace": "org.example"}\n')
    bundle = make_bundle(tmp_path, checked_pack)
    (bundle / "result.json").write_bytes(b'{"schema_version": "2.\xff0"}\n')
    capsys.readouterr()

    refused = {
        "validate": ["validate", "case-pack", str(broken)],
        "corpus validate": ["corpus", "validate", str(broken)],
        "corpus approve": ["corpus", "approve", str(broken), "--case-id", "case-finding",
                           "--reviewer", "R. Eviewer", "--role", "curator", "--level", "L2",
                           "--note", "structural review"],
    }
    for argv in refused.values():
        code, _, err = cli(capsys, *argv)
        assert code == 2 and f"could not load {broken}" in err
        assert "utf-8" in err and "Traceback" not in err
        assert err.startswith("scaneval: ")

    code, _, err = cli(capsys, "replay", str(bundle))
    assert code == 2 and f"could not load {bundle / 'result.json'}" in err
    assert err.startswith("scaneval: ") and "utf-8" in err and "Traceback" not in err


def test_review_commands_refuse_a_bundle_that_is_itself_a_trial_directory(tmp_path, capsys,
                                                                         checked_pack):
    trial = tmp_path / "trial" / "snap-a"
    assert (trial / "provenance.json").is_file() and (trial / "source").is_dir()
    before = sorted(path.name for path in trial.iterdir())
    capsys.readouterr()

    refused = {
        "init": ["review", "init", str(trial), "--pack", str(checked_pack["pack"])],
        "record": ["review", "record", str(trial)],
        "approve": ["review", "approve", str(trial), "--reviewer", "R. Eviewer", "--note", "n"],
    }
    for argv in refused.values():
        code, _, err = cli(capsys, *argv)
        assert code == 2 and "which is itself the trial directory" in err
        assert err.startswith("scaneval: ") and "Traceback" not in err

    assert not (trial / "evaluator").exists()
    assert sorted(path.name for path in trial.iterdir()) == before


def test_writing_commands_refuse_an_output_that_is_itself_a_trial_directory(tmp_path, capsys,
                                                                           checked_pack):
    trial = tmp_path / "trial" / "snap-a"
    config = write_config(tmp_path)
    before = sorted(path.name for path in trial.iterdir())
    capsys.readouterr()

    for argv in (["demo", str(trial)], ["run", str(config), "--output", str(trial)]):
        code, _, err = cli(capsys, *argv)
        assert code == 2 and "which is itself the trial directory" in err
        assert err.startswith("scaneval: ") and "Traceback" not in err

    assert sorted(path.name for path in trial.iterdir()) == before
    assert not (trial / "evaluator").exists() and not (trial / "invocations").exists()


def test_a_pack_replaced_through_a_symlink_does_not_take_the_permissions_it_points_at(tmp_path,
                                                                                      capsys,
                                                                                      checked_pack):
    from scaneval import cli as cli_module
    from scaneval import review as review_module

    # The pack file and the review record are replaced by one helper, so the two cannot drift.
    assert cli_module._keep_mode is review_module._keep_mode

    target = checked_pack["pack"]
    target.chmod(0o666)
    linked = tmp_path / "linked-pack.json"
    linked.symlink_to(target)
    capsys.readouterr()

    assert main(["corpus", "disposition", str(linked), "--case-id", "case-finding",
                 "--value", "validate", "--reason", "evidence reviewed"]) == 0

    # os.replace puts a regular file where the link was; it keeps the temporary file's own
    # owner-only mode rather than widening itself to the mode of the file the link pointed at.
    assert not linked.is_symlink() and linked.is_file()
    assert linked.stat().st_mode & 0o777 == 0o600
    assert target.stat().st_mode & 0o777 == 0o666
    assert read_pack(linked)["cases"][0]["disposition"]["value"] == "validate"
    assert read_pack(target)["cases"][0]["disposition"]["value"] == "needs_evidence"


@pytest.mark.parametrize("reviewer", ["\u200b", "\u200b\u200b\ufeff", "\xad"])
def test_review_approve_refuses_a_reviewer_name_made_only_of_format_characters(tmp_path, capsys,
                                                                               checked_pack,
                                                                               reviewer):
    bundle = make_bundle(tmp_path, checked_pack)
    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    record_path = bundle / "evaluator" / "review-record.json"
    before = record_path.read_bytes()
    capsys.readouterr()

    code, _, err = cli(capsys, "review", "approve", str(bundle), "--reviewer", reviewer,
                       "--note", "read them")
    assert code == 2 and "explicit reviewer name" in err
    assert record_path.read_bytes() == before
    assert load_document(record_path, "review-record")["state"] == "draft"


def test_every_corpus_command_that_rewrites_a_pack_refuses_one_inside_a_trial_directory(tmp_path, capsys,
                                                                                        checked_pack):
    """A pack a command would rewrite is evaluator material, so it never lives in exported source."""
    trial = tmp_path / "trial" / "snap-a"
    assert (trial / "provenance.json").is_file() and (trial / "source").is_dir()
    planted = trial / "source" / "pack.json"
    planted.write_bytes(checked_pack["pack"].read_bytes())
    before = planted.read_bytes()
    capsys.readouterr()

    mutating = {
        "add-snapshot": snapshot_argv(planted, checked_pack["repo"], checked_pack["commit"], "snap-b"),
        "import": import_argv(planted, "case-second", "--finding", str(write_finding(tmp_path))),
        "validate": ["corpus", "validate", str(planted), "--snapshot-id", "snap-a",
                     "--cache-root", str(tmp_path / "planted-cache"),
                     "--trial-root", str(tmp_path / "planted-trial")],
        "approve": ["corpus", "approve", str(planted), "--case-id", "case-finding",
                    "--reviewer", "R. Eviewer", "--role", "curator", "--level", "L2",
                    "--note", "structural review"],
        "admit": ["corpus", "admit", str(planted), "--case-id", "case-finding", "--decision",
                  "admitted", "--by", "J. Curator", "--reason", "pilot slice"],
        "disposition": ["corpus", "disposition", str(planted), "--case-id", "case-finding",
                        "--value", "validate", "--reason", "evidence reviewed"],
    }
    for argv in mutating.values():
        code, _, err = cli(capsys, *argv)
        assert code == 2 and "inside the trial directory" in err
        assert err.startswith("scaneval: ") and "Traceback" not in err
        assert planted.read_bytes() == before
    assert not (tmp_path / "planted-cache").exists() and not (tmp_path / "planted-trial").exists()

    # The read-only spelling writes nothing, so it still summarizes a pack wherever it sits.
    code, out, _ = cli(capsys, "corpus", "validate", str(planted))
    assert code == 0 and json.loads(out)["pack_id"] == "cli-pilot"


def test_review_status_refuses_a_bundle_inside_a_trial_directory(tmp_path, capsys, checked_pack):
    """Every review subcommand treats a trial directory the same way, reading ones included."""
    trial = tmp_path / "trial" / "snap-a"
    planted = trial / "source" / "bundle"
    planted.mkdir(parents=True)
    capsys.readouterr()

    code, out, err = cli(capsys, "review", "status", str(planted))
    assert code == 2 and "inside the trial directory" in err and out == ""
    assert err.startswith("scaneval: ") and "Traceback" not in err

    code, out, err = cli(capsys, "review", "status", str(trial))
    assert code == 2 and "which is itself the trial directory" in err and out == ""

    outside = make_bundle(tmp_path, checked_pack)
    capsys.readouterr()
    code, out, _ = cli(capsys, "review", "status", str(outside))
    assert code == 0 and out.strip() == "missing"


def test_new_version_refuses_a_value_made_only_of_zero_width_characters(tmp_path, capsys, checked_pack):
    """A version made only of format characters is not a version a plan or report could cite."""
    pack = checked_pack["pack"]
    release_pack(pack)
    before = pack.read_bytes()
    capsys.readouterr()

    for version in ("\u200b", " \u200b\ufeff ", "\xad"):
        code, _, err = cli(capsys, "corpus", "admit", str(pack), "--case-id", "case-finding",
                           "--decision", "admitted", "--by", "J. Curator", "--reason", "pilot slice",
                           "--new-version", version)
        assert code == 2 and "non-blank version" in err
        assert pack.read_bytes() == before


def deep_json(depth: int = 200_000) -> str:
    """Nested past any recursion limit: the parser raises RecursionError rather than a value."""
    return "[" * depth + "]" * depth


def long_integer_json() -> str:
    """One integer literal past int_max_str_digits: the parser raises a bare ValueError."""
    digits = "1" * (sys.get_int_max_str_digits() + 1)
    return '{"allegation": "shell", "path": "src/app.py", "start_line": ' + digits + ', "end_line": 5}'


@pytest.mark.parametrize("text", [deep_json(), long_integer_json()],
                         ids=["nested-too-deep", "integer-too-long"])
def test_a_supplied_finding_the_parser_cannot_read_is_refused_naming_the_file(tmp_path, capsys,
                                                                             upstream, text):
    pack = pack_with_snapshot(tmp_path, upstream)
    finding = tmp_path / "unreadable-finding.json"
    finding.write_text(text, encoding="utf-8")
    capsys.readouterr()

    code, _, err = cli(capsys, *import_argv(pack, "case-finding", "--finding", str(finding)))
    assert code == 2 and f"could not load {finding}" in err
    assert err.startswith("scaneval: ") and "Traceback" not in err
    assert read_pack(pack)["cases"] == []


@pytest.mark.parametrize("text", [deep_json(), long_integer_json()],
                         ids=["nested-too-deep", "integer-too-long"])
def test_a_contract_file_the_parser_cannot_read_is_refused_naming_the_file(tmp_path, capsys, text):
    path = tmp_path / "unreadable-pack.json"
    path.write_text(text, encoding="utf-8")
    capsys.readouterr()

    code, _, err = cli(capsys, "validate", "case-pack", str(path))
    assert code == 2 and f"could not load {path}" in err
    assert err.startswith("scaneval: ") and "Traceback" not in err


def test_a_hand_edited_pack_cannot_claim_a_review_or_an_admission_by_an_unnamed_person(tmp_path, capsys,
                                                                                       checked_pack):
    """The write paths refuse a blank name; the contract must refuse one a text editor put there."""
    pack = checked_pack["pack"]
    assert main(["corpus", "disposition", str(pack), "--case-id", "case-finding", "--value",
                 "validate", "--reason", "evidence reviewed; worth validating"]) == 0
    assert main(["corpus", "approve", str(pack), "--case-id", "case-finding", "--reviewer",
                 "R. Eviewer", "--role", "independent_reviewer", "--level", "L3",
                 "--note", "read the source"]) == 0
    assert main(["corpus", "admit", str(pack), "--case-id", "case-finding", "--decision", "admitted",
                 "--by", "J. Curator", "--reason", "pilot slice"]) == 0
    reviewed = tmp_path / "reviewed-plan.json"
    assert main(["plan", "--pack", str(pack), "--snapshot-id", "snap-a", "--tree-hash",
                 checked_pack["tree_hash"], "--output", str(reviewed)]) == 0
    assert load_document(reviewed, "evaluation-plan")["scope"] == "reviewed"
    capsys.readouterr()

    document = read_pack(pack)
    document["cases"][0]["validation"]["reviews"][0]["reviewer"] = "\u200b"
    pack.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    code, _, err = cli(capsys, "validate", "case-pack", str(pack))
    assert code == 2 and "must name its reviewer" in err and "Traceback" not in err

    unnamed = tmp_path / "unnamed-plan.json"
    code, _, err = cli(capsys, "plan", "--pack", str(pack), "--snapshot-id", "snap-a", "--tree-hash",
                       checked_pack["tree_hash"], "--output", str(unnamed))
    assert code == 2 and "must name its reviewer" in err
    assert not unnamed.exists()

    document["cases"][0]["validation"]["reviews"][0]["reviewer"] = "R. Eviewer"
    document["admissions"][0]["by"] = "\u200b\ufeff"
    pack.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    code, _, err = cli(capsys, "validate", "case-pack", str(pack))
    assert code == 2 and "must name who decided it" in err and "Traceback" not in err


def test_a_hand_edited_review_record_cannot_report_an_approval_by_an_unnamed_person(tmp_path, capsys,
                                                                                    checked_pack):
    bundle = make_bundle(tmp_path, checked_pack)
    assert main(["review", "init", str(bundle), "--pack", str(checked_pack["pack"])]) == 0
    assert main(["review", "approve", str(bundle), "--reviewer", "R. Eviewer",
                 "--note", "read every routed claim"]) == 0
    record_path = bundle / "evaluator" / "review-record.json"
    capsys.readouterr()

    code, out, _ = cli(capsys, "review", "status", str(bundle))
    assert code == 0 and out.strip() == "human_approved"

    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["reviews"][0]["reviewer"] = "\u200b"
    record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    code, out, err = cli(capsys, "review", "status", str(bundle))
    assert code == 2 and "must name its reviewer" in err and "human_approved" not in out

    code, _, err = cli(capsys, "replay", str(bundle))
    assert code == 2 and "must name its reviewer" in err and "Traceback" not in err
