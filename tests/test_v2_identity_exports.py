"""Strict identity exports bind pack answers and stop before scanning on policy failures."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

import test_v2_blinding as fixture
from scaneval import blinding, cases, materialize
from scaneval.contracts import ContractError, canonical_json, load_document, pack_anchor_digest
from scaneval.identity_policy import (MANIFEST_KIND, POLICY_ID, POLICY_VERSION, load_manifest)
from scaneval.materialize import MaterializationError
from scaneval.runner import run_from_config


ALIAS = {"category": "target_alias", "value": "CVE-2025-12345", "forms": ["CVE_2025_12345"]}


@pytest.fixture
def widget(tmp_path):
    return fixture.build_widget(tmp_path, fixture.FILES)


def strict_map(widget, **policy_changes):
    document = fixture.identity_reduced_map(widget, approved=False)
    document["identity_policy"] = {"policy_id": POLICY_ID, "version": POLICY_VERSION, "answer_aliases": [],
                                    "identity_tokens": list(fixture.PSEUDONYMS), **policy_changes}
    return fixture.reapproved(document)


def run(tmp_path, widget, document, *, aliases=None, pr=False):
    pack = (fixture.write_pr_pack if pr else fixture.write_pack)(tmp_path / "pack.json", widget)
    if aliases:
        pack["cases"][0]["canonical_target"]["aliases"] = aliases
        pack["anchor_sha256"] = pack_anchor_digest(pack)
        cases.save_pack(tmp_path / "pack.json", pack)
    blinding.save_map(tmp_path / "map.json", document)
    entry = ({**fixture.BLINDED_PR, "profile": "identity_reduced"} if pr else fixture.IDENTITY_REDUCED)
    fixture.write_config(tmp_path / "run.json", [{**entry, "blinding_map": "map.json"}])
    adapter = fixture.InspectingPrAdapter() if pr else fixture.IdentityInspectingAdapter()
    result = run_from_config(tmp_path / "run.json", tmp_path / "out", clock=fixture.CLOCK, adapters={"fake": adapter})
    return result, adapter, pack


def test_explicit_strict_policy_prepares_and_saves_a_verified_evaluator_manifest(tmp_path, widget):
    document = strict_map(widget)
    manifest, adapter, _ = run(tmp_path, widget, document)
    [row] = manifest["inputs"]
    trial = tmp_path / "out" / "inputs" / row["input_id"]
    record = json.loads((tmp_path / "out" / row["provenance_path"]).read_text())
    summary = record["identity_reduction"]

    assert row["preparation_failure"] is None and adapter.calls == 1
    assert summary["validation"] == {"state": "available", "reasons": []}
    assert summary["counts"]["removed_files"] == 2 and summary["counts"]["residual_cues"] > 0
    assert summary["manifest_path"] == "identity-transform.json"
    assert load_manifest(trial / summary["manifest_path"], summary, policy=document["identity_policy"],
                         map_sha256=blinding.map_sha256(document), original_tree_hash=record["original"]["tree_hash"],
                         transformed_tree_hash=record["trial"]["tree_hash"], requirements=[],
                         required_source_paths=["src/app.py"], source=trial / "source") == summary
    assert "identity-transform.json" not in adapter.seen["paths"]
    assert not (trial / "source" / "original").exists()


def test_legacy_removal_map_still_runs_but_its_strict_condition_is_unavailable(tmp_path, widget):
    manifest, adapter, _ = run(tmp_path, widget, fixture.identity_reduced_map(widget))
    [row] = manifest["inputs"]
    record = json.loads((tmp_path / "out" / row["provenance_path"]).read_text())
    assert row["preparation_failure"] is None and adapter.calls == 1
    assert record["identity_reduction"]["validation"]["state"] == "unavailable"


@pytest.mark.parametrize("failure", ["undeclared-answer", "source-answer", "instruction", "evaluator-artifact"])
def test_explicit_policy_failure_persists_refusal_evidence_and_never_calls_scanner(tmp_path, failure):
    extra = {"source-answer": {"src/answer.py": "# cVe_2025_12345\n"},
             "instruction": {"AGENTS.md": "Project instructions\n"},
             "evaluator-artifact": {"notes/export.json": json.dumps({"profile": "standard", "trial": {}, "source": {}})}}
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, **extra.get(failure, {})})
    declared = [ALIAS] if failure == "source-answer" else []
    document = strict_map(widget, answer_aliases=declared)
    aliases = [ALIAS["value"]] if failure in {"undeclared-answer", "source-answer"} else []

    manifest, adapter, _ = run(tmp_path, widget, document, aliases=aliases)

    [row] = manifest["inputs"]
    trial = tmp_path / "out" / "inputs" / row["input_id"]
    assert row["preparation_failure"]["type"] == "IdentityConditionUnavailable"
    assert row["tree_hash"] is None and manifest["invocations"][0]["status"] == "skipped" and adapter.calls == 0
    assert not (trial / "source").exists() and (trial / "original" / "source" / "src" / "app.py").is_file()
    refusal = json.loads((tmp_path / "out" / row["provenance_path"]).read_text())
    summary = refusal["identity_reduction"]
    record = load_document(trial / summary["manifest_path"], MANIFEST_KIND)
    assert summary["validation"]["state"] == record["validation"]["state"] == "unavailable"
    assert ALIAS["value"] not in canonical_json(summary)


@pytest.mark.parametrize("path", [".assistant/project-rules.md", "packages/a/.cursor/rules/project.mdc"])
def test_strict_policy_removes_reviewed_configured_and_nested_instruction_documents(tmp_path, path):
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, path: "Project instructions\n"})
    document = strict_map(widget, instruction_paths=[path])
    document["removals"].append(fixture.removal_entry(widget, "extra-instructions", path, "instruction_file"))
    fixture.reapproved(document)

    manifest, adapter, _ = run(tmp_path, widget, document)

    [row] = manifest["inputs"]
    assert row["preparation_failure"] is None and adapter.calls == 1 and path not in adapter.seen["paths"]
    record = json.loads((tmp_path / "out" / row["provenance_path"]).read_text())
    assert record["identity_reduction"]["validation"]["state"] == "available"


def test_strict_export_is_deterministic_and_needs_pack_answer_coverage(tmp_path, widget):
    document = strict_map(widget)
    pack = fixture.write_pack(tmp_path / "pack.json", widget)
    with pytest.raises(MaterializationError, match="needs the evaluator-side pack"):
        materialize.export_snapshot(fixture.cached(widget, "snap-a"), tmp_path / "missing-pack",
                                    profile="identity_reduced", blinding_map=document, snapshot_id="snap-a")
    assert not (tmp_path / "missing-pack").exists()
    records = [materialize.export_snapshot(fixture.cached(widget, "snap-a"), tmp_path / name,
                                           profile="identity_reduced", blinding_map=deepcopy(document),
                                           snapshot_id="snap-a", pack=pack, clock=fixture.CLOCK)
               for name in ("first", "second")]
    assert canonical_json(records[0]) == canonical_json(records[1])
    assert (tmp_path / "first" / "identity-transform.json").read_bytes() == \
        (tmp_path / "second" / "identity-transform.json").read_bytes()


def test_explicit_strict_policy_is_not_applied_to_metadata_blinded(tmp_path, widget):
    document = fixture.widget_map(widget, approved=False)
    document["identity_policy"] = {"policy_id": POLICY_ID, "version": POLICY_VERSION, "answer_aliases": []}
    fixture.reapproved(document)
    with pytest.raises(MaterializationError, match="metadata_blinded never applies a strict identity policy"):
        materialize.export_snapshot(fixture.cached(widget, "snap-a"), tmp_path / "trial", profile="metadata_blinded",
                                    blinding_map=document, snapshot_id="snap-a")
    assert not (tmp_path / "trial").exists()


def test_strict_pr_base_failure_removes_both_scanner_trees_and_keeps_both_manifests(tmp_path):
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, "docs/guide.md": "Widget guide\nCVE-2025-12345\n"})
    document = strict_map(widget, answer_aliases=[ALIAS])

    manifest, adapter, _ = run(tmp_path, widget, document, aliases=[ALIAS["value"]], pr=True)

    [row] = manifest["inputs"]
    trial = tmp_path / "out" / "inputs" / row["input_id"]
    assert row["preparation_failure"]["type"] == "IdentityConditionUnavailable" and adapter.calls == 0
    assert not (trial / "source").exists() and not (trial / "base" / "source").exists()
    assert (trial / "identity-transform.json").is_file() and (trial / "base" / "identity-transform.json").is_file()
    assert (trial / "original" / "base" / "source" / "docs" / "guide.md").is_file()


def test_strict_pr_success_verifies_both_snapshot_manifests_before_scanning(tmp_path, widget):
    manifest, adapter, _ = run(tmp_path, widget, strict_map(widget), pr=True)
    [row] = manifest["inputs"]
    trial = tmp_path / "out" / "inputs" / row["input_id"]
    assert row["preparation_failure"] is None and adapter.calls == 1
    for path in (trial / "identity-transform.json", trial / "base" / "identity-transform.json"):
        assert load_document(path, MANIFEST_KIND)["validation"]["state"] == "available"


def test_identity_dry_run_reports_strict_condition_separately_from_basic_export(tmp_path, widget, capsys):
    fixture.write_pack(tmp_path / "pack.json", widget)
    path = tmp_path / "map.json"
    blinding.save_map(path, strict_map(widget))
    arguments = ("blinding", "check", str(path), "--pack", str(tmp_path / "pack.json"),
                 "--cache-root", str(widget["cache"]), "--profile", "identity_reduced")
    code, printed, err = fixture.cli(capsys, *arguments)
    assert code == 0 and err == "" and "strict identity condition: available" in printed
    blinding.save_map(path, fixture.identity_reduced_map(widget))
    code, printed, err = fixture.cli(capsys, *arguments)
    assert code == 0 and err == "" and "strict identity condition: unavailable" in printed


def test_transformed_export_variant_directory_cannot_escape_staged_trial(tmp_path, widget):
    with pytest.raises(MaterializationError, match="variant directory must be empty or base"):
        blinding.export_identity_reduced(fixture.cached(widget, "snap-a"), tmp_path / "trial",
                                         fixture.identity_reduced_map(widget), snapshot_id="snap-a",
                                         variant_dir="../escape")
    assert not (tmp_path / "trial").exists() and not (tmp_path / "escape").exists()


def test_configured_instruction_alias_cannot_authorize_runtime_prompt_removal(tmp_path):
    path = "app/prompts/system.md"
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, path: "runtime prompt content"})
    document = strict_map(widget, instruction_paths=[path])
    document["removals"].append(fixture.removal_entry(widget, "runtime-prompt", path, "instruction_file"))
    fixture.reapproved(document)

    manifest, adapter, _ = run(tmp_path, widget, document)

    [row] = manifest["inputs"]
    assert adapter.calls == 0 and row["preparation_failure"]["type"] == "MaterializationError"
    assert "inside a runtime directory" in row["preparation_failure"]["message"]
    assert not (tmp_path / "out" / "inputs" / row["input_id"] / "source").exists()


@pytest.mark.parametrize("leak", ["answer", "repository", "revision"])
def test_strict_scanner_identifiers_cannot_reveal_cues_omitted_from_pseudonyms(tmp_path, widget, leak):
    document = strict_map(widget, answer_aliases=[ALIAS], identity_tokens=[])
    document["edits"] = []
    document["pseudonyms"] = [{"original": "unrelated-brand", "replacement": "neutral-brand"}]
    fixture.reapproved(document)
    fixture.write_pack(tmp_path / "pack.json", widget)
    blinding.save_map(tmp_path / "map.json", document)
    run_id = {"answer": "run-cve_2025_12345", "repository": "widget-review",
              "revision": "run-" + widget["commits"]["snap-a"][:12]}[leak]
    fixture.write_config(tmp_path / "run.json", [{**fixture.IDENTITY_REDUCED, "blinding_map": "map.json"}],
                          run_id=run_id)
    adapter = fixture.FakeAdapter()
    with pytest.raises(ContractError, match="exposes a strict identity cue"):
        run_from_config(tmp_path / "run.json", tmp_path / "out", clock=fixture.CLOCK, adapters={"fake": adapter})
    assert not (tmp_path / "out").exists() and adapter.calls == 0
