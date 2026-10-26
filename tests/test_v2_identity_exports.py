"""Strict identity exports bind pack answers and stop before scanning on policy failures."""

from copy import deepcopy
import json
from pathlib import Path
import tomllib

import pytest

import test_v2_blinding as fixture
from scaneval import blinding, cases, materialize
from scaneval.contracts import ContractError, canonical_json, load_document, pack_anchor_digest, validate_document
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


def run(tmp_path, widget, document, *, aliases=None, pr=False, scoring_location=None):
    pack = (fixture.write_pr_pack if pr else fixture.write_pack)(tmp_path / "pack.json", widget)
    if aliases or scoring_location:
        if scoring_location:
            kind, path, line = scoring_location
            location = (pack["cases"][0]["target"]["accepted_locations"][0] if kind == "target"
                        else pack["cases"][0]["controls"][0]["locations"][0])
            location.update(path=path, start_line=line, end_line=line)
    if aliases:
        pack["cases"][0]["canonical_target"]["aliases"] = aliases
    if aliases or scoring_location:
        pack["anchor_sha256"] = pack_anchor_digest(pack)
        cases.save_pack(tmp_path / "pack.json", pack)
    blinding.save_map(tmp_path / "map.json", document)
    entry = ({**fixture.BLINDED_PR, "profile": "identity_reduced"} if pr else fixture.IDENTITY_REDUCED)
    if scoring_location and scoring_location[0] == "control":
        entry = fixture.IDENTITY_REDUCED_FIXED
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
             "evaluator-artifact": {"notes/export.json": json.dumps({"profile": "standard",
                 "trial": {"tree_hash": "sha256:" + "1" * 64}, "source": {"commit": "a" * 40}})}}
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


ROLE_CHECK = "Reviewed package URL metadata; dependencies, runtime code, and security behavior do not read it."


def metadata_entry(widget, edit_id, path, field_path, replacement):
    expected = []
    for snapshot_id, exported in widget["exports"].items():
        if path not in exported.hashes:
            expected.append({"snapshot_id": snapshot_id, "state": "absent"})
            continue
        text = (widget["probes"][snapshot_id] / path).read_text()
        value = json.loads(text) if path.endswith(".json") else tomllib.loads(text)
        for key in field_path:
            value = value[key]
        expected.append({"snapshot_id": snapshot_id, "state": "present", "file_sha256": exported.hashes[path],
                         "original": value})
    return {"edit_id": edit_id, "path": path, "field_path": field_path, "replacement": replacement,
            "role_check": ROLE_CHECK, "rationale": "This reviewed metadata leaf carries public repository identity.",
            "expected": expected}


def test_reviewed_json_and_toml_metadata_exports_preserve_dependency_source_and_line_structure(tmp_path):
    package = {"name": "widget-cli", "homepage": "https://widget.invalid/home",
               "repository": {"type": "git", "url": "https://widget.invalid/repository"},
               "bugs": {"url": "https://widget.invalid/issues"}, "dependencies": {"widget-dep": "1.2.3"},
               "scripts": {"test": "node test.js"}}
    pyproject = '[project]\nname = "widget-cli"\ndependencies = ["widget-dep>=1"]\n[project.urls]\nHomepage = "https://widget.invalid/docs"\n'
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, "package.json": json.dumps(package, indent=2) + "\n",
                                            "pyproject.toml": pyproject})
    document = strict_map(widget)
    document["metadata_edits"] = [metadata_entry(widget, name, "package.json", keys, "https://example.invalid/" + name)
                                   for name, keys in (("homepage", ["homepage"]), ("repository", ["repository", "url"]),
                                                      ("bugs", ["bugs", "url"]))]
    document["metadata_edits"].append(metadata_entry(widget, "project-url", "pyproject.toml",
                                                     ["project", "urls", "Homepage"], "https://example.invalid/docs"))
    fixture.reapproved(document)

    manifest, adapter, _ = run(tmp_path, widget, document)

    [row] = manifest["inputs"]
    assert row["preparation_failure"] is None and adapter.calls == 1
    trial = tmp_path / "out" / "inputs" / row["input_id"]
    transformed = json.loads((trial / "source" / "package.json").read_text())
    assert transformed["name"] == package["name"] and transformed["dependencies"] == package["dependencies"]
    assert transformed["scripts"] == package["scripts"] and transformed["repository"]["type"] == "git"
    assert transformed["homepage"] == "https://example.invalid/homepage"
    assert tomllib.loads((trial / "source" / "pyproject.toml").read_text())["project"]["dependencies"] == ["widget-dep>=1"]
    for path in ("package.json", "pyproject.toml"):
        assert (trial / "source" / path).read_bytes().count(b"\n") == \
            (trial / "original" / "source" / path).read_bytes().count(b"\n")
    assert (trial / "source" / "src" / "app.py").read_bytes() == \
        (trial / "original" / "source" / "src" / "app.py").read_bytes()
    record = json.loads((tmp_path / "out" / row["provenance_path"]).read_text())
    assert len(record["blinding"]["metadata_edits"]) == 4
    assert record["identity_reduction"]["counts"]["changed_files"] == 4


@pytest.mark.parametrize("reason", ["duplicate-token", "scoring-overlap"])
def test_unsafe_or_ambiguous_metadata_edits_are_retained_and_reported(tmp_path, reason):
    package = {"homepage": "https://widget.invalid/home"}
    if reason == "duplicate-token":
        package["runtime_endpoint"] = package["homepage"]
    text = json.dumps(package, indent=2) + "\n"
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, "package.json": text})
    document = strict_map(widget)
    document["metadata_edits"] = [metadata_entry(widget, "homepage", "package.json", ["homepage"], "")]
    fixture.reapproved(document)

    manifest, adapter, _ = run(tmp_path, widget, document,
                               scoring_location=("target", "package.json", 2) if reason == "scoring-overlap" else None)

    [row] = manifest["inputs"]
    assert row["preparation_failure"] is None and adapter.calls == 1
    trial = tmp_path / "out" / "inputs" / row["input_id"]
    assert (trial / "source" / "package.json").read_text() == text
    record = json.loads((tmp_path / "out" / row["provenance_path"]).read_text())
    assert record["identity_reduction"]["counts"]["skipped_transformations"] == 1
    assert record["blinding"]["metadata_edits"] == []
    assert record["blinding"]["skipped_transformations"][0]["reason"]


def test_metadata_leaf_can_remove_an_answer_alias_without_rewriting_source(tmp_path):
    package = {"homepage": "https://example.invalid/" + ALIAS["value"], "dependencies": {"widget-dep": "1"}}
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, "package.json": json.dumps(package) + "\n"})
    document = strict_map(widget, answer_aliases=[ALIAS])
    document["metadata_edits"] = [metadata_entry(widget, "homepage", "package.json", ["homepage"], "")]
    fixture.reapproved(document)
    manifest, adapter, _ = run(tmp_path, widget, document, aliases=[ALIAS["value"]])
    [row] = manifest["inputs"]
    assert row["preparation_failure"] is None and adapter.calls == 1
    trial = tmp_path / "out" / "inputs" / row["input_id"]
    assert ALIAS["value"] not in (trial / "source" / "package.json").read_text()


def advisory_map(widget, path, *, role_check=True):
    document = strict_map(widget, answer_aliases=[ALIAS])
    removal = fixture.removal_entry(widget, "historical-advisory", path, "identity_document")
    if role_check:
        removal["role_check"] = "Historical identity prose; no runtime, security configuration, deployment, or scoring role."
    document["removals"].append(removal)
    return fixture.reapproved(document)


@pytest.mark.parametrize("path", ["SECURITY-ADVISORY.md", "security/advisories/CVE-2025-12345.md"])
def test_strict_reviewed_advisory_prose_can_be_removed_and_recorded(tmp_path, path):
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, path: ALIAS["value"] + " historical advisory\n"})
    manifest, adapter, _ = run(tmp_path, widget, advisory_map(widget, path), aliases=[ALIAS["value"]])
    [row] = manifest["inputs"]
    assert row["preparation_failure"] is None and adapter.calls == 1 and path not in adapter.seen["paths"]
    record = json.loads((tmp_path / "out" / row["provenance_path"]).read_text())
    assert record["identity_reduction"]["counts"]["removed_files"] == 3
    assert record["blinding"]["removals"][-1]["role_check"]


@pytest.mark.parametrize("path", ["SECURITY.md", "SECURITY.txt", "SECURITY-ADVISORY.yml",
                                  "src/SECURITY-ADVISORY.md", "tests/advisories/SECURITY-ADVISORY.md",
                                  "docs/prompts/SECURITY-ADVISORY.md", ".github/workflows/SECURITY-ADVISORY.md",
                                  "licenses/advisories/SECURITY-ADVISORY.md", "notes/SECURITY-ADVISORY.md"])
def test_advisory_role_check_cannot_bypass_protected_material(tmp_path, path):
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, path: "security material\n"})
    manifest, adapter, _ = run(tmp_path, widget, advisory_map(widget, path))
    assert manifest["inputs"][0]["preparation_failure"]["type"] == "MaterializationError" and adapter.calls == 0


@pytest.mark.parametrize("requirement", ["role-check", "strict-policy"])
def test_security_advisory_exception_requires_a_stated_strict_role_check(tmp_path, requirement):
    path = "SECURITY-ADVISORY.md"
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, path: "historical advisory\n"})
    document = advisory_map(widget, path, role_check=requirement != "role-check")
    if requirement == "strict-policy":
        document.pop("identity_policy")
        fixture.reapproved(document)
    manifest, adapter, _ = run(tmp_path, widget, document)
    assert manifest["inputs"][0]["preparation_failure"]["type"] == "MaterializationError" and adapter.calls == 0


@pytest.mark.parametrize("kind", ["target", "control"])
def test_advisory_removal_never_discards_accepted_scoring_evidence(tmp_path, kind):
    path = "SECURITY-ADVISORY.md"
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, path: "historical advisory\n"})
    with pytest.raises(ContractError, match="would remove labelled scoring path"):
        run(tmp_path, widget, advisory_map(widget, path), scoring_location=(kind, path, 1))
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("invalid", ["dependency-field", "inconsistent-file-hash", "missing-variant", "duplicate-selector"])
def test_reviewed_metadata_contract_rejects_unsafe_or_inconsistent_definitions(tmp_path, invalid):
    package = {"homepage": "https://widget.invalid/home", "repository": "https://widget.invalid/repository",
               "dependencies": {"widget-dep": "1"}}
    widget = fixture.build_widget(tmp_path, {**fixture.FILES, "package.json": json.dumps(package) + "\n"})
    document = strict_map(widget)
    document["metadata_edits"] = [metadata_entry(widget, field, "package.json", [field], "")
                                   for field in ("homepage", "repository")]
    if invalid == "dependency-field":
        document["metadata_edits"][0]["field_path"] = ["dependencies", "widget-dep"]
    elif invalid == "inconsistent-file-hash":
        document["metadata_edits"][1]["expected"][0]["file_sha256"] = "sha256:" + "0" * 64
    elif invalid == "missing-variant":
        document["metadata_edits"][0]["expected"].pop()
    else:
        document["metadata_edits"][1]["field_path"] = ["homepage"]
    with pytest.raises(ContractError):
        validate_document("blinding-map", document)
