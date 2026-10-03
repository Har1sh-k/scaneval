"""Metadata blinding: a reviewed map, applied only to documentation and display text, all or nothing.

The fixture is one local repository with a vulnerable and a fixed commit and one map covering both.
Every approval here is recorded by "Fixture Reviewer (fictional)": no test records, implies, or
stands in for a real person's review. The scanners are fake adapters; nothing touches the network,
calls a model, or sleeps.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Callable

import pytest

from scaneval import blinding, cases, materialize
from scaneval.adapters.base import Adapter, NativeOutcome
from scaneval.cli import _retained_in, main
from scaneval.contracts import ContractError, canonical_json, chain_digest, load_document, validate_document
from scaneval.execution import LOCAL_ISOLATION
from scaneval.materialize import MaterializationError
from scaneval.runner import run_from_config


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
AT = "2026-09-20T15:00:00+00:00"
REVIEWER = "Fixture Reviewer (fictional)"
REVIEW_NOTE = "Fixture approval recorded by a fictional reviewer; no person reviewed this map."
README_VULNERABLE = ("# Widget\n\nWidget runs shell commands for AcmeCorp teams.\n"
                     "Install it with pip install widget-cli.\n")
README_FIXED = README_VULNERABLE + "Widget 1.1 passes an argument list instead.\n"
GUIDE = "Widget guide\nRating: ***\n"
MKDOCS = "site_name: Widget Docs\n"
APP_VULNERABLE = ("# Widget core helpers\nimport subprocess\n\n\ndef run(cmd):\n"
                  "    return subprocess.run(cmd, shell=True)\n")
APP_FIXED = APP_VULNERABLE.replace("shell=True", "shell=False")
FILES = {"README.md": README_VULNERABLE, "docs/guide.md": GUIDE, "mkdocs.yml": MKDOCS,
         "src/app.py": APP_VULNERABLE, "LICENSE": "Copyright AcmeCorp\n",
         "package.json": '{"name": "widget-cli"}\n', ".github/workflows/ci.yml": "name: Widget CI\n",
         "CLAUDE.md": "Widget project notes for assistants.\n"}
PSEUDONYMS = {"Widget": "Sprocket", "AcmeCorp": "ExampleCo"}
EDITED = ("README.md", "docs/guide.md", "mkdocs.yml")
ROLE_CHECK = "mkdocs reads site_name only to title rendered pages; the application never reads mkdocs.yml."
REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
              "assumption, and adds a single-file Python sink for the blinding tests.")
BLINDED = {"snapshot_id": "snap-a", "profile": "metadata_blinded", "blinding_map": "widget-map.json"}
BLINDED_FIXED = {"snapshot_id": "snap-fixed", "profile": "metadata_blinded", "blinding_map": "widget-map.json"}


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


def build_widget(root: Path, files: dict[str, str]) -> dict:
    """A repository holding *files* with a vulnerable and a fixed commit, and a probe export of each.

    The fixed commit repairs the shell call, adds a README line naming the project again, and
    deletes the guide, so one map has to expect different bytes and counts per variant and one
    file present in one variant and absent in the other.
    """
    repo = root / "upstream"
    for relative, text in files.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "vulnerable", cwd=repo)
    vulnerable = git("rev-parse", "HEAD", cwd=repo)
    (repo / "README.md").write_text(README_FIXED, encoding="utf-8")
    (repo / "src" / "app.py").write_text(APP_FIXED, encoding="utf-8")
    (repo / "docs" / "guide.md").unlink()
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "fixed", cwd=repo)
    fixed = git("rev-parse", "HEAD", cwd=repo)
    commits = {"snap-a": vulnerable, "snap-fixed": fixed}
    exports, probes = {}, {}
    for snapshot_id, commit in commits.items():
        cached = materialize.fetch_snapshot(str(repo), commit, root / "cache")
        probes[snapshot_id] = root / "probe" / snapshot_id / "source"
        exports[snapshot_id] = materialize.export_tree(cached, probes[snapshot_id])
    return {"repo": repo, "commits": commits, "exports": exports, "probes": probes, "cache": root / "cache"}


@pytest.fixture
def widget(tmp_path: Path) -> dict:
    """The widget repository: :data:`FILES` at a vulnerable commit and at a fixed one."""
    return build_widget(tmp_path, FILES)


def cached(widget: dict, snapshot_id: str) -> materialize.CachedSnapshot:
    return materialize.fetch_snapshot(str(widget["repo"]), widget["commits"][snapshot_id], widget["cache"])


def edit_entry(widget: dict, edit_id: str, path: str, role: str, replacements: list[str], *,
               role_check: str | None = None) -> dict:
    """One edit whose expectations are read from the probe exports, as a curator would record them."""
    expected = []
    for snapshot_id, exported in widget["exports"].items():
        if path in exported.hashes:
            text = (widget["probes"][snapshot_id] / path).read_text(encoding="utf-8")
            expected.append({"snapshot_id": snapshot_id, "state": "present", "file_sha256": exported.hashes[path],
                             "occurrences": {token: text.count(token) for token in replacements}})
        else:
            expected.append({"snapshot_id": snapshot_id, "state": "absent"})
    entry = {"edit_id": edit_id, "path": path, "role": role,
             "rationale": f"{path} names the project in text no code reads.",
             "replacements": list(replacements), "expected": expected}
    if role_check is not None:
        entry["role_check"] = role_check
    return entry


def approve(document: dict, decision: str = "approve") -> dict:
    blinding.record_review(document, reviewer=REVIEWER, role="independent_reviewer", decision=decision,
                           note=REVIEW_NOTE, clock=CLOCK)
    return document


def reapproved(document: dict) -> dict:
    """Drop the recorded reviews and approve the map as it now stands, as the fictional reviewer."""
    document["reviews"] = []
    document.pop("reviews_sha256", None)
    return approve(document)


def widget_map(widget: dict, *, approved: bool = True) -> dict:
    document = {
        "schema_version": "2.1", "map_id": "widget-metadata", "map_version": "1",
        "repository": {"url": str(widget["repo"]), "name": "widget"},
        "pseudonyms": [{"original": original, "replacement": replacement}
                       for original, replacement in PSEUDONYMS.items()],
        "variants": [{"snapshot_id": snapshot_id, "commit": widget["commits"][snapshot_id],
                      "tree_hash": materialize.tree_hash(exported.hashes)}
                     for snapshot_id, exported in widget["exports"].items()],
        "edits": [edit_entry(widget, "readme-brand", "README.md", "non_runtime_branding", ["Widget", "AcmeCorp"]),
                  edit_entry(widget, "guide-title", "docs/guide.md", "documentation_identifier", ["Widget"]),
                  edit_entry(widget, "site-name", "mkdocs.yml", "display_metadata", ["Widget"],
                             role_check=ROLE_CHECK)],
        "reviews": [],
    }
    validate_document("blinding-map", document)
    return approve(document) if approved else document


def _variant(document: dict, snapshot_id: str) -> dict:
    return next(variant for variant in document["variants"] if variant["snapshot_id"] == snapshot_id)


def _edit(document: dict, edit_id: str) -> dict:
    return next(edit for edit in document["edits"] if edit["edit_id"] == edit_id)


def _expected(edit: dict, snapshot_id: str) -> dict:
    return next(entry for entry in edit["expected"] if entry["snapshot_id"] == snapshot_id)


# --- the map contract and its reviews ----------------------------------------------------------


def _pseudonyms(*pairs: tuple[str, str]) -> Callable[[dict], None]:
    def mutate(document: dict) -> None:
        document["pseudonyms"] = [{"original": original, "replacement": replacement} for original, replacement in pairs]
    return mutate


@pytest.mark.parametrize(("mutate", "match"), [
    (_pseudonyms(("Widget", " ​"), ("AcmeCorp", "ExampleCo")), r"pseudonyms\[0\].replacement is blank"),
    (_pseudonyms(("Widget", "Sprock et"), ("AcmeCorp", "ExampleCo")), "holds a line break"),
    (_pseudonyms(("Widget", "Widget"), ("AcmeCorp", "ExampleCo")), "with itself"),
    (_pseudonyms(("Widget", "Sprocket"), ("Widget", "ExampleCo")), "pseudonyms.original values must be unique"),
    (_pseudonyms(("Widget", "Sprocket"), ("AcmeCorp", "Sprocket")), "pseudonyms.replacement values must be unique"),
    (_pseudonyms(("Widget", "WIDGETS"), ("AcmeCorp", "ExampleCo")), "contains the original 'Widget'"),
    (_pseudonyms(("Widget", "Sprocket"), ("AcmeCorp", "ExampleCo"), ("Sprocket Inc", "Holdings")),
     "contains 'Sprocket', the replacement"),
], ids=["blank", "line-break", "identity", "duplicate-original", "duplicate-replacement",
        "replacement-holds-original", "original-holds-replacement"])
def test_the_map_contract_refuses_pseudonyms_that_cannot_be_applied_cleanly(widget, mutate, match):
    document = widget_map(widget, approved=False)
    mutate(document)
    with pytest.raises(ContractError, match=match):
        validate_document("blinding-map", document)


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda document: _edit(document, "readme-brand").update(path="../README.md"), "relative path"),
    (lambda document: _edit(document, "readme-brand").update(path="docs//README.md"), "normalized"),
    (lambda document: _edit(document, "site-name").pop("role_check"), "states its role_check"),
    (lambda document: _edit(document, "readme-brand").update(rationale="​"), "must state its rationale"),
    (lambda document: _edit(document, "guide-title")["replacements"].append("Gadget"), "no pseudonym declares"),
    (lambda document: _edit(document, "guide-title")["expected"].pop(), "one expectation for every variant"),
    (lambda document: _expected(_edit(document, "readme-brand"), "snap-a")["occurrences"].pop("AcmeCorp"),
     "must name exactly the tokens"),
    (lambda document: _edit(document, "guide-title").update(path="README.md"), "edits.path values must be unique"),
], ids=["escaping-path", "unnormalized-path", "display-without-role-check", "blank-rationale",
        "undeclared-token", "missing-variant", "miscounted-tokens", "two-edits-one-path"])
def test_the_map_contract_refuses_malformed_edits(widget, mutate, match):
    document = widget_map(widget, approved=False)
    mutate(document)
    with pytest.raises(ContractError, match=match):
        validate_document("blinding-map", document)


def test_the_map_contract_refuses_a_review_history_that_does_not_chain(widget):
    document = approve(widget_map(widget))
    assert len(document["reviews"]) == 2

    edited = deepcopy(document)
    edited["reviews"][0]["note"] = "rewritten afterwards"
    with pytest.raises(ContractError, match=r"reviews\[0\] does not chain"):
        validate_document("blinding-map", edited)
    truncated = deepcopy(document)
    truncated["reviews"].pop()
    with pytest.raises(ContractError, match="deleted from the end"):
        validate_document("blinding-map", truncated)
    headless = deepcopy(document)
    headless.pop("reviews_sha256")
    with pytest.raises(ContractError, match="reviews_sha256 is missing"):
        validate_document("blinding-map", headless)
    wiped = deepcopy(document)
    wiped["reviews"] = []
    with pytest.raises(ContractError, match="deleted whole"):
        validate_document("blinding-map", wiped)
    unnamed = deepcopy(document)
    unnamed["reviews"] = unnamed["reviews"][:1]
    unnamed["reviews"][0]["reviewer"] = "​"
    unnamed["reviews"][0]["chain_sha256"] = chain_digest(None, unnamed["reviews"][0], "blinding_review")
    unnamed["reviews_sha256"] = unnamed["reviews"][0]["chain_sha256"]
    with pytest.raises(ContractError, match="must name its reviewer"):
        validate_document("blinding-map", unnamed)


def test_a_map_is_approved_only_while_its_latest_review_approves_its_current_content(widget):
    document = widget_map(widget, approved=False)
    content, whole = blinding.content_digest(document), blinding.map_sha256(document)
    assert "unreviewed: no review is recorded" in blinding.approval_gap(document)

    approve(document)
    assert blinding.approval_gap(document) is None
    assert blinding.approving_reviews(document) == [{"reviewer": REVIEWER, "role": "independent_reviewer", "at": AT}]
    assert blinding.content_digest(document) == content, "a review is not part of what it approves"
    assert blinding.map_sha256(document) != whole, "but it is part of which map document was used"
    assert blinding.map_identity(document) == {"map_id": "widget-metadata", "map_version": "1",
                                               "map_sha256": blinding.map_sha256(document)}
    assert document["reviews"][-1]["content_sha256"] == content

    approve(document, "unresolved")
    assert f"reopened by {REVIEWER}" in blinding.approval_gap(document)
    assert blinding.approving_reviews(document) == [], "a reopening withdraws the approvals before it"
    approve(document)
    approve(document, "reject")
    assert f"rejected by {REVIEWER}" in blinding.approval_gap(document)
    approve(document)
    _edit(document, "readme-brand")["rationale"] = "Reworded after the approval."
    assert "edited after it was approved" in blinding.approval_gap(document)
    assert blinding.approving_reviews(document) == [], "no approval covers the edited content"
    approve(document)
    assert blinding.approval_gap(document) is None and len(blinding.approving_reviews(document)) == 1


def test_a_review_names_its_reviewer_role_and_decision_or_changes_nothing(widget):
    document = widget_map(widget, approved=False)
    before = deepcopy(document)

    for changes, match in (({"reviewer": " ​"}, "must name its reviewer; the tool never supplies one"),
                           ({"role": "maintainer"}, "review role must be one of curator, independent_reviewer"),
                           ({"decision": "accept"}, "review decision must be one of approve, reject, unresolved")):
        arguments = {"reviewer": REVIEWER, "role": "curator", "decision": "approve", "note": REVIEW_NOTE, **changes}
        with pytest.raises(ContractError, match=match):
            blinding.record_review(document, clock=CLOCK, **arguments)
    assert document == before


# --- the export ---------------------------------------------------------------------------------


def export_blinded(widget: dict, document: dict, trial: Path, snapshot_id: str = "snap-a") -> dict:
    return materialize.export_snapshot(cached(widget, snapshot_id), trial, profile="metadata_blinded",
                                       blinding_map=document, snapshot_id=snapshot_id, clock=CLOCK)


def blinded_text(text: str) -> str:
    for original, replacement in PSEUDONYMS.items():
        text = text.replace(original, replacement)
    return text


def file_map(root: Path) -> dict[str, str]:
    return {relative: materialize.sha256_file(path)[0]
            for relative, path in materialize.walk_regular_files(root).items()}


def test_the_standard_export_record_is_the_record_it_always_was(tmp_path, widget):
    """No new key, no changed value: blinding arguments play no part in a standard export."""
    snapshot = cached(widget, "snap-a")
    record = materialize.export_snapshot(snapshot, tmp_path / "trial", clock=CLOCK)
    named = materialize.export_snapshot(snapshot, tmp_path / "named", clock=CLOCK, snapshot_id="snap-a",
                                        blinding_map=None)

    assert canonical_json(named) == canonical_json(record)
    exported = widget["exports"]["snap-a"]
    assert record == {
        "schema_version": "2.0",
        "source": {"url": str(widget["repo"]), "commit": widget["commits"]["snap-a"],
                   "git_tree": snapshot.git_tree, "fetch_method": "cached"},
        "profile": "standard",
        "trial": {"root": "source", "tree_hash": materialize.tree_hash(exported.hashes), "file_count": 8,
                  "byte_count": sum(len(text.encode("utf-8")) for text in FILES.values())},
        "stripped": [], "skipped": [], "instruction_files": ["CLAUDE.md"], "synthetic_history": None,
        "exported_at": AT, "tool_versions": {"git": materialize.git_version()},
        "limits": ["Export removes original git history and controller state; it is not a sandbox.",
                   "Tracked regular files only: submodules and symbolic links are recorded as skipped.",
                   "Instruction files stay in the standard profile and are recorded as identity cues."],
    }
    assert not (tmp_path / "trial" / "original").exists()


def test_a_blinded_export_replaces_exactly_the_reviewed_occurrences_and_records_them(tmp_path, widget):
    document = widget_map(widget)
    trial = tmp_path / "trial"

    record = export_blinded(widget, document, trial)

    source, original = trial / "source", trial / "original" / "source"
    assert (source / "README.md").read_text(encoding="utf-8") == blinded_text(README_VULNERABLE)
    assert (source / "docs" / "guide.md").read_text(encoding="utf-8") == "Sprocket guide\nRating: ***\n"
    assert (source / "mkdocs.yml").read_text(encoding="utf-8") == "site_name: Sprocket Docs\n"
    for relative, text in FILES.items():
        assert (original / relative).read_text(encoding="utf-8") == text, "the original export is kept whole"
    applied = record["blinding"]
    assert record["schema_version"] == "2.1" and record["profile"] == "metadata_blinded"
    assert record["trial"]["tree_hash"] == applied["transformed_tree_hash"] == \
        materialize.hash_exported_tree(source)["tree_hash"]
    assert applied["original_tree_hash"] == materialize.hash_exported_tree(original)["tree_hash"] == \
        document["variants"][0]["tree_hash"]
    assert record["original"] == {"root": "original/source", "tree_hash": applied["original_tree_hash"],
                                  "file_count": 8, "byte_count": widget["exports"]["snap-a"].byte_count}
    assert {key: applied[key] for key in ("map_id", "map_version", "map_sha256")} == blinding.map_identity(document)
    assert applied["content_sha256"] == blinding.content_digest(document)
    assert applied["reviewers"] == [{"reviewer": REVIEWER, "role": "independent_reviewer", "at": AT}]
    assert [(edit["edit_id"], edit["path"], edit["changed_lines"], edit["occurrences"]) for edit in applied["edits"]] == [
        ("readme-brand", "README.md", [1, 3], {"Widget": 2, "AcmeCorp": 1}),
        ("guide-title", "docs/guide.md", [1], {"Widget": 1}),
        ("site-name", "mkdocs.yml", [1], {"Widget": 1})]
    for edit in applied["edits"]:
        assert edit["original_sha256"] == materialize.sha256_file(original / edit["path"])[0]
        assert edit["transformed_sha256"] == materialize.sha256_file(source / edit["path"])[0]
    assert all(check["result"] == "pass" for check in applied["validation"])
    assert {check["check"] for check in applied["validation"]} == {
        "map_contract", "approval", "repository", "variant_commit", "edit_path_class", "variant_tree",
        "edit_file_hash", "edit_occurrences", "edit_line_structure", "edit_structure", "unedited_files_unchanged"}
    assert [check["detail"][:len("site-name: parsed as the YAML block subset")] for check in applied["validation"]
            if check["check"] == "edit_structure"] == ["site-name: parsed as the YAML block subset"]
    assert applied["location_remapping"] == {"lines": "identity", "paths": "identity",
                                             "verified_paths": ["README.md", "docs/guide.md", "mkdocs.yml"]}
    # What stays: the package name the README must keep, source, license, manifest, CI, instructions.
    cues = applied["retained_identity_cues"]
    assert cues["instruction_files"] == ["CLAUDE.md"] and record["instruction_files"] == ["CLAUDE.md"]
    assert (cues["token_count"], cues["total_occurrences"], cues["path_count"]) == (2, 6, 6)
    assert {entry["path"] for entry in cues["paths"]} == {
        ".github/workflows/ci.yml", "CLAUDE.md", "LICENSE", "README.md", "package.json", "src/app.py"}
    assert "not anonymization" in " ".join(record["limits"])


def test_every_file_the_map_does_not_edit_is_byte_identical_to_the_original(tmp_path, widget):
    trial = tmp_path / "trial"
    export_blinded(widget, widget_map(widget), trial)

    before, after = file_map(trial / "original" / "source"), file_map(trial / "source")

    assert set(after) == set(before), "blinding never adds, removes, or renames a path"
    assert {path for path in before if after[path] != before[path]} == set(EDITED)
    for relative in before:
        modes = {stat.S_IMODE(os.stat(root / relative).st_mode)
                 for root in (trial / "original" / "source", trial / "source")}
        assert len(modes) == 1, f"{relative} changed its mode"


def test_an_edited_files_lines_map_to_the_original_as_the_identity(tmp_path, widget):
    trial = tmp_path / "trial"
    record = export_blinded(widget, widget_map(widget), trial)

    for relative in EDITED:
        old = (trial / "original" / "source" / relative).read_text(encoding="utf-8").split("\n")
        new = (trial / "source" / relative).read_text(encoding="utf-8").split("\n")
        assert len(new) == len(old)
        assert new == [blinded_text(line) for line in old], "line n is line n with its tokens replaced"
    checks = [check["detail"] for check in record["blinding"]["validation"] if check["check"] == "edit_line_structure"]
    assert checks == ["readme-brand: 4 line(s) before and after; each line maps to the same line",
                      "guide-title: 2 line(s) before and after; each line maps to the same line",
                      "site-name: 1 line(s) before and after; each line maps to the same line"]


def test_repeating_a_valid_transformation_gives_byte_identical_source_and_provenance(tmp_path, widget):
    document = widget_map(widget)

    first = export_blinded(widget, deepcopy(document), tmp_path / "first")
    second = export_blinded(widget, deepcopy(document), tmp_path / "second")

    assert canonical_json(first) == canonical_json(second)
    for tree in ("source", "original/source"):
        one, two = tmp_path / "first" / tree, tmp_path / "second" / tree
        assert file_map(one) == file_map(two)
        assert all((one / relative).read_bytes() == (two / relative).read_bytes() for relative in file_map(one))


def test_the_vulnerable_and_fixed_variants_use_one_map_with_the_same_pseudonyms(tmp_path, widget):
    document = widget_map(widget)

    vulnerable = export_blinded(widget, document, tmp_path / "vulnerable", "snap-a")
    fixed = export_blinded(widget, document, tmp_path / "fixed", "snap-fixed")

    assert vulnerable["blinding"]["map_sha256"] == fixed["blinding"]["map_sha256"]
    assert (tmp_path / "fixed" / "source" / "README.md").read_text(encoding="utf-8") == blinded_text(README_FIXED)
    assert "Sprocket 1.1 passes an argument list instead." in (tmp_path / "fixed" / "source" / "README.md").read_text(
        encoding="utf-8")
    assert not (tmp_path / "fixed" / "source" / "docs" / "guide.md").exists()
    assert [edit["edit_id"] for edit in fixed["blinding"]["edits"]] == ["readme-brand", "site-name"]
    assert fixed["blinding"]["edits"][0]["occurrences"] == {"Widget": 3, "AcmeCorp": 1}
    assert "guide-title: docs/guide.md is absent, as expected" in [
        check["detail"] for check in fixed["blinding"]["validation"] if check["check"] == "edit_absent"]


def test_a_dry_run_reports_an_unapproved_map_instead_of_refusing_it(tmp_path, widget):
    document = widget_map(widget, approved=False)

    with pytest.raises(MaterializationError, match="unreviewed"):
        export_blinded(widget, document, tmp_path / "refused")
    record = blinding.dry_run(document, cached(widget, "snap-a"), "snap-a", tmp_path / "dry", clock=CLOCK)

    assert "unreviewed" in blinding.approval_gap(document)
    assert record["blinding"]["reviewers"] == []
    assert "approval" not in {check["check"] for check in record["blinding"]["validation"]}
    assert not (tmp_path / "refused" / "source").exists()


# --- refusals: every one before a transformed tree exists and before any scanner runs ----------


def _ambiguous(document: dict, widget: dict) -> None:
    document["pseudonyms"].append({"original": "**", "replacement": "++"})
    guide = _edit(document, "guide-title")
    guide["replacements"].append("**")
    _expected(guide, "snap-a")["occurrences"]["**"] = 1


def _forbidden(path: str, replacements: list[str], role: str = "documentation_identifier",
               role_check: str | None = None) -> Callable[[dict, dict], None]:
    def mutate(document: dict, widget: dict) -> None:
        document["edits"].append(edit_entry(widget, "forbidden", path, role, replacements, role_check=role_check))
    return mutate


# Each refusal the acceptance list names: (mutation, whether the curator re-approved afterwards,
# the words the refusal carries). A structural edit is re-approved so the refusal reached is the
# one under test and not the approval check in front of it.
REFUSALS = {
    "stale-commit": (lambda document, widget: _variant(document, "snap-a").update(commit="0" * 40), True,
                     r"stale map: .* at commit 0{40}"),
    "stale-tree": (lambda document, widget: _variant(document, "snap-a").update(tree_hash="sha256:" + "0" * 64),
                   True, r"stale map: .* as tree sha256:0{64}"),
    "stale-file-hash": (lambda document, widget: _expected(_edit(document, "readme-brand"), "snap-a").update(
        file_sha256="sha256:" + "0" * 64), True, r"stale map: edit readme-brand: README\.md is expected at"),
    "unexpected-count": (lambda document, widget: _expected(_edit(document, "readme-brand"), "snap-a")[
        "occurrences"].update(Widget=3), True, "unexpected occurrence count"),
    "overlapping": (lambda document, widget: document["pseudonyms"].append(
        {"original": "Widget Docs", "replacement": "Handbook"}), True, "overlapping matches"),
    "ambiguous": (_ambiguous, True, r"'\*\*' overlaps itself .* ambiguous"),
    "python-file": (_forbidden("src/app.py", ["Widget"]), True, "neither documentation"),
    "license": (_forbidden("LICENSE", ["AcmeCorp"]), True, "license, attribution, or security file"),
    "package-json": (_forbidden("package.json", ["Widget"], "display_metadata", ROLE_CHECK), True,
                     r"dependency manifest.*\(package\.json\)"),
    "workflow": (_forbidden(".github/workflows/ci.yml", ["Widget"], "display_metadata", ROLE_CHECK), True,
                 r"under \.github/workflows/"),
    "unreviewed": (lambda document, widget: (document.update(reviews=[]), document.pop("reviews_sha256")), False,
                   "unreviewed: no review is recorded"),
    "rejected": (lambda document, widget: approve(document, "reject"), False, f"rejected by {re.escape(REVIEWER)}"),
    "reopened": (lambda document, widget: approve(document, "unresolved"), False,
                 f"reopened by {re.escape(REVIEWER)}"),
    "approval-of-older-content": (lambda document, widget: _edit(document, "readme-brand").update(
        rationale="Reworded after the approval."), False, "edited after it was approved"),
}


def refused_map(widget: dict, name: str) -> dict:
    mutate, reapprove, _ = REFUSALS[name]
    document = widget_map(widget)
    mutate(document, widget)
    if reapprove:
        reapproved(document)
    validate_document("blinding-map", document)
    return document


@pytest.mark.parametrize("name", sorted(REFUSALS))
def test_a_map_that_does_not_fit_is_refused_before_a_transformed_tree_exists(tmp_path, widget, name):
    document = refused_map(widget, name)
    trial = tmp_path / "trial"

    with pytest.raises(MaterializationError, match=REFUSALS[name][2]):
        export_blinded(widget, document, trial)

    assert not (trial / "source").exists(), "nothing is transformed unless every check passes"


def _other_repository(document: dict) -> str:
    document["repository"]["url"] = "https://example.invalid/other.git"
    return "snap-a"


def _absent_expected_but_present(document: dict) -> str:
    guide = _edit(document, "guide-title")
    guide["expected"] = [{"snapshot_id": "snap-a", "state": "absent"}, _expected(guide, "snap-fixed")]
    return "snap-a"


def _present_expected_but_missing(document: dict) -> str:
    guide = _edit(document, "guide-title")
    guide["expected"] = [_expected(guide, "snap-a"), {"snapshot_id": "snap-fixed", "state": "present",
                                                      "file_sha256": "sha256:" + "1" * 64,
                                                      "occurrences": {"Widget": 1}}]
    return "snap-fixed"


def _no_variant(document: dict) -> str:
    document["variants"] = [_variant(document, "snap-a")]
    for edit in document["edits"]:
        edit["expected"] = [_expected(edit, "snap-a")]
    return "snap-fixed"


@pytest.mark.parametrize(("mutate", "match"), [
    (_other_repository, "is for repository https://example.invalid/other.git"),
    (_absent_expected_but_present, r"stale map: edit guide-title: docs/guide\.md is expected to be absent"),
    (_present_expected_but_missing, r"stale map: edit guide-title: docs/guide\.md is expected in snapshot snap-fixed"),
    (_no_variant, "stale map: map widget-metadata 1 has no variant for snapshot snap-fixed"),
], ids=["other-repository", "absent-expected-but-present", "present-expected-but-missing", "no-variant"])
def test_a_map_written_for_another_repository_or_another_state_is_refused(tmp_path, widget, mutate, match):
    document = widget_map(widget)
    snapshot_id = mutate(document)
    reapproved(document)

    with pytest.raises(MaterializationError, match=match):
        export_blinded(widget, document, tmp_path / "trial", snapshot_id)
    assert not (tmp_path / "trial" / "source").exists()


def _one_file_edit(tmp_path: Path, widget: dict, content: bytes, pseudonyms: dict[str, str],
                   counts: dict[str, int]) -> tuple[dict, dict, Path, dict]:
    """A map whose one README edit is checked against a scratch file holding *content*."""
    source = tmp_path / "scratch"
    source.mkdir()
    (source / "README.md").write_bytes(content)
    digest = materialize.sha256_file(source / "README.md")[0]
    document = widget_map(widget, approved=False)
    document["pseudonyms"] = [{"original": original, "replacement": replacement}
                              for original, replacement in pseudonyms.items()]
    edit = {"edit_id": "readme-brand", "path": "README.md", "role": "non_runtime_branding",
            "rationale": "The README names the project in prose.", "replacements": sorted(counts),
            "expected": [{"snapshot_id": "snap-a", "state": "present", "file_sha256": digest,
                          "occurrences": dict(counts)}, {"snapshot_id": "snap-fixed", "state": "absent"}]}
    document["edits"] = [edit]
    validate_document("blinding-map", document)
    return document, edit, source, {"README.md": digest}


def test_a_replacement_that_forms_the_original_again_with_its_neighbours_is_refused(tmp_path, widget):
    """``Widget`` replaced by ``Wid`` inside ``Widgetget`` spells ``Widget`` again."""
    document, edit, source, hashes = _one_file_edit(tmp_path, widget, b"Widgetget\n",
                                                    {"Widget": "Wid", "AcmeCorp": "ExampleCo"}, {"Widget": 1})

    with pytest.raises(MaterializationError, match="replacing forms 'Widget' again"):
        blinding._edit_for(document, edit, "snap-a", source, hashes)


def test_a_file_that_is_not_strict_utf8_is_refused(tmp_path, widget):
    document, edit, source, hashes = _one_file_edit(tmp_path, widget, b"Widget caf\xe9\n",
                                                    PSEUDONYMS, {"Widget": 1})

    with pytest.raises(MaterializationError, match="is not strict UTF-8 text"):
        blinding._edit_for(document, edit, "snap-a", source, hashes)


@pytest.mark.parametrize(("path", "role", "role_check", "reason"), [
    ("README.md", "documentation_identifier", None, None),
    ("docs/guide.rst", "non_runtime_branding", None, None),
    ("mkdocs.yml", "display_metadata", ROLE_CHECK, None),
    ("mkdocs.yml", "non_runtime_branding", None, "only as display_metadata"),
    ("mkdocs.yml", "display_metadata", None, "states no role check"),
    ("README.md", "rebranding", None, "is not an edit role"),
    ("src/app.py", "documentation_identifier", None, "neither documentation"),
    ("scripts/build.sh", "documentation_identifier", None, "neither documentation"),
    ("CHANGES", "documentation_identifier", None, "neither documentation"),
    ("LICENSE", "documentation_identifier", None, "license"),
    ("License.md", "documentation_identifier", None, "license"),
    ("SECURITY.md", "documentation_identifier", None, "security"),
    ("AUTHORS.txt", "documentation_identifier", None, "attribution"),
    ("package.json", "display_metadata", ROLE_CHECK, "dependency manifest"),
    ("requirements-dev.txt", "documentation_identifier", None, "requirements*.txt"),
    ("CMakeLists.txt", "documentation_identifier", None, "cmakelists.txt"),
    ("pyproject.toml", "display_metadata", ROLE_CHECK, "pyproject.toml"),
    (".github/workflows/ci.yml", "display_metadata", ROLE_CHECK, "under .github/workflows/"),
    ("tools/.circleci/config.yml", "display_metadata", ROLE_CHECK, "under .circleci/"),
    (".env.example.txt", "documentation_identifier", None, ".env*"),
    ("CLAUDE.md", "documentation_identifier", None, "reads as instructions"),
    (".github/copilot-instructions.md", "documentation_identifier", None, "reads as instructions"),
    # Dependency files a suffix alone would have let through: any name holding requirements or
    # constraints that ends .txt, whatever comes before it, and anything in a requirements/ directory.
    ("dev-requirements.txt", "documentation_identifier", None, "*requirements*.txt"),
    ("test-requirements.txt", "non_runtime_branding", None, "*requirements*.txt"),
    ("docs/requirements_docs.txt", "documentation_identifier", None, "*requirements*.txt"),
    ("dev-constraints.txt", "documentation_identifier", None, "*constraints*.txt"),
    ("requirements/prod.txt", "documentation_identifier", None, "under requirements/"),
    ("Requirements/README.md", "documentation_identifier", None, "under requirements/"),
    ("backend/requirements/base.txt", "documentation_identifier", None, "under requirements/"),
    ("runtime.txt", "documentation_identifier", None, "runtime.txt"),
    # License and attribution files by their other names: copyright, third-party notices, licenses/.
    ("COPYRIGHT.txt", "documentation_identifier", None, "license, attribution, or security file"),
    ("Copyright-Notice.md", "documentation_identifier", None, "license, attribution, or security file"),
    ("THIRD-PARTY-NOTICES.txt", "documentation_identifier", None, "license, attribution, or security file"),
    ("docs/ThirdPartyLicenses.md", "documentation_identifier", None, "license, attribution, or security file"),
    ("third_party_credits.rst", "non_runtime_branding", None, "license, attribution, or security file"),
    ("LICENSES/MIT.txt", "documentation_identifier", None, "under licenses/"),
    ("vendor/licenses/Apache-2.0.txt", "documentation_identifier", None, "under licenses/"),
    # Instruction files in any case, and the local one.
    ("CLAUDE.local.md", "documentation_identifier", None, "reads as instructions"),
    ("docs/claude.local.MD", "documentation_identifier", None, "reads as instructions"),
    ("claude.md", "documentation_identifier", None, "reads as instructions"),
    ("docs/Agents.md", "non_runtime_branding", None, "reads as instructions"),
    ("GEMINI.MD", "documentation_identifier", None, "reads as instructions"),
    (".Claude/notes.md", "documentation_identifier", None, "reads as instructions"),
    (".GitHub/Copilot-Instructions.md", "documentation_identifier", None, "reads as instructions"),
    (".github/INSTRUCTIONS/backend.md", "documentation_identifier", None, "reads as instructions"),
    # Manifests and CI configuration that a display suffix and any stated role check let through.
    ("environment.yml", "display_metadata", ROLE_CHECK, "environment.yml"),
    ("ci/environment.yaml", "display_metadata", ROLE_CHECK, "environment.yaml"),
    ("bower.json", "display_metadata", ROLE_CHECK, "bower.json"),
    ("pubspec.yaml", "display_metadata", ROLE_CHECK, "pubspec.yaml"),
    ("compose.yaml", "display_metadata", ROLE_CHECK, "compose.yaml"),
    ("deploy/Compose.yml", "display_metadata", ROLE_CHECK, "compose.yml"),
    ("bitbucket-pipelines.yml", "display_metadata", ROLE_CHECK, "bitbucket-pipelines.yml"),
    (".github/codeql/codeql-config.yml", "display_metadata", ROLE_CHECK, "under .github/codeql/"),
])
def test_only_documentation_and_reviewed_display_metadata_may_be_edited(path, role, role_check, reason):
    gap = blinding.path_class_gap(path, role, role_check)
    if reason is None:
        assert gap is None
    else:
        assert gap is not None and reason in gap


@pytest.mark.parametrize("path", [
    "README.md", "docs/guide.rst", "docs/requirements.md", "docs/party-third.md", "docs/third-parties.md",
    "docs/on-copyright-and-licensing.md", "docs/claude-notes.md", "docs/my-agents.md", "docs/instructions.md",
    ".github/ISSUE_TEMPLATE/bug.md",
])
def test_a_document_that_only_resembles_a_forbidden_file_stays_editable(path):
    """The rules match a name's start, a dependency file's kind, or a directory, not any word in a path."""
    assert blinding.path_class_gap(path, "documentation_identifier") is None


def test_a_scanner_reads_an_instruction_file_by_any_case_and_a_blinded_export_lists_it():
    listed = ["CLAUDE.md"]
    paths = ["CLAUDE.md", "claude.md", "docs/Agents.md", "CLAUDE.local.md", ".CLAUDE/notes.md", "src/app.py",
             "docs/claude-notes.md", ".github/workflows/ci.yml", ".GITHUB/copilot-instructions.md"]
    assert blinding._instruction_files(paths, listed) == [
        ".CLAUDE/notes.md", ".GITHUB/copilot-instructions.md", "CLAUDE.local.md", "CLAUDE.md", "claude.md",
        "docs/Agents.md"]
    assert blinding._instruction_files(["src/app.py"], []) == []


# --- a display file keeps its structure: JSON, TOML, and INI ------------------------------------
#
# A replacement is written into a file as text, so the hash, occurrence, and line checks pass for one
# that turns valid JSON into invalid JSON. The first tests are that reproduction; the rest ask each
# format's check of a scratch file, where one edit needs no repository.


DISPLAY_JSON = '{"Widget": {"title": "Widget Docs", "tags": ["Widget", "docs"]}, "count": 3}\n'


@pytest.fixture
def display(tmp_path: Path) -> Callable[[str, str], dict]:
    """The widget repository with one more file, a display file: ``display("display.json", text)``."""
    return lambda path, text: build_widget(tmp_path / "display", {**FILES, path: text})


def display_map(widget: dict, path: str, replacement: str, *, tokens: tuple[str, ...] = ("Widget",)) -> dict:
    """An approved map whose one edit replaces *tokens* in the display file *path*; Widget becomes *replacement*."""
    document = widget_map(widget, approved=False)
    document["pseudonyms"][0]["replacement"] = replacement
    document["edits"] = [edit_entry(widget, "display", path, "display_metadata", list(tokens), role_check=ROLE_CHECK)]
    validate_document("blinding-map", document)
    return reapproved(document)


def test_a_replacement_that_breaks_a_json_display_file_is_refused_before_a_transformed_tree_exists(tmp_path, display):
    """The reviewer's reproduction: a quotation mark in an approved replacement made valid JSON invalid, and the
    hash, occurrence, and line checks all still passed."""
    widget = display("display.json", DISPLAY_JSON)
    trial = tmp_path / "trial"

    with pytest.raises(MaterializationError, match=r"blinding map refused: edit display: display\.json: the "
                                                    r"transformed file is not valid JSON \(Expecting"):
        export_blinded(widget, display_map(widget, "display.json", 'Sprock"et'), trial)

    assert not (trial / "source").exists(), "nothing is transformed unless every check passes"


def test_a_json_display_file_with_a_plain_replacement_is_verified_by_parsing_and_the_check_is_recorded(tmp_path,
                                                                                                       display):
    widget = display("display.json", DISPLAY_JSON)

    record = export_blinded(widget, display_map(widget, "display.json", "Sprocket"), tmp_path / "trial")

    transformed = (tmp_path / "trial" / "source" / "display.json").read_text(encoding="utf-8")
    assert transformed == DISPLAY_JSON.replace("Widget", "Sprocket")
    assert json.loads(transformed) == {"Sprocket": {"title": "Sprocket Docs", "tags": ["Sprocket", "docs"]},
                                       "count": 3}
    validation = record["blinding"]["validation"]
    assert all(check["result"] == "pass" for check in validation)
    assert [check["detail"] for check in validation if check["check"] == "edit_structure"] == [
        "display: parsed as strict JSON before and after; the result is the original with only the reviewed "
        "replacements applied to its keys and strings"]
    assert record["blinding"]["edits"][0]["occurrences"] == {"Widget": 3}


@pytest.mark.parametrize(("path", "text", "verified"), [
    ("display.toml", "title = \"Widget Docs\"\n[tool.Widget]\nname = 'Widget'\n", "parsed as TOML"),
    ("display.ini", "[site]\nname = Widget Docs\n; a Widget comment\n", "parsed as INI"),
    ("display.cfg", "[Widget]\nname = Widget Docs\n", "parsed as INI"),
], ids=["toml", "ini", "cfg"])
def test_toml_and_ini_display_files_are_verified_by_parsing_too(tmp_path, display, path, text, verified):
    widget = display(path, text)

    record = export_blinded(widget, display_map(widget, path, "Sprocket"), tmp_path / "trial")

    assert (tmp_path / "trial" / "source" / path).read_text(encoding="utf-8") == text.replace("Widget", "Sprocket")
    [structure] = [check for check in record["blinding"]["validation"] if check["check"] == "edit_structure"]
    assert structure["result"] == "pass" and structure["detail"].startswith(f"display: {verified} before and after")


def test_a_percent_sign_that_the_default_ini_reader_cannot_interpolate_is_refused_before_a_transformed_tree_exists(
        tmp_path, display):
    """Read as written the file keeps its structure; the default reader cannot read the value the replacement makes."""
    widget = display("display.ini", "[site]\nname = Widget Docs\n")
    trial = tmp_path / "trial"

    with pytest.raises(MaterializationError, match=r"blinding map refused: edit display: display\.ini: read with "
                                                    r"Python's default INI reader .*\(\[site\] name cannot be "
                                                    r"interpolated \(InterpolationSyntaxError\)"):
        export_blinded(widget, display_map(widget, "display.ini", "Sprocket 100%"), trial)

    assert not (trial / "source").exists()
    record = export_blinded(widget, display_map(widget, "display.ini", "Sprocket"), tmp_path / "plain")
    assert (tmp_path / "plain" / "source" / "display.ini").read_text(encoding="utf-8") == (
        "[site]\nname = Sprocket Docs\n")
    assert "edit_structure" in {check["check"] for check in record["blinding"]["validation"]}


def test_documentation_is_not_asked_for_structure_and_takes_any_reviewed_replacement(tmp_path, widget):
    document = widget_map(widget, approved=False)
    document["pseudonyms"][0]["replacement"] = 'Sprock"et: {a, [b]} #c'
    document["edits"] = [edit_entry(widget, "readme-brand", "README.md", "non_runtime_branding", ["Widget"])]
    reapproved(document)

    record = export_blinded(widget, document, tmp_path / "trial")

    assert 'Sprock"et: {a, [b]} #c runs shell commands' in (tmp_path / "trial" / "source" / "README.md").read_text(
        encoding="utf-8")
    assert "edit_structure" not in {check["check"] for check in record["blinding"]["validation"]}


def display_edit(tmp_path: Path, path: str, content: str, pseudonyms: dict[str, str] | None = None) -> blinding._Edit:
    """One edit of *path*, holding *content*, as ``_edit_for`` computes it on a scratch file: no export needed.

    The edit lists every pseudonym (by default Widget becomes Sprocket) and expects the counts *content* holds.
    """
    pseudonyms = pseudonyms or {"Widget": "Sprocket"}
    source = tmp_path / "scratch"
    (source / path).parent.mkdir(parents=True, exist_ok=True)
    (source / path).write_bytes(content.encode("utf-8"))
    digest = materialize.sha256_file(source / path)[0]
    document = {"pseudonyms": [{"original": original, "replacement": new} for original, new in pseudonyms.items()]}
    edit = {"edit_id": "display", "path": path, "role": "display_metadata", "replacements": list(pseudonyms),
            "expected": [{"snapshot_id": "snap-a", "state": "present", "file_sha256": digest,
                          "occurrences": {token: content.count(token) for token in pseudonyms}}]}
    return blinding._edit_for(document, edit, "snap-a", source, {path: digest})


def refusal(tmp_path: Path, path: str, content: str, pseudonyms: dict[str, str] | None = None) -> str:
    """The reason ``_edit_for`` refuses this edit of *path*, after the words every such refusal starts with."""
    prefix = f"blinding map refused: edit display: {path}"
    with pytest.raises(MaterializationError) as refused:
        display_edit(tmp_path, path, content, pseudonyms)
    assert str(refused.value).startswith(prefix)
    return str(refused.value)[len(prefix):]


# What each text becomes when Widget is replaced by the string beside it, for the edits that keep the structure.
JSON_ACCEPTED = {
    "nested": ('{"Widget": {"title": "Widget Docs", "tags": ["Widget", 3, 1.5, true, null]}, "n": -0.0}\n',
               "Sprocket"),
    "escapes-kept": ('{"title": "Widget \\"quoted\\" \\u00e9 \\\\ \\/"}\n', "Sprocket"),
    "byte-order-mark": ('\ufeff{"title": "Widget"}\n', "Sprocket"),
    "duplicate-keys-are-kept": ('{"a": "Widget", "a": "x", "b": [{}, []]}\n', "Sprocket"),
    "non-ascii-and-slash": ('{"title": "Widget"}\n', "Spr\u00f6cket/2"),
    "top-level-string": ('"Widget"\n', "Sprocket"),
}


@pytest.mark.parametrize("name", sorted(JSON_ACCEPTED))
def test_a_json_edit_that_keeps_the_structure_is_accepted(tmp_path, name):
    content, replacement = JSON_ACCEPTED[name]

    edit = display_edit(tmp_path, "display.json", content, {"Widget": replacement})

    assert edit.structure_check == "json" and edit.data.decode("utf-8") == content.replace("Widget", replacement)


KEEP = ("the transformed file does not keep the original's structure: it is not the original with only the "
        "reviewed replacements applied to its keys and strings ")
JSON_REFUSED = {
    "quotation-mark": ('{"title": "Widget Docs"}\n', {"Widget": 'Sprock"et'},
                       " the transformed file is not valid JSON (Expecting ',' delimiter"),
    "invalid-escape": ('{"title": "Widget Docs"}\n', {"Widget": "Sprocket\\"},
                       " the transformed file is not valid JSON (Invalid \\escape"),
    "injected-key": ('{"title": "Widget Docs"}\n', {"Widget": 'Wid", "x": "y'},
                     f"{KEEP}($ holds the keys ['title', 'x'], expected ['title'])"),
    "decoded-escape": ('{"title": "Widget Docs"}\n', {"Widget": "Sprocket\\u0021"},
                       f"{KEEP}($['title'] is 'Sprocket! Docs', expected 'Sprocket\\\\u0021 Docs')"),
    "merged-keys": ('{"Widget": 1, "Sprocket": 2}\n', {"Widget": "Sprocket"},
                    ": the replacements make the keys 'Widget' and 'Sprocket' of the mapping at $ the same key "
                    "'Sprocket', a duplicate that would merge two entries"),
    "merged-keys-below": ('{"a": [{"Widget": 1, "Sprocket": 2}]}\n', {"Widget": "Sprocket"},
                          ": the replacements make the keys 'Widget' and 'Sprocket' of the mapping at $['a'][0] the "
                          "same key 'Sprocket'"),
    "changed-number": ('{"n": 12, "s": "12"}\n', {"12": "13"}, "$['n'] is 13, expected 12"),
    "changed-type": ('{"on": true, "s": "true"}\n', {"true": "1"},
                     "$['on'] is an integer 1, expected a boolean True"),
    "changed-literal": ('{"a": null, "b": "null"}\n', {"null": "none"}, " the transformed file is not valid JSON ("),
    "token-spelled-with-an-escape": ('{"title": "Wid\\u0067et Docs"}\n', {"Widget": "Sprocket"},
                                     "$['title'] is 'Widget Docs', expected 'Sprocket Docs'"),
    # The parser's own words differ by Python version (3.13 says Illegal trailing comma), so only ours are asserted.
    "trailing-comma": ('{"title": "Widget",}\n', {"Widget": "Sprocket"},
                       " is not strict JSON, so an edit of it cannot be verified to keep its structure ("),
    "not-a-number": ('{"n": NaN, "s": "Widget"}\n', {"Widget": "Sprocket"},
                     " is not strict JSON, so an edit of it cannot be verified to keep its structure "
                     "(NaN is not JSON"),
    "comment": ('{"s": "Widget"} // note\n', {"Widget": "Sprocket"},
                " is not strict JSON, so an edit of it cannot be verified to keep its structure (Extra data"),
}


@pytest.mark.parametrize("name", sorted(JSON_REFUSED))
def test_a_json_edit_that_would_change_the_structure_or_cannot_be_verified_is_refused(tmp_path, name):
    content, pseudonyms, reason = JSON_REFUSED[name]

    assert reason in refusal(tmp_path, "display.json", content, pseudonyms)


def test_a_json_file_nested_too_deeply_to_read_is_refused_and_does_not_crash(tmp_path):
    content = "[" * 100_000 + '"Widget"' + "]" * 100_000

    reason = refusal(tmp_path, "display.json", content)

    assert " is not strict JSON, so an edit of it cannot be verified to keep its structure (nested too deeply" in reason


TOML_ACCEPTED = {
    "tables-and-strings": ('title = "Widget Docs"\n[tool.Widget]\nname = \'Widget\'\nn = 2\n'
                           'when = 1979-05-27T07:32:00Z\n[[items]]\nlabel = """Widget\ntwo"""\n', "Sprocket"),
    "literal-string-backslash": ("title = 'Widget Docs'\n", "Spr\\ocket"),
    "comment-and-spacing-not-compared": ('title   =   "Widget"   # the Widget\n', "Sprocket"),
}


@pytest.mark.parametrize("name", sorted(TOML_ACCEPTED))
def test_a_toml_edit_that_keeps_the_structure_is_accepted(tmp_path, name):
    content, replacement = TOML_ACCEPTED[name]

    edit = display_edit(tmp_path, "display.toml", content, {"Widget": replacement})

    assert edit.structure_check == "toml" and edit.data.decode("utf-8") == content.replace("Widget", replacement)


TOML_REFUSED = {
    "quotation-mark": ('title = "Widget Docs"\n', {"Widget": 'Sprock"et'},
                       " the transformed file is not valid TOML ("),
    "escape-in-a-basic-string": ('title = "Widget Docs"\n', {"Widget": "Sprocket\\n"},
                                 "$['title'] is 'Sprocket\\n Docs', expected 'Sprocket\\\\n Docs'"),
    "dotted-key": ("Widget = 1\n", {"Widget": "a.b"}, "$ holds the keys ['a'], expected ['a.b']"),
    "merged-tables": ("[Widget]\na = 1\n[Sprocket]\nb = 2\n", {"Widget": "Sprocket"},
                      ": the replacements make the keys 'Widget' and 'Sprocket' of the mapping at $ the same key "
                      "'Sprocket'"),
    "changed-integer": ("year = 2019\ntitle = \"2019\"\n", {"2019": "2020"}, "$['year'] is 2020, expected 2019"),
    "not-toml": ("title = \n", {"Widget": "Sprocket"},
                 " is not valid TOML, so an edit of it cannot be verified to keep its structure ("),
}


@pytest.mark.parametrize("name", sorted(TOML_REFUSED))
def test_a_toml_edit_that_would_change_the_structure_or_cannot_be_verified_is_refused(tmp_path, name):
    content, pseudonyms, reason = TOML_REFUSED[name]

    assert reason in refusal(tmp_path, "display.toml", content, pseudonyms)


INI_ACCEPTED = {
    "sections-and-options": ("[site]\nname = Widget Docs\nlong = one\n  Widget two\n; a Widget comment\n"
                             "[Widget]\nWidget name: x\n", "Sprocket"),
    "defaults": ("[DEFAULT]\nbrand = Widget\n[site]\nname = Widget\n", "Sprocket"),
    "percent-signs-are-not-interpolated": ("[site]\nname = 100%% Widget %(x)s ${y}\n", "Sprocket"),
    # Read the ways Python's configparser reads it, each of these reads as the original does with Widget replaced.
    "an-interpolated-reference-stays-consistent": ("[site]\nname = Widget Docs\nfull = %(name)s Guide\n", "Sprocket"),
    "an-option-that-overrides-a-default-keeps-overriding": ("[DEFAULT]\nname = x\n[site]\nname = Widget\n",
                                                            "Sprocket"),
    "a-value-no-interpolating-reader-could-read-was-never-asked-to": ("[site]\nname = Widget 100%\n", "Sprocket"),
    "names-that-differ-in-case-stay-apart-for-a-reader-that-keeps-case": (
        "[site]\nWidget Name = 1\nwidget name = 2\n", "Sprocket"),
    # Readers with inline comments end a header at a hash or semicolon, so they can read other sections than the raw parse.
    "a-header-an-inline-comment-reader-reads-as-another-section": ("[site] ; x]\nname = Widget\n", "Sprocket"),
    "a-header-that-is-one-section-as-written": ("[site] ; Widget]\nname = x\n", "Sprocket"),
    "an-inline-comment-in-the-original-is-cut-from-both-readings": (
        "[site]\nname = Widget ; the brand\nother = Widget # too\nthird = a;b Widget\n", "Sprocket"),
}


@pytest.mark.parametrize("name", sorted(INI_ACCEPTED))
@pytest.mark.parametrize("path", ["display.ini", "display.cfg"])
def test_an_ini_edit_that_keeps_the_structure_is_accepted(tmp_path, name, path):
    content, replacement = INI_ACCEPTED[name]

    edit = display_edit(tmp_path, path, content, {"Widget": replacement})

    assert edit.structure_check == "ini" and edit.data.decode("utf-8") == content.replace("Widget", replacement)


INI_REFUSED = {
    "another-option-value-split": ("[site]\nWidget name = x\n", {"Widget": "Sprocket=Inc"},
                                   "$['site'] holds the keys ['Sprocket'], expected ['Sprocket=Inc name']"),
    "a-comment-not-an-option": ("[site]\nWidget = 1\nother = 2\n", {"Widget": "#x"},
                                "$['site'] holds the keys ['other'], expected ['#x', 'other']"),
    "a-continuation-not-an-option": ("[site]\na = 1\nWidget = 2\n", {"Widget": " x"},
                                     "$['site'] holds the keys ['a'], expected ['a', ' x']"),
    "a-section-that-becomes-the-defaults": ("[Widget]\na = 1\n", {"Widget": "DEFAULT"},
                                            "$['DEFAULT'] is the defaults section"),
    "merged-sections": ("[Widget]\na = 1\n[Sprocket]\nb = 2\n", {"Widget": "Sprocket"},
                        ": the replacements make the keys 'Widget' and 'Sprocket' of the mapping at $ the same key "
                        "'Sprocket'"),
    "merged-options": ("[site]\nWidget = 1\nSprocket = 2\n", {"Widget": "Sprocket"},
                       "of the mapping at $['site'] the same key 'Sprocket'"),
    "no-section-header": ("name = Widget\n", {"Widget": "Sprocket"},
                          " is not a valid INI file, so an edit of it cannot be verified to keep its structure ("),
    "duplicate-option": ("[site]\na = Widget\na = 2\n", {"Widget": "Sprocket"},
                         " is not a valid INI file, so an edit of it cannot be verified to keep its structure ("),
    # Each of these keeps its structure as written, and breaks or changes when Python's configparser reads it.
    "a-percent-sign-the-default-reader-cannot-interpolate": (
        "[site]\nname = Widget Docs\n", {"Widget": "Sprocket 100%"},
        ": read with Python's default INI reader (option names folded to lower case, [DEFAULT] merged into each "
        "section, % interpolation), the transformed file does not read as the original with only the reviewed "
        "replacements applied to its names and values ([site] name cannot be interpolated "
        "(InterpolationSyntaxError), expected 'Sprocket 100% Docs')"),
    "a-replacement-that-interpolates-another-option": (
        "[site]\nname = Widget Docs\nsecret = s3cr3t\n", {"Widget": "%(secret)s"},
        "[site] name reads as 's3cr3t Docs', expected '%(secret)s Docs')"),
    "a-replacement-that-interpolates-in-the-extended-syntax": (
        "[site]\nname = Widget\nother = x\n", {"Widget": "${other}"},
        "read with option names folded to lower case, [DEFAULT] merged into each section, ${} interpolation, the "
        "transformed file does not read as the original"),
    "a-reference-left-pointing-at-a-renamed-option": (
        "[site]\nWidget = 1\nb = %(widget)s\n", {"Widget": "Sprocket"},
        "[site] b cannot be interpolated (InterpolationMissingOptionError), expected '1')"),
    "two-options-that-differ-only-in-case-once-one-is-renamed": (
        "[site]\nWidget = 1\nsprocket = 2\n", {"Widget": "Sprocket"},
        ": read with Python's default INI reader (option names folded to lower case, [DEFAULT] merged into each "
        "section, % interpolation), the original reads but the transformed file does not (While reading from "
        "'<string>' [line 3]: option 'sprocket' in section 'site' already exists)"),
    "a-section-option-that-starts-hiding-a-default": (
        "[DEFAULT]\nSprocket = 1\n[site]\nWidget = 2\n", {"Widget": "Sprocket"},
        ": read with Python's default INI reader (option names folded to lower case, [DEFAULT] merged into each "
        "section, % interpolation), the replacements make the options 'Sprocket' and 'Widget' of [site] the same "
        "option 'sprocket', so one would hide the other"),
    "a-default-that-starts-hiding-a-section-option": (
        "[DEFAULT]\nWidget = 1\n[site]\nSprocket = 2\n", {"Widget": "Sprocket"},
        "the replacements make the options 'Widget' and 'Sprocket' of [site] the same option 'sprocket', so one "
        "would hide the other"),
    "a-replacement-that-starts-an-inline-comment": (
        "[site]\nname = Widget\n", {"Widget": "Sprocket ; note"},
        ": read with option names folded to lower case, [DEFAULT] merged into each section, % interpolation, # and ; "
        "inline comments, the transformed file does not read as the original with only the reviewed replacements "
        "applied to its names and values ([site] name reads as 'Sprocket', expected 'Sprocket ; note')"),
    "a-replacement-that-starts-a-hash-comment-in-a-name": (
        "[site]\nWidget = 1\nother = 2\n", {"Widget": "Sprocket # x"},
        "the original reads but the transformed file does not ("),
    "an-escaped-percent-sign-reads-as-one-by-the-default-reader": (
        "[site]\nname = Widget Docs\n", {"Widget": "Sprocket 100%%"},
        "[site] name reads as 'Sprocket 100% Docs', expected 'Sprocket 100%% Docs')"),
    "a-percent-sign-in-the-one-value-the-original-could-be-read-with": (
        "[site]\nrate = 100%\nname = Widget\n", {"Widget": "Sprocket 5%"},
        "[site] name cannot be interpolated (InterpolationSyntaxError), expected 'Sprocket 5%')"),
}


@pytest.mark.parametrize("name", sorted(INI_REFUSED))
def test_an_ini_edit_that_would_change_the_structure_or_cannot_be_verified_is_refused(tmp_path, name):
    content, pseudonyms, reason = INI_REFUSED[name]

    assert reason in refusal(tmp_path, "display.ini", content, pseudonyms)


# --- a display file keeps its structure: YAML ---------------------------------------------------
#
# A YAML edit is verified only within a strict block subset (``blinding._parse_yaml``): block mappings and sequences
# of one-line plain and quoted scalars, and comments. A file outside it cannot be verified, so its edit is refused. A
# plain scalar is a string there only if neither YAML 1.1 nor YAML 1.2 reads it as a boolean, a null, a number, or a
# date, so a replacement that turns a string into one of those, or opens a flow collection, an anchor, a tag, a block
# scalar, or a comment, changes what the file reads as and is refused.


DISPLAY_YAML = 'Widget:\n  title: "Widget Docs"\n  tags:\n    - Widget\n    - docs\ncount: 3\n'
BOM = "\N{BYTE ORDER MARK}"
W = {"Widget": "Sprocket"}
COPYRIGHT = ('copyright: Copyright &copy; 2014 <a href="https://github.com/tomchristie">Tom Christie</a>, '
             'Maintained by the <a href="/about/release-notes/#maintenance-team">MkDocs Team</a>.\n')
MKDOCS_FULL = ("site_name: Widget Docs\nsite_description: The *Widget* documentation\n"
               "site_url: https://widget.example.org/\nrepo_url: https://github.com/widget/widget\n" + COPYRIGHT +
               "theme:\n  name: material\n  palette:\n    - scheme: default\n  features:\n    - navigation.tabs\n"
               "nav:\n  - Home: index.md\n  - Widget Guide: guide.md\n"
               "markdown_extensions:\n  - toc:\n      permalink: true\n")
BAD_ENTRY = "a line that is not a 'key: value' entry (a scalar on its own line, or a key without ':')"
BAD_INDENT = "a line more indented than the entries before it (a multi-line scalar, or misaligned indentation)"
NOT_CLOSED = "a quoted scalar that does not close on its line (a multi-line scalar)"
SAME_KEY = "which a reader may read as the same key as another in its mapping"
UNLOADABLE = "which readers take for a number or a date and cannot load"
MERGE_OR_VALUE = "a YAML 1.1 merge or value indicator"


def plain(text: str) -> blinding._NonString:
    """What the subset keeps of a plain scalar that a YAML reader may read as something other than a string."""
    return blinding._NonString(text)


def tree(node):
    """A parsed YAML file as Python values: a mapping as a dict (in the file's order), a scalar as the subset keeps
    it."""
    if isinstance(node, blinding._Pairs):
        return {key: tree(value) for key, value in node}
    if isinstance(node, list):
        return [tree(item) for item in node]
    return node


YAML_READS = {
    "a-mapping": ("a: b\nc: d e\n", {"a": "b", "c": "d e"}),
    "nested-mappings": ("a:\n  b:\n    c: d\n  e: f\ng: h\n", {"a": {"b": {"c": "d"}, "e": "f"}, "g": "h"}),
    "sequences-indented-and-indentless": ("a:\n  - b\n  - c\nd:\n- e\n- f\ng: h\n",
                                          {"a": ["b", "c"], "d": ["e", "f"], "g": "h"}),
    "a-sequence-at-the-top": ("- a\n-\n- 'b'\n-   c\n", ["a", plain(""), "b", "c"]),
    "compact-entries": ("- a: 1\n  b:\n  - x\n  - p: z\n    w: v\n-   c: d\n    e: f\n",
                        [{"a": plain("1"), "b": ["x", {"p": "z", "w": "v"}]}, {"c": "d", "e": "f"}]),
    "a-block-node-under-a-dash": ("-\n  a: b\n-\n  - c\n", [{"a": "b"}, ["c"]]),
    "an-indent-of-one-space": ("a:\n b: c\n d:\n  - e\n", {"a": {"b": "c", "d": ["e"]}}),
    "an-empty-value-before-the-next-entry-of-an-outer-sequence": ("- a:\n- b\n", [{"a": plain("")}, "b"]),
    "an-empty-value": ("a:\nb: # c\nd: e\n", {"a": plain(""), "b": plain(""), "d": "e"}),
    "plain-scalars-that-may-not-be-strings": (
        "k1: true\nk2: No\nk3: ~\nk4: null\nk5: 12\nk6: 0x1F\nk7: 0o17\nk8: 1e3\nk9: 2019-01-01\nk10: 1_0.5\n"
        "k11: 1:30\nk12: .inf\nk13: y\nk14: 007\nk15: +1\nk16: .5\nk17: 2001-12-14t21:59:43.10-05:00\n",
        {"k1": plain("true"), "k2": plain("No"), "k3": plain("~"), "k4": plain("null"), "k5": plain("12"),
         "k6": plain("0x1F"), "k7": plain("0o17"), "k8": plain("1e3"), "k9": plain("2019-01-01"),
         "k10": plain("1_0.5"), "k11": plain("1:30"), "k12": plain(".inf"), "k13": plain("y"), "k14": plain("007"),
         "k15": plain("+1"), "k16": plain(".5"), "k17": plain("2001-12-14t21:59:43.10-05:00")}),
    "plain-scalars-that-are-strings": (
        "a: tru\nb: 1.2.3\nc: 0xZZ\nd: 12 months\ne: v1.0\nf: a:b\ng: a #b\nh: a#b\ni: yes please\nj: 1,000\nk: .\n",
        {"a": "tru", "b": "1.2.3", "c": "0xZZ", "d": "12 months", "e": "v1.0", "f": "a:b", "g": "a", "h": "a#b",
         "i": "yes please", "j": "1,000", "k": "."}),
    "unicode-spaces-are-not-spaces": ("a: \xa0b\N{IDEOGRAPHIC SPACE}\nc: d\N{EM SPACE}e\n",
                                      {"a": "\xa0b\N{IDEOGRAPHIC SPACE}", "c": "d\N{EM SPACE}e"}),
    "quoted-scalars-are-strings": (
        "a: 'true'\nb: \"12\"\nc: '~'\nd: 'it''s'\ne: \"say \\\"hi\\\"\"\nf: ''\ng: \"\"\nh: '\\n'\ni: \"a # b: c\"\n",
        {"a": "true", "b": "12", "c": "~", "d": "it's", "e": 'say "hi"', "f": "", "g": "", "h": "\\n",
         "i": "a # b: c"}),
    "escapes": ('a: "\\0\\a\\b\\t\\n\\v\\f\\r\\e\\ \\"\\/\\\\\\N\\_\\L\\P"\nb: "\\x41\\xe9\\u00e9\\U0001F600"\n',
                {"a": "\0\a\b\t\n\v\f\r\x1b \"/\\\x85\xa0\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}",
                 "b": "A\xe9\xe9\N{GRINNING FACE}"}),
    "quoted-keys": ("\"a b\": 1\n'c: d': 2\n\"\": 3\n\"e\\tf\": 4\n",
                    {"a b": plain("1"), "c: d": plain("2"), "": plain("3"), "e\tf": plain("4")}),
    "keys-that-are-not-strings": ("200: ok\n404: missing\n", {plain("200"): "ok", plain("404"): "missing"}),
    "a-key-that-is-a-boolean": ("true: a\n", {plain("true"): "a"}),
    "spaces-before-the-colon": ("a : b\n\"c\"  : d\n", {"a": "b", "c": "d"}),
    "comments": ("# a\na: b # c\n\n   # d\ne: # f\n  - g #h\n#i\n  - 'j' # k\n", {"a": "b", "e": ["g", "j"]}),
    "a-document-start-marker": ("# a\n---   # b\n\na: b\n", {"a": "b"}),
    "a-byte-order-mark": (BOM + "a: b\n", {"a": "b"}),
    "carriage-returns-before-line-feeds": ("a: b\r\nc:\r\n  - d\r\n", {"a": "b", "c": ["d"]}),
    "no-line-feed-at-the-end": ("a: b", {"a": "b"}),
    "punctuation-inside-a-plain-scalar": (
        "a: The *Widget* docs\nb: Run `Widget --help`\nc: Follow @Widget\nd: x &y z\ne: a, b [c] {d}\n"
        "f: http://x.example/a?b=c\n",
        {"a": "The *Widget* docs", "b": "Run `Widget --help`", "c": "Follow @Widget", "d": "x &y z",
         "e": "a, b [c] {d}", "f": "http://x.example/a?b=c"}),
}


@pytest.mark.parametrize("name", sorted(YAML_READS))
def test_the_yaml_subset_reads_block_collections_and_scalars_as_yaml_does(name):
    text, expected = YAML_READS[name]

    parsed = blinding._parse_yaml(text)

    assert tree(parsed) == expected
    if isinstance(expected, dict):
        assert [key for key, _ in parsed] == list(expected), "the keys stay in the order the file wrote them"


@pytest.mark.parametrize("text", ["", "\n", "# a comment\n", "   \n\n", "---\n", "--- # a comment\n# another\n", BOM])
def test_an_empty_yaml_document_reads_as_null(text):
    assert blinding._parse_yaml(text) == plain("")


# Each edit here keeps the file's structure: Widget becomes Sprocket unless the case says otherwise.
YAML_ACCEPTED = {
    "the-mkdocs-site-name": (MKDOCS, W),
    "nested-mappings": ("Widget:\n  title: Widget Docs\n  theme:\n    name: Widget\n    palette:\n"
                        "      primary: indigo\n", W),
    "sequences-indented-and-indentless": ("nav:\n  - Widget: index.md\n  - Guide: guide.md\n"
                                          "extra:\n- Widget\n- docs\n", W),
    "a-sequence-at-the-top": ("- Widget\n- docs\n-\n- 'Widget'\n", W),
    "compact-entries": ("- name: Widget\n  tags:\n  - Widget\n  - docs\n-   title: Widget Docs\n    weight: 3\n", W),
    "quoted-values-and-escapes": ("single: 'Widget it''s'\n"
                                  "double: \"Widget \\\"quoted\\\" \\x41 \\u00e9 \\\\ \\/ \\t\"\nempty: ''\n", W),
    "quoted-keys": ("\"Widget\": 1\n'Widget two': 2\n", W),
    "full-line-and-trailing-comments": ("# Widget\nsite_name: Widget Docs # the Widget\n\n   # indented Widget\n"
                                        "nav:  # Widget\n  - a\n", W),
    "a-replacement-in-a-comment-that-holds-a-quotation-mark": ("# the Widget docs\nsite_name: Docs # Widget\n",
                                                               {"Widget": 'Sprock"et: {a, [b]} #c'}),
    "a-quotation-mark-in-a-plain-value": ("title: The Widget Docs\n", {"Widget": 'Sprock"et'}),
    "a-quotation-mark-in-a-single-quoted-value": ("title: 'The Widget Docs'\n", {"Widget": 'Sprock"et'}),
    "an-apostrophe-in-a-double-quoted-value": ('title: "The Widget Docs"\n', {"Widget": "Sprocket's"}),
    "a-colon-and-a-hash-in-a-quoted-value": ('title: "The Widget Docs"\n', {"Widget": "Sprocket: Inc #1"}),
    "the-mkdocs-copyright-line": (COPYRIGHT, {"Tom Christie": "Jane Doe"}),
    "a-description-holding-asterisks": ("site_description: The *Widget* documentation\n", W),
    "a-list-item-holding-asterisks": ("- The **Widget** documentation\n", W),
    "a-value-holding-an-at-sign": ("tagline: Follow @Widget for updates\n", W),
    "a-value-holding-backticks": ("description: Run `Widget --help` first\n", W),
    "a-url": ("repo_url: https://github.com/widget/widget\n", {"widget": "sprocket"}),
    "a-whole-mkdocs-file": (MKDOCS_FULL, {"Widget": "Sprocket", "widget": "sprocket", "Tom Christie": "Jane Doe"}),
    "values-that-are-not-strings-stay-as-they-are": ("year: 2019\nflag: true\nnothing:\nratio: 1.5\nwhen: 2019-01-01\n"
                                                     "title: Widget Docs\n", W),
    "keys-that-are-not-strings-stay-as-they-are": ("200: Widget ok\n404: missing\n", W),
    "a-single-key-that-is-a-boolean": ("true: Widget\n", W),
    "a-null-value-and-a-null-item": ("Widget:\nnav:\n-\n- Widget\n", W),
    "a-document-start-marker": ("# Widget\n---  # Widget\nsite_name: Widget\n", W),
    "a-byte-order-mark": (BOM + "site_name: Widget Docs\n", W),
    "carriage-return-line-feeds": ("site_name: Widget Docs\r\nnav:\r\n  - Widget\r\n", W),
    "no-final-line-feed": ("site_name: Widget Docs", W),
    "an-empty-file": ("", W),
    "a-key-of-the-longest-length-readers-allow": ("k" * 1024 + ": Widget\n", W),
    "a-quoted-key-of-the-longest-length-readers-allow": ('"' + "k" * 1022 + '": Widget\n', W),
    "unicode-spaces-at-the-ends-of-a-plain-value": ("title: \xa0Widget\N{IDEOGRAPHIC SPACE}\n", W),
    "non-ascii-text": ("title: Widget \xe9 \N{GRINNING FACE}\n", {"Widget": "Spr\xf6cket \N{GRINNING FACE}"}),
    "a-replacement-that-is-a-string-to-every-version": ("title: Widget\n", {"Widget": "Sprocket 12 months"}),
    "a-replacement-that-is-almost-a-number": ("title: Widget Docs\n", {"Widget": "1.2.3"}),
    "a-replacement-ending-a-plain-value-with-a-dash": ("title: The Widget\n", {"Widget": "Sprocket -"}),
    "a-backslash-in-a-single-quoted-value": ("title: 'Widget Docs'\n", {"Widget": "Sprocket\\n"}),
    "several-pseudonyms": ("Widget: AcmeCorp\nnav:\n  - Widget\n  - 'AcmeCorp Widget'\n",
                           {"Widget": "Sprocket", "AcmeCorp": "ExampleCo"}),
}


def replaced(text: str, pseudonyms: dict[str, str]) -> str:
    for original, replacement in pseudonyms.items():
        text = text.replace(original, replacement)
    return text


@pytest.mark.parametrize("name", sorted(YAML_ACCEPTED))
@pytest.mark.parametrize("path", ["display.yml", "display.yaml"])
def test_a_yaml_edit_that_keeps_the_structure_is_accepted(tmp_path, name, path):
    content, pseudonyms = YAML_ACCEPTED[name]

    edit = display_edit(tmp_path, path, content, pseudonyms)

    assert edit.structure_check == "yaml" and edit.data.decode("utf-8") == replaced(content, pseudonyms)


@pytest.mark.parametrize("replacement", [
    'Sprock"et', "it's", "Sprocket & Sons", "Sprocket*", "50% Sprocket", "Sprocket, Inc.", "@sprocket", "`sprocket`",
    "Sprocket - 2", "a#b", "Sprocket [beta]", "{x}", "Sprocket |", "Sprocket >", "Sprocket ? maybe", "Sprocket\\",
    "!sprocket", "%sprocket", "=sprocket", "<<sprocket", "~sprocket", "-sprocket", ":sprocket", "sprocket:x",
    "a b  c"])
def test_a_replacement_inside_a_plain_value_may_hold_yaml_punctuation_that_does_not_end_the_value(tmp_path,
                                                                                                   replacement):
    edit = display_edit(tmp_path, "display.yml", "title: The Widget Docs\n", {"Widget": replacement})

    assert edit.data.decode("utf-8") == f"title: The {replacement} Docs\n"


OUTSIDE = "is outside the YAML subset read here"


def transformed_outside(line: int, what: str) -> str:
    """The refusal when the transformed file leaves the subset at *line*, for the reason *what*."""
    return (f" the transformed file is not valid YAML within the subset this module reads (line {line}: {what} "
            f"{OUTSIDE})")


def retyped(text: str) -> str:
    """The refusal when the title, a string, becomes the plain scalar *text*, which is not one."""
    return f"{KEEP}($['title'] is a plain scalar {text!r} (read as a non-string), expected a string {text!r})"


YAML_REFUSED = {
    # The reviewer's reproduction, for each way of writing a value: a replacement is written in without quoting.
    "a-quotation-mark-in-a-double-quoted-value": ('title: "Widget Docs"\n', {"Widget": 'Sprock"et'},
                                                  transformed_outside(1, "text after a quoted scalar")),
    "an-apostrophe-in-a-single-quoted-value": ("title: 'Widget Docs'\n", {"Widget": "Sprocket's"},
                                               transformed_outside(1, "text after a quoted scalar")),
    "a-doubled-apostrophe-in-a-single-quoted-value": (
        "title: 'The Widget Docs'\n", {"Widget": "Sprocket''s"},
        "$['title'] is \"The Sprocket's Docs\", expected \"The Sprocket''s Docs\""),
    "a-quotation-mark-that-ends-a-quoted-key-and-starts-a-comment": (
        '"Widget": 1\n', {"Widget": 'a": 2 #'}, "$ holds the keys ['a'], expected ['a\": 2 #']"),
    "a-colon-and-a-space-in-a-plain-value": (
        "title: Widget Docs\n", {"Widget": "Sprocket: Inc"},
        transformed_outside(1, "a ':' in a value (a mapping on the line of another key)")),
    "a-colon-that-ends-a-plain-value": (
        "title: Widget\n", {"Widget": "Sprocket:"},
        transformed_outside(1, "a ':' in a value (a mapping on the line of another key)")),
    "a-colon-that-makes-a-list-item-a-mapping": ("- Widget\n- docs\n", {"Widget": "a: b"},
                                                 "$[0] is a mapping (('a', 'b'),), expected a string 'a: b'"),
    "a-space-and-a-hash-that-start-a-comment": ("title: Widget Docs\n", {"Widget": "Sprocket #1"},
                                                "$['title'] is 'Sprocket', expected 'Sprocket #1 Docs'"),
    "a-hash-that-starts-the-value": (
        "title: Widget Docs\n", {"Widget": "#a"},
        "$['title'] is a plain scalar '' (read as a non-string), expected a string '#a Docs'"),
    "an-anchor": ("title: Widget Docs\n", {"Widget": "&anchor"}, transformed_outside(1, "an anchor ('&')")),
    "an-alias": ("title: Widget Docs\n", {"Widget": "*alias"}, transformed_outside(1, "an alias ('*')")),
    "a-tag": ("title: Widget Docs\n", {"Widget": "!!int"}, transformed_outside(1, "a tag ('!')")),
    "a-flow-sequence": ("title: Widget Docs\n", {"Widget": "[a, b]"},
                        transformed_outside(1, "a flow collection ('[')")),
    "a-flow-mapping": ("title: Widget Docs\n", {"Widget": "{a: b}"},
                       transformed_outside(1, "a flow collection ('{')")),
    "a-literal-block-scalar": ("title: Widget Docs\n", {"Widget": "|"}, transformed_outside(1, "a block scalar ('|')")),
    "a-folded-block-scalar": ("title: Widget Docs\n", {"Widget": ">"}, transformed_outside(1, "a block scalar ('>')")),
    "a-dash-that-starts-the-value": ("title: Widget Docs\n", {"Widget": "- a"},
                                     transformed_outside(1, "a scalar starting with '-'")),
    "a-question-mark-that-starts-the-value": (
        "title: Widget Docs\n", {"Widget": "? a"},
        transformed_outside(1, "an explicit key, or a scalar starting with '?'")),
    "a-percent-sign-that-starts-the-value": ("title: Widget Docs\n", {"Widget": "%a"},
                                             transformed_outside(1, "a reserved indicator ('%')")),
    "an-at-sign-that-starts-the-value": ("title: Widget Docs\n", {"Widget": "@a"},
                                         transformed_outside(1, "a reserved indicator ('@')")),
    "a-tab": ("title: Widget Docs\n", {"Widget": "a\tb"}, transformed_outside(1, "a tab outside a comment")),
    "a-control-character": (
        "title: Widget Docs\n", {"Widget": "a\x01b"},
        transformed_outside(1, "the character U+0001, which readers disagree on or refuse")),
    # A replacement that makes a whole plain scalar something other than a string.
    "a-boolean": ("title: Widget\n", {"Widget": "true"}, retyped("true")),
    "a-boolean-by-its-yaml-1-1-name": ("title: Widget\n", {"Widget": "yes"}, retyped("yes")),
    "a-boolean-by-another-name": ("title: Widget\n", {"Widget": "on"}, retyped("on")),
    "a-yaml-1-1-boolean-letter": ("title: Widget\n", {"Widget": "n"}, retyped("n")),
    "null": ("title: Widget\n", {"Widget": "null"}, retyped("null")),
    "a-tilde": ("title: Widget\n", {"Widget": "~"}, retyped("~")),
    "an-integer": ("title: Widget\n", {"Widget": "12"}, retyped("12")),
    "a-hexadecimal-integer": ("title: Widget\n", {"Widget": "0x1F"}, retyped("0x1F")),
    "an-octal-integer": ("title: Widget\n", {"Widget": "0o17"}, retyped("0o17")),
    "a-float-with-an-exponent": ("title: Widget\n", {"Widget": "1e3"}, retyped("1e3")),
    "a-float-with-an-underscore": ("title: Widget\n", {"Widget": "1_0.5"}, retyped("1_0.5")),
    "a-base-60-number": ("title: Widget\n", {"Widget": "1:30"}, retyped("1:30")),
    "a-date": ("title: Widget\n", {"Widget": "2019-01-01"}, retyped("2019-01-01")),
    "a-date-and-time": ("title: Widget\n", {"Widget": "2019-01-01 10:00:00"}, retyped("2019-01-01 10:00:00")),
    "a-date-and-time-with-an-offset": ("title: Widget\n", {"Widget": "2001-12-14t21:59:43.10-05:00"},
                                       retyped("2001-12-14t21:59:43.10-05:00")),
    "infinity": ("title: Widget\n", {"Widget": ".inf"}, retyped(".inf")),
    "a-boolean-in-a-list": ("- Widget\n", {"Widget": "true"}, "$[0] is a plain scalar 'true'"),
    "a-boolean-below-a-key-that-is-not-a-string": ("200:\n  title: Widget\n", {"Widget": "true"},
                                                   "$['200']['title'] is a plain scalar 'true'"),
    "a-boolean-as-a-key": ("Widget: 1\nb: 2\n", {"Widget": "true"},
                           "$ holds the keys ['true' (read as a non-string), 'b'], expected ['true', 'b']"),
    # A scalar that was not a string is not one a replacement may touch.
    "a-non-string-that-is-replaced": (
        'year: 2019\ntitle: "2019"\n', {"2019": "2020"},
        "$['year'] is '2020' (read as a non-string), expected '2019' (read as a non-string)"),
    "a-non-string-key-that-is-replaced": (
        "200: a\n", {"200": "300"},
        "$ holds the keys ['300' (read as a non-string)], expected ['200' (read as a non-string)]"),
    # Keys the replacements make the same key, or another kind of key.
    "two-keys-made-one": ("Widget: 1\nSprocket: 2\n", W,
                          ": the replacements make the keys 'Widget' and 'Sprocket' of the mapping at $ the same key "
                          "'Sprocket', a duplicate that would merge two entries"),
    "two-keys-made-one-below": ("a:\n  - Widget: 1\n    Sprocket: 2\n", W,
                                "of the mapping at $['a'][0] the same key 'Sprocket'"),
    "a-quoted-key-and-a-plain-key-made-one": ('"Widget": 1\nSprocket: 2\n', W, "the same key 'Sprocket'"),
    "a-key-made-the-merge-key": ("Widget: 1\n", {"Widget": "<<"},
                                 transformed_outside(1, f"the scalar '<<', {MERGE_OR_VALUE}")),
    "a-key-made-the-value-indicator": ("Widget: 1\n", {"Widget": "="},
                                       transformed_outside(1, f"the scalar '=', {MERGE_OR_VALUE}")),
    "a-key-made-one-that-yaml-1-2-reads-as-a-string": ('on: 1\n"Widget": 2\n', {"Widget": "on"},
                                                      transformed_outside(2, f"the key 'on', {SAME_KEY}")),
    "a-key-made-a-second-key-that-is-not-a-string": ("true: 1\nWidget: 2\n", {"Widget": "1"},
                                                     transformed_outside(2, f"the key '1', {SAME_KEY}")),
    # A backslash inside a double-quoted value is an escape, so what the file then holds is not what the map replaced.
    "an-escape-that-decodes-to-another-character": (
        'title: "Widget Docs"\n', {"Widget": "Sprocket\\n"},
        f"{KEEP}($['title'] is 'Sprocket\\n Docs', expected 'Sprocket\\\\n Docs')"),
    "an-escaped-backslash": ('title: "Widget Docs"\n', {"Widget": "Sprocket\\\\"},
                             "$['title'] is 'Sprocket\\\\ Docs', expected 'Sprocket\\\\\\\\ Docs'"),
    "an-escaped-quotation-mark": ('title: "Widget Docs"\n', {"Widget": 'Sprocket\\"'},
                                  "$['title'] is 'Sprocket\" Docs', expected 'Sprocket\\\\\" Docs'"),
    "an-escaped-space": ('title: "Widget Docs"\n', {"Widget": "Sprocket\\"},
                         "$['title'] is 'Sprocket Docs', expected 'Sprocket\\\\ Docs'"),
    "an-escaped-code-point": ('title: "Widget Docs"\n', {"Widget": "Sprocket\\u0021"},
                              "$['title'] is 'Sprocket! Docs', expected 'Sprocket\\\\u0021 Docs'"),
    "an-escape-yaml-does-not-have": ('title: "Widget Docs"\n', {"Widget": "Sprocket\\q"},
                                     transformed_outside(1, "the escape '\\q'")),
    "an-escape-with-too-few-digits": ('title: "Widget Docs"\n', {"Widget": "Sprocket\\x4"},
                                      transformed_outside(1, "the escape '\\x' without 2 hexadecimal digits")),
    "an-escape-that-is-not-a-character": (
        'title: "Widget Docs"\n', {"Widget": "Sprocket\\uD800"},
        transformed_outside(1, "the escape '\\uD800', which is not a Unicode scalar value")),
    "a-backslash-that-escapes-the-closing-quotation-mark": ('title: "Widget"\n', {"Widget": "Sprocket\\"},
                                                            transformed_outside(1, NOT_CLOSED)),
    "a-token-spelled-with-an-escape": ('title: "Wid\\x67et Docs"\n', W,
                                       "$['title'] is 'Widget Docs', expected 'Sprocket Docs'"),
    # The parsed values match, but ruamel.yaml reading YAML 1.1 takes an explicit '---' as a switch to 1.2, so the
    # untouched 'no' and 'yes' would read as strings after the first edit and as booleans after the second.
    "a-replacement-that-adds-the-document-start-marker": (
        "#Widget documentation site\nsite_name: Docs\nuse_directory_urls: no\nstrict: yes\n",
        {"#Widget": "--- #Sprocket"}, "the replacements add the '---' that starts the document, which ruamel.yaml "
                                      "reading YAML 1.1 takes as a switch to YAML 1.2"),
    "a-replacement-that-removes-the-document-start-marker": (
        "---\nsite_name: Widget Docs\nuse_directory_urls: no\n", {"---": "#"},
        "the replacements remove the '---' that starts the document"),
}


@pytest.mark.parametrize("name", sorted(YAML_REFUSED))
def test_a_yaml_edit_that_would_change_the_structure_is_refused_with_its_reason(tmp_path, name):
    content, pseudonyms, reason = YAML_REFUSED[name]

    assert reason in refusal(tmp_path, "display.yml", content, pseudonyms)


NOT_IN_THE_SUBSET = (" is not in the YAML subset this module reads (block mappings and sequences of one-line plain or "
                     "quoted scalars, and comments), so an edit of it cannot be verified to keep its structure "
                     "(line {line}: {what} " + OUTSIDE + ")")
# An original outside the subset cannot be verified, so even a harmless replacement is refused, naming the line and
# the construct.
YAML_OUTSIDE = {
    "a-flow-sequence": ("a: [Widget]\n", 1, "a flow collection ('[')"),
    "a-flow-mapping": ("a: {k: Widget}\n", 1, "a flow collection ('{')"),
    "an-anchor": ("a: &x Widget\nb: *x\n", 1, "an anchor ('&')"),
    "an-alias": ("a: Widget\nb: *x\n", 2, "an alias ('*')"),
    "a-tag": ("a: !!str Widget\n", 1, "a tag ('!')"),
    "a-literal-block-scalar": ("a: |\n  Widget\n", 1, "a block scalar ('|')"),
    "a-folded-block-scalar": ("a: >\n  Widget\n", 1, "a block scalar ('>')"),
    "a-multi-line-plain-scalar": ("a: Widget\n  and more\n", 2, BAD_INDENT),
    "a-multi-line-plain-scalar-in-a-list": ("- Widget\n  and more\n", 2, BAD_INDENT),
    "a-multi-line-double-quoted-scalar": ('a: "Widget\n  more"\n', 1, NOT_CLOSED),
    "a-multi-line-single-quoted-scalar": ("a: 'Widget\n  more'\n", 1, NOT_CLOSED),
    "an-escaped-line-break": ('a: "Widget\\\n  more"\n', 1, "a backslash at the end of a line (a multi-line scalar)"),
    "a-directive": ("%YAML 1.1\n---\na: Widget\n", 1, "a directive ('%')"),
    "a-document-end-marker": ("a: Widget\n...\n", 2, "a line starting with '...' (a document end marker)"),
    "a-second-document": ("a: Widget\n---\nb: 2\n", 2, "a second '---' (a document start marker)"),
    "content-after-the-document-start-marker": ("--- a: Widget\n", 1, "content after '---' on its line"),
    "a-tab-before-a-value": ("a:\tWidget\n", 1, "a tab outside a comment"),
    "a-tab-in-the-indentation": ("a:\n\tb: Widget\n", 2, "a tab outside a comment"),
    "a-tab-before-a-comment": ("a: Widget\t# note\n", 1, "a tab outside a comment"),
    "a-tab-in-a-quoted-scalar": ('a: "Widget\t"\n', 1, "a tab outside a comment"),
    "a-lone-carriage-return": ("a: Widget\rb: 1\n", 1, "a carriage return that does not end a line"),
    "a-next-line-character": ("a: Widget\x85\n", 1, "the character U+0085, which readers disagree on or refuse"),
    "a-line-separator": ("a: Widget\N{LINE SEPARATOR}\n", 1,
                         "the character U+2028, which readers disagree on or refuse"),
    "a-control-character": ("a: Wid\x07get\n", 1, "the character U+0007, which readers disagree on or refuse"),
    "a-second-byte-order-mark": (BOM + BOM + "a: Widget\n", 1, "a byte-order mark inside the text"),
    "a-byte-order-mark-after-the-first-line": ("a: Widget\n" + BOM + "b: 1\n", 2, "a byte-order mark inside the text"),
    "a-duplicate-key": ("a: Widget\na: 2\n", 2, "the duplicate key 'a'"),
    "a-duplicate-key-once-quoted": ("a: Widget\n'a': 2\n", 2, "the duplicate key 'a'"),
    "keys-that-one-reader-reads-as-one": ("yes: Widget\ntrue: 2\n", 2, f"the key 'true', {SAME_KEY}"),
    "a-plain-key-and-a-quoted-one-that-one-reader-reads-as-one": ('"no": Widget\nno: 2\n', 2,
                                                                 f"the key 'no', {SAME_KEY}"),
    "a-merge-key": ("<<: Widget\n", 1, f"the scalar '<<', {MERGE_OR_VALUE}"),
    "a-merge-indicator-as-a-value": ("a: <<\nb: Widget\n", 1, f"the scalar '<<', {MERGE_OR_VALUE}"),
    "a-value-indicator": ("a: =\nb: Widget\n", 1, f"the scalar '=', {MERGE_OR_VALUE}"),
    "an-explicit-key": ("? a\n: Widget\n", 1, "an explicit key, or a scalar starting with '?'"),
    "a-sequence-on-the-line-of-its-entry": ("- - Widget\n", 1, "a sequence on the line of its entry ('- -')"),
    "a-scalar-document": ("Widget\n", 1, BAD_ENTRY),
    "a-quoted-scalar-document": ('"Widget"\n', 1, BAD_ENTRY),
    "a-line-without-a-colon": ("a: 1\nWidget\n", 2, BAD_ENTRY),
    "a-scalar-on-the-line-after-a-key": ("a:\n  Widget\n", 2, BAD_ENTRY),
    "a-line-indented-to-no-collection": ("a:\n    b: Widget\n  c: 1\n", 3, BAD_INDENT),
    "a-line-that-continues-no-collection": ("  a: Widget\nb: 1\n", 2,
                                            "a line that continues no collection (misaligned indentation)"),
    "a-sequence-entry-among-mapping-entries": ("a: 1\n- Widget\n", 2, "a sequence entry among mapping entries"),
    "a-number-written-with-only-underscores": ("a: +_\nb: Widget\n", 1, f"the scalar '+_', {UNLOADABLE}"),
    "a-date-that-does-not-exist": ("a: 2019-02-30\nb: Widget\n", 1, f"the scalar '2019-02-30', {UNLOADABLE}"),
    "a-key-longer-than-readers-allow": ("k" * 1025 + ": Widget\n", 1, "a key longer than 1024 characters"),
    "a-scalar-starting-with-a-dash": ("a: -1\nb: Widget\n", 1, "a scalar starting with '-'"),
    "a-key-starting-with-a-dash": ("-a: Widget\n", 1, "a scalar starting with '-'"),
    "a-scalar-starting-with-a-colon": ("a: :b\nb: Widget\n", 1, "a scalar starting with ':'"),
    "a-closing-bracket": ("a: ]\nb: Widget\n", 1, "a flow indicator (']')"),
    "a-closing-brace": ("a: }\nb: Widget\n", 1, "a flow indicator ('}')"),
    "a-comma": ("a: , Widget\n", 1, "a flow indicator (',')"),
    "a-percent-sign-after-the-first-line": ("a: 1\n%b: Widget\n", 2, "a directive ('%')"),
    "an-at-sign": ("a: @Widget\n", 1, "a reserved indicator ('@')"),
    "a-backtick": ("a: `Widget`\n", 1, "a reserved indicator ('`')"),
    "text-after-a-quoted-scalar": ('a: "Widget" x\n', 1, "text after a quoted scalar"),
    "a-comment-against-a-quoted-scalar": ('a: "Widget"# note\n', 1, "text after a quoted scalar"),
    "an-escape-yaml-does-not-have": ('a: "Widget\\q"\n', 1, "the escape '\\q'"),
    "an-escape-that-is-cut-short": ('a: "Widget\\u00"\n', 1, "the escape '\\u' without 4 hexadecimal digits"),
    "an-unterminated-quoted-key": ("'Widget: 1\n", 1, NOT_CLOSED),
}


@pytest.mark.parametrize("name", sorted(YAML_OUTSIDE))
def test_a_yaml_file_outside_the_subset_cannot_be_verified_so_even_a_harmless_edit_of_it_is_refused(tmp_path, name):
    content, line, what = YAML_OUTSIDE[name]

    assert refusal(tmp_path, "display.yml", content) == NOT_IN_THE_SUBSET.format(line=line, what=what)


def nested(levels: int, dash: bool = False) -> str:
    """*levels* collections one inside the other, one space deeper each, around one value holding Widget."""
    lines = [" " * level + ("-" if dash else "a:") for level in range(levels - 1)]
    return "\n".join(lines + [" " * (levels - 1) + ("- Widget" if dash else "a: Widget")]) + "\n"


@pytest.mark.parametrize("dash", [False, True], ids=["mappings", "sequences"])
def test_nesting_to_the_limit_is_read_and_nesting_beyond_it_is_refused(tmp_path, dash):
    assert blinding._YAML_DEPTH == 64
    edit = display_edit(tmp_path, "display.yml", nested(64, dash))
    assert edit.structure_check == "yaml" and "Sprocket" in edit.data.decode("utf-8")

    for levels in (65, 2000):
        assert refusal(tmp_path, "display.yml", nested(levels, dash)) == NOT_IN_THE_SUBSET.format(
            line=65, what="nesting deeper than 64 levels")


def test_a_large_yaml_file_is_read_in_time_linear_in_its_size():
    """A rescan of earlier lines, or of earlier keys, would make these minutes; the bound is ten seconds."""
    count = 40_000
    texts = ["".join(f"key{index}: value {index} # note\n" for index in range(count)),
             "".join(f"- item {index}\n" for index in range(count)),
             "".join(f"{index}: value\n" for index in range(count)),
             "".join(f"- k{index}: v\n  n{index}:\n  - x\n  - 'y'\n" for index in range(count // 4)),
             "a: " + "x:" * 1_500_000 + "\n",
             "a: " + "1" * 1_000_000 + "x\n",
             "a: 2019-01-01" + " " * 1_000_000 + "x\n",
             "a: '" + "''" * 500_000 + "'\n",
             'a: "' + "\\n" * 500_000 + '"\n']
    started = time.perf_counter()

    for text in texts:
        try:
            blinding._parse_yaml(text)
        except ValueError:
            pass

    assert time.perf_counter() - started < 10


def test_pyyaml_and_ruamel_read_every_accepted_edit_as_the_original_with_only_the_reviewed_replacements(tmp_path):
    """The subset's claim, checked against the libraries whose reading it claims: same keys, order, nesting, types."""
    yaml = pytest.importorskip("yaml")
    ruamel = pytest.importorskip("ruamel.yaml")
    readers = {"PyYAML": yaml.safe_load, "ruamel.yaml (YAML 1.2)": lambda text: ruamel.YAML(typ="safe").load(text)}

    def rewritten(value, pseudonyms):
        if isinstance(value, dict):
            return {rewritten(key, pseudonyms): rewritten(item, pseudonyms) for key, item in value.items()}
        if isinstance(value, list):
            return [rewritten(item, pseudonyms) for item in value]
        return replaced(value, pseudonyms) if isinstance(value, str) else value

    def typed(value):
        if isinstance(value, dict):
            return ("mapping", [(typed(key), typed(item)) for key, item in value.items()])
        if isinstance(value, list):
            return ("sequence", [typed(item) for item in value])
        return (type(value), value)

    for name, (content, pseudonyms) in sorted(YAML_ACCEPTED.items()):
        transformed = display_edit(tmp_path / name, "display.yml", content, pseudonyms).data.decode("utf-8")
        for reader, load in readers.items():
            assert typed(load(transformed)) == typed(rewritten(load(content), pseudonyms)), (name, reader)


def test_a_yaml_display_file_is_verified_as_the_block_subset_and_the_check_is_recorded(tmp_path, display):
    widget = display("display.yml", DISPLAY_YAML)

    record = export_blinded(widget, display_map(widget, "display.yml", "Sprocket"), tmp_path / "trial")

    transformed = (tmp_path / "trial" / "source" / "display.yml").read_text(encoding="utf-8")
    assert transformed == DISPLAY_YAML.replace("Widget", "Sprocket")
    assert [check["detail"] for check in record["blinding"]["validation"] if check["check"] == "edit_structure"] == [
        "display: parsed as the YAML block subset before and after; the result is the original with only the reviewed "
        "replacements applied to its keys and strings, and every replaced plain scalar still reads as a string under "
        "YAML 1.1 and 1.2"]
    assert all(check["result"] == "pass" for check in record["blinding"]["validation"])


def test_a_replacement_that_breaks_a_yaml_display_file_is_refused_before_a_transformed_tree_exists(tmp_path, display):
    """The reviewer's reproduction, for YAML: a quotation mark in an approved replacement, in a double-quoted value."""
    widget = display("display.yml", DISPLAY_YAML)
    trial = tmp_path / "trial"

    with pytest.raises(MaterializationError, match=r"blinding map refused: edit display: display\.yml: the transformed "
                                                    r"file is not valid YAML within the subset this module reads "
                                                    r"\(line 2: text after a quoted scalar is outside the YAML subset "
                                                    r"read here\)"):
        export_blinded(widget, display_map(widget, "display.yml", 'Sprock"et'), trial)

    assert not (trial / "source").exists(), "nothing is transformed unless every check passes"
    record = export_blinded(widget, display_map(widget, "display.yml", "Sprocket"), tmp_path / "plain")
    written = (tmp_path / "plain" / "source" / "display.yml").read_text(encoding="utf-8")
    assert written == DISPLAY_YAML.replace("Widget", "Sprocket")
    assert "edit_structure" in {check["check"] for check in record["blinding"]["validation"]}


def test_a_realistic_mkdocs_file_with_markup_in_its_values_is_blinded_and_verified(tmp_path, display):
    """A copyright line holding HTML, asterisks, a URL, and nested lists are what an earlier lexical rule refused."""
    widget = display("mkdocs.yml", MKDOCS_FULL)

    record = export_blinded(widget, display_map(widget, "mkdocs.yml", "Sprocket"), tmp_path / "trial")

    blinded = (tmp_path / "trial" / "source" / "mkdocs.yml").read_text(encoding="utf-8")
    assert blinded == MKDOCS_FULL.replace("Widget", "Sprocket")
    assert [check["check"] for check in record["blinding"]["validation"]].count("edit_structure") == 1


def test_a_display_suffix_is_read_without_regard_to_case():
    paths = ("a/b.json", "c.TOML", "d.Ini", "e.CFG", "f.YML", "g/h.Yaml")
    assert [blinding._structure_check_for(path) for path in paths] == ["json", "toml", "ini", "ini", "yaml", "yaml"]
    assert [blinding._structure_check_for(path) for path in ("README.md", "docs/guide.rst", "CHANGES", "a.json.bak")
            ] == [None, None, None, None]


# --- the runner: refusals are preparation failures; nothing reaches a scanner ------------------


def write_pack(path: Path, widget: dict, *, checked: bool = False) -> dict:
    """The vulnerable snapshot's target and its fixed-target control on the repaired snapshot."""
    pack = cases.new_pack("test", "blinding", "Local fixture pack for the blinding tests.")
    base = {"repository": {"url": str(widget["repo"]), "name": "widget"},
            "reference": "Commit chosen by the test fixture; no advisory is claimed.",
            "languages": ["python"], "workload": "conventional_application", "component_role": "application",
            "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}}
    cases.add_snapshot(pack, {**base, "snapshot_id": "snap-a", "commit": widget["commits"]["snap-a"]})
    cases.add_snapshot(pack, {**base, "snapshot_id": "snap-fixed", "commit": widget["commits"]["snap-fixed"],
                              "role": "fixed"})
    case = cases.draft_case(
        "case-a", snapshot_id="snap-a", kind="command_injection",
        description="Caller-controlled command string reaches subprocess with shell=True.",
        represents=REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                 reference="src/app.py", note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "src/app.py", "start_line": 6, "end_line": 6, "role": "sink", "note": ""}])
    case["controls"].append({
        "control_id": "C-case-a-fixed", "snapshot_id": "snap-fixed", "type": "fixed_target",
        "target_id": "T-case-a", "description": "The repaired call passes an argument list.",
        "property": "No shell string is built at this call site.",
        "allowed_actors_inputs": "The same callers as the vulnerable snapshot.",
        "assumptions": ["Default deployment."],
        "ruled_out_allegation": "Caller-controlled shell interpolation at this call site.",
        "locations": [{"path": "src/app.py", "start_line": 6, "end_line": 6, "role": "operation", "note": ""}],
        "evidence_ids": ["source"],
    })
    cases.add_case(pack, case)
    if checked:
        for snapshot_id in ("snap-a", "snap-fixed"):
            cases.mechanical_checks(pack, snapshot_id, widget["probes"][snapshot_id],
                                    materialize.tree_hash(widget["exports"][snapshot_id].hashes), clock=CLOCK)
    cases.save_pack(path, pack)
    return pack


def write_config(path: Path, inputs: list[dict], *, systems: list[dict] | None = None,
                 run_id: str = "run-blind") -> dict:
    config = {"schema_version": "2.1", "run_id": run_id, "pack": "pack.json", "cache_root": "cache",
              "inputs": inputs, "systems": systems or [{"system_id": "fake-a", "adapter": "fake", "config": {}}],
              "repetitions": 1, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none"}
    path.write_text(canonical_json(config) + "\n", encoding="utf-8")
    return config


class FakeAdapter(Adapter):
    """Returns one claim on the target's sink and records which trees it was handed."""

    name = "fake"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})

    def __init__(self):
        self.calls = 0
        self.scanned: list[str] = []

    def prepare(self, spec, cache_root):
        return {"system": spec.system_id}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        self.calls += 1
        self.scanned.append(request["input"]["tree_hash"])
        native = raw_dir / "native.json"
        native.write_text('{"findings": [{"file": "src/app.py"}]}\n', encoding="utf-8")
        claims = [{"claim_id": "c1", "allegation": "shell=True with a caller-controlled command",
                   "kind": "command_injection", "native_rule_id": "fake.shell", "raw_artifact_id": "native",
                   "primary_location": {"path": "src/app.py", "start_line": 6, "end_line": 6}}]
        return NativeOutcome(status="success", exit_code=0, command=["fake", "scan"], claims=claims,
                             artifacts=[{"id": "native", "path": native}], tool_versions={"fake": "1.0.0"},
                             capture={"model_requests": "not_applicable"}, notes=["fake run"])


class InspectingAdapter(FakeAdapter):
    """Looks through everything it was handed before it scans, the way a curious scanner would."""

    def __init__(self):
        super().__init__()
        self.seen: dict = {}

    def scan(self, *, request, source_dir, raw_dir, **kwargs):
        workspace = source_dir.parent
        files = [path for path in workspace.rglob("*") if path.is_file()]
        every_name = {part for path in workspace.rglob("*") for part in path.relative_to(workspace).parts}
        self.seen = {
            "map_files": [path.name for path in files
                          if path.name == "widget-map.json" or b'"pseudonyms"' in path.read_bytes()],
            "provenance": "provenance.json" in every_name,
            "evaluator": sorted(every_name & {"evaluator", "pack.json", "schedule.json", "plan.json",
                                             "decisions.json", "original"}),
            "tokens_in_edited": {relative: [token for token in PSEUDONYMS
                                            if token in (source_dir / relative).read_text(encoding="utf-8")]
                                 for relative in EDITED},
            "tokens_in_request": [token for token in PSEUDONYMS
                                  if token.casefold() in json.dumps(request).casefold()],
            "profile": request["input"]["profile"],
        }
        return super().scan(request=request, source_dir=source_dir, raw_dir=raw_dir, **kwargs)


def blinded_run(tmp_path: Path, widget: dict, document: dict, inputs: list[dict], adapter: Adapter, *,
                checked: bool = False, **config_changes) -> tuple[dict, Path]:
    write_pack(tmp_path / "pack.json", widget, checked=checked)
    blinding.save_map(tmp_path / "widget-map.json", document)
    write_config(tmp_path / "run.json", inputs, **config_changes)
    out = tmp_path / "out"
    manifest = run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": adapter})
    return manifest, out


@pytest.mark.parametrize("name", sorted(REFUSALS))
def test_a_refused_map_is_a_preparation_failure_and_no_scanner_ever_sees_that_input(tmp_path, widget, name):
    adapter = FakeAdapter()

    manifest, out = blinded_run(tmp_path, widget, refused_map(widget, name),
                                [{"snapshot_id": "snap-a"}, BLINDED], adapter)

    assert manifest["status"] == "completed"
    standard, blinded = manifest["inputs"]
    assert standard["preparation_failure"] is None
    failure = blinded["preparation_failure"]
    assert blinded["input_id"] == "snap-a.blinded" and failure["type"] == "MaterializationError"
    assert re.search(REFUSALS[name][2], failure["message"])
    assert (blinded["tree_hash"], blinded["input_hash"], blinded["mechanical_checks"]) == (None, None, [])
    rows = {row["input_id"]: row for row in manifest["invocations"]}
    assert rows["snap-a.blinded"]["status"] == "skipped"
    assert rows["snap-a.blinded"]["skipped_reason"].startswith(
        "input snap-a.blinded could not be prepared: MaterializationError: ")
    assert rows["snap-a"]["status"] == "success", "the other input still ran"
    assert adapter.calls == 1 and adapter.scanned == [standard["tree_hash"]], "the refused input reached no scanner"
    assert not (out / "inputs" / "snap-a.blinded" / "source").exists()
    frozen = load_document(out / manifest["schedule_path"], "evaluation-schedule")
    assert [row["assignment_id"] for row in frozen["assignments"]] == [
        "snap-a__fake-a__r1", "snap-a.blinded__fake-a__r1"], "the refused input's assignment stays scheduled"


@pytest.mark.parametrize(("path", "text", "refusal"), [
    ("display.json", DISPLAY_JSON, "blinding map refused: edit display: display.json: the transformed file is not "
                                   "valid JSON ("),
    ("display.yml", DISPLAY_YAML, "blinding map refused: edit display: display.yml: the transformed file is not valid "
                                  "YAML within the subset this module reads (line 2: text after a quoted scalar is "
                                  "outside the YAML subset read here)"),
], ids=["json", "yaml"])
def test_a_replacement_that_breaks_a_display_file_is_a_preparation_failure_and_no_scanner_ever_sees_that_input(
        tmp_path, display, path, text, refusal):
    """The reviewer's reproduction, through a run: the input is not prepared, and the other input still runs."""
    widget = display(path, text)
    adapter = FakeAdapter()

    manifest, out = blinded_run(tmp_path, widget, display_map(widget, path, 'Sprock"et'),
                                [{"snapshot_id": "snap-a"}, BLINDED], adapter)

    assert manifest["status"] == "completed"
    standard, blinded = manifest["inputs"]
    failure = blinded["preparation_failure"]
    assert blinded["input_id"] == "snap-a.blinded" and failure["type"] == "MaterializationError"
    assert failure["message"].startswith(refusal)
    assert (blinded["tree_hash"], blinded["input_hash"], blinded["mechanical_checks"]) == (None, None, [])
    rows = {row["input_id"]: row for row in manifest["invocations"]}
    assert rows["snap-a.blinded"]["status"] == "skipped"
    assert rows["snap-a"]["status"] == "success", "the other input still ran"
    assert adapter.calls == 1 and adapter.scanned == [standard["tree_hash"]], "the refused input reached no scanner"
    assert not (out / "inputs" / "snap-a.blinded" / "source").exists()


def test_a_scanner_handed_a_blinded_input_finds_no_map_no_provenance_and_no_original_token(tmp_path, widget):
    adapter = InspectingAdapter()

    manifest, _out = blinded_run(tmp_path, widget, widget_map(widget), [BLINDED], adapter)

    assert manifest["invocations"][0]["status"] == "success" and adapter.calls == 1
    assert adapter.seen == {"map_files": [], "provenance": False, "evaluator": [],
                            "tokens_in_edited": {relative: [] for relative in EDITED},
                            "tokens_in_request": [], "profile": "metadata_blinded"}


def test_a_blinded_run_binds_results_to_the_transformed_tree_and_labels_to_the_original(tmp_path, widget):
    document = widget_map(widget)
    adapter = FakeAdapter()

    manifest, out = blinded_run(tmp_path, widget, document, [BLINDED, BLINDED_FIXED], adapter)

    rows = {row["input_id"]: row for row in manifest["inputs"]}
    blinded = rows["snap-a.blinded"]
    original_hash = materialize.tree_hash(widget["exports"]["snap-a"].hashes)
    transformed = materialize.hash_exported_tree(out / "inputs" / "snap-a.blinded" / "source")["tree_hash"]
    assert blinded["tree_hash"] == blinded["input_hash"] == transformed != original_hash
    assert blinded["provenance_path"] == "inputs/snap-a.blinded/provenance.json"
    assert [(outcome["case_id"], outcome["passed"]) for outcome in blinded["mechanical_checks"]] == [("case-a", True)]
    frozen = cases.load_pack(out / "evaluator" / "pack.json")
    assert cases.snapshot_by_id(frozen, "snap-a")["tree_hash"] == original_hash, "labels refer to the original"
    assert adapter.scanned == [transformed, rows["snap-fixed.blinded"]["tree_hash"]]

    bundle = out / "invocations" / "snap-a.blinded__fake-a__r1"
    request = load_document(bundle / "request.json", "scan-request")
    assert request["input"]["tree_hash"] == transformed and request["input"]["profile"] == "metadata_blinded"
    assert load_document(bundle / "result.json", "scan-result")["input_hash"] == transformed
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    assert plan["schema_version"] == "2.1" and plan["input_hash"] == transformed
    assert plan["provenance"]["source_tree_hash"] == original_hash
    assert plan["provenance"]["blinding"] == blinding.map_identity(document)
    assert [(target["target_id"], target["canonical_id"]) for target in plan["targets"]] == [("T-case-a", "T-case-a")]
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["schema_version"] == "2.1" and execution["isolation"] == LOCAL_ISOLATION
    provenance = execution["provenance"]
    assert (provenance["tree_hash"], provenance["input_hash"], provenance["mode"], provenance["pr"]) == (
        transformed, transformed, "full", None)
    assert provenance["blinding"] == {**blinding.map_identity(document), "original_tree_hash": original_hash,
                                      "transformed_tree_hash": transformed}
    fixed = load_document(out / "invocations" / "snap-fixed.blinded__fake-a__r1" / "execution.json",
                          "execution-record")
    assert fixed["provenance"]["blinding"]["map_sha256"] == provenance["blinding"]["map_sha256"], "one map"
    evaluation = json.loads((bundle / "evaluation.json").read_text(encoding="utf-8"))
    assert evaluation["input_hash"] == transformed and evaluation["metrics"]["targets_assigned"] == 1


def test_the_schedule_names_each_blinded_map_and_pairs_only_within_one_profile(tmp_path, widget):
    document = widget_map(widget)
    inputs = [{"snapshot_id": "snap-a"}, {"snapshot_id": "snap-fixed"}, BLINDED, BLINDED_FIXED]

    manifest, out = blinded_run(tmp_path, widget, document, inputs, FakeAdapter(), checked=True)

    frozen = load_document(out / manifest["schedule_path"], "evaluation-schedule")
    identities = {row["input_id"]: row["blinding"] for row in frozen["inputs"]}
    assert identities == {"snap-a": None, "snap-fixed": None, "snap-a.blinded": blinding.map_identity(document),
                          "snap-fixed.blinded": blinding.map_identity(document)}
    assert [(pair["vulnerable_input_id"], pair["fixed_input_id"]) for pair in frozen["pairs"]] == [
        ("snap-a", "snap-fixed"), ("snap-a.blinded", "snap-fixed.blinded")]
    assert all(pair["repetition_pairs"] == [[1, 1]] for pair in frozen["pairs"])


LEAKS = {
    "run-id": {"run_id": "widget-nightly"},
    "system-id": {"systems": [{"system_id": "widget-scanner", "adapter": "fake", "config": {}}]},
    "model-id": {"systems": [{"system_id": "fake-a", "adapter": "fake", "config": {},
                              "model_id": "vendor/acmecorp-tuned"}]},
    "model-revision": {"systems": [{"system_id": "fake-a", "adapter": "fake", "config": {},
                                    "model_revision": "Widget-2026"}]},
    "config-value": {"systems": [{"system_id": "fake-a", "adapter": "fake",
                                  "config": {"prompts": ["Review the WIDGET service."]}}]},
    "config-key": {"systems": [{"system_id": "fake-a", "adapter": "fake", "config": {"widget": {"depth": 2}}}]},
}


@pytest.mark.parametrize("name", sorted(LEAKS))
def test_a_run_that_would_carry_an_original_token_to_a_blinded_scan_is_refused(tmp_path, widget, name):
    adapter = FakeAdapter()
    write_pack(tmp_path / "pack.json", widget)
    blinding.save_map(tmp_path / "widget-map.json", widget_map(widget))
    write_config(tmp_path / "run.json", [{"snapshot_id": "snap-a"}, BLINDED], **LEAKS[name])
    out = tmp_path / "out"

    with pytest.raises(ContractError, match="an original identity token of blinding map widget-metadata"):
        run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": adapter})

    assert not out.exists() and adapter.calls == 0


def test_a_leak_check_reads_keys_and_values_and_ignores_case(widget):
    document = widget_map(widget)

    assert blinding.leaked_originals(document, {"a": ["x", {"acmecorp": 1}], "b": "the WIDGET way"}) == [
        "AcmeCorp", "Widget"]
    assert blinding.leaked_originals(document, {"a": [1, 2.0, None, True], "b": "sprocket"}) == []


def blinded_config(tmp_path: Path, widget: dict, *, directory: str = "config", inputs: list[dict] | None = None,
                   **config_changes) -> Path:
    """A run configuration in its own directory, with its pack and approved map beside it."""
    home = tmp_path / directory
    home.mkdir()
    write_pack(home / "pack.json", widget)
    blinding.save_map(home / "widget-map.json", widget_map(widget))
    config = write_config(home / "run.json", inputs or [{"snapshot_id": "snap-a"}, BLINDED])
    (home / "run.json").write_text(canonical_json({**config, **config_changes}) + "\n", encoding="utf-8")
    return home / "run.json"


def leaky_paths(tmp_path: Path) -> dict:
    """Each path a scanner is told, once with an original token in its name: what the refusal calls it,
    the token it names first, and the arguments that make the run name it so."""
    return {
        "workspace_root": ("workspace_root", "AcmeCorp", {"workspace_root": tmp_path / "AcmeCorp-Widget-eval"}),
        "cache_root": ("cache_root", "Widget", {"cache_root": "widget-cache"}),
        "configuration directory": ("the configuration directory", "Widget",
                                    {"directory": "Widget-eval", "cache_root": str(tmp_path / "cache")}),
    }


@pytest.mark.parametrize("name", ["workspace_root", "cache_root", "configuration directory"])
def test_a_path_naming_an_original_token_reaches_the_scan_so_the_run_is_refused(tmp_path, widget, name):
    """A scanner is handed its workspace as an absolute path, its rules under the cache root, and both sit
    beside the configuration; the guard read the run id and the system fields but never these."""
    label, token, changes = leaky_paths(tmp_path)[name]
    workspace_root = changes.pop("workspace_root", None)
    if workspace_root is not None:
        workspace_root.mkdir()
    config = blinded_config(tmp_path, widget, directory=changes.pop("directory", "config"), **changes)
    adapter, out = FakeAdapter(), tmp_path / "out"

    with pytest.raises(ContractError, match=rf"{label} \S+ names '{token}', an original identity token of "
                                            "blinding map widget-metadata, which would reach the scan of blinded "
                                            "input snap-a.blinded"):
        run_from_config(config, out, clock=CLOCK, workspace_root=workspace_root, adapters={"fake": adapter})

    assert not out.exists() and adapter.calls == 0


def test_a_symbolic_link_is_read_both_as_named_and_as_resolved(tmp_path, widget):
    """The scanner sees the workspace as it was named; the resolved path is where it really is."""
    (tmp_path / "AcmeCorp-real").mkdir()
    (tmp_path / "neutral-real").mkdir()
    (tmp_path / "AcmeCorp-link").symlink_to(tmp_path / "neutral-real")
    (tmp_path / "neutral-link").symlink_to(tmp_path / "AcmeCorp-real")
    for link in ("AcmeCorp-link", "neutral-link"):
        out = tmp_path / f"out-{link}"
        with pytest.raises(ContractError, match="workspace_root .* names 'AcmeCorp'"):
            run_from_config(blinded_config(tmp_path, widget, directory=f"config-{link}"), out, clock=CLOCK,
                            workspace_root=tmp_path / link, adapters={"fake": FakeAdapter()})
        assert not out.exists()


def test_paths_that_name_no_original_token_and_standard_inputs_are_not_refused(tmp_path, widget):
    workspace_root = tmp_path / "workspaces"
    workspace_root.mkdir()
    manifest = run_from_config(blinded_config(tmp_path, widget), tmp_path / "out", clock=CLOCK,
                               workspace_root=workspace_root, adapters={"fake": FakeAdapter()})
    assert manifest["status"] == "completed"
    # The guard is for a blinded input: a standard one is handed the original tree whatever its paths say.
    leaky = tmp_path / "AcmeCorp-workspaces"
    leaky.mkdir()
    manifest = run_from_config(blinded_config(tmp_path, widget, directory="standard-config",
                                              inputs=[{"snapshot_id": "snap-a"}]),
                               tmp_path / "out-standard", clock=CLOCK, workspace_root=leaky,
                               adapters={"fake": FakeAdapter()})
    assert manifest["status"] == "completed"


def test_related_blinded_inputs_are_blinded_with_one_map(tmp_path, widget):
    document = widget_map(widget)
    other = deepcopy(document)
    other["pseudonyms"][0]["replacement"] = "Gizmo"
    reapproved(other)
    write_pack(tmp_path / "pack.json", widget)
    blinding.save_map(tmp_path / "widget-map.json", document)
    blinding.save_map(tmp_path / "other-map.json", other)
    write_config(tmp_path / "run.json", [BLINDED, {**BLINDED_FIXED, "blinding_map": "other-map.json"}])
    out = tmp_path / "out"

    with pytest.raises(ContractError, match="blinded snapshots of one repository .* name different maps"):
        run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": FakeAdapter()})
    assert not out.exists()


def test_a_map_that_cannot_be_loaded_is_refused_before_the_output_exists(tmp_path, widget):
    write_pack(tmp_path / "pack.json", widget)
    write_config(tmp_path / "run.json", [BLINDED])
    out = tmp_path / "out"
    with pytest.raises(ContractError, match=r"inputs\[0\] \(snap-a.blinded\): the blinding map .* cannot be used"):
        run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": FakeAdapter()})

    document = widget_map(widget)
    document["pseudonyms"][0]["replacement"] = "Widget"
    (tmp_path / "widget-map.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ContractError, match="replaces 'Widget' with itself"):
        run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": FakeAdapter()})
    assert not out.exists()


def cli(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_scaneval_run_on_a_blinded_input_then_replay_reproduces_the_evaluation(tmp_path, widget, capsys,
                                                                                monkeypatch):
    write_pack(tmp_path / "pack.json", widget)
    blinding.save_map(tmp_path / "widget-map.json", widget_map(widget))
    write_config(tmp_path / "run.json", [BLINDED])
    monkeypatch.setattr("scaneval.runner.get_adapter", lambda name: FakeAdapter())
    out = tmp_path / "out"

    code, printed, _ = cli(capsys, "run", str(tmp_path / "run.json"), "--output", str(out))
    assert code == 0 and "snap-a.blinded__fake-a__r1 status=success claims=1" in printed

    bundle = out / "invocations" / "snap-a.blinded__fake-a__r1"
    replayed = tmp_path / "replayed.json"
    code, _, _ = cli(capsys, "replay", str(bundle), "--output", str(replayed))
    assert code == 0 and replayed.read_bytes() == (bundle / "evaluation.json").read_bytes()


# --- the CLI: check a map against its variants, and record a review of it -----------------------


def test_blinding_check_dry_runs_every_variant_and_writes_nothing_to_the_map(tmp_path, widget, capsys):
    write_pack(tmp_path / "pack.json", widget)
    path = tmp_path / "widget-map.json"
    blinding.save_map(path, widget_map(widget))
    before = path.read_bytes()
    argv = ["blinding", "check", str(path), "--pack", str(tmp_path / "pack.json"), "--cache-root", str(widget["cache"])]

    code, printed, err = cli(capsys, *argv)

    assert code == 0 and err == "" and path.read_bytes() == before
    assert f"approval: approved by {REVIEWER} (independent_reviewer)" in printed
    assert "snap-a: pass" in printed and "snap-fixed: pass" in printed
    assert "readme-brand README.md: AcmeCorp=1, Widget=2; changed line(s): 1, 3" in printed
    assert "retained identity cues: 2 token(s), 6 occurrence(s) in 6 file(s); instruction files: CLAUDE.md" in printed
    assert ("retained in: .github/workflows/ci.yml (1), CLAUDE.md (1), LICENSE (1), README.md (1), "
            "package.json (1), src/app.py (1)\n") in printed

    code, printed, _ = cli(capsys, *argv, "--snapshot-id", "snap-fixed")
    assert code == 0 and "snap-a:" not in printed and "snap-fixed: pass" in printed
    code, _, err = cli(capsys, *argv, "--snapshot-id", "snap-zzz")
    assert code == 2 and "has no variant for snapshot snap-zzz" in err


def test_blinding_check_names_at_most_ten_files_that_keep_a_cue_and_counts_the_rest():
    cues = {"path_count": 12, "paths": [{"path": f"docs/page-{index:02d}.md", "count": 12 - index}
                                        for index in range(12)]}

    line = _retained_in(cues)

    assert line.startswith("retained in: docs/page-00.md (12), docs/page-01.md (11), ")
    assert line.endswith("docs/page-09.md (3), and 2 more file(s)") and "page-10" not in line
    assert _retained_in({"path_count": 1, "paths": [{"path": "LICENSE", "count": 1}]}) == "retained in: LICENSE (1)"


def test_blinding_check_exits_one_for_a_refused_or_unapproved_map(tmp_path, widget, capsys):
    write_pack(tmp_path / "pack.json", widget)
    path = tmp_path / "widget-map.json"
    argv = ["blinding", "check", str(path), "--pack", str(tmp_path / "pack.json"), "--cache-root", str(widget["cache"])]

    blinding.save_map(path, refused_map(widget, "stale-file-hash"))
    code, printed, err = cli(capsys, *argv)
    assert code == 1 and "snap-a: refused: stale map" in printed and "snap-fixed: pass" in printed
    assert "refused for 1 variant(s): snap-a" in err

    path.unlink()
    blinding.save_map(path, widget_map(widget, approved=False))
    code, printed, err = cli(capsys, *argv)
    assert code == 1 and "approval: not approved:" in printed and "unreviewed" in printed
    assert "snap-a: pass" in printed and "a run refuses it" in err


def test_blinding_review_appends_one_chained_review_and_never_names_a_reviewer_itself(tmp_path, widget, capsys):
    path = tmp_path / "widget-map.json"
    blinding.save_map(path, widget_map(widget, approved=False))
    before = path.read_bytes()

    code, _, err = cli(capsys, "blinding", "review", str(path), "--reviewer", "  ", "--role", "curator",
                       "--decision", "approve", "--note", "blank reviewer")
    assert code == 2 and "must name its reviewer" in err and path.read_bytes() == before

    code, printed, _ = cli(capsys, "blinding", "review", str(path), "--reviewer", REVIEWER,
                           "--role", "independent_reviewer", "--decision", "approve", "--note", REVIEW_NOTE)
    assert code == 0
    recorded = json.loads(printed)
    document = blinding.load_map(path)
    assert document["reviews"] == [recorded] and document["reviews_sha256"] == recorded["chain_sha256"]
    assert recorded["reviewer"] == REVIEWER and recorded["content_sha256"] == blinding.content_digest(document)
    assert blinding.approval_gap(document) is None
    assert not list(tmp_path.glob("widget-map.json.*.tmp"))

    trial = tmp_path / "trial"
    (trial / "source").mkdir(parents=True)
    (trial / "provenance.json").write_text("{}\n", encoding="utf-8")
    blinding.save_map(trial / "map.json", document)
    code, _, err = cli(capsys, "blinding", "review", str(trial / "map.json"), "--reviewer", REVIEWER,
                       "--role", "curator", "--decision", "reject", "--note", "inside a trial")
    assert code == 2 and "inside the trial directory" in err


# --- a blinded PR: one map, both snapshots, originals kept evaluator-side ---------------------------


def export_blinded_pr(widget: dict, document: dict, trial: Path, *, base: str = "snap-a",
                      head: str = "snap-fixed") -> dict:
    return materialize.export_pr(cached(widget, base), cached(widget, head), trial, profile="metadata_blinded",
                                 blinding_map=document, base_snapshot_id=base, head_snapshot_id=head, clock=CLOCK)


def test_a_blinded_pr_transforms_the_base_and_the_head_with_one_map(tmp_path, widget):
    document = widget_map(widget)
    trial = tmp_path / "trial"

    record = export_blinded_pr(widget, document, trial)

    # Where everything sits: what a scanner may be given, and the originals that are never given.
    assert {path.relative_to(trial).as_posix() for path in (trial.glob("*"))} == {"source", "base", "original"}
    assert (trial / "base" / "source" / "README.md").is_file() and (trial / "source" / "README.md").is_file()
    assert (trial / "original" / "source" / "README.md").is_file()
    assert (trial / "original" / "base" / "source" / "README.md").is_file()
    assert not (trial / "base" / "original").exists(), "an original never sits beside what a scanner may see"
    head, base = record["head"], record["base"]
    assert (head["trial"]["root"], base["trial"]["root"]) == ("source", "base/source")
    assert (head["original"]["root"], base["original"]["root"]) == ("original/source", "original/base/source")
    # One map: the same identity, the same reviewers, the same pseudonyms in both trees.
    assert {key: head["blinding"][key] for key in ("map_id", "map_version", "map_sha256")} == \
        {key: base["blinding"][key] for key in ("map_id", "map_version", "map_sha256")} == \
        blinding.map_identity(document)
    assert head["blinding"]["reviewers"] == base["blinding"]["reviewers"]
    assert (trial / "base" / "source" / "README.md").read_text(encoding="utf-8") == blinded_text(README_VULNERABLE)
    assert (trial / "source" / "README.md").read_text(encoding="utf-8") == blinded_text(README_FIXED)
    # The originals are the exports the labels and checks refer to, and the transformed trees are what is hashed.
    assert base["original"]["tree_hash"] == materialize.tree_hash(widget["exports"]["snap-a"].hashes)
    assert head["original"]["tree_hash"] == materialize.tree_hash(widget["exports"]["snap-fixed"].hashes)
    assert base["trial"]["tree_hash"] == materialize.hash_exported_tree(trial / "base" / "source")["tree_hash"]
    assert head["trial"]["tree_hash"] == materialize.hash_exported_tree(trial / "source")["tree_hash"]
    assert base["blinding"]["transformed_tree_hash"] == base["trial"]["tree_hash"]
    assert {base["trial"]["tree_hash"], head["trial"]["tree_hash"]}.isdisjoint(
        {base["original"]["tree_hash"], head["original"]["tree_hash"]})


def test_a_blinded_pr_records_the_diff_of_the_transformed_trees_and_none_of_the_originals(tmp_path, widget):
    trial = tmp_path / "trial"

    record = export_blinded_pr(widget, widget_map(widget), trial)

    changes = record["diff"]["changes"]
    assert changes == {"added": [], "deleted": ["docs/guide.md"], "modified": ["README.md", "src/app.py"],
                       "renamed": [], "mode_changed": []}
    assert record["diff"]["base_tree_hash"] == record["base"]["trial"]["tree_hash"]
    assert record["diff"]["head_tree_hash"] == record["head"]["trial"]["tree_hash"]
    # The recorded diff names a path a scanner can see and quotes nothing of an original.
    assert "Widget" not in json.dumps(record["diff"]) and "AcmeCorp" not in json.dumps(record["diff"])
    # The history a scanner is handed is built from the transformed trees, so an original token is
    # in no blob of it, whatever the original exports hold.
    history = materialize.prepare_pr_history(trial / "source", trial / "base" / "source")
    assert git("rev-parse", "HEAD", cwd=trial / "source") == history["head_commit"]
    for commit in (history["base_commit"], history["head_commit"]):
        for path in ("README.md", "mkdocs.yml", "docs/guide.md"):
            shown = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=trial / "source", capture_output=True,
                                   text=True)
            assert shown.returncode in (0, 128) and "Widget" not in shown.stdout and "AcmeCorp" not in shown.stdout


@pytest.mark.parametrize("name", ["unreviewed", "rejected", "stale-commit", "python-file"])
def test_a_map_that_does_not_fit_either_snapshot_leaves_no_blinded_pr_behind(tmp_path, widget, name):
    """Every check that needs no export is asked of both snapshots before either is exported."""
    document = refused_map(widget, name)
    trial = tmp_path / "trial"

    with pytest.raises(MaterializationError, match=REFUSALS[name][2]):
        export_blinded_pr(widget, document, trial)

    assert not trial.exists(), "no half-blinded input: neither tree was written"


def test_a_map_that_does_not_cover_the_base_refuses_the_pr_and_is_never_replaced_by_standard(tmp_path, widget):
    document = widget_map(widget, approved=False)
    document["variants"] = [_variant(document, "snap-fixed")]
    for edit in document["edits"]:
        edit["expected"] = [_expected(edit, "snap-fixed")]
    approve(document)
    trial = tmp_path / "trial"

    with pytest.raises(MaterializationError, match="stale map: map widget-metadata 1 has no variant for snapshot snap-a"):
        export_blinded_pr(widget, document, trial)

    assert not trial.exists()
    with pytest.raises(MaterializationError, match="blinding unavailable"):
        materialize.export_pr(cached(widget, "snap-a"), cached(widget, "snap-fixed"), tmp_path / "other",
                              profile="metadata_blinded")
    assert not (tmp_path / "other").exists()


def test_a_blinded_pr_refuses_a_base_whose_files_are_not_the_ones_the_map_reviewed(tmp_path, widget):
    """The checks that need the export are asked of the base too, after the head was exported."""
    document = widget_map(widget, approved=False)
    _expected(_edit(document, "readme-brand"), "snap-a")["occurrences"]["Widget"] = 3
    approve(document)

    with pytest.raises(MaterializationError, match="unexpected occurrence count in snapshot snap-a"):
        export_blinded_pr(widget, document, tmp_path / "trial")


def test_repeating_a_blinded_pr_gives_byte_identical_trees_and_records(tmp_path, widget):
    document = widget_map(widget)

    first = export_blinded_pr(widget, deepcopy(document), tmp_path / "first")
    second = export_blinded_pr(widget, deepcopy(document), tmp_path / "second")

    assert canonical_json(first) == canonical_json(second)
    for tree in ("source", "base/source", "original/source", "original/base/source"):
        assert file_map(tmp_path / "first" / tree) == file_map(tmp_path / "second" / tree)


# --- a blinded PR through the runner: one map, both variants, a scanner that sees no original ---------


BLINDED_PR = {"mode": "pr", "change_set_id": "cs-fix", "profile": "metadata_blinded",
              "blinding_map": "widget-map.json"}


def write_pr_pack(path: Path, widget: dict) -> dict:
    """The blinding fixture's pack plus the change set from the vulnerable snapshot to the fixed one."""
    pack = write_pack(path, widget)
    cases.add_change_set(pack, {"change_set_id": "cs-fix", "base_snapshot_id": "snap-a",
                                "head_snapshot_id": "snap-fixed", "boundary": "repair",
                                "review_scope": "changed_files",
                                "description": "The pull request that repairs the shell call."})
    cases.set_pr_eligibility(pack, "case-a", "cs-fix", "repaired", "changed", control_id="C-case-a-fixed")
    cases.save_pack(path, pack)
    return pack


class InspectingPrAdapter(FakeAdapter):
    """Reads every blob of both synthetic commits and the workspace, the way a curious PR scanner would."""

    scan_modes = frozenset({"full", "pr"})

    def __init__(self):
        super().__init__()
        self.seen: dict = {}

    def scan(self, *, request, source_dir, raw_dir, **kwargs):
        pr = request["input"]["pr"]
        blobs = {}
        for commit in (pr["base"], pr["head"]):
            names = subprocess_git(source_dir, "ls-tree", "-r", "--name-only", commit).splitlines()
            blobs[commit] = {name: subprocess_git(source_dir, "show", f"{commit}:{name}") for name in names}
        workspace = source_dir.parent
        every_name = {part for path in workspace.rglob("*")
                      if ".git" not in path.relative_to(workspace).parts
                      for part in path.relative_to(workspace).parts}
        self.seen = {
            "tokens_in_edited": sorted({(name, token) for commit in blobs.values()
                                        for name, text in commit.items() if name in EDITED
                                        for token in PSEUDONYMS if token in text}),
            "tokens_in_request": [token for token in PSEUDONYMS if token.casefold() in json.dumps(request).casefold()],
            "replaced_in_base": [name for name, text in blobs[pr["base"]].items() if "Sprocket" in text],
            "replaced_in_head": [name for name, text in blobs[pr["head"]].items() if "Sprocket" in text],
            "paths": {"base": sorted(blobs[pr["base"]]), "head": sorted(blobs[pr["head"]])},
            "leaked_names": sorted(every_name & {"widget-map.json", "provenance.json", "original", "evaluator",
                                                 "pack.json", "schedule.json"}),
            "name_status": subprocess_git(source_dir, "diff", "--name-status", pr["base"], pr["head"]),
        }
        return super().scan(request=request, source_dir=source_dir, raw_dir=raw_dir, **kwargs)


def subprocess_git(workspace: Path, *args: str) -> str:
    argv, env = materialize.git_command(list(args))
    return subprocess.run(argv, cwd=str(workspace), env=env, capture_output=True, text=True, check=True).stdout


def blinded_pr_run(tmp_path: Path, widget: dict, document: dict, adapter: Adapter) -> tuple[dict, Path]:
    write_pr_pack(tmp_path / "pack.json", widget)
    blinding.save_map(tmp_path / "widget-map.json", document)
    write_config(tmp_path / "run.json", [BLINDED_PR])
    out = tmp_path / "out"
    return run_from_config(tmp_path / "run.json", out, clock=CLOCK, adapters={"fake": adapter}), out


def test_a_blinded_pr_input_is_blinded_with_one_map_for_the_base_and_the_head(tmp_path, widget):
    document = widget_map(widget)
    adapter = InspectingPrAdapter()

    manifest, out = blinded_pr_run(tmp_path, widget, document, adapter)

    [row] = manifest["inputs"]
    assert manifest["status"] == "completed" and manifest["invocations"][0]["status"] == "success"
    assert (row["input_id"], row["mode"], row["profile"], row["change_set_id"]) == (
        "cs-fix.blinded", "pr", "metadata_blinded", "cs-fix")
    assert row["preparation_failure"] is None and adapter.calls == 1
    # The scanner reads the transformed trees, in the head and, through git, in the base: no original
    # token in any file the map edited, in either commit, and the same pseudonym where the same
    # original was. Files the map leaves alone keep what they hold, as in a full blinded input.
    assert adapter.seen["tokens_in_edited"] == [] and adapter.seen["tokens_in_request"] == []
    assert adapter.seen["replaced_in_base"] == ["README.md", "docs/guide.md", "mkdocs.yml"]
    assert adapter.seen["replaced_in_head"] == ["README.md", "mkdocs.yml"], "the fixed head deletes the guide"
    assert adapter.seen["leaked_names"] == []
    assert sorted(line.split("\t")[0] + " " + line.split("\t")[1] for line in adapter.seen["name_status"].splitlines()
                  ) == ["D docs/guide.md", "M README.md", "M src/app.py"]

    execution = load_document(out / "invocations" / "cs-fix.blinded__fake-a__r1" / "execution.json",
                              "execution-record")
    provenance = execution["provenance"]
    original_head = materialize.tree_hash(widget["exports"]["snap-fixed"].hashes)
    original_base = materialize.tree_hash(widget["exports"]["snap-a"].hashes)
    head = materialize.hash_exported_tree(out / "inputs" / "cs-fix.blinded" / "source")["tree_hash"]
    base = materialize.hash_exported_tree(out / "inputs" / "cs-fix.blinded" / "base" / "source")["tree_hash"]
    assert row["tree_hash"] == provenance["tree_hash"] == head and provenance["profile"] == "metadata_blinded"
    assert {head, base}.isdisjoint({original_head, original_base}), "what is hashed is what a scanner saw"
    assert provenance["blinding"] == {
        **blinding.map_identity(document), "original_tree_hash": original_head, "transformed_tree_hash": head,
        "base_original_tree_hash": original_base, "base_transformed_tree_hash": base}
    assert provenance["pr"]["base_tree_hash"] == base and provenance["pr"]["head_tree_hash"] == head
    assert provenance["pr"]["changes"] == {"added": [], "deleted": ["docs/guide.md"],
                                            "modified": ["README.md", "src/app.py"], "renamed": [], "mode_changed": []}
    # One map, recorded once per variant in the preparation record, with the same identity.
    record = json.loads((out / "inputs" / "cs-fix.blinded" / "provenance.json").read_text(encoding="utf-8"))
    assert record["head"]["blinding"]["map_sha256"] == record["base"]["blinding"]["map_sha256"] == \
        blinding.map_sha256(document)
    assert (out / "inputs" / "cs-fix.blinded" / "original" / "source" / "README.md").read_text(
        encoding="utf-8") == README_FIXED, "the originals stay evaluator-side"
    assert (out / "inputs" / "cs-fix.blinded" / "original" / "base" / "source" / "README.md").read_text(
        encoding="utf-8") == README_VULNERABLE
    assert not (out / "inputs" / "cs-fix.blinded" / "base" / "original").exists()


def test_a_blinded_pr_plan_names_the_map_binds_to_the_transformed_trees_and_refers_labels_to_the_original(tmp_path,
                                                                                                        widget):
    document = widget_map(widget)

    manifest, out = blinded_pr_run(tmp_path, widget, document, InspectingPrAdapter())

    bundle = out / "invocations" / "cs-fix.blinded__fake-a__r1"
    execution = load_document(bundle / "execution.json", "execution-record")
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    original_head = materialize.tree_hash(widget["exports"]["snap-fixed"].hashes)
    assert plan["schema_version"] == "2.1" and plan["input_hash"] == execution["provenance"]["input_hash"]
    assert plan["provenance"]["source_tree_hash"] == original_head, "the labels refer to the original head export"
    assert plan["provenance"]["blinding"] == blinding.map_identity(document)
    assert plan["provenance"]["input_id"] == "cs-fix.blinded" and plan["provenance"]["profile"] == "metadata_blinded"
    assert plan["provenance"]["pr"]["head_tree_hash"] == execution["provenance"]["tree_hash"] != original_head
    assert [(c["control_id"], c["pr_scope"]) for c in plan["controls"]] == [
        ("C-case-a-fixed", {"relation": "repaired", "code_scope": "changed"})]
    assert plan["targets"] == [], "the target is on the base, and a PR review reads the head"
    frozen = cases.load_pack(out / "evaluator" / "pack.json")
    for snapshot_id in ("snap-a", "snap-fixed"):
        assert cases.snapshot_by_id(frozen, snapshot_id)["tree_hash"] == materialize.tree_hash(
            widget["exports"][snapshot_id].hashes), "both declared hashes are the originals'"
    outcomes = [(outcome["case_id"], outcome["passed"]) for outcome in manifest["inputs"][0]["mechanical_checks"]]
    assert outcomes == [("case-a", True), ("case-a", True)], "the case is checked against both original exports"
    assert main(["replay", str(bundle), "--output", str(tmp_path / "replayed.json")]) == 0
    assert (tmp_path / "replayed.json").read_bytes() == (bundle / "evaluation.json").read_bytes()


def test_a_map_that_does_not_cover_the_base_fails_the_pr_input_and_no_scanner_sees_it(tmp_path, widget):
    document = widget_map(widget, approved=False)
    document["variants"] = [_variant(document, "snap-fixed")]
    for edit in document["edits"]:
        edit["expected"] = [_expected(edit, "snap-fixed")]
    approve(document)
    adapter = InspectingPrAdapter()

    manifest, out = blinded_pr_run(tmp_path, widget, document, adapter)

    [row] = manifest["inputs"]
    assert row["preparation_failure"]["type"] == "MaterializationError"
    assert "has no variant for snapshot snap-a" in row["preparation_failure"]["message"]
    assert (row["tree_hash"], row["input_hash"]) == (None, None) and adapter.calls == 0
    assert manifest["invocations"][0]["status"] == "skipped"
    assert not (out / "inputs" / "cs-fix.blinded").exists(), "nothing was exported: no half-blinded input"


def test_a_blinded_pr_run_is_refused_when_related_inputs_name_different_maps(tmp_path, widget):
    document = widget_map(widget)
    write_pr_pack(tmp_path / "pack.json", widget)
    blinding.save_map(tmp_path / "widget-map.json", document)
    other = deepcopy(document)
    other["map_id"] = "another-map"
    reapproved(other)
    blinding.save_map(tmp_path / "another-map.json", other)
    write_config(tmp_path / "run.json", [BLINDED_PR, {"snapshot_id": "snap-a", "profile": "metadata_blinded",
                                                       "blinding_map": "another-map.json"}])

    with pytest.raises(ContractError, match="are blinded snapshots of one repository .* but name different maps"):
        run_from_config(tmp_path / "run.json", tmp_path / "out", clock=CLOCK, adapters={"fake": FakeAdapter()})
    assert not (tmp_path / "out").exists()
