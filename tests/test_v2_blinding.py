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
from typing import Callable

import pytest

from scaneval import blinding, cases, materialize
from scaneval.adapters.base import Adapter, NativeOutcome
from scaneval.cli import main
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


@pytest.fixture
def widget(tmp_path: Path) -> dict:
    """A repository with a vulnerable and a fixed commit, and a probe export of each.

    The fixed commit repairs the shell call, adds a README line naming the project again, and
    deletes the guide, so one map has to expect different bytes and counts per variant and one
    file present in one variant and absent in the other.
    """
    repo = tmp_path / "upstream"
    for relative, text in FILES.items():
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
        cached = materialize.fetch_snapshot(str(repo), commit, tmp_path / "cache")
        probes[snapshot_id] = tmp_path / "probe" / snapshot_id / "source"
        exports[snapshot_id] = materialize.export_tree(cached, probes[snapshot_id])
    return {"repo": repo, "commits": commits, "exports": exports, "probes": probes, "cache": tmp_path / "cache"}


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
        "edit_file_hash", "edit_occurrences", "edit_line_structure", "unedited_files_unchanged"}
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
])
def test_only_documentation_and_reviewed_display_metadata_may_be_edited(path, role, role_check, reason):
    gap = blinding.path_class_gap(path, role, role_check)
    if reason is None:
        assert gap is None
    else:
        assert gap is not None and reason in gap


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

    code, printed, _ = cli(capsys, *argv, "--snapshot-id", "snap-fixed")
    assert code == 0 and "snap-a:" not in printed and "snap-fixed: pass" in printed
    code, _, err = cli(capsys, *argv, "--snapshot-id", "snap-zzz")
    assert code == 2 and "has no variant for snapshot snap-zzz" in err


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
