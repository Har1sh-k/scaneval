"""Metadata blinding: a reviewed map, applied only to documentation and display text, all or nothing.

The fixture is one local repository with a vulnerable and a fixed commit and one map covering both.
Every approval here is recorded by "Fixture Reviewer (fictional)": no test records, implies, or
stands in for a real person's review. Nothing touches the network, calls a model, or sleeps.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Callable

import pytest

from scaneval import blinding, materialize
from scaneval.contracts import ContractError, canonical_json, chain_digest, validate_document
from scaneval.materialize import MaterializationError


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
