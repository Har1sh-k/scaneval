"""Metadata blinding maps: the contract, the review chain, and what approves a map.

The fixture is one local repository with a vulnerable and a fixed commit and one map covering both.
Every approval here is recorded by "Fixture Reviewer (fictional)": no test records, implies, or
stands in for a real person's review. Nothing touches the network, calls a model, or sleeps.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
from typing import Callable

import pytest

from scaneval import blinding, materialize
from scaneval.contracts import ContractError, chain_digest, validate_document


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
