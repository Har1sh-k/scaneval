"""Source cache immutability, pinned export, tree hashing, and synthetic history."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

import pytest

from scaneval.contracts import ContractError, canonical_sha256
from scaneval.materialize import (
    HARNESS_STATE_DIRS,
    STRIPPED_TOP_LEVEL,
    MaterializationError,
    cache_key,
    export_snapshot,
    fetch_snapshot,
    hash_exported_tree,
    prepare_synthetic_history,
    tree_hash,
    walk_regular_files,
    write_provenance,
)


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "upstream"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "app.py").write_text("print('v1')\n", encoding="utf-8")
    (repo / "src").mkdir()
    (repo / "src" / "run.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    (repo / "src" / "run.sh").chmod(0o755)
    (repo / ".securevibes").mkdir()
    (repo / ".securevibes" / "findings.md").write_text("controller state\n", encoding="utf-8")
    (repo / "CLAUDE.md").write_text("project instructions\n", encoding="utf-8")
    (repo / ".claude").mkdir()
    (repo / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    (repo / ".github" / "copilot-instructions.md").write_text("assistant instructions\n", encoding="utf-8")
    (repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (repo / "ignored.txt").write_text("tracked despite ignore\n", encoding="utf-8")
    os.symlink("app.py", repo / "link.py")
    git("add", "-A", "-f", ".", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    first = git("rev-parse", "HEAD", cwd=repo)
    (repo / "app.py").write_text("print('v2')\n", encoding="utf-8")
    git("commit", "-q", "-am", "second", cwd=repo)
    return repo, first


def test_cache_key_is_stable_and_url_derived():
    sha = "a" * 40
    assert cache_key("https://github.com/acme/widget.git", sha) == "acme_widget__aaaaaaaaaaaa"
    assert cache_key("git@github.com:acme/widget.git", sha) == "acme_widget__aaaaaaaaaaaa"
    assert cache_key("/local/path/widget", sha).endswith("__aaaaaaaaaaaa")


def test_fetch_requires_a_full_sha(tmp_path, upstream):
    repo, _ = upstream
    with pytest.raises(MaterializationError, match="full 40-hex SHA"):
        fetch_snapshot(str(repo), "main", tmp_path / "cache")


def test_fetch_pins_exact_commit_and_second_fetch_verifies_cache(tmp_path, upstream):
    repo, first = upstream
    cache = tmp_path / "cache"
    snapshot = fetch_snapshot(str(repo), first, cache)
    assert snapshot.commit == first
    assert snapshot.fetch_method in {"depth1-sha", "full-fetch"}
    assert (snapshot.path / "app.py").read_text(encoding="utf-8") == "print('v1')\n"
    assert not list(cache.glob("*.partial"))

    again = fetch_snapshot(str(repo), first, cache)
    assert again.fetch_method == "cached"
    assert again.git_tree == snapshot.git_tree


def test_modified_cache_entry_is_rejected(tmp_path, upstream):
    repo, first = upstream
    cache = tmp_path / "cache"
    snapshot = fetch_snapshot(str(repo), first, cache)
    (snapshot.path / "app.py").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(MaterializationError, match="immutable"):
        fetch_snapshot(str(repo), first, cache)


def test_export_strips_state_skips_links_records_cues_and_hashes_tree(tmp_path, upstream):
    repo, first = upstream
    snapshot = fetch_snapshot(str(repo), first, tmp_path / "cache")
    trial = tmp_path / "trial"
    clock = lambda: datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)  # noqa: E731
    record = export_snapshot(snapshot, trial, clock=clock)

    source = trial / "source"
    exported = sorted(p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file())
    assert exported == [".claude/settings.json", ".github/copilot-instructions.md", ".github/workflows/ci.yml",
                        ".gitignore", "CLAUDE.md", "app.py", "ignored.txt", "src/run.sh"]
    assert not (source / ".git").exists()
    assert not (source / ".securevibes").exists()
    assert os.access(source / "src" / "run.sh", os.X_OK)
    assert record["stripped"] == [".securevibes/findings.md"]
    assert record["skipped"] == [{"path": "link.py", "reason": "symbolic link not exported"}]
    # Instruction cues are the files an assistant reads as instructions, not all of .github:
    # ordinary workflow and CODEOWNERS files are repository content, not a retained cue.
    assert record["instruction_files"] == [".claude/settings.json", ".github/copilot-instructions.md", "CLAUDE.md"]
    assert ".github/workflows/ci.yml" not in record["instruction_files"]
    assert ".github/copilot-instructions.md" in record["instruction_files"]
    assert ".claude/settings.json" in record["instruction_files"]
    assert record["source"] == {"url": str(repo), "commit": first, "git_tree": snapshot.git_tree,
                                "fetch_method": snapshot.fetch_method}
    assert record["exported_at"] == "2026-09-20T12:00:00+00:00"
    assert record["profile"] == "standard"
    assert record["synthetic_history"] is None
    assert record["trial"]["file_count"] == 8

    expected = {}
    for rel in exported:
        import hashlib
        expected[rel] = "sha256:" + hashlib.sha256((source / rel).read_bytes()).hexdigest()
    assert record["trial"]["tree_hash"] == tree_hash(expected) == canonical_sha256(dict(sorted(expected.items())))
    assert hash_exported_tree(source) == {"tree_hash": record["trial"]["tree_hash"], "file_count": 8}

    path = write_provenance(trial, record)
    assert json.loads(path.read_text(encoding="utf-8")) == record
    with pytest.raises(FileExistsError):
        write_provenance(trial, record)


def test_export_refuses_existing_source_and_unavailable_blinding(tmp_path, upstream):
    repo, first = upstream
    snapshot = fetch_snapshot(str(repo), first, tmp_path / "cache")
    trial = tmp_path / "trial"
    with pytest.raises(MaterializationError, match="blinding unavailable"):
        export_snapshot(snapshot, trial, profile="metadata_blinded")
    with pytest.raises(MaterializationError, match="not implemented"):
        export_snapshot(snapshot, trial, profile="metadata_blinded", blinding_map={})
    with pytest.raises(MaterializationError, match="unknown input profile"):
        export_snapshot(snapshot, trial, profile="anonymized")
    assert not (trial / "source").exists()
    export_snapshot(snapshot, trial)
    with pytest.raises(MaterializationError, match="already exists"):
        export_snapshot(snapshot, trial)


def test_synthetic_history_is_single_neutral_commit_covering_ignored_files(tmp_path, upstream):
    repo, first = upstream
    snapshot = fetch_snapshot(str(repo), first, tmp_path / "cache")
    trial = tmp_path / "trial"
    record = export_snapshot(snapshot, trial)
    before = hash_exported_tree(trial / "source")
    history = prepare_synthetic_history(trial / "source")
    source = trial / "source"
    assert git("rev-parse", "HEAD", cwd=source) == history["commit"]
    assert git("log", "--format=%s%n%an <%ae>", cwd=source).splitlines() == ["snapshot", "ScanEval <scaneval@localhost>"]
    assert git("rev-list", "--count", "HEAD", cwd=source) == "1"
    assert "ignored.txt" in git("ls-files", cwd=source).splitlines()
    assert hash_exported_tree(source) == before
    assert record["trial"]["tree_hash"] == before["tree_hash"]
    with pytest.raises(MaterializationError, match="already has git history"):
        prepare_synthetic_history(source)


def test_inspect_commit_reports_parent_and_dates_without_caching(tmp_path, upstream):
    from scaneval.materialize import inspect_commit
    repo, first = upstream
    second = git("rev-parse", "HEAD", cwd=repo)
    info = inspect_commit(str(repo), second)
    assert info["commit"] == second and info["parents"] == [first] and info["subject"] == "second"
    assert info["committed_at"][:4].isdigit() and "T" in info["committed_at"]
    assert not list(tmp_path.glob("scaneval-inspect-*"))
    with pytest.raises(MaterializationError, match="full 40-hex SHA"):
        inspect_commit(str(repo), "HEAD")


def test_a_provenance_record_utf8_cannot_encode_leaves_no_file_behind(tmp_path):
    """A lone UTF-16 surrogate survives canonical JSON and fails only when the bytes are made.

    The refusal must come before the file exists: an empty provenance.json would read as a
    preparation record for an export nothing can verify.
    """
    trial = tmp_path / "trial"
    trial.mkdir()

    with pytest.raises(ContractError, match="not canonical UTF-8 JSON"):
        write_provenance(trial, {"note": f"lone surrogate {chr(0xD800)}"})

    assert not (trial / "provenance.json").exists()


def test_instruction_cue_detection_covers_assistant_files_only():
    from scaneval.materialize import _is_instruction_file

    for path in ("CLAUDE.md", "docs/AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".clinerules",
                 ".claude/settings.json", ".codex/config.toml", ".cursor/rules/style.mdc",
                 ".github/copilot-instructions.md", ".github/instructions/python.instructions.md"):
        assert _is_instruction_file(path), path
    for path in (".github/workflows/ci.yml", ".github/CODEOWNERS", ".github/ISSUE_TEMPLATE/bug.md",
                 ".github/dependabot.yml", "README.md", "src/claude.py", "docs/github/instructions/x.md"):
        assert not _is_instruction_file(path), path


# --- one enumeration, and one list of harness state directories ---------------------------


def test_the_exported_hash_raises_rather_than_shrinking_when_a_directory_cannot_be_walked(tmp_path):
    """An unreadable directory used to hash exactly like an absent one.

    :meth:`Path.rglob` swallows the ``OSError`` the walk raises, so the files behind such a
    directory silently left the map and the recomputed hash described a tree that was never
    there. The walk raises now, and the caller decides what a tree it cannot enumerate means.
    """
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    closed = source / "closed"
    closed.mkdir()
    (closed / "hidden.py").write_text("y = 2\n", encoding="utf-8")
    closed.chmod(0o000)
    try:
        with pytest.raises(PermissionError):
            hash_exported_tree(source)
        with pytest.raises(PermissionError):
            walk_regular_files(source)
        # The exclusions are never descended into, so an unreadable one cannot fail the walk.
        closed.chmod(0o700)
        git_dir = source / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        git_dir.chmod(0o000)
        assert sorted(walk_regular_files(source)) == ["closed/hidden.py", "src/app.py"]
        assert sorted(walk_regular_files(source, skip_top_level=frozenset({"closed"}))) == ["src/app.py"]
    finally:
        for directory in (closed, source / ".git"):
            if directory.exists():
                directory.chmod(0o700)


def test_one_list_of_harness_state_directories_feeds_the_export_and_the_adapter():
    """The export stripped ``.securevibes`` but not ``.fieldglass``; the adapter claimed both.

    A repository shipping a top-level ``.fieldglass`` was therefore exported with it in place
    and then had it excluded from the modification check as scanner scratch, so bytes inside the
    input hash were rewritten unwatched. One list is the source of truth for both ends now.
    """
    from scaneval.adapters.llm_harness import HARNESS_PRESETS, LlmHarnessAdapter

    assert set(LlmHarnessAdapter.state_dirs) == set(HARNESS_STATE_DIRS)
    assert {preset["state_dir"] for preset in HARNESS_PRESETS.values()} == set(HARNESS_STATE_DIRS)
    assert HARNESS_STATE_DIRS <= STRIPPED_TOP_LEVEL
    assert ".fieldglass" in HARNESS_STATE_DIRS


def test_an_export_strips_every_harness_state_directory(tmp_path):
    """The end of the same finding: both state directories leave the snapshot on export."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "app.py").write_text("print('v1')\n", encoding="utf-8")
    for name in sorted(HARNESS_STATE_DIRS):
        (repo / name).mkdir()
        (repo / name / "findings.md").write_text(f"{name} scratch\n", encoding="utf-8")
    git("add", "-A", "-f", ".", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    commit = git("rev-parse", "HEAD", cwd=repo)

    snapshot = fetch_snapshot(str(repo), commit, tmp_path / "cache")
    record = export_snapshot(snapshot, tmp_path / "trial")

    source = tmp_path / "trial" / "source"
    assert record["stripped"] == [f"{name}/findings.md" for name in sorted(HARNESS_STATE_DIRS)]
    assert [path.name for path in source.iterdir()] == ["app.py"]
    assert record["trial"]["file_count"] == 1
