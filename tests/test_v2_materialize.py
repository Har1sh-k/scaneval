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
    git_command,
    hash_exported_tree,
    prepare_synthetic_history,
    tree_hash,
    verify_cached_snapshot,
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


def test_only_the_top_level_git_directory_is_left_out_of_the_walk(tmp_path):
    """A ``.git`` at any depth was skipped, which handed a scanner one name to hide under.

    The exclusion exists for the single repository this runner creates at the top of a trial
    source, so that its own bookkeeping is not reported as a scanner modification. Applying it to
    every ``.git`` component anywhere meant anything written under a nested one left the map, the
    exported hash, and the modification check built from it, without a word.
    """
    source = tmp_path / "source"
    (source / "vendor" / ".git").mkdir(parents=True)
    (source / "vendor" / ".git" / "planted.py").write_text("written by the scanner\n", encoding="utf-8")
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    (source / ".git").mkdir()
    (source / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

    walked = walk_regular_files(source)

    assert sorted(walked) == ["app.py", "vendor/.git/planted.py"]
    assert hash_exported_tree(source)["file_count"] == 2
    # An export never ships a nested one, which is why excluding only the top level is sound.
    assert all(part != ".git" for part in "app.py".split("/"))


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


# --- area B: one hermetic environment for every git call ----------------------------------


def test_every_git_invocation_is_built_hermetically(monkeypatch):
    """The single place the rule lives: argv and environment for every git call this package makes.

    Testing each call site separately is what let the last one be missed, so this pins the
    builder itself: no ``GIT_*`` variable from the operator environment survives, global and
    system configuration are off, and hooks and templates are off on the command line as well.
    """
    monkeypatch.setenv("GIT_DIR", "/somewhere/else/.git")
    monkeypatch.setenv("GIT_WORK_TREE", "/somewhere/else")
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i /operator/key")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Operator")

    argv, env = git_command(["status", "--porcelain"])

    assert argv[0] == "git" and argv[-2:] == ["status", "--porcelain"]
    assert f"core.hooksPath={os.devnull}" in argv and "init.templateDir=" in argv
    # The operator's own attributes and ignore files are the same class of input: git falls back
    # to $XDG_CONFIG_HOME/git/ for both when no configuration names them, and that fallback
    # survives GIT_CONFIG_GLOBAL, so it has to be beaten on the command line.
    assert f"core.attributesFile={os.devnull}" in argv
    assert f"core.excludesFile={os.devnull}" in argv
    assert {name for name in env if name.startswith("GIT_")} == {
        "GIT_TERMINAL_PROMPT", "GIT_ASKPASS", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_GLOBAL", "GIT_ATTR_NOSYSTEM", "GIT_TEMPLATE_DIR"}
    assert env["GIT_CONFIG_GLOBAL"] == env["GIT_CONFIG_SYSTEM"] == os.devnull
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_TEMPLATE_DIR"] == ""
    # Everything that is not git's own knob is passed through: ssh still finds ~/.ssh.
    assert env["PATH"] == os.environ["PATH"] and env["HOME"] == os.environ["HOME"]


def test_an_operator_file_in_home_cannot_change_the_bytes_a_snapshot_exports(tmp_path, monkeypatch):
    """Global configuration was off, but git\'s own fallback paths under HOME were still read.

    ``core.attributesFile`` and ``core.excludesFile`` default to ``$XDG_CONFIG_HOME/git/``
    when no configuration names them, and that default survives ``GIT_CONFIG_GLOBAL``. So one
    ``* text eol=crlf`` line in the operator\'s home directory changed the bytes ``git checkout``
    wrote into the cache, and therefore the exported snapshot and the ``tree_hash`` every result
    in the run binds to; one line in the global ignore file hid an untracked file from the check
    that is supposed to prove a cache entry is clean. Both are pointed at os.devnull now.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "app.py").write_bytes(b"print('v1')\nprint('v2')\n")
    git("add", "-A", "-f", ".", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    commit = git("rev-parse", "HEAD", cwd=repo)

    home = tmp_path / "home"
    (home / "git").mkdir(parents=True)
    (home / "git" / "attributes").write_text("* text eol=crlf\n", encoding="utf-8")
    (home / "git" / "ignore").write_text("planted.txt\n", encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home))

    snapshot = fetch_snapshot(str(repo), commit, tmp_path / "cache")
    record = export_snapshot(snapshot, tmp_path / "trial")

    exported = (tmp_path / "trial" / "source" / "app.py").read_bytes()
    assert exported == b"print('v1')\nprint('v2')\n", "an operator attributes file rewrote the export"
    assert b"\r\n" not in exported
    assert record["trial"]["tree_hash"] == hash_exported_tree(tmp_path / "trial" / "source")["tree_hash"]

    # The ignore half of the same finding: a file the operator ignores globally is still an
    # untracked file in a cache entry that is supposed to be a clean checkout of the commit.
    (snapshot.path / "planted.txt").write_text("left behind\n", encoding="utf-8")
    with pytest.raises(MaterializationError, match="immutable"):
        verify_cached_snapshot(snapshot.path, commit)
    monkeypatch.undo()


def test_a_git_call_cannot_be_redirected_by_the_environment(tmp_path, monkeypatch):
    """GIT_DIR and GIT_WORK_TREE were inherited, so this committed into an unrelated repository.

    ``prepare_synthetic_history`` names the directory it is given, but git took the environment
    first: with those variables set it reinitialized, staged, and committed into whatever they
    pointed at, outside the trial workspace entirely. The identity went the same way, since
    ``GIT_AUTHOR_NAME`` overrides the local configuration this sets, so the neutral identity the
    record reports was a claim the operator environment could falsify.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    git("init", "-q", "-b", "main", cwd=outside)
    (outside / "keep.txt").write_text("untouched\n", encoding="utf-8")
    git("add", "-A", cwd=outside)
    git("commit", "-q", "-m", "only commit", cwd=outside)
    head_before = git("rev-parse", "HEAD", cwd=outside)
    source = tmp_path / "trial" / "source"
    source.mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")

    for name, value in (("GIT_DIR", str(outside / ".git")), ("GIT_WORK_TREE", str(outside)),
                        ("GIT_INDEX_FILE", str(outside / ".git" / "index")),
                        ("GIT_AUTHOR_NAME", "Operator"), ("GIT_AUTHOR_EMAIL", "operator@example.com"),
                        ("GIT_COMMITTER_NAME", "Operator"), ("GIT_COMMITTER_EMAIL", "operator@example.com")):
        monkeypatch.setenv(name, value)
    history = prepare_synthetic_history(source)
    monkeypatch.undo()  # the checks below must not be redirected either

    assert (source / ".git").is_dir(), "the history belongs to the directory the call named"
    assert git("rev-parse", "HEAD", cwd=source) == history["commit"]
    assert git("log", "--format=%an <%ae>", cwd=source).splitlines() == ["ScanEval <scaneval@localhost>"]
    # The unrelated repository is exactly as it was: no commit, no staged file, nothing added.
    assert git("rev-parse", "HEAD", cwd=outside) == head_before
    assert git("status", "--porcelain", "--untracked-files=all", cwd=outside) == ""
    assert sorted(p.name for p in outside.iterdir()) == [".git", "keep.txt"]


def test_a_global_hook_or_template_cannot_run_inside_the_trial_workspace(tmp_path, monkeypatch):
    """The operator's global git configuration reached the workspace and could write in it.

    A global ``core.hooksPath``, or a global ``init.templateDir`` holding hooks, put a program in
    the repository this creates, and git then ran it inside the trial workspace where it could
    write into the exported source the runner is about to compare against its hash. ``--no-verify``
    never covered this: it skips the pre-commit and commit-msg hooks, not ``post-commit``.
    """
    home = tmp_path / "home"
    template_hooks = home / "template" / "hooks"
    global_hooks = home / "hooks"
    source = tmp_path / "trial" / "source"
    source.mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    for hooks in (template_hooks, global_hooks):
        hooks.mkdir(parents=True)
        hook = hooks / "post-commit"
        hook.write_text(f"#!/bin/sh\necho ran > {source / 'HOOK-RAN.txt'}\n", encoding="utf-8")
        hook.chmod(0o755)
    (home / ".gitconfig").write_text(
        f"[core]\n\thooksPath = {global_hooks}\n"
        f"[init]\n\ttemplateDir = {home / 'template'}\n"
        "[user]\n\tname = Operator\n\temail = operator@example.com\n", encoding="utf-8")
    before = hash_exported_tree(source)

    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "xdg"))
    prepare_synthetic_history(source)
    monkeypatch.undo()

    assert not (source / "HOOK-RAN.txt").exists(), "a global hook ran inside the trial workspace"
    assert not (source / ".git" / "hooks" / "post-commit").exists(), "the template was copied in"
    assert hash_exported_tree(source) == before, "the exported source is not what it was"
    assert git("log", "--format=%an <%ae>", cwd=source).splitlines() == ["ScanEval <scaneval@localhost>"]
