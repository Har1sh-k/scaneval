"""Source cache immutability, pinned export, tree hashing, and synthetic history."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

import pytest

from scaneval.contracts import ContractError, canonical_sha256, pr_diff_sha256, pr_input_hash
from scaneval.materialize import (
    HARNESS_STATE_DIRS,
    STRIPPED_TOP_LEVEL,
    Containment,
    MaterializationError,
    cache_key,
    changed_paths,
    diff_trees,
    export_pr,
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
    """Blinding without a map is unavailable, and a map that is not a blinding map is refused.

    The second refusal used to read "not implemented". Blinding is implemented now, so a supplied
    map is validated as the blinding-map contract it claims to be, and an empty one is refused by
    that contract before anything is exported; ``test_v2_blinding.py`` covers real maps.
    """
    repo, first = upstream
    snapshot = fetch_snapshot(str(repo), first, tmp_path / "cache")
    trial = tmp_path / "trial"
    with pytest.raises(MaterializationError, match="blinding unavailable"):
        export_snapshot(snapshot, trial, profile="metadata_blinded")
    with pytest.raises(ContractError, match="not a blinding-map version"):
        export_snapshot(snapshot, trial, profile="metadata_blinded", blinding_map={}, snapshot_id="snap-a")
    with pytest.raises(MaterializationError, match="unknown input profile"):
        export_snapshot(snapshot, trial, profile="anonymized")
    assert not (trial / "source").exists() and not (trial / "original").exists()
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


def test_containment_compares_against_the_base_it_captured_not_one_resolved_afterwards(tmp_path):
    """The check used to resolve its own base on every call, which made it vacuous against a swap.

    A process with write access to the directory it was handed can reach the directory above it.
    Moving the real base aside and leaving a symbolic link to a tree it controls moved the base
    along with the path: both resolved under the root it chose, the comparison succeeded, and
    the check said nothing at all. The real path is read once, before that process runs, and
    every comparison afterwards is against that captured path.
    """
    workspace = tmp_path / "workspace"
    (workspace / "source").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "source").mkdir(parents=True)
    (elsewhere / "source" / "planted.py").write_text("planted\n", encoding="utf-8")

    captured = Containment.capture(workspace)
    real = workspace.resolve()
    assert captured.contains(workspace / "source") == (workspace / "source").resolve()
    assert captured.contains(workspace) == workspace.resolve(), "the base is inside itself"
    assert captured.contains(elsewhere / "source") is None

    workspace.rename(tmp_path / "moved")
    workspace.symlink_to(elsewhere, target_is_directory=True)

    # What resolving the base afterwards would compare: both sides land in the substituted tree.
    assert (workspace / "source").resolve() == (elsewhere / "source").resolve()
    assert captured.contains(workspace / "source") is None
    assert captured.contains(workspace / "source" / "planted.py") is None
    # The captured root is where the directory really was, which the swap cannot change; the
    # base stays the name this run was handed, for making a contained path relative in a record.
    assert captured.base == workspace and captured.root == real


def test_containment_reports_a_path_it_cannot_resolve_the_same_way_as_one_that_escaped(tmp_path):
    """Three outcomes a caller must treat alike, and one that is a setup failure instead."""
    captured = Containment.capture(tmp_path)

    assert captured.contains(tmp_path / "does-not-exist-yet") is not None, "a capture destination"
    assert captured.contains(Path(f"{tmp_path}/holds\x00a-nul")) is None
    assert captured.contains(tmp_path.parent) is None

    with pytest.raises(MaterializationError, match="could not be resolved"):
        # No captured path means nothing can be proved inside it, so this is refused where it
        # happens rather than returning None from a check made after a scanner has run.
        Containment.capture(Path("base\x00with-a-nul"))


# --- native PR inputs: two exports, the diff between them, and the neutral history a scanner is given ---


def write_tree(root: Path, files: dict[str, str | tuple[str, int]]) -> Path:
    """Write *files* under *root*; a value is the text, or the text and the mode to give the file."""
    for relative, value in files.items():
        text, mode = (value, 0o644) if isinstance(value, str) else value
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(mode)
    return root


UNCHANGED = "print('unchanged')\n"
MOVED = "def helper():\n    return 'shared by the rename'\n"
BASE_FILES = {
    "README.md": "# widget\n", "src/unchanged.py": UNCHANGED, "src/app.py": "print('v1')\n",
    "src/old_only.py": "print('only in the base')\n", "lib/util.py": MOVED,
    "bin/run.sh": ("#!/bin/sh\necho run\n", 0o644),
}
HEAD_FILES = {
    "README.md": "# widget\n", "src/unchanged.py": UNCHANGED, "src/app.py": "print('v2')\n",
    "src/new_only.py": "print('added in the head')\n", "lib/helpers.py": MOVED,
    "bin/run.sh": ("#!/bin/sh\necho run\n", 0o755),
}


def test_diff_trees_records_added_deleted_modified_renamed_and_mode_changed_files(tmp_path):
    base = write_tree(tmp_path / "base", BASE_FILES)
    head = write_tree(tmp_path / "head", HEAD_FILES)

    changes = diff_trees(base, head)

    assert changes == {"added": ["src/new_only.py"], "deleted": ["src/old_only.py"],
                       "modified": ["src/app.py"], "renamed": [["lib/util.py", "lib/helpers.py"]],
                       "mode_changed": ["bin/run.sh"]}
    assert changed_paths(changes) == ["bin/run.sh", "lib/helpers.py", "src/app.py", "src/new_only.py",
                                      "src/old_only.py"], "a rename is named by its new path, as git names it"
    assert diff_trees(base, base) == {"added": [], "deleted": [], "modified": [], "renamed": [], "mode_changed": []}


def test_diff_trees_pairs_only_an_unambiguous_exact_rename_and_never_a_similar_file(tmp_path):
    base = write_tree(tmp_path / "base", {
        "a/one.txt": "same bytes\n", "a/two.txt": "same bytes\n", "b/moved.py": "x = 1\ny = 2\n",
        "c/edited.py": "keep\nkeep\nkeep\nold\n", "e/empty": "", "s/script.sh": ("echo\n", 0o644)})
    head = write_tree(tmp_path / "head", {
        "z/one.txt": "same bytes\n", "z/two.txt": "same bytes\n", "b2/moved.py": "x = 1\ny = 2\n",
        "c/edited2.py": "keep\nkeep\nkeep\nnew\n", "e2/empty": "", "s2/script.sh": ("echo\n", 0o755)})

    changes = diff_trees(base, head)

    assert changes["renamed"] == [["b/moved.py", "b2/moved.py"], ["e/empty", "e2/empty"],
                                  ["s/script.sh", "s2/script.sh"]]
    assert changes["added"] == ["c/edited2.py", "z/one.txt", "z/two.txt"], \
        "two identical files on each side name no pairing, and an edited move is an add and a delete"
    assert changes["deleted"] == ["a/one.txt", "a/two.txt", "c/edited.py"]
    assert changes["modified"] == [] and changes["mode_changed"] == ["s2/script.sh"], \
        "the renamed file whose executable bit differs from its source's says so under its new name"


def test_diff_trees_reports_a_file_whose_bytes_and_mode_both_changed_under_both_headings(tmp_path):
    base = write_tree(tmp_path / "base", {"tool.sh": ("echo one\n", 0o644)})
    head = write_tree(tmp_path / "head", {"tool.sh": ("echo two\n", 0o755)})

    assert diff_trees(base, head) == {"added": [], "deleted": [], "modified": ["tool.sh"], "renamed": [],
                                      "mode_changed": ["tool.sh"]}


def test_diff_trees_reads_the_trees_as_they_lie_and_leaves_out_links_and_the_git_directory(tmp_path):
    base = write_tree(tmp_path / "base", {"a.py": "1\n"})
    head = write_tree(tmp_path / "head", {"a.py": "1\n", ".git/config": "[core]\n"})
    os.symlink("a.py", head / "link.py")

    assert diff_trees(base, head) == {"added": [], "deleted": [], "modified": [], "renamed": [],
                                      "mode_changed": []}


@pytest.fixture
def pull_request(tmp_path: Path) -> dict:
    """A repository with a base commit and a head commit one pull request apart, both fetched."""
    repo = tmp_path / "upstream"
    write_tree(repo, {**BASE_FILES, ".securevibes/state.md": "controller state\n",
                      "CLAUDE.md": "project instructions\n"})
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    git("add", "-A", "-f", ".", cwd=repo)
    git("commit", "-q", "-m", "base", cwd=repo)
    base = git("rev-parse", "HEAD", cwd=repo)
    (repo / "src" / "old_only.py").unlink()
    (repo / "lib" / "util.py").rename(repo / "lib" / "helpers.py")
    write_tree(repo, {name: HEAD_FILES[name] for name in ("src/new_only.py", "src/app.py", "bin/run.sh")})
    git("add", "-A", "-f", ".", cwd=repo)
    git("commit", "-q", "-m", "head", cwd=repo)
    head = git("rev-parse", "HEAD", cwd=repo)
    cache = tmp_path / "cache"
    return {"repo": repo, "base": fetch_snapshot(str(repo), base, cache), "head": fetch_snapshot(str(repo), head, cache),
            "cache": cache}


CLOCK = lambda: datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)  # noqa: E731


def test_export_pr_writes_the_head_and_the_base_and_records_the_change_between_them(tmp_path, pull_request):
    trial = tmp_path / "trial"

    record = export_pr(pull_request["base"], pull_request["head"], trial, clock=CLOCK)

    assert record["schema_version"] == "2.1" and record["mode"] == "pr" and record["profile"] == "standard"
    assert (trial / "source" / "src" / "new_only.py").is_file()
    assert (trial / "base" / "source" / "src" / "old_only.py").is_file()
    assert not (trial / "source" / ".securevibes").exists() and not (trial / "base" / "source" / ".securevibes").exists()
    assert (record["head"]["trial"]["root"], record["base"]["trial"]["root"]) == ("source", "base/source")
    assert record["head"]["source"]["commit"] == pull_request["head"].commit
    assert record["base"]["source"]["commit"] == pull_request["base"].commit
    for side, root in (("head", trial / "source"), ("base", trial / "base" / "source")):
        assert record[side]["trial"]["tree_hash"] == hash_exported_tree(root)["tree_hash"]
        assert record[side]["profile"] == "standard" and record[side]["synthetic_history"] is None
    changes = {"added": ["src/new_only.py"], "deleted": ["src/old_only.py"], "modified": ["src/app.py"],
               "renamed": [["lib/util.py", "lib/helpers.py"]], "mode_changed": ["bin/run.sh"]}
    base_hash, head_hash = record["base"]["trial"]["tree_hash"], record["head"]["trial"]["tree_hash"]
    assert base_hash != head_hash
    assert record["diff"] == {"base_tree_hash": base_hash, "head_tree_hash": head_hash, "changes": changes,
                              "diff_sha256": pr_diff_sha256(base_hash, head_hash, changes)}
    assert record["input_hash"] == pr_input_hash(base_hash, head_hash, record["diff"]["diff_sha256"])
    assert write_provenance(trial, record).is_file(), "the record is a document the trial can carry"
    assert (trial / "provenance.json").is_file() and (trial / "source").is_dir(), "and a trial the CLI recognizes"


def test_export_pr_refuses_a_change_with_nothing_in_it(tmp_path, pull_request):
    with pytest.raises(MaterializationError, match="no change to review"):
        export_pr(pull_request["head"], pull_request["head"], tmp_path / "trial", clock=CLOCK)
    with pytest.raises(MaterializationError, match="unknown input profile"):
        export_pr(pull_request["base"], pull_request["head"], tmp_path / "other", profile="anonymized")
    with pytest.raises(MaterializationError, match="blinding unavailable"):
        export_pr(pull_request["base"], pull_request["head"], tmp_path / "other", profile="metadata_blinded")
    assert not (tmp_path / "other").exists()


def test_export_pr_refuses_a_trial_that_already_holds_an_export(tmp_path, pull_request):
    trial = tmp_path / "trial"
    export_pr(pull_request["base"], pull_request["head"], trial, clock=CLOCK)

    with pytest.raises(MaterializationError, match="already exists"):
        export_pr(pull_request["base"], pull_request["head"], trial, clock=CLOCK)
