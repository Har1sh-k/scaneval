"""Source cache immutability, pinned export, tree hashing, and synthetic history."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess

import pytest

from scaneval import materialize as materialize_module
from scaneval.contracts import ContractError, canonical_sha256, pr_diff_sha256, pr_input_hash
from scaneval.materialize import (
    HARNESS_STATE_DIRS,
    STRIPPED_TOP_LEVEL,
    Containment,
    MaterializationError,
    cache_key,
    changed_paths,
    check_pr_history,
    compute_pr_history,
    diff_trees,
    export_pr,
    export_snapshot,
    fetch_snapshot,
    git_command,
    hash_exported_tree,
    prepare_pr_history,
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
    assert changed_paths(changes) == ["bin/run.sh", "lib/helpers.py", "lib/util.py", "src/app.py", "src/new_only.py",
                                      "src/old_only.py"], "a rename is named by both its paths, as git names it without rename detection"
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


def prepared_pr(tmp_path: Path, pull_request: dict, name: str = "trial") -> tuple[Path, Path, dict]:
    trial = tmp_path / name
    record = export_pr(pull_request["base"], pull_request["head"], trial, clock=CLOCK)
    return trial / "source", trial / "base" / "source", record


def test_the_two_commit_history_is_neutral_deterministic_and_the_recorded_change(tmp_path, pull_request):
    head, base, record = prepared_pr(tmp_path, pull_request)
    before = hash_exported_tree(head)

    history = prepare_pr_history(head, base)

    assert history["messages"] == {"base": "base", "head": "head"}
    assert history["identity"] == "ScanEval <scaneval@localhost>" and history["date"] == "2000-01-01T00:00:00+00:00"
    assert git("rev-parse", "HEAD", cwd=head) == history["head_commit"]
    assert git("rev-parse", "HEAD~1", cwd=head) == history["base_commit"]
    assert git("rev-list", "--count", "HEAD", cwd=head) == "2"
    assert git("log", "--date=raw", "--format=%an <%ae>|%cn <%ce>|%ad|%cd|%s", cwd=head).splitlines() == [
        "ScanEval <scaneval@localhost>|ScanEval <scaneval@localhost>|946684800 +0000|946684800 +0000|head",
        "ScanEval <scaneval@localhost>|ScanEval <scaneval@localhost>|946684800 +0000|946684800 +0000|base"]
    assert git("status", "--porcelain", "--untracked-files=all", cwd=head) == ""
    assert hash_exported_tree(head) == before, "only .git was added to the head worktree"
    hooks = head / ".git" / "hooks"
    assert not hooks.exists() or not list(hooks.iterdir()), "no hook or template was copied into the repository"
    # The base tree is read, never written.
    assert not (base / ".git").exists() and hash_exported_tree(base)["tree_hash"] == record["base"]["trial"]["tree_hash"]
    check_pr_history(head, history, record["diff"]["changes"])

    # The same two trees give the same two commits somewhere else, which is what a workspace relies on.
    again_head, again_base, _ = prepared_pr(tmp_path, pull_request, "again")
    assert prepare_pr_history(again_head, again_base) == history


def test_the_git_diff_between_the_synthetic_commits_is_the_recorded_diff(tmp_path, pull_request):
    """The record and git agree without rename detection; with it, git's own pairing of an exact rename is R100."""
    head, base, record = prepared_pr(tmp_path, pull_request)
    history = prepare_pr_history(head, base)
    commits = (history["base_commit"], history["head_commit"])
    changes = record["diff"]["changes"]
    renamed_from = [source for source, _ in changes["renamed"]]
    renamed_to = [target for _, target in changes["renamed"]]

    def name_status(*options: str) -> list[list[str]]:
        return sorted(line.split("\t") for line in git("diff", "--name-status", *options, *commits, cwd=head).splitlines())

    modified = [["M", path] for path in sorted(set(changes["modified"]) | set(changes["mode_changed"]))]
    assert name_status("--no-renames") == sorted(
        [["A", path] for path in changes["added"] + renamed_to] + [["D", path] for path in changes["deleted"] + renamed_from]
        + modified), "a renamed pair is the deletion of its source and the addition of its target"
    assert git("diff", "--name-only", "--no-renames", "-z", f"{commits[0]}..{commits[1]}",
               cwd=head).split("\0")[:-1] == changed_paths(changes)
    # The workspace leaves rename detection on for a scanner's own plain ``git diff``, which pairs the exact rename.
    assert name_status() == sorted(
        [["A", path] for path in changes["added"]] + [["D", path] for path in changes["deleted"]] + modified
        + [["R100", source, target] for source, target in changes["renamed"]])
    assert git("diff", "--name-only", "-z", f"{commits[0]}..{commits[1]}", cwd=head).split("\0")[:-1] == \
        [path for path in changed_paths(changes) if path not in renamed_from], \
        "with rename detection a rename is named by its new path alone"


EDITED = "def helper():\n    a = 1\n    b = 2\n    c = 3\n    d = 4\n    return a + b + c + d\n"


@pytest.mark.parametrize(("base_files", "head_files", "recorded"), [
    ({"lib/util.py": EDITED, "keep.py": "x\n"}, {"lib/helpers.py": EDITED.replace("d = 4", "d = 5"), "keep.py": "x\n"},
     {"added": ["lib/helpers.py"], "deleted": ["lib/util.py"], "modified": [], "renamed": [], "mode_changed": []}),
    ({"a.py": "same\n", "b.py": "same\n", "keep.py": "x\n"}, {"c.py": "same\n", "keep.py": "x\n"},
     {"added": ["c.py"], "deleted": ["a.py", "b.py"], "modified": [], "renamed": [], "mode_changed": []}),
], ids=["moved-and-edited", "one-of-several-identical-files"])
def test_a_move_the_record_does_not_pair_is_an_addition_and_a_deletion_to_git_unless_it_detects_renames(
        tmp_path, base_files, head_files, recorded):
    """The record pairs a rename only when the bytes are identical and one path holds them on each side.

    A moved file that was edited, and one of several identical files that moved, are an addition and a
    deletion in the record. Git's own rename detection, which the workspace leaves on for a scanner's
    plain ``git diff``, pairs both; compared without it, the record is exactly what git lists.
    """
    base = write_tree(tmp_path / "base", base_files)
    head = write_tree(tmp_path / "head", head_files)
    changes = diff_trees(base, head)
    assert changes == recorded

    compute_pr_history(head, base, changes)
    history = prepare_pr_history(head, base)
    commits = (history["base_commit"], history["head_commit"])

    listed = sorted(line.split("\t") for line in
                    git("diff", "--name-status", "--no-renames", *commits, cwd=head).splitlines())
    assert listed == sorted([["A", path] for path in changes["added"]] + [["D", path] for path in changes["deleted"]])
    assert git("diff", "--name-only", "--no-renames", "-z", *commits, cwd=head).split("\0")[:-1] == changed_paths(changes)
    paired = [line.split("\t") for line in git("diff", "--name-status", *commits, cwd=head).splitlines()
              if line.startswith("R")]
    assert len(paired) == 1 and paired[0][1] in changes["deleted"] and paired[0][2] in changes["added"], \
        "git's own rename detection pairs a deletion with an addition here, and the record does not"
    assert set(git("diff", "--name-only", *commits, cwd=head).splitlines()) < set(changed_paths(changes))


def test_the_history_does_not_read_the_operator_environment(tmp_path, pull_request, monkeypatch):
    head, base, _ = prepared_pr(tmp_path, pull_request)
    expected = prepare_pr_history(head, base)
    for name, value in (("GIT_AUTHOR_NAME", "Mallory"), ("GIT_AUTHOR_EMAIL", "m@evil.test"),
                        ("GIT_COMMITTER_NAME", "Mallory"), ("GIT_AUTHOR_DATE", "1999-12-31T00:00:00+00:00"),
                        ("GIT_COMMITTER_DATE", "1999-12-31T00:00:00+00:00"), ("GIT_DIR", str(tmp_path / "elsewhere")),
                        ("GIT_WORK_TREE", str(tmp_path / "elsewhere")), ("GIT_INDEX_FILE", str(tmp_path / "idx"))):
        monkeypatch.setenv(name, value)
    home = tmp_path / "home"
    home.mkdir()
    (home / ".gitconfig").write_text("[user]\n    name = Mallory\n[diff]\n    renames = false\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    other_head, other_base, _ = prepared_pr(tmp_path, pull_request, "hostile")

    assert prepare_pr_history(other_head, other_base) == expected
    assert not (tmp_path / "elsewhere").exists() and not (tmp_path / "idx").exists()


def test_the_history_refuses_a_head_that_already_has_git_and_a_base_that_is_not_there(tmp_path, pull_request):
    head, base, _ = prepared_pr(tmp_path, pull_request)

    with pytest.raises(MaterializationError, match="is not a directory"):
        prepare_pr_history(head, tmp_path / "no-such-base")
    assert not (head / ".git").exists()
    prepare_pr_history(head, base)
    with pytest.raises(MaterializationError, match="already has git history"):
        prepare_pr_history(head, base)


def write_bytes_tree(root: Path, files: dict[str, bytes]) -> Path:
    """Write *files* under *root* byte for byte: :func:`write_tree` writes text, which cannot hold a CRLF."""
    root.mkdir(parents=True, exist_ok=True)
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


def git_bytes(*args: str, cwd: Path) -> bytes:
    """What git prints, byte for byte: :func:`git` decodes and strips, which hides a line-ending rewrite."""
    return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True,
                          env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null"}).stdout


def read_tree_bytes(root: Path) -> dict[str, bytes]:
    """Every regular file under *root* outside ``.git`` and its bytes."""
    return {relative: path.read_bytes() for relative, path in sorted(walk_regular_files(root).items())}


def operator_git(home: Path, cwd: Path, *args: str) -> str:
    """Git as a scanner's own process runs it: the operator's HOME and global configuration, and none of
    the hermetic settings this package gives its own git calls."""
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_") and name != "XDG_CONFIG_HOME"}
    env.update({"HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1"})
    return subprocess.run(["git", *args], cwd=str(cwd), env=env, capture_output=True, text=True, check=True).stdout


def history_built_by_a_plain_git(head: Path, base: Path) -> dict:
    """The two commits of a PR history as an unhardened ``git add`` writes them: no attribute override."""
    git("init", "-q", cwd=head)
    git("config", "core.autocrlf", "false", cwd=head)
    git("--work-tree", str(base), "add", "-A", "-f", ".", cwd=head)
    git("commit", "-q", "--allow-empty", "--no-verify", "-m", "base", cwd=head)
    base_commit = git("rev-parse", "HEAD", cwd=head)
    git("add", "-A", "-f", ".", cwd=head)
    git("commit", "-q", "--allow-empty", "--no-verify", "-m", "head", cwd=head)
    return {"base_commit": base_commit, "head_commit": git("rev-parse", "HEAD", cwd=head)}


@pytest.mark.parametrize(("attributes", "name", "base_bytes", "head_bytes"), [
    (b"* text=auto\n", "crlf.py", b"import os\r\nprint(os)\r\n", b"import os\r\nprint(os.sep)\r\n"),
    (b"* text\n", "crlf.py", b"import os\r\nprint(os)\r\n", b"import os\r\nprint(os.sep)\r\n"),
    (b"*.txt ident\n", "keyword.txt", b"revision $Id: 3f2a$\n", b"revision $Id: 9c1b$\n"),
    (b"*.enc working-tree-encoding=UTF-16\n", "wide.enc", "caf\u00e9\n".encode(), "caf\u00e9 au lait\n".encode()),
], ids=["text-auto", "text", "ident", "working-tree-encoding"])
def test_the_history_stores_the_exported_bytes_whatever_an_in_tree_gitattributes_asks_git_to_convert(
        tmp_path, attributes, name, base_bytes, head_bytes):
    """Each attribute here made ``git add`` store other bytes than the export held, or refuse the file.

    A scanner's own git restores the tree from those blobs, so what it wrote back was not the tree it
    was handed. The history is built with git's content conversion switched off, and every committed
    blob, in the base commit and in the head commit, is the bytes of the file the export wrote.
    """
    base = write_bytes_tree(tmp_path / "base", {".gitattributes": attributes, name: base_bytes, "keep.md": b"keep\n"})
    head = write_bytes_tree(tmp_path / "head", {".gitattributes": attributes, name: head_bytes, "keep.md": b"keep\n"})
    changes = diff_trees(base, head)
    assert changes["modified"] == [name]

    history = prepare_pr_history(head, base)

    for commit, root in ((history["base_commit"], base), (history["head_commit"], head)):
        assert git_bytes("cat-file", "blob", f"{commit}:{name}", cwd=head) == (root / name).read_bytes()
    assert git("diff", "--name-only", "--no-renames", history["base_commit"], history["head_commit"], cwd=head) == name
    check_pr_history(head, history, changes, base)


def operator_home(tmp_path: Path) -> Path:
    """A HOME whose git configuration rewrites content: attributes, a filter, CRLF conversion, and a diff driver."""
    home = tmp_path / "operator-home"
    (home / ".config" / "git").mkdir(parents=True)
    (home / ".config" / "git" / "attributes").write_text(
        "*.py text eol=crlf diff=shout\n*.md filter=shout\n", encoding="utf-8")
    (home / ".gitconfig").write_text(
        "[core]\n\tautocrlf = true\n\teol = crlf\n[filter \"shout\"]\n\tsmudge = tr a-z A-Z\n\tclean = cat\n"
        "[diff \"shout\"]\n\ttextconv = tr a-z A-Z <\n", encoding="utf-8")
    return home


def test_a_scanners_own_git_restores_the_exported_bytes_under_in_tree_and_operator_attributes(tmp_path):
    """Semgrep's baseline scan resets the workspace to the base commit and back to the head, a checkout.

    Whatever git converts on checkout was written into the tree the scanner had been handed: the
    in-tree attributes here ask for CRLF on a shell script, the operator's own attributes file asks
    for CRLF on Python and runs a filter over Markdown, and the operator's global configuration turns
    autocrlf on. None of it reaches the workspace's repository, and the tree is byte for byte what
    the export wrote once both commits have been checked out and restored.
    """
    files = {".gitattributes": b"* text=auto\n*.sh text eol=crlf\n", "run.sh": b"#!/bin/sh\necho run\n",
             "app.py": b"import os\nprint(os)\n", "notes.md": b"lower case\n", "crlf.txt": b"one\r\ntwo\r\n"}
    base = write_bytes_tree(tmp_path / "base", files)
    head = write_bytes_tree(tmp_path / "head", {**files, "app.py": b"import os\nprint(os.sep)\n"})
    history = prepare_pr_history(head, base)
    home = operator_home(tmp_path)
    exported = read_tree_bytes(head)

    for command in (["reset", "-q", "--hard", history["base_commit"]], ["reset", "-q", "--hard", history["head_commit"]],
                    ["checkout", "-q", "--detach", history["base_commit"]],
                    ["checkout", "-q", "--detach", history["head_commit"]]):
        operator_git(home, head, *command)

    assert read_tree_bytes(head) == exported
    assert operator_git(home, head, "status", "--porcelain", "--untracked-files=all") == ""


def test_a_scanners_git_diff_in_the_workspace_reads_no_attribute_from_the_operators_attributes_file(tmp_path):
    """The override unsets conversion of content, and the pinned ``core.attributesFile`` keeps out the rest.

    The operator's attributes file names a ``diff`` driver for Python files, and its configuration
    defines that driver as a program that upper-cases what it is shown. A scanner's ``git diff`` in the
    workspace shows the change as it is; the same command in an ordinary repository under the same
    home shows it upper-cased, which is what makes the first result mean something.
    """
    base = write_tree(tmp_path / "base", {"app.py": "print('one')\n"})
    head = write_tree(tmp_path / "head", {"app.py": "print('two')\n"})
    history = prepare_pr_history(head, base)
    home = operator_home(tmp_path)

    control = tmp_path / "control"
    control.mkdir()
    operator_git(home, control, "init", "-q")
    for name, content in (("app.py", "print('one')\n"), ("app.py", "print('two')\n")):
        (control / name).write_text(content, encoding="utf-8")
        operator_git(home, control, "add", "-A")
        operator_git(home, control, "-c", "user.name=u", "-c", "user.email=u@x", "commit", "-q", "-m", "c")
    if "PRINT('TWO')" not in operator_git(home, control, "diff", "HEAD~1", "HEAD"):
        pytest.skip("this git does not run the operator's diff driver in an ordinary repository")

    shown = operator_git(home, head, "diff", history["base_commit"], history["head_commit"])

    assert "+print('two')" in shown and "PRINT" not in shown


def test_a_scanners_own_git_in_the_workspace_runs_no_hook_and_no_monitor_program_the_operator_configured(tmp_path):
    base = write_tree(tmp_path / "base", {"a.py": "1\n"})
    head = write_tree(tmp_path / "head", {"a.py": "2\n"})
    history = prepare_pr_history(head, base)
    home = tmp_path / "operator-home"
    home.mkdir()
    hooks, ran = tmp_path / "operator-hooks", tmp_path / "ran"
    hooks.mkdir()
    ran.mkdir()
    for program in ("post-checkout", "monitor"):
        (hooks / program).write_text(f"#!/bin/sh\necho ran >> '{ran / program}'\n", encoding="utf-8")
        (hooks / program).chmod(0o755)
    (home / ".gitconfig").write_text(f"[core]\n\thooksPath = {hooks}\n\tfsmonitor = {hooks / 'monitor'}\n",
                                     encoding="utf-8")

    def scanner_reads_the_repository(repository: Path, commit: str) -> list[str]:
        operator_git(home, repository, "checkout", "-q", "--detach", commit)
        operator_git(home, repository, "status", "--porcelain")
        found = sorted(path.name for path in ran.iterdir())
        for path in ran.iterdir():
            path.unlink()
        return found

    control = tmp_path / "control"
    control.mkdir()
    operator_git(home, control, "init", "-q")
    (control / "a.py").write_text("1\n", encoding="utf-8")
    operator_git(home, control, "-c", "user.name=u", "-c", "user.email=u@x", "-c", "core.hooksPath=/dev/null",
                 "-c", "core.fsmonitor=false", "add", "-A")
    operator_git(home, control, "-c", "user.name=u", "-c", "user.email=u@x", "-c", "core.hooksPath=/dev/null",
                 "-c", "core.fsmonitor=false", "commit", "-q", "-m", "one")
    if scanner_reads_the_repository(control, "HEAD") != ["monitor", "post-checkout"]:
        pytest.skip("this git does not run the operator's hook and monitor program in an ordinary repository")

    assert scanner_reads_the_repository(head, history["base_commit"]) == []


def test_the_history_pins_the_settings_a_scanners_own_git_would_otherwise_take_from_the_operator(tmp_path):
    base = write_tree(tmp_path / "base", {"a.py": "1\n"})
    head = write_tree(tmp_path / "head", {"a.py": "2\n"})

    prepare_pr_history(head, base)

    assert (head / ".git" / "info" / "attributes").read_text(encoding="utf-8") == \
        "* -text -eol -ident -filter -working-tree-encoding\n"
    for key, value in (("core.attributesFile", os.devnull), ("core.hooksPath", os.devnull), ("core.fsmonitor", "false"),
                       ("core.autocrlf", "false"), ("core.fileMode", "true"), ("diff.renames", "true")):
        assert git("config", "--local", "--get", key, cwd=head) == value


def test_an_in_tree_gitattributes_no_longer_makes_git_read_a_different_change_from_the_export(tmp_path):
    """A base CRLF file and a head LF one under ``* text=auto`` used to be refused; it is now reviewed exactly.

    The export records a modification. With git's conversion on, ``* text=auto`` made ``git add`` store
    one blob for both, so a scanner's ``git diff`` would have shown nothing where the record scores a
    change, and the input was refused. The blobs are now the two files' own bytes, git's diff names
    the file, and the history is the recorded one.
    """
    base = write_bytes_tree(tmp_path / "base", {".gitattributes": b"* text=auto\n", "notes.txt": b"one\r\ntwo\r\n"})
    head = write_bytes_tree(tmp_path / "head", {".gitattributes": b"* text=auto\n", "notes.txt": b"one\ntwo\n"})
    changes = diff_trees(base, head)
    assert changes["modified"] == ["notes.txt"]

    history = compute_pr_history(head, base, changes)

    assert not (head / ".git").exists(), "the history was built in a scratch copy"
    assert prepare_pr_history(head, base) == history
    assert git_bytes("cat-file", "blob", f"{history['base_commit']}:notes.txt", cwd=head) == b"one\r\ntwo\r\n"
    assert git_bytes("cat-file", "blob", f"{history['head_commit']}:notes.txt", cwd=head) == b"one\ntwo\n"
    assert git("diff", "--name-status", history["base_commit"], history["head_commit"], cwd=head) == "M\tnotes.txt"


def test_a_history_whose_blobs_are_not_the_exported_bytes_is_refused_with_the_paths(tmp_path):
    """The path lists agree here, so only the bytes can say the history is not the export's.

    A plain ``git add`` under ``* text=auto`` stores LF for files the export wrote with CRLF, in both
    commits, and the two commits still differ in exactly the file the record says changed. The head's
    blobs are compared whether or not the base tree is named; naming it compares the base commit too.
    """
    files = {".gitattributes": b"* text=auto\n", "notes.txt": b"one\r\ntwo\r\n", "keep.md": b"keep\n"}
    base = write_bytes_tree(tmp_path / "base", files)
    head = write_bytes_tree(tmp_path / "head", {**files, "notes.txt": b"one\r\ntwo\r\nthree\r\n"})
    changes = diff_trees(base, head)
    history = history_built_by_a_plain_git(head, base)
    assert git("diff", "--name-only", history["base_commit"], history["head_commit"], cwd=head) == "notes.txt"

    with pytest.raises(MaterializationError, match="does not hold the exported bytes") as head_only:
        check_pr_history(head, history, changes)
    with pytest.raises(MaterializationError, match="does not hold the exported bytes") as both:
        check_pr_history(head, history, changes, base)

    assert "notes.txt (head)" in str(head_only.value) and "(base)" not in str(head_only.value)
    assert "notes.txt (base)" in str(both.value) and "notes.txt (head)" in str(both.value)


def test_the_base_commit_is_compared_with_the_base_tree_when_it_is_named(tmp_path):
    """A CRLF base beside an LF head under ``* text=auto``: only the base blob is other than exported.

    Without the base tree the head's blobs are fine and the disagreement is found later, as a diff
    that is not the recorded one; with it, the check says which commit holds bytes nobody exported.
    """
    base = write_bytes_tree(tmp_path / "base", {".gitattributes": b"* text=auto\n", "notes.txt": b"one\r\ntwo\r\n"})
    head = write_bytes_tree(tmp_path / "head", {".gitattributes": b"* text=auto\n", "notes.txt": b"one\ntwo\n"})
    changes = diff_trees(base, head)
    history = history_built_by_a_plain_git(head, base)

    with pytest.raises(MaterializationError, match="does not reproduce the recorded diff"):
        check_pr_history(head, history, changes)
    with pytest.raises(MaterializationError, match="does not hold the exported bytes") as refused:
        check_pr_history(head, history, changes, base)

    assert "notes.txt (base)" in str(refused.value) and "(head)" not in str(refused.value)


@pytest.mark.parametrize(("base_bytes", "head_bytes", "named"), [
    (b"one\r\ntwo\r\n", b"one\r\ntwo\r\nthree\r\n", "notes.txt (base), notes.txt (head)"),
    (b"one\r\ntwo\r\n", b"one\ntwo\n", "notes.txt (base)"),
    (b"one\ntwo\n", b"one\r\ntwo\r\n", "notes.txt (head)"),
], ids=["both-commits", "base-only", "head-only"])
def test_a_conversion_that_survives_the_history_override_is_a_preparation_failure_naming_the_paths(
        tmp_path, monkeypatch, base_bytes, head_bytes, named):
    """The blob comparison is the second line: if git converted anyway, the input is refused, not reviewed.

    The override is replaced by a comment, which is what a git that did not honor it would amount to,
    and ``* text=auto`` then stores LF for every CRLF file the export wrote. Which commit holds the
    other bytes is named, so the base tree has to reach the comparison as well as the head.
    """
    monkeypatch.setattr(materialize_module, "PR_HISTORY_ATTRIBUTES", "# nothing is overridden\n")
    base = write_bytes_tree(tmp_path / "base", {".gitattributes": b"* text=auto\n", "notes.txt": base_bytes})
    head = write_bytes_tree(tmp_path / "head", {".gitattributes": b"* text=auto\n", "notes.txt": head_bytes})
    changes = diff_trees(base, head)

    with pytest.raises(MaterializationError, match="does not hold the exported bytes") as refused:
        compute_pr_history(head, base, changes)

    assert f"git stored {named} as something other than what the export wrote" in str(refused.value)
    assert not (head / ".git").exists(), "the history was built in a scratch copy"


@pytest.mark.parametrize("squeezed", ["_HASH_BATCH_PATHS", "_HASH_BATCH_BYTES"])
def test_the_blob_comparison_reads_every_batch_of_a_tree_too_large_for_one_git_call(tmp_path, monkeypatch, squeezed):
    """A mismatch in the last of several batches is found, and a tree is never compared in part."""
    monkeypatch.setattr(materialize_module, squeezed, 2 if squeezed == "_HASH_BATCH_PATHS" else 1)
    files = {f"src/file{index}.txt": f"line {index}\n".encode() for index in range(5)}
    base = write_bytes_tree(tmp_path / "base", {**files, ".gitattributes": b"zzz.txt text=auto\n"})
    head = write_bytes_tree(tmp_path / "head", {**files, ".gitattributes": b"zzz.txt text=auto\n",
                                               "zzz.txt": b"crlf\r\n"})
    changes = diff_trees(base, head)
    history = history_built_by_a_plain_git(head, base)

    with pytest.raises(MaterializationError, match="does not hold the exported bytes") as refused:
        check_pr_history(head, history, changes, base)

    assert "git stored zzz.txt (head) as something other" in str(refused.value)


def test_a_history_whose_diff_is_not_the_recorded_one_is_refused_with_the_paths(tmp_path):
    base = write_tree(tmp_path / "base", {"a.py": "1\n", "b.py": "1\n"})
    head = write_tree(tmp_path / "head", {"a.py": "2\n", "b.py": "1\n"})
    history = prepare_pr_history(head, base)
    stale = diff_trees(base, write_tree(tmp_path / "other", {"a.py": "1\n", "b.py": "2\n"}))
    assert stale["modified"] == ["b.py"]

    with pytest.raises(MaterializationError, match="does not reproduce the recorded diff") as refused:
        check_pr_history(head, history, stale, base)

    assert "a.py" in str(refused.value) and "b.py" in str(refused.value)


def test_a_case_only_rename_on_a_case_insensitive_filesystem_is_refused_as_a_preparation_failure(tmp_path):
    (tmp_path / "Probe").write_text("x", encoding="utf-8")
    if not (tmp_path / "probe").exists():
        pytest.skip("this filesystem is case-sensitive, so a case-only rename is two paths to git as well")
    base = write_tree(tmp_path / "base", {"Readme.md": "hello\n", "a.py": "1\n"})
    head = write_tree(tmp_path / "head", {"README.md": "hello\n", "a.py": "2\n"})
    changes = diff_trees(base, head)

    with pytest.raises(MaterializationError, match="does not reproduce the recorded diff") as refused:
        compute_pr_history(head, base, changes)

    assert "README.md" in str(refused.value) or "Readme.md" in str(refused.value)


def test_compute_pr_history_builds_in_a_scratch_copy_and_leaves_no_trace(tmp_path, pull_request, monkeypatch):
    head, base, record = prepared_pr(tmp_path, pull_request)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setenv("TMPDIR", str(scratch))
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", None)
    before = (hash_exported_tree(head), hash_exported_tree(base))

    history = compute_pr_history(head, base, record["diff"]["changes"])

    assert set(history) == {"base_commit", "head_commit", "messages", "identity", "date"}
    assert (hash_exported_tree(head), hash_exported_tree(base)) == before
    assert not (head / ".git").exists() and not (base / ".git").exists()
    assert list(scratch.iterdir()) == [], "the scratch copy is removed"
    other_head, other_base, _ = prepared_pr(tmp_path, pull_request, "second")
    assert prepare_pr_history(other_head, other_base) == history
