from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest

from scaneval import open_context
from scaneval.materialize import (CachedSnapshot, MaterializationError, export_snapshot, fetch_snapshot,
                                  git_command, hash_exported_tree)
from scaneval.open_context import export_history, install_history, validate_policy


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-c", "user.name=Fixture", "-c", "user.email=f@example.test",
                                    *args], cwd=root, text=True).strip()


def history_fixture(tmp_path):
    root = tmp_path / "upstream"
    root.mkdir()
    git(root, "init", "-q")
    (root / "source.py").write_text("first = True\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "original context")
    ancestor = git(root, "rev-parse", "HEAD")
    (root / "source.py").write_text("vulnerable = True\n")
    git(root, "commit", "-qam", "evaluated vulnerable input")
    head = git(root, "rev-parse", "HEAD")
    git(root, "branch", "unrelated", ancestor)
    git(root, "checkout", "-q", "unrelated")
    (root / "unrelated.txt").write_text("UNRELATED SECRET BLOB\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "unrelated branch")
    unrelated = git(root, "rev-parse", "HEAD")
    git(root, "checkout", "-q", "--detach", head)
    (root / "source.py").write_text("fixed = True\n")
    git(root, "commit", "-qam", "later security fix")
    fix = git(root, "rev-parse", "HEAD")
    git(root, "tag", "security-fix", fix)
    git(root, "notes", "add", "-m", "evaluation note", head)
    git(root, "checkout", "-q", "--detach", head)
    snapshot = CachedSnapshot(root, str(root), head, git(root, "rev-parse", f"{head}^{{tree}}"), "fixture")
    trial = tmp_path / "input"
    record = export_snapshot(snapshot, trial)
    return snapshot, trial / "source", record["trial"]["tree_hash"], ancestor, fix, unrelated


def test_original_ancestors_only_with_no_hidden_descendants(tmp_path):
    snapshot, source, digest, ancestor, fix, unrelated = history_fixture(tmp_path)
    evidence = export_history(snapshot, tmp_path / "bounded.git", source_dir=source, expected_tree_hash=digest)
    workspace = tmp_path / "workspace"
    shutil.copytree(source, workspace)
    assert install_history(tmp_path / "bounded.git", workspace, expected=evidence) == evidence
    assert git(workspace, "rev-parse", "HEAD") == snapshot.commit
    assert set(git(workspace, "rev-list", "HEAD").splitlines()) == {ancestor, snapshot.commit}
    assert git(workspace, "for-each-ref") == ""
    objects = set(git(workspace, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)").splitlines())
    assert fix not in objects and unrelated not in objects
    assert evidence["reachable_commit_count"] == 2
    assert not (workspace / ".git" / "logs").exists()
    assert not (workspace / ".git" / "hooks").exists()
    assert git(workspace, "remote") == ""
    assert git(workspace, "ls-files") == "source.py"
    assert git(workspace, "status", "--porcelain") == ""
    assert git(workspace, "diff", "--name-status", "HEAD") == ""
    assert evidence["git_index_sha256"].startswith("sha256:")


def test_metadata_and_content_tampering_are_refused(tmp_path):
    snapshot, source, digest, *_ = history_fixture(tmp_path)
    directory = tmp_path / "bounded.git"
    evidence = export_history(snapshot, directory, source_dir=source, expected_tree_hash=digest)
    (directory / "objects" / "info" / "alternates").write_text(str(snapshot.path / ".git" / "objects"))
    with pytest.raises(MaterializationError, match="forbidden metadata"):
        install_history(directory, source, expected=evidence)
    (directory / "objects" / "info" / "alternates").unlink()
    (source / "source.py").write_text("changed = True\n")
    with pytest.raises(MaterializationError, match="tree hash"):
        install_history(directory, source, expected=evidence)


def test_corrupt_ancestor_blob_is_refused_even_when_object_names_are_unchanged(tmp_path):
    snapshot, source, digest, ancestor, *_ = history_fixture(tmp_path)
    history = tmp_path / "bounded.git"
    evidence = export_history(snapshot, history, source_dir=source, expected_tree_hash=digest)
    ancestor_blob = git(snapshot.path, "rev-parse", ancestor + ":source.py")
    index = next((history / "objects/pack").glob("*.idx"))
    listing = git(tmp_path, "verify-pack", "-v", str(index))
    row = next(line.split() for line in listing.splitlines() if line.startswith(ancestor_blob + " "))
    pack = index.with_suffix(".pack")
    raw = bytearray(pack.read_bytes())
    raw[int(row[4]) + 4] ^= 1
    pack.chmod(0o644)
    pack.write_bytes(raw)
    with pytest.raises(MaterializationError, match="git fsck .*failed"):
        install_history(history, source, expected=evidence)
    assert not (source / ".git").exists()


def test_history_is_deterministic_and_upstream_config_hooks_do_not_cross(tmp_path, monkeypatch):
    snapshot, source, digest, *_ = history_fixture(tmp_path)
    sentinel = tmp_path / "HOOK_RAN"
    (snapshot.path / ".git" / "hooks" / "post-checkout").write_text(f"#!/bin/sh\ntouch {sentinel}\n")
    (snapshot.path / ".git" / "hooks" / "post-checkout").chmod(0o755)
    git(snapshot.path, "config", "credential.helper", "!echo forbidden")
    monkeypatch.setenv("GIT_DIR", str(snapshot.path / ".git"))
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(snapshot.path / ".git" / "objects"))
    first = export_history(snapshot, tmp_path / "first.git", source_dir=source, expected_tree_hash=digest)
    second = export_history(snapshot, tmp_path / "second.git", source_dir=source, expected_tree_hash=digest)
    assert first == second
    assert not sentinel.exists()
    assert "forbidden" not in (tmp_path / "first.git" / "config").read_text()


def test_omitted_head_paths_and_stale_policies_are_unavailable(tmp_path):
    snapshot, source, digest, *_ = history_fixture(tmp_path)
    (source / "extra.py").write_text("different input\n")
    with pytest.raises(MaterializationError, match="tree hash"):
        export_history(snapshot, tmp_path / "bounded.git", source_dir=source, expected_tree_hash=digest)
    with pytest.raises(MaterializationError, match="stale"):
        validate_policy({"history": "old", "retrieval": "recorded_public_v1", "web_mode": "live",
                         "capture": "content", "retention": "bundle"})


def test_harmless_symlink_stays_unfollowed_but_its_history_is_declared(tmp_path):
    snapshot, source, _digest, *_ = history_fixture(tmp_path)
    (snapshot.path / "readme-link").symlink_to("/etc/passwd")
    git(snapshot.path, "add", "readme-link")
    git(snapshot.path, "commit", "-qm", "tracked link")
    head = git(snapshot.path, "rev-parse", "HEAD")
    newer = CachedSnapshot(snapshot.path, snapshot.url, head, git(snapshot.path, "rev-parse", f"{head}^{{tree}}"), "fixture")
    record = export_snapshot(newer, tmp_path / "linked-input")
    linked_source = tmp_path / "linked-input" / "source"
    evidence = export_history(newer, tmp_path / "linked.git", source_dir=linked_source,
                              expected_tree_hash=record["trial"]["tree_hash"])
    assert not (linked_source / "readme-link").exists()
    assert evidence["source_export_omissions"][0]["path"] == "readme-link"
    assert evidence["source_export_omissions"][0]["history_exposure"] == "original_object_preserved"
    install_history(tmp_path / "linked.git", linked_source, expected=evidence)
    assert "readme-link" in git(linked_source, "ls-files").splitlines()
    assert git(linked_source, "status", "--porcelain") == ""
    assert git(linked_source, "diff", "--name-status", "HEAD") == ""


def test_excluded_controller_state_anywhere_in_ancestry_is_refused(tmp_path):
    snapshot, source, _digest, *_ = history_fixture(tmp_path)
    state = snapshot.path / ".scaneval"
    state.mkdir()
    (state / "labels.json").write_text("controller data\n")
    git(snapshot.path, "add", ".")
    git(snapshot.path, "commit", "-qm", "controller state")
    shutil.rmtree(state)
    git(snapshot.path, "commit", "-qam", "remove controller state")
    head = git(snapshot.path, "rev-parse", "HEAD")
    newer = CachedSnapshot(snapshot.path, snapshot.url, head, git(snapshot.path, "rev-parse", f"{head}^{{tree}}"), "fixture")
    record = export_snapshot(newer, tmp_path / "controller-input")
    with pytest.raises(MaterializationError, match="evaluator or harness state"):
        export_history(newer, tmp_path / "controller.git", source_dir=tmp_path / "controller-input" / "source",
                       expected_tree_hash=record["trial"]["tree_hash"])


def test_out_of_range_original_commit_time_is_a_structured_refusal(tmp_path):
    snapshot, source, digest, *_ = history_fixture(tmp_path)
    payload = (f"tree {snapshot.git_tree}\nauthor Fixture <f@example.test> 99999999999999 +0000\n"
               "committer Fixture <f@example.test> 99999999999999 +0000\n\nOriginal out-of-range date\n")
    head = subprocess.check_output(["git", "hash-object", "-t", "commit", "-w", "--stdin"],
                                   cwd=snapshot.path, input=payload.encode()).decode().strip()
    git(snapshot.path, "update-ref", "refs/heads/out-of-range", head)
    unusual = CachedSnapshot(snapshot.path, snapshot.url, head, snapshot.git_tree, "fixture")
    with pytest.raises(MaterializationError, match="out-of-range committer timestamp"):
        export_history(unusual, tmp_path / "unusual.git", source_dir=source, expected_tree_hash=digest)


def hermetic(root: Path, *args: str) -> bytes:
    argv, env = git_command(["-c", "user.name=Fixture", "-c", "user.email=f@example.test",
                             "-c", "core.autocrlf=false", *args])
    return subprocess.run(argv, cwd=root, env=env, capture_output=True, check=True).stdout


def converted_snapshot(tmp_path, *commits):
    """Commit each file map in turn to a local upstream, then use the real cache and export path."""
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    hermetic(upstream, "init", "-q")
    for files in commits:
        for rel, data in files.items():
            (upstream / rel).parent.mkdir(parents=True, exist_ok=True)
            (upstream / rel).write_bytes(data)
        hermetic(upstream, "add", "--", *files)
        hermetic(upstream, "commit", "-qm", "fixture commit")
    head = hermetic(upstream, "rev-parse", "HEAD").decode().strip()
    snapshot = fetch_snapshot(str(upstream), head, tmp_path / "cache")
    record = export_snapshot(snapshot, tmp_path / "input")
    return snapshot, tmp_path / "input" / "source", record["trial"]["tree_hash"]


# Each fixture: first commit, evaluated second commit, and a path whose checkout bytes differ
# from its stored blob because of a committed built-in conversion.
CONVERSIONS = {
    "crlf": ({".gitattributes": b"*.bat text eol=crlf\n", "run.bat": b"@echo off\n"},
             {"run.bat": b"@echo off\nexit /b 1\n"}, "run.bat"),
    "ident": ({".gitattributes": b"*.c ident\n", "version.c": b"/* $Id$ */\n"},
              {"version.c": b"/* $Id$ */\nint vulnerable;\n"}, "version.c"),
    "utf16": ({".gitattributes": b"*.txt working-tree-encoding=UTF-16\n", "notes.txt": "first\n".encode("utf-16")},
              {"notes.txt": "evaluated\n".encode("utf-16")}, "notes.txt"),
    "nested": ({".gitattributes": b"*.txt text eol=lf\n", "docs/.gitattributes": b"*.txt text eol=crlf\n",
                "docs/guide.txt": b"first\n", "top.txt": b"top\n"},
               {"docs/guide.txt": b"first\nevaluated\n"}, "docs/guide.txt"),
}


@pytest.mark.parametrize("kind", sorted(CONVERSIONS))
def test_committed_checkout_conversions_bind_export_and_install_exactly(tmp_path, monkeypatch, kind):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    first, second, converted = CONVERSIONS[kind]
    snapshot, source, digest = converted_snapshot(tmp_path, first, second)
    blob = hermetic(snapshot.path, "cat-file", "blob", f"{snapshot.commit}:{converted}")
    assert (source / converted).read_bytes() != blob, "fixture must export a converted representation"
    if kind == "nested":
        assert (source / converted).read_bytes() == b"first\r\nevaluated\r\n"
        assert (source / "top.txt").read_bytes() == b"top\n"
    evidence = export_history(snapshot, tmp_path / "bounded.git", source_dir=source, expected_tree_hash=digest)
    assert evidence["source_tree_hash"] == digest
    workspace = tmp_path / "workspace"
    shutil.copytree(source, workspace)
    assert install_history(tmp_path / "bounded.git", workspace, expected=evidence) == evidence
    assert (workspace / converted).read_bytes() == (source / converted).read_bytes()
    assert hermetic(workspace, "status", "--porcelain") == b""
    assert list(scratch.iterdir()) == [], "private verification checkouts must be removed"


def mixed_conversion_snapshot(tmp_path):
    return converted_snapshot(
        tmp_path, {".gitattributes": b"*.bat text eol=crlf\n*.c ident\n", "run.bat": b"@echo off\n",
                   "version.c": b"/* $Id$ */\n"},
        {"run.bat": b"@echo off\nexit /b 1\n", "version.c": b"/* $Id$ */\nint vulnerable;\n"})


@pytest.mark.parametrize("mutation", ["eol", "ident", "mode", "attributes", "bytes"])
def test_blob_equivalent_mode_and_attribute_rewrites_of_the_export_are_refused(tmp_path, monkeypatch, mutation):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    snapshot, source, digest = mixed_conversion_snapshot(tmp_path)
    bat, version = source / "run.bat", source / "version.c"
    assert bat.read_bytes() == b"@echo off\r\nexit /b 1\r\n"
    assert version.read_bytes().startswith(b"/* $Id: ") and b"$Id$" not in version.read_bytes()
    if mutation == "eol":
        bat.write_bytes(bat.read_bytes().replace(b"\r\n", b"\n"))
    elif mutation == "ident":
        version.write_bytes(b"/* $Id$ */\nint vulnerable;\n")
    elif mutation == "mode":
        bat.chmod(0o755)
    elif mutation == "attributes":
        # A scanner-visible attribute file cannot redefine the expected checkout representation.
        (source / ".gitattributes").write_bytes(b"*.c ident\n")
        bat.write_bytes(b"@echo off\nexit /b 1\n")
    else:
        bat.write_bytes(bat.read_bytes() + b"rem altered\r\n")
    if mutation in ("eol", "ident"):
        # Git's clean conversion maps these altered bytes to the same stored blob.
        rel = "run.bat" if mutation == "eol" else "version.c"
        cleaned = hermetic(snapshot.path, "hash-object", f"--path={rel}", str(source / rel)).strip()
        assert cleaned == hermetic(snapshot.path, "rev-parse", f"{snapshot.commit}:{rel}").strip()
    changed = hash_exported_tree(source)["tree_hash"]
    assert (changed == digest) == (mutation == "mode")
    with pytest.raises(MaterializationError, match="bytes or executable mode differ"):
        export_history(snapshot, tmp_path / "bounded.git", source_dir=source, expected_tree_hash=changed)
    assert list(scratch.iterdir()) == [], "a refused verification still removes its checkout"
    assert not (tmp_path / "bounded.git").exists()


def test_blob_invalid_in_its_declared_working_tree_encoding_is_refused(tmp_path):
    snapshot, source, digest = converted_snapshot(
        tmp_path, {"legacy.txt": b"\xff\xfe\xfa legacy\n"},
        {".gitattributes": b"*.txt working-tree-encoding=UTF-16\n"})
    # The cache checkout silently kept unconverted bytes; exact verification does not accept that.
    assert (source / "legacy.txt").read_bytes() == b"\xff\xfe\xfa legacy\n"
    with pytest.raises(MaterializationError, match="conversion failed or is unsupported"):
        export_history(snapshot, tmp_path / "bounded.git", source_dir=source, expected_tree_hash=digest)


def test_configured_filters_hooks_and_operator_attributes_are_never_executed(tmp_path, monkeypatch):
    sentinel = tmp_path / "FILTER_OR_HOOK_RAN"
    command = f"touch {sentinel}; cat"
    snapshot, source, digest = converted_snapshot(
        tmp_path, {".gitattributes": b"*.py filter=evil\n*.bat text eol=crlf\n", "app.py": b"first = 1\n",
                   "run.bat": b"@echo off\n"},
        {"app.py": b"evaluated = 1\n"})
    hook = f"#!/bin/sh\ntouch {sentinel}\n"
    for repository in (snapshot.path, tmp_path / "upstream"):
        for key in ("smudge", "clean"):
            hermetic(repository, "config", f"filter.evil.{key}", command)
        hermetic(repository, "config", "filter.evil.required", "true")
        for name in ("post-checkout", "post-index-change", "reference-transaction"):
            (repository / ".git" / "hooks").mkdir(exist_ok=True)
            (repository / ".git" / "hooks" / name).write_text(hook)
            (repository / ".git" / "hooks" / name).chmod(0o755)
        (repository / ".git" / "info").mkdir(exist_ok=True)
        (repository / ".git" / "info" / "attributes").write_text("* filter=evil ident eol=lf\n")
    home = tmp_path / "home"
    (home / ".config" / "git").mkdir(parents=True)
    operator = f'[filter "evil"]\n\tsmudge = {command}\n\tclean = {command}\n\trequired = true\n'
    (home / ".gitconfig").write_text(operator)
    (home / ".config" / "git" / "config").write_text(operator)
    (home / ".config" / "git" / "attributes").write_text("* filter=evil\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "filter.evil.smudge")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", command)
    monkeypatch.setenv("GIT_ATTR_SOURCE", snapshot.commit)
    evidence = export_history(snapshot, tmp_path / "bounded.git", source_dir=source, expected_tree_hash=digest)
    workspace = tmp_path / "workspace"
    shutil.copytree(source, workspace)
    assert install_history(tmp_path / "bounded.git", workspace, expected=evidence) == evidence
    # Even a repository argument carrying the hostile configuration contributes only its objects.
    assert open_context._source_binding(snapshot.path, source, snapshot.commit, digest)[0] == digest
    assert not sentinel.exists()
    assert (source / "run.bat").read_bytes() == b"@echo off\r\n"


def test_link_and_gitlink_omissions_stay_explicit_beside_converted_files(tmp_path):
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    hermetic(upstream, "init", "-q")
    (upstream / ".gitattributes").write_bytes(b"*.bat text eol=crlf\n")
    (upstream / "run.bat").write_bytes(b"@echo off\n")
    (upstream / "run-link").symlink_to("run.bat")
    hermetic(upstream, "add", "--", ".gitattributes", "run.bat", "run-link")
    hermetic(upstream, "commit", "-qm", "first")
    first = hermetic(upstream, "rev-parse", "HEAD").decode().strip()
    hermetic(upstream, "update-index", "--add", "--cacheinfo", f"160000,{first},vendor/lib")
    hermetic(upstream, "commit", "-qm", "evaluated with gitlink")
    head = hermetic(upstream, "rev-parse", "HEAD").decode().strip()
    snapshot = fetch_snapshot(str(upstream), head, tmp_path / "cache")
    record = export_snapshot(snapshot, tmp_path / "input")
    source = tmp_path / "input" / "source"
    evidence = export_history(snapshot, tmp_path / "bounded.git", source_dir=source,
                              expected_tree_hash=record["trial"]["tree_hash"])
    assert {(item["path"], item["reason"]) for item in evidence["source_export_omissions"]} == {
        ("run-link", "symbolic link"), ("vendor/lib", "submodule gitlink")}
    assert not (source / "run-link").exists() and not (source / "vendor").exists()
    workspace = tmp_path / "workspace"
    shutil.copytree(source, workspace)
    assert install_history(tmp_path / "bounded.git", workspace, expected=evidence) == evidence
    assert not (workspace / "run-link").is_symlink()
