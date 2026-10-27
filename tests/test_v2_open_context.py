from pathlib import Path
import shutil
import subprocess

import pytest

from scaneval.materialize import CachedSnapshot, MaterializationError, export_snapshot
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
