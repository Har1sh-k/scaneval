"""The scan modes an adapter implements, and how a PR request is read.

Nothing here starts a scanner. The git the workspace tests use is a scratch repository built
with a neutral identity, the same shape as the two-commit history the runner builds for a PR
input: a base commit, a head commit, ``HEAD`` at head, and a clean status.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

from scaneval.adapters.base import Adapter, AdapterError, NativeOutcome
from scaneval.adapters.pr import Change, PrRange, _parse_name_status, pr_range, workspace_changes


class BareAdapter(Adapter):
    """An adapter that declares nothing beyond what the protocol requires."""

    name = "bare"

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        return NativeOutcome(status="success", exit_code=0, command=[])


class ReviewingAdapter(BareAdapter):
    """An adapter that says it reads PR requests."""

    name = "reviewing"
    scan_modes = frozenset({"full", "pr"})


BASE = "a" * 40
HEAD = "b" * 40


def pr_request(base: str = BASE, head: str = HEAD, **input_fields) -> dict:
    return {"input": {"mode": "pr", "pr": {"base": base, "head": head}, **input_fields}}


def git(cwd: Path, *args: str) -> str:
    """One git command for building a scratch repository: neutral identity, no operator config."""
    environment = {**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
                   "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
    return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
                          env=environment).stdout.strip()


def make_history(tmp_path: Path, base: dict, head: dict, *, name: str = "workspace") -> tuple[Path, PrRange]:
    """A repository with a base commit and a head commit, ``HEAD`` at head, and a clean status.

    *base* and *head* map a path to its text or bytes. In *head* a value of ``None`` deletes the
    path, and a path absent from *head* is left exactly as the base commit had it.
    """
    repository = tmp_path / name
    repository.mkdir()
    git(repository, "init", "-q", "-b", "main")

    def write(files: dict) -> None:
        for relative, content in files.items():
            target = repository / relative
            if content is None:
                target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))

    write(base)
    git(repository, "add", "-A", "-f", ".")
    git(repository, "commit", "-q", "--no-verify", "-m", "base")
    base_commit = git(repository, "rev-parse", "HEAD")
    write(head)
    git(repository, "add", "-A", "-f", ".")
    git(repository, "commit", "-q", "--no-verify", "--allow-empty", "-m", "head")
    return repository, PrRange(base_commit, git(repository, "rev-parse", "HEAD"))


def test_an_adapter_that_declares_no_modes_implements_full_scans_only():
    """A PR request must never reach an adapter that did not say it reads one.

    The default is the whole reason the runner can refuse a PR input for an adapter that never
    heard of the mode, instead of handing it a request whose ``pr`` it would ignore.
    """
    assert BareAdapter.scan_modes == frozenset({"full"})
    assert BareAdapter().scan_modes == frozenset({"full"})
    assert isinstance(Adapter.scan_modes, frozenset)


# --- reading the request ----------------------------------------------------------------


@pytest.mark.parametrize("request_", [
    {},
    {"input": {}},
    {"input": {"mode": "full"}},
    {"input": {"mode": "full", "profile": "standard", "languages": ["python"]}},
])
def test_a_request_that_is_not_a_pr_request_is_a_full_scan(request_):
    """A direct caller of ``scan()`` may hand over a bare request; it cannot be a PR request."""
    assert pr_range(request_, BareAdapter()) is None
    assert pr_range(request_, ReviewingAdapter()) is None


def test_a_pr_request_names_the_two_commits_it_asks_about():
    named = pr_range(pr_request(), ReviewingAdapter())
    assert named == PrRange(BASE, HEAD)
    assert named.base == BASE and named.head == HEAD
    assert named.revision_range == f"{BASE}..{HEAD}"
    # SHA-256 repositories name commits with 64 hex digits, and the request may carry them.
    long_base, long_head = "c" * 64, "d" * 64
    assert pr_range(pr_request(long_base, long_head), ReviewingAdapter()) == PrRange(long_base, long_head)


def test_an_adapter_that_does_not_declare_pr_refuses_a_pr_request_by_name():
    with pytest.raises(AdapterError, match=r"bare does not implement scan mode 'pr' \(it implements: full\)"):
        pr_range(pr_request(), BareAdapter())
    with pytest.raises(AdapterError, match="nothing was run in its place"):
        pr_range(pr_request(), BareAdapter())


@pytest.mark.parametrize("mode", ["batch", "bootstrap", "", "PR", None, 3, ["pr"]])
def test_a_mode_the_adapter_does_not_implement_is_refused_whatever_it_looks_like(mode):
    with pytest.raises(AdapterError, match="does not implement scan mode"):
        pr_range({"input": {"mode": mode}}, ReviewingAdapter())


def test_a_full_request_that_also_carries_a_pr_is_refused_rather_than_ignoring_it():
    """The ``pr`` would be silently dropped, which is a PR request run as a full scan."""
    with pytest.raises(AdapterError, match="full-mode request that also carries input.pr"):
        pr_range({"input": {"mode": "full", "pr": {"base": BASE, "head": HEAD}}}, ReviewingAdapter())
    with pytest.raises(AdapterError, match="full-mode request that also carries input.pr"):
        pr_range({"input": {"pr": {"base": BASE, "head": HEAD}}}, ReviewingAdapter())


@pytest.mark.parametrize("pr, fragment", [
    (None, "input.pr is absent"),
    ("base..head", "input.pr is a str"),
    ([BASE, HEAD], "input.pr is a list"),
    ({}, "input.pr.base is not a full lowercase commit id"),
    ({"base": BASE}, "input.pr.head is not a full lowercase commit id"),
    ({"head": HEAD}, "input.pr.base is not a full lowercase commit id"),
    ({"base": BASE[:12], "head": HEAD}, "input.pr.base is not a full lowercase commit id"),
    ({"base": BASE, "head": "HEAD"}, "input.pr.head is not a full lowercase commit id"),
    ({"base": "origin/main", "head": HEAD}, "input.pr.base is not a full lowercase commit id"),
    ({"base": BASE.upper(), "head": HEAD}, "input.pr.base is not a full lowercase commit id"),
    ({"base": "--output=x" + "a" * 30, "head": HEAD}, "input.pr.base is not a full lowercase commit id"),
    ({"base": BASE, "head": 7}, "input.pr.head is not a full lowercase commit id"),
])
def test_a_pr_request_that_does_not_name_two_full_commits_is_refused(pr, fragment):
    request = {"input": {"mode": "pr", **({} if pr is None else {"pr": pr})}}
    with pytest.raises(AdapterError, match=fragment):
        pr_range(request, ReviewingAdapter())


def test_a_request_whose_input_is_not_an_object_is_refused():
    with pytest.raises(AdapterError, match="input is a list, not an object"):
        pr_range({"input": ["pr"]}, ReviewingAdapter())


# --- reading the workspace --------------------------------------------------------------


def test_the_workspace_lists_each_kind_of_change_between_the_two_commits(tmp_path):
    """Added, modified, deleted, renamed with exact content, mode-only, and a type change."""
    workspace, pr = make_history(tmp_path, {
        "keep.py": "unchanged\n",
        "edit.py": "one\n",
        "gone.py": "bye\n",
        "run.sh": "#!/bin/sh\n",
        "old name.py": "moved content that is long enough to be recognized as a rename\n",
        "link.txt": "a regular file for now\n",
    }, {
        "edit.py": "two\n",
        "gone.py": None,
        "added.py": "new\n",
        "new name.py": "moved content that is long enough to be recognized as a rename\n",
        "old name.py": None,
    })
    os.chmod(workspace / "run.sh", 0o755)
    (workspace / "link.txt").unlink()
    os.symlink("edit.py", workspace / "link.txt")
    git(workspace, "add", "-A", "-f", ".")
    git(workspace, "commit", "-q", "--no-verify", "-m", "more head")
    pr = PrRange(pr.base, git(workspace, "rev-parse", "HEAD"))

    changes = workspace_changes(workspace, pr)

    by_path = {change.path: change for change in changes}
    assert by_path["edit.py"] == Change("M", "edit.py")
    assert by_path["gone.py"] == Change("D", "gone.py")
    assert by_path["added.py"] == Change("A", "added.py")
    assert by_path["run.sh"] == Change("M", "run.sh"), "a mode change alone is a modification"
    assert by_path["new name.py"] == Change("R", "new name.py", "old name.py")
    assert by_path["link.txt"] == Change("T", "link.txt")
    assert "keep.py" not in by_path
    assert "old name.py" not in by_path, "the rename is one entry, filed under its new name"
    assert [change.present for change in changes if change.status == "D"] == [False]
    assert all(change.present for change in changes if change.status != "D")


def test_paths_with_spaces_newlines_and_non_ascii_names_come_through_intact(tmp_path):
    odd = {"we\nird.py": "x\n", "caf\u00e9/na\u00efve.py": "y\n", "a b/c d.py": "z\n", '"quoted".py': "q\n"}
    workspace, pr = make_history(tmp_path, {"seed.py": "s\n"}, odd)
    changes = workspace_changes(workspace, pr)
    assert {change.path for change in changes} == set(odd)
    assert all(change.status == "A" for change in changes)


def test_a_name_that_is_not_utf8_is_spelled_with_escapes_and_never_a_lone_surrogate():
    """Read from the bytes git prints: a file system that refuses such a name cannot be made to hold one."""
    changes = _parse_name_status(b"A\x00caf\xe9.py\x00R090\x00old\xff.py\x00new\xfe.py\x00")
    assert changes == (Change("A", "caf\\xe9.py"), Change("R", "new\\xfe.py", "old\\xff.py"))
    for change in changes:
        change.path.encode("utf-8")  # a recordable string: encoding it cannot raise
        (change.old_path or "").encode("utf-8")


@pytest.mark.parametrize("raw", [b"A\x00", b"R100\x00only-one.py\x00", b"\x00x\x00", b"C50\x00a\x00"])
def test_a_change_record_git_did_not_finish_is_refused_rather_than_guessed_at(raw):
    with pytest.raises(AdapterError, match="change record this adapter cannot read"):
        _parse_name_status(raw)


def test_the_workspace_read_refuses_a_commit_the_history_does_not_hold(tmp_path):
    workspace, pr = make_history(tmp_path, {"a.py": "1\n"}, {"a.py": "2\n"})
    with pytest.raises(AdapterError, match="holds no commit 000000000000 for the request's base"):
        workspace_changes(workspace, PrRange("0" * 40, pr.head))
    with pytest.raises(AdapterError, match="holds no commit 111111111111 for the request's head"):
        workspace_changes(workspace, PrRange(pr.base, "1" * 40))


def test_the_workspace_read_refuses_a_workspace_whose_head_is_not_the_head_commit(tmp_path):
    workspace, pr = make_history(tmp_path, {"a.py": "1\n"}, {"a.py": "2\n"})
    git(workspace, "checkout", "-q", "--detach", pr.base)
    with pytest.raises(AdapterError, match="not at the request's head commit"):
        workspace_changes(workspace, pr)


def test_the_workspace_read_refuses_a_modified_or_untracked_workspace(tmp_path):
    workspace, pr = make_history(tmp_path, {"a.py": "1\n"}, {"a.py": "2\n"})
    assert workspace_changes(workspace, pr)
    (workspace / "a.py").write_text("3\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="modified or untracked paths"):
        workspace_changes(workspace, pr)
    git(workspace, "checkout", "-q", "--", "a.py")
    assert workspace_changes(workspace, pr)
    (workspace / "stray").mkdir()
    (workspace / "stray" / "note.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="modified or untracked paths"):
        workspace_changes(workspace, pr)


def test_a_change_that_changes_nothing_is_refused_because_it_is_not_a_review(tmp_path):
    workspace, pr = make_history(tmp_path, {"a.py": "1\n"}, {})
    assert pr.base != pr.head, "the empty head commit is a different commit"
    with pytest.raises(AdapterError, match="no change between the request's base and head"):
        workspace_changes(workspace, pr)
    with pytest.raises(AdapterError, match="no change between the request's base and head"):
        workspace_changes(workspace, PrRange(pr.head, pr.head))


def test_a_directory_that_is_not_a_repository_is_refused_without_naming_the_machine(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(AdapterError) as refused:
        workspace_changes(plain, PrRange(BASE, HEAD))
    assert str(tmp_path) not in str(refused.value)


def test_the_workspace_read_never_runs_a_program_the_repository_configures(tmp_path):
    """``git status`` runs ``core.fsmonitor`` if the repository names one; this read must not.

    The control first: plain ``git status`` does run the program, so a passing check below is the
    override at work and not a git that never looked at the setting.
    """
    workspace, pr = make_history(tmp_path, {"a.py": "1\n"}, {"a.py": "2\n"})
    hook = tmp_path / "hook.sh"
    marker = tmp_path / "marker"
    hook.write_text(f"#!/bin/sh\necho ran >> {marker}\nprintf '\\0'\n", encoding="utf-8")
    hook.chmod(0o755)
    git(workspace, "config", "core.fsmonitor", str(hook))
    subprocess.run(["git", "status", "--porcelain"], cwd=str(workspace), check=True, capture_output=True,
                   env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull})
    assert marker.exists(), "git ran the configured program, so the control is meaningful"
    marker.unlink()

    assert workspace_changes(workspace, pr)
    assert not marker.exists()
