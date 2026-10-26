"""Offline tests for the workflow's conservative real-Docker path decision."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/oci_ci_path_gate.py"
SPEC = importlib.util.spec_from_file_location("oci_ci_path_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "CI",
    "GIT_AUTHOR_EMAIL": "ci@example.invalid",
    "GIT_COMMITTER_NAME": "CI",
    "GIT_COMMITTER_EMAIL": "ci@example.invalid",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=repo, env=GIT_ENV, check=True, capture_output=True, text=True,
    ).stdout.strip()


def commit(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def repository(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    commit(repo, "base")
    return repo


def depth_two_clone(source: Path, destination: Path) -> Path:
    subprocess.run(
        ["git", "clone", "-q", "--depth", "2", source.resolve().as_uri(), str(destination)],
        cwd=source.parent, env=GIT_ENV, check=True, capture_output=True, text=True,
    )
    return destination


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/scaneval/isolation/oci.py", True),
        ("src/scaneval/execution.py", True),
        ("src/scaneval/open_context.py", True),
        ("src/scaneval/open_context_evidence.py", True),
        ("tests/test_v2_open_context_docker.py", True),
        ("tests/test_v2_public_retrieval.py", True),
        ("examples/open_context_fixture.py", True),
        ("src/scaneval/cli.py", True),
        ("src/scaneval/__init__.py", True),
        ("src/scaneval/cases.py", True),
        ("src/scaneval/schedule.py", True),
        ("src/scaneval/kinds.py", True),
        ("src/scaneval/mappings/kinds.json", True),
        ("src/scaneval/adapters/semgrep.py", True),
        ("src/scaneval/schemas/execution-record.schema.json", True),
        ("tests/fixtures/oci config with spaces.json", True),
        ("tests/test_v2_isolation_docker.py", True),
        ("tests/test_v2_isolation_future.py", True),
        ("tests/conftest.py", True),
        ("tests/nested/conftest.py", True),
        ("conftest.py", True),
        (".github/workflows/release.yml", True),
        ("requirements-ci.txt", True),
        ("pytest.ini", True),
        ("setup.cfg", True),
        ("tox.ini", True),
        ("setup.py", True),
        ("MANIFEST.in", True),
        ("docs/THREAT_MODEL.md", False),
        ("src/scaneval/diagnostics.py", False),
        ("tests/test_v2_diagnostics.py", False),
    ],
)
def test_path_policy(path: str, expected: bool):
    assert gate.is_relevant_path(path) is expected


@pytest.mark.parametrize("event_name", ["push", "workflow_dispatch"])
def test_non_pr_events_always_run_without_reading_git(tmp_path, event_name):
    assert gate.should_run_oci(event_name, tmp_path / "not-a-repository") is True


def test_pull_request_decision_uses_the_complete_multi_commit_merge_diff(tmp_path):
    repo = repository(tmp_path, {"README.md": "base\n"})
    git(repo, "checkout", "-q", "-b", "topic")
    execution = repo / "src/scaneval/execution.py"
    execution.parent.mkdir(parents=True)
    execution.write_text("first PR commit\n", encoding="utf-8")
    commit(repo, "relevant first commit")
    (repo / "README.md").write_text("unrelated final commit\n", encoding="utf-8")
    commit(repo, "unrelated final commit")
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "topic", "-m", "merge")
    shallow = depth_two_clone(repo, tmp_path / "depth-two")

    assert len(git(shallow, "rev-list", "--parents", "-n", "1", "HEAD").split()) == 3
    paths = gate.pull_request_changed_paths(shallow)

    assert "src/scaneval/execution.py" in paths
    assert "README.md" in paths
    assert gate.should_run_oci("pull_request", shallow) is True


def test_renames_report_both_ends_and_preserve_spaces(tmp_path):
    repo = repository(tmp_path, {
        "src/scaneval/isolation/old name.py": "moves out\n",
        "docs/old guide.py": "moves in\n",
    })
    git(repo, "checkout", "-q", "-b", "topic")
    (repo / "docs").mkdir(exist_ok=True)
    git(repo, "mv", "src/scaneval/isolation/old name.py", "docs/new name.py")
    (repo / "src/scaneval/isolation").mkdir(parents=True, exist_ok=True)
    git(repo, "mv", "docs/old guide.py", "src/scaneval/isolation/new guide.py")
    commit(repo, "rename across the OCI boundary")
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "topic", "-m", "merge")

    paths = set(gate.pull_request_changed_paths(repo))

    assert {
        "src/scaneval/isolation/old name.py",
        "docs/new name.py",
        "docs/old guide.py",
        "src/scaneval/isolation/new guide.py",
    } <= paths
    assert gate.should_run_oci("pull_request", repo) is True


def test_docs_only_pull_request_skips_docker(tmp_path):
    repo = repository(tmp_path, {"docs/PILOT.md": "base\n"})
    git(repo, "checkout", "-q", "-b", "topic")
    (repo / "docs/PILOT.md").write_text("docs only\n", encoding="utf-8")
    commit(repo, "docs only")
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "topic", "-m", "merge")
    shallow = depth_two_clone(repo, tmp_path / "docs-depth-two")

    assert gate.pull_request_changed_paths(shallow) == ("docs/PILOT.md",)
    assert gate.should_run_oci("pull_request", shallow) is False


def test_non_merge_pr_checkout_fails_instead_of_returning_false(tmp_path):
    repo = repository(tmp_path, {"README.md": "one parent\n"})
    with pytest.raises(gate.GateError, match="two-parent merge"):
        gate.pull_request_changed_paths(repo)
