#!/usr/bin/env python3
"""Decide whether CI needs the real-Docker OCI integration job.

Pushes and manual runs always return true.  Pull requests use GitHub's checked-out merge commit
and compare its base parent with the complete merge tree.  ``--no-renames`` deliberately reports
a rename as a deletion plus an addition, so both its source and destination are matched.  NUL
delimiters preserve spaces and newlines in filenames.  Any unexpected Git state is an error: the
workflow turns a gate failure into a failed Docker check rather than silently skipping it.

The path policy is intentionally conservative around the OCI boundary: isolation code, execution
and materialization, adapters used by container runs, contracts/schemas, corresponding tests and
fixtures, and shared CI or Python dependency configuration all require the Docker job.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


RELEVANT_PREFIXES = (
    ".github/actions/",
    ".github/workflows/",
    "src/scaneval/isolation/",
    "src/scaneval/mappings/",
    "src/scaneval/schemas/",
    "tests/fixtures/",
    "tests/test_v2_isolation",
    "tests/test_v2_open_context",
    "tests/test_v2_public_retrieval",
    "tests/test_v2_experiment",
    "tests/test_v2_identity",
)

RELEVANT_FILES = frozenset({
    ".github/dependabot.yml",
    ".python-version",
    "MANIFEST.in",
    "pyproject.toml",
    "pytest.ini",
    "setup.cfg",
    "setup.py",
    "scripts/oci_ci_path_gate.py",
    "src/scaneval/__init__.py",
    "src/scaneval/cases.py",
    "src/scaneval/cli.py",
    "src/scaneval/contracts.py",
    "src/scaneval/execution.py",
    "src/scaneval/kinds.py",
    "src/scaneval/materialize.py",
    "src/scaneval/open_context.py",
    "src/scaneval/open_context_evidence.py",
    "src/scaneval/identity_policy.py",
    "src/scaneval/blinding.py",
    "src/scaneval/conditions.py",
    "src/scaneval/experiment.py",
    "src/scaneval/experiment_execution.py",
    "src/scaneval/experiment_report.py",
    "examples/experiment_matrix_fixture.py",
    "examples/open_context_fixture.py",
    "src/scaneval/runner.py",
    "src/scaneval/schedule.py",
    "src/scaneval/adapters/__init__.py",
    "src/scaneval/adapters/base.py",
    "src/scaneval/adapters/pr.py",
    "src/scaneval/adapters/semgrep.py",
    "tests/test_ci_oci_path_gate.py",
    "tests/test_v2_adapter_modes.py",
    "tests/test_v2_contracts.py",
    "tests/test_v2_contracts_21.py",
    "tests/test_v2_execution.py",
    "tests/test_v2_materialize.py",
    "tests/test_v2_pr.py",
    "tests/test_v2_runner.py",
    "tests/test_v2_runner_inputs.py",
    "tests/test_v2_semgrep.py",
    "tox.ini",
})


class GateError(RuntimeError):
    """The PR checkout could not support a trustworthy path decision."""


def is_relevant_path(path: str) -> bool:
    """Return whether one changed repository path can affect real OCI execution."""
    normalized = path.removeprefix("./")
    if normalized in RELEVANT_FILES or normalized.startswith(RELEVANT_PREFIXES):
        return True
    if normalized == "conftest.py" or (normalized.startswith("tests/")
                                         and normalized.endswith("/conftest.py")):
        return True
    if "/" not in normalized:
        lower = normalized.lower()
        return (
            lower == ".dockerignore"
            or lower.startswith("dockerfile")
            or lower.startswith("compose.")
            or lower.startswith("docker-compose.")
            or lower in {"pdm.lock", "pipfile", "pipfile.lock", "poetry.lock", "uv.lock"}
            or (lower.startswith("requirements") and lower.endswith((".in", ".txt")))
        )
    return normalized.startswith(("requirements/", "constraints/"))


def _git(repo: Path, *args: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=repo, check=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            detail = f": {os.fsdecode(exc.stderr).strip()}"
        raise GateError(f"git {' '.join(args)} failed{detail}") from exc
    return completed.stdout


def pull_request_changed_paths(repo: Path) -> tuple[str, ...]:
    """Read the full PR diff from a two-parent GitHub pull-request merge checkout."""
    parents = _git(repo, "rev-list", "--parents", "-n", "1", "HEAD").split()
    if len(parents) != 3:
        raise GateError("pull_request checkout is not a two-parent merge commit")
    raw = _git(repo, "diff", "--name-only", "--no-renames", "-z", "HEAD^1", "HEAD")
    if not raw:
        return ()
    if not raw.endswith(b"\0"):
        raise GateError("git diff did not return a NUL-terminated path list")
    fields = raw[:-1].split(b"\0")
    if any(not field for field in fields):
        raise GateError("git diff returned an empty path")
    return tuple(os.fsdecode(field) for field in fields)


def should_run_oci(event_name: str, repo: Path) -> bool:
    """Run unconditionally outside PRs; on PRs, run for any relevant changed path."""
    if event_name != "pull_request":
        return True
    return any(is_relevant_path(path) for path in pull_request_changed_paths(repo))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        decision = should_run_oci(args.event_name, args.repo)
    except GateError as exc:
        print(f"OCI path gate failed: {exc}", file=sys.stderr)
        return 2
    print("true" if decision else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
