"""What the repository publishes must not carry one machine's private detail.

Two things leak easily and are hard to notice in review: an operator's home directory
baked into a path, and a run record committed alongside the code that produced it. Run
records hold scanner output and, on the harness path under content tracing, the source
that was sent to a model. Neither belongs in a public branch, and neither is needed to
reproduce a run: the frozen run configurations are.

These tests read the working tree rather than the index so an uncommitted change is
caught before it is staged.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]

# Directories that are never published: build output, caches, virtual environments,
# dependency trees, and the gitignored places runs and private review notes are kept.
UNPUBLISHED = {".git", ".venv", ".repos", "node_modules", "dist", "build", "results",
               "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".idea", ".vscode"}

# An absolute path into some named user's home directory on macOS or Linux.
HOME_PATH = re.compile(r"/(?:Users|home)/([A-Za-z0-9._-]+)/")

# Stand-in account names. Test fixtures need a home path to exercise path handling, and a
# vulnerability description needs one to show where an escape lands. Neither identifies a
# real operator, so the check is for the account name, not for the shape of the path.
PLACEHOLDERS = {"user", "users", "someone", "example", "youruser", "test", "x", "y"}

# Text files only. A binary fixture is not something a home path hides in readably.
TEXTUAL = {".py", ".md", ".json", ".jsonl", ".ts", ".mts", ".js", ".mjs", ".yml", ".yaml",
           ".toml", ".cfg", ".ini", ".txt", ".sh", ".html", ".css"}


def published_files() -> list[Path]:
    out = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if UNPUBLISHED & set(path.relative_to(ROOT).parts):
            continue
        out.append(path)
    return sorted(out)


def textual_files() -> list[Path]:
    return [p for p in published_files() if p.suffix in TEXTUAL]


def test_no_published_file_names_a_users_home_directory():
    """A path like /Users/someone/... identifies an operator and works on one machine.

    ``~`` is expanded by the harness adapter and by every shell, so it is the portable
    spelling and the one to use instead.
    """
    offenders = []
    for path in textual_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            match = HOME_PATH.search(line)
            if match and match.group(1) not in PLACEHOLDERS:
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {match.group(0)}")
    assert not offenders, "home directory paths must not be published:\n" + "\n".join(offenders)


def test_no_run_record_is_published():
    """Run bundles are evidence, not source, and content-mode traces carry model input.

    The check is for the documents a bundle is made of rather than for a directory name,
    so moving a bundle somewhere else does not get it past this test.
    """
    names = {"result.json", "plan.json", "decisions.json", "review-record.json",
             "invocation.json", "trace.jsonl"}
    found = [str(p.relative_to(ROOT)) for p in published_files()
             if p.name in names and "fixtures" not in p.parts and "schema" not in p.parts]
    assert not found, "run records must not be committed:\n" + "\n".join(found)


@pytest.mark.parametrize("layout", ["directory", "symlink"])
@pytest.mark.parametrize("name", ["results", ".repos"])
def test_local_storage_is_ignored_as_a_directory_or_a_symlink_to_one(tmp_path: Path, name: str, layout: str):
    """Runs and source caches can be large, so ``results`` and ``.repos`` may be symlinks elsewhere.

    Git records a symlink as a file, which a directory-only rule such as ``results/`` does not
    match; ``git add -A`` would then commit a link to one machine's absolute path. The
    repository's ``.gitignore`` is checked in a scratch repository, so the result does not
    depend on this checkout or on the operator's own git configuration.
    """
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    storage = tmp_path / "storage"
    (storage / "entry").mkdir(parents=True)
    (storage / "entry" / "data.json").write_text("{}\n", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    # Inherited GIT_ variables, such as GIT_DIR inside a hook, would point git at another repository.
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    env.update({"HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path / "config"),
                "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
    subprocess.run(["git", "init", "-q"], cwd=repo, env=env, check=True)
    shutil.copyfile(ROOT / ".gitignore", repo / ".gitignore")
    if layout == "symlink":
        (repo / name).symlink_to(storage, target_is_directory=True)
    else:
        shutil.copytree(storage, repo / name)
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo, env=env,
                            check=True, capture_output=True, text=True).stdout
    assert status.splitlines() == ["?? .gitignore"], f"{name} as a {layout} is not ignored:\n{status}"


@pytest.mark.parametrize("config", sorted((ROOT / "corpus").glob("*/run-*.json")))
def test_every_published_run_configuration_is_portable(config: Path):
    """The configurations are the reproduction path, so they must not pin to one machine."""
    text = config.read_text(encoding="utf-8")
    match = HOME_PATH.search(text)
    offender = match.group(0) if match and match.group(1) not in PLACEHOLDERS else None
    assert offender is None, f"{config.name} pins an operator home directory: {offender}"
