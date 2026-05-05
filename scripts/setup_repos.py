"""SASTbench Full Track repo setup.

Clones and pins real-world repositories at their vulnerable commits
for Full Track benchmark cases.

Each snapshot is stored at .repos/<owner_repo>__<shortsha>/ so that
multiple advisories from the same repo at different commits don't collide.

Usage:
    python scripts/setup_repos.py
"""

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_CASES_DIR = REPO_ROOT / "cases" / "full"
REPOS_DIR = REPO_ROOT / ".repos"


def repo_dir_name(repo: str, commit: str) -> str:
    """Build a unique directory name for a repo at a specific commit."""
    owner_repo = repo.replace("/", "_")
    short_sha = commit[:8]
    return f"{owner_repo}__{short_sha}"


REAL_WORLD_CASE_TYPES = {"real_world_disclosed", "real_world_generic"}


def find_real_world_cases() -> list[tuple[Path, dict]]:
    """Find all real-world cases (both agentic disclosed and generic)."""
    cases = []
    for case_json in sorted(FULL_CASES_DIR.rglob("case.json")):
        with open(case_json, encoding="utf-8") as f:
            case = json.load(f)
        if case.get("caseType") in REAL_WORLD_CASE_TYPES:
            cases.append((case_json.parent, case))
    return cases


def has_checked_out_files(target_dir: Path) -> bool:
    """Return whether a git snapshot contains files beyond the .git dir."""
    try:
        return any(child.name != ".git" for child in target_dir.iterdir())
    except OSError:
        return False


def run_git(args: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run a git command and capture output."""
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def disable_lfs(target_dir: Path) -> None:
    """Disable git-lfs filters so checkouts work without lfs installed."""
    for key, val in [
        ("filter.lfs.clean", "cat"),
        ("filter.lfs.smudge", "cat"),
        ("filter.lfs.process", ""),
        ("filter.lfs.required", "false"),
    ]:
        run_git(
            ["git", "-C", str(target_dir), "config", "--local", key, val],
            timeout=10,
        )


def ensure_repo_checkout(repo: str, commit: str, target_dir: Path) -> bool:
    """Clone or repair a snapshot, then checkout the requested commit."""
    if target_dir.exists():
        git_dir = target_dir / ".git"
        if not git_dir.exists():
            print(f"    FAILED: existing directory is not a git repo: {target_dir}")
            return False

        disable_lfs(target_dir)

        if has_checked_out_files(target_dir):
            print(f"    Ready: {target_dir.name}")
            return True

        print(f"    Repairing incomplete checkout for {target_dir.name}...", end=" ", flush=True)
        fetch_result = run_git(
            ["git", "-C", str(target_dir), "fetch", "--depth", "1", "origin", commit],
            timeout=300,
        )
        if fetch_result.returncode != 0:
            print(f"FAILED: {fetch_result.stderr.strip()}")
            return False
    else:
        target_dir.parent.mkdir(parents=True, exist_ok=True)

        print(f"    Cloning {repo}...", end=" ", flush=True)
        clone_result = run_git(
            ["git", "clone", "--no-checkout", f"https://github.com/{repo}.git", str(target_dir)],
            timeout=300,
        )
        if clone_result.returncode != 0:
            print(f"FAILED: {clone_result.stderr.strip()}")
            return False

        disable_lfs(target_dir)

    print(f"checking out {commit[:8]}...", end=" ", flush=True)
    checkout_result = run_git(
        ["git", "-C", str(target_dir), "checkout", "--force", commit],
        timeout=60,
    )
    if checkout_result.returncode != 0:
        print(f"FAILED: {checkout_result.stderr.strip()}")
        return False

    print("OK")
    return True


def main() -> int:
    cases = find_real_world_cases()

    if not cases:
        print("No real-world cases found in Full Track.")
        print("Full Track cases will be added as they are annotated.")
        return 0

    print(f"Setting up {len(cases)} real-world repos\n")

    success = 0
    for case_dir, case in cases:
        rw = case.get("realWorld", {})
        repo = rw.get("repo", "")
        commit = rw.get("vulnerableCommit", "")

        if not repo or not commit:
            print(f"  [{case['id']}] Missing repo or commit metadata, skipping")
            continue

        dir_name = repo_dir_name(repo, commit)
        print(f"  [{case['id']}] {repo} @ {commit[:8]} -> .repos/{dir_name}")
        target = REPOS_DIR / dir_name

        if ensure_repo_checkout(repo, commit, target):
            success += 1

    print(f"\n{success}/{len(cases)} repos ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
