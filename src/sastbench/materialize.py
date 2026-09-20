"""Immutable source cache, pinned snapshot export, tree hashing, and preparation provenance.

The cache under ``.repos`` is controller-only. A scanner never receives a cache path; it
receives a fresh export under a trial directory whose ``source`` subtree contains tracked
regular files only. Exporting a tree records what was stripped or skipped, but it is not a
sandbox: filesystem and network policy must be enforced outside this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Callable

from .contracts import canonical_json, canonical_sha256


SCHEMA_VERSION = "2.0"
PROFILES = ("standard", "metadata_blinded")
# Harness or evaluator state that must never travel with an exported snapshot.
STRIPPED_TOP_LEVEL = frozenset({".securevibes", ".sastbench", ".repos"})
# Files whose presence a scanner may treat as project instructions. They stay in the export
# under the standard profile, but their presence is recorded as a retained identity cue.
INSTRUCTION_FILE_NAMES = frozenset({"CLAUDE.md", "AGENTS.md", ".cursorrules", ".windsurfrules"})
INSTRUCTION_TOP_LEVEL = frozenset({".claude", ".codex", ".cursor", ".github"})
_SHA = re.compile(r"^[0-9a-f]{40}$")
_LFS_CONFIG = (
    ("filter.lfs.clean", "cat"),
    ("filter.lfs.smudge", "cat"),
    ("filter.lfs.process", ""),
    ("filter.lfs.required", "false"),
)


class MaterializationError(RuntimeError):
    """A snapshot could not be fetched, verified, or exported as requested."""


def _git(args: list[str], cwd: Path, *, timeout: float = 600) -> str:
    try:
        completed = subprocess.run(
            ["git", *args], cwd=str(cwd), capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MaterializationError(f"git {' '.join(args)} failed: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise MaterializationError(f"git {' '.join(args)} failed ({completed.returncode}): {detail}")
    return completed.stdout


def git_version() -> str:
    return _git(["--version"], Path.cwd()).strip()


def cache_key(url: str, commit: str) -> str:
    """Stable directory name: ``<owner>_<repo>__<sha12>`` derived from the URL path."""
    trimmed = url.rstrip("/")
    if trimmed.endswith(".git"):
        trimmed = trimmed[:-4]
    parts = [part for part in re.split(r"[/:]", trimmed) if part]
    tail = parts[-2:] if len(parts) >= 2 else parts[-1:]
    slug = "_".join(re.sub(r"[^A-Za-z0-9._-]+", "-", part) for part in tail) or "repo"
    return f"{slug}__{commit[:12]}"


@dataclass(frozen=True)
class CachedSnapshot:
    path: Path
    url: str
    commit: str
    git_tree: str
    fetch_method: str


def _require_commit(commit: str) -> str:
    commit = commit.strip().lower()
    if not _SHA.match(commit):
        raise MaterializationError("commit must be a full 40-hex SHA, not a branch, tag, or short id")
    return commit


def verify_cached_snapshot(path: Path, commit: str) -> str:
    """Check that *path* is a clean checkout of *commit*; return its tree id."""
    if not (path / ".git").exists():
        raise MaterializationError(f"cache entry is not a git checkout: {path}")
    head = _git(["rev-parse", "HEAD"], path).strip()
    if head != commit:
        raise MaterializationError(f"cache entry {path} is at {head}, expected {commit}")
    if _git(["status", "--porcelain", "--untracked-files=all"], path).strip():
        raise MaterializationError(f"cache entry {path} has local modifications; the cache is immutable")
    return _git(["rev-parse", f"{commit}^{{tree}}"], path).strip()


def fetch_snapshot(url: str, commit: str, cache_root: Path, *, timeout: float = 900) -> CachedSnapshot:
    """Fetch exactly *commit* from *url* into the immutable cache, or verify the existing entry."""
    commit = _require_commit(commit)
    target = cache_root / cache_key(url, commit)
    if target.exists():
        tree = verify_cached_snapshot(target, commit)
        return CachedSnapshot(target, url, commit, tree, "cached")
    cache_root.mkdir(parents=True, exist_ok=True)
    staging = cache_root / (target.name + ".partial")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    try:
        _git(["init", "-q"], staging)
        for key, value in _LFS_CONFIG:
            _git(["config", "--local", key, value], staging)
        _git(["config", "--local", "core.autocrlf", "false"], staging)
        _git(["remote", "add", "origin", url], staging)
        method = "depth1-sha"
        try:
            _git(["fetch", "-q", "--depth", "1", "origin", commit], staging, timeout=timeout)
        except MaterializationError:
            # Servers without allowAnySHA1InWant need the full history before checkout.
            method = "full-fetch"
            _git(["fetch", "-q", "origin"], staging, timeout=timeout)
        _git(["checkout", "-q", "--detach", commit], staging)
        tree = verify_cached_snapshot(staging, commit)
        staging.rename(target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return CachedSnapshot(target, url, commit, tree, method)


def inspect_commit(url: str, commit: str, *, timeout: float = 600) -> dict:
    """Describe *commit* at *url* (parents, committer date, subject) through a throwaway shallow fetch.

    Nothing is cached: this is a read-only lookup used to pin a vulnerable snapshot as the
    parent of a fix commit and to record the fix commit date as disclosure evidence.
    """
    commit = _require_commit(commit)
    import tempfile

    staging = Path(tempfile.mkdtemp(prefix="sastbench-inspect-"))
    try:
        _git(["init", "-q"], staging)
        _git(["remote", "add", "origin", url], staging)
        try:
            _git(["fetch", "-q", "--depth", "2", "origin", commit], staging, timeout=timeout)
        except MaterializationError:
            _git(["fetch", "-q", "origin"], staging, timeout=timeout)
        line = _git(["log", "-1", "--format=%H%x00%P%x00%cI%x00%aI%x00%s", commit], staging).strip("\n")
        sha, parents, committed, authored, subject = line.split("\x00")
        return {"commit": sha, "parents": parents.split() if parents else [], "committed_at": committed,
                "authored_at": authored, "subject": subject}
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return f"sha256:{digest.hexdigest()}", size


def tree_hash(file_hashes: dict[str, str]) -> str:
    """Canonical SHA-256 over the ``{relative path: file content hash}`` map."""
    return canonical_sha256(dict(sorted(file_hashes.items())))


def _first_component(path: str) -> str:
    return path.split("/", 1)[0]


def _is_instruction_file(path: str) -> bool:
    return path.split("/")[-1] in INSTRUCTION_FILE_NAMES or _first_component(path) in INSTRUCTION_TOP_LEVEL


def export_snapshot(
    snapshot: CachedSnapshot,
    trial_dir: Path,
    *,
    profile: str = "standard",
    blinding_map: dict | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict:
    """Copy the tracked regular files of *snapshot* into ``trial_dir/source`` and record provenance.

    ``metadata_blinded`` is refused without a reviewed replacement map, and this build does not
    apply one: blinding is reported unavailable rather than silently replaced by ``standard``.
    """
    if profile not in PROFILES:
        raise MaterializationError(f"unknown input profile {profile!r}; expected one of {PROFILES}")
    if profile == "metadata_blinded":
        if blinding_map is None:
            raise MaterializationError("metadata blinding unavailable: no reviewed replacement map was supplied")
        raise MaterializationError("metadata blinding is not implemented in this build; do not substitute standard")
    source = trial_dir / "source"
    if source.exists():
        raise MaterializationError(f"trial source directory already exists: {source}")
    listing = _git(["ls-tree", "-r", "-z", snapshot.commit], snapshot.path)
    entries = [item for item in listing.split("\0") if item]
    source.mkdir(parents=True)
    hashes: dict[str, str] = {}
    stripped: list[str] = []
    skipped: list[dict] = []
    instructions: list[str] = []
    byte_count = 0
    for entry in entries:
        meta, _, rel = entry.partition("\t")
        mode, kind, _object = meta.split(" ", 2)
        if any(part == ".git" for part in rel.split("/")) or _first_component(rel) in STRIPPED_TOP_LEVEL:
            stripped.append(rel)
            continue
        if kind == "commit":
            skipped.append({"path": rel, "reason": "submodule gitlink not exported"})
            continue
        if mode == "120000":
            skipped.append({"path": rel, "reason": "symbolic link not exported"})
            continue
        if kind != "blob":
            skipped.append({"path": rel, "reason": f"unsupported entry kind {kind}"})
            continue
        origin = snapshot.path / rel
        destination = source / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origin, destination)
        if mode == "100755":
            destination.chmod(0o755)
        else:
            destination.chmod(0o644)
        digest, size = sha256_file(destination)
        hashes[rel] = digest
        byte_count += size
        if _is_instruction_file(rel):
            instructions.append(rel)
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    record = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "url": snapshot.url,
            "commit": snapshot.commit,
            "git_tree": snapshot.git_tree,
            "fetch_method": snapshot.fetch_method,
        },
        "profile": profile,
        "trial": {
            "root": "source",
            "tree_hash": tree_hash(hashes),
            "file_count": len(hashes),
            "byte_count": byte_count,
        },
        "stripped": sorted(stripped),
        "skipped": sorted(skipped, key=lambda item: item["path"]),
        "instruction_files": sorted(instructions),
        "synthetic_history": None,
        "exported_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "tool_versions": {"git": git_version()},
        "limits": [
            "Export removes original git history and controller state; it is not a sandbox.",
            "Tracked regular files only: submodules and symbolic links are recorded as skipped.",
            "Instruction files stay in the standard profile and are recorded as identity cues.",
        ],
    }
    return record


def prepare_synthetic_history(source_dir: Path, *, message: str = "snapshot") -> dict:
    """Create the minimum single-commit history a git-dependent scanner needs, with neutral identity."""
    if (source_dir / ".git").exists():
        raise MaterializationError(f"{source_dir} already has git history")
    _git(["init", "-q"], source_dir)
    for key, value in (
        ("user.name", "SASTbench"), ("user.email", "sastbench@localhost"),
        ("commit.gpgsign", "false"), ("core.autocrlf", "false"), *_LFS_CONFIG,
    ):
        _git(["config", "--local", key, value], source_dir)
    # Force-add so an upstream .gitignore cannot drop exported files from the synthetic tree.
    _git(["add", "-A", "-f", "."], source_dir)
    _git(["commit", "-q", "--allow-empty", "--no-verify", "-m", message], source_dir)
    commit = _git(["rev-parse", "HEAD"], source_dir).strip()
    return {"commit": commit, "message": message, "identity": "SASTbench <sastbench@localhost>"}


def write_provenance(trial_dir: Path, record: dict) -> Path:
    path = trial_dir / "provenance.json"
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical_json(record) + "\n")
    return path


def hash_exported_tree(source_dir: Path) -> dict:
    """Recompute the export's file map from disk, for verification against provenance."""
    hashes: dict[str, str] = {}
    for path in sorted(source_dir.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(source_dir).as_posix()
        if any(part == ".git" for part in rel.split("/")):
            continue
        hashes[rel] = sha256_file(path)[0]
    return {"tree_hash": tree_hash(hashes), "file_count": len(hashes)}
