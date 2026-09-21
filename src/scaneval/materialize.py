"""Immutable source cache, pinned snapshot export, tree hashing, and preparation provenance.

The cache under ``.repos`` is controller-only for evaluated source: a scanner never receives a
cache path to a source snapshot, it receives a fresh export under a trial directory whose
``source`` subtree contains tracked regular files only. The cache holds adapter preparation
material as well, and an adapter may hand its scanner paths to its own pinned rulesets there;
that is configuration the adapter checked out, not the tree under evaluation. Exporting a tree
records what was stripped or skipped, but it is not a sandbox: filesystem and network policy
must be enforced outside this module.

Every git invocation this package makes is built by :func:`git_command`, so a git call depends
on nothing outside the directory it is given: see that function for what is neutralized and
what is not.
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

from .contracts import ContractError, canonical_json, canonical_sha256


SCHEMA_VERSION = "2.0"
PROFILES = ("standard", "metadata_blinded")
# The scratch directories a scanning harness writes inside the tree it was handed. This is the
# source of truth for that set: the export strips them, and adapters derive their ``state_dirs``
# from it, so a directory one of them treats as harness scratch is never ordinary content to the
# other. A repository that ships one at the top level is therefore stripped on export and
# excluded from the modification check by the same list.
HARNESS_STATE_DIRS = frozenset({".securevibes", ".fieldglass"})
# Harness or evaluator state that must never travel with an exported snapshot.
STRIPPED_TOP_LEVEL = frozenset({".scaneval", ".repos"}) | HARNESS_STATE_DIRS
# Files whose presence a scanner may treat as project instructions. They stay in the export
# under the standard profile, but their presence is recorded as a retained identity cue. Only
# paths an agent actually reads as instructions count: ``.github`` as a whole does not, because
# workflows and CODEOWNERS are ordinary repository content, not instructions to a scanner.
INSTRUCTION_FILE_NAMES = frozenset({"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
                                    ".windsurfrules", ".clinerules"})
INSTRUCTION_TOP_LEVEL = frozenset({".claude", ".codex", ".cursor"})
INSTRUCTION_PATHS = frozenset({".github/copilot-instructions.md"})
INSTRUCTION_PATH_PREFIXES = (".github/instructions/",)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_LFS_CONFIG = (
    ("filter.lfs.clean", "cat"),
    ("filter.lfs.smudge", "cat"),
    ("filter.lfs.process", ""),
    ("filter.lfs.required", "false"),
)


class MaterializationError(RuntimeError):
    """A snapshot could not be fetched, verified, or exported as requested."""


# Command-line settings every git invocation carries. Both are neutralizations rather than
# preferences: ``core.hooksPath`` under a path that cannot hold a hook means no hook is ever
# found, and an empty ``init.templateDir`` means ``git init`` copies nothing into the new
# repository, hooks included.
_GIT_HARDENING = ("-c", f"core.hooksPath={os.devnull}", "-c", "init.templateDir=")
# The git variables the child is given. Everything else named ``GIT_*`` is removed, so no
# variable in the operator environment can redirect a call, inject configuration, name an
# identity, or point git at a program to run.
_GIT_ENVIRONMENT = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_TEMPLATE_DIR": "",
    "LC_ALL": "C",
}


def git_command(args: list[str]) -> tuple[list[str], dict[str, str]]:
    """The argv and environment for one git invocation that depends on nothing outside its *cwd*.

    Every git call this package makes is built here, so the rule holds on every path rather than
    at each call site: a git invocation must depend on nothing but the directory it names.

    What is neutralized. Every ``GIT_*`` variable in the operator environment is dropped, which
    covers the ones that point git somewhere else (``GIT_DIR``, ``GIT_WORK_TREE``,
    ``GIT_COMMON_DIR``, ``GIT_INDEX_FILE``, ``GIT_OBJECT_DIRECTORY``,
    ``GIT_ALTERNATE_OBJECT_DIRECTORIES``, ``GIT_CEILING_DIRECTORIES``, ``GIT_NAMESPACE``), the
    ones that inject configuration (``GIT_CONFIG``, ``GIT_CONFIG_COUNT`` and its key/value
    pairs), the ones that name an author or committer, and the ones that name a program to run
    (``GIT_SSH_COMMAND``, ``GIT_EXTERNAL_DIFF``, ``GIT_PROXY_COMMAND``, ``GIT_ASKPASS``,
    ``GIT_TEMPLATE_DIR``). Global, XDG, and system configuration are switched off with
    ``GIT_CONFIG_GLOBAL``, ``GIT_CONFIG_SYSTEM``, and ``GIT_CONFIG_NOSYSTEM``, so a global
    ``init.templateDir``, ``core.hooksPath``, ``core.fsmonitor``, or ``core.autocrlf`` cannot
    reach a trial workspace; system gitattributes are off for the same reason. Hooks and
    templates are switched off again on the command line, so neither a leftover value nor a
    future variable reintroduces them.

    What is not. The ``git`` binary itself is whatever ``PATH`` resolves, and ``PATH``, ``HOME``,
    and the rest of the non-git environment are passed through, so ssh still reads ``~/.ssh``.
    Configuration *inside* the directory a call names is still honored, which is deliberate:
    that is the repository the call is about. And because global configuration is off, a
    credential helper or a ``url.insteadOf`` rewrite an operator relies on is off too, so a
    fetch that needed one fails loudly rather than reaching a different remote than the one
    recorded.
    """
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    env.update(_GIT_ENVIRONMENT)
    return ["git", *_GIT_HARDENING, *args], env


def _git(args: list[str], cwd: Path, *, timeout: float = 600) -> str:
    """Run one hermetic git command in *cwd* and return its stdout. See :func:`git_command`."""
    argv, env = git_command(args)
    try:
        completed = subprocess.run(
            argv, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, env=env,
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

    staging = Path(tempfile.mkdtemp(prefix="scaneval-inspect-"))
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


def walk_regular_files(root: Path, *, skip_top_level: frozenset[str] = frozenset()) -> dict[str, Path]:
    """Every regular file under *root*, as ``{relative posix path: path}``.

    This is the one enumeration both the exported-tree hash and the modification check in
    :mod:`scaneval.execution` are built from, so neither can cover a path the other ignores.

    The walk is explicit rather than :meth:`Path.rglob`, which swallows the ``OSError`` a
    directory listing raises: under it a directory that cannot be listed is indistinguishable
    from an empty one, so a scanner could write files into the source, make the directory
    holding them unreadable, and watch them drop out of the map without a word. Here a listing
    that fails raises, and the caller decides whether that is a refused input or a failed
    observation.

    Left out and never descended into: any path with a ``.git`` component, and each name in
    *skip_top_level* at the top level. Left out as files: symbolic links and anything that is
    not a regular file, because they have no content of their own to hash. Because an excluded
    directory is never descended into, one of them being unreadable cannot fail the walk.
    """
    found: dict[str, Path] = {}
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        with os.scandir(directory) as entries:
            listed = sorted(entries, key=lambda entry: entry.name)
        for entry in listed:
            if entry.name == ".git" or (not prefix and entry.name in skip_top_level):
                continue
            if entry.is_symlink():
                continue
            relative = f"{prefix}{entry.name}"
            if entry.is_dir(follow_symlinks=False):
                pending.append((Path(entry.path), f"{relative}/"))
            elif entry.is_file(follow_symlinks=False):
                found[relative] = Path(entry.path)
    return found


def _first_component(path: str) -> str:
    return path.split("/", 1)[0]


def _is_instruction_file(path: str) -> bool:
    return (
        path.split("/")[-1] in INSTRUCTION_FILE_NAMES
        or _first_component(path) in INSTRUCTION_TOP_LEVEL
        or path in INSTRUCTION_PATHS
        or path.startswith(INSTRUCTION_PATH_PREFIXES)
    )


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
    """Create the minimum single-commit history a git-dependent scanner needs, with neutral identity.

    Every git call here is built by :func:`git_command`, so the repository this creates is the
    one in *source_dir* and nothing else. That matters twice over. ``GIT_DIR`` and
    ``GIT_WORK_TREE`` in the operator environment used to be inherited, so this could stage and
    commit into an unrelated repository outside the trial workspace; they are dropped now. And
    the operator's global configuration used to be read, so a global ``init.templateDir`` or
    ``core.hooksPath`` put a hook in the new repository that then ran inside the workspace and
    could write into the exported source this is supposed to leave untouched; global and system
    configuration are off, hooks and templates are off, and ``--no-verify`` stays as the
    commit-time belt to that suspenders. The recorded identity is the local configuration set
    below rather than ``GIT_AUTHOR_NAME`` or ``GIT_COMMITTER_NAME`` from the environment, which
    could otherwise make the identity this returns a false record of who committed.

    What is still not guaranteed: the returned commit describes what git wrote, not that the
    worked tree is unchanged. The caller compares the source before and after instead.
    """
    if (source_dir / ".git").exists():
        raise MaterializationError(f"{source_dir} already has git history")
    _git(["init", "-q"], source_dir)
    for key, value in (
        ("user.name", "ScanEval"), ("user.email", "scaneval@localhost"),
        ("commit.gpgsign", "false"), ("core.autocrlf", "false"), *_LFS_CONFIG,
    ):
        _git(["config", "--local", key, value], source_dir)
    # Force-add so an upstream .gitignore cannot drop exported files from the synthetic tree.
    _git(["add", "-A", "-f", "."], source_dir)
    _git(["commit", "-q", "--allow-empty", "--no-verify", "-m", message], source_dir)
    commit = _git(["rev-parse", "HEAD"], source_dir).strip()
    return {"commit": commit, "message": message, "identity": "ScanEval <scaneval@localhost>"}


def write_provenance(trial_dir: Path, record: dict) -> Path:
    """Write the preparation record beside the export, refusing to overwrite an existing file.

    The record is serialized and encoded before the file is created, so a record canonical JSON
    or UTF-8 cannot represent raises :class:`~scaneval.contracts.ContractError` and leaves no
    empty file behind for a reader to mistake for provenance. A lone UTF-16 surrogate is the
    case that survives serialization and fails only on encoding.
    """
    path = trial_dir / "provenance.json"
    text = canonical_json(record) + "\n"
    try:
        payload = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"provenance record is not canonical UTF-8 JSON: {exc}") from exc
    with path.open("xb") as handle:
        handle.write(payload)
    return path


def hash_exported_tree(source_dir: Path) -> dict:
    """Recompute the export's file map from disk, for verification against provenance.

    Enumeration is :func:`walk_regular_files`, the same one the modification check uses, so a
    directory that cannot be walked raises here instead of quietly shrinking the map that is
    compared against the recorded hash.
    """
    hashes = {relative: sha256_file(path)[0]
              for relative, path in sorted(walk_regular_files(source_dir).items())}
    return {"tree_hash": tree_hash(hashes), "file_count": len(hashes)}
