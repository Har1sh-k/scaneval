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

A native PR input is two exports, not one. :func:`export_pr` writes the head to ``source`` and the
base to ``base/source`` beside it, records the diff between the two trees a scanner is handed
(:func:`diff_trees`), and refuses a change with nothing in it.

:class:`Containment` is the one containment check this package has. Every path read or written
after a scanner ran is a path the scanner could have replaced, and the final component is not the
only one that can be a link, so the rule is stated once here and every such path is resolved
whole against a directory whose own real path was captured before the scanner started.

What that check is for, and what it is not, is stated in ``docs/THREAT_MODEL.md``: it defends
against a careless or buggy scanner and against accidental escape, and it does not survive a
hostile one running concurrently in a directory it controls. Read that document before treating
anything here as isolation.
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

from .contracts import ContractError, canonical_json, canonical_sha256, pr_diff_sha256, pr_input_hash


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


# Command-line settings every git invocation carries. All four are neutralizations rather than
# preferences: ``core.hooksPath`` under a path that cannot hold a hook means no hook is ever
# found, an empty ``init.templateDir`` means ``git init`` copies nothing into the new repository,
# hooks included, and the two file settings replace paths git would otherwise look for under the
# operator's HOME. They are set on the command line rather than in the environment because that
# is the only way to beat git's built-in fallback: ``core.attributesFile`` and
# ``core.excludesFile`` default to ``$XDG_CONFIG_HOME/git/attributes`` and ``.../git/ignore``
# when no configuration names them, and switching global configuration off does not switch that
# default off. A file at either path changes the bytes git writes into a working tree, and so the
# tree hash a whole run binds to.
_GIT_HARDENING = ("-c", f"core.hooksPath={os.devnull}", "-c", "init.templateDir=",
                  "-c", f"core.attributesFile={os.devnull}", "-c", f"core.excludesFile={os.devnull}")
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
    pairs), the ones that name an author or committer, the ones that name a program to run
    (``GIT_SSH_COMMAND``, ``GIT_EXTERNAL_DIFF``, ``GIT_PROXY_COMMAND``, ``GIT_ASKPASS``,
    ``GIT_TEMPLATE_DIR``), and the one that names a tree to read attributes from
    (``GIT_ATTR_SOURCE``). Global, XDG, and system configuration are switched off with
    ``GIT_CONFIG_GLOBAL``, ``GIT_CONFIG_SYSTEM``, and ``GIT_CONFIG_NOSYSTEM``, so a global
    ``init.templateDir``, ``core.hooksPath``, ``core.fsmonitor``, or ``core.autocrlf`` cannot
    reach a trial workspace; system gitattributes are off for the same reason. Hooks and
    templates are switched off again on the command line, so neither a leftover value nor a
    future variable reintroduces them.

    The operator's own attributes and ignore files are the same class of input and are covered
    the same way. ``core.attributesFile`` and ``core.excludesFile`` are pointed at
    :data:`os.devnull` on the command line, because git falls back to
    ``$XDG_CONFIG_HOME/git/attributes`` and ``$XDG_CONFIG_HOME/git/ignore`` (``~/.config/git/``
    when that variable is unset) when no configuration names them, and that fallback survives
    ``GIT_CONFIG_GLOBAL``. Without this, one ``* text=auto`` or one ``*.md filter=...`` line in
    the operator's home directory changed the bytes ``git checkout`` wrote into a cache entry,
    and therefore the exported snapshot and the ``tree_hash`` every result in the run binds to;
    one line in the global ignore file hid an untracked file from the ``--untracked-files=all``
    check that is supposed to prove a cache entry is clean.

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


@dataclass(frozen=True)
class Containment:
    """One directory, its real path captured before an untrusted process ran, and the rule for it.

    The one containment check in this package, and the one rule for every path that is read or
    written after a scanner has run: :meth:`contains` resolves the path whole, every symbolic
    link on the way followed, so it catches a link anywhere in the path and not only in its last
    component. Checking the final component is what let a link one level up redirect a read to
    anywhere on the host while each file behind it looked like an ordinary regular file.

    Why this is a captured object rather than a function of two paths. The check used to resolve
    its own base on every call, after the scanner had run, so a scanner that replaced the
    directory it was handed with a link to somewhere else moved the base as well as the path:
    both resolved under the root the scanner had chosen, the comparison succeeded, and the check
    said nothing at all. :meth:`capture` reads the base's real path once, before the scanner
    starts, and every later comparison is against that captured path, which nothing the scanner
    does can move. A base is therefore never resolved after the process it contains has run.

    *base* is kept beside *root* because a caller that has proved a path is inside still needs
    the name it was handed to make the path relative for a record: ``root`` is where the
    directory really is, ``base`` is what this run called it.

    The limits. This compares resolved paths: it does not follow bind mounts or hard links, so it
    is a check against the obvious escape rather than an isolation boundary. And resolving is not
    opening, so a process still running in that directory can replace a component between the
    check and the read; the callers here run after the scanner process has exited, which narrows
    that window rather than closing it. ``docs/THREAT_MODEL.md`` states plainly what that leaves
    undefended, with the restore-before-return race as the worked example.
    """

    base: Path
    root: Path

    @classmethod
    def capture(cls, base: Path) -> "Containment":
        """Read *base*'s real path now, to compare against for the rest of the run.

        Call this before handing the directory to anything untrusted. A base the filesystem
        refuses to resolve, or that is not a path it accepts at all, is a setup failure rather
        than a check that returns ``None`` later: there is no captured path to contain against,
        so nothing can be proved inside it. A base that does not exist yet resolves to where it
        would be created, which is what a capture destination needs.
        """
        base = Path(base)
        try:
            return cls(base, base.resolve())
        except (OSError, ValueError) as exc:
            raise MaterializationError(
                f"the directory {base} could not be resolved, so nothing can be proved to be "
                f"inside it: {exc}") from exc

    def contains(self, path: Path) -> Path | None:
        """*path* resolved whole, when it is still inside this directory; ``None`` when it is not.

        The captured root itself is inside it, and a path that does not exist yet resolves to
        where it would be created. ``None`` means one of three things, all of which a caller must
        treat the same way: the path left the directory, the filesystem refused to resolve it
        (``OSError``), or it is not a path the filesystem accepts at all, such as one holding an
        embedded NUL byte (``ValueError``).
        """
        try:
            resolved = Path(path).resolve()
        except (OSError, ValueError):
            return None
        return resolved if resolved == self.root or resolved.is_relative_to(self.root) else None


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

    Left out and never descended into, at the top level only: ``.git``, and each name in
    *skip_top_level*. Both exclusions are for directories this runner creates or hands over, and
    the top-level restriction is the point of them. A ``.git`` at any depth used to be skipped,
    so a scanner could put everything it wrote under a nested ``.git`` and the map, the exported
    hash, and the modification check built from it would all report a tree nobody had touched.
    Only the one the runner creates for a git-dependent adapter is excluded now, and an export
    ships no other: :func:`export_snapshot` strips every ``.git`` path out of the snapshot.

    Left out as files: symbolic links and anything that is not a regular file, because they have
    no content of their own to hash. Because an excluded directory is never descended into, one
    of them being unreadable cannot fail the walk; a nested ``.git`` that cannot be listed now
    fails it, like any other directory whose files the map is supposed to cover.
    """
    found: dict[str, Path] = {}
    pending: list[tuple[Path, str]] = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        with os.scandir(directory) as entries:
            listed = sorted(entries, key=lambda entry: entry.name)
        for entry in listed:
            if not prefix and (entry.name == ".git" or entry.name in skip_top_level):
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


@dataclass(frozen=True)
class ExportedTree:
    """What one export wrote: ``{relative path: content hash}`` for every file, and what it left out.

    ``hashes`` covers exactly the regular files written, so :func:`tree_hash` over it is the tree
    hash of the export. ``stripped``, ``skipped``, and ``instruction_files`` are sorted as the
    provenance record carries them.
    """

    hashes: dict[str, str]
    stripped: list[str]
    skipped: list[dict]
    instruction_files: list[str]
    byte_count: int


def export_snapshot(
    snapshot: CachedSnapshot,
    trial_dir: Path,
    *,
    profile: str = "standard",
    blinding_map: dict | None = None,
    snapshot_id: str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> dict:
    """Copy the tracked regular files of *snapshot* into ``trial_dir/source`` and record provenance.

    The ``standard`` profile writes exactly the export and the record this function has always
    written; ``blinding_map`` and ``snapshot_id`` play no part in it. ``metadata_blinded`` needs
    the reviewed replacement map and the pack snapshot id its variants are keyed by, and is
    delegated to :func:`scaneval.blinding.export_blinded`: the original export goes to
    ``trial_dir/original/source``, which no scanner is handed, and the transformed copy to
    ``trial_dir/source``. A map that is not approved or does not fit this export is refused with
    the reason, and without a map blinding is reported unavailable; neither is ever silently
    replaced by ``standard``.
    """
    if profile not in PROFILES:
        raise MaterializationError(f"unknown input profile {profile!r}; expected one of {PROFILES}")
    if profile == "metadata_blinded":
        if blinding_map is None:
            raise MaterializationError("metadata blinding unavailable: no reviewed replacement map was supplied")
        # Imported here because the blinding module builds on this one.
        from .blinding import export_blinded
        return export_blinded(snapshot, trial_dir, blinding_map, snapshot_id=snapshot_id, clock=clock)
    source = trial_dir / "source"
    if source.exists():
        raise MaterializationError(f"trial source directory already exists: {source}")
    return provenance_record(snapshot, profile, export_tree(snapshot, source), clock=clock)


def export_tree(snapshot: CachedSnapshot, source: Path) -> ExportedTree:
    """Write the tracked regular files of *snapshot* under *source*, which must not exist yet.

    Controller and harness state and every ``.git`` path are stripped; submodule gitlinks,
    symbolic links, and anything else that is not a blob are skipped with a reason. Files keep
    their executable bit and nothing else of their metadata.
    """
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
    return ExportedTree(hashes, sorted(stripped), sorted(skipped, key=lambda item: item["path"]),
                        sorted(instructions), byte_count)


def provenance_record(snapshot: CachedSnapshot, profile: str, exported: ExportedTree, *,
                      clock: Callable[[], datetime] | None = None) -> dict:
    """The preparation record of one export, as :func:`export_snapshot` writes it for ``standard``.

    Every field describes *exported*, the tree a scanner is handed. A blinded record starts from
    this one and adds what describes the original export and the transformation.
    """
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
            "tree_hash": tree_hash(exported.hashes),
            "file_count": len(exported.hashes),
            "byte_count": exported.byte_count,
        },
        "stripped": list(exported.stripped),
        "skipped": list(exported.skipped),
        "instruction_files": list(exported.instruction_files),
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


# Where a PR input's base export sits beneath its trial directory: ``base/source``.
PR_BASE_DIR = "base"


def _tree_state(root: Path) -> dict[str, tuple[str, bool]]:
    """``{relative path: (content hash, executable)}`` for every regular file under *root*."""
    return {relative: (sha256_file(path)[0], bool(os.stat(path).st_mode & 0o100))
            for relative, path in sorted(walk_regular_files(root).items())}


def diff_trees(base_root: Path, head_root: Path) -> dict:
    """The changes between two exported trees, as file-level facts about what a scanner is handed.

    ``added`` and ``deleted`` are paths in only one tree. ``modified`` are paths in both whose bytes
    differ, and ``mode_changed`` paths whose executable bit differs, whether or not their bytes do.
    ``renamed`` is ``[from, to]`` for a file deleted from one path and added at another with the
    same bytes: exact content only, so a file that moved and was also edited is an addition and a
    deletion, and only when exactly one deleted path and exactly one added path hold those bytes,
    because among several identical files nothing says which one went where and no pairing is
    invented. A renamed pair is in neither ``added`` nor ``deleted``, and its ``to`` is also in
    ``mode_changed`` when its executable bit differs from its source's. Every list is sorted, so
    the record is canonical.

    The trees are read as they lie on disk, through :func:`walk_regular_files`, so this is the
    diff of the trees a scanner is handed, transformed ones included, and never of the originals.
    Symbolic links have no content and are in neither tree. It compares bytes and one mode bit; it
    does not read source, follow moved code, or say whether a change matters.
    """
    base, head = _tree_state(base_root), _tree_state(head_root)
    added, deleted = sorted(set(head) - set(base)), sorted(set(base) - set(head))
    common = sorted(set(base) & set(head))
    modified = [path for path in common if base[path][0] != head[path][0]]
    mode_changed = [path for path in common if base[path][1] != head[path][1]]
    deleted_by_content: dict[str, list[str]] = {}
    added_by_content: dict[str, list[str]] = {}
    for path in deleted:
        deleted_by_content.setdefault(base[path][0], []).append(path)
    for path in added:
        added_by_content.setdefault(head[path][0], []).append(path)
    renamed = sorted([sources[0], added_by_content[digest][0]]
                     for digest, sources in deleted_by_content.items()
                     if len(sources) == 1 and len(added_by_content.get(digest, [])) == 1)
    moved_from, moved_to = {source for source, _ in renamed}, {target for _, target in renamed}
    mode_changed += [target for source, target in renamed if base[source][1] != head[target][1]]
    return {"added": [path for path in added if path not in moved_to],
            "deleted": [path for path in deleted if path not in moved_from],
            "modified": modified, "renamed": renamed, "mode_changed": sorted(mode_changed)}


def changed_paths(changes: dict) -> list[str]:
    """Every path ``git diff --name-only`` names between the two synthetic commits, sorted.

    The added, modified, mode-changed, and deleted paths, and the new name of each rename, because
    git names a detected rename by its new path alone. This is the list a scanner that asks git
    which files changed is told, which is why a test can hold a scanner's own reading of the change
    to the record.
    """
    paths = (set(changes["added"]) | set(changes["deleted"]) | set(changes["modified"])
             | set(changes["mode_changed"]) | {target for _, target in changes["renamed"]})
    return sorted(paths)


def export_pr(base: CachedSnapshot, head: CachedSnapshot, trial_dir: Path, *, profile: str = "standard",
              blinding_map: dict | None = None, base_snapshot_id: str | None = None,
              head_snapshot_id: str | None = None, clock: Callable[[], datetime] | None = None) -> dict:
    """Export the two snapshots of a change set into one trial and record the change between them.

    The head goes to ``trial_dir/source``, exactly where a full input's export goes, and the base
    to ``trial_dir/base/source``. Under ``metadata_blinded`` both are transformed with the one
    reviewed map, so its variants must cover both snapshots and a base and a head carry one set of
    pseudonyms, and the originals stay evaluator-side under ``original/source`` and
    ``original/base/source``; the labels and mechanical checks refer to those, and a scanner is
    handed only the transformed trees. A map that is unapproved, or does not fit either export,
    refuses the whole input with its reason: neither snapshot is ever exported standard in its
    place.

    The record returned is the preparation record of the input, ``schema_version`` 2.1: the
    ``head`` and ``base`` records exactly as :func:`export_snapshot` writes them (each with its
    ``trial.root``), the ``diff`` between the trees a scanner is handed (:func:`diff_trees` over
    them, the two tree hashes, and :func:`scaneval.contracts.pr_diff_sha256` of all three), and the
    ``input_hash`` the input is identified by (:func:`scaneval.contracts.pr_input_hash`). A change
    with nothing in it, two exports that are identical, is refused before anything else is asked:
    there is no change to review, and a scan of it would be a scan of nothing recorded as a review.
    The synthetic history a git-dependent scanner is handed is not built here.
    """
    if profile not in PROFILES:
        raise MaterializationError(f"unknown input profile {profile!r}; expected one of {PROFILES}")
    base_source = trial_dir / PR_BASE_DIR / "source"
    if base_source.exists() or base_source.is_symlink():
        raise MaterializationError(f"trial source directory already exists: {base_source}")
    if profile == "metadata_blinded":
        if blinding_map is None:
            raise MaterializationError("metadata blinding unavailable: no reviewed replacement map was supplied")
        # Both snapshots are asked everything that needs no export before either is exported, so a map
        # that does not fit one of them leaves no half-blinded input behind.
        from .blinding import preflight
        for snapshot, snapshot_id in ((head, head_snapshot_id), (base, base_snapshot_id)):
            preflight(blinding_map, snapshot_id, snapshot)
    head_record = export_snapshot(head, trial_dir, profile=profile, blinding_map=blinding_map,
                                  snapshot_id=head_snapshot_id, clock=clock)
    if profile == "metadata_blinded":
        from .blinding import export_blinded
        base_record = export_blinded(base, trial_dir, blinding_map, snapshot_id=base_snapshot_id,
                                     clock=clock, variant_dir=PR_BASE_DIR)
    else:
        base_record = provenance_record(base, profile, export_tree(base, base_source), clock=clock)
        base_record["trial"]["root"] = f"{PR_BASE_DIR}/source"
    changes = diff_trees(base_source, trial_dir / "source")
    if not any(changes.values()):
        raise MaterializationError(
            "no change to review: the base and head exports of this change set hold the same files "
            "with the same bytes and modes")
    base_hash, head_hash = base_record["trial"]["tree_hash"], head_record["trial"]["tree_hash"]
    digest = pr_diff_sha256(base_hash, head_hash, changes)
    return {
        "schema_version": "2.1", "mode": "pr", "profile": profile, "head": head_record, "base": base_record,
        "diff": {"base_tree_hash": base_hash, "head_tree_hash": head_hash, "changes": changes,
                 "diff_sha256": digest},
        "input_hash": pr_input_hash(base_hash, head_hash, digest),
        "limits": [
            "The diff is over the trees a scanner is handed, file by file: bytes and the executable bit. "
            "A rename is recorded only when the bytes are identical.",
            "The base sits beside the head under base/source and reaches a scanner only as the first "
            "commit of the synthetic history; the original exports of a blinded input never do.",
        ],
    }


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
