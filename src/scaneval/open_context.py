"""Construct and attest the original ancestor history of an open-context input.

An arbitrary clone is never copied into a trial. A fresh fetch supplies objects, then a second,
fresh object store receives only the closure of the evaluated commit. No repository-local
configuration, ref, hook, alternate, reflog, or unreachable object crosses that boundary.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from .contracts import canonical_sha256
from .materialize import (
    CachedSnapshot, MaterializationError, _git, _require_commit, git_command,
    sha256_file, tree_hash, walk_regular_files, STRIPPED_TOP_LEVEL,
)


HISTORY_POLICY = "ancestor_history_v1"
RETRIEVAL_POLICY = "recorded_public_v1"
# This is the entire scanner-visible configuration. Never inherit a fetched repository's config.
_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
    "\tlogallrefupdates = false\n\tautocrlf = false\n\thooksPath = /dev/null\n"
    "\tattributesFile = /dev/null\n\texcludesFile = /dev/null\n"
    "[credential]\n\thelper =\n[commit]\n\tgpgsign = false\n"
)


def validate_policy(policy: dict) -> dict:
    """Refuse stale or ambiguous policy names before any input or scanner is prepared."""
    required = {"history", "retrieval", "web_mode", "capture", "retention"}
    if not isinstance(policy, dict) or set(policy) != required:
        raise MaterializationError(f"open_context policy must declare exactly {', '.join(sorted(required))}")
    if policy["history"] != HISTORY_POLICY or policy["retrieval"] != RETRIEVAL_POLICY:
        raise MaterializationError("open_context history/retrieval policy is unknown or stale")
    if policy["web_mode"] != "live":
        raise MaterializationError("this open_context backend supports live retrieval only")
    if (policy["capture"], policy["retention"]) not in (("content", "bundle"), ("hashes", "hashes_only")):
        raise MaterializationError("open_context capture/retention must be content/bundle or hashes/hashes_only")
    return dict(policy)


def _binary_git(args: list[str], cwd: Path, *, data: bytes | None = None, output=None) -> bytes:
    argv, env = git_command(args)
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, input=data, stdout=output or subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=900)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MaterializationError(f"bounded history git command failed: {exc}") from exc
    if result.returncode:
        raise MaterializationError(f"bounded history git command failed: {result.stderr.decode('utf-8', 'replace')[:1000]}")
    return result.stdout or b""


def _metadata_files(directory: Path) -> list[str]:
    """Require a small, regular, self-contained metadata tree before asking Git to read it."""
    allowed = []
    if directory.is_symlink() or not directory.is_dir():
        raise MaterializationError("bounded history metadata is not a real directory")
    def failed(exc):
        raise MaterializationError(f"bounded history metadata could not be enumerated: {exc}") from exc
    for base, directories, files in os.walk(directory, followlinks=False, onerror=failed):
        for name in directories + files:
            path = Path(base) / name
            mode = path.lstat()
            if stat.S_ISLNK(mode.st_mode) or (not stat.S_ISDIR(mode.st_mode) and
                                            (not stat.S_ISREG(mode.st_mode) or mode.st_nlink != 1)):
                raise MaterializationError("bounded history contains a link or special file")
            if stat.S_ISREG(mode.st_mode):
                rel = path.relative_to(directory).as_posix()
                if rel not in ("HEAD", "config", "index") and not (
                    re.fullmatch(r"objects/pack/pack-[0-9a-f]{40}\.(pack|idx|rev)", rel)):
                    raise MaterializationError(f"bounded history contains forbidden metadata: {rel}")
                allowed.append(rel)
            elif path.relative_to(directory).as_posix() not in (
                "objects", "objects/info", "objects/pack", "refs", "refs/heads", "refs/tags",
            ):
                raise MaterializationError("bounded history contains a forbidden metadata directory")
    if set(("HEAD", "config", "index")) - set(allowed):
        raise MaterializationError("bounded history lacks HEAD, config, or its evaluated-tree index")
    if (directory / "config").read_text() != _CONFIG:
        raise MaterializationError("bounded history configuration differs from its hermetic policy")
    return sorted(allowed)


def _source_binding(repository: Path, source_dir: Path, head: str, expected_tree_hash: str) -> tuple[str, list]:
    files = walk_regular_files(source_dir, skip_top_level=frozenset({".git"}))
    actual = tree_hash({rel: sha256_file(path)[0] for rel, path in files.items()})
    if actual != expected_tree_hash:
        raise MaterializationError("bounded history source tree does not match the evaluated tree hash")
    raw = _binary_git(["ls-tree", "-r", "-z", head], repository)
    entries = {}
    omitted = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, name = item.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        try:
            rel = name.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MaterializationError("bounded history requires UTF-8 source paths") from exc
        if any(part == ".git" for part in rel.split("/")) or rel.split("/", 1)[0] in STRIPPED_TOP_LEVEL:
            raise MaterializationError("bounded history exposes excluded evaluator or harness state")
        if mode == "120000" or kind == "commit":
            omitted.append({"path": rel, "reason": "symbolic link" if mode == "120000" else "submodule gitlink",
                            "object": oid, "history_exposure": "original_object_preserved"})
            continue
        if mode not in ("100644", "100755") or kind != "blob":
            raise MaterializationError("bounded history head contains an unsupported Git entry")
        entries[rel] = (mode, oid)
    if set(entries) != set(files):
        raise MaterializationError("bounded history head and evaluated export contain different paths")
    paths = sorted(files)
    for offset in range(0, len(paths), 200):
        group = paths[offset:offset + 200]
        # --no-filters prevents repository attributes from rewriting the bytes being compared.
        ids = _git(["hash-object", "--no-filters", "--", *[str(files[rel]) for rel in group]], repository).splitlines()
        for rel, oid in zip(group, ids, strict=True):
            executable = bool(files[rel].stat().st_mode & 0o111)
            if oid != entries[rel][1] or executable != (entries[rel][0] == "100755"):
                raise MaterializationError(f"bounded history head bytes or executable mode differ at {rel}")
    return actual, sorted(omitted, key=lambda item: item["path"])


def _index_binding(repository: Path, head: str, omissions: list) -> str:
    """Require ordinary stage-zero HEAD entries, skipping only explicit export omissions."""
    expected = {}
    for item in _binary_git(["ls-tree", "-r", "-z", head], repository).split(b"\0"):
        if item:
            metadata, name = item.split(b"\t", 1)
            mode, _kind, oid = metadata.decode("ascii").split()
            expected[name] = (mode, oid, "0")
    staged = {}
    for item in _binary_git(["ls-files", "--stage", "-z"], repository).split(b"\0"):
        if item:
            metadata, name = item.split(b"\t", 1)
            if name in staged:
                raise MaterializationError("bounded history index contains unresolved stages")
            staged[name] = tuple(metadata.decode("ascii").split())
    flags = {}
    for item in _binary_git(["ls-files", "-v", "-z"], repository).split(b"\0"):
        if item:
            flag, name = item.split(b" ", 1)
            flags[name] = flag
    omitted = {entry["path"].encode("utf-8") for entry in omissions}
    if staged != expected or set(flags) != set(expected) or any(
            flag != (b"S" if name in omitted else b"H") for name, flag in flags.items()):
        raise MaterializationError("bounded history index does not bind to HEAD and declared export omissions")
    return sha256_file(repository / ".git" / "index")[0]


def attest_history(repository: Path, source_dir: Path, *, head_commit: str,
                   expected_tree_hash: str) -> dict:
    """Verify both reachable and *all stored* objects; refs alone cannot exclude descendant fixes."""
    head = _require_commit(head_commit)
    git_dir = repository / ".git"
    _metadata_files(git_dir)
    if (git_dir / "HEAD").read_text() != head + "\n":
        raise MaterializationError("bounded history must expose only the detached evaluated HEAD")
    if _git(["for-each-ref", "--format=%(refname)"], repository).strip():
        raise MaterializationError("bounded history contains a branch, tag, or other ref")
    if _git(["rev-parse", "--is-shallow-repository"], repository).strip() != "false":
        raise MaterializationError("bounded history ancestry is shallow or incomplete")
    lines = _git(["rev-list", "--parents", head], repository).splitlines()
    parents = {parts[0]: parts[1:] for parts in (line.split() for line in lines)}
    if not parents or any(parent not in parents for row in parents.values() for parent in row):
        raise MaterializationError("bounded history ancestry is incomplete")
    reachable = sorted({line.split()[0] for line in _git(["rev-list", "--objects", head], repository).splitlines()})
    stored = sorted(_git(["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"], repository).splitlines())
    if reachable != stored:
        raise MaterializationError("bounded history contains unreachable or missing objects")
    # Removing these paths from an export cannot remove their original blobs from exact ancestor
    # history. Refuse such a history explicitly, rather than rewriting commits or claiming absence.
    if _git(["log", "--full-history", "--format=%H", head, "--", *sorted(STRIPPED_TOP_LEVEL)], repository).strip():
        raise MaterializationError("bounded history exposes excluded evaluator or harness state")
    source_hash, omissions = _source_binding(repository, source_dir, head, expected_tree_hash)
    index_hash = _index_binding(repository, head, omissions)
    commit_times = []
    for line in _git(["log", "--format=%ct %H", head], repository).splitlines():
        timestamp, oid = line.split()
        commit_times.append((int(timestamp), oid))
    earliest, earliest_commit = min(commit_times)
    git_tree = _git(["rev-parse", f"{head}^{{tree}}"], repository).strip()
    refs = [{"name": "HEAD", "target": head, "symbolic": False}]
    config_hash = "sha256:" + hashlib.sha256(_CONFIG.encode()).hexdigest()
    return {
        "status": "available", "policy": HISTORY_POLICY, "head_commit": head, "git_tree": git_tree,
        "reachable_commit_count": len(parents), "object_count": len(stored),
        "earliest_commit": earliest_commit,
        "earliest_committed_at": datetime.fromtimestamp(earliest, timezone.utc).isoformat(),
        "root_commits": sorted(oid for oid, row in parents.items() if not row), "refs": refs,
        "history_digest": canonical_sha256({"policy": HISTORY_POLICY, "head": head, "objects": reachable,
                                             "parents": parents, "refs": refs, "config": config_hash,
                                             "index": index_hash}),
        "source_tree_hash": source_hash, "git_config_sha256": config_hash,
        "git_index_sha256": index_hash,
        "source_export_omissions": omissions,
        "capture": "constructed_and_verified",
    }


def export_history(snapshot: CachedSnapshot, destination: Path, *, source_dir: Path,
                   expected_tree_hash: str) -> dict:
    """Fetch complete ancestry, repack its exact closure, and publish a sanitized .git artifact.

    Fetching may receive extra objects. Repacking into a *different* object store, followed by
    an all-object inventory, removes that ambiguity. A shallow upstream is refused rather than
    being represented as complete ancestry. Original object ids preserve authors, dates, messages,
    trees, and diffs exactly. Symbolic links and gitlinks stay omitted from the working tree as in
    the standard export; their original history exposure is recorded, and neither is followed.
    """
    head = _require_commit(snapshot.commit)
    if destination.exists():
        raise MaterializationError("bounded history destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="history-", dir=destination.parent) as scratch:
        root = Path(scratch)
        fetched = root / "fetch"
        fetched.mkdir()
        _git(["init", "-q", "--bare"], fetched)
        _git(["-c", "protocol.ext.allow=never", "fetch", "-q", "--no-tags", "--no-recurse-submodules",
              "--", snapshot.url, head], fetched, timeout=900)
        if _git(["rev-parse", "--is-shallow-repository"], fetched).strip() != "false":
            raise MaterializationError("open_context unavailable: upstream ancestry is shallow")
        clean = root / "clean"
        clean.mkdir()
        _git(["init", "-q"], clean)
        git_dir = clean / ".git"
        for entry in list(git_dir.iterdir()):
            if entry.name != "objects":
                shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
        (git_dir / "HEAD").write_text(head + "\n")
        (git_dir / "config").write_text(_CONFIG)
        (git_dir / "refs").mkdir()
        pack = root / "ancestor.pack"
        with pack.open("wb") as stream:
            _binary_git(["pack-objects", "--stdout", "--revs", "--no-reuse-delta", "--no-reuse-object"],
                        fetched, data=(head + "\n").encode(), output=stream)
        with pack.open("rb") as stream:
            argv, env = git_command(["index-pack", "--stdin"])
            result = subprocess.run(argv, cwd=clean, env=env, stdin=stream, capture_output=True, timeout=900)
            if result.returncode:
                raise MaterializationError("bounded ancestor pack could not be indexed")
        _source_hash, omissions = _source_binding(clean, source_dir, head, expected_tree_hash)
        # read-tree writes a stat-free v2 index and invokes no checkout, attributes, filters, or
        # hooks. Thus it is deterministic and does not rewrite the exported source bytes.
        _git(["-c", "index.version=2", "read-tree", head], clean)
        if omissions:
            _binary_git(["update-index", "--skip-worktree", "-z", "--stdin"], clean,
                        data=b"".join(entry["path"].encode("utf-8") + b"\0" for entry in omissions))
        evidence = attest_history(clean, source_dir, head_commit=head, expected_tree_hash=expected_tree_hash)
        shutil.copytree(git_dir, destination)
        return evidence


def install_history(history_dir: Path, source_dir: Path, *, expected: dict) -> dict:
    """Install only verified metadata in a private workspace and recheck the source binding."""
    if not history_dir or not isinstance(expected, dict) or expected.get("policy") != HISTORY_POLICY:
        raise MaterializationError("open_context unavailable: no attested ancestor history")
    _metadata_files(Path(history_dir))
    target = source_dir / ".git"
    if target.exists() or target.is_symlink():
        raise MaterializationError("open_context workspace already contains Git metadata")
    shutil.copytree(history_dir, target)
    actual = attest_history(source_dir, source_dir, head_commit=expected["head_commit"],
                            expected_tree_hash=expected["source_tree_hash"])
    if actual != expected:
        raise MaterializationError("bounded history differs from its preparation attestation")
    return actual
