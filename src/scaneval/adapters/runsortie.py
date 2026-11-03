"""Native RunSortie adapter: one full RunSortie orchestration of one disposable ScanEval workspace.

RunSortie is a local orchestrator around the Fieldglass engine: its ``scan`` command runs Fieldglass,
hands the engine's findings to a primary coding agent for packet-level disposition, sends every
proposed disposition at the configured severity to a separately configured challenger model, and
commits the resulting evidence under ``.fieldglass``. That is a different system from the
``llm-harness`` adapter, which drives the Fieldglass engine directly with no primary review, no
challenger and no evidence commit; a run of one is never recorded as the other, and this adapter
reuses ``llm_harness`` only for its hardened snapshot, staging and import of finding records, never
for its completion semantics.

What one invocation does. :meth:`RunSortieAdapter.prepare` refuses anything but an explicit, clean,
prebuilt RunSortie checkout at the exact ``expected_commit`` and package version, with its bundled
Fieldglass already installed, and records each runtime identity at the assurance it really has.
:meth:`RunSortieAdapter.scan` writes a mode-0600 RunSortie configuration naming the disposable ScanEval
workspace as the only target, ``.fieldglass`` as the only evidence root, ``commitResults: true``,
``pushResults: false``, no schedule and no notification, with the pinned checkout's installed
Fieldglass as ``engine.localPath`` so RunSortie never copies or installs an engine. State and cache
directories and agent homes are created for the invocation, with operator homes/configuration refused.
When Codex is selected its API-key login and status check run privately first; then exactly one
``node dist/cli.js scan --config ... --target scaneval`` process is started. Every process goes through
:func:`~scaneval.adapters.base.run_command` with the shared deadline; RunSortie's separate native
``status`` prose is never invoked or parsed.

What decides the status. Everything RunSortie leaves behind is read without following a link and
bounded, staged create-only into the bundle and registered file by file before the workspace
disappears, and judged by :mod:`scaneval.adapters.runsortie_evidence`. Completion is bound to the
head ScanEval evaluated, never to RunSortie's evidence head: ``success`` needs exit zero, a
``committed`` outcome, a ``ready``/``complete`` baseline, an engine checkpoint and accepted policy-1
baseline acceptance at the evaluated head, a complete and internally consistent verification summary
over well-formed review packets, a work budget that was not exhausted, exactly one evidence commit
changing only ``.fieldglass``, and no import loss.

What is not established. Network access is not enforced: the local backend is the only one this
adapter runs under, and RunSortie's agents reach their providers directly. No provider attests the
model it served, and RunSortie has three model roles (engine, primary, challenger) where a result has
one model slot, so ``model_identity`` is ``None``; the requested routes are in the frozen system
configuration and the routes RunSortie's own records name are in the receipts and notes. The evidence
commit changes the workspace's synthetic ``.git``, which ScanEval's condition audit records as
``history_changed``; that is the truth about the run and is not hidden. The checks against what
RunSortie wrote are checks, not isolation: ``docs/THREAT_MODEL.md`` applies here as to every adapter.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import posixpath
import pwd
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zlib
from typing import Any, NamedTuple

from ..materialize import Containment, MaterializationError, git_command
from . import runsortie_evidence as evidence
from .base import (Adapter, AdapterError, NativeOutcome, SystemSpec, _process_group_absent_after_reap,
                   _signal_reserved_process_group, _wait_for_unreaped_exit, active_backend, build_env, run_command)
from .llm_harness import (Enclosure, HarnessImport, LostRecord, _native_scan_site, kind_for_harness_class,
                          parse_frontmatter)


TARGET = "scaneval"
ENGINE_SOURCE = "bundled:fieldglass"
SUPPORTED_RUNSORTIE_COMMIT = "af8f2402469dca441f6d9efd5929ddeab5c64957"
SUPPORTED_RUNSORTIE_VERSION = "0.1.0"
AGENTS = ("codex",)
VERIFIER_AGENTS = ("codex",)
# ``AGENT_REASONING_EFFORTS`` in the pinned src/types.ts. Cursor is refused outright: its headless
# mode is not read-only, so RunSortie will not run it as a verifier, and as a primary it would receive
# its prompt on the command line. Direct Gemini routes are also refused in v1: its pinned headless CLI
# cannot both proceed in an untrusted workspace and prove that repository hooks/config were ignored.
# Claude 2.1.310 ``--bare`` suppresses hooks/plugins but not remote admin permission policy, while
# pinned RunSortie's allowed-tools arguments are additive. Direct Claude agents are therefore also
# refused in secure v1; two distinct Codex model routes retain native cross-model review.
AGENT_EFFORTS = {"codex": ("minimal", "low", "medium", "high", "xhigh"),
                 "claude": ("low", "medium", "high", "xhigh", "max")}
AGENT_BINARIES = {"codex": "codex", "claude": "claude"}
SEVERITIES = ("high", "medium", "low")
BUDGET_ROLES = evidence.WORK_BUDGET_ROLES
CONFIG_KEYS = frozenset({"root", "expected_commit", "expected_version", "expected_dist_tree_sha256", "engine_model",
                         "primary", "challenger", "minimum_severity", "work_budget", "credential_env"})
ROUTE_KEYS = frozenset({"agent", "model", "reasoning_effort"})
_ROUTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
# The pinned native agents' documented provider credentials. Configuration accepts no generic
# environment passthrough: names such as CODEX_HOME, CLAUDE_CONFIG_DIR, PI_CODING_AGENT_DIR,
# BASH_ENV, or ENV redirect code/configuration and are runtime inputs rather than credentials.
CREDENTIAL_ENV_ALLOWLIST = frozenset({
    "AI_GATEWAY_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_OAUTH_TOKEN",
    "ANT_LING_API_KEY", "AZURE_OPENAI_API_KEY", "BASETEN_API_KEY", "CEREBRAS_API_KEY",
    "CLOUDFLARE_API_KEY", "COPILOT_GITHUB_TOKEN", "DEEPSEEK_API_KEY", "FIREWORKS_API_KEY",
    "GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_CLOUD_API_KEY", "GROQ_API_KEY", "HF_TOKEN",
    "KIMI_API_KEY", "META_API_KEY", "MINIMAX_API_KEY", "MINIMAX_CN_API_KEY", "MISTRAL_API_KEY",
    "MOONSHOT_API_KEY", "NVIDIA_API_KEY", "OPENCODE_API_KEY", "OPENAI_API_KEY",
    "OPENROUTER_API_KEY", "QWEN_TOKEN_PLAN_API_KEY", "QWEN_TOKEN_PLAN_CN_API_KEY", "RADIUS_API_KEY",
    "TOGETHER_API_KEY", "TYPESAFE_API_KEY", "XAI_API_KEY", "XIAOMI_API_KEY",
    "XIAOMI_TOKEN_PLAN_AMS_API_KEY", "XIAOMI_TOKEN_PLAN_CN_API_KEY", "XIAOMI_TOKEN_PLAN_SGP_API_KEY",
    "ZAI_API_KEY", "ZAI_CODING_CN_API_KEY",
})
# Receipts RunSortie and Fieldglass write under .fieldglass that this adapter stages and registers.
RECEIPTS = (".state.json", "baseline-acceptance.json", "verification-summary.json", "primary-review-packets.json",
            "sortie-state.json", "sortie-review.md", "work-budget.json", "fieldglass-work-budget.json",
            "target-security-policy.json", "scan-log.md", "threat-model.md", "bootstrap-plan.md", "specialists.json",
            "specialists.md", "dependency-capabilities.json")
MAX_RECEIPT_BYTES = 8 * 1024 * 1024
MAX_STATE_FILES = 500
MAX_STATE_FILE_BYTES = 4 * 1024 * 1024
MAX_STATE_TOTAL_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_FILES = 2000
MAX_DIST_FILES = 2000
MAX_PRIVATE_ENTRIES = 4000
MAX_PRIVATE_DEPTH = 32
MAX_CACHE_ENTRIES = 2000
MAX_PRIVATE_CLEANUP_ENTRIES = MAX_PRIVATE_ENTRIES + MAX_CACHE_ENTRIES + 32
MAX_GIT_METADATA_ENTRIES = 200_000
MAX_PRODUCT_ENTRIES = 200_000
MAX_PRODUCT_DEPTH = 128
MAX_PRODUCT_FILE_BYTES = 512 * 1024 * 1024
MAX_PRODUCT_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_IDENTITY_JSON_BYTES = 8 * 1024 * 1024
MAX_PACKAGED_SKILL_BYTES = 1024 * 1024
MAX_PRIMARY_PROMPT_BYTES = 2 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_DEPENDENCY_ENTRIES = 20_000
MAX_DEPENDENCY_DEPTH = 64
MAX_DEPENDENCY_FILE_BYTES = 256 * 1024 * 1024
MAX_DEPENDENCY_TOTAL_BYTES = 512 * 1024 * 1024
MAX_DEPENDENCY_SYMLINK_HOPS = 64
MAX_NPM_PACKAGE_ANCESTORS = 8
PI_ISOLATION_FLAGS = ("--no-tools", "--no-extensions", "--no-mcp", "--no-skills",
                      "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve")
NPM_SCRIPT_SHELL = Path("/bin/sh")
AGENT_SHELL = Path("/bin/bash")
MANAGED_PREFERENCES_ROOT = Path("/Library/Managed Preferences")
CODEX_SYSTEM_POLICY_PATHS = (
    Path("/etc/codex/config.toml"), Path("/etc/codex/requirements.toml"),
    Path("/etc/codex/managed_config.toml"),
    MANAGED_PREFERENCES_ROOT / "com.openai.codex.plist",
    Path("/Library/Preferences/com.openai.codex.plist"),
)
CLAUDE_SYSTEM_POLICY_PATHS = (
    Path("/Library/Application Support/ClaudeCode"), Path("/etc/claude-code"),
    MANAGED_PREFERENCES_ROOT / "com.anthropic.claude-code.plist",
    MANAGED_PREFERENCES_ROOT / "com.anthropic.claudecode.plist",
)
GIT_TIMEOUT_SECONDS = 60
PROBE_TIMEOUT_SECONDS = 30
PREPARATION_TIMEOUT_SECONDS = 300
POST_RUN_EVIDENCE_GRACE_SECONDS = 30
PRIVATE_CLEANUP_GRACE_SECONDS = 5
MAX_PROBE_OUTPUT_BYTES = 1024 * 1024
CLAUDE_BARE_PACKAGE_VERSION = "2.1.310"
CLI_PACKAGE_PINS = {
    "pi": ("@earendil-works/pi-coding-agent", "1.4.0"),
    "codex": ("@openai/codex", "0.165.0"),
    "claude": ("@anthropic-ai/claude-code", CLAUDE_BARE_PACKAGE_VERSION),
}


def _credential_wrapper(real: str, *, keep: frozenset[str], arguments: tuple[str, ...] = ()) -> bytes:
    """A deterministic shell wrapper that removes every non-role provider secret before exec."""
    remove = sorted(CREDENTIAL_ENV_ALLOWLIST - keep)
    lines = ["#!/bin/sh", "unset " + " ".join(remove)] if remove else ["#!/bin/sh"]
    argv = " ".join((shlex.quote(real), *(shlex.quote(argument) for argument in arguments), '"$@"'))
    lines.append("exec " + argv)
    return ("\n".join(lines) + "\n").encode("utf-8")


class DeadlineExpired(RuntimeError):
    pass


class Deadline:
    """One sticky monotonic budget for preparation or scan/evidence work.

    Invocation-private deletion deliberately uses a separate bounded security-cleanup grace after a
    sticky timeout; it must not be skipped merely because evidence work exhausted this deadline.
    """

    def __init__(self, seconds: float):
        self.started = time.monotonic()
        self.ends = self.started + max(float(seconds), 0.0)
        self.expired = False

    def remaining(self, cap: float | None = None) -> float:
        left = self.ends - time.monotonic()
        if left <= 0:
            self.expired = True
            raise DeadlineExpired("the shared adapter deadline expired")
        return min(left, cap) if cap is not None else left

    def check(self) -> None:
        self.remaining()


class RootGuard(NamedTuple):
    containment: Containment
    device: int
    inode: int
    fsid: int | None = None
    mount_id: str | None = None


class GitRepositoryGuard(NamedTuple):
    """Captured roots and immutable control files for the disposable repository's own Git store."""

    root: RootGuard
    directories: tuple[tuple[str, int, int], ...]
    protected_files: tuple[tuple[str, bytes | None], ...]


class FdTreeEntry(NamedTuple):
    """One entry observed through an anchored parent directory descriptor."""

    kind: str
    mode: int
    size: int
    device: int
    inode: int
    rdev: int
    target: str | None
    payload: Any = None


def _entry_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "char-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return "other"


def _valid_entry_name(name: str) -> bool:
    return bool(name) and name not in (".", "..") and "/" not in name and "\0" not in name


def _same_entry(left: os.stat_result, right: os.stat_result, *, contents: bool = False) -> bool:
    same = ((left.st_dev, left.st_ino, stat.S_IFMT(left.st_mode), stat.S_IMODE(left.st_mode))
            == (right.st_dev, right.st_ino, stat.S_IFMT(right.st_mode), stat.S_IMODE(right.st_mode)))
    if contents:
        same = (same and left.st_size == right.st_size
                and left.st_mtime_ns == right.st_mtime_ns and left.st_ctime_ns == right.st_ctime_ns)
    return same


def _fd_mount_id(descriptor: int) -> str | None:
    """Return Linux's mount id for an open fd; other supported POSIX hosts fall back to st_dev."""
    fd: int | None = None
    try:
        fd = os.open(f"/proc/self/fdinfo/{descriptor}", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        data = os.read(fd, 16 * 1024 + 1)
    except OSError:
        return None
    finally:
        if fd is not None:
            os.close(fd)
    if len(data) > 16 * 1024:
        return None
    for line in data.splitlines():
        if line.startswith(b"mnt_id:"):
            return line.split(b":", 1)[1].strip().decode("ascii", errors="strict")
    return None


def _fd_fsid(descriptor: int) -> int | None:
    """Return the filesystem id where the platform exposes it through ``fstatvfs``."""
    try:
        return getattr(os.fstatvfs(descriptor), "f_fsid", None)
    except OSError:
        return None


def _require_mount_identity(descriptor: int, *, root_device: int, root_fsid: int | None,
                            root_mount: str | None, relative: str) -> None:
    status = os.fstat(descriptor)
    if status.st_dev != root_device:
        raise OSError(errno.EXDEV, "tree crosses a filesystem boundary", relative)
    child_fsid = _fd_fsid(descriptor)
    if root_fsid is not None and child_fsid != root_fsid:
        raise OSError(errno.EXDEV, "tree crosses a filesystem-id boundary", relative)
    child_mount = _fd_mount_id(descriptor)
    if sys.platform.startswith("linux"):
        if root_mount is None or child_mount is None:
            raise OSError(errno.ENOTSUP, "Linux mount identity is unavailable", relative)
        if child_mount != root_mount:
            raise OSError(errno.EXDEV, "tree crosses a mount boundary", relative)
    elif root_mount is not None and child_mount is not None and child_mount != root_mount:
        raise OSError(errno.EXDEV, "tree crosses a mount boundary", relative)


def _open_absolute_directory(path: Path) -> int:
    """Open every component of one absolute directory without following any symbolic link."""
    if not path.is_absolute():
        raise OSError(errno.EINVAL, "directory path is not absolute", str(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(os.sep, flags)
    try:
        for component in path.parts[1:]:
            if not _valid_entry_name(component):
                raise OSError(errno.EINVAL, "directory path contains an invalid component", component)
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                try:
                    parent_mode = oct(os.fstat(descriptor).st_mode)
                except OSError:
                    parent_mode = "closed"
                raise OSError(exc.errno, f"could not anchor {path} at {component} (parent mode {parent_mode})",
                              component) from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_guarded_directory(path: Path, guard: RootGuard | None = None) -> tuple[int, os.stat_result]:
    # ``/var`` and similar OS-owned aliases may be symlinks on supported hosts. A captured guard
    # already carries the canonical root; use it while still refusing every link below that root.
    open_path = guard.containment.root if guard is not None else path
    descriptor = _open_absolute_directory(open_path)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISDIR(status.st_mode):
            raise OSError(errno.ENOTDIR, "tree root is not a directory", str(path))
        if guard is not None and (status.st_dev, status.st_ino) != (guard.device, guard.inode):
            raise OSError(errno.ESTALE, "tree root no longer matches its captured inode", str(path))
        if guard is not None and guard.fsid is not None and _fd_fsid(descriptor) != guard.fsid:
            raise OSError(errno.ESTALE, "tree root no longer matches its captured filesystem", str(path))
        if guard is not None and guard.mount_id is not None and _fd_mount_id(descriptor) != guard.mount_id:
            raise OSError(errno.ESTALE, "tree root no longer matches its captured mount", str(path))
        return descriptor, status
    except BaseException:
        os.close(descriptor)
        raise


def _read_fd_bytes(descriptor: int, status: os.stat_result, limit: int,
                   deadline: Deadline | None = None) -> bytes:
    if not stat.S_ISREG(status.st_mode) or status.st_size > limit:
        raise OSError(errno.EFBIG, f"regular file exceeds {limit} bytes")
    chunks: list[bytes] = []
    total = 0
    while True:
        if deadline:
            deadline.check()
        chunk = os.read(descriptor, 1 << 20)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise OSError(errno.EFBIG, f"regular file exceeds {limit} bytes")
        chunks.append(chunk)
    if total != status.st_size:
        raise OSError(errno.ESTALE, "regular file changed size while read")
    return b"".join(chunks)


def _fd_tree_snapshot(root: Path, guard: RootGuard | None, deadline: Deadline | None, *,
                      maximum: int, max_depth: int, regular_reader=None,
                      skip_top: frozenset[str] = frozenset(),
                      walk_issues: list[str] | None = None,
                      require_same_mount: bool = True) -> dict[str, FdTreeEntry]:
    """Walk a mutable tree only through anchored directory descriptors.

    Only the recursion-depth descriptor chain is retained. Every stat, open, and readlink is relative
    to the descriptor that produced the name, and every opened inode is rechecked before and after use.
    A parent replacement therefore fails the snapshot instead of redirecting a read outside *root*.
    """
    descriptor, root_before = _open_guarded_directory(root, guard)
    root_mount = _fd_mount_id(descriptor) if require_same_mount else None
    root_fsid = _fd_fsid(descriptor) if require_same_mount else None
    if require_same_mount and sys.platform.startswith("linux") and root_mount is None:
        os.close(descriptor)
        raise OSError(errno.ENOTSUP, "Linux mount identity is unavailable", str(root))
    observed: dict[str, FdTreeEntry] = {}
    count = 0

    def walk(directory_fd: int, prefix: tuple[str, ...], depth: int) -> None:
        nonlocal count
        if deadline:
            deadline.check()
        if depth > max_depth:
            raise OSError(errno.EOVERFLOW, "tree depth bound exceeded", str(root))
        directory_before = os.fstat(directory_fd)
        names: list[str] = []
        with os.scandir(directory_fd) as listing:
            for directory_entry in listing:
                if deadline:
                    deadline.check()
                name = directory_entry.name
                if not _valid_entry_name(name):
                    raise OSError(errno.EINVAL, "tree contains an invalid entry name", name)
                if not prefix and name in skip_top:
                    continue
                count += 1
                if count > maximum:
                    raise OSError(errno.EOVERFLOW, "tree entry bound exceeded", str(root))
                names.append(name)
        names.sort(key=os.fsencode)
        for name in names:
            if deadline:
                deadline.check()
            relative_parts = (*prefix, name)
            relative = "/".join(relative_parts)
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if require_same_mount and before.st_dev != root_before.st_dev:
                raise OSError(errno.EXDEV, "tree crosses a filesystem boundary", relative)
            kind = _entry_kind(before.st_mode)
            mode = stat.S_IMODE(before.st_mode)
            target: str | None = None
            payload = None
            if kind == "directory":
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                child_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if not _same_entry(before, opened):
                        raise OSError(errno.ESTALE, "directory changed while opened", relative)
                    if require_same_mount:
                        _require_mount_identity(
                            child_fd, root_device=root_before.st_dev, root_fsid=root_fsid,
                            root_mount=root_mount, relative=relative)
                    observed[relative] = FdTreeEntry(
                        kind, mode, opened.st_size, opened.st_dev, opened.st_ino, opened.st_rdev, None)
                    walk(child_fd, relative_parts, depth + 1)
                    after_fd = os.fstat(child_fd)
                    after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if not _same_entry(opened, after_fd, contents=True) or not _same_entry(opened, after_path):
                        raise OSError(errno.ESTALE, "directory changed or was replaced while walked", relative)
                finally:
                    os.close(child_fd)
                continue
            if kind == "regular":
                flags = (os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
                         | getattr(os, "O_CLOEXEC", 0))
                file_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(file_fd)
                    if not _same_entry(before, opened, contents=True):
                        raise OSError(errno.ESTALE, "regular file changed while opened", relative)
                    if require_same_mount:
                        _require_mount_identity(
                            file_fd, root_device=root_before.st_dev, root_fsid=root_fsid,
                            root_mount=root_mount, relative=relative)
                    if regular_reader is not None:
                        payload = regular_reader(file_fd, opened, relative)
                    after_fd = os.fstat(file_fd)
                    after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if not _same_entry(opened, after_fd, contents=True) \
                            or not _same_entry(opened, after_path, contents=True):
                        raise OSError(errno.ESTALE, "regular file changed or was replaced while read", relative)
                finally:
                    os.close(file_fd)
            elif kind == "symlink":
                target = os.readlink(name, dir_fd=directory_fd)
                after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not _same_entry(before, after_path, contents=True):
                    raise OSError(errno.ESTALE, "symbolic link changed while read", relative)
            observed[relative] = FdTreeEntry(
                kind, mode, before.st_size, before.st_dev, before.st_ino, before.st_rdev, target, payload)
        directory_after = os.fstat(directory_fd)
        if not _same_entry(directory_before, directory_after, contents=True):
            raise OSError(errno.ESTALE, "directory changed while enumerated", "/".join(prefix) or str(root))

    try:
        try:
            walk(descriptor, (), 0)
            root_after = os.fstat(descriptor)
            if not _same_entry(root_before, root_after, contents=True):
                raise OSError(errno.ESTALE, "tree root changed while walked", str(root))
        except DeadlineExpired:
            raise
        except OSError as exc:
            if walk_issues is None:
                raise
            walk_issues.append(exc.strerror or str(exc))
        try:
            path_fd, path_status = _open_guarded_directory(root, guard)
            try:
                if not _same_entry(root_before, path_status, contents=True):
                    raise OSError(errno.ESTALE, "tree root pathname was replaced while walked", str(root))
            finally:
                os.close(path_fd)
        except OSError as exc:
            if walk_issues is None:
                raise
            walk_issues.append(exc.strerror or str(exc))
        return observed
    finally:
        os.close(descriptor)


def _open_snapshot_parent(root_fd: int, relative: str,
                          snapshot: dict[str, FdTreeEntry]) -> tuple[int, str]:
    """Reopen one captured parent chain without following links, retaining one fd per depth only."""
    parts = relative.split("/")
    if not parts or any(not _valid_entry_name(part) for part in parts):
        raise OSError(errno.EINVAL, "snapshot path is invalid", relative)
    descriptor = os.dup(root_fd)
    try:
        prefix: list[str] = []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        for component in parts[:-1]:
            prefix.append(component)
            expected = snapshot.get("/".join(prefix))
            if expected is None or expected.kind != "directory":
                raise OSError(errno.ESTALE, "snapshot parent is absent or no longer a directory", relative)
            child = os.open(component, flags, dir_fd=descriptor)
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino, stat.S_IMODE(opened.st_mode)) \
                    != (expected.device, expected.inode, expected.mode):
                os.close(child)
                raise OSError(errno.ESTALE, "snapshot parent was replaced", relative)
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _open_relative_parent(root: Path, guard: RootGuard | None, relative: str) -> tuple[int, str]:
    """Anchor a relative leaf's parent without following any component."""
    parts = relative.split("/")
    if not parts or any(not _valid_entry_name(part) for part in parts):
        raise OSError(errno.EINVAL, "relative path is invalid", relative)
    descriptor, root_status = _open_guarded_directory(root, guard)
    try:
        root_fsid = _fd_fsid(descriptor)
        root_mount = _fd_mount_id(descriptor)
        if sys.platform.startswith("linux") and root_mount is None:
            raise OSError(errno.ENOTSUP, "Linux mount identity is unavailable", relative)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        for component in parts[:-1]:
            child = os.open(component, flags, dir_fd=descriptor)
            opened = os.fstat(child)
            if not stat.S_ISDIR(opened.st_mode):
                os.close(child)
                raise OSError(errno.ENOTDIR, "relative parent is not a directory", relative)
            _require_mount_identity(
                child, root_device=root_status.st_dev, root_fsid=root_fsid,
                root_mount=root_mount, relative=relative)
            os.close(descriptor)
            descriptor = child
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _read_relative_regular(root: Path, guard: RootGuard | None, relative: str, limit: int,
                           deadline: Deadline | None = None) -> bytes:
    effective_guard = guard or _capture_root(root)
    parent_fd, name = _open_relative_parent(root, effective_guard, relative)
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        flags = (os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        if not _same_entry(before, opened, contents=True):
            raise OSError(errno.ESTALE, "relative regular file changed while opened", relative)
        _require_mount_identity(
            descriptor, root_device=effective_guard.device, root_fsid=effective_guard.fsid,
            root_mount=effective_guard.mount_id, relative=relative)
        data = _read_fd_bytes(descriptor, opened, limit, deadline)
        after_fd = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_entry(opened, after_fd, contents=True) \
                or not _same_entry(opened, after_path, contents=True):
            raise OSError(errno.ESTALE, "relative regular file changed while read", relative)
        return data
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _capture_root(path: Path) -> RootGuard:
    status = os.lstat(path)
    if not stat.S_ISDIR(status.st_mode):
        raise AdapterError(f"{path} is not a private directory")
    containment = Containment.capture(path)
    descriptor = _open_absolute_directory(containment.root)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (status.st_dev, status.st_ino):
            raise OSError(errno.ESTALE, "captured root changed while opened", str(path))
        mount_id = _fd_mount_id(descriptor)
        if sys.platform.startswith("linux") and mount_id is None:
            raise OSError(errno.ENOTSUP, "Linux mount identity is unavailable", str(path))
        return RootGuard(containment, opened.st_dev, opened.st_ino, _fd_fsid(descriptor), mount_id)
    finally:
        os.close(descriptor)


def _capture_child_root(parent: Path, parent_guard: RootGuard, name: str) -> RootGuard:
    """Capture one literal child via its already-canonical parent without resolving the child."""
    if not _valid_entry_name(name):
        raise OSError(errno.EINVAL, "child root name is invalid", name)
    parent_fd, _parent_status = _open_guarded_directory(parent, parent_guard)
    child_fd: int | None = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        child_fd = os.open(name, flags, dir_fd=parent_fd)
        status = os.fstat(child_fd)
        if not stat.S_ISDIR(status.st_mode):
            raise OSError(errno.ENOTDIR, "child root is not a directory", name)
        parent_status = os.fstat(parent_fd)
        parent_fsid = _fd_fsid(parent_fd)
        parent_mount = _fd_mount_id(parent_fd)
        _require_mount_identity(
            child_fd, root_device=parent_status.st_dev, root_fsid=parent_fsid,
            root_mount=parent_mount, relative=name)
        canonical = parent_guard.containment.root / name
        return RootGuard(Containment(parent / name, canonical), status.st_dev, status.st_ino,
                         _fd_fsid(child_fd), _fd_mount_id(child_fd))
    finally:
        if child_fd is not None:
            os.close(child_fd)
        os.close(parent_fd)


def _root_intact(path: Path, guard: RootGuard) -> bool:
    try:
        status = os.lstat(path)
    except OSError:
        return False
    return (stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode)
            and (status.st_dev, status.st_ino) == (guard.device, guard.inode)
            and guard.containment.contains(path) == guard.containment.root)


def _cleanup_private(root: Path, guard: RootGuard, deadline: Deadline, *,
                     maximum: int = MAX_PRIVATE_CLEANUP_ENTRIES) -> str | None:
    """Delete only captured inodes through dirfds; a replaced parent can never redirect cleanup."""
    if not os.path.lexists(root):
        return "the captured private root pathname is missing; its inode may have been renamed and was not cleaned"
    try:
        entries = _fd_tree_snapshot(
            root, guard, deadline, maximum=maximum, max_depth=MAX_PRIVATE_DEPTH)
        root_fd, root_status = _open_guarded_directory(root, guard)
        try:
            ordered = sorted(entries.items(),
                             key=lambda item: (item[0].count("/"), os.fsencode(item[0])), reverse=True)
            for relative, expected in ordered:
                deadline.check()
                parent_fd, name = _open_snapshot_parent(root_fd, relative, entries)
                try:
                    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    current_identity = (current.st_dev, current.st_ino, _entry_kind(current.st_mode),
                                        stat.S_IMODE(current.st_mode))
                    expected_identity = (expected.device, expected.inode, expected.kind, expected.mode)
                    if current_identity != expected_identity:
                        raise OSError(errno.ESTALE, "private entry was replaced before cleanup", relative)
                    if expected.kind == "directory":
                        os.rmdir(name, dir_fd=parent_fd)
                    else:
                        os.unlink(name, dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
            deadline.check()
            if not _same_entry(root_status, os.fstat(root_fd)):
                raise OSError(errno.ESTALE, "private root changed during cleanup", str(root))
        finally:
            os.close(root_fd)
        canonical_root = guard.containment.root
        parent_fd = _open_absolute_directory(canonical_root.parent)
        try:
            current = os.stat(canonical_root.name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (guard.device, guard.inode) \
                    or not stat.S_ISDIR(current.st_mode):
                raise OSError(errno.ESTALE, "private root was replaced before removal", str(root))
            os.rmdir(canonical_root.name, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    except DeadlineExpired:
        return "the shared adapter deadline expired before bounded private cleanup completed"
    except OSError as exc:
        return f"bounded private cleanup stopped: {exc.strerror or str(exc)}"[:500]
    return None


class Route(NamedTuple):
    agent: str
    model: str
    reasoning_effort: str | None

    def native(self) -> dict[str, str | None]:
        return {"agent": self.agent, "model": self.model, "reasoning_effort": self.reasoning_effort}


class Settings(NamedTuple):
    """The validated system configuration. Nothing in it is a secret: credentials are named, never held."""

    root: Path
    configured_root: str
    expected_commit: str
    expected_version: str
    expected_dist_tree_sha256: str
    engine_model: str
    primary: Route
    challenger: Route
    minimum_severity: str
    work_budget: dict | None
    credential_env: dict[str, str]


def _route(value: Any, label: str, allowed: tuple[str, ...]) -> Route:
    if not isinstance(value, dict) or not set(value) <= ROUTE_KEYS or not {"agent", "model"} <= set(value):
        raise AdapterError(f"config.{label} must be {{agent, model[, reasoning_effort]}} and nothing else")
    agent, model, effort = value["agent"], value["model"], value.get("reasoning_effort")
    if agent not in allowed:
        raise AdapterError(f"config.{label}.agent must be one of {', '.join(allowed)}")
    if not isinstance(model, str) or not _ROUTE.match(model):
        raise AdapterError(f"config.{label}.model must be a model route name")
    if effort is not None:
        if not AGENT_EFFORTS[agent]:
            raise AdapterError(f"config.{label}.reasoning_effort: {agent} exposes no enforceable reasoning-effort control")
        if effort not in AGENT_EFFORTS[agent]:
            raise AdapterError(f"config.{label}.reasoning_effort must be one of {', '.join(AGENT_EFFORTS[agent])} for {agent}")
    return Route(agent, model, effort)


def _work_budget(value: Any) -> dict | None:
    """``parseWorkBudget`` of the pinned config.ts, refusing what it refuses and nothing looser."""
    if value is None:
        return None
    if not isinstance(value, dict) or not set(value) <= {"version", "maxElapsedMs", "maxModelFiles", "modelCalls"}:
        raise AdapterError("config.work_budget must be {version, maxElapsedMs?, maxModelFiles?, modelCalls?}")
    if value.get("version") != 1:
        raise AdapterError("config.work_budget.version must be 1")
    budget: dict[str, Any] = {"version": 1}
    for key in ("maxElapsedMs", "maxModelFiles"):
        if key in value:
            limit = value[key]
            if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
                raise AdapterError(f"config.work_budget.{key} must be a positive integer")
            budget[key] = limit
    calls = value.get("modelCalls")
    if calls is not None:
        if not isinstance(calls, dict) or not set(calls) <= set(BUDGET_ROLES):
            raise AdapterError(f"config.work_budget.modelCalls roles must be among {', '.join(BUDGET_ROLES)}")
        for role, limit in calls.items():
            if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
                raise AdapterError(f"config.work_budget.modelCalls.{role} must be a non-negative integer")
        if calls:
            budget["modelCalls"] = dict(calls)
    if len(budget) == 1:
        raise AdapterError("config.work_budget must define at least one enforceable limit")
    return budget


def read_settings(config: dict) -> Settings:
    """Validate a system configuration strictly; an unknown key or an inline value is refused, not ignored."""
    stray = sorted(set(config) - CONFIG_KEYS)
    if stray:
        raise AdapterError(f"config has unknown key(s) {', '.join(stray)}; runsortie accepts only "
                           f"{', '.join(sorted(CONFIG_KEYS))} (credentials are named by credential_env, never inlined)")
    configured_root = config.get("root")
    if not isinstance(configured_root, str) or not configured_root.strip():
        raise AdapterError("config.root (the RunSortie checkout) is required")
    commit = config.get("expected_commit")
    if not isinstance(commit, str) or not evidence.HEX40.match(commit):
        raise AdapterError("config.expected_commit must be the exact 40-hex RunSortie commit")
    if commit != SUPPORTED_RUNSORTIE_COMMIT:
        raise AdapterError(f"runsortie adapter 0.1.0 supports only RunSortie commit {SUPPORTED_RUNSORTIE_COMMIT}")
    version = config.get("expected_version")
    if not isinstance(version, str) or not _VERSION.match(version):
        raise AdapterError("config.expected_version must be the exact RunSortie package version")
    if version != SUPPORTED_RUNSORTIE_VERSION:
        raise AdapterError(f"runsortie adapter 0.1.0 supports only RunSortie package version {SUPPORTED_RUNSORTIE_VERSION}")
    dist_digest = config.get("expected_dist_tree_sha256")
    if not isinstance(dist_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", dist_digest):
        raise AdapterError("config.expected_dist_tree_sha256 must pin the observed dist/ tree as sha256:<64 lowercase hex>")
    engine_model = config.get("engine_model")
    if not isinstance(engine_model, str) or not _ROUTE.match(engine_model):
        raise AdapterError("config.engine_model (the Fieldglass --llm-model route) is required")
    if engine_model.startswith("claude:"):
        raise AdapterError(
            "config.engine_model may not select Fieldglass's direct claude: driver: the pinned invocation "
            "does not expose an enforceable empty-tool policy; v1 supports the hardened Pi engine route only")
    pi_model = engine_model[3:] if engine_model.startswith("pi:") and len(engine_model) > 3 else engine_model
    if pi_model == "openai-codex" or pi_model.startswith("openai-codex/"):
        raise AdapterError(
            "config.engine_model may not select Pi's openai-codex provider: it is OAuth-only, while secure v1 "
            "uses an empty private Pi credential store and explicit environment credentials")
    primary = _route(config.get("primary"), "primary", AGENTS)
    challenger = _route(config.get("challenger"), "challenger", VERIFIER_AGENTS)
    if challenger.model == primary.model:
        raise AdapterError("config.challenger.model must differ from config.primary.model for cross-model review")
    severity = config.get("minimum_severity", "high")
    if severity not in SEVERITIES:
        raise AdapterError(f"config.minimum_severity must be one of {', '.join(SEVERITIES)}")
    credentials = config.get("credential_env")
    if not isinstance(credentials, dict) or set(credentials) != {"engine"} \
            or not isinstance(credentials.get("engine"), str):
        raise AdapterError(
            "config.credential_env must be exactly {engine: PROVIDER_SECRET_NAME}; direct-agent credentials "
            "are fixed by secure v1 and no values are inlined")
    refused = credentials["engine"] if credentials["engine"] not in CREDENTIAL_ENV_ALLOWLIST else None
    if refused:
        raise AdapterError(
            "config.credential_env.engine accepts one documented provider secret environment name "
            f"({', '.join(sorted(CREDENTIAL_ENV_ALLOWLIST))}); refused {refused}")
    root = Path(configured_root).expanduser()
    if not root.is_absolute():
        raise AdapterError("config.root must be an absolute path to the RunSortie checkout")
    return Settings(root.resolve(), configured_root, commit, version, dist_digest, engine_model, primary, challenger,
                    severity, _work_budget(config.get("work_budget")), dict(credentials))


def native_config(settings: Settings, *, repo: Path, branch: str) -> dict[str, Any]:
    """The RunSortie configuration one invocation runs with. Every security-relevant field is explicit."""
    verifier: dict[str, Any] = {"agent": settings.challenger.agent, "model": settings.challenger.model,
                                "minimumSeverity": settings.minimum_severity}
    if settings.challenger.reasoning_effort:
        verifier["reasoningEffort"] = settings.challenger.reasoning_effort
    config: dict[str, Any] = {
        "version": 1,
        "agent": settings.primary.agent,
        "agentModel": settings.primary.model,
        **({"agentReasoningEffort": settings.primary.reasoning_effort} if settings.primary.reasoning_effort else {}),
        "verifier": verifier,
        "targets": [{"name": TARGET, "repo": str(repo), "branch": branch, "scopeHints": [],
                     "outputPaths": [evidence.EVIDENCE_ROOT], "commitResults": True, "pushResults": False}],
        "schedule": {"enabled": False, "expression": "0 2 * * *"},
        "engine": {"source": ENGINE_SOURCE, "ref": "bundled", "localPath": str(settings.root / "fieldglass"),
                   "model": settings.engine_model},
    }
    if settings.work_budget is not None:
        config["workBudget"] = settings.work_budget
    return config


# --- runtime identity ------------------------------------------------------------------------

def _sha256(path: Path, deadline: Deadline | None = None) -> str:
    digest = hashlib.sha256()
    parent_guard = _capture_root(path.parent)
    parent_fd, name = _open_relative_parent(path.parent, parent_guard, path.name)
    descriptor: int | None = None
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=parent_fd)
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or not _same_entry(before, status, contents=True):
            raise OSError(f"{path} is not a no-follow regular file")
        while True:
            if deadline:
                deadline.check()
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        if not _same_entry(status, os.fstat(descriptor), contents=True) \
                or not _same_entry(status, os.stat(name, dir_fd=parent_fd, follow_symlinks=False), contents=True):
            raise OSError(errno.ESTALE, f"{path} changed or was replaced while hashed")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)
    return "sha256:" + digest.hexdigest()


def _canonical_runtime_path() -> str:
    """Return an absolute directory-only PATH whose meaning cannot depend on a child cwd."""
    raw = os.environ.get("PATH")
    entries = raw.split(os.pathsep) if raw is not None else []
    if not entries or any(not entry or not Path(entry).is_absolute() for entry in entries):
        raise AdapterError("PATH must contain only nonempty absolute directory entries for a pinned RunSortie run")
    canonical: list[str] = []
    try:
        for entry in entries:
            try:
                resolved = Path(entry).resolve(strict=True)
            except FileNotFoundError:
                # Shell lookup ignores an absent absolute PATH entry; omitting it preserves that meaning
                # while making the PATH handed to children canonical and cwd-independent.
                continue
            if not resolved.is_dir():
                continue
            value = str(resolved)
            if value not in canonical:
                canonical.append(value)
    except OSError as exc:
        raise AdapterError(f"PATH could not be canonicalized for a pinned RunSortie run: {exc}") from exc
    if not canonical:
        raise AdapterError("PATH contains no existing absolute directory entries")
    return os.pathsep.join(canonical)


def _hermetic_git(cwd: Path, *args: str, git_dir: Path | None = None,
                  deadline: Deadline | None = None) -> subprocess.CompletedProcess:
    """One git command that runs no program a repository's configuration names and writes nothing.

    ``--no-optional-locks`` keeps ``git status`` from refreshing the index, so checking the operator's
    RunSortie checkout never writes into it.
    """
    prefix = ["--no-optional-locks", "-c", "core.fsmonitor=false",
              *([f"--git-dir={git_dir}"] if git_dir is not None else [])]
    argv, env = git_command([*prefix, *args])
    runtime_path = _canonical_runtime_path()
    git_executable = shutil.which(argv[0], path=runtime_path)
    if git_executable is None or not Path(git_executable).is_absolute():
        raise AdapterError("git is not resolvable through the canonical absolute PATH")
    argv[0] = git_executable
    env = {**env, "PATH": runtime_path, "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1"}
    process: subprocess.Popen | None = None
    output = {"stdout": bytearray(), "stderr": bytearray()}

    def stop_group() -> None:
        # The group can still contain a helper after its leader has been reaped.  Probe by signalling
        # the group itself, not by treating the leader's return code as proof that the group is empty.
        if process is None:
            return
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            # macOS can report EPERM for a reaped session leader whose group no longer exists.  If the
            # leader is in fact still live, retain the direct-child kill as a bounded fallback.
            if process.poll() is None:
                process.kill()

    try:
        timeout = deadline.remaining(GIT_TIMEOUT_SECONDS) if deadline else GIT_TIMEOUT_SECONDS
        ends = time.monotonic() + timeout
        process = subprocess.Popen(argv, cwd=str(cwd), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
            raise OSError("Git output pipes were not created")
        selector = selectors.DefaultSelector()
        try:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = ends - time.monotonic()
                if remaining <= 0:
                    stop_group()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired as exc:
                        raise AdapterError(f"git {args[0]} process group could not be stopped after timeout") from exc
                    if deadline is not None:
                        deadline.remaining()
                    raise AdapterError(f"git {args[0]} exceeded {GIT_TIMEOUT_SECONDS} seconds")
                for key, _events in selector.select(min(remaining, 0.1)):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 1 << 16)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total = len(output["stdout"]) + len(output["stderr"])
                    available = MAX_GIT_OUTPUT_BYTES - total
                    if len(chunk) > available:
                        if available > 0:
                            output[key.data].extend(chunk[:available])
                        stop_group()
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired as exc:
                            raise AdapterError(f"git {args[0]} process group could not be stopped after output overflow") from exc
                        raise AdapterError(
                            f"git {args[0]} output exceeded the {MAX_GIT_OUTPUT_BYTES}-byte bound")
                    output[key.data].extend(chunk)
            remaining = ends - time.monotonic()
            if remaining <= 0:
                stop_group()
                process.wait(timeout=1)
                if deadline is not None:
                    deadline.remaining()
                raise AdapterError(f"git {args[0]} exceeded {GIT_TIMEOUT_SECONDS} seconds")
            return subprocess.CompletedProcess(argv, process.wait(timeout=remaining), bytes(output["stdout"]),
                                               bytes(output["stderr"]))
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
    except DeadlineExpired:
        stop_group()
        if process is not None:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        raise
    except AdapterError:
        raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        stop_group()
        if process is not None:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        raise AdapterError(f"git {args[0]} could not be run: {exc}") from exc


def _linux_group_has_live_descendant(pgid: int, deadline: float) -> bool | None:
    """Inspect Linux procfs for a non-zombie member other than the reserved group leader.

    ``killpg`` alone cannot distinguish a lingering descendant from kernels that allow signalling an
    exited-but-unreaped leader.  Procfs is already required for Linux mount-id safety; an unavailable
    or malformed view is therefore an indeterminate result and preparation fails closed.
    """
    if not sys.platform.startswith("linux"):
        return None
    scanned = 0
    try:
        with os.scandir("/proc") as listing:
            for entry in listing:
                if time.monotonic() >= deadline:
                    return None
                if not entry.name.isdecimal():
                    continue
                scanned += 1
                if scanned > 262_144:
                    return None
                try:
                    descriptor = os.open(
                        f"/proc/{entry.name}/stat", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
                    try:
                        raw = os.read(descriptor, 8193)
                    finally:
                        os.close(descriptor)
                except OSError:
                    continue
                if len(raw) > 8192:
                    return None
                closing = raw.rfind(b")")
                if closing < 0:
                    return None
                fields = raw[closing + 2:].split()
                if len(fields) < 3:
                    return None
                try:
                    pid = int(entry.name)
                    process_group = int(fields[2])
                except ValueError:
                    return None
                if pid != pgid and process_group == pgid and fields[0] != b"Z":
                    return True
    except OSError:
        return None
    return False


def _probe(executable: str, *args: str, env: dict[str, str] | None = None,
           cwd: Path | None = None, timeout_seconds: float = PROBE_TIMEOUT_SECONDS) -> str | None:
    """Run one bounded, group-cleaned capability probe and return its complete text output."""
    process: subprocess.Popen | None = None
    try:
        process = subprocess.Popen(
            [executable, *args], cwd=str(cwd) if cwd else None, env=env or build_env(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        if process.stdout is None or process.stderr is None:  # pragma: no cover - Popen contract
            return None
        selector = selectors.DefaultSelector()
        output = bytearray()
        ends = time.monotonic() + timeout_seconds
        try:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = ends - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired([executable, *args], timeout_seconds)
                for key, _events in selector.select(min(remaining, 0.1)):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 1 << 15)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if len(output) + len(chunk) > MAX_PROBE_OUTPUT_BYTES:
                        raise OSError(errno.EOVERFLOW, "capability probe output bound exceeded")
                    output.extend(chunk)
            remaining = ends - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired([executable, *args], timeout_seconds)
            if not _wait_for_unreaped_exit(process.pid, remaining):
                raise subprocess.TimeoutExpired([executable, *args], timeout_seconds)
            live_descendant = _linux_group_has_live_descendant(process.pid, ends)
            signalled = _signal_reserved_process_group(process.pid, signal.SIGTERM)
            if signalled:
                time.sleep(0.1)
            _signal_reserved_process_group(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            if not _process_group_absent_after_reap(process.pid, 1.0):
                return None
            if (live_descendant is None and sys.platform.startswith("linux")) \
                    or live_descendant is True or (live_descendant is None and signalled):
                return None
            return output.decode("utf-8", errors="replace") if process.returncode == 0 else None
        finally:
            selector.close()
            process.stdout.close()
            process.stderr.close()
    except ChildProcessError:
        # A SIGCHLD handler or another waiter already reaped the reserved leader.  Its numeric PID
        # and PGID are free for reuse, so signalling or waiting by that number could target an
        # unrelated process.  Preparation fails closed without attempting numeric-id cleanup.
        return None
    except (OSError, subprocess.TimeoutExpired):
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        return None


def _executable(name: str, deadline: Deadline | None = None, *, runtime_path: str | None = None) -> dict[str, str]:
    """The executable *name* resolves to on this PATH, at path-and-digest assurance only."""
    found = shutil.which(name, path=runtime_path or _canonical_runtime_path())
    if found is None or not Path(found).is_absolute():
        raise AdapterError(f"{name} is not on PATH; RunSortie resolves it there and this adapter installs nothing")
    real = Path(found).resolve()
    return {"path": found, "realpath": str(real), "sha256": _sha256(real, deadline)}


def _fixed_executable(path: Path, label: str, deadline: Deadline | None = None) -> dict[str, str]:
    """Identity for an absolute executable path placed directly in a child-process setting."""
    try:
        status = os.lstat(path)
        if not stat.S_ISREG(status.st_mode) or not os.access(path, os.X_OK):
            raise OSError(f"{path} is not a no-follow executable regular file")
        real = path.resolve(strict=True)
    except OSError as exc:
        raise AdapterError(f"{label} is unavailable: {exc}") from exc
    return {"path": str(path), "realpath": str(real), "sha256": _sha256(real, deadline)}


def _absent_agent_system_policy(selected_agents: set[str]) -> dict[str, Any]:
    """Refuse host-admin policy layers that private HOME variables do not redirect."""
    try:
        username = pwd.getpwuid(os.getuid()).pw_name
    except (KeyError, OSError) as exc:
        raise AdapterError(f"the OS account name needed for managed-policy checks is unavailable: {exc}") from exc
    candidates: list[tuple[str, Path]] = []
    if "codex" in selected_agents:
        candidates.extend(("Codex", path) for path in CODEX_SYSTEM_POLICY_PATHS)
        candidates.extend(("Codex", MANAGED_PREFERENCES_ROOT / username / name) for name in (
            "com.openai.codex.plist", "com.openai.codex"))
    if "claude" in selected_agents:
        candidates.extend(("Claude", path) for path in CLAUDE_SYSTEM_POLICY_PATHS)
        candidates.extend(("Claude", MANAGED_PREFERENCES_ROOT / username / name) for name in (
            "com.anthropic.claude-code.plist", "com.anthropic.claudecode.plist"))
    checked: list[str] = []
    for agent, path in candidates:
        try:
            os.lstat(path)
        except FileNotFoundError:
            checked.append(str(path))
            continue
        except OSError as exc:
            raise AdapterError(f"{agent} system/managed policy path could not be proven absent ({path}): {exc}") from exc
        raise AdapterError(
            f"{agent} system/managed policy is present at {path}; secure v1 refuses policy, hooks, plugins, "
            "or routing outside the invocation-private home")
    return {"selected_agents": sorted(selected_agents), "checked_absent": checked,
            "assurance": "known Codex/Claude system and managed policy paths were absent by no-follow lstat"}


def _json_file(path: Path, label: str, deadline: Deadline | None = None) -> dict:
    try:
        if deadline:
            deadline.check()
        parent_guard = _capture_root(path.parent)
        data = _read_relative_regular(path.parent, parent_guard, path.name, MAX_IDENTITY_JSON_BYTES, deadline)
        value = json.loads(data.decode("utf-8"))
    except AdapterError:
        raise
    except (OSError, UnicodeDecodeError, ValueError, MaterializationError) as exc:
        raise AdapterError(f"{label} could not be read: {exc}") from exc
    if not isinstance(value, dict):
        raise AdapterError(f"{label} is not a JSON object")
    return value


def _inside(path: Path, root: Path) -> Path:
    real = path.resolve()
    if real != root and root not in real.parents:
        raise AdapterError(f"{path} resolves outside the RunSortie checkout")
    return real


def _tree_symlink_destination(relative: str, target: str,
                              entries: dict[str, FdTreeEntry], deadline: Deadline | None,
                              memo: dict[str, str | None]) -> str | None:
    """Resolve one captured internal link lexically through the captured map, never through the OS."""
    def resolve_link(link: str, stack: frozenset[str], hops: int) -> str | None:
        if deadline:
            deadline.check()
        if hops >= MAX_DEPENDENCY_SYMLINK_HOPS:
            return None
        if link in memo:
            return memo[link]
        if link in stack:
            memo[link] = None
            return None
        entry = entries.get(link)
        if entry is None or entry.kind != "symlink" or entry.target is None:
            return link if entry is not None else None
        resolved = resolve_candidate(
            posixpath.join(posixpath.dirname(link), entry.target), stack | {link}, hops + 1)
        memo[link] = resolved
        return resolved

    def resolve_candidate(candidate: str, stack: frozenset[str], hops: int) -> str | None:
        if deadline:
            deadline.check()
        if candidate.startswith("/"):
            return None
        candidate = posixpath.normpath(candidate)
        if candidate in ("", ".") or candidate == ".." or candidate.startswith("../"):
            return None
        parts = candidate.split("/")
        for index in range(1, len(parts) + 1):
            if deadline:
                deadline.check()
            prefix = "/".join(parts[:index])
            entry = entries.get(prefix)
            if entry is None or entry.kind != "symlink":
                continue
            expanded = resolve_link(prefix, stack, hops)
            if expanded is None:
                return None
            return resolve_candidate(posixpath.join(expanded, *parts[index:]), stack, hops)
        return candidate if candidate in entries else None

    if relative in memo:
        return memo[relative]
    destination = resolve_candidate(
        posixpath.join(posixpath.dirname(relative), target), frozenset({relative}), 1)
    memo[relative] = destination
    return destination


def _installed_tree_identity(root: Path, label: str, deadline: Deadline | None = None) -> dict[str, Any]:
    """Bounded no-follow identity of every installed dependency path and byte."""
    total = 0

    def digest_file(descriptor: int, status: os.stat_result, relative: str) -> tuple[int, str]:
        nonlocal total
        if status.st_size > MAX_DEPENDENCY_FILE_BYTES or total + status.st_size > MAX_DEPENDENCY_TOTAL_BYTES:
            raise AdapterError(f"{label} exceeds its installed byte bound")
        digest = hashlib.sha256()
        size = 0
        while True:
            if deadline:
                deadline.check()
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_DEPENDENCY_FILE_BYTES or total + size > MAX_DEPENDENCY_TOTAL_BYTES:
                raise AdapterError(f"{label} exceeds its installed byte bound")
            digest.update(chunk)
        if size != status.st_size:
            raise AdapterError(f"{label} file {relative} changed size while read")
        total += size
        return size, digest.hexdigest()

    try:
        root_guard = _capture_root(root)
        root_fd, root_status = _open_guarded_directory(root, root_guard)
        os.close(root_fd)
        snapshot = _fd_tree_snapshot(
            root, root_guard, deadline, maximum=MAX_DEPENDENCY_ENTRIES,
            max_depth=MAX_DEPENDENCY_DEPTH, regular_reader=digest_file)
    except AdapterError:
        raise
    except OSError as exc:
        raise AdapterError(f"{label} could not be walked: {exc}") from exc
    records: list[tuple[bytes, bytes]] = []
    files = links = 0
    link_memo: dict[str, str | None] = {}
    for name, entry in snapshot.items():
        relative = os.fsencode(name)
        if entry.kind == "symlink":
            if entry.target is None or _tree_symlink_destination(
                    name, entry.target, snapshot, deadline, link_memo) is None:
                raise AdapterError(f"{label} symlink {name} leaves or dangles outside the dependency tree")
            links += 1
            detail = b"symlink\0" + oct(entry.mode).encode("ascii") + b"\0" + os.fsencode(entry.target)
        elif entry.kind == "directory":
            detail = b"directory\0" + oct(entry.mode).encode("ascii")
        elif entry.kind == "regular":
            files += 1
            size, file_digest = entry.payload
            detail = (b"regular\0" + oct(entry.mode).encode("ascii") + b"\0"
                      + str(size).encode("ascii") + b"\0" + file_digest.encode("ascii"))
        else:
            raise AdapterError(f"{label} contains a special file at {name}")
        records.append((relative, detail))
    digest = hashlib.sha256()
    for relative, detail in sorted(records):
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative + b"\0" + detail + b"\n")
    return {"root": str(root), "root_mode": oct(stat.S_IMODE(root_status.st_mode)),
            "entries": len(snapshot), "files": files, "symlinks": links, "bytes": total,
            "tree_sha256": "sha256:" + digest.hexdigest()}


def _npm_launcher_identity(name: str, deadline: Deadline | None = None, *,
                           runtime_path: str | None = None) -> dict[str, Any]:
    """Bind a selected CLI to the complete npm package tree that supplies its launcher."""
    executable = _executable(name, deadline, runtime_path=runtime_path)
    real = Path(executable["realpath"])
    package_root: Path | None = None
    package: dict[str, Any] | None = None
    candidate = real.parent
    for _ in range(MAX_NPM_PACKAGE_ANCESTORS):
        manifest = candidate / "package.json"
        try:
            metadata = os.lstat(manifest)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise AdapterError(f"{name} npm package metadata could not be inspected: {exc}") from exc
        else:
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise AdapterError(f"{name} npm package.json is not a no-follow regular file")
            parsed = _json_file(manifest, f"{name} npm package.json", deadline)
            bin_field = parsed.get("bin")
            mapped = bin_field.get(name) if isinstance(bin_field, dict) else bin_field
            if isinstance(mapped, str) and mapped:
                relative = Path(mapped)
                if relative.is_absolute() or ".." in relative.parts:
                    raise AdapterError(f"{name} npm launcher mapping leaves its package root")
                try:
                    mapped_real = (candidate / relative).resolve(strict=True)
                except OSError as exc:
                    raise AdapterError(f"{name} npm launcher mapping cannot be resolved: {exc}") from exc
                if mapped_real == real and (real == candidate or candidate in real.parents):
                    package_root, package = candidate, parsed
                    break
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    if package_root is None or package is None:
        raise AdapterError(f"{name} is not supplied by a bounded discoverable npm package")
    tree = _installed_tree_identity(package_root, f"{name} npm package", deadline)
    return {**executable, "package_name": package.get("name"), "package_version": package.get("version"),
            "package_root": str(package_root), "package_tree": tree,
            "assurance": "launcher path plus every package path, mode, symlink target and regular-file byte is hashed"}


def _fieldglass_identity(root: Path, deadline: Deadline | None = None) -> dict[str, Any]:
    """The installed bundled Fieldglass RunSortie will run as ``engine.localPath``, without running it.

    Required files and the complete installed dependency tree are hashed, and every package the npm
    hidden lockfile says is installed must carry the version ``package-lock.json`` pins, with every
    non-optional pinned package installed.
    """
    engine = root / "fieldglass"
    required = {name: engine / name for name in ("package.json", "package-lock.json", "src/runtime/cli.ts",
                                                 "node_modules/.package-lock.json", "node_modules/tsx/package.json",
                                                 "node_modules/.bin/tsx")}
    missing = [name for name, path in required.items() if not path.exists()]
    if missing:
        raise AdapterError("the bundled Fieldglass is not installed in the RunSortie checkout; missing "
                           + ", ".join(missing) + " (this adapter never installs it)")
    for path in required.values():
        if not _inside(path, root).is_file():
            raise AdapterError(f"{path} is not a regular file")
    package = _json_file(required["package.json"], "fieldglass/package.json", deadline)
    if package.get("name") != "@runsortie/fieldglass" or not isinstance(package.get("scripts"), dict) \
            or package["scripts"].get("runtime") != "tsx src/runtime/cli.ts":
        raise AdapterError("fieldglass/package.json is not the bundled engine RunSortie runs with `npm run runtime`")
    pinned = _json_file(required["package-lock.json"], "fieldglass/package-lock.json", deadline).get("packages")
    installed = _json_file(required["node_modules/.package-lock.json"],
                           "fieldglass/node_modules/.package-lock.json", deadline).get("packages")
    if not isinstance(pinned, dict) or not isinstance(installed, dict):
        raise AdapterError("the Fieldglass lockfiles carry no package inventory")
    drift = sorted(key for key, entry in installed.items() if key and (
        not isinstance(entry, dict) or not isinstance(pinned.get(key), dict) or entry.get("version") != pinned[key].get("version")))
    absent = sorted(key for key, entry in pinned.items()
                    if key and isinstance(entry, dict) and not entry.get("optional") and key not in installed)
    if drift or absent or "node_modules/tsx" not in installed:
        raise AdapterError("the installed Fieldglass dependencies differ from its package-lock.json: "
                           + ", ".join((drift + absent)[:5] or ["tsx is not installed"]))
    launcher = required["node_modules/.bin/tsx"]
    launcher_real = _inside(launcher, root)
    dependency_tree = _installed_tree_identity(engine / "node_modules", "fieldglass/node_modules", deadline)
    return {"local_path": str(engine), "package_version": package.get("version"),
            "package_lock_sha256": _sha256(required["package-lock.json"], deadline),
            "installed_lock_sha256": _sha256(required["node_modules/.package-lock.json"], deadline),
            "runtime_cli_sha256": _sha256(required["src/runtime/cli.ts"], deadline),
            "tsx_launcher": {"path": str(launcher),
                             "symlink_target": os.readlink(launcher) if launcher.is_symlink() else None,
                             "realpath": str(launcher_real), "sha256": _sha256(launcher_real, deadline)},
            "tsx_version": _json_file(required["node_modules/tsx/package.json"], "tsx/package.json", deadline).get("version"),
            "installed_packages": len([key for key in installed if key]),
            "node_modules_tree": dependency_tree,
            "assurance": "every fieldglass/node_modules path, mode, symlink target and regular-file byte is hashed; "
                         "installed package versions also match package-lock.json"}


def _dist_identity(root: Path, deadline: Deadline | None = None) -> dict[str, Any]:
    dist = root / "dist"
    files: list[tuple[str, str]] = []

    def digest_file(descriptor: int, status: os.stat_result, relative: str) -> str:
        digest = hashlib.sha256()
        total = 0
        while True:
            if deadline:
                deadline.check()
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        if total != status.st_size:
            raise OSError(errno.ESTALE, "dist file changed size while read", relative)
        return "sha256:" + digest.hexdigest()

    try:
        dist_guard = _capture_root(dist)
        dist_fd, dist_status = _open_guarded_directory(dist, dist_guard)
        os.close(dist_fd)
        snapshot = _fd_tree_snapshot(
            dist, dist_guard, deadline, maximum=MAX_DIST_FILES,
            max_depth=MAX_PRIVATE_DEPTH, regular_reader=digest_file)
    except OSError as exc:
        raise AdapterError(f"dist/ could not be read: {exc}") from exc
    cli_entry = snapshot.get("cli.js")
    if cli_entry is None or cli_entry.kind != "regular":
        raise AdapterError("dist/cli.js is missing: the RunSortie checkout must already be built (this adapter never builds it)")
    for relative, entry in snapshot.items():
        if entry.kind == "directory":
            continue
        if entry.kind != "regular":
            raise AdapterError(f"dist/ holds a link or special file ({relative}); refused")
        files.append((relative, entry.payload))
    tree = hashlib.sha256("".join(f"{name}\0{digest}\n" for name, digest in sorted(files)).encode()).hexdigest()
    return {"root_mode": oct(stat.S_IMODE(dist_status.st_mode)),
            "cli_sha256": cli_entry.payload, "tree_sha256": "sha256:" + tree, "files": len(files),
            "assurance": "observed digest only; dist/ is ignored build output, not proven to be built from expected_commit"}


def _isolated_probe_identity(identity: dict[str, Any], selected_agents: set[str],
                             deadline: Deadline) -> dict[str, Any]:
    """Probe security flags under an empty private HOME/config with no provider credentials."""
    private = Path(tempfile.mkdtemp(prefix="scaneval-runsortie-probe-"))
    guard = _capture_root(private)
    result: dict[str, Any] | None = None
    failure: BaseException | None = None
    try:
        home, tmp = private / "home", private / "tmp"
        xdg_config, xdg_cache = home / ".config", home / ".cache"
        xdg_state, xdg_data = home / ".local/state", home / ".local/share"
        codex_home, claude_home = home / ".codex", home / ".claude"
        gemini_home, pi_home = home / ".gemini", home / ".pi/agent"
        npm_cache = private / "npm-cache"
        for directory in (home, tmp, xdg_config, xdg_cache, xdg_state, xdg_data, codex_home,
                          claude_home, gemini_home, pi_home, npm_cache):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
        _write_private_file(pi_home / "auth.json", b"{}")
        _write_private_file(pi_home / "models-store.json", b"{}")
        probe_shell = private / "scaneval-bash"
        _write_private_file(
            probe_shell, ("#!/bin/sh\nexec " + shlex.quote(str(AGENT_SHELL))
                          + ' --noprofile --norc "$@"\n').encode("utf-8"), mode=0o700)
        env = build_env((), {
            "PATH": identity["runtime_path"], "HOME": str(home), "TMPDIR": str(tmp),
            "LANG": "C", "LC_ALL": "C", "SHELL": str(probe_shell),
            "CLAUDE_CODE_SHELL": str(probe_shell), "CLAUDE_CODE_SAFE_MODE": "1",
            "XDG_CONFIG_HOME": str(xdg_config), "XDG_CACHE_HOME": str(xdg_cache),
            "XDG_STATE_HOME": str(xdg_state), "XDG_DATA_HOME": str(xdg_data),
            "CODEX_HOME": str(codex_home), "CLAUDE_CONFIG_DIR": str(claude_home),
            "GEMINI_CLI_HOME": str(gemini_home), "PI_CODING_AGENT_DIR": str(pi_home),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "NODE_OPTIONS": "", "npm_config_node_options": "", "npm_config_userconfig": os.devnull,
            "npm_config_globalconfig": os.devnull, "npm_config_script_shell": str(NPM_SCRIPT_SHELL),
            "npm_config_cache": str(npm_cache), "npm_config_offline": "true",
            "npm_config_update_notifier": "false", "NO_UPDATE_NOTIFIER": "1",
        })

        def output(executable: str, *args: str) -> str:
            value = _probe(executable, *args, env=env, cwd=private,
                           timeout_seconds=deadline.remaining(PROBE_TIMEOUT_SECONDS))
            if value is None:
                command = " ".join((Path(executable).name, *args))
                raise AdapterError(f"the isolated {command} probe failed")
            return value

        versions = {
            "node": output(identity["node"]["path"], "--version").strip().splitlines()[0][:200],
            "npm": output(identity["npm"]["path"], "--version").strip().splitlines()[0][:200],
            "git": output(identity["git"]["path"], "--version").strip().splitlines()[0][:200],
            "pi": output(identity["engine_driver"]["realpath"], "--version").strip().splitlines()[0][:200],
        }
        for agent in sorted(selected_agents):
            versions[agent] = output(identity["agents"][agent]["realpath"], "--version").strip().splitlines()[0][:200]
        pi_help = output(identity["engine_driver"]["realpath"], "--help")
        pi_flags = {flag: flag in pi_help for flag in PI_ISOLATION_FLAGS}
        if not all(pi_flags.values()):
            missing = ", ".join(flag for flag, present in pi_flags.items() if not present)
            raise AdapterError(f"the selected Pi CLI does not expose required isolation flag(s): {missing}")
        capabilities: dict[str, Any] = {
            "probeEnvironment": "invocation-private-empty-home-with-no-credentials",
            "pi": {"allIsolationFlags": True, "flags": pi_flags},
        }
        if "codex" in selected_agents:
            codex = identity["agents"]["codex"]["realpath"]
            login_help = output(codex, "login", "--help")
            status_help = output(codex, "login", "status", "--help")
            codex_capabilities = {"loginWithApiKey": "--with-api-key" in login_help,
                                  "loginStatus": bool(status_help.strip())}
            if not all(codex_capabilities.values()):
                raise AdapterError("the selected Codex CLI lacks login --with-api-key or login status capability")
            capabilities["codex"] = codex_capabilities
        if "claude" in selected_agents:
            claude_identity = identity["agents"]["claude"]
            if (claude_identity.get("package_name") != "@anthropic-ai/claude-code"
                    or claude_identity.get("package_version") != CLAUDE_BARE_PACKAGE_VERSION):
                raise AdapterError(f"secure v1 Claude --bare requires package version {CLAUDE_BARE_PACKAGE_VERSION}")
            claude_help = output(claude_identity["realpath"], "--help").lower()
            claude_capabilities = {
                "bare": "--bare" in claude_help, "bareSkipsHooks": "hook" in claude_help,
                "bareSkipsPlugins": "plugin" in claude_help,
                "bareIgnoresOauth": "oauth" in claude_help or "keychain" in claude_help,
                "bareUsesApiKey": "api key" in claude_help or "api-key" in claude_help,
            }
            if not all(claude_capabilities.values()):
                raise AdapterError("the selected Claude CLI help does not prove secure-v1 --bare semantics")
            capabilities["claude"] = claude_capabilities
        result = {"versions": versions, "capabilities": capabilities}
    except BaseException as exc:
        failure = exc
    cleanup = _cleanup_private(private, guard, Deadline(PRIVATE_CLEANUP_GRACE_SECONDS))
    if cleanup:
        raise AdapterError(f"the isolated capability-probe home could not be safely cleaned: {cleanup}") from failure
    if failure is not None:
        raise failure
    assert result is not None
    return result


def runtime_identity(settings: Settings, *, probe_versions: bool, deadline: Deadline | None = None) -> dict[str, Any]:
    """Every identity the run depends on, each at the assurance it really has.

    Refused, never substituted: a missing or unbuilt checkout, a HEAD other than ``expected_commit``, any
    tracked-byte mismatch or Git-status-visible change, a package version other than ``expected_version``, an engine that is
    not installed, and a tool not on PATH. Versions are probed only during preparation; re-checks compare
    paths and digests.
    """
    selected_agents = {settings.primary.agent, settings.challenger.agent}
    system_policy = _absent_agent_system_policy(selected_agents)
    root = settings.root
    runtime_path = _canonical_runtime_path()
    if not root.is_dir():
        raise AdapterError(f"RunSortie root does not exist: {root}")
    for name in ("package.json", "package-lock.json", "skills/security-review/SKILL.md", "node_modules"):
        if not (root / name).is_file():
            if name != "node_modules" or not (root / name).is_dir():
                raise AdapterError(f"the RunSortie checkout has no {name}")
    checkout = _verified_runtime_checkout(root, settings.expected_commit, deadline)
    git_head = checkout["commit"]
    package = _json_file(root / "package.json", "package.json", deadline)
    lock = _json_file(root / "package-lock.json", "package-lock.json", deadline)
    if package.get("name") != "runsortie" or package.get("version") != settings.expected_version:
        raise AdapterError(f"package.json is {package.get('name')}@{package.get('version')}, not runsortie@{settings.expected_version}")
    if (lock.get("packages") or {}).get("", {}).get("version") != settings.expected_version:
        raise AdapterError("package-lock.json does not pin the expected RunSortie version")
    dist_identity = _dist_identity(root, deadline)
    if dist_identity["tree_sha256"] != settings.expected_dist_tree_sha256:
        raise AdapterError("the observed dist/ tree digest does not equal config.expected_dist_tree_sha256")
    engine_driver = "claude" if settings.engine_model.startswith("claude:") and len(settings.engine_model) > 7 else "pi"
    root_dependencies = _installed_tree_identity(root / "node_modules", "runsortie/node_modules", deadline)
    identity: dict[str, Any] = {
        "runsortie": {"root": str(root), "configured_root": settings.configured_root, "git_head": git_head,
                      "expected_commit": settings.expected_commit, "git_status_clean": True,
                      "tree_oid": checkout["tree_oid"], "tracked_leaves": checkout["tracked_leaves"],
                      "tracked_bytes": checkout["tracked_bytes"],
                      "tracked_manifest_sha256": checkout["tracked_manifest_sha256"],
                      "package_version": package.get("version"),
                      "package_lock_sha256": _sha256(root / "package-lock.json", deadline),
                      "assurance": "commit/tree objects and every tracked worktree leaf match expected_commit; "
                                   "Git status reports no tracked or non-ignored untracked change"},
        "dist": dist_identity,
        "runsortie_node_modules": root_dependencies,
        "fieldglass": _fieldglass_identity(root, deadline),
        "runtime_path": runtime_path,
        "agent_system_policy": system_policy,
        "engine_driver": {"driver": engine_driver,
                          **_npm_launcher_identity(engine_driver, deadline, runtime_path=runtime_path)},
        "node": _executable("node", deadline, runtime_path=runtime_path),
        "npm": _npm_launcher_identity("npm", deadline, runtime_path=runtime_path),
        "npm_script_shell": _fixed_executable(NPM_SCRIPT_SHELL, "the pinned npm script shell", deadline),
        "agent_shell": _fixed_executable(AGENT_SHELL, "the pinned agent command shell", deadline),
        "git": _executable("git", deadline, runtime_path=runtime_path),
        "agents": {agent: _npm_launcher_identity(AGENT_BINARIES[agent], deadline, runtime_path=runtime_path)
                   for agent in sorted(selected_agents)},
    }
    pinned_identities = {"pi": identity["engine_driver"],
                         **{agent: identity["agents"][agent] for agent in selected_agents}}
    for role, selected in pinned_identities.items():
        expected_name, expected_version = CLI_PACKAGE_PINS[role]
        if (selected.get("package_name"), selected.get("package_version")) != (expected_name, expected_version):
            raise AdapterError(
                f"secure v1 requires {role} from {expected_name}@{expected_version}; observed "
                f"{selected.get('package_name')}@{selected.get('package_version')}")
    if probe_versions:
        probes = _isolated_probe_identity(
            identity, selected_agents, deadline or Deadline(PREPARATION_TIMEOUT_SECONDS))
        identity["node"]["version"] = probes["versions"]["node"]
        node_match = re.fullmatch(r"v?(\d+)\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?",
                                  identity["node"]["version"] or "")
        if node_match is None or int(node_match.group(1)) < 22:
            raise AdapterError("RunSortie and its bundled Fieldglass require a readable Node.js version >=22")
        identity["npm"]["version"] = probes["versions"]["npm"]
        identity["git"]["version"] = probes["versions"]["git"]
        identity["engine_driver"]["version"] = probes["versions"]["pi"]
        for agent in selected_agents:
            identity["agents"][agent]["version"] = probes["versions"][agent]
        identity["probe_capabilities"] = probes["capabilities"]
    return identity


def _without_versions(identity: dict) -> dict:
    def strip(value):
        if isinstance(value, dict):
            return {key: strip(item) for key, item in value.items() if key != "version"}
        if isinstance(value, list):
            return [strip(item) for item in value]
        return value

    return strip(identity)


# --- bounded reads and create-only writes ----------------------------------------------------

class Read(NamedTuple):
    data: bytes | None
    failure: str | None             # set when something is there but could not be read as a regular file

    @property
    def parsed_input(self) -> bytes | None:
        """What a reader is handed: ``None`` for absent, bytes that cannot parse for a refused read."""
        return b"" if self.failure else self.data


class EvidenceEntry(NamedTuple):
    kind: str                       # directory | regular | symlink | special
    mode: int
    data: bytes | None              # regular bytes, or a symlink target encoded with os.fsencode
    failure: str | None = None


class EvidenceSnapshot(NamedTuple):
    entries: dict[str, EvidenceEntry]  # paths relative to .fieldglass; directories included
    complete: bool
    issues: tuple[str, ...]

    def regular(self, relative: str) -> bytes | None:
        entry = self.entries.get(relative)
        return entry.data if entry is not None and entry.kind == "regular" and entry.failure is None else None

    def git_entries(self) -> dict[str, tuple[str, str]] | None:
        if not self.complete:
            return None
        found: dict[str, tuple[str, str]] = {}
        for relative, entry in self.entries.items():
            path = f"{evidence.EVIDENCE_ROOT}/{relative}"
            if entry.kind == "directory":
                continue
            if entry.kind == "regular" and entry.data is not None and entry.failure is None:
                git_mode = "100755" if entry.mode & 0o111 else "100644"
                found[path] = (f"file-{git_mode}", _blob_id(entry.data))
            elif entry.kind == "symlink" and entry.data is not None:
                found[path] = ("link", _blob_id(entry.data))
            else:
                return None
        return found


def read_bounded(path: Path, contained: Path | None, limit: int, deadline: Deadline | None = None) -> Read:
    """Read one scanner-owned file without following a link, blocking on a pipe, or exceeding *limit*."""
    if contained is None:
        return Read(None, "it does not resolve inside the directory this run gave it")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return Read(None, None)
    except OSError as exc:
        return Read(None, "it is a symbolic link" if exc.errno == errno.ELOOP else (exc.strerror or str(exc)))
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            return Read(None, "it is not a regular file")
        if status.st_size > limit:
            return Read(None, f"it exceeds {limit} bytes")
        chunks, total = [], 0
        while True:
            if deadline:
                deadline.check()
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                return Read(None, f"it exceeds {limit} bytes")
            chunks.append(chunk)
        return Read(b"".join(chunks), None)
    except OSError as exc:
        return Read(None, exc.strerror or str(exc))
    finally:
        os.close(descriptor)


def _primary_prompt(settings: Settings, evaluated: str, deadline: Deadline) -> bytes:
    """Reconstruct the exact pinned primary prompt from the verified packaged skill."""
    skill_path = settings.root / "skills" / "security-review" / "SKILL.md"
    read = read_bounded(skill_path, skill_path, MAX_PACKAGED_SKILL_BYTES, deadline)
    if read.data is None:
        raise AdapterError(f"the packaged security-review skill could not be read: {read.failure or 'absent'}")
    try:
        skill = read.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AdapterError("the packaged security-review skill is not UTF-8") from exc
    prompt = evidence.build_scan_prompt(
        skill=skill, target=TARGET, source_revision=evaluated,
        minimum_severity=settings.minimum_severity, verifier_configured=True,
        scope_hints=(), output_paths=(evidence.EVIDENCE_ROOT,))
    encoded = prompt.encode("utf-8")
    if len(encoded) > MAX_PRIMARY_PROMPT_BYTES:
        raise AdapterError("the exact primary review prompt exceeds the adapter's preservation bound")
    return encoded


def write_new(path: Path, data: bytes, staging: Containment, deadline: Deadline | None = None) -> str | None:
    """Create *path* inside staging; never overwrite/follow/block, and propagate the shared deadline."""
    if staging.contains(path) is None or staging.contains(path.parent) is None:
        return "the destination does not resolve inside this run's raw output"
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if staging.contains(path.parent) is None:
            return "the destination directory left this run's raw output"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), 0o600)
        status = os.fstat(descriptor)
        created_identity = (status.st_dev, status.st_ino)
    except OSError as exc:
        return exc.strerror or str(exc)

    def discard_created() -> None:
        """Remove only the inode this call created; never a path swapped in afterwards."""
        try:
            current = os.lstat(path)
            if created_identity == (current.st_dev, current.st_ino):
                os.unlink(path)
        except OSError:
            pass

    try:
        if deadline:
            deadline.check()
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(data)
    except DeadlineExpired:
        if descriptor is not None:
            os.close(descriptor)
        discard_created()
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        discard_created()
        return exc.strerror or str(exc)
    return None


def _write_private_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create one adapter-owned private input without following or replacing anything."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _import_runsortie_findings(snapshot: EvidenceSnapshot, stage_dir: Path, enclosure: Enclosure,
                               deadline: Deadline) -> HarnessImport:
    """Import finding records only from the already preserved evidence snapshot."""
    claims: list[dict] = []
    artifacts: list[dict] = []
    notes: list[str] = []
    losses: list[LostRecord] = []

    def lose(name: str, finding_id: str | None, reason: str) -> None:
        loss = LostRecord(name, finding_id, reason)
        losses.append(loss)
        notes.append(loss.note)

    finding_root = snapshot.entries.get("findings")
    if finding_root is None:
        return HarnessImport(claims, artifacts, ["no findings directory was written by RunSortie"], ())
    if finding_root.kind != "directory":
        lose("findings", None, "the findings path is not a plain directory in the preserved snapshot")
        return HarnessImport(claims, artifacts, notes, tuple(losses))
    names = [relative[len("findings/"):]
             for relative in snapshot.entries
             if relative.startswith("findings/") and "/" not in relative[len("findings/"):]]
    if len(names) > MAX_STATE_FILES:
        lose("findings", None, f"the findings directory exceeds the {MAX_STATE_FILES}-entry import bound")
        return HarnessImport(claims, artifacts, notes, tuple(losses))

    total = 0
    markdown = sorted(name for name in names if name.endswith(".md"))
    for index, name in enumerate(markdown):
        path = Path(name)
        try:
            deadline.check()
        except DeadlineExpired:
            lose(name, None, f"the shared deadline expired with {len(markdown) - index} finding record(s) unimported")
            break
        entry = snapshot.entries.get(f"findings/{name}")
        if entry is None or entry.kind != "regular" or entry.data is None or entry.failure:
            reason = entry.failure if entry is not None else "absent from the evidence snapshot"
            lose(name, None, f"finding record could not be read ({reason or 'not a regular file'}); not imported")
            continue
        data = entry.data
        total += len(data)
        if total > MAX_STATE_TOTAL_BYTES:
            lose(name, None, f"finding records exceed the {MAX_STATE_TOTAL_BYTES}-byte total import bound")
            break
        text = data.decode("utf-8", errors="replace")
        record, body = parse_frontmatter(text)
        finding_id = str(record.get("id") or "")
        if not finding_id:
            lose(name, None, "no id in frontmatter; not imported")
            continue
        file_path = str(record.get("file_path") or "").replace("\\", "/")
        if file_path.startswith("./"):
            file_path = file_path[2:]
        if (not file_path or "\0" in file_path or file_path.startswith("/")
                or re.match(r"^[A-Za-z]:/", file_path) or ".." in file_path.split("/")):
            lose(name, finding_id, f"unusable file_path {file_path!r}; not imported, see the raw finding record")
            continue
        destination = stage_dir / name
        try:
            failure = write_new(destination, data, enclosure.staging, deadline)
        except DeadlineExpired:
            lose(name, finding_id, f"the shared deadline expired with {len(markdown) - index} finding record(s) unimported")
            break
        if failure:
            lose(name, finding_id, f"finding record could not be staged ({failure}); not imported")
            continue
        vulnerability_class = str(record.get("vulnerability_class") or "")
        title = str(record.get("title") or path.stem)
        reasoning = body.split("## Reasoning", 1)[1].strip() if "## Reasoning" in body else body.strip()
        claim: dict[str, Any] = {
            "claim_id": finding_id,
            "allegation": title,
            "kind": kind_for_harness_class(vulnerability_class),
            "primary_location": {"path": file_path},
            "native_id": finding_id,
            "native_rule_id": f"fieldglass:{vulnerability_class or 'unknown'}",
            "raw_artifact_id": f"runsortie-findings/{name}",
        }
        site, site_error = _native_scan_site(record)
        if site_error:
            notes.append(f"{finding_id}: {site_error}; location kept file-level")
        if site is not None:
            line = site.get("line")
            if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                claim["primary_location"].update(start_line=line, end_line=line)
            elif line is not None:
                notes.append(f"{finding_id}: scan site line is not a positive integer; location kept file-level")
            for source, destination_key in (("sourceSymbol", "native_source_symbol"),
                                            ("sinkSymbol", "native_sink_symbol")):
                value = site.get(source)
                if isinstance(value, str) and value.strip():
                    claim[destination_key] = value
        if reasoning and reasoning != "N/A":
            claim["evidence_text"] = reasoning
        severity = record.get("severity")
        if isinstance(severity, str) and severity:
            claim["native_severity"] = severity
        claims.append(claim)
        artifacts.append({"id": claim["raw_artifact_id"], "path": destination})
    return HarnessImport(claims, artifacts, notes, tuple(losses))


# --- the evaluated repository ----------------------------------------------------------------

_GIT_PROTECTED_FILES = ("HEAD", "config", "packed-refs", "shallow")
_GIT_GUARDED_DIRECTORIES = ("objects", "refs", "logs", "info")


def _git_control_file(git: Path, root: RootGuard, relative: str, deadline: Deadline | None) -> bytes | None:
    """Read one small Git control file without following a scanner-planted link."""
    try:
        if deadline:
            deadline.check()
        return _read_relative_regular(git, root, relative, MAX_RECEIPT_BYTES, deadline)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AdapterError(f"the workspace .git/{relative} could not be inspected: {exc}") from exc


def _walk_plain_git_tree(git: Path, root: RootGuard, relative: str,
                         deadline: Deadline | None, expected: tuple[int, int] | None = None) -> None:
    """Refuse every link or special entry in a Git metadata subtree before plumbing follows it."""
    start = git / relative
    try:
        start_guard = _capture_child_root(git, root, relative)
        if expected is not None and (start_guard.device, start_guard.inode) != expected:
            raise OSError(errno.ESTALE, "Git metadata root was replaced", relative)
        snapshot = _fd_tree_snapshot(
            start, start_guard, deadline, maximum=MAX_GIT_METADATA_ENTRIES, max_depth=MAX_PRIVATE_DEPTH)
    except FileNotFoundError as exc:
        if expected is None:
            return
        raise AdapterError(f"the captured workspace .git/{relative} directory disappeared") from exc
    except OSError as exc:
        raise AdapterError(f"the workspace .git/{relative} could not be fd-safely walked: {exc}") from exc
    for name, entry in snapshot.items():
        if entry.kind not in ("directory", "regular"):
            raise AdapterError(f"the workspace .git/{relative}/{name} is a link or special file")


def _capture_git_repository(source: Path, deadline: Deadline | None = None) -> GitRepositoryGuard:
    git = source / ".git"
    try:
        root = _capture_root(git)
    except OSError as exc:
        raise AdapterError(f"the workspace .git could not be inspected: {exc.strerror or exc}") from exc
    directories: list[tuple[str, int, int]] = []
    for relative in _GIT_GUARDED_DIRECTORIES:
        path = git / relative
        if not os.path.lexists(path):
            if relative in ("objects", "refs"):
                raise AdapterError(f"the workspace .git/{relative} directory is missing")
            continue
        try:
            child_guard = _capture_child_root(git, root, relative)
        except OSError as exc:
            raise AdapterError(f"the workspace .git/{relative} is not a contained plain directory: {exc}") from exc
        directories.append((relative, child_guard.device, child_guard.inode))
        _walk_plain_git_tree(git, root, relative, deadline, (child_guard.device, child_guard.inode))
    protected = tuple((relative, _git_control_file(git, root, relative, deadline))
                      for relative in _GIT_PROTECTED_FILES)
    if dict(protected)["HEAD"] is None or dict(protected)["config"] is None:
        raise AdapterError("the workspace .git lacks a plain HEAD or config file")
    guard = GitRepositoryGuard(root, tuple(directories), protected)
    _git_dir(source, guard=guard, deadline=deadline)
    return guard


def _git_dir(source: Path, *, guard: GitRepositoryGuard | None = None,
             deadline: Deadline | None = None) -> Path:
    """The guarded in-workspace Git store, checked without following links before any plumbing."""
    if guard is None:
        return _capture_git_repository(source, deadline).root.containment.root
    git = source / ".git"
    if not _root_intact(git, guard.root):
        raise AdapterError("the workspace .git root was replaced after capture")
    for relative, device, inode in guard.directories:
        try:
            status = os.lstat(git / relative)
        except OSError as exc:
            raise AdapterError(f"the workspace .git/{relative} was removed after capture: {exc}") from exc
        if (not stat.S_ISDIR(status.st_mode) or stat.S_ISLNK(status.st_mode)
                or (status.st_dev, status.st_ino) != (device, inode)
                or guard.root.containment.contains(git / relative) is None):
            raise AdapterError(f"the workspace .git/{relative} root was replaced or redirected after capture")
    guarded = {relative: (device, inode) for relative, device, inode in guard.directories}
    for relative in _GIT_GUARDED_DIRECTORIES:
        _walk_plain_git_tree(git, guard.root, relative, deadline, guarded.get(relative))
    for redirect in ("commondir", "objects/info/alternates", "info/grafts", "refs/replace"):
        if os.path.lexists(git / redirect):
            raise AdapterError(f"the workspace .git/{redirect} can redirect object reads; it was refused")
    for relative, expected in guard.protected_files:
        if _git_control_file(git, guard.root, relative, deadline) != expected:
            raise AdapterError(f"the workspace .git/{relative} changed after capture")
    return git


def _git_object_id(kind: str, data: bytes) -> str:
    digest = hashlib.sha1(b"%s %d\0" % (kind.encode("ascii"), len(data)), usedforsecurity=False)
    digest.update(data)
    return digest.hexdigest()


class VerifiedGitTree(NamedTuple):
    tree: str
    parents: tuple[str, ...]
    entries: dict[bytes, tuple[str, str]]  # complete leaf path -> (Git mode, object id)


def _verified_git_object(source: Path, git: Path, kind: str, oid: str, deadline: Deadline | None) -> bytes:
    """Read one bounded SHA-1 Git object and independently verify its canonical object id."""
    if kind not in ("commit", "tree") or not evidence.HEX40.fullmatch(oid):
        raise AdapterError(f"invalid {kind} object id in evaluated history")
    result = _hermetic_git(source, "cat-file", kind, oid, git_dir=git, deadline=deadline)
    if result.returncode:
        raise AdapterError(f"Git {kind} object {oid} could not be read")
    data = bytes(result.stdout)
    if _git_object_id(kind, data) != oid:
        raise AdapterError(f"Git {kind} object {oid} does not hash to its object id")
    return data


def _verified_commit_tree(source: Path, git: Path, commit: str,
                          deadline: Deadline | None = None) -> VerifiedGitTree:
    """Verify a commit and every reachable tree object, then return its bounded leaf map.

    Blob contents are not read from the post-run object store.  Evaluated product blobs are instead
    bound to the clean pre-run worktree, and evidence blobs are bound to the preserved post-run
    evidence tree.  Thus no unverified blob payload can influence source lines or classification.
    """
    content = _verified_git_object(source, git, "commit", commit, deadline)
    header = content.split(b"\n\n", 1)[0]
    trees: list[str] = []
    parents: list[str] = []
    for line in header.splitlines():
        if line.startswith(b"tree "):
            trees.append(line[5:].decode("ascii", errors="replace"))
        elif line.startswith(b"parent "):
            parents.append(line[7:].decode("ascii", errors="replace"))
    if len(trees) != 1 or not evidence.HEX40.fullmatch(trees[0]) \
            or any(not evidence.HEX40.fullmatch(parent) for parent in parents):
        raise AdapterError(f"Git commit object {commit} has malformed tree or parent headers")

    parsed_cache: dict[str, tuple[tuple[bytes, str, str], ...]] = {}

    def parse_tree(oid: str) -> tuple[tuple[bytes, str, str], ...]:
        cached = parsed_cache.get(oid)
        if cached is not None:
            return cached
        raw = _verified_git_object(source, git, "tree", oid, deadline)
        offset = 0
        parsed: list[tuple[bytes, str, str]] = []
        names: set[bytes] = set()
        while offset < len(raw):
            if deadline:
                deadline.check()
            space = raw.find(b" ", offset)
            nul = raw.find(b"\0", space + 1 if space >= 0 else offset)
            if space <= offset or nul <= space + 1 or nul + 21 > len(raw):
                raise AdapterError(f"Git tree object {oid} has a malformed entry")
            mode = raw[offset:space].decode("ascii", errors="replace")
            name = raw[space + 1:nul]
            child = raw[nul + 1:nul + 21].hex()
            offset = nul + 21
            if (mode not in ("40000", "100644", "100755", "120000", "160000")
                    or not name or name in (b".", b"..") or b"/" in name or name in names):
                raise AdapterError(f"Git tree object {oid} has an unsupported or duplicate entry")
            names.add(name)
            parsed.append((name, mode, child))
            if len(parsed) > MAX_PRODUCT_ENTRIES:
                raise AdapterError("Git tree object exceeds the product entry bound")
        parsed_cache[oid] = tuple(parsed)
        return parsed_cache[oid]

    entries: dict[bytes, tuple[str, str]] = {}
    pending: list[tuple[bytes, str, int]] = [(b"", trees[0], 0)]
    while pending:
        if deadline:
            deadline.check()
        prefix, oid, depth = pending.pop()
        if depth > MAX_PRODUCT_DEPTH:
            raise AdapterError("Git commit tree exceeds the product depth bound")
        for name, mode, child in parse_tree(oid):
            path = prefix + (b"/" if prefix else b"") + name
            if mode == "40000":
                pending.append((path, child, depth + 1))
            else:
                entries[path] = (mode, child)
                if len(entries) > MAX_PRODUCT_ENTRIES:
                    raise AdapterError("Git commit tree exceeds the product entry bound")
    return VerifiedGitTree(trees[0], tuple(parents), entries)


def _verify_loose_evaluated_blobs(git: Path, guard: GitRepositoryGuard, verified: VerifiedGitTree,
                                  deadline: Deadline | None = None) -> None:
    """Stream/re-hash every loose blob named by the evaluated tree.

    Product and evidence semantics never use post-run blob payloads.  This additional check rejects
    the concrete loose-object overlay attack: a corrupt loose file shadows even an otherwise valid
    packed object under the same old object id.
    """
    object_ids = {oid for mode, oid in verified.entries.values() if mode in ("100644", "100755", "120000")}
    for oid in sorted(object_ids):
        if deadline:
            deadline.check()
        path = git / "objects" / oid[:2] / oid[2:]
        if not os.path.lexists(path):
            continue
        relative = f"objects/{oid[:2]}/{oid[2:]}"
        parent_fd: int | None = None
        descriptor: int | None = None
        try:
            parent_fd, name = _open_relative_parent(git, guard.root, relative)
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                                 dir_fd=parent_fd)
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or not _same_entry(before, status, contents=True):
                raise AdapterError(f"loose Git blob {oid} is not a regular object file")
            decompressor = zlib.decompressobj()
            digest = hashlib.sha1(usedforsecurity=False)
            header = bytearray()
            payload_size = total = 0
            declared: int | None = None

            def consume(output: bytes) -> None:
                nonlocal payload_size, total, declared
                if not output:
                    return
                total += len(output)
                if total > MAX_PRODUCT_FILE_BYTES + 128:
                    raise AdapterError(f"loose Git blob {oid} exceeds the product file bound")
                digest.update(output)
                if declared is None:
                    header.extend(output)
                    marker = header.find(b"\0")
                    if marker < 0:
                        if len(header) > 127:
                            raise AdapterError(f"loose Git blob {oid} has no bounded object header")
                        return
                    raw_header = bytes(header[:marker])
                    body = bytes(header[marker + 1:])
                    prefix, separator, raw_size = raw_header.partition(b" ")
                    if prefix != b"blob" or separator != b" " or not raw_size.isdigit():
                        raise AdapterError(f"loose Git blob {oid} has an invalid object header")
                    declared = int(raw_size)
                    if declared > MAX_PRODUCT_FILE_BYTES:
                        raise AdapterError(f"loose Git blob {oid} exceeds the product file bound")
                    payload_size += len(body)
                    header.clear()
                else:
                    payload_size += len(output)

            while True:
                if deadline:
                    deadline.check()
                chunk = os.read(descriptor, 1 << 16)
                if not chunk:
                    break
                pending = chunk
                while pending:
                    consume(decompressor.decompress(pending, 1 << 20))
                    pending = decompressor.unconsumed_tail
            consume(decompressor.flush(1 << 20))
            if (not decompressor.eof or decompressor.unused_data or declared is None
                    or payload_size != declared or digest.hexdigest() != oid):
                raise AdapterError(f"loose Git blob {oid} does not hash to its evaluated-tree object id")
            if not _same_entry(status, os.fstat(descriptor), contents=True) \
                    or not _same_entry(status, os.stat(name, dir_fd=parent_fd, follow_symlinks=False), contents=True):
                raise AdapterError(f"loose Git blob {oid} changed or was replaced while verified")
        except AdapterError:
            raise
        except (OSError, zlib.error, ValueError) as exc:
            raise AdapterError(f"loose Git blob {oid} could not be verified: {exc}") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if parent_fd is not None:
                os.close(parent_fd)


def _tracked_worktree_identity(root: Path, verified: VerifiedGitTree,
                               deadline: Deadline | None = None) -> dict[str, Any]:
    """Hash every tracked regular/symlink leaf and bind it to the verified commit tree."""
    try:
        worktree_guard = _capture_root(root)
    except OSError as exc:
        raise AdapterError(f"the tracked worktree root could not be captured: {exc}") from exc
    manifest = hashlib.sha256()
    total = 0
    for raw_path in sorted(verified.entries):
        if deadline:
            deadline.check()
        mode, expected_oid = verified.entries[raw_path]
        if mode == "160000":
            raise AdapterError("the pinned RunSortie checkout contains an unsupported gitlink")
        relative = os.fsdecode(raw_path)
        try:
            if mode == "120000":
                parent_fd, name = _open_relative_parent(root, worktree_guard, relative)
                try:
                    status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if not stat.S_ISLNK(status.st_mode):
                        raise AdapterError(f"tracked RunSortie path {relative} is not its committed symlink")
                    target = os.readlink(name, dir_fd=parent_fd)
                    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if not _same_entry(status, after, contents=True):
                        raise AdapterError(f"tracked RunSortie symlink {relative} changed while read")
                    oid = _blob_id(os.fsencode(target))
                finally:
                    os.close(parent_fd)
            elif mode in ("100644", "100755"):
                parent_fd, name = _open_relative_parent(root, worktree_guard, relative)
                try:
                    status = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                finally:
                    os.close(parent_fd)
                if not stat.S_ISREG(status.st_mode) or bool(status.st_mode & 0o111) != (mode == "100755"):
                    raise AdapterError(f"tracked RunSortie path {os.fsdecode(raw_path)} has the wrong kind or mode")
                if status.st_size > MAX_PRODUCT_FILE_BYTES or total + status.st_size > MAX_PRODUCT_TOTAL_BYTES:
                    raise AdapterError("the pinned RunSortie tracked tree exceeds its byte bound")
                data = _read_relative_regular(root, worktree_guard, relative, MAX_PRODUCT_FILE_BYTES, deadline)
                if total + len(data) > MAX_PRODUCT_TOTAL_BYTES:
                    raise AdapterError("the pinned RunSortie tracked tree exceeds its byte bound")
                oid = _blob_id(data)
                total += len(data)
            else:
                raise AdapterError(f"tracked RunSortie path {os.fsdecode(raw_path)} has unsupported mode {mode}")
        except AdapterError:
            raise
        except OSError as exc:
            raise AdapterError(f"tracked RunSortie path {os.fsdecode(raw_path)} could not be verified: {exc}") from exc
        if oid != expected_oid:
            raise AdapterError(f"tracked RunSortie path {os.fsdecode(raw_path)} does not match the pinned commit tree")
        manifest.update(len(raw_path).to_bytes(8, "big"))
        manifest.update(raw_path)
        manifest.update(b"\0" + mode.encode("ascii") + b"\0" + expected_oid.encode("ascii") + b"\n")
    return {"tree_oid": verified.tree, "tracked_leaves": len(verified.entries),
            "tracked_bytes": total, "tracked_manifest_sha256": "sha256:" + manifest.hexdigest()}


def _verified_runtime_checkout(root: Path, expected_commit: str,
                               deadline: Deadline | None = None) -> dict[str, Any]:
    """Prove the configured checkout's tracked bytes are exactly the af8f240 tree."""
    guard = _capture_git_repository(root, deadline)
    git = _git_dir(root, guard=guard, deadline=deadline)
    head = _hermetic_git(root, "rev-parse", "--verify", "HEAD^{commit}", git_dir=git, deadline=deadline)
    status = _hermetic_git(root, "status", "--porcelain", "--untracked-files=all", git_dir=git, deadline=deadline)
    object_format = _hermetic_git(root, "rev-parse", "--show-object-format", git_dir=git, deadline=deadline)
    commit = head.stdout.decode("ascii", errors="replace").strip() if head.returncode == 0 else ""
    if commit != expected_commit:
        raise AdapterError(f"RunSortie checkout is at {commit[:40]}, not expected_commit {expected_commit}")
    if status.returncode or status.stdout.strip():
        raise AdapterError("the RunSortie checkout has tracked or non-ignored untracked modifications; "
                           "a pinned run needs Git-status-clean inputs")
    if object_format.returncode or object_format.stdout.strip() != b"sha1":
        raise AdapterError("the RunSortie checkout does not use the pinned SHA-1 Git object format")
    verified = _verified_commit_tree(root, git, commit, deadline)
    _verify_loose_evaluated_blobs(git, guard, verified, deadline)
    identity = _tracked_worktree_identity(root, verified, deadline)
    _git_dir(root, guard=guard, deadline=deadline)
    return {"commit": commit, **identity}


def initial_repository(source: Path, deadline: Deadline | None = None) \
        -> tuple[str, str, GitRepositoryGuard, VerifiedGitTree]:
    """The evaluated head and branch, read before anything ran, with a clean tree required."""
    guard = _capture_git_repository(source, deadline)
    git = _git_dir(source, guard=guard, deadline=deadline)
    head = _hermetic_git(source, "rev-parse", "--verify", "HEAD^{commit}", git_dir=git, deadline=deadline)
    branch = _hermetic_git(source, "symbolic-ref", "--short", "HEAD", git_dir=git, deadline=deadline)
    status = _hermetic_git(source, "status", "--porcelain", "--untracked-files=all", git_dir=git, deadline=deadline)
    object_format = _hermetic_git(source, "rev-parse", "--show-object-format", git_dir=git, deadline=deadline)
    evaluated = head.stdout.decode("ascii", errors="replace").strip()
    name = branch.stdout.decode("utf-8", errors="replace").strip()
    if head.returncode or not evidence.HEX40.match(evaluated):
        raise AdapterError("the workspace has no readable HEAD commit to evaluate")
    if branch.returncode or not _BRANCH.match(name):
        raise AdapterError("the workspace HEAD is not on a branch RunSortie can name")
    if status.returncode or status.stdout.strip():
        raise AdapterError("the workspace is not a clean checkout of the evaluated head")
    if object_format.returncode or object_format.stdout.strip() != b"sha1":
        raise AdapterError("the workspace does not use the pinned SHA-1 Git object format")
    verified = _verified_commit_tree(source, git, evaluated, deadline)
    _verify_loose_evaluated_blobs(git, guard, verified, deadline)
    _git_dir(source, guard=guard, deadline=deadline)
    return evaluated, name, guard, verified


def product_tree(source: Path, deadline: Deadline | None = None,
                 guard: RootGuard | None = None) -> dict[str, tuple] | None:
    """Bounded inventory of every product path kind outside ``.git`` and ``.fieldglass``.

    Taken before launch and after exit, so a product change RunSortie's guard did not catch, committed
    or not, is this adapter's own ``product_mutation`` error rather than only the runner's later
    ``source_modified`` downgrade. ``None`` is a tree that could not be walked, which is not unchanged.
    """
    inventory: dict[str, tuple] = {}
    total_bytes = 0

    def digest_file(descriptor: int, status: os.stat_result, relative: str) -> tuple[str, int, str]:
        nonlocal total_bytes
        if status.st_size > MAX_PRODUCT_FILE_BYTES or total_bytes + status.st_size > MAX_PRODUCT_TOTAL_BYTES:
            raise OSError(errno.EFBIG, "product byte bound exceeded", relative)
        digest = hashlib.sha256()
        git_digest = hashlib.sha1(b"blob %d\0" % status.st_size, usedforsecurity=False)
        size = 0
        while True:
            if deadline:
                deadline.check()
            chunk = os.read(descriptor, 1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_PRODUCT_FILE_BYTES or total_bytes + size > MAX_PRODUCT_TOTAL_BYTES:
                raise OSError(errno.EFBIG, "product byte bound exceeded", relative)
            digest.update(chunk)
            git_digest.update(chunk)
        if size != status.st_size:
            raise OSError(errno.ESTALE, "product file changed size while read", relative)
        total_bytes += size
        return "sha256:" + digest.hexdigest(), size, git_digest.hexdigest()

    try:
        source_guard = guard or _capture_root(source)
        snapshot = _fd_tree_snapshot(
            source, source_guard, deadline, maximum=MAX_PRODUCT_ENTRIES, max_depth=MAX_PRODUCT_DEPTH,
            regular_reader=digest_file, skip_top=frozenset({".git", evidence.EVIDENCE_ROOT}))
        for relative, entry in snapshot.items():
            if entry.kind == "directory":
                inventory[relative] = ("directory", entry.mode)
            elif entry.kind == "symlink":
                target = entry.target or ""
                inventory[relative] = ("symlink", entry.mode, target, _blob_id(os.fsencode(target)))
            elif entry.kind == "regular":
                digest, size, git_digest = entry.payload
                inventory[relative] = ("regular", entry.mode, digest, size, git_digest)
            elif entry.kind in ("char-device", "block-device"):
                inventory[relative] = (entry.kind, entry.mode, entry.rdev)
            else:
                inventory[relative] = (entry.kind, entry.mode)
        return inventory
    except DeadlineExpired:
        raise
    except (OSError, ValueError):
        return None


def _product_matches_evaluated(product: dict[str, tuple], verified: VerifiedGitTree) -> bool:
    """Bind every tracked evaluated leaf to the independently hashed clean worktree bytes."""
    for raw_path, (git_mode, oid) in verified.entries.items():
        path = os.fsdecode(raw_path)
        record = product.get(path)
        if git_mode in ("100644", "100755"):
            expected_mode = git_mode == "100755"
            if (record is None or record[0] != "regular" or bool(record[1] & 0o111) != expected_mode
                    or len(record) < 5 or record[4] != oid):
                return False
        elif git_mode == "120000":
            if record is None or record[0] != "symlink" or len(record) < 4 or record[3] != oid:
                return False
        else:
            # A gitlink has no ordinary file bytes this local full-source adapter can bind.
            return False
    return True


def _blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


class HistoryRead(NamedTuple):
    evidence: evidence.GitEvidence
    manifest: bytes | None


def read_history(source: Path, evaluated: str, evaluated_tree: VerifiedGitTree,
                 evidence_snapshot: EvidenceSnapshot, git_guard: GitRepositoryGuard,
                 deadline: Deadline | None = None) -> HistoryRead:
    """Classify history only from independently rehashed commit/tree objects and local bytes.

    ``git diff-tree``, ``ls-tree`` and ``rev-list`` are deliberately not trusted: ordinary Git object
    reads do not verify that a loose or packed payload still hashes to the name its parent references.
    This reader hashes the canonical commit/tree object framing itself, parses the tree recursively,
    and joins evidence blob ids to no-follow working-tree bytes.
    """
    resolved: str | None = None
    try:
        git = _git_dir(source, guard=git_guard, deadline=deadline)
        head = _hermetic_git(source, "rev-parse", "--verify", "HEAD^{commit}", git_dir=git, deadline=deadline)
        resolved = head.stdout.decode("ascii", errors="replace").strip() if head.returncode == 0 else None
        if resolved is None or not evidence.HEX40.fullmatch(resolved):
            return HistoryRead(evidence.classify_commit(evaluated=evaluated, head=resolved, parents=None,
                                                        changed=None, worktree_matches=None), None)
        current_evaluated = _verified_commit_tree(source, git, evaluated, deadline)
        if current_evaluated != evaluated_tree:
            raise AdapterError("the evaluated commit/tree mapping changed after the scan")
        _verify_loose_evaluated_blobs(git, git_guard, current_evaluated, deadline)
        head_tree = current_evaluated if resolved == evaluated else _verified_commit_tree(source, git, resolved, deadline)
        _git_dir(source, guard=git_guard, deadline=deadline)
    except AdapterError as exc:
        return HistoryRead(evidence.GitEvidence("invalid", resolved, (), (str(exc)[:300],)), None)
    if resolved == evaluated:
        return HistoryRead(evidence.classify_commit(evaluated=evaluated, head=resolved, parents=None,
                                                    changed=None, worktree_matches=None), None)

    changed_raw = tuple(sorted(path for path in set(evaluated_tree.entries) | set(head_tree.entries)
                               if evaluated_tree.entries.get(path) != head_tree.entries.get(path)))

    def display(path: bytes) -> str:
        return path.decode("utf-8", errors="backslashreplace")

    changed = tuple(display(path) for path in changed_raw)
    committed_raw: dict[bytes, tuple[str, str]] = {}
    evidence_root = os.fsencode(evidence.EVIDENCE_ROOT)
    for path, (mode, oid) in head_tree.entries.items():
        if path != evidence_root and not path.startswith(evidence_root + b"/"):
            continue
        if mode not in ("100644", "100755", "120000"):
            return HistoryRead(evidence.GitEvidence(
                "invalid", resolved, changed, ("the verified evidence tree contains an unsupported object mode",)), None)
        committed_raw[path] = ("link" if mode == "120000" else f"file-{mode}", oid)
    # This is the same byte/mode map used for semantic parsing and raw artifacts. Never sample the
    # live worktree again: an escaped helper could otherwise swap receipts between those phases.
    worktree = evidence_snapshot.git_entries()
    worktree_raw = ({os.fsencode(path): value for path, value in worktree.items()}
                    if worktree is not None else None)
    matches = worktree_raw is not None and committed_raw == worktree_raw
    classified = evidence.classify_commit(evaluated=evaluated, head=resolved, parents=head_tree.parents,
                                          changed=changed, worktree_matches=matches)
    committed = {display(path): value for path, value in committed_raw.items()}

    def entries(values: dict[str, tuple[str, str]] | None) -> list[dict[str, str]] | None:
        if values is None:
            return None
        result = []
        for path, (kind, oid) in sorted(values.items()):
            record = {"path": path, "kind": kind, "oid": oid}
            if kind.startswith("file-") and path.startswith(evidence.EVIDENCE_ROOT + "/"):
                record["artifactId"] = "runsortie-evidence-tree/" + path[len(evidence.EVIDENCE_ROOT) + 1:]
            result.append(record)
        return result

    manifest_value = {
        "format": "scaneval-runsortie-git-evidence-v1",
        "evaluated": evaluated,
        "head": resolved,
        "parents": list(head_tree.parents),
        "objectFormat": "sha1",
        "evaluatedTree": evaluated_tree.tree,
        "headTree": head_tree.tree,
        "commitAndTreeObjectsRehashed": True,
        "changedPaths": list(changed),
        "committedEvidence": entries(committed),
        "worktreeEvidence": entries(worktree),
        "worktreeMatches": matches,
        "classification": {"state": classified.state, "head": classified.head,
                           "changed": list(classified.changed), "issues": list(classified.issues)},
    }
    manifest = (json.dumps(manifest_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return HistoryRead(classified, manifest)


def _snapshot_evidence_tree(root: Path, enclosure: Enclosure, raw: Path, register,
                            deadline: Deadline, source_guard: RootGuard | None = None) -> EvidenceSnapshot:
    """Read .fieldglass once; stage and judge only these exact bounded bytes and modes."""
    captured: dict[str, EvidenceEntry] = {}
    issues: list[str] = []
    total = 0

    def read_file(descriptor: int, status: os.stat_result, relative: str) -> tuple[bytes | None, str | None]:
        nonlocal total
        if status.st_size > MAX_RECEIPT_BYTES or total + status.st_size > MAX_STATE_TOTAL_BYTES:
            return None, "the per-file or total byte bound was reached"
        try:
            data = _read_fd_bytes(descriptor, status, MAX_RECEIPT_BYTES, deadline)
        except OSError as exc:
            return None, exc.strerror or str(exc)
        if total + len(data) > MAX_STATE_TOTAL_BYTES:
            return None, "the per-file or total byte bound was reached"
        total += len(data)
        return data, None

    try:
        if enclosure.read(root) is None:
            return EvidenceSnapshot({}, False, ("the .fieldglass evidence root is not a captured plain directory",))
        if source_guard is None:
            source_guard = _capture_root(enclosure.workspace.base)
        evidence_guard = _capture_child_root(enclosure.workspace.base, source_guard, evidence.EVIDENCE_ROOT)
        walk_issues: list[str] = []
        snapshot = _fd_tree_snapshot(
            root, evidence_guard, deadline, maximum=MAX_PRIVATE_ENTRIES, max_depth=MAX_PRIVATE_DEPTH,
            regular_reader=read_file, walk_issues=walk_issues)
        if walk_issues:
            issues.extend(f"the .fieldglass evidence tree walk failed closed ({issue})" for issue in walk_issues)
        files = sum(entry.kind == "regular" for entry in snapshot.values())
        if files > MAX_EVIDENCE_FILES:
            issues.append(f"the .fieldglass evidence tree exceeds {MAX_EVIDENCE_FILES} files")
        for relative, entry in snapshot.items():
            if entry.kind == "directory":
                captured[relative] = EvidenceEntry("directory", entry.mode, None)
            elif entry.kind == "symlink":
                captured[relative] = EvidenceEntry("symlink", entry.mode, os.fsencode(entry.target or ""))
                issues.append(f"native evidence {relative} is a symbolic link; it was not preserved")
            elif entry.kind == "regular":
                data, failure = entry.payload
                captured[relative] = EvidenceEntry("regular", entry.mode, data, failure)
                if failure:
                    issues.append(f"native evidence {relative} was not snapshotted ({failure})")
            else:
                captured[relative] = EvidenceEntry("special", entry.mode, None, "special file")
                issues.append(f"native evidence {relative} is a special file; it was not opened or preserved")
    except DeadlineExpired:
        raise
    except OSError as exc:
        issues.append(f"the .fieldglass evidence tree could not be boundedly snapshotted ({exc.strerror or exc})")

    for relative, entry in sorted(captured.items()):
        if entry.kind != "regular" or entry.data is None or entry.failure:
            continue
        if not register(f"runsortie-evidence-tree/{relative}",
                        raw / "runsortie-evidence-tree" / relative, entry.data):
            issues.append(f"native evidence {relative} could not be staged from the snapshot")
    return EvidenceSnapshot(captured, not issues, tuple(dict.fromkeys(issues)))


def source_reader(source: Path, product_before: dict[str, tuple], evaluated_tree: VerifiedGitTree,
                  enclosure: Enclosure, deadline: Deadline,
                  source_guard: RootGuard | None = None) -> Any:
    """Read source only from no-follow worktree bytes bound to the pre-run evaluated tree.

    The preflight independently matched every tracked worktree blob id to the verified evaluated
    commit tree.  This reader also checks the pre-run SHA-256/size for the requested path, so a
    scanner-planted replacement Git object can never supply security-argument source lines.
    """
    if source_guard is None:
        try:
            source_guard = _capture_root(source)
        except OSError:
            source_guard = None

    def read(path: str) -> bytes | None:
        try:
            deadline.check()
            if source_guard is None:
                return None
            expected = product_before.get(path)
            tracked = evaluated_tree.entries.get(os.fsencode(path))
            if expected is None or expected[0] != "regular" or len(expected) < 5 \
                    or expected[3] > evidence.MAX_SOURCE_EVIDENCE_BYTES or tracked is None \
                    or tracked[0] not in ("100644", "100755") or tracked[1] != expected[4]:
                return None
            if enclosure.read(source / path) is None:
                return None
            data = _read_relative_regular(
                source, source_guard, path, evidence.MAX_SOURCE_EVIDENCE_BYTES, deadline)
            if len(data) != expected[3] or "sha256:" + hashlib.sha256(data).hexdigest() != expected[2]:
                return None
            return data
        except (DeadlineExpired, OSError, ValueError):
            if deadline.expired:
                raise DeadlineExpired("the shared adapter deadline expired while reading source evidence")
            return None

    return read


# --- the adapter -----------------------------------------------------------------------------

class RunSortieAdapter(Adapter):
    name = "runsortie"
    adapter_version = "0.1.0"
    requires_git = True
    scan_modes = frozenset({"full"})
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})
    # Execution records describe the runner's possible offer statically. The exact one engine key
    # selected for an invocation is separately bound in preparation/config/isolation artifacts.
    env_passthrough = tuple(sorted(CREDENTIAL_ENV_ALLOWLIST))
    # RunSortie's own evidence root. Declared so the runner leaves it out of the watched input tree,
    # and refuses an input that ships one.  This adapter imports findings and receipts itself with
    # no-follow byte/entry/deadline bounds, so the runner's generic whole-tree capture is disabled;
    # malformed special files therefore cannot discard the claims already staged by the adapter.
    state_dirs = (evidence.EVIDENCE_ROOT,)
    state_capture_dirs = ()
    # Local, unenforced only: RunSortie, Node, npm, Git and the agent CLIs are host installs.
    oci_compatible = False

    def prepare(self, spec: SystemSpec, cache_root: Path) -> dict[str, Any]:
        settings = read_settings(spec.config)
        deadline = Deadline(PREPARATION_TIMEOUT_SECONDS)
        try:
            identity = runtime_identity(settings, probe_versions=True, deadline=deadline)
        except DeadlineExpired as exc:
            raise AdapterError(
                f"RunSortie preparation exceeded its {PREPARATION_TIMEOUT_SECONDS}-second monotonic bound") from exc
        return {**identity,
                "routes": {"engine": settings.engine_model,
                           "primary": settings.primary._asdict(), "challenger": settings.challenger._asdict(),
                           "minimum_severity": settings.minimum_severity},
                "work_budget": settings.work_budget,
                "credential_env": dict(settings.credential_env),
                "provider_attestation": None}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        deadline = Deadline(timeout_seconds)
        try:
            backend = active_backend()
            if backend is not None:
                raise AdapterError(f"runsortie runs only on the local unenforced backend, not {getattr(backend, 'name', 'another')}; "
                                   "its runtime and agents are host installs")
            if request["input"]["mode"] != "full" or request["input"].get("pr") is not None:
                raise AdapterError("runsortie carries out fresh full baselines only; this request was refused")
            settings = read_settings(spec.config)
            current = runtime_identity(settings, probe_versions=False, deadline=deadline)
            if current != _without_versions({key: preparation.get(key) for key in current}):
                raise AdapterError("the RunSortie runtime changed between preparation and this invocation; nothing was run")
            source, raw = Path(source_dir), Path(raw_dir)
            if os.path.lexists(source / evidence.EVIDENCE_ROOT):
                raise AdapterError("the initial tree already holds .fieldglass; RunSortie would resume from it, so it was refused")
            if os.path.lexists(source / ".pi"):
                raise AdapterError(
                    "the initial tree already holds a target-root .pi path; secure v1 refuses project Pi "
                    "configuration and migration surfaces before launch")
            evaluated, branch, git_guard, evaluated_tree = initial_repository(source, deadline)
            source_guard = _capture_root(source)
            product_before = product_tree(source, deadline, source_guard)
            if product_before is None:
                raise AdapterError("the evaluated product tree could not be walked before the run")
            if not _product_matches_evaluated(product_before, evaluated_tree):
                raise AdapterError("the clean worktree bytes do not match the independently verified evaluated tree")
            enclosure = Enclosure.capture(source, raw)
            config = native_config(settings, repo=source, branch=branch)
            config_bytes = (json.dumps(config, indent=2, sort_keys=True) + "\n").encode("utf-8")
            primary_prompt_bytes = _primary_prompt(settings, evaluated, deadline)
            private = Path(tempfile.mkdtemp(prefix="scaneval-runsortie-"))
            private_guard = _capture_root(private)
            try:
                outcome = self._run(settings=settings, preparation=preparation, source=source, raw=raw, private=private,
                                    private_guard=private_guard, enclosure=enclosure, evaluated=evaluated,
                                    branch=branch,
                                    evaluated_tree=evaluated_tree, git_guard=git_guard,
                                    product_before=product_before, config_bytes=config_bytes,
                                    primary_prompt_bytes=primary_prompt_bytes,
                                    timeout_seconds=timeout_seconds, deadline=deadline,
                                    source_guard=source_guard)
            except Exception as exc:
                cleanup_failure = _cleanup_private(
                    private, private_guard, Deadline(PRIVATE_CLEANUP_GRACE_SECONDS))
                if cleanup_failure:
                    if isinstance(exc, DeadlineExpired):
                        raise DeadlineExpired(f"{exc}; {cleanup_failure}") from exc
                    raise AdapterError(f"RunSortie failed and its private workspace cleanup was deferred: "
                                       f"{cleanup_failure}; original error: {type(exc).__name__}: {exc}") from exc
                raise
            # The normal evidence path cleans before it judges.  An earlier evidence-reader failure
            # returns an outcome directly, so make one bounded fallback attempt here and expose any
            # deferral without discarding claims already imported.
            if os.path.lexists(private):
                cleanup_failure = _cleanup_private(
                    private, private_guard, Deadline(PRIVATE_CLEANUP_GRACE_SECONDS))
                if cleanup_failure:
                    note = f"RunSortie private workspace cleanup was deferred: {cleanup_failure}"
                    if note not in outcome.notes:
                        outcome.notes.append(note)
                    outcome.bundles_resolved = False
                    if deadline.expired:
                        outcome.status = "timeout"
                        outcome.timed_out = True
                        outcome.error = {"code": "timeout", "message": cleanup_failure}
                    elif outcome.status == "success":
                        outcome.status = "partial"
                        outcome.error = {"code": "private_cleanup_incomplete", "message": cleanup_failure}
            return outcome
        except DeadlineExpired as exc:
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True, command=[], claims=[], artifacts=[],
                                 notes=["The shared adapter deadline expired before durable findings could be read."],
                                 error={"code": "timeout", "message": str(exc)}, model_identity=None,
                                 bundles_resolved=False, processing="full", usage={"cost_usd": None})

    def _run(self, *, settings, preparation, source, raw, private, private_guard, enclosure, evaluated, branch,
             evaluated_tree, git_guard, product_before, config_bytes, timeout_seconds,
             primary_prompt_bytes, deadline: Deadline, source_guard: RootGuard) -> NativeOutcome:
        state_dir, cache_dir, npm_cache_dir = private / "state", private / "cache", private / "npm-cache"
        home_dir, private_tmp = private / "home", private / "tmp"
        xdg_config, xdg_cache = home_dir / ".config", home_dir / ".cache"
        xdg_state, xdg_data = home_dir / ".local" / "state", home_dir / ".local" / "share"
        codex_home, claude_home = home_dir / ".codex", home_dir / ".claude"
        gemini_home, pi_home = home_dir / ".gemini", home_dir / ".pi" / "agent"
        isolated_bin = private / "isolated-bin"
        for directory in (state_dir, cache_dir, npm_cache_dir, home_dir, private_tmp, xdg_config, xdg_cache,
                          xdg_state, xdg_data, codex_home, claude_home, gemini_home, pi_home, isolated_bin):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory.chmod(0o700)
        state_guard, cache_guard = _capture_root(state_dir), _capture_root(cache_dir)
        config_path = private / "runsortie-config.json"
        _write_private_file(config_path, config_bytes)
        gemini_settings = (json.dumps({
            "hooksConfig": {"enabled": False},
            "security": {"blockGitExtensions": True, "folderTrust": {"enabled": True}},
            "skills": {"enabled": False},
        }, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        gemini_user_settings = gemini_home / "settings.json"
        gemini_system_settings = gemini_home / "system-settings.json"
        gemini_system_defaults = gemini_home / "system-defaults.json"
        for path in (gemini_user_settings, gemini_system_settings, gemini_system_defaults):
            _write_private_file(path, gemini_settings)
        pi_auth_bytes, pi_models_store_bytes = b"{}", b"{}"
        pi_auth = pi_home / "auth.json"
        pi_models_store = pi_home / "models-store.json"
        _write_private_file(pi_auth, pi_auth_bytes)
        _write_private_file(pi_models_store, pi_models_store_bytes)
        codex_selected = settings.primary.agent == "codex" or settings.challenger.agent == "codex"
        claude_selected = settings.primary.agent == "claude" or settings.challenger.agent == "claude"
        engine_credential = settings.credential_env["engine"]
        credential_names = {engine_credential}
        if codex_selected:
            credential_names.add("OPENAI_API_KEY")
        if claude_selected:
            credential_names.add("ANTHROPIC_API_KEY")

        def required_secret(name: str, role: str) -> str:
            value = os.environ.get(name)
            if not value or len(value.encode("utf-8")) > 8192 or any(char in value for char in "\r\n\0"):
                raise AdapterError(
                    f"secure v1 {role} requires a nonempty, single-line {name} of at most 8192 UTF-8 bytes; "
                    "cached operator login state is never copied")
            return value

        required_secret(engine_credential, "Pi engine")
        if codex_selected:
            required_secret("OPENAI_API_KEY", "Codex agent")
        if claude_selected:
            required_secret("ANTHROPIC_API_KEY", "Claude --bare agent")

        wrapper_specs: list[tuple[str, Path, bytes]] = []
        pi_wrapper = isolated_bin / "pi"
        pi_wrapper_bytes = _credential_wrapper(
            preparation["engine_driver"]["realpath"], keep=frozenset({engine_credential}),
            arguments=PI_ISOLATION_FLAGS)
        wrapper_specs.append(("Pi isolation wrapper", pi_wrapper, pi_wrapper_bytes))
        if codex_selected:
            wrapper_specs.append(("Codex credential-isolation wrapper", isolated_bin / "codex",
                                  _credential_wrapper(preparation["agents"]["codex"]["realpath"], keep=frozenset())))
        if claude_selected:
            wrapper_specs.append(("Claude bare isolation wrapper", isolated_bin / "claude",
                                  _credential_wrapper(preparation["agents"]["claude"]["realpath"],
                                                      keep=frozenset({"ANTHROPIC_API_KEY"}),
                                                      arguments=("--bare",))))
        runtime_path = str(isolated_bin) + os.pathsep + preparation["runtime_path"]
        npm_script_wrapper = isolated_bin / "runsortie-npm-script-shell"
        npm_script_wrapper_bytes = (
            "#!/bin/sh\nPATH=" + shlex.quote(runtime_path) + "\nexport PATH\nexec "
            + shlex.quote(str(NPM_SCRIPT_SHELL)) + ' "$@"\n').encode("utf-8")
        wrapper_specs.append(("npm lifecycle PATH-reset wrapper", npm_script_wrapper, npm_script_wrapper_bytes))
        tsx_wrapper = isolated_bin / "tsx"
        tsx_wrapper_bytes = _credential_wrapper(
            preparation["fieldglass"]["tsx_launcher"]["realpath"], keep=CREDENTIAL_ENV_ALLOWLIST)
        wrapper_specs.append(("Fieldglass tsx absolute-launch wrapper", tsx_wrapper, tsx_wrapper_bytes))
        agent_shell_wrapper = isolated_bin / "scaneval-bash"
        agent_shell_wrapper_bytes = (
            "#!/bin/sh\nexec " + shlex.quote(str(AGENT_SHELL))
            + ' --noprofile --norc "$@"\n').encode("utf-8")
        wrapper_specs.append(("agent no-startup-files shell wrapper", agent_shell_wrapper,
                              agent_shell_wrapper_bytes))
        for _label, wrapper_path, wrapper_bytes in wrapper_specs:
            _write_private_file(wrapper_path, wrapper_bytes, mode=0o700)
        immutable_policy_files = [
            ("Gemini user settings", gemini_user_settings, gemini_settings, 0o600),
            ("Gemini system settings", gemini_system_settings, gemini_settings, 0o600),
            ("Gemini system defaults", gemini_system_defaults, gemini_settings, 0o600),
            ("Pi empty credential store", pi_auth, pi_auth_bytes, 0o600),
            ("Pi empty model store", pi_models_store, pi_models_store_bytes, 0o600),
        ]
        immutable_policy_files.extend(
            (label, wrapper_path, wrapper_bytes, 0o700)
            for label, wrapper_path, wrapper_bytes in wrapper_specs)
        artifacts: list[dict] = []
        notes: list[str] = []
        preservation_failures: list[str] = []

        def register(artifact_id: str, path: Path, data: bytes) -> bool:
            failure = write_new(path, data, enclosure.staging, deadline)
            if failure:
                notes.append(f"{artifact_id}: could not be staged ({failure}); not registered")
                preservation_failures.append(artifact_id)
                return False
            artifacts.append({"id": artifact_id, "path": path})
            return True

        register("runsortie-config", raw / "runsortie-config.json", config_bytes)
        register("runsortie-primary-prompt", raw / "runsortie-primary-prompt.txt", primary_prompt_bytes)
        register("runsortie-gemini-settings", raw / "runsortie-gemini-settings.json", gemini_settings)
        register("runsortie-gemini-system-settings", raw / "runsortie-gemini-system-settings.json", gemini_settings)
        register("runsortie-gemini-system-defaults", raw / "runsortie-gemini-system-defaults.json", gemini_settings)
        wrapper_artifacts = {
            "Pi isolation wrapper": ("runsortie-pi-wrapper", raw / "runsortie-pi-wrapper.sh"),
            "Codex credential-isolation wrapper": ("runsortie-codex-wrapper", raw / "runsortie-codex-wrapper.sh"),
            "Claude bare isolation wrapper": ("runsortie-claude-wrapper", raw / "runsortie-claude-wrapper.sh"),
            "npm lifecycle PATH-reset wrapper": (
                "runsortie-npm-script-shell-wrapper", raw / "runsortie-npm-script-shell-wrapper.sh"),
            "Fieldglass tsx absolute-launch wrapper": (
                "runsortie-tsx-wrapper", raw / "runsortie-tsx-wrapper.sh"),
            "agent no-startup-files shell wrapper": (
                "runsortie-agent-shell-wrapper", raw / "runsortie-agent-shell-wrapper.sh"),
        }
        for label, _wrapper_path, wrapper_bytes in wrapper_specs:
            artifact_id, artifact_path = wrapper_artifacts[label]
            register(artifact_id, artifact_path, wrapper_bytes)
        isolation_record = (json.dumps({
            "version": 1, "cachedLoginImported": False,
            "credentialEnvironmentRoles": dict(settings.credential_env),
            "privateHomes": ["HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME",
                             "CODEX_HOME", "CLAUDE_CONFIG_DIR", "GEMINI_CLI_HOME", "PI_CODING_AGENT_DIR"],
            "claudeSafeMode": True, "claudeBare": claude_selected, "directGeminiAgentRoutes": "refused",
            "geminiFolderTrust": "empty-private-store-untrusted",
            "geminiHooksEnabled": False, "geminiSkillsEnabled": False,
            "geminiSystemSettingsControlled": True, "geminiSystemDefaultsControlled": True,
            "codexApiKeyBootstrap": codex_selected,
            "agentShellStartupFilesDisabled": True,
            "dynamicAgentStatePreserved": False,
            "immutablePolicy": {
                label: {"mode": oct(mode), "sha256": "sha256:" + hashlib.sha256(data).hexdigest()}
                for label, _path, data, mode in immutable_policy_files
            },
            "piIsolationFlags": list(PI_ISOLATION_FLAGS),
            "roleCredentialRetention": {
                "pi-engine": [engine_credential], "codex-agent": [],
                "claude-agent": ["ANTHROPIC_API_KEY"] if claude_selected else []},
        }, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        register("runsortie-agent-isolation", raw / "runsortie-agent-isolation.json", isolation_record)
        env = build_env(tuple(sorted(credential_names)), {
            "PATH": runtime_path, "HOME": str(home_dir), "TMPDIR": str(private_tmp),
            "LANG": "C", "LC_ALL": "C",
            "XDG_CONFIG_HOME": str(xdg_config), "XDG_CACHE_HOME": str(xdg_cache),
            "XDG_STATE_HOME": str(xdg_state), "XDG_DATA_HOME": str(xdg_data),
            "CODEX_HOME": str(codex_home), "CLAUDE_CONFIG_DIR": str(claude_home),
            "GEMINI_CLI_HOME": str(gemini_home), "PI_CODING_AGENT_DIR": str(pi_home),
            "GEMINI_CLI_SYSTEM_SETTINGS_PATH": str(gemini_system_settings),
            "GEMINI_CLI_SYSTEM_DEFAULTS_PATH": str(gemini_system_defaults),
            "CLAUDE_CODE_SAFE_MODE": "1", "SHELL": str(agent_shell_wrapper),
            "CLAUDE_CODE_SHELL": str(agent_shell_wrapper),
            "RUNSORTIE_STATE_DIR": str(state_dir), "RUNSORTIE_CACHE_DIR": str(cache_dir),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": os.devnull,
            "GIT_CONFIG_KEY_1": "core.fsmonitor", "GIT_CONFIG_VALUE_1": "false",
            # npm must not read executable-affecting user/global configuration from any home.
            "NODE_OPTIONS": "", "npm_config_node_options": "",
            "npm_config_userconfig": os.devnull, "npm_config_globalconfig": os.devnull,
            "npm_config_script_shell": str(npm_script_wrapper), "npm_config_cache": str(npm_cache_dir),
            "npm_config_logs_max": "0", "npm_config_offline": "true",
            "npm_config_update_notifier": "false", "NO_UPDATE_NOTIFIER": "1"})
        if codex_selected:
            api_key = required_secret("OPENAI_API_KEY", "Codex agent")
            codex_env = dict(env)
            for credential_name in CREDENTIAL_ENV_ALLOWLIST - {"OPENAI_API_KEY"}:
                codex_env.pop(credential_name, None)
            codex = preparation["agents"]["codex"]["realpath"]
            auth_timeout = deadline.remaining(cap=min(10.0, max(0.5, deadline.remaining() * 0.10)))
            login = run_command(
                [codex, "login", "--with-api-key"], cwd=private, timeout_seconds=auth_timeout, env=codex_env,
                stdin_text=api_key + "\n", stdout_path=private / "codex-login.stdout",
                stderr_path=private / "codex-login.stderr", ensure_group_empty=True)
            if login.timed_out or login.exit_code != 0 or not login.cleanup_succeeded:
                raise AdapterError("the private Codex API-key bootstrap failed before RunSortie launch")
            status = run_command(
                [codex, "login", "status"], cwd=private,
                timeout_seconds=deadline.remaining(cap=min(10.0, max(0.5, deadline.remaining() * 0.10))), env=codex_env,
                stdout_path=private / "codex-login-status.stdout", stderr_path=private / "codex-login-status.stderr",
                ensure_group_empty=True)
            if status.timed_out or status.exit_code != 0 or not status.cleanup_succeeded:
                raise AdapterError("the private Codex login status check failed before RunSortie launch")
            # Codex now authenticates from its invocation-private CODEX_HOME and its runtime wrapper
            # removes every provider secret.  Do not expose the bootstrap key to RunSortie, npm,
            # Fieldglass, Git, or the engine unless OPENAI_API_KEY is deliberately also the one
            # configured Pi-engine credential.
            if engine_credential != "OPENAI_API_KEY":
                env.pop("OPENAI_API_KEY", None)
        argv = [preparation["node"]["path"], str(settings.root / "dist" / "cli.js"), "scan",
                "--config", str(config_path), "--target", TARGET]
        remaining = deadline.remaining()
        result = run_command(argv, cwd=private, timeout_seconds=remaining, env=env,
                             stdout_path=raw / "runsortie-stdout.txt", stderr_path=raw / "runsortie-stderr.txt",
                             ensure_group_empty=True)
        # Process-group termination may itself consume the tail of the scan budget.  Give evidence
        # already written before termination one independent, bounded chance to be snapshotted,
        # imported, staged and judged.  This never turns a scanner/main-deadline timeout into success.
        scan_timed_out = result.timed_out or time.monotonic() >= deadline.ends
        if scan_timed_out:
            deadline.expired = True
            result.timed_out = True
        deadline = Deadline(POST_RUN_EVIDENCE_GRACE_SECONDS)
        artifacts += [{"id": "runsortie-stdout", "path": raw / "runsortie-stdout.txt"},
                      {"id": "runsortie-stderr", "path": raw / "runsortie-stderr.txt"}]
        if not result.cleanup_succeeded:
            notes.append("the RunSortie process group was not empty after bounded descendant cleanup")

        imported = HarnessImport([], [], [], ())
        records: list[evidence.FindingMeta] = []
        try:
            # One no-follow byte/kind/mode snapshot is the sole source for full-tree artifacts,
            # semantic receipts/findings, and the later verified evidence-commit comparison.
            evidence_snapshot = _snapshot_evidence_tree(
                source / evidence.EVIDENCE_ROOT, enclosure, raw, register, deadline, source_guard)
            notes.extend(evidence_snapshot.issues)
            if not evidence_snapshot.complete:
                preservation_failures.append("runsortie-evidence-tree")

            imported = _import_runsortie_findings(
                evidence_snapshot, raw / "runsortie-findings", enclosure, deadline)
            artifacts += imported.artifacts
            notes += imported.notes
            for claim in imported.claims:
                deadline.check()
                staged = raw / "runsortie-findings" / claim["raw_artifact_id"].split("/", 1)[1]
                data = evidence_snapshot.regular(
                    f"findings/{claim['raw_artifact_id'].split('/', 1)[1]}")
                front, _body = parse_frontmatter(data.decode("utf-8", errors="replace")) if data is not None else ({}, "")
                cwes = front.get("cwe_ids")
                if isinstance(cwes, list):
                    normalized = list(dict.fromkeys(str(item).strip() for item in cwes if str(item).strip()))
                    if normalized:
                        claim["native_cwe"] = normalized
                if data is not None:
                    captured = evidence.capture_finding(data, record=staged.name, artifact_id=claim["raw_artifact_id"],
                                                        evidence_path=f"{evidence.EVIDENCE_ROOT}/findings/{staged.name}")
                    native_path = captured.native.get("filePath") if captured.native is not None else None
                    normalized_path = native_path.replace("\\", "/") if isinstance(native_path, str) else ""
                    if normalized_path.startswith("./"):
                        normalized_path = normalized_path[2:]
                    capture_valid = (captured.finding_id == claim["claim_id"]
                                     and evidence.FINDING_ID.fullmatch(captured.finding_id) is not None
                                     and captured.severity in evidence.REVIEW_SEVERITY_ORDER
                                     and bool(normalized_path) and "\0" not in normalized_path
                                     and not normalized_path.startswith("/")
                                     and not re.match(r"^[A-Za-z]:/", normalized_path)
                                     and ".." not in normalized_path.split("/"))
                    if not capture_valid:
                        captured = captured._replace(finding_id=claim["claim_id"], native=None)
                    else:
                        claim["primary_location"]["path"] = normalized_path
                        claim["native_severity"] = captured.severity
                    records.append(captured)
                else:
                    records.append(evidence.FindingMeta(claim["claim_id"], staged.name, claim["raw_artifact_id"],
                                                        None, None, None))

            # External native state is likewise parsed from the exact bytes staged by this walk.
            state_notes, state_preserved, state_files = self._preserve_state(
                state_dir, state_guard, raw, register, deadline)
            notes += state_notes
            if not state_preserved:
                preservation_failures.append("runsortie-native-state")
            state_data = state_files.get("state.json")
            state_read = (Read(state_data, None) if state_data is not None else
                          Read(None, "state.json was absent from the preserved native-state snapshot"))
            target_state_key = hashlib.sha256(
                f"{TARGET}\0{source.resolve()}\0{branch}".encode("utf-8")).hexdigest()[:32]
            binding_hash = evidence.review_work_binding_hash(TARGET, evaluated)
            expected_journal = (f"review-work/{target_state_key}/"
                                f"review-work-{binding_hash[:32]}.json")
            review_work_files = {
                relative: data for relative, data in state_files.items()
                if relative == "review-work" or relative.startswith("review-work/")}
            review_journal_data = (review_work_files[expected_journal]
                                   if set(review_work_files) == {expected_journal} else None)
            if review_journal_data is None:
                notes.append(
                    "the invocation did not produce exactly the one native review-work journal path "
                    f"{expected_journal}; observed {sorted(review_work_files)[:5]}")
            try:
                leftover = len(_fd_tree_snapshot(
                    cache_dir, cache_guard, deadline, maximum=MAX_CACHE_ENTRIES,
                    max_depth=MAX_PRIVATE_DEPTH))
            except OSError:
                leftover = -1
                preservation_failures.append("runsortie-cache-inspection")
            if leftover:
                notes.append(f"RunSortie wrote {leftover if leftover > 0 else 'an unreadable set of'} entr(ies) to its private "
                             "cache; with engine.localPath set nothing should be copied or installed there")
                preservation_failures.append("runsortie-cache-not-empty")

            receipts: dict[str, Read] = {}
            for name in RECEIPTS:
                deadline.check()
                entry = evidence_snapshot.entries.get(name)
                if entry is None:
                    read = Read(None, None)
                elif entry.kind == "regular" and entry.data is not None and entry.failure is None:
                    read = Read(entry.data, None)
                else:
                    read = Read(None, entry.failure or f"it is a {entry.kind}, not a regular file")
                receipts[name] = read
                if read.failure:
                    notes.append(f".fieldglass/{name}: not read ({read.failure}); treated as invalid evidence")
                    preservation_failures.append(f"runsortie-receipts/{name}")
                elif read.data is not None:
                    register(f"runsortie-receipts/{name}", raw / "runsortie-receipts" / name, read.data)

            agent_isolation_unchanged = True
            for label, policy_path, expected_bytes, expected_mode in immutable_policy_files:
                policy_read = read_bounded(
                    policy_path, private_guard.containment.contains(policy_path), len(expected_bytes), deadline)
                try:
                    policy_stat = os.lstat(policy_path)
                except OSError:
                    policy_stat = None
                policy_mode = stat.S_IMODE(policy_stat.st_mode) if policy_stat is not None else -1
                if policy_read.data != expected_bytes or policy_stat is None \
                        or not stat.S_ISREG(policy_stat.st_mode) or policy_mode != expected_mode:
                    notes.append(f"the invocation-owned {label} changed during the run")
                    preservation_failures.append("runsortie-agent-policy-changed")
                    agent_isolation_unchanged = False

            cleanup_failure = _cleanup_private(
                private, private_guard, Deadline(PRIVATE_CLEANUP_GRACE_SECONDS))
            if cleanup_failure:
                notes.append(f"RunSortie private workspace cleanup was deferred: {cleanup_failure}")
                preservation_failures.append("runsortie-private-cleanup")

            return self._judge(settings=settings, preparation=preparation, source=source, raw=raw,
                               enclosure=enclosure, evaluated=evaluated, evaluated_tree=evaluated_tree,
                               evidence_snapshot=evidence_snapshot,
                               product_before=product_before,
                               source_guard=source_guard,
                               git_guard=git_guard,
                               result=result, argv=argv, state_read=state_read, receipts=receipts,
                               review_journal_data=review_journal_data,
                               primary_prompt_bytes=primary_prompt_bytes,
                               agent_isolation_unchanged=agent_isolation_unchanged,
                               imported=imported, records=records, artifacts=artifacts, notes=notes,
                               register=register, timeout_seconds=timeout_seconds, deadline=deadline,
                               preservation_failures=preservation_failures)
        except Exception as exc:  # noqa: BLE001 - the claims already read must survive a reader defect
            claims, seen = [], set()
            for claim in imported.claims:
                if claim["claim_id"] not in seen:
                    seen.add(claim["claim_id"])
                    claims.append(claim)
            notes.append("The evidence could not be judged after the run; every imported finding is kept as a "
                         "provisional claim and nothing about completion is asserted.")
            return NativeOutcome(
                status="timeout" if result.timed_out or deadline.expired else "error", exit_code=result.exit_code,
                timed_out=result.timed_out or deadline.expired, command=argv, claims=claims, artifacts=artifacts, notes=notes,
                error={"code": "timeout" if result.timed_out or deadline.expired else "evidence_unjudged",
                       "message": f"RunSortie evidence could not be judged: {type(exc).__name__}: {exc}"[:2000]},
                model_identity=None, bundles_resolved=False, processing="full", usage={"cost_usd": None})

    def _judge(self, *, settings, preparation, source, raw, enclosure, evaluated, evaluated_tree, git_guard,
               evidence_snapshot, product_before, result, argv, state_read, receipts, review_journal_data,
               agent_isolation_unchanged, imported, records,
               primary_prompt_bytes, artifacts, notes, register, timeout_seconds, deadline: Deadline,
               preservation_failures: list[str], source_guard: RootGuard) -> NativeOutcome:
        """Read history and identity, judge every native record, and build the outcome."""
        history_read = read_history(source, evaluated, evaluated_tree, evidence_snapshot, git_guard, deadline)
        history = history_read.evidence
        if history_read.manifest is not None:
            register("runsortie-git-evidence-manifest", raw / "runsortie-git-evidence-manifest.json",
                     history_read.manifest)
        elif history.state == "evidence-commit":
            preservation_failures.append("runsortie-git-evidence-manifest")
            notes.append("the evidence commit could not be rendered as a bounded replay manifest")
        product_after = product_tree(source, deadline, source_guard)
        if product_after != product_before:
            after_map = product_after or {}
            changed = sorted(path for path in set(product_before) | set(after_map)
                             if product_before.get(path) != after_map.get(path))
            notes.append("the evaluated product tree changed during the run"
                         + (f": {', '.join(changed[:5])}" if product_after is not None else " or could not be re-walked"))
        try:
            after = runtime_identity(settings, probe_versions=False, deadline=deadline)
            runtime_unchanged = (after == _without_versions({key: preparation.get(key) for key in after})
                                 and agent_isolation_unchanged)
        except (AdapterError, OSError) as exc:
            notes.append(f"the RunSortie runtime could not be re-verified after the run: {exc}")
            runtime_unchanged = False

        immutable_source = source_reader(
            source, product_before, evaluated_tree, enclosure, deadline, source_guard)
        proposals: dict[str, str] = {}
        for path in evidence.POLICY_SOURCE_CANDIDATES:
            deadline.check()
            content = immutable_source(path)
            if content is not None and len(content) <= evidence.MAX_POLICY_SOURCE_BYTES:
                proposals[path] = hashlib.sha256(content).hexdigest()
        target = evidence.read_target_state(state_read.parsed_input, TARGET)
        checkpoint = evidence.read_checkpoint(receipts[".state.json"].parsed_input, evaluated)
        acceptance = evidence.read_acceptance(receipts["baseline-acceptance.json"].parsed_input, evaluated)
        target = evidence.bind_ready_baseline(target, acceptance, evaluated)
        policy = evidence.read_policy(receipts["target-security-policy.json"].parsed_input,
                                      repository_proposals=proposals)
        packets = evidence.read_packets(receipts["primary-review-packets.json"].parsed_input,
                                        policy=policy, records=records,
                                        minimum_severity=settings.minimum_severity, check=deadline.check)
        review = evidence.read_review_state(receipts["sortie-state.json"].parsed_input)
        verification = evidence.read_verification(
            receipts["verification-summary.json"].parsed_input, evaluated=evaluated,
            minimum_severity=settings.minimum_severity, packets=packets, review=review,
            primary=settings.primary.native(), challenger=settings.challenger.native(),
            primary_prompt_bytes=len(primary_prompt_bytes),
            source_reader=immutable_source, check=deadline.check)
        review_journal = evidence.read_review_journal(
            review_journal_data, evaluated=evaluated, target=TARGET, packets=packets, review=review,
            verification=verification, summary_data=receipts["verification-summary.json"].parsed_input,
            review_markdown=receipts["sortie-review.md"].data,
            primary=settings.primary.native(), challenger=settings.challenger.native(),
            primary_prompt_hash=evidence.primary_review_prompt_hash(primary_prompt_bytes.decode("utf-8")),
            source_reader=immutable_source)
        if review_journal.state != "valid" and verification.state == "complete":
            verification = verification._replace(
                state="invalid", issues=tuple(dict.fromkeys((*verification.issues, *review_journal.issues))))
        budget = evidence.read_work_budget(
            receipts["work-budget.json"].parsed_input,
            fieldglass_data=receipts["fieldglass-work-budget.json"].parsed_input,
            configured=settings.work_budget, snapshot=target.work_budget, verification=verification,
            evaluated=evaluated, target=TARGET, attempted_at=target.last_attempt_at, check=deadline.check)
        lost_ids = frozenset(loss.finding_id for loss in imported.losses if loss.finding_id)
        fallback_population = (packets.finding_ids if packets.state == "valid"
                               else review.captured if review.state == "valid" else None)
        reconciliation = evidence.reconcile_findings(records, minimum_severity=settings.minimum_severity,
                                                     verification=verification, lost_ids=lost_ids,
                                                     fallback_captured=fallback_population,
                                                     honor_dispositions=False)
        lost = imported.lost + len(reconciliation.losses)
        baseline = target.baseline
        # A native failure recorded on RunSortie's catch path carries no heads; it is already an error,
        # and a head it does name must still be the evaluated one.
        named = (target.repository_head, target.product_head)
        heads_bound = ((all(head in (None, evaluated) for head in named) if target.outcome == "failed"
                        else all(head == evaluated for head in named))
                       and (baseline is None or baseline.attempted_head in (None, evaluated))
                       and (baseline is None or baseline.status != "ready" or baseline.checkpoint == evaluated))
        facts = evidence.Facts(
            timed_out=result.timed_out or deadline.expired, exit_code=result.exit_code,
            runtime_unchanged=runtime_unchanged and result.cleanup_succeeded,
            product_tree_unchanged=product_after == product_before,
            target_state=target.state, heads_bound=heads_bound, git=history.state,
            evidence_head_matches=history.head is not None and target.evidence_head == history.head,
            outcome=target.outcome, baseline=baseline.status if baseline else "absent", checkpoint=checkpoint.state,
            acceptance=acceptance.state, policy=policy.state, packets=packets.state,
            verification=verification.state, work_budget=budget.state, import_lost=lost,
            evidence_preserved=not preservation_failures)
        verdict = evidence.evaluate(facts)
        review_bindings_valid = (verdict.status == "success" and history.state == "evidence-commit"
                                 and policy.state == "valid" and packets.state == "valid"
                                 and review.state == "valid" and verification.state == "complete"
                                 and not preservation_failures)
        if review_bindings_valid:
            reconciliation = evidence.reconcile_findings(records, minimum_severity=settings.minimum_severity,
                                                         verification=verification, lost_ids=lost_ids,
                                                         fallback_captured=fallback_population,
                                                         honor_dispositions=True)

        receipt = {
            "version": 1, "evaluated_head": evaluated, "evidence_head": history.head, "changed_paths": list(history.changed),
            "exit_code": result.exit_code, "timed_out": result.timed_out,
            "verdict": {"status": verdict.status, "code": verdict.code, "unmet": list(verdict.unmet)},
            "facts": facts._asdict(),
            "readings": {name: {"state": reading.state, "issues": list(reading.issues)} for name, reading in (
                ("target_state", target), ("git", history), ("checkpoint", checkpoint), ("acceptance", acceptance),
                ("target_security_policy", policy), ("packets", packets), ("review_state", review),
                ("verification", verification), ("review_work_journal", review_journal), ("work_budget", budget))},
            "native": {"outcome": target.outcome, "message": (target.message or "")[:2000],
                       "baseline": baseline._asdict() if baseline else None,
                       "acceptance_reasons": list(acceptance.reasons), "observed_routes": list(verification.routes)},
            "requested_routes": preparation.get("routes"),
            "findings": list(reconciliation.entries),
            "import_loss": [loss.note for loss in imported.losses] + list(reconciliation.losses),
            "runtime_unchanged": runtime_unchanged,
        }
        reconciliation_registered = register(
            "runsortie-reconciliation", raw / "runsortie-reconciliation.json",
            (json.dumps(receipt, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8"))
        if not reconciliation_registered:
            facts = facts._replace(evidence_preserved=False)
            verdict = evidence.evaluate(facts)
            reconciliation = evidence.reconcile_findings(
                records, minimum_severity=settings.minimum_severity, verification=verification,
                lost_ids=lost_ids, fallback_captured=fallback_population, honor_dispositions=False)

        claims = [claim for claim in imported.claims if claim["claim_id"] in reconciliation.keep]
        seen: set[str] = set()
        claims = [claim for claim in claims if not (claim["claim_id"] in seen or seen.add(claim["claim_id"]))]

        notes.extend(self._notes(verdict, facts, target, history, verification, reconciliation, imported.lost))
        tool_versions = {
            "runsortie": f"runsortie@{settings.expected_commit}",
            "runsortie_package": str(preparation["runsortie"].get("package_version")),
            "fieldglass_package": str(preparation["fieldglass"].get("package_version")),
            "node": str(preparation["node"].get("version") or "unknown"),
            "npm": str(preparation["npm"].get("version") or "unknown"),
            "engine_route": settings.engine_model,
            "primary_route": f"{settings.primary.agent}/{settings.primary.model}",
            "challenger_route": f"{settings.challenger.agent}/{settings.challenger.model}",
        }
        if verification.routes:
            tool_versions["observed_review_routes"] = ", ".join(verification.routes)[:500]
        message = "; ".join(f"{code}" for code in verdict.unmet)
        detail = [issue for reading in (target, history, checkpoint, acceptance, policy, packets, review,
                                        verification, review_journal, budget)
                  for issue in reading.issues][:8] + list(reconciliation.losses[:3]) + [loss.note for loss in imported.losses[:3]]
        if verdict.status in ("error", "timeout") and result.exit_code not in (0, None):
            stderr = raw / "runsortie-stderr.txt"
            read = read_bounded(stderr, enclosure.write(stderr), MAX_RECEIPT_BYTES, deadline)
            tail = (read.data or b"")[-600:].decode("utf-8", errors="replace").strip()
            if tail:
                detail.append(f"stderr tail: {tail}")
        if verdict.status == "timeout":
            message = f"RunSortie exceeded the shared {timeout_seconds}s deadline; evidence written before it was kept"
        else:
            message = f"RunSortie obligations not met: {message}"
        error = None if verdict.code is None else {
            "code": verdict.code, "message": (message + (f" ({'; '.join(detail)})" if detail else ""))[:2000]}
        return NativeOutcome(
            status=verdict.status, exit_code=result.exit_code, timed_out=result.timed_out or deadline.expired, command=argv,
            claims=claims, artifacts=artifacts, notes=notes, error=error, tool_versions=tool_versions,
            model_identity=None,
            bundles_resolved=(verdict.status in ("success", "partial") and lost == 0
                              and facts.evidence_preserved and history.state == "evidence-commit"
                              and facts.checkpoint == "bound" and facts.acceptance == "accepted"
                              and facts.policy == "valid" and facts.target_state == "valid"
                              and facts.heads_bound and facts.evidence_head_matches
                              and packets.state == "valid" and review.state == "valid"
                              and verification.state in ("complete", "unresolved")),
            processing="full", usage={"cost_usd": None})

    @staticmethod
    def _preserve_state(state_dir: Path, guard: RootGuard, raw: Path, register,
                        deadline: Deadline) -> tuple[list[str], bool, dict[str, bytes]]:
        """Stage the private native state, journals included, file by file and bounded; never a directory."""
        notes: list[str] = []
        count = total = 0
        preserved = True
        saw_anchor = False
        observed: dict[str, bytes] = {}

        def read_file(descriptor: int, status: os.stat_result, relative: str) -> tuple[bytes | None, str | None]:
            nonlocal total
            if status.st_size > MAX_STATE_FILE_BYTES or total + status.st_size > MAX_STATE_TOTAL_BYTES:
                return None, "byte bound reached"
            try:
                data = _read_fd_bytes(descriptor, status, MAX_STATE_FILE_BYTES, deadline)
            except OSError as exc:
                return None, exc.strerror or str(exc)
            if total + len(data) > MAX_STATE_TOTAL_BYTES:
                return None, "byte bound reached"
            total += len(data)
            return data, None

        try:
            walk_issues: list[str] = []
            entries = _fd_tree_snapshot(
                state_dir, guard, deadline, maximum=MAX_PRIVATE_ENTRIES, max_depth=MAX_PRIVATE_DEPTH,
                regular_reader=read_file, walk_issues=walk_issues)
            if walk_issues:
                notes.extend(f"native state walk failed closed ({issue})" for issue in walk_issues)
                preserved = False
            for relative, entry in sorted(entries.items()):
                if entry.kind == "directory":
                    continue
                if entry.kind != "regular":
                    notes.append(f"native state {relative} is a link or special file; it was not followed or preserved")
                    preserved = False
                    continue
                if relative == "state.json":
                    saw_anchor = True
                if count >= MAX_STATE_FILES:
                    notes.append(f"native state holds more than {MAX_STATE_FILES} files; the rest were not preserved")
                    preserved = False
                    break
                data, failure = entry.payload
                if data is None:
                    notes.append(f"native state {relative} was not preserved ({failure or 'byte bound reached'})")
                    preserved = False
                    continue
                if register(f"runsortie-native-state/{relative}", raw / "runsortie-native-state" / relative, data):
                    count += 1
                    observed[relative] = data
                else:
                    preserved = False
            if not saw_anchor:
                notes.append("the native state.json anchor was absent and could not be preserved")
                preserved = False
        except OSError as exc:
            notes.append(f"the native state directory could not be boundedly listed ({exc.strerror or exc}); it was not preserved")
            preserved = False
        return notes, preserved, observed

    @staticmethod
    def _notes(verdict, facts, target, history, verification, reconciliation, unreadable) -> list[str]:
        withheld = [entry["finding_id"] for entry in reconciliation.entries
                    if entry["reportability"].startswith("withheld")]
        counts: dict[str, int] = {}
        for entry in reconciliation.entries:
            counts[entry["reportability"]] = counts.get(entry["reportability"], 0) + 1
        notes = [
            f"RunSortie native outcome={target.outcome} baseline={facts.baseline} checkpoint={facts.checkpoint} "
            f"acceptance={facts.acceptance} packets={facts.packets} verification={facts.verification} "
            f"work_budget={facts.work_budget} git={history.state}; ScanEval status {verdict.status}"
            + (f" (unmet: {', '.join(verdict.unmet)})" if verdict.unmet else "") + ".",
            "Completion is bound to the head ScanEval evaluated, not to RunSortie's evidence head. Exit zero, an "
            "evidence commit and an empty finding set are each insufficient alone; see raw runsortie-reconciliation.json.",
            "Finding reportability: " + (", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "no findings")
            + ". A native reviewer disposition is preserved as metadata, never as benchmark truth.",
            "Model identity is not recorded: RunSortie has engine, primary and challenger roles and no provider "
            "attests what it served. Requested routes are in the system configuration; routes RunSortie's own "
            "records name are in the receipts" + (f" ({', '.join(verification.routes)})" if verification.routes else "") + ".",
            "Execution was local and unenforced: network access was not restricted, evidence commits stayed in the "
            "disposable workspace, and push was disabled.",
        ]
        if withheld:
            notes.append(f"{len(withheld)} finding(s) were dismissed by a complete native verification and are not "
                         f"reported as claims; their raw records remain registered: {', '.join(withheld[:10])}.")
        if history.state != "unchanged":
            notes.append("RunSortie committed evidence into the workspace's synthetic Git history, so the condition "
                         "audit records the repository metadata as changed during execution.")
        if unreadable or reconciliation.losses:
            notes.append(f"Import loss: {unreadable + len(reconciliation.losses)} finding record(s) or population "
                         "disagreement(s); this scan can earn neither completeness nor quiet credit.")
        return notes
