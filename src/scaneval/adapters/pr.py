"""What a native PR request names, and what git in the scanner's workspace says changed.

A pull-request scan is asked for by ``request["input"]["mode"] == "pr"`` and names its change as
``request["input"]["pr"] == {"base": <commit>, "head": <commit>}``: the neutral synthetic commits
of the two-commit history the runner builds in the scanner's workspace, with ``HEAD`` at ``head``
and a clean status. Nothing else about the change reaches a scanner: no snapshot id, no tree hash,
no change-set name. An adapter declares that it reads such a request by listing ``"pr"`` in
:attr:`~scaneval.adapters.base.Adapter.scan_modes`; the runner calls ``scan()`` only for a mode
the adapter declared, and this module is the adapter's own second line.

:func:`pr_range` is that second line. It answers "which change is this request about" for an
adapter that implements PR review and refuses everything it cannot serve exactly: a mode the
adapter does not declare, a full request that carries a ``pr`` it would ignore, a PR request that
does not name its two commits. So a PR request is never quietly run as a full scan, and a full
request is never quietly run as a review of something.

:func:`workspace_changes` is the evaluator reading the workspace before the scanner does. It
checks that the history the request names is really there (both commits exist, ``HEAD`` is at
head, nothing is modified or untracked) and lists what changed between them. Two properties are
deliberate. It uses the hermetic git of :func:`scaneval.materialize.git_command`, which depends on
nothing outside the directory it names, and it starts that git directly rather than through
:func:`~scaneval.adapters.base.run_command`: this is the evaluator reading its own history, not a
scanner process, so no execution backend routes it. And it runs before any scanner process
starts, because a scanner writes into the workspace it runs in, ``.git`` included, and anything
read from that repository afterwards would be read from a place the scanner could have changed.
What it lists is what git says about the two commits; it says nothing about what a scanner then
did with them.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
from typing import Any, NamedTuple

from ..materialize import git_command
from .base import Adapter, AdapterError


# A commit id the runner's history builder can produce: a full SHA-1 or SHA-256 object name. An
# abbreviation or a ref name is refused because both depend on the repository they are resolved in,
# and the request names the commits the runner made rather than anything a scanner could resolve
# differently.
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
# Each git command gets this long. Semgrep's own git calls get five minutes; nothing this module
# asks git for reads more than the two commits' trees and the status of one workspace.
GIT_TIMEOUT_SECONDS = 120.0


class PrRange(NamedTuple):
    """The two commits a PR request names, both full object names."""

    base: str
    head: str

    @property
    def revision_range(self) -> str:
        """``base..head``, the spelling git and DeepSec's ``--diff`` take for exactly these two."""
        return f"{self.base}..{self.head}"


class Change(NamedTuple):
    """One path git reports between the two commits.

    ``status`` is git's own letter: ``A`` added, ``M`` modified (a mode change alone is one),
    ``D`` deleted, ``T`` type changed, ``R`` renamed, ``C`` copied. For ``R`` and ``C``, ``path`` is
    the name at head and ``old_path`` the name the content came from; for every other status
    ``old_path`` is ``None``. A name that is not UTF-8 is spelled with backslash escapes rather
    than as a lone surrogate, so it can be written into a record; such a name can then no longer
    be compared with a file's real name, and nothing here pretends it can.
    """

    status: str
    path: str
    old_path: str | None = None

    @property
    def present(self) -> bool:
        """Whether something exists at ``path`` at head: everything but a deletion."""
        return self.status != "D"


def removed_paths(changes: tuple[Change, ...]) -> list[str]:
    """The paths the change removed, sorted and each once: every deletion and the old name of every rename.

    Nothing exists at one of them at head, so a scanner that reads head reads none of them. The old name
    of a copy is not here: the source of a copy is still at head, as it was.
    """
    return sorted({change.path for change in changes if change.status == "D"}
                  | {change.old_path for change in changes if change.status == "R" and change.old_path})


def pr_range(request: Any, adapter: Adapter) -> PrRange | None:
    """The change *request* asks *adapter* to review, or ``None`` when it asks for a full scan.

    A request with no ``input`` at all, which is what a direct caller of ``scan()`` may still hand
    over, is a full request: it cannot be a PR request, since a PR request is defined by the
    ``pr`` it carries. Everything else is checked exactly, and each refusal is an
    :class:`~scaneval.adapters.base.AdapterError` raised before anything runs:

    - a mode that is not ``full`` or ``pr``, or one the adapter's ``scan_modes`` does not list;
    - a full request that also carries ``pr``, which the adapter would otherwise ignore;
    - a PR request whose ``pr`` is not an object holding a ``base`` and a ``head`` that are each
      a full lowercase commit id.

    That the two commits exist in the workspace, and that ``HEAD`` is at ``head``, is a property of
    the workspace and is checked by :func:`workspace_changes`, not here.
    """
    scan_input = request.get("input") if isinstance(request, dict) else None
    if scan_input is None:
        return None
    if not isinstance(scan_input, dict):
        raise AdapterError(f"{adapter.name} was given a request whose input is a {type(scan_input).__name__}, "
                           "not an object")
    mode = scan_input.get("mode", "full")
    if not isinstance(mode, str) or mode not in ("full", "pr") or mode not in adapter.scan_modes:
        implemented = ", ".join(sorted(adapter.scan_modes)) or "none"
        raise AdapterError(f"{adapter.name} does not implement scan mode {mode!r} (it implements: "
                           f"{implemented}); the request was refused and nothing was run in its place")
    pr = scan_input.get("pr")
    if mode == "full":
        if pr is not None:
            raise AdapterError(f"{adapter.name} was given a full-mode request that also carries input.pr; "
                               "it would ignore the change it names, so the request was refused")
        return None
    if not isinstance(pr, dict):
        raise AdapterError(f"{adapter.name} was given a pr-mode request whose input.pr is "
                           f"{'absent' if pr is None else 'a ' + type(pr).__name__}, not an object naming "
                           "base and head")
    named = []
    for key in ("base", "head"):
        value = pr.get(key)
        if not isinstance(value, str) or not _COMMIT.match(value):
            raise AdapterError(f"{adapter.name} was given a pr-mode request whose input.pr.{key} is not a full "
                               "lowercase commit id")
        named.append(value)
    return PrRange(named[0], named[1])


def _scrub(text: str, workspace: Path) -> str:
    """*text* with the workspace's path spelled ``<workspace>``, so a record never names a machine."""
    for spelling in {str(workspace), str(workspace.resolve())}:
        text = text.replace(spelling, "<workspace>")
    return text


def _git(workspace: Path, *args: str, allow: tuple[int, ...] = (0,)) -> tuple[int, bytes]:
    """Run one hermetic git command in *workspace*; ``(exit code, stdout)``, refusing any other exit.

    ``core.fsmonitor`` is switched off on top of what :func:`~scaneval.materialize.git_command`
    already neutralizes, because ``git status`` would otherwise run whatever program the
    repository's own configuration names.
    """
    argv, env = git_command(["-c", "core.fsmonitor=false", *args])
    label = f"git {args[0]}"
    try:
        done = subprocess.run(argv, cwd=str(workspace), env=env, capture_output=True,
                              timeout=GIT_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as exc:
        raise AdapterError(f"{label} did not finish in {GIT_TIMEOUT_SECONDS:.0f}s in the scanner's workspace") from exc
    except OSError as exc:
        raise AdapterError(f"{label} could not be run in the scanner's workspace: {exc.strerror or exc}") from exc
    if done.returncode not in allow:
        detail = _scrub(done.stderr.decode("utf-8", errors="replace").strip(), workspace)[:300]
        raise AdapterError(f"{label} failed in the scanner's workspace (exit {done.returncode})"
                           + (f": {detail}" if detail else ""))
    return done.returncode, done.stdout


def _name(raw: bytes) -> str:
    return raw.decode("utf-8", errors="backslashreplace")


def _parse_name_status(raw: bytes) -> tuple[Change, ...]:
    """The changes in ``git diff --name-status -z`` output: ``status NUL path NUL``, two paths for R and C."""
    tokens = raw.split(b"\x00")
    if tokens and tokens[-1] == b"":
        tokens.pop()
    changes: list[Change] = []
    index = 0
    while index < len(tokens):
        code = tokens[index].decode("ascii", errors="replace")
        index += 1
        letter = code[:1]
        paths = 2 if letter in ("R", "C") else 1
        if not letter or index + paths > len(tokens):
            raise AdapterError("git printed a change record this adapter cannot read; nothing was run")
        names = [_name(token) for token in tokens[index:index + paths]]
        index += paths
        changes.append(Change(letter, names[-1], names[0] if paths == 2 else None))
    return tuple(changes)


def workspace_changes(workspace: Path, pr: PrRange) -> tuple[Change, ...]:
    """Check that *workspace* holds the history *pr* names, and list what changed between its commits.

    Refused with :class:`~scaneval.adapters.base.AdapterError`, before any scanner runs, when a
    commit is missing, when ``HEAD`` is not at head, when the workspace holds any modified or
    untracked path, or when the two commits differ in nothing: a review of an empty change is not a
    review, and the runner refuses to prepare one, so one that arrives here means the input was not
    prepared the way the request says. Renames are detected (``-M``), so a moved file is one
    ``R`` entry and not a deletion plus an addition; the paths present at head are the same
    either way.

    The result is git's account of two commits, in git's order. It says which paths changed, not
    that any of them is worth reading, and not how a scanner will treat them.
    """
    for label, commit in (("base", pr.base), ("head", pr.head)):
        code, _ = _git(workspace, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}", allow=(0, 1))
        if code != 0:
            raise AdapterError(f"the scanner's workspace holds no commit {commit[:12]} for the request's {label}: "
                               "the synthetic PR history it names is not there")
    _, printed = _git(workspace, "rev-parse", "HEAD")
    if printed.decode("ascii", errors="replace").strip() != pr.head:
        raise AdapterError("the scanner's workspace is not at the request's head commit, so a review of that "
                           "change would read a different tree")
    _, dirty = _git(workspace, "status", "--porcelain", "--untracked-files=all")
    if dirty.strip():
        raise AdapterError("the scanner's workspace holds modified or untracked paths; the request names a "
                           "clean two-commit history")
    _, raw = _git(workspace, "diff", "--name-status", "-z", "-M", "--no-ext-diff", "--no-textconv",
                  pr.base, pr.head, "--")
    changes = _parse_name_status(raw)
    if not changes:
        raise AdapterError("git reports no change between the request's base and head commits, so there is "
                           "nothing for a PR review to read")
    return changes
