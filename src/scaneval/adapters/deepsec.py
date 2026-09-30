"""Third-party DeepSec adapter: run the product unchanged, read only what it wrote down.

DeepSec (``vercel-labs/deepsec``) is not ours and is never modified. It is a two-stage
scanner: ``scan`` runs regex matchers and records candidate sites, ``process`` hands
batches of those files to an agent built on the Claude Agent SDK, and ``export`` renders
the findings the agent produced. Each stage writes its own records under ``data/``, and
the agent stage leaves a Claude Code transcript behind for every session it opened. Those
two on-disk traces are the whole of what this adapter can observe: it injects nothing,
wraps no model client, and patches no part of the product.

Everything here follows from that. The events this adapter emits carry
``metadata.source: "harness_record"`` because they are read off DeepSec's own files after
the fact, not seen as they happened, and the events derived from a Claude Code transcript
carry whatever source :mod:`scaneval.collectors.claude_code` stamps on them. A model
request is reconstructed from an ``analysisHistory`` entry, so retries inside the SDK are
invisible and ``retries_observable`` is false. The numbers on one file are that file's
*share* of a batch, which is why every aggregate this module builds is a sum over the
files that name one ``agentSessionId`` and carries ``aggregation:
"sum_of_per_file_shares"`` saying so. :func:`capture_status` states the per-category
availability, checked against a frozen matrix in the adapter tests.

The private workspace. DeepSec resolves ``deepsec.config.ts`` from the current working
directory, walking up, and writes ``data/`` beside it. So this adapter builds a workspace
of its own inside the run's raw output directory: a ``package.json``, a generated config
declaring exactly one project whose root is the exported source, no plugins, and a
``node_modules`` symbolic link to the operator's installed DeepSec so the config's
``import ... from "deepsec/config"`` resolves. Nothing is written to that installation,
and the operator's own workspace, its config, and its ``data/`` are never read or
touched. The link is cut on the way into the bundle by
:func:`scaneval.execution._privatize`, which is what should happen to it: the bundle keeps
the config and the records, not a live pointer into a node_modules tree.

Every path this adapter reads after the DeepSec process starts is a path DeepSec could
have replaced, and any component of it can be a symbolic link. So each read goes through
the same :class:`~scaneval.adapters.llm_harness.Enclosure` and
:func:`~scaneval.adapters.llm_harness.read_record` the own-harness adapter uses, with the
boundary captured before the first process starts. A path that resolves out is refused and
counted, never followed; a named pipe left where a record belongs is refused rather than
blocking the invocation forever.

What is not copied, and why. The own-harness adapter copies records into the raw directory
because the harness writes them inside a workspace that is deleted when the scan returns.
DeepSec's workspace *is* the raw directory, so its ``data/`` tree is already staged where
the bundle wants it: it is registered as artifacts in place rather than duplicated beside
itself. The reads are hardened exactly the same way either path would need.

Status, exactly. A non-zero exit from any of the three steps is an error, named by the step
it came from; a step that ran out of the shared timeout budget is a timeout; an export this
adapter cannot read is an error and never an empty successful scan. A run whose records
report a file left in ``status: "error"``, a parse-failure dump under ``debug/``, or an
agent refusal is ``partial`` with code ``deepsec_batches_failed``: part of the input
reached no verdict, so the scan cannot stand as a complete or quiet observation of it.

PR mode. A request whose ``input.mode`` is ``pr`` is a review of the change between two commits
of the workspace's own history (:mod:`scaneval.adapters.pr`), run through DeepSec's own direct
mode: ``process --diff <base>..<head>`` in place of the ``scan`` and ``process`` pair, then
``export``. DeepSec itself lists the files that range changed (``git diff --name-only
--diff-filter=AMRC``, so no deletion), drops any matching its default ignore filter, runs its regex
scan over just those and investigates each. Which files it dropped is DeepSec's scope and not a
failure, and this adapter says which: before the scanner starts it asks git for what changed, and
afterwards names the changed paths that got no file record. ``--limit`` has no effect in direct
mode (2.3.10 never passes it on), so it is not passed and the run says so.

Two kinds of drop are not DeepSec's scope, and both come from its listing and not from the files.
The listing is git's plain one (no ``-z``); DeepSec trims each line of it and keeps only the
entries that name an existing file. So a path whose name git prints quoted (a non-ASCII name, or
one holding a quote, a backslash or a control character) is never investigated, whatever its
ignore filter says: the entry DeepSec holds is the quoted spelling, which names nothing. Nor is a
path whose name begins or ends with a space, which git prints as it is and the trim then removes:
the entry names another path, or none. Such a path with no file record is a known omission of part
of the change, so the run is ``partial`` with code ``scope_incomplete``, or an ``error`` when no
file reached a verdict, and never a ``success``, the only status that lets the scoring contract
complete a control and grant it quiet credit. Its bundles are unresolved, as when a file is left in
``error``: the claims about the rest are a part delivered, and no claim budget is read off a part.
The error and the note name the path from one list (:class:`DroppedPaths`), and the run says
nothing about it. A path that only the ignore filter dropped stays a note: that is DeepSec's own
scope.

Direct mode exits 1 for three different reasons (a run that produced findings, a batch that
errored, an exhausted quota) and also for a runtime failure such as an unresolvable range, so an
exit 1 is not fatal here and is not innocent either. The run goes on to export, and what an exit 1
means is read from DeepSec's own records: findings, files left in ``error`` or unfinished, a
parse-failure dump. An exit 1 that none of those explains is an ``error`` naming the step. What
DeepSec prints is used to name the reason, never to decide the status, because text an agent's
output can reach must not be able to turn a failure into a success. A run stopped by an exhausted
quota, with an errored batch, or with a changed path DeepSec could not list (above) is ``partial``
when some file still reached a verdict and an ``error`` when none did. "Nothing to process" is a
completed empty review only with exit 0, no file record, no changed path DeepSec could not list,
and DeepSec's own statement that it found nothing to do; the same silence without that statement
is an error.
"""

from __future__ import annotations

from importlib import import_module
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, NamedTuple, Sequence

from ..collectors import EXTERNAL_PREFIX, relocate_paths, workspace_path
from ..execution import list_directory
from ..kinds import kind_for_harness_class
from ..observer import Observer, create_jsonl_sink
from .base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command
from .llm_harness import Enclosure, read_record
from .pr import Change, pr_range, workspace_changes


ARTIFACT_EXPORT = "deepsec-export"
# The module WP-D owns. Resolved by name at call time so this adapter loads, and a scan
# without transcript import still runs, on a checkout where the collectors are absent.
COLLECTOR_MODULE = "scaneval.collectors.claude_code"
DEFAULT_PROJECTS_DIR = "~/.claude/projects"
# DeepSec's own rule for a project id, from resolve-project-id.ts in 2.3.10. The id names a
# directory under data/, so a value it would refuse must be refused here rather than sent.
PROJECT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# ``export`` writes the severity into the title it renders; the claim keeps the severity in
# its own field, so the rendered prefix is removed rather than repeated inside the allegation.
TITLE_SEVERITY = re.compile(r"^\[(?:CRITICAL|HIGH|MEDIUM|HIGH_BUG|BUG|LOW)\]\s*")
# A claim location has to be a relative path inside the scanned tree. Leading "./" segments
# name the same file, so they are removed; nothing else about a path is rewritten.
LEADING_DOT_SEGMENTS = re.compile(r"^(?:\./+)+")
# How much of a DeepSec description a claim carries as evidence. The whole of it stays in the
# export artifact the claim cites, so this bounds the record rather than dropping evidence.
EVIDENCE_LIMIT = 4000
# What a Claude Agent SDK session id may look like before it is handed to transcript
# discovery. A UUID satisfies it; a glob, a path, and anything with whitespace do not.
SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$")
# Stated rather than left implicit in the class above, so what is refused is visible.
SESSION_ID_FORBIDDEN = re.compile(r"[*?\[\]{}!~^/\\\s]")
# The capture-status keys Contract 3 names, in the order the guide tables them.
CAPTURE_KEYS = ("model_requests", "model_responses", "tool_calls", "context_selection",
                "finding_candidate", "finding_submitted", "finding_validation",
                "finding_filtered")
THINKING_LEVELS = ("minimal", "low", "medium", "high", "xhigh")
AGENTS = ("claude", "codex", "pi")
# What DeepSec 2.3.10's direct-mode ``process`` prints when a run ends (process.ts and quota-message.ts
# in its bundle). It colors its output whether or not stdout is a terminal, so the escape sequences
# come off before anything is matched.
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
NOTHING_TO_PROCESS = re.compile("^Nothing to process \u2014 exit 0\\.$", re.MULTILINE)
QUOTA_STOPPED = re.compile("^\u2718 Stopped: (.+) exhausted$", re.MULTILINE)
PROCESS_FINDINGS = re.compile(r"^ *Findings: ([0-9]+)$", re.MULTILINE)
PROCESS_ERRORED_BATCHES = re.compile(r"^ *Errored batches: ([0-9]+)$", re.MULTILINE)
# The summary is the last thing DeepSec prints, so the end of the file is what is read for it.
PROCESS_OUTPUT_TAIL = 16384
# Direct mode's exit for findings, an errored batch and an exhausted quota, and for a runtime failure.
DIRECT_MODE_EXIT = 1


def _shape(value: Any) -> str:
    return type(value).__name__


def collector() -> tuple[Any, Any] | None:
    """``(find_transcripts, import_transcript)`` from the Claude Code collector, or ``None``.

    Resolved by name at call time rather than imported at module scope for two reasons. The
    collector is built by a different work package, so this adapter has to load and scan on a
    checkout that does not have it yet, with transcript import reported as unavailable rather
    than as a crash. And a test can replace this function to drive the import path without a
    real transcript on disk.
    """
    try:
        module = import_module(COLLECTOR_MODULE)
    except ImportError:
        return None
    find = getattr(module, "find_transcripts", None)
    load = getattr(module, "import_transcript", None)
    if find is None or load is None:
        return None
    return find, load


def session_id_usable(session_id: Any) -> bool:
    """Whether an ``agentSessionId`` may be handed to transcript discovery.

    The id comes off a record the scanner wrote, and discovery looks a transcript up by it. An
    id interpolated into a glob made ``*`` match every session on the machine, so a record
    could pull transcripts of unrelated runs into this run's trace; discovery is literal now,
    and this is the other half of the same fix, at the boundary where the value enters.

    The collector's own :func:`session_id_is_usable` is the rule when it is installed, so the
    two cannot drift. The fallback is the same rule spelled here: a Claude Agent SDK session id
    is a UUID, so it starts alphanumeric, continues in ``[A-Za-z0-9_-]``, runs 8 to 128
    characters, and carries no glob metacharacter, no path separator and no whitespace — which
    the character class already excludes, and which :data:`SESSION_ID_FORBIDDEN` restates so a
    reader can see what is being refused rather than infer it.
    """
    if not isinstance(session_id, str):
        return False
    try:
        helper = getattr(import_module("scaneval.collectors"), "session_id_is_usable", None)
    except ImportError:
        helper = None
    if helper is not None:
        return bool(helper(session_id))
    return bool(SESSION_ID.match(session_id)) and not SESSION_ID_FORBIDDEN.search(session_id)


def kind_for_slug(slug: str | None) -> str:
    """The canonical kind for a DeepSec ``vulnSlug``.

    DeepSec spells its matcher slugs with hyphens (``sql-injection``) where the kind mapping
    keys them without separators, so the separators are removed before the lookup. An
    ``other-`` slug the agent minted for a novel finding, and any slug the mapping does not
    know, stays ``unmapped`` and keeps its native identity on the claim.
    """
    if not slug:
        return kind_for_harness_class(None)
    return kind_for_harness_class(re.sub(r"[-_\s]", "", str(slug)))


def claim_path(raw: str) -> tuple[str, str]:
    """``(path relative to the scanned tree, "")``, or ``(raw, reason)`` when it is not one.

    DeepSec records ``filePath`` relative to the root it was handed and with forward slashes,
    so the only normalization needed is dropping leading ``./`` segments, which name the same
    file. A value that cannot be expressed as a relative path inside the tree is not rewritten
    at all: an absolute path, one holding a NUL byte, one that leaves the tree through ``..``,
    and one that names nothing once its dot segments are removed come back verbatim with the
    reason they are unusable, for the caller to count as import loss and report.
    """
    if not isinstance(raw, str) or not raw:
        return str(raw), "it is not a non-empty string"
    if "\x00" in raw:
        return raw, "it holds a NUL byte, which cannot name a file"
    if raw.startswith("/"):
        return raw, "it is an absolute path"
    remainder = LEADING_DOT_SEGMENTS.sub("", raw)
    segments = [segment for segment in remainder.split("/") if segment not in ("", ".")]
    if not segments:
        return raw, "it names nothing once its dot segments are removed"
    if ".." in segments:
        return raw, "it leaves the scanned tree through a '..' segment"
    return remainder, ""


def portable(path: Path) -> str:
    """*path* with the operator's home directory written as ``~``.

    Every path this adapter puts into a note goes through here. A note is recorded evidence and
    a home directory in one names the operator rather than the run, which Contract 3 forbids of
    an event and this repository's own hygiene check forbids of a published file. ``~`` is the
    portable spelling and the one a reader can act on. A home directory that cannot be resolved
    at all leaves the path as it is: there is nothing to abbreviate against, and an unreadable
    ``HOME`` must not cost the note.
    """
    try:
        home = Path.home()
    except (OSError, RuntimeError):
        return path.as_posix()
    try:
        return ("~" if path == home else "~/" + path.relative_to(home).as_posix())
    except ValueError:
        return path.as_posix()


def workspace_spellings(source_dir: Path) -> tuple[Path, ...]:
    """Every spelling of the scanned workspace a transcript could name it by.

    The path this run handed the scanner and the path the filesystem really stores it at, in
    that order, deduplicated when they are the same.

    Why both. The Claude Agent SDK records its working directory and every file it read under
    the platform's real path: on macOS a workspace handed over as ``/var/folders/.../source``
    appears in the transcript as ``/private/var/folders/.../source``. The collectors compare
    paths textually and never resolve a symbolic link, deliberately, because resolving would
    touch the filesystem the trace is being *read* on rather than the one the run happened on.
    So the caller is the only party that can supply both spellings, and a caller that supplied
    one produced a trace in which every span and every tool input read ``external:<basename>``:
    a real run of this adapter did exactly that, and the coverage attribution downstream could
    join none of it.

    A source directory that cannot be resolved contributes only the spelling it was handed,
    which is the same position this was in before: no worse, and never a failure.
    """
    try:
        resolved = source_dir.resolve()
    except (OSError, ValueError):
        return (source_dir,)
    return (source_dir,) if resolved == source_dir else (source_dir, resolved)


def bounded_tail(path: Path, contained: Path | None, limit: int = 2000) -> str:
    """The last *limit* bytes of one path DeepSec owns, or ``""`` when it cannot be read.

    Every failure message this adapter records quotes a scanner-written stderr file, and the
    scanner can replace that file between the moment its own descriptor closed and the moment
    this reads it. :func:`~scaneval.adapters.base.tail_text` was doing that read, and it follows
    a symbolic link, blocks forever on a named pipe, and reads the whole file into memory before
    keeping the tail: a scanner could therefore choose which host file the bundle quotes, hang
    the invocation with no record that it had happened, or exhaust memory with a large enough
    file. All three are one read, so the fix is one read.

    Three things are proved before a byte is taken, and the first two in the same open, which is
    the rule :func:`~scaneval.execution.read_regular_file` keeps. It must resolve inside this
    run's raw output, which is what *contained* carries (``None`` is a refusal, not a missing
    file). ``O_NOFOLLOW`` refuses a symbolic link and ``O_NONBLOCK`` makes a named pipe fail at
    once rather than wait for a writer that never comes, and :func:`os.fstat` on the descriptor
    that will be read refuses anything that is not a regular file. Then the read is bounded by
    seeking to the last *limit* bytes rather than by slicing the whole file afterwards, so the
    size of what the scanner wrote does not decide how much memory this takes.

    Never raises. A failure costs the quoted tail, never the record of the run, so the caller
    reports its own failure with an empty tail rather than losing the failure it was reporting.
    """
    if contained is None:
        return ""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return ""
    try:
        with os.fdopen(descriptor, "rb") as stream:
            status = os.fstat(stream.fileno())
            if not stat.S_ISREG(status.st_mode):
                return ""
            if status.st_size > limit:
                stream.seek(status.st_size - limit)
            return stream.read(limit).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def record_path(name: str, record: dict, roots: tuple[Path, ...] = ()) -> tuple[str, bool]:
    """The canonical workspace-relative path of one FileRecord, and whether it is external.

    The path comes from where DeepSec *put* the record, not from what the record says about
    itself. ``data/<project>/files/<path>.json`` mirrors the source path under the scanned root,
    and this adapter walked that tree itself, so the relative name it holds is relative by
    construction and cannot carry an absolute prefix, a ``..`` segment, or a home directory. The
    record's own ``filePath`` is scanner-written text: it was being published verbatim into
    ``batch_paths`` and into refusal metadata, where an absolute path would have put the run's
    workspace, and with it the operator's home, into a trace. Contract 3 forbids that of any
    event, so no event is built from that text any more.

    A name that still cannot be expressed as a path inside the tree, and a ``filePath`` that
    disagrees with it in a way that leaves the tree, become ``external:<basename>``, which the
    caller counts in ``metadata.external_paths``: the event then says a path was observed and
    says nothing about whose machine it named. *roots* is offered so an absolute name can be
    relocated against the workspace spellings first, the same way the collectors relocate one.
    """
    stem = name[:-5] if name.endswith(".json") else name
    path, unusable = claim_path(stem)
    if not unusable:
        return path, False
    if roots:
        relocated, external = workspace_path(stem, roots)
        if relocated and not external:
            return relocated, False
    return EXTERNAL_PREFIX + (PurePosixPath(stem.replace("\\", "/")).name or "record"), True


def line_span(values: Any) -> tuple[int | None, int | None]:
    """``(min, max)`` of the 1-based line numbers in *values*, or ``(None, None)``.

    A finding with no usable line number is recorded file-level rather than given an invented
    span: DeepSec reports the lines its agent cited, and a claim must not say more.
    """
    if not isinstance(values, list):
        return None, None
    numbers = [int(value) for value in values
               if isinstance(value, int) and not isinstance(value, bool) and value >= 1]
    if not numbers:
        return None, None
    return min(numbers), max(numbers)


class Settings(NamedTuple):
    """One validated DeepSec system configuration."""

    root: Path
    binary: Path
    agent: str
    model: str
    thinking_level: str | None
    limit: int | None
    batch_size: int | None
    concurrency: int
    max_turns: int | None
    projects_dir: Path
    claude_code_executable: str | None
    project_id: str | None
    configured_root: str


def _text(spec: SystemSpec, key: str, default: str | None = None, *,
          required: bool = False, allowed: tuple[str, ...] = ()) -> str | None:
    value = spec.config.get(key, default)
    if value is None or value == "":
        if required:
            raise AdapterError(f"deepsec config.{key} is required")
        return None
    if not isinstance(value, str):
        raise AdapterError(f"deepsec config.{key} must be a string, got a {_shape(value)}")
    # A NUL byte reaches subprocess as a raw ValueError from the C layer, which would leave the
    # adapter as something other than the setup failure it is.
    if "\x00" in value:
        raise AdapterError(f"deepsec config.{key} contains a NUL byte")
    if allowed and value not in allowed:
        raise AdapterError(f"deepsec config.{key} must be one of {list(allowed)}, got {value!r}")
    return value


def _integer(spec: SystemSpec, key: str, default: int | None, minimum: int) -> int | None:
    value = spec.config.get(key, default)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AdapterError(f"deepsec config.{key} must be an integer, got a {_shape(value)}")
    try:
        number = int(str(value).strip())
    except ValueError as exc:
        raise AdapterError(f"deepsec config.{key} must be an integer, got {value!r}") from exc
    if number < minimum:
        raise AdapterError(f"deepsec config.{key} must be at least {minimum}, got {number}")
    return number


def settings(spec: SystemSpec) -> Settings:
    """Validate one system configuration, resolving every path before anything runs.

    ``deepsec_root`` is expanded and resolved the way the own-harness adapter resolves its
    harness root and for the same reason: the value is both the prefix of the executable path
    and the target of a symbolic link this adapter creates, so a relative one would be applied
    against two different directories. Every value is checked here, before a process starts, so
    a bad configuration is a setup failure rather than a scan whose output can be interpreted.
    """
    configured_root = _text(spec, "deepsec_root", required=True) or ""
    root = Path(configured_root).expanduser()
    try:
        root = root.resolve()
    except (OSError, ValueError) as exc:
        raise AdapterError(f"deepsec config.deepsec_root could not be resolved: {exc}") from exc
    if not root.is_dir():
        raise AdapterError(f"deepsec workspace root does not exist: {root}")
    binary = root / "node_modules" / ".bin" / "deepsec"
    project_id = _text(spec, "project_id")
    if project_id is not None and not PROJECT_ID.match(project_id):
        raise AdapterError(f"deepsec config.project_id {project_id!r} is not a project id DeepSec "
                           f"accepts (it must match {PROJECT_ID.pattern})")
    projects_dir = Path(_text(spec, "claude_projects_dir", DEFAULT_PROJECTS_DIR) or
                        DEFAULT_PROJECTS_DIR).expanduser()
    return Settings(
        root=root,
        binary=binary,
        agent=_text(spec, "agent", "claude", allowed=AGENTS) or "claude",
        model=_text(spec, "model", required=True) or "",
        thinking_level=_text(spec, "thinking_level", allowed=THINKING_LEVELS),
        limit=_integer(spec, "limit", None, 1),
        batch_size=_integer(spec, "batch_size", None, 1),
        concurrency=_integer(spec, "concurrency", 1, 1) or 1,
        max_turns=_integer(spec, "max_turns", None, 1),
        projects_dir=projects_dir,
        claude_code_executable=_text(spec, "claude_code_executable"),
        project_id=project_id,
        configured_root=configured_root,
    )


def project_id_for(request: dict, configured: str | None) -> str:
    """The DeepSec project id for one invocation.

    DeepSec names a data directory after the project id and refuses anything outside
    ``[A-Za-z0-9][A-Za-z0-9._-]{0,63}``. The scan request carries no snapshot id, only the
    hash of the exported input, so the default id is derived from that hash: it is
    deterministic, it names the exact bytes that were scanned, and it is a valid id. An
    operator who wants their own name sets ``config.project_id``.
    """
    if configured:
        return configured
    digest = str(request.get("input", {}).get("tree_hash", ""))
    digest = digest.split(":")[-1][:16] or "unknown"
    return f"scaneval-{digest}"


def workspace_config(project_id: str, source_dir: Path, agent: str, model: str) -> str:
    """The ``deepsec.config.ts`` this run hands DeepSec: one project, no plugins, local auth.

    ``ai: {mode: "local", provider: "local"}`` is the route that uses the operator's own CLI
    login rather than an API key, which is how the pilot is configured and why no credential
    is written into this file or into the recorded system configuration. No plugin is declared,
    so only DeepSec's built-in matchers run and the scan is reproducible from this file alone.
    """
    resolved_agent = "claude-agent-sdk" if agent == "claude" else agent
    return (
        "// Generated by ScanEval's deepsec adapter for one invocation. Do not edit.\n"
        '// One project, no plugins, local CLI auth. Everything here is recorded in the bundle.\n'
        'import { defineConfig } from "deepsec/config";\n'
        "\n"
        "export default defineConfig({\n"
        f"  defaultAgent: {json.dumps(resolved_agent)},\n"
        f"  defaultModel: {json.dumps(model)},\n"
        '  ai: { mode: "local", provider: "local" },\n'
        "  projects: [\n"
        f"    {{ id: {json.dumps(project_id)}, root: {json.dumps(str(source_dir))} }},\n"
        "  ],\n"
        "  plugins: [],\n"
        "});\n"
    )


def build_workspace(raw_dir: Path, source_dir: Path, project_id: str, config: Settings) -> Path:
    """Create the private DeepSec workspace inside *raw_dir* and return it.

    Everything DeepSec needs to run is here and nowhere else: the generated config, a minimal
    ``package.json``, and a ``node_modules`` symbolic link to the operator's installation so
    ``import { defineConfig } from "deepsec/config"`` resolves from the config's own directory.
    The link is the only thing in this tree that points outside the bundle, it is never written
    through, and :func:`scaneval.execution._privatize` cuts it when the staged output enters
    the bundle, recording where it pointed.
    """
    workspace = raw_dir / "deepsec-workspace"
    try:
        workspace.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise AdapterError(f"the deepsec workspace under {raw_dir} could not be created: {exc}") from exc
    try:
        (workspace / "package.json").write_text(json.dumps({
            "name": "scaneval-deepsec-workspace",
            "version": "0.0.0",
            "private": True,
            "type": "module",
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (workspace / "deepsec.config.ts").write_text(
            workspace_config(project_id, source_dir, config.agent, config.model), encoding="utf-8")
        os.symlink(config.root / "node_modules", workspace / "node_modules",
                   target_is_directory=True)
    except OSError as exc:
        raise AdapterError(f"the deepsec workspace under {raw_dir} could not be prepared: {exc}") from exc
    return workspace


# DeepSec's own FileRecord status enum, from the schema in its 2.3.10 bundle. ``analyzed`` is
# the only value that says the AI stage finished with the file: ``pending`` has not started,
# ``processing`` is a run still holding it, and ``error`` is a run that crashed on it. DeepSec's
# own metrics count everything but ``analyzed`` as not done, and so does this.
RECORD_STATUSES = ("pending", "processing", "analyzed", "error")
FINISHED_STATUS = "analyzed"
UNFINISHED_STATUSES = ("pending", "processing")


class RecordStatuses(NamedTuple):
    """How many FileRecords this run finished, left unfinished, failed on, and cannot read.

    ``unfinished`` is every record in a state DeepSec's own enum says is not done: ``pending``
    for one the AI stage never reached, and ``processing`` for one a run was still holding when
    it ended. Only ``pending`` used to count, so a record left mid-flight read as a finished
    one and a run that abandoned a file in flight returned ``success`` with its bundles
    resolved, which is quiet credit for a file no verdict was ever reached on.

    ``invalid`` is a record whose status is missing, is not a string, or is a value the enum
    does not have. That is not a state to interpret: this adapter cannot say whether the file
    was finished, so it says so, and the run is partial with its bundles unresolved rather than
    guessing in the direction that earns credit.
    """

    finished: int
    unfinished: tuple[str, ...]
    errored: tuple[str, ...]
    invalid: tuple[tuple[str, str], ...]

    @property
    def incomplete(self) -> int:
        """Records this run cannot stand as a complete observation of."""
        return len(self.unfinished) + len(self.invalid)


def record_statuses(files: tuple[tuple[str, dict], ...]) -> RecordStatuses:
    """Classify every FileRecord by DeepSec's own status enum, refusing to guess at the rest."""
    finished = 0
    unfinished: list[str] = []
    errored: list[str] = []
    invalid: list[tuple[str, str]] = []
    for name, record in files:
        status = record.get("status") if isinstance(record, dict) else None
        if status == FINISHED_STATUS:
            finished += 1
        elif status in UNFINISHED_STATUSES:
            unfinished.append(f"{name} ({status})")
        elif status == "error":
            errored.append(name)
        elif status is None:
            invalid.append((name, "the record carries no status at all"))
        elif not isinstance(status, str):
            invalid.append((name, f"the status is a {_shape(status)}, not a string"))
        else:
            invalid.append((name, f"the status {status!r} is not one DeepSec declares "
                                  f"({', '.join(RECORD_STATUSES)})"))
    return RecordStatuses(finished, tuple(sorted(unfinished)), tuple(sorted(errored)),
                          tuple(sorted(invalid)))


class Records(NamedTuple):
    """Everything this adapter could read out of one run's ``data/<project>`` tree.

    ``failures`` is every record that could not be listed or read, each with its reason. A
    failure is never an absent record: a directory this cannot enumerate is a failed
    observation, and the caller reports it rather than treating the tree as smaller than it is.
    """

    files: tuple[tuple[str, dict], ...]
    runs: tuple[tuple[str, dict], ...]
    debug: tuple[str, ...]
    artifacts: tuple[dict, ...]
    failures: tuple[str, ...]


def _json_records(directory: Path, enclosure: Enclosure, *, suffix: str = ".json",
                  ) -> tuple[list[tuple[str, dict, Path]], list[str]]:
    """Every record under *directory* as ``(relative name, payload, path)``, and the failures.

    The name, the payload and the path travel together in one tuple rather than in three lists
    sorted separately: the artifact this adapter registers for a record must be the file that
    record was read from, and two lists sorted by different keys made that pairing depend on
    the order the filesystem happened to hand back.

    The walk is explicit rather than :meth:`Path.rglob`, which swallows the error a directory
    that cannot be listed raises and would report it as holding nothing. Every read goes
    through :func:`~scaneval.adapters.llm_harness.read_record`, so a record that is a symbolic
    link, that resolves outside this run's raw output, or that is not a regular file is a
    counted failure rather than a followed path or a blocked invocation.

    One rule for every entry this walk refuses, and it is the whole point of counting them: a
    path this cannot safely read is import loss, never an absent record. A symbolic link was
    the hole. A link to a record file was already refused by the read and counted; a link
    standing where a record *directory* belongs matched neither branch and was passed over in
    silence, so every record behind it vanished and the run read as a complete scan of what
    remained. Replacing one directory under ``files/`` turned a two-file scan from partial into
    success. Every refusal is in ``failures`` now, named with its reason, and the caller makes
    the run partial with its bundles unresolved.
    """
    records: list[tuple[str, dict, Path]] = []
    failures: list[str] = []
    if enclosure.write(directory) is None:
        return records, [f"{directory.name}/: the directory does not resolve inside this run's "
                         "raw output; nothing in it was read"]
    pending = [directory]
    while pending:
        current = pending.pop()
        try:
            entries = list_directory(current)
        except FileNotFoundError:
            continue
        except OSError as exc:
            failures.append(f"{current.name}/: the directory could not be listed "
                            f"({exc.strerror or exc}); an unknown number of records was not read")
            continue
        for entry in sorted(entries, key=lambda item: item.name):
            path = Path(entry.path)
            relative = path.relative_to(directory).as_posix()
            if entry.is_symlink():
                # Refusing to follow it is right; treating it as absent is not. A symbolic
                # link where a record directory belongs hid every record behind it, and the
                # run read as a complete scan of the files it could still see: replacing one
                # directory under ``files/`` turned a two-file scan from partial into success.
                # Counted here, it is import loss, which makes the run partial with its
                # bundles unresolved.
                failures.append(f"{relative}: the entry is a symbolic link; it was not followed "
                                "and nothing behind it was read")
                continue
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
                continue
            if not path.name.endswith(suffix):
                continue
            if not entry.is_file(follow_symlinks=False):
                # A named pipe or a socket wearing a record's name. Nothing opens it, and it is
                # not an absent record either.
                failures.append(f"{relative}: the entry is not a regular file, so the record it "
                                "names was not read")
                continue
            data, failure = read_record(path, enclosure.write(path))
            if data is None:
                failures.append(f"{relative}: the record could not be read ({failure})")
                continue
            try:
                payload = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                failures.append(f"{relative}: the record is not readable JSON ({exc})")
                continue
            if not isinstance(payload, dict):
                failures.append(f"{relative}: the record is a {_shape(payload)}, not an object")
                continue
            records.append((relative, payload, path))
    return sorted(records, key=lambda item: item[0]), failures


def read_records(data_dir: Path, enclosure: Enclosure) -> Records:
    """Read one project's ``files/``, ``runs/`` and ``debug/`` trees and register them.

    Artifacts are registered where DeepSec wrote them. The workspace is inside this run's raw
    output already, so copying the tree beside itself would double every byte in the bundle
    and prove nothing the read discipline above does not already prove.
    """
    files, file_failures = _json_records(data_dir / "files", enclosure)
    runs, run_failures = _json_records(data_dir / "runs", enclosure)
    artifacts = [{"id": f"deepsec-file/{name}", "path": path} for name, _record, path in files]
    artifacts += [{"id": f"deepsec-run/{name}", "path": path} for name, _record, path in runs]
    debug: list[str] = []
    debug_failures: list[str] = []
    debug_dir = data_dir / "debug"
    if enclosure.write(debug_dir) is None:
        debug_failures.append("debug/: the directory does not resolve inside this run's raw output")
    else:
        try:
            for entry in list_directory(debug_dir):
                path = Path(entry.path)
                if not entry.is_file(follow_symlinks=False):
                    continue
                debug.append(path.name)
                artifacts.append({"id": f"deepsec-debug/{path.name}", "path": path})
        except FileNotFoundError:
            pass
        except OSError as exc:
            debug_failures.append(f"debug/: the directory could not be listed "
                                  f"({exc.strerror or exc}); parse-failure dumps may be missing")
    # Whatever else the project directory holds at its top level: project.json, the tech.json a
    # real scan writes beside it, and any INFO.md or config.json the operator supplied. Listed
    # rather than named one by one, because DeepSec adds files here between versions and a
    # record that only registered the ones this adapter knew about would quietly omit them.
    try:
        for entry in list_directory(data_dir):
            path = Path(entry.path)
            if entry.is_file(follow_symlinks=False) and enclosure.write(path) is not None:
                artifacts.append({"id": f"deepsec-project/{path.name}", "path": path})
    except FileNotFoundError:
        pass
    except OSError as exc:
        debug_failures.append(f"{data_dir.name}/: the project directory could not be listed "
                              f"({exc.strerror or exc})")
    return Records(tuple((name, record) for name, record, _path in files),
                   tuple((name, record) for name, record, _path in runs),
                   tuple(sorted(debug)), tuple(artifacts),
                   tuple(file_failures + run_failures + debug_failures))


class Refusal(NamedTuple):
    """One agent refusal, reduced to what an event may carry.

    ``code`` is a closed value derived from the *structure* of DeepSec's ``RefusalReport`` and
    never from classifying its prose: ``refused`` when it says so, ``refused_with_skipped_files``
    when it also lists the files it skipped. That code and the file path are the whole of what
    reaches metadata.

    A clipped prefix of the reason used to go there too. It was still model prose: a 120-
    character window onto a sentence the model wrote, which can open mid-way through a line of
    source it was quoting. Metadata is read by tooling and printed in summaries, and neither
    source nor an operator's machine belongs in it at any length, so the window is gone rather
    than narrowed.

    ``reason`` is the reason with every absolute path relocated against the workspace, and it
    goes only in ``content``, which the observer stores in content mode and drops in metadata
    mode. Relocation happens even there because a home directory may not appear in an event at
    all, whatever the recording mode.
    """

    path: str
    code: str
    reason: str
    external: bool


class Session(NamedTuple):
    """One agent session, aggregated over the files that carry its share of a batch.

    DeepSec writes each file's *share* of a batch onto that file's own ``AnalysisEntry``: the
    turn count, the API duration, the cost and the token counts of one batch are divided among
    the files in it, and every file in the batch names the same ``agentSessionId``. Summing the
    shares of one session therefore reconstructs the batch, which is why every event built from
    this carries ``aggregation: "sum_of_per_file_shares"``. A sum is not a measurement of a
    single model call and must never be read as one.

    ``durationMs`` is summed like the rest. An older DeepSec wrote it whole onto every file of
    the batch instead, and a record from that version was read as evidence that the installed
    one does too; it does not. The installed 2.3.10 divides it, and a real run of this adapter
    recorded 45316.33 ms on each of a batch's three files for a batch its own stdout timed at
    135.9 seconds. Taking a maximum reported that batch as having taken a third as long as it
    did. ``duration_suspect`` marks the shape the older version produced, so a bundle read from
    one says the number may be a duplicate rather than a share; it never changes the number,
    because a guess at a different total would be worse than a flagged one.

``correlation`` says how the call boundary was arrived at, and only one of its three values
    means DeepSec supplied it.

    ``agent_session_id`` is DeepSec's own. ``missing_session_id`` is an entry that carried none:
    those used to share one empty key, so unrelated batches were merged into a single call with
    their paths, turns, cost and tokens added together, which is correlation being invented at
    exactly the moment the native identifier was absent. ``invalid_session_id`` is an entry
    whose id is not one transcript discovery may be handed — the value is scanner-written, and
    an id like ``*`` reached a glob and imported the transcripts of unrelated sessions. Both of
    the latter get their own per-entry group and are never passed to discovery.
    """

    run_id: str
    session_id: str
    model: str | None
    paths: tuple[str, ...]
    num_turns: float
    cost_usd: float
    # The batch wall clock, summed from the per-file shares like everything else.
    duration_ms: float
    duration_api_ms: float
    usage: dict[str, int]
    refusals: tuple[Refusal, ...]
    correlation: str
    key: str
    external_paths: int
    # True when every entry of this group carried the same whole-number ``durationMs`` while
    # its other shares were fractional, which is how the older DeepSec wrote a duplicated wall
    # clock. The sum is still the sum; this only says a reader should not trust it.
    duration_suspect: bool = False

    @property
    def call_id(self) -> str:
        """The logical invocation this group stands for, stable across a re-read."""
        return f"deepsec/{self.key}"

    @property
    def correlated(self) -> bool:
        """Whether DeepSec itself named this call, which is what discovery may be given."""
        return self.correlation == "agent_session_id"


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    if value != value or value in (float("inf"), float("-inf")):  # NaN and the infinities
        return 0.0
    return float(value)


def _refusal(entry: dict, path: str, external: bool, roots: tuple[Path, ...]) -> "Refusal | None":
    """One :class:`Refusal` from an ``AnalysisEntry``, or ``None`` when it refused nothing.

    The code comes from the report's shape and never from reading its prose, because a
    classifier over model text would be this adapter inventing a category DeepSec did not
    record. The prose itself is kept only for ``content``, with every absolute path relocated
    against the workspace first: a refusal reason is free text a model wrote, it can quote
    source and name a machine, and Contract 3 allows neither into an event's paths at any
    recording mode and no source at all into metadata.
    """
    refusal = entry.get("refusal")
    if not isinstance(refusal, dict) or refusal.get("refused") is not True:
        return None
    skipped = refusal.get("skipped")
    code = "refused_with_skipped_files" if isinstance(skipped, list) and skipped else "refused"
    raw = refusal.get("reason")
    reason = raw if isinstance(raw, str) else ""
    return Refusal(path, code, relocate_paths(reason, roots) if roots else reason, external)


def _duplicated_duration(durations: list[float], fractional: bool) -> bool:
    """Whether this group's ``durationMs`` looks repeated rather than divided.

    The shape an older DeepSec wrote: the same whole-number wall clock on every file of the
    batch while every other number on those files was a fraction of one. It is a heuristic and
    it only ever sets a flag: the sum stays the sum, because inventing a different total from a
    guess about which version wrote the record would be worse than reporting one with a caveat.
    A single-entry group is never suspect, since one share and one whole are the same number.
    """
    if len(durations) < 2 or not fractional:
        return False
    first = durations[0]
    return first > 0 and first == int(first) and all(value == first for value in durations)


def sessions_from(files: tuple[tuple[str, dict], ...],
                  roots: tuple[Path, ...] = ()) -> tuple[Session, ...]:
    """Group every ``analysisHistory`` entry into the model call it belongs to.

    The grouping key is ``agentSessionId``, which is what DeepSec correlates a batch by and what
    a Claude Code transcript is named after. An entry carrying none is not merged with the other
    entries carrying none: it becomes its own uncorrelated group, keyed by the record it sits on
    and its position in that record's history. Merging them was inventing a call boundary at
    exactly the moment the scanner had failed to record one, and it added the paths, turns, cost
    and tokens of unrelated batches together.

    An id that :func:`session_id_usable` refuses is treated exactly like a missing one and never
    reaches transcript discovery. The value is scanner-written, and discovery used to
    interpolate it into a glob, so a record naming its session ``*`` imported every transcript
    on the machine into this run's trace.

    Paths come from :func:`record_path`, which reads where DeepSec put the record rather than
    what the record says about itself, so no scanner-written absolute path reaches an event. The
    model is kept only when every entry in the group names the same one, because a group whose
    entries disagree about the model has not told us which model ran.
    """
    grouped: dict[str, dict[str, Any]] = {}
    for name, record in files:
        path, external = record_path(name, record, roots)
        history = record.get("analysisHistory")
        if not isinstance(history, list):
            continue
        for index, entry in enumerate(history):
            if not isinstance(entry, dict):
                continue
            run_id = str(entry.get("runId") or "")
            session_id = str(entry.get("agentSessionId") or "")
            if not session_id:
                correlation = "missing_session_id"
            elif not session_id_usable(session_id):
                correlation = "invalid_session_id"
            else:
                correlation = "agent_session_id"
            correlated = correlation == "agent_session_id"
            key = f"{run_id}/{session_id}" if correlated else f"uncorrelated/{path}/{index}"
            bucket = grouped.setdefault(key, {
                "run_id": run_id, "session_id": session_id, "correlation": correlation,
                "models": [], "paths": [], "turns": 0.0, "cost": 0.0, "duration": 0.0,
                "api": 0.0, "usage": {}, "refusals": [], "external": 0,
                "durations": [], "fractional": False})
            model = entry.get("model")
            if isinstance(model, str) and model:
                bucket["models"].append(model)
            if path not in bucket["paths"]:
                bucket["paths"].append(path)
                bucket["external"] += int(external)
            turns, cost = _number(entry.get("numTurns")), _number(entry.get("costUsd"))
            api, duration = _number(entry.get("durationApiMs")), _number(entry.get("durationMs"))
            bucket["turns"] += turns
            bucket["cost"] += cost
            bucket["duration"] += duration
            bucket["api"] += api
            bucket["durations"].append(duration)
            # Whether anything else in this entry was written as a fraction. It is what tells a
            # duplicated whole-number duration apart from a batch of one file whose share
            # happens to be whole.
            bucket["fractional"] = bucket["fractional"] or any(
                value != int(value) for value in (turns, cost, api))
            usage = entry.get("usage")
            if isinstance(usage, dict):
                for source, target in (("inputTokens", "input_tokens"),
                                       ("outputTokens", "output_tokens"),
                                       ("cacheReadInputTokens", "cache_read_input_tokens"),
                                       ("cacheCreationInputTokens", "cache_creation_input_tokens")):
                    share = _number(usage.get(source))
                    bucket["usage"][target] = bucket["usage"].get(target, 0.0) + share
                    bucket["fractional"] = bucket["fractional"] or share != int(share)
            refused = _refusal(entry, path, external, roots)
            if refused is not None:
                bucket["refusals"].append(refused)
    sessions = []
    for key, bucket in sorted(grouped.items()):
        models = bucket["models"]
        sessions.append(Session(
            run_id=bucket["run_id"], session_id=bucket["session_id"],
            model=models[0] if models and len(set(models)) == 1 else None,
            paths=tuple(sorted(bucket["paths"])),
            num_turns=bucket["turns"], cost_usd=bucket["cost"],
            duration_ms=bucket["duration"], duration_api_ms=bucket["api"],
            # Token counts are whole tokens; the per-file shares are fractions of them, so the
            # sum is rounded once, here, rather than written as a fraction of a token.
            usage={name: int(round(value)) for name, value in sorted(bucket["usage"].items())},
            refusals=tuple(bucket["refusals"]), correlation=bucket["correlation"], key=key,
            external_paths=bucket["external"],
            duration_suspect=_duplicated_duration(bucket["durations"], bucket["fractional"])))
    return tuple(sessions)


class Candidate(NamedTuple):
    """One candidate site DeepSec's ``scan`` stage recorded, with every matcher that named it.

    A site, not a matcher hit. Several of DeepSec's regexes routinely fire at the same file,
    class and line: a real scan of one express route produced two ``js-sql-raw`` hits on line 5
    from two different patterns. The candidate id names ``<file>#<vulnSlug>#<first line>``, so
    those hits share one id, and emitting one event each would put two events carrying the same
    ``candidate_id`` and different metadata into the trace. They are merged instead, and
    ``patterns`` and ``hits`` say how many matchers agreed on the site.
    """

    path: str
    slug: str
    lines: tuple[int, ...]
    patterns: tuple[str, ...]
    hits: int
    external: bool = False

    @property
    def candidate_id(self) -> str:
        first = self.lines[0] if self.lines else 0
        return f"{self.path}#{self.slug}#{first}"


def candidates_from(files: tuple[tuple[str, dict], ...],
                    roots: tuple[Path, ...] = ()) -> tuple[Candidate, ...]:
    """Every candidate site in the file records, merged by id, in a stable order.

    The path is :func:`record_path`, so it comes from where DeepSec put the record and never
    from the record's own ``filePath``. A record whose location cannot be expressed inside the
    tree used to be dropped here without a word, which made a candidate disappear from a
    category this adapter calls complete; it becomes ``external:<basename>`` instead and is
    counted, so the trace says a candidate was observed and says nothing about whose machine
    the path named.
    """
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for name, record in files:
        path, external = record_path(name, record, roots)
        entries = record.get("candidates")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            lines = tuple(int(value) for value in (entry.get("lineNumbers") or [])
                          if isinstance(value, int) and not isinstance(value, bool) and value >= 1)
            slug = str(entry.get("vulnSlug") or "unknown")
            key = f"{path}#{slug}#{lines[0] if lines else 0}"
            site = merged.get(key)
            if site is None:
                merged[key] = site = {"path": path, "slug": slug, "lines": [], "patterns": [],
                                      "hits": 0, "external": external}
                order.append(key)
            site["lines"] += [line for line in lines if line not in site["lines"]]
            pattern = str(entry.get("matchedPattern") or "")
            if pattern and pattern not in site["patterns"]:
                site["patterns"].append(pattern)
            site["hits"] += 1
    return tuple(Candidate(merged[key]["path"], merged[key]["slug"],
                           tuple(sorted(merged[key]["lines"])), tuple(merged[key]["patterns"]),
                           merged[key]["hits"], merged[key]["external"]) for key in order)


class DeepsecImport(NamedTuple):
    """One import of a DeepSec ``export --format json`` payload.

    ``lost`` is the number of exported findings that did not become claims. The caller must
    degrade the outcome when it is above zero: a finding DeepSec exported and ScanEval dropped
    is a finding the scanner did report, so the scan can earn neither completeness nor quiet
    credit for that file.
    """

    claims: list[dict]
    notes: list[str]
    lost: int
    findings: list[dict]


def finding_ids(files: tuple[tuple[str, dict], ...]) -> dict[tuple[str, str], str]:
    """``{(file path, title): findingId}`` from the file records.

    ``export --format json`` in DeepSec 2.3.10 renders a finding for an issue tracker and does
    not carry the ``findingId`` the file record holds, so the id a claim reports as its
    ``native_id`` is recovered here. The key is the pair DeepSec itself derives the id from
    (``computeFindingId(projectId, filePath, title)``), which is why it joins exactly.
    """
    index: dict[tuple[str, str], str] = {}
    for name, record in files:
        # Both spellings: the export renders ``metadata.filePath`` from the record's own text,
        # and everything else this adapter publishes is keyed on where DeepSec put the record.
        # Indexing both keeps the join exact without publishing the scanner's text anywhere.
        declared, unusable = claim_path(str(record.get("filePath") or ""))
        stored, external = record_path(name, record)
        paths = [path for path in ((None if unusable else declared),
                                   (None if external else stored)) if path]
        if not paths:
            continue
        findings = record.get("findings")
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            identifier = finding.get("findingId")
            title = finding.get("title")
            if isinstance(identifier, str) and identifier and isinstance(title, str):
                for path in paths:
                    index.setdefault((path, title), identifier)
    return index


def import_export(payload: Any, *, artifact_id: str = ARTIFACT_EXPORT,
                  ids: dict[tuple[str, str], str] | None = None) -> DeepsecImport:
    """Translate an ``export --format json`` payload into atomic claims.

    The payload is a JSON array of exported findings, each carrying the rendered ``title`` and
    ``description`` plus a ``metadata`` object with the file path, the line numbers, the
    severity, the slug and the confidence. Every value read here is type-checked; an entry with
    a shape this cannot read is counted as loss and noted rather than guessed at, so an export
    ScanEval could not fully read never reaches scoring as a clean scan.

    ``primary_location`` spans the lines DeepSec cited: a single line when it cited one, and
    the file alone, with a note, when it cited none. No line range is invented.
    """
    claims: list[dict] = []
    notes: list[str] = []
    findings: list[dict] = []
    lost = 0
    ids = ids or {}
    if not isinstance(payload, list):
        raise AdapterError(f"deepsec export is a {_shape(payload)}, not an array of findings")
    used: set[str] = set()
    for index, entry in enumerate(payload, start=1):
        if not isinstance(entry, dict):
            lost += 1
            notes.append(f"export entry {index} is a {_shape(entry)}, not an object; no claim was recorded")
            continue
        metadata = entry.get("metadata")
        if not isinstance(metadata, dict):
            lost += 1
            notes.append(f"export entry {index} has metadata as a {_shape(metadata)}, not an object; "
                         "no claim was recorded")
            continue
        path, unusable = claim_path(str(metadata.get("filePath") or ""))
        if unusable:
            lost += 1
            notes.append(f"export entry {index}: path {metadata.get('filePath')!r} cannot be expressed as a "
                         f"path inside the scanned tree ({unusable}); no claim was recorded for it and the "
                         "raw export keeps the entry verbatim")
            continue
        raw_title = entry.get("title")
        title = TITLE_SEVERITY.sub("", raw_title).strip() if isinstance(raw_title, str) else ""
        slug = str(metadata.get("vulnSlug") or "")
        allegation = title or f"deepsec:{slug or 'finding'} at {path}"
        start, end = line_span(metadata.get("lineNumbers"))
        location: dict[str, Any] = {"path": path}
        if start is not None and end is not None:
            location["start_line"] = start
            location["end_line"] = end
        else:
            notes.append(f"export entry {index} ({path}) cited no line number; the claim is file-level "
                         "and no range was inferred")
        identifier = ids.get((path, title))
        claim_id = identifier or f"deepsec-{index}"
        while claim_id in used:
            # Two findings DeepSec could not tell apart would otherwise collide into one claim
            # id, which the scan-result contract refuses. Suffixing keeps both claims.
            claim_id = f"{claim_id}.{index}"
        used.add(claim_id)
        claim: dict[str, Any] = {
            "claim_id": claim_id,
            "allegation": allegation,
            "kind": kind_for_slug(slug),
            "primary_location": location,
            "native_rule_id": f"deepsec:{slug or 'unknown'}",
            "raw_artifact_id": artifact_id,
        }
        if identifier:
            claim["native_id"] = identifier
        else:
            notes.append(f"export entry {index} ({path}) could not be joined to a file record, so no "
                         "native finding id is recorded for it")
        severity = metadata.get("severity") or entry.get("severity")
        if isinstance(severity, str) and severity:
            claim["native_severity"] = severity
        description = entry.get("description")
        if isinstance(description, str) and description.strip():
            claim["evidence_text"] = description[:EVIDENCE_LIMIT]
        revalidation = metadata.get("revalidation")
        verdict = revalidation.get("verdict") if isinstance(revalidation, dict) else None
        claims.append(claim)
        findings.append({
            "claim_id": claim_id, "path": path, "slug": slug,
            "severity": str(severity) if isinstance(severity, str) else "",
            "confidence": str(metadata.get("confidence") or ""),
            "run_id": str(metadata.get("runId") or ""),
            "start": start, "end": end,
            # A revalidation DeepSec recorded, or "reported" when it never re-checked this one.
            # A revalidation object carrying no verdict says nothing, so it reads as "reported"
            # rather than as the string "None".
            "status": verdict if isinstance(verdict, str) and verdict else "reported",
        })
    return DeepsecImport(claims, notes, lost, findings)


def capture_status(trace_mode: str, *, transcripts_found: int, sessions: int,
                   batches_failed: int, imports_clean: bool = True,
                   record_failures: int = 0, findings_lost: int = 0,
                   capture_gap: bool = False) -> dict[str, str]:
    """Per-category capture availability for one DeepSec run.

    Nothing here is observed as it happens. DeepSec's records and the Claude Code transcripts
    are read after the run, so a model request is a reconstruction and never better than
    ``partial``: the SDK's own retries happen below anything this adapter can see.

    Every input is something that can make the answer smaller, and each of them used to be
    ignored by a category it plainly affects. ``record_failures`` is FileRecords this run could
    not read, which is exactly the population ``finding_candidate`` claimed to have read in
    full. ``findings_lost`` is exported findings that did not become claims, which is the
    population ``finding_submitted`` stands for. ``capture_gap`` is the observer's own report
    that it dropped an event or degraded one, which no category may claim completeness over: an
    execution record that said ``complete`` on one line while its trace record admitted a hole
    on the next was answering one question twice.

    ``tool_calls`` is the strictest. ``transcripts_found`` counts sessions whose transcript
    import *captured something* — a turn, a tool call, a span — rather than sessions whose
    transcript merely existed: the collector reports an unreadable transcript by returning a
    summary carrying an error event and nothing else, so counting a returned import as a found
    one let a session nobody could read stand behind a ``complete``. ``imports_clean`` is the
    second half of it and is false whenever any import came back short of its file: a malformed
    line, an unmatched tool result, a capture key the importer marked unavailable, a note it
    attached for a refused or truncated read, or a main transcript that produced no model turn
    at all. ``complete`` needs every session captured, every import clean, and no observer gap;
    anything captured but not all of it is ``partial``; nothing captured, and tracing off, is
    ``unavailable``.

    ``finding_validation`` and ``finding_filtered`` are always ``unavailable``. DeepSec's agent
    decides inside one session which candidates become findings and records only its outputs; a
    candidate that produced no finding leaves nothing saying whether it was checked and
    dismissed or never looked at. Read that ``unavailable`` as "this cannot be seen", never as
    "this did not happen".
    """
    if trace_mode not in ("off", "metadata", "content"):
        raise AdapterError(f"unknown trace mode {trace_mode!r}")
    traced = trace_mode != "off"
    if not traced:
        return {key: "unavailable" for key in CAPTURE_KEYS}
    whole = not capture_gap
    if sessions > 0 and transcripts_found >= sessions and imports_clean and whole:
        tools = "complete"
    elif transcripts_found > 0:
        tools = "partial"
    else:
        tools = "unavailable"
    return {
        "model_requests": "partial",
        "model_responses": "partial",
        "tool_calls": tools,
        "context_selection": "partial" if transcripts_found > 0 else "unavailable",
        "finding_candidate": "complete" if (record_failures == 0 and whole) else "partial",
        "finding_submitted": ("complete" if (batches_failed == 0 and findings_lost == 0 and whole)
                              else "partial"),
        "finding_validation": "unavailable",
        "finding_filtered": "unavailable",
    }


class ImportHealth(NamedTuple):
    """What one transcript import actually delivered, read off the summary it returned.

    The collector does not raise when it cannot read a transcript: a scan has already finished
    by then, and a permission error on a log must not retroactively fail it. It returns a
    summary carrying an ``observer.error`` event, zero turns, zero tool calls and a note. So a
    call that returned is not a call that captured anything, and this is the difference. Taking
    "it returned" for "it worked" suppressed the reconstructed model pair for a session whose
    transcript had been read by nobody, and let ``tool_calls`` read ``complete`` over it.

    ``turns`` is what decides whether the *main* transcript described the call: a fallback pair
    is suppressed only when at least one model turn came out of it. ``captured`` is the weaker
    question, whether anything at all was recorded, which is what separates a partial view from
    no view. ``loss`` is every way the collector said this import was short of the file: a
    malformed line, an unmatched tool result, a capture key it marked unavailable, and any note
    it attached, which is where it reports a refused or truncated read.
    """

    turns: int
    captured: bool
    loss: tuple[str, ...]


def import_health(summary: Any) -> ImportHealth:
    """Read one :class:`~scaneval.collectors.ImportSummary` without trusting its shape.

    Every field is read defensively because the summary comes from another package and may gain
    fields; a missing one reads as zero rather than as an error, and a present one that is not a
    number is ignored rather than compared.
    """
    def count(name: str) -> int:
        value = getattr(summary, name, 0)
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    turns = count("model_turns")
    captured = bool(turns or count("tool_calls") or count("spans") or count("tool_results"))
    loss: list[str] = []
    malformed, unmatched = count("malformed_lines"), count("unmatched_tool_results")
    if malformed:
        loss.append(f"{malformed} malformed line(s)")
    if unmatched:
        loss.append(f"{unmatched} unmatched tool result(s)")
    capture = getattr(summary, "capture", None)
    if isinstance(capture, dict):
        unavailable = sorted(name for name, value in capture.items() if value == "unavailable")
        if unavailable:
            loss.append("the importer reported no capture of " + ", ".join(unavailable))
    for note in getattr(summary, "notes", ()) or ():
        if isinstance(note, str) and note:
            loss.append(note)
    if not captured:
        loss.append("nothing was captured from it")
    return ImportHealth(turns, captured, tuple(loss))


class TraceResult(NamedTuple):
    """What writing the trace produced: the observer's state and what the import could claim."""

    capture_state: dict
    transcripts_found: int
    imports_clean: bool
    notes: tuple[str, ...]


def _overlapping(candidates: tuple[Candidate, ...], path: str,
                 start: int | None, end: int | None) -> list[str]:
    """Candidate ids on *path* whose lines overlap ``[start, end]``, or all of them file-level.

    A finding that cited no line cannot be narrowed to a candidate by line, so every candidate
    on the same file is listed: the link says these are the candidates that were on this file,
    not that the agent read any particular one.
    """
    ids = []
    for candidate in candidates:
        if candidate.path != path:
            continue
        if start is None or end is None or not candidate.lines:
            ids.append(candidate.candidate_id)
            continue
        if any(start <= line <= end for line in candidate.lines):
            ids.append(candidate.candidate_id)
    return sorted(dict.fromkeys(ids))


def write_trace(*, trace_dir: Path, trace_mode: str, run_id: str, source_dir: Path,
                projects_dir: Path, records: Records, sessions: tuple[Session, ...],
                candidates: tuple[Candidate, ...], imported: DeepsecImport,
                model_requested: str, thinking: str | None) -> TraceResult:
    """Write this run's trace and report what the observer and the transcript import saw.

    Ordering is the order the run happened in: the regex candidates first, then each agent
    session, then the parse failures, then the findings DeepSec exported. Every event built from
    a DeepSec record carries ``source: "harness_record"``; the events the transcript importer
    emits carry its own source and its own capture status, which this function neither sets nor
    overrides.

    **One model call is recorded once.** A session whose transcript imported is described by the
    per-turn ``model.request``/``model.response`` pairs that importer emits, and this function
    emits no pair of its own for it. It used to emit an aggregate pair as well, so any accounting
    over the trace counted every call and every token of such a session twice: once per real
    turn and once more in the reconstruction. The aggregate pair is the *fallback*, for a session
    with no usable transcript, where it is the only description of the call there will be and
    carries the summed usage, cost, turn count and batch file list. DeepSec's own totals are in
    the execution record's ``usage`` either way, so nothing is lost by not repeating them.

    **Nothing that is not an attempt is shaped like one.** A parse-failure dump is DeepSec
    failing to read its own agent's output; it is emitted as an ``observer.error``, which is what
    the contract has for "something could not be captured", rather than as a ``model.response``
    with no request that a reader would count as an attempt. An agent refusal is a fact about the
    call that did happen, so it rides on that call's own response metadata as a closed code and a
    bounded summary; when a transcript described the call instead, the refusal is named in the
    run's notes, because inventing a second response to hang it on is the thing this fixed.

    A failure inside the collector is contained here, because a collector that cannot read one
    transcript must cost that import rather than the scan. Anything else that raises leaves
    through :meth:`DeepsecAdapter.scan`, which contains it in one place with a note.
    """
    events_path = trace_dir / "events.jsonl"
    notes: list[str] = []
    transcripts_found = 0
    imports_clean = True
    # Both spellings of the workspace, because the SDK writes the transcript under the real one
    # and the collectors match textually. See :func:`workspace_spellings`.
    roots = workspace_spellings(source_dir)
    collectors = collector()
    if collectors is None:
        notes.append("The Claude Code transcript collector is not installed, so no tool call, "
                     "context selection, or per-turn model event was imported for any session.")
    with events_path.open("a", encoding="utf-8") as stream:
        observer = Observer(mode=trace_mode, sink=create_jsonl_sink(stream.write),
                            run_id=run_id, producer_id="deepsec-adapter")
        for candidate in candidates:
            observer.emit(
                type="finding.candidate", category="finding", capture_status="complete",
                candidate_id=candidate.candidate_id,
                metadata={"source": "harness_record", "stage": "regex_matcher",
                          "file_path": candidate.path, "line_numbers": list(candidate.lines),
                          "vulnerability_class": candidate.slug,
                          "matched_patterns": list(candidate.patterns),
                          "matcher_hits": candidate.hits,
                          "external_paths": int(candidate.external)})
        for session in sessions:
            call_id = session.call_id
            located = False
            main_turns = 0
            captured_anything = False
            # ``correlated`` is the gate, not the bare presence of an id: an id discovery may
            # not be handed is treated exactly like a missing one.
            if collectors is not None and session.correlated:
                find, load = collectors
                try:
                    paths = list(find(session.session_id, projects_dir=projects_dir))
                except Exception as exc:  # noqa: BLE001 - a collector failure costs the import
                    notes.append(f"transcripts for session {session.session_id} could not be "
                                 f"located ({type(exc).__name__}); none were imported")
                    imports_clean = False
                    paths = []
                located = bool(paths)
                for path in paths:
                    sidechain = Path(path).parent.name == "subagents"
                    try:
                        summary = load(observer, Path(path), workspace_root=roots,
                                       call_id=call_id, sidechain=sidechain,
                                       agent_id=Path(path).stem if sidechain else None)
                    except Exception as exc:  # noqa: BLE001 - same rule: the import, not the scan
                        notes.append(f"transcript {Path(path).name} could not be imported "
                                     f"({type(exc).__name__})")
                        imports_clean = False
                        continue
                    health = import_health(summary)
                    captured_anything = captured_anything or health.captured
                    if not sidechain:
                        main_turns += health.turns
                    if health.loss:
                        imports_clean = False
                        notes.append(f"transcript {Path(path).name} was imported short of the "
                                     f"file: {'; '.join(health.loss)}")
            if located and main_turns <= 0:
                # The transcript is there and it did not describe the call. Whatever else was
                # read from it, this session's own turns were not, so no category may claim a
                # complete view of them.
                imports_clean = False
                notes.append(f"the main transcript of session {session.session_id} produced no "
                             "model turn, so the call is described by DeepSec's own record "
                             "instead")
            if captured_anything:
                transcripts_found += 1
            if session.refusals:
                notes.append(
                    f"DeepSec recorded {len(session.refusals)} refusal(s) on the analysis entries "
                    f"of call {call_id}: "
                    + "; ".join(f"{refusal.path} ({refusal.code})" for refusal in session.refusals))
            if main_turns > 0:
                # The main transcript is the record of this call, turn by turn. Adding a summed
                # pair beside it would be the same call counted twice. A transcript that is
                # there but described no turn is not that record, so the fallback below still
                # runs: a call must never disappear from the trace because a log was unreadable.
                continue
            attempt_id = f"{call_id}/attempt-1"
            shared = {"source": "harness_record", "session_id": session.session_id,
                      "correlation": session.correlation,
                      "batch_paths": list(session.paths),
                      "external_paths": session.external_paths,
                      "aggregation": "sum_of_per_file_shares", "retries_observable": False}
            observer.emit(
                type="model.request", category="model", capture_status="partial",
                call_id=call_id, attempt_id=attempt_id,
                metadata={**shared, "route": "claude_agent_sdk",
                          "model_requested": model_requested, "thinking": thinking,
                          "stage": "process", "attempt": 1, "max_attempts": 1,
                          "run_id_native": session.run_id,
                          "transcript_imported": False})
            # A closed code and a path. Nothing the model wrote reaches metadata.
            refusals = [{"file_path": refusal.path, "reason_code": refusal.code}
                        for refusal in session.refusals]
            observer.emit(
                type="model.response", category="model", capture_status="partial",
                call_id=call_id, attempt_id=attempt_id,
                # The schema's own duration field, and the one number in the entry that is a
                # measurement of the batch rather than a share of it. See :class:`Session`.
                duration_ms=int(round(session.duration_ms)),
                metadata={**shared, "exit_code": None, "error": None, "attempt": 1,
                          "will_retry": False,
                          "failure_kind": "refusal" if refusals else None,
                          "usage_available": True, "usage": dict(session.usage),
                          "cost_usd_cli_reported": session.cost_usd,
                          "num_turns": session.num_turns,
                          "result_subtype": "refusal" if refusals else None,
                          "is_error": bool(refusals),
                          "duration_api_ms": session.duration_api_ms,
                          "model_served": session.model,
                          "transcript_imported": False,
                          **({"refusals": refusals} if refusals else {})},
                # The reason is model prose and can quote source, so it is content, which the
                # observer stores only in content mode. Its paths are relocated even here,
                # because a home directory may not appear in an event in any mode.
                **({"content": {"refusal_reasons": [
                    {"file_path": refusal.path, "reason": refusal.reason}
                    for refusal in session.refusals]}} if refusals else {}))
        for index, name in enumerate(records.debug, start=1):
            observer.emit(
                type="observer.error", category="observer", capture_status="unavailable",
                metadata={"source": "harness_record",
                          "error_code": "agent_output_parse_failure",
                          "stage": "process", "debug_dump": name, "sequence_in_run": index,
                          "detail": "DeepSec could not parse one batch's agent output and wrote "
                                    "a debug dump; the findings of that batch, if any, were not "
                                    "recorded and nothing here says what the model produced"})
        for finding in imported.findings:
            observer.emit(
                type="finding.submitted", category="finding", capture_status="complete",
                candidate_id=finding["claim_id"], claim_id=finding["claim_id"],
                metadata={"source": "harness_record", "stage": "process",
                          "file_path": finding["path"],
                          "candidate_ids": _overlapping(candidates, finding["path"],
                                                        finding["start"], finding["end"]),
                          "vulnerability_class": finding["slug"],
                          "severity": finding["severity"], "confidence": finding["confidence"],
                          "status": finding["status"], "disposition": "new"})
        observer.flush()
        state = observer.get_state()
        observer.close()
    invalid = [session.paths[0] if session.paths else session.key
               for session in sessions if session.correlation == "invalid_session_id"]
    if invalid:
        notes.append(
            f"{len(invalid)} analysis entr(ies) carried an agentSessionId that is not one "
            "transcript discovery may be handed, so each became its own uncorrelated call and "
            "none was looked up: " + ", ".join(sorted(invalid)[:5]))
    if sessions:
        notes.append(f"{transcripts_found} of {len(sessions)} agent session(s) had a Claude Code "
                     "transcript this run could import. A session with a transcript is described "
                     "by that transcript's own per-turn model events; a session without one is "
                     "described by a single reconstructed request/response pair carrying "
                     "DeepSec's summed usage. No call is described both ways.")
        notes.append(
            "Transcript paths were matched against "
            + ("both spellings of the scanned workspace" if len(roots) > 1
               else "the one spelling of the scanned workspace")
            + f" ({', '.join(portable(root) for root in roots)}): the Claude Agent SDK records "
            "its working directory and every file it read under the platform's real path, and "
            "the collectors compare textually without resolving a link, so a path matched "
            "against one spelling alone reads as external to the workspace.")
    return TraceResult({"capture_gap": state.capture_gap, "dropped_events": state.dropped_events},
                       transcripts_found, imports_clean, tuple(notes))


class ProcessOutput(NamedTuple):
    """What DeepSec printed at the end of one direct-mode ``process`` run, and nothing more.

    Every field is absent unless DeepSec's own summary line for it is there. This is advisory by
    construction: stdout is text an agent's output can reach, so nothing here decides a status.
    The records DeepSec wrote decide that, and this only names the reason (the quota source
    DeepSec reported, how many batches it counted as errored) and carries DeepSec's own statement
    that a diff selected no file, which the caller accepts only beside the records that agree.
    """

    quota: str | None = None
    errored_batches: int | None = None
    findings: int | None = None
    nothing_to_process: bool = False


def read_process_output(text: str) -> ProcessOutput:
    """The summary of one direct-mode ``process`` run, read from the end of its stdout.

    The last match of each line wins, since a summary is printed once and after everything else.
    An empty or unreadable stdout is a :class:`ProcessOutput` with nothing in it, never an error:
    a caller that needs the statement it would have carried treats its absence as absence.
    """
    plain = ANSI_ESCAPE.sub("", text)

    def last(pattern: re.Pattern) -> str | None:
        found = pattern.findall(plain)
        return found[-1] if found else None

    errored, findings = last(PROCESS_ERRORED_BATCHES), last(PROCESS_FINDINGS)
    return ProcessOutput(quota=last(QUOTA_STOPPED),
                         errored_batches=int(errored) if errored is not None else None,
                         findings=int(findings) if findings is not None else None,
                         nothing_to_process=bool(NOTHING_TO_PROCESS.search(plain)))


def _listed(names: Sequence[str], limit: int = 8) -> str:
    """At most *limit* of *names* joined for a note, and how many more there were.

    A name DeepSec would trim (:func:`listing_trims`) is written as a JSON string. The space at its end is the
    reason it is listed at all, and a space there cannot be seen in a list.
    """
    shown = [json.dumps(name) if listing_trims(name) else name for name in names[:limit]]
    return ", ".join(shown) + (f" and {len(names) - limit} more" if len(names) > limit else "")


def git_prints_quoted(path: str) -> bool:
    """Whether git, by default (``core.quotePath``), prints *path* as a quoted, escaped string.

    A name with a byte outside printable ASCII, a double quote, a backslash or a control character
    is. DeepSec 2.3.10 reads git's plain-text listing (``git diff --name-only``, no ``-z``) and
    keeps only entries that name an existing file, so it never selects such a path: the entry it
    holds is the quoted spelling, which names nothing. Checked against the real CLI with a
    non-ASCII name; the other characters are quoted by the same git rule and are not checked.
    :func:`listing_trims` is the other way a name is lost to that listing.
    """
    return any(ord(char) < 0x20 or ord(char) >= 0x7F or char in '"\\' for char in path)


# What JavaScript's ``String.prototype.trim`` takes off both ends of a string (ECMAScript's WhiteSpace and
# LineTerminator), as Node reports it. It is spelled out because Python's ``str.strip`` is not the same set: it also
# removes U+001C to U+001F and U+0085, which JavaScript keeps, and keeps U+FEFF, which JavaScript removes.
JS_TRIM = ("\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
           "\u2028\u2029\u202f\u205f\u3000\ufeff")


def listing_trims(path: str) -> bool:
    """Whether DeepSec 2.3.10 looks for something other than *path*, because it trims each line of its listing first.

    ``resolveFiles`` runs ``entry.trim()`` on every line of ``git diff --name-only`` before it looks for the file. A
    name that begins or ends with a character in :data:`JS_TRIM` is therefore looked for without it, and the entry it
    holds names another path, or none. Git quotes every one of those characters but the space (a control character,
    and by default a non-ASCII one), and a quoted line starts and ends with a quote, which the trim leaves alone. So
    what is left is a space, which git prints as it is at the start or the end of a name. A space inside a name, or
    at the end of a directory in it (``src /a.js``), is not at an end of the line and is not touched. Read from the
    2.3.10 bundle, with the set of characters taken from Node's own ``trim`` and the unquoted spelling checked against
    git's output for a leading and a trailing space; the real CLI was not run over such a name.
    """
    return path != path.strip(JS_TRIM)


class DroppedPaths(NamedTuple):
    """The paths a change leaves at head, and which of them DeepSec created no file record for.

    Both lists are sorted, hold each path once, and come from one comparison by path of what git says
    the change touches against the file records DeepSec left, so everything this adapter says about a
    path DeepSec did not investigate, in the notes and in the status, is read from here. In direct
    mode DeepSec creates a record for every file it selected and none for a file it did not:
    ``present`` is every path that exists at head (everything but a deletion, which DeepSec never
    reads) and ``dropped`` those of them with no record. A record whose name cannot be expressed as a
    path inside the tree (:func:`record_path` calls it external) is the record of no path here, and a
    path git spells with escapes because it is not UTF-8 can never match a record, so it is dropped.

    ``dropped`` says which paths have no record and never why. The one reason this adapter can state
    is a limit of the listing DeepSec reads, and there are two: a name git prints quoted
    (:attr:`quoted`) and a name that begins or ends with a space (:attr:`trimmed`). Together they are
    :attr:`unlistable`, the known omissions.
    """

    present: tuple[str, ...]
    dropped: tuple[str, ...]

    @property
    def quoted(self) -> tuple[str, ...]:
        """The dropped paths whose name git prints quoted (:func:`git_prints_quoted`).

        DeepSec 2.3.10 reads the plain listing of ``git diff --name-only`` and keeps only the entries
        that name an existing file. For a path git prints quoted, the entry it holds is the quoted
        spelling, which names nothing, so it never selects that path, whatever its ignore filter would
        have said, and never investigates it.
        """
        return tuple(path for path in self.dropped if git_prints_quoted(path))

    @property
    def trimmed(self) -> tuple[str, ...]:
        """The dropped paths git prints as they are and DeepSec's trim of its listing changes.

        That is a name that begins or ends with a space (:func:`listing_trims`). The entry DeepSec
        holds is the name without it, which names no file, or another one, and DeepSec may then have
        reviewed that one in place of the changed path. A name git prints quoted is not counted here
        as well: the trim leaves a quoted line alone, so the quoting is what drops it.
        """
        return tuple(path for path in self.dropped if not git_prints_quoted(path) and listing_trims(path))

    @property
    def unlistable(self) -> tuple[str, ...]:
        """The dropped paths DeepSec's listing cannot resolve to themselves: the known omissions.

        Each is a limit of the listing DeepSec reads and not a choice of scope, so a run over a change
        that leaves such a path is not a review of all of it. It is :attr:`quoted` and :attr:`trimmed`
        in one list, each path once, and the note that names these paths, the bundle flag and the
        status of the run are all made from it, so they cannot disagree.

        It is deliberately not narrowed by the ignore filter, which this adapter cannot see: a name
        the filter would have dropped anyway is counted too. The cost is credit withheld from a run
        that was complete after all; the alternative is quiet credit for a file nobody opened.
        """
        return tuple(path for path in self.dropped if git_prints_quoted(path) or listing_trims(path))


def dropped_paths(changes: tuple[Change, ...], files: tuple[tuple[str, dict], ...]) -> DroppedPaths:
    """What git says the change leaves at head, set against the file records DeepSec left.

    *changes* is what git in the workspace says the two commits differ in, asked by this adapter
    before DeepSec started; *files* is the file records DeepSec left. This says which paths have no
    record and never why; :attr:`DroppedPaths.unlistable` is the reason this adapter can state.
    """
    recorded = {path for path, external in (record_path(name, record) for name, record in files) if not external}
    present = sorted({change.path for change in changes if change.present})
    return DroppedPaths(tuple(present), tuple(path for path in present if path not in recorded))


def listing_limits(paths: DroppedPaths, subject: str) -> list[str]:
    """One clause for each limit of DeepSec's listing that *paths* met: which of them, and what the limit is.

    The error that ends the run and the note both say this, in these words, from the same lists.
    *subject* is what they count: ``changed path(s)`` in the error and ``of them`` in the note.
    """
    clauses = []
    if paths.quoted:
        clauses.append(
            f"{len(paths.quoted)} {subject} ({_listed(paths.quoted)}) have a name git prints quoted by default (a "
            "non-ASCII name, or one holding a quote, a backslash or a control character): DeepSec reads git's plain "
            "listing and cannot resolve a quoted name to a file")
    if paths.trimmed:
        clauses.append(
            f"{len(paths.trimmed)} {subject} ({_listed(paths.trimmed)}) begin or end with a space: DeepSec trims "
            "every line of git's plain listing before it looks for the file, and the entry it holds then names "
            "another path, or none")
    return clauses


def unlistable_error(paths: DroppedPaths) -> str:
    """The ``scope_incomplete`` error for a change that leaves a path DeepSec's listing cannot resolve."""
    return ("; ".join(listing_limits(paths, "changed path(s)"))
            + ", so it never investigated them, whatever its ignore filter says. This run therefore observed only "
              "part of the change (or none of it) and says nothing about them")


def unreviewed_note(changes: tuple[Change, ...], files: tuple[tuple[str, dict], ...]) -> str | None:
    """The changed paths DeepSec created no file record for, as a note, or ``None`` when there are none.

    *changes* and *files* are as for :func:`dropped_paths`, and the note is written from what it
    returns. A path present at head with no record is one DeepSec's own selection dropped: it
    keeps only added, modified, renamed and copied paths (a deletion never reaches it) and drops those
    matching its default ignore filter (tests, docs, build output and similar). That is DeepSec's
    scope, not a failure of the run, and the note says so, with the reminder that silence about such a
    path is not a negative result. A file DeepSec did select but left in ``error`` or unfinished has a
    record and is reported by the status logic, not here.

    Not every path listed was dropped by the ignore filter. One whose name git prints quoted
    (:attr:`DroppedPaths.quoted`) is dropped by DeepSec whatever the filter says, because it cannot
    resolve the quoted spelling to a file, and so is one that begins or ends with a space
    (:attr:`DroppedPaths.trimmed`), because DeepSec trims each line of its listing and looks for another
    path. The note names those separately, each with the limit it met: the omission is a limit of
    DeepSec's own listing and not a scoping choice, so the run observed nothing about them and cannot
    stand as a complete or quiet observation of the change. The status logic ends such a run
    ``scope_incomplete`` from the same list, so the note and the status cannot disagree. This adapter
    cannot tell the other paths apart by reason and does not try to.
    """
    paths = dropped_paths(changes, files)
    omitted = paths.unlistable
    removed = sorted({change.path for change in changes if change.status == "D"}
                     | {change.old_path for change in changes if change.status == "R" and change.old_path})
    sentences = []
    if paths.dropped:
        apart = f", except for the {len(omitted)} named next" if omitted else ""
        sentences.append(
            f"DeepSec did not investigate {len(paths.dropped)} of the {len(paths.present)} path(s) this change "
            f"leaves at head, because it created no file record for them ({_listed(paths.dropped)}). Its --diff "
            "selection keeps only added, modified, renamed and copied paths and drops those matching its default "
            "ignore filter (tests, docs, build output and similar), so this is DeepSec's own scope and not a "
            f"failure of the run{apart}; silence about these paths is not a negative result.")
        if omitted:
            sentences.append(". ".join(listing_limits(paths, "of them")) + ".")
            sentences.append(
                "DeepSec drops such a path whatever its ignore filter says; for these the omission is a limit of "
                "DeepSec's own listing, not a choice of scope, so this run observed nothing about them and does not "
                "stand as a complete or quiet observation of the change.")
    if removed:
        sentences.append(f"The change also removed {len(removed)} path(s) ({_listed(removed)}); DeepSec never reads "
                         "a path that no longer exists at head.")
    return " ".join(sentences) or None


class DeepsecAdapter(Adapter):
    name = "deepsec"
    adapter_version = "1.1.0"
    requires_git = False
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})
    scan_modes = frozenset({"full", "pr"})
    # On top of the base set. The provider keys are here because the agent needs one when the
    # operator's route is a direct API key rather than a CLI login; they are secrets, so they
    # are passed and never recorded. ``HOME`` is already in the base set and is what the local
    # CLI login is read from. ``NODE_OPTIONS`` is deliberately absent: node executes what it
    # names, so ``--require`` in the operator's environment would run code inside the scanner
    # while the record showed only a variable name.
    env_passthrough = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")

    def prepare(self, spec: SystemSpec, cache_root: Path) -> dict[str, Any]:
        """Verify the installed DeepSec and record both versions it reports.

        Two versions, because they can disagree and a reader needs to know which one ran: the
        ``--version`` the executable prints, and the ``version`` in the installed package's own
        ``package.json``. The version command runs with its working directory in the cache
        rather than anywhere near the operator's workspace, so it cannot pick up a
        ``deepsec.config.ts`` by walking up and report on a project this run has nothing to do
        with.
        """
        config = settings(spec)
        if not config.binary.exists():
            raise AdapterError(f"deepsec executable not found at {config.binary}; "
                               "config.deepsec_root must name a workspace with deepsec installed")
        if not os.access(config.binary, os.X_OK):
            raise AdapterError(f"deepsec executable at {config.binary} is not executable")
        package_version = None
        package = config.root / "node_modules" / "deepsec" / "package.json"
        try:
            package_version = json.loads(package.read_text(encoding="utf-8")).get("version")
        except (OSError, ValueError):
            pass
        cwd = cache_root / "deepsec-version"
        try:
            cwd.mkdir(parents=True, exist_ok=True)
            reported = subprocess.run([str(config.binary), "--version"], cwd=str(cwd),
                                      env=build_env(self.env_passthrough), capture_output=True,
                                      text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdapterError(f"deepsec --version could not be run: {exc}") from exc
        if reported.returncode != 0:
            raise AdapterError(f"deepsec --version exited {reported.returncode}: "
                               f"{reported.stderr.strip()[:500]}")
        return {
            "deepsec": {
                "root": str(config.root), "configured_root": config.configured_root,
                "binary": str(config.binary),
                "cli_version": reported.stdout.strip(),
                "package_version": package_version if isinstance(package_version, str) else None,
            },
            "agent": config.agent,
            "model": config.model,
        }

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds,
             trace_mode, trace_dir):
        """Run scan, process and export once each, then import what DeepSec wrote down.

        The three steps share one timeout budget: each is given whatever is left of
        ``timeout_seconds``, and a step that exhausts it ends the invocation as a timeout with
        the partial stdout and stderr of every step kept as raw artifacts. A step that exits
        non-zero ends it as an error naming that step, because a stage that failed did not
        produce the records the next stage reads and the result must not read as a quiet scan.

        A PR request (``request["input"]["mode"] == "pr"``) runs two steps instead: ``process
        --diff <base>..<head>``, DeepSec's direct mode, and ``export``. It is refused before
        anything runs, as an ``AdapterError``, when the request does not name two full commit ids
        or the workspace does not hold the clean two-commit history it names, and any mode but
        ``full`` and ``pr`` is refused too, so a request this adapter cannot serve is never run
        as a full scan. An exit 1 from ``process`` is DeepSec's own signal and is classified from
        its records, not treated as fatal; the module docstring states how.
        """
        pr = pr_range(request, self)
        config = settings(spec)
        if not config.binary.exists():
            raise AdapterError(f"deepsec executable not found at {config.binary}")
        # Read before DeepSec starts: its agent can run a shell in this workspace, ``.git`` included.
        changes = workspace_changes(Path(source_dir), pr) if pr is not None else ()
        project = project_id_for(request, config.project_id)
        # Captured before the first process starts: DeepSec writes into the raw directory while
        # it runs, so every read below is checked against a boundary it cannot move.
        enclosure = Enclosure.capture(Path(source_dir), Path(raw_dir))
        workspace = build_workspace(Path(raw_dir), Path(source_dir), project, config)
        data_dir = workspace / "data" / project
        export_path = Path(raw_dir) / "deepsec-export.json"
        overrides = {"DEEPSEC_DATA_ROOT": "data"}
        if config.claude_code_executable:
            overrides["CLAUDE_CODE_EXECUTABLE"] = config.claude_code_executable
        env = build_env(self.env_passthrough, overrides)

        scan_argv = [str(config.binary), "scan", "--project-id", project, "--root", str(source_dir)]
        process_argv = [str(config.binary), "process", "--project-id", project,
                        "--root", str(source_dir),
                        *(["--diff", pr.revision_range] if pr is not None else []),
                        "--agent", config.agent,
                        "--model", config.model, "--concurrency", str(config.concurrency)]
        if config.thinking_level:
            process_argv += ["--thinking-level", config.thinking_level]
        if config.limit is not None and pr is None:
            # Direct mode never passes --limit on (2.3.10), so a PR run does not send it.
            process_argv += ["--limit", str(config.limit)]
        if config.batch_size is not None:
            process_argv += ["--batch-size", str(config.batch_size)]
        if config.max_turns is not None:
            process_argv += ["--max-turns", str(config.max_turns)]
        export_argv = [str(config.binary), "export", "--format", "json",
                       "--project-id", project, "--out", str(export_path)]

        artifacts: list[dict] = [
            {"id": "deepsec-config", "path": workspace / "deepsec.config.ts"},
            {"id": "deepsec-package-json", "path": workspace / "package.json"},
        ]
        notes: list[str] = []
        remaining = float(timeout_seconds)
        results: dict[str, Any] = {}
        timed_out_step = None
        steps = ((("scan", scan_argv),) if pr is None else ()) + (("process", process_argv), ("export", export_argv))
        for step, argv in steps:
            stdout = Path(raw_dir) / f"deepsec-{step}.stdout.txt"
            stderr = Path(raw_dir) / f"deepsec-{step}.stderr.txt"
            artifacts.append({"id": f"deepsec-{step}-stdout", "path": stdout})
            artifacts.append({"id": f"deepsec-{step}-stderr", "path": stderr})
            if remaining <= 0:
                timed_out_step = step
                stdout.write_text("", encoding="utf-8")
                stderr.write_text("", encoding="utf-8")
                break
            result = run_command(argv, cwd=workspace, timeout_seconds=remaining, env=env,
                                 stdout_path=stdout, stderr_path=stderr)
            results[step] = result
            remaining -= result.wall_seconds
            if result.timed_out:
                timed_out_step = step
                break
            if result.exit_code != 0:
                if pr is not None and step == "process" and result.exit_code == DIRECT_MODE_EXIT:
                    # Direct mode's own exit for findings, an errored batch and an exhausted quota.
                    # It also exits 1 for a runtime failure, so what it means is decided below, from
                    # the records; the run goes on to export either way.
                    continue
                break

        records = read_records(data_dir, enclosure)
        artifacts.extend(records.artifacts)
        if os.path.lexists(export_path):
            # Declared only when it is there. A step that failed before the export ran left no
            # file, and declaring one anyway would put "declared artifact missing" in the record
            # of a run whose actual failure is already named.
            artifacts.append({"id": ARTIFACT_EXPORT, "path": export_path})
        # Both spellings of the workspace, so a record path that is somehow absolute is
        # relocated rather than published, exactly as the transcript importer relocates one.
        roots = workspace_spellings(Path(source_dir))
        candidates = candidates_from(records.files, roots)
        sessions = sessions_from(records.files, roots)
        # Only ``analyzed`` says the AI stage finished with a file. ``pending`` is one it never
        # reached, which is what ``--limit`` does by design; ``processing`` is one a run was
        # still holding when it ended; a status DeepSec does not declare, or none at all, is a
        # record this adapter cannot classify and must not classify in the direction that earns
        # credit. None of the three is a file silence says anything about.
        statuses = record_statuses(records.files)
        errored_files = list(statuses.errored)
        unfinished_files = len(statuses.unfinished)
        refusals = sum(len(session.refusals) for session in sessions)
        batches_failed = len(errored_files) + len(records.debug) + refusals
        suspect_durations = [session.call_id for session in sessions if session.duration_suspect]
        # The changed paths DeepSec's listing could not resolve (a name git quotes, a name it trims), so that no model
        # was ever given them. Read once, here, for the bundle flag and the status below; the note is made from the
        # same helper.
        dropped = dropped_paths(changes, records.files) if pr is not None else DroppedPaths((), ())
        omitted = dropped.unlistable

        exported: Any = None
        export_failure = None
        data, failure = read_record(export_path, enclosure.write(export_path))
        if data is None:
            export_failure = f"the export was not read ({failure})"
        else:
            try:
                exported = json.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                export_failure = f"the export is not readable JSON ({exc})"
        imported = DeepsecImport([], [], 0, [])
        if export_failure is None:
            try:
                imported = import_export(exported, ids=finding_ids(records.files))
            except AdapterError as exc:
                export_failure = str(exc)

        # A PR review's own facts. ``output`` is what DeepSec printed and is advisory only: what an
        # exit 1 means is read from the records it left, which is where each of its three causes
        # (findings, an errored batch, an exhausted quota) is written down as it happens.
        output = ProcessOutput()
        process_result = results.get("process") if pr is not None else None
        if process_result is not None:
            process_stdout = Path(raw_dir) / "deepsec-process.stdout.txt"
            output = read_process_output(bounded_tail(process_stdout, enclosure.write(process_stdout),
                                                      PROCESS_OUTPUT_TAIL))
        finding_records = sum(len(record["findings"]) for _name, record in records.files
                              if isinstance(record.get("findings"), list))
        exit_one_explained = bool(finding_records or imported.claims or statuses.errored or statuses.unfinished
                                  or records.debug)

        trace_path = (trace_dir / "events.jsonl") if trace_dir is not None else None
        capture_state: dict | None = None
        transcripts_found = 0
        imports_clean = True
        if trace_dir is not None and trace_mode != "off":
            try:
                traced = write_trace(
                    trace_dir=Path(trace_dir), trace_mode=trace_mode, run_id=request["run_id"],
                    source_dir=Path(source_dir), projects_dir=config.projects_dir, records=records,
                    sessions=sessions, candidates=candidates, imported=imported,
                    model_requested=config.model, thinking=config.thinking_level)
            except Exception as exc:  # noqa: BLE001
                # The one place a trace failure is contained. A trace is instrumentation: losing
                # it must not discard the claims the import already built, and it must not read
                # as a clean run either, so the capture matrix below sees no transcript and
                # scaneval.execution records the missing trace as an incomplete observation.
                notes.append(f"the trace could not be written ({type(exc).__name__}: {exc}); this "
                             "run is recorded as one that observed nothing of what the scanner did")
            else:
                capture_state = traced.capture_state
                transcripts_found = traced.transcripts_found
                imports_clean = traced.imports_clean
                notes.extend(traced.notes)

        capture = capture_status(
            trace_mode, transcripts_found=transcripts_found, sessions=len(sessions),
            batches_failed=batches_failed, imports_clean=imports_clean,
            # Everything this run already knows it did not see. A category may not claim
            # completeness over a population this run could not read in full, and none may
            # claim it over an observer that reported a hole in its own record.
            record_failures=len(records.failures), findings_lost=imported.lost,
            capture_gap=bool((capture_state or {}).get("capture_gap")
                             or (capture_state or {}).get("dropped_events")))
        models = sorted({session.model for session in sessions if session.model})
        model_identity = {
            "requested": config.model,
            "resolved": models[0] if len(models) == 1 else None,
            # The record's enumeration has no value for "the scanner told us": a model read off
            # DeepSec's own analysisHistory is the scanner's word for it, which is what
            # self_reported means here. The note below says which record it came from.
            "verification": "self_reported" if models else "unverified",
            "notes": ["The resolved model is the one DeepSec recorded on its own analysisHistory "
                      "entries (harness_reported). Nothing here verifies which model the provider "
                      "actually served."] if len(models) == 1 else
                     ([f"DeepSec recorded {len(models)} different models across this run's sessions "
                       f"({', '.join(models)}), so no single resolved model is reported."] if models
                      else ["DeepSec recorded no model on any analysis entry for this run."]),
        }
        usage = {
            "cost_usd": round(sum(session.cost_usd for session in sessions), 6),
            "input_tokens": sum(session.usage.get("input_tokens", 0) for session in sessions),
            "output_tokens": sum(session.usage.get("output_tokens", 0) for session in sessions),
        }
        tool_versions = {
            "deepsec": str(preparation.get("deepsec", {}).get("cli_version") or "unknown")
            if isinstance(preparation, dict) else "unknown",
            "deepsec_package": str((preparation.get("deepsec", {}) if isinstance(preparation, dict)
                                    else {}).get("package_version") or "unknown"),
            "agent": config.agent,
        }
        if pr is None:
            steps_note = (f"DeepSec ran as three CLI steps in one workspace under raw/deepsec-workspace: scan, "
                          f"process and export. The recorded command is those three argv lists in order, "
                          f"separated by '&&'; each step's stdout and stderr is its own raw artifact.")
        else:
            steps_note = (f"DeepSec ran as two CLI steps in one workspace under raw/deepsec-workspace: process in its "
                          f"direct mode, given --diff {pr.revision_range}, and export; no separate scan step was run. "
                          "Direct mode listed the files that range changed itself, ran its own regex scan over just "
                          "those files and investigated each of them. The recorded command is those two argv lists "
                          "in order, separated by '&&'; each step's stdout and stderr is its own raw artifact.")
        notes = [
            steps_note,
            f"Project id {project} is derived from the input tree hash: the scan request carries "
            "no snapshot id, and DeepSec needs an id it accepts as a directory name.",
            "Cost and token counts are DeepSec's own per-file shares of each batch, summed; they "
            "are CLI-reported estimates, never a bill, and no single number here measures one "
            "model call.",
            "Tool dispatch, context selection and per-turn model events come only from the Claude "
            "Code transcripts the agent sessions left behind. Absence of them is not evidence that "
            "no tool ran.",
            f"{len(candidates)} regex candidate(s) and {len(sessions)} agent session(s) were read "
            f"out of {len(records.files)} file record(s).",
        ] + notes + list(imported.notes)
        if pr is not None:
            if config.limit is not None:
                notes.append(f"config.limit ({config.limit}) was not passed to DeepSec: its direct mode never applies "
                             "--limit, so it would have had no effect on which files were investigated.")
            if process_result is not None and process_result.exit_code == DIRECT_MODE_EXIT and exit_one_explained:
                said = ([f"{output.quota} exhausted"] if output.quota else []) + (
                    [f"{output.errored_batches} errored batch(es)"] if output.errored_batches else []) + (
                    [f"{output.findings} finding(s)"] if output.findings else [])
                notes.append(
                    "deepsec process exited 1 and the run went on to export: in direct mode DeepSec exits 1 for "
                    "findings, for an errored batch and for an exhausted quota, and its records show "
                    f"{finding_records} finding(s), {len(statuses.errored)} file(s) in status 'error' and "
                    f"{unfinished_files} unfinished file(s). This run was classified from those records"
                    + (f"; DeepSec's own summary said {', '.join(said)}." if said else "."))
            unreviewed = unreviewed_note(changes, records.files)
            if unreviewed:
                if records.failures:
                    # A record this run could not read is missing from the comparison, so a path
                    # listed as having none may have had one.
                    unreviewed += (f" {len(records.failures)} DeepSec record(s) could not be read, so a path "
                                   "listed here may have had one.")
                notes.append(unreviewed)
        for failure_note in records.failures:
            notes.append(f"DeepSec record not read: {failure_note}")
        if errored_files:
            notes.append(f"{len(errored_files)} file(s) were left in status 'error' by DeepSec: "
                         + ", ".join(errored_files[:5]))
        if records.debug:
            notes.append(f"{len(records.debug)} parse-failure dump(s) under data/{project}/debug: "
                         + ", ".join(records.debug[:5]))
        if refusals:
            notes.append(f"{refusals} agent refusal report(s) were recorded on this run's analysis "
                         "entries; the files they name reached no verdict.")
        if unfinished_files and pr is not None:
            notes.append(
                f"{unfinished_files} of {len(records.files)} file record(s) were left unfinished "
                f"({', '.join(statuses.unfinished[:5])}): DeepSec's direct mode created them and its AI stage "
                "either never reached them, which is how a run ends when its quota runs out, or was still "
                "holding them when the run ended. No model reached a verdict on those files, so silence about "
                "them is not a negative result.")
        elif unfinished_files:
            notes.append(
                f"{unfinished_files} of {len(records.files)} file record(s) were left unfinished "
                f"({', '.join(statuses.unfinished[:5])}): DeepSec's scan stage found them and its "
                "AI stage either never reached them, which is what config.limit"
                + (f" ({config.limit})" if config.limit is not None else "")
                + " does, or was still holding them when the run ended. No model reached a "
                "verdict on those files, so silence about them is not a negative result.")
        if statuses.invalid:
            notes.append(
                f"{len(statuses.invalid)} file record(s) carry a status this adapter cannot "
                "classify, so whether DeepSec finished with them is unknown: "
                + "; ".join(f"{name}: {reason}" for name, reason in statuses.invalid[:5]))
        if suspect_durations:
            notes.append(
                f"{len(suspect_durations)} agent session(s) carry the same whole-number "
                "durationMs on every file of the batch while their other shares are fractional, "
                "which is how a DeepSec older than 2.3.10 wrote a duplicated wall clock rather "
                "than a divided one. The recorded duration is still the sum of the shares; read "
                f"it as possibly duplicated for: {', '.join(suspect_durations[:5])}")

        command = ([*scan_argv, "&&", *process_argv, "&&", *export_argv] if pr is None
                   else [*process_argv, "&&", *export_argv])
        base = dict(command=command, artifacts=artifacts, tool_versions=tool_versions,
                    capture=capture, usage=usage, notes=notes, model_identity=model_identity,
                    trace_path=trace_path, capture_state=capture_state,
                    # A run that left records pending delivered claims about part of the input
                    # and nothing at all about the rest, so its bundles are not resolved: the
                    # scoring contract must not read a claim budget off it, and must not grant
                    # quiet credit for a file no model opened. In a PR review a file left in
                    # ``error`` is the same case, and the ordinary one: direct mode exits 1 and
                    # the run goes on, so the claims of the batches that finished are all there is.
                    # So is a changed path DeepSec never listed: the claims about the rest are a
                    # part delivered, and a budget read off a part reads as one read off the whole.
                    bundles_resolved=(imported.lost == 0 and not records.failures
                                      and statuses.incomplete == 0
                                      and (pr is None or not (statuses.errored or omitted))))
        exit_code = None
        for step in ("export", "process", "scan"):
            result = results.get(step)
            if result is not None and not result.timed_out:
                exit_code = result.exit_code
                break

        def tail(step: str) -> str:
            """The tail of one step's stderr, read the way a scanner-owned path must be.

            DeepSec can replace this file after its own descriptor closed, so it is read
            through :func:`bounded_tail`: contained in this run's raw output, no symbolic link
            followed, no named pipe waited on, and only the last bytes taken rather than the
            whole file. An unreadable one costs the quoted tail and not the failure being
            reported.
            """
            path = Path(raw_dir) / f"deepsec-{step}.stderr.txt"
            return bounded_tail(path, enclosure.write(path))

        if timed_out_step is not None:
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True, claims=imported.claims,
                                 error={"code": "timeout",
                                        "message": f"deepsec {timed_out_step} exhausted the shared "
                                                   f"{timeout_seconds}s budget and was killed"}, **base)
        for step, _argv in steps:
            result = results.get(step)
            if result is None:
                return NativeOutcome(status="error", exit_code=exit_code, claims=[],
                                     error={"code": f"{step}_not_run",
                                            "message": f"deepsec {step} never ran; an earlier step "
                                                       "ended the invocation"}, **base)
            if result.exit_code != 0:
                direct_exit = pr is not None and step == "process" and result.exit_code == DIRECT_MODE_EXIT
                if direct_exit and exit_one_explained:
                    # Direct mode's exit 1 for findings, an errored batch or an exhausted quota, and
                    # its records say which one it was; the status below is made from them.
                    continue
                message = f"deepsec {step} exited {result.exit_code}; stderr: {tail(step)}"
                if direct_exit:
                    message = ("deepsec process exited 1 and left no finding, no file in status 'error' or "
                               "unfinished and no parse-failure dump, which is what an exit 1 means in direct "
                               "mode; it also exits 1 for a runtime failure such as an unresolvable range; "
                               f"stderr: {tail(step)}")
                return NativeOutcome(status="error", exit_code=result.exit_code, claims=[],
                                     error={"code": f"{step}_exit_{result.exit_code}",
                                            "message": message[:2000]}, **base)
        if export_failure is not None:
            return NativeOutcome(status="error", exit_code=exit_code, claims=[],
                                 error={"code": "unreadable_export",
                                        "message": f"deepsec exported findings this adapter could not "
                                                   f"read: {export_failure}; stderr: {tail('export')}"[:2000]},
                                 **base)
        if imported.lost or records.failures:
            detail = "; ".join(list(imported.notes) + list(records.failures))
            return NativeOutcome(status="partial", exit_code=exit_code, claims=imported.claims,
                                 error={"code": "import_loss",
                                        "message": f"{imported.lost} exported finding(s) and "
                                                   f"{len(records.failures)} DeepSec record(s) could not "
                                                   f"be imported: {detail}"[:2000]}, **base)

        def stopped(code: str, message: str) -> NativeOutcome:
            """The outcome of a run that reached no verdict on part of what it was given.

            ``partial``, carrying the claims DeepSec did produce, in every mode. The one refinement
            is a PR review in which no file reached a verdict at all: with nothing analyzed there is
            no partial observation to report, so it is an ``error`` with no claims.
            """
            if pr is not None:
                # What DeepSec wrote to stderr says why a run that stopped short stopped, when it
                # crashed instead of running out of quota, and costs nothing when it is empty.
                if process_result is not None and process_result.exit_code == DIRECT_MODE_EXIT:
                    detail = tail("process").strip()
                    message = f"{message}; deepsec process stderr: {detail}" if detail else message
                if statuses.finished == 0:
                    return NativeOutcome(status="error", exit_code=exit_code, claims=[],
                                         error={"code": code, "message": (f"{message}; no file reached a verdict, so "
                                                                          "none of the change was observed")[:2000]},
                                         **base)
                message = message[:2000]
            return NativeOutcome(status="partial", exit_code=exit_code, claims=imported.claims,
                                 error={"code": code, "message": message}, **base)

        if pr is not None and output.quota and (statuses.errored or statuses.unfinished):
            return stopped("quota_exhausted",
                           f"deepsec process stopped: {output.quota} exhausted, in DeepSec's own words. "
                           f"{statuses.finished} of {len(records.files)} file record(s) reached a verdict, "
                           f"{len(statuses.errored)} were left in status 'error' and {unfinished_files} were never "
                           "finished, so the rest of the change was not reviewed")
        subject = "input" if pr is None else "change"
        if batches_failed:
            counted = (f"; DeepSec itself counted {output.errored_batches} errored batch(es)"
                       if pr is not None and output.errored_batches else "")
            return stopped("deepsec_batches_failed",
                           f"{len(errored_files)} file(s) in status 'error', {len(records.debug)} parse-failure "
                           f"dump(s) and {refusals} refusal(s): part of the {subject} reached no verdict{counted}")
        if statuses.invalid:
            # A record whose state this cannot read is not a record this run can claim to have
            # finished. Reported before the unfinished ones because it is the stronger failure:
            # there, the run knows what it did not do; here, it does not know what it did.
            return stopped("invalid_record_status",
                           f"{len(statuses.invalid)} of {len(records.files)} "
                           "file record(s) carry a status DeepSec does not "
                           "declare, so whether it finished with them cannot "
                           "be read: "
                           + "; ".join(f"{name}: {reason}" for name, reason in statuses.invalid[:5]))
        if unfinished_files:
            # The AI stage never finished with these files. A ``success`` here would let the
            # scoring contract treat every assigned control as completed and grant quiet credit
            # for a file no model reached a verdict on, which is the one thing this adapter's
            # notes say the run does not establish. The status now says it too.
            limit = f" under config.limit {config.limit}" if config.limit is not None and pr is None else ""
            return stopped("scope_incomplete",
                           f"{unfinished_files} of {len(records.files)} file "
                           f"record(s) were left unfinished{limit} "
                           f"({', '.join(statuses.unfinished[:5])}): DeepSec "
                           "reached no verdict on them, so this run observed "
                           f"part of the {subject} and says nothing about the "
                           "rest")
        if omitted:
            # Known omissions of the change: DeepSec's listing cannot resolve these names (git quotes them, or
            # DeepSec trims the space at an end of them), so it never selected them and no model was given them.
            # Left to the empty-review block below, a change that touches only such paths would be a ``success``
            # with resolved bundles, the scoring contract would complete every control planned on one of them, and
            # a quiet assessment would be granted credit for a file nobody opened. It is the same case as a file
            # left unfinished, so it ends the same way.
            return stopped("scope_incomplete", unlistable_error(dropped))
        if pr is not None and not records.files:
            # No file record at all. DeepSec says so itself when its diff selects nothing, and that
            # statement is what makes this an empty review: without it the same silence could be a
            # run that never read the change.
            if process_result is not None and process_result.exit_code == 0 and output.nothing_to_process:
                base["notes"].append(
                    f"Empty review: DeepSec's direct mode resolved no file to investigate from {pr.revision_range} "
                    "(it said \"Nothing to process\") and left no file record. Every path the change touches was "
                    "deleted or dropped by DeepSec's own selection, so nothing was investigated; that is DeepSec's "
                    "scope and not a failure, and it says nothing about the paths it did not read.")
            else:
                return NativeOutcome(
                    status="error", exit_code=exit_code, claims=[],
                    error={"code": "nothing_processed",
                           "message": (f"deepsec process exited {process_result.exit_code if process_result else None} "
                                       "and left no file record, and its output does not carry the statement DeepSec "
                                       "prints when a diff selects no file, so an empty review cannot be told from a "
                                       f"run that read nothing; stderr: {tail('process')}")[:2000]}, **base)
        return NativeOutcome(status="success", exit_code=exit_code, claims=imported.claims, **base)
