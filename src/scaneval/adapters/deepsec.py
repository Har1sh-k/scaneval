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
it came from, except the exit 1 ``process`` gives a run that ended short, which is read from the
records (below); a step that ran out of the shared timeout budget is a timeout; an export this
adapter cannot read is an error and never an empty successful scan. A run whose records
report a file left in ``status: "error"``, a parse-failure dump under ``debug/``, or an
agent refusal is ``partial`` with code ``deepsec_batches_failed``: part of the input
reached no verdict, so the scan cannot stand as a complete or quiet observation of it. The
code is ``quota_exhausted`` when the exit says the quota ran out, and the status is an
``error`` with no claims when no file reached a verdict in a run whose exit 1 is read below.

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
of the change, so the run is never a ``success``, the only status that lets the scoring contract
complete a control and grant it quiet credit. Its bundles are unresolved, as when a file is left in
``error``: the claims about the rest are a part delivered, and no claim budget is read off a part.
The note names the path from one list (:class:`DroppedPaths`) in every such run, and the run says
nothing about it.

Whether the error names it too depends on whether another failure ends the run first: a timeout, a
step that failed, an export that could not be read, a record or a finding that could not be
imported, an exhausted quota, an errored batch, a record status DeepSec does not declare, or a file
left unfinished. If none does, the run is ``partial`` with code ``scope_incomplete``, or an
``error`` when no file reached a verdict, and the error names the path from the same list as the
note. If one does, the run keeps that failure's own status, code and error, and only the note names
the path. A file left unfinished also ends ``scope_incomplete``, so the code alone does not say
which of the two errors the run carries. A path that only the ignore filter dropped stays a note:
that is DeepSec's own scope.

What the run says about the paths it did not examine. A PR run that carries the claims DeepSec
produced, a ``success`` or a ``partial``, lists in the result's ``omitted_paths`` every path the
change touches that DeepSec created no file record for: each path present at head with none,
whatever the reason (the ignore filter, or a name its listing cannot resolve), and each path the
change removed, which DeepSec never reads (:func:`unexamined_paths`). The list comes from the same
comparison as the note and changes no status: a change that touches only paths DeepSec's filter
drops is still an empty review and a ``success``, and DeepSec's own filtering is not touched. What
it changes is what the scorer may conclude from that success. A control planned on a listed path, or
one the plan places on no path, earns no quiet credit, because DeepSec's own selection is not a
scope declared before the run; a scope exclusion is declared by leaving the item out of the plan.
When the list is every path the change touches, so that DeepSec made a record for none of it, the
result also says ``examined_nothing`` (:func:`~scaneval.adapters.pr.examined_nothing`), and then no
control earns quiet credit, one on a file the change leaves alone included: a review that read none
of the change reached no control. It says ``False`` when some path has a record. A full run reports
no omissions and says neither, unless it is curated.

Curated processing is an explicit diagnostic of a full run, never a benchmark. When
``config.process_manifest_by_tree`` is present it maps input tree hashes to neutral, repository-relative
path arrays, and the request's ``input.tree_hash`` must be a key; a tree with no entry, a malformed map
or path, a listed path that is not a regular file of the tree as spelled, a PR request (direct mode
ignores ``--manifest``) and ``config.files_from`` are all refused before anything runs. DeepSec's
ordinary ``scan`` still runs over the whole supported repository, then standard-mode ``process
--manifest`` assigns AI batches only to the pending records whose ``filePath`` is exactly a listed
path, and ``export`` runs unchanged. The manifest is a raw artifact holding paths only, its bytes are
checked after the run, and the map is part of the digested system configuration. Batch assignment is
not a sandbox: the agent still runs with the whole repository visible and may read unlisted files
(following an import, say), so ``omitted_paths`` are candidates that were assigned no verdict, not
files shown to be unread. Nothing is filtered out of the reconciliation: every record, status and
exported claim counts as in an ordinary run, so the regex candidates the manifest did not list are
assigned no AI batch, stay ``pending``, make the run ``scope_incomplete``, and are its
``omitted_paths``. After a scan that ran to the end, a listed path with no record had no regex
candidate, or was skipped by DeepSec's ignore filter, so no AI batch ran on it: native triage, not a
model's miss; after a scan that failed or was killed, the note says only that no scan completed. An
unlisted record carrying analysis, a finding or a status other than ``pending``, a claim on an unlisted
path, or a manifest whose bytes changed is
``process_manifest_not_honored``; its claims are kept. Every other failure keeps its precedence, and a
curated run that would otherwise succeed is ``partial`` with ``scope_incomplete`` instead. Its bundles
are never resolved, so it completes no control and earns no quiet credit. Every outcome a curated run
returns, whatever its status, records ``processing: curated`` on its result, the selection marker that
aggregation, comparison and the benchmark score show beside the adapter version; a full run records
none. A curated configuration refused before anything runs raises instead, so the error result the
runner records for it carries no marker, and reports derive one from the configuration.

``process`` exits 1 when a run ends short. Direct mode does it for three different reasons (a run
that produced findings, a batch that errored, an exhausted quota) and standard mode for the last two,
never for findings; both also exit 1 for a runtime failure such as an unresolvable range. Every
verdict is on disk before DeepSec exits, so an exit 1 is not fatal here and is not innocent either.
The run goes on to export, and what an exit 1 means is read from DeepSec's own records. In direct
mode findings, files left in ``error`` or unfinished, and a parse-failure dump explain it. In
standard mode only two things do: a file left in ``error``, which both of its causes leave on every
file of the batch that failed, and a file still ``processing``, which a run that died was holding. A
``pending`` record there is one the manifest or ``--limit`` left out or a quota stop put back, and a
dump can come from a batch that finished, so neither explains anything. An exit 1 that nothing
explains is an ``error`` naming the step, and keeps no claim. What DeepSec prints is used to name
the reason, never to decide the status, because text an agent's output can reach must not be able
to turn a failure into a success; a full run reads it only beside an exit 1. A PR review, or a full
run whose ``process`` exited 1, that was stopped by an exhausted quota, with an errored batch, or
with a changed path DeepSec could not list (above) is ``partial`` when some file still reached a
verdict and an ``error`` when none did, and its bundles are unresolved; a full run that exited 0
stays ``partial`` either way. "Nothing to process" is a
completed empty review only with exit 0, no file record, no changed path DeepSec could not list,
and DeepSec's own statement that it found nothing to do; the same silence without that statement
is an error.
"""

from __future__ import annotations

from collections import Counter
import errno
import hashlib
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
from ..kinds import kind_for_harness_class, load_mapping
from ..observer import Observer, create_jsonl_sink
from .base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command
from .llm_harness import Enclosure, read_record
from .pr import Change, examined_nothing, pr_range, removed_paths, workspace_changes


ARTIFACT_EXPORT = "deepsec-export"
# The module WP-D owns. Resolved by name at call time so this adapter loads, and a scan
# without transcript import still runs, on a checkout where the collectors are absent.
COLLECTOR_MODULE = "scaneval.collectors.claude_code"
DEFAULT_PROJECTS_DIR = "~/.claude/projects"
# The most a transcript being moved may hold: the collector's MAX_TRANSCRIPT_BYTES, spelled here
# for a checkout without the collector. See transcript_limit, which prefers the collector's own.
TRANSCRIPT_LIMIT = 64 * 1024 * 1024
# How much of a transcript a move holds in memory at once, the chunk the collector reads in.
TRANSCRIPT_CHUNK = 1 << 20
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
# What DeepSec 2.3.10's ``process`` prints when a run ends (process.ts and quota-message.ts in its
# bundle): both modes print the same summary and quota lines, and only direct mode says it had nothing
# to process. It colors its output whether or not stdout is a terminal, so the escape sequences come
# off before anything is matched.
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
NOTHING_TO_PROCESS = re.compile("^Nothing to process \u2014 exit 0\\.$", re.MULTILINE)
QUOTA_STOPPED = re.compile("^\u2718 Stopped: (.+) exhausted$", re.MULTILINE)
PROCESS_FINDINGS = re.compile(r"^ *Findings: ([0-9]+)$", re.MULTILINE)
PROCESS_ERRORED_BATCHES = re.compile(r"^ *Errored batches: ([0-9]+)$", re.MULTILINE)
# The summary is the last thing DeepSec prints, so the end of the file is what is read for it.
PROCESS_OUTPUT_TAIL = 16384
# Direct mode's exit for findings, an errored batch and an exhausted quota, and for a runtime failure.
DIRECT_MODE_EXIT = 1
# Standard mode's exit for an errored batch and an exhausted quota, never for findings, and for a
# runtime failure (processCommand in 2.3.10). It prints the reason on stdout, after every record is
# written.
STANDARD_MODE_EXIT = 1
# DeepSec 2.3.10's exportCommand applies these exclusions unless --include-resolved is
# passed. This adapter deliberately preserves the producer's defaults and passes no such flag.
DEFAULT_EXPORT_RESOLVED_VERDICTS = ("fixed", "false-positive", "accepted-risk", "duplicate")
# A key of config.process_manifest_by_tree: the ``input.tree_hash`` a scan request carries.
TREE_HASH = re.compile(r"sha256:[0-9a-f]{64}")
WINDOWS_DRIVE = re.compile(r"[A-Za-z]:")
ARTIFACT_PROCESS_MANIFEST = "deepsec-process-manifest"


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


def workspace_discovery() -> Any | None:
    """The collector's ``find_workspace_sessions``, or ``None`` on a checkout without it."""
    try:
        module = import_module(COLLECTOR_MODULE)
    except ImportError:
        return None
    return getattr(module, "find_workspace_sessions", None)


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

    Producer-specific slugs use the versioned DeepSec table, matched exactly. Common
    slugs use the existing harness table: DeepSec spells ``sql-injection`` with hyphens
    where that table keys it without separators, so separators are removed for the fallback. An
    ``other-`` slug the agent minted for a novel finding, and any slug the mapping does not
    know, stays ``unmapped`` and keeps its native identity on the claim.
    """
    if not slug:
        return kind_for_harness_class(None)
    native = str(slug)
    return (load_mapping()["deepsec_slugs"].get(native)
            or kind_for_harness_class(re.sub(r"[-_\s]", "", native)))


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
    files_from: tuple[str, ...] | None = None
    capture_claude_sessions: bool = False
    process_manifest_by_tree: dict[str, tuple[str, ...]] | None = None


def process_manifest_path_issue(entry: Any) -> str | None:
    """Why *entry* cannot be a ``process --manifest`` path, or ``None`` when it can.

    DeepSec 2.3.10 selects a record when ``Set.has(record.filePath)`` holds: an exact string
    match, with no normalization and no directory prefix. The ``filePath`` its scan writes is the
    one spelling ``assertSafeFilePath`` admits, relative, with forward slashes and no empty, ``.``
    or ``..`` segment. So an entry must already be that spelling. Nothing is rewritten into it,
    because what the configuration digest binds must be exactly what DeepSec's ``--manifest``
    reads; an entry that is not that spelling would select nothing, or, through a separator or
    traversal, name something outside the tree. A backslash, a drive letter, a control character
    and whitespace at either end are refused for the same reason: each is either outside the
    native spelling or one DeepSec's own listing reads differently. The drive-letter test is any
    ASCII letter then ``:`` at the start, so it also refuses a valid POSIX name such as ``a:b``;
    that over-refusal is in the safe direction.
    """
    if not isinstance(entry, str):
        return f"it is a {_shape(entry)}, not a string"
    if not entry:
        return "it is empty"
    if "\x00" in entry:
        return "it holds a NUL byte"
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in entry):
        return "it holds a control character"
    if any(0xD800 <= ord(character) <= 0xDFFF for character in entry):
        # Python's spelling of an undecodable byte in a file name; DeepSec reads that name as
        # U+FFFD, so the two can never match.
        return "it holds a lone surrogate, which no file path DeepSec records can"
    if "\\" in entry:
        return "it holds a backslash, which DeepSec refuses in a file path"
    if entry.startswith("/"):
        return "it is an absolute path"
    if WINDOWS_DRIVE.match(entry):
        return "it starts with a drive letter"
    if entry != entry.strip():
        return "it begins or ends with whitespace"
    if any(part in ("", ".", "..") for part in entry.split("/")):
        return "it has an empty, '.' or '..' segment, so it is not the one spelling DeepSec records"
    return None


def _process_manifest_by_tree(spec: SystemSpec) -> dict[str, tuple[str, ...]] | None:
    """The curated AI-batch assignment of a full run, one neutral path list per input tree hash.

    Absent is off, and off is the ordinary full run. Present is an object whose keys are input
    tree hashes and whose values are non-empty arrays of paths, each checked by
    :func:`process_manifest_path_issue` and each listed once. Anything else is refused here,
    before a process starts: ``null`` and ``{}`` included, because a generator that wrote either
    for an input it had no list for must not get an unscoped run in its place, and an empty list
    too, because a run that assigns no AI batch is not the diagnostic this configures.
    The map lives in the system configuration, so the run's configuration digest binds it, and it
    carries paths only.
    """
    if "process_manifest_by_tree" not in spec.config:
        return None
    raw = spec.config["process_manifest_by_tree"]
    if not isinstance(raw, dict) or not raw:
        raise AdapterError("deepsec config.process_manifest_by_tree must be a non-empty object mapping input "
                           f"tree hashes to path arrays, got {raw!r}"[:500])
    result: dict[str, tuple[str, ...]] = {}
    for tree_hash, entries in raw.items():
        if not isinstance(tree_hash, str) or TREE_HASH.fullmatch(tree_hash) is None:
            raise AdapterError("deepsec config.process_manifest_by_tree keys must be input tree hashes "
                               f"(sha256:<64 lowercase hex>), got {tree_hash!r}"[:500])
        if not isinstance(entries, list) or not entries:
            raise AdapterError(f"deepsec config.process_manifest_by_tree[{tree_hash!r}] must be a non-empty "
                               f"array of paths, got a {_shape(entries)}"
                               + (" with no entry" if isinstance(entries, list) else ""))
        seen: set[str] = set()
        for index, entry in enumerate(entries):
            issue = process_manifest_path_issue(entry)
            if issue is None and entry in seen:
                issue = "it is listed twice"
            if issue is not None:
                raise AdapterError(f"deepsec config.process_manifest_by_tree[{tree_hash!r}][{index}] is not a "
                                   f"usable path: {issue} ({entry!r})"[:500])
            seen.add(entry)
        result[tree_hash] = tuple(entries)
    return result


def _files_from(spec: SystemSpec) -> tuple[str, ...] | None:
    """The operator's file list for a PR review, read from the file ``config.files_from`` names.

    One path per line, relative to the repository root; blank lines and ``#`` comments are skipped.
    Each is checked here, before anything runs, so a list that would leave the tree is a setup
    failure. The list is a scope declared before the run: DeepSec reviews exactly these paths
    instead of the whole change, and the changed paths it leaves out are reported as omitted.
    """
    configured = _text(spec, "files_from")
    if configured is None:
        return None
    path = Path(configured).expanduser()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise AdapterError(f"deepsec config.files_from could not be read: {exc}") from exc
    paths: list[str] = []
    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if "\x00" in entry or entry.startswith("/") or ".." in PurePosixPath(entry).parts:
            raise AdapterError(f"deepsec config.files_from names a path outside the repository: {entry!r}")
        if entry not in paths:
            paths.append(entry)
    if not paths:
        raise AdapterError("deepsec config.files_from names no path")
    return tuple(paths)


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
    config = Settings(
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
        files_from=_files_from(spec),
        capture_claude_sessions=_flag(spec, "capture_claude_sessions"),
        process_manifest_by_tree=_process_manifest_by_tree(spec),
    )
    if config.files_from is not None and config.process_manifest_by_tree is not None:
        raise AdapterError("deepsec config.files_from and config.process_manifest_by_tree are mutually exclusive: "
                           "the first scopes a PR review through direct mode, which ignores --manifest")
    return config


def _flag(spec: SystemSpec, key: str) -> bool:
    value = spec.config.get(key, False)
    if not isinstance(value, bool):
        raise AdapterError(f"deepsec config.{key} must be a boolean, got a {_shape(value)}")
    return value


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

    ``held`` is the subset of ``unfinished`` in ``processing``. Standard-mode ``process`` claims
    every record it selected as ``processing`` before its first batch, so one still held after
    the run is a run that ended while working on it; a ``pending`` record is one it never
    selected (the manifest or ``--limit`` left it out) or put back after a quota stop.
    """

    finished: int
    unfinished: tuple[str, ...]
    errored: tuple[str, ...]
    invalid: tuple[tuple[str, str], ...]
    held: tuple[str, ...] = ()

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
    held: list[str] = []
    for name, record in files:
        status = record.get("status") if isinstance(record, dict) else None
        if status == FINISHED_STATUS:
            finished += 1
        elif status in UNFINISHED_STATUSES:
            unfinished.append(f"{name} ({status})")
            if status == "processing":
                held.append(name)
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
                          tuple(sorted(invalid)), tuple(sorted(held)))


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
                payload = json.loads(
                    data.decode("utf-8"), parse_constant=_reject_nonstandard_json_constant)
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

``correlation`` says how the call boundary was arrived at, and only one of its four values
    means DeepSec supplied it.

    ``agent_session_id`` is DeepSec's own. ``missing_session_id`` is an entry that carried none:
    those used to share one empty key, so unrelated batches were merged into a single call with
    their paths, turns, cost and tokens added together, which is correlation being invented at
    exactly the moment the native identifier was absent. ``invalid_session_id`` is an entry
    whose id is not one transcript discovery may be handed — the value is scanner-written, and
    an id like ``*`` reached a glob and imported the transcripts of unrelated sessions. Both of
    the latter get their own per-entry group and are never passed to discovery.
    ``workspace_history`` is a session no analysis entry names, found by
    :func:`workspace_history` in the history of this invocation's own workspace: a batch
    that failed before DeepSec recorded an analysis. It carries no paths and no numbers, because
    DeepSec wrote none for it.
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
        """Whether DeepSec itself named this call."""
        return self.correlation == "agent_session_id"

    @property
    def discoverable(self) -> bool:
        """Whether transcript discovery may be given this session's id.

        DeepSec's own id, or one this adapter read off a transcript name in the workspace's own
        history. Never a missing or refused id.
        """
        return self.correlation in ("agent_session_id", "workspace_history")


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


class WorkspaceHistory(NamedTuple):
    """The sessions this invocation's own workspace history holds, and the files it verified."""

    # The sessions no analysis entry names.
    unreferenced: tuple[Session, ...]
    # Every adopted session's verified files, main transcript first. Import and archive read
    # these paths and never look an ID up anywhere else.
    transcripts: dict[str, tuple[Path, ...]]
    # Transcripts in the workspace's project directory whose records did not show they ran in it.
    foreign: int
    # Transcripts that could not be read to their end, so their ownership was never settled.
    unverified: int
    # Whether the workspace history could be listed at all.
    listed: bool


NO_HISTORY = WorkspaceHistory((), {}, 0, 0, False)


def workspace_history(sessions: tuple[Session, ...], roots: tuple[Path, ...],
                      projects_dir: Path) -> WorkspaceHistory:
    """The agent sessions this run opened, as its own workspace history verifies them.

    Every session of this invocation ran in its private source directory, and the CLI files each
    transcript under the project directory named after that working directory, so that directory
    is the run's own register of the sessions it opened. The collector lists it and nothing else,
    and adopts only transcripts whose records, read to their end, say they ran inside the
    workspace. Those verified paths are the only transcripts this adapter reads: a session ID,
    named by DeepSec or not, is never looked up across the operator's other project directories,
    where the same ID could name another project's records.

    DeepSec writes ``agentSessionId`` only onto the analysis entries of a batch that finished, so
    a batch that failed (an exhausted session limit, an output it could not parse) leaves a
    transcript and no record naming it. The sessions DeepSec did not name are returned as
    ``unreferenced``.
    """
    find = workspace_discovery()
    if find is None:
        return NO_HISTORY
    try:
        found = find(tuple(str(root) for root in roots), projects_dir=projects_dir)
    except Exception:  # noqa: BLE001 - a discovery failure costs the transcripts, not the scan
        return NO_HISTORY
    verified = getattr(found, "transcripts", None)
    transcripts = {session_id: tuple(Path(path) for path in paths)
                   for session_id, paths in (verified.items() if isinstance(verified, dict) else ())
                   if session_id_usable(session_id) and isinstance(paths, (list, tuple)) and paths}
    named = {session.session_id for session in sessions if session.correlated}
    extra = tuple(
        Session(run_id="", session_id=session_id, model=None, paths=(), num_turns=0.0, cost_usd=0.0,
                duration_ms=0.0, duration_api_ms=0.0, usage={}, refusals=(),
                correlation="workspace_history", key=f"workspace-history/{session_id}",
                external_paths=0)
        for session_id in transcripts if session_id not in named)
    count = lambda name: value if isinstance(value := getattr(found, name, 0), int) else 0  # noqa: E731
    return WorkspaceHistory(extra, transcripts, count("foreign"), count("unverified"), True)


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

    ``lost`` is the number of exported findings that did not become claims. ``unjoined`` is
    different: those export entries did become usable claims, but the export carries no native
    id and its retained fields could not establish one exact record identity. The caller
    degrades either case, while keeping the usable unjoined claims and never counting them as
    dropped findings.
    """

    claims: list[dict]
    notes: list[str]
    lost: int
    unjoined: int
    findings: list[dict]


class FindingIdentity(NamedTuple):
    """Fields copied unchanged from one record finding into the JSON export."""

    project: str
    path: str
    title: str
    severity: str
    slug: str
    lines: tuple[Any, ...]
    confidence: str
    revalidation: tuple[Any, ...] | None


FindingIdIndex = dict[FindingIdentity, Counter[str]]

NATIVE_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "HIGH_BUG", "BUG", "LOW")
NATIVE_CONFIDENCES = ("high", "medium", "low")
NATIVE_REVALIDATION_VERDICTS = (
    "true-positive", "false-positive", "fixed", "uncertain", "accepted-risk", "duplicate")


class NativeExportPopulation(NamedTuple):
    """Native-loaded findings, exact export identities, exclusions, and validation gaps."""

    ids: Counter[str]
    identities: FindingIdIndex
    derived_identities: FindingIdIndex
    status_identities: FindingIdIndex
    status_derived_identities: FindingIdIndex
    no_latest_analysis: int
    resolved: Counter[str]
    validation_issues: tuple[str, ...]
    status_validation_issues: tuple[str, ...]

    @property
    def excluded(self) -> int:
        return self.no_latest_analysis + self.resolved.total()


def _reject_nonstandard_json_constant(value: str) -> Any:
    """Reject numeric tokens accepted by Python but rejected by JavaScript ``JSON.parse``."""
    raise ValueError(f"non-standard JSON constant {value}")


def _native_number(value: Any) -> bool:
    """Whether *value* is a finite JavaScript/JSON number accepted by Zod's number schema."""
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and value == value and value not in (float("inf"), float("-inf")))


def _native_strings(value: Any, fields: tuple[str, ...], label: str) -> str | None:
    if not isinstance(value, dict):
        return f"{label} is a {_shape(value)}, not an object"
    for field in fields:
        if not isinstance(value.get(field), str):
            return f"{label}.{field} is not a string"
    return None


def _native_candidate_issue(value: Any, label: str) -> str | None:
    issue = _native_strings(value, ("vulnSlug", "snippet", "matchedPattern"), label)
    if issue:
        return issue
    lines = value.get("lineNumbers")
    if not isinstance(lines, list) or not all(_native_number(line) for line in lines):
        return f"{label}.lineNumbers is not an array of numbers"
    return None


def _native_refusal_issue(value: Any, label: str) -> str | None:
    if not isinstance(value, dict):
        return f"{label} is a {_shape(value)}, not an object"
    if not isinstance(value.get("refused"), bool):
        return f"{label}.refused is not a boolean"
    for field in ("reason", "raw"):
        if field in value and not isinstance(value[field], str):
            return f"{label}.{field} is not a string"
    if "skipped" in value:
        skipped = value["skipped"]
        if not isinstance(skipped, list):
            return f"{label}.skipped is not an array"
        for index, item in enumerate(skipped):
            item_label = f"{label}.skipped[{index}]"
            issue = _native_strings(item, ("reason",), item_label)
            if issue:
                return issue
            if "filePath" in item and not isinstance(item["filePath"], str):
                return f"{item_label}.filePath is not a string"
    return None


def _native_analysis_issue(value: Any, label: str) -> str | None:
    issue = _native_strings(
        value, ("runId", "investigatedAt", "agentType", "model"), label)
    if issue:
        return issue
    for field in ("durationMs", "findingCount"):
        if not _native_number(value.get(field)):
            return f"{label}.{field} is not a number"
    if not isinstance(value.get("modelConfig"), dict):
        return f"{label}.modelConfig is not an object"
    for field in ("durationApiMs", "numTurns", "costUsd", "reinvestigateMarker"):
        if field in value and not _native_number(value[field]):
            return f"{label}.{field} is not a number"
    for field in ("agentSessionId", "codexStderr"):
        if field in value and not isinstance(value[field], str):
            return f"{label}.{field} is not a string"
    if "phase" in value and value["phase"] not in ("process", "revalidate"):
        return f"{label}.phase is not 'process' or 'revalidate'"
    if "usage" in value:
        usage = value["usage"]
        if not isinstance(usage, dict):
            return f"{label}.usage is not an object"
        for field in ("inputTokens", "outputTokens", "cacheReadInputTokens",
                      "cacheCreationInputTokens"):
            if not _native_number(usage.get(field)):
                return f"{label}.usage.{field} is not a number"
    if "refusal" in value:
        return _native_refusal_issue(value["refusal"], f"{label}.refusal")
    return None


def _native_git_issue(value: Any, label: str) -> str | None:
    if not isinstance(value, dict):
        return f"{label} is a {_shape(value)}, not an object"
    committers = value.get("recentCommitters")
    if not isinstance(committers, list):
        return f"{label}.recentCommitters is not an array"
    for index, committer in enumerate(committers):
        issue = _native_strings(
            committer, ("name", "email", "date"), f"{label}.recentCommitters[{index}]")
        if issue:
            return issue
    if not isinstance(value.get("enrichedAt"), str):
        return f"{label}.enrichedAt is not a string"
    if "ownership" not in value:
        return None
    ownership = value["ownership"]
    if not isinstance(ownership, dict):
        return f"{label}.ownership is not an object"
    contributors = ownership.get("contributors")
    if not isinstance(contributors, list):
        return f"{label}.ownership.contributors is not an array"
    for index, contributor in enumerate(contributors):
        item_label = f"{label}.ownership.contributors[{index}]"
        issue = _native_strings(
            contributor, ("email", "name", "github_username", "context", "last_contrib"),
            item_label)
        if issue:
            return issue
        if not _native_number(contributor.get("score")):
            return f"{item_label}.score is not a number"
    teams = ownership.get("escalationTeams")
    if not isinstance(teams, list):
        return f"{label}.ownership.escalationTeams is not an array"
    for index, team in enumerate(teams):
        item_label = f"{label}.ownership.escalationTeams[{index}]"
        issue = _native_strings(
            team, ("name", "slug", "source", "escalation_path_id"), item_label)
        if issue:
            return issue
        if "slack_channel_id" not in team:
            return f"{item_label}.slack_channel_id is missing"
        if team["slack_channel_id"] is not None and not isinstance(team["slack_channel_id"], str):
            return f"{item_label}.slack_channel_id is neither a string nor null"
        issue = _native_strings(team.get("manager"), ("email", "slack_user_id"),
                                f"{item_label}.manager")
        if issue:
            return issue
        issue = _native_strings(
            team.get("current_oncall"),
            ("name", "email", "slack_user_id", "github_username"),
            f"{item_label}.current_oncall")
        if issue:
            return issue
    approvers = ownership.get("approvers")
    if not isinstance(approvers, list):
        return f"{label}.ownership.approvers is not an array"
    for index, approver in enumerate(approvers):
        item_label = f"{label}.ownership.approvers[{index}]"
        issue = _native_strings(approver, ("owner", "owner_type"), item_label)
        if issue:
            return issue
        if "pattern" not in approver:
            return f"{item_label}.pattern is missing"
        if approver["pattern"] is not None and not isinstance(approver["pattern"], str):
            return f"{item_label}.pattern is neither a string nor null"
        for field in ("is_primary", "is_direct"):
            if not isinstance(approver.get(field), bool):
                return f"{item_label}.{field} is not a boolean"
    if not isinstance(ownership.get("fetchedAt"), str):
        return f"{label}.ownership.fetchedAt is not a string"
    return None


def _native_record_envelope_issue(record: dict) -> str | None:
    """Validate DeepSec's FileRecord envelope, whose findings are salvaged separately."""
    issue = _native_strings(
        record, ("filePath", "projectId", "lastScannedAt", "lastScannedRunId", "fileHash"),
        "record")
    if issue:
        return issue
    candidates = record.get("candidates")
    if not isinstance(candidates, list):
        return "record.candidates is not an array"
    for index, candidate in enumerate(candidates):
        issue = _native_candidate_issue(candidate, f"record.candidates[{index}]")
        if issue:
            return issue
    if not isinstance(record.get("findings"), list):
        return "record.findings is not an array"
    history = record.get("analysisHistory")
    if not isinstance(history, list):
        return "record.analysisHistory is not an array"
    for index, entry in enumerate(history):
        issue = _native_analysis_issue(entry, f"record.analysisHistory[{index}]")
        if issue:
            return issue
    # Status is classified separately by ``native_export_population``. It is still a native
    # envelope failure, but by itself it must not masquerade as lost import evidence and outrank
    # the adapter's established quota/batch failure codes.
    for field in ("lockedByRunId", "lockedAt"):
        if field in record and not isinstance(record[field], str):
            return f"record.{field} is not a string"
    if "gitInfo" in record:
        return _native_git_issue(record["gitInfo"], "record.gitInfo")
    return None


def _native_revalidation_issue(value: Any, label: str) -> str | None:
    issue = _native_strings(value, ("reasoning", "revalidatedAt", "runId", "model"), label)
    if issue:
        return issue
    if value.get("verdict") not in NATIVE_REVALIDATION_VERDICTS:
        return f"{label}.verdict is not a declared DeepSec verdict"
    if "adjustedSeverity" in value and value["adjustedSeverity"] not in NATIVE_SEVERITIES:
        return f"{label}.adjustedSeverity is not a declared DeepSec severity"
    if "duplicateOf" in value and not isinstance(value["duplicateOf"], str):
        return f"{label}.duplicateOf is not a string"
    return None


def _native_finding_issue(value: Any, label: str) -> str | None:
    issue = _native_strings(
        value, ("vulnSlug", "title", "description", "recommendation"), label)
    if issue:
        return issue
    if "findingId" in value and not isinstance(value["findingId"], str):
        return f"{label}.findingId is not a string"
    if value.get("severity") not in NATIVE_SEVERITIES:
        return f"{label}.severity is not a declared DeepSec severity"
    if value.get("confidence") not in NATIVE_CONFIDENCES:
        return f"{label}.confidence is not a declared DeepSec confidence"
    lines = value.get("lineNumbers")
    if not isinstance(lines, list) or not all(_native_number(line) for line in lines):
        return f"{label}.lineNumbers is not an array of numbers"
    if "producedByRunId" in value and not isinstance(value["producedByRunId"], str):
        return f"{label}.producedByRunId is not a string"
    if "triage" in value:
        triage = value["triage"]
        issue = _native_strings(triage, ("reasoning", "triagedAt", "model"), f"{label}.triage")
        if issue:
            return issue
        if triage.get("priority") not in ("P0", "P1", "P2", "skip"):
            return f"{label}.triage.priority is not a declared priority"
        if triage.get("exploitability") not in ("trivial", "moderate", "difficult"):
            return f"{label}.triage.exploitability is not a declared exploitability"
        if triage.get("impact") not in ("critical", "high", "medium", "low"):
            return f"{label}.triage.impact is not a declared impact"
    if "revalidation" in value:
        return _native_revalidation_issue(value["revalidation"], f"{label}.revalidation")
    return None


def _javascript_utf8(value: str) -> bytes:
    """Encode a Python string as Node's UTF-8 encoder treats JavaScript UTF-16 strings.

    JSON can legally carry escaped lone surrogates. Python's default UTF-8 encoder raises on
    them, while Node replaces each unpaired UTF-16 code unit with U+FFFD and combines a valid
    surrogate pair. Reproducing that rule keeps deterministic native IDs from crashing on valid
    JSON or silently hashing Python's different replacement byte.
    """
    scalars: list[str] = []
    index = 0
    while index < len(value):
        codepoint = ord(value[index])
        if 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 < len(value):
                following = ord(value[index + 1])
                if 0xDC00 <= following <= 0xDFFF:
                    scalars.append(chr(0x10000 + ((codepoint - 0xD800) << 10)
                                       + following - 0xDC00))
                    index += 2
                    continue
            scalars.append("\ufffd")
        elif 0xDC00 <= codepoint <= 0xDFFF:
            scalars.append("\ufffd")
        else:
            scalars.append(value[index])
        index += 1
    return "".join(scalars).encode("utf-8")


def _native_finding_id(project: str, raw_path: str, title: str) -> str:
    """DeepSec 2.3.10 ``computeFindingId``, byte-for-byte and without touching records."""
    normalized = raw_path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    material = f"{project}\0{normalized}\0{title}"
    return f"finding_{hashlib.sha256(_javascript_utf8(material)).hexdigest()[:16]}"


def _effective_finding_ids(record: dict, findings: list[dict]) -> tuple[tuple[str, bool], ...]:
    """Pure ``ensureFindingIds`` output as ``(id, was_derived)`` in finding order."""
    used = {finding["findingId"] for finding in findings if finding.get("findingId")}
    effective: list[tuple[str, bool]] = []
    for finding in findings:
        stored = finding.get("findingId")
        if stored:
            effective.append((stored, False))
            continue
        title = finding["title"]
        identifier = _native_finding_id(record["projectId"], record["filePath"], title)
        ordinal = 2
        while identifier in used:
            identifier = _native_finding_id(
                record["projectId"], record["filePath"], f"{title}\0{ordinal}")
            ordinal += 1
        used.add(identifier)
        effective.append((identifier, True))
    return tuple(effective)


def _identity_value(value: Any) -> Any:
    """A hashable, type-preserving form of a JSON value used only for exact comparison."""
    if isinstance(value, dict):
        return ("object", tuple(sorted((str(key), _identity_value(item))
                                       for key, item in value.items())))
    if isinstance(value, list):
        return ("array", tuple(_identity_value(item) for item in value))
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, (int, float)):
        return ("number", value)
    return (type(value).__name__, repr(value))


def _retained_revalidation(value: Any) -> tuple[Any, ...] | None:
    """The two revalidation members ``exportCommand`` retains, including absence vs null."""
    if value is None:
        return None
    if not isinstance(value, dict):
        return ("invalid", _identity_value(value))
    return tuple((key, key in value, _identity_value(value.get(key)))
                 for key in ("verdict", "reasoning"))


def _record_finding_identity(record: dict, finding: dict) -> FindingIdentity | None:
    """Exact identity available on both a native record finding and its JSON export entry."""
    project = record.get("projectId")
    raw_path = record.get("filePath")
    title = finding.get("title")
    severity = finding.get("severity")
    slug = finding.get("vulnSlug")
    lines = finding.get("lineNumbers")
    confidence = finding.get("confidence")
    if not all(isinstance(value, str) for value in (project, raw_path, title, severity,
                                                    slug, confidence)):
        return None
    path, unusable = claim_path(raw_path)
    if unusable or not isinstance(lines, list):
        return None
    return FindingIdentity(project, path, title, severity, slug,
                           tuple(_identity_value(line) for line in lines), confidence,
                           _retained_revalidation(finding.get("revalidation")))


def _export_finding_identity(entry: dict, metadata: dict, path: str) -> FindingIdentity | None:
    """Reconstruct the raw record identity without applying display-title normalization."""
    project = metadata.get("projectId")
    rendered_title = entry.get("title")
    rendered_severity = entry.get("severity")
    severity = metadata.get("severity")
    slug = metadata.get("vulnSlug")
    lines = metadata.get("lineNumbers")
    confidence = metadata.get("confidence")
    if not all(isinstance(value, str) for value in (project, rendered_title, rendered_severity,
                                                    severity, slug, confidence)):
        return None
    if rendered_severity != severity:
        return None
    prefix = f"[{severity}] "
    if not rendered_title.startswith(prefix) or not isinstance(lines, list):
        return None
    # Native export uses exactly ``[severity] ${finding.title}``; retaining the remainder
    # verbatim is essential because finding ids include title whitespace.
    title = rendered_title[len(prefix):]
    return FindingIdentity(project, path, title, severity, slug,
                           tuple(_identity_value(line) for line in lines), confidence,
                           _retained_revalidation(metadata.get("revalidation")))


def native_export_population(files: tuple[tuple[str, dict], ...]) -> NativeExportPopulation:
    """Reproduce the population DeepSec 2.3.10 actually loads and exports, without mutation.

    ``loadAllFileRecords`` first validates the FileRecord envelope, dropping the whole record if
    any non-finding field is invalid. Its salvage path then validates findings one by one and
    drops malformed findings. Only after that does it call ``ensureFindingIds`` in memory. The
    raw JSON record is not rewritten. This function follows the same order, records every native
    validation gap, and never uses malformed evidence to claim an intended producer exclusion.

    The only verified no-latest case is an actual empty, schema-valid ``analysisHistory`` list.
    Missing, null, non-array and malformed histories make the FileRecord envelope invalid and are
    therefore unresolved import evidence, not successful default-export exclusions. Likewise a
    resolved verdict counts as an intended exclusion only when the entire Finding and its full
    Revalidation satisfy the pinned schemas.

    ``ensureFindingIds`` preloads every truthy stored id, preserves it, then derives missing or
    empty ids from project id, the raw path with backslashes replaced and only one initial ``./``
    removed, and the raw title. A collision retries ``title + NUL + n`` from 2. The pure port here
    reproduces Node's UTF-8 handling, including escaped surrogate code units, but never mutates a
    record or artifact. Derived provenance travels separately from the native-equivalent id.
    """
    identifiers: Counter[str] = Counter()
    identities: FindingIdIndex = {}
    derived_identities: FindingIdIndex = {}
    status_identities: FindingIdIndex = {}
    status_derived_identities: FindingIdIndex = {}
    no_latest_analysis = 0
    resolved: Counter[str] = Counter()
    validation_issues: list[str] = []
    status_validation_issues: list[str] = []
    for name, record in files:
        issue = _native_record_envelope_issue(record)
        if issue:
            validation_issues.append(
                f"{name}: {issue}; DeepSec's FileRecord envelope validation skips the whole record")
            continue
        status_only = record.get("status") not in RECORD_STATUSES
        if status_only:
            status_validation_issues.append(
                f"{name}: record.status is not one of {RECORD_STATUSES}; "
                "DeepSec's FileRecord envelope validation skips the whole record")
        valid_findings: list[dict] = []
        for index, finding in enumerate(record["findings"]):
            issue = _native_finding_issue(finding, f"finding[{index}]")
            if issue:
                validation_issues.append(
                    f"{name}: {issue}; DeepSec's salvage loader drops this malformed finding")
                continue
            valid_findings.append(finding)
        effective_ids = _effective_finding_ids(record, valid_findings)
        if not record["analysisHistory"]:
            if not status_only:
                no_latest_analysis += len(valid_findings)
            continue
        target_identities = status_identities if status_only else identities
        target_derived = status_derived_identities if status_only else derived_identities
        for finding, (identifier, was_derived) in zip(valid_findings, effective_ids):
            revalidation = finding.get("revalidation")
            verdict = revalidation.get("verdict") if isinstance(revalidation, dict) else None
            if verdict in DEFAULT_EXPORT_RESOLVED_VERDICTS:
                if not status_only:
                    resolved[verdict] += 1
                continue
            if not status_only:
                identifiers[identifier] += 1
            identity = _record_finding_identity(record, finding)
            if identity is not None:
                target_identities.setdefault(identity, Counter())[identifier] += 1
                if was_derived:
                    target_derived.setdefault(identity, Counter())[identifier] += 1
    return NativeExportPopulation(
        identifiers, identities, derived_identities, status_identities,
        status_derived_identities, no_latest_analysis, resolved,
        tuple(validation_issues), tuple(status_validation_issues))


def finding_ids(files: tuple[tuple[str, dict], ...]) -> FindingIdIndex:
    """Exact default-export identity to eligible native-id multisets from file records."""
    return native_export_population(files).identities


def import_export(payload: Any, *, artifact_id: str = ARTIFACT_EXPORT,
                  ids: FindingIdIndex | None = None,
                  derived_ids: FindingIdIndex | None = None) -> DeepsecImport:
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
    unjoined = 0
    available_ids = {identity: Counter(identifiers) for identity, identifiers in (ids or {}).items()}
    native_derived = {identity: Counter(identifiers)
                      for identity, identifiers in (derived_ids or {}).items()}
    noted_derived: set[tuple[FindingIdentity, str]] = set()
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
        # Display normalization is deliberately separate from native identity. In particular,
        # trailing whitespace is stripped from the allegation but retained by the exact join.
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
        identity = _export_finding_identity(entry, metadata, path)
        identifiers = available_ids.get(identity) if identity is not None else None
        identifier = None
        if identifiers:
            remaining = [candidate for candidate, count in identifiers.items() if count > 0]
            if len(remaining) == 1:
                # Reused identical ids remain safe: every indistinguishable occurrence names
                # the same native identity. Distinct ids for one retained identity are not safe
                # to hand out by occurrence, because the export carries no ordering key for them.
                identifier = remaining[0]
                derived_count = native_derived.get(identity, Counter())[identifier]
                population_count = identifiers[identifier]
                provenance = (identity, identifier)
                if derived_count and provenance not in noted_derived:
                    qualifier = ("every matching raw FileRecord occurrence lacked a stored findingId"
                                 if derived_count == population_count else
                                 f"{derived_count} of {population_count} matching raw FileRecord occurrence(s) "
                                 "lacked a stored findingId")
                    notes.append(
                        f"For this retained identity, {qualifier}. Native finding id {identifier!r} was "
                        "deterministically reproduced in memory with DeepSec 2.3.10's ensureFindingIds "
                        "algorithm; the raw record and artifact were not changed.")
                    noted_derived.add(provenance)
                identifiers[identifier] -= 1
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
            unjoined += 1
            notes.append(f"export entry {index} ({path}) could not establish one exact native record "
                         "identity, so no native finding id is recorded for it")
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
    return DeepsecImport(claims, notes, lost, unjoined, findings)


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
    # Every session this run knows it opened: the ones DeepSec named, the ones found only in
    # the workspace history, and one for each failed batch whose session neither one found.
    sessions_expected: int = 0
    # How many sessions ended on each closed cause the Claude Code CLI recorded for a request
    # the provider refused (``session_limit``, ``rate_limit``, ...): the session's last response
    # was that refusal. A refusal the session went on past is not counted here.
    sessions_ended_on_refusal: dict = {}
    # Every refused request the transcripts recorded, by cause, whether or not a later response
    # recovered from it.
    refusals_recorded: dict = {}


def _overlapping(candidates: tuple[Candidate, ...], path: str, slug: str,
                 start: int | None, end: int | None) -> list[str]:
    """Candidate ids of *slug* on *path* that overlap ``[start, end]``, or all file-level.

    A finding that cited no line cannot be narrowed by line, so every candidate of the same
    native vulnerability class on the file is listed. The slug remains part of the intersection:
    a regex hit for an unrelated class on the same line is not evidence for this finding.
    """
    ids = []
    for candidate in candidates:
        if candidate.path != path or candidate.slug != slug:
            continue
        if start is None or end is None or not candidate.lines:
            ids.append(candidate.candidate_id)
            continue
        if any(start <= line <= end for line in candidate.lines):
            ids.append(candidate.candidate_id)
    return sorted(dict.fromkeys(ids))


def transcript_limit() -> int:
    """The most a transcript being moved may hold: the collector's ``MAX_TRANSCRIPT_BYTES``.

    Discovery adopts only a transcript it read to its end within that bound, so a transcript past
    it by the time it is moved has changed since and is not the file the workspace history
    verified. The collector's constant is the rule when it is installed, so the two cannot drift,
    as :func:`session_id_usable` keeps the session id rule; :data:`TRANSCRIPT_LIMIT` is the same
    number spelled here for a checkout without the collector, which never has a workspace history
    and so never has a transcript to move.
    """
    try:
        limit = getattr(import_module(COLLECTOR_MODULE), "MAX_TRANSCRIPT_BYTES", None)
    except ImportError:
        limit = None
    return limit if isinstance(limit, int) and limit > 0 else TRANSCRIPT_LIMIT


def move_transcript(source: Path, target: Path, enclosure: Enclosure) -> str | None:
    """Move one verified transcript to *target*; return why it was not moved, never raise.

    Both ends are paths something other than this run can change. *target* is in this run's raw
    output, which DeepSec and every agent session it opened could write to while they ran, and
    *source* is in the operator's projects directory, which every Claude Code session on the
    machine writes to. The move used to check the enclosure on the destination's directory and
    then call :func:`shutil.copyfile` and unlink the original, which left open the two holes
    :func:`~scaneval.adapters.llm_harness.stage_record` had already closed for harness records.

    A link already planted at the destination was written through, because :func:`shutil.copyfile`
    follows a symbolic link and truncates whatever file a hard link names: the transcript
    overwrote a host file of the planter's choosing, the original was deleted, and the note said
    the transcript had been moved and registered. A check on the directory is a check on the
    wrong path. Now the enclosure is checked on the destination itself, resolved whole so a link
    anywhere along it is caught, and before ``mkdir``, which would otherwise descend a directory
    link planted on the way and create the session's directory behind it. The destination is then
    created with ``O_CREAT|O_EXCL|O_NOFOLLOW``, so whatever is already at that name (a symbolic
    link, a named pipe, a second name for a host file, a regular file) is refused rather than
    opened.

    A transcript replaced by a link after discovery and the import had read it was followed as
    well, so a host file's bytes were registered and hashed as that session's transcript, and
    nothing said so. And the move read the transcript whole, so a regular file swapped in after
    the import was held in memory at whatever size it had: one large enough raised
    :class:`MemoryError` out of the move and the scan, and a run that had finished with its claims
    was recorded as an adapter failure with none. Now the source is opened with
    ``O_NOFOLLOW|O_NONBLOCK``, which refuses a symbolic link and returns at once from a named pipe,
    and its descriptor is proved with :func:`os.fstat`, before a byte is read, to be a regular file
    no larger than :func:`transcript_limit`, the collector's bound. A larger one is refused:
    discovery adopts only a transcript it read to its end within that bound, so the file there now
    is not the one it verified. The copy then streams from one descriptor to the other in chunks of
    :data:`TRANSCRIPT_CHUNK`, so a move never holds more than one chunk in memory. The bytes the
    import read are not reused instead: the collector hands back a summary rather than the file,
    and the lines it decodes are bounded and repaired, so they are not the file either.

    The original is removed only after a verified write: the copy received exactly as many bytes
    as the source held when it was opened, the source had nothing past them, and :func:`os.fstat`
    on the copy's descriptor shows a regular file with one name and that size. A copy that fails
    or does not verify is removed again and the original is left as it was, and so is a copy whose
    original then cannot be removed, so a transcript is either moved or left where it was, and no
    copy of it stays in ``raw/claude-sessions``. An original already gone by the time it is
    removed costs nothing: the verified copy holds it.

    What is not verified, named so it is not mistaken for an oversight: the copy's content. Nothing
    holds a digest of the file to check it against, because the collector hashes the spans it
    delivers and never the file. A hash here could only compare the copy with the bytes this move
    had just written to it, which proves nothing a process able to rewrite the copy could not undo
    a moment later, before the run hashes the copy it registers.

    That narrows the class ``docs/THREAT_MODEL.md`` names; it does not close it. The enclosure
    check, the ``mkdir`` and the open are separate operations, and so are the read and the
    unlink, so a process still running can plant a link or swap a directory in between. The
    projects directory is inside neither enclosure root, so what vouches for the directory the
    source is read from is the workspace history that listed it.
    """
    reader = writer = None
    created = False
    try:
        try:
            reader = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            found = os.fstat(reader)
        except OSError as exc:
            reason = ("it is a symbolic link, not a regular file" if exc.errno == errno.ELOOP
                      else exc.strerror or str(exc))
            return f"the transcript could not be read as a regular file ({reason})"
        if not stat.S_ISREG(found.st_mode):
            return "the transcript could not be read as a regular file (not a regular file)"
        limit = transcript_limit()
        if found.st_size > limit:
            return (f"the transcript holds {found.st_size} byte(s), past the collector's bound of {limit}, "
                    "so it is not the file discovery read to its end")
        if enclosure.write(target) is None:
            return "the destination does not resolve inside this run's raw output"
        try:
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            return f"the destination's directory could not be created ({exc.strerror or exc})"
        try:
            # The umask decides the mode, as it did for the copy this replaces; the directory is private.
            writer = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
        except FileExistsError:
            return "something was already at the destination, and it was not written through"
        except OSError as exc:
            return f"the destination could not be created ({exc.strerror or exc})"
        created = True
        copied = 0
        try:
            # Cleared now that the descriptor is proved a regular file, as the collector clears it:
            # on a regular file it could only turn a slow read into a spurious EAGAIN.
            os.set_blocking(reader, True)
            with os.fdopen(writer, "wb") as stream:
                writer = None
                while copied < found.st_size:
                    chunk = os.read(reader, min(TRANSCRIPT_CHUNK, found.st_size - copied))
                    if not chunk:
                        break
                    stream.write(chunk)
                    copied += len(chunk)
                # One byte past the size it was opened at says whether it grew while it was copied.
                grew = copied == found.st_size and bool(os.read(reader, 1))
                stream.flush()
                written = os.fstat(stream.fileno())
        except OSError as exc:
            return f"the transcript could not be copied ({exc.strerror or exc})"
        if copied != found.st_size or grew:
            return (f"the transcript changed size while it was copied, from the {found.st_size} byte(s) it "
                    "held when it was opened")
        if not (stat.S_ISREG(written.st_mode) and written.st_nlink == 1 and written.st_size == copied):
            return f"the copy did not verify as a regular file with one name holding all {copied} byte(s)"
        try:
            source.unlink(missing_ok=True)
        except OSError as exc:
            return f"the original could not be removed ({exc.strerror or exc}), so the copy was discarded"
        created = False
        return None
    finally:
        for descriptor in (reader, writer):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if created:
            # Created by this call alone (``O_EXCL``), so removing it removes nothing anyone else wrote.
            try:
                target.unlink()
            except OSError:
                pass


def preserve_transcripts(sessions: tuple[Session, ...], transcripts: dict[str, tuple[Path, ...]],
                         projects_dir: Path, raw_dir: Path, enclosure: Enclosure) -> tuple[list[dict], list[str]]:
    """Move each session's Claude Code transcripts into ``raw/claude-sessions`` and register them.

    Run after :func:`write_trace` has imported them in place. The agent sessions leave their
    transcripts under the operator's projects directory, where they outlive the run and share a
    directory with every other session on the machine; moved here they become hashed artifacts of
    the run that wrote them. Only the files the workspace history verified are moved, the same
    paths the import read, and a subagent transcript keeps its ``subagents/`` level. That includes
    the sessions no analysis entry names, which are the evidence of a failed batch.

    Each move is :func:`move_transcript`. A transcript it refuses stays where it was, is not
    registered, and is named in the note with the reason, so a link planted at either end reads
    as a transcript this run did not keep rather than as one it moved. Neither the status nor any
    claim depends on this: a transcript is evidence about how the run went, and a refused one
    costs that evidence and nothing else.
    """
    root = raw_dir / "claude-sessions"
    artifacts: list[dict] = []
    moved = 0
    refused: list[str] = []
    seen: set[str] = set()
    for session in sessions:
        if not session.discoverable or session.session_id in seen:
            continue
        seen.add(session.session_id)
        for source in transcripts.get(session.session_id, ()):
            relative = (Path("subagents", source.name) if source.parent.name == "subagents"
                        else Path(source.name))
            target = root / session.session_id / relative
            failure = move_transcript(source, target, enclosure)
            if failure is not None:
                refused.append(f"{session.session_id}/{relative.as_posix()} ({failure})")
                continue
            artifacts.append({"id": f"claude-session/{session.session_id}/{relative.as_posix()}", "path": target})
            moved += 1
    notes = [f"{moved} Claude Code transcript(s) were moved from {projects_dir} into raw/claude-sessions and "
             "registered as artifacts of this run."
             + (f" {len(refused)} transcript(s) could not be moved and were left in place: "
                + "; ".join(refused[:5]) + ("; ..." if len(refused) > 5 else "") + "."
                if refused else "")]
    return artifacts, notes


def write_trace(*, trace_dir: Path, trace_mode: str, run_id: str, source_dir: Path,
                projects_dir: Path, records: Records, sessions: tuple[Session, ...],
                candidates: tuple[Candidate, ...], imported: DeepsecImport,
                agent: str, model_requested: str, thinking: str | None,
                unreferenced: tuple[Session, ...] = (), failed_batches: int = 0,
                transcripts: dict[str, tuple[Path, ...]] | None = None,
                frozen_source=None) -> TraceResult:
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

    **A failed batch is a session too.** ``unreferenced`` holds the sessions found only in the
    workspace history (:func:`workspace_history`); each is imported exactly like a named one,
    and none gets a reconstructed pair, because DeepSec wrote no record to reconstruct one from.
    ``failed_batches`` is how many batches this run's records show failed. Each one beyond the
    unreferenced sessions found is a session this run opened and could not find, and is recorded
    as an ``observer.error`` of its own, so the denominator of every session count is what ran and
    not what succeeded.

    A failure inside the collector is contained here, because a collector that cannot read one
    transcript must cost that import rather than the scan. Anything else that raises leaves
    through :meth:`DeepsecAdapter.scan`, which contains it in one place with a note.
    """
    events_path = trace_dir / "events.jsonl"
    notes: list[str] = []
    transcripts_found = 0
    imports_clean = True
    # How each session's main transcript ended when its last response was a refusal, by session
    # id, and every refusal the transcripts recorded on the way, which is a different count.
    ended_on: dict[str, str] = {}
    refusals_recorded: dict[str, int] = {}
    refused_sessions: set[str] = set()
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
        for session in sessions + unreferenced:
            call_id = session.call_id
            located = False
            main_turns = 0
            captured_anything = False
            # ``correlated`` is the gate, not the bare presence of an id: an id discovery may
            # not be handed is treated exactly like a missing one.
            if collectors is not None and session.discoverable:
                _find, load = collectors
                # Only the files the workspace history verified as this session's, never a
                # lookup of the ID across other project directories.
                paths = list((transcripts or {}).get(session.session_id, ()))
                located = bool(paths)
                for path in paths:
                    sidechain = Path(path).parent.name == "subagents"
                    try:
                        summary = load(observer, Path(path), workspace_root=roots,
                                       call_id=call_id, sidechain=sidechain,
                                       frozen_source=frozen_source,
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
                        for cause in getattr(summary, "api_errors", ()) or ():
                            if isinstance(cause, str) and cause:
                                refusals_recorded[cause] = refusals_recorded.get(cause, 0) + 1
                                refused_sessions.add(session.session_id)
                        final = getattr(summary, "final_api_error", None)
                        if isinstance(final, str) and final:
                            ended_on[session.session_id] = final
                    if health.loss:
                        imports_clean = False
                        notes.append(f"transcript {Path(path).name} was imported short of the "
                                     f"file: {'; '.join(health.loss)}")
            if session.correlation == "workspace_history":
                # Found by its transcript, so the transcript is the only description there is.
                if captured_anything:
                    transcripts_found += 1
                if main_turns <= 0:
                    imports_clean = False
                    notes.append(f"the main transcript of session {session.session_id}, which no "
                                 "analysis entry names, produced no model turn")
                continue
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
                metadata={**shared, "route": "claude_agent_sdk" if agent == "claude" else agent,
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
        ended_by: dict[str, int] = {}
        for cause in ended_on.values():
            ended_by[cause] = ended_by.get(cause, 0) + 1
        for index, name in enumerate(records.debug, start=1):
            observer.emit(
                type="observer.error", category="observer", capture_status="unavailable",
                metadata={"source": "harness_record",
                          "error_code": "agent_output_parse_failure",
                          "stage": "process", "debug_dump": name, "sequence_in_run": index,
                          # A dump names no session, so it is tied to no call. What the run's own
                          # transcripts recorded is counted beside it instead: how many sessions
                          # ended on a refusal, and every refusal, recovered from or not.
                          "correlation": "uncorrelated",
                          "sessions_ended_on_refusal_in_run": dict(sorted(ended_by.items())),
                          "refusals_recorded_in_run": dict(sorted(refusals_recorded.items())),
                          "detail": "DeepSec could not parse one batch's agent output and wrote "
                                    "a debug dump; the findings of that batch, if any, were not "
                                    "recorded and nothing here says what the model produced. "
                                    "When the run's transcripts recorded a provider refusing a "
                                    "request, this is the downstream symptom of one: DeepSec "
                                    "read the CLI's error text as the agent's answer"})
        missing = max(0, failed_batches - len(unreferenced))
        for index in range(1, missing + 1):
            observer.emit(
                type="observer.error", category="observer", capture_status="unavailable",
                metadata={"source": "harness_record",
                          "error_code": "failed_batch_session_not_found",
                          "stage": "process", "sequence_in_run": index,
                          "detail": "DeepSec's records show a batch that failed, and no session "
                                    "in this invocation's workspace history could be matched "
                                    "to it; whatever that session did is not in this trace"})
        for finding in imported.findings:
            observer.emit(
                type="finding.submitted", category="finding", capture_status="complete",
                candidate_id=finding["claim_id"], claim_id=finding["claim_id"],
                metadata={"source": "harness_record", "stage": "process",
                          "file_path": finding["path"],
                          "candidate_ids": _overlapping(candidates, finding["path"], finding["slug"],
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
    expected = len(sessions) + len(unreferenced) + missing
    if expected:
        notes.append(f"{transcripts_found} of {expected} agent session(s) had a Claude Code "
                     "transcript this run could import. A session with a transcript is described "
                     "by that transcript's own per-turn model events; a session without one is "
                     "described by a single reconstructed request/response pair carrying "
                     "DeepSec's summed usage. No call is described both ways.")
    if unreferenced or missing:
        listed = ", ".join(session.session_id for session in unreferenced[:5])
        notes.append(
            f"The {expected} session(s) are the {len(sessions)} DeepSec's analysis entries name, "
            f"{len(unreferenced)} found only in this invocation's workspace history"
            + (f" ({listed}{', ...' if len(unreferenced) > 5 else ''})" if unreferenced else "")
            + f", and {missing} failed batch(es) whose session that history did not hold. DeepSec "
            "names a session only on the analysis entries of a batch that finished, so a failed "
            "batch is found by its transcript or not at all.")
    if expected:
        notes.append(
            "Transcript paths were matched against "
            + ("both spellings of the scanned workspace" if len(roots) > 1
               else "the one spelling of the scanned workspace")
            + f" ({', '.join(portable(root) for root in roots)}): the Claude Agent SDK records "
            "its working directory and every file it read under the platform's real path, and "
            "the collectors compare textually without resolving a link, so a path matched "
            "against one spelling alone reads as external to the workspace.")
    if ended_by:
        notes.append(
            f"{len(ended_on)} session(s) ended on a request the provider refused, as the Claude Code "
            "CLI recorded it in the transcript: "
            + ", ".join(f"{cause} ({count})" for cause, count in sorted(ended_by.items()))
            + ". Each is on that session's own model.response as failure_kind api_error. The reset "
            "the CLI named, if any, is kept there as it wrote it.")
    recovered = len(refused_sessions - set(ended_on))
    if recovered:
        notes.append(
            f"{recovered} session(s) recorded a refused request and went on to a real response "
            "after it, so the refusal is an error the session encountered and not how it ended. "
            "Refused requests recorded in all: "
            + ", ".join(f"{cause} ({count})" for cause, count in sorted(refusals_recorded.items())) + ".")
    return TraceResult({"capture_gap": state.capture_gap, "dropped_events": state.dropped_events},
                       transcripts_found, imports_clean, tuple(notes), expected,
                       dict(sorted(ended_by.items())), dict(sorted(refusals_recorded.items())))


def failed_batch_count(agent: str, records: Records, statuses: RecordStatuses, output: "ProcessOutput") -> int:
    """How many batches this run's evidence shows failed, as a lower bound, for the claude agent.

    Each parse-failure dump is one failed batch, and a file left in ``error`` is at least one. The
    count DeepSec printed is advisory and is used only here, where it can raise the number of
    sessions the run must account for and so lower what the capture may claim, never raise it.
    Other agents leave no Claude Code transcript, so no session of theirs is expected to be found.
    """
    if agent != "claude":
        return 0
    return max(len(records.debug), output.errored_batches or 0, 1 if statuses.errored else 0)


class ProcessOutput(NamedTuple):
    """What DeepSec printed at the end of one ``process`` run, in either mode, and nothing more.

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
    """The summary of one ``process`` run, read from the end of its stdout.

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
    at the end of a directory in it (``src /a.js``), is not at an end of the line and is not touched.

    Checked by running the 2.3.10 bundle's own ``resolveFiles`` (its ignore filter stubbed out, no agent) over a git
    range: a name with a leading or a trailing space is dropped, or resolved to another file that exists (``src/a.js ``
    to the untouched ``src/a.js``), and a name with a space inside it or at the end of a directory resolves. The
    characters are the ones Node's own ``trim`` removes. The CLI was not run over such a name, since after the
    listing it starts a model.
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
        refusal to call the run a ``success`` are all made from it, so they cannot disagree. The error
        that names them is made from it too, but a run carries that error only when no earlier failure
        ends the run first (see the module docstring).

        It is deliberately not narrowed by the ignore filter, which this adapter cannot see: a name
        the filter would have dropped anyway is counted too. The cost is credit withheld from a run
        that was complete after all; the alternative is quiet credit for a file nobody opened.

        Checked against the bundle's own ``resolveFiles`` (see :func:`listing_trims`) over a git range
        that adds one regular file for each of 1112 names: every printable ASCII character, and several
        control and non-ASCII ones, at the start, in the middle and at the end of a file name and of a
        directory name. With git's default configuration it resolved a name to itself exactly when
        neither :func:`git_prints_quoted` nor :func:`listing_trims` held, so no other spelling is lost;
        with ``core.quotePath=false`` it dropped no name they did not flag. What it drops for a reason
        other than the spelling of the name (its ignore filter, an entry that is not a file) is not
        counted here.
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


def unexamined_paths(changes: tuple[Change, ...], dropped: DroppedPaths) -> list[str]:
    """Every path the change touches that DeepSec created no file record for, sorted: the result's ``omitted_paths``.

    That is each path present at head with no record, for whatever reason (:attr:`DroppedPaths.dropped`: its ignore
    filter, or a name its listing cannot resolve), and each path the change removed, which DeepSec never reads
    (:func:`~scaneval.adapters.pr.removed_paths`). A path that has a record is not here, however far its file got:
    which files reached no verdict is the status's to say, and the status logic reads the records, not this list.

    The note, the status and this list are made from the same comparison, so they cannot disagree about a path. It is
    deliberately not narrowed by the ignore filter, which this adapter cannot see, nor by the reason a path has no
    record: a path DeepSec's own selection dropped is a choice of DeepSec's and not one declared before the run, so a
    control planned on it earns no quiet credit however legitimate the drop was. A scope exclusion is declared by
    leaving the item out of the plan, before the run.
    """
    return sorted(set(dropped.dropped) | set(removed_paths(changes)))


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
    """The ``scope_incomplete`` error of a run that ends on a path DeepSec's listing cannot resolve.

    The status logic gives a run this error only when no failure it tests earlier ends the run first; a
    run one of them ends keeps that failure's own code and error, and only the note names the paths (see
    the module docstring).
    """
    return ("; ".join(listing_limits(paths, "changed path(s)"))
            + ", so it never investigated them, whatever its ignore filter says. This run therefore observed only "
              "part of the change (or none of it) and says nothing about them")


def unreviewed_note(changes: tuple[Change, ...], files: tuple[tuple[str, dict], ...],
                    source: str = "--diff") -> str | None:
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
    stand as a complete or quiet observation of the change. The status logic reads the same list, so
    the note and the status cannot disagree: a run whose note names such a path is never a ``success``
    and its bundles are unresolved. The note is written whatever ends the run. The error names these
    paths, in the same words, only when none of the failures the status logic tests before the omission
    ends the run first (a timeout, a step that failed, an export that could not be read, a record or a
    finding that could not be imported, an exhausted quota, an errored batch, a record status DeepSec
    does not declare, a file left unfinished), and the run then ends ``scope_incomplete``. A run one of
    those ends keeps that failure's own code and error, and only this note names the paths. This adapter
    cannot tell the other paths apart by reason and does not try to.
    """
    paths = dropped_paths(changes, files)
    omitted = paths.unlistable
    removed = removed_paths(changes)
    sentences = []
    if paths.dropped:
        apart = f", except for the {len(omitted)} named next" if omitted else ""
        sentences.append(
            f"DeepSec did not investigate {len(paths.dropped)} of the {len(paths.present)} path(s) this change "
            f"leaves at head, because it created no file record for them ({_listed(paths.dropped)}). "
            + ("Its --diff selection keeps only added, modified, renamed and copied paths"
               if source == "--diff" else "Its --files-from selection keeps only listed paths that exist as files")
            + " and drops those matching its default ignore filter (tests, docs, build output and similar), so this "
            f"is DeepSec's own scope and not a failure of the run{apart}; silence about these paths is not a "
            "negative result.")
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


def process_manifest_tree_issue(source_dir: Path, path: str,
                                listings: dict[Path, dict[str, os.DirEntry]]) -> str | None:
    """Why *path* names no regular file of the input tree exactly as spelled, or ``None``.

    Read before DeepSec starts. Each component is looked up by its exact name in its parent's
    listing rather than opened, so a case or Unicode-form alias that a case- or
    normalization-insensitive filesystem would resolve is refused: DeepSec selects by exact string,
    and such an alias would select nothing while appearing to name a file. A symbolic link in any
    component is refused too, because the scan's record would sit at another spelling. *listings*
    caches each directory's listing across the paths of one manifest.
    """
    current = source_dir
    parts = path.split("/")
    for index, part in enumerate(parts):
        if current not in listings:
            try:
                listings[current] = {entry.name: entry for entry in list_directory(current)}
            except OSError as exc:
                return f"its directory could not be listed ({exc.strerror or exc})"
        entry = listings[current].get(part)
        if entry is None:
            return "the input tree holds no entry spelled exactly so"
        if entry.is_symlink():
            return "a component of it is a symbolic link"
        if index == len(parts) - 1:
            return None if entry.is_file(follow_symlinks=False) else "it is not a regular file"
        if not entry.is_dir(follow_symlinks=False):
            return "a component of it is not a directory"
        current = Path(entry.path)
    return None


class CuratedScope(NamedTuple):
    """What one curated run's manifest selected, out of every FileRecord DeepSec left.

    Read off all of ``records.files``, never a filtered copy: the status, export and identity
    reconciliation of the run stay global, and this only names populations inside it. A record is
    ``selected``, so eligible for an AI batch, exactly when DeepSec's own
    ``Set.has(record.filePath)`` would hold. ``unselected`` are the regex candidates assigned no AI
    batch, still as the scan left them, by record path; ``external`` counts those whose record name
    is not a path inside the tree. Every unlisted record is in exactly one of those and
    ``unexpected``. ``listed_without_record`` are listed paths DeepSec's scan made no record for (no
    matcher hit, its ignore filter, an empty file): no AI batch could run on them, which is native
    triage, not a model's miss. ``unexpected`` are unselected records that are not in the state a
    fresh scan leaves (``pending``, no analysis, no finding), and ``out_of_scope_claims`` imported
    claims on a path the manifest does not list; either says verdicts were written outside the
    declared batch assignment. None of this says which files the agent read: selection assigns
    batches and does not restrict repository access, so an unselected file may still have been read.
    """

    manifest: tuple[str, ...]
    selected: tuple[str, ...]
    unselected: tuple[str, ...]
    external: int
    listed_without_record: tuple[str, ...]
    unexpected: tuple[str, ...]
    out_of_scope_claims: int


def curated_scope(manifest: tuple[str, ...], files: tuple[tuple[str, dict], ...], claims: list[dict],
                  roots: tuple[Path, ...]) -> CuratedScope:
    """Partition *files* by *manifest* the way DeepSec's standard-mode ``process`` does."""
    listed = set(manifest)
    selected: list[str] = []
    unselected: list[str] = []
    external = 0
    unexpected: list[str] = []
    recorded: set[str] = set()
    for name, record in files:
        file_path = record.get("filePath")
        if isinstance(file_path, str):
            recorded.add(file_path)
        if isinstance(file_path, str) and file_path in listed:
            selected.append(name)
            continue
        if not (record.get("status") == "pending" and record.get("analysisHistory") == []
                and record.get("findings") == []):
            # Not left as the scan wrote it, so not a candidate that simply went without an AI batch.
            unexpected.append(name)
            continue
        path, outside = record_path(name, record, roots)
        if outside:
            external += 1
        else:
            unselected.append(path)
    out_of_scope = sum(1 for claim in claims
                       if (claim.get("primary_location") or {}).get("path") not in listed)
    return CuratedScope(manifest, tuple(selected), tuple(sorted(set(unselected))), external,
                        tuple(path for path in manifest if path not in recorded), tuple(unexpected),
                        out_of_scope)


class DeepsecAdapter(Adapter):
    name = "deepsec"
    # 1.2.0 honors config.process_manifest_by_tree; an earlier adapter ignores the key and runs unscoped.
    # An experiment frozen against 1.1.0 is refused as adapter version drift until it is frozen again.
    # 1.2.1 reads a full run's standard-mode process exit 1 from the records instead of ending the run
    # with no claims, so the records of a failed batch written before and after can be told apart.
    adapter_version = "1.2.1"
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
        The exception is ``process``'s exit 1, DeepSec's own signal that a run ended short: the run
        goes on to export and is classified from the records, in a full run as in a PR review.

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
        if config.files_from is not None and pr is None:
            raise AdapterError("deepsec config.files_from scopes a PR review and is refused for a full run")
        if config.process_manifest_by_tree is not None and pr is not None:
            raise AdapterError("deepsec config.process_manifest_by_tree assigns a full run's AI batches and is refused "
                               "for a PR review: DeepSec's direct mode ignores --manifest, so the review would run "
                               "unscoped")
        if config.capture_claude_sessions and trace_mode != "content":
            raise AdapterError("deepsec config.capture_claude_sessions keeps transcripts that hold prompts and "
                               "source, and requires content tracing")
        if not config.binary.exists():
            raise AdapterError(f"deepsec executable not found at {config.binary}")
        # The curated scope of this input, resolved and checked against the tree before anything runs.
        process_manifest: tuple[str, ...] | None = None
        input_record = request.get("input") if isinstance(request, dict) else None
        tree_hash = input_record.get("tree_hash") if isinstance(input_record, dict) else None
        if config.process_manifest_by_tree is not None:
            process_manifest = (config.process_manifest_by_tree.get(tree_hash)
                                if isinstance(tree_hash, str) else None)
            if process_manifest is None:
                raise AdapterError(f"deepsec config.process_manifest_by_tree has no entry for input tree {tree_hash!r}; "
                                   "refusing to fall back to an unscoped AI-batch assignment"[:500])
            listings: dict[Path, dict[str, os.DirEntry]] = {}
            for listed_path in process_manifest:
                issue = process_manifest_tree_issue(Path(source_dir), listed_path, listings)
                if issue is not None:
                    raise AdapterError(f"deepsec config.process_manifest_by_tree lists {listed_path!r} for input tree "
                                       f"{tree_hash}, but {issue}; the map does not describe this tree"[:500])
        # Read before DeepSec starts: its agent can run a shell in this workspace, ``.git`` included.
        changes = workspace_changes(Path(source_dir), pr) if pr is not None else ()
        project = project_id_for(request, config.project_id)
        # Captured before the first process starts: DeepSec writes into the raw directory while
        # it runs, so every read below is checked against a boundary it cannot move.
        from ..collectors.source import FrozenSource
        frozen_source = (FrozenSource.capture(Path(source_dir))
                         if trace_mode != "off" and trace_dir is not None else None)
        enclosure = Enclosure.capture(Path(source_dir), Path(raw_dir))
        workspace = build_workspace(Path(raw_dir), Path(source_dir), project, config)
        data_dir = workspace / "data" / project
        export_path = Path(raw_dir) / "deepsec-export.json"
        overrides = {"DEEPSEC_DATA_ROOT": "data"}
        if config.claude_code_executable:
            overrides["CLAUDE_CODE_EXECUTABLE"] = config.claude_code_executable
        env = build_env(self.env_passthrough, overrides)

        scan_argv = [str(config.binary), "scan", "--project-id", project, "--root", str(source_dir)]
        # A PR review normally lets DeepSec list the change itself. An operator's file list
        # replaces that listing with --files-from, the other source its direct mode accepts.
        files_from_path = Path(raw_dir) / "deepsec-files-from.txt"
        if pr is not None and config.files_from is not None:
            files_from_path.write_text("\n".join(config.files_from) + "\n", encoding="utf-8")
            source_argv = ["--files-from", str(files_from_path)]
        else:
            source_argv = ["--diff", pr.revision_range] if pr is not None else []
        # The curated scope goes to standard-mode process as the JSON array its --manifest reads,
        # written once before DeepSec starts; these exact bytes are the artifact and are checked
        # again after the run, because DeepSec's agent can run a shell in this directory.
        manifest_path = Path(raw_dir) / "deepsec-process-manifest.json"
        manifest_bytes = b""
        if process_manifest is not None:
            manifest_bytes = (json.dumps(list(process_manifest), indent=2) + "\n").encode("utf-8")
            try:
                with manifest_path.open("xb") as stream:
                    stream.write(manifest_bytes)
            except OSError as exc:
                raise AdapterError(f"the deepsec process manifest could not be written: {exc}") from exc
            source_argv = ["--manifest", str(manifest_path)]
        process_argv = [str(config.binary), "process", "--project-id", project,
                        "--root", str(source_dir),
                        *source_argv,
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
            *([{"id": "deepsec-files-from", "path": files_from_path}] if "--files-from" in source_argv else []),
            *([{"id": ARTIFACT_PROCESS_MANIFEST, "path": manifest_path}] if process_manifest is not None else []),
        ]
        notes: list[str] = []
        remaining = float(timeout_seconds)
        results: dict[str, Any] = {}
        timed_out_step = None
        # The exit ``process`` uses for a run that ended short, which is classified from the records.
        process_exit = DIRECT_MODE_EXIT if pr is not None else STANDARD_MODE_EXIT
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
                if step == "process" and result.exit_code == process_exit:
                    # DeepSec's own exit for a run that ended short: an errored batch or an exhausted
                    # quota in either mode, and findings too in direct mode. It also exits 1 for a
                    # runtime failure, so what it means is decided below, from the records; the run
                    # goes on to export either way, since every verdict is on disk before it exits.
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
        # The sessions of failed batches, which DeepSec names nowhere. Only the claude agent leaves
        # a Claude Code transcript, and only a traced run reads any.
        history = (workspace_history(sessions, roots, config.projects_dir)
                   if config.agent == "claude" and trace_dir is not None and trace_mode != "off"
                   else NO_HISTORY)
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
        # With an operator's file list, what DeepSec's own listing could or could not resolve is judged over that list,
        # and every other changed path is an omission the operator declared before the run.
        selected = set(config.files_from) if pr is not None and config.files_from is not None else None
        scoped = tuple(change for change in changes if change.path in selected) if selected is not None else changes
        dropped = dropped_paths(scoped, records.files) if pr is not None else DroppedPaths((), ())
        omitted = dropped.unlistable
        # What the result lists as omitted_paths, for the outcomes that carry claims DeepSec produced, and whether that
        # is every path the change touches, so that DeepSec examined none of it: both ``None`` in a full run, which
        # reports no omission.
        unexamined = unexamined_paths(changes, dropped_paths(changes, records.files)) if pr is not None else None
        nothing_examined = examined_nothing(changes, unexamined) if pr is not None else None

        exported: Any = None
        export_failure = None
        data, failure = read_record(export_path, enclosure.write(export_path))
        if data is None:
            export_failure = f"the export was not read ({failure})"
        else:
            try:
                exported = json.loads(
                    data.decode("utf-8"), parse_constant=_reject_nonstandard_json_constant)
            except (UnicodeDecodeError, ValueError) as exc:
                export_failure = f"the export is not readable JSON ({exc})"
        imported = DeepsecImport([], [], 0, 0, [])
        missing_export_lower = 0
        missing_export_upper = 0
        identity_gaps = 0
        findings_lost = 0
        native_validation_failures = 0
        native_status_validation_failures = 0
        finding_import_notes: list[str] = []
        if export_failure is None:
            native_population = native_export_population(records.files)
            native_validation_failures = len(native_population.validation_issues)
            native_status_validation_failures = len(native_population.status_validation_issues)
            finding_import_notes.extend(
                "Native load reconciliation failed closed: " + issue
                for issue in (*native_population.validation_issues,
                              *native_population.status_validation_issues))
            join_identities = {
                identity: Counter(identifiers)
                for identity, identifiers in native_population.identities.items()
            }
            for identity, identifiers in native_population.status_identities.items():
                join_identities.setdefault(identity, Counter()).update(identifiers)
            join_derived_identities = {
                identity: Counter(identifiers)
                for identity, identifiers in native_population.derived_identities.items()
            }
            for identity, identifiers in native_population.status_derived_identities.items():
                join_derived_identities.setdefault(identity, Counter()).update(identifiers)
            try:
                imported = import_export(
                    exported, ids=join_identities, derived_ids=join_derived_identities)
            except AdapterError as exc:
                export_failure = str(exc)
            else:
                imported_finding_ids = Counter(
                    claim["native_id"] for claim in imported.claims
                    if isinstance(claim.get("native_id"), str) and claim["native_id"])
                unmatched_records = native_population.ids - imported_finding_ids
                unmatched_count = unmatched_records.total()
                unidentified_exports = imported.lost + imported.unjoined
                # Each unidentified export entry may correspond to at most one unmatched record
                # occurrence, but it may instead be unrelated. Without correlation that yields a
                # bound, not an exact subtraction: saying zero here hid a real dropped finding
                # whenever an unrelated unjoinable entry happened to offset it.
                missing_export_lower = max(unmatched_count - unidentified_exports, 0)
                missing_export_upper = unmatched_count
                identity_gaps = imported.unjoined
                findings_lost = imported.lost + missing_export_lower
                if unmatched_count:
                    if missing_export_lower == missing_export_upper:
                        finding_import_notes.append(
                            f"Exact native identity reconciliation establishes that "
                            f"{missing_export_lower} eligible record finding occurrence(s) had no JSON export "
                            "entry; those findings could not be imported, so the run is incomplete.")
                    else:
                        finding_import_notes.append(
                            f"{unmatched_count} eligible record finding occurrence(s) remain unmatched, and "
                            f"{unidentified_exports} export entry or imported claim(s) have no established "
                            "native identity. The unidentified entries may account for some or all of those "
                            f"records, so the number with no JSON export entry is bounded between "
                            f"{missing_export_lower} and {missing_export_upper}; no exact omission count is "
                            "claimed without correlation.")
                if identity_gaps:
                    finding_import_notes.append(
                        f"{identity_gaps} JSON export claim(s) were imported but could not be joined to native "
                        "finding identity; the usable claims were preserved, but record/export conservation "
                        "could not be fully resolved.")
                if native_population.excluded:
                    excluded_reasons = []
                    if native_population.no_latest_analysis:
                        excluded_reasons.append(
                            f"{native_population.no_latest_analysis} because the schema-valid file record had "
                            "an actual empty analysisHistory list")
                    excluded_reasons.extend(
                        f"{native_population.resolved[verdict]} with revalidation verdict {verdict!r}"
                        for verdict in DEFAULT_EXPORT_RESOLVED_VERDICTS
                        if native_population.resolved[verdict])
                    finding_import_notes.append(
                        f"DeepSec's unchanged default export intentionally excluded "
                        f"{native_population.excluded} record finding occurrence(s): "
                        f"{'; '.join(excluded_reasons)}. These producer exclusions are expected and are not "
                        "counted as import loss.")

        # A curated run's populations, named inside the global reconciliation above and never in place
        # of it: every record, status and exported claim still counts exactly as in an ordinary run.
        scope: CuratedScope | None = None
        manifest_changed: str | None = None
        if process_manifest is not None:
            scope = curated_scope(process_manifest, records.files, imported.claims, roots)
            # The regex candidates assigned no AI batch are this run's known omission: no verdict was
            # assigned to them, which does not say the agent never read them.
            unexamined = list(scope.unselected)
            written, failure = read_record(manifest_path, enclosure.write(manifest_path))
            if written is None:
                manifest_changed = f"the process manifest could not be read back after the run ({failure})"
            elif written != manifest_bytes:
                manifest_changed = ("the process manifest's bytes after the run differ from the bytes written "
                                    "before DeepSec started")

        # ``output`` is what DeepSec printed and is advisory only: what an exit 1 means is read from
        # the records it left, which is where each of its causes (an errored batch, an exhausted
        # quota, and in direct mode findings) is written down as it happens. A full run reads it
        # only beside the exit 1 it is printed with, so text an agent's output can reach says
        # nothing about a full run that exited 0.
        output = ProcessOutput()
        process_result = results.get("process")
        process_exited_short = (process_result is not None and not process_result.timed_out
                                and process_result.exit_code == process_exit)
        if process_result is not None and (pr is not None or process_exited_short):
            process_stdout = Path(raw_dir) / "deepsec-process.stdout.txt"
            output = read_process_output(bounded_tail(process_stdout, enclosure.write(process_stdout),
                                                      PROCESS_OUTPUT_TAIL))
        finding_records = sum(len(record["findings"]) for _name, record in records.files
                              if isinstance(record.get("findings"), list))
        if pr is not None:
            exit_one_explained = bool(finding_records or imported.claims or statuses.errored or statuses.unfinished
                                      or records.debug)
        else:
            # 2.3.10's standard mode exits 1 for an errored batch or an exhausted quota, and either one
            # leaves every file of the batch that failed in ``error``; it puts back to ``pending`` only
            # what it never started. A ``pending`` record is what the manifest or ``--limit`` left out,
            # so it explains nothing, and neither does a finding or a parse-failure dump on its own (a
            # batch that drops an invalid field writes one and finishes). A record still
            # ``processing`` is one a run that died was holding, which is an incomplete AI stage.
            exit_one_explained = bool(statuses.errored or statuses.held)

        trace_path = (trace_dir / "events.jsonl") if trace_dir is not None else None
        capture_state: dict | None = None
        transcripts_found = 0
        imports_clean = True
        sessions_expected = len(sessions)
        ended_on_refusal: dict[str, int] = {}
        if trace_dir is not None and trace_mode != "off":
            try:
                traced = write_trace(
                    trace_dir=Path(trace_dir), trace_mode=trace_mode, run_id=request["run_id"],
                    source_dir=Path(source_dir), projects_dir=config.projects_dir, records=records,
                    sessions=sessions, candidates=candidates, imported=imported,
                    agent=config.agent, model_requested=config.model, thinking=config.thinking_level,
                    unreferenced=history.unreferenced, transcripts=history.transcripts,
                    frozen_source=frozen_source,
                    failed_batches=failed_batch_count(config.agent, records, statuses, output))
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
                sessions_expected = traced.sessions_expected
                ended_on_refusal = dict(traced.sessions_ended_on_refusal)
                notes.extend(traced.notes)
                if history.foreign:
                    notes.append(f"{history.foreign} transcript(s) in this workspace's project directory "
                                 "did not show they ran in it, and were neither imported nor moved.")
                if history.unverified:
                    notes.append(f"{history.unverified} transcript(s) in this workspace's project directory could "
                                 "not be read to their end, so whether they ran in it was never settled; none of "
                                 "them was imported or moved.")
        if config.capture_claude_sessions:
            # After the import, which reads the transcripts where the sessions left them.
            moved, capture_notes = preserve_transcripts(sessions + history.unreferenced, history.transcripts,
                                                        config.projects_dir, Path(raw_dir), enclosure)
            artifacts.extend(moved)
            notes.extend(capture_notes)

        capture = capture_status(
            trace_mode, transcripts_found=transcripts_found, sessions=sessions_expected,
            batches_failed=batches_failed, imports_clean=imports_clean,
            # Everything this run already knows it did not see. A category may not claim
            # completeness over a population this run could not read in full, and none may
            # claim it over an observer that reported a hole in its own record.
            record_failures=(len(records.failures) + native_validation_failures
                             + native_status_validation_failures),
            # An unjoined claim was submitted, but the record/export population cannot be proved
            # complete; this count is used only as the matrix's incomplete-population signal.
            findings_lost=findings_lost + identity_gaps,
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
        if pr is None and process_manifest is not None:
            steps_note = ("DeepSec ran as three CLI steps in one workspace under raw/deepsec-workspace: scan over the "
                          "whole supported repository, process in standard mode with --manifest "
                          f"raw/deepsec-process-manifest.json ({len(process_manifest)} path(s), sha256:"
                          f"{hashlib.sha256(manifest_bytes).hexdigest()}), and export. The recorded command is those "
                          "three argv lists in order, separated by '&&'; each step's stdout and stderr is its own raw "
                          "artifact.")
        elif pr is None:
            steps_note = (f"DeepSec ran as three CLI steps in one workspace under raw/deepsec-workspace: scan, "
                          f"process and export. The recorded command is those three argv lists in order, "
                          f"separated by '&&'; each step's stdout and stderr is its own raw artifact.")
        elif selected is not None:
            steps_note = (f"DeepSec ran as two CLI steps in one workspace under raw/deepsec-workspace: process in its "
                          f"direct mode, given --files-from raw/deepsec-files-from.txt, the operator's list of "
                          f"{len(selected)} path(s) chosen from the change {pr.revision_range}, and export; no separate "
                          "scan step was run. Direct mode ran its own regex scan over just those files and "
                          "investigated each of them. The recorded command is those two argv lists in order, "
                          "separated by '&&'; each step's stdout and stderr is its own raw artifact.")
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
        ] + notes + list(imported.notes) + finding_import_notes
        if scope is not None:
            left_out = len(scope.unselected) + scope.external
            # A listed path's missing record is DeepSec's triage only when its scan ran to the end; a
            # scan that failed or was killed leaves a record list that says nothing about any path.
            scan_result = results.get("scan")
            scan_unfinished = ("never ran" if scan_result is None
                               else "ran out of the shared time budget" if scan_result.timed_out
                               else f"exited {scan_result.exit_code}" if scan_result.exit_code != 0
                               else None)
            if scan_unfinished is None:
                scope_account = (
                    f"Its regex scan left {len(records.files)} file record(s); {len(scope.selected)} are on a listed "
                    "path, which are the only ones standard-mode process could assign to an AI batch, and "
                    f"{left_out} regex candidate file(s) were assigned no AI batch"
                    + (f" ({_listed(scope.unselected)})" if scope.unselected else "")
                    + (f", {scope.external} of them under a record name outside the tree" if scope.external else "")
                    + ". Their records stay as DeepSec wrote them, and a partial run that carries claims lists "
                    "their paths as omitted. Batch assignment does not restrict repository access: the agent still "
                    "sees the whole repository and may have read unlisted files, so an omitted path is a candidate "
                    "with no assigned verdict, not evidence that it was never read. "
                    f"{len(scope.listed_without_record)} listed path(s) got no file record"
                    + (f" ({_listed(scope.listed_without_record)})" if scope.listed_without_record else "")
                    + ": DeepSec's scan found no regex candidate there or its ignore filter skipped them, so no AI "
                    "batch ran on them; that is native triage, not a model's miss"
                    + (f", unless the record is one of the {len(records.failures)} DeepSec record(s) this run could "
                       "not read" if records.failures else "")
                    + ". ")
            else:
                scope_account = (
                    f"Its regex scan {scan_unfinished} before it finished, so no AI batch was assigned and the "
                    f"{len(records.files)} file record(s) it left are not a full list of its candidates. "
                    f"{len(scope.listed_without_record)} listed path(s) have no file record"
                    + (f" ({_listed(scope.listed_without_record)})" if scope.listed_without_record else "")
                    + ", which says nothing about DeepSec's triage of them, since no scan completed. ")
            notes.append(
                f"Curated diagnostic, not a blind full-repository benchmark: config.process_manifest_by_tree chose "
                f"{len(scope.manifest)} repository-relative path(s) for input tree {tree_hash} before the run. The "
                "manifest holds those paths only, with no case identifier, label, weakness class, expected result "
                "or reason for the selection. "
                + scope_account
                + "A curated run is never a success and its bundles are unresolved, so it completes no control "
                "and earns no quiet credit.")
            if scope.unexpected or scope.out_of_scope_claims:
                notes.append(
                    f"{len(scope.unexpected)} file record(s) the manifest does not list are not in the state a "
                    "fresh scan leaves (status 'pending', no analysis, no finding)"
                    + (f" ({_listed(scope.unexpected)})" if scope.unexpected else "")
                    + f", and {scope.out_of_scope_claims} imported claim(s) are on a path the manifest does not "
                    "list. All of them are kept in this run's records and claims, but they say DeepSec wrote "
                    "verdicts outside the declared AI-batch assignment.")
            if manifest_changed:
                notes.append(f"Process manifest integrity: {manifest_changed}.")
        exit_one_note = None
        if process_exited_short and exit_one_explained:
            said = ([f"{output.quota} exhausted"] if output.quota else []) + (
                [f"{output.errored_batches} errored batch(es)"] if output.errored_batches else []) + (
                [f"{output.findings} finding(s)"] if output.findings else [])
            exit_one_note = (
                "deepsec process exited 1 and the run went on to export: "
                + ("in direct mode DeepSec exits 1 for findings, for an errored batch and for an exhausted quota, "
                   f"and its records show {finding_records} finding(s), {len(statuses.errored)} file(s) in status "
                   f"'error' and {unfinished_files} unfinished file(s)"
                   if pr is not None else
                   "in standard mode DeepSec exits 1 for an errored batch and for an exhausted quota, never for "
                   f"findings, and its records show {len(statuses.errored)} file(s) in status 'error' and "
                   f"{len(statuses.held)} still 'processing' when the run ended")
                + ". What the exit meant was read from those records"
                + (f"; DeepSec's own summary said {', '.join(said)}." if said else "."))
        if pr is None and exit_one_note:
            notes.append(exit_one_note)
        if pr is not None:
            if config.limit is not None:
                notes.append(f"config.limit ({config.limit}) was not passed to DeepSec: its direct mode never applies "
                             "--limit, so it would have had no effect on which files were investigated.")
            if exit_one_note:
                notes.append(exit_one_note)
            if selected is not None:
                present = {change.path for change in changes if change.present}
                excluded = sorted(present - selected)
                outside = sorted(selected - present)
                notes.append(
                    f"config.files_from limited the review to {len(selected & present)} of the {len(present)} path(s) "
                    f"this change leaves at head. The other {len(excluded)} were left out by the operator before the "
                    "run and are listed as omitted; silence about them is not a negative result."
                    + (f" {len(outside)} listed path(s) are not changed by this range ({_listed(outside)}) and were "
                       "reviewed at head anyway." if outside else ""))
            unreviewed = unreviewed_note(scoped, records.files,
                                         source="--files-from" if selected is not None else "--diff")
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
                "AI stage either "
                + ("gave them no batch, which is what config.process_manifest_by_tree does to every candidate "
                   "it does not list and "
                   if process_manifest is not None else "never reached them, which is what ")
                + "config.limit"
                + (f" ({config.limit})" if config.limit is not None else "")
                + " does, or was still holding them when the run ended"
                + (", or put them back unstarted when the run stopped short (process exited 1, which is how an "
                   "exhausted quota ends it)" if process_exited_short else "")
                + ". No model reached a verdict on those files, so silence about them is not a negative result.")
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
                    # The selection marker of a curated system, on every outcome this run returns,
                    # whatever its status: its configuration chose the AI batches before the run. A
                    # full run reports none, so its result stays the document it always was.
                    processing="curated" if process_manifest is not None else None,
                    # A run that left records pending delivered claims about part of the input
                    # and nothing at all about the rest, so its bundles are not resolved: the
                    # scoring contract must not read a claim budget off it, and must not grant
                    # quiet credit for a file no model opened. In a PR review a file left in
                    # ``error`` is the same case, and the ordinary one: direct mode exits 1 and
                    # the run goes on, so the claims of the batches that finished are all there is.
                    # So is a changed path DeepSec never listed: the claims about the rest are a
                    # part delivered, and a budget read off a part reads as one read off the whole.
                    # A full run whose process exited 1 with a file in ``error`` is the same case:
                    # standard mode exits 1 for exactly that and the run goes on. A full run that
                    # exited 0 with one (a batch whose results left a file out) keeps its bundles.
                    bundles_resolved=(findings_lost == 0 and identity_gaps == 0
                                      and native_validation_failures == 0
                                      and native_status_validation_failures == 0
                                      and not records.failures and statuses.incomplete == 0
                                      and (pr is None or not omitted)
                                      and not (statuses.errored and (pr is not None or process_exited_short))
                                      # Claims over a curated scope are a part chosen before the run.
                                      and process_manifest is None))
        exit_code = None
        for step in ("export", "process", "scan"):
            result = results.get(step)
            if result is not None and not result.timed_out:
                exit_code = result.exit_code
                break

        def tail(step: str, stream: str = "stderr") -> str:
            """The tail of one step's stderr, or its stdout, read the way a scanner-owned path must be.

            DeepSec can replace this file after its own descriptor closed, so it is read
            through :func:`bounded_tail`: contained in this run's raw output, no symbolic link
            followed, no named pipe waited on, and only the last bytes taken rather than the
            whole file. An unreadable one costs the quoted tail and not the failure being
            reported.
            """
            path = Path(raw_dir) / f"deepsec-{step}.{stream}.txt"
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
                short = step == "process" and result.exit_code == process_exit
                if short and exit_one_explained:
                    # DeepSec's exit 1 for a run that ended short, and its records say how; the
                    # status below is made from them.
                    continue
                message = f"deepsec {step} exited {result.exit_code}; stderr: {tail(step)}"
                if short and pr is not None:
                    message = ("deepsec process exited 1 and left no finding, no file in status 'error' or "
                               "unfinished and no parse-failure dump, which is what an exit 1 means in direct "
                               "mode; it also exits 1 for a runtime failure such as an unresolvable range; "
                               f"stderr: {tail(step)}")
                elif short:
                    # Standard mode prints its reason on stdout, so both are quoted, stderr first, each
                    # bounded so that neither can push the other out of the message.
                    printed = ANSI_ESCAPE.sub("", tail(step, "stdout")).strip()[-500:]
                    message = ("deepsec process exited 1 and left no file in status 'error' and none still "
                               "'processing', which is what an exit 1 means in standard mode (an errored batch or "
                               "an exhausted quota leaves its batch's files in 'error'); it also exits 1 for a "
                               f"runtime failure; stderr: {tail(step)[-1000:]}; stdout: {printed}")
                return NativeOutcome(status="error", exit_code=result.exit_code, claims=[],
                                     error={"code": f"{step}_exit_{result.exit_code}",
                                            "message": message[:2000]}, **base)
        if export_failure is not None:
            return NativeOutcome(status="error", exit_code=exit_code, claims=[],
                                 error={"code": "unreadable_export",
                                        "message": f"deepsec exported findings this adapter could not "
                                                   f"read: {export_failure}; stderr: {tail('export')}"[:2000]},
                                 **base)

        def stopped(code: str, message: str) -> NativeOutcome:
            """The outcome of a run that reached no verdict on part of what it was given.

            ``partial``, carrying the claims DeepSec did produce, in every mode. The one refinement
            is a PR review, or a full run whose ``process`` exited 1, in which no file reached a
            verdict at all: with nothing analyzed there is no partial observation to report, so it is
            an ``error`` with no claims. A full run that exited 0 keeps its ``partial``, as it always
            did.
            """
            if pr is not None or process_exited_short:
                # What DeepSec wrote to stderr says why a run that stopped short stopped, when it
                # crashed instead of running out of quota, and costs nothing when it is empty.
                if process_exited_short:
                    detail = tail("process").strip()
                    message = f"{message}; deepsec process stderr: {detail}" if detail else message
                if statuses.finished == 0:
                    return NativeOutcome(status="error", exit_code=exit_code, claims=[],
                                         error={"code": code, "message": (f"{message}; no file reached a verdict, so "
                                                                          f"none of the {subject} was observed")[:2000]},
                                         **base)
                message = message[:2000]
            return NativeOutcome(status="partial", exit_code=exit_code, claims=imported.claims,
                                 error={"code": code, "message": message}, omitted_paths=unexamined,
                                 examined_nothing=nothing_examined, **base)

        if findings_lost or identity_gaps or native_validation_failures or records.failures:
            detail = "; ".join(list(imported.notes) + finding_import_notes + list(records.failures))
            if missing_export_lower == missing_export_upper:
                omission = (f"{missing_export_lower} record finding(s) are established to have no "
                            "export entry")
            else:
                omission = (f"record findings with no export entry are bounded between "
                            f"{missing_export_lower} and {missing_export_upper} because unidentified "
                            "entries cannot be correlated")
            return NativeOutcome(status="partial", exit_code=exit_code, claims=imported.claims,
                                 error={"code": "import_loss",
                                        "message": (f"{imported.lost} exported finding(s) could not be imported; "
                                                    f"{omission}; {identity_gaps} imported claim(s) could not be "
                                                    f"joined to native identity; {native_validation_failures} "
                                                    "native record/finding validation issue(s) prevented exact "
                                                    f"reconciliation; and {len(records.failures)} DeepSec "
                                                    "record(s) could not be imported. Counts from "
                                                    f"unidentified exports and unmatched records are bounds, not "
                                                    f"additive losses: {detail}")[:2000]},
                                 omitted_paths=unexamined, examined_nothing=nothing_examined, **base)

        subject = "input" if pr is None else "change"
        # Which of two failures the records already show is named from what DeepSec printed; a full run
        # reads that only beside the exit it prints it with, since standard mode exits 1 on a quota.
        if (pr is not None or process_exited_short) and output.quota and (statuses.errored or statuses.unfinished):
            return stopped("quota_exhausted",
                           f"deepsec process stopped: {output.quota} exhausted, in DeepSec's own words. "
                           f"{statuses.finished} of {len(records.files)} file record(s) reached a verdict, "
                           f"{len(statuses.errored)} were left in status 'error' and {unfinished_files} were never "
                           f"finished, so the rest of the {subject} was not reviewed")
        if batches_failed:
            counted = (f"; DeepSec itself counted {output.errored_batches} errored batch(es)"
                       if output.errored_batches else "")
            # The cause, when the sessions' own transcripts recorded one as how they ended. Named by
            # closed code only; a refusal a session recovered from is not a cause of anything here.
            caused = ("; the Claude Code CLI recorded the provider refusing a request that ended "
                      + ", ".join(f"{count} session(s) with {cause}" for cause, count in ended_on_refusal.items())
                      if ended_on_refusal else "")
            return stopped("deepsec_batches_failed",
                           f"{len(errored_files)} file(s) in status 'error', {len(records.debug)} parse-failure "
                           f"dump(s) and {refusals} refusal(s): part of the {subject} reached no verdict{counted}"
                           f"{caused}")
        if statuses.invalid:
            return stopped("invalid_record_status",
                           f"{len(statuses.invalid)} of {len(records.files)} "
                           "file record(s) carry a status DeepSec does not "
                           "declare, so whether it finished with them cannot "
                           "be read: "
                           + "; ".join(f"{name}: {reason}" for name, reason in statuses.invalid[:5]))
        if scope is not None and (scope.unexpected or scope.out_of_scope_claims or manifest_changed):
            # The run cannot show its verdicts kept to the declared batch assignment, which is a stronger
            # failure than a scope left incomplete. Every record and claim stays; only the status says so.
            return stopped("process_manifest_not_honored",
                           f"config.process_manifest_by_tree declared {len(scope.manifest)} path(s) for DeepSec's AI "
                           f"batches, but {len(scope.unexpected)} unlisted file record(s) carry analysis, findings or "
                           f"a status other than 'pending', {scope.out_of_scope_claims} imported claim(s) are on "
                           "unlisted paths"
                           + (f", and {manifest_changed}" if manifest_changed else "")
                           + "; the claims are kept, but the run is not the declared curated diagnostic")
        if unfinished_files:
            # The AI stage never finished with these files. A ``success`` here would let the
            # scoring contract treat every assigned control as completed and grant quiet credit
            # for a file no model reached a verdict on, which is the one thing this adapter's
            # notes say the run does not establish. The status now says it too. A run whose process
            # exited 1 was still holding some of them when it died, which its stderr names, so the
            # limit is not offered as the cause.
            limit = (f" under config.limit {config.limit}"
                     if config.limit is not None and pr is None and not process_exited_short else "")
            return stopped("scope_incomplete",
                           f"{unfinished_files} of {len(records.files)} file "
                           f"record(s) were left unfinished{limit} "
                           f"({', '.join(statuses.unfinished[:5])}): DeepSec "
                           "reached no verdict on them, so this run observed "
                           f"part of the {subject} and says nothing about the "
                           "rest"
                           + (f"; config.process_manifest_by_tree limited AI batches to {len(scope.manifest)} "
                              f"listed path(s) and assigned none to {len(scope.unselected) + scope.external} regex "
                              "candidate file(s), so this is a curated diagnostic and not a full-repository "
                              "observation"
                              if scope is not None else ""))
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
        if scope is not None:
            # Every regex candidate was on a listed path, or none was. DeepSec then did what an ordinary run
            # does, but which paths could get an AI batch was decided before the run with evaluator-side
            # knowledge, so the run still completes no control: a curated diagnostic is never a success.
            reached = ("every regex candidate file DeepSec's scan produced was on a listed path"
                       if scope.selected else
                       "DeepSec's scan produced no regex candidate on any listed path, so no AI batch ran")
            return stopped("scope_incomplete",
                           f"config.process_manifest_by_tree limited this full run's AI batches to "
                           f"{len(scope.manifest)} listed path(s) before it started, and {reached}; a curated diagnostic "
                           "is never a complete or blind observation of the full repository")
        return NativeOutcome(status="success", exit_code=exit_code, claims=imported.claims,
                             omitted_paths=unexamined, examined_nothing=nothing_examined, **base)
