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
"sum_of_per_file_shares"`` saying so. :func:`capture_status` states the rest of that
matrix, and ``docs/DEEPSEC.md`` documents it; a test parses the document and compares it
cell for cell against this function, so the two cannot drift apart.

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
"""

from __future__ import annotations

from importlib import import_module
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, NamedTuple

from ..collectors import EXTERNAL_PREFIX, relocate_paths, workspace_path
from ..execution import list_directory
from ..kinds import kind_for_harness_class
from ..observer import Observer, create_jsonl_sink
from .base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command
from .llm_harness import Enclosure, read_record


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
# How much of a refusal reason a metadata field may carry. Metadata is read by
# tooling and shown in summaries; the untouched reason goes to content, which the
# observer stores only in content mode.
REASON_SUMMARY_CHARS = 120
# The capture-status keys Contract 3 names, in the order the guide tables them.
CAPTURE_KEYS = ("model_requests", "model_responses", "tool_calls", "context_selection",
                "finding_candidate", "finding_submitted", "finding_validation",
                "finding_filtered")
THINKING_LEVELS = ("minimal", "low", "medium", "high", "xhigh")
AGENTS = ("claude", "codex", "pi")


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
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)
                continue
            if not path.name.endswith(suffix):
                continue
            relative = path.relative_to(directory).as_posix()
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
    when it also lists the files it skipped. ``summary`` is the reason with every absolute path
    relocated against the workspace and then clipped, so a metadata field carries a sentence a
    reader can act on rather than a paragraph of model prose that may quote source or name a
    machine. ``reason`` is that prose untouched, for ``content``, which the observer stores only
    in content mode and drops in metadata mode.
    """

    path: str
    code: str
    summary: str
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

    ``durationMs`` is the exception, found in a real run: it is written whole onto every file of
    the batch rather than divided, so it is taken as a maximum. Everything else is summed.

    ``correlated`` says whether DeepSec named the session at all. Entries carrying no
    ``agentSessionId`` used to share one empty key, so unrelated batches were merged into a
    single call with their paths, turns, cost and tokens added together: the one case where the
    native identifier is missing is the one case where correlation was being invented. Each such
    entry is its own group now, and the events built from it carry
    ``correlation: "missing_session_id"`` so a reader knows the call boundary is this adapter's
    guess at one entry rather than DeepSec's own.
    """

    run_id: str
    session_id: str
    model: str | None
    paths: tuple[str, ...]
    num_turns: float
    cost_usd: float
    # The batch wall clock, observed once. Unlike every other number here it is repeated on
    # each file rather than divided among them, so it is taken as a maximum and not a sum.
    duration_ms: float
    duration_api_ms: float
    usage: dict[str, int]
    refusals: tuple[Refusal, ...]
    correlated: bool
    key: str
    external_paths: int

    @property
    def call_id(self) -> str:
        """The logical invocation this group stands for, stable across a re-read."""
        return f"deepsec/{self.key}"

    @property
    def correlation(self) -> str:
        """How this call was correlated, for the event that has to say so."""
        return "agent_session_id" if self.correlated else "missing_session_id"


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    if value != value or value in (float("inf"), float("-inf")):  # NaN and the infinities
        return 0.0
    return float(value)


def clip(text: Any, limit: int) -> str:
    """*text* bounded to *limit* characters, with an ellipsis when it had to be cut."""
    if not isinstance(text, str):
        return ""
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _refusal(entry: dict, path: str, external: bool, roots: tuple[Path, ...]) -> "Refusal | None":
    """One :class:`Refusal` from an ``AnalysisEntry``, or ``None`` when it refused nothing.

    The code comes from the report's shape and never from reading its prose, because a
    classifier over model text would be this adapter inventing a category DeepSec did not
    record. The summary is the prose with every absolute path relocated against the workspace
    first, then clipped: a refusal reason is free text a model wrote and can quote source or an
    operator path, and Contract 3 says neither belongs in metadata.
    """
    refusal = entry.get("refusal")
    if not isinstance(refusal, dict) or refusal.get("refused") is not True:
        return None
    skipped = refusal.get("skipped")
    code = "refused_with_skipped_files" if isinstance(skipped, list) and skipped else "refused"
    raw = refusal.get("reason")
    reason = raw if isinstance(raw, str) else ""
    summary = clip(relocate_paths(reason, roots) if roots else reason, REASON_SUMMARY_CHARS)
    return Refusal(path, code, summary, reason, external)


def sessions_from(files: tuple[tuple[str, dict], ...],
                  roots: tuple[Path, ...] = ()) -> tuple[Session, ...]:
    """Group every ``analysisHistory`` entry into the model call it belongs to.

    The grouping key is ``agentSessionId``, which is what DeepSec correlates a batch by and what
    a Claude Code transcript is named after. An entry carrying none is not merged with the other
    entries carrying none: it becomes its own uncorrelated group, keyed by the record it sits on
    and its position in that record's history. Merging them was inventing a call boundary at
    exactly the moment the scanner had failed to record one, and it added the paths, turns, cost
    and tokens of unrelated batches together.

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
            correlated = bool(session_id)
            key = f"{run_id}/{session_id}" if correlated else f"uncorrelated/{path}/{index}"
            bucket = grouped.setdefault(key, {
                "run_id": run_id, "session_id": session_id, "correlated": correlated,
                "models": [], "paths": [], "turns": 0.0, "cost": 0.0, "duration": 0.0,
                "api": 0.0, "usage": {}, "refusals": [], "external": 0})
            model = entry.get("model")
            if isinstance(model, str) and model:
                bucket["models"].append(model)
            if path not in bucket["paths"]:
                bucket["paths"].append(path)
                bucket["external"] += int(external)
            bucket["turns"] += _number(entry.get("numTurns"))
            bucket["cost"] += _number(entry.get("costUsd"))
            # ``durationMs`` is the one field in the entry that is NOT a per-file share: a real
            # run wrote the identical batch wall clock (40847 ms) onto all three files of a
            # batch while dividing every other number by three. Summing it would report the
            # batch as having taken three times as long as it did, so the largest value is
            # taken instead, which is that one wall clock however many files repeat it.
            bucket["duration"] = max(bucket["duration"], _number(entry.get("durationMs")))
            bucket["api"] += _number(entry.get("durationApiMs"))
            usage = entry.get("usage")
            if isinstance(usage, dict):
                for source, target in (("inputTokens", "input_tokens"),
                                       ("outputTokens", "output_tokens"),
                                       ("cacheReadInputTokens", "cache_read_input_tokens"),
                                       ("cacheCreationInputTokens", "cache_creation_input_tokens")):
                    bucket["usage"][target] = bucket["usage"].get(target, 0.0) + _number(usage.get(source))
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
            refusals=tuple(bucket["refusals"]), correlated=bucket["correlated"], key=key,
            external_paths=bucket["external"]))
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
    """Per-category capture availability for one DeepSec run. See ``docs/DEEPSEC.md``.

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

    ``tool_calls`` is the strictest: every session this run opened had a transcript found *and*
    imported with no malformed line and no unmatched tool result, and the observer reported no
    gap. One session without a transcript, or an import that reported either, is ``partial``; no
    transcript at all, and a run with tracing off, is ``unavailable``.

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
            imported_transcript = False
            if collectors is not None and session.session_id:
                find, load = collectors
                try:
                    paths = list(find(session.session_id, projects_dir=projects_dir))
                except Exception as exc:  # noqa: BLE001 - a collector failure costs the import
                    notes.append(f"transcripts for session {session.session_id} could not be "
                                 f"located ({type(exc).__name__}); none were imported")
                    imports_clean = False
                    paths = []
                if paths:
                    transcripts_found += 1
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
                    imported_transcript = True
                    malformed = getattr(summary, "malformed_lines", 0) or 0
                    unmatched = getattr(summary, "unmatched_tool_results", 0) or 0
                    if malformed or unmatched:
                        imports_clean = False
                        notes.append(f"transcript {Path(path).name} imported with {malformed} "
                                     f"malformed line(s) and {unmatched} unmatched tool result(s)")
            if session.refusals:
                notes.append(
                    f"DeepSec recorded {len(session.refusals)} refusal(s) on the analysis entries "
                    f"of call {call_id}: "
                    + "; ".join(f"{refusal.path} ({refusal.code})" for refusal in session.refusals))
            if imported_transcript:
                # The transcript is the record of this call, turn by turn. Adding a summed pair
                # beside it would be the same call counted twice.
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
            refusals = [{"file_path": refusal.path, "reason_code": refusal.code,
                         "summary": refusal.summary} for refusal in session.refusals]
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
                # The untouched reason is model prose and can quote source or name a machine, so
                # it is content, which the observer stores only in content mode.
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


class DeepsecAdapter(Adapter):
    name = "deepsec"
    adapter_version = "1.0.0"
    requires_git = False
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})
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
        """
        config = settings(spec)
        if not config.binary.exists():
            raise AdapterError(f"deepsec executable not found at {config.binary}")
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
                        "--root", str(source_dir), "--agent", config.agent,
                        "--model", config.model, "--concurrency", str(config.concurrency)]
        if config.thinking_level:
            process_argv += ["--thinking-level", config.thinking_level]
        if config.limit is not None:
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
        for step, argv in (("scan", scan_argv), ("process", process_argv), ("export", export_argv)):
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
        errored_files = sorted(name for name, record in records.files
                               if record.get("status") == "error")
        # Files the scan found and the AI stage never reached, which is what ``--limit`` does by
        # design: a real run left 29 of 35 records pending. No model opened those files, so
        # silence about them is not a negative result about them, and a run that leaves any of
        # them is not a complete observation of the input it was handed.
        pending_files = sum(1 for _name, record in records.files
                            if record.get("status") == "pending")
        refusals = sum(len(session.refusals) for session in sessions)
        batches_failed = len(errored_files) + len(records.debug) + refusals

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
        notes = [
            f"DeepSec ran as three CLI steps in one workspace under raw/deepsec-workspace: scan, "
            f"process and export. The recorded command is those three argv lists in order, "
            f"separated by '&&'; each step's stdout and stderr is its own raw artifact.",
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
        if pending_files:
            notes.append(
                f"{pending_files} of {len(records.files)} file record(s) were left in status "
                "'pending': DeepSec's scan stage found them but the AI stage never investigated "
                f"them, which is what config.limit"
                + (f" ({config.limit})" if config.limit is not None else "")
                + " does. No model looked at those files, so silence about them is not a "
                "negative result about them.")

        command = [*scan_argv, "&&", *process_argv, "&&", *export_argv]
        base = dict(command=command, artifacts=artifacts, tool_versions=tool_versions,
                    capture=capture, usage=usage, notes=notes, model_identity=model_identity,
                    trace_path=trace_path, capture_state=capture_state,
                    # A run that left records pending delivered claims about part of the input
                    # and nothing at all about the rest, so its bundles are not resolved: the
                    # scoring contract must not read a claim budget off it, and must not grant
                    # quiet credit for a file no model opened.
                    bundles_resolved=(imported.lost == 0 and not records.failures
                                      and pending_files == 0))
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
        for step in ("scan", "process", "export"):
            result = results.get(step)
            if result is None:
                return NativeOutcome(status="error", exit_code=exit_code, claims=[],
                                     error={"code": f"{step}_not_run",
                                            "message": f"deepsec {step} never ran; an earlier step "
                                                       "ended the invocation"}, **base)
            if result.exit_code != 0:
                return NativeOutcome(status="error", exit_code=result.exit_code, claims=[],
                                     error={"code": f"{step}_exit_{result.exit_code}",
                                            "message": f"deepsec {step} exited {result.exit_code}; "
                                                       f"stderr: {tail(step)}"[:2000]}, **base)
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
        if batches_failed:
            return NativeOutcome(status="partial", exit_code=exit_code, claims=imported.claims,
                                 error={"code": "deepsec_batches_failed",
                                        "message": f"{len(errored_files)} file(s) in status 'error', "
                                                   f"{len(records.debug)} parse-failure dump(s) and "
                                                   f"{refusals} refusal(s): part of the input reached "
                                                   "no verdict"}, **base)
        if pending_files:
            # The AI stage never opened these files. A ``success`` here would let the scoring
            # contract treat every assigned control as completed and grant quiet credit for a
            # file no model looked at, which is the one thing this adapter's notes say the run
            # does not establish. The status now says it too.
            limit = f" under config.limit {config.limit}" if config.limit is not None else ""
            return NativeOutcome(status="partial", exit_code=exit_code, claims=imported.claims,
                                 error={"code": "scope_incomplete",
                                        "message": f"{pending_files} of {len(records.files)} file "
                                                   f"record(s) were left in status 'pending'{limit}: "
                                                   "DeepSec's scan stage found them and its AI stage "
                                                   "never investigated them, so this run observed "
                                                   "part of the input and says nothing about the "
                                                   "rest"}, **base)
        return NativeOutcome(status="success", exit_code=exit_code, claims=imported.claims, **base)
