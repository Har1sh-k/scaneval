"""Offline import of one saved SARIF 2.1.0 log: profile ``sarif-import-1``.

``docs/SARIF_IMPORT.md`` states the profile. This module reads a log a scanner wrote somewhere
else, at some other time, and never runs anything to produce one.

What it reads. The SARIF file the operator names, read once, as bytes, up to a stated bound, and
only when it is a regular file, and beside it the operator's own small JSON files (a system
configuration, a normalization file), read the same strict way. Nothing a log names is ever
fetched or opened: not ``$schema``,
not a rule's ``helpUri``, and not a path in a location, which is a string to map into the scanned
tree or to refuse, never a file to read. The one tree it may open files in is an exported source
tree the operator supplies to check locations against, and only after that tree hashes to the
declared tree hash; there it opens the regular files of its own listing, to count their lines. A
log that carries ``externalPropertyFileReferences`` anywhere (on any run, or on the log object) is
refused whole, because its results, rules, or artifacts may live in files an offline import will
not read, and importing the part that happens to be inline would present an incomplete run as the
whole one.

Refusal is for the log as a whole. A file that cannot be read, that is larger than the bound,
whose bytes are not UTF-8, whose text is not JSON, or whose JSON repeats an object key, carries
``NaN`` or an infinity, holds a string that is not Unicode text, or nests past the parser's
recursion limit is refused with :class:`SarifImportError` naming what was wrong, and so is a
log whose ``version`` is not ``2.1.0``, whose ``runs`` is missing, ``null``, or empty, that holds
more than one run when no run index was named, whose named run index is out of range, or whose
selected run is not shaped like a run (no ``tool.driver.name``, or a container property of the
wrong JSON type). A refusal writes nothing.

Every result of the selected run is accounted for exactly once, by :func:`convert_run`:

- **A claim**, id ``r<run>-<index>``, when the result alleges a problem (kind ``fail``, the
  default, or ``review`` or ``open``) and its rule, message, and primary location resolve. One
  result is at most one claim, cited to the preserved artifact. Claims are unranked: SARIF array
  order has no meaning (Appendix F.3), and ``rank`` and ``level`` are a tool's scores, not a
  review order the tool delivered.
- **An exclusion** the profile states: kind ``pass``, ``notApplicable``, or ``informational``,
  which allege nothing; ``baselineState`` ``absent``, which the log says was not detected in this
  run; and a suppressed result unless suppressed results are asked for. Exclusions are counted and
  listed, never dropped in silence.
- **A loss**, when the result alleges something this importer cannot place: a rule reference
  that names no descriptor or conflicts with itself, a message that does not resolve, or a
  primary location that is not a file in the scanned tree, or when reading it raised a
  ``ValueError`` (no one result can end an import). A loss is import loss: it leaves the
  bundles unresolved and a clean run ``partial`` with error code ``import_loss``, so a scan whose
  finding ScanEval could not read can earn neither completeness nor quiet credit.

Within a claim, a related location or a code-flow step that does not resolve is an evidence
loss recorded against that claim, not a reason to drop the claim. A result whose shape suggests
it may bundle separate allegations (several primary locations, or code flows that start in
different places) is flagged for bundle review rather than split or guessed at.

What is bounded, and what is not. ``--max-bytes`` bounds the bytes read. After that, one message,
as written or once formatted, is at most :data:`MESSAGE_LIMIT` characters, and a rule's
relationships and tags and the run's taxonomies are read once, not once per result. Not bounded: a
run's messages together (results that share one long string each hold a copy of it), the CWE ids a
rule lists (each of its claims holds a copy), and the search for a rule or a component named by
guid, which reads the list each time. So the size bound of a log is not a bound on the memory or
the time an import takes.

What it never invents. A line range is read from a region's ``startLine`` and ``endLine`` or not
at all: an offset-only region stays file-only. Execution success is the log's own report and is
never verified; a log that reports no execution outcome is not a clean scan. Timing, cost, and
model identity are not in a SARIF log, so the scan result says ``usage.wall_seconds`` is ``null``
and claims nothing else. Nothing here reads source semantics, applies a fix, renders Markdown,
or decides whether an allegation is true.

What an import writes. :func:`import_sarif` binds the result to the pack snapshot, tree hash,
and system the operator declares, never to anything the log says about itself, and writes one
new bundle: the artifact's bytes under ``raw/``, ``result.json`` (scan-result 2.1),
``import.json`` (the import record), the plan, a machine draft of review decisions in which
every decision is ``unresolved``, a draft review record, ``evaluation.json`` and
``report.html``, so ``review``, ``score``, ``replay`` and ``report`` read it exactly as they
read a bundle ``scaneval run`` wrote. Every document is built and checked before the bundle
directory exists, the directory must not exist, and every file in it is created exclusively; a
write that fails part way removes what this call created. Nothing here approves anything: a
bundle review decision is only ever read from the operator's normalization file, where a
named person recorded it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping
from urllib.parse import unquote

from . import __version__, cases, materialize, report, review, scoring
# _require_relative_path is imported rather than re-implemented so a location this importer records
# is judged by the one rule the scan-result contract applies to every claim path.
from .contracts import (
    ContractError,
    _require_relative_path,
    canonical_json,
    canonical_sha256,
    is_stated,
    validate_document,
)
from .kinds import cwe_ids, kind_for_cwes, mapping_version


PROFILE = "sarif-import-1"
RECORD_KIND = "import-record"
RECORD_FILE = "import.json"
RESULT_FILE = "result.json"
RAW_DIR = "raw"
SARIF_VERSION = "2.1.0"
# SARIF 3.14.2: where a run says which of its properties live in external property files.
_EXTERNAL = "externalPropertyFileReferences"
# The largest artifact read by default: 64 MiB, the same bound the transcript readers keep. A
# larger log is refused rather than read part way; --max-bytes raises the bound deliberately.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 1 << 20
_BYTE_ORDER_MARK = chr(0xFEFF)
# A lone UTF-16 surrogate survives JSON parsing as a string that is not Unicode text; it cannot
# be written into any record, so a log carrying one is refused rather than half written.
_SURROGATE = re.compile("[\ud800-\udfff]")

ARTIFACT_ID = "sarif"
# The base id SARIF's own examples and both CodeQL and Semgrep use for the source root. It is a
# convention, not a SARIF definition, and this profile reads it as the scanned tree's root only
# when neither the operator nor the log says otherwise.
SRCROOT = "%SRCROOT%"
# What Semgrep OSS writes in place of a fingerprint it withholds from a user who is not logged in.
UNAVAILABLE_FINGERPRINT = "requires login"
CLAIMED_KINDS = ("fail", "review", "open")
EXCLUDED_KINDS = ("pass", "notApplicable", "informational")
LEVELS = ("none", "note", "warning", "error")
BASELINE_STATES = ("new", "unchanged", "updated", "absent")
SUPPRESSION_STATUSES = ("accepted", "underReview", "rejected")
# A suppression under review or rejected does not suppress; any other suppression does, a missing
# status included. SARIF 2.1.0 states no rule for a missing status; this is how the SARIF SDK's
# Result.TryIsSuppressed reads one.
_UNSUPPRESSING = frozenset({"underReview", "rejected"})
MULTIPLE_LOCATIONS = "multiple_locations"
DIVERGENT_CODE_FLOWS = "divergent_code_flows"
# Evidence text renders at most this many flow steps and this many UTF-8 bytes per claim; the
# rest is counted, recorded as an evidence loss, and kept in the raw artifact.
FLOW_STEP_LIMIT = 256
FLOW_TEXT_LIMIT = 65536
# A message is at most this many characters, as written or once formatted. A tool's message is a
# sentence or two, but formatting turns a few bytes of log into megabytes (one long argument under
# thousands of placeholders, or one messageStrings entry shared by every result), and the import
# keeps a copy of the message in every claim. A longer message is a loss; the raw artifact keeps it.
MESSAGE_LIMIT = 65536
# The claim text of one whole run (every allegation and every evidence text, counted in characters) is
# at most this much. MESSAGE_LIMIT bounds one message, but every result can name the same one: a single
# messageStrings entry used by 4000 results turned a 1.45 MB log into 252 MB of allegations. Claims are
# read in result order until the next one would take the total past the budget; that result and every
# one after it is a loss, and the raw artifact keeps them. It is a constant of the profile, not an option.
RUN_TEXT_BUDGET = 64 * 1024 * 1024

# The most digits a log's number can have where this module reads one out of a string: a placeholder
# index or a location id. int() refuses a string of more than 4300 digits (a limit an environment can
# lower), so a longer one is never handed to it, and no log holds a billion arguments or locations.
_MAX_DIGITS = 9

_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_DRIVE = re.compile(r"^[A-Za-z]:")
_TOKEN = re.compile(r"\{\{|\}\}|\{([0-9]+)\}|[{}]")
_LINK = re.compile(r"\[(?:[^\\\[\]]|\\.)*\]\(([0-9]+)\)")
_DIGITS = re.compile(r"[0-9]+")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")


class SarifImportError(ContractError):
    """The import is refused as a whole, and nothing is written for it."""


class _Unusable(Exception):
    """One reference, location, or message this importer cannot use, carrying the reason."""


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _bounded_int(digits: str) -> int | None:
    """The value of the ASCII digit string *digits*, or ``None`` when it needs more than :data:`_MAX_DIGITS`.

    Leading zeros do not count: ``0007`` is 7. A longer number is not converted at all.
    """
    trimmed = digits.lstrip("0")
    if len(trimmed) > _MAX_DIGITS:
        return None
    return int(trimmed) if trimmed else 0


def _text(value: Any) -> str | None:
    """*value* when it is a non-empty string, else ``None``."""
    return value if isinstance(value, str) and value else None


def _elided(text: str, limit: int = 80) -> str:
    """*text* as a reason quotes it: whole when short, cut at *limit* characters with ``...`` when a log made it long."""
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _shown(value: Any, limit: int = 80) -> str:
    """*value* as a phrase in a reason: a scalar as written, cut at *limit* characters, and an array
    or an object by its type.

    A reason is built from what a log holds. The repr of a structure a log nested deeply can run past
    the recursion limit, so a container is never walked here.
    """
    if isinstance(value, (dict, list)):
        return "an object" if isinstance(value, dict) else "an array"
    return _elided(repr(value), limit)


# --- reading the artifact ---------------------------------------------------------------


def _read_bounded(path: Path, max_bytes: int, what: str, hint: str = "") -> bytes:
    """The bytes of the regular file at *path*, read once and never past *max_bytes*.

    *what* names the file in every refusal ("the SARIF file", "the --normalization file"), and
    *hint* is appended to the refusal of a file above the bound.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise SarifImportError(f"could not open {what} {path}: {exc}") from exc
    chunks: list[bytes] = []
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SarifImportError(f"{what} {path} is not a regular file, so it is not read")
        if info.st_size > max_bytes:
            raise SarifImportError(f"{what} {path} holds {info.st_size} bytes, more than the "
                                   f"{max_bytes}-byte bound{hint}")
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise SarifImportError(f"{what} {path} grew past the {max_bytes}-byte bound while it was "
                                       "read; it is not read in part")
    except OSError as exc:
        raise SarifImportError(f"could not read {what} {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def read_artifact(path: Path, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """The bytes of the SARIF file at *path*, read at most once and never past *max_bytes*.

    The file is opened without blocking and checked to be a regular file before anything is
    read, so a FIFO or a device named as the log is refused instead of hanging the import or
    reading forever. A file whose size is above *max_bytes*, or that grows past it while it is
    read, is refused rather than read in part. A symbolic link named on the command line is
    followed, because the operator chose it; that is the only path this module ever opens on a
    log's behalf, and it is not one the log supplied.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise SarifImportError(f"the size bound must be a positive number of bytes, not {max_bytes!r}")
    return _read_bounded(path, max_bytes, "the SARIF file", "; raise --max-bytes to import a larger log")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SarifImportError(f"repeats the object key {key!r}; which value was meant cannot be told")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise SarifImportError(f"carries the non-finite JSON number {value}, which JSON does not allow")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise SarifImportError(f"carries the number {text}, which overflows to infinity")
    return value


def _refuse_non_text(document: Any) -> None:
    """Refuse a key or string value holding a lone surrogate, walking without recursion.

    The walk is iterative so a document the parser accepted is never refused here for its depth.
    """
    pending = [document]
    while pending:
        value = pending.pop()
        if isinstance(value, str):
            if _SURROGATE.search(value):
                raise SarifImportError("holds a string with a lone UTF-16 surrogate escape, which is not "
                                       "Unicode text")
        elif isinstance(value, dict):
            for key, item in value.items():
                if _SURROGATE.search(key):
                    raise SarifImportError("holds an object key with a lone UTF-16 surrogate escape, which "
                                           "is not Unicode text")
                pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)


def _strict_json(text: str, subject: str) -> Any:
    """Parse *text* strictly, naming *subject* in every refusal."""
    try:
        value = json.loads(text, object_pairs_hook=_strict_object, parse_constant=_reject_constant,
                           parse_float=_finite_float)
        _refuse_non_text(value)
    except SarifImportError as exc:
        raise SarifImportError(f"{subject} {exc}") from None
    except RecursionError as exc:
        raise SarifImportError(f"{subject} nests deeper than the JSON parser's recursion limit") from exc
    except ValueError as exc:
        raise SarifImportError(f"{subject} is not valid JSON: {exc}") from exc
    return value


# An operator-supplied JSON object (a system configuration, a normalization file) is small; one
# larger than this is refused rather than read.
_OPERATOR_FILE_BOUND = 1024 * 1024


def load_json_object(path: Path, label: str) -> dict:
    """The JSON object in an operator-supplied file, read with the same strictness as a log.

    For the files an operator hands an import beside the log (``--system-config``,
    ``--normalization``): a regular file of at most 1 MiB, UTF-8, JSON without repeated keys,
    non-finite numbers, or text that is not Unicode, holding one object. *label* names the option
    the file came from, and every refusal names that option and the file. Nothing in the file is
    followed: a path or URI it holds is a string like any other.
    """
    what = f"the {label} file"
    data = _read_bounded(Path(path), _OPERATOR_FILE_BOUND, what)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SarifImportError(f"{what} {path} is not UTF-8 text: {exc}") from exc
    value = _strict_json(text, f"{what} {path}")
    if not isinstance(value, dict):
        raise SarifImportError(f"{what} {path} is not a JSON object")
    return value


def parse_log(data: bytes) -> tuple[dict, list[str]]:
    """The SARIF log *data* holds, and notes on what reading it tolerated.

    Parsing is strict: bytes that are not UTF-8, text that is not JSON, a repeated object key, a
    ``NaN`` or infinity (spelled as a constant or as a number too large for a float), an integer
    literal longer than the interpreter's digit limit, nesting past the parser's recursion limit,
    and a string that is not Unicode text are each refused with :class:`SarifImportError`. The one
    thing tolerated is a leading UTF-8 byte order mark, which RFC 8259 section 8.1 lets a parser
    ignore; it is ignored and noted, and the artifact hash still covers it. Only the document's
    shape as a JSON object is checked here: which of its fields are SARIF is read later.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SarifImportError(f"the log is not UTF-8 text: {exc}") from exc
    notes: list[str] = []
    if text.startswith(_BYTE_ORDER_MARK):
        text = text[1:]
        notes.append("A leading UTF-8 byte order mark was ignored (RFC 8259 section 8.1); the "
                     "artifact hash covers the bytes as supplied.")
    document = _strict_json(text, "the log")
    if not isinstance(document, dict):
        raise SarifImportError(f"the log is a JSON {type(document).__name__}, not a SARIF log object")
    return document, notes


def select_run(log: dict, run_index: int | None = None) -> tuple[int, dict, int]:
    """``(index, run, run count)`` for the one run of *log* this import reads.

    The log must be SARIF ``2.1.0`` with a non-empty ``runs`` array: ``null`` there means the
    producer tried and failed to populate it (SARIF 2.1.0 errata 01, section 3.13.4), an empty
    array means it found no data, and neither is a run to import. A log with more than one run
    needs *run_index*, because which run is the scan being evaluated is the operator's statement,
    not something to infer. Every run is checked for ``externalPropertyFileReferences``, not only
    the selected one, and so is the log object itself, because the log is what is being imported
    and a log that points outside itself is not complete offline. The property is refused
    whatever its value, ``null`` included: SARIF gives it no meaning there, and what a producer
    that wrote it meant to leave outside the file cannot be told.
    """
    version = log.get("version")
    if version != SARIF_VERSION:
        raise SarifImportError(f"the log declares version {version!r}; this importer reads SARIF "
                               f"{SARIF_VERSION} only")
    if _EXTERNAL in log:
        raise SarifImportError(f"the log object carries {_EXTERNAL}, which points at files outside this "
                               "log that an offline import never reads")
    if "runs" not in log:
        raise SarifImportError("the log has no runs property; SARIF requires one")
    runs = log["runs"]
    if runs is None:
        raise SarifImportError("the log's runs is null: the producer failed to populate it, so there "
                               "is no run to import")
    if not isinstance(runs, list):
        raise SarifImportError(f"the log's runs is a {type(runs).__name__}, not an array")
    if not runs:
        raise SarifImportError("the log's runs is empty: the producer reported no run to import")
    for index, run in enumerate(runs):
        if isinstance(run, dict) and _EXTERNAL in run:
            raise SarifImportError(
                f"runs[{index}] carries {_EXTERNAL}: its results, rules, or artifacts may live in "
                "files outside this log, which an offline import never reads")
    if run_index is None:
        if len(runs) != 1:
            raise SarifImportError(f"the log holds {len(runs)} runs; name the one to import with "
                                   "--run-index")
        run_index = 0
    elif isinstance(run_index, bool) or not isinstance(run_index, int) or not 0 <= run_index < len(runs):
        raise SarifImportError(f"run index {run_index!r} is out of range: the log holds {len(runs)} "
                               f"run(s), numbered from 0")
    run = runs[run_index]
    if not isinstance(run, dict):
        raise SarifImportError(f"runs[{run_index}] is a {type(run).__name__}, not a run object")
    return run_index, run, len(runs)


# --- mapping artifact URIs into the scanned tree ------------------------------------------


@dataclass(frozen=True)
class _Uri:
    """A URI split far enough to map it: a scheme (``None`` for a relative reference), the
    authority of a ``file`` URI, its percent-decoded path segments, and whether it ends in ``/``."""

    scheme: str | None
    authority: str
    segments: tuple[str, ...]
    directory: bool


def _segments(path: str, label: str, raw: str) -> tuple[str, ...]:
    """Percent-decode *path* one segment at a time, dropping empty and ``.`` segments.

    Decoding is per segment and strict UTF-8 (SARIF 3.10.4), so an encoded slash, backslash, or
    NUL inside a segment is refused rather than turned into a separator: every reader of a claim
    path downstream (the scan-result contract, scoring, review routing) takes a backslash as a
    separator too. A ``..`` segment is refused, never resolved away (SARIF 3.10.2).
    """
    kept: list[str] = []
    for part in path.split("/"):
        try:
            decoded = unquote(part, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise _Unusable(f"{label} {raw!r} percent-decodes to bytes that are not UTF-8") from exc
        if decoded in ("", "."):
            continue
        if decoded == "..":
            raise _Unusable(f"{label} {raw!r} has a '..' segment, which is refused rather than "
                            "resolved (SARIF 3.10.2)")
        if "/" in decoded or "\\" in decoded or "\x00" in decoded:
            raise _Unusable(f"{label} {raw!r} encodes a slash, a backslash, or a NUL inside one path "
                            "segment")
        kept.append(decoded)
    return tuple(kept)


def _split_uri(raw: Any, label: str) -> _Uri:
    """Split one URI string, refusing what cannot name a file under a base.

    A backslash is not a URI character, so a Windows path written into a URI is refused rather
    than guessed at, and so is a drive letter, a query or fragment, a network-path reference
    (``//host``), and an absolute-path reference (a leading ``/``, SARIF errata 3.4.3). A scheme
    other than ``file`` is returned with no path for the caller to refuse by name.
    """
    if not isinstance(raw, str):
        raise _Unusable(f"{label} is a {type(raw).__name__}, not a URI string")
    if "\x00" in raw:
        raise _Unusable(f"{label} holds a NUL byte")
    if "\\" in raw:
        raise _Unusable(f"{label} {raw!r} holds a backslash, which is not a URI character, so the "
                        "path it means cannot be told")
    if _DRIVE.match(raw):
        raise _Unusable(f"{label} {raw!r} begins with a drive letter, so it is absolute on the "
                        "machine that wrote it")
    scheme = _SCHEME.match(raw)
    if scheme and scheme.group(1).lower() != "file":
        return _Uri(scheme.group(1).lower(), "", (), False)
    if "?" in raw or "#" in raw:
        raise _Unusable(f"{label} {raw!r} has a query or fragment, which no file path carries")
    if scheme:
        rest = raw[scheme.end():]
        authority = ""
        if rest.startswith("//"):
            authority, slash, remainder = rest[2:].partition("/")
            rest = slash + remainder
        if not rest.startswith("/"):
            raise _Unusable(f"{label} {raw!r} is a file URI without an absolute path")
        # RFC 8089: an empty authority and "localhost" both name the local machine.
        authority = "" if authority.lower() == "localhost" else authority.lower()
        return _Uri("file", authority, _segments(rest, label, raw), rest.endswith("/"))
    if raw.startswith("//"):
        raise _Unusable(f"{label} {raw!r} is a network-path reference, which SARIF errata 3.4.3 "
                        "forbids")
    if raw.startswith("/"):
        raise _Unusable(f"{label} {raw!r} is an absolute path, not a path relative to a base")
    return _Uri(None, "", _segments(raw, label, raw), raw == "" or raw.endswith("/"))


class UriSettings:
    """How an import maps artifact URIs into the scanned tree: configured bases and a source root.

    ``uri_bases`` maps a ``uriBaseId`` to where it points, which SARIF 3.4.4 says a consumer uses
    before anything the log says. A value is a directory relative to the scanned tree's root
    (ending in ``/``; empty or ``.`` for the root itself) or an absolute ``file`` URI ending in
    ``/`` that lies under ``source_root_uri``. ``source_root_uri`` is the absolute ``file`` URI
    of the scanned tree's root on the machine that wrote the log; without it no absolute file URI
    maps anywhere. A value that cannot mean a directory inside the scanned tree is refused with
    :class:`SarifImportError` before any result is read.
    """

    def __init__(self, uri_bases: Mapping[str, str] | None = None, source_root_uri: str | None = None):
        self.source_root_uri = source_root_uri
        self.root = None if source_root_uri is None else self._source_root(source_root_uri)
        self.configured = {name: (uri_bases or {})[name] for name in sorted(uri_bases or {})}
        self.bases = {name: self._configured_base(name, value) for name, value in self.configured.items()}

    @staticmethod
    def _source_root(value: Any) -> _Uri:
        try:
            root = _split_uri(value, "--source-root-uri")
        except _Unusable as exc:
            raise SarifImportError(str(exc)) from None
        if root.scheme != "file":
            raise SarifImportError(f"--source-root-uri {value!r} is not an absolute file URI")
        return root

    def _configured_base(self, name: Any, value: Any) -> tuple[str, ...]:
        label = f"--uri-base {name}"
        if not isinstance(name, str) or not name:
            raise SarifImportError(f"a --uri-base needs a name before '=', not {name!r}")
        if not isinstance(value, str):
            raise SarifImportError(f"{label} is a {type(value).__name__}, not a URI string")
        if value in ("", ".", "./"):
            return ()
        try:
            parsed = _split_uri(value, label)
            if parsed.scheme not in (None, "file"):
                raise _Unusable(f"{label}={value!r} is neither a directory inside the scanned tree nor "
                                "a file URI")
            if not parsed.directory:
                raise _Unusable(f"{label}={value!r} must end with '/', because it names a directory")
            return parsed.segments if parsed.scheme is None else self.under_root(parsed, f"{label}={value!r}")
        except _Unusable as exc:
            raise SarifImportError(str(exc)) from None

    def under_root(self, absolute: _Uri, what: str) -> tuple[str, ...]:
        """The segments of *absolute* below the declared source root, or why there are none.

        *what* names the URI in the reason, which is all the reason says about where it came from.
        """
        if self.root is None:
            raise _Unusable(f"{what} is an absolute file URI, and no --source-root-uri says which "
                            "directory is the scanned tree")
        size = len(self.root.segments)
        if absolute.authority != self.root.authority or absolute.segments[:size] != self.root.segments:
            raise _Unusable(f"{what} lies outside the declared source root {self.source_root_uri}")
        return absolute.segments[size:]


@dataclass(frozen=True)
class _Base:
    """Where a base id points: segments under the scanned root, or an absolute file URI."""

    prefix: tuple[str, ...] | None
    absolute: _Uri | None = None

    def join(self, segments: tuple[str, ...]) -> "_Base":
        if self.prefix is not None:
            return _Base(self.prefix + segments)
        assert self.absolute is not None
        return _Base(None, _Uri("file", self.absolute.authority, self.absolute.segments + segments, False))


class SourceTree:
    """An exported tree an import checks locations against: its listing, and line counts.

    :meth:`load` hashes the tree the way an export is hashed and refuses one whose hash is not
    the declared tree hash, because a check against some other tree would say nothing about the
    input a result binds to. The listing is the one the hash covers (regular files, symbolic
    links left out), and a file is opened only when it is in that listing, only to count its
    lines, and never through a symbolic link in its last component.
    """

    def __init__(self, root: Path, files: Mapping[str, Path]):
        self.root = root
        self.files = dict(files)
        self._lines: dict[str, int] = {}

    @classmethod
    def load(cls, root: Path, tree_hash: str) -> "SourceTree":
        root = Path(root)
        if not root.is_dir():
            raise SarifImportError(f"--source-dir {root} is not a directory")
        try:
            files = materialize.walk_regular_files(root)
            hashes = {relative: materialize.sha256_file(path)[0] for relative, path in sorted(files.items())}
        except OSError as exc:
            raise SarifImportError(f"--source-dir {root} could not be read: {exc}") from exc
        actual = materialize.tree_hash(hashes)
        if actual != tree_hash:
            raise SarifImportError(
                f"--source-dir {root} hashes to {actual}, not the declared tree hash {tree_hash}; "
                "checking locations against it would say nothing about the input")
        return cls(root, files)

    def _line_count(self, path: str) -> int:
        if path not in self._lines:
            descriptor = os.open(self.files[path], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as handle:
                self._lines[path] = sum(1 for _ in handle)
        return self._lines[path]

    def check(self, path: str, lines: tuple[int, int] | None, label: str) -> None:
        """Refuse a mapped path the exported tree does not hold, or a line past its end."""
        if path not in self.files:
            raise _Unusable(f"{label} maps to {path!r}, which is not a regular file in the exported tree")
        if lines is None:
            return
        try:
            count = self._line_count(path)
        except OSError as exc:
            raise _Unusable(f"{label} maps to {path!r}, whose lines could not be counted: {exc}") from exc
        if lines[1] > count:
            raise _Unusable(f"{label} ends on line {lines[1]} of {path!r}, which has {count} line(s)")


def _region_lines(region: Any, label: str) -> tuple[tuple[int, int] | None, str | None]:
    """``((start, end), None)`` for the lines *region* covers, or ``(None, why it is file-only)``.

    No region means the whole file (SARIF 3.29.4). A region without ``startLine`` but with a
    character or byte offset is recorded file-only: text and binary properties are independent
    (SARIF 3.30.4) and lines are never computed from offsets. ``endLine`` defaults to
    ``startLine``, and ``endColumn`` 1 on a later line means the region ends with the newline of
    the line before it (SARIF 3.30.2, example 5), so that line is the last one covered.
    Coordinates of the wrong type or out of order are refused.
    """
    if region is None:
        return None, "no region: the location is the whole file"
    if not isinstance(region, dict):
        raise _Unusable(f"{label} is a {type(region).__name__}, not a region object")
    start = region.get("startLine")
    if start is None:
        stray = [key for key in ("endLine", "startColumn", "endColumn") if region.get(key) is not None]
        if stray:
            raise _Unusable(f"{label} has {', '.join(stray)} without startLine")
        for key, least in (("charOffset", -1), ("byteOffset", -1), ("charLength", 0), ("byteLength", 0)):
            value = region.get(key)
            if value is not None and (not _is_int(value) or value < least):
                raise _Unusable(f"{label}.{key} is {value!r}, not an integer of at least {least}")
        if any(region.get(key) is not None and region[key] >= 0 for key in ("charOffset", "byteOffset")):
            return None, "offset-only region: recorded file-only, because lines are never computed from offsets"
        raise _Unusable(f"{label} states no startLine, charOffset, or byteOffset (SARIF 3.30.1)")
    for key in ("startLine", "endLine", "startColumn", "endColumn"):
        value = region.get(key)
        if value is not None and (not _is_int(value) or value < 1):
            raise _Unusable(f"{label}.{key} is {value!r}, not a positive integer")
    end = start if region.get("endLine") is None else region["endLine"]
    start_column = 1 if region.get("startColumn") is None else region["startColumn"]
    end_column = region.get("endColumn")
    if end < start:
        raise _Unusable(f"{label} ends on line {end}, before it starts on line {start}")
    if end == start and end_column is not None and end_column < start_column:
        raise _Unusable(f"{label} ends at column {end_column}, before it starts at column {start_column}")
    if end_column == 1 and end > start:
        end -= 1
    return (start, end), None


@dataclass(frozen=True)
class _Place:
    """One location resolved to a path in the scanned tree and, when the region states them, lines."""

    path: str
    lines: tuple[int, int] | None
    note: str | None = None

    def location(self) -> dict:
        location: dict[str, Any] = {"path": self.path}
        if self.lines is not None:
            location["start_line"], location["end_line"] = self.lines
        return location

    def label(self) -> str:
        if self.lines is None:
            return self.path
        start, end = self.lines
        return f"{self.path}:{start}" if start == end else f"{self.path}:{start}-{end}"


# --- messages and rules ------------------------------------------------------------------


def _too_long(label: str) -> _Unusable:
    return _Unusable(f"{label} is longer than {MESSAGE_LIMIT} characters, as written or once formatted, so it "
                     "is not read; the raw artifact keeps it")


def _formatted(template: str, arguments: list[str], label: str) -> str:
    """*template* with ``{n}`` replaced by ``arguments[n]`` and ``{{``/``}}`` undoubled (SARIF 3.11.5).

    A placeholder past the end of *arguments*, one with more than :data:`_MAX_DIGITS` digits, or a
    single brace that is neither half of an escape nor part of a placeholder, leaves the message
    unresolved rather than guessed at. So does a template longer than :data:`MESSAGE_LIMIT`
    characters, which is refused before it is scanned, and one that formats to more than that: the
    text is built piece by piece and stops at the bound, so the work is bounded by it whatever the
    log holds. That bounds one message, not a run: results that share a long string each hold a copy.
    """
    if len(template) > MESSAGE_LIMIT:
        raise _too_long(label)
    pieces: list[str] = []
    size = 0

    def emit(piece: str) -> None:
        nonlocal size
        size += len(piece)
        if size > MESSAGE_LIMIT:
            raise _too_long(label)
        pieces.append(piece)

    position = 0
    for match in _TOKEN.finditer(template):
        emit(template[position:match.start()])
        token = match.group(0)
        if token == "{{":
            emit("{")
        elif token == "}}":
            emit("}")
        elif match.group(1) is not None:
            index = _bounded_int(match.group(1))
            if index is None or index >= len(arguments):
                raise _Unusable(f"{label} uses placeholder {_elided(token)}, and {len(arguments)} argument(s) "
                                "are supplied (SARIF 3.11.11)")
            emit(arguments[index])
        else:
            raise _Unusable(f"{label} has a lone {token!r} that is neither a placeholder nor an "
                            "escaped brace (SARIF 3.11.5)")
        position = match.end()
    emit(template[position:])
    return "".join(pieces)


def _message_text(message: Any, label: str, *, descriptor: dict | None, component: dict | None) -> str:
    """The plain text of one SARIF message object (SARIF 3.11.7), before surrounding space is trimmed.

    The message's own ``text`` comes first. It is formatted only when the message carries
    ``arguments``: a producer that uses no placeholders (Semgrep and CodeQL both) writes braces
    unescaped, and its text is the message as written. Without text, ``id`` is looked up in the
    rule's ``messageStrings`` and then in its component's ``globalMessageStrings``, and the string
    found is formatted with the message's arguments. Markdown is never read. A message of more
    than :data:`MESSAGE_LIMIT` characters, written or formatted, is refused.
    """
    if not isinstance(message, dict):
        raise _Unusable(f"{label} is a {type(message).__name__}, not a message object")
    arguments = message.get("arguments")
    if arguments is not None and (not isinstance(arguments, list)
                                  or not all(isinstance(item, str) for item in arguments)):
        raise _Unusable(f"{label}.arguments is not an array of strings")
    text = message.get("text")
    if text is not None and not isinstance(text, str):
        raise _Unusable(f"{label}.text is a {type(text).__name__}, not a string")
    if text is not None and text.strip():
        if arguments is not None:
            return _formatted(text, arguments, label)
        if len(text) > MESSAGE_LIMIT:
            raise _too_long(label)
        return text
    identifier = message.get("id")
    if identifier is None:
        state = "blank text and no id" if text is not None else "no text and no id"
        raise _Unusable(f"{label} has {state}, so there is no message to read (SARIF 3.11.2)")
    if not _text(identifier):
        raise _Unusable(f"{label}.id is not a non-empty string")
    for owner, key in ((descriptor, "messageStrings"), (component, "globalMessageStrings")):
        strings = owner.get(key) if isinstance(owner, dict) else None
        entry = strings.get(identifier) if isinstance(strings, dict) else None
        if isinstance(entry, dict) and isinstance(entry.get("text"), str):
            return _formatted(entry["text"], arguments or [], label)
    raise _Unusable(f"{label}.id {identifier!r} is in neither the rule's messageStrings nor its "
                    "component's globalMessageStrings (SARIF 3.11.7)")


def _names(descriptor_id: str, identity: str) -> bool:
    """Whether a rule reference id names *descriptor_id*: equal, or it plus one hierarchical component."""
    if identity == descriptor_id:
        return True
    prefix = descriptor_id + "/"
    return identity.startswith(prefix) and len(identity) > len(prefix) and "/" not in identity[len(prefix):]


@dataclass(frozen=True)
class _Rule:
    """The rule a result names: the id it carried, the descriptor it resolved to, and its component."""

    reference: str | None
    native_id: str | None
    descriptor: dict | None
    component: dict
    pointer: str | None


def _cwe_token(value: Any) -> str | None:
    """``CWE-<n>`` for a taxon id such as ``"327"`` or ``"CWE-327"``, else ``None``.

    An id of more digits than :func:`scaneval.kinds.cwe_ids` reads is not a CWE.
    """
    if not isinstance(value, str):
        return None
    found = cwe_ids(f"CWE-{value}" if _DIGITS.fullmatch(value) else value)
    return found[0] if found else None


def _tags(owner: Any) -> list[str]:
    properties = owner.get("properties") if isinstance(owner, dict) else None
    tags = properties.get("tags") if isinstance(properties, dict) else None
    return [tag for tag in tags if isinstance(tag, str)] if isinstance(tags, list) else []


# --- one run --------------------------------------------------------------------------------


@dataclass
class Conversion:
    """What :func:`convert_run` made of one run: claims, their import entries, and the rest.

    ``claims`` and ``entries`` are parallel lists in result order. ``execution`` is the log's own
    account of the run, never verified, and ``failed`` the pointer of every invocation it reports
    failed. ``status`` and ``error`` are the scan status this profile derives from that account and
    from the losses; ``flagged`` maps the pointer of every claim flagged for bundle review to its
    reasons.
    """

    run_index: int
    run_count: int
    tool: dict
    claims: list[dict]
    entries: list[dict]
    excluded: list[dict]
    losses: list[dict]
    results_present: bool
    execution: dict
    notes: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    @property
    def result_count(self) -> int:
        return len(self.claims) + len(self.excluded) + len(self.losses)

    @property
    def flagged(self) -> dict[str, list[str]]:
        return {entry["pointer"]: entry["bundle_review"] for entry in self.entries if entry["bundle_review"]}

    def outcome(self) -> tuple[str, dict | None]:
        """``(status, error)`` for the scan result, from the execution evidence and the losses.

        Absent results are an error with no claims. A reported failure is ``partial`` when a claim
        was imported from what the run did produce and ``error`` otherwise, because a failed run's
        results are not complete (SARIF 3.20.21). A run whose execution the log does not report is
        ``partial``, never a clean scan. Import loss makes an otherwise clean run ``partial``. Every
        reason that applies is named in the message; the code is the first of them in that order.
        """
        reasons: list[tuple[str, str]] = []
        evidence = self.execution["evidence"]
        if not self.results_present:
            reasons.append(("results_absent", "run.results is null or absent: the tool produced no "
                                              "result list (SARIF 3.14.23)"))
        if evidence == "reported_failed":
            reasons.append(("execution_failed", "the log reports a failed execution at "
                            + ", ".join(self.failed) + "; a failed run's results are not complete "
                            "(SARIF 3.20.21)"))
        elif evidence == "unreported":
            reasons.append(("execution_unreported", "the log does not report whether the tool ran to "
                            "completion (no invocation, or one whose executionSuccessful or notification "
                            "levels cannot be read), so this is not a complete scan"))
        if self.losses:
            reasons.append(("import_loss", f"{len(self.losses)} result(s) the log reports could not be "
                            "imported as claims"))
        if not reasons:
            return "success", None
        code = reasons[0][0]
        if code == "results_absent":
            status = "error"
        elif code == "execution_failed":
            status = "partial" if self.claims else "error"
        else:
            status = "partial"
        return status, {"code": code, "message": "; ".join(message for _, message in reasons)[:2000]}


class _RunReader:
    """Reads one run: its tool components, artifacts, bases, and taxonomies, then each result."""

    def __init__(self, run: dict, run_index: int, *, settings: UriSettings, tree: SourceTree | None,
                 include_suppressed: bool):
        self.run = run
        self.run_index = run_index
        self.pointer = f"/runs/{run_index}"
        self.settings = settings
        self.tree = tree
        self.include_suppressed = include_suppressed
        tool = run.get("tool")
        if not isinstance(tool, dict) or not isinstance(tool.get("driver"), dict):
            raise SarifImportError(f"{self.pointer} has no tool.driver object; SARIF requires one")
        self.driver = tool["driver"]
        if not _text(self.driver.get("name")):
            raise SarifImportError(f"{self.pointer}/tool/driver has no name; SARIF requires one")
        self.extensions = self._array(tool, "extensions", f"{self.pointer}/tool")
        for index, extension in enumerate(self.extensions):
            if not isinstance(extension, dict):
                raise SarifImportError(f"{self.pointer}/tool/extensions/{index} is not a tool component object")
        for component, pointer in self._components():
            self._array(component, "rules", pointer)
            self._array(component, "notifications", pointer)
        self.artifacts = self._array(run, "artifacts", self.pointer)
        self.taxonomies = self._array(run, "taxonomies", self.pointer)
        self.thread_flow_locations = self._array(run, "threadFlowLocations", self.pointer)
        self.invocations = self._array(run, "invocations", self.pointer)
        bases = run.get("originalUriBaseIds")
        if bases is not None and not isinstance(bases, dict):
            raise SarifImportError(f"{self.pointer}/originalUriBaseIds is not an object")
        self.original_bases = bases or {}
        results = run.get("results")
        if results is not None and not isinstance(results, list):
            raise SarifImportError(f"{self.pointer}/results is a {type(results).__name__}, not an array")
        self.results = results
        self._paths: dict[tuple[Any, Any], str | _Unusable] = {}
        self._indexed: dict[int, str | _Unusable] = {}
        self._rule_ids: dict[str, dict[str, list[int]]] = {}
        self._notification_tables: dict[str, dict[str, dict[str, list[int]]]] = {}
        # Each taxonomy is found by guid or by name from one table, built here once, because every
        # relationship and taxon of every result asks; the first taxonomy carrying a value wins.
        self._taxonomy_by: dict[str, dict[str, dict]] = {"guid": {}, "name": {}}
        for taxonomy in self.taxonomies:
            if isinstance(taxonomy, dict):
                for key, table in self._taxonomy_by.items():
                    if isinstance(taxonomy.get(key), str):
                        table.setdefault(taxonomy[key], taxonomy)
        self._descriptor_cwes: dict[str | None, tuple[list[str], list[str]]] = {}
        # A tool component is found by guid from one table too, because every result that names one
        # by guid asks, and so does every notification descriptor that does. A guid is a string, as
        # SARIF defines it, and a reference whose guid is not one names no component.
        self._component_guids: dict[str, list[tuple[dict, str]]] = {}
        for pair in self._components():
            if isinstance(pair[0].get("guid"), str):
                self._component_guids.setdefault(pair[0]["guid"], []).append(pair)
        self._rule_guids: dict[str, dict[str, list[int]]] = {}
        # A uriBaseId is followed to the end of its chain once, however many results sit under it.
        self._bases: dict[str, _Base | _Unusable] = {}
        # The characters of allegation and evidence text the claims so far hold, and, once a claim
        # would take that past RUN_TEXT_BUDGET, the reason every result from it on is a loss.
        self._text_used = 0
        self._budget_reason: str | None = None

    @staticmethod
    def _array(owner: dict, key: str, pointer: str) -> list:
        value = owner.get(key)
        if value is None:
            return []
        if not isinstance(value, list):
            raise SarifImportError(f"{pointer}/{key} is a {type(value).__name__}, not an array")
        return value

    def _components(self) -> list[tuple[dict, str]]:
        return [(self.driver, f"{self.pointer}/tool/driver")] + [
            (extension, f"{self.pointer}/tool/extensions/{index}")
            for index, extension in enumerate(self.extensions)]

    # -- paths ----------------------------------------------------------------------------

    def _resolve_base(self, name: str, seen: tuple[str, ...]) -> _Base:
        """Resolve a base id: a configured value, then ``originalUriBaseIds``, then ``%SRCROOT%``.

        A configured value applies wherever its id appears, inside a chain as well, so an operator
        can say where a base the log hid (an entry without ``uri``) points. A chain that loops, an
        entry that is not an absolute URI and names no further base, and an entry URI that does
        not end in ``/`` do not resolve (SARIF 3.14.14).

        The chain is followed once for each name a result asks for, and the answer, a base or the
        reason there is none, is kept: every result under a base asks, and a chain of hundreds of
        entries followed again for each of them costs the whole run again. A name met part way along
        a chain is not kept, because what it answers there depends on the names before it, which
        decide whether it loops.
        """
        if seen:
            return self._follow_base(name, seen)
        if name not in self._bases:
            try:
                self._bases[name] = self._follow_base(name, seen)
            except _Unusable as exc:
                self._bases[name] = exc
        answer = self._bases[name]
        if isinstance(answer, _Unusable):
            raise _Unusable(str(answer))
        return answer

    def _follow_base(self, name: str, seen: tuple[str, ...]) -> _Base:
        """One step of :meth:`_resolve_base`: *name*, and then, through its entry, the rest of its chain."""
        if name in seen:
            raise _Unusable(f"uriBaseId chain {' -> '.join(seen + (name,))} loops")
        if name in self.settings.bases:
            return _Base(self.settings.bases[name])
        if name in self.original_bases:
            entry = self.original_bases[name]
            label = f"{self.pointer}/originalUriBaseIds[{name!r}]"
            if not isinstance(entry, dict):
                raise _Unusable(f"{label} is not an artifactLocation object")
            if entry.get("uri") is None:
                raise _Unusable(f"{label} omits its uri, so only --uri-base {name}=... can say where it points")
            parsed = _split_uri(entry["uri"], f"{label}.uri")
            if parsed.scheme not in (None, "file"):
                raise _Unusable(f"{label}.uri uses the {parsed.scheme} scheme, not a file URI")
            if not parsed.directory:
                raise _Unusable(f"{label}.uri {entry['uri']!r} does not end with '/' (SARIF 3.14.14)")
            if parsed.scheme == "file":
                return _Base(None, parsed)
            inner = entry.get("uriBaseId")
            if not _text(inner):
                raise _Unusable(f"{label} has a relative uri and no uriBaseId to resolve it against "
                                "(SARIF 3.14.14)")
            return self._follow_base(inner, seen + (name,)).join(parsed.segments)
        if name.upper() == SRCROOT:
            return _Base(())
        raise _Unusable(f"uriBaseId {name!r} is not configured with --uri-base, not declared in "
                        f"run.originalUriBaseIds, and is not {SRCROOT}")

    def _path(self, uri: Any, base_id: Any, label: str) -> str:
        """The path in the scanned tree that *uri* against *base_id* names, cached per pair.

        The cached answer, a path or the reason there is none, says nothing about where the pair
        was met, so every caller gets the reason under its own *label*.
        """
        key = (uri, base_id) if isinstance(uri, str) and (base_id is None or isinstance(base_id, str)) else None
        if key is None or key not in self._paths:
            try:
                answer: str | _Unusable = self._map(uri, base_id)
            except _Unusable as exc:
                answer = exc
            if key is None:
                if isinstance(answer, _Unusable):
                    raise _Unusable(f"{label}: {answer}")
                return answer
            self._paths[key] = answer
        cached = self._paths[key]
        if isinstance(cached, _Unusable):
            raise _Unusable(f"{label}: {cached}")
        return cached

    def _map(self, uri: Any, base_id: Any) -> str:
        parsed = _split_uri(uri, "uri")
        if parsed.scheme is not None and parsed.scheme != "file":
            raise _Unusable(f"uri {uri!r} uses the {parsed.scheme} scheme; only a file in the scanned "
                            "tree can be a claim location")
        if parsed.scheme == "file":
            if base_id is not None:
                raise _Unusable(f"uri {uri!r} is an absolute URI and also names uriBaseId {base_id!r} "
                                "(SARIF 3.4.4: it SHALL be absent)")
            segments = self.settings.under_root(parsed, f"uri {uri!r}")
        else:
            if base_id is None:
                base = _Base(())
            elif not _text(base_id):
                raise _Unusable(f"uriBaseId {base_id!r} is not a non-empty string")
            else:
                base = self._resolve_base(base_id, ())
            joined = base.join(parsed.segments)
            if joined.prefix is not None:
                segments = joined.prefix
            else:
                assert joined.absolute is not None
                segments = self.settings.under_root(joined.absolute, f"uri {uri!r} under uriBaseId {base_id!r}")
        if parsed.directory or not segments:
            raise _Unusable(f"uri {uri!r} names a directory, not a file")
        path = "/".join(segments)
        try:
            _require_relative_path(path, "the mapped path")
        except ContractError as exc:
            raise _Unusable(f"uri {uri!r} maps to {path!r}: {exc}") from exc
        return path

    def _indexed_artifact(self, index: int, label: str) -> str:
        """The path of ``run.artifacts[index]``, refusing a nested member or an index out of range."""
        if index not in self._indexed:
            try:
                self._indexed[index] = self._artifact_at(index, label)
            except _Unusable as exc:
                self._indexed[index] = exc
        cached = self._indexed[index]
        if isinstance(cached, _Unusable):
            raise _Unusable(f"{label}: {cached}")
        return cached

    def _artifact_at(self, index: int, label: str) -> str:
        pointer = f"{self.pointer}/artifacts/{index}"
        if index >= len(self.artifacts):
            raise _Unusable(f"index {index} is out of range: run.artifacts holds {len(self.artifacts)}")
        artifact = self.artifacts[index]
        if not isinstance(artifact, dict):
            raise _Unusable(f"{pointer} is not an artifact object")
        parent = artifact.get("parentIndex")
        if parent is not None and parent != -1:
            raise _Unusable(f"{pointer} is nested inside artifacts[{parent}]; a member of a container "
                            "is not a file in the scanned tree")
        location = artifact.get("location")
        if not isinstance(location, dict) or location.get("uri") is None:
            raise _Unusable(f"{pointer} has no location uri")
        own = location.get("index")
        if own is not None and own != index:
            raise _Unusable(f"{pointer}/location/index is {own!r}, not its own position {index}")
        return self._path(location["uri"], location.get("uriBaseId"), f"{pointer}/location")

    def _artifact_path(self, location: Any, label: str) -> str:
        """The path an ``artifactLocation`` names, by ``uri``, by ``index``, or by both in agreement."""
        if not isinstance(location, dict):
            raise _Unusable(f"{label} is not an artifactLocation object")
        index = location.get("index")
        if index is None:
            index = -1
        if not _is_int(index) or index < -1:
            raise _Unusable(f"{label}.index is {index!r}, not an array index")
        uri = location.get("uri")
        if index == -1:
            if uri is None:
                raise _Unusable(f"{label} has neither uri nor index (SARIF 3.4.2)")
            return self._path(uri, location.get("uriBaseId"), label)
        indexed = self._indexed_artifact(index, label)
        if uri is not None:
            named = self._path(uri, location.get("uriBaseId"), label)
            if named != indexed:
                raise _Unusable(f"{label} names {named!r} by uri and {indexed!r} by index {index}; SARIF "
                                "3.4.2 says both SHALL denote the same artifact")
        return indexed

    def _place(self, location: Any, label: str) -> _Place:
        """One ``location`` object as a path in the scanned tree and, when stated, its lines."""
        if not isinstance(location, dict):
            raise _Unusable(f"{label} is not a location object")
        physical = location.get("physicalLocation")
        if physical is None:
            if location.get("logicalLocations"):
                raise _Unusable(f"{label} has only a logical location, which names no file")
            raise _Unusable(f"{label} has no physicalLocation")
        if not isinstance(physical, dict):
            raise _Unusable(f"{label}/physicalLocation is not an object")
        if physical.get("artifactLocation") is None:
            raise _Unusable(f"{label}/physicalLocation has no artifactLocation; an address names no file")
        path = self._artifact_path(physical["artifactLocation"], f"{label}/physicalLocation/artifactLocation")
        lines, note = _region_lines(physical.get("region"), f"{label}/physicalLocation/region")
        if self.tree is not None:
            self.tree.check(path, lines, label)
        return _Place(path, lines, note)

    # -- rules --------------------------------------------------------------------------

    def _component(self, reference: Any, label: str) -> tuple[dict, str]:
        """The tool component a ``toolComponent`` reference names: by index, by guid, or the driver."""
        driver = (self.driver, f"{self.pointer}/tool/driver")
        if reference is None:
            return driver
        if not isinstance(reference, dict):
            raise _Unusable(f"{label} is not a toolComponent reference object")
        index = reference.get("index")
        if index is not None and index != -1:
            if not _is_int(index) or not 0 <= index < len(self.extensions):
                raise _Unusable(f"{label}.index {index!r} names no element of tool.extensions "
                                f"({len(self.extensions)} present)")
            return self.extensions[index], f"{self.pointer}/tool/extensions/{index}"
        guid = reference.get("guid")
        if guid is not None:
            matches = self._component_guids.get(guid, []) if isinstance(guid, str) else []
            if len(matches) != 1:
                raise _Unusable(f"{label}.guid {guid!r} names {len(matches)} tool components, not one")
            return matches[0]
        return driver

    def _rules_by_id(self, component: dict, pointer: str) -> dict[str, list[int]]:
        if pointer not in self._rule_ids:
            table: dict[str, list[int]] = {}
            for index, descriptor in enumerate(component.get("rules") or []):
                if isinstance(descriptor, dict) and _text(descriptor.get("id")):
                    table.setdefault(descriptor["id"], []).append(index)
            self._rule_ids[pointer] = table
        return self._rule_ids[pointer]

    def _rules_by_guid(self, component: dict, pointer: str) -> dict[str, list[int]]:
        """Where each ``guid`` sits among *component*'s rule descriptors, built once per component.

        Every position is kept, not the first, because how many descriptors carry a guid is what a
        reference by it reports when it is ambiguous. A guid is a string, as SARIF defines it, and
        a descriptor whose guid is not one is never named by a reference.
        """
        if pointer not in self._rule_guids:
            table: dict[str, list[int]] = {}
            for index, descriptor in enumerate(component.get("rules") or []):
                if isinstance(descriptor, dict) and isinstance(descriptor.get("guid"), str):
                    table.setdefault(descriptor["guid"], []).append(index)
            self._rule_guids[pointer] = table
        return self._rule_guids[pointer]

    def _rule(self, result: dict, label: str) -> _Rule:
        """The rule *result* names, located as SARIF 3.52.3 says, and matched by id where it cannot be.

        ``ruleId`` and ``rule.id`` must agree, and so must ``ruleIndex`` and ``rule.index``. The
        component is the one ``rule.toolComponent`` names, else the driver; within it the
        descriptor is found by index, else by guid, else, for producers such as Semgrep that name a
        rule by id alone, by a whole-id match or the id less one trailing hierarchical component.
        A found descriptor must carry an id the reference names (SARIF 3.52.4). A result naming no
        rule at all, or an id no descriptor carries, has no descriptor, which is not a loss. A guid
        and an id are each looked up in a table built once for the component, not by reading its
        rules again for every result that names one.
        """
        rule_id = result.get("ruleId")
        if rule_id is not None and not _text(rule_id):
            raise _Unusable(f"{label}/ruleId is not a non-empty string")
        reference = result.get("rule")
        if reference is not None and not isinstance(reference, dict):
            raise _Unusable(f"{label}/rule is not a reportingDescriptorReference object")
        reference = reference or {}
        reference_id = reference.get("id")
        if reference_id is not None and not _text(reference_id):
            raise _Unusable(f"{label}/rule/id is not a non-empty string")
        if rule_id is not None and reference_id is not None and rule_id != reference_id:
            raise _Unusable(f"{label} carries ruleId {rule_id!r} and rule.id {reference_id!r}, which "
                            "SARIF 3.27.7 says SHALL be equal")
        identity = reference_id if reference_id is not None else rule_id
        indices = []
        for key, value in (("ruleIndex", result.get("ruleIndex")), ("rule/index", reference.get("index"))):
            if value is None or value == -1:
                continue
            if not _is_int(value) or value < 0:
                raise _Unusable(f"{label}/{key} is {value!r}, not an array index")
            indices.append(value)
        if len(set(indices)) > 1:
            raise _Unusable(f"{label} carries ruleIndex {indices[0]} and rule.index {indices[1]}, which "
                            "SARIF 3.27.7 says SHALL be equal")
        component, component_pointer = self._component(reference.get("toolComponent"),
                                                        f"{label}/rule/toolComponent")
        rules = component.get("rules") or []
        guid = reference.get("guid")
        position: int | None = None
        if indices:
            position = indices[0]
            if position >= len(rules):
                raise _Unusable(f"{label} names rule index {position}, and {component_pointer}/rules "
                                f"holds {len(rules)}")
            if guid is not None and isinstance(rules[position], dict) and rules[position].get("guid") != guid:
                raise _Unusable(f"{label} names one rule by index and another by guid")
        elif guid is not None:
            matches = self._rules_by_guid(component, component_pointer).get(guid, []) if isinstance(guid, str) else []
            if len(matches) != 1:
                raise _Unusable(f"{label}/rule/guid {guid!r} names {len(matches)} rules in "
                                f"{component_pointer}, not one")
            position = matches[0]
        elif identity is not None:
            by_id = self._rules_by_id(component, component_pointer)
            matches = by_id.get(identity) or (by_id.get(identity.rsplit("/", 1)[0], [])
                                              if "/" in identity else [])
            if len(matches) > 1:
                raise _Unusable(f"{label} names rule {identity!r}, which {len(matches)} descriptors in "
                                f"{component_pointer} share, and carries no index or guid to choose "
                                "between them")
            position = matches[0] if matches else None
        if position is None:
            return _Rule(identity, identity, None, component, None)
        descriptor = rules[position]
        pointer = f"{component_pointer}/rules/{position}"
        if not isinstance(descriptor, dict) or not _text(descriptor.get("id")):
            raise _Unusable(f"{pointer} is not a rule descriptor with an id")
        if identity is not None and not _names(descriptor["id"], identity):
            raise _Unusable(f"{label} names rule {identity!r}, which is neither descriptor "
                            f"{descriptor['id']!r} at {pointer} nor a narrowing of it (SARIF 3.52.4)")
        return _Rule(identity, descriptor["id"], descriptor, component, pointer)

    def _cwe_taxonomy(self, reference: Any) -> bool:
        """Whether a ``toolComponent`` reference names the CWE taxonomy.

        SARIF 3.54.2 locates components only among the driver and extensions, while its own
        taxonomy examples point into ``run.taxonomies``; a reference is read against
        ``run.taxonomies`` by guid, then index, then name, and failing all three by its own name.
        A guid or name is a string, and is looked up in the table built once for the run.
        """
        if not isinstance(reference, dict):
            return False
        found = None
        guid, index, name = reference.get("guid"), reference.get("index"), reference.get("name")
        if isinstance(guid, str):
            found = self._taxonomy_by["guid"].get(guid)
        if found is None and _is_int(index) and 0 <= index < len(self.taxonomies):
            found = self.taxonomies[index] if isinstance(self.taxonomies[index], dict) else None
        if found is None and isinstance(name, str):
            found = self._taxonomy_by["name"].get(name)
        label = found.get("name") if found is not None else name
        return isinstance(label, str) and label.strip().upper() == "CWE"

    def _taxon_cwe(self, reference: Any) -> str | None:
        if not isinstance(reference, dict) or not self._cwe_taxonomy(reference.get("toolComponent")):
            return None
        return _cwe_token(reference.get("id"))

    def _descriptor_cwe_ids(self, rule: _Rule) -> tuple[list[str], list[str]]:
        """The CWE ids a descriptor gives every result of its rule: from its relationships, then its tags.

        Read once per descriptor, however many results name it: what a descriptor lists does not
        depend on the result, and a rule with thousands of relationships used by thousands of
        results was read thousands of times over.
        """
        if rule.pointer not in self._descriptor_cwes:
            descriptor = rule.descriptor
            related: list[str | None] = []
            relationships = descriptor.get("relationships") if descriptor else None
            for relationship in relationships if isinstance(relationships, list) else []:
                if not isinstance(relationship, dict):
                    continue
                kinds = relationship.get("kinds", ["relevant"])
                if isinstance(kinds, list) and {"superset", "equal"} & {kind for kind in kinds if isinstance(kind, str)}:
                    related.append(self._taxon_cwe(relationship.get("target")))
            self._descriptor_cwes[rule.pointer] = (list(dict.fromkeys(cwe for cwe in related if cwe)),
                                                   cwe_ids(_tags(descriptor)))
        return self._descriptor_cwes[rule.pointer]

    def _cwes(self, rule: _Rule, result: dict) -> list[str]:
        """CWE ids for one result: the rule's CWE relationships, the result's taxa, then tags.

        A rule relationship counts only when its kinds include ``superset`` or ``equal``, which
        SARIF 3.27.8 says place every result of the rule in the taxon; any narrower relationship
        applies to a result only through that result's own ``taxa``. Tags follow, rule then
        result, through :func:`scaneval.kinds.cwe_ids`, which reads ``CWE-89`` and
        ``external/cwe/cwe-089`` alike. Each id is listed once, in the order found, which is the
        order ``native_cwe`` keeps; :func:`scaneval.kinds.kind_for_cwes` reads them in its own order.
        """
        related, tagged = self._descriptor_cwe_ids(rule)
        found: list[str | None] = list(related)
        taxa = result.get("taxa")
        for reference in taxa if isinstance(taxa, list) else []:
            found.append(self._taxon_cwe(reference))
        found.extend(tagged)
        found.extend(cwe_ids(_tags(result)))
        return list(dict.fromkeys(cwe for cwe in found if cwe))

    # -- one result ---------------------------------------------------------------------

    def _suppression(self, result: dict, label: str) -> tuple[dict, bool]:
        value = result.get("suppressions")
        if value is None:
            return {"state": "unavailable", "entries": []}, False
        if not isinstance(value, list):
            raise _Unusable(f"{label}/suppressions is not an array")
        if not value:
            return {"state": "none", "entries": []}, False
        entries = []
        for index, item in enumerate(value):
            if not isinstance(item, dict):
                raise _Unusable(f"{label}/suppressions/{index} is not a suppression object")
            status = item.get("status")
            if status is not None and status not in SUPPRESSION_STATUSES:
                raise _Unusable(f"{label}/suppressions/{index}/status {status!r} is not a SARIF "
                                "suppression status")
            entries.append({"kind": _text(item.get("kind")), "status": status})
        suppressed = not any(entry["status"] in _UNSUPPRESSING for entry in entries)
        return {"state": "suppressed" if suppressed else "not_suppressed", "entries": entries}, suppressed

    def _level(self, result: dict, rule: _Rule, label: str, notes: list[str], kind: str) -> str:
        """``result.level``, else the rule's ``defaultConfiguration.level``, else ``warning``.

        This is the chain SARIF 3.27.10 intends for a ``fail`` result; an invocation's rule
        configuration overrides are not read. A ``review`` or ``open`` result has no severity of
        its own, so its level is its stated one or ``none``.
        """
        level = result.get("level")
        if level is not None:
            if level not in LEVELS:
                raise _Unusable(f"{label}/level {level!r} is not a SARIF level")
            if kind != "fail" and level != "none":
                notes.append(f"a {kind} result carries level {level!r}; SARIF 3.27.10 expects none")
            return level
        if kind != "fail":
            return "none"
        configuration = rule.descriptor.get("defaultConfiguration") if rule.descriptor else None
        default = configuration.get("level") if isinstance(configuration, dict) else None
        if default is None:
            return "warning"
        if default not in LEVELS:
            notes.append(f"{rule.pointer}/defaultConfiguration/level {default!r} is not a SARIF level; "
                         "the default warning applies")
            return "warning"
        return default

    def _step(self, step: Any, pointer: str, rule: _Rule, losses: list[dict]) -> tuple[str, str | None]:
        """``(where, message)`` rendering one ``threadFlowLocation``; what fails is an evidence loss."""
        try:
            step = self._thread_flow_location(step, pointer)
        except _Unusable as exc:
            losses.append({"pointer": pointer, "reason": str(exc)})
            return "(unresolved location)", None
        location = step.get("location")
        if location is None:
            return "(no location)", None
        try:
            where = self._place(location, f"{pointer}/location").label()
        except _Unusable as exc:
            losses.append({"pointer": f"{pointer}/location", "reason": str(exc)})
            where = "(unresolved location)"
        message = location.get("message") if isinstance(location, dict) else None
        if message is None:
            return where, None
        try:
            text = _message_text(message, f"{pointer}/location/message", descriptor=None,
                                 component=rule.component)
        except _Unusable as exc:
            losses.append({"pointer": f"{pointer}/location/message", "reason": str(exc)})
            return where, None
        return where, " ".join(_LINE_BREAK.split(text.strip())) or None

    def _thread_flow_location(self, step: Any, pointer: str) -> dict:
        """*step*, with the properties of the cached object its ``index`` names (SARIF 3.38.2)."""
        if not isinstance(step, dict):
            raise _Unusable(f"{pointer} is not a threadFlowLocation object")
        index = step.get("index")
        if index is None or index == -1:
            return step
        if not _is_int(index) or not 0 <= index < len(self.thread_flow_locations):
            raise _Unusable(f"{pointer}/index {index!r} names no element of run.threadFlowLocations "
                            f"({len(self.thread_flow_locations)} present)")
        cached = self.thread_flow_locations[index]
        if not isinstance(cached, dict):
            raise _Unusable(f"{self.pointer}/threadFlowLocations/{index} is not a threadFlowLocation object")
        for key, value in step.items():
            if key != "index" and key in cached and cached[key] != value:
                raise _Unusable(f"{pointer} disagrees with the cached {self.pointer}/threadFlowLocations/"
                                f"{index} on {key} (SARIF 3.38.2)")
        return {**cached, **step}

    def _first_step(self, flow: Any, pointer: str) -> tuple:
        """What identifies where one code flow starts: its first step's resolved location."""
        try:
            threads = flow.get("threadFlows") if isinstance(flow, dict) else None
            steps = threads[0].get("locations") if isinstance(threads, list) and threads and isinstance(threads[0], dict) else None
            if not isinstance(steps, list) or not steps:
                raise _Unusable("no first step")
            step = self._thread_flow_location(steps[0], pointer)
            place = self._place(step.get("location"), pointer)
            return ("at", place.path, place.lines)
        except _Unusable:
            # A start that cannot be placed cannot be shown to be the same as another one.
            return ("unresolved", pointer)

    def _flows(self, result: dict, label: str, rule: _Rule, losses: list[dict]) -> tuple[str | None, bool]:
        """Evidence text rendered from ``codeFlows`` in execution order, and whether their starts differ.

        Each step is one line, ``flow i, thread j, step k: path:line message``, numbered from 1 in
        array order, which SARIF 3.37.6 makes the execution order. Rendering stops at
        :data:`FLOW_STEP_LIMIT` steps or :data:`FLOW_TEXT_LIMIT` bytes; the steps past it are
        counted and recorded as an evidence loss. Several flows are not split into several claims
        (a result with several paths to one sink is one allegation), but flows that start at
        different places may be separate allegations bundled into one result, so they are flagged.
        """
        flows = result.get("codeFlows")
        if flows is None:
            return None, False
        if not isinstance(flows, list):
            losses.append({"pointer": f"{label}/codeFlows", "reason": "codeFlows is not an array; no flow "
                           "was rendered"})
            return None, False
        lines: list[str] = []
        size = rendered = total = 0
        for flow_index, flow in enumerate(flows):
            flow_pointer = f"{label}/codeFlows/{flow_index}"
            threads = flow.get("threadFlows") if isinstance(flow, dict) else None
            if not isinstance(threads, list) or not threads:
                losses.append({"pointer": flow_pointer, "reason": "a codeFlow without a threadFlows array; "
                               "nothing of it was rendered"})
                continue
            for thread_index, thread in enumerate(threads):
                thread_pointer = f"{flow_pointer}/threadFlows/{thread_index}"
                steps = thread.get("locations") if isinstance(thread, dict) else None
                if not isinstance(steps, list) or not steps:
                    losses.append({"pointer": thread_pointer, "reason": "a threadFlow without a locations "
                                   "array; nothing of it was rendered"})
                    continue
                for step_index, step in enumerate(steps):
                    total += 1
                    if rendered >= FLOW_STEP_LIMIT or size >= FLOW_TEXT_LIMIT:
                        continue
                    where, message = self._step(step, f"{thread_pointer}/locations/{step_index}", rule, losses)
                    line = (f"flow {flow_index + 1}, thread {thread_index + 1}, step {step_index + 1}: "
                            f"{where}" + (f" {message}" if message else ""))
                    cost = len(line.encode("utf-8")) + 1
                    if size + cost > FLOW_TEXT_LIMIT:
                        size = FLOW_TEXT_LIMIT
                        continue
                    lines.append(line)
                    size += cost
                    rendered += 1
        if total > rendered:
            lines.append(f"({total - rendered} more flow step(s) not rendered; the raw artifact keeps them)")
            losses.append({"pointer": f"{label}/codeFlows", "reason": f"{total - rendered} of {total} flow "
                           f"steps were not rendered: evidence text stops at {FLOW_STEP_LIMIT} steps or "
                           f"{FLOW_TEXT_LIMIT} bytes"})
        starts = {self._first_step(flow, f"{label}/codeFlows/{index}") for index, flow in enumerate(flows)}
        return ("\n".join(lines) if lines else None), len(starts) > 1

    def _location_ids(self, result: dict) -> dict[int, int]:
        """How many location objects in *result* carry each ``id`` (SARIF 3.28.2)."""
        found: list[Any] = []
        for key in ("locations", "relatedLocations"):
            value = result.get(key)
            found.extend(value if isinstance(value, list) else [])
        flows = result.get("codeFlows")
        for flow in flows if isinstance(flows, list) else []:
            threads = flow.get("threadFlows") if isinstance(flow, dict) else None
            for thread in threads if isinstance(threads, list) else []:
                steps = thread.get("locations") if isinstance(thread, dict) else None
                for step in steps if isinstance(steps, list) else []:
                    try:
                        found.append(self._thread_flow_location(step, "").get("location"))
                    except _Unusable:
                        continue
        stacks = result.get("stacks")
        for stack in stacks if isinstance(stacks, list) else []:
            frames = stack.get("frames") if isinstance(stack, dict) else None
            for frame in frames if isinstance(frames, list) else []:
                found.append(frame.get("location") if isinstance(frame, dict) else None)
        counts: dict[int, int] = {}
        for location in found:
            identifier = location.get("id") if isinstance(location, dict) else None
            if _is_int(identifier) and identifier >= 0:
                counts[identifier] = counts.get(identifier, 0) + 1
        return counts

    def _link_losses(self, allegation: str, result: dict, label: str) -> list[dict]:
        """An evidence loss for each embedded link (``[text](n)``) that names no single location.

        A link of more than :data:`_MAX_DIGITS` digits names no location this import looks for, and
        is one loss however many there are.
        """
        digits = {match.group(1) for match in _LINK.finditer(allegation)}
        numbers = {_bounded_int(item) for item in digits}
        links = sorted(number for number in numbers if number is not None)
        counts = self._location_ids(result) if links else {}
        losses = [{"pointer": f"{label}/message", "reason": f"the message links to location id {link}, and "
                   f"the result holds {counts.get(link, 0)} location(s) with that id, not exactly one "
                   "(SARIF 3.11.6)"}
                  for link in links if counts.get(link, 0) != 1]
        if None in numbers:
            losses.append({"pointer": f"{label}/message", "reason": "the message links to a location id of "
                           f"more than {_MAX_DIGITS} digits, which this import does not look for (SARIF 3.11.6)"})
        return losses

    def convert(self, index: int, result: Any) -> tuple[str, dict, dict | None]:
        """``("claim", claim, entry)``, ``("excluded", exclusion, None)`` or ``("loss", loss, None)``.

        Results are read in order while the claims they make hold at most :data:`RUN_TEXT_BUDGET`
        characters of allegation and evidence text. The first result whose claim would take the
        total past it is a loss, and so is every result after it, which is not read at all: no
        result is dropped in silence, and none can make the run cost more than the budget allows.
        """
        pointer = f"{self.pointer}/results/{index}"
        if self._budget_reason is not None:
            return "loss", {"pointer": pointer, "reason": self._budget_reason}, None
        try:
            outcome = self._convert(index, pointer, result)
        except _Unusable as exc:
            return "loss", {"pointer": pointer, "reason": str(exc)}, None
        except RecursionError:
            return "loss", {"pointer": pointer, "reason": f"{pointer} nests too deeply to read"}, None
        except SarifImportError:
            # A refusal of the whole log is not one result's loss, though it is a ValueError too.
            raise
        except ValueError as exc:
            # Whatever else a hostile value turns into, one result never ends the import.
            return "loss", {"pointer": pointer,
                            "reason": f"{pointer} could not be read: {type(exc).__name__}: {exc}"[:300]}, None
        if outcome[0] == "claim":
            size = len(outcome[1]["allegation"]) + len(outcome[1].get("evidence_text", ""))
            if self._text_used + size > RUN_TEXT_BUDGET:
                self._budget_reason = (
                    f"reading {pointer} would take the run's claim text (allegations and evidence text) past "
                    f"its budget of {RUN_TEXT_BUDGET} characters, so that result and every later one are not "
                    "read; the raw artifact keeps them")
                return "loss", {"pointer": pointer, "reason": self._budget_reason}, None
            self._text_used += size
        return outcome

    def _convert(self, index: int, pointer: str, result: Any) -> tuple[str, dict, dict | None]:
        if not isinstance(result, dict):
            raise _Unusable(f"{pointer} is a {type(result).__name__}, not a result object")
        kind = result.get("kind")
        kind = "fail" if kind is None else kind
        if kind in EXCLUDED_KINDS:
            return "excluded", {"pointer": pointer, "reason": f"kind:{kind}"}, None
        if kind not in CLAIMED_KINDS:
            raise _Unusable(f"{pointer}/kind {kind!r} is not a SARIF result kind")
        baseline = result.get("baselineState")
        if baseline is not None and baseline not in BASELINE_STATES:
            raise _Unusable(f"{pointer}/baselineState {baseline!r} is not a SARIF baseline state")
        if baseline == "absent":
            return "excluded", {"pointer": pointer, "reason": "baseline:absent"}, None
        suppression, suppressed = self._suppression(result, pointer)
        if suppressed and not self.include_suppressed:
            return "excluded", {"pointer": pointer, "reason": "suppressed", "suppression": suppression}, None

        rule = self._rule(result, pointer)
        notes: list[str] = []
        level = self._level(result, rule, pointer, notes, kind)
        if result.get("message") is None:
            raise _Unusable(f"{pointer} has no message, which SARIF 3.27.11 requires")
        allegation = _message_text(result["message"], f"{pointer}/message", descriptor=rule.descriptor,
                                   component=rule.component).strip()
        if not allegation:
            raise _Unusable(f"{pointer}/message resolves to blank text")
        locations = result.get("locations")
        if locations is not None and not isinstance(locations, list):
            raise _Unusable(f"{pointer}/locations is a {type(locations).__name__}, not an array")
        if not locations:
            raise _Unusable(f"{pointer} has no locations, so there is no file to place a claim in")
        primary = self._place(locations[0], f"{pointer}/locations/0")
        if primary.note:
            notes.append(f"primary location: {primary.note}")

        evidence_losses: list[dict] = []
        related: list[dict] = []
        bundle_review: list[str] = []
        if len(locations) > 1:
            bundle_review.append(MULTIPLE_LOCATIONS)
        extra = [(f"{pointer}/locations/{number}", location)
                 for number, location in enumerate(locations) if number]
        related_locations = result.get("relatedLocations")
        if related_locations is not None and not isinstance(related_locations, list):
            evidence_losses.append({"pointer": f"{pointer}/relatedLocations",
                                    "reason": "relatedLocations is not an array; none was recorded"})
        elif related_locations:
            extra += [(f"{pointer}/relatedLocations/{number}", location)
                      for number, location in enumerate(related_locations)]
        for location_pointer, location in extra:
            try:
                related.append(self._place(location, location_pointer).location())
            except _Unusable as exc:
                evidence_losses.append({"pointer": location_pointer, "reason": str(exc)})
        evidence, divergent = self._flows(result, pointer, rule, evidence_losses)
        if divergent:
            bundle_review.append(DIVERGENT_CODE_FLOWS)
        evidence_losses.extend(self._link_losses(allegation, result, pointer))

        cwes = self._cwes(rule, result)
        if rule.descriptor is None and rule.reference is not None:
            notes.append(f"no rule descriptor matches {rule.reference!r}; the level and CWE ids come from "
                         "the result alone")
        severity = level if kind == "fail" else kind
        security = _security_severity(rule.descriptor)
        if kind == "fail" and security is not None:
            severity = f"{level}; security-severity {security}"
        claim: dict[str, Any] = {
            "claim_id": f"r{self.run_index}-{index}",
            "allegation": allegation,
            "kind": kind_for_cwes(cwes),
            "primary_location": primary.location(),
            "native_severity": severity,
            "raw_artifact_id": ARTIFACT_ID,
        }
        if rule.native_id is not None:
            claim["native_rule_id"] = rule.native_id
        if _text(result.get("guid")):
            claim["native_id"] = result["guid"]
        if cwes:
            claim["native_cwe"] = cwes
        if evidence is not None:
            claim["evidence_text"] = evidence
        if related:
            claim["related_locations"] = related
        entry = {
            "claim_id": claim["claim_id"], "pointer": pointer, "rule_id": rule.reference,
            "descriptor": rule.pointer, "kind": kind, "level": level,
            "fingerprints": _fingerprints(result.get("fingerprints"), f"{pointer}/fingerprints", notes),
            "partial_fingerprints": _fingerprints(result.get("partialFingerprints"),
                                                  f"{pointer}/partialFingerprints", notes),
            "suppression": suppression, "baseline_state": baseline, "bundle_review": bundle_review,
            "evidence_losses": evidence_losses, "notes": notes,
        }
        return "claim", claim, entry

    # -- the run's own account of its execution -------------------------------------------

    def _notification_ids(self, component: dict, pointer: str) -> dict[str, dict[str, list[int]]]:
        """Where each ``id`` and ``guid`` sits among *component*'s notification descriptors, built once.

        At most two positions are kept for a value: two descriptors that share one already make a
        reference by it ambiguous, and no log can make a lookup cost more than that.
        """
        if pointer not in self._notification_tables:
            table: dict[str, dict[str, list[int]]] = {"id": {}, "guid": {}}
            for position, descriptor in enumerate(component.get("notifications") or []):
                for key, positions in table.items():
                    value = descriptor.get(key) if isinstance(descriptor, dict) else None
                    if _text(value):
                        found = positions.setdefault(value, [])
                        if len(found) < 2:
                            found.append(position)
            self._notification_tables[pointer] = table
        return self._notification_tables[pointer]

    def _notification_descriptor(self, reference: Any) -> tuple[tuple[str, int], dict]:
        """The notification descriptor *reference* names and where it sits, or why it names none.

        Found as SARIF 3.52 finds a descriptor: in the component ``toolComponent`` names, else
        the driver, by ``index``, else by ``guid``, else by ``id``; every other one of the three that
        the reference states must agree with the descriptor found. A value no descriptor carries,
        one that two carry, and a reference that states none of the three name nothing.
        """
        if not isinstance(reference, dict):
            raise _Unusable("descriptor is not a reportingDescriptorReference object")
        component, pointer = self._component(reference.get("toolComponent"), "descriptor")
        descriptors = component.get("notifications") or []
        table = self._notification_ids(component, pointer)
        index, guid, identifier = reference.get("index"), reference.get("guid"), reference.get("id")
        if index is not None and index != -1:
            found = [index] if _is_int(index) and 0 <= index < len(descriptors) else []
        elif guid is not None:
            found = table["guid"].get(guid, []) if isinstance(guid, str) else []
        elif identifier is not None:
            found = table["id"].get(identifier, []) if isinstance(identifier, str) else []
        else:
            raise _Unusable("descriptor states none of index, guid, and id")
        descriptor = descriptors[found[0]] if len(found) == 1 else None
        if not isinstance(descriptor, dict) or any(
                value is not None and descriptor.get(key) != value for key, value in (("guid", guid), ("id", identifier))):
            stated = ", ".join(f"{key} {_shown(value)}" for key, value in
                               (("index", index), ("guid", guid), ("id", identifier)) if value is not None)
            raise _Unusable(f"descriptor with {stated} names no single notification descriptor of {pointer}")
        return (pointer, found[0]), descriptor

    def _override_levels(self, overrides: Any) -> dict[tuple[str, int], set[str | None]]:
        """The levels an invocation's ``notificationConfigurationOverrides`` set, by the descriptor each names.

        An entry configures one notification descriptor for this invocation, and only its ``level``
        is read; a level that is not a SARIF level is kept as ``None``, which cannot be read. An
        entry that is not an object, or whose descriptor reference names no single descriptor, could
        configure any notification, so the whole set is refused with :class:`_Unusable`.
        """
        if overrides is None:
            return {}
        if not isinstance(overrides, list):
            raise _Unusable("notificationConfigurationOverrides is not an array")
        levels: dict[tuple[str, int], set[str | None]] = {}
        for number, entry in enumerate(overrides):
            where = f"notificationConfigurationOverrides/{number}"
            if not isinstance(entry, dict):
                raise _Unusable(f"{where} is not a configurationOverride object")
            try:
                position, _ = self._notification_descriptor(entry.get("descriptor"))
            except _Unusable as exc:
                raise _Unusable(f"{where}: {exc}") from None
            configuration = entry.get("configuration")
            level = configuration.get("level") if isinstance(configuration, dict) else None
            if not isinstance(configuration, dict) or level is not None:
                levels.setdefault(position, set()).add(level if level in LEVELS else None)
        return levels

    def _notification_level(self, notification: Any, overrides: dict | _Unusable) -> str:
        """A notification's level (SARIF 3.58.6), or why the log leaves it unreadable.

        The notification's own ``level`` comes first. Without one, its descriptor is looked up, and
        the level is what the invocation's ``notificationConfigurationOverrides`` (*overrides*) give
        that descriptor, else the descriptor's ``defaultConfiguration.level``, else ``warning``. A
        notification that names no descriptor has nothing to configure it and is at ``warning``.
        Nothing unreadable is read as ``warning``: a level that is not one of SARIF's four, a
        descriptor the log does not hold or names ambiguously, and overrides that cannot be told
        apart raise :class:`_Unusable`, so the evidence is ``unreported`` and a quiet control earns
        nothing on a guess.
        """
        if not isinstance(notification, dict):
            raise _Unusable("it is not a notification object")
        level = notification.get("level")
        if level is not None:
            if level not in LEVELS:
                raise _Unusable(f"its level {_shown(level)} is not a SARIF level")
            return level
        reference = notification.get("descriptor")
        if reference is None:
            return "warning"
        position, descriptor = self._notification_descriptor(reference)
        if isinstance(overrides, _Unusable):
            raise _Unusable(str(overrides))
        configured = overrides.get(position)
        if configured:
            if None in configured or len(configured) > 1:
                raise _Unusable(f"the overrides for {position[0]}/notifications/{position[1]} do not give one "
                                "readable level (a level that is not a SARIF level, a configuration that "
                                "is not an object, or levels that disagree)")
            return next(iter(configured))
        configuration = descriptor.get("defaultConfiguration")
        default = configuration.get("level") if isinstance(configuration, dict) else None
        if default is None:
            return "warning"
        if default not in LEVELS:
            raise _Unusable(f"its descriptor's default level {_shown(default)} is not a SARIF level")
        return default

    def execution(self) -> tuple[dict, list[str], list[str]]:
        """The log's own account of execution, notes on reading it, and where it reports failure.

        ``reported_failed`` when any invocation says ``executionSuccessful: false``, carries a tool
        execution or configuration notification at level ``error`` (SARIF 3.20.21-22), or names a
        signal that ended the process or a failure to start it (``exitSignalName``,
        ``processStartFailureMessage``), even beside ``executionSuccessful: true``.
        ``unreported`` when there is no invocation, or one that says nothing this can read about how
        it ended, a notification whose level is unreadable (:meth:`_notification_level`) included.
        ``reported_success`` otherwise. None of these is verified: nothing here watched the tool run.
        The last value is the pointer of every invocation reported failed.
        """
        rows: list[dict] = []
        notes: list[str] = []
        failed_at: list[str] = []
        unknown = False
        for index, invocation in enumerate(self.invocations):
            pointer = f"{self.pointer}/invocations/{index}"
            if not isinstance(invocation, dict):
                unknown = True
                notes.append(f"{pointer} is not an invocation object; it reports nothing readable")
                rows.append({"pointer": pointer, "execution_successful": None, "exit_code": None,
                             "exit_signal_name": None, "notifications": 0, "error_notifications": []})
                continue
            failed = False
            succeeded = invocation.get("executionSuccessful")
            if not isinstance(succeeded, bool):
                unknown = True
                notes.append(f"{pointer} has no boolean executionSuccessful, which SARIF 3.20.14 requires")
                succeeded = None
            elif not succeeded:
                failed = True
            stopped = []
            for key in ("exitSignalName", "processStartFailureMessage"):
                value = invocation.get(key)
                if value is None or value == "":
                    continue
                if not isinstance(value, str):
                    unknown = True
                    notes.append(f"{pointer}/{key} is not a string; whether the process was stopped cannot be read")
                else:
                    stopped.append(f"{key} {_shown(value)}")
            if stopped:
                failed = True
                notes.append(f"{pointer} reports {' and '.join(stopped)}, so the tool did not run to completion")
            count = 0
            errors: list[str] = []
            try:
                overrides: dict | _Unusable = self._override_levels(invocation.get("notificationConfigurationOverrides"))
            except _Unusable as exc:
                overrides = exc
            for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
                notifications = invocation.get(key)
                if notifications is None:
                    continue
                if not isinstance(notifications, list):
                    unknown = True
                    notes.append(f"{pointer}/{key} is not an array; whether it reports an error cannot be read")
                    continue
                for number, notification in enumerate(notifications):
                    count += 1
                    try:
                        level = self._notification_level(notification, overrides)
                    except _Unusable as exc:
                        unknown = True
                        notes.append(f"{pointer}/{key}/{number} has no readable level: {exc}")
                    else:
                        if level == "error":
                            errors.append(f"{pointer}/{key}/{number}")
            if errors:
                failed = True
            if failed:
                failed_at.append(pointer)
            exit_code = invocation.get("exitCode")
            rows.append({"pointer": pointer, "execution_successful": succeeded,
                         "exit_code": exit_code if _is_int(exit_code) else None,
                         "exit_signal_name": _text(invocation.get("exitSignalName")),
                         "notifications": count, "error_notifications": errors})
        evidence = "reported_failed" if failed_at else "unreported" if unknown or not rows else "reported_success"
        return {"evidence": evidence, "results": "absent" if self.results is None else "present",
                "verified": False, "invocations": rows}, notes, failed_at

    def tool(self) -> dict:
        def component(value: dict) -> dict:
            return {key: _text(value.get(key)) for key in ("name", "version", "semanticVersion", "organization")}

        return {**component(self.driver), "extensions": [component(item) for item in self.extensions]}


def _security_severity(descriptor: dict | None) -> str | None:
    """A rule's ``security-severity`` property (a GitHub convention, not SARIF), as written."""
    properties = descriptor.get("properties") if descriptor else None
    value = properties.get("security-severity") if isinstance(properties, dict) else None
    if isinstance(value, str) and value.strip():
        return value.strip()
    if _is_int(value) or (isinstance(value, float) and math.isfinite(value)):
        return json.dumps(value)
    return None


def _fingerprints(value: Any, label: str, notes: list[str]) -> dict | None:
    """A result's fingerprints as provenance, with a withheld value recorded as ``None``.

    These are never a claim's identity: exact-duplicate identity is the canonical claim payload,
    and a producer's fingerprint may be per location, per rule, or withheld altogether.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        notes.append(f"{label} is not an object and was not recorded")
        return None
    recorded: dict[str, str | None] = {}
    for name in sorted(value):
        item = value[name]
        if item == UNAVAILABLE_FINGERPRINT:
            recorded[name] = None
        elif isinstance(item, str):
            recorded[name] = item
        else:
            notes.append(f"{label}[{name!r}] is not a string and was not recorded")
    return recorded


def convert_run(log: dict, run_index: int | None = None, *, settings: UriSettings | None = None,
                tree: SourceTree | None = None, include_suppressed: bool = False) -> Conversion:
    """Turn every result of one run of *log* into a claim, an exclusion, or a loss.

    The run is chosen by :func:`select_run`, which refuses a log this profile cannot read as a
    whole. *settings* says how artifact URIs map into the scanned tree (the root, and ``%SRCROOT%``
    as the root, when omitted), and *tree*, when supplied, is the exported tree every mapped path
    and line must exist in. Nothing here writes, fetches, or opens a path the log names.
    """
    index, run, count = select_run(log, run_index)
    reader = _RunReader(run, index, settings=settings or UriSettings(), tree=tree,
                        include_suppressed=include_suppressed)
    execution, notes, failed = reader.execution()
    conversion = Conversion(run_index=index, run_count=count, tool=reader.tool(), claims=[], entries=[],
                            excluded=[], losses=[], results_present=reader.results is not None,
                            execution=execution, notes=notes, failed=failed)
    for number, result in enumerate(reader.results or []):
        outcome, record, entry = reader.convert(number, result)
        if outcome == "claim":
            conversion.claims.append(record)
            conversion.entries.append(entry)
        elif outcome == "excluded":
            conversion.excluded.append(record)
        else:
            conversion.losses.append(record)
    return conversion


# --- one import: from a SARIF file to a bundle -----------------------------------------------


_NORMALIZATION_KEYS = frozenset({"artifact_sha256", "decisions"})
_DECISION_KEYS = frozenset({"pointer", "decision", "reviewer", "note", "at"})
_TREE_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def normalization_decisions(document: Any, artifact_sha256: str,
                            flagged: Mapping[str, list[str]]) -> dict:
    """The recorded bundle-review decisions in *document*, checked, as ``import.json`` embeds them.

    A normalization file is what a person recorded after reading the results this profile flags
    for bundle review: ``{"artifact_sha256": ..., "decisions": [{"pointer", "decision", "reviewer",
    "note", "at"?}]}``. It must name the artifact being imported, by its SHA-256, and each decision
    must name a result this import flagged, once. The one decision this profile accepts is
    ``atomic``: the result is one allegation and stays one claim. A result that bundles separate
    allegations is not something this importer splits, so no other decision can be recorded here.
    The reviewer is taken as written and never supplied by the tool; recording a name proves
    nothing about who read what. Anything else is refused with :class:`SarifImportError`.
    """
    if not isinstance(document, dict):
        raise SarifImportError("the normalization file is not a JSON object")
    unknown = sorted(set(document) - _NORMALIZATION_KEYS)
    missing = sorted(_NORMALIZATION_KEYS - set(document))
    if unknown or missing:
        raise SarifImportError(f"the normalization file must hold exactly artifact_sha256 and decisions "
                               f"(unknown: {', '.join(unknown) or 'none'}; missing: {', '.join(missing) or 'none'})")
    if document["artifact_sha256"] != artifact_sha256:
        raise SarifImportError(f"the normalization decisions were recorded for artifact "
                               f"{document['artifact_sha256']!r}, not this one ({artifact_sha256})")
    decisions = document["decisions"]
    if not isinstance(decisions, list):
        raise SarifImportError("the normalization file's decisions is not an array")
    recorded: list[dict] = []
    for index, decision in enumerate(decisions):
        label = f"normalization decisions[{index}]"
        if not isinstance(decision, dict):
            raise SarifImportError(f"{label} is not an object")
        unknown = sorted(set(decision) - _DECISION_KEYS)
        missing = sorted({"pointer", "decision", "reviewer", "note"} - set(decision))
        if unknown or missing:
            raise SarifImportError(f"{label} has unknown keys {unknown} or lacks {missing}")
        pointer = decision["pointer"]
        if not isinstance(pointer, str) or pointer not in flagged:
            raise SarifImportError(f"{label} names {pointer!r}, which this import did not flag for bundle "
                                   "review")
        if any(item["pointer"] == pointer for item in recorded):
            raise SarifImportError(f"{label} decides {pointer} a second time")
        if decision["decision"] != "atomic":
            raise SarifImportError(
                f"{label} records {decision['decision']!r}; only 'atomic' can be recorded, because a "
                "result that bundles separate allegations is not split by this importer")
        if not is_stated(decision["reviewer"]):
            raise SarifImportError(f"{label} names no reviewer; the tool never supplies one")
        if not is_stated(decision["note"]):
            raise SarifImportError(f"{label} states no note saying what the reviewer read")
        if "at" in decision and not is_stated(decision["at"]):
            raise SarifImportError(f"{label}.at is blank")
        recorded.append({key: decision[key] for key in sorted(decision)})
    return {"sha256": canonical_sha256(document), "decisions": recorded}


def default_run_id(artifact_sha256: str, run_index: int) -> str:
    """``import-<first 12 hex of the artifact digest>-r<run index>``: the same log, the same id."""
    return f"import-{artifact_sha256.split(':', 1)[1][:12]}-r{run_index}"


def _raw_name(path: Path) -> str:
    """The name the artifact is kept under in ``raw/``: its own name, made portable, ending ``.sarif``."""
    name = re.sub(r"[^A-Za-z0-9._-]", "-", Path(path).name).lstrip(".-") or "log"
    return name if name.endswith(".sarif") else f"{name}.sarif"


def _document(value: dict) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def _encoded(text: str, label: str) -> bytes:
    """*text* as UTF-8, refused before any file exists when it cannot be encoded."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"{label} is not UTF-8 text: {exc}") from exc


def _write_new(path: Path, payload: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(payload)


@dataclass(frozen=True)
class ImportOutcome:
    """What :func:`import_sarif` wrote: the bundle and every document in it."""

    bundle: Path
    result: dict
    record: dict
    plan: dict
    decisions: dict
    review_record: dict
    evaluation: dict


def import_sarif(sarif_path: Path, *, pack: dict, snapshot_id: str, tree_hash: str, system_id: str,
                 output: Path, run_index: int | None = None, run_id: str | None = None,
                 system_config: dict | None = None, source_dir: Path | None = None,
                 uri_bases: Mapping[str, str] | None = None, source_root_uri: str | None = None,
                 normalization: dict | None = None, include_suppressed: bool = False,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 clock: Callable[[], datetime] | None = None) -> ImportOutcome:
    """Import one run of the SARIF log at *sarif_path* into a new bundle at *output*.

    The result binds to *tree_hash*, and the plan is :func:`scaneval.cases.build_plan` for
    *snapshot_id* at that hash, which refuses a snapshot whose recorded tree hash is another one.
    *system_id* and the optional *system_config* (recorded by digest only) are the operator's
    statement of what produced the log. With *source_dir*, an exported tree that must hash to
    *tree_hash*, every mapped location is checked against it; without it the mapping is recorded
    as unverified. *normalization* is a parsed normalization file (see
    :func:`normalization_decisions`); only when it resolves every result flagged for bundle review,
    and no result was lost, are the bundles resolved.

    Everything is built and validated in memory first: a refused import, whatever refused it,
    leaves no directory behind. *output* must not exist, and the parents it lacks are created and
    removed again if the write fails; it is resolved once, so every path written is inside the same
    real directory. The run id defaults to :func:`default_run_id`. The review is a machine draft:
    every decision is ``unresolved`` and the record's state is ``draft``.
    """
    if not isinstance(tree_hash, str) or not _TREE_HASH.match(tree_hash):
        raise SarifImportError(f"the tree hash must be a sha256:<64 hex digits> digest, not {tree_hash!r}")
    if not is_stated(system_id):
        raise SarifImportError("a system id is required: say which system produced the log")
    if run_id is not None and not is_stated(run_id):
        raise SarifImportError("a run id, when given, must not be blank")
    if system_config is not None and not isinstance(system_config, dict):
        raise SarifImportError("the system configuration must be a JSON object")
    named = Path(output).expanduser()
    if named.is_symlink():
        raise SarifImportError(f"refusing to write through the symbolic link {output}")
    bundle = named.resolve()
    if bundle.exists():
        raise SarifImportError(f"{bundle} already exists; an import writes a new bundle directory")
    settings = UriSettings(uri_bases, source_root_uri)
    plan, plan_notes = cases.build_plan(pack, snapshot_id, tree_hash)
    tree = None
    if source_dir is not None:
        source = Path(source_dir).expanduser().resolve()
        if bundle == source or bundle.is_relative_to(source):
            raise SarifImportError(f"{bundle} is inside --source-dir {source}; evaluator records stay "
                                   "outside the exported tree")
        tree = SourceTree.load(source, tree_hash)

    data = read_artifact(Path(sarif_path), max_bytes)
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    log, parse_notes = parse_log(data)
    conversion = convert_run(log, run_index, settings=settings, tree=tree,
                             include_suppressed=include_suppressed)
    embedded = (None if normalization is None
                else normalization_decisions(normalization, digest, conversion.flagged))
    decided = {decision["pointer"] for decision in embedded["decisions"]} if embedded else set()
    status, error = conversion.outcome()
    bundles_resolved = (conversion.results_present and not conversion.losses
                        and set(conversion.flagged) <= decided)

    raw_path = f"{RAW_DIR}/{_raw_name(Path(sarif_path))}"
    run_id = run_id if run_id is not None else default_run_id(digest, conversion.run_index)
    result: dict[str, Any] = {
        "schema_version": "2.1", "run_id": run_id, "system_id": system_id, "input_hash": tree_hash,
        "status": status, "ranking": "unranked", "claims": conversion.claims,
        "bundles_resolved": bundles_resolved, "usage": {"wall_seconds": None},
        "raw_artifacts": [{"id": ARTIFACT_ID, "path": raw_path, "sha256": digest}],
    }
    if error is not None:
        result["error"] = error
    validate_document("scan-result", result)

    snapshot = cases.snapshot_by_id(pack, snapshot_id)
    notes = list(parse_notes) + list(conversion.notes)
    notes.append(f"Execution evidence is the log's own report ({conversion.execution['evidence']}); "
                 "nothing here observed the scan, so it is recorded as unverified.")
    if tree is None:
        notes.append("No --source-dir was supplied, so no mapped path or line was checked against the "
                     "exported tree.")
    if not snapshot.get("tree_hash"):
        notes.append(f"The pack records no tree hash for snapshot {snapshot_id}; the tree hash this "
                     "import binds to is the operator's declaration alone.")
    record = {
        "schema_version": "2.1", "profile": PROFILE, "run_id": run_id, "system_id": system_id,
        "input_hash": tree_hash, "result_sha256": canonical_sha256(result),
        "artifact": {"path": raw_path, "sha256": digest, "bytes": len(data)},
        "sarif": {"version": SARIF_VERSION, "run_index": conversion.run_index,
                  "run_count": conversion.run_count},
        "tool": conversion.tool,
        "source_binding": {"pack_sha256": cases.pack_sha256(pack), "snapshot_id": snapshot_id,
                           "tree_hash": tree_hash, "source_dir_verified": tree is not None},
        "system": {"system_id": system_id,
                   "config_sha256": None if system_config is None else canonical_sha256(system_config)},
        "versions": {"scaneval": __version__, "kind_mapping": mapping_version()},
        "execution": conversion.execution,
        "options": {"run_index": run_index, "include_suppressed": include_suppressed,
                    "uri_bases": settings.configured, "source_root_uri": source_root_uri,
                    "max_bytes": max_bytes},
        "counts": {"results": conversion.result_count, "claims": len(conversion.claims),
                   "excluded": len(conversion.excluded), "losses": len(conversion.losses),
                   "evidence_losses": sum(len(entry["evidence_losses"]) for entry in conversion.entries),
                   "bundle_review_flagged": len(conversion.flagged), "bundle_review_resolved": len(decided)},
        "claims": conversion.entries, "excluded": conversion.excluded, "losses": conversion.losses,
        "normalization": embedded, "notes": notes,
    }
    validate_document(RECORD_KIND, record)

    decisions = review.draft_decisions(plan, result, pack, clock=clock)
    review_notes = list(plan_notes) + [
        f"Imported from a saved SARIF log (profile {PROFILE}); execution evidence is the log's own "
        "and unverified."]
    record_draft = review.review_record(plan, decisions, clock=clock, notes=review_notes)
    evaluation = scoring.score(plan, result, decisions)
    report_html = report.render_report(evaluation, result, plan, review_state=record_draft["state"])
    _write_bundle(bundle, raw_path, data, result=result, record=record, plan=plan, decisions=decisions,
                  review_record=record_draft, evaluation=evaluation, report_html=report_html)
    return ImportOutcome(bundle, result, record, plan, decisions, record_draft, evaluation)


def _write_bundle(bundle: Path, raw_path: str, data: bytes, *, result: dict, record: dict, plan: dict,
                  decisions: dict, review_record: dict, evaluation: dict, report_html: str) -> None:
    """Create *bundle*, and any parent directory it lacks, and write every file into it exclusively,
    or leave nothing this call made.

    Every payload is encoded before the directory is created, so text UTF-8 cannot encode is a
    refusal rather than a half-written bundle. The evaluator files go through
    :func:`scaneval.review.write_evaluator_records`, the one writer every bundle's review files
    use. A failure part way, in making a directory as much as in writing a file, removes the files
    and the directories this call created, the parents it made included, and re-raises. A parent
    that was already there is never removed, and neither is a directory that holds anything else.
    """
    early = [(bundle / raw_path, data), (bundle / RESULT_FILE, _document(result)),
             (bundle / RECORD_FILE, _document(record))]
    late = [(bundle / "evaluation.json", _document(evaluation)),
            (bundle / "report.html", _encoded(report_html, "the report"))]
    for value, label in ((plan, "the plan"), (decisions, "the decisions"), (review_record, "the review record")):
        _encoded(canonical_json(value), label)
    missing = [bundle]
    for parent in bundle.parents:
        if parent.exists():
            break
        missing.append(parent)
    directories: list[Path] = []
    files: list[Path] = []
    try:
        for directory in reversed(missing):
            try:
                directory.mkdir()
            except FileExistsError:
                if directory == bundle:
                    raise
                continue  # made by someone else since it was looked for: not this call's to remove
            directories.append(directory)
        (bundle / RAW_DIR).mkdir()
        directories.append(bundle / RAW_DIR)
        for path, payload in early:
            _write_new(path, payload)
            files.append(path)
        directories.append(bundle / review.EVALUATOR_DIR)
        files.extend(review.write_evaluator_records(bundle, plan, decisions, review_record).values())
        for path, payload in late:
            _write_new(path, payload)
            files.append(path)
    except BaseException:
        for path in reversed(files):
            try:
                path.unlink()
            except OSError:
                pass
        for directory in reversed(directories):
            try:
                directory.rmdir()
            except OSError:
                pass
        raise
