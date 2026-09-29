"""Offline import of one saved SARIF 2.1.0 log: profile ``sarif-import-1``.

``docs/SARIF_IMPORT.md`` states the profile. This module reads a log a scanner wrote somewhere
else, at some other time, and never runs anything to produce one.

What it reads. The SARIF file the operator names, read once, as bytes, up to a stated bound, and
only when it is a regular file. Nothing a log names is ever fetched or opened: not ``$schema``,
not a rule's ``helpUri``, and not a path in a location, which is a string to map into the scanned
tree or to refuse, never a file to read. A log that declares ``externalPropertyFileReferences``
anywhere is refused whole, because its results, rules, or artifacts may live in files an offline
import will not read, and importing the part that happens to be inline would present an
incomplete run as the whole one.

Refusal is for the log as a whole. A file that cannot be read, that is larger than the bound,
whose bytes are not UTF-8, whose text is not JSON, or whose JSON repeats an object key, carries
``NaN`` or an infinity, holds a string that is not Unicode text, or nests past the interpreter's
recursion limit is refused with :class:`SarifImportError` naming what was wrong, and so is a
log whose ``version`` is not ``2.1.0``, whose ``runs`` is missing, ``null``, or empty, that holds
more than one run when no run index was named, or whose named run index is out of range. A
refusal writes nothing. What a readable log says about any one result is not a refusal of the
log; that is decided per result.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any

from .contracts import ContractError


SARIF_VERSION = "2.1.0"
# The largest artifact read by default: 64 MiB, the same bound the transcript readers keep. A
# larger log is refused rather than read part way; --max-bytes raises the bound deliberately.
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 1 << 20
# A lone UTF-16 surrogate survives JSON parsing as a string that is not Unicode text; it cannot
# be written into any record, so a log carrying one is refused rather than half written.
_SURROGATE = re.compile("[\ud800-\udfff]")


class SarifImportError(ContractError):
    """The import is refused as a whole, and nothing is written for it."""


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
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise SarifImportError(f"could not open the SARIF file {path}: {exc}") from exc
    chunks: list[bytes] = []
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise SarifImportError(f"{path} is not a regular file, so it is not read as a SARIF log")
        if info.st_size > max_bytes:
            raise SarifImportError(
                f"{path} holds {info.st_size} bytes, more than the {max_bytes}-byte bound; raise "
                "--max-bytes to import a larger log")
        total = 0
        while True:
            chunk = os.read(descriptor, min(_READ_CHUNK, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise SarifImportError(
                    f"{path} grew past the {max_bytes}-byte bound while it was read; it is not "
                    "imported in part")
    except OSError as exc:
        raise SarifImportError(f"could not read the SARIF file {path}: {exc}") from exc
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SarifImportError(f"the log repeats the object key {key!r}; which value was meant "
                                   "cannot be told")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise SarifImportError(f"the log carries the non-finite JSON number {value}, which JSON does not allow")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise SarifImportError(f"the log carries the number {text}, which overflows to infinity")
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
                raise SarifImportError("the log holds a string with a lone UTF-16 surrogate escape, "
                                       "which is not Unicode text")
        elif isinstance(value, dict):
            for key, item in value.items():
                if _SURROGATE.search(key):
                    raise SarifImportError("the log holds an object key with a lone UTF-16 surrogate "
                                           "escape, which is not Unicode text")
                pending.append(item)
        elif isinstance(value, list):
            pending.extend(value)


def parse_log(data: bytes) -> tuple[dict, list[str]]:
    """The SARIF log *data* holds, and notes on what reading it tolerated.

    Parsing is strict: bytes that are not UTF-8, text that is not JSON, a repeated object key, a
    ``NaN`` or infinity (spelled as a constant or as a number too large for a float), an integer
    literal longer than the interpreter's digit limit, nesting past the recursion limit, and a
    string that is not Unicode text are each refused with :class:`SarifImportError`. The one
    thing tolerated is a leading UTF-8 byte order mark, which RFC 8259 section 8.1 lets a parser
    ignore; it is ignored and noted, and the artifact hash still covers it. Only the document's
    shape as a JSON object is checked here: which of its fields are SARIF is read later.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SarifImportError(f"the log is not UTF-8 text: {exc}") from exc
    notes: list[str] = []
    if text.startswith("﻿"):
        text = text[1:]
        notes.append("A leading UTF-8 byte order mark was ignored (RFC 8259 section 8.1); the "
                     "artifact hash covers the bytes as supplied.")
    try:
        document = json.loads(text, object_pairs_hook=_strict_object, parse_constant=_reject_constant,
                              parse_float=_finite_float)
    except SarifImportError:
        raise
    except RecursionError as exc:
        raise SarifImportError("the log nests deeper than the JSON parser's recursion limit") from exc
    except ValueError as exc:
        raise SarifImportError(f"the log is not valid JSON: {exc}") from exc
    _refuse_non_text(document)
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
    the selected one, because the log is what is being imported and a log that points outside
    itself is not complete offline.
    """
    version = log.get("version")
    if version != SARIF_VERSION:
        raise SarifImportError(f"the log declares version {version!r}; this importer reads SARIF "
                               f"{SARIF_VERSION} only")
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
        if isinstance(run, dict) and run.get("externalPropertyFileReferences") is not None:
            raise SarifImportError(
                f"runs[{index}] declares externalPropertyFileReferences: its results, rules, or "
                "artifacts may live in files outside this log, which an offline import never reads")
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
