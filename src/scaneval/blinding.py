"""Metadata blinding: a reviewed map of identity tokens, applied to documentation and display text.

The ``metadata_blinded`` input profile (``docs/DESIGN_DECISIONS.md``, configurable identity
profiles) reduces selected identity cues in an exported snapshot: branding, documentation
identifiers, and display metadata. It never renames a package, module, import, source identifier,
or path, and never changes a dependency, executable logic, or build, CI, or security
configuration. It is partial blinding: package names and recognizable code may still reveal the
repository, and every export records which cues remain. It is not anonymization and not a defence
against memorization.

The map. A blinding map (contract kind ``blinding-map``) is evaluator-side data and never enters a
scanner workspace. It declares pseudonyms (an original token and its replacement), the snapshot
variants it covers, each pinned by commit and export tree hash, and its edits: one file each, a
stated role and rationale, the originals replaced there, and for every variant either the exact
file hash and occurrence count expected or that the file is absent. One map covers every variant
of one repository, so a vulnerable and a fixed snapshot are blinded with the same pseudonyms.

Approval. A map is applied only when its latest recorded review approves the map's content as it
stands now. Reviews are a chain (:func:`scaneval.contracts.chain_digest`, kind
``blinding_review``) whose end the map records in ``reviews_sha256``, and each review binds
:func:`content_digest`, the map without its review history. An unreviewed map, one whose latest
review rejected it or reopened the question, and one edited after the approval its latest review
recorded are all refused. The tool records the reviewer name a person supplies and never supplies
one. Like every chain in this package, this makes a quiet deletion visible; it is not a signature.

Application is all-or-nothing. Every check runs before the transformed tree exists, and a
refusal raises :class:`~scaneval.materialize.MaterializationError` naming the reason: the map is
unapproved; it is for another repository; its variant for this snapshot is missing or pinned to
another commit or export tree (a stale map); an edit names a path outside documentation and
display configuration, or a forbidden one; an expected file is missing, present when it should be
absent, or holds other bytes (stale); a file is not strict UTF-8; an original overlaps itself or
another original (ambiguous or overlapping matches); an occurrence count differs from the one
reviewed; a replacement would form an original again with the text beside it; a line would move;
or a display file would not keep its structure. Only then is the original export copied and the
reviewed occurrences replaced, and the result is verified: every file the map does not edit is
byte-identical to the original export, every file keeps its mode, every edited file keeps its line
structure, and line ``n`` of an edited file is line ``n`` of the original with the reviewed tokens
replaced. Claim locations therefore map back to the original export as the identity, which is what
lets labels written against the original score a blinded run.

Structure. A replacement is written into a file as text, without quoting, so an edit of a JSON,
TOML, INI, or YAML display file (``.json``, ``.toml``, ``.ini``, ``.cfg``, ``.yml``, ``.yaml``) is
verified against the file's own syntax before it is accepted: the file is parsed before and after,
and the result must parse to the original's value with the reviewed replacements applied to its keys
and strings and nothing else, the same keys in the same order, of the same types, nested the same
way (:func:`_check_parsed`). JSON must be strict, an original that does not parse cannot be verified,
and a replacement that makes two distinct keys equal is refused. An INI file is also read the ways
Python's ``configparser`` reads one (option names folded to lower case, ``[DEFAULT]`` merged into
each section, ``%`` and ``${}`` interpolation) and must read under each way that can read the
original as the original does (:func:`_check_ini_readings`). YAML is verified only within a strict
block subset: block mappings and sequences of one-line plain and quoted scalars, and comments.
:func:`_parse_yaml` reads it as PyYAML and ruamel.yaml (YAML 1.2 and 1.1) do, and keeps a plain scalar
that either YAML version reads as a boolean, a null, a number, or a date as the text it was written
as, so a replacement that turns a string into one is refused. A YAML file outside the subset, valid
YAML or not, cannot be verified, and its edit is refused. Documentation is not asked for structure,
and no other display file is verified.

What this does not do: parse source, discover identity cues on its own, decide whether a field is
read at runtime (a ``display_metadata`` edit carries the reviewer's stated ``role_check`` for that),
verify a structure it does not read (a comment, the whitespace between values), or establish that a
scanner cannot recognize the repository.
"""

from __future__ import annotations

import configparser
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tomllib
from typing import Any, Callable

from .contracts import (
    ContractError,
    canonical_sha256,
    chain_digest,
    is_stated,
    load_document,
    validate_document,
)
from .materialize import (
    CachedSnapshot,
    ExportedTree,
    INSTRUCTION_FILE_NAMES,
    INSTRUCTION_PATH_PREFIXES,
    INSTRUCTION_PATHS,
    INSTRUCTION_TOP_LEVEL,
    MaterializationError,
    # The export's own test of what a scanner reads as instructions. It compares exact case, so
    # :func:`_reads_as_instructions` asks it and then asks the same lists again without regard to case.
    _is_instruction_file,
    export_tree,
    provenance_record,
    sha256_file,
    tree_hash,
    walk_regular_files,
)


MAP_KIND = "blinding-map"
# The version of the map contract, and of the preparation record a blinded export writes: the
# standard record stays 2.0, and a blinded one carries fields only 2.1 defines.
SCHEMA_VERSION = "2.1"
# The chain kind of a map review, so a map review can never be replayed as a case review.
REVIEW_KIND = "blinding_review"
# Where a blinded trial keeps its original export, relative to the trial directory. Evaluator-side:
# the runner hands a scanner a copy of ``source`` only, never this.
ORIGINAL_ROOT = "original/source"
# These mirror the blinding-map contract enums; the schema stays authoritative.
EDIT_ROLES = ("documentation_identifier", "non_runtime_branding", "display_metadata")
REVIEW_ROLES = ("curator", "independent_reviewer")
REVIEW_DECISIONS = ("approve", "reject", "unresolved")
# Files any role may edit, and configuration only a display_metadata edit with a stated role check
# may edit. Everything else, source and scripts included, is never edited.
DOCUMENTATION_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".txt", ".adoc", ".asciidoc", ".org"})
DISPLAY_SUFFIXES = frozenset({".yml", ".yaml", ".toml", ".json", ".cfg", ".ini"})
# Refused whatever the suffix or role. File names compare case-insensitively.
FORBIDDEN_NAME_PREFIXES = ("license", "licence", "copying", "copyright", "notice", "authors", "contributors",
                           "citation", "patents", "security")
# Attribution notices for third-party code, wherever in the name the two words fall.
FORBIDDEN_ATTRIBUTION_NAMES = ("*third*party*",)
FORBIDDEN_NAMES = (
    # Dependency manifests and lockfiles: they name what is installed and run.
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "pyproject.toml", "setup.cfg", "setup.py", "pipfile*", "poetry.lock", "uv.lock",
    "*requirements*.txt", "*constraints*.txt", "runtime.txt", "go.mod", "go.sum", "cargo.toml", "cargo.lock",
    "composer.*", "gemfile*", "*.gemspec", "pom.xml", "build.gradle*", "settings.gradle*",
    "tsconfig*.json", "jsconfig.json", "deno.json*", "environment.yml", "environment.yaml", "bower.json",
    "pubspec.yaml",
    # Build, CI, and security configuration.
    "dockerfile*", "docker-compose*", "compose.yml", "compose.yaml", "makefile", "jenkinsfile",
    ".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml", "bitbucket-pipelines.yml",
    ".pre-commit-config.yaml", "tox.ini", "pytest.ini", ".env*", "cmakelists.txt", "action.yml",
    "action.yaml", "dependabot.yml", "dependabot.yaml",
)
FORBIDDEN_DIRECTORIES = (".github/workflows", ".github/actions", ".github/codeql", ".circleci", ".git")
# Refused for what they hold, whatever their files are called. Directory names compare like file names.
DEPENDENCY_DIRECTORIES = ("requirements",)
LICENSE_DIRECTORIES = ("licenses",)
# Retained cues are reported for at most this many paths, the most affected first.
CUE_PATH_LIMIT = 50


def _now(clock: Callable[[], datetime] | None) -> str:
    moment = (clock or (lambda: datetime.now(timezone.utc)))()
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _refused(reason: str) -> MaterializationError:
    return MaterializationError(f"blinding map refused: {reason}")


# --- the map as a document ---------------------------------------------------------------------


def load_map(path: str | os.PathLike[str]) -> dict:
    """Load and validate one blinding map. Approval is not asked here; applying the map asks it."""
    return load_document(path, MAP_KIND)


def save_map(path: Path, document: dict) -> None:
    """Validate *document* and write it to *path* as indented JSON, as a pack is written."""
    validate_document(MAP_KIND, document)
    Path(path).write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def content_digest(document: dict) -> str:
    """What a review approves: the canonical digest of the map without its review history."""
    return canonical_sha256({key: value for key, value in document.items()
                             if key not in ("reviews", "reviews_sha256")})


def map_sha256(document: dict) -> str:
    """The canonical digest of the whole map, reviews included: which map document was used."""
    return canonical_sha256(document)


def map_identity(document: dict) -> dict:
    """The identity plans, schedules, and execution records carry; the map itself stays here."""
    return {"map_id": document["map_id"], "map_version": document["map_version"],
            "map_sha256": map_sha256(document)}


def _named(document: dict) -> str:
    return f"map {document['map_id']} {document['map_version']}"


def approval_gap(document: dict) -> str | None:
    """Why *document* may not be applied as it stands, or ``None`` when its latest review approves it.

    The latest recorded review is the operative one, as it is for a case: a rejection and an
    unresolved reopening both withdraw an earlier approval, and an approval covers the content
    digest it recorded, so a map edited afterwards is unapproved until a review covers the edit.
    The chain itself is verified when the map is loaded; this reads what it records.
    """
    reviews = document["reviews"]
    if not reviews:
        return f"{_named(document)} is unreviewed: no review is recorded"
    latest = reviews[-1]
    who = f"{latest['reviewer']} ({latest['role']}) at {latest['at']}"
    if latest["decision"] == "reject":
        return f"{_named(document)} was rejected by {who}"
    if latest["decision"] == "unresolved":
        return f"{_named(document)} was reopened by {who}, so it is not approved"
    current = content_digest(document)
    if latest["content_sha256"] != current:
        return (f"{_named(document)}: the latest approval, by {who}, covers content "
                f"{latest['content_sha256']}, but the map now hashes to {current}; it was edited "
                "after it was approved")
    return None


def approving_reviews(document: dict) -> list[dict]:
    """The approvals standing behind the map as it is now: after its last withdrawal, of this content."""
    current = content_digest(document)
    standing: list[dict] = []
    for review in document["reviews"]:
        if review["decision"] != "approve":
            standing = []
        elif review["content_sha256"] == current:
            standing.append({"reviewer": review["reviewer"], "role": review["role"], "at": review["at"]})
    return standing


def record_review(document: dict, *, reviewer: str, role: str, decision: str, note: str,
                  clock: Callable[[], datetime] | None = None) -> dict:
    """Append one review of the map as it stands, chained to the review before it; return it.

    The reviewer is the name the caller supplies; a blank one is refused and none is ever
    supplied here. The review binds :func:`content_digest` of the map at this moment, so an
    approval says exactly which content was approved. The decision is recorded as made: nothing
    here checks the map against an export first (:func:`dry_run` is that check). A refused review
    leaves *document* exactly as it was; a recorded one replaces its contents.
    """
    validate_document(MAP_KIND, document)
    if not is_stated(reviewer):
        raise ContractError("a map review must name its reviewer; the tool never supplies one")
    if role not in REVIEW_ROLES:
        raise ContractError(f"review role must be one of {', '.join(REVIEW_ROLES)}, not {role!r}")
    if decision not in REVIEW_DECISIONS:
        raise ContractError(f"review decision must be one of {', '.join(REVIEW_DECISIONS)}, not {decision!r}")
    candidate = copy.deepcopy(document)
    entry = {"reviewer": reviewer, "role": role, "decision": decision, "at": _now(clock), "note": note,
             "content_sha256": content_digest(candidate)}
    previous = candidate["reviews"][-1]["chain_sha256"] if candidate["reviews"] else None
    entry["chain_sha256"] = chain_digest(previous, entry, REVIEW_KIND)
    candidate["reviews"].append(entry)
    candidate["reviews_sha256"] = entry["chain_sha256"]
    validate_document(MAP_KIND, candidate)
    document.clear()
    document.update(candidate)
    return entry


def leaked_originals(document: dict, value: Any) -> list[str]:
    """Every original token of *document* that occurs, ignoring case, in any string of *value*.

    Dictionary keys and values and list items are walked; anything else is not a string and is
    not read. A run refuses to hand a blinded input to a system whose identity or configuration
    names an original, because the request and the adapter would carry it into the scan.
    """
    strings: list[str] = []
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            strings.append(item.casefold())
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
    return sorted({pseudonym["original"] for pseudonym in document["pseudonyms"]
                   if any(pseudonym["original"].casefold() in text for text in strings)})


# --- which paths an edit may touch -------------------------------------------------------------


# What a scanner reads as instructions, spelled in lower case for a comparison that ignores case:
# the export's own lists, and CLAUDE.local.md, the local instructions file, which they do not name.
_INSTRUCTION_NAMES = frozenset(name.casefold() for name in INSTRUCTION_FILE_NAMES) | {"claude.local.md"}
_INSTRUCTION_ROOTS = frozenset(name.casefold() for name in INSTRUCTION_TOP_LEVEL)
_INSTRUCTION_PATHS = frozenset(path.casefold() for path in INSTRUCTION_PATHS)
_INSTRUCTION_PREFIXES = tuple(prefix.casefold() for prefix in INSTRUCTION_PATH_PREFIXES)


def _reads_as_instructions(path: str) -> bool:
    """Whether a scanner may read *path* as project instructions, whatever the case of its name.

    The export records instruction files exactly as it spells them, and a case-insensitive file
    system opens ``claude.md`` as ``CLAUDE.md``, so blinding asks the export's test and then the
    same lists again with case ignored, plus ``CLAUDE.local.md``.
    """
    folded = path.casefold()
    return (_is_instruction_file(path)
            or folded.rsplit("/", 1)[-1] in _INSTRUCTION_NAMES
            or folded.split("/", 1)[0] in _INSTRUCTION_ROOTS
            or folded in _INSTRUCTION_PATHS
            or folded.startswith(_INSTRUCTION_PREFIXES))


def _instruction_files(paths, listed) -> list[str]:
    """The instruction files among *paths* by this module's test, with those the export *listed*."""
    return sorted({*listed, *(path for path in paths if _reads_as_instructions(path))})


def path_class_gap(path: str, role: str, role_check: str | None = None) -> str | None:
    """Why *path* may not be edited under *role*, or ``None`` when it may.

    Documentation (``.md``, ``.rst``, ``.txt`` and the like) may be edited under any role.
    Configuration with a display suffix (``.yml``, ``.toml``, ``.json`` and the like) only as
    ``display_metadata`` with a stated ``role_check``, the reviewer's reason the field is not read
    at runtime. Refused whatever the suffix and role, with names and directories compared without
    regard to case: license, attribution, and security files (a name that starts ``license``,
    ``copyright``, ``notice``, ``authors``, ``security`` and the like, or holds ``third`` then
    ``party``, and anything under ``licenses/``); dependency manifests and lockfiles (a ``.txt``
    whose name holds ``requirements`` or ``constraints``, and anything under ``requirements/``);
    build, CI, and security configuration; anything under ``.github/workflows/``,
    ``.github/actions/``, ``.github/codeql/``, ``.circleci/``, or ``.git/``; and the files a scanner
    reads as instructions, ``CLAUDE.local.md`` among them, since changing those changes the
    execution condition. Every other file, source and scripts included, is never edited. The lists
    are a guard, not a classifier: they name what is known to matter and cannot name everything.
    This reads the path only.
    """
    if role not in EDIT_ROLES:
        return f"{role!r} is not an edit role; the roles are {', '.join(EDIT_ROLES)}"
    parts = PurePosixPath(path).parts
    folded_parts = tuple(part.casefold() for part in parts)

    def under(directory: str) -> bool:
        needle = tuple(directory.split("/"))
        return any(folded_parts[index:index + len(needle)] == needle
                   for index in range(len(folded_parts) - len(needle)))

    for directories, what in ((FORBIDDEN_DIRECTORIES, "which is build, CI, or repository machinery"),
                              (DEPENDENCY_DIRECTORIES, "which holds dependency manifests"),
                              (LICENSE_DIRECTORIES, "which holds license and attribution texts")):
        for directory in directories:
            if under(directory):
                return f"{path} is under {directory}/, {what}"
    name = folded_parts[-1]
    if name.startswith(FORBIDDEN_NAME_PREFIXES) or any(
            fnmatch.fnmatchcase(name, pattern) for pattern in FORBIDDEN_ATTRIBUTION_NAMES):
        return f"{path} is a license, attribution, or security file"
    for pattern in FORBIDDEN_NAMES:
        if fnmatch.fnmatchcase(name, pattern):
            return (f"{path} is a dependency manifest, a lockfile, or build, CI, or security "
                    f"configuration ({pattern})")
    if _reads_as_instructions(path):
        return (f"{path} is a file a scanner reads as instructions; editing it changes the execution "
                "condition, not display metadata")
    suffix = PurePosixPath(name).suffix
    if suffix in DOCUMENTATION_SUFFIXES:
        return None
    if suffix in DISPLAY_SUFFIXES:
        if role != "display_metadata":
            return (f"{path} is configuration ({suffix}), which may be edited only as display_metadata "
                    "with a stated role check")
        if not is_stated(role_check):
            return f"{path} is configuration ({suffix}) and its display_metadata edit states no role check"
        return None
    return (f"{path} is neither documentation ({', '.join(sorted(DOCUMENTATION_SUFFIXES))}) nor display "
            f"configuration ({', '.join(sorted(DISPLAY_SUFFIXES))}); source, scripts, and every other "
            "file are never edited")


# --- occurrences --------------------------------------------------------------------------------


def _starts(text: str, token: str) -> list[int]:
    """Every offset *token* starts at in *text*, overlapping occurrences included."""
    found: list[int] = []
    index = text.find(token)
    while index != -1:
        found.append(index)
        index = text.find(token, index + 1)
    return found


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_count(text: str) -> int:
    """Lines as a byte-oriented reader counts them: one per newline, plus an unterminated last one."""
    return text.count("\n") + (1 if text and not text.endswith("\n") else 0)


def _spans(text: str, originals: list[str], where: str) -> list[tuple[int, int, str]]:
    """Every occurrence of every original in *text* as ``(start, end, original)``, in order.

    An original that overlaps itself (``aa`` in ``aaa``) has no one occurrence count, and two
    originals whose occurrences overlap (``Acme`` inside ``Acme Widget``) leave it open which one
    the text names; both are refused rather than resolved by a rule nobody reviewed.
    """
    spans: list[tuple[int, int, str]] = []
    for token in originals:
        starts = _starts(text, token)
        for first, second in zip(starts, starts[1:]):
            if second < first + len(token):
                raise _refused(f"{where}: {token!r} overlaps itself on line {_line_of(text, second)}, "
                               "so how many times it occurs is ambiguous")
        spans.extend((start, start + len(token), token) for start in starts)
    spans.sort()
    for (_, first_end, first), (second_start, _, second) in zip(spans, spans[1:]):
        if second_start < first_end:
            raise _refused(f"{where}: {first!r} and {second!r} are overlapping matches on line "
                           f"{_line_of(text, second_start)}, so which one the text names is ambiguous")
    return spans


def _replaced(text: str, spans: list[tuple[int, int, str]], replacement_of: dict[str, str]) -> str:
    pieces: list[str] = []
    cursor = 0
    for start, end, token in spans:
        pieces.append(text[cursor:start])
        pieces.append(replacement_of[token])
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


@dataclass(frozen=True)
class _Edit:
    """One edit as it applies to one variant, computed and verified before anything is written.

    *structure_check* names how a display file's structure was verified (``json``, ``toml``,
    ``ini``, or ``yaml``), and is ``None`` for a file that is not verified by parsing.
    """

    edit_id: str
    path: str
    present: bool
    original_sha256: str | None = None
    data: bytes | None = None
    transformed_sha256: str | None = None
    occurrences: dict | None = None
    changed_lines: tuple[int, ...] = ()
    line_count: int = 0
    structure_check: str | None = None


def _variant(document: dict, snapshot_id: str, commit: str) -> dict:
    """The map's variant for *snapshot_id*, which must pin the snapshot's own commit."""
    for variant in document["variants"]:
        if variant["snapshot_id"] == snapshot_id:
            if variant["commit"] != commit:
                raise MaterializationError(
                    f"stale map: {_named(document)} records snapshot {snapshot_id} at commit "
                    f"{variant['commit']}, but the snapshot is pinned at {commit}")
            return variant
    known = ", ".join(variant["snapshot_id"] for variant in document["variants"])
    raise MaterializationError(
        f"stale map: {_named(document)} has no variant for snapshot {snapshot_id}; it covers {known}")


# --- a display file keeps its structure ---------------------------------------------------------
#
# A replacement is written into a file as text, with no quoting and no escaping, so one that holds a
# quotation mark, a backslash, a colon, or a bracket can turn valid configuration into invalid or
# different configuration, and the hash, occurrence, and line checks cannot see it. Every edit of a
# JSON, TOML, INI, or YAML file is therefore verified by parsing the file before and after.


# The check an edit of each suffix gets, as the preparation record names it. Suffixes are read without
# regard to case, as :func:`path_class_gap` reads them.
_STRUCTURE_CHECKS = {".json": "json", ".toml": "toml", ".ini": "ini", ".cfg": "ini", ".yml": "yaml",
                     ".yaml": "yaml"}
# What the preparation record says each check verified, on one line.
_STRUCTURE_DETAILS = {
    "json": "parsed as strict JSON before and after; the result is the original with only the reviewed "
            "replacements applied to its keys and strings",
    "toml": "parsed as TOML before and after; the result is the original with only the reviewed "
            "replacements applied to its keys and strings",
    "ini": "parsed as INI before and after, as written and as Python's configparser reads it (option names folded "
           "to lower case, [DEFAULT] merged into each section, % and ${} interpolation); the result is the original "
           "with only the reviewed replacements applied to its section names, option names, and values",
    "yaml": "parsed as the YAML block subset before and after; the result is the original with only the reviewed "
            "replacements applied to its keys and strings, and every replaced plain scalar still reads as a string "
            "under YAML 1.1 and 1.2",
}


def _structure_check_for(path: str) -> str | None:
    """The check an edit of *path* gets, or ``None`` for a file this module does not verify by parsing."""
    return _STRUCTURE_CHECKS.get(PurePosixPath(path).suffix.casefold())


class _Pairs(tuple):
    """An object, table, or section as its ordered ``(key, value)`` pairs.

    A tuple, so it is never the same type as a list, and pairs rather than a dict, so the order of
    the keys, and a key that occurs twice, are part of what :func:`_difference` compares.
    """

    __slots__ = ()


class _Defaults(_Pairs):
    """An INI file's ``[DEFAULT]`` section, which a reader merges into every other section.

    A type of its own, so a replacement that renames a section to or from ``DEFAULT``, which changes
    what the file means, is a difference like any other.
    """

    __slots__ = ()


def _refuse_constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def _parse_json(text: str) -> Any:
    """Strict JSON after one leading byte-order mark: objects are :class:`_Pairs`, NaN and Infinity are refused."""
    return json.loads(text[1:] if text.startswith("\ufeff") else text, object_pairs_hook=_Pairs,
                      parse_constant=_refuse_constant)


def _tomlish(value: Any) -> Any:
    """A parsed TOML value with each table, in the order the file wrote it, as :class:`_Pairs`."""
    if isinstance(value, dict):
        return _Pairs((key, _tomlish(item)) for key, item in value.items())
    if isinstance(value, list):
        return [_tomlish(item) for item in value]
    return value


def _parse_toml(text: str) -> Any:
    return _tomlish(tomllib.loads(text))


# A default section no header line can spell, so configparser reads ``[DEFAULT]`` as the ordinary
# section it is written as and never merges one section's options into another's: what it returns is
# the file's own sections, and :class:`_Defaults` marks the one a reader treats differently.
_NO_DEFAULT_SECTION = "\n"


def _parse_ini(text: str, prefixes: tuple[str, ...] | None = None) -> Any:
    """Each section in order, with its own options in order; no interpolation, and any duplicate is refused.

    *prefixes* are the inline comment prefixes a reader is told to honour (the check as written has none).
    """
    parser = configparser.ConfigParser(interpolation=None, strict=True, default_section=_NO_DEFAULT_SECTION,
                                       inline_comment_prefixes=prefixes)
    parser.optionxform = str
    parser.read_string(text)
    return _Pairs((name, (_Defaults if name == configparser.DEFAULTSECT else _Pairs)(parser.items(name, raw=True)))
                  for name in parser.sections())


# YAML is read through a strict block subset rather than checked by lexical rules. A replacement written into a YAML
# file unquoted can open a flow collection, an anchor, a tag, or a block scalar, end a value at a comment, or turn a
# string into a boolean, a null, a number, or a date, and no list of characters finds every way to do that without
# also refusing the common safe ones (a copyright line holding HTML, a description holding ``*`` or a backtick). So a
# YAML edit is verified like the others, by parsing before and after, but only for text the parser below reads
# exactly: for every text it accepts, PyYAML (YAML 1.1) and ruamel.yaml (YAML 1.2, and its 1.1 mode) load the same
# keys, in the same order, nested the same way, with the same strings. A file outside the subset is refused, however
# valid YAML it is, because nothing can then be said of how an edit of it reads.


# Nesting of collections deeper than this is outside the subset.
_YAML_DEPTH = 64
# The longest a key may run, from its first character to its colon: readers refuse an implicit key that is longer.
_YAML_KEY_LENGTH = 1024
# The longest a scalar that readers resolve as a number or date may be: they refuse an integer of more than 4300 digits.
_YAML_NUMBER_LENGTH = 4000
# What a line may not hold anywhere: a control character, a line break other than LF (a CR is one, unless it ends the
# line before the LF), a surrogate, a non-character, and a byte-order mark after the first character. YAML 1.1 and
# 1.2 disagree about several of these, and readers refuse or strip the others.
_YAML_FORBIDDEN = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff\ufeff\ufffe\uffff]")
# A key's colon: one followed by a space or the end of the line.
_YAML_KEY_COLON = re.compile(r":(?= |\Z)")
# What may not start a scalar of this subset, and what it would be.
_YAML_INDICATORS = {
    "[": "a flow collection ('[')", "{": "a flow collection ('{')", "]": "a flow indicator (']')",
    "}": "a flow indicator ('}')", ",": "a flow indicator (',')", "&": "an anchor ('&')", "*": "an alias ('*')",
    "!": "a tag ('!')", "|": "a block scalar ('|')", ">": "a block scalar ('>')",
    "%": "a reserved indicator ('%')", "@": "a reserved indicator ('@')",
    "`": "a reserved indicator ('`')", "?": "an explicit key, or a scalar starting with '?'",
    "-": "a scalar starting with '-'", ":": "a scalar starting with ':'",
}
# The escapes of a double-quoted scalar, and the lengths of those that hold a code point.
_YAML_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r", "e": "\x1b",
                 " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0", "L": "\u2028", "P": "\u2029"}
_YAML_CODE_ESCAPES = {"x": 2, "u": 4, "U": 8}
_YAML_QUOTE = re.compile(r'["\\]')

# Timestamps as readers resolve them: a date, or a date and a time with a fraction and an offset.
_YAML_DATE = re.compile("([0-9]{4})-([0-9]{2})-([0-9]{2})")
_YAML_DATETIME = re.compile("([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})(?:[Tt]| +)([0-9]{1,2}):([0-9]{2}):([0-9]{2})"
                            "(?:\\.([0-9]*))?(?: *(?:Z|([-+])([0-9]{1,2})(?::([0-9]{2}))?))?")
# Every plain scalar that YAML 1.1 (PyYAML, ruamel.yaml's 1.1 mode) or the YAML 1.2 core schema (ruamel.yaml) reads as
# something other than a string: null, the booleans (1.1 adds y, n, yes, no, on, off), integers (binary, octal,
# hexadecimal, underscores, and 1.1's base 60), floats (an exponent, underscores, .inf, .nan, base 60), and timestamps.
# A scalar is a string only if neither reads it as anything else, so this is the union of both.
_YAML_NON_STRING = re.compile("|".join((
    "~|null|Null|NULL",
    "[yYnN]|yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF",
    "[-+]?0b[01_]+|[-+]?0o[0-7_]+|[-+]?0x[0-9a-fA-F_]+|[0-9][0-9_]*|[-+][0-9_]+",
    "[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+",
    "[-+]?[0-9][0-9_]*\\.[0-9_]*(?:[eE][-+]?[0-9]+)?|[-+]?[0-9][0-9_]*[eE][-+]?[0-9]+",
    "[-+]?\\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\\.[0-9_]*",
    "[-+]?\\.(?:inf|Inf|INF)|\\.(?:nan|NaN|NAN)",
    _YAML_DATE.pattern, _YAML_DATETIME.pattern)))
# A number those readers resolve but have no digit to build: a sign, a base, or a dot and then only underscores.
_YAML_NO_DIGITS = re.compile("[-+]?(?:0[box])?_+|[-+]?\\._+(?:[eE][-+]?[0-9]+)?")
# A plain decimal number: no sign, leading zero, or underscore, so no reader reads it as another key's number.
_YAML_DECIMAL = re.compile("0|[1-9][0-9]*")


class _OutsideYaml(ValueError):
    """Text the YAML subset does not read; the message names the line and the construct that is outside it."""

    def __init__(self, number: int, what: str) -> None:
        super().__init__(f"line {number}: {what} is outside the YAML subset read here")


class _NonString:
    """A plain YAML scalar that some reader reads as something other than a string, held as the text it was written as.

    Null (an empty value too), a boolean, a number, or a date, which of them depending on the YAML version, so the text
    is what is kept. Never a ``str``, so no reviewed replacement is applied to it, and :func:`_difference` compares the
    type and the text.
    """

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        self.text = text

    def __eq__(self, other: object) -> bool:
        return type(other) is _NonString and other.text == self.text

    def __hash__(self) -> int:
        return hash((_NonString, self.text))

    def __repr__(self) -> str:
        return f"{self.text!r} (read as a non-string)"


def _real_timestamp(text: str) -> bool:
    """Whether *text*, if it is shaped like a timestamp, is a date, time, and offset a reader can build."""
    match = _YAML_DATE.fullmatch(text) or _YAML_DATETIME.fullmatch(text)
    if match is None:
        return True
    groups = match.groups()
    try:
        datetime(*(int(part) for part in groups[:6]))
        if len(groups) > 7 and groups[7]:
            offset = timedelta(hours=int(groups[8]), minutes=int(groups[9] or 0))
            timezone(-offset if groups[7] == "-" else offset)
    except ValueError:
        return False
    return True


def _yaml_plain(number: int, text: str) -> str | _NonString:
    """A plain scalar's value: *text* itself when every reader reads it as a string, else a :class:`_NonString`.

    Outside the subset: a tab, the YAML 1.1 merge and value indicators (``<<`` and ``=``, which most readers cannot load
    as a value), and a scalar that readers resolve as a number or date and then cannot build one from.
    """
    if "\t" in text:
        raise _OutsideYaml(number, "a tab outside a comment")
    if text in ("<<", "="):
        raise _OutsideYaml(number, f"the scalar {text!r}, a YAML 1.1 merge or value indicator")
    if not _YAML_NON_STRING.fullmatch(text):
        return text
    if len(text) > _YAML_NUMBER_LENGTH or _YAML_NO_DIGITS.fullmatch(text) or not _real_timestamp(text):
        raise _OutsideYaml(number, f"the scalar {text[:40]!r}, which readers take for a number or a date and cannot "
                                   "load")
    return _NonString(text)


def _yaml_single(number: int, content: str) -> tuple[str, int]:
    """The single-quoted scalar at the start of *content*, and the offset after its closing quote; ``''`` is a quote."""
    pieces, at = [], 1
    while True:
        end = content.find("'", at)
        if end == -1:
            raise _OutsideYaml(number, "a quoted scalar that does not close on its line (a multi-line scalar)")
        if content.startswith("'", end + 1):
            pieces.append(content[at:end + 1])
            at = end + 2
        else:
            pieces.append(content[at:end])
            return "".join(pieces), end + 1


def _yaml_double(number: int, content: str) -> tuple[str, int]:
    """The double-quoted scalar at the start of *content* with its escapes decoded, and the offset after its quote."""
    pieces, at = [], 1
    while True:
        found = _YAML_QUOTE.search(content, at)
        if found is None:
            raise _OutsideYaml(number, "a quoted scalar that does not close on its line (a multi-line scalar)")
        pieces.append(content[at:found.start()])
        if found.group() == '"':
            return "".join(pieces), found.end()
        letter = content[found.end():found.end() + 1]
        at = found.end() + 1
        if not letter:
            raise _OutsideYaml(number, "a backslash at the end of a line (a multi-line scalar)")
        if letter in _YAML_ESCAPES:
            pieces.append(_YAML_ESCAPES[letter])
        elif letter in _YAML_CODE_ESCAPES:
            width = _YAML_CODE_ESCAPES[letter]
            digits = content[at:at + width]
            if len(digits) != width or any(digit not in "0123456789abcdefABCDEF" for digit in digits):
                raise _OutsideYaml(number, f"the escape '\\{letter}' without {width} hexadecimal digits")
            code = int(digits, 16)
            if 0xD800 <= code <= 0xDFFF or code > 0x10FFFF:
                raise _OutsideYaml(number, f"the escape '\\{letter}{digits}', which is not a Unicode scalar value")
            pieces.append(chr(code))
            at += width
        else:
            raise _OutsideYaml(number, f"the escape '\\{letter}'")


def _yaml_start(number: int, content: str) -> tuple[str, str | _NonString, str]:
    """Read the scalar at the start of *content*, which does not start with a space.

    Returns ``("key", key, after)`` when *content* starts ``KEY:`` and then holds the end of its line or a space,
    *after* being what follows the colon, and ``("scalar", value, rest)`` otherwise, *rest* being what follows the
    scalar on its line, which is its comment. Text after a quoted scalar that is not a comment or a key's colon is
    refused here.
    """
    first = content[0]
    if first in "\"'":
        value, end = (_yaml_double if first == '"' else _yaml_single)(number, content)
        if "\t" in content[:end]:
            raise _OutsideYaml(number, "a tab outside a comment")
        tail = content[end:]
        bare = tail.lstrip(" ")
        if bare.startswith(":") and (len(bare) == 1 or bare[1] == " "):
            return "key", value, bare[1:]
        if tail and not (tail[0] == " " and (not bare or bare[0] == "#")):
            raise _OutsideYaml(number, "text after a quoted scalar")
        return "scalar", value, tail
    if first in _YAML_INDICATORS:
        raise _OutsideYaml(number, _YAML_INDICATORS[first])
    colon, comment = _YAML_KEY_COLON.search(content), content.find(" #")
    if colon is not None and (comment == -1 or colon.start() < comment):
        return "key", _yaml_plain(number, content[:colon.start()].rstrip(" ")), content[colon.end():]
    text = (content if comment == -1 else content[:comment]).rstrip(" ")
    return "scalar", _yaml_plain(number, text), "" if comment == -1 else content[comment:]


def _yaml_dash(content: str) -> bool:
    """Whether *content* starts a block sequence entry: a dash that ends the line or is followed by a space."""
    return content[0] == "-" and (len(content) == 1 or content[1] == " ")


def _yaml_character(character: str) -> str:
    if character == "\r":
        return "a carriage return that does not end a line"
    if character == "\ufeff":
        return "a byte-order mark inside the text"
    return f"the character U+{ord(character):04X}, which readers disagree on or refuse"


def _yaml_lines(text: str) -> list[list]:
    """The lines of *text* that hold more than spaces and a comment, each as ``[number, indent, content]``.

    A byte-order mark at the start is dropped, and a carriage return before a line feed is part of the break. The
    ``---`` that may start the document, alone on its line, is dropped too; a second one, and ``...``, are refused.
    """
    lines: list[list] = []
    started = False
    if text.startswith("\ufeff"):
        text = text[1:]
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw[:-1] if raw.endswith("\r") else raw
        bad = _YAML_FORBIDDEN.search(line)
        if bad:
            raise _OutsideYaml(number, _yaml_character(bad.group()))
        content = line.lstrip(" ")
        if not content or content[0] == "#":
            continue
        indent = len(line) - len(content)
        if indent == 0 and content[0] == "%":
            raise _OutsideYaml(number, "a directive ('%')")
        if indent == 0 and content[:3] in ("---", "..."):
            if content[:3] == "...":
                raise _OutsideYaml(number, "a line starting with '...' (a document end marker)")
            if started:
                raise _OutsideYaml(number, "a second '---' (a document start marker)")
            rest = content[3:]
            if rest[:1] not in ("", " ") or rest.lstrip(" ")[:1] not in ("", "#"):
                raise _OutsideYaml(number, "content after '---' on its line")
            started = True
            continue
        started = True
        lines.append([number, indent, content])
    return lines


class _YamlKeys:
    """The keys of one mapping as they are read, refusing a key that a reader may read as one already there.

    Two strings are one key when they are equal. A plain scalar that is not a string is one key with another, or with a
    string, when some reader reads them alike: ``yes`` and ``true`` are both true to YAML 1.1, ``1`` and ``0x1`` are one
    number, and ``no`` is the string ``no`` to YAML 1.2. So such a key is accepted only alone in its mapping, or among
    plain decimal numbers, which no reader reads as any other key.
    """

    def __init__(self) -> None:
        self.strings: set[str] = set()
        self.plain: set[str] = set()
        self.numbers = True

    def add(self, number: int, key: str | _NonString) -> None:
        text = key if isinstance(key, str) else key.text
        decimal = _YAML_DECIMAL.fullmatch(text) is not None
        if isinstance(key, str):
            duplicate = text in self.strings
            clash = text in self.plain and not decimal
            self.strings.add(text)
        else:
            self.numbers = self.numbers and decimal
            duplicate = text in self.plain
            clash = (text in self.strings and not decimal) or (bool(self.plain) and not self.numbers)
            self.plain.add(text)
        if duplicate:
            raise _OutsideYaml(number, f"the duplicate key {text!r}")
        if clash:
            raise _OutsideYaml(number, f"the key {text!r}, which a reader may read as the same key as another in its "
                                       "mapping")


class _YamlReader:
    """The block collections of a document's lines, read in one pass; each line is handled once."""

    def __init__(self, lines: list[list]) -> None:
        self.lines = lines
        self.at = 0

    def line(self) -> list | None:
        return self.lines[self.at] if self.at < len(self.lines) else None

    def node(self, column: int, depth: int) -> Any:
        """The collection that starts at the current line, which is at *column*: a sequence if it is an entry."""
        return (self.sequence if _yaml_dash(self.lines[self.at][2]) else self.mapping)(column, depth)

    def mapping(self, column: int, depth: int) -> _Pairs:
        """The block mapping whose keys are at *column*, from the current line to the first line outside it."""
        if depth > _YAML_DEPTH:
            raise _OutsideYaml(self.lines[self.at][0], f"nesting deeper than {_YAML_DEPTH} levels")
        pairs: list[tuple[Any, Any]] = []
        keys = _YamlKeys()
        while True:
            line = self.line()
            if line is None or line[1] < column:
                break
            number, indent, content = line
            if indent > column:
                raise _OutsideYaml(number, "a line more indented than the entries before it (a multi-line scalar, "
                                           "or misaligned indentation)")
            if _yaml_dash(content):
                raise _OutsideYaml(number, "a sequence entry among mapping entries")
            kind, key, after = _yaml_start(number, content)
            if kind != "key":
                raise _OutsideYaml(number, "a line that is not a 'key: value' entry (a scalar on its own line, or a "
                                           "key without ':')")
            if len(content) - len(after) - 1 > _YAML_KEY_LENGTH:   # where the colon is, counted from the key's start
                raise _OutsideYaml(number, f"a key longer than {_YAML_KEY_LENGTH} characters")
            keys.add(number, key)
            pairs.append((key, self.value(number, column, after, depth)))
        return _Pairs(pairs)

    def value(self, number: int, column: int, after: str, depth: int) -> Any:
        """The value of the key just read, whose line holds *after* beyond its colon, and whose key is at *column*."""
        body = after.lstrip(" ")
        if body and body[0] != "#":
            kind, scalar, _ = _yaml_start(number, body)
            if kind == "key":
                raise _OutsideYaml(number, "a ':' in a value (a mapping on the line of another key)")
            self.at += 1
            return scalar
        self.at += 1
        following = self.line()
        if following is not None:
            if following[1] > column:
                return self.node(following[1], depth + 1)
            if following[1] == column and _yaml_dash(following[2]):
                return self.sequence(column, depth + 1)   # a sequence level with its key is that key's value
        return _NonString("")

    def sequence(self, column: int, depth: int) -> list:
        """The block sequence whose dashes are at *column*, from the current line to the first line outside it."""
        if depth > _YAML_DEPTH:
            raise _OutsideYaml(self.lines[self.at][0], f"nesting deeper than {_YAML_DEPTH} levels")
        items = []
        while True:
            line = self.line()
            if line is None or line[1] < column:
                break
            number, indent, content = line
            if indent > column:
                raise _OutsideYaml(number, "a line more indented than the entries before it (a multi-line scalar, "
                                           "or misaligned indentation)")
            if not _yaml_dash(content):
                break
            items.append(self.item(line, column, depth))
        return items

    def item(self, line: list, column: int, depth: int) -> Any:
        """The value of the sequence entry on *line*, whose dash is at *column*."""
        number, _, content = line
        body = content[1:].lstrip(" ")
        if not body or body[0] == "#":
            self.at += 1
            following = self.line()
            if following is not None and following[1] > column:
                return self.node(following[1], depth + 1)
            return _NonString("")
        if _yaml_dash(body):
            raise _OutsideYaml(number, "a sequence on the line of its entry ('- -')")
        # What follows the dash is a line of its own, at its own column: a key that starts a mapping whose other keys
        # are at that column, or a scalar.
        line[1], line[2] = column + len(content) - len(body), body
        kind, scalar, _ = _yaml_start(number, body)
        if kind == "key":
            return self.mapping(line[1], depth + 1)
        self.at += 1
        return scalar


def _parse_yaml(text: str) -> Any:
    """*text* as the YAML subset this module reads: block mappings and sequences of one-line plain or quoted scalars.

    A mapping is :class:`_Pairs` of its keys and values in order, a sequence a list, a quoted scalar a string, a plain
    scalar a string when no reader reads it as anything else, and otherwise a :class:`_NonString` of its text. A key
    with nothing after it, and an empty document, are the empty :class:`_NonString`, null. Anything else raises
    :class:`_OutsideYaml` naming the line and the construct: a flow collection, an anchor, an alias, a tag, a block
    scalar, a directive, a second document, an explicit key, a merge key, a duplicate key, a scalar that goes on to
    the next line, a tab, a control character, a nesting deeper than 64 levels, and whatever else the subset leaves
    out, which includes valid YAML. Guaranteed for what this returns: PyYAML, and ruamel.yaml in YAML 1.2 and in 1.1,
    load the same keys, in order, nested the same way, and the same strings, and a scalar they read as other than a
    string is a :class:`_NonString`. Not guaranteed: anything about a text this refuses, or about how a YAML reader
    other than those two reads a text it returns. The work is linear in the size of *text*.
    """
    lines = _yaml_lines(text)
    if not lines:
        return _NonString("")
    reader = _YamlReader(lines)
    root = reader.node(lines[0][1], 1)
    if reader.at < len(lines):
        raise _OutsideYaml(lines[reader.at][0], "a line that continues no collection (misaligned indentation)")
    return root


# For each parsed check: what the refusal calls the format, what the original must be, and how to read it.
_PARSERS = {"json": ("JSON", "strict JSON", _parse_json),
            "toml": ("TOML", "valid TOML", _parse_toml),
            "ini": ("INI", "a valid INI file", _parse_ini),
            "yaml": ("YAML within the subset this module reads",
                     "in the YAML subset this module reads (block mappings and sequences of one-line plain or quoted "
                     "scalars, and comments)", _parse_yaml)}
# What a parser raises for text it cannot read: its own error, or a nesting deeper than Python recurses.
_PARSE_ERRORS = (ValueError, configparser.Error, RecursionError)


def _reason(exc: BaseException) -> str:
    """A parser's own words on one line, at most 200 characters; a runaway nesting is named as such."""
    if isinstance(exc, RecursionError):
        return "nested too deeply to read"
    text = " ".join(str(exc).split())
    return text if len(text) <= 200 else text[:197] + "..."


def _shown(value: Any, limit: int = 80) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _kind(value: Any) -> str:
    named = {_Defaults: "the defaults section", _Pairs: "a mapping", list: "a list", str: "a string",
             bool: "a boolean", int: "an integer", float: "a float", type(None): "null", _NonString: "a plain scalar"}
    return named.get(type(value)) or f"a {type(value).__name__} value"


def _at(path: tuple) -> str:
    """Where in a parsed file: ``$`` is the whole, ``$['a'][0]`` the first item of the value at the key ``a``."""
    return "$" + "".join(f"[{(part.text if isinstance(part, _NonString) else part)!r}]" for part in path)


def _rewritten(value: Any, rewrite: Callable[[str], str], where: str, path: tuple = ()) -> Any:
    """*value* with *rewrite* applied to every string it holds, keys included, as the raw edit did to the text.

    A value or key that is not a string is left as it is. Refused where two keys of one mapping that
    differ become the same key: a reader would keep one of the two entries or merge them, which no
    reviewed replacement said.
    """
    if isinstance(value, str):
        return rewrite(value)
    if isinstance(value, list):
        return [_rewritten(item, rewrite, where, path + (index,)) for index, item in enumerate(value)]
    if not isinstance(value, _Pairs):
        return value
    kept: dict[Any, Any] = {}
    pairs = []
    for key, item in value:
        new = rewrite(key) if isinstance(key, str) else key
        if kept.setdefault(new, key) != key:
            raise _refused(f"{where}: the replacements make the keys {kept[new]!r} and {key!r} of the mapping at "
                           f"{_at(path)} the same key {new!r}, a duplicate that would merge two entries")
        pairs.append((new, _rewritten(item, rewrite, where, path + (key,))))
    return type(value)(pairs)


def _difference(expected: Any, found: Any, path: tuple = ()) -> str | None:
    """Where *found* is not *expected*, in words, or ``None`` when they are the same.

    Strict: a value of another type differs (``1``, ``1.0``, and ``true`` are three values), the keys
    of a mapping are compared in order and with any duplicate, and NaN is the same as NaN, so no key,
    type, nesting, or non-string value can change unseen.
    """
    if type(expected) is not type(found):
        return f"{_at(path)} is {_kind(found)} {_shown(found)}, expected {_kind(expected)} {_shown(expected)}"
    if isinstance(expected, _Pairs):
        expected_keys, found_keys = [key for key, _ in expected], [key for key, _ in found]
        if expected_keys != found_keys:
            return f"{_at(path)} holds the keys {_shown(found_keys)}, expected {_shown(expected_keys)}"
        for (key, want), (_, got) in zip(expected, found):
            inner = _difference(want, got, path + (key,))
            if inner:
                return inner
        return None
    if isinstance(expected, list):
        if len(expected) != len(found):
            return f"{_at(path)} holds {len(found)} item(s), expected {len(expected)}"
        for index, (want, got) in enumerate(zip(expected, found)):
            inner = _difference(want, got, path + (index,))
            if inner:
                return inner
        return None
    # Floats and dates compare by what they print, which keeps NaN, the sign of a zero, and an offset.
    if isinstance(expected, (str, int, _NonString)) or expected is None:
        same = expected == found
    else:
        same = repr(expected) == repr(found)
    return None if same else f"{_at(path)} is {_shown(found)}, expected {_shown(expected)}"


# An INI file that keeps its structure as written can still read differently. Python's ``configparser`` folds
# option names to lower case unless it is told not to, so two options that differ only in case become one; it
# merges the ``[DEFAULT]`` section's options into every section, so a section's option can start to hide a
# default or be hidden by one; its default reader interpolates ``%(name)s`` in every value, as
# ``ExtendedInterpolation`` does ``${name}``, so a ``%`` or ``$`` in a replacement can fail to interpolate or
# read as another option's value; and a reader told to may end a line at a ``#`` or ``;`` that follows
# whitespace, so a replacement that holds one cuts what follows it from the value. The transformed file is
# therefore also compared with the original under each of these readers that can read the original, the default
# reader first.
def _ini_label(names: str, how: str, inline: str) -> str:
    label = f"option names {names}, [DEFAULT] merged into each section, {how}" + (f", {inline}" if inline else "")
    default = (names, how, inline) == ("folded to lower case", "% interpolation", "")
    return f"Python's default INI reader ({label})" if default else label


_INI_READERS = tuple((_ini_label(names, how, inline), fold, interpolation, prefixes)
                     for inline, prefixes in (("", None), ("# and ; inline comments", ("#", ";")))
                     for names, fold, how, interpolation in (
    ("folded to lower case", str.lower, "% interpolation", configparser.BasicInterpolation),
    ("folded to lower case", str.lower, "no interpolation", lambda: None),
    ("folded to lower case", str.lower, "${} interpolation", configparser.ExtendedInterpolation),
    ("as written", str, "no interpolation", lambda: None),
    ("as written", str, "% interpolation", configparser.BasicInterpolation),
    ("as written", str, "${} interpolation", configparser.ExtendedInterpolation)))


class _Unreadable:
    """An INI value a reader cannot return because interpolating it raised; *reason* names the error."""

    def __init__(self, reason: str) -> None:
        self.reason = reason


def _ini_reading(text: str, fold: Callable[[str], str], interpolation: Callable[[], Any],
                 prefixes: tuple[str, ...] | None) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    """Each section's options as a reader that folds names by *fold*, interpolates as *interpolation*, and ends a line
    at an inline comment beginning with one of *prefixes*, returns them, with the names as they are written.

    A section's options are the ``[DEFAULT]`` section's, then its own, keyed by the name *fold* gives them; a value
    the reader cannot interpolate is an :class:`_Unreadable`. The second result gives, for each section, the name
    as written of each option the first holds, read the same way but with names kept and nothing interpolated, so
    that it names the sections that reader sees (an inline comment can end a header earlier). Raises what
    ``configparser`` raises for a file the reader cannot read at all.
    """
    parser = configparser.ConfigParser(interpolation=interpolation(), strict=True, inline_comment_prefixes=prefixes)
    parser.optionxform = fold
    parser.read_string(text)
    structure = _parse_ini(text, prefixes)
    shared = [option for _, pairs in structure if isinstance(pairs, _Defaults) for option, _ in pairs]
    own = {section: [option for option, _ in pairs] for section, pairs in structure
           if not isinstance(pairs, _Defaults)}
    defaults = list(parser.defaults())
    reading: dict[str, dict[str, Any]] = {}
    names: dict[str, dict[str, str]] = {}
    for section in parser.sections():
        options: dict[str, Any] = {}
        for option in defaults + [name for name in parser.options(section) if name not in parser.defaults()]:
            try:
                options[option] = parser.get(section, option)
            except configparser.Error as exc:
                options[option] = _Unreadable(type(exc).__name__)
        reading[section] = options
        names[section] = {fold(option): option for option in shared + own[section]}
    return reading, names


def _check_ini_readings(where: str, text: str, new_text: str, rewrite: Callable[[str], str]) -> None:
    """Refuse unless each reader of :data:`_INI_READERS` that reads the original reads the transformed file as it does.

    The expectation is the original as that reader reads it, with every name and value rewritten as the raw edit
    rewrote the text: the same sections, the same options under the names the replaced names fold to, and the
    same values, which a reader that interpolates has already resolved. A reader that cannot read the original
    (an option it folds twice, a value it cannot interpolate) is asked nothing it never did, so such a value is
    not compared.
    """
    for label, fold, interpolation, prefixes in _INI_READERS:
        try:
            old, written = _ini_reading(text, fold, interpolation, prefixes)
        except _PARSE_ERRORS:
            continue
        try:
            new, _ = _ini_reading(new_text, fold, interpolation, prefixes)
        except _PARSE_ERRORS as exc:
            raise _refused(f"{where}: read with {label}, the original reads but the transformed file does not "
                           f"({_reason(exc)}); a replacement is written into the file as it is, so one that repeats "
                           "another option's name in another case can break how it reads") from exc
        sections = [rewrite(section) for section in old]
        if list(new) != sections:
            raise _refused(f"{where}: read with {label}, the transformed file does not read as the original with only "
                           f"the reviewed replacements applied to its names and values (it holds the sections "
                           f"{_shown(list(new))}, expected {_shown(sections)})")
        for section, options in old.items():
            named: dict[str, str] = {}
            expected: dict[str, Any] = {}
            for option, value in options.items():
                renamed = fold(rewrite(written[section].get(option, option)))
                if named.setdefault(renamed, option) != option:
                    raise _refused(f"{where}: read with {label}, the replacements make the options "
                                   f"{written[section].get(named[renamed], named[renamed])!r} and "
                                   f"{written[section].get(option, option)!r} of [{section}] the same "
                                   f"option {renamed!r}, so one would hide the other")
                expected[renamed] = value if isinstance(value, _Unreadable) else rewrite(value)
            found = new[rewrite(section)]
            difference = None
            if list(found) != list(expected):
                difference = f"[{section}] holds the options {_shown(list(found))}, expected {_shown(list(expected))}"
            for option, want in expected.items():
                got = found.get(option)
                if difference or isinstance(want, _Unreadable):
                    continue
                if isinstance(got, _Unreadable):
                    difference = (f"[{section}] {option} cannot be interpolated ({got.reason}), "
                                  f"expected {_shown(want)}")
                elif got != want:
                    difference = f"[{section}] {option} reads as {_shown(got)}, expected {_shown(want)}"
            if difference:
                raise _refused(f"{where}: read with {label}, the transformed file does not read as the original with "
                               f"only the reviewed replacements applied to its names and values ({difference})")


def _check_parsed(kind: str, where: str, text: str, new_text: str, originals: list[str], listed: set[str],
                  replacement_of: dict[str, str]) -> None:
    """Refuse unless the transformed *kind* file is the original with the reviewed replacements applied.

    Both files are parsed. The value expected of the result is the original's, with every string in
    it, keys and section and option names included, rewritten by the same reviewed replacements the
    raw edit applied to the text, and the result must equal it under :func:`_difference`: the same
    keys in the same order, of the same types, nested the same way, so a replacement that breaks the
    syntax, injects or merges a key, or changes what a value means is refused. An original that does
    not parse cannot be verified and is refused too. Only what the parser reads is compared: a
    comment, or the whitespace between values, is not.
    """
    name, phrase, parse = _PARSERS[kind]
    label = f"{where} (a parsed string)"

    def rewrite(string: str) -> str:
        return _replaced(string, [span for span in _spans(string, originals, label) if span[2] in listed],
                         replacement_of)

    try:
        before = parse(text)
    except _PARSE_ERRORS as exc:
        raise _refused(f"{where} is not {phrase}, so an edit of it cannot be verified to keep its structure "
                       f"({_reason(exc)})") from exc
    try:
        expected = _rewritten(before, rewrite, where)
        try:
            after = parse(new_text)
        except _PARSE_ERRORS as exc:
            raise _refused(f"{where}: the transformed file is not valid {name} ({_reason(exc)}); replacements are "
                           "written into the file as they are, without quoting or escaping, so one holding a "
                           "quotation mark, a backslash, or another delimiter can break it") from exc
        difference = _difference(expected, after)
    except RecursionError:
        raise _refused(f"{where} is nested too deeply for its structure to be compared") from None
    if difference:
        raise _refused(f"{where}: the transformed file does not keep the original's structure: it is not the "
                       f"original with only the reviewed replacements applied to its keys and strings ({difference})")
    if kind == "ini":
        _check_ini_readings(where, text, new_text, rewrite)


def _edit_for(document: dict, edit: dict, snapshot_id: str, source: Path, hashes: dict[str, str]) -> _Edit:
    """Check one edit against one original export and compute its result, writing nothing."""
    where = f"edit {edit['edit_id']}: {edit['path']}"
    expected = next(entry for entry in edit["expected"] if entry["snapshot_id"] == snapshot_id)
    path = edit["path"]
    exported = source / path
    if expected["state"] == "absent":
        if path in hashes or exported.exists() or exported.is_symlink():
            raise MaterializationError(f"stale map: {where} is expected to be absent from snapshot "
                                       f"{snapshot_id}, but the export holds it")
        return _Edit(edit["edit_id"], path, False)
    if path not in hashes or exported.is_symlink() or not exported.is_file():
        raise MaterializationError(f"stale map: {where} is expected in snapshot {snapshot_id}, but the "
                                   "export holds no regular file there")
    if hashes[path] != expected["file_sha256"]:
        raise MaterializationError(f"stale map: {where} is expected at {expected['file_sha256']} in "
                                   f"snapshot {snapshot_id}, but the export holds {hashes[path]}")
    raw = exported.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _refused(f"{where} is not strict UTF-8 text ({exc}); only text can be edited") from exc
    originals = [pseudonym["original"] for pseudonym in document["pseudonyms"]]
    replacement_of = {pseudonym["original"]: pseudonym["replacement"] for pseudonym in document["pseudonyms"]}
    listed = set(edit["replacements"])
    spans = _spans(text, originals, where)
    found = {token: sum(1 for _, _, name in spans if name == token) for token in originals}
    counts = {token: found[token] for token in edit["replacements"]}
    if counts != expected["occurrences"]:
        raise _refused(f"{where}: unexpected occurrence count in snapshot {snapshot_id}: the map "
                       f"reviewed {dict(sorted(expected['occurrences'].items()))}, the file holds "
                       f"{dict(sorted(counts.items()))}")
    replaced = [span for span in spans if span[2] in listed]
    new_text = _replaced(text, replaced, replacement_of)
    # Every replaced original must be gone and every other original exactly as often as before: a
    # replacement that spells an original together with the text beside it would put back the
    # identity it removes, or add one nobody reviewed.
    formed = sorted(token for token in originals
                    if len(_starts(new_text, token)) != (0 if token in listed else found[token]))
    if formed:
        raise _refused(f"{where}: replacing forms {formed[0]!r} again with the text beside it, so the "
                       "transformed file would not hold what the map reviewed")
    # Line identity, verified rather than assumed: the same line count by every reading of a line
    # break, and each line of the result is that same line of the original with its own reviewed
    # occurrences replaced, so line n of the transformed file is line n of the original.
    old_lines, new_lines = text.split("\n"), new_text.split("\n")
    remapped = [_replaced(line, [span for span in _spans(line, originals, where) if span[2] in listed],
                          replacement_of) for line in old_lines]
    if (len(old_lines) != len(new_lines) or remapped != new_lines
            or len(text.splitlines()) != len(new_text.splitlines())):
        raise _refused(f"{where}: the replacement would move a line, so claim locations could not be "
                       "mapped back to the original export")
    # A JSON, TOML, INI, or YAML display file must also keep its structure, as a parser reads it.
    # Anything else is not asked.
    check = _structure_check_for(path)
    if check is not None:
        _check_parsed(check, where, text, new_text, originals, listed, replacement_of)
    data = new_text.encode("utf-8")
    changed = tuple(index + 1 for index, (old, new) in enumerate(zip(old_lines, new_lines)) if old != new)
    return _Edit(edit["edit_id"], path, True, hashes[path], data,
                 f"sha256:{hashlib.sha256(data).hexdigest()}", counts, changed, _line_count(text), check)


# --- the blinded export --------------------------------------------------------------------------


# The limits a blinded preparation record states, in place of the standard profile's.
BLINDED_LIMITS = [
    "Export removes original git history and controller state; it is not a sandbox.",
    "Tracked regular files only: submodules and symbolic links are recorded as skipped.",
    "Metadata blinding replaced reviewed identity tokens in documentation and display metadata "
    "only; package names, imports, source identifiers, paths, and recognizable code are unchanged "
    "and may still reveal the repository. It is not anonymization.",
    "Instruction files are never edited by blinding and are recorded as retained identity cues.",
    "The original export under original/source is evaluator-side and is never handed to a scanner.",
    "JSON, TOML, INI, and YAML display files within the block subset read here are verified by parsing them before "
    "and after the edit, and a YAML file outside that subset is refused; nothing else a scanner may read is "
    "re-validated.",
]


def _passed(check: str, detail: str) -> dict:
    return {"check": check, "result": "pass", "detail": detail}


def _preflight(document: dict, snapshot_id: str | None, snapshot: CachedSnapshot, *,
               approval_required: bool) -> tuple[dict, list[dict]]:
    """Every check that needs no export: the contract, approval, repository, variant, and paths.

    Run before anything is written, so a map refused for any of these leaves no trial behind.
    """
    validate_document(MAP_KIND, document)
    if not snapshot_id:
        raise MaterializationError(
            "a metadata-blinded export needs the pack snapshot id its map's variants are keyed by")
    validation = [_passed("map_contract", f"{MAP_KIND} {_named(document)}, content {content_digest(document)}")]
    gap = approval_gap(document)
    if gap is None:
        latest = document["reviews"][-1]
        validation.append(_passed("approval", f"the latest review, by {latest['reviewer']} "
                                              f"({latest['role']}) at {latest['at']}, approves this content"))
    elif approval_required:
        raise _refused(gap)
    if document["repository"]["url"] != snapshot.url:
        raise _refused(f"{_named(document)} is for repository {document['repository']['url']}, but snapshot "
                       f"{snapshot_id} is fetched from {snapshot.url}")
    validation.append(_passed("repository", snapshot.url))
    variant = _variant(document, snapshot_id, snapshot.commit)
    validation.append(_passed("variant_commit", f"{snapshot_id} at {snapshot.commit}"))
    for edit in document["edits"]:
        gap = path_class_gap(edit["path"], edit["role"], edit.get("role_check"))
        if gap:
            raise _refused(f"edit {edit['edit_id']}: {gap}")
        validation.append(_passed("edit_path_class", f"{edit['edit_id']}: {edit['path']} as {edit['role']}"))
    return variant, validation


def _write_transformed(original_source: Path, source: Path, original: ExportedTree,
                       edits: list[_Edit]) -> ExportedTree:
    """Copy the original export to *source*, write the edits, and verify the result.

    Verified, not assumed: the transformed tree holds exactly the original export's paths, every
    file no edit names is byte-identical to the original, every edited file holds exactly the
    bytes computed for it, and every file keeps its mode. Anything that fails, or is interrupted,
    after *source* is created removes it whole, so a refused transformation never leaves a
    half-blinded tree where a scanner's input belongs. *source* must not exist yet; a directory
    that already does is refused by ``mkdir`` before anything could remove it.
    """
    changed = {edit.path: edit for edit in edits if edit.present}

    def mode(root: Path, relative: str) -> int:
        return stat.S_IMODE(os.stat(root / relative).st_mode)

    source.mkdir(parents=True)
    try:
        for relative in sorted(original.hashes):
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original_source / relative, target)
            os.chmod(target, mode(original_source, relative))
        for path, edit in changed.items():
            (source / path).write_bytes(edit.data)
        hashes: dict[str, str] = {}
        byte_count = 0
        for relative, file in sorted(walk_regular_files(source).items()):
            digest, size = sha256_file(file)
            hashes[relative] = digest
            byte_count += size
        expected = {**original.hashes, **{path: edit.transformed_sha256 for path, edit in changed.items()}}
        if hashes != expected:
            differing = {path for path in hashes.keys() & expected.keys() if hashes[path] != expected[path]}
            wrong = sorted((hashes.keys() ^ expected.keys()) | differing)
            raise MaterializationError("the transformed tree is not the original export with the reviewed "
                                       f"edits: {', '.join(wrong[:5])}")
        moved = [path for path in sorted(hashes) if mode(source, path) != mode(original_source, path)]
        if moved:
            raise MaterializationError(f"a transformed file changed its mode: {', '.join(moved[:5])}")
    except BaseException:
        shutil.rmtree(source, ignore_errors=True)
        raise
    return ExportedTree(hashes, list(original.stripped), list(original.skipped),
                        _instruction_files(hashes, original.instruction_files), byte_count)


def _retained_cues(document: dict, source: Path, paths: list[str], instruction_files: list[str]) -> dict:
    """How much of the declared identity is still in the tree a scanner is handed.

    Every regular file is read, edited or not, and every original is counted wherever it still
    occurs, ignoring the case of ASCII letters: a package name the map deliberately left alone is
    as much a cue as a missed brand. Counts are per original, so one occurrence of a phrase holding
    two originals counts for both. Instruction files are listed because they stay as exported.
    """
    needles = [(pseudonym["original"], pseudonym["original"].encode("utf-8").lower())
               for pseudonym in document["pseudonyms"]]
    totals = {token: 0 for token, _ in needles}
    per_path: dict[str, int] = {}
    for relative in sorted(paths):
        data = (source / relative).read_bytes().lower()
        found = 0
        for token, needle in needles:
            count = data.count(needle)
            totals[token] += count
            found += count
        if found:
            per_path[relative] = found
    ranked = sorted(per_path.items(), key=lambda item: (-item[1], item[0]))[:CUE_PATH_LIMIT]
    return {"token_count": sum(1 for count in totals.values() if count),
            "total_occurrences": sum(totals.values()),
            "path_count": len(per_path),
            "paths": [{"path": path, "count": count} for path, count in ranked],
            "instruction_files": list(instruction_files)}


def _blind(snapshot: CachedSnapshot, trial_dir: Path, document: dict, *, snapshot_id: str | None,
           clock: Callable[[], datetime] | None, approval_required: bool, variant_dir: str = "") -> dict:
    """Export the original, check the map against it, write the transformed tree, and record it all.

    *variant_dir* names where this snapshot's trees sit beneath the trial directory: ``""`` for the
    input's own snapshot, the transformed tree at ``source`` and the original at
    ``original/source``, and for the base of a PR input ``"base"``, the transformed tree at
    ``base/source`` and the original at ``original/base/source``. The original stays under
    ``original`` in both, which is the one place nothing is ever handed to a scanner from.
    """
    variant, validation = _preflight(document, snapshot_id, snapshot, approval_required=approval_required)
    source = trial_dir / variant_dir / "source"
    original_root = str(PurePosixPath("original") / variant_dir / "source")
    original_source = trial_dir / original_root
    for directory in (source, original_source):
        if directory.exists() or directory.is_symlink():
            raise MaterializationError(f"trial source directory already exists: {directory}")
    original = export_tree(snapshot, original_source)
    original_hash = tree_hash(original.hashes)
    if variant["tree_hash"] != original_hash:
        raise MaterializationError(
            f"stale map: {_named(document)} records snapshot {snapshot_id} as tree {variant['tree_hash']}, "
            f"but its export is {original_hash}")
    validation.append(_passed("variant_tree", original_hash))
    edits = [_edit_for(document, edit, snapshot_id, original_source, original.hashes)
             for edit in document["edits"]]
    for edit in edits:
        if not edit.present:
            validation.append(_passed("edit_absent", f"{edit.edit_id}: {edit.path} is absent, as expected"))
            continue
        validation += [
            _passed("edit_file_hash", f"{edit.edit_id}: {edit.path} is {edit.original_sha256}, as expected"),
            _passed("edit_occurrences", f"{edit.edit_id}: {dict(sorted(edit.occurrences.items()))}, as "
                                        "reviewed, with no ambiguous or overlapping match"),
            _passed("edit_line_structure", f"{edit.edit_id}: {edit.line_count} line(s) before and after; "
                                           "each line maps to the same line"),
        ]
        if edit.structure_check is not None:
            detail = _STRUCTURE_DETAILS[edit.structure_check]
            validation.append(_passed("edit_structure", f"{edit.edit_id}: {detail}"))
    transformed = _write_transformed(original_source, source, original, edits)
    unedited = len(original.hashes) - sum(1 for edit in edits if edit.present)
    validation.append(_passed("unedited_files_unchanged",
                              f"{unedited} file(s) byte-identical to the original export"))
    record = provenance_record(snapshot, "metadata_blinded", transformed, clock=clock)
    record["schema_version"] = SCHEMA_VERSION
    record["limits"] = list(BLINDED_LIMITS)
    if variant_dir:
        record["trial"]["root"] = str(PurePosixPath(variant_dir) / "source")
    record["original"] = {"root": original_root, "tree_hash": original_hash,
                          "file_count": len(original.hashes), "byte_count": original.byte_count}
    record["blinding"] = {
        **map_identity(document),
        "content_sha256": content_digest(document),
        "reviewers": approving_reviews(document),
        "original_tree_hash": original_hash,
        "transformed_tree_hash": record["trial"]["tree_hash"],
        "edits": [{"edit_id": edit.edit_id, "path": edit.path, "changed_lines": list(edit.changed_lines),
                   "occurrences": dict(edit.occurrences), "original_sha256": edit.original_sha256,
                   "transformed_sha256": edit.transformed_sha256} for edit in edits if edit.present],
        "validation": validation,
        "retained_identity_cues": _retained_cues(document, source, sorted(transformed.hashes),
                                                 transformed.instruction_files),
        "location_remapping": {"lines": "identity", "paths": "identity",
                               "verified_paths": sorted(edit.path for edit in edits if edit.present)},
    }
    return record


def preflight(document: dict, snapshot_id: str | None, snapshot: CachedSnapshot) -> None:
    """Ask *document* every question about one snapshot that needs no export, refusing as a run would.

    The contract, approval, repository, variant commit, and edit path classes: everything
    :func:`export_blinded` checks before it writes a tree. An input made of two snapshots, the base
    and the head of a PR, asks it of both before either is exported, so a map that is unapproved,
    for another repository, or stale for either snapshot leaves no half-blinded input behind. What
    needs an export, the tree hash and each expected file, is still asked of each variant as it is
    exported. Writes nothing.
    """
    _preflight(document, snapshot_id, snapshot, approval_required=True)


def export_blinded(snapshot: CachedSnapshot, trial_dir: Path, document: dict, *,
                   snapshot_id: str | None, clock: Callable[[], datetime] | None = None,
                   variant_dir: str = "") -> dict:
    """Export *snapshot* blinded by *document*: the original to ``original/source``, the result to ``source``.

    A PR input blinds its base with the map that blinded its head, so the same function writes the
    base under *variant_dir* ``"base"``: the transformed tree to ``base/source`` and the original to
    ``original/base/source``. Every check below is asked of each variant on its own, and the map
    must cover both snapshots.

    Returns the preparation record (``schema_version`` 2.1): the standard fields describe the
    transformed tree a scanner is handed, ``original`` describes the original export the labels
    and mechanical checks refer to, and ``blinding`` records the map identity, the approving
    reviewers, both tree hashes, every edit with the lines it changed, every check that passed,
    the identity cues that remain, and that line and path locations map to the original as the
    identity. Every refusal is raised before ``source`` exists; see the module docstring for the
    list. The map must be approved: :func:`dry_run` is the one path that reports approval instead.
    """
    return _blind(snapshot, Path(trial_dir), document, snapshot_id=snapshot_id, clock=clock,
                  approval_required=True, variant_dir=variant_dir)


def dry_run(document: dict, snapshot: CachedSnapshot, snapshot_id: str, workdir: Path, *,
            clock: Callable[[], datetime] | None = None) -> dict:
    """Apply *document* to one variant inside *workdir* exactly as a run would, approval aside.

    Everything :func:`export_blinded` checks is checked, except that an unapproved map is reported
    rather than refused, so a curator can check a map before anyone reviews it; whether it is
    approved is :func:`approval_gap`. Returns the record a run would write. Writes nothing outside
    *workdir* and never modifies the map. What this returns is never a scan input.
    """
    return _blind(snapshot, Path(workdir), document, snapshot_id=snapshot_id, clock=clock,
                  approval_required=False)
