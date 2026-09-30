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
reviewed; a replacement would form an original again with the text beside it; or a line would move.
Only then is the original export copied and the reviewed occurrences replaced, and the result is
verified: every file the map does not edit is byte-identical to the original export, every file
keeps its mode, every edited file keeps its line structure, and line ``n`` of an edited file is
line ``n`` of the original with the reviewed tokens replaced. Claim locations therefore map back
to the original export as the identity, which is what lets labels written against the original
score a blinded run.

What this does not do: parse source, discover identity cues on its own, decide whether a field is
read at runtime (a ``display_metadata`` edit carries the reviewer's stated ``role_check`` for that),
or establish that a scanner cannot recognize the repository.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
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
# Attribution files named for whose code they credit, wherever in the name the words fall.
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
    """One edit as it applies to one variant, computed and verified before anything is written."""

    edit_id: str
    path: str
    present: bool
    original_sha256: str | None = None
    data: bytes | None = None
    transformed_sha256: str | None = None
    occurrences: dict | None = None
    changed_lines: tuple[int, ...] = ()
    line_count: int = 0


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
    data = new_text.encode("utf-8")
    changed = tuple(index + 1 for index, (old, new) in enumerate(zip(old_lines, new_lines)) if old != new)
    return _Edit(edit["edit_id"], path, True, hashes[path], data,
                 f"sha256:{hashlib.sha256(data).hexdigest()}", counts, changed, _line_count(text))


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
