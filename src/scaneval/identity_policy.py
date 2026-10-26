"""Strict identity-reduction policy helpers; evaluator-side data never enters source trees.

Metadata edits are deliberately narrow. A reviewer selects one identity-only URL field and pins
the complete original file. The field is parsed before and after replacing one unambiguous raw
string token. The complete parsed result must differ only at that leaf; all bytes outside the
token and every physical line boundary remain unchanged. Repository code is never executed.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal
from functools import lru_cache
import hashlib
from importlib.resources import files
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tomllib
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

from .contracts import (ContractError, canonical_json, canonical_sha256, is_stated, load_document,
                         validate_document)
from .materialize import (INSTRUCTION_FILE_NAMES, INSTRUCTION_PATH_PREFIXES, INSTRUCTION_PATHS,
                          INSTRUCTION_TOP_LEVEL, MaterializationError, tree_hash)


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LINE_BREAK = re.compile(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")
_JSON_FIELDS = frozenset({("repository",), ("repository", "url"), ("homepage",),
                          ("bugs",), ("bugs", "url")})
POLICY_ID = "scaneval.identity-reduced"
POLICY_VERSION = "1"
MANIFEST_KIND = "identity-transformation-manifest"
MANIFEST_NAME = "identity-transform.json"
_ALIAS_CATEGORIES = frozenset({"target_alias", "advisory_url", "answer_alias"})
_ARTIFACT_CATEGORIES = frozenset({"evaluator_evidence", "redaction_dictionary", "transformation_manifest"})
_TEXT_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".txt", ".adoc", ".asciidoc", ".org", ".mdc"})


class IdentityConditionUnavailable(MaterializationError):
    """An explicit strict policy failed; evaluator-side refusal evidence has been saved."""

    def __init__(self, summary: dict, provenance_path: Path | None = None):
        self.summary = deepcopy(summary)
        self.provenance_path = provenance_path
        super().__init__("strict identity-reduced condition unavailable: " + "; ".join(summary["validation"]["reasons"]))


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _refuse(message: str) -> MaterializationError:
    return MaterializationError("identity policy refused: " + message)


def _strict_text(value: str, where: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise _refuse(f"metadata values must be strict UTF-8 strings ({where})") from exc


def _path(path: str) -> PurePosixPath:
    if (not isinstance(path, str) or not path or "\\" in path or "\x00" in path
            or re.match(r"^[A-Za-z]:", path)):
        raise _refuse("a file path must be a normalized relative POSIX path")
    _strict_text(path, "path")
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in path.split("/")):
        raise _refuse("a file path must be a normalized relative POSIX path")
    return pure


def _metadata_format(path: str, field_path: tuple[str, ...]) -> str:
    pure = _path(path)
    folded = tuple(part.casefold() for part in pure.parts)
    if any(part in {".git", ".hg", ".svn", ".circleci", "licenses"} for part in folded[:-1]):
        raise _refuse(f"{path} is in protected repository, CI, or license material")
    if any(folded[index:index + 2] in {(".github", "workflows"), (".github", "actions"),
                                      (".github", "codeql")} for index in range(len(folded) - 2)):
        raise _refuse(f"{path} is in protected CI material")
    if pure.name.casefold() == "package.json" and field_path in _JSON_FIELDS:
        return "json"
    if (pure.name.casefold() == "pyproject.toml" and len(field_path) == 3
            and field_path[:2] == ("project", "urls") and is_stated(field_path[2])):
        return "toml"
    raise _refuse(
        f"{path} {list(field_path)!r} is not a supported identity-only metadata field; only package.json "
        "homepage/repository/bugs URL strings and pyproject.toml project.urls strings are supported")


def _json_object(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-JSON constant {value}")


def _parse(text: str, format_: str, *, label: str = "metadata file") -> Any:
    try:
        if format_ == "json":
            return json.loads(text, object_pairs_hook=_json_object, parse_float=Decimal,
                              parse_constant=_reject_json_constant)
        return tomllib.loads(text)
    except (ValueError, RecursionError) as exc:
        raise _refuse(f"the {label} is not valid strict {format_.upper()}: {exc}") from exc


def _leaf(tree: Any, field_path: tuple[str, ...]) -> tuple[dict, str]:
    current = tree
    for part in field_path[:-1]:
        if not isinstance(current, dict) or part not in current:
            raise _refuse(f"metadata field {list(field_path)!r} is absent")
        current = current[part]
    if not isinstance(current, dict) or field_path[-1] not in current:
        raise _refuse(f"metadata field {list(field_path)!r} is absent")
    return current, field_path[-1]


def _same_tree(one: Any, two: Any) -> bool:
    if type(one) is not type(two):
        return False
    if isinstance(one, dict):
        return list(one) == list(two) and all(_same_tree(one[key], two[key]) for key in one)
    if isinstance(one, list):
        return len(one) == len(two) and all(_same_tree(a, b) for a, b in zip(one, two))
    if isinstance(one, float) and math.isnan(one) and math.isnan(two):
        return True
    return one == two


@dataclass(frozen=True)
class MetadataEdit:
    """Verified replacement bytes and the evaluator-side record of one selected leaf."""

    data: bytes
    record: dict


@dataclass(frozen=True)
class MetadataFile:
    """One file with all of its disjoint, independently verified metadata leaf edits applied."""

    data: bytes
    records: list[dict]


def prepare_metadata_edit(data: bytes | bytearray, *, path: str, field_path: list[str] | tuple[str, ...],
                          expected_sha256: str, original: str, replacement: str,
                          role_check: str, raw_token: str | None = None) -> MetadataEdit:
    """Prepare a hash-pinned identity metadata edit, without writing any file.

    ``field_path`` is a list of parsed object keys, never a dotted selector or JSONPath.
    ``raw_token`` optionally spells the exact reviewed quoted token, useful for a TOML literal
    string or a JSON string with escapes. Its decoded value must be ``original``. Ambiguous
    tokens, missing fields, non-string leaves, and any broader parsed change are refused.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise _refuse("metadata data must be bytes or bytearray")
    data = bytes(data)
    if (not isinstance(field_path, (list, tuple)) or not field_path
            or not all(isinstance(part, str) for part in field_path)):
        raise _refuse("field_path must be a nonempty list of string keys")
    keys = tuple(field_path)
    for key in keys:
        _strict_text(key, "field_path")
    format_ = _metadata_format(path, keys)
    if not isinstance(role_check, str) or not is_stated(role_check):
        raise _refuse("an identity metadata edit must state why the field has no runtime role")
    _strict_text(role_check, "role_check")
    if (not isinstance(original, str) or not is_stated(original) or not isinstance(replacement, str)
            or _LINE_BREAK.search(original) or _LINE_BREAK.search(replacement)):
        raise _refuse("original and replacement must be single-line strings and original must be stated")
    if original == replacement:
        raise _refuse("an identity metadata edit must change its selected value")
    _strict_text(original, "original")
    _strict_text(replacement, "replacement")
    if not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256):
        raise _refuse("an identity metadata edit must pin the original file SHA-256")
    digest = _sha256(data)
    if digest != expected_sha256:
        raise _refuse(f"stale metadata edit: {path} is {digest}, expected {expected_sha256}")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _refuse(f"{path} is not strict UTF-8") from exc
    before = _parse(text, format_)
    parent, key = _leaf(before, keys)
    if type(parent[key]) is not str or parent[key] != original:
        raise _refuse(f"{path} {list(keys)!r} does not hold the reviewed string value")
    token = json.dumps(original, ensure_ascii=False) if raw_token is None else raw_token
    if not isinstance(token, str) or not token or _LINE_BREAK.search(token):
        raise _refuse("the reviewed raw token must be a single-line quoted string")
    _strict_text(token, "raw_token")
    if format_ == "json":
        decoded = _parse(token, "json", label="reviewed raw token")
        quoted = token.startswith('"') and token.endswith('"')
    else:
        quoted = bool(re.fullmatch(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", token))
        decoded = _parse("value = " + token, "toml", label="reviewed raw token")
        if not isinstance(decoded, dict) or list(decoded) != ["value"]:
            raise _refuse("the reviewed raw token is not one TOML string")
        decoded = decoded["value"]
    if not quoted or type(decoded) is not str or decoded != original:
        raise _refuse("the reviewed raw token does not encode the selected string value")
    start = text.find(token)
    if start < 0:
        raise _refuse("the reviewed raw token is absent; its exact spelling is required")
    if text.rfind(token) != start:
        raise _refuse("the reviewed raw token is ambiguous; duplicate occurrences cannot be safely selected")
    encoded = json.dumps(replacement, ensure_ascii=False)
    changed = text[:start] + encoded + text[start + len(token):]
    expected = deepcopy(before)
    selected, selected_key = _leaf(expected, keys)
    selected[selected_key] = replacement
    after = _parse(changed, format_, label="transformed metadata file")
    if not _same_tree(expected, after):
        raise _refuse("the token replacement changes something other than the selected metadata leaf")
    if _LINE_BREAK.findall(text) != _LINE_BREAK.findall(changed):
        raise _refuse("the token replacement changes physical line boundaries")
    output = changed.encode("utf-8")
    return MetadataEdit(output, {
        "path": path, "field_path": list(keys), "format": format_, "original_sha256": digest,
        "transformed_sha256": _sha256(output), "redactions": 1,
        "changed_lines": [len(_LINE_BREAK.findall(text[:start])) + 1], "role_check": role_check,
    })


def validate_metadata_selector(path: str, field_path: list[str]) -> str:
    """The supported format of a parsed metadata selector, or a controlled policy refusal."""
    if not isinstance(field_path, list) or not field_path or not all(isinstance(key, str) for key in field_path):
        raise _refuse("field_path must be a nonempty list of string keys")
    for key in field_path:
        _strict_text(key, "field_path")
    return _metadata_format(path, tuple(field_path))


def prepare_metadata_file(data: bytes | bytearray, edits: list[dict]) -> MetadataFile:
    """Combine distinct leaf changes prepared against the same original bytes, without writing.

    Every individual edit must be safe on the original file. A duplicate raw token still refuses
    the batch rather than guessing its position. After disjoint byte changes are combined, the
    complete parsed tree is verified again with exactly the selected leaves changed.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise _refuse("metadata data must be bytes or bytearray")
    if not isinstance(edits, list) or not edits:
        raise ContractError("a metadata file needs a nonempty list of edits")
    allowed = {"path", "field_path", "expected_sha256", "original", "replacement", "role_check", "raw_token",
               "edit_id", "rationale"}
    required = {"path", "field_path", "expected_sha256", "original", "replacement", "role_check"}
    original = bytes(data)
    prepared, spans, selectors, path = [], [], set(), None
    for entry in edits:
        _object(entry, allowed=allowed, required=required, where="metadata edit")
        change = prepare_metadata_edit(original, **{key: value for key, value in entry.items()
                                                   if key not in {"edit_id", "rationale"}})
        selector = tuple(change.record["field_path"])
        if selector in selectors or path is not None and entry["path"] != path:
            raise ContractError("a metadata file batch must select distinct leaves in one file")
        selectors.add(selector)
        path = entry["path"]
        prefix, limit = 0, min(len(original), len(change.data))
        while prefix < limit and original[prefix] == change.data[prefix]:
            prefix += 1
        suffix = 0
        while suffix < limit - prefix and original[-1 - suffix] == change.data[-1 - suffix]:
            suffix += 1
        end = len(original) - suffix
        replacement_end = len(change.data) - suffix
        spans.append((prefix, end, change.data[prefix:replacement_end]))
        record = deepcopy(change.record)
        record.update({key: entry[key] for key in ("edit_id", "rationale") if key in entry})
        prepared.append((entry, record))
    parts, cursor = [], 0
    for start, end, replacement in sorted(spans):
        if start < cursor:
            raise _refuse("metadata leaf changes overlap in the original file")
        parts.extend((original[cursor:start], replacement))
        cursor = end
    parts.append(original[cursor:])
    output = b"".join(parts)
    format_ = prepared[0][1]["format"]
    expected = _parse(original.decode("utf-8"), format_)
    for entry, _ in prepared:
        parent, key = _leaf(expected, tuple(entry["field_path"]))
        parent[key] = entry["replacement"]
    if not _same_tree(expected, _parse(output.decode("utf-8"), format_, label="combined metadata file")):
        raise _refuse("combined metadata edits change more than their selected leaves")
    records = []
    for _, record in prepared:
        record["transformed_sha256"] = _sha256(output)
        records.append(record)
    return MetadataFile(output, sorted(records, key=canonical_json))


def _object(value: Any, *, allowed: set[str], required: set[str], where: str) -> None:
    if not isinstance(value, dict) or set(value) - allowed or required - set(value):
        raise ContractError(f"{where} must be an object with required keys {sorted(required)} and "
                            f"only keys {sorted(allowed)}")


def _strings(values: Any, where: str) -> list[str]:
    if not isinstance(values, list):
        raise ContractError(f"{where} must be a list of stated single-line strings")
    for value in values:
        if not isinstance(value, str) or not is_stated(value) or _LINE_BREAK.search(value):
            raise ContractError(f"{where} must contain stated single-line strings")
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ContractError(f"{where} must contain strict UTF-8 strings") from exc
    if len({value.casefold() for value in values}) != len(values):
        raise ContractError(f"{where} must be unique ignoring case")
    return sorted(values, key=lambda value: (value.casefold(), value))


def _aliases(values: Any, where: str) -> list[dict]:
    if not isinstance(values, list):
        raise ContractError(f"{where} must be a list")
    rows, seen = [], set()
    for index, entry in enumerate(values):
        label = f"{where}[{index}]"
        _object(entry, allowed={"category", "value", "forms"}, required={"category", "value"}, where=label)
        if not isinstance(entry["category"], str) or entry["category"] not in _ALIAS_CATEGORIES:
            raise ContractError(f"{label}.category must be one of {sorted(_ALIAS_CATEGORIES)}")
        value = _strings([entry["value"]], f"{label}.value")[0]
        forms = _strings(entry.get("forms", []), f"{label}.forms")
        if value.casefold() in {form.casefold() for form in forms}:
            raise ContractError(f"{label}.forms repeats its canonical value")
        if value.casefold() in seen:
            raise ContractError(f"{where} values must be unique ignoring case")
        seen.add(value.casefold())
        rows.append({"category": entry["category"], "value": value, "forms": forms})
    return sorted(rows, key=lambda row: (row["category"], row["value"].casefold(), row["value"]))


def validate_policy(policy: dict) -> dict:
    """Validate and normalize the explicit strict policy, without modifying its input.

    Answer aliases must be declared even when the list is empty. Their coverage is checked
    separately against evaluator-side pack requirements; absence from the source is not enough
    to excuse an omitted declaration. Configured instruction paths declare cues, never permission
    to remove executable code or configuration.
    """
    _object(policy, allowed={"policy_id", "version", "answer_aliases", "instruction_paths",
                             "forbidden_artifacts", "identity_tokens"},
            required={"policy_id", "version", "answer_aliases"}, where="identity policy")
    if policy["policy_id"] != POLICY_ID or policy["version"] != POLICY_VERSION:
        raise ContractError(f"unsupported identity policy; expected {POLICY_ID} version {POLICY_VERSION}")
    paths = _strings(policy.get("instruction_paths", []), "instruction_paths")
    for path in paths:
        try:
            _path(path)
        except MaterializationError as exc:
            raise ContractError(f"instruction_paths: {exc}") from exc
    artifacts = policy.get("forbidden_artifacts", [])
    if not isinstance(artifacts, list):
        raise ContractError("forbidden_artifacts must be a list")
    normalized = []
    for index, entry in enumerate(artifacts):
        label = f"forbidden_artifacts[{index}]"
        _object(entry, allowed={"category", "path", "sha256"}, required={"category"}, where=label)
        if (not isinstance(entry["category"], str) or entry["category"] not in _ARTIFACT_CATEGORIES
                or not ({"path", "sha256"} & set(entry))):
            raise ContractError(f"{label} must state an evaluator artifact category and a path or SHA-256")
        if "path" in entry:
            try:
                _path(entry["path"])
            except MaterializationError as exc:
                raise ContractError(f"{label}: {exc}") from exc
        if "sha256" in entry and (not isinstance(entry["sha256"], str) or not _DIGEST.fullmatch(entry["sha256"])):
            raise ContractError(f"{label}.sha256 must be a SHA-256 digest")
        normalized.append(deepcopy(entry))
    if len({canonical_json(entry) for entry in normalized}) != len(normalized):
        raise ContractError("forbidden_artifacts entries must be unique")
    return {"policy_id": POLICY_ID, "version": POLICY_VERSION,
            "answer_aliases": _aliases(policy["answer_aliases"], "answer_aliases"),
            "instruction_paths": paths,
            "forbidden_artifacts": sorted(normalized, key=canonical_json),
            "identity_tokens": _strings(policy.get("identity_tokens", []), "identity_tokens")}


def required_answers(pack: dict, snapshot_ids: list[str]) -> list[dict]:
    """The aliases and advisory references of every case touching these snapshots.

    The caller supplies a validated pack. Requirements include fixed controls of a target, so
    its answer aliases cannot leak through the control condition. Normalized forms explicitly
    supplied by a dataset can additionally be passed to :func:`inspect_tree` as requirements.
    """
    selected, found = set(snapshot_ids), {}
    for case in pack["cases"]:
        snapshots = {case["target"]["snapshot_id"], *(item["snapshot_id"] for item in case["controls"])}
        if not selected & snapshots:
            continue
        for alias in case["canonical_target"]["aliases"]:
            found[alias.casefold()] = {"category": "target_alias", "value": alias, "forms": []}
        for evidence in case["evidence"]:
            if evidence["kind"] not in {"cve_record", "ghsa_advisory", "vendor_advisory"}:
                continue
            value = evidence["reference"]
            try:
                parsed = urlsplit(value)
                url = parsed.scheme in {"https", "http"} and bool(parsed.netloc)
            except ValueError:
                url = False
            category = "advisory_url" if url else "answer_alias"
            found.setdefault(value.casefold(), {"category": category, "value": value, "forms": []})
    return _aliases(list(found.values()), "required answers")


def snapshot_requirements(pack: dict, snapshot_id: str) -> tuple[list[dict], list[str]]:
    """Shared export/report requirements: answer aliases and accepted scoring paths for a snapshot."""
    from .blinding import scoring_paths
    return required_answers(pack, [snapshot_id]), scoring_paths(pack, snapshot_id)


def scanner_identity_gaps(value: Any, *, policy: dict, repository: dict, commits: list[str]) -> list[dict]:
    """Declared answers and upstream identity cues in scanner-visible identifiers/configuration.

    Qualified repository names, URLs, and revision tokens are checked independently of the
    reviewed pseudonyms. Short unqualified names are ambiguous with language/runtime settings;
    qualified names and declared identity tokens can still cover them explicitly.
    """
    normalized = validate_policy(policy)
    pending, strings, visited = [value], [], set()
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            strings.append(item.casefold())
        elif isinstance(item, (dict, list, tuple)) and id(item) not in visited:
            visited.add(id(item))
            if isinstance(item, dict):
                pending.extend(item.keys())
                pending.extend(item.values())
            else:
                pending.extend(item)
    needles = []
    for entry in normalized["answer_aliases"]:
        needles.extend((entry["category"], form, False) for form in [entry["value"], *entry["forms"]])
    names = {repository["url"]}
    name = repository["name"]
    if "/" in name or len(name) >= 4:
        names.add(name)
    if len(name.rsplit("/", 1)[-1]) >= 4:
        names.add(name.rsplit("/", 1)[-1])
    needles.extend(("repository_identity", name, True) for name in names)
    needles.extend(("repository_identity", token, True) for token in normalized["identity_tokens"])
    needles.extend(("upstream_revision", revision, True) for commit in commits
                   for revision in {commit, commit[:12], commit[:7]})
    found = {}
    for category, needle, bounded in needles:
        folded = needle.casefold()
        pattern = re.compile(r"(?<![^\W_])" + re.escape(folded) + r"(?![^\W_])") if bounded else None
        if any(pattern.search(text) if pattern else folded in text for text in strings):
            digest = canonical_sha256({"category": category, "value": needle})
            found[category, digest] = {"category": category, "cue_sha256": digest}
    return [found[key] for key in sorted(found)]


def policy_coverage(policy: dict | None, requirements: list[dict]) -> dict:
    """Whether an explicit reviewed policy declares every evaluator-side answer requirement."""
    required = _aliases(requirements, "required answers")
    if policy is None:
        return {"state": "unavailable", "reasons": ["no explicit strict identity policy was supplied"],
                "required_aliases": len(required), "declared_aliases": 0}
    normalized = validate_policy(policy)
    declared = {entry["value"].casefold(): entry for entry in normalized["answer_aliases"]}
    reasons = []
    for entry in required:
        match = declared.get(entry["value"].casefold())
        if match is None or match["category"] != entry["category"]:
            reasons.append("the policy does not declare required answer " + canonical_sha256(entry))
            continue
        forms = {match["value"].casefold(), *(form.casefold() for form in match["forms"])}
        if any(form.casefold() not in forms for form in entry["forms"]):
            reasons.append("the policy does not declare every required normalized form of " + canonical_sha256(entry))
    return {"state": "unavailable" if reasons else "available", "reasons": sorted(reasons),
            "required_aliases": len(required), "declared_aliases": len(declared)}


def _instruction_class(path: str, configured: set[str]) -> str | None:
    folded = path.casefold()
    pure = PurePosixPath(folded)
    named = pure.name in {name.casefold() for name in INSTRUCTION_FILE_NAMES} | {"claude.local.md"}
    roots = {part.casefold() for part in INSTRUCTION_TOP_LEVEL}
    within = (any(part in roots for part in pure.parts[:-1])
              or any(pure.parts[-len(PurePosixPath(part).parts):] == PurePosixPath(part.casefold()).parts
                     for part in INSTRUCTION_PATHS)
              or any(tuple(pure.parts[index:index + len(PurePosixPath(prefix).parts)])
                     == PurePosixPath(prefix.casefold()).parts
                     for prefix in INSTRUCTION_PATH_PREFIXES
                     for index in range(len(pure.parts) - len(PurePosixPath(prefix).parts))))
    explicit = folded in configured
    if not (named or within or explicit):
        return None
    textual = pure.suffix in _TEXT_SUFFIXES or pure.name in {"readme", "instructions"}
    if named or textual:
        return "instruction_file"
    return "unsafe_configured_instruction" if explicit else "assistant_support_file"


def instruction_inventory(paths, policy: dict | None = None) -> list[dict]:
    """Classify known, configured, and nested assistant files without granting removal permission."""
    configured = {path.casefold() for path in (policy or {}).get("instruction_paths", [])}
    return [{"path": path, "classification": classification} for path in sorted(paths)
            if (classification := _instruction_class(path, configured)) is not None]


def _tree_entries(root: Path):
    """Read only regular files through no-follow descriptors anchored to the export root."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK

    def names(descriptor):
        with os.scandir(descriptor) as directory:
            return sorted(entry.name for entry in directory)

    try:
        descriptor = os.open(Path(root), directory_flags)
    except OSError as exc:
        yield ".", None, f"the export root could not be opened safely: {exc.strerror}"
        return
    stack = [[descriptor, "", None, 0]]
    try:
        while stack:
            frame = stack[-1]
            descriptor, prefix = frame[:2]
            if frame[2] is None:
                try:
                    frame[2] = names(descriptor)
                except OSError as exc:
                    yield prefix.rstrip("/") or ".", None, f"directory entries could not be read safely: {exc.strerror}"
                    stack.pop()
                    os.close(descriptor)
                    continue
            if frame[3] == len(frame[2]):
                stack.pop()
                os.close(descriptor)
                continue
            name = frame[2][frame[3]]
            frame[3] += 1
            try:
                name.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                opaque = _sha256(os.fsencode(name)).split(":", 1)[1]
                yield prefix + f"[non-utf8-name-{opaque}]", None, "file names must be strict UTF-8"
                continue
            relative = prefix + name
            if name.casefold() in {".git", ".hg", ".svn", ".bzr", "cvs"}:
                yield relative, None, "original VCS directories and history are forbidden"
                continue
            try:
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    yield relative, None, "symbolic links are forbidden in a validated identity export"
                elif stat.S_ISDIR(info.st_mode):
                    child = os.open(name, directory_flags, dir_fd=descriptor)
                    if frame[3] == len(frame[2]):
                        stack.pop()
                        os.close(descriptor)
                    stack.append([child, relative + "/", None, 0])
                elif stat.S_ISREG(info.st_mode):
                    opened = os.open(name, file_flags, dir_fd=descriptor)
                    with os.fdopen(opened, "rb") as handle:
                        before = os.fstat(handle.fileno())
                        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                            yield relative, None, "the staged file changed while being opened"
                            continue
                        data = handle.read()
                        after = os.fstat(handle.fileno())
                    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                            after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        yield relative, None, "the staged file changed while being read"
                    else:
                        yield relative, data, None
                else:
                    yield relative, None, "special files are forbidden in a validated identity export"
            except OSError as exc:
                yield relative, None, f"the staged entry could not be read safely: {exc.strerror}"

    finally:
        for descriptor, *_ in stack:
            os.close(descriptor)


def _artifact_category(path: str, data: bytes) -> str | None:
    if PurePosixPath(path).name.casefold() == MANIFEST_NAME:
        return "transformation_manifest"
    if PurePosixPath(path).name.casefold() == "provenance.json":
        return "evaluator_evidence"
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(document, dict):
        return None
    keys = set(document)
    if document.get("kind") == MANIFEST_KIND or {"original_tree_hash", "transformed_tree_hash", "policy"} <= keys:
        return "transformation_manifest"
    if {"manifest_sha256", "config_sha256", "validation"} <= keys:
        return "transformation_manifest"
    if ({"map_id", "pseudonyms", "variants", "edits"} <= keys
            or document.get("policy_id") == POLICY_ID and "answer_aliases" in keys):
        return "redaction_dictionary"
    if any(required <= keys for required in (
            {"profile", "trial", "source"}, {"blinding", "original", "trial"},
            {"namespace", "pack_id", "snapshots", "cases"},
            {"canonical_target", "target", "evidence", "validation"},
            {"targets", "controls", "review_budgets", "input_hash"},
            {"claim_matches", "control_assessments", "result_sha256", "input_hash"})):
        return "evaluator_evidence"
    return None


def _cue(category: str, value: str, path: str, count: int, surface: str, reason: str) -> dict:
    return {"category": category, "cue_sha256": canonical_sha256({"category": category, "value": value}),
            "path": path, "occurrences": count, "surface": surface, "reason": reason}


def _decoded_spans(text: str, encoding: str, forms: set[str]) -> list[tuple[int, int]]:
    """Map case-folded matches back to byte spans, including Unicode case expansions."""
    folded = text.casefold()
    matches = []
    for form in forms:
        start = folded.find(form)
        while start >= 0:
            matches.append((start, start + len(form)))
            start = folded.find(form, start + len(form))
    if not matches:
        return []
    starts, ends = sorted({start for start, _ in matches}), sorted({end for _, end in matches})
    start_bytes, end_bytes = {}, {}
    start_index = end_index = folded_offset = byte_offset = 0
    for character in text:
        folded_end = folded_offset + len(character.casefold())
        byte_end = byte_offset + len(character.encode(encoding, errors="surrogateescape"))
        while start_index < len(starts) and starts[start_index] < folded_end:
            start_bytes[starts[start_index]] = byte_offset
            start_index += 1
        while end_index < len(ends) and ends[end_index] <= folded_end:
            end_bytes[ends[end_index]] = byte_end
            end_index += 1
        folded_offset, byte_offset = folded_end, byte_end
        if start_index == len(starts) and end_index == len(ends):
            break
    return [(start_bytes[start], end_bytes[end]) for start, end in matches]


def _answer_occurrences(data: bytes, forms: set[str]) -> int:
    """Count Unicode aliases across common text encodings without duplicate overlap credit."""
    encodings = ["utf-8"]
    if b"\x00" in data:
        encodings += ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"]
    spans = []
    for encoding in encodings:
        try:
            text = data.decode(encoding, errors="surrogateescape" if encoding == "utf-8" else "strict")
        except UnicodeDecodeError:
            continue
        spans.extend(_decoded_spans(text, encoding, forms))
    return _merged_count(spans)


def _merged_count(spans: list[tuple[int, int]]) -> int:
    count, end = 0, -1
    for start, finish in sorted(spans):
        if start >= end:
            count += 1
        end = max(end, finish)
    return count


def inspect_tree(source: Path, policy: dict | None, *, requirements: list[dict],
                 required_source_paths: list[str] | None = None) -> dict:
    """Inspect the final export without executing it, and report strict availability and residuals.

    Answer aliases are inspected case-insensitively in file content and paths, including explicitly
    declared normalized forms. Residual source identities and assistant support files are disclosed;
    residual answers, instructions, evaluator artifacts, unsafe entries, or missing scoring paths
    make the strict experimental condition unavailable. A legacy export with no policy stays usable
    through the basic export API, while its strict condition remains unavailable.
    """
    normalized = validate_policy(policy) if policy is not None else None
    required = _aliases(requirements, "required answers")
    coverage = policy_coverage(normalized, required)
    answers = {entry["value"].casefold(): deepcopy(entry) for entry in required}
    for entry in (normalized or {}).get("answer_aliases", []):
        known = answers.get(entry["value"].casefold())
        if known is None:
            answers[entry["value"].casefold()] = deepcopy(entry)
        else:
            known["forms"] = sorted(set(known["forms"]) | set(entry["forms"]))
    configured = {path.casefold() for path in (normalized or {}).get("instruction_paths", [])}
    required_paths = sorted(set(required_source_paths or []))
    for path in required_paths:
        _path(path)
    hashes, residuals, unsafe, artifacts, instructions, support, reasons = {}, [], [], [], [], [], list(coverage["reasons"])
    byte_count = 0
    for path, data, issue in _tree_entries(Path(source)):
        if issue is not None:
            unsafe.append({"path": path, "reason": issue})
            reasons.append(f"unsafe export entry {path}: {issue}")
            continue
        digest = _sha256(data)
        hashes[path] = digest
        byte_count += len(data)
        artifact_categories = set()
        detected = _artifact_category(path, data)
        if detected:
            artifact_categories.add(detected)
        for artifact in (normalized or {}).get("forbidden_artifacts", []):
            if artifact.get("path", "").casefold() == path.casefold() or artifact.get("sha256") == digest:
                artifact_categories.add(artifact["category"])
        for category in sorted(artifact_categories):
            artifacts.append({"path": path, "category": category, "sha256": digest})
            reasons.append(f"evaluator-only {category} is present at {path}")
        instruction = _instruction_class(path, configured)
        if instruction == "instruction_file":
            instructions.append(path)
            reasons.append(f"repository instruction document remains at {path}")
        elif instruction is not None:
            support.append(path)
            reason = "source, scripts, and assistant configuration are outside the removal policy"
            residuals.append(_cue(instruction, path, path, 1, "path", reason))
            if instruction == "unsafe_configured_instruction":
                reasons.append(f"configured instruction path {path} cannot be removed safely")
        folded_text = data.decode("utf-8", errors="surrogateescape").casefold()
        folded_path = path.casefold()
        for entry in answers.values():
            forms = {entry["value"].casefold(), *(form.casefold() for form in entry["forms"])}
            for surface, text in (("content", folded_text), ("path", folded_path)):
                count = (_answer_occurrences(data, forms) if surface == "content"
                         else _merged_count(_decoded_spans(path, "utf-8", forms)))
                if count:
                    residuals.append(_cue(entry["category"], entry["value"], path, count, surface,
                                          "answer-bearing content remains; unsafe source rewrites are forbidden"))
                    reasons.append(f"residual {entry['category']} in {surface} at {path}")
        for value in (normalized or {}).get("identity_tokens", []):
            pattern = re.compile(r"(?<!\w)" + re.escape(value.casefold()) + r"(?!\w)")
            for surface, text in (("content", folded_text), ("path", folded_path)):
                count = len(pattern.findall(text))
                if count:
                    residuals.append(_cue("repository_identity", value, path, count, surface,
                                          "source identifiers, dependencies, paths, and runtime content are preserved"))
    for path in required_paths:
        if path not in hashes:
            reasons.append(f"accepted scoring path {path} is absent from the transformed export")
    return {"tree_hash": None if unsafe else tree_hash(hashes), "file_count": len(hashes), "byte_count": byte_count,
            "paths": sorted(hashes),
            "policy_sha256": canonical_sha256(normalized), "requirements_sha256": canonical_sha256(required),
            "required_source_paths_sha256": canonical_sha256(required_paths),
            "answer_coverage": coverage, "instruction_files": sorted(instructions),
            "assistant_support_files": sorted(support), "residual_cues": sorted(residuals, key=canonical_json),
            "forbidden_artifacts": sorted(artifacts, key=canonical_json), "unsafe_entries": sorted(unsafe, key=canonical_json),
            "validation": {"state": "unavailable" if reasons else "available", "reasons": sorted(set(reasons))}}


@lru_cache(maxsize=1)
def _manifest_schema() -> dict:
    return json.loads(files("scaneval").joinpath("schemas", MANIFEST_KIND + ".schema.json").read_text(encoding="utf-8"))


def _validate_components(inspection: dict, edits, fields, removals, skipped) -> None:
    schema = _manifest_schema()
    properties = schema["properties"]
    inspection_properties = {key: properties[key] for key in
                             ("validation", "residual_cues", "forbidden_artifacts", "unsafe_entries")}
    inspection_properties.update({
        "tree_hash": {"anyOf": [{"$ref": "#/$defs/digest"}, {"type": "null"}]},
        "paths": {"type": "array", "items": {"type": "string"}},
        "instruction_files": {"type": "array", "items": {"type": "string"}},
        "assistant_support_files": {"type": "array", "items": {"type": "string"}},
        "file_count": {"$ref": "#/$defs/count"}, "byte_count": {"$ref": "#/$defs/count"},
        "policy_sha256": {"$ref": "#/$defs/digest"}, "requirements_sha256": {"$ref": "#/$defs/digest"},
        "required_source_paths_sha256": {"$ref": "#/$defs/digest"},
        "answer_coverage": {"type": "object", "additionalProperties": False,
                            "required": ["state", "reasons", "required_aliases", "declared_aliases"],
                            "properties": {**properties["validation"]["properties"],
                                           "required_aliases": {"$ref": "#/$defs/count"},
                                           "declared_aliases": {"$ref": "#/$defs/count"}}},
    })
    checked = {"$defs": schema["$defs"], "type": "object", "properties": {
        "inspection": {"type": "object", "additionalProperties": False,
                       "required": sorted(inspection_properties), "properties": inspection_properties},
        **{key: properties[key] for key in ("edits", "metadata_edits", "removals", "skipped")}}}
    value = {"inspection": inspection, "edits": edits, "metadata_edits": fields, "removals": removals, "skipped": skipped}
    errors = sorted(Draft202012Validator(checked).iter_errors(value), key=lambda error: str(list(error.absolute_path)))
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path)
        raise ContractError(f"identity manifest component {location}: {errors[0].message}")


def _inspection_blockers(inspection: dict) -> list[str]:
    reasons = []
    if inspection["tree_hash"] is None:
        reasons.append("the inspected export has no verified tree hash")
    if inspection["forbidden_artifacts"]:
        reasons.append("evaluator-only artifacts remain in the transformed export")
    if inspection["unsafe_entries"]:
        reasons.append("the transformed export contains unsafe filesystem entries")
    if inspection["instruction_files"]:
        reasons.append("repository instruction documents remain in the transformed export")
    if any(entry["category"] in _ALIAS_CATEGORIES | {"unsafe_configured_instruction"}
           for entry in inspection["residual_cues"]):
        reasons.append("answer-bearing content or unsafe configured instructions remain in the transformed export")
    return reasons


def build_manifest(policy: dict | None, *, source_snapshot: dict, original_tree_hash: str,
                   transformed_tree_hash: str, map_sha256: str, requirements: list[dict], inspection: dict,
                   edits: list[dict], removals: list[dict], tool_versions: dict[str, str],
                   metadata_edits: list[dict] | None = None, skipped: list[dict] | None = None,
                   original_instruction_files: list[str] | None = None,
                   required_source_paths: list[str] | None = None) -> tuple[dict, dict]:
    """Build deterministic evaluator-side provenance and its portable condition summary.

    No timestamp, temporary path, or random value is introduced. The surrounding export record
    can retain its wall-clock preparation timestamp independently. The manifest digest lives in
    the summary rather than inside the object it hashes. Neither object belongs in scanner input.
    """
    fields_input = [] if metadata_edits is None else metadata_edits
    skipped_input = [] if skipped is None else skipped
    _validate_components(inspection, edits, fields_input, removals, skipped_input)
    normalized = validate_policy(policy) if policy is not None else None
    required = _aliases(requirements, "required answers")
    required_paths = sorted(set(required_source_paths or []))
    for path in required_paths:
        _path(path)
    required_paths_sha256 = canonical_sha256(required_paths)
    for name, digest in (("original_tree_hash", original_tree_hash), ("transformed_tree_hash", transformed_tree_hash),
                         ("map_sha256", map_sha256)):
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ContractError(f"{name} must be a SHA-256 digest")
    if not isinstance(tool_versions, dict) or not all(isinstance(key, str) and isinstance(value, str)
                                                   for key, value in tool_versions.items()):
        raise ContractError("tool_versions must map tool names to version strings")
    validation = deepcopy(inspection["validation"])
    coverage = policy_coverage(normalized, required)
    validation["reasons"] = sorted(set(validation["reasons"]) | set(coverage["reasons"])
                                    | set(_inspection_blockers(inspection)))
    for path in required_paths:
        if path not in inspection["paths"]:
            validation["reasons"].append(f"accepted scoring path {path} is absent from the transformed export")
    if validation["state"] != "available" and not validation["reasons"]:
        validation["reasons"].append("the export inspection did not establish strict identity availability")
    if inspection.get("policy_sha256") != canonical_sha256(normalized):
        validation["reasons"].append("the export was inspected under a different identity policy")
    if inspection.get("requirements_sha256") != canonical_sha256(required):
        validation["reasons"].append("the export was inspected against different answer requirements")
    if inspection.get("required_source_paths_sha256") != required_paths_sha256:
        validation["reasons"].append("the export was inspected against different accepted scoring paths")
    if inspection["tree_hash"] != transformed_tree_hash:
        validation["reasons"].append("the inspected export does not match the transformed tree hash")
    validation["reasons"] = sorted(set(validation["reasons"]))
    validation["state"] = "unavailable" if validation["reasons"] else "available"
    configuration = {"policy": normalized, "map_sha256": map_sha256, "required_answers": required,
                     "required_source_paths_sha256": required_paths_sha256}
    config_sha256 = canonical_sha256(configuration)
    changed = sorted(deepcopy(edits), key=canonical_json)
    fields = sorted(deepcopy(fields_input), key=canonical_json)
    removed = sorted(deepcopy(removals), key=canonical_json)
    remaining = set(inspection["instruction_files"])
    final_paths = set(inspection["paths"])
    before = set(original_instruction_files or [])
    declared = set((normalized or {}).get("instruction_paths", []))
    configured = {path.casefold() for path in declared}
    inventory = before | remaining
    for path in declared:
        matches = {actual for actual in before | final_paths if actual.casefold() == path.casefold()}
        inventory.update(matches or {path})
    disposition = [{"path": path, "classification": _instruction_class(path, configured) or "instruction_file",
                    "disposition": "retained" if path in final_paths else
                    "removed" if path in before else "absent"} for path in sorted(inventory)]
    counts = {
        "changed_files": len({entry["path"] for entry in changed + fields}),
        "removed_files": len({entry["path"] for entry in removed}),
        "redactions": sum(sum(entry.get("occurrences", {}).values()) for entry in changed)
                      + sum(entry.get("redactions", 1) for entry in fields),
        "instruction_files_discovered": sum(entry["disposition"] != "absent" for entry in disposition),
        "instruction_files_removed": sum(entry["disposition"] == "removed" for entry in disposition),
        "instruction_files_retained": sum(entry["disposition"] == "retained" for entry in disposition),
        "residual_cues": sum(entry["occurrences"] for entry in inspection["residual_cues"]),
        "skipped_transformations": len(skipped_input),
    }
    manifest = {
        "schema_version": "2.1", "kind": MANIFEST_KIND,
        "policy": {"policy_id": (normalized or {}).get("policy_id"), "version": (normalized or {}).get("version"),
                   "config_sha256": config_sha256},
        "source_snapshot": deepcopy(source_snapshot), "original_tree_hash": original_tree_hash,
        "transformed_tree_hash": transformed_tree_hash, "map_sha256": map_sha256,
        "requirements_sha256": canonical_sha256(required), "inspection_sha256": canonical_sha256(inspection),
        "required_source_paths_sha256": required_paths_sha256,
        "tool_versions": dict(sorted(tool_versions.items())),
        "edits": changed, "metadata_edits": fields, "removals": removed,
        "skipped": sorted(deepcopy(skipped_input), key=canonical_json), "instruction_files": disposition,
        "residual_cues": deepcopy(inspection["residual_cues"]),
        "forbidden_artifacts": deepcopy(inspection["forbidden_artifacts"]),
        "unsafe_entries": deepcopy(inspection["unsafe_entries"]), "counts": counts, "validation": validation,
    }
    validate_document(MANIFEST_KIND, manifest)
    return manifest, _portable_summary(manifest)


def _portable_summary(manifest: dict) -> dict:
    categories = sorted({entry["category"] for entry in manifest["residual_cues"]})
    return {**manifest["policy"], "manifest_sha256": canonical_sha256(manifest),
               "original_tree_hash": manifest["original_tree_hash"],
               "transformed_tree_hash": manifest["transformed_tree_hash"],
               "counts": deepcopy(manifest["counts"]), "residual_categories": [
                   {"category": category, "occurrences": sum(entry["occurrences"]
                    for entry in manifest["residual_cues"] if entry["category"] == category)}
                   for category in categories], "validation": {
                       "state": manifest["validation"]["state"],
                       "reasons": [_portable_reason(reason) for reason in manifest["validation"]["reasons"]]}}


def _portable_reason(reason: str) -> str:
    safe = {
        "no explicit strict identity policy was supplied",
        "the export inspection did not establish strict identity availability",
        "the export was inspected under a different identity policy",
        "the export was inspected against different answer requirements",
        "the export was inspected against different accepted scoring paths",
        "the inspected export does not match the transformed tree hash",
        "the inspected export has no verified tree hash",
        "evaluator-only artifacts remain in the transformed export",
        "the transformed export contains unsafe filesystem entries",
        "repository instruction documents remain in the transformed export",
        "answer-bearing content or unsafe configured instructions remain in the transformed export",
    }
    if reason in safe or re.fullmatch(r"the policy does not declare (?:required answer |every required normalized form of )sha256:[0-9a-f]{64}", reason):
        return reason
    return "strict identity validation diagnostic " + canonical_sha256(reason)


def _validate_manifest_invariants(document: dict) -> None:
    """Cross-field manifest checks, invoked after the registered JSON schema validates its shape."""
    try:
        canonical_json(document).encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ContractError("identity manifest text must be strict UTF-8") from exc
    for key in ("edits", "metadata_edits", "removals", "skipped", "instruction_files", "residual_cues",
                "forbidden_artifacts", "unsafe_entries"):
        for entry in document[key]:
            if key == "unsafe_entries" and entry["path"] == ".":
                continue
            try:
                _path(entry["path"])
            except MaterializationError as exc:
                raise ContractError(f"{key}: {exc}") from exc
    instructions = document["instruction_files"]
    if len({entry["path"] for entry in instructions}) != len(instructions):
        raise ContractError("instruction_files paths must be unique")
    edited = {entry["path"] for entry in document["edits"] + document["metadata_edits"]}
    removed = {entry["path"] for entry in document["removals"]}
    if edited & removed:
        raise ContractError("an identity manifest path cannot be both edited and removed")
    counts = {
        "changed_files": len(edited), "removed_files": len(removed),
        "redactions": sum(sum(entry["occurrences"].values()) for entry in document["edits"])
                      + sum(entry["redactions"] for entry in document["metadata_edits"]),
        "instruction_files_discovered": sum(entry["disposition"] != "absent" for entry in instructions),
        "instruction_files_removed": sum(entry["disposition"] == "removed" for entry in instructions),
        "instruction_files_retained": sum(entry["disposition"] == "retained" for entry in instructions),
        "residual_cues": sum(entry["occurrences"] for entry in document["residual_cues"]),
        "skipped_transformations": len(document["skipped"]),
    }
    if counts != document["counts"]:
        raise ContractError("identity manifest counts do not match its transformations and residuals")
    validation = document["validation"]
    if (validation["state"] == "available") != (not validation["reasons"]):
        raise ContractError("identity manifest availability must agree with its reasons")
    named = document["policy"]["policy_id"] is not None
    if named != (document["policy"]["version"] is not None):
        raise ContractError("identity manifest policy identifier and version must be present together")
    blockers = (not named or document["forbidden_artifacts"] or document["unsafe_entries"]
                or any(entry["category"] in _ALIAS_CATEGORIES | {"unsafe_configured_instruction"}
                       for entry in document["residual_cues"])
                or any(entry["disposition"] == "retained" and entry["classification"] != "assistant_support_file"
                       for entry in instructions))
    if blockers and validation["state"] == "available":
        raise ContractError("identity manifest cannot claim availability with unresolved strict-policy blockers")


def verify_manifest(manifest: dict, summary: dict, *, policy: dict | None, map_sha256: str,
                    original_tree_hash: str, transformed_tree_hash: str, requirements: list[dict],
                    required_source_paths: list[str] | None = None, source: Path | None = None,
                    source_snapshot: dict | None = None) -> dict:
    """Revalidate saved provenance against the exact expected policy, source, and target bindings.

    A scalar ``validation.state`` is insufficient. The schema and accounting checks run first;
    summary and manifest hashes, policy configuration, aliases, accepted paths, and both tree
    hashes are recomputed. If the staged tree is available, re-inspection must reproduce the
    recorded inspection digest as well. No result is upgraded from unavailable on reuse.
    """
    validate_document(MANIFEST_KIND, manifest)
    if not isinstance(summary, dict):
        raise ContractError("identity transformation summary must be an object")
    expected_summary = _portable_summary(manifest)
    if set(summary) - set(expected_summary) - {"manifest_path"}:
        raise ContractError("identity transformation summary contains unbound extension fields")
    for key, value in expected_summary.items():
        if canonical_json(summary.get(key)) != canonical_json(value):
            raise ContractError(f"identity summary {key} does not match its transformation manifest")
    if "manifest_path" in summary:
        try:
            _path(summary["manifest_path"])
        except MaterializationError as exc:
            raise ContractError(f"manifest_path: {exc}") from exc
    normalized = validate_policy(policy) if policy is not None else None
    required = _aliases(requirements, "required answers")
    paths = sorted(set(required_source_paths or []))
    for path in paths:
        _path(path)
    path_digest = canonical_sha256(paths)
    config_digest = canonical_sha256({"policy": normalized, "map_sha256": map_sha256,
                                     "required_answers": required, "required_source_paths_sha256": path_digest})
    expected = {"original_tree_hash": original_tree_hash, "transformed_tree_hash": transformed_tree_hash,
                "map_sha256": map_sha256, "requirements_sha256": canonical_sha256(required),
                "required_source_paths_sha256": path_digest}
    for key, value in expected.items():
        if manifest[key] != value:
            raise ContractError(f"identity manifest {key} is stale or belongs to another input")
    policy_identity = {"policy_id": (normalized or {}).get("policy_id"),
                       "version": (normalized or {}).get("version"), "config_sha256": config_digest}
    if manifest["policy"] != policy_identity:
        raise ContractError("identity manifest policy configuration is stale")
    if source_snapshot is not None and canonical_json(manifest["source_snapshot"]) != canonical_json(source_snapshot):
        raise ContractError("identity manifest source snapshot is stale")
    coverage = policy_coverage(normalized, required)
    if coverage["state"] != "available" and manifest["validation"]["state"] == "available":
        raise ContractError("identity manifest cannot claim strict availability without answer coverage")
    if source is not None:
        inspection = inspect_tree(source, normalized, requirements=required, required_source_paths=paths)
        if canonical_sha256(inspection) != manifest["inspection_sha256"]:
            raise ContractError("identity manifest inspection is stale for the staged export")
    return deepcopy(summary)


def load_manifest(path: Path, summary: dict, **expected) -> dict:
    """Load one registered manifest contract and revalidate its saved bindings."""
    return verify_manifest(load_document(path, MANIFEST_KIND), summary, **expected)
