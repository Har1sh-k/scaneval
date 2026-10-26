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
import hashlib
import json
from pathlib import PurePosixPath
import re
import tomllib
from typing import Any

from .contracts import is_stated
from .materialize import MaterializationError


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LINE_BREAK = re.compile(r"\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]")
_JSON_FIELDS = frozenset({("repository",), ("repository", "url"), ("homepage",),
                          ("bugs",), ("bugs", "url")})


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _refuse(message: str) -> MaterializationError:
    return MaterializationError("identity policy refused: " + message)


def _path(path: str) -> PurePosixPath:
    if (not isinstance(path, str) or not path or "\\" in path or "\x00" in path
            or re.match(r"^[A-Za-z]:", path)):
        raise _refuse("a file path must be a normalized relative POSIX path")
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


def _parse(text: str, format_: str) -> Any:
    try:
        if format_ == "json":
            return json.loads(text, object_pairs_hook=_json_object, parse_float=Decimal,
                              parse_constant=_reject_json_constant)
        return tomllib.loads(text)
    except (ValueError, RecursionError) as exc:
        raise _refuse(f"the metadata file is not valid strict {format_.upper()}: {exc}") from exc


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
    return one == two


@dataclass(frozen=True)
class MetadataEdit:
    """Verified replacement bytes and the evaluator-side record of one selected leaf."""

    data: bytes
    record: dict


def prepare_metadata_edit(data: bytes, *, path: str, field_path: list[str] | tuple[str, ...],
                          expected_sha256: str, original: str, replacement: str,
                          role_check: str, raw_token: str | None = None) -> MetadataEdit:
    """Prepare a hash-pinned identity metadata edit, without writing any file.

    ``field_path`` is a list of parsed object keys, never a dotted selector or JSONPath.
    ``raw_token`` optionally spells the exact reviewed quoted token, useful for a TOML literal
    string or a JSON string with escapes. Its decoded value must be ``original``. Ambiguous
    tokens, missing fields, non-string leaves, and any broader parsed change are refused.
    """
    if (not isinstance(field_path, (list, tuple)) or not field_path
            or not all(isinstance(part, str) for part in field_path)):
        raise _refuse("field_path must be a nonempty list of string keys")
    keys = tuple(field_path)
    format_ = _metadata_format(path, keys)
    if not isinstance(role_check, str) or not is_stated(role_check):
        raise _refuse("an identity metadata edit must state why the field has no runtime role")
    if (not isinstance(original, str) or not is_stated(original) or not isinstance(replacement, str)
            or _LINE_BREAK.search(original) or _LINE_BREAK.search(replacement)):
        raise _refuse("original and replacement must be single-line strings and original must be stated")
    if original == replacement:
        raise _refuse("an identity metadata edit must change its selected value")
    try:
        original.encode("utf-8", errors="strict")
        replacement.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise _refuse("original and replacement must be strict UTF-8 strings") from exc
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
    if format_ == "json":
        decoded = _parse(token, "json")
        quoted = token.startswith('"') and token.endswith('"')
    else:
        quoted = bool(re.fullmatch(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"", token))
        decoded = _parse("value = " + token, "toml")
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
    after = _parse(changed, format_)
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
