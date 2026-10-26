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
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tomllib
from typing import Any
from urllib.parse import urlsplit

from .contracts import ContractError, canonical_json, canonical_sha256, is_stated
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
    within = (pure.parts[0] in {part.casefold() for part in INSTRUCTION_TOP_LEVEL}
              or folded in {part.casefold() for part in INSTRUCTION_PATHS}
              or folded.startswith(tuple(part.casefold() for part in INSTRUCTION_PATH_PREFIXES)))
    explicit = folded in configured
    if not (named or within or explicit):
        return None
    textual = pure.suffix in _TEXT_SUFFIXES or pure.name in {"readme", "instructions"}
    if named or textual:
        return "instruction_file"
    return "unsafe_configured_instruction" if explicit else "assistant_support_file"


def _tree_entries(root: Path):
    """Read only regular files through no-follow descriptors anchored to the export root."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK

    def walk(descriptor: int, prefix: str):
        with os.scandir(descriptor) as directory:
            names = sorted(entry.name for entry in directory)
        for name in names:
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
                    try:
                        yield from walk(child, relative + "/")
                    finally:
                        os.close(child)
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

    try:
        descriptor = os.open(Path(root), directory_flags)
    except OSError as exc:
        yield ".", None, f"the export root could not be opened safely: {exc.strerror}"
        return
    try:
        yield from walk(descriptor, "")
    finally:
        os.close(descriptor)


def _artifact_category(path: str, data: bytes) -> str | None:
    if PurePosixPath(path).name.casefold() == MANIFEST_NAME:
        return "transformation_manifest"
    try:
        document = json.loads(data)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(document, dict):
        return None
    keys = set(document)
    if document.get("kind") == MANIFEST_KIND or {"original_tree_hash", "transformed_tree_hash", "policy"} <= keys:
        return "transformation_manifest"
    if ({"map_id", "pseudonyms", "variants", "edits"} <= keys
            or document.get("policy_id") == POLICY_ID and "answer_aliases" in keys):
        return "redaction_dictionary"
    if any(required <= keys for required in (
            {"namespace", "pack_id", "snapshots", "cases"},
            {"canonical_target", "target", "evidence", "validation"},
            {"targets", "controls", "provenance", "review_budgets", "input_hash"},
            {"claim_matches", "control_assessments", "result_sha256", "input_hash"})):
        return "evaluator_evidence"
    return None


def _cue(category: str, value: str, path: str, count: int, surface: str, reason: str) -> dict:
    return {"category": category, "cue_sha256": canonical_sha256({"category": category, "value": value}),
            "path": path, "occurrences": count, "surface": surface, "reason": reason}


def _answer_occurrences(data: bytes, folded_text: str, forms: set[str]) -> int:
    """Count ASCII aliases in common text encodings, merging overlapping encoded matches."""
    folded_bytes = data.lower()
    encodings = ["utf-8"]
    if b"\x00" in data:
        encodings += ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"]
    spans = []
    count = sum(folded_text.count(form) for form in forms if not form.isascii())
    for form in forms:
        if not form.isascii():
            continue
        for encoding in encodings:
            needle = form.encode(encoding)
            start = folded_bytes.find(needle)
            while start >= 0:
                spans.append((start, start + len(needle)))
                start = folded_bytes.find(needle, start + len(needle))
    end = -1
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
            if artifact.get("path") == path or artifact.get("sha256") == digest:
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
                count = (_answer_occurrences(data, folded_text, forms) if surface == "content"
                         else sum(text.count(form) for form in forms))
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


def build_manifest(policy: dict | None, *, source_snapshot: dict, original_tree_hash: str,
                   transformed_tree_hash: str, map_sha256: str, requirements: list[dict], inspection: dict,
                   edits: list[dict], removals: list[dict], tool_versions: dict[str, str],
                   metadata_edits: list[dict] | None = None, skipped: list[dict] | None = None,
                   original_instruction_files: list[str] | None = None) -> tuple[dict, dict]:
    """Build deterministic evaluator-side provenance and its portable condition summary.

    No timestamp, temporary path, or random value is introduced. The surrounding export record
    can retain its wall-clock preparation timestamp independently. The manifest digest lives in
    the summary rather than inside the object it hashes. Neither object belongs in scanner input.
    """
    normalized = validate_policy(policy) if policy is not None else None
    required = _aliases(requirements, "required answers")
    for name, digest in (("original_tree_hash", original_tree_hash), ("transformed_tree_hash", transformed_tree_hash),
                         ("map_sha256", map_sha256)):
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ContractError(f"{name} must be a SHA-256 digest")
    if not isinstance(tool_versions, dict) or not all(isinstance(key, str) and isinstance(value, str)
                                                   for key, value in tool_versions.items()):
        raise ContractError("tool_versions must map tool names to version strings")
    validation = deepcopy(inspection["validation"])
    coverage = policy_coverage(normalized, required)
    validation["reasons"] = sorted(set(validation["reasons"]) | set(coverage["reasons"]))
    if validation["state"] != "available" and not validation["reasons"]:
        validation["reasons"].append("the export inspection did not establish strict identity availability")
    if inspection.get("policy_sha256") != canonical_sha256(normalized):
        validation["reasons"].append("the export was inspected under a different identity policy")
    if inspection.get("requirements_sha256") != canonical_sha256(required):
        validation["reasons"].append("the export was inspected against different answer requirements")
    if inspection["tree_hash"] != transformed_tree_hash:
        validation["reasons"].append("the inspected export does not match the transformed tree hash")
    validation["reasons"] = sorted(set(validation["reasons"]))
    validation["state"] = "unavailable" if validation["reasons"] else "available"
    configuration = {"policy": normalized, "map_sha256": map_sha256, "required_answers": required}
    config_sha256 = canonical_sha256(configuration)
    changed = sorted(deepcopy(edits), key=canonical_json)
    fields = sorted(deepcopy(metadata_edits or []), key=canonical_json)
    removed = sorted(deepcopy(removals), key=canonical_json)
    remaining = set(inspection["instruction_files"])
    final_paths = set(inspection["paths"])
    before = set(original_instruction_files or [])
    declared = set((normalized or {}).get("instruction_paths", []))
    disposition = [{"path": path, "disposition": "retained" if path in final_paths else
                    "removed" if path in before else "absent"} for path in sorted(before | remaining | declared)]
    counts = {
        "changed_files": len({entry["path"] for entry in changed + fields}),
        "removed_files": len({entry["path"] for entry in removed}),
        "redactions": sum(sum(entry.get("occurrences", {}).values()) for entry in changed)
                      + sum(entry.get("redactions", 1) for entry in fields),
        "instruction_files_discovered": len(before | remaining),
        "instruction_files_removed": sum(entry["disposition"] == "removed" for entry in disposition),
        "instruction_files_retained": sum(entry["disposition"] == "retained" for entry in disposition),
        "residual_cues": sum(entry["occurrences"] for entry in inspection["residual_cues"]),
        "skipped_transformations": len(skipped or []),
    }
    manifest = {
        "schema_version": "2.1", "kind": MANIFEST_KIND,
        "policy": {"policy_id": (normalized or {}).get("policy_id"), "version": (normalized or {}).get("version"),
                   "config_sha256": config_sha256},
        "source_snapshot": deepcopy(source_snapshot), "original_tree_hash": original_tree_hash,
        "transformed_tree_hash": transformed_tree_hash, "map_sha256": map_sha256,
        "requirements_sha256": canonical_sha256(required), "inspection_sha256": canonical_sha256(inspection),
        "tool_versions": dict(sorted(tool_versions.items())),
        "edits": changed, "metadata_edits": fields, "removals": removed,
        "skipped": sorted(deepcopy(skipped or []), key=canonical_json), "instruction_files": disposition,
        "residual_cues": deepcopy(inspection["residual_cues"]),
        "forbidden_artifacts": deepcopy(inspection["forbidden_artifacts"]),
        "unsafe_entries": deepcopy(inspection["unsafe_entries"]), "counts": counts, "validation": validation,
    }
    categories = sorted({entry["category"] for entry in inspection["residual_cues"]})
    summary = {**manifest["policy"], "manifest_sha256": canonical_sha256(manifest),
               "original_tree_hash": original_tree_hash, "transformed_tree_hash": transformed_tree_hash,
               "counts": deepcopy(counts), "residual_categories": [
                   {"category": category, "occurrences": sum(entry["occurrences"]
                    for entry in inspection["residual_cues"] if entry["category"] == category)}
                   for category in categories], "validation": deepcopy(validation)}
    return manifest, summary
