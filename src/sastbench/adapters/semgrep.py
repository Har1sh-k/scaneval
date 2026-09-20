"""Pinned Semgrep OSS adapter: local ruleset checkout, no registry downloads, no metrics.

The ruleset is a git commit of a rules repository fetched into the immutable cache. The
preparation records the commit, the git tree of that commit, the number of rule files, and
one aggregate hash over the ``{path: content hash}`` map of those files. Per-file hashes are
computed to build that aggregate but are not kept in the preparation record. Only plain files
inside the pinned checkout are read: a symlink under a configured ruleset directory is refused
rather than followed, so the recorded hash describes that commit's own content. Live ``p/...``
registry configs are refused because they are moving targets, not pins.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import sys
from typing import Any

from ..kinds import cwe_ids, kind_for_cwes, mapping_version
from ..materialize import fetch_snapshot, sha256_file, tree_hash
from .base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command, tail_text


ARTIFACT_JSON = "semgrep-json"
_UNAVAILABLE = "requires login"
# semgrep.rule_lang.sanitize_rule_id_fragment deletes every other character from the path it
# turns into a check_id prefix, so a cache directory named "rule cache (1)" appears in the
# check_id as "rulecache1".
_RULE_ID_DROPPED = re.compile(r"[^A-Za-z0-9._-]")


def _binary(spec: SystemSpec) -> str:
    configured = spec.config.get("binary")
    if configured:
        return str(configured)
    sibling = Path(sys.executable).with_name("semgrep")
    if sibling.exists():
        return str(sibling)
    found = shutil.which("semgrep")
    if not found:
        raise AdapterError("semgrep binary not found; install the official-adapters extra or set config.binary")
    return found


def semgrep_version(binary: str, raw_dir: Path, timeout_seconds: float = 60) -> str:
    """Record ``semgrep --version`` under *raw_dir* and return the recorded string.

    A non-zero exit or timeout, and an output file that cannot be written or read, are setup
    failures raised as ``AdapterError``. Bytes that are not UTF-8 are replaced rather than
    raising, so the returned string can contain replacement characters: an undecodable version
    banner is a provenance defect, not a reason to abandon the run before it starts.
    """
    stdout_path = raw_dir / "semgrep-version.txt"
    try:
        result = run_command([binary, "--version"], cwd=raw_dir, timeout_seconds=timeout_seconds,
                             env=build_env(), stdout_path=stdout_path,
                             stderr_path=raw_dir / "semgrep-version.stderr.txt")
        if result.exit_code != 0:
            raise AdapterError(f"semgrep --version failed: {tail_text(result.stderr_path)}")
        text = stdout_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError) as exc:
        raise AdapterError(f"semgrep --version output under {raw_dir} could not be recorded: {exc}") from exc
    return text.strip()


def _shape(value: Any) -> str:
    return type(value).__name__


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AdapterError(message)


def _dotted_prefixes(directories) -> list[str]:
    # Semgrep builds check_id from the rule file's path: the directory components joined with
    # dots, the leading separator dropped, every character outside [A-Za-z0-9._-] deleted, then
    # the declared rule id. The path part is a machine location, so it is removed before
    # recording. The same characters are deleted here, otherwise a cache directory containing a
    # space or a parenthesis never matches and the machine path survives in native_rule_id.
    # Longest first, so a nested directory is stripped before a parent of it.
    prefixes: list[str] = []
    for directory in directories or ():
        if not isinstance(directory, (str, Path)):
            continue
        path = Path(directory)
        # pathlib splits the path, so a backslash separates components only on a platform whose
        # os.sep is a backslash. On POSIX a directory literally named "we\ird" stays one
        # component and the backslash is deleted by the sanitizer below, which is what Semgrep
        # does with it.
        segments = list(path.parts)
        if path.anchor and segments:
            # Semgrep drops the leading separator; a Windows drive anchor ("C:\") keeps only the
            # characters the sanitizer leaves.
            head = _RULE_ID_DROPPED.sub("", path.anchor)
            segments = ([head] if head else []) + segments[1:]
        # Segments that sanitize away entirely stay as empty segments, which is what Semgrep
        # produces: it sanitizes the already joined string.
        dotted = ".".join(_RULE_ID_DROPPED.sub("", segment) for segment in segments)
        if dotted.strip("."):
            prefixes.append(dotted + ".")
    return sorted(set(prefixes), key=len, reverse=True)


def _path_segment_pool(prefixes) -> set[str]:
    """Leading segments of the supplied prefixes, used only to flag an unmatched path prefix.

    The last segment of a prefix is the directory the rule files sit in, which in rule
    repositories is a language or category name that legitimately opens a rule id, so it is
    excluded. This is a heuristic for a note, not proof that a check_id carries a path.
    """
    pool: set[str] = set()
    for prefix in prefixes:
        segments = [segment for segment in prefix.strip(".").split(".") if segment]
        pool.update(segments[:-1])
    return pool


def _line_number(item: dict, index: int, key: str) -> int:
    span = item.get(key)
    _require(isinstance(span, dict), f"semgrep JSON result {index} has {key} as a {_shape(span)}, not an object")
    line = span.get("line")
    _require(isinstance(line, int) and not isinstance(line, bool),
             f"semgrep JSON result {index} has {key}.line as a {_shape(line)}, not an integer")
    return int(line)


def import_semgrep_results(payload: dict, *, artifact_id: str = ARTIFACT_JSON,
                           ruleset_roots=(), config_dirs=()) -> tuple[list[dict], list[str]]:
    """Translate Semgrep JSON ``results`` into atomic claims without inventing evidence.

    ``ruleset_roots`` is the preferred input: stripping the rules checkout root leaves
    ``native_rule_id`` as the id relative to that checkout, so the language and category
    directories a rule was declared under survive while the local cache path does not.
    ``config_dirs`` is the older behavior kept for existing callers and drops every directory
    segment inside the checkout as well; it is used only when no root is supplied.

    Every unexpected JSON shape raises ``AdapterError`` naming the offending field; no other
    exception type is raised for payload content. This does not assign truth labels, split
    bundled findings, invent locations, or recover a rule id from a check_id whose path prefix
    none of the supplied directories match: such an id is kept verbatim.

    Whether an unshortened id is also *noted* is a heuristic keyed on the supplied roots'
    leading segments: the note fires only when the id's first segment is one of those segments
    (the last segment of each root is excluded, being the language or category directory that
    legitimately opens a rule id). So the note can miss a machine path that came from a root
    nobody supplied, and it can flag an id that carries no path at all.
    """
    claims: list[dict] = []
    notes: list[str] = []
    _require(isinstance(payload, dict), f"semgrep JSON payload is a {_shape(payload)}, not an object")
    results = payload.get("results")
    if not isinstance(results, list):
        raise AdapterError("semgrep JSON has no results array")
    prefixes = _dotted_prefixes(ruleset_roots) if ruleset_roots else _dotted_prefixes(config_dirs)
    pool = _path_segment_pool(prefixes)
    unmatched: dict[str, int] = {}
    login_gated = False
    for index, item in enumerate(results, start=1):
        _require(isinstance(item, dict), f"semgrep JSON result {index} is a {_shape(item)}, not an object")
        # Absent means empty; a present value of any other type is a shape error, so a
        # falsy non-object (0, "", []) is reported rather than silently read as {}.
        extra = item.get("extra")
        if extra is None:
            extra = {}
        _require(isinstance(extra, dict),
                 f"semgrep JSON result {index} has extra as a {_shape(extra)}, not an object")
        metadata = extra.get("metadata")
        if metadata is None:
            metadata = {}
        _require(isinstance(metadata, dict),
                 f"semgrep JSON result {index} has extra.metadata as a {_shape(metadata)}, not an object")
        raw_cwe = metadata.get("cwe")
        _require(raw_cwe is None or isinstance(raw_cwe, (str, list)),
                 f"semgrep JSON result {index} has extra.metadata.cwe as a {_shape(raw_cwe)}, not a string or array")
        cwes = cwe_ids(raw_cwe)
        check_id = item.get("check_id")
        _require(isinstance(check_id, str) and check_id,
                 f"semgrep JSON result {index} has check_id as a {_shape(check_id)}, not a non-empty string")
        rule_id = check_id
        for prefix in prefixes:
            if rule_id.startswith(prefix):
                rule_id = rule_id[len(prefix):]
                break
        else:
            head = rule_id.split(".", 1)[0]
            if head in pool:
                unmatched[head] = unmatched.get(head, 0) + 1
        raw_path = item.get("path")
        _require(isinstance(raw_path, str) and raw_path,
                 f"semgrep JSON result {index} has path as a {_shape(raw_path)}, not a non-empty string")
        path = raw_path.replace("\\", "/")
        if path.startswith("./"):
            path = path[2:]
        start = _line_number(item, index, "start")
        end = _line_number(item, index, "end")
        if end < start:
            end = start
            notes.append(f"result {index}: end line before start line; clamped to start")
        message = str(extra.get("message") or "").strip() or check_id
        claim: dict[str, Any] = {
            "claim_id": f"c{index}",
            "allegation": message,
            "kind": kind_for_cwes(cwes),
            "primary_location": {"path": path, "start_line": start, "end_line": end},
            "native_rule_id": rule_id,
            "raw_artifact_id": artifact_id,
        }
        fingerprint = extra.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint and fingerprint != _UNAVAILABLE:
            claim["native_id"] = fingerprint
        lines = extra.get("lines")
        if isinstance(lines, str) and lines and lines != _UNAVAILABLE:
            claim["evidence_text"] = lines
        if extra.get("lines") == _UNAVAILABLE:
            login_gated = True
        severity = extra.get("severity")
        if isinstance(severity, str) and severity:
            claim["native_severity"] = severity
        if cwes:
            claim["native_cwe"] = cwes
        claims.append(claim)
    for head, count in sorted(unmatched.items()):
        notes.append(f"{count} check_id(s) start with {head!r}, a path-like prefix that no supplied ruleset root "
                     "matches; native_rule_id keeps those ids verbatim and may contain a machine path")
    if login_gated:
        notes.append("Semgrep OSS omitted matched source text and fingerprints (requires login); evidence_text left absent")
    return claims, notes


def _integer_config(spec: SystemSpec, key: str, default: int, minimum: int) -> int:
    value = spec.config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AdapterError(f"semgrep config.{key} must be an integer, got a {_shape(value)}")
    try:
        number = int(str(value).strip())
    except ValueError as exc:
        raise AdapterError(f"semgrep config.{key} must be an integer, got {value!r}") from exc
    if number < minimum:
        raise AdapterError(f"semgrep config.{key} must be at least {minimum}, got {number}")
    return number


def _prepared_ruleset(preparation) -> tuple[list[str], str, str]:
    """Config directories, ruleset commit, and ruleset tree hash from a prepare() record."""
    if not isinstance(preparation, dict):
        raise AdapterError(f"semgrep preparation must be the mapping prepare() returned, got a {_shape(preparation)}")
    directories = preparation.get("config_dirs")
    if not isinstance(directories, list) or not directories or not all(
            isinstance(directory, str) and directory for directory in directories):
        raise AdapterError("semgrep preparation has no non-empty config_dirs list of strings; run prepare() first")
    ruleset = preparation.get("ruleset")
    if not isinstance(ruleset, dict):
        raise AdapterError(f"semgrep preparation has ruleset as a {_shape(ruleset)}, not an object")
    commit = ruleset.get("commit")
    digest = ruleset.get("tree_hash")
    if not isinstance(commit, str) or not isinstance(digest, str) or not commit or not digest:
        raise AdapterError("semgrep preparation ruleset needs commit and tree_hash strings; run prepare() first")
    return list(directories), commit, digest


def _error_entries(payload: dict) -> tuple[list[dict], int]:
    """Error-level diagnostics and the number of entries that were not objects."""
    errors = payload.get("errors")
    if errors is None:
        errors = []
    _require(isinstance(errors, list), f"semgrep JSON errors is a {_shape(errors)}, not an array")
    malformed = sum(1 for entry in errors if not isinstance(entry, dict))
    fatal = [entry for entry in errors if isinstance(entry, dict) and entry.get("level") == "error"]
    return fatal, malformed


def _path_list(payload: dict, key: str) -> tuple[list, bool]:
    """``(paths[key], whether the payload reported that list at all)``."""
    paths = payload.get("paths")
    if paths is None:
        return [], False
    _require(isinstance(paths, dict), f"semgrep JSON paths is a {_shape(paths)}, not an object")
    value = paths.get(key)
    if value is None:
        return [], False
    _require(isinstance(value, list), f"semgrep JSON paths.{key} is a {_shape(value)}, not an array")
    return value, True


class SemgrepAdapter(Adapter):
    name = "semgrep"
    adapter_version = "2.0.0"
    requires_git = False
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})

    def prepare(self, spec: SystemSpec, cache_root: Path) -> dict[str, Any]:
        ruleset = spec.config.get("ruleset")
        if not isinstance(ruleset, dict) or not {"url", "commit", "paths"} <= set(ruleset):
            raise AdapterError("semgrep config.ruleset needs url, commit, and paths (a pinned rules checkout)")
        paths = ruleset["paths"]
        if not isinstance(paths, list) or not paths or not all(
                isinstance(entry, str) and entry.strip() for entry in paths):
            raise AdapterError("semgrep config.ruleset.paths must be a non-empty list of non-empty strings "
                               "relative to the pinned checkout")
        if any(p.startswith("p/") or p.startswith("r/") for p in paths):
            raise AdapterError("registry rulesets are not pins; use a rules repository commit")
        for entry in paths:
            if "\x00" in entry:
                raise AdapterError(f"ruleset path {entry!r} contains a NUL byte and cannot name a directory")
            relative = Path(entry)
            if relative.is_absolute() or ".." in relative.parts:
                raise AdapterError(f"ruleset path {entry!r} must stay inside the checkout: no absolute paths and no '..'")
        snapshot = fetch_snapshot(str(ruleset["url"]), str(ruleset["commit"]), cache_root)
        # scan() runs semgrep with cwd=source_dir (a private workspace), so a config path
        # relative to the controller's working directory would not resolve there. Record
        # absolute paths only.
        root = snapshot.path.resolve()
        config_dirs: list[str] = []
        hashes: dict[str, str] = {}
        for entry in paths:
            try:
                directory = (root / entry).resolve()
            except (OSError, ValueError) as exc:
                raise AdapterError(f"ruleset path {entry!r} could not be resolved under {root}: {exc}") from exc
            # Resolution follows symlinks, so this also refuses a checked-in symlink that
            # points out of the pinned checkout. Keeping every rule file under the root is
            # what makes the recorded tree hash describe the pinned commit and nothing else.
            if directory != root and root not in directory.parents:
                raise AdapterError(f"ruleset path {entry!r} resolves to {directory}, outside the pinned checkout {root}")
            if not directory.is_dir():
                raise AdapterError(f"ruleset path {entry!r} is not a directory in {root}")
            config_dirs.append(str(directory))
            for rule_file in sorted(directory.rglob("*")):
                # Every symlink under the directory is refused, not followed. rglob does not
                # descend into a symlinked directory, so rules Semgrep would load through one
                # would be missing from this hash; a symlinked rule file is followed by both
                # rglob and Semgrep and can point anywhere on the machine. Neither is content
                # the pinned commit holds at this path.
                if rule_file.is_symlink():
                    raise AdapterError(
                        f"ruleset path {entry!r} contains the symlink {rule_file.relative_to(root).as_posix()!r}; "
                        "a pinned ruleset must be plain files inside the checkout")
                if (rule_file.suffix not in {".yaml", ".yml"} or rule_file.name.startswith(".")
                        or not rule_file.is_file()):
                    continue
                try:
                    resolved = rule_file.resolve()
                except (OSError, ValueError) as exc:
                    raise AdapterError(f"rule file {rule_file} could not be resolved: {exc}") from exc
                if root not in resolved.parents:
                    raise AdapterError(f"rule file {rule_file.relative_to(root).as_posix()!r} resolves to {resolved}, "
                                       f"outside the pinned checkout {root}")
                hashes[rule_file.relative_to(root).as_posix()] = sha256_file(rule_file)[0]
        if not hashes:
            raise AdapterError("ruleset contains no rule files")
        return {
            "ruleset": {
                "url": snapshot.url,
                "commit": snapshot.commit,
                "git_tree": snapshot.git_tree,
                "paths": [str(p) for p in paths],
                "rule_files": len(hashes),
                # Aggregate over the {path: content hash} map; the per-file map is not kept.
                "tree_hash": tree_hash(hashes),
            },
            "config_dirs": config_dirs,
            # The checkout root, recorded so the importer can shorten check_id to a
            # ruleset-relative rule id instead of dropping the directories inside the checkout.
            "ruleset_root": str(root),
        }

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        # Configuration and preparation are validated before the process starts: a bad value
        # here is a setup failure (AdapterError), not a scan whose output can be interpreted.
        binary = _binary(spec)
        rule_timeout = _integer_config(spec, "rule_timeout_seconds", 30, minimum=0)
        jobs = _integer_config(spec, "jobs", 1, minimum=1)
        config_dirs, ruleset_commit, ruleset_tree_hash = _prepared_ruleset(preparation)
        version = semgrep_version(binary, raw_dir)
        argv = [
            binary, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
            "--timeout", str(rule_timeout),
            "--jobs", str(jobs),
        ]
        for directory in config_dirs:
            argv.append(f"--config={directory}")
        argv.append(".")
        stdout = raw_dir / "semgrep.json"
        stderr = raw_dir / "semgrep.stderr.txt"
        try:
            result = run_command(argv, cwd=source_dir, timeout_seconds=timeout_seconds, env=build_env(),
                                 stdout_path=stdout, stderr_path=stderr)
        except OSError as exc:
            raise AdapterError(f"semgrep output files could not be opened under {raw_dir}: {exc}") from exc
        artifacts = [{"id": ARTIFACT_JSON, "path": stdout}, {"id": "semgrep-stderr", "path": stderr}]
        tool_versions = {"semgrep": version, "ruleset_commit": ruleset_commit,
                         "ruleset_tree_hash": ruleset_tree_hash}
        capture = {"model_requests": "not_applicable", "tool_calls": "not_applicable",
                   "context_selection": "not_applicable", "finding_lifecycle": "not_applicable"}
        base = dict(command=argv, artifacts=artifacts, tool_versions=tool_versions, capture=capture,
                    usage={"cost_usd": 0.0}, notes=["Semgrep OSS has no metered cost; license cost not included."])
        if result.timed_out:
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True, error={"code": "timeout",
                                 "message": f"semgrep exceeded {timeout_seconds}s; output written at exit only"}, **base)
        try:
            payload = json.loads(stdout.read_text(encoding="utf-8"))
            ruleset_root = preparation.get("ruleset_root")
            # config_dirs stays as the fallback so a preparation recorded before ruleset_root
            # existed still keeps the cache path out of native_rule_id.
            claims, notes = import_semgrep_results(
                payload,
                ruleset_roots=(ruleset_root,) if isinstance(ruleset_root, str) and ruleset_root else (),
                config_dirs=config_dirs,
            )
            fatal, malformed_errors = _error_entries(payload)
            scanned, scanned_reported = _path_list(payload, "scanned")
            skipped, _ = _path_list(payload, "skipped")
            reported_version = str(payload.get("version", ""))
        except (AdapterError, OSError, AttributeError, TypeError, LookupError, ValueError,
                RecursionError) as exc:
            # Every unexpected JSON shape lands here, nesting deep enough to exhaust the JSON
            # parser's recursion included: the run produced something this adapter cannot read
            # as a result, which is never an empty successful scan.
            message = (f"semgrep output at {stdout.name} could not be read as a result payload: {exc}; "
                       f"exit code {result.exit_code}; stderr: {tail_text(stderr)}")
            return NativeOutcome(status="error", exit_code=result.exit_code,
                                 error={"code": "unparseable_output", "message": message[:2000]}, **base)
        base["notes"] = base["notes"] + notes
        base["tool_versions"]["semgrep_reported"] = reported_version
        if malformed_errors:
            base["notes"].append(f"{malformed_errors} entries in the Semgrep errors array were not objects and "
                                 "could not be classified; see raw semgrep.json errors")
        if result.exit_code != 0:
            # --quiet keeps the reason off stderr, so the JSON errors array carries it.
            reason = str(fatal[0].get("message", "")).strip() if fatal else ""
            detail = f"; reason: {reason}" if reason else ""
            if not scanned and not claims:
                # Nothing was scanned and nothing was reported: this run produced no output at
                # all, so it is an error. Calling it partial would let a failed invocation read
                # as a quiet negative result.
                message = (f"semgrep exited {result.exit_code} with no scanned paths and no results"
                           f"{detail}; stderr: {tail_text(stderr)}")
                return NativeOutcome(status="error", exit_code=result.exit_code, claims=[],
                                     error={"code": f"exit_{result.exit_code}", "message": message[:2000]}, **base)
            message = (f"semgrep exited {result.exit_code} after scanning {len(scanned)} paths"
                       f"{detail}; stderr: {tail_text(stderr)}")
            return NativeOutcome(status="partial", exit_code=result.exit_code, claims=claims,
                                 error={"code": f"exit_{result.exit_code}", "message": message[:2000]}, **base)
        if fatal:
            base["notes"].append(f"{len(fatal)} error-level Semgrep diagnostics; see raw semgrep.json errors")
            reason = str(fatal[0].get("message", "")).strip()
            if not scanned and not claims:
                # Exit 0 does not make this a clean run: nothing was scanned and nothing was
                # reported, so the invocation observed no source at all. Calling it partial
                # would let a failed run read as a quiet negative result.
                detail = f"; reason: {reason}" if reason else ""
                message = ("semgrep exited 0 with error-level diagnostics, no scanned paths and "
                           f"no results{detail}; stderr: {tail_text(stderr)}")
                return NativeOutcome(status="error", exit_code=0, claims=[],
                                     error={"code": "scan_errors", "message": message[:2000]}, **base)
            return NativeOutcome(status="partial", exit_code=0, claims=claims,
                                 error={"code": "scan_errors", "message": reason[:500]}, **base)
        if skipped:
            base["notes"].append(f"Semgrep skipped {len(skipped)} paths under its own ignore rules; see raw semgrep.json paths")
        if not scanned_reported:
            base["notes"].append("Semgrep output reported no paths.scanned list, so an empty result set here cannot "
                                 "be distinguished from a run that looked at no files")
        elif not scanned and not claims:
            # An explicit empty scanned list means Semgrep opened no file. Silence from a scan
            # that read nothing is missing evidence, not a clean negative control.
            message = ("semgrep exited 0 having scanned no files and reported no results: Semgrep looked at no "
                       "source at all, which its ignore rules, an empty tree, or a default-ignored directory "
                       f"layout can cause; stderr: {tail_text(stderr)}")
            return NativeOutcome(status="error", exit_code=0, claims=[],
                                 error={"code": "nothing_scanned", "message": message[:2000]}, **base)
        return NativeOutcome(status="success", exit_code=0, claims=claims, **base)
