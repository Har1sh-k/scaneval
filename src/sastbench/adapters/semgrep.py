"""Pinned Semgrep OSS adapter: local ruleset checkout, no registry downloads, no metrics.

The ruleset is a git commit of a rules repository fetched into the immutable cache. The
preparation records the commit, the git tree of that commit, the number of rule files, and
one aggregate hash over the ``{path: content hash}`` map of those files. Per-file hashes are
computed to build that aggregate but are not kept in the preparation record.

``rule_files`` and ``tree_hash`` cover exactly the files Semgrep's own ``--config <directory>``
walk selects: every file under a configured directory whose final suffix is ``.yaml`` or
``.yml``, excluding ``.test.yaml``/``.test.yml`` rule tests and any name carrying a ``.fixed``
suffix, dotfiles such as ``.hidden.yaml`` included. That mirrors
``semgrep.util.is_config_suffix`` and ``read_config_folder`` as of Semgrep 1.177, checked
against the installed binary. Selection is not parse success: a file Semgrep selects and then
fails to parse, or whose rules its version filter drops, is still counted and hashed here, and
rules Semgrep reads from anywhere but the configured directories are not covered at all.

Only plain files inside the pinned checkout are read: a symlink under a configured ruleset
directory is refused rather than followed, so the recorded hash describes that commit's own
content. Live ``p/...`` registry configs are refused because they are moving targets, not pins.

Raw output files are create-only. ``semgrep.json``, ``semgrep.stderr.txt``,
``semgrep-version.txt`` and ``semgrep-version.stderr.txt`` are claimed with an exclusive
create before the process starts, so an existing file under the supplied raw directory is a
setup failure rather than silently replaced evidence.
"""

from __future__ import annotations

import json
import os
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
# semgrep.constants: the suffixes read_config_folder loads and the two it leaves out.
_YAML_SUFFIXES = frozenset({".yaml", ".yml"})
_RULE_TEST_SUFFIX = ".test"
_RULE_FIXTEST_SUFFIX = ".fixed"
# A backslash separates directories only on Windows. On POSIX it is an ordinary character in a
# file name, so a payload path is only translated when it cannot be a POSIX path.
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_NATIVE_SEPARATOR = os.sep


def _is_loaded_rule_file(path: Path) -> bool:
    """Whether Semgrep's ``--config <directory>`` walk would select *path* as a rule file.

    Mirrors ``semgrep.util.is_config_suffix`` (Semgrep 1.177): the final suffix is ``.yaml`` or
    ``.yml``, the name is not a ``.test.yaml``/``.test.yml`` rule test, and no ``.fixed``
    suffix appears anywhere in it. A dotfile such as ``.hidden.yaml`` is selected; a name that
    is only an extension (``.yaml``) has no suffix at all under ``pathlib`` and is not. This
    answers which files Semgrep reads, not whether it can parse them.
    """
    suffixes = path.suffixes
    if not suffixes or suffixes[-1] not in _YAML_SUFFIXES:
        return False
    if _RULE_FIXTEST_SUFFIX in suffixes:
        return False
    return suffixes[-2:-1] != [_RULE_TEST_SUFFIX]


def _claim_output(path: Path, what: str) -> None:
    """Create *path* exclusively so an existing raw artifact is never overwritten.

    ``run_command`` opens its output files with ``wb``, which truncates whatever the directory
    already held. The runner hands ``scan()`` a fresh staging directory, so this only fires
    under direct library use, where replacing recorded raw output would destroy evidence.
    """
    try:
        path.touch(exist_ok=False)
    except FileExistsError as exc:
        raise AdapterError(f"{what} could not be recorded: {path.name} already exists and semgrep raw "
                           "output files are create-only") from exc
    except OSError as exc:
        raise AdapterError(f"{what} could not be recorded: {exc}") from exc


def _binary(spec: SystemSpec) -> str:
    configured = spec.config.get("binary")
    if configured:
        text = str(configured)
        # A NUL byte reaches subprocess as a raw ValueError from the C layer, which would leave
        # the adapter instead of being reported as the setup failure it is.
        if "\x00" in text:
            raise AdapterError("semgrep config.binary contains a NUL byte and cannot name an executable")
        return text
    sibling = Path(sys.executable).with_name("semgrep")
    if sibling.exists():
        return str(sibling)
    found = shutil.which("semgrep")
    if not found:
        raise AdapterError("semgrep binary not found; install the official-adapters extra or set config.binary")
    return found


def semgrep_version(binary: str, raw_dir: Path, timeout_seconds: float = 60) -> str:
    """Record ``semgrep --version`` under *raw_dir* and return the recorded string.

    Both output files are claimed with an exclusive create first, so an existing
    ``semgrep-version.txt`` or ``semgrep-version.stderr.txt`` is a setup failure rather than
    overwritten evidence. A timeout is reported with the limit and the elapsed seconds, since
    an empty stderr tail says nothing about why the command produced no version. A non-zero
    exit, and an output file that cannot be written or read, are setup failures too; all of
    these are raised as ``AdapterError``. Bytes that are not UTF-8 are replaced rather than
    raising, so the returned string can contain replacement characters: an undecodable version
    banner is a provenance defect, not a reason to abandon the run before it starts.
    """
    stdout_path = raw_dir / "semgrep-version.txt"
    stderr_path = raw_dir / "semgrep-version.stderr.txt"
    what = f"semgrep --version output under {raw_dir}"
    _claim_output(stdout_path, what)
    _claim_output(stderr_path, what)
    try:
        result = run_command([binary, "--version"], cwd=raw_dir, timeout_seconds=timeout_seconds,
                             env=build_env(), stdout_path=stdout_path, stderr_path=stderr_path)
        if result.timed_out:
            raise AdapterError(f"semgrep --version exceeded its {timeout_seconds}s limit and was killed after "
                               f"{result.wall_seconds:.1f}s: {tail_text(result.stderr_path)}")
        if result.exit_code != 0:
            raise AdapterError(f"semgrep --version failed: {tail_text(result.stderr_path)}")
        text = stdout_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError) as exc:
        raise AdapterError(f"{what} could not be recorded: {exc}") from exc
    return text.strip()


def _shape(value: Any) -> str:
    return type(value).__name__


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AdapterError(message)


def _dotted_prefixes(directories) -> list[str]:
    # Semgrep builds check_id from the rule file's path: semgrep.rule_lang.convert_config_id_to_prefix
    # joins the directory components with dots (the anchor among them), calls .lstrip("./") on
    # that joined string, and only then deletes every character outside [A-Za-z0-9._-]; the
    # declared rule id follows. The path part is a machine location, so it is removed before
    # recording. The same steps run here in the same order. Deleting the same characters matters
    # because a cache directory containing a space or a parenthesis would otherwise never match;
    # stripping leading "." and "/" together matters because the lstrip drops leading dots as
    # well as the separator, so a checkout whose first path segment begins with a dot (a
    # ".cache" directory, a "../" relative config) never matched while a leading dot was kept.
    # Longest first, so a nested directory is stripped before a parent of it.
    prefixes: list[str] = []
    for directory in directories or ():
        if not isinstance(directory, (str, Path)):
            continue
        # pathlib splits the path, so a backslash separates components only on a platform whose
        # os.sep is a backslash. On POSIX a directory literally named "we\ird" stays one
        # component and the backslash is deleted by the sanitizer below, which is what Semgrep
        # does with it.
        joined = ".".join(Path(directory).parts)
        # Sanitizing the already joined string, as Semgrep does, leaves a segment that
        # sanitizes away entirely as an empty segment rather than dropping its separator.
        dotted = _RULE_ID_DROPPED.sub("", joined.lstrip("./"))
        # A path that leaves nothing but dots is not a usable prefix. Semgrep would still build
        # one ("." alone), but matching on it would strip a leading dot off any rule id.
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


def _claim_path(raw: str) -> str:
    """The payload path with a leading ``./`` removed, without inventing a rename.

    Semgrep emits the path with the separators of the platform it ran on, and the adapter reads
    the output of a scan that just ran on this one. So backslashes are translated only when the
    value cannot be a POSIX path: a Windows drive prefix, or any backslash when this platform's
    separator is a backslash. On POSIX a source file named ``we\\ird.py`` keeps the name it
    really has instead of becoming ``we/ird.py``, which names a different file or none at all.
    The cost is that a payload recorded on Windows and imported on POSIX keeps its backslashes.
    """
    if _NATIVE_SEPARATOR == "\\" or _WINDOWS_DRIVE.match(raw):
        raw = raw.replace("\\", "/")
    if raw.startswith("./"):
        raw = raw[2:]
    return raw


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

    Every value read here is type-checked and an unexpected JSON shape raises ``AdapterError``
    naming the offending field: ``results`` and each entry, ``check_id``, ``path``,
    ``start``/``end`` and their ``line``, ``extra``, ``extra.metadata``,
    ``extra.metadata.cwe``, and the ``extra.message``, ``extra.severity``,
    ``extra.fingerprint`` and ``extra.lines`` values. An optional field may be absent or null;
    a present value of another type is a shape error, so a non-string message is never
    ``str()``-ed into an allegation and a non-string severity or fingerprint is never dropped
    in silence. No other exception type is raised for payload content. This does not assign
    truth labels, split bundled findings, invent locations, or recover a rule id from a
    check_id whose path prefix none of the supplied directories match: such an id is kept
    verbatim.

    ``primary_location.path`` is the payload's ``path`` with a leading ``./`` removed.
    Backslashes become forward slashes only for a path that cannot be a POSIX one: a Windows
    drive prefix, or any backslash when this platform's separator is a backslash. On POSIX a
    file whose name contains a backslash keeps the name it really has, and a payload recorded
    on Windows and imported here keeps its backslashes rather than being guessed at.

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
        path = _claim_path(raw_path)
        start = _line_number(item, index, "start")
        end = _line_number(item, index, "end")
        if end < start:
            end = start
            notes.append(f"result {index}: end line before start line; clamped to start")
        raw_message = extra.get("message")
        _require(raw_message is None or isinstance(raw_message, str),
                 f"semgrep JSON result {index} has extra.message as a {_shape(raw_message)}, not a string")
        message = (raw_message or "").strip() or check_id
        claim: dict[str, Any] = {
            "claim_id": f"c{index}",
            "allegation": message,
            "kind": kind_for_cwes(cwes),
            "primary_location": {"path": path, "start_line": start, "end_line": end},
            "native_rule_id": rule_id,
            "raw_artifact_id": artifact_id,
        }
        fingerprint = extra.get("fingerprint")
        _require(fingerprint is None or isinstance(fingerprint, str),
                 f"semgrep JSON result {index} has extra.fingerprint as a {_shape(fingerprint)}, not a string")
        if fingerprint and fingerprint != _UNAVAILABLE:
            claim["native_id"] = fingerprint
        lines = extra.get("lines")
        _require(lines is None or isinstance(lines, str),
                 f"semgrep JSON result {index} has extra.lines as a {_shape(lines)}, not a string")
        if lines and lines != _UNAVAILABLE:
            claim["evidence_text"] = lines
        if lines == _UNAVAILABLE:
            login_gated = True
        severity = extra.get("severity")
        _require(severity is None or isinstance(severity, str),
                 f"semgrep JSON result {index} has extra.severity as a {_shape(severity)}, not a string")
        if severity:
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
    for directory in directories:
        # A NUL byte would reach subprocess as a raw ValueError from the C layer instead of
        # being reported as the setup failure it is.
        if "\x00" in directory:
            raise AdapterError(f"semgrep preparation config_dirs entry {directory!r} contains a NUL byte and "
                               "cannot name a directory")
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
        url = str(ruleset["url"])
        # A NUL byte reaches git through subprocess as a raw ValueError from the C layer, so it
        # is refused here, before anything is fetched.
        if "\x00" in url:
            raise AdapterError("semgrep config.ruleset.url contains a NUL byte and cannot name a repository")
        for entry in paths:
            if "\x00" in entry:
                raise AdapterError(f"ruleset path {entry!r} contains a NUL byte and cannot name a directory")
            relative = Path(entry)
            if relative.is_absolute() or ".." in relative.parts:
                raise AdapterError(f"ruleset path {entry!r} must stay inside the checkout: no absolute paths and no '..'")
        snapshot = fetch_snapshot(url, str(ruleset["commit"]), cache_root)
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
                # Exactly Semgrep's own selection for a --config directory: read_config_folder
                # walks rglob("*") and keeps is_config_suffix() files. Skipping dotfiles here
                # missed rules Semgrep loads, and keeping .test/.fixed YAMLs hashed files it
                # never reads, so the recorded hash described neither set.
                if not _is_loaded_rule_file(rule_file) or not rule_file.is_file():
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
        """Run Semgrep once over *source_dir* and translate its JSON into claims.

        Configuration and preparation are validated before the process starts, and the four raw
        output files are created exclusively under *raw_dir*: a bad value, and an output file
        that is already there, are setup failures (``AdapterError``), not a scan whose output
        can be interpreted. Nothing under *raw_dir* is replaced.
        """
        binary = _binary(spec)
        rule_timeout = _integer_config(spec, "rule_timeout_seconds", 30, minimum=0)
        jobs = _integer_config(spec, "jobs", 1, minimum=1)
        config_dirs, ruleset_commit, ruleset_tree_hash = _prepared_ruleset(preparation)
        stdout = raw_dir / "semgrep.json"
        stderr = raw_dir / "semgrep.stderr.txt"
        _claim_output(stdout, f"semgrep output under {raw_dir}")
        _claim_output(stderr, f"semgrep output under {raw_dir}")
        version = semgrep_version(binary, raw_dir)
        argv = [
            binary, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
            "--timeout", str(rule_timeout),
            "--jobs", str(jobs),
        ]
        for directory in config_dirs:
            argv.append(f"--config={directory}")
        argv.append(".")
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
