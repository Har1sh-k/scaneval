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

Every hashed byte comes from inside the pinned checkout. A symlink under a configured ruleset
directory is judged only when Semgrep would load it as a rule file, which is the selection above
and being a regular file once followed: such a link is refused when its target resolves outside
the checkout root, and is otherwise hashed by the content it resolves to, recorded under the path
the link occupies. A symlink Semgrep would not read as a rule file is ignored, because rules
repositories carry symlinks for other things. Rules reachable only through a symlinked directory
are covered by neither this inventory nor Semgrep's own walk, since neither descends into one.
Live ``p/...`` registry configs are refused because they are moving targets, not pins.

Raw output files are create-only. ``semgrep.json``, ``semgrep.stderr.txt``,
``semgrep-version.txt`` and ``semgrep-version.stderr.txt`` are claimed with an exclusive
create before the process starts, so an existing file under the supplied raw directory is a
setup failure rather than silently replaced evidence.

A result the importer cannot turn into a claim is import loss, not a detail: it is counted,
and a count above zero degrades the outcome to ``partial`` with unresolved bundles and error
code ``import_loss``, so a scan that reported a finding ScanEval could not read can earn
neither completeness nor silence credit for it.

Both processes the adapter starts, the version probe and the scan, go through ``run_command``,
and both pass ``--disable-version-check``, so neither asks the network for a newer release or
writes that answer under ``HOME``. Every file either of them wrote is read back without following
a link and without blocking on a named pipe (:func:`~scaneval.execution.read_regular_file` and
:func:`~scaneval.adapters.base.tail_text`), because the process that wrote the raw directory can
leave anything at those names. That is what makes the adapter ``oci_compatible``: under the
``oci`` backend both run in the configured image, the binary defaults to that image's own
``semgrep`` rather than a host install, and the pinned rules checkout is declared as a read-only
runtime mount at its own path, so the ``--config`` paths and the ``check_id`` prefixes they
produce are the same inside the container as outside it.

PR mode. A request whose ``input.mode`` is ``pr`` is a review of the change between two commits of
the workspace's own history (:mod:`scaneval.adapters.pr`), and the scan argv is the full-scan argv
plus ``--baseline-commit=<base>``: Semgrep's own diff scan. Semgrep then scans the files changed
between the two commits and drops every finding its own baseline comparison matches to the base
commit, one that moved with a renamed file included; this adapter compares nothing itself. Semgrep
does it by resetting the workspace tree to the base commit and back to head in place (for a clean
repository, which the request promises and this adapter checks first), so the source must be
writable. Under the ``oci`` backend, which mounts it read-only, a PR request is answered
``unsupported`` with the reason recorded and nothing is run. A kill between the two resets leaves
the tree at the base commit, which the invocation's own source check then reports.

A diff scan over a change that touches only deleted paths and files outside the supported
languages scans nothing and reports nothing, which in a full scan is the ``nothing_scanned``
error. In a PR review it is a success with a note (an empty baseline review), and only when
Semgrep exited 0 with no diagnostic of any level, no result was lost in the import, and git, run
by this adapter before Semgrep starts, shows that no path present at head has the extension of a
supported language. Anything else stays the error, with the reason added. That extension test is
this adapter's own approximation of what Semgrep would scan, not Semgrep's target selection, and
it errs toward the error. Import-loss accounting and every other outcome rule below are the
full-scan ones, unchanged.
"""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
from typing import Any, NamedTuple

from ..execution import read_regular_file
from ..kinds import cwe_ids, kind_for_cwes, mapping_version
from ..materialize import MaterializationError, fetch_snapshot, sha256_file, tree_hash
from .base import (Adapter, AdapterError, NativeOutcome, SystemSpec, active_backend, build_env, run_command,
                   tail_text)
from .pr import Change, pr_range, workspace_changes


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
# Semgrep 1.177's own extension table (semgrep_interfaces/lang.json) for the five languages this adapter
# supports. It is only used to ask whether a change touches a file this adapter's languages could have
# scanned; it is not Semgrep's target selection, which also applies ignore rules, size limits and rule
# languages that are not known here. See _source_paths.
_SOURCE_SUFFIXES = frozenset({".cjs", ".go", ".js", ".jsx", ".mjs", ".py", ".pyi", ".rs", ".ts", ".tsx"})
# The diagnostics Semgrep 1.177 treats as a scan failure (semgrep.error.SemgrepCoreError.is_scan_failure): a
# baseline scan that ends in one of them makes it drop the head findings of that file or rule.
_SCAN_FAILURES = frozenset({"Timeout", "OutOfMemory", "StackOverflow", "FixpointTimeout", "TimeoutDuringInterfile",
                            "OutOfMemoryDuringInterfile"})
# Recorded on every PR-mode outcome, so a reader of the result knows what the claims are relative to.
_PR_NOTE = (
    "PR mode: Semgrep ran with --baseline-commit set to the request's base commit over the workspace's two-commit "
    "history. It scans the files changed between base and head and reports only the findings its own baseline "
    "comparison does not match to the base commit; this adapter does no baseline comparison of its own, so a finding "
    "Semgrep matched to the base is absent from the claims rather than marked pre-existing, and a file the change did "
    "not touch is not scanned. Semgrep 1.177 also drops a head finding on a file whose baseline scan failed (a "
    "timeout or an out-of-memory) and records that failure only as a diagnostic in the raw errors list.")
# A backslash separates directories only on Windows. On POSIX it is an ordinary character in a
# file name, so a payload path is only translated when it cannot be a POSIX path.
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_NATIVE_SEPARATOR = os.sep
# Leading "./" segments name the same file the rest of the path does: "./x", ".//x" and "././x"
# are all "x". Consuming the slashes together with the dot is what keeps ".//x" from becoming
# "/x", an absolute path naming a different file.
_LEADING_DOT_SEGMENTS = re.compile(r"^(?:\./+)+")


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


def _discard_outputs(paths) -> None:
    """Remove raw files this module created for an attempt that recorded nothing usable.

    A failure that leaves zero-byte artifacts behind makes the next attempt in the same raw
    directory fail on the create-only claim, which reports a file collision instead of the
    failure that actually stopped the first one. Only files the failing call created are passed
    here, so evidence from an earlier attempt is never removed.
    """
    for path in paths:
        try:
            path.unlink()
        except OSError:
            pass


def _binary(spec: SystemSpec) -> str:
    """``config.binary`` when set; under the ``oci`` backend the image's own ``semgrep``; else a host install.

    A host install is looked up only when commands run on the host: under ``oci`` the process
    runs in the configured image, where a path to this machine's virtual environment names
    nothing, so the default there is the ``semgrep`` on the image's own ``PATH``.
    """
    configured = spec.config.get("binary")
    if configured:
        text = str(configured)
        # A NUL byte reaches subprocess as a raw ValueError from the C layer, which would leave
        # the adapter instead of being reported as the setup failure it is.
        if "\x00" in text:
            raise AdapterError("semgrep config.binary contains a NUL byte and cannot name an executable")
        return text
    if getattr(active_backend(), "name", None) == "oci":
        return "semgrep"
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

    A failure removes the two files this call created, carrying their content into the raised
    message as a stderr tail instead. Left behind, the empty pair would make a second attempt in
    the same raw directory fail on the create-only claim and report a file collision rather than
    the failure that actually stopped the first one. A file this call did not create is never
    removed: that one is an earlier attempt's evidence.

    The probe passes ``--disable-version-check``. Without it Semgrep asks the network for its
    latest release and caches the answer under ``HOME`` (``~/.cache/semgrep_version``), which is
    a network call and a host write outside the scan, and fails outright where there is no
    network. The flag leaves the reported version unchanged.
    """
    stdout_path = raw_dir / "semgrep-version.txt"
    stderr_path = raw_dir / "semgrep-version.stderr.txt"
    what = f"semgrep --version output under {raw_dir}"
    _claim_output(stdout_path, what)
    created = [stdout_path]
    try:
        _claim_output(stderr_path, what)
        created.append(stderr_path)
        try:
            result = run_command([binary, "--version", "--disable-version-check"], cwd=raw_dir,
                                 timeout_seconds=timeout_seconds, env=build_env(), stdout_path=stdout_path,
                                 stderr_path=stderr_path)
            if result.timed_out:
                raise AdapterError(f"semgrep --version exceeded its {timeout_seconds}s limit and was killed after "
                                   f"{result.wall_seconds:.1f}s: {tail_text(result.stderr_path)}")
            if result.exit_code != 0:
                raise AdapterError(f"semgrep --version failed: {tail_text(result.stderr_path)}")
            # The one read of a file the probe could have replaced: a link is refused rather than
            # followed to a file whose content would become the recorded version.
            text = read_regular_file(stdout_path).decode("utf-8", errors="replace")
        except (OSError, UnicodeDecodeError) as exc:
            raise AdapterError(f"{what} could not be recorded: {exc}") from exc
    except AdapterError:
        _discard_outputs(created)
        raise
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


def _claim_path(raw: str) -> tuple[str, str]:
    """``(path relative to the scanned tree, "")``, or ``(raw, reason)`` when it is not one.

    Semgrep emits the path with the separators of the platform it ran on, and the adapter reads
    the output of a scan that just ran on this one. So backslashes are translated only when the
    value cannot be a POSIX path: a Windows drive prefix, or any backslash when this platform's
    separator is a backslash. On POSIX a source file named ``we\\ird.py`` keeps the name it
    really has instead of becoming ``we/ird.py``, which names a different file or none at all.
    The cost is that a payload recorded on Windows and imported on POSIX keeps its backslashes.

    The only other normalization is dropping leading ``./`` segments, which name the same file:
    ``./app.py``, ``.//app.py`` and ``././app.py`` all become ``app.py``. A returned path is
    therefore always usable as a claim location: never absolute, never empty, never carrying a
    ``..`` segment and never carrying a NUL byte, which is exactly what the scan-result contract
    requires of one. A value that cannot be expressed that way is not rewritten at all: an
    absolute path, a drive-prefixed path, one that names nothing once its dot segments are
    removed (``./``, ``.``), one that leaves the scanned tree (``..``, ``../x.py``) and one
    holding a NUL byte come back verbatim with the reason they are unusable, for the caller to
    report.
    """
    text = raw
    if "\x00" in text:
        return raw, "it holds a NUL byte, which cannot name a file"
    if _NATIVE_SEPARATOR == "\\" or _WINDOWS_DRIVE.match(text):
        text = text.replace("\\", "/")
    if _WINDOWS_DRIVE.match(text):
        return raw, "it carries a drive prefix, so it is absolute on the platform that emitted it"
    if text.startswith("/"):
        return raw, "it is an absolute path"
    remainder = _LEADING_DOT_SEGMENTS.sub("", text)
    segments = [segment for segment in remainder.split("/") if segment not in ("", ".")]
    if not segments:
        return raw, "it names nothing once its dot segments are removed"
    if ".." in segments:
        return raw, "it leaves the scanned tree through a '..' segment"
    return remainder, ""


def _line_number(item: dict, index: int, key: str) -> int:
    span = item.get(key)
    _require(isinstance(span, dict), f"semgrep JSON result {index} has {key} as a {_shape(span)}, not an object")
    line = span.get("line")
    _require(isinstance(line, int) and not isinstance(line, bool),
             f"semgrep JSON result {index} has {key}.line as a {_shape(line)}, not an integer")
    return int(line)


class SemgrepImport(NamedTuple):
    """One import of a Semgrep JSON ``results`` array.

    ``lost`` is the number of results the importer could not turn into a claim. It is part of
    the return shape rather than a note, for the same reason
    :class:`~scaneval.adapters.llm_harness.HarnessImport` carries one: the caller must degrade
    the outcome when it is above zero, because a result ScanEval dropped is a finding Semgrep
    did report, so the scan cannot stand as a complete or quiet observation of the input.
    """

    claims: list[dict]
    notes: list[str]
    lost: int


def import_semgrep_results(payload: dict, *, artifact_id: str = ARTIFACT_JSON,
                           ruleset_roots=(), config_dirs=()) -> SemgrepImport:
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

    ``primary_location.path`` is the payload's ``path`` with its leading ``./`` segments
    removed. Backslashes become forward slashes only for a path that cannot be a POSIX one: a
    Windows drive prefix, or any backslash when this platform's separator is a backslash. On
    POSIX a file whose name contains a backslash keeps the name it really has, and a payload
    recorded on Windows and imported here keeps its backslashes rather than being guessed at.
    A payload path that cannot be expressed as a path inside the scanned tree (an absolute or
    drive-prefixed path, one that names nothing once its dot segments are removed, one that
    leaves the tree through ``..``, or one holding a NUL byte) is neither rewritten nor
    recorded: a claim location must be a relative path, so that result contributes a note
    naming it and its reason instead of a claim, and it is counted in ``lost``. ``lost`` is
    every result Semgrep reported that did not become a claim, and the caller must degrade the
    outcome when it is above zero: a dropped result is a finding Semgrep did report, so the
    scan can earn neither completeness nor quiet credit for that file. A shape error is not
    counted here at all, because it raises ``AdapterError`` and abandons the whole payload.

    Whether an unshortened id is also *noted* is a heuristic keyed on the supplied roots'
    leading segments: the note fires only when the id's first segment is one of those segments
    (the last segment of each root is excluded, being the language or category directory that
    legitimately opens a rule id). So the note can miss a machine path that came from a root
    nobody supplied, and it can flag an id that carries no path at all.
    """
    claims: list[dict] = []
    notes: list[str] = []
    lost = 0
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
        path, unusable = _claim_path(raw_path)
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
        if unusable:
            # Every field of the result was still read and type-checked above, so a malformed
            # payload is reported whether or not its location can be used; only the claim is
            # left out, because a claim location has to be a relative path. Semgrep reported a
            # finding here and ScanEval is delivering none, so it counts as import loss.
            lost += 1
            notes.append(f"result {index}: path {raw_path!r} cannot be expressed as a path inside the scanned "
                         f"tree ({unusable}); no claim was recorded for it and the raw payload keeps the result "
                         "verbatim")
            continue
        claims.append(claim)
    for head, count in sorted(unmatched.items()):
        notes.append(f"{count} check_id(s) start with {head!r}, a path-like prefix that no supplied ruleset root "
                     "matches; native_rule_id keeps those ids verbatim and may contain a machine path")
    if login_gated:
        notes.append("Semgrep OSS omitted matched source text and fingerprints (requires login); evidence_text left absent")
    return SemgrepImport(claims, notes, lost)


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


def _listed(names: list[str], limit: int = 8) -> str:
    """At most *limit* of *names* joined for a note, and how many more there were."""
    shown = ", ".join(names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def _source_paths(changes: tuple[Change, ...]) -> list[str]:
    """The paths present at head whose extension names a language this adapter scans, sorted.

    This is the adapter's own approximation of "a file Semgrep would scan", made from Semgrep's
    extension table for the five supported languages and nothing else. It is deliberately the
    cautious direction: a changed ``.py`` file that Semgrep skipped for its own reasons (a ``tests/``
    directory, a size limit, a generated-file marker) still counts here, so a diff that touches one
    is never reported as an empty review. What it does not see is a file in another language that a
    ruleset could target (YAML, Dockerfiles), or a script with no extension whose shebang names one
    of these languages; a change to only such files, from a scan that read nothing and reported no
    diagnostic, is called an empty review.
    """
    return sorted(change.path for change in changes
                  if change.present and PurePosixPath(change.path).suffix.lower() in _SOURCE_SUFFIXES)


def _error_type(entry: dict) -> str:
    """The name of a Semgrep diagnostic's type, which the JSON writes as a string or as ``[name, ...]``."""
    kind = entry.get("type")
    if isinstance(kind, list) and kind and isinstance(kind[0], str):
        return kind[0]
    return kind if isinstance(kind, str) else ""


def _empty_baseline_review(payload: dict, changes: tuple[Change, ...]) -> tuple[bool, str]:
    """Whether a baseline scan that read nothing is an empty review, and the sentence that says why or why not.

    Called only for an exit-0 scan that reported no result and an explicit empty ``paths.scanned``.
    It is an empty review only when Semgrep also reported no diagnostic of any level and git shows the
    change touches no path this adapter's languages could have scanned (see :func:`_source_paths`):
    deleted paths, and paths outside those languages. Either counter-example is a scan that looked
    at nothing it should have looked at, which stays the ``nothing_scanned`` error.
    """
    reasons = []
    diagnostics = payload.get("errors")
    if isinstance(diagnostics, list) and diagnostics:
        reasons.append(f"it also reported {len(diagnostics)} diagnostic(s)")
    source = _source_paths(changes)
    if source:
        reasons.append(f"the change touches {len(source)} file(s) in a language this adapter scans "
                       f"({_listed(source)}), which Semgrep did not scan; its own ignore rules, or no rule for the "
                       "language, can cause that")
    if reasons:
        return False, "; ".join(reasons) + ", so this is not an empty baseline review"
    deleted = [change.path for change in changes if change.status == "D"]
    other = sorted(change.path for change in changes if change.present)
    parts = ([f"{len(deleted)} deleted path(s)"] if deleted else []) + (
        [f"{len(other)} path(s) outside those languages ({_listed(other)})"] if other else [])
    return True, ("Empty baseline review: Semgrep exited 0 with no diagnostics, scanned no file and reported nothing, "
                  "and git shows the change touches no file in a language this adapter scans, only "
                  + " and ".join(parts) + ". Semgrep's diff scan had no changed source to read, so there was "
                  "nothing for it to report; this is not a scan that read nothing.")


def _pr_review_notes(payload: dict, changes: tuple[Change, ...], scanned: list) -> list[str]:
    """What a reader of a PR-mode result needs beyond the claims: failed scans and unscanned source."""
    notes = []
    diagnostics = payload.get("errors")
    failures = 0
    if isinstance(diagnostics, list):
        failures = sum(1 for entry in diagnostics if isinstance(entry, dict) and _error_type(entry) in _SCAN_FAILURES)
    if failures:
        notes.append(f"{failures} diagnostic(s) of a scan-failure type (timeout, out of memory, stack overflow) are in "
                     "the raw errors list. In --baseline-commit mode Semgrep drops a head finding on a file whose "
                     "baseline scan ended that way, so silence about those files is not a negative result.")
    covered = {_claim_path(item)[0] for item in scanned if isinstance(item, str)}
    unscanned = [path for path in _source_paths(changes) if path not in covered]
    if scanned and unscanned:
        notes.append(f"PR mode: {len(unscanned)} changed file(s) in a language this adapter scans were not among the "
                     f"paths Semgrep reports as scanned ({_listed(unscanned)}); its own ignore rules, or no rule for "
                     "the language, can cause that, and nothing was looked for in them.")
    return notes


class SemgrepAdapter(Adapter):
    name = "semgrep"
    adapter_version = "2.0.0"
    requires_git = False
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})
    scan_modes = frozenset({"full", "pr"})
    oci_compatible = True

    def runtime_mounts(self, spec: SystemSpec, preparation: dict) -> tuple[str, ...]:
        """The pinned rules checkout, which the scan reads through its ``--config`` directories.

        The whole checkout rather than each configured directory, because ``prepare()`` accepts a
        rule file that is a symbolic link to another file inside the checkout, and inside a
        container that link resolves only if its target is mounted too: mounting the directories
        alone would drop such a rule silently while the recorded ruleset hash still counted it.
        The checkout is one pinned commit in the cache, never the cache itself. A preparation
        recorded before ``ruleset_root`` existed falls back to the configured directories.
        """
        directories, _commit, _digest = _prepared_ruleset(preparation)
        root = preparation.get("ruleset_root")
        if isinstance(root, str) and root and "\x00" not in root and all(
                directory == root or Path(directory).is_relative_to(root) for directory in directories):
            return (root,)
        return tuple(sorted(set(directories)))

    def prepare(self, spec: SystemSpec, cache_root: Path) -> dict[str, Any]:
        """Fetch the pinned rules commit and record an inventory of the rule files it holds.

        The symlink rule, exactly: a symlink under a configured ruleset path is refused only
        when Semgrep would load it as a rule file, which is ``_is_loaded_rule_file`` and being a
        regular file once followed (``read_config_folder`` keeps ``is_config_suffix(l) and
        l.is_file()``), and its target resolves outside the pinned checkout root. Such a link
        would put content the recorded commit does not hold into the recorded hash and into the
        scan. A link Semgrep would load whose target resolves inside the checkout is kept and
        hashed by the content it resolves to, under the path the link occupies. Every other
        symlink is ignored, including one to a directory and one whose target is missing, since
        Semgrep reads neither.

        Every failure raised here is an ``AdapterError``, which is what the adapter contract
        promises its callers: a bad configuration value, a ruleset path that leaves the
        checkout, and the ``MaterializationError`` that a short or non-hex commit, an
        unreachable URL, or a modified cache entry raises, whose message is kept verbatim
        inside the wrapper.
        """
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
        try:
            snapshot = fetch_snapshot(url, str(ruleset["commit"]), cache_root)
        except MaterializationError as exc:
            # The runner records either exception as a skip, but prepare() is contracted to
            # raise AdapterError, so the materialization failure is wrapped rather than left to
            # escape as a second exception type with the same meaning.
            raise AdapterError(f"semgrep ruleset could not be materialized: {exc}") from exc
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
                # Exactly Semgrep's own selection for a --config directory: read_config_folder
                # walks rglob("*") and keeps `is_config_suffix(l) and l.is_file()`. Skipping
                # dotfiles here missed rules Semgrep loads, and keeping .test/.fixed YAMLs
                # hashed files it never reads, so the recorded hash described neither set. The
                # same two questions decide a symlink, which is why a linked README or a link
                # to a directory or to a missing target is passed over rather than refused:
                # Semgrep opens none of them, and rules repositories do carry them.
                if not _is_loaded_rule_file(rule_file) or not rule_file.is_file():
                    continue
                try:
                    resolved = rule_file.resolve()
                except (OSError, ValueError) as exc:
                    raise AdapterError(f"rule file {rule_file} could not be resolved: {exc}") from exc
                # A file Semgrep will load has to hold content the pinned commit holds.
                # resolve() follows symlinks, so a link out of the checkout is refused here and
                # a link inside it is hashed below by the content it resolves to. rglob does not
                # descend into a symlinked directory, and neither does Semgrep's own walk.
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

        A result Semgrep reported that the importer could not turn into a claim sets
        ``bundles_resolved`` false for every outcome built after the import, names itself in
        whichever failure message that branch already carries, and, where the run would
        otherwise have been a clean success, makes the outcome ``partial`` with error code
        ``import_loss``. A timeout and an unreadable payload return before the import, so
        neither reports a loss count: nothing was imported at all.

        A PR request (``request["input"]["mode"] == "pr"``) adds one option to the argv,
        ``--baseline-commit=<base>``, and is otherwise the same scan. It is refused before anything
        runs, as an ``AdapterError``, when the request does not name two full commit ids or the
        workspace does not hold the clean two-commit history it names, and it is answered
        ``unsupported``, not run, under the ``oci`` backend. Any mode but ``full`` and ``pr`` is
        refused too, so a request this adapter cannot serve is never run as a full scan. What a PR
        review that scanned nothing is called, and when, is :func:`_empty_baseline_review`'s
        rule, stated in the module docstring.
        """
        pr = pr_range(request, self)
        binary = _binary(spec)
        rule_timeout = _integer_config(spec, "rule_timeout_seconds", 30, minimum=0)
        jobs = _integer_config(spec, "jobs", 1, minimum=1)
        config_dirs, ruleset_commit, ruleset_tree_hash = _prepared_ruleset(preparation)
        changes: tuple[Change, ...] = ()
        if pr is not None:
            if getattr(active_backend(), "name", None) == "oci":
                return NativeOutcome(
                    status="unsupported", exit_code=None, command=[],
                    error={"code": "unsupported_mode",
                           "message": "semgrep does not run a PR review under the oci backend: --baseline-commit "
                                      "resets the scanned tree to the merge base and restores it in place, and "
                                      "that backend mounts the source read-only, so the scan was not started"},
                    notes=["Unsupported work stays in the denominator; nothing was executed."])
            # Read before Semgrep starts, from a repository nothing but the runner has written to.
            changes = workspace_changes(Path(source_dir), pr)
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
        if pr is not None:
            argv.append(f"--baseline-commit={pr.base}")
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
                    usage={"cost_usd": 0.0},
                    notes=["Semgrep OSS has no metered cost; license cost not included."]
                    + ([_PR_NOTE] if pr is not None else []))
        if result.timed_out:
            if pr is not None:
                base["notes"].append(
                    "Semgrep was killed at the timeout. Its --baseline-commit scan resets the workspace tree to the "
                    "base commit and back in place, so a kill between the two resets leaves the tree at the base "
                    "commit; the invocation's source check reports that as a modified source.")
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True, error={"code": "timeout",
                                 "message": f"semgrep exceeded {timeout_seconds}s; output written at exit only"}, **base)
        try:
            # Read without following a link and without blocking on a pipe: the scan wrote this
            # directory, and under an isolating backend a link planted here would name a host file.
            payload = json.loads(read_regular_file(stdout).decode("utf-8"))
            ruleset_root = preparation.get("ruleset_root")
            # config_dirs stays as the fallback so a preparation recorded before ruleset_root
            # existed still keeps the cache path out of native_rule_id.
            imported = import_semgrep_results(
                payload,
                ruleset_roots=(ruleset_root,) if isinstance(ruleset_root, str) and ruleset_root else (),
                config_dirs=config_dirs,
            )
            claims, notes = imported.claims, imported.notes
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
        if pr is not None:
            base["notes"] += _pr_review_notes(payload, changes, scanned)
        base["tool_versions"]["semgrep_reported"] = reported_version
        # Import loss leaves the claim set incomplete, so the bundles it delivers are not
        # resolved: the scoring contract then refuses both completed-control and quiet credit.
        base["bundles_resolved"] = imported.lost == 0
        loss_message = None
        if imported.lost:
            loss_message = (f"{imported.lost} semgrep result(s) could not be imported: "
                            + "; ".join(notes))[:2000]
            base["notes"].append(
                f"Import loss: {imported.lost} result(s) semgrep reported could not be imported, so "
                "this scan can earn neither completeness nor quiet credit.")

        def with_loss(message: str) -> str:
            """The branch's own message, with the import loss named beside it."""
            return f"{message}; {loss_message}"[:2000] if loss_message else message

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
                message = with_loss(f"semgrep exited {result.exit_code} with no scanned paths and no "
                                    f"results{detail}; stderr: {tail_text(stderr)}")
                return NativeOutcome(status="error", exit_code=result.exit_code, claims=[],
                                     error={"code": f"exit_{result.exit_code}", "message": message[:2000]}, **base)
            message = with_loss(f"semgrep exited {result.exit_code} after scanning {len(scanned)} "
                                f"paths{detail}; stderr: {tail_text(stderr)}")
            return NativeOutcome(status="partial", exit_code=result.exit_code, claims=claims,
                                 error={"code": f"exit_{result.exit_code}", "message": message[:2000]}, **base)
        if fatal:
            base["notes"].append(f"{len(fatal)} error-level Semgrep diagnostics; see raw semgrep.json errors")
            reason = str(fatal[0].get("message", "")).strip()
            detail = f"; reason: {reason}" if reason else ""
            if not scanned and not claims:
                # Exit 0 does not make this a clean run: nothing was scanned and nothing was
                # reported, so the invocation observed no source at all. Calling it partial
                # would let a failed run read as a quiet negative result.
                message = with_loss("semgrep exited 0 with error-level diagnostics, no scanned paths "
                                    f"and no results{detail}; stderr: {tail_text(stderr)}")
                return NativeOutcome(status="error", exit_code=0, claims=[],
                                     error={"code": "scan_errors", "message": message[:2000]}, **base)
            # The same shape as every other failure message here: what the run did, the first
            # diagnostic when it carries one, and the stderr tail. Reporting the diagnostic
            # alone left an empty message whenever Semgrep sent an empty one, and dropped the
            # only other place the reason could be.
            message = with_loss(f"semgrep exited 0 after scanning {len(scanned)} paths with {len(fatal)} "
                                f"error-level diagnostics{detail}; stderr: {tail_text(stderr)}")
            return NativeOutcome(status="partial", exit_code=0, claims=claims,
                                 error={"code": "scan_errors", "message": message[:2000]}, **base)
        if skipped:
            base["notes"].append(f"Semgrep skipped {len(skipped)} paths under its own ignore rules; see raw semgrep.json paths")
        if not scanned_reported:
            base["notes"].append("Semgrep output reported no paths.scanned list, so an empty result set here cannot "
                                 "be distinguished from a run that looked at no files")
        elif not scanned and not claims:
            # An explicit empty scanned list means Semgrep opened no file. Silence from a scan
            # that read nothing is missing evidence, not a clean negative control. A PR review
            # is the one place it can also be the truth: a change that touched only deleted
            # paths and files outside the scanned languages leaves a diff scan nothing to read,
            # and git, asked by this adapter, is what says so. Anything else stays an error.
            explanation = ""
            if pr is not None:
                empty, detail = _empty_baseline_review(payload, changes)
                if empty and not imported.lost:
                    base["notes"].append(detail)
                    return NativeOutcome(status="success", exit_code=0, claims=[], **base)
                explanation = f"; {detail}" if not empty else ""
            message = with_loss("semgrep exited 0 having scanned no files and reported no results: Semgrep "
                                "looked at no source at all, which its ignore rules, an empty tree, or a "
                                f"default-ignored directory layout can cause{explanation}; stderr: {tail_text(stderr)}")
            return NativeOutcome(status="error", exit_code=0, claims=[],
                                 error={"code": "nothing_scanned", "message": message[:2000]}, **base)
        if loss_message:
            # A scan whose results did not all survive the import is not a clean run: it is
            # partial, and the count and the reason travel with it as an explicit error.
            return NativeOutcome(status="partial", exit_code=0, claims=claims,
                                 error={"code": "import_loss", "message": loss_message}, **base)
        return NativeOutcome(status="success", exit_code=0, claims=claims, **base)
