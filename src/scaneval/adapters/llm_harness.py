"""Own-harness adapter for the securevibes-agent / Fieldglass engine family.

The harness runs unchanged through its own engine entry point inside its own ``tsx``.
ScanEval only injects the harness's default model runner wrapped by the observer SDK
and a progress reporter, then imports the finding records the engine wrote. Findings
are file-level; this importer keeps them file-level and never invents line ranges.

A record the importer cannot read is import loss, not a detail: it is counted, and a
count above zero degrades the outcome to ``partial`` with unresolved bundles and error
code ``import_loss``, so a scan that emitted a finding ScanEval could not read can earn
neither completeness nor silence credit for it.

So is a record the importer never saw. The harness names the findings it wrote in its own
summary, and :func:`reconcile_import` compares that self-report against the claims the import
delivered: a finding the harness says it wrote that did not arrive is the same loss, counted
the same way. Counting only what the importer could see made the worst case invisible, because
a scan that lost every finding before the import left nothing to count and read as a clean
success. A self-report in a shape the reader cannot parse is counted as loss for the same
reason: unreadable evidence is missing evidence, not evidence that nothing was lost.

Only records this scan produced are imported. The findings directory is snapshotted before
the harness process starts, and a record already present with the same bytes is left out, so
a finding record the repository under test shipped cannot be counted as a detection. That
establishes that the bytes are new to the workspace, not that the harness's model wrote them.

Every path this adapter touches after the harness process starts is a path the harness could
have replaced, and any component of it can be a symbolic link, not only the last one. So each
read and each copy destination goes through one :class:`Enclosure`, which resolves the whole
path and proves it is still inside the workspace the scanner was handed or the staging
directory this run created. A path that resolves out is refused and counted, never followed.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, NamedTuple

from ..kinds import kind_for_harness_class
from ..materialize import HARNESS_STATE_DIRS, git_command, resolve_within
from .base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command, tail_text


DRIVER = Path(__file__).with_name("llm_harness_driver.mts")
HARNESS_PRESETS: dict[str, dict[str, Any]] = {
    "securevibes-agent": {
        "state_dir": ".securevibes",
        "engine_entry": "src/runtime/engine.ts",
        "runner_entry": "src/runtime/pi-runner.ts",
        "mock_entry": "src/testing/mock-llm-runner.ts",
        "plan_file": "bootstrap-plan.md",
    },
    "fieldglass": {
        "state_dir": ".fieldglass",
        "engine_entry": "src/runtime/engine.ts",
        "runner_entry": "src/runtime/pi-runner.ts",
        "mock_entry": "src/testing/mock-llm-runner.ts",
        "plan_file": "bootstrap-plan.md",
    },
}
_ARRAY = re.compile(r"^\[(.*)\]$")
# What each harness route asks its model CLI to allow. Recorded as the harness's own
# declaration; this adapter never verifies that the CLI honored it, and it observes no
# tool call either way, so these strings explain an unavailable category rather than
# standing in for one.
TOOL_POLICY = {
    "pi": "the whole tool surface is disabled with --no-tools.",
    "claude": "network and spawn tools are denied with --disallowedTools; file tools such as Read and Bash remain permitted inside an isolated working directory.",
    "mock": "no model process is spawned, so no tool surface exists.",
}


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Parse the harness's ``key: value`` frontmatter (arrays in brackets, JSON-quoted strings)."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    block = text[3:end].strip("\n")
    body = text[end + 4:].lstrip("\n")
    record: dict[str, Any] = {}
    for line in block.splitlines():
        if ":" not in line or line.startswith(" "):
            continue
        key, _, raw = line.partition(":")
        record[key.strip()] = _scalar(raw.strip())
    return record, body


def _scalar(raw: str) -> Any:
    if raw == "":
        return ""
    match = _ARRAY.match(raw)
    if match:
        inner = match.group(1).strip()
        return [] if not inner else [_scalar(item.strip()) for item in _split_items(inner)]
    if raw.startswith('"'):
        try:
            return json.loads(raw)
        except ValueError:
            return raw.strip('"')
    if raw in ("true", "false"):
        return raw == "true"
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


def _split_items(inner: str) -> list[str]:
    items, current, quoted = [], [], False
    for char in inner:
        if char == '"':
            quoted = not quoted
        if char == "," and not quoted:
            items.append("".join(current))
            current = []
        else:
            current.append(char)
    items.append("".join(current))
    return [item for item in items if item.strip()]


class Enclosure(NamedTuple):
    """The two directories this adapter may touch once the harness has started, and the rule.

    ``workspace`` is the exported source the scanner was handed: every read after the harness
    process starts must resolve inside it. ``staging`` is this run's raw output directory: every
    copy destination must resolve inside that. Both checks are
    :func:`~scaneval.materialize.resolve_within`, which resolves the path whole, so a link
    anywhere along it is caught and not only one in the last component.

    That is the difference this class exists for. The importer used to check each record for
    being a link and never its ancestors, so a link one level up, at the harness state directory
    or at any parent of it, left every record behind it looking like an ordinary regular file in
    an ordinary directory. Records from anywhere on the host were read, staged into the bundle,
    and imported as claims of this scan. Checking the last component is not a containment check;
    resolving the whole path is.
    """

    workspace: Path
    staging: Path

    def read(self, path: Path) -> Path | None:
        """*path* when it still resolves inside the workspace the scanner was handed, else ``None``."""
        return resolve_within(path, self.workspace)

    def write(self, path: Path) -> Path | None:
        """*path* when it still resolves inside this run's staging directory, else ``None``."""
        return resolve_within(path, self.staging)


class LostRecord(NamedTuple):
    """One finding record this scan produced that did not become a claim.

    ``name`` is the record's file name, or the findings path itself when nothing could be
    listed. ``finding_id`` is the id in its frontmatter when the importer got far enough to read
    one, and ``None`` otherwise. That distinction is what :func:`reconcile_import` needs: a
    record dropped under a known id explains a self-reported finding that never arrived, and one
    dropped before its id could be read explains nothing in particular.
    """

    name: str
    finding_id: str | None
    reason: str

    @property
    def note(self) -> str:
        """The note this loss reads as in the record: the id when there is one, else the name."""
        return f"{self.finding_id or self.name}: {self.reason}"


class HarnessImport(NamedTuple):
    """One import of the harness's own finding records.

    ``losses`` is every record the importer could not turn into a claim, for any reason. The
    caller must degrade the outcome when there is one: a record ScanEval dropped is a finding
    the scanner did emit, so the scan cannot stand as a complete or quiet observation. A
    directory listing that failed contributes one entry, so the count is a floor rather than an
    exact number whenever a loss says a listing failed.

    ``lost`` is derived from ``losses`` rather than counted alongside it, so the count and the
    list of reasons cannot disagree about how much was lost.
    """

    claims: list[dict]
    artifacts: list[dict]
    notes: list[str]
    losses: tuple[LostRecord, ...]

    @property
    def lost(self) -> int:
        """How many finding records did not become claims."""
        return len(self.losses)


class FindingsBaseline(NamedTuple):
    """What the harness findings directory held before the scan ran.

    ``digests`` maps each ``*.md`` file name present beforehand to the SHA-256 of its bytes,
    or to ``None`` when the file was there but could not be read. ``established`` is false
    when the directory could not be listed at all, which is not the same as an empty
    directory: nothing can then be attributed to the scan.
    """

    digests: dict[str, str | None]
    established: bool
    note: str | None


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _list_markdown(directory: Path, enclosure: Enclosure) -> tuple[list[str], str | None, bool]:
    """Sorted ``*.md`` names in *directory*, a note naming any failure, and whether it exists.

    Enumeration is explicit rather than delegated to :meth:`Path.glob`, which swallows the
    ``OSError`` the directory walk raises and would make an unreadable directory
    indistinguishable from an empty one. The third value is false only when the directory is
    absent; a directory that exists and cannot be listed returns true with a note, so the
    caller counts the records it could not see instead of reporting none.

    A findings path that does not resolve inside the workspace is one of those failures, not a
    directory to read: what lies behind it is not the workspace this scan was given, so records
    found there were not shown to be anything this scan wrote. It is refused whole, before
    anything in it is listed, because a per-record check never sees a record reached only
    through a link above it.
    """
    if enclosure.read(directory) is None:
        return [], ("the findings path does not resolve inside the workspace the scan was "
                    "given; it was not followed"), True
    try:
        with os.scandir(directory) as entries:
            names = sorted(entry.name for entry in entries)
    except FileNotFoundError:
        return [], None, False
    except NotADirectoryError:
        return [], "the findings path is not a directory", True
    except OSError as exc:
        return [], f"the findings directory could not be listed ({exc.strerror or exc})", True
    return [name for name in names if name.endswith(".md")], None, True


def snapshot_findings(findings_dir: Path, enclosure: Enclosure) -> FindingsBaseline:
    """Record the finding records present before the scan, so the import can exclude them.

    Call this before the harness process starts. Each ``*.md`` file is hashed; one that cannot
    be read is recorded with a ``None`` digest, which no content hash equals, so the importer
    treats it as pre-existing rather than as something the scan produced. A directory that
    cannot be listed, or that does not resolve inside the workspace, yields ``established``
    false, and the importer then attributes nothing to the scan instead of guessing.
    """
    names, note, exists = _list_markdown(findings_dir, enclosure)
    if not exists:
        return FindingsBaseline({}, True, None)
    if note:
        return FindingsBaseline({}, False, note)
    digests: dict[str, str | None] = {}
    for name in names:
        if enclosure.read(findings_dir / name) is None:
            # A name that resolves out of the workspace is recorded with no digest, which no
            # content hash equals, so the importer treats it as pre-existing and credits the
            # scan with nothing found behind it.
            digests[name] = None
            continue
        try:
            digests[name] = _digest((findings_dir / name).read_bytes())
        except OSError:
            digests[name] = None
    return FindingsBaseline(digests, True, None)


def stage_record(source: Path, destination: Path, enclosure: Enclosure) -> str | None:
    """Copy one harness record into the staging directory; return a failure message, never raise.

    Every record this adapter stages goes through here: the finding records, whose failure is
    import loss, and the plan records, whose failure is a note. That is the rule in one place: a
    copy made to preserve evidence must not raise out of :meth:`LlmHarnessAdapter.scan`, where
    it would discard every claim the importer had already built and turn the whole scan into an
    adapter failure. The scanner owns both ends of this copy, so both ends can fail.

    Both ends are checked against the enclosure, and that is what makes the destination safe.
    The harness writes into the staging directory while it runs, so a link it left where these
    records go redirected the copy to any absolute path it chose and this wrote outside the
    bundle: ``mkdir(exist_ok=True)`` succeeds on a link to a directory and
    :func:`shutil.copyfile` follows one. Neither is reached now unless the destination resolves
    back inside the staging directory.

    Only a regular file is copied. Both callers classify the record before they get here, but
    the guard belongs to the copy as well: :func:`shutil.copyfile` follows a symbolic link and
    would preserve a host file the scan never wrote, and opening a named pipe for reading would
    block until something wrote to it, which nothing here ever does.
    """
    if enclosure.read(source) is None or source.is_symlink() or not source.is_file():
        return "the record is not a regular file inside the workspace; it was not followed or copied"
    if enclosure.write(destination) is None:
        return "the staging destination does not resolve inside this run's raw output"
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    except OSError as exc:
        return exc.strerror or str(exc)
    return None


def import_harness_findings(findings_dir: Path, *, harness: str, artifact_prefix: str,
                            stage_dir: Path, baseline: FindingsBaseline,
                            enclosure: Enclosure) -> HarnessImport:
    """Stage the ``findings/*.md`` records this scan produced and translate each into a claim.

    A finding record is a ``*.md`` file in *findings_dir*, which is what the harness's own
    reader treats as one. Each imported record is copied into *stage_dir* and registered as its
    own raw artifact under ``<artifact_prefix>/<file name>``, and the claim carries that same
    id, so every claim points at a hash-backed record the bundle holds rather than at a name
    nothing registers. A record that is not a regular file, cannot be read, carries no id,
    carries an unusable ``file_path``, or cannot be staged yields no claim and becomes one
    :class:`LostRecord`, which is both the loss and the note it reads as. The directory is listed
    explicitly, so a listing that fails is counted and noted rather than read as an empty
    directory, and a findings path that does not resolve inside *enclosure* is one of those
    failures: nothing behind it is read, because it is not the workspace this scan was handed.
    Every record read and every staged copy goes through the same enclosure, so a link anywhere
    above a record is refused exactly like a record that is a link. The full native allegation
    text is preserved; line ranges are never invented.

    Provenance. *baseline* is :func:`snapshot_findings` taken before the harness process
    started, and a record whose name and bytes are both in it is not imported: it was already
    in the exported input, so importing it would credit the scan with a finding the repository
    shipped. A name in the baseline whose bytes now differ is imported, because the scan
    rewrote it. When the baseline could not be established, nothing is attributed to the scan
    and every record is counted in ``lost``, since one of them may have been the scan's own.

    What this does not prove. It establishes only that the bytes were not in the workspace
    before the harness ran. It does not show that the harness's model produced them: anything
    else with write access to the workspace during the scan could have. It also cannot tell a
    record the harness rewrote byte-for-byte from one it left alone, so a planted record the
    harness happened to re-emit unchanged is still excluded.
    """
    claims: list[dict] = []
    artifacts: list[dict] = []
    notes: list[str] = []
    losses: list[LostRecord] = []

    def lose(name: str, finding_id: str | None, reason: str) -> None:
        """Record one lost record once: the loss and the note it reads as come from one call."""
        loss = LostRecord(name, finding_id, reason)
        losses.append(loss)
        notes.append(loss.note)

    names, listing_failure, exists = _list_markdown(findings_dir, enclosure)
    if not exists:
        return HarnessImport(claims, artifacts, ["no findings directory was written by the harness"], ())
    if listing_failure:
        # A directory this could not read is not an empty one: an unknown number of records
        # went unimported, so one loss is recorded as a floor and the note says so.
        lose(findings_dir.name, None,
             f"{listing_failure}; an unknown number of finding records was not imported")
        return HarnessImport(claims, artifacts, notes, tuple(losses))
    if not baseline.established:
        # Nothing separates a record the scan wrote from one the input shipped, so none is
        # attributed to the scan and all of them are counted as lost.
        note = baseline.note or "the findings directory could not be listed before the scan"
        reason = f"finding record provenance could not be established ({note}); not imported"
        for name in names or [findings_dir.name]:
            lose(name, None, reason)
        return HarnessImport(claims, artifacts, notes, tuple(losses))
    for name in names:
        path = findings_dir / name
        if enclosure.read(path) is None:
            lose(path.name, None, "finding record does not resolve inside the workspace; not imported")
            continue
        if path.is_symlink() or not path.is_file():
            lose(path.name, None, "finding record is not a regular file; not imported")
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            lose(path.name, None, f"finding record could not be read ({exc.strerror}); not imported")
            continue
        if name in baseline.digests and baseline.digests[name] in (None, _digest(data)):
            # These bytes were in the exported input before the harness ran, so the scan did
            # not produce this finding and cannot be credited with it. Not import loss: the
            # record is not a claim the scanner made.
            notes.append(f"{path.name}: this record was already in the exported input before the scan; "
                         "not imported as a finding of this scan")
            continue
        text = data.decode("utf-8", errors="replace")
        record, body = parse_frontmatter(text)
        finding_id = str(record.get("id") or "")
        if not finding_id:
            lose(path.name, None, "no id in frontmatter; not imported")
            continue
        file_path = str(record.get("file_path") or "").replace("\\", "/")
        if file_path.startswith("./"):
            file_path = file_path[2:]
        if not file_path or file_path.startswith("/") or ".." in file_path.split("/"):
            lose(path.name, finding_id,
                 f"unusable file_path {file_path!r}; not imported, see the raw finding record")
            continue
        failure = stage_record(path, stage_dir / path.name, enclosure)
        if failure:
            # The claim would name an artifact the bundle does not hold, so the record is
            # counted as lost rather than imported against a copy that was never made.
            lose(path.name, finding_id, f"finding record could not be staged ({failure}); not imported")
            continue
        vulnerability_class = str(record.get("vulnerability_class") or "")
        title = str(record.get("title") or path.stem)
        reasoning = body.split("## Reasoning", 1)[1].strip() if "## Reasoning" in body else body.strip()
        claim: dict[str, Any] = {
            "claim_id": finding_id,
            "allegation": title,
            "kind": kind_for_harness_class(vulnerability_class),
            "primary_location": {"path": file_path},
            "native_id": finding_id,
            "native_rule_id": f"{harness}:{vulnerability_class or 'unknown'}",
            "raw_artifact_id": f"{artifact_prefix}/{path.name}",
        }
        if reasoning and reasoning != "N/A":
            claim["evidence_text"] = reasoning
        severity = record.get("severity")
        if isinstance(severity, str) and severity:
            claim["native_severity"] = severity
        claims.append(claim)
        artifacts.append({"id": claim["raw_artifact_id"], "path": stage_dir / path.name})
    return HarnessImport(claims, artifacts, notes, tuple(losses))


class SelfReport(NamedTuple):
    """What the harness says its own run wrote, read off the driver summary.

    ``ids`` are the distinct finding ids it named in ``newFindings`` and ``updatedFindings``,
    each of which the engine writes as one ``findings/*.md`` record. ``unnamed`` counts reported
    entries carrying no usable id, which can still be compared by number. ``unreadable`` counts
    the parts of the self-report this could not read at all, and ``note`` names them.

    ``unreadable`` is separate from ``total`` on purpose. A part this cannot read says nothing
    about how many records the harness wrote, so it cannot be added to a count; what it is, is
    evidence the run offered and the importer could not use, and :func:`reconcile_import` counts
    each one as a lost record rather than as nothing at all.
    """

    ids: tuple[str, ...]
    unnamed: int
    unreadable: int
    note: str | None

    @property
    def total(self) -> int:
        """How many finding records the harness says this run wrote."""
        return len(self.ids) + self.unnamed


def read_self_report(summary: object) -> SelfReport:
    """Read the harness's own count of the finding records it wrote.

    A summary that names no findings yields an empty report, which asserts nothing: this is a
    cross-check against a scanner's own words, not a guarantee. ``None``, an absent key, and a
    summary that is not a mapping at all are all that case: no self-report was offered, and the
    run that produced no summary is already reported as a failed one.

    A self-report that was offered and cannot be parsed is the opposite case and is counted.
    ``newFindings`` or ``updatedFindings`` in a shape this cannot read used to yield a note and
    no number, which reconciled to a shortfall of zero: a run whose entire self-report was a
    shape the reader did not expect reached scoring as a clean success. An unreadable part is
    missing evidence, not evidence that nothing was written, so each one is counted in
    ``unreadable`` for the caller to treat as loss.
    """
    if not isinstance(summary, dict):
        if summary is None:
            return SelfReport((), 0, 0, None)
        return SelfReport((), 0, 1,
                          f"the harness summary is a {type(summary).__name__}, not a mapping, so "
                          "the findings it reports could not be read")
    ids: list[str] = []
    unnamed = 0
    unreadable: list[str] = []
    for key in ("newFindings", "updatedFindings"):
        reported = summary.get(key)
        if reported is None:
            continue
        if isinstance(reported, int) and not isinstance(reported, bool):
            # Some summaries carry a count where others carry the records themselves.
            unnamed += max(reported, 0)
            continue
        if not isinstance(reported, list):
            unreadable.append(f"summary.{key} is a {type(reported).__name__}, not a list of findings")
            continue
        for entry in reported:
            identifier = entry.get("id") if isinstance(entry, dict) else None
            if isinstance(identifier, str) and identifier:
                ids.append(identifier)
            else:
                unnamed += 1
    return SelfReport(tuple(dict.fromkeys(ids)), unnamed, len(unreadable), "; ".join(unreadable) or None)


class ImportAccounting(NamedTuple):
    """The one count of finding records this scan produced that did not arrive as claims.

    Everything the outcome does about import loss reads this: the status, ``bundles_resolved``,
    the error message, and the note. ``lost`` above zero means the scan can earn neither
    completeness nor quiet credit.
    """

    lost: int
    message: str | None
    notes: tuple[str, ...]


def reconcile_import(imported: HarnessImport, report: SelfReport) -> ImportAccounting:
    """Reconcile what the harness says it wrote against what the importer could read.

    The rule: a scanner self-report that disagrees with what we could read is evidence of loss,
    not something to ignore. Counting only the records the importer could see left the worst
    case invisible, because a scan whose findings all vanished before the import produced no
    record to count and reached scoring as a clean success.

    The arithmetic, and why it cannot count one record twice. Every record the importer read and
    rejected is one loss, with its own reason. Against that, each finding the harness named is
    accounted for when a claim carries its id, and each finding it reported without an id is
    accounted for by any delivered claim the report did not name. What is left over is the
    shortfall: findings the harness says it wrote that neither arrived nor are already counted
    as a rejected record. A rejected record is assumed to be one of the reported findings, so a
    record that was both reported and rejected is counted once, as a rejection with a reason.

    A part of the self-report that could not be read at all is counted too, one lost record
    each, which is a floor rather than a number: it says at least one record may be behind it,
    not how many. It used to produce a shortfall of zero, so a run whose whole self-report was
    unreadable read as a scan that reported nothing and lost nothing.

    The limits. This trusts the self-report only as a lower bound on what was written: a harness
    that reports nothing produces no shortfall, and one that under-reports hides the same way.
    The comparison is by id, so a record the harness rewrote byte for byte is excluded by the
    import baseline and then shows up here as a shortfall, which is the conservative direction:
    it was reported, and no claim for it arrived.
    """
    delivered = {str(claim.get("claim_id") or "") for claim in imported.claims}
    named_lost = {loss.finding_id for loss in imported.losses if loss.finding_id}
    matched = sum(1 for identifier in report.ids if identifier in delivered)
    absorbed = min(report.unnamed, max(len(delivered) - matched, 0))
    shortfall = max(report.total - matched - absorbed - imported.lost, 0)
    reasons = [loss.note for loss in imported.losses]
    notes = [report.note] if report.note else []
    if shortfall:
        unattributed = [identifier for identifier in report.ids
                        if identifier not in delivered and identifier not in named_lost]
        detail = ", ".join(unattributed[:10]) if unattributed else "none of them carried an id"
        reasons.append(f"the harness reported writing {report.total} finding record(s) and "
                       f"{shortfall} of them did not arrive as claims ({detail})")
    if report.unreadable:
        reasons.append(f"the harness self-report could not be read ({report.note}), so the "
                       f"findings it names could not be compared with the claims that arrived; "
                       f"counted as {report.unreadable} lost record(s), which is a floor")
    lost = imported.lost + shortfall + report.unreadable
    message = None
    if lost:
        message = (f"{lost} harness finding record(s) could not be imported: "
                   + "; ".join(reasons))[:2000]
        notes.append(f"Import loss: {lost} finding record(s) the harness wrote could not be "
                     "imported, so this scan can earn neither completeness nor quiet credit.")
    return ImportAccounting(lost, message, tuple(notes))


def capture_status(trace_mode: str, routes: list[str], *, has_summary: bool,
                   capture_state: dict | None = None) -> dict[str, str]:
    """Per-category capture availability for one harness run.

    Tool dispatch is ``unavailable`` on every real route: it happens inside the model CLI
    this adapter spawns, so no tool event is observed and the absence of one establishes
    nothing about whether a tool ran. Only the mock runner, which spawns no process at
    all, makes the concept inapplicable. Model events are ``partial`` at best because the
    harness retries inside its own runner, below the observed boundary.

    ``finding_submitted`` is read off *capture_state*, the observer state the driver reported,
    rather than off the bare fact that a trace was written. It used to be ``complete`` whenever
    the run was traced and produced a summary, which contradicted the ``capture_gap`` and
    ``dropped_events`` the same execution record carries. ``complete`` now requires a state that
    explicitly reports no gap and no dropped event; a state reporting either, and a run that
    reported no state at all, are ``partial``, because nothing there rules a gap out.
    """
    request_capture = {"off": "unavailable", "metadata": "partial", "content": "partial"}[trace_mode]
    traced = trace_mode != "off"
    gapless = (isinstance(capture_state, dict) and capture_state.get("capture_gap") is False
               and capture_state.get("dropped_events") == 0)
    submitted = ("complete" if gapless else "partial") if (traced and has_summary) else "unavailable"
    return {
        "model_requests": request_capture,
        "model_responses": request_capture,
        "tool_calls": "not_applicable" if routes == ["mock"] else "unavailable",
        "context_selection": "partial" if traced else "unavailable",
        "finding_submitted": submitted,
        "finding_candidate": "unavailable",
        "finding_validation": "unavailable",
        "finding_filtered": "unavailable",
    }


class LlmHarnessAdapter(Adapter):
    name = "llm-harness"
    adapter_version = "2.1.0"
    requires_git = True
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})
    # What the driver process inherits from the operator environment, on top of the base set in
    # :mod:`scaneval.adapters.base`, and recorded as ``environment.passthrough`` in every
    # execution record. ``NODE_OPTIONS`` is deliberately not here: node executes what it names,
    # so ``--require`` or ``--import`` in the operator's environment would run code inside the
    # driver, changing what the run did while the record showed only the variable's name and
    # never its value. The provider keys are here because the harness needs them to call a
    # model; they are secrets, so they are passed and never recorded.
    env_passthrough = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "XDG_CONFIG_HOME")
    # Derived from the one list the export strips, so a repository shipping a top-level
    # harness state directory cannot be stripped by one of them and treated as ordinary
    # content by the other.
    state_dirs = tuple(sorted(HARNESS_STATE_DIRS))

    def _preset(self, spec: SystemSpec) -> tuple[str, dict[str, Any], Path]:
        """The harness preset and its root, resolved to an absolute path.

        The root is used both as the prefix of the executable path and as the working
        directory of the process that runs it, so a relative one would be applied twice and
        produce a doubled path such as ``harness/harness/node_modules/.bin/tsx``. Resolving it
        here makes preparation and the scan agree on one absolute path, which is the value the
        preparation record reports.
        """
        harness = str(spec.config.get("harness") or "")
        if harness not in HARNESS_PRESETS:
            raise AdapterError(f"config.harness must be one of {sorted(HARNESS_PRESETS)}")
        root = Path(str(spec.config.get("root") or "")).expanduser().resolve()
        if not root.is_dir():
            raise AdapterError(f"harness root does not exist: {root}")
        return harness, HARNESS_PRESETS[harness], root

    def prepare(self, spec: SystemSpec, cache_root: Path) -> dict[str, Any]:
        harness, preset, root = self._preset(spec)
        tsx = root / "node_modules" / ".bin" / "tsx"
        missing = [str(p) for p in (root / preset["engine_entry"], root / preset["runner_entry"], tsx) if not p.exists()]
        observer_sdk = Path(str(spec.config.get("observer_sdk") or Path(__file__).resolve().parents[3] / "sdk" / "typescript" / "dist" / "index.js"))
        if not observer_sdk.exists():
            missing.append(f"{observer_sdk} (run npm ci && npm run build in sdk/typescript)")
        if not DRIVER.exists():
            missing.append(str(DRIVER))
        if missing:
            raise AdapterError("harness preparation failed; missing: " + "; ".join(missing))
        if spec.config.get("runner", "default") not in ("default", "mock"):
            raise AdapterError("config.runner must be 'default' or 'mock'")
        if not spec.config.get("model"):
            raise AdapterError("config.model (harness model route) is required")
        head, dirty = None, None
        try:
            # Hermetic, like every other git call this package makes: an inherited GIT_DIR would
            # otherwise make this record an unrelated repository's HEAD as the harness version.
            head_argv, git_environment = git_command(["rev-parse", "HEAD"])
            status_argv, _ = git_command(["status", "--porcelain"])
            head = subprocess.run(head_argv, cwd=root, env=git_environment, capture_output=True,
                                  text=True, timeout=30).stdout.strip() or None
            dirty = bool(subprocess.run(status_argv, cwd=root, env=git_environment, capture_output=True,
                                        text=True, timeout=30).stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            pass
        package_version = None
        try:
            package_version = json.loads((root / "package.json").read_text(encoding="utf-8")).get("version")
        except (OSError, ValueError):
            pass
        return {
            "harness": {"name": harness, "root": str(root), "configured_root": str(spec.config.get("root") or ""),
                        "package_version": package_version, "git_head": head,
                        "working_tree_modified": dirty, "state_dir": preset["state_dir"]},
            "observer_sdk": str(observer_sdk),
            "runner": spec.config.get("runner", "default"),
            "model": spec.config["model"],
        }

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        harness, preset, root = self._preset(spec)
        if request["input"]["mode"] != "full":
            raise AdapterError("native PR mode is not wired in this build; only full scans are supported")
        mode = str(spec.config.get("mode", "bootstrap"))
        if mode != "bootstrap":
            raise AdapterError("only bootstrap (full baseline) mode is supported for full-scan requests")
        trace_path = (trace_dir / "events.jsonl") if trace_dir is not None else None
        config = {
            "harness_root": str(root), "engine_entry": preset["engine_entry"], "runner_entry": preset["runner_entry"],
            "mock_entry": preset["mock_entry"], "observer_sdk": preparation["observer_sdk"],
            "repo_path": str(source_dir), "mode": mode, "model": str(spec.config["model"]),
            **({"llm_max_files": int(spec.config["llm_max_files"])} if "llm_max_files" in spec.config else {}),
            **({"llm_timeout_ms": int(spec.config["llm_timeout_ms"])} if "llm_timeout_ms" in spec.config else {}),
            **({"qmd_profile": spec.config["qmd_profile"]} if spec.config.get("qmd_profile") else {}),
            **({"specialist_ids": list(spec.config["specialist_ids"])} if spec.config.get("specialist_ids") else {}),
            "runner": str(spec.config.get("runner", "default")), "trace_mode": trace_mode,
            **({"trace_path": str(trace_path)} if trace_path else {}),
            "run_id": request["run_id"], "producer_id": f"{harness}-driver",
            "output_path": str(raw_dir / "driver-output.json"), "progress_path": str(raw_dir / "driver-progress.log"),
            "flush_timeout_ms": int(spec.config.get("flush_timeout_ms", 30000)),
        }
        state_dir = source_dir / preset["state_dir"]
        # The one enclosure every read and every copy destination below goes through: the
        # harness may read from and write to both of these directories while it runs, so each
        # path is resolved whole and proved to be inside the one it belongs to.
        enclosure = Enclosure(Path(source_dir), Path(raw_dir))
        # Taken before the harness process starts: whatever is in the findings directory now
        # came with the exported input, not from this scan.
        findings_baseline = snapshot_findings(state_dir / "findings", enclosure)
        config_path = raw_dir / "driver-config.json"
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (raw_dir / "driver-progress.log").write_text("", encoding="utf-8")
        argv = [str(root / "node_modules" / ".bin" / "tsx"), str(DRIVER), "--config", str(config_path)]
        result = run_command(argv, cwd=root, timeout_seconds=timeout_seconds, env=build_env(self.env_passthrough),
                             stdout_path=raw_dir / "driver-stdout.txt", stderr_path=raw_dir / "driver-stderr.txt")
        artifacts = [{"id": "driver-output", "path": raw_dir / "driver-output.json"},
                     {"id": "driver-stdout", "path": raw_dir / "driver-stdout.txt"},
                     {"id": "driver-stderr", "path": raw_dir / "driver-stderr.txt"},
                     {"id": "driver-progress", "path": raw_dir / "driver-progress.log"},
                     {"id": "driver-config", "path": config_path}]
        # The finding records live in the workspace too, so each imported one is copied into the
        # staging directory and registered under the id its claim carries. Only records this
        # scan produced are imported; the baseline above says which those are.
        imported = import_harness_findings(state_dir / "findings", harness=harness,
                                           artifact_prefix="harness-findings",
                                           stage_dir=raw_dir / "harness-findings",
                                           baseline=findings_baseline, enclosure=enclosure)
        claims = imported.claims
        artifacts.extend(imported.artifacts)
        # The harness writes its plan and scan log inside the workspace, which is removed once
        # the scan returns. Copy the records worth hashing into the staging directory so they
        # survive as raw artifacts; the whole state directory is preserved separately.
        plans = raw_dir / "harness-plan"
        plan_notes: list[str] = []
        for name in ("bootstrap-plan.md", "pr-plan.md", "batch-plan.md", "hypothesis-scanned-files.md",
                     "specialists.json", "specialists.md", "scan-log.md", "threat-model.md", "codebase-profile.json"):
            written = state_dir / name
            if enclosure.read(written) is None:
                # Reached through a link that leaves the workspace, so it is not a record this
                # scan wrote and nothing behind it is read or copied.
                plan_notes.append(f"{name}: harness record does not resolve inside the workspace; "
                                  "it was not staged as an artifact")
            elif written.is_symlink() or (written.exists() and not written.is_file()):
                # Not staged and not hashed, and said so rather than dropped in silence. These
                # are plan records, not claims, so this does not degrade the scan status.
                plan_notes.append(f"{name}: harness record is not a regular file; it was not staged as an artifact")
            elif written.is_file():
                copied = plans / name
                failure = stage_record(written, copied, enclosure)
                if failure:
                    # Contained, not raised: a plan record is evidence, and a copy that fails
                    # must not discard the claims the importer already built. The scanner owns
                    # the record and the directory it goes to, so it can break either.
                    plan_notes.append(f"{name}: harness record could not be staged ({failure}); "
                                      "it was not staged as an artifact")
                else:
                    artifacts.append({"id": f"harness-{name}", "path": copied})
        output: dict[str, Any] = {}
        driver_output = raw_dir / "driver-output.json"
        if enclosure.write(driver_output) is None:
            # The harness writes this file, so it can also leave a link there. Nothing outside
            # the staging directory is parsed as this run's own output.
            notes_prefix = ["the driver output path does not resolve inside this run's raw "
                            "output; it was not read"]
        else:
            notes_prefix = []
            try:
                output = json.loads(driver_output.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                output = {}
        # Only a mapping is a summary this can read. A truthy value of any other shape is not
        # one, and treating it as one crashed the scan on the first ``.get`` below; it is a
        # self-report that could not be read, which :func:`read_self_report` counts as loss.
        summary = output.get("summary") if isinstance(output, dict) else None
        usable_summary = summary if isinstance(summary, dict) and summary else None
        trace = output.get("trace") if isinstance(output, dict) else None
        capture_state = (trace or {}).get("state") if isinstance(trace, dict) else None
        routes = sorted({str(route) for route in (output.get("observed_routes") or [])}) if isinstance(output, dict) else []
        mock_only = routes == ["mock"]
        capture = capture_status(trace_mode, routes, has_summary=bool(usable_summary), capture_state=capture_state)
        # One accounting of import loss, reconciling the records the importer could read against
        # the findings the harness says it wrote. Every branch below reads this and nothing else:
        # the status, the resolved-bundle flag, the error message, and the notes.
        accounting = reconcile_import(imported, read_self_report(summary))
        loss_message = accounting.message
        notes = notes_prefix + list(imported.notes) + plan_notes + list(accounting.notes)
        notes.append("Model requests are captured per logical harness call; retries inside the harness runner and token usage are not observable at this boundary.")
        for route in routes:
            policy = TOOL_POLICY.get(route)
            if policy:
                notes.append(f"Declared tool policy on the {route} route: {policy} This is the argv the harness built, not an observation of what the CLI did.")
        if not mock_only:
            notes.append("Tool dispatch was not observed: it happens inside the model CLI subprocess. Absence of tool events is not evidence that no tool ran.")
        notes.append("Harness findings are file-level; no line ranges were inferred.")
        model_identity = {"requested": str(spec.config["model"]), "resolved": None, "verification": "unverified",
                          "notes": ["The pi/claude CLI path does not report the served model; only the requested route is known."]}
        if spec.config.get("runner") == "mock":
            model_identity = {"requested": str(spec.config["model"]), "resolved": "deterministic-mock", "verification": "not_applicable",
                              "notes": ["Deterministic mock runner; diagnostic only, no model was called."]}
            notes.append("DIAGNOSTIC: deterministic mock runner, no model calls; results are not scanner evidence.")
        usage: dict[str, Any] = {"cost_usd": None}
        # Import loss leaves the claim set incomplete, so the bundles it delivers are not
        # resolved: the scoring contract then refuses both completed-control and quiet credit.
        base = dict(command=argv, claims=claims, artifacts=artifacts, capture=capture, notes=notes,
                    model_identity=model_identity, usage=usage, trace_path=trace_path, capture_state=capture_state,
                    bundles_resolved=accounting.lost == 0,
                    tool_versions={"harness": f"{harness}@{preparation['harness'].get('git_head') or 'unknown'}",
                                   "harness_package": str(preparation["harness"].get("package_version")),
                                   "driver": str(output.get("driver_version", "unknown"))})

        def stderr_tail() -> str:
            """The tail of this run's own driver stderr, empty when that path left the staging area.

            The file is created here before the driver starts, but the driver can replace it with
            a link, and this text goes into the recorded error message: without the check a
            scanner could choose which host file the bundle quotes.
            """
            stderr_path = raw_dir / "driver-stderr.txt"
            return tail_text(stderr_path) if enclosure.write(stderr_path) is not None else ""

        def with_loss(message: str) -> str:
            """The branch's own message, with the import loss named beside it.

            Every branch that reports a message goes through here, so what was lost travels with
            the outcome whichever way the run ended rather than only on the branches that
            remembered to ask.
            """
            return f"{message}; {loss_message}"[:2000] if loss_message else message

        if result.timed_out:
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True,
                                 error={"code": "timeout",
                                        "message": with_loss(f"harness exceeded {timeout_seconds}s")}, **base)
        if not usable_summary:
            failure = (output.get("error") or {}) if isinstance(output, dict) else {}
            message = failure.get("message") or stderr_tail()
            return NativeOutcome(status="error", exit_code=result.exit_code,
                                 error={"code": f"driver_exit_{result.exit_code}",
                                        "message": with_loss(str(message)[:2000])}, **base)
        budget = usable_summary.get("budget") or {}
        if isinstance(budget, dict) and "estimatedSpentUsd" in budget:
            notes.append(f"Harness cost estimate (not measured): {budget.get('estimatedSpentUsd')} USD "
                         f"for {budget.get('actualLlmFilesScanned')} LLM files; measured cost unavailable.")
        scan_stats = usable_summary.get("bootstrapScan") or {}
        llm_calls = int(scan_stats.get("llmCalls") or 0)
        failed_calls = int(scan_stats.get("failedCalls") or 0)
        notes.append(f"Harness self-report: llm_calls={llm_calls} failed_calls={failed_calls} "
                     f"coverage={scan_stats.get('hypothesisCoverage')} status={scan_stats.get('status')} "
                     f"runtime_profile={usable_summary.get('runtimeProfile')} degraded={usable_summary.get('degraded')}")
        if result.exit_code not in (0, 2):
            return NativeOutcome(status="error", exit_code=result.exit_code,
                                 error={"code": f"driver_exit_{result.exit_code}",
                                        "message": with_loss(stderr_tail())}, **base)
        if llm_calls and failed_calls >= llm_calls:
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "llm_path_failed", "message": with_loss("every harness model call failed; findings come from deterministic passes only")}, **base)
        if usable_summary.get("degradation") or scan_stats.get("status") == "inconclusive":
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "harness_inconclusive",
                                        "message": with_loss(f"degradation={usable_summary.get('degradation')} scan_status={scan_stats.get('status')} reasons={scan_stats.get('reasons')}")}, **base)
        if loss_message:
            # A scan whose findings did not all survive the import is not a clean run: it is
            # partial, and the count and the reason travel with it as an explicit error.
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "import_loss", "message": loss_message}, **base)
        return NativeOutcome(status="success", exit_code=result.exit_code, **base)
