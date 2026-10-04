"""Run one system once on one prepared input and write a reproducible invocation bundle.

Bundle layout (all evaluator-side; the scanner only ever sees a private workspace copy):

    <out>/<invocation_id>/
      request.json      sanitized scan request, no labels
      result.json       normalized claims with explicit status
      execution.json    exit status, timing, versions, policy, capture, provenance
      raw/              stdout, stderr, native artifacts, captured harness state
      trace/            observer events when the adapter captured any

What this module defends against, and what it does not, is stated in ``docs/THREAT_MODEL.md``.
In short: the scanner is untrusted by design, and the checks here, path containment, the input
hash, source-modification detection and state capture, defend against a careless or buggy
scanner and against accidental escape. They do not survive a hostile scanner running
concurrently in a directory it controls, which can undo any of them between the moment they are
made and the moment they are read. Read that document before treating any of this as isolation.

``raw/`` and ``trace/`` are staged inside the private workspace while the scanner runs and
are moved into the bundle once it returns or raises, so no path handed to an adapter resolves
inside the run directory and declared artifact paths are re-rooted before they are hashed. One
rule decides what a staged tree may contain, and :func:`_move_into_bundle` is the one place it
is enforced: no path in a bundle may name a file outside it. A hard link is copied, a symbolic
link is cut, and every directory that remains is a real one, so nothing in the bundle is a
second name for a live host file and nothing in it leads out. An entry the sweep cannot
inspect or clear is a recorded failure of the invocation rather than a skipped entry, and the
sweep completes before it reports, so the record names every one of them.

Two rules hold for every path this module touches, and each of them lives in one function.
:func:`list_directory` is the one listing: an enumeration that cannot complete is a failed
observation, never an empty one, so every walk here raises rather than reporting a directory it
could not read as empty. :func:`read_regular_file` is the one read of a path a scanner could
have written: it proves the file is a regular file in the same open that reads it, so a named
pipe left where output belongs is refused instead of blocking the invocation forever.

An outcome that breaks the adapter contract, an execution record the contract refuses, a trace
file that is not UTF-8 text, and anything raised while capturing harness state, moving the
staged directories, collecting artifacts, or serializing what the adapter reported are all
recorded failures: the bundle then holds an error result and an execution record carrying the
message, never a successful result beside a missing execution record. The staged raw output is
preserved either way.

A source the scanner modified is a changed execution condition rather than a scanner failure,
and it is recorded as one: the result keeps the claims but goes partial with unresolved bundles,
so it cannot stand as a clean observation of the frozen input it binds to. :func:`_input_tree`
is the single definition of what that source is, used both for the hash the result binds to and
for the before/after comparison, so neither can cover a path the other ignores. A source tree
that cannot be walked is a failed observation rather than an empty one, so a scanner cannot hide
what it wrote by making the directory it wrote in unreadable. A top-level ``.git`` is left out
of that tree only when this run created it, so a scanner that makes one has it watched like any
other directory it writes.

No tree this module copies is ever copied through a symbolic link: :func:`_copy_tree_unresolved`
is the one copy, for the exported input on the way in and for the scanner's state directory on
the way out, and it preserves a link as a link or refuses one, so a link the scanner planted
cannot pull a host file into the bundle. A link it preserved is cut when the staged tree enters
the bundle, by the one rule stated above; what the scanner left is named in the record instead.

Every path this module reads or writes after the scanner returns is a path the scanner could
have replaced, and any component of it can be a link, not only the last one. So each of them,
the exported source, the destination of the harness-state capture, a declared artifact, and a
declared trace file, is resolved whole against a :class:`~scaneval.materialize.Containment`
before it is touched. A path that resolves out is refused with a note or a recorded violation,
never followed. Every one of those directories has its real path captured before the scanner
starts, because a base resolved afterwards is a base the scanner may have moved, and a check
against a moved base passes whatever the scanner points it at.

Nothing the scanner names can make this bundle unrecordable. A string that UTF-8 cannot encode,
which is what a file name the filesystem accepted and the decoder had to escape becomes, used to
raise while the documents were serialized, and it raised again on the rebuilt record, so the
invocation ended with ``raw/`` and ``request.json`` on disk and neither ``result.json`` nor
``execution.json``. :func:`_recordable` is the one place both documents pass through on their way
to being written, and it renders such text rather than failing on it.

How completely this run was observed is one fact, derived in one place. :func:`_capture_record`
reads the observer's reported state and the bundle's own trace record together and returns both
the ``capture`` mapping the record carries and how the observation broke, so the two cannot
disagree: no category can claim it was observed at all, to any extent, in a bundle that holds no
counted trace, and a reported gap cannot sit beside a clean success. A run whose observation
broke is recorded as ``partial`` with error code ``trace_capture_gap`` when nothing else already
failed, and keeps the adapter's own ``bundles_resolved``. Losing trace events is not losing a
claim, so nothing about the claim set is withdrawn; what is withdrawn is the result's standing
as a clean complete observation.

An adapter may report ``omitted_paths``, the paths of its input it observed the scanner did not
examine. They are written into the result sorted and each path once, and the result is then a 2.1
result, because the version moves only when a 2.1 field needs it. They are the adapter's claim:
this module checks only their shape, the contract checks that each is a relative POSIX path, and
nothing here can see whether a path was really examined. It may also report ``examined_nothing``,
that it can show no part of the input to have been examined, and a ``bool`` is written into the
result as it is, in a 2.1 result for the same reason; it too is the adapter's claim and is checked
for its type only. The error result recorded in place of a result the contract refused carries
neither, like everything else the adapter supplied.

Directory separation documents the boundary; it does not enforce it. Network and
filesystem policy are declared here and must be enforced outside this process.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import os
from pathlib import Path, PurePath
import shutil
import stat
import tempfile
import time
from typing import Any, Callable, Iterator
import uuid

from . import __version__
from .adapters.base import Adapter, NativeOutcome, SystemSpec
from .contracts import ContractError, canonical_json, canonical_sha256, validate_document
from .kinds import mapping_version
from .materialize import (
    Containment,
    MaterializationError,
    prepare_pr_history,
    prepare_synthetic_history,
    sha256_file,
    tree_hash,
    walk_regular_files,
)


NETWORK_POLICIES = ("none", "model_provider_only", "unrestricted")
_USAGE_KEYS = ("wall_seconds", "setup_seconds", "cost_usd", "input_tokens", "output_tokens")


class ExecutionError(RuntimeError):
    """The invocation could not be set up or recorded."""


class _BundleRefused(Exception):
    """The bundle documents cannot be written as built; the message names the refusal.

    Raised only inside :func:`run_invocation`, which then discards the adapter's outcome and
    records the refusal itself. It never leaves this module: a refusal that survives the rebuild
    becomes an :class:`ExecutionError` and no document is written.
    """


@dataclass(frozen=True)
class PreparedInput:
    """One prepared input as a scanner receives it, and the identities the evaluator binds to it.

    ``tree_hash`` is the tree the workspace holds and the pre-scan check compares against: the
    exported snapshot, the transformed tree of a blinded input, or the head of a PR input.
    ``input_hash`` is what the result, the plan, and the decisions bind to; it defaults to
    ``tree_hash`` and differs only for a PR input, whose identity is its base, its head, and the
    diff between them. ``source_tree_hash`` is the original export the labels refer to, which
    differs from ``tree_hash`` for a blinded input. ``blinding`` and ``pr`` carry the evaluator-side
    identities recorded in a 2.1 execution record; neither is ever handed to a scanner.

    ``base_source_dir`` is the base tree of a PR input, the one the first commit of its synthetic
    history is built from; it is read, never written, and never copied into a workspace. ``pr`` then
    carries the neutral ``base_commit`` and ``head_commit`` the request names, which the history
    built in each workspace must reproduce exactly.
    """

    input_id: str
    source_dir: Path
    tree_hash: str
    languages: tuple[str, ...]
    provenance: dict
    profile: str = "standard"
    mode: str = "full"
    input_hash: str | None = None
    source_tree_hash: str | None = None
    blinding: dict | None = None
    pr: dict | None = None
    base_source_dir: Path | None = None

    @property
    def binding_hash(self) -> str:
        """The identity the result and every evaluator record of this input bind to."""
        return self.input_hash or self.tree_hash

    @property
    def needs_2_1(self) -> bool:
        """Whether a record of this input needs a 2.1 field: a PR or blinded input does."""
        return self.mode != "full" or self.profile != "standard" or self.binding_hash != self.tree_hash


# The isolation record of every invocation run without an OS-level backend. It is written into 2.1
# execution records only; a 2.0 record written for a standard local run says the same thing through
# its network note, and nothing about it changes.
LOCAL_ISOLATION = {
    "backend": "local",
    "enforced": False,
    "note": ("The scanner ran as the operator with no OS-level boundary. Workspace separation, path "
             "containment, and the before/after source hash are checks, not enforcement; see "
             "docs/THREAT_MODEL.md."),
}


def invocation_id(input_id: str, system_id: str, repetition: int) -> str:
    return f"{input_id}__{system_id}__r{repetition}"


def _passthrough(adapter: Adapter, isolation: dict) -> list[str]:
    """The environment variable names this record says reached the scanner, sorted.

    Without a backend the scanner process gets the operator's variables, and the record names the
    runner's own offer: its base names and the adapter's, whether or not the operator's environment
    holds each of them. Under a backend the scanner's environment is the one the backend built and
    the operator's is not what it receives, so the names are the backend's own record of it
    (``isolation.settings.environment``): what it set in the container, and the declared
    credentials it passed by name. A backend that ran nothing set nothing. One that records no
    environment leaves the runner's offer, which is then all the record can say.
    """
    settings = isolation.get("settings")
    environment = settings.get("environment") if isinstance(settings, dict) else None
    if not isinstance(environment, dict):
        return sorted(set(("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "USER", "SHELL")
                          + tuple(adapter.env_passthrough)))
    names = {name for name in environment.get("set") or () if isinstance(name, str)}
    names |= {item["env"] for item in environment.get("credentials") or ()
              if isinstance(item, dict) and item.get("passed") is True and isinstance(item.get("env"), str)}
    return sorted(names)


def _now(clock: Callable[[], datetime] | None) -> str:
    moment = (clock or (lambda: datetime.now(timezone.utc)))()
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _canonical_bytes(value: dict) -> bytes:
    """The exact UTF-8 bytes of one canonical JSON document.

    A lone UTF-16 surrogate survives :func:`canonical_json` and every contract check but cannot
    be encoded, so the encoding happens here, before any file exists, rather than inside an open
    file where it would leave an empty record behind.
    """
    text = canonical_json(value) + "\n"
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(f"value is not canonical UTF-8 JSON: {exc}") from exc


def _write_new_documents(documents: list[tuple[Path, bytes]]) -> None:
    """Write several documents so a reader sees either all of them or none.

    Every payload goes to a temporary file in its destination directory first, and nothing is
    renamed into place until all of them are written, so a reader never sees a partially written
    document and a failure part way leaves no document at all. A rename that fails after an
    earlier one succeeded is undone by removing what was already renamed, so an I/O failure
    between ``result.json`` and ``execution.json`` cannot leave a successful result beside a
    missing execution record.

    Two limits. The renames are separate operations, so a process killed between them can still
    leave the first document behind; what this removes is every failure this module can observe.
    And the existence check and the rename are two operations as well, so this refuses a record
    that is already there; it does not arbitrate between concurrent writers for one path.
    """
    for path, _payload in documents:
        if os.path.lexists(path):
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(path))
    staged: list[tuple[Path, Path]] = []
    renamed: list[Path] = []
    try:
        for path, payload in documents:
            temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.part")
            # Created the way a plain create would be, so the umask still decides the mode, and
            # with O_EXCL so this never writes through a name something else put there first.
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
            staged.append((temporary, path))
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
        for temporary, path in staged:
            os.replace(temporary, path)
            renamed.append(path)
    except BaseException:
        for path in renamed:
            path.unlink(missing_ok=True)
        raise
    finally:
        for temporary, _path in staged:
            temporary.unlink(missing_ok=True)


def _write_new_bytes(path: Path, payload: bytes) -> None:
    """Write one document, refusing to overwrite an existing path. See :func:`_write_new_documents`."""
    _write_new_documents([(path, payload)])


def _write_new(path: Path, value: dict) -> None:
    """Write one canonical JSON document, refusing to overwrite an existing path.

    The document is serialized and encoded before the file is created, so a value canonical JSON
    or UTF-8 cannot represent leaves no empty file behind for a reader to mistake for a record.
    """
    _write_new_bytes(path, _canonical_bytes(value))


def build_request(run_id: str, prepared: PreparedInput, spec: SystemSpec, *, timeout_seconds: float,
                  trace_mode: str, pr: dict | None = None) -> dict:
    request = {
        "schema_version": "2.0",
        "run_id": run_id,
        "input": {"tree_hash": prepared.tree_hash, "root": ".", "languages": list(prepared.languages),
                  "mode": prepared.mode, "profile": prepared.profile, **({"pr": pr} if pr else {})},
        "system": {"id": spec.system_id, **({"model_id": spec.model_id} if spec.model_id else {}),
                   **({"model_revision": spec.model_revision} if spec.model_revision else {})},
        "limits": {"timeout_seconds": timeout_seconds},
        "trace_mode": trace_mode,
    }
    return validate_document("scan-request", request)


def _pr_history(source: Path, prepared: PreparedInput) -> dict:
    """Build the two-commit history of a PR input in its workspace, and prove it is the recorded one.

    The head is the workspace's own copy of the export and the base is read from the input's base
    tree, so the history a scanner finds is exactly the one preparation computed in a scratch copy.
    Equal trees give equal commit ids, so a difference is not noise: the workspace was not built
    from the trees the input recorded, or git did not read them the way it did then, and the
    request names commits that are not the ones the workspace holds. That is refused rather than
    scanned.
    """
    try:
        history = prepare_pr_history(source, Path(prepared.base_source_dir))
    except MaterializationError as exc:
        raise ExecutionError(f"the synthetic PR history could not be built in the workspace: {exc}") from exc
    recorded = (prepared.pr["base_commit"], prepared.pr["head_commit"])
    built = (history["base_commit"], history["head_commit"])
    if built != recorded:
        raise ExecutionError(
            f"synthetic PR history is not reproducible: the workspace holds {built[0]}..{built[1]}, "
            f"and the prepared input recorded {recorded[0]}..{recorded[1]}")
    return history


def _failure_message(exc: BaseException) -> str:
    """The exception's own type name and message, for a recorded failure."""
    return f"{type(exc).__name__}: {str(exc) or repr(exc)}"[:2000]


def _enclose(base: Path) -> Containment:
    """Capture *base*'s real path before the scanner runs, or refuse the invocation.

    Every containment check in this module is against a path captured this way, and every
    capture happens before the adapter is called. A base that cannot be resolved has no real
    path to contain against, so it is a setup failure rather than a check that quietly returns
    ``None`` after the scan.
    """
    try:
        return Containment.capture(base)
    except MaterializationError as exc:
        raise ExecutionError(str(exc)) from exc


def list_directory(directory: Path) -> list[os.DirEntry]:
    """Every entry in *directory*, sorted by name, raising when the listing cannot complete.

    The one listing this module and the harness adapter make, and the one rule behind it: an
    enumeration that cannot complete is a failed observation, never an empty one.
    :func:`os.scandir` raises when the directory cannot be opened, and iterating it raises when
    the listing breaks part way through; both happen inside this ``with``, so a caller receives
    the error rather than a short list it cannot tell from a complete one.

    Why this exists rather than ``os.walk``, ``Path.glob``, or ``Path.rglob``. Each of those
    swallows exactly that error: ``os.walk`` reports a directory it could not list as holding
    nothing, and the glob methods drop it without a word. This package built four separate
    checks on one of them and every one read an unreadable directory as an empty one, which is
    four ways a scanner could hide what it wrote by closing a directory behind itself. The
    package's other enumeration, :func:`~scaneval.materialize.walk_regular_files`, keeps the
    same rule for the input tree.
    """
    with os.scandir(directory) as entries:
        return sorted(entries, key=lambda entry: entry.name)


def walk_entries(root: Path) -> Iterator[tuple[Path, os.DirEntry]]:
    """Every entry under *root* and its path, never descending through a symbolic link.

    Built on :func:`list_directory`, so a directory that cannot be listed raises out of the walk
    instead of contributing nothing to it: every walk in this module is this one, for that
    reason. A symbolic link is yielded and never followed, so nothing behind one is enumerated
    as part of *root*; what to do with the link itself is the caller's rule, not this one's.
    """
    pending = [Path(root)]
    while pending:
        directory = pending.pop()
        for entry in list_directory(directory):
            path = Path(entry.path)
            yield path, entry
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)


def read_regular_file(path: Path) -> bytes:
    """The bytes at *path*, which must be a regular file, read without following a link.

    The one read this module and the harness adapter make of a path a scanner wrote or could
    have replaced, and the one rule behind it: such a read must prove the file is a regular file
    before it can block on it. The proof and the read are the same open, so nothing can be
    swapped in between: ``O_NOFOLLOW`` refuses a symbolic link as the last component,
    ``O_NONBLOCK`` makes opening a named pipe return at once rather than wait for a writer that
    never comes, and the descriptor is checked with :func:`os.fstat` before a byte is read.

    Everything that is not a readable regular file raises :class:`OSError`, so a caller that
    must not fail records the message instead of the bytes. A named pipe left where a scanner's
    own output belongs used to block an invocation forever, leaving no bundle and no record that
    the run had happened at all.

    The one read that does not come through here, named so it is not mistaken for an oversight:
    an artifact's content hash, taken by :func:`~scaneval.materialize.sha256_file`, which streams
    the file rather than holding it in memory. :func:`run_invocation` states the same requirement
    before it calls that, with :meth:`Path.is_symlink` and :meth:`Path.is_file`, over a tree
    :func:`_privatize` has already cleared of links; that is two operations rather than one, and
    the window between them is the one ``docs/THREAT_MODEL.md`` describes.
    """
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, "rb") as stream:
        return stream.read()


def _copy_tree_unresolved(source: Path, destination: Path) -> list[str]:
    """Copy one directory tree without following a symbolic link, and name the links it kept.

    This is the one rule for every tree this module copies, into the private workspace and into
    the bundle alike: a link is preserved as a link or refused, never resolved. Copying with
    ``symlinks=False`` followed every link, so a scanner that planted one inside its state
    directory, or planted one *as* its state directory, had the host file behind it copied into
    the bundle as if the scan had produced it.

    A link at the top is refused, because a state directory that is a link is not the directory
    this run handed the scanner; the caller records the refusal. A link inside the tree is
    recreated as a link, so the bundle records what the scanner left rather than the bytes it
    pointed at, and the returned relative paths let the caller say so in the record.

    The limits. A hard link is not a symbolic link: this copy reads its bytes, which gives the
    destination an inode of its own, and a staged tree that is moved rather than copied is
    de-aliased instead by :func:`_privatize`. A link preserved here is preserved in a staging
    directory, not in a bundle: :func:`_move_into_bundle` cuts it on the way in and names it in
    the record, so nothing that reaches a bundle resolves to a host path when someone follows it
    by hand later.

    The walk that names the links is :func:`walk_entries`, so a copied directory that cannot be
    listed raises rather than reporting that the copy holds no link. Under ``os.walk`` it did
    the second thing, and the record then said a tree holding links held none.
    """
    if source.is_symlink():
        raise ExecutionError(f"{source} is a symbolic link, not a directory; it was not copied")
    shutil.copytree(source, destination, symlinks=True)
    links = [path.relative_to(destination).as_posix()
             for path, entry in walk_entries(destination) if entry.is_symlink()]
    return sorted(links)



def _home_relative(rendered: str) -> str:
    """Spell a path under the operator's home directory with a leading ``~``.

    A cut link's target is recorded as a fact about the run, and a run record travels: a target
    under the home directory would carry the operator's account name into every copy of the
    bundle, which is the one thing a record must never do (see ``docs/THREAT_MODEL.md``). The
    directory structure below the home is kept, because that is what says where the link went;
    only the prefix that names the machine and the account is replaced.
    """
    home = str(Path.home())
    if home and (rendered == home or rendered.startswith(home + os.sep)):
        return "~" + rendered[len(home):]
    return rendered

def _privatize(root: Path) -> tuple[list[str], list[str], list[str]]:
    """Make every path under *root* name a file inside it; name what was copied, cut, and failed.

    This is what a staged tree must satisfy to be part of a bundle, and the whole of it: **no
    path in a bundle may name a file outside the bundle.** Three things break that rule and each
    is handled here, in one walk, before anything reads, hashes, or counts a line of the tree.

    A hard link. ``raw/`` and ``trace/`` are moved rather than copied, which is what keeps the
    scanner's own bytes exactly as it wrote them, but a move preserves inodes: a hard link the
    scanner planted made the bundle's copy and a live host file one and the same file, so what
    ScanEval hashed and line-counted was whatever that host file held at that moment, it went on
    changing under the recorded hash afterwards, and anything later written through the bundle's
    name would have written into the host file. It is copied rather than refused, because
    refusing would destroy the scanner's raw output to prevent something the scanner could do
    anyway: it could have copied any file it can read into ``raw/`` itself, and this module never
    claimed the raw tree holds only bytes the scan invented. What a hard link adds is the live
    alias, and copying removes exactly that: the bundle keeps a private snapshot of the bytes,
    the host file keeps its own inode and is never written to. The copy is read and replaced
    through the bundle's own name, so the host path is neither opened for writing nor unlinked.

    What the check behind that actually establishes, because the note this writes must not say
    more: a link count above one, and nothing else. It says the inode has at least one other
    name; it does not say where that name is. Two staged files the scanner linked to each other
    inside ``raw/`` have the same link count as one linked to the operator's private key, and
    this sweep cannot tell them apart without searching every filesystem the bundle can reach,
    which it does not do. So both are copied, which is right either way, and the record says a
    link count was observed rather than claiming an alias out of the bundle was proved.

    A symbolic link. It used to be kept, on the argument that it is visibly a link and nothing
    here follows one. That argument was wrong twice. ``bundle/raw/x`` naming a host file is the
    same alias a hard link is, and it stays live: it is what anyone reading the bundle by hand
    afterwards actually opens. And a link to a directory hid a whole subtree from this walk, so
    a hard link behind one was never de-aliased at all, which made the hard-link rule above
    defeatable by planting one link above it. Every link is cut instead, and its name and its
    target go into the record: what the scanner did is preserved as a fact about the run rather
    than as a live pointer out of the bundle. Nothing behind it was ever the bundle's to keep.

    Anything else the scanner left, a named pipe or a socket among them, stays exactly as it
    wrote it. Those name no file, so they alias nothing, and nothing in this package opens one.

    Nothing here is skipped and nothing here stops the sweep. Every way an entry can resist the
    rule, a directory that cannot be listed, an entry that cannot be inspected, a link that
    cannot be cut, and a hard link that cannot be copied, is collected into the third returned
    list and the walk carries on, so the caller learns about all of them; it records them and
    refuses the invocation, because a tree only half cleared may still hold a second name for a
    file outside the bundle and must not stand behind a clean result.

    Both halves of that were defects. An entry :func:`os.lstat` refused used to be skipped in
    silence, which is exactly what a hard link inside a directory the scanner left readable but
    not searchable is: the listing succeeds, the stat does not, the alias stayed live in the
    bundle, and no note, no error, and no count said so. And the first copy or unlink that failed
    raised out of here, so every entry the walk had not yet reached stayed aliased while the
    record named only the problem that stopped it. A failure to observe an entry is a recorded
    failed observation, never a skip, which is the rule :func:`list_directory` states for a
    listing and this one keeps for an entry.

    The walk is this function's own rather than :func:`walk_entries` for the same reason: a
    generator that raises cannot be resumed, so one unlistable directory ended the sweep for
    every directory after it too. An entry's kind is read with :func:`os.lstat` rather than from
    the directory entry, because an entry that cannot be stat'ed has no knowable kind and a link
    must never be followed to learn one.

    The limit. The bytes copied are the bytes at this moment, which is after the scanner's
    process has exited but is still a read the scanner could have raced had it left something
    running. See ``docs/THREAT_MODEL.md``.
    """
    dealiased: list[str] = []
    cut: list[str] = []
    failures: list[str] = []
    pending = [Path(root)]
    while pending:
        directory = pending.pop()
        try:
            entries = list_directory(directory)
        except OSError as exc:
            failures.append(f"{directory.relative_to(root).as_posix()}: the directory could not "
                            f"be listed, so nothing in it was de-aliased: {_failure_message(exc)}")
            continue
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            try:
                status = os.lstat(path)
            except OSError as exc:
                failures.append(f"{relative}: the entry could not be inspected, so whether it "
                                f"names a file outside the bundle is unknown: {_failure_message(exc)}")
                continue
            if stat.S_ISLNK(status.st_mode):
                try:
                    target = _home_relative(os.readlink(path))
                except OSError:
                    target = "an unreadable target"
                try:
                    os.unlink(path)
                except OSError as exc:
                    failures.append(f"{relative}: the symbolic link to {target} could not be cut: "
                                    f"{_failure_message(exc)}")
                    continue
                cut.append(f"{relative} -> {target}")
                continue
            if stat.S_ISDIR(status.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(status.st_mode) or status.st_nlink <= 1:
                continue
            private = path.with_name(f".{path.name}.{uuid.uuid4().hex}.dealias")
            try:
                shutil.copyfile(path, private)
                os.chmod(private, stat.S_IMODE(status.st_mode))
                os.replace(private, path)
            except OSError as exc:
                Path(private).unlink(missing_ok=True)
                failures.append(f"{relative}: the hard link could not be copied, so this path may "
                                f"still be a second name for a file outside the bundle: "
                                f"{_failure_message(exc)}")
                continue
            dealiased.append(relative)
    return sorted(dealiased), sorted(cut), sorted(failures)


def _move_into_bundle(staging: Path, destination: Path) -> tuple[list[str], list[str], list[str]]:
    """Move one staged directory into the bundle under the rule for what a bundle may hold.

    A staging directory the adapter removed is recreated empty at the destination, so the
    bundle always holds the directory the execution record describes. A staging directory the
    adapter replaced with a symbolic link is refused instead of moved: moving it would make the
    bundle's own ``raw/`` or ``trace/`` a link to somewhere outside the bundle while the run
    recorded a success. The caller records that refusal as an outcome contract violation.

    This is the one place a staged tree enters a bundle, so it is the one place the rule is
    enforced: no path in a bundle may name a file outside it. :func:`_privatize` runs on the
    moved tree before anything reads, hashes, or counts a line of it, copying every hard link
    and cutting every symbolic link. The three returned lists are the files that had to be
    copied, the links that were cut, each as ``name -> target``, and every entry the sweep could
    not clear, for the caller to record. The sweep finishes whatever it finds, so the third list
    names every such entry rather than the first one; a non-empty third list means this tree may
    still hold a second name for a file outside the bundle, which the caller refuses.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    if staging.is_symlink():
        raise ExecutionError(
            f"the staging directory {staging.name} is a symbolic link, not a directory; it was "
            "not moved into the bundle")
    if staging.exists():
        shutil.move(str(staging), str(destination))
    else:
        destination.mkdir(parents=True, exist_ok=True)
    return _privatize(destination)


def _rebase(path: Path, areas: list[tuple[Path, Path, Path]]) -> Path:
    """Re-root a path the adapter reported in a staging area to its place in the bundle.

    Both the staging path as handed out and its resolved form are tried, because an adapter may
    report either. A path in no staging area is returned unchanged rather than guessed at.
    """
    for staged, resolved, final in areas:
        for base in (staged, resolved):
            try:
                relative = path.relative_to(base)
            except ValueError:
                continue
            return final / relative
    return path


def _git_tree(source_dir: Path) -> dict[str, str]:
    """``{relative path: content hash}`` for a top-level ``.git`` this run did not create.

    :func:`~scaneval.materialize.walk_regular_files` always leaves the top-level ``.git`` out,
    because the runner writes one itself for a git-dependent adapter. When it did not write one,
    that directory is ordinary content of the tree under evaluation and belongs in the map, so
    it is walked here and put back. A ``.git`` that is a symbolic link is left out, like every
    other link: it has no content of its own to hash.

    The walk is :func:`walk_entries`, so a ``.git`` the scanner filled and then closed raises
    instead of reading as empty. That is the whole point of counting it: the exclusion was one
    directory name a scanner could write under freely, whether or not the adapter asked for git
    and whether or not this run had created one.
    """
    root = source_dir / ".git"
    if root.is_symlink() or not root.is_dir():
        return {}
    return {f".git/{path.relative_to(root).as_posix()}": sha256_file(path)[0]
            for path, entry in walk_entries(root)
            if not entry.is_symlink() and entry.is_file(follow_symlinks=False)}


def _input_tree(source_dir: Path, state_dirs: frozenset[str], *, created_git: bool) -> dict[str, str]:
    """The one definition of the input tree: ``{relative path: content hash}``.

    Two things need this map and must not disagree about it: the hash compared against
    ``prepared.tree_hash`` before the scan, and the before/after comparison that decides
    ``source_modified``. Both are computed from this function, so a path one of them counts
    cannot be a path the other ignores.

    Excluded, and why. Symbolic links and anything that is not a regular file, because they
    have no content of their own to hash. Each of the adapter's declared *state_dirs*, because
    they are the scanner's private scratch space, are preserved separately under
    ``raw/harness-state/``, and exist only because the scanner created them. A top-level
    ``.git`` component only when *created_git* says this run wrote one
    (:func:`~scaneval.materialize.prepare_synthetic_history`), since counting the runner's own
    bookkeeping would report it as a scanner modification.

    That ``.git`` exclusion used to be unconditional, which handed every scanner one directory
    name it could write under and stay out of this map, including on a run whose adapter never
    asked for git and where no ``.git`` existed until the scanner made one. It is excluded only
    when this run created it now: see :func:`_git_tree`, which puts the directory back otherwise.

    Only the top-level ``.git`` is ever excluded. Excluding every path with a ``.git`` component
    anywhere gave a scanner the same hiding place at any depth, which is the same escape as the
    state directories without even needing an adapter to declare one.

    The exclusions are sound only while the exported input contains no such directory itself.
    :func:`run_invocation` establishes that by comparing this map's hash against
    ``prepared.tree_hash``, which :func:`~scaneval.materialize.hash_exported_tree` computed over
    the whole export: an input that ships one of the adapter's state directories, or a ``.git``
    that the export strips and this map counts, cannot produce a matching hash here, so it is
    refused rather than scanned with bytes the two sides disagree about.

    The walk is :func:`~scaneval.materialize.walk_regular_files`, which enumerates explicitly
    and raises when a directory cannot be listed. It used to be :meth:`Path.rglob`, which
    swallows that error: a scanner could write into the source, make the directory it wrote in
    unreadable, and the files it left behind would simply not appear in the map, so the scan
    read as a clean observation of a tree it had changed. A tree that cannot be walked is now a
    failed observation, never an empty one.
    """
    hashes = {relative: sha256_file(path)[0]
              for relative, path in sorted(walk_regular_files(source_dir, skip_top_level=state_dirs).items())}
    if not created_git:
        hashes.update(_git_tree(source_dir))
    return hashes


def _recordable_text(value: str) -> str:
    """*value* when UTF-8 can encode it, else the same text with what it cannot escaped.

    The escape is ``backslashreplace``, so a surrogate stands as ``\\udcff`` and a reader can
    recover the byte the filesystem held. The rendering is lossless and it is not the name: a
    path recorded this way no longer opens by the string the record carries, which is why an
    artifact whose bundle path needs it is dropped with a note instead (see
    :func:`run_invocation`), and why what remains recorded this way is text nothing dereferences.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return value.encode("utf-8", "backslashreplace").decode("ascii")
    return value


def _recordable(value: object) -> tuple[object, int]:
    """*value* with every string in it recordable, and how many had to be rendered.

    The one place both bundle documents pass through before they are validated and written, so
    the rule holds for every string either of them can carry, wherever it came from: a path the
    scanner chose, a note, an adapter's own version string, a key in a mapping it supplied.

    Why it is here rather than at each of those places. A file name is bytes, and a filesystem
    that accepts bytes UTF-8 cannot decode hands Python a string holding escaped surrogates,
    which canonical JSON keeps and every contract check passes but :meth:`str.encode` refuses. So
    the failure surfaced at the moment the documents became bytes, where the only thing left to
    do was refuse the bundle, and the refusal record was built from the same values and refused
    again: the invocation raised with ``raw/`` and ``request.json`` written and neither
    ``result.json`` nor ``execution.json`` beside them. A scanner could reach that by naming one
    file it wrote. Rendering the text costs a name that no longer opens; raising costs the whole
    record of the run.

    A cyclic container raises :class:`RecursionError` here, as it does in validation, and the
    caller records that refusal.
    """
    if isinstance(value, str):
        rendered = _recordable_text(value)
        return rendered, int(rendered != value)
    if isinstance(value, dict):
        rendered_map: dict = {}
        count = 0
        for key, item in value.items():
            if isinstance(key, str):
                key_text = _recordable_text(key)
                count += int(key_text != key)
                key = key_text
            rendered_item, item_count = _recordable(item)
            rendered_map[key] = rendered_item
            count += item_count
        return rendered_map, count
    if isinstance(value, list):
        rendered_list = []
        count = 0
        for item in value:
            rendered_item, item_count = _recordable(item)
            rendered_list.append(rendered_item)
            count += item_count
        return rendered_list, count
    return value, 0


def _empty_trace(trace_mode: str) -> dict:
    """The trace record for a bundle whose trace was never read: counted as unavailable."""
    return {"path": None, "events": None, "mode": trace_mode, "capture_gap": None, "dropped_events": None}


def _recordable_document(document: dict) -> tuple[dict, int]:
    """One bundle document with every string in it recordable, and how many were rendered.

    A mapping in is a mapping out; the copy is what makes that true for the type as well as at
    runtime, and a bundle document is small enough for it to cost nothing.
    """
    rendered, count = _recordable(document)
    return dict(rendered), count  # type: ignore[call-overload]


# Every ``capture`` value that claims the category was observed at all, and so needs a trace in
# this bundle behind it. ``unavailable`` and ``not_applicable`` are the rest of the schema's
# enumeration and claim no observation, so nothing backs them and nothing has to.
#
# A tuple rather than a set, because the membership test runs over values an adapter supplied and
# those are not yet known to be strings: a ``capture`` holding a dict is a contract violation the
# record is built to report, and ``in`` over a set would hash it and raise before it could be.
_OBSERVED_CAPTURE = ("complete", "partial", "redacted")


def _capture_record(capture: dict, capture_state: dict | None, trace_record: dict | None,
                    ) -> tuple[dict, str | None]:
    """The capture mapping this bundle can support, and how the observation of this run broke.

    One function for two facts that used to be written independently into the same document, and
    could therefore contradict each other. ``trace.events`` counts the events the bundle holds;
    each ``capture`` category says how completely that category was observed. A run could reach a
    clean success with ``trace.events`` null and ``capture.finding_submitted`` reading
    ``complete``, in four ways, one for each way :func:`_read_trace` declines to count: a trace
    path that is a symbolic link, one that resolves outside the bundle, one that is not a regular
    file, and one that is simply not there. A trace mode of ``off`` and a discarded outcome make
    six. The adapter is not lying in any of them; it reports what its observer saw, and it cannot
    know whether the file landed in the bundle. This module does know, so this is where the two
    are reconciled.

    The rule: a category may claim that it was observed at all only in a bundle that holds a
    trace with at least one event in it. Anywhere else, every value in :data:`_OBSERVED_CAPTURE`
    becomes ``unavailable``, because what was recorded is then a claim of observation with no
    record of any observation behind it. Two values are left alone, and only two: ``unavailable``
    claims nothing, and ``not_applicable`` says the category does not apply to this scan at all,
    which is a fact about the scanner rather than about what this run observed.

    The rule used to reconcile ``complete`` alone, and rewrite it to ``partial``. That closed the
    loudest half and left the quiet half open: a bundle holding no trace at all went on recording
    ``partial`` observation of categories nothing had observed, and the downgrade wrote a second
    one of those into the record itself. ``partial`` is a claim that something was seen and some
    of it was missed, and ``redacted`` is a claim that something was seen and stored with values
    hidden; neither is a claim a bundle with no trace in it can back any better than ``complete``
    is. The downgrade target is therefore the one value that claims nothing.

    A trace of zero events is one of those places, and it used to count as a trace. An empty
    file backs no claim about what was observed: it is the same record a run that wrote nothing
    at all leaves, so a bundle could say ``trace.events`` zero beside ``complete`` capture of
    ``finding_submitted`` and still read as a clean success.

    The second value is how the observation broke, and it is ``None`` when it did not: the
    observer's own report of a capture gap or a dropped event, read off the same
    ``capture_state`` the trace record carries, and a downgraded category, named. The caller
    records ``partial`` on an outcome that still carries claims, so a run cannot be a clean
    success while its own records say it was not completely observed.
    """
    reasons = []
    if isinstance(capture_state, dict):
        if capture_state.get("capture_gap") is True:
            reasons.append("a capture gap")
        dropped = capture_state.get("dropped_events")
        if isinstance(dropped, int) and not isinstance(dropped, bool) and dropped > 0:
            reasons.append(f"{dropped} dropped event(s)")
    events = trace_record.get("events") if isinstance(trace_record, dict) else None
    counted = isinstance(events, int) and not isinstance(events, bool) and events > 0
    recorded = dict(capture)
    unbacked = sorted(name for name, value in recorded.items()
                      if value in _OBSERVED_CAPTURE) if not counted else []
    for name in unbacked:
        recorded[name] = "unavailable"
    if unbacked:
        reasons.append(f"observed capture of {', '.join(unbacked)} claimed with no trace event "
                       "in this bundle")
    return recorded, " and ".join(reasons) or None


def _read_trace(outcome: NativeOutcome, staged_areas: list[tuple[Path, Path, Path]], trace_dir: Path,
                trace_mode: str, bundle: Containment) -> dict:
    """Count the events in the staged trace file and record where it landed.

    Only a regular file this bundle actually holds is read: a trace path that is a symbolic link,
    that resolves outside the bundle, or that is not a regular file is refused with a note and no
    count. A number taken from a file the run never staged would describe something the bundle
    does not contain, and opening a named pipe for reading would block until something wrote to
    it, which nothing here ever does. A missing trace file is an unavailable count, not a
    failure. A file that is not UTF-8 text raises, because a count taken from bytes this cannot
    decode would be an invented number.

    The read itself is :func:`read_regular_file`, so the regular-file requirement is proved by
    the same open that reads the bytes rather than by a check the scanner could have raced.
    """
    events_path = (_rebase(Path(outcome.trace_path), staged_areas) if outcome.trace_path
                   else trace_dir / "events.jsonl")
    count = None
    recorded_trace_path = None
    if events_path.is_symlink():
        outcome.notes.append("declared trace file is a symbolic link; it was not read or counted")
    elif bundle.contains(events_path) is None:
        outcome.notes.append("declared trace file is outside the bundle; it was not read or counted")
    elif events_path.exists() and not events_path.is_file():
        outcome.notes.append("declared trace file is not a regular file; it was not read or "
                             f"counted: {events_path.name}")
    elif events_path.is_file():
        try:
            recorded_trace_path = events_path.relative_to(bundle.base).as_posix()
        except ValueError:
            outcome.notes.append("trace file left outside the bundle; its path is not recorded")
        else:
            text = read_regular_file(events_path).decode("utf-8")
            count = sum(1 for line in text.splitlines() if line.strip())
    return {"path": recorded_trace_path, "events": count, "mode": trace_mode,
            "capture_gap": (outcome.capture_state or {}).get("capture_gap"),
            "dropped_events": (outcome.capture_state or {}).get("dropped_events")}


def _outcome_violation(outcome: object) -> str | None:
    """The first way *outcome* breaks the adapter contract, or ``None`` when it keeps it.

    This checks only the shapes the bundle documents are built from: the outcome type itself,
    artifact entries, tool versions, command words, usage numbers, notes, the omitted paths, the
    ``examined_nothing`` flag, and the containers this module copies or walks. It says nothing
    about whether the scan was correct, complete, or honest, and it does not check the claims, the
    ranking, or the status: the scan-result contract checks those, and a violation there is
    recorded as a failed import. A field only the execution record constrains, such as a
    non-integer exit code, is caught when that record is validated.
    """
    if not isinstance(outcome, NativeOutcome):
        return f"adapter returned {type(outcome).__name__}, not a NativeOutcome"
    if not isinstance(outcome.artifacts, list):
        return f"artifacts must be a list, not {type(outcome.artifacts).__name__}"
    declared: set[str] = set()
    for index, artifact in enumerate(outcome.artifacts):
        if not isinstance(artifact, dict):
            return f"artifacts[{index}] must be a mapping, not {type(artifact).__name__}"
        identifier = artifact.get("id")
        if not isinstance(identifier, str) or not identifier:
            return f"artifacts[{index}].id must be a non-empty string, not {identifier!r}"
        if identifier in declared:
            # A claim cites one id, so an id naming two files makes the citation ambiguous: the
            # reader cannot tell which bytes the claim rests on, and the second file would be
            # registered under a name already taken.
            return (f"artifacts[{index}].id {identifier!r} is declared twice; one artifact id "
                    "must name one file")
        declared.add(identifier)
        path = artifact.get("path")
        if not isinstance(path, (str, PurePath)):
            return f"artifacts[{index}].path must be a string or a path, not {type(path).__name__}"
    if not isinstance(outcome.tool_versions, dict):
        return f"tool_versions must be a mapping, not {type(outcome.tool_versions).__name__}"
    for name, version in outcome.tool_versions.items():
        if not isinstance(name, str) or not isinstance(version, str):
            return f"tool_versions[{name!r}] must be a string, not {type(version).__name__}"
    if not isinstance(outcome.command, list):
        return f"command must be a list, not {type(outcome.command).__name__}"
    for index, word in enumerate(outcome.command):
        if not isinstance(word, str):
            return f"command[{index}] must be a string, not {type(word).__name__}"
    if not isinstance(outcome.usage, dict):
        return f"usage must be a mapping, not {type(outcome.usage).__name__}"
    for key, value in outcome.usage.items():
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return f"usage[{key!r}] must be a number, not {type(value).__name__}"
    if not isinstance(outcome.notes, list):
        return f"notes must be a list, not {type(outcome.notes).__name__}"
    for index, note in enumerate(outcome.notes):
        if not isinstance(note, str):
            return f"notes[{index}] must be a string, not {type(note).__name__}"
    if not isinstance(outcome.capture, dict):
        return f"capture must be a mapping, not {type(outcome.capture).__name__}"
    if outcome.capture_state is not None and not isinstance(outcome.capture_state, dict):
        return f"capture_state must be a mapping or None, not {type(outcome.capture_state).__name__}"
    if outcome.model_identity is not None and not isinstance(outcome.model_identity, dict):
        return f"model_identity must be a mapping or None, not {type(outcome.model_identity).__name__}"
    if outcome.trace_path is not None and not isinstance(outcome.trace_path, (str, PurePath)):
        return f"trace_path must be a string, a path, or None, not {type(outcome.trace_path).__name__}"
    if outcome.omitted_paths is not None:
        if not isinstance(outcome.omitted_paths, list):
            return f"omitted_paths must be a list or None, not {type(outcome.omitted_paths).__name__}"
        for index, path in enumerate(outcome.omitted_paths):
            if not isinstance(path, str):
                return f"omitted_paths[{index}] must be a string, not {type(path).__name__}"
    if outcome.examined_nothing is not None and not isinstance(outcome.examined_nothing, bool):
        return f"examined_nothing must be a bool or None, not {type(outcome.examined_nothing).__name__}"
    return None


def _violation_outcome(message: str) -> NativeOutcome:
    """The outcome recorded in place of one that broke the contract.

    Nothing the adapter reported is carried over: an outcome this module could not read is not
    a source of claims, artifact paths, versions, or usage. The raw output the scanner already
    wrote is still staged into the bundle, so what the scan produced on disk is preserved.

    ``bundles_resolved`` is false for the same reason it is false on :func:`_error_result`:
    every claim the scan may have made was discarded, so this record must not carry the numeric
    shape of a scan whose claims all arrived.
    """
    return NativeOutcome(
        status="error", exit_code=None, command=[], bundles_resolved=False,
        error={"code": "outcome_contract_violation", "message": message[:2000]},
        notes=[f"The adapter outcome was discarded: {message}"[:2000]])


def _error_result(run_id: str, system_id: str, input_hash: str, wall: float, error: dict) -> dict:
    """A scan result carrying an explicit error and nothing the adapter supplied.

    Only fields the scan request already validated and this module computed are used, so a value
    the adapter reported cannot carry its own contract violation into the record that reports
    the refusal. The raw artifacts stay in the execution record, which is where a failed import
    leaves the evidence of what the scan wrote.

    ``bundles_resolved`` is false. This record reports that every claim the scan made was lost,
    which is maximal import loss; reporting resolved bundles would give it the numeric shape of
    a fully imported scan and let the scoring contract read a claim budget off it.
    """
    return {"schema_version": "2.0", "run_id": run_id, "system_id": system_id,
            "input_hash": input_hash, "status": "error", "claims": [], "ranking": "unranked",
            "bundles_resolved": False, "usage": {"wall_seconds": round(wall, 3), "cost_usd": None},
            "error": error}


def run_invocation(
    *,
    prepared: PreparedInput,
    adapter: Adapter,
    spec: SystemSpec,
    preparation: dict,
    out_dir: Path,
    run_id: str,
    repetition: int = 1,
    timeout_seconds: float = 1800,
    trace_mode: str = "off",
    network_policy: str = "none",
    workspace_root: Path | None = None,
    clock: Callable[[], datetime] | None = None,
    backend: Any = None,
) -> Path:
    """Execute one invocation and return its bundle directory. Never overwrites.

    *backend* is the execution backend the scanner's processes run under; ``None`` is the local,
    unenforced one. A backend exposes ``activate()``, a context manager in force while the adapter
    runs, ``isolation_record()``, the 2.1 isolation block describing what actually bounded the
    run, and ``network_enforced``. The execution record is written at 2.1 when the input is PR or
    blinded or the backend is not local, and at 2.0 exactly as before otherwise.

    An input whose mode the adapter does not declare in :attr:`~scaneval.adapters.base.Adapter.scan_modes`
    is recorded as ``unsupported`` with error code ``unsupported_mode`` and the adapter's ``scan`` is
    never called, whatever it would have done: an adapter that cannot review a change is never run
    on the head instead, and the invocation stays in every denominator, as an unsupported language
    does. For a PR input the workspace also holds the neutral two-commit history the request names
    (:func:`_pr_history`): built from the head copy and the input's base tree, whether or not the
    adapter asked for git, verified to be the commits the input recorded, and left out of the watched
    tree like the single commit a git-dependent full scan gets. A PR input that carries no synthetic
    commits or no base tree is refused before the bundle exists.

    ``result.json`` and ``execution.json`` are written only once both documents validate and
    encode, and they are renamed into place together, so a bundle never holds a successful
    result beside a missing execution record: a write that fails part way leaves neither. An
    outcome this module cannot read, an execution record the contract refuses, a trace file that
    is not UTF-8 text, and any failure while capturing harness state, moving the staged
    directories into the bundle, collecting or hashing declared artifacts, or serializing what
    the adapter reported all end as an error result carrying code ``outcome_contract_violation``
    and a message naming what was wrong. The adapter's own outcome is discarded in that case,
    because nothing in it can be trusted to describe the scan; the raw output it had already
    written is still staged into the bundle where the failure allowed it.

    A claim citing a ``raw_artifact_id`` this bundle does not register is one of those refused
    documents: the scan-result contract enforces the reference, so an id the adapter invented,
    and an id whose artifact was dropped here for being a link, missing, outside the bundle, or
    named in bytes this record cannot carry, both end as an error result carrying code
    ``import_contract_violation`` rather than as a success pointing at evidence nobody can open.

    Nothing else a scanner or an adapter named can make this bundle unrecordable. Both documents
    go through :func:`_recordable` before they are validated and written, so a string UTF-8
    cannot encode is rendered with backslash escapes and named in a note rather than raising
    where the only thing left to do is refuse. The two failures that still end the invocation
    with no record are named below, and both are the caller's own values rather than the
    scanner's: an adapter attribute the record copies that is not a string, and a prepared
    provenance that cannot be hashed, which is why that hash is taken before anything is created.

    A source the scan itself changed is a condition change, not a scanner failure: when the
    workspace source differs after the scan, an outcome that still carries claims is recorded as
    ``partial`` with ``bundles_resolved`` false and, unless the adapter already named a failure of
    its own, error code ``source_modified``. The claims stay, the modified paths stay in the
    provenance, and nothing about the scanner's competence is asserted; what is withdrawn is the
    result's claim to be a clean observation of the frozen input. What counts as the source for
    that comparison is :func:`_input_tree`, which is also what the pre-scan hash check covers, so
    the watched tree and the hashed tree are the same tree; an input that already holds one of
    the adapter's state directories, or a top-level ``.git`` the export strips and the watched
    tree counts, fails that check and is refused before the scanner runs, as is an input tree
    that cannot be walked at all, since there is no honest map of it to bind a result to. A
    ``.git`` is left out of the watched tree only when this run created it for a git-dependent
    adapter, so one a scanner makes is watched like any other directory it writes.

    Two things are narrower than they look. When the post-scan re-hash of the source fails, the
    comparison never completed, so the provenance reports no observed modification and the
    violation names the failed re-hash. And an adapter whose own ``name`` or ``adapter_version``
    is not a non-empty string still makes the execution record unwritable: that raises
    :class:`ExecutionError` once the bundle directory, its ``request.json``, and the staged
    ``raw/`` and ``trace/`` trees are already there, so what remains is a bundle holding the
    request and the scanner's own output with neither ``result.json`` nor ``execution.json``.
    That is why :mod:`scaneval.runner` vets the attributes every record copies when it prepares
    a system rather than when it invokes one.

    The scanner's private workspace is removed once both staged directories are in the bundle. A
    removal that fails does not change what the scan observed, so it is not a violation: the
    execution record carries a note naming the directory still on disk, which is a leak an
    operator can find rather than one that was swallowed.

    One rule decides what a staged tree may carry into the bundle, and it is enforced where the
    tree lands: no path in a bundle may name a file outside it. A staged file that turns out to
    be a second name for a file outside the bundle is copied as it lands, so the bundle holds
    its own inode and the hash it records is of bytes nothing else can change afterwards, and a
    symbolic link is cut, because it is a live name for a file the bundle does not hold and,
    when it points at a directory, it hides a subtree from the copy that breaks those aliases.
    Both are named in notes, links with their targets, so the record says what the scanner left
    where the bundle no longer holds it. A staged path the sweep could not inspect or clear,
    which is what a hard link inside a directory left readable but not searchable used to be
    until it was skipped in silence, is named in a note too and makes the invocation a recorded
    failure: a bundle that may still hold a second name for a host file must not read as a clean
    success. The sweep finishes before it reports, so that note names every such path rather than
    the one that stopped it. See :func:`_privatize`.

    Harness state is captured without following a link, at both ends of the copy. A state
    directory that is a symbolic link, or that is not a directory at all, is left out of
    ``captured_state_dirs`` and named in a note instead of copied through, because what lies
    behind it is not the scratch space this run created; a link inside one is copied as a link
    and counted in a note, then cut when the staged tree enters the bundle, so what it pointed
    at is named in the record and reachable from nothing. The destination is checked the same
    way, because the scanner
    writes into the staging directory too: a ``raw/harness-state`` it replaced with a link no
    longer resolves inside the staged raw output, so nothing is copied and the note says so
    rather than the copy landing wherever the link pointed. None of that is a violation of the
    outcome: nothing failed and no claim is affected, but the bundle says plainly that it does
    not hold what the link pointed at.

    A run the observer could not record completely is not a clean one, and how completely it was
    observed is derived once, by :func:`_capture_record`, for both the status and the ``capture``
    mapping the execution record carries. It breaks two ways: ``capture_state`` reporting a
    capture gap or a dropped event, and a ``capture`` category claiming ``complete`` in a bundle
    that holds no trace event, which is what a declared trace file that was a link, resolved
    out, was not a regular file, was never written, or was written empty used to leave beside a
    clean success. The category is downgraded to ``partial`` in the record, and an outcome that
    still carries claims
    is recorded as ``partial`` with error code ``trace_capture_gap``, unless the adapter already
    named a failure of its own. ``bundles_resolved`` is untouched: a dropped trace event is not a
    lost claim, and saying otherwise would withdraw the claim budget over a hole in the trace.
    The status is what changes, because that is what a reader and the scoring contract take as
    the run's claim to be complete.
    """
    if network_policy not in NETWORK_POLICIES:
        raise ExecutionError(f"unknown network policy {network_policy!r}")
    if trace_mode not in ("off", "metadata", "content"):
        raise ExecutionError(f"unknown trace mode {trace_mode!r}")
    unsupported = [lang for lang in prepared.languages if lang not in adapter.supported_languages]
    # Hashed before anything is created: the provenance is the caller's, it is fixed before the
    # scan, and a value it cannot be hashed from would otherwise surface while the execution
    # record was being built, where every rebuilt record would carry it too and the invocation
    # would end with no record at all.
    try:
        provenance_digest = canonical_sha256(prepared.provenance)
    except ContractError as exc:
        raise ExecutionError(f"the prepared input's provenance cannot be hashed, so no execution "
                             f"record can bind to it: {exc}") from exc
    request_pr = None
    if prepared.mode == "pr":
        # The request names the neutral synthetic commits the workspace history holds, and nothing
        # else about the change: no change set id, no snapshot, no tree hash. Checked before the
        # bundle exists, so a malformed PR input leaves no empty directory behind.
        commits = prepared.pr if isinstance(prepared.pr, dict) else {}
        base_commit, head_commit = commits.get("base_commit"), commits.get("head_commit")
        if not (isinstance(base_commit, str) and base_commit and isinstance(head_commit, str) and head_commit):
            raise ExecutionError("a PR input must carry the synthetic base_commit and head_commit its "
                                 "request names")
        if prepared.base_source_dir is None or not Path(prepared.base_source_dir).is_dir():
            raise ExecutionError("a PR input must carry the base export its synthetic history is built from")
        request_pr = {"base": base_commit, "head": head_commit}
    # Decided from what the adapter declares and never from what its scan would do: an input whose
    # mode the adapter does not carry out is recorded as unsupported and scan() is never called.
    mode_unsupported = prepared.mode not in adapter.scan_modes
    bundle = out_dir / invocation_id(prepared.input_id, spec.system_id, repetition)
    bundle.mkdir(parents=True, exist_ok=False)
    raw_dir = bundle / "raw"
    trace_dir = bundle / "trace" if trace_mode != "off" else None
    bundle_area = _enclose(bundle)
    request = build_request(run_id, prepared, spec, timeout_seconds=timeout_seconds, trace_mode=trace_mode,
                            pr=request_pr)
    _write_new(bundle / "request.json", request)

    state_dirs = frozenset(getattr(adapter, "state_dirs", ()))
    workspace = Path(tempfile.mkdtemp(prefix="scaneval-trial-", dir=str(workspace_root) if workspace_root else None))
    # The scanner writes into the workspace, never into the run directory; both staged
    # directories are moved into the bundle below, whether the scan returns or raises.
    #
    # Every directory a path is later checked against has its real path read here, before the
    # scanner exists, and each check below is against that captured path. Resolving a base after
    # the scanner ran was the same as asking the scanner where its own containment was.
    workspace_area = _enclose(workspace)
    staging_raw = workspace / "raw"
    staging_trace = None
    staged_areas = [(staging_raw, workspace_area.root / "raw", raw_dir)]
    if trace_dir is not None:
        staging_trace = workspace / "trace"
        staged_areas.append((staging_trace, workspace_area.root / "trace", trace_dir))
    staging_raw_area = _enclose(staging_raw)
    started_at = _now(clock)
    started = time.monotonic()
    synthetic = None
    outcome: NativeOutcome
    violation: str | None = None
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    captured_state: list[str] = []
    move_failures: list[str] = []
    alias_notes: list[str] = []
    capture_notes: list[str] = []
    cleanup_notes: list[str] = []
    try:
        staging_raw.mkdir()
        if staging_trace is not None:
            staging_trace.mkdir()
        source = workspace / "source"
        # No link is followed on the way in either: a link in the exported input stays a link,
        # which keeps it outside the hashed tree exactly as :func:`_input_tree` leaves it.
        _copy_tree_unresolved(prepared.source_dir, source)
        try:
            # Nothing has created a ``.git`` yet, so any that is here came with the input and is
            # counted; the hash check below is what refuses an input that ships one.
            before = _input_tree(source, state_dirs, created_git=False)
        except OSError as exc:
            # The tree handed to this invocation cannot be enumerated, so there is nothing to
            # compare the scan against and no honest hash to bind a result to. Refused the same
            # way a hash mismatch is, before the scanner runs.
            raise ExecutionError(f"the exported input could not be walked, so no observation of "
                                 f"it can be recorded: {_failure_message(exc)}") from exc
        actual = tree_hash(before)
        if actual != prepared.tree_hash:
            # The hash is taken over the same map the modification check uses, so a mismatch
            # also catches an input that already holds one of the adapter's state directories:
            # those bytes are inside prepared.tree_hash and outside the modification check, so
            # the scan is refused rather than run with part of its input unwatched.
            collision = sorted(name for name in state_dirs if (source / name).exists())
            detail = (f"; the exported input already contains adapter state directories "
                      f"({', '.join(collision)}), which are excluded from the input tree and so "
                      f"cannot be part of a matching hash") if collision else ""
            git = source / ".git"
            if not git.is_symlink() and git.is_dir():
                # The other direction of the same disagreement: the export hash leaves a
                # top-level .git out and the watched tree counts one this run did not create,
                # so an input that ships one can never match and is refused rather than scanned.
                detail += ("; the exported input already contains a top-level .git, which the "
                           "watched input tree counts and the exported hash does not")
            raise ExecutionError(f"workspace tree hash {actual} does not match prepared input "
                                 f"{prepared.tree_hash}{detail}")
        if prepared.mode == "pr":
            # A PR scanner reads a base and a head whether or not the adapter asked for git, and
            # nothing is built for one that will not scan: the history exists to be reviewed.
            if not mode_unsupported and not unsupported:
                synthetic = _pr_history(source, prepared)
        elif adapter.requires_git and not (source / ".git").exists():
            synthetic = prepare_synthetic_history(source)
        if mode_unsupported:
            outcome = NativeOutcome(status="unsupported", exit_code=None, command=[],
                                    error={"code": "unsupported_mode",
                                           "message": f"{adapter.name} does not declare support for "
                                                      f"{prepared.mode} scans; it carries out: "
                                                      f"{', '.join(sorted(adapter.scan_modes))}"},
                                    notes=["Not executed; stays in the denominator. A scan of any other "
                                           "mode is never run in its place."])
        elif unsupported:
            outcome = NativeOutcome(status="unsupported", exit_code=None, command=[],
                                    error={"code": "unsupported_language",
                                           "message": f"{adapter.name} does not declare support for: {', '.join(unsupported)}"},
                                    notes=["Unsupported work stays in the denominator; nothing was executed."])
        else:
            try:
                with (backend.activate() if backend is not None else nullcontext()):
                    outcome = adapter.scan(request=request, source_dir=source, raw_dir=staging_raw, spec=spec,
                                           preparation=preparation, timeout_seconds=timeout_seconds,
                                           trace_mode=trace_mode, trace_dir=staging_trace)
            except Exception as exc:
                # Any failure inside the adapter is a recorded error with its own type name,
                # never an empty successful scan and never a crash of the whole run.
                outcome = NativeOutcome(status="error", exit_code=None, command=[],
                                        error={"code": "adapter_failure", "message": _failure_message(exc)})
            else:
                # An outcome this module cannot read is a recorded failure too, checked here so
                # that nothing further reads an attribute the adapter did not really supply.
                violation = _outcome_violation(outcome)
        # Everything below this line reads or writes a path the scanner had write access to,
        # so each one is resolved whole and proved to be inside the directory it belongs to
        # before it is touched. This is the first of them: the exported source itself is one
        # component inside the private workspace, and a scanner that replaced it with a link
        # would otherwise have the capture and the re-hash walk whatever it pointed at.
        source_inside = workspace_area.contains(source) is not None
        if not source_inside:
            violation = violation or (
                "the exported source no longer resolves inside the private workspace, so "
                "nothing under it was read after the scan")
        try:
            for name in sorted(state_dirs) if source_inside else ():
                state_path = source / name
                if state_path.is_symlink():
                    # Checked before exists(), which follows the link and would report the
                    # target. Nothing behind it is copied and it is not counted as captured
                    # state: what a link points at is not the scratch space this run created
                    # for the scanner, and following it would pull host files into the bundle.
                    capture_notes.append(
                        f"the harness state directory {name} is a symbolic link; it was not "
                        "followed and nothing behind it was captured")
                    continue
                if not state_path.exists():
                    continue
                if not state_path.is_dir():
                    capture_notes.append(
                        f"the harness state path {name} is not a directory; it was not captured")
                    continue
                destination = staging_raw / "harness-state" / name.lstrip(".")
                if staging_raw_area.contains(destination) is None:
                    # The scanner owns the destination as well as the source: it writes into the
                    # staging directory while it runs, so a link at ``harness-state`` sends this
                    # copy to any absolute path it chooses. Nothing is created along a path that
                    # does not resolve back inside the staged raw output.
                    capture_notes.append(
                        f"the harness state destination for {name} does not resolve inside the "
                        "staged raw output; nothing was copied there")
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                links = _copy_tree_unresolved(state_path, destination)
                captured_state.append(name)
                if links:
                    capture_notes.append(
                        f"harness state {name} holds {len(links)} symbolic link(s), copied as "
                        f"links rather than copied through and cut when the staged output "
                        f"entered the bundle: {', '.join(links[:5])}")
        except Exception as exc:
            # The scanner owns both ends of this copy: the state directory it wrote and the
            # staging path it may have created there first. A failure is a recorded violation,
            # never a crash of the run, and the directories copied before it stay recorded.
            violation = violation or f"harness state could not be captured: {_failure_message(exc)}"
        try:
            # A ``.git`` is the runner's own bookkeeping only when the runner wrote it; when it
            # did not, one the scanner made is watched like everything else it wrote.
            after = (_input_tree(source, state_dirs, created_git=synthetic is not None)
                     if source_inside else dict(before))
        except Exception as exc:
            # The comparison never completed, so nothing is claimed about the source: `before`
            # stands in for `after`, the provenance reports no observed modification, and the
            # violation says the re-hash failed. A directory the scan made unreadable arrives
            # here, because the walk raises rather than reporting the files behind it as gone.
            after = dict(before)
            violation = violation or f"the source tree could not be re-hashed: {_failure_message(exc)}"
    finally:
        try:
            for staged, _resolved, final in staged_areas:
                try:
                    dealiased, cut, unswept = _move_into_bundle(staged, final)
                except Exception as exc:
                    # A staged directory that cannot be moved is recorded below rather than
                    # raised here, where it would replace whatever failure is already in flight.
                    move_failures.append(f"{final.name}: {_failure_message(exc)}")
                else:
                    if unswept:
                        # Every entry the sweep could not clear, not the first of them: this
                        # tree may still hold a second name for a file outside the bundle, so
                        # the note says which paths and the violation below refuses the run.
                        # The note carries all of them because a record naming only some is the
                        # defect this replaced.
                        alias_notes.append(
                            f"{len(unswept)} staged path(s) under {final.name}/ could not be "
                            f"inspected or de-aliased, so this bundle may still hold a second "
                            f"name for a file outside it: {'; '.join(unswept)}")
                        move_failures.append(
                            f"{final.name}: {len(unswept)} staged path(s) could not be inspected "
                            f"or de-aliased: {'; '.join(unswept)}")
                    if dealiased:
                        # A fact about this invocation, not something the adapter reported, so
                        # it outlives a discarded outcome like the capture and cleanup notes.
                        alias_notes.append(
                            f"{len(dealiased)} file(s) staged into {final.name}/ were hard links "
                            f"and were copied so the bundle holds an inode of its own. What was "
                            f"observed of each is a link count above one, so the inode had at "
                            f"least one other name; where that name is, inside this bundle or "
                            f"outside it, is not something this sweep looked for: "
                            f"{', '.join(dealiased[:5])}")
                    if cut:
                        # The link is gone from the bundle and its target is recorded here, so
                        # what the scanner left is a fact in the record rather than a live path
                        # out of the bundle for whoever opens it next.
                        alias_notes.append(
                            f"{len(cut)} symbolic link(s) staged into {final.name}/ were cut so "
                            f"no path in this bundle names a file outside it; the bytes behind "
                            f"them were never part of the scan: {'; '.join(cut[:5])}")
        finally:
            try:
                shutil.rmtree(workspace)
            except Exception as exc:
                # The bundle documents are still exactly as good as they were, so this is not a
                # violation of the outcome: it is a directory left behind, and it is named in
                # the execution record with its path rather than ignored. Contained here so a
                # failed cleanup cannot replace whatever failure is already in flight.
                cleanup_notes.append(
                    f"the scanner's private workspace could not be removed and is still on disk "
                    f"at {workspace}: {_failure_message(exc)}")
    if move_failures:
        violation = violation or ("staged output could not be moved into the bundle: "
                                  + "; ".join(move_failures))
    wall = time.monotonic() - started
    finished_at = _now(clock)
    modified = sorted(set(before) ^ set(after) | {p for p in before if p in after and before[p] != after[p]})
    trace_record: dict | None = None

    isolation = dict(LOCAL_ISOLATION) if backend is None else backend.isolation_record()
    network_enforced = backend is not None and bool(backend.network_enforced)
    record_2_1 = prepared.needs_2_1 or isolation.get("backend") != "local"

    def build_documents() -> tuple[dict, dict]:
        """The result and execution documents for the outcome as it currently stands.

        Both documents leave here recordable: every string in them has been through
        :func:`_recordable`, so nothing a scanner or an adapter named can make them unwritable,
        and the execution record says so in a note when anything had to be rendered.
        """
        raw_artifacts: list[dict] = []
        for artifact in outcome.artifacts:
            path = _rebase(Path(artifact["path"]), staged_areas)
            if path.is_symlink():
                # A link is never followed and never hashed: what it points at is not the file
                # this bundle preserved, and need not be inside the bundle at all.
                outcome.notes.append(f"declared artifact is a symbolic link and was not followed: {artifact['id']}")
                continue
            if path.exists() and bundle_area.contains(path) is None:
                outcome.notes.append(f"declared artifact resolves outside the bundle: {artifact['id']}")
                continue
            if not path.exists():
                outcome.notes.append(f"declared artifact missing: {artifact['id']}")
                continue
            if not path.is_file():
                # Only a regular file is hashed. A directory has no bytes of its own, and opening
                # a named pipe for reading would block until something wrote to it.
                outcome.notes.append(
                    f"declared artifact is not a regular file and was not hashed: {artifact['id']}")
                continue
            try:
                relative = path.relative_to(bundle).as_posix()
            except ValueError:
                # An artifact the adapter left outside its staging areas is reported, not copied:
                # this records what the scan produced, and never moves files it was not handed.
                outcome.notes.append(f"declared artifact outside the bundle: {artifact['id']}")
                continue
            if _recordable_text(relative) != relative:
                # The name is bytes UTF-8 cannot encode, so the only path this record could
                # carry is an escaped rendering of it, and a reader following that string would
                # find nothing. An artifact is evidence a claim cites, so it is dropped here with
                # the other artifacts nobody can open rather than registered under a name that
                # does not name it. The file itself stays in the bundle exactly as it is.
                outcome.notes.append(
                    f"declared artifact has a name this record cannot carry and was not "
                    f"registered: {artifact['id']}")
                continue
            raw_artifacts.append({"id": artifact["id"], "path": relative, "sha256": sha256_file(path)[0]})
        usage = {key: value for key, value in outcome.usage.items() if key in _USAGE_KEYS and value is not None}
        usage["wall_seconds"] = round(wall, 3)
        if "cost_usd" not in usage:
            usage["cost_usd"] = None
        result = {
            "schema_version": "2.0", "run_id": run_id, "system_id": spec.system_id,
            "input_hash": prepared.binding_hash, "status": outcome.status, "ranking": outcome.ranking,
            "claims": outcome.claims, "bundles_resolved": outcome.bundles_resolved, "usage": usage,
            **({"error": outcome.error} if outcome.error else {}),
            **({"raw_artifacts": raw_artifacts} if raw_artifacts else {}),
        }
        if prepared.mode == "pr":
            # A PR review reads the head tree, so its claims locate against head. Said in the
            # result itself, where the locations are, rather than left for a reader to infer.
            result["schema_version"] = "2.1"
            result["location_basis"] = "pr_head"
        if outcome.omitted_paths is not None:
            # A 2.1 field, so the result is 2.1 whatever the mode. Sorted and each path once, so one set of
            # omissions is one list, which is what the contract requires of it.
            result["schema_version"] = "2.1"
            result["omitted_paths"] = sorted(set(outcome.omitted_paths))
        if outcome.examined_nothing is not None:
            # Also a 2.1 field, so also 2.1 whatever the mode, and written as the adapter said it.
            result["schema_version"] = "2.1"
            result["examined_nothing"] = outcome.examined_nothing
        result, rendered_in_result = _recordable_document(result)
        if "omitted_paths" in result:
            # Rendering a name UTF-8 cannot encode can reorder the list or merge two entries into one, so the
            # order and the uniqueness the contract checks are made last, on the text that is written.
            result["omitted_paths"] = sorted(set(result["omitted_paths"]))
        import_error = None
        try:
            # The document validated is the document written: the rendering above happens first,
            # so nothing the contract approved is reshaped after it approved it.
            validate_document("scan-result", result)
        except ContractError as exc:
            # A normalization that violates the contract is a failed import, not a quiet empty
            # success. The replacement is built from known-good fields only: spreading the
            # refused document would carry its usage or artifacts, and their violation with
            # them, straight into the record that reports the refusal.
            import_error = _recordable_text(str(exc))
            result = _error_result(run_id, spec.system_id, prepared.binding_hash, wall,
                                   {"code": "import_contract_violation", "message": import_error[:2000]})
            if prepared.mode == "pr":
                result["schema_version"] = "2.1"
                result["location_basis"] = "pr_head"
            try:
                validate_document("scan-result", result)
            except ContractError as refusal:
                raise _BundleRefused(
                    f"scan result violates its contract and its error record was refused too: "
                    f"{refusal}") from refusal
        execution = {
            "schema_version": "2.0", "run_id": run_id, "invocation_id": bundle.name,
            "input_id": prepared.input_id, "system_id": spec.system_id, "repetition": repetition,
            "adapter": {"name": adapter.name, "version": adapter.adapter_version},
            "versions": {"scaneval": __version__, "kind_mapping": mapping_version()},
            "status": result["status"], "exit_code": outcome.exit_code,
            "timed_out": bool(outcome.timed_out or outcome.status == "timeout"), "command": list(outcome.command),
            "started_at": started_at, "finished_at": finished_at, "wall_seconds": round(wall, 3),
            "timeout_seconds": timeout_seconds,
            "tool_versions": dict(outcome.tool_versions), "model_identity": outcome.model_identity,
            "system_config": dict(spec.config),
            "network_policy": ({"declared": network_policy, "enforced": True,
                                "note": "Enforced by the execution backend; see isolation.network."}
                               if network_enforced else
                               {"declared": network_policy, "enforced": False,
                                "note": "Policy is recorded, not enforced by this runner; enforce it in the execution environment."}),
            "environment": {"passthrough": _passthrough(adapter, isolation)},
            # One derivation for both: the capture mapping and the trace record cannot claim
            # different things about how completely this run was observed.
            "capture": _capture_record(dict(outcome.capture), outcome.capture_state, trace_record)[0],
            "trace": trace_record,
            "provenance": {"tree_hash": prepared.tree_hash, "provenance_sha256": provenance_digest,
                           "profile": prepared.profile, "synthetic_history": synthetic,
                           "source_modified": bool(modified), "modified_paths": modified[:200],
                           "captured_state_dirs": captured_state},
            "preparation": preparation, "unsupported_languages": unsupported,
            "error": result.get("error"), "import_error": import_error,
            # The runner's own notes outlive a discarded outcome: a link refused where harness
            # state belongs, and a workspace left on disk, are facts about this invocation
            # rather than anything the adapter reported.
            "notes": list(outcome.notes) + alias_notes + capture_notes + cleanup_notes,
            "raw_artifacts": raw_artifacts,
        }
        if record_2_1:
            execution["schema_version"] = "2.1"
            execution["provenance"].update({"input_hash": prepared.binding_hash, "mode": prepared.mode,
                                            "pr": prepared.pr, "blinding": prepared.blinding})
            execution["isolation"] = isolation
        execution, rendered_in_execution = _recordable_document(execution)
        if rendered_in_result + rendered_in_execution:
            # Appended after the rendering, so this sentence is itself plain ASCII and needs no
            # second pass. It is the record saying that a name in it is not the name on disk.
            execution["notes"].append(
                f"{rendered_in_result + rendered_in_execution} string(s) in this bundle hold "
                "bytes UTF-8 cannot encode and are recorded with backslash escapes; a path among "
                "them does not open under the name written here.")
        return result, execution

    def finished_documents() -> tuple[bytes, bytes]:
        """The exact bytes of both bundle documents, built, validated, and encoded together.

        Every way the documents can fail to be written is a :class:`_BundleRefused` naming it:
        anything raised while collecting or hashing declared artifacts, a scan result the
        contract refuses even as an explicit error record, an execution record the contract
        refuses, anything else raised while validating that record, and a document holding text
        UTF-8 cannot encode. Nothing is written until both documents survive all of it.
        """
        try:
            result, execution = build_documents()
        except _BundleRefused:
            raise
        except Exception as exc:
            raise _BundleRefused(
                f"the bundle documents could not be built: {_failure_message(exc)}") from exc
        try:
            validate_document("execution-record", execution)
        except ContractError as exc:
            raise _BundleRefused(f"execution record violates its contract: {exc}") from exc
        except Exception as exc:
            # Validating walks what the adapter supplied, so a cyclic capture or model_identity
            # mapping raises here rather than violating the contract. Contained the same way the
            # build step is, so no adapter-supplied mapping escapes as a crash of the run.
            raise _BundleRefused(
                f"the execution record could not be validated: {_failure_message(exc)}") from exc
        try:
            return _canonical_bytes(result), _canonical_bytes(execution)
        except ContractError as exc:
            raise _BundleRefused(f"the bundle documents could not be encoded: {exc}") from exc

    if violation is None and trace_dir is not None:
        try:
            trace_record = _read_trace(outcome, staged_areas, trace_dir, trace_mode, bundle_area)
        except (UnicodeDecodeError, OSError) as exc:
            # A trace this module cannot read as UTF-8 text is a recorded failure, not a
            # silently missing count beside an otherwise successful result.
            violation = f"trace file could not be read as UTF-8 text: {_failure_message(exc)}"

    if violation is None and modified and outcome.status in ("success", "partial"):
        # The scanner changed the tree it was given, so what it scanned is no longer the frozen
        # input the result binds to. Only a status that still carries claims is touched: an
        # error, a timeout, and an unsupported outcome already claim no observation at all.
        outcome.status = "partial"
        outcome.bundles_resolved = False
        outcome.notes.append(
            f"The exported source changed during the scan ({len(modified)} path(s): "
            f"{', '.join(modified[:3])}); this result is not a clean observation of "
            f"{prepared.tree_hash}.")
        # An outcome that already named its own failure keeps that code: the note above, the
        # partial status, and the provenance carry the changed condition.
        outcome.error = outcome.error or {
            "code": "source_modified",
            "message": (f"the scanner modified {len(modified)} path(s) of the exported source "
                        f"during the scan ({', '.join(modified[:3])}); the result is not a clean "
                        f"observation of the frozen input")[:2000]}

    # The same derivation the execution record's ``capture`` mapping comes from, so the status
    # and that mapping cannot say different things about how completely this run was observed.
    capture_break = (_capture_record(dict(outcome.capture), outcome.capture_state, trace_record)[1]
                     if violation is None else None)
    if capture_break and outcome.status in ("success", "partial"):
        # The run itself recorded that the observation of it broke, so the result must not read
        # as a clean complete one. Only the status changes: ``bundles_resolved`` is left as the
        # adapter reported it, because a dropped trace event is not a lost claim.
        outcome.status = "partial"
        outcome.notes.append(
            f"This run reports {capture_break}, so the trace is not a complete record of what "
            "the scanner did. The claims themselves are unaffected.")
        outcome.error = outcome.error or {
            "code": "trace_capture_gap",
            "message": (f"this run reports {capture_break}; this result is a complete claim "
                        f"set over an incomplete observation of the run")[:2000]}

    if violation is not None:
        outcome = _violation_outcome(violation)
        trace_record = _empty_trace(trace_mode) if trace_dir is not None else None
    try:
        result_bytes, execution_bytes = finished_documents()
    except _BundleRefused as refused:
        # The documents the outcome produced are not writable, so the outcome is discarded and
        # the refusal itself becomes the recorded failure; the result never stays a success.
        outcome = _violation_outcome(str(refused))
        trace_record = _empty_trace(trace_mode) if trace_dir is not None else None
        try:
            result_bytes, execution_bytes = finished_documents()
        except _BundleRefused as again:
            # Nothing the adapter supplied is left in these documents, so the refusal is about
            # the invocation itself; writing half a bundle would be worse than writing none.
            raise ExecutionError(f"the invocation could not be recorded: {again}") from again
    _write_new_documents([(bundle / "result.json", result_bytes),
                          (bundle / "execution.json", execution_bytes)])
    return bundle
