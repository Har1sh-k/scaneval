"""Adapter protocol for invoking one scanner on one prepared input.

An adapter runs the real product once, preserves its raw output, and translates the
native findings into normalized claims. It never receives labels, never decides whether
a claim is true, and never turns an execution failure into an empty successful scan.

Every scanner process an adapter starts goes through :func:`run_command`, and that is what lets
an execution backend hold it: while a backend is active (:func:`routed_through`, which the
backend's own ``activate()`` enters for the span of one scan), :func:`run_command` hands the
command to that backend instead of starting it on the host. With no backend active the command
runs locally exactly as it always has. A process an adapter starts any other way is outside every
backend, which is why only an adapter declaring :attr:`Adapter.oci_compatible` is run under one.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import os
from pathlib import Path
import signal
import stat
import subprocess
import threading
import time
from typing import Any, Iterator


STATUSES = ("success", "partial", "unsupported", "error", "timeout")
# Environment variables passed to scanner subprocesses unless an adapter adds more.
BASE_ENV_PASSTHROUGH = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "USER", "SHELL")

# The execution backend every scanner process in this context is routed through, or None, which
# runs it on the host. Set only by :func:`routed_through`.
_ACTIVE_BACKEND: ContextVar[Any] = ContextVar("scaneval_execution_backend", default=None)
# How many backends are routing commands anywhere in this process. A context variable does not
# follow a thread started inside the routed block, so a command started on such a thread finds no
# backend in its context; this count is what makes that a refusal rather than a process started
# on the host while the scan it belongs to is recorded as contained.
_ROUTING = 0
_ROUTING_LOCK = threading.Lock()


class AdapterError(RuntimeError):
    """The adapter could not be prepared or invoked as configured."""


@dataclass(frozen=True)
class SystemSpec:
    """One evaluated system configuration. ``config`` is recorded verbatim, so keep secrets out."""

    system_id: str
    adapter: str
    config: dict = field(default_factory=dict)
    model_id: str | None = None
    model_revision: str | None = None


@dataclass
class CommandResult:
    argv: list[str]
    exit_code: int | None
    timed_out: bool
    wall_seconds: float
    stdout_path: Path
    stderr_path: Path
    cleanup_succeeded: bool = True


@dataclass
class NativeOutcome:
    """Everything one invocation produced, before the runner writes the bundle.

    ``omitted_paths`` is what the adapter observed the scanner did not examine of its input: paths the
    scanner's own selection, filter, or limit left out, as the adapter saw them, in no particular
    order. ``None`` is an adapter that reports no omissions, which says nothing about whether there
    were any, and ``[]`` is one that looked and saw none. The runner records a list as the result's
    ``omitted_paths``, sorted and each path once, in a 2.1 result, and the scorer withholds quiet credit
    from a control on a listed path. A list is only as true as the adapter's observation, and it is
    meant for an outcome that carries claims the adapter read; it does not change ``status``, which
    stays the adapter's own account of how the run ended.

    ``examined_nothing`` is the adapter's statement about the whole input, beside that list: ``True``
    says it can show no part of the input to have been examined, and in a PR review that is every path
    the change touches being one the scanner is not shown to have read; ``False`` says it saw some
    examined; ``None`` says it does not report. The runner records a ``bool`` as the result's
    ``examined_nothing`` in a 2.1 result, and the scorer withholds quiet credit from every control of a
    result that says ``True``, wherever the plan places it, because a scan that read none of what it
    was given has reached no control. It is the adapter's claim like the list, and like the list it
    never changes ``status``.

    ``processing`` is the adapter's statement about the system it ran rather than about what the scan
    saw: ``"curated"`` says the system's configuration chose, before the run, which paths of the input
    are assigned the scanner's analysis, ``"full"`` says it chose none, and ``None`` says the adapter
    does not report it. The runner records a string as the result's ``processing`` in a 2.1 result,
    whose contract admits only those two values. It is the selection marker that aggregation, comparison
    and the benchmark score show beside the adapter version, and they refuse one that the system's
    configuration and recorded adapter version do not give. It changes no status, claim, or quiet
    credit.
    """

    status: str
    exit_code: int | None
    command: list[str]
    claims: list[dict] = field(default_factory=list)
    ranking: str = "unranked"
    bundles_resolved: bool = True
    artifacts: list[dict] = field(default_factory=list)  # {"id": ..., "path": Path}
    tool_versions: dict[str, str] = field(default_factory=dict)
    model_identity: dict | None = None
    usage: dict = field(default_factory=dict)
    error: dict | None = None
    capture: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    trace_path: Path | None = None
    capture_state: dict | None = None
    timed_out: bool = False
    omitted_paths: list[str] | None = None
    examined_nothing: bool | None = None
    processing: str | None = None

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise AdapterError(f"invalid outcome status {self.status!r}")


def build_env(extra_names: tuple[str, ...] = (), overrides: dict[str, str] | None = None) -> dict[str, str]:
    env = {name: os.environ[name] for name in (*BASE_ENV_PASSTHROUGH, *extra_names) if name in os.environ}
    env.update(overrides or {})
    return env


@contextmanager
def routed_through(backend: Any) -> Iterator[None]:
    """Hand every :func:`run_command` in this context to *backend* until the block exits.

    *backend* provides ``run_command`` with this module's signature and returns a
    :class:`CommandResult`. The routing follows the context, not the process: a thread started
    inside the block does not carry it. While any such block is open, a :func:`run_command` whose
    context carries no backend is therefore refused instead of run on the host, because the only
    way to reach that state during a routed scan is a command the backend would never see. The
    block does not start, stop, or clean up anything itself; that is the backend's job.
    """
    global _ROUTING
    token = _ACTIVE_BACKEND.set(backend)
    with _ROUTING_LOCK:
        _ROUTING += 1
    try:
        yield
    finally:
        with _ROUTING_LOCK:
            _ROUTING -= 1
        _ACTIVE_BACKEND.reset(token)


def active_backend() -> Any:
    """The backend :func:`run_command` hands commands to in this context, or ``None`` (the host)."""
    return _ACTIVE_BACKEND.get()


def _wait_for_unreaped_exit(pid: int, timeout_seconds: float) -> bool:
    """Observe *pid* exit without releasing its PID/process-group identity.

    ``waitpid`` (and :meth:`subprocess.Popen.wait`) reaps the leader. A later
    ``killpg(pid, ...)`` can then target an unrelated process group if the kernel
    recycles that numeric ID between the probe and signal. ``WNOWAIT`` leaves the
    exited leader waitable, so its PID and process-group ID cannot be recycled while
    the caller drains descendants.
    """
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    while True:
        try:
            event = os.waitid(os.P_PID, pid, flags)
        except InterruptedError:
            continue
        if event is not None:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _signal_reserved_process_group(pid: int, signal_to_send: int) -> bool:
    """Signal a group whose unreaped leader still reserves *pid*.

    Some supported kernels report ``EPERM`` for a group containing only an exited
    zombie leader. The definitive check is therefore the observation after the
    leader is reaped; this return value only controls the TERM grace period.
    """
    try:
        os.killpg(pid, signal_to_send)
    except OSError:
        return False
    return True


def _process_group_absent_after_reap(pid: int, timeout_seconds: float) -> bool:
    """Boundedly observe group disappearance after reaping, without signalling it."""
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        try:
            os.killpg(pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            # Permission denial or any other result is not proof of absence. It may
            # still clear as a killed descendant is reaped, so keep observing briefly.
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _feed_stdin_while_leader_is_unreaped(process: subprocess.Popen, data: bytes, deadline: float) -> bool:
    """Boundedly feed stdin without polling or reaping the process-group leader."""
    if process.stdin is None:
        return True
    descriptor = process.stdin.fileno()
    offset = 0
    try:
        os.set_blocking(descriptor, False)
        while offset < len(data):
            try:
                written = os.write(descriptor, data[offset:])
            except BlockingIOError:
                written = 0
            except BrokenPipeError:
                return True
            if written:
                offset += written
                continue
            try:
                event = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except InterruptedError:
                continue
            if event is not None:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))
        return True
    finally:
        process.stdin.close()


def run_command(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    env: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
    stdin_text: str | None = None,
    ensure_group_empty: bool = False,
) -> CommandResult:
    """Run one process with a hard timeout, streaming stdout/stderr to files.

    On timeout the whole process group is killed and ``timed_out`` is reported; the
    partial stdout/stderr files are kept as raw artifacts.

    Inside :func:`routed_through` the command goes to the active backend instead, with the same
    arguments, and what that backend returns is returned; the backend decides where the process
    runs and states its own guarantees. A command started outside every routed context while one
    is open elsewhere in the process, which is a thread the routed scan started, is refused with
    :class:`AdapterError` and never started. Everything below that applies only when no backend
    is involved, and it is the same code path this function has always had.
    """
    backend = _ACTIVE_BACKEND.get()
    if backend is not None:
        if ensure_group_empty:
            raise AdapterError("process-group emptiness checks are available only on the local execution seam")
        return backend.run_command(argv, cwd=cwd, timeout_seconds=timeout_seconds, env=env,
                                   stdout_path=stdout_path, stderr_path=stderr_path, stdin_text=stdin_text)
    if _ROUTING:
        raise AdapterError(
            f"could not start {argv[0] if argv else 'a command'}: an execution backend is holding a "
            "scan in this process and this command was started outside it, from a thread that does "
            "not carry the backend; it was not run on the host")
    if ensure_group_empty:
        waitid_names = ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT", "killpg")
        if any(not hasattr(os, name) for name in waitid_names):
            raise AdapterError("process-group emptiness checks require POSIX waitid(WNOWAIT) support")
    started = time.monotonic()
    with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
        try:
            process = subprocess.Popen(
                argv, cwd=str(cwd), env=env, stdout=out, stderr=err,
                stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            raise AdapterError(f"could not start {argv[0]}: {exc}") from exc
        timed_out = False
        cleanup_succeeded = True
        if ensure_group_empty:
            # Do not call poll(), communicate(), or wait() until the process group has been
            # drained: all three can reap the leader and free its numeric PGID for reuse.
            try:
                command_deadline = started + max(0.0, timeout_seconds)
                input_delivered = _feed_stdin_while_leader_is_unreaped(
                    process, stdin_text.encode("utf-8") if stdin_text is not None else b"", command_deadline)
                leader_exited = input_delivered and _wait_for_unreaped_exit(
                    process.pid, max(0.0, command_deadline - time.monotonic()))
                if not leader_exited:
                    timed_out = True
                    _signal_reserved_process_group(process.pid, signal.SIGKILL)
                    leader_exited = _wait_for_unreaped_exit(process.pid, 5)
                if not leader_exited:
                    raise AdapterError("scanner leader did not exit within bounded process-group cleanup")

                # The exited leader is deliberately still waitable here. Its PID/PGID therefore
                # cannot be recycled between either signal and the eventual reap.
                if _signal_reserved_process_group(process.pid, signal.SIGTERM):
                    time.sleep(0.25)
                _signal_reserved_process_group(process.pid, signal.SIGKILL)
            except ChildProcessError as exc:
                # An unexpected external waiter has already freed the group identity. Never
                # signal that numeric PGID after this point.
                raise AdapterError("scanner leader was reaped before process-group cleanup") from exc
            except BaseException as original:
                # The code above has not reaped the leader, so these group signals cannot hit a
                # recycled PGID. Preserve the triggering exception after bounded best-effort
                # termination and reaping.
                group_stopped = False
                for _ in range(3):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        group_stopped = True
                        break
                    except ProcessLookupError:
                        group_stopped = True
                        break
                    except BaseException:
                        pass
                if not group_stopped:
                    try:
                        original.add_note("scanner process-group cleanup failed after three attempts")
                    except BaseException:
                        pass
                    try:
                        process.kill()
                    except BaseException:
                        pass
                try:
                    exited_for_reap = _wait_for_unreaped_exit(process.pid, 5)
                except BaseException:
                    exited_for_reap = False
                if exited_for_reap:
                    deadline = time.monotonic() + 5
                    for _ in range(3):
                        try:
                            process.wait(timeout=max(0, deadline - time.monotonic()))
                            break
                        except BaseException:
                            pass
                if process.returncode is None:
                    try:
                        original.add_note("scanner could not be reaped within bounded cleanup attempts")
                    except BaseException:
                        pass
                raise

            # From this point onward the implementation may reap and observe, but must never
            # signal the numeric PGID again. A surviving group makes the command non-success.
            process.wait(timeout=5)
            cleanup_succeeded = _process_group_absent_after_reap(process.pid, 1.0)
        else:
            try:
                process.communicate(input=stdin_text.encode("utf-8") if stdin_text is not None else None,
                                    timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            except BaseException as original:
                # Retry interrupted cleanup without replacing the triggering exception. The
                # attempts and total wait are bounded even if another signal handler raises.
                group_stopped = False
                for _ in range(3):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        group_stopped = True
                        break
                    except ProcessLookupError:
                        group_stopped = True
                        break
                    except BaseException:
                        pass
                if not group_stopped:
                    try:
                        original.add_note("scanner process-group cleanup failed after three attempts")
                    except BaseException:
                        pass
                    # A group operation can fail independently of direct-child termination.
                    try:
                        process.kill()
                    except BaseException:
                        pass
                deadline = time.monotonic() + 5
                reaped = False
                for _ in range(3):
                    try:
                        process.wait(timeout=max(0, deadline - time.monotonic()))
                        reaped = True
                        break
                    except BaseException:
                        pass
                if not reaped:
                    try:
                        original.add_note("scanner could not be reaped within bounded cleanup attempts")
                    except BaseException:
                        pass
                if process.stdin is not None:
                    try:
                        process.stdin.close()
                    except BaseException:
                        pass
                raise
    wall = time.monotonic() - started
    return CommandResult(list(argv), None if timed_out else process.returncode, timed_out, wall,
                         stdout_path, stderr_path, cleanup_succeeded)


def tail_text(path: Path, limit: int = 2000) -> str:
    """The last *limit* bytes of *path* as text, or ``""`` when it cannot be read. Never raises.

    The file is one a scanner wrote, and the scanner can replace it after its own descriptor
    closed, so it is read the way :func:`~scaneval.execution.read_regular_file` reads:
    ``O_NOFOLLOW`` refuses a symbolic link, ``O_NONBLOCK`` makes a named pipe fail at once instead
    of waiting for a writer that never comes, and :func:`os.fstat` on the descriptor refuses
    anything that is not a regular file. The read seeks to the last *limit* bytes, so the size of
    the file does not decide how much memory this takes. A regular file gives exactly the text it
    always gave. What changed is that a link planted where stderr belongs is no longer followed to
    a file of the scanner's choosing, whose tail every failure message would then have quoted into
    the record; under an isolating backend that was a host file carried across the boundary.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return ""
    try:
        with os.fdopen(descriptor, "rb") as stream:
            status = os.fstat(stream.fileno())
            if not stat.S_ISREG(status.st_mode):
                return ""
            if status.st_size > limit:
                stream.seek(status.st_size - limit)
            return stream.read(limit).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


class Adapter(ABC):
    """Invoke one system once on one prepared input and normalize its native output."""

    name: str = "abstract"
    adapter_version: str = "0.0.0"
    requires_git: bool = False
    supported_languages: frozenset[str] = frozenset()
    # The scan modes this adapter carries out: ``full`` scans the whole exported tree, ``pr`` reviews
    # the change between the base and head commits its request names. The runner never calls scan()
    # for an input whose mode is not listed: it records the invocation as unsupported, which stays in
    # every denominator, and a full scan of the head is never run in place of a PR review. An adapter
    # declaring ``pr`` promises to read ``request["input"]["pr"]`` and to review that change, and to
    # refuse a request it cannot honour rather than scan something else.
    scan_modes: frozenset[str] = frozenset({"full"})
    env_passthrough: tuple[str, ...] = ()
    # Top-level scanner-owned paths excluded from the immutable input comparison.  By default the
    # runner also copies each one under raw/harness-state.  An adapter that independently performs a
    # bounded, no-follow evidence import may set ``state_capture_dirs`` to a subset (including the
    # empty tuple) so the generic unbounded tree copy cannot replace its already-preserved outcome.
    state_dirs: tuple[str, ...] = ()
    state_capture_dirs: tuple[str, ...] | None = None
    # Whether this adapter may run under the ``oci`` execution backend. True is three promises:
    # every scanner process it starts goes through :func:`run_command` from the thread that called
    # ``scan()``; its scanner exists in a Linux image and it takes the in-image tool when a backend
    # is active; and every host-side read of what a command wrote goes through
    # :func:`~scaneval.execution.read_regular_file` or :func:`tail_text`, because a container can
    # replace any path under its writable mounts with a link to a host file, and a read that
    # followed it would carry that file across the boundary. An adapter that shells out any other
    # way, whose tools exist only as host installs, or whose reads follow links would run partly
    # outside the boundary, so the default is False and the runner refuses such a system under
    # ``oci`` with a recorded reason instead of running it.
    oci_compatible: bool = False

    def condition_controls(self, spec: SystemSpec, preparation: dict) -> dict[str, Any]:
        """Machine-readable retrieval controls applied by this adapter, recorded beside the run.

        The default supplies no evidence. An implementation describes actual adapter controls,
        not the operator's policy or a scanner's self-report. ``inference`` is ``offline`` or
        ``remote``; ``tools`` maps browser, web_search, remote_fetch, package_install, and
        scanner_update to disabled/enabled/unknown. Provider capability, the requested control,
        and an applicable provider attestation remain separate in ``provider``. Artifact paths
        in an attestation are bundle-relative and must name saved bytes.
        """
        return {}

    def prepare(self, spec: SystemSpec, cache_root: Path) -> dict[str, Any]:
        """Separately recorded preparation phase (rulesets, dependencies). Default: nothing."""
        return {}

    def runtime_mounts(self, spec: SystemSpec, preparation: dict) -> tuple[str, ...]:
        """Host paths the scanner reads at run time besides its workspace. Default: none.

        An isolating backend mounts each of them read-only at its own path, so a path the adapter
        hands its scanner means the same file inside the boundary as outside it. Only what the
        scan needs belongs here, and never a directory holding evaluator material: whatever is
        listed becomes readable to the scanner.
        """
        return ()

    @abstractmethod
    def scan(
        self,
        *,
        request: dict,
        source_dir: Path,
        raw_dir: Path,
        spec: SystemSpec,
        preparation: dict,
        timeout_seconds: float,
        trace_mode: str,
        trace_dir: Path | None,
    ) -> NativeOutcome:
        """Run the system once. Must preserve raw output and report an explicit status."""
