"""The ``oci`` execution backend: each scanner process in a fresh, locked-down Docker container.

For one invocation this backend

- checks, before any scanner process starts, that the engine answers, that the pinned image is
  present (it never pulls one), that every path it will mount is visible to the daemon, and,
  under ``model_provider_only``, that the scan network really has no gateway;
- runs each command the adapter issues as a container of its own: created with ``docker create``
  under a unique name and this run's labels, started with ``docker start -a`` under the
  command's timeout, killed by name on a timeout or any failure (killing the docker client does
  not stop a container), inspected for its exit code and ``OOMKilled``, and removed by name;
- gives every container the same settings: read-only root filesystem, every capability dropped,
  ``no-new-privileges``, a non-root user, no IPC namespace, an init process, pids, memory (with
  swap equal to it so nothing is swapped), CPU, core-dump, and open-file limits, a size-limited
  ``noexec`` tmpfs at ``/tmp`` that is also ``HOME``, the image's own ``PATH``, and an environment
  reduced to an allowlist plus the declared credentials, which are passed by name so a value is
  never on a command line and never in a record;
- mounts only what the scan needs, each at its own path: the workspace source read-only, the
  adapter's declared state directories inside it writable, the staged raw output and trace
  writable, and the adapter's declared runtime paths read-only, each strictly inside the source
  cache and holding no socket; never the operator's home, the source cache as a whole, the run
  directory, the Docker socket, or a directory above any of them, and never with ``-v``, whose
  missing source becomes a silently empty directory;
- enforces the network policy: ``none`` is no interface but loopback; ``model_provider_only`` is
  an internal network made for this invocation whose bridge carries no address, verified by
  inspecting it because the engine accepts options it does not apply, plus a dual-homed proxy
  container (:mod:`scaneval.isolation.egress_proxy`) that forwards ``CONNECT`` only to the
  declared host:port pairs and logs each decision; ``unrestricted`` is a plain bridge network and
  is recorded as not enforced;
- tears down every container and network it created when the scan ends, and records what it
  could not remove.

What it does not do. It trusts the engine, its kernel, and the image, none of which it verifies
beyond the image's digest. It does not bound what a scanner writes through a writable mount: the
engine applies no quota to a bind mount, so raw output is limited by the host disk alone. It does
not change the engine's seccomp or AppArmor profiles, which are recorded as found. It proves that
the daemon can see each mount source, not that what it sees is the host's directory: an engine
running in a virtual machine that holds its own directory at the same path mounts that one. It
cannot clean up after a ScanEval process that is itself killed; what that leaves on the engine
carries the ``scaneval.backend=oci`` label and this run's id. And it does not make ScanEval's own
reads of the staged output after the scan trusted or bounded; those still go through
:mod:`scaneval.execution`, which treats that output as untrusted, but by then every container of
the scan has been removed, so no scanner process is alive to race them. The full statement is in
``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any, Callable, Iterator
import uuid

from ..adapters.base import CommandResult, routed_through
from . import PINNED_IMAGE, ExecutionSettings, IsolationError, Limits


# Seconds a docker control command (version, inspect, create, rm, network) may take before the
# backend gives up on the engine, and seconds the docker client gets to exit once its container
# has been killed.
CONTROL_TIMEOUT = 120.0
KILL_GRACE = 10.0
PROXY_PORT = 3128
PROXY_READY_SECONDS = 30.0
# The egress log is written by this package's own proxy, but its lines name destinations the
# scanner chose, so it is read with a ceiling.
PROXY_LOG_LIMIT = 16 * 1024 * 1024
DESTINATIONS_RECORDED = 20
# The variables whose values a container takes from the environment the adapter built. HOME and
# TMPDIR are the container's own /tmp, PATH is the image's, and everything else the adapter set,
# the operator's USER and SHELL among it, is dropped and named in the record.
CONTAINER_ENV_ALLOWLIST = ("LANG", "LC_ALL", "TERM")
# What the docker client itself is given: where the engine is, and nothing a scanner declared.
_CLIENT_ENV = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH",
               "DOCKER_TLS_VERIFY", "DOCKER_API_VERSION", "XDG_RUNTIME_DIR")
_DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
_PROXY_LIMITS = Limits(memory_mb=256, cpus=1.0, pids=64, tmpfs_mb=16, nofile=1024)
_ISOLATED_GATEWAY = "com.docker.network.bridge.gateway_mode_ipv4"
# The start time the engine reports for a container that never started, the zero time of Go.
_NEVER_STARTED = "0001-01-01T00:00:00"
_TRIAL_PREFIX = "scaneval-trial-"
_STATE_NAME = re.compile(r"^[^/\x00]+$")

ENFORCED_NOTE = (
    "Each scanner process ran in a container created for it alone and removed after it: read-only "
    "root filesystem, every capability dropped, no new privileges, the non-root user in settings, "
    "pids, memory, and CPU limits, only the mounts listed, and the network recorded under network. "
    "The engine, its kernel, and the image are trusted rather than verified; see "
    "docs/THREAT_MODEL.md.")
NOTHING_RAN_NOTE = "No scanner process was started under the oci backend, so nothing was enforced."
UNRESTRICTED_NOTE = (
    "Not restricted. The container sits on a plain bridge network made for this invocation and can "
    "reach the internet, and on Colima and Docker Desktop also services bound to the host's own "
    "loopback through the host gateway (host.docker.internal; 192.168.5.2 on Colima).")


def _home_relative(text: str) -> str:
    """*text* with a leading home directory spelled ``~``, so a record never names the account."""
    home = str(Path.home())
    if home and home != os.sep and (text == home or text.startswith(home + os.sep)):
        return "~" + text[len(home):]
    return text


def _scrub_home(text: str) -> str:
    """*text* with every mention of the home directory spelled ``~``, for messages that quote paths."""
    home = str(Path.home())
    if not home or home == os.sep:
        return text
    return re.sub(re.escape(home) + r"(?![A-Za-z0-9._-])", "~", text)


def _tail(text: str, limit: int = 600) -> str:
    """The last *limit* characters of a docker message, one line, home directory spelled ``~``."""
    flat = " ".join(text.split())
    return _scrub_home(flat[-limit:]) if flat else "no message"


def _csv_field(value: str) -> str:
    """One field of a ``--mount`` value, which docker parses as CSV, quoted when it must be."""
    return '"' + value.replace('"', '""') + '"' if ("," in value or '"' in value) else value


def _client_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {name: os.environ[name] for name in _CLIENT_ENV if name in os.environ}
    env.update(extra or {})
    return env


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


@dataclass(frozen=True)
class DockerResult:
    returncode: int
    stdout: str
    stderr: str


class DockerClient:
    """The docker CLI, and the only way this module reaches the engine.

    ``run`` is for control commands, whose output is small; ``attach`` is for ``docker start -a``,
    whose output is the scanner's and streams into the files the adapter named. The client is
    given only the variables that say where the engine is (:data:`_CLIENT_ENV`), plus, for one
    ``docker create``, the credential values its ``--env NAME`` arguments read.
    """

    def __init__(self, binary: str | None = None) -> None:
        self.binary = binary or shutil.which("docker")

    def _argv(self, args: list[str]) -> list[str]:
        if not self.binary:
            raise IsolationError("the docker CLI is not installed or not on PATH, so the oci backend "
                                 "cannot reach an engine")
        return [self.binary, *args]

    def run(self, args: list[str], *, timeout: float, extra_env: dict[str, str] | None = None) -> DockerResult:
        try:
            completed = subprocess.run(self._argv(args), stdin=subprocess.DEVNULL, capture_output=True,
                                       env=_client_env(extra_env), timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise IsolationError(f"docker {args[0]} gave no answer within {timeout:g}s") from exc
        except OSError as exc:
            raise IsolationError(f"the docker CLI could not be started: {exc}") from exc
        return DockerResult(completed.returncode, completed.stdout.decode("utf-8", "replace"),
                            completed.stderr.decode("utf-8", "replace"))

    def attach(self, args: list[str], *, stdout_path: Path, stderr_path: Path, stdin_text: str | None,
               timeout: float, on_timeout: Callable[[], None]) -> tuple[int | None, bool]:
        """Run ``docker start -a`` into the two files; ``(client exit code, timed out)``.

        The files are created or truncated as :func:`~scaneval.adapters.base.run_command` does,
        and an output path that cannot be opened raises :class:`OSError` as it would locally, with
        one difference that matters here: they are opened by :func:`_open_output`, which refuses a
        link, a pipe, and a second name for another file. An earlier container of the same scan had
        these directories mounted writable and may have left any of those at the path; the local
        runner's plain open would have written this command's output through it into a host file
        of that container's choosing. On timeout *on_timeout* runs first, which kills the container
        by name; the client then ends on its own, and is killed with its process group only if it
        does not within :data:`KILL_GRACE` seconds. Any other interruption kills the client and
        re-raises; the caller removes the container.
        """
        argv = self._argv(args)
        out_descriptor = _open_output(Path(stdout_path))
        try:
            err_descriptor = _open_output(Path(stderr_path))
        except BaseException:
            os.close(out_descriptor)
            raise
        with os.fdopen(out_descriptor, "wb") as out, os.fdopen(err_descriptor, "wb") as err:
            try:
                process = subprocess.Popen(
                    argv, stdout=out, stderr=err, env=_client_env(),
                    stdin=subprocess.PIPE if stdin_text is not None else subprocess.DEVNULL,
                    start_new_session=True)
            except OSError as exc:
                raise IsolationError(f"the docker CLI could not be started: {exc}") from exc
            payload = stdin_text.encode("utf-8") if stdin_text is not None else None
            try:
                process.communicate(input=payload, timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    on_timeout()
                finally:
                    try:
                        process.communicate(timeout=KILL_GRACE)
                    except subprocess.TimeoutExpired:
                        _kill_group(process)
                        process.communicate()
                return None, True
            except BaseException:
                _kill_group(process)
                process.wait()
                raise
        return process.returncode, False


@dataclass(frozen=True)
class _Mount:
    """One bind mount at its own path. ``role`` says why it exists; ``mode`` is ``ro`` or ``rw``."""

    path: str
    mode: str
    role: str

    def argument(self) -> str:
        fields = ["type=bind", f"src={self.path}", f"dst={self.path}"]
        if self.mode == "ro":
            fields.append("readonly")
        return ",".join(_csv_field(field) for field in fields)

    def record(self) -> dict:
        return {"target": _home_relative(self.path), "mode": self.mode, "role": self.role}


def _hardening(limits: Limits, user: str) -> list[str]:
    """The settings every container of this backend gets, worker and proxy alike."""
    return ["--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", user,
            "--ipc", "none", "--init", "--pids-limit", str(limits.pids),
            "--memory", f"{limits.memory_mb}m", "--memory-swap", f"{limits.memory_mb}m",
            "--cpus", format(limits.cpus, "g"), "--ulimit", "core=0:0",
            "--ulimit", f"nofile={limits.nofile}:{limits.nofile}",
            "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size={limits.tmpfs_mb}m,mode=1777"]


def _open_output(path: Path) -> int:
    """A descriptor that writes *path* from its start, refusing anything a container could plant there.

    Created with the process's umask when missing, as ``open(path, "wb")`` would be. When
    something is already there it must be a regular file with exactly one name: ``O_NOFOLLOW``
    refuses a symbolic link, ``O_NONBLOCK`` makes a named pipe fail at once instead of waiting
    for a reader, and :func:`os.fstat` on the descriptor refuses anything else, and a file with a
    second name, before a byte of it is truncated. Raises :class:`OSError`.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), 0o666)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise OSError(errno.EINVAL, "not a regular file, so no command output is written to it", str(path))
        if status.st_nlink != 1:
            raise OSError(errno.EMLINK, "a file with another name, so no command output is written to it",
                          str(path))
        os.ftruncate(descriptor, 0)
        os.set_blocking(descriptor, True)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _read_bounded(path: Path, limit: int) -> bytes:
    """The bytes of a regular file of at most *limit* bytes, read without following a link."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise OSError(errno.EINVAL, "not a regular file", str(path))
        if status.st_size > limit:
            raise OSError(errno.EFBIG, f"larger than {limit} bytes", str(path))
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read(limit + 1)[:limit]
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _inside(path: str, base: str) -> bool:
    return PurePosixPath(path) == PurePosixPath(base) or PurePosixPath(path).is_relative_to(PurePosixPath(base))


class OciBackend:
    """Runs every command of one invocation's scan in its own container, and records how.

    Build one per invocation (:func:`scaneval.isolation.backend_for` does), create the
    invocation's workspace inside :attr:`workspace_root`, activate it around the scan, read
    :meth:`isolation_record` afterwards, and call :meth:`close` whatever happened. The constructor
    creates the private scratch directory and touches no engine; everything that talks to the
    engine happens inside :meth:`activate`, :meth:`run_command`, and :meth:`close`.

    *protected* names host directories no mount may equal, sit inside, or contain (the run's
    output directory, which holds the evaluator's labels); *runtime_roots* names the directories
    an adapter-declared runtime path must sit strictly inside (the source cache, from which one
    pinned checkout may be mounted but never the cache itself), and with none named no runtime
    path is mounted at all; *proxy_network* names an existing network the egress proxy uses in
    place of the bridge it would otherwise create, for an endpoint served on a local network;
    *labels* are added to every container and network; *docker* replaces the engine client.
    """

    name = "oci"

    def __init__(self, settings: ExecutionSettings, *, run_id: str, invocation_id: str,
                 scratch_root: Path | None, state_dirs: tuple[str, ...] = (),
                 runtime_mounts: Callable[[], Any] | None = None,
                 protected: tuple[Path, ...] = (), runtime_roots: tuple[Path, ...] = (),
                 proxy_network: str | None = None, labels: dict[str, str] | None = None,
                 docker: Any = None) -> None:
        if settings.backend != "oci":
            raise IsolationError(f"OciBackend runs the oci backend, not {settings.backend!r}")
        self.settings = settings
        self.run_id = run_id
        self.invocation_id = invocation_id
        self._docker = docker if docker is not None else DockerClient()
        self._session = uuid.uuid4().hex[:12]
        self._labels = {**(labels or {}), "scaneval.backend": "oci", "scaneval.session": self._session,
                        "scaneval.run": run_id, "scaneval.invocation": invocation_id}
        self._state_dirs = tuple(state_dirs)
        self._declared = runtime_mounts or (lambda: ())
        self._protected = tuple(Path(path) for path in protected)
        self._runtime_roots = tuple(Path(path) for path in runtime_roots)
        self._proxy_network = proxy_network
        root = Path(scratch_root) if scratch_root is not None else Path(tempfile.gettempdir())
        self._private = Path(tempfile.mkdtemp(prefix="scaneval-oci-", dir=str(root)))
        self.workspace_root = self._private / "work"
        self.workspace_root.mkdir()
        self._activated = False
        self._active = False
        self._refusal: str | None = None
        self._runtime: dict = {}
        self._image: dict = {"reference": settings.image}
        self._proxy_image: dict | None = ({"reference": settings.proxy_image}
                                          if settings.network_policy == "model_provider_only" else None)
        self._mounts: list[_Mount] = []
        self._network_args = ["--network", "none"]
        self._network: dict = {"policy": settings.network_policy, "enforced": False, "mode": "not set up"}
        self._proxy: dict | None = None
        self._proxy_env: dict[str, str] = {}
        self._networks: list[dict] = []
        self._containers: list[dict] = []
        self._environment = {"set": [], "credentials": [], "dropped": set()}
        self._touched = False
        self._counter = 0

    # --- the interface run_invocation relies on --------------------------------------------

    @property
    def network_enforced(self) -> bool:
        """True only when a container ran and the policy was one this backend enforces."""
        return self._ran() and self.settings.network_policy in ("none", "model_provider_only")

    @contextmanager
    def activate(self) -> Iterator["OciBackend"]:
        """Preflight, set up the network, route the scan's commands here, and tear down after.

        A preflight that fails raises :class:`IsolationError` naming the refusal, after removing
        whatever it had created, and the refusal becomes the record's note. Nothing is ever run on
        the host instead. A backend is activated once.
        """
        if self._activated:
            raise IsolationError("an oci backend holds one scan; this one was already activated")
        self._activated = True
        try:
            self._preflight()
        except BaseException as exc:
            self._refusal = _scrub_home(str(exc) or type(exc).__name__)
            self._teardown()
            if isinstance(exc, IsolationError) or not isinstance(exc, Exception):
                raise
            raise IsolationError(f"the oci backend could not prepare the scan: {type(exc).__name__}: "
                                 f"{self._refusal}") from exc
        self._active = True
        try:
            with routed_through(self):
                yield self
        finally:
            self._active = False
            self._teardown()

    def run_command(self, argv: list[str], *, cwd: Path, timeout_seconds: float, env: dict[str, str],
                    stdout_path: Path, stderr_path: Path, stdin_text: str | None = None) -> CommandResult:
        """Run *argv* as its own container and return what the local runner would have returned.

        The container's working directory is *cwd*, which must be one of the mounted paths or
        inside one. ``argv[0]`` becomes the entrypoint, so the image's own entrypoint never
        wraps the command. The exit code is the container's, read by inspection after it stopped;
        a timeout kills the container, reports ``timed_out`` with no exit code, and keeps the
        partial output, as the local runner does. However the command ends, the container is
        killed if it still runs, inspected, and only then removed by name, so its exit code and
        ``OOMKilled`` are read before they are gone.

        Three outcomes raise :class:`IsolationError` rather than return, each because the command
        did not run as a command the adapter could read the result of: a container the engine
        refuses to create (a mount it cannot see, say), one it created but could not start (an
        entrypoint the image does not hold, say), which is what the local runner reports as a
        process it could not start, and one whose final state cannot be read, where whether it
        ran at all is unknown. A fourth is a container that exited 0 while recording an
        out-of-memory kill: some process of the scan was killed under the memory limit while the
        command reported success, so its output is not a complete observation, and a clean exit
        code must not say that it is.
        """
        if not self._active:
            raise IsolationError("the oci backend is not holding a scan, so it runs no command")
        words = self._words(argv)
        workdir = self._workdir(cwd)
        for output in (stdout_path, stderr_path):
            self._check_output(Path(output))
        environment, credential_names, credential_env = self._environment_for(env)
        interactive = stdin_text is not None
        self._counter += 1
        name = f"scaneval-{self._session}-w{self._counter}"
        shown = _home_relative(words[0])
        args = ["create", "--name", name, *self._label_args("worker"), "--pull", "never",
                *(["--interactive"] if interactive else []),
                *_hardening(self.settings.limits, self.settings.user), *self._network_args,
                "--workdir", workdir,
                *[word for key in sorted(environment) for word in ("--env", f"{key}={environment[key]}")],
                *[word for key in credential_names for word in ("--env", key)],
                *[word for mount in self._mounts for word in ("--mount", mount.argument())],
                "--entrypoint", words[0], self.settings.image, *words[1:]]
        record = {"name": name, "role": "worker", "command": shown, "created": False,
                  "started": False, "exit_code": None, "oom_killed": None, "timed_out": False,
                  "removed": False, "status": None, "error": None, "wall_seconds": None}
        self._containers.append(record)
        wall = 0.0
        timed_out = False
        client_code: int | None = None
        settled = False
        # Marked before the create is sent: a create the client gave up waiting for may still have
        # made the container, and close() sweeps only a backend that says it touched the engine.
        self._touched = True
        try:
            created = self._docker.run(args, timeout=CONTROL_TIMEOUT, extra_env=credential_env)
            if created.returncode != 0:
                message = (f"the engine refused to create the container for {shown}, so the command was "
                           f"not run: {_tail(created.stderr)}")
                record["error"] = message
                raise IsolationError(message)
            record["created"] = True
            started = time.monotonic()
            try:
                client_code, timed_out = self._docker.attach(
                    ["start", "--attach", *(["--interactive"] if interactive else []), name],
                    stdout_path=stdout_path, stderr_path=stderr_path, stdin_text=stdin_text,
                    timeout=timeout_seconds, on_timeout=lambda: self._kill(name))
            finally:
                wall = time.monotonic() - started
                # Whatever ended the attach, a timeout, an error, or the client returning while the
                # container still runs, the container is stopped here and its state read before
                # anything reads what it wrote, so no process of the scan outlives the command.
                settled = self._settle(name, record)
        finally:
            record["removed"] = self._remove_container(name)
            record["wall_seconds"] = round(wall, 3)
        record["timed_out"] = timed_out
        if not settled:
            raise IsolationError(f"the final state of the container for {shown} could not be read from the "
                                 "engine, so whether the command ran is unknown; it is not reported as a run")
        if not record["started"]:
            raise IsolationError(f"the engine could not start the container for {shown}, so the command was not "
                                 f"run: {record['error'] or 'the engine gave no reason'}")
        exit_code = None if timed_out else (record["exit_code"] if record["exit_code"] is not None else client_code)
        if exit_code == 0 and record["oom_killed"]:
            raise IsolationError(
                f"the container for {shown} exited 0 but recorded an out-of-memory kill under the "
                f"{self.settings.limits.memory_mb} MB limit, so a process of the scan was killed while the "
                "command reported success; its output is not a complete observation")
        return CommandResult(list(words), exit_code, timed_out, wall, Path(stdout_path), Path(stderr_path))

    def _settle(self, name: str, record: dict) -> bool:
        """Kill *name* if it still runs and record its final state; whether the state was read.

        ``started`` is recorded from the engine's own start time rather than inferred from the
        client returning: a container whose start failed stays ``created`` with a zero start time
        and an exit code of its own, and counting it as run would record a scan nothing executed
        as enforced. Never raises; a failure to reach the engine is recorded as the error.
        """
        try:
            state = self._state(name)
            if state is not None and state.get("Running"):
                self._kill(name)
                state = self._state(name)
        except Exception as exc:
            record["error"] = record["error"] or _scrub_home(str(exc))
            return False
        if state is None:
            return False
        code = state.get("ExitCode")
        started_at = state.get("StartedAt")
        record.update(status=state.get("Status") if isinstance(state.get("Status"), str) else None,
                      started=isinstance(started_at, str) and bool(started_at)
                      and not started_at.startswith(_NEVER_STARTED),
                      oom_killed=state.get("OOMKilled") is True,
                      exit_code=code if isinstance(code, int) and not isinstance(code, bool) else None,
                      error=record["error"] or (_tail(state["Error"]) if state.get("Error") else None))
        return True

    def isolation_record(self) -> dict:
        """The 2.1 isolation block: what bounded this invocation's scanner processes, as it happened.

        ``enforced`` is true only when at least one scanner container ran; every command either
        ran inside a container under the recorded settings or did not run at all, so a refused or
        empty scan is recorded as nothing enforced, never as enforced over nothing. Home paths are
        spelled ``~`` and no credential value appears anywhere in the block.
        """
        ran = self._ran()
        if self._refusal is not None:
            note = ("No scanner process ran: the oci backend refused this invocation before starting "
                    f"one. {self._refusal}")
        elif not ran:
            note = NOTHING_RAN_NOTE
        else:
            note = ENFORCED_NOTE
            starved = [c["name"] for c in self._containers if c["role"] == "worker" and c["oom_killed"]]
            if starved:
                note += (f" {len(starved)} scanner container(s) recorded an out-of-memory kill under the "
                         f"{self.settings.limits.memory_mb} MB limit: {', '.join(starved)}.")
            stranded = [c["name"] for c in self._containers if c["created"] and not c["removed"]]
            if stranded:
                note += f" {len(stranded)} container(s) could not be removed afterwards: {', '.join(stranded)}."
        network = dict(self._network)
        network["enforced"] = ran and self.settings.network_policy in ("none", "model_provider_only")
        if self._networks:
            network["networks"] = [dict(item) for item in self._networks]
        if self._proxy is not None:
            network["proxy"] = {key: value for key, value in self._proxy.items() if key != "log_dir"}
        image = dict(self._image)
        if self._proxy_image is not None:
            image["proxy"] = dict(self._proxy_image)
        mounts = [mount.record() for mount in self._mounts]
        if mounts:
            mounts.append({"target": "/tmp", "mode": "tmpfs", "role": "scratch"})
        return {"backend": "oci", "enforced": ran, "note": note, "runtime": dict(self._runtime),
                "image": image, "settings": self._settings_record(), "mounts": mounts,
                "network": network, "containers": [dict(item) for item in self._containers]}

    def close(self) -> list[str]:
        """Remove everything this backend created; return what could not be removed. Never raises.

        Every container and network carrying this backend's session label is removed, whatever
        state it is in, and then the private scratch directory. A message names each thing still
        there afterwards, with the home directory spelled ``~``, for the caller to record.
        """
        problems: list[str] = []
        if self._touched:
            for kind, listing, remove in (
                    ("container", ["ps", "--all", "--quiet", "--filter", f"label=scaneval.session={self._session}"],
                     lambda ident: ["rm", "--force", ident]),
                    ("network", ["network", "ls", "--quiet", "--filter", f"label=scaneval.session={self._session}"],
                     lambda ident: ["network", "rm", ident])):
                try:
                    found = self._docker.run(listing, timeout=CONTROL_TIMEOUT)
                    for ident in found.stdout.split():
                        self._docker.run(remove(ident), timeout=CONTROL_TIMEOUT)
                    left = self._docker.run(listing, timeout=CONTROL_TIMEOUT)
                    if left.returncode != 0:
                        problems.append(f"the {kind}s of oci session {self._session} could not be listed "
                                        f"after removal: {_tail(left.stderr)}")
                    elif left.stdout.split():
                        problems.append(f"{len(left.stdout.split())} {kind}(s) of oci session "
                                        f"{self._session} could not be removed")
                except Exception as exc:
                    problems.append(f"the {kind}s of oci session {self._session} could not be removed: "
                                    f"{_scrub_home(str(exc))}")
        try:
            _remove_tree(self._private)
        except Exception as exc:
            problems.append(f"the oci backend's scratch directory could not be removed and is still on "
                            f"disk at {_home_relative(str(self._private))}: {_scrub_home(str(exc))}")
        return problems

    # --- preflight ------------------------------------------------------------------------

    def _preflight(self) -> None:
        self._runtime = self._engine()
        self._image = self._image_identity(self.settings.image, "image")
        if self.settings.network_policy == "model_provider_only":
            self._proxy_image = self._image_identity(self.settings.proxy_image, "proxy image")
        self._mounts = self._plan_mounts()
        self._check_mounts_visible()
        self._prepare_network()

    def _engine(self) -> dict:
        """Versions and settings of the engine that will run the scan, or a refusal."""
        version = self._docker.run(["version", "--format", "{{json .}}"], timeout=CONTROL_TIMEOUT)
        if version.returncode != 0:
            raise IsolationError(f"the Docker engine is not reachable, so nothing was run: {_tail(version.stderr)}")
        info = self._docker.run(["info", "--format", "{{json .}}"], timeout=CONTROL_TIMEOUT)
        if info.returncode != 0:
            raise IsolationError(f"the Docker engine did not describe itself, so nothing was run: {_tail(info.stderr)}")
        try:
            reported, described = json.loads(version.stdout), json.loads(info.stdout)
            server, client = reported["Server"], reported["Client"]
            if not isinstance(server, dict) or not isinstance(client, dict) or not isinstance(described, dict):
                raise TypeError("the report has no server section")
        except (ValueError, KeyError, TypeError) as exc:
            raise IsolationError(f"the Docker engine's version report could not be read: {exc}") from exc

        def text(value: Any) -> str | None:
            return value if isinstance(value, str) else None

        security = [item for item in described.get("SecurityOptions") or [] if isinstance(item, str)]
        components = {item.get("Name"): item.get("Version") for item in server.get("Components") or []
                      if isinstance(item, dict)}
        return {"engine": "docker", "client_version": text(client.get("Version")),
                "server_version": text(server.get("Version")), "api_version": text(server.get("ApiVersion")),
                "os": text(server.get("Os")), "arch": text(server.get("Arch")),
                "kernel": text(server.get("KernelVersion")),
                "components": {key: value for key, value in sorted(components.items())
                               if isinstance(key, str) and isinstance(value, str)},
                "operating_system": text(described.get("OperatingSystem")),
                "cgroup_version": text(described.get("CgroupVersion")),
                "cgroup_driver": text(described.get("CgroupDriver")),
                "default_runtime": text(described.get("DefaultRuntime")),
                "security_options": sorted(security),
                "rootless": any("rootless" in item for item in security),
                "user_namespaces": any("userns" in item for item in security)}

    def _image_identity(self, reference: str | None, label: str) -> dict:
        """The pinned image as the engine holds it, or a refusal. Nothing is ever pulled."""
        if not isinstance(reference, str) or not PINNED_IMAGE.match(reference):
            raise IsolationError(f"the {label} {reference!r} is not pinned by digest")
        found = self._docker.run(["image", "inspect", reference], timeout=CONTROL_TIMEOUT)
        if found.returncode != 0:
            raise IsolationError(f"the {label} {reference} is not present on the engine and the oci backend "
                                 f"never pulls one; pull it by digest first (docker pull {reference}): "
                                 f"{_tail(found.stderr)}")
        try:
            data = json.loads(found.stdout)[0]
            image_id = data["Id"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise IsolationError(f"the engine's description of the {label} could not be read: {exc}") from exc
        digest = "sha256:" + reference.rsplit("sha256:", 1)[1]
        repo_digests = sorted(item for item in data.get("RepoDigests") or [] if isinstance(item, str))
        if image_id != digest and not any(item.endswith("@" + digest) for item in repo_digests):
            raise IsolationError(f"the engine resolved the {label} {reference} to an image whose id and "
                                 f"repository digests do not include {digest}; the pinned image is not "
                                 "the one that would run")
        identity = {"reference": reference, "id": image_id, "repo_digests": repo_digests,
                    "os": data.get("Os"), "architecture": data.get("Architecture")}
        if isinstance(data.get("Variant"), str) and data["Variant"]:
            identity["variant"] = data["Variant"]
        return identity

    def _workspace(self) -> Path:
        """The one private workspace the invocation created inside :attr:`workspace_root`."""
        try:
            with os.scandir(self.workspace_root) as listing:
                entries = sorted(listing, key=lambda entry: entry.name)
        except OSError as exc:
            raise IsolationError(f"the backend's workspace directory could not be listed: {exc}") from exc
        if (len(entries) != 1 or not entries[0].name.startswith(_TRIAL_PREFIX)
                or entries[0].is_symlink() or not entries[0].is_dir(follow_symlinks=False)):
            raise IsolationError(
                f"expected exactly one private workspace directory ({_TRIAL_PREFIX}*) inside the backend's "
                f"workspace root, found {[entry.name for entry in entries]}; the scan was not started")
        workspace = Path(entries[0].path)
        for part in ("source", "raw"):
            path = workspace / part
            if path.is_symlink() or not path.is_dir():
                raise IsolationError(f"the workspace has no {part} directory to mount; the scan was not started")
        return workspace

    def _plan_mounts(self) -> list[_Mount]:
        """Every bind mount of a scanner container, each checked, and the workspace made usable.

        The workspace copy of the source is made readable to any user and each writable mount is
        opened to mode 0777, because the container runs as another user; on an engine that maps
        ownership to the host user this is harmless, and on one that does not it is what lets the
        container user read and write at all. None of it widens access on the host: the private
        workspace above them is the operator's alone and mode 0700.
        """
        workspace = self._workspace()
        source, raw, trace = workspace / "source", workspace / "raw", workspace / "trace"
        _open_for_reading(source)
        mounts = [_Mount(str(source), "ro", "source")]
        for state in self._state_dirs:
            if not isinstance(state, str) or not _STATE_NAME.match(state) or state in (".", ".."):
                raise IsolationError(f"the adapter's state directory {state!r} is not one directory name")
            path = source / state
            if path.is_symlink() or (path.exists() and not path.is_dir()):
                raise IsolationError(f"the state directory {state} in the workspace is not a directory")
            # Created before the container starts: a writable mount over a missing directory inside
            # a read-only one cannot be made. It is excluded from the input tree, so creating it
            # changes nothing the source hash or the modification check covers.
            path.mkdir(exist_ok=True)
            os.chmod(path, 0o777)
            mounts.append(_Mount(str(path), "rw", "state"))
        os.chmod(raw, 0o777)
        mounts.append(_Mount(str(raw), "rw", "raw"))
        if trace.is_dir() and not trace.is_symlink():
            os.chmod(trace, 0o777)
            mounts.append(_Mount(str(trace), "rw", "trace"))
        declared = self._declared()
        if isinstance(declared, (str, bytes)) or not isinstance(declared, (list, tuple)):
            raise IsolationError(f"the adapter's runtime mounts must be a list of paths, not {declared!r}")
        for path in declared:
            mounts.append(self._runtime_mount(path, workspace))
        for mount in mounts:
            if "\n" in mount.path or "\x00" in mount.path:
                raise IsolationError("a mount path holds a line break or NUL byte and cannot be passed to docker")
        return mounts

    def _runtime_mount(self, declared: Any, workspace: Path) -> _Mount:
        """One adapter-declared runtime path, refused when it would widen what the scanner sees.

        A runtime path is allowed, not merely not denied: it must sit strictly inside one of the
        backend's runtime roots, which for a run is the source cache, so what a scanner can read
        besides its workspace is what its preparation fetched there, one pinned checkout at a
        time. The denials are checked first, so a refusal names the most specific reason: the
        filesystem root, the home directory or anything above it, a Docker socket, the scanner's
        own workspace, and the run's evaluator material. A tree holding a unix socket anywhere is
        refused too, because ``connect()`` works through a read-only mount, and a tree that cannot
        be walked is refused because whether it holds one is then unknown.
        """
        if not isinstance(declared, (str, Path)) or not str(declared):
            raise IsolationError(f"the adapter declared a runtime mount that is not a path: {declared!r}")
        text = str(declared)
        path = Path(text)
        shown = _home_relative(text)
        if not path.is_absolute():
            raise IsolationError(f"the runtime mount {shown} is not an absolute path")
        if not path.exists():
            raise IsolationError(f"the runtime mount {shown} does not exist")
        resolved = path.resolve()
        home = Path.home().resolve()
        if resolved == Path(resolved.anchor) or resolved == home or home.is_relative_to(resolved):
            raise IsolationError(f"the runtime mount {shown} is the home directory, the root, or a directory "
                                 "above the home directory; only what the scan reads is mounted")
        for socket_path in _DOCKER_SOCKETS:
            if Path(socket_path).resolve().is_relative_to(resolved):
                raise IsolationError(f"the runtime mount {shown} would expose the Docker socket")
        for owned in (self._private.resolve(), workspace.resolve()):
            if resolved.is_relative_to(owned) or owned.is_relative_to(resolved):
                raise IsolationError(f"the runtime mount {shown} overlaps the scanner's own workspace")
        for protected in self._protected:
            guarded = protected.resolve()
            if guarded.is_relative_to(resolved) or resolved.is_relative_to(guarded):
                raise IsolationError(f"the runtime mount {shown} overlaps {_home_relative(str(guarded))}, "
                                     "which holds evaluator material no scanner may see")
        roots = [root.resolve() for root in self._runtime_roots]
        if not roots:
            raise IsolationError(f"the runtime mount {shown} was refused because no runtime root was given; a "
                                 "scanner is given only what its preparation put in the source cache")
        for root in roots:
            if root.is_relative_to(resolved):
                raise IsolationError(f"the runtime mount {shown} would expose all of {_home_relative(str(root))}; "
                                     "only one checkout inside it may be mounted")
        if not any(resolved.is_relative_to(root) for root in roots):
            where = ", ".join(_home_relative(str(root)) for root in roots)
            raise IsolationError(f"the runtime mount {shown} is not inside {where}; a scanner is given only what "
                                 "its preparation put in the source cache")
        try:
            socket_found = _first_socket(resolved)
        except OSError as exc:
            raise IsolationError(f"the runtime mount {shown} could not be walked, so whether it holds a socket "
                                 f"is unknown: {_scrub_home(str(exc))}") from exc
        if socket_found is not None:
            raise IsolationError(f"the runtime mount {shown} holds a unix socket ({socket_found}); no socket is "
                                 "mounted into a scanner, not even read-only")
        return _Mount(text, "ro", "runtime")

    def _check_mounts_visible(self) -> None:
        """Create, never start, a container with every mount, so the daemon proves it sees each one.

        ``--mount`` refuses a source the daemon cannot see (on Colima, anything outside the shared
        home directory) at create time, where ``-v`` would have made an empty directory and let
        the scan run over nothing. The probe is removed straight away.
        """
        probe = f"scaneval-{self._session}-probe"
        args = ["create", "--name", probe, *self._label_args("probe"), "--pull", "never", "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", self.settings.user,
                *[word for mount in self._mounts for word in ("--mount", mount.argument())],
                "--entrypoint", "/scaneval-mount-probe-is-never-started", self.settings.image]
        self._touched = True
        try:
            created = self._docker.run(args, timeout=CONTROL_TIMEOUT)
        finally:
            self._remove_container(probe)
        if created.returncode != 0:
            message = _tail(created.stderr)
            hint = (" The daemon sees only directories shared with it (on Colima, the home directory by "
                    "default), so the workspace root (--workspace-root) and the source cache must both be "
                    "inside one." if "does not exist" in message or "not shared" in message else "")
            raise IsolationError(f"a path this scan needs mounted is not visible to the Docker daemon, so "
                                 f"the scan was refused rather than run over an empty directory: "
                                 f"{message}.{hint}")

    # --- network --------------------------------------------------------------------------

    def _prepare_network(self) -> None:
        policy = self.settings.network_policy
        if policy == "none":
            self._network_args = ["--network", "none"]
            self._network = {"policy": "none", "mode": "none",
                             "note": "No network interface but loopback: no DNS, no gateway, no route."}
            return
        if policy == "unrestricted":
            bridge = self._create_network("net", internal=False)
            self._network_args = ["--network", bridge]
            self._network = {"policy": "unrestricted", "mode": "bridge", "note": UNRESTRICTED_NOTE}
            return
        internal = self._create_network("int", internal=True)
        egress = self._proxy_network or self._create_network("egress", internal=False)
        self._start_proxy(internal, egress)
        self._network_args = ["--network", internal]
        self._network = {
            "policy": "model_provider_only", "mode": "internal network with egress proxy",
            "note": ("The scanner's only network is an internal one with no gateway; the one reachable "
                     "address on it is the egress proxy, which forwards CONNECT only to the declared "
                     "destinations. DNS for the scanner resolves nothing outside that network.")}

    def _create_network(self, suffix: str, *, internal: bool) -> str:
        """Create one labelled network for this invocation and verify what the engine made."""
        name = f"scaneval-{self._session}-{suffix}"
        args = ["network", "create", *self._label_args(suffix)]
        if internal:
            args += ["--internal", "--opt", f"{_ISOLATED_GATEWAY}=isolated"]
        self._touched = True
        created = self._docker.run([*args, name], timeout=CONTROL_TIMEOUT)
        if created.returncode != 0:
            raise IsolationError(f"the engine refused to create the {suffix} network, so the scan was not "
                                 f"started: {_tail(created.stderr)}")
        record = {"name": name, "role": suffix, "internal": internal, "removed": False}
        self._networks.append(record)
        found = self._docker.run(["network", "inspect", name], timeout=CONTROL_TIMEOUT)
        try:
            facts = json.loads(found.stdout)[0]
            subnets = [entry for entry in (facts.get("IPAM") or {}).get("Config") or [] if isinstance(entry, dict)]
        except (ValueError, IndexError, TypeError, AttributeError) as exc:
            raise IsolationError(f"the {suffix} network could not be inspected: {_tail(found.stderr)} {exc}") from exc
        gateways = sorted(entry["Gateway"] for entry in subnets if entry.get("Gateway"))
        record.update(subnets=sorted(str(entry.get("Subnet")) for entry in subnets if entry.get("Subnet")),
                      gateways=gateways, ipv6=bool(facts.get("EnableIPv6")))
        if internal:
            option = (facts.get("Options") or {}).get(_ISOLATED_GATEWAY)
            record["gateway_mode_ipv4"] = option
            if facts.get("Internal") is not True or option != "isolated" or gateways or facts.get("EnableIPv6"):
                # The engine accepts an option it does not apply, so the network is judged by what
                # inspection shows: an internal network whose bridge carries an address is the
                # route to the engine's host the scanner must not have.
                raise IsolationError(
                    f"the engine did not make the scan network isolated (internal={facts.get('Internal')!r}, "
                    f"{_ISOLATED_GATEWAY}={option!r}, gateways={gateways}, ipv6={bool(facts.get('EnableIPv6'))}); "
                    "model_provider_only needs an internal network with no gateway, which this engine "
                    "did not provide, so the scan was refused")
        return name

    def _start_proxy(self, internal: str, egress: str) -> None:
        """Start the egress proxy on both networks and wait until it listens, or refuse."""
        directory = self._private / "proxy"
        directory.mkdir()
        os.chmod(directory, 0o755)
        script = directory / "egress_proxy.py"
        shutil.copyfile(Path(__file__).with_name("egress_proxy.py"), script)
        os.chmod(script, 0o644)
        log_dir = directory / "log"
        log_dir.mkdir()
        os.chmod(log_dir, 0o777)
        allow = [f"{host}:{port}" for host, port in self.settings.egress]
        name = f"scaneval-{self._session}-proxy"
        args = ["create", "--name", name, *self._label_args("proxy"), "--pull", "never",
                *_hardening(_PROXY_LIMITS, self.settings.user), "--network", egress,
                "--sysctl", "net.ipv4.ip_forward=0", "--workdir", "/tmp", "--env", "HOME=/tmp",
                "--mount", _Mount(str(script), "ro", "proxy").argument(),
                "--mount", _Mount(str(log_dir), "rw", "proxy log").argument(),
                "--entrypoint", "python3", str(self.settings.proxy_image), "-I", str(script),
                "--port", str(PROXY_PORT), "--log-dir", str(log_dir),
                *[word for pair in allow for word in ("--allow", pair)]]
        record = {"name": name, "role": "proxy", "command": "python3 egress_proxy.py", "created": False,
                  "started": False, "exit_code": None, "oom_killed": None, "timed_out": False,
                  "removed": False, "status": None, "error": None, "wall_seconds": None}
        self._containers.append(record)
        self._proxy = {"name": name, "port": PROXY_PORT, "allow": allow, "log_dir": log_dir,
                       "egress_network": egress, "log": "not read"}
        self._touched = True
        created = self._docker.run(args, timeout=CONTROL_TIMEOUT)
        if created.returncode != 0:
            record["error"] = _tail(created.stderr)
            raise IsolationError(f"the engine refused to create the egress proxy: {_tail(created.stderr)}")
        record["created"] = True
        connected = self._docker.run(["network", "connect", internal, name], timeout=CONTROL_TIMEOUT)
        if connected.returncode != 0:
            raise IsolationError(f"the egress proxy could not join the scan network: {_tail(connected.stderr)}")
        started = self._docker.run(["start", name], timeout=CONTROL_TIMEOUT)
        if started.returncode != 0:
            raise IsolationError(f"the egress proxy could not be started: {_tail(started.stderr)}")
        record["started"] = True
        deadline = time.monotonic() + PROXY_READY_SECONDS
        while not (log_dir / "ready").exists():
            state = self._state(name)
            if state is None or not state.get("Running"):
                logs = self._docker.run(["logs", "--tail", "20", name], timeout=CONTROL_TIMEOUT)
                raise IsolationError(f"the egress proxy exited before it was listening: "
                                     f"{_tail(logs.stderr or logs.stdout)}")
            if time.monotonic() > deadline:
                raise IsolationError(f"the egress proxy was not listening within {PROXY_READY_SECONDS:g}s")
            time.sleep(0.05)
        found = self._docker.run(["container", "inspect", name], timeout=CONTROL_TIMEOUT)
        try:
            address = json.loads(found.stdout)[0]["NetworkSettings"]["Networks"][internal]["IPAddress"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise IsolationError(f"the egress proxy's address on the scan network could not be read: {exc}") from exc
        if not isinstance(address, str) or not address:
            raise IsolationError("the egress proxy has no address on the scan network")
        self._proxy["ip"] = address
        url = f"http://{address}:{PROXY_PORT}"
        self._proxy_env = {"HTTPS_PROXY": url, "https_proxy": url, "HTTP_PROXY": url, "http_proxy": url,
                           "ALL_PROXY": url, "all_proxy": url, "NO_PROXY": "", "no_proxy": ""}

    # --- per command ----------------------------------------------------------------------

    def _words(self, argv: list[str]) -> list[str]:
        if not isinstance(argv, (list, tuple)) or not argv:
            raise IsolationError("a command must be a non-empty list of strings")
        for word in argv:
            if not isinstance(word, str) or "\x00" in word:
                raise IsolationError(f"a command word must be a string without a NUL byte, not {word!r}")
        if not argv[0]:
            raise IsolationError("a command must name what it runs")
        return list(argv)

    def _check_output(self, path: Path) -> None:
        """Refuse an output path under a writable mount whose directory no longer resolves inside it.

        A container of this scan could write under that mount and may have replaced a directory
        there with a link to a host directory; :func:`_open_output` refuses a link only as the last
        component. Raises :class:`OSError`, as a local open through a broken directory would, and
        before any container is created for the command.
        """
        text = os.path.normpath(str(path))
        for mount in self._mounts:
            if mount.mode == "rw" and _inside(text, mount.path):
                if not _inside(os.path.realpath(os.path.dirname(text)), os.path.realpath(mount.path)):
                    raise OSError(errno.ELOOP, "a directory of this output path resolves outside its writable "
                                  "mount, so no command output is written through it", _home_relative(text))

    def _workdir(self, cwd: Path) -> str:
        text = os.path.normpath(str(cwd))
        if not os.path.isabs(text) or not any(_inside(text, mount.path) for mount in self._mounts):
            raise IsolationError(f"the command's working directory {_home_relative(text)} is not one the "
                                 "container can see; it must be a mounted path")
        return text

    def _environment_for(self, env: dict[str, str]) -> tuple[dict[str, str], list[str], dict[str, str]]:
        """The container's variables, the credential names passed by name, and their values.

        Values reach the container only through the docker client's own environment, read by
        ``--env NAME``, so they never appear in an argument list or in the record. A declared
        credential that is not set in this process's environment is not passed and is recorded as
        not passed.
        """
        values = {"HOME": "/tmp", "TMPDIR": "/tmp"}
        for key in CONTAINER_ENV_ALLOWLIST:
            value = env.get(key)
            if isinstance(value, str) and "\x00" not in value:
                values[key] = value
        values.update(self._proxy_env)
        names: list[str] = []
        secret: dict[str, str] = {}
        recorded = []
        for key, provider in self.settings.credentials:
            present = key in os.environ and "\x00" not in os.environ[key]
            if present:
                names.append(key)
                secret[key] = os.environ[key]
            recorded.append({"env": key, "provider": provider, "passed": present})
        declared = {key for key, _ in self.settings.credentials}
        self._environment["set"] = sorted(values)
        self._environment["credentials"] = recorded
        self._environment["dropped"] |= {key for key in env if key not in values and key not in declared}
        return values, names, secret

    def _label_args(self, role: str) -> list[str]:
        labels = {**self._labels, "scaneval.role": role}
        return [word for key in sorted(labels) for word in ("--label", f"{key}={labels[key]}")]

    def _state(self, name: str) -> dict | None:
        found = self._docker.run(["container", "inspect", "--format", "{{json .State}}", name],
                                 timeout=CONTROL_TIMEOUT)
        if found.returncode != 0:
            return None
        try:
            state = json.loads(found.stdout)
        except ValueError:
            return None
        return state if isinstance(state, dict) else None

    def _kill(self, name: str) -> None:
        self._docker.run(["kill", name], timeout=CONTROL_TIMEOUT)

    def _remove_container(self, name: str) -> bool:
        """Remove *name* whatever its state; True only when the engine then reports it gone."""
        try:
            self._docker.run(["rm", "--force", name], timeout=CONTROL_TIMEOUT)
            check = self._docker.run(["container", "inspect", "--format", "{{.Id}}", name], timeout=CONTROL_TIMEOUT)
        except IsolationError:
            return False
        return check.returncode != 0 and "no such" in (check.stderr + check.stdout).lower()

    # --- teardown and the record ---------------------------------------------------------------

    def _teardown(self) -> None:
        """Stop and remove the proxy, read its log, and remove this invocation's networks.

        Runs when the scan ends and when a preflight refuses; it never raises, and what it could
        not remove stays recorded as not removed for :meth:`close` to try again.
        """
        if self._proxy is not None:
            name = self._proxy["name"]
            record = next(item for item in self._containers if item["name"] == name)
            try:
                if record["started"]:
                    self._kill(name)
                    state = self._state(name)
                    if state is not None:
                        code = state.get("ExitCode")
                        record.update(status=state.get("Status"), oom_killed=bool(state.get("OOMKilled")),
                                      exit_code=code if isinstance(code, int) else None)
            except Exception as exc:
                record["error"] = _scrub_home(str(exc))
            record["removed"] = self._remove_container(name)
            self._proxy.update(self._proxy_log())
        for network in reversed(self._networks):
            try:
                self._docker.run(["network", "rm", network["name"]], timeout=CONTROL_TIMEOUT)
                check = self._docker.run(["network", "inspect", network["name"]], timeout=CONTROL_TIMEOUT)
                network["removed"] = check.returncode != 0
            except Exception:
                network["removed"] = False

    def _proxy_log(self) -> dict:
        """Allow and deny counts from the proxy's own log, read with a ceiling."""
        path = self._proxy["log_dir"] / "egress.jsonl"
        try:
            data = _read_bounded(path, PROXY_LOG_LIMIT)
        except OSError as exc:
            return {"log": f"unavailable: {exc.strerror or exc}"}
        allowed = denied = unreadable = 0
        allowed_to: set[str] = set()
        denied_to: set[str] = set()
        for line in data.decode("utf-8", "replace").splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                unreadable += 1
                continue
            if not isinstance(entry, dict):
                unreadable += 1
                continue
            where = f"{entry.get('host', entry.get('target', '?'))}:{entry.get('port', '?')}"[:300]
            if entry.get("event") == "allow":
                allowed += 1
                allowed_to.add(where)
            elif entry.get("event") == "deny":
                denied += 1
                denied_to.add(where if "host" in entry else str(entry.get("target", entry.get("reason", "?")))[:300])
        return {"log": "read", "allowed": allowed, "denied": denied, "unreadable_lines": unreadable,
                "allowed_destinations": sorted(allowed_to)[:DESTINATIONS_RECORDED],
                "denied_destinations": sorted(denied_to)[:DESTINATIONS_RECORDED]}

    def _ran(self) -> bool:
        return any(item["role"] == "worker" and item["started"] for item in self._containers)

    def _settings_record(self) -> dict:
        limits = self.settings.limits
        uid, gid = (int(part) for part in self.settings.user.split(":"))
        return {"user": self.settings.user, "uid": uid, "gid": gid, "container_per_command": True,
                "read_only_root_filesystem": True, "cap_drop": ["ALL"], "cap_add": [],
                "no_new_privileges": True, "ipc": "none", "init": True, "pull": "never",
                "pids_limit": limits.pids, "memory_mb": limits.memory_mb, "memory_swap_mb": limits.memory_mb,
                "cpus": limits.cpus, "ulimits": {"core": "0:0", "nofile": f"{limits.nofile}:{limits.nofile}"},
                "tmpfs": [{"target": "/tmp", "size_mb": limits.tmpfs_mb,
                           "options": "rw,nosuid,nodev,noexec", "mode": "1777"}],
                "home": "/tmp", "path": "the image's own", "writable_mounts_mode": "0777",
                "seccomp": "engine default", "apparmor": "engine default",
                "environment": {"set": list(self._environment["set"]),
                                "credentials": [dict(item) for item in self._environment["credentials"]],
                                "dropped": sorted(self._environment["dropped"])}}


def _first_socket(root: Path) -> str | None:
    """The first unix socket at or under *root*, as a relative path, or ``None`` when there is none.

    A directory that cannot be listed raises :class:`OSError` rather than reading as empty. Links
    are never followed: a link inside a bind mount resolves inside the container, where it cannot
    reach the host path it names.
    """
    status = os.lstat(root)
    if stat.S_ISSOCK(status.st_mode):
        return "."
    if not stat.S_ISDIR(status.st_mode):
        return None
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as listing:
            entries = sorted(listing, key=lambda entry: entry.name)
        for entry in entries:
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISSOCK(mode):
                return Path(entry.path).relative_to(root).as_posix()
            if stat.S_ISDIR(mode):
                pending.append(Path(entry.path))
    return None


def _open_for_reading(root: Path) -> None:
    """Give every user read access to the workspace copy of the source, without following a link.

    Each directory is opened before it is listed, and a listing that fails raises rather than
    reading as empty (``os.walk`` would skip it in silence), so part of the input left unreadable
    to the container user is a refusal of the scan, never a subtree the scanner quietly cannot see.
    """
    os.chmod(root, stat.S_IMODE(os.lstat(root).st_mode) | 0o555)
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as listing:
            entries = list(listing)
        for entry in entries:
            if entry.is_symlink():
                continue
            mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
            if entry.is_dir(follow_symlinks=False):
                os.chmod(entry.path, mode | 0o555)
                pending.append(Path(entry.path))
            else:
                os.chmod(entry.path, mode | 0o444)


def _remove_tree(root: Path) -> None:
    """Remove *root*, reopening directories a scanner closed; raises when something stays."""
    if not os.path.lexists(root):
        return
    for directory, directories, _files in os.walk(root):
        for name in directories:
            path = os.path.join(directory, name)
            if not os.path.islink(path):
                try:
                    os.chmod(path, 0o700)
                except OSError:
                    pass
    shutil.rmtree(root)
