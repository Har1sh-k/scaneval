#!/usr/bin/env python3
"""POSIX operator utility: supervise one command against live Codex quota reads.

No model calls are made by this monitor. See docs/CODEX_QUOTA_GUARD.md for the
ownership, reporting-delay, and whole-percent limitations.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from typing import Callable


class Stop(Exception):
    """Only fixed internal reason codes, never upstream error text."""


@dataclass(frozen=True)
class Window:
    name: str
    used_percent: int
    resets_at: int
    duration_minutes: int

    @property
    def remaining_percent(self) -> int:
        return 100 - self.used_percent

    def receipt(self) -> dict:
        return {
            "window": self.name,
            "used_percent": self.used_percent,
            "remaining_percent": self.remaining_percent,
            "resets_at": self.resets_at,
            "duration_minutes": self.duration_minutes,
        }


def parse_windows(result: object) -> tuple[Window, ...]:
    """Select only the Codex bucket; do not guess from another model's quota."""
    if not isinstance(result, dict):
        raise Stop("invalid_usage")
    buckets = result.get("rateLimitsByLimitId")
    if buckets is not None:
        if not isinstance(buckets, dict) or "codex" not in buckets:
            raise Stop("missing_codex_bucket")
        bucket = buckets["codex"]
    else:
        bucket = result.get("rateLimits")
    if not isinstance(bucket, dict) or bucket.get("limitId") not in (None, "codex"):
        raise Stop("invalid_codex_bucket")
    if bucket.get("spendControlReached") is True or bucket.get("rateLimitReachedType"):
        raise Stop("quota_unavailable")
    windows = []
    for name in ("primary", "secondary"):
        if name not in bucket:
            raise Stop("missing_window")
        value = bucket[name]
        if value is None:
            continue
        if not isinstance(value, dict):
            raise Stop("invalid_window")
        used, reset, duration = (value.get(key) for key in (
            "usedPercent", "resetsAt", "windowDurationMins"))
        if any(type(item) is not int for item in (used, reset, duration)):
            raise Stop("invalid_window")
        if not 0 <= used <= 100 or reset <= 0 or duration <= 0:
            raise Stop("invalid_window")
        windows.append(Window(name, used, reset, duration))
    if not any(window.duration_minutes == 10080 for window in windows):
        raise Stop("missing_weekly_window")
    return tuple(windows)


@dataclass
class Policy:
    stale_after: float
    previous: tuple[Window, ...] | None = None
    observed_at: float = 0
    reset_deadline: float = math.inf

    def check_time(self, now: float, wall: float) -> None:
        if self.previous is None:
            return
        if now >= self.reset_deadline or any(wall >= w.resets_at for w in self.previous):
            raise Stop("reset_elapsed")
        if now - self.observed_at >= self.stale_after:
            raise Stop("stale_usage")

    def accept(self, windows: tuple[Window, ...], *, now: float, wall: float) -> None:
        self.check_time(now, wall)
        if any(w.resets_at <= wall for w in windows):
            raise Stop("reset_elapsed")
        if self.previous is not None:
            old_shape = [(w.name, w.duration_minutes) for w in self.previous]
            if old_shape != [(w.name, w.duration_minutes) for w in windows]:
                raise Stop("windows_changed")
            if any(old.resets_at != new.resets_at for old, new in zip(self.previous, windows)):
                raise Stop("reset_changed")
            if any(new.remaining_percent > old.remaining_percent
                   for old, new in zip(self.previous, windows)):
                raise Stop("remaining_increased")
        if any(w.remaining_percent <= 1 for w in windows):
            raise Stop("remaining_at_or_below_1")
        if any(w.remaining_percent >= 90 for w in windows):
            raise Stop("remaining_at_or_above_90")
        self.previous = windows
        self.observed_at = now
        # Never extend the original local reset deadline if the wall clock moves.
        self.reset_deadline = min(self.reset_deadline, now + min(w.resets_at - wall for w in windows))


@dataclass(frozen=True)
class Options:
    poll: float = 30
    read_timeout: float = 10
    stale_after: float = 45
    max_runtime: float = 21600
    grace: float = 3

    def validate(self) -> None:
        for value, lower, upper in (
            (self.poll, .1, 60), (self.read_timeout, .1, 30),
            (self.stale_after, .2, 120), (self.max_runtime, .1, 86400),
            (self.grace, .1, 10),
        ):
            if not math.isfinite(value) or not lower <= value <= upper:
                raise Stop("invalid_options")
        if self.stale_after <= self.poll + self.read_timeout:
            raise Stop("invalid_options")


class Receipts:
    def __init__(self, path: Path):
        # Exclusive creation avoids overwriting evidence or following a symlink.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.file = os.fdopen(descriptor, "w", encoding="utf-8")

    def emit(self, event: str, **fields: object) -> None:
        try:
            self.file.write(json.dumps({"schema": 1, "time": time.time(), "event": event,
                                        **fields}, allow_nan=False, sort_keys=True) + "\n")
            self.file.flush()
        except (OSError, ValueError):
            raise Stop("receipt_write_failed") from None

    def close(self) -> None:
        self.file.close()


class OwnedProcess:
    """Only a process started here can supply a process-group cleanup target."""

    def __init__(self, args: list[str], **kwargs):
        self.process = subprocess.Popen(args, start_new_session=True, **kwargs)
        self.pgid = self.process.pid
        self.closed = False

    def dead_darwin_group(self) -> bool:
        # Darwin returns EPERM for a group containing only a zombie. Inspect
        # this exact owned group, with its leader still unreaped; never turn a
        # permission failure for a live group into apparent cleanup success.
        if sys.platform != "darwin" or self.exit_code() is None:
            return False
        import ctypes

        try:
            library = ctypes.CDLL("/usr/lib/libproc.dylib")
            library.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                                             ctypes.c_void_p, ctypes.c_int]
            library.proc_listpids.restype = ctypes.c_int
            members = (ctypes.c_int * 1024)()
            size = library.proc_listpids(2, self.pgid, members, ctypes.sizeof(members))
            # PROC_PGRP_ONLY=2 in Darwin's sys/proc_info.h. Refuse a possibly
            # truncated list rather than assume unseen members are absent.
            if size <= 0 or size >= ctypes.sizeof(members) or size % ctypes.sizeof(ctypes.c_int):
                return False
            return set(members[:size // ctypes.sizeof(ctypes.c_int)]) - {0} == {self.pgid}
        except (OSError, AttributeError):
            return False

    def stop(self, grace: float) -> bool:
        if self.closed:
            return True
        self.closed = True
        okay = True
        try:
            os.killpg(self.pgid, signal.SIGTERM)
        except OSError:
            pass  # Final KILL/exit verification below determines cleanup status.
        # Keep the leader unreaped during the grace period: descendants can
        # outlive it, and its PID must not be reused as another group leader.
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            try:
                os.killpg(self.pgid, 0)
            except ProcessLookupError:
                break
            except PermissionError:
                if self.dead_darwin_group():
                    break
            except OSError:
                break
            time.sleep(min(.05, max(0, deadline - time.monotonic())))
        try:
            os.killpg(self.pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            okay = self.dead_darwin_group() and okay
        except OSError:
            okay = False
        try:
            self.process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            okay = False
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    okay = False
        return okay

    def exit_code(self) -> int | None:
        # WNOWAIT observes completion without reaping the leader. It prevents
        # PID/PGID reuse between detecting job completion and group cleanup.
        status = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if status is None:
            return None
        if status.si_code == os.CLD_EXITED:
            return status.si_status
        return -status.si_status


class AppServer:
    MAX_BYTES = 1024 * 1024

    def __init__(self, command: list[str], grace: float):
        self.command = command
        self.grace = grace
        self.owned: OwnedProcess | None = None
        self.buffer = bytearray()
        self.next_id = 0

    def start(self, timeout: float, check: Callable[[], None]) -> None:
        self.owned = OwnedProcess(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, bufsize=0)
        for stream in (self.owned.process.stdin, self.owned.process.stdout):
            os.set_blocking(stream.fileno(), False)
        deadline = time.monotonic() + timeout
        self.request("initialize", {"clientInfo": {"name": "scaneval_quota_guard",
                     "version": "1.0", "title": "ScanEval quota guard"}}, deadline, check)
        self.write({"method": "initialized"}, deadline, check)

    def write(self, message: dict, deadline: float, check: Callable[[], None]) -> None:
        pending = memoryview((json.dumps(message) + "\n").encode())
        with selectors.DefaultSelector() as selector:
            selector.register(self.owned.process.stdin, selectors.EVENT_WRITE)
            while pending:
                self.check_deadline(deadline, check)
                if not selector.select(min(.1, max(0, deadline - time.monotonic()))):
                    continue
                try:
                    count = os.write(self.owned.process.stdin.fileno(), pending)
                    pending = pending[count:]
                except BlockingIOError:
                    continue
                except OSError:
                    raise Stop("usage_unavailable") from None

    @staticmethod
    def check_deadline(deadline: float, check: Callable[[], None]) -> None:
        check()
        if time.monotonic() >= deadline:
            raise Stop("usage_read_timeout")

    def request(self, method: str, params: dict, deadline: float,
                check: Callable[[], None]) -> dict:
        self.next_id += 1
        request_id = self.next_id
        self.write({"id": request_id, "method": method, "params": params}, deadline, check)
        received = 0
        with selectors.DefaultSelector() as selector:
            selector.register(self.owned.process.stdout, selectors.EVENT_READ)
            while True:
                self.check_deadline(deadline, check)
                if b"\n" not in self.buffer:
                    if not selector.select(min(.1, max(0, deadline - time.monotonic()))):
                        continue
                    try:
                        chunk = os.read(self.owned.process.stdout.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    except OSError:
                        raise Stop("usage_unavailable") from None
                    if not chunk:
                        raise Stop("usage_unavailable")
                    received += len(chunk)
                    self.buffer.extend(chunk)
                    if received > self.MAX_BYTES or len(self.buffer) > self.MAX_BYTES:
                        raise Stop("usage_response_too_large")
                    continue
                line, _, remainder = self.buffer.partition(b"\n")
                self.buffer = bytearray(remainder)
                try:
                    message = json.loads(line)
                except (ValueError, UnicodeError):
                    raise Stop("invalid_usage_protocol") from None
                if not isinstance(message, dict):
                    raise Stop("invalid_usage_protocol")
                if "id" not in message and "method" in message:
                    continue  # Notifications are not fresh request responses.
                if type(message.get("id")) is not int or message["id"] != request_id:
                    raise Stop("invalid_usage_protocol")
                if "error" in message or not isinstance(message.get("result"), dict):
                    raise Stop("usage_unavailable")
                self.check_deadline(deadline, check)
                return message["result"]

    def read(self, timeout: float, check: Callable[[], None]) -> dict:
        return self.request("account/rateLimits/read", {"excludeResetCreditDetails": True},
                            time.monotonic() + timeout, check)

    def close(self) -> bool:
        return self.owned is None or self.owned.stop(self.grace)


CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")


class Containers:
    """Operator registrations only; never enumerate containers or attach by name."""

    def __init__(self, ids: list[str], cidfiles: list[Path], docker: str, grace: float,
                 registry: Path | None = None, remove: bool = False):
        if any(not CONTAINER_ID.fullmatch(value) for value in ids):
            raise Stop("invalid_container_id")
        if len(set(cidfiles)) != len(cidfiles):
            raise Stop("duplicate_cidfile")
        self.ids = set(ids)
        self.cidfiles = {path: None for path in cidfiles}
        self.docker = docker
        self.grace = grace
        self.registry = registry
        self.remove = remove
        self.registry_ids: set[str] | None = None
        self.cleanup: list[dict] = []
        # cidfiles are reserved for containers the wrapped job will create.
        if any(path.exists() or path.is_symlink() for path in cidfiles):
            raise Stop("cidfile_already_exists")

    def refresh(self) -> None:
        failed = False
        for path, previous in self.cidfiles.items():
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                if previous is not None:
                    failed = True
                continue
            except OSError:
                failed = True
                continue
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    failed = True
                    continue
                value = os.read(descriptor, 128).decode("ascii").strip()
            except (OSError, UnicodeError):
                failed = True
                continue
            finally:
                os.close(descriptor)
            if not CONTAINER_ID.fullmatch(value) or (previous is not None and previous != value):
                failed = True
                continue
            self.cidfiles[path] = value
            self.ids.add(value)
        if failed:
            raise Stop("invalid_container_registration")
        if self.registry is not None:
            try:
                descriptor = os.open(self.registry, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                if self.registry_ids is None:
                    return
                raise Stop("invalid_container_registration") from None
            except OSError:
                raise Stop("invalid_container_registration") from None
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise Stop("invalid_container_registration")
                raw = os.read(descriptor, 65537)
                if len(raw) > 65536:
                    raise Stop("invalid_container_registration")
                value = json.loads(raw)
                if (not isinstance(value, dict) or type(value.get("schema")) is not int
                        or value["schema"] != 1 or not isinstance(value.get("container_ids"), list)):
                    raise Stop("invalid_container_registration")
                ids = value["container_ids"]
                if len(ids) > 256 or any(not isinstance(item, str) or not CONTAINER_ID.fullmatch(item)
                                         for item in ids):
                    raise Stop("invalid_container_registration")
                ids = set(ids)
                if self.registry_ids is not None and not self.registry_ids <= ids:
                    raise Stop("invalid_container_registration")
                self.registry_ids = ids
                self.ids.update(ids)
            except (OSError, ValueError, UnicodeError):
                raise Stop("invalid_container_registration") from None
            finally:
                os.close(descriptor)

    def control(self, args: list[str], deadline: float) -> tuple[int | None, bytes, bytes]:
        """Bound Docker control output/time; never persist raw diagnostic text."""
        owned = None
        output = [bytearray(), bytearray()]
        deadline = min(deadline, time.monotonic() + 5)
        try:
            if time.monotonic() >= deadline:
                return None, b"", b""
            owned = OwnedProcess([self.docker, *args], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((owned.process.stdout, owned.process.stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map() or owned.exit_code() is None:
                    if time.monotonic() >= deadline:
                        return None, b"", b""
                    for key, _ in selector.select(min(.05, max(0, deadline - time.monotonic()))):
                        try:
                            chunk = os.read(key.fd, 8192)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output[key.data].extend(chunk)
                        if sum(map(len, output)) > 65536:
                            return None, b"", b""
            return owned.exit_code(), bytes(output[0]), bytes(output[1])
        except OSError:
            return None, b"", b""
        finally:
            if owned is not None:
                if not owned.stop(min(self.grace, .2)):
                    return None, b"", b""

    @staticmethod
    def proves_missing(container_id: str, code: int | None, out: bytes, err: bytes) -> bool:
        # Refuse ambiguous or connection failures. These exact Docker errors
        # are accepted only alongside a successful daemon version read.
        expected = {
            f"Error: No such object: {container_id}",
            f"Error: No such container: {container_id}",
            f"Error response from daemon: No such container: {container_id}",
        }
        try:
            return code == 1 and not out.strip() and err.decode("utf-8").strip() in expected
        except UnicodeError:
            return False

    def stop(self) -> tuple[int, int]:
        failures = 0
        try:
            self.refresh()
        except Stop:
            failures += 1
        if self.ids:
            deadline = time.monotonic() + 10
            action = ["container", "rm", "--force"] if self.remove else ["container", "stop", "--time", "0"]
            code, _, _ = self.control([*action, "--", *sorted(self.ids)], deadline)
            pending_missing = []
            for container_id in sorted(self.ids):
                state = ("removed" if self.remove else "stopped") if code == 0 else "unverified"
                if code != 0:
                    status, out, err = self.control(["container", "inspect", "--format",
                        '{"id":{{json .Id}},"running":{{json .State.Running}}}', "--", container_id], deadline)
                    if status == 0:
                        try:
                            observed = json.loads(out)
                            if observed.get("id") == container_id and type(observed.get("running")) is bool:
                                state = "still_running" if observed["running"] else ("not_removed" if self.remove else "stopped")
                        except (ValueError, AttributeError, UnicodeError):
                            pass
                    elif self.proves_missing(container_id, status, out, err):
                        state = "pending_missing"
                record = {"container_id": container_id, "state": state}
                self.cleanup.append(record)
                if state == "pending_missing":
                    pending_missing.append(record)
            if pending_missing:
                status, out, _ = self.control(["version", "--format", "{{json .Server.Version}}"], deadline)
                try:
                    server_version = json.loads(out) if status == 0 else None
                except (ValueError, UnicodeError):
                    server_version = None
                for record in pending_missing:
                    record["state"] = "not_found" if isinstance(server_version, str) and server_version else "unverified"
            failures += sum(record["state"] not in ("stopped", "removed", "not_found") for record in self.cleanup)
        return len(self.ids), failures


class Controller:
    def __init__(self, options: Options, source: AppServer, receipts: Receipts,
                 containers: Containers, stop_file: Path | None = None):
        self.options = options
        self.source = source
        self.receipts = receipts
        self.containers = containers
        self.policy = Policy(options.stale_after)
        self.interrupted = False
        self.deadline = math.inf
        self.stop_file = stop_file

    def check(self) -> None:
        if self.interrupted:
            raise Stop("interrupted")
        if self.stop_file is not None and (self.stop_file.exists() or self.stop_file.is_symlink()):
            raise Stop("stop_file_present")
        now = time.monotonic()
        if now >= self.deadline:
            raise Stop("runtime_elapsed")
        self.policy.check_time(now, time.time())

    def observe(self) -> None:
        result = self.source.read(self.options.read_timeout, self.check)
        windows = parse_windows(result)
        try:
            self.policy.accept(windows, now=time.monotonic(), wall=time.time())
        except Stop as error:
            self.receipts.emit("usage_rejected", reason=str(error), windows=[w.receipt() for w in windows])
            raise
        self.receipts.emit("usage_accepted", windows=[w.receipt() for w in windows])

    def run(self, command: list[str]) -> int:
        child = None
        reason, code = "internal_error", 125
        child_exit = None
        cleanup_okay = True
        self.deadline = time.monotonic() + self.options.max_runtime
        try:
            self.receipts.emit("guard_started", poll_seconds=self.options.poll,
                               read_timeout_seconds=self.options.read_timeout,
                               stale_after_seconds=self.options.stale_after,
                               max_runtime_seconds=self.options.max_runtime,
                               container_action="remove" if self.containers.remove else "stop",
                               upstream_observation_time_available=False)
            self.source.start(self.options.read_timeout, self.check)
            self.observe()
            self.containers.refresh()
            self.check()
            child = OwnedProcess(command)
            self.receipts.emit("command_started", process_group=child.pgid)
            next_read = time.monotonic() + self.options.poll
            while True:
                self.check()
                child_exit = child.exit_code()
                if child_exit is not None:
                    reason = "command_completed"
                    code = child_exit if 0 <= child_exit <= 255 else 128 - child_exit
                    break
                if time.monotonic() >= next_read:
                    self.containers.refresh()
                    self.observe()
                    next_read = time.monotonic() + self.options.poll
                time.sleep(min(.1, max(0, next_read - time.monotonic())))
        except Stop as error:
            reason = str(error)
            code = 130 if reason == "interrupted" else 125
        except (Exception, KeyboardInterrupt):
            # No exception text: OS and upstream failures may contain secrets.
            reason = "internal_error"
        finally:
            stop_gate_closed = None
            if self.stop_file is not None:
                try:
                    descriptor = os.open(self.stop_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    os.close(descriptor)  # Existence alone closes the wrapper's start gate.
                    stop_gate_closed = True
                except OSError:
                    stop_gate_closed = False
                    cleanup_okay = False
            try:
                self.receipts.emit("guard_stopping", reason=reason, stop_gate_closed=stop_gate_closed)
            except (Stop, OSError):
                cleanup_okay = False
            if child is not None:
                try:
                    cleanup_okay = child.stop(self.options.grace) and cleanup_okay
                except Exception:
                    cleanup_okay = False
            count, failures = len(self.containers.ids), 1
            try:
                count, failures = self.containers.stop()
            except Exception:
                pass
            try:
                cleanup_okay = self.source.close() and cleanup_okay
            except Exception:
                cleanup_okay = False
            cleanup_okay = cleanup_okay and failures == 0
            if not cleanup_okay:
                code = 125
            try:
                self.receipts.emit("guard_stopped", reason=reason, exit_code=code,
                                   command_exit_code=child_exit, cleanup_okay=cleanup_okay,
                                   registered_containers=count, container_cleanup_failures=failures,
                                   containers=self.containers.cleanup, stop_gate_closed=stop_gate_closed)
            except (Stop, OSError):
                code = 125
        return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipts", type=Path, required=True, help="New private JSONL receipt file")
    parser.add_argument("--codex", default="codex", help="Installed Codex executable")
    parser.add_argument("--docker", default="docker", help="Docker executable for registered containers")
    parser.add_argument("--poll-seconds", type=float, default=30)
    parser.add_argument("--read-timeout-seconds", type=float, default=10)
    parser.add_argument("--stale-after-seconds", type=float, default=45)
    parser.add_argument("--max-runtime-seconds", type=float, default=21600)
    parser.add_argument("--grace-seconds", type=float, default=3)
    parser.add_argument("--container-id", action="append", default=[], help="Exact 64-character experiment container ID")
    parser.add_argument("--container-cidfile", type=Path, action="append", default=[],
                        help="Initially absent cidfile that the wrapped experiment will write")
    parser.add_argument("--container-registry", type=Path,
                        help="Operator-maintained atomic JSON registry of append-only full container IDs")
    parser.add_argument("--remove-containers", action="store_true",
                        help="Opt in to removing exact registered ephemeral containers, preventing delayed restarts")
    parser.add_argument("--stop-file", type=Path,
                        help="Create this initially absent private marker before cleanup to close a wrapper's start gate")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command after -- is required")
    receipts = None
    old_handlers = {}
    try:
        if os.name != "posix" or not all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "P_PID")):
            raise Stop("unsupported_platform")
        options = Options(args.poll_seconds, args.read_timeout_seconds,
                          args.stale_after_seconds, args.max_runtime_seconds, args.grace_seconds)
        options.validate()
        if args.stop_file is not None and (args.stop_file.exists() or args.stop_file.is_symlink()):
            raise Stop("stop_file_already_exists")
        containers = Containers(args.container_id, args.container_cidfile, args.docker, options.grace,
                                args.container_registry, args.remove_containers)
        receipts = Receipts(args.receipts)
        source = AppServer([args.codex, "app-server", "--listen", "stdio://"], options.grace)
        controller = Controller(options, source, receipts, containers, args.stop_file)

        def interrupted(signum, frame):
            # Record only. Never interrupt Popen before its owned PID is stored,
            # nor let a second signal interrupt bounded cleanup.
            controller.interrupted = True

        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, interrupted)
        return controller.run(command)
    except Stop as error:
        print(json.dumps({"event": "guard_refused", "reason": str(error)}), file=sys.stderr)
        return 125
    except Exception:
        print('{"event":"guard_refused","reason":"initialization_failed"}', file=sys.stderr)
        return 125
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        if receipts is not None:
            try:
                receipts.close()
            except OSError:
                pass  # A flush failure has already made the controller fail closed.


if __name__ == "__main__":
    sys.exit(main())
