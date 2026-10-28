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
            if size < 0 or size >= ctypes.sizeof(members) or size % ctypes.sizeof(ctypes.c_int):
                return False
            return set(members[:size // ctypes.sizeof(ctypes.c_int)]) <= {0, self.pgid}
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

    def __init__(self, ids: list[str], cidfiles: list[Path], docker: str, grace: float):
        if any(not CONTAINER_ID.fullmatch(value) for value in ids):
            raise Stop("invalid_container_id")
        if len(set(cidfiles)) != len(cidfiles):
            raise Stop("duplicate_cidfile")
        self.ids = set(ids)
        self.cidfiles = {path: None for path in cidfiles}
        self.docker = docker
        self.grace = grace
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

    def stop(self) -> tuple[int, int]:
        failures = 0
        try:
            self.refresh()
        except Stop:
            failures += 1
        if self.ids:
            owned = None
            try:
                owned = OwnedProcess([self.docker, "container", "stop", "--time", "0", "--", *sorted(self.ids)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
                deadline = time.monotonic() + 5
                while owned.exit_code() is None and time.monotonic() < deadline:
                    time.sleep(.05)
                if owned.exit_code() != 0:
                    failures += 1
            except OSError:
                failures += 1
            finally:
                if owned is not None and not owned.stop(self.grace):
                    failures += 1
        return len(self.ids), failures


class Controller:
    def __init__(self, options: Options, source: AppServer, receipts: Receipts,
                 containers: Containers):
        self.options = options
        self.source = source
        self.receipts = receipts
        self.containers = containers
        self.policy = Policy(options.stale_after)
        self.interrupted = False
        self.deadline = math.inf

    def check(self) -> None:
        if self.interrupted:
            raise Stop("interrupted")
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
            if child is not None:
                try:
                    cleanup_okay = child.stop(self.options.grace)
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
                                   registered_containers=count, container_cleanup_failures=failures)
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
        containers = Containers(args.container_id, args.container_cidfile, args.docker, options.grace)
        receipts = Receipts(args.receipts)
        source = AppServer([args.codex, "app-server", "--listen", "stdio://"], options.grace)
        controller = Controller(options, source, receipts, containers)

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
