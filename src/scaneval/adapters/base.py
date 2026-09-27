"""Adapter protocol for invoking one scanner on one prepared input.

An adapter runs the real product once, preserves its raw output, and translates the
native findings into normalized claims. It never receives labels, never decides whether
a claim is true, and never turns an execution failure into an empty successful scan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import os
from pathlib import Path
import signal
import subprocess
import time
from typing import Any


STATUSES = ("success", "partial", "unsupported", "error", "timeout")
# Environment variables passed to scanner subprocesses unless an adapter adds more.
BASE_ENV_PASSTHROUGH = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TERM", "USER", "SHELL")


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


@dataclass
class NativeOutcome:
    """Everything one invocation produced, before the runner writes the bundle."""

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

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise AdapterError(f"invalid outcome status {self.status!r}")


def build_env(extra_names: tuple[str, ...] = (), overrides: dict[str, str] | None = None) -> dict[str, str]:
    env = {name: os.environ[name] for name in (*BASE_ENV_PASSTHROUGH, *extra_names) if name in os.environ}
    env.update(overrides or {})
    return env


def run_command(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    env: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
    stdin_text: str | None = None,
) -> CommandResult:
    """Run one process with a hard timeout, streaming stdout/stderr to files.

    On timeout the whole process group is killed and ``timed_out`` is reported; the
    partial stdout/stderr files are kept as raw artifacts.
    """
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
        try:
            process.communicate(input=stdin_text.encode("utf-8") if stdin_text is not None else None,
                                timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
    wall = time.monotonic() - started
    return CommandResult(list(argv), None if timed_out else process.returncode, timed_out, wall, stdout_path, stderr_path)


def tail_text(path: Path, limit: int = 2000) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return data[-limit:].decode("utf-8", errors="replace")


class Adapter(ABC):
    """Invoke one system once on one prepared input and normalize its native output."""

    name: str = "abstract"
    adapter_version: str = "0.0.0"
    requires_git: bool = False
    supported_languages: frozenset[str] = frozenset()
    env_passthrough: tuple[str, ...] = ()

    def prepare(self, spec: SystemSpec, cache_root: Path) -> dict[str, Any]:
        """Separately recorded preparation phase (rulesets, dependencies). Default: nothing."""
        return {}

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
