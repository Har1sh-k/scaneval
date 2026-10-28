#!/usr/bin/env python3
"""Task-local Docker launch gate for codex_quota_guard.py (POSIX, standard library).

SCANEVAL_GUARD_DOCKER_CONFIG names a private absolute JSON file:
{"schema":1,"real_docker":"/absolute/docker","allowed_run_ids":["run-id"],
 "registry_file":"/absolute/containers.json","stop_file":"/absolute/stopped"}.

Install a task-local launcher named docker on PATH that sets this variable before
execing this script: ScanEval deliberately filters the Docker client's environment.
The guard must use real_docker directly, the same registry and stop file, and
--remove-containers. Its stop marker is permanent; each run needs fresh paths.
This is an operator-controlled launch gate, not a boundary against an operator
who changes the configuration, registry, marker, or Docker command being used.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

CONFIG_ENV = "SCANEVAL_GUARD_DOCKER_CONFIG"
ACTIVE_ENV = "SCANEVAL_GUARD_DOCKER_ACTIVE"
MAX_BYTES = 65536
MAX_IDS = 256
CONTROL_TIMEOUT = 10
ID = re.compile(r"[0-9a-f]{64}\Z")
ROLES = ("worker", "proxy", "probe")
INSPECT_FORMAT = '{"id":{{json .Id}},"labels":{{json .Config.Labels}}}'


class Refused(Exception):
    """Fixed reason codes only; never command output, arguments, or environment."""


@dataclass(frozen=True)
class Config:
    real_docker: str
    allowed_run_ids: frozenset[str]
    registry_file: Path
    stop_file: Path


def _unique(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("duplicate_json_key")
        result[key] = value
    return result


def _read_json(path: Path, *, missing: bool = False, private: bool = False) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        if missing:
            return {"schema": 1, "container_ids": []}
        raise Refused("configuration_unavailable") from None
    try:
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES
                    or (private and (info.st_uid != os.geteuid() or info.st_mode & 0o077))):
                raise Refused("unsafe_json_file")
            data = source.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise Refused("oversize_json_file")
        document = json.loads(data, object_pairs_hook=_unique)
    except (ValueError, RecursionError):
        raise Refused("invalid_json_file") from None
    if not isinstance(document, dict):
        raise Refused("invalid_json_file")
    return document


def _absolute(value: object) -> Path:
    if not isinstance(value, str) or not value or "\0" in value or not Path(value).is_absolute():
        raise Refused("absolute_path_required")
    return Path(value)


def load_config() -> Config:
    if os.environ.get(ACTIVE_ENV):
        raise Refused("recursive_docker_wrapper")
    path = _absolute(os.environ.get(CONFIG_ENV))
    raw = _read_json(path, private=True)
    if set(raw) != {"schema", "real_docker", "allowed_run_ids", "registry_file", "stop_file"} or type(raw.get("schema")) is not int or raw["schema"] != 1:
        raise Refused("invalid_configuration")
    real = _absolute(raw["real_docker"])
    registry, stop = (_absolute(raw[key]) for key in ("registry_file", "stop_file"))
    runs = raw["allowed_run_ids"]
    if (not isinstance(runs, list) or not 1 <= len(runs) <= MAX_IDS
            or not all(isinstance(run, str) and 0 < len(run) <= 256 and not any(ord(c) < 32 for c in run) for run in runs)
            or len(set(runs)) != len(runs)):
        raise Refused("invalid_run_allowlist")
    if not real.is_file() or not os.access(real, os.X_OK) or real.resolve() == Path(__file__).resolve():
        raise Refused("invalid_real_docker")
    paths = [path.resolve(), registry.resolve(), stop.resolve(), Path(str(registry) + ".lock").resolve()]
    if len(set(paths)) != len(paths):
        raise Refused("overlapping_control_paths")
    return Config(str(real), frozenset(runs), registry, stop)


def _running(config: Config) -> None:
    # Any entry, including a broken link, is a closed gate. Never delete or reset it.
    try:
        config.stop_file.lstat()
    except FileNotFoundError:
        return
    raise Refused("guard_stopped")


def _ids(config: Config) -> set[str]:
    raw = _read_json(config.registry_file, missing=True)
    ids = raw.get("container_ids")
    if (set(raw) != {"schema", "container_ids"} or type(raw.get("schema")) is not int or raw["schema"] != 1
            or not isinstance(ids, list) or len(ids) > MAX_IDS
            or not all(isinstance(ident, str) and ID.fullmatch(ident) for ident in ids)
            or len(set(ids)) != len(ids)):
        raise Refused("invalid_container_registry")
    return set(ids)


@contextmanager
def _registry_lock(config: Config):
    fd = os.open(str(config.registry_file) + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise Refused("unsafe_registry_lock")
        deadline = time.monotonic() + CONTROL_TIMEOUT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Refused("registry_lock_timeout") from None
                time.sleep(.01)
        yield
    finally:
        os.close(fd)


def _register(config: Config, ident: str) -> None:
    with _registry_lock(config):
        _running(config)
        ids = _ids(config)
        ids.add(ident)
        if len(ids) > MAX_IDS:
            raise Refused("container_registry_full")
        fd, temporary = tempfile.mkstemp(prefix=".codex-container-registry-", dir=config.registry_file.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump({"schema": 1, "container_ids": sorted(ids)}, output, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, config.registry_file)
        finally:
            if os.path.lexists(temporary):
                os.unlink(temporary)


def _environment() -> dict[str, str]:
    # Keep named credentials available to Docker --env NAME without inspecting their values.
    return {**os.environ, ACTIVE_ENV: "1"}


def _control(config: Config, args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run([config.real_docker, *args], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=CONTROL_TIMEOUT, env=_environment())
    except (OSError, subprocess.TimeoutExpired):
        raise Refused("docker_control_unavailable") from None


def _owned(config: Config, target: str) -> tuple[str, dict]:
    result = _control(config, ["container", "inspect", "--format", INSPECT_FORMAT, "--", target])
    if result.returncode != 0 or len(result.stdout) > MAX_BYTES:
        raise Refused("container_identity_unavailable")
    try:
        found = json.loads(result.stdout, object_pairs_hook=_unique)
    except (ValueError, RecursionError):
        raise Refused("container_identity_invalid") from None
    if not isinstance(found, dict) or not isinstance(found.get("id"), str) or not ID.fullmatch(found["id"]):
        raise Refused("container_identity_invalid")
    labels = found.get("labels")
    if (not isinstance(labels, dict) or labels.get("scaneval.backend") != "oci"
            or not isinstance(labels.get("scaneval.run"), str) or labels["scaneval.run"] not in config.allowed_run_ids
            or labels.get("scaneval.role") not in ROLES):
        raise Refused("container_not_allowlisted")
    return found["id"], labels


# Deliberately the OCI backend's create vocabulary. Unknown options cannot hide a label file,
# consume the image argument, or reinterpret a command's --label text as ownership evidence.
VALUE_OPTIONS = {"--name", "--label", "-l", "--pull", "--cap-drop", "--security-opt", "--user", "--ipc",
                 "--pids-limit", "--memory", "--memory-swap", "--cpus", "--ulimit", "--tmpfs", "--network",
                 "--workdir", "--env", "-e", "--mount", "--entrypoint", "--sysctl"}
FLAG_OPTIONS = {"--interactive", "-i", "--read-only", "--init"}


def _create_labels(config: Config, args: list[str]) -> dict[str, str]:
    labels = {}
    name = None
    index = 0
    while index < len(args) and args[index].startswith("-"):
        option, separator, inline = args[index].partition("=")
        if option in FLAG_OPTIONS and not separator:
            index += 1
            continue
        if option not in VALUE_OPTIONS:
            raise Refused("unsupported_create_option")
        if separator:
            value = inline
        else:
            index += 1
            if index >= len(args):
                raise Refused("incomplete_create_option")
            value = args[index]
        if option in ("--label", "-l"):
            key, equal, label = value.partition("=")
            if not equal or not key or key in labels:
                raise Refused("invalid_create_labels")
            labels[key] = label
        elif option == "--name":
            if name is not None or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
                raise Refused("invalid_container_name")
            name = value
        index += 1
    if index >= len(args) or not name:
        raise Refused("incomplete_create_command")
    if (labels.get("scaneval.backend") != "oci" or labels.get("scaneval.run") not in config.allowed_run_ids
            or labels.get("scaneval.role") not in ROLES):
        raise Refused("container_not_allowlisted")
    return labels


def create(config: Config, args: list[str]) -> int:
    _running(config)
    labels = _create_labels(config, args)
    # Refuse an already malformed registry before asking Docker to create anything.
    with _registry_lock(config):
        _running(config)
        _ids(config)
    result = _control(config, ["create", *args])
    if result.returncode != 0:
        raise Refused("docker_create_failed")
    try:
        ident = result.stdout.decode("ascii").strip()
    except UnicodeError:
        raise Refused("created_container_id_invalid") from None
    if not ID.fullmatch(ident):
        raise Refused("created_container_id_invalid")
    owned, actual = _owned(config, ident)
    if owned != ident or any(actual.get(key) != labels[key] for key in ("scaneval.backend", "scaneval.run", "scaneval.role")):
        raise Refused("created_container_identity_mismatch")
    try:
        _register(config, ident)
        _running(config)
    except (Refused, OSError):
        # Only the immutable ID just created and positively verified as owned is removed.
        removed = _control(config, ["rm", "--force", ident])
        if removed.returncode != 0:
            raise Refused("new_container_cleanup_failed") from None
        raise
    # Never relay create stderr or unexpected stdout: it may quote args or environment.
    print(ident, flush=True)
    return 0


def start(config: Config, args: list[str]) -> None:
    _running(config)
    flags = []
    while args and args[0] in ("--attach", "-a", "--interactive", "-i"):
        flags.append(args[0])
        args = args[1:]
    if len(args) != 1 or not args[0] or args[0].startswith("-"):
        raise Refused("unsupported_start_command")
    ident, _ = _owned(config, args[0])
    with _registry_lock(config):
        _running(config)
        if ident not in _ids(config):
            raise Refused("container_not_registered")
    _running(config)
    # Immutable ID closes name-reuse races. The guard removes it with --force: a delayed
    # start either precedes removal and is killed, or follows removal and cannot find it.
    os.execve(config.real_docker, [config.real_docker, "start", *flags, ident], _environment())


def main(argv: list[str] | None = None) -> int:
    try:
        config = load_config()
        args = list(sys.argv[1:] if argv is None else argv)
        if not args:
            raise Refused("docker_command_required")
        if args[0] == "container" and len(args) > 1 and args[1] in ("create", "start"):
            args = args[1:]
        if args[0] == "create":
            return create(config, args[1:])
        if args[0] == "start":
            start(config, args[1:])
        passthrough = args[0] in ("version", "info", "inspect", "ps", "logs", "wait", "kill", "stop", "rm")
        passthrough |= len(args) > 1 and ((args[0] == "container" and args[1] in ("inspect", "ls", "logs", "wait", "kill", "stop", "rm"))
                                       or (args[0] == "image" and args[1] in ("inspect", "ls"))
                                       or (args[0] == "network" and args[1] in ("create", "connect", "disconnect", "inspect", "ls", "rm")))
        if not passthrough:
            raise Refused("unsupported_docker_command")
        os.execve(config.real_docker, [config.real_docker, *args], _environment())
    except Refused as exc:
        print(f"codex_guard_docker: {exc}", file=sys.stderr)
    except (OSError, ValueError, TypeError, RecursionError):
        print("codex_guard_docker: wrapper_failure", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
