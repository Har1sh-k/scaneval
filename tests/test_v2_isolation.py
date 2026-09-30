"""The execution backend seam and the oci backend, without an engine.

Every test here that concerns the oci backend talks to a scripted engine (:class:`FakeDocker`)
that records the exact docker argument lists the backend sends and answers them the way Docker 29
does, so what is checked is what the backend asks for and what it records, never what a real
engine did; the tests that run a real engine are in ``test_v2_isolation_docker.py``. The rest run
the pieces that need no engine at all: the reads of files a scanner wrote, the routing of
``run_command``, the selection of a backend, the egress proxy script on the loopback interface,
the docker client against a stand-in CLI, and the runner with the engine scripted. No network, no
model calls, no engine.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

from scaneval import cases, isolation
from scaneval.adapters import get_adapter
from scaneval.adapters import base as base_module
from scaneval.adapters.base import (Adapter, AdapterError, CommandResult, NativeOutcome, SystemSpec, build_env,
                                    run_command, tail_text)
from scaneval.adapters.semgrep import SemgrepAdapter, _binary, semgrep_version
from scaneval.cli import main
from scaneval.contracts import canonical_json, validate_document
from scaneval.execution import PreparedInput, run_invocation
from scaneval.isolation import IsolationError, backend_for, refusal_for, resolve_execution
from scaneval.isolation import egress_proxy
from scaneval.isolation import oci as oci_module
from scaneval.isolation.oci import DockerClient, DockerResult, OciBackend
from scaneval.materialize import hash_exported_tree
from scaneval.runner import run_from_config


CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
IMAGE = "scanner:1@sha256:" + "a" * 64
PROXY = "proxy:1@sha256:" + "b" * 64
NEVER_STARTED = "0001-01-01T00:00:00Z"
VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
              "assumption, and adds a single-file Python sink for the isolation tests.")
mkfifo_required = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")


def finishes(action, seconds: float = 10.0):
    """Run *action* on a thread and return what it returned, failing rather than hanging the suite."""
    outcome: dict = {}

    def target():
        try:
            outcome["value"] = action()
        except BaseException as exc:  # noqa: BLE001 - handed back to the test below
            outcome["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"the call was still blocked after {seconds}s"
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


# --- reads of files a scanner wrote --------------------------------------------------------------


def test_tail_text_quotes_a_regular_file_exactly_and_never_a_link_or_a_pipe(tmp_path):
    """The tail every failure message quotes is of a file the scanner could have replaced."""
    data = b"x" * 5000 + "last words \u00e9\n".encode("utf-8")
    stderr = tmp_path / "stderr.txt"
    stderr.write_bytes(data)
    for limit in (16, 2000, 10000):
        assert tail_text(stderr, limit=limit) == data[-limit:].decode("utf-8", errors="replace")
    secret = tmp_path / "secret.txt"
    secret.write_text("host-only-token\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(secret)
    assert tail_text(link) == ""
    assert tail_text(tmp_path / "missing.txt") == "" and tail_text(tmp_path) == ""


@mkfifo_required
def test_tail_text_returns_at_once_for_a_named_pipe_left_where_stderr_belongs(tmp_path):
    pipe = tmp_path / "stderr.txt"
    os.mkfifo(pipe)
    assert finishes(lambda: tail_text(pipe)) == ""


def planting_semgrep(tmp_path: Path, secret: Path, *, version_link: bool, stderr_link: bool,
                     output_link: bool) -> Path:
    """A stand-in Semgrep that replaces the files it was given with links to *secret*, then fails."""
    raw = tmp_path / "raw"
    script = tmp_path / "planting-semgrep"
    script.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"raw, secret = {str(raw)!r}, {str(secret)!r}\n"
        "def plant(name):\n"
        "    os.unlink(os.path.join(raw, name))\n"
        "    os.symlink(secret, os.path.join(raw, name))\n"
        "if '--version' in sys.argv:\n"
        f"    if {version_link!r}:\n"
        "        plant('semgrep-version.txt')\n"
        f"    if {stderr_link!r}:\n"
        "        plant('semgrep-version.stderr.txt')\n"
        "        raise SystemExit(2)\n"
        "    print('9.9.9')\n"
        "    raise SystemExit(0)\n"
        f"if {output_link!r}:\n"
        "    plant('semgrep.json')\n"
        "    plant('semgrep.stderr.txt')\n"
        "raise SystemExit(1)\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def test_semgrep_reads_back_what_it_wrote_without_following_a_link_the_scanner_planted(tmp_path):
    """A link where Semgrep's output belongs would otherwise put a file of the scanner's choosing in the record.

    The secret here parses as a Semgrep result, so following the link would not even have failed:
    it would have become a claim, and its text a recorded version or a quoted stderr tail.
    """
    token = "host-only-token-7d1e"
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"version": token, "results": [{
        "check_id": "planted.rule", "path": "app.py", "start": {"line": 1}, "end": {"line": 1},
        "extra": {"message": token, "severity": "ERROR", "metadata": {"cwe": ["CWE-78"]}}}],
        "errors": [], "paths": {"scanned": ["app.py"]}}), encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    for version_link, stderr_link in ((True, False), (False, True)):
        binary = planting_semgrep(tmp_path, secret, version_link=version_link, stderr_link=stderr_link,
                                  output_link=False)
        with pytest.raises(AdapterError) as raised:
            semgrep_version(str(binary), raw)
        assert token not in str(raised.value)
        for leftover in raw.iterdir():
            leftover.unlink()

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("import subprocess\n", encoding="utf-8")
    binary = planting_semgrep(tmp_path, secret, version_link=False, stderr_link=False, output_link=True)
    preparation = {"ruleset": {"commit": "a" * 40, "tree_hash": "sha256:" + "b" * 64},
                   "config_dirs": [str(tmp_path / "rules" / "python")], "ruleset_root": str(tmp_path / "rules")}
    outcome = SemgrepAdapter().scan(request={}, source_dir=source, raw_dir=raw,
                                    spec=SystemSpec("semgrep-fake", "semgrep", {"binary": str(binary)}),
                                    preparation=preparation, timeout_seconds=60, trace_mode="off", trace_dir=None)
    assert outcome.status == "error" and outcome.error["code"] == "unparseable_output"
    assert outcome.claims == [] and token not in outcome.error["message"]


# --- routing in adapters.base ----------------------------------------------------------------


class RecordingBackend:
    name = "recording"

    def __init__(self):
        self.commands = []

    def run_command(self, argv, **kwargs):
        self.commands.append((list(argv), kwargs))
        return CommandResult(list(argv), 0, False, 0.0, kwargs["stdout_path"], kwargs["stderr_path"])


def test_run_command_goes_to_the_active_backend_and_runs_on_the_host_otherwise(tmp_path):
    held = RecordingBackend()
    with base_module.routed_through(held):
        assert base_module.active_backend() is held
        routed = run_command(["scanner", "--version"], cwd=tmp_path, timeout_seconds=5, env={"A": "1"},
                             stdout_path=tmp_path / "out.txt", stderr_path=tmp_path / "err.txt")
    assert base_module.active_backend() is None
    assert routed.exit_code == 0 and held.commands[0][0] == ["scanner", "--version"]
    assert held.commands[0][1]["env"] == {"A": "1"} and not (tmp_path / "out.txt").exists()
    local = run_command([sys.executable, "-c", "print('local')"], cwd=tmp_path, timeout_seconds=30, env=build_env(),
                        stdout_path=tmp_path / "out.txt", stderr_path=tmp_path / "err.txt")
    assert local.exit_code == 0 and (tmp_path / "out.txt").read_text(encoding="utf-8") == "local\n"


def test_a_command_started_from_a_thread_outside_the_routed_context_is_refused_not_run_on_the_host(tmp_path):
    """A context variable does not follow a thread, so such a command would otherwise run on the host."""
    held = RecordingBackend()
    marker = tmp_path / "ran-on-the-host"
    raised: list[BaseException] = []

    def from_a_thread():
        try:
            run_command([sys.executable, "-c", f"open({str(marker)!r}, 'w')"], cwd=tmp_path, timeout_seconds=30,
                        env=build_env(), stdout_path=tmp_path / "o.txt", stderr_path=tmp_path / "e.txt")
        except BaseException as exc:
            raised.append(exc)

    with base_module.routed_through(held):
        worker = threading.Thread(target=from_a_thread)
        worker.start()
        worker.join(30)
    assert raised and isinstance(raised[0], AdapterError) and "not run on the host" in str(raised[0])
    assert not marker.exists() and held.commands == []
    # Once the routed block is closed, a thread runs locally again.
    worker = threading.Thread(target=from_a_thread)
    worker.start()
    worker.join(30)
    assert marker.exists() and len(raised) == 1


def test_an_adapter_is_not_oci_compatible_and_mounts_nothing_unless_it_says_so():
    class Plain(Adapter):
        def scan(self, **kwargs):
            raise AssertionError("not called")

    assert Plain.oci_compatible is False
    assert Plain().runtime_mounts(SystemSpec("plain", "plain", {}), {}) == ()


# --- semgrep's version probe ------------------------------------------------------------------


def test_semgrep_probes_its_version_without_asking_the_network_for_a_newer_one(tmp_path):
    recorded = tmp_path / "argv.json"
    binary = tmp_path / "fake-semgrep"
    binary.write_text(f"#!{sys.executable}\nimport json, sys\n"
                      f"open({str(recorded)!r}, 'w').write(json.dumps(sys.argv[1:]))\nprint('9.9.9')\n",
                      encoding="utf-8")
    binary.chmod(0o755)
    raw = tmp_path / "raw"
    raw.mkdir()
    assert semgrep_version(str(binary), raw) == "9.9.9"
    assert json.loads(recorded.read_text(encoding="utf-8")) == ["--version", "--disable-version-check"]


# --- settings and selection ------------------------------------------------------------------


def settings(policy: str = "none", **overrides) -> isolation.ExecutionSettings:
    block = {"backend": "oci", "image": IMAGE, **overrides}
    if policy == "model_provider_only":
        block.setdefault("proxy_image", PROXY)
        block.setdefault("egress", [{"host": "api.model.example", "port": 443}])
    return resolve_execution(block, policy)


def test_an_absent_or_local_execution_block_is_the_local_backend():
    for block in (None, {}, {"backend": "local"}):
        resolved = resolve_execution(block, "none")
        assert resolved.backend == "local" and not resolved.enforcing
    with pytest.raises(IsolationError, match="takes no image"):
        resolve_execution({"backend": "local", "image": IMAGE}, "none")


def test_oci_settings_carry_defaults_and_refuse_what_the_contract_cannot_express():
    resolved = settings()
    assert resolved.enforcing and resolved.user == "65534:65534" and resolved.limits.memory_mb == 2048
    assert settings("model_provider_only", egress=[{"host": "API.Model.Example", "port": 443},
                                                   {"host": "api.model.example", "port": 443}]).egress == (
        ("api.model.example", 443),)
    cases_refused = [
        ({"image": "scanner:latest"}, "none", "pinned by digest"),
        ({"limits": {"memory_mb": 128, "tmpfs_mb": 128}}, "none", "must be smaller than memory_mb"),
        ({"limits": {"pids": 4}}, "none", "at least 16"),
        ({"limits": {"swap": 1}}, "none", "unknown field"),
        ({"user": "0:0"}, "none", "non-root"),
        ({"user": "nobody"}, "none", "numeric uid:gid"),
        ({"egress": [{"host": "a.example", "port": 443}]}, "none", "apply only to model_provider_only"),
        ({"egress": [{"host": "http://a.example", "port": 443}], "proxy_image": PROXY}, "model_provider_only",
         "host name or an IP literal"),
        ({"egress": [{"host": "a.example", "port": 443}]}, "model_provider_only", "proxy_image pinned"),
        ({"egress": [{"host": "a.example", "port": 443}], "proxy_image": PROXY,
          "credentials": [{"env": "KEY", "provider": "p"}, {"env": "KEY", "provider": "q"}]},
         "model_provider_only", "names KEY twice"),
    ]
    for overrides, policy, message in cases_refused:
        with pytest.raises(IsolationError, match=message):
            resolve_execution({"backend": "oci", "image": IMAGE, **overrides}, policy)
    with pytest.raises(IsolationError, match="unknown network policy"):
        resolve_execution(None, "open")


def test_adapters_that_do_not_declare_oci_compatibility_are_refused_under_oci():
    """llm-harness and DeepSec have no Linux image and no audit that every process goes through a backend."""
    oci = settings()
    for name in ("llm-harness", "deepsec"):
        adapter = get_adapter(name)
        assert adapter.oci_compatible is False
        reason = refusal_for(adapter, oci)
        assert reason is not None and f"refuses adapter {name!r}" in reason and "not invoked" in reason
        assert refusal_for(adapter, resolve_execution(None, "none")) is None

    class Claims(Adapter):
        name = "claims"
        oci_compatible = "yes"  # anything but True is not a declaration

        def scan(self, **kwargs):
            raise AssertionError("not called")

    assert refusal_for(Claims(), oci) is not None


# --- the egress proxy script, run locally --------------------------------------------------


def test_split_authority_reads_host_and_port_and_refuses_anything_else():
    assert egress_proxy.split_authority("API.Example.com:443") == ("api.example.com", 443)
    assert egress_proxy.split_authority("[2001:DB8::1]:8443") == ("2001:db8::1", 8443)
    for bad in ("example.com", "example.com:0", "example.com:65536", "a b:1", "user@host:1", "/x:1",
                "2001:db8::1:443", "[2001:db8::1]", ":443", "host:44a"):
        assert egress_proxy.split_authority(bad) is None, bad


def test_the_egress_proxy_gives_a_request_head_one_deadline_not_one_per_read(monkeypatch):
    """A client trickling one byte at a time must not hold a connection slot past the head deadline."""
    monkeypatch.setattr(egress_proxy, "HEAD_TIMEOUT", 0.5)
    client, server = socket.socketpair()
    stop = threading.Event()

    def trickle():
        while not stop.is_set():
            try:
                client.sendall(b"C")
            except OSError:
                return
            time.sleep(0.1)

    feeder = threading.Thread(target=trickle, daemon=True)
    feeder.start()
    started = time.monotonic()
    try:
        assert finishes(lambda: egress_proxy.read_head(server)) is None
        assert time.monotonic() - started < 5
    finally:
        stop.set()
        client.close()
        server.close()
        feeder.join(5)


@contextmanager
def local_service(body: bytes):
    """A one-thread HTTP/1.0 server on 127.0.0.1 answering every request with *body*."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    stop = threading.Event()

    def serve():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except OSError:
                continue
            with connection:
                connection.settimeout(5)
                try:
                    connection.recv(4096)
                    connection.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(5)
        listener.close()


def proxy_request(port: int, head: bytes, then: bytes = b"") -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall(head)
        reply = connection.recv(4096)
        if then and reply.startswith(b"HTTP/1.1 200"):
            connection.sendall(then)
            chunks = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            reply += b"".join(chunks)
        return reply


def test_the_egress_proxy_forwards_only_declared_pairs_and_logs_every_decision(tmp_path):
    with local_service(b"model-endpoint-token") as allowed_port, local_service(b"undeclared") as other_port:
        process = subprocess.Popen(
            [sys.executable, "-I", egress_proxy.__file__, "--bind", "127.0.0.1", "--port", "0",
             "--log-dir", str(tmp_path), "--allow", f"127.0.0.1:{allowed_port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 30
            while not (tmp_path / "ready").exists():
                assert process.poll() is None, process.stderr.read().decode()
                assert time.monotonic() < deadline, "the proxy never became ready"
                time.sleep(0.05)
            port = json.loads((tmp_path / "ready").read_text(encoding="utf-8"))["port"]
            tunnelled = proxy_request(port, f"CONNECT 127.0.0.1:{allowed_port} HTTP/1.1\r\nHost: x\r\n\r\n".encode(),
                                      b"GET / HTTP/1.0\r\n\r\n")
            assert tunnelled.startswith(b"HTTP/1.1 200") and b"model-endpoint-token" in tunnelled
            assert proxy_request(port, f"CONNECT 127.0.0.1:{other_port} HTTP/1.1\r\n\r\n".encode()).startswith(
                b"HTTP/1.1 403")
            assert proxy_request(port, f"GET http://127.0.0.1:{allowed_port}/ HTTP/1.1\r\n\r\n".encode()).startswith(
                b"HTTP/1.1 405")
            assert proxy_request(port, b"CONNECT nowhere HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 400")
        finally:
            process.kill()
            process.wait(10)
            process.stderr.close()
    entries = [json.loads(line) for line in (tmp_path / "egress.jsonl").read_text(encoding="utf-8").splitlines()]
    events = [entry["event"] for entry in entries]
    assert events[0] == "listening" and events.count("allow") == 1 and events.count("deny") == 3
    denied = [entry for entry in entries if entry["event"] == "deny"]
    assert {"host": "127.0.0.1", "port": other_port} == {key: denied[0][key] for key in ("host", "port")}
    assert "only CONNECT" in denied[1]["reason"] and "not host:port" in denied[2]["reason"]


# --- the oci backend against a scripted engine ----------------------------------------------------


def _flag_values(args: list[str], flag: str) -> list[str]:
    return [args[index + 1] for index, word in enumerate(args[:-1]) if word == flag]


def _mount_sources(args: list[str]) -> list[str]:
    sources = []
    for value in _flag_values(args, "--mount"):
        for field in value.split(","):
            field = field.strip('"')
            if field.startswith("src="):
                sources.append(field[4:])
    return sources


class FakeDocker:
    """Answers the docker commands the oci backend sends, and records every one of them.

    ``behavior(container, stdout, stderr, stdin_text)`` plays the scanner for ``docker start
    --attach``: it writes what the process would have written and returns its exit code, the
    string ``"timeout"``, or ``(exit code, oom_killed)``; it may also raise, as an interrupted
    client would. With ``unstartable`` the engine fails the start the way Docker 29 does for an
    entrypoint the image lacks: the container stays ``created`` with a zero start time. Output
    files are opened the way the real client opens them. Nothing is executed.
    """

    def __init__(self, *, reachable: bool = True, images=(IMAGE, PROXY), invisible=(),
                 isolated_applies: bool = True, behavior=None, proxy_log: str = "",
                 unstartable: bool = False) -> None:
        self.calls: list[list[str]] = []
        self.extra_envs: list[dict] = []
        self.reachable = reachable
        self.images = {reference: {"Id": "sha256:" + reference.rsplit("sha256:", 1)[1],
                                   "RepoDigests": [reference.split(":", 1)[0] + "@sha256:" + reference.rsplit("sha256:", 1)[1]],
                                   "Os": "linux", "Architecture": "arm64"} for reference in images}
        self.invisible = tuple(str(path) for path in invisible)
        self.isolated_applies = isolated_applies
        self.behavior = behavior or (lambda container, out, err, stdin: 0)
        self.proxy_log = proxy_log
        self.unstartable = unstartable
        self.containers: dict[str, dict] = {}
        self.networks: dict[str, dict] = {}

    @staticmethod
    def ok(stdout: str = "") -> DockerResult:
        return DockerResult(0, stdout, "")

    @staticmethod
    def fail(stderr: str, code: int = 1) -> DockerResult:
        return DockerResult(code, "", stderr)

    def _labels(self, args: list[str]) -> dict:
        return dict(value.split("=", 1) for value in _flag_values(args, "--label"))

    def run(self, args, *, timeout, extra_env=None) -> DockerResult:
        args = list(args)
        self.calls.append(args)
        self.extra_envs.append(dict(extra_env or {}))
        head = args[0]
        if head == "version":
            if not self.reachable:
                return DockerResult(1, json.dumps({"Client": {"Version": "29.4.3"}, "Server": None}),
                                    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
                                    "Is the docker daemon running?")
            return self.ok(json.dumps({"Client": {"Version": "29.4.3", "ApiVersion": "1.53"},
                                       "Server": {"Version": "29.2.1", "ApiVersion": "1.53", "Os": "linux",
                                                  "Arch": "arm64", "KernelVersion": "6.8.0",
                                                  "Components": [{"Name": "runc", "Version": "1.3.4"}]}}))
        if head == "info":
            return self.ok(json.dumps({"OperatingSystem": "Ubuntu 24.04.4 LTS", "CgroupVersion": "2",
                                       "CgroupDriver": "cgroupfs", "DefaultRuntime": "runc",
                                       "SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin"]}))
        if args[:2] == ["image", "inspect"]:
            found = self.images.get(args[2])
            return self.ok(json.dumps([found])) if found else self.fail(f"Error: No such image: {args[2]}")
        if head == "create":
            name = _flag_values(args, "--name")[0]
            for source in _mount_sources(args):
                if any(source == hidden or source.startswith(hidden + "/") for hidden in self.invisible):
                    return self.fail('Error response from daemon: invalid mount config for type "bind": '
                                     f"bind source path does not exist: {source}")
            self.containers[name] = {"name": name, "args": args, "labels": self._labels(args),
                                     "networks": _flag_values(args, "--network"),
                                     "state": {"Status": "created", "Running": False, "ExitCode": 0,
                                               "OOMKilled": False, "Error": "", "StartedAt": NEVER_STARTED}}
            return self.ok(f"{name}-id\n")
        if head == "start":
            container = self.containers[args[-1]]
            container["state"].update(Status="running", Running=True, StartedAt="2026-09-20T15:00:00.1Z")
            log_dir = _flag_values(container["args"], "--log-dir")
            if log_dir:
                Path(log_dir[0], "ready").write_text("{}\n", encoding="utf-8")
                Path(log_dir[0], "egress.jsonl").write_text(self.proxy_log, encoding="utf-8")
            return self.ok(args[-1])
        if head == "kill":
            container = self.containers.get(args[-1])
            if container is None or not container["state"]["Running"]:
                return self.fail(f"Error response from daemon: container {args[-1]} is not running")
            container["state"].update(Status="exited", Running=False, ExitCode=137)
            return self.ok(args[-1])
        if head == "rm":
            self.containers.pop(args[-1], None)
            return self.ok(args[-1])
        if args[:2] == ["container", "inspect"]:
            name = args[-1]
            container = self.containers.get(name)
            if container is None:
                return self.fail(f"Error: No such container: {name}")
            if "{{json .State}}" in args:
                return self.ok(json.dumps(container["state"]))
            if "{{.Id}}" in args:
                return self.ok(f"{name}-id")
            networks = {network: {"IPAddress": f"172.30.0.{index + 2}"}
                        for index, network in enumerate(container["networks"])}
            return self.ok(json.dumps([{"NetworkSettings": {"Networks": networks}}]))
        if args[:2] == ["network", "create"]:
            name = args[-1]
            options = dict(value.split("=", 1) for value in _flag_values(args, "--opt"))
            internal = "--internal" in args
            config = {"Subnet": f"172.{30 + len(self.networks)}.0.0/16"}
            if not (internal and options.get(oci_module._ISOLATED_GATEWAY) == "isolated" and self.isolated_applies):
                config["Gateway"] = f"172.{30 + len(self.networks)}.0.1"
            self.networks[name] = {"Name": name, "Internal": internal, "EnableIPv6": False, "Options": options,
                                   "IPAM": {"Config": [config]}, "labels": self._labels(args)}
            return self.ok(f"{name}-id")
        if args[:2] == ["network", "inspect"]:
            found = self.networks.get(args[-1])
            return self.ok(json.dumps([found])) if found else self.fail(f"Error: network {args[-1]} not found")
        if args[:2] == ["network", "connect"]:
            self.containers[args[-1]]["networks"].append(args[2])
            return self.ok()
        if args[:2] == ["network", "rm"]:
            self.networks.pop(args[-1], None)
            return self.ok(args[-1])
        if args[:2] == ["network", "ls"]:
            wanted = _flag_values(args, "--filter")[0].split("=", 1)[1].split("=", 1)
            return self.ok("\n".join(name for name, network in self.networks.items()
                                     if network["labels"].get(wanted[0]) == wanted[1]))
        if head == "ps":
            wanted = _flag_values(args, "--filter")[0].split("=", 1)[1].split("=", 1)
            return self.ok("\n".join(name for name, container in self.containers.items()
                                     if container["labels"].get(wanted[0]) == wanted[1]))
        if head == "logs":
            return self.ok()
        raise AssertionError(f"the fake engine was sent an unexpected command: {args}")

    def attach(self, args, *, stdout_path, stderr_path, stdin_text, timeout, on_timeout):
        self.calls.append(list(args))
        self.extra_envs.append({})
        container = self.containers[args[-1]]
        with os.fdopen(oci_module._open_output(Path(stdout_path)), "wb") as out, \
                os.fdopen(oci_module._open_output(Path(stderr_path)), "wb") as err:
            if self.unstartable:
                err.write(b"Error response from daemon: failed to create task for container: exec: "
                          b"\"scanner\": executable file not found in $PATH\n")
                container["state"].update(ExitCode=127, Error='exec: "scanner": executable file not found in $PATH')
                return 1, False
            container["state"].update(Status="running", Running=True, StartedAt="2026-09-20T15:00:00.2Z")
            outcome = self.behavior(container, out, err, stdin_text)
        if outcome == "timeout":
            on_timeout()
            return None, True
        code, oom = outcome if isinstance(outcome, tuple) else (outcome, False)
        container["state"].update(Status="exited", Running=False, ExitCode=code, OOMKilled=oom)
        return code, False

    def creates(self, role: str = "worker") -> list[list[str]]:
        return [call for call in self.calls
                if call[0] == "create" and f"scaneval.role={role}" in _flag_values(call, "--label")]


def prepared_input(tmp_path: Path, *, languages=("python",)) -> PreparedInput:
    source = tmp_path / "trial" / "source"
    source.mkdir(parents=True)
    (source / "app.py").write_text(VULNERABLE, encoding="utf-8")
    digest = hash_exported_tree(source)["tree_hash"]
    return PreparedInput("input-a", source, digest, tuple(languages), {"source": {"commit": "x"}})


class ScannerAdapter(Adapter):
    """Runs one containerized command and turns the JSON it prints into claims."""

    name = "container-fixture"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})
    oci_compatible = True

    def __init__(self, *, mounts=(), state_dirs=(), stdin_text=None):
        self.mounts = tuple(mounts)
        self.state_dirs = tuple(state_dirs)
        self.stdin_text = stdin_text
        self.results: list[CommandResult] = []
        self.prepared = 0

    def prepare(self, spec, cache_root):
        self.prepared += 1
        return {"fixture": True}

    def runtime_mounts(self, spec, preparation):
        return self.mounts

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        stdout = raw_dir / "scanner.json"
        result = run_command(["scanner", "--json", "."], cwd=source_dir, timeout_seconds=timeout_seconds,
                             env=build_env(("SCANEVAL_FIXTURE_TOKEN",)), stdout_path=stdout,
                             stderr_path=raw_dir / "scanner.stderr.txt", stdin_text=self.stdin_text)
        self.results.append(result)
        artifacts = [{"id": "scanner-json", "path": stdout}]
        if result.timed_out:
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True, command=result.argv,
                                 error={"code": "timeout", "message": "killed"}, artifacts=artifacts)
        if result.exit_code != 0:
            return NativeOutcome(status="error", exit_code=result.exit_code, command=result.argv,
                                 error={"code": f"exit_{result.exit_code}", "message": "scanner failed"},
                                 artifacts=artifacts)
        findings = json.loads(stdout.read_text(encoding="utf-8"))["findings"]
        claims = [{"claim_id": f"c{index}", "allegation": "shell=True with a caller-controlled command",
                   "kind": "command_injection", "native_rule_id": "fixture.shell", "raw_artifact_id": "scanner-json",
                   "primary_location": {"path": finding["path"], "start_line": finding["line"],
                                        "end_line": finding["line"]}}
                  for index, finding in enumerate(findings, start=1)]
        return NativeOutcome(status="success", exit_code=0, command=result.argv, claims=claims,
                             artifacts=artifacts, capture={"model_requests": "not_applicable"})


def finds_one(container, out, err, stdin_text):
    out.write(b'{"findings": [{"path": "src/app.py", "line": 5}]}\n')
    return 0


def backend(tmp_path: Path, fake: FakeDocker, policy: str = "none", *, adapter=None, **kwargs) -> OciBackend:
    scratch = tmp_path / "scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    adapter = adapter or ScannerAdapter()
    return OciBackend(kwargs.pop("execution", None) or settings(policy), run_id="run-1",
                      invocation_id="input-a__fixture__r1", scratch_root=scratch,
                      state_dirs=tuple(adapter.state_dirs),
                      runtime_mounts=lambda: adapter.runtime_mounts(None, {}), docker=fake, **kwargs)


def invoke(tmp_path: Path, fake: FakeDocker, policy: str = "none", *, adapter=None, prepared=None,
           **kwargs) -> tuple[Path, OciBackend]:
    adapter = adapter or ScannerAdapter()
    held = backend(tmp_path, fake, policy, adapter=adapter, **kwargs)
    try:
        bundle = run_invocation(prepared=prepared or prepared_input(tmp_path), adapter=adapter,
                                spec=SystemSpec("fixture", "container-fixture", {}), preparation={},
                                out_dir=tmp_path / "out", run_id="run-1", network_policy=policy,
                                workspace_root=held.workspace_root, clock=CLOCK, backend=held)
    finally:
        held.close()
    return bundle, held


def documents(bundle: Path) -> tuple[dict, dict]:
    return (json.loads((bundle / "result.json").read_text(encoding="utf-8")),
            json.loads((bundle / "execution.json").read_text(encoding="utf-8")))


def test_every_scanner_container_gets_the_hardening_settings_and_identity_mounts_only(tmp_path):
    cache = tmp_path / "cache"
    rules = cache / "rules__abc"
    rules.mkdir(parents=True)
    fake = FakeDocker(behavior=finds_one)
    adapter = ScannerAdapter(mounts=(str(rules),), state_dirs=(".scannerstate",))
    bundle, held = invoke(tmp_path, fake, adapter=adapter, runtime_roots=(cache,))
    result, execution = documents(bundle)
    assert result["status"] == "success" and len(result["claims"]) == 1
    [create] = fake.creates()
    for expected in (["--read-only"], ["--cap-drop", "ALL"], ["--security-opt", "no-new-privileges"],
                     ["--user", "65534:65534"], ["--ipc", "none"], ["--init"], ["--pids-limit", "256"],
                     ["--memory", "2048m"], ["--memory-swap", "2048m"], ["--cpus", "2"],
                     ["--ulimit", "core=0:0"], ["--ulimit", "nofile=4096:4096"],
                     ["--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777"], ["--pull", "never"],
                     ["--network", "none"], ["--env", "HOME=/tmp"], ["--env", "TMPDIR=/tmp"],
                     ["--entrypoint", "scanner"]):
        assert any(create[index:index + len(expected)] == expected for index in range(len(create))), expected
    assert create[-3:] == [IMAGE, "--json", "."]
    for forbidden in ("--rm", "-v", "--volume", "--privileged", "--cap-add"):
        assert forbidden not in create, forbidden
    mounts = _flag_values(create, "--mount")
    for value in mounts:
        fields = dict(field.split("=", 1) if "=" in field else (field, True) for field in value.split(","))
        assert fields["type"] == "bind" and fields["src"] == fields["dst"], value
    by_role = {entry["role"]: entry for entry in execution["isolation"]["mounts"]}
    assert set(by_role) == {"source", "state", "raw", "runtime", "scratch"}
    assert by_role["source"]["mode"] == "ro" and by_role["runtime"]["mode"] == "ro"
    assert by_role["raw"]["mode"] == "rw" and by_role["state"]["mode"] == "rw"
    workdir = _flag_values(create, "--workdir")[0]
    assert workdir.endswith("/source") and workdir == [src for src in _mount_sources(create)
                                                       if src.endswith("/source")][0]
    # Nothing broad is ever mounted: not the home directory, not the run, not the cache, not the socket.
    for source in _mount_sources(create):
        assert source not in (str(Path.home()), "/", "/var/run/docker.sock", str(cache))
        assert not str(tmp_path / "out").startswith(source)
    # The container was stopped, read, and removed by name after it ran, and the record says so.
    name = _flag_values(create, "--name")[0]
    assert ["rm", "--force", name] in fake.calls and name not in fake.containers
    [container] = [item for item in execution["isolation"]["containers"] if item["role"] == "worker"]
    assert container["removed"] is True and container["exit_code"] == 0 and container["oom_killed"] is False
    assert container["started"] is True and container["status"] == "exited"


def test_credentials_reach_the_container_by_name_only_and_never_appear_in_a_record(tmp_path, monkeypatch):
    secret = "sk-fixture-" + "9" * 24
    monkeypatch.setenv("FIXTURE_API_KEY", secret)
    monkeypatch.delenv("FIXTURE_UNSET_KEY", raising=False)
    monkeypatch.setenv("SCANEVAL_FIXTURE_TOKEN", "dropped-not-declared")
    fake = FakeDocker(behavior=finds_one)
    execution_settings = settings(credentials=[{"env": "FIXTURE_API_KEY", "provider": "fixture"},
                                               {"env": "FIXTURE_UNSET_KEY", "provider": "fixture"}])
    bundle, _held = invoke(tmp_path, fake, execution=execution_settings)
    [create] = fake.creates()
    index = fake.calls.index(create)
    assert ["--env", "FIXTURE_API_KEY"] == create[create.index("FIXTURE_API_KEY") - 1:create.index("FIXTURE_API_KEY") + 1]
    assert all(secret not in word for call in fake.calls for word in call)
    assert fake.extra_envs[index] == {"FIXTURE_API_KEY": secret}
    assert "FIXTURE_UNSET_KEY" not in create and "SCANEVAL_FIXTURE_TOKEN" not in " ".join(create)
    for name in ("result.json", "execution.json", "request.json"):
        assert secret not in (bundle / name).read_text(encoding="utf-8")
    environment = documents(bundle)[1]["isolation"]["settings"]["environment"]
    assert environment["credentials"] == [{"env": "FIXTURE_API_KEY", "passed": True, "provider": "fixture"},
                                          {"env": "FIXTURE_UNSET_KEY", "passed": False, "provider": "fixture"}]
    assert "SCANEVAL_FIXTURE_TOKEN" in environment["dropped"] and "PATH" in environment["dropped"]


def test_a_timeout_kills_the_container_by_name_then_inspects_and_removes_it(tmp_path):
    fake = FakeDocker(behavior=lambda *args: "timeout")
    bundle, _held = invoke(tmp_path, fake)
    result, execution = documents(bundle)
    assert result["status"] == "timeout" and execution["timed_out"] is True
    name = _flag_values(fake.creates()[0], "--name")[0]
    order = [call[0] if call[0] != "container" else "inspect" for call in fake.calls
             if call[-1] == name and call[0] in ("kill", "rm", "start", "container")]
    assert order == ["start", "kill", "inspect", "rm", "inspect"]
    [container] = execution["isolation"]["containers"]
    assert container["timed_out"] is True and container["removed"] is True and container["exit_code"] == 137


def test_an_error_while_attached_still_stops_reads_and_removes_the_container(tmp_path):
    """Whatever ends the attach, the container is killed if it runs and read before it is removed."""

    def interrupted(container, out, err, stdin_text):
        raise RuntimeError("the docker client lost its connection to the engine")

    fake = FakeDocker(behavior=interrupted)
    bundle, _held = invoke(tmp_path, fake)
    result, execution = documents(bundle)
    assert result["status"] == "error" and result["error"]["code"] == "adapter_failure"
    assert "lost its connection" in result["error"]["message"]
    name = _flag_values(fake.creates()[0], "--name")[0]
    order = [call[0] if call[0] != "container" else "inspect" for call in fake.calls if call[-1] == name]
    assert order == ["start", "inspect", "kill", "inspect", "rm", "inspect"]
    [container] = execution["isolation"]["containers"]
    assert container["removed"] is True and container["exit_code"] == 137 and container["started"] is True


def test_an_oom_kill_is_read_from_inspection_and_recorded(tmp_path):
    fake = FakeDocker(behavior=lambda *args: (137, True))
    bundle, _held = invoke(tmp_path, fake, execution=settings(limits={"memory_mb": 128, "tmpfs_mb": 16}))
    result, execution = documents(bundle)
    assert result["status"] == "error" and result["error"]["code"] == "exit_137"
    [container] = execution["isolation"]["containers"]
    assert container["oom_killed"] is True and container["exit_code"] == 137
    assert execution["isolation"]["settings"]["memory_mb"] == execution["isolation"]["settings"]["memory_swap_mb"] == 128
    assert "recorded an out-of-memory kill under the 128 MB limit" in execution["isolation"]["note"]


def test_an_oom_kill_under_a_clean_exit_is_a_failure_not_a_clean_success(tmp_path):
    """A process of the scan was killed while the command reported success; the claims cannot stand."""

    def starved(container, out, err, stdin_text):
        finds_one(container, out, err, stdin_text)
        return 0, True

    fake = FakeDocker(behavior=starved)
    bundle, _held = invoke(tmp_path, fake)
    result, execution = documents(bundle)
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "adapter_failure" and "out-of-memory kill" in result["error"]["message"]
    [container] = execution["isolation"]["containers"]
    assert container["oom_killed"] is True and container["exit_code"] == 0 and container["removed"] is True
    # The container did run, under the recorded limits, so what bounded it is still recorded as enforced.
    assert execution["isolation"]["enforced"] is True
    assert (bundle / "raw" / "scanner.json").is_file()


def test_a_container_the_engine_could_not_start_is_a_refusal_and_nothing_is_enforced(tmp_path):
    """Docker leaves a container whose start failed in ``created``; counting it as run would claim enforcement."""
    fake = FakeDocker(unstartable=True)
    bundle, _held = invoke(tmp_path, fake)
    result, execution = documents(bundle)
    validate_document("execution-record", execution)
    assert result["status"] == "error" and result["error"]["code"] == "adapter_failure"
    assert "could not start the container for scanner" in result["error"]["message"]
    assert "executable file not found" in result["error"]["message"]
    assert execution["isolation"]["enforced"] is False and execution["network_policy"]["enforced"] is False
    assert execution["isolation"]["note"] == oci_module.NOTHING_RAN_NOTE
    [container] = execution["isolation"]["containers"]
    assert container["created"] is True and container["started"] is False and container["exit_code"] == 127
    assert container["removed"] is True and fake.containers == {}


def test_output_paths_a_container_could_have_planted_are_never_written_through(tmp_path):
    """A link, a pipe, or a second name left where the next command's output goes is refused, not followed."""
    secret = tmp_path / "host-only.txt"
    secret.write_text("host-only\n", encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    fresh = oci_module._open_output(raw / "fresh.txt")
    os.write(fresh, b"new")
    os.close(fresh)
    existing = raw / "existing.txt"
    existing.write_text("old content that is longer\n", encoding="utf-8")
    descriptor = oci_module._open_output(existing)
    os.write(descriptor, b"new")
    os.close(descriptor)
    assert (raw / "fresh.txt").read_bytes() == b"new" and existing.read_bytes() == b"new"
    (raw / "linked.txt").symlink_to(secret)
    os.link(secret, raw / "hard.txt")
    (raw / "directory").mkdir()
    for name, code in (("linked.txt", errno.ELOOP), ("hard.txt", errno.EMLINK), ("directory", errno.EISDIR)):
        with pytest.raises(OSError) as raised:
            oci_module._open_output(raw / name)
        assert raised.value.errno == code, name
    if hasattr(os, "mkfifo"):
        os.mkfifo(raw / "pipe.txt")
        with pytest.raises(OSError):
            finishes(lambda: oci_module._open_output(raw / "pipe.txt"))
    assert secret.read_text(encoding="utf-8") == "host-only\n"

    # A directory under a writable mount replaced by a link out of it: refused before any container.
    held = backend(tmp_path / "held", FakeDocker())
    held._mounts = [oci_module._Mount(str(raw), "rw", "raw")]
    (raw / "nested").symlink_to(tmp_path)
    with pytest.raises(OSError, match="resolves outside its writable mount"):
        held._check_output(raw / "nested" / "out.txt")
    held._check_output(raw / "out.txt")
    held.close()


def test_the_docker_client_never_writes_output_through_a_planted_link_and_kills_a_client_that_hangs(
        tmp_path, monkeypatch):
    """The real client, against a stand-in CLI: the open is refused before anything starts."""
    started = tmp_path / "cli-started"
    cli = tmp_path / "docker"
    cli.write_text(f"#!{sys.executable}\nimport signal, sys, time\n"
                   f"open({str(started)!r}, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n"
                   "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                   "print('streamed', flush=True)\n"
                   "time.sleep(60) if 'hang' in sys.argv else None\n", encoding="utf-8")
    cli.chmod(0o755)
    client = DockerClient(binary=str(cli))
    secret = tmp_path / "host-only.txt"
    secret.write_text("host-only\n", encoding="utf-8")
    out, err = tmp_path / "out.txt", tmp_path / "err.txt"
    out.symlink_to(secret)
    with pytest.raises(OSError):
        client.attach(["start", "--attach", "c1"], stdout_path=out, stderr_path=err, stdin_text=None,
                      timeout=30, on_timeout=lambda: None)
    assert not started.exists() and secret.read_text(encoding="utf-8") == "host-only\n"
    out.unlink()
    assert client.attach(["start", "--attach", "c1"], stdout_path=out, stderr_path=err, stdin_text=None,
                         timeout=30, on_timeout=lambda: None) == (0, False)
    assert out.read_text(encoding="utf-8") == "streamed\n"

    monkeypatch.setattr(oci_module, "KILL_GRACE", 0.5)
    killed = []
    begun = time.monotonic()
    assert client.attach(["start", "--attach", "hang"], stdout_path=out, stderr_path=err, stdin_text=None,
                         timeout=0.5, on_timeout=lambda: killed.append(True)) == (None, True)
    assert killed == [True] and time.monotonic() - begun < 20


def assert_refused(bundle: Path, fragment: str) -> dict:
    result, execution = documents(bundle)
    validate_document("execution-record", execution)
    assert result["status"] == "error" and result["claims"] == []
    assert result["error"]["code"] == "adapter_failure" and "IsolationError" in result["error"]["message"]
    assert fragment in result["error"]["message"]
    isolation_block = execution["isolation"]
    assert isolation_block["backend"] == "oci" and isolation_block["enforced"] is False
    assert fragment in isolation_block["note"] and "No scanner process ran" in isolation_block["note"]
    assert execution["network_policy"]["enforced"] is False
    return execution


def test_a_mount_the_daemon_cannot_see_is_a_recorded_refusal_and_no_scanner_starts(tmp_path):
    fake = FakeDocker(behavior=finds_one, invisible=(tmp_path / "scratch",))
    bundle, _held = invoke(tmp_path, fake)
    execution = assert_refused(bundle, "not visible to the Docker daemon")
    assert "--workspace-root" in execution["isolation"]["note"]
    assert not [call for call in fake.calls if call[0] == "start"] and fake.creates() == []
    assert fake.containers == {}


def test_an_unreachable_engine_and_a_missing_image_are_refusals(tmp_path):
    bundle, _held = invoke(tmp_path / "a", FakeDocker(reachable=False))
    assert_refused(bundle, "engine is not reachable")
    bundle, _held = invoke(tmp_path / "b", FakeDocker(images=()))
    assert_refused(bundle, "never pulls one")


def test_model_provider_only_refuses_a_scan_network_the_engine_did_not_isolate(tmp_path):
    """The engine accepts an option it does not apply, so the network is judged by inspection."""
    fake = FakeDocker(isolated_applies=False)
    bundle, _held = invoke(tmp_path, fake, "model_provider_only")
    execution = assert_refused(bundle, "did not make the scan network isolated")
    assert fake.networks == {} and fake.containers == {}
    assert all(network["removed"] for network in execution["isolation"]["network"]["networks"])


def test_runtime_mounts_are_allowed_only_inside_the_source_cache_and_never_widen_what_the_scanner_sees(
        tmp_path, monkeypatch):
    home = tmp_path / "home"
    checkout = home / "cache" / "checkout"
    checkout.mkdir(parents=True)
    (home / "run").mkdir()
    (home / "elsewhere").mkdir()
    socketed = home / "cache" / "socketed"
    socketed.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(socketed)
    listener = socket.socket(socket.AF_UNIX)
    listener.bind("engine.sock")  # relative, so the path length limit of AF_UNIX is not the test's problem
    try:
        for declared, fragment in ((str(home), "home directory"), ("/", "home directory"),
                                   (str(home / "run"), "evaluator material"),
                                   (str(home / "cache"), "only one checkout inside it"),
                                   (str(home / "elsewhere"), "is not inside ~/cache"),
                                   (str(socketed), "holds a unix socket (engine.sock)"),
                                   ("relative/path", "not an absolute path"),
                                   (str(home / "missing"), "does not exist")):
            fake = FakeDocker(behavior=finds_one)
            target = tmp_path / f"case-{abs(hash(declared))}"
            target.mkdir()
            bundle, _held = invoke(target, fake, adapter=ScannerAdapter(mounts=(declared,)),
                                   protected=(home / "run",), runtime_roots=(home / "cache",))
            assert_refused(bundle, fragment)
    finally:
        listener.close()
    # With no runtime root given, nothing may be mounted at all.
    bundle, _held = invoke(tmp_path / "rootless", FakeDocker(behavior=finds_one),
                           adapter=ScannerAdapter(mounts=(str(checkout),)))
    assert_refused(bundle, "no runtime root was given")
    # One checkout inside the cache is exactly what may be mounted.
    fake = FakeDocker(behavior=finds_one)
    bundle, _held = invoke(tmp_path / "allowed", fake, adapter=ScannerAdapter(mounts=(str(checkout),)),
                           protected=(home / "run",), runtime_roots=(home / "cache",))
    assert documents(bundle)[0]["status"] == "success"
    assert str(checkout) in _mount_sources(fake.creates()[0])


def test_model_provider_only_runs_the_scanner_behind_the_proxy_and_reads_back_its_decisions(tmp_path):
    log = "".join(json.dumps(entry) + "\n" for entry in (
        {"event": "listening", "port": 3128},
        {"event": "allow", "host": "api.model.example", "port": 443, "outcome": "connected"},
        {"event": "deny", "host": "exfil.example", "port": 443, "reason": "not a declared destination"},
        {"event": "deny", "target": "http://plain.example/", "reason": "only CONNECT is forwarded"}))
    fake = FakeDocker(behavior=finds_one, proxy_log=log)
    bundle, _held = invoke(tmp_path, fake, "model_provider_only")
    result, execution = documents(bundle)
    validate_document("execution-record", execution)
    assert result["status"] == "success" and execution["network_policy"]["enforced"] is True
    [proxy_create] = fake.creates("proxy")
    [worker_create] = fake.creates("worker")
    internal, egress = [network["name"] for network in execution["isolation"]["network"]["networks"]]
    assert ["--network", internal] == worker_create[worker_create.index("--network"):worker_create.index("--network") + 2]
    assert ["network", "connect", internal, _flag_values(proxy_create, "--name")[0]] in fake.calls
    assert _flag_values(proxy_create, "--network") == [egress]
    assert ["--sysctl", "net.ipv4.ip_forward=0"] == proxy_create[proxy_create.index("--sysctl"):proxy_create.index("--sysctl") + 2]
    assert _flag_values(proxy_create, "--allow") == ["api.model.example:443"]
    for flag in ("--read-only", "--init"):
        assert flag in proxy_create
    assert _flag_values(proxy_create, "--user") == ["65534:65534"] and ["--cap-drop", "ALL"] == proxy_create[
        proxy_create.index("--cap-drop"):proxy_create.index("--cap-drop") + 2]
    assert "HTTPS_PROXY=http://172.30.0.3:3128" in _flag_values(worker_create, "--env")
    assert "HTTP_PROXY=http://172.30.0.3:3128" in _flag_values(worker_create, "--env")
    network = execution["isolation"]["network"]
    assert network["policy"] == "model_provider_only" and network["enforced"] is True
    assert network["networks"][0]["gateway_mode_ipv4"] == "isolated" and network["networks"][0]["gateways"] == []
    proxy = network["proxy"]
    assert proxy["allowed"] == 1 and proxy["denied"] == 2 and proxy["log"] == "read"
    assert "exfil.example:443" in proxy["denied_destinations"] and "log_dir" not in proxy
    assert fake.networks == {} and fake.containers == {}
    assert all(item["removed"] for item in execution["isolation"]["containers"])


def test_unrestricted_is_recorded_as_not_enforced_with_the_host_loopback_caveat(tmp_path):
    fake = FakeDocker(behavior=finds_one)
    bundle, _held = invoke(tmp_path, fake, "unrestricted")
    result, execution = documents(bundle)
    validate_document("execution-record", execution)
    assert result["status"] == "success"
    assert execution["isolation"]["enforced"] is True and execution["network_policy"]["enforced"] is False
    assert execution["isolation"]["network"]["enforced"] is False
    assert "host's own loopback" in execution["isolation"]["network"]["note"]
    assert "Colima" in execution["isolation"]["network"]["note"]
    [bridge] = execution["isolation"]["network"]["networks"]
    assert bridge["internal"] is False and bridge["removed"] is True


def test_an_oci_record_is_2_1_with_home_relative_mounts_and_nothing_enforced_when_nothing_ran(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    bundle, _held = invoke(tmp_path, FakeDocker(behavior=finds_one))
    result, execution = documents(bundle)
    validate_document("execution-record", execution)
    assert execution["schema_version"] == "2.1" and result["schema_version"] == "2.0"
    assert execution["provenance"]["mode"] == "full" and execution["provenance"]["pr"] is None
    block = execution["isolation"]
    assert block["enforced"] is True and block["runtime"]["server_version"] == "29.2.1"
    assert block["image"]["id"] == "sha256:" + "a" * 64
    assert block["image"]["repo_digests"] == ["scanner@sha256:" + "a" * 64]
    assert all(entry["target"].startswith("~/") for entry in block["mounts"] if entry["role"] != "scratch")
    assert str(tmp_path) not in json.dumps(block)
    assert block["settings"]["uid"] == 65534 and block["settings"]["read_only_root_filesystem"] is True
    # An invocation whose language the adapter does not support starts nothing, and says so.
    unsupported = prepared_input(tmp_path / "go", languages=("go",))
    bundle, _held = invoke(tmp_path / "go", FakeDocker(), prepared=unsupported)
    result, execution = documents(bundle)
    assert result["status"] == "unsupported" and execution["isolation"]["enforced"] is False
    assert execution["isolation"]["note"].startswith("No scanner process was started")


def test_close_removes_what_the_session_left_and_reports_what_it_cannot(tmp_path):
    """The session label is what close() sweeps by, so a stray container of this invocation goes too."""

    class StubbornDocker(FakeDocker):
        def run(self, args, *, timeout, extra_env=None):
            if args[0] == "rm":
                self.calls.append(list(args))
                return self.fail("Error response from daemon: removal of container stray is already in progress")
            return super().run(args, timeout=timeout, extra_env=extra_env)

    for fake, expected in ((FakeDocker(isolated_applies=False), 0), (StubbornDocker(isolated_applies=False), 1)):
        root = tmp_path / type(fake).__name__
        held = backend(root, fake, "model_provider_only")
        (held.workspace_root / "scaneval-trial-x" / "source").mkdir(parents=True)
        (held.workspace_root / "scaneval-trial-x" / "raw").mkdir()
        # A preflight refused after it had created something on the engine: close() must sweep.
        with pytest.raises(IsolationError, match="isolated"):
            with held.activate():
                pass
        fake.containers["stray"] = {"labels": {"scaneval.session": held._session}, "state": {}}
        problems = held.close()
        assert len(problems) == expected and not held._private.exists()
        assert ("stray" in fake.containers) is bool(expected)
        if expected:
            assert "could not be removed" in problems[0] and held._session in problems[0]


@pytest.mark.parametrize("role", ["probe", "worker"])
def test_a_create_the_client_gave_up_on_leaves_nothing_on_the_engine(tmp_path, role):
    """A create that timed out on the client may still have made the container on the engine.

    The mount probe's container used to be one nothing removed: the removal came after the create
    returned, and close() swept only a backend that had recorded touching the engine, which a create
    that raised had not yet done.
    """

    class SlowCreate(FakeDocker):
        def run(self, args, *, timeout, extra_env=None):
            if args[0] == "create" and f"scaneval.role={role}" in _flag_values(args, "--label"):
                super().run(args, timeout=timeout, extra_env=extra_env)
                raise IsolationError(f"docker create gave no answer within {timeout:g}s")
            return super().run(args, timeout=timeout, extra_env=extra_env)

    fake = SlowCreate(behavior=finds_one)
    bundle, _held = invoke(tmp_path, fake)
    if role == "probe":
        assert_refused(bundle, "gave no answer")
    else:
        result, _execution = documents(bundle)
        assert result["status"] == "error" and "gave no answer" in result["error"]["message"]
    assert fake.containers == {}


def test_backend_for_builds_nothing_for_local_and_refuses_what_refusal_for_refuses(tmp_path):
    assert backend_for(resolve_execution(None, "none"), adapter=ScannerAdapter(), spec=None, preparation={},
                       run_id="r", invocation_id="i", scratch_root=tmp_path) is None
    for name in ("llm-harness", "deepsec"):
        with pytest.raises(IsolationError, match="refuses adapter"):
            backend_for(settings(), adapter=get_adapter(name), spec=None, preparation={}, run_id="r",
                        invocation_id="i", scratch_root=tmp_path)
    assert list(tmp_path.iterdir()) == []
    held = backend_for(settings(), adapter=ScannerAdapter(), spec=None, preparation={}, run_id="r",
                       invocation_id="i", scratch_root=tmp_path)
    assert isinstance(held, OciBackend) and held.workspace_root.is_dir()
    assert held.close() == [] and list(tmp_path.iterdir()) == []


# --- semgrep under oci -----------------------------------------------------------------------


def test_semgrep_takes_the_images_own_binary_under_oci_and_mounts_its_pinned_checkout(tmp_path):
    assert SemgrepAdapter.oci_compatible is True and refusal_for(SemgrepAdapter(), settings()) is None
    spec = SystemSpec("semgrep", "semgrep", {})
    held = RecordingBackend()
    held.name = "oci"
    with base_module.routed_through(held):
        assert _binary(spec) == "semgrep"
        assert _binary(SystemSpec("semgrep", "semgrep", {"binary": "/opt/semgrep"})) == "/opt/semgrep"
    root = tmp_path / "cache" / "rules__abc"
    preparation = {"ruleset": {"commit": "a" * 40, "tree_hash": "sha256:" + "b" * 64},
                   "config_dirs": [str(root / "python"), str(root / "go")], "ruleset_root": str(root)}
    assert SemgrepAdapter().runtime_mounts(spec, preparation) == (str(root),)
    legacy = {key: value for key, value in preparation.items() if key != "ruleset_root"}
    assert SemgrepAdapter().runtime_mounts(spec, legacy) == (str(root / "go"), str(root / "python"))
    with pytest.raises(AdapterError, match="run prepare"):
        SemgrepAdapter().runtime_mounts(spec, {})


# --- the runner ------------------------------------------------------------------------------


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


@pytest.fixture
def pilot(tmp_path: Path) -> dict:
    repo = tmp_path / "upstream"
    (repo / "src").mkdir(parents=True)
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "src" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    pack = cases.new_pack("test", "isolation-pilot", "Local fixture pack for the isolation tests.")
    cases.add_snapshot(pack, {
        "snapshot_id": "snap-a", "repository": {"url": str(repo), "name": "widget"},
        "commit": git("rev-parse", "HEAD", cwd=repo), "reference": "Fixture commit; no advisory is claimed.",
        "languages": ["python"], "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}})
    cases.add_case(pack, cases.draft_case(
        "case-a", snapshot_id="snap-a", kind="command_injection",
        description="Caller-controlled command string reaches subprocess with shell=True.",
        represents=REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                 reference="src/app.py", note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "sink", "note": ""}]))
    cases.save_pack(tmp_path / "pack.json", pack)
    (tmp_path / "work").mkdir()
    return {"root": tmp_path, "work": tmp_path / "work"}


def write_config(root: Path, systems: list[dict], *, policy: str = "none") -> Path:
    config = {"schema_version": "2.1", "run_id": "run-oci", "pack": "pack.json", "cache_root": "cache",
              "inputs": [{"snapshot_id": "snap-a"}], "systems": systems, "repetitions": 1,
              "timeout_seconds": 60, "trace_mode": "off", "network_policy": policy}
    path = root / "run-config.json"
    path.write_text(canonical_json(config) + "\n", encoding="utf-8")
    return path


def test_the_runner_skips_llm_harness_and_deepsec_under_oci_before_they_prepare(pilot, monkeypatch):
    prepared = []
    for name in ("llm-harness", "deepsec"):
        adapter_class = type(get_adapter(name))
        monkeypatch.setattr(adapter_class, "prepare", lambda self, spec, cache_root: prepared.append(spec.system_id))
    oci = {"backend": "oci", "image": IMAGE}
    config = write_config(pilot["root"], [
        {"system_id": "harness-oci", "adapter": "llm-harness", "config": {}, "execution": oci},
        {"system_id": "deepsec-oci", "adapter": "deepsec", "config": {}, "execution": oci}])
    manifest = run_from_config(config, pilot["root"] / "out", clock=CLOCK, workspace_root=pilot["work"])
    assert prepared == []
    for system in manifest["systems"]:
        assert system["skipped_reason"].startswith("IsolationError: the oci execution backend refuses adapter")
        assert system["preparation"] == {}
    assert {row["status"] for row in manifest["invocations"]} == {"skipped"}
    assert all("refuses adapter" in row["skipped_reason"] for row in manifest["invocations"])
    assert list(pilot["work"].iterdir()) == []


def test_a_system_whose_execution_block_cannot_be_held_is_skipped_never_run_locally(pilot):
    """The contract accepts these limits; the backend cannot hold them, so the system is not run at all."""
    adapter = ScannerAdapter()
    config = write_config(pilot["root"], [{
        "system_id": "fixture-oci", "adapter": "container-fixture", "config": {},
        "execution": {"backend": "oci", "image": IMAGE, "limits": {"memory_mb": 128, "tmpfs_mb": 128}}}])
    manifest = run_from_config(config, pilot["root"] / "out", clock=CLOCK, workspace_root=pilot["work"],
                               adapters={"container-fixture": adapter})
    [system] = manifest["systems"]
    assert system["skipped_reason"].startswith("IsolationError: execution.limits.tmpfs_mb (128) must be smaller")
    [row] = manifest["invocations"]
    assert row["status"] == "skipped" and adapter.prepared == 0 and adapter.results == []


def test_the_runner_runs_an_oci_compatible_adapter_in_containers_and_leaves_nothing_behind(pilot, monkeypatch, tmp_path):
    fake = FakeDocker(behavior=finds_one)
    monkeypatch.setattr(oci_module, "DockerClient", lambda: fake)
    adapter = ScannerAdapter()
    config = write_config(pilot["root"], [{"system_id": "fixture-oci", "adapter": "container-fixture", "config": {},
                                           "execution": {"backend": "oci", "image": IMAGE}}])
    out = pilot["root"] / "out"
    manifest = run_from_config(config, out, clock=CLOCK, workspace_root=pilot["work"],
                               adapters={"container-fixture": adapter})
    [row] = manifest["invocations"]
    assert manifest["status"] == "completed" and row["status"] == "success" and row["claim_records"] == 1
    assert adapter.prepared == 1
    assert not [warning for warning in manifest["warnings"] if "oci" in warning or "scratch" in warning]
    bundle = out / row["bundle_path"]
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    assert execution["schema_version"] == "2.1" and execution["isolation"]["enforced"] is True
    assert execution["network_policy"] == {"declared": "none", "enforced": True,
                                           "note": "Enforced by the execution backend; see isolation.network."}
    assert list(pilot["work"].iterdir()) == [] and fake.containers == {} and fake.networks == {}
    # No mount reaches the run directory, where the frozen pack and the labels live.
    for source in _mount_sources(fake.creates()[0]):
        assert not source.startswith(str(out)) and not str(out).startswith(source + "/")

    # Replay needs neither an engine nor a network: sockets and child processes are both refused.
    def refused(*args, **kwargs):
        raise AssertionError("replay tried to open a socket or start a process")

    monkeypatch.setenv("DOCKER_HOST", "unix:///nonexistent/docker.sock")
    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(subprocess, "Popen", refused)
    replayed = tmp_path / "replayed.json"
    assert main(["replay", str(bundle), "--output", str(replayed)]) == 0
    assert replayed.read_bytes() == (bundle / "evaluation.json").read_bytes()


def test_an_engine_refusal_is_a_recorded_failed_invocation_and_the_run_goes_on(pilot, monkeypatch):
    """Nothing is skipped and nothing runs locally instead: the invocation records the refusal."""
    monkeypatch.setattr(oci_module, "DockerClient", lambda: FakeDocker(reachable=False))
    adapter = ScannerAdapter()
    config = write_config(pilot["root"], [{"system_id": "fixture-oci", "adapter": "container-fixture", "config": {},
                                           "execution": {"backend": "oci", "image": IMAGE}}])
    out = pilot["root"] / "out"
    manifest = run_from_config(config, out, clock=CLOCK, workspace_root=pilot["work"],
                               adapters={"container-fixture": adapter})
    [row] = manifest["invocations"]
    assert manifest["status"] == "completed" and row["status"] == "error" and adapter.results == []
    result = json.loads((out / row["bundle_path"] / "result.json").read_text(encoding="utf-8"))
    assert "engine is not reachable" in result["error"]["message"]
    assert list(pilot["work"].iterdir()) == []
