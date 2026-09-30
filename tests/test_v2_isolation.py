"""The execution backend seam, the selection of a backend, and the egress proxy, without an engine.

These run the pieces of the isolation work that need no engine: the reads of files a scanner
wrote, the routing of ``run_command``, the settings and refusals that decide which backend a
system runs under, and the egress proxy script on the loopback interface. No network beyond
loopback, no model calls, no engine.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

from scaneval import isolation
from scaneval.adapters import get_adapter
from scaneval.adapters import base as base_module
from scaneval.adapters.base import (Adapter, AdapterError, CommandResult, SystemSpec, build_env, run_command,
                                    tail_text)
from scaneval.adapters.semgrep import SemgrepAdapter, semgrep_version
from scaneval.isolation import IsolationError, refusal_for, resolve_execution
from scaneval.isolation import egress_proxy


IMAGE = "scanner:1@sha256:" + "a" * 64
PROXY = "proxy:1@sha256:" + "b" * 64
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
