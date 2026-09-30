"""The oci backend against a real Docker engine: what a hostile scanner can and cannot do inside it.

Every test here starts real containers from images pinned by digest. The module is skipped, with
the reason, when no engine answers or a pinned image is not present locally, except under
``SCANEVAL_REQUIRE_DOCKER=1`` (the ``oci-integration`` CI job), where either is a failure. Nothing
is pulled here: pull the two images first.

Scratch lives under ``~/.cache/scaneval-oci-tests``, because Colima shares only the home
directory with the virtual machine that runs its engine, and every container and network a test
starts carries a label naming it, so each test removes exactly what it made. No model is called
and nothing leaves the machine: the one allowed destination is a fixture service on a local
network.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import random
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid

import pytest

from scaneval import cases
from scaneval.adapters.base import Adapter, NativeOutcome, SystemSpec, build_env, run_command
from scaneval.cli import main
from scaneval.contracts import canonical_json, validate_document
from scaneval.execution import PreparedInput, read_regular_file, run_invocation
from scaneval.isolation import resolve_execution
from scaneval.isolation.oci import OciBackend
from scaneval.materialize import hash_exported_tree
from scaneval.runner import run_from_config


PYTHON_IMAGE = "python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9"
SEMGREP_IMAGE = "semgrep/semgrep:1.177.0@sha256:acaac22ffc7b7cc5926de0751b223bce0b2491c33d18422fa72f632c78d81198"
REQUIRED = os.environ.get("SCANEVAL_REQUIRE_DOCKER") == "1"
CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
              "assumption, and adds a single-file Python sink for the container tests.")
SHELL_RULE = ("rules:\n- id: subprocess-shell-true\n  languages: [python]\n  severity: ERROR\n"
              "  message: subprocess called with shell=True\n"
              "  metadata:\n    cwe: ['CWE-78: OS Command Injection']\n"
              "  pattern: subprocess.run(..., shell=True, ...)\n")


def _docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _engine_problem() -> str | None:
    if not shutil.which("docker"):
        return "the docker CLI is not installed"
    try:
        version = _docker("version", "--format", "{{.Server.Version}}", timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"the docker CLI could not reach an engine: {exc}"
    if version.returncode != 0:
        return f"no Docker engine is reachable: {' '.join(version.stderr.split())[-300:]}"
    missing = [image for image in (PYTHON_IMAGE, SEMGREP_IMAGE)
               if _docker("image", "inspect", image, timeout=60).returncode != 0]
    if missing:
        return f"pinned test image(s) not present locally; docker pull them first: {', '.join(missing)}"
    return None


PROBLEM = _engine_problem()
if PROBLEM is not None:
    if REQUIRED:
        raise RuntimeError(f"SCANEVAL_REQUIRE_DOCKER=1 but {PROBLEM}")
    pytest.skip(PROBLEM, allow_module_level=True)


# --- scratch, labels, and cleanup ----------------------------------------------------------


def _remove_labelled(label: str) -> None:
    for listing, remove in ((["ps", "--all", "--quiet"], ["rm", "--force"]),
                            (["network", "ls", "--quiet"], ["network", "rm"])):
        found = _docker(*listing, "--filter", f"label={label}").stdout.split()
        if found:
            _docker(*remove, *found)


def _remove_scratch(root: Path) -> None:
    """Remove a scratch tree, including what a container user owns on a native Linux engine."""
    for directory, directories, _files in os.walk(root):
        for name in directories:
            try:
                os.chmod(os.path.join(directory, name), 0o700)
            except OSError:
                pass
    shutil.rmtree(root, ignore_errors=True)
    if root.exists():
        # On Linux the container user's files keep its uid, which the operator cannot remove. This
        # one cleanup container runs as root with the engine's default capabilities and sees only
        # the scratch tree; the backend itself never runs anything like it.
        _docker("run", "--rm", "--network", "none", "--label", "scaneval.test=cleanup", "--user", "0:0",
                "--mount", f"type=bind,src={root},dst={root}", "--entrypoint", "rm", PYTHON_IMAGE,
                "-rf", *[str(root / name) for name in os.listdir(root)])
        shutil.rmtree(root, ignore_errors=True)
    assert not root.exists(), f"scratch tree {root} could not be removed"


SCRATCH_PARENT = Path.home() / ".cache" / "scaneval-oci-tests"


@pytest.fixture(scope="module", autouse=True)
def scratch_parent():
    """The directory every test's scratch sits in, removed once when the module is done.

    Not between tests: on Colima the virtual machine keeps resolving a name the host removed and
    re-created to the old directory for about a second, so a scratch made under a parent re-created
    moments earlier is invisible to the daemon, and the backend (correctly) refuses the scan.
    """
    SCRATCH_PARENT.mkdir(parents=True, exist_ok=True)
    yield SCRATCH_PARENT
    try:
        SCRATCH_PARENT.rmdir()  # only when every test's scratch is gone from it
    except OSError:
        pass


@pytest.fixture
def scratch():
    tag = f"t{uuid.uuid4().hex[:10]}"
    root = SCRATCH_PARENT / tag
    root.mkdir()
    try:
        yield root
    finally:
        _remove_labelled(f"scaneval.test={tag}")
        _remove_labelled(f"scaneval.run=run-{tag}")
        _remove_scratch(root)
        assert not _docker("ps", "--all", "--quiet", "--filter", f"label=scaneval.run=run-{tag}").stdout.split()


def run_id(scratch: Path) -> str:
    return f"run-{scratch.name}"


def leftovers(scratch: Path) -> list[str]:
    """Containers and networks any backend of this test's run left on the engine."""
    label = f"label=scaneval.run={run_id(scratch)}"
    return (_docker("ps", "--all", "--quiet", "--filter", label).stdout.split()
            + _docker("network", "ls", "--quiet", "--filter", label).stdout.split())


# --- fixture adapters, inputs, and runs ------------------------------------------------------


class ScriptAdapter(Adapter):
    """Runs one Python script in the pinned Python image: argv is the raw directory, then *args*."""

    name = "script"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})
    oci_compatible = True

    def __init__(self, script: str, *args: str) -> None:
        self.script = script
        self.args = args

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        stdout, stderr = raw_dir / "stdout.txt", raw_dir / "stderr.txt"
        result = run_command(["python3", "-I", "-c", self.script, str(raw_dir), *self.args], cwd=source_dir,
                             timeout_seconds=timeout_seconds, env=build_env(), stdout_path=stdout,
                             stderr_path=stderr)
        artifacts = [{"id": "stdout", "path": stdout}, {"id": "stderr", "path": stderr}]
        if result.timed_out:
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True, command=result.argv,
                                 error={"code": "timeout", "message": "killed at the limit"}, artifacts=artifacts)
        if result.exit_code != 0:
            return NativeOutcome(status="error", exit_code=result.exit_code, command=result.argv,
                                 error={"code": f"exit_{result.exit_code}", "message": "the script failed"},
                                 artifacts=artifacts)
        return NativeOutcome(status="success", exit_code=0, command=result.argv, artifacts=artifacts,
                             capture={"model_requests": "not_applicable"})


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


def repository(path: Path, files: dict[str, str]) -> str:
    path.mkdir(parents=True)
    git("init", "-q", "-b", "main", cwd=path)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=path)
    for name, text in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(text, encoding="utf-8")
    git("add", "-A", cwd=path)
    git("commit", "-q", "-m", "fixture", cwd=path)
    return git("rev-parse", "HEAD", cwd=path)


def pilot(scratch: Path, systems: list[dict], *, policy: str = "none", timeout: float = 120) -> Path:
    """A pack with one snapshot and one case, and a 2.1 run configuration beside it."""
    upstream = scratch / "upstream"
    commit = repository(upstream, {"src/app.py": VULNERABLE, "README.md": "fixture\n"})
    pack = cases.new_pack("test", "oci-pilot", "Local fixture pack for the container tests.")
    cases.add_snapshot(pack, {
        "snapshot_id": "snap-a", "repository": {"url": str(upstream), "name": "widget"}, "commit": commit,
        "reference": "Fixture commit; no advisory is claimed.", "languages": ["python"],
        "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Local fixture repository."}})
    cases.add_case(pack, cases.draft_case(
        "case-a", snapshot_id="snap-a", kind="command_injection",
        description="Caller-controlled command string reaches subprocess with shell=True.",
        represents=REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                 reference="src/app.py", note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "sink", "note": ""}]))
    cases.save_pack(scratch / "pack.json", pack)
    config = {"schema_version": "2.1", "run_id": run_id(scratch), "pack": "pack.json", "cache_root": "cache",
              "inputs": [{"snapshot_id": "snap-a"}], "systems": systems, "repetitions": 1,
              "timeout_seconds": timeout, "trace_mode": "off", "network_policy": policy}
    path = scratch / "run-config.json"
    path.write_text(canonical_json(config) + "\n", encoding="utf-8")
    (scratch / "work").mkdir()
    return path


def script_system(**execution) -> dict:
    return {"system_id": "hostile", "adapter": "script", "config": {},
            "execution": {"backend": "oci", "image": PYTHON_IMAGE, **execution}}


def only_bundle(out: Path, manifest: dict) -> Path:
    [row] = manifest["invocations"]
    return out / row["bundle_path"]


def documents(bundle: Path) -> tuple[dict, dict]:
    result = json.loads((bundle / "result.json").read_text(encoding="utf-8"))
    execution = json.loads((bundle / "execution.json").read_text(encoding="utf-8"))
    validate_document("execution-record", execution)
    return result, execution


def bundle_text(bundle: Path) -> str:
    """Every regular file in the bundle, decoded, so a leaked token can be searched for."""
    parts = []
    for path in sorted(bundle.rglob("*")):
        if path.is_file() and not path.is_symlink():
            parts.append(path.read_bytes().decode("utf-8", "replace"))
    return "\n".join(parts)


def prepared_input(scratch: Path) -> PreparedInput:
    source = scratch / "trial" / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    return PreparedInput("snap-a", source, hash_exported_tree(source)["tree_hash"], ("python",),
                         {"source": {"commit": "x"}})


def invoke(scratch: Path, adapter: Adapter, policy: str = "none", *, timeout: float = 120,
           execution: dict | None = None, **backend_options) -> tuple[Path, OciBackend]:
    """Run one invocation under a real backend at the execution level, then tear it down."""
    block = {"backend": "oci", "image": PYTHON_IMAGE, **(execution or {})}
    held = OciBackend(resolve_execution(block, policy), run_id=run_id(scratch), invocation_id="snap-a__script__r1",
                      scratch_root=scratch, **backend_options)
    try:
        bundle = run_invocation(prepared=prepared_input(scratch), adapter=adapter,
                                spec=SystemSpec("script", "script", {}), preparation={},
                                out_dir=scratch / "out", run_id=run_id(scratch), timeout_seconds=timeout,
                                network_policy=policy, workspace_root=held.workspace_root, clock=CLOCK,
                                backend=held)
    finally:
        assert held.close() == []
    return bundle, held


# --- a hostile scanner's view of the host ----------------------------------------------------


HOSTILE = r'''
import errno, json, os, subprocess, sys
raw, targets = sys.argv[1], json.loads(sys.argv[2])
report = {}
def attempt(label, action):
    try:
        report[label] = {"ok": True, "value": action()}
    except OSError as exc:
        report[label] = {"ok": False, "errno": errno.errorcode.get(exc.errno, str(exc.errno))}
def read(path):
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8", "replace")
def write(path):
    with open(path, "w") as handle:
        handle.write("planted by a hostile scanner\n")
    return "written"
def execute_from_tmp():
    with open("/tmp/probe.sh", "w") as handle:
        handle.write("#!/bin/sh\necho executed\n")
    os.chmod("/tmp/probe.sh", 0o755)
    return subprocess.run(["/tmp/probe.sh"], capture_output=True, text=True).stdout
attempt("read_sentinel", lambda: read(targets["sentinel"]))
attempt("list_sentinel_directory", lambda: os.listdir(os.path.dirname(targets["sentinel"])))
attempt("read_evaluator_pack", lambda: read(targets["pack"]))
attempt("list_run_directory", lambda: os.listdir(targets["run"]))
attempt("read_exported_input", lambda: read(targets["export"]))
attempt("read_upstream_repository", lambda: read(targets["upstream"]))
attempt("write_source", lambda: write(os.path.join(os.getcwd(), "planted.py")))
attempt("write_root", lambda: write("/planted"))
attempt("write_etc", lambda: write("/etc/planted"))
attempt("write_var_tmp", lambda: write("/var/tmp/planted"))
attempt("write_unmounted", lambda: write(os.path.join(targets["scratch"], "planted")))
attempt("mkdir_unmounted", lambda: os.makedirs(os.path.join(targets["scratch"], "planted-dir", "inner")))
attempt("write_dev_shm", lambda: write("/dev/shm/planted"))
attempt("stat_docker_socket", lambda: os.stat("/var/run/docker.sock").st_mode)
attempt("stat_run_docker_socket", lambda: os.stat("/run/docker.sock").st_mode)
attempt("execute_from_tmp", execute_from_tmp)
attempt("write_raw", lambda: write(os.path.join(raw, "written-by-the-scanner.txt")))
attempt("list_home", lambda: sorted(os.listdir(targets["home"])))
status = dict(line.split(":\t", 1) for line in read("/proc/self/status").splitlines() if ":\t" in line)
report["identity"] = {"uid": os.getuid(), "gid": os.getgid(), "cap_eff": status["CapEff"].strip(),
                      "cap_bnd": status["CapBnd"].strip(), "no_new_privs": status["NoNewPrivs"].strip(),
                      "seccomp": status["Seccomp"].strip()}
report["mount_points"] = sorted(line.split()[4] for line in read("/proc/self/mountinfo").splitlines())
print(json.dumps(report, sort_keys=True))
'''


def test_a_hostile_scanner_cannot_reach_host_files_or_labels_or_write_outside_its_mounts(scratch):
    token = f"host-only-sentinel-{uuid.uuid4().hex}"
    sentinel = scratch / "host-only" / "sentinel.txt"
    sentinel.parent.mkdir()
    sentinel.write_text(token + "\n", encoding="utf-8")
    config = pilot(scratch, [script_system()])
    out = scratch / "out"
    targets = {"sentinel": str(sentinel), "pack": str(out / "evaluator" / "pack.json"), "run": str(out),
               "export": str(out / "inputs" / "snap-a" / "source" / "src" / "app.py"),
               "upstream": str(scratch / "upstream" / "src" / "app.py"), "scratch": str(scratch),
               "home": str(Path.home())}
    manifest = run_from_config(config, out, clock=CLOCK, workspace_root=scratch / "work",
                               adapters={"script": ScriptAdapter(HOSTILE, json.dumps(targets))})
    bundle = only_bundle(out, manifest)
    result, execution = documents(bundle)
    assert result["status"] == "success", result
    # The labels existed on the host while the scan ran: the frozen pack is written before any invocation.
    assert (out / "evaluator" / "pack.json").is_file()
    report = json.loads((bundle / "raw" / "stdout.txt").read_text(encoding="utf-8"))

    for label in ("read_sentinel", "list_sentinel_directory", "read_evaluator_pack", "list_run_directory",
                  "read_exported_input", "read_upstream_repository"):
        assert report[label] == {"ok": False, "errno": "ENOENT"}, (label, report[label])
    for label in ("write_source", "write_root", "write_etc", "write_var_tmp", "write_unmounted", "mkdir_unmounted"):
        assert report[label] == {"ok": False, "errno": "EROFS"}, (label, report[label])
    assert report["write_dev_shm"]["ok"] is False
    assert report["stat_docker_socket"]["ok"] is False and report["stat_run_docker_socket"]["ok"] is False
    assert report["execute_from_tmp"] == {"ok": False, "errno": "EACCES"}
    assert report["write_raw"] == {"ok": True, "value": "written"}
    assert report["list_home"] == {"ok": True, "value": [".cache"]}
    assert report["identity"] == {"uid": 65534, "gid": 65534, "cap_eff": "0000000000000000",
                                  "cap_bnd": "0000000000000000", "no_new_privs": "1", "seccomp": "2"}
    home_mounts = [point for point in report["mount_points"] if point.startswith(str(Path.home()) + "/")]
    assert len(home_mounts) == 2 and {Path(point).name for point in home_mounts} == {"source", "raw"}

    # Nothing it read reached the bundle, nothing it wrote reached the host, and the record says so.
    assert token not in bundle_text(bundle)
    assert sentinel.read_text(encoding="utf-8") == token + "\n"
    assert not (scratch / "planted").exists() and not (scratch / "planted-dir").exists()
    assert execution["provenance"]["source_modified"] is False
    assert (bundle / "raw" / "written-by-the-scanner.txt").is_file()
    assert execution["isolation"]["enforced"] is True and execution["network_policy"]["enforced"] is True
    [container] = execution["isolation"]["containers"]
    assert container["removed"] is True and container["exit_code"] == 0
    assert all(entry["target"].startswith("~/") for entry in execution["isolation"]["mounts"]
               if entry["role"] != "scratch")
    assert leftovers(scratch) == [] and list((scratch / "work").iterdir()) == []


# --- the network --------------------------------------------------------------------------------


NETWORK_PROBE = r'''
import errno, json, os, socket, sys
raw, targets = sys.argv[1], json.loads(sys.argv[2])
def outcome(exc):
    if isinstance(exc, socket.timeout):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "no_name"
    return errno.errorcode.get(exc.errno, type(exc).__name__) if exc.errno else type(exc).__name__
def tcp(host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(4)
            sock.connect((host, port))
            return "connected"
    except OSError as exc:
        return outcome(exc)
def lookup(name):
    try:
        return "resolved " + socket.getaddrinfo(name, 443)[0][4][0]
    except OSError as exc:
        return outcome(exc)
def dns_query(server):
    query = bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            sock.sendto(query, (server, 53))
            sock.recvfrom(512)
            return "answered"
    except OSError as exc:
        return outcome(exc)
report = {"external_ip": tcp("1.1.1.1", 443), "external_name": lookup("example.com"),
          "external_dns_server": dns_query("1.1.1.1"), "metadata_service": tcp("169.254.169.254", 80),
          "ipv6": tcp("2606:4700:4700::1111", 443), "host_docker_internal": lookup("host.docker.internal")}
for label, (host, port) in targets.get("tcp", {}).items():
    report[label] = tcp(host, port)
for label, name in targets.get("names", {}).items():
    report[label] = lookup(name)
proxy = os.environ.get("HTTPS_PROXY")
if proxy:
    address, port = proxy.rsplit("/", 1)[-1].rsplit(":", 1)
    def through_proxy(request, then=b""):
        with socket.create_connection((address, int(port)), timeout=10) as sock:
            sock.sendall(request)
            reply = sock.recv(4096)
            if then and reply.startswith(b"HTTP/1.1 200"):
                sock.sendall(then)
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    reply += chunk
            return reply.decode("latin-1")
    for label, (request, then) in targets.get("via_proxy", {}).items():
        report[label] = through_proxy(request.encode(), then.encode())
    report["proxy_other_port"] = tcp(address, 22)
print(json.dumps(report, sort_keys=True))
'''


@contextmanager
def host_listener(scratch: Path):
    """An HTTP listener in the engine host's own network namespace, on the default bridge's gateway.

    It is what "the gateway or the VM" means concretely: a service a container on an ordinary
    bridge network reaches. Bound to that one address rather than to every interface, because
    Colima forwards a port the VM opens on every interface to every interface of the Mac.
    """
    gateway = json.loads(_docker("network", "inspect", "bridge").stdout)[0]["IPAM"]["Config"][0]["Gateway"]
    port = random.randint(20000, 40000)
    name = f"scaneval-{scratch.name}-listener"
    started = _docker("run", "--detach", "--name", name, "--label", f"scaneval.test={scratch.name}",
                      "--network", "host", "--read-only", "--cap-drop", "ALL", "--user", "65534:65534",
                      "--entrypoint", "python3", PYTHON_IMAGE, "-c",
                      "import http.server, sys; http.server.HTTPServer((sys.argv[1], int(sys.argv[2])), "
                      "http.server.BaseHTTPRequestHandler).serve_forever()", gateway, str(port))
    assert started.returncode == 0, started.stderr
    try:
        # The control: an ordinary container on the default bridge does reach it.
        deadline = time.monotonic() + 30
        while True:
            control = _docker("run", "--rm", "--network", "bridge", "--label", f"scaneval.test={scratch.name}",
                              "--entrypoint", "python3", PYTHON_IMAGE, "-c",
                              "import socket, sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 3)",
                              gateway, str(port))
            if control.returncode == 0:
                break
            assert time.monotonic() < deadline, f"the control never reached {gateway}:{port}: {control.stderr}"
            time.sleep(0.5)
        yield gateway, port
    finally:
        _docker("rm", "--force", name)


BLOCKED = ("connected", "answered")


def assert_nothing_reachable(report: dict, labels) -> None:
    for label in labels:
        value = report[label]
        assert value not in BLOCKED and not value.startswith("resolved"), (label, value)


def test_no_network_is_reachable_under_none(scratch):
    with host_listener(scratch) as (gateway, port):
        targets = {"tcp": {"engine_host_listener": [gateway, port], "colima_vm_ssh": ["192.168.5.1", 22],
                           "colima_host_gateway": ["192.168.5.2", 22]}}
        bundle, _held = invoke(scratch, ScriptAdapter(NETWORK_PROBE, json.dumps(targets)), "none")
    result, execution = documents(bundle)
    assert result["status"] == "success"
    report = json.loads((bundle / "raw" / "stdout.txt").read_text(encoding="utf-8"))
    assert_nothing_reachable(report, ("external_ip", "external_name", "external_dns_server", "metadata_service",
                                      "ipv6", "host_docker_internal", "engine_host_listener", "colima_vm_ssh",
                                      "colima_host_gateway"))
    assert report["external_ip"] == "ENETUNREACH" and report["engine_host_listener"] == "ENETUNREACH"
    assert execution["network_policy"]["enforced"] is True
    assert execution["isolation"]["network"]["mode"] == "none"
    assert leftovers(scratch) == []


SERVICE = ("import http.server, sys\n"
           "token = sys.argv[1].encode()\n"
           "class Handler(http.server.BaseHTTPRequestHandler):\n"
           "    def do_GET(self):\n"
           "        self.send_response(200)\n"
           "        self.send_header('Content-Length', str(len(token)))\n"
           "        self.end_headers()\n"
           "        self.wfile.write(token)\n"
           "http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()\n")


@contextmanager
def fixture_services(scratch: Path):
    """A local network holding an allowed model-style endpoint and an undeclared one."""
    network = f"scaneval-{scratch.name}-svc"
    created = _docker("network", "create", "--label", f"scaneval.test={scratch.name}", network)
    assert created.returncode == 0, created.stderr
    services = {}
    try:
        for role in ("allowed", "undeclared"):
            name = f"{role}-{scratch.name}"
            started = _docker("run", "--detach", "--name", name, "--label", f"scaneval.test={scratch.name}",
                              "--network", network, "--read-only", "--cap-drop", "ALL", "--user", "65534:65534",
                              "--entrypoint", "python3", PYTHON_IMAGE, "-c", SERVICE, f"{role}-token-{scratch.name}")
            assert started.returncode == 0, started.stderr
            facts = json.loads(_docker("container", "inspect", name).stdout)[0]
            services[role] = {"name": name, "ip": facts["NetworkSettings"]["Networks"][network]["IPAddress"]}
        yield network, services
    finally:
        for service in services.values():
            _docker("rm", "--force", service["name"])
        _docker("network", "rm", network)


def test_model_provider_only_reaches_only_the_declared_endpoint_and_only_through_the_proxy(scratch):
    with host_listener(scratch) as (gateway, port), fixture_services(scratch) as (network, services):
        allowed, undeclared = services["allowed"]["name"], services["undeclared"]["name"]
        targets = {
            "tcp": {"engine_host_listener": [gateway, port], "colima_vm_ssh": ["192.168.5.1", 22],
                    "allowed_service_directly": [services["allowed"]["ip"], 8080],
                    "undeclared_service_directly": [services["undeclared"]["ip"], 8080]},
            "names": {"allowed_service_by_name": allowed},
            "via_proxy": {
                "proxy_allowed": [f"CONNECT {allowed}:8080 HTTP/1.1\r\nHost: {allowed}:8080\r\n\r\n",
                                  f"GET / HTTP/1.0\r\nHost: {allowed}\r\n\r\n"],
                "proxy_undeclared": [f"CONNECT {undeclared}:8080 HTTP/1.1\r\n\r\n", ""],
                "proxy_external": ["CONNECT 1.1.1.1:443 HTTP/1.1\r\n\r\n", ""],
                "proxy_plain_request": [f"GET http://{allowed}:8080/ HTTP/1.1\r\nHost: {allowed}\r\n\r\n", ""]}}
        execution_block = {"proxy_image": PYTHON_IMAGE, "egress": [{"host": allowed, "port": 8080}]}
        bundle, _held = invoke(scratch, ScriptAdapter(NETWORK_PROBE, json.dumps(targets)), "model_provider_only",
                               execution=execution_block, proxy_network=network,
                               labels={"scaneval.test": scratch.name})
    result, execution = documents(bundle)
    assert result["status"] == "success", (bundle / "raw" / "stderr.txt").read_text(encoding="utf-8")
    report = json.loads((bundle / "raw" / "stdout.txt").read_text(encoding="utf-8"))
    # Model-style traffic to the declared endpoint goes through, and only through the proxy.
    assert report["proxy_allowed"].startswith("HTTP/1.1 200 Connection Established")
    assert f"allowed-token-{scratch.name}" in report["proxy_allowed"]
    assert report["proxy_undeclared"].startswith("HTTP/1.1 403")
    assert report["proxy_external"].startswith("HTTP/1.1 403")
    assert report["proxy_plain_request"].startswith("HTTP/1.1 405")
    assert report["proxy_other_port"] == "ECONNREFUSED"
    assert_nothing_reachable(report, ("external_ip", "external_name", "external_dns_server", "metadata_service",
                                      "ipv6", "host_docker_internal", "engine_host_listener", "colima_vm_ssh",
                                      "allowed_service_directly", "undeclared_service_directly",
                                      "allowed_service_by_name"))
    # The proxy's own log, read back into the record.
    network_record = execution["isolation"]["network"]
    assert execution["network_policy"]["enforced"] is True and network_record["enforced"] is True
    [internal] = [item for item in network_record["networks"] if item["internal"]]
    assert internal["gateway_mode_ipv4"] == "isolated" and internal["gateways"] == [] and internal["removed"]
    proxy = network_record["proxy"]
    assert proxy["log"] == "read" and proxy["allowed"] == 1 and proxy["denied"] == 3
    assert proxy["allowed_destinations"] == [f"{allowed}:8080"]
    assert {f"{undeclared}:8080", "1.1.1.1:443"} <= set(proxy["denied_destinations"])
    assert all(item["removed"] for item in execution["isolation"]["containers"])
    assert leftovers(scratch) == []


# --- processes, time, memory, and pids ---------------------------------------------------------


LINGERING = r'''
import os, signal, subprocess, sys, time
raw, marker = sys.argv[1], sys.argv[2]
sleeper = [sys.executable, "-c", "import time; time.sleep(3600)", marker]
subprocess.Popen(sleeper)
subprocess.Popen(sleeper, start_new_session=True)
subprocess.Popen(["nohup", *sleeper], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        os.execv(sys.executable, sleeper)
    os._exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print("children started", flush=True)
time.sleep(3600)
'''

COUNT_PROCESSES = r'''
import os, sys
needle = (sys.argv[1] + sys.argv[2]).encode()
found = 0
for pid in os.listdir("/proc"):
    if pid.isdigit():
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                found += needle in handle.read()
        except OSError:
            pass
print(found)
'''


def processes_carrying(scratch: Path, marker: str) -> int:
    """How many processes anywhere on the engine host carry *marker* in their command line."""
    counted = _docker("run", "--rm", "--pid", "host", "--network", "none", "--read-only", "--cap-drop", "ALL",
                      "--user", "65534:65534", "--label", f"scaneval.test={scratch.name}", "--entrypoint", "python3",
                      PYTHON_IMAGE, "-c", COUNT_PROCESSES, marker[:8], marker[8:])
    assert counted.returncode == 0, counted.stderr
    return int(counted.stdout.strip())


def test_a_timeout_leaves_no_container_and_no_process_behind(scratch):
    """Background, setsid, nohup, and double-forked children all die with the container."""
    marker = f"scaneval-lingering-{uuid.uuid4().hex}"
    seen: list[int] = []
    finished = threading.Event()
    outcome: dict = {}

    def scan():
        try:
            outcome["bundle"], _ = invoke(scratch, ScriptAdapter(LINGERING, marker), timeout=12)
        except BaseException as exc:
            outcome["error"] = exc
        finally:
            finished.set()

    worker = threading.Thread(target=scan)
    worker.start()
    deadline = time.monotonic() + 60
    while not finished.is_set() and time.monotonic() < deadline:
        count = processes_carrying(scratch, marker)
        seen.append(count)
        if count >= 4:
            break
        time.sleep(0.5)
    worker.join(120)
    assert not worker.is_alive() and "error" not in outcome, outcome.get("error")
    assert max(seen) >= 4, f"the children were never seen running: {seen}"
    result, execution = documents(outcome["bundle"])
    assert result["status"] == "timeout" and execution["timed_out"] is True
    [container] = execution["isolation"]["containers"]
    assert container["timed_out"] is True and container["removed"] is True
    assert processes_carrying(scratch, marker) == 0
    assert leftovers(scratch) == []
    # BSD-style options, which both the macOS and the Linux procps ps accept.
    clients = subprocess.run(["ps", "axww", "-o", "command="], capture_output=True, text=True).stdout
    assert container["name"] not in clients, "a docker client of the killed container is still running"


HUNGRY = r'''
import sys
hoard = []
for _ in range(64):
    hoard.append(b"x" * (8 << 20))
print("allocated", len(hoard))
'''

FORKER = r'''
import errno, os, signal, sys, time
children, failure = [], None
for _ in range(500):
    try:
        pid = os.fork()
    except OSError as exc:
        failure = errno.errorcode.get(exc.errno, str(exc.errno))
        break
    if pid == 0:
        time.sleep(60)
        os._exit(0)
    children.append(pid)
for pid in children:
    os.kill(pid, signal.SIGKILL)
for pid in children:
    os.waitpid(pid, 0)
print(len(children), failure)
'''


def test_memory_and_pids_limits_are_enforced_and_recorded(scratch):
    limits = {"memory_mb": 96, "tmpfs_mb": 16, "pids": 24}
    (scratch / "memory").mkdir()
    bundle, _held = invoke(scratch / "memory", ScriptAdapter(HUNGRY), execution={"limits": limits})
    result, execution = documents(bundle)
    assert result["status"] == "error" and result["error"]["code"] == "exit_137"
    [container] = execution["isolation"]["containers"]
    assert container["oom_killed"] is True and container["exit_code"] == 137
    settings = execution["isolation"]["settings"]
    assert settings["memory_mb"] == settings["memory_swap_mb"] == 96 and settings["pids_limit"] == 24
    assert "out-of-memory kill under the 96 MB limit" in execution["isolation"]["note"]
    assert "allocated" not in (bundle / "raw" / "stdout.txt").read_text(encoding="utf-8")

    (scratch / "pids").mkdir()
    bundle, _held = invoke(scratch / "pids", ScriptAdapter(FORKER), execution={"limits": limits})
    result, execution = documents(bundle)
    assert result["status"] == "success"
    forked, failure = (bundle / "raw" / "stdout.txt").read_text(encoding="utf-8").split()
    assert failure == "EAGAIN" and 0 < int(forked) < 24
    assert leftovers(scratch) == []


# --- what the scanner leaves behind stays untrusted -----------------------------------------------


MALFORMED = r'''
import os, sys
raw, sentinel = sys.argv[1], sys.argv[2]
os.symlink(sentinel, os.path.join(raw, "leak.json"))
os.mkfifo(os.path.join(raw, "pipe.json"))
with open(os.path.join(raw, "result.json"), "w") as handle:
    handle.write('{"findings": [ this is not json')
with open(os.path.join(raw, "big.bin"), "wb") as handle:
    for _ in range(24):
        handle.write(b"x" * (1 << 20))
sys.stdout.write("y" * (4 << 20))
'''


class MalformedAdapter(ScriptAdapter):
    """Declares everything the scanner wrote and parses its result the way an importer would."""

    def scan(self, **kwargs):
        raw_dir = kwargs["raw_dir"]
        outcome = super().scan(**kwargs)
        outcome.artifacts += [{"id": name.split(".")[0], "path": raw_dir / name}
                              for name in ("leak.json", "pipe.json", "result.json", "big.bin")]
        try:
            json.loads(read_regular_file(raw_dir / "result.json"))
        except ValueError as exc:
            outcome.status, outcome.error = "error", {"code": "unparseable_output", "message": str(exc)[:500]}
        return outcome


def test_malformed_worker_artifacts_stay_untrusted_through_the_ingestion_boundary(scratch):
    token = f"host-only-sentinel-{uuid.uuid4().hex}"
    sentinel = scratch / "host-only.txt"
    sentinel.write_text(token + "\n", encoding="utf-8")
    finished: dict = {}

    def scan():
        finished["value"] = invoke(scratch, MalformedAdapter(MALFORMED, str(sentinel)))

    worker = threading.Thread(target=scan, daemon=True)
    worker.start()
    worker.join(180)
    assert "value" in finished, "the invocation blocked or failed on what the scanner left behind"
    bundle, _held = finished["value"]
    result, execution = documents(bundle)
    assert result["status"] == "error" and result["error"]["code"] == "unparseable_output"
    notes = " ".join(execution["notes"])
    assert "leak.json -> ~/" in notes and "were cut" in notes
    assert "declared artifact missing: leak" in notes
    assert "declared artifact is not a regular file and was not hashed: pipe" in notes
    artifacts = {item["id"]: item for item in execution["raw_artifacts"]}
    assert {"big", "result", "stdout"} <= set(artifacts) and "leak" not in artifacts and "pipe" not in artifacts
    assert (bundle / "raw" / "big.bin").stat().st_size == 24 << 20
    assert not (bundle / "raw" / "leak.json").exists() and not (bundle / "raw" / "leak.json").is_symlink()
    assert (bundle / "raw" / "pipe.json").is_fifo()
    assert token not in bundle_text(bundle)
    assert leftovers(scratch) == []


PLANTER = r'''
import os, sys
raw, sentinel = sys.argv[1], sys.argv[2]
os.unlink(os.path.join(raw, "second.out"))
os.symlink(sentinel, os.path.join(raw, "second.out"))
os.symlink(os.path.dirname(sentinel), os.path.join(raw, "nested"))
print("planted")
'''


class PlantingAdapter(Adapter):
    """Runs a first command that plants links where the next commands' output goes, then those commands.

    The first output file is claimed before anything runs, the way the Semgrep adapter claims its
    own, so what the first container replaces is a file the host itself created.
    """

    name = "planting"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})
    oci_compatible = True

    def __init__(self, sentinel: Path) -> None:
        self.sentinel = sentinel

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        (raw_dir / "second.out").touch()
        run_command(["python3", "-I", "-c", PLANTER, str(raw_dir), str(self.sentinel)], cwd=source_dir,
                    timeout_seconds=timeout_seconds, env=build_env(), stdout_path=raw_dir / "first.out",
                    stderr_path=raw_dir / "first.err")
        refused = []
        for name in ("second.out", "nested/third.out"):
            try:
                run_command(["python3", "-I", "-c", "print('written by the scan')"], cwd=source_dir,
                            timeout_seconds=timeout_seconds, env=build_env(), stdout_path=raw_dir / name,
                            stderr_path=raw_dir / "later.err")
            except OSError as exc:
                refused.append(f"{name} refused: {exc.strerror}")
        return NativeOutcome(status="success", exit_code=0, command=["python3"], notes=refused,
                             capture={"model_requests": "not_applicable"})


def test_a_link_one_command_plants_where_the_next_writes_is_never_written_through(scratch):
    """Every container can write under raw/; the host-side open of the next command's output must not follow it."""
    token = f"host-only-sentinel-{uuid.uuid4().hex}"
    sentinel = scratch / "host-only" / "sentinel.txt"
    sentinel.parent.mkdir()
    sentinel.write_text(token + "\n", encoding="utf-8")
    bundle, _held = invoke(scratch, PlantingAdapter(sentinel))
    result, execution = documents(bundle)
    assert result["status"] == "success"
    notes = " ".join(execution["notes"])
    assert "second.out refused" in notes and "nested/third.out refused" in notes
    assert sentinel.read_text(encoding="utf-8") == token + "\n"
    assert sorted(path.name for path in sentinel.parent.iterdir()) == ["sentinel.txt"]
    assert "second.out -> ~/" in notes and "nested -> ~/" in notes and token not in bundle_text(bundle)
    containers = execution["isolation"]["containers"]
    assert len(containers) == 2, "the redirected directory is refused before any container is created"
    first, second = containers
    assert first["started"] is True and first["exit_code"] == 0
    assert second["created"] is True and second["started"] is False and second["removed"] is True
    assert leftovers(scratch) == []


class CommandAdapter(Adapter):
    """Runs one fixed command in the image, in *cwd* under the source, and reports its exit code."""

    name = "command"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})
    oci_compatible = True

    def __init__(self, *argv: str, cwd: str = ".") -> None:
        self.argv = list(argv)
        self.cwd = cwd

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        result = run_command(self.argv, cwd=source_dir / self.cwd, timeout_seconds=timeout_seconds,
                             env=build_env(), stdout_path=raw_dir / "stdout.txt", stderr_path=raw_dir / "stderr.txt")
        return NativeOutcome(status="success" if result.exit_code == 0 else "error", exit_code=result.exit_code,
                             command=result.argv, capture={"model_requests": "not_applicable"},
                             error=None if result.exit_code == 0 else {"code": "exit", "message": "failed"})


def test_a_container_the_engine_cannot_start_is_a_recorded_refusal_and_nothing_is_enforced(scratch):
    """The engine leaves such a container ``created``; it never ran, so the record must not say it was held.

    A working directory missing from the read-only source is one: the runtime cannot make it, which
    is where the local runner reports a process it could not start. A binary the image lacks is not
    one: under ``--init`` the init process starts and reports 127, a command that ran and failed.
    """
    bundle, _held = invoke(scratch, CommandAdapter("python3", "-c", "print(1)", cwd="no-such-directory"))
    result, execution = documents(bundle)
    assert result["status"] == "error" and result["error"]["code"] == "adapter_failure"
    assert "could not start the container for python3" in result["error"]["message"]
    assert "read-only file system" in result["error"]["message"] and str(Path.home()) not in result["error"]["message"]
    assert execution["isolation"]["enforced"] is False and execution["network_policy"]["enforced"] is False
    [container] = execution["isolation"]["containers"]
    assert container["started"] is False and container["status"] == "created" and container["removed"] is True
    assert leftovers(scratch) == []

    (scratch / "missing-binary").mkdir()
    bundle, _held = invoke(scratch / "missing-binary", CommandAdapter("scaneval-no-such-tool", "--version"))
    result, execution = documents(bundle)
    assert result["status"] == "error" and result["error"]["code"] == "exit"
    [container] = execution["isolation"]["containers"]
    assert container["started"] is True and container["exit_code"] == 127 and container["removed"] is True
    assert "scaneval-no-such-tool" in (bundle / "raw" / "stderr.txt").read_text(encoding="utf-8")
    assert leftovers(scratch) == []


def test_a_workspace_the_daemon_cannot_see_is_refused_rather_than_scanned_empty(scratch):
    """On an engine in a virtual machine that does not share the temporary directory, ``-v`` would mount nothing."""
    unshared = Path(tempfile.mkdtemp(prefix="scaneval-oci-unshared-"))
    try:
        probe = _docker("create", "--label", f"scaneval.test={scratch.name}", "--network", "none",
                        "--mount", f"type=bind,src={unshared},dst=/probe", "--entrypoint", "true", PYTHON_IMAGE)
        if probe.returncode == 0:
            _docker("rm", "--force", probe.stdout.strip())
            pytest.skip("this engine sees the system temporary directory (a native engine), so there is no "
                        "unshared path here to refuse")
        held = OciBackend(resolve_execution({"backend": "oci", "image": PYTHON_IMAGE}, "none"),
                          run_id=run_id(scratch), invocation_id="snap-a__script__r1", scratch_root=unshared)
        adapter = ScriptAdapter("print('the scanner ran')")
        try:
            bundle = run_invocation(prepared=prepared_input(scratch), adapter=adapter,
                                    spec=SystemSpec("script", "script", {}), preparation={},
                                    out_dir=scratch / "out", run_id=run_id(scratch), network_policy="none",
                                    workspace_root=held.workspace_root, clock=CLOCK, backend=held)
        finally:
            assert held.close() == []
        result, execution = documents(bundle)
        assert result["status"] == "error" and "not visible to the Docker daemon" in result["error"]["message"]
        assert "--workspace-root" in execution["isolation"]["note"]
        assert execution["isolation"]["enforced"] is False and execution["isolation"]["containers"] == []
        assert not (bundle / "raw" / "stdout.txt").exists()
        assert leftovers(scratch) == []
    finally:
        shutil.rmtree(unshared, ignore_errors=True)


# --- replay, and a real scanner ------------------------------------------------------------------


def test_an_oci_bundle_replays_with_no_engine_and_no_network(scratch, monkeypatch, tmp_path):
    config = pilot(scratch, [script_system()])
    out = scratch / "out"
    manifest = run_from_config(config, out, clock=CLOCK, workspace_root=scratch / "work",
                               adapters={"script": ScriptAdapter("print('{}')")})
    bundle = only_bundle(out, manifest)
    assert documents(bundle)[1]["isolation"]["enforced"] is True

    def refused(*args, **kwargs):
        raise AssertionError("replay tried to open a socket or start a process")

    monkeypatch.setenv("DOCKER_HOST", "unix:///nonexistent/docker.sock")
    monkeypatch.setattr(socket, "socket", refused)
    monkeypatch.setattr(subprocess, "Popen", refused)
    replayed = tmp_path / "replayed.json"
    assert main(["replay", str(bundle), "--output", str(replayed)]) == 0
    assert replayed.read_bytes() == (bundle / "evaluation.json").read_bytes()


def test_semgrep_runs_end_to_end_in_the_pinned_official_image(scratch):
    rules = scratch / "rules"
    rules_commit = repository(rules, {"python/shell.yaml": SHELL_RULE})
    config = pilot(scratch, [{"system_id": "semgrep-oci", "adapter": "semgrep",
                              "config": {"ruleset": {"url": str(rules), "commit": rules_commit, "paths": ["python"]}},
                              "execution": {"backend": "oci", "image": SEMGREP_IMAGE}}])
    out = scratch / "out"
    manifest = run_from_config(config, out, clock=CLOCK, workspace_root=scratch / "work")
    bundle = only_bundle(out, manifest)
    result, execution = documents(bundle)
    assert result["status"] == "success", result.get("error")
    [claim] = result["claims"]
    assert claim["native_rule_id"] == "python.subprocess-shell-true"
    assert claim["primary_location"] == {"path": "src/app.py", "start_line": 5, "end_line": 5}
    assert execution["command"][0] == "semgrep" and "--disable-version-check" in execution["command"]
    assert execution["tool_versions"]["semgrep"] == "1.177.0"
    image = execution["isolation"]["image"]
    assert image["reference"] == SEMGREP_IMAGE and SEMGREP_IMAGE.rsplit("@", 1)[1] in (
        [image["id"]] + [digest.rsplit("@", 1)[1] for digest in image["repo_digests"]])
    workers = execution["isolation"]["containers"]
    assert len(workers) == 2 and all(item["exit_code"] == 0 and item["removed"] for item in workers)
    runtime = [entry for entry in execution["isolation"]["mounts"] if entry["role"] == "runtime"]
    assert len(runtime) == 1 and runtime[0]["mode"] == "ro" and runtime[0]["target"].startswith("~/")
    assert execution["network_policy"]["enforced"] is True
    assert manifest["status"] == "completed" and leftovers(scratch) == []
