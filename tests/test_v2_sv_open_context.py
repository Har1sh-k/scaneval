"""SV-Agent image runtime (config.runtime = oci_image): selection, refusals, and a local fixture run.

The fixture run is the real adapter starting the real driver with the SDK's tsx, which composes the
real image Pi runner under the harness's retry and isolation wrappers and runs a stand-in ``pi``
that loads the real research tool module. Only two things are not real: the ``pi`` binary, which
emits a Pi-shaped JSON stream instead of calling a model, and the backend, a test-only subclass of
the oci backend that runs each command on this host instead of in a container. Nothing here calls
a model or starts a container; ``test_v2_sv_open_context_docker.py`` does the real-boundary run.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time

import pytest

from scaneval.adapters import get_adapter
from scaneval.adapters.base import AdapterError, CommandResult, SystemSpec, routed_through
from scaneval.adapters.llm_harness import (
    DEFAULT_PI_AUTH_ENV, SYNTHETIC_MODEL, check_pi_credential, credential_validity, image_settings, read_completion,
)
from scaneval.isolation import resolve_execution
from scaneval.isolation.oci import OciBackend


ROOT = Path(__file__).resolve().parents[1]
ADAPTERS = ROOT / "src" / "scaneval" / "adapters"
SDK = ROOT / "sdk" / "typescript"
MODEL = "openai-codex/gpt-5.6-sol"
ACCESS = "ACCESS-TOKEN-MARKER-7f3a"
REFRESH = "REFRESH-TOKEN-MARKER-91bc"
API_KEY = "sk-PAID-KEY-MARKER-55"
PROMPT = "SENTINEL-PROMPT-c41d: review app.py for injection"
RETRIEVAL = {"policy": "recorded_public_v1", "allowed_origins": ["https://example.com"],
             "capture": "content", "retention": "bundle"}
COMMIT = "f959cbcf010c7e41f780c718b65b1724d3aecb43"


def credential(*, expires_in: float = 3600, provider: str = "openai-codex", kind: str = "oauth") -> str:
    return json.dumps({provider: {"type": kind, "access": ACCESS,
                                  "expires": int((time.time() + expires_in) * 1000), "accountId": "acct"}})


def settings_for(policy: str = "public_research", *, credentials: bool = True, search: bool = False):
    execution = {"backend": "oci", "image": "sha256:" + "0" * 64,
                 **({"credentials": [{"env": DEFAULT_PI_AUTH_ENV, "provider": "openai-codex"}]} if credentials else {})}
    if policy in ("public_research", "model_provider_only"):
        execution.update(proxy_image="sha256:" + "1" * 64, egress=[{"host": "chatgpt.com", "port": 443}])
    if policy == "public_research":
        execution["retrieval"] = {**RETRIEVAL, **({"search_endpoint": "https://example.com/search"} if search else {})}
    return resolve_execution(execution, policy)


class HostOciBackend(OciBackend):
    """TEST ONLY: holds a scan as the oci backend does, but runs each command on this host.

    Passes what the real backend passes into a container: the base environment, the retrieval and
    proxy variables, and each declared credential by name from this process's environment.
    """

    def __init__(self, settings, scratch: Path, extra_env: dict[str, str], *, forward_credentials: bool = True,
                 credential_override: str | None = None):
        super().__init__(settings, run_id="run-sv-oc", invocation_id="inv-sv-oc", scratch_root=scratch)
        self.extra_env = extra_env
        self.forward_credentials = forward_credentials
        self.credential_override = credential_override
        self.commands: list[dict] = []
        self.scratch_dirs: list[str] = []

    def track(self, path: str) -> None:
        self.scratch_dirs.append(path)

    def cleanup(self) -> list[str]:
        """Remove the per-command /tmp directories; what is left in them is what the run left."""
        leftovers = []
        for path in self.scratch_dirs:
            leftovers.extend(sorted(entry.name for entry in Path(path).iterdir()))
            shutil.rmtree(path, ignore_errors=True)
        return leftovers

    def run_command(self, argv, *, cwd, timeout_seconds, env, stdout_path, stderr_path, stdin_text=None):
        self.commands.append({"argv": list(argv), "cwd": str(cwd), "env": sorted(env)})
        # A short private /tmp, as in the container: tsx listens on a unix socket under TMPDIR, and
        # a socket path longer than the platform limit cannot be bound.
        scratch = tempfile.mkdtemp(prefix="svoc-", dir="/tmp" if Path("/tmp").is_dir() else None)
        self.track(scratch)
        environment = {"PATH": os.environ["PATH"], "HOME": scratch, "TMPDIR": scratch, **self.extra_env}
        if self.forward_credentials:
            for key, _provider in self.settings.credentials:
                if key in os.environ:
                    environment[key] = os.environ[key]
        if self.credential_override is not None:
            environment[DEFAULT_PI_AUTH_ENV] = self.credential_override
        started = time.monotonic()
        with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
            completed = subprocess.run(argv, cwd=cwd, env=environment, stdout=out, stderr=err,
                                       timeout=timeout_seconds, check=False)
        return CommandResult(list(argv), completed.returncode, False, time.monotonic() - started,
                             Path(stdout_path), Path(stderr_path))


# --- configuration --------------------------------------------------------------------------------

@pytest.mark.parametrize("config, message", [
    ({"harness": "fieldglass"}, "securevibes-agent harness only"),
    ({"runner": "mock"}, "synthetic"),
    ({"model": "anthropic/claude-opus"}, "provider route"),
    ({"model": "openai-codex/gpt:high"}, "provider route"),
    ({"thinking_level": "ultra"}, "thinking_level"),
    ({"pi_auth_env": "SCANEVAL_PI_AUTH_JSON"}, "outside the GIT_, SCANEVAL_ and PI_"),
    ({"pi_auth_env": "PI_AUTH"}, "outside the GIT_, SCANEVAL_ and PI_"),
    ({"pi_auth_env": "lower"}, "outside the GIT_"),
    ({"research_search": "yes"}, "boolean"),
    ({"image_paths": {"elsewhere": "/x"}}, "may name only"),
    ({"image_paths": {"driver": "relative.mts"}}, "absolute path inside the image"),
    ({"expected_harness_commit": "abc"}, "40-character"),
    ({"synthetic_tool_calls": []}, "synthetic diagnostic model route"),
    ({"mode": "pr"}, "bootstrap"),
])
def test_image_configuration_is_refused_with_the_field_it_names(config, message):
    with pytest.raises(AdapterError, match=message):
        image_settings({"harness": "securevibes-agent", "model": MODEL, "runtime": "oci_image", **config})


def test_image_defaults_pin_high_reasoning_and_the_image_paths():
    settings = image_settings({"harness": "securevibes-agent", "model": MODEL})
    assert (settings["provider"], settings["model_id"], settings["thinking"]) == ("openai-codex", "gpt-5.6-sol", "high")
    assert settings["auth_env"] == DEFAULT_PI_AUTH_ENV and not settings["synthetic"]
    assert settings["paths"]["driver"] == "/opt/scaneval/llm_harness_driver.mts"
    assert settings["paths"]["tsx"] == "/opt/scaneval/harness/node_modules/.bin/tsx"
    synthetic = image_settings({"harness": "securevibes-agent", "model": SYNTHETIC_MODEL})
    assert synthetic["synthetic"] and synthetic["auth_env"] is None
    with pytest.raises(AdapterError, match="takes no credential"):
        image_settings({"harness": "securevibes-agent", "model": SYNTHETIC_MODEL, "pi_auth_env": "X_AUTH"})


def test_prepare_on_the_image_runtime_inspects_nothing_on_the_host(tmp_path):
    adapter = get_adapter("llm-harness")
    spec = SystemSpec("sv", "llm-harness", {"harness": "securevibes-agent", "runtime": "oci_image", "model": MODEL,
                                            "image_paths": {"root": "/definitely/not/on/this/host"}})
    preparation = adapter.prepare(spec, tmp_path)
    assert preparation["runtime"] == "oci_image"
    assert preparation["harness"]["root"] == "/definitely/not/on/this/host"
    assert preparation["harness"]["location"] == "scanner image"
    assert not (tmp_path / "definitely").exists()


def test_the_local_runtime_refuses_image_only_settings_and_unknown_runtimes(tmp_path):
    adapter = get_adapter("llm-harness")
    with pytest.raises(AdapterError, match="only to runtime oci_image"):
        adapter.prepare(SystemSpec("s", "llm-harness", {"harness": "securevibes-agent", "root": str(tmp_path),
                                                        "model": MODEL, "thinking_level": "high"}), tmp_path)
    with pytest.raises(AdapterError, match="config.runtime must be one of"):
        adapter.prepare(SystemSpec("s", "llm-harness", {"harness": "securevibes-agent", "model": MODEL,
                                                        "runtime": "container"}), tmp_path)


def test_condition_controls_describe_research_only_on_the_image_runtime():
    adapter = get_adapter("llm-harness")
    local = SystemSpec("s", "llm-harness", {"harness": "securevibes-agent", "model": MODEL})
    assert adapter.condition_controls(local, {}) == {}
    image = SystemSpec("s", "llm-harness", {"harness": "securevibes-agent", "model": MODEL, "runtime": "oci_image",
                                            "research_search": True})
    controls = adapter.condition_controls(image, {})
    assert controls["inference"] == "remote"
    assert controls["tools"] == {"browser": "disabled", "web_search": "enabled", "remote_fetch": "enabled",
                                 "package_install": "disabled", "scanner_update": "disabled"}
    assert controls["provider"]["control"] == "unverifiable"


@pytest.mark.parametrize("raw, message", [
    (None, "is not set"),
    ("not json " + ACCESS, "is not JSON"),
    (json.dumps([ACCESS]), "not a JSON object"),
    (json.dumps({"openai-codex": {}, "anthropic": {"access": ACCESS}}), "exactly one entry"),
    (credential(provider="anthropic"), "exactly one entry, for provider 'openai-codex'; it holds 1 entry for another"),
    (credential(kind="api_key"), "OAuth credential"),
    (credential(expires_in=-10), "expired"),
])
def test_a_bad_credential_is_refused_without_its_value(raw, message):
    with pytest.raises(AdapterError, match=message) as caught:
        check_pi_credential(raw, "openai-codex", DEFAULT_PI_AUTH_ENV)
    rendered = str(caught.value) + repr(caught.value.__cause__) + repr(caught.value.__context__)
    assert ACCESS not in rendered and REFRESH not in rendered


# --- scan refusals ----------------------------------------------------------------------------------

def _request(mode: str = "full") -> dict:
    return {"run_id": "run-sv-oc", "input": {"mode": mode, **({"pr": {"base": "a", "head": "b"}} if mode == "pr" else {})}}


def _scan(adapter, spec, tmp_path, backend=None, request=None):
    source, raw = tmp_path / "src", tmp_path / "raw"
    source.mkdir(exist_ok=True)
    raw.mkdir(exist_ok=True)
    kwargs = dict(request=request or _request(), source_dir=source, raw_dir=raw, spec=spec,
                  preparation=adapter.prepare(spec, tmp_path), timeout_seconds=30, trace_mode="off", trace_dir=None)
    if backend is None:
        return adapter.scan(**kwargs)
    with routed_through(backend):
        return adapter.scan(**kwargs)


IMAGE = {"harness": "securevibes-agent", "runtime": "oci_image", "model": MODEL}


def test_the_image_runtime_never_runs_without_the_oci_backend(tmp_path):
    with pytest.raises(AdapterError, match="never run on the host"):
        _scan(get_adapter("llm-harness"), SystemSpec("s", "llm-harness", IMAGE), tmp_path)


def test_the_local_runtime_is_refused_under_an_oci_backend(tmp_path):
    adapter = get_adapter("llm-harness")
    root = tmp_path / "harness"
    for part in ("src/runtime/engine.ts", "src/runtime/pi-runner.ts", "node_modules/.bin/tsx"):
        (root / part).parent.mkdir(parents=True, exist_ok=True)
        (root / part).write_text("")
    spec = SystemSpec("s", "llm-harness", {"harness": "securevibes-agent", "root": str(root), "model": MODEL,
                                           "observer_sdk": str(root / "node_modules/.bin/tsx")})
    backend = HostOciBackend(settings_for(), tmp_path, {})
    with pytest.raises(AdapterError, match="select config.runtime oci_image"):
        _scan(adapter, spec, tmp_path, backend)
    assert backend.commands == []


@pytest.mark.parametrize("policy", ["none", "model_provider_only"])
def test_closed_book_policies_never_get_the_research_route(tmp_path, policy, monkeypatch):
    monkeypatch.setenv(DEFAULT_PI_AUTH_ENV, credential())
    backend = HostOciBackend(settings_for(policy, credentials=policy != "none"), tmp_path, {})
    with pytest.raises(AdapterError, match="only under network policy public_research"):
        _scan(get_adapter("llm-harness"), SystemSpec("s", "llm-harness", IMAGE), tmp_path, backend)
    assert backend.commands == []


def test_undeclared_missing_or_bad_credentials_and_mismatched_search_are_refused_before_any_command(tmp_path, monkeypatch):
    adapter = get_adapter("llm-harness")
    spec = SystemSpec("s", "llm-harness", IMAGE)
    backend = HostOciBackend(settings_for(credentials=False), tmp_path, {})
    with pytest.raises(AdapterError, match="execution.credentials must declare"):
        _scan(adapter, spec, tmp_path, backend)
    backend = HostOciBackend(settings_for(), tmp_path, {})
    monkeypatch.delenv(DEFAULT_PI_AUTH_ENV, raising=False)
    with pytest.raises(AdapterError, match="is not set"):
        _scan(adapter, spec, tmp_path, backend)
    monkeypatch.setenv(DEFAULT_PI_AUTH_ENV, credential(expires_in=-5))
    with pytest.raises(AdapterError, match="expired") as caught:
        _scan(adapter, spec, tmp_path, backend)
    assert ACCESS not in str(caught.value)
    monkeypatch.setenv(DEFAULT_PI_AUTH_ENV, credential())
    with pytest.raises(AdapterError, match="research_search"):
        _scan(adapter, spec, tmp_path, HostOciBackend(settings_for(search=True), tmp_path, {}))
    with pytest.raises(AdapterError, match="full scans only"):
        _scan(adapter, spec, tmp_path, backend, request=_request("pr"))
    assert backend.commands == []


# --- local fixture run ----------------------------------------------------------------------------

STUB_ENGINE = r"""
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
export async function runRuntimeScan(options: any): Promise<any> {
  const leaked = Object.keys(process.env).filter((key) => key === "SV_AGENT_PI_AUTH_JSON" || key === "OPENAI_API_KEY");
  const result = await options.llmRunner.runPi({
    args: ["-p", "--no-session", "--model", options.llmModel, "--thinking", "medium", "__PROMPT__"],
    cwd: options.repoPath, timeoutMs: 60000, env: process.env,
  });
  const findings: any[] = [];
  if (result.code === 0 && result.stdout.includes("FINDING")) {
    const dir = join(options.repoPath, ".securevibes", "findings");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "f-1.md"), '---\nid: "f-1"\ntitle: "Injected handler"\nfile_path: "app.py"\n'
      + 'vulnerability_class: "injection"\nseverity: "high"\n---\n## Reasoning\nfixture\n');
    findings.push({ id: "f-1", filePath: "app.py", vulnerabilityClass: "injection", severity: "high" });
  }
  return { newFindings: findings, updatedFindings: [], runtimeProfile: "full", degraded: false,
    bootstrapScan: { llmCalls: 1, failedCalls: result.code === 0 ? 0 : 1, status: "complete", hypothesisCoverage: 1 },
    completion: __COMPLETION__,
    fixture: { leaked, runnerStderr: result.stderr.slice(0, 500) } };
}
""".replace("__PROMPT__", PROMPT).replace("__COMPLETION__", (ROOT / "tests/fixtures/sv-completion.json").read_text())

# Upstream's retry/isolation composition, reduced to what the image route relies on. When
# SCANEVAL_SV_HARNESS_ROOT names the pinned checkout, its real pi-runner.ts and exec.ts are used.
STUB_RUNNER = r"""
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
export function createRetryingPiRunner(runner: any) {
  return { async runPi(invocation: any) { return await runner.runPi(invocation); } };
}
export function createIsolatedPiRunner(runner: any) {
  return { async runPi(options: any) {
    const cwd = await mkdtemp(join(tmpdir(), "sv-pi-"));
    try {
      return await runner.runPi({ ...options, args: options.args.map((a: string) => a.replace(/\0/g, "\\0")), cwd });
    } finally { await rm(cwd, { recursive: true, force: true }); }
  } };
}
export function createDefaultPiRunner() { throw new Error("the image route must not use the default runner"); }
"""
STUB_EXEC = r"""
import { spawn } from "node:child_process";
export async function execCommand(command: string, args: string[], options: any = {}): Promise<any> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: options.cwd, env: options.env,
      stdio: [options.stdin === undefined ? "ignore" : "pipe", "pipe", "pipe"] });
    let stdout = ""; let stderr = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error(`Command timed out: ${command} ${args.join(" ")}`)); },
      options.timeoutMs ?? 60000);
    child.stdout.on("data", (chunk: Buffer) => { stdout += chunk; });
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk; });
    child.on("error", reject);
    if (options.stdin !== undefined) child.stdin.end(options.stdin);
    child.on("close", (code: number | null) => { clearTimeout(timer); resolve({ code: code ?? 1, stdout, stderr }); });
  });
}
"""

# A stand-in for the pi binary: no model. It records what it was started with, loads the real
# research tool module from beside the -e extension, runs a fixed tool script through it, and
# prints a Pi-shaped JSON stream whose final text depends on what the history tool returned.
FAKE_PI = r"""#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
const argv = process.argv.slice(2);
const here = dirname(process.argv[1]);
if (argv[0] === "--version") { console.log("1.4.0"); process.exit(0); }
const control = existsSync(join(here, "control.json")) ? JSON.parse(readFileSync(join(here, "control.json"), "utf8")) : {};
let stdin = "";
for await (const chunk of process.stdin) stdin += chunk;
const auth = join(process.env.PI_CODING_AGENT_DIR, "auth.json");
const authDocument = existsSync(auth) ? JSON.parse(readFileSync(auth, "utf8")) : null;
const authFacts = authDocument
  ? { exists: true, mode: (statSync(auth).mode & 0o777).toString(8), providers: Object.keys(authDocument),
      refreshDisabled: authDocument["openai-codex"]?.refresh === "scaneval-refresh-disabled",
      fields: Object.keys(authDocument["openai-codex"]).sort() }
  : { exists: false };
mkdirSync(join(here, "captures"), { recursive: true });
writeFileSync(join(here, "captures", `${process.pid}.json`), JSON.stringify({ argv, stdin, cwd: process.cwd(),
  envNames: Object.keys(process.env).sort(), authFacts }));
const extension = argv[argv.indexOf("-e") + 1];
const allowed = argv.includes("--tools") ? argv[argv.indexOf("--tools") + 1].split(",") : [];
const Type = { Object: (p) => ({ type: "object", properties: p }), String: (o = {}) => ({ type: "string", ...o }),
  Integer: (o = {}) => ({ type: "integer", ...o }), Optional: (s) => s, Literal: (v) => ({ const: v }),
  Union: (s) => ({ anyOf: s }) };
const available = new Map();
if (!control.skipExtension) {
  const module = await import(join(dirname(extension), "pi_open_context_tools.mjs"));
  for (const tool of module.createOpenContextTools({ Type, env: process.env }).tools) {
    if (allowed.includes(tool.name)) available.set(tool.name, tool);
  }
}
const script = [["scaneval_git", { op: "log" }], ["scaneval_read", { path: "app.py" }],
  ["scaneval_fetch", { url: "https://example.com/advisory" }], ["scaneval_fetch", { url: "https://127.0.0.1/metadata" }],
  ["bash", { command: "cat /etc/passwd" }]];
const out = [{ type: "session", version: 3, id: "fixture", timestamp: "t", cwd: process.cwd() },
  { type: "message_end", message: { role: "user", content: stdin } }];
const seen = [];
for (const [name, params] of script) {
  const tool = available.get(name);
  if (!tool) { out.push({ type: "tool_execution_end", toolCallId: name, toolName: name, isError: true }); continue; }
  try {
    const result = await tool.execute(name, params);
    seen.push(result.content[0].text);
    out.push({ type: "tool_execution_end", toolCallId: name, toolName: name, isError: false });
  } catch {
    out.push({ type: "tool_execution_end", toolCallId: name, toolName: name, isError: true });
  }
}
const text = seen.some((t) => t.includes("second ancestor")) ? "FINDING: handler" : "no finding";
out.push({ type: "message_end", message: { role: "assistant", provider: "openai-codex", model: "gpt-5.6-sol",
  stopReason: "stop", content: [{ type: "text", text }],
  usage: { input: 7, output: 3, cacheRead: 0, cacheWrite: 0, cost: { total: 0.01 } } } });
process.stdout.write(out.map((line) => JSON.stringify(line)).join("\n") + "\n");
"""


class _Retrieval(BaseHTTPRequestHandler):
    """A stand-in for the recorded retrieval API: one fetch is public and served, one is denied."""

    requests: list[dict] = []

    def log_message(self, *_args):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).requests.append({"path": self.path, "payload": payload, "proxy": self.headers.get("Proxy-Connection")})
        denied = "127.0.0.1" in str(payload.get("url"))
        reply = ({"id": "e-denied", "outcome": "denied", "url": payload.get("url"), "redirect_chain": [],
                  "error": "destination has no public address"} if denied else
                 {"id": "e-ok", "outcome": "ok", "url": payload.get("url"), "content_sha256": "sha256:" + "a" * 64,
                  "byte_count": 8, "capture_status": "preserved", "redirect_chain": [{"status": 200}],
                  "content_base64": "YWR2aXNvcnk="})
        data = json.dumps(reply).encode()
        self.send_response(403 if denied else 200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def retrieval():
    _Retrieval.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Retrieval)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false", *args],
                   cwd=repo, check=True, capture_output=True,
                   env={"PATH": os.environ["PATH"], "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1",
                        "GIT_CONFIG_GLOBAL": "/dev/null"})


def _fixture(tmp_path: Path, *, receipt_commit: str = COMMIT) -> dict:
    tsx = SDK / "node_modules" / ".bin" / "tsx"
    if not tsx.exists() or not (SDK / "dist" / "index.js").exists():
        pytest.skip("the TypeScript SDK is not built (npm ci && npm run build in sdk/typescript)")
    if shutil.which("node") is None or shutil.which("git") is None:
        pytest.skip("node and git are required")
    harness = tmp_path / "harness"
    (harness / "src" / "runtime").mkdir(parents=True)
    (harness / "src" / "testing").mkdir(parents=True)
    (harness / "node_modules").symlink_to(SDK / "node_modules", target_is_directory=True)
    (harness / "package.json").write_text(json.dumps({"name": "securevibes-agent", "version": "0.1.0", "type": "module"}))
    (harness / "src" / "runtime" / "engine.ts").write_text(STUB_ENGINE)
    pinned = os.environ.get("SCANEVAL_SV_HARNESS_ROOT")
    if pinned:
        shutil.copyfile(Path(pinned) / "src" / "runtime" / "pi-runner.ts", harness / "src" / "runtime" / "pi-runner.ts")
        shutil.copyfile(Path(pinned) / "src" / "runtime" / "exec.ts", harness / "src" / "runtime" / "exec.ts")
    else:
        (harness / "src" / "runtime" / "pi-runner.ts").write_text(STUB_RUNNER)
        (harness / "src" / "runtime" / "exec.ts").write_text(STUB_EXEC)
    (harness / "src" / "testing" / "mock-llm-runner.ts").write_text("export {};\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_pi = bin_dir / "pi.mjs"
    fake_pi.write_text(FAKE_PI)
    fake_pi.chmod(0o755)
    receipt = tmp_path / "runtime.json"
    receipt.write_text(json.dumps({"harness": {"commit": receipt_commit, "package_version": "0.1.0"},
                                   "pi": {"version": "1.4.0"}, "node": {"version": "v26.7.0"}}))
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("def handler(q):\n    return eval(q)\n")
    _git(source, "init", "-q")
    _git(source, "add", "app.py")
    _git(source, "commit", "-q", "-m", "first ancestor")
    (source / "app.py").write_text("def handler(q):\n    return eval(q)  # v2\n")
    _git(source, "commit", "-q", "-am", "second ancestor")
    paths = {"root": str(harness), "tsx": str(tsx), "driver": str(ADAPTERS / "llm_harness_driver.mts"),
             "pi_runner": str(ADAPTERS / "pi_oci_runner.mts"), "pi_extension": str(ADAPTERS / "pi_open_context.mts"),
             "observer_sdk": str(SDK / "dist" / "index.js"), "runtime_receipt": str(receipt), "pi_binary": str(fake_pi)}
    return {"paths": paths, "source": source, "bin": bin_dir}


def _fixture_run(tmp_path, monkeypatch, retrieval, *, config: dict | None = None, forward_credentials=True,
                 control: dict | None = None, receipt_commit: str = COMMIT, container_credential: str | None = None,
                 completion_override="native"):
    fixture = _fixture(tmp_path, receipt_commit=receipt_commit)
    if completion_override != "native":
        engine = STUB_ENGINE.replace((ROOT / "tests/fixtures/sv-completion.json").read_text(), json.dumps(completion_override))
        Path(fixture["paths"]["root"], "src/runtime/engine.ts").write_text(engine)
    if control:
        (fixture["bin"] / "control.json").write_text(json.dumps(control))
    monkeypatch.setenv(DEFAULT_PI_AUTH_ENV, credential())
    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    adapter = get_adapter("llm-harness")
    spec = SystemSpec("sv-agent-image", "llm-harness", {**IMAGE, "image_paths": fixture["paths"],
                                                        "expected_harness_commit": COMMIT, **(config or {})})
    raw, trace = tmp_path / "raw", tmp_path / "trace"
    raw.mkdir()
    trace.mkdir()
    # What the oci backend puts in a public_research container: a proxy for inference (dead here,
    # so any client that used it for retrieval would fail) and the retrieval API address.
    backend = HostOciBackend(settings_for(), tmp_path, {
        "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
        "http_proxy": "http://127.0.0.1:9", "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1",
        "SCANEVAL_RETRIEVAL_URL": retrieval}, forward_credentials=forward_credentials,
        credential_override=container_credential)
    try:
        with routed_through(backend):
            outcome = adapter.scan(request=_request(), source_dir=fixture["source"], raw_dir=raw, spec=spec,
                                   preparation=adapter.prepare(spec, tmp_path), timeout_seconds=180,
                                   trace_mode="content", trace_dir=trace)
    finally:
        fixture["leftovers"] = backend.cleanup()
    captures =[json.loads(path.read_text()) for path in sorted((fixture["bin"] / "captures").glob("*.json"))] \
        if (fixture["bin"] / "captures").exists() else []
    output = json.loads((raw / "driver-output.json").read_text())
    return outcome, output, captures, backend, fixture, raw, trace


def _no_secret_anywhere(*roots: Path, extra: str = "") -> None:
    for root in roots:
        for path in root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()
                for marker in (ACCESS, REFRESH, API_KEY):
                    assert marker.encode() not in data, f"{marker} leaked into {path}"
    for marker in (ACCESS, REFRESH, API_KEY):
        assert marker not in extra


def test_fixture_run_exercises_research_history_and_tool_policy_without_leaking_the_credential(
        tmp_path, monkeypatch, retrieval):
    outcome, output, captures, backend, fixture, raw, trace = _fixture_run(tmp_path, monkeypatch, retrieval)
    assert outcome.status == "partial", (outcome.error, outcome.notes)
    assert outcome.error["code"] == "completion_unknown"
    assert "source_analysis_completion_not_established" in outcome.error["message"]
    # The driver ran with the image's tsx, from the mounted workspace, never from the harness root.
    command = backend.commands[0]
    assert command["argv"][:2] == [fixture["paths"]["tsx"], fixture["paths"]["driver"]]
    assert command["cwd"] == str(fixture["source"])
    assert "OPENAI_API_KEY" not in command["env"]
    # Pi was started with the explicit policy; the prompt reached it on stdin and never in argv.
    assert len(captures) == 1
    pi = captures[0]
    assert pi["argv"][pi["argv"].index("--tools") + 1] == "scaneval_fetch,scaneval_git,scaneval_read"
    assert "--no-tools" not in pi["argv"] and "--no-extensions" in pi["argv"] and "--no-mcp" in pi["argv"]
    assert pi["argv"][pi["argv"].index("--thinking") + 1] == "high"
    assert pi["argv"][pi["argv"].index("--model") + 1] == "gpt-5.6-sol"
    assert pi["stdin"] == PROMPT and not any(PROMPT in word for word in pi["argv"])
    assert pi["cwd"] != str(fixture["source"])
    assert DEFAULT_PI_AUTH_ENV not in pi["envNames"] and "OPENAI_API_KEY" not in pi["envNames"]
    assert pi["authFacts"] == {"exists": True, "mode": "600", "providers": ["openai-codex"],
                               "refreshDisabled": True, "fields": ["access", "accountId", "expires", "refresh", "type"]}
    # Neither the harness process nor anything it started saw the credential variable.
    assert output["summary"]["fixture"]["leaked"] == []
    # Research went straight to the retrieval API, as a tool, and the denial is the service's.
    assert [(item["path"], item["payload"].get("source"), item["payload"].get("url"))
            for item in _Retrieval.requests] == [("/fetch", "browser_tool", "https://example.com/advisory"),
                                                 ("/fetch", "browser_tool", "https://127.0.0.1/metadata")]
    # Ancestor history was reachable through the history tool: the finding depends on it.
    assert [claim["claim_id"] for claim in outcome.claims] == ["f-1"]
    calls = output["pi_calls"]
    assert calls["tool_executions"] == {"bash": {"ok": 0, "error": 1}, "scaneval_fetch": {"ok": 1, "error": 1},
                                        "scaneval_git": {"ok": 1, "error": 0}, "scaneval_read": {"ok": 1, "error": 0}}
    assert calls["thinking_overridden"] == 1 and calls["models_addressed"] == {"gpt-5.6-sol": 1}
    route = output["pi_route"]
    assert route["credential"] == {"env": DEFAULT_PI_AUTH_ENV, "provider": "openai-codex", "materialized": True,
                                   "removed": True}
    assert output["observed_routes"] == ["pi-oci"]
    assert output["runtime"]["pi_version"] == "1.4.0"
    assert all(entry["sha256"].startswith("sha256:") for entry in output["runtime"]["files"].values())
    # The record keeps availability, execution and consumption apart, and claims no served model.
    assert outcome.model_identity["requested"] == MODEL
    assert outcome.model_identity["resolved"] is None and outcome.model_identity["verification"] == "unverified"
    assert outcome.tool_versions["runtime"] == "oci_image"
    assert outcome.tool_versions["harness"] == f"securevibes-agent@{COMMIT}"
    assert outcome.tool_versions["pi"] == "1.4.0"
    assert any(artifact["id"].startswith("open-context-tools/") for artifact in outcome.artifacts)
    text = "\n".join(outcome.notes)
    assert "Tool availability" in text and "Tool execution" in text and "model consumption stays unverifiable" in text
    assert "Declared tool policy on the pi-oci route" in text
    assert outcome.usage["input_tokens"] == 7
    # The private agent directory, and the credential in it, did not outlive the run.
    assert not [name for name in fixture["leftovers"] if name.startswith("scaneval-pi-agent-")]
    _no_secret_anywhere(raw, trace, extra=repr(outcome))


def test_a_runtime_that_is_not_the_pinned_one_is_an_error(tmp_path, monkeypatch, retrieval):
    outcome, *_ = _fixture_run(tmp_path, monkeypatch, retrieval, receipt_commit="0" * 40)
    assert outcome.status == "error"
    assert outcome.error["code"] == "runtime_mismatch"
    assert COMMIT in outcome.error["message"]


def test_research_tools_that_were_not_shown_available_make_the_run_partial(tmp_path, monkeypatch, retrieval):
    outcome, *_ = _fixture_run(tmp_path, monkeypatch, retrieval, control={"skipExtension": True})
    assert outcome.status == "partial"
    assert outcome.error["code"] == "research_tools_unavailable"


def test_a_credential_that_never_reached_the_container_fails_actionably(tmp_path, monkeypatch, retrieval):
    outcome, output, captures, *_rest, raw, trace = _fixture_run(tmp_path, monkeypatch, retrieval,
                                                                 forward_credentials=False)
    assert outcome.status == "error"
    assert "is not set in the scanner container" in outcome.error["message"]
    assert captures == []
    _no_secret_anywhere(raw, trace, extra=repr(outcome))


def test_node_level_runner_and_tool_tests_pass():
    """The Pi runner's argv/stdin/output rules and the research tools' bounds, under Node's own runner."""
    if shutil.which("node") is None or shutil.which("git") is None:
        pytest.skip("node and git are required")
    completed = subprocess.run(["node", "--test", str(ROOT / "tests" / "node" / "sv_pi_oci.test.mjs")],
                               capture_output=True, text=True, timeout=300, check=False)
    assert completed.returncode == 0, completed.stdout[-4000:] + completed.stderr[-2000:]


def _completion():
    return json.loads((ROOT / "tests/fixtures/sv-completion.json").read_text())


def _no_source_completion():
    """Pinned native shape for a scan explicitly requiring no source assessment."""
    report = _completion()
    report["changedFileSupport"] = {"status": "not-required", "scope": {
        "totalChangedFiles": 1, "changedFilesInScope": 0, "unsupportedChangedFiles": 0,
        "excludedChangedFiles": 0, "knownNonCodeChangedFiles": 1,
        "unknownUnsupportedChangedFiles": 0, "unsupportedExtensionHistogram": {}}}
    report["hypothesisEvaluation"] = {"status": "not-required", "planned": 0, "evaluated": 0,
                                       "failedIds": [], "unevaluatedIds": []}
    report["sourceAssessment"] = {"status": "not-required", "files": []}
    report["coverage"] = {"status": "not-required", "reasons": []}
    return report


def test_completion_absence_is_legacy_only_and_null_is_malformed():
    assert read_completion({}, required=False) == ([], None, None)
    assert read_completion({}, required=True)[1] == "completion_unavailable"
    assert read_completion({"completion": None}, required=False)[1] == "completion_malformed"
    assert read_completion({"completion": _no_source_completion()}, required=True)[1] is None
    notes, code, message = read_completion({"completion": _completion()}, required=True)
    assert code == "completion_unknown"
    assert "source_analysis_completion_not_established" in message
    assert "logical invocation" in notes[0]


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(schemaVersion=True),
    lambda r: r.pop("execution"),
    lambda r: r["execution"].update(status="pending"),
    lambda r: r["modelCalls"].update(status="unknown"),
    lambda r: r["modelCalls"].update(status="not-run"),
    lambda r: r["modelCalls"].update(attempted=2),
    lambda r: r["modelCalls"].update(attempted=True),
    lambda r: r["modelCalls"].update(unit="transport-attempts"),
    lambda r: r["modelCalls"].pop("failureSamples"),
    lambda r: r["modelCalls"].update(truncatedFailureSamples=1),
    lambda r: r["coverage"].update(status="future-state"),
    lambda r: r["coverage"].update(reasons="not a list"),
    lambda r: r["coverage"].update(status="complete", reasons=[]),
    lambda r: r.pop("sourceAssessment"),
    lambda r: r["structuralCoverage"]["planningInspections"].update(failed=1),
])
def test_malformed_or_contradictory_native_completion_never_means_success(mutate):
    report = _completion()
    mutate(report)
    assert read_completion({"completion": report}, required=True)[1] == "completion_malformed"


def test_failed_and_pending_calls_and_incomplete_coverage_are_partial():
    report = _completion()
    report["modelCalls"].update(status="failures-recorded", succeeded=0, failed=1,
                                failureSamples=[{"callId": 1, "phase": "planning", "kind": "nonzero-exit", "code": 1}])
    assert read_completion({"completion": report}, required=True)[1] == "completion_model_calls"
    report["modelCalls"]["failureSamples"][0]["callId"] = 2
    assert read_completion({"completion": report}, required=True)[1] == "completion_malformed"
    report = _completion()
    report["modelCalls"].update(succeeded=0, pending=1)
    assert read_completion({"completion": report}, required=True)[1] == "completion_model_calls"
    report = _completion()
    report["coverage"] = {"status": "incomplete", "reasons": ["structural_coverage_incomplete"]}
    report["structuralCoverage"].update(status="incomplete", requiredInspectionFailures=1)
    assert read_completion({"completion": report}, required=True)[1] == "completion_incomplete"


@pytest.mark.parametrize("completion,expected", [
    (None, "completion_malformed"),
    ({**_completion(), "modelCalls": {**_completion()["modelCalls"], "status": "unknown"}}, "completion_malformed"),
    ({**_completion(), "modelCalls": {**_completion()["modelCalls"], "succeeded": 0, "pending": 1}}, "completion_model_calls"),
])
def test_real_driver_completion_fault_preserves_findings_without_success(tmp_path, monkeypatch, retrieval, completion, expected):
    outcome, _output, _captures, _backend, _fixture_data, raw, trace = _fixture_run(
        tmp_path, monkeypatch, retrieval, completion_override=completion)
    assert outcome.status == "partial"
    assert outcome.error["code"] == expected
    assert [claim["claim_id"] for claim in outcome.claims] == ["f-1"]
    _no_secret_anywhere(raw, trace, extra=repr(outcome))


@pytest.mark.parametrize("extra", [{"refresh": REFRESH}, {"refresh": ""}, {REFRESH: "opaque"}, {"metadata": {"refresh": REFRESH}}])
def test_host_rejects_refresh_material_and_unrecognized_fields_before_container_entry(tmp_path, monkeypatch, extra):
    document = json.loads(credential())
    document["openai-codex"].update(extra)
    raw = json.dumps(document)
    monkeypatch.setenv(DEFAULT_PI_AUTH_ENV, raw)
    backend = HostOciBackend(settings_for(), tmp_path, {})
    with pytest.raises(AdapterError) as caught:
        _scan(get_adapter("llm-harness"), SystemSpec("s", "llm-harness", IMAGE), tmp_path, backend)
    assert backend.commands == []
    assert os.environ[DEFAULT_PI_AUTH_ENV] == raw, "the shared host environment is never rewritten"
    assert ACCESS not in str(caught.value) and REFRESH not in str(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize("expires", [float("nan"), float("inf"), float("-inf"), 10**100, True, ACCESS])
def test_host_expiry_is_finite_numeric_without_secret_error_context(expires):
    document = json.loads(credential())
    document["openai-codex"]["expires"] = expires
    with pytest.raises(AdapterError, match="numeric expiry") as caught:
        check_pi_credential(json.dumps(document), "openai-codex", DEFAULT_PI_AUTH_ENV)
    assert ACCESS not in repr(caught.value) and REFRESH not in repr(caught.value)
    assert caught.value.__context__ is None


def test_access_token_must_outlive_timeout_plus_pi_refresh_window_and_margin():
    now = 1000
    window = credential_validity(1800)
    assert window == 2160
    document = json.loads(credential())
    document["openai-codex"]["expires"] = (now + window) * 1000
    with pytest.raises(AdapterError, match="expires within 2160 seconds"):
        check_pi_credential(json.dumps(document), "openai-codex", DEFAULT_PI_AUTH_ENV, now=now, valid_for_seconds=window)
    document["openai-codex"]["expires"] += 1
    check_pi_credential(json.dumps(document), "openai-codex", DEFAULT_PI_AUTH_ENV, now=now, valid_for_seconds=window)
    for timeout in (float("nan"), float("inf"), True, -1):
        with pytest.raises(AdapterError):
            credential_validity(timeout)


def test_duplicate_credential_fields_are_refused_without_dumping_document():
    raw = '{"openai-codex":{"type":"oauth","access":"' + ACCESS + '","access":"' + REFRESH + '"}}'
    with pytest.raises(AdapterError, match="not JSON") as caught:
        check_pi_credential(raw, "openai-codex", DEFAULT_PI_AUTH_ENV)
    assert ACCESS not in repr(caught.value) and REFRESH not in repr(caught.value)
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize("extra", [{"refresh": REFRESH}, {REFRESH: ACCESS}, {"expires": 1e309}])
def test_driver_checks_access_only_credentials_again_without_dumping_fields(tmp_path, monkeypatch, retrieval, extra):
    document = json.loads(credential())
    document["openai-codex"].update(extra)
    outcome, _output, captures, _backend, _fixture_data, raw, trace = _fixture_run(
        tmp_path, monkeypatch, retrieval, container_credential=json.dumps(document))
    assert outcome.status == "error"
    assert captures == []
    _no_secret_anywhere(raw, trace, extra=repr(outcome))
