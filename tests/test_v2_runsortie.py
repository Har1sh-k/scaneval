"""Native RunSortie adapter: strict preparation, one native scan, independent evidence, completion.

Every default end-to-end test runs the real :func:`scaneval.execution.run_invocation` against a deterministic
stand-in for ``node dist/cli.js scan`` (tests/fixtures/runsortie/fake_runsortie.py) that follows the
pinned ``scanTarget`` control flow: the engine, the review packets, the primary's guard, the challenger,
the work budget, the wrapper's own evidence commit, checkpoint withholding, the baseline state machine
and the native exit codes. By default no model, network, or real RunSortie is used. The separately marked
opt-in conformance cases use the real pinned CLI with fabricated engine and agent processes. Scenario
hooks tamper with what the stand-in leaves so the adapter's own checks, not the stand-in's honesty,
decide each status.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import itertools
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import threading
import zlib

import pytest

from scaneval.adapters import get_adapter
from scaneval.adapters import runsortie_evidence as ev
from scaneval.adapters.base import AdapterError, SystemSpec, _unreaped_wait_supported, routed_through
from scaneval.adapters import runsortie as rs
from scaneval.adapters.runsortie import (RunSortieAdapter, SUPPORTED_RUNSORTIE_COMMIT,
                                         SUPPORTED_RUNSORTIE_VERSION, native_config, read_settings)
from scaneval.cli import main
from scaneval.contracts import canonical_json, canonical_sha256, load_document
from scaneval.execution import PreparedInput, run_invocation
from scaneval.materialize import git_command, hash_exported_tree
from scaneval.scoring import score


FAKE = Path(__file__).parent / "fixtures" / "runsortie" / "fake_runsortie.py"
CLOCK = lambda: datetime(2026, 11, 3, tzinfo=timezone.utc)  # noqa: E731
FINDINGS = [
    {"id": "FG-CMDI-0001", "severity": "critical", "file": "src/app.py", "cwe": ["CWE-78"]},
    {"id": "FG-SQLI-0002", "severity": "high", "file": "src/db.py", "class": "sql_injection"},
    {"id": "FG-LOG-0003", "severity": "low", "file": "src/app.py", "class": "information_disclosure"},
]
# CPython has os.waitid on Linux, and on macOS only from 3.13. Without it the native path refuses at
# its first capability probe, which the waitid regressions below check on every platform.
WAITID_SKIP = "needs os.waitid, which macOS CPython has from Python 3.13"
NEEDS_WAITID = pytest.mark.skipif(not _unreaped_wait_supported(), reason=WAITID_SKIP)


def _git(cwd: Path, *args: str) -> str:
    argv, env = git_command(["-c", "user.name=t", "-c", "user.email=t@example.invalid", *args])
    return subprocess.run(argv, cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _executable(path: Path, text: str) -> None:
    _write(path, text)
    path.chmod(0o755)


class Runtime:
    def __init__(self, tmp_path: Path, monkeypatch):
        self.tmp = tmp_path
        # Production secure v1 refuses every direct-agent route.  Most tests below exercise the
        # already-written evidence/runtime machinery with deterministic fake processes through this
        # explicit test-only monkeypatch; refusal itself has dedicated unpatched regressions.
        self.native_direct_agent_capability = rs._direct_agent_capability
        monkeypatch.setattr(rs, "_direct_agent_capability", lambda settings: {
            "runnable": True, "status": "synthetic-test-only",
            "selected_agents": sorted({settings.primary.agent, settings.challenger.agent}),
            "required_boundary": "synthetic deterministic fake", "reasons": [],
        })
        monkeypatch.setattr(RunSortieAdapter, "env_passthrough", tuple(sorted(rs.CREDENTIAL_ENV_ALLOWLIST)))
        self.root = tmp_path / "runsortie"
        root = self.root
        _write(root / "package.json", json.dumps({"name": "runsortie", "version": "0.1.0"}))
        _write(root / "package-lock.json", json.dumps({"name": "runsortie", "lockfileVersion": 3,
                                                       "packages": {"": {"name": "runsortie", "version": "0.1.0"}}}))
        _write(root / ".gitignore", "dist/\nnode_modules/\n")
        _write(root / "skills" / "security-review" / "SKILL.md", "# skill\n")
        _write(root / "dist" / "cli.js", "#!/usr/bin/env node\nimport './main.js';\n")
        _write(root / "dist" / "main.js", "export {};\n")
        _write(root / "node_modules" / "runtime-dependency" / "index.js", "export const runtime = 1;\n")
        _write(root / "node_modules" / "runtime-dependency" / "twin.js", "export const runtime = 1;\n")
        (root / "node_modules" / "runtime-dependency" / "current.js").symlink_to("index.js")
        engine = root / "fieldglass"
        _write(engine / "package.json", json.dumps({"name": "@runsortie/fieldglass", "version": "0.1.0",
                                                    "scripts": {"runtime": "tsx src/runtime/cli.ts"}}))
        _write(engine / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "@runsortie/fieldglass"}, "node_modules/tsx": {"version": "4.19.2"},
            "node_modules/@esbuild/linux-x64": {"version": "0.23.0", "optional": True}}}))
        _write(engine / "src" / "runtime" / "cli.ts", "// engine entry\n")
        _write(engine / "node_modules" / ".package-lock.json",
               json.dumps({"packages": {"node_modules/tsx": {"version": "4.19.2"}}}))
        _write(engine / "node_modules" / "tsx" / "package.json", json.dumps({"version": "4.19.2"}))
        _write(engine / "node_modules" / "tsx" / "dist" / "cli.mjs", "// tsx\n")
        (engine / "node_modules" / ".bin").mkdir()
        (engine / "node_modules" / ".bin" / "tsx").symlink_to("../tsx/dist/cli.mjs")
        _git(root, "init", "-q")
        _git(root, "add", "-A")
        _git(root, "commit", "-q", "-m", "pinned")
        self.actual_commit = _git(root, "rev-parse", "HEAD")
        self.commit = SUPPORTED_RUNSORTIE_COMMIT
        native_checkout = rs._verified_runtime_checkout
        self.native_verified_checkout = native_checkout

        def pinned_checkout(checkout, expected_commit, deadline=None):
            if Path(checkout) == root:
                identity = native_checkout(checkout, self.actual_commit, deadline)
                return {**identity, "commit": expected_commit}
            return native_checkout(checkout, expected_commit, deadline)

        monkeypatch.setattr(rs, "_verified_runtime_checkout", pinned_checkout)
        files = []
        for path in sorted((root / "dist").rglob("*")):
            if path.is_file() and not path.is_symlink():
                digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
                files.append((path.relative_to(root / "dist").as_posix(), digest))
        self.dist_digest = "sha256:" + hashlib.sha256(
            "".join(f"{name}\0{digest}\n" for name, digest in files).encode()).hexdigest()
        self.bin = tmp_path / "bin"
        self.scenario = tmp_path / "scenario.json"
        self.log = tmp_path / "invocations.jsonl"
        _executable(self.bin / "node", f'#!/bin/sh\nexec "{sys.executable}" -I "{FAKE}" --scenario "{self.scenario}" "$@"\n')
        self.agent_packages = {}
        npm_root = self.tmp / "cli-packages" / "npm"
        _write(npm_root / "package.json", json.dumps({
            "name": "npm", "version": "10.9.0", "bin": {"npm": "bin/npm-cli.js"}}))
        _executable(npm_root / "bin" / "npm-cli.js", "#!/bin/sh\necho 10.9.0\n")
        _write(npm_root / "lib" / "cli.js", "export const npmRuntime = 1;\n")
        (self.bin / "npm").symlink_to(npm_root / "bin" / "npm-cli.js")
        self.npm_package = npm_root
        package_specs = {
            "claude": ("@anthropic-ai/claude-code", "2.1.310", Path("bin/claude.exe")),
            "gemini": ("@google/gemini-cli", "1.0.0", Path("bundle/gemini.js")),
            "pi": ("@earendil-works/pi-coding-agent", "1.4.0", Path("dist/bundle/cli.js")),
        }
        for agent, (package_name, package_version, launcher_relative) in package_specs.items():
            package_root = self.tmp / "cli-packages" / agent
            _write(package_root / "package.json", json.dumps({
                "name": package_name, "version": package_version, "bin": {agent: launcher_relative.as_posix()}}))
            _executable(package_root / launcher_relative, "#!/bin/sh\nexit 0\n")
            self.agent_packages[agent] = package_root
            (self.bin / agent).symlink_to(package_root / launcher_relative)
        agent_fixture = r'''#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "2.1.310 (Claude Code)"
fi
exit 0
'''
        _executable(self.agent_packages["claude"] / "bin" / "claude.exe", agent_fixture)
        pi_fixture = r'''#!/bin/sh
for argument in "$@"; do
  case "$argument" in
    --fixture-env-output=*)
      output=${argument#*=}
      env | LC_ALL=C sort > "$output"
      printf '%s\n' "$@" > "$output.args"
      exit 0
      ;;
  esac
done
if [ "$1" = "--version" ]; then echo "1.4.0"; exit 0; fi
if [ "$1" = "--help" ]; then
  echo "--no-tools --no-extensions --no-mcp --no-skills --no-prompt-templates --no-themes --no-context-files --no-approve"
  exit 0
fi
exit 0
'''
        _executable(self.agent_packages["pi"] / "dist" / "bundle" / "cli.js", pi_fixture)
        _write(self.agent_packages["pi"] / "dist" / "bundle" / "cli-runtime.js",
               "export const runtime = 1;\n")
        # Only the fakes and the real Git: an agent CLI installed elsewhere on the operator's PATH must
        # never be found, recorded or started by a test.
        (self.bin / "git").symlink_to(shutil.which("git"))
        monkeypatch.setenv("PATH", os.pathsep.join((str(self.bin), "/usr/bin", "/bin")))
        monkeypatch.setenv("OPENAI_API_KEY", "fixture-engine-api-key")

    def config(self, **overrides) -> dict:
        config = {"root": str(self.root), "expected_commit": self.commit,
                  "expected_version": SUPPORTED_RUNSORTIE_VERSION,
                  "expected_dist_tree_sha256": self.dist_digest,
                  "engine_model": "fieldglass-route/model-a",
                  "primary": {"agent": "claude", "model": "primary-model", "reasoning_effort": "high"},
                  "challenger": {"agent": "claude", "model": "challenger-model"},
                  "credential_env": {"engine": "OPENAI_API_KEY"}}
        config.update(overrides)
        return {key: value for key, value in config.items() if value is not None}

    def invocations(self) -> list[dict]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]


@pytest.fixture
def runtime(tmp_path, monkeypatch) -> Runtime:
    return Runtime(tmp_path, monkeypatch)


def _prepared(tmp_path: Path, *, mode: str = "full", target_pi: bool = False, **extra) -> PreparedInput:
    source = tmp_path / "input" / "source"
    _write(source / "src" / "app.py", "import os\n\ndef run(cmd):\n    os.system(cmd)\n")
    _write(source / "src" / "db.py", "def q(c, v):\n    return c.execute('select ' + v)\n")
    _write(source / "README.md", "# fixture\n")
    if target_pi:
        _write(source / ".pi" / "commands" / "poison.md", "project Pi migration surface\n")
    return PreparedInput("fixture-py", source, hash_exported_tree(source)["tree_hash"], ("python",),
                         {"source": {"commit": "fixture"}}, mode=mode, **extra)


def _run(runtime: Runtime, scenario: dict, *, config: dict | None = None, timeout: float = 60,
         name: str = "run") -> tuple[dict, dict, Path]:
    if not _unreaped_wait_supported():
        pytest.skip(WAITID_SKIP)  # every run prepares through the capability probes
    scenario = {"invocation_log": str(runtime.log), **scenario}
    runtime.scenario.write_text(json.dumps(scenario), encoding="utf-8")
    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-fake", "runsortie", config or runtime.config())
    preparation = adapter.prepare(spec, runtime.tmp / "cache")
    bundle = run_invocation(prepared=_prepared(runtime.tmp / name), adapter=adapter, spec=spec,
                            preparation=preparation, out_dir=runtime.tmp / name / "out", run_id=f"run-{name}",
                            timeout_seconds=timeout, trace_mode="off", network_policy="model_provider_only",
                            clock=CLOCK)
    return (load_document(bundle / "result.json", "scan-result"),
            load_document(bundle / "execution.json", "execution-record"), bundle)


def _reconciliation(bundle: Path) -> dict:
    return json.loads((bundle / "raw" / "runsortie-reconciliation.json").read_text(encoding="utf-8"))


def _artifacts(execution: dict) -> dict[str, str]:
    return {artifact["id"]: artifact["path"] for artifact in execution["raw_artifacts"]}


def _claim_ids(result: dict) -> list[str]:
    return sorted(claim["claim_id"] for claim in result["claims"])


def _quiet_review(result: dict) -> tuple[dict, dict]:
    plan = {"schema_version": "2.0", "input_hash": result["input_hash"], "scope": "diagnostic",
            "targets": [{"target_id": "T1", "description": "planted", "validation_level": "fixture"}],
            "controls": [{"control_id": "C1", "description": "safe capability", "type": "capability_safe",
                          "validation_level": "fixture"}],
            "review_budgets": [3]}
    decisions = {"schema_version": "2.0", "run_id": result["run_id"], "input_hash": result["input_hash"],
                 "result_sha256": canonical_sha256(result), "claim_matches": [],
                 "control_assessments": [{"control_id": "C1", "decision": "quiet", "claim_ids": [],
                                          "reason": "nothing was said about the safe capability"}]}
    return plan, decisions


def _call_with_deadline(function, seconds: float = 60.0):
    box: dict = {}

    def call():
        try:
            box["value"] = function()
        except BaseException as exc:  # noqa: BLE001 - re-raised on the test thread
            box["error"] = exc

    thread = threading.Thread(target=call, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), f"the call did not return within {seconds}s"
    if "error" in box:
        raise box["error"]
    return box["value"]


# --- registry and configuration ---------------------------------------------------------------

def test_runsortie_is_a_standalone_adapter_and_llm_harness_keeps_its_meaning():
    adapter = get_adapter("runsortie")
    assert isinstance(adapter, RunSortieAdapter)
    assert (adapter.name, adapter.adapter_version, adapter.requires_git) == ("runsortie", "0.1.0", True)
    assert adapter.scan_modes == frozenset({"full"}) and adapter.oci_compatible is False
    assert adapter.supported_languages == frozenset({"python", "javascript", "typescript", "go", "rust"})
    assert adapter.env_passthrough == ()
    assert adapter.state_dirs == (".fieldglass",) and adapter.state_capture_dirs == ()
    harness = get_adapter("llm-harness")
    assert harness.name == "llm-harness" and harness.adapter_version == "2.7.0"
    assert type(harness).__module__ == "scaneval.adapters.llm_harness"


def test_git_plumbing_ignores_and_workspace_guard_rejects_replace_refs(tmp_path, monkeypatch):
    repo = tmp_path / "replace-repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _write(repo / "value.txt", "one\n")
    _git(repo, "add", "value.txt")
    _git(repo, "commit", "-q", "-m", "first")
    first = _git(repo, "rev-parse", "HEAD")
    _write(repo / "value.txt", "two\n")
    _git(repo, "add", "value.txt")
    _git(repo, "commit", "-q", "-m", "second")
    second = _git(repo, "rev-parse", "HEAD")
    _git(repo, "replace", first, second)

    normal = subprocess.run(["git", "-C", str(repo), "show", "-s", "--format=%s", first],
                            check=True, capture_output=True, text=True).stdout.strip()
    hermetic = rs._hermetic_git(repo, "show", "-s", "--format=%s", first,
                               git_dir=repo / ".git").stdout.decode().strip()
    assert normal == "second" and hermetic == "first"
    monkeypatch.setattr(rs, "MAX_GIT_OUTPUT_BYTES", 2)
    with pytest.raises(AdapterError, match="output exceeded"):
        rs._hermetic_git(repo, "show", "-s", "--format=%s", first, git_dir=repo / ".git")
    with pytest.raises(AdapterError, match="refs/replace"):
        rs._git_dir(repo)


@pytest.mark.parametrize("change,match", [
    ({"api_key": "sk-inline"}, "unknown key"),
    ({"root": None}, "config.root"),
    ({"root": "relative/path"}, "absolute path"),
    ({"expected_commit": "abc123"}, "40-hex"),
    ({"expected_commit": "af8f2402469dca441f6d9efd5929ddeab5c64958"}, "supports only RunSortie commit"),
    ({"expected_version": "latest"}, "package version"),
    ({"expected_version": "0.1.1"}, "supports only RunSortie package version"),
    ({"expected_dist_tree_sha256": None}, "expected_dist_tree_sha256"),
    ({"expected_dist_tree_sha256": "sha256:" + "A" * 64}, "expected_dist_tree_sha256"),
    ({"engine_model": None}, "engine_model"),
    ({"primary": {"agent": "unknown", "model": "m"}}, "primary.agent"),
    ({"primary": {"agent": "claude", "model": "m", "reasoning_effort": "minimal"}}, "reasoning_effort must be one of"),
    ({"primary": {"agent": "cursor", "model": "m", "reasoning_effort": "low"}}, "no enforceable reasoning-effort"),
    ({"primary": {"agent": "claude", "model": "m", "token": "x"}}, "nothing else"),
    ({"challenger": {"agent": "unknown", "model": "other"}}, "challenger.agent"),
    ({"challenger": {"agent": "claude", "model": "primary-model"}}, "must differ"),
    ({"engine_model": "claude:engine-model"}, "hardened Pi engine route only"),
    ({"engine_model": "openai-codex/gpt-5.1-codex"}, "openai-codex provider"),
    ({"engine_model": "pi:openai-codex/gpt-5.1-codex"}, "openai-codex provider"),
    ({"minimum_severity": "critical"}, "minimum_severity"),
    ({"credential_env": {"engine": "sk-live-value"}}, "refused sk-live-value"),
    ({"credential_env": {"engine": "RUNSORTIE_ENGINE_PATH"}}, "refused RUNSORTIE_ENGINE_PATH"),
    ({"credential_env": {"engine": "NODE_OPTIONS"}}, "refused NODE_OPTIONS"),
    ({"credential_env": {"engine": "CLAUDE_CONFIG_DIR"}}, "refused CLAUDE_CONFIG_DIR"),
    ({"credential_env": {"engine": "CODEX_HOME"}}, "refused CODEX_HOME"),
    ({"credential_env": {"engine": "PI_CODING_AGENT_DIR"}}, "refused PI_CODING_AGENT_DIR"),
    ({"credential_env": {"engine": "BASH_ENV"}}, "refused BASH_ENV"),
    ({"credential_env": {"engine": "ENV"}}, "refused ENV"),
    ({"work_budget": {"version": 1}}, "at least one"),
    ({"work_budget": {"version": 1, "modelCalls": {"reviewer": 1}}}, "roles"),
    ({"work_budget": {"version": 2, "maxModelFiles": 1}}, "version"),
    ({"work_budget": {"version": 1, "maxElapsedMs": 0}}, "positive"),
])
def test_configuration_is_strict_and_never_holds_an_inline_secret(runtime, change, match):
    with pytest.raises(AdapterError, match=match):
        read_settings(runtime.config(**change))


def test_configuration_accepts_only_named_provider_secrets_without_values(runtime):
    settings = read_settings(runtime.config(credential_env={"engine": "OPENROUTER_API_KEY"}))
    assert settings.credential_env == {"engine": "OPENROUTER_API_KEY"}


@pytest.mark.parametrize(("primary_agent", "challenger_agent"), list(itertools.product(rs.AGENTS, repeat=2)))
def test_secure_v1_records_and_returns_unsupported_for_every_native_direct_agent_without_launch(
        runtime, monkeypatch, primary_agent, challenger_agent):
    monkeypatch.setattr(rs, "_direct_agent_capability", runtime.native_direct_agent_capability)
    monkeypatch.setattr(rs, "runtime_identity",
                        lambda *_args, **_kwargs: pytest.fail("refusal must precede runtime probing"))
    monkeypatch.setattr(rs, "_probe",
                        lambda *_args, **_kwargs: pytest.fail("refusal must precede CLI probes"))
    monkeypatch.setattr(rs, "run_command",
                        lambda *_args, **_kwargs: pytest.fail("unsupported capability must never launch a command"))
    config = runtime.config(
        primary={"agent": primary_agent, "model": "primary-route"},
        challenger={"agent": challenger_agent, "model": "challenger-route"})
    adapter = RunSortieAdapter()
    spec = SystemSpec("r", "runsortie", config)
    preparation = adapter.prepare(spec, runtime.tmp)
    assert preparation["runnable"] is False
    assert preparation["capability"]["selected_agents"] == sorted({primary_agent, challenger_agent})
    assert preparation["capability"]["reasons"]
    outcome = adapter.scan(
        request={"input": {"mode": "full", "pr": None}}, source_dir=runtime.tmp / "source",
        raw_dir=runtime.tmp / "raw", spec=spec, preparation=preparation, timeout_seconds=30,
        trace_mode="off", trace_dir=None)
    assert outcome.status == "unsupported" and outcome.command == [] and outcome.exit_code is None
    assert outcome.error["code"] == "unsupported_runtime_boundary"
    assert outcome.examined_nothing is True and outcome.bundles_resolved is False
    assert runtime.invocations() == []


def test_secure_v1_unsupported_bundle_validates_replays_and_advertises_no_provider_credentials(
        tmp_path, monkeypatch):
    config = {
        "root": str(tmp_path / "checkout-is-not-inspected"),
        "expected_commit": SUPPORTED_RUNSORTIE_COMMIT,
        "expected_version": SUPPORTED_RUNSORTIE_VERSION,
        "expected_dist_tree_sha256": "sha256:" + "0" * 64,
        "engine_model": "fabricated/engine",
        "primary": {"agent": "codex", "model": "primary-route"},
        "challenger": {"agent": "claude", "model": "challenger-route"},
        "credential_env": {"engine": "OPENROUTER_API_KEY"},
    }
    adapter = RunSortieAdapter()
    spec = SystemSpec("runsortie-unsupported", "runsortie", config)
    preparation = adapter.prepare(spec, tmp_path / "cache")
    assert preparation["runnable"] is False
    bundle = run_invocation(
        prepared=_prepared(tmp_path), adapter=adapter, spec=spec, preparation=preparation,
        out_dir=tmp_path / "out", run_id="run-unsupported", timeout_seconds=30,
        trace_mode="off", network_policy="model_provider_only", clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    assert result["status"] == execution["status"] == "unsupported"
    assert result["examined_nothing"] is True and result["bundles_resolved"] is False
    assert execution["command"] == [] and execution["exit_code"] is None
    assert execution["raw_artifacts"] == []
    assert not set(rs.CREDENTIAL_ENV_ALLOWLIST) & set(execution["environment"]["passthrough"])

    plan, decisions = _quiet_review(result)
    evaluator = bundle / "evaluator"
    evaluator.mkdir()
    (evaluator / "plan.json").write_text(canonical_json(plan) + "\n", encoding="utf-8")
    (evaluator / "decisions.json").write_text(canonical_json(decisions) + "\n", encoding="utf-8")

    def refused(*_args, **_kwargs):
        raise AssertionError("unsupported offline replay tried to open a socket or start a process")

    # Refuse construction rather than replace the class: replay may import ssl first, which subclasses it.
    monkeypatch.setattr(socket.socket, "__init__", refused)
    monkeypatch.setattr(subprocess, "Popen", refused)
    replayed = tmp_path / "replayed-unsupported.json"
    assert main(["replay", str(bundle), "--output", str(replayed)]) == 0
    assert json.loads(replayed.read_text(encoding="utf-8")) == score(plan, result, decisions)


@NEEDS_WAITID
def test_preparation_records_pinned_identities_at_their_real_assurance(runtime):
    preparation = get_adapter("runsortie").prepare(SystemSpec("s", "runsortie", runtime.config(
        credential_env={"engine": "OPENAI_API_KEY"}, work_budget={"version": 1, "maxModelFiles": 3})), runtime.tmp)
    assert preparation["runsortie"]["git_head"] == runtime.commit and preparation["runsortie"]["git_status_clean"]
    assert preparation["runsortie"]["package_version"] == "0.1.0"
    assert "not proven to be built" in preparation["dist"]["assurance"]
    assert preparation["dist"]["cli_sha256"].startswith("sha256:") and preparation["dist"]["files"] == 2
    assert preparation["fieldglass"]["local_path"] == str(runtime.root / "fieldglass")
    assert preparation["fieldglass"]["tsx_version"] == "4.19.2"
    assert "every fieldglass/node_modules" in preparation["fieldglass"]["assurance"]
    assert preparation["runsortie_node_modules"]["files"] == 2
    assert preparation["engine_driver"]["driver"] == "pi" and preparation["engine_driver"]["sha256"].startswith("sha256:")
    assert preparation["engine_driver"]["package_name"] == "@earendil-works/pi-coding-agent"
    assert preparation["engine_driver"]["package_version"] == "1.4.0"
    assert preparation["engine_driver"]["package_tree"]["tree_sha256"].startswith("sha256:")
    assert preparation["node"]["version"] == "v22.11.0" and preparation["npm"]["version"] == "10.9.0"
    assert preparation["npm"]["package_name"] == "npm"
    assert preparation["npm"]["package_tree"]["tree_sha256"].startswith("sha256:")
    assert preparation["npm_script_shell"]["configured_path"] == "/bin/sh"
    assert preparation["npm_script_shell"]["path"] == str(rs.NPM_SCRIPT_SHELL.resolve(strict=True))
    assert preparation["npm_script_shell"]["sha256"].startswith("sha256:")
    assert preparation["agent_shell"]["path"] == "/bin/bash"
    assert preparation["agent_shell"]["sha256"].startswith("sha256:")
    assert set(preparation["agents"]) == {"claude"}
    assert preparation["agents"]["claude"]["package_name"] == "@anthropic-ai/claude-code"
    assert preparation["agents"]["claude"]["package_version"] == "2.1.310"
    assert preparation["probe_capabilities"]["pi"]["allIsolationFlags"] is True
    assert preparation["probe_capabilities"]["directAgentSecurityBoundaryAttested"] is False
    assert preparation["probe_capabilities"]["agents"]["claude"] == {
        "versionObservedOnly": True, "securityBoundaryAttested": False}
    assert preparation["provider_attestation"] is None
    assert preparation["credential_env"] == {"engine": "OPENAI_API_KEY"}
    assert preparation["routes"]["primary"] == {"agent": "claude", "model": "primary-model", "reasoning_effort": "high"}
    json.dumps(preparation)


@pytest.mark.parametrize("role,field,value", [
    ("pi", "name", "@mariozechner/pi-coding-agent"),
    ("pi", "version", "1.4.1"),
    ("claude", "name", "@anthropic-ai/claude-code-near-miss"),
    ("claude", "version", "2.1.311"),
])
def test_preparation_refuses_near_miss_selected_cli_package_contracts(runtime, role, field, value):
    manifest = runtime.agent_packages[role] / "package.json"
    package = json.loads(manifest.read_text(encoding="utf-8"))
    package[field] = value
    manifest.write_text(json.dumps(package), encoding="utf-8")
    with pytest.raises(AdapterError, match=rf"synthetic native-path contract requires {role}"):
        RunSortieAdapter().prepare(SystemSpec("r", "runsortie", runtime.config()), runtime.tmp / "cache")


@NEEDS_WAITID
def test_preparation_refuses_pi_without_every_injected_isolation_capability(runtime):
    _executable(runtime.agent_packages["pi"] / "dist" / "bundle" / "cli.js", r'''#!/bin/sh
if [ "$1" = "--version" ]; then echo 1.4.0; exit 0; fi
if [ "$1" = "--help" ]; then echo --no-tools; exit 0; fi
exit 0
''')
    with pytest.raises(AdapterError, match="does not expose required isolation flag"):
        RunSortieAdapter().prepare(SystemSpec("r", "runsortie", runtime.config()), runtime.tmp / "cache")


def test_dist_identity_refuses_an_external_module_symlink(runtime):
    outside = runtime.tmp / "outside-runtime.js"
    _write(outside, "export const redirected = true;\n")
    (runtime.root / "dist" / "redirected.js").symlink_to(outside)
    with pytest.raises(AdapterError, match="link or special file"):
        rs._dist_identity(runtime.root)


@pytest.mark.parametrize("relative", [False, True])
def test_fixed_executable_identity_refuses_a_link_even_to_a_regular_binary(tmp_path, relative):
    target = tmp_path / "regular-shell"
    _executable(target, "#!/bin/sh\nexit 0\n")
    linked = tmp_path / "linked-agent-shell"
    linked.symlink_to(target.name if relative else target)
    with pytest.raises(AdapterError, match="no-follow executable regular file"):
        rs._fixed_executable(linked, "fixture shell")


@pytest.mark.parametrize("relative", [False, True])
def test_npm_script_shell_identity_records_the_exact_trusted_alias_target(tmp_path, monkeypatch, relative):
    target = tmp_path / "regular-shell"
    _executable(target, "#!/bin/sh\nexit 0\n")
    alias = tmp_path / "trusted-system-shell"
    alias.symlink_to(target.name if relative else target)
    monkeypatch.setattr(rs, "NPM_SCRIPT_SHELL", alias)
    identity = rs._npm_script_shell_identity()
    assert identity == {"configured_path": str(alias), **rs._fixed_executable(target, "fixture shell")}
    assert identity["path"] == identity["realpath"] == str(target.resolve(strict=True))
    assert not Path(identity["path"]).is_symlink()


@pytest.mark.parametrize("unsafe", ["space shell", "tab\tshell", "line\nshell", "return\rshell"])
def test_npm_script_shell_identity_refuses_a_target_unsafe_for_shebang(tmp_path, monkeypatch, unsafe):
    target = tmp_path / unsafe
    _executable(target, "#!/bin/sh\nexit 0\n")
    alias = tmp_path / "trusted-system-shell"
    alias.symlink_to(target)
    monkeypatch.setattr(rs, "NPM_SCRIPT_SHELL", alias)
    with pytest.raises(AdapterError, match="unsafe for a shebang"):
        rs._npm_script_shell_identity()


@NEEDS_WAITID
def test_npm_script_shell_alias_resolves_before_probes_and_detects_drift(runtime, monkeypatch):
    target = rs.AGENT_SHELL.resolve(strict=True)
    replacement = runtime.tmp / "replacement-shell"
    _executable(replacement, "#!/bin/sh\nexit 0\n")
    agent_shell_identity = rs._fixed_executable(rs.AGENT_SHELL, "fixture agent shell")
    alias = runtime.tmp / "trusted-system-shell"
    alias.symlink_to(target)
    monkeypatch.setattr(rs, "NPM_SCRIPT_SHELL", alias)
    native_probe = rs._probe
    observed_shells = []

    def probe(*args, **kwargs):
        observed_shells.append(kwargs["env"]["npm_config_script_shell"])
        wrapper = Path(kwargs["env"]["SHELL"]).read_text(encoding="utf-8")
        assert wrapper.startswith("#!" + str(target) + "\n")
        assert ("\nexec " + shlex.quote(agent_shell_identity["realpath"])
                + ' --noprofile --norc "$@"\n') in wrapper
        assert "#!/bin/sh" not in wrapper
        return native_probe(*args, **kwargs)

    monkeypatch.setattr(rs, "_probe", probe)
    adapter = RunSortieAdapter()
    spec = SystemSpec("r", "runsortie", runtime.config())
    preparation = adapter.prepare(spec, runtime.tmp)
    assert preparation["npm_script_shell"]["path"] == str(target)
    assert preparation["agent_shell"] == agent_shell_identity
    assert observed_shells and set(observed_shells) == {str(target)}
    alias.unlink()
    alias.symlink_to(replacement)
    with pytest.raises(AdapterError, match="runtime changed"):
        adapter.scan(request={"input": {"mode": "full", "pr": None}}, source_dir=runtime.tmp / "source",
                     raw_dir=runtime.tmp / "raw", spec=spec, preparation=preparation, timeout_seconds=30,
                     trace_mode="off", trace_dir=None)
    assert runtime.invocations() == []


@pytest.mark.parametrize("reported", [
    None, pytest.param("v21.19.0", marks=NEEDS_WAITID), pytest.param("not-a-node-version", marks=NEEDS_WAITID),
])
def test_preparation_requires_node_22_or_newer(runtime, monkeypatch, reported):
    native_probe = rs._probe

    def probe(executable, *args, **kwargs):
        return reported if Path(executable).name == "node" else native_probe(executable, *args, **kwargs)

    monkeypatch.setattr(rs, "_probe", probe)
    with pytest.raises(AdapterError, match=r"Node\.js version >=22|isolated node --version probe failed"):
        RunSortieAdapter().prepare(SystemSpec("r", "runsortie", runtime.config()), runtime.tmp / "cache")


@NEEDS_WAITID
def test_probe_never_signals_a_numeric_group_after_the_leader_was_already_reaped(monkeypatch):
    monkeypatch.setattr(rs, "_wait_for_unreaped_exit",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(ChildProcessError()))

    def forbidden_signal(*_args, **_kwargs):
        raise AssertionError("a reaped leader's PID/PGID must never be signalled")

    monkeypatch.setattr(rs.os, "killpg", forbidden_signal)
    assert rs._probe(shutil.which("true")) is None


@NEEDS_WAITID
def test_probe_drains_and_refuses_a_successful_launcher_that_leaves_a_group_child(tmp_path):
    launcher = tmp_path / "lingering-help"
    _executable(launcher, "#!/bin/sh\nsleep 30 </dev/null >/dev/null 2>&1 &\necho --help\n")
    assert rs._probe(str(launcher), "--help", timeout_seconds=3) is None


def test_probe_refuses_before_launch_where_waitid_is_missing(monkeypatch):
    # macOS CPython has no os.waitid before 3.13, so the probe could not keep its leader unreaped.
    monkeypatch.delattr(rs.os, "waitid", raising=False)
    monkeypatch.setattr(rs.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("a probe was launched"))
    with pytest.raises(AdapterError, match=r"capability probes require POSIX waitid\(WNOWAIT\) support"):
        rs._probe(shutil.which("true"))


def test_preparation_refuses_where_waitid_is_missing_and_removes_the_probe_home(runtime, monkeypatch):
    probe_parent = runtime.tmp / "probe-parent"
    probe_parent.mkdir()
    monkeypatch.setattr(rs.tempfile, "tempdir", str(probe_parent))
    monkeypatch.delattr(rs.os, "waitid", raising=False)
    with pytest.raises(AdapterError, match=r"capability probes require POSIX waitid\(WNOWAIT\) support"):
        RunSortieAdapter().prepare(SystemSpec("r", "runsortie", runtime.config()), runtime.tmp / "cache")
    assert list(probe_parent.iterdir()) == []


@pytest.mark.parametrize("prefix", ["", ".", "relative/bin"])
def test_preparation_rejects_path_entries_whose_meaning_depends_on_cwd(runtime, monkeypatch, prefix):
    monkeypatch.setenv("PATH", prefix + os.pathsep + os.environ["PATH"])
    with pytest.raises(AdapterError, match="nonempty absolute directory entries"):
        RunSortieAdapter().prepare(SystemSpec("r", "runsortie", runtime.config()), runtime.tmp / "cache")


@pytest.mark.parametrize("route,driver", [
    ("pi:model-a", "pi"), ("unknown:model-a", "pi"),
])
@NEEDS_WAITID
def test_engine_driver_identity_uses_the_pinned_fieldglass_route_parser(runtime, route, driver):
    preparation = get_adapter("runsortie").prepare(
        SystemSpec("s", "runsortie", runtime.config(engine_model=route)), runtime.tmp / "cache")
    assert preparation["engine_driver"]["driver"] == driver
    assert preparation["engine_driver"]["realpath"] == str((runtime.bin / driver).resolve())
    assert preparation["engine_driver"]["sha256"].startswith("sha256:")


def test_preparation_refuses_an_unpinned_dirty_unbuilt_or_uninstalled_runtime(runtime):
    adapter = get_adapter("runsortie")

    def prepare(**change):
        return adapter.prepare(SystemSpec("s", "runsortie", runtime.config(**change)), runtime.tmp)

    with pytest.raises(AdapterError, match="does not exist"):
        prepare(root=str(runtime.tmp / "missing"))
    with pytest.raises(AdapterError, match="supports only RunSortie commit"):
        prepare(expected_commit="0" * 40)
    with pytest.raises(AdapterError, match="supports only RunSortie package version"):
        prepare(expected_version="9.9.9")
    (runtime.root / "untracked.txt").write_text("x", encoding="utf-8")
    with pytest.raises(AdapterError, match="untracked modifications"):
        prepare()
    (runtime.root / "untracked.txt").unlink()
    lock = runtime.root / "fieldglass" / "node_modules" / ".package-lock.json"
    original = lock.read_text(encoding="utf-8")
    lock.write_text(json.dumps({"packages": {"node_modules/tsx": {"version": "4.0.0"}}}), encoding="utf-8")
    with pytest.raises(AdapterError, match="differ from its package-lock"):
        prepare()
    lock.write_text(original, encoding="utf-8")
    (runtime.root / "dist" / "cli.js").unlink()
    with pytest.raises(AdapterError, match="must already be built"):
        prepare()
    _write(runtime.root / "dist" / "cli.js", "#!/usr/bin/env node\nimport './main.js';\n")
    (runtime.bin / "claude").unlink()
    with pytest.raises(AdapterError, match="claude is not on PATH"):
        prepare()


def test_preparation_rejects_the_real_checkout_head_when_it_differs_from_the_supported_pin(runtime, monkeypatch):
    monkeypatch.setattr(rs, "_verified_runtime_checkout", runtime.native_verified_checkout)
    assert runtime.actual_commit != SUPPORTED_RUNSORTIE_COMMIT
    with pytest.raises(AdapterError, match="not expected_commit"):
        RunSortieAdapter().prepare(SystemSpec("r", "runsortie", runtime.config()), runtime.tmp / "cache")


def test_runtime_checkout_pin_rehashes_tracked_bytes_and_old_oid_objects(runtime):
    relative = "fieldglass/src/runtime/cli.ts"
    object_id = _git(runtime.root, "rev-parse", f"HEAD:{relative}")
    _git(runtime.root, "update-index", "--assume-unchanged", relative)
    forged = b"// forged tracked runtime\n"
    (runtime.root / relative).write_bytes(forged)
    raw = b"blob %d\0" % len(forged) + forged
    object_path = runtime.root / ".git" / "objects" / object_id[:2] / object_id[2:]
    object_path.chmod(0o600)
    object_path.write_bytes(zlib.compress(raw))
    assert _git(runtime.root, "status", "--porcelain", "--untracked-files=all") == "", \
        "the fixture hid the tracked mutation from ordinary status/stat-cache checks"

    with pytest.raises(AdapterError, match="loose Git blob|does not match the pinned commit tree"):
        runtime.native_verified_checkout(runtime.root, runtime.actual_commit, rs.Deadline(10))


def test_native_config_targets_the_workspace_only_and_never_pushes(runtime):
    settings = read_settings(runtime.config(minimum_severity="medium",
                                            work_budget={"version": 1, "modelCalls": {"challenger": 2}}))
    config = native_config(settings, repo=Path("/work/source"), branch="master")
    assert config["targets"] == [{"name": "scaneval", "repo": "/work/source", "branch": "master", "scopeHints": [],
                                  "outputPaths": [".fieldglass"], "commitResults": True, "pushResults": False}]
    assert config["schedule"]["enabled"] is False and "notifications" not in config
    assert config["engine"] == {"source": "bundled:fieldglass", "ref": "bundled",
                                "localPath": str(runtime.root / "fieldglass"), "model": "fieldglass-route/model-a"}
    assert config["agent"] == "claude" and config["agentModel"] == "primary-model"
    assert config["agentReasoningEffort"] == "high"
    assert config["verifier"] == {"agent": "claude", "model": "challenger-model", "minimumSeverity": "medium"}
    assert config["workBudget"] == {"version": 1, "modelCalls": {"challenger": 2}}


def test_primary_prompt_port_has_the_pinned_native_preimage():
    prompt = ev.build_scan_prompt(
        skill="# skill\n", target="scaneval",
        source_revision="0123456789abcdef0123456789abcdef01234567",
        minimum_severity="high", verifier_configured=True)
    assert len(prompt.encode("utf-8")) == 3922
    assert hashlib.sha256(prompt.encode("utf-8")).hexdigest() == \
        "b7e33b9eabcde48f40dda461e2ae55d43cab314b045d9f7efe09c2616cd65d96"
    assert ev.primary_review_prompt_hash(prompt) == \
        "97192c61632530c1a2055c54e11f40a287c6500bd7c812cf920c9762ff98a135"


# --- success and completion ------------------------------------------------------------------

def test_a_complete_run_succeeds_with_claims_and_separate_disposition_metadata(runtime, monkeypatch):
    npm_shell_target = rs.AGENT_SHELL.resolve(strict=True)
    npm_shell_alias = runtime.tmp / "trusted-system-shell"
    npm_shell_alias.symlink_to(npm_shell_target)
    monkeypatch.setattr(rs, "NPM_SCRIPT_SHELL", npm_shell_alias)
    fieldglass_bin = runtime.root / "fieldglass" / "node_modules" / ".bin"
    for poisoned in ("pi", "git", "node"):
        _executable(fieldglass_bin / poisoned, "#!/bin/sh\nexit 96\n")
    operator_home = runtime.tmp / "operator-home"
    _write(operator_home / ".npmrc", "script-shell=/operator/attacker-shell\nnode-options=--require=/operator/hook.js\n")
    _write(operator_home / ".pi" / "agent" / "extensions" / "poison.js", "throw new Error('poison');\n")
    monkeypatch.setenv("HOME", str(operator_home))
    poison_shell = operator_home / "attacker-bash"
    _executable(poison_shell, "#!/bin/sh\nexit 97\n")
    monkeypatch.setenv("SHELL", str(poison_shell))
    monkeypatch.setenv("LANG", "poison_LOCALE")
    monkeypatch.setenv("LC_ALL", "poison_LOCALE")
    monkeypatch.setenv("NODE_OPTIONS", "--require=/operator/environment-hook.js")
    monkeypatch.setenv("OPENAI_API_KEY", "s3cr3t-token-value")
    monkeypatch.setenv("OPENROUTER_API_KEY", "engine-role-secret")
    monkeypatch.setenv("UNNAMED_SECRET", "never-passed-value")
    monkeypatch.setenv("RUNSORTIE_ENGINE_PATH", "/operator/engine")
    result, execution, bundle = _run(runtime, {
        "engine": {"findings": FINDINGS}, "primary": {"dispositions": {"FG-SQLI-0002": "dismissed"}},
        "probe_role_wrappers": ["pi"],
        "probe_npm_shell_path": True,
        "wrapper_log_env": ["OPENAI_API_KEY", "OPENROUTER_API_KEY", "HF_TOKEN"],
        "log_env": ["RUNSORTIE_STATE_DIR", "RUNSORTIE_CACHE_DIR", "RUNSORTIE_ENGINE_PATH", "OPENAI_API_KEY",
                    "OPENROUTER_API_KEY", "UNNAMED_SECRET", "GIT_CONFIG_GLOBAL", "npm_config_offline", "NODE_OPTIONS",
                    "npm_config_node_options", "npm_config_userconfig", "npm_config_globalconfig",
                    "npm_config_script_shell", "npm_config_cache", "HOME", "TMPDIR", "XDG_CONFIG_HOME",
                    "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "PI_CODING_AGENT_DIR",
                    "SHELL", "LANG", "LC_ALL"],
    }, config=runtime.config(credential_env={"engine": "OPENROUTER_API_KEY"}))

    assert result["status"] == "success", result.get("error")
    assert result["bundles_resolved"] is True and "error" not in result
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003"], "a verified dismissal is withheld from claims"
    claim = next(claim for claim in result["claims"] if claim["claim_id"] == "FG-CMDI-0001")
    assert claim["native_rule_id"] == "fieldglass:command_injection" and claim["native_severity"] == "critical"
    assert claim["native_cwe"] == ["CWE-78"] and claim["primary_location"] == {"path": "src/app.py"}
    artifacts = _artifacts(execution)
    assert all(claim["raw_artifact_id"] in artifacts for claim in result["claims"])
    assert any(name.startswith("runsortie-findings/") and "sqli" in name for name in artifacts), \
        "the dismissed finding's raw record stays registered"
    for name in ("runsortie-config", "runsortie-stdout", "runsortie-stderr", "runsortie-reconciliation",
                 "runsortie-primary-prompt", "runsortie-agent-isolation", "runsortie-pi-wrapper",
                 "runsortie-npm-script-shell-wrapper", "runsortie-tsx-wrapper",
                 "runsortie-agent-shell-wrapper",
                 "runsortie-receipts/verification-summary.json", "runsortie-receipts/baseline-acceptance.json",
                 "runsortie-receipts/.state.json", "runsortie-receipts/sortie-state.json",
                 "runsortie-receipts/primary-review-packets.json", "runsortie-native-state/state.json"):
        assert name in artifacts, name
    assert all((bundle / path).is_file() for path in artifacts.values()), "only concrete files are registered"
    assert any(name.startswith("runsortie-native-state/review-work/") for name in artifacts)

    receipt = _reconciliation(bundle)
    by_id = {entry["finding_id"]: entry for entry in receipt["findings"]}
    assert by_id["FG-CMDI-0001"]["native_disposition"] == "confirmed"
    assert by_id["FG-CMDI-0001"]["reportability"] == "reported-confirmed"
    assert by_id["FG-SQLI-0002"]["native_disposition"] == "dismissed"
    assert by_id["FG-SQLI-0002"]["reportability"] == "withheld-dismissed-after-complete-verification"
    assert by_id["FG-LOG-0003"]["reportability"] == "reported-outside-review"
    assert by_id["FG-LOG-0003"]["severity"] == "low" and by_id["FG-LOG-0003"]["engine_status"] == "open"
    assert receipt["verdict"] == {"status": "success", "code": None, "unmet": []}
    assert receipt["readings"]["review_work_journal"] == {"state": "valid", "issues": []}
    assert receipt["native"]["observed_routes"] == ["challenger=claude/challenger-model", "primary=claude/primary-model"]
    assert receipt["changed_paths"] and all(path.startswith(".fieldglass/") for path in receipt["changed_paths"])

    assert execution["model_identity"] is None
    assert "OPENROUTER_API_KEY" in execution["environment"]["passthrough"]
    assert execution["tool_versions"]["runsortie"] == f"runsortie@{runtime.commit}"
    assert execution["tool_versions"]["observed_review_routes"].startswith("challenger=claude/")
    assert any("local and unenforced" in note for note in execution["notes"])
    assert any("history" in note for note in execution["notes"])
    condition = json.loads((bundle / "condition.json").read_text(encoding="utf-8"))
    assert "history_changed" in {reason["code"] for reason in condition["reasons"]}, \
        "the evidence commit is recorded by the condition audit, not hidden"
    assert result["processing"] == "full"

    [call] = runtime.invocations()
    assert call["argv"][1:] == ["scan", "--config", call["argv"][3], "--target", "scaneval"]
    assert call["argv"][0] == str(runtime.root / "dist" / "cli.js")
    assert call["config_mode"] == "0o600"
    env = call["env"]
    assert env["OPENAI_API_KEY"] is None and env["UNNAMED_SECRET"] is None
    assert env["OPENROUTER_API_KEY"] == "engine-role-secret"
    assert env["RUNSORTIE_ENGINE_PATH"] is None, "the operator's engine override never reaches RunSortie"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull and env["npm_config_offline"] == "true"
    assert env["NODE_OPTIONS"] == env["npm_config_node_options"] == ""
    assert env["npm_config_userconfig"] == env["npm_config_globalconfig"] == os.devnull
    assert Path(env["npm_config_script_shell"]).name == "runsortie-npm-script-shell"
    assert env["HOME"] != str(operator_home) and Path(env["HOME"]).name == "home"
    private_root = Path(env["HOME"]).parent
    for key in ("TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME",
                "PI_CODING_AGENT_DIR"):
        assert Path(env[key]).is_relative_to(private_root), (key, env[key])
    assert set(call["private_modes"].values()) == {"0o700"}
    assert call["private_poison_paths"] == [], "operator config/hooks were not copied into the private homes"
    assert Path(env["SHELL"]).name == "scaneval-bash"
    shell_wrapper = (bundle / artifacts["runsortie-agent-shell-wrapper"]).read_text(encoding="utf-8")
    assert shlex.quote(str(rs.AGENT_SHELL.resolve(strict=True))) + " --noprofile --norc" in shell_wrapper
    assert env["LANG"] == env["LC_ALL"] == "C"
    assert not private_root.exists(), "the isolated home and agent state are deleted after bounded inspection"
    assert call["pi_auth"] == call["pi_models_store"] == "{}"
    assert Path(call["resolved_pi"]).name == "pi" and "isolated-bin" in Path(call["resolved_pi"]).parts
    assert all(flag in call["pi_wrapper"] for flag in rs.PI_ISOLATION_FLAGS)
    preparation_pi_target = str(runtime.agent_packages["pi"] / "dist" / "bundle" / "cli.js")
    assert preparation_pi_target in call["pi_wrapper"]
    assert call["role_wrapper_env"]["pi"] == {
        "OPENAI_API_KEY": None, "OPENROUTER_API_KEY": "engine-role-secret", "HF_TOKEN": None}
    assert all(flag in call["role_wrapper_argv"]["pi"] for flag in rs.PI_ISOLATION_FLAGS)
    assert [Path(path).name for path in call["npm_shell_resolutions"]] == ["pi", "git", "node", "tsx"]
    assert all(not Path(path).is_relative_to(fieldglass_bin) for path in call["npm_shell_resolutions"])
    assert "isolated-bin" in Path(call["npm_shell_resolutions"][0]).parts
    assert "isolated-bin" in Path(call["npm_shell_resolutions"][3]).parts
    npm_wrapper = (bundle / artifacts["runsortie-npm-script-shell-wrapper"]).read_text(encoding="utf-8")
    assert "\nexec " + shlex.quote(str(npm_shell_target)) + ' "$@"\n' in npm_wrapper
    for name in ("runsortie-pi-wrapper", "runsortie-npm-script-shell-wrapper", "runsortie-tsx-wrapper",
                 "runsortie-agent-shell-wrapper"):
        wrapper = (bundle / artifacts[name]).read_text(encoding="utf-8")
        assert wrapper.startswith("#!" + str(npm_shell_target) + "\n")
        assert "#!/bin/sh" not in wrapper
    isolation = json.loads((bundle / artifacts["runsortie-agent-isolation"]).read_text(encoding="utf-8"))
    assert isolation["syntheticNativePathOnly"] is True
    assert isolation["productionDirectAgentCapability"] == "unsupported"
    assert isolation["directAgentSecurityBoundaryAttested"] is False
    assert isolation["credentialEnvironmentRoles"] == {"engine": "OPENROUTER_API_KEY"}
    assert isolation["dynamicAgentStatePreserved"] is False
    assert all(value["sha256"].startswith("sha256:") for value in isolation["immutablePolicy"].values())
    assert Path(env["npm_config_cache"]).name == "npm-cache" and not Path(env["npm_config_cache"]).exists()
    assert Path(env["RUNSORTIE_STATE_DIR"]).name == "state" and not Path(env["RUNSORTIE_STATE_DIR"]).exists(), \
        "the invocation-owned state directory is removed once its files are staged"
    config = json.loads((bundle / artifacts["runsortie-config"]).read_text(encoding="utf-8"))
    assert config["targets"][0]["pushResults"] is False and config["targets"][0]["commitResults"] is True
    prompt = (bundle / artifacts["runsortie-primary-prompt"]).read_text(encoding="utf-8")
    summary = json.loads((bundle / artifacts["runsortie-receipts/verification-summary.json"]).read_text())
    assert summary["primaryReview"]["promptBytes"] == len(prompt.encode("utf-8"))
    for path in bundle.rglob("*"):
        if path.is_file() and not path.is_symlink():
            assert b"s3cr3t-token-value" not in path.read_bytes(), path

    plan, decisions = _quiet_review(result)
    controls = score(plan, result, decisions)["metrics"]["controls"]["capability_safe"]
    assert controls["completed"] == 1, "a fully established run can earn quiet credit"


@pytest.mark.parametrize("operation,expected_state", [
    ({"op": "journal_delete"}, "absent"),
    ({"op": "journal_relocate_wrong_path"}, "absent"),
    ({"op": "journal_drop_challenger_reseal"}, "invalid"),
])
def test_missing_or_self_consistently_tampered_review_work_journal_blocks_success_and_keeps_claims(
        runtime, operation, expected_state):
    result, _, bundle = _run(runtime, {
        "engine": {"findings": FINDINGS},
        "hooks": {"before_commit": [operation]},
    })

    receipt = _reconciliation(bundle)
    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert receipt["readings"]["review_work_journal"]["state"] == expected_state
    assert "verification_invalid" in receipt["verdict"]["unmet"]
    if expected_state == "invalid":
        assert any("challenger journal" in issue
                   for issue in receipt["readings"]["review_work_journal"]["issues"])


def test_resealed_arbitrary_primary_prompt_hash_blocks_success_and_keeps_claims(runtime):
    result, _, bundle = _run(runtime, {
        "engine": {"findings": FINDINGS},
        "hooks": {"before_commit": [{"op": "journal_prompt_hash_reseal"}]},
    })
    receipt = _reconciliation(bundle)
    assert result["status"] == "partial"
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert receipt["readings"]["review_work_journal"]["state"] == "invalid"
    assert any("primary journal identity" in issue
               for issue in receipt["readings"]["review_work_journal"]["issues"])


@pytest.mark.parametrize("operation,reading", [
    ({"op": "json_set", "path": ".fieldglass/sortie-state.json",
      "keys": ["reviewPolicy", "evaluatedAt"], "value": "2026-11-03T12:00:00+00:00"},
     "review_state"),
    ({"op": "json_set", "path": ".fieldglass/verification-summary.json",
      "keys": ["evaluatedAt"], "value": "2026-11-03T12:00:00Z"},
     "verification"),
    ({"op": "json_set", "path": ".fieldglass/verification-summary.json",
      "keys": ["groups", 0, "reviewedAt"], "value": "2026-11-03T12:00:00+00:00"},
     "verification"),
    ({"op": "journal_created_at_reseal", "value": "2026-11-03T12:00:00+00:00"},
     "review_work_journal"),
    ({"op": "journal_updated_at_reseal", "value": "2026-11-03T12:00:00Z"},
     "review_work_journal"),
    ({"op": "journal_attempt_at_reseal", "value": "2026-11-03T12:00:00+00:00"},
     "review_work_journal"),
], ids=["policy-offset", "summary-no-millis", "group-offset", "journal-created-offset",
        "journal-updated-no-millis", "journal-attempt-offset"])
def test_non_native_review_timestamp_spellings_never_gate_success(runtime, operation, reading):
    result, _, bundle = _run(runtime, {
        "engine": {"findings": FINDINGS}, "hooks": {"before_commit": [operation]}})
    receipt = _reconciliation(bundle)
    assert result["status"] != "success" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert receipt["readings"][reading]["state"] == "invalid"


@pytest.mark.parametrize("findings", [[], FINDINGS], ids=["empty-plan", "nonempty-plan"])
def test_primary_prompt_byte_counter_is_bound_for_empty_and_nonempty_plans(runtime, findings):
    result, _, bundle = _run(runtime, {
        "engine": {"findings": findings},
        "hooks": {"before_commit": [{"op": "json_set", "path": ".fieldglass/verification-summary.json",
                                       "keys": ["primaryReview", "promptBytes"], "value": 0}]},
    })
    receipt = _reconciliation(bundle)
    assert result["status"] == "partial"
    assert receipt["readings"]["verification"]["state"] == "invalid"
    assert any("primary-review accounting" in issue
               for issue in receipt["readings"]["verification"]["issues"])


def test_complete_runsortie_bundle_validates_and_replays_offline(runtime, monkeypatch, tmp_path):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS}})
    assert result["status"] == "success"
    plan, decisions = _quiet_review(result)
    evaluator = bundle / "evaluator"
    evaluator.mkdir()
    (evaluator / "plan.json").write_text(canonical_json(plan) + "\n", encoding="utf-8")
    (evaluator / "decisions.json").write_text(canonical_json(decisions) + "\n", encoding="utf-8")
    expected = score(plan, result, decisions)

    def refused(*_args, **_kwargs):
        raise AssertionError("offline replay tried to open a socket or start a process")

    # Refuse construction rather than replace the class: replay may import ssl first, which subclasses it.
    monkeypatch.setattr(socket.socket, "__init__", refused)
    monkeypatch.setattr(subprocess, "Popen", refused)
    replayed = tmp_path / "replayed.json"
    assert main(["replay", str(bundle), "--output", str(replayed)]) == 0
    assert json.loads(replayed.read_text(encoding="utf-8")) == expected


def test_exact_root_multi_member_packet_and_verification_are_accepted_end_to_end(runtime):
    grouped = [
        {"id": "FG-GROUP-0001", "severity": "high", "file": "src/app.py", "class": "command_injection",
         "component": "api", "source_symbol": "request.cmd", "sink_symbol": "os.system",
         "structural": "flow=request.cmd to os.system"},
        {"id": "FG-GROUP-0002", "severity": "high", "file": "src/app.py", "class": "command_injection",
         "component": "api", "source_symbol": "request.cmd", "sink_symbol": "os.system",
         "structural": "flow=request.cmd to os.system"},
    ]
    result, execution, bundle = _run(runtime, {"engine": {"findings": grouped}})
    assert result["status"] == "success", result.get("error")
    assert _claim_ids(result) == ["FG-GROUP-0001", "FG-GROUP-0002"]
    artifacts = _artifacts(execution)
    plan = json.loads((bundle / artifacts["runsortie-receipts/primary-review-packets.json"]).read_text())
    summary = json.loads((bundle / artifacts["runsortie-receipts/verification-summary.json"]).read_text())
    assert plan["packetCount"] == 1 and plan["findingCount"] == 2
    assert plan["packets"][0]["grouping"] == "exact-root-cause"
    assert plan["packets"][0]["memberFindingIds"] == ["FG-GROUP-0001", "FG-GROUP-0002"]
    assert summary["primaryReview"]["decisionsAvoided"] == 1
    assert summary["challenger"]["groupCount"] == 1
    [group] = summary["groups"]
    assert group["canonicalFindingId"] == "FG-GROUP-0001"
    assert group["duplicateFindingIds"] == ["FG-GROUP-0002"]
    assert group["findingIds"] == ["FG-GROUP-0001", "FG-GROUP-0002"]


def test_native_utf16_sort_order_binds_unicode_packet_hash_plan_and_journal(runtime):
    """U+10000 sorts before U+E000 in JavaScript UTF-16 order, opposite Python code-point order."""
    astral, bmp = "\U00010000-capability", "\ue000-capability"
    assert ev._js_sorted([bmp, astral]) == [astral, bmp]
    result, execution, bundle = _run(runtime, {"engine": {"findings": [{
        "id": "FG-UNICODE-0001", "severity": "high", "file": "src/app.py",
        "class": "command_injection", "required_capabilities": [bmp, astral],
        "scanner_sources": [bmp, astral],
    }]}})

    assert result["status"] == "success", result.get("error")
    artifacts = _artifacts(execution)
    plan = json.loads((bundle / artifacts["runsortie-receipts/primary-review-packets.json"]).read_text())
    assert plan["packets"][0]["members"][0]["requiredCapabilities"] == [astral, bmp]
    receipt = _reconciliation(bundle)
    assert receipt["readings"]["packets"]["state"] == "valid"
    assert receipt["readings"]["review_work_journal"]["state"] == "valid"


def test_git_evidence_manifest_replays_classification_and_exposes_tampering(runtime):
    result, execution, bundle = _run(runtime, {"engine": {"findings": FINDINGS}})
    assert result["status"] == "success", result.get("error")
    artifacts = _artifacts(execution)
    manifest_path = bundle / artifacts["runsortie-git-evidence-manifest"]
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw)
    assert raw == (json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    assert manifest["format"] == "scaneval-runsortie-git-evidence-v1"

    committed = {item["path"]: (item["kind"], item["oid"]) for item in manifest["committedEvidence"]}
    rebuilt = {}
    first_file = None
    for item in manifest["worktreeEvidence"]:
        assert item["kind"].startswith("file-"), "a successful preserved evidence tree contains no links"
        data = (bundle / artifacts[item["artifactId"]]).read_bytes()
        oid = rs._blob_id(data)
        assert oid == item["oid"]
        rebuilt[item["path"]] = (item["kind"], oid)
        first_file = first_file or (item, data)
    assert rebuilt == committed and manifest["worktreeMatches"] is True
    replayed = ev.classify_commit(evaluated=manifest["evaluated"], head=manifest["head"],
                                  parents=tuple(manifest["parents"]), changed=tuple(manifest["changedPaths"]),
                                  worktree_matches=rebuilt == committed)
    assert replayed.state == manifest["classification"]["state"] == "evidence-commit"

    item, data = first_file
    tampered = dict(rebuilt)
    tampered[item["path"]] = (item["kind"], rs._blob_id(data + b"tamper"))
    assert ev.classify_commit(evaluated=manifest["evaluated"], head=manifest["head"],
                              parents=tuple(manifest["parents"]), changed=tuple(manifest["changedPaths"]),
                              worktree_matches=tampered == committed).state == "evidence-commit-unmatched"
    assert ev.classify_commit(evaluated=manifest["evaluated"], head=manifest["head"],
                              parents=("f" * 40,), changed=tuple(manifest["changedPaths"]),
                              worktree_matches=True).state == "invalid"


def test_zero_findings_succeed_only_with_positive_native_verification(runtime):
    result, execution, bundle = _run(runtime, {"engine": {"findings": []}})
    assert result["status"] == "success", result.get("error")
    assert result["claims"] == [] and result["bundles_resolved"] is True
    receipt = _reconciliation(bundle)
    assert receipt["readings"]["verification"]["state"] == "complete"
    assert receipt["native"]["outcome"] == "committed"
    summary = json.loads((bundle / "raw" / "runsortie-receipts" / "verification-summary.json").read_text())
    assert {key: summary["primaryReview"][key] for key in ("agentCalls", "liveCalls", "attempts")} == {
        "agentCalls": 1, "liveCalls": 1, "attempts": 1,
    }, "af8f240 invokes the primary once even for an empty packet plan"


def test_zero_findings_with_exit_zero_and_a_ready_baseline_but_no_verification_are_partial(runtime):
    result, execution, bundle = _run(runtime, {"engine": {"findings": []},
                                               "primary": {"sentinel": "no-changes", "dispositions": "none"}})
    receipt = _reconciliation(bundle)
    assert receipt["exit_code"] == 0 and receipt["native"]["outcome"] == "no-changes"
    assert receipt["native"]["baseline"]["status"] == "ready", "the native state alone would look complete"
    assert result["status"] == "partial" and result["claims"] == []
    assert result["error"]["code"] == "runsortie_no_changes"
    assert "verification_missing" in receipt["verdict"]["unmet"]
    plan, decisions = _quiet_review(result)
    assert score(plan, result, decisions)["metrics"]["controls"]["capability_safe"]["completed"] == 0


# --- refusals before launch ------------------------------------------------------------------

@NEEDS_WAITID
def test_a_pr_request_is_unsupported_and_never_launches(runtime):
    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-fake", "runsortie", runtime.config())
    runtime.scenario.write_text(json.dumps({"invocation_log": str(runtime.log)}), encoding="utf-8")
    preparation = adapter.prepare(spec, runtime.tmp)
    prepared = _prepared(runtime.tmp / "pr", mode="pr", pr={"base_commit": "a" * 40, "head_commit": "b" * 40},
                         base_source_dir=runtime.tmp / "pr" / "input" / "source")
    bundle = run_invocation(prepared=prepared, adapter=adapter, spec=spec, preparation=preparation,
                            out_dir=runtime.tmp / "pr" / "out", run_id="run-pr", timeout_seconds=30,
                            trace_mode="off", network_policy="model_provider_only", clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    assert result["status"] == "unsupported" and result["error"]["code"] == "unsupported_mode"
    with pytest.raises(AdapterError, match="fresh full baselines only"):
        adapter.scan(request={"input": {"mode": "full", "pr": {"base": "a", "head": "b"}}},
                     source_dir=runtime.tmp, raw_dir=runtime.tmp, spec=spec, preparation=preparation,
                     timeout_seconds=5, trace_mode="off", trace_dir=None)
    assert runtime.invocations() == []


@NEEDS_WAITID
def test_active_oci_backend_is_refused_before_the_native_fake_launches(runtime):
    class OciBackend:
        name = "oci"

        def run_command(self, *args, **kwargs):
            raise AssertionError("RunSortie must not reach the OCI execution seam")

    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-fake", "runsortie", runtime.config())
    preparation = adapter.prepare(spec, runtime.tmp)
    runtime.scenario.write_text(json.dumps({"invocation_log": str(runtime.log)}), encoding="utf-8")
    with routed_through(OciBackend()), pytest.raises(AdapterError, match="only on the local unenforced backend"):
        adapter.scan(request={"input": {"mode": "full"}}, source_dir=runtime.tmp, raw_dir=runtime.tmp,
                     spec=spec, preparation=preparation, timeout_seconds=5, trace_mode="off", trace_dir=None)
    assert runtime.invocations() == []


@NEEDS_WAITID
def test_target_root_pi_configuration_is_refused_before_runsortie_launch(runtime):
    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-fake", "runsortie", runtime.config())
    preparation = adapter.prepare(spec, runtime.tmp)
    runtime.scenario.write_text(json.dumps({"invocation_log": str(runtime.log)}), encoding="utf-8")
    bundle = run_invocation(
        prepared=_prepared(runtime.tmp / "target-pi", target_pi=True), adapter=adapter, spec=spec,
        preparation=preparation, out_dir=runtime.tmp / "target-pi" / "out", run_id="run-target-pi",
        timeout_seconds=30, trace_mode="off", network_policy="model_provider_only", clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    assert result["status"] == "error" and "target-root .pi" in result["error"]["message"]
    assert runtime.invocations() == []


@NEEDS_WAITID
def test_a_runtime_changed_after_preparation_is_refused_before_launch(runtime):
    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-fake", "runsortie", runtime.config())
    preparation = adapter.prepare(spec, runtime.tmp)
    _write(runtime.root / "dist" / "cli.js", "rebuilt\n")
    runtime.scenario.write_text(json.dumps({"invocation_log": str(runtime.log)}), encoding="utf-8")
    bundle = run_invocation(prepared=_prepared(runtime.tmp / "drift"), adapter=adapter, spec=spec,
                            preparation=preparation, out_dir=runtime.tmp / "drift" / "out", run_id="run-drift",
                            timeout_seconds=30, trace_mode="off", network_policy="model_provider_only", clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    assert result["status"] == "error" and "dist/ tree digest" in result["error"]["message"]
    assert runtime.invocations() == []


@NEEDS_WAITID
def test_agent_shell_identity_drift_is_refused_before_launch(runtime):
    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-fake", "runsortie", runtime.config())
    preparation = adapter.prepare(spec, runtime.tmp)
    preparation["agent_shell"]["sha256"] = "sha256:" + "0" * 64
    runtime.scenario.write_text(json.dumps({"invocation_log": str(runtime.log)}), encoding="utf-8")
    bundle = run_invocation(
        prepared=_prepared(runtime.tmp / "agent-shell-drift"), adapter=adapter, spec=spec,
        preparation=preparation, out_dir=runtime.tmp / "agent-shell-drift" / "out",
        run_id="run-agent-shell-drift", timeout_seconds=30, trace_mode="off",
        network_policy="model_provider_only", clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    assert result["status"] == "error" and "runtime changed" in result["error"]["message"]
    assert runtime.invocations() == []


@pytest.mark.parametrize("mutation", ["same-version-bytes", "symlink-target"])
@NEEDS_WAITID
def test_installed_dependency_tree_mutation_after_preparation_is_refused(runtime, mutation):
    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-fake", "runsortie", runtime.config())
    preparation = adapter.prepare(spec, runtime.tmp)
    dependency = runtime.root / "node_modules" / "runtime-dependency"
    if mutation == "same-version-bytes":
        (dependency / "index.js").write_text("export const runtime = 2;\n", encoding="utf-8")
    else:
        (dependency / "current.js").unlink()
        (dependency / "current.js").symlink_to("twin.js")
    runtime.scenario.write_text(json.dumps({"invocation_log": str(runtime.log)}), encoding="utf-8")
    bundle = run_invocation(prepared=_prepared(runtime.tmp / mutation), adapter=adapter, spec=spec,
                            preparation=preparation, out_dir=runtime.tmp / mutation / "out",
                            run_id=f"run-{mutation}", timeout_seconds=30, trace_mode="off",
                            network_policy="model_provider_only", clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    assert result["status"] == "error" and "runtime changed" in result["error"]["message"]
    assert runtime.invocations() == []


@pytest.mark.parametrize("launcher,relative", [
    ("claude", "bin/claude.exe"),
    ("pi", "dist/bundle/cli-runtime.js"),
    ("npm", "lib/cli.js"),
])
@NEEDS_WAITID
def test_selected_launcher_package_mutation_after_preparation_is_refused(runtime, launcher, relative):
    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-fake", "runsortie", runtime.config())
    preparation = adapter.prepare(spec, runtime.tmp)
    package_root = runtime.npm_package if launcher == "npm" else runtime.agent_packages[launcher]
    (package_root / relative).write_text("same-version modified runtime\n", encoding="utf-8")
    runtime.scenario.write_text(json.dumps({"invocation_log": str(runtime.log)}), encoding="utf-8")
    name = f"launcher-{launcher}"
    bundle = run_invocation(prepared=_prepared(runtime.tmp / name), adapter=adapter, spec=spec,
                            preparation=preparation, out_dir=runtime.tmp / name / "out", run_id=f"run-{name}",
                            timeout_seconds=30, trace_mode="off", network_policy="model_provider_only", clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    assert result["status"] == "error" and "runtime changed" in result["error"]["message"]
    assert runtime.invocations() == []


# --- failures after findings -----------------------------------------------------------------

def test_a_timeout_after_findings_keeps_them(runtime):
    result, execution, bundle = _run(runtime, {
        "engine": {"findings": FINDINGS, "sleep": 30},
        "hooks": {"after_engine_write": [{"op": "bulk_file", "path": ".fieldglass/bulk-evidence.bin",
                                            "bytes": 4 * 1024 * 1024}]},
    }, timeout=4)
    assert result["status"] == "timeout" and result["error"]["code"] == "timeout"
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"], "provisional claims are kept"
    assert result["bundles_resolved"] is False
    assert {entry["reportability"] for entry in _reconciliation(bundle)["findings"]} <= {
        "reported-provisional", "reported-outside-review"}
    artifacts = _artifacts(execution)
    assert "runsortie-evidence-tree/bulk-evidence.bin" in artifacts
    assert (bundle / artifacts["runsortie-evidence-tree/bulk-evidence.bin"]).stat().st_size == 4 * 1024 * 1024


def test_an_engine_failure_after_findings_is_an_error_that_keeps_them(runtime):
    result, execution, bundle = _run(runtime, {"engine": {"findings": FINDINGS, "exit": 2}})
    assert result["status"] == "error" and result["error"]["code"] == "runsortie_runtime"
    assert "model provider unavailable" in result["error"]["message"], "the stderr tail explains the failure"
    assert len(result["claims"]) == 3 and result["bundles_resolved"] is False
    assert _reconciliation(bundle)["native"]["outcome"] == "failed"


def test_a_guard_failure_after_findings_is_an_error_that_keeps_them(runtime):
    result, execution, bundle = _run(runtime, {"engine": {"findings": FINDINGS},
                                               "primary": {"write_outside": "src/app.py"}})
    assert result["status"] == "error" and result["error"]["code"] == "runsortie_guard"
    assert "product_mutation" in _reconciliation(bundle)["verdict"]["unmet"]
    assert len(result["claims"]) == 3
    assert _reconciliation(bundle)["native"]["baseline"]["status"] == "retry-required"


def test_a_missing_agent_is_an_auth_error(runtime):
    result, _, _ = _run(runtime, {"agent_missing": True})
    assert result["status"] == "error" and result["error"]["code"] == "runsortie_auth"
    assert result["claims"] == []


def test_a_failed_primary_process_is_an_error(runtime):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS}, "primary": {"exit": 1}})
    assert result["status"] == "error" and result["error"]["code"] == "runsortie_runtime"
    assert len(result["claims"]) == 3


# --- exit zero but incomplete ----------------------------------------------------------------

def test_exit_zero_committed_incomplete_is_partial(runtime):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS, "acceptance": {"status": "inconclusive"}}})
    receipt = _reconciliation(bundle)
    assert receipt["exit_code"] == 0 and receipt["native"]["outcome"] == "committed-incomplete"
    assert result["status"] == "partial" and result["error"]["code"] == "runsortie_committed_incomplete"
    assert {"baseline_retry_required", "checkpoint_not_established", "acceptance_not_established"} <= set(
        receipt["verdict"]["unmet"])
    assert result["bundles_resolved"] is False and len(result["claims"]) == 3


def test_blocked_recovery_is_partial(runtime):
    recovery = {"status": "blocked", "planHash": "a" * 64, "reasons": ["work_item_exhausted"],
                "hypotheses": {"planned": 2, "scheduled": 2, "succeeded": 1, "failed": 1, "exhausted": 1,
                               "stillUnevaluated": 1},
                "workItems": {"scheduled": 2, "succeeded": 1, "retryable": 0, "exhausted": 1, "terminal": 0,
                              "capacityExhausted": False},
                "limits": {"maxWorkItems": 10, "maxAttemptsPerItem": 2}}
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS, "acceptance": {
        "status": "inconclusive", "reasons": ["baseline_recovery_blocked:work_item_exhausted"], "recovery": recovery}}})
    assert result["status"] == "partial"
    assert "baseline_blocked" in _reconciliation(bundle)["verdict"]["unmet"]


def test_a_missing_primary_disposition_is_review_required_and_keeps_every_claim_provisional(runtime):
    result, execution, bundle = _run(runtime, {"engine": {"findings": FINDINGS},
                                               "primary": {"dispositions": {"FG-SQLI-0002": "missing",
                                                                            "FG-CMDI-0001": "dismissed"}}})
    receipt = _reconciliation(bundle)
    assert result["status"] == "partial"
    assert {"review_required", "verification_incomplete"} <= set(receipt["verdict"]["unmet"])
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"], \
        "a dismissal is not honored while verification is incomplete"
    assert {entry["finding_id"]: entry["reportability"] for entry in receipt["findings"]}["FG-CMDI-0001"] \
        == "reported-provisional"
    summary_path = _artifacts(execution)["runsortie-receipts/verification-summary.json"]
    primary = json.loads((bundle / summary_path).read_text())["primaryReview"]
    assert {key: primary[key] for key in ("liveCalls", "failedCalls", "attempts", "journalFailedAttempts",
                                           "journalSuccessfulAttempts", "state")} == {
        "liveCalls": 1, "failedCalls": 1, "attempts": 1, "journalFailedAttempts": 1,
        "journalSuccessfulAttempts": 0, "state": "degraded"}


def test_a_failed_challenger_is_partial(runtime):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS}, "challenger": {"FG-CMDI-0001": "fail"}})
    receipt = _reconciliation(bundle)
    assert result["status"] == "partial" and "verification_incomplete" in receipt["verdict"]["unmet"]
    assert receipt["native"]["outcome"] == "committed-incomplete"


def test_an_inconclusive_disposition_the_native_summary_calls_complete_is_still_partial(runtime):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS},
                                       "primary": {"dispositions": {"FG-CMDI-0001": "inconclusive"}}})
    receipt = _reconciliation(bundle)
    assert receipt["native"]["outcome"] == "committed" and receipt["native"]["baseline"]["status"] == "ready"
    assert result["status"] == "partial" and result["error"]["code"] == "verification_unresolved"
    assert "FG-CMDI-0001" in _claim_ids(result)


def test_an_exhausted_work_budget_is_partial(runtime):
    budget = {"version": 1, "modelCalls": {"challenger": 0}}
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS}}, config=runtime.config(work_budget=budget))
    receipt = _reconciliation(bundle)
    assert result["status"] == "partial"
    assert {"work_budget_exhausted", "verification_incomplete"} <= set(receipt["verdict"]["unmet"])
    assert receipt["readings"]["work_budget"]["issues"] == ["work budget exhausted: model-calls:challenger"]


def test_zero_primary_review_budget_uses_native_skipped_call_accounting(runtime):
    budget = {"version": 1, "modelCalls": {"primaryReview": 0}}
    result, execution, bundle = _run(runtime, {"engine": {"findings": FINDINGS}},
                                     config=runtime.config(work_budget=budget))
    assert result["status"] == "partial" and result["bundles_resolved"] is False
    artifacts = _artifacts(execution)
    primary = json.loads((bundle / artifacts["runsortie-receipts/verification-summary.json"]).read_text())["primaryReview"]
    assert {key: primary[key] for key in ("liveCalls", "failedCalls", "exhaustedItems", "attempts", "state")} == {
        "liveCalls": 0, "failedCalls": 0, "exhaustedItems": 0, "attempts": 0, "state": "degraded"}
    assert "journalFailedAttempts" not in primary and "journalSuccessfulAttempts" not in primary


def test_an_unexhausted_work_budget_does_not_block_success(runtime):
    budget = {"version": 1, "modelCalls": {"challenger": 5, "primaryReview": 1}}
    result, execution, _ = _run(runtime, {"engine": {"findings": FINDINGS}}, config=runtime.config(work_budget=budget))
    assert result["status"] == "success", result.get("error")
    assert "runsortie-receipts/work-budget.json" in _artifacts(execution)


def test_nested_native_evidence_outside_the_fixed_receipt_list_is_preserved(runtime):
    result, execution, _ = _run(runtime, {"engine": {"findings": FINDINGS}, "hooks": {"before_commit": [
        {"op": "write", "path": ".fieldglass/sentinels/example.json", "text": "{\"sentinel\":true}\n"},
    ]}})
    assert result["status"] == "success", result.get("error")
    artifacts = _artifacts(execution)
    assert "runsortie-evidence-tree/sentinels/example.json" in artifacts


@pytest.mark.parametrize("relative,marker", [
    ("scan-log.md", b"# transient forged scan log\n"),
    ("findings/fg-cmdi-0001-finding.md", b"\ntransient forged finding bytes\n"),
], ids=["receipt", "finding"])
def test_single_evidence_snapshot_cannot_be_swapped_away_before_commit_verification(
        runtime, monkeypatch, relative, marker):
    native_snapshot = rs._snapshot_evidence_tree

    def transient_snapshot(root, enclosure, raw, register, deadline, source_guard=None):
        path = root / relative
        original = path.read_bytes()
        try:
            path.write_bytes(original + marker)
            snapshot = native_snapshot(root, enclosure, raw, register, deadline, source_guard)
            assert snapshot.regular(relative) == original + marker
            return snapshot
        finally:
            path.write_bytes(original)

    monkeypatch.setattr(rs, "_snapshot_evidence_tree", transient_snapshot)
    result, execution, bundle = _run(runtime, {"engine": {"findings": FINDINGS}})
    receipt = _reconciliation(bundle)
    assert result["status"] != "success"
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert receipt["readings"]["git"]["state"] == "evidence-commit-unmatched"
    assert any("single preserved evidence snapshot" in issue for issue in receipt["readings"]["git"]["issues"])
    artifacts = _artifacts(execution)
    snapshot_artifact = bundle / artifacts[f"runsortie-evidence-tree/{relative}"]
    assert snapshot_artifact.read_bytes().endswith(marker)
    if relative == "scan-log.md":
        assert (bundle / artifacts["runsortie-receipts/scan-log.md"]).read_bytes() == snapshot_artifact.read_bytes()
    else:
        finding_id = next(name for name in artifacts if name.startswith("runsortie-findings/fg-cmdi"))
        assert (bundle / artifacts[finding_id]).read_bytes() == snapshot_artifact.read_bytes()


def test_private_state_is_judged_from_the_exact_staged_snapshot(runtime, monkeypatch):
    native_preserve = RunSortieAdapter._preserve_state

    def preserve_then_swap(state_dir, guard, raw, register, deadline):
        result = native_preserve(state_dir, guard, raw, register, deadline)
        (state_dir / "state.json").write_text('{"targets":{}}\n', encoding="utf-8")
        return result

    monkeypatch.setattr(RunSortieAdapter, "_preserve_state", staticmethod(preserve_then_swap))
    result, execution, bundle = _run(runtime, {"engine": {"findings": FINDINGS}})
    assert result["status"] == "success"
    artifacts = _artifacts(execution)
    staged = json.loads((bundle / artifacts["runsortie-native-state/state.json"]).read_text())
    assert staged["targets"]["scaneval"]["outcome"] == "committed"
    assert _reconciliation(bundle)["readings"]["target_state"]["state"] == "valid"


@pytest.mark.parametrize("operation", [
    {"op": "cache_write", "path": "unexpected.txt"},
    {"op": "cache_symlink", "path": "unexpected-link", "target": "/nonexistent"},
    {"op": "cache_fifo", "path": "unexpected.fifo"},
    {"op": "cache_socket", "path": "unexpected.sock"},
])
def test_nonempty_private_cache_is_never_success_and_never_loses_claims(runtime, operation):
    result, _, bundle = _call_with_deadline(lambda: _run(runtime, {
        "engine": {"findings": FINDINGS}, "hooks": {"after": [operation]}}), 20)
    assert result["status"] != "success" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    receipt = _reconciliation(bundle)
    if operation["op"] != "cache_socket" or receipt["native"]["message"] != "[Errno 1] Operation not permitted":
        assert "evidence_preservation_failed" in receipt["verdict"]["unmet"]


def test_work_budget_reader_rejects_every_bound_counter_and_integrity_mutant(runtime):
    budget = {"version": 1, "maxModelFiles": 2, "modelCalls": {
        "planner": 3, "validation": 3, "specialist": 3, "consensus": 3,
        "primaryReview": 3, "challenger": 3,
    }}
    engine = {"findings": FINDINGS, "modelFiles": 1,
              "modelCalls": {role: 1 for role in ("planner", "validation", "specialist", "consensus")}}
    result, _, bundle = _run(runtime, {"engine": engine}, config=runtime.config(work_budget=budget))
    assert result["status"] == "success", result.get("error")
    public = json.loads((bundle / "raw" / "runsortie-receipts" / "work-budget.json").read_text())
    internal = json.loads((bundle / "raw" / "runsortie-receipts" / "fieldglass-work-budget.json").read_text())
    state = json.loads((bundle / "raw" / "runsortie-native-state" / "state.json").read_text())
    snapshot = state["targets"]["scaneval"]["workBudget"]
    summary = json.loads((bundle / "raw" / "runsortie-receipts" / "verification-summary.json").read_text())
    verification = ev.Verification("complete", frozenset(), frozenset(), frozenset(), frozenset(), (),
                                   {"primaryLiveCalls": summary["primaryReview"]["liveCalls"],
                                    "challengerAttemptedCalls": summary["challenger"]["attemptedCalls"]}, ())

    def seal(value):
        payload = {key: item for key, item in value.items() if key != "integrity"}
        value["integrity"] = hashlib.sha256(json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()

    def reading(public_value, internal_value, snapshot_value):
        return ev.read_work_budget(
            json.dumps(public_value).encode(), fieldglass_data=json.dumps(internal_value).encode(),
            configured=budget, snapshot=snapshot_value, verification=verification,
            evaluated=public["sourceHead"], target="scaneval", attempted_at=public["startedAt"])

    assert reading(public, internal, snapshot).state == "complete"
    mutants = []

    changed_public = copy.deepcopy(public)
    changed_public["updatedAt"] = "2026-11-03T23:59:59.999Z"
    mutants.append(("wrapper/state equality", changed_public, copy.deepcopy(internal), copy.deepcopy(snapshot)))

    for role in ("planner", "validation", "specialist", "consensus", "primaryReview", "challenger"):
        changed_public, changed_internal, changed_snapshot = (copy.deepcopy(public), copy.deepcopy(internal),
                                                              copy.deepcopy(snapshot))
        changed_public["modelCalls"][role]["limit"] = 99
        changed_snapshot["modelCalls"][role]["limit"] = 99
        if role in ("planner", "validation", "specialist", "consensus"):
            changed_internal["modelCalls"][role]["limit"] = 99
            seal(changed_internal)
        mutants.append((f"{role} counter", changed_public, changed_internal, changed_snapshot))

    changed_internal = copy.deepcopy(internal)
    changed_internal["modelFileHashes"] = []
    seal(changed_internal)
    mutants.append(("model-file hashes", copy.deepcopy(public), changed_internal, copy.deepcopy(snapshot)))

    changed_internal = copy.deepcopy(internal)
    changed_internal["integrity"] = "0" * 64
    mutants.append(("internal seal", copy.deepcopy(public), changed_internal, copy.deepcopy(snapshot)))

    changed_internal = copy.deepcopy(internal)
    changed_internal["status"] = "exhausted"
    seal(changed_internal)
    mutants.append(("internal exhausted without exhaustion", copy.deepcopy(public), changed_internal,
                    copy.deepcopy(snapshot)))

    changed_internal = copy.deepcopy(internal)
    changed_internal["status"] = "exhausted"
    changed_internal["modelCalls"]["planner"]["reserved"] = 3
    changed_internal["exhaustions"] = [{"resource": "model-calls:planner",
                                        "at": changed_internal["updatedAt"], "limit": 3, "reserved": 3}]
    seal(changed_internal)
    mutants.append(("internal-only exhaustion", copy.deepcopy(public), changed_internal, copy.deepcopy(snapshot)))

    changed_public, changed_internal, changed_snapshot = (copy.deepcopy(public), copy.deepcopy(internal),
                                                          copy.deepcopy(snapshot))
    aggregate_only = {"resource": "model-calls:planner", "at": changed_internal["updatedAt"],
                      "limit": 3, "reserved": 3}
    for value in (changed_public, changed_snapshot):
        value["status"] = "exhausted"
        value["modelCalls"]["planner"]["reserved"] = 3
        value["exhaustions"] = [aggregate_only]
    changed_internal["modelCalls"]["planner"]["reserved"] = 3
    seal(changed_internal)
    mutants.append(("aggregate-only internal-owned exhaustion", changed_public, changed_internal, changed_snapshot))

    changed_public, changed_internal, changed_snapshot = (copy.deepcopy(public), copy.deepcopy(internal),
                                                          copy.deepcopy(snapshot))
    exhaustion = {"resource": "model-calls:planner", "at": changed_internal["updatedAt"],
                  "limit": 3, "reserved": 3}
    for value in (changed_public, changed_snapshot):
        value["status"] = "exhausted"
        value["modelCalls"]["planner"]["reserved"] = 3
        value["exhaustions"] = [exhaustion]
    changed_internal["modelCalls"]["planner"]["reserved"] = 3
    changed_internal["exhaustions"] = [exhaustion]
    changed_internal["status"] = "complete"
    seal(changed_internal)
    mutants.append(("internal complete with exhaustion", changed_public, changed_internal, changed_snapshot))

    changed_public, changed_internal, changed_snapshot = (copy.deepcopy(public), copy.deepcopy(internal),
                                                          copy.deepcopy(snapshot))
    for value in (changed_public, changed_snapshot, changed_internal):
        value["runId"] = "not-a-uuid"
    seal(changed_internal)
    mutants.append(("run UUID", changed_public, changed_internal, changed_snapshot))

    changed_public, changed_snapshot = copy.deepcopy(public), copy.deepcopy(snapshot)
    changed_public["sourceHead"] = changed_snapshot["sourceHead"] = "f" * 40
    mutants.append(("source head", changed_public, copy.deepcopy(internal), changed_snapshot))

    changed_public, changed_internal, changed_snapshot = (copy.deepcopy(public), copy.deepcopy(internal),
                                                          copy.deepcopy(snapshot))
    changed_public["updatedAt"] = changed_snapshot["updatedAt"] = "2026-11-02T00:00:00.000Z"
    changed_internal["updatedAt"] = "2026-11-02T00:00:00.000Z"
    seal(changed_internal)
    mutants.append(("timestamp chronology", changed_public, changed_internal, changed_snapshot))

    for label, public_value, internal_value, snapshot_value in mutants:
        assert reading(public_value, internal_value, snapshot_value).state == "invalid", label


# --- contradictions --------------------------------------------------------------------------

@pytest.mark.parametrize("hook,code", [
    ({"before_commit": [{"op": "write", "path": ".fieldglass/verification-summary.json", "text": "{"}]},
     "verification_invalid"),
    ({"before_commit": [{"op": "patch", "path": ".fieldglass/verification-summary.json", "set": {"version": 3}}]},
     "verification_invalid"),
    ({"before_commit": [{"op": "delete", "path": ".fieldglass/verification-summary.json"}]}, "verification_missing"),
    ({"before_commit": [{"op": "patch", "path": ".fieldglass/baseline-acceptance.json", "set": {"sourceHead": "f" * 40}}]},
     "acceptance_not_established"),
    ({"before_commit": [{"op": "patch", "path": ".fieldglass/baseline-acceptance.json", "set": {"policyVersion": 2}}]},
     "acceptance_not_established"),
    ({"before_commit": [{"op": "patch", "path": ".fieldglass/.state.json", "set": {"headRef": "e" * 40}}]},
     "checkpoint_not_established"),
    ({"after": [{"op": "state_baseline_acceptance_mismatch"}]}, "native_state_invalid"),
    ({"before_commit": [{"op": "patch", "path": ".fieldglass/primary-review-packets.json", "set": {"findingCount": 9}}]},
     "review_packets_not_established"),
    ({"before_commit": [{"op": "patch", "path": ".fieldglass/sortie-state.json", "set": {"dismissedFindingIds": []}}]},
     "verification_invalid"),
    ({"after": [{"op": "write", "path": ".fieldglass/scan-log.md", "text": "rewritten after the commit\n"}]},
     "evidence_commit_unmatched"),
])
def test_receipts_that_contradict_the_native_outcome_are_partial(runtime, hook, code):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS},
                                       "primary": {"dispositions": {"FG-SQLI-0002": "dismissed"}}, "hooks": hook})
    receipt = _reconciliation(bundle)
    assert receipt["native"]["outcome"] == "committed", "the native wrapper believed the run complete"
    acceptable = {code, "native_state_invalid"} if code == "acceptance_not_established" else {code}
    assert result["status"] in ("partial", "error") and acceptable & set(receipt["verdict"]["unmet"]), receipt["verdict"]
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert result["bundles_resolved"] is False


@pytest.mark.parametrize("operation", [
    {"op": "json_set", "path": ".fieldglass/target-security-policy.json",
     "keys": ["evidenceHash"], "value": "0" * 64},
    {"op": "json_set", "path": ".fieldglass/primary-review-packets.json",
     "keys": ["packets", 0, "members", 0, "evidenceHash"], "value": "0" * 64},
    {"op": "json_set", "path": ".fieldglass/primary-review-packets.json",
     "keys": ["packets", 0, "packetEvidenceHash"], "value": "0" * 64},
    {"op": "json_set", "path": ".fieldglass/verification-summary.json",
     "keys": ["groups", 0, "primarySecurityArgument", "attackerCapability", "evidence", 0, "startLine"],
     "value": 999999},
    {"op": "json_set", "path": ".fieldglass/verification-summary.json",
     "keys": ["groups", 0, "primarySecurityArgument", "attackerCapability", "evidence", 0, "contentHash"],
     "value": "0" * 64},
    {"op": "json_set", "path": ".fieldglass/verification-summary.json",
     "keys": ["groups", 0, "primarySecurityArgument", "argumentHash"], "value": "0" * 64},
    {"op": "json_set", "path": ".fieldglass/verification-summary.json",
     "keys": ["groups", 0, "primarySecurityArgument", "packetId"], "value": "RCP-" + "0" * 24},
    {"op": "json_set", "path": ".fieldglass/verification-summary.json",
     "keys": ["groups", 0, "challengerSecurityArgument", "argumentHash"], "value": "0" * 64},
    {"op": "json_set", "path": ".fieldglass/verification-summary.json",
     "keys": ["groups", 0, "challengerSecurityArgument", "packetEvidenceHash"], "value": "0" * 64},
    {"op": "json_set", "path": ".fieldglass/verification-summary.json",
     "keys": ["groups", 0, "challengerPacketBytes"], "value": 1},
    {"op": "tamper_security_argument_consistently", "sourceRevision": "f" * 40},
    {"op": "json_set", "path": ".fieldglass/verification-summary.json",
     "keys": ["groups", 0, "explanation"], "value": ""},
    {"op": "json_delete", "path": ".fieldglass/verification-summary.json",
     "keys": ["primaryReview", "journalSuccessfulAttempts"]},
    {"op": "json_set", "path": ".fieldglass/verification-summary.json",
     "keys": ["challenger", "attemptedCalls"], "value": 99},
])
def test_native_policy_packet_argument_and_accounting_tampering_is_never_accepted(runtime, operation):
    result, _, bundle = _run(runtime, {
        "engine": {"findings": FINDINGS},
        "primary": {"dispositions": {"FG-SQLI-0002": "dismissed"}},
        "hooks": {"before_commit": [operation]},
    })
    receipt = _reconciliation(bundle)
    assert result["status"] != "success", receipt
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"], \
        "a tampered native dismissal must never hide its engine finding"
    assert result["bundles_resolved"] is False
    assert receipt["readings"]["target_security_policy"]["state"] != "valid" \
        or receipt["readings"]["packets"]["state"] != "valid" \
        or receipt["readings"]["verification"]["state"] != "complete"


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_native_json_readers_reject_nonfinite_constants(constant):
    assert ev.read_checkpoint(f'{{"lastBatchHead":{constant}}}'.encode(), "a" * 40).state == "invalid"
    assert ev.read_policy(f'{{"evidenceHash":{constant}}}'.encode(), repository_proposals={}).state == "invalid"


def test_native_finding_and_review_manifest_byte_ceilings_are_exact():
    prefix = ("---\nid: FG-BOUND-0001\nseverity: high\nfile_path: src/app.py\n---\n").encode()
    at_limit = prefix + b"x" * (ev.MAX_NATIVE_FINDING_BYTES - len(prefix))
    accepted = ev.capture_finding(at_limit, record="bound.md", artifact_id="bound",
                                  evidence_path=".fieldglass/findings/bound.md")
    rejected = ev.capture_finding(at_limit + b"x", record="over.md", artifact_id="over",
                                  evidence_path=".fieldglass/findings/over.md")
    assert accepted.native is not None and accepted.finding_id == "FG-BOUND-0001"
    assert rejected.native is None

    policy = ev.expected_absent_policy({})
    over_plan = ev.read_packets(b" " * (ev.MAX_NATIVE_REVIEW_BYTES + 1),
                                policy=ev.Policy("valid", policy, ()), records=[], minimum_severity="high")
    assert over_plan.state == "invalid"
    assert "exceeds the native" in over_plan.issues[0]


def test_absent_policy_uses_native_localecompare_order_for_fixed_proposal_paths():
    proposals = {path: hashlib.sha256(path.encode()).hexdigest() for path in ev.POLICY_SOURCE_CANDIDATES}
    policy = ev.expected_absent_policy(proposals)
    assert [entry["path"] for entry in policy["repositoryProposals"]] == list(ev.POLICY_SOURCE_CANONICAL_ORDER)
    canonical = {key: value for key, value in policy.items() if key != "evidenceHash"}
    assert policy["evidenceHash"] == hashlib.sha256(json.dumps(
        canonical, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


@pytest.mark.parametrize("verification_op", [
    {"op": "write", "path": ".fieldglass/verification-summary.json", "text": "{"},
    {"op": "delete", "path": ".fieldglass/verification-summary.json"},
])
def test_missing_finding_plus_broken_verification_still_records_import_loss(runtime, verification_op):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS}, "hooks": {"before_commit": [
        {"op": "delete", "path": ".fieldglass/findings/fg-sqli-0002-finding.md"}, verification_op]}})
    receipt = _reconciliation(bundle)
    assert result["status"] != "success" and result["bundles_resolved"] is False
    assert any("no finding record of it was imported" in note for note in receipt["import_loss"]), receipt


def test_reconciliation_preservation_failure_after_claim_import_is_non_success(runtime, monkeypatch):
    real_write = rs.write_new

    def fail_reconciliation(path, data, staging, deadline=None):
        if Path(path).name == "runsortie-reconciliation.json":
            return "forced create-only staging failure"
        return real_write(path, data, staging, deadline)

    monkeypatch.setattr(rs, "write_new", fail_reconciliation)
    result, _, _bundle = _run(runtime, {"engine": {"findings": FINDINGS},
                                        "primary": {"dispositions": {"FG-SQLI-0002": "dismissed"}}})
    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert result["error"]["code"] == "evidence_preservation_failed"


def test_unmatched_commit_never_honors_a_native_dismissal(runtime):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS},
        "primary": {"dispositions": {"FG-SQLI-0002": "dismissed"}},
        "hooks": {"after": [{"op": "write", "path": ".fieldglass/scan-log.md", "text": "uncommitted\n"}]}})
    assert "evidence_commit_unmatched" in _reconciliation(bundle)["verdict"]["unmet"]
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert result["bundles_resolved"] is False


@pytest.mark.parametrize("hook,code", [
    ({"after": [{"op": "state", "set": {"repositoryHead": "d" * 40}}]}, "head_mismatch"),
    ({"after": [{"op": "state", "set": {"evidenceHead": "d" * 40}}]}, "evidence_head_mismatch"),
    ({"after": [{"op": "state", "set": {"outcome": "no-changes"}}]}, "evidence_commit_contradiction"),
    ({"after": [{"op": "state", "set": {}, "extra_targets": {"stale": {"target": "stale", "outcome": "failed",
                                                                     "lastAttemptAt": "x"}}}]}, "native_state_invalid"),
    ({"after": [{"op": "write", "path": "src/new.py", "text": "x\n"}]}, "product_mutation"),
    ({"after": [{"op": "write", "path": "notes.txt", "text": "x\n"}, {"op": "commit", "paths": ["notes.txt"]}]},
     "evidence_commit_invalid"),
    ({"after": [{"op": "write", "path": "src/app.py", "text": "changed\n"},
                {"op": "commit", "paths": ["src/app.py"], "amend": True},
                {"op": "write", "path": "src/app.py", "text": "import os\n\ndef run(cmd):\n    os.system(cmd)\n"}]},
     "product_mutation_committed"),
])
def test_identity_head_commit_and_product_contradictions_are_errors(runtime, hook, code):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS},
                                       "primary": {"dispositions": {"FG-SQLI-0002": "dismissed"}}, "hooks": hook})
    assert result["status"] == "error", result
    assert code in _reconciliation(bundle)["verdict"]["unmet"], _reconciliation(bundle)["verdict"]
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"], \
        "an error keeps every claim, and a native dismissal is not honored on a run that is not identified"
    assert result["bundles_resolved"] is False


@pytest.mark.parametrize("scenario,needle", [
    ({"hooks": {"before_commit": [{"op": "write", "path": ".fieldglass/findings/extra.md",
                                   "text": "---\nid: FG-EXTRA-0009\nseverity: high\nfile_path: src/app.py\n---\n# x\n"}]}},
     "absent from the native review population"),
    ({"hooks": {"before_commit": [{"op": "delete", "path": ".fieldglass/findings/fg-sqli-0002-finding.md"}]}},
     "no finding record of it was imported"),
    ({"engine": {"findings": FINDINGS + [{"id": "FG-CMDI-0001", "severity": "critical", "record": "zz-copy.md"}]}},
     "a second finding record carries this id"),
    ({"hooks": {"before_commit": [{"op": "write", "path": ".fieldglass/findings/bad.md", "text": "---\nseverity: high\n---\n"}]}},
     "no id in frontmatter"),
    ({"engine": {"findings": FINDINGS + [{"id": "FG-TRAV-0004", "severity": "high", "file": "../outside.py"}]}},
     "unusable file_path"),
    ({"engine": {"findings": FINDINGS + [{"id": "FG-DRIVE-0005", "severity": "high", "file": "C:\\outside.py"}]}},
     "unusable file_path"),
    ({"engine": {"findings": FINDINGS + [{"id": "FG-NUL-0006", "severity": "high", "file": "bad\0path.py"}]}},
     "unusable file_path"),
    ({"engine": {"findings": FINDINGS + [{"id": "FG-SEVERITY-0007", "severity": "unknown"}]}},
     "exact native parse with a known severity"),
])
def test_population_disagreements_are_visible_import_loss(runtime, scenario, needle):
    scenario = {"engine": {"findings": FINDINGS}, **scenario}
    result, execution, bundle = _run(runtime, scenario)
    assert result["status"] in ("partial", "error") and result["bundles_resolved"] is False
    expected_preserved = {"FG-CMDI-0001", "FG-LOG-0003"}
    if needle != "no finding record of it was imported":
        expected_preserved.add("FG-SQLI-0002")
    assert expected_preserved <= set(_claim_ids(result))
    receipt = _reconciliation(bundle)
    if result["status"] == "partial":
        assert "import_loss" in receipt["verdict"]["unmet"]
    assert receipt["import_loss"]
    assert any(needle in loss for loss in receipt["import_loss"]), receipt["import_loss"]
    assert any("Import loss" in note for note in execution["notes"])


def test_a_reader_defect_after_import_keeps_every_claim(runtime, monkeypatch):
    def broken(*args, **kwargs):
        raise RecursionError("reader defect")

    monkeypatch.setattr(ev, "read_verification", broken)
    result, execution, _ = _run(runtime, {"engine": {"findings": FINDINGS},
                                          "primary": {"dispositions": {"FG-SQLI-0002": "dismissed"}}})
    assert result["status"] == "error" and result["error"]["code"] == "evidence_unjudged"
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert result["bundles_resolved"] is False
    assert all(claim["raw_artifact_id"] in _artifacts(execution) for claim in result["claims"])


# --- isolation and filesystem safety ---------------------------------------------------------

def test_adapter_owned_engine_policy_mutation_prevents_success_but_keeps_claims(runtime):
    operation = {"op": "private_file_write", "env": "PI_CODING_AGENT_DIR", "path": "auth.json",
                 "text": '{"attacker":"secret"}\n'}
    result, execution, _bundle = _run(runtime, {
        "engine": {"findings": FINDINGS}, "hooks": {"after": [operation]}})
    assert result["status"] != "success" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert any("invocation-owned" in note and "changed" in note for note in execution["notes"])


def test_dynamic_private_agent_state_is_not_mistaken_for_operator_configuration(runtime):
    result, _execution, _bundle = _run(runtime, {
        "engine": {"findings": FINDINGS}, "hooks": {"after": [{
            "op": "private_file_write", "env": "PI_CODING_AGENT_DIR", "path": "sessions/runtime-state.json",
            "text": '{"generated":true}\n'}]}})
    assert result["status"] == "success", result.get("error")

def test_operator_state_is_never_read_and_stays_untouched(runtime, monkeypatch):
    stale = runtime.tmp / "operator-state"
    stale_state = {"version": 1, "targets": {"scaneval": {"target": "scaneval", "outcome": "committed",
                                                          "productHead": "c" * 40, "lastAttemptAt": "x",
                                                          "baseline": {"version": 1, "status": "ready"}}}}
    _write(stale / "state.json", json.dumps(stale_state))
    monkeypatch.setenv("RUNSORTIE_STATE_DIR", str(stale))
    monkeypatch.setenv("XDG_STATE_HOME", str(stale))
    monkeypatch.setenv("RUNSORTIE_CACHE_DIR", str(stale / "cache"))
    result, _, _ = _run(runtime, {"engine": {"findings": FINDINGS},
                                  "log_env": ["RUNSORTIE_STATE_DIR", "XDG_STATE_HOME", "RUNSORTIE_CACHE_DIR"]})
    assert result["status"] == "success", result.get("error")
    env = runtime.invocations()[0]["env"]
    assert env["RUNSORTIE_STATE_DIR"] != str(stale) and env["XDG_STATE_HOME"] != str(stale)
    assert not env["RUNSORTIE_CACHE_DIR"].startswith(str(stale))
    assert json.loads((stale / "state.json").read_text(encoding="utf-8")) == stale_state
    assert not (stale / "cache").exists()


def test_scanner_planted_links_are_not_followed(runtime):
    host = runtime.tmp / "host"
    _write(host / "secret.json", '{"policyVersion": 1, "marker": "HOST-SECRET-MARKER"}')
    _write(host / "findings" / "planted.md",
           "---\nid: FG-HOST-0001\nseverity: high\nfile_path: src/app.py\n---\nHOST-SECRET-MARKER\n")
    result, execution, bundle = _run(runtime, {"engine": {"findings": FINDINGS}, "hooks": {"after": [
        {"op": "symlink", "path": ".fieldglass/baseline-acceptance.json", "target": str(host / "secret.json")},
        {"op": "symlink", "path": ".fieldglass/findings", "target": str(host / "findings")}]}})
    assert result["status"] in ("partial", "error") and result["bundles_resolved"] is False
    assert "FG-HOST-0001" not in _claim_ids(result)
    assert any(".fieldglass/baseline-acceptance.json: not read" in note for note in execution["notes"])
    assert "runsortie-receipts/baseline-acceptance.json" not in _artifacts(execution)
    for path in bundle.rglob("*"):
        if path.is_file() and not path.is_symlink():
            assert b"HOST-SECRET-MARKER" not in path.read_bytes(), path


def test_relocated_git_object_store_is_rejected_before_post_run_plumbing(runtime):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS}, "hooks": {"before_commit": [
        {"op": "git_objects_relocate"},
    ]}})
    assert result["status"] == "error" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    receipt = _reconciliation(bundle)
    assert receipt["readings"]["git"]["state"] == "invalid"
    assert any(".git/objects" in issue for issue in receipt["readings"]["git"]["issues"])


def test_loose_blob_overlay_under_an_existing_oid_is_rehashed_and_rejected(runtime):
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS}, "hooks": {"after": [
        {"op": "git_loose_blob_replace", "path": "src/app.py", "text": "forged source bytes\n"},
    ]}})
    receipt = _reconciliation(bundle)
    assert result["status"] == "error" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert receipt["readings"]["git"]["state"] == "invalid"
    assert any("loose Git blob" in issue for issue in receipt["readings"]["git"]["issues"])


@pytest.mark.parametrize("operation", [
    {"op": "symlink", "path": "ignored-special", "target": "missing-target"},
    {"op": "fifo", "path": "ignored-special"},
    {"op": "socket", "path": "ignored-special"},
])
def test_product_symlink_fifo_and_socket_are_detected_without_blocking(runtime, operation):
    result, _, bundle = _call_with_deadline(lambda: _run(runtime, {
        "engine": {"findings": FINDINGS}, "hooks": {"after": [operation]}}), 20)
    receipt = _reconciliation(bundle)
    assert result["status"] == "error"
    if operation["op"] == "socket" and receipt["native"]["message"] == "[Errno 1] Operation not permitted":
        assert "runsortie_runtime" in receipt["verdict"]["unmet"], \
            "this sandbox refused creation of the test socket; the run still failed closed"
    else:
        assert "product_mutation" in receipt["verdict"]["unmet"]
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert result["bundles_resolved"] is False


@pytest.mark.parametrize("operation", [
    {"op": "state_fifo", "path": "untrusted.fifo"},
    {"op": "state_symlink", "path": "untrusted-link", "target": "/nonexistent"},
    {"op": "state_root_replace"},
    {"op": "cache_root_replace"},
])
def test_private_state_specials_and_replaced_roots_prevent_success_but_keep_claims(runtime, operation):
    result, _, _bundle = _call_with_deadline(lambda: _run(runtime, {
        "engine": {"findings": FINDINGS}, "hooks": {"after": [operation]}}), 20)
    assert result["status"] != "success" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]


def test_a_named_pipe_receipt_does_not_block_the_invocation(runtime, tmp_path):
    """The adapter refuses a pipe at once and keeps findings staged before the malformed receipt."""
    from scaneval.adapters.runsortie import read_bounded

    pipe = tmp_path / "pipe.json"
    os.mkfifo(pipe)
    read = _call_with_deadline(lambda: read_bounded(pipe, pipe, 1024), seconds=10)
    assert read.data is None and read.failure == "it is not a regular file"
    result, execution, bundle = _call_with_deadline(lambda: _run(runtime, {"engine": {"findings": FINDINGS}, "hooks": {
        "after": [{"op": "fifo", "path": ".fieldglass/verification-summary.json"}]}}))
    assert result["status"] != "success" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert "verification_invalid" in _reconciliation(bundle)["verdict"]["unmet"]
    assert execution["provenance"]["captured_state_dirs"] == []


@NEEDS_WAITID
def test_an_initial_tree_with_fieldglass_is_refused(runtime, tmp_path):
    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-fake", "runsortie", runtime.config())
    preparation = adapter.prepare(spec, tmp_path)
    source = tmp_path / "src-with-state"
    _write(source / ".fieldglass" / ".state.json", "{}")
    with pytest.raises(AdapterError, match="already holds .fieldglass"):
        adapter.scan(request={"input": {"mode": "full"}}, source_dir=source, raw_dir=tmp_path / "raw", spec=spec,
                     preparation=preparation, timeout_seconds=5, trace_mode="off", trace_dir=None)
    assert runtime.invocations() == []


# --- readers and the completion rule ---------------------------------------------------------

HEAD = "a" * 40


def test_source_path_uses_exact_js_trim_and_node_posix_normalization():
    assert ev._source_path("src/app.py/") == "src/app.py/", "Node preserves a trailing separator"
    assert ev._source_path("\ufeff./src/app.py\ufeff") == "src/app.py", "JavaScript trim removes BOM"
    assert ev._source_path("\u0085src/app.py\u0085") == "\u0085src/app.py\u0085", \
        "JavaScript trim does not remove U+0085"
    assert ev._source_path(".//src/app.py") is None, "one native ./ removal leaves an absolute path"

    def argument(path):
        value = {"version": 1, "sourceRevision": HEAD, "packetId": "RCP-" + "1" * 24,
                 "packetEvidenceHash": "2" * 64}
        for claim in ev.CLAIM_NAMES:
            value[claim] = {"status": "established", "summary": "bound",
                            "evidence": [{"path": path, "startLine": 1, "endLine": 1}]}
        return value

    reader = lambda path: b"source line\n" if path == "src/app.py" else None
    assert ev._validate_argument(argument("src/app.py/"), source_revision=HEAD,
                                 packet_id="RCP-" + "1" * 24, packet_hash="2" * 64,
                                 source_reader=reader, validated=False) is None
    checked = ev._validate_argument(argument("\ufeffsrc/app.py\ufeff"), source_revision=HEAD,
                                    packet_id="RCP-" + "1" * 24, packet_hash="2" * 64,
                                    source_reader=reader, validated=False)
    assert checked[ev.CLAIM_NAMES[0]]["evidence"][0]["path"] == "src/app.py"


def test_source_reader_never_accepts_an_ignored_untracked_file(tmp_path):
    source, raw = tmp_path / "source", tmp_path / "raw"
    _write(source / "tracked.py", "tracked\n")
    _write(source / "ignored.py", "ignored\n")
    raw.mkdir()
    product = rs.product_tree(source, rs.Deadline(5))
    assert product is not None
    tracked_oid = product["tracked.py"][4]
    verified = rs.VerifiedGitTree("1" * 40, (), {b"tracked.py": ("100644", tracked_oid)})
    reader = rs.source_reader(source, product, verified, rs.Enclosure.capture(source, raw), rs.Deadline(5))
    assert reader("tracked.py") == b"tracked\n"
    assert reader("ignored.py") is None


def test_target_state_reader_refuses_foreign_or_internally_inconsistent_records():
    recovery = {"status": "complete", "planHash": "c" * 64, "reasons": [],
                "hypotheses": {"planned": 1, "scheduled": 1, "succeeded": 1, "failed": 0,
                               "exhausted": 0, "stillUnevaluated": 0},
                "workItems": {"scheduled": 1, "succeeded": 1, "retryable": 0, "exhausted": 0,
                              "terminal": 0, "capacityExhausted": False},
                "limits": {"maxWorkItems": 1, "maxAttemptsPerItem": 1}}
    good = {"target": "scaneval", "outcome": "committed", "repositoryHead": HEAD, "productHead": HEAD,
            "evidenceHead": "b" * 40, "checkpoint": HEAD, "lastAttemptAt": "2026-11-03T00:00:00.000Z",
            "lastSuccessAt": "2026-11-03T00:00:01.000Z",
            "baseline": {"version": 1, "status": "ready", "reason": "complete", "attemptedHead": HEAD,
                         "checkpoint": HEAD, "acceptancePolicyVersion": 1, "acceptanceReasons": [],
                         "recovery": recovery}}

    def read(record, **extra):
        return ev.read_target_state(json.dumps({"version": 1, "targets": {"scaneval": record, **extra}}).encode(), "scaneval")

    assert read(good).state == "valid"
    assert read({**good, "baseline": {key: value for key, value in good["baseline"].items()
                                      if key != "recovery"}}).state == "valid"
    assert read({**good, "baseline": {**good["baseline"], "recovery": None}}).state == "invalid"
    assert read(good, other=good).state == "invalid"
    assert read({**good, "baseline": {**good["baseline"], "status": "retry-required"}}).state == "invalid"
    assert read({**good, "baseline": {**good["baseline"], "approvals": [{"x": 1}]}}).state == "invalid"
    assert read({**good, "checkpoint": "c" * 40}).state == "invalid"
    assert read({**good, "unknownField": 1}).state == "invalid"
    assert ev.read_target_state(None, "scaneval").state == "absent"
    assert ev.read_target_state(b"{", "scaneval").state == "invalid"


def test_acceptance_reader_reimplements_policy_one_and_recovery():
    complete = {"status": "complete", "planHash": "c" * 64, "reasons": [],
                "hypotheses": {"planned": 1, "scheduled": 1, "succeeded": 1, "failed": 0, "exhausted": 0, "stillUnevaluated": 0},
                "workItems": {"scheduled": 1, "succeeded": 1, "retryable": 0, "exhausted": 0, "terminal": 0,
                              "capacityExhausted": False},
                "limits": {"maxWorkItems": 1, "maxAttemptsPerItem": 1}}

    def read(**record):
        base = {"policyVersion": 1, "status": "accepted", "checkpointEligible": True, "reasons": [],
                "sourceHead": HEAD, "recovery": complete}
        return ev.read_acceptance(json.dumps({**base, **record}).encode(), HEAD).state

    assert read() == "accepted"
    assert read(status="inconclusive", checkpointEligible=False, reasons=["x"]) == "inconclusive"
    assert read(status="accepted", checkpointEligible=False) == "invalid"
    assert read(status="inconclusive", checkpointEligible=False, reasons=[]) == "invalid"
    assert read(reasons=["x"]) == "invalid"
    assert read(sourceHead="b" * 40) == "mismatch"
    assert read(extra=True) == "invalid"
    assert read(recovery=complete) == "accepted"
    assert ev.read_acceptance(json.dumps({
        "policyVersion": 1, "status": "accepted", "checkpointEligible": True,
        "reasons": [], "sourceHead": HEAD,
    }).encode(), HEAD).state == "accepted"
    assert read(recovery=None) == "invalid"
    assert read(recovery={**complete, "hypotheses": {**complete["hypotheses"], "succeeded": 0}}) == "invalid"
    assert read(recovery={**complete, "status": "retryable", "reasons": ["r"],
                          "workItems": {**complete["workItems"], "succeeded": 0, "retryable": 1}}) == "invalid"


def test_checkpoint_reader_accepts_only_the_bootstrap_record():
    assert ev.read_checkpoint(json.dumps({"lastBatchHead": HEAD}).encode(), HEAD).state == "bound"
    assert ev.read_checkpoint(json.dumps({"lastBatchHead": "b" * 40}).encode(), HEAD).state == "mismatch"
    assert ev.read_checkpoint(json.dumps({"lastBatchHead": HEAD, "headRef": HEAD}).encode(), HEAD).state == "invalid"
    assert ev.read_checkpoint(None, HEAD).state == "absent"


def test_packet_plan_port_groups_exact_review_equivalent_and_explicit_members():
    def finding(identifier, root_key, *, root_fingerprint=None, root_hash=None, relationships=(),
                review_evidence=None):
        native = {
            "id": identifier, "severity": "high", "vulnerabilityClass": "command_injection",
            "component": "api", "filePath": "src/app.py",
            "evidencePath": f".fieldglass/findings/{identifier.lower()}.md",
            "scannerSources": ["llm-bootstrap@1"], "identityRelationships": list(relationships),
            "rootCauseFingerprintVersion": 2,
            "rootCauseFingerprint": root_fingerprint or hashlib.sha256(identifier.encode()).hexdigest()[:24],
            "rootCauseEvidenceHash": root_hash or hashlib.sha256((identifier + "-root").encode()).hexdigest(),
            "rootCauseIdentityStatus": "exact", "rootCauseEvidence": ["flow=user-to-shell"],
            "evidenceHash": hashlib.sha256((identifier + "-evidence").encode()).hexdigest(),
            "evidence": f"finding {identifier}\n", "rootCauseKey": root_key,
            "sourceSymbol": "request.cmd", "sinkSymbol": "exec", "patternSignature": "shell-exec",
        }
        if review_evidence is not None:
            review_hash = hashlib.sha256("\n".join(sorted(review_evidence)).encode()).hexdigest()
            native.update({"reviewEquivalenceVersion": 1, "reviewEquivalenceFingerprint": review_hash[:24],
                           "reviewEquivalenceEvidenceHash": review_hash,
                           "reviewEquivalenceEvidence": sorted(review_evidence)})
        return native

    exact_key = hashlib.sha256(b"exact-root").hexdigest()
    exact_fingerprint = hashlib.sha256(b"exact-fingerprint").hexdigest()[:24]
    exact_hash = hashlib.sha256(b"exact-evidence").hexdigest()
    findings = [
        finding("FG-EXACT-1", exact_key, root_fingerprint=exact_fingerprint, root_hash=exact_hash),
        finding("FG-EXACT-2", exact_key, root_fingerprint=exact_fingerprint, root_hash=exact_hash),
        finding("FG-REVIEW-1", hashlib.sha256(b"review-root-1").hexdigest(), review_evidence=["flow=shared"]),
        finding("FG-REVIEW-2", hashlib.sha256(b"review-root-2").hexdigest(), review_evidence=["flow=shared"]),
        finding("FG-REL-1", hashlib.sha256(b"relationship-root-1").hexdigest()),
        finding("FG-REL-2", hashlib.sha256(b"relationship-root-2").hexdigest(),
                relationships=["possible-duplicate | FG-REL-1"]),
    ]
    policy = ev.expected_absent_policy({})
    plan = ev._build_primary_review_plan(findings, policy)
    by_grouping = {packet["grouping"]: packet for packet in plan["packets"]}
    assert set(by_grouping) == {"exact-root-cause", "review-equivalence", "explicit-structural-relationship"}
    assert by_grouping["exact-root-cause"]["memberFindingIds"] == ["FG-EXACT-1", "FG-EXACT-2"]
    assert by_grouping["review-equivalence"]["memberFindingIds"] == ["FG-REVIEW-1", "FG-REVIEW-2"]
    assert by_grouping["explicit-structural-relationship"]["memberFindingIds"] == ["FG-REL-1", "FG-REL-2"]
    assert by_grouping["explicit-structural-relationship"]["canonicalFindingId"] == "FG-REL-1"
    assert plan["rejectedRelationships"] == []

    records = [ev.FindingMeta(item["id"], f"{item['id']}.md", f"artifact-{item['id']}",
                              item["severity"], "open", item) for item in findings]
    encoded = (json.dumps(plan, ensure_ascii=False, indent=2) + "\n").encode()
    reading = ev.read_packets(encoded, policy=ev.Policy("valid", policy, ()), records=records,
                              minimum_severity="high")
    assert reading.state == "valid" and {packet.members for packet in reading.packets} == {
        ("FG-EXACT-1", "FG-EXACT-2"), ("FG-REVIEW-1", "FG-REVIEW-2"), ("FG-REL-1", "FG-REL-2")}


def test_commit_classification():
    def classify(**kw):
        base = dict(evaluated=HEAD, head="b" * 40, parents=(HEAD,), changed=(".fieldglass/a.json",), worktree_matches=True)
        return ev.classify_commit(**{**base, **kw}).state

    assert classify() == "evidence-commit"
    assert classify(head=HEAD) == "unchanged"
    assert classify(parents=("c" * 40,)) == "invalid"
    assert classify(parents=(HEAD, "c" * 40)) == "invalid"
    assert classify(changed=(".fieldglass/a.json", "src/app.py")) == "product-modified"
    assert classify(changed=(".fieldglassx/a",)) == "product-modified"
    assert classify(changed=()) == "invalid"
    assert classify(worktree_matches=False) == "evidence-commit-unmatched"
    assert classify(head=None) == "invalid"


# Bounded enumeration of the completion rule against an independently written oracle. This is not a
# proof: it covers every combination of a few representative values per fact (listed below), and a
# disagreement is reported with the concrete fact tuples that produced it.
DOMAINS = {
    "timed_out": (False, True),
    "exit_code": (0, 98, None),
    "runtime_unchanged": (True, False),
    "product_tree_unchanged": (True, False),
    "target_state": ("valid", "invalid"),
    "heads_bound": (True, False),
    "git": ("evidence-commit", "unchanged", "evidence-commit-unmatched", "product-modified"),
    "evidence_head_matches": (True, False),
    "outcome": ("committed", "committed-incomplete", "no-changes", "failed"),
    "baseline": ("ready", "review-required"),
    "checkpoint": ("bound", "absent"),
    "acceptance": ("accepted", "invalid"),
    "policy": ("valid", "invalid"),
    "packets": ("valid", "absent"),
    "verification": ("complete", "unresolved", "absent"),
    "work_budget": ("unconfigured", "complete", "exhausted"),
    "import_lost": (0, 1),
    "evidence_preserved": (True, False),
}


def _oracle(f: dict) -> str:
    if f["timed_out"]:
        return "timeout"
    identity_ok = (f["exit_code"] == 0 and f["runtime_unchanged"] and f["product_tree_unchanged"]
                   and f["target_state"] == "valid" and f["heads_bound"] and f["evidence_head_matches"]
                   and f["git"] not in ("product-modified", "invalid") and f["outcome"] != "failed")
    committed_shape = f["git"] in ("evidence-commit", "evidence-commit-unmatched")
    if not identity_ok or committed_shape != (f["outcome"] in ("committed", "committed-incomplete")):
        return "error"
    proven = (f["outcome"] == "committed" and f["git"] == "evidence-commit" and f["baseline"] == "ready"
              and f["checkpoint"] == "bound" and f["acceptance"] == "accepted" and f["packets"] == "valid"
              and f["policy"] == "valid" and f["evidence_preserved"]
              and f["verification"] == "complete" and f["work_budget"] in ("unconfigured", "complete")
              and f["import_lost"] == 0)
    return "success" if proven else "partial"


def test_completion_rule_matches_an_independent_oracle_over_a_bounded_domain():
    names = list(DOMAINS)
    mismatches, statuses = [], set()
    for values in itertools.product(*DOMAINS.values()):
        facts = dict(zip(names, values))
        actual = ev.evaluate(ev.Facts(**facts)).status
        statuses.add(actual)
        if actual != _oracle(facts):
            mismatches.append((facts, actual, _oracle(facts)))
    assert not mismatches, f"{len(mismatches)} disagreement(s); first: {mismatches[:3]}"
    assert statuses == {"timeout", "error", "partial", "success"}


def test_success_is_reachable_only_from_every_positive_obligation():
    positive = ev.Facts(timed_out=False, exit_code=0, runtime_unchanged=True, product_tree_unchanged=True,
                        target_state="valid", heads_bound=True, git="evidence-commit", evidence_head_matches=True,
                        outcome="committed", baseline="ready", checkpoint="bound", acceptance="accepted",
                        policy="valid", packets="valid", verification="complete", work_budget="unconfigured",
                        import_lost=0, evidence_preserved=True)
    assert ev.evaluate(positive) == ev.Verdict("success", None, ())
    for name, values in DOMAINS.items():
        for value in values:
            if value == getattr(positive, name) or (name == "work_budget" and value == "complete"):
                continue
            assert ev.evaluate(positive._replace(**{name: value})).status != "success", (name, value)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_staged_receipts_are_created_without_overwriting(tmp_path):
    from scaneval.adapters.runsortie import write_new
    from scaneval.materialize import Containment

    area = Containment.capture(tmp_path)
    assert write_new(tmp_path / "a" / "b.json", b"one", area) is None
    assert stat.S_IMODE((tmp_path / "a" / "b.json").stat().st_mode) == 0o600
    assert write_new(tmp_path / "a" / "b.json", b"two", area) is not None
    assert (tmp_path / "a" / "b.json").read_bytes() == b"one"
    (tmp_path / "link").symlink_to(tmp_path.parent)
    assert write_new(tmp_path / "link" / "escape.json", b"x", area) is not None
    assert not (tmp_path.parent / "escape.json").exists()


def test_private_cleanup_is_hard_bounded_and_never_follows_links(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("keep\n", encoding="utf-8")
    (private / "record.json").write_text("{}\n", encoding="utf-8")
    (private / "outside-link").symlink_to(outside)
    guard = rs._capture_root(private)

    failure = rs._cleanup_private(private, guard, rs.Deadline(5), maximum=1)
    assert failure is not None and "entry bound" in failure
    assert private.is_dir() and outside.read_text(encoding="utf-8") == "keep\n"

    assert rs._cleanup_private(private, guard, rs.Deadline(5), maximum=8) is None
    assert not private.exists() and outside.read_text(encoding="utf-8") == "keep\n"


def test_fd_tree_snapshot_rejects_root_rename_and_replacement(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "record").write_bytes(b"old-root\n")
    guard = rs._capture_root(root)
    moved = tmp_path / "moved-root"

    def replace_root(descriptor, status, relative):
        data = rs._read_fd_bytes(descriptor, status, 1024)
        root.rename(moved)
        root.mkdir()
        (root / "record").write_bytes(b"replacement\n")
        return data

    with pytest.raises(OSError, match="changed|replaced|match"):
        rs._fd_tree_snapshot(root, guard, rs.Deadline(5), maximum=8, max_depth=4,
                             regular_reader=replace_root)


def test_fd_tree_snapshot_never_follows_a_replaced_parent_to_external_bytes(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    (root / "child").mkdir(parents=True)
    outside.mkdir()
    (root / "child" / "record").write_bytes(b"captured\n")
    (outside / "record").write_bytes(b"EXTERNAL-SENTINEL\n")
    guard = rs._capture_root(root)
    observed = []

    def replace_parent(descriptor, status, relative):
        data = rs._read_fd_bytes(descriptor, status, 1024)
        observed.append(data)
        if relative == "child/record":
            (root / "child").rename(root / "captured-child")
            (root / "child").symlink_to(outside, target_is_directory=True)
        return data

    with pytest.raises(OSError, match="changed|replaced"):
        rs._fd_tree_snapshot(root, guard, rs.Deadline(5), maximum=16, max_depth=4,
                             regular_reader=replace_parent)
    assert observed == [b"captured\n"] and (outside / "record").read_bytes() == b"EXTERNAL-SENTINEL\n"


def test_fd_tree_snapshot_bounds_one_directory_before_sorting(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    for index in range(4):
        (root / f"entry-{index}").write_bytes(b"x")
    with pytest.raises(OSError, match="entry bound"):
        rs._fd_tree_snapshot(root, rs._capture_root(root), rs.Deadline(5), maximum=3, max_depth=2)


def test_fd_tree_snapshot_uses_canonical_guard_under_a_symlinked_trusted_prefix(tmp_path):
    actual = tmp_path / "actual"
    (actual / "root").mkdir(parents=True)
    (actual / "root" / "record").write_bytes(b"ok")
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    spelled = alias / "root"
    guard = rs._capture_root(spelled)
    snapshot = rs._fd_tree_snapshot(spelled, guard, rs.Deadline(5), maximum=4, max_depth=2)
    assert snapshot["record"].kind == "regular"


def test_linux_fd_tree_snapshot_fails_closed_without_mount_identity(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    guard = rs._capture_root(root)._replace(mount_id=None)
    monkeypatch.setattr(rs.sys, "platform", "linux")
    monkeypatch.setattr(rs, "_fd_mount_id", lambda _descriptor: None)
    with pytest.raises(OSError, match="mount identity is unavailable"):
        rs._fd_tree_snapshot(root, guard, rs.Deadline(5), maximum=4, max_depth=2)


def test_fd_tree_snapshot_refuses_a_nested_mount_id_change(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "child").mkdir(parents=True)
    guard = rs._capture_root(root)._replace(mount_id="root-mount")

    def mount_id(descriptor):
        return "root-mount" if os.fstat(descriptor).st_ino == guard.inode else "nested-mount"

    monkeypatch.setattr(rs, "_fd_mount_id", mount_id)
    with pytest.raises(OSError, match="mount boundary"):
        rs._fd_tree_snapshot(root, guard, rs.Deadline(5), maximum=4, max_depth=2)


def test_fd_relative_regular_refuses_a_leaf_mount_id_change(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    (root / "leaf").write_bytes(b"local")
    guard = rs._capture_root(root)._replace(mount_id="root-mount")
    calls = 0

    def mount_id(_descriptor):
        nonlocal calls
        calls += 1
        return "root-mount" if calls <= 2 else "leaf-mount"

    monkeypatch.setattr(rs, "_fd_mount_id", mount_id)
    with pytest.raises(OSError, match="mount boundary"):
        rs._read_relative_regular(root, guard, "leaf", 1024, rs.Deadline(5))


def test_cleanup_parent_replacement_never_deletes_external_tree(tmp_path, monkeypatch):
    root, outside = tmp_path / "private", tmp_path / "outside"
    (root / "child").mkdir(parents=True)
    (root / "child" / "secret").write_bytes(b"private")
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"external")
    guard = rs._capture_root(root)
    native = rs._open_snapshot_parent
    replaced = False

    def replace_before_open(root_fd, relative, snapshot):
        nonlocal replaced
        if not replaced and relative.startswith("child/"):
            replaced = True
            (root / "child").rename(root / "captured-child")
            (root / "child").symlink_to(outside, target_is_directory=True)
        return native(root_fd, relative, snapshot)

    monkeypatch.setattr(rs, "_open_snapshot_parent", replace_before_open)
    failure = rs._cleanup_private(root, guard, rs.Deadline(5))
    assert failure is not None and sentinel.read_bytes() == b"external"


def test_cleanup_missing_renamed_root_is_failure_and_leaves_captured_inode_observable(tmp_path):
    root = tmp_path / "private"
    root.mkdir()
    (root / "secret").write_bytes(b"credential")
    guard = rs._capture_root(root)
    moved = tmp_path / "renamed-private"
    root.rename(moved)
    failure = rs._cleanup_private(root, guard, rs.Deadline(5))
    assert failure is not None and "missing" in failure and (moved / "secret").read_bytes() == b"credential"


def test_emergency_cleanup_uses_a_fresh_budget_after_the_scan_deadline_expires(tmp_path):
    root = tmp_path / "private"
    (root / "home" / ".claude").mkdir(parents=True)
    (root / "home" / ".claude" / "runtime-state.json").write_bytes(b"private")
    guard = rs._capture_root(root)
    expired = rs.Deadline(0)
    with pytest.raises(rs.DeadlineExpired):
        expired.check()
    assert rs._cleanup_private(root, guard, rs.Deadline(rs.PRIVATE_CLEANUP_GRACE_SECONDS)) is None
    assert not root.exists()


def test_dependency_symlink_chain_above_the_explicit_hop_bound_is_refused(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "target").write_bytes(b"target")
    for index in reversed(range(rs.MAX_DEPENDENCY_SYMLINK_HOPS + 1)):
        target = "target" if index == rs.MAX_DEPENDENCY_SYMLINK_HOPS else f"link-{index + 1:03d}"
        (root / f"link-{index:03d}").symlink_to(target)
    with pytest.raises(AdapterError, match="leaves or dangles"):
        rs._installed_tree_identity(root, "fixture package", rs.Deadline(5))


def test_private_cleanup_deferral_is_observable_and_preserves_claims(runtime, monkeypatch):
    cleanup = rs._cleanup_private
    attempts = 0

    def fail_once(root, guard, deadline, **kwargs):
        nonlocal attempts
        if "-probe-" in Path(root).name:
            return cleanup(root, guard, deadline, **kwargs)
        attempts += 1
        if attempts == 1:
            return "fixture cleanup bound exceeded"
        return cleanup(root, guard, deadline, **kwargs)

    monkeypatch.setattr(rs, "_cleanup_private", fail_once)
    result, _, bundle = _run(runtime, {"engine": {"findings": FINDINGS}})
    receipt = _reconciliation(bundle)
    assert result["status"] == "partial" and result["bundles_resolved"] is False
    assert len(result["claims"]) == 3
    assert "evidence_preservation_failed" in receipt["verdict"]["unmet"]
    assert receipt["facts"]["evidence_preserved"] is False and attempts == 2


def test_process_group_cleanup_failure_prevents_success_without_losing_claims(runtime, monkeypatch):
    native = rs.run_command

    def report_cleanup_failure(*args, **kwargs):
        result = native(*args, **kwargs)
        argv = args[0] if args else kwargs.get("argv", [])
        if any(str(item).endswith("dist/cli.js") for item in argv):
            result.cleanup_succeeded = False
        return result

    monkeypatch.setattr(rs, "run_command", report_cleanup_failure)
    result, execution, bundle = _run(runtime, {"engine": {"findings": FINDINGS}})
    receipt = _reconciliation(bundle)
    assert result["status"] == "error" and result["bundles_resolved"] is False
    assert _claim_ids(result) == ["FG-CMDI-0001", "FG-LOG-0003", "FG-SQLI-0002"]
    assert "runtime_identity_changed" in receipt["verdict"]["unmet"]
    assert any("process group" in note for note in execution["notes"])


# --- optional conformance against a real pinned RunSortie -----------------------------------

CONFORMANCE_ROOT = os.environ.get("SCANEVAL_RUNSORTIE_CONFORMANCE_ROOT")
TOOLS = Path(__file__).parent / "fixtures" / "runsortie" / "fake_tools.py"


@pytest.mark.skipif(not CONFORMANCE_ROOT, reason="opt-in: set SCANEVAL_RUNSORTIE_CONFORMANCE_ROOT to a clean, "
                    "built RunSortie checkout to run the real CLI with fabricated engine and agents")
@pytest.mark.parametrize("challenger,budget,empty", [
    ("claude", None, False),
    ("claude-inconclusive", None, False),
    ("claude", {"version": 1, "modelCalls": {"primaryReview": 1, "challenger": 3}}, False),
    ("claude", None, True),
])
@NEEDS_WAITID
def test_real_runsortie_cli_with_fabricated_engine_and_agents(tmp_path, monkeypatch, challenger, budget, empty):
    """Deterministic conformance, not live readiness: the real RunSortie CLI, Node and Git run, and its
    Fieldglass engine and both agents are fabricated processes, so no model and no network is used.

    Fabricated tools take precedence in PATH; host agent-install directories are excluded, while
    ``/usr/bin`` and ``/bin`` remain for ordinary shell utilities. The checkout is only read.
    """
    monkeypatch.setattr(rs, "_direct_agent_capability", lambda settings: {
        "runnable": True, "status": "synthetic-test-only",
        "selected_agents": sorted({settings.primary.agent, settings.challenger.agent}),
        "required_boundary": "synthetic deterministic fake", "reasons": [],
    })
    monkeypatch.setattr(RunSortieAdapter, "env_passthrough", tuple(sorted(rs.CREDENTIAL_ENV_ALLOWLIST)))
    root = Path(CONFORMANCE_ROOT).resolve()
    real_node = shutil.which("node")
    if real_node is None:
        pytest.skip("node is not on PATH")
    argv, env = git_command(["--no-optional-locks", "rev-parse", "HEAD"])
    commit = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True, check=True).stdout.strip()
    version = json.loads((root / "package.json").read_text(encoding="utf-8"))["version"]
    if commit != SUPPORTED_RUNSORTIE_COMMIT or version != SUPPORTED_RUNSORTIE_VERSION:
        pytest.fail(f"conformance root must be exactly {SUPPORTED_RUNSORTIE_COMMIT} / {SUPPORTED_RUNSORTIE_VERSION}")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "node").symlink_to(real_node)
    (bin_dir / "git").symlink_to(shutil.which("git"))
    package_specs = {
        "npm": ("npm", "10.9.0", "bin/npm-cli.js", "npm-empty" if empty else "npm"),
        "pi": ("@earendil-works/pi-coding-agent", "1.4.0", "dist/bundle/cli.js", "pi"),
        "claude": ("@anthropic-ai/claude-code", "2.1.310", "bin/claude.js", challenger),
    }
    for tool, (package_name, package_version, relative, mode) in package_specs.items():
        package_root = tmp_path / "packages" / tool
        _write(package_root / "package.json", json.dumps({
            "name": package_name, "version": package_version, "bin": {tool: relative}}))
        launcher = package_root / relative
        _executable(launcher, f'#!/bin/sh\nexec "{sys.executable}" -I "{TOOLS}" {mode} "$@"\n')
        (bin_dir / tool).symlink_to(launcher)
    monkeypatch.setenv("PATH", os.pathsep.join((str(bin_dir), "/usr/bin", "/bin")))
    monkeypatch.setenv("OPENAI_API_KEY", "fabricated-engine-key")
    config = {"root": str(root), "expected_commit": commit, "expected_version": version,
              "expected_dist_tree_sha256": rs._dist_identity(root)["tree_sha256"],
              "engine_model": "fabricated/engine", "primary": {"agent": "claude", "model": "fabricated-primary"},
              "challenger": {"agent": "claude", "model": "fabricated-challenger"},
              "credential_env": {"engine": "OPENAI_API_KEY"}}
    if budget is not None:
        config["work_budget"] = budget
    adapter = get_adapter("runsortie")
    spec = SystemSpec("runsortie-conformance", "runsortie", config)
    preparation = adapter.prepare(spec, tmp_path)
    bundle = run_invocation(prepared=_prepared(tmp_path), adapter=adapter, spec=spec, preparation=preparation,
                            out_dir=tmp_path / "out", run_id="run-conformance", timeout_seconds=300,
                            trace_mode="off", network_policy="model_provider_only", clock=CLOCK)
    result = load_document(bundle / "result.json", "scan-result")
    execution = load_document(bundle / "execution.json", "execution-record")
    receipt = _reconciliation(bundle)
    assert _claim_ids(result) == ([] if empty else ["FG-API-CMDI-0001", "FG-API-INFO-0002"])
    assert receipt["runtime_unchanged"] is True and receipt["readings"]["git"]["state"] == "evidence-commit"
    if challenger == "claude-inconclusive":
        # The real wrapper withholds the checkpoint and still exits zero; the adapter reads that as partial.
        assert receipt["exit_code"] == 0 and receipt["native"]["outcome"] == "committed-incomplete"
        assert receipt["native"]["baseline"]["status"] == "review-required"
        assert result["status"] == "partial", receipt["verdict"]
        assert {"review_required", "verification_incomplete"} <= set(receipt["verdict"]["unmet"])
        return
    assert result["status"] == "success", (result.get("error"), receipt["readings"])
    assert receipt["native"]["outcome"] == "committed" and receipt["native"]["baseline"]["status"] == "ready"
    expected_findings = {} if empty else {
        "FG-API-CMDI-0001": "reported-confirmed", "FG-API-INFO-0002": "reported-outside-review"}
    assert {entry["finding_id"]: entry["reportability"] for entry in receipt["findings"]} == expected_findings
    assert receipt["native"]["observed_routes"] == ([] if empty else [
        "challenger=claude/fabricated-challenger", "primary=claude/fabricated-primary"])
    assert execution["tool_versions"]["runsortie"] == f"runsortie@{commit}"
    assert receipt["readings"]["work_budget"]["state"] == ("unconfigured" if budget is None else "complete")
    if empty:
        summary = json.loads((bundle / "raw" / "runsortie-receipts" / "verification-summary.json").read_text())
        assert summary["primaryReview"]["packetCount"] == 0
        assert {key: summary["primaryReview"][key] for key in ("agentCalls", "liveCalls", "attempts")} == {
            "agentCalls": 1, "liveCalls": 1, "attempts": 1,
        }
