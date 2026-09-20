"""Own-harness adapter for the securevibes-agent / Fieldglass engine family.

The harness runs unchanged through its own engine entry point inside its own ``tsx``.
SASTbench only injects the harness's default model runner wrapped by the observer SDK
and a progress reporter, then imports the finding records the engine wrote. Findings
are file-level; this importer keeps them file-level and never invents line ranges.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
from typing import Any

from ..kinds import kind_for_harness_class
from .base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command, tail_text


DRIVER = Path(__file__).with_name("llm_harness_driver.mts")
HARNESS_PRESETS: dict[str, dict[str, Any]] = {
    "securevibes-agent": {
        "state_dir": ".securevibes",
        "engine_entry": "src/runtime/engine.ts",
        "runner_entry": "src/runtime/pi-runner.ts",
        "mock_entry": "src/testing/mock-llm-runner.ts",
        "plan_file": "bootstrap-plan.md",
    },
    "fieldglass": {
        "state_dir": ".fieldglass",
        "engine_entry": "src/runtime/engine.ts",
        "runner_entry": "src/runtime/pi-runner.ts",
        "mock_entry": "src/testing/mock-llm-runner.ts",
        "plan_file": "bootstrap-plan.md",
    },
}
_ARRAY = re.compile(r"^\[(.*)\]$")


def parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Parse the harness's ``key: value`` frontmatter (arrays in brackets, JSON-quoted strings)."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    block = text[3:end].strip("\n")
    body = text[end + 4:].lstrip("\n")
    record: dict[str, Any] = {}
    for line in block.splitlines():
        if ":" not in line or line.startswith(" "):
            continue
        key, _, raw = line.partition(":")
        record[key.strip()] = _scalar(raw.strip())
    return record, body


def _scalar(raw: str) -> Any:
    if raw == "":
        return ""
    match = _ARRAY.match(raw)
    if match:
        inner = match.group(1).strip()
        return [] if not inner else [_scalar(item.strip()) for item in _split_items(inner)]
    if raw.startswith('"'):
        try:
            return json.loads(raw)
        except ValueError:
            return raw.strip('"')
    if raw in ("true", "false"):
        return raw == "true"
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return raw


def _split_items(inner: str) -> list[str]:
    items, current, quoted = [], [], False
    for char in inner:
        if char == '"':
            quoted = not quoted
        if char == "," and not quoted:
            items.append("".join(current))
            current = []
        else:
            current.append(char)
    items.append("".join(current))
    return [item for item in items if item.strip()]


def import_harness_findings(findings_dir: Path, *, harness: str, artifact_id: str) -> tuple[list[dict], list[str]]:
    """Translate ``findings/*.md`` into file-only claims with the full native allegation text."""
    claims: list[dict] = []
    notes: list[str] = []
    if not findings_dir.is_dir():
        return claims, ["no findings directory was written by the harness"]
    for path in sorted(findings_dir.glob("*.md")):
        record, body = parse_frontmatter(path.read_text(encoding="utf-8", errors="replace"))
        finding_id = str(record.get("id") or "")
        if not finding_id:
            notes.append(f"{path.name}: no id in frontmatter; skipped")
            continue
        file_path = str(record.get("file_path") or "").replace("\\", "/")
        if file_path.startswith("./"):
            file_path = file_path[2:]
        if not file_path or file_path.startswith("/") or ".." in file_path.split("/"):
            notes.append(f"{finding_id}: unusable file_path {file_path!r}; claim excluded, see raw finding record")
            continue
        vulnerability_class = str(record.get("vulnerability_class") or "")
        title = str(record.get("title") or path.stem)
        reasoning = body.split("## Reasoning", 1)[1].strip() if "## Reasoning" in body else body.strip()
        claim: dict[str, Any] = {
            "claim_id": finding_id,
            "allegation": title,
            "kind": kind_for_harness_class(vulnerability_class),
            "primary_location": {"path": file_path},
            "native_id": finding_id,
            "native_rule_id": f"{harness}:{vulnerability_class or 'unknown'}",
            "raw_artifact_id": artifact_id,
        }
        if reasoning and reasoning != "N/A":
            claim["evidence_text"] = reasoning
        severity = record.get("severity")
        if isinstance(severity, str) and severity:
            claim["native_severity"] = severity
        claims.append(claim)
    if any(True for _ in findings_dir.glob("*.md")) and not claims and not notes:
        notes.append("finding records were present but none could be imported")
    return claims, notes


class LlmHarnessAdapter(Adapter):
    name = "llm-harness"
    adapter_version = "2.0.0"
    requires_git = True
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})
    env_passthrough = ("NODE_OPTIONS", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "XDG_CONFIG_HOME")
    state_dirs = (".securevibes", ".fieldglass")

    def _preset(self, spec: SystemSpec) -> tuple[str, dict[str, Any], Path]:
        harness = str(spec.config.get("harness") or "")
        if harness not in HARNESS_PRESETS:
            raise AdapterError(f"config.harness must be one of {sorted(HARNESS_PRESETS)}")
        root = Path(str(spec.config.get("root") or "")).expanduser()
        if not root.is_dir():
            raise AdapterError(f"harness root does not exist: {root}")
        return harness, HARNESS_PRESETS[harness], root

    def prepare(self, spec: SystemSpec, cache_root: Path) -> dict[str, Any]:
        harness, preset, root = self._preset(spec)
        tsx = root / "node_modules" / ".bin" / "tsx"
        missing = [str(p) for p in (root / preset["engine_entry"], root / preset["runner_entry"], tsx) if not p.exists()]
        observer_sdk = Path(str(spec.config.get("observer_sdk") or Path(__file__).resolve().parents[3] / "sdk" / "typescript" / "dist" / "index.js"))
        if not observer_sdk.exists():
            missing.append(f"{observer_sdk} (run npm ci && npm run build in sdk/typescript)")
        if not DRIVER.exists():
            missing.append(str(DRIVER))
        if missing:
            raise AdapterError("harness preparation failed; missing: " + "; ".join(missing))
        if spec.config.get("runner", "default") not in ("default", "mock"):
            raise AdapterError("config.runner must be 'default' or 'mock'")
        if not spec.config.get("model"):
            raise AdapterError("config.model (harness model route) is required")
        head, dirty = None, None
        try:
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=30).stdout.strip() or None
            dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, timeout=30).stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            pass
        package_version = None
        try:
            package_version = json.loads((root / "package.json").read_text(encoding="utf-8")).get("version")
        except (OSError, ValueError):
            pass
        return {
            "harness": {"name": harness, "root": str(root), "package_version": package_version,
                        "git_head": head, "working_tree_modified": dirty, "state_dir": preset["state_dir"]},
            "observer_sdk": str(observer_sdk),
            "runner": spec.config.get("runner", "default"),
            "model": spec.config["model"],
        }

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        harness, preset, root = self._preset(spec)
        if request["input"]["mode"] != "full":
            raise AdapterError("native PR mode is not wired in this build; only full scans are supported")
        mode = str(spec.config.get("mode", "bootstrap"))
        if mode != "bootstrap":
            raise AdapterError("only bootstrap (full baseline) mode is supported for full-scan requests")
        trace_path = (trace_dir / "events.jsonl") if trace_dir is not None else None
        config = {
            "harness_root": str(root), "engine_entry": preset["engine_entry"], "runner_entry": preset["runner_entry"],
            "mock_entry": preset["mock_entry"], "observer_sdk": preparation["observer_sdk"],
            "repo_path": str(source_dir), "mode": mode, "model": str(spec.config["model"]),
            **({"llm_max_files": int(spec.config["llm_max_files"])} if "llm_max_files" in spec.config else {}),
            **({"llm_timeout_ms": int(spec.config["llm_timeout_ms"])} if "llm_timeout_ms" in spec.config else {}),
            **({"qmd_profile": spec.config["qmd_profile"]} if spec.config.get("qmd_profile") else {}),
            **({"specialist_ids": list(spec.config["specialist_ids"])} if spec.config.get("specialist_ids") else {}),
            "runner": str(spec.config.get("runner", "default")), "trace_mode": trace_mode,
            **({"trace_path": str(trace_path)} if trace_path else {}),
            "run_id": request["run_id"], "producer_id": f"{harness}-driver",
            "output_path": str(raw_dir / "driver-output.json"), "progress_path": str(raw_dir / "driver-progress.log"),
            "flush_timeout_ms": int(spec.config.get("flush_timeout_ms", 30000)),
        }
        config_path = raw_dir / "driver-config.json"
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (raw_dir / "driver-progress.log").write_text("", encoding="utf-8")
        argv = [str(root / "node_modules" / ".bin" / "tsx"), str(DRIVER), "--config", str(config_path)]
        result = run_command(argv, cwd=root, timeout_seconds=timeout_seconds, env=build_env(self.env_passthrough),
                             stdout_path=raw_dir / "driver-stdout.txt", stderr_path=raw_dir / "driver-stderr.txt")
        artifacts = [{"id": "driver-output", "path": raw_dir / "driver-output.json"},
                     {"id": "driver-stdout", "path": raw_dir / "driver-stdout.txt"},
                     {"id": "driver-stderr", "path": raw_dir / "driver-stderr.txt"},
                     {"id": "driver-progress", "path": raw_dir / "driver-progress.log"},
                     {"id": "driver-config", "path": config_path}]
        state_dir = source_dir / preset["state_dir"]
        claims, import_notes = import_harness_findings(state_dir / "findings", harness=harness, artifact_id="harness-findings")
        for name in ("bootstrap-plan.md", "hypothesis-scanned-files.md", "specialists.json", "scan-log.md"):
            if (state_dir / name).exists():
                artifacts.append({"id": f"harness-{name}", "path": state_dir / name})
        output: dict[str, Any] = {}
        try:
            output = json.loads((raw_dir / "driver-output.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            output = {}
        summary = output.get("summary") if isinstance(output, dict) else None
        trace = output.get("trace") if isinstance(output, dict) else None
        capture_state = (trace or {}).get("state") if isinstance(trace, dict) else None
        request_capture = {"off": "unavailable", "metadata": "partial", "content": "partial"}[trace_mode]
        capture = {
            "model_requests": request_capture, "model_responses": request_capture,
            "tool_calls": "not_applicable", "context_selection": "partial" if trace_mode != "off" else "unavailable",
            "finding_submitted": "complete" if (trace_mode != "off" and summary) else "unavailable",
            "finding_candidate": "unavailable", "finding_validation": "unavailable", "finding_filtered": "unavailable",
        }
        notes = list(import_notes)
        notes.append("Model requests are captured per logical harness call; retries inside the harness runner and token usage are not observable at this boundary.")
        notes.append("Harness findings are file-level; no line ranges were inferred.")
        model_identity = {"requested": str(spec.config["model"]), "resolved": None, "verification": "unverified",
                          "notes": ["The pi/claude CLI path does not report the served model; only the requested route is known."]}
        if spec.config.get("runner") == "mock":
            model_identity = {"requested": str(spec.config["model"]), "resolved": "deterministic-mock", "verification": "not_applicable",
                              "notes": ["Deterministic mock runner; diagnostic only, no model was called."]}
            notes.append("DIAGNOSTIC: deterministic mock runner, no model calls; results are not scanner evidence.")
        usage: dict[str, Any] = {"cost_usd": None}
        base = dict(command=argv, claims=claims, artifacts=artifacts, capture=capture, notes=notes,
                    model_identity=model_identity, usage=usage, trace_path=trace_path, capture_state=capture_state,
                    tool_versions={"harness": f"{harness}@{preparation['harness'].get('git_head') or 'unknown'}",
                                   "harness_package": str(preparation["harness"].get("package_version")),
                                   "driver": str(output.get("driver_version", "unknown"))})
        if result.timed_out:
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True,
                                 error={"code": "timeout", "message": f"harness exceeded {timeout_seconds}s"}, **base)
        if not summary:
            failure = (output.get("error") or {}) if isinstance(output, dict) else {}
            message = failure.get("message") or tail_text(raw_dir / "driver-stderr.txt")
            return NativeOutcome(status="error", exit_code=result.exit_code,
                                 error={"code": f"driver_exit_{result.exit_code}", "message": str(message)[:2000]}, **base)
        budget = summary.get("budget") or {}
        if isinstance(budget, dict) and "estimatedSpentUsd" in budget:
            notes.append(f"Harness cost estimate (not measured): {budget.get('estimatedSpentUsd')} USD "
                         f"for {budget.get('actualLlmFilesScanned')} LLM files; measured cost unavailable.")
        scan_stats = summary.get("bootstrapScan") or {}
        llm_calls = int(scan_stats.get("llmCalls") or 0)
        failed_calls = int(scan_stats.get("failedCalls") or 0)
        notes.append(f"Harness self-report: llm_calls={llm_calls} failed_calls={failed_calls} "
                     f"coverage={scan_stats.get('hypothesisCoverage')} status={scan_stats.get('status')} "
                     f"runtime_profile={summary.get('runtimeProfile')} degraded={summary.get('degraded')}")
        if result.exit_code not in (0, 2):
            return NativeOutcome(status="error", exit_code=result.exit_code,
                                 error={"code": f"driver_exit_{result.exit_code}", "message": tail_text(raw_dir / "driver-stderr.txt")}, **base)
        if llm_calls and failed_calls >= llm_calls:
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "llm_path_failed", "message": "every harness model call failed; findings come from deterministic passes only"}, **base)
        if summary.get("degradation") or scan_stats.get("status") == "inconclusive":
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "harness_inconclusive",
                                        "message": f"degradation={summary.get('degradation')} scan_status={scan_stats.get('status')} reasons={scan_stats.get('reasons')}"}, **base)
        return NativeOutcome(status="success", exit_code=result.exit_code, **base)
