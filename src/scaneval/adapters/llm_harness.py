"""Own-harness adapter for the securevibes-agent / Fieldglass engine family.

The harness runs unchanged through its own engine entry point inside its own ``tsx``.
ScanEval only injects the harness's default model runner wrapped by the observer SDK
and a progress reporter, then imports the finding records the engine wrote. Findings
are file-level; this importer keeps them file-level and never invents line ranges.

A record the importer cannot read is import loss, not a detail: it is counted, and a
count above zero degrades the outcome to ``partial`` with unresolved bundles and error
code ``import_loss``, so a scan that emitted a finding ScanEval could not read can earn
neither completeness nor silence credit for it.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, NamedTuple

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
# What each harness route asks its model CLI to allow. Recorded as the harness's own
# declaration; this adapter never verifies that the CLI honored it, and it observes no
# tool call either way, so these strings explain an unavailable category rather than
# standing in for one.
TOOL_POLICY = {
    "pi": "the whole tool surface is disabled with --no-tools.",
    "claude": "network and spawn tools are denied with --disallowedTools; file tools such as Read and Bash remain permitted inside an isolated working directory.",
    "mock": "no model process is spawned, so no tool surface exists.",
}


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


class HarnessImport(NamedTuple):
    """One import of the harness's own finding records.

    ``lost`` is the number of records the importer could not turn into a claim, for any
    reason. It is part of the contract rather than a note because the caller must degrade
    the outcome when it is above zero: a record ScanEval dropped is a finding the scanner
    did emit, so the scan cannot stand as a complete or quiet observation.
    """

    claims: list[dict]
    artifacts: list[dict]
    notes: list[str]
    lost: int


def import_harness_findings(findings_dir: Path, *, harness: str, artifact_prefix: str,
                            stage_dir: Path) -> HarnessImport:
    """Stage ``findings/*.md`` and translate each one into a file-only claim.

    A finding record is a ``*.md`` file in *findings_dir*, which is what the harness's own
    reader treats as one. Each imported record is copied into *stage_dir* and registered as its
    own raw artifact under ``<artifact_prefix>/<file name>``, and the claim carries that same
    id, so every claim points at a hash-backed record the bundle holds rather than at a name
    nothing registers. A record that is not a regular file, cannot be read, carries no id,
    carries an unusable ``file_path``, or cannot be staged yields no claim and is counted in
    ``lost`` as well as noted. The full native allegation text is preserved; line ranges are
    never invented.
    """
    claims: list[dict] = []
    artifacts: list[dict] = []
    notes: list[str] = []
    lost = 0
    if not findings_dir.is_dir():
        return HarnessImport(claims, artifacts, ["no findings directory was written by the harness"], 0)
    for path in sorted(findings_dir.glob("*.md")):
        if path.is_symlink() or not path.is_file():
            lost += 1
            notes.append(f"{path.name}: finding record is not a regular file; not imported")
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            lost += 1
            notes.append(f"{path.name}: finding record could not be read ({exc.strerror}); not imported")
            continue
        record, body = parse_frontmatter(text)
        finding_id = str(record.get("id") or "")
        if not finding_id:
            lost += 1
            notes.append(f"{path.name}: no id in frontmatter; not imported")
            continue
        file_path = str(record.get("file_path") or "").replace("\\", "/")
        if file_path.startswith("./"):
            file_path = file_path[2:]
        if not file_path or file_path.startswith("/") or ".." in file_path.split("/"):
            lost += 1
            notes.append(f"{finding_id}: unusable file_path {file_path!r}; not imported, see the raw finding record")
            continue
        try:
            stage_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, stage_dir / path.name)
        except OSError as exc:
            # The claim would name an artifact the bundle does not hold, so the record is
            # counted as lost rather than imported against a copy that was never made.
            lost += 1
            notes.append(f"{finding_id}: finding record could not be staged ({exc.strerror}); not imported")
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
            "raw_artifact_id": f"{artifact_prefix}/{path.name}",
        }
        if reasoning and reasoning != "N/A":
            claim["evidence_text"] = reasoning
        severity = record.get("severity")
        if isinstance(severity, str) and severity:
            claim["native_severity"] = severity
        claims.append(claim)
        artifacts.append({"id": claim["raw_artifact_id"], "path": stage_dir / path.name})
    return HarnessImport(claims, artifacts, notes, lost)


def capture_status(trace_mode: str, routes: list[str], *, has_summary: bool) -> dict[str, str]:
    """Per-category capture availability for one harness run.

    Tool dispatch is ``unavailable`` on every real route: it happens inside the model CLI
    this adapter spawns, so no tool event is observed and the absence of one establishes
    nothing about whether a tool ran. Only the mock runner, which spawns no process at
    all, makes the concept inapplicable. Model events are ``partial`` at best because the
    harness retries inside its own runner, below the observed boundary.
    """
    request_capture = {"off": "unavailable", "metadata": "partial", "content": "partial"}[trace_mode]
    traced = trace_mode != "off"
    return {
        "model_requests": request_capture,
        "model_responses": request_capture,
        "tool_calls": "not_applicable" if routes == ["mock"] else "unavailable",
        "context_selection": "partial" if traced else "unavailable",
        "finding_submitted": "complete" if (traced and has_summary) else "unavailable",
        "finding_candidate": "unavailable",
        "finding_validation": "unavailable",
        "finding_filtered": "unavailable",
    }


class LlmHarnessAdapter(Adapter):
    name = "llm-harness"
    adapter_version = "2.1.0"
    requires_git = True
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})
    env_passthrough = ("NODE_OPTIONS", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "XDG_CONFIG_HOME")
    state_dirs = (".securevibes", ".fieldglass")

    def _preset(self, spec: SystemSpec) -> tuple[str, dict[str, Any], Path]:
        """The harness preset and its root, resolved to an absolute path.

        The root is used both as the prefix of the executable path and as the working
        directory of the process that runs it, so a relative one would be applied twice and
        produce a doubled path such as ``harness/harness/node_modules/.bin/tsx``. Resolving it
        here makes preparation and the scan agree on one absolute path, which is the value the
        preparation record reports.
        """
        harness = str(spec.config.get("harness") or "")
        if harness not in HARNESS_PRESETS:
            raise AdapterError(f"config.harness must be one of {sorted(HARNESS_PRESETS)}")
        root = Path(str(spec.config.get("root") or "")).expanduser().resolve()
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
            "harness": {"name": harness, "root": str(root), "configured_root": str(spec.config.get("root") or ""),
                        "package_version": package_version, "git_head": head,
                        "working_tree_modified": dirty, "state_dir": preset["state_dir"]},
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
        # The finding records live in the workspace too, so each imported one is copied into the
        # staging directory and registered under the id its claim carries.
        imported = import_harness_findings(state_dir / "findings", harness=harness,
                                           artifact_prefix="harness-findings",
                                           stage_dir=raw_dir / "harness-findings")
        claims = imported.claims
        artifacts.extend(imported.artifacts)
        # The harness writes its plan and scan log inside the workspace, which is removed once
        # the scan returns. Copy the records worth hashing into the staging directory so they
        # survive as raw artifacts; the whole state directory is preserved separately.
        plans = raw_dir / "harness-plan"
        plan_notes: list[str] = []
        for name in ("bootstrap-plan.md", "pr-plan.md", "batch-plan.md", "hypothesis-scanned-files.md",
                     "specialists.json", "specialists.md", "scan-log.md", "threat-model.md", "codebase-profile.json"):
            written = state_dir / name
            if written.is_symlink() or (written.exists() and not written.is_file()):
                # Not staged and not hashed, and said so rather than dropped in silence. These
                # are plan records, not claims, so this does not degrade the scan status.
                plan_notes.append(f"{name}: harness record is not a regular file; it was not staged as an artifact")
            elif written.is_file():
                plans.mkdir(parents=True, exist_ok=True)
                copied = plans / name
                shutil.copyfile(written, copied)
                artifacts.append({"id": f"harness-{name}", "path": copied})
        output: dict[str, Any] = {}
        try:
            output = json.loads((raw_dir / "driver-output.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            output = {}
        summary = output.get("summary") if isinstance(output, dict) else None
        trace = output.get("trace") if isinstance(output, dict) else None
        capture_state = (trace or {}).get("state") if isinstance(trace, dict) else None
        routes = sorted({str(route) for route in (output.get("observed_routes") or [])}) if isinstance(output, dict) else []
        mock_only = routes == ["mock"]
        capture = capture_status(trace_mode, routes, has_summary=bool(summary))
        notes = list(imported.notes) + plan_notes
        loss_message = None
        if imported.lost:
            loss_message = (f"{imported.lost} harness finding record(s) could not be imported: "
                            + "; ".join(imported.notes))[:2000]
            notes.append(f"Import loss: {imported.lost} finding record(s) the harness wrote could not be "
                         "imported, so this scan can earn neither completeness nor quiet credit.")
        notes.append("Model requests are captured per logical harness call; retries inside the harness runner and token usage are not observable at this boundary.")
        for route in routes:
            policy = TOOL_POLICY.get(route)
            if policy:
                notes.append(f"Declared tool policy on the {route} route: {policy} This is the argv the harness built, not an observation of what the CLI did.")
        if not mock_only:
            notes.append("Tool dispatch was not observed: it happens inside the model CLI subprocess. Absence of tool events is not evidence that no tool ran.")
        notes.append("Harness findings are file-level; no line ranges were inferred.")
        model_identity = {"requested": str(spec.config["model"]), "resolved": None, "verification": "unverified",
                          "notes": ["The pi/claude CLI path does not report the served model; only the requested route is known."]}
        if spec.config.get("runner") == "mock":
            model_identity = {"requested": str(spec.config["model"]), "resolved": "deterministic-mock", "verification": "not_applicable",
                              "notes": ["Deterministic mock runner; diagnostic only, no model was called."]}
            notes.append("DIAGNOSTIC: deterministic mock runner, no model calls; results are not scanner evidence.")
        usage: dict[str, Any] = {"cost_usd": None}
        # Import loss leaves the claim set incomplete, so the bundles it delivers are not
        # resolved: the scoring contract then refuses both completed-control and quiet credit.
        base = dict(command=argv, claims=claims, artifacts=artifacts, capture=capture, notes=notes,
                    model_identity=model_identity, usage=usage, trace_path=trace_path, capture_state=capture_state,
                    bundles_resolved=imported.lost == 0,
                    tool_versions={"harness": f"{harness}@{preparation['harness'].get('git_head') or 'unknown'}",
                                   "harness_package": str(preparation["harness"].get("package_version")),
                                   "driver": str(output.get("driver_version", "unknown"))})

        def with_loss(message: str) -> str:
            """The branch's own message, with the import loss named beside it."""
            return f"{message}; {loss_message}"[:2000] if loss_message else message

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
                                 error={"code": "llm_path_failed", "message": with_loss("every harness model call failed; findings come from deterministic passes only")}, **base)
        if summary.get("degradation") or scan_stats.get("status") == "inconclusive":
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "harness_inconclusive",
                                        "message": with_loss(f"degradation={summary.get('degradation')} scan_status={scan_stats.get('status')} reasons={scan_stats.get('reasons')}")}, **base)
        if loss_message:
            # A scan whose findings did not all survive the import is not a clean run: it is
            # partial, and the count and the reason travel with it as an explicit error.
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "import_loss", "message": loss_message}, **base)
        return NativeOutcome(status="success", exit_code=result.exit_code, **base)
