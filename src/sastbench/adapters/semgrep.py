"""Pinned Semgrep OSS adapter: local ruleset checkout, no registry downloads, no metrics.

The ruleset is a git commit of a rules repository fetched into the immutable cache; its
commit and per-file hashes are recorded. Live ``p/...`` registry configs are refused
because they are moving targets, not pins.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
from typing import Any

from ..kinds import cwe_ids, kind_for_cwes, mapping_version
from ..materialize import fetch_snapshot, sha256_file, tree_hash
from .base import Adapter, AdapterError, NativeOutcome, SystemSpec, build_env, run_command, tail_text


ARTIFACT_JSON = "semgrep-json"
_UNAVAILABLE = "requires login"


def _binary(spec: SystemSpec) -> str:
    configured = spec.config.get("binary")
    if configured:
        return str(configured)
    sibling = Path(sys.executable).with_name("semgrep")
    if sibling.exists():
        return str(sibling)
    found = shutil.which("semgrep")
    if not found:
        raise AdapterError("semgrep binary not found; install the official-adapters extra or set config.binary")
    return found


def semgrep_version(binary: str, raw_dir: Path, timeout_seconds: float = 60) -> str:
    result = run_command([binary, "--version"], cwd=raw_dir, timeout_seconds=timeout_seconds,
                         env=build_env(), stdout_path=raw_dir / "semgrep-version.txt",
                         stderr_path=raw_dir / "semgrep-version.stderr.txt")
    if result.exit_code != 0:
        raise AdapterError(f"semgrep --version failed: {tail_text(result.stderr_path)}")
    return (raw_dir / "semgrep-version.txt").read_text(encoding="utf-8").strip()


def _dotted_prefixes(directories) -> list[str]:
    # Semgrep builds check_id as the config path it was given, dot-separated and without the
    # leading slash, then the subdirectories under that path, then the declared rule id. The
    # path part is a machine location, so it is removed before recording. Longest first, so a
    # nested directory is stripped before a parent of it.
    prefixes = []
    for directory in directories or ():
        dotted = str(directory).replace("\\", "/").strip("/").replace("/", ".")
        if dotted:
            prefixes.append(dotted + ".")
    return sorted(prefixes, key=len, reverse=True)


def import_semgrep_results(payload: dict, *, artifact_id: str = ARTIFACT_JSON,
                           ruleset_roots=(), config_dirs=()) -> tuple[list[dict], list[str]]:
    """Translate Semgrep JSON ``results`` into atomic claims without inventing evidence.

    ``ruleset_roots`` is the preferred input: stripping the rules checkout root leaves
    ``native_rule_id`` as the id relative to that checkout, so the language and category
    directories a rule was declared under survive while the local cache path does not.
    ``config_dirs`` is the older behavior kept for existing callers and drops every directory
    segment inside the checkout as well; it is used only when no root is supplied.

    This does not assign truth labels, split bundled findings, invent locations, or recover a
    rule id from a check_id that carries a path prefix none of the supplied directories match.
    """
    claims: list[dict] = []
    notes: list[str] = []
    results = payload.get("results")
    if not isinstance(results, list):
        raise AdapterError("semgrep JSON has no results array")
    prefixes = _dotted_prefixes(ruleset_roots) if ruleset_roots else _dotted_prefixes(config_dirs)
    for index, item in enumerate(results, start=1):
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        cwes = cwe_ids(metadata.get("cwe"))
        rule_id = str(item["check_id"])
        for prefix in prefixes:
            if rule_id.startswith(prefix):
                rule_id = rule_id[len(prefix):]
                break
        path = str(item["path"]).replace("\\", "/")
        if path.startswith("./"):
            path = path[2:]
        start = int(item["start"]["line"])
        end = int(item["end"]["line"])
        if end < start:
            end = start
            notes.append(f"result {index}: end line before start line; clamped to start")
        message = str(extra.get("message") or "").strip() or str(item["check_id"])
        claim: dict[str, Any] = {
            "claim_id": f"c{index}",
            "allegation": message,
            "kind": kind_for_cwes(cwes),
            "primary_location": {"path": path, "start_line": start, "end_line": end},
            "native_rule_id": rule_id,
            "raw_artifact_id": artifact_id,
        }
        fingerprint = extra.get("fingerprint")
        if isinstance(fingerprint, str) and fingerprint and fingerprint != _UNAVAILABLE:
            claim["native_id"] = fingerprint
        lines = extra.get("lines")
        if isinstance(lines, str) and lines and lines != _UNAVAILABLE:
            claim["evidence_text"] = lines
        severity = extra.get("severity")
        if isinstance(severity, str) and severity:
            claim["native_severity"] = severity
        if cwes:
            claim["native_cwe"] = cwes
        claims.append(claim)
    if any(extra.get("lines") == _UNAVAILABLE for extra in (r.get("extra") or {} for r in results)):
        notes.append("Semgrep OSS omitted matched source text and fingerprints (requires login); evidence_text left absent")
    return claims, notes


class SemgrepAdapter(Adapter):
    name = "semgrep"
    adapter_version = "2.0.0"
    requires_git = False
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})

    def prepare(self, spec: SystemSpec, cache_root: Path) -> dict[str, Any]:
        ruleset = spec.config.get("ruleset")
        if not isinstance(ruleset, dict) or not {"url", "commit", "paths"} <= set(ruleset):
            raise AdapterError("semgrep config.ruleset needs url, commit, and paths (a pinned rules checkout)")
        if any(str(p).startswith("p/") or str(p).startswith("r/") for p in ruleset["paths"]):
            raise AdapterError("registry rulesets are not pins; use a rules repository commit")
        snapshot = fetch_snapshot(str(ruleset["url"]), str(ruleset["commit"]), cache_root)
        # scan() runs semgrep with cwd=source_dir (a private workspace), so a config path
        # relative to the controller's working directory would not resolve there. Record
        # absolute paths only.
        root = snapshot.path.resolve()
        config_dirs: list[str] = []
        hashes: dict[str, str] = {}
        for relative in ruleset["paths"]:
            directory = (root / str(relative)).resolve()
            if not directory.is_dir():
                raise AdapterError(f"ruleset path {relative!r} is not a directory in {root}")
            config_dirs.append(str(directory))
            for rule_file in sorted(directory.rglob("*")):
                if rule_file.suffix in {".yaml", ".yml"} and rule_file.is_file() and not rule_file.name.startswith("."):
                    hashes[rule_file.relative_to(root).as_posix()] = sha256_file(rule_file)[0]
        if not hashes:
            raise AdapterError("ruleset contains no rule files")
        return {
            "ruleset": {
                "url": snapshot.url,
                "commit": snapshot.commit,
                "git_tree": snapshot.git_tree,
                "paths": [str(p) for p in ruleset["paths"]],
                "rule_files": len(hashes),
                "tree_hash": tree_hash(hashes),
            },
            "config_dirs": config_dirs,
            # The checkout root, recorded so the importer can shorten check_id to a
            # ruleset-relative rule id instead of dropping the directories inside the checkout.
            "ruleset_root": str(root),
        }

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        binary = _binary(spec)
        version = semgrep_version(binary, raw_dir)
        argv = [
            binary, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
            "--timeout", str(int(spec.config.get("rule_timeout_seconds", 30))),
            "--jobs", str(int(spec.config.get("jobs", 1))),
        ]
        for directory in preparation["config_dirs"]:
            argv.append(f"--config={directory}")
        argv.append(".")
        stdout = raw_dir / "semgrep.json"
        stderr = raw_dir / "semgrep.stderr.txt"
        result = run_command(argv, cwd=source_dir, timeout_seconds=timeout_seconds, env=build_env(),
                             stdout_path=stdout, stderr_path=stderr)
        artifacts = [{"id": ARTIFACT_JSON, "path": stdout}, {"id": "semgrep-stderr", "path": stderr}]
        tool_versions = {"semgrep": version, "ruleset_commit": preparation["ruleset"]["commit"],
                         "ruleset_tree_hash": preparation["ruleset"]["tree_hash"]}
        capture = {"model_requests": "not_applicable", "tool_calls": "not_applicable",
                   "context_selection": "not_applicable", "finding_lifecycle": "not_applicable"}
        base = dict(command=argv, artifacts=artifacts, tool_versions=tool_versions, capture=capture,
                    usage={"cost_usd": 0.0}, notes=["Semgrep OSS has no metered cost; license cost not included."])
        if result.timed_out:
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True, error={"code": "timeout",
                                 "message": f"semgrep exceeded {timeout_seconds}s; output written at exit only"}, **base)
        try:
            payload = json.loads(stdout.read_text(encoding="utf-8"))
            ruleset_root = preparation.get("ruleset_root")
            # config_dirs stays as the fallback so a preparation recorded before ruleset_root
            # existed still keeps the cache path out of native_rule_id.
            claims, notes = import_semgrep_results(
                payload,
                ruleset_roots=(ruleset_root,) if ruleset_root else (),
                config_dirs=preparation.get("config_dirs") or (),
            )
        except (OSError, ValueError, KeyError, TypeError, AdapterError) as exc:
            return NativeOutcome(status="error", exit_code=result.exit_code,
                                 error={"code": f"exit_{result.exit_code}" if result.exit_code else "unparseable_output",
                                        "message": f"{exc}; stderr: {tail_text(stderr)}"}, **base)
        base["notes"] = base["notes"] + notes
        base["tool_versions"]["semgrep_reported"] = str(payload.get("version", ""))
        errors = payload.get("errors") or []
        fatal = [e for e in errors if isinstance(e, dict) and e.get("level") == "error"]
        scanned = (payload.get("paths") or {}).get("scanned") or []
        if result.exit_code != 0:
            # --quiet keeps the reason off stderr, so the JSON errors array carries it.
            reason = str(fatal[0].get("message", "")).strip() if fatal else ""
            detail = f"; reason: {reason}" if reason else ""
            if not scanned and not claims:
                # Nothing was scanned and nothing was reported: this run produced no output at
                # all, so it is an error. Calling it partial would let a failed invocation read
                # as a quiet negative result.
                message = (f"semgrep exited {result.exit_code} with no scanned paths and no results"
                           f"{detail}; stderr: {tail_text(stderr)}")
                return NativeOutcome(status="error", exit_code=result.exit_code, claims=[],
                                     error={"code": f"exit_{result.exit_code}", "message": message[:2000]}, **base)
            message = (f"semgrep exited {result.exit_code} after scanning {len(scanned)} paths"
                       f"{detail}; stderr: {tail_text(stderr)}")
            return NativeOutcome(status="partial", exit_code=result.exit_code, claims=claims,
                                 error={"code": f"exit_{result.exit_code}", "message": message[:2000]}, **base)
        if fatal:
            base["notes"].append(f"{len(fatal)} error-level Semgrep diagnostics; see raw semgrep.json errors")
            reason = str(fatal[0].get("message", "")).strip()
            if not scanned and not claims:
                # Exit 0 does not make this a clean run: nothing was scanned and nothing was
                # reported, so the invocation observed no source at all. Calling it partial
                # would let a failed run read as a quiet negative result.
                detail = f"; reason: {reason}" if reason else ""
                message = ("semgrep exited 0 with error-level diagnostics, no scanned paths and "
                           f"no results{detail}; stderr: {tail_text(stderr)}")
                return NativeOutcome(status="error", exit_code=0, claims=[],
                                     error={"code": "scan_errors", "message": message[:2000]}, **base)
            return NativeOutcome(status="partial", exit_code=0, claims=claims,
                                 error={"code": "scan_errors", "message": reason[:500]}, **base)
        skipped = (payload.get("paths") or {}).get("skipped") or []
        if skipped:
            base["notes"].append(f"Semgrep skipped {len(skipped)} paths under its own ignore rules; see raw semgrep.json paths")
        return NativeOutcome(status="success", exit_code=0, claims=claims, **base)
