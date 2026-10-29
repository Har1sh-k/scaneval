"""Own-harness adapter for the securevibes-agent / Fieldglass engine family.

The harness runs through its own engine entry point inside its own ``tsx``.
ScanEval injects the harness's model runner wrapped by the observer SDK and a progress
reporter, then imports the finding records the engine wrote. Native scan-site anchors
are kept when present; a missing or invalid anchor remains file-level.

Two request modes are carried out. A full request runs the harness's ``bootstrap`` mode over the
whole exported tree, and one that also carries a ``pr`` is refused before anything runs, because
bootstrap would ignore the change it names. A PR request runs its ``pr`` mode over the change
between the base and head commits the request names, which the runner has already made real in the
workspace's git history: the two are handed to the engine as ``baseRef`` and ``headRef`` exactly as
named, so the engine never falls back to ``origin/main`` or ``HEAD~1``, and the engine's own write
policy is left alone, so its knowledge base is written into the workspace and imported like any
bootstrap run's.
The run starts from a fresh state either way: an export strips the harness's state directory, so
no earlier finding, decision, or context note reaches it, which is recorded in the run's notes.
The consensus judge, the one stage that validates findings, runs only when consensus is
configured, and this adapter never configures it, so no run it produces has a validation stage.

A record the importer cannot read is import loss, not a detail: it is counted, and a
count above zero degrades the outcome to ``partial`` with unresolved bundles and error
code ``import_loss``, so a scan that emitted a finding ScanEval could not read can earn
neither completeness nor silence credit for it.

So is a record the importer never saw. The harness names the findings it wrote in its own
summary, and :func:`reconcile_import` compares that self-report against the claims the import
delivered: a finding the harness says it wrote that did not arrive is the same loss, counted
the same way. Counting only what the importer could see made the worst case invisible, because
a scan that lost every finding before the import left nothing to count and read as a clean
success. A self-report in a shape the reader cannot parse is counted as loss for the same
reason: unreadable evidence is missing evidence, not evidence that nothing was lost.

Only records this scan produced are imported. The findings directory is snapshotted before
the harness process starts, and a record already present with the same bytes is left out, so
a finding record the repository under test shipped cannot be counted as a detection. That
establishes that the bytes are new to the workspace, not that the harness's model wrote them.

Every path this adapter touches after the harness process starts is a path the harness could
have replaced, and any component of it can be a symbolic link, not only the last one. So each
read and each copy destination goes through one :class:`Enclosure`, which resolves the whole
path and proves it is still inside the workspace the scanner was handed or the staging
directory this run created. Both of those directories have their real path captured before the
harness process starts, so a harness that replaces one cannot move the boundary it is checked
against. A path that resolves out is refused and counted, never followed.

Two rules about touching such a path at all, each stated in exactly one place, and both of
those places in :mod:`scaneval.execution`, so the adapter and the bundle writer cannot drift
apart about them. :func:`~scaneval.execution.list_directory` is the one listing, so a directory
this cannot read is a counted failure and never an empty directory. :func:`read_record`, which
wraps :func:`~scaneval.execution.read_regular_file`, is the one read, so every read proves the
file is a regular file in the same open that reads it: a named pipe the harness left where its
own output belongs used to block the invocation forever, leaving no bundle and no record that
the run had happened. :func:`stage_record` is the one write, and it proves the same thing about
its destination in the open that creates it, for the same reasons in the other direction.

That boundary is a check, not isolation: ``docs/THREAT_MODEL.md`` says what it does and does not
defend against, and a harness process still running in the workspace can defeat any of it. The
checks in :func:`stage_record` are the clearest case: each of them is a separate operation from
the open that follows it, so they refuse what is planted before them and nothing planted after.
"""

from __future__ import annotations

import base64
import binascii
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Any, NamedTuple

from ..execution import list_directory, read_regular_file
from ..kinds import kind_for_harness_class
from ..materialize import HARNESS_STATE_DIRS, Containment, MaterializationError, git_command
from .base import Adapter, AdapterError, NativeOutcome, SystemSpec, active_backend, build_env, run_command


DRIVER = Path(__file__).with_name("llm_harness_driver.mts")
DEFAULT_IMAGE_HARNESS_COMMIT = "f959cbcf010c7e41f780c718b65b1724d3aecb43"
DEFAULT_IMAGE_PI_VERSION = "1.4.0"
IMAGE_ADAPTER_FILES = {
    "driver": "llm_harness_driver.mts",
    "runner": "pi_oci_runner.mts",
    "extension": "pi_open_context.mts",
    "extension_tools": "pi_open_context_tools.mjs",
}
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
    "pi-oci": ("an explicit allowlist (--tools scaneval_fetch, scaneval_git, scaneval_read, and scaneval_search only "
               "when a search endpoint is declared) served by the image-owned research extension loaded with "
               "--no-extensions -e; MCP, skills, prompt templates, themes, context files and project trust are "
               "disabled, and no built-in file, shell, edit or write tool is declared."),
}

# The two places the harness can run. ``local`` is the host checkout this adapter has always run,
# unchanged. ``oci_image`` is an image-owned runtime (Node, tsx, the pinned harness, Pi, the observer
# SDK, this driver, the Pi runner and the research extension, all inside the scanner image), run
# only under the oci backend with public_research. Neither ever stands in for the other.
RUNTIMES = ("local", "oci_image")
IMAGE_PATHS = {
    "root": "/opt/scaneval/harness",
    "tsx": "/opt/scaneval/harness/node_modules/.bin/tsx",
    "driver": "/opt/scaneval/llm_harness_driver.mts",
    "pi_runner": "/opt/scaneval/pi_oci_runner.mts",
    "pi_extension": "/opt/scaneval/pi_open_context.mts",
    "pi_synthetic_extension": "/opt/scaneval/pi_synthetic_provider.mts",
    "observer_sdk": "/opt/scaneval/observer/index.js",
    "runtime_receipt": "/opt/scaneval/runtime.json",
    "pi_binary": "pi",
}
IMAGE_PROVIDERS = ("openai-codex",)
# DIAGNOSTIC ONLY: an in-process deterministic provider that calls no model, for exercising the
# image route end to end. A run on it is recorded as diagnostic, never as scanner evidence.
SYNTHETIC_MODEL = "scaneval-synthetic/deterministic-open-context"
THINKING_LEVELS = ("off", "minimal", "low", "medium", "high", "xhigh", "max")
DEFAULT_PI_AUTH_ENV = "SV_AGENT_PI_AUTH_JSON"
# Configuration that only the image runtime reads. A local system naming any of them is refused
# rather than run with the setting silently ignored.
IMAGE_ONLY_KEYS = frozenset({"image_paths", "thinking_level", "pi_auth_env", "research_search",
                             "research_preflight_url", "expected_harness_commit", "expected_pi_version",
                             "synthetic_tool_calls"})
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
MAX_JOURNAL_FILES = 1000
# Pi refreshes an OAuth token with less than five minutes left. The container's copy carries no
# refresh token, so the access token must outlive the scan's limit, that window, and a margin.
PI_REFRESH_WINDOW_SECONDS = 300


def credential_validity(timeout_seconds: float) -> float:
    """Seconds the access token must remain valid for a scan of *timeout_seconds*."""
    if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
            or not 0 < timeout_seconds <= 2**53 - 1 or not math.isfinite(timeout_seconds)):
        raise AdapterError("the image scan timeout must be a finite positive number")
    return float(timeout_seconds) + PI_REFRESH_WINDOW_SECONDS + 60


_UNPARSED = object()


def check_pi_credential(raw: str | None, provider: str, name: str, *, now: float | None = None,
                        valid_for_seconds: float = PI_REFRESH_WINDOW_SECONDS + 60) -> None:
    """Refuse a Pi OAuth credential document that cannot be the one this route needs.

    The same shape the driver checks inside the container, checked here first so a run with a
    missing or malformed credential is refused before any container starts. Every message names
    the variable and the defect, never a value, and no parser error is chained, because a JSON
    error carries the document it failed on.

    The access token must stay valid for *valid_for_seconds*: the container's copy never carries
    the refresh token, so nothing inside a scan can refresh, and concurrent shards cannot rotate
    one operator credential underneath each other. Refreshing is the operator's, once, before.
    """
    if not raw:
        raise AdapterError(f"{name} is not set in this process's environment: export in it a JSON object holding "
                           f"exactly one access-only {provider!r} OAuth entry (omit refresh and other fields), and "
                           f"declare it under execution.credentials with provider {provider!r}")
    if len(raw) > 65536:
        raise AdapterError(f"{name} is larger than 65536 characters, which no single Pi OAuth entry is")
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate credential field")
            result[key] = value
        return result

    try:
        parsed = json.loads(raw, object_pairs_hook=unique_fields)
    except (ValueError, RecursionError):
        parsed = _UNPARSED
    # Raised outside the handler, so the parser's error, which holds the document, is not chained.
    if parsed is _UNPARSED:
        raise AdapterError(f"{name} is not JSON; it must hold {{{provider!r}: {{\"type\": \"oauth\", ...}}}}")
    if not isinstance(parsed, dict):
        raise AdapterError(f"{name} is not a JSON object")
    if list(parsed) != [provider]:
        raise AdapterError(f"{name} must hold exactly one entry, for provider {provider!r}; it holds {len(parsed)} "
                           f"entr{'y' if len(parsed) == 1 else 'ies'}" + (" for another provider" if len(parsed) == 1 else ""))
    entry = parsed[provider]
    if not isinstance(entry, dict) or entry.get("type") != "oauth":
        raise AdapterError(f"the {provider} entry in {name} must be an OAuth credential (type 'oauth'); this route "
                           "accepts no API key and falls back to no paid provider")
    if "refresh" in entry:
        raise AdapterError(f"the {provider} OAuth entry in {name} must be access-only: omit the refresh field; "
                           "a refresh token must never enter a scanner container")
    if set(entry) - {"type", "access", "expires", "accountId"}:
        raise AdapterError(f"the {provider} OAuth entry in {name} contains unsupported fields; "
                           "export only type, access, expires, and optional accountId")
    if "accountId" in entry and (not isinstance(entry["accountId"], str) or not entry["accountId"]):
        raise AdapterError(f"the {provider} OAuth entry in {name} has an invalid accountId")
    if not isinstance(entry.get("access"), str) or not entry["access"]:
        raise AdapterError(f"the {provider} OAuth entry in {name} has no access token")
    expires = entry.get("expires")
    if (isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not -2**53 < expires < 2**53 or not math.isfinite(expires)):
        raise AdapterError(f"the {provider} OAuth entry in {name} has no numeric expiry")
    if (isinstance(valid_for_seconds, bool) or not isinstance(valid_for_seconds, (int, float))
            or not PI_REFRESH_WINDOW_SECONDS + 60 <= valid_for_seconds < 2**53
            or not math.isfinite(valid_for_seconds)):
        raise AdapterError("the Pi access-token validity window must be finite and include its refresh margin")
    if expires <= ((now if now is not None else time.time()) + valid_for_seconds) * 1000:
        raise AdapterError(f"the {provider} access token in {name} has expired or expires within {int(valid_for_seconds)} seconds, "
                           "before this scan's limit and Pi's refresh window; refresh it explicitly once (pi auth "
                           "check) before the run, nothing inside the scan refreshes it")


def image_settings(config: dict) -> dict[str, Any]:
    """The image runtime's validated settings, or an :class:`AdapterError` naming the field.

    Everything is decided from configuration alone, so ``prepare()`` can refuse a bad system
    without touching the host, and the paths are paths inside the image, never checked here.
    """
    harness = config.get("harness")
    if harness != "securevibes-agent":
        raise AdapterError("runtime oci_image runs the securevibes-agent harness only; "
                           f"config.harness is {harness!r}")
    if config.get("runner", "default") != "default":
        raise AdapterError("runtime oci_image runs the default Pi route; for a diagnostic run without a model use "
                           f"config.model {SYNTHETIC_MODEL!r} rather than the mock runner")
    if str(config.get("mode", "bootstrap")) != "bootstrap":
        raise AdapterError("runtime oci_image runs bootstrap (full) scans only")
    model = config.get("model")
    if not isinstance(model, str) or not model:
        raise AdapterError("config.model (harness model route) is required")
    synthetic = model == SYNTHETIC_MODEL
    provider, _, model_id = model.partition("/")
    if not synthetic and (provider not in IMAGE_PROVIDERS or not _MODEL_ID.match(model_id)):
        raise AdapterError(f"runtime oci_image supports the provider route(s) {', '.join(IMAGE_PROVIDERS)} as "
                           f"'<provider>/<model id>', not {model!r}; no other provider or model is substituted")
    thinking = config.get("thinking_level", "high")
    if thinking not in THINKING_LEVELS:
        raise AdapterError(f"config.thinking_level must be one of {', '.join(THINKING_LEVELS)}, not {thinking!r}")
    auth_env = config.get("pi_auth_env", None if synthetic else DEFAULT_PI_AUTH_ENV)
    if synthetic:
        if auth_env is not None:
            raise AdapterError("the synthetic diagnostic route takes no credential; remove config.pi_auth_env")
    elif (not isinstance(auth_env, str) or not _ENV_NAME.match(auth_env)
          or auth_env.startswith(("GIT_", "SCANEVAL_", "PI_"))
          or auth_env in {"HOME", "PATH", "TMPDIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}):
        raise AdapterError("config.pi_auth_env must name an environment variable outside the GIT_, SCANEVAL_ and PI_ "
                           f"namespaces, not {auth_env!r}")
    search = config.get("research_search", False)
    if not isinstance(search, bool):
        raise AdapterError("config.research_search must be a boolean")
    preflight = config.get("research_preflight_url")
    if preflight is not None and (not isinstance(preflight, str) or not preflight.startswith("https://")
                                  or len(preflight) > 2048 or any(ord(ch) < 33 for ch in preflight)):
        raise AdapterError("config.research_preflight_url must be one https:// URL")
    paths = dict(IMAGE_PATHS)
    overrides = config.get("image_paths") or {}
    if not isinstance(overrides, dict) or set(overrides) - set(IMAGE_PATHS):
        raise AdapterError(f"config.image_paths may name only {', '.join(sorted(IMAGE_PATHS))}")
    for key, value in overrides.items():
        if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or (
                key != "pi_binary" and not value.startswith("/")):
            raise AdapterError(f"config.image_paths.{key} must be an absolute path inside the image")
        paths[key] = value
    if "root" in overrides and "tsx" not in overrides:
        paths["tsx"] = paths["root"].rstrip("/") + "/node_modules/.bin/tsx"
    expected_commit = config.get("expected_harness_commit", None if synthetic else DEFAULT_IMAGE_HARNESS_COMMIT)
    if not synthetic and expected_commit is None:
        raise AdapterError("config.expected_harness_commit cannot be null on the real model route")
    if expected_commit is not None and (not isinstance(expected_commit, str) or not _COMMIT.match(expected_commit)):
        raise AdapterError("config.expected_harness_commit must be a full 40-character commit id")
    expected_pi = config.get("expected_pi_version", None if synthetic else DEFAULT_IMAGE_PI_VERSION)
    if not synthetic and expected_pi is None:
        raise AdapterError("config.expected_pi_version cannot be null on the real model route")
    if expected_pi is not None and (not isinstance(expected_pi, str) or not expected_pi.strip()):
        raise AdapterError("config.expected_pi_version must be a version string")
    calls = config.get("synthetic_tool_calls")
    if calls is not None:
        if not synthetic:
            raise AdapterError("config.synthetic_tool_calls applies only to the synthetic diagnostic model route")
        if (not isinstance(calls, list) or len(calls) > 16
                or not all(isinstance(call, dict) and set(call) <= {"name", "arguments"}
                           and isinstance(call.get("name"), str) and isinstance(call.get("arguments", {}), dict)
                           for call in calls)):
            raise AdapterError("config.synthetic_tool_calls must be at most 16 {name, arguments} objects")
    return {"synthetic": synthetic, "provider": "scaneval-synthetic" if synthetic else provider,
            "model_id": model_id, "model": model, "thinking": thinking, "auth_env": auth_env, "search": search,
            "preflight": preflight, "paths": paths, "expected_commit": expected_commit,
            "expected_pi": expected_pi.strip() if isinstance(expected_pi, str) else None,
            "tool_calls": list(calls or [])}


def _receipt_value(receipt: Any, *paths: tuple[str, ...]) -> str | None:
    """The first string at any of *paths* in the image's runtime receipt, or ``None``."""
    for path in paths:
        value = receipt
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def read_tool_journal(directory: Path, enclosure: "Enclosure") -> tuple[list[dict], dict[str, Any], list[str]]:
    """The research extension's journal files: artifacts to register, a summary, and notes.

    Written by code inside the scanner container, so it is read like every other path the scanner
    owns: listed with the one listing, each entry a regular file proved in the same open that reads
    it, and the whole directory contained in this run's raw output. What it says is the extension's
    own account of what it registered and what each tool returned; it is availability and execution
    evidence, never evidence of what a model consumed.
    """
    artifacts: list[dict] = []
    notes: list[str] = []
    summary: dict[str, Any] = {"files": 0, "loaded": [], "tools": {}, "unreadable": 0, "malformed": 0}
    if enclosure.write(directory) is None:
        notes.append("the research tool journal does not resolve inside this run's raw output; it was not read")
        summary["unreadable"] += 1
        return artifacts, summary, notes
    try:
        entries = list_directory(directory)
    except FileNotFoundError:
        return artifacts, summary, notes
    except OSError as exc:
        notes.append(f"the research tool journal could not be listed ({exc.strerror or exc})")
        summary["unreadable"] += 1
        return artifacts, summary, notes
    for entry in sorted(entries, key=lambda item: item.name)[:MAX_JOURNAL_FILES]:
        path = Path(entry.path)
        if not re.fullmatch(r"pi-[0-9]+-[0-9a-f]{12}\.jsonl", entry.name):
            summary["unreadable"] += 1
            notes.append("the research tool journal holds an unexpected entry; it was not read")
            continue
        data, failure = read_record(path, enclosure.write(path))
        if data is None:
            summary["unreadable"] += 1
            notes.append(f"a research tool journal file could not be read ({failure})")
            continue
        summary["files"] += 1
        artifacts.append({"id": f"open-context-tools/{entry.name}", "path": path})
        for line in data.decode("utf-8", errors="replace").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                summary["malformed"] += 1
                continue
            if not isinstance(record, dict):
                summary["malformed"] += 1
            elif record.get("event") == "loaded" and isinstance(record.get("tools"), list):
                summary["loaded"].append(sorted(str(name) for name in record["tools"]))
            elif record.get("event") == "tool" and isinstance(record.get("tool"), str):
                outcomes = summary["tools"].setdefault(record["tool"], {})
                outcome = str(record.get("outcome") or "unknown")
                outcomes[outcome] = outcomes.get(outcome, 0) + 1
    if len(entries) > MAX_JOURNAL_FILES:
        notes.append(f"the research tool journal holds {len(entries)} files; only the first {MAX_JOURNAL_FILES} were read")
    return artifacts, summary, notes


def _counts(value: Any) -> dict[str, int]:
    """A ``{name: count}`` table the driver reported, keeping only entries this can read."""
    if not isinstance(value, dict):
        return {}
    return {str(key): count for key, count in value.items()
            if isinstance(count, int) and not isinstance(count, bool) and count >= 0}


def _listed(table: dict[str, int]) -> str:
    return ", ".join(f"{name} x{count}" for name, count in sorted(table.items())) or "none"


def image_tools(settings: dict[str, Any]) -> list[str]:
    """The exact tool allowlist the image route declares to the model."""
    return ["scaneval_fetch", *(["scaneval_search"] if settings["search"] else []), "scaneval_git", "scaneval_read"]


def image_run_account(image: dict[str, Any], output: Any,
                      journal: dict[str, Any]) -> tuple[list[str], dict[str, str] | None, dict[str, str]]:
    """Notes, a failure if any, and tool versions for one image-runtime run, from what it reported.

    The failure is ``error`` when what ran is not what the system pins (a different harness commit
    or Pi version than configured, or a model other than the pinned one addressed), and ``partial``
    when the research tools the condition depends on were not shown available in every Pi process.
    Tool availability, tool execution and model consumption are kept as three separate statements:
    the extension's journal shows the first, Pi's own JSON stream the second, and nothing here the
    third.
    """
    out = output if isinstance(output, dict) else {}
    runtime = out.get("runtime") if isinstance(out.get("runtime"), dict) else {}
    route = out.get("pi_route") if isinstance(out.get("pi_route"), dict) else {}
    calls = out.get("pi_calls") if isinstance(out.get("pi_calls"), dict) else {}
    receipt = runtime.get("receipt")
    commit = _receipt_value(receipt, ("harness_commit",), ("harness", "commit"))
    package = _receipt_value(receipt, ("harness_package_version",), ("harness", "package_version"))
    pi_receipt = _receipt_value(receipt, ("pi_version",), ("pi", "version"))
    node_receipt = _receipt_value(receipt, ("node_version",), ("node", "version"))
    pi_observed = runtime.get("pi_version") if isinstance(runtime.get("pi_version"), str) else None
    node_observed = runtime.get("node_version") if isinstance(runtime.get("node_version"), str) else None
    files = runtime.get("files") if isinstance(runtime.get("files"), dict) else {}
    versions = {"runtime": "oci_image", "harness": f"securevibes-agent@{commit or 'unknown'}",
                "harness_package": str(package), "pi": pi_observed or pi_receipt or "unknown",
                "node": node_observed or node_receipt or "unknown"}
    for role in (*IMAGE_ADAPTER_FILES, "synthetic_provider"):
        entry = files.get(role)
        if isinstance(entry, dict) and isinstance(entry.get("sha256"), str):
            versions["driver_sha256" if role == "driver" else f"pi_{role}"] = entry["sha256"]
    notes: list[str] = []
    errors: list[str] = []
    partial: list[str] = []
    if not image["synthetic"]:
        if not runtime:
            errors.append("the driver reported no image runtime identity")
        if not isinstance(receipt, dict) or not receipt or runtime.get("receipt_error"):
            errors.append("the image runtime receipt is missing or unreadable")
        if not route:
            errors.append("the driver reported no Pi route")
        adapters = receipt.get("adapters") if isinstance(receipt, dict) else None
        adapters = adapters if isinstance(adapters, dict) else {}
        for role, name in IMAGE_ADAPTER_FILES.items():
            try:
                expected_digest = "sha256:" + hashlib.sha256(DRIVER.with_name(name).read_bytes()).hexdigest()
            except OSError:
                errors.append(f"the host adapter file {name} could not be read for identity verification")
                continue
            versions[f"host_{role}_sha256"] = expected_digest
            entry = files.get(role)
            reported_digest = entry.get("sha256") if isinstance(entry, dict) else None
            if reported_digest != expected_digest:
                errors.append(f"runtime.files.{role} digest is missing or differs from the host's {name}")
            if adapters.get(name) != expected_digest:
                errors.append(f"runtime receipt adapters.{name} digest is missing or differs from the host")
    else:
        notes.append("DIAGNOSTIC: synthetic runs do not attest host/image adapter code identity.")
    if not runtime:
        notes.append("The driver reported no image runtime identity, so which harness, Pi and Node ran is unknown.")
    else:
        if receipt is None:
            notes.append(f"The image's runtime receipt was not read ({runtime.get('receipt_error') or 'no reason'}); "
                         "the harness commit and package version are unknown.")
        notes.append(f"Image runtime: harness commit {commit or 'unknown'} (package {package or 'unknown'}) per the "
                     f"image receipt; Pi {pi_observed or 'unknown'} as the binary reported it (receipt: "
                     f"{pi_receipt or 'none'}); Node {node_observed or 'unknown'} as the driver process reported it "
                     f"(receipt: {node_receipt or 'none'}). Digests of the driver, runner and extension files the "
                     "driver loaded are recorded with the tool versions.")
    if image["expected_commit"] and commit != image["expected_commit"]:
        errors.append(f"the image's harness commit is {commit or 'unknown'}, not the configured "
                      f"{image['expected_commit']}")
    if pi_observed and pi_receipt and pi_receipt != pi_observed.strip():
        errors.append(f"the Pi binary reports {pi_observed!r}, which contradicts the image receipt's {pi_receipt!r}")
    if image["expected_pi"] and (pi_receipt != image["expected_pi"]
                                  or (pi_observed or "").strip() != image["expected_pi"]):
        errors.append(f"Pi binary {pi_observed or 'unknown'} and receipt {pi_receipt or 'unknown'} do not both "
                      f"match the configured {image['expected_pi']}")
    declared = route.get("tools")
    expected_tools = image_tools(image)
    if route and declared != expected_tools:
        errors.append(f"the driver declared the tools {declared!r}, not the configured allowlist {expected_tools!r}")
    if not route:
        notes.append("The driver reported no Pi route, so the tools and reasoning level it applied are unknown.")
    else:
        notes.append(f"Requested model route {image['model']} with reasoning level {image['thinking']} on every call; "
                     f"declared tools {', '.join(expected_tools)} and nothing else.")
    addressed = _counts(calls.get("models_addressed"))
    providers = _counts(calls.get("providers_addressed"))
    unexpected = sorted(set(addressed) - {image["model_id"], "unknown"}) + sorted(
        set(providers) - {image["provider"], "unknown"})
    if unexpected:
        errors.append("Pi reported addressing a provider or model other than the pinned route: " + ", ".join(unexpected))
    pi_count = calls.get("calls") if isinstance(calls.get("calls"), int) else 0
    loaded = [entry for entry in journal.get("loaded", []) if isinstance(entry, list)]
    if pi_count and not loaded:
        partial.append(f"Pi ran {pi_count} time(s) but the research extension journaled no tool registration, so "
                       "research tool availability is not established")
    short = [sorted(set(expected_tools) - set(entry)) for entry in loaded if set(expected_tools) - set(entry)]
    if short:
        partial.append(f"{len(short)} Pi process(es) registered without {', '.join(short[0])}, so the research tools "
                       "were not available to every model call")
    if loaded:
        notes.append(f"Tool availability: the research extension reported registering its tools in {len(loaded)} Pi "
                     f"process(es), across {pi_count} Pi invocation(s) counting retries. That is the extension's own "
                     "account of what it offered, not of what the model did.")
    executions = calls.get("tool_executions") if isinstance(calls.get("tool_executions"), dict) else {}
    executed = ", ".join(f"{name} ok={entry.get('ok')} error={entry.get('error')}" for name, entry in sorted(executions.items())
                         if isinstance(entry, dict)) or "none"
    journaled = ", ".join(f"{tool} " + "/".join(f"{outcome}={count}" for outcome, count in sorted(outcomes.items()))
                          for tool, outcomes in sorted((journal.get("tools") or {}).items())) or "none"
    notes.append(f"Tool execution: Pi's JSON stream reported {executed}; the extension journaled {journaled}. Neither "
                 "shows that fetched content or history entered a model request or shaped a finding: retrieval is "
                 "recorded by the proxy, and model consumption stays unverifiable.")
    research = route.get("research") if isinstance(route.get("research"), dict) else {}
    preflight = research.get("preflight")
    if isinstance(preflight, dict):
        notes.append(f"Research transport preflight (the driver, before any model call; not model research): "
                     f"{preflight.get('url')} -> {preflight.get('outcome')} "
                     f"(retrieval event {preflight.get('retrieval_event_id')}).")
    overridden = calls.get("thinking_overridden")
    if isinstance(overridden, int) and overridden:
        notes.append(f"{overridden} harness call(s) asked for another reasoning level; each ran at the pinned "
                     f"{image['thinking']}.")
    replaced = _counts(calls.get("replaced_stage_flags"))
    if replaced:
        notes.append(f"Stage flags replaced by the route's explicit tool policy: {_listed(replaced)}.")
    unparsed = calls.get("unparsed_stream_records")
    if isinstance(unparsed, int) and unparsed:
        notes.append(f"{unparsed} record(s) of Pi's JSON stream could not be parsed; the call outcomes still come "
                     "from the last parsed assistant message.")
    credential = route.get("credential") if isinstance(route.get("credential"), dict) else {}
    if not image["synthetic"]:
        if credential.get("removed") is True:
            notes.append(f"The {image['provider']} OAuth credential arrived through the container environment and "
                         "was copied into its private Pi agent directory, which was removed when the scan ended. "
                         "The driver removed the variable before starting child processes; this does not erase "
                         "its initial process environment from OS inspection. No value is recorded.")
        else:
            notes.append(f"The private Pi agent directory holding the {image['provider']} credential was not shown "
                         "removed; it lived on the container's private /tmp, which ends with the container.")
    stops = _counts(calls.get("stop_reasons"))
    if stops:
        notes.append(f"Pi stop reasons over {pi_count} invocation(s): {_listed(stops)}.")
    failure = None
    if errors:
        failure = {"status": "error", "code": "runtime_mismatch", "message": "; ".join(errors)[:2000]}
    elif partial:
        failure = {"status": "partial", "code": "research_tools_unavailable", "message": "; ".join(partial)[:2000]}
    return notes, failure, versions


COMPLETION_COVERAGE = ("complete", "incomplete", "unknown", "not-required")
REVIEW_WORKFLOW_STATUSES = ("complete", "incomplete", "unknown", "not-required")
REVIEW_WORKFLOW_MODES = ("bootstrap", "pr", "batch")
REVIEW_WORKFLOW_PROCEDURES = frozenset({
    "security-review", "category:rails-initializer", "category:rails-routes",
    "category:configuration", "category:convention-dsl",
})
REVIEW_WORKFLOW_MAX_FILES = 50_000
REVIEW_WORKFLOW_MAX_RECEIPTS = 100_000
REVIEW_WORKFLOW_MAX_FILE_BYTES = 8 * 1024 * 1024
REVIEW_WORKFLOW_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_HASH40 = re.compile(r"^[a-f0-9]{40}$")
_HASH64 = re.compile(r"^[a-f0-9]{64}$")


class ReviewWorkflowReading(NamedTuple):
    """One parsed native workflow report, without upgrading its evidence claims."""

    present: bool
    status: str | None
    report: dict[str, Any] | None
    notes: list[str]
    code: str | None
    message: str | None


def _wire_count(value: Any, maximum: int = 2**53 - 1) -> bool:
    return type(value) is int and 0 <= value <= maximum


def _wire_text(value: Any, *, maximum: int = 10_000) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and "\x00" not in value


def _workflow_path(value: Any) -> bool:
    if not _wire_text(value, maximum=60_000) or value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", value):
        return False
    return "\\" not in value and value not in (".", "..") and ".." not in value.split("/")


def _unique_texts(value: Any, *, maximum: int, item_maximum: int = 10_000) -> bool:
    return (isinstance(value, list) and len(value) <= maximum
            and all(_wire_text(item, maximum=item_maximum) for item in value)
            and len(set(value)) == len(value))


def _procedures(value: Any, *, required: bool) -> bool:
    return (_unique_texts(value, maximum=16, item_maximum=100)
            and (not required or bool(value))
            and all(item in REVIEW_WORKFLOW_PROCEDURES for item in value)
            and (not required or "security-review" in value))


def _workflow_identity(value: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    return value.get("invocationId"), value.get("model"), value.get("hypothesisId"), value.get("shardIndex")


def _workflow_file_identity(value: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    procedures = value.get("requiredProcedures")
    return value.get("path"), value.get("sha256"), value.get("bytes"), tuple(procedures) if isinstance(procedures, list) else None


def _review_workflow_shape(report: Any) -> list[str]:
    """Validate the closed v1 values and bounded repeated records; return terse defects."""
    issues: list[str] = []

    def issue(name: str) -> None:
        if name not in issues and len(issues) < 50:
            issues.append(name)

    if not isinstance(report, dict):
        return ["report_not_object"]
    if type(report.get("schemaVersion")) is not int or report.get("schemaVersion") != 1:
        issue("schema_version")
    if report.get("workflow") != "bootstrap-source-review":
        issue("workflow")
    if report.get("status") not in REVIEW_WORKFLOW_STATUSES:
        issue("status")
    if report.get("sourceAssessment") != "unassessed":
        issue("source_assessment")
    scope = report.get("scope")
    if (not isinstance(scope, dict) or scope.get("mode") not in REVIEW_WORKFLOW_MODES
            or scope.get("policy") != "bootstrap-source-review/v1"):
        issue("scope")
    elif ("repository" in scope and not _wire_text(scope.get("repository"), maximum=60_000)):
        issue("scope_repository")
    elif ("sourceRef" in scope and not isinstance(scope.get("sourceRef"), str)) or (
            isinstance(scope.get("sourceRef"), str) and not _HASH40.fullmatch(scope["sourceRef"])):
        issue("scope_source_ref")
    elif ("inventoryDigest" in scope and not isinstance(scope.get("inventoryDigest"), str)) or (
            isinstance(scope.get("inventoryDigest"), str) and not _HASH64.fullmatch(scope["inventoryDigest"])):
        issue("scope_inventory_digest")
    inventory, obligations, receipts = (report.get(key) for key in ("inventory", "obligations", "receipts"))
    if not isinstance(inventory, list) or len(inventory) > REVIEW_WORKFLOW_MAX_FILES:
        issue("inventory")
        inventory = []
    if not isinstance(obligations, list) or len(obligations) > REVIEW_WORKFLOW_MAX_RECEIPTS:
        issue("obligations")
        obligations = []
    if not isinstance(receipts, list) or len(receipts) > REVIEW_WORKFLOW_MAX_RECEIPTS:
        issue("receipts")
        receipts = []
    reasons = report.get("reasons")
    if not _unique_texts(reasons, maximum=REVIEW_WORKFLOW_MAX_RECEIPTS, item_maximum=10_000):
        issue("reasons")
    stages = report.get("stages")
    stage_values = {
        "modelCalls": {"complete", "incomplete", "not-recorded"},
        "structural": {"complete", "incomplete", "not-applicable", "not-recorded"},
        "lint": {"complete", "incomplete", "not-recorded"},
        "markers": {"complete", "incomplete", "not-recorded"},
        "specialists": {"complete", "incomplete", "not-recorded"},
    }
    if not isinstance(stages, dict) or any(stages.get(name) not in values for name, values in stage_values.items()):
        issue("stages")

    inventory_paths: set[str] = set()
    total_bytes = 0
    for entry in inventory:
        if not isinstance(entry, dict):
            issue("inventory_entry")
            continue
        path, disposition = entry.get("path"), entry.get("disposition")
        if not _workflow_path(path) or path in inventory_paths:
            issue("inventory_path")
        elif isinstance(path, str):
            inventory_paths.add(path)
        if (not isinstance(entry.get("sourceRef"), str) or not _HASH40.fullmatch(entry["sourceRef"])
                or not isinstance(entry.get("objectId"), str) or not _HASH40.fullmatch(entry["objectId"])
                or disposition not in ("supported", "excluded", "unsupported", "unassigned")
                or not _wire_text(entry.get("reason"), maximum=10_000)):
            issue("inventory_identity")
        requires_source = disposition in ("supported", "unassigned")
        if requires_source:
            if (not isinstance(entry.get("sha256"), str) or not _HASH64.fullmatch(entry["sha256"])
                    or not _wire_count(entry.get("bytes"), REVIEW_WORKFLOW_MAX_FILE_BYTES)
                    or not _procedures(entry.get("requiredProcedures"), required=True)):
                issue("inventory_source")
            elif isinstance(entry.get("bytes"), int):
                total_bytes += entry["bytes"]
        elif (entry.get("sha256") is not None or entry.get("bytes") is not None
              or not _procedures(entry.get("requiredProcedures"), required=False)
              or entry.get("requiredProcedures")):
            issue("inventory_non_source")
    if total_bytes > REVIEW_WORKFLOW_MAX_TOTAL_BYTES:
        issue("inventory_total_bytes")

    obligation_ids: set[tuple[Any, Any, Any, Any]] = set()
    for obligation in obligations:
        if not isinstance(obligation, dict):
            issue("obligation_entry")
            continue
        identity = _workflow_identity(obligation)
        if (not all(_wire_text(value, maximum=1_000) for value in identity[:3])
                or not _wire_count(identity[3]) or identity[3] < 1
                or not isinstance(obligation.get("sourceRef"), str) or not _HASH40.fullmatch(obligation["sourceRef"])):
            issue("obligation_identity")
        if identity in obligation_ids:
            issue("duplicate_obligation")
        obligation_ids.add(identity)
        if "requestDigest" in obligation and (not isinstance(obligation.get("requestDigest"), str)
                                               or not _HASH64.fullmatch(obligation["requestDigest"])):
            issue("obligation_request_digest")
        files = obligation.get("files")
        if not isinstance(files, list) or not files or len(files) > REVIEW_WORKFLOW_MAX_FILES:
            issue("obligation_files")
            continue
        paths: set[str] = set()
        for file in files:
            if (not isinstance(file, dict) or not _workflow_path(file.get("path")) or file.get("path") in paths
                    or not isinstance(file.get("sha256"), str) or not _HASH64.fullmatch(file["sha256"])
                    or not _wire_count(file.get("bytes"), REVIEW_WORKFLOW_MAX_FILE_BYTES)
                    or not _procedures(file.get("requiredProcedures"), required=True)):
                issue("obligation_file")
            elif isinstance(file.get("path"), str):
                paths.add(file["path"])

    receipt_ids: set[tuple[Any, Any, Any, Any]] = set()
    for receipt in receipts:
        if not isinstance(receipt, dict):
            issue("receipt_entry")
            continue
        identity = _workflow_identity(receipt)
        if (receipt.get("schemaVersion") != 1 or not all(_wire_text(value, maximum=1_000) for value in identity[:3])
                or not _wire_count(identity[3]) or identity[3] < 1
                or not isinstance(receipt.get("sourceRef"), str) or not _HASH40.fullmatch(receipt["sourceRef"])
                or not isinstance(receipt.get("requestDigest"), str) or not _HASH64.fullmatch(receipt["requestDigest"])
                or not isinstance(receipt.get("responseDigest"), str) or not _HASH64.fullmatch(receipt["responseDigest"])):
            issue("receipt_identity")
        if identity in receipt_ids:
            issue("duplicate_receipt")
        receipt_ids.add(identity)
        files = receipt.get("files")
        if not isinstance(files, list) or not files or len(files) > REVIEW_WORKFLOW_MAX_FILES:
            issue("receipt_files")
            continue
        paths: set[str] = set()
        for file in files:
            if (not isinstance(file, dict) or not _workflow_path(file.get("path")) or file.get("path") in paths
                    or not isinstance(file.get("sha256"), str) or not _HASH64.fullmatch(file["sha256"])
                    or not _wire_count(file.get("bytes"), REVIEW_WORKFLOW_MAX_FILE_BYTES)
                    or not _procedures(file.get("requiredProcedures"), required=True)):
                issue("receipt_file")
                continue
            paths.add(file["path"])
            terminals = file.get("terminals")
            if not isinstance(terminals, list) or len(terminals) > 16:
                issue("terminals")
                continue
            seen: set[str] = set()
            for terminal in terminals:
                if (not isinstance(terminal, dict) or terminal.get("procedure") not in REVIEW_WORKFLOW_PROCEDURES
                        or terminal.get("procedure") in seen
                        or terminal.get("status") not in ("completed", "inconclusive")
                        or not _wire_text(terminal.get("reason"), maximum=1_000)):
                    issue("terminal")
                elif isinstance(terminal.get("procedure"), str):
                    seen.add(terminal["procedure"])
            if seen != set(file["requiredProcedures"]):
                issue("terminal_coverage")
    return issues


def _review_workflow_reconciliation(summary: dict[str, Any], report: dict[str, Any]) -> list[str]:
    """Reconcile a structurally valid positive report with its inventory and original stages."""
    issues: list[str] = []

    def issue(name: str) -> None:
        if name not in issues and len(issues) < 50:
            issues.append(name)

    scope = report["scope"]
    source_ref = scope.get("sourceRef")
    if summary.get("mode") != scope.get("mode"):
        issue("mode_mismatch")
    if scope.get("mode") != "bootstrap":
        issue("unsupported_mode")
    if summary.get("consensus") is not None:
        issue("unsupported_consensus")
    if not all(key in scope for key in ("repository", "sourceRef", "inventoryDigest")):
        issue("scope_metadata_missing")
    if summary.get("headRef") != source_ref:
        issue("head_ref_mismatch")
    if isinstance(summary.get("repoPath"), str) and summary.get("repoPath") != scope.get("repository"):
        issue("repository_mismatch")
    inventory = report["inventory"]
    by_path = {entry["path"]: entry for entry in inventory}
    if not inventory:
        issue("empty_inventory")
    if any(entry["sourceRef"] != source_ref for entry in inventory):
        issue("inventory_source_ref_mismatch")
    supported = {path: entry for path, entry in by_path.items() if entry["disposition"] in ("supported", "unassigned")}
    if any(entry["disposition"] in ("unsupported", "unassigned") for entry in inventory):
        issue("inventory_gap")

    obligations = report["obligations"]
    observed_assignments: dict[tuple[str, str, int, str], int] = {}
    obligation_by_id = {_workflow_identity(item): item for item in obligations}
    for obligation in obligations:
        if obligation["sourceRef"] != source_ref or "requestDigest" not in obligation:
            issue("obligation_binding")
        for file in obligation["files"]:
            entry = supported.get(file["path"])
            if entry is None or _workflow_file_identity(file) != _workflow_file_identity(entry):
                issue("obligation_source_mismatch")
            key = (obligation["model"], obligation["hypothesisId"], obligation["shardIndex"], file["path"])
            observed_assignments[key] = observed_assignments.get(key, 0) + 1
    if any(not any(file["path"] == path for obligation in obligations for file in obligation["files"])
           for path in supported):
        issue("unassigned_inventory")
    models = {obligation["model"] for obligation in obligations}
    if len(models) > 1:
        issue("multiple_models")

    receipt_by_id = {_workflow_identity(item): item for item in report["receipts"]}
    if set(receipt_by_id) != set(obligation_by_id):
        issue("receipt_set_mismatch")
    for identity, obligation in obligation_by_id.items():
        receipt = receipt_by_id.get(identity)
        if receipt is None:
            continue
        if (receipt["sourceRef"] != obligation["sourceRef"]
                or receipt["requestDigest"] != obligation.get("requestDigest")
                or [_workflow_file_identity(item) for item in receipt["files"]]
                != [_workflow_file_identity(item) for item in obligation["files"]]):
            issue("receipt_binding_mismatch")
        if any(terminal["status"] != "completed" for file in receipt["files"] for terminal in file["terminals"]):
            issue("inconclusive_terminal")

    scan = summary.get("bootstrapScan")
    expected_assignments: dict[tuple[str, str, int, str], int] = {}
    if not isinstance(scan, dict):
        issue("bootstrap_scan_missing")
    else:
        if scan.get("status") != "ok" or scan.get("failedCalls") != 0 or scan.get("quotaFailureCount") != 0:
            issue("bootstrap_scan_incomplete")
        counts = [scan.get(key) for key in ("hypothesesPlanned", "hypothesesEvaluated")]
        if not all(_wire_count(value) for value in counts) or counts[0] != counts[1]:
            issue("hypothesis_counts")
        if scan.get("hypothesisCoverage") != 1:
            issue("hypothesis_coverage")
        if not _unique_texts(scan.get("failedHypothesisIds"), maximum=REVIEW_WORKFLOW_MAX_RECEIPTS) or scan.get("failedHypothesisIds"):
            issue("failed_hypotheses")
        if not _unique_texts(scan.get("unevaluatedHypothesisIds"), maximum=REVIEW_WORKFLOW_MAX_RECEIPTS) or scan.get("unevaluatedHypothesisIds"):
            issue("unevaluated_hypotheses")
        selections = scan.get("hypothesisSelections")
        if not isinstance(selections, list) or len(selections) > REVIEW_WORKFLOW_MAX_RECEIPTS:
            issue("hypothesis_selections")
            selections = []
        for selection in selections:
            if not isinstance(selection, dict) or not _wire_text(selection.get("model"), maximum=1_000) or not _wire_text(selection.get("hypothesisId"), maximum=1_000):
                issue("hypothesis_selection_identity")
                continue
            failures = selection.get("relationshipExtractionFailures", [])
            truncated = selection.get("relationshipExtractionFailuresTruncated", 0)
            if not isinstance(failures, list) or failures or not _wire_count(truncated) or truncated:
                issue("relationship_source_gap")
            coverage = selection.get("fileCoverage")
            if not isinstance(coverage, dict):
                issue("file_coverage_missing")
                continue
            if (coverage.get("hypothesisId") != selection["hypothesisId"] or coverage.get("coverage") != "complete"
                    or coverage.get("partialFiles") != [] or coverage.get("omittedAssignedFiles") != []):
                issue("file_coverage_incomplete")
            calls = coverage.get("calls")
            if not isinstance(calls, list) or len(calls) > REVIEW_WORKFLOW_MAX_RECEIPTS:
                issue("file_calls")
                continue
            for call in calls:
                if not isinstance(call, dict) or not _wire_count(call.get("shardIndex")) or call["shardIndex"] < 1:
                    issue("file_call_identity")
                    continue
                requested, delivered = call.get("requestedFiles"), call.get("deliveredFiles")
                if (not _unique_texts(requested, maximum=REVIEW_WORKFLOW_MAX_FILES, item_maximum=60_000)
                        or not _unique_texts(delivered, maximum=REVIEW_WORKFLOW_MAX_FILES, item_maximum=60_000)
                        or set(requested) != set(delivered) or call.get("partialFiles") != []
                        or call.get("omittedFiles") != [] or call.get("transport") != "succeeded"):
                    issue("file_call_incomplete")
                    continue
                for path in requested:
                    if path in supported:
                        key = (selection["model"], selection["hypothesisId"], call["shardIndex"], path)
                        expected_assignments[key] = expected_assignments.get(key, 0) + 1
    if expected_assignments != observed_assignments:
        issue("assignment_mismatch")

    stages = report["stages"]
    if stages != {"modelCalls": "complete", "structural": "not-applicable", "lint": "complete",
                  "markers": "complete", "specialists": "complete"}:
        issue("stage_incomplete")
    lint = summary.get("repositoryLint")
    if (not isinstance(lint, dict) or lint.get("status") != "ok" or lint.get("failures") != 0
            or any(rule.get("status") != "ok" or rule.get("failures", 0) or rule.get("baseFailures", 0)
                   for rule in summary.get("repositoryLintRules", []) if isinstance(rule, dict))):
        issue("lint_incomplete")
    marker = summary.get("reviewAssessment")
    if not isinstance(marker, dict) or marker.get("status") != "none-pending" or any(
            marker.get(key) != 0 for key in ("pendingReviews", "pendingSites", "pendingInspectionGaps")):
        issue("markers_incomplete")
    activated = summary.get("specialistsActivated")
    scans = summary.get("specialistScans", [])
    if not isinstance(activated, list) or not isinstance(scans, list):
        issue("specialists_malformed")
    else:
        by_id = {item.get("id"): item for item in scans if isinstance(item, dict) and isinstance(item.get("id"), str)}
        for activation in activated:
            specialist_id = activation.get("id") if isinstance(activation, dict) else None
            specialist = by_id.get(specialist_id)
            if (specialist is None or specialist.get("status") != "ok" or specialist.get("assessmentStatus") == "not-assessed"
                    or specialist.get("failedCalls", 0) != 0 or specialist.get("quotaFailureCount", 0) != 0):
                issue("specialist_incomplete")
    return issues


def read_review_workflow(summary: Any) -> ReviewWorkflowReading:
    """Read and reconcile ``summary.reviewWorkflow`` without treating it as source safety."""
    if not isinstance(summary, dict) or "reviewWorkflow" not in summary:
        return ReviewWorkflowReading(False, None, None, [], None, None)
    report = summary.get("reviewWorkflow")
    shape = _review_workflow_shape(report)
    if shape:
        shown = ", ".join(shape[:10])
        return ReviewWorkflowReading(True, None, None, [], "review_workflow_malformed",
                                     f"the harness review-workflow report is malformed ({shown})")
    assert isinstance(report, dict)
    status = report["status"]
    reasons = report["reasons"]
    shown = ", ".join(reasons[:20]) + (f", and {len(reasons) - 20} more" if len(reasons) > 20 else "")
    notes = [f"Harness review workflow v1: {status}"
             + (f" ({shown})" if reasons else "")
             + "; native producer-declared receipts bind source, request, response, and terminal records, "
               "but do not assess the source as safe or attest a provider/model revision."]
    if status in ("complete", "not-required"):
        reconciliation = _review_workflow_reconciliation(summary, report)
        if status == "complete":
            if not any(entry["disposition"] == "supported" for entry in report["inventory"]):
                reconciliation.append("no_supported_inventory")
            if reasons:
                reconciliation.append("positive_status_has_reasons")
        else:
            if (not report["inventory"] or any(entry["disposition"] != "excluded" for entry in report["inventory"])
                    or report["obligations"] or report["receipts"] or reasons):
                reconciliation.append("not_required_scope")
            # Exclusion-only scope has no assignments to reconcile with bootstrap hypotheses.
            reconciliation = [item for item in reconciliation if item not in {
                "bootstrap_scan_missing", "assignment_mismatch", "stage_incomplete", "no_supported_inventory"}]
        if reconciliation:
            shown_reconciliation = ", ".join(dict.fromkeys(reconciliation))
            return ReviewWorkflowReading(True, status, report, notes, "review_workflow_malformed",
                                         f"the harness review-workflow report contradicts its positive status ({shown_reconciliation})")
        if status == "complete":
            notes.append("Accepted scope: completed declared bootstrap review workflow; source assessment remains unassessed.")
        else:
            notes.append("Accepted scope: the immutable inventory contains only explicit exclusions, so this workflow was not required.")
        return ReviewWorkflowReading(True, status, report, notes, None, None)
    if not reasons:
        return ReviewWorkflowReading(True, status, report, notes, "review_workflow_malformed",
                                     "the harness review-workflow report has a non-positive status without a reason")
    return ReviewWorkflowReading(True, status, report, notes, f"review_workflow_{status}",
                                 f"the harness reports its declared review workflow {status}: {shown}")


def _valid_completion(completion: Any) -> bool:
    """Check the pinned ScanCompletionReport/ModelCallHealth wire shape and arithmetic.

    This reads native reporting only; it does not reconstruct or change engine decisions.
    Unknown enum values never acquire success by looking like a truthy status string.
    """
    def count(value: Any) -> bool:
        return type(value) is int and 0 <= value <= 2**53 - 1

    def strings(value: Any) -> bool:
        return isinstance(value, list) and all(isinstance(item, str) for item in value)

    if not isinstance(completion, dict) or type(completion.get("schemaVersion")) is not int or completion["schemaVersion"] != 1:
        return False
    if completion.get("execution") != {"status": "completed", "evidence": "engine-returned-summary"}:
        return False
    calls, coverage = completion.get("modelCalls"), completion.get("coverage")
    if (not isinstance(calls, dict) or not isinstance(coverage, dict)
            or calls.get("unit") != "logical-invocations" or calls.get("transportAttempts") != "not-recorded"
            or not all(count(calls.get(key)) for key in ("attempted", "succeeded", "failed", "pending", "truncatedFailureSamples"))
            or coverage.get("status") not in COMPLETION_COVERAGE or not strings(coverage.get("reasons"))):
        return False
    if calls["attempted"] != calls["succeeded"] + calls["failed"] + calls["pending"]:
        return False
    expected = "failures-recorded" if calls["failed"] else "no-recorded-failures" if calls["attempted"] else "not-run"
    samples = calls.get("failureSamples")
    if (calls.get("status") != expected or not isinstance(samples, list) or len(samples) > 20
            or calls["failed"] != len(samples) + calls["truncatedFailureSamples"]):
        return False
    seen = set()
    for sample in samples:
        if (not isinstance(sample, dict) or not count(sample.get("callId"))
                or not 1 <= sample["callId"] <= calls["attempted"] or sample["callId"] in seen
                or sample.get("phase") not in ("planning", "hypothesis-validation", "static-validation", "consensus-resolution", "mitigation-verification", "specialist")
                or sample.get("kind") not in ("nonzero-exit", "exception")
                or ("code" in sample and (type(sample["code"]) is not int or not -(2**53 - 1) <= sample["code"] <= 2**53 - 1
                                        or (sample["kind"] == "nonzero-exit" and sample["code"] == 0)))):
            return False
        seen.add(sample["callId"])
    # The remaining native sections carry the evidence underlying coverage. Validate their
    # public states and required counters/lists; retained sample details remain raw artifacts.
    sections = {
        "changedFileSupport": ("complete", "incomplete", "not-required", "not-recorded"),
        "structuralCoverage": ("complete", "incomplete", "not-recorded"),
        "lintCoverage": ("complete", "incomplete"),
        "hypothesisEvaluation": ("complete", "incomplete", "not-required", "not-recorded"),
        "sourceAssessment": ("unassessed", "not-recorded", "not-required"),
        "markerAssessment": ("pending", "none-pending", "not-recorded"),
    }
    for name, states in sections.items():
        if not isinstance(completion.get(name), dict) or completion[name].get("status") not in states:
            return False
    changed = completion["changedFileSupport"]
    if changed["status"] != "not-recorded":
        scope = changed.get("scope")
        if (not isinstance(scope, dict) or not all(count(scope.get(key)) for key in
                ("totalChangedFiles", "changedFilesInScope", "unsupportedChangedFiles", "excludedChangedFiles", "knownNonCodeChangedFiles", "unknownUnsupportedChangedFiles"))
                or not isinstance(scope.get("unsupportedExtensionHistogram"), dict)
                or not all(count(value) for value in scope["unsupportedExtensionHistogram"].values())):
            return False
        expected_scope = "incomplete" if scope["unknownUnsupportedChangedFiles"] else "complete" if scope["changedFilesInScope"] else "not-required"
        if changed["status"] != expected_scope:
            return False
    structural, lint = completion["structuralCoverage"], completion["lintCoverage"]
    hypotheses, source, marker = (completion[key] for key in ("hypothesisEvaluation", "sourceAssessment", "markerAssessment"))
    inspections = structural.get("planningInspections")
    if (not isinstance(inspections, dict) or not all(count(inspections.get(key)) for key in ("attempted", "parsed", "failed"))
            or inspections["attempted"] != inspections["parsed"] + inspections["failed"]
            or not all(count(structural.get(key)) for key in ("requiredInspectionFailures", "truncatedFailureSamples"))
            or not isinstance(structural.get("failureSamples"), list)
            or not count(lint.get("failures")) or not strings(lint.get("failureSamples")) or not strings(lint.get("inconclusiveRuleIds"))
            or not all(count(hypotheses.get(key)) for key in ("planned", "evaluated"))
            or not strings(hypotheses.get("failedIds")) or not strings(hypotheses.get("unevaluatedIds"))
            or not isinstance(source.get("files"), list)):
        return False
    for sample in structural["failureSamples"]:
        if (not isinstance(sample, dict) or not all(isinstance(sample.get(key), str) for key in ("path", "operation", "reason"))
                or "contentHash" not in sample or not (sample["contentHash"] is None or isinstance(sample["contentHash"], str))
                or sample.get("role") not in ("changed", "required-dependency", "unknown")
                or sample.get("origin") not in ("planning-discovery", "required-inspection")):
            return False
    for item in source["files"]:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str) or item.get("outcome") != "unassessed"
                or item.get("reason") not in ("analysis_completion_not_established", "not_fully_delivered")):
            return False
    if marker["status"] != "not-recorded":
        if (marker.get("scope") != "marker-reviews" or not isinstance(marker.get("ledgerPath"), str)
                or not all(count(marker.get(key)) for key in ("pendingReviews", "pendingSites", "pendingInspectionGaps", "carriedForwardReviews"))
                or (marker["status"] == "pending") != bool(marker["pendingReviews"])):
            return False
    if (coverage["status"] in ("complete", "not-required")) != (not coverage["reasons"]):
        return False
    # An internally contradictory positive aggregate is unreadable evidence, not success.
    if coverage["status"] in ("complete", "not-required"):
        if (marker["status"] == "not-recorded" or hypotheses["status"] == "not-recorded"
                or source["status"] == "not-recorded"
                or (coverage["status"] == "complete" and structural["status"] == "not-recorded")
                or any(completion[name]["status"] in ("incomplete", "pending", "unassessed") for name in sections)):
            return False
        if (lint["failures"] or lint["inconclusiveRuleIds"] or hypotheses["failedIds"] or hypotheses["unevaluatedIds"]
                or hypotheses["planned"] != hypotheses["evaluated"] or source["files"]
                or inspections["failed"] or structural["requiredInspectionFailures"] or structural["truncatedFailureSamples"]):
            return False
    return True


def _workflow_completion_consistent(completion: dict[str, Any], report: dict[str, Any]) -> bool:
    """Whether legacy unknown coverage is exactly the gap v1 intentionally leaves open."""
    allowed = {"source_analysis_completion_not_established", "structural_coverage_not_recorded"}
    coverage = completion["coverage"]
    if coverage["status"] != "unknown" or not coverage["reasons"] or not set(coverage["reasons"]) <= allowed:
        return False
    calls = completion["modelCalls"]
    if calls["status"] != "no-recorded-failures" or calls["failed"] or calls["pending"]:
        return False
    if completion["changedFileSupport"]["status"] != "not-recorded":
        return False
    structural = completion["structuralCoverage"]
    inspections = structural["planningInspections"]
    if (structural["status"] not in ("complete", "not-recorded") or inspections["failed"]
            or structural["requiredInspectionFailures"] or structural["failureSamples"]
            or structural["truncatedFailureSamples"]):
        return False
    lint, hypotheses = completion["lintCoverage"], completion["hypothesisEvaluation"]
    if (lint["status"] != "complete" or lint["failures"] or lint["failureSamples"] or lint["inconclusiveRuleIds"]
            or hypotheses["status"] != "complete" or hypotheses["planned"] != hypotheses["evaluated"]
            or hypotheses["failedIds"] or hypotheses["unevaluatedIds"]):
        return False
    marker, source = completion["markerAssessment"], completion["sourceAssessment"]
    if marker["status"] != "none-pending" or any(marker[key] for key in
                                                   ("pendingReviews", "pendingSites", "pendingInspectionGaps")):
        return False
    supported = {entry["path"] for entry in report["inventory"] if entry["disposition"] == "supported"}
    if (source["status"] != "unassessed" or {item["path"] for item in source["files"]} != supported
            or any(item["reason"] != "analysis_completion_not_established" for item in source["files"])):
        return False
    return report["stages"] == {"modelCalls": "complete", "structural": "not-applicable", "lint": "complete",
                                 "markers": "complete", "specialists": "complete"}


def read_completion(summary: Any, *, required: bool,
                    workflow: ReviewWorkflowReading | None = None) -> tuple[list[str], str | None, str | None]:
    """Read legacy completion and narrowly reconcile it with review-workflow v1 when present."""
    absent = not isinstance(summary, dict) or "completion" not in summary
    completion = summary.get("completion") if isinstance(summary, dict) else None
    if absent:
        if required:
            return ([], "completion_unavailable",
                    "the harness returned no completion report, so whether its scan is complete is unknown")
        return [], None, None
    if not _valid_completion(completion):
        return ([], "completion_malformed",
                "the harness completion report is not in a shape this adapter can read, so whether its scan is "
                "complete is unknown")
    coverage, calls = completion["coverage"], completion["modelCalls"]
    reasons = coverage["reasons"]
    counts = {key: calls[key] for key in ("attempted", "succeeded", "failed", "pending")}
    status = coverage["status"]
    shown = ", ".join(reasons[:20]) + (f", and {len(reasons) - 20} more" if len(reasons) > 20 else "")
    notes = [f"Harness completion report: assessment coverage {status}"
             + (f" ({shown})" if reasons else "") + f"; model calls {calls['status']} "
             f"({counts['succeeded']}/{counts['attempted']} succeeded, {counts['failed']} failed, "
             f"{counts['pending']} pending, counted per logical invocation)."]
    if calls["status"] == "failures-recorded" or counts["failed"] or counts["pending"]:
        return (notes, "completion_model_calls",
                f"the harness recorded {counts['failed']} failed and {counts['pending']} pending model call(s)")
    if workflow is not None and workflow.status == "complete" and workflow.code is None:
        if not isinstance(workflow.report, dict) or not _workflow_completion_consistent(completion, workflow.report):
            return (notes, "review_workflow_malformed",
                    "the completed review-workflow report contradicts the original completion stages")
        notes.append("Legacy source assessment remains unassessed and legacy coverage remains unknown only for the "
                     "versioned workflow's source-assessment and bootstrap structural-policy gaps; the completed "
                     "declared workflow is accepted separately, not as assessed-safe source.")
        return notes, None, None
    if status in ("incomplete", "unknown"):
        return notes, f"completion_{status}", f"the harness reports its assessment coverage {status}: {shown or 'no reason given'}"
    return notes, None, None


def image_model_identity(image: dict[str, Any], output: Any) -> dict[str, Any]:
    """Requested and observed model identity for the image route, without promoting either."""
    if image["synthetic"]:
        return {"requested": image["model"], "resolved": "synthetic-deterministic", "verification": "not_applicable",
                "notes": ["Synthetic in-process Pi provider; diagnostic only, no model was called."]}
    calls = output.get("pi_calls") if isinstance(output, dict) and isinstance(output.get("pi_calls"), dict) else {}
    addressed = _counts(calls.get("models_addressed"))
    providers = _counts(calls.get("providers_addressed"))
    notes = ["Pi names, in each assistant message, the provider and model it addressed. That is the client's own "
             "routing record, not the provider's statement of the model or revision it served, so no resolved "
             "model is recorded."]
    if addressed or providers:
        notes.append(f"Pi addressed models {_listed(addressed)} through providers {_listed(providers)}.")
    return {"requested": image["model"], "resolved": None, "verification": "unverified", "notes": notes}


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


def _native_scan_site(record: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Read a bounded native anchor; never infer one from a finding's prose."""
    encoded = record.get("scan_site_json_b64")
    if encoded is None:
        return None, None
    if not isinstance(encoded, str) or len(encoded) > 90_000:
        return None, "scan site is not a bounded base64 string"
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > 65_536:
            return None, "scan site exceeds 64 KiB"
        site = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None, "scan site could not be decoded"
    if not isinstance(site, dict):
        return None, "scan site is not an object"
    return site, None


class Enclosure(NamedTuple):
    """The two directories this adapter may touch once the harness has started, and the rule.

    ``workspace`` is the exported source the scanner was handed: every read after the harness
    process starts must resolve inside it. ``staging`` is this run's raw output directory: every
    copy destination must resolve inside that. Both are
    :class:`~scaneval.materialize.Containment`, which resolves the path whole, so a link anywhere
    along it is caught and not only one in the last component.

    That is the first difference this class exists for. The importer used to check each record
    for being a link and never its ancestors, so a link one level up, at the harness state
    directory or at any parent of it, left every record behind it looking like an ordinary
    regular file in an ordinary directory. Records from anywhere on the host were read, staged
    into the bundle, and imported as claims of this scan. Checking the last component is not a
    containment check; resolving the whole path is.

    The second is :meth:`capture`. Both directories have their real path read once, before the
    harness process starts, and every check afterwards is against those captured paths. The
    check used to resolve its own base on each call, after the harness had run, so a harness that
    replaced the workspace or the staging directory with a link moved the base along with the
    path and every comparison succeeded against a root it had chosen.
    """

    workspace: Containment
    staging: Containment

    @classmethod
    def capture(cls, workspace: Path, staging: Path) -> "Enclosure":
        """Read both directories' real paths now, before the harness process starts.

        A directory that cannot be resolved is an :class:`AdapterError` rather than a check that
        fails quietly later: without a captured path there is nothing to contain against, and the
        run must not start believing it has a boundary it does not have.
        """
        try:
            return cls(Containment.capture(workspace), Containment.capture(staging))
        except MaterializationError as exc:
            raise AdapterError(f"the scan boundary could not be established: {exc}") from exc

    def read(self, path: Path) -> Path | None:
        """*path* when it still resolves inside the workspace the scanner was handed, else ``None``."""
        return self.workspace.contains(path)

    def write(self, path: Path) -> Path | None:
        """*path* when it still resolves inside this run's staging directory, else ``None``."""
        return self.staging.contains(path)


class LostRecord(NamedTuple):
    """One finding record this scan produced that did not become a claim.

    ``name`` is the record's file name, or the findings path itself when nothing could be
    listed. ``finding_id`` is the id in its frontmatter when the importer got far enough to read
    one, and ``None`` otherwise. That distinction is what :func:`reconcile_import` needs: a
    record dropped under a known id explains a self-reported finding that never arrived, and one
    dropped before its id could be read explains nothing in particular.
    """

    name: str
    finding_id: str | None
    reason: str

    @property
    def note(self) -> str:
        """The note this loss reads as in the record: the id when there is one, else the name."""
        return f"{self.finding_id or self.name}: {self.reason}"


class HarnessImport(NamedTuple):
    """One import of the harness's own finding records.

    ``losses`` is every record the importer could not turn into a claim, for any reason. The
    caller must degrade the outcome when there is one: a record ScanEval dropped is a finding
    the scanner did emit, so the scan cannot stand as a complete or quiet observation. A
    directory listing that failed contributes one entry, so the count is a floor rather than an
    exact number whenever a loss says a listing failed.

    ``lost`` is derived from ``losses`` rather than counted alongside it, so the count and the
    list of reasons cannot disagree about how much was lost.
    """

    claims: list[dict]
    artifacts: list[dict]
    notes: list[str]
    losses: tuple[LostRecord, ...]

    @property
    def lost(self) -> int:
        """How many finding records did not become claims."""
        return len(self.losses)


class FindingsBaseline(NamedTuple):
    """What the harness findings directory held before the scan ran.

    ``digests`` maps each ``*.md`` file name present beforehand to the SHA-256 of its bytes,
    or to ``None`` when the file was there but could not be read. ``established`` is false
    when the directory could not be listed at all, which is not the same as an empty
    directory: nothing can then be attributed to the scan.
    """

    digests: dict[str, str | None]
    established: bool
    note: str | None


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_record(path: Path, contained: Path | None) -> tuple[bytes | None, str | None]:
    """The bytes at one path the harness could have written, or a message naming why not.

    Every read this adapter makes of such a path goes through here, so both rules hold on every
    one of them rather than at whichever call site remembered to state them.

    The path must resolve inside the directory it belongs to, which is what *contained* carries:
    the caller passes :meth:`Enclosure.read` for a path in the workspace the scanner was handed
    and :meth:`Enclosure.write` for one in this run's staging directory, and ``None`` there is a
    refusal rather than a missing file.

    And it must be a regular file, proved by :func:`~scaneval.execution.read_regular_file`, whose
    open is the same open that reads the bytes. A named pipe left where the harness's own output
    belongs used to block :func:`~scaneval.execution.run_invocation` forever, with no bundle and
    no record that the run had happened; a symbolic link would have put a host file the scan
    never wrote into the bundle as evidence. Neither is followed now, and both read as a failure
    naming what was there, which every caller counts as loss or as a note.
    """
    if contained is None:
        return None, "it does not resolve inside the directory this run gave it"
    try:
        return read_regular_file(path), None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            return None, "it is a symbolic link, not a regular file"
        return None, exc.strerror or str(exc)


def _list_markdown(directory: Path, enclosure: Enclosure) -> tuple[list[str], str | None, bool]:
    """Sorted ``*.md`` names in *directory*, a note naming any failure, and whether it exists.

    Enumeration is :func:`~scaneval.execution.list_directory`, the package's one listing, rather
    than :meth:`Path.glob`, which swallows the ``OSError`` the directory walk raises and would
    make an unreadable directory indistinguishable from an empty one. The third value is false
    only when the directory is absent; a directory that exists and cannot be listed returns true
    with a note, so the caller counts the records it could not see instead of reporting none.

    A findings path that does not resolve inside the workspace is one of those failures, not a
    directory to read: what lies behind it is not the workspace this scan was given, so records
    found there were not shown to be anything this scan wrote. It is refused whole, before
    anything in it is listed, because a per-record check never sees a record reached only
    through a link above it.
    """
    if enclosure.read(directory) is None:
        return [], ("the findings path does not resolve inside the workspace the scan was "
                    "given; it was not followed"), True
    try:
        names = [entry.name for entry in list_directory(directory)]
    except FileNotFoundError:
        return [], None, False
    except NotADirectoryError:
        return [], "the findings path is not a directory", True
    except OSError as exc:
        return [], f"the findings directory could not be listed ({exc.strerror or exc})", True
    return [name for name in names if name.endswith(".md")], None, True


def snapshot_findings(findings_dir: Path, enclosure: Enclosure) -> FindingsBaseline:
    """Record the finding records present before the scan, so the import can exclude them.

    Call this before the harness process starts. Each ``*.md`` file is hashed through
    :func:`read_record`; one that cannot be read, that resolves out of the workspace, or that is
    not a regular file is recorded with a ``None`` digest, which no content hash equals, so the
    importer treats it as pre-existing rather than as something the scan produced. A directory
    that cannot be listed, or that does not resolve inside the workspace, yields ``established``
    false, and the importer then attributes nothing to the scan instead of guessing.

    The regular-file rule matters here as much as at the import: this runs on the exported input,
    and a named pipe shipped where a finding record belongs would otherwise block the baseline
    before the scanner had even started.
    """
    names, note, exists = _list_markdown(findings_dir, enclosure)
    if not exists:
        return FindingsBaseline({}, True, None)
    if note:
        return FindingsBaseline({}, False, note)
    digests: dict[str, str | None] = {}
    for name in names:
        data, _failure = read_record(findings_dir / name, enclosure.read(findings_dir / name))
        digests[name] = _digest(data) if data is not None else None
    return FindingsBaseline(digests, True, None)


def stage_record(source: Path, destination: Path, enclosure: Enclosure) -> str | None:
    """Copy one harness record into the staging directory; return a failure message, never raise.

    Every record this adapter stages goes through here: the finding records, whose failure is
    import loss, and the plan records, whose failure is a note. That is the rule in one place: a
    copy made to preserve evidence must not raise out of :meth:`LlmHarnessAdapter.scan`, where
    it would discard every claim the importer had already built and turn the whole scan into an
    adapter failure. The scanner owns both ends of this copy, so both ends can fail.

    Both ends are checked against the enclosure, and that is what makes the destination safe.
    The harness writes into the staging directory while it runs, so a link it left where these
    records go redirected the copy to any absolute path it chose and this wrote outside the
    bundle: ``mkdir(exist_ok=True)`` succeeds on a link to a directory and
    :func:`shutil.copyfile` followed one. Neither is reached now unless the destination resolves
    back inside the staging directory, and the write itself refuses a link as well.

    Only a regular file is copied, and the source goes through :func:`read_record` like every
    other read this adapter makes: :func:`shutil.copyfile` followed a symbolic link and would
    preserve a host file the scan never wrote, and opening a named pipe for reading would block
    until something wrote to it, which nothing here ever does.

    The destination is proved to be a regular file this run alone names, in the same open that
    writes it, which is the rule :func:`~scaneval.execution.read_regular_file` keeps for a read.
    ``O_NONBLOCK`` makes opening a named pipe planted here fail at once rather than wait forever
    for a reader, and the descriptor is checked with :func:`os.fstat` before a byte is written:
    anything that is not a regular file is refused, and so is one carrying a second link, because
    ``O_NOFOLLOW`` refuses a symbolic link and a hard link is not one, so the write would have
    truncated and overwritten whatever host file the harness had linked here. The truncation
    happens after those checks rather than in the open, so a refused destination is left exactly
    as it was found.

    That hardening narrows two instances; it does not close the class they belong to. The
    enclosure check and this open are still two operations, and so are the ``mkdir`` and the
    open, so a harness process still running can plant a pipe, a link, or a whole directory in
    between. ``docs/THREAT_MODEL.md`` states that class and what an operator has to do about it.
    """
    data, failure = read_record(source, enclosure.read(source))
    if data is None:
        return f"the record is not a regular file inside the workspace ({failure}); it was not copied"
    if enclosure.write(destination) is None:
        return "the staging destination does not resolve inside this run's raw output"
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
                             | getattr(os, "O_NONBLOCK", 0), 0o666)
    except OSError as exc:
        return exc.strerror or str(exc)
    try:
        try:
            staged = os.fstat(descriptor)
            if not stat.S_ISREG(staged.st_mode):
                raise OSError(errno.EINVAL, "the staging destination is not a regular file",
                              str(destination))
            if staged.st_nlink > 1:
                raise OSError(errno.EMLINK, "the staging destination is a second name for another "
                              "file, so writing the record would overwrite that file", str(destination))
            os.ftruncate(descriptor, 0)
        except BaseException:
            os.close(descriptor)
            raise
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
    except OSError as exc:
        return exc.strerror or str(exc)
    return None


def import_harness_findings(findings_dir: Path, *, harness: str, artifact_prefix: str,
                            stage_dir: Path, baseline: FindingsBaseline,
                            enclosure: Enclosure) -> HarnessImport:
    """Stage the ``findings/*.md`` records this scan produced and translate each into a claim.

    A finding record is a ``*.md`` file in *findings_dir*, which is what the harness's own
    reader treats as one. Each imported record is copied into *stage_dir* and registered as its
    own raw artifact under ``<artifact_prefix>/<file name>``, and the claim carries that same
    id, so every claim points at a hash-backed record the bundle holds rather than at a name
    nothing registers. A record that is not a regular file, cannot be read, carries no id,
    carries an unusable ``file_path``, or cannot be staged yields no claim and becomes one
    :class:`LostRecord`, which is both the loss and the note it reads as. The directory is listed
    explicitly, so a listing that fails is counted and noted rather than read as an empty
    directory, and a findings path that does not resolve inside *enclosure* is one of those
    failures: nothing behind it is read, because it is not the workspace this scan was handed.
    Every record read and every staged copy goes through the same enclosure, so a link anywhere
    above a record is refused exactly like a record that is a link. The full native allegation
    text is preserved. A line is imported only when the native scan-site record
    supplies a positive integer; no location is inferred from the prose.

    Provenance. *baseline* is :func:`snapshot_findings` taken before the harness process
    started, and a record whose name and bytes are both in it is not imported: it was already
    in the exported input, so importing it would credit the scan with a finding the repository
    shipped. A name in the baseline whose bytes now differ is imported, because the scan
    rewrote it. When the baseline could not be established, nothing is attributed to the scan
    and every record is counted in ``lost``, since one of them may have been the scan's own.

    What this does not prove. It establishes only that the bytes were not in the workspace
    before the harness ran. It does not show that the harness's model produced them: anything
    else with write access to the workspace during the scan could have. It also cannot tell a
    record the harness rewrote byte-for-byte from one it left alone, so a planted record the
    harness happened to re-emit unchanged is still excluded.
    """
    claims: list[dict] = []
    artifacts: list[dict] = []
    notes: list[str] = []
    losses: list[LostRecord] = []

    def lose(name: str, finding_id: str | None, reason: str) -> None:
        """Record one lost record once: the loss and the note it reads as come from one call."""
        loss = LostRecord(name, finding_id, reason)
        losses.append(loss)
        notes.append(loss.note)

    names, listing_failure, exists = _list_markdown(findings_dir, enclosure)
    if not exists:
        return HarnessImport(claims, artifacts, ["no findings directory was written by the harness"], ())
    if listing_failure:
        # A directory this could not read is not an empty one: an unknown number of records
        # went unimported, so one loss is recorded as a floor and the note says so.
        lose(findings_dir.name, None,
             f"{listing_failure}; an unknown number of finding records was not imported")
        return HarnessImport(claims, artifacts, notes, tuple(losses))
    if not baseline.established:
        # Nothing separates a record the scan wrote from one the input shipped, so none is
        # attributed to the scan and all of them are counted as lost.
        note = baseline.note or "the findings directory could not be listed before the scan"
        reason = f"finding record provenance could not be established ({note}); not imported"
        for name in names or [findings_dir.name]:
            lose(name, None, reason)
        return HarnessImport(claims, artifacts, notes, tuple(losses))
    for name in names:
        path = findings_dir / name
        contained = enclosure.read(path)
        if contained is None:
            lose(path.name, None, "finding record does not resolve inside the workspace; not imported")
            continue
        data, failure = read_record(path, contained)
        if data is None:
            # One message for every way the read did not happen, including a record that is not
            # a regular file: a link the importer must not follow and a named pipe it must not
            # open are refusals of the same read, not two different kinds of event.
            lose(path.name, None, f"finding record could not be read ({failure}); not imported")
            continue
        if name in baseline.digests and baseline.digests[name] in (None, _digest(data)):
            # These bytes were in the exported input before the harness ran, so the scan did
            # not produce this finding and cannot be credited with it. Not import loss: the
            # record is not a claim the scanner made.
            notes.append(f"{path.name}: this record was already in the exported input before the scan; "
                         "not imported as a finding of this scan")
            continue
        text = data.decode("utf-8", errors="replace")
        record, body = parse_frontmatter(text)
        finding_id = str(record.get("id") or "")
        if not finding_id:
            lose(path.name, None, "no id in frontmatter; not imported")
            continue
        file_path = str(record.get("file_path") or "").replace("\\", "/")
        if file_path.startswith("./"):
            file_path = file_path[2:]
        if not file_path or file_path.startswith("/") or ".." in file_path.split("/"):
            lose(path.name, finding_id,
                 f"unusable file_path {file_path!r}; not imported, see the raw finding record")
            continue
        failure = stage_record(path, stage_dir / path.name, enclosure)
        if failure:
            # The claim would name an artifact the bundle does not hold, so the record is
            # counted as lost rather than imported against a copy that was never made.
            lose(path.name, finding_id, f"finding record could not be staged ({failure}); not imported")
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
        site, site_error = _native_scan_site(record)
        if site_error:
            notes.append(f"{finding_id}: {site_error}; location kept file-level")
        if site is not None:
            line = site.get("line")
            if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                claim["primary_location"]["start_line"] = line
                claim["primary_location"]["end_line"] = line
            elif line is not None:
                notes.append(f"{finding_id}: scan site line is not a positive integer; location kept file-level")
            for source, destination in (("sourceSymbol", "native_source_symbol"),
                                        ("sinkSymbol", "native_sink_symbol")):
                value = site.get(source)
                if isinstance(value, str) and value.strip():
                    claim[destination] = value
        if reasoning and reasoning != "N/A":
            claim["evidence_text"] = reasoning
        severity = record.get("severity")
        if isinstance(severity, str) and severity:
            claim["native_severity"] = severity
        claims.append(claim)
        artifacts.append({"id": claim["raw_artifact_id"], "path": stage_dir / path.name})
    return HarnessImport(claims, artifacts, notes, tuple(losses))


class SelfReport(NamedTuple):
    """What the harness says its own run wrote, read off the driver summary.

    ``ids`` are the distinct finding ids it named in ``newFindings`` and ``updatedFindings``,
    each of which the engine writes as one ``findings/*.md`` record. ``unnamed`` counts reported
    entries carrying no usable id, which can still be compared by number. ``unreadable`` counts
    the parts of the self-report this could not read at all, and ``note`` names them.

    ``unreadable`` is separate from ``total`` on purpose. A part this cannot read says nothing
    about how many records the harness wrote, so it cannot be added to a count; what it is, is
    evidence the run offered and the importer could not use, and :func:`reconcile_import` counts
    each one as a lost record rather than as nothing at all.
    """

    ids: tuple[str, ...]
    unnamed: int
    unreadable: int
    note: str | None

    @property
    def total(self) -> int:
        """How many finding records the harness says this run wrote."""
        return len(self.ids) + self.unnamed


def read_self_report(summary: object) -> SelfReport:
    """Read the harness's own count of the finding records it wrote.

    A summary that names no findings yields an empty report, which asserts nothing: this is a
    cross-check against a scanner's own words, not a guarantee. ``None``, an absent key, and a
    summary that is not a mapping at all are all that case: no self-report was offered, and the
    run that produced no summary is already reported as a failed one.

    A self-report that was offered and cannot be parsed is the opposite case and is counted.
    ``newFindings`` or ``updatedFindings`` in a shape this cannot read used to yield a note and
    no number, which reconciled to a shortfall of zero: a run whose entire self-report was a
    shape the reader did not expect reached scoring as a clean success. An unreadable part is
    missing evidence, not evidence that nothing was written, so each one is counted in
    ``unreadable`` for the caller to treat as loss.
    """
    if not isinstance(summary, dict):
        if summary is None:
            return SelfReport((), 0, 0, None)
        return SelfReport((), 0, 1,
                          f"the harness summary is a {type(summary).__name__}, not a mapping, so "
                          "the findings it reports could not be read")
    ids: list[str] = []
    unnamed = 0
    unreadable: list[str] = []
    for key in ("newFindings", "updatedFindings"):
        reported = summary.get(key)
        if reported is None:
            continue
        if isinstance(reported, int) and not isinstance(reported, bool):
            # Some summaries carry a count where others carry the records themselves.
            unnamed += max(reported, 0)
            continue
        if not isinstance(reported, list):
            unreadable.append(f"summary.{key} is a {type(reported).__name__}, not a list of findings")
            continue
        for entry in reported:
            identifier = entry.get("id") if isinstance(entry, dict) else None
            if isinstance(identifier, str) and identifier:
                ids.append(identifier)
            else:
                unnamed += 1
    return SelfReport(tuple(dict.fromkeys(ids)), unnamed, len(unreadable), "; ".join(unreadable) or None)


class ImportAccounting(NamedTuple):
    """The one count of finding records this scan produced that did not arrive as claims.

    Everything the outcome does about import loss reads this: the status, ``bundles_resolved``,
    the error message, and the note. ``lost`` above zero means the scan can earn neither
    completeness nor quiet credit.
    """

    lost: int
    message: str | None
    notes: tuple[str, ...]


def reconcile_import(imported: HarnessImport, report: SelfReport) -> ImportAccounting:
    """Reconcile what the harness says it wrote against what the importer could read.

    The rule: a scanner self-report that disagrees with what we could read is evidence of loss,
    not something to ignore. Counting only the records the importer could see left the worst
    case invisible, because a scan whose findings all vanished before the import produced no
    record to count and reached scoring as a clean success.

    The arithmetic, and why it cannot count one record twice. Every record the importer read and
    rejected is one loss, with its own reason. Against that, each finding the harness named is
    accounted for when a claim carries its id, and each finding it reported without an id is
    accounted for by any delivered claim the report did not name. What is left over is the
    shortfall: findings the harness says it wrote that neither arrived nor are already counted
    as a rejected record. A rejected record is assumed to be one of the reported findings, so a
    record that was both reported and rejected is counted once, as a rejection with a reason.

    A part of the self-report that could not be read at all is counted too, one lost record
    each, which is a floor rather than a number: it says at least one record may be behind it,
    not how many. It used to produce a shortfall of zero, so a run whose whole self-report was
    unreadable read as a scan that reported nothing and lost nothing.

    The limits. This trusts the self-report only as a lower bound on what was written: a harness
    that reports nothing produces no shortfall, and one that under-reports hides the same way.
    The comparison is by id, so a record the harness rewrote byte for byte is excluded by the
    import baseline and then shows up here as a shortfall, which is the conservative direction:
    it was reported, and no claim for it arrived.
    """
    delivered = {str(claim.get("claim_id") or "") for claim in imported.claims}
    named_lost = {loss.finding_id for loss in imported.losses if loss.finding_id}
    matched = sum(1 for identifier in report.ids if identifier in delivered)
    absorbed = min(report.unnamed, max(len(delivered) - matched, 0))
    shortfall = max(report.total - matched - absorbed - imported.lost, 0)
    reasons = [loss.note for loss in imported.losses]
    notes = [report.note] if report.note else []
    if shortfall:
        unattributed = [identifier for identifier in report.ids
                        if identifier not in delivered and identifier not in named_lost]
        detail = ", ".join(unattributed[:10]) if unattributed else "none of them carried an id"
        reasons.append(f"the harness reported writing {report.total} finding record(s) and "
                       f"{shortfall} of them did not arrive as claims ({detail})")
    if report.unreadable:
        reasons.append(f"the harness self-report could not be read ({report.note}), so the "
                       f"findings it names could not be compared with the claims that arrived; "
                       f"counted as {report.unreadable} lost record(s), which is a floor")
    lost = imported.lost + shortfall + report.unreadable
    message = None
    if lost:
        message = (f"{lost} harness finding record(s) could not be imported: "
                   + "; ".join(reasons))[:2000]
        notes.append(f"Import loss: {lost} finding record(s) the harness wrote could not be "
                     "imported, so this scan can earn neither completeness nor quiet credit.")
    return ImportAccounting(lost, message, tuple(notes))


# The harness modes this adapter runs and makes capture claims about: bootstrap for a full request,
# pr for a PR request. A mode outside this pair has no claim behind it, so capture_status refuses it.
CAPTURE_MODES = ("bootstrap", "pr")


def capture_status(trace_mode: str, routes: list[str], *, has_summary: bool,
                   capture_state: dict | None = None, hooks: dict | None = None,
                   hook_failures: int | None = None, mode: str = "bootstrap") -> dict[str, str]:
    """Per-category capture availability for one harness run.

    *mode* is the harness mode the run was in, ``bootstrap`` (the default, and every run before PR
    mode existed) or ``pr``. It changes no value returned here, and that is a claim, not an
    oversight: what this adapter can observe depends on the trace mode, the routes, the summary,
    the observer's own state, and which observation surfaces the harness build exports, and none of
    those is a property of the mode. The documented matrix and its test hold every cell equal
    across the two modes, so a difference between them would have to be found and stated. A mode
    this adapter has no claim about is refused rather than answered as if it were bootstrap.

    *hooks* is the ``hooks`` object the driver reported: the harness observation surfaces that
    build actually exported, ``{"runner": <version or None>, "engine": <version or None>}``.
    Omitted, or with both versions absent, this describes a harness that exports neither, which
    is what every value here meant before either existed. A shape this cannot read is read as
    neither, because a capture claim must rest on something observed.

    Tool dispatch is ``unavailable`` on every real route: it happens inside the model CLI
    this adapter spawns, so no tool event is observed and the absence of one establishes
    nothing about whether a tool ran. Only the mock runner, which spawns no process at
    all, makes the concept inapplicable.

    Model events stay ``partial`` on every traced run, with the runner hooks and without them,
    and for reasons the hooks do not touch. An attempt is a CLI invocation, not an API request:
    what the CLI did inside one attempt is not visible from here. And the pi route reports no
    token usage at all. What the hooks changed is real but is not this: every attempt inside a
    logical call is now its own pair of events instead of one recorded pair standing for all of
    them, and on the claude json route each attempt carries the tokens and the cost estimate the
    CLI reported for it. The notes on the run say which of those this run got.

    ``context_selection`` stays ``partial`` even with the engine hooks. The engine reports the
    exact spans it placed in each hypothesis and file-scan prompt, which is far stronger than the
    progress notes it replaces, but not every model invocation is instrumented: the threat
    planner reports none, and only some specialists do. A run therefore has model calls whose
    context nothing reported, and a category that misses some of its subject is not complete.
    How many were reported and how many were not is measured per run by the driver and repeated
    in this run's notes, because which stages are instrumented is the harness's business and
    changes as it instruments more of itself.

    ``finding_candidate`` and ``finding_filtered`` are what the engine hooks made observable at
    all. With them, a traced run reporting no capture gap and no dropped event carries the
    engine's whole candidate and filter set: ``complete``. One reporting either, or reporting no
    state, is ``partial`` for the same reason ``finding_submitted`` is. Neither waits on a
    summary, because the engine reports each decision as it makes it: a scan that died half way
    still reported every candidate it had reached by then. Without the hooks nothing is observed
    and both are ``unavailable``.

    *hook_failures* is the engine's own count of hooks that threw or rejected, as the run
    finally reported it, and it is a second, independent way those three categories lose
    records. The observer's capture state cannot see it: a hook that failed never reached the
    emitter, so nothing was dropped on the way to a sink and ``dropped_events`` is still zero.
    So a count this cannot read as zero downgrades every category the engine hooks feed --
    candidate, filtered and submitted -- to ``partial``. ``None`` means the run reported no
    final count, which is not a report of none: an unknown number of records may be missing, and
    an unknown loss is not a complete capture.

    The runner's own hook failures are not an input, because they cannot change an answer here:
    model events are already never better than ``partial`` on a traced run and ``unavailable``
    on an untraced one. The count is carried in the run's notes instead, where a reader looking
    at a thin attempt stream can find out why it is thin.

    ``finding_validation`` is ``not_applicable`` with the engine hooks, and that is a statement
    about the scan and not about the observer: validation is the consensus judge, and no run this
    adapter can produce has a validation stage in it. A bootstrap run never has one, because the
    engine runs the judge only in pr mode. A pr run has one only when consensus is configured, and
    this adapter never configures it: the driver passes no ``consensus`` option in either mode, so
    the judge is never given the chance to run. Without the hooks the honest answer is the weaker
    one, ``unavailable``, which says nothing was observed and not that nothing ran.

    ``finding_submitted`` is read off *capture_state*, the observer state the driver reported,
    and, where the engine hooks produced it, off *hook_failures* as well, rather than off the
    bare fact that a trace was written. It used to be ``complete`` whenever
    the run was traced and produced a summary, which contradicted the ``capture_gap`` and
    ``dropped_events`` the same execution record carries. ``complete`` now requires a state that
    explicitly reports no gap and no dropped event; a state reporting either, and a run that
    reported no state at all, are ``partial``, because nothing there rules a gap out.

    This reports what the observer saw. Whether the trace file reached the bundle is something
    only the runner knows, so that half of the same question is settled there: a ``complete``
    here is downgraded by :func:`~scaneval.execution._capture_record` when the bundle it lands in
    holds no counted trace, and the run is recorded as partial. Do not answer it twice.
    """
    if mode not in CAPTURE_MODES:
        raise ValueError(f"capture is described for the harness modes {', '.join(CAPTURE_MODES)}, not {mode!r}")
    request_capture = {"off": "unavailable", "metadata": "partial", "content": "partial"}[trace_mode]
    traced = trace_mode != "off"
    engine_hooks = bool(hooks.get("engine")) if isinstance(hooks, dict) else False
    gapless = (isinstance(capture_state, dict) and capture_state.get("capture_gap") is False
               and capture_state.get("dropped_events") == 0)
    # A count only rules loss out when it is a reading of zero. Anything else -- a nonzero
    # count, an absent one, a value in a shape this cannot read -- leaves records possibly lost
    # before the emitter ever saw them.
    hooks_intact = isinstance(hook_failures, int) and not isinstance(hook_failures, bool) and hook_failures == 0
    engine_clean = gapless and (hooks_intact or not engine_hooks)
    submitted = ("complete" if engine_clean else "partial") if (traced and has_summary) else "unavailable"
    engine_findings = (("complete" if gapless and hooks_intact else "partial")
                       if (traced and engine_hooks) else "unavailable")
    return {
        "model_requests": request_capture,
        "model_responses": request_capture,
        "tool_calls": "not_applicable" if routes == ["mock"] else "unavailable",
        "context_selection": "partial" if traced else "unavailable",
        "finding_submitted": submitted,
        "finding_candidate": engine_findings,
        "finding_validation": "not_applicable" if engine_hooks else "unavailable",
        "finding_filtered": engine_findings,
    }


SESSION_BACKENDS = {"pi": "pi-session", "claude": "claude-session"}
SESSION_TRANSCRIPTS = ("moved", "not_found", "session_id_not_reported", "in_call_directory")


def session_manifest(output: Any) -> list[dict[str, Any]] | None:
    """The driver's per-attempt manifest of native sessions, or None when it reported none.

    Each entry names the call directory, the backend, the attempt where one is observable, the
    session id where the CLI reported one, and what became of the transcript. An entry this
    cannot read is dropped rather than guessed at; the notes then count only the readable ones.
    """
    entries = output.get("session_manifest") if isinstance(output, dict) else None
    if not isinstance(entries, list):
        return None
    readable = []
    for entry in entries:
        if (isinstance(entry, dict) and isinstance(entry.get("call"), str)
                and re.fullmatch(r"call-[1-9][0-9]*", entry["call"])
                and entry.get("backend") in SESSION_BACKENDS
                and entry.get("transcript") in SESSION_TRANSCRIPTS):
            readable.append(entry)
    return readable


def session_history_notes(manifest: list[dict[str, Any]], registered: dict[str, set[str]]) -> list[str]:
    """What native history this run kept, per backend, read off the manifest and the artifacts.

    Logical calls, attempt sessions and transcript files are three different counts and each is
    named as itself. A transcript counts as preserved only when the driver moved it and the file
    is among the artifacts this run registered, so the two records are reconciled rather than
    either one being taken on its own word.
    """
    notes: list[str] = []
    for backend in sorted({entry["backend"] for entry in manifest}):
        entries = [entry for entry in manifest if entry["backend"] == backend]
        calls = list(dict.fromkeys(entry["call"] for entry in entries))
        if backend == "pi":
            files = sum(len(registered.get(call, ())) for call in calls)
            notes.append(f"ScanEval-only pi session history: {files} JSONL file(s) preserved for {len(calls)} "
                         "logical pi call(s); separate call directories do not resume one another.")
            empty = [call for call in calls if not registered.get(call)]
            if empty:
                notes.append(f"Pi history is incomplete: {len(empty)} logical pi call(s) have no session file "
                             f"({', '.join(empty[:10])}). The observer trace and native history must not be "
                             "treated as independent complete records.")
            continue
        missing: list[str] = []
        preserved = 0
        for entry in entries:
            name = f"{entry.get('session_id')}.jsonl"
            where = entry["call"] + (f" attempt {entry['attempt']}" if isinstance(entry.get("attempt"), int) else "")
            if entry["transcript"] == "moved" and name in registered.get(entry["call"], ()):
                preserved += 1
            elif entry["transcript"] == "moved":
                missing.append(f"{where}: moved by the driver but not registered")
            elif entry["transcript"] == "not_found":
                missing.append(f"{where}: no transcript found for its session id")
            else:
                missing.append(f"{where}: the CLI reported no session id")
        by_attempt = any(isinstance(entry.get("attempt"), int) for entry in entries)
        notes.append(f"ScanEval-only claude session history: {preserved} of {len(entries)} "
                     + ("attempt session(s)" if by_attempt else "session(s)")
                     + f" preserved, for {len(calls)} logical claude call(s)"
                     + ("; every attempt that reported a session id is kept, retried and failed ones included."
                        if by_attempt else "; this harness build reports no attempts, so only the session each "
                        "call returned is known."))
        if missing:
            notes.append(f"Claude history is incomplete: {len(missing)} session(s) were not preserved ("
                         + "; ".join(missing[:10]) + ("; ..." if len(missing) > 10 else "")
                         + "). The observer trace and native history must not be treated as independent "
                         "complete records.")
    return notes


class LlmHarnessAdapter(Adapter):
    name = "llm-harness"
    adapter_version = "2.6.0"
    requires_git = True
    # A full request runs the harness's bootstrap mode; a PR request runs its pr mode over the base
    # and head commits the request names (see the module docstring).
    scan_modes = frozenset({"full", "pr"})
    supported_languages = frozenset({"python", "javascript", "typescript", "go", "rust"})
    # What the driver process inherits from the operator environment, on top of the base set in
    # :mod:`scaneval.adapters.base`, and recorded as ``environment.passthrough`` in every
    # execution record. ``NODE_OPTIONS`` is deliberately not here: node executes what it names,
    # so ``--require`` or ``--import`` in the operator's environment would run code inside the
    # driver, changing what the run did while the record showed only the variable's name and
    # never its value. The provider keys are here because the harness needs them to call a
    # model; they are secrets, so they are passed and never recorded.
    env_passthrough = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "XDG_CONFIG_HOME")
    # Derived from the one list the export strips, so a repository shipping a top-level
    # harness state directory cannot be stripped by one of them and treated as ordinary
    # content by the other.
    state_dirs = tuple(sorted(HARNESS_STATE_DIRS))
    # Declared for the image runtime alone, and the declaration is kept honest in scan(): a system on
    # runtime ``local`` that reaches an oci backend is refused there before anything starts, and one
    # on ``oci_image`` that reaches no oci backend is refused the same way. On the image runtime every
    # process starts through :func:`run_command` from the scanning thread, with the image's own tsx,
    # and every host read of what the container wrote goes through :func:`read_record`,
    # :func:`~scaneval.execution.list_directory`, or a no-follow stat beneath a contained path.
    oci_compatible = True

    @staticmethod
    def _runtime(spec: SystemSpec) -> str:
        runtime = spec.config.get("runtime", "local")
        if runtime not in RUNTIMES:
            raise AdapterError(f"config.runtime must be one of {', '.join(RUNTIMES)}, not {runtime!r}")
        if runtime == "local":
            stray = sorted(IMAGE_ONLY_KEYS & set(spec.config))
            if stray:
                raise AdapterError(f"config {', '.join(stray)} appl{'ies' if len(stray) == 1 else 'y'} only to "
                                   "runtime oci_image; the local runtime would ignore it")
        return runtime

    def execution_refusal(self, spec: SystemSpec, settings: Any) -> str | None:
        """Why this system's runtime cannot run under *settings*' backend, decided before preparation.

        The host runtime runs only on the local backend and the image runtime only under oci with
        public_research. scan() checks the same again against the backend actually holding it.
        """
        runtime = self._runtime(spec)
        backend = getattr(settings, "backend", None)
        if runtime == "local" and backend != "local":
            return (f"the {backend} execution backend refuses adapter 'llm-harness' on config.runtime local: the "
                    "host harness checkout has no image and its processes would run outside the boundary; select "
                    "config.runtime oci_image to run the image-owned harness")
        if runtime == "oci_image" and (backend != "oci" or getattr(settings, "network_policy", None) != "public_research"):
            return ("config.runtime oci_image runs only under the oci execution backend with network policy "
                    f"public_research, not {backend} with {getattr(settings, 'network_policy', None)}; it is never "
                    "run on the host, and closed-book systems use the local runtime")
        return None

    def condition_controls(self, spec: SystemSpec, preparation: dict) -> dict[str, Any]:
        """The image route's research controls; the local route supplies none, as before.

        Read from the configuration this adapter enforces in scan(): the image route declares fetch
        and history tools to the model, search only when configured, and nothing that installs or
        updates software. Provider-side retrieval is the provider's and stays unverifiable.
        """
        if spec.config.get("runtime", "local") != "oci_image":
            return {}
        settings = image_settings(spec.config)
        return {"inference": "offline" if settings["synthetic"] else "remote",
                "tools": {"browser": "disabled", "web_search": "enabled" if settings["search"] else "disabled",
                          "remote_fetch": "enabled", "package_install": "disabled", "scanner_update": "disabled"},
                "basis": "adapter_controls",
                "provider": ({"capability": "not_applicable", "control": "not_applicable", "attestation": None}
                             if settings["synthetic"] else
                             {"name": settings["provider"], "capability": "unverifiable",
                              "control": "unverifiable", "attestation": None})}

    def _prepare_image(self, spec: SystemSpec) -> dict[str, Any]:
        """Preparation of the image runtime: configuration only, nothing on the host is inspected.

        The paths are inside the scanner image, which this process cannot see; what actually ran is
        read back from the driver's own report of the image's receipt, versions and file digests.
        """
        settings = image_settings(spec.config)
        return {
            "runtime": "oci_image",
            "harness": {"name": "securevibes-agent", "root": settings["paths"]["root"],
                        "configured_root": settings["paths"]["root"], "location": "scanner image",
                        "package_version": None, "git_head": None, "working_tree_modified": None,
                        "expected_commit": settings["expected_commit"], "state_dir": ".securevibes"},
            "observer_sdk": settings["paths"]["observer_sdk"],
            "runner": "default",
            "model": spec.config["model"],
            "pi": {"provider": settings["provider"], "model_id": settings["model_id"],
                   "thinking_level": settings["thinking"], "expected_version": settings["expected_pi"],
                   "synthetic": settings["synthetic"]},
        }

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
        if self._runtime(spec) == "oci_image":
            return self._prepare_image(spec)
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
            # Hermetic, like every other git call this package makes: an inherited GIT_DIR would
            # otherwise make this record an unrelated repository's HEAD as the harness version.
            head_argv, git_environment = git_command(["rev-parse", "HEAD"])
            status_argv, _ = git_command(["status", "--porcelain"])
            head = subprocess.run(head_argv, cwd=root, env=git_environment, capture_output=True,
                                  text=True, timeout=30).stdout.strip() or None
            dirty = bool(subprocess.run(status_argv, cwd=root, env=git_environment, capture_output=True,
                                        text=True, timeout=30).stdout.strip())
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

    def _image_preflight(self, spec: SystemSpec, request: dict, backend: Any, timeout_seconds: float) -> dict[str, Any]:
        """Refuse an image-runtime scan that would not run where and how it is recorded.

        The backend must be the real oci backend holding this scan under public_research, because
        that is what supplies the recorded retrieval API the research tools use and the boundary the
        open-context condition is classified from. The credential must be declared to that backend
        under the configured provider, and present and well formed here, so a missing one is refused
        before any container starts; its value is never read into a message.
        """
        from ..isolation.oci import OciBackend

        settings = image_settings(spec.config)
        if not isinstance(backend, OciBackend):
            raise AdapterError("config.runtime oci_image runs only under the oci execution backend with network policy "
                               "public_research; this scan has no oci backend, and the image runtime is never run on "
                               "the host")
        policy = backend.settings.network_policy
        if policy != "public_research":
            raise AdapterError(f"config.runtime oci_image runs its research route only under network policy "
                               f"public_research, not {policy!r}; closed-book scans use the local runtime, so no "
                               "research tool reaches them")
        if request["input"]["mode"] != "full":
            raise AdapterError("config.runtime oci_image carries out full scans only; a PR request is refused rather "
                               "than scanned as a full tree")
        retrieval = backend.settings.retrieval or {}
        if bool(retrieval.get("search_endpoint")) != settings["search"]:
            raise AdapterError("config.research_search must be true exactly when execution.retrieval declares a "
                               "search_endpoint, so the declared tools are the ones the boundary serves")
        if not settings["synthetic"]:
            declared = dict(backend.settings.credentials)
            if declared.get(settings["auth_env"]) != settings["provider"]:
                raise AdapterError(f"execution.credentials must declare {{env: {settings['auth_env']}, provider: "
                                   f"{settings['provider']}}} so the OAuth credential reaches the container by name")
            check_pi_credential(os.environ.get(settings["auth_env"]), settings["provider"], settings["auth_env"],
                                valid_for_seconds=credential_validity(timeout_seconds))
        return settings

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        backend = active_backend()
        image: dict[str, Any] | None = None
        if self._runtime(spec) == "oci_image":
            image = self._image_preflight(spec, request, backend, timeout_seconds)
            harness, preset = "securevibes-agent", HARNESS_PRESETS["securevibes-agent"]
            root = Path(image["paths"]["root"])
        else:
            if backend is not None:
                raise AdapterError(f"config.runtime local runs the host harness checkout, which no "
                                   f"{getattr(backend, 'name', 'execution')} backend holds; select config.runtime "
                                   "oci_image to run the image-owned harness under it")
            harness, preset, root = self._preset(spec)
        requested = request["input"]["mode"]
        if requested not in self.scan_modes:
            raise AdapterError(f"llm-harness carries out {', '.join(sorted(self.scan_modes))} scans, not "
                               f"{requested!r}; it is never run on another mode's input")
        if str(spec.config.get("mode", "bootstrap")) != "bootstrap":
            raise AdapterError("config.mode names the harness mode of a full request, and only bootstrap (full "
                               "baseline) is supported; a PR request runs the harness's pr mode by itself")
        # The mode the harness runs in follows the request, never the configuration, and a PR request
        # names its two commits: the refs are handed to the engine exactly as named, so it can never
        # resolve a base of its own choosing (origin/main, HEAD~1) for a change it was not asked about.
        mode = "bootstrap"
        refs: dict[str, str] = {}
        if requested == "pr":
            pr = request["input"].get("pr")
            base_ref, head_ref = (pr or {}).get("base"), (pr or {}).get("head")
            if not (isinstance(base_ref, str) and base_ref and isinstance(head_ref, str) and head_ref):
                raise AdapterError("a PR request must name the base and head commits the review runs between")
            mode, refs = "pr", {"base_ref": base_ref, "head_ref": head_ref}
        elif request["input"].get("pr") is not None:
            # The refusal ``pr_range`` gives the other two adapters: this request would run bootstrap over
            # the whole tree and drop the change it names. ``build_request`` never produces one.
            raise AdapterError("llm-harness was given a full-mode request that also carries input.pr; it would "
                               "ignore the change it names, so the request was refused")
        trace_path = (trace_dir / "events.jsonl") if trace_dir is not None else None
        capture_pi_sessions = spec.config.get("capture_pi_sessions", trace_mode == "content")
        if not isinstance(capture_pi_sessions, bool):
            raise AdapterError("config.capture_pi_sessions must be a boolean")
        if capture_pi_sessions and trace_mode != "content":
            raise AdapterError("pi session history contains prompts and requires content tracing")
        pi_session_root = (raw_dir / "pi-sessions" if capture_pi_sessions
                           and spec.config.get("runner", "default") == "default" else None)
        config = {
            "harness_root": str(root), "engine_entry": preset["engine_entry"], "runner_entry": preset["runner_entry"],
            "mock_entry": preset["mock_entry"], "observer_sdk": preparation["observer_sdk"],
            "repo_path": str(source_dir), "mode": mode, **refs, "model": str(spec.config["model"]),
            **({"llm_max_files": int(spec.config["llm_max_files"])} if "llm_max_files" in spec.config else {}),
            **({"llm_timeout_ms": int(spec.config["llm_timeout_ms"])} if "llm_timeout_ms" in spec.config else {}),
            **({"qmd_profile": spec.config["qmd_profile"]} if spec.config.get("qmd_profile") else {}),
            **({"specialist_ids": list(spec.config["specialist_ids"])} if spec.config.get("specialist_ids") else {}),
            "runner": str(spec.config.get("runner", "default")), "trace_mode": trace_mode,
            **({"trace_path": str(trace_path)} if trace_path else {}),
            **({"pi_session_root": str(pi_session_root)} if pi_session_root else {}),
            "run_id": request["run_id"], "producer_id": f"{harness}-driver",
            "output_path": str(raw_dir / "driver-output.json"), "progress_path": str(raw_dir / "driver-progress.log"),
            "flush_timeout_ms": int(spec.config.get("flush_timeout_ms", 30000)),
        }
        journal_dir = raw_dir / "open-context-tools"
        if image is not None:
            paths = image["paths"]
            config["runtime"] = "oci_image"
            config["image"] = {
                "pi_runner_entry": paths["pi_runner"], "pi_extension": paths["pi_extension"],
                "pi_synthetic_extension": paths["pi_synthetic_extension"] if image["synthetic"] else None,
                "exec_entry": "src/runtime/exec.ts", "pi_binary": paths["pi_binary"],
                "pi_provider": image["provider"], "pi_model_id": image["model_id"],
                "thinking_level": image["thinking"], "pi_auth_env": image["auth_env"],
                "runtime_receipt": paths["runtime_receipt"],
                "credential_valid_for_ms": int(credential_validity(timeout_seconds) * 1000),
                # Created by the driver inside the container, so the container user owns it.
                "research": {"search": image["search"], "journal_dir": str(journal_dir),
                             "preflight_url": image["preflight"]},
                "synthetic": ({"tool_calls": image["tool_calls"],
                               "harness_mock": paths["root"].rstrip("/") + "/" + preset["mock_entry"]}
                              if image["synthetic"] else None),
            }
        state_dir = source_dir / preset["state_dir"]
        # The one enclosure every read and every copy destination below goes through: the
        # harness may read from and write to both of these directories while it runs, so each
        # path is resolved whole and proved to be inside the one it belongs to.
        enclosure = Enclosure.capture(Path(source_dir), Path(raw_dir))
        # Taken before the harness process starts: whatever is in the findings directory now
        # came with the exported input, not from this scan.
        findings_baseline = snapshot_findings(state_dir / "findings", enclosure)
        config_path = raw_dir / "driver-config.json"
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (raw_dir / "driver-progress.log").write_text("", encoding="utf-8")
        if image is not None:
            # The image's own tsx and driver, from the mounted workspace: the container's working
            # directory must be a mounted path, and the harness root exists only in the image. No
            # provider key is passed: the backend passes the declared credential by name alone.
            argv = [image["paths"]["tsx"], image["paths"]["driver"], "--config", str(config_path)]
            result = run_command(argv, cwd=Path(source_dir), timeout_seconds=timeout_seconds, env=build_env(),
                                 stdout_path=raw_dir / "driver-stdout.txt", stderr_path=raw_dir / "driver-stderr.txt")
        else:
            argv = [str(root / "node_modules" / ".bin" / "tsx"), str(DRIVER), "--config", str(config_path)]
            result = run_command(argv, cwd=root, timeout_seconds=timeout_seconds, env=build_env(self.env_passthrough),
                                 stdout_path=raw_dir / "driver-stdout.txt", stderr_path=raw_dir / "driver-stderr.txt")
        artifacts = [{"id": "driver-output", "path": raw_dir / "driver-output.json"},
                     {"id": "driver-stdout", "path": raw_dir / "driver-stdout.txt"},
                     {"id": "driver-stderr", "path": raw_dir / "driver-stderr.txt"},
                     {"id": "driver-progress", "path": raw_dir / "driver-progress.log"},
                     {"id": "driver-config", "path": config_path}]
        session_notes: list[str] = []
        # Listed now, registered once the driver's manifest says which backend each call used.
        session_files: list[tuple[str, str, Path]] = []
        if pi_session_root is not None:
            try:
                if enclosure.write(pi_session_root) is None:
                    raise OSError(errno.EPERM, "pi session directory escaped the private run directory")
                for call in list_directory(pi_session_root):
                    if not re.fullmatch(r"call-[1-9][0-9]*", call.name) or not call.is_dir(follow_symlinks=False):
                        session_notes.append("pi session capture contains an unexpected entry; it was not registered")
                        continue
                    for entry in list_directory(Path(call.path)):
                        path = Path(entry.path)
                        if not entry.name.endswith(".jsonl") or not entry.is_file(follow_symlinks=False):
                            session_notes.append("pi session capture contains a non-JSONL or non-regular entry; "
                                                 "it was not registered")
                            continue
                        if enclosure.write(path) is None:
                            session_notes.append("pi session capture record escaped the private run directory")
                            continue
                        session_files.append((call.name, entry.name, path))
            except FileNotFoundError:
                pass  # A run that made no pi call has no history directory.
            except OSError as exc:
                session_notes.append(f"pi session capture could not be listed ({exc.strerror or exc})")
        # The finding records live in the workspace too, so each imported one is copied into the
        # staging directory and registered under the id its claim carries. Only records this
        # scan produced are imported; the baseline above says which those are.
        imported = import_harness_findings(state_dir / "findings", harness=harness,
                                           artifact_prefix="harness-findings",
                                           stage_dir=raw_dir / "harness-findings",
                                           baseline=findings_baseline, enclosure=enclosure)
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
            if enclosure.read(written) is None:
                # Reached through a link that leaves the workspace, so it is not a record this
                # scan wrote and nothing behind it is read or copied.
                plan_notes.append(f"{name}: harness record does not resolve inside the workspace; "
                                  "it was not staged as an artifact")
            elif written.is_symlink() or (written.exists() and not written.is_file()):
                # Not staged and not hashed, and said so rather than dropped in silence. These
                # are plan records, not claims, so this does not degrade the scan status.
                plan_notes.append(f"{name}: harness record is not a regular file; it was not staged as an artifact")
            elif written.is_file():
                copied = plans / name
                failure = stage_record(written, copied, enclosure)
                if failure:
                    # Contained, not raised: a plan record is evidence, and a copy that fails
                    # must not discard the claims the importer already built. The scanner owns
                    # the record and the directory it goes to, so it can break either.
                    plan_notes.append(f"{name}: harness record could not be staged ({failure}); "
                                      "it was not staged as an artifact")
                else:
                    artifacts.append({"id": f"harness-{name}", "path": copied})
        output: dict[str, Any] = {}
        driver_output = raw_dir / "driver-output.json"
        # The harness writes this file, so it can leave a link, a directory, or a named pipe
        # there instead. It is read like every other path it owns, through one function that
        # proves the file is a regular file inside this run's raw output before it reads a byte.
        # Reading it with read_text() blocked the whole invocation on a named pipe: no bundle,
        # no execution record, and no way to tell the run from one that never finished.
        raw_output, output_failure = read_record(driver_output, enclosure.write(driver_output))
        if raw_output is None:
            notes_prefix = [f"the driver output was not read ({output_failure}); this run is "
                            "recorded as one that produced no summary"]
        else:
            notes_prefix = []
            try:
                output = json.loads(raw_output.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                output = {}
        # Only a mapping is a summary this can read. A truthy value of any other shape is not
        # one, and treating it as one crashed the scan on the first ``.get`` below; it is a
        # self-report that could not be read, which :func:`read_self_report` counts as loss.
        summary = output.get("summary") if isinstance(output, dict) else None
        usable_summary = summary if isinstance(summary, dict) and summary else None
        if usable_summary:
            native_findings = [item for key in ("newFindings", "updatedFindings")
                               for item in (usable_summary.get(key)
                                            if isinstance(usable_summary.get(key), list) else [])
                               if isinstance(item, dict)]
            cwe_by_id = {item.get("id"): item.get("cweIds") for item in native_findings
                         if isinstance(item.get("id"), str) and isinstance(item.get("cweIds"), list)}
            for claim in claims:
                cwes = cwe_by_id.get(claim["claim_id"])
                if cwes:
                    normalized = list(dict.fromkeys(value.strip() for value in cwes
                                                    if isinstance(value, str) and value.strip()))
                    if normalized:
                        claim["native_cwe"] = normalized
        trace = output.get("trace") if isinstance(output, dict) else None
        capture_state = (trace or {}).get("state") if isinstance(trace, dict) else None
        routes = sorted({str(route) for route in (output.get("observed_routes") or [])}) if isinstance(output, dict) else []
        mock_only = routes == ["mock"]
        # Which observation surfaces this harness build exported, as the driver found them. Read
        # like every other value the harness process wrote: a shape this cannot read is read as a
        # build that exported neither, never as one that exported something.
        reported_hooks = output.get("hooks") if isinstance(output, dict) else None
        hooks = reported_hooks if isinstance(reported_hooks, dict) else None
        runner_hooks = bool(hooks.get("runner")) if hooks else False
        engine_hooks = bool(hooks.get("engine")) if hooks else False
        # The engine's closing count when it reported one, because it is taken after the summary
        # was built and a hook promise can reject after that snapshot; the summary's count when
        # it did not; and None when neither is a number this can read. None is indeterminate,
        # not zero, and capture_status treats it as the loss it might be hiding.
        scan_complete = output.get("observer_scan_complete") if isinstance(output, dict) else None
        hook_failures = scan_complete.get("hook_failures") if isinstance(scan_complete, dict) else None
        if not isinstance(hook_failures, int) or isinstance(hook_failures, bool):
            hook_failures = output.get("observer_hook_failures") if isinstance(output, dict) else None
        if not isinstance(hook_failures, int) or isinstance(hook_failures, bool):
            hook_failures = None
        runner_hook_failures = output.get("runner_hook_failures") if isinstance(output, dict) else None
        if not isinstance(runner_hook_failures, int) or isinstance(runner_hook_failures, bool):
            runner_hook_failures = None
        capture = capture_status(trace_mode, routes, has_summary=bool(usable_summary),
                                 capture_state=capture_state, hooks=hooks, hook_failures=hook_failures,
                                 mode=mode)
        # One accounting of import loss, reconciling the records the importer could read against
        # the findings the harness says it wrote. Every branch below reads this and nothing else:
        # the status, the resolved-bundle flag, the error message, and the notes.
        accounting = reconcile_import(imported, read_self_report(summary))
        loss_message = accounting.message
        notes = notes_prefix + list(imported.notes) + plan_notes + session_notes + list(accounting.notes)
        if pi_session_root is not None:
            manifest = session_manifest(output)
            backend_of = {entry["call"]: entry["backend"] for entry in manifest or ()}
            registered: dict[str, set[str]] = {}
            for call, name, path in session_files:
                prefix = SESSION_BACKENDS.get(backend_of.get(call, ""), "native-session")
                artifacts.append({"id": f"{prefix}/{call}/{name}", "path": path})
                registered.setdefault(call, set()).add(name)
            if manifest is None:
                notes.append(f"The driver reported no session manifest, so the {len(session_files)} native session "
                             "file(s) registered here cannot be attributed to calls, attempts or backends.")
            else:
                notes.extend(session_history_notes(manifest, registered))
        # What the boundary this run was observed at could and could not see. It is capability
        # dependent because the boundary is: the same adapter against an older harness build
        # sees less, and says so, rather than repeating a fixed sentence that is true of one of
        # them and generous about the other.
        if runner_hooks:
            notes.append("Model requests are captured per CLI attempt: the harness runner reported every attempt "
                         "inside its own retry loop and the retry decision it made. An attempt is a CLI invocation, "
                         "not an API request, so what the CLI did inside one attempt is still not observable here.")
        elif image is not None:
            notes.append("Model requests are captured per logical harness call; retries inside the harness runner are "
                         "counted per Pi process under pi_calls but not traced, and token usage is Pi's own account "
                         "from its JSON stream.")
        else:
            notes.append("Model requests are captured per logical harness call; retries inside the harness runner and token usage are not observable at this boundary.")
        if engine_hooks:
            tagged = output.get("model_calls_with_context") if isinstance(output, dict) else None
            untagged = output.get("model_calls_without_context") if isinstance(output, dict) else None
            by_stage = output.get("model_calls_without_context_by_stage") if isinstance(output, dict) else None
            staged = (" (by the stage the engine tagged them: "
                      + ", ".join(f"{stage} {count}" for stage, count in sorted(by_stage.items())
                                  if isinstance(stage, str) and isinstance(count, int)) + ")"
                      if isinstance(by_stage, dict) and by_stage else "")
            counted = (f" It reported context for {tagged} model invocation(s) and none for {untagged}{staged}."
                       if isinstance(tagged, int) and isinstance(untagged, int) else "")
            no_validation = ("a bootstrap scan runs no validation stage" if mode == "bootstrap" else
                             "a pr scan runs no validation stage either, because the consensus judge is the "
                             "only one and this adapter never configures consensus")
            notes.append("The engine reported the context it supplied and the life of every finding candidate."
                         + counted +
                         " A model call with no context event is an uninstrumented one, not proof that it was "
                         f"given no context; and {no_validation}, so there is no validation to miss.")
            if hook_failures is None:
                notes.append("The run reported no final count of engine observer hook failures, so whether any "
                             "candidate, filter or submission record was lost before it reached the trace is "
                             "unknown; those categories are recorded as partial rather than complete.")
            elif hook_failures > 0:
                notes.append(f"The engine reported {hook_failures} observer hook failure(s); that many observation "
                             "records never reached the trace, which is a loss the observer's own capture state "
                             "cannot see because nothing was dropped on the way to a sink. Scan results are "
                             "unaffected by definition; the candidate, filter and submission categories are "
                             "recorded as partial.")
        if runner_hook_failures:
            notes.append(f"The harness runner reported {runner_hook_failures} attempt hook failure(s): that many "
                         "CLI attempts produced no request or response event. The attempt stream is incomplete by "
                         "at least that much, and the model categories stay partial, which they already were.")
        for route in routes:
            policy = TOOL_POLICY.get(route)
            if policy:
                notes.append(f"Declared tool policy on the {route} route: {policy} This is the argv the harness built, not an observation of what the CLI did.")
        if not mock_only and image is None:
            notes.append("Tool dispatch was not observed: it happens inside the model CLI subprocess. Absence of tool events is not evidence that no tool ran.")
        notes.append("Native scan-site lines and source/sink symbols were imported when present; "
                     "no missing location or symbol was inferred.")
        if mode == "pr":
            notes.append("Prepared state: fresh. The harness's state directory is stripped from every export, so "
                         "this review started with the harness's default threat model and no earlier finding, "
                         "decision, or context note; nothing is carried from one invocation to the next.")
        image_failure: dict[str, str] | None = None
        image_versions: dict[str, str] = {}
        if image is not None:
            journal_artifacts, journal, journal_notes = read_tool_journal(journal_dir, enclosure)
            artifacts.extend(journal_artifacts)
            notes.extend(journal_notes)
            image_notes, image_failure, image_versions = image_run_account(image, output, journal)
            notes.extend(image_notes)
        served_models = sorted({str(name) for name in (output.get("models_served") or [])}) \
            if isinstance(output, dict) and isinstance(output.get("models_served"), list) else []
        model_identity: dict[str, Any] = {
            "requested": str(spec.config["model"]), "resolved": None, "verification": "unverified",
            "notes": ["No served model id was reported for this run: the pi route prints none, and the claude "
                      "route names one only in the json result object the runner hooks ask for."]}
        if len(served_models) == 1:
            # The CLI's own report about itself, which is what the record's ``self_reported``
            # means. Nothing here checks which model the provider actually served.
            model_identity = {"requested": str(spec.config["model"]), "resolved": served_models[0],
                              "verification": "self_reported",
                              "notes": ["The model CLI named this served model in the modelUsage key of its own "
                                        "json result object, on every attempt that reported one. That is the CLI "
                                        "reporting on itself, not a verification of what the provider served."]}
        elif len(served_models) > 1:
            model_identity["notes"].append(
                "The run reported more than one served model id (" + ", ".join(served_models) + "), so none is "
                "recorded as the resolved model.")
        if spec.config.get("runner") == "mock":
            model_identity = {"requested": str(spec.config["model"]), "resolved": "deterministic-mock", "verification": "not_applicable",
                              "notes": ["Deterministic mock runner; diagnostic only, no model was called."]}
            notes.append("DIAGNOSTIC: deterministic mock runner, no model calls; results are not scanner evidence.")
        if image is not None:
            model_identity = image_model_identity(image, output)
            if image["synthetic"]:
                notes.append("DIAGNOSTIC: synthetic in-process Pi provider, no model was called; results exercise the "
                             "image route and are not scanner evidence or a publishable approval of it.")
        # Token counts and cost come from the model CLI's own json result object, summed by the
        # driver over the attempts that reported one. An attempt that reported none contributes
        # nothing, so both are floors rather than totals, and the cost is an estimate the CLI
        # printed rather than anything billed.
        usage: dict[str, Any] = {"cost_usd": None}
        totals = output.get("usage_totals") if isinstance(output, dict) else None
        if isinstance(totals, dict):
            for key in ("input_tokens", "output_tokens"):
                value = totals.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    usage[key] = value
        cost_total = output.get("cost_usd_cli_reported_total") if isinstance(output, dict) else None
        if isinstance(cost_total, (int, float)) and not isinstance(cost_total, bool) and cost_total >= 0:
            usage["cost_usd"] = float(cost_total)
        if "input_tokens" in usage or "output_tokens" in usage or usage["cost_usd"] is not None:
            notes.append(f"Model CLI self-report: input_tokens={usage.get('input_tokens')} "
                         f"output_tokens={usage.get('output_tokens')} cost_usd={usage['cost_usd']}. Summed over the "
                         "attempts that reported them; the cost is the CLI's own estimate, never a bill, and an "
                         "attempt that reported nothing contributes nothing, so these are floors.")
        # Import loss leaves the claim set incomplete, so the bundles it delivers are not
        # resolved: the scoring contract then refuses both completed-control and quiet credit.
        base = dict(command=argv, claims=claims, artifacts=artifacts, capture=capture, notes=notes,
                    model_identity=model_identity, usage=usage, trace_path=trace_path, capture_state=capture_state,
                    bundles_resolved=accounting.lost == 0,
                    tool_versions=({"driver": str(output.get("driver_version", "unknown")) if isinstance(output, dict)
                                    else "unknown", **image_versions} if image is not None else
                                   {"harness": f"{harness}@{preparation['harness'].get('git_head') or 'unknown'}",
                                    "harness_package": str(preparation["harness"].get("package_version")),
                                    "driver": str(output.get("driver_version", "unknown"))}))

        def stderr_tail(limit: int = 2000) -> str:
            """The tail of this run's own driver stderr, empty when it could not be read.

            The file is created here before the driver starts, but the driver can replace it with
            a link, a directory, or a named pipe, and this text goes into the recorded error
            message: without the check a scanner could choose which host file the bundle quotes,
            and a pipe would hold the read open forever. Read through :func:`read_record`, like
            every other path the harness owns.
            """
            stderr_path = raw_dir / "driver-stderr.txt"
            data, _failure = read_record(stderr_path, enclosure.write(stderr_path))
            return "" if data is None else data[-limit:].decode("utf-8", errors="replace")

        def with_loss(message: str) -> str:
            """The branch's own message, with the import loss named beside it.

            Every branch that reports a message goes through here, so what was lost travels with
            the outcome whichever way the run ended rather than only on the branches that
            remembered to ask.
            """
            return f"{message}; {loss_message}"[:2000] if loss_message else message

        workflow = read_review_workflow(usable_summary)
        notes.extend(workflow.notes)
        completion_notes, completion_code, completion_message = read_completion(
            usable_summary, required=image is not None or workflow.present, workflow=workflow)
        notes.extend(completion_notes)
        native_completion_code = workflow.code or completion_code
        native_completion_message = workflow.message or completion_message
        if native_completion_code and native_completion_message and not (workflow.notes or completion_notes):
            notes.append(f"Harness native completion evidence: {native_completion_message}.")
        if result.timed_out:
            return NativeOutcome(status="timeout", exit_code=None, timed_out=True,
                                 error={"code": "timeout",
                                        "message": with_loss(f"harness exceeded {timeout_seconds}s")}, **base)
        if image_failure is not None and image_failure["status"] == "error":
            # What ran is not what the system pins: nothing it produced is this system's observation.
            message = image_failure["message"]
            if not usable_summary:
                failure = output.get("error") if isinstance(output, dict) else None
                native_message = failure.get("message") if isinstance(failure, dict) else None
                if native_message:
                    message = f"{str(native_message)[:1000]}; {message}"[:2000]
            return NativeOutcome(status="error", exit_code=result.exit_code,
                                 error={"code": image_failure["code"], "message": with_loss(message)},
                                 **base)
        if not usable_summary:
            failure = (output.get("error") or {}) if isinstance(output, dict) else {}
            message = failure.get("message") or stderr_tail()
            return NativeOutcome(status="error", exit_code=result.exit_code,
                                 error={"code": f"driver_exit_{result.exit_code}",
                                        "message": with_loss(str(message)[:2000])}, **base)
        if image_failure is not None:
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": image_failure["code"], "message": with_loss(image_failure["message"])},
                                 **base)
        budget = usable_summary.get("budget") or {}
        if isinstance(budget, dict) and "estimatedSpentUsd" in budget:
            notes.append(f"Harness cost estimate (not measured): {budget.get('estimatedSpentUsd')} USD "
                         f"for {budget.get('actualLlmFilesScanned')} LLM files; measured cost unavailable.")
        # The engine reports how a scan went under the record of the mode it ran: bootstrapScan for
        # a bootstrap run and changeScan for a pr run. Both carry the same fields, so what is read
        # from them below is one reading, and a pr run is never judged by a record it cannot have.
        stats_key = "changeScan" if mode == "pr" else "bootstrapScan"
        scan_stats = usable_summary.get(stats_key) or {}
        llm_calls = int(scan_stats.get("llmCalls") or 0)
        failed_calls = int(scan_stats.get("failedCalls") or 0)
        driver_failures = output.get("model_call_failures") if isinstance(output, dict) else None
        driver_failures = (driver_failures if isinstance(driver_failures, int) and
                           not isinstance(driver_failures, bool) and driver_failures >= 0 else None)
        driver_recovered = output.get("model_call_failures_recovered") if isinstance(output, dict) else None
        driver_recovered = (driver_recovered if isinstance(driver_recovered, int) and
                            not isinstance(driver_recovered, bool) and driver_recovered >= 0 else None)
        driver_unrecovered_reported = (output.get("model_call_failures_unrecovered")
                                       if isinstance(output, dict) else None)
        driver_unrecovered_reported = (
            driver_unrecovered_reported
            if isinstance(driver_unrecovered_reported, int)
            and not isinstance(driver_unrecovered_reported, bool)
            and driver_unrecovered_reported >= 0 else None)
        # A new driver keeps its historical failure count and supplies a partition of it. Trust
        # that partition only when all three integers reconcile; an older or malformed output
        # falls back to treating every observed failure as unresolved.
        if (driver_failures is not None and driver_recovered is not None
                and driver_unrecovered_reported is not None
                and driver_recovered + driver_unrecovered_reported == driver_failures):
            driver_unrecovered = driver_unrecovered_reported
        else:
            driver_recovered = None
            driver_unrecovered = driver_failures
        notes.append(f"Harness self-report: llm_calls={llm_calls} failed_calls={failed_calls} "
                     f"coverage={scan_stats.get('hypothesisCoverage')} status={scan_stats.get('status')} "
                     f"runtime_profile={usable_summary.get('runtimeProfile')} degraded={usable_summary.get('degraded')}")
        if driver_failures is not None:
            notes.append("ScanEval driver observation: "
                         f"failed_runner_invocations={driver_failures} "
                         f"recovered_planner_timeouts={driver_recovered if driver_recovered is not None else 'unavailable'} "
                         f"unrecovered_runner_invocations={driver_unrecovered}.")
        if mode == "pr":
            advisories = scan_stats.get("advisories")
            if not scan_stats:
                notes.append("The harness summary carried no changeScan record, so its own account of how the "
                             "review went is unavailable; llm_calls and failed_calls above are zero because "
                             "nothing was reported, not because nothing was called.")
            elif scan_stats.get("status") == "skipped" or advisories:
                notes.append("The harness reported its own account of the change scan: status="
                             f"{scan_stats.get('status')} advisories={advisories}. A change scan the harness "
                             "skips is its native scope, not a failure of this run.")
        if result.exit_code not in (0, 2):
            return NativeOutcome(status="error", exit_code=result.exit_code,
                                 error={"code": f"driver_exit_{result.exit_code}",
                                        "message": with_loss(stderr_tail())}, **base)
        if llm_calls and failed_calls >= llm_calls:
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "llm_path_failed", "message": with_loss("every harness model call failed; findings come from deterministic passes only")}, **base)
        if failed_calls > 0 or (driver_unrecovered is not None and driver_unrecovered > 0):
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "llm_calls_failed",
                                        "message": with_loss(f"unrecovered model calls failed: harness={failed_calls}, "
                                                             f"driver={driver_unrecovered if driver_unrecovered is not None else 'unavailable'} "
                                                             f"(observed={driver_failures if driver_failures is not None else 'unavailable'}, "
                                                             f"recovered={driver_recovered if driver_recovered is not None else 'unavailable'})")},
                                 **base)
        scan_status = scan_stats.get("status")
        # Recovery clears exactly one observed timeout reason; it does not manufacture a
        # successful native scan. Require the active mode's explicit terminal scan record when
        # a recovery partition is what lowered the driver failure count. A PR-native skip is an
        # explicit terminal scope decision, as above, rather than absent coverage.
        recovery_without_complete_scan = (
            driver_recovered is not None and driver_recovered > 0
            and (not scan_stats or scan_status not in ({"ok", "complete", "skipped"}
                                                        if mode == "pr" else {"ok", "complete"}))
        )
        if (usable_summary.get("degradation") or scan_status == "inconclusive"
                or recovery_without_complete_scan):
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "harness_inconclusive",
                                        "message": with_loss(f"degradation={usable_summary.get('degradation')} scan_status={scan_status} reasons={scan_stats.get('reasons')}")}, **base)
        if native_completion_code:
            # The engine's native reports are additive. Either one's fail-closed statement prevents
            # success while preserving imported findings and the other report's notes.
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": native_completion_code,
                                        "message": with_loss(native_completion_message or "native completion evidence is unavailable")[:2000]},
                                 **base)
        if loss_message:
            # A scan whose findings did not all survive the import is not a clean run: it is
            # partial, and the count and the reason travel with it as an explicit error.
            return NativeOutcome(status="partial", exit_code=result.exit_code,
                                 error={"code": "import_loss", "message": loss_message}, **base)
        return NativeOutcome(status="success", exit_code=result.exit_code, **base)
