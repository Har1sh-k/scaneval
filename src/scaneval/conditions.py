"""Deterministic evaluation-condition classification from saved invocation artifacts.

A condition is independent of a source profile. The standard snapshot keeps repository identity;
closed-book describes the evidence for history and retrieval restrictions, never model memory.
Records are hashes of saved bytes, not signatures: the evaluator and execution backend remain
trusted, and an operator able to rewrite every artifact can construct a different evidence set.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable

from .contracts import (ContractError, _reject_json_constant, _strict_object, canonical_sha256,
                        reject_nonfinite, validate_document)
from .trace import parse_trace


KIND = "condition-record"
RECORD_FILE = "condition.json"
POLICY_FILE = "condition-policy.json"
CONFIGURATION_FILE = "condition-configuration.json"
PROVENANCE_FILE = "input-provenance.json"
EVIDENCE_FILE = "condition-evidence.json"
STATUSES = ("attested", "declared_only", "failed", "unavailable")
NAMES = ("closed_book_standard", "open_context", "identity_reduced")
IDENTITY_FORMAT = "condition-structural-v1"
TOOLS = ("browser", "web_search", "remote_fetch", "package_install", "scanner_update")
_LOCAL_TOOLS = frozenset({"read", "write", "edit", "multiedit", "glob", "grep", "ls",
                          "read_file", "list_directory", "search_files", "apply_patch"})
_RETRIEVAL_TOOLS = frozenset({"websearch", "web_search", "webfetch", "web_fetch", "browser",
                              "browse", "remote_fetch", "fetch_url", "package_install", "scanner_update", "curl", "wget"})


def resolve_condition(condition: dict | None = None, *, profile: str = "standard",
                      mode: str = "full") -> dict:
    """Complete a condition declaration without equating that declaration with attestation."""
    name = "identity_reduced" if profile in ("identity_reduced", "metadata_blinded") else "closed_book_standard"
    if condition is not None and not isinstance(condition, dict):
        raise ContractError("condition must be an object")
    value = {"name": name, "policy": {}} if condition is None else dict(condition)
    if set(value) - {"name", "policy"} or value.get("name") not in NAMES:
        raise ContractError(f"condition must name one of {', '.join(NAMES)} and an optional policy object")
    value.setdefault("policy", {})
    if not isinstance(value["policy"], dict):
        raise ContractError("condition.policy must be an object")
    canonical_sha256(value)
    return value


def _bytes(root: Path, relative: str) -> bytes:
    """Read an ordinary saved file inside the bundle; refuse links and special files."""
    from .execution import read_regular_file
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ContractError("condition artifact path must be bundle-relative without parent components")
    path = root / relative
    try:
        inside = path.resolve().is_relative_to(root)
    except (OSError, RuntimeError) as exc:
        raise ContractError(f"condition artifact path cannot be resolved: {relative}") from exc
    if not inside:
        raise ContractError(f"condition artifact resolves outside its bundle: {relative}")
    current = path
    while current != root:
        if current.is_symlink():
            raise ContractError(f"condition artifact is a symbolic link: {relative}")
        current = current.parent
    try:
        return read_regular_file(path)
    except OSError as exc:
        raise ContractError(f"could not read condition artifact {relative}: {type(exc).__name__}: {exc.strerror or 'read failed'}") from exc
    except ValueError as exc:
        raise ContractError(f"could not read condition artifact {relative}: {str(exc).replace(str(root), '<bundle>')}") from exc


def _json(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object,
                           parse_constant=_reject_json_constant)
        reject_nonfinite(value)
        if not isinstance(value, dict):
            raise ValueError("expected an object")
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContractError(f"invalid saved condition evidence: {exc}") from exc


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _reason(code: str, message: str) -> dict:
    return {"code": code, "message": message}


def _check_evidence(value: dict) -> None:
    for key in ("history", "controls"):
        if key in value and not isinstance(value[key], dict):
            raise ContractError(f"condition evidence {key} must be an object")
    for key in ("before", "after"):
        if key in value.get("history", {}) and not isinstance(value["history"][key], dict):
            raise ContractError(f"condition history {key} must be an object")
    controls = value.get("controls", {})
    if value.get("trace") is not None and not isinstance(value["trace"], dict):
        raise ContractError("condition evidence trace must be an object or null")
    for key in ("tools", "provider"):
        if key in controls and not isinstance(controls[key], dict):
            raise ContractError(f"condition controls {key} must be an object")
    hosts = controls.get("provider", {}).get("inference_hosts")
    if hosts is not None and (not isinstance(hosts, list) or not all(isinstance(host, str) for host in hosts)):
        raise ContractError("provider inference_hosts must be a list of host:port strings")


def _verify_previous(root: Path, record: dict) -> dict:
    record["artifacts"].sort(key=lambda item: (item["role"], item["path"]))
    record["bindings"].update({item["role"] + "_sha256": item["sha256"]
                                for item in record["artifacts"]})
    if (root / RECORD_FILE).exists():
        try:
            previous = _json(_bytes(root, RECORD_FILE))
            validate_document(KIND, previous)
            if record_identity(previous) != record_identity(record):
                record["status"] = "failed"
                record["reasons"].insert(0, _reason("stale_condition_record", "The saved condition record does not match the exact artifacts now present."))
        except ContractError as exc:
            record["status"] = "failed"
            record["reasons"].insert(0, _reason("invalid_condition_record", str(exc)))
    return validate_document(KIND, record)


def record_identity(record: dict) -> str:
    """Versioned structural identity, including artifact hashes and reason codes, excluding prose.

    This is deliberately named an identity digest, not the byte hash of ``condition.json``.
    Human-readable reason messages may differ by operating system or locale without changing
    saved evidence or the condition's structural conclusion.
    """
    projection = {**record, "reasons": [{"code": row["code"]} for row in record["reasons"]]}
    return canonical_sha256({"format": IDENTITY_FORMAT, "record": projection})


def _configured_retrieval(config: dict) -> bool:
    """Recognize explicit enabling flags/tool lists; prose is never interpreted as configuration."""
    for key, value in config.items():
        normalized = str(key).lower().replace("-", "_")
        if normalized in {"tools", "enabled_tools", "allowed_tools"}:
            listed = value if isinstance(value, list) else re.split(r"[,;\s]+", value) if isinstance(value, str) else []
            if any(isinstance(item, str) and _is_retrieval_tool(item) for item in listed):
                return True
        if normalized in {*TOOLS, "web", "browsing", "web_retrieval", "provider_retrieval",
                          "enable_browser", "enable_web_search", "enable_retrieval"} or normalized in _RETRIEVAL_TOOLS:
            if value is True or isinstance(value, str) and value.casefold() in {"on", "true", "yes", "enabled", "allowed"}:
                return True
            if isinstance(value, dict) and any(value.get(key) is True or isinstance(value.get(key), str)
                                               and value[key].casefold() in {"on", "true", "yes", "enabled", "allowed"}
                                               for key in ("enabled", "allow", "allowed")):
                return True
        if isinstance(value, dict) and _configured_retrieval(value):
            return True
    return False


def _is_retrieval_tool(name: str) -> bool:
    normalized = name.casefold()
    if normalized in _RETRIEVAL_TOOLS or normalized.startswith(("mcp__browser__", "mcp__web__", "mcp__playwright__", "browser.", "web.")):
        return True
    if normalized.startswith("mcp:") and "/" in normalized:
        server, tool = normalized[4:].split("/", 1)
        return server in {"web", "browser", "playwright"} or tool in _RETRIEVAL_TOOLS
    if normalized.startswith("mcp:"):
        return normalized[4:] in _RETRIEVAL_TOOLS
    return False


def _history(evidence: dict, execution: dict) -> tuple[str, list[dict]]:
    observations = evidence.get("history") or {}
    before, after = observations.get("before") or {}, observations.get("after") or {}
    states = (before.get("state"), after.get("state"))
    if "unexpected" in states:
        return "unexpected", [_reason("unexpected_history", "A saved mechanical audit found unexpected Git history or controller state.")]
    if (states[0] != states[1] or states[0] not in ("original_absent", "neutral_synthetic", "bounded_ancestor_history")):
        return "unavailable", [_reason("history_audit_gap", "Before and after history audits are missing or disagree.")]
    if states[0] in ("neutral_synthetic", "bounded_ancestor_history"):
        if (not before.get("git_files_sha256")
                or before["git_files_sha256"] != after.get("git_files_sha256")):
            return "unexpected", [_reason("history_changed", "The repository metadata changed during execution.")]
        if states[0] == "neutral_synthetic":
            neutral = execution["provenance"].get("synthetic_history") or {}
            if execution["provenance"].get("mode") == "pr":
                from .materialize import PR_HISTORY_DATE, PR_HISTORY_IDENTITY, PR_HISTORY_MESSAGES
                pr = execution["provenance"].get("pr") or {}
                valid = (neutral.get("messages") == PR_HISTORY_MESSAGES
                         and neutral.get("identity") == PR_HISTORY_IDENTITY and neutral.get("date") == PR_HISTORY_DATE
                         and all(isinstance(neutral.get(key), str) and re.fullmatch(r"[0-9a-f]{40}", neutral[key])
                                 and neutral[key] == pr.get(key) for key in ("base_commit", "head_commit")))
            else:
                valid = (neutral.get("message") == "snapshot" and neutral.get("identity") == "ScanEval <scaneval@localhost>"
                         and isinstance(neutral.get("commit"), str) and re.fullmatch(r"[0-9a-f]{40}", neutral["commit"]))
            if not valid:
                return "unexpected", [_reason("non_neutral_history", "The saved synthetic history is not the minimal neutral snapshot repository.")]
    return states[0], []


def _network(execution: dict, controls: dict) -> tuple[str, list[dict], list[dict]]:
    declared = execution["network_policy"]["declared"]
    failed: list[dict] = []
    gaps: list[dict] = []
    inference = controls.get("inference", "unknown")
    if declared not in ("none", "model_provider_only"):
        failed.append(_reason("unrestricted_network", "Unrestricted network access is incompatible with closed-book standard."))
    if inference == "offline" and declared != "none":
        failed.append(_reason("offline_network_policy", "An offline scanner must declare network_policy none."))
    if inference == "remote" and declared != "model_provider_only":
        failed.append(_reason("remote_inference_policy", "Remote inference requires the model_provider_only route."))
    isolation = execution.get("isolation") or {}
    actual = isolation.get("network") or {}
    enforced = (execution["network_policy"]["enforced"] is True
                and isolation.get("backend") == "oci" and isolation.get("enforced") is True
                and actual.get("enforced") is True and actual.get("policy") == declared
                and any(item.get("role") == "worker" and item.get("started") is True
                        for item in isolation.get("containers", [])))
    if declared == "model_provider_only":
        proxy = actual.get("proxy") or {}
        allowed = proxy.get("allow")
        hosts = (controls.get("provider") or {}).get("inference_hosts")
        if (not isinstance(allowed, list) or not allowed or not all(isinstance(item, str) for item in allowed)
                or not isinstance(hosts, list) or not hosts):
            enforced = False
            gaps.append(_reason("provider_route_gap", "Saved evidence does not bind the egress allowlist to remote-inference hosts."))
        elif set(allowed) - set(hosts):
            failed.append(_reason("unrelated_egress", "The egress allowlist permits destinations outside the recorded inference route."))
        elif (actual.get("mode") != "internal network with egress proxy"
              or not any(item.get("role") == "proxy" and item.get("started") is True
                         for item in isolation.get("containers", []))):
            enforced = False
            gaps.append(_reason("provider_route_unenforced", "The saved backend record does not establish an isolated inference proxy route."))
    elif declared == "none" and actual.get("mode") != "none":
        enforced = False
    if not enforced:
        gaps.append(_reason("network_unenforced", "A declared local network policy is not evidence of enforced isolation."))
    return "enforced" if enforced else "unenforced", failed, gaps


def _retrieval(execution: dict, evidence: dict, trace: Any) -> tuple[str, str, list[dict], list[dict]]:
    controls = evidence.get("controls") or {}
    tools = controls.get("tools") or {}
    failed, gaps = [], []
    if _configured_retrieval(execution["system_config"]) or any(tools.get(name) == "enabled" for name in TOOLS):
        failed.append(_reason("retrieval_enabled", "Configuration or adapter controls enable a prohibited retrieval tool."))
    unknown_tools = False
    if trace is not None:
        for event in trace.events:
            if event["type"] != "tool.start":
                continue
            metadata = event.get("metadata") or {}
            name = metadata.get("tool_name") or metadata.get("name") or ""
            # A filename, search pattern, or quoted source mentioning curl/browser is ordinary
            # input. Only structured tool identity establishes a retrieval operation here.
            normalized = name.lower() if isinstance(name, str) else ""
            if _is_retrieval_tool(normalized):
                failed.append(_reason("retrieval_observed", "A saved tool event records a prohibited retrieval operation."))
            if not isinstance(name, str) or name.lower() not in _LOCAL_TOOLS:
                unknown_tools = True
    if failed:
        return "enabled", "tool_enabled", failed, gaps
    complete = (trace is not None and trace.state == "valid" and not unknown_tools
                and execution["capture"].get("tool_calls") == "complete"
                and (execution.get("trace") or {}).get("capture_gap") is False
                and (execution.get("trace") or {}).get("dropped_events") == 0)
    trace_gap = ((execution.get("trace") or {}).get("capture_gap") is True
                 or bool((execution.get("trace") or {}).get("dropped_events"))
                 or (trace is not None and trace.state not in ("valid", "empty")))
    disabled = (controls.get("basis") == "adapter_controls"
                and all(tools.get(name) == "disabled" for name in TOOLS))
    if disabled and not trace_gap:
        return "disabled", "tool_disabling", failed, gaps
    if complete:
        return "observed_none", "complete_observation", failed, gaps
    gaps.append(_reason("retrieval_capture_gap", "Tool visibility is incomplete; absent events do not establish absence of retrieval."))
    return "capture_gap", "capture_gap", failed, gaps


def _provider(root: Path, execution: dict, configuration: dict, controls: dict,
              artifacts: list[dict]) -> tuple[str, dict, list[dict], list[dict]]:
    provider = controls.get("provider") or {}
    capability = provider.get("capability", "unverifiable")
    control = provider.get("control", "unverifiable")
    detail = {"capability": capability, "control": control, "attestation": "missing"}
    if controls.get("inference") == "offline" and capability == "not_applicable":
        detail["attestation"] = "not_applicable"
        return "not_applicable", detail, [], []
    if control == "enabled":
        return "enabled", detail, [_reason("provider_retrieval_enabled", "Provider-hosted retrieval is enabled.")], []
    reference = provider.get("attestation")
    if isinstance(reference, dict):
        try:
            path = reference["path"]
            registered = {item["path"]: item["sha256"] for item in execution["raw_artifacts"]}
            raw = _bytes(root, path)
            digest = _digest(raw)
            if digest != reference["sha256"] or registered.get(path) != digest:
                raise ContractError("provider attestation does not bind to a registered artifact")
            attestation = _json(raw)
            model = configuration.get("model_id") or (execution.get("model_identity") or {}).get("requested")
            if (attestation.get("scope") != "invocation"
                    or attestation.get("invocation_id") != execution["invocation_id"]
                    or attestation.get("system_id") != execution["system_id"]
                    or not model or attestation.get("model_id") != model
                    or not provider.get("name") or attestation.get("provider") != provider["name"]
                    or attestation.get("retrieval_disabled") is not True
                    or control != "disabled"):
                raise ContractError("provider attestation is not applicable to this invocation and requested control")
            artifacts.append({"role": "provider_attestation", "path": path, "sha256": digest})
            # Matching hashes and invocation scope bind this assertion to the run; they do
            # not authenticate a provider. No provider verifier is implemented by this build.
            detail["attestation"] = "self_reported"
            return "unverifiable", detail, [], [_reason("provider_attestation_unverified", "The saved assertion is bound to this invocation but has no trusted provider verification.")]
        except (KeyError, TypeError, ContractError) as exc:
            detail["attestation"] = "inapplicable"
            return "unverifiable", detail, [], [_reason("provider_attestation_gap", str(exc))]
    return "unverifiable", detail, [], [_reason("provider_unverifiable", "No applicable saved provider attestation establishes that provider retrieval was disabled.")]


def classify_observation(bundle: str | Path, *, condition: dict | None = None,
                         identity_profile: str | None = None, input_mode: str | None = None) -> dict:
    """Classify one saved bundle; never promote legacy declarations to attested evidence.

    Missing execution/input/trace evidence produces an unavailable or declared-only record. An
    existing ``condition.json`` is verified against recomputed evidence, including exact file
    hashes, and never trusted as an assertion. No artifact is modified by this function.
    """
    root = Path(bundle).expanduser().resolve()
    artifacts: list[dict] = []
    documents: dict[str, dict] = {}
    gaps: list[dict] = []
    failed: list[dict] = []
    names = {"request": "request.json", "result": "result.json", "execution": "execution.json",
             "policy": POLICY_FILE, "configuration": CONFIGURATION_FILE,
             "provenance": PROVENANCE_FILE, "evidence": EVIDENCE_FILE}
    kinds = {"request": "scan-request", "result": "scan-result", "execution": "execution-record"}
    for role, relative in names.items():
        try:
            raw = _bytes(root, relative)
            value = _json(raw)
            if role in kinds:
                validate_document(kinds[role], value)
            if role == "evidence":
                _check_evidence(value)
            documents[role] = value
            artifacts.append({"role": role, "path": relative, "sha256": _digest(raw)})
        except ContractError as exc:
            (failed if role == "policy" and (root / relative).exists() else gaps).append(
                _reason("invalid_condition_policy" if role == "policy" and (root / relative).exists() else "missing_" + role, str(exc)))
    execution, result, request = (documents.get(name, {}) for name in ("execution", "result", "request"))
    profile = (execution.get("provenance") or {}).get("profile", (request.get("input") or {}).get("profile", identity_profile or "standard"))
    mode = (execution.get("provenance") or {}).get("mode", (request.get("input") or {}).get("mode", input_mode or "full"))
    saved_policy = documents.get("policy")
    policy = ({key: value for key, value in saved_policy.items() if key != "declared"}
              if saved_policy is not None else None)
    try:
        declaration = resolve_condition(condition or policy or execution.get("condition"), profile=profile, mode=mode)
    except ContractError as exc:
        failed.append(_reason("invalid_condition_policy", str(exc)))
        declaration = resolve_condition(profile=profile, mode=mode)
    # The keyword carries an expectation from a schedule/caller. It cannot turn an inferred
    # observation into an explicitly declared one or make reclassification depend on the caller.
    declared = (saved_policy or {}).get("declared") is True
    record = {"schema_version": "2.1", "condition": declaration["name"], "status": "unavailable",
              "identity_profile": profile, "history": "unavailable", "retrieval": "capture_gap",
              "mode": mode,
              "declared": declared,
              "network": "unenforced", "provider_retrieval": "unverifiable",
              "run_id": execution.get("run_id", result.get("run_id", "unknown")),
              "invocation_id": execution.get("invocation_id", root.name),
              "system_id": execution.get("system_id", result.get("system_id", "unknown")),
              "input_hash": result.get("input_hash", (execution.get("provenance") or {}).get("tree_hash")),
              "policy_sha256": canonical_sha256(declaration), "artifacts": artifacts,
              "bindings": {"adapter_sha256": canonical_sha256(execution["adapter"]) if execution else None,
                           "configuration_sha256": canonical_sha256(documents["configuration"]) if "configuration" in documents else None,
                           "input_hash": result.get("input_hash"),
                           "tree_hash": (execution.get("provenance") or {}).get("tree_hash")},
              "retained_identity_cues": (documents.get("provenance") or {}).get("retained_identity_cues", {
                  "instruction_files": (documents.get("provenance") or {}).get("instruction_files", []),
                  "source_identifiers": "retained" if profile == "standard" else "unverified",
                  "ordinary_paths": "retained" if profile == "standard" else "unverified"}),
              "assurance": {"network": "declared", "retrieval": "capture_gap", "provider": "unverifiable"},
              "provider": {}, "details": {}, "reasons": []}
    trace = None
    trace_meta = execution.get("trace") or {}
    trace_binding = (documents.get("evidence") or {}).get("trace") or {}
    if trace_meta.get("path"):
        try:
            raw = _bytes(root, trace_meta["path"])
            trace = parse_trace(raw)
            artifacts.append({"role": "trace", "path": trace_meta["path"], "sha256": _digest(raw)})
            if not trace_binding:
                gaps.append(_reason("trace_binding_unavailable", "No saved execution-time digest binds the trace bytes."))
                trace = None
            elif trace_binding.get("path") != trace_meta["path"] or trace_binding.get("sha256") != _digest(raw):
                failed.append(_reason("trace_binding_mismatch", "The saved trace differs from its execution-time digest."))
                trace = None
            if trace is not None and any(event["run_id"] != execution.get("run_id") for event in trace.events):
                failed.append(_reason("trace_run_mismatch", "A trace event belongs to a different run."))
                trace = None
            if trace is not None and trace_binding.get("run_ids") != sorted({event["run_id"] for event in trace.events}):
                failed.append(_reason("trace_run_binding_mismatch", "The saved trace run identities differ from their execution-time binding."))
                trace = None
            if trace is not None and trace_meta.get("events") != len(trace.events):
                gaps.append(_reason("trace_count_mismatch", "The saved trace count differs from the execution record."))
                trace = None
        except ContractError as exc:
            gaps.append(_reason("trace_unavailable", str(exc)))
    if not execution or not result:
        record["status"] = "failed" if failed else "unavailable"
        record["reasons"] = failed + gaps
        return _verify_previous(root, record)
    expected_input = execution["provenance"].get("input_hash", execution["provenance"]["tree_hash"])
    if (execution["run_id"] != result["run_id"] or execution["system_id"] != result["system_id"]
            or result["input_hash"] != expected_input
            or (request and (request["run_id"] != execution["run_id"]
                             or request["system"]["id"] != execution["system_id"]
                             or request["input"]["tree_hash"] != execution["provenance"]["tree_hash"]))):
        failed.append(_reason("observation_binding_mismatch", "Saved request, execution, and result do not describe the same observation."))
    provenance = documents.get("provenance")
    if provenance is not None:
        source_record = provenance.get("head", provenance) if mode == "pr" else provenance
        source_record = source_record if isinstance(source_record, dict) else {}
        recorded_profile = provenance.get("profile", source_record.get("profile"))
        trial = source_record.get("trial")
        recorded_tree = trial.get("tree_hash") if isinstance(trial, dict) else None
        if (canonical_sha256(provenance) != execution["provenance"]["provenance_sha256"]
                or recorded_profile is not None and recorded_profile != profile
                or recorded_tree is not None and recorded_tree != execution["provenance"]["tree_hash"]):
            failed.append(_reason("input_provenance_mismatch", "Saved input provenance contradicts the executed source tree."))
        elif recorded_profile is None or recorded_tree is None:
            gaps.append(_reason("input_provenance_incomplete", "Saved preparation notes do not establish the full export profile and tree identity."))
    configuration = documents.get("configuration", {})
    if configuration and (configuration.get("system_id") != execution["system_id"]
            or configuration.get("config") != execution["system_config"]
            or configuration.get("network_policy") != execution["network_policy"]["declared"]):
        failed.append(_reason("configuration_mismatch", "The saved configuration differs from the execution record."))
    if configuration:
        actual_adapter = configuration.get("adapter_identity") or {"name": configuration.get("adapter"),
                                                                   "version": execution["adapter"]["version"]}
        if actual_adapter != execution["adapter"]:
            failed.append(_reason("adapter_identity_mismatch", "The saved adapter identity differs from the execution record."))
        if request and any(configuration.get(key) != request["system"].get(key)
                           for key in ("model_id", "model_revision")):
            failed.append(_reason("model_configuration_mismatch", "The saved model identity/revision differs from the invocation request."))
        requested_model = (execution.get("model_identity") or {}).get("requested")
        adapter_config = configuration.get("config")
        adapter_model = adapter_config.get("model") if isinstance(adapter_config, dict) else None
        if isinstance(adapter_model, str) and requested_model is not None and adapter_model != requested_model:
            failed.append(_reason("model_identity_mismatch", "The executed model identity differs from the saved requested model."))
    if execution.get("condition") is not None and execution["condition"] != declaration:
        failed.append(_reason("condition_policy_mismatch", "The saved policy differs from the execution's condition."))
    if policy is not None and policy != declaration:
        failed.append(_reason("condition_policy_mismatch", "The requested condition differs from the saved condition policy."))
    evidence = documents.get("evidence", {})
    controls = evidence.get("controls") or {}
    record["details"]["history_audit"] = evidence.get("history", {})
    record["history"], history_reasons = _history(evidence, execution)
    (failed if record["history"] == "unexpected" else gaps).extend(history_reasons)
    if execution["provenance"]["source_modified"]:
        failed.append(_reason("source_modified", "The executed source changed from the frozen input."))
    identity_unavailable = False
    if declaration["name"] in ("closed_book_standard", "identity_reduced"):
        record["network"], network_failures, network_gaps = _network(execution, controls)
        failed.extend(network_failures)
        gaps.extend(network_gaps)
        record["retrieval"], assurance, retrieval_failures, retrieval_gaps = _retrieval(execution, evidence, trace)
        record["assurance"].update({"network": "external_enforcement" if record["network"] == "enforced" else "declared",
                                     "retrieval": assurance})
        failed.extend(retrieval_failures)
        gaps.extend(retrieval_gaps)
        record["provider_retrieval"], record["provider"], provider_failures, provider_gaps = _provider(
            root, execution, configuration, controls, artifacts)
        record["assurance"]["provider"] = record["provider"].get("attestation", "unverifiable")
        failed.extend(provider_failures)
        gaps.extend(provider_gaps)
        if controls.get("inference") not in ("offline", "remote"):
            gaps.append(_reason("inference_unverified", "The saved adapter controls do not establish offline or remote inference."))
        if declaration["name"] == "closed_book_standard":
            if profile != "standard" or mode != "full":
                failed.append(_reason("ineligible_input", "closed_book_standard requires the standard full-scan source profile."))
        else:
            from .conditions_identity import verify_saved_identity
            identity = verify_saved_identity(root, execution, documents.get("provenance", {}), evidence, artifacts)
            record["details"]["identity_reduction"] = identity["details"]
            record["assurance"]["identity"] = "saved_manifest_verified" if identity["state"] == "available" else "unavailable"
            summary = identity["details"].get("summary", {})
            record["retained_identity_cues"] = {"residual_categories": summary.get("residual_categories", []),
                                                "counts": summary.get("counts", {}),
                                                "source_identifiers": "residuals_reported"}
            if identity["state"] == "failed":
                failed.extend(identity["reasons"])
            elif identity["state"] != "available":
                identity_unavailable = True
                gaps.extend(identity["reasons"])
        if record["history"] == "bounded_ancestor_history":
            failed.append(_reason("original_history_present", "Original ancestor history is incompatible with a closed-book source condition."))
    elif declaration["name"] == "open_context":
        try:
            from . import open_context
        except ImportError:
            open_context = None
        classify = getattr(open_context, "classify_condition", None)
        if classify is None:
            gaps.append(_reason("condition_classifier_unavailable", "The open-context classifier is unavailable."))
        else:
            details = classify(root, execution, declaration["policy"], evidence)
            record["details"].update(details.get("details", {}))
            record["assurance"].update(details.get("assurance", {}))
            for reference in details.get("artifacts", []):
                try:
                    raw = _bytes(root, reference["path"])
                    if _digest(raw) != reference["sha256"]:
                        raise ContractError("condition extension artifact hash differs from saved bytes")
                    artifacts.append(reference)
                except (KeyError, TypeError, ContractError) as exc:
                    failed.append(_reason("condition_extension_artifact", str(exc)))
            for key in ("history", "retrieval", "network", "provider_retrieval"):
                if key in details:
                    record[key] = details[key]
            if details.get("status") == "failed":
                failed.extend(details.get("reasons", []))
            elif details.get("status") != "attested":
                gaps.extend(details.get("reasons", []))
    legacy = not all(key in documents for key in ("evidence", "provenance", "configuration", "policy"))
    eligibility_failures = {"unexpected_history", "history_changed", "non_neutral_history", "source_modified",
                            "ineligible_input", "original_history_present", "unrestricted_network", "offline_network_policy",
                            "remote_inference_policy", "unrelated_egress", "retrieval_enabled", "retrieval_observed",
                            "provider_retrieval_enabled"}
    inferred_ineligible = (not declared and declaration["name"] in ("closed_book_standard", "identity_reduced") and failed
                           and all(row["code"] in eligibility_failures for row in failed))
    record["status"] = ("unavailable" if inferred_ineligible else "failed" if failed
                        else "unavailable" if execution["status"] == "unsupported" or legacy or identity_unavailable
                        else "declared_only" if gaps else "attested")
    record["reasons"] = failed + gaps
    if not record["reasons"]:
        record["reasons"] = [_reason("saved_evidence_verified", "Saved input, history, retrieval controls, provider state, and enforced network evidence satisfy the condition.")]
    return _verify_previous(root, record)


def condition_coverage(records: Iterable[dict]) -> list[dict]:
    """Count each condition/status stratum explicitly without pooling detection metrics."""
    counts = Counter((row.get("system_id", "unknown"), row.get("mode", "full"), row["condition"],
                      row["status"], row["identity_profile"], row["policy_sha256"]) for row in records)
    return [{"system_id": system, "mode": mode, "condition": name, "status": status,
             "identity_profile": profile, "policy_sha256": policy, "observations": count}
            for (system, mode, name, status, profile, policy), count in sorted(counts.items())]
