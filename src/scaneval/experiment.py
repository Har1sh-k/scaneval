"""Frozen three-condition experiments with explicit context differences and missingness.

No function here recognizes a vulnerability or adjudicates a finding. A frozen population uses
the existing schedule planner's eligibility and binds the complete case pack, including labels
and accepted locations, outside every scanner input.
"""

from __future__ import annotations

from copy import deepcopy
from importlib.resources import files
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from . import blinding, cases, conditions, schedule
from .adapters import get_adapter
from .contracts import (ContractError, canonical_sha256, load_document, reject_nonfinite,
                        validate_document)
from .execution import invocation_id
from .isolation import PINNED_IMAGE, IsolationError, resolve_execution
from .resampling import ALGORITHM, Stream, sample_without_replacement


KIND = "experiment-matrix"
NAMES = ("open_context", "closed_book_standard", "identity_reduced")
CONTEXT_DIFFERENCES = frozenset({"profile", "transformation_map", "history", "network", "retrieval"})
_CONTEXT_EXECUTION = frozenset({"egress", "proxy_image", "retrieval"})
AGGREGATION_POLICY = {"policy_id": "scaneval.matrix.equal-canonical-target", "version": "1"}
CAPABILITIES = frozenset({"external_isolation", "history", "retrieval_events", "identity_manifest",
                          "tool_controls", "model_requests", "tool_calls", "context_spans"})


def resolve_aggregation_policy(value: dict) -> dict:
    allowed = {"policy_id", "version", "views", "target_weights", "workload_weights"}
    if (not isinstance(value, dict) or set(value) - allowed
            or any(value.get(key) != expected for key, expected in AGGREGATION_POLICY.items())
            or value.get("views", ["equal_target"]) != ["equal_target"]
            or value.get("target_weights") is not None or value.get("workload_weights") is not None):
        raise ContractError("matrix v1 supports only its versioned equal-canonical-target policy; other views or custom/workload weights are unavailable")
    return {**AGGREGATION_POLICY, "views": ["equal_target"], "target_weights": None, "workload_weights": None}


def _cell_order(document: dict) -> list[str]:
    order = list(document["run_order"].get("cells", NAMES))
    if document["run_order"]["method"] == "seeded_cell_order":
        order = sample_without_replacement(order, len(order), Stream(document["run_order"]["seed"],
            label="experiment-cell-order:" + document["experiment_id"] + ":" + document["experiment_version"]))
    return order


def _schema_validate(document: dict) -> None:
    schema = json.loads(files("scaneval").joinpath("schemas", KIND + ".schema.json").read_text())
    reject_nonfinite(document)
    errors = list(Draft202012Validator(schema).iter_errors(document))
    if errors:
        error = errors[0]
        raise ContractError(f"experiment matrix {'.'.join(map(str, error.absolute_path))}: {error.message}")


def matrix_digest(document: dict) -> str:
    return canonical_sha256({key: value for key, value in document.items() if key != "matrix_sha256"})


def _unique(rows: list[dict], field: str, label: str) -> None:
    values = [row[field] for row in rows]
    if len(values) != len(set(values)):
        raise ContractError(f"duplicate {label}")


def validate_matrix(document: dict) -> dict:
    """Validate declaration semantics; no arbitrary scanner/model/scope difference can be waived."""
    _schema_validate(document)
    if document["stage"] == "frozen":
        return validate_frozen(document)
    _unique(document["systems"], "system_id", "experiment system_id")
    _unique(document["conditions"], "name", "condition name")
    if {row["name"] for row in document["conditions"]} != set(NAMES):
        raise ContractError("an experiment must define all three core conditions exactly once")
    if set(document["allowed_differences"]) != CONTEXT_DIFFERENCES:
        raise ContractError("allowed_differences must name only the five declared context differences")
    systems = {row["system_id"]: row for row in document["systems"]}
    for row in systems.values():
        if row["inference"] == "remote" and (not row.get("model_id") or not row.get("model_revision")):
            raise ContractError("a remote experiment system requires exact model_id and model_revision")
        if set(row["execution"]) & _CONTEXT_EXECUTION:
            raise ContractError("network/retrieval execution controls belong in each condition's system_context")
        try:
            resolve_execution(row["execution"], "none")
        except IsolationError as exc:
            raise ContractError(f"invalid common execution settings: {exc}") from exc
        if row["execution"].get("backend") != "oci":
            raise ContractError("a three-condition experiment requires external OCI isolation for every cell")
    for row in document["conditions"]:
        name = row["name"]
        expected = (("standard", "bounded_ancestor", "recorded_public", "preserved") if name == "open_context"
                    else ("identity_reduced", "none", "disabled", "reduced") if name == "identity_reduced"
                    else ("standard", "none", "disabled", "preserved"))
        if tuple(row[key] for key in ("profile", "history", "retrieval", "identity")) != expected:
            raise ContractError(f"{name} has incompatible profile/history/retrieval/identity settings")
        if name == "open_context":
            policy = row["policy"]
            if (set(policy) != {"history", "retrieval", "web_mode", "capture", "retention"}
                    or policy.get("history") != "ancestor_history_v1" or policy.get("retrieval") != "recorded_public_v1"
                    or policy.get("web_mode") != "live"
                    or (policy.get("capture"), policy.get("retention")) not in (("content", "bundle"), ("hashes", "hashes_only"))):
                raise ContractError("open-context matrix policy is unknown, stale, or incompatible")
        elif row["policy"]:
            raise ContractError("matrix v1 closed conditions use their standard restriction policy; custom condition policies are unavailable")
        if set(row["system_context"]) != set(systems):
            raise ContractError(f"{name} must declare context controls for exactly the common systems")
        maps = row.get("transformation_maps", {})
        if name == "identity_reduced":
            if set(maps) != set(document["population"]["snapshot_ids"]):
                raise ContractError("identity_reduced must pin a reviewed transformation map for every snapshot")
        elif maps:
            raise ContractError(f"{name} does not apply an identity transformation")
        for system_id, context in row["system_context"].items():
            policy = context["network_policy"]
            controls = context.get("execution", {})
            if name == "open_context":
                if policy != "public_research" or systems[system_id]["execution"].get("backend") != "oci":
                    raise ContractError("open_context requires the controlled OCI public_research route")
                if not controls.get("retrieval"):
                    raise ContractError("open_context requires an explicit recorded public retrieval policy")
                retrieval = controls["retrieval"]
                if retrieval.get("policy") != row["policy"]["retrieval"] or any(
                        retrieval.get(key) != row["policy"][key] for key in ("capture", "retention")):
                    raise ContractError("condition and actual retrieval capture policies differ")
                if not isinstance(controls.get("proxy_image"), str) or not PINNED_IMAGE.fullmatch(controls["proxy_image"]):
                    raise ContractError("open-context requires a digest-pinned public retrieval proxy image")
                if not controls.get("egress"):
                    raise ContractError("open-context requires explicit allowed provider endpoints")
            else:
                expected_policy = "none" if systems[system_id]["inference"] == "offline" else "model_provider_only"
                if policy != expected_policy or controls.get("retrieval"):
                    raise ContractError(f"{name} must disable retrieval and use the inference-appropriate network route")
    if set(document["required_capture"]) != set(NAMES):
        raise ContractError("required_capture must state capabilities separately for all three conditions")
    for name, capabilities in document["required_capture"].items():
        minimum = {"external_isolation", "history"}
        minimum |= {"retrieval_events"} if name == "open_context" else {"tool_controls"}
        if name == "identity_reduced":
            minimum.add("identity_manifest")
        if not minimum <= set(capabilities) or set(capabilities) - CAPABILITIES:
            raise ContractError(f"{name} must declare supported required capture capabilities including {', '.join(sorted(minimum))}")
    order = document["run_order"]
    if "cells" in order and set(order["cells"]) != set(NAMES):
        raise ContractError("run_order.cells must include each core condition once")
    if order["method"] == "seeded_cell_order" and "seed" not in order:
        raise ContractError("seeded_cell_order requires a frozen seed")
    if order["method"] == "fixed" and "seed" in order:
        raise ContractError("fixed cell order does not use a random seed")
    excluded = {row["snapshot_id"] for row in document["exclusions"]}
    if excluded & set(document["population"]["snapshot_ids"]):
        raise ContractError("an excluded snapshot cannot also enter the experiment population")
    if document["uncertainty"]["method"] == "paired_cluster_bootstrap":
        if not {"replicates", "confidence", "seed", "min_clusters"} <= set(document["uncertainty"]):
            raise ContractError("paired_cluster_bootstrap requires replicates/confidence/seed/min_clusters")
    elif set(document["uncertainty"]) != {"method"}:
        raise ContractError("uncertainty method none does not apply resampling options")
    _unique(document.get("extensions", []), "cell_id", "optional extension cell")
    for extension in document.get("extensions", []):
        expected = ("bounded_ancestor", "disabled") if extension["cell_id"] == "git_only" else ("none", "recorded_public")
        if (extension["history"], extension["retrieval"]) != expected:
            raise ContractError("optional Git-only/web-only definitions must preserve their stated factor isolation")
    resolve_aggregation_policy(document["aggregation_policy"])
    return document


def _system_spec(row: dict) -> dict:
    return {key: deepcopy(value) for key, value in row.items() if key != "inference"}


def _population(pack: dict, document: dict) -> list[dict]:
    population = []
    target_ids, control_ids = set(), set()
    for snapshot_id in document["population"]["snapshot_ids"]:
        snapshot = cases.snapshot_by_id(pack, snapshot_id)
        planned = schedule._frozen_plan(pack, snapshot, "full")
        if planned["state"] != "frozen":
            raise ContractError(f"cannot freeze population for {snapshot_id}: {planned['reason']}")
        plan, _notes = cases.build_plan(pack, snapshot_id, snapshot["tree_hash"], mode="full")
        target_ids.update(row["canonical_id"] for row in planned["targets"])
        control_ids.update(row["canonical_id"] for row in planned["controls"])
        population.append({"snapshot_id": snapshot_id, "source_tree_hash": snapshot["tree_hash"],
                           "commit": snapshot["commit"], "project": snapshot["repository"]["name"],
                           "source_property": document["population"]["source_property"],
                           "plan": plan, "schedule_plan": planned})
    if target_ids != set(document["population"]["canonical_target_ids"]) or control_ids != set(document["population"]["canonical_control_ids"]):
        raise ContractError("declared canonical target/control populations differ from the schedule planner's exact eligibility")
    return population


def _assignments(document: dict, name: str, population: list[dict]) -> list[dict]:
    run_id = f"{document['experiment_id']}.{name}"
    return [{"condition": name, "run_id": run_id, "snapshot_id": source["snapshot_id"],
             "system_id": system["system_id"], "repetition": repetition,
             "assignment_id": invocation_id(source["snapshot_id"], system["system_id"], repetition)}
            for source in population for system in document["systems"]
            for repetition in range(1, document["repetitions"] + 1)]


def _config(document: dict, cell: dict, population: list[dict], map_bindings: dict[str, str]) -> dict:
    name = cell["name"]
    inputs = []
    for source in population:
        snapshot_id = source["snapshot_id"]
        entry = {"input_id": snapshot_id, "snapshot_id": snapshot_id, "mode": "full", "profile": cell["profile"],
                 "condition": {"name": name, "policy": deepcopy(cell["policy"])}}
        if name == "identity_reduced":
            digest = map_bindings[cell["transformation_maps"][snapshot_id]]
            entry["blinding_map"] = "maps/" + digest.removeprefix("sha256:") + ".json"
        inputs.append(entry)
    configured = []
    for system in document["systems"]:
        spec = _system_spec(system)
        context = cell["system_context"][system["system_id"]]
        spec["network_policy"] = context["network_policy"]
        spec["execution"].update(deepcopy(context.get("execution", {})))
        configured.append(spec)
    return {"schema_version": "2.1", "run_id": f"{document['experiment_id']}.{name}", "pack": "pack.json", "cache_root": "cache",
            "inputs": inputs, "systems": configured, "repetitions": document["repetitions"],
            "timeout_seconds": document["timeout_seconds"], "trace_mode": document["trace_mode"], "network_policy": "none"}


def freeze(document: dict, *, base_dir: Path, created_at: str, adapters: dict | None = None) -> dict:
    """Resolve and freeze every cell and assignment without fetching source or running a scanner."""
    validate_matrix(document)
    if document["stage"] != "declared":
        raise ContractError("freeze expects a declared matrix")
    base = Path(base_dir).expanduser().resolve()
    pack = load_document(base / document["pack"], "case-pack")
    population = _population(pack, document)
    for exclusion in document["exclusions"]:
        cases.snapshot_by_id(pack, exclusion["snapshot_id"])
    if len({row["snapshot_id"] for row in document["exclusions"]}) != len(document["exclusions"]):
        raise ContractError("duplicate predeclared snapshot exclusion")
    maps, cells, assignments, systems = {}, [], [], []
    map_bindings = {}
    for system in document["systems"]:
        adapter = (adapters or {}).get(system["adapter"]) or get_adapter(system["adapter"])
        if any(not isinstance(value, str) or not value for value in (adapter.name, adapter.adapter_version)):
            raise ContractError("experiment adapters must declare stable nonempty name and version")
        systems.append({**deepcopy(system), "adapter_identity": {"name": adapter.name, "version": adapter.adapter_version}})
    for cell in document["conditions"]:
        name = cell["name"]
        for source in population:
            snapshot_id = source["snapshot_id"]
            if name == "identity_reduced":
                map_path = cell["transformation_maps"][snapshot_id]
                mapping = blinding.load_map(base / map_path)
                gap = blinding.approval_gap(mapping)
                if gap:
                    raise ContractError(gap)
                variant = next((row for row in mapping["variants"] if row["snapshot_id"] == snapshot_id), None)
                if variant is None or (variant["commit"], variant["tree_hash"]) != (source["commit"], source["source_tree_hash"]):
                    raise ContractError("identity map is not bound to the experiment's exact source snapshot")
                if not isinstance(mapping.get("identity_policy"), dict):
                    raise ContractError("identity-reduced matrix cells require an explicit strict identity policy in every reviewed map")
                if mapping["repository"]["url"] != cases.snapshot_by_id(pack, snapshot_id)["repository"]["url"]:
                    raise ContractError("identity map repository differs from the exact source repository")
                blinding.check_scoring_paths(mapping, pack, snapshot_id)
                digest = blinding.map_sha256(mapping)
                maps[digest] = mapping
                map_bindings[map_path] = digest
        config = _config(document, cell, population, map_bindings)
        validate_document("run-config", config)
        cell_assignments = _assignments(document, name, population)
        assignments.extend(cell_assignments)
        cells.append({"name": name, "config": config, "config_sha256": canonical_sha256(config),
                      "population_sha256": canonical_sha256(population), "assignments": cell_assignments})
    order = _cell_order(document)
    frozen = {"schema_version": "2.1", "stage": "frozen", "experiment_id": document["experiment_id"],
              "experiment_version": document["experiment_version"], "created_at": created_at,
              "declaration": deepcopy(document), "pack": pack, "maps": maps, "population": population,
              "systems": systems, "cells": cells, "assignments": assignments, "cell_order": order,
              "bindings": {"pack_sha256": canonical_sha256(pack), "population_sha256": canonical_sha256(population),
                           "adjudication_sha256": canonical_sha256(document["adjudication"]),
                           "aggregation_policy_sha256": canonical_sha256(resolve_aggregation_policy(document["aggregation_policy"])),
                           "run_order_algorithm_sha256": canonical_sha256(ALGORITHM),
                           **{"map." + path: digest for path, digest in map_bindings.items()}}}
    frozen["matrix_sha256"] = matrix_digest(frozen)
    return validate_frozen(frozen)


def validate_frozen(document: dict) -> dict:
    """Check immutable matrix bindings and complete assignment coverage before execution/reporting."""
    _schema_validate(document)
    if document["stage"] != "frozen":
        raise ContractError("expected a frozen experiment matrix")
    validate_matrix(document["declaration"])
    if document["matrix_sha256"] != matrix_digest(document):
        raise ContractError("stale experiment matrix binding")
    if (document["experiment_id"], document["experiment_version"]) != (document["declaration"]["experiment_id"], document["declaration"]["experiment_version"]):
        raise ContractError("frozen experiment identity differs from its declaration")
    if document["bindings"]["pack_sha256"] != canonical_sha256(document["pack"]):
        raise ContractError("frozen case pack binding differs")
    validate_document("case-pack", document["pack"])
    if document["bindings"]["population_sha256"] != canonical_sha256(document["population"]):
        raise ContractError("frozen target population binding differs")
    if document["population"] != _population(document["pack"], document["declaration"]):
        raise ContractError("frozen source property, labels, accepted locations, or target population differ from the common pack")
    for key, value in (("adjudication_sha256", document["declaration"]["adjudication"]),
                       ("aggregation_policy_sha256", resolve_aggregation_policy(document["declaration"]["aggregation_policy"])),
                       ("run_order_algorithm_sha256", ALGORITHM)):
        if document["bindings"][key] != canonical_sha256(value):
            raise ContractError("frozen adjudication/aggregation policy binding differs")
    if [{key: value for key, value in row.items() if key != "adapter_identity"} for row in document["systems"]] != document["declaration"]["systems"]:
        raise ContractError("frozen scanner/model/scope/resource settings differ from their common declaration")
    if any(not isinstance(row.get("adapter_identity"), dict) or set(row["adapter_identity"]) != {"name", "version"}
           or any(not isinstance(value, str) or not value for value in row["adapter_identity"].values()) for row in document["systems"]):
        raise ContractError("frozen adapter identity is missing or malformed")
    for digest, mapping in document["maps"].items():
        validate_document("blinding-map", mapping)
        if canonical_sha256(mapping) != digest or blinding.approval_gap(mapping):
            raise ContractError("frozen transformation map is stale or unreviewed")
    map_bindings = {key.removeprefix("map."): digest for key, digest in document["bindings"].items() if key.startswith("map.")}
    paths = {path for cell in document["declaration"]["conditions"] for path in cell.get("transformation_maps", {}).values()}
    if set(map_bindings) != paths or set(document["maps"]) != set(map_bindings.values()):
        raise ContractError("frozen transformation map population differs from its declaration")
    expected = []
    _unique(document["cells"], "name", "frozen condition name")
    if {cell["name"] for cell in document["cells"]} != set(NAMES) or set(document["cell_order"]) != set(NAMES):
        raise ContractError("frozen matrix omits a core condition")
    if document["cell_order"] != _cell_order(document["declaration"]):
        raise ContractError("frozen run order differs from the predeclared ordering policy")
    if [cell["name"] for cell in document["cells"]] != [cell["name"] for cell in document["declaration"]["conditions"]]:
        raise ContractError("frozen cell inventory order differs from its declaration")
    for cell in document["cells"]:
        if cell["config_sha256"] != canonical_sha256(cell["config"]):
            raise ContractError("frozen cell configuration binding differs")
        if cell["population_sha256"] != document["bindings"]["population_sha256"]:
            raise ContractError("frozen cells do not share the same exact population")
        declared_cell = next(row for row in document["declaration"]["conditions"] if row["name"] == cell["name"])
        try:
            expected_config = _config(document["declaration"], declared_cell, document["population"], map_bindings)
        except KeyError as exc:
            raise ContractError("frozen transformation map binding is missing") from exc
        if cell["config"] != expected_config:
            raise ContractError("frozen cell changes scanner/model/scope/budget outside the allowed context differences")
        validate_document("run-config", cell["config"])
        if cell["name"] == "identity_reduced":
            for source in document["population"]:
                path = declared_cell["transformation_maps"][source["snapshot_id"]]
                digest = map_bindings.get(path)
                mapping = document["maps"].get(digest)
                if not isinstance(mapping, dict) or not isinstance(mapping.get("identity_policy"), dict):
                    raise ContractError("frozen strict identity policy or transformation map is missing")
                variant = next((row for row in mapping["variants"] if row["snapshot_id"] == source["snapshot_id"]), None)
                if variant is None or (variant["commit"], variant["tree_hash"]) != (source["commit"], source["source_tree_hash"]):
                    raise ContractError("frozen identity map differs from the exact paired source property")
                if mapping["repository"]["url"] != cases.snapshot_by_id(document["pack"], source["snapshot_id"])["repository"]["url"]:
                    raise ContractError("frozen identity map repository differs from the paired repository")
                blinding.check_scoring_paths(mapping, document["pack"], source["snapshot_id"])
        if cell["assignments"] != _assignments(document["declaration"], cell["name"], document["population"]):
            raise ContractError("frozen cell omits or changes a scheduled repetition")
        expected.extend(cell["assignments"])
    if document["assignments"] != expected:
        raise ContractError("frozen matrix assignment coverage differs from its cell schedules")
    keys = [(row["condition"], row["assignment_id"]) for row in document["assignments"]]
    if len(keys) != len(set(keys)):
        raise ContractError("duplicate experiment condition assignment")
    return document


def execute(*args, **kwargs) -> dict:
    from .experiment_execution import execute as execute_matrix
    return execute_matrix(*args, **kwargs)


def freeze_file(*args, **kwargs) -> dict:
    from .experiment_execution import freeze_file as freeze_matrix
    return freeze_matrix(*args, **kwargs)
