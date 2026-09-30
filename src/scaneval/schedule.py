"""The evaluation schedule: what a run commits to before it prepares a single input.

A run writes ``evaluator/schedule.json`` once, after its configuration is copied and before the
first input is fetched or exported, so nothing the run observes can change what it was assigned
to do. The schedule names:

- every assignment of a system to an input and a repetition, including every assignment of an
  input whose preparation later fails and of a system that is later skipped, because a failed
  assignment stays in every denominator rather than dropping out of it;
- for each input, the plan the pack gives it before execution: the targets and controls it
  carries, their canonical ids and validation levels, and the scope and review budgets, when the
  snapshot declares the tree hash a plan binds to;
- the vulnerable/fixed observation pairs, matched in advance: a target planned on one input with a
  fixed-target control of that target planned on another input of the same profile and mode, each
  repetition paired with the same repetition, so a pair is never chosen after its outcomes are
  known (``docs/EVALUATION_MATH.md``, pair correctness).

What it is not. It is not a result and holds no outcome, no claim, and no label content beyond
ids, kinds, and levels. A plan recorded ``unavailable`` means the snapshot declared no tree hash
before the run, or the pack refused to plan it; each invocation's plan is still built from the
checked pack when it runs and is recorded in its own bundle, but it was not pre-registered here.
Nothing here reads an export, a scanner, the network, a clock, or a random source: the schedule is
a function of the configuration, the pack as it was supplied, and the ``created_at`` it is given,
so two runs of one configuration against one pack at one moment schedule byte-identical work.
"""

from __future__ import annotations

from pathlib import Path

from . import blinding, cases
from .contracts import ContractError, canonical_sha256, input_identity, validate_document
from .execution import invocation_id


SCHEDULE_KIND = "evaluation-schedule"
SCHEMA_VERSION = "2.1"
# Where a run writes its schedule, relative to the run directory; the run manifest records it.
SCHEDULE_PATH = "evaluator/schedule.json"


def _planned_targets(pack: dict, plan: dict, project: str) -> list[dict]:
    """The targets of *plan* with the case facts a pre-registered assignment is grouped by."""
    by_target = {case["target"]["target_id"]: case for case in pack["cases"]}
    rows = []
    for target in plan["targets"]:
        case = by_target[target["target_id"]]
        rows.append({"target_id": target["target_id"], "case_id": case["case_id"],
                     "canonical_id": cases.target_canonical_id(case), "kind": target["kind"],
                     "variant_family": case["canonical_target"]["variant_family"],
                     "workload": case["workload"], "component_role": case["component_role"],
                     "project": project, "validation_level": target["validation_level"]})
    return rows


def _planned_controls(pack: dict, plan: dict) -> list[dict]:
    """The controls of *plan*, each with its case, its canonical id, and the target it guards."""
    by_control = {control["control_id"]: (case, control)
                  for case in pack["cases"] for control in case["controls"]}
    rows = []
    for planned in plan["controls"]:
        case, control = by_control[planned["control_id"]]
        rows.append({"control_id": planned["control_id"], "case_id": case["case_id"],
                     "canonical_id": cases.control_canonical_id(control), "type": planned["type"],
                     "target_id": planned.get("target_id"),
                     "validation_level": planned["validation_level"]})
    return rows


def _frozen_plan(pack: dict, snapshot: dict, mode: str) -> dict:
    """The plan the pack gives one input before execution, or why it gives none.

    A plan binds to an export, so it is built only from the tree hash the snapshot already
    declares; a snapshot that declares none is planned for the first time once this run has
    exported and checked it, which is after the schedule is frozen. A refusal from
    :func:`scaneval.cases.build_plan` is recorded with its own message rather than raised: the
    schedule records what the pack could say before execution, and a pack that could say nothing
    about one input is a fact about that input, not a reason to schedule nothing.
    """
    declared = snapshot.get("tree_hash")
    if not declared:
        return {"state": "unavailable",
                "reason": (f"snapshot {snapshot['snapshot_id']} declares no tree hash, so no plan "
                           "binds to its export before this run exports and checks it")}
    try:
        plan, notes = cases.build_plan(pack, snapshot["snapshot_id"], declared, mode=mode)
    except ContractError as exc:
        return {"state": "unavailable", "reason": f"the pack does not plan this input: {exc}"}
    return {"state": "frozen", "scope": plan["scope"], "review_budgets": plan["review_budgets"],
            "targets": _planned_targets(pack, plan, snapshot["repository"]["name"]),
            "controls": _planned_controls(pack, plan), "notes": notes}


def _input_row(entry: dict, pack: dict, base_dir: Path, maps: dict[str, dict]) -> dict:
    """One configured input as the schedule records it.

    A metadata-blinded input records the identity of its map: the document in *maps* under its
    input id when the caller loaded it already, which is what makes the schedule name the map the
    run actually applies, and otherwise the map its entry names under *base_dir*. A native PR input
    is refused here as the runner refuses it, rather than scheduled as something it is not.
    """
    input_id = input_identity(entry)
    mode = entry.get("mode", "full")
    profile = entry.get("profile", "standard")
    if mode != "full":
        raise ContractError(f"input {input_id} is a native PR input, which this build cannot schedule")
    snapshot = cases.snapshot_by_id(pack, entry["snapshot_id"])
    identity = None
    if profile == "metadata_blinded":
        document = maps.get(input_id)
        if document is None:
            if "blinding_map" not in entry:
                raise ContractError(f"input {input_id} is metadata_blinded but names no blinding map")
            document = blinding.load_map(base_dir / entry["blinding_map"])
        identity = blinding.map_identity(document)
    return {"input_id": input_id, "mode": mode, "profile": profile,
            "snapshot_id": snapshot["snapshot_id"], "change_set_id": None, "change_set": None,
            "blinding": identity, "project": snapshot["repository"]["name"],
            "workload": snapshot["workload"], "component_role": snapshot["component_role"],
            "declared_tree_hash": snapshot.get("tree_hash"),
            "plan": _frozen_plan(pack, snapshot, mode)}


def _system_row(entry: dict, default_policy: str) -> dict:
    """One configured system: its identity, a digest of its configuration, and its declared backend.

    ``enforced_expected`` says the configuration asks for an enforcing backend. Whether one bounded
    an invocation is recorded in that invocation's execution record, never inferred from this.
    """
    execution = entry.get("execution") or {"backend": "local"}
    return {"system_id": entry["system_id"], "adapter": entry["adapter"],
            "model_id": entry.get("model_id"), "model_revision": entry.get("model_revision"),
            "config_sha256": canonical_sha256(entry["config"]),
            "network_policy": entry.get("network_policy", default_policy),
            "execution": {"backend": execution["backend"],
                          "enforced_expected": execution["backend"] != "local",
                          "image": execution.get("image")}}


def _pairs(rows: list[dict], repetitions: int) -> list[dict]:
    """Every vulnerable/fixed pair the frozen plans support, each repetition with its own number.

    A target planned on input V pairs with a ``fixed_target`` or ``both`` control of that target
    planned on a different input F of the same profile and mode. Only plans frozen before execution
    take part, because a pair matched from a plan built during the run is a pair matched after the
    run had started observing.
    """
    pairs = []
    frozen = [row for row in rows if row["plan"]["state"] == "frozen"]
    for vulnerable in frozen:
        for target in vulnerable["plan"]["targets"]:
            for fixed in frozen:
                if fixed["input_id"] == vulnerable["input_id"]:
                    continue
                if (fixed["profile"], fixed["mode"]) != (vulnerable["profile"], vulnerable["mode"]):
                    continue
                for control in fixed["plan"]["controls"]:
                    if control["type"] in ("fixed_target", "both") and control["target_id"] == target["target_id"]:
                        pairs.append({"target_id": target["target_id"], "canonical_id": target["canonical_id"],
                                      "vulnerable_input_id": vulnerable["input_id"],
                                      "control_id": control["control_id"],
                                      "fixed_input_id": fixed["input_id"],
                                      "repetition_pairs": [[r, r] for r in range(1, repetitions + 1)]})
    return sorted(pairs, key=lambda pair: (pair["target_id"], pair["control_id"],
                                           pair["vulnerable_input_id"], pair["fixed_input_id"]))


def build_schedule(config: dict, pack: dict, *, base_dir: Path, created_at: str,
                   inputs: list[dict] | None = None, systems: list[dict] | None = None,
                   maps: dict[str, dict] | None = None) -> dict:
    """The validated schedule of one run: every assignment, each input's frozen plan, and the pairs.

    *config* is the run configuration as loaded, and ``config_sha256`` hashes the whole of it, as
    the run manifest does. *pack* is the pack as it was supplied, before any mechanical check ran
    against an export; its digest is recorded as that. *base_dir* is the directory the
    configuration's relative paths resolve against, which is where a blinded input's map is read
    from unless *maps* already holds it under the input's id. *inputs* and *systems* are the entries
    this run actually covers when ``--only-input`` or ``--only-system`` narrowed it, in
    configuration order; left out, every configured entry is scheduled, and a narrowed schedule
    says in its notes what it left out. Inputs and systems keep configuration order, and
    assignments and pairs are sorted, so identical arguments give an identical document.

    An input whose snapshot the pack does not declare, and a blinded input whose map cannot be
    loaded, are refused, as the runner refuses them before anything is written. Nothing here
    creates a file.
    """
    selected_inputs = list(config["inputs"] if inputs is None else inputs)
    selected_systems = list(config["systems"] if systems is None else systems)
    repetitions = config["repetitions"]
    rows = [_input_row(entry, pack, Path(base_dir), maps or {}) for entry in selected_inputs]
    system_rows = [_system_row(entry, config["network_policy"]) for entry in selected_systems]
    assignments = sorted(
        ({"assignment_id": invocation_id(row["input_id"], system["system_id"], repetition),
          "input_id": row["input_id"], "system_id": system["system_id"], "repetition": repetition}
         for row in rows for system in system_rows for repetition in range(1, repetitions + 1)),
        key=lambda item: (item["input_id"], item["system_id"], item["repetition"]))
    notes = ["Frozen before any input was prepared. An assignment whose input cannot be prepared, or "
             "whose system is skipped, stays scheduled here and stays in every denominator."]
    if any(row["plan"]["state"] == "unavailable" for row in rows):
        notes.append("An input whose plan is unavailable here is planned from the checked pack when "
                     "its invocations run; that plan was not pre-registered in this schedule.")
    if any(row["blinding"] is not None for row in rows):
        notes.append("A blinded input names the map it is transformed with. Whether that map is approved and "
                     "fits the export is asked when the input is prepared; a refusal is that input's "
                     "preparation failure, and its assignments stay here.")
    left_out_inputs = len(config["inputs"]) - len(selected_inputs)
    left_out_systems = len(config["systems"]) - len(selected_systems)
    if left_out_inputs or left_out_systems:
        notes.append(f"This run was narrowed: {left_out_inputs} configured input(s) and "
                     f"{left_out_systems} configured system(s) are not scheduled here.")
    schedule = {
        "schema_version": SCHEMA_VERSION,
        "run_id": config["run_id"],
        "created_at": created_at,
        "config_sha256": canonical_sha256(config),
        "pack": {"namespace": pack["namespace"], "pack_id": pack["pack_id"], "version": pack["version"],
                 "sha256": cases.pack_sha256(pack)},
        "repetitions": repetitions,
        "inputs": rows,
        "systems": system_rows,
        "assignments": assignments,
        "pairs": _pairs(rows, repetitions),
        "notes": notes,
    }
    return validate_document(SCHEDULE_KIND, schedule)
