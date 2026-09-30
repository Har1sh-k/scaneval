"""Input identity from the configuration to the manifest: ids, plans, the schedule, and failures.

A standard full input that is its snapshot's own export keeps the 2.0 plan it always had, byte for
byte. Any other input (a renamed one, or a metadata-blinded one bound to a transformed tree) plans
at 2.1 and says which input it is, which export its labels refer to, and which map transformed it.
Which cases are planned, at which level and in which scope, never depends on that identity.

Every run writes a 2.1 manifest and freezes its schedule before the first input is fetched. An
input whose preparation fails is recorded against that input, its assignments are skipped
invocations naming the failure, no adapter is called for it, and the other inputs still run.

Every repository here is a local ``git init`` fixture and the only scanner is a fake adapter: no
network, no model calls, no sleeping.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess

import pytest

from scaneval import cases, materialize
from scaneval.adapters.base import Adapter, NativeOutcome
from scaneval.cli import main
from scaneval.contracts import (
    ContractError,
    canonical_json,
    load_document,
    pack_anchor_digest,
    validate_document,
)
from scaneval.runner import MANIFEST_NAME, run_from_config


CLOCK = lambda: datetime(2026, 9, 20, 17, 0, tzinfo=timezone.utc)  # noqa: E731
HASH = "sha256:" + "b" * 64
TRANSFORMED = "sha256:" + "c" * 64
MAP_IDENTITY = {"map_id": "widget-metadata", "map_version": "1", "map_sha256": "sha256:" + "d" * 64}
SNAPSHOT = {
    "snapshot_id": "widget-abc", "repository": {"url": "https://example.invalid/acme/widget.git", "name": "acme/widget"},
    "commit": "a" * 40, "reference": "parent of fix commit", "languages": ["python"],
    "workload": "conventional_application", "component_role": "application",
    "license": {"spdx": "MIT", "verified": False, "note": "not checked"},
}
REPRESENTS = ("This case tests shell interpolation of a request parameter under a default deployment, "
              "and adds a Python command-injection target.")


def checked_pack(tmp_path: Path) -> dict:
    """One mechanically checked case with a capability-safe control, both on one export."""
    pack = cases.new_pack("org.example", "inputs", "input identity fixture")
    cases.add_snapshot(pack, SNAPSHOT)
    case = cases.draft_case(
        "widget-shell", snapshot_id="widget-abc", kind="command_injection",
        description="cmd reaches subprocess with shell=True", represents=REPRESENTS,
        workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("fix", origin="fix_without_advisory", kind="fix_commit",
                                 reference="acme/widget@" + "c" * 40)],
        accepted_locations=[{"path": "src/app.py", "start_line": 3, "end_line": 3, "role": "sink"}])
    case["controls"].append({
        "control_id": "C-widget-safe", "snapshot_id": "widget-abc", "type": "capability_safe",
        "description": "The admin helper runs a fixed argument list.",
        "property": "No caller-supplied string reaches a shell at this call site.",
        "allowed_actors_inputs": "Operators on the host.", "assumptions": ["Default deployment."],
        "ruled_out_allegation": "Caller-controlled shell interpolation in the admin helper.",
        "locations": [{"path": "src/app.py", "start_line": 1, "end_line": 1, "role": "operation"}],
        "evidence_ids": ["fix"],
    })
    cases.add_case(pack, case)
    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "app.py").write_text(
        "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n", encoding="utf-8")
    cases.mechanical_checks(pack, "widget-abc", source, HASH, clock=CLOCK)
    return pack


def test_a_snapshot_input_named_as_itself_keeps_the_2_0_plan_byte_for_byte(tmp_path):
    pack = checked_pack(tmp_path)

    plain, notes = cases.build_plan(pack, "widget-abc", HASH)
    named, named_notes = cases.build_plan(pack, "widget-abc", HASH, input_id="widget-abc",
                                          input_hash=HASH, profile="standard", blinding=None)

    assert canonical_json(named) == canonical_json(plain) and named_notes == notes
    assert plain["schema_version"] == "2.0" and plain["input_hash"] == HASH
    assert set(plain["provenance"]) == {"namespace", "pack_id", "pack_version", "pack_sha256",
                                        "snapshot_id", "mode", "case_ids"}
    assert all("canonical_id" not in item for item in plain["targets"] + plain["controls"])


def test_a_blinded_input_plans_at_2_1_bound_to_the_transformed_tree(tmp_path):
    pack = checked_pack(tmp_path)
    plain, _ = cases.build_plan(pack, "widget-abc", HASH)

    plan, _ = cases.build_plan(pack, "widget-abc", HASH, input_id="widget-abc.blinded",
                               input_hash=TRANSFORMED, profile="metadata_blinded",
                               blinding={**MAP_IDENTITY, "original_tree_hash": HASH})

    assert validate_document("evaluation-plan", plan) is plan
    assert plan["schema_version"] == "2.1" and plan["input_hash"] == TRANSFORMED
    provenance = plan["provenance"]
    assert provenance["input_id"] == "widget-abc.blinded" and provenance["profile"] == "metadata_blinded"
    assert provenance["source_tree_hash"] == HASH, "the labels refer to the original export"
    assert provenance["blinding"] == MAP_IDENTITY, "only the map identity travels into a plan"
    assert provenance["snapshot_id"] == "widget-abc"
    assert [(t["target_id"], t["canonical_id"]) for t in plan["targets"]] == [("T-widget-shell", "T-widget-shell")]
    assert [(c["control_id"], c["canonical_id"]) for c in plan["controls"]] == [("C-widget-safe", "C-widget-safe")]
    # The identity changes what the plan says about its input, never what it plans.
    assert plan["scope"] == plain["scope"] and plan["review_budgets"] == plain["review_budgets"]
    assert [{k: v for k, v in t.items() if k != "canonical_id"} for t in plan["targets"]] == plain["targets"]
    assert [{k: v for k, v in c.items() if k != "canonical_id"} for c in plan["controls"]] == plain["controls"]


def test_a_renamed_standard_input_plans_at_2_1_without_a_blinding_identity(tmp_path):
    pack = checked_pack(tmp_path)

    plan, _ = cases.build_plan(pack, "widget-abc", HASH, input_id="widget-main")

    assert plan["schema_version"] == "2.1" and plan["input_hash"] == HASH
    assert plan["provenance"]["input_id"] == "widget-main" and plan["provenance"]["profile"] == "standard"
    assert plan["provenance"]["source_tree_hash"] == HASH and "blinding" not in plan["provenance"]


def test_a_blinded_profile_and_a_map_identity_come_together_or_not_at_all(tmp_path):
    pack = checked_pack(tmp_path)

    with pytest.raises(ContractError, match="identity of the map it was transformed with"):
        cases.build_plan(pack, "widget-abc", HASH, profile="metadata_blinded", input_hash=TRANSFORMED)
    with pytest.raises(ContractError, match="identity of the map it was transformed with"):
        cases.build_plan(pack, "widget-abc", HASH, profile="standard", blinding=MAP_IDENTITY)


def test_a_2_1_plan_carries_the_canonical_ids_the_pack_declares(tmp_path):
    """Several target records can be one root cause; the plan carries the pack's grouping."""
    pack = checked_pack(tmp_path)
    pack["schema_version"] = "2.1"
    case = pack["cases"][0]
    case["canonical_target"]["canonical_id"] = "widget-shell-root"
    case["controls"][0]["canonical_id"] = "widget-admin-fixed-argv"
    pack["anchor_sha256"] = pack_anchor_digest(pack)
    validate_document("case-pack", pack)

    plan, _ = cases.build_plan(pack, "widget-abc", HASH, input_id="widget-main")

    assert [t["canonical_id"] for t in plan["targets"]] == ["widget-shell-root"]
    assert [c["canonical_id"] for c in plan["controls"]] == ["widget-admin-fixed-argv"]
    assert cases.target_canonical_id(case) == "widget-shell-root"
    assert cases.control_canonical_id(case["controls"][0]) == "widget-admin-fixed-argv"


# --- the runner: input ids, the 2.1 manifest, the schedule, and preparation failures ------------


RUN_CLOCK = lambda: datetime(2026, 9, 20, 15, 0, tzinfo=timezone.utc)  # noqa: E731
VULNERABLE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
RUN_REPRESENTS = ("This case tests caller-controlled shell command construction under a trusted-argument "
                  "assumption, and adds a single-file Python sink for the runner tests.")
DIGEST_IMAGE = "ghcr.io/example/scanner@sha256:" + "c" * 64


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
             "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"},
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "upstream"
    (repo / "src").mkdir(parents=True)
    git("init", "-q", "-b", "main", cwd=repo)
    git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=repo)
    (repo / "src" / "app.py").write_text(VULNERABLE, encoding="utf-8")
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    git("add", "-A", cwd=repo)
    git("commit", "-q", "-m", "first", cwd=repo)
    return repo, git("rev-parse", "HEAD", cwd=repo)


def write_pack(path: Path, repo: Path, commits: dict[str, str]) -> dict:
    """One snapshot per entry of *commits*, each carrying one draft case on ``src/app.py``."""
    pack = cases.new_pack("test", "runner-inputs", "Local fixture pack for the input tests.")
    for snapshot_id, commit in commits.items():
        cases.add_snapshot(pack, {
            "snapshot_id": snapshot_id, "repository": {"url": str(repo), "name": "widget"}, "commit": commit,
            "reference": "Commit chosen by the test fixture; no advisory is claimed.",
            "languages": ["python"], "workload": "conventional_application", "component_role": "application",
            "license": {"spdx": None, "verified": False, "note": "Local fixture repository."},
        })
        cases.add_case(pack, cases.draft_case(
            f"case-{snapshot_id}", snapshot_id=snapshot_id, kind="command_injection",
            description="Caller-controlled command string reaches subprocess with shell=True.",
            represents=RUN_REPRESENTS, workload="conventional_application", component_role="application",
            aliases=[],
            evidence=[cases.evidence("source", origin="research_note", kind="source_inspection",
                                     reference="src/app.py", note="Fixture inspection, not an advisory.")],
            accepted_locations=[{"path": "src/app.py", "start_line": 5, "end_line": 5, "role": "sink", "note": ""}],
        ))
    cases.save_pack(path, pack)
    return pack


def write_config(path: Path, *, inputs: list[dict], systems: list[dict] | None = None,
                 version: str = "2.1", repetitions: int = 1) -> dict:
    config = {
        "schema_version": version, "run_id": "run-inputs", "pack": "pack.json", "cache_root": "cache",
        "inputs": inputs,
        "systems": systems or [{"system_id": "fake-a", "adapter": "fake", "config": {"knob": 1}}],
        "repetitions": repetitions, "timeout_seconds": 60, "trace_mode": "off", "network_policy": "none",
    }
    path.write_text(canonical_json(config) + "\n", encoding="utf-8")
    return config


class FakeAdapter(Adapter):
    """Returns one claim on the accepted location and counts its calls. Never touches the network."""

    name = "fake"
    adapter_version = "1.0.0"
    supported_languages = frozenset({"python"})

    def __init__(self):
        self.prepared = 0
        self.calls = 0
        self.scanned: list[str] = []

    def prepare(self, spec, cache_root):
        self.prepared += 1
        return {"system": spec.system_id}

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        self.calls += 1
        self.scanned.append(request["input"]["tree_hash"])
        native = raw_dir / "native.json"
        native.write_text('{"findings": [{"file": "src/app.py"}]}\n', encoding="utf-8")
        claims = [{"claim_id": "c1", "allegation": "shell=True with a caller-controlled command",
                   "kind": "command_injection", "native_rule_id": "fake.shell", "raw_artifact_id": "native",
                   "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5}}]
        return NativeOutcome(status="success", exit_code=0, command=["fake", "scan"], claims=claims,
                             artifacts=[{"id": "native", "path": native}], tool_versions={"fake": "1.0.0"},
                             capture={"model_requests": "not_applicable"}, notes=["fake run"])


def test_every_run_writes_a_2_1_manifest_naming_its_schedule(tmp_path, upstream):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a"}], version="2.0")
    out = tmp_path / "out"

    manifest = run_from_config(tmp_path / "run.json", out, clock=RUN_CLOCK, adapters={"fake": FakeAdapter()})

    assert manifest["schema_version"] == "2.1" and manifest["schedule_path"] == "evaluator/schedule.json"
    frozen = load_document(out / manifest["schedule_path"], "evaluation-schedule")
    assert [row["assignment_id"] for row in frozen["assignments"]] == [
        row["invocation_id"] for row in manifest["invocations"]] == ["snap-a__fake-a__r1"]
    assert frozen["config_sha256"] == manifest["config_sha256"]
    assert frozen["created_at"] == manifest["created_at"] == "2026-09-20T15:00:00+00:00"


def test_the_schedule_is_on_disk_before_the_first_input_is_fetched(tmp_path, upstream, monkeypatch):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a"}])
    out = tmp_path / "out"
    seen: list[tuple[bool, bool, bool]] = []
    fetch = materialize.fetch_snapshot

    def watching_fetch(*args, **kwargs):
        evaluator = out / "evaluator"
        seen.append(((evaluator / "schedule.json").is_file(), (evaluator / "pack.json").exists(),
                     (out / "inputs").exists()))
        return fetch(*args, **kwargs)

    monkeypatch.setattr("scaneval.runner.materialize.fetch_snapshot", watching_fetch)
    run_from_config(tmp_path / "run.json", out, clock=RUN_CLOCK, adapters={"fake": FakeAdapter()})

    assert seen == [(True, False, False)], "schedule written, pack not yet frozen, nothing exported"


def test_the_schedule_of_identical_runs_is_byte_identical(tmp_path, upstream):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a"}], repetitions=2)

    for name in ("first", "second"):
        run_from_config(tmp_path / "run.json", tmp_path / name, clock=RUN_CLOCK, adapters={"fake": FakeAdapter()})

    first = (tmp_path / "first" / "evaluator" / "schedule.json").read_bytes()
    assert first == (tmp_path / "second" / "evaluator" / "schedule.json").read_bytes()


def test_an_input_that_cannot_be_prepared_is_scheduled_recorded_and_skipped_while_others_run(tmp_path, upstream):
    """The failed input keeps its assignments in the schedule and its rows in the manifest."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit, "snap-gone": "f" * 40})
    systems = [{"system_id": "fake-a", "adapter": "fake", "config": {}},
               {"system_id": "fake-b", "adapter": "fake", "config": {}}]
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-gone"}, {"snapshot_id": "snap-a"}],
                 systems=systems)
    adapter = FakeAdapter()
    out = tmp_path / "out"

    manifest = run_from_config(tmp_path / "run.json", out, clock=RUN_CLOCK, adapters={"fake": adapter})

    assert manifest["status"] == "completed"
    frozen = load_document(out / "evaluator" / "schedule.json", "evaluation-schedule")
    assert sorted(row["invocation_id"] for row in manifest["invocations"]) == [
        row["assignment_id"] for row in frozen["assignments"]]
    gone = {row["invocation_id"]: row for row in manifest["invocations"] if row["input_id"] == "snap-gone"}
    assert sorted(gone) == ["snap-gone__fake-a__r1", "snap-gone__fake-b__r1"]
    failure = manifest["inputs"][0]["preparation_failure"]
    assert failure["type"] == "MaterializationError"
    for row in gone.values():
        assert (row["status"], row["bundle_path"], row["claim_records"]) == ("skipped", None, None)
        assert row["skipped_reason"] == f"input snap-gone could not be prepared: MaterializationError: {failure['message']}"
    assert [(row["invocation_id"], row["status"]) for row in manifest["invocations"]
            if row["input_id"] == "snap-a"] == [("snap-a__fake-a__r1", "success"), ("snap-a__fake-b__r1", "success")]
    assert adapter.calls == 2, "the adapter ran for the prepared input only"
    assert not (out / "invocations" / "snap-gone__fake-a__r1").exists()


def test_a_run_whose_every_input_failed_still_completes_with_every_assignment_skipped(tmp_path, upstream):
    repo, _commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": "e" * 40, "snap-b": "f" * 40})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a"}, {"snapshot_id": "snap-b"}])
    adapter = FakeAdapter()

    manifest = run_from_config(tmp_path / "run.json", tmp_path / "out", clock=RUN_CLOCK, adapters={"fake": adapter})

    assert manifest["status"] == "completed" and "failure" not in manifest
    assert [row["input_id"] for row in manifest["inputs"] if row["preparation_failure"]] == ["snap-a", "snap-b"]
    assert [row["status"] for row in manifest["invocations"]] == ["skipped", "skipped"]
    assert adapter.calls == 0


def test_an_interrupt_while_an_input_is_prepared_still_stops_the_run(tmp_path, upstream, monkeypatch):
    """Only an Exception is an input's own failure; an interrupt stops everything, as before."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a"}])
    out = tmp_path / "out"

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt("the operator stopped the run")

    monkeypatch.setattr("scaneval.runner.materialize.fetch_snapshot", interrupted)
    with pytest.raises(KeyboardInterrupt):
        run_from_config(tmp_path / "run.json", out, clock=RUN_CLOCK, adapters={"fake": FakeAdapter()})

    manifest = load_document(out / MANIFEST_NAME, "run-manifest")
    assert manifest["status"] == "failed"
    assert manifest["failure"] == {"type": "KeyboardInterrupt", "message": "the operator stopped the run"}
    assert manifest["inputs"] == [] and manifest["invocations"] == []
    assert (out / "evaluator" / "schedule.json").is_file()


def test_a_renamed_input_runs_under_its_own_id_and_plans_at_2_1(tmp_path, upstream):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a", "input_id": "widget-main"}])
    out = tmp_path / "out"

    manifest = run_from_config(tmp_path / "run.json", out, clock=RUN_CLOCK, adapters={"fake": FakeAdapter()})

    [recorded] = manifest["inputs"]
    assert (recorded["input_id"], recorded["snapshot_id"]) == ("widget-main", "snap-a")
    assert recorded["provenance_path"] == "inputs/widget-main/provenance.json"
    bundle = out / "invocations" / "widget-main__fake-a__r1"
    plan = load_document(bundle / "evaluator" / "plan.json", "evaluation-plan")
    assert plan["schema_version"] == "2.1" and plan["provenance"]["input_id"] == "widget-main"
    assert plan["provenance"]["snapshot_id"] == "snap-a" and plan["input_hash"] == recorded["tree_hash"]
    execution = load_document(bundle / "execution.json", "execution-record")
    assert execution["schema_version"] == "2.0" and execution["input_id"] == "widget-main", \
        "a standard full local input needs no 2.1 field in its execution record"
    replayed = tmp_path / "replayed.json"
    assert main(["replay", str(bundle), "--output", str(replayed)]) == 0
    assert replayed.read_bytes() == (bundle / "evaluation.json").read_bytes()


def test_a_narrowed_run_selects_by_input_id(tmp_path, upstream):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a"},
                                                {"snapshot_id": "snap-a", "input_id": "snap-a-again"}])
    out = tmp_path / "out"

    manifest = run_from_config(tmp_path / "run.json", out, clock=RUN_CLOCK, adapters={"fake": FakeAdapter()},
                               only_inputs={"snap-a-again"})

    assert manifest["selection"]["excluded_inputs"] == ["snap-a"]
    assert [row["invocation_id"] for row in manifest["invocations"]] == ["snap-a-again__fake-a__r1"]
    frozen = load_document(out / "evaluator" / "schedule.json", "evaluation-schedule")
    assert [row["input_id"] for row in frozen["inputs"]] == ["snap-a-again"]
    assert any("1 configured input(s) and 0 configured system(s) are not scheduled" in note
               for note in frozen["notes"])


def test_a_pr_input_naming_a_change_set_the_pack_does_not_declare_is_refused_before_the_output_exists(
        tmp_path, upstream):
    """Changed deliberately: this pinned the phase-1 refusal of every native PR input. A PR input is
    prepared now (``test_v2_pr.py``), so what is refused is the one whose change set the pack does not
    declare, and a full scan of the head is still never its stand-in."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a"}, {"mode": "pr", "change_set_id": "cs-1"}])
    adapter = FakeAdapter()
    out = tmp_path / "out"

    with pytest.raises(ContractError, match=r"inputs\[1\] \(cs-1\) is a native PR input that cannot be run: "
                                            r"unknown change set 'cs-1'"):
        run_from_config(tmp_path / "run.json", out, clock=RUN_CLOCK, adapters={"fake": adapter})
    assert not out.exists() and adapter.prepared == 0

    # Narrowed away, the PR input is never prepared, so it does not stand in the way.
    manifest = run_from_config(tmp_path / "run.json", out, clock=RUN_CLOCK, adapters={"fake": adapter},
                               only_inputs={"snap-a"})
    assert manifest["selection"]["excluded_inputs"] == ["cs-1"]


def test_a_system_configured_for_an_enforcing_backend_is_skipped_rather_than_run_unenforced(tmp_path, upstream):
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit})
    systems = [{"system_id": "fake-a", "adapter": "fake", "config": {}},
               {"system_id": "fake-oci", "adapter": "fake", "config": {},
                "execution": {"backend": "oci", "image": DIGEST_IMAGE}}]
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a"}], systems=systems)
    adapter = FakeAdapter()

    manifest = run_from_config(tmp_path / "run.json", tmp_path / "out", clock=RUN_CLOCK, adapters={"fake": adapter})

    # The oci backend exists now, and it refuses an adapter that has not declared itself safe to
    # run in a container rather than running it anywhere weaker.
    reason = manifest["systems"][1]["skipped_reason"]
    assert reason.startswith("IsolationError: the oci execution backend refuses adapter 'fake'")
    assert "not oci_compatible" in reason
    assert [(row["system_id"], row["status"]) for row in manifest["invocations"]] == [
        ("fake-a", "success"), ("fake-oci", "skipped")]
    assert adapter.calls == 1 and adapter.prepared == 1


def test_a_metadata_blinded_input_of_a_2_0_configuration_is_refused_before_the_output_exists(tmp_path, upstream):
    """A 2.0 configuration cannot name the reviewed map, so its blinded input is never run standard.

    Renamed deliberately: this build blinds a 2.1 input that names its map (``test_v2_blinding.py``),
    so the refusal left here is the one for a configuration with no way to name one.
    """
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a", "profile": "metadata_blinded"}],
                 version="2.0")
    adapter = FakeAdapter()
    out = tmp_path / "out"

    with pytest.raises(ContractError, match=r"\(snap-a.blinded\) asks for metadata_blinded"):
        run_from_config(tmp_path / "run.json", out, clock=RUN_CLOCK, adapters={"fake": adapter})
    assert not out.exists() and adapter.prepared == 0


def test_the_cli_names_an_unprepared_input_and_exits_one(tmp_path, upstream, monkeypatch, capsys):
    """An input that could not be prepared is a negative result, never a quiet empty scan."""
    repo, commit = upstream
    write_pack(tmp_path / "pack.json", repo, {"snap-a": commit, "snap-gone": "f" * 40})
    write_config(tmp_path / "run.json", inputs=[{"snapshot_id": "snap-a"}, {"snapshot_id": "snap-gone"}])
    adapter = FakeAdapter()
    monkeypatch.setattr("scaneval.runner.get_adapter", lambda name: adapter)
    out = tmp_path / "out"

    code = main(["run", str(tmp_path / "run.json"), "--output", str(out)])
    captured = capsys.readouterr()

    assert code == 1
    assert "snap-a__fake-a__r1 status=success claims=1" in captured.out
    assert "snap-gone__fake-a__r1 status=skipped claims=None plan=None review=None" in captured.out
    assert f"Schedule: {out / 'evaluator' / 'schedule.json'}" in captured.out
    assert "scaneval: input snap-gone could not be prepared: MaterializationError: " in captured.err
    assert "no usable scan from 1 invocation(s): snap-gone__fake-a__r1" in captured.err
    manifest = load_document(out / MANIFEST_NAME, "run-manifest")
    assert manifest["status"] == "completed"
    assert [row["input_id"] for row in manifest["inputs"] if row["preparation_failure"]] == ["snap-gone"]
    assert adapter.calls == 1
