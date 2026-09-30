"""SARIF 2.1.0 import (profile sarif-import-1): the import record, the importer, and its CLI.

Every log here is a fabricated fixture under ``tests/fixtures/sarif`` or a document built in the
test; no test fetches anything, calls a model, or reads a file a log names. The one test that
runs the real Semgrep binary is skipped when it is not installed, and it runs with HOME redirected
into the test's own directory. Reviewers named here are fictional.
"""

from __future__ import annotations

import builtins
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

import pytest

from scaneval import cases, materialize, review, scoring
from scaneval.adapters.semgrep import import_semgrep_results
from scaneval.cli import main
from scaneval.contracts import (
    CONTRACT_KINDS,
    ContractError,
    SCHEMA_VERSIONS,
    canonical_json,
    canonical_sha256,
    load_document,
    schema_file,
    validate_document,
)
from scaneval.sarif import (
    FLOW_STEP_LIMIT,
    SarifImportError,
    SourceTree,
    UriSettings,
    convert_run,
    default_run_id,
    import_sarif,
    load_json_object,
    parse_log,
    read_artifact,
    select_run,
)


HASH = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
FICTIONAL_REVIEWER = "Fixture Reviewer (fictional)"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "sarif"
SHELL_RULE = "rules.python.probe.subprocess-shell"
CLOCK = lambda: datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)  # noqa: E731
REPRESENTS = ("This case tests request data interpolated into a SQL query under a default deployment, "
              "and adds a Python SQL sink for the SARIF import tests.")
BUNDLE_FILES = {"raw/codeql.sarif", "result.json", "import.json", "evaluator/plan.json",
                "evaluator/decisions.json", "evaluator/review-record.json", "evaluation.json", "report.html"}


def numbered(count: int) -> str:
    return "".join(f"line {number}\n" for number in range(1, count + 1))


# The exported tree every fixture's locations fall in. Content is filler: the importer counts lines
# and checks paths, and never reads what a line says.
SOURCE_FILES = {
    "README.md": "fixture\n", "src/app.py": numbered(12), "src/db.py": numbered(10),
    "app/web.py": numbered(20), "app/files.py": numbered(15), "app/run.py": numbered(25),
    "app/my file.py": numbered(3),
}


def write_tree(root: Path, files: dict[str, str] = SOURCE_FILES) -> str:
    """Write *files* under *root* and return the tree hash an export of them would carry."""
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return materialize.hash_exported_tree(root)["tree_hash"]


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def minimal_log(**run_changes) -> dict:
    """One Semgrep-shaped run with one finding, the smallest log every import path accepts."""
    run = {
        "tool": {"driver": {"name": "Semgrep OSS", "semanticVersion": "1.177.0", "rules": [{
            "id": SHELL_RULE, "name": SHELL_RULE, "defaultConfiguration": {"level": "warning"},
            "properties": {"precision": "very-high", "tags": ["CWE-78: OS Command Injection", "security"]}}]}},
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": []}],
        "results": [result_at("src/app.py")],
    }
    run.update(run_changes)
    return {"version": "2.1.0", "runs": [run]}


def result_at(uri, *, base="%SRCROOT%", region=None, **changes) -> dict:
    """One Semgrep-shaped result at *uri*; ``base=None`` leaves uriBaseId out, ``region=False`` the region."""
    artifact = {"uri": uri} if base is None else {"uri": uri, "uriBaseId": base}
    physical = {"artifactLocation": artifact}
    if region is not False:
        physical["region"] = ({"startLine": 5, "startColumn": 12, "endLine": 5, "endColumn": 43}
                              if region is None else region)
    result = {"ruleId": SHELL_RULE, "message": {"text": "subprocess call with shell=True"},
              "locations": [{"physicalLocation": physical}],
              "fingerprints": {"matchBasedId/v1": "requires login"}, "properties": {}}
    result.update(changes)
    return result


def converted(results: list, *, settings: UriSettings | None = None, tree: SourceTree | None = None,
              include_suppressed: bool = False, **run_changes):
    return convert_run(minimal_log(results=results, **run_changes), settings=settings, tree=tree,
                       include_suppressed=include_suppressed)


def only_claim(conversion) -> tuple[dict, dict]:
    assert conversion.losses == [] and conversion.excluded == [], (conversion.losses, conversion.excluded)
    assert len(conversion.claims) == 1
    return conversion.claims[0], conversion.entries[0]


def only_loss(conversion) -> str:
    assert conversion.claims == [] and conversion.excluded == []
    assert len(conversion.losses) == 1
    return conversion.losses[0]["reason"]


def encoded(document: dict) -> bytes:
    return json.dumps(document).encode("utf-8")


def make_pack(source: Path, tree_hash: str, *, control: bool = False, target: tuple[str, int] = ("app/web.py", 16),
              kind: str = "sql_injection") -> dict:
    """A draft pack with one mechanically checked case on snapshot ``snap-a``, built without git.

    With *control*, the case carries a capability-safe control on the same snapshot. The checks
    run against *source*, the exported tree, so the plan built from the pack is a draft plan
    holding the case's target (and control).
    """
    pack = cases.new_pack("org.example", "sarif-fixture", "Fabricated pack for the SARIF import tests.")
    cases.add_snapshot(pack, {
        "snapshot_id": "snap-a", "repository": {"url": "https://example.invalid/acme/app.git", "name": "acme/app"},
        "commit": "c" * 40, "reference": "Fixture commit; no advisory is claimed.", "languages": ["python"],
        "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": None, "verified": False, "note": "Fabricated fixture."}})
    path, line = target
    case = cases.draft_case(
        "case-a", snapshot_id="snap-a", kind=kind, description="Request data reaches the sink unescaped.",
        represents=REPRESENTS, workload="conventional_application", component_role="application", aliases=[],
        evidence=[cases.evidence("source", origin="research_note", kind="source_inspection", reference=path,
                                 note="Fixture inspection, not an advisory.")],
        accepted_locations=[{"path": path, "start_line": line, "end_line": line, "role": "sink", "note": ""}])
    if control:
        case["controls"] = [{
            "control_id": "C-case-a-safe", "snapshot_id": "snap-a", "type": "capability_safe",
            "description": "The file helper joins a fixed directory with a constant name.",
            "property": "No request value reaches the path at this call.",
            "allowed_actors_inputs": "Operators on the host.", "assumptions": ["Default deployment."],
            "ruled_out_allegation": "Request-controlled path traversal in the file helper.",
            "locations": [{"path": "app/files.py", "start_line": 1, "end_line": 1, "role": "operation"}],
            "evidence_ids": ["source"]}]
    cases.add_case(pack, case)
    cases.mechanical_checks(pack, "snap-a", source, tree_hash, clock=CLOCK)
    return pack


@pytest.fixture
def workspace(tmp_path) -> dict:
    """An exported tree, its hash, a pack checked against it, and a directory for new bundles."""
    source = tmp_path / "export" / "source"
    tree_hash = write_tree(source)
    return {"source": source, "tree_hash": tree_hash, "pack": make_pack(source, tree_hash),
            "out": tmp_path / "bundles", "tmp": tmp_path}


def imported(workspace: dict, log: str | Path = "codeql.sarif", name: str = "bundle", **options):
    path = log if isinstance(log, Path) else FIXTURES / log
    return import_sarif(path, pack=workspace["pack"], snapshot_id="snap-a", tree_hash=workspace["tree_hash"],
                        system_id="codeql-fixture", output=workspace["out"] / name, clock=CLOCK, **options)


def write_log(workspace: dict, log: dict, name: str = "built.sarif") -> Path:
    path = workspace["tmp"] / name
    path.write_bytes(encoded(log))
    return path


def bundle_files(bundle: Path) -> set[str]:
    return {path.relative_to(bundle).as_posix() for path in bundle.rglob("*") if path.is_file()}


def claim_entry(index: int, **changes) -> dict:
    entry = {
        "claim_id": f"r0-{index}", "pointer": f"/runs/0/results/{index}", "rule_id": "py/sql-injection",
        "descriptor": "/runs/0/tool/driver/rules/0", "kind": "fail", "level": "error",
        "fingerprints": None, "partial_fingerprints": {"primaryLocationLineHash": "e08e53ec4172332b:1"},
        "suppression": {"state": "unavailable", "entries": []}, "baseline_state": None,
        "bundle_review": [], "evidence_losses": [], "notes": [],
    }
    entry.update(changes)
    return entry


def import_record(**changes) -> dict:
    record = {
        "schema_version": "2.1", "profile": "sarif-import-1", "run_id": "import-0123456789ab-r0",
        "system_id": "codeql-fixture", "input_hash": HASH, "result_sha256": OTHER,
        "artifact": {"path": "raw/codeql.sarif", "sha256": OTHER, "bytes": 10},
        "sarif": {"version": "2.1.0", "run_index": 0, "run_count": 1},
        "tool": {"name": "CodeQL", "version": None, "semanticVersion": "2.26.2", "organization": "GitHub",
                 "extensions": []},
        "source_binding": {"pack_sha256": OTHER, "snapshot_id": "snap-a", "tree_hash": HASH,
                           "source_dir_verified": False},
        "system": {"system_id": "codeql-fixture", "config_sha256": None},
        "versions": {"scaneval": "2.0.0a1", "kind_mapping": "1.0.0"},
        "execution": {"evidence": "reported_success", "results": "present", "verified": False,
                      "invocations": [{"pointer": "/runs/0/invocations/0", "execution_successful": True,
                                       "exit_code": None, "exit_signal_name": None, "notifications": 0,
                                       "error_notifications": []}]},
        "options": {"run_index": None, "include_suppressed": False, "uri_bases": {}, "source_root_uri": None,
                    "max_bytes": 67108864},
        "counts": {"results": 3, "claims": 1, "excluded": 1, "losses": 1, "evidence_losses": 0,
                   "bundle_review_flagged": 0, "bundle_review_resolved": 0},
        "claims": [claim_entry(0)],
        "excluded": [{"pointer": "/runs/0/results/1", "reason": "kind:pass"}],
        "losses": [{"pointer": "/runs/0/results/2", "reason": "locations[0] has only a logical location"}],
        "normalization": None, "notes": [],
    }
    record.update(changes)
    return record


# --- the import-record contract ---------------------------------------------------------


def test_the_import_record_is_a_2_1_kind_with_its_own_plain_schema_file():
    assert "import-record" in CONTRACT_KINDS
    assert SCHEMA_VERSIONS["import-record"] == ("2.1",)
    assert schema_file("import-record", "2.1") == "import-record.schema.json"
    record = import_record()
    assert validate_document("import-record", record) is record
    with pytest.raises(ContractError, match="not a import-record version"):
        validate_document("import-record", {**record, "schema_version": "2.0"})


def test_every_result_is_accounted_for_exactly_once():
    record = import_record()
    with pytest.raises(ContractError, match="result pointer across claims, excluded, and losses"):
        validate_document("import-record", import_record(
            excluded=[{"pointer": "/runs/0/results/0", "reason": "kind:pass"}]))
    with pytest.raises(ContractError, match="counts.results is 4"):
        validate_document("import-record", import_record(counts={**record["counts"], "results": 4}))
    with pytest.raises(ContractError, match="counts.losses is 0, but 1 are recorded"):
        validate_document("import-record", import_record(counts={**record["counts"], "losses": 0, "results": 2}))
    absent = {**record["execution"], "results": "absent"}
    with pytest.raises(ContractError, match="results are absent has no result"):
        validate_document("import-record", import_record(execution=absent))
    validate_document("import-record", import_record(
        execution=absent, claims=[], excluded=[], losses=[],
        counts={key: 0 for key in record["counts"]}))


def test_the_record_binds_one_tree_hash_one_system_and_a_run_the_log_has():
    record = import_record()
    with pytest.raises(ContractError, match="tree_hash must equal input_hash"):
        validate_document("import-record", import_record(source_binding={**record["source_binding"],
                                                                         "tree_hash": OTHER}))
    with pytest.raises(ContractError, match="system.system_id must equal system_id"):
        validate_document("import-record", import_record(system={"system_id": "other", "config_sha256": None}))
    with pytest.raises(ContractError, match="run_index must name one of the log's runs"):
        validate_document("import-record", import_record(sarif={"version": "2.1.0", "run_index": 1,
                                                                "run_count": 1}))
    with pytest.raises(ContractError, match="relative path"):
        validate_document("import-record", import_record(artifact={**record["artifact"],
                                                                   "path": "/tmp/log.sarif"}))
    with pytest.raises(ContractError, match="verified"):
        validate_document("import-record", import_record(execution={**record["execution"], "verified": True}))


def test_a_normalization_decision_names_a_flagged_result_and_a_stated_reviewer():
    flagged = claim_entry(0, bundle_review=["multiple_locations"])
    counts = {**import_record()["counts"], "bundle_review_flagged": 1, "bundle_review_resolved": 1}
    decision = {"pointer": "/runs/0/results/0", "decision": "atomic", "reviewer": FICTIONAL_REVIEWER,
                "note": "both locations are one missing check"}
    normalization = {"sha256": HASH, "decisions": [decision]}
    validate_document("import-record", import_record(claims=[flagged], counts=counts, normalization=normalization))

    with pytest.raises(ContractError, match="did not flag for bundle review"):
        validate_document("import-record", import_record(counts={**counts, "bundle_review_flagged": 0},
                                                         normalization=normalization))
    with pytest.raises(ContractError, match="reviewer is blank"):
        validate_document("import-record", import_record(
            claims=[flagged], counts=counts,
            normalization={"sha256": HASH, "decisions": [{**decision, "reviewer": chr(0x200B)}]}))
    with pytest.raises(ContractError, match="normalization.decisions.pointer values must be unique"):
        validate_document("import-record", import_record(
            claims=[flagged], counts={**counts, "bundle_review_resolved": 2},
            normalization={"sha256": HASH, "decisions": [decision, deepcopy(decision)]}))
    with pytest.raises(ContractError, match="bundle_review_resolved"):
        validate_document("import-record", import_record(claims=[flagged], counts=counts))
    with pytest.raises(ContractError, match="decision"):
        validate_document("import-record", import_record(
            claims=[flagged], counts=counts,
            normalization={"sha256": HASH, "decisions": [{**decision, "decision": "split"}]}))


# --- reading a log: whole-log refusals ---------------------------------------------------


def test_a_log_is_read_only_as_a_regular_file_within_the_size_bound(tmp_path):
    log = tmp_path / "scan.sarif"
    log.write_bytes(encoded(minimal_log()))
    assert read_artifact(log) == log.read_bytes()
    assert read_artifact(log, max_bytes=log.stat().st_size) == log.read_bytes()
    with pytest.raises(SarifImportError, match="more than the .*-byte bound"):
        read_artifact(log, max_bytes=log.stat().st_size - 1)
    with pytest.raises(SarifImportError, match="could not open the SARIF file"):
        read_artifact(tmp_path / "missing.sarif")
    with pytest.raises(SarifImportError, match="not a regular file"):
        read_artifact(tmp_path)
    with pytest.raises(SarifImportError, match="positive number of bytes"):
        read_artifact(log, max_bytes=0)


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="root reads a file whatever its permission bits say")
def test_a_log_the_operator_may_not_read_is_refused(tmp_path):
    log = tmp_path / "scan.sarif"
    log.write_bytes(encoded(minimal_log()))
    log.chmod(0)
    try:
        with pytest.raises(SarifImportError, match="could not open the SARIF file .*Permission denied"):
            read_artifact(log)
    finally:
        log.chmod(0o600)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_a_fifo_named_as_the_log_is_refused_without_blocking(tmp_path):
    fifo = tmp_path / "scan.sarif"
    os.mkfifo(fifo)
    with pytest.raises(SarifImportError, match="not a regular file"):
        read_artifact(fifo)


@pytest.mark.parametrize("data,message", [
    (b"\xff\xfe{}", "not UTF-8 text"),
    (b'{"version": "2.1.0", "runs": [', "not valid JSON"),
    (b'{"version": "2.1.0", "version": "2.1.0", "runs": []}', "repeats the object key 'version'"),
    (b'{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x", "rank": NaN}}}]}',
     "non-finite JSON number NaN"),
    (b'{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x", "rank": -Infinity}}}]}',
     "non-finite JSON number -Infinity"),
    (b'{"version": "2.1.0", "runs": [{"rank": 1e999}]}', "overflows to infinity"),
    (b'{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "\\udc80"}}}]}', "lone UTF-16 surrogate"),
    (b'{"version": "2.1.0", "\\ud800": 1}', "lone UTF-16 surrogate"),
    # Longer than the interpreter's limit on digits in an integer literal (4300 by default).
    (b'{"version": "2.1.0", "runs": [{"rank": ' + b"9" * 5000 + b"}]}", "not valid JSON: Exceeds the limit"),
    (b'["2.1.0"]', "not a SARIF log object"),
    (b'{"a":' * 200000 + b"1" + b"}" * 200000, "recursion limit"),
])
def test_bytes_that_are_not_a_strict_json_object_are_refused_whole(data, message):
    with pytest.raises(SarifImportError, match=message):
        parse_log(data)


@pytest.mark.parametrize("data,message", [
    (b'{"threads": 4, "threads": 8}', "repeats the object key 'threads'"),
    (b'{"threads": NaN}', "non-finite JSON number NaN"),
    (b'{"threads": 1e999}', "overflows to infinity"),
    (b'{"name": "\\udc80"}', "lone UTF-16 surrogate"),
    (b"\xff{}", "is not UTF-8 text"),
    (b'{"threads":', "is not valid JSON"),
    (b"[4]", "is not a JSON object"),
])
def test_an_operator_json_file_is_read_as_strictly_as_a_log(tmp_path, data, message):
    path = tmp_path / "system.json"
    path.write_bytes(b'{"threads": 4}')
    assert load_json_object(path, "--system-config") == {"threads": 4}
    path.write_bytes(data)
    with pytest.raises(SarifImportError, match=message) as refused:
        load_json_object(path, "--system-config")
    # Every refusal names the option the file came from and the file itself.
    assert str(refused.value).startswith(f"the --system-config file {path}")


def test_an_operator_json_file_is_bounded_and_must_be_a_readable_regular_file(tmp_path):
    large = tmp_path / "large.json"
    large.write_bytes(b'{"note": "' + b"x" * (1024 * 1024) + b'"}')
    with pytest.raises(SarifImportError, match="more than the 1048576-byte bound"):
        load_json_object(large, "--normalization")
    with pytest.raises(SarifImportError, match="could not open the --normalization file"):
        load_json_object(tmp_path / "missing.json", "--normalization")
    with pytest.raises(SarifImportError, match="the --normalization file .* is not a regular file, so it is not read"):
        load_json_object(tmp_path, "--normalization")


def test_a_leading_byte_order_mark_is_the_one_thing_tolerated_and_it_is_noted():
    log, notes = parse_log(b"\xef\xbb\xbf" + encoded(minimal_log()))
    assert log == minimal_log()
    assert notes == ["A leading UTF-8 byte order mark was ignored (RFC 8259 section 8.1); the artifact "
                     "hash covers the bytes as supplied."]
    assert parse_log(encoded(minimal_log())) == (minimal_log(), [])


@pytest.mark.parametrize("log,message", [
    ({"version": "2.0.0", "runs": []}, "declares version '2.0.0'; this importer reads SARIF 2.1.0 only"),
    ({"runs": []}, "declares version None"),
    ({"version": "2.1.0"}, "no runs property"),
    ({"version": "2.1.0", "runs": None}, "runs is null: the producer failed to populate it"),
    ({"version": "2.1.0", "runs": []}, "runs is empty"),
    ({"version": "2.1.0", "runs": {}}, "runs is a dict, not an array"),
    ({"version": "2.1.0", "runs": ["run"]}, r"runs\[0\] is a str, not a run object"),
])
def test_a_log_that_is_not_one_readable_sarif_2_1_0_run_is_refused(log, message):
    with pytest.raises(SarifImportError, match=message):
        select_run(log)


def test_several_runs_need_a_named_index_and_the_index_must_exist():
    log = minimal_log()
    log["runs"].append(deepcopy(log["runs"][0]))
    with pytest.raises(SarifImportError, match="holds 2 runs; name the one to import with --run-index"):
        select_run(log)
    index, run, count = select_run(log, 1)
    assert (index, count) == (1, 2) and run is log["runs"][1]
    for bad in (2, -1, True):
        with pytest.raises(SarifImportError, match="out of range: the log holds 2 run"):
            select_run(log, bad)
    assert select_run(minimal_log())[::2] == (0, 1)


@pytest.mark.parametrize("value", [
    {"results": [{"location": {"uri": "results.sarif-external-properties"}}]},
    {"rules": [{"guid": "00000000-0000-4000-8000-000000000001"}]},
    {},
    None,
])
def test_external_property_files_anywhere_in_the_log_refuse_it_whole(value):
    log = minimal_log()
    log["runs"].append({**deepcopy(log["runs"][0]), "externalPropertyFileReferences": value})
    # The run that points outside the log is not the one selected, and the log is still refused,
    # whatever the property holds: even an empty or null one says nothing an import can check.
    with pytest.raises(SarifImportError, match=r"runs\[1\] carries externalPropertyFileReferences"):
        select_run(log, 0)
    on_the_log = {**minimal_log(), "externalPropertyFileReferences": value}
    with pytest.raises(SarifImportError, match="the log object carries externalPropertyFileReferences"):
        select_run(on_the_log)
    # Inline external properties stay inside the file, and nothing refers to them without the
    # property above, so their presence alone is not a refusal.
    assert select_run({**minimal_log(), "inlineExternalProperties": [{"results": []}]})[0] == 0


@pytest.mark.parametrize("run,message", [
    ({"results": []}, "has no tool.driver object"),
    ({"tool": {"driver": {"rules": []}}, "results": []}, "tool/driver has no name"),
    ({"tool": {"driver": {"name": "x"}, "extensions": {}}, "results": []}, "tool/extensions is a dict"),
    ({"tool": {"driver": {"name": "x"}, "extensions": ["e"]}, "results": []}, "extensions/0 is not a tool component"),
    ({"tool": {"driver": {"name": "x", "rules": {}}}, "results": []}, "driver/rules is a dict, not an array"),
    ({"tool": {"driver": {"name": "x"}}, "artifacts": {}, "results": []}, "artifacts is a dict"),
    ({"tool": {"driver": {"name": "x"}}, "originalUriBaseIds": [], "results": []}, "originalUriBaseIds is not an object"),
    ({"tool": {"driver": {"name": "x"}}, "results": {}}, "results is a dict, not an array"),
])
def test_a_run_not_shaped_like_a_run_is_refused_whole(run, message):
    with pytest.raises(SarifImportError, match=message):
        convert_run({"version": "2.1.0", "runs": [run]})


# --- claims from a Semgrep-shaped and a CodeQL-shaped log --------------------------------


def test_a_semgrep_shaped_log_matches_rules_by_id_and_excludes_its_nosemgrep_suppression(tmp_path):
    tree = SourceTree.load(tmp_path, write_tree(tmp_path))
    conversion = convert_run(fixture("semgrep.sarif"), tree=tree)

    assert [claim["claim_id"] for claim in conversion.claims] == ["r0-0", "r0-2"]
    assert conversion.losses == []
    assert conversion.excluded == [{"pointer": "/runs/0/results/1", "reason": "suppressed",
                                    "suppression": {"state": "suppressed",
                                                    "entries": [{"kind": "inSource", "status": None}]}}]
    shell, sql = conversion.claims
    assert shell == {
        "claim_id": "r0-0", "allegation": "subprocess call with shell=True", "kind": "command_injection",
        "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5},
        "native_rule_id": "build.rules.python.probe.subprocess-shell", "native_severity": "warning",
        "native_cwe": ["CWE-78"], "raw_artifact_id": "sarif"}
    # Semgrep names the rule by id alone; the descriptor is found by that id. The login-gated
    # fingerprint is recorded as withheld, never as an identity.
    entry = conversion.entries[0]
    assert entry["descriptor"] == "/runs/0/tool/driver/rules/1" and entry["rule_id"] == shell["native_rule_id"]
    assert entry["fingerprints"] == {"matchBasedId/v1": None} and "native_id" not in shell
    assert entry["suppression"] == {"state": "unavailable", "entries": []}
    assert sql["kind"] == "sql_injection" and sql["native_severity"] == "error"
    # The trace's steps carry no uriBaseId, which this profile reads as the scanned root.
    assert sql["evidence_text"] == "\n".join([
        "flow 1, thread 1, step 1: src/db.py:4 Source: 'request.args' @ 'src/db.py:4'",
        "flow 1, thread 1, step 2: src/db.py:4 Propagator : 'name' @ 'src/db.py:4'",
        "flow 1, thread 1, step 3: src/db.py:7 Taint reaches: 'cursor.execute(...)' @ 'src/db.py:7'"])
    assert conversion.execution["evidence"] == "reported_success"
    assert conversion.outcome() == ("success", None)
    assert conversion.tool == {"name": "Semgrep OSS", "version": None, "semanticVersion": "1.177.0",
                               "organization": None, "extensions": []}


def test_include_suppressed_imports_the_suppressed_result_and_still_records_its_suppression():
    conversion = convert_run(fixture("semgrep.sarif"), include_suppressed=True)
    assert [claim["claim_id"] for claim in conversion.claims] == ["r0-0", "r0-1", "r0-2"]
    assert conversion.excluded == []
    assert conversion.entries[1]["suppression"] == {"state": "suppressed",
                                                    "entries": [{"kind": "inSource", "status": None}]}


def test_a_codeql_shaped_log_resolves_driver_and_extension_rules_artifacts_links_and_flows(tmp_path):
    tree = SourceTree.load(tmp_path, write_tree(tmp_path))
    conversion = convert_run(fixture("codeql.sarif"), tree=tree)

    assert conversion.losses == [] and conversion.excluded == []
    sql, path, command = conversion.claims
    sql_entry, path_entry, command_entry = conversion.entries
    assert sql["native_rule_id"] == "py/sql-injection" and sql_entry["descriptor"] == "/runs/0/tool/driver/rules/0"
    assert sql["allegation"] == "This SQL query depends on a [user-provided value](1)."
    assert sql["kind"] == "sql_injection" and sql["native_cwe"] == ["CWE-89"]
    assert sql["native_severity"] == "error; security-severity 8.8"
    assert sql["primary_location"] == {"path": "app/web.py", "start_line": 16, "end_line": 16}
    assert sql["related_locations"] == [{"path": "app/web.py", "start_line": 5, "end_line": 5}]
    assert sql["evidence_text"] == "\n".join([
        "flow 1, thread 1, step 1: app/web.py:5 ControlFlowNode for ImportMember",
        "flow 1, thread 1, step 2: app/web.py:12 ControlFlowNode for Attribute",
        "flow 1, thread 1, step 3: app/web.py:16 ControlFlowNode for BinaryExpr"])
    assert sql_entry["partial_fingerprints"] == {"primaryLocationLineHash": "e08e53ec4172332b:1",
                                                 "primaryLocationStartColumnFingerprint": "15"}
    assert sql_entry["fingerprints"] is None
    # Both embedded links name the one related location carrying that id, so nothing is lost.
    assert [entry["evidence_losses"] for entry in conversion.entries] == [[], [], []]

    # Rules found in an extension by rule.toolComponent.index and rule.index.
    assert path_entry["descriptor"] == "/runs/0/tool/extensions/0/rules/0"
    assert path["kind"] == "path_traversal" and path["native_cwe"] == ["CWE-22", "CWE-23", "CWE-36"]
    assert command_entry["descriptor"] == "/runs/0/tool/extensions/0/rules/1"
    assert command["kind"] == "command_injection"
    # Two paths from one source to one sink are one allegation; two different sources may not be.
    assert path_entry["bundle_review"] == []
    assert path["evidence_text"].count("flow 2, thread 1") == 3
    assert command_entry["bundle_review"] == ["divergent_code_flows"]
    assert command["related_locations"] == [{"path": "app/run.py", "start_line": 4, "end_line": 4},
                                            {"path": "app/run.py", "start_line": 14, "end_line": 14}]
    assert conversion.flagged == {"/runs/0/results/2": ["divergent_code_flows"]}
    # A level-none notification is not a failure.
    assert conversion.execution == {
        "evidence": "reported_success", "results": "present", "verified": False,
        "invocations": [{"pointer": "/runs/0/invocations/0", "execution_successful": True, "exit_code": None,
                         "exit_signal_name": None, "notifications": 1, "error_notifications": []}]}
    assert conversion.tool["extensions"] == [{"name": "codeql/python-queries", "version": None,
                                              "semanticVersion": "1.8.7+" + "0" * 40, "organization": None}]


def test_a_multi_run_log_imports_the_named_run_with_run_scoped_claim_ids():
    log = fixture("semgrep.sarif")
    log["runs"].append(fixture("codeql.sarif")["runs"][0])
    with pytest.raises(SarifImportError, match="holds 2 runs"):
        convert_run(log)
    second = convert_run(log, 1)
    assert (second.run_index, second.run_count) == (1, 2)
    assert [claim["claim_id"] for claim in second.claims] == ["r1-0", "r1-1", "r1-2"]
    assert [entry["pointer"] for entry in second.entries] == [f"/runs/1/results/{n}" for n in range(3)]
    assert second.entries[0]["descriptor"] == "/runs/1/tool/driver/rules/0"
    assert [claim["claim_id"] for claim in convert_run(log, 0).claims] == ["r0-0", "r0-2"]


# --- mapping URIs into the scanned tree ---------------------------------------------------


def test_srcroot_in_any_case_and_a_missing_base_both_mean_the_scanned_root():
    conversion = converted([result_at("src/app.py", base="%srcroot%"), result_at("src/app.py", base=None),
                            result_at("./src//app.py")])
    assert [claim["primary_location"]["path"] for claim in conversion.claims] == ["src/app.py"] * 3


def test_an_original_uri_base_id_chain_resolves_through_the_source_root_or_a_configured_base():
    bases = {"PROJECTROOT": {"uri": "file:///build/checkout/"},
             "SRCROOT": {"uri": "app/", "uriBaseId": "PROJECTROOT"}}
    results = [result_at("web.py", base="SRCROOT")]
    reason = only_loss(converted(results, originalUriBaseIds=bases))
    assert "under uriBaseId 'SRCROOT' is an absolute file URI, and no --source-root-uri says" in reason
    claim, _ = only_claim(converted(results, originalUriBaseIds=bases,
                                    settings=UriSettings(source_root_uri="file:///build/checkout/")))
    assert claim["primary_location"]["path"] == "app/web.py"
    outside = only_loss(converted(results, originalUriBaseIds=bases,
                                  settings=UriSettings(source_root_uri="file:///build/other/")))
    assert "lies outside the declared source root file:///build/other/" in outside
    # A configured value applies wherever its id appears, inside the chain too.
    claim, _ = only_claim(converted(results, originalUriBaseIds=bases,
                                    settings=UriSettings({"PROJECTROOT": "."})))
    assert claim["primary_location"]["path"] == "app/web.py"


def test_a_configured_base_comes_first_and_an_unknown_base_is_a_loss():
    results = [result_at("web.py", base="APPROOT")]
    assert "uriBaseId 'APPROOT' is not configured with --uri-base, not declared in run.originalUriBaseIds, " \
           "and is not %SRCROOT%" in only_loss(converted(results))
    claim, _ = only_claim(converted(results, settings=UriSettings({"APPROOT": "app/"})))
    assert claim["primary_location"]["path"] == "app/web.py"
    # Configured beats what the log declares, and beats the %SRCROOT% default.
    elsewhere = {"%SRCROOT%": {"uri": "file:///somewhere/else/"}}
    claim, _ = only_claim(converted([result_at("web.py")], originalUriBaseIds=elsewhere,
                                    settings=UriSettings({"%SRCROOT%": "app/"})))
    assert claim["primary_location"]["path"] == "app/web.py"
    assert "no --source-root-uri" in only_loss(converted([result_at("web.py")], originalUriBaseIds=elsewhere))


@pytest.mark.parametrize("bases,message", [
    ({"A": {"uri": "a/", "uriBaseId": "B"}, "B": {"uri": "b/", "uriBaseId": "A"}}, "uriBaseId chain A -> B -> A loops"),
    ({"A": {"uri": "src", "uriBaseId": "%SRCROOT%"}}, "does not end with '/'"),
    ({"A": {"description": {"text": "hidden"}}}, "omits its uri, so only --uri-base A=... can say where it points"),
    ({"A": {"uri": "src/"}}, "has a relative uri and no uriBaseId"),
    ({"A": {"uri": "https://example.invalid/src/"}}, "uses the https scheme, not a file URI"),
    ({"A": {"uri": "../src/", "uriBaseId": "%SRCROOT%"}}, "'..' segment"),
])
def test_an_original_uri_base_id_that_cannot_resolve_is_a_loss(bases, message):
    assert message in only_loss(converted([result_at("web.py", base="A")], originalUriBaseIds=bases))


def test_absolute_file_uris_map_only_under_the_declared_source_root():
    results = [result_at("file:///build/checkout/app/web.py", base=None)]
    assert "is an absolute file URI, and no --source-root-uri" in only_loss(converted(results))
    root = UriSettings(source_root_uri="file:///build/checkout")
    claim, _ = only_claim(converted(results, settings=root))
    assert claim["primary_location"]["path"] == "app/web.py"
    localhost = [result_at("file://localhost/build/checkout/app/web.py", base=None)]
    assert only_claim(converted(localhost, settings=root))[0]["primary_location"]["path"] == "app/web.py"
    assert "outside the declared source root" in only_loss(converted(
        [result_at("file:///etc/passwd", base=None)], settings=root))
    assert "also names uriBaseId" in only_loss(converted(
        [result_at("file:///build/checkout/app/web.py")], settings=root))


@pytest.mark.parametrize("uri,message", [
    ("http://example.invalid/app/web.py", "uses the http scheme; only a file in the scanned tree"),
    ("sarif:/runs/0/results/1", "uses the sarif scheme"),
    ("../etc/passwd", "'..' segment"),
    ("app/%2E%2E/%2E%2E/etc/passwd", "'..' segment"),
    ("/etc/passwd", "is an absolute path, not a path relative to a base"),
    ("//fileserver/share/app.py", "network-path reference"),
    ("C:/src/app.py", "begins with a drive letter"),
    ("c:app.py", "begins with a drive letter"),
    ("app\\web.py", "holds a backslash"),
    ("app/web.py?raw=1", "has a query or fragment"),
    ("app/web.py#L5", "has a query or fragment"),
    ("app/%2Fetc/passwd", "encodes a slash, a backslash, or a NUL"),
    ("app/web%00.py", "encodes a slash, a backslash, or a NUL"),
    # Decoded, this is "..\..\etc\passwd" in one segment, which every later reader splits.
    ("%2E%2E%5C%2E%2E%5Cetc%5Cpasswd", "encodes a slash, a backslash, or a NUL"),
    ("app%5Cweb.py", "encodes a slash, a backslash, or a NUL"),
    ("app/%FF.py", "percent-decodes to bytes that are not UTF-8"),
    ("app/", "names a directory, not a file"),
    ("", "names a directory, not a file"),
])
def test_a_uri_that_names_no_file_inside_the_scanned_tree_is_a_loss(uri, message):
    reason = only_loss(converted([result_at(uri)]))
    assert reason.startswith("/runs/0/results/0/locations/0/physicalLocation/artifactLocation: ")
    assert message in reason


def test_percent_encoding_is_decoded_one_segment_at_a_time():
    claim, _ = only_claim(converted([result_at("app/my%20file.py", region={"startLine": 2})]))
    assert claim["primary_location"] == {"path": "app/my file.py", "start_line": 2, "end_line": 2}


def test_an_artifact_index_is_bounds_checked_and_must_agree_with_the_uri():
    artifacts = [{"location": {"uri": "app/web.py", "uriBaseId": "%SRCROOT%", "index": 0}},
                 {"location": {"uri": "app/files.py", "uriBaseId": "%SRCROOT%"}, "parentIndex": 0},
                 {"location": {"uri": "app/run.py", "uriBaseId": "%SRCROOT%", "index": 7}}]

    def at(**artifact_location):
        return result_at("unused", locations=[{"physicalLocation": {
            "artifactLocation": artifact_location, "region": {"startLine": 5}}}])

    conversion = converted([at(index=0), at(uri="app/web.py", uriBaseId="%SRCROOT%", index=0),
                            at(index=3), at(uri="app/run.py", uriBaseId="%SRCROOT%", index=0),
                            at(index=1), at(index=2), at(index=-2), at()], artifacts=artifacts)
    assert [claim["primary_location"]["path"] for claim in conversion.claims] == ["app/web.py", "app/web.py"]
    reasons = [loss["reason"] for loss in conversion.losses]
    assert "index 3 is out of range: run.artifacts holds 3" in reasons[0]
    assert "names 'app/run.py' by uri and 'app/web.py' by index 0" in reasons[1]
    assert "is nested inside artifacts[0]" in reasons[2]
    assert "/location/index is 7, not its own position 2" in reasons[3]
    assert "index is -2, not an array index" in reasons[4]
    assert "has neither uri nor index" in reasons[5]


def test_with_a_source_dir_every_mapped_path_and_line_must_exist_in_the_exported_tree(tmp_path):
    tree = SourceTree.load(tmp_path, write_tree(tmp_path))
    conversion = converted([result_at("src/app.py"), result_at("src/missing.py"),
                            result_at("src/app.py", region={"startLine": 12, "endLine": 13})], tree=tree)
    assert [claim["claim_id"] for claim in conversion.claims] == ["r0-0"]
    reasons = [loss["reason"] for loss in conversion.losses]
    assert "maps to 'src/missing.py', which is not a regular file in the exported tree" in reasons[0]
    assert "ends on line 13 of 'src/app.py', which has 12 line(s)" in reasons[1]
    os.symlink(tmp_path / "src" / "app.py", tmp_path / "linked.py")
    tree = SourceTree.load(tmp_path, materialize.hash_exported_tree(tmp_path)["tree_hash"])
    assert "not a regular file in the exported tree" in only_loss(converted([result_at("linked.py")], tree=tree))


def test_a_source_dir_that_is_not_the_declared_tree_is_refused(tmp_path):
    write_tree(tmp_path)
    with pytest.raises(SarifImportError, match="hashes to sha256:[0-9a-f]{64}, not the declared tree hash"):
        SourceTree.load(tmp_path, HASH)
    with pytest.raises(SarifImportError, match="is not a directory"):
        SourceTree.load(tmp_path / "README.md", HASH)


@pytest.mark.parametrize("bases,root,message", [
    ({"A": "src"}, None, "must end with '/'"),
    ({"A": "../src/"}, None, "'..' segment"),
    ({"A": "https://example.invalid/src/"}, None, "neither a directory inside the scanned tree nor a file URI"),
    ({"A": "file:///build/checkout/src/"}, None, "no --source-root-uri"),
    ({"A": "file:///elsewhere/src/"}, "file:///build/checkout/", "outside the declared source root"),
    ({"": "src/"}, None, "needs a name before '='"),
    ({}, "https://example.invalid/", "is not an absolute file URI"),
    ({}, "build/checkout/", "is not an absolute file URI"),
])
def test_a_configured_base_or_source_root_that_cannot_name_a_directory_is_refused(bases, root, message):
    with pytest.raises(SarifImportError, match=message):
        UriSettings(bases, root)
    assert UriSettings({"A": "file:///build/checkout/src/"}, "file:///build/checkout/").bases == {"A": ("src",)}
    assert UriSettings({"A": "", "B": "./"}).bases == {"A": (), "B": ()}


# --- regions -------------------------------------------------------------------------------


@pytest.mark.parametrize("region,lines", [
    ({"startLine": 5}, (5, 5)),
    ({"startLine": 5, "startColumn": 3, "endColumn": 9}, (5, 5)),
    ({"startLine": 2, "endLine": 4, "endColumn": 7}, (2, 4)),
    # endColumn 1 on a later line ends with the previous line's newline (SARIF 3.30.2, example 5).
    ({"startLine": 2, "endLine": 3, "endColumn": 1}, (2, 2)),
    ({"startLine": 2, "endLine": 5, "endColumn": 1}, (2, 4)),
    ({"startLine": 5, "startColumn": 1, "endColumn": 1}, (5, 5)),
    ({"startLine": 5, "charOffset": 70, "charLength": 31}, (5, 5)),
])
def test_region_lines_come_from_start_and_end_line_with_the_end_column_trap(region, lines):
    claim, entry = only_claim(converted([result_at("src/app.py", region=region)]))
    assert (claim["primary_location"]["start_line"], claim["primary_location"]["end_line"]) == lines
    assert entry["notes"] == []


@pytest.mark.parametrize("region,note", [
    (False, "primary location: no region: the location is the whole file"),
    ({"charOffset": 70, "charLength": 31}, "primary location: offset-only region: recorded file-only"),
    ({"byteOffset": 0}, "primary location: offset-only region"),
])
def test_a_missing_or_offset_only_region_stays_file_only_and_says_so(region, note):
    claim, entry = only_claim(converted([result_at("src/app.py", region=region)]))
    assert claim["primary_location"] == {"path": "src/app.py"}
    assert len(entry["notes"]) == 1 and entry["notes"][0].startswith(note)


@pytest.mark.parametrize("region,message", [
    ({"startLine": 0}, "startLine is 0, not a positive integer"),
    ({"startLine": "5"}, "startLine is '5', not a positive integer"),
    ({"startLine": True}, "startLine is True"),
    ({"startLine": 5.0}, "startLine is 5.0"),
    ({"startLine": 6, "endLine": 5}, "ends on line 5, before it starts on line 6"),
    ({"startLine": 5, "startColumn": 9, "endColumn": 3}, "ends at column 3, before it starts at column 9"),
    ({"endLine": 5}, "has endLine without startLine"),
    ({"startColumn": 2, "charOffset": 4}, "has startColumn without startLine"),
    ({}, "states no startLine, charOffset, or byteOffset"),
    ({"charOffset": -1}, "states no startLine, charOffset, or byteOffset"),
    ({"charOffset": -2}, "charOffset is -2, not an integer of at least -1"),
    ({"snippet": {"text": "x"}}, "states no startLine"),
    ("5", "not a region object"),
])
def test_malformed_region_coordinates_are_a_loss(region, message):
    assert message in only_loss(converted([result_at("src/app.py", region=region)]))


# --- kinds, baselines, and suppressions ----------------------------------------------------


def test_results_that_allege_nothing_or_were_not_detected_are_excluded_and_counted():
    conversion = converted([
        result_at("src/app.py", kind="pass"), result_at("src/app.py", kind="notApplicable"),
        result_at("src/app.py", kind="informational"), result_at("src/app.py", baselineState="absent"),
        result_at("src/app.py", kind="review"), result_at("src/app.py", kind="open", level="none"),
        result_at("src/app.py", baselineState="new"), result_at("src/app.py", kind="warning"),
        result_at("src/app.py", baselineState="gone")])
    assert conversion.excluded == [
        {"pointer": "/runs/0/results/0", "reason": "kind:pass"},
        {"pointer": "/runs/0/results/1", "reason": "kind:notApplicable"},
        {"pointer": "/runs/0/results/2", "reason": "kind:informational"},
        {"pointer": "/runs/0/results/3", "reason": "baseline:absent"}]
    review, opened, new = conversion.claims
    assert (review["native_severity"], opened["native_severity"], new["native_severity"]) == ("review", "open", "warning")
    assert [entry["kind"] for entry in conversion.entries] == ["review", "open", "fail"]
    assert [entry["level"] for entry in conversion.entries] == ["none", "none", "warning"]
    assert conversion.entries[2]["baseline_state"] == "new"
    assert [loss["pointer"] for loss in conversion.losses] == ["/runs/0/results/7", "/runs/0/results/8"]
    assert "kind 'warning' is not a SARIF result kind" in conversion.losses[0]["reason"]
    assert "baselineState 'gone' is not a SARIF baseline state" in conversion.losses[1]["reason"]
    assert conversion.result_count == 9


@pytest.mark.parametrize("suppressions,suppressed", [
    ([{"kind": "inSource"}], True),
    ([{"kind": "external", "status": "accepted"}], True),
    ([{"kind": "inSource", "status": "underReview"}], False),
    ([{"kind": "inSource", "status": "rejected"}], False),
    ([{"kind": "inSource"}, {"kind": "external", "status": "rejected"}], False),
])
def test_a_suppression_suppresses_unless_one_is_under_review_or_rejected(suppressions, suppressed):
    conversion = converted([result_at("src/app.py", suppressions=suppressions)])
    entries = [{"kind": item["kind"], "status": item.get("status")} for item in suppressions]
    if suppressed:
        assert conversion.claims == []
        assert conversion.excluded == [{"pointer": "/runs/0/results/0", "reason": "suppressed",
                                        "suppression": {"state": "suppressed", "entries": entries}}]
        included = converted([result_at("src/app.py", suppressions=suppressions)], include_suppressed=True)
        assert only_claim(included)[1]["suppression"] == {"state": "suppressed", "entries": entries}
    else:
        assert only_claim(conversion)[1]["suppression"] == {"state": "not_suppressed", "entries": entries}


def test_empty_absent_and_malformed_suppressions():
    conversion = converted([result_at("src/app.py", suppressions=[]), result_at("src/app.py"),
                            result_at("src/app.py", suppressions=[{"kind": "inSource", "status": "maybe"}]),
                            result_at("src/app.py", suppressions={"kind": "inSource"})])
    assert [entry["suppression"]["state"] for entry in conversion.entries] == ["none", "unavailable"]
    assert "status 'maybe' is not a SARIF suppression status" in conversion.losses[0]["reason"]
    assert "suppressions is not an array" in conversion.losses[1]["reason"]


# --- rules, levels, CWE ids, and messages ---------------------------------------------------


def codeql_with(result: dict) -> dict:
    log = fixture("codeql.sarif")
    log["runs"][0]["results"] = [result]
    return log


def codeql_result(**changes) -> dict:
    result = deepcopy(fixture("codeql.sarif")["runs"][0]["results"][0])
    result.update(changes)
    return result


@pytest.mark.parametrize("changes,message", [
    ({"ruleId": "py/sql-injection", "rule": {"id": "py/xss", "index": 0}}, "carries ruleId 'py/sql-injection' and rule.id 'py/xss'"),
    ({"ruleIndex": 0, "rule": {"index": 1}}, "carries ruleIndex 0 and rule.index 1"),
    ({"ruleIndex": 4, "rule": {"id": "py/sql-injection", "index": 4}}, "names rule index 4, and /runs/0/tool/driver/rules holds 1"),
    ({"rule": {"id": "py/sql-injection", "index": 0, "toolComponent": {"index": 3}}}, "toolComponent.index 3 names no element of tool.extensions (1 present)"),
    ({"ruleId": "py/xss", "ruleIndex": 0, "rule": {"id": "py/xss", "index": 0}}, "names rule 'py/xss', which is neither descriptor 'py/sql-injection'"),
    ({"ruleIndex": "0", "rule": None}, "ruleIndex is '0', not an array index"),
    ({"ruleId": 7}, "ruleId is not a non-empty string"),
    ({"rule": "py/sql-injection"}, "rule is not a reportingDescriptorReference object"),
    ({"rule": {"guid": "11111111-2222-3333-4444-555555555555"}, "ruleIndex": None}, "names 0 rules"),
])
def test_a_rule_reference_that_conflicts_or_names_nothing_is_a_loss(changes, message):
    result = codeql_result(**changes)
    result = {key: value for key, value in result.items() if value is not None}
    assert message in only_loss(convert_run(codeql_with(result)))


def test_rules_are_found_by_guid_by_a_hierarchical_narrowing_or_not_at_all():
    log = codeql_with(codeql_result(ruleId="py/sql-injection/concatenation", ruleIndex=None,
                                    rule={"id": "py/sql-injection/concatenation", "guid": "rule-guid",
                                          "toolComponent": {"guid": "driver-guid"}}))
    log["runs"][0]["tool"]["driver"]["guid"] = "driver-guid"
    log["runs"][0]["tool"]["driver"]["rules"][0]["guid"] = "rule-guid"
    log["runs"][0]["results"][0] = {key: value for key, value in log["runs"][0]["results"][0].items()
                                    if value is not None}
    claim, entry = only_claim(convert_run(log))
    assert claim["native_rule_id"] == "py/sql-injection" and entry["rule_id"] == "py/sql-injection/concatenation"
    assert entry["descriptor"] == "/runs/0/tool/driver/rules/0"

    # An id-only reference is matched whole, then less its last hierarchical component.
    claim, entry = only_claim(converted([result_at("src/app.py", ruleId=SHELL_RULE + "/md5")]))
    assert claim["native_rule_id"] == SHELL_RULE and entry["descriptor"] == "/runs/0/tool/driver/rules/0"
    # No descriptor is not a loss: the result keeps its own id and says where its level came from.
    claim, entry = only_claim(converted([result_at("src/app.py", ruleId="rules.unlisted")]))
    assert claim["native_rule_id"] == "rules.unlisted" and entry["descriptor"] is None
    assert claim["kind"] == "unmapped" and claim["native_severity"] == "warning"
    assert entry["notes"] == ["no rule descriptor matches 'rules.unlisted'; the level and CWE ids come from "
                              "the result alone"]
    unnamed = {key: value for key, value in result_at("src/app.py").items() if key != "ruleId"}
    claim, entry = only_claim(converted([unnamed]))
    assert "native_rule_id" not in claim and entry["rule_id"] is None


def test_an_id_shared_by_two_descriptors_needs_an_index_or_guid():
    log = minimal_log()
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    rules.append(deepcopy(rules[0]))
    assert "which 2 descriptors in /runs/0/tool/driver share" in only_loss(convert_run(log))
    log["runs"][0]["results"][0]["ruleIndex"] = 1
    assert only_claim(convert_run(log))[1]["descriptor"] == "/runs/0/tool/driver/rules/1"


def test_the_level_is_the_results_else_the_rules_default_else_warning():
    log = minimal_log(results=[result_at("src/app.py", level="note"), result_at("src/app.py"),
                               result_at("src/app.py", ruleId="rules.unlisted"),
                               result_at("src/app.py", level="severe")])
    log["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] = 9.1
    conversion = convert_run(log)
    assert [entry["level"] for entry in conversion.entries] == ["note", "warning", "warning"]
    assert [claim["native_severity"] for claim in conversion.claims] == [
        "note; security-severity 9.1", "warning; security-severity 9.1", "warning"]
    assert "level 'severe' is not a SARIF level" in conversion.losses[0]["reason"]


def test_cwe_ids_come_from_taxonomy_relationships_result_taxa_and_tags():
    log = minimal_log(results=[
        result_at("src/app.py", taxa=[{"id": "79", "toolComponent": {"name": "CWE"}}]),
        result_at("src/app.py", taxa=[{"id": "80", "toolComponent": {"name": "OWASP"}}])])
    run = log["runs"][0]
    run["taxonomies"] = [{"name": "CWE", "guid": "cwe-guid", "taxa": [{"id": "89"}, {"id": "327"}]}]
    rule = run["tool"]["driver"]["rules"][0]
    rule["properties"]["tags"] = ["security", "external/cwe/cwe-022"]
    rule["relationships"] = [
        {"target": {"id": "89", "toolComponent": {"guid": "cwe-guid"}}, "kinds": ["superset"]},
        {"target": {"id": "CWE-327", "toolComponent": {"index": 0}}, "kinds": ["equal"]},
        # A narrower relationship applies to a result only through that result's own taxa.
        {"target": {"id": "798", "toolComponent": {"name": "CWE"}}, "kinds": ["relevant"]},
        {"target": {"id": "1", "toolComponent": {"name": "CodeScanner"}}, "kinds": ["superset"]}]
    first, second = convert_run(log).claims
    assert first["native_cwe"] == ["CWE-89", "CWE-327", "CWE-79", "CWE-22"]
    assert first["kind"] == "sql_injection"
    assert second["native_cwe"] == ["CWE-89", "CWE-327", "CWE-22"]


@pytest.mark.parametrize("message,descriptor_changes,expected", [
    ({"text": "  Tainted {x} reaches sink()  \n"}, {}, "Tainted {x} reaches sink()"),
    ({"text": "Variable '{0}' is uninitialized; {{0}} is literal.", "arguments": ["pBuffer"]}, {},
     "Variable 'pBuffer' is uninitialized; {0} is literal."),
    ({"id": "default", "arguments": ["cmd", "5"]},
     {"messageStrings": {"default": {"text": "'{0}' reaches a shell on line {1}."}}}, "'cmd' reaches a shell on line 5."),
    ({"text": "", "id": "default"}, {"messageStrings": {"default": {"text": "No arguments needed."}}}, "No arguments needed."),
])
def test_a_message_is_its_own_text_or_its_rules_message_string_formatted_with_its_arguments(
        message, descriptor_changes, expected):
    log = minimal_log(results=[result_at("src/app.py", message=message)])
    log["runs"][0]["tool"]["driver"]["rules"][0].update(descriptor_changes)
    assert only_claim(convert_run(log))[0]["allegation"] == expected


def test_a_global_message_string_is_the_last_place_an_id_is_looked_up():
    log = minimal_log(results=[result_at("src/app.py", message={"id": "shared"})])
    log["runs"][0]["tool"]["driver"]["globalMessageStrings"] = {"shared": {"text": "Shared {{text}}."}}
    assert only_claim(convert_run(log))[0]["allegation"] == "Shared {text}."


@pytest.mark.parametrize("message,expected", [
    ({"text": "{1}", "arguments": ["only one"]}, "uses placeholder {1}, and 1 argument(s) are supplied"),
    ({"text": "a lone { brace", "arguments": []}, "has a lone '{' that is neither a placeholder"),
    ({"text": "a lone } brace", "arguments": []}, "has a lone '}'"),
    ({"text": "x", "arguments": [1]}, "arguments is not an array of strings"),
    ({"markdown": "**bold**"}, "has no text and no id"),
    ({"text": "   "}, "has blank text and no id"),
    ({"id": "missing"}, "id 'missing' is in neither the rule's messageStrings nor its component's globalMessageStrings"),
    ({"text": 5}, "text is a int, not a string"),
    ("plain", "is a str, not a message object"),
    (None, "has no message, which SARIF 3.27.11 requires"),
])
def test_a_message_that_does_not_resolve_is_a_loss(message, expected):
    assert expected in only_loss(converted([result_at("src/app.py", message=message)]))


def test_the_guid_is_the_native_id_and_fingerprints_are_provenance_only():
    result = result_at("src/app.py", guid="c0ffee00-0000-4000-8000-000000000001",
                       fingerprints={"matchBasedId/v1": "abc_0", "withheld/v1": "requires login", "odd": 5},
                       partialFingerprints={"primaryLocationLineHash": "e08e53ec4172332b:1"})
    claim, entry = only_claim(converted([result]))
    assert claim["native_id"] == "c0ffee00-0000-4000-8000-000000000001"
    assert entry["fingerprints"] == {"matchBasedId/v1": "abc_0", "withheld/v1": None}
    assert entry["partial_fingerprints"] == {"primaryLocationLineHash": "e08e53ec4172332b:1"}
    assert entry["notes"] == ["/runs/0/results/0/fingerprints['odd'] is not a string and was not recorded"]


# --- locations, related locations, flows, and links ------------------------------------------


def test_a_result_without_a_file_to_place_its_claim_in_is_a_loss():
    logical = {"logicalLocations": [{"fullyQualifiedName": "app.run"}]}
    conversion = converted([result_at("src/app.py", locations=[logical]), result_at("src/app.py", locations=[]),
                            {key: value for key, value in result_at("src/app.py").items() if key != "locations"},
                            result_at("src/app.py", locations=[{"physicalLocation": {"address": {"absoluteAddress": 4}}}]),
                            result_at("src/app.py", locations=["src/app.py"]), "a string",
                            result_at("src/app.py", locations={"physicalLocation": {}})])
    reasons = [loss["reason"] for loss in conversion.losses]
    assert "has only a logical location, which names no file" in reasons[0]
    assert "has no locations, so there is no file to place a claim in" in reasons[1]
    assert "has no locations" in reasons[2]
    assert "has no artifactLocation; an address names no file" in reasons[3]
    assert "/runs/0/results/4/locations/0 is not a location object" in reasons[4]
    assert reasons[5] == "/runs/0/results/5 is a str, not a result object"
    assert reasons[6] == "/runs/0/results/6/locations is a dict, not an array"


def test_more_locations_become_related_locations_and_flag_the_result_for_bundle_review():
    second = {"physicalLocation": {"artifactLocation": {"uri": "src/db.py", "uriBaseId": "%SRCROOT%"},
                                   "region": {"startLine": 3}}}
    broken = {"physicalLocation": {"artifactLocation": {"uri": "http://x.invalid/a.py"}}}
    related = [{"id": 1, "physicalLocation": {"artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 1}}},
               {"physicalLocation": {"artifactLocation": {"uri": "../outside.py"}}}]
    result = result_at("src/app.py", relatedLocations=related,
                       message={"text": "shell=True with [a caller value](1) and [another](4)"})
    result["locations"] += [second, broken]
    claim, entry = only_claim(converted([result]))
    assert claim["related_locations"] == [{"path": "src/db.py", "start_line": 3, "end_line": 3},
                                          {"path": "src/app.py", "start_line": 1, "end_line": 1}]
    assert entry["bundle_review"] == ["multiple_locations"]
    assert [loss["pointer"] for loss in entry["evidence_losses"]] == [
        "/runs/0/results/0/locations/2", "/runs/0/results/0/relatedLocations/1", "/runs/0/results/0/message"]
    assert "uses the http scheme" in entry["evidence_losses"][0]["reason"]
    assert "'..' segment" in entry["evidence_losses"][1]["reason"]
    assert entry["evidence_losses"][2]["reason"] == (
        "the message links to location id 4, and the result holds 0 location(s) with that id, not exactly one "
        "(SARIF 3.11.6)")


def flow(*steps) -> dict:
    return {"threadFlows": [{"locations": list(steps)}]}


def step(uri, line, text=None, **extra) -> dict:
    location = {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
    if text is not None:
        location["message"] = {"text": text}
    return {"location": location, **extra}


def test_flow_steps_render_in_execution_order_and_an_unresolved_step_is_an_evidence_loss():
    flows = [flow(step("src/app.py", 1, "source\nsplit over lines"), {"kinds": ["call"]},
                  step("/etc/passwd", 2, "escapes"), {"index": 0}, step("src/app.py", 5))]
    result = result_at("src/app.py", codeFlows=flows)
    claim, entry = only_claim(converted([result], threadFlowLocations=[step("src/db.py", 3, "cached step")]))
    assert claim["evidence_text"] == "\n".join([
        "flow 1, thread 1, step 1: src/app.py:1 source split over lines",
        "flow 1, thread 1, step 2: (no location)",
        "flow 1, thread 1, step 3: (unresolved location) escapes",
        "flow 1, thread 1, step 4: src/db.py:3 cached step",
        "flow 1, thread 1, step 5: src/app.py:5"])
    assert [loss["pointer"] for loss in entry["evidence_losses"]] == [
        "/runs/0/results/0/codeFlows/0/threadFlows/0/locations/2/location"]
    assert entry["bundle_review"] == []


def test_flow_rendering_stops_at_its_bound_and_records_the_rest_as_an_evidence_loss():
    steps = [step("src/app.py", 1 + number % 10, f"step {number}") for number in range(FLOW_STEP_LIMIT + 44)]
    claim, entry = only_claim(converted([result_at("src/app.py", codeFlows=[flow(*steps)])]))
    lines = claim["evidence_text"].split("\n")
    assert len(lines) == FLOW_STEP_LIMIT + 1
    assert lines[-1] == "(44 more flow step(s) not rendered; the raw artifact keeps them)"
    assert entry["evidence_losses"] == [{"pointer": "/runs/0/results/0/codeFlows", "reason": (
        f"44 of {FLOW_STEP_LIMIT + 44} flow steps were not rendered: evidence text stops at {FLOW_STEP_LIMIT} "
        "steps or 65536 bytes")}]


def test_flows_that_start_in_different_places_flag_bundle_review_and_malformed_flows_are_losses():
    same = [flow(step("src/app.py", 1), step("src/app.py", 5)), flow(step("src/app.py", 1), step("src/app.py", 3))]
    assert only_claim(converted([result_at("src/app.py", codeFlows=same)]))[1]["bundle_review"] == []
    different = [flow(step("src/app.py", 1)), flow(step("src/db.py", 2))]
    claim, entry = only_claim(converted([result_at("src/app.py", codeFlows=different)]))
    assert entry["bundle_review"] == ["divergent_code_flows"]
    malformed = [{"threadFlows": []}, {"threadFlows": [{"locations": []}]}, flow({"index": 9})]
    claim, entry = only_claim(converted([result_at("src/app.py", codeFlows=malformed)]))
    assert claim["evidence_text"] == "flow 3, thread 1, step 1: (unresolved location)"
    assert [loss["pointer"] for loss in entry["evidence_losses"]] == [
        "/runs/0/results/0/codeFlows/0", "/runs/0/results/0/codeFlows/1/threadFlows/0",
        "/runs/0/results/0/codeFlows/2/threadFlows/0/locations/0"]
    assert "index 9 names no element of run.threadFlowLocations (0 present)" in entry["evidence_losses"][2]["reason"]
    # Starts that cannot be placed cannot be shown to be the same start.
    assert entry["bundle_review"] == ["divergent_code_flows"]


# --- the log's own account of execution -----------------------------------------------------


def test_a_log_without_invocations_is_never_a_clean_scan_even_with_no_results():
    conversion = converted([], invocations=None)
    assert conversion.execution["evidence"] == "unreported" and conversion.execution["invocations"] == []
    status, error = conversion.outcome()
    assert status == "partial" and error["code"] == "execution_unreported"
    conversion = converted([], invocations=[{"toolExecutionNotifications": []}])
    assert conversion.execution["evidence"] == "unreported"
    assert conversion.notes == ["/runs/0/invocations/0 has no boolean executionSuccessful, which SARIF "
                                "3.20.14 requires"]


def test_a_reported_failure_is_partial_with_claims_and_an_error_without_them():
    failed = [{"executionSuccessful": False, "exitCode": 2}]
    status, error = converted([result_at("src/app.py")], invocations=failed).outcome()
    assert status == "partial" and error["code"] == "execution_failed"
    assert "the log reports a failed execution at /runs/0/invocations/0" in error["message"]
    assert converted([], invocations=failed).outcome()[0] == "error"


def test_an_error_notification_beside_execution_successful_true_is_a_failed_run():
    # Semgrep's own shape for a scan that exited 2: success claimed, an error-level notification.
    invocations = [{"executionSuccessful": True, "toolExecutionNotifications": [
        {"descriptor": {"id": "SemgrepError"}, "level": "error",
         "message": {"text": "Invalid scanning root: targets/basic/inexistent.py"}}]}]
    conversion = converted([], invocations=invocations)
    assert conversion.execution["evidence"] == "reported_failed"
    assert conversion.execution["invocations"][0]["error_notifications"] == [
        "/runs/0/invocations/0/toolExecutionNotifications/0"]
    assert conversion.outcome()[0] == "error"
    # A notification with no level of its own takes its descriptor's default level.
    configured = [{"executionSuccessful": True, "toolConfigurationNotifications": [
        {"descriptor": {"id": "bad-config"}, "message": {"text": "rule file unreadable"}}]}]
    log = minimal_log(results=[], invocations=configured)
    log["runs"][0]["tool"]["driver"]["notifications"] = [
        {"id": "bad-config", "defaultConfiguration": {"level": "error"}}]
    assert convert_run(log).execution["evidence"] == "reported_failed"
    log["runs"][0]["tool"]["driver"]["notifications"][0]["defaultConfiguration"]["level"] = "note"
    assert convert_run(log).execution["evidence"] == "reported_success"


@pytest.mark.parametrize("results", [None, "absent"])
def test_absent_results_are_an_error_with_no_claims(results):
    log = minimal_log()
    if results == "absent":
        del log["runs"][0]["results"]
    else:
        log["runs"][0]["results"] = None
    conversion = convert_run(log)
    assert conversion.results_present is False and conversion.claims == [] and conversion.result_count == 0
    status, error = conversion.outcome()
    assert status == "error" and error["code"] == "results_absent"
    assert conversion.execution["results"] == "absent"


def test_import_loss_makes_an_otherwise_clean_run_partial():
    conversion = converted([result_at("src/app.py"), result_at("/etc/passwd")])
    status, error = conversion.outcome()
    assert status == "partial" and error == {
        "code": "import_loss", "message": "1 result(s) the log reports could not be imported as claims"}
    assert converted([result_at("src/app.py")]).outcome() == ("success", None)


# --- one import: the bundle ------------------------------------------------------------------


def test_an_import_writes_a_bundle_the_review_score_and_replay_paths_read(workspace):
    outcome = imported(workspace, source_dir=workspace["source"])
    bundle = outcome.bundle
    data = (FIXTURES / "codeql.sarif").read_bytes()
    digest = "sha256:" + hashlib.sha256(data).hexdigest()

    assert bundle_files(bundle) == BUNDLE_FILES
    assert (bundle / "raw" / "codeql.sarif").read_bytes() == data
    result = load_document(bundle / "result.json", "scan-result")
    assert result == outcome.result and result["schema_version"] == "2.1"
    assert result["run_id"] == default_run_id(digest, 0) == f"import-{digest[7:19]}-r0"
    assert result["usage"] == {"wall_seconds": None}
    assert (result["ranking"], result["status"], result["input_hash"]) == ("unranked", "success", workspace["tree_hash"])
    assert result["raw_artifacts"] == [{"id": "sarif", "path": "raw/codeql.sarif", "sha256": digest}]
    assert {claim["raw_artifact_id"] for claim in result["claims"]} == {"sarif"}
    # r0-2 is flagged for bundle review and nobody recorded a decision on it.
    assert result["bundles_resolved"] is False

    record = load_document(bundle / "import.json", "import-record")
    assert record == outcome.record and record["result_sha256"] == canonical_sha256(result)
    assert record["artifact"] == {"path": "raw/codeql.sarif", "sha256": digest, "bytes": len(data)}
    assert record["sarif"] == {"version": "2.1.0", "run_index": 0, "run_count": 1}
    assert record["source_binding"] == {"pack_sha256": cases.pack_sha256(workspace["pack"]), "snapshot_id": "snap-a",
                                        "tree_hash": workspace["tree_hash"], "source_dir_verified": True}
    assert record["system"] == {"system_id": "codeql-fixture", "config_sha256": None}
    assert record["counts"] == {"results": 3, "claims": 3, "excluded": 0, "losses": 0, "evidence_losses": 0,
                                "bundle_review_flagged": 1, "bundle_review_resolved": 0}
    assert record["execution"]["evidence"] == "reported_success" and record["execution"]["verified"] is False
    assert record["normalization"] is None
    assert record["options"] == {"run_index": None, "include_suppressed": False, "uri_bases": {},
                                 "source_root_uri": None, "max_bytes": 67108864}

    plan, decisions, review_record = review.load_evaluator(bundle)
    assert plan == cases.build_plan(workspace["pack"], "snap-a", workspace["tree_hash"])[0]
    assert [(match["claim_id"], match["target_id"], match["decision"]) for match in decisions["claim_matches"]] == [
        ("r0-0", "T-case-a", "unresolved")]
    assert review_record["state"] == "draft" and review_record["reviews"] == []
    assert review.review_status(bundle) == "draft"
    evaluation = scoring.score(plan, result, decisions)
    assert (bundle / "evaluation.json").read_bytes() == (canonical_json(evaluation) + "\n").encode("utf-8")
    assert evaluation["metrics"]["pending_matching_count"] == 1 and evaluation["metrics"]["targets_detected"] == 0
    assert "Decisions: machine-drafted, all unresolved" in (bundle / "report.html").read_text(encoding="utf-8")


def test_the_same_log_imports_to_the_same_documents_and_run_id(workspace):
    first = imported(workspace, name="first")
    second = imported(workspace, name="second")
    for name in ("result.json", "import.json", "evaluator/plan.json", "evaluator/decisions.json", "evaluation.json"):
        assert (first.bundle / name).read_bytes() == (second.bundle / name).read_bytes()
    assert first.record["source_binding"]["source_dir_verified"] is False
    assert "No --source-dir was supplied" in " ".join(first.record["notes"])
    named = imported(workspace, name="named", run_id="codeql-nightly-42")
    assert named.result["run_id"] == named.record["run_id"] == "codeql-nightly-42"


def test_a_system_configuration_is_recorded_by_digest_only(workspace):
    config = {"queries": "security-extended", "threads": 4}
    outcome = imported(workspace, system_config=config)
    assert outcome.record["system"] == {"system_id": "codeql-fixture", "config_sha256": canonical_sha256(config)}
    assert "security-extended" not in (outcome.bundle / "import.json").read_text(encoding="utf-8")


def test_an_import_without_invocations_is_partial_and_says_so_in_the_score(workspace):
    log = fixture("codeql.sarif")
    del log["runs"][0]["invocations"]
    outcome = imported(workspace, write_log(workspace, log))
    assert outcome.result["status"] == "partial"
    assert outcome.result["error"]["code"] == "execution_unreported"
    assert outcome.record["execution"]["evidence"] == "unreported"
    assert "Incomplete or failed execution cannot establish a successful negative control." in \
        outcome.evaluation["warnings"]


def test_absent_results_are_an_error_result_with_no_claims_and_unresolved_bundles(workspace):
    log = fixture("codeql.sarif")
    log["runs"][0]["results"] = None
    outcome = imported(workspace, write_log(workspace, log))
    assert (outcome.result["status"], outcome.result["claims"], outcome.result["bundles_resolved"]) == ("error", [], False)
    assert outcome.result["error"]["code"] == "results_absent"
    assert outcome.record["execution"]["results"] == "absent" and outcome.record["counts"]["results"] == 0


def normalization(outcome_or_digest, *decisions) -> dict:
    return {"artifact_sha256": outcome_or_digest, "decisions": list(decisions)}


def atomic(pointer: str = "/runs/0/results/2", **changes) -> dict:
    decision = {"pointer": pointer, "decision": "atomic", "reviewer": FICTIONAL_REVIEWER,
                "note": "Both flows reach one os.system call through one missing check.",
                "at": "2026-09-29T12:00:00+00:00"}
    decision.update(changes)
    return decision


def codeql_digest() -> str:
    return "sha256:" + hashlib.sha256((FIXTURES / "codeql.sarif").read_bytes()).hexdigest()


def test_a_recorded_atomic_decision_for_every_flagged_result_resolves_the_bundles(workspace):
    document = normalization(codeql_digest(), atomic())
    outcome = imported(workspace, normalization=document)
    assert outcome.result["bundles_resolved"] is True
    assert outcome.record["normalization"] == {"sha256": canonical_sha256(document), "decisions": [atomic()]}
    assert outcome.record["counts"]["bundle_review_resolved"] == 1
    # The claim stays one claim: resolving a bundle never splits or drops it.
    assert [claim["claim_id"] for claim in outcome.result["claims"]] == ["r0-0", "r0-1", "r0-2"]
    # Import loss keeps the bundles unresolved whatever was decided.
    log = fixture("codeql.sarif")
    log["runs"][0]["results"].append(result_at("/etc/passwd"))
    path = write_log(workspace, log)
    digest = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    lost = imported(workspace, path, name="lost", normalization=normalization(digest, atomic()))
    assert lost.result["bundles_resolved"] is False and lost.result["error"]["code"] == "import_loss"


@pytest.mark.parametrize("document,message", [
    (lambda digest: normalization(OTHER, atomic()), "recorded for artifact 'sha256:b"),
    (lambda digest: normalization(digest, atomic("/runs/0/results/0")), "did not flag for bundle review"),
    (lambda digest: normalization(digest, atomic("/runs/1/results/2")), "did not flag for bundle review"),
    (lambda digest: normalization(digest, atomic(), atomic()), "decides /runs/0/results/2 a second time"),
    (lambda digest: normalization(digest, atomic(decision="split")), "only 'atomic' can be recorded"),
    (lambda digest: normalization(digest, atomic(reviewer=chr(0x200B))), "names no reviewer"),
    (lambda digest: normalization(digest, atomic(note=" ")), "states no note"),
    (lambda digest: normalization(digest, atomic(approved=True)), "unknown keys"),
    (lambda digest: {"decisions": []}, "missing: artifact_sha256"),
    (lambda digest: [], "is not a JSON object"),
])
def test_a_normalization_file_that_does_not_fit_this_import_is_refused(workspace, document, message):
    with pytest.raises(SarifImportError, match=message):
        imported(workspace, normalization=document(codeql_digest()))
    assert not (workspace["out"] / "bundle").exists()


@pytest.mark.parametrize("change,error,message", [
    (lambda ws: {"tree_hash": "sha256:short"}, SarifImportError, "tree hash must be a sha256"),
    (lambda ws: {"tree_hash": HASH}, ContractError, "tree hash does not match the materialized input"),
    (lambda ws: {"snapshot_id": "snap-z"}, ContractError, "unknown snapshot 'snap-z'"),
    (lambda ws: {"system_id": " "}, SarifImportError, "a system id is required"),
    (lambda ws: {"run_id": ""}, SarifImportError, "run id, when given, must not be blank"),
    (lambda ws: {"system_config": ["x"]}, SarifImportError, "must be a JSON object"),
    (lambda ws: {"uri_bases": {"A": "../x/"}}, SarifImportError, "'..' segment"),
    (lambda ws: {"source_dir": ws["tmp"] / "export"}, SarifImportError, "not the declared tree hash"),
    (lambda ws: {"output": ws["source"] / "bundle", "source_dir": ws["source"]}, SarifImportError,
     "is inside --source-dir"),
    (lambda ws: {"sarif_path": FIXTURES / "missing.sarif"}, SarifImportError, "could not open the SARIF file"),
    (lambda ws: {"max_bytes": 100}, SarifImportError, "more than the 100-byte bound"),
    (lambda ws: {"run_index": 3}, SarifImportError, "run index 3 is out of range"),
])
def test_a_refused_import_writes_nothing(workspace, change, error, message):
    arguments = {"sarif_path": FIXTURES / "codeql.sarif", "pack": workspace["pack"], "snapshot_id": "snap-a",
                 "tree_hash": workspace["tree_hash"], "system_id": "codeql-fixture",
                 "output": workspace["out"] / "bundle", "clock": CLOCK}
    arguments.update(change(workspace))
    with pytest.raises(error, match=message):
        import_sarif(arguments.pop("sarif_path"), **arguments)
    assert not arguments["output"].exists()
    assert not workspace["out"].exists()


def test_an_existing_or_symlinked_output_is_refused_and_left_alone(workspace, monkeypatch):
    workspace["out"].mkdir()
    existing = workspace["out"] / "bundle"
    existing.mkdir()
    with pytest.raises(SarifImportError, match="already exists; an import writes a new bundle directory"):
        imported(workspace)
    assert list(existing.iterdir()) == []
    link = workspace["out"] / "link"
    link.symlink_to(workspace["tmp"] / "elsewhere")
    with pytest.raises(SarifImportError, match="refusing to write through the symbolic link"):
        imported(workspace, name="link")
    # The same link named through the home directory is the same link.
    monkeypatch.setenv("HOME", str(workspace["out"]))
    with pytest.raises(SarifImportError, match="refusing to write through the symbolic link ~/link"):
        import_sarif(FIXTURES / "codeql.sarif", pack=workspace["pack"], snapshot_id="snap-a",
                     tree_hash=workspace["tree_hash"], system_id="codeql-fixture", output=Path("~/link"), clock=CLOCK)
    assert not (workspace["tmp"] / "elsewhere").exists()


def test_a_write_that_fails_part_way_removes_what_the_import_created(workspace, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(review, "write_evaluator_records", refuse)
    with pytest.raises(OSError, match="No space left on device"):
        imported(workspace)
    assert not (workspace["out"] / "bundle").exists()


# --- the command line ------------------------------------------------------------------------


def cli(capsys, *argv) -> tuple[int, str, str]:
    code = main([str(arg) for arg in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def import_argv(workspace: dict, log: Path = FIXTURES / "codeql.sarif", name: str = "bundle") -> list:
    """``import sarif`` arguments for *log* against the workspace pack, which is written to a file once."""
    pack = workspace["tmp"] / "pack.json"
    if not pack.exists():
        cases.save_pack(pack, workspace["pack"])
    return ["import", "sarif", log, "--pack", pack, "--snapshot-id", "snap-a", "--tree-hash", workspace["tree_hash"],
            "--system-id", "codeql-fixture", "--output", workspace["out"] / name]


def test_import_sarif_writes_the_bundle_the_library_writes_and_says_what_it_made_of_the_log(workspace, capsys):
    code, out, err = cli(capsys, *import_argv(workspace), "--source-dir", workspace["source"])
    assert (code, err) == (0, "")
    bundle = workspace["out"] / "bundle"
    assert bundle_files(bundle) == BUNDLE_FILES
    result = load_document(bundle / "result.json", "scan-result")
    assert out.splitlines() == [
        f"Imported run 0 of 1 from {FIXTURES / 'codeql.sarif'} as {result['run_id']}: status=success claims=3 "
        "excluded=0 losses=0 evidence_losses=0",
        "Bundle review: 1 flagged, 0 decided in the normalization file; bundles_resolved=false",
        "Execution evidence: reported_success, as the log reports it; not verified",
        "Locations checked against an exported tree: yes",
        "Review state: draft; every decision stays unresolved until a person records one",
        f"Bundle: {bundle}"]
    # The command adds nothing of its own: every document but the timestamped review record is
    # byte-for-byte what the library writes for the same arguments.
    library = import_sarif(FIXTURES / "codeql.sarif", pack=cases.load_pack(workspace["tmp"] / "pack.json"),
                           snapshot_id="snap-a", tree_hash=workspace["tree_hash"], system_id="codeql-fixture",
                           output=workspace["out"] / "library", source_dir=workspace["source"], clock=CLOCK)
    for name in ("result.json", "import.json", "raw/codeql.sarif", "evaluator/plan.json", "evaluator/decisions.json",
                 "evaluation.json"):
        assert (bundle / name).read_bytes() == (library.bundle / name).read_bytes(), name
    assert review.review_status(bundle) == "draft"


def test_import_sarif_help_names_every_option(capsys):
    with pytest.raises(SystemExit) as stopped:
        main(["import", "sarif", "--help"])
    assert stopped.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    for option in ("SARIF_FILE", "--pack", "--snapshot-id", "--tree-hash", "--system-id", "--output", "--run-index",
                   "--run-id", "--system-config", "--source-dir", "--uri-base NAME=URI", "--source-root-uri",
                   "--normalization", "--include-suppressed", "--max-bytes", "default 67108864"):
        assert option in text, option
    assert "Nothing the log names is fetched or opened" in text


def two_runs() -> dict:
    return {"version": "2.1.0", "runs": [minimal_log()["runs"][0], fixture("codeql.sarif")["runs"][0]]}


REFUSED_LOGS = [
    ("missing", None, [], "could not open the SARIF file"),
    ("a directory", "directory", [], "is not a regular file, so it is not read"),
    ("above the bound", encoded(minimal_log()), ["--max-bytes", "64"], "more than the 64-byte bound; raise --max-bytes"),
    ("not UTF-8", b"\xff\xfe{}", [], "is not UTF-8 text"),
    ("not JSON", b'{"version": "2.1.0", "runs": [', [], "is not valid JSON"),
    ("a repeated key", b'{"version": "2.1.0", "runs": [], "runs": []}', [], "repeats the object key 'runs'"),
    ("NaN", b'{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "properties": {"n": NaN}}]}', [],
     "non-finite JSON number NaN"),
    ("Infinity", b'{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "properties": {"n": Infinity}}]}',
     [], "non-finite JSON number Infinity"),
    ("too deep", b'{"a":' * 200000 + b"1" + b"}" * 200000, [], "nests deeper than the JSON parser's recursion limit"),
    ("SARIF 2.0.0", encoded({**minimal_log(), "version": "2.0.0"}), [], "declares version '2.0.0'"),
    ("runs null", encoded({"version": "2.1.0", "runs": None}), [], "runs is null"),
    ("runs empty", encoded({"version": "2.1.0", "runs": []}), [], "runs is empty"),
    ("two runs, no index", encoded(two_runs()), [], "holds 2 runs; name the one to import with --run-index"),
    ("index out of range", encoded(two_runs()), ["--run-index", "2"], "run index 2 is out of range"),
    ("a negative index", encoded(two_runs()), ["--run-index", "-1"], "run index -1 is out of range"),
    ("external property files", encoded({**minimal_log(), "runs": [
        {**minimal_log()["runs"][0], "externalPropertyFileReferences": {"results": [{"location": {"uri": "r.json"}}]}}]}),
     [], "runs[0] carries externalPropertyFileReferences"),
]


@pytest.mark.parametrize("data,extra,message", [case[1:] for case in REFUSED_LOGS],
                         ids=[case[0] for case in REFUSED_LOGS])
def test_import_sarif_refuses_a_log_it_cannot_trust_whole_with_exit_2_and_writes_nothing(
        workspace, capsys, data, extra, message):
    log = workspace["tmp"] / "scan.sarif"
    if data == "directory":
        log.mkdir()
    elif data is not None:
        log.write_bytes(data)
    code, out, err = cli(capsys, *import_argv(workspace, log), *extra)
    assert (code, out) == (2, "")
    assert err.startswith("scaneval: ") and message in err
    assert not workspace["out"].exists()


@pytest.mark.parametrize("extra,message", [
    (["--uri-base", "APPROOT"], "--uri-base 'APPROOT' must be NAME=URI"),
    (["--uri-base", "=app/"], "--uri-base '=app/' must be NAME=URI"),
    (["--uri-base", "A=app/", "--uri-base", "A=src/"], "--uri-base names 'A' twice"),
    (["--uri-base", "A=../app/"], "'..' segment"),
    (["--uri-base", "A=file:///build/checkout/app/"], "no --source-root-uri says which directory is the scanned tree"),
    (["--source-root-uri", "https://example.invalid/checkout/"], "is not an absolute file URI"),
    (["--run-id", " "], "a run id, when given, must not be blank"),
    (["--max-bytes", "0"], "the size bound must be a positive number of bytes"),
    (["--source-dir", "/nonexistent-scaneval-export/source"], "is not a directory"),
])
def test_import_sarif_refuses_option_values_it_cannot_use(workspace, capsys, extra, message):
    code, out, err = cli(capsys, *import_argv(workspace), *extra)
    assert (code, out) == (2, "") and message in err
    assert not workspace["out"].exists()


def test_import_sarif_reads_the_operator_files_strictly_and_records_the_configuration_by_digest(workspace, capsys):
    config = workspace["tmp"] / "system.json"
    config.write_bytes(b'{"queries": "security-extended", "queries": "default"}')
    code, _, err = cli(capsys, *import_argv(workspace), "--system-config", config)
    assert code == 2 and f"the --system-config file {config} repeats the object key 'queries'" in err
    normalization_file = workspace["tmp"] / "normalization.json"
    normalization_file.write_text("[]", encoding="utf-8")
    code, _, err = cli(capsys, *import_argv(workspace), "--normalization", normalization_file)
    assert code == 2 and f"the --normalization file {normalization_file} is not a JSON object" in err
    assert not workspace["out"].exists()

    config.write_text('{"queries": "security-extended", "threads": 4}', encoding="utf-8")
    code, _, _ = cli(capsys, *import_argv(workspace), "--system-config", config)
    record = load_document(workspace["out"] / "bundle" / "import.json", "import-record")
    assert code == 0 and record["system"] == {
        "system_id": "codeql-fixture", "config_sha256": canonical_sha256({"queries": "security-extended", "threads": 4})}


def test_import_sarif_refuses_a_bundle_inside_a_trial_directory(workspace, capsys):
    trial = workspace["tmp"] / "trial"
    (trial / "source").mkdir(parents=True)
    (trial / "provenance.json").write_text("{}", encoding="utf-8")
    argv = import_argv(workspace)
    argv[argv.index("--output") + 1] = trial / "bundle"
    code, _, err = cli(capsys, *argv)
    assert code == 2 and "refusing to write" in err and "inside the trial directory" in err
    assert not (trial / "bundle").exists()


def test_import_sarif_exits_1_for_a_log_that_holds_no_usable_scan_and_still_writes_its_bundle(workspace, capsys):
    log = fixture("codeql.sarif")
    log["runs"][0]["results"] = None
    code, out, err = cli(capsys, *import_argv(workspace, write_log(workspace, log)))
    assert code == 1 and "status=error claims=0" in out
    assert "scaneval: status error (results_absent): run.results is null or absent" in err
    assert err.splitlines()[-1] == "scaneval: the imported log holds no usable scan"
    result = load_document(workspace["out"] / "bundle" / "result.json", "scan-result")
    assert (result["status"], result["claims"], result["bundles_resolved"]) == ("error", [], False)

    # A partial scan still carries claims, so it is reported and exits 0, as it does for run.
    log = fixture("codeql.sarif")
    del log["runs"][0]["invocations"]
    code, out, err = cli(capsys, *import_argv(workspace, write_log(workspace, log, "partial.sarif"), "partial"))
    assert code == 0 and "status=partial claims=3" in out
    assert "scaneval: status partial (execution_unreported)" in err and "no usable scan" not in err


def test_import_sarif_imports_the_named_run_of_a_multi_run_log(workspace, capsys):
    log = write_log(workspace, two_runs(), "two-runs.sarif")
    code, out, _ = cli(capsys, *import_argv(workspace, log), "--run-index", "1")
    assert code == 0 and out.startswith(f"Imported run 1 of 2 from {log} as import-")
    bundle = workspace["out"] / "bundle"
    result = load_document(bundle / "result.json", "scan-result")
    record = load_document(bundle / "import.json", "import-record")
    assert [claim["claim_id"] for claim in result["claims"]] == ["r1-0", "r1-1", "r1-2"]
    assert result["run_id"].endswith("-r1") and record["sarif"] == {"version": "2.1.0", "run_index": 1, "run_count": 2}
    assert record["options"]["run_index"] == 1 and "raw/two-runs.sarif" in bundle_files(bundle)


# --- the workflow after an import: review, score, replay, and what it never touches ----------


def refuse_network(monkeypatch) -> list:
    """Make every way this process could open a connection raise, and return the attempts made."""
    attempts: list = []

    def refused(*args, **kwargs):
        attempts.append(args)
        raise OSError("network access attempted during an offline import")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, refused)
    return attempts


def test_a_saved_log_is_imported_reviewed_scored_and_replayed_fully_offline(workspace, capsys, monkeypatch):
    attempts = refuse_network(monkeypatch)
    bundle = workspace["out"] / "bundle"
    decided = workspace["tmp"] / "normalization.json"
    decided.write_text(canonical_json(normalization(codeql_digest(), atomic())) + "\n", encoding="utf-8")
    code, out, err = cli(capsys, *import_argv(workspace), "--source-dir", workspace["source"],
                         "--normalization", decided)
    assert (code, err) == (0, "") and "1 flagged, 1 decided in the normalization file; bundles_resolved=true" in out

    # Replaying the bundle as imported reproduces the evaluation the import wrote, byte for byte.
    code, _, err = cli(capsys, "replay", bundle, "--output", workspace["tmp"] / "replay-draft.json")
    assert code == 0 and "review state draft" in err
    assert (workspace["tmp"] / "replay-draft.json").read_bytes() == (bundle / "evaluation.json").read_bytes()

    # A reviewer edits the machine draft by hand: the one routed candidate is accepted.
    path = bundle / "evaluator" / "decisions.json"
    decisions = json.loads(path.read_text(encoding="utf-8"))
    assert [(match["claim_id"], match["target_id"], match["decision"]) for match in decisions["claim_matches"]] == [
        ("r0-0", "T-case-a", "unresolved")]
    decisions["claim_matches"][0].update(decision="accepted", reason="the claim names the query this target is about")
    path.write_text(canonical_json(decisions) + "\n", encoding="utf-8")
    code, out, _ = cli(capsys, "review", "record", bundle, "--note", "accepted the SQL injection claim")
    assert code == 0 and "Review record state: draft (0 recorded reviews)" in out
    code, out, _ = cli(capsys, "review", "approve", bundle, "--reviewer", FICTIONAL_REVIEWER,
                       "--note", "read the claim, its flow, and the target")
    assert code == 0 and "Review record state: human_approved (1 recorded reviews)" in out
    code, out, _ = cli(capsys, "review", "status", bundle)
    assert (code, out.strip()) == (0, "human_approved")

    scored = workspace["tmp"] / "scored.json"
    code, _, _ = cli(capsys, "score", "--plan", bundle / "evaluator" / "plan.json", "--result", bundle / "result.json",
                     "--decisions", path, "--output", scored)
    evaluation = json.loads(scored.read_text(encoding="utf-8"))
    assert code == 0 and evaluation["decisions_sha256"] == canonical_sha256(decisions)
    metrics = evaluation["metrics"]
    assert (metrics["targets_detected"], metrics["known_target_recall"], metrics["pending_matching_count"]) == (1, 1.0, 0)
    # Unranked output has no native review order, so no budget recall is read off it.
    assert set(metrics["recall_at_budget"].values()) == {None} and metrics["claim_records"] == 3
    assert metrics["usage"] == {"wall_seconds": None}

    # The replay of the reviewed bundle is the score of the reviewed documents, byte for byte.
    replayed = workspace["tmp"] / "replayed.json"
    code, _, err = cli(capsys, "replay", bundle, "--output", replayed)
    assert (code, err) == (0, "") and replayed.read_bytes() == scored.read_bytes()
    code, _, err = cli(capsys, "report", bundle, "--output", workspace["tmp"] / "report.html")
    assert (code, err) == (0, "")
    assert attempts == []


def test_a_quiet_control_on_an_import_without_invocations_earns_no_quiet_credit(tmp_path):
    source = tmp_path / "export" / "source"
    tree_hash = write_tree(source)
    pack = make_pack(source, tree_hash, control=True)

    def quiet(name: str, log: dict) -> tuple[dict, dict]:
        """Import *log*, record the control as quiet the way a reviewer would, and score it."""
        path = tmp_path / f"{name}.sarif"
        path.write_bytes(encoded(log))
        outcome = import_sarif(path, pack=pack, snapshot_id="snap-a", tree_hash=tree_hash, system_id="semgrep-fixture",
                               output=tmp_path / name, clock=CLOCK)
        decisions = deepcopy(outcome.decisions)
        assert [(item["control_id"], item["decision"]) for item in decisions["control_assessments"]] == [
            ("C-case-a-safe", "unresolved")]
        decisions["control_assessments"][0].update(decision="quiet", reason="no claim names the file helper")
        return outcome.result, scoring.score(outcome.plan, outcome.result, decisions)

    silent = minimal_log(results=[])
    del silent["runs"][0]["invocations"]
    result, evaluation = quiet("no-invocations", silent)
    # Nothing was lost and nothing was flagged, so the bundles are resolved; the missing account
    # of execution alone keeps the silence from counting.
    assert (result["status"], result["error"]["code"], result["bundles_resolved"], result["claims"]) == (
        "partial", "execution_unreported", True, [])
    safe = evaluation["metrics"]["controls"]["capability_safe"]
    assert (safe["assigned"], safe["completed"], safe["resolved"], safe["assessable_mass"]) == (1, 0, 0, 0.0)
    assert safe["resolved_false_alarm_rate"] is None
    assert "Incomplete or failed execution cannot establish a successful negative control." in evaluation["warnings"]

    # The same silence from a run the log reports as finished is a quiet control.
    result, evaluation = quiet("reported", minimal_log(results=[]))
    safe = evaluation["metrics"]["controls"]["capability_safe"]
    assert result["status"] == "success" and (safe["completed"], safe["resolved"], safe["assessable_mass"]) == (1, 1, 1.0)
    assert safe["resolved_false_alarm_rate"] == 0.0


def test_an_import_opens_nothing_the_log_names_and_reaches_no_network(workspace, monkeypatch):
    source = workspace["source"]
    outside = workspace["tmp"] / "outside.py"
    outside.write_text(numbered(30), encoding="utf-8")
    # A link inside the exported tree that leads out of it. The tree hash leaves links out, so the
    # declared hash still holds.
    os.symlink(outside, source / "app" / "linked.py")
    log = fixture("codeql.sarif")
    log["$schema"] = "https://example.invalid/sarif-schema.json"
    run = log["runs"][0]
    run["tool"]["driver"]["rules"][0]["helpUri"] = "https://example.invalid/help/py-sql-injection"
    run["originalUriBaseIds"] = {"OUTSIDE": {"uri": workspace["tmp"].as_uri() + "/"}}
    run["invocations"][0].update(workingDirectory={"uri": "file:///etc/"}, responseFiles=[{"uri": outside.as_uri()}])
    named = [("../outside.py", "%SRCROOT%"), (outside.as_uri(), None), ("outside.py", "OUTSIDE"),
             ("app/linked.py", "%SRCROOT%"), ("/etc/passwd", None), ("file:///etc/passwd", None),
             ("https://example.invalid/app/web.py", None)]
    run["results"] += [result_at(uri, base=base) for uri, base in named]
    path = write_log(workspace, log, "hostile.sarif")

    attempts = refuse_network(monkeypatch)
    touched: list[str] = []
    real = {"os.open": os.open, "io.open": io.open, "os.scandir": os.scandir, "os.stat": os.stat, "os.lstat": os.lstat}

    def recording(name: str):
        def call(target=".", *args, **kwargs):
            if not isinstance(target, int):
                touched.append((name, os.path.abspath(os.fspath(target))))
            return real[name](target, *args, **kwargs)
        return call

    for module, attribute, name in ((os, "open", "os.open"), (io, "open", "io.open"), (builtins, "open", "io.open"),
                                    (os, "scandir", "os.scandir"), (os, "stat", "os.stat"), (os, "lstat", "os.lstat")):
        monkeypatch.setattr(module, attribute, recording(name))
    outcome = imported(workspace, path, source_dir=source, source_root_uri=source.as_uri() + "/")
    during = list(touched)
    monkeypatch.undo()

    assert [claim["claim_id"] for claim in outcome.result["claims"]] == ["r0-0", "r0-1", "r0-2"]
    reasons = [loss["reason"] for loss in outcome.record["losses"]]
    assert [loss["pointer"] for loss in outcome.record["losses"]] == [f"/runs/0/results/{n}" for n in range(3, 10)]
    for reason, expected in zip(reasons, (
            "'..' segment", "lies outside the declared source root", "lies outside the declared source root",
            "maps to 'app/linked.py', which is not a regular file in the exported tree",
            "is an absolute path, not a path relative to a base", "lies outside the declared source root",
            "uses the https scheme")):
        assert expected in reason, (expected, reason)
    assert attempts == []
    # Nothing named by the log was opened, listed, or even looked up: not the file outside the
    # tree (directly, through the link, or through a base), not a host path, not a URL.
    for _, target in during:
        assert target != str(outside) and not target.startswith(("/etc", "/opt")), target
    # Every file read or directory listed is the log, the exported tree, the new bundle, or the
    # package's own schemas and mappings.
    allowed = (str(source), str(outcome.bundle), str(Path(cases.__file__).parent), sys.prefix, sys.base_prefix)
    for name, target in during:
        if name in ("os.open", "io.open", "os.scandir"):
            assert target == str(path) or target.startswith(allowed), (name, target)
    assert ("os.open", str(path)) in during


# --- one Semgrep finding, through the live adapter's JSON path and through a SARIF import -----


# The fields scoring reads a claim's exact-duplicate identity from, less native_rule_id, whose
# spelling is the one thing the two producers are expected to disagree on.
CANONICAL_FIELDS = ("allegation", "kind", "primary_location", "related_locations", "evidence_text")


def reviewed_score(plan: dict, pack: dict, result: dict) -> dict:
    """Score *result* under the decisions a reviewer records the same way for either producer:
    the routed claim accepted for the case's target, and every control assessed quiet."""
    decisions = review.draft_decisions(plan, result, pack)
    (match,) = decisions["claim_matches"]
    match.update(decision="accepted", reason="the claim names the shell call this target is about")
    for assessment in decisions["control_assessments"]:
        assessment.update(decision="quiet", reason="no claim names the file helper")
    return scoring.score(plan, result, decisions)


def comparable(evaluation: dict) -> dict:
    """What a score says about the scan, without the run's identity or its measured usage."""
    metrics = {key: value for key, value in evaluation["metrics"].items() if key != "usage"}
    return {"metrics": metrics, **{key: evaluation[key] for key in ("scope", "status", "targets", "warnings")}}


def adapter_result(payload: bytes, claims: list, tree_hash: str) -> dict:
    """The scan result execution frames around the Semgrep adapter's claims after a clean run."""
    return validate_document("scan-result", {
        "schema_version": "2.0", "run_id": "semgrep-live", "system_id": "semgrep-fixture", "input_hash": tree_hash,
        "status": "success", "ranking": "unranked", "claims": claims, "bundles_resolved": True,
        "usage": {"wall_seconds": 1.5, "cost_usd": 0.0},
        "raw_artifacts": [{"id": "semgrep-json", "path": "raw/semgrep.json",
                           "sha256": "sha256:" + hashlib.sha256(payload).hexdigest()}]})


def test_one_semgrep_finding_scores_alike_through_the_adapter_json_path_and_a_sarif_import(tmp_path):
    source = tmp_path / "export" / "source"
    tree_hash = write_tree(source)
    pack = make_pack(source, tree_hash, control=True, target=("src/app.py", 5), kind="command_injection")
    plan, _ = cases.build_plan(pack, "snap-a", tree_hash)

    # The live adapter's path: Semgrep JSON through import_semgrep_results, with the ruleset
    # checkout root the adapter passes, which it strips from every check_id.
    payload = (FIXTURES / "semgrep-shell.json").read_bytes()
    live = import_semgrep_results(json.loads(payload), ruleset_roots=("build/rules",))
    assert live.lost == 0
    (live_claim,) = live.claims
    # The same finding in the SARIF Semgrep writes, imported offline: result 0 of the fixture.
    log = fixture("semgrep.sarif")
    log["runs"][0]["results"] = log["runs"][0]["results"][:1]
    outcome = import_sarif(write_log({"tmp": tmp_path}, log, "semgrep-shell.sarif"), pack=pack, snapshot_id="snap-a",
                           tree_hash=tree_hash, system_id="semgrep-fixture", output=tmp_path / "bundle",
                           source_dir=source, clock=CLOCK)
    (sarif_claim,) = outcome.result["claims"]
    assert (outcome.result["status"], outcome.result["bundles_resolved"]) == ("success", True)

    # The canonical allegation is the same claim from either producer.
    assert {key: sarif_claim.get(key) for key in CANONICAL_FIELDS + ("native_cwe",)} == {
        key: live_claim.get(key) for key in CANONICAL_FIELDS + ("native_cwe",)} == {
        "allegation": "subprocess call with shell=True", "kind": "command_injection",
        "primary_location": {"path": "src/app.py", "start_line": 5, "end_line": 5}, "related_locations": None,
        "evidence_text": None, "native_cwe": ["CWE-78"]}
    # The rule id is spelled differently. Semgrep writes the rule file's directory, dotted, into
    # the id in both formats; the adapter strips the ruleset checkout it pinned, and an import
    # has no checkout to strip, so it keeps the id as the log wrote it. Severity is each format's
    # own word for the same thing and is not part of a claim's identity.
    assert (live_claim["native_rule_id"], sarif_claim["native_rule_id"]) == (
        "python.probe.subprocess-shell", "build.rules.python.probe.subprocess-shell")
    assert (live_claim["native_severity"], sarif_claim["native_severity"]) == ("WARNING", "warning")
    # So the exact-duplicate identities differ by that spelling alone: with the id spelled alike,
    # or with no checkout root for the adapter to strip, they are one identity.
    assert scoring.claim_fingerprint(live_claim) != scoring.claim_fingerprint(sarif_claim)
    assert scoring.claim_fingerprint({**sarif_claim, "native_rule_id": live_claim["native_rule_id"]}) == \
        scoring.claim_fingerprint(live_claim)
    (verbatim,) = import_semgrep_results(json.loads(payload)).claims
    assert scoring.claim_fingerprint(verbatim) == scoring.claim_fingerprint(sarif_claim)

    # Under the same decisions, the two score alike, down to the controls and the warnings.
    live_score = reviewed_score(plan, pack, adapter_result(payload, live.claims, tree_hash))
    sarif_score = reviewed_score(plan, pack, outcome.result)
    assert comparable(live_score) == comparable(sarif_score)
    assert live_score["metrics"]["targets_detected"] == 1
    assert live_score["metrics"]["controls"]["capability_safe"]["resolved"] == 1
    # Usage is where they differ: a live run measures its wall time; a log reports none.
    assert (live_score["metrics"]["usage"]["wall_seconds"], sarif_score["metrics"]["usage"]) == (
        1.5, {"wall_seconds": None})


semgrep_required = pytest.mark.skipif(
    not (Path(sys.executable).with_name("semgrep").exists() or shutil.which("semgrep")),
    reason="semgrep binary not installed")

SHELL_RULE_YAML = """rules:
  - id: probe.subprocess-shell
    languages: [python]
    severity: WARNING
    message: subprocess call with shell=True
    metadata:
      cwe:
        - "CWE-78: OS Command Injection"
    patterns:
      - pattern: subprocess.$F(..., shell=True, ...)
"""
SHELL_SOURCE = "import subprocess\n\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"


@semgrep_required
def test_real_semgrep_json_and_sarif_from_one_scan_score_one_finding_alike(tmp_path):
    sibling = Path(sys.executable).with_name("semgrep")
    binary = str(sibling) if sibling.exists() else shutil.which("semgrep")
    rules = tmp_path / "rules"
    (rules / "python").mkdir(parents=True)
    (rules / "python" / "shell.yaml").write_text(SHELL_RULE_YAML, encoding="utf-8")
    source = tmp_path / "export" / "source"
    tree_hash = write_tree(source, {"README.md": "fixture\n", "src/app.py": SHELL_SOURCE})
    pack = make_pack(source, tree_hash, target=("src/app.py", 5), kind="command_injection")
    plan, _ = cases.build_plan(pack, "snap-a", tree_hash)
    # One scan writes both formats. HOME and the temporary and cache directories are redirected
    # into this test's own directory, and metrics and the version check are off.
    home = tmp_path / "home"
    (home / "tmp").mkdir(parents=True)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "TMPDIR": str(home / "tmp"),
           "XDG_CONFIG_HOME": str(home / ".config"), "XDG_CACHE_HOME": str(home / ".cache"), "LANG": "C.UTF-8"}
    completed = subprocess.run(
        [binary, "scan", "--metrics=off", "--disable-version-check", "--quiet", f"--config={rules / 'python'}",
         f"--json-output={tmp_path / 'semgrep.json'}", f"--sarif-output={tmp_path / 'semgrep.sarif'}", "."],
        cwd=source, env=env, capture_output=True, text=True, timeout=300)
    assert completed.returncode == 0, completed.stderr[-2000:]

    payload = (tmp_path / "semgrep.json").read_bytes()
    live = import_semgrep_results(json.loads(payload), ruleset_roots=(str(rules),))
    (live_claim,) = live.claims
    # --source-dir re-hashes the tree, so this also shows the scan left the exported tree as it was.
    outcome = import_sarif(tmp_path / "semgrep.sarif", pack=pack, snapshot_id="snap-a", tree_hash=tree_hash,
                           system_id="semgrep-fixture", output=tmp_path / "bundle", source_dir=source, clock=CLOCK)
    (sarif_claim,) = outcome.result["claims"]
    assert (outcome.result["status"], outcome.record["execution"]["evidence"]) == ("success", "reported_success")
    assert outcome.record["tool"]["name"] == "Semgrep OSS"
    assert outcome.record["claims"][0]["fingerprints"] == {"matchBasedId/v1": None}

    assert {key: sarif_claim.get(key) for key in CANONICAL_FIELDS + ("native_cwe",)} == {
        key: live_claim.get(key) for key in CANONICAL_FIELDS + ("native_cwe",)}
    assert sarif_claim["primary_location"] == {"path": "src/app.py", "start_line": 5, "end_line": 5}
    # Real Semgrep spells the rule with this test's own directory, dotted, in both formats.
    check_id = json.loads(payload)["results"][0]["check_id"]
    assert sarif_claim["native_rule_id"] == check_id
    assert live_claim["native_rule_id"] == "python.probe.subprocess-shell"
    assert check_id.endswith(".rules.python.probe.subprocess-shell")
    assert scoring.claim_fingerprint({**sarif_claim, "native_rule_id": live_claim["native_rule_id"]}) == \
        scoring.claim_fingerprint(live_claim)
    assert comparable(reviewed_score(plan, pack, adapter_result(payload, live.claims, tree_hash))) == \
        comparable(reviewed_score(plan, pack, outcome.result))
