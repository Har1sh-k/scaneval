"""SARIF 2.1.0 import (profile sarif-import-1): the import record, the importer, and its CLI.

Every log here is a fabricated fixture under ``tests/fixtures/sarif`` or a document built in the
test; no test fetches anything, calls a model, or reads a file a log names. The one test that
runs the real Semgrep binary is skipped when it is not installed, and it runs with HOME redirected
into the test's own directory. Reviewers named here are fictional.
"""

from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from scaneval.contracts import CONTRACT_KINDS, ContractError, SCHEMA_VERSIONS, schema_file, validate_document
from scaneval.sarif import SarifImportError, parse_log, read_artifact, select_run


HASH = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
FICTIONAL_REVIEWER = "Fixture Reviewer (fictional)"


def minimal_log(**run_changes) -> dict:
    """One Semgrep-shaped run with one finding, the smallest log every import path accepts."""
    run = {
        "tool": {"driver": {"name": "Semgrep OSS", "semanticVersion": "1.177.0", "rules": [{
            "id": "rules.python.probe.subprocess-shell", "name": "rules.python.probe.subprocess-shell",
            "defaultConfiguration": {"level": "warning"},
            "properties": {"precision": "very-high", "tags": ["CWE-78: OS Command Injection", "security"]}}]}},
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": []}],
        "results": [{
            "ruleId": "rules.python.probe.subprocess-shell",
            "message": {"text": "subprocess call with shell=True"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/app.py", "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 5, "startColumn": 12, "endLine": 5, "endColumn": 43}}}],
            "fingerprints": {"matchBasedId/v1": "requires login"}, "properties": {}}],
    }
    run.update(run_changes)
    return {"version": "2.1.0", "runs": [run]}


def encoded(document: dict) -> bytes:
    return json.dumps(document).encode("utf-8")


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
            normalization={"sha256": HASH, "decisions": [{**decision, "reviewer": "​"}]}))
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
    (b'["2.1.0"]', "not a SARIF log object"),
    (b'{"a":' * 200000 + b"1" + b"}" * 200000, "recursion limit"),
])
def test_bytes_that_are_not_a_strict_json_object_are_refused_whole(data, message):
    with pytest.raises(SarifImportError, match=message):
        parse_log(data)


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


def test_external_property_files_anywhere_in_the_log_refuse_it_whole():
    log = minimal_log()
    external = {"results": [{"location": {"uri": "results.sarif-external-properties"}}]}
    log["runs"].append({**deepcopy(log["runs"][0]), "externalPropertyFileReferences": external})
    # The run that points outside the log is not the one selected, and the log is still refused.
    with pytest.raises(SarifImportError, match=r"runs\[1\] declares externalPropertyFileReferences"):
        select_run(log, 0)
