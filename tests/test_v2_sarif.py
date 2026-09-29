"""SARIF 2.1.0 import (profile sarif-import-1): the import record, the importer, and its CLI.

Every log here is a fabricated fixture under ``tests/fixtures/sarif`` or a document built in the
test; no test fetches anything, calls a model, or reads a file a log names. The one test that
runs the real Semgrep binary is skipped when it is not installed, and it runs with HOME redirected
into the test's own directory. Reviewers named here are fictional.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from scaneval.contracts import CONTRACT_KINDS, ContractError, SCHEMA_VERSIONS, schema_file, validate_document


HASH = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
FICTIONAL_REVIEWER = "Fixture Reviewer (fictional)"


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
