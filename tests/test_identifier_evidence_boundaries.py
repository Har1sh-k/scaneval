"""Native evidence and configuration names must consume their entire supplied value."""

import json

import pytest

from scaneval.adapters import runsortie as rs
from scaneval.adapters import runsortie_evidence as evidence
from scaneval.adapters.base import AdapterError
from scaneval.collectors import claude_code
from scaneval.isolation import IsolationError
from scaneval.isolation.oci import OciBackend
from scaneval.sarif import SarifImportError, import_sarif


HEAD = "a" * 40


def _json(value):
    return json.dumps(value).encode()


@pytest.mark.parametrize("field", ["repositoryHead", "productHead", "evidenceHead", "checkpoint",
                                  "attemptedHead", "baselineCheckpoint"])
def test_native_target_state_rejects_a_line_break_after_a_commit(field):
    record = {"target": "scaneval", "outcome": "failed",
              "lastAttemptAt": "2026-11-03T00:00:00.000Z"}
    if field in {"attemptedHead", "baselineCheckpoint"}:
        record["baseline"] = {"version": 1, "status": "pending",
                              "attemptedHead" if field == "attemptedHead" else "checkpoint": HEAD}
        owner = record["baseline"]
        key = "attemptedHead" if field == "attemptedHead" else "checkpoint"
    else:
        owner, key = record, field
        owner[key] = HEAD

    def read():
        return evidence.read_target_state(_json({"version": 1, "targets": {"scaneval": record}}), "scaneval")

    assert read().state == "valid"
    owner[key] += "\n"
    assert read().state == "invalid"


def test_a_newline_commit_cannot_bind_a_checkpoint_or_classify_unchanged_history():
    assert evidence.read_checkpoint(_json({"lastBatchHead": HEAD}), HEAD).state == "bound"
    malformed = HEAD + "\n"
    assert evidence.read_checkpoint(_json({"lastBatchHead": malformed}), malformed).state == "invalid"
    assert evidence.classify_commit(evaluated=malformed, head=malformed, parents=(), changed=(),
                                    worktree_matches=True).state == "invalid"


def test_baseline_acceptance_rejects_a_line_break_after_its_recovery_plan_hash():
    recovery = {"status": "complete", "planHash": "c" * 64, "reasons": [],
                "hypotheses": {"planned": 1, "scheduled": 1, "succeeded": 1, "failed": 0,
                               "exhausted": 0, "stillUnevaluated": 0},
                "workItems": {"scheduled": 1, "succeeded": 1, "retryable": 0, "exhausted": 0,
                              "terminal": 0, "capacityExhausted": False},
                "limits": {"maxWorkItems": 1, "maxAttemptsPerItem": 1}}
    record = {"policyVersion": 1, "status": "accepted", "checkpointEligible": True,
              "reasons": [], "sourceHead": HEAD, "recovery": recovery}
    assert evidence.read_acceptance(_json(record), HEAD).state == "accepted"
    recovery["planHash"] += "\n"
    assert evidence.read_acceptance(_json(record), HEAD).state == "invalid"


@pytest.mark.parametrize("field", ["engine_model", "primary", "challenger"])
def test_runsortie_rejects_a_line_break_in_each_model_route(tmp_path, field):
    config = {"root": str(tmp_path), "expected_commit": rs.SUPPORTED_RUNSORTIE_COMMIT,
              "expected_version": rs.SUPPORTED_RUNSORTIE_VERSION,
              "expected_dist_tree_sha256": "sha256:" + "b" * 64,
              "engine_model": "pi:provider/engine", "primary": {"agent": "codex", "model": "primary"},
              "challenger": {"agent": "codex", "model": "challenger"},
              "credential_env": {"engine": "OPENAI_API_KEY"}}
    assert rs.read_settings(config).engine_model == config["engine_model"]
    if field == "engine_model":
        config[field] += "\n"
    else:
        config[field]["model"] += "\n"
    with pytest.raises(AdapterError, match=field):
        rs.read_settings(config)


def test_digest_pinned_image_is_rejected_before_engine_access_when_it_has_a_newline():
    # No engine is attached: malformed identity must be refused before any Docker command.
    backend = object.__new__(OciBackend)
    with pytest.raises(IsolationError, match="not pinned by digest"):
        backend._image_identity("scanner@sha256:" + "a" * 64 + "\n", "scanner image")


def test_newline_state_directory_is_refused_before_creating_it(tmp_path, monkeypatch):
    (tmp_path / "source").mkdir()
    (tmp_path / "raw").mkdir()
    backend = object.__new__(OciBackend)
    backend._state_dirs = ("scanner-state\n",)
    monkeypatch.setattr(backend, "_workspace", lambda: tmp_path)
    with pytest.raises(IsolationError, match="not one directory name"):
        backend._plan_mounts()
    assert not (tmp_path / "source" / "scanner-state\n").exists()


def test_sarif_import_refuses_a_newline_tree_digest_before_reading_or_writing(tmp_path):
    output = tmp_path / "bundle"
    with pytest.raises(SarifImportError, match="tree hash must be"):
        import_sarif(tmp_path / "absent.sarif", pack={}, snapshot_id="source",
                     tree_hash="sha256:" + "a" * 64 + "\n", system_id="scanner", output=output)
    assert not output.exists()


def test_collector_does_not_preserve_a_timestamp_with_a_trailing_line_break():
    timestamp = "2026-11-03T00:00:00.000Z"
    assert claude_code._origin({"timestamp": timestamp}, 1).timestamp == timestamp
    assert claude_code._origin({"timestamp": timestamp + "\n"}, 1).timestamp is None
