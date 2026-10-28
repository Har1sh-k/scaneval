"""Offline projection fixtures exercise declarations, never fetched source code."""
import copy
import hashlib
import json
from pathlib import Path

import pytest

from scaneval.cli import main
from scaneval.model_cutoff_projection import prepare_chronology
from scaneval.model_cutoffs import CutoffError, assess_candidates, load_registry


AUTHORITY = "CNA-primary base severity"
DOSSIER_SCHEMA = "scaneval.research-candidate-dossier.v1"
POLICY_VERSION = "scaneval.dossier-chronology.v1"


@pytest.fixture
def dossier():
    return {
        "schema_version": DOSSIER_SCHEMA,
        "candidates": [{
            "cve_id": "CVE-2026-10000",
            "proposed_stratum": "MEDIUM",
            "severity": {"selected": {
                "authority": "Example CNA",
                "source": "https://example.com/cna/10000",
                "version": "3.1", "score": 6.1, "severity": "MEDIUM",
            }},
            "dates": {
                "earliest_observed_public_evidence_at": "2026-08-27T11:41:22Z",
                "earliest_observed_public_evidence_url": "https://example.com/advisory/10000",
                "evidence_kind": "maintainer_advisory_publication",
                "note": "Only an observation; earlier public history remains unresolved.",
                "earliest_observed_public_evidence_scope": "Exact-bypass advisory only.",
            },
        }],
    }


def canonical_sha256(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def set_path(document, path, value):
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def add_related_predecessor(dossier, published_at="2026-07-01T09:31:11Z", updated="2026-07-07"):
    dossier["candidates"][0]["dates"]["related_predecessor"] = {
        "published_at": published_at,
        "url": "https://example.com/advisory/predecessor",
        "current_body_updated_at_day": updated,
        "publication_time_wording_established": False,
    }


def test_committed_dossier_cli_round_trip_is_pending_bound_and_read_only(tmp_path, capsys):
    source = Path(__file__).resolve().parents[1] / "docs/research/recent-cve-candidates.json"
    original = source.read_bytes()
    research = json.loads(original)
    args = ["model-cutoffs", "prepare-chronology", str(source), "--severity-authority", AUTHORITY]
    assert main(args) == 0
    first = capsys.readouterr()
    assert first.err == ""
    assert main(args) == 0
    assert capsys.readouterr().out == first.out
    assert source.read_bytes() == original
    assert list(tmp_path.iterdir()) == []

    projected = json.loads(first.out)
    assert projected["severity_authority"] == AUTHORITY
    assert len(projected["candidates"]) == 10
    assert {c["cve_id"] for c in projected["candidates"]} == {c["cve_id"] for c in research["candidates"]}
    assert all(c["chronology"]["status"] == "pending" for c in projected["candidates"])
    assert projected["projection_provenance"] == {
        "policy_version": POLICY_VERSION,
        "dossier_schema_version": DOSSIER_SCHEMA,
        "dossier_sha256": canonical_sha256(research),
    }

    composer = next(c for c in projected["candidates"] if c["cve_id"] == "CVE-2026-59944")
    predecessor = next(a for a in composer["chronology"]["public_artifacts"]
                       if a["relationship"] == "related_predecessor")
    assert predecessor["date"] == "2026-07-01"
    assert predecessor["original_timestamp"] == "2026-07-01T09:31:11Z"
    assert predecessor["kind"] == "advisory"
    assert predecessor["native_evidence_kind"] == "related_predecessor_advisory_publication"
    assert predecessor["source_url"].endswith("GHSA-gjfg-22fp-rrxx")
    assert predecessor["current_body_updated_at_day"] == "2026-07-07"
    assert predecessor["publication_time_wording_established"] is False
    assert "wording" in predecessor["scope_note"].lower()
    assert "distinct" in predecessor["scope_note"].lower()
    research_composer = next(c for c in research["candidates"] if c["cve_id"] == composer["cve_id"])
    candidate_artifact = next(a for a in composer["chronology"]["public_artifacts"]
                              if a["relationship"] == "candidate")
    shared_note = research_composer["dates"]["note"]
    candidate_scope = research_composer["dates"]["earliest_observed_public_evidence_scope"]
    assert shared_note in candidate_artifact["scope_note"]
    assert candidate_scope in candidate_artifact["scope_note"]
    assert shared_note in predecessor["scope_note"]
    assert candidate_scope not in predecessor["scope_note"]

    path = tmp_path / "chronology.json"
    path.write_text(first.out)
    assert main(["model-cutoffs", "check", str(path), "--model", "claude-opus-5-5"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["projection_provenance"] == projected["projection_provenance"]
    assert report["candidate_document_sha256"] == canonical_sha256(projected)
    assert report["eligible_total"] == 0
    assert report["pack_target_met"] is False
    assert all(c["status"] == "unresolved" and c["chronology_status"] == "pending"
               and c["earliest_public_evidence_lower_bound"] is None
               and c["earliest_observed_artifact_date_lower_bound"] is not None
               for c in report["candidates"])
    reported_composer = next(c for c in report["candidates"] if c["cve_id"] == composer["cve_id"])
    assert reported_composer["earliest_observed_artifact_date_lower_bound"] == "2026-07-01"
    assert path.read_text() == first.out
    assert list(tmp_path.iterdir()) == [path]


def test_projection_preserves_selected_rating_and_scope_without_mutating_input(dossier):
    before = copy.deepcopy(dossier)
    candidate = prepare_chronology(dossier, AUTHORITY)["candidates"][0]
    selected = dossier["candidates"][0]["severity"]["selected"]
    assert candidate["selected_rating"] == selected
    assert candidate["severity"] == "Medium"
    assert candidate["severity_source_url"] == selected["source"]
    observation = candidate["chronology"]["public_artifacts"][0]
    assert observation["relationship"] == "candidate"
    assert observation["precision"] == "day"
    assert observation["date_basis"] == "public_availability"
    assert "Exact-bypass advisory only." in observation["scope_note"]
    assert dossier == before


def test_related_predecessor_scope_keeps_shared_note_separate_from_candidate_scope(dossier):
    add_related_predecessor(dossier)
    dates = dossier["candidates"][0]["dates"]
    artifacts = prepare_chronology(dossier, AUTHORITY)["candidates"][0]["chronology"]["public_artifacts"]
    candidate = next(a for a in artifacts if a["relationship"] == "candidate")
    predecessor = next(a for a in artifacts if a["relationship"] == "related_predecessor")
    assert dates["note"] in candidate["scope_note"]
    assert dates["earliest_observed_public_evidence_scope"] in candidate["scope_note"]
    assert dates["note"] in predecessor["scope_note"]
    assert dates["earliest_observed_public_evidence_scope"] not in predecessor["scope_note"]
    assert "wording" in predecessor["scope_note"].lower()
    assert "distinctness" in predecessor["scope_note"].lower()


def test_later_predecessor_advisory_publication_is_allowed_for_an_older_weakness(dossier):
    add_related_predecessor(dossier, published_at="2026-09-01T09:31:11Z", updated="2026-09-02")
    artifacts = prepare_chronology(dossier, AUTHORITY)["candidates"][0]["chronology"]["public_artifacts"]
    candidate = next(a for a in artifacts if a["relationship"] == "candidate")
    predecessor = next(a for a in artifacts if a["relationship"] == "related_predecessor")
    assert predecessor["date"] > candidate["date"]


def test_predecessor_update_day_uses_publication_timestamp_utc_day(dossier):
    add_related_predecessor(dossier, published_at="2026-09-01T00:30:00+02:00", updated="2026-08-31")
    predecessor = prepare_chronology(dossier, AUTHORITY)["candidates"][0]["chronology"]["public_artifacts"][1]
    assert predecessor["date"] == "2026-08-31"
    dossier["candidates"][0]["dates"]["related_predecessor"]["current_body_updated_at_day"] = "2026-08-30"
    with pytest.raises(CutoffError, match="update day precedes its publication UTC day"):
        prepare_chronology(dossier, AUTHORITY)


def test_contradictory_predecessor_chronology_is_cli_exit_2(dossier, tmp_path, capsys):
    add_related_predecessor(dossier, published_at="2026-07-02T00:30:00+02:00", updated="2026-06-30")
    path = tmp_path / "dossier.json"
    path.write_text(json.dumps(dossier))
    assert main(["model-cutoffs", "prepare-chronology", str(path),
                 "--severity-authority", AUTHORITY]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "update day precedes its publication UTC day" in captured.err
    assert "Traceback" not in captured.err


def test_whole_dossier_hash_binds_unconsumed_fields_and_is_key_order_independent(dossier):
    first = prepare_chronology(dossier, AUTHORITY)
    reordered = json.loads(json.dumps(dossier, sort_keys=True))
    assert prepare_chronology(reordered, AUTHORITY) == first
    dossier["unconsumed_research_note"] = "Later discovery: \u00e9"
    later = prepare_chronology(dossier, AUTHORITY)
    assert later["candidates"] == first["candidates"]
    assert later["projection_provenance"]["dossier_sha256"] != first["projection_provenance"]["dossier_sha256"]
    assert later["projection_provenance"]["dossier_sha256"] == canonical_sha256(dossier)


@pytest.mark.parametrize("native,kind", [
    ("maintainer_advisory_publication", "advisory"),
    ("public_release_publication", "release"),
    ("public_pull_request_creation", "pull_request"),
])
def test_explicit_native_evidence_kinds(dossier, native, kind):
    dossier["candidates"][0]["dates"]["evidence_kind"] = native
    artifact = prepare_chronology(dossier, AUTHORITY)["candidates"][0]["chronology"]["public_artifacts"][0]
    assert artifact["kind"] == kind
    assert artifact["native_evidence_kind"] == native


@pytest.mark.parametrize("timestamp,utc_date", [
    ("2026-07-02T00:30:00+02:00", "2026-07-01"),
    ("2026-07-01T23:30:00-02:00", "2026-07-02"),
    ("2024-03-01T00:30:00+01:00", "2024-02-29"),
    ("2026-08-27T11:41:22.1Z", "2026-08-27"),
    ("2026-08-27T11:41:22.123456Z", "2026-08-27"),
])
def test_timestamp_precision_is_retained_while_utc_day_is_projected(dossier, timestamp, utc_date):
    dossier["candidates"][0]["dates"]["earliest_observed_public_evidence_at"] = timestamp
    artifact = prepare_chronology(dossier, AUTHORITY)["candidates"][0]["chronology"]["public_artifacts"][0]
    assert artifact["date"] == utc_date
    assert artifact["original_timestamp"] == timestamp
    assert artifact["precision"] == "day"


@pytest.mark.parametrize("timestamp", [
    None, [], {}, True, "2026-07", "2026-07-02", "2026-07-02T00:30:00",
    "2026-07-02T00:30Z", "2026-07-02T00:30:00-00:00",
    "2026-07-02T00:30:00+24:00", "2026-07-02T00:30:00+00:60",
    "2026-02-29T00:30:00Z", "2026-07-02T00:30:60Z",
    "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00",
])
def test_ambiguous_invalid_or_unrepresentable_timestamp_is_input_error(dossier, timestamp):
    dossier["candidates"][0]["dates"]["earliest_observed_public_evidence_at"] = timestamp
    with pytest.raises(CutoffError):
        prepare_chronology(dossier, AUTHORITY)


def test_timestamp_fraction_longer_than_six_digits_is_rejected_without_rounding(dossier):
    dossier["candidates"][0]["dates"]["earliest_observed_public_evidence_at"] = "2026-08-27T23:59:59.9999999Z"
    with pytest.raises(CutoffError, match="at most six digits"):
        prepare_chronology(dossier, AUTHORITY)


@pytest.mark.parametrize("bad", [None, [], True, "dossier", 1])
def test_dossier_must_be_an_object(bad):
    with pytest.raises(CutoffError):
        prepare_chronology(bad, AUTHORITY)


@pytest.mark.parametrize("authority", [None, [], {}, True, "", " \n"])
def test_severity_authority_is_required(dossier, authority):
    with pytest.raises(CutoffError):
        prepare_chronology(dossier, authority)


@pytest.mark.parametrize("path,value", [
    (("schema_version",), []),
    (("schema_version",), "scaneval.research-candidate-dossier.v2"),
    (("candidates",), {}),
    (("candidates", 0), []),
    (("candidates", 0, "cve_id"), []),
    (("candidates", 0, "cve_id"), "CVE-2026-010000"),
    (("candidates", 0, "cve_id"), "CVE-2026-\uff11\uff10\uff10\uff10\uff10"),
    (("candidates", 0, "severity"), []),
    (("candidates", 0, "severity", "selected"), []),
    (("candidates", 0, "dates"), []),
    (("candidates", 0, "dates", "evidence_kind"), []),
    (("candidates", 0, "dates", "evidence_kind"), "commit_author_date"),
    (("candidates", 0, "dates", "evidence_kind"), "cve_publication"),
    (("candidates", 0, "dates", "evidence_kind"), "advisory"),
    (("candidates", 0, "dates", "note"), []),
    (("candidates", 0, "dates", "earliest_observed_public_evidence_scope"), []),
    (("candidates", 0, "dates", "related_predecessor"), []),
])
def test_consumed_fields_reject_malformed_scalar_and_container_types(dossier, path, value):
    set_path(dossier, path, value)
    with pytest.raises(CutoffError):
        prepare_chronology(dossier, AUTHORITY)


def test_duplicate_cve_ids_fail(dossier):
    dossier["candidates"].append(copy.deepcopy(dossier["candidates"][0]))
    with pytest.raises(CutoffError):
        prepare_chronology(dossier, AUTHORITY)


@pytest.mark.parametrize("field", ["earliest_observed_public_evidence_at", "earliest_observed_public_evidence_url", "evidence_kind"])
def test_missing_observation_never_falls_back_to_cve_or_commit_date(dossier, field):
    candidate = dossier["candidates"][0]
    candidate["dates"].pop(field)
    candidate["cve_published_at"] = "2026-08-27T11:41:22Z"
    candidate["primary_advisory_published_at"] = "2026-08-27T11:41:22Z"
    candidate["candidate_fix"] = {"author_date": "2026-08-27T11:41:22Z"}
    with pytest.raises(CutoffError):
        prepare_chronology(dossier, AUTHORITY)


@pytest.mark.parametrize("path", [
    ("candidates", 0, "severity", "selected", "source"),
    ("candidates", 0, "dates", "earliest_observed_public_evidence_url"),
])
@pytest.mark.parametrize("source", [None, [], "file:///tmp/advisory", "https://", "https://user:password@example.com/advisory"])
def test_selected_and_observed_sources_must_be_structural_http_urls(dossier, path, source):
    set_path(dossier, path, source)
    with pytest.raises(CutoffError):
        prepare_chronology(dossier, AUTHORITY)


def test_source_url_validation_does_not_imply_reachability_or_reject_private_hosts(dossier):
    candidate = dossier["candidates"][0]
    candidate["severity"]["selected"]["source"] = "http://127.0.0.1/severity"
    candidate["dates"]["earliest_observed_public_evidence_url"] = "https://localhost/advisory"
    add_related_predecessor(dossier)
    candidate["dates"]["related_predecessor"]["url"] = "http://[::1]/predecessor"
    projected = prepare_chronology(dossier, AUTHORITY)["candidates"][0]
    assert projected["severity_source_url"] == "http://127.0.0.1/severity"
    assert [artifact["source_url"] for artifact in projected["chronology"]["public_artifacts"]] == [
        "https://localhost/advisory", "http://[::1]/predecessor",
    ]


@pytest.mark.parametrize("field,value", [
    ("score", True), ("score", []), ("score", "6.1"), ("score", float("nan")),
    ("score", float("inf")), ("score", -1), ("score", 0), ("score", 10.1),
    ("score", 6.11), ("score", 9.8), ("severity", []), ("severity", "HIGH"),
    ("severity", "MEDIUM-ish"), ("version", []), ("version", 3.1),
    ("version", "2.0"), ("version", "4.1"), ("authority", []), ("authority", ""),
])
def test_selected_rating_rejects_malformed_or_contradictory_values(dossier, field, value):
    dossier["candidates"][0]["severity"]["selected"][field] = value
    with pytest.raises(CutoffError):
        prepare_chronology(dossier, AUTHORITY)


@pytest.mark.parametrize("score,band", [(0.1, "LOW"), (3.9, "LOW"), (4.0, "MEDIUM"),
                                        (6.9, "MEDIUM"), (7.0, "HIGH"), (8.9, "HIGH"),
                                        (9.0, "CRITICAL"), (10, "CRITICAL")])
@pytest.mark.parametrize("version", ["3.0", "3.1", "4.0"])
def test_supported_cvss_versions_and_band_boundaries(dossier, score, band, version):
    candidate = dossier["candidates"][0]
    candidate["proposed_stratum"] = band
    candidate["severity"]["selected"].update(score=score, severity=band, version=version)
    assert prepare_chronology(dossier, AUTHORITY)["candidates"][0]["severity"] == band.title()


@pytest.mark.parametrize("stratum", [None, [], "HIGH", "Medium-ish"])
def test_proposed_stratum_must_agree_with_selected_band(dossier, stratum):
    dossier["candidates"][0]["proposed_stratum"] = stratum
    with pytest.raises(CutoffError):
        prepare_chronology(dossier, AUTHORITY)


def test_claimed_review_or_admission_never_promotes_projected_chronology(dossier):
    dossier["status"] = "accepted"
    candidate = dossier["candidates"][0]
    candidate.update(status="accepted", machine_reviewed=True, human_approved=True,
                     temporally_eligible=True, chronology={"status": "reviewed"})
    candidate["dates"].update(exhaustive_prior_public_history_checked=True,
                              earliest_public_evidence_lower_bound="2026-08-27")
    projected = prepare_chronology(dossier, AUTHORITY)
    assert projected["candidates"][0]["chronology"]["status"] == "pending"
    result = assess_candidates(load_registry(), projected, ["claude-opus-5-5"])["candidates"][0]
    assert result["status"] == "unresolved"
    assert result["earliest_public_evidence_lower_bound"] is None


@pytest.mark.parametrize("provenance", [
    None, [], "claimed", {},
    {"policy_version": [], "dossier_schema_version": DOSSIER_SCHEMA, "dossier_sha256": "a" * 64},
    {"policy_version": "future-policy", "dossier_schema_version": DOSSIER_SCHEMA, "dossier_sha256": "a" * 64},
    {"policy_version": POLICY_VERSION, "dossier_schema_version": [], "dossier_sha256": "a" * 64},
    {"policy_version": POLICY_VERSION, "dossier_schema_version": "future-schema", "dossier_sha256": "a" * 64},
    {"policy_version": POLICY_VERSION, "dossier_schema_version": DOSSIER_SCHEMA, "dossier_sha256": []},
    {"policy_version": POLICY_VERSION, "dossier_schema_version": DOSSIER_SCHEMA, "dossier_sha256": "A" * 64},
    {"policy_version": POLICY_VERSION, "dossier_schema_version": DOSSIER_SCHEMA, "dossier_sha256": "a" * 63},
    {"policy_version": POLICY_VERSION, "dossier_schema_version": DOSSIER_SCHEMA, "dossier_sha256": "a" * 64, "verified": True},
])
def test_check_rejects_malformed_projection_provenance_as_exit_2(dossier, provenance, tmp_path, capsys):
    projected = prepare_chronology(dossier, AUTHORITY)
    projected["projection_provenance"] = provenance
    path = tmp_path / "chronology.json"
    path.write_text(json.dumps(projected))
    assert main(["model-cutoffs", "check", str(path), "--model", "claude-opus-5-5"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "scaneval:" in captured.err
    assert "Traceback" not in captured.err


def test_projection_marker_cannot_be_retained_after_manual_review_promotion(dossier):
    projected = prepare_chronology(dossier, AUTHORITY)
    projected["candidates"][0]["chronology"]["status"] = "reviewed"
    with pytest.raises(CutoffError):
        assess_candidates(load_registry(), projected, ["claude-opus-5-5"])
    projected.pop("projection_provenance")
    report = assess_candidates(load_registry(), projected, ["claude-opus-5-5"])
    assert "projection_provenance" not in report
    assert report["candidates"][0]["status"] == "eligible"


def test_prepare_cli_returns_input_error_without_output_on_invalid_dossier(dossier, tmp_path, capsys):
    dossier["candidates"][0]["severity"]["selected"]["version"] = []
    path = tmp_path / "dossier.json"
    path.write_text(json.dumps(dossier))
    original = path.read_bytes()
    assert main(["model-cutoffs", "prepare-chronology", str(path), "--severity-authority", AUTHORITY]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "scaneval:" in captured.err
    assert "Traceback" not in captured.err
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]
