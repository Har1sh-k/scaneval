"""Chronology assertions use fabricated CVEs; no source or scanner execution."""
import copy
import json
from pathlib import Path

import pytest

from scaneval.cli import main
from scaneval import model_cutoffs
from scaneval.model_cutoffs import CutoffError, assess_candidates, date_bounds, load_registry


@pytest.fixture
def registry():
    return load_registry()


def candidate(number=10000, severity="Low", when="2026-07-01", precision="day", status="reviewed"):
    return {"cve_id": f"CVE-2026-{number}", "severity": severity,
            "severity_source_url": "https://example.com/advisory",
            "chronology": {"status": status,
                           "review_note": "Fabricated fixture: advisory, issue, PR, release, commit publication and PoC chronology checked.",
                           "public_artifacts": [{"date": when, "precision": precision,
                                                 "date_basis": "public_availability", "kind": "advisory",
                                                 "source_url": "https://example.com/advisory"}]}}


def document(*candidates):
    return {"schema_version": 1, "severity_authority": "CNA CVSS v3.1", "candidates": list(candidates)}


def result(registry, c=None, models=None, basis="training"):
    return assess_candidates(registry, document(c or candidate()), models or ["claude-opus-5-5"], basis=basis)


def test_registry_retains_training_knowledge_unknowns_and_source_conflicts(registry):
    by_id = {m["model_id"]: m for m in registry["models"]}
    assert len(by_id) == 42
    assert by_id["claude-opus-4-6"]["reliable_knowledge_cutoff"]["value"] == "2025-05"
    assert by_id["claude-opus-4-6"]["training_data_cutoff"]["value"] == "2025-08"
    assert by_id["claude-sonnet-4-6"]["conflicting_sources"]
    assert by_id["gpt-6.1-terra"]["knowledge_cutoff"]["value"] == "2026-06-01"
    assert by_id["gpt-6.1-terra"]["training_data_cutoff"] is None
    assert by_id["glm-5.2"]["knowledge_cutoff"] is None
    assert by_id["grok-4.6"]["knowledge_cutoff"] is None
    assert by_id["grok-4.6"]["rejected_candidate_cutoff"]["value"] == "2026-02-01"
    assert registry["endpoint_routes"][0]["endpoint"] == "Coding Plan"


@pytest.mark.parametrize("when,precision,expected", [
    ("2026-07-01", "day", "eligible"), ("2026-06-30", "day", "ineligible"),
    ("2026-06-29", "day", "ineligible"), ("2026-07", "month", "eligible"),
    ("2026-06", "month", "ineligible"),
])
def test_conservative_month_boundary_is_strict(registry, when, precision, expected):
    report = result(registry, candidate(when=when, precision=precision))
    assert report["candidates"][0]["status"] == expected
    assert report["models"][0]["cutoff"]["upper_bound"] == "2026-06-30"
    assert report["models"][0]["cutoff"]["upper_bound_is_inference"] is True


def test_leap_month_and_day_cutoff(registry):
    assert tuple(d.isoformat() for d in date_bounds("2024-02", "month")) == ("2024-02-01", "2024-02-29")
    for when, status in [("2026-06-01", "ineligible"), ("2026-06-02", "eligible")]:
        report = result(registry, candidate(when=when), ["gpt-6.1-terra"], "documented")
        assert report["candidates"][0]["status"] == status
        assert report["models"][0]["cutoff_field"] == "knowledge_cutoff"
    assert result(registry, models=["gpt-6.1-terra"])["candidates"][0]["status"] == "unresolved"


def test_documented_basis_prefers_later_training_field(registry):
    report = result(registry, candidate(when="2025-06-01"), ["claude-opus-4-6"], "documented")
    assert report["models"][0]["cutoff_field"] == "training_data_cutoff"
    assert report["candidates"][0]["status"] == "ineligible"


def test_provider_temporal_bound_keeps_unknown_actual_cutoff(registry):
    report = result(registry, candidate(when="2026-03-21"), ["claude-mythos-preview"])
    assert report["candidates"][0]["status"] == "eligible"
    assert report["models"][0]["cutoff"]["value"] is None
    assert report["models"][0]["cutoff"]["status"] == "temporal_bound"


@pytest.mark.parametrize("model,reason", [("glm-5.3", "cutoff_unknown_for_basis"),
                                          ("not-a-model", "unknown_model"),
                                          ("gpt-5.6", "alias_requires_served_model"),
                                          ("gpt-5.6-cyber", "alias_requires_served_model"),
                                          ("openai/gpt-6.1-sol-pro", "alias_requires_served_model")])
def test_unknown_models_and_routes_cannot_certify_universal_eligibility(registry, model, reason):
    report = result(registry, models=["claude-opus-5-5", model], basis="documented")
    assert report["candidates"][0]["status"] == "unresolved"
    assert reason in [reason for decision in report["candidates"][0]["models"] for reason in decision["reasons"]]
    assert report["eligible_total"] == 0


def test_pending_chronology_and_earlier_artifact_prevent_eligibility(registry):
    c = candidate(status="pending")
    pending = result(registry, c)["candidates"][0]
    assert pending["status"] == "unresolved"
    assert pending["earliest_public_evidence_lower_bound"] is None
    assert pending["earliest_observed_artifact_date_lower_bound"] == "2026-07-01"
    c["chronology"]["status"] = "reviewed"
    earlier = copy.deepcopy(c["chronology"]["public_artifacts"][0])
    earlier.update(date="2026-06-01", kind="pull_request")
    c["chronology"]["public_artifacts"].append(earlier)
    report = result(registry, c)
    assert report["candidates"][0]["status"] == "ineligible"
    assert report["candidates"][0]["earliest_public_evidence_lower_bound"] == "2026-06-01"


def complete_pack():
    severities = ["Low"] * 2 + ["Medium"] * 3 + ["High"] * 3 + ["Critical"] * 2
    return document(*(candidate(10000 + i, severity) for i, severity in enumerate(severities)))


def test_complete_target_and_shortage_are_reported_by_unique_cve(registry):
    pack = complete_pack()
    report = assess_candidates(registry, pack, ["claude-opus-5-5"])
    assert report["pack_target_met"] is True
    assert report["eligible_total"] == 10
    pack["candidates"][-1]["chronology"]["status"] = "pending"
    report = assess_candidates(registry, pack, ["claude-opus-5-5"])
    assert report["pack_target_met"] is False
    assert report["shortages"] == {"Low": 0, "Medium": 0, "High": 0, "Critical": 1}
    pack["candidates"].append(copy.deepcopy(pack["candidates"][0]))
    with pytest.raises(CutoffError, match="duplicate CVE"):
        assess_candidates(registry, pack, ["claude-opus-5-5"])


@pytest.mark.parametrize("cve_id", ["CVE-2026-010000", "CVE-2026-00001",
                                    "CVE-２０２６-10000", "CVE-2026-１００００"])
def test_noncanonical_cve_spellings_cannot_count_as_distinct_cases(registry, cve_id):
    pack = complete_pack()
    pack["candidates"][-1]["cve_id"] = cve_id
    with pytest.raises(CutoffError, match="invalid or duplicate CVE"):
        assess_candidates(registry, pack, ["claude-opus-5-5"])


@pytest.mark.parametrize("cve_id", ["CVE-2026-0001", "CVE-2026-9999", "CVE-2026-10000"])
def test_canonical_four_and_longer_digit_cve_ids_are_accepted(registry, cve_id):
    c = candidate()
    c["cve_id"] = cve_id
    assert result(registry, c)["eligible_total"] == 1


@pytest.mark.parametrize("identity_status", ["alias", "documented-alias", "future_status"])
def test_unrecognized_identity_status_cannot_authorize_eligibility(registry, identity_status):
    model = next(m for m in registry["models"] if m["model_id"] == "claude-opus-5-5")
    model["identity_status"] = identity_status
    with pytest.raises(CutoffError, match="unsupported identity_status"):
        result(registry)


@pytest.mark.parametrize("identity_status,expected", [("pinned_snapshot", "eligible"),
                                                      ("documented_api_id", "eligible"),
                                                      ("documented_alias", "unresolved")])
def test_supported_identity_statuses_preserve_alias_uncertainty(registry, identity_status, expected):
    model = next(m for m in registry["models"] if m["model_id"] == "claude-opus-5-5")
    model["identity_status"] = identity_status
    assert result(registry)["candidates"][0]["status"] == expected


@pytest.mark.parametrize("value,precision", [("2026-02-29", "day"), ("2026-13", "month"),
                                             ("20260701", "day"), ("2026", "year"),
                                             ("2026-01", []), (None, "day")])
def test_bad_dates_fail_as_input_errors(value, precision):
    with pytest.raises(CutoffError):
        date_bounds(value, precision)


@pytest.mark.parametrize("mutation", [
    lambda c: c.update(severity=[]),
    lambda c: c["chronology"].update(status=[]),
    lambda c: c["chronology"].update(public_artifacts=[]),
    lambda c: c["chronology"].update(review_note=""),
    lambda c: c["chronology"]["public_artifacts"][0].update(date_basis="commit_author_date"),
    lambda c: c["chronology"]["public_artifacts"][0].update(kind=[]),
])
def test_invalid_review_declarations_do_not_pass(registry, mutation):
    c = candidate()
    mutation(c)
    with pytest.raises(CutoffError):
        result(registry, c)


def test_registry_rejects_invented_bounds_duplicates_and_alias_targets(registry):
    for mutation in (
        lambda r: r["models"][0]["training_data_cutoff"].update(upper_bound="2025-08-01"),
        lambda r: r["models"][0]["training_data_cutoff"].update(upper_bound_is_inference=False),
        lambda r: r["models"].append(copy.deepcopy(r["models"][0])),
        lambda r: r["aliases"][0].update(target_model_id=[]),
    ):
        altered = copy.deepcopy(registry)
        mutation(altered)
        with pytest.raises(CutoffError):
            result(altered)


def test_cli_pack_results_are_deterministic_bound_to_inputs_and_read_only(tmp_path, capsys):
    path = tmp_path / "candidates.json"
    path.write_text(json.dumps(complete_pack()))
    before = path.read_bytes()
    args = ["model-cutoffs", "check", str(path), "--model", "claude-opus-5-5"]
    assert main(args) == 0
    first = capsys.readouterr().out
    assert main(args) == 0
    assert capsys.readouterr().out == first
    assert path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [path]
    report = json.loads(first)
    assert len(report["registry_sha256"]) == len(report["candidate_document_sha256"]) == 64
    assert main(args + ["--model", "glm-5.3"]) == 1
    assert json.loads(capsys.readouterr().out)["eligible_total"] == 0


def test_cli_lists_registry_supports_custom_copy_and_rejects_malformed_inputs(tmp_path, capsys):
    assert main(["model-cutoffs", "list"]) == 0
    registry_text = capsys.readouterr().out
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(registry_text)
    assert main(["model-cutoffs", "list", "--registry", str(registry_path)]) == 0
    assert capsys.readouterr().out == registry_text
    path = tmp_path / "candidates.json"
    for bad in ['{"schema_version":NaN}', '{"schema_version":1,"schema_version":1}', '[]', '{']:
        path.write_text(bad)
        assert main(["model-cutoffs", "check", str(path), "--model", "claude-opus-5-5"]) == 2
        assert "scaneval:" in capsys.readouterr().err


@pytest.mark.parametrize("field", ["duplicate_key", "model_id", "alias_id"])
def test_cli_escapes_untrusted_identifiers_in_errors(registry, tmp_path, capsys, field):
    payload = "untrusted\x1b[31m\x07\u009b\u202e"
    path = tmp_path / "registry.json"
    if field == "duplicate_key":
        key = json.dumps(payload)
        text = "{" + key + ": 1, " + key + ": 2}"
    else:
        if field == "model_id":
            registry["models"][0].update(model_id=payload, provider="")
        else:
            registry["aliases"][0].update(model_id=payload, target_model_id="unknown")
        text = json.dumps(registry)
    path.write_text(text)
    assert main(["model-cutoffs", "list", "--registry", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert repr(payload) in output.err
    assert all(control not in output.err for control in ("\x1b", "\x07", "\u009b", "\u202e"))


@pytest.mark.parametrize("command", ["list", "check"])
def test_cli_json_escapes_controls_without_changing_values(registry, tmp_path, capsys, command):
    payload = "untrusted\x1b[31m\x07\u009b\u202e"
    registry["models"][0]["identity_notes"] = payload
    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps(registry))
    args = ["model-cutoffs", command]
    if command == "check":
        candidate_path = tmp_path / "candidates.json"
        candidate_path.write_text(json.dumps(document(candidate())))
        args.extend([str(candidate_path), "--model", payload])
    args.extend(["--registry", str(registry_path)])
    assert main(args) == (0 if command == "list" else 1)
    output = capsys.readouterr()
    assert output.err == ""
    assert output.out.isascii()
    assert "\x1b" not in output.out and "\x07" not in output.out
    parsed = json.loads(output.out)
    assert parsed["models"][0]["identity_notes" if command == "list" else "model_id"] == payload


@pytest.mark.parametrize("text,error", [('{"schema_version":1,"schema_version":1}', "duplicate JSON key"),
                                        ('{"schema_version":NaN}', "invalid JSON number")])
def test_packaged_registry_uses_strict_json_loader(tmp_path, monkeypatch, text, error):
    data = tmp_path / "data"
    data.mkdir()
    (data / "model-cutoffs.json").write_text(text)
    monkeypatch.setattr(model_cutoffs, "files", lambda package: tmp_path)
    with pytest.raises(CutoffError, match=error):
        load_registry()


def test_committed_research_candidates_remain_pending(registry):
    root = Path(__file__).resolve().parents[1]
    research = json.loads((root / "docs/research/recent-cve-candidates.json").read_text())
    chronology = json.loads((root / "docs/research/recent-cve-chronology.json").read_text())
    assert {c["cve_id"] for c in research["candidates"]} == {c["cve_id"] for c in chronology["candidates"]}
    assert all(c["machine_reviewed"] is False and c["temporally_eligible"] is False for c in research["candidates"])
    report = assess_candidates(registry, chronology, ["claude-opus-5-5"])
    assert report["eligible_total"] == 0
    assert all(c["status"] == "unresolved" and c["earliest_public_evidence_lower_bound"] is None for c in report["candidates"])
