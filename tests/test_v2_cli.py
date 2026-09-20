from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastbench import __version__
from sastbench.cli import main
from sastbench.contracts import canonical_json, canonical_sha256


def run_demo(tmp_path: Path) -> Path:
    bundle = tmp_path / "demo"
    assert main(["demo", str(bundle)]) == 0
    return bundle


def write_json(path: Path, value: dict) -> None:
    path.write_text(canonical_json(value) + "\n", encoding="utf-8")


def score_args(bundle: Path, output: Path) -> list[str]:
    return [
        "score",
        "--plan",
        str(bundle / "evaluator" / "plan.json"),
        "--result",
        str(bundle / "result.json"),
        "--decisions",
        str(bundle / "evaluator" / "decisions.json"),
        "--output",
        str(output),
    ]


def test_demo_creates_complete_separated_diagnostic_bundle(tmp_path):
    bundle = run_demo(tmp_path)

    expected = {
        "scan-input/app.py",
        "request.json",
        "result.json",
        "evaluator/plan.json",
        "evaluator/decisions.json",
        "evaluation.json",
        "report.html",
        "README.txt",
    }
    assert expected == {
        str(path.relative_to(bundle)) for path in bundle.rglob("*") if path.is_file()
    }
    assert json.loads((bundle / "evaluator" / "plan.json").read_text())["scope"] == "diagnostic"
    readme = (bundle / "README.txt").read_text(encoding="utf-8")
    assert "No scanner was run" in readme
    assert "not a sandbox" in readme


def test_score_and_replay_are_byte_identical(tmp_path):
    bundle = run_demo(tmp_path)
    scored = tmp_path / "scored.json"
    replayed = tmp_path / "replayed.json"

    assert main(score_args(bundle, scored)) == 0
    assert main(["replay", str(bundle), "--output", str(replayed)]) == 0

    assert scored.read_bytes() == replayed.read_bytes()
    assert scored.read_bytes() == (bundle / "evaluation.json").read_bytes()


def test_version_and_validate_commands(tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == __version__

    bundle = run_demo(tmp_path)
    capsys.readouterr()
    assert main(["validate", "scan-request", str(bundle / "request.json")]) == 0
    assert "Valid scan-request" in capsys.readouterr().out


def test_cli_refuses_to_overwrite_output_file_or_demo_directory(tmp_path, capsys):
    bundle = run_demo(tmp_path)
    capsys.readouterr()
    existing = tmp_path / "existing.json"
    existing.write_text("keep me", encoding="utf-8")

    assert main(score_args(bundle, existing)) == 2
    assert existing.read_text(encoding="utf-8") == "keep me"
    assert "File exists" in capsys.readouterr().err

    marker = bundle / "marker.txt"
    marker.write_text("keep me too", encoding="utf-8")
    assert main(["demo", str(bundle)]) == 2
    assert marker.read_text(encoding="utf-8") == "keep me too"
    assert "File exists" in capsys.readouterr().err


def test_replay_rejects_result_changed_after_decisions_were_frozen(tmp_path, capsys):
    bundle = run_demo(tmp_path)
    capsys.readouterr()
    result_path = bundle / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["claims"][0]["allegation"] = "altered after review"
    write_json(result_path, result)

    assert main(["replay", str(bundle)]) == 2
    error = capsys.readouterr().err.lower()
    assert "result_sha256" in error and "does not match" in error


@pytest.mark.parametrize("payload", ["{", '{"schema_version": NaN}'])
def test_validate_malformed_input_returns_nonzero(tmp_path, capsys, payload):
    path = tmp_path / "malformed.json"
    path.write_text(payload, encoding="utf-8")

    assert main(["validate", "scan-request", str(path)]) != 0
    assert "sastbench:" in capsys.readouterr().err


def test_report_escapes_untrusted_claim_and_target_text(tmp_path):
    bundle = run_demo(tmp_path)
    result_path = bundle / "result.json"
    plan_path = bundle / "evaluator" / "plan.json"
    decisions_path = bundle / "evaluator" / "decisions.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    decisions = json.loads(decisions_path.read_text(encoding="utf-8"))
    malicious_claim = '<script>alert("claim")</script>'
    malicious_target = '<img src=x onerror="alert(\'target\')">'
    result["claims"][0]["allegation"] = malicious_claim
    plan["targets"][0]["description"] = malicious_target
    decisions["result_sha256"] = canonical_sha256(result)
    write_json(result_path, result)
    write_json(plan_path, plan)
    write_json(decisions_path, decisions)
    report = tmp_path / "report.html"

    assert main(["report", str(bundle), "--output", str(report)]) == 0
    html = report.read_text(encoding="utf-8")
    assert malicious_claim not in html
    assert malicious_target not in html
    assert '&lt;script&gt;alert(&quot;' in html
    assert '&lt;img src=x onerror=' in html


def test_diagnostic_report_has_prominent_fixture_banner(tmp_path):
    bundle = run_demo(tmp_path)
    report = (bundle / "report.html").read_text(encoding="utf-8")

    assert '<p class="notice">Diagnostic fixture only.' in report
    assert "No scanner or model was run." in report
    assert "not real-world performance results" in report
