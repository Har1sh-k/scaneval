"""Selected quota identity and bucket visibility, using only fabricated readings."""
import importlib.util
import json
from pathlib import Path
import sys
import time

import pytest


TOOL = Path(__file__).resolve().parents[1] / "tools/codex_quota_guard.py"
spec = importlib.util.spec_from_file_location("codex_quota_buckets_guard", TOOL)
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)


def bucket(limit_id="codex", used=62):
    return {"limitId": limit_id, "primary": {"usedPercent": used,
        "resetsAt": int(time.time()) + 3600, "windowDurationMins": 10080}, "secondary": None}


def multiple():
    return {"rateLimits": bucket(), "rateLimitsByLimitId": {
        "codex": bucket(), "model-specific": bucket("model-specific", 100)}}


def test_other_live_quota_cannot_be_silently_ignored():
    with pytest.raises(guard.Stop, match="other_limit_windows_present"):
        guard.parse_windows(multiple())
    assert guard.parse_windows(multiple(), allow_other_limit_windows=True)[0].remaining_percent == 38


def test_selecting_other_quota_does_not_relax_its_threshold():
    windows = guard.parse_windows(multiple(), limit_id="model-specific", allow_other_limit_windows=True)
    assert windows[0].remaining_percent == 0
    with pytest.raises(guard.Stop, match="remaining_at_or_below_1"):
        guard.Policy(45).accept(windows, now=time.monotonic(), wall=time.time())


@pytest.mark.parametrize("actual", [None, "", "other"])
@pytest.mark.parametrize("mapped", [False, True])
def test_selected_bucket_requires_exact_limit_id_even_legacy(actual, mapped):
    selected = bucket()
    selected["limitId"] = actual
    result = {"rateLimits": selected}
    if mapped:
        result["rateLimitsByLimitId"] = {"codex": selected}
    with pytest.raises(guard.Stop):
        guard.parse_windows(result)


def test_explicit_custom_bucket_can_use_identified_legacy_response():
    result = {"rateLimits": bucket("model-specific", 50)}
    assert guard.parse_windows(result, limit_id="model-specific")[0].remaining_percent == 50
    assert guard.visible_bucket_keys(result) == ("model-specific",)
    with pytest.raises(guard.Stop):
        guard.parse_windows(result)


def test_missing_selected_bucket_cannot_fall_back_to_legacy_or_another_bucket():
    result = {"rateLimits": bucket(), "rateLimitsByLimitId": {"model-specific": bucket("model-specific")}}
    with pytest.raises(guard.Stop, match="missing_codex_bucket"):
        guard.parse_windows(result, allow_other_limit_windows=True)


def test_other_buckets_without_windows_are_visible_and_allowed():
    result = {"rateLimitsByLimitId": {"z-metadata": {}, "codex": bucket(),
              "a-metadata": {"limitId": "a-metadata", "primary": None, "secondary": None}}}
    assert guard.parse_windows(result)[0].remaining_percent == 38
    assert guard.visible_bucket_keys(result) == ("a-metadata", "codex", "z-metadata")


@pytest.mark.parametrize("bad", [None, [], 1, {"limitId": "wrong", "primary": bucket()["primary"]},
    {"limitId": "model-specific", "primary": False, "secondary": None},
    {"limitId": "model-specific", "primary": {"usedPercent": True, "resetsAt": 1,
                                               "windowDurationMins": 1}, "secondary": None}])
def test_opt_in_does_not_excuse_malformed_other_bucket(bad):
    result = multiple()
    result["rateLimitsByLimitId"]["model-specific"] = bad
    with pytest.raises(guard.Stop):
        guard.parse_windows(result, allow_other_limit_windows=True)


@pytest.mark.parametrize("limit_id", ["", "unsafe\nkey", "x" * 129, "../codex", 12, None])
def test_bad_limit_identifiers_refuse_without_echoing_values(limit_id):
    with pytest.raises(guard.Stop, match="^invalid_limit_selection$"):
        guard.parse_windows({"rateLimits": bucket()}, limit_id=limit_id)


@pytest.mark.parametrize("keys", [{12: {}}, {"bad\nkey": {}}, {"x" * 129: {}}])
def test_malformed_visible_bucket_identifiers_are_not_logged(keys):
    with pytest.raises(guard.Stop, match="invalid_bucket_map"):
        guard.visible_bucket_keys({"rateLimitsByLimitId": keys})


class Source:
    def __init__(self, result):
        self.result = result

    def start(self, timeout, check):
        check()

    def read(self, timeout, check):
        check()
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def close(self):
        return True


def controller(tmp_path, result, **selection):
    return guard.Controller(guard.Options(grace=.1), Source(result),
        guard.Receipts(tmp_path / "receipts.jsonl"), guard.Containers([], [], "unused", .1), **selection)


def receipt_events(tmp_path):
    return [json.loads(line) for line in (tmp_path / "receipts.jsonl").read_text().splitlines()]


def test_default_refusal_before_launch_records_selected_and_visible_buckets(tmp_path):
    subject = controller(tmp_path, multiple())
    marker = tmp_path / "must-not-launch"
    try:
        assert subject.run([sys.executable, "-c", f"open({str(marker)!r}, 'w').close() "]) == 125
    finally:
        subject.receipts.close()
    assert not marker.exists()
    events = receipt_events(tmp_path)
    for event in events:
        if event["event"] in ("guard_started", "usage_rejected"):
            assert event["selected_limit_id"] == "codex"
            assert event["visible_bucket_keys"] == ["codex", "model-specific"]
    assert any(event["event"] == "guard_started" for event in events)
    assert events[-1]["reason"] == "other_limit_windows_present"


def test_allowed_other_windows_and_selected_custom_bucket_are_audited(tmp_path):
    result = multiple()
    result["rateLimitsByLimitId"]["model-specific"] = bucket("model-specific", 50)
    subject = controller(tmp_path, result, limit_id="model-specific", allow_other_limit_windows=True)
    try:
        assert subject.run([sys.executable, "-c", "pass"]) == 0
    finally:
        subject.receipts.close()
    accepted = [event for event in receipt_events(tmp_path) if event["event"] == "usage_accepted"]
    assert accepted and accepted[0]["selected_limit_id"] == "model-specific"
    assert accepted[0]["visible_bucket_keys"] == ["codex", "model-specific"]
    assert accepted[0]["windows"][0]["remaining_percent"] == 50
    started = next(event for event in receipt_events(tmp_path) if event["event"] == "guard_started")
    assert started["allow_other_limit_windows"] is True


def test_unavailable_read_reports_unknown_visibility_without_stale_keys(tmp_path):
    subject = controller(tmp_path, guard.Stop("usage_unavailable"))
    try:
        assert subject.run(["never-launch"]) == 125
    finally:
        subject.receipts.close()
    rejected = next(event for event in receipt_events(tmp_path) if event["event"] == "usage_rejected")
    assert rejected["selected_limit_id"] == "codex"
    assert rejected["visible_bucket_keys"] == []
    assert rejected["bucket_visibility_available"] is False


def test_cli_wires_explicit_quota_selection(tmp_path, monkeypatch):
    captured = []

    def run(self, command):
        captured.append((self.limit_id, self.allow_other_limit_windows, command))
        return 0

    monkeypatch.setattr(guard.Controller, "run", run)
    assert guard.main(["--receipts", str(tmp_path / "receipts.jsonl"), "--limit-id", "model-specific",
                       "--allow-other-limit-windows", "--", "never-launch"]) == 0
    assert captured == [("model-specific", True, ["never-launch"])]


def test_local_freshness_starts_when_usage_request_starts(tmp_path, monkeypatch):
    subject = controller(tmp_path, {"rateLimits": bucket()})
    tick = [100.0]
    monkeypatch.setattr(guard.time, "monotonic", lambda: tick[0])
    original = subject.source.read

    def delayed_read(timeout, check):
        result = original(timeout, check)
        tick[0] = 105.0
        return result

    subject.source.read = delayed_read
    try:
        subject.observe()
        assert subject.policy.observed_at == 100.0
    finally:
        subject.receipts.close()
