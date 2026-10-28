"""Fabricated quota endpoints and owned local children only; no model calls."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest


TOOL = Path(__file__).resolve().parents[1] / "tools" / "codex_quota_guard.py"
spec = importlib.util.spec_from_file_location("codex_quota_guard", TOOL)
guard = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = guard
spec.loader.exec_module(guard)
TEST_RESET = int(time.time()) + 3600


def usage(used=62, reset=None, secondary=None):
    return {"rateLimits": {"limitId": "codex", "primary": {
        "usedPercent": used, "resetsAt": reset or TEST_RESET,
        "windowDurationMins": 10080}, "secondary": secondary}}


def windows(used=62, reset=5000, secondary=None):
    return guard.parse_windows(usage(used, reset, secondary))


@pytest.mark.parametrize("used,reason", [
    (0, "remaining_at_or_above_90"), (10, "remaining_at_or_above_90"),
    (99, "remaining_at_or_below_1"), (100, "remaining_at_or_below_1"),
])
def test_strict_boundaries(used, reason):
    policy = guard.Policy(45)
    with pytest.raises(guard.Stop, match=f"^{reason}$"):
        policy.accept(windows(used), now=10, wall=1000)
    assert policy.previous is None


def test_equal_then_decreasing_remaining_and_upper_interior_are_allowed():
    policy = guard.Policy(45)
    for index, used in enumerate([11, 11, 62, 98]):
        policy.accept(windows(used), now=10 + index, wall=1000 + index)
    assert policy.previous[0].remaining_percent == 2
    assert policy.reset_deadline == 4010


@pytest.mark.parametrize("new,reason", [
    (windows(61), "remaining_increased"),
    (windows(62, reset=6000), "reset_changed"),
    (windows(62, secondary={"usedPercent": 20, "resetsAt": 4000,
                           "windowDurationMins": 300}), "windows_changed"),
])
def test_reset_or_increase_or_new_window_is_terminal(new, reason):
    policy = guard.Policy(45)
    policy.accept(windows(), now=10, wall=1000)
    with pytest.raises(guard.Stop, match=f"^{reason}$"):
        policy.accept(new, now=11, wall=1001)


def test_secondary_is_checked_even_when_weekly_remaining_declines():
    policy = guard.Policy(45)
    secondary = {"usedPercent": 20, "resetsAt": 4000, "windowDurationMins": 300}
    policy.accept(windows(62, secondary=secondary), now=10, wall=1000)
    with pytest.raises(guard.Stop, match="remaining_increased"):
        policy.accept(windows(63, secondary={**secondary, "usedPercent": 19}), now=11, wall=1001)
    with pytest.raises(guard.Stop, match="reset_changed"):
        policy.accept(windows(63, secondary={**secondary, "resetsAt": 4001}), now=11, wall=1001)


def test_missing_and_changed_duration_windows_refuse():
    policy = guard.Policy(45)
    secondary = {"usedPercent": 20, "resetsAt": 4000, "windowDurationMins": 300}
    policy.accept(windows(62, secondary=secondary), now=10, wall=1000)
    for replacement in (None, {**secondary, "windowDurationMins": 301}):
        with pytest.raises(guard.Stop, match="windows_changed"):
            policy.accept(windows(62, secondary=replacement), now=11, wall=1001)


@pytest.mark.parametrize("now,wall,reason", [
    (55, 1045, "stale_usage"), (4010, 1000, "reset_elapsed"),
    (11, 5000, "reset_elapsed"),
])
def test_freshness_and_reset_deadlines_even_with_clock_changes(now, wall, reason):
    policy = guard.Policy(45)
    policy.accept(windows(), now=10, wall=1000)
    with pytest.raises(guard.Stop, match=f"^{reason}$"):
        policy.accept(windows(), now=now, wall=wall)


def test_clock_rollback_does_not_extend_reset_deadline():
    policy = guard.Policy(45)
    policy.accept(windows(), now=10, wall=1000)
    policy.accept(windows(), now=20, wall=900)
    assert policy.reset_deadline == 4010


@pytest.mark.parametrize("field,value", [
    ("usedPercent", None), ("usedPercent", True), ("usedPercent", 62.0),
    ("usedPercent", -1), ("usedPercent", 101), ("resetsAt", None),
    ("resetsAt", "5000"), ("resetsAt", -1), ("windowDurationMins", None),
    ("windowDurationMins", 300), ("windowDurationMins", 0),
])
def test_malformed_readings_fail_closed(field, value):
    result = usage()
    result["rateLimits"]["primary"][field] = value
    with pytest.raises(guard.Stop):
        guard.parse_windows(result)


@pytest.mark.parametrize("result", [
    None, [], {}, {"rateLimits": {}},
    {"rateLimits": {"primary": None, "secondary": None}},
    {"rateLimits": {"primary": False, "secondary": None}},
    {"rateLimitsByLimitId": {"other": {}}, **usage()},
    {"rateLimitsByLimitId": {}, **usage()},
    {"rateLimitsByLimitId": {"codex": None}, **usage()},
    {"rateLimitsByLimitId": [], **usage()},
])
def test_missing_and_ambiguous_data_cannot_use_legacy_fallback(result):
    with pytest.raises(guard.Stop):
        guard.parse_windows(result)


def test_codex_bucket_has_priority_and_other_metadata_is_ignored():
    result = usage(0)
    result["rateLimitsByLimitId"] = {"codex": usage()["rateLimits"], "other": {}}
    assert guard.parse_windows(result)[0].used_percent == 62
    result["rateLimitsByLimitId"]["codex"]["limitId"] = "other"
    with pytest.raises(guard.Stop, match="invalid_codex_bucket"):
        guard.parse_windows(result)


@pytest.mark.parametrize("field,value", [("spendControlReached", True),
                                          ("rateLimitReachedType", "credits")])
def test_reported_unavailability_fails_closed(field, value):
    result = usage()
    result["rateLimits"][field] = value
    with pytest.raises(guard.Stop, match="quota_unavailable"):
        guard.parse_windows(result)


@pytest.mark.parametrize("options", [
    guard.Options(poll=0), guard.Options(poll=61), guard.Options(poll=float("nan")),
    guard.Options(read_timeout=float("inf")), guard.Options(read_timeout=31),
    guard.Options(stale_after=40), guard.Options(stale_after=121),
    guard.Options(max_runtime=86401), guard.Options(grace=0),
])
def test_invalid_or_unbounded_options_refuse(options):
    with pytest.raises(guard.Stop, match="invalid_options"):
        options.validate()


SERVER = r'''
import json, os, pathlib, sys, time
root = pathlib.Path(sys.argv[1])
steps = json.loads((root/'responses.json').read_text())
index = 0
for line in sys.stdin:
    message = json.loads(line)
    with (root/'requests.jsonl').open('a') as out:
        out.write(json.dumps(message)+'\n')
    if message['method'] == 'initialized':
        continue
    if message['method'] == 'initialize':
        result = {'id': message['id'], 'result': {}}
    else:
        value = steps[min(index, len(steps)-1)]
        index += 1
        if value == 'hang':
            time.sleep(30)
        if value == 'eof':
            sys.exit(0)
        if value == 'noise':
            for _ in range(100):
                print(json.dumps({'method': 'notice', 'params': {'secret': 'SENSITIVE'*4096}}), flush=True)
            continue
        if value == 'malformed':
            print('SENSITIVE not json', flush=True)
            continue
        if value == 'error':
            result = {'id': message['id'], 'error': {'message': 'SENSITIVE token error'}}
        elif value == 'wrong_id':
            result = {'id': message['id']+1, 'result': {}}
        else:
            result = {'id': message['id'], 'result': value}
    print(json.dumps({'method': 'ignored/notice', 'params': {'token': 'SENSITIVE'}}), flush=True)
    print('SENSITIVE stderr', file=sys.stderr, flush=True)
    print(json.dumps(result), flush=True)
'''


def source_fixture(tmp_path, responses):
    (tmp_path / "responses.json").write_text(json.dumps(responses))
    server = tmp_path / "server.py"
    server.write_text(SERVER)
    return guard.AppServer([sys.executable, str(server), str(tmp_path)], .1)


def controller_fixture(tmp_path, responses, **overrides):
    options = guard.Options(poll=.1, read_timeout=.3, stale_after=.6, max_runtime=5, grace=.1)
    options = guard.Options(**{**vars(options), **overrides})
    options.validate()
    source = source_fixture(tmp_path, responses)
    receipts = guard.Receipts(tmp_path / "receipts.jsonl")
    containers = guard.Containers([], [], "not-used", .1)
    return guard.Controller(options, source, receipts, containers)


def events(tmp_path):
    return [json.loads(line) for line in (tmp_path / "receipts.jsonl").read_text().splitlines()]


def run_controller(controller, command):
    try:
        return controller.run(command)
    finally:
        controller.receipts.close()


@pytest.mark.parametrize("first,reason", [
    (usage(99), "remaining_at_or_below_1"), (usage(10), "remaining_at_or_above_90"),
    ("hang", "usage_read_timeout"), ("eof", "usage_unavailable"),
    ("error", "usage_unavailable"), ("malformed", "invalid_usage_protocol"),
    ("wrong_id", "invalid_usage_protocol"), ("noise", "usage_response_too_large"),
])
def test_bad_initial_read_never_launches_and_receipts_are_sanitized(tmp_path, first, reason):
    controller = controller_fixture(tmp_path, [first])
    marker = tmp_path / "launched"
    code = run_controller(controller, [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"])
    assert code == 125
    assert not marker.exists()
    assert events(tmp_path)[-1]["reason"] == reason
    assert events(tmp_path)[-1]["cleanup_okay"] is True
    contents = (tmp_path / "receipts.jsonl").read_text()
    assert "SENSITIVE" not in contents
    assert str(marker) not in contents
    assert (tmp_path / "receipts.jsonl").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("second,reason", [
    (usage(99), "remaining_at_or_below_1"),
    (usage(61), "remaining_increased"),
    (usage(62, int(time.time()) + 7200), "reset_changed"),
    ("hang", "usage_read_timeout"), ("eof", "usage_unavailable"),
])
def test_later_refusal_stops_running_owned_command(tmp_path, second, reason):
    controller = controller_fixture(tmp_path, [usage(), second])
    code = run_controller(controller, [sys.executable, "-c", "import time; time.sleep(30)"])
    assert code == 125
    receipt = events(tmp_path)[-1]
    assert receipt["reason"] == reason
    assert receipt["cleanup_okay"] is True
    pgid = next(event["process_group"] for event in events(tmp_path) if event["event"] == "command_started")
    with pytest.raises(ProcessLookupError):
        os.kill(pgid, 0)


@pytest.mark.parametrize("exit_code", [0, 17])
def test_command_exit_and_protocol_allowlist(tmp_path, exit_code):
    controller = controller_fixture(tmp_path, [usage()])
    code = run_controller(controller, [sys.executable, "-c", f"raise SystemExit({exit_code})", "SENSITIVE"])
    assert code == exit_code
    assert events(tmp_path)[-1]["reason"] == "command_completed"
    assert events(tmp_path)[-1]["command_exit_code"] == exit_code
    requests = [json.loads(line) for line in (tmp_path / "requests.jsonl").read_text().splitlines()]
    assert [message["method"] for message in requests] == ["initialize", "initialized", "account/rateLimits/read"]
    assert requests[-1]["params"] == {"excludeResetCreditDetails": True}
    assert "SENSITIVE" not in (tmp_path / "receipts.jsonl").read_text()


def test_runtime_expires_during_pending_usage_read(tmp_path):
    controller = controller_fixture(tmp_path, [usage(), "hang"], read_timeout=2, stale_after=3, max_runtime=.4)
    start = time.monotonic()
    assert run_controller(controller, [sys.executable, "-c", "import time; time.sleep(30)"]) == 125
    assert time.monotonic() - start < 2
    assert events(tmp_path)[-1]["reason"] == "runtime_elapsed"


def test_stale_observation_expires_during_pending_read(tmp_path):
    controller = controller_fixture(tmp_path, [usage(), "hang"], read_timeout=2, stale_after=3)
    # Simulate a previously accepted observation aging faster than the polling
    # budget (e.g. scheduling/suspend delay) without waiting several seconds.
    original = controller.source.read

    def delayed(timeout, check):
        if controller.policy.previous is not None:
            controller.policy.observed_at -= 2.8
        return original(timeout, check)

    controller.source.read = delayed
    assert run_controller(controller, [sys.executable, "-c", "import time; time.sleep(30)"]) == 125
    assert events(tmp_path)[-1]["reason"] == "stale_usage"


def test_known_reset_expires_during_pending_read(tmp_path):
    controller = controller_fixture(tmp_path, [usage(), "hang"], read_timeout=2, stale_after=3)
    original = controller.source.read

    def reset_soon(timeout, check):
        if controller.policy.previous is not None:
            controller.policy.reset_deadline = time.monotonic() + .1
        return original(timeout, check)

    controller.source.read = reset_soon
    assert run_controller(controller, [sys.executable, "-c", "import time; time.sleep(30)"]) == 125
    assert events(tmp_path)[-1]["reason"] == "reset_elapsed"


def test_receipt_write_failure_stops_owned_command(tmp_path, monkeypatch):
    owned_processes = []
    real_owned = guard.OwnedProcess

    class TrackedOwned(real_owned):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            owned_processes.append(self)

    monkeypatch.setattr(guard, "OwnedProcess", TrackedOwned)
    controller = controller_fixture(tmp_path, [usage()])
    original = controller.receipts.emit

    def fail_after_launch(event, **fields):
        if event == "command_started":
            controller.receipts.file.close()
        original(event, **fields)

    controller.receipts.emit = fail_after_launch
    assert run_controller(controller, [sys.executable, "-c", "import time; time.sleep(30)"]) == 125
    # The receipt sink cannot report the failure, but cleanup still completes.
    assert controller.source.owned.process.returncode is not None
    assert len(owned_processes) == 2
    assert all(owned.process.returncode is not None for owned in owned_processes)


def test_receipt_path_must_be_new_and_not_a_symlink(tmp_path):
    original = tmp_path / "existing"
    original.write_text("keep")
    link = tmp_path / "link"
    link.symlink_to(original)
    for path in (original, link):
        with pytest.raises(OSError):
            guard.Receipts(path)
    assert original.read_text() == "keep"


def wait_file(path, process=None):
    deadline = time.monotonic() + 5
    while not path.exists():
        assert time.monotonic() < deadline
        if process is not None:
            assert process.poll() is None
        time.sleep(.01)


def test_cleanup_kills_stubborn_grandchild_after_leader_exit_and_preserves_unrelated(tmp_path):
    heartbeat = tmp_path / "heartbeat"
    descendant = "import pathlib,signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); p=pathlib.Path(%r); exec('while True:\\n p.write_text(str(time.time()))\\n time.sleep(.01)')" % str(heartbeat)
    parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1]]); time.sleep(.15)"
    unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    owned = guard.OwnedProcess([sys.executable, "-c", parent, descendant])
    try:
        wait_file(heartbeat)
        deadline = time.monotonic() + 5
        while owned.exit_code() is None:
            assert time.monotonic() < deadline
            time.sleep(.01)
        # The leader is still ours and unreaped even though it exited.
        assert owned.process.returncode is None
        assert owned.stop(.1)
        before = heartbeat.read_bytes()
        time.sleep(.1)
        assert heartbeat.read_bytes() == before
        assert unrelated.poll() is None
        with pytest.raises(ProcessLookupError):
            os.kill(owned.pgid, 0)
    finally:
        owned.stop(.1)
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_exact_container_registrations_and_bounded_cleanup(tmp_path):
    docker = tmp_path / "docker"
    log = tmp_path / "docker-args.json"
    docker.write_text(f"#!{sys.executable}\nimport json,pathlib,sys\npathlib.Path({str(log)!r}).write_text(json.dumps(sys.argv[1:]))\n")
    docker.chmod(0o700)
    cidfile = tmp_path / "cid"
    containers = guard.Containers(["b" * 64], [cidfile], str(docker), .1)
    containers.refresh()  # not created yet
    cidfile.write_text("a" * 64 + "\n")
    containers.refresh()
    cidfile.write_text("c" * 64)
    with pytest.raises(guard.Stop, match="invalid_container_registration"):
        containers.refresh()
    count, failures = containers.stop()
    assert (count, failures) == (2, 1)
    assert json.loads(log.read_text()) == ["container", "stop", "--time", "0", "--", "a" * 64, "b" * 64]


def test_cleanup_refreshes_cidfile_written_since_last_poll(tmp_path):
    cidfile = tmp_path / "cid"
    containers = guard.Containers([], [cidfile], "/usr/bin/true", .1)
    cidfile.write_text("a" * 64)
    assert containers.stop() == (1, 0)


def test_docker_cleanup_failure_is_reported(tmp_path):
    containers = guard.Containers(["a" * 64], [], "/usr/bin/false", .1)
    assert containers.stop() == (1, 1)


def test_docker_cleanup_timeout_is_bounded(tmp_path):
    docker = tmp_path / "docker"
    marker = tmp_path / "docker-pid"
    docker.write_text(f"#!{sys.executable}\nimport os,pathlib,time\npathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\ntime.sleep(30)\n")
    docker.chmod(0o700)
    containers = guard.Containers(["a" * 64], [], str(docker), .1)
    start = time.monotonic()
    assert containers.stop() == (1, 1)
    assert time.monotonic() - start < 12
    with pytest.raises(ProcessLookupError):
        os.kill(int(marker.read_text()), 0)


def test_real_permission_failure_cannot_claim_cleanup_success(monkeypatch):
    owned = guard.OwnedProcess([sys.executable, "-c", "import time; time.sleep(30)"])
    real_killpg = os.killpg

    def denied(pgid, signum):
        raise PermissionError("synthetic permission failure")

    try:
        monkeypatch.setattr(os, "killpg", denied)
        assert owned.stop(.1) is False
        assert owned.process.returncode is None
    finally:
        real_killpg(owned.pgid, signal.SIGKILL)
        owned.process.wait(timeout=5)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin zombie-group proof")
def test_failed_darwin_group_query_cannot_claim_cleanup_success(monkeypatch):
    import ctypes
    import types

    owned = guard.OwnedProcess([sys.executable, "-c", "pass"])
    try:
        deadline = time.monotonic() + 5
        while owned.exit_code() is None:
            assert time.monotonic() < deadline
            time.sleep(.01)
        with monkeypatch.context() as patch:
            patch.setattr(ctypes, "CDLL", lambda path: types.SimpleNamespace(proc_listpids=lambda *args: 0))
            assert owned.dead_darwin_group() is False
    finally:
        assert owned.stop(.1)


def test_app_server_initialization_timeout_is_bounded():
    source = guard.AppServer([sys.executable, "-c", "import time; time.sleep(30)"], .1)
    start = time.monotonic()
    try:
        with pytest.raises(guard.Stop, match="usage_read_timeout"):
            source.start(.1, lambda: None)
    finally:
        assert source.close()
    assert time.monotonic() - start < 2


def test_runtime_expires_before_next_scheduled_poll(tmp_path):
    controller = controller_fixture(tmp_path, [usage()], poll=1, read_timeout=.3,
                                    stale_after=2, max_runtime=.25)
    assert run_controller(controller, [sys.executable, "-c", "import time; time.sleep(30)"]) == 125
    assert events(tmp_path)[-1]["reason"] == "runtime_elapsed"
    assert len([event for event in events(tmp_path) if event["event"] == "usage_accepted"]) == 1


def test_dynamic_registry_is_append_only_and_refreshes_at_cleanup(tmp_path):
    registry = tmp_path / "registry.json"
    containers = guard.Containers([], [], "/usr/bin/true", .1, registry)
    containers.refresh()  # A controller may not have created the file yet.
    registry.write_text(json.dumps({"schema": 1, "container_ids": ["a" * 64]}))
    containers.refresh()
    registry.write_text(json.dumps({"schema": 1, "container_ids": ["b" * 64]}))
    with pytest.raises(guard.Stop, match="invalid_container_registration"):
        containers.refresh()
    assert containers.ids == {"a" * 64}
    registry.write_text(json.dumps({"schema": 1, "container_ids": ["a" * 64, "b" * 64]}))
    assert containers.stop() == (2, 0)
    assert containers.cleanup == [
        {"container_id": "a" * 64, "state": "stopped"},
        {"container_id": "b" * 64, "state": "stopped"},
    ]


@pytest.mark.parametrize("value", [
    [], {}, {"schema": True, "container_ids": []}, {"schema": 2, "container_ids": []},
    {"schema": 1, "container_ids": "a" * 64}, {"schema": 1, "container_ids": ["short"]},
    {"schema": 1, "container_ids": [12]}, {"schema": 1, "container_ids": ["a" * 64] * 257},
])
def test_dynamic_registry_malformed_data_fails_closed(tmp_path, value):
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps(value))
    containers = guard.Containers([], [], "/usr/bin/true", .1, registry)
    with pytest.raises(guard.Stop, match="invalid_container_registration"):
        containers.refresh()
    assert containers.ids == set()


def test_dynamic_registry_cannot_disappear_or_be_symlink_or_oversized(tmp_path):
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"schema": 1, "container_ids": ["a" * 64]}))
    containers = guard.Containers([], [], "/usr/bin/true", .1, registry)
    containers.refresh()
    registry.unlink()
    with pytest.raises(guard.Stop, match="invalid_container_registration"):
        containers.refresh()
    target = tmp_path / "target.json"
    target.write_text(json.dumps({"schema": 1, "container_ids": ["a" * 64]}))
    registry.symlink_to(target)
    with pytest.raises(guard.Stop, match="invalid_container_registration"):
        containers.refresh()
    registry.unlink()
    registry.write_text(" " * (guard.MAX_REGISTRY_BYTES + 1))
    with pytest.raises(guard.Stop, match="invalid_container_registration"):
        containers.refresh()
    assert containers.ids == {"a" * 64}


def docker_state_fixture(tmp_path, mode):
    executable = tmp_path / "docker-state"
    script = r'''
import json, sys
mode = MODE
args = sys.argv[1:]
if args[:2] in (['container', 'stop'], ['container', 'rm']):
    print('SENSITIVE generic stop diagnostic', file=sys.stderr)
    sys.exit(1)
if args[:2] == ['container', 'inspect']:
    ident = args[-1]
    if mode in ('stopped', 'running', 'bad_id'):
        print(json.dumps({'id': ident if mode != 'bad_id' else 'z'*64,
                          'running': mode == 'running'}))
        sys.exit(0)
    if mode == 'connection_failure':
        print('SENSITIVE cannot connect to daemon', file=sys.stderr)
    else:
        print('Error: No such object: '+ident, file=sys.stderr)
    sys.exit(1)
if args[0] == 'version':
    if mode == 'daemon_down':
        print('SENSITIVE cannot connect to daemon', file=sys.stderr)
        sys.exit(1)
    print(json.dumps('synthetic-server-version'))
    sys.exit(0)
sys.exit(2)
'''
    executable.write_text(f"#!{sys.executable}\nMODE={mode!r}\n" + script)
    executable.chmod(0o700)
    return str(executable)


@pytest.mark.parametrize("mode,state,failures", [
    ("missing", "not_found", 0), ("stopped", "stopped", 0),
    ("running", "still_running", 1), ("bad_id", "unverified", 1),
    ("connection_failure", "unverified", 1), ("daemon_down", "unverified", 1),
])
def test_cleanup_requires_exact_inspection_and_reachable_daemon_for_missing(tmp_path, mode, state, failures):
    containers = guard.Containers(["a" * 64], [], docker_state_fixture(tmp_path, mode), .1)
    assert containers.stop() == (1, failures)
    assert containers.cleanup == [{"container_id": "a" * 64, "state": state}]


def test_container_audit_records_exact_ids_and_state_without_raw_errors(tmp_path):
    controller = controller_fixture(tmp_path, [usage()])
    controller.containers = guard.Containers(["a" * 64], [], docker_state_fixture(tmp_path, "missing"), .1)
    assert run_controller(controller, [sys.executable, "-c", "pass"]) == 0
    assert events(tmp_path)[-1]["containers"] == [{"container_id": "a" * 64, "state": "not_found"}]
    assert "SENSITIVE" not in (tmp_path / "receipts.jsonl").read_text()


def test_opt_in_removal_targets_only_registered_full_ids(tmp_path):
    executable = tmp_path / "docker-remove"
    log = tmp_path / "remove-args.json"
    executable.write_text(f"#!{sys.executable}\nimport json,pathlib,sys\npathlib.Path({str(log)!r}).write_text(json.dumps(sys.argv[1:]))\n")
    executable.chmod(0o700)
    containers = guard.Containers(["a" * 64, "b" * 64], [], str(executable), .1, remove=True)
    assert containers.stop() == (2, 0)
    assert json.loads(log.read_text()) == ["container", "rm", "--force", "--", "a" * 64, "b" * 64]
    assert all(record["state"] == "removed" for record in containers.cleanup)


@pytest.mark.parametrize("mode,state,failures", [
    ("missing", "not_found", 0), ("stopped", "not_removed", 1),
    ("running", "still_running", 1), ("daemon_down", "unverified", 1),
])
def test_opt_in_removal_requires_absence_or_success(tmp_path, mode, state, failures):
    containers = guard.Containers(["a" * 64], [], docker_state_fixture(tmp_path, mode), .1, remove=True)
    assert containers.stop() == (1, failures)
    assert containers.cleanup == [{"container_id": "a" * 64, "state": state}]


def test_stop_marker_precedes_all_process_and_container_cleanup(tmp_path, monkeypatch):
    controller = controller_fixture(tmp_path, [usage()])
    marker = tmp_path / "stopped"
    controller.stop_file = marker
    real_stop = guard.OwnedProcess.stop
    real_containers_stop = controller.containers.stop

    def stop_owned(owned, grace):
        assert marker.is_file()
        return real_stop(owned, grace)

    def stop_containers():
        assert marker.is_file()
        return real_containers_stop()

    monkeypatch.setattr(guard.OwnedProcess, "stop", stop_owned)
    controller.containers.stop = stop_containers
    assert run_controller(controller, [sys.executable, "-c", "pass"]) == 0
    assert marker.stat().st_mode & 0o777 == 0o600
    assert events(tmp_path)[-1]["stop_gate_closed"] is True


def test_failed_stop_marker_still_cleans_up_and_reports_failure(tmp_path):
    controller = controller_fixture(tmp_path, [usage()])
    controller.stop_file = tmp_path / "missing-directory" / "stopped"
    assert run_controller(controller, [sys.executable, "-c", "pass"]) == 125
    assert events(tmp_path)[-1]["stop_gate_closed"] is False
    assert events(tmp_path)[-1]["cleanup_okay"] is False
    assert controller.source.owned.process.returncode is not None


def test_cli_refuses_existing_stop_marker_before_usage_or_launch(tmp_path):
    marker = tmp_path / "stopped"
    marker.write_text("keep")
    assert guard.main(["--receipts", str(tmp_path / "receipt"), "--stop-file", str(marker),
                       "--codex", "never-launch", "--", "never-launch"]) == 125
    assert marker.read_text() == "keep"
    assert not (tmp_path / "receipt").exists()


@pytest.mark.parametrize("value", ["short", "-option", "a" * 63, "g" * 64])
def test_container_ids_must_be_exact(value):
    with pytest.raises(guard.Stop, match="invalid_container_id"):
        guard.Containers([value], [], "docker", .1)


def test_cidfile_cannot_preexist_and_cannot_be_symlink_or_fifo(tmp_path):
    cidfile = tmp_path / "cid"
    cidfile.write_text("a" * 64)
    with pytest.raises(guard.Stop, match="cidfile_already_exists"):
        guard.Containers([], [cidfile], "docker", .1)
    other = tmp_path / "other"
    containers = guard.Containers([], [other], "docker", .1)
    other.symlink_to(cidfile)
    with pytest.raises(guard.Stop, match="invalid_container_registration"):
        containers.refresh()
    other.unlink()
    os.mkfifo(other)
    with pytest.raises(guard.Stop, match="invalid_container_registration"):
        containers.refresh()


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT])
def test_cli_signal_stops_only_owned_job_and_app_server(tmp_path, signum):
    (tmp_path / "responses.json").write_text(json.dumps([usage()]))
    executable = tmp_path / "fake-codex"
    # The executable receives app-server arguments; bind the fabricated root.
    executable.write_text(f"#!{sys.executable}\nimport sys\nsys.argv = [sys.argv[0], {str(tmp_path)!r}]\n" + SERVER)
    executable.chmod(0o700)
    marker = tmp_path / "job-pid"
    command = [sys.executable, str(TOOL), "--receipts", str(tmp_path / "receipts.jsonl"),
               "--codex", str(executable), "--grace-seconds", ".1", "--stop-file", str(tmp_path / "signal.stop"), "--",
               sys.executable, "-c", f"import os,pathlib,time; pathlib.Path({str(marker)!r}).write_text(str(os.getpid())); time.sleep(30)"]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        wait_file(marker, process)
        process.send_signal(signum)
        out, err = process.communicate(timeout=5)
        assert process.returncode == 130
        assert out == err == b""
        assert events(tmp_path)[-1]["reason"] == "interrupted"
        assert events(tmp_path)[-1]["cleanup_okay"] is True
        assert (tmp_path / "signal.stop").stat().st_mode & 0o777 == 0o600
        with pytest.raises(ProcessLookupError):
            os.kill(int(marker.read_text()), 0)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_many_historical_ids_use_one_batched_inspection_and_one_daemon_check(tmp_path):
    ids = [f"{i:064x}" for i in range(1, 81)]
    log = tmp_path / "calls.jsonl"
    docker = tmp_path / "docker-many"
    docker.write_text(f"#!{sys.executable}\n" + f"LOG={str(log)!r}\n" + r'''
import json, pathlib, sys, time
args = sys.argv[1:]
with pathlib.Path(LOG).open('a') as f: f.write(json.dumps(args) + '\n')
if args[:2] == ['container','rm']: sys.exit(1)
if args[:2] == ['container','inspect']:
    time.sleep(.3)
    for ident in args[args.index('--')+1:]:
        print('Error response from daemon: No such container: '+ident,file=sys.stderr)
    sys.exit(1)
if args[0] == 'version': print(json.dumps('fixture-daemon')); sys.exit(0)
sys.exit(2)
''')
    docker.chmod(0o700)
    containers = guard.Containers(ids, [], str(docker), .1, remove=True)
    started = time.monotonic()
    assert containers.stop() == (80, 0)
    assert time.monotonic() - started < 3
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(calls) == 3
    assert calls[1][:2] == ["container", "inspect"]
    assert calls[1][calls[1].index("--") + 1:] == sorted(ids)
    assert all(record["state"] == "not_found" for record in containers.cleanup)


@pytest.mark.parametrize("fault", ["duplicate", "foreign", "omitted", "unexpected_stderr", "both_streams", "bad_json"])
def test_batch_inspection_requires_unambiguous_accounting_for_every_id(fault):
    a, b = "a"*64, "b"*64
    containers = guard.Containers([a,b], [], "/usr/bin/true", .1)
    out = json.dumps({"id":a,"running":False}) + "\n"
    err = f"Error: No such object: {b}\n"
    if fault == "duplicate": err += err
    if fault == "foreign": err += f"Error: No such object: {'c'*64}\n"
    if fault == "omitted": err = ""
    if fault == "unexpected_stderr": err += "untrusted daemon error\n"
    if fault == "both_streams": err += f"Error: No such object: {a}\n"
    if fault == "bad_json": out = '{"id":"'+a+'","id":"'+a+'","running":false}\n'
    assert containers.inspection_states(1,out.encode(),err.encode()) == {a:"unverified",b:"unverified"}


def test_mixed_inspection_maps_existing_and_missing_exact_ids():
    a, b = "a"*64, "b"*64
    containers = guard.Containers([a,b], [], "/usr/bin/true", .1)
    out = (json.dumps({"id":a,"running":False})+"\n").encode()
    err = f"Error: No such container: {b}\n".encode()
    assert containers.inspection_states(1,out,err) == {a:"stopped",b:"pending_missing"}
    containers.remove = True
    assert containers.inspection_states(1,out,err) == {a:"not_removed",b:"pending_missing"}


def test_registry_capacity_is_documented_and_excess_is_refused(tmp_path):
    registry = tmp_path / "registry.json"
    ids = [f"{i:064x}" for i in range(guard.MAX_CONTAINER_IDS)]
    registry.write_text(json.dumps({"schema":1,"container_ids":ids}))
    containers = guard.Containers([], [], "/usr/bin/true", .1, registry)
    containers.refresh()
    assert len(containers.ids) == 2048
    assert registry.stat().st_size < guard.MAX_REGISTRY_BYTES
    registry.write_text(json.dumps({"schema":1,"container_ids":ids+["f"*64]}))
    with pytest.raises(guard.Stop,match="invalid_container_registration"):
        containers.refresh()


@pytest.mark.parametrize("unsafe", ["writable", "hardlink", "foreign_owner"])
def test_registry_metadata_must_be_owned_and_not_replaceable_by_other_users(tmp_path, monkeypatch, unsafe):
    registry = tmp_path / "registry.json"
    registry.write_text('{"schema":1,"container_ids":[]}')
    if unsafe == "writable": registry.chmod(0o666)
    elif unsafe == "hardlink": os.link(registry,tmp_path / "other")
    else:
        real = os.fstat
        def other_owner(fd):
            fields = list(real(fd)); fields[4] = os.geteuid()+1
            return os.stat_result(fields)
        monkeypatch.setattr(os,"fstat",other_owner)
    with pytest.raises(guard.Stop,match="invalid_container_registration"):
        guard.Containers([],[],"/usr/bin/true",.1,registry).refresh()


@pytest.mark.parametrize("flags", [[], ["--remove-containers"], ["--stop-file","STOP"]])
def test_dynamic_registry_requires_all_launch_gate_controls_before_usage(tmp_path,flags,capsys):
    flags = [str(tmp_path / "stopped") if value == "STOP" else value for value in flags]
    result = guard.main(["--receipts",str(tmp_path / "receipts.jsonl"),"--container-registry",str(tmp_path / "registry.json"),
                         *flags,"--codex","must-not-start","--","must-not-start"])
    assert result == 125
    assert "dynamic_container_controls_required" in capsys.readouterr().err
    assert not (tmp_path / "receipts.jsonl").exists()


@pytest.mark.parametrize("parent", ["missing", "writable"])
def test_control_parent_is_validated_before_receipts_or_usage_start(tmp_path,parent,capsys):
    directory = tmp_path / parent
    if parent == "writable": directory.mkdir(); directory.chmod(0o777)
    assert guard.main(["--receipts",str(tmp_path / "receipts.jsonl"),"--stop-file",str(directory / "stop"),
                       "--codex","must-not-start","--","must-not-start"]) == 125
    assert "unsafe_control_parent" in capsys.readouterr().err
    assert not (tmp_path / "receipts.jsonl").exists()
