"""Fake Docker only: exact ownership, atomic registration, stop/start races, and redaction."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

import pytest


WRAPPER = Path(__file__).resolve().parents[1] / "tools/codex_guard_docker.py"
SECRET = "FABRICATED-CREDENTIAL-DO-NOT-ECHO"
RUN = "run-owned"
FAKE = r'''#!__PYTHON__
import fcntl, hashlib, json, os, sys, time
from pathlib import Path
root = Path(__ROOT__)
args = sys.argv[1:]
control_path = root / 'control.json'
control = json.loads(control_path.read_text()) if control_path.exists() else {}
def event(value):
    with (root / 'events.jsonl').open('a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(value) + '\n'); f.flush()
def wait_file(name):
    if name:
        end = time.monotonic() + 8
        while not (root / name).exists():
            if time.monotonic() >= end: sys.exit(70)
            time.sleep(.01)
def update(callback):
    with (root / 'state.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        p = root / 'state.json'
        state = json.loads(p.read_text()) if p.exists() else {}
        value = callback(state)
        p.write_text(json.dumps(state))
        return value
def resolve(state, target):
    if target in state: return target
    return next((key for key, item in state.items() if item['name'] == target), None)
if args[0] == 'create':
    if control.get('fail_create'):
        print('unsafe error ' + os.environ.get('TEST_CREDENTIAL', ''), file=sys.stderr)
        sys.exit(19)
    labels = {}
    for i, word in enumerate(args):
        if word == '--label':
            key, value = args[i + 1].split('=', 1); labels[key] = value
        elif word.startswith('--label='):
            key, value = word[8:].split('=', 1); labels[key] = value
    name = args[args.index('--name') + 1]
    def make(state):
        ident = hashlib.sha256(name.encode()).hexdigest()
        state[ident] = {'name':name, 'labels':labels, 'running':False}
        return ident
    ident = update(make)
    event({'action':'create','id':ident,'credential_present':os.environ.get('TEST_CREDENTIAL') == __SECRET__})
    wait_file(control.get('create_gate'))
    print(control.get('create_output', ident))
    print('ignored private engine warning ' + os.environ.get('TEST_CREDENTIAL', ''), file=sys.stderr)
elif args[:2] == ['container','inspect']:
    target = args[-1]
    def inspect(state):
        ident = resolve(state,target)
        if not ident: return None
        item = state[ident]
        value = {'id':ident, 'labels':item['labels']}
        if control.get('replace_name_on_inspect') and target == item['name']:
            state[ident]['name'] += '-old'
            state['f'*64] = {'name':target,'labels':{'scaneval.run':'unrelated'},'running':False}
        return value
    found = update(inspect)
    event({'action':'inspect','target':target})
    if found is None: sys.exit(1)
    print(json.dumps(found))
elif args[0] == 'start':
    target = args[-1]
    event({'action':'start_wait','target':target})
    wait_file(control.get('start_gate'))
    def launch(state):
        ident = resolve(state,target)
        if ident: state[ident]['running'] = True
        return ident
    ident = update(launch)
    if ident is None: sys.exit(1)
    registry = json.loads((root / 'registry.json').read_text())
    event({'action':'started','target':target,'registered':ident in registry['container_ids']})
    print('scanner-output')
elif args[0] == 'rm':
    target = args[-1]
    update(lambda state: state.pop(target,None))
    event({'action':'removed','target':target})
else:
    event({'action':'passthrough','command':args[0]})
    print('fake-docker-ok')
'''


@pytest.fixture
def setup(tmp_path):
    fake = tmp_path / "real-docker"
    fake.write_text(FAKE.replace("__PYTHON__", sys.executable).replace("__ROOT__", repr(str(tmp_path))).replace("__SECRET__", repr(SECRET)))
    fake.chmod(0o700)
    config = tmp_path / "config.json"
    data = {"schema": 1, "real_docker": str(fake), "allowed_run_ids": [RUN],
            "registry_file": str(tmp_path / "registry.json"), "stop_file": str(tmp_path / "stop")}
    config.write_text(json.dumps(data)); config.chmod(0o600)
    env = {**os.environ, "SCANEVAL_GUARD_DOCKER_CONFIG": str(config), "TEST_CREDENTIAL": SECRET}
    env.pop("SCANEVAL_GUARD_DOCKER_ACTIVE", None)
    return tmp_path, data, env


def create_args(name="owned", run=RUN, role="worker"):
    return ["create", "--name", name, "--label", "scaneval.backend=oci", "--label", f"scaneval.run={run}",
            "--label", f"scaneval.role={role}", "--env", "TEST_CREDENTIAL", "--entrypoint", "fixture", "sha256:" + "a"*64]


def invoke(setup, *args):
    return subprocess.run([sys.executable, str(WRAPPER), *args], env=setup[2], capture_output=True, text=True, timeout=15)


def events(root):
    path = root / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def wait_event(root, action):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        found = [e for e in events(root) if e["action"] == action]
        if found:
            return found[-1]
        time.sleep(.01)
    pytest.fail(f"fake Docker never reached {action}")


def test_create_registers_before_output_and_start_executes_the_exact_id(setup):
    root, _, _ = setup
    created = invoke(setup, *create_args())
    assert created.returncode == 0 and created.stderr == ""
    ident = created.stdout.strip()
    assert len(ident) == 64
    assert json.loads((root / "registry.json").read_text()) == {"schema":1,"container_ids":[ident]}
    result = invoke(setup, "start", "--attach", "--interactive", "owned")
    assert result.returncode == 0 and result.stdout == "scanner-output\n"
    assert wait_event(root, "started") == {"action":"started","target":ident,"registered":True}
    assert events(root)[0]["credential_present"] is True
    assert SECRET not in created.stdout + created.stderr + result.stdout + result.stderr


@pytest.mark.parametrize("args", [create_args(run="unrelated"), create_args(role="other"),
    ["run","--label",f"scaneval.run={RUN}","image"], ["restart","owned"], ["container","run","image"],
    ["create","--name","owned","image","--label",f"scaneval.run={RUN}"],
    create_args()[:2] + ["--label-file","file"] + create_args()[2:]])
def test_unrelated_and_alternative_launches_are_refused_without_docker_calls(setup, args):
    result = invoke(setup, *args)
    assert result.returncode == 2
    assert events(setup[0]) == []
    assert SECRET not in result.stdout + result.stderr


def test_alias_start_requires_registration_and_owned_labels(setup):
    root, _, _ = setup
    ident = invoke(setup, *create_args()).stdout.strip()
    (root / "registry.json").write_text('{"schema":1,"container_ids":[]}')
    result = invoke(setup, "container", "start", "owned")
    assert result.returncode == 2 and "container_not_registered" in result.stderr
    (root / "registry.json").write_text(json.dumps({"schema":1,"container_ids":[ident]}))
    state = json.loads((root / "state.json").read_text()); state[ident]["labels"]["scaneval.run"] = "unrelated"
    (root / "state.json").write_text(json.dumps(state))
    result = invoke(setup, "start", "owned")
    assert result.returncode == 2 and "container_not_allowlisted" in result.stderr
    assert not any(e["action"] == "started" for e in events(root))


def test_name_reuse_after_inspection_cannot_redirect_start(setup):
    root, _, _ = setup
    ident = invoke(setup, *create_args()).stdout.strip()
    (root / "control.json").write_text('{"replace_name_on_inspect":true}')
    assert invoke(setup, "start", "owned").returncode == 0
    assert wait_event(root, "started")["target"] == ident
    assert json.loads((root / "state.json").read_text())["f"*64]["running"] is False


def test_existing_stop_marker_blocks_create_start_but_keeps_cleanup_available(setup):
    root, _, _ = setup
    ident = invoke(setup, *create_args()).stdout.strip()
    before = len(events(root)); (root / "stop").touch()
    assert invoke(setup, *create_args("late")).returncode == 2
    assert invoke(setup, "start", "owned").returncode == 2
    assert len(events(root)) == before
    assert invoke(setup, "rm", "--force", ident).returncode == 0
    assert (root / "stop").exists()


def test_stop_during_create_removes_only_the_new_owned_id(setup):
    root, _, env = setup
    (root / "control.json").write_text('{"create_gate":"release-create"}')
    child = subprocess.Popen([sys.executable,str(WRAPPER),*create_args()],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        ident = wait_event(root,"create")["id"]
        (root / "stop").touch(); (root / "release-create").touch()
        out, err = child.communicate(timeout=10)
        assert child.returncode == 2 and out == "" and "guard_stopped" in err
        assert json.loads((root / "state.json").read_text()) == {}
        assert [e["target"] for e in events(root) if e["action"] == "removed"] == [ident]
    finally:
        if child.poll() is None: child.kill(); child.wait()


def test_delayed_start_after_terminal_reset_cleanup_cannot_run(setup):
    root, data, env = setup
    ident = invoke(setup, *create_args()).stdout.strip()
    (root / "control.json").write_text('{"start_gate":"release-start"}')
    child = subprocess.Popen([sys.executable,str(WRAPPER),"start","owned"],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        wait_event(root,"start_wait")
        # The guard writes its permanent reset/stop marker BEFORE removing registered IDs.
        (root / "stop").touch()
        subprocess.run([data["real_docker"],"rm","--force",ident],check=True,capture_output=True)
        (root / "release-start").touch()
        out, err = child.communicate(timeout=10)
        assert child.returncode == 1 and out == ""
        assert not any(e["action"] == "started" for e in events(root))
        assert invoke(setup,"start","owned").returncode == 2
    finally:
        if child.poll() is None: child.kill(); child.wait()


def test_concurrent_creates_preserve_registry_union(setup):
    root, _, env = setup
    children = [subprocess.Popen([sys.executable,str(WRAPPER),*create_args(f"owned-{i}")],env=env,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for i in range(8)]
    ids = []
    for child in children:
        out, err = child.communicate(timeout=15)
        assert child.returncode == 0, err
        ids.append(out.strip())
    assert set(json.loads((root / "registry.json").read_text())["container_ids"]) == set(ids)
    assert len(set(ids)) == 8


@pytest.mark.parametrize("contents", ['{', '{"schema":true,"container_ids":[]}',
    '{"schema":1,"container_ids":["short"]}', '{"schema":1,"container_ids":[],"schema":1}',
    json.dumps({"schema":1,"container_ids":["a"*64,"a"*64]})])
def test_malformed_registry_prevents_creation(setup, contents):
    root, _, _ = setup
    (root / "registry.json").write_text(contents)
    result = invoke(setup,*create_args())
    assert result.returncode == 2 and events(root) == []
    assert SECRET not in result.stdout + result.stderr


def test_registry_symlink_is_refused_and_target_is_unchanged(setup):
    root, _, _ = setup
    outside = root / "outside.json"; outside.write_text('{"schema":1,"container_ids":[]}')
    (root / "registry.json").symlink_to(outside)
    assert invoke(setup,*create_args()).returncode == 2
    assert outside.read_text() == '{"schema":1,"container_ids":[]}'
    assert events(root) == []


@pytest.mark.parametrize("value", ["abc123", "A"*64, "a"*64 + "\n" + SECRET])
def test_create_id_must_be_exact_full_lowercase_hex_without_echoing_output(setup,value):
    root, _, _ = setup
    (root / "control.json").write_text(json.dumps({"create_output":value}))
    result = invoke(setup,*create_args())
    assert result.returncode == 2 and result.stdout == ""
    assert SECRET not in result.stderr
    assert not (root / "registry.json").exists()
    assert not any(e["action"] in ("started","removed") for e in events(root))


def test_create_errors_are_sanitized_without_command_or_credential_dump(setup):
    (setup[0] / "control.json").write_text('{"fail_create":true}')
    result = invoke(setup,*create_args(),SECRET)
    assert result.returncode == 2 and result.stderr == "codex_guard_docker: docker_create_failed\n"
    assert result.stdout == ""


def test_task_local_launcher_restores_configuration_after_oci_environment_filter(setup):
    root, _, env = setup
    launcher = root / "docker"
    launcher.write_text("#!/bin/sh\nexport SCANEVAL_GUARD_DOCKER_CONFIG=" + shlex.quote(env["SCANEVAL_GUARD_DOCKER_CONFIG"])
                        + "\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(WRAPPER)) + ' "$@"\n')
    launcher.chmod(0o700)
    stripped = {"PATH": str(root) + os.pathsep + os.environ["PATH"], "TEST_CREDENTIAL":SECRET}
    result = subprocess.run([str(launcher),*create_args()],env=stripped,capture_output=True,text=True,timeout=10)
    assert result.returncode == 0
    assert events(root)[0]["credential_present"] is True
    assert SECRET not in result.stdout + result.stderr


def test_recursion_and_nonprivate_configuration_fail_closed(setup):
    root, _, env = setup
    env["SCANEVAL_GUARD_DOCKER_ACTIVE"] = "1"
    assert invoke(setup,"version").returncode == 2
    env.pop("SCANEVAL_GUARD_DOCKER_ACTIVE")
    (root / "config.json").chmod(0o644)
    assert invoke(setup,"version").returncode == 2
    assert events(root) == []
