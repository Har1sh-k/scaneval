"""Local invocation lifecycle tests use only owned synthetic process groups."""
import os
import signal
import subprocess
import sys
import time

import pytest

from scaneval.adapters.base import build_env, run_command


def test_interrupt_reaps_scanner_and_stops_its_grandchild(tmp_path):
    scanner = r'''
import os, pathlib, subprocess, sys, time
root = pathlib.Path(sys.argv[1])
child = subprocess.Popen([sys.executable, '-c', "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); exec('while True:\\n p.write_text(str(time.time()))\\n time.sleep(.02)')", str(root/'heartbeat')])
(root/'pids').write_text(str(os.getpid())+' '+str(child.pid))
print('partial stdout', flush=True)
print('partial stderr', file=sys.stderr, flush=True)
time.sleep(60)
'''
    controller = r'''
import pathlib, sys
from scaneval.adapters.base import run_command, build_env
root = pathlib.Path(sys.argv[1])
run_command([sys.executable, '-c', sys.argv[2], str(root)], cwd=root, timeout_seconds=60, env=build_env(), stdout_path=root/'out', stderr_path=root/'err')
'''
    proc = subprocess.Popen([sys.executable, '-c', controller, str(tmp_path), scanner],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    pids = []
    try:
        deadline = time.monotonic() + 10
        while not (tmp_path/'heartbeat').exists() or not (tmp_path/'pids').exists():
            assert time.monotonic() < deadline
            assert proc.poll() is None
            time.sleep(.02)
        pids = list(map(int, (tmp_path/'pids').read_text().split()))
        proc.send_signal(signal.SIGINT)
        _, err = proc.communicate(timeout=8)
        assert b'KeyboardInterrupt' in err
        with pytest.raises(ProcessLookupError):
            os.kill(pids[0], 0)  # direct child was reaped before propagation
        before = (tmp_path/'heartbeat').read_bytes()
        time.sleep(.15)
        assert (tmp_path/'heartbeat').read_bytes() == before
        assert 'partial stdout' in (tmp_path/'out').read_text()
        assert 'partial stderr' in (tmp_path/'err').read_text()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if not pids and (tmp_path/"pids").exists():
            pids = list(map(int, (tmp_path/"pids").read_text().split()))
        if pids:
            try:
                os.killpg(pids[0], signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_communication_exception_is_preserved_and_process_reaped(tmp_path, monkeypatch):
    real_popen = subprocess.Popen
    processes = []
    original = RuntimeError('communication failed')

    def start(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        processes.append(process)
        def fail(**kwargs):
            raise original
        process.communicate = fail
        return process

    monkeypatch.setattr(subprocess, 'Popen', start)
    with pytest.raises(RuntimeError) as caught:
        run_command([sys.executable, '-c', 'import time; time.sleep(60)'], cwd=tmp_path,
                    timeout_seconds=60, env=build_env(), stdout_path=tmp_path/'out', stderr_path=tmp_path/'err')
    assert caught.value is original
    assert processes[0].returncode == -signal.SIGKILL


@pytest.mark.parametrize('timeout', [False, True])
def test_normal_and_timeout_preserve_both_output_streams(tmp_path, timeout):
    script = "import sys,time; print('out',flush=True); print('err',file=sys.stderr,flush=True)"
    if timeout:
        script += '; time.sleep(60)'
    result = run_command([sys.executable, '-c', script], cwd=tmp_path, timeout_seconds=.5 if timeout else 10,
                         env=build_env(), stdout_path=tmp_path/'out', stderr_path=tmp_path/'err')
    assert result.timed_out is timeout
    assert result.exit_code == (None if timeout else 0)
    assert (tmp_path/'out').read_text() == 'out\n'
    assert (tmp_path/'err').read_text() == 'err\n'


@pytest.mark.parametrize('persistent_failure,bad_note', [(False, False), (True, False), (True, True)])
def test_cleanup_interrupts_preserve_original_and_still_reap_and_close(tmp_path, monkeypatch, persistent_failure, bad_note):
    real_popen = subprocess.Popen
    real_killpg = os.killpg
    processes = []
    attempts = []
    waits = []
    class OriginalError(ValueError):
        def add_note(self, note):
            if bad_note:
                raise KeyboardInterrupt('diagnostic recording interrupted')
            super().add_note(note)

    original = OriginalError('retained original exception')

    def start(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        processes.append(process)
        real_wait = process.wait
        def fail(**kwargs):
            raise original
        def interrupted_wait(*args, **kwargs):
            waits.append(kwargs['timeout'])
            if len(waits) == 1:
                raise KeyboardInterrupt('second interrupt during wait')
            return real_wait(*args, **kwargs)
        process.communicate = fail
        process.wait = interrupted_wait
        return process

    def interrupted_killpg(pid, sig):
        attempts.append(pid)
        if persistent_failure or len(attempts) == 1:
            raise KeyboardInterrupt('secondary interrupt during group kill')
        return real_killpg(pid, sig)

    monkeypatch.setattr(subprocess, 'Popen', start)
    monkeypatch.setattr(os, 'killpg', interrupted_killpg)
    try:
        with pytest.raises(ValueError) as caught:
            run_command([sys.executable, '-c', 'import time; time.sleep(60)'], cwd=tmp_path,
                        timeout_seconds=60, env=build_env(), stdin_text='payload',
                        stdout_path=tmp_path/'out', stderr_path=tmp_path/'err')
        assert caught.value is original
        assert len(attempts) == (3 if persistent_failure else 2)
        assert len(waits) == 2
        assert all(0 <= timeout <= 5 for timeout in waits)
        assert processes[0].returncode == -signal.SIGKILL
        assert processes[0].stdin.closed
        if persistent_failure and not bad_note:
            assert 'process-group cleanup failed' in original.__notes__[0]
    finally:
        for process in processes:
            try:
                real_killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # Bypass the injected wait while ensuring the test never leaves its child.
            real_popen.wait(process, timeout=5)
