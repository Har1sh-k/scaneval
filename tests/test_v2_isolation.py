"""The execution backend seam in :mod:`scaneval.adapters.base`, and the reads made of what a scanner wrote.

``run_command`` hands every command to the backend active in its context and refuses one started
from a thread that does not carry it; the stderr tail every failure message quotes, and an
adapter's own read of its output, never follow a link or block on a pipe. No network, no model
calls, no engine.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import threading

import pytest

from scaneval.adapters import base as base_module
from scaneval.adapters.base import (Adapter, AdapterError, CommandResult, SystemSpec, build_env, run_command,
                                    tail_text)
from scaneval.adapters.semgrep import SemgrepAdapter, semgrep_version


mkfifo_required = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")


def finishes(action, seconds: float = 10.0):
    """Run *action* on a thread and return what it returned, failing rather than hanging the suite."""
    outcome: dict = {}

    def target():
        try:
            outcome["value"] = action()
        except BaseException as exc:  # noqa: BLE001 - handed back to the test below
            outcome["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), f"the call was still blocked after {seconds}s"
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


# --- reads of files a scanner wrote --------------------------------------------------------------


def test_tail_text_quotes_a_regular_file_exactly_and_never_a_link_or_a_pipe(tmp_path):
    """The tail every failure message quotes is of a file the scanner could have replaced."""
    data = b"x" * 5000 + "last words \u00e9\n".encode("utf-8")
    stderr = tmp_path / "stderr.txt"
    stderr.write_bytes(data)
    for limit in (16, 2000, 10000):
        assert tail_text(stderr, limit=limit) == data[-limit:].decode("utf-8", errors="replace")
    secret = tmp_path / "secret.txt"
    secret.write_text("host-only-token\n", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(secret)
    assert tail_text(link) == ""
    assert tail_text(tmp_path / "missing.txt") == "" and tail_text(tmp_path) == ""


@mkfifo_required
def test_tail_text_returns_at_once_for_a_named_pipe_left_where_stderr_belongs(tmp_path):
    pipe = tmp_path / "stderr.txt"
    os.mkfifo(pipe)
    assert finishes(lambda: tail_text(pipe)) == ""


def planting_semgrep(tmp_path: Path, secret: Path, *, version_link: bool, stderr_link: bool,
                     output_link: bool) -> Path:
    """A stand-in Semgrep that replaces the files it was given with links to *secret*, then fails."""
    raw = tmp_path / "raw"
    script = tmp_path / "planting-semgrep"
    script.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        f"raw, secret = {str(raw)!r}, {str(secret)!r}\n"
        "def plant(name):\n"
        "    os.unlink(os.path.join(raw, name))\n"
        "    os.symlink(secret, os.path.join(raw, name))\n"
        "if '--version' in sys.argv:\n"
        f"    if {version_link!r}:\n"
        "        plant('semgrep-version.txt')\n"
        f"    if {stderr_link!r}:\n"
        "        plant('semgrep-version.stderr.txt')\n"
        "        raise SystemExit(2)\n"
        "    print('9.9.9')\n"
        "    raise SystemExit(0)\n"
        f"if {output_link!r}:\n"
        "    plant('semgrep.json')\n"
        "    plant('semgrep.stderr.txt')\n"
        "raise SystemExit(1)\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def test_semgrep_reads_back_what_it_wrote_without_following_a_link_the_scanner_planted(tmp_path):
    """A link where Semgrep's output belongs would otherwise put a file of the scanner's choosing in the record.

    The secret here parses as a Semgrep result, so following the link would not even have failed:
    it would have become a claim, and its text a recorded version or a quoted stderr tail.
    """
    token = "host-only-token-7d1e"
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"version": token, "results": [{
        "check_id": "planted.rule", "path": "app.py", "start": {"line": 1}, "end": {"line": 1},
        "extra": {"message": token, "severity": "ERROR", "metadata": {"cwe": ["CWE-78"]}}}],
        "errors": [], "paths": {"scanned": ["app.py"]}}), encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    for version_link, stderr_link in ((True, False), (False, True)):
        binary = planting_semgrep(tmp_path, secret, version_link=version_link, stderr_link=stderr_link,
                                  output_link=False)
        with pytest.raises(AdapterError) as raised:
            semgrep_version(str(binary), raw)
        assert token not in str(raised.value)
        for leftover in raw.iterdir():
            leftover.unlink()

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("import subprocess\n", encoding="utf-8")
    binary = planting_semgrep(tmp_path, secret, version_link=False, stderr_link=False, output_link=True)
    preparation = {"ruleset": {"commit": "a" * 40, "tree_hash": "sha256:" + "b" * 64},
                   "config_dirs": [str(tmp_path / "rules" / "python")], "ruleset_root": str(tmp_path / "rules")}
    outcome = SemgrepAdapter().scan(request={}, source_dir=source, raw_dir=raw,
                                    spec=SystemSpec("semgrep-fake", "semgrep", {"binary": str(binary)}),
                                    preparation=preparation, timeout_seconds=60, trace_mode="off", trace_dir=None)
    assert outcome.status == "error" and outcome.error["code"] == "unparseable_output"
    assert outcome.claims == [] and token not in outcome.error["message"]


# --- routing in adapters.base ----------------------------------------------------------------


class RecordingBackend:
    name = "recording"

    def __init__(self):
        self.commands = []

    def run_command(self, argv, **kwargs):
        self.commands.append((list(argv), kwargs))
        return CommandResult(list(argv), 0, False, 0.0, kwargs["stdout_path"], kwargs["stderr_path"])


def test_run_command_goes_to_the_active_backend_and_runs_on_the_host_otherwise(tmp_path):
    held = RecordingBackend()
    with base_module.routed_through(held):
        assert base_module.active_backend() is held
        routed = run_command(["scanner", "--version"], cwd=tmp_path, timeout_seconds=5, env={"A": "1"},
                             stdout_path=tmp_path / "out.txt", stderr_path=tmp_path / "err.txt")
    assert base_module.active_backend() is None
    assert routed.exit_code == 0 and held.commands[0][0] == ["scanner", "--version"]
    assert held.commands[0][1]["env"] == {"A": "1"} and not (tmp_path / "out.txt").exists()
    local = run_command([sys.executable, "-c", "print('local')"], cwd=tmp_path, timeout_seconds=30, env=build_env(),
                        stdout_path=tmp_path / "out.txt", stderr_path=tmp_path / "err.txt")
    assert local.exit_code == 0 and (tmp_path / "out.txt").read_text(encoding="utf-8") == "local\n"


def test_a_command_started_from_a_thread_outside_the_routed_context_is_refused_not_run_on_the_host(tmp_path):
    """A context variable does not follow a thread, so such a command would otherwise run on the host."""
    held = RecordingBackend()
    marker = tmp_path / "ran-on-the-host"
    raised: list[BaseException] = []

    def from_a_thread():
        try:
            run_command([sys.executable, "-c", f"open({str(marker)!r}, 'w')"], cwd=tmp_path, timeout_seconds=30,
                        env=build_env(), stdout_path=tmp_path / "o.txt", stderr_path=tmp_path / "e.txt")
        except BaseException as exc:
            raised.append(exc)

    with base_module.routed_through(held):
        worker = threading.Thread(target=from_a_thread)
        worker.start()
        worker.join(30)
    assert raised and isinstance(raised[0], AdapterError) and "not run on the host" in str(raised[0])
    assert not marker.exists() and held.commands == []
    # Once the routed block is closed, a thread runs locally again.
    worker = threading.Thread(target=from_a_thread)
    worker.start()
    worker.join(30)
    assert marker.exists() and len(raised) == 1


def test_an_adapter_is_not_oci_compatible_and_mounts_nothing_unless_it_says_so():
    class Plain(Adapter):
        def scan(self, **kwargs):
            raise AssertionError("not called")

    assert Plain.oci_compatible is False
    assert Plain().runtime_mounts(SystemSpec("plain", "plain", {}), {}) == ()


# --- semgrep's version probe ------------------------------------------------------------------


def test_semgrep_probes_its_version_without_asking_the_network_for_a_newer_one(tmp_path):
    recorded = tmp_path / "argv.json"
    binary = tmp_path / "fake-semgrep"
    binary.write_text(f"#!{sys.executable}\nimport json, sys\n"
                      f"open({str(recorded)!r}, 'w').write(json.dumps(sys.argv[1:]))\nprint('9.9.9')\n",
                      encoding="utf-8")
    binary.chmod(0o755)
    raw = tmp_path / "raw"
    raw.mkdir()
    assert semgrep_version(str(binary), raw) == "9.9.9"
    assert json.loads(recorded.read_text(encoding="utf-8")) == ["--version", "--disable-version-check"]
