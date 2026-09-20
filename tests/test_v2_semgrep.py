"""Semgrep adapter edges: rule-id prefixes, malformed payloads, ruleset paths, and empty scans.

The fake-binary tests never touch the network or a model; the one test that runs the real
Semgrep binary is skipped when it is not installed. Fixtures here are local git checkouts.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from sastbench.adapters import semgrep as semgrep_module
from sastbench.adapters.base import AdapterError, SystemSpec
from sastbench.adapters.semgrep import (SemgrepAdapter, _dotted_prefixes, import_semgrep_results,
                                        semgrep_version)


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
                               "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"}).stdout.strip()


RULE_YAML = (
    "rules:\n  - id: probe.subprocess-shell\n    languages: [python]\n    severity: WARNING\n"
    "    message: subprocess call with shell=True\n    metadata:\n      cwe:\n        - 'CWE-78: OS Command Injection'\n"
    "    patterns:\n      - pattern: subprocess.$F(..., shell=True, ...)\n")


def pinned_rules_repo(tmp_path: Path, *, escape_symlink: bool = False,
                      rule_symlink: str | None = None) -> tuple[Path, str]:
    """A tiny git repository holding one pinned Semgrep rule, as an offline ruleset source.

    ``rule_symlink`` checks in ``python/linked.yaml`` as a symlink to that literal target, the
    way a rules repository can carry one: git stores the target string and recreates it on
    checkout, so the link is relative to wherever the pinned checkout lands.
    """
    rules = tmp_path / "rules-repo"
    (rules / "python").mkdir(parents=True)
    (rules / "python" / "shell.yaml").write_text(RULE_YAML, encoding="utf-8")
    if rule_symlink is not None:
        os.symlink(rule_symlink, rules / "python" / "linked.yaml")
    if escape_symlink:
        # A checked-in symlink that leaves the checkout once it is resolved.
        (rules / "escape").symlink_to("..")
    _git("init", "-q", "-b", "main", cwd=rules)
    _git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=rules)
    _git("add", "-A", cwd=rules)
    _git("commit", "-q", "-m", "rules", cwd=rules)
    return rules, _git("rev-parse", "HEAD", cwd=rules)


semgrep_required = pytest.mark.skipif(
    not (Path(sys.executable).with_name("semgrep").exists() or shutil.which("semgrep")),
    reason="semgrep binary not installed")


def fake_semgrep(tmp_path: Path, stdout_text: str, exit_code: int, *,
                 version_bytes: bytes = b"9.9.9\n") -> Path:
    """A stand-in binary that answers ``--version`` and then writes *stdout_text* verbatim.

    ``--version`` answers with raw bytes, so a banner that is not valid UTF-8 can be exercised.
    """
    script = tmp_path / "fake-semgrep"
    script.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        "if '--version' in sys.argv:\n"
        f"    sys.stdout.buffer.write({version_bytes!r})\n"
        "    raise SystemExit(0)\n"
        f"sys.stdout.write({stdout_text!r})\n"
        f"raise SystemExit({exit_code})\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def fake_preparation(tmp_path: Path) -> dict:
    return {"ruleset": {"commit": "a" * 40, "tree_hash": "sha256:" + "b" * 64},
            "config_dirs": [str(tmp_path / "rules" / "python")],
            "ruleset_root": str(tmp_path / "rules")}


def scan_with_fake(tmp_path: Path, stdout_text: str, exit_code: int, *, config=None, preparation=None,
                   version_bytes: bytes = b"9.9.9\n"):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("import subprocess\n", encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    settings = {"binary": str(fake_semgrep(tmp_path, stdout_text, exit_code, version_bytes=version_bytes))}
    settings.update(config or {})
    spec = SystemSpec("semgrep-fake", "semgrep", settings)
    outcome = SemgrepAdapter().scan(request={}, source_dir=source, raw_dir=raw, spec=spec,
                                    preparation=fake_preparation(tmp_path) if preparation is None else preparation,
                                    timeout_seconds=60, trace_mode="off", trace_dir=None)
    return outcome, raw


# --- rule-id prefixes -------------------------------------------------------------------


def test_semgrep_dotted_prefix_drops_the_characters_semgrep_drops():
    # semgrep.rule_lang.sanitize_rule_id_fragment removes everything outside [A-Za-z0-9._-]
    # from the path it turns into a check_id prefix, so the adapter must remove the same
    # characters before comparing. Without this, a cache directory with a space never matches.
    assert _dotted_prefixes(["/tmp/rule cache (1)/rules__abc"]) == ["tmp.rulecache1.rules__abc."]
    assert _dotted_prefixes(["/Users/x/My Rules/go"]) == ["Users.x.MyRules.go."]
    # Longest first, and a directory that sanitizes away entirely is not a usable prefix.
    assert _dotted_prefixes(["/a/b", "/a"]) == ["a.b.", "a."]
    assert _dotted_prefixes(["/", "."]) == []


@pytest.mark.skipif(os.sep != "/", reason="POSIX path-separator semantics")
def test_semgrep_dotted_prefix_keeps_a_posix_directory_named_with_a_backslash():
    # On POSIX a backslash is an ordinary filename character, not a separator, so Semgrep keeps
    # "we\\ird" as one path component and deletes the backslash while sanitizing. Splitting on
    # the backslash here would build "tmp.we.ird.rules.", which never matches the check_id and
    # leaves the machine path in native_rule_id.
    assert _dotted_prefixes(["/tmp/we\\ird/rules"]) == ["tmp.weird.rules."]
    payload = {"results": [
        {"check_id": "tmp.weird.rules.python.probe.subprocess-shell", "path": "app.py",
         "start": {"line": 1}, "end": {"line": 1}, "extra": {"message": "m", "metadata": {}}},
    ]}
    claims, notes = import_semgrep_results(payload, ruleset_roots=["/tmp/we\\ird/rules"])
    assert claims[0]["native_rule_id"] == "python.probe.subprocess-shell"
    assert notes == []


def test_semgrep_import_strips_a_root_whose_directory_name_has_a_space():
    payload = {"results": [
        {"check_id": "tmp.rulecache1.rules__abc.python.probe.subprocess-shell", "path": "app.py",
         "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 9},
         "extra": {"message": "shell=True", "severity": "WARNING", "metadata": {}}},
    ]}
    claims, notes = import_semgrep_results(payload, ruleset_roots=["/tmp/rule cache (1)/rules__abc"])
    assert claims[0]["native_rule_id"] == "python.probe.subprocess-shell"
    assert notes == []


def test_semgrep_import_notes_an_unmatched_path_like_prefix():
    payload = {"results": [
        {"check_id": "tmp.other-cache.rules.python.probe.a", "path": "app.py",
         "start": {"line": 1}, "end": {"line": 1}, "extra": {"message": "m", "metadata": {}}},
        {"check_id": "tmp.other-cache.rules.python.probe.b", "path": "app.py",
         "start": {"line": 2}, "end": {"line": 2}, "extra": {"message": "m", "metadata": {}}},
    ]}
    claims, notes = import_semgrep_results(payload, ruleset_roots=["/tmp/cache/rules__abc"])
    # The id is kept verbatim rather than guessed at, but the leak is recorded once per prefix.
    assert [claim["native_rule_id"] for claim in claims] == ["tmp.other-cache.rules.python.probe.a",
                                                             "tmp.other-cache.rules.python.probe.b"]
    assert len(notes) == 1
    assert "2 check_id(s) start with 'tmp'" in notes[0] and "no supplied ruleset root" in notes[0]


def test_semgrep_import_does_not_note_a_plain_unprefixed_rule_id():
    payload = {"results": [
        {"check_id": "custom.rule", "path": "app.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "m", "metadata": {}}},
        {"check_id": "python.lang.security.audit.eval", "path": "app.py", "start": {"line": 2}, "end": {"line": 2},
         "extra": {"message": "m", "metadata": {}}},
    ]}
    claims, notes = import_semgrep_results(payload, config_dirs=["/tmp/cache/rules__abc/python"])
    # Neither id carries the config path, and the language segment that opens the second one
    # also ends the config directory, which is not evidence of a leaked machine path.
    assert [claim["native_rule_id"] for claim in claims] == ["custom.rule", "python.lang.security.audit.eval"]
    assert notes == []


@pytest.mark.parametrize("extra, fragment", [
    (0, "result 1 has extra as a int"),
    ([], "result 1 has extra as a list"),
    ("", "result 1 has extra as a str"),
    (False, "result 1 has extra as a bool"),
    ({"metadata": 0}, "extra.metadata as a int"),
    ({"metadata": []}, "extra.metadata as a list"),
    ({"metadata": ""}, "extra.metadata as a str"),
])
def test_semgrep_import_rejects_a_falsy_non_object_extra_or_metadata(extra, fragment):
    # A present value of the wrong type is a shape error even when it is falsy. Coercing it to
    # an empty object would read a malformed result as one that simply carries no metadata, and
    # its missing cwe list would then look like an honest absence.
    payload = {"results": [{"check_id": "a", "path": "p", "start": {"line": 1}, "end": {"line": 1},
                            "extra": extra}]}
    with pytest.raises(AdapterError, match=fragment):
        import_semgrep_results(payload)


def test_semgrep_import_treats_an_absent_or_null_extra_as_empty():
    payload = {"results": [
        {"check_id": "a", "path": "p", "start": {"line": 1}, "end": {"line": 1}},
        {"check_id": "b", "path": "p", "start": {"line": 2}, "end": {"line": 2}, "extra": None},
        {"check_id": "c", "path": "p", "start": {"line": 3}, "end": {"line": 3}, "extra": {"metadata": None}},
    ]}
    claims, notes = import_semgrep_results(payload)
    # No message, so the allegation falls back to the check_id; no metadata, so no native_cwe.
    assert [claim["allegation"] for claim in claims] == ["a", "b", "c"]
    assert not any("native_cwe" in claim for claim in claims)
    assert notes == []


def test_semgrep_import_docstring_calls_the_unmatched_prefix_note_a_heuristic():
    doc = import_semgrep_results.__doc__ or ""
    assert "heuristic" in doc and "leading segments" in doc
    # The limits of that heuristic are stated, not implied.
    assert "can miss" in doc and "can flag an id that carries no path" in doc


@pytest.mark.parametrize("payload, fragment", [
    ([], "payload is a list"),
    ("results", "payload is a str"),
    ({"results": {}}, "no results array"),
    ({"results": ["oops"]}, "result 1 is a str"),
    ({"results": [{"check_id": "a", "path": "p", "start": {"line": 1}, "end": {"line": 1}, "extra": [1]}]},
     "result 1 has extra as a list"),
    ({"results": [{"check_id": "a", "path": "p", "start": {"line": 1}, "end": {"line": 1},
                   "extra": {"metadata": [1]}}]}, "extra.metadata as a list"),
    ({"results": [{"check_id": "a", "path": "p", "start": {"line": 1}, "end": {"line": 1},
                   "extra": {"metadata": {"cwe": 78}}}]}, "extra.metadata.cwe as a int"),
    ({"results": [{"path": "p", "start": {"line": 1}, "end": {"line": 1}}]}, "check_id as a NoneType"),
    ({"results": [{"check_id": "a", "start": {"line": 1}, "end": {"line": 1}}]}, "path as a NoneType"),
    ({"results": [{"check_id": "a", "path": "p", "start": 3, "end": {"line": 1}}]}, "start as a int"),
    ({"results": [{"check_id": "a", "path": "p", "start": {"line": "3"}, "end": {"line": 1}}]}, "start.line as a str"),
    ({"results": [{"check_id": "a", "path": "p", "start": {"line": 1}, "end": {}}]}, "end.line as a NoneType"),
])
def test_semgrep_import_raises_adapter_error_naming_the_bad_shape(payload, fragment):
    with pytest.raises(AdapterError, match=fragment.replace("(", r"\(").replace(")", r"\)")):
        import_semgrep_results(payload)


# --- malformed payloads reaching scan() -------------------------------------------------


@pytest.mark.parametrize("stdout_text, exit_code, fragment", [
    ("not json at all\n", 0, "could not be read as a result payload"),
    (json.dumps([1, 2]), 0, "payload is a list"),
    (json.dumps({"results": ["oops"]}), 0, "result 1 is a str"),
    (json.dumps({"results": [{"check_id": "a", "path": "p", "start": {"line": 1}, "end": {"line": 1},
                              "extra": ["nope"]}]}), 0, "extra as a list"),
    (json.dumps({"results": [], "paths": "everything"}), 0, "paths is a str"),
    (json.dumps({"results": [], "paths": {"scanned": 3}}), 0, "paths.scanned is a int"),
    (json.dumps({"results": [], "paths": {"scanned": ["app.py"]}, "errors": "boom"}), 0, "errors is a str"),
    (json.dumps({"results": [], "paths": {"scanned": ["app.py"]}, "errors": "boom"}), 7, "errors is a str"),
])
def test_semgrep_scan_reports_unparseable_output_for_malformed_payloads(tmp_path, stdout_text, exit_code, fragment):
    outcome, raw = scan_with_fake(tmp_path, stdout_text, exit_code)
    assert outcome.status == "error" and outcome.claims == []
    # A shape this adapter cannot read is never an exit-code verdict and never an empty success.
    assert outcome.error["code"] == "unparseable_output"
    assert fragment in outcome.error["message"]
    assert f"exit code {exit_code}" in outcome.error["message"]
    assert (raw / "semgrep.json").read_text(encoding="utf-8") == stdout_text
    assert [artifact["id"] for artifact in outcome.artifacts] == ["semgrep-json", "semgrep-stderr"]


@pytest.mark.parametrize("config, fragment", [
    ({"rule_timeout_seconds": "soon"}, "rule_timeout_seconds must be an integer"),
    ({"rule_timeout_seconds": [30]}, "rule_timeout_seconds must be an integer, got a list"),
    ({"rule_timeout_seconds": -1}, "rule_timeout_seconds must be at least 0"),
    ({"jobs": "many"}, "jobs must be an integer"),
    ({"jobs": None}, "jobs must be an integer, got a NoneType"),
    ({"jobs": 0}, "jobs must be at least 1"),
])
def test_semgrep_scan_rejects_non_integer_or_out_of_range_config_values(tmp_path, config, fragment):
    # A bad knob is a setup failure, not a scan whose output could be interpreted, so it
    # raises before the binary runs.
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})
    with pytest.raises(AdapterError, match=fragment):
        scan_with_fake(tmp_path, payload, 0, config=config)


def test_semgrep_scan_accepts_string_integers_in_config(tmp_path):
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})
    outcome, _ = scan_with_fake(tmp_path, payload, 0, config={"rule_timeout_seconds": "45", "jobs": "3"})
    assert outcome.status == "success"
    assert outcome.command[outcome.command.index("--timeout") + 1] == "45"
    assert outcome.command[outcome.command.index("--jobs") + 1] == "3"


@pytest.mark.parametrize("preparation, fragment", [
    ({}, "no non-empty config_dirs"),
    ({"config_dirs": []}, "no non-empty config_dirs"),
    ({"config_dirs": "rules/python"}, "no non-empty config_dirs"),
    ({"config_dirs": [None]}, "no non-empty config_dirs"),
    ("rules", "preparation must be the mapping"),
    ({"config_dirs": ["/rules/python"]}, "ruleset as a NoneType"),
    ({"config_dirs": ["/rules/python"], "ruleset": {"commit": "a" * 40}}, "commit and tree_hash strings"),
])
def test_semgrep_scan_requires_a_prepared_ruleset_record(tmp_path, preparation, fragment):
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})
    with pytest.raises(AdapterError, match=fragment):
        scan_with_fake(tmp_path, payload, 0, preparation=preparation)


# --- ruleset paths ----------------------------------------------------------------------


@pytest.mark.parametrize("paths, fragment", [
    ("python", "non-empty list of non-empty strings"),
    ([], "non-empty list of non-empty strings"),
    ([""], "non-empty list of non-empty strings"),
    ([123], "non-empty list of non-empty strings"),
    (["python", None], "non-empty list of non-empty strings"),
    (["../rules-repo"], "must stay inside the checkout"),
    (["python/../.."], "must stay inside the checkout"),
    (["/etc"], "must stay inside the checkout"),
])
def test_semgrep_prepare_requires_relative_string_paths_inside_the_checkout(tmp_path, paths, fragment):
    rules, commit = pinned_rules_repo(tmp_path)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": paths}})
    with pytest.raises(AdapterError, match=fragment):
        SemgrepAdapter().prepare(spec, tmp_path / "cache")


def test_semgrep_prepare_refuses_a_ruleset_path_that_escapes_through_a_symlink(tmp_path):
    # The entry itself looks relative and harmless; only resolution shows it leaves the pinned
    # checkout, which would hash and scan rules that the recorded commit does not contain.
    rules, commit = pinned_rules_repo(tmp_path, escape_symlink=True)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["escape"]}})
    with pytest.raises(AdapterError, match="outside the pinned checkout"):
        SemgrepAdapter().prepare(spec, tmp_path / "cache")


def test_semgrep_prepare_refuses_a_symlinked_rule_file_inside_an_allowed_directory(tmp_path):
    # The ruleset path itself is fine; the symlink sits inside it. rglob yields the link and
    # is_file() follows it, so without this refusal a rule file from outside the pinned commit
    # would be hashed into the recorded tree hash and loaded by Semgrep.
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "evil.yaml").write_text(RULE_YAML, encoding="utf-8")
    rules, commit = pinned_rules_repo(tmp_path, rule_symlink="../../../outside/evil.yaml")
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    with pytest.raises(AdapterError, match="contains the symlink") as raised:
        SemgrepAdapter().prepare(spec, tmp_path / "cache")
    assert "'python'" in str(raised.value) and "python/linked.yaml" in str(raised.value)


def test_semgrep_prepare_refuses_a_rule_file_resolving_outside_the_checkout(tmp_path, monkeypatch):
    # Defense in depth behind the symlink refusal: with is_symlink() answering False, the
    # resolved location of every hashed rule file still has to sit under the pinned root.
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "evil.yaml").write_text(RULE_YAML, encoding="utf-8")
    rules, commit = pinned_rules_repo(tmp_path, rule_symlink="../../../outside/evil.yaml")
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    with pytest.raises(AdapterError, match="outside the pinned checkout") as raised:
        SemgrepAdapter().prepare(spec, tmp_path / "cache")
    assert "python/linked.yaml" in str(raised.value)


def test_semgrep_prepare_rejects_a_ruleset_path_containing_a_nul_byte(tmp_path):
    # A NUL byte cannot name a directory, and resolving it raises ValueError rather than the
    # adapter's own error, so it is refused before anything is fetched.
    rules, commit = pinned_rules_repo(tmp_path)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["py\x00thon"]}})
    with pytest.raises(AdapterError, match="NUL byte"):
        SemgrepAdapter().prepare(spec, tmp_path / "cache")
    assert not (tmp_path / "cache").exists()


def test_semgrep_prepare_reports_a_path_resolution_failure_as_an_adapter_error(tmp_path, monkeypatch):
    # resolve() raises ValueError for a path the platform cannot represent. That is a setup
    # failure named after the offending entry, not an exception type escaping the adapter.
    rules, commit = pinned_rules_repo(tmp_path)
    real_resolve = Path.resolve

    def refuse(self, *args, **kwargs):
        if self.name == "python":
            raise ValueError("embedded null byte")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", refuse)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    with pytest.raises(AdapterError, match="could not be resolved") as raised:
        SemgrepAdapter().prepare(spec, tmp_path / "cache")
    assert "'python'" in str(raised.value)


def test_semgrep_prepare_records_an_aggregate_tree_hash_and_no_per_file_hashes(tmp_path):
    rules, commit = pinned_rules_repo(tmp_path)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    preparation = SemgrepAdapter().prepare(spec, tmp_path / "cache")
    assert set(preparation["ruleset"]) == {"url", "commit", "git_tree", "paths", "rule_files", "tree_hash"}
    assert preparation["ruleset"]["rule_files"] == 1 and preparation["ruleset"]["tree_hash"].startswith("sha256:")
    assert "rule_hashes" not in json.dumps(preparation)
    # The module docstring must describe what is actually recorded.
    doc = semgrep_module.__doc__ or ""
    assert "aggregate hash" in doc and "not kept in the preparation record" in doc


def test_semgrep_scan_reports_deeply_nested_json_as_unparseable_output(tmp_path):
    # Nesting deep enough to exhaust the JSON parser's recursion raises RecursionError, which is
    # output this adapter cannot read, not an empty successful scan.
    depth = 20000
    stdout_text = "[" * depth + "]" * depth
    outcome, raw = scan_with_fake(tmp_path, stdout_text, 0)
    assert outcome.status == "error" and outcome.claims == []
    assert outcome.error["code"] == "unparseable_output"
    assert "could not be read as a result payload" in outcome.error["message"]
    # The invocation record stays intact: the command and both raw artifacts are still reported.
    assert outcome.command[1:4] == ["scan", "--json", "--metrics=off"]
    assert [artifact["id"] for artifact in outcome.artifacts] == ["semgrep-json", "semgrep-stderr"]
    assert (raw / "semgrep.json").read_text(encoding="utf-8") == stdout_text


def test_semgrep_scan_records_an_undecodable_version_banner_without_failing(tmp_path):
    # A version banner that is not valid UTF-8 is a provenance defect, not a reason to abandon
    # the run: the bytes are kept verbatim in the raw artifact and the recorded string replaces
    # what it cannot decode.
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})
    outcome, raw = scan_with_fake(tmp_path, payload, 0, version_bytes=b"9.9.9-\xff\xfe\n")
    assert outcome.status == "success"
    assert outcome.tool_versions["semgrep"] == "9.9.9-\ufffd\ufffd"
    assert (raw / "semgrep-version.txt").read_bytes() == b"9.9.9-\xff\xfe\n"


def test_semgrep_version_reports_an_unwritable_output_file_as_an_adapter_error(tmp_path):
    # An OSError while recording the version is a setup failure, not an OSError escaping the
    # adapter into the runner.
    raw = tmp_path / "raw"
    (raw / "semgrep-version.txt").mkdir(parents=True)
    binary = fake_semgrep(tmp_path, "", 0)
    with pytest.raises(AdapterError, match="could not be recorded"):
        semgrep_version(str(binary), raw)


# --- empty and partially reported scans -------------------------------------------------


def test_semgrep_zero_exit_with_an_explicit_empty_scanned_list_is_nothing_scanned(tmp_path):
    # Exit 0 with an explicit empty scanned list means Semgrep opened no file at all. Silence
    # from a run that read nothing is missing evidence, not a quiet negative control.
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": []}, "errors": []})
    outcome, _ = scan_with_fake(tmp_path, payload, 0)
    assert outcome.status == "error" and outcome.exit_code == 0 and outcome.claims == []
    assert outcome.error["code"] == "nothing_scanned"
    assert "looked at no source" in outcome.error["message"]
    assert "ignore rules" in outcome.error["message"]


def test_semgrep_zero_exit_without_a_paths_key_stays_success_with_a_note(tmp_path):
    payload = json.dumps({"version": "9.9.9", "results": [], "errors": []})
    outcome, _ = scan_with_fake(tmp_path, payload, 0)
    assert outcome.status == "success" and outcome.claims == []
    assert outcome.error is None
    assert any("reported no paths.scanned list" in note for note in outcome.notes)


def test_semgrep_zero_exit_with_scanned_paths_and_no_results_stays_a_clean_negative(tmp_path):
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"], "skipped": ["big.min.js"]},
                          "errors": []})
    outcome, _ = scan_with_fake(tmp_path, payload, 0)
    assert outcome.status == "success" and outcome.claims == [] and outcome.error is None
    assert any("skipped 1 paths" in note for note in outcome.notes)
    assert not any("paths.scanned list" in note for note in outcome.notes)


def test_semgrep_non_object_entries_in_the_errors_array_are_noted(tmp_path):
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]},
                          "errors": ["boom", {"level": "warn", "message": "ok"}]})
    outcome, _ = scan_with_fake(tmp_path, payload, 0)
    assert outcome.status == "success"
    assert any("were not objects" in note for note in outcome.notes)


# --- the real binary --------------------------------------------------------------------


@semgrep_required
def test_semgrep_real_binary_keeps_the_rule_id_relative_to_a_root_containing_a_space(tmp_path):
    # Regression for a cache directory whose name Semgrep cannot keep in a rule id: it deletes
    # the space and the parentheses, so the raw dotted path never matched and the machine
    # location survived in native_rule_id.
    rules, commit = pinned_rules_repo(tmp_path)
    spec = SystemSpec("semgrep-spaced", "semgrep",
                      {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    preparation = SemgrepAdapter().prepare(spec, tmp_path / "rule cache (1)")
    assert "rule cache (1)" in preparation["ruleset_root"]

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n",
                                   encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    outcome = SemgrepAdapter().scan(request={}, source_dir=source, raw_dir=raw, spec=spec, preparation=preparation,
                                    timeout_seconds=300, trace_mode="off", trace_dir=None)

    assert outcome.status == "success"
    assert [claim["native_rule_id"] for claim in outcome.claims] == ["python.probe.subprocess-shell"]
    assert not any("path-like prefix" in note for note in outcome.notes)
    raw_check_id = json.loads((raw / "semgrep.json").read_text(encoding="utf-8"))["results"][0]["check_id"]
    # Semgrep really did sanitize the directory name, which is what the adapter now mirrors.
    assert "rulecache1" in raw_check_id and "rule cache (1)" not in raw_check_id
