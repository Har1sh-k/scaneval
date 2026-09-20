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
from sastbench.adapters.base import AdapterError, CommandResult, SystemSpec
from sastbench.adapters.semgrep import (SemgrepAdapter, _dotted_prefixes, import_semgrep_results,
                                        semgrep_version)


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "u", "GIT_AUTHOR_EMAIL": "u@x", "GIT_COMMITTER_NAME": "u",
                               "GIT_COMMITTER_EMAIL": "u@x", "GIT_CONFIG_GLOBAL": "/dev/null"}).stdout.strip()


def rule_yaml(rule_id: str) -> str:
    return (f"rules:\n  - id: {rule_id}\n    languages: [python]\n    severity: WARNING\n"
            "    message: subprocess call with shell=True\n    metadata:\n      cwe:\n"
            "        - 'CWE-78: OS Command Injection'\n"
            "    patterns:\n      - pattern: subprocess.$F(..., shell=True, ...)\n")


RULE_YAML = rule_yaml("probe.subprocess-shell")
VULNERABLE_PY = "import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
# Files a --config directory walk in Semgrep 1.177 loads besides the plain shell.yaml: a
# dotfile rule and a .yml. Probed against the installed binary, not assumed.
LOADED_RULE_FILES = {
    "python/.hidden.yaml": rule_yaml("probe.hidden-rule"),
    "python/more.yml": rule_yaml("probe.more-rule"),
}
# Files that same walk leaves out: rule tests, fixtest fixtures, a bare extension, and names
# whose final suffix is not .yaml/.yml.
UNLOADED_RULE_FILES = {
    "python/shell.test.yaml": rule_yaml("probe.test-only"),
    "python/shell.fixed.yaml": rule_yaml("probe.fixed-only"),
    "python/shell.test.fixed.yml": rule_yaml("probe.testfixed-only"),
    "python/.yaml": rule_yaml("probe.bare-extension"),
    "python/old.yaml.bak": rule_yaml("probe.backup-only"),
    "python/notes.txt": rule_yaml("probe.text-only"),
}


def pinned_rules_repo(tmp_path: Path, *, escape_symlink: bool = False, rule_symlink: str | None = None,
                      extra_files: dict[str, str] | None = None, name: str = "rules-repo") -> tuple[Path, str]:
    """A tiny git repository holding one pinned Semgrep rule, as an offline ruleset source.

    ``rule_symlink`` checks in ``python/linked.yaml`` as a symlink to that literal target, the
    way a rules repository can carry one: git stores the target string and recreates it on
    checkout, so the link is relative to wherever the pinned checkout lands. ``extra_files``
    adds further checkout-relative files verbatim, and ``name`` allows two repositories under
    one tmp_path.
    """
    rules = tmp_path / name
    (rules / "python").mkdir(parents=True)
    (rules / "python" / "shell.yaml").write_text(RULE_YAML, encoding="utf-8")
    for relative, content in (extra_files or {}).items():
        target = rules / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
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


def test_semgrep_dotted_prefix_drops_a_leading_dot_the_way_semgrep_does():
    # semgrep.rule_lang.convert_config_id_to_prefix runs .lstrip("./") on the joined directory
    # parts before sanitizing, so it drops leading dots as well as the leading separator. A
    # prefix that kept the dot never matched a check_id from a dot-prefixed checkout root.
    assert _dotted_prefixes([".rulecache/rules"]) == ["rulecache.rules."]
    assert _dotted_prefixes(["/.cache/rules"]) == ["cache.rules."]
    assert _dotted_prefixes(["../.rulecache/rules"]) == ["rulecache.rules."]
    # A dot inside the path is not leading, so it survives in the prefix exactly as Semgrep
    # leaves it.
    assert _dotted_prefixes(["/tmp/.cache/rules"]) == ["tmp..cache.rules."]


@pytest.mark.skipif(os.sep != "/", reason="POSIX path-separator semantics")
def test_semgrep_dotted_prefix_agrees_with_semgreps_own_prefix_function():
    # Differential against the installed Semgrep: the adapter has to build the same prefix
    # semgrep.rule_lang.convert_config_id_to_prefix builds, or the machine path survives in
    # native_rule_id. Nothing is executed here, the function is imported and called.
    rule_lang = pytest.importorskip("semgrep.rule_lang")
    for directory in ["/Users/x/.sastbench/rules/python", "/tmp/rule cache (1)/rules__abc",
                      "/.cache/rules", ".rulecache/rules", "../.rulecache/rules", "/a/b",
                      "/tmp/we\\ird/rules"]:
        expected = rule_lang.convert_config_id_to_prefix(str(Path(directory) / "shell.yaml"))
        assert _dotted_prefixes([directory]) == [expected], directory


def test_semgrep_import_strips_a_dot_prefixed_root_from_the_rule_id():
    payload = {"results": [
        {"check_id": "rulecache.rules.python.probe.subprocess-shell", "path": "app.py",
         "start": {"line": 1}, "end": {"line": 1}, "extra": {"message": "m", "metadata": {}}},
    ]}
    claims, notes = import_semgrep_results(payload, ruleset_roots=["../.rulecache/rules"])
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


@pytest.mark.parametrize("extra, fragment", [
    ({"message": {"text": "boom"}}, "extra.message as a dict"),
    ({"message": 7}, "extra.message as a int"),
    ({"message": ["boom"]}, "extra.message as a list"),
    ({"severity": 4}, "extra.severity as a int"),
    ({"severity": ["WARNING"]}, "extra.severity as a list"),
    ({"fingerprint": 12345}, "extra.fingerprint as a int"),
    ({"fingerprint": {"v": 1}}, "extra.fingerprint as a dict"),
    ({"lines": ["code"]}, "extra.lines as a list"),
    ({"lines": 3}, "extra.lines as a int"),
])
def test_semgrep_import_rejects_non_string_message_severity_fingerprint_and_lines(extra, fragment):
    # A non-string message used to be str()-ed into the allegation, which invents scanner prose
    # out of a JSON object, and a non-string severity or fingerprint was dropped without a word.
    # Both are shapes this adapter cannot read, so both are named errors.
    payload = {"results": [{"check_id": "a", "path": "p", "start": {"line": 1}, "end": {"line": 1},
                            "extra": extra}]}
    with pytest.raises(AdapterError, match=fragment):
        import_semgrep_results(payload)


def test_semgrep_import_accepts_null_optional_strings_as_absent():
    # Absent and null stay absences: only a present value of the wrong type is a shape error.
    payload = {"results": [{"check_id": "a", "path": "p", "start": {"line": 1}, "end": {"line": 1},
                            "extra": {"message": None, "severity": None, "fingerprint": None, "lines": None}}]}
    claims, notes = import_semgrep_results(payload)
    assert claims[0]["allegation"] == "a"
    assert "native_severity" not in claims[0] and "native_id" not in claims[0]
    assert "evidence_text" not in claims[0] and notes == []


def test_semgrep_import_docstring_names_the_fields_whose_value_type_is_checked():
    # The claim that every unexpected shape is reported is only worth keeping if the docstring
    # lists the fields it covers, so the reader can check it against the code.
    doc = " ".join((import_semgrep_results.__doc__ or "").split())
    for field in ("extra.message", "extra.severity", "extra.fingerprint", "extra.lines",
                  "extra.metadata.cwe", "check_id", "path"):
        assert field in doc
    assert "may be absent or null" in doc and "never ``str()``-ed into an allegation" in doc


@pytest.mark.skipif(os.sep != "/", reason="POSIX file-name semantics")
def test_semgrep_import_keeps_a_posix_file_name_containing_a_backslash():
    # On POSIX "we\\ird.py" is one file name. Rewriting it to "we/ird.py" made
    # primary_location name a file that does not exist, and the claim could then never be
    # matched against the real source.
    payload = {"results": [
        {"check_id": "a", "path": "we\\ird.py", "start": {"line": 1}, "end": {"line": 1}, "extra": {}},
        {"check_id": "b", "path": "src/we\\ird.py", "start": {"line": 1}, "end": {"line": 1}, "extra": {}},
    ]}
    claims, _ = import_semgrep_results(payload)
    assert [claim["primary_location"]["path"] for claim in claims] == ["we\\ird.py", "src/we\\ird.py"]


@pytest.mark.skipif(os.sep != "/", reason="POSIX file-name semantics")
@pytest.mark.parametrize("raw_path, expected", [
    # A drive prefix cannot be a POSIX path, so that one is translated even here.
    ("C:\\proj\\app.py", "C:/proj/app.py"),
    ("src\\app.py", "src\\app.py"),
    ("./app.py", "app.py"),
    ("src/app.py", "src/app.py"),
])
def test_semgrep_import_translates_only_paths_that_cannot_be_posix(raw_path, expected):
    payload = {"results": [{"check_id": "a", "path": raw_path, "start": {"line": 1}, "end": {"line": 1},
                            "extra": {}}]}
    claims, _ = import_semgrep_results(payload)
    assert claims[0]["primary_location"]["path"] == expected


@pytest.mark.parametrize("raw_path, expected", [
    ("src\\app.py", "src/app.py"),
    (".\\app.py", "app.py"),
    ("C:\\proj\\app.py", "C:/proj/app.py"),
    ("we\\ird.py", "we/ird.py"),
])
def test_semgrep_import_translates_separators_when_the_platform_uses_backslashes(monkeypatch, raw_path, expected):
    # On Windows the backslash really is the separator Semgrep emitted, so the claim path is
    # translated there. The platform is read from one module constant so this stays a local
    # substitution rather than a global os.sep change.
    monkeypatch.setattr(semgrep_module, "_NATIVE_SEPARATOR", "\\")
    payload = {"results": [{"check_id": "a", "path": raw_path, "start": {"line": 1}, "end": {"line": 1},
                            "extra": {}}]}
    claims, _ = import_semgrep_results(payload)
    assert claims[0]["primary_location"]["path"] == expected


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


def test_semgrep_scan_rejects_a_binary_path_containing_a_nul_byte(tmp_path):
    # subprocess raises a bare ValueError("embedded null byte") from the C layer, which would
    # leave the adapter as an exception the runner cannot attribute to a configuration field.
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})
    with pytest.raises(AdapterError, match="config.binary contains a NUL byte"):
        scan_with_fake(tmp_path, payload, 0, config={"binary": "sem\x00grep"})


def test_semgrep_scan_rejects_a_config_dir_containing_a_nul_byte(tmp_path):
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})
    preparation = {"ruleset": {"commit": "a" * 40, "tree_hash": "sha256:" + "b" * 64},
                   "config_dirs": [str(tmp_path / "rules"), "/rules/py\x00thon"],
                   "ruleset_root": str(tmp_path / "rules")}
    with pytest.raises(AdapterError, match="config_dirs entry .* contains a NUL byte"):
        scan_with_fake(tmp_path, payload, 0, preparation=preparation)


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


def test_semgrep_prepare_rejects_a_ruleset_url_containing_a_nul_byte(tmp_path):
    # git is invoked through subprocess, which raises a bare ValueError for an argument holding
    # a NUL byte. The URL is refused by name before anything is fetched.
    rules, commit = pinned_rules_repo(tmp_path)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": f"{rules}\x00", "commit": commit, "paths": ["python"]}})
    with pytest.raises(AdapterError, match="config.ruleset.url contains a NUL byte"):
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


def test_semgrep_prepare_hashes_exactly_the_files_semgrep_loads_from_a_config_directory(tmp_path):
    # Semgrep's read_config_folder keeps is_config_suffix() files: dotfile YAMLs included, rule
    # tests and .fixed fixtures left out. Hashing a different set in either direction made the
    # recorded tree hash describe neither the loaded rules nor the checkout.
    loaded_only, commit_a = pinned_rules_repo(tmp_path, name="loaded-only", extra_files=LOADED_RULE_FILES)
    mixed, commit_b = pinned_rules_repo(tmp_path, name="mixed",
                                        extra_files={**LOADED_RULE_FILES, **UNLOADED_RULE_FILES})
    prepared_loaded = SemgrepAdapter().prepare(
        SystemSpec("s", "semgrep", {"ruleset": {"url": str(loaded_only), "commit": commit_a, "paths": ["python"]}}),
        tmp_path / "cache")
    prepared_mixed = SemgrepAdapter().prepare(
        SystemSpec("s", "semgrep", {"ruleset": {"url": str(mixed), "commit": commit_b, "paths": ["python"]}}),
        tmp_path / "cache")
    # shell.yaml, .hidden.yaml and more.yml in both; the six unloaded files change nothing.
    assert prepared_loaded["ruleset"]["rule_files"] == 3
    assert prepared_mixed["ruleset"]["rule_files"] == 3
    assert prepared_loaded["ruleset"]["tree_hash"] == prepared_mixed["ruleset"]["tree_hash"]


@pytest.mark.parametrize("name, selected", [
    ("shell.yaml", True), ("more.yml", True), (".hidden.yaml", True), ("a.b.yaml", True),
    ("shell.test.yaml", False), ("shell.test.yml", False), ("shell.fixed.yaml", False),
    ("shell.test.fixed.yml", False), (".yaml", False), ("old.yaml.bak", False), ("notes.txt", False),
])
def test_semgrep_rule_file_selection_matches_semgreps_own_predicate(name, selected):
    # Differential against the installed Semgrep's own predicate, so the recorded inventory
    # cannot drift from what a --config directory actually contributes. Nothing is executed.
    util = pytest.importorskip("semgrep.util")
    assert semgrep_module._is_loaded_rule_file(Path(name)) is selected
    assert util.is_config_suffix(Path(name)) is selected


def test_semgrep_module_docstring_says_which_rule_files_the_recorded_hash_covers():
    doc = " ".join((semgrep_module.__doc__ or "").split())
    assert ".test.yaml" in doc and "``.fixed``" in doc and "dotfiles" in doc
    # The hash covers selection, not whether Semgrep could parse what it selected.
    assert "Selection is not parse success" in doc
    assert "create-only" in doc


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


def test_semgrep_version_timeout_names_the_limit_and_the_elapsed_time(tmp_path, monkeypatch):
    # A killed --version writes nothing to stderr, so the old message was "failed: " with an
    # empty tail and no hint that a timeout was what happened. No real process is started here:
    # the command result is substituted, so the test neither sleeps nor waits on a clock.
    raw = tmp_path / "raw"
    raw.mkdir()

    def timed_out(argv, *, cwd, timeout_seconds, env, stdout_path, stderr_path, stdin_text=None):
        return CommandResult(list(argv), None, True, 12.5, stdout_path, stderr_path)

    monkeypatch.setattr(semgrep_module, "run_command", timed_out)
    with pytest.raises(AdapterError) as raised:
        semgrep_version("/nonexistent/semgrep", raw, timeout_seconds=3)
    assert "exceeded its 3s limit" in str(raised.value) and "killed after 12.5s" in str(raised.value)


def test_semgrep_version_refuses_to_overwrite_an_existing_raw_file(tmp_path):
    # run_command opens its output files with "wb". The runner hands scan() a fresh staging
    # directory, but direct library use can point two calls at one raw directory, and the
    # earlier invocation's recorded output must not be replaced.
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "semgrep-version.txt").write_text("1.2.3 from an earlier run\n", encoding="utf-8")
    binary = fake_semgrep(tmp_path, "", 0)
    with pytest.raises(AdapterError, match="already exists and semgrep raw output files are create-only"):
        semgrep_version(str(binary), raw)
    assert (raw / "semgrep-version.txt").read_text(encoding="utf-8") == "1.2.3 from an earlier run\n"


def test_semgrep_scan_refuses_to_overwrite_an_existing_raw_output_file(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("import subprocess\n", encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "semgrep.json").write_text("{\"results\": []}\n", encoding="utf-8")
    spec = SystemSpec("semgrep-fake", "semgrep", {"binary": str(fake_semgrep(tmp_path, "{}", 0))})
    with pytest.raises(AdapterError, match="already exists and semgrep raw output files are create-only"):
        SemgrepAdapter().scan(request={}, source_dir=source, raw_dir=raw, spec=spec,
                              preparation=fake_preparation(tmp_path), timeout_seconds=60,
                              trace_mode="off", trace_dir=None)
    assert (raw / "semgrep.json").read_text(encoding="utf-8") == "{\"results\": []}\n"
    # The refusal comes before anything runs, so no version banner was recorded either.
    assert not (raw / "semgrep-version.txt").exists()


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
    (source / "app.py").write_text(VULNERABLE_PY, encoding="utf-8")
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


@semgrep_required
def test_semgrep_real_binary_loads_exactly_the_rule_files_prepare_counted(tmp_path):
    # The recorded rule_files count and tree hash are only a description of the rules that ran
    # if they cover the same files Semgrep loads from the configured directory. The dotfile
    # rule must be counted and must fire; the rule test and the .fixed fixture must do neither.
    rules, commit = pinned_rules_repo(tmp_path, extra_files={**LOADED_RULE_FILES, **UNLOADED_RULE_FILES})
    spec = SystemSpec("semgrep-inventory", "semgrep",
                      {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    preparation = SemgrepAdapter().prepare(spec, tmp_path / "cache")
    assert preparation["ruleset"]["rule_files"] == 3

    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text(VULNERABLE_PY, encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    outcome = SemgrepAdapter().scan(request={}, source_dir=source, raw_dir=raw, spec=spec, preparation=preparation,
                                    timeout_seconds=300, trace_mode="off", trace_dir=None)

    assert outcome.status == "success"
    assert sorted(claim["native_rule_id"] for claim in outcome.claims) == [
        "python.probe.hidden-rule", "python.probe.more-rule", "python.probe.subprocess-shell"]


@semgrep_required
def test_semgrep_real_binary_matches_a_rule_id_from_a_dot_prefixed_cache_root(tmp_path):
    # Semgrep lstrips "./" off the joined directory parts, so a configured directory under a
    # dot-prefixed cache loses that dot in the check_id. An absolute path on this machine never
    # begins with a dot segment, so the reachable shape is a relative config directory: the
    # adapter records absolute ones, but a caller supplying its own preparation record can hand
    # scan() a relative path, which Semgrep resolves against the scan working directory.
    cache = tmp_path / ".rulecache" / "rules" / "python"
    cache.mkdir(parents=True)
    (cache / "shell.yaml").write_text(RULE_YAML, encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text(VULNERABLE_PY, encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    preparation = {"ruleset": {"commit": "a" * 40, "tree_hash": "sha256:" + "b" * 64},
                   "config_dirs": ["../.rulecache/rules/python"],
                   "ruleset_root": "../.rulecache/rules"}
    outcome = SemgrepAdapter().scan(request={}, source_dir=source, raw_dir=raw,
                                    spec=SystemSpec("semgrep-dotted", "semgrep", {}), preparation=preparation,
                                    timeout_seconds=300, trace_mode="off", trace_dir=None)

    assert outcome.status == "success"
    assert [claim["native_rule_id"] for claim in outcome.claims] == ["python.probe.subprocess-shell"]
    assert not any("path-like prefix" in note for note in outcome.notes)
    raw_check_id = json.loads((raw / "semgrep.json").read_text(encoding="utf-8"))["results"][0]["check_id"]
    # The dot really is gone from what Semgrep emitted, which is why keeping it never matched.
    assert raw_check_id == "rulecache.rules.python.probe.subprocess-shell"
