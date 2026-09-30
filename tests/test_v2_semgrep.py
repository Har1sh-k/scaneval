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

from scaneval.adapters import base as base_module
from scaneval.adapters import semgrep as semgrep_module
from scaneval.adapters.base import AdapterError, CommandResult, SystemSpec
from scaneval.contracts import _require_relative_path as validate_relative_path
from scaneval.adapters.semgrep import (SemgrepAdapter, _dotted_prefixes, import_semgrep_results,
                                        semgrep_version)
from scaneval.execution import PreparedInput, build_request


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


def pinned_rules_repo(tmp_path: Path, *, symlinks: dict[str, str] | None = None,
                      extra_files: dict[str, str] | None = None, name: str = "rules-repo") -> tuple[Path, str]:
    """A tiny git repository holding one pinned Semgrep rule, as an offline ruleset source.

    ``symlinks`` checks in each checkout-relative path as a symlink to that literal target, the
    way a rules repository can carry one: git stores the target string and recreates it on
    checkout, so a relative link resolves against wherever the pinned checkout lands.
    ``extra_files`` adds further checkout-relative files verbatim, and ``name`` allows two
    repositories under one tmp_path.
    """
    rules = tmp_path / name
    (rules / "python").mkdir(parents=True)
    (rules / "python" / "shell.yaml").write_text(RULE_YAML, encoding="utf-8")
    for relative, content in (extra_files or {}).items():
        target = rules / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    for relative, link_target in (symlinks or {}).items():
        link = rules / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(link_target, link)
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


def failing_version_semgrep(tmp_path: Path, stderr_text: str = "semgrep: unknown option --version\n") -> Path:
    """A stand-in binary whose ``--version`` writes to stderr and exits non-zero."""
    script = tmp_path / "fake-semgrep-badversion"
    script.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"sys.stderr.write({stderr_text!r})\n"
        "raise SystemExit(2)\n", encoding="utf-8")
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
    claims, notes, _lost = import_semgrep_results(payload, ruleset_roots=["/tmp/we\\ird/rules"])
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
    for directory in ["/Users/x/.scaneval/rules/python", "/tmp/rule cache (1)/rules__abc",
                      "/.cache/rules", ".rulecache/rules", "../.rulecache/rules", "/a/b",
                      "/tmp/we\\ird/rules"]:
        expected = rule_lang.convert_config_id_to_prefix(str(Path(directory) / "shell.yaml"))
        assert _dotted_prefixes([directory]) == [expected], directory


def test_semgrep_import_strips_a_dot_prefixed_root_from_the_rule_id():
    payload = {"results": [
        {"check_id": "rulecache.rules.python.probe.subprocess-shell", "path": "app.py",
         "start": {"line": 1}, "end": {"line": 1}, "extra": {"message": "m", "metadata": {}}},
    ]}
    claims, notes, _lost = import_semgrep_results(payload, ruleset_roots=["../.rulecache/rules"])
    assert claims[0]["native_rule_id"] == "python.probe.subprocess-shell"
    assert notes == []


def test_semgrep_import_strips_a_root_whose_directory_name_has_a_space():
    payload = {"results": [
        {"check_id": "tmp.rulecache1.rules__abc.python.probe.subprocess-shell", "path": "app.py",
         "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 9},
         "extra": {"message": "shell=True", "severity": "WARNING", "metadata": {}}},
    ]}
    claims, notes, _lost = import_semgrep_results(payload, ruleset_roots=["/tmp/rule cache (1)/rules__abc"])
    assert claims[0]["native_rule_id"] == "python.probe.subprocess-shell"
    assert notes == []


def test_semgrep_import_notes_an_unmatched_path_like_prefix():
    payload = {"results": [
        {"check_id": "tmp.other-cache.rules.python.probe.a", "path": "app.py",
         "start": {"line": 1}, "end": {"line": 1}, "extra": {"message": "m", "metadata": {}}},
        {"check_id": "tmp.other-cache.rules.python.probe.b", "path": "app.py",
         "start": {"line": 2}, "end": {"line": 2}, "extra": {"message": "m", "metadata": {}}},
    ]}
    claims, notes, _lost = import_semgrep_results(payload, ruleset_roots=["/tmp/cache/rules__abc"])
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
    claims, notes, _lost = import_semgrep_results(payload, config_dirs=["/tmp/cache/rules__abc/python"])
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
    claims, notes, _lost = import_semgrep_results(payload)
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
    claims, notes, _lost = import_semgrep_results(payload)
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
    claims, _notes, _lost = import_semgrep_results(payload)
    assert [claim["primary_location"]["path"] for claim in claims] == ["we\\ird.py", "src/we\\ird.py"]


@pytest.mark.skipif(os.sep != "/", reason="POSIX file-name semantics")
@pytest.mark.parametrize("raw_path, expected", [
    ("src\\app.py", "src\\app.py"),
    ("./app.py", "app.py"),
    ("src/app.py", "src/app.py"),
])
def test_semgrep_import_leaves_a_posix_path_spelling_alone(raw_path, expected):
    payload = {"results": [{"check_id": "a", "path": raw_path, "start": {"line": 1}, "end": {"line": 1},
                            "extra": {}}]}
    claims, notes, lost = import_semgrep_results(payload)
    assert claims[0]["primary_location"]["path"] == expected
    assert notes == [] and lost == 0


@pytest.mark.parametrize("raw_path, expected", [
    ("src\\app.py", "src/app.py"),
    (".\\app.py", "app.py"),
    ("we\\ird.py", "we/ird.py"),
])
def test_semgrep_import_translates_separators_when_the_platform_uses_backslashes(monkeypatch, raw_path, expected):
    # On Windows the backslash really is the separator Semgrep emitted, so the claim path is
    # translated there. The platform is read from one module constant so this stays a local
    # substitution rather than a global os.sep change.
    monkeypatch.setattr(semgrep_module, "_NATIVE_SEPARATOR", "\\")
    payload = {"results": [{"check_id": "a", "path": raw_path, "start": {"line": 1}, "end": {"line": 1},
                            "extra": {}}]}
    claims, _notes, _lost = import_semgrep_results(payload)
    assert claims[0]["primary_location"]["path"] == expected


@pytest.mark.parametrize("raw_path, expected", [
    ("./app.py", "app.py"),
    (".//app.py", "app.py"),
    ("././app.py", "app.py"),
    (".///src/app.py", "src/app.py"),
    ("./.hidden.py", ".hidden.py"),
])
def test_semgrep_import_drops_leading_dot_segments_without_making_the_path_absolute(raw_path, expected):
    # ".//app.py" used to lose exactly two characters and come back as "/app.py", an absolute
    # path naming a different file, which the scan-result contract then refuses outright.
    payload = {"results": [{"check_id": "a", "path": raw_path, "start": {"line": 1}, "end": {"line": 1},
                            "extra": {}}]}
    claims, notes, _lost = import_semgrep_results(payload)
    assert claims[0]["primary_location"]["path"] == expected
    assert notes == []


@pytest.mark.parametrize("raw_path", ["./", ".//", "././", ".", "..", "../app.py", "src/../../app.py",
                                     "/etc/passwd", "/", "C:\\proj\\app.py", "app\x00.py"])
def test_semgrep_import_reports_a_path_that_cannot_be_relative_instead_of_rewriting_it(raw_path):
    # "./" became the empty string, which no claim can carry. A path that cannot be expressed
    # inside the scanned tree is reported and left out rather than rewritten into some other
    # file's name: a claim location has to be a relative path.
    payload = {"results": [{"check_id": "a", "path": raw_path, "start": {"line": 1}, "end": {"line": 1},
                            "extra": {}},
                           {"check_id": "b", "path": "app.py", "start": {"line": 2}, "end": {"line": 2},
                            "extra": {}}]}
    claims, notes, lost = import_semgrep_results(payload)
    # The usable result is still imported and keeps its own result index in the claim id.
    assert [claim["claim_id"] for claim in claims] == ["c2"]
    assert claims[0]["primary_location"]["path"] == "app.py"
    assert len(notes) == 1 and repr(raw_path) in notes[0]
    assert "no claim was recorded" in notes[0] and "result 1:" in notes[0]
    assert lost == 1, "a result semgrep reported that yields no claim is import loss"


def test_semgrep_import_returns_paths_the_scan_result_contract_accepts():
    # The property the unusable branch exists for: whatever reaches primary_location.path is a
    # relative path with no '..' segment, which is what _require_relative_path checks when the
    # runner writes result.json.
    payload = {"results": [{"check_id": f"c{index}", "path": raw_path, "start": {"line": 1}, "end": {"line": 1},
                            "extra": {}}
                           for index, raw_path in enumerate([".//app.py", "./", "..", "/etc/passwd", "src/app.py",
                                                             "../x.py", "C:\\proj\\app.py", "app\x00.py",
                                                             "we\\ird.py"])]}
    claims, notes, lost = import_semgrep_results(payload)
    for claim in claims:
        validate_relative_path(claim["primary_location"]["path"], "primary_location.path")
    assert [claim["primary_location"]["path"] for claim in claims] == ["app.py", "src/app.py", "we\\ird.py"]
    assert len(notes) == 6 and lost == 6


def test_semgrep_import_reports_a_windows_absolute_path_as_unusable(monkeypatch):
    # On Windows both a drive path and a UNC path are absolute, so neither can be a location
    # inside the scanned tree; translating the separators would only hide that.
    monkeypatch.setattr(semgrep_module, "_NATIVE_SEPARATOR", "\\")
    for raw_path in ("C:\\proj\\app.py", "\\\\server\\share\\app.py"):
        payload = {"results": [{"check_id": "a", "path": raw_path, "start": {"line": 1}, "end": {"line": 1},
                                "extra": {}}]}
        claims, notes, lost = import_semgrep_results(payload)
        assert claims == []
        assert len(notes) == 1 and "absolute" in notes[0] and repr(raw_path) in notes[0]
        assert lost == 1


def test_semgrep_import_still_reports_a_bad_shape_in_a_result_whose_path_is_unusable():
    # Dropping the claim must not skip the checks: a malformed field in that same result is
    # still a named shape error, not a result quietly passed over.
    payload = {"results": [{"check_id": "a", "path": "/etc/passwd", "start": {"line": 1}, "end": {"line": 1},
                            "extra": {"message": 7}}]}
    with pytest.raises(AdapterError, match="extra.message as a int"):
        import_semgrep_results(payload)


def test_semgrep_import_docstring_states_what_happens_to_an_unusable_path():
    doc = " ".join((import_semgrep_results.__doc__ or "").split())
    assert "neither rewritten nor recorded" in doc and "a claim location must be a relative path" in doc


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
    rules, commit = pinned_rules_repo(tmp_path, symlinks={"escape": ".."})
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["escape"]}})
    with pytest.raises(AdapterError, match="outside the pinned checkout"):
        SemgrepAdapter().prepare(spec, tmp_path / "cache")


def test_semgrep_prepare_refuses_a_rule_symlink_resolving_outside_the_checkout(tmp_path):
    # The ruleset path itself is fine; the symlink sits inside it and Semgrep would load it,
    # since read_config_folder keeps `is_config_suffix(l) and l.is_file()` and is_file() follows
    # the link. Without this refusal a rule file the pinned commit does not hold would be hashed
    # into the recorded tree hash and scanned with.
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "evil.yaml").write_text(RULE_YAML, encoding="utf-8")
    rules, commit = pinned_rules_repo(tmp_path, symlinks={"python/linked.yaml": "../../../outside/evil.yaml"})
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    with pytest.raises(AdapterError, match="outside the pinned checkout") as raised:
        SemgrepAdapter().prepare(spec, tmp_path / "cache")
    assert "python/linked.yaml" in str(raised.value) and "outside/evil.yaml" in str(raised.value)


def test_semgrep_prepare_hashes_a_rule_symlink_that_stays_inside_the_checkout(tmp_path):
    # A rule file symlinked to another file in the same pinned commit is content that commit
    # holds, and Semgrep loads it under the path the link occupies. Refusing it refused
    # legitimate rulesets; it is counted and hashed by the content it resolves to, which is why
    # the checkout carrying the link and the one carrying a plain copy record the same hash.
    linked, commit_link = pinned_rules_repo(tmp_path, name="linked-repo",
                                            symlinks={"python/linked.yaml": "shell.yaml"})
    copied, commit_copy = pinned_rules_repo(tmp_path, name="copied-repo",
                                            extra_files={"python/linked.yaml": RULE_YAML})
    prepared_link = SemgrepAdapter().prepare(
        SystemSpec("s", "semgrep", {"ruleset": {"url": str(linked), "commit": commit_link, "paths": ["python"]}}),
        tmp_path / "cache")
    prepared_copy = SemgrepAdapter().prepare(
        SystemSpec("s", "semgrep", {"ruleset": {"url": str(copied), "commit": commit_copy, "paths": ["python"]}}),
        tmp_path / "cache")
    assert (Path(prepared_link["ruleset_root"]) / "python" / "linked.yaml").is_symlink()
    assert prepared_link["ruleset"]["rule_files"] == 2
    assert prepared_link["ruleset"]["tree_hash"] == prepared_copy["ruleset"]["tree_hash"]


def test_semgrep_prepare_ignores_a_symlink_semgrep_would_not_load_as_a_rule_file(tmp_path):
    # Real rules repositories carry symlinks that are not rule files. read_config_folder keeps
    # only `is_config_suffix(l) and l.is_file()`, so Semgrep opens none of these three, and
    # refusing them refused whole rulesets over files no scan ever reads.
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "NOTES.md").write_text("notes\n", encoding="utf-8")
    (tmp_path / "outside" / "more-rules").mkdir()
    rules, commit = pinned_rules_repo(tmp_path, symlinks={
        # Not a rule-file suffix, a directory once followed, and a target that is not there.
        "python/README.md": "../../../outside/NOTES.md",
        "python/dir.yaml": "../../../outside/more-rules",
        "python/missing.yaml": "../../../outside/absent.yaml",
    })
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    prepared = SemgrepAdapter().prepare(spec, tmp_path / "cache")
    root = Path(prepared["ruleset_root"])
    assert (root / "python" / "README.md").is_symlink() and (root / "python" / "dir.yaml").is_symlink()
    # Only shell.yaml is a rule file Semgrep would load, so only shell.yaml is in the inventory.
    assert prepared["ruleset"]["rule_files"] == 1


def test_semgrep_prepare_docstring_states_the_symlink_rule_and_the_error_type(tmp_path):
    doc = " ".join((SemgrepAdapter.prepare.__doc__ or "").split())
    assert "refused only when Semgrep would load it as a rule file" in doc
    assert "resolves outside the pinned checkout root" in doc
    assert "resolves inside the checkout is kept and hashed by the content it resolves to" in doc
    assert "Every other symlink is ignored" in doc
    assert "Every failure raised here is an ``AdapterError``" in doc


def test_semgrep_prepare_wraps_a_short_commit_in_an_adapter_error(tmp_path):
    # MaterializationError is not an AdapterError, and prepare() is contracted to raise the
    # latter, so a commit git never sees must still arrive as an AdapterError.
    rules, _ = pinned_rules_repo(tmp_path)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": "abc123", "paths": ["python"]}})
    with pytest.raises(AdapterError, match="ruleset could not be materialized") as raised:
        SemgrepAdapter().prepare(spec, tmp_path / "cache")
    # The original message survives inside the wrapper.
    assert "full 40-hex SHA" in str(raised.value)


def test_semgrep_prepare_wraps_an_unreachable_ruleset_url_in_an_adapter_error(tmp_path):
    # A local path that is not a repository: the fetch fails without touching the network.
    missing = tmp_path / "no-such-repo"
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(missing), "commit": "a" * 40, "paths": ["python"]}})
    with pytest.raises(AdapterError, match="ruleset could not be materialized") as raised:
        SemgrepAdapter().prepare(spec, tmp_path / "cache")
    assert "git fetch" in str(raised.value)


def test_semgrep_prepare_wraps_a_modified_cache_entry_in_an_adapter_error(tmp_path):
    # The cache is immutable, so a checkout someone edited is refused on the next preparation.
    rules, commit = pinned_rules_repo(tmp_path)
    spec = SystemSpec("s", "semgrep", {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    prepared = SemgrepAdapter().prepare(spec, tmp_path / "cache")
    (Path(prepared["ruleset_root"]) / "python" / "extra.yaml").write_text(RULE_YAML, encoding="utf-8")
    with pytest.raises(AdapterError, match="ruleset could not be materialized") as raised:
        SemgrepAdapter().prepare(spec, tmp_path / "cache")
    assert "local modifications" in str(raised.value)


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


def test_semgrep_version_failure_leaves_no_artifacts_for_the_next_attempt(tmp_path):
    # The two claimed files stayed behind empty when the probe failed, so a second attempt in
    # the same raw directory reported a create-only collision instead of the failure that
    # actually stopped the first one.
    raw = tmp_path / "raw"
    raw.mkdir()
    binary = str(failing_version_semgrep(tmp_path))
    with pytest.raises(AdapterError, match="semgrep --version failed") as first:
        semgrep_version(binary, raw)
    assert "unknown option" in str(first.value)
    assert sorted(path.name for path in raw.iterdir()) == []
    with pytest.raises(AdapterError, match="semgrep --version failed") as second:
        semgrep_version(binary, raw)
    assert "already exists" not in str(second.value)


def test_semgrep_version_failure_keeps_a_file_it_did_not_create(tmp_path):
    # Cleanup covers only what this call claimed: an earlier attempt's recorded output is
    # evidence, and the create-only refusal is what protects it.
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "semgrep-version.stderr.txt").write_text("an earlier run\n", encoding="utf-8")
    with pytest.raises(AdapterError, match="already exists and semgrep raw output files are create-only"):
        semgrep_version(str(failing_version_semgrep(tmp_path)), raw)
    assert (raw / "semgrep-version.stderr.txt").read_text(encoding="utf-8") == "an earlier run\n"
    # The file this call did create before the refusal is gone, so a retry reports its own cause.
    assert not (raw / "semgrep-version.txt").exists()


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


@pytest.mark.parametrize("diagnostic, reason_in_message", [
    ("Rule timeout on app.py", True),
    ("   ", False),
    ("", False),
])
def test_semgrep_zero_exit_with_fatal_diagnostics_reports_the_shared_message_shape(tmp_path, diagnostic,
                                                                                   reason_in_message):
    # This partial branch reported the first diagnostic and nothing else, so an empty diagnostic
    # left an empty error message, and the stderr tail every other failure path carries was
    # dropped exactly where the JSON said least.
    payload = json.dumps({"version": "9.9.9", "paths": {"scanned": ["app.py"]},
                          "errors": [{"level": "error", "message": diagnostic}],
                          "results": [{"check_id": "probe.rule", "path": "app.py", "start": {"line": 1},
                                       "end": {"line": 1},
                                       "extra": {"message": "finding", "severity": "WARNING", "metadata": {}}}]})
    outcome, _ = scan_with_fake(tmp_path, payload, 0)
    assert outcome.status == "partial" and outcome.exit_code == 0
    assert outcome.error["code"] == "scan_errors"
    message = outcome.error["message"]
    assert message.startswith("semgrep exited 0 after scanning 1 paths with 1 error-level diagnostics")
    assert message.endswith("; stderr: ")
    assert ("reason: Rule timeout on app.py" in message) is reason_in_message
    assert [claim["native_rule_id"] for claim in outcome.claims] == ["probe.rule"]


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


# --- import loss ------------------------------------------------------------------------


UNPLACEABLE = {"check_id": "probe.rule", "path": "/etc/passwd", "start": {"line": 1}, "end": {"line": 1},
               "extra": {"message": "a finding ScanEval cannot place", "severity": "WARNING", "metadata": {}}}
PLACEABLE = {"check_id": "probe.rule", "path": "app.py", "start": {"line": 1}, "end": {"line": 1},
             "extra": {"message": "a finding ScanEval can place", "severity": "WARNING", "metadata": {}}}


def test_a_lost_semgrep_result_forces_partial_with_unresolved_bundles_and_an_import_loss_error(tmp_path):
    """A result that yielded no claim is a finding Semgrep reported and ScanEval did not deliver.

    It used to be dropped with a note while the scan still reported success with resolved
    bundles, so a run that lost a finding during import could still earn silence credit.
    """
    payload = {"version": "9.9.9", "paths": {"scanned": ["app.py"]}, "errors": [],
               "results": [PLACEABLE, UNPLACEABLE]}
    outcome, _ = scan_with_fake(tmp_path, json.dumps(payload), 0)

    assert outcome.status == "partial" and outcome.bundles_resolved is False
    assert outcome.error["code"] == "import_loss"
    assert "1 semgrep result(s) could not be imported" in outcome.error["message"]
    assert "/etc/passwd" in outcome.error["message"]
    assert [claim["claim_id"] for claim in outcome.claims] == ["c1"]
    assert any("Import loss: 1 result(s)" in note for note in outcome.notes)


def test_an_import_that_lost_nothing_stays_a_success_with_resolved_bundles(tmp_path):
    """The control: every reported result became a claim, so nothing about the run is degraded."""
    payload = {"version": "9.9.9", "paths": {"scanned": ["app.py"]}, "errors": [], "results": [PLACEABLE]}
    outcome, _ = scan_with_fake(tmp_path, json.dumps(payload), 0)

    assert outcome.status == "success" and outcome.bundles_resolved is True
    assert outcome.error is None and [claim["claim_id"] for claim in outcome.claims] == ["c1"]
    assert not any("Import loss" in note for note in outcome.notes)


def test_import_loss_travels_with_a_failure_the_run_already_had(tmp_path):
    """A run that already failed keeps its own error code and names the loss beside it.

    The loss still clears ``bundles_resolved``, so the scoring contract refuses quiet credit
    whichever branch the outcome took.
    """
    payload = {"version": "9.9.9", "paths": {"scanned": ["app.py"]},
               "errors": [{"level": "error", "message": "Rule timeout on app.py"}],
               "results": [PLACEABLE, UNPLACEABLE]}
    outcome, _ = scan_with_fake(tmp_path, json.dumps(payload), 0)

    assert outcome.status == "partial" and outcome.bundles_resolved is False
    assert outcome.error["code"] == "scan_errors"
    assert "Rule timeout on app.py" in outcome.error["message"]
    assert "1 semgrep result(s) could not be imported" in outcome.error["message"]


def test_the_semgrep_loss_contract_matches_the_harness_one():
    """Both importers report loss the same way, so the caller degrades both the same way."""
    assert semgrep_module.SemgrepImport._fields == ("claims", "notes", "lost")
    doc = " ".join((import_semgrep_results.__doc__ or "").split())
    assert "it is counted in ``lost``" in doc
    assert "neither completeness nor quiet credit" in doc


# --- PR mode ----------------------------------------------------------------------------
#
# A PR request names the two commits of a history the runner builds in the scanner's workspace,
# and the scan is Semgrep's own diff scan over it. The workspaces below are built the same way:
# a base commit, a head commit, HEAD at head, a clean status, and a neutral identity.


def pr_workspace(tmp_path: Path, base: dict, head: dict, *, name: str = "pr-source") -> tuple[Path, str, str]:
    """A workspace holding a base commit and a head commit, and the two commit ids.

    *base* and *head* map a path to its text. In *head* a value of ``None`` deletes the path, and a
    path *head* does not name is left as the base commit had it.
    """
    workspace = tmp_path / name
    workspace.mkdir()
    _git("init", "-q", "-b", "main", cwd=workspace)

    def commit(files: dict, message: str) -> str:
        for relative, content in files.items():
            target = workspace / relative
            if content is None:
                target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        _git("add", "-A", "-f", ".", cwd=workspace)
        _git("commit", "-q", "--no-verify", "--allow-empty", "-m", message, cwd=workspace)
        return _git("rev-parse", "HEAD", cwd=workspace)

    return workspace, commit(base, "base"), commit(head, "head")


def pr_scan_request(base: str, head: str) -> dict:
    """The scan request the runner would build for a PR input, checked against the request contract."""
    prepared = PreparedInput("pr-fixture", Path("."), "sha256:" + "0" * 64, ("python",), {}, mode="pr",
                             pr={"base_commit": base, "head_commit": head})
    return build_request("run-pr", prepared, SystemSpec("semgrep-pr", "semgrep", {}), timeout_seconds=300,
                         trace_mode="off", pr={"base": base, "head": head})


def working_tree(workspace: Path) -> dict[str, bytes]:
    """Every file outside ``.git`` and its bytes, for comparing a workspace before and after a scan."""
    return {path.relative_to(workspace).as_posix(): path.read_bytes()
            for path in sorted(workspace.rglob("*")) if path.is_file() and ".git" not in path.relative_to(workspace).parts}


def scan_pr_with_fake(tmp_path: Path, stdout_text: str, exit_code: int, *, request=None, config=None,
                      base=None, head=None):
    """One PR-mode scan whose scanner is the stand-in binary, over a two-commit workspace."""
    workspace, base_commit, head_commit = pr_workspace(
        tmp_path, base or {"app.py": "import subprocess\n"}, head or {"app.py": "import subprocess\nimport os\n"})
    raw = tmp_path / "raw"
    raw.mkdir()
    settings = {"binary": str(fake_semgrep(tmp_path, stdout_text, exit_code))}
    settings.update(config or {})
    outcome = SemgrepAdapter().scan(
        request=request or pr_scan_request(base_commit, head_commit), source_dir=workspace, raw_dir=raw,
        spec=SystemSpec("semgrep-fake", "semgrep", settings), preparation=fake_preparation(tmp_path),
        timeout_seconds=60, trace_mode="off", trace_dir=None)
    return outcome, raw, workspace, base_commit, head_commit


def prepared_semgrep(tmp_path: Path) -> tuple[SystemSpec, dict]:
    """A system over the offline one-rule ruleset, and its preparation record."""
    rules, commit = pinned_rules_repo(tmp_path)
    spec = SystemSpec("semgrep-pr", "semgrep",
                      {"ruleset": {"url": str(rules), "commit": commit, "paths": ["python"]}})
    return spec, SemgrepAdapter().prepare(spec, tmp_path / "cache")


def scan_pr(tmp_path: Path, workspace: Path, base: str, head: str, spec: SystemSpec, preparation: dict):
    raw = tmp_path / "raw"
    raw.mkdir()
    outcome = SemgrepAdapter().scan(request=pr_scan_request(base, head), source_dir=workspace, raw_dir=raw,
                                    spec=spec, preparation=preparation, timeout_seconds=300, trace_mode="off",
                                    trace_dir=None)
    text = (raw / "semgrep.json").read_text(encoding="utf-8")
    return outcome, (json.loads(text) if text else None)


def test_semgrep_declares_pr_beside_full():
    assert SemgrepAdapter.scan_modes == frozenset({"full", "pr"})


def test_semgrep_full_mode_argv_is_what_it_always_was_and_carries_no_baseline(tmp_path):
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})
    outcome, _ = scan_with_fake(tmp_path, payload, 0)
    binary = str(tmp_path / "fake-semgrep")
    assert outcome.command == [binary, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
                               "--timeout", "30", "--jobs", "1", f"--config={tmp_path / 'rules' / 'python'}", "."]
    assert not any("baseline" in word for word in outcome.command)
    assert not any("PR mode" in note for note in outcome.notes)


def test_semgrep_pr_mode_adds_only_the_baseline_option_to_the_full_argv(tmp_path):
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})
    outcome, raw, _workspace, base, _head = scan_pr_with_fake(tmp_path, payload, 0)
    binary = str(tmp_path / "fake-semgrep")
    assert outcome.command == [binary, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
                               "--timeout", "30", "--jobs", "1", f"--baseline-commit={base}",
                               f"--config={tmp_path / 'rules' / 'python'}", "."]
    assert outcome.status == "success" and outcome.claims == []
    assert any(note.startswith("PR mode: Semgrep ran with --baseline-commit") for note in outcome.notes)
    assert (raw / "semgrep.json").read_text(encoding="utf-8") == payload


def test_semgrep_pr_mode_keeps_import_loss_accounting(tmp_path):
    """A result the importer cannot place is a finding Semgrep reported, in a PR review as in a full scan."""
    payload = {"version": "9.9.9", "paths": {"scanned": ["app.py"]}, "errors": [], "results": [PLACEABLE, UNPLACEABLE]}
    outcome, *_ = scan_pr_with_fake(tmp_path, json.dumps(payload), 0)
    assert outcome.status == "partial" and outcome.bundles_resolved is False
    assert outcome.error["code"] == "import_loss"
    assert "1 semgrep result(s) could not be imported" in outcome.error["message"]
    assert [claim["claim_id"] for claim in outcome.claims] == ["c1"]


def test_semgrep_pr_mode_keeps_the_failure_classification_of_a_nonzero_exit(tmp_path):
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": []},
                          "errors": [{"level": "error", "message": "baseline commit is not in this repository"}]})
    outcome, *_ = scan_pr_with_fake(tmp_path, payload, 2)
    assert outcome.status == "error" and outcome.exit_code == 2 and outcome.claims == []
    assert outcome.error["code"] == "exit_2"
    assert "baseline commit is not in this repository" in outcome.error["message"]


def test_semgrep_pr_mode_notes_that_a_timeout_can_leave_the_tree_at_the_base_commit(tmp_path, monkeypatch):
    workspace, base, head = pr_workspace(tmp_path, {"app.py": "1\n"}, {"app.py": "2\n"})
    raw = tmp_path / "raw"
    raw.mkdir()
    real_run = semgrep_module.run_command

    def killed_scan(argv, **kwargs):
        if "scan" in argv:
            return CommandResult(list(argv), None, True, 61.0, kwargs["stdout_path"], kwargs["stderr_path"])
        return real_run(argv, **kwargs)

    monkeypatch.setattr(semgrep_module, "run_command", killed_scan)
    spec = SystemSpec("semgrep-fake", "semgrep", {"binary": str(fake_semgrep(tmp_path, "{}", 0))})
    outcome = SemgrepAdapter().scan(request=pr_scan_request(base, head), source_dir=workspace, raw_dir=raw,
                                    spec=spec, preparation=fake_preparation(tmp_path), timeout_seconds=60,
                                    trace_mode="off", trace_dir=None)
    assert outcome.status == "timeout" and outcome.timed_out is True and outcome.claims == []
    assert any("leaves the tree at the base commit" in note for note in outcome.notes)


# --- PR mode: what is refused before anything runs --------------------------------------


@pytest.mark.parametrize("mode", ["batch", "bootstrap", "PR", ""])
def test_semgrep_refuses_a_mode_it_does_not_implement_and_runs_nothing(tmp_path, mode):
    request = {"input": {"mode": mode}}
    with pytest.raises(AdapterError, match="semgrep does not implement scan mode"):
        scan_pr_with_fake(tmp_path, "{}", 0, request=request)
    assert list((tmp_path / "raw").iterdir()) == [], "no output file was claimed and no process ran"


def test_semgrep_refuses_a_pr_request_that_does_not_name_two_commits_and_runs_nothing(tmp_path):
    with pytest.raises(AdapterError, match="input.pr is absent"):
        scan_pr_with_fake(tmp_path, "{}", 0, request={"input": {"mode": "pr"}})
    assert list((tmp_path / "raw").iterdir()) == []


def test_semgrep_refuses_a_full_request_that_carries_a_pr_rather_than_ignoring_it(tmp_path):
    request = {"input": {"mode": "full", "pr": {"base": "a" * 40, "head": "b" * 40}}}
    with pytest.raises(AdapterError, match="full-mode request that also carries input.pr"):
        scan_pr_with_fake(tmp_path, "{}", 0, request=request)
    assert list((tmp_path / "raw").iterdir()) == []


def test_semgrep_refuses_a_pr_request_over_a_workspace_that_does_not_hold_its_history(tmp_path):
    """Semgrep would otherwise fail inside its own git call, or scan a tree the request does not describe."""
    workspace, base, head = pr_workspace(tmp_path, {"app.py": "1\n"}, {"app.py": "2\n"})
    _git("checkout", "-q", "--detach", base, cwd=workspace)
    raw = tmp_path / "raw"
    raw.mkdir()
    spec = SystemSpec("semgrep-fake", "semgrep", {"binary": str(fake_semgrep(tmp_path, "{}", 0))})
    with pytest.raises(AdapterError, match="not at the request's head commit"):
        SemgrepAdapter().scan(request=pr_scan_request(base, head), source_dir=workspace, raw_dir=raw, spec=spec,
                              preparation=fake_preparation(tmp_path), timeout_seconds=60, trace_mode="off",
                              trace_dir=None)
    assert list(raw.iterdir()) == []


class HeldBackend:
    """A backend that holds every command it is handed and never runs one."""

    def __init__(self, name: str):
        self.name = name
        self.commands: list[list[str]] = []

    def run_command(self, argv, **kwargs):
        self.commands.append(list(argv))
        return CommandResult(list(argv), 0, False, 0.0, kwargs["stdout_path"], kwargs["stderr_path"])


def test_semgrep_pr_mode_is_refused_under_the_oci_backend_with_the_reason_recorded(tmp_path):
    """The container mounts the source read-only and Semgrep's baseline scan rewrites the tree in place."""
    workspace, base, head = pr_workspace(tmp_path, {"app.py": "1\n"}, {"app.py": "2\n"})
    raw = tmp_path / "raw"
    raw.mkdir()
    held = HeldBackend("oci")
    with base_module.routed_through(held):
        outcome = SemgrepAdapter().scan(
            request=pr_scan_request(base, head), source_dir=workspace, raw_dir=raw,
            spec=SystemSpec("semgrep-oci", "semgrep", {}), preparation=fake_preparation(tmp_path),
            timeout_seconds=60, trace_mode="off", trace_dir=None)
    assert outcome.status == "unsupported" and outcome.claims == [] and outcome.command == []
    assert outcome.error["code"] == "unsupported_mode"
    assert "oci backend" in outcome.error["message"] and "read-only" in outcome.error["message"]
    assert "--baseline-commit" in outcome.error["message"]
    assert any("stays in the denominator" in note for note in outcome.notes)
    assert held.commands == [] and list(raw.iterdir()) == [], "nothing ran and nothing was claimed"


def test_semgrep_full_mode_still_runs_under_oci_and_only_pr_is_refused(tmp_path):
    """The refusal is about the mode, not the backend: a full scan goes through the backend as before."""
    workspace, base, head = pr_workspace(tmp_path, {"app.py": "1\n"}, {"app.py": "2\n"})
    raw = tmp_path / "raw"
    raw.mkdir()
    payload = json.dumps({"version": "9.9.9", "results": [], "paths": {"scanned": ["app.py"]}, "errors": []})

    class ScanningBackend(HeldBackend):
        def run_command(self, argv, **kwargs):
            result = super().run_command(argv, **kwargs)
            kwargs["stdout_path"].write_text("9.9.9\n" if "--version" in argv else payload, encoding="utf-8")
            return result

    held = ScanningBackend("oci")
    with base_module.routed_through(held):
        outcome = SemgrepAdapter().scan(
            request={}, source_dir=workspace, raw_dir=raw, spec=SystemSpec("semgrep-oci", "semgrep", {}),
            preparation=fake_preparation(tmp_path), timeout_seconds=60, trace_mode="off", trace_dir=None)
    assert outcome.status == "success"
    assert [argv[0] for argv in held.commands] == ["semgrep", "semgrep"]
    assert not any("--baseline-commit" in word for argv in held.commands for word in argv)


# --- PR mode: the real binary -----------------------------------------------------------


@semgrep_required
def test_semgrep_pr_mode_reports_only_the_new_finding_and_never_scans_an_unchanged_file(tmp_path):
    """The workspace holds two findings at base and a third added by the change.

    ``old.py`` is touched but keeps its finding; ``keep.py`` is not touched at all. Only the
    finding the change introduced is reported, ``keep.py`` is neither scanned nor reported, and
    the workspace is exactly as it was handed over once Semgrep's in-place baseline scan is done.
    """
    spec, preparation = prepared_semgrep(tmp_path)
    workspace, base, head = pr_workspace(
        tmp_path,
        {"old.py": VULNERABLE_PY, "keep.py": VULNERABLE_PY, "README.md": "# readme\n"},
        {"new.py": VULNERABLE_PY, "old.py": "# a comment that shifts the finding down\n" + VULNERABLE_PY})
    before = working_tree(workspace)

    outcome, payload = scan_pr(tmp_path, workspace, base, head, spec, preparation)

    assert outcome.status == "success", outcome.error
    assert [(claim["primary_location"]["path"], claim["primary_location"]["start_line"])
            for claim in outcome.claims] == [("new.py", 3)]
    assert [claim["native_rule_id"] for claim in outcome.claims] == ["python.probe.subprocess-shell"]
    assert outcome.bundles_resolved is True
    assert [result["path"] for result in payload["results"]] == ["new.py"]
    assert payload["paths"]["scanned"] == ["new.py", "old.py"], "the unchanged file was not scanned"
    assert "keep.py" not in json.dumps(payload["results"]) and "README.md" not in payload["paths"]["scanned"]
    assert f"--baseline-commit={base}" in outcome.command

    assert working_tree(workspace) == before
    assert _git("rev-parse", "HEAD", cwd=workspace) == head
    assert _git("status", "--porcelain", cwd=workspace) == ""


@semgrep_required
def test_semgrep_pr_mode_reports_the_added_finding_in_a_file_that_already_had_one(tmp_path):
    spec, preparation = prepared_semgrep(tmp_path)
    second = VULNERABLE_PY + "def other(cmd):\n    return subprocess.call(cmd, shell=True)\n"
    workspace, base, head = pr_workspace(tmp_path, {"old.py": VULNERABLE_PY}, {"old.py": second})
    outcome, _payload = scan_pr(tmp_path, workspace, base, head, spec, preparation)
    assert outcome.status == "success", outcome.error
    assert [(claim["primary_location"]["path"], claim["primary_location"]["start_line"])
            for claim in outcome.claims] == [("old.py", 5)]


@semgrep_required
def test_semgrep_pr_mode_does_not_report_a_finding_that_only_moved_with_a_renamed_file(tmp_path):
    spec, preparation = prepared_semgrep(tmp_path)
    workspace, base, head = pr_workspace(tmp_path, {"old.py": VULNERABLE_PY}, {"old.py": None, "moved.py": VULNERABLE_PY})
    outcome, payload = scan_pr(tmp_path, workspace, base, head, spec, preparation)
    assert outcome.status == "success", outcome.error
    assert outcome.claims == []
    assert payload["paths"]["scanned"] == ["moved.py"], "the renamed file was scanned, and its finding matched to base"
