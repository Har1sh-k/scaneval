"""Narrow metadata transformations change only a reviewed, hash-pinned identity leaf."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tomllib

import pytest

from scaneval.contracts import ContractError, canonical_json, canonical_sha256
from scaneval.identity_policy import (MANIFEST_KIND, POLICY_ID, POLICY_VERSION, build_manifest,
                                     inspect_tree, policy_coverage, prepare_metadata_edit,
                                     required_answers, validate_policy)
from scaneval.materialize import MaterializationError


ORIGINAL = "https://github.com/upstream/project"
REPLACEMENT = "https://example.invalid/project"
ROLE_CHECK = "This field is published package metadata; dependencies and runtime code do not read it."


def edit(data: bytes, *, path="package.json", field_path=("homepage",), **changes):
    options = {"path": path, "field_path": field_path,
               "expected_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
               "original": ORIGINAL, "replacement": REPLACEMENT, "role_check": ROLE_CHECK}
    return prepare_metadata_edit(data, **{**options, **changes})


@pytest.mark.parametrize("field_path", [("homepage",), ("repository",), ("repository", "url"),
                                       ("bugs",), ("bugs", "url")])
def test_json_metadata_edits_preserve_dependencies_and_all_unselected_bytes(field_path):
    metadata = ORIGINAL if len(field_path) == 1 else {field_path[1]: ORIGINAL, "type": "git"}
    tree = {"name": "upstream-project", field_path[0]: metadata,
            "dependencies": {"upstream-project": "1.2.3"}, "scripts": {"test": "node test.js"}}
    data = (json.dumps(tree, indent=2) + "\r\n").encode()

    change = edit(data, field_path=field_path)

    assert change.data == data.replace(ORIGINAL.encode(), REPLACEMENT.encode())
    expected = deepcopy(tree)
    if len(field_path) == 1:
        expected[field_path[0]] = REPLACEMENT
    else:
        expected[field_path[0]][field_path[1]] = REPLACEMENT
    assert json.loads(change.data) == expected
    assert change.record["field_path"] == list(field_path) and change.record["redactions"] == 1
    assert change.record["original_sha256"] != change.record["transformed_sha256"]
    assert change.data.count(b"\n") == data.count(b"\n")


@pytest.mark.parametrize("token", [f'"{ORIGINAL}"', f"'{ORIGINAL}'"])
def test_toml_metadata_edits_keep_comments_dependencies_and_table_structure(token):
    data = ("[project]\nname = 'upstream-project'\ndependencies = ['upstream-project>=1']\n"
            "[project.urls]\n# Reviewed public identity metadata\n"
            f"'Issue tracker' = {token} # public support link\n"
            "[tool.runtime]\nendpoint = 'https://service.invalid'\n").encode()

    change = edit(data, path="pyproject.toml", field_path=("project", "urls", "Issue tracker"), raw_token=token)

    assert change.data == data.replace(token.encode(), json.dumps(REPLACEMENT).encode())
    tree = tomllib.loads(data.decode())
    tree["project"]["urls"]["Issue tracker"] = REPLACEMENT
    assert tomllib.loads(change.data.decode()) == tree
    assert change.record["changed_lines"] == [6]
    assert change.data.count(b"\n") == data.count(b"\n")


@pytest.mark.parametrize("path, field_path", [
    ("package.json", ("name",)), ("package.json", ("dependencies", "upstream-project")),
    ("package.json", ("scripts", "test")), ("package.json", ("repository.url",)),
    ("pyproject.toml", ("project", "dependencies")), ("pyproject.toml", ("tool", "runtime", "endpoint")),
    ("config.json", ("homepage",)), ("../package.json", ("homepage",)),
    ("docs//package.json", ("homepage",)), (".github/workflows/package.json", ("homepage",)),
    ("licenses/package.json", ("homepage",)), ("C:/package.json", ("homepage",)),
])
def test_metadata_selectors_cannot_rewrite_dependency_runtime_or_protected_fields(path, field_path):
    with pytest.raises(MaterializationError):
        edit(b"{}", path=path, field_path=field_path)


@pytest.mark.parametrize("data, options, reason", [
    (b'{"homepage": "url"}', {"expected_sha256": "sha256:" + "0" * 64}, "stale metadata edit"),
    (b'{"homepage": "url"}', {"role_check": "\u200b"}, "must state why"),
    (b'{"homepage": "url"}', {"field_path": "homepage"}, "list of string keys"),
    (b'{"homepage": 42}', {}, "reviewed string value"),
    (b'{}', {}, "field.*absent"),
    (b'{"homepage": "url", "homepage": "url"}', {}, "duplicate JSON key"),
    (b'{"homepage": "url", "other": NaN}', {}, "non-JSON constant"),
    (b'{"homepage": "\xff"}', {}, "strict UTF-8"),
    (b'{"homepage": "url"}', {"replacement": "https://safe.invalid\nnext"}, "single-line strings"),
])
def test_unreviewable_metadata_changes_are_refused(data, options, reason):
    with pytest.raises(MaterializationError, match=reason):
        edit(data, **options)


@pytest.mark.parametrize("format_", ["json", "toml"])
def test_duplicate_raw_tokens_are_ambiguous_even_when_one_is_an_allowed_field(format_):
    if format_ == "json":
        data = json.dumps({"homepage": ORIGINAL, "runtime_endpoint": ORIGINAL}).encode()
        kwargs = {}
    else:
        data = f'[project.urls]\nHomepage = "{ORIGINAL}"\n[tool.runtime]\nendpoint = "{ORIGINAL}"\n'.encode()
        kwargs = {"path": "pyproject.toml", "field_path": ("project", "urls", "Homepage")}
    with pytest.raises(MaterializationError, match="ambiguous"):
        edit(data, **kwargs)


def test_unique_token_in_a_comment_is_not_a_selected_toml_field():
    escaped = ORIGINAL.replace("https", r"\u0068ttps")
    data = f'[project.urls]\nHomepage = "{escaped}"\n# "{ORIGINAL}"\n'.encode()
    with pytest.raises(MaterializationError, match="other than the selected metadata leaf"):
        edit(data, path="pyproject.toml", field_path=("project", "urls", "Homepage"))


def test_a_reviewed_toml_token_cannot_include_a_trailing_quoted_comment():
    token = f'"{ORIGINAL}" # "retain this comment"'
    data = f'[project.urls]\nHomepage = {token}\n'.encode()
    with pytest.raises(MaterializationError, match="does not encode the selected string value"):
        edit(data, path="pyproject.toml", field_path=("project", "urls", "Homepage"), raw_token=token)


@pytest.mark.parametrize("field", ["original", "replacement"])
def test_unpaired_unicode_surrogates_cannot_escape_the_strict_utf8_refusal(field):
    data = json.dumps({"homepage": ORIGINAL}).encode()
    with pytest.raises(MaterializationError, match="strict UTF-8 strings"):
        edit(data, **{field: "https://example.invalid/\ud800"})


@pytest.mark.parametrize("data", [None, "text", memoryview(b"text"), 42])
def test_metadata_data_types_have_a_controlled_materialization_refusal(data):
    with pytest.raises(MaterializationError, match="metadata data must be bytes or bytearray"):
        prepare_metadata_edit(data, path="package.json", field_path=["homepage"],
                              expected_sha256="sha256:" + "0" * 64, original=ORIGINAL,
                              replacement=REPLACEMENT, role_check=ROLE_CHECK)


def test_bytearray_metadata_input_is_normalized_without_mutating_it():
    data = bytearray(json.dumps({"homepage": ORIGINAL}).encode())
    before = bytes(data)
    changed = edit(data)
    assert type(changed.data) is bytes and bytes(data) == before


@pytest.mark.parametrize("changes", [
    {"path": "docs/\ud800/package.json"}, {"role_check": "reviewed \ud800"},
    {"path": "pyproject.toml", "field_path": ["project", "urls", "\ud800"]},
    {"raw_token": '"\ud800"'},
])
def test_all_metadata_record_text_has_a_controlled_strict_utf8_refusal(changes):
    data = json.dumps({"homepage": ORIGINAL}).encode()
    with pytest.raises(MaterializationError, match="strict UTF-8 strings"):
        edit(data, **changes)


def test_unrelated_toml_nan_is_preserved_without_falsely_blaming_the_leaf_edit():
    data = f'[project.urls]\nHomepage = "{ORIGINAL}"\n[tool.runtime]\nvalue = nan\n'.encode()
    changed = edit(data, path="pyproject.toml", field_path=["project", "urls", "Homepage"])
    assert changed.data == data.replace(ORIGINAL.encode(), REPLACEMENT.encode())
    assert b"value = nan" in changed.data


def test_a_json_key_token_cannot_be_mistaken_for_the_selected_leaf_value():
    escaped = json.dumps(ORIGINAL).replace("/", r"\/")
    data = f'{{"homepage": {escaped}, "{ORIGINAL}": 42}}'.encode()
    with pytest.raises(MaterializationError, match="other than the selected metadata leaf"):
        edit(data)


def test_reviewed_json_escaped_token_can_be_selected_without_reserializing_the_file():
    token = json.dumps(ORIGINAL).replace("/", r"\/")
    data = f'{{ "homepage" : {token}, "name" : "upstream-project" }}\n'.encode()
    with pytest.raises(MaterializationError, match="exact spelling is required"):
        edit(data)

    change = edit(data, raw_token=token)

    assert change.data == data.replace(token.encode(), json.dumps(REPLACEMENT).encode())


def test_metadata_edits_are_deterministic_and_do_not_mutate_their_configuration():
    data = json.dumps({"homepage": ORIGINAL}).encode()
    fields = ["homepage"]
    first = edit(data, field_path=fields)
    second = edit(data, field_path=fields)
    assert first == second and fields == ["homepage"]


ALIAS = {"category": "target_alias", "value": "CVE-2025-12345", "forms": ["CVE_2025_12345"]}
ADVISORY = {"category": "advisory_url", "value": "https://example.invalid/advisory/12345", "forms": []}


def policy(**changes):
    return {"policy_id": POLICY_ID, "version": POLICY_VERSION, "answer_aliases": [deepcopy(ALIAS)], **changes}


def source(root: Path, files: dict[str, str | bytes]) -> Path:
    tree = root / "source"
    tree.mkdir()
    for relative, content in files.items():
        path = tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
    return tree


def manifest(inspection, *, selected_policy=None, **changes):
    options = {"source_snapshot": {"snapshot_id": "snap-a", "commit": "a" * 40},
               "original_tree_hash": "sha256:" + "1" * 64, "transformed_tree_hash": inspection["tree_hash"],
               "map_sha256": "sha256:" + "2" * 64, "requirements": [ALIAS], "inspection": inspection,
               "edits": [{"path": "docs/title.md", "occurrences": {"Project": 2}}],
               "removals": [{"path": "AGENTS.md", "original_sha256": "sha256:" + "3" * 64}],
               "tool_versions": {"scaneval": "test", "python": "3.11", "git": "test"}}
    return build_manifest(selected_policy if selected_policy is not None else policy(), **{**options, **changes})


def test_explicit_policy_defaults_and_order_are_normalized_without_mutation():
    original = policy(answer_aliases=[ADVISORY, ALIAS], instruction_paths=["docs/INSTRUCTIONS.md", "AGENTS.md"])
    before = deepcopy(original)
    first = validate_policy(original)
    reversed_order = {**original, "answer_aliases": list(reversed(original["answer_aliases"])),
                      "instruction_paths": list(reversed(original["instruction_paths"]))}
    assert first == validate_policy(reversed_order)
    assert first["forbidden_artifacts"] == first["identity_tokens"] == []
    assert original == before


@pytest.mark.parametrize("change", [
    {"version": "2"}, {"policy_id": "anonymous"}, {"unexpected": True},
    {"answer_aliases": [{**ALIAS, "category": []}]},
    {"answer_aliases": [{**ALIAS, "forms": ["same", "SAME"]}]},
    {"answer_aliases": [{**ALIAS, "forms": [ALIAS["value"]]}]},
    {"answer_aliases": [ALIAS, {**ALIAS, "value": ALIAS["value"].lower()}]},
    {"instruction_paths": ["../AGENTS.md"]}, {"instruction_paths": ["docs//rules.md"]},
    {"identity_tokens": ["\ud800"]}, {"forbidden_artifacts": [{"category": "redaction_dictionary"}]},
    {"forbidden_artifacts": [{"category": [], "path": "secret.json"}]},
    {"forbidden_artifacts": [{"category": "evaluator_evidence", "sha256": "invalid"}]},
])
def test_malformed_or_unsupported_strict_policies_are_rejected(change):
    with pytest.raises(ContractError):
        validate_policy(policy(**change))


def test_pack_answer_requirements_cover_target_and_fixed_control_conditions():
    case = {"target": {"snapshot_id": "vulnerable"}, "controls": [{"snapshot_id": "fixed"}],
            "canonical_target": {"aliases": [ALIAS["value"]]},
            "evidence": [{"kind": "vendor_advisory", "reference": ADVISORY["value"]},
                         {"kind": "source_inspection", "reference": "src/app.py"}]}
    pack = {"cases": [case, {**case, "target": {"snapshot_id": "other"}, "controls": [],
                            "canonical_target": {"aliases": ["CVE-2024-99999"]}, "evidence": []}]}
    expected = [ADVISORY, {**ALIAS, "forms": []}]
    assert required_answers(pack, ["vulnerable"]) == required_answers(pack, ["fixed"]) == expected
    assert required_answers(pack, ["unrelated"]) == []


def test_answer_coverage_requires_declared_normalized_forms_even_when_the_tree_is_clean():
    assert policy_coverage(policy(), [ALIAS])["state"] == "available"
    missing_form = policy(answer_aliases=[{**ALIAS, "forms": []}])
    coverage = policy_coverage(missing_form, [ALIAS])
    assert coverage["state"] == "unavailable" and "normalized form" in coverage["reasons"][0]
    assert policy_coverage(policy(answer_aliases=[]), [ALIAS])["state"] == "unavailable"
    assert policy_coverage(None, [ALIAS])["state"] == "unavailable"


def test_retained_source_identity_is_reported_without_invalidating_safe_reduction(tmp_path):
    tree = source(tmp_path, {"src/app.py": "# upstream-project recognizable source\nprint('ok')\n"})
    configured = policy(identity_tokens=["upstream-project"])

    result = inspect_tree(tree, configured, requirements=[ALIAS], required_source_paths=["src/app.py"])

    assert result["validation"] == {"state": "available", "reasons": []}
    assert result["residual_cues"][0]["category"] == "repository_identity"
    assert result["residual_cues"][0]["occurrences"] == 1
    assert result["paths"] == ["src/app.py"] and result["tree_hash"].startswith("sha256:")


def test_short_identity_tokens_use_word_boundaries_for_residual_reporting(tmp_path):
    tree = source(tmp_path, {"src/app.py": "algorithm logo go!\n"})
    result = inspect_tree(tree, policy(identity_tokens=["go"]), requirements=[ALIAS])
    cues = [entry for entry in result["residual_cues"] if entry["category"] == "repository_identity"]
    assert len(cues) == 1 and cues[0]["occurrences"] == 1


@pytest.mark.parametrize("text", ["# cve-2025-12345", "# cVe_2025_12345"])
def test_answer_aliases_in_source_are_residual_and_never_rewritten(tmp_path, text):
    tree = source(tmp_path, {"src/app.py": text})
    before = (tree / "src" / "app.py").read_bytes()

    result = inspect_tree(tree, policy(), requirements=[ALIAS])

    assert result["validation"]["state"] == "unavailable"
    assert result["residual_cues"][0]["category"] == "target_alias"
    assert result["residual_cues"][0]["surface"] == "content"
    assert (tree / "src" / "app.py").read_bytes() == before


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
def test_ascii_answer_aliases_are_detected_in_common_unicode_text_encodings(tmp_path, encoding):
    tree = source(tmp_path, {"src/script.ps1": "prefix cVe-2025-12345 suffix".encode(encoding)})
    result = inspect_tree(tree, policy(), requirements=[ALIAS])
    assert result["validation"]["state"] == "unavailable"
    assert result["residual_cues"][0]["occurrences"] == 1


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
@pytest.mark.parametrize("value, rendered", [("München-advisory", "MÜNCHEN-ADVISORY"),
                                            ("Straße-code", "STRASSE-CODE"),
                                            ("STRASSE-code", "Straße-code")])
def test_unicode_answer_aliases_and_case_expansions_are_detected_in_each_supported_encoding(
        tmp_path, encoding, value, rendered):
    alias = {"category": "answer_alias", "value": value, "forms": []}
    tree = source(tmp_path, {"src/app.py": f"prefix {rendered} suffix".encode(encoding)})
    result = inspect_tree(tree, policy(answer_aliases=[alias]), requirements=[alias])
    assert result["validation"]["state"] == "unavailable"
    assert result["residual_cues"][0]["occurrences"] == 1


def test_answer_aliases_in_paths_also_make_the_condition_unavailable(tmp_path):
    tree = source(tmp_path, {"docs/CVE-2025-12345.md": "redacted prose\n"})
    result = inspect_tree(tree, policy(), requirements=[ALIAS])
    assert result["validation"]["state"] == "unavailable"
    assert result["residual_cues"][0]["surface"] == "path"


def test_missing_alias_declarations_never_become_available_from_a_clean_tree(tmp_path):
    tree = source(tmp_path, {"src/app.py": "print('ok')\n"})
    result = inspect_tree(tree, policy(answer_aliases=[]), requirements=[ALIAS])
    assert result["residual_cues"] == [] and result["validation"]["state"] == "unavailable"
    assert "does not declare required answer" in result["validation"]["reasons"][0]
    legacy = inspect_tree(tree, None, requirements=[ALIAS])
    assert legacy["validation"]["state"] == "unavailable"
    assert "no explicit strict identity policy" in legacy["validation"]["reasons"][0]


@pytest.mark.parametrize("path", ["AGENTS.md", "CLAUDE.local.md", ".cursor/rules/project.mdc",
                                  ".github/copilot-instructions.md", ".assistant/project-rules.txt"])
def test_known_and_configured_instruction_documents_must_be_absent(tmp_path, path):
    tree = source(tmp_path, {path: "Project instructions\n"})
    result = inspect_tree(tree, policy(instruction_paths=[".assistant/project-rules.txt"]), requirements=[ALIAS])
    assert result["validation"]["state"] == "unavailable" and result["instruction_files"] == [path]


def test_assistant_configuration_is_preserved_and_explicit_unsafe_instruction_requests_refuse(tmp_path):
    tree = source(tmp_path, {".claude/settings.json": "{}", ".assistant/hook.py": "print('safe')"})
    basic = inspect_tree(tree, policy(), requirements=[ALIAS])
    assert basic["validation"]["state"] == "available"
    assert basic["assistant_support_files"] == [".claude/settings.json"]
    assert basic["residual_cues"][0]["category"] == "assistant_support_file"
    explicit = inspect_tree(tree, policy(instruction_paths=[".assistant/hook.py"]), requirements=[ALIAS])
    assert explicit["validation"]["state"] == "unavailable"
    assert any("cannot be removed safely" in reason for reason in explicit["validation"]["reasons"])
    assert (tree / ".assistant" / "hook.py").is_file()


@pytest.mark.parametrize("document, category", [
    ({"map_id": "map", "pseudonyms": [], "variants": [], "edits": []}, "redaction_dictionary"),
    ({"policy_id": POLICY_ID, "answer_aliases": []}, "redaction_dictionary"),
    ({"kind": MANIFEST_KIND}, "transformation_manifest"),
    ({"namespace": "test", "pack_id": "p", "snapshots": [], "cases": []}, "evaluator_evidence"),
    ({"targets": [], "controls": [], "provenance": {}, "review_budgets": [], "input_hash": "x"},
     "evaluator_evidence"),
])
def test_evaluator_artifacts_are_detected_after_arbitrary_renaming(tmp_path, document, category):
    tree = source(tmp_path, {"ordinary-file.txt": json.dumps(document)})
    result = inspect_tree(tree, policy(), requirements=[ALIAS])
    assert result["validation"]["state"] == "unavailable"
    assert result["forbidden_artifacts"][0]["category"] == category


def test_declared_evaluator_evidence_is_detected_by_path_or_content_hash(tmp_path):
    content = b"private evaluator evidence without a recognizable JSON structure"
    tree = source(tmp_path, {"notes.txt": "evidence", "renamed.txt": content})
    configured = policy(forbidden_artifacts=[{"category": "evaluator_evidence", "path": "notes.txt"},
                                             {"category": "redaction_dictionary",
                                              "sha256": "sha256:" + hashlib.sha256(content).hexdigest()}])
    result = inspect_tree(tree, configured, requirements=[ALIAS])
    assert result["validation"]["state"] == "unavailable"
    assert {entry["path"] for entry in result["forbidden_artifacts"]} == {"notes.txt", "renamed.txt"}


def test_source_mentioning_a_manifest_kind_is_data_and_never_executed(tmp_path):
    tree = source(tmp_path, {"src/app.py": "raise RuntimeError('identity-transformation-manifest')\n"})
    result = inspect_tree(tree, policy(), requirements=[ALIAS])
    assert result["validation"]["state"] == "available" and result["forbidden_artifacts"] == []


@pytest.mark.parametrize("kind", ["file-link", "directory-link", "root-link", "fifo", "git-file", "git-directory"])
def test_strict_validation_rejects_links_special_files_and_vcs_without_reading_them(tmp_path, kind):
    tree = source(tmp_path, {"src/app.py": "print('ok')"})
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "answer.txt").write_text(ALIAS["value"])
    if kind == "file-link":
        (tree / "escape.txt").symlink_to(outside / "answer.txt")
    elif kind == "directory-link":
        (tree / "escape").symlink_to(outside, target_is_directory=True)
    elif kind == "root-link":
        linked = tmp_path / "linked-source"
        linked.symlink_to(tree, target_is_directory=True)
        tree = linked
    elif kind == "fifo":
        os.mkfifo(tree / "pipe")
    elif kind == "git-file":
        (tree / ".git").write_text("gitdir: /outside/history")
    else:
        (tree / ".git").mkdir()
        (tree / ".git" / "answer.txt").write_text(ALIAS["value"])

    result = inspect_tree(tree, policy(), requirements=[ALIAS])

    assert result["validation"]["state"] == "unavailable" and result["tree_hash"] is None
    assert result["unsafe_entries"] and result["residual_cues"] == []
    assert (outside / "answer.txt").read_text() == ALIAS["value"]


def test_missing_accepted_paths_are_reported_and_traversal_is_rejected(tmp_path):
    tree = source(tmp_path, {"src/app.py": "print('ok')"})
    result = inspect_tree(tree, policy(), requirements=[ALIAS], required_source_paths=["src/missing.py"])
    assert result["validation"]["state"] == "unavailable"
    assert "accepted scoring path src/missing.py is absent" in result["validation"]["reasons"][0]
    with pytest.raises(MaterializationError, match="normalized relative POSIX path"):
        inspect_tree(tree, policy(), requirements=[ALIAS], required_source_paths=["../outside/answer.txt"])


def test_manifest_and_portable_summary_are_deterministic_and_bind_all_provenance(tmp_path):
    tree = source(tmp_path, {"src/app.py": "print('ok')", ".claude/settings.json": "{}"})
    configured = policy(instruction_paths=[".assistant/rules.md"])
    inspection = inspect_tree(tree, configured, requirements=[ALIAS])
    first, summary = manifest(inspection, selected_policy=configured,
                              original_instruction_files=["AGENTS.md", ".claude/settings.json"])
    second, again = manifest(deepcopy(inspection), selected_policy=deepcopy(configured),
                              original_instruction_files=[".claude/settings.json", "AGENTS.md"])

    assert canonical_json(first) == canonical_json(second) and summary == again
    assert summary["manifest_sha256"] == canonical_sha256(first)
    assert summary["validation"] == {"state": "available", "reasons": []}
    assert first["instruction_files"] == [
        {"path": ".assistant/rules.md", "disposition": "absent"},
        {"path": ".claude/settings.json", "disposition": "retained"},
        {"path": "AGENTS.md", "disposition": "removed"}]
    assert summary["counts"]["changed_files"] == 1 and summary["counts"]["removed_files"] == 1
    assert summary["counts"]["redactions"] == 2
    assert summary["counts"]["instruction_files_removed"] == summary["counts"]["instruction_files_retained"] == 1
    assert "CVE-2025-12345" not in canonical_json(summary)
    assert "exported_at" not in first and "created_at" not in first


@pytest.mark.parametrize("change", ["map", "alias-form", "tool-version", "source-snapshot", "tree"])
def test_manifest_identity_changes_invalidate_stale_bindings(tmp_path, change):
    tree = source(tmp_path, {"src/app.py": "print('ok')"})
    inspection = inspect_tree(tree, policy(), requirements=[ALIAS])
    original, summary = manifest(inspection)
    configured, options = policy(), {}
    if change == "map":
        options["map_sha256"] = "sha256:" + "4" * 64
    elif change == "alias-form":
        configured["answer_aliases"][0]["forms"].append("CVE202512345")
    elif change == "tool-version":
        options["tool_versions"] = {"scaneval": "next"}
    elif change == "source-snapshot":
        options["source_snapshot"] = {"snapshot_id": "snap-other", "commit": "b" * 40}
    else:
        options["transformed_tree_hash"] = "sha256:" + "5" * 64
    changed, other = manifest(inspection, selected_policy=configured, **options)
    assert changed != original and other["manifest_sha256"] != summary["manifest_sha256"]
    if change == "tree":
        assert other["validation"]["state"] == "unavailable"


def test_a_legacy_removal_only_export_cannot_claim_the_strict_condition(tmp_path):
    tree = source(tmp_path, {"src/app.py": "print('ok')"})
    inspection = inspect_tree(tree, None, requirements=[ALIAS])
    record, summary = build_manifest(
        None, source_snapshot={"snapshot_id": "snap-a", "commit": "a" * 40},
        original_tree_hash="sha256:" + "1" * 64, transformed_tree_hash=inspection["tree_hash"],
        map_sha256="sha256:" + "2" * 64, requirements=[ALIAS], inspection=inspection,
        edits=[], removals=[], tool_versions={"scaneval": "test"})
    assert record["validation"]["state"] == summary["validation"]["state"] == "unavailable"
    assert summary["policy_id"] is None and "no explicit strict identity policy" in summary["validation"]["reasons"][0]


def test_new_alias_requirements_cannot_reuse_an_inspection_of_the_same_tree_under_old_policy(tmp_path):
    new_alias = {"category": "target_alias", "value": "CVE-2024-99999", "forms": []}
    tree = source(tmp_path, {"src/app.py": f"# {new_alias['value']}\n"})
    old = inspect_tree(tree, policy(), requirements=[ALIAS])
    assert old["validation"]["state"] == "available"
    changed = policy(answer_aliases=[ALIAS, new_alias])

    _, summary = manifest(old, selected_policy=changed, requirements=[ALIAS, new_alias])

    assert summary["validation"]["state"] == "unavailable"
    assert "the export was inspected under a different identity policy" in summary["validation"]["reasons"]
    assert "the export was inspected against different answer requirements" in summary["validation"]["reasons"]


def test_an_unavailable_inspection_is_never_silently_upgraded_from_an_empty_reason_list(tmp_path):
    tree = source(tmp_path, {"src/app.py": "print('ok')"})
    inspection = inspect_tree(tree, policy(), requirements=[ALIAS])
    inspection["validation"] = {"state": "unavailable", "reasons": []}
    _, summary = manifest(inspection)
    assert summary["validation"]["state"] == "unavailable"
    assert "did not establish strict identity availability" in summary["validation"]["reasons"][0]


def test_changed_accepted_source_paths_cannot_reuse_a_stale_tree_inspection(tmp_path):
    tree = source(tmp_path, {"src/app.py": "print('ok')"})
    old = inspect_tree(tree, policy(), requirements=[ALIAS], required_source_paths=["src/app.py"])
    _, expected = manifest(old, required_source_paths=["src/app.py"])
    _, changed = manifest(old, required_source_paths=["src/missing.py"])
    assert expected["validation"]["state"] == "available"
    assert changed["validation"]["state"] == "unavailable"
    assert changed["config_sha256"] != expected["config_sha256"]
    assert "the export was inspected against different accepted scoring paths" in changed["validation"]["reasons"]
