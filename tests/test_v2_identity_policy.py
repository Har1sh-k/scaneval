"""Narrow metadata transformations change only a reviewed, hash-pinned identity leaf."""

from copy import deepcopy
import hashlib
import json
import tomllib

import pytest

from scaneval.identity_policy import prepare_metadata_edit
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
