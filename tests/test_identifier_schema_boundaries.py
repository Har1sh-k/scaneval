"""Whole-document contracts reject suffixes hidden by regex line-end anchors."""

from copy import deepcopy
from importlib.resources import files
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from scaneval import cases
from scaneval.contracts import ContractError, pack_anchor_digest, schema_file, validate_document
from test_v2_cases import make_pack
from test_v2_contracts import scan_request
from test_v2_contracts_21 import run_config
from test_v2_experiment_matrix import declaration
from test_v2_sarif import import_record


HASH = "sha256:" + "a" * 64
ROOT = Path(__file__).resolve().parents[1]


def pack(version):
    document = cases.new_pack("fixture", "boundary-pack", "Boundary fixture")
    document["schema_version"] = version
    document["snapshots"] = [{
        "snapshot_id": "source", "repository": {"url": "https://example.test/source", "name": "source"},
        "commit": "a" * 40, "tree_hash": HASH, "languages": ["python"],
        "workload": "conventional_application", "component_role": "application",
        "license": {"spdx": "MIT", "verified": False, "note": "Fixture only"},
        "reference": "Fabricated revision",
    }]
    document["anchor_sha256"] = pack_anchor_digest(document)
    return document


def mapping():
    return {
        "schema_version": "2.1", "map_id": "identity-map", "map_version": "1",
        "repository": {"url": "https://example.test/source", "name": "source"},
        "pseudonyms": [{"original": "Widget", "replacement": "Sprocket"}],
        "variants": [{"snapshot_id": "source", "commit": "a" * 40, "tree_hash": HASH}],
        "edits": [{"edit_id": "readme-brand", "path": "README.md", "role": "non_runtime_branding",
                   "rationale": "Fixture display text", "replacements": ["Widget"],
                   "expected": [{"snapshot_id": "source", "state": "present", "file_sha256": HASH,
                                 "occurrences": {"Widget": 1}}]}],
        "reviews": [],
    }


def dated_pack():
    document = make_pack()
    document["cases"][0]["evidence"][0]["retrieved"] = "2026-10-22"
    document["anchor_sha256"] = pack_anchor_digest(document)
    return document


def oci_config():
    document = run_config()
    document["systems"][0]["execution"] = {
        "backend": "oci", "image": "scanner@" + HASH, "user": "1000:1000",
        "credentials": [{"env": "SCANNER_API_KEY", "provider": "fixture"}],
    }
    return document


def example(name):
    return json.loads((ROOT / "examples" / (name + ".json")).read_text())


def validator(kind, document):
    schema = files("scaneval").joinpath("schemas", schema_file(kind, document["schema_version"]))
    return Draft202012Validator(json.loads(schema.read_text()))


BOUNDARIES = [
    ("run-config", lambda: run_config(schema_version="2.0"), ("run_id",)),
    ("run-config", lambda: run_config(schema_version="2.0"), ("systems", 0, "system_id")),
    ("run-config", lambda: run_config(schema_version="2.0"), ("inputs", 0, "snapshot_id")),
    ("run-config", run_config, ("run_id",)),
    ("run-config", run_config, ("systems", 0, "system_id")),
    ("run-config", run_config, ("inputs", 0, "input_id")),
    ("run-config", run_config, ("inputs", 0, "snapshot_id")),
    ("run-config", lambda: run_config(inputs=[{"mode": "pr", "change_set_id": "change-source"}]),
     ("inputs", 0, "change_set_id")),
    ("run-config", oci_config, ("systems", 0, "execution", "user")),
    ("run-config", oci_config, ("systems", 0, "execution", "credentials", 0, "env")),
    ("blinding-map", mapping, ("map_id",)),
    ("blinding-map", mapping, ("edits", 0, "edit_id")),
    ("blinding-map", mapping, ("variants", 0, "commit")),
    ("blinding-map", mapping, ("variants", 0, "tree_hash")),
    ("gate-policy", lambda: example("gate-policy"), ("policy_id",)),
    ("gate-policy", lambda: example("gate-policy"), ("regressions", 0, "id")),
    ("aggregation-policy", lambda: example("aggregation-policy"), ("policy_id",)),
    ("experiment-matrix", declaration, ("experiment_id",)),
    ("experiment-matrix", declaration, ("systems", 0, "system_id")),
    ("scan-request", scan_request, ("input", "tree_hash")),
    ("case-pack", dated_pack, ("cases", 0, "evidence", 0, "retrieved")),
    ("import-record", import_record, ("claims", 0, "pointer")),
    ("import-record", import_record, ("claims", 0, "descriptor")),
    ("import-record", import_record, ("execution", "invocations", 0, "pointer")),
]
for version in ("2.0", "2.1"):
    for path in (("namespace",), ("pack_id",), ("snapshots", 0, "snapshot_id"),
                 ("snapshots", 0, "commit"), ("snapshots", 0, "tree_hash")):
        BOUNDARIES.append(("case-pack", lambda version=version: pack(version), path))


@pytest.mark.parametrize("suffix", ["\n", "\r", "\r\n", "\x00", "\u2028", "\u2029"],
                         ids=["lf", "cr", "crlf", "nul", "line-separator", "paragraph-separator"])
@pytest.mark.parametrize("kind,factory,path", BOUNDARIES,
                         ids=[f"{kind}-{index}-" + ".".join(map(str, path))
                              for index, (kind, _, path) in enumerate(BOUNDARIES)])
def test_full_document_boundaries_reject_hidden_suffixes(kind, factory, path, suffix):
    document = factory()
    if path == ("inputs", 0, "input_id"):
        document["inputs"][0]["input_id"] = "input-source"
    # A valid control proves rejection is caused by this field's suffix. Check the
    # schema directly as well, so a Python guard cannot mask a permissive schema.
    validate_document(kind, document)
    schema = validator(kind, document)
    schema.validate(document)
    changed = deepcopy(document)
    parent = changed
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] += suffix
    assert not schema.is_valid(changed)
    with pytest.raises(ContractError):
        validate_document(kind, changed)


def test_boundary_fix_preserves_free_text_and_adapter_regex_configuration():
    document = run_config()
    document["notes"] = ["A multiline\noperator note\n"]
    document["systems"][0]["config"] = {"pattern": "^source$", "prompt": "First line\nSecond line\n"}
    assert validate_document("run-config", document) is document
    validator("run-config", document).validate(document)


def test_sarif_pointer_suffix_does_not_hide_an_unconsumed_line_feed():
    document = import_record()
    document["losses"][0]["pointer"] += "\n"
    assert not validator("import-record", document).is_valid(document)
    with pytest.raises(ContractError):
        validate_document("import-record", document)


def test_sarif_pointer_keeps_characters_allowed_in_arbitrary_property_names():
    document = import_record()
    document["losses"][0]["pointer"] = "/runs/0/properties/free text\r\u2028\x00"
    validator("import-record", document).validate(document)
    assert validate_document("import-record", document) is document
