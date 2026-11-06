"""Direct Python entry points reject identifiers with trailing unvalidated bytes."""

from types import SimpleNamespace

import pytest

from scaneval import cases
from scaneval.adapters import deepsec, llm_harness
from scaneval.adapters.base import AdapterError, SystemSpec
from scaneval.adapters.pr import pr_range
from scaneval.contracts import ContractError
from scaneval.isolation import IsolationError, resolve_execution


IMAGE = "scanner@sha256:" + "a" * 64
SUFFIXES = ("\n", "\r\n", "\x00", "\u2028", "\u200b")


@pytest.mark.parametrize("field", ("image", "proxy_image", "egress", "credentials", "user"))
@pytest.mark.parametrize("suffix", SUFFIXES)
def test_execution_identifiers_require_the_entire_value(field, suffix):
    block = {
        "backend": "oci", "image": IMAGE, "proxy_image": IMAGE,
        "egress": [{"host": "api.model.example", "port": 443}],
        "credentials": [{"env": "MODEL_KEY", "provider": "model"}],
        "user": "65534:65534",
    }
    if field == "egress":
        block[field][0]["host"] += suffix
    elif field == "credentials":
        block[field][0]["env"] += suffix
    else:
        block[field] += suffix
    with pytest.raises(IsolationError):
        resolve_execution(block, "model_provider_only")


@pytest.mark.parametrize("host", ("api.model.example", "127.0.0.1", "[2001:db8::1]"))
def test_execution_identifiers_preserve_supported_values(host):
    resolved = resolve_execution({
        "backend": "oci", "image": IMAGE, "proxy_image": IMAGE,
        "egress": [{"host": host, "port": 443}],
        "credentials": [{"env": "MODEL_KEY_1", "provider": "model"}],
        "user": "1234:5678",
    }, "model_provider_only")
    assert resolved.image == resolved.proxy_image == IMAGE
    assert resolved.egress == ((host, 443),)
    assert resolved.credentials == (("MODEL_KEY_1", "model"),)
    assert resolved.user == "1234:5678"


@pytest.mark.parametrize("field", ("model", "pi_auth_env", "expected_harness_commit"))
@pytest.mark.parametrize("suffix", SUFFIXES)
def test_image_settings_require_complete_identifiers(field, suffix):
    config = {
        "harness": "securevibes-agent", "model": "openai-codex/gpt-5.4",
        "pi_auth_env": "MODEL_AUTH", "expected_harness_commit": "b" * 40,
    }
    config[field] += suffix
    with pytest.raises(AdapterError):
        llm_harness.image_settings(config)


def test_image_settings_preserve_supported_identifiers():
    resolved = llm_harness.image_settings({
        "harness": "securevibes-agent", "model": "openai-codex/gpt-5.4",
        "pi_auth_env": "MODEL_AUTH_1", "expected_harness_commit": "b" * 40,
    })
    assert resolved["model_id"] == "gpt-5.4"
    assert resolved["auth_env"] == "MODEL_AUTH_1"
    assert resolved["expected_commit"] == "b" * 40


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_deepsec_project_id_rejects_unvalidated_suffix(tmp_path, suffix):
    spec = SystemSpec("system", "deepsec", {
        "deepsec_root": str(tmp_path), "model": "model", "project_id": "project-1" + suffix,
    })
    with pytest.raises(AdapterError, match="project_id"):
        deepsec.settings(spec)


def test_deepsec_project_id_preserves_supported_value(tmp_path):
    spec = SystemSpec("system", "deepsec", {
        "deepsec_root": str(tmp_path), "model": "model", "project_id": "project-1.example",
    })
    assert deepsec.settings(spec).project_id == "project-1.example"


@pytest.mark.parametrize("suffix", SUFFIXES)
@pytest.mark.parametrize("side", ("base", "head"))
@pytest.mark.parametrize("length", (40, 64))
def test_pr_range_rejects_commit_suffixes(side, length, suffix):
    request = {"input": {"mode": "pr", "pr": {"base": "a" * length, "head": "b" * length}}}
    request["input"]["pr"][side] += suffix
    adapter = SimpleNamespace(name="test", scan_modes=("full", "pr"))
    with pytest.raises(AdapterError, match="commit id"):
        pr_range(request, adapter)


@pytest.mark.parametrize("length", (40, 64))
def test_pr_range_preserves_supported_commit_ids(length):
    request = {"input": {"mode": "pr", "pr": {"base": "a" * length, "head": "b" * length}}}
    adapter = SimpleNamespace(name="test", scan_modes=("full", "pr"))
    assert pr_range(request, adapter) == ("a" * length, "b" * length)


@pytest.mark.parametrize("alias", ("CVE-2026-1234", "GHSA-abcd-1234-efgh"))
@pytest.mark.parametrize("suffix", SUFFIXES)
def test_public_aliases_reject_unvalidated_suffixes(alias, suffix):
    assert cases.alias_problem(alias + suffix) is not None


@pytest.mark.parametrize("alias", ("CVE-٢٠٢٦-1234", "CVE-2026-１２３４", "CVE-２０２６-１２３４"))
def test_cve_aliases_require_ascii_digits(alias):
    assert cases.alias_problem(alias) is not None


@pytest.mark.parametrize("alias", ("CVE-2026-1234", "CVE-2026-1234567", "GHSA-abcd-1234-efgh", "INTERNAL-123"))
def test_alias_validation_preserves_supported_values(alias):
    assert cases.alias_problem(alias) is None


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_mechanical_checks_reject_a_tree_hash_suffix_before_reading_source(tmp_path, suffix):
    with pytest.raises(ContractError, match="tree_hash"):
        cases.mechanical_checks({}, "snapshot", tmp_path / "absent", "sha256:" + "a" * 64 + suffix)


@pytest.mark.parametrize("suffix", ("", *SUFFIXES))
def test_checked_tree_hash_never_returns_a_partially_valid_digest(suffix):
    digest = "sha256:" + "a" * 64 + suffix
    case = {"validation": {"check_sets": {"snapshot": {"tree_hash": digest}}, "checks": []}}
    assert cases.checked_tree_hash(case, "snapshot") == (digest if not suffix else None)
