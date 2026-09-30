"""The shared kind mapping: how CWE identities are read out of native text and mapped to kinds.

Both the Semgrep adapter and the SARIF import read CWE ids through :mod:`scaneval.kinds`, so what
a hostile or odd tag can do to it is checked here once. Every string is fabricated.
"""

from __future__ import annotations

import pytest

from scaneval.adapters.semgrep import import_semgrep_results
from scaneval.kinds import cwe_ids


# More digits than int() will read (4300 by default).
LONG_DIGITS = "9" * 5000


def test_cwe_ids_read_both_spellings_once_and_in_the_order_written():
    assert cwe_ids(["CWE-89: SQL Injection", "external/cwe/cwe-089", "cwe-22", "CWE-0078"]) == [
        "CWE-89", "CWE-22", "CWE-78"]
    assert cwe_ids("CWE-79 and CWE-20") == ["CWE-79", "CWE-20"]
    assert cwe_ids([None, 5, "no id here"]) == [] and cwe_ids(None) == []


@pytest.mark.parametrize("text", ["CWE-" + LONG_DIGITS, "external/cwe/cwe-" + LONG_DIGITS,
                                  "CWE-" + "0" * 5000 + "1" + "0" * 9, "CWE-1234567890"],
                         ids=["long", "long-tag", "long-after-zeros", "ten-digits"])
def test_an_id_of_more_than_nine_digits_is_not_a_cwe_and_never_raises(text):
    assert cwe_ids(text) == []
    assert cwe_ids(["CWE-89", text, "CWE-22"]) == ["CWE-89", "CWE-22"]


def test_leading_zeros_are_not_digits_and_nine_digits_are_read():
    assert cwe_ids("CWE-" + "0" * 5000 + "89") == ["CWE-89"]
    assert cwe_ids("CWE-999999999") == ["CWE-999999999"]
    assert cwe_ids("CWE-0") == ["CWE-0"]


def test_the_semgrep_adapter_reads_a_rule_tagged_with_more_digits_than_any_cwe_has():
    payload = {"results": [{
        "check_id": "probe.long-cwe", "path": "src/app.py", "start": {"line": 5}, "end": {"line": 5},
        "extra": {"message": "probe", "metadata": {"cwe": ["CWE-" + LONG_DIGITS, "CWE-78: OS Command Injection"]}}}]}
    imported = import_semgrep_results(payload)
    assert imported.lost == 0
    (claim,) = imported.claims
    assert (claim["native_cwe"], claim["kind"]) == (["CWE-78"], "command_injection")
