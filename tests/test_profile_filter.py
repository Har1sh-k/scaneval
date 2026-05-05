"""Tests for the --profile filter in scripts/run.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from run import is_agentic_case


def test_default_is_agentic_when_field_missing():
    assert is_agentic_case({"id": "X", "caseType": "synthetic_vulnerable"}) is True


def test_explicit_agentic_false():
    assert is_agentic_case({"id": "X", "agentic": False}) is False


def test_explicit_agentic_true():
    assert is_agentic_case({"id": "X", "agentic": True}) is True
