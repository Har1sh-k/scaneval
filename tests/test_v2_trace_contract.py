"""The TypeScript emitter's shared fixture must satisfy the wire schema."""

from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema/v2/trace-event.schema.json").read_text())
FIXTURE = json.loads((ROOT / "schema/v2/fixtures/trace-event-v2.json").read_text())


def test_shared_emitter_fixture_conforms_to_wire_schema():
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    assert not list(validator.iter_errors(FIXTURE))
    # jsonschema's date-time format checker is an optional extra. Also check
    # the actual emitted timestamp without adding that extra to this package.
    assert datetime.fromisoformat(FIXTURE["timestamp"]).tzinfo is not None


@pytest.mark.parametrize("key,value", [
    ("duration_ms", -1),
    ("type", "toString"),
    ("capture_status", "pretend_complete"),
    ("sequence", -1),
    ("metadata", []),
])
def test_wire_schema_rejects_invalid_event_fields(key, value):
    event = deepcopy(FIXTURE)
    event[key] = value
    validator = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
    assert list(validator.iter_errors(event))
