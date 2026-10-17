"""Shared loss-aware reader for the observer wire contract.

Identity and ordering are producer data: run IDs need not equal the bundle ID,
sequences are producer-local, and repeated event IDs remain separate physical records.
The wire contract does not promise unique IDs or global ordering. Consumers must not
silently deduplicate or infer missing events from sequence gaps.
"""
from dataclasses import dataclass
from datetime import datetime
import re
from importlib.resources import files
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from .contracts import reject_nonfinite

_VALIDATOR = Draft202012Validator(
    json.loads(files("scaneval").joinpath("schemas", "trace-event.schema.json").read_text()),
)

_TIMESTAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}[Tt](?:[01]\d|2[0-3]):[0-5]\d:(?:[0-5]\d|60)"
    r"(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)"
)


def _reject_constant(value: str):
    raise ValueError(f"non-JSON numeric constant: {value}")


@dataclass
class TraceRead:
    events: list[dict]
    physical_lines: int
    rejected_records: int
    diagnostics: list[str]
    state: str


def parse_trace(raw: bytes) -> TraceRead:
    """Validate each nonblank JSONL record, retaining all readable valid events."""
    events, diagnostics = [], []
    lines = raw.splitlines()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line.decode("utf-8"),
                               parse_constant=_reject_constant)
            # A valid JSON numeric lexeme can overflow Python's float decoder
            # (for example 1e999) without calling parse_constant.
            reject_nonfinite(event)
            errors = list(_VALIDATOR.iter_errors(event))
            if not errors:
                stamp = event["timestamp"]
                if not _TIMESTAMP.fullmatch(stamp):
                    raise ValueError("invalid timestamp")
                # jsonschema date-time checking otherwise depends on optional extras.
                # RFC 3339 permits leap seconds; validate the calendar with second 59.
                datetime.fromisoformat(stamp.upper().replace(":60", ":59"))
            if errors:
                raise ValueError("wire schema violation")
        except (ValueError, UnicodeError):
            diagnostics.append(f"trace line {number}: invalid UTF-8, JSON, or observer wire record")
        else:
            events.append(event)
    state = ("partial" if events else "malformed") if diagnostics else ("valid" if events else "empty")
    return TraceRead(events, len(lines), len(diagnostics), diagnostics, state)


def read_trace(path: Path) -> TraceRead:
    """Read a trace; callers enforce their own bundle containment boundary."""
    try:
        from .execution import read_regular_file
        return parse_trace(read_regular_file(path))
    except FileNotFoundError:
        return TraceRead([], 0, 0, [], "missing")
