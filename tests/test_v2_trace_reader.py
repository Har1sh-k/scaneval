import json

import pytest

from scaneval.observer import Observer
from scaneval.trace import parse_trace, read_trace


def wire_event(**changes):
    events = []
    Observer(mode="metadata", sink=events.append, run_id="producer-run", producer_id="p").emit(
        type="model.request", capture_status="complete", metadata={})
    return {**events[0], **changes}


@pytest.mark.parametrize("bad", [b'not json', b'{}', b'[]', b'\xff',
                                    json.dumps(wire_event(sequence=-1)).encode(),
                                    json.dumps(wire_event(timestamp="yesterday")).encode()])
def test_mixed_trace_preserves_valid_rows_and_counts_rejections(bad):
    good = json.dumps(wire_event()).encode()
    parsed = parse_trace(good + b'\n\n' + bad + b'\n' + good)
    assert parsed.physical_lines == 4
    assert parsed.rejected_records == 1
    assert len(parsed.events) == 2
    assert parsed.state == "partial"
    assert parsed.events[0] == parsed.events[1]  # duplicate IDs are physical evidence


def test_empty_missing_and_malformed_are_distinct(tmp_path):
    assert read_trace(tmp_path / "missing").state == "missing"
    assert parse_trace(b'\n ').state == "empty"
    assert parse_trace(b'{}').state == "malformed"
    # A native producer namespace is not required to equal a bundle's invocation ID.
    assert parse_trace(json.dumps(wire_event(run_id="different-run")).encode()).state == "valid"
