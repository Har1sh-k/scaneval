"""Single HTTP lines trickled across raw socket reads cannot outlast the total retrieval deadline.

Each line below arrives in four fragments, each delayed 19 seconds: inside the 20-second per-read
timeout, so only the 60-second total budget can stop it. Enforcement only between readline or
read1 calls would let the line finish at 76 seconds; raw-read enforcement gives the fourth read
just the 3 remaining seconds and fails at exactly 60, before that fragment reaches the parser.
"""

import base64

import pytest

from scaneval.isolation import public_retrieval as retrieval
from test_v2_public_retrieval import POLICY, capture_and_classify, open_files, real_transport

CHUNKED = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
TAIL = b"Content-Length: 11\r\n\r\nhello world"

# (fast prefix ending exactly at a line boundary, fragments of one line, fast remainder)
LINES = {
    "status_line": (None, [b"HTT", b"P/1.1 2", b"00 O", b"K\r\n"], TAIL),
    "header_line": (b"HTTP/1.1 200 OK\r\n", [b"X-Sl", b"ow: fr", b"agme", b"nt\r\n"], TAIL),
    "chunk_size_line": (CHUNKED + b"5\r\nhello\r\n", [b"0", b"006", b";x=y", b"\r\n"], b" world\r\n0\r\n\r\n"),
    "trailer_line": (CHUNKED + b"5\r\nhello\r\n6\r\n world\r\n0\r\n", [b"X-Tr", b"ailer: ", b"va", b"lue\r\n"],
                     b"\r\n"),
}


def fragmented(case, delay):
    prefix, fragments, rest = LINES[case]
    return ([(0, prefix)] if prefix else []) + [(delay, fragment) for fragment in fragments] + [(0, rest)]


def journaling(monkeypatch, recorder, wires):
    """Record each terminal event with the socket files still open at the moment it is journaled."""
    observed = []
    original = recorder.write
    def write(event):
        observed.append((event["id"], sum(open_files(wire) for wire in wires)))
        original(event)
    monkeypatch.setattr(recorder, "write", write)
    return observed


@pytest.mark.parametrize("case", list(LINES))
def test_one_line_trickled_across_raw_reads_times_out_at_the_total_deadline(tmp_path, monkeypatch, case):
    clock = [0.0]
    wires = real_transport(monkeypatch, fragmented(case, 19), clock=clock)
    logs = tmp_path / "proxy-log"
    logs.mkdir()
    recorder = retrieval.Recorder(str(logs), POLICY)
    journaled = journaling(monkeypatch, recorder, wires)
    event = recorder.retrieve({"url": "https://research.example/" + case})
    wire, last = wires[0], LINES[case][1][-1]
    assert event["outcome"] == "failed" and event["error"] == "TimeoutError"
    assert event["content_base64"] is None and event["capture_status"] == "unavailable"
    # Per-line enforcement would read all four fragments (76 s) before any check could fire.
    assert clock[0] == 60.0 and wire.timeouts[-1] == pytest.approx(3.0)
    assert wire.script[0] == (16, last), "the deadline must cut the line before its last fragment arrives"
    assert wire.reads == (4 if LINES[case][0] is None else 5)
    hop = event["redirect_chain"][0]
    assert hop["status"] == (None if case in ("status_line", "header_line") else 200)
    assert hop["connected_address"] == "8.8.8.8" and len(event["redirect_chain"]) == 1
    assert wire.io_refs == 0 and wire.file_closes == 1 and wire.closed == 1
    assert journaled == [(event["id"], 0)]
    summary, condition, _saved = capture_and_classify(tmp_path, logs)
    assert summary["capture_status"] == "recorded" and summary["incomplete_attempts"] == 0
    assert summary["failed"] == 1 and summary["preserved"] == 0
    assert condition["retrieval"] == "recorded", condition["reasons"]
    assert not any(reason["code"] == "retrieval_artifact_mismatch" for reason in condition["reasons"])


@pytest.mark.parametrize("case", list(LINES))
def test_the_same_fragmented_lines_complete_when_delivered_promptly(tmp_path, monkeypatch, case):
    clock = [0.0]
    wires = real_transport(monkeypatch, fragmented(case, 0), clock=clock)
    logs = tmp_path / "proxy-log"
    logs.mkdir()
    recorder = retrieval.Recorder(str(logs), POLICY)
    journaled = journaling(monkeypatch, recorder, wires)
    event = recorder.retrieve({"url": "https://research.example/" + case})
    wire = wires[0]
    assert event["outcome"] == "ok" and event["redirect_chain"][0]["status"] == 200
    assert base64.b64decode(event["content_base64"]) == b"hello world"
    assert event["capture_status"] == "preserved" and clock[0] == 0.0
    assert not wire.script and set(wire.timeouts) == {20}
    assert wire.io_refs == 0 and wire.file_closes == 1 and wire.closed == 1
    assert journaled == [(event["id"], 0)]
    summary, condition, _saved = capture_and_classify(tmp_path, logs)
    assert summary["capture_status"] == "recorded" and summary["incomplete_attempts"] == 0
    assert summary["preserved"] == 1 and condition["retrieval"] == "recorded", condition["reasons"]
