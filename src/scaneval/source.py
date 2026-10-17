"""Byte-preserving source inspection shared by location validators."""

from typing import BinaryIO


def count_physical_lines(handle: BinaryIO) -> int:
    """Count LF, CRLF, and CR physical lines without decoding or changing bytes.

    CRLF is one terminator, including when it straddles a read boundary. An
    unterminated final line counts once; an empty file has no lines. Other byte
    values (including Unicode line separators) are ordinary source content.
    """
    count = 0
    previous = b""
    while chunk := handle.read(64 * 1024):
        count += chunk.count(b"\n") + chunk.count(b"\r") - chunk.count(b"\r\n")
        if previous == b"\r" and chunk.startswith(b"\n"):
            count -= 1
        previous = chunk[-1:]
    return count + int(bool(previous) and previous not in (b"\r", b"\n"))
