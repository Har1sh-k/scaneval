"""Deterministic, versioned random draws for review sampling and resampling.

Every random choice ScanEval makes, a review sample or a bootstrap replicate, comes from a
:class:`Stream` named by an explicit seed and a label, so the same frozen frame, seed, and
algorithm version always make the same choices. The generator is SHA-256 in counter mode rather
than :mod:`random`: its output is defined by this file alone, so a Python release that changes how
``random`` maps its state to integers cannot change a recorded sample, and a record names the
algorithm it was drawn with (:data:`ALGORITHM`).

What this is not. It is not a cryptographic RNG and nothing here is secret: anyone holding the
seed reproduces every draw, which is the point. Choosing a seed after looking at the result it
produces defeats the purpose, so the seed belongs in a policy or command frozen before the draw.
"""

from __future__ import annotations

import hashlib
from typing import Sequence, TypeVar

from .contracts import ContractError, canonical_json


ALGORITHM = "sha256-counter-v1"
_WORD = 1 << 64
T = TypeVar("T")


def _require_seed(seed: object) -> int:
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ContractError(f"a seed must be a non-negative integer, not {seed!r}")
    return seed


class Stream:
    """One reproducible stream of 64-bit words, keyed by a seed and a label.

    The label separates streams that share a seed, so a stratified sample draws each stratum from
    its own stream and adding a stratum never moves the draws of another. Words are read from
    ``sha256(key || counter)`` blocks in order, four 64-bit big-endian words per block.
    """

    def __init__(self, seed: int, *, label: str) -> None:
        self.seed = _require_seed(seed)
        if not isinstance(label, str):
            raise ContractError(f"a stream label must be a string, not {label!r}")
        self.label = label
        self._key = canonical_json({"algorithm": ALGORITHM, "label": label, "seed": seed}).encode("utf-8")
        self._counter = 0
        self._buffer: list[int] = []

    def _word(self) -> int:
        if not self._buffer:
            block = hashlib.sha256(self._key + self._counter.to_bytes(8, "big")).digest()
            self._counter += 1
            self._buffer = [int.from_bytes(block[offset:offset + 8], "big")
                            for offset in range(24, -1, -8)]
        return self._buffer.pop()

    def below(self, n: int) -> int:
        """A uniform integer in ``[0, n)``, by rejection so no residue is favoured."""
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise ContractError(f"a bound must be a positive integer, not {n!r}")
        limit = _WORD - (_WORD % n)
        while True:
            word = self._word()
            if word < limit:
                return word % n


def sample_without_replacement(items: Sequence[T], size: int, stream: Stream) -> list[T]:
    """*size* distinct members of *items*, each included with probability ``size / len(items)``.

    Simple random sampling without replacement by a partial Fisher-Yates shuffle over a copy of
    *items* in the order given, so the caller must supply a deterministic order (sorted identifiers)
    for the result to be independent of how the population was enumerated. The selection is
    returned in draw order; a caller that records it should sort it.
    """
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ContractError(f"a sample size must be a non-negative integer, not {size!r}")
    pool = list(items)
    if size > len(pool):
        raise ContractError(f"cannot draw {size} of {len(pool)} units without replacement")
    for index in range(size):
        swap = index + stream.below(len(pool) - index)
        pool[index], pool[swap] = pool[swap], pool[index]
    return pool[:size]


def resample_with_replacement(count: int, stream: Stream) -> list[int]:
    """*count* indices drawn uniformly with replacement from ``range(count)``: one bootstrap replicate."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ContractError(f"a resampled population must hold at least one unit, not {count!r}")
    return [stream.below(count) for _ in range(count)]
