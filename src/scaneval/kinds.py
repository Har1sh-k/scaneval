"""Versioned mapping from native rule/class/CWE identity to canonical kinds.

The mapping never decides truth. It only labels which canonical family a native
allegation belongs to; anything unknown stays ``unmapped`` and keeps its native identity.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
import json
import re

_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
# CWE ids have four digits today. A tag can be any string, and int() refuses one of more than 4300
# digits (a limit an environment can lower), so an id of more than this many digits is not read as a
# CWE at all, whatever a rule or a result tags itself with.
MAX_CWE_DIGITS = 9


@lru_cache(maxsize=1)
def load_mapping() -> dict:
    resource = files("scaneval").joinpath("mappings", "kinds.json")
    return json.loads(resource.read_text(encoding="utf-8"))


def mapping_version() -> str:
    return load_mapping()["mapping_version"]


def cwe_ids(values) -> list[str]:
    """Extract unique ``CWE-<n>`` identifiers from strings or lists of strings, in order.

    ``CWE-089`` and ``CWE-89`` are one identifier. An id of more than :data:`MAX_CWE_DIGITS` digits,
    leading zeros aside, is not a CWE and is left out.
    """
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    seen: dict[str, None] = {}
    for value in values:
        if not isinstance(value, str):
            continue
        for match in _CWE.finditer(value):
            digits = match.group(1).lstrip("0")
            if len(digits) > MAX_CWE_DIGITS:
                continue
            seen.setdefault(f"CWE-{int(digits) if digits else 0}")
    return list(seen)


def kind_for_cwes(cwes: list[str]) -> str:
    mapping = load_mapping()
    for cwe in cwes:
        kind = mapping["cwe"].get(cwe)
        if kind:
            return kind
    return mapping["unmapped_kind"]


def kind_for_harness_class(value: str | None) -> str:
    mapping = load_mapping()
    if not value:
        return mapping["unmapped_kind"]
    return mapping["harness_classes"].get(value.strip().lower(), mapping["unmapped_kind"])
