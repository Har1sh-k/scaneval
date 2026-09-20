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


@lru_cache(maxsize=1)
def load_mapping() -> dict:
    resource = files("sastbench").joinpath("mappings", "kinds.json")
    return json.loads(resource.read_text(encoding="utf-8"))


def mapping_version() -> str:
    return load_mapping()["mapping_version"]


def cwe_ids(values) -> list[str]:
    """Extract unique ``CWE-<n>`` identifiers from strings or lists of strings, in order."""
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    seen: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        for match in _CWE.finditer(value):
            token = f"CWE-{int(match.group(1))}"
            if token not in seen:
                seen.append(token)
    return seen


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
