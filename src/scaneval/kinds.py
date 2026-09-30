"""Versioned mapping from native rule/class/CWE identity to canonical kinds.

The mapping never decides truth. It only labels which canonical family a native
allegation belongs to; anything unknown stays ``unmapped`` and keeps its native identity.
When several CWE ids of one allegation map to different kinds, the lowest-numbered id the
mapping knows decides, so no producer's ordering of them picks the kind.
"""

from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
import json
import re

_CWE = re.compile(r"CWE-(\d+)", re.IGNORECASE)
_CWE_TOKEN = re.compile(r"CWE-([0-9]+)")
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


def _numeric_order(cwe: str) -> tuple[int, int]:
    """Sort key for :func:`kind_for_cwes`: a ``CWE-<n>`` identifier by its number, anything else after them all."""
    match = _CWE_TOKEN.fullmatch(cwe) if isinstance(cwe, str) else None
    if match and len(match.group(1)) <= MAX_CWE_DIGITS:
        return 0, int(match.group(1))
    return 1, 0


def kind_for_cwes(cwes: list[str]) -> str:
    """The canonical kind of the lowest-numbered of *cwes* that the mapping knows, else ``unmapped``.

    The choice does not depend on the order *cwes* arrive in. A rule that lists CWE-918 before
    CWE-22, one that lists them the other way, and a producer that sorts what another keeps in order
    all get the kind of CWE-22, so two paths that read one finding (the Semgrep adapter and the
    SARIF import) cannot disagree about it. An id the mapping does not know never hides a higher
    one it does, and is never ordered at all: only the few ids the mapping holds are compared, so
    the cost is one lookup for each id given however many there are. Anything that is not a
    ``CWE-<n>`` identifier ranks after every one that is.
    """
    mapping = load_mapping()
    known = {cwe for cwe in cwes if mapping["cwe"].get(cwe)}
    if known:
        return mapping["cwe"][min(known, key=_numeric_order)]
    return mapping["unmapped_kind"]


def kind_for_harness_class(value: str | None) -> str:
    mapping = load_mapping()
    if not value:
        return mapping["unmapped_kind"]
    return mapping["harness_classes"].get(value.strip().lower(), mapping["unmapped_kind"])
