"""Model knowledge-cutoff gating for SASTbench.

A real-world case is only a fair test for a model if the vulnerability's public
disclosure postdates the model's training knowledge cutoff. Otherwise a "hit"
may be memorization of the advisory or fix rather than detection.

The public-knowledge horizon of a case is the EARLIEST public signal that the
code path is a problem: min(realWorld.disclosure.*). A case counts for a model
when that horizon is strictly after the model's knowledge cutoff (exact gate, no
buffer).

Cases without disclosure dates (synthetic core, capability-safe, mixed-intent)
are author-written and not subject to contamination gating, so they are always
kept; only dated real-world cases can be excluded by a cutoff.
"""

import json
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODELS_PATH = REPO_ROOT / "taxonomy" / "models.json"

DISCLOSURE_DATE_KEYS = ("ghsaPublished", "fixCommitDate", "cvePublished")


def parse_date(value: str) -> date:
    """Parse a YYYY-MM-DD string into a date."""
    return date.fromisoformat(value)


def load_models(models_path: Path = MODELS_PATH) -> dict:
    """Load the model registry."""
    with open(models_path, encoding="utf-8") as f:
        return json.load(f)


def resolve_model_cutoff(model_ref: str, registry: dict | None = None) -> tuple[str, date]:
    """Resolve a model id or alias to (canonical_id, cutoff_date).

    Raises KeyError with the list of known ids if the reference is unknown.
    """
    registry = registry or load_models()
    needle = model_ref.strip().lower()
    for model in registry.get("models", []):
        candidates = {model["id"].lower()} | {a.lower() for a in model.get("aliases", [])}
        if needle in candidates:
            return model["id"], parse_date(model["knowledgeCutoff"])
    known = ", ".join(m["id"] for m in registry.get("models", []))
    raise KeyError(f"Unknown model '{model_ref}'. Known models: {known or '(none)'}")


def case_disclosure_dates(case: dict) -> dict[str, date]:
    """Return the parsed disclosure dates present on a case, keyed by field."""
    disclosure = case.get("realWorld", {}).get("disclosure", {})
    return {
        key: parse_date(disclosure[key])
        for key in DISCLOSURE_DATE_KEYS
        if disclosure.get(key)
    }


def case_horizon(case: dict) -> date | None:
    """Return the public-knowledge horizon (min disclosure date) or None."""
    dates = case_disclosure_dates(case)
    return min(dates.values()) if dates else None


def case_passes_cutoff(case: dict, cutoff: date) -> bool:
    """Whether a case counts for a model with the given cutoff.

    Cases with no disclosure horizon are not gated (kept). Dated cases pass only
    when their horizon is strictly after the cutoff.
    """
    horizon = case_horizon(case)
    if horizon is None:
        return True
    return horizon > cutoff


def partition_by_cutoff(cases, cutoff: date):
    """Split (case_dir, case) tuples into (kept, excluded) by a cutoff.

    Returns (kept, excluded) where kept is the list of (case_dir, case) tuples
    that count for the cutoff, and excluded is a list of (case_id, horizon_iso)
    pairs describing the dated cases that were filtered out.
    """
    kept = []
    excluded = []
    for case_dir, case in cases:
        if case_passes_cutoff(case, cutoff):
            kept.append((case_dir, case))
        else:
            horizon = case_horizon(case)
            excluded.append((case["id"], horizon.isoformat() if horizon else None))
    return kept, excluded
