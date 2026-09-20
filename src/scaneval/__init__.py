"""Framework-independent ScanEval evaluation core.

Live scanner integrations and legacy results remain separate from this protocol.
"""

__version__ = "2.0.0a1"


def evaluate(plan: dict, result: dict, decisions: dict) -> dict:
    """Evaluate one saved scan with frozen evaluator-side decisions, offline."""
    from .scoring import score

    return score(plan, result, decisions)
