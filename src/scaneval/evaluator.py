"""ScanEval Evaluator: assess saved findings against frozen decisions and report metrics.

This is the public entry point for evaluation. It re-exports the scoring core rather than
wrapping it, so the behavior is exactly what :mod:`scaneval.scoring` implements.

The evaluator makes no model call, holds no truth label of its own, and never reads a
trace. Scoring depends only on the saved result, the plan, and the frozen review
decisions, which is what makes replay deterministic. Instrumentation cannot change a
score, and a score cannot be improved by capturing more events.
"""

from __future__ import annotations

from .contracts import ContractError, canonical_json, canonical_sha256, load_document, validate_document
from .report import render_report
from .scoring import claim_fingerprint, score

__all__ = [
    "score",
    "claim_fingerprint",
    "render_report",
    "load_document",
    "validate_document",
    "canonical_json",
    "canonical_sha256",
    "ContractError",
]
