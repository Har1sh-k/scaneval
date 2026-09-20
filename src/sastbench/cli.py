"""Local validation, saved-output scoring, and deterministic replay. No live runner."""

import argparse
from pathlib import Path
import sys

from . import __version__
from .contracts import CONTRACT_KINDS, ContractError, canonical_json, load_document
from .demo import SOURCE, demo_documents
from .report import render_report
from .scoring import score


def _write_new(path: Path, content: str) -> None:
    # Refuse overwrite, including symlinks, rather than destroy a prior run.
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(content)


def _json(value: dict) -> str:
    return canonical_json(value) + "\n"


def load_bundle(directory: Path) -> tuple[dict, dict, dict]:
    plan = load_document(directory / "evaluator" / "plan.json", "evaluation-plan")
    result = load_document(directory / "result.json", "scan-result")
    decisions = load_document(directory / "evaluator" / "decisions.json", "review-decisions")
    return plan, result, decisions


def _demo(directory: Path) -> None:
    documents = demo_documents()
    record = score(documents["plan"], documents["result"], documents["decisions"])
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "scan-input").mkdir()
    (directory / "evaluator").mkdir()
    _write_new(directory / "scan-input" / "app.py", SOURCE)
    for name, relative in [("request", "request.json"), ("result", "result.json"),
                           ("plan", "evaluator/plan.json"), ("decisions", "evaluator/decisions.json")]:
        _write_new(directory / relative, _json(documents[name]))
    _write_new(directory / "evaluation.json", _json(record))
    _write_new(directory / "report.html", render_report(record, documents["result"], documents["plan"]))
    _write_new(directory / "README.txt", "Diagnostic fixture only. No scanner was run.\n"
               "scan-input contains source only; evaluator contains scripted labels and decisions.\n"
               "Directory separation illustrates the contract, not a sandbox or access restriction.\n"
               "Input hash: canonical SHA-256 of the app.py path/content map, not a git archive.\n"
               "Replay reads result.json and evaluator/{plan,decisions}.json, not source or request.\n"
               "It verifies the decision-to-result binding, not the actual input tree or a signature.\n")
    print(f"Created diagnostic bundle: {directory}\nOpen {directory / 'report.html'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate a versioned JSON contract")
    validate.add_argument("kind", choices=sorted(CONTRACT_KINDS))
    validate.add_argument("path", type=Path)
    scoring = sub.add_parser("score", help="score saved output with frozen evaluator decisions")
    for name in ("plan", "result", "decisions"):
        scoring.add_argument(f"--{name}", required=True, type=Path)
    scoring.add_argument("--output", type=Path, help="new JSON file; default stdout")
    replay = sub.add_parser("replay", help="recompute a saved bundle offline")
    replay.add_argument("bundle", type=Path)
    replay.add_argument("--output", type=Path, help="new JSON file; default stdout")
    report = sub.add_parser("report", help="score a saved bundle and render a standalone HTML report")
    report.add_argument("bundle", type=Path)
    report.add_argument("--output", required=True, type=Path)
    demo = sub.add_parser("demo", help="create a fabricated conformance bundle, no scanner execution")
    demo.add_argument("directory", type=Path, help="new directory, must not exist")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            load_document(args.path, args.kind)
            print(f"Valid {args.kind}: {args.path}")
        elif args.command == "demo":
            _demo(args.directory)
        else:
            if args.command == "score":
                plan = load_document(args.plan, "evaluation-plan")
                result = load_document(args.result, "scan-result")
                decisions = load_document(args.decisions, "review-decisions")
            else:
                plan, result, decisions = load_bundle(args.bundle)
            record = score(plan, result, decisions)
            content = render_report(record, result, plan) if args.command == "report" else _json(record)
            if args.output:
                _write_new(args.output, content)
            else:
                sys.stdout.write(content)
        return 0
    except (ContractError, OSError, UnicodeError) as exc:
        print(f"sastbench: {exc}", file=sys.stderr)
        return 2
