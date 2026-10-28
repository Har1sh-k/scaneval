"""Read-only command surface for model-cutoff research."""
import argparse
import json
from pathlib import Path

from .model_cutoffs import assess_candidates, load_registry, read_json


def add_commands(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser("model-cutoffs", help="inspect sourced model cutoffs and offline CVE chronology")
    commands = parser.add_subparsers(dest="cutoff_command", required=True)
    listing = commands.add_parser("list", help="print the dated registry; unknown fields remain null")
    listing.add_argument("--registry", type=Path)
    check = commands.add_parser("check", help="check a research candidate document without admitting cases")
    check.add_argument("candidates", type=Path)
    check.add_argument("--model", required=True, action="append", dest="models", help="exact served model ID; repeat for cross-model coverage")
    check.add_argument("--basis", choices=("training", "documented"), default="training")
    check.add_argument("--registry", type=Path)


def dispatch(args: argparse.Namespace) -> int:
    registry = load_registry(args.registry)
    if args.cutoff_command == "list":
        result = registry
        status = 0
    else:
        result = assess_candidates(registry, read_json(args.candidates), args.models, basis=args.basis)
        status = 0 if result["pack_target_met"] else 1
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return status
