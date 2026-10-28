"""Read-only command surface for model-cutoff research."""
import argparse
import json
from pathlib import Path

from .model_cutoffs import assess_candidates, load_registry, read_json
from .model_cutoff_projection import prepare_chronology


def add_commands(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser("model-cutoffs", help="inspect sourced model cutoffs and offline CVE chronology")
    commands = parser.add_subparsers(dest="cutoff_command", required=True)
    listing = commands.add_parser("list", help="print the dated registry; unknown fields remain null")
    listing.add_argument("--registry", type=Path)
    prepare = commands.add_parser("prepare-chronology", help="project dossier observations into pending chronology without admitting cases")
    prepare.add_argument("dossier", type=Path)
    prepare.add_argument("--severity-authority", required=True)
    check = commands.add_parser("check", help="check a research candidate document without admitting cases")
    check.add_argument("candidates", type=Path)
    check.add_argument("--model", required=True, action="append", dest="models", help="exact served model ID; repeat for cross-model coverage")
    check.add_argument("--basis", choices=("training", "documented"), default="training")
    check.add_argument("--registry", type=Path)


def dispatch(args: argparse.Namespace) -> int:
    if args.cutoff_command == "prepare-chronology":
        result = prepare_chronology(read_json(args.dossier), args.severity_authority)
        status = 0
    elif args.cutoff_command == "list":
        result = load_registry(args.registry)
        status = 0
    else:
        result = assess_candidates(load_registry(args.registry), read_json(args.candidates), args.models, basis=args.basis)
        status = 0 if result["pack_target_met"] else 1
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return status
