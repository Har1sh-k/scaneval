"""CLI for pluggable data ingestion; scanner execution stays in benchmark mode."""
from pathlib import Path
import json

from . import adapter_names, import_dataset, read_json, summary, validate_dataset, write_json
from .builtin import fetch_source, source_lock


def add_commands(sub) -> None:
    parser = sub.add_parser("dataset", help="fetch, import, and inspect pluggable benchmark datasets")
    commands = parser.add_subparsers(dest="dataset_command", required=True)
    commands.add_parser("list", help="list built-in and installed dataset adapters")
    fetch = commands.add_parser("fetch", help="download a pinned built-in data release, no target code")
    fetch.add_argument("adapter")
    fetch.add_argument("--output", type=Path, required=True)
    importing = commands.add_parser("import", help="normalize a dataset through its adapter, offline")
    importing.add_argument("--adapter", required=True)
    importing.add_argument("--source", type=Path, required=True)
    importing.add_argument("--output", type=Path, required=True)
    for command in ("validate", "inspect"):
        child = commands.add_parser(command, help=f"{command} a normalized dataset, offline")
        child.add_argument("dataset", type=Path)
    inspect = commands.choices["inspect"]
    inspect.add_argument("--output", type=Path)


def dispatch(args) -> int:
    action = args.dataset_command
    if action == "list":
        from . import BUILTINS
        for name in adapter_names():
            description = source_lock(name)["mode"] if name in BUILTINS else "custom dataset"
            print(f"{name}\t{description}")
    elif action == "fetch":
        lock = fetch_source(args.adapter, args.output)
        print(f"Fetched {len(lock['files'])} verified source files at {lock['revision']}: {args.output}")
    elif action == "import":
        document = import_dataset(args.adapter, args.source)
        write_json(args.output, document)
        print(f"Imported {document['dataset_id']}: {len(document['tasks'])} tasks -> {args.output}")
    elif action == "validate":
        validate_dataset(read_json(args.dataset))
        print(f"Valid dataset: {args.dataset}")
    else:
        record = summary(read_json(args.dataset))
        if args.output:
            write_json(args.output, record)
        else:
            print(json.dumps(record, indent=2, sort_keys=True))
    return 0
