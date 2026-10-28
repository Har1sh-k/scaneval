"""Dataset-based benchmark commands."""
from pathlib import Path
import json

from . import benchmark
from .datasets import read_json, write_json
from .contracts import canonical_sha256


def add_commands(sub) -> None:
    parser = sub.add_parser("benchmark", help="plan, run, and score an imported dataset")
    commands = parser.add_subparsers(dest="benchmark_command", required=True)
    plan = commands.add_parser("plan", help="freeze dataset identity, systems, tasks, and repetitions")
    plan.add_argument("--dataset", type=Path, required=True)
    plan.add_argument("--systems", type=Path, required=True, help="JSON array of scanner system specifications")
    plan.add_argument("--run-id", required=True)
    plan.add_argument("--repetitions", type=int, default=3)
    plan.add_argument("--timeout-seconds", type=float, default=1800)
    plan.add_argument("--trace-mode", choices=("off", "metadata", "content"), default="off")
    plan.add_argument("--task", action="append", help="exact task ID; repeat to select a subset before running")
    plan.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("run", help="execute a frozen dataset plan with existing scanner adapters")
    run.add_argument("--plan", type=Path, required=True)
    run.add_argument("--dataset", type=Path, required=True)
    run.add_argument("--cache", type=Path, default=Path(".repos/benchmark-sources"))
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--quiet", action="store_true")
    packets = commands.add_parser("judge-packet", help="export saved claims and reference annotations for semantic judging")
    packets.add_argument("run", type=Path)
    packets.add_argument("--output", type=Path, required=True)
    score = commands.add_parser("score", help="score saved output with frozen machine or human judgments, offline")
    score.add_argument("run", type=Path)
    score.add_argument("--judgments", type=Path, help="judgments bound to the exact judge-packet hash")
    score.add_argument("--output", type=Path)


def dispatch(args) -> int:
    command = args.benchmark_command
    if command == "plan":
        plan = benchmark.build_plan(read_json(args.dataset), read_json(args.systems), run_id=args.run_id,
                                    repetitions=args.repetitions, timeout_seconds=args.timeout_seconds,
                                    task_ids=args.task, trace_mode=args.trace_mode)
        write_json(args.output, plan)
        print(f"Frozen {len(plan['task_ids']) * len(plan['systems']) * plan['repetitions']} invocations: {args.output}")
    elif command == "run":
        record = benchmark.run(read_json(args.plan), read_json(args.dataset), args.output, args.cache,
                               progress=(lambda _: None) if args.quiet else print)
        print(f"Saved {len(record['invocations'])} invocations: {args.output}")
        return 0 if all(r["status"] == "success" for r in record["invocations"]) else 1
    elif command == "judge-packet":
        packet = benchmark.judge_packet(args.run)
        write_json(args.output, packet)
        print(f"Judge packet: {args.output}\npacket_sha256: {canonical_sha256(packet)}")
    else:
        report = benchmark.score(args.run, read_json(args.judgments) if args.judgments else None)
        if args.output:
            write_json(args.output, report)
            print(f"Saved benchmark score: {args.output}")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
    return 0
