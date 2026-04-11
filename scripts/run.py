"""SASTbench runner.

Runs a scanner adapter against benchmark cases and produces
normalized results in the official JSON format.

Usage:
    python scripts/run.py --scanner semgrep --track core
    python scripts/run.py --scanner semgrep --track core --verbose
    python scripts/run.py --scanner bandit --track core -o results.json
    python scripts/run.py --scanner semgrep --track full --case-id SB-PY-RW-001
    python scripts/run.py --scanner semgrep --mode pr --track core
"""

import argparse
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from scoring import Finding, classify_findings, compute_summary

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "cases"
ADAPTERS_DIR = REPO_ROOT / "adapters"


def find_cases(
    track: str,
    case_type: str | None = None,
    case_id: str | None = None,
) -> list[tuple[Path, dict]]:
    """Find cases, optionally filtered by case type or specific case ID."""
    cases = []

    if track == "core":
        search_dirs = [CASES_DIR / "core"]
    elif track == "full":
        search_dirs = [CASES_DIR / "core", CASES_DIR / "full"]
    else:
        print(f"Unknown track: {track}")
        sys.exit(1)

    for search_dir in search_dirs:
        for case_json in sorted(search_dir.rglob("case.json")):
            with open(case_json, encoding="utf-8") as f:
                case = json.load(f)
            if case_type and case["caseType"] != case_type:
                continue
            if case_id and case["id"] != case_id:
                continue
            cases.append((case_json.parent, case))

    return cases


def load_adapter(scanner_name: str):
    """Load a scanner adapter module."""
    adapter_dir = ADAPTERS_DIR / scanner_name
    if not adapter_dir.exists():
        print(f"Adapter not found: {scanner_name}")
        print(f"Available adapters: {[d.name for d in ADAPTERS_DIR.iterdir() if d.is_dir()]}")
        sys.exit(1)

    sys.path.insert(0, str(adapter_dir))
    try:
        adapter = importlib.import_module("adapter")
    except ImportError as e:
        print(f"Failed to load adapter for {scanner_name}: {e}")
        sys.exit(1)

    return adapter


def default_output_path(scanner_name: str, track: str, started_at: datetime, mode: str = "benchmark") -> Path:
    """Build a default output path when none is provided."""
    stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
    mode_tag = f"_{mode}" if mode != "benchmark" else ""
    return REPO_ROOT / "results" / f"{scanner_name}_{track}{mode_tag}_{stamp}.json"


def normalize_relpath(path: Path, base_dir: Path) -> str:
    """Convert a path into a forward-slash relative path."""
    return str(path.relative_to(base_dir)).replace("\\", "/")


def write_artifact(path: Path, content: str) -> None:
    """Write an artifact file as UTF-8 text."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _case_outcome(scoring, skip_reason: str | None) -> str:
    """Return a concise outcome label for a case."""
    if skip_reason:
        return "SKIP"
    if scoring.false_negatives > 0 and scoring.true_positives == 0:
        return "TARGET MISS"
    if scoring.true_positives > 0:
        noise = scoring.false_positives + scoring.capability_false_positives
        return "TARGET HIT" if noise == 0 else "TARGET HIT (noisy)"
    noise = scoring.false_positives + scoring.capability_false_positives
    return "CLEAN" if noise == 0 else "NOISY"


def _format_default_status(scoring, skip_reason: str | None) -> str:
    """Format a concise one-line status for default mode using security-readable language."""
    outcome = _case_outcome(scoring, skip_reason)
    parts = [outcome]
    if scoring.false_negatives:
        parts.append(f"missed={scoring.false_negatives}")
    if scoring.false_positives:
        parts.append(f"additional={scoring.false_positives}")
    if scoring.capability_false_positives:
        parts.append(f"cap-noise={scoring.capability_false_positives}")
    if skip_reason:
        parts.append(f"skip={skip_reason}")
    return " | ".join(parts)


def _print_verbose_findings(finding_dicts: list[dict], prefix: str) -> None:
    """Print per-finding detail in verbose mode."""
    if not finding_dicts:
        print(f"{prefix}   (no findings)")
        return
    CLASS_COLOR = {
        "true_positive": "\033[32m",     # green
        "false_positive": "\033[33m",    # yellow
        "capability_false_positive": "\033[31m",  # red
    }
    RESET = "\033[0m"
    for fd in finding_dicts:
        cls = fd["classification"]
        color = CLASS_COLOR.get(cls, "")
        tag = cls.upper().replace("_", " ")
        region = fd.get("matchedRegionId") or "-"
        print(f"{prefix}   {color}[{tag}]{RESET} {fd['path']}:{fd['startLine']}-{fd['endLine']}")
        print(f"{prefix}     kind={fd['mappedKind']}  rule={fd['ruleId']}  region={region}")
        if fd.get("message"):
            print(f"{prefix}     {fd['message']}")


def run_benchmark(
    scanner_name: str,
    track: str,
    output_path: Path | None,
    case_type: str | None = None,
    case_id: str | None = None,
    verbose: bool = False,
    mode: str = "benchmark",
) -> int:
    """Run the benchmark and produce results."""
    started_at = datetime.now(timezone.utc)
    output_path = output_path or default_output_path(scanner_name, track, started_at, mode)

    if mode == "pr":
        from pr_runner import run_pr_benchmark
        return run_pr_benchmark(
            scanner_name=scanner_name,
            track=track,
            output_path=output_path,
            case_type=case_type,
            case_id=case_id,
            verbose=verbose,
            started_at=started_at,
        )
    output_dir = output_path.parent
    artifacts_root = output_dir / f"{output_path.stem}_artifacts"

    adapter = load_adapter(scanner_name)
    adapter_version = getattr(adapter, "ADAPTER_VERSION", "1.0.0")
    llm_model = getattr(adapter, "LLM_MODEL", None)
    cases = find_cases(track, case_type, case_id)

    if not cases:
        print("No cases found.")
        return 1

    B = "\033[1;36m[SASTbench]\033[0m"
    SEP = "\033[2m" + "-" * 45 + "\033[0m"
    print(f"{B} Running SASTbench ({track} track) with {scanner_name}")
    if llm_model:
        print(f"{B} LLM model: {llm_model}")
    print(f"{B} Found {len(cases)} cases\n")

    scanner_version = adapter.get_version()
    case_results = []
    all_scorings = []
    all_cases = []

    for case_dir, case in cases:
        current_case_id = case["id"]
        scan_root = case_dir / case["files"]["root"]

        print(f"{B} Scanning {current_case_id}...")
        print(f"{SEP}", flush=True)

        scan_meta = {
            "findings": [],
            "commandInvocation": None,
            "exitCode": None,
            "rawStdout": "",
            "rawStderr": "",
            "skipReason": None,
        }

        try:
            if hasattr(adapter, "scan_with_metadata"):
                scan_meta = adapter.scan_with_metadata(scan_root, case["language"])
            else:
                scan_meta["findings"] = adapter.scan(scan_root, case["language"])
        except Exception as e:
            print(f"{B} ERROR: {e}")
            scan_meta["rawStderr"] = str(e)
            scan_meta["skipReason"] = "adapter_error"

        raw_findings = scan_meta["findings"]

        findings = []
        for rf in raw_findings:
            findings.append(Finding(
                rule_id=rf["ruleId"],
                mapped_kind=rf["mappedKind"],
                path=rf["path"],
                start_line=rf["startLine"],
                end_line=rf["endLine"],
                severity=rf.get("severity", ""),
                message=rf.get("message", ""),
            ))

        scoring, classifications = classify_findings(case, findings)
        all_scorings.append(scoring)
        all_cases.append(case)

        finding_dicts = []
        for f, fc in zip(findings, classifications):
            finding_dicts.append({
                "ruleId": f.rule_id,
                "mappedKind": f.mapped_kind,
                "path": f.path,
                "startLine": f.start_line,
                "endLine": f.end_line,
                "severity": f.severity,
                "message": f.message,
                "matchedRegionId": fc.matched_region_id,
                "classification": fc.classification,
            })

        artifact_info = {
            "commandInvocation": scan_meta.get("commandInvocation"),
            "exitCode": scan_meta.get("exitCode"),
            "rawStdoutPath": None,
            "rawStderrPath": None,
            "skipReason": scan_meta.get("skipReason"),
        }

        raw_stdout = scan_meta.get("rawStdout", "")
        raw_stderr = scan_meta.get("rawStderr", "")
        if raw_stdout or raw_stderr:
            case_artifact_dir = artifacts_root / current_case_id
            stdout_path = case_artifact_dir / "scanner.stdout.txt"
            stderr_path = case_artifact_dir / "scanner.stderr.txt"
            write_artifact(stdout_path, raw_stdout)
            write_artifact(stderr_path, raw_stderr)
            artifact_info["rawStdoutPath"] = normalize_relpath(stdout_path, output_dir)
            artifact_info["rawStderrPath"] = normalize_relpath(stderr_path, output_dir)

        case_results.append({
            "caseId": current_case_id,
            "caseTrack": case["track"],
            "caseType": case["caseType"],
            "language": case["language"],
            "findings": finding_dicts,
            "scoring": {
                "truePositives": scoring.true_positives,
                "falseNegatives": scoring.false_negatives,
                "falsePositives": scoring.false_positives,
                "capabilityFalsePositives": scoring.capability_false_positives,
            },
            "artifacts": artifact_info,
        })

        skip_reason = scan_meta.get("skipReason")
        result_str = _format_default_status(scoring, skip_reason)
        print(f"{SEP}")
        print(f"{B} {current_case_id} => {result_str}")
        if verbose:
            _print_verbose_findings(finding_dicts, B)
        print()

    summary = compute_summary(all_scorings, all_cases)

    results = {
        "schemaVersion": "1.0.0",
        "benchmarkVersion": "1.0.0-dev",
        "mode": "benchmark",
        "scanner": {
            "name": scanner_name,
            "version": scanner_version,
            "adapter": adapter_version,
            **({"llmModel": llm_model} if llm_model else {}),
        },
        "track": track,
        "timestamp": started_at.isoformat(),
        "caseResults": case_results,
        "summary": {
            "recall": summary.recall,
            "precision": summary.precision,
            "capabilityFpRate": summary.capability_fp_rate,
            "mixedIntentAccuracy": summary.mixed_intent_accuracy,
            "agenticScore": summary.agentic_score,
        },
    }

    print(f"\n{B} {'='*50}")
    print(f"{B} Results - {scanner_name} v{scanner_version} ({track} track)")
    if llm_model:
        print(f"{B}   LLM Model:             {llm_model}")
    print(f"{B} {'='*50}")
    print(f"{B}   Target Hit Rate:       {summary.recall:.1%}")
    print(f"{B}   Intent Accuracy:       {summary.mixed_intent_accuracy:.1%}")
    print(f"{B}   Capability Noise:      {summary.capability_fp_rate:.1%}")
    if verbose:
        print(f"{B}   ---")
        print(f"{B}   Recall:                {summary.recall:.1%}")
        print(f"{B}   Precision:             {summary.precision:.1%}")
        print(f"{B}   Capability FP Rate:    {summary.capability_fp_rate:.1%}")
        print(f"{B}   Mixed-Intent Accuracy: {summary.mixed_intent_accuracy:.1%}")
        print(f"{B}   Benchmark Index:       {summary.agentic_score:.1%}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"{B} Results written to {output_path}")
    print(f"{B} Raw artifacts written to {artifacts_root}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SASTbench runner")
    parser.add_argument("--scanner", required=True, help="Scanner adapter name")
    parser.add_argument("--track", default="core", choices=["core", "full"])
    parser.add_argument("--mode", default="benchmark", choices=["benchmark", "pr"],
                        help="Execution mode: benchmark (default) or pr (PR simulation)")
    parser.add_argument("--output", "-o", type=Path, help="Output JSON file path (defaults under results/)")
    parser.add_argument(
        "--case-type",
        choices=["synthetic_vulnerable", "capability_safe", "mixed_intent", "real_world_disclosed"],
        help="Filter to a specific case type",
    )
    parser.add_argument(
        "--case-id",
        help="Run a single case by ID (e.g. SB-TS-RW-001)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show per-finding detail with classifications",
    )
    args = parser.parse_args()

    return run_benchmark(args.scanner, args.track, args.output, args.case_type, args.case_id, args.verbose, args.mode)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\033[1;33m[SASTbench]\033[0m Interrupted by user.")
        sys.exit(130)
