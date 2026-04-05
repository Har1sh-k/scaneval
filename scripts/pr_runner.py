"""SASTbench PR mode runner.

Implements PR simulation benchmark: scans base and head trees,
computes diff, synthesizes review findings, and scores whether
introduced vulnerabilities are detected.

Usage (via run.py):
    python scripts/run.py --scanner semgrep --mode pr --track core
"""

import difflib
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from scoring import Finding
from pr_scoring import (
    PRCaseScoring,
    synthesize_review_findings,
    score_pr_case,
    compute_pr_summary,
)
from run import (
    REPO_ROOT,
    CASES_DIR,
    find_cases,
    load_adapter,
    normalize_relpath,
    write_artifact,
)

B = "\033[1;36m[SASTbench]\033[0m"
SEP = "\033[2m" + "-" * 45 + "\033[0m"

# Directories to exclude from PR tree copies and diffs.
# These are generated artifacts that pollute changed-file lists
# and are machine-dependent.
_IGNORED_DIRS = {
    "__pycache__",
    ".git",
    ".claude",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "venv",
    ".venv",
    ".tox",
    ".eggs",
    "*.egg-info",
}


def _copytree_ignore(directory: str, contents: list[str]) -> set[str]:
    """shutil.copytree ignore callback — skip generated/junk dirs."""
    return {name for name in contents if name in _IGNORED_DIRS}


def _is_ignored_path(rel_path: str) -> bool:
    """Check if a relative path falls under an ignored directory."""
    parts = rel_path.replace("\\", "/").split("/")
    return any(part in _IGNORED_DIRS for part in parts)


def _has_pr_simulation(case: dict) -> bool:
    """Check if a case has prSimulation metadata."""
    return "prSimulation" in case


def _git_init(directory: Path) -> None:
    """Initialize a git repo with an initial commit so LLM scanners work.

    Some scanners (e.g. securevibes-agent) require a git repository.
    Temp dirs created by copytree are not git repos, so we init one.
    """
    subprocess.run(
        ["git", "init"],
        cwd=str(directory),
        capture_output=True,
        timeout=10,
    )
    subprocess.run(
        ["git", "add", "."],
        cwd=str(directory),
        capture_output=True,
        timeout=30,
    )
    subprocess.run(
        ["git", "-c", "user.name=SASTbench", "-c", "user.email=bench@local",
         "commit", "-m", "initial", "--allow-empty"],
        cwd=str(directory),
        capture_output=True,
        timeout=30,
    )


def _materialize_vendored(case_dir: Path, case: dict, tmp_root: Path) -> tuple[Path, Path]:
    """Materialize base and head trees for a vendored_base case.

    Copies both trees into a temp directory for symmetric scanning.
    Returns (base_scan_root, head_scan_root).
    """
    pr_sim = case["prSimulation"]
    base_src = case_dir / pr_sim["baseRoot"]
    head_src = case_dir / case["files"]["root"]

    base_dst = tmp_root / "base"
    head_dst = tmp_root / "head"

    shutil.copytree(base_src, base_dst, ignore=_copytree_ignore)
    shutil.copytree(head_src, head_dst, ignore=_copytree_ignore)

    # Init git repos so LLM-backed scanners can operate
    _git_init(base_dst)
    _git_init(head_dst)

    return base_dst, head_dst


def _materialize_git_commits(case_dir: Path, case: dict, tmp_root: Path) -> tuple[Path, Path]:
    """Materialize base and head trees for a git_commit_pair case.

    Uses git worktrees from the repo snapshot to check out both commits.
    Returns (base_scan_root, head_scan_root).
    """
    pr_sim = case["prSimulation"]
    real_world = case["realWorld"]

    base_commit = pr_sim["baseCommit"]
    head_commit = pr_sim.get("headCommit", real_world["vulnerableCommit"])

    # Resolve the repo root from the case's files.root
    repo_root = (case_dir / case["files"]["root"]).resolve()

    base_dst = tmp_root / "base"
    head_dst = tmp_root / "head"

    # Use git archive to extract each commit into a temp dir
    for commit, dst in [(base_commit, base_dst), (head_commit, head_dst)]:
        dst.mkdir(parents=True)
        result = subprocess.run(
            ["git", "archive", "--format=tar", commit],
            cwd=str(repo_root),
            capture_output=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git archive failed for {commit}: {result.stderr.decode()}"
            )
        # Extract tar into destination
        subprocess.run(
            ["tar", "xf", "-"],
            input=result.stdout,
            cwd=str(dst),
            timeout=120,
            check=True,
        )

    return base_dst, head_dst


def _compute_changed_files(base_root: Path, head_root: Path) -> list[str]:
    """Compute list of changed files between base and head trees.

    Uses simple file comparison for vendored trees.
    """
    changed: list[str] = []

    # Gather all relative paths from both trees
    base_files: set[str] = set()
    head_files: set[str] = set()

    for p in base_root.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(base_root)).replace("\\", "/")
            if not _is_ignored_path(rel):
                base_files.add(rel)

    for p in head_root.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(head_root)).replace("\\", "/")
            if not _is_ignored_path(rel):
                head_files.add(rel)

    # New files in head
    for f in sorted(head_files - base_files):
        changed.append(f)

    # Deleted files
    for f in sorted(base_files - head_files):
        changed.append(f)

    # Modified files (present in both, content differs)
    for f in sorted(base_files & head_files):
        base_content = (base_root / f).read_bytes()
        head_content = (head_root / f).read_bytes()
        if base_content != head_content:
            changed.append(f)

    return changed


def _compute_diff_text(base_root: Path, head_root: Path, changed_files: list[str]) -> str:
    """Compute a unified diff text between base and head for changed files."""
    diff_parts: list[str] = []
    for rel_path in changed_files:
        base_file = base_root / rel_path
        head_file = head_root / rel_path

        base_lines = []
        head_lines = []
        if base_file.exists():
            try:
                base_lines = base_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            except Exception:
                pass
        if head_file.exists():
            try:
                head_lines = head_file.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
            except Exception:
                pass

        diff = difflib.unified_diff(
            base_lines, head_lines,
            fromfile=f"a/{rel_path}",
            tofile=f"b/{rel_path}",
        )
        diff_parts.extend(diff)

    return "".join(diff_parts)


def _try_native_pr_scan(
    adapter,
    base_root: Path,
    head_root: Path,
    changed_files: list[str],
    diff_text: str,
    language: str,
    case: dict,
) -> tuple[list[Finding], list[Finding], list[Finding], dict] | None:
    """Try native PR scan if adapter supports it.

    Returns (base_findings, head_findings, review_findings, meta) or None.
    """
    if not hasattr(adapter, "scan_pr_with_metadata"):
        return None

    try:
        result = adapter.scan_pr_with_metadata(
            base_root=base_root,
            head_root=head_root,
            changed_files=changed_files,
            diff_text=diff_text,
            language=language,
            case=case,
        )
    except Exception as e:
        print(
            f"{B} WARNING: native scan_pr_with_metadata() failed: {e}",
            file=sys.stderr,
        )
        print(f"{B} WARNING: falling back to dual-scan mode", file=sys.stderr)
        return None

    def _parse_findings(raw: list[dict]) -> list[Finding]:
        findings = []
        for rf in raw:
            findings.append(Finding(
                rule_id=rf["ruleId"],
                mapped_kind=rf["mappedKind"],
                path=rf["path"],
                start_line=rf["startLine"],
                end_line=rf["endLine"],
                severity=rf.get("severity", ""),
                message=rf.get("message", ""),
            ))
        return findings

    base_findings = _parse_findings(result.get("baselineFindings", []))
    head_findings = _parse_findings(result.get("headFindings", []))
    review_findings = _parse_findings(result.get("reviewFindings", []))

    meta = {
        "commandInvocation": result.get("commandInvocation"),
        "exitCode": result.get("exitCode"),
        "rawStdout": result.get("rawStdout", ""),
        "rawStderr": result.get("rawStderr", ""),
        "skipReason": result.get("skipReason"),
    }

    return base_findings, head_findings, review_findings, meta


def _scan_tree(adapter, scan_root: Path, language: str) -> tuple[list[Finding], dict]:
    """Scan a tree using the adapter and return (findings, scan_meta)."""
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
            scan_meta = adapter.scan_with_metadata(scan_root, language)
        else:
            scan_meta["findings"] = adapter.scan(scan_root, language)
    except Exception as e:
        scan_meta["rawStderr"] = str(e)
        scan_meta["skipReason"] = "adapter_error"

    findings = []
    for rf in scan_meta["findings"]:
        findings.append(Finding(
            rule_id=rf["ruleId"],
            mapped_kind=rf["mappedKind"],
            path=rf["path"],
            start_line=rf["startLine"],
            end_line=rf["endLine"],
            severity=rf.get("severity", ""),
            message=rf.get("message", ""),
        ))

    return findings, scan_meta


def _finding_to_dict(f: Finding) -> dict:
    """Convert a Finding to a result dict."""
    d = {
        "ruleId": f.rule_id,
        "mappedKind": f.mapped_kind,
        "path": f.path,
        "startLine": f.start_line,
        "endLine": f.end_line,
    }
    if f.severity:
        d["severity"] = f.severity
    if f.message:
        d["message"] = f.message
    return d


def _format_pr_status(scoring: PRCaseScoring, skip_reason: str | None) -> str:
    """Format a concise one-line PR status."""
    if skip_reason:
        return f"SKIP | skip={skip_reason}"

    if scoring.introduced_targets_total == 0:
        return "NO TARGETS"

    if scoring.introduced_targets_detected == scoring.introduced_targets_total:
        outcome = "INTRODUCED VULN DETECTED"
    elif scoring.introduced_targets_detected > 0:
        outcome = "PARTIAL DETECTION"
    else:
        outcome = "INTRODUCED VULN MISSED"

    parts = [outcome]
    if scoring.review_noise:
        parts.append(f"review-noise={scoring.review_noise}")
    if scoring.capability_noise:
        parts.append(f"cap-noise={scoring.capability_noise}")
    return " | ".join(parts)


def _print_pr_verbose(
    base_findings: list[Finding],
    head_findings: list[Finding],
    review_findings: list[Finding],
    changed_files: list[str],
    prefix: str,
) -> None:
    """Print detailed PR findings in verbose mode."""
    print(f"{prefix}   changed files: {len(changed_files)}")
    for cf in changed_files[:10]:
        print(f"{prefix}     {cf}")
    if len(changed_files) > 10:
        print(f"{prefix}     ... and {len(changed_files) - 10} more")

    print(f"{prefix}   base findings: {len(base_findings)}")
    print(f"{prefix}   head findings: {len(head_findings)}")
    print(f"{prefix}   review (new-in-head) findings: {len(review_findings)}")

    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"
    for rf in review_findings:
        print(f"{prefix}     {GREEN}[REVIEW]{RESET} {rf.path}:{rf.start_line}-{rf.end_line}")
        print(f"{prefix}       kind={rf.mapped_kind}  rule={rf.rule_id}")
        if rf.message:
            print(f"{prefix}       {rf.message}")


def run_pr_benchmark(
    scanner_name: str,
    track: str,
    output_path: Path,
    case_type: str | None = None,
    case_id: str | None = None,
    verbose: bool = False,
    started_at: datetime | None = None,
) -> int:
    """Run PR simulation benchmark."""
    started_at = started_at or datetime.now(timezone.utc)
    output_dir = output_path.parent
    artifacts_root = output_dir / f"{output_path.stem}_artifacts"

    adapter = load_adapter(scanner_name)
    adapter_version = getattr(adapter, "ADAPTER_VERSION", "1.0.0")
    llm_model = getattr(adapter, "LLM_MODEL", None)
    scanner_version = adapter.get_version()

    all_cases = find_cases(track, case_type, case_id)
    # PR mode only runs cases that have prSimulation AND mustDetectRegionIds.
    # Cases with empty mustDetectRegionIds (e.g. capability_safe) don't test
    # vulnerability detection, so they are excluded from PR benchmarking.
    pr_cases = []
    no_targets_skipped = 0
    for d, c in all_cases:
        if not _has_pr_simulation(c):
            continue
        if not c["expectedOutcome"].get("mustDetectRegionIds"):
            no_targets_skipped += 1
            continue
        pr_cases.append((d, c))

    if not pr_cases:
        print(f"{B} No PR-capable cases found (need prSimulation + mustDetectRegionIds).")
        skipped_count = len(all_cases) - len(pr_cases)
        if skipped_count:
            print(f"{B} {skipped_count} case(s) skipped.")
        return 1

    skipped = len(all_cases) - len(pr_cases) - no_targets_skipped
    print(f"{B} Running SASTbench PR mode ({track} track) with {scanner_name}")
    if llm_model:
        print(f"{B} LLM model: {llm_model}")
    print(f"{B} Found {len(pr_cases)} PR-capable cases")
    if no_targets_skipped:
        print(f"{B} Skipping {no_targets_skipped} cases with no mustDetectRegionIds (e.g. capability_safe)")
    if skipped:
        print(f"{B} Skipping {skipped} cases without prSimulation")
    print()

    case_results = []
    all_scorings: list[PRCaseScoring] = []

    for case_dir, case in pr_cases:
        current_case_id = case["id"]
        pr_sim = case["prSimulation"]
        pr_mode = pr_sim["mode"]

        print(f"{B} PR scanning {current_case_id} (mode={pr_mode})...")
        print(f"{SEP}", flush=True)

        skip_reason = None
        base_findings: list[Finding] = []
        head_findings: list[Finding] = []
        review_findings: list[Finding] = []
        changed_files: list[str] = []
        base_meta: dict = {}
        head_meta: dict = {}

        tmp_dir = None
        try:
            tmp_dir = Path(tempfile.mkdtemp(prefix=f"sastbench_pr_{current_case_id}_"))

            # Materialize trees
            if pr_mode == "vendored_base":
                base_root, head_root = _materialize_vendored(case_dir, case, tmp_dir)
            elif pr_mode == "git_commit_pair":
                base_root, head_root = _materialize_git_commits(case_dir, case, tmp_dir)
            else:
                skip_reason = f"unknown_pr_mode:{pr_mode}"
                base_root = head_root = tmp_dir

            if not skip_reason:
                # Compute changed files
                changed_files = _compute_changed_files(base_root, head_root)

                # Try native PR scan first
                diff_text = _compute_diff_text(base_root, head_root, changed_files)
                native_result = _try_native_pr_scan(
                    adapter, base_root, head_root, changed_files,
                    diff_text, case["language"], case,
                )

                if native_result is not None:
                    print(f"{B}   Using native PR scan...", flush=True)
                    base_findings, head_findings, review_findings, head_meta = native_result
                    if head_meta.get("skipReason"):
                        skip_reason = head_meta["skipReason"]
                else:
                    # Fallback: scan both trees independently
                    print(f"{B}   Scanning base tree...", flush=True)
                    base_findings, base_meta = _scan_tree(adapter, base_root, case["language"])

                    print(f"{B}   Scanning head tree...", flush=True)
                    head_findings, head_meta = _scan_tree(adapter, head_root, case["language"])

                    if base_meta.get("skipReason") or head_meta.get("skipReason"):
                        skip_reason = base_meta.get("skipReason") or head_meta.get("skipReason")

                    if not skip_reason:
                        # Synthesize review findings from base vs head diff
                        review_findings = synthesize_review_findings(base_findings, head_findings)

        except Exception as e:
            print(f"{B} ERROR: {e}")
            skip_reason = f"materialization_error"

        finally:
            if tmp_dir and tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)

        # Score — only count cases that actually ran as "evaluated"
        if not skip_reason:
            pr_scoring = score_pr_case(case, review_findings)
            all_scorings.append(pr_scoring)
        else:
            pr_scoring = PRCaseScoring(
                case_id=current_case_id,
                introduced_targets_total=len(
                    case["expectedOutcome"].get("mustDetectRegionIds", [])
                ),
            )
            skipped += 1

        # Write artifacts
        artifact_info = {
            "commandInvocation": head_meta.get("commandInvocation") if head_meta else None,
            "exitCode": head_meta.get("exitCode") if head_meta else None,
            "rawStdoutPath": None,
            "rawStderrPath": None,
            "skipReason": skip_reason,
        }

        raw_stdout = (head_meta.get("rawStdout", "") if head_meta else "")
        raw_stderr = (head_meta.get("rawStderr", "") if head_meta else "")
        if raw_stdout or raw_stderr:
            case_artifact_dir = artifacts_root / current_case_id
            stdout_path = case_artifact_dir / "scanner.stdout.txt"
            stderr_path = case_artifact_dir / "scanner.stderr.txt"
            write_artifact(stdout_path, raw_stdout)
            write_artifact(stderr_path, raw_stderr)
            artifact_info["rawStdoutPath"] = normalize_relpath(stdout_path, output_dir)
            artifact_info["rawStderrPath"] = normalize_relpath(stderr_path, output_dir)

        # Build case result
        # Use head findings as the primary finding list for benchmark compatibility
        from scoring import classify_findings
        benchmark_scoring, classifications = classify_findings(case, head_findings)

        finding_dicts = []
        for f, fc in zip(head_findings, classifications):
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

        case_result = {
            "caseId": current_case_id,
            "caseTrack": case["track"],
            "caseType": case["caseType"],
            "language": case["language"],
            "findings": finding_dicts,
            "scoring": {
                "truePositives": benchmark_scoring.true_positives,
                "falseNegatives": benchmark_scoring.false_negatives,
                "falsePositives": benchmark_scoring.false_positives,
                "capabilityFalsePositives": benchmark_scoring.capability_false_positives,
            },
            "artifacts": artifact_info,
            "prContext": {
                "changedFiles": changed_files,
                "baselineFindings": [_finding_to_dict(f) for f in base_findings],
                "headFindings": [_finding_to_dict(f) for f in head_findings],
                "reviewFindings": [_finding_to_dict(f) for f in review_findings],
            },
            "prScoring": {
                "introducedTargetsDetected": pr_scoring.introduced_targets_detected,
                "introducedTargetsTotal": pr_scoring.introduced_targets_total,
                "introducedTargetHitRate": pr_scoring.introduced_target_hit_rate,
                "reviewNoise": pr_scoring.review_noise,
                "capabilityNoise": pr_scoring.capability_noise,
            },
        }
        case_results.append(case_result)

        # Print status
        result_str = _format_pr_status(pr_scoring, skip_reason)
        print(f"{SEP}")
        print(f"{B} {current_case_id} => {result_str}")
        if verbose:
            _print_pr_verbose(base_findings, head_findings, review_findings, changed_files, B)
        print()

    # Compute PR summary (the authoritative metrics for PR mode)
    pr_summary = compute_pr_summary(all_scorings, skipped)

    # Populate the required summary block from PR scoring so it reflects
    # review-finding reality, not head-tree benchmark scoring.
    # recall = introduced target hit rate (the PR-mode analog)
    # precision/capabilityFpRate/mixedIntentAccuracy/agenticScore are not
    # meaningful in PR mode, so they are set to 0.
    results = {
        "schemaVersion": "1.0.0",
        "benchmarkVersion": "1.0.0-dev",
        "mode": "pr",
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
            "recall": pr_summary.introduced_target_hit_rate,
            "precision": 0.0,
            "capabilityFpRate": 0.0,
            "mixedIntentAccuracy": 0.0,
            "agenticScore": 0.0,
        },
        "prSummary": {
            "introducedTargetHitRate": pr_summary.introduced_target_hit_rate,
            "totalReviewNoise": pr_summary.total_review_noise,
            "totalCapabilityNoise": pr_summary.total_capability_noise,
            "casesEvaluated": pr_summary.cases_evaluated,
            "casesSkipped": pr_summary.cases_skipped,
        },
    }

    # Print PR summary
    print(f"\n{B} {'='*50}")
    print(f"{B} PR Results - {scanner_name} v{scanner_version} ({track} track)")
    if llm_model:
        print(f"{B}   LLM Model:                  {llm_model}")
    print(f"{B} {'='*50}")
    print(f"{B}   Introduced Target Hit Rate: {pr_summary.introduced_target_hit_rate:.1%}")
    print(f"{B}   Review Noise:               {pr_summary.total_review_noise}")
    print(f"{B}   Capability Noise:           {pr_summary.total_capability_noise}")
    print(f"{B}   Cases Evaluated:            {pr_summary.cases_evaluated}")
    if pr_summary.cases_skipped:
        print(f"{B}   Cases Skipped:              {pr_summary.cases_skipped}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"{B} Results written to {output_path}")
    print(f"{B} Raw artifacts written to {artifacts_root}")
    return 0
