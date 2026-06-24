"""Backfill public-knowledge disclosure dates onto real-world cases.

For each real_world_* case this records, under realWorld.disclosure:

    ghsaPublished  - GHSA advisory publication date (when a GHSA id is present)
    fixCommitDate  - author/committer date of realWorld.fixCommit

These feed the model-cutoff gate: a case "counts" for a model only when the
public-knowledge horizon = min(present disclosure dates) is strictly after the
model's knowledge cutoff (see scripts/cutoff.py and taxonomy/models.json).

Dates are sourced from the GitHub API via `gh api`, so `gh auth status` must be
green. Existing disclosure values are kept unless --overwrite is passed; this is
incremental and safe to re-run when new cases are added.

The realWorld object is re-serialized and spliced back in place so the rest of
each case.json (notably inline region arrays) is left byte-for-byte unchanged.

Usage:
    python scripts/backfill_disclosure_dates.py
    python scripts/backfill_disclosure_dates.py --overwrite
    python scripts/backfill_disclosure_dates.py --dry-run
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_CASES_DIR = REPO_ROOT / "cases" / "full"


def gh_api(path: str, jq: str) -> tuple[str | None, str | None]:
    """Return (value, error) from a `gh api <path> --jq <jq>` call."""
    proc = subprocess.run(
        ["gh", "api", path, "--jq", jq],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None, proc.stderr.strip() or f"exit {proc.returncode}"
    out = proc.stdout.strip()
    return (out or None), None


def date_only(iso: str | None) -> str | None:
    """Convert an ISO 8601 timestamp to a YYYY-MM-DD date string."""
    if not iso:
        return None
    return iso.split("T", 1)[0]


def fetch_disclosure(real_world: dict) -> tuple[dict, list[str]]:
    """Look up disclosure dates for a realWorld block. Returns (dates, warnings)."""
    dates: dict[str, str] = {}
    warnings: list[str] = []

    ghsa = real_world.get("ghsa")
    if ghsa:
        published, err = gh_api(f"/advisories/{ghsa}", ".published_at")
        if published:
            dates["ghsaPublished"] = date_only(published)
        else:
            warnings.append(f"ghsa {ghsa}: {err}")

    repo = real_world.get("repo")
    fix_commit = real_world.get("fixCommit")
    if repo and fix_commit:
        committed, err = gh_api(
            f"/repos/{repo}/commits/{fix_commit}", ".commit.committer.date"
        )
        if committed:
            dates["fixCommitDate"] = date_only(committed)
        else:
            warnings.append(f"commit {repo}@{fix_commit[:10]}: {err}")

    return dates, warnings


def splice_real_world(text: str, new_real_world: dict) -> str:
    """Replace the realWorld object in case.json text with a re-serialized version.

    Only the realWorld object is reformatted; everything else (including inline
    region arrays) is preserved exactly. realWorld contains no arrays, so its
    re-serialization is stable.
    """
    key = '"realWorld"'
    key_idx = text.index(key)
    brace_start = text.index("{", key_idx)

    depth = 0
    in_string = False
    escape = False
    brace_end = -1
    for i in range(brace_start, len(text)):
        ch = text[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                brace_end = i
                break
    if brace_end == -1:
        raise ValueError("could not find end of realWorld object")

    serialized = json.dumps(new_real_world, indent=2)
    lines = serialized.split("\n")
    # realWorld is nested one level (2 spaces) under the top-level object, so
    # every line after the opening brace gets 2 extra spaces of indentation.
    reindented = lines[0] + "\n" + "\n".join("  " + line for line in lines[1:])

    return text[:brace_start] + reindented + text[brace_end + 1:]


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill disclosure dates onto real-world cases")
    parser.add_argument("--overwrite", action="store_true",
                        help="Re-fetch and replace existing disclosure values")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would change without writing files")
    args = parser.parse_args()

    case_files = sorted(FULL_CASES_DIR.rglob("case.json"))
    real_world = [
        cf for cf in case_files
        if json.loads(cf.read_text()).get("caseType", "").startswith("real_world")
    ]

    print(f"Found {len(real_world)} real-world cases.\n")

    updated = 0
    skipped = 0
    all_warnings: list[str] = []
    horizon_rows: list[tuple[str, str | None]] = []

    for cf in real_world:
        case = json.loads(cf.read_text())
        case_id = case["id"]
        rw = case.get("realWorld", {})

        existing = rw.get("disclosure", {})
        if existing and not args.overwrite:
            skipped += 1
            horizon = min(existing.values()) if existing else None
            horizon_rows.append((case_id, horizon))
            continue

        dates, warnings = fetch_disclosure(rw)
        for w in warnings:
            all_warnings.append(f"{case_id}: {w}")

        if not dates:
            print(f"  {case_id}: NO DATES FOUND (skipping write)")
            horizon_rows.append((case_id, None))
            continue

        # Rebuild realWorld with disclosure appended last, preserving field order.
        new_rw = {k: v for k, v in rw.items() if k != "disclosure"}
        new_rw["disclosure"] = dates

        horizon = min(dates.values())
        horizon_rows.append((case_id, horizon))

        text = cf.read_text()
        new_text = splice_real_world(text, new_rw)

        if args.dry_run:
            print(f"  {case_id}: would set {dates}")
        else:
            cf.write_text(new_text)
            print(f"  {case_id}: {dates}")
        updated += 1

    print(f"\nUpdated {updated}, skipped {skipped} (already had disclosure).")

    if all_warnings:
        print(f"\n{len(all_warnings)} warning(s):")
        for w in all_warnings:
            print(f"  WARN {w}")

    print("\nHorizon (min disclosure date) per case:")
    for case_id, horizon in sorted(horizon_rows, key=lambda r: (r[1] or "")):
        print(f"  {horizon or '????-??-??'}  {case_id}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
