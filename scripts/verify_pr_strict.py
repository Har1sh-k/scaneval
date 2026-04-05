"""Strict verifier for real_world_disclosed PR simulation data.

Checks every real_world_disclosed case against:
1. Snapshot is at realWorld.vulnerableCommit
2. headCommit contains the exact annotated vulnerable slice
3. baseCommit does NOT contain the exact annotated vulnerable slice
4. Fix is verified via one of two modes:
   - slice_absent (default): fixCommit must not contain the vulnerable slice
   - mitigation_anchor_present: fixCommit must contain declared anchor strings
     that the vulnerable commit does not, and the fix diff must touch anchor files

Usage:
    python scripts/verify_pr_strict.py
    python scripts/verify_pr_strict.py --case-id SB-PY-RW-001
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "cases" / "full" / "real_world_disclosed"
REPOS_DIR = REPO_ROOT / ".repos"


def git_show(repo: Path, commit: str, filepath: str) -> str | None:
    r = subprocess.run(
        ["git", "show", f"{commit}:{filepath}"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    return r.stdout if r.returncode == 0 else None


def git_diff_names(repo: Path, base: str, head: str) -> set[str]:
    r = subprocess.run(
        ["git", "diff", "--name-only", base, head],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return set()
    return set(r.stdout.strip().split("\n"))


def get_snapshot_commit(repo: Path) -> str | None:
    r = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    return r.stdout.strip() if r.returncode == 0 else None


def get_vuln_slice(repo: Path, commit: str, filepath: str, start: int, end: int) -> str | None:
    content = git_show(repo, commit, filepath)
    if not content:
        return None
    lines = content.split("\n")
    if end > len(lines):
        return None
    return "\n".join(lines[start - 1 : end])


def verify_fix_slice_absent(repo, fix, vc, regions, must_detect):
    """Default mode: fix commit must not contain the vulnerable slice."""
    ok = True
    details = []
    for region in regions:
        if region["id"] not in must_detect:
            continue
        fp, sl, el = region["path"], region["startLine"], region["endLine"]
        vuln_text = get_vuln_slice(repo, vc, fp, sl, el)
        if not vuln_text:
            continue
        fc = git_show(repo, fix, fp)
        if fc and vuln_text in fc:
            ok = False
            details.append(f"{region['id']}: fix {fix[:8]} still contains detection slice")
    return ok, details


def verify_fix_mitigation_anchor(repo, fix, vc, anchors):
    """Indirect mitigation mode: fix must contain declared anchors that vuln does not."""
    ok = True
    details = []
    # Check fix diff touches anchor files
    changed = git_diff_names(repo, vc, fix)
    for anchor in anchors:
        apath = anchor["path"]
        strings = anchor["mustContainAll"]

        # Fix must contain all anchor strings
        fix_content = git_show(repo, fix, apath)
        if not fix_content:
            ok = False
            details.append(f"anchor {apath}: file missing at fix {fix[:8]}")
            continue

        for s in strings:
            if s not in fix_content:
                ok = False
                details.append(f"anchor {apath}: fix missing '{s}'")

        # Vulnerable commit must NOT already contain all anchor strings
        vuln_content = git_show(repo, vc, apath)
        if vuln_content and all(s in vuln_content for s in strings):
            ok = False
            details.append(f"anchor {apath}: vulnerable commit already contains all anchors")

        # Fix diff must touch the anchor file
        if apath not in changed:
            ok = False
            details.append(f"anchor {apath}: not in fix diff")

    return ok, details


def verify_case(case_path: Path) -> dict:
    with open(case_path) as f:
        c = json.load(f)

    rw = c["realWorld"]
    pr = c.get("prSimulation", {})
    fv = c.get("fixValidation", {})
    cid = c.get("caseId", case_path.parent.name)
    vc = rw["vulnerableCommit"]
    fix = rw.get("fixCommit", "")
    base = pr.get("baseCommit", "")
    head = pr.get("headCommit", vc)
    repo = REPOS_DIR / f"{rw['repo'].replace('/', '_')}__{vc[:8]}"
    fv_mode = fv.get("mode", "slice_absent")

    result = {
        "caseId": cid,
        "snap_ok": False,
        "head_ok": True,
        "base_ok": True,
        "fix_mode": fv_mode,
        "fix_slice_ok": True,
        "fix_remediation_ok": True,
        "details": [],
    }

    if not repo.exists():
        result["details"].append("repo directory missing")
        return result

    # 1. Snapshot at vulnerableCommit
    snap = get_snapshot_commit(repo)
    result["snap_ok"] = bool(snap and snap.startswith(vc[:8]))
    if not result["snap_ok"]:
        result["details"].append(f"snapshot at {snap[:8] if snap else 'N/A'}, expected {vc[:8]}")

    must = set(c.get("expectedOutcome", {}).get("mustDetectRegionIds", []))
    regions = [r for r in c.get("regions", []) if r["id"] in must]

    for region in regions:
        fp = region["path"]
        sl, el = region["startLine"], region["endLine"]
        rid = region["id"]

        vuln_text = get_vuln_slice(repo, vc, fp, sl, el)
        if not vuln_text:
            result["details"].append(f"{rid}: cannot read vuln slice at vulnerableCommit")
            result["head_ok"] = False
            continue

        # 2. Head must contain vuln text
        hc = git_show(repo, head, fp)
        if not hc or vuln_text not in hc:
            result["head_ok"] = False
            result["details"].append(f"{rid}: head {head[:8]} missing detection slice")

        # 3. Base must NOT contain vuln text
        bc = git_show(repo, base, fp)
        if bc and vuln_text in bc:
            result["base_ok"] = False
            result["details"].append(f"{rid}: base {base[:8]} contains detection slice")

    # 4. Fix verification
    if fix:
        if fv_mode == "mitigation_anchor_present":
            anchors = fv.get("anchors", [])
            ok, dets = verify_fix_mitigation_anchor(repo, fix, vc, anchors)
            result["fix_remediation_ok"] = ok
            # Slice check is N/A for this mode but we still run it for reporting
            slice_ok, slice_dets = verify_fix_slice_absent(repo, fix, vc, c.get("regions", []), must)
            result["fix_slice_ok"] = slice_ok
            result["details"].extend(dets)
        else:
            ok, dets = verify_fix_slice_absent(repo, fix, vc, c.get("regions", []), must)
            result["fix_slice_ok"] = ok
            result["fix_remediation_ok"] = ok
            result["details"].extend(dets)

    result["strict"] = all([
        result["snap_ok"],
        result["head_ok"],
        result["base_ok"],
        result["fix_remediation_ok"],
    ])
    return result


def main():
    parser = argparse.ArgumentParser(description="Strict PR simulation verifier")
    parser.add_argument("--case-id", help="Verify a single case")
    args = parser.parse_args()

    case_files = sorted(CASES_DIR.rglob("case.json"))
    if args.case_id:
        case_files = [cf for cf in case_files if args.case_id in str(cf)]

    results = [verify_case(cf) for cf in case_files]
    total = len(results)

    snap_count = sum(1 for r in results if r["snap_ok"])
    head_count = sum(1 for r in results if r["head_ok"])
    base_count = sum(1 for r in results if r["base_ok"])
    slice_count = sum(1 for r in results if r["fix_slice_ok"])
    remediation_count = sum(1 for r in results if r["fix_remediation_ok"])
    strict_count = sum(1 for r in results if r["strict"])

    indirect = [r for r in results if r["fix_mode"] == "mitigation_anchor_present"]
    direct = [r for r in results if r["fix_mode"] == "slice_absent"]

    print(f"Remediation verified:       {strict_count}/{total}")
    print(f"  Snapshots at vulnCommit:  {snap_count}/{total}")
    print(f"  Head has detection slice:  {head_count}/{total}")
    print(f"  Base clean:                {base_count}/{total}")
    print(f"  Fix removes detect slice:  {slice_count}/{total} (direct slice-removal)")
    print(f"  Fix indirect mitigation:   {len([r for r in indirect if r['fix_remediation_ok']])}/{len(indirect)} anchor-verified")
    print(f"  Remediation verified:      {remediation_count}/{total}")

    for r in results:
        if not r["strict"]:
            print(f"\nFAIL {r['caseId']}:")
            for d in r["details"]:
                print(f"  {d}")

    return 0 if strict_count == total else 1


if __name__ == "__main__":
    sys.exit(main())
