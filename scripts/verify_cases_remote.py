"""Independent remote verification of real-world case metadata against GitHub.

For each real-world case this re-checks, via `gh api` (no clone, no trust in how
the case was authored):

  - realWorld.vulnerableCommit resolves to a real commit
  - realWorld.fixCommit resolves to a real commit
  - realWorld.disclosure.fixCommitDate equals the fixCommit's committer date
  - realWorld.disclosure.ghsaPublished equals the advisory's published_at (when
    the GHSA is resolvable in the global DB)
  - every region's file exists at vulnerableCommit and its line range fits inside
    the file (startLine >= 1, startLine <= endLine <= file length)

Usage:
    python scripts/verify_cases_remote.py            # all real-world cases
    python scripts/verify_cases_remote.py --new-only # only cases not on origin/main
"""

import argparse
import base64
import glob
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor

REAL_WORLD = ("real_world_disclosed", "real_world_generic")


def gh(path):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def commit_date(repo, sha):
    rc, out, _ = gh(f"/repos/{repo}/commits/{sha}")
    if rc != 0:
        return None, f"commit {sha[:10]} not found"
    try:
        return json.loads(out)["commit"]["committer"]["date"][:10], None
    except Exception as e:
        return None, f"commit {sha[:10]} parse error: {e}"


def file_line_count(repo, path, ref):
    rc, out, err = gh(f"/repos/{repo}/contents/{path}?ref={ref}")
    if rc != 0:
        return None, f"file missing at {ref[:10]}: {path}"
    try:
        d = json.loads(out)
    except Exception:
        return None, f"file response parse error: {path}"
    if isinstance(d, list):
        return None, f"path is a directory: {path}"
    if d.get("encoding") != "base64" or not d.get("content"):
        return None, f"file content unavailable (large/binary?): {path}"
    text = base64.b64decode(d["content"]).decode("utf-8", "replace")
    return len(text.splitlines()), None


def advisory_published(ghsa):
    rc, out, _ = gh(f"/advisories/{ghsa}")
    if rc != 0:
        return None
    try:
        return (json.loads(out).get("published_at") or "")[:10] or None
    except Exception:
        return None


def verify(case):
    cid = case["id"]
    rw = case.get("realWorld", {})
    repo = rw.get("repo")
    disc = rw.get("disclosure", {})
    issues = []

    vc, fc = rw.get("vulnerableCommit"), rw.get("fixCommit")
    if not vc:
        issues.append("missing vulnerableCommit")
    if not fc:
        issues.append("missing fixCommit")

    if fc:
        fdate, err = commit_date(repo, fc)
        if err:
            issues.append(err)
        elif disc.get("fixCommitDate") and disc["fixCommitDate"] != fdate:
            issues.append(f"fixCommitDate {disc['fixCommitDate']} != actual {fdate}")

    if vc:
        vdate, err = commit_date(repo, vc)
        if err:
            issues.append(err)
        else:
            for r in case["regions"]:
                n, ferr = file_line_count(repo, r["path"], vc)
                if ferr:
                    issues.append(ferr)
                    continue
                if r["startLine"] < 1 or r["startLine"] > r["endLine"]:
                    issues.append(f"region {r['id']} bad range {r['startLine']}-{r['endLine']}")
                elif r["endLine"] > n:
                    issues.append(f"region {r['id']} endLine {r['endLine']} > file len {n}")

    if disc.get("ghsaPublished") and rw.get("ghsa"):
        pub = advisory_published(rw["ghsa"])
        if pub and pub != disc["ghsaPublished"]:
            issues.append(f"ghsaPublished {disc['ghsaPublished']} != advisory {pub}")

    return cid, repo, issues


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--new-only", action="store_true", help="Only cases absent from origin/main")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    new_set = None
    if args.new_only:
        r = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", "origin/main", "cases/"],
            capture_output=True, text=True,
        )
        on_main = set(r.stdout.splitlines())
        new_set = on_main  # case.json paths present on main

    cases = []
    for cf in glob.glob("cases/full/**/case.json", recursive=True):
        c = json.load(open(cf))
        if c.get("caseType") not in REAL_WORLD:
            continue
        if new_set is not None and cf in new_set:
            continue
        cases.append(c)

    print(f"Verifying {len(cases)} real-world cases against GitHub...\n")
    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for cid, repo, issues in ex.map(verify, cases):
            results.append((cid, repo, issues))

    failed = [r for r in results if r[2]]
    for cid, repo, issues in sorted(failed):
        print(f"FAIL {cid} ({repo})")
        for i in issues:
            print(f"      - {i}")

    print(f"\n{len(results) - len(failed)}/{len(results)} cases verified clean; {len(failed)} with issues.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
