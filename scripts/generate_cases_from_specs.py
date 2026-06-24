"""Generate real_world_disclosed case dirs from researched spec JSON.

Reads spec objects (as produced by the OpenClaw / other-repo research agents)
and writes cases/full/real_world_disclosed/<ID>/{case.json,context.md}.

Each spec object must have:
  cve, ghsa, repo, vulnerableCommit, vulnerableTag, fixCommit, fixTag,
  language, canonicalKind, filePathRelToRepoRoot, startLine, endLine,
  title, description, whyVulnerable, howFixed,
  source, carrier, sink, missingGuard, scannerExpectation  (vulnerableSnippet/confidence/evidence ignored)

Behaviour:
- Idempotent: specs whose (repo, ghsa) or (repo, cve) already exist as a case
  are skipped, so re-runs only add genuinely new cases.
- Skips specs whose language is not a SASTbench language or whose canonicalKind
  is not a canonical kind (reported, not built).
- Assigns IDs SB-<LANG>-RW-<NNN> continuing from the current per-language max.
- Disclosure dates are NOT written here; run backfill_disclosure_dates.py after.

Usage:
    python scripts/generate_cases_from_specs.py '.openclaw_build/results_batch*.json'
    python scripts/generate_cases_from_specs.py --dry-run '<glob>'
"""

import argparse
import glob
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DISCLOSED_DIR = REPO_ROOT / "cases" / "full" / "real_world_disclosed"
GENERIC_DIR = REPO_ROOT / "cases" / "full" / "real_world_generic"
ALL_CASES_GLOB = str(REPO_ROOT / "cases" / "full" / "**" / "case.json")

LANG_CODE = {
    "python": "PY", "typescript": "TS", "rust": "RS", "swift": "SW",
    "go": "GO", "java": "JV", "clojure": "CL",
}
VALID_KINDS = {"command_injection", "path_traversal", "ssrf", "auth_bypass", "authz_bypass", "sql_injection"}

CAPABILITY = {
    "command_injection": "code_execution",
    "path_traversal": "filesystem",
    "ssrf": "network",
    "auth_bypass": "authentication",
    "authz_bypass": "authorization",
    "sql_injection": "data_store",
}
ACCEPTED = {
    "command_injection": ["command_injection"],
    "path_traversal": ["path_traversal"],
    "ssrf": ["ssrf"],
    "auth_bypass": ["auth_bypass", "authz_bypass"],
    "authz_bypass": ["authz_bypass", "auth_bypass"],
    "sql_injection": ["sql_injection"],
}
OWASP = {
    "command_injection": {"primary": "ASI05", "secondary": ["ASI02"]},
    "path_traversal": {"primary": "ASI02"},
    "ssrf": {"primary": "ASI02"},
    "auth_bypass": {"primary": "ASI03"},
    "authz_bypass": {"primary": "ASI03"},
    "sql_injection": {"primary": "ASI02"},
}


def repo_dir_name(repo: str, commit: str) -> str:
    return f"{repo.replace('/', '_')}__{commit[:8]}"


def load_existing():
    """Return (covered, max_id, repo_class).

    covered: set of (repo, ghsa) / (repo, cve) already built.
    max_id: {(langCode, suffix): highest int} where suffix is RW or RG.
    repo_class: {repo: {"caseType": str, "generic": bool, "suffix": "RW"|"RG"}}
    """
    covered = set()
    max_id = {}
    repo_class = {}
    for cf in glob.glob(ALL_CASES_GLOB, recursive=True):
        d = json.load(open(cf, encoding="utf-8"))
        rw = d.get("realWorld", {})
        repo = rw.get("repo")
        ct = d.get("caseType")
        if repo:
            if rw.get("ghsa"):
                covered.add((repo, rw["ghsa"]))
            if rw.get("cve"):
                covered.add((repo, rw["cve"]))
            if ct in ("real_world_generic", "real_world_disclosed") and repo not in repo_class:
                generic = ct == "real_world_generic"
                repo_class[repo] = {
                    "caseType": ct,
                    "generic": generic,
                    "suffix": "RG" if generic else "RW",
                }
        m = re.match(r"^SB-([A-Z]{2})-(RW|RG)-(\d{3})$", d.get("id", ""))
        if m:
            key = (m.group(1), m.group(2))
            max_id[key] = max(max_id.get(key, 0), int(m.group(3)))
    return covered, max_id, repo_class


def build_case(spec: dict, case_id: str, generic: bool) -> dict:
    kind = spec["canonicalKind"]
    case = {
        "schemaVersion": "1.0.0",
        "id": case_id,
        "track": "full",
        "caseType": "real_world_generic" if generic else "real_world_disclosed",
    }
    if generic:
        case["agentic"] = False
    case.update({
        "language": spec["language"],
        "canonicalKind": kind,
        "title": spec["title"],
        "description": spec["description"],
        "files": {"root": f"../../../../.repos/{repo_dir_name(spec['repo'], spec['vulnerableCommit'])}/"},
        "regions": [{
            "id": "R1",
            "path": spec["filePathRelToRepoRoot"],
            "startLine": int(spec["startLine"]),
            "endLine": int(spec["endLine"]),
            "label": "vulnerable",
            "capability": CAPABILITY[kind],
            "acceptedKinds": ACCEPTED[kind],
        }],
        "expectedOutcome": {"mustDetectRegionIds": ["R1"], "mustNotFlagRegionIds": []},
        "realWorld": {
            "repo": spec["repo"],
            "vulnerableCommit": spec["vulnerableCommit"],
            "fixCommit": spec["fixCommit"],
            "ghsa": spec.get("ghsa", "") or "",
            "cve": spec.get("cve", "") or "",
        },
    })
    # OWASP Agentic Top 10 mapping is only meaningful for agentic cases;
    # real_world_generic cases carry no such mapping (matches existing convention).
    if not generic:
        case["standards"] = {"owaspAgenticTop10": OWASP[kind]}
    return case


def build_context(spec: dict, case_id: str) -> str:
    return f"""# {case_id}: {spec['title']}

## Advisory
- Repo: `{spec['repo']}`
- GHSA: `{spec.get('ghsa','')}`
- CVE: `{spec.get('cve','')}`
- Vulnerable commit: `{spec['vulnerableCommit']}` (release {spec.get('vulnerableTag') or '?'})
- Fix commit: `{spec['fixCommit']}` (release {spec.get('fixTag') or '?'})

## Vulnerability
{spec['whyVulnerable']}

## Source / Carrier / Sink
- Source: {spec['source']}
- Carrier: {spec['carrier']}
- Sink: {spec['sink']}
- Missing guard: {spec['missingGuard']}

## Fix
{spec['howFixed']}

## Scanner Expectation
{spec['scannerExpectation']}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate cases from researched specs")
    parser.add_argument("specs_glob", help="Glob for spec JSON files (each a list of spec objects)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    specs = []
    for f in sorted(glob.glob(args.specs_glob)):
        specs.extend(json.load(open(f, encoding="utf-8")))
    specs.sort(key=lambda s: (s["repo"], s["cve"]))

    covered, max_id, repo_class = load_existing()
    created, skipped_dup, skipped_bad = [], [], []

    for spec in specs:
        repo = spec["repo"]
        # Only dedup on non-empty identifiers; an empty ghsa/cve must not collide
        # on (repo, "") and falsely mark distinct advisories as duplicates.
        key_ghsa = (repo, spec["ghsa"]) if spec.get("ghsa") else None
        key_cve = (repo, spec["cve"]) if spec.get("cve") else None
        if (key_ghsa and key_ghsa in covered) or (key_cve and key_cve in covered):
            skipped_dup.append(spec.get("cve") or spec.get("ghsa"))
            continue
        if spec["language"] not in LANG_CODE or spec["canonicalKind"] not in VALID_KINDS:
            skipped_bad.append(f"{spec.get('cve')} (lang={spec['language']}, kind={spec['canonicalKind']})")
            continue
        if not spec.get("fixCommit") or not spec.get("vulnerableCommit"):
            skipped_bad.append(f"{spec.get('cve') or spec.get('ghsa')} (missing commit: fix={spec.get('fixCommit')!r} vuln={spec.get('vulnerableCommit')!r})")
            continue

        cls = repo_class.get(repo, {"generic": False, "suffix": "RW"})
        if repo not in repo_class:
            print(f"  NOTE: {repo} not previously in benchmark; defaulting to real_world_disclosed (-RW-)")
        generic = cls["generic"]
        suffix = cls["suffix"]
        code = LANG_CODE[spec["language"]]
        key = (code, suffix)
        max_id[key] = max_id.get(key, 0) + 1
        case_id = f"SB-{code}-{suffix}-{max_id[key]:03d}"

        case = build_case(spec, case_id, generic)
        context = build_context(spec, case_id)
        if key_ghsa:
            covered.add(key_ghsa)
        if key_cve:
            covered.add(key_cve)
        created.append((case_id, spec.get("cve") or spec.get("ghsa"), spec["canonicalKind"]))

        if not args.dry_run:
            parent = GENERIC_DIR if generic else DISCLOSED_DIR
            d = parent / case_id
            d.mkdir(parents=True, exist_ok=True)
            (d / "case.json").write_text(json.dumps(case, indent=2) + "\n", encoding="utf-8")
            (d / "context.md").write_text(context, encoding="utf-8")

    verb = "Would create" if args.dry_run else "Created"
    print(f"{verb} {len(created)} cases:")
    for cid, cve, kind in created:
        print(f"  {cid}  {cve}  {kind}")
    if skipped_dup:
        print(f"\nSkipped {len(skipped_dup)} already-covered: {', '.join(skipped_dup)}")
    if skipped_bad:
        print(f"\nSkipped {len(skipped_bad)} unmappable:")
        for s in skipped_bad:
            print(f"  {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
