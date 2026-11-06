"""Fabricated engine and agent processes for the opt-in conformance test against a real RunSortie.

The real pinned RunSortie CLI starts these by name from PATH: ``npm run runtime -- bootstrap ...`` for
the Fieldglass engine and ``claude`` for both direct review roles. None of them calls a model or the
network. The engine writes Fieldglass-shaped evidence; the primary disposes every packet
as confirmed with a security argument citing real lines of the evaluated commit; the challenger agrees.

Invoked as ``fake_tools.py <npm|npm-empty|pi|claude|claude-inconclusive> <arguments...>``;
``npm-empty`` emits a valid zero-finding engine result and the last mode is a challenger that returns
INCONCLUSIVE, for the negative conformance case.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys


def claim(path: str) -> dict:
    return {"status": "established", "summary": "fabricated deterministic claim",
            "evidence": [{"path": path, "startLine": 1, "endLine": 2}]}


def argument(revision: str, packet_id: str, packet_hash: str, path: str) -> dict:
    return {"version": 1, "sourceRevision": revision, "packetId": packet_id, "packetEvidenceHash": packet_hash,
            "attackerCapability": claim(path), "violatedControl": claim(path), "authorityDelta": claim(path),
            "securityConsequence": claim(path)}


def engine(args: list[str], *, empty: bool = False) -> int:
    repo = Path(args[args.index("--repo") + 1])
    head = args[args.index("--head") + 1]
    out = repo / ".fieldglass"
    (out / "findings").mkdir(parents=True, exist_ok=True)
    findings = () if empty else (("FG-API-CMDI-0001", "critical"), ("FG-API-INFO-0002", "low"))
    for identifier, severity in findings:
        evidence = "class=command_injection"
        record = "\n".join([
            "---", f"id: {identifier}", f"title: Fabricated {identifier}", "vulnerability_class: command_injection",
            f"severity: {severity}", "status: open", "component: api", "file_path: src/app.py", "confidence: 0.9",
            "crown_jewel: false", "scanner_sources: [llm-bootstrap@1]", f"fingerprint: {identifier.lower()}",
            "root_cause_fingerprint_version: 2", f"root_cause_fingerprint: {hashlib.sha256(identifier.encode()).hexdigest()[:24]}",
            f"root_cause_evidence_hash: {hashlib.sha256(evidence.encode()).hexdigest()}",
            "root_cause_identity_status: exact", f"root_cause_evidence: [{evidence}]", "---",
            f"# Fabricated {identifier}", "", "## Reasoning", "Deterministic fixture finding.", ""])
        (out / "findings" / f"{identifier.lower()}.md").write_text(record, encoding="utf-8")
    (out / "threat-model.md").write_text("# Threat model\n", encoding="utf-8")
    (out / "scan-log.md").write_text("# Scan Log\n", encoding="utf-8")
    (out / "baseline-acceptance.json").write_text(json.dumps({
        "policyVersion": 1, "status": "accepted", "checkpointEligible": True, "reasons": [], "sourceHead": head}) + "\n")
    (out / ".state.json").write_text(json.dumps({"lastBatchHead": head}) + "\n")
    budget = os.environ.get("FIELDGLASS_WORK_BUDGET")
    if budget:
        state = write_budget_state(json.loads(budget))
        (out / "fieldglass-work-budget.json").write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": {"mode": "bootstrap", "fabricated": True}}))
    return 0


def write_budget_state(spec: dict) -> dict:
    """The engine's budget state RunSortie syncs: bound to the spec, sealed as ``work-budget.ts`` seals it."""
    limits = spec["limits"]
    calls = limits.get("modelCalls", {})
    state = {"version": 1, "runId": spec["runId"], "startedAt": spec["startedAt"], "updatedAt": spec["startedAt"],
             **({"deadlineAt": spec["deadlineAt"]} if "deadlineAt" in spec else {}), "limits": limits,
             "status": "complete",
             "modelCalls": {role: {**({"limit": calls[role]} if role in calls else {}), "reserved": 0}
                            for role in ("planner", "validation", "specialist", "consensus")},
             "modelFiles": {**({"limit": limits["maxModelFiles"]} if "maxModelFiles" in limits else {}), "reserved": 0},
             "modelFileHashes": [], "exhaustions": []}
    payload = json.dumps(state, separators=(",", ":"), ensure_ascii=False)
    state["integrity"] = hashlib.sha256(payload.encode()).hexdigest()
    path = Path(spec["stateFile"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return state


def primary(args: list[str]) -> int:
    prompt = sys.stdin.read()
    repo = Path.cwd()
    revision = re.search(r"source revision ([0-9a-f]{40})", prompt).group(1)
    target = re.search(r"RUNSORTIE_DONE:([^:\s]+):evidence-updated", prompt).group(1)
    plan = json.loads((repo / ".fieldglass" / "primary-review-packets.json").read_text(encoding="utf-8"))
    dispositions = [{"packetId": packet["packetId"], "packetEvidenceHash": packet["packetEvidenceHash"],
                     "disposition": "confirmed", "rationale": "fabricated confirmation",
                     "securityArgument": argument(revision, packet["packetId"], packet["packetEvidenceHash"], "src/app.py")}
                    for packet in plan["packets"]]
    (repo / ".fieldglass" / "sortie-state.json").write_text(json.dumps({
        "primaryReviewPacketDispositionVersion": 2, "primaryReviewPacketDispositions": dispositions}, indent=2) + "\n")
    (repo / ".fieldglass" / "sortie-review.md").write_text("# Fabricated review\n\nAll packets confirmed.\n")
    print(f"RUNSORTIE_DONE:{target}:evidence-updated")
    return 0


def challenger(args: list[str], verdict: str = "CONFIRMED VULNERABLE") -> int:
    if args[:1] == ["--version"]:
        print("2.1.310 (Claude Code)")
        return 0
    if args[:2] == ["auth", "status"]:
        print(json.dumps({"loggedIn": True, "authMethod": "api_key", "apiProvider": "firstParty",
                          "apiKeySource": "ANTHROPIC_API_KEY"}))
        return 0
    prompt = sys.stdin.read()
    binding = re.search(r'"sourceRevision":"([0-9a-f]{40})","packetId":"(RCP-[0-9a-f]{24})","packetEvidenceHash":"([0-9a-f]{64})"',
                        prompt)
    revision, packet_id, packet_hash = binding.groups()
    supplied = argument(revision, packet_id, packet_hash, "src/app.py")
    if verdict == "INCONCLUSIVE":
        supplied["violatedControl"] = {"status": "unknown", "summary": "fabricated uncertainty", "evidence": []}
    print(json.dumps({"verdict": verdict, "explanation": "fabricated challenger", "securityArgument": supplied}))
    return 0


def main(argv: list[str]) -> int:
    tool, args = argv[0], argv[1:]
    if tool == "npm":
        if args[:1] == ["--version"]:
            print("10.0.0-fabricated")
            return 0
        if args[:3] == ["run", "runtime", "--"] and args[3] == "bootstrap":
            return engine(args[4:])
        print(f"fabricated npm refuses {args}", file=sys.stderr)
        return 1
    if tool == "npm-empty":
        if args[:1] == ["--version"]:
            print("10.0.0-fabricated")
            return 0
        if args[:3] == ["run", "runtime", "--"] and args[3] == "bootstrap":
            return engine(args[4:], empty=True)
        print(f"fabricated npm refuses {args}", file=sys.stderr)
        return 1
    if tool == "pi":
        if args[:1] == ["--version"]:
            print("1.4.0")
            return 0
        if args[:1] == ["--help"]:
            print("--no-tools --no-extensions --no-mcp --no-skills --no-prompt-templates --no-themes --no-context-files --no-approve")
            return 0
        return 0
    if tool in ("claude", "claude-inconclusive"):
        if args[:1] == ["--version"]:
            print("2.1.310 (Claude Code)")
            return 0
        if args[:1] == ["--help"]:
            print("--bare skip hooks, background prefetches, keychain reads; Anthropic auth is strictly ANTHROPIC_API_KEY")
            print("--restricted removes the built-in command tools and WebFetch unless --tools names them; confines the file tools to working directories")
            print("--strict-mcp-config ignoring all other MCP configurations")
            print("--tools <tools...> Specify the list of available tools")
            print("--permission-prompts <target>: anything that would prompt is denied automatically")
            print("--disable-slash-commands")
            return 0
        if args[:3] == ["auth", "status", "--help"]:
            print("--json Output as JSON")
            return 0
        if args[:3] == ["auth", "status", "--json"] or args[:4] == ["--bare", "auth", "status", "--json"]:
            print(json.dumps({"loggedIn": True, "authMethod": "api_key", "apiProvider": "firstParty",
                              "apiKeySource": "ANTHROPIC_API_KEY"}))
            return 0
        permission = args[args.index("--permission-mode") + 1]
        if permission == "acceptEdits":
            return primary(args)
        if permission == "plan":
            return challenger(args, "INCONCLUSIVE" if tool == "claude-inconclusive" else "CONFIRMED VULNERABLE")
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
