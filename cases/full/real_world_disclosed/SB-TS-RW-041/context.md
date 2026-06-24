# SB-TS-RW-041: ACP child sessions do not inherit subagent security envelope constraints in spawnAcpDirect

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-q3jj-46pq-826r`
- CVE: `CVE-2026-44997`
- Vulnerable commit: `f788c88b4c508c335336fb292afed8c900656d6d` (release v2026.4.21)
- Fix commit: `31160dc069b7cc5d833b39c53736a41ad3befda2` (release v2026.4.22)

## Vulnerability
The ACP spawn path is a distinct code path from the regular subagent spawn path and never threaded the subagent envelope through it, so depth/child-count caps and control-scope/target-agent restrictions that apply to subagents were silently dropped. Because the child sessions.patch wrote no envelope fields, the new ACP child session was created with default (unrestricted) capabilities even when its parent was a constrained subagent.

## Source / Carrier / Sink
- Source: A restricted subagent session invoking sessions_spawn with runtime="acp" (attacker-influenced agent acting within a constrained subagent envelope).
- Carrier: spawnAcpDirect requester-state resolution and the gateway sessions.patch payload that creates the child ACP session.
- Sink: Creation of the ACP child session via callGateway sessions.patch with no envelope fields, plus absence of any depth/child-count enforcement before spawn.
- Missing guard: No resolution/enforcement of subagent envelope (max spawn depth, max active children, control scope, target-agent restriction) and no persistence of spawnDepth/subagentRole/subagentControlScope onto the child session.

## Fix
The fix resolves the subagent capability store, calls a new resolveAcpSubagentEnvelopeState that enforces DEFAULT_SUBAGENT_MAX_SPAWN_DEPTH and DEFAULT_SUBAGENT_MAX_CHILDREN_PER_AGENT and computes a childSessionPatch (spawnDepth, subagentRole, subagentControlScope). It rejects over-limit spawns with a new subagent_policy forbidden error and spreads childSessionPatch into the sessions.patch call so child ACP sessions inherit the parent's envelope.

## Scanner Expectation
Flag that a child session/subprocess is created from a privilege-constrained parent context without propagating or re-checking the parent's authorization envelope (insecure inherited permissions / missing authorization check on spawn).
