# SB-TS-RW-061: OpenClaw resolveGroupToolPolicy accepted unvalidated caller-supplied group IDs

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-985f-72mj-8gf7`
- CVE: `CVE-2026-53863`
- Vulnerable commit: `cbcfdf62c7297bda66009ea7476f053c3e9addab` (release v2026.4.24)
- Fix commit: `665b0ef542ef9a6df9b5bfd5e9373fd8d9ace121` (release v2026.4.25)

## Vulnerability
Group-policy resolution treated the caller-controlled group id as authoritative instead of validating it against server-verified session/spawnedBy context. Because the fail-closed trust check was implemented in only one consumer, other call paths (and direct/subagent/cron sessions that encode no group) could opt into or widen group-scoped tool availability by passing an attacker-chosen groupId.

## Source / Carrier / Sink
- Source: Caller-supplied group identifier params.groupId passed into resolveGroupToolPolicy.
- Carrier: buildScopedGroupIdCandidates(params.groupId) merged into the groupIds list used to look up plugin and config group tool policy.
- Sink: Group-scoped tool policy decision returned by resolveGroupToolPolicy (plugin?.groups?.resolveToolPolicy and resolveChannelGroupToolsPolicy) and applied to a tool invocation.
- Missing guard: No validation of params.groupId against server-derived session/spawnedBy group context inside resolveGroupToolPolicy (the resolveTrustedGroupId fail-closed check existed only in the effective-tool-policy caller).

## Fix
The trust check was centralized: resolveTrustedGroupId(Params) was moved into pi-tools.policy.ts and invoked inside resolveGroupToolPolicy itself, so the caller groupId is resolved against session/spawn-derived group ids and dropped (fail closed) when no server-derived context vouches for it, and group-only metadata (groupChannel/groupSpace) is stripped when dropped. Server-derived ids are now ordered first so a trusted parent candidate cannot skip a more-specific session policy.

## Scanner Expectation
Flag authorization-relevant policy resolution keyed on an unvalidated, user-controlled group identifier (CWE-639 authorization bypass through user-controlled key): the group id should be checked against trusted session context before being used to select tool policy.
