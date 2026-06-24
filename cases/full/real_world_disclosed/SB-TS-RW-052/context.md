# SB-TS-RW-052: OpenClaw Discord allowFrom resolved allowlist entries against mutable user display names

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-cw4q-gqg5-g38h`
- CVE: `CVE-2026-53849`
- Vulnerable commit: `c97b9f79ec43b531a3472c3219ca51efbf7695a3` (release v2026.5.6)
- Fix commit: `ff80167e5a29c8111fd26c4948a8ab775d411c37` (release v2026.5.12)

## Vulnerability
The allowlist resolution always performed name-based user lookup, binding the allowFrom policy to mutable Discord display/global-name metadata that an attacker controls on their own account. An attacker can change their display name to match a configured allowlist entry and thereby be resolved to an allowed identity.

## Source / Carrier / Sink
- Source: A Discord account that can set its display name or global name to a value matching a configured allowFrom entry.
- Carrier: resolveDiscordAllowlistConfig unconditionally calls resolveAllowFromByUserAllowlist / resolveGuildEntriesByUserAllowlist, which resolve allowlist entries by user name via resolveDiscordUserAllowlist.
- Sink: The resolved allowFrom/guild allowlist authorizes the sender's Discord identity, granting agent access intended for another identity.
- Missing guard: No opt-in/feature gate restricting name-based allowlist matching; mutable display/global names were treated as valid allowlist match keys without operator consent.

## Fix
The fix gates the name-based resolution behind isDangerousNameMatchingEnabled(params.discordConfig): resolveAllowFromByUserAllowlist and resolveGuildEntriesByUserAllowlist are only invoked when the operator has explicitly opted into dangerous name matching. By default, allowlist entries are no longer resolved via mutable display/global names, so matching relies on stable Discord user IDs.

## Scanner Expectation
A scanner should flag the unconditional name-based allowlist resolution (resolveAllowFromByUserAllowlist binding allowFrom to mutable Discord display names) as an authentication/identity-binding flaw where a policy is matched against attacker-controllable metadata instead of a stable identifier.
