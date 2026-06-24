# SB-TS-RW-056: OpenClaw Zalo (zalouser) allowFrom startup resolution matched entries against mutable friend/group display names without the dangerous-name-matching gate

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-8c59-hr4w-qg69`
- CVE: `CVE-2026-53857`
- Vulnerable commit: `8b2a6e57fef6c582ec6d27b85150616f9e3a7ba4` (release v2026.5.2)
- Fix commit: `ea75cd897182bef44da045be3ab51913ccfa4714` (release v2026.5.4)

## Vulnerability
allowFrom entries were resolved to concrete userIds by matching against mutable display names with no stable-identifier requirement and no dangerous-name-matching gate. A contact who changes their display name to match a configured entry is silently added to the effective allowlist, allowing identity confusion / unintended authorization.

## Source / Carrier / Sink
- Source: Zalo friend/contact and group directory entries (listZaloFriends / listZaloGroups) whose displayName/name are attacker-mutable.
- Carrier: byName index built from friend.displayName / group.name, against which non-numeric allowFrom/groupAllowFrom entries are matched in resolveUserAllowlistEntries.
- Sink: mergeAllowlist(...) updating account.config.allowFrom/groupAllowFrom (and the groups map) with userIds/groupIds resolved from mutable display names, forming the effective inbound authorization allowlist.
- Missing guard: A gate requiring isDangerousNameMatchingEnabled (opt-in) before resolving allowlist entries by mutable display names; default must restrict matching to stable identifiers.

## Fix
Fix commit ea75cd89 gates the display-name resolution behind allowNameMatching = isDangerousNameMatchingEnabled(account.config): both the friend allowFrom/groupAllowFrom name-resolution block and the group-name resolution block now run only when allowNameMatching is true, so by default only stable numeric identifiers resolve and mutable display names no longer bind allowlist entries.

## Scanner Expectation
Flag the startup allowlist resolution that maps allowFrom/groupAllowFrom entries to ids by matching mutable display names without the dangerous-name-matching opt-in, enabling identity-confusion authorization (CWE-290/863).
