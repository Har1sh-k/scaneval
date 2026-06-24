# SB-TS-RW-039: Owner-enforced commands accept wildcard channel senders as command owner

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-c28g-vh7m-fm7v`
- CVE: `CVE-2026-44991`
- Vulnerable commit: `115f05d5952adeaa8043311c24c4b8a3803481ba` (release v2026.4.20)
- Fix commit: `995febb7b1e811ff6a1df5b18c22de94103f4c9f` (release v2026.4.21)

## Vulnerability
The owner-command decision reused the channel's inbound wildcard allowFrom as if it were a command-owner grant. With enforceOwnerForCommands set but no explicit ownerAllowFrom, the fallback treats ownerState.allowAll (the inbound wildcard) and an empty owner-candidate list as sufficient owner authorization, so wildcard inbound senders are authorized as command owners.

## Source / Carrier / Sink
- Source: A non-owner sender on a channel that accepts wildcard inbound senders (allowFrom: ["*"]) where the plugin enforces owner-only commands but no commands.ownerAllowFrom is set.
- Carrier: resolveCommandAuthorization() computes isOwnerForCommands via a fallback that returns true when ownerState.allowAll (the inbound wildcard) is set or no owner candidates exist.
- Sink: The owner-command authorization gate (isAuthorizedSender/isOwnerForCommands) permits execution of owner-enforced slash commands such as /send, /config, /debug.
- Missing guard: The owner-command decision did not require a concrete owner identity or operator-admin scope; it accepted the channel inbound wildcard (ownerState.allowAll) and an empty owner-candidate list as owner authorization.

## Fix
The fix replaces the fallback with 'senderIsOwnerByScope || Boolean(matchedCommandOwner)', requiring a concrete owner identity (matchedCommandOwner) or internal operator-admin scope when owner-only commands are enforced. Wildcard channel allowFrom no longer implies wildcard command ownership.

## Scanner Expectation
Flag the isOwnerForCommands fallback at lines 703-711 as an authorization bypass: an owner-only authorization decision that resolves to true from a wildcard inbound allowlist (ownerState.allowAll) / empty owner-candidate set instead of a verified owner identity.
