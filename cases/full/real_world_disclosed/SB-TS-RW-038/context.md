# SB-TS-RW-038: MCP loopback owner context is derived from the spoofable x-openclaw-sender-is-owner request header

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-r6xh-pqhr-v4xh`
- CVE: `CVE-2026-44118`
- Vulnerable commit: `f788c88b4c508c335336fb292afed8c900656d6d` (release v2026.4.21)
- Fix commit: `3cb1a56bfc9579a0f2336f9cfa12a8a744332a19` (release v2026.4.22)

## Vulnerability
Owner status was taken from a request header that the client fully controls rather than from an authenticated, server-side trust signal. The loopback path issued one shared token regardless of caller privilege, so a non-owner loopback client could simply assert senderIsOwner=true via the header and pass owner checks.

## Source / Carrier / Sink
- Source: A non-owner client on the MCP loopback HTTP path setting the x-openclaw-sender-is-owner request header.
- Carrier: resolveMcpRequestContext() copies the header value into McpRequestContext.senderIsOwner used by owner-gated MCP handlers.
- Sink: Owner-gated MCP operations that branch on requestContext.senderIsOwner and execute privileged actions for an apparent owner.
- Missing guard: senderIsOwner is not bound to an authenticated trust signal (per-privilege token); it is taken verbatim from an attacker-settable header.

## Fix
The fix issues two distinct loopback bearer tokens (owner and non-owner) and derives senderIsOwner exclusively from which token authenticated the request inside validateMcpLoopbackRequest; resolveMcpRequestContext now takes the authenticated { senderIsOwner } value instead of reading the header. The spoofable x-openclaw-sender-is-owner header is no longer emitted or trusted.

## Scanner Expectation
Flag resolveMcpRequestContext at lines 165-180 as an authentication/authorization bypass: a security-relevant owner flag is derived from a client-controlled request header (x-openclaw-sender-is-owner) and flows into owner-gated decisions.
