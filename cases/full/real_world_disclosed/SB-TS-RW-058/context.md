# SB-TS-RW-058: Hostname normalization stripped only one trailing dot, allowing blocklist evasion via repeated trailing dots

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-gxg4-2rrr-jhc7`
- CVE: `CVE-2026-53859`
- Vulnerable commit: `a374c3a5bfd5225ce319bce3865aab6216309c4f` (release v2026.5.22)
- Fix commit: `0314d67d87faf601ee291bbbe9b805db987a929f` (release v2026.5.27)

## Vulnerability
The trailing-dot stripping uses /\.$/ (single trailing dot) instead of /\.+$/ (all trailing dots), and a fully-qualified DNS name with a trailing dot resolves to the same host as the bare name but is not equal as a string. Because the SSRF/host blocklist compares against this normalized form, a host presented with a trailing dot bypasses the comparison and is treated as a different, non-blocked destination, enabling requests to private-network or metadata endpoints the policy intended to deny.

## Source / Carrier / Sink
- Source: model-/workspace-derived request URL hostname with a trailing dot (e.g. metadata.internal.)
- Carrier: normalizeHostname() canonicalizes the hostname but removes only one trailing dot, yielding a value that differs from the canonical blocked host
- Sink: SSRF/hostname blocklist comparison and the subsequent outbound fetch to the resolved host
- Missing guard: complete trailing-dot canonicalization (strip all trailing dots) before the blocklist comparison

## Fix
The fix changes the regex from /\.$/ to /\.+$/ so normalizeHostname() strips any number of trailing dots, producing a single canonical form for trailing-dot variants that the blocklist comparison then matches consistently.

## Scanner Expectation
Flag normalizeHostname() at lines 3-9 (the /\.$/ trailing-dot strip) as incomplete host canonicalization that lets trailing-dot hostnames evade the SSRF/blocklist comparison.
