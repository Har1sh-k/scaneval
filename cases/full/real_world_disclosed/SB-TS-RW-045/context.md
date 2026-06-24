# SB-TS-RW-045: OpenClaw MCP Streamable HTTP transport forwarded operator-configured custom headers across cross-origin redirects

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-rjxq-qqhf-8hwh`
- CVE: `CVE-2026-53840`
- Vulnerable commit: `eeef4864494f859838fec1586bedbab1f8fa5702` (release v2026.5.7)
- Fix commit: `47eb2d48d43452afc4b0160e40a2630e4a38a0ff` (release v2026.5.12)

## Vulnerability
The streamable-http transport hands the SDK requestInit headers and relies on the default fetch, which auto-follows 3xx redirects while retaining request headers. There is no cross-origin check or header-scrubbing on redirect, so configured MCP credentials are sent to whatever origin the endpoint redirects to.

## Source / Carrier / Sink
- Source: Operator-configured MCP server custom headers (mcp.servers.*.headers), e.g. API keys / tenant-routing headers
- Carrier: requestInit.headers passed to StreamableHTTPClientTransport, carried through the default redirect-following fetch
- Sink: Outbound HTTP request to the cross-origin redirect Location target
- Missing guard: No same-origin check or header scrubbing on cross-origin redirect for the streamable-http transport (no custom fetch supplied)

## Fix
The fix adds a custom fetchStreamableHttpWithRedirectScrub fetch (passed as the transport's fetch option) that follows redirects manually, and when the redirect target origin differs from the current origin it strips sensitive headers via retainSafeHeadersForCrossOriginRedirect, also bounding redirect count and detecting loops.

## Scanner Expectation
Flag that operator-configured custom headers attached to the Streamable HTTP MCP transport can be forwarded to a cross-origin redirect target because no redirect-aware fetch / header-scrubbing guard is present.
