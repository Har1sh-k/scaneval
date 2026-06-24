# SB-TS-RG-011: SSRF via WebSocket upgrade proxying in Next.js self-hosted router-server

## Advisory
- Repo: `vercel/next.js`
- GHSA: `GHSA-c4j6-fc7j-m34r`
- CVE: `CVE-2026-44578`
- Vulnerable commit: `412eb90b6587ec02e8361c92efa9091487e7348f` (release v15.5.15)
- Fix commit: `c4f69086cc8dcbd81b1dbc321c98ea874d90d6f8` (release v15.5.16)

## Vulnerability
The upgrade handler proxies to parsedUrl based only on the presence of parsedUrl.protocol, without consulting the routing result that distinguishes intentional, trusted external rewrites from arbitrary attacker-controlled destinations. Because the same safety gating used for ordinary HTTP requests (the routing `finished` decision and absence of a terminal statusCode) is not applied here, a crafted upgrade request can steer parsedUrl to any host and the server will dial it.

## Source / Carrier / Sink
- Source: Attacker-controlled WebSocket/HTTP `upgrade` request (path/host) sent to the self-hosted Next.js Node origin server.
- Carrier: parsedUrl returned by resolveRoutes() for the upgrade request, carrying the protocol/host derived from the crafted request.
- Sink: proxyRequest(req, socket, parsedUrl, head) on line 834, which opens a proxied connection to parsedUrl's host.
- Missing guard: No check that routing finished and explicitly authorized an external rewrite (the fix's `finished && !statusCode` gate); the upgrade path trusts parsedUrl.protocol alone.

## Fix
The fix destructures `finished` and `statusCode` from resolveRoutes() and only proxies the upgrade when `finished && parsedUrl.protocol && !statusCode`; otherwise it ends the socket. This mirrors the safety checks already applied to normal HTTP requests so upgrades are only proxied when routing has explicitly marked them as safe external rewrites.

## Scanner Expectation
Flag the flow from the attacker-influenced upgrade request URL (parsedUrl) into proxyRequest() as an SSRF (CWE-918) sink lacking a routing-authorized / allowlisted-destination guard.
