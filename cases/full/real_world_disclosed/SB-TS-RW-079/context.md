# SB-TS-RW-079: SSRF bypass via unprotected built-in http/https/net modules in Custom Function sandbox (utils.ts)

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-xhmj-rg95-44hv`
- CVE: `CVE-2026-41270`
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `b7e836cf14c3f39aea63a644a3db5cd47979cd37` (release flowise@3.1.0)

## Vulnerability
The SSRF mitigation only intercepts axios and node-fetch, but the same sandbox exposes the unwrapped Node core networking modules http, https, and net. User code can import those directly and reach internal/metadata services, so the deny-list protection is trivially circumvented.

## Source / Carrier / Sink
- Source: Authenticated user-supplied JavaScript executed via the Custom Function node (/api/v1/node-custom-function).
- Carrier: The NodeVM require.builtin list (defaultAllowBuiltInDep) exposes unwrapped http/https/net to the sandboxed code.
- Sink: http.request/https.request/net.connect to attacker-chosen internal hosts (e.g. 169.254.169.254 IMDS), bypassing axios/node-fetch deny-list wrappers.
- Missing guard: No SSRF wrapper for the built-in networking modules; they should not be allowlisted in the sandbox at all.

## Fix
Fix commit b7e836cf removes 'http', 'https', 'net', and 'tls' from defaultAllowBuiltInDep, leaving only non-networking built-ins (assert, buffer, crypto, events, path, querystring, timers, url, zlib). With the raw networking modules no longer importable in the sandbox, outbound HTTP must go through the secured axios/node-fetch wrappers that enforce the deny list.

## Scanner Expectation
Flag the inclusion of http/https/net (and tls) in the sandbox allowlist (defaultAllowBuiltInDep, lines 130-136) as exposing unguarded network egress, enabling SSRF that bypasses the axios/node-fetch deny-list controls.
