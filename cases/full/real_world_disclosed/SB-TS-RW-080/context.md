# SB-TS-RW-080: Prompt-injection SSRF in Flowise POST API Chain (postCore.ts)

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-6r77-hqx7-7vw8`
- CVE: `CVE-2026-41271`
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `efffd12f161761790c4bfb7bb25771e0a6ff4b75` (release flowise@3.1.0)

## Vulnerability
The destination URL is derived from LLM output that is controllable via prompt-injected API documentation, and it is passed directly to secureFetch without any application-level validation of the target host. At 3.0.13 secureFetch's deny-list enforcement is opt-in (only active when HTTP_DENY_LIST is set), so the default configuration performs no SSRF filtering at all.

## Source / Carrier / Sink
- Source: Attacker-influenced LLM output (api_url_body) parsed into url, driven by prompt-injected api_docs.
- Carrier: url field flows from JSON.parse(api_url_body) directly into secureFetch().
- Sink: secureFetch(url, { method: 'POST', ... }) performs a server-side HTTP request to the LLM-chosen host.
- Missing guard: No allowlist of permitted hosts and, at 3.0.13, no default deny list for secureFetch (deny-list only active when HTTP_DENY_LIST is configured).

## Fix
Fix commit efffd12f introduces a built-in DEFAULT_DENY_LIST and getHttpDenyList() in packages/components/src/httpSecurity.ts so that secureFetch/secureAxiosRequest block loopback, link-local, and private ranges by default even when HTTP_DENY_LIST is unset. This closes the SSRF path because the LLM-supplied URL is now validated against a secure default deny list before the request is made (postCore.ts itself is unchanged).

## Scanner Expectation
Flag untrusted (LLM-derived) url flowing into a server-side fetch as SSRF at postCore.ts lines 91-99, with no host validation before the outbound request.
