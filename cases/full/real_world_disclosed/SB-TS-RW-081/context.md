# SB-TS-RW-081: SSRF protection bypass: default-insecure deny list in httpSecurity.ts

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-2x8m-83vc-6wv4`
- CVE: `CVE-2026-41272`
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `efffd12f161761790c4bfb7bb25771e0a6ff4b75` (release flowise@3.1.0)

## Vulnerability
SSRF filtering is opt-in: when HTTP_DENY_LIST is not configured the deny-list check short-circuits and every destination, including internal/metadata addresses, is permitted. The IP-pinning DNS-rebinding mitigation present at 3.0.13 is also bypassed in the default case because no addresses are ever rejected.

## Source / Carrier / Sink
- Source: URL passed to secureFetch/secureAxiosRequest (originating from user- or LLM-controlled inputs across many Flowise nodes).
- Carrier: checkDenyList()/resolveAndValidate() short-circuit when HTTP_DENY_LIST is unset, so the URL reaches the HTTP client unvalidated.
- Sink: The pinned-agent HTTP request to the resolved IP (loopback/link-local/private hosts reachable).
- Missing guard: No secure default deny list; SSRF filtering only applies when HTTP_DENY_LIST is explicitly configured (default-insecure).

## Fix
Fix commit efffd12f adds a built-in DEFAULT_DENY_LIST (loopback, 0.0.0.0, 10/8, 169.254/16 incl. 169.254.169.254, 172.16/12, 192.168/16, ::1, fc00::/7, localhost, etc.) and a getHttpDenyList() helper. checkDenyList() and resolveAndValidate() now use getHttpDenyList(), which falls back to the secure default when HTTP_DENY_LIST is unset, removing the early return / null deny-list paths so internal targets are blocked by default.

## Scanner Expectation
Flag the deny-list check that returns early when the env var is unset (line 42, mirrored by the denyList?null in resolveAndValidate) as a protection-mechanism bypass enabling SSRF to internal addresses by default.
