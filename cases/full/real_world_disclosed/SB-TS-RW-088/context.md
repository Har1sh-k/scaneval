# SB-TS-RW-088: Flowise SSRF protection bypass: tools call raw node-fetch/axios instead of the secure HTTP wrapper

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-qqvm-66q4-vf5c`
- CVE: `CVE-2026-43995`
- Vulnerable commit: `840d2ae14d25230579a58aa4305f8506672a0a45` (release ?)
- Fix commit: `c7f18f51bb2e729e34f8301f0fb633a873fe946e` (release flowise@3.1.0)

## Vulnerability
Outbound HTTP validation is not centralized or structurally enforced; tools voluntarily choose between raw fetch/axios and the secure wrapper. OpenAPIToolkit imports `fetch` from 'node-fetch' and calls it directly on the user-controlled openApiLink, so HTTP_DENY_LIST, IP-resolution validation, IP pinning and loopback blocking from httpSecurity.ts are never applied to that request. This makes the previously patched SSRF mitigation incomplete.

## Source / Carrier / Sink
- Source: User/LLM-controlled URL supplied as the OpenAPI 'link' (openApiLink) input to the OpenAPIToolkit tool node.
- Carrier: openApiLink is destructured from args in getOpenAPISpec/runtime and passed straight to the HTTP client without validation.
- Sink: Raw node-fetch call `await fetch(openApiLink)` issuing an outbound request to an attacker-chosen host.
- Missing guard: No use of the centralized secureFetch/httpSecurity wrapper (HTTP_DENY_LIST, DNS-resolution validation, IP pinning, loopback blocking) before performing the request.

## Fix
Fix commit c7f18f51 ('Use secureFetch and secureAxiosRequest for more URLs', #5886; shipped in flowise@3.1.0) changes the import to `import { secureFetch } from '../../../src/httpSecurity'` and replaces `await fetch(openApiLink)` with `await secureFetch(openApiLink)`, routing the user-controlled URL through the centralized SSRF validation. The same commit converts other affected nodes (MCP, Jira, APILoader, ExecuteFlow, etc.) to secureFetch/secureAxiosRequest.

## Scanner Expectation
A scanner should flag a user-controlled URL flowing into a raw HTTP client (node-fetch/axios) without SSRF validation, allowing requests to internal/metadata endpoints (server-side request forgery).
