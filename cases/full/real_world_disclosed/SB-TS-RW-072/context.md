# SB-TS-RW-072: Flowise whitelists /api/v1/nvidia-nim, leaving privileged NIM endpoints unauthenticated

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-5f53-522j-j454`
- CVE: `CVE-2026-30824`
- Vulnerable commit: `55b6913c03f0dba37cc207975f0c0d0786e0f3c7` (release flowise@3.0.12)
- Fix commit: `8ce06c72017c271bbc7990784c27710d49599f6b` (release flowise@3.0.13)

## Vulnerability
Adding the NIM prefix to the auth whitelist removes the only authentication gate for a set of critical, state-changing functions, and the controllers assume the middleware already authenticated the caller. This is Missing Authentication for a Critical Function (CWE-306): privileged operations are reachable with no credentials.

## Source / Carrier / Sink
- Source: Unauthenticated HTTP requests to /api/v1/nvidia-nim/* (e.g. GET /api/v1/nvidia-nim/get-token).
- Carrier: The route prefix matches the WHITELIST_URLS entry '/api/v1/nvidia-nim', so the global auth middleware short-circuits and skips credential checks.
- Sink: The NVIDIA NIM controllers (get-token / container management) execute privileged actions for the unauthenticated caller.
- Missing guard: No authentication enforced for the NIM routes (the whitelist entry disables it, and controllers add no per-route auth check).

## Fix
Fix commit 8ce06c72 (shipped in flowise@3.0.13) removes '/api/v1/nvidia-nim' (and '/api/v1/vector/upsert/') from WHITELIST_URLS and instead adds 'export const API_KEY_BLACKLIST_URLS = ["/api/v1/nvidia-nim"]', so the NIM routes now require authentication.

## Scanner Expectation
A scanner should flag that critical/state-changing NIM endpoints are reachable without authentication because their prefix is in WHITELIST_URLS (CWE-306 missing authentication / auth bypass): the auth middleware is bypassed and no compensating check exists.
