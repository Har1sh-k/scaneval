# SB-TS-RW-070: Unauthenticated read of any organization's SSO config with cleartext OAuth secrets via GET /api/v1/loginmethod

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-6pcv-j4jx-m4vx`
- CVE: ``
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `c22f2d3d25077f065001e07b79870aee2c37d70c` (release flowise@3.1.0)

## Vulnerability
The read method performs no caller identity/authorization check (it only gates on platform type via assertEnterprisePlatform), the route is unauthenticated (whitelisted), and it returns the fully decrypted provider config including clientSecret. This is Missing Authentication for a Critical Function (CWE-306) compounded by Cleartext exposure of stored secrets (CWE-312).

## Source / Carrier / Sink
- Source: Unauthenticated HTTP request with attacker-chosen organizationId (or id) query parameter on GET /api/v1/loginmethod (req.query).
- Carrier: query.organizationId / query.id passed to LoginMethodService.readLoginMethodByOrganizationId / readLoginMethodById, with results decrypted into loginMethodConfig.providers.
- Sink: res.status(200).json(loginMethodConfig) returning decrypted provider configs (including clientSecret) to the caller.
- Missing guard: No authentication requirement on the route (it is whitelisted) and no check that the caller is logged in and owns the requested organizationId; secrets are returned in cleartext rather than redacted.

## Fix
Commit c22f2d3d removed /api/v1/loginmethod from WHITELIST_URLS (leaving only /loginmethod/default public), added checkPermission('sso:manage') to the GET route, added a req.user.activeOrganizationId authentication check plus an organizationId ownership check in read(), and introduced getSafeConfig() to strip clientSecret from returned config. The fix landed in flowise@3.1.0.

## Scanner Expectation
Flag a route handler reachable without authentication that reads sensitive records by a request-supplied identifier and returns them without verifying caller identity or ownership (missing authentication / authorization on a critical function).
