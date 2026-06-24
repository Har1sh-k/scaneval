# SB-TS-RW-071: IDOR in PUT /api/v1/loginmethod allows overwriting any organization's SSO config

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-cwc3-p92j-g7qm`
- CVE: `CVE-2026-30823`
- Vulnerable commit: `55b6913c03f0dba37cc207975f0c0d0786e0f3c7` (release flowise@3.0.12)
- Fix commit: `06b812653843f21b197cc676a7b2732c06997501` (release flowise@3.0.13)

## Vulnerability
The update method trusts the organizationId supplied in req.body and writes the corresponding database record with no authorization check tying request.user's organization to body.organizationId, an Authorization Bypass Through User-Controlled Key (CWE-639) combined with Missing Authorization (CWE-862). An authenticated free-tier user can therefore mutate SSO config belonging to other tenants.

## Source / Carrier / Sink
- Source: Attacker-controlled JSON request body fields organizationId, userId, and providers[] on PUT /api/v1/loginmethod (req.body).
- Carrier: req.body passed verbatim into loginMethodService.createOrUpdateConfig(req.body) which persists the SSO config keyed by the supplied organizationId.
- Sink: Database update of the login-method record for the attacker-specified organizationId and initializeSsoProvider() call applying the attacker's OAuth credentials.
- Missing guard: No authorization check that the authenticated user owns or administers body.organizationId (no request.user.organizationId === body.organizationId comparison) and no platform/role gate.

## Fix
Commit 06b81265 introduced an assertEnterprisePlatform() guard that is invoked at the start of create/read/update, rejecting requests with HTTP 403 FORBIDDEN when the running platform is CLOUD or OPEN_SOURCE so non-enterprise/multi-tenant callers can no longer mutate SSO configuration; later releases added explicit per-organization ownership checks. The endpoint was also tightened in constants/route configuration.

## Scanner Expectation
Flag a controller handler that uses a request-body-supplied object identifier (organizationId) to update a resource without an ownership/authorization check (IDOR / missing function-level authorization).
