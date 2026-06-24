# SB-TS-RW-121: Cross-user authorization bypass: OAuth credential reconnect authorized with credential:read instead of credential:update

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-6h4j-wcr9-2vg7`
- CVE: `CVE-2026-45732`
- Vulnerable commit: `29d42560ad14983ceb3dcda8cab0a1988d932a5d` (release n8n@2.20.6)
- Fix commit: `545da1aa8f9389532ee71a33a0e1beb93ad86591` (release n8n@2.20.7)

## Vulnerability
Initiating the OAuth authorization/reconnect flow mutates the credential's stored OAuth tokens, which requires update authority, but the permission check requested `credential:read`. A user holding only read access on a shared credential therefore passed the check and was allowed to overwrite token material they should not be able to modify.

## Source / Carrier / Sink
- Source: Authenticated user with only credential:read (read-only shared) access invoking the OAuth1/OAuth2 credential auth/reconnect endpoint with a target credential id.
- Carrier: The credentialId from req.query passed into the credential authorization lookup.
- Sink: credentialsFinderService.findCredentialForUser(credentialId, req.user, ['credential:read']) gating the token-overwriting reconnect flow with the wrong (read) scope.
- Missing guard: Authorization check used credential:read instead of the credential:update scope required for an operation that overwrites stored OAuth token material.

## Fix
The method was renamed to getCredentialForUpdate and the scope passed to findCredentialForUser was changed from `['credential:read']` to `['credential:update']`, so only users with update permission can start the reconnect flow. The callback path (decodeCsrfState) was likewise hardened to re-resolve the credential with `['credential:update']` for the requesting user instead of fetching it without an authorization check.

## Scanner Expectation
Flag the OAuth credential authorization that gates a token-overwriting reconnect operation with a read-level scope (credential:read) instead of credential:update (broken object-level / function-level authorization).
