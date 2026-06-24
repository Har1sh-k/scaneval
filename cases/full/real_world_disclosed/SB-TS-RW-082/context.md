# SB-TS-RW-082: Flowise unauthenticated OAuth2 token refresh endpoint discloses access tokens

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-6f7g-v4pp-r667`
- CVE: `CVE-2026-41273`
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `da8b251a9a4c59484ceaf6f71df7406aede7bef2` (release flowise@3.1.0)

## Vulnerability
The refresh handler treats credentialId as the only authorization and never verifies the caller's identity or ownership, while being whitelisted from authentication, so anyone who knows a credentialId can trigger a refresh and read the resulting access_token from the response (CWE-306). Credential IDs are not secret: they are exposed by the public chatbot config endpoint.

## Source / Carrier / Sink
- Source: Unauthenticated POST /api/v1/oauth2-credential/refresh/:credentialId, with credentialId discoverable from the unauthenticated GET /api/v1/public-chatbotConfig/:chatflowId flowData.
- Carrier: const { credentialId } = req.params is used directly to look up the credential (credentialRepository.findOneBy({ id: credentialId })) with no ownership/auth check.
- Sink: res.json({ ... tokenInfo: { ...tokenData, ... } }) returns the freshly refreshed OAuth2 token (including access_token) to the caller.
- Missing guard: No authentication/authorization on the refresh route (it is whitelisted) and no restriction of the returned token fields, so an unauthenticated caller can both trigger the refresh and read the token.

## Fix
Fix commit da8b251a (FLOWISE-566, included in the 3.1.0 patch line) hardens this flow: the success response no longer spreads the full token (tokenInfo now returns only token_type / has_new_refresh_token / expires_at instead of '...tokenData'), token requests go through secureAxiosRequest with validateOAuth2Url, and extractOAuth2TokenFields limits the fields propagated, so the access_token is no longer disclosed to the caller.

## Scanner Expectation
A scanner should flag that POST /api/v1/oauth2-credential/refresh/:credentialId is a critical function reachable without authentication (prefix in WHITELIST_URLS) that returns secret token material keyed only by an attacker-obtainable credentialId (CWE-306 missing authentication / auth bypass).
