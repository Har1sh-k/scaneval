# SB-TS-RW-111: OAuth callback authorization bypass: state-owner check skipped when N8N_SKIP_AUTH_ON_OAUTH_CALLBACK is true

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-vpgc-2f6g-7w7x`
- CVE: `CVE-2026-33720`
- Vulnerable commit: `aac5be18c4f08a95dade36307af621d29605c5f7` (release n8n@2.7.5)
- Fix commit: `7108ef45fad8e1b131767a80237ff6b212c4fade` (release n8n@2.8.0)

## Vulnerability
Because the user-ownership comparison was combined with !skipAuthOnOAuthCallback in a single AND condition, enabling the skip flag disabled the ownership check entirely for static credentials instead of only relaxing it for legitimate embed/iframe flows. There was also no guard against req.user?.id being undefined, allowing unauthenticated/owner-mismatched callbacks to bind tokens to an arbitrary credential.

## Source / Carrier / Sink
- Source: Attacker-crafted OAuth callback request whose encrypted state references a credential the attacker controls, completed by a victim.
- Carrier: The CSRF/state parameter decoded in OauthService.decodeCsrfState (cid + userId) during the OAuth credential callback.
- Sink: Storing the victim's OAuth tokens into the credential identified by the state without verifying the caller owns it.
- Missing guard: Ownership verification (decryptedState.userId === req.user.id) is skipped whenever N8N_SKIP_AUTH_ON_OAUTH_CALLBACK is true, with no undefined-user guard.

## Fix
Commit 7108ef45 restructured decodeCsrfState to handle the skip flag as an explicit early-return only for static credentials and added a strengthened ownership check (req.user?.id === undefined || decryptedState.userId !== req.user.id) so that, when auth is not skipped, the callback is rejected unless the authenticated caller owns the state; the test notes describe this as BOLA prevention.

## Scanner Expectation
Flag the OAuth callback state decode where the user-ownership check is bypassed under a configuration flag as a broken object-level authorization (authz bypass) sink.
