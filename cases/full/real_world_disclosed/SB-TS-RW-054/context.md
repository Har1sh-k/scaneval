# SB-TS-RW-054: OpenClaw device token re-pairing computed caller-scope containment from request scopes, so an empty scope set bypassed the guard

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-8mg9-j9cf-54cj`
- CVE: `CVE-2026-53852`
- Vulnerable commit: `cbcfdf62c7297bda66009ea7476f053c3e9addab` (release v2026.4.24)
- Fix commit: `8bbb143ab87e0a45f9d3f986768d75168750b672` (release v2026.4.25)

## Vulnerability
Caller-scope containment was evaluated against the request-supplied (or token/device-derived) scopes rather than the effective scopes the operation would restore. An empty requested scope set makes resolveMissingRequestedScope return null, so the guard passes while the underlying rotate/re-pair re-applies the device's broader approved baseline, retaining more scope than the caller authority allows.

## Source / Carrier / Sink
- Source: Gateway client device-management RPC (device token rotate/re-pair) carrying deviceId, role, and a scopes field that can be empty.
- Carrier: requestedScopes derived from the request (scopes ?? token scopes ?? device scopes) and authz.callerScopes, evaluated by resolveMissingRequestedScope before rotateDeviceToken/revokeDeviceToken.
- Sink: rotateDeviceToken({ deviceId, role, scopes }) / revokeDeviceToken({ deviceId, role }), which re-issue/persist tokens using the device's existing approved scope baseline.
- Missing guard: Containment of the effective restored scopes against caller scopes that holds even when the request scope set is empty (empty-set must not be treated as 'nothing requested' = allowed).

## Fix
Fix commit 8bbb143a moves containment enforcement into the device-pairing library: rotateDeviceToken and revokeDeviceToken now accept callerScopes and call resolveMissingRequestedScope against the effective target scopes, returning a 'caller-missing-scope' denial; the gateway handler passes authz.callerScopes and drops the request-derived pre-check. revokeDeviceToken is converted to a result type that also enforces caller-scope containment.

## Scanner Expectation
Flag the device token rotate/re-pair containment check that derives requested scopes from request input and is no-op for an empty set, allowing the broader device baseline to be restored without caller-scope containment (CWE-863 incorrect authorization).
