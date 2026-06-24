# SB-TS-RW-060: OpenClaw bootstrap token replay could widen pending pairing scopes in verifyDeviceBootstrapToken

## Advisory
- Repo: `openclaw/openclaw`
- GHSA: `GHSA-9v8j-9c9g-w66c`
- CVE: `CVE-2026-53862`
- Vulnerable commit: `8287402da75236c63b6c144b97689e1930ae807b` (release v2026.5.10-beta.2)
- Fix commit: `2d00bedc1e731c19ceeac3c7058809ece7b3dc2b` (release v2026.5.12)

## Vulnerability
The verify path bound a token to a device and persisted the caller's requested profile each time it was presented, with no notion of a sticky pending profile to compare subsequent presentations against. Because nothing pinned the first requested scope set, replaying the token with broader scopes simply overwrote the pending state, so an attacker with access to the pending token could escalate the pending pairing authority before approval.

## Source / Carrier / Sink
- Source: Caller-supplied role and scopes passed to verifyDeviceBootstrapToken (params.role, params.scopes) for a held pending bootstrap token.
- Carrier: The token record persisted via persistState; the requested profile (allowedProfile derived from the presented role/scopes) written into state[tokenKey] on each presentation.
- Sink: Persisted pending pairing authority (the bootstrap token record's effective/pending profile) that an operator later approves.
- Missing guard: No comparison of the current presentation's requested scope set against a pinned pending profile from the first presentation; pendingProfile and the sameBootstrapProfile equality check were absent.

## Fix
The fix introduces a pendingProfile field on the token record and, in verifyDeviceBootstrapToken, computes requestedProfile from the role/scopes and rejects (bootstrap_token_invalid) any presentation whose requested profile does not match a previously stored pendingProfile; the first presentation pins pendingProfile so later replays cannot widen it. The redeem path also carries pendingProfile forward until satisfied.

## Scanner Expectation
Flag that a security-sensitive pairing/authorization record is rewritten from caller-controlled scope input on token re-presentation without verifying it matches the originally requested pending scope, allowing privilege/scope widening (improper privilege management, CWE-269).
