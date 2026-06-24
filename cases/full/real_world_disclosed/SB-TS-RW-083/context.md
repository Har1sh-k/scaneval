# SB-TS-RW-083: Flowise resetPassword authentication bypass via null/empty reset token

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-f6hc-c5jr-878p`
- CVE: `CVE-2026-41276`
- Vulnerable commit: `20eac8f1eca9ef4697e6da9e357d70bec0ed16c5` (release ?)
- Fix commit: `6c78e1c36f4cf08874b9b7a444d61ab63441d78a` (release flowise@3.1.0)

## Vulnerability
The token check only compares submitted vs stored tempToken for equality with no guard that the stored (or submitted) token is non-empty, so a null/empty stored token (the default for accounts that never requested a reset) is matched by a null/empty submitted token. Combined with an expiry check using Math.abs(diff) against a default tokenExpiry tied to account creation, an attacker who knows a recently-created user's email can reset that user's password without ever possessing a real reset token.

## Source / Carrier / Sink
- Source: Unauthenticated HTTP request to POST /api/v1/account/reset-password with a known victim email and a null/empty tempToken plus a chosen new password.
- Carrier: data.user (email, tempToken, password) flows into AccountService.resetPassword(); user is loaded via readUserByEmail and compared field-by-field.
- Sink: The password update path (bcrypt hash of attacker-chosen password then userService.saveUser), reached after the token/expiry checks pass.
- Missing guard: No check that a reset token was actually issued: neither the submitted token nor the stored user.tempToken is required to be non-empty before the equality comparison, and tokenExpiry is not required to exist.

## Fix
Fix commit 6c78e1c ('Fixes to password reset functionality', #5913; shipped in flowise@3.1.0) adds `if (!data.user.tempToken) throw INVALID_TEMP_TOKEN` to reject empty submitted tokens, changes the comparison to `if (!user.tempToken || user.tempToken !== data.user.tempToken)` to reject accounts with no stored token, and adds `if (!tokenExpiry) throw INVALID_TEMP_TOKEN` plus a directional expiry check `moment().isAfter(tokenExpiryMoment)` instead of the absolute-difference window.

## Scanner Expectation
A scanner should flag that a security-critical token equality check (`user.tempToken !== data.user.tempToken`) gates password reset without verifying the token is present/non-empty, allowing an empty/null token to satisfy authentication (authentication bypass / account takeover).
