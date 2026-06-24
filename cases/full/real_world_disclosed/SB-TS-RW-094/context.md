# SB-TS-RW-094: Authentication bypass in Chat Trigger node n8nUserAuth mode

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-jh8h-6c9q-7gmw`
- CVE: ``
- Vulnerable commit: `8e81f3e31398b04fd6f8cc27cf844980cd382117` (release n8n@2.10.0)
- Fix commit: `9e5212ecbc5d2d4e6f340b636a5e84be6369882e` (release n8n@2.10.1)

## Vulnerability
The n8nUserAuth branch extracts the 'n8n-auth' cookie and throws an error only when the cookie is entirely absent (`if (!authCookie && webhookName !== 'setup')`). It performs no cryptographic or session validation of the cookie value, so any attacker-supplied cookie string satisfies the check. The presence test is mistaken for an authentication check.

## Source / Carrier / Sink
- Source: Attacker-controlled HTTP request to the chat trigger webhook endpoint, specifically the Cookie header.
- Carrier: The 'n8n-auth' cookie value parsed by getCookie() from headers.cookie inside validateAuth().
- Sink: The authentication decision `if (!authCookie && webhookName !== 'setup')` that grants access whenever any non-empty cookie is supplied.
- Missing guard: No verification that the n8n-auth cookie is a valid, signed session token (e.g. via context.validateCookieAuth); only presence is checked.

## Fix
The fix wraps the cookie handling in an `if (webhookName !== 'setup')` guard, throws a 401 when the cookie is missing, and crucially calls `await context.validateCookieAuth(authCookie)` to verify the cookie corresponds to a valid authenticated n8n user, throwing on failure. This turns the presence check into a real authentication check.

## Scanner Expectation
Flag an authentication routine that treats the mere presence of a credential/cookie as proof of authentication without validating it, allowing trivial bypass.
