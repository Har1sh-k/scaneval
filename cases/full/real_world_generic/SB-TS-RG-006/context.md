# SB-TS-RG-006: Next.js dev server allowedDevOrigins bypass: Origin: null skips cross-site validation for internal dev endpoints

## Advisory
- Repo: `vercel/next.js`
- GHSA: `GHSA-jcc7-9wpm-mj36`
- CVE: `CVE-2026-27977`
- Vulnerable commit: `adf8c612adddd103647c90ff0f511ea35c57076e` (release v16.1.6)
- Fix commit: `862f9b9bb41d235e0d8cf44aa811e7fd118cee2a` (release v16.1.7)

## Vulnerability
The literal Origin 'null' is a real, attacker-reachable value emitted by sandboxed/opaque browser contexts, but the guard `rawOrigin !== 'null'` excludes it from the cross-site origin-allowance check, so it is never compared against allowedDevOrigins and the request is allowed by the trailing `return false`. The exclusion was presumably intended to permit same-site GET requests with no meaningful origin, but it instead created a blanket allow for any 'null' origin against privileged internal dev endpoints.

## Source / Carrier / Sink
- Source: Attacker-influenced Origin request header with the literal value 'null', sent from an opaque/sandboxed browser context to an internal next dev endpoint (e.g. websocket upgrade).
- Carrier: rawOrigin (req.headers['origin']) is gated by `if (rawOrigin && rawOrigin !== 'null')`, which excludes the 'null' origin from the parseUrl/isCsrfOriginAllowed path.
- Sink: The cross-site decision: control falls past the skipped allow-list check to `return false`, allowing the internal dev-endpoint request instead of warnOrBlockRequest.
- Missing guard: No validation of the literal 'null' origin against allowedDevOrigins/allowedOrigins; 'null' is excluded from isCsrfOriginAllowed and silently allowed.

## Fix
The fix (commit 862f9b9, shipped in v16.1.7) removes the special-case that skipped 'null' and instead routes a null origin through the same cross-site allowance check: rawOrigin is normalized (keeping the string 'null' when present) into originLowerCase, and the request is blocked unless originLowerCase is undefined (no origin) or isCsrfOriginAllowed(originLowerCase, allowedOrigins) returns true. The function (renamed blockCrossSiteDEV) now blocks a disallowed 'null' origin on internal dev endpoints instead of letting it through.

## Scanner Expectation
A scanner should flag that the Origin header value 'null' bypasses the isCsrfOriginAllowed cross-site check for internal dev endpoints and falls through to an allow (return false), permitting an unvalidated cross-origin request (origin-validation bypass, CWE-1385).
