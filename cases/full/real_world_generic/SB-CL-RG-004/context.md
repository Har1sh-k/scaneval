# SB-CL-RG-004: Public dashboard/card parameter endpoints missing public-sharing-enabled check

## Advisory
- Repo: `metabase/metabase`
- GHSA: `GHSA-j3qp-7mr8-hr55`
- CVE: ``
- Vulnerable commit: `740ab6d8c95eb6e484f27dca75abc2291b7d8986` (release v0.58.7)
- Fix commit: `4ab19dce4d1660a819893a8303981d306addc2b3` (release v0.59.1)

## Vulnerability
These four public endpoint handlers omit the (public-sharing.validation/check-public-sharing-enabled) gate that the other public endpoints use, then escalate to request/as-admin to fetch parameter values. With the site-wide public-sharing setting disabled they still serve data for previously-shared UUIDs, so revoking public sharing does not actually deny access.

## Source / Carrier / Sink
- Source: Unauthenticated HTTP request to GET /api/public/... carrying a previously-valid public UUID and parameter key.
- Carrier: The handler looks up the card/dashboard by public_uuid and runs the parameter query under request/as-admin without verifying public sharing is enabled.
- Sink: queries/card-param-remapped-value and parameters.dashboard/param-values / dashboard-param-remapped-value return parameter data to the unauthenticated caller.
- Missing guard: No call to public-sharing.validation/check-public-sharing-enabled (and no route-level middleware) gating these endpoints on the site-wide Enable Public Sharing setting.

## Fix
The fix adds (public-sharing.validation/check-public-sharing-enabled) to each of the four endpoints and additionally wraps the whole /api/public route group with a +public-sharing-enabled Ring middleware (enforce-public-sharing-enabled) so the site-wide check is enforced for every public endpoint.

## Scanner Expectation
Flag the four public param endpoints (lines 512-566) that run under request/as-admin without a check-public-sharing-enabled guard while sibling endpoints have it, as an inconsistent/missing access-control check.
