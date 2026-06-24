# SB-TS-RG-010: Middleware authorization bypass via App Router segment-prefetch/.rsc transport routes in Next.js

## Advisory
- Repo: `vercel/next.js`
- GHSA: `GHSA-267c-6grr-h53f`
- CVE: `CVE-2026-44575`
- Vulnerable commit: `412eb90b6587ec02e8361c92efa9091487e7348f` (release v15.5.15)
- Fix commit: `25926510f8d3223a447f2e37a56a7686f9190ef2` (release v15.5.16)

## Vulnerability
The matcher-suffix generation enumerates only the legacy `.json` data-route transport (plus root index forms), omitting the App Router `.rsc` and segment-prefetch transport suffixes. Because middleware only runs when a request URL matches a generated matcher, the omitted transport forms of a protected route bypass middleware entirely, defeating any authorization enforced there.

## Source / Carrier / Sink
- Source: Attacker-crafted request URL using an App Router transport variant (`<path>.rsc` or `<path>.segments/<seg>.segment.rsc`) that resolves to a middleware-protected page.
- Carrier: The middleware matcher regex string built in `source` from the configured matcher, used to decide whether middleware runs for a given request.
- Sink: The matcher-suffix template assignment (lines 340-344) that omits App Router transport variants, producing a matcher that fails to match `.rsc`/segment-prefetch URLs of protected pages.
- Missing guard: The generated matcher does not enumerate the App Router transport suffixes (`.rsc`, `.segments/...segment.rsc`), so middleware authorization is not enforced on those equivalent route forms.

## Fix
The fix imports the RSC suffix constants and escapeStringRegexp and extends the matcher suffix so the generated regex also matches App Router transport variants: it adds APP_ROUTE_RSC_SUFFIX_MATCHER (.rsc) and APP_ROUTE_SEGMENT_PREFETCH_SUFFIX_MATCHER (.segments/.+.segment.rsc) into both the root index group and the non-root `{(...)}?` group, so middleware matchers are applied consistently to those transport requests as well as the normal page URL.

## Scanner Expectation
Flag the middleware-matcher construction that whitelists only `.json` transport forms while protected App Router pages are also reachable via `.rsc`/segment-prefetch URLs, as an authorization-bypass (CWE-288) caused by an incomplete request-form match set.
