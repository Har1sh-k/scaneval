# SB-RS-RG-001: Middleware authorization bypass via App Router transport routes under Turbopack (incomplete fix of CVE-2026-44575)

## Advisory
- Repo: `vercel/next.js`
- GHSA: `GHSA-26hh-7cqf-hhc6`
- CVE: `CVE-2026-45109`
- Vulnerable commit: `ad6fd4e50e5aba20b60d283c42b89273a3167ccd` (release v15.5.16)
- Fix commit: `423623ae38c106273085b66946ee5bf9aab77f2c` (release v15.5.17)

## Vulnerability
The Turbopack/Rust matcher generator mirrors the old (vulnerable) JS logic and only enumerates the `.json` transport suffix, leaving out the App Router `.rsc` and segment-prefetch suffixes. Because user middleware runs only when a request URL matches a generated matcher, the omitted transport forms of a protected route bypass middleware, so the earlier fix in the webpack/get-page-static-info path did not protect Turbopack-built apps.

## Source / Carrier / Sink
- Source: Attacker-crafted request URL using an App Router transport variant (`<path>.rsc` or `<path>.segments/<seg>.segment.rsc`) that resolves to a middleware-protected page, in a Turbopack-built app.
- Carrier: The middleware matcher regex `source` string built in MiddlewareEndpoint, used by the Turbopack runtime to decide whether middleware runs for a request.
- Sink: The matcher-suffix construction (lines 217-225) that pushes only `.json`/index forms, producing a matcher that fails to match `.rsc`/segment-prefetch URLs of protected pages.
- Missing guard: The generated matcher does not enumerate the App Router transport suffixes (`.rsc`, `.segments/...segment.rsc`), so middleware authorization is not enforced on those equivalent route forms under Turbopack.

## Fix
The fix updates crates/next-api/src/middleware.rs to also append the App Router transport variants to the generated matcher: the root group gains `/?index(?:\.rsc|\.segments/.+\.segment\.rsc)` and the non-root group becomes `{(\.json|\.rsc|\.segments/.+\.segment\.rsc)}?`, matching the webpack implementation so middleware matchers cover those transport requests too.

## Scanner Expectation
Flag the middleware-matcher construction that whitelists only `.json` transport forms while protected App Router pages are also reachable via `.rsc`/segment-prefetch URLs, as an authorization-bypass (CWE-288) caused by an incomplete request-form match set.
