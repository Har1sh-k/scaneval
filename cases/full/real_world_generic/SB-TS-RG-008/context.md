# SB-TS-RG-008: Next.js Pages Router i18n middleware bypass via locale-less /_next/data/<buildId>/<page>.json requests

## Advisory
- Repo: `vercel/next.js`
- GHSA: `GHSA-36qx-fr4f-26g5`
- CVE: `CVE-2026-44573`
- Vulnerable commit: `412eb90b6587ec02e8361c92efa9091487e7348f` (release v15.5.15)
- Fix commit: `6c72e0b4ee096643b42c742f35e0de84c41d190d` (release v15.5.16)

## Vulnerability
For locale-less data requests with a default locale configured, normalizeLocalePath returns no detectedLocale, so the code never re-prefixes the normalized pathname with the default locale the way direct page requests are normalized. The middleware/proxy matcher then sees a pathname that does not match the locale-prefixed shape it was built against, so middleware (and any authorization it enforces) is skipped for the data route. The intended invariant -- that a data route is matched the same way as its corresponding page route -- is broken only for the locale-less default-locale case.

## Source / Carrier / Sink
- Source: Attacker-crafted HTTP request to /_next/data/<buildId>/<page>.json with no locale prefix in the path.
- Carrier: The request pathname flows through getResolveRoutes(): data-prefix stripping (normalizers.data.normalize) then normalizeLocalePath against config.i18n.locales, producing a still-locale-less `normalized` pathname when no locale is detected.
- Sink: The downstream middleware/proxy matcher that decides whether authorization-enforcing middleware runs for the resolved pathname.
- Missing guard: No re-prefixing of the normalized default-locale data-route pathname to the locale-prefixed internal shape, so the middleware matcher (and its authorization checks) is not applied to locale-less data requests.

## Fix
The fix (commit 6c72e0b, shipped in v15.5.16 and v16.2.5) adds an `else if` branch to the i18n block: when no locale was detected, a defaultLocale exists, and the pathname is not an internal /_next/ path, it re-prefixes the normalized pathname with `/${defaultLocale}` so the data route is matched against the same locale-prefixed internal pathname shape used by direct page requests. This makes the middleware matcher run for locale-less data routes, restoring the authorization checks.

## Scanner Expectation
A scanner should flag that an attacker-controlled data-route pathname reaches the middleware matcher without being normalized to the same locale-prefixed form as the equivalent page route, allowing the authorization-enforcing middleware to be skipped (authorization bypass / inconsistent route matching).
