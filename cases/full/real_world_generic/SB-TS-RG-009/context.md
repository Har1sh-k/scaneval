# SB-TS-RG-009: Middleware authorization bypass via dynamic route-parameter query injection in Next.js

## Advisory
- Repo: `vercel/next.js`
- GHSA: `GHSA-492v-c6pp-mqqv`
- CVE: `CVE-2026-44574`
- Vulnerable commit: `412eb90b6587ec02e8361c92efa9091487e7348f` (release v15.5.15)
- Fix commit: `87080764c96f5416decccd43f4c434545fd5d4e1` (release v15.5.16)

## Vulnerability
normalizeQueryParams is applied to every request regardless of whether Next is actually wrapped by a trusted upstream router process, so externally-supplied route-parameter query encodings are honored even from ordinary client requests. This decouples the dynamic route value the page renders from the path middleware matched against, allowing the authorization decision (based on path) and the rendered content (based on injected params) to diverge.

## Source / Carrier / Sink
- Source: Attacker-supplied query parameters on an ordinary request that encode dynamic route-parameter values.
- Carrier: The `query` object passed through normalizeQueryParams(query, routeParamKeys), promoting query values into routeParamKeys used to render the dynamic page.
- Sink: serverUtils.normalizeQueryParams(query, routeParamKeys) on line 704, which makes the page render a dynamic route value different from the path middleware matched.
- Missing guard: No check that the request actually came through a trusted Next router wrapper (isWrappedByNextServer) before honoring external route-param query encodings, and no filtering of those internal params from untrusted requests.

## Fix
The fix consults routerServerContext.isWrappedByNextServer and only calls normalizeQueryParams(query, routeParamKeys) in that trusted single-process wrapped environment; otherwise it calls serverUtils.filterInternalQuery(query, []) to strip externally-supplied internal/route-param encodings that should never be accepted from ordinary requests. This ensures only internal route-parameter normalization from trusted routing flows is honored.

## Scanner Expectation
Flag the unconditional promotion of attacker-controlled query values into dynamic route parameters (normalizeQueryParams) without a trusted-source check, as an authorization-bypass (CWE-288) where path-based middleware and rendered route params can diverge.
