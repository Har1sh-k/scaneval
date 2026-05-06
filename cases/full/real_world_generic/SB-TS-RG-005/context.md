# SB-TS-RG-005 — Next.js middleware Location-header SSRF in self-hosted apps

## Summary

Next.js middleware can return a response with arbitrary headers, often via `NextResponse.next({ request: { headers: ... } })`. In versions prior to v15.4.7 (and equivalent backports), the routing layer treated *any* response from middleware that carried a `Location` header as a redirect, regardless of status code. The router converted the supplied value through `getRelativeURL`, assigned it to `parsedUrl`, and continued routing as if it were a normal redirect.

When custom middleware reflects a request-supplied value into the `Location` header (a common pattern when "echoing" a request header back into the response), an attacker can supply that value and steer the server's internal routing pass to an arbitrary URL — Server-Side Request Forgery in self-hosted Next.js.

## Why it is a real bug

In `packages/next/src/server/lib/router-utils/resolve-routes.ts`, the `getResolveRoutes` helper unconditionally converts a `Location` header to a relative URL and reuses it as `parsedUrl`:

```ts
if (middlewareHeaders['location']) {
    const value = middlewareHeaders['location'] as string
    const rel = getRelativeURL(value, initUrl)
    resHeaders['location'] = rel
    parsedUrl = url.parse(rel, true)
    return {
        parsedUrl,
        resHeaders,
        finished: true,
        statusCode: middlewareRes.status,
    }
}
```

The fix wraps this conversion in `if (allowedStatusCodes.has(middlewareRes.status))` so a Location header with a non-redirect status (e.g., 200) is forwarded as a plain response header rather than driving routing.

## What a SAST tool should flag

A scanner that recognises "URL extracted from a header used in `url.parse` and reused for further routing/fetch" should flag this region. The taint chain is short: `middlewareHeaders['location']` (request-influenced via reflective middleware) → `getRelativeURL` → `parsedUrl`.

## References

- Advisory: <https://github.com/vercel/next.js/security/advisories/GHSA-4342-x723-ch2f>
- CVE: CVE-2025-57822
- Fix: vercel/next.js commit `1a026e338d2b` (PR #82588)
- Vulnerable snapshot: vercel/next.js at `be4aafd4b744` (v15.4.6)
