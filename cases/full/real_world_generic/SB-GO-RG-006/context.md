# SB-GO-RG-006 — oauth2-proxy header smuggling via underscore variants

## Summary

oauth2-proxy is responsible for stripping client-controlled identity-related headers (such as `X-Forwarded-User`) before forwarding requests to the upstream, so that authenticated identity can be communicated reliably from the proxy. In versions prior to v7.13.0, the strip routine deletes header names verbatim using Go's `req.Header.Del`, which only removes the canonical Title-Case dashed form. A client that sends an *underscore* variant — `X_Forwarded-User` — survives the strip. Many WSGI frameworks (Django, Flask, FastAPI, and PHP via `HTTP_*` translation) normalize underscores to dashes when reading headers, so the upstream sees the attacker-controlled value as the legitimate `X-Forwarded-User`.

The result is a header-smuggling primitive that lets authenticated users escalate privileges by spoofing identity-bearing headers. oauth2-proxy's authentication itself is not compromised; only the integrity of the headers it forwards.

## Why it is a real bug

`pkg/middleware/headers.go:stripHeaders`:

```go
func stripHeaders(headers []string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
        for _, header := range headers {
            req.Header.Del(header)
        }
        next.ServeHTTP(rw, req)
    })
}
```

`req.Header.Del("X-Forwarded-User")` does not delete a key stored as `X_Forwarded-User` (or other capitalisation variants that, after WSGI normalisation, alias to the same logical header).

The fix in v7.13.0 introduces `stripNormalizedHeader`, which lowercases header names and replaces underscores with hyphens before iterating the map and deleting matching keys directly.

## What a SAST tool should flag

A scanner that recognises "header allowlist/denylist applied without normalisation" should flag this region. Specifically: any rule that fires on `req.Header.Del(name)` used as a security boundary — when the application also accepts underscore-variant headers via downstream frameworks — applies here.

## References

- Advisory: <https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-vjrc-mh2v-45x6>
- CVE: CVE-2025-64484
- Fix: oauth2-proxy/oauth2-proxy commit `5993067505ca`
- Vulnerable snapshot: oauth2-proxy/oauth2-proxy at `87827435ce89`
