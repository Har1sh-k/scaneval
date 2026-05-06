# SB-GO-RG-001 — oauth2-proxy skip_auth_routes auth bypass

## Summary

oauth2-proxy is a reverse proxy that adds an authentication layer in front of upstream services. Operators configure `skip_auth_routes` (or `skip_auth_regex`) with regex patterns describing public paths that should be reachable without authentication.

In versions prior to v7.11.0, the proxy decides whether a request is "allowed" by matching the configured regex against the full request URI — including the query string. An attacker can therefore craft a request whose path is protected but whose query string makes the URI match one of the public allowlist entries, bypassing authentication entirely.

## Why it is a real bug

Two routines collaborate to produce the bypass:

- `pkg/requests/util/util.go:GetRequestURI` returns either the value of the `X-Forwarded-Uri` header (when proxied) or `req.URL.RequestURI()`. Both representations include the query string.
- `oauthproxy.go:isAllowedPath` matches the configured `skip_auth_routes` regex (`route.pathRegex`) against the result of `GetRequestURI`. The match operates on path **plus query**, so a request like `GET /protected/?foo=/public/anything` can satisfy a regex such as `^/public/.*`.

The fix in v7.11.0 narrows the matching surface so that only the path component is regex-matched.

## What a SAST tool should flag

A scanner that follows the data flow from `req.URL.RequestURI()` (which carries attacker-controlled query data) into a `pathRegex.MatchString` used to decide whether to skip authentication should flag this as an authentication-bypass risk.

## References

- Advisory: <https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-7rh7-c77v-6434>
- CVE: CVE-2025-54576
- Fix: oauth2-proxy/oauth2-proxy commit `9ffafad4b2d2`
- Vulnerable snapshot: oauth2-proxy/oauth2-proxy at `f4b33b64bd66`
