# SB-GO-RG-003 — oauth2-proxy reverse-proxy mode trusts forwarded headers from any client

## Summary

`--reverse-proxy` tells oauth2-proxy that an upstream load balancer is in front of it, so it should honour `X-Forwarded-Proto`, `X-Forwarded-Host`, and `X-Forwarded-Uri` headers. In versions prior to v7.15.2, this trust is global: once `--reverse-proxy` is on, the proxy honours those headers from *any* peer, including direct clients. An attacker who can reach oauth2-proxy directly can therefore spoof `X-Forwarded-Uri` so that authentication and skip-auth rules evaluate against a different path than the one the upstream backend actually serves, bypassing authentication on protected routes.

## Why it is a real bug

In `pkg/requests/util/util.go`, `IsProxied(req)` returns `scope.ReverseProxy` — a static configuration flag — with no check on the source IP. Every X-Forwarded-* reader (`GetRequestProto`, `GetRequestHost`, `GetRequestURI`) uses `IsProxied` to gate whether to use the header. The fix renames the function to `CanTrustForwardedHeaders` and consults a `--trusted-proxy-ip` allowlist (`scope.TrustedProxies`) before honouring forwarded headers.

```go
func IsProxied(req *http.Request) bool {
    scope := middlewareapi.GetRequestScope(req)
    if scope == nil {
        return false
    }
    return scope.ReverseProxy
}
```

## What a SAST tool should flag

The `IsProxied` function is the single trust gate for client-supplied forwarded headers, and it makes its decision purely from a static config flag without referencing `req.RemoteAddr`. A scanner that recognizes "header trust decision without source-IP validation" should flag this region (R1). Annotated R2 covers the most security-relevant consumer (`GetRequestURI`), where the unsafe trust decision becomes a controlled URI used for skip-auth-route matching.

## References

- Advisory: <https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-7x63-xv5r-3p2x>
- CVE: CVE-2026-40575
- Fix: oauth2-proxy/oauth2-proxy commit `aff369dfa31c`
- Vulnerable snapshot: oauth2-proxy/oauth2-proxy at `848ec8ba82e8` (v7.15.1)
