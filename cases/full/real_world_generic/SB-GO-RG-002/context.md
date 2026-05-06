# SB-GO-RG-002 — oauth2-proxy health-check User-Agent auth bypass

## Summary

oauth2-proxy can identify health-check probes by either path (`--ping-path`) or user-agent (`--ping-user-agent`, `--gcp-healthchecks`). Health-check requests are answered directly with a 200 and never reach the authentication path. In versions prior to v7.15.2, the check is "path matches OR user-agent matches" — so a non-health-check request that simply carries the configured User-Agent header is treated as healthy and answered with a successful response.

In an `auth_request`-style integration (nginx `auth_request`, Traefik `ForwardAuth`, etc.), the reverse proxy forwards each inbound request to oauth2-proxy at `/oauth2/auth` and decides admit/deny based on the response. Because the inbound `User-Agent` header is preserved on the auth subrequest, any external client that sets `User-Agent: GoogleHC/1.0` (when `--gcp-healthchecks` is on) sees the proxy treat the auth subrequest as a health probe and return 200, bypassing authentication entirely.

## Why it is a real bug

`pkg/middleware/healthcheck.go:isHealthCheckRequest`:

```go
func isHealthCheckRequest(paths, userAgents map[string]struct{}, req *http.Request) bool {
    if _, ok := paths[req.URL.EscapedPath()]; ok {
        return true
    }
    if _, ok := userAgents[req.Header.Get("User-Agent")]; ok {
        return true
    }
    return false
}
```

The two checks are independent. The fix in v7.15.2 nests the user-agent check inside the path check so the request must hit a configured ping path *and* carry a matching user-agent.

## What a SAST tool should flag

A scanner that recognizes "request-attribute classification used to gate authentication" should flag this region: an attacker-controlled header (`User-Agent`) is the sole input to a control-flow decision (`return true`) that short-circuits authentication.

## References

- Advisory: <https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-5hvv-m4w4-gf6v>
- CVE: CVE-2026-34457
- Fix: oauth2-proxy/oauth2-proxy commit `43596a7bab20`
- Vulnerable snapshot: oauth2-proxy/oauth2-proxy at `848ec8ba82e8` (v7.15.1)
