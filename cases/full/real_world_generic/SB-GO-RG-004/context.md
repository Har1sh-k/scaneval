# SB-GO-RG-004 — oauth2-proxy fragment confusion bypasses skip_auth_routes

## Summary

oauth2-proxy normalises the inbound request URI before evaluating `skip_auth_routes` and `skip_auth_regex` patterns. In versions prior to v7.15.2, the normalisation step strips the query string but not the URL fragment (`#`). Many upstream HTTP frameworks treat `#` as a client-side fragment delimiter and route the request to the path before `#`. Because oauth2-proxy still sees the full path-plus-fragment when applying its allowlist regex, an attacker can craft a request whose pre-fragment path is protected but whose suffix lets the regex match a public allowlist entry, bypassing authentication.

The advisory's example: a regex like `^/foo/.*/bar$` configured to expose a public path. A request to `/foo/secret#/bar` (or the encoded `%23/bar` form) makes oauth2-proxy regex-match `^/foo/.*/bar$`, while the upstream serves `/foo/secret`.

## Why it is a real bug

`pkg/requests/util/util.go:GetRequestPath` builds the path used for skip-auth matching by parsing the URI and returning `parsedURL.Path` (or, in the fallback branch, by stripping `?` only). Neither branch strips a `#` suffix. The fix introduces `stripRequestFragment` and applies it both to the parsed `Path` and to the fallback string before the regex match runs.

```go
func GetRequestPath(req *http.Request) string {
    uri := GetRequestURI(req)
    if parsedURL, err := url.Parse(uri); err == nil {
        return parsedURL.Path     // includes fragment-bearing path
    }
    if idx := strings.Index(uri, "?"); idx != -1 {
        return uri[:idx]
    }
    return uri
}
```

## What a SAST tool should flag

Any rule that recognises "request-derived path used for an authorization/route allowlist check without canonicalisation" should flag this region. The annotated lines build the path that is later regex-matched against `skip_auth_routes`.

## References

- Advisory: <https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-pxq7-h93f-9jrg>
- CVE: CVE-2026-41059
- Fix: oauth2-proxy/oauth2-proxy commit `bdfde725c617`
- Vulnerable snapshot: oauth2-proxy/oauth2-proxy at `848ec8ba82e8` (v7.15.1)
