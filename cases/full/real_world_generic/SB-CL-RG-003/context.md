# SB-CL-RG-003 — Metabase HTTP channel webhook SSRF

## Summary

Metabase's HTTP channel implements webhook delivery and the "test webhook" admin action. The channel takes a destination URL from the admin's webhook configuration and posts to it. In versions prior to 0.55.13 / 0.56.3 / 0.57.1, the implementation does not validate that the destination resolves to a legitimate external host: any URL the admin enters (including the Webhook test form) is fetched. In a self-hosted deployment colocated with internal services or cloud-metadata endpoints (`http://metadata.google.internal/`, `http://127.0.0.1:…`, link-local addresses), the test endpoint becomes a server-side request gun.

## Why it is a real bug

`src/metabase/channel/impl/http.clj`'s `:channel/http` send method:

```clojure
(mu/defmethod channel/send! :channel/http
  [{{:keys [url method auth-method auth-info]} :details} :- HTTPChannel request]
  (let [req (merge ... {:url url} ...)]
    (http/request (cond-> req ...))))
```

There is no inspection of `url` before invoking `clj-http.client/request`. The fix adds `metabase.util.http/valid-host?` (strategy-driven: rejects link-local, loopback, site-local, and `metadata.google.internal`) and gates `send!` on it.

## What a SAST tool should flag

A scanner with rules for SSRF — particularly "HTTP request invoked with admin-influenced URL without destination-host validation" — should fire on the annotated region. Metabase-specific rule packs that recognise `clj-http.client/request` (or `:url` in a request map) sourced from configuration data should land here.

## References

- Advisory: <https://github.com/metabase/metabase/security/advisories/GHSA-2wgg-7r2p-cmqx>
- CVE: CVE-2026-22805
- Fix: metabase/metabase commit `7ac7990ceb9f` (PR #62015 / #62118)
- Vulnerable snapshot: metabase/metabase at `51045504469c` (parent of fix on 0.55 release branch)
