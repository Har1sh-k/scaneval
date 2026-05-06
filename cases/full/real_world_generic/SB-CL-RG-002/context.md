# SB-CL-RG-002 — Metabase GeoJSON fetch defeats local-link protection via DNS rebinding

## Summary

Metabase lets administrators register custom GeoJSON sources by URL. The application verifies that the URL is HTTP/HTTPS and that the host is not an obvious link-local literal, then fetches the URL server-side and serves the response back to the user. In versions prior to v0.53.8 / v0.52.16.4, the fetch uses the JVM's default DNS resolver. An attacker who controls a domain with multiple A records — one being a link-local IP — defeats the static host check: the static check sees the public domain, the runtime resolution returns the link-local address, and the HTTP client connects there. Self-hosted Metabase instances colocated with other unsecured services can have those services reached over the SSRF channel.

## Why it is a real bug

`src/metabase/api/geojson.clj:url->geojson` performs the HTTP fetch with no DNS-rebinding mitigation:

```clojure
(defn- url->geojson [url]
  (let [resp (try (http/get url {:as                 :reader
                                 :redirect-strategy  :none
                                 :socket-timeout     connection-timeout-ms
                                 :connection-timeout connection-timeout-ms
                                 :throw-exceptions   false})
                  ...)
```

The fix adds a custom `DnsResolver` (`non-link-local-dns-resolver`) that resolves the host, checks that no returned `InetAddress` is link-local, and otherwise throws an "invalid location" error before any connection is made. The resolver is injected via `:dns-resolver`.

## What a SAST tool should flag

A scanner with rules for SSRF — particularly "HTTP request to admin-influenced URL without DNS-rebinding-resistant host validation" — should fire on the annotated region. Even rules that recognise "validated host string fed to a separate resolver during connect" will land here.

## References

- Advisory: <https://github.com/metabase/metabase/security/advisories/GHSA-8xf9-9jc8-qp98>
- CVE: CVE-2025-30371
- Fix: metabase/metabase commit `e47b76cf6b6d` (PR #55460 / #55489)
- Vulnerable snapshot: metabase/metabase at `faf54a43ba46` (parent of fix on 0.53 release branch)
