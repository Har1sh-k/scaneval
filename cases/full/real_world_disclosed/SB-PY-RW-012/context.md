# SB-PY-RW-012: Unauthenticated SSRF in Dify console /remote-files/upload endpoint

## Advisory
- Repo: `langgenius/dify`
- GHSA: `GHSA-8235-vv5j-mmvg`
- CVE: ``
- Vulnerable commit: `cd03e0a9ef7f2383853ace444e3aefe4fac05cde` (release 1.12.1)
- Fix commit: `26b704da0bed2a0673fcefb06c17532527ab6de6` (release 1.13.0)

## Vulnerability
The url value comes straight from the request payload and is passed unvalidated into ssrf_proxy.head(url)/ssrf_proxy.get(url), which perform a server-side fetch with no allow-list or private/reserved IP range checks. Because the endpoint is wired into the fastopenapi console_router with no login_required guard, the request executes as an anonymous user, making this SSRF reachable without authentication.

## Source / Carrier / Sink
- Source: Attacker-controlled url field in the JSON request body to POST /console/api/remote-files/upload (payload.url).
- Carrier: The url string is bound to RemoteFileUploadPayload and read as url = payload.url, then passed directly as the url argument to the ssrf_proxy fetch helpers.
- Sink: ssrf_proxy.head(url=url) and ssrf_proxy.get(url=url, ...) (and the later ssrf_proxy.get(url)) which perform server-side HTTP requests to the supplied URL.
- Missing guard: No authentication (no @login_required on the fastopenapi route) and no URL/host validation against private, loopback, or cloud-metadata IP ranges before the outbound request.

## Fix
PR #32236 (merged in release 1.13.0) re-registered both remote-files handlers as flask_restx Resource classes under console_ns and added the @login_required decorator to the get and post methods, so the SSRF-prone fetch can no longer be triggered by unauthenticated callers.

## Scanner Expectation
Flag the data flow from the request-supplied url (payload.url) into ssrf_proxy.head/ssrf_proxy.get as an SSRF (CWE-918): a user-controlled URL reaching a server-side HTTP fetch without host/IP allow-listing, compounded by the missing authentication on the route.
