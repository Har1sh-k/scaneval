# SB-TS-RW-064: Credential 'Allowed domains' wildcard bypass enables credentialed requests to attacker domains in n8n

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-2xcx-75h9-vr9h`
- CVE: `CVE-2026-25631`
- Vulnerable commit: `6c484fd4e85bd12025ff13eb88c37e701b468bbe` (release n8n@1.120.4)
- Fix commit: `404640f1e93fe848ec4b90e972a1ea53e33f80e2` (release n8n@1.121.0)

## Vulnerability
The wildcard match uses hostname.endsWith(domainSuffix) without enforcing a '.' boundary, so the suffix matches any host whose name ends with the bare domain string (e.g. 'example.com' matches 'evilexample.com'). Hostnames are also not normalized (case / trailing dot), widening the bypass. This lets the domain allowlist intended to confine where credentials are sent be defeated.

## Source / Carrier / Sink
- Source: The request URL configured by an authenticated workflow author in an HTTP Request node that uses a credential restricted with a wildcard 'Allowed domains' pattern (e.g. *.example.com).
- Carrier: The URL's hostname is parsed via new URL(urlString).hostname and compared in the wildcard branch of isDomainAllowed against domainSuffix = allowedDomain.substring(2).
- Sink: The allowlist decision hostname.endsWith(domainSuffix) returning true, which authorizes the server-side HTTP Request to be sent (with the attached credential) to the supplied host.
- Missing guard: No dot-boundary check on the wildcard suffix (and no hostname normalization), so endsWith matches sibling/look-alike domains; the allowlist fails to confine outbound credentialed requests to the intended domain.

## Fix
The fix (commit 404640f, released in 1.121.0) normalizes the hostname and allowed domains (lowercase, strip trailing dot), rejects empty hostnames, and changes the wildcard check to hostname.endsWith('.' + domainSuffix) so *.example.com matches only true subdomains and never evilexample.com or the bare base domain.

## Scanner Expectation
Flag the wildcard domain check hostname.endsWith(domainSuffix) as a flawed allowlist that permits server-side credentialed requests to attacker-influenced hosts (SSRF-style allowlist bypass / CWE-20): the host-allowlist boundary is improperly validated, letting a user-controlled URL reach an outbound request to an unintended domain.
