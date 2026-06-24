# SB-TS-RW-092: Credential allowed-domains restriction bypassed in declarative node HTTP requests (SSRF)

## Advisory
- Repo: `n8n-io/n8n`
- GHSA: `GHSA-3875-8gcx-7v46`
- CVE: ``
- Vulnerable commit: `4e527293307f5cefd6e801b728bffd54e450d308` (release n8n@2.19.5)
- Fix commit: `8551b1b90ce16b31a017bd07177694ef39ad226d` (release n8n@2.20.0)

## Vulnerability
While building each declarative request, RoutingNode sets options such as timeout and proxy but does not consult the credential's allowedHttpRequestDomains/allowedDomains settings before calling this.makeRequest with the decrypted credentials. As a result the server issues credentialed requests to hosts the operator intended to forbid, allowing SSRF and credential exfiltration to attacker-controlled endpoints.

## Source / Carrier / Sink
- Source: Attacker-controllable target URL/host derived from request parameters sent to /rest/dynamic-node-parameters/options for a declarative node.
- Carrier: itemContext[itemIndex].requestData (request options/URL) carrying decrypted credentials into the HTTP client.
- Sink: this.makeRequest(...) dispatching the credentialed HTTP request.
- Missing guard: No enforcement of the credential's allowedHttpRequestDomains / allowedDomains allow-list before the request is sent.

## Fix
The fix adds a domain check before requestPromises.push: it rejects when allowedHttpRequestDomains === 'none', requires a non-empty list when in 'domains' mode, and otherwise injects the credential's allow-list via getCredentialAllowedDomains(credentials) into requestData.options.allowedDomains so the outgoing request is restricted to the permitted hosts.

## Scanner Expectation
Flag the credentialed makeRequest dispatch of an attacker-influenced URL without an allowed-domains/host allow-list check as SSRF.
