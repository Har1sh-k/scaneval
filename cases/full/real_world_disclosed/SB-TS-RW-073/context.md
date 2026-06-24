# SB-TS-RW-073: SSRF in AgentFlow HTTP Node: user-controlled URL reaches server-side request with no default host restrictions

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-fvcw-9w9r-pxc7`
- CVE: `CVE-2026-31829`
- Vulnerable commit: `55b6913c03f0dba37cc207975f0c0d0786e0f3c7` (release flowise@3.0.12)
- Fix commit: `643ebf533550460d7688f9e636174885ba2bb5cf` (release flowise@3.0.13)

## Vulnerability
The node sends a request to an attacker-controlled URL through secureAxiosRequest, but the underlying checkDenyList short-circuits with 'if (!httpDenyListString) return' when HTTP_DENY_LIST is not configured, which is the out-of-the-box default. This leaves the server-side request unrestricted (CWE-918 SSRF), allowing access to internal services and cloud metadata.

## Source / Carrier / Sink
- Source: User-controlled HTTP node url input (nodeData.inputs.url) configurable in a chatflow/agentflow and triggerable via chat input.
- Carrier: finalUrl built from url plus query parameters and assigned to requestConfig.url (AxiosRequestConfig).
- Sink: secureAxiosRequest(requestConfig) performing the server-side HTTP request to the user-supplied URL.
- Missing guard: checkDenyList returns early when HTTP_DENY_LIST is unset (the default), so no validation of the target host against private/loopback/link-local/cloud-metadata ranges is performed before the request.

## Fix
The 3.0.13 fix (commit 643ebf53, #5653) reworked packages/components/src/httpSecurity.ts to address DNS-rebinding/TOCTOU in the deny-list enforcement used by secureAxiosRequest/secureFetch; full secure-by-default blocking of private ranges/metadata was completed by a follow-up that ships a built-in default HTTP_DENY_LIST. Operators are expected to enable the deny list to block private and metadata addresses.

## Scanner Expectation
Flag a server-side HTTP request whose target URL derives from user-controlled input without validation/allow-listing of the destination host (SSRF).
