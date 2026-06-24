# SB-TS-RW-067: Flowise Execute Flow node SSRF: user-controlled base URL passed to axios without checkDenyList/secureFetch validation

## Advisory
- Repo: `FlowiseAI/Flowise`
- GHSA: `GHSA-9hrv-gvrv-6gf2`
- CVE: ``
- Vulnerable commit: `f0c1294173a55f26e0b972c39c0c16917f5ca9e7` (release flowise@3.0.13)
- Fix commit: `c7f18f51bb2e729e34f8301f0fb633a873fe946e` (release flowise@3.1.0)

## Vulnerability
The base URL is fully attacker-controlled through the executeFlowBaseURL node input and is used to build the request URL with no validation against private ranges, loopback, link-local or cloud-metadata addresses. The request is made with the plain axios client instead of the existing secureAxiosRequest/checkDenyList helpers in httpSecurity.ts, so the SSRF deny-list and DNS-rebinding protections that the rest of the codebase relies on are simply never invoked for this code path.

## Source / Carrier / Sink
- Source: User-configurable executeFlowBaseURL input on the Execute Flow agentflow node (nodeData.inputs.executeFlowBaseURL), set by any authenticated user or via a chatflow-update API.
- Carrier: baseURL is concatenated into finalUrl (`${baseURL}/api/v1/prediction/${selectedFlowId}`) and placed in requestConfig.url, triggered when POST /api/v1/prediction/<chatflowId> runs the flow.
- Sink: await axios(requestConfig) issues the outbound HTTP request to the attacker-controlled URL using the raw axios client.
- Missing guard: No call to httpSecurity's checkDenyList / resolveAndValidate / secureAxiosRequest; the URL is never validated against private, loopback, link-local or cloud-metadata addresses before the request.

## Fix
Fix commit c7f18f51 (shipped in 3.1.0) imports secureAxiosRequest from ../../../src/httpSecurity and replaces `const response = await axios(requestConfig)` with `const response = await secureAxiosRequest(requestConfig)`, so the Execute Flow request now flows through the SSRF deny-list / host-validation logic before any outbound request is made.

## Scanner Expectation
A scanner should flag that an attacker-controlled URL (executeFlowBaseURL) reaches an outbound HTTP request (axios) without passing through an SSRF allow/deny-list validation, permitting requests to internal/metadata endpoints (SSRF, CWE-918).
