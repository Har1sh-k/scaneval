# CVE corpus shortlist

Research date: 2026-09-19. **30 published-CVE candidates from 29 repositories**, scoped to Python, TypeScript/JavaScript, Go, and Rust. This is a detailed curation queue, not an admitted or validated corpus.

The [repository inventory](REPOSITORY_INVENTORY.md) is the broader source pool. These candidates were chosen for distinct security mechanisms and available public evidence, not severity quotas or advisory volume. Grafana appears twice because its Go path handling and TypeScript SVG rendering test different mechanisms.

## What has been checked

- Every CVE below had a `PUBLISHED` record in the official [CVE List V5](https://github.com/CVEProject/cvelistV5) when checked.
- Advisory-linked public commit objects were fetched where supplied. The files listed below are review starting points, not accepted scoring regions. A reachable commit is not proof that it fixes the issue on a selected release branch.
- Source discrepancies are retained. Public CVE records, GHSA metadata, and vendor bulletins sometimes disagree on versions, severity, or dates.
- No source snapshots have been cloned, built, or assigned L1-L4 validation in this pass. No vulnerability was reproduced and no fixed/safe label was granted.

An advisory's publication date and a CVE record's publication date are different artifacts. Neither alone establishes the earliest disclosure or a model's exposure horizon. The date below is explicitly the CVE record date. Severity in the index is the captured CNA metric and includes its CVSS version; it is not a measure of SAST difficulty.

## Language and workload coverage

| Implementation lead | Candidate count | Limitation |
|---|---:|---|
| Python | 11 | Several are framework/AI-service integration bugs, not bugs caused by model output. |
| TypeScript/JavaScript | 5 | Includes one Strapi case whose exact source language still needs mapping. |
| Go | 8 | Infrastructure/identity-heavy; this is not a balanced estimate of all Go applications. |
| Rust | 6 | Includes mixed Rust/JS boundaries and embedding-specific cases. |

These are research counts, not release weights. A repository language badge does not establish the language of a vulnerability. Libraries/runtimes and full applications also need separate reporting. The current list includes prospective class extensions such as XSS, deserialization, template/code injection, and resource exhaustion; do not squeeze these into an incompatible existing six-kind label. Final class scope is still a decision.

## Candidate index

"Next check" is the unresolved work, not a validation verdict. All candidates require exact source mapping and independent label review, including those with focused patches.

| Candidate / official CVE record | Implementation | Distinct mechanism | CNA severity | Next check |
|---|---|---|---|---|
| [Langflow: CVE-2026-33017](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/33xxx/CVE-2026-33017.json) | Python | Public flow data replaces trusted executable node definitions | critical 9.3 (v4.0) | Validate source/flow boundary |
| [Open WebUI: CVE-2026-87015](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/87xxx/CVE-2026-87015.json) | Python | Closure-bound cookies cross tool-server credentials | medium 6.8 (v3.1) | Validate multi-server configuration |
| [FastMCP: CVE-2026-32871](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/32xxx/CVE-2026-32871.json) | Python | URL path substitution escapes an authorized API prefix | critical 10 (v4.0) | Validate URL/auth propagation |
| [MCP Python SDK: CVE-2025-66416](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/66xxx/CVE-2025-66416.json) | Python | Local HTTP transport lacks default rebinding protection | high 7.6 (v4.0) | Validate HTTP-only defaults |
| [LiteLLM: CVE-2026-59820](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/59xxx/CVE-2026-59820.json) | Python | Skills ZIP extraction escapes its destination | medium 6.1 (v4.0) | Resolve package/tag version naming |
| [Argo CD: CVE-2025-55190](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/55xxx/CVE-2025-55190.json) | Go | Project-read authority exposes repository credentials | critical 10 (v3.1) | Validate scope and branch |
| [vLLM: CVE-2025-24357](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/24xxx/CVE-2025-24357.json) | Python | Untrusted model weights reach unsafe deserialization | high 7.5 (v3.1) | Validate loader and dependency semantics |
| [Haystack: CVE-2024-41950](https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/41xxx/CVE-2024-41950.json) | Python | User-controlled pipeline templates reach unsandboxed rendering | high 7.5 (v3.1) | Choose component/root-cause family |
| [BentoML: CVE-2025-32375](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/32xxx/CVE-2025-32375.json) | Python | Runner RPC accepts unsafe serialized input | critical 9.8 (v3.1) | Needs exact fix and range reconciliation |
| [Flask: CVE-2023-30861](https://github.com/CVEProject/cvelistV5/blob/main/cves/2023/30xxx/CVE-2023-30861.json) | Python | Session refresh omits cache variance | high 7.5 (v3.1) | Validate proxy/session assumptions |
| [Starlette: CVE-2024-47874](https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/47xxx/CVE-2024-47874.json) | Python | Multipart text buffering lacks a size bound | high 8.7 (v4.0) | Validate parser path and resource guard |
| [Next.js: CVE-2025-29927](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/29xxx/CVE-2025-29927.json) | TypeScript | External control header skips authorization middleware | critical 9.1 (v3.1) | Validate one supported patch branch |
| [Fastify: CVE-2026-76169](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/76xxx/CVE-2026-76169.json) | JavaScript | Malformed URL reaches a sibling fallback without its hook | high 7.5 (v3.1) | Validate routing/auth-hook chain |
| [Strapi: CVE-2024-52588](https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/52xxx/CVE-2024-52588.json) | TS/JS pending | Administrative webhook reaches a forbidden destination | medium 4.9 (v3.1) | Needs fix mapping and boundary review |
| [Directus: CVE-2026-61835](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/61xxx/CVE-2026-61835.json) | TypeScript | Address deny-list fails to block a loopback-equivalent literal | high 7.7 (v3.1) | Resolve advisory boundary conflict |
| [Windmill: CVE-2026-33881](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/33xxx/CVE-2026-33881.json) | Rust + JS generation | Workspace variable data is inserted as executable script | high 7.3 (v4.0) | Validate authority; preserve severity conflict |
| [Tauri: CVE-2024-35222](https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/35xxx/CVE-2024-35222.json) | Rust + JS IPC | Iframe invokes host IPC without origin permission | medium 5.9 (v3.1) | Use stable branch; resolve beta conflict |
| [Wasmtime WASI: CVE-2026-47261](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/47xxx/CVE-2026-47261.json) | Rust | Truncation is omitted from write-authority checking | high 7.5 (v3.1) | Validate embedding, not stock CLI |
| [SurrealDB: CVE-2026-49997](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/49xxx/CVE-2026-49997.json) | Rust | Node deletion bypasses graph-edge permissions | medium 5.4 (v3.1) | Isolate edge-delete patch from other fixes |
| [Qdrant: CVE-2026-25628](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/25xxx/CVE-2026-25628.json) | Rust | Read-only actor can append through logger path setting | high 8.6 (v3.1) | Resolve 1.15.6 versus 1.16.0 fix records |
| [Cargo: CVE-2026-5222](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/5xxx/CVE-2026-5222.json) | Rust | Registry URL identity merges credential boundaries | low 2.3 (v4.0) | Map binary versus crate versions |
| [runc: CVE-2024-21626](https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/21xxx/CVE-2024-21626.json) | Go | Leaked file descriptor crosses container filesystem boundary | high 8.6 (v3.1) | Separate variants and required fixes |
| [Kubernetes kubelet: CVE-2024-9042](https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/9xxx/CVE-2024-9042.json) | Go | Authorized Windows log query reaches command construction | medium 5.9 (v3.1) | Needs Windows branch and fix mapping |
| [Vault: CVE-2025-6203](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/6xxx/CVE-2025-6203.json) | Go | Byte-size limit does not bound JSON processing cost | high 7.5 (v3.1) | Needs complete corrected fix mapping |
| [Grafana backend: CVE-2021-43798](https://github.com/CVEProject/cvelistV5/blob/main/cves/2021/43xxx/CVE-2021-43798.json) | Go | Plugin asset path escapes its directory | high 7.5 (v3.1) | Validate route and fixed branch |
| [Authentik: CVE-2024-47070](https://github.com/CVEProject/cvelistV5/blob/main/cves/2024/47xxx/CVE-2024-47070.json) | Python | Invalid proxy-IP context causes an authentication policy to fail open | critical 9.1 (v3.1) | Validate Python plus policy configuration |
| [Grafana GeoMap: CVE-2022-23552](https://github.com/CVEProject/cvelistV5/blob/main/cves/2022/23xxx/CVE-2022-23552.json) | TypeScript | Editor-controlled SVG executes in a viewer's session | high 7.3 (v3.1) | Validate SVG sanitizer and editor/viewer boundary |
| [oauth2-proxy: CVE-2025-54576](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/54xxx/CVE-2025-54576.json) | Go | Query text incorrectly satisfies a path-only auth-skip rule | critical 9.1 (v3.1) | Validate affected regex configuration |
| [NATS Server: CVE-2022-26652](https://github.com/CVEProject/cvelistV5/blob/main/cves/2022/26xxx/CVE-2022-26652.json) | Go | JetStream archive restore escapes its output area | Not supplied | Validate restore authority and archive format |
| [Dex: CVE-2022-39222](https://github.com/CVEProject/cvelistV5/blob/main/cves/2022/39xxx/CVE-2022-39222.json) | Go | OAuth approval state is insufficiently bound to the user flow | critical 9.3 (v3.1) | Validate public-client state transitions |

## Candidate dossiers

For every case, a future accepted finding must establish the specific failure below under its stated authority/deployment assumptions. A type label or overlapping line alone is insufficient. Endpoint and parameter names are evidence where applicable, not universal required fields.

### 01. Langflow: CVE-2026-33017

CVE record published: 2026-03-20. Implementation lead: Python. Inspect first: `src/backend/base/langflow/api/v1/chat.py`. These are not final reporting locations.

* Advisory record: [CVE-2026-33017 / GHSA-vwmf-pq79-vjvx](https://github.com/advisories/GHSA-vwmf-pq79-vjvx), published 2026-03-17.
* Affected/fixed evidence: PyPI `langflow` `<= 1.8.2`; first patched `1.9.0`, as stated by the GHSA. The record links the [1.8.2 release](https://github.com/langflow-ai/langflow/releases/tag/1.8.2) and [1.9.0 is the stated fix](https://github.com/advisories/GHSA-vwmf-pq79-vjvx).
* Public fix pointer: advisory references [PR #12160](https://github.com/langflow-ai/langflow/pull/12160) and [commit `73b6612`](https://github.com/langflow-ai/langflow/commit/73b6612e3ef25fdae0a752d75b0fabd47328d4f0). Inspect that diff for the public-flow build endpoint and authorization/execution guard; this pass did not assert a particular pre-fix line.
* Assumptions / mechanism: server exposes a public flow build endpoint; the advisory describes unauthenticated code execution through that route. The issue is accepting caller-supplied executable flow data instead of the stored public flow, not merely having an intentionally public endpoint.
* Still unvalidated: endpoint configuration, whether the vulnerable component remains enabled in a deployment, exact source mapping for 1.8.2, and any safe local reproduction.

### 02. Open WebUI: CVE-2026-87015

CVE record published: 2026-09-09. Implementation lead: Python. Inspect first: `backend/open_webui/utils/tools.py`. These are not final reporting locations.

* Advisory record: [CVE-2026-87015 / GHSA-p78m-89r6-pgf7](https://github.com/advisories/GHSA-p78m-89r6-pgf7), published 2026-09-10.
* Affected/fixed evidence: PyPI `open-webui` `>= 0.6.27, < 0.11.1`; fixed in `0.11.1`. The GHSA also links [release v0.11.1](https://github.com/open-webui/open-webui/releases/tag/v0.11.1).
* Public fix pointer: [PR #28630](https://github.com/open-webui/open-webui/pull/28630) and [commit `cd9db21`](https://github.com/open-webui/open-webui/commit/cd9db21c5276807a2975ddba17cef369ad1114b7), both referenced by the advisory. Review request forwarding / tool-server authentication logic in that diff.
* Assumptions / mechanism: a user reaches a bearer-authenticated configured tool server; the advisory says session cookies were sent to it. The CVE record identifies late-bound closure capture of the enclosing connection loop's cookie jar; multiple server configurations and iteration order matter.
* Still unvalidated: browser/server cookie settings, user interaction and tool-server configuration; no claim that cookies can be captured in a particular deployment.

### 03. FastMCP: CVE-2026-32871

CVE record published: 2026-04-02. Implementation lead: Python. Inspect first: `src/fastmcp/utilities/openapi/director.py`. These are not final reporting locations.

* Advisory record: [CVE-2026-32871 / GHSA-vv7q-7jx5-f767](https://github.com/advisories/GHSA-vv7q-7jx5-f767), published 2026-03-31.
* Affected/fixed evidence: PyPI `fastmcp` `< 3.2.0`; first patched `3.2.0`, with linked [v3.2.0 release](https://github.com/PrefectHQ/fastmcp/releases/tag/v3.2.0).
* Public fix pointer: [PR #3507](https://github.com/PrefectHQ/fastmcp/pull/3507) and [commit `40bdfb6`](https://github.com/PrefectHQ/fastmcp/commit/40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71). Treat the OpenAPI-provider URL/path validation code altered there as the first inspection target.
* Assumptions / mechanism: an MCP client controls a path parameter consumed by `RequestDirector._build_url()`. Unencoded substitution followed by URL joining can escape the intended API prefix while retaining the provider's authorization headers. This is backend URL traversal/SSRF, not filesystem traversal. The model need not originate the input.
* Still unvalidated: provider enablement, allowed backend endpoints, network egress, source locations and practical impact in a pinned pre-3.2.0 environment.

### 04. MCP Python SDK: CVE-2025-66416

CVE record published: 2025-12-02. Implementation lead: Python. Inspect first: `src/mcp/server/fastmcp/server.py`. These are not final reporting locations.

* Advisory record: [CVE-2025-66416 / GHSA-9h52-p55h-vw2f](https://github.com/advisories/GHSA-9h52-p55h-vw2f), published 2025-12-02.
* Affected/fixed evidence: PyPI `mcp` `< 1.23.0`; first patched `1.23.0`, exactly as recorded in the GHSA.
* Public fix pointer: [commit `d3a1841`](https://github.com/modelcontextprotocol/python-sdk/commit/d3a184119e4479ea6a63590bc41f01dc06e3fa99), linked by the advisory. Inspect localhost host/origin or DNS-rebinding defaults in that commit rather than presuming the currently named module path.
* Assumptions / mechanism: an MCP server bound on localhost with defaults, and a browser/network setup capable of the advisory’s rebinding precondition. The CVE limits this to unauthenticated localhost HTTP/SSE servers without configured transport security; stdio is unaffected.
* Still unvalidated: browser behavior, bind address, deployment flags, reachable ports and affected source in a pre-1.23.0 tag.

### 05. LiteLLM: CVE-2026-59820

CVE record published: 2026-07-08. Implementation lead: Python. Inspect first: `litellm/llms/litellm_proxy/skills/sandbox_executor.py`. These are not final reporting locations.

* Advisory record: [CVE-2026-59820 / GHSA-5jmr-gcrj-2c9q](https://github.com/advisories/GHSA-5jmr-gcrj-2c9q), published 2026-07-22.
* Affected/fixed evidence: PyPI `litellm` `< 1.83.7`; patched `1.83.7`. The advisory links [v1.83.7-stable](https://github.com/BerriAI/litellm/releases/tag/v1.83.7-stable).
* Public fix pointer: [PR #25475](https://github.com/BerriAI/litellm/pull/25475) and [commit `6a15adc`](https://github.com/BerriAI/litellm/commit/6a15adcd64137d37f73dee76dfe7481f8c2d9196). The archive extraction / skill-install path in the diff is the code-review pointer.
* Assumptions / mechanism: a proxy/operator exposes the relevant Skills archive ingestion path to a malicious archive. Distinct archive-path traversal / arbitrary-write mechanism in an LLM gateway.
* Still unvalidated: upload authorization, extraction destination/privilege, archive format and the exact pre-1.83.7 code path.

Source reconciliation: the CVE record names `<1.83.7-stable` and specifies an authenticated key/user authorized for Skills or LLM API routes. Resolve package-version and Git-tag naming before selecting the snapshot; do not assume the route is publicly writable.

### 06. Argo CD: CVE-2025-55190

CVE record published: 2025-09-04. Implementation lead: Go. Inspect first: `server/project/project.go; pkg/apis/application/v1alpha1/types.go`. These are not final reporting locations.

* Advisory record: [CVE-2025-55190 / GHSA-786q-9hcg-v9ff](https://github.com/advisories/GHSA-786q-9hcg-v9ff), published 2025-09-04.
* Affected/fixed evidence: `github.com/argoproj/argo-cd/v2`: `>=2.13.0,<2.13.9` fixed `2.13.9`, and `>=2.14.0,<2.14.16` fixed `2.14.16`; v3 ranges `<3.0.14` fixed `3.0.14`, and `>=3.1.0-rc1,<3.1.2` fixed `3.1.2`. These four ranges are in the GHSA.
* Public fix pointer: [commit `e8f8610`](https://github.com/argoproj/argo-cd/commit/e8f86101f5378662ae6151ce5c3a76e9141900e8), referenced by the GHSA. Inspect project-token authorization and repository credential redaction in the diff.
* Assumptions / mechanism: attacker holds a project API token and the target installation stores usable repository credentials. Distinct GitOps secret-isolation / authorization case.
* Still unvalidated: RBAC policy, token scope, repo credential configuration, affected release source and whether secrets are actually observable.

Source reconciliation: the CVE record covers any token with project-get permission, not only project-scoped tokens. It reports CVSS 3.1 10.0, while the GHSA value captured above is 9.9. Its 3.0.x narrative and structured endpoint also differ; preserve branch-specific evidence.

### 07. vLLM: CVE-2025-24357

CVE record published: 2025-01-27. Implementation lead: Python. Inspect first: `vllm/model_executor/model_loader/weight_utils.py`. These are not final reporting locations.

* Advisory record: [CVE-2025-24357 / GHSA-rh4j-5rhw-hr54](https://github.com/advisories/GHSA-rh4j-5rhw-hr54), published 2025-01-27.
* Affected/fixed evidence: PyPI `vllm` `< 0.7.0`; first patched `0.7.0`; linked [v0.7.0 release](https://github.com/vllm-project/vllm/releases/tag/v0.7.0).
* Public fix pointer: [PR #12366](https://github.com/vllm-project/vllm/pull/12366) and [commit `d3d6bb1`](https://github.com/vllm-project/vllm/commit/d3d6bb13fb62da3234addf6574922a4ec0513d04). The advisory specifically identifies the Hugging Face model-weight iterator / `torch.load` decision as the review target.
* Assumptions / mechanism: victim is induced to load attacker-controlled model weights; advisory rates this as requiring user interaction. Distinct model-artifact deserialization case.
* Still unvalidated: actual model source controls, PyTorch version/options, GPU environment and executable payload behavior; do not download malicious weights.

### 08. Haystack: CVE-2024-41950

CVE record published: 2024-07-31. Implementation lead: Python. Inspect first: `haystack/components/routers/conditional_router.py`. These are not final reporting locations.

* Advisory record: [CVE-2024-41950 / GHSA-hx9v-6r9f-w677](https://github.com/advisories/GHSA-hx9v-6r9f-w677), published 2024-07-31.
* Affected/fixed evidence: PyPI `haystack-ai` `< 2.3.1`; fixed `2.3.1`, with [v2.3.1 release](https://github.com/deepset-ai/haystack/releases/tag/v2.3.1).
* Public fix pointer: [PR #8095](https://github.com/deepset-ai/haystack/pull/8095), [PR #8096](https://github.com/deepset-ai/haystack/pull/8096), [commit `3fed136`](https://github.com/deepset-ai/haystack/commit/3fed1366c448b02189851bf08166c1f6477a02b0), and [commit `6c25a5c`](https://github.com/deepset-ai/haystack/commit/6c25a5c73e83aa32c3241ba84a5cbb3ac0e8a89e). Inspect component template rendering / environment selection there.
* Assumptions / mechanism: authenticated or otherwise permitted actor can supply an untrusted Jinja2 template to the affected component. Distinct template execution/sandbox boundary.
* Still unvalidated: actual pipeline configuration, permissions, template source and exact reachability on a pre-2.3.1 checkout.

### 09. BentoML: CVE-2025-32375

CVE record published: 2025-04-09. Implementation lead: Python. Inspect first: `Runner server; precise source mapping pending`. These are not final reporting locations.

* Advisory record: [CVE-2025-32375 / GHSA-7v4r-c989-xh26](https://github.com/advisories/GHSA-7v4r-c989-xh26), published 2025-04-09.
* Affected/fixed evidence: PyPI `bentoml` `>= 1.0.0a1, < 1.4.8`; first patched `1.4.8`, as supplied by the GHSA.
* Public fix pointer: the [maintainer/security advisory](https://github.com/bentoml/BentoML/security/advisories/GHSA-7v4r-c989-xh26) is the public source; unlike the other cards, the global record did not expose a fix commit/PR in its reference list. Start from runner-server request serialization/deserialization in a `1.4.7` vs `1.4.8` source diff.
* Assumptions / mechanism: runner server is network-exposed/reachable by a party that can supply the serialized input. Distinct RPC/serialization boundary rather than model-weight deserialization.
* Still unvalidated: transport exposure, serialization format, authentication, precise changed files and a safe reproduction.

Source reconciliation: the GHSA includes the prerelease lower bound `1.0.0a1`; the CVE record uses `>=1.0`. Choose and verify a stable affected snapshot instead of silently merging these bounds.

### 10. Flask: CVE-2023-30861

CVE record published: 2023-05-02. Implementation lead: Python. Inspect first: `src/flask/sessions.py`. These are not final reporting locations.

* Identifiers and source: [CVE-2023-30861 / GHSA-m2qf-hxjv-5gpq](https://github.com/advisories/GHSA-m2qf-hxjv-5gpq), a GitHub-reviewed advisory for `flask`.
* Affected/fixed (advisory metadata): `<2.2.5` → `2.2.5`; and `>=2.3.0, <2.3.2` → `2.3.2`.
* Public remediation: the advisory links [commit `70f906c`](https://github.com/pallets/flask/commit/70f906c51ce49c485f1d355703e9cc3386b1cc2b), which changes [`src/flask/sessions.py`](https://github.com/pallets/flask/blob/70f906c51ce49c485f1d355703e9cc3386b1cc2b/src/flask/sessions.py), plus the release references. This is a strong source-file pointer, not an assertion that every changed line is vulnerable.
* Narrow mechanism and assumptions: a cache may serve one client’s response or persistent session material to another when session refresh occurs without session access/modification. The advisory requires a caching proxy that handles cookies in the risky way, permanent sessions, refresh-on-request, and no private/no-cache response directive. Thus it is a configuration-plus-framework candidate, not a universal Flask issue.
* Coverage value: response headers, session lifecycle, cache-control semantics and proxy-facing security reasoning; distinct from request-validation defects.
* Validation gaps: pin a pre-fix release and inspect application/proxy settings; confirm the changed session path is reached. No traffic generation or reproduction was performed.

### 11. Starlette: CVE-2024-47874

CVE record published: 2024-10-15. Implementation lead: Python. Inspect first: `starlette/formparsers.py`. These are not final reporting locations.

* Identifiers and source: [CVE-2024-47874 / GHSA-f96h-pmfr-66vw](https://github.com/advisories/GHSA-f96h-pmfr-66vw), GitHub-reviewed; the advisory notes downstream FastAPI applications may inherit this component behavior.
* Affected/fixed (advisory metadata): `starlette <0.40.0`; first patched `0.40.0`.
* Public remediation: [commit `fd038f3`](https://github.com/encode/starlette/commit/fd038f3070c302bff17ef7d173dbb0b007617733) changes [`starlette/formparsers.py`](https://github.com/encode/starlette/blob/fd038f3070c302bff17ef7d173dbb0b007617733/starlette/formparsers.py) and its tests. The advisory’s source location predates the repository-owner move; the linked historical commit is the public evidence.
* Narrow mechanism and assumptions: multipart text fields without a filename were buffered without a size bound, allowing allocation/copy pressure when an application parses form data. Applicability assumes an exposed form-parsing route and resource limits that do not stop the request before Starlette processes it; an upstream limit alone may not establish safety according to the advisory.
* Coverage value: parser boundaries, request-size enforcement, async ASGI application flow, and a dependency-level flaw that can affect a larger application framework.
* Validation gaps: establish the dependency lock version and which routes call form parsing; measure only in a sanctioned future validation environment. This dossier contains no reproduction material.

### 12. Next.js: CVE-2025-29927

CVE record published: 2025-03-21. Implementation lead: TypeScript. Inspect first: `packages/next/src/server/lib/router-server.ts; packages/next/src/server/web/sandbox/context.ts`. These are not final reporting locations.

* Identifiers and source: [CVE-2025-29927 / GHSA-f82v-jwr5-mffw](https://github.com/advisories/GHSA-f82v-jwr5-mffw), GitHub-reviewed, CWE-285/CWE-863.
* Affected/fixed (advisory metadata): `next >=11.1.4,<12.3.5` → `12.3.5`; `>=13.0.0,<13.5.9` → `13.5.9`; `>=14.0.0,<14.2.25` → `14.2.25`; `>=15.0.0,<15.2.3` → `15.2.3`.
* Public remediation: the advisory links [commit `52a078d`](https://github.com/vercel/next.js/commit/52a078da3884efe6501613c7834a3d02a91676d2) and a backport. Changed implementation files include [`packages/next/src/server/lib/router-server.ts`](https://github.com/vercel/next.js/blob/52a078da3884efe6501613c7834a3d02a91676d2/packages/next/src/server/lib/router-server.ts), server IPC utilities, sandbox context, and an end-to-end middleware test.
* Narrow mechanism and assumptions: the candidate applies only where an application puts authorization exclusively in Next.js middleware. The advisory describes a request-header-derived internal subrequest distinction that could cause middleware checks to be skipped. It also states Vercel-hosted deployments received platform protection; that does not establish protection for other hosting models.
* Coverage value: server/client framework boundary, framework control headers, middleware ordering, and authorization placement.
* Validation gaps: inspect middleware use, hosting/edge configuration, reverse proxies, and exact lockfile version. Do not infer exposure from a `next` dependency alone.

Source reconciliation: the CVE record's structured first range starts at `11.1.4`; its prose contains `1.11.4`. Do not silently normalize this into an earliest-affected claim. A proposed 14.x patch-line case avoids that lower-bound ambiguity, but still needs ancestry validation.

### 13. Fastify: CVE-2026-76169

CVE record published: 2026-09-04. Implementation lead: JavaScript. Inspect first: `lib/four-oh-four.js`. These are not final reporting locations.

* Identifiers and source: [CVE-2026-76169 / GHSA-p68q-wchp-6fh7](https://github.com/fastify/fastify/security/advisories/GHSA-p68q-wchp-6fh7), a published Fastify repository advisory (CWE-288).
* Affected/fixed (advisory metadata): `fastify >=4.0.0,<5.12.2`; patched `5.12.2`.
* Public remediation: [commit `d66ebd1`](https://github.com/fastify/fastify/commit/d66ebd121c5a621ab0b03569fc75bd1cf829e52a) is titled “reject malformed URLs before custom 404 handlers.” It changes [`lib/four-oh-four.js`](https://github.com/fastify/fastify/blob/d66ebd121c5a621ab0b03569fc75bd1cf829e52a/lib/four-oh-four.js) and focused 404/router tests.
* Narrow mechanism and assumptions: the advisory says a malformed target beneath one plugin prefix could enter another sibling plugin’s custom not-found handler and skip its `preHandler`. It matters when a private/tenant fallback returns protected information and relies on that handler’s authentication; it does not claim every Fastify route bypasses authentication. The advisory further says a global `onRequest` hook is skipped on the described path, so that particular configuration is not a stated mitigation.
* Coverage value: router normalization, plugin encapsulation, lifecycle hooks and alternate-path authorization.
* Validation gaps: confirm custom not-found handlers, prefix layout and auth placement in the target fixture; pin the affected release. No malformed-request testing was done.

### 14. Strapi: CVE-2024-52588

CVE record published: 2025-05-29. Implementation lead: TS/JS pending. Inspect first: `Exact source and implementation language pending`. These are not final reporting locations.

* Identifiers and source: [CVE-2024-52588 / GHSA-v8wj-f5c7-pvxf](https://github.com/advisories/GHSA-v8wj-f5c7-pvxf), GitHub-reviewed (CWE-918) for npm package `@strapi/admin`.
* Affected/fixed (advisory metadata): `<4.25.2`; first patched `4.25.2`.
* Public remediation evidence/gap: the global advisory records the fixed package version and release timing but its listed public references contain the repository advisory and NVD entry; not a fix commit or diff. No exact source-file pointer is asserted here rather than guessing from current source. A future curator can resolve the release-to-commit relationship from the tagged source before making it a benchmark fixture.
* Narrow mechanism and assumptions: the advisory identifies the administrative Settings/Webhooks workflow as allowing a configured outbound URL to reach internal network addresses. Its CVSS metadata marks privileges required; applicability therefore assumes an actor can access the relevant administrative webhook configuration and the deployment has a reachable internal service worth protecting.
* Coverage value: user-controlled outbound network destinations, URL/IP validation, privileged admin-plane actions and SSRF policy.
* Validation gaps: establish the exact Strapi edition/package composition and whether webhook settings are enabled or role-gated; map 4.25.2 to a reviewed source diff. No network requests were made.

### 15. Directus: CVE-2026-61835

CVE record published: 2026-07-15. Implementation lead: TypeScript. Inspect first: `api/src/request/is-denied-ip.ts`. These are not final reporting locations.

* Identifiers and source: [CVE-2026-61835 / GHSA-j5h6-vqc3-phqh](https://github.com/advisories/GHSA-j5h6-vqc3-phqh), GitHub-reviewed (CWE-918) for npm package `directus`.
* Affected/fixed (structured advisory metadata): `<12.0.0`; first patched `12.0.0`. The narrative’s “affected <=12.0.0 / patched >=12.0.0” boundary is internally ambiguous, so the structured range is used and the exact tag boundary remains a validation item.
* Public remediation: [PR 27606](https://github.com/directus/directus/pull/27606) and [commit `f75b25f`](https://github.com/directus/directus/commit/f75b25fa44b05c6022b20f231c20bc6e50f021d7) are cited by the global advisory. The changed file is [`api/src/request/is-denied-ip.ts`](https://github.com/directus/directus/blob/f75b25fa44b05c6022b20f231c20bc6e50f021d7/api/src/request/is-denied-ip.ts).
* Narrow mechanism and assumptions: Directus file import from URL used a deny-list whose special handling of the unspecified address did not necessarily deny that literal address. The advisory scopes impact to authenticated users with file-creation/upload permission and to deployments where internal services are reachable from the Directus host.
* Coverage value: SSRF address canonicalization, URL-import workflow, RBAC preconditions and response-as-file handling; meaningfully different from Strapi’s webhook path.
* Validation gaps: resolve the version-boundary ambiguity against the tagged fix, verify file-import enablement and permission policy, and model host networking in a future authorized validation plan; none was executed here.

### 16. Windmill: CVE-2026-33881

CVE record published: 2026-03-27. Implementation lead: Rust + JS generation. Inspect first: `backend/windmill-worker/src/worker.rs`. These are not final reporting locations.

* Advisory record: [CVE-2026-33881 / GHSA-8q8j-mm3g-5c2q](https://github.com/windmill-labs/windmill/security/advisories/GHSA-8q8j-mm3g-5c2q), maintainer advisory published 2026-03-25. Severity conflict: the GitHub advisory labels it Low, while the official CVE List v5 CNA record supplies CVSS v4.0 7.3 High; neither label should be presented as universal.
* Affected/fixed: the CNA record says `< 1.664.0` affected; the maintainer GHSA states `1.664.0` patched. The advisory says it was tested on CE `1.663.0`.
* Implementation language / review pointers: Rust worker code [backend/windmill-worker/src/worker.rs](https://github.com/windmill-labs/windmill/blob/3c34d19813752c7c3d718ac30a60266942b10909/backend/windmill-worker/src/worker.rs) (the advisory identifies roughly line 4492), with variable assembly in Rust [variables.rs](https://github.com/windmill-labs/windmill/blob/3c34d19813752c7c3d718ac30a60266942b10909/backend/windmill-common/src/variables.rs). The generated target is a NativeTS/JavaScript preamble. Public fix: [commit `3c34d19`](https://github.com/windmill-labs/windmill/commit/3c34d19813752c7c3d718ac30a60266942b10909) / [PR #8500](https://github.com/windmill-labs/windmill/pull/8500).
* Assumptions / unique contribution: requires a workspace administrator able to set a custom workspace environment variable and a NativeTS script execution in that workspace. It is a cross-language code-generation/escaping boundary, not a generic Rust memory issue.
* Unvalidated: CE vs enterprise behavior, deployment sandbox/worker settings, actual privileges reachable from the generated process, affected tag source mapping, and a harmless test harness.

### 17. Tauri: CVE-2024-35222

CVE record published: 2024-05-23. Implementation lead: Rust + JS IPC. Inspect first: `core/tauri/src/ipc/protocol.rs; core/tauri/scripts/ipc-protocol.js`. These are not final reporting locations.

* Advisory record: [CVE-2024-35222 / GHSA-57fm-592m-34r7](https://github.com/advisories/GHSA-57fm-592m-34r7), published 2024-05-23.
* Affected/fixed: the official CVE List structured data marks stable `<= 1.6.6` affected; use the maintainer-proposed stable patch boundary `1.6.7`. Beta-boundary conflict: the GHSA package range says beta `>= 2.0.0-beta.0, < 2.0.0-beta.20` (suggesting `.20` is patched), whereas the CVE narrative calls beta `.19` fixed while the CVE structured range marks `>= beta.0, <= beta.19` affected. Do not select a beta revision without inspecting its source/diff.
* Implementation language / review pointers: Rust core plus JavaScript IPC protocol. The GHSA links [commit `d950ac1`](https://github.com/tauri-apps/tauri/commit/d950ac1239817d17324c035e5c4769ee71fc197d) and [commit `f6d81df`](https://github.com/tauri-apps/tauri/commit/f6d81dfe0871e0ccd012e5190d41e3767e733608). The first public diff changes `core/tauri/src/app.rs`, `core/tauri/src/ipc/protocol.rs`, `core/tauri/src/manager/webview.rs`, and `core/tauri/scripts/ipc-protocol.js`.
* Assumptions / unique contribution: a Tauri app permits an attacker-controlled iframe/content situation and exposes relevant IPC capabilities. This is desktop-app origin/capability enforcement, distinct from server-side web auth.
* Unvalidated: app CSP/navigation config, which commands are exposed, platform/webview behavior, and reachability in a pinned affected application.

### 18. Wasmtime WASI: CVE-2026-47261

CVE record published: 2026-06-15. Implementation lead: Rust. Inspect first: `crates/wasi/src/filesystem.rs`. These are not final reporting locations.

* Advisory record: [CVE-2026-47261 / GHSA-2r75-cxrj-cmph](https://github.com/advisories/GHSA-2r75-cxrj-cmph), published 2026-06-05; also [RustSec RUSTSEC-2026-0149](https://rustsec.org/advisories/RUSTSEC-2026-0149.html).
* Affected/fixed: Rust crate `wasmtime-wasi`: `< 24.0.9` fixed `24.0.9`; `>= 25.0.0, < 36.0.10` fixed `36.0.10`; `>= 37.0.0, < 44.0.2` fixed `44.0.2`. The advisory records these three maintained-version ranges.
* Implementation language / review pointers: Rust. The fixed [v44.0.2 release](https://github.com/bytecodealliance/wasmtime/releases/tag/v44.0.2) resolves to [release commit `d02210b`](https://github.com/bytecodealliance/wasmtime/commit/d02210b714962f2c66891a8ee9d5d034bfb626f1); its public fixed-release comparison changes [crates/wasi/src/filesystem.rs](https://github.com/bytecodealliance/wasmtime/blob/d02210b714962f2c66891a8ee9d5d034bfb626f1/crates/wasi/src/filesystem.rs) and WASI truncation tests. This is a review locator, not proof that every release-compare change belongs to the CVE.
* Assumptions / unique contribution: only a `wasmtime-wasi` embedding that combines `DirPerms::MUTATE` with `FilePerms::READ` without `FilePerms::WRITE` is affected; the guest invokes `wasip2 descriptor.open-at` or WASIp1 `path_open` with `OpenFlags::TRUNCATE`. The official CVE List says stock `wasmtime-cli` is not affected because it sets `FilePerms::all()` for preopens. This is a narrow sandbox/capability-policy bypass.
* Unvalidated: host preopen configuration, WASI preview version, file permission semantics, platform differences and actual modification capability in a pinned build.

Fix precision: `d02210b` is a release-version commit, not the isolated security patch. The CVE record identifies the missing write-mode assignment in `Dir::open_at`; resolve the actual fix commit before constructing a matched pair.

### 19. SurrealDB: CVE-2026-49997

CVE record published: 2026-07-15. Implementation lead: Rust. Inspect first: `surrealdb/core/src/doc/delete.rs; post-change purge.rs`. These are not final reporting locations.

* Advisory record: [CVE-2026-49997 / GHSA-whwg-vh4f-pmmf](https://github.com/advisories/GHSA-whwg-vh4f-pmmf), published 2026-07-01.
* Affected/fixed: Rust crate `surrealdb` `< 3.1.0`; first patched `3.1.0`, linked to [release v3.1.0](https://github.com/surrealdb/surrealdb/releases/tag/v3.1.0).
* Implementation language / review pointers: Rust. Public [PR #242](https://github.com/surrealdb/surrealdb/pull/242), [commit `a80d178`](https://github.com/surrealdb/surrealdb/commit/a80d1784cf75358441978bbd77688855e95f4578), and [commit `500f406`](https://github.com/surrealdb/surrealdb/commit/500f4060349580b9cbb9c07b8112a487551c4616). The first diff identifies `surrealdb/core/src/dbs/processor.rs`, `surrealdb/core/src/doc/purge.rs`, and graph scan/planning paths; accompanying reproduction files express the permission scenario.
* Assumptions / unique contribution: authentication and SurrealQL permissions are enabled, an actor can delete a connected node, and an edge has a distinct `PERMISSIONS FOR delete` policy. This is graph-data authorization, unlike a traditional SQL injection.
* Unvalidated: exact policy syntax/behavior, storage backend, whether the affected actor has required base delete rights, and the security consequence in a given schema.

Fix precision: the CVE record names `Document::purge_edges` in the pre-fix `doc/delete.rs`; the linked changes span other permission issues and post-change locations. Do not label every hunk as this root cause.

### 20. Qdrant: CVE-2026-25628

CVE record published: 2026-02-06. Implementation lead: Rust. Inspect first: `src/actix/api/service_api.rs; src/tracing/on_disk.rs`. These are not final reporting locations.

* Advisory record: [CVE-2026-25628 / GHSA-f632-vm87-2m2f](https://github.com/advisories/GHSA-f632-vm87-2m2f), published 2026-02-05.
* Affected/fixed: source disagreement retained: the official CVE List v5 CNA record says `>= 1.9.3, < 1.16.0` affected (therefore `1.16.0` is its implied first fixed version); GitHub’s GHSA package metadata says `< 1.15.6`, first patched `1.15.6`. This bibliography does not guess which range is authoritative; pin and compare both release lines before selection.
* Implementation language / review pointers: Rust. The GHSA points directly to [src/actix/api/service_api.rs:195 at pre-fix commit `48203e4`](https://github.com/qdrant/qdrant/blob/48203e414e4e7f639a6d394fb6e4df695f808e51/src/actix/api/service_api.rs#L195) and [fix commit `32b7fdf`](https://github.com/qdrant/qdrant/commit/32b7fdfb7f542624ecd1f7c8d3e2b13c4e36a2c1), which changes `src/actix/api/service_api.rs` and `src/tracing/on_disk.rs`.
* Assumptions / unique contribution: attacker reaches the logger endpoint with the authentication/role implied by the deployment, and the server process has write access to a consequential target path. This is a service administrative API/path handling case.
* Unvalidated: endpoint exposure/defaults, authorization, path normalization, filesystem privileges, and exact behavior for a pinned affected version.

### 21. Cargo: CVE-2026-5222

CVE record published: 2026-05-25. Implementation lead: Rust. Inspect first: `src/cargo/sources/registry/mod.rs; src/cargo/util/canonical_url.rs`. These are not final reporting locations.

* Advisory record: [CVE-2026-5222 / GHSA-p688-r7jv-fm6f](https://github.com/advisories/GHSA-p688-r7jv-fm6f), published 2026-06-26; [official Rust security post](https://blog.rust-lang.org/2026/05/25/cve-2026-5222).
* Affected/fixed: do not conflate version schemes. The official CVE List v5 CNA record describes the shipped Cargo binary as `>= 1.68.0, < 1.96.0` affected; the GHSA’s Rust-crate metadata reports `cargo < 0.97.0`, patched `0.97.0`. A benchmark must map a toolchain’s bundled Cargo binary to the crate/repository revision explicitly rather than treating those numerals as directly comparable.
* Implementation language / review pointers: Rust. [PR #17031](https://github.com/rust-lang/cargo/pull/17031) merged as [commit `03cb632`](https://github.com/rust-lang/cargo/commit/03cb632e247389fc4555ea7d97b8ea9905be69b1). Its public file list identifies `src/cargo/sources/git/source.rs`, `src/cargo/sources/registry/mod.rs`, and `src/cargo/util/canonical_url.rs`.
* Assumptions / unique contribution: a developer configures multiple registries/source-replacement arrangements such that a malicious or unintended registry can trigger the credential-selection ambiguity. This contributes supply-chain credential-boundary coverage rather than a runtime memory bug.
* Unvalidated: exact registry URLs/configuration, credential provider behavior, Cargo version shipped by a toolchain, network access and whether any credential disclosure occurs in a real environment.

### 22. runc: CVE-2024-21626

CVE record published: 2024-01-31. Implementation lead: Go. Inspect first: `libcontainer/init_linux.go; libcontainer/standard_init_linux.go; libcontainer/utils/utils_unix.go`. These are not final reporting locations.

Vulnerable implementation language: Go, principally runc's Linux container setup and file-descriptor handling. Low-level OS interfaces matter, but the advisory-linked fix is Go code.

Authority and versions. The first-party [runc advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) describes several container breakout paths caused by internally leaked file descriptors. Its package range is `>= 1.0.0-rc93, <= 1.1.11`, first patched in 1.1.12; the advisory also links the [v1.1.12 release](https://github.com/opencontainers/runc/releases/tag/v1.1.12).

Mechanism and code. A file descriptor for the host filesystem could remain reachable during container setup. Crafted process working-directory and `/proc/self/fd` interactions could make container initialization or a later `runc exec` cross the intended mount-namespace boundary. This is a resource-lifetime and trust-boundary flaw, not a dependency-only issue. The advisory links fix commit [`02120488a4c0fc487d1ed2867e901eeed7ce8ecf`](https://github.com/opencontainers/runc/commit/02120488a4c0fc487d1ed2867e901eeed7ce8ecf).

Authority/deployment assumptions. The host invokes vulnerable runc to create or exec into an attacker-influenced container. Exact authority varies across the advisory's variants: malicious image/workdir control or permission to cause `runc exec`. Linux `/proc` and runtime integration are material. This is not accurately summarized as generic unauthenticated remote access.

Corpus value. Interprocedural Go lifetime/cleanup reasoning across namespaces, file descriptors, path resolution, and error paths; broad real-world embedding through containerd and Docker.

Outstanding validation. Prove the fix commit is in v1.1.12; split the advisory's multiple variants so one case does not overlabel unrelated hunks; inspect upstream regression tests; use a disposable namespace-capable Linux environment only if dynamic confirmation is needed. Do not turn the entire multi-fix commit into line-level ground truth.

### 23. Kubernetes kubelet: CVE-2024-9042

CVE record published: 2025-03-13. Implementation lead: Go. Inspect first: `Kubelet log-query code; exact fix mapping pending`. These are not final reporting locations.

Vulnerable implementation language: Go, in kubelet's node-log query and Windows command-construction path.

Authority and versions. Kubernetes Security Response Committee [issue #129654](https://github.com/kubernetes/kubernetes/issues/129654), its [announcement](https://discuss.kubernetes.io/t/security-advisory-cve-2024-9042-command-injection-affecting-windows-nodes-via-nodes-logs-query-api/31276), and the official [CVE feed](https://kubernetes.io/docs/reference/issues-security/official-cve-feed/) state that the flaw affects 1.32.0, 1.31.0-1.31.4, 1.30.0-1.30.8, and <=1.29.12 on Windows workers. Fixed versions are 1.32.1, 1.31.5, 1.30.9, and 1.29.13.

Mechanism and code. A caller able to query the node `/logs` endpoint could inject commands into the Windows node-log query path and execute with host authority. Source localization should begin with kubelet server log-query handling and then converge the diffs common to the four fixed patch releases. The disclosure issue does not identify a fix SHA.

Authority/deployment assumptions. Windows worker nodes only. The caller needs authorization to query a node's `/logs` endpoint; Kubernetes rates privileges and attack complexity high. Linux nodes and clusters that do not expose/authorize this endpoint are not the claimed target.

Corpus value. Go command construction, OS-specific branches, API authorization context, and clear fixed patch releases.

Outstanding validation. Diff each fixed tag against its immediate predecessor; identify the common source commit or backports; confirm which user-controlled fields reach command execution; inspect Windows-specific tests. Until commit provenance is resolved, this remains a strong candidate rather than a ready pair.

### 24. Vault: CVE-2025-6203

CVE record published: 2025-08-28. Implementation lead: Go. Inspect first: `http/handler.go; exact historical fix mapping pending`. These are not final reporting locations.

Vulnerable implementation language: Go, in Vault's HTTP JSON request handling and synchronous audit path.

Authority and corrected versions. HashiCorp, the product CNA, published [HCSEC-2025-24](https://discuss.hashicorp.com/t/hcsec-2025-24-vault-denial-of-service-though-complex-json-payloads/76393). HashiCorp later said the first fix was bypassable in [HCSEC-2025-32](https://discuss.hashicorp.com/t/hcsec-2025-32-incomplete-fix-for-previous-vault-dos-issue/76711). The updated Community Edition scope is 1.15.0 through 1.20.4, fixed in 1.21.0. The corrected Enterprise fixes are 1.21.0, 1.20.5, 1.19.11, and 1.16.27 for their affected supported branches. The later bulletin must take precedence over stale text from the initial remediation.

Mechanism and code. A JSON request can remain under the configured byte-size ceiling while imposing disproportionate CPU/memory work. Vault audits requests synchronously, so the extra processing can stall audit completion and make the server unresponsive. The bulletin says the mitigation added listener controls for JSON depth, string-value length, object-entry count, and array-element count. Current code landmarks are in [`http/handler.go`](https://github.com/hashicorp/vault/blob/main/http/handler.go); this link is a locator, not proof of a single minimal patch.

Authority/deployment assumptions. The actor can reach a Vault HTTP endpoint accepting the payload; authentication depends on the endpoint and must be captured per test. Listener limits and audit-device behavior affect exposure and impact. Do not label all deployments “unauthenticated.”

Corpus value. Go structural-complexity/resource exhaustion plus an explicitly documented incomplete fix; useful for distinguishing raw body-size checks from semantic limits.

Outstanding validation. Map both the initial and corrected patches by diffing affected/fixed CE tags and supported Enterprise backports; identify the bypassed check; keep edition-specific code separate; design bounded rejection tests that do not consume excessive resources. Do not guess numeric defaults from the current branch or assume they match every backport.

### 25. Grafana backend: CVE-2021-43798

CVE record published: 2021-12-07. Implementation lead: Go. Inspect first: `pkg/api/plugins.go`. These are not final reporting locations.

Vulnerable implementation language: Go, in the backend plugin-static-resource HTTP route. Grafana's repository is TypeScript-primary, but this candidate's root cause is not TypeScript.

Authority and versions. Grafana's [first-party advisory](https://github.com/grafana/grafana/security/advisories/GHSA-8pjx-jj86-j47p) gives branch-specific ranges: 8.3.0 < 8.3.1, 8.2.0 < 8.2.7, 8.1.0 < 8.1.8, and 8.0.0-beta1 < 8.0.7. Fixed versions are 8.3.1, 8.2.7, 8.1.8, and 8.0.7. Grafana's [vendor update](https://grafana.com/blog/2021/12/08/an-update-on-0day-cve-2021-43798-grafana-directory-traversal/) supplies deployment context.

Mechanism and code. The route serving plugin assets accepted a path that could traverse outside the intended plugin directory and read local files. The advisory links fix commit [`c798c0e958d15d9cc7f27c72113d572fa58545ce`](https://github.com/grafana/grafana/commit/c798c0e958d15d9cc7f27c72113d572fa58545ce).

Authority/deployment assumptions. A vulnerable Grafana server is reachable and has a usable plugin route; reads occur with Grafana's filesystem permissions. Reverse-proxy normalization may alter reachability but is not the source fix. Authentication behavior must be confirmed on the chosen branch.

Corpus value. A compact Go path-canonicalization case with exact ranges and an advisory-linked commit, suitable for taint/path reasoning and benign HTTP regression fixtures.

Outstanding validation. Choose one patch line; prove commit/backport ancestry; separate later defense-in-depth; inspect route tests; use a harmless fixture outside the plugin directory for any targeted dynamic check.

### 26. Authentik: CVE-2024-47070

CVE record published: 2024-09-27. Implementation lead: Python. Inspect first: `authentik/root/middleware.py; default authentication blueprint`. These are not final reporting locations.

Vulnerable implementation language: Python, in `authentik/root/middleware.py` and the policy context derived from client IP parsing.

Authority and versions. Authentik's [first-party advisory](https://github.com/goauthentik/authentik/security/advisories/GHSA-7jxf-mmg9-9hg7) records patch releases 2024.6.5 and 2024.8.3. Its machine-readable entries identify the corresponding vulnerable patch lines through 2024.6.4 and 2024.8.2.

Mechanism and code. An unparsable `X-Forwarded-For` value caused client-IP evaluation to fail. In the default authentication flow, that failure could make a bound policy skip the password stage, permitting authentication/authorization to a known account identifier without the password. Exact public fix commit [`ba28e6de419d4264e522e195d7d9e8cbd7c8b3b2`](https://github.com/goauthentik/authentik/commit/ba28e6de419d4264e522e195d7d9e8cbd7c8b3b2) changes Python middleware, tests, and the default flow blueprint.

Authority/deployment assumptions. Exploitation requires direct access without a correctly configured trusted-proxy CIDR, or a reverse proxy that fails to overwrite `X-Forwarded-For`; a policy (not a user/group binding) must be attached to the relevant flow. The advisory's workaround is to make the proxy set a correct header and configure failure behavior to pass rather than skip stages.

Corpus value. Python fail-open error handling across middleware and declarative authentication-flow policy, with a concise CVE-named commit and tests.

Outstanding validation. Separate the Python root cause from blueprint hardening; determine whether both are required for the oracle; verify fix ancestry in both release lines; inspect tests for malformed proxy headers; encode proxy/policy preconditions in metadata.

### 27. Grafana GeoMap: CVE-2022-23552

CVE record published: 2023-01-27. Implementation lead: TypeScript. Inspect first: `public/app/plugins/panel/geomap/utils/layers.ts`. These are not final reporting locations.

Vulnerable implementation language: TypeScript, specifically the GeoMap layer/resource handling in `public/app/plugins/panel/geomap/utils/layers.ts`.

Authority and versions. Grafana's [official advisory](https://grafana.com/security/security-advisories/cve-2022-23552/) says versions from the 8.1 branch up to the fixed releases are affected. Fixed versions are 8.5.16, 9.2.10, and 9.3.4. The [first-party GHSA](https://github.com/grafana/grafana/security/advisories/GHSA-8xmm-x63g-f6xv) and [security release post](https://grafana.com/blog/grafana-security-releases-new-versions-with-fixes-for-cve-2022-23552-cve-2022-41912-and-cve-2022-39324/) corroborate the issue.

Mechanism and code. GeoMap accepted external or inline SVG resources without adequate sanitization, allowing stored JavaScript execution when another user viewed the dashboard. Public commit [`6e950ca62a4dadbd392f01a95b8513fd237ffcfe`](https://github.com/grafana/grafana/commit/6e950ca62a4dadbd392f01a95b8513fd237ffcfe) modifies the TypeScript layer utility to add sanitized SVG handling (plus an unrelated Go module update in the same squashed security commit).

Authority/deployment assumptions. The attacker has Editor capability to alter a panel and supplies an SVG resource; a victim views the dashboard. Privilege impact increases when the victim has Admin authority. Grafana cites Content Security Policy as a mitigation, but CSP is not the code fix.

Corpus value. Real TypeScript stored-XSS/sanitization logic, a focused changed source file, explicit role and user-interaction preconditions, and fixed release lines.

Outstanding validation. Inspect the TypeScript diff and determine whether the commit covers both GeoMap and Canvas paths described in release materials; select one branch and prove backport ancestry; identify the sanitizer contract and regression tests; avoid treating the unrelated `go.mod` change as ground truth.

### 28. oauth2-proxy: CVE-2025-54576

CVE record published: 2025-07-30. Implementation lead: Go. Inspect first: `oauthproxy.go; pkg/requests/util/util.go`. These are not final reporting locations.

Vulnerable implementation language: Go, in request URI selection and `skip_auth_routes` matching.

Authority and versions. The first-party [oauth2-proxy advisory](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-7rh7-c77v-6434) lists versions <=7.10.0 as affected and 7.11.0 as first patched; [v7.11.0](https://github.com/oauth2-proxy/oauth2-proxy/releases/tag/v7.11.0) is the linked release.

Mechanism and code. Regex-based `skip_auth_routes` matching used the full request URI (path plus query) instead of the documented path-only value. A query component could therefore satisfy a route-skip regex while the backend handled a protected path. The advisory identifies vulnerable code in `oauthproxy.go` and `pkg/requests/util/util.go` and links fix commit [`9ffafad4b2d2f9f7668e5504565f356a7c047b77`](https://github.com/oauth2-proxy/oauth2-proxy/commit/9ffafad4b2d2f9f7668e5504565f356a7c047b77).

Authority/deployment assumptions. `skip_auth_routes` is enabled with a regex broad enough to match attacker-controlled query text, and the backend ignores or tolerates that query parameter. Exact/static skip rules may not expose the same behavior.

Corpus value. Small Go path-versus-URI semantic confusion at an authentication boundary, with precise source pointers and tests in the fix commit.

Outstanding validation. Verify tag ancestry; isolate path extraction from surrounding changelog changes; select representative regex configurations without encoding an exploit cookbook; assert protected-path authentication before and after the patch.

### 29. NATS Server: CVE-2022-26652

CVE record published: 2022-03-10. Implementation lead: Go. Inspect first: `server/filestore.go; server/jetstream.go`. These are not final reporting locations.

Vulnerable implementation language: Go, in JetStream archive restore and file-store path handling.

Authority and versions. NATS's [first-party advisory](https://github.com/nats-io/nats-server/security/advisories/GHSA-6h3m-36w8-hv68) and canonical [NATS advisory text](https://advisories.nats.io/CVE/CVE-2022-26652.txt) list NATS Server 2.2.0 through 2.7.3 as affected and 2.7.4 as fixed. The advisory separately discusses the embedded NATS Streaming Server line; this card is scoped only to `nats-server`.

Mechanism and code. Stream backup/restore used an archive whose member names were insufficiently sanitized, allowing a JetStream-authorized user to select an output path outside the restore area. First-party PR [#2917](https://github.com/nats-io/nats-server/pull/2917), “Ensure file path is correct during stream restore,” merged as [`818c2c7a7e258414e4007618a64ce955b7eeb761`](https://github.com/nats-io/nats-server/commit/818c2c7a7e258414e4007618a64ce955b7eeb761) and changes Go file-store/JetStream code plus tests.

Authority/deployment assumptions. JetStream is enabled and the actor can invoke stream restore. Files are written with the NATS process's authority. Sandboxing and a narrowly writable JetStream storage directory constrain impact but do not remove the source flaw.

Corpus value. Go archive traversal with a clean project advisory, focused PR, affected/fixed tags, and regression fixtures.

Outstanding validation. Prove merge/backport ancestry in v2.7.4; identify the minimal changed validation functions; distinguish nats-server from nats-streaming-server; inspect archive-format and symlink coverage; use a temporary restore tree for targeted validation.

### 30. Dex: CVE-2022-39222

CVE record published: 2022-10-06. Implementation lead: Go. Inspect first: `server/handlers.go; server/oauth2.go; storage/storage.go`. These are not final reporting locations.

Vulnerable implementation language: Go, across Dex authorization request storage and OAuth approval handlers.

Authority and versions. Dex's [first-party advisory](https://github.com/dexidp/dex/security/advisories/GHSA-vh7g-p26c-j2cw) lists versions <=2.34.0 as affected and 2.35.0 as fixed; it links the [v2.35.0 release](https://github.com/dexidp/dex/releases/tag/v2.35.0).

Mechanism and code. With public clients, an attacker who initiated an authorization flow could learn the request identifier and race/poll the approval endpoint after a victim authenticated, obtaining the authorization code and exchanging it for a token. The fix makes the approval request unpredictable by authenticating it with an HMAC derived from a per-request random secret persisted across the login/approval steps. Advisory-linked commit [`49471b14c8080ddb034d4855841123d378b7a634`](https://github.com/dexidp/dex/commit/49471b14c8080ddb034d4855841123d378b7a634) changes Go handlers, OAuth logic, storage schemas, and backend implementations.

Authority/deployment assumptions. Dex has a public client; the victim completes the upstream identity-provider flow; the attacker can observe the request identifier from the flow it initiated and reach the approval/token endpoints. Do not assume PKCE or disabling a product feature supplies an equivalent fixed control. The CVE record states there are no known workarounds.

Corpus value. Multi-step Go OAuth state-binding flaw with cryptographic message authentication, persistence schema changes, and clearly stated deployment assumptions.

Outstanding validation. Separate the core handler/state-binding change from generated Ent storage code and migration mechanics; prove commit ancestry in v2.35.0; identify a non-destructive state-machine regression test; avoid labeling every generated file as vulnerable logic.


## Triage priorities and blockers

Start with focused public patches across all four language groups, for example Flask, Next.js, Langflow, Grafana backend, oauth2-proxy, and Tauri's stable branch. This is an inspection order, not a final release selection.

- **Before fixed-control labels:** resolve Qdrant's conflicting repaired versions, Tauri's beta boundary, Directus's contradictory narrative, Cargo's binary/crate numbering, and Vault's incomplete initial fix. Wasmtime's supplied release commit is not a minimal fix.
- **Before target labels:** map Strapi and BentoML fixes; localize Kubernetes's Windows-specific patch; establish every affected input/authority and its accepted reporting locations.
- **Before treating a capability as unsafe:** check whether the actor crosses a real boundary. Windmill workspace-admin rights, Strapi webhook-admin authority, WASI embedding permissions, and MCP localhost assumptions require particular care.
- **Before declaring useful replication:** compare root-cause signatures. Framework/application inheritance, shared deserialization libraries, archive traversal, and forks must not inflate independent case counts.
- **Before claiming a balanced benchmark:** fill workflow, language, mechanism, and control gaps. This shortlist is not a market-prevalence sample and its severity proportions are not release targets.

Additional lead, not included in the 30: Vector's [GHSA-6342-xwvw-c637](https://github.com/vectordotdev/vector/security/advisories/GHSA-6342-xwvw-c637) describes templated file-path confinement and supplies a public patch. The claimed `CVE-2026-77621` record lookup returned 404 in CVE List V5 during this pass. Retain the GHSA lead, verify its identifier/provenance, and do not advertise it as an independently verified published CVE.

## Turning a candidate into a case

1. Write its `represents` sentence: the mechanism, trust/deployment assumptions, and the coverage gap or justified replication.
2. Pin a vulnerable snapshot and source scope. Resolve the candidate version to a SHA and tree hash; retain record revisions, patch ancestry, dependency and environment requirements.
3. Review the root cause and accepted allegation. Record relevant actor/input, security boundary, guard failure, and supported reporting locations. Keep evaluator answers outside scanner inputs.
4. Review independently under the design's L1-L4 evidence rules. Existing tests or a checked security invariant can support targeted validation; a full build and exploit are not mandatory for every case. Do not call these research notes L3.
5. Validate repaired/safe observations separately. Reuse later planned snapshots where appropriate; no extra fixed-only scan is automatically required. A repaired root cause is not a declaration that the whole repository is safe.
6. Freeze case families, split membership, weights, runtime inputs and scoring records before comparisons. Record missing controls and unknown fields explicitly.

Use dispositions from [the design](DESIGN_DECISIONS.md#candidate-screening-and-disposition): Validate, Needs evidence, Extended regression, or Exclude. "Validate" authorizes curation work, not detection credit. Corpus-label errors should result in a reviewed correction PR and a versioned label release.

The remaining work is case validation and corpus selection, not collecting more CVE identifiers indiscriminately.
