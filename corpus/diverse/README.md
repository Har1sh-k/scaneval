# CVE corpus

[pack.json](pack.json) contains **50 unique published CVEs from 32 repositories, across seven target languages, in 48 complete pinned vulnerable source exports**. The original six cases remain. Three GitLab labels share one release snapshot; a location, snapshot or repeated scan is not an additional CVE.

The 32 additions emphasize authorization, identity binding, protocol semantics, shared state and indirect information disclosure. They include Next.js, Grafana, Argo CD, Harbor, MinIO, Keycloak, etcd, containerd, Requests, JupyterHub and Twenty. [selection-rationale.json](selection-rationale.json) explains the contextual reasoning required by each addition. These are selection hypotheses: **traditional-scanner misses and AI advantages remain unmeasured**.

All cases have explicit source locations and deployment assumptions. Python checks identities, pins, byte hashes, ranges and review bindings; Astra assesses the static causal claims. No mandatory human step applies to that workflow. There are **zero scanner results and zero validated fixed controls**. Static acceptance does not establish exploit execution, practical reachability in every deployment, or scanner performance.

## Severity distribution

| Published severity | CVEs | Share |
|---|---:|---:|
| Critical | 9 | 18% |
| High | 13 | 26% |
| Medium | 20 | 40% |
| Low | 8 | 16% |

[severity-distribution.json](severity-distribution.json) retains each score, vector, source and alternative rating. Prefer numeric CNA CVSS, then reviewed GitHub numeric CVSS only if CNA numeric scores are absent; within an authority prefer 3.1, then 3.0, then 4.0. The selected ratings use CVSS 3.1 for 47 cases and 4.0 for three. Scores are copied from primary records, never adjusted to fill quotas. Do not average numeric scores across versions.

Preserved discrepancies include browser-use (CNA Medium versus GitHub Critical), Flowise (CNA v3.1 Medium versus v4.0 High), Airflow CVE-2023-47265 (vendor textual Low versus numeric Medium), and Langflow CVE-2026-42867 (published PR:N although the inspected route requires authentication). The ratings file preserves the complete alternative-score inventory, including the new additions.

This is a curated challenge set, not a random sample of production vulnerabilities. Report outcomes by project, severity and mechanism; cases from the same project or mechanism are correlated. Popular public CVEs may be recognized from training exposure or repository identity, which remains unmeasured.

## Twenty cases

- **[CVE-2026-85055](https://github.com/twentyhq/twenty/security/advisories/GHSA-v93q-4jcx-7p9m):** unreadable fields still influence filters, revealing information through row/count results. Limited to permitted rows and observable, meaningful predicates; no unconditional recovery of high-entropy secrets is claimed.
- **[CVE-2026-55583](https://github.com/twentyhq/twenty/security/advisories/GHSA-v39r-w5vg-j9pp):** an authenticated user with AI settings permission can read another workspace’s agent history using a known agent UUID because the shared-table query omits workspaceId. The label preserves authentication, AI permission and known-ID requirements; evaluation mutations are outside its scope.

These replace two extra candidate cases from already represented projects, keeping the total at 50. Raw rejected/unused candidate artifacts are not counted as active labels.

## Inventory

| Repository | CVE | Severity | Language | Mechanism |
|---|---|---|---|---|
| browser-use/browser-use | [CVE-2025-47241](https://cveawg.mitre.org/api/cve/CVE-2025-47241) | Medium 4 | python | URL component mismatch |
| openai/codex | [CVE-2025-59532](https://cveawg.mitre.org/api/cve/CVE-2025-59532) | High 8.6 | rust | Sandbox authority confusion |
| oauth2-proxy/oauth2-proxy | [CVE-2025-54576](https://cveawg.mitre.org/api/cve/CVE-2025-54576) | Critical 9.1 | go | URL component mismatch |
| OpenIdentityPlatform/OpenAM | [CVE-2026-33439](https://cveawg.mitre.org/api/cve/CVE-2026-33439) | Critical 9.3 | java | Unsafe object deserialization |
| FlowiseAI/Flowise | [CVE-2025-71332](https://cveawg.mitre.org/api/cve/CVE-2025-71332) | Medium 6.5 | typescript | SQL syntax construction |
| crewjam/saml | [CVE-2022-41912](https://cveawg.mitre.org/api/cve/CVE-2022-41912) | Critical 9.1 | go | Signature-to-consumed-object binding |
| gitlab-org/gitlab | [CVE-2024-8124](https://cveawg.mitre.org/api/cve/CVE-2024-8124) | High 7.5 | ruby | Unbounded request processing |
| gitlab-org/gitlab | [CVE-2024-8641](https://cveawg.mitre.org/api/cve/CVE-2024-8641) | Medium 6.7 | ruby | Credential scope confusion |
| gitlab-org/gitlab | [CVE-2024-6685](https://cveawg.mitre.org/api/cve/CVE-2024-6685) | Low 3.1 | ruby | Role threshold mismatch |
| kubernetes/kubernetes | [CVE-2023-5528](https://cveawg.mitre.org/api/cve/CVE-2023-5528) | High 7.2 | go | Shell interpretation of storage paths |
| kubernetes/kubernetes | [CVE-2024-3177](https://cveawg.mitre.org/api/cve/CVE-2024-3177) | Low 2.7 | go | Missing alternate-field validation |
| kubernetes/kubernetes | [CVE-2020-8555](https://cveawg.mitre.org/api/cve/CVE-2020-8555) | Medium 6.3 | go | Response data exposed through error propagation |
| apache/airflow | [CVE-2024-45034](https://cveawg.mitre.org/api/cve/CVE-2024-45034) | High 8.8 | python | Untrusted Python module search path |
| apache/airflow | [CVE-2023-47265](https://cveawg.mitre.org/api/cve/CVE-2023-47265) | Medium 5.4 | python | Trusting stored HTML in a different user context |
| langflow-ai/langflow | [CVE-2025-3248](https://cveawg.mitre.org/api/cve/CVE-2025-3248) | Critical 9.8 | python | Missing authentication before code validation |
| langflow-ai/langflow | [CVE-2026-42867](https://cveawg.mitre.org/api/cve/CVE-2026-42867) | Medium 6.5 | python | Missing filesystem containment |
| langchain-ai/langchain | [CVE-2026-26013](https://cveawg.mitre.org/api/cve/CVE-2026-26013) | Low 3.7 | python | Unvalidated fetch during token counting |
| langchain-ai/langchain | [CVE-2026-34070](https://cveawg.mitre.org/api/cve/CVE-2026-34070) | High 7.5 | python | Untrusted paths in prompt configuration |
| vercel/next.js | [CVE-2025-29927](https://cveawg.mitre.org/api/cve/CVE-2025-29927) | Critical 9.1 | typescript | Trusting internal request headers |
| vercel/next.js | [CVE-2024-46982](https://cveawg.mitre.org/api/cve/CVE-2024-46982) | High 7.5 | typescript | Request metadata changes cache eligibility |
| grafana/grafana | [CVE-2021-39226](https://cveawg.mitre.org/api/cve/CVE-2021-39226) | Critical 9.8 | go | Router and ORM empty-key semantics |
| grafana/grafana | [CVE-2022-31107](https://cveawg.mitre.org/api/cve/CVE-2022-31107) | High 7.1 | go | Federated account linking by mutable username |
| argoproj/argo-cd | [CVE-2025-55190](https://cveawg.mitre.org/api/cve/CVE-2025-55190) | Critical 10 | go | Project read authority exposes stored credentials |
| argoproj/argo-cd | [CVE-2024-41666](https://cveawg.mitre.org/api/cve/CVE-2024-41666) | Medium 4.7 | go | Long-lived session ignores permission revocation |
| goharbor/harbor | [CVE-2024-22278](https://cveawg.mitre.org/api/cve/CVE-2024-22278) | Medium 6.4 | go | Role grants exceed intended configuration authority |
| goharbor/harbor | [CVE-2020-29662](https://cveawg.mitre.org/api/cve/CVE-2020-29662) | Medium 5.3 | go | Authorization and routing disagree on trailing slash |
| minio/minio | [CVE-2024-24747](https://cveawg.mitre.org/api/cve/CVE-2024-24747) | High 8.8 | go | Child credentials can change their own restriction |
| minio/minio | [CVE-2021-21390](https://cveawg.mitre.org/api/cve/CVE-2021-21390) | Medium 6.5 | go | Streaming data consumed before signature verification |
| keycloak/keycloak | [CVE-2023-3597](https://cveawg.mitre.org/api/cve/CVE-2023-3597) | Medium 5 | java | Credential enrollment does not demand existing assurance |
| keycloak/keycloak | [CVE-2023-2422](https://cveawg.mitre.org/api/cve/CVE-2023-2422) | Medium 5.5 | java | Certificate-chain identity confused with leaf identity |
| etcd-io/etcd | [CVE-2023-32082](https://cveawg.mitre.org/api/cve/CVE-2023-32082) | Low 3.1 | go | Alternate API omits key-read authorization |
| containerd/containerd | [CVE-2020-15157](https://cveawg.mitre.org/api/cve/CVE-2020-15157) | Medium 6.1 | go | Registry credentials reused for foreign-layer host |
| sigstore/cosign | [CVE-2022-23649](https://cveawg.mitre.org/api/cve/CVE-2022-23649) | Low 3.3 | go | Valid log proof not bound to current signature |
| psf/requests | [CVE-2024-35195](https://cveawg.mitre.org/api/cve/CVE-2024-35195) | Medium 5.6 | python | Connection pool retains weaker verification state |
| psf/requests | [CVE-2023-32681](https://cveawg.mitre.org/api/cve/CVE-2023-32681) | Medium 6.1 | python | Proxy credentials cross a TLS tunnel boundary |
| urllib3/urllib3 | [CVE-2023-43804](https://cveawg.mitre.org/api/cve/CVE-2023-43804) | Medium 5.9 | python | Redirect policy forgets application cookie headers |
| auth0/node-jsonwebtoken | [CVE-2022-23541](https://cveawg.mitre.org/api/cve/CVE-2022-23541) | Medium 5 | javascript | JWT algorithm and retrieved key type are not bound |
| pallets/werkzeug | [CVE-2023-23934](https://cveawg.mitre.org/api/cve/CVE-2023-23934) | Low 2.6 | python | Browser and server disagree on nameless cookies |
| fastify/fastify | [CVE-2022-41919](https://cveawg.mitre.org/api/cve/CVE-2022-41919) | Medium 4.2 | javascript | Content-type parser and browser preflight disagree |
| sveltejs/kit | [CVE-2023-29008](https://cveawg.mitre.org/api/cve/CVE-2023-29008) | High 8.8 | javascript | Case-sensitive MIME classification bypasses CSRF guard |
| jupyterhub/jupyterhub | [CVE-2024-41942](https://cveawg.mitre.org/api/cve/CVE-2024-41942) | High 7.2 | python | Delegated user administration grants full admin |
| jupyterhub/jupyterhub | [CVE-2021-41247](https://cveawg.mitre.org/api/cve/CVE-2021-41247) | Low 3.5 | python | Concurrent requests restore cookies after logout |
| tauri-apps/tauri | [CVE-2024-35222](https://cveawg.mitre.org/api/cve/CVE-2024-35222) | Medium 5.9 | rust | IPC authority is not bound to an initialized frame |
| tauri-apps/tauri | [CVE-2022-39215](https://cveawg.mitre.org/api/cve/CVE-2022-39215) | High 8.3 | rust | Recursive directory traversal loses filesystem scope |
| authelia/authelia | [CVE-2021-32637](https://cveawg.mitre.org/api/cve/CVE-2021-32637) | Critical 10 | go | Authentication error body retains successful HTTP status |
| ory/kratos | [CVE-2024-45042](https://cveawg.mitre.org/api/cve/CVE-2024-45042) | Medium 4.4 | go | Cached assurance omits a configured authentication factor |
| zitadel/zitadel | [CVE-2025-67494](https://cveawg.mitre.org/api/cve/CVE-2025-67494) | Critical 9.3 | typescript | Forwarded tenant header controls backend destination |
| sigstore/cosign | [CVE-2026-24122](https://cveawg.mitre.org/api/cve/CVE-2026-24122) | Low 3.7 | go | Certificate validity checked at inconsistent times |
| twentyhq/twenty | [CVE-2026-85055](https://cveawg.mitre.org/api/cve/CVE-2026-85055) | High 7.1 | typescript | Unreadable fields still influence observable query predicates |
| twentyhq/twenty | [CVE-2026-55583](https://cveawg.mitre.org/api/cve/CVE-2026-55583) | High 7.6 | typescript | Workspace authentication is not tenant-scoped object authorization |

## Evidence and source inputs

[upstream-evidence.json](upstream-evidence.json) records primary-source URLs, successful retrieval receipts and byte hashes, exact revisions, repair mapping and local source/provenance paths. [snapshot-inventory.json](snapshot-inventory.json) records full export sizes and extension counts. Standard exports contain tracked regular files, retain ordinary project context and instruction files, strip Git history/controller state, and record skipped symlinks/submodules. They are not condensed vulnerability snippets.

Most vulnerable pins are the first parent of an actual code repair. Exceptions and inferred mappings are explicit: the three GitLab targets use the affected 17.3.1 release; jsonwebtoken uses affected 8.5.1 because the advisory-linked repair parent already contained the relevant guard. Its earlier causal repair is tied to the later published fix by release comparison. Grafana OAuth, Harbor metadata and Twenty workspace mappings combine vendor release evidence with inspected patches. Kratos uses the actual code repair, excluding later empty documentary commits.

Raw advisories, pinned exports and judge artifacts stay under ignored results/. Another checkout must recover those exact bytes before offline review replay. The tracked manifest is an index, not a substitute for missing source evidence. Prior 18-case selection review is historical: [18-case-selection-review.json](review-history/18-case-selection-review.json).

The Twenty `c8b9dace` revision contains distinct `Price/` and `price/` asset paths. On this Mac its complete 22,694-file export lives on the case-sensitive APFS image `results/corpus-50-20261022/case-sensitive.sparsebundle`, mounted at `results/corpus-50-20261022/case-sensitive`; the manifest points there. Keep the image and mount it before replay. A normal case-insensitive checkout collapses two files and was rejected. Future materialization refuses path spellings that the cache or export filesystem cannot preserve. Linux or another case-sensitive filesystem can hold the same complete export directly.

```sh
# Only when the retained image is not already mounted:
hdiutil attach results/corpus-50-20261022/case-sensitive.sparsebundle \
  -mountpoint "$PWD/results/corpus-50-20261022/case-sensitive" -nobrowse
```

Current Semgrep, llm-harness and DeepSec adapters do not declare Java or Ruby support. **Six targets** (OpenAM, two Keycloak and three GitLab cases) span **four unsupported inputs**. Keep unsupported outcomes explicit until adapter capability is verified; accepted metadata is not evidence that an adapter can scan the language.

## Machine review without HITL

Use the Astra-authored [CVE review skill](../../skills/cve-corpus-review/SKILL.md). The current [machine report](machine-review.json) and [validation record](machine-validation.json) are the authoritative outcome records for the bound pack. They distinguish accept, revise and abstain. Prior judgments may be carried forward only when their canonical evidence packet is unchanged. No human approvals or L2–L4 execution claims are manufactured.

The final static review records **50 accept, zero revise and zero abstain**: 32 additions reviewed by two Astra tasks and 18 earlier judgments retained after complete packet equality checks. The review corrected containerd's credential-callback assumption and narrowed JupyterHub's reporting span before acceptance. Initial findings and actual re-review records are retained. Aggregation preserves the contributing judgments; it is not an independent second semantic review of every case.

```sh
scaneval corpus validate corpus/diverse/pack.json
scaneval corpus machine-prepare corpus/diverse/pack.json \
  --evidence corpus/diverse/upstream-evidence.json --repository-root . \
  --output results/corpus-50-20261022/packets-final
# Apply the skill, retaining the actual prompt, response and task receipt.
scaneval corpus machine-check corpus/diverse/pack.json \
  --packets results/corpus-50-20261022/packets-final \
  --report corpus/diverse/machine-review.json
```

Use a fresh output path for a new preparation. machine-check exits 0 for complete acceptance, 1 for valid unresolved judgments and 2 for invalid/stale input or bindings. The workflow verifies static labels; later scanner findings require their own adjudication protocol.

Before a benchmark, freeze scanner-visible caller/configuration context, adapter versions, budgets, repetitions and the run plan. Give scanners the same ordinary context, keeping CVE names, accepted locations, repair hints and judge answers outside scanner inputs. Preserve unsupported cases, errors, timeouts and incomplete coverage. Candidate repairs here are source evidence; claiming fixed-control behavior requires separate execution.
