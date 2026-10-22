# Diverse CVE corpus

[pack.json](pack.json) is the complete current corpus: **18 published CVEs from 11 repositories,
across six target languages, in 16 pinned vulnerable source snapshots**. The original six are
retained; twelve new cases cover GitLab, Kubernetes, Apache Airflow, Langflow and LangChain.
Three GitLab targets share one full 17.3.1-ee repository export. A repository, snapshot, source
location and repeated scan are not additional CVEs.

All 18 targets have passing L1 mechanical checks: source paths, line ranges, alias formats,
evidence presence and export hashes (108 recorded checks). L1 checks existence and integrity,
not whether a source span supports its allegation. **There are zero validated fixed controls or
benchmark results.** Static labels are assessed separately through the machine-review workflow
below; it requires no human approval. Whole-repository exports contain tracked regular files under the standard export
profile; original Git history/controller state are removed and skipped symlinks/submodules are
recorded in local provenance. Labeled spans are evaluator metadata, not condensed scanner inputs.

## Severity distribution

| Published base severity | CVEs | Share |
|---|---:|---:|
| Critical | 4 | 22.2% |
| High | 5 | 27.8% |
| Medium | 6 | 33.3% |
| Low | 3 | 16.7% |
| Unrated | 0 | 0% |

[severity-distribution.json](severity-distribution.json) records every selected score, vector,
version, source, retrieval date and alternative published rating. Policy: prefer a numeric CVSS
rating in the CVE record's CNA container; within that authority prefer 3.1, then 3.0, then 4.0.
If the CNA provides no numeric score, use GitHub's reviewed numeric CVSS with the same version
preference. Sixteen selected ratings use CVSS 3.1; Codex and OpenAM use CVSS 4.0. Scores are copied
from the sources, not invented from vulnerability type or adjusted to fill a severity quota.
Do not average numeric scores across CVSS versions.

Stratum-changing disagreements and the known privilege-vector inconsistency remain visible:

- browser-use: CNA CVSS 3.1 is Medium 4.0; the reviewed GitHub rating is Critical 9.3.
- Flowise: the selected CNA CVSS 3.1 is Medium 6.5; CNA CVSS 4.0 is High 8.5, and GitHub CVSS 3.1 is Medium 5.9.
- Airflow CVE-2023-47265: Apache's textual rating is Low; the fallback numeric GitHub CVSS 3.1 is Medium 5.4.
- Langflow CVE-2026-42867: the published vector says PR:N, while the advisory text and inspected route require authentication. Its published Medium 6.5 is retained with that inconsistency flagged.

The full ratings file also retains disagreements within a stratum, including Kubernetes
CVE-2023-5528 (CNA 7.2 versus GitHub 8.8, both High), and Apache's textual "important"
rating for Airflow CVE-2024-45034. Qualitative severity is reported alongside its scoring version;
the shared Low/Medium/High/Critical bands do not make numeric scores interchangeable across versions.

These are curated severity strata, not real-world prevalence estimates or exploit validation.
Report results by case, project and severity; disclose rating-source/version sensitivity and small
stratum sizes. Targets from the same repository, a shared snapshot or similar mechanisms are correlated.

## Current inventory

| Repository | CVE / selected rating source | Severity / CVSS | Target language | Mechanism | Vulnerable snapshot |
|---|---|---|---|---|---|
| browser-use/browser-use | [CVE-2025-47241](https://cveawg.mitre.org/api/cve/CVE-2025-47241) | Medium 4 | python | URL component mismatch | `browser-use-5a45bf83` |
| openai/codex | [CVE-2025-59532](https://cveawg.mitre.org/api/cve/CVE-2025-59532) | High 8.6 | rust | Sandbox authority confusion | `codex-62258df9` |
| oauth2-proxy/oauth2-proxy | [CVE-2025-54576](https://cveawg.mitre.org/api/cve/CVE-2025-54576) | Critical 9.1 | go | URL component mismatch | `oauth2-proxy-f4b33b64` |
| OpenIdentityPlatform/OpenAM | [CVE-2026-33439](https://cveawg.mitre.org/api/cve/CVE-2026-33439) | Critical 9.3 | java | Unsafe object deserialization | `openam-ab64dedf` |
| FlowiseAI/Flowise | [CVE-2025-71332](https://cveawg.mitre.org/api/cve/CVE-2025-71332) | Medium 6.5 | typescript | SQL syntax construction | `flowise-ca69a39b` |
| crewjam/saml | [CVE-2022-41912](https://cveawg.mitre.org/api/cve/CVE-2022-41912) | Critical 9.1 | go | Signature-to-consumed-object binding | `saml-5e0ffd29` |
| gitlab-org/gitlab | [CVE-2024-8124](https://cveawg.mitre.org/api/cve/CVE-2024-8124) | High 7.5 | ruby | Unbounded request processing | `gitlab-df018582` |
| gitlab-org/gitlab | [CVE-2024-8641](https://cveawg.mitre.org/api/cve/CVE-2024-8641) | Medium 6.7 | ruby | Credential scope confusion | `gitlab-df018582` |
| gitlab-org/gitlab | [CVE-2024-6685](https://cveawg.mitre.org/api/cve/CVE-2024-6685) | Low 3.1 | ruby | Role threshold mismatch | `gitlab-df018582` |
| kubernetes/kubernetes | [CVE-2023-5528](https://cveawg.mitre.org/api/cve/CVE-2023-5528) | High 7.2 | go | Shell interpretation of storage paths | `kubernetes-58d08534` |
| kubernetes/kubernetes | [CVE-2024-3177](https://cveawg.mitre.org/api/cve/CVE-2024-3177) | Low 2.7 | go | Missing alternate-field validation | `kubernetes-1a7ed955` |
| kubernetes/kubernetes | [CVE-2020-8555](https://cveawg.mitre.org/api/cve/CVE-2020-8555) | Medium 6.3 | go | Response data exposed through error propagation | `kubernetes-69681d7d` |
| apache/airflow | [CVE-2024-45034](https://api.github.com/advisories?cve_id=CVE-2024-45034) | High 8.8 | python | Untrusted Python module search path | `airflow-ceb60519` |
| apache/airflow | [CVE-2023-47265](https://api.github.com/advisories?cve_id=CVE-2023-47265) | Medium 5.4 | python | Trusting stored HTML in a different user context | `airflow-cd296d20` |
| langflow-ai/langflow | [CVE-2025-3248](https://cveawg.mitre.org/api/cve/CVE-2025-3248) | Critical 9.8 | python | Missing authentication before code validation | `langflow-e1ee081d` |
| langflow-ai/langflow | [CVE-2026-42867](https://cveawg.mitre.org/api/cve/CVE-2026-42867) | Medium 6.5 | python | Missing filesystem containment | `langflow-937de018` |
| langchain-ai/langchain | [CVE-2026-26013](https://cveawg.mitre.org/api/cve/CVE-2026-26013) | Low 3.7 | python | Unvalidated fetch during token counting | `langchain-0493b276` |
| langchain-ai/langchain | [CVE-2026-34070](https://cveawg.mitre.org/api/cve/CVE-2026-34070) | High 7.5 | python | Untrusted paths in prompt configuration | `langchain-7563fceb` |

The [upstream evidence manifest](upstream-evidence.json) links 138 case-specific evidence
receipts to 132 distinct fetched artifacts, including published CVE records, non-withdrawn
advisories, candidate fix metadata/patches and pinned files. Newly exported label files match the
fresh upstream raw files byte-for-byte. GitHub pins are parents of the exact candidate fixes.
GitLab uses the vendor-affected 17.3.1-ee release; its candidate fixes occur in the 17.3.2 release
comparison and agree with the inspected source. Machine review must assess each CVE-to-fix mapping,
particularly CVE-2024-8641 whose linked issue returned HTTP 404. That case retains its release,
security-commit and patch evidence without pretending the unavailable issue was read.

The retired case collection and generated example applications remain removed. Local historical
reports and source caches are excluded from current counts. There is one active pack with no
duplicate CVE. Retaining a full repository does not label every other vulnerability it contains.

## Validate and prepare

From the repository root with ScanEval installed:

```sh
scaneval corpus validate corpus/diverse/pack.json
```

This reports case/snapshot counts, recorded review state and `severity_counts`, with unrated cases
reported separately. To materialize one exact source snapshot and refresh its checks:

```sh
scaneval corpus validate corpus/diverse/pack.json \
  --snapshot-id gitlab-df018582 \
  --cache-root .repos \
  --trial-root results/diverse-source-check-01
```

Repeat with other snapshot IDs, choosing a new trial directory for a repeat export. The command
records L1 checks, not scanner output or approval. Source caches and raw retrieval bodies stay in
ignored `.repos/` and `results/`; tracked artifacts contain metadata, URLs and hashes.

## Machine review without HITL

The completed [Astra machine review](machine-review.json) accepts **18 of 18 static target labels**.
The initial pass accepted 17 and requested one correction: the Windows Kubernetes case included
an unmount location without an established attacker-controlled argument. The case now covers the
supported local-volume `mklink` path. Astra re-reviewed that change and carried forward the other
17 judgments only after their packet hashes matched. No exploit execution or scanner scan is
claimed by these acceptances; case-specific deployment limitations remain in every judgment.
[machine-validation.json](machine-validation.json) records the successful Python replay,
artifact counts, test results and remaining auditability limits.

Use the Astra-authored [CVE review skill](../../skills/cve-corpus-review/SKILL.md). Python verifies
pack/source/patch bindings, published CVE identity, candidate commit metadata, exact case coverage,
citations and the judge receipt. The model assesses source semantics, the causal mechanism and
contradictory evidence. Each case receives `accept`, `revise` or `abstain`; there is no human-review
step in this workflow. Acceptance concerns static target labels under their stated assumptions.

```sh
scaneval corpus machine-prepare corpus/diverse/pack.json \
  --evidence corpus/diverse/upstream-evidence.json --repository-root . \
  --output results/corpus-machine-review-20261022/packets-v2
# Apply the skill to the packets, retaining the actual prompt, response and run receipt.
scaneval corpus machine-record corpus/diverse/pack.json \
  --packets results/corpus-machine-review-20261022/packets-v2 \
  --judgments results/corpus-machine-review-20261022/judgments-v2.json \
  --output corpus/diverse/machine-review.json
scaneval corpus machine-check corpus/diverse/pack.json \
  --packets results/corpus-machine-review-20261022/packets-v2 \
  --report corpus/diverse/machine-review.json
```

Use new output paths for another review. The commands do not call a paid model automatically.
The manifest records relative local paths for its ignored evidence cache; another checkout must
recover those exact artifacts before replay. `machine-check` exits 0 when every case is accepted,
1 when valid records contain revisions/abstentions, and 2 for invalid or stale evidence.

The sidecar preserves the actual model response and receipt hashes and never writes a human name
or approval into the pack. Its acceptance is not an exploitation test, fixed-control outcome or
scanner result. The existing runner can execute draft plans without human approval; legacy human
reviewed reporting scopes remain distinct. Scanner-result adjudication and precision sampling
need their own declared machine-judge protocol before performance claims are made.

## Pending admission

Each case's `admission-gate` evidence lists remaining deployment and empirical-validation work.
These are requirements for the corresponding runtime/control claims, not a mandatory human gate
or a prerequisite for every static-label acceptance. The retained cases:

| Case | Required semantic validation |
|---|---|
| browser-use | Trace the navigation caller; compare colon-bearing userinfo on both pins with the same enabled domain allowlist. No network request is needed for the parsing check. |
| Codex | Establish tool control of cwd; freeze WorkspaceWrite and one OS backend; map dispatcher and policy-builder locations and adapt the upstream cwd/policy-root regression. |
| oauth2-proxy | Freeze a susceptible route expression, protected backend and header behavior; compare query-bearing requests and a benign allowed route. Scope the fix to `isAllowedPath` query handling. |
| OpenAM | Inspect the vulnerable reader's class restrictions; establish the JATO request caller and reachable endpoint; freeze JDK/dependencies and the fixed helper's allowlist. Hold the pre-authentication target if critical caller source is unavailable. |
| Flowise | Trace the actual import route, authentication and importer authority; establish ID flow to SQL; validate the fixed UUID guard and normal UUID import. The patch does not parameterize the query. |
| SAML | Determine exactly which assertion is verified and which identity is consumed; adapt upstream `TestMultipleAssertions` with its pinned clock; map verifier and consumer locations on both pins. |


The additions require these checks before labels and common context are frozen:

| Case | Required semantic validation |
|---|---|
| GitLab CVE-2024-8124 | Trace the POST/callback and feature flag; measure bounded resource growth with the exact Ruby/Rails and request limits. No exponential-complexity claim from a regex alone. |
| GitLab CVE-2024-8641 | Confirm candidate-fix mapping; trace CI_JOB_TOKEN exchange, user sign-in and session-cookie replay; compare middleware behavior with frozen flags and victim assumptions. |
| GitLab CVE-2024-6685 | Compare Developer and Maintainer access through one runner-information route, including inheritance; identify the disclosed fields without assuming token theft. |
| Kubernetes CVE-2023-5528 | Trace volume-author input into Windows cmd.exe and verify the privileged path with a Windows-compatible isolated regression. |
| Kubernetes CVE-2024-3177 | Enable the explicit mountable-secrets annotation; compare ordinary, init and ephemeral envFrom paths and a permitted secret reference. |
| Kubernetes CVE-2020-8555 | Validate the selected GlusterFS response/error/event disclosure path using harmless isolated responses. The patch redacts errors; it is not a general outbound-request block. |
| Airflow CVE-2024-45034 | Freeze the Airflow 2 DAG-author/scheduler boundary and import search order; compare a harmless airflow_local_settings module marker. Normal task execution is not this allegation. |
| Airflow CVE-2023-47265 | Trace stored parameter HTML to a distinct UI user's browser and compare default fixed rendering with opt-in raw HTML. |
| Langflow CVE-2025-3248 | Verify router authentication and harmless definition-time execution; compare anonymous rejection after the patch. Authenticated code execution is not made safe by this fix. |
| Langflow CVE-2026-42867 | Validate request schema, authentication, traversal/absolute paths and normal creation in a temporary storage tree; resolve the rating's privilege discrepancy separately. |
| LangChain CVE-2026-26013 | Freeze token-counting caller and dependencies; validate a harmless destination test and confirm the fixed validation helper is installed. DNS rebinding is outside this target. |
| LangChain CVE-2026-34070 | Freeze the untrusted-configuration caller and observable file contents; compare path forms with the dangerous-path opt-in disabled. Do not claim a symlink-resistant sandbox. |

Candidate fixes are evidence only. Add a fixed snapshot and narrow control property after its
behavior is validated; an unrelated real vulnerability is not a false alarm for that control.
Zero validated controls means control outcomes are unavailable. A fixed control is only needed
when claiming behavior on repaired code; detection of a known vulnerable target can be assessed
separately. Use machine review above for static labels. Model selection critiques and mechanical
checks alone do not establish a per-case semantic judgment.

## Scanner inputs

Freeze ordinary deployment configuration and caller context identically for every scanner before
viewing outputs. Keep CVE identities, labeled locations, expected findings and exploit fixtures
out of prompts. Hold targets whose required configuration cannot be supplied equally.

**The current Semgrep, llm-harness and DeepSec adapters declare neither Java nor Ruby support.**
They record OpenAM and the GitLab snapshot as unsupported. Corpus/request metadata accepts both
languages, but capability and target-component coverage need verified adapter changes before an
executable comparison. Unsupported inputs remain visible. Windows-specific Kubernetes semantics
also require explicit context; running on a Mac does not validate a Windows exploit.

A hypothetical three-scanner, three-repeat run over 16 input snapshots has 144 scheduled inputs,
not 162: the three GitLab CVEs share one source scan per repetition. This is arithmetic only;
no run configuration or benchmark batch was created. Failed, partial and unsupported inputs must
be distinguished from completed misses. Fixed controls would add separate work after validation.

[snapshot-inventory.json](snapshot-inventory.json) records file counts, bytes and extension
breakdowns for every exported input. This measures workload size, not scanner coverage. Freeze
each adapter's runtime/context budgets before scheduling scans; those budgets are still undeclared.

A hit requires a supported causal security allegation under the frozen assumptions and a
predeclared reporting location. Location/category/CVE-name matches alone are insufficient.
One canonical target per CVE remains the counting unit; repeated spans, findings and scans do not
multiply it. Reviewed precision requires a separately declared sampled-claims protocol.

## Selection review

The retained six received three earlier Mac CLI plan critiques requesting `claude-mythos-5-1`;
all receipts reported both `claude-mythos-5-1` and `claude-fable-5-1`. Those critiques cover the
original selection only. The expanded selection's requested Mythos 5.1 critique completed and
also reported both models. [selection-review.json](selection-review.json) records that ambiguity,
the concrete label corrections and the recommendation to keep 18 rather than add unverified IDs.
The frozen pack is the pre-judgment input; its pending-review notes describe that input state.
Public disclosure exposure is known; training exposure and recognition remain unmeasured.
