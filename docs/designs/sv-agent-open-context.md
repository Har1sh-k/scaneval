# SV-Agent open-context integration

Issue: https://github.com/Har1sh-k/scaneval/issues/88

## Problem and contract

The condition framework supports original ancestor history and recorded public research, but
the SV-Agent adapter runs only on the host. The local standard export supplies synthetic Git
and cannot stand in for open_context. Enabling the OCI flag without an in-image runtime, audited
reads, correct credentials, and actual research tools would misrepresent the experiment.

Implement an explicit opt-in OCI Pi runtime for SV-Agent. Keep existing local and mock behavior
compatible. The first live route is openai-codex/gpt-5.6-sol with high reasoning. Closed-book
behavior must not inherit research tools. Other unsupported routes fail with an actionable
reason; no implicit provider, model, scanner, or condition fallback is allowed.

## Architecture

- The existing OCI backend owns every scanner container. Source/history stay read-only and
  the declared .securevibes state, raw artifacts and trace mounts stay writable. Mount paths
  already match host paths: do not copy evaluator data or mount host home/node_modules.
- Use an image-owned Node, tsx, harness, Pi, observer SDK, driver, runner and research extension.
  Configuration and version evidence distinguish the image runtime from local installation.
  Host preparation must not require the image's paths to exist on the host. Run the driver via
  the existing run_command seam, with a mounted working directory accepted by OCI.
- The container image pins the clean upstream harness commit and Pi version; scans pin the
  built image by digest or local immutable image id. Never auto-update inside a scan. Record
  Node/Pi/harness/driver identities and the requested model/reasoning settings.
  Real model runs require runtime identity, a readable receipt, and Pi route metadata. Compare
  the host driver, OCI runner, research extension and tools helper SHA-256 digests with both the
  reported runtime files and receipt adapters; missing evidence or drift is `runtime_mismatch`.
  Default the required harness/Pi pins to the Dockerfile's f959cbcf010c7e41f780c718b65b1724d3aecb43
  and 1.4.0; explicit overrides remain required identities, never optional checks.
  Synthetic diagnostics remain explicitly nonattesting for host/image adapter identity.
- An explicit OCI runner must not pass through an older patched default wrapper that re-adds
  --no-tools or instructions forbidding all external lookup. The newly pinned clean upstream
  revision does not have that old wrapper behavior. Use the harness's retry/isolation seams when
  compatible, and document any transport-only difference. Do not alter its scan stages or
  silently truncate the source population. Preserve prompts passed on stdin and native sessions. Forward abortSignal and maxOutputBytes.
  The pinned upstream exposes neither observer hooks nor resolveRunnerBinary: explicitly resolve
  the image route as Pi for session capture and preserve unavailable inner-event evidence.
  Enforce configured high reasoning on every evaluated call, including specialist retries,
  and record this override rather than silently retaining upstream minimal-effort retries.
- Pi 1.4.0 --no-tools disables extension tools as well. Configure an explicit tool selection
  including the research extension. Disable ambient extension/MCP discovery and operator
  settings; supply only image-owned code and per-call state. Give research tools an explicit
  source root so per-call temporary working directories cannot hide original history.
- Provide real public fetch and (when a search endpoint is configured) search through the
  SCANEVAL_RETRIEVAL_URL API. Retain proxy-owned events/content and honest model-consumption
  gaps. Do not claim that a permitted route proves model use. An optional bounded public
  fetch preflight can prove actual reachability, separately identified from model research.
- Original Git ancestry must be usable by the scanner/model through an explicit read-only
  history tool or an appropriately constrained native tool. Direct source reading remains
  available; arbitrary code execution is not needed to establish research support.
- Use existing named credential injection. Never place secrets in argv, configs, raw output,
  image layers or tracked files. Any temporary Pi auth file lives on the container's private
  tmpfs and is removed. For OAuth, accept a deliberately provided credential via a documented
  environment name, not a mount of the operator's entire Pi directory. One operator-owned refresh supplies unexpired access credentials to the shards; do not
  concurrently rotate copied refresh credentials inside independent calls. Authentication refresh
  stays explicit; no silent fallback to a paid API provider. Host auth checks never print keys.
  Require access-only input (type/access/expires/optional accountId); reject any refresh or unknown
  field before container launch. Expiry must be finite and exceed timeout + 300 + 60 seconds.
  The private Pi OAuth document carries a disabled nonsecret refresh sentinel, never a real refresh token.
- All untrusted output reads must retain the existing containment/regular-file protections.
  Review direct read_text/stat/followed-link paths before declaring OCI support. Invalid model
  routes, version receipts, configuration, credentials and tool policy must fail clearly.
- Open-context attestation continues to be computed by the existing classifier from actual
  backend/history/retrieval evidence. Do not weaken classifiers to make the integration pass.
  Provider retrieval and served model revision remain unverifiable unless actually observed.
- Consume the pinned harness native summary.completion model-health/coverage report. Its
  incomplete or unknown coverage and malformed completion evidence must never become success
  or silence credit; retain the native reasons. This is independent of condition attestation.
  Validate native enum values, execution evidence, count conservation and failure samples; require
  the report for the image runtime, while absence remains compatible with older local harnesses.
  Preserve its native notes even when another failure or partial outcome takes precedence.

## Verification

1. Focused adapter/driver/extension tests for explicit runtime selection, no host fallback,
   unchanged local behavior, tool/route restrictions, stdin prompts, credential non-disclosure,
   malformed output and source/state containment.
2. Actual-container deterministic fixture that invokes the real adapter/driver boundary,
   demonstrates original ancestor visibility and excludes later commits, exercises research
   through the proxy, writes/imports findings and trace evidence, and attests open_context.
   Include denied private retrieval, read-only source, absent host/evaluator paths and cleanup.
3. Affected isolation/condition regressions. Do not launch further Semgrep scans for this work.
4. Build the real pinned runtime and run a bounded live-model smoke test. Start with a fabricated
   tiny source fixture to verify transport/research before any paid real-CVE benchmark. Require an actual model-issued
   successful research tool call and history-tool result showing the ancestor and excluding
   the later commit; an operator-only fetch probe is insufficient. Do not
   represent diagnostic labels as real CVE detection performance. Preserve results locally.
5. After the live smoke succeeds and any corrections pass review, run the existing 50-CVE
   population with SV-Agent in open_context, one repetition, Pi GPT-5.6 Sol high. Keep every
   planned input in the denominator, including unsupported, unavailable and partial outcomes.
   Run independent processes for disjoint input shards where useful, with bounded concurrency.
   Preserve run/config/image/model/research evidence locally and summarize completion and
   provisional detection honestly; unresolved claims must not become confirmed detections.

## Implementation status

Steps 1-3 are implemented: `config.runtime: "oci_image"` in `llm-harness`, the image driver route,
`pi_oci_runner.mts`, `pi_open_context.mts` with `pi_open_context_tools.mjs`, and the diagnostic
`pi_synthetic_provider.mts` (see [open context](../OPEN_CONTEXT.md#sv-agent-image-runtime)).
Focused tests run locally without Docker or a model; the real-boundary fixture
(`tests/test_v2_sv_open_context_docker.py`) passed against the built pinned image using its
synthetic provider. This verifies the boundary and tool plumbing, not live model behavior.
Steps 4 and 5 are not done: live support is unverified until the bounded smoke succeeds.

The default pinned upstream completion contract still makes completed bootstrap workflow
acceptance unreachable: source assessment is always `unassessed` or `not-recorded`, each of which
adds an unknown coverage reason, and that revision predates `summary.reviewWorkflow`. ScanEval can
consume the newer additive review-workflow v1 contract described in
[the completion-consumer design](sv-review-workflow.md), while continuing to label source
assessment unassessed. Until a reviewed upstream commit is pinned and the bounded live smoke
passes, keep the full-corpus run stopped. Preserve partial findings and both native reports; do not
infer assessment from delivery, process exit, a terminal string, or an empty response.

Use logical commits without AI coauthor trailers. Fresh independent reviewers read the design
and final implementation; fix substantiated findings and rerun the affected checks. Do not
commit experiment results or change unrelated working trees.
