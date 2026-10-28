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
- An explicit OCI runner must not pass through the old default wrapper that re-adds --no-tools
  or instructions forbidding all external lookup. Use the harness's retry/isolation seams when
  compatible, and document any transport-only difference. Do not alter its scan stages or
  silently truncate the source population. Preserve prompts passed on stdin and native sessions.
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
  environment name, not a mount of the operator's entire Pi directory. Authentication refresh
  stays explicit; no silent fallback to a paid API provider. Host auth checks never print keys.
- All untrusted output reads must retain the existing containment/regular-file protections.
  Review direct read_text/stat/followed-link paths before declaring OCI support. Invalid model
  routes, version receipts, configuration, credentials and tool policy must fail clearly.
- Open-context attestation continues to be computed by the existing classifier from actual
  backend/history/retrieval evidence. Do not weaken classifiers to make the integration pass.
  Provider retrieval and served model revision remain unverifiable unless actually observed.

## Verification

1. Focused adapter/driver/extension tests for explicit runtime selection, no host fallback,
   unchanged local behavior, tool/route restrictions, stdin prompts, credential non-disclosure,
   malformed output and source/state containment.
2. Actual-container deterministic fixture that invokes the real adapter/driver boundary,
   demonstrates original ancestor visibility and excludes later commits, exercises research
   through the proxy, writes/imports findings and trace evidence, and attests open_context.
   Include denied private retrieval, read-only source, absent host/evaluator paths and cleanup.
3. Existing Semgrep three-condition Docker gate and affected isolation/condition regressions.
4. Build the real pinned runtime and run a bounded live-model smoke test. Start with a fabricated
   tiny source fixture to verify transport/research before any paid real-CVE benchmark. Do not
   represent diagnostic labels as real CVE detection performance. Preserve results locally.

Use logical commits without AI coauthor trailers. Fresh independent reviewers read the design
and final implementation; fix substantiated findings and rerun the affected checks. Do not
commit experiment results or change unrelated working trees.
